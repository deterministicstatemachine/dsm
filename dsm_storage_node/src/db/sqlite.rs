// SPDX-License-Identifier: MIT OR Apache-2.0

//! Storage node DB layer — SQLite backend for local development.
//!
//! Provides the same public API as `db::pg` but backed by a single SQLite file.
//! All operations use `tokio::task::spawn_blocking` since rusqlite is synchronous.

use crate::api::infra::hardening::{BBYTES, BEV};
use crate::timing::TimingStrategy;
use anyhow::{anyhow, Result};
use rusqlite::{params, Connection, OptionalExtension};
use std::sync::{Arc, Mutex};

// ===================== Pool Type Alias =====================

/// SQLite "pool" — a mutex-protected connection (single writer, local-dev only).
pub type DBPool = Arc<Mutex<Connection>>;

// Helper to run blocking DB operations on a spawn_blocking thread
async fn with_conn<F, T>(pool: &DBPool, f: F) -> Result<T>
where
    F: FnOnce(&Connection) -> Result<T> + Send + 'static,
    T: Send + 'static,
{
    let pool = pool.clone();
    tokio::task::spawn_blocking(move || {
        let conn = pool.lock().map_err(|e| anyhow!("mutex poisoned: {}", e))?;
        f(&conn)
    })
    .await
    .map_err(|e| anyhow!("spawn_blocking join: {}", e))?
}

// ===================== Pool Creation =====================

/// Create a SQLite "pool" (single connection).
/// The `database_url` is treated as a file path. If it contains "postgresql" it's ignored
/// and a default local path is used.
pub fn create_pool(database_url: &str, _lazy: bool) -> Result<DBPool> {
    let path = if database_url.contains("postgresql") || database_url.contains("postgres") {
        // Derive a unique SQLite filename from the PostgreSQL database name
        // (e.g. "postgresql://...dsm_storage_node3" → "dsm-storage-node3.db")
        // so that each dev node gets its own file.
        let db_name = database_url.rsplit('/').next().unwrap_or("local");
        let sqlite_file = format!("dsm-storage-{}.db", db_name);
        log::info!(
            "local-dev mode: ignoring PostgreSQL URL, using local SQLite: {}",
            sqlite_file
        );
        sqlite_file
    } else {
        database_url.to_string()
    };
    log::info!("Opening SQLite database: {}", path);
    let conn = Connection::open(&path)?;
    conn.execute_batch(
        "PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA foreign_keys=ON;",
    )?;
    Ok(Arc::new(Mutex::new(conn)))
}

// ===================== Schema Init =====================

/// The SQLite backend's side of the durability gate.
///
/// Nothing to refuse: a write raises `synchronous` to FULL on the one
/// connection this backend has, and there is no server whose settings could
/// defeat it. The function exists so
/// the startup path is the same shape on both backends and cannot be wired on
/// one and forgotten on the other.
pub async fn require_durable_commit_posture(_pool: &DBPool) -> Result<()> {
    Ok(())
}

/// This node's durable REGISTER INCARNATION: the identity of its register
/// history, not of the node.
///
/// Generated once, from the OS random source, and stored only here. It is
/// deliberately not derivable from the node's signing key, its id, or any
/// seed — a node that still holds its identity key but lost its register
/// database MUST come back with a different incarnation, because that is the
/// fact a vault needs to know. Otherwise a rebuilt member can assert "no
/// claim here" for a cell the real incarnation once held, and owning the
/// identity key would be the whole test.
///
/// Write-once with a same-transaction read-back, like the registers it
/// speaks for: two racing callers agree on one value rather than each
/// minting one.
pub async fn register_incarnation(pool: &DBPool) -> Result<[u8; 32]> {
    let fresh: [u8; 32] = rand::random();
    with_conn(pool, move |conn| {
        conn.execute_batch("PRAGMA synchronous=FULL;")?;
        let tx = conn.unchecked_transaction()?;
        tx.execute(
            "INSERT OR IGNORE INTO register_incarnation (only_row, incarnation) VALUES (1, ?1)",
            params![fresh.to_vec()],
        )?;
        let held: Vec<u8> = tx.query_row(
            "SELECT incarnation FROM register_incarnation WHERE only_row = 1",
            [],
            |row| row.get(0),
        )?;
        tx.commit()?;
        let held: [u8; 32] = held
            .try_into()
            .map_err(|_| anyhow!("stored register incarnation is not 32 bytes"))?;
        Ok(held)
    })
    .await
}

// ===================== Generic conditional binding (Rev 15 §15.5) =====================

/// Initialize database schema (SQLite version).
pub async fn init_db(pool: &DBPool) -> Result<()> {
    with_conn(pool, |conn| {
        conn.execute_batch(
            r#"CREATE TABLE IF NOT EXISTS register_incarnation (
                    only_row    INTEGER PRIMARY KEY CHECK (only_row = 1),
                    incarnation BLOB NOT NULL
                );

                -- Keyed cells: the member keeps EVERY value it is given for a
                -- key, in arrival order, and never refuses, replaces or
                -- compares. Which value counts is the reader's question.
                CREATE TABLE IF NOT EXISTS cells (
                    seq       INTEGER PRIMARY KEY AUTOINCREMENT,
                    namespace BLOB NOT NULL,
                    cell_key  BLOB NOT NULL,
                    value     BLOB NOT NULL
                );
                CREATE INDEX IF NOT EXISTS cells_by_key ON cells (namespace, cell_key, seq);

                -- Indexes: content addresses appended under a locator, never
                -- removed, read back in append order.
                CREATE TABLE IF NOT EXISTS index_entries (
                    seq     INTEGER PRIMARY KEY AUTOINCREMENT,
                    locator BLOB NOT NULL,
                    addr    BLOB NOT NULL
                );
                CREATE INDEX IF NOT EXISTS index_entries_by_locator ON index_entries (locator, seq);

                CREATE TABLE IF NOT EXISTS dlv_slots (
                    dlv_id         BLOB PRIMARY KEY,
                    capacity_bytes INTEGER NOT NULL,
                    used_bytes     INTEGER NOT NULL DEFAULT 0,
                    stake_hash     BLOB NOT NULL
                );

                CREATE TABLE IF NOT EXISTS objects (
                    key           TEXT PRIMARY KEY,
                    value         BLOB NOT NULL,
                    dlv_id        BLOB NOT NULL,
                    size_bytes    INTEGER NOT NULL,
                    iter_created  INTEGER NOT NULL DEFAULT 0,
                    iter_expires  INTEGER
                );

                CREATE INDEX IF NOT EXISTS idx_objects_dlv_id ON objects(dlv_id);
                CREATE INDEX IF NOT EXISTS idx_objects_iter_expires ON objects(iter_expires);



                CREATE TABLE IF NOT EXISTS inbox_spool (
                    id                INTEGER PRIMARY KEY AUTOINCREMENT,
                    device_id         TEXT NOT NULL,
                    message_id        TEXT NOT NULL UNIQUE,
                    envelope          BLOB NOT NULL,
                    seq_num           INTEGER NOT NULL DEFAULT 0
                );

                CREATE INDEX IF NOT EXISTS idx_inbox_spool_device_seq ON inbox_spool(device_id, seq_num);

                -- Phase B.4 (issue #275): bounded validator for the
                -- published Device Tree state. Each row is one genesis's
                -- current `DeviceTreeStateV1` proto with the version
                -- counter and Merkle root broken out for indexed lookup
                -- and monotonic-version enforcement.
                CREATE TABLE IF NOT EXISTS device_tree_states (
                    genesis_b32     TEXT PRIMARY KEY,
                    version_number  INTEGER NOT NULL,
                    device_count    INTEGER NOT NULL,
                    root_hash       BLOB NOT NULL,
                    payload         BLOB NOT NULL,
                    updated_at_tick INTEGER NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_device_tree_states_version
                    ON device_tree_states(genesis_b32, version_number);

                -- Single-assignment store for recovery-authority anchors
                -- (spec §0.5 bind-once). Keyed by genesis: the FIRST valid
                -- anchor for a genesis wins and is immutable thereafter; a
                -- different anchor for the same genesis is rejected (409).
                -- Storage enforces single-assignment ONLY — it does not attest
                -- recovery validity; clients verify the anchor cryptographically.
                CREATE TABLE IF NOT EXISTS recovery_authority_anchors (
                    genesis_b32        TEXT PRIMARY KEY,
                    anchor_hash        BLOB NOT NULL,
                    payload            BLOB NOT NULL,
                    first_written_tick INTEGER NOT NULL
                );

                -- IMMUTABLE OBJECT STORE (Area 4, Rev 15 §15.3). Keyed by the
                -- content address addr(N, P); write-once forever — no UPDATE
                -- and no DELETE statement exists against this table anywhere.
                -- The node recomputes the address on write AND on read; it
                -- never decodes the payload. Deletion, if ever needed for
                -- capacity, is a node-policy concern that must not be
                -- implemented as overwrite, and no validity rule may key on
                -- absence.
                CREATE TABLE IF NOT EXISTS immutable_objects (
                    addr_b32           TEXT PRIMARY KEY,
                    namespace          BLOB NOT NULL,
                    payload            BLOB NOT NULL,
                    first_written_tick INTEGER NOT NULL
                );

                -- Append-only Per-Device SMT head chain (spec §0.5 gap 13, R4
                -- layer 1). One row per (device, head_number); a new head is
                -- accepted only if it links the current tip (parent_head_hash ==
                -- current head_hash) at the next head_number. No overwrite, no
                -- fork. Full history is retained so recovery can read the head at
                -- or before the tombstone snapshot. Storage enforces the chain
                -- shape ONLY; clients verify head signatures + inclusion.
                CREATE TABLE IF NOT EXISTS pdsmt_head_chain (
                    device_b32        TEXT NOT NULL,
                    head_number       INTEGER NOT NULL,
                    head_hash         BLOB NOT NULL,
                    parent_head_hash  BLOB NOT NULL,
                    payload           BLOB NOT NULL,
                    inserted_at_tick  INTEGER NOT NULL,
                    PRIMARY KEY (device_b32, head_number)
                );
            "#,
        )?;
        // Arrival order is committed (storage spec §14). SQLite has no
        // ADD COLUMN IF NOT EXISTS, so check the table first.
        let has_index: bool = conn
            .prepare("SELECT 1 FROM pragma_table_info('cells') WHERE name = 'arrival_index'")?
            .exists([])?;
        if !has_index {
            conn.execute_batch(
                "ALTER TABLE cells ADD COLUMN arrival_index INTEGER;
                 ALTER TABLE cells ADD COLUMN running_hash BLOB;",
            )?;
        }
        conn.execute_batch(
            "CREATE UNIQUE INDEX IF NOT EXISTS cells_by_arrival
                 ON cells (namespace, cell_key, arrival_index);",
        )?;
        // Device tokens, their replay guard and the spend-gate flag are gone
        // with writer authorization (storage spec §4). Older local files still
        // carry them; drop them so registration matches this schema.
        // The spool is append-only: no read flag and no expiry. Drop the
        // indexes first; SQLite cannot drop an indexed column.
        conn.execute_batch(
            "DROP INDEX IF EXISTS idx_inbox_spool_device_acked;
             DROP INDEX IF EXISTS idx_inbox_spool_expires;",
        )?;
        for column in ["acked", "expires_at_iter"] {
            let present: bool = conn
                .prepare("SELECT 1 FROM pragma_table_info('inbox_spool') WHERE name = ?1")?
                .exists([column])?;
            if present {
                conn.execute_batch(&format!("ALTER TABLE inbox_spool DROP COLUMN {column};"))?;
            }
        }
        conn.execute_batch("DROP TABLE IF EXISTS devices;")?;
        conn.execute_batch(
            "DROP TABLE IF EXISTS inbox_receipts; DROP TABLE IF EXISTS payment_receipts;
             DROP TABLE IF EXISTS registry_evidence; DROP TABLE IF EXISTS node_registry;
             DROP TABLE IF EXISTS capacity_signals; DROP TABLE IF EXISTS applicants;",
        )?;
        // Which ByteCommit first committed an entry (storage spec §14).
        let has_committed: bool = conn
            .prepare("SELECT 1 FROM pragma_table_info('cells') WHERE name = 'committed_cycle'")?
            .exists([])?;
        if !has_committed {
            conn.execute_batch("ALTER TABLE cells ADD COLUMN committed_cycle INTEGER;")?;
        }
        conn.execute_batch(
            "CREATE INDEX IF NOT EXISTS cells_uncommitted
                 ON cells (seq) WHERE committed_cycle IS NULL;
             CREATE TABLE IF NOT EXISTS own_bytecommits (
                 cycle_index INTEGER PRIMARY KEY,
                 digest      BLOB NOT NULL,
                 commit_pb   BLOB NOT NULL
             );
             CREATE TABLE IF NOT EXISTS bytecommit_mirror (
                 member_id   BLOB NOT NULL,
                 cycle_index INTEGER NOT NULL,
                 digest      BLOB NOT NULL,
                 commit_pb   BLOB NOT NULL,
                 PRIMARY KEY (member_id, cycle_index, digest)
             );",
        )?;
        Ok(())
    })
    .await?;
    // Before the node serves a single put: rows from before arrival records
    // existed get theirs, so no key ever mixes recorded and unrecorded rows.
    backfill_cell_arrival_records(pool).await?;
    Ok(())
}

// ===================== DLV Slots =====================

pub async fn slot_exists(pool: &DBPool, dlv_id: &[u8]) -> Result<bool> {
    let dlv_id = dlv_id.to_vec();
    with_conn(pool, move |conn| {
        let exists: bool = conn
            .query_row(
                "SELECT 1 FROM dlv_slots WHERE dlv_id = ?1 LIMIT 1",
                params![dlv_id],
                |_| Ok(true),
            )
            .optional()?
            .unwrap_or(false);
        Ok(exists)
    })
    .await
}

pub async fn create_slot(
    pool: &DBPool,
    dlv_id: &[u8],
    capacity_bytes: i64,
    stake_hash: &[u8],
) -> Result<()> {
    let dlv_id = dlv_id.to_vec();
    let stake_hash = stake_hash.to_vec();
    with_conn(pool, move |conn| {
        conn.execute(
            "INSERT OR IGNORE INTO dlv_slots (dlv_id, capacity_bytes, used_bytes, stake_hash) VALUES (?1,?2,0,?3)",
            params![dlv_id, capacity_bytes, stake_hash],
        )?;
        Ok(())
    })
    .await
}

// ============================================================
// Phase B.4 (issue #275): Device Tree state — bounded validator
// ============================================================

/// Outcome of a [`upsert_device_tree_state_if_monotonic`] call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceTreeUpsertOutcome {
    /// No prior row existed for this genesis; the row was newly inserted.
    Inserted,
    /// A prior row existed and was replaced because
    /// `new_version > prior_version`.
    Updated { prior_version: u64 },
    /// A prior row existed and the write was rejected because
    /// `new_version <= prior_version`. The persisted state is unchanged.
    RejectedStale { prior_version: u64 },
}

/// Atomically upsert a `DeviceTreeStateV1` row for `genesis_b32`,
/// enforcing strictly-monotonic `version_number`.
///
/// Wraps the read-then-write in a single `BEGIN IMMEDIATE`-equivalent
/// rusqlite transaction so two concurrent writers serialise. Returns
/// [`DeviceTreeUpsertOutcome::Inserted`] / [`Updated`] / [`RejectedStale`]
/// based on what the row looked like before the write.
///
/// `payload` is the canonical `DeviceTreeStateV1` proto bytes the
/// caller already validated upstream (root_hash 32-byte non-zero,
/// device_count >= 1, device_count matches device_ids.len()).
#[allow(clippy::too_many_arguments)]
pub async fn upsert_device_tree_state_if_monotonic(
    pool: &DBPool,
    genesis_b32: &str,
    new_version: u64,
    device_count: u32,
    root_hash: &[u8],
    payload: &[u8],
    updated_at_tick: u64,
) -> Result<DeviceTreeUpsertOutcome> {
    let genesis_b32 = genesis_b32.to_string();
    let new_version_i64 = i64::try_from(new_version)
        .map_err(|_| anyhow!("version_number {new_version} does not fit in i64"))?;
    let device_count_i64 = i64::from(device_count);
    let updated_at_tick_i64 = i64::try_from(updated_at_tick)
        .map_err(|_| anyhow!("updated_at_tick {updated_at_tick} does not fit in i64"))?;
    let root_hash = root_hash.to_vec();
    let payload = payload.to_vec();
    with_conn(pool, move |conn| {
        let tx = conn.unchecked_transaction()?;

        let prior_version_i64: Option<i64> = tx
            .query_row(
                "SELECT version_number FROM device_tree_states WHERE genesis_b32=?1",
                params![genesis_b32],
                |row| row.get(0),
            )
            .optional()?;

        let outcome = match prior_version_i64 {
            Some(prior_i64) => {
                let prior_u64 = u64::try_from(prior_i64).unwrap_or(0);
                if new_version_i64 <= prior_i64 {
                    DeviceTreeUpsertOutcome::RejectedStale {
                        prior_version: prior_u64,
                    }
                } else {
                    tx.execute(
                        "UPDATE device_tree_states
                         SET version_number=?2, device_count=?3, root_hash=?4,
                             payload=?5, updated_at_tick=?6
                         WHERE genesis_b32=?1",
                        params![
                            genesis_b32,
                            new_version_i64,
                            device_count_i64,
                            root_hash,
                            payload,
                            updated_at_tick_i64,
                        ],
                    )?;
                    DeviceTreeUpsertOutcome::Updated {
                        prior_version: prior_u64,
                    }
                }
            }
            None => {
                tx.execute(
                    "INSERT INTO device_tree_states
                       (genesis_b32, version_number, device_count, root_hash, payload, updated_at_tick)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    params![
                        genesis_b32,
                        new_version_i64,
                        device_count_i64,
                        root_hash,
                        payload,
                        updated_at_tick_i64,
                    ],
                )?;
                DeviceTreeUpsertOutcome::Inserted
            }
        };

        tx.commit()?;
        Ok(outcome)
    })
    .await
}

/// Return the persisted `DeviceTreeStateV1` payload bytes for a
/// genesis, or `None` if no state has been written yet.
pub async fn get_device_tree_state_payload(
    pool: &DBPool,
    genesis_b32: &str,
) -> Result<Option<Vec<u8>>> {
    let genesis_b32 = genesis_b32.to_string();
    with_conn(pool, move |conn| {
        let payload: Option<Vec<u8>> = conn
            .query_row(
                "SELECT payload FROM device_tree_states WHERE genesis_b32=?1",
                params![genesis_b32],
                |row| row.get(0),
            )
            .optional()?;
        Ok(payload)
    })
    .await
}

/// Return only the current `version_number` for a genesis's persisted
/// Device Tree state, or `None`. Used by tests asserting monotonic
/// enforcement without re-decoding the full proto.
pub async fn get_device_tree_state_version(
    pool: &DBPool,
    genesis_b32: &str,
) -> Result<Option<u64>> {
    let genesis_b32 = genesis_b32.to_string();
    with_conn(pool, move |conn| {
        let version_i64: Option<i64> = conn
            .query_row(
                "SELECT version_number FROM device_tree_states WHERE genesis_b32=?1",
                params![genesis_b32],
                |row| row.get(0),
            )
            .optional()?;
        Ok(version_i64.map(|v| u64::try_from(v).unwrap_or(0)))
    })
    .await
}

/// Outcome of [`insert_recovery_authority_anchor_if_absent`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecoveryAnchorUpsertOutcome {
    /// No prior anchor existed for this genesis; the row was newly inserted.
    Inserted,
    /// An identical anchor (same `anchor_hash`) already exists — idempotent replay.
    AlreadyExistsIdentical,
    /// A DIFFERENT anchor already exists for this genesis — rejected (bind-once).
    Conflict,
}

/// Single-assignment insert of a recovery-authority anchor, keyed by genesis
/// (spec §0.5 bind-once). First write wins; an identical replay (same
/// `anchor_hash`) is idempotent; any DIFFERENT anchor for the same genesis is
/// rejected. The read-then-write is wrapped in one transaction so concurrent
/// writers serialise. Storage enforces single-assignment ONLY — it does NOT
/// attest recovery validity; clients verify the anchor cryptographically.
pub async fn insert_recovery_authority_anchor_if_absent(
    pool: &DBPool,
    genesis_b32: &str,
    anchor_hash: &[u8],
    payload: &[u8],
    first_written_tick: u64,
) -> Result<RecoveryAnchorUpsertOutcome> {
    let genesis_b32 = genesis_b32.to_string();
    let anchor_hash = anchor_hash.to_vec();
    let payload = payload.to_vec();
    let tick_i64 = i64::try_from(first_written_tick)
        .map_err(|_| anyhow!("first_written_tick {first_written_tick} does not fit in i64"))?;
    with_conn(pool, move |conn| {
        let tx = conn.unchecked_transaction()?;

        let prior_hash: Option<Vec<u8>> = tx
            .query_row(
                "SELECT anchor_hash FROM recovery_authority_anchors WHERE genesis_b32=?1",
                params![genesis_b32],
                |row| row.get(0),
            )
            .optional()?;

        let outcome = match prior_hash {
            Some(existing) if existing == anchor_hash => {
                RecoveryAnchorUpsertOutcome::AlreadyExistsIdentical
            }
            Some(_) => RecoveryAnchorUpsertOutcome::Conflict,
            None => {
                tx.execute(
                    "INSERT INTO recovery_authority_anchors
                       (genesis_b32, anchor_hash, payload, first_written_tick)
                     VALUES (?1, ?2, ?3, ?4)",
                    params![genesis_b32, anchor_hash, payload, tick_i64],
                )?;
                RecoveryAnchorUpsertOutcome::Inserted
            }
        };

        tx.commit()?;
        Ok(outcome)
    })
    .await
}

/// Outcome of [`insert_immutable_object_if_absent`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImmutablePutOutcome {
    /// No object existed at this address; the row was newly inserted.
    Inserted,
    /// The identical `(namespace, payload)` tuple already exists — idempotent.
    AlreadyExistsIdentical,
    /// A DIFFERENT tuple already exists at this address. By construction this
    /// is unreachable without a hash collision or a damaged store, which is
    /// exactly why it is surfaced as its own outcome rather than assumed away.
    Conflict,
}

/// Write-once insert of an immutable object, keyed by content address.
///
/// Idempotence compares the stored `(namespace, payload)` TUPLE, not payload
/// bytes alone: the namespace is stored beside the payload rather than
/// derived from it, so a corrupted or mis-migrated namespace column is
/// exactly the divergence a bytes-only comparison would pass over.
pub async fn insert_immutable_object_if_absent(
    pool: &DBPool,
    addr_b32: &str,
    namespace: &[u8],
    payload: &[u8],
    first_written_tick: u64,
) -> Result<ImmutablePutOutcome> {
    let addr_b32 = addr_b32.to_string();
    let namespace = namespace.to_vec();
    let payload = payload.to_vec();
    let tick_i64 = i64::try_from(first_written_tick)
        .map_err(|_| anyhow!("first_written_tick {first_written_tick} does not fit in i64"))?;
    with_conn(pool, move |conn| {
        let tx = conn.unchecked_transaction()?;

        let prior: Option<(Vec<u8>, Vec<u8>)> = tx
            .query_row(
                "SELECT namespace, payload FROM immutable_objects WHERE addr_b32=?1",
                params![addr_b32],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;

        let outcome = match prior {
            Some((ns, pl)) if ns == namespace && pl == payload => {
                ImmutablePutOutcome::AlreadyExistsIdentical
            }
            Some(_) => ImmutablePutOutcome::Conflict,
            None => {
                tx.execute(
                    "INSERT INTO immutable_objects
                       (addr_b32, namespace, payload, first_written_tick)
                     VALUES (?1, ?2, ?3, ?4)",
                    params![addr_b32, namespace, payload, tick_i64],
                )?;
                ImmutablePutOutcome::Inserted
            }
        };

        tx.commit()?;
        Ok(outcome)
    })
    .await
}

/// Return the `(namespace, payload)` tuple at a content address, or `None`.
pub async fn get_immutable_object(
    pool: &DBPool,
    addr_b32: &str,
) -> Result<Option<(Vec<u8>, Vec<u8>)>> {
    let addr_b32 = addr_b32.to_string();
    with_conn(pool, move |conn| {
        let row: Option<(Vec<u8>, Vec<u8>)> = conn
            .query_row(
                "SELECT namespace, payload FROM immutable_objects WHERE addr_b32=?1",
                params![addr_b32],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        Ok(row)
    })
    .await
}

/// Return the persisted recovery-authority anchor payload bytes for a genesis,
/// or `None` if none has been written.
pub async fn get_recovery_authority_anchor_payload(
    pool: &DBPool,
    genesis_b32: &str,
) -> Result<Option<Vec<u8>>> {
    let genesis_b32 = genesis_b32.to_string();
    with_conn(pool, move |conn| {
        let payload: Option<Vec<u8>> = conn
            .query_row(
                "SELECT payload FROM recovery_authority_anchors WHERE genesis_b32=?1",
                params![genesis_b32],
                |row| row.get(0),
            )
            .optional()?;
        Ok(payload)
    })
    .await
}

// ============================================================
// Append-only Per-Device SMT head chain (spec §0.5 gap 13, R4 layer 1)
// ============================================================

/// Outcome of [`insert_pdsmt_head_if_chained`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PdsmtHeadChainOutcome {
    /// The head was appended at `head_number` (0 = genesis head).
    Appended { head_number: u64 },
    /// A head with the SAME hash already exists at this `head_number` — idempotent replay.
    AlreadyExistsIdentical,
    /// The head does not link the current tip (fork / gap / stale / position mismatch).
    Conflict,
}

/// Append a PDSMT head iff it correctly links the device's current chain tip:
/// the first head must be the genesis head (`head_number == 0`, `parent_head_hash`
/// all-zero); a later head must have `head_number == tip + 1` and
/// `parent_head_hash == tip head_hash`. An identical replay at an existing position
/// is idempotent; anything else is a [`PdsmtHeadChainOutcome::Conflict`]. Read+write
/// run in one transaction so concurrent posters serialise. Append-only: existing rows
/// are never updated or deleted (full history retained for snapshot reads).
#[allow(clippy::too_many_arguments)]
pub async fn insert_pdsmt_head_if_chained(
    pool: &DBPool,
    device_b32: &str,
    head_number: u64,
    head_hash: &[u8],
    parent_head_hash: &[u8],
    payload: &[u8],
    inserted_at_tick: u64,
) -> Result<PdsmtHeadChainOutcome> {
    let device_b32 = device_b32.to_string();
    let head_hash = head_hash.to_vec();
    let parent_head_hash = parent_head_hash.to_vec();
    let payload = payload.to_vec();
    let head_number_i64 = i64::try_from(head_number)
        .map_err(|_| anyhow!("head_number {head_number} does not fit in i64"))?;
    let tick_i64 = i64::try_from(inserted_at_tick)
        .map_err(|_| anyhow!("inserted_at_tick {inserted_at_tick} does not fit in i64"))?;
    with_conn(pool, move |conn| {
        let tx = conn.unchecked_transaction()?;

        // A row already at this position? (idempotent replay vs position fork)
        let at_hash: Option<Vec<u8>> = tx
            .query_row(
                "SELECT head_hash FROM pdsmt_head_chain WHERE device_b32=?1 AND head_number=?2",
                params![device_b32, head_number_i64],
                |row| row.get(0),
            )
            .optional()?;

        let outcome = if let Some(existing) = at_hash {
            if existing == head_hash {
                PdsmtHeadChainOutcome::AlreadyExistsIdentical
            } else {
                PdsmtHeadChainOutcome::Conflict
            }
        } else {
            // Current tip (highest head_number) for this device.
            let tip: Option<(i64, Vec<u8>)> = tx
                .query_row(
                    "SELECT head_number, head_hash FROM pdsmt_head_chain
                     WHERE device_b32=?1 ORDER BY head_number DESC LIMIT 1",
                    params![device_b32],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()?;

            let chains = match &tip {
                None => head_number == 0 && parent_head_hash.iter().all(|&b| b == 0),
                Some((tip_n, tip_hash)) => {
                    let tip_n_u = u64::try_from(*tip_n).unwrap_or(u64::MAX);
                    head_number == tip_n_u.saturating_add(1) && &parent_head_hash == tip_hash
                }
            };

            if chains {
                tx.execute(
                    "INSERT INTO pdsmt_head_chain
                       (device_b32, head_number, head_hash, parent_head_hash, payload, inserted_at_tick)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    params![
                        device_b32,
                        head_number_i64,
                        head_hash,
                        parent_head_hash,
                        payload,
                        tick_i64
                    ],
                )?;
                PdsmtHeadChainOutcome::Appended { head_number }
            } else {
                PdsmtHeadChainOutcome::Conflict
            }
        };

        tx.commit()?;
        Ok(outcome)
    })
    .await
}

/// Return the payload of the device's latest (highest `head_number`) PDSMT head,
/// or `None` if the chain is empty.
pub async fn get_pdsmt_head_latest(pool: &DBPool, device_b32: &str) -> Result<Option<Vec<u8>>> {
    let device_b32 = device_b32.to_string();
    with_conn(pool, move |conn| {
        let payload: Option<Vec<u8>> = conn
            .query_row(
                "SELECT payload FROM pdsmt_head_chain WHERE device_b32=?1
                 ORDER BY head_number DESC LIMIT 1",
                params![device_b32],
                |row| row.get(0),
            )
            .optional()?;
        Ok(payload)
    })
    .await
}

/// Return the payload of the device's PDSMT head at a specific `head_number`
/// (for reading the head at/before the recovery snapshot), or `None`.
pub async fn get_pdsmt_head_at(
    pool: &DBPool,
    device_b32: &str,
    head_number: u64,
) -> Result<Option<Vec<u8>>> {
    let device_b32 = device_b32.to_string();
    let head_number_i64 = i64::try_from(head_number)
        .map_err(|_| anyhow!("head_number {head_number} does not fit in i64"))?;
    with_conn(pool, move |conn| {
        let payload: Option<Vec<u8>> = conn
            .query_row(
                "SELECT payload FROM pdsmt_head_chain WHERE device_b32=?1 AND head_number=?2",
                params![device_b32, head_number_i64],
                |row| row.get(0),
            )
            .optional()?;
        Ok(payload)
    })
    .await
}

// ===================== b0x Inbox Spool (clockless) =====================

pub async fn spool_insert(
    pool: &DBPool,
    device_id: &str,
    message_id: &str,
    envelope: &[u8],
) -> Result<()> {
    let device_id = device_id.to_string();
    let message_id = message_id.to_string();
    let envelope = envelope.to_vec();
    with_conn(pool, move |conn| {
        let tx = conn.unchecked_transaction()?;
        let seq: i64 = tx
            .query_row(
                "SELECT COALESCE(MAX(seq_num), 0) + 1 FROM inbox_spool WHERE device_id = ?1",
                params![device_id],
                |row| row.get(0),
            )?;
        tx.execute(
            "INSERT OR IGNORE INTO inbox_spool(device_id, message_id, envelope, seq_num) VALUES (?1, ?2, ?3, ?4)",
            params![device_id, message_id, envelope, seq],
        )?;
        tx.commit()?;
        Ok(())
    })
    .await
}

/// Every envelope in a spool from a sequence number on, in order, limited.
/// The spool is append-only (storage spec §4): nothing is marked, hidden or
/// removed after a write, and which messages a device has consumed is the
/// device's own state.
pub async fn spool_list_from_seq(
    pool: &DBPool,
    device_id: &str,
    from_seq: i64,
    limit: i64,
) -> Result<Vec<(Vec<u8>, i64)>> {
    let device_id = device_id.to_string();
    with_conn(pool, move |conn| {
        let mut stmt = conn.prepare_cached(
            "SELECT envelope, seq_num FROM inbox_spool
             WHERE device_id=?1 AND seq_num >= ?2
             ORDER BY seq_num ASC LIMIT ?3",
        )?;
        let rows = stmt
            .query_map(params![device_id, from_seq, limit], |row| {
                Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    })
    .await
}

// ===================== Centralized Query Functions =====================

pub async fn get_object_by_key(pool: &DBPool, key: &str) -> Result<Option<Vec<u8>>> {
    let key = key.to_string();
    with_conn(pool, move |conn| {
        let result: Option<Vec<u8>> = conn
            .query_row(
                "SELECT value FROM objects WHERE key=?1 LIMIT 1",
                params![key],
                |row| row.get(0),
            )
            .optional()?;
        Ok(result)
    })
    .await
}

pub async fn get_dlv_slot_capacity(pool: &DBPool, dlv_id: &[u8]) -> Result<Option<(i64, i64)>> {
    let dlv_id = dlv_id.to_vec();
    with_conn(pool, move |conn| {
        let result: Option<(i64, i64)> = conn
            .query_row(
                "SELECT capacity_bytes, used_bytes FROM dlv_slots WHERE dlv_id=?1 LIMIT 1",
                params![dlv_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        Ok(result)
    })
    .await
}

// ===================== PaidK Spend-Gate =====================

// ===================== Node Registry & Signals =====================

// ── keyed cells and indexes: bytes in, bytes out ───────────────────────────

/// Keep `value` for `(namespace, key)`, after anything already held there,
/// and return its arrival record's `(index, running hash)` (storage spec
/// §6, §14). Nothing is compared and nothing is refused.
pub async fn put_cell(
    pool: &DBPool,
    namespace: &[u8],
    key: &[u8],
    value: &[u8],
) -> Result<(u64, [u8; 32])> {
    let (namespace, key, value) = (namespace.to_vec(), key.to_vec(), value.to_vec());
    with_conn(pool, move |conn| {
        let tx = conn.unchecked_transaction()?;
        let record = append_cell_entry(&tx, &namespace, &key, &value)?;
        tx.commit()?;
        Ok(record)
    })
    .await
}

/// Several keys in ONE transaction: every entry is kept after anything
/// already at its key, or none of them is. An entry that names no coordinate
/// — an empty namespace, a key that is not 32 bytes — makes the whole batch
/// nothing. Returns each entry's `(index, running hash)` in batch order.
pub async fn put_cells(
    pool: &DBPool,
    entries: &[(Vec<u8>, Vec<u8>, Vec<u8>)],
) -> Result<Vec<(u64, [u8; 32])>> {
    let entries = entries.to_vec();
    with_conn(pool, move |conn| {
        let tx = conn.unchecked_transaction()?;
        let mut records = Vec::with_capacity(entries.len());
        for (namespace, key, value) in &entries {
            if namespace.is_empty() || key.len() != 32 {
                anyhow::bail!("batch put: an entry names no cell");
            }
            records.push(append_cell_entry(&tx, namespace, key, value)?);
        }
        tx.commit()?;
        Ok(records)
    })
    .await
}

/// Append one entry inside `tx`. The single pooled connection serialises
/// every put, so no two entries can claim one arrival index; the unique
/// index is the backstop.
fn append_cell_entry(
    tx: &rusqlite::Transaction<'_>,
    namespace: &[u8],
    key: &[u8],
    value: &[u8],
) -> Result<(u64, [u8; 32])> {
    let key32: [u8; 32] = key
        .try_into()
        .map_err(|_| anyhow!("cell key is not 32 bytes"))?;
    let last: Option<(i64, Vec<u8>)> = tx
        .query_row(
            "SELECT arrival_index, running_hash FROM cells
             WHERE namespace = ?1 AND cell_key = ?2 AND arrival_index IS NOT NULL
             ORDER BY arrival_index DESC LIMIT 1",
            rusqlite::params![namespace, key],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    let (prev_index, prev_hash) = match last {
        Some((i, h)) => {
            let h: [u8; 32] = h
                .as_slice()
                .try_into()
                .map_err(|_| anyhow!("stored running hash is not 32 bytes"))?;
            (u64::try_from(i)?, h)
        }
        None => (0, dsm::storage_cell::running_hash_init(namespace, &key32)),
    };
    let index = prev_index + 1;
    let running_hash =
        dsm::storage_cell::running_hash_next(&prev_hash, &dsm::storage_cell::entry_digest(value));
    tx.execute(
        "INSERT INTO cells (namespace, cell_key, value, arrival_index, running_hash)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        rusqlite::params![
            namespace,
            key,
            value,
            i64::try_from(index)?,
            running_hash.to_vec()
        ],
    )?;
    Ok((index, running_hash))
}

/// Everything held for `(namespace, key)`, in the order it arrived.
pub async fn get_cell_values(pool: &DBPool, namespace: &[u8], key: &[u8]) -> Result<Vec<Vec<u8>>> {
    Ok(get_cell_entries(pool, namespace, key)
        .await?
        .into_iter()
        .map(|(v, _, _)| v)
        .collect())
}

/// Everything held for `(namespace, key)`, in arrival order, each with its
/// `(index, running hash)`.
pub async fn get_cell_entries(
    pool: &DBPool,
    namespace: &[u8],
    key: &[u8],
) -> Result<Vec<(Vec<u8>, u64, [u8; 32])>> {
    let (namespace, key) = (namespace.to_vec(), key.to_vec());
    with_conn(pool, move |conn| {
        let mut stmt = conn.prepare(
            "SELECT value, arrival_index, running_hash FROM cells
             WHERE namespace = ?1 AND cell_key = ?2 ORDER BY seq ASC",
        )?;
        let rows = stmt.query_map(rusqlite::params![namespace, key], |r| {
            Ok((
                r.get::<_, Vec<u8>>(0)?,
                r.get::<_, Option<i64>>(1)?,
                r.get::<_, Option<Vec<u8>>>(2)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (v, i, h) = row?;
            let (Some(i), Some(h)) = (i, h) else {
                anyhow::bail!("cell entry has no arrival record; backfill has not run");
            };
            let h: [u8; 32] = h
                .as_slice()
                .try_into()
                .map_err(|_| anyhow!("stored running hash is not 32 bytes"))?;
            out.push((v, u64::try_from(i)?, h));
        }
        Ok(out)
    })
    .await
}

/// Give every entry of every key that holds an entry without an arrival
/// record its record: the key's values replayed in arrival (`seq`) order,
/// exactly as storage spec §14 defines `(i, h_i)`. The key's indexes are
/// cleared first so the unique arrival index never sees two rows claim one
/// position mid-rewrite. Only the two metadata columns are written; no value
/// is touched.
pub async fn backfill_cell_arrival_records(pool: &DBPool) -> Result<u64> {
    with_conn(pool, move |conn| {
        let keys: Vec<(Vec<u8>, Vec<u8>)> = conn
            .prepare("SELECT DISTINCT namespace, cell_key FROM cells WHERE arrival_index IS NULL")?
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect::<std::result::Result<_, _>>()?;
        let mut fixed = 0u64;
        for (namespace, key) in keys {
            let key32: [u8; 32] = key
                .as_slice()
                .try_into()
                .map_err(|_| anyhow!("a held cell key is not 32 bytes"))?;
            let tx = conn.unchecked_transaction()?;
            let rows: Vec<(i64, Vec<u8>)> = tx
                .prepare(
                    "SELECT seq, value FROM cells WHERE namespace = ?1 AND cell_key = ?2
                     ORDER BY seq ASC",
                )?
                .query_map(rusqlite::params![namespace, key], |r| {
                    Ok((r.get(0)?, r.get(1)?))
                })?
                .collect::<std::result::Result<_, _>>()?;
            tx.execute(
                "UPDATE cells SET arrival_index = NULL, running_hash = NULL
                 WHERE namespace = ?1 AND cell_key = ?2",
                rusqlite::params![namespace, key],
            )?;
            let mut h = dsm::storage_cell::running_hash_init(&namespace, &key32);
            for (n, (seq, value)) in rows.iter().enumerate() {
                h = dsm::storage_cell::running_hash_next(
                    &h,
                    &dsm::storage_cell::entry_digest(value),
                );
                tx.execute(
                    "UPDATE cells SET arrival_index = ?2, running_hash = ?3 WHERE seq = ?1",
                    rusqlite::params![seq, n as i64 + 1, h.to_vec()],
                )?;
            }
            tx.commit()?;
            fixed += 1;
        }
        Ok(fixed)
    })
    .await
}

/// A cell row exactly as a binary from before arrival records wrote it: the
/// value and nothing else. Unit tests only.
#[cfg(test)]
pub(crate) async fn insert_cell_without_record(
    pool: &DBPool,
    namespace: &[u8],
    key: &[u8],
    value: &[u8],
) -> Result<()> {
    let (namespace, key, value) = (namespace.to_vec(), key.to_vec(), value.to_vec());
    with_conn(pool, move |conn| {
        conn.execute(
            "INSERT INTO cells (namespace, cell_key, value) VALUES (?1, ?2, ?3)",
            rusqlite::params![namespace, key, value],
        )?;
        Ok(())
    })
    .await
}

// ── ByteCommits (storage spec §14) ─────────────────────────────────────────

/// Close the next cycle if any cell entry has arrived since the last one.
/// See the Postgres backend for the contract; the single pooled connection
/// serialises closers and puts here.
pub async fn close_cycle(
    pool: &DBPool,
    member_id: &[u8],
) -> Result<Option<dsm::storage_cell::ByteCommit>> {
    if member_id.is_empty() || member_id.len() > dsm::storage_cell::MAX_MEMBER_ID_LEN {
        anyhow::bail!("member id cannot name a ByteCommit");
    }
    let member_id = member_id.to_vec();
    with_conn(pool, move |conn| {
        use prost::Message;
        let tx = conn.unchecked_transaction()?;
        let last = tx
            .query_row(
                "SELECT commit_pb FROM own_bytecommits ORDER BY cycle_index DESC LIMIT 1",
                [],
                |r| r.get::<_, Vec<u8>>(0),
            )
            .optional()?
            .map(|b| decode_commit(&b))
            .transpose()?;
        let pending: bool = tx
            .prepare("SELECT 1 FROM cells WHERE committed_cycle IS NULL LIMIT 1")?
            .exists([])?;
        if !pending {
            tx.commit()?;
            return Ok(last);
        }
        let cycle = last.as_ref().map_or(1, |c| c.cycle_index + 1);
        let cycle_i64 = i64::try_from(cycle)?;
        tx.execute(
            "UPDATE cells SET committed_cycle = ?1 WHERE committed_cycle IS NULL",
            params![cycle_i64],
        )?;
        let leaves = cell_leaves(&tx, cycle_i64)?;
        let tree = dsm::storage_cell::cell_tree(
            leaves.iter().map(|(n, k, i, h)| (n.as_slice(), k, *i, h)),
        );
        let bytes_used: i64 = tx.query_row(
            "SELECT COALESCE((SELECT SUM(LENGTH(value)) FROM cells), 0)
                  + COALESCE((SELECT SUM(LENGTH(payload)) FROM immutable_objects), 0)",
            [],
            |r| r.get(0),
        )?;
        let commit = dsm::storage_cell::ByteCommit {
            member_id: member_id.clone(),
            cycle_index: cycle,
            smt_root: *tree.root(),
            bytes_used: u64::try_from(bytes_used.max(0))?,
            parent_digest: last.as_ref().map_or([0u8; 32], |c| c.digest()),
        };
        let digest = commit.digest();
        tx.execute(
            "INSERT INTO own_bytecommits (cycle_index, digest, commit_pb) VALUES (?1, ?2, ?3)",
            params![
                cycle_i64,
                digest.to_vec(),
                commit.to_proto().encode_to_vec()
            ],
        )?;
        tx.commit()?;
        Ok(Some(commit))
    })
    .await
}

fn decode_commit(bytes: &[u8]) -> Result<dsm::storage_cell::ByteCommit> {
    use prost::Message;
    let p = dsm::types::proto::ByteCommitV4::decode(bytes)?;
    dsm::storage_cell::ByteCommit::from_proto(&p)
        .ok_or_else(|| anyhow!("stored ByteCommit is malformed"))
}

type CellLeaf = (Vec<u8>, [u8; 32], u64, [u8; 32]);

/// Every cell's latest entry committed at or before `cycle`. Committed
/// entries are a prefix of each key's arrival order, so the latest is the
/// highest committed index.
fn cell_leaves(conn: &Connection, cycle: i64) -> Result<Vec<CellLeaf>> {
    let mut stmt = conn.prepare(
        "SELECT namespace, cell_key, arrival_index, running_hash FROM cells c
         WHERE committed_cycle <= ?1
           AND arrival_index = (SELECT MAX(arrival_index) FROM cells c2
                                WHERE c2.namespace = c.namespace
                                  AND c2.cell_key = c.cell_key
                                  AND c2.committed_cycle <= ?1)",
    )?;
    let rows = stmt.query_map(params![cycle], |r| {
        Ok((
            r.get::<_, Vec<u8>>(0)?,
            r.get::<_, Vec<u8>>(1)?,
            r.get::<_, i64>(2)?,
            r.get::<_, Vec<u8>>(3)?,
        ))
    })?;
    let mut out = Vec::new();
    for row in rows {
        let (n, k, i, h) = row?;
        out.push((
            n,
            k.as_slice()
                .try_into()
                .map_err(|_| anyhow!("cell key is not 32 bytes"))?,
            u64::try_from(i)?,
            h.as_slice()
                .try_into()
                .map_err(|_| anyhow!("stored running hash is not 32 bytes"))?,
        ));
    }
    Ok(out)
}

/// This node's ByteCommit for `cycle`, or its latest when `cycle` is `None`.
pub async fn get_own_bytecommit(
    pool: &DBPool,
    cycle: Option<u64>,
) -> Result<Option<dsm::storage_cell::ByteCommit>> {
    with_conn(pool, move |conn| {
        let bytes: Option<Vec<u8>> = match cycle {
            Some(t) => conn
                .query_row(
                    "SELECT commit_pb FROM own_bytecommits WHERE cycle_index = ?1",
                    params![i64::try_from(t)?],
                    |r| r.get(0),
                )
                .optional()?,
            None => conn
                .query_row(
                    "SELECT commit_pb FROM own_bytecommits ORDER BY cycle_index DESC LIMIT 1",
                    [],
                    |r| r.get(0),
                )
                .optional()?,
        };
        bytes.map(|b| decode_commit(&b)).transpose()
    })
    .await
}

/// The proof that this node's ByteCommit for `cycle` commits `(namespace,
/// key)`'s latest entry as of that cycle.
pub async fn cell_commit_proof(
    pool: &DBPool,
    namespace: &[u8],
    key: &[u8; 32],
    cycle: u64,
) -> Result<Option<dsm::storage_cell::CellCommitProof>> {
    let (namespace, key) = (namespace.to_vec(), *key);
    with_conn(pool, move |conn| {
        let cycle_i64 = i64::try_from(cycle)?;
        let exists = conn
            .prepare("SELECT 1 FROM own_bytecommits WHERE cycle_index = ?1")?
            .exists(params![cycle_i64])?;
        if !exists {
            return Ok(None);
        }
        let leaves = cell_leaves(conn, cycle_i64)?;
        let Some((_, _, index, running_hash)) = leaves
            .iter()
            .find(|(n, k, _, _)| *n == namespace && *k == key)
            .cloned()
        else {
            return Ok(None);
        };
        let tree = dsm::storage_cell::cell_tree(
            leaves.iter().map(|(n, k, i, h)| (n.as_slice(), k, *i, h)),
        );
        Ok(dsm::storage_cell::CellCommitProof::from_tree(
            &tree,
            &namespace,
            &key,
            index,
            running_hash,
        ))
    })
    .await
}

/// Keep a ByteCommit this node fetched from its member itself. Returns
/// whether it was not already held.
pub async fn mirror_put(pool: &DBPool, commit: &dsm::storage_cell::ByteCommit) -> Result<bool> {
    let commit = commit.clone();
    with_conn(pool, move |conn| {
        use prost::Message;
        let inserted = conn.execute(
            "INSERT OR IGNORE INTO bytecommit_mirror (member_id, cycle_index, digest, commit_pb)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                commit.member_id,
                i64::try_from(commit.cycle_index)?,
                commit.digest().to_vec(),
                commit.to_proto().encode_to_vec()
            ],
        )?;
        Ok(inserted == 1)
    })
    .await
}

/// Every distinct ByteCommit this node mirrored for `member_id` at `cycle`.
pub async fn mirror_get(
    pool: &DBPool,
    member_id: &[u8],
    cycle: u64,
) -> Result<Vec<dsm::storage_cell::ByteCommit>> {
    let member_id = member_id.to_vec();
    with_conn(pool, move |conn| {
        let mut stmt = conn.prepare(
            "SELECT commit_pb FROM bytecommit_mirror
             WHERE member_id = ?1 AND cycle_index = ?2 ORDER BY digest",
        )?;
        let rows = stmt.query_map(params![member_id, i64::try_from(cycle)?], |r| {
            r.get::<_, Vec<u8>>(0)
        })?;
        let mut out = Vec::new();
        for row in rows {
            out.push(decode_commit(&row?)?);
        }
        Ok(out)
    })
    .await
}

/// The highest cycle mirrored for `member_id`, 0 if none.
pub async fn mirror_last_cycle(pool: &DBPool, member_id: &[u8]) -> Result<u64> {
    let member_id = member_id.to_vec();
    with_conn(pool, move |conn| {
        let t: Option<i64> = conn.query_row(
            "SELECT MAX(cycle_index) FROM bytecommit_mirror WHERE member_id = ?1",
            params![member_id],
            |r| r.get(0),
        )?;
        Ok(u64::try_from(t.unwrap_or(0))?)
    })
    .await
}

/// Append a content address under `locator`. Never removed.
pub async fn append_index(pool: &DBPool, locator: &[u8], addr: &[u8]) -> Result<()> {
    let (locator, addr) = (locator.to_vec(), addr.to_vec());
    with_conn(pool, move |conn| {
        conn.execute(
            "INSERT INTO index_entries (locator, addr) VALUES (?1, ?2)",
            rusqlite::params![locator, addr],
        )?;
        Ok(())
    })
    .await
}

/// Addresses under `locator` with `seq > after`, in append order, at most
/// `limit`. Returns `(seq, addr)` so a reader can page from the last `seq`.
pub async fn read_index(
    pool: &DBPool,
    locator: &[u8],
    after: i64,
    limit: i64,
) -> Result<Vec<(i64, Vec<u8>)>> {
    let locator = locator.to_vec();
    with_conn(pool, move |conn| {
        let mut stmt = conn.prepare(
            "SELECT seq, addr FROM index_entries WHERE locator = ?1 AND seq > ?2 \
             ORDER BY seq ASC LIMIT ?3",
        )?;
        let rows = stmt.query_map(rusqlite::params![locator, after, limit], |r| {
            Ok((r.get::<_, i64>(0)?, r.get::<_, Vec<u8>>(1)?))
        })?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    })
    .await
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)] // unwrap/expect acceptable in deterministic tests
mod tests {
    use super::*;

    // -----------------------------------------------------------------
    // Phase B.4 (issue #275) — atomic monotonic Device Tree state upsert.
    // -----------------------------------------------------------------

    async fn make_inmem_pool() -> DBPool {
        // Each test gets its own private in-memory DB so they don't
        // collide on shared file state.
        let conn = Connection::open_in_memory().expect("open :memory:");
        conn.execute_batch("PRAGMA foreign_keys=ON;")
            .expect("pragma");
        let pool = Arc::new(Mutex::new(conn));
        init_db(&pool).await.expect("init schema");
        pool
    }

    // -----------------------------------------------------------------
    // Area 4 — immutable object store: write-once on the TUPLE.
    // -----------------------------------------------------------------

    /// Obligation: idempotence on the tuple. Two puts of the identical
    /// `(namespace, payload)` leave one row; a differing PAYLOAD at the same
    /// address is a conflict; and a differing NAMESPACE with the identical
    /// payload is ALSO a conflict — the case a bytes-only comparison would
    /// pass over, which is why the comparison is on the tuple.
    #[tokio::test]
    async fn immutable_put_is_write_once_on_the_tuple() {
        let pool = make_inmem_pool().await;
        let addr = "ADDR1";
        let ns = b"DSM/vault-state".to_vec();
        let payload = b"canonical bytes".to_vec();

        let first = insert_immutable_object_if_absent(&pool, addr, &ns, &payload, 1)
            .await
            .expect("insert");
        assert_eq!(first, ImmutablePutOutcome::Inserted);

        let replay = insert_immutable_object_if_absent(&pool, addr, &ns, &payload, 2)
            .await
            .expect("replay");
        assert_eq!(replay, ImmutablePutOutcome::AlreadyExistsIdentical);

        let other_payload = insert_immutable_object_if_absent(&pool, addr, &ns, b"different", 3)
            .await
            .expect("query");
        assert_eq!(other_payload, ImmutablePutOutcome::Conflict);

        let other_ns =
            insert_immutable_object_if_absent(&pool, addr, b"DSM/genesis/v3", &payload, 4)
                .await
                .expect("query");
        assert_eq!(
            other_ns,
            ImmutablePutOutcome::Conflict,
            "a mutated namespace with identical payload must NOT re-ack"
        );

        let (got_ns, got_payload) = get_immutable_object(&pool, addr)
            .await
            .expect("get")
            .expect("present");
        assert_eq!(got_ns, ns);
        assert_eq!(got_payload, payload);
    }

    /// Obligation: no overwrite path exists — behaviourally, the losing write
    /// leaves the first tuple untouched.
    #[tokio::test]
    async fn a_conflicting_put_leaves_the_first_write_untouched() {
        let pool = make_inmem_pool().await;
        insert_immutable_object_if_absent(&pool, "A", b"DSM/vault-state", b"first", 1)
            .await
            .expect("insert");
        let _ = insert_immutable_object_if_absent(&pool, "A", b"DSM/vault-state", b"second", 2)
            .await
            .expect("query");
        let (_, payload) = get_immutable_object(&pool, "A")
            .await
            .expect("get")
            .expect("present");
        assert_eq!(payload, b"first".to_vec());
    }

    #[tokio::test]
    async fn devtree_first_insert_returns_inserted() {
        let pool = make_inmem_pool().await;
        let outcome = upsert_device_tree_state_if_monotonic(
            &pool,
            "GENESISA",
            1,
            1,
            &[0x11u8; 32],
            b"payload1",
            42,
        )
        .await
        .expect("insert");
        assert_eq!(outcome, DeviceTreeUpsertOutcome::Inserted);

        let v = get_device_tree_state_version(&pool, "GENESISA")
            .await
            .expect("read");
        assert_eq!(v, Some(1u64));
        let p = get_device_tree_state_payload(&pool, "GENESISA")
            .await
            .expect("read payload");
        assert_eq!(p.as_deref(), Some(b"payload1".as_ref()));
    }

    // -----------------------------------------------------------------
    // Recovery-authority anchor — single-assignment / bind-once (§0.5).
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn recovery_anchor_first_write_inserts() {
        let pool = make_inmem_pool().await;
        let outcome = insert_recovery_authority_anchor_if_absent(
            &pool,
            "GENESISA",
            &[0xAB; 32],
            b"anchor-bytes-1",
            7,
        )
        .await
        .expect("insert");
        assert_eq!(outcome, RecoveryAnchorUpsertOutcome::Inserted);
        let p = get_recovery_authority_anchor_payload(&pool, "GENESISA")
            .await
            .expect("read");
        assert_eq!(p.as_deref(), Some(b"anchor-bytes-1".as_ref()));
    }

    #[tokio::test]
    async fn recovery_anchor_identical_replay_is_idempotent() {
        let pool = make_inmem_pool().await;
        insert_recovery_authority_anchor_if_absent(
            &pool,
            "GENESISA",
            &[0xAB; 32],
            b"anchor-bytes-1",
            7,
        )
        .await
        .unwrap();
        // Same genesis, same anchor_hash (even with a different tick) → idempotent.
        let outcome = insert_recovery_authority_anchor_if_absent(
            &pool,
            "GENESISA",
            &[0xAB; 32],
            b"anchor-bytes-1",
            99,
        )
        .await
        .unwrap();
        assert_eq!(outcome, RecoveryAnchorUpsertOutcome::AlreadyExistsIdentical);
        let p = get_recovery_authority_anchor_payload(&pool, "GENESISA")
            .await
            .unwrap();
        assert_eq!(p.as_deref(), Some(b"anchor-bytes-1".as_ref()));
    }

    #[tokio::test]
    async fn recovery_anchor_different_same_genesis_conflicts() {
        let pool = make_inmem_pool().await;
        insert_recovery_authority_anchor_if_absent(
            &pool,
            "GENESISA",
            &[0xAB; 32],
            b"anchor-bytes-1",
            7,
        )
        .await
        .unwrap();
        // Same genesis, DIFFERENT anchor_hash → bind-once rejects (no overwrite).
        let outcome = insert_recovery_authority_anchor_if_absent(
            &pool,
            "GENESISA",
            &[0xCD; 32],
            b"anchor-bytes-2",
            8,
        )
        .await
        .unwrap();
        assert_eq!(outcome, RecoveryAnchorUpsertOutcome::Conflict);
        // The first anchor is preserved unchanged.
        let p = get_recovery_authority_anchor_payload(&pool, "GENESISA")
            .await
            .unwrap();
        assert_eq!(p.as_deref(), Some(b"anchor-bytes-1".as_ref()));
    }

    #[tokio::test]
    async fn recovery_anchor_different_genesis_succeeds() {
        let pool = make_inmem_pool().await;
        insert_recovery_authority_anchor_if_absent(&pool, "GENESISA", &[0xAB; 32], b"anchor-a", 7)
            .await
            .unwrap();
        let outcome = insert_recovery_authority_anchor_if_absent(
            &pool,
            "GENESISB",
            &[0xCD; 32],
            b"anchor-b",
            8,
        )
        .await
        .unwrap();
        assert_eq!(outcome, RecoveryAnchorUpsertOutcome::Inserted);
    }

    // -----------------------------------------------------------------
    // Append-only PDSMT head chain (§0.5 gap 13, R4 layer 1).
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn pdsmt_head_genesis_appends_then_valid_child_appends() {
        let pool = make_inmem_pool().await;
        let h0 = [0x10u8; 32];
        let o0 = insert_pdsmt_head_if_chained(&pool, "DEVA", 0, &h0, &[0u8; 32], b"head0", 1)
            .await
            .unwrap();
        assert_eq!(o0, PdsmtHeadChainOutcome::Appended { head_number: 0 });

        let h1 = [0x11u8; 32];
        // Valid child: head_number 1, parent == h0.
        let o1 = insert_pdsmt_head_if_chained(&pool, "DEVA", 1, &h1, &h0, b"head1", 2)
            .await
            .unwrap();
        assert_eq!(o1, PdsmtHeadChainOutcome::Appended { head_number: 1 });

        assert_eq!(
            get_pdsmt_head_latest(&pool, "DEVA")
                .await
                .unwrap()
                .as_deref(),
            Some(b"head1".as_ref())
        );
        // History retained: head at/before snapshot reads the older head.
        assert_eq!(
            get_pdsmt_head_at(&pool, "DEVA", 0)
                .await
                .unwrap()
                .as_deref(),
            Some(b"head0".as_ref())
        );
    }

    #[tokio::test]
    async fn pdsmt_head_non_genesis_first_rejected() {
        let pool = make_inmem_pool().await;
        // First head must be genesis (number 0, zero parent).
        let bad_num =
            insert_pdsmt_head_if_chained(&pool, "DEVA", 1, &[0x10; 32], &[0u8; 32], b"x", 1)
                .await
                .unwrap();
        assert_eq!(bad_num, PdsmtHeadChainOutcome::Conflict);
        let bad_parent =
            insert_pdsmt_head_if_chained(&pool, "DEVA", 0, &[0x10; 32], &[0x99; 32], b"x", 1)
                .await
                .unwrap();
        assert_eq!(bad_parent, PdsmtHeadChainOutcome::Conflict);
    }

    #[tokio::test]
    async fn pdsmt_head_fork_and_gap_rejected() {
        let pool = make_inmem_pool().await;
        let h0 = [0x10u8; 32];
        insert_pdsmt_head_if_chained(&pool, "DEVA", 0, &h0, &[0u8; 32], b"head0", 1)
            .await
            .unwrap();
        // Fork: head_number 1 but parent != h0.
        let fork =
            insert_pdsmt_head_if_chained(&pool, "DEVA", 1, &[0x11; 32], &[0xEE; 32], b"f", 2)
                .await
                .unwrap();
        assert_eq!(fork, PdsmtHeadChainOutcome::Conflict);
        // Gap: head_number 2 with no head 1 yet.
        let gap = insert_pdsmt_head_if_chained(&pool, "DEVA", 2, &[0x12; 32], &h0, b"g", 3)
            .await
            .unwrap();
        assert_eq!(gap, PdsmtHeadChainOutcome::Conflict);
    }

    #[tokio::test]
    async fn pdsmt_head_replay_idempotent_but_position_fork_conflicts() {
        let pool = make_inmem_pool().await;
        let h0 = [0x10u8; 32];
        insert_pdsmt_head_if_chained(&pool, "DEVA", 0, &h0, &[0u8; 32], b"head0", 1)
            .await
            .unwrap();
        // Identical replay at position 0 → idempotent.
        let replay = insert_pdsmt_head_if_chained(&pool, "DEVA", 0, &h0, &[0u8; 32], b"head0", 9)
            .await
            .unwrap();
        assert_eq!(replay, PdsmtHeadChainOutcome::AlreadyExistsIdentical);
        // DIFFERENT head at the same position → conflict (no overwrite).
        let fork0 =
            insert_pdsmt_head_if_chained(&pool, "DEVA", 0, &[0xAB; 32], &[0u8; 32], b"evil", 9)
                .await
                .unwrap();
        assert_eq!(fork0, PdsmtHeadChainOutcome::Conflict);
        assert_eq!(
            get_pdsmt_head_latest(&pool, "DEVA")
                .await
                .unwrap()
                .as_deref(),
            Some(b"head0".as_ref())
        );
    }

    #[tokio::test]
    async fn pdsmt_head_distinct_devices_independent() {
        let pool = make_inmem_pool().await;
        let a = insert_pdsmt_head_if_chained(&pool, "DEVA", 0, &[0x10; 32], &[0u8; 32], b"a0", 1)
            .await
            .unwrap();
        let b = insert_pdsmt_head_if_chained(&pool, "DEVB", 0, &[0x20; 32], &[0u8; 32], b"b0", 1)
            .await
            .unwrap();
        assert_eq!(a, PdsmtHeadChainOutcome::Appended { head_number: 0 });
        assert_eq!(b, PdsmtHeadChainOutcome::Appended { head_number: 0 });
    }

    #[tokio::test]
    async fn devtree_strictly_greater_version_is_accepted() {
        let pool = make_inmem_pool().await;
        upsert_device_tree_state_if_monotonic(
            &pool,
            "GENESISA",
            1,
            1,
            &[0x11u8; 32],
            b"payload1",
            10,
        )
        .await
        .expect("v1");
        let outcome = upsert_device_tree_state_if_monotonic(
            &pool,
            "GENESISA",
            2,
            2,
            &[0x22u8; 32],
            b"payload2",
            11,
        )
        .await
        .expect("v2");
        assert_eq!(
            outcome,
            DeviceTreeUpsertOutcome::Updated { prior_version: 1 }
        );

        let v = get_device_tree_state_version(&pool, "GENESISA")
            .await
            .expect("read");
        assert_eq!(v, Some(2u64));
        let p = get_device_tree_state_payload(&pool, "GENESISA")
            .await
            .expect("read payload");
        assert_eq!(p.as_deref(), Some(b"payload2".as_ref()));
    }

    #[tokio::test]
    async fn devtree_equal_version_is_rejected_as_stale() {
        let pool = make_inmem_pool().await;
        upsert_device_tree_state_if_monotonic(
            &pool,
            "GENESISA",
            5,
            1,
            &[0x11u8; 32],
            b"payload-v5",
            10,
        )
        .await
        .expect("v5");
        let outcome = upsert_device_tree_state_if_monotonic(
            &pool,
            "GENESISA",
            5,
            1,
            &[0x99u8; 32],
            b"payload-replay",
            11,
        )
        .await
        .expect("replay");
        assert_eq!(
            outcome,
            DeviceTreeUpsertOutcome::RejectedStale { prior_version: 5 }
        );

        // Persisted state must be unchanged.
        let p = get_device_tree_state_payload(&pool, "GENESISA")
            .await
            .expect("read");
        assert_eq!(p.as_deref(), Some(b"payload-v5".as_ref()));
    }

    #[tokio::test]
    async fn devtree_lesser_version_is_rejected_as_stale() {
        let pool = make_inmem_pool().await;
        upsert_device_tree_state_if_monotonic(
            &pool,
            "GENESISA",
            10,
            1,
            &[0x11u8; 32],
            b"payload-v10",
            10,
        )
        .await
        .expect("v10");
        let outcome = upsert_device_tree_state_if_monotonic(
            &pool,
            "GENESISA",
            3,
            1,
            &[0x33u8; 32],
            b"payload-v3",
            11,
        )
        .await
        .expect("attempt v3");
        assert_eq!(
            outcome,
            DeviceTreeUpsertOutcome::RejectedStale { prior_version: 10 }
        );
        let p = get_device_tree_state_payload(&pool, "GENESISA")
            .await
            .expect("read");
        assert_eq!(p.as_deref(), Some(b"payload-v10".as_ref()));
    }

    #[tokio::test]
    async fn devtree_different_genesis_keys_are_isolated() {
        let pool = make_inmem_pool().await;
        let a = upsert_device_tree_state_if_monotonic(
            &pool,
            "GENESISA",
            1,
            1,
            &[0x11u8; 32],
            b"a-v1",
            10,
        )
        .await
        .expect("a v1");
        let b = upsert_device_tree_state_if_monotonic(
            &pool,
            "GENESISB",
            1,
            1,
            &[0x22u8; 32],
            b"b-v1",
            10,
        )
        .await
        .expect("b v1");
        assert_eq!(a, DeviceTreeUpsertOutcome::Inserted);
        assert_eq!(b, DeviceTreeUpsertOutcome::Inserted);

        let v_a = get_device_tree_state_version(&pool, "GENESISA")
            .await
            .expect("read a");
        let v_b = get_device_tree_state_version(&pool, "GENESISB")
            .await
            .expect("read b");
        assert_eq!(v_a, Some(1u64));
        assert_eq!(v_b, Some(1u64));
    }

    #[tokio::test]
    async fn devtree_get_returns_none_when_absent() {
        let pool = make_inmem_pool().await;
        let v = get_device_tree_state_version(&pool, "DOES_NOT_EXIST")
            .await
            .expect("read");
        assert_eq!(v, None);
        let p = get_device_tree_state_payload(&pool, "DOES_NOT_EXIST")
            .await
            .expect("read payload");
        assert!(p.is_none());
    }
}
