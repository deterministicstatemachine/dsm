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

// ===================== Durable Replication Outbox (clockless) =====================

/// A pending outbox row loaded from the DB.
#[derive(Debug, Clone)]
pub struct ReplicationOutboxRow {
    pub id: i64,
    pub target: String,
    pub method: String,
    pub path: String,
    pub headers: Vec<u8>,
    pub body: Vec<u8>,
    pub idempotency_key: String,
    pub attempts: i32,
    pub eligible_iter: i64,
}

/// Parameters for enqueuing a replication outbox entry.
#[derive(Debug, Clone, Copy)]
pub struct ReplicationOutboxEnqueueParams<'a> {
    pub target: &'a str,
    pub method: &'a str,
    pub path: &'a str,
    pub headers: &'a [u8],
    pub body: &'a [u8],
    pub idempotency_key: &'a str,
    pub eligible_iter: i64,
}

/// Deterministically encode HTTP headers to bytes.
pub fn encode_headers_deterministic(headers: &[(String, Vec<u8>)]) -> Vec<u8> {
    let mut items: Vec<(Vec<u8>, Vec<u8>)> = headers
        .iter()
        .map(|(k, v)| (k.to_ascii_lowercase().into_bytes(), v.clone()))
        .collect();
    items.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));

    let mut out = Vec::new();
    for (k, v) in items {
        let klen: u16 = u16::try_from(k.len()).unwrap_or(u16::MAX);
        let vlen: u32 = u32::try_from(v.len()).unwrap_or(u32::MAX);
        out.extend_from_slice(&klen.to_le_bytes());
        out.extend_from_slice(&k[..(klen as usize)]);
        out.extend_from_slice(&vlen.to_le_bytes());
        out.extend_from_slice(&v[..(vlen as usize)]);
    }
    out
}

/// Decode deterministic header bytes back into pairs.
pub fn decode_headers_deterministic(mut bytes: &[u8]) -> Result<Vec<(String, Vec<u8>)>> {
    let mut out: Vec<(String, Vec<u8>)> = Vec::new();
    while !bytes.is_empty() {
        if bytes.len() < 2 {
            return Err(anyhow!("header decode: truncated k_len"));
        }
        let mut klen_b = [0u8; 2];
        klen_b.copy_from_slice(&bytes[..2]);
        bytes = &bytes[2..];
        let klen = u16::from_le_bytes(klen_b) as usize;
        if bytes.len() < klen {
            return Err(anyhow!("header decode: truncated key"));
        }
        let k = bytes[..klen].to_vec();
        bytes = &bytes[klen..];

        if bytes.len() < 4 {
            return Err(anyhow!("header decode: truncated v_len"));
        }
        let mut vlen_b = [0u8; 4];
        vlen_b.copy_from_slice(&bytes[..4]);
        bytes = &bytes[4..];
        let vlen = u32::from_le_bytes(vlen_b) as usize;
        if bytes.len() < vlen {
            return Err(anyhow!("header decode: truncated value"));
        }
        let v = bytes[..vlen].to_vec();
        bytes = &bytes[vlen..];

        let k = String::from_utf8(k).map_err(|_| anyhow!("header decode: non-utf8 key"))?;
        out.push((k, v));
    }
    Ok(out)
}

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

/// Initialize database schema (SQLite version).
pub async fn init_db(pool: &DBPool) -> Result<()> {
    with_conn(pool, |conn| {
        conn.execute_batch(
            r#"CREATE TABLE IF NOT EXISTS dlv_slots (
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

                CREATE TABLE IF NOT EXISTS registry_evidence (
                    addr        TEXT PRIMARY KEY,
                    kind_code   INTEGER NOT NULL,
                    dlv_id      BLOB NOT NULL,
                    size_bytes  INTEGER NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_registry_evidence_kind ON registry_evidence(kind_code);

                CREATE TABLE IF NOT EXISTS replication_outbox (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    target          TEXT NOT NULL,
                    method          TEXT NOT NULL,
                    path            TEXT NOT NULL,
                    headers         BLOB NOT NULL,
                    body            BLOB NOT NULL,
                    idempotency_key TEXT NOT NULL,
                    attempts        INTEGER NOT NULL DEFAULT 0,
                    eligible_iter   INTEGER NOT NULL DEFAULT 0,
                    done            INTEGER NOT NULL DEFAULT 0,
                    last_err        TEXT
                );

                CREATE UNIQUE INDEX IF NOT EXISTS ux_replication_outbox_idem_target
                    ON replication_outbox(target, idempotency_key);

                CREATE INDEX IF NOT EXISTS idx_replication_outbox_due
                    ON replication_outbox(done, eligible_iter, id);

                CREATE TABLE IF NOT EXISTS devices (
                    device_id        TEXT PRIMARY KEY,
                    genesis_hash     BLOB NOT NULL,
                    pubkey           BLOB NOT NULL,
                    token_hash       BLOB NOT NULL,
                    kyber_public_key  BLOB NOT NULL,
                    kyber_binding_sig BLOB NOT NULL,
                    revoked          INTEGER NOT NULL DEFAULT 0,
                    paidk_satisfied  INTEGER NOT NULL DEFAULT 0
                );

                CREATE TABLE IF NOT EXISTS inbox_receipts (
                    id         INTEGER PRIMARY KEY AUTOINCREMENT,
                    device_id  TEXT NOT NULL,
                    message_id TEXT NOT NULL,
                    UNIQUE(device_id, message_id)
                );

                CREATE INDEX IF NOT EXISTS idx_inbox_receipts_device ON inbox_receipts(device_id);
                CREATE INDEX IF NOT EXISTS idx_inbox_receipts_device_id ON inbox_receipts(device_id, id);

                CREATE TABLE IF NOT EXISTS inbox_spool (
                    id                INTEGER PRIMARY KEY AUTOINCREMENT,
                    device_id         TEXT NOT NULL,
                    message_id        TEXT NOT NULL UNIQUE,
                    envelope          BLOB NOT NULL,
                    acked             INTEGER NOT NULL DEFAULT 0,
                    seq_num           INTEGER NOT NULL DEFAULT 0,
                    expires_at_iter   INTEGER
                );

                CREATE INDEX IF NOT EXISTS idx_inbox_spool_device_acked ON inbox_spool(device_id, acked, id);
                CREATE INDEX IF NOT EXISTS idx_inbox_spool_device_seq ON inbox_spool(device_id, seq_num);
                CREATE INDEX IF NOT EXISTS idx_inbox_spool_expires ON inbox_spool(expires_at_iter)
                    WHERE expires_at_iter IS NOT NULL;

                CREATE TABLE IF NOT EXISTS bytecommit_chain (
                    node_id      BLOB NOT NULL,
                    cycle_index  INTEGER NOT NULL,
                    digest       BLOB NOT NULL,
                    PRIMARY KEY(node_id, cycle_index)
                );

                CREATE INDEX IF NOT EXISTS idx_bytecommit_chain_node_cycle
                    ON bytecommit_chain(node_id, cycle_index);

                -- PaidK payment receipts
                CREATE TABLE IF NOT EXISTS payment_receipts (
                    id               INTEGER PRIMARY KEY AUTOINCREMENT,
                    device_id        TEXT NOT NULL,
                    operator_node_id BLOB NOT NULL,
                    amount           INTEGER NOT NULL,
                    receipt_addr     TEXT NOT NULL UNIQUE,
                    receipt_bytes    BLOB NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_payment_receipts_device ON payment_receipts(device_id);

                -- Node registry
                CREATE TABLE IF NOT EXISTS node_registry (
                    node_id         BLOB PRIMARY KEY,
                    first_cycle     INTEGER NOT NULL,
                    utilization_avg REAL NOT NULL DEFAULT 0.0,
                    active          INTEGER NOT NULL DEFAULT 1
                );
                CREATE INDEX IF NOT EXISTS idx_node_registry_active ON node_registry(active);

                -- Capacity signals
                CREATE TABLE IF NOT EXISTS capacity_signals (
                    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
                    signal_addr        TEXT NOT NULL UNIQUE,
                    node_id            BLOB NOT NULL,
                    signal_type        INTEGER NOT NULL,
                    capacity           INTEGER NOT NULL,
                    cycle_window_start INTEGER NOT NULL,
                    cycle_window_end   INTEGER NOT NULL,
                    signal_bytes       BLOB NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_capacity_signals_node ON capacity_signals(node_id);
                CREATE INDEX IF NOT EXISTS idx_capacity_signals_window ON capacity_signals(cycle_window_end);

                -- Applicant submissions
                CREATE TABLE IF NOT EXISTS applicants (
                    applicant_addr  TEXT PRIMARY KEY,
                    seed_app        BLOB NOT NULL,
                    stake_dlv       BLOB NOT NULL,
                    capacity        INTEGER NOT NULL,
                    applicant_bytes BLOB NOT NULL
                );

                -- Drain proofs
                CREATE TABLE IF NOT EXISTS drain_proofs (
                    id             INTEGER PRIMARY KEY AUTOINCREMENT,
                    proof_addr     TEXT NOT NULL UNIQUE,
                    node_id        BLOB NOT NULL,
                    start_cycle    INTEGER NOT NULL,
                    end_cycle      INTEGER NOT NULL,
                    verified_local INTEGER NOT NULL DEFAULT 0,
                    proof_bytes    BLOB NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_drain_proofs_node ON drain_proofs(node_id);

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
        Ok(())
    })
    .await
}

// ===================== Replication Outbox =====================

pub async fn replication_outbox_enqueue(
    pool: &DBPool,
    params: ReplicationOutboxEnqueueParams<'_>,
) -> Result<()> {
    let target = params.target.to_string();
    let method = params.method.to_string();
    let path = params.path.to_string();
    let headers = params.headers.to_vec();
    let body = params.body.to_vec();
    let idempotency_key = params.idempotency_key.to_string();
    let eligible_iter = params.eligible_iter;

    with_conn(pool, move |conn| {
        conn.execute(
            "INSERT OR IGNORE INTO replication_outbox (target, method, path, headers, body, idempotency_key, eligible_iter)
             VALUES (?1,?2,?3,?4,?5,?6,?7)",
            params![target, method, path, headers, body, idempotency_key, eligible_iter],
        )?;
        Ok(())
    }).await
}

pub async fn replication_outbox_list_due(
    pool: &DBPool,
    now_iter: i64,
    limit: i64,
) -> Result<Vec<ReplicationOutboxRow>> {
    with_conn(pool, move |conn| {
        let mut stmt = conn.prepare_cached(
            "SELECT id, target, method, path, headers, body, idempotency_key, attempts, eligible_iter
             FROM replication_outbox WHERE done=0 AND eligible_iter <= ?1
             ORDER BY eligible_iter ASC, id ASC LIMIT ?2",
        )?;
        let rows = stmt
            .query_map(params![now_iter, limit], |row| {
                Ok(ReplicationOutboxRow {
                    id: row.get(0)?,
                    target: row.get(1)?,
                    method: row.get(2)?,
                    path: row.get(3)?,
                    headers: row.get(4)?,
                    body: row.get(5)?,
                    idempotency_key: row.get(6)?,
                    attempts: row.get(7)?,
                    eligible_iter: row.get(8)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    })
    .await
}

pub async fn replication_outbox_mark_done(pool: &DBPool, id: i64) -> Result<()> {
    with_conn(pool, move |conn| {
        conn.execute(
            "UPDATE replication_outbox SET done=1, last_err=NULL WHERE id=?1",
            params![id],
        )?;
        Ok(())
    })
    .await
}

pub async fn replication_outbox_record_failure(
    pool: &DBPool,
    timing: &dyn TimingStrategy,
    id: i64,
    now_iter: i64,
    attempts_next: i32,
    last_err: &str,
) -> Result<()> {
    let eligible_iter_next = timing
        .calculate_retry_eligible_iter(now_iter, attempts_next)
        .await;
    let last_err = last_err.to_string();

    with_conn(pool, move |conn| {
        conn.execute(
            "UPDATE replication_outbox SET attempts=?2, eligible_iter=?3, last_err=?4 WHERE id=?1",
            params![id, attempts_next, eligible_iter_next, last_err],
        )?;
        Ok(())
    })
    .await
}

// ===================== Core Object Store =====================

pub async fn get_current_cycle_stats(pool: &DBPool) -> Result<([u8; 32], u64)> {
    with_conn(pool, |conn| {
        let mut stmt =
            conn.prepare_cached("SELECT key, size_bytes FROM objects ORDER BY key ASC")?;
        let mut bytes_used: u64 = 0;
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"DSM/smt-node\0");

        let mut rows = stmt.query([])?;
        while let Some(row) = rows.next()? {
            let key: String = row.get(0)?;
            let sz: i64 = row.get(1)?;
            if sz > 0 {
                bytes_used = bytes_used.saturating_add(sz as u64);
            }
            hasher.update(key.as_bytes());
            hasher.update(&[0u8]);
            hasher.update(&sz.to_le_bytes());
        }

        let out = hasher.finalize();
        Ok((*out.as_bytes(), bytes_used))
    })
    .await
}

pub async fn get_last_bytecommit_hash(pool: &DBPool, node_id: &[u8]) -> Result<Option<[u8; 32]>> {
    let node_id = node_id.to_vec();
    with_conn(pool, move |conn| {
        let result: Option<Vec<u8>> = conn
            .query_row(
                "SELECT digest FROM bytecommit_chain WHERE node_id=?1 ORDER BY cycle_index DESC LIMIT 1",
                params![node_id],
                |row| row.get(0),
            )
            .optional()?;
        Ok(result.map(|b| {
            let mut out = [0u8; 32];
            if b.len() == 32 {
                out.copy_from_slice(&b);
            }
            out
        }))
    })
    .await
}

pub async fn record_bytecommit_hash(
    pool: &DBPool,
    node_id: &[u8],
    cycle_index: u64,
    digest: &[u8; 32],
) -> Result<()> {
    let node_id = node_id.to_vec();
    let digest = digest.to_vec();
    with_conn(pool, move |conn| {
        conn.execute(
            "INSERT OR IGNORE INTO bytecommit_chain(node_id, cycle_index, digest) VALUES (?1,?2,?3)",
            params![node_id, cycle_index as i64, digest],
        )?;
        Ok(())
    })
    .await
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

pub async fn upsert_object(
    pool: &DBPool,
    key: &str,
    value: &[u8],
    dlv_id: &[u8],
    size_bytes: i64,
) -> Result<()> {
    let key = key.to_string();
    let value = value.to_vec();
    let dlv_id = dlv_id.to_vec();
    with_conn(pool, move |conn| {
        conn.execute(
            "INSERT INTO objects(key, value, dlv_id, size_bytes) VALUES (?1,?2,?3,?4)
             ON CONFLICT (key) DO UPDATE SET value=excluded.value, size_bytes=excluded.size_bytes, dlv_id=excluded.dlv_id",
            params![key, value, dlv_id, size_bytes],
        )?;
        Ok(())
    })
    .await
}

pub async fn store_registry_evidence(
    pool: &DBPool,
    addr: &str,
    kind_code: i16,
    dlv_id: &[u8],
    size_bytes: i64,
) -> Result<()> {
    let addr = addr.to_string();
    let dlv_id = dlv_id.to_vec();
    with_conn(pool, move |conn| {
        conn.execute(
            "INSERT OR IGNORE INTO registry_evidence (addr, kind_code, dlv_id, size_bytes) VALUES (?1, ?2, ?3, ?4)",
            params![addr, kind_code as i32, dlv_id, size_bytes],
        )?;
        Ok(())
    })
    .await
}

pub async fn list_registry_evidence_by_kind(
    pool: &DBPool,
    kind_code: i16,
) -> Result<Vec<(String, i16, i64)>> {
    with_conn(pool, move |conn| {
        let mut stmt = conn.prepare_cached(
            "SELECT addr, kind_code, size_bytes FROM registry_evidence WHERE kind_code=?1 ORDER BY addr ASC",
        )?;
        let rows = stmt
            .query_map(params![kind_code as i32], |row| {
                let kc: i32 = row.get(1)?;
                Ok((row.get::<_, String>(0)?, kc as i16, row.get::<_, i64>(2)?))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    })
    .await
}

pub async fn get_registry_object_by_addr(pool: &DBPool, addr: &str) -> Result<Option<Vec<u8>>> {
    let addr = addr.to_string();
    with_conn(pool, move |conn| {
        let result: Option<Vec<u8>> = conn
            .query_row(
                "SELECT o.value FROM objects o JOIN registry_evidence r ON o.key = r.addr WHERE r.addr=?1 LIMIT 1",
                params![addr],
                |row| row.get(0),
            )
            .optional()?;
        Ok(result)
    })
    .await
}

pub async fn upsert_object_with_capacity_check(
    pool: &DBPool,
    key: &str,
    value: &[u8],
    dlv_id: &[u8],
    new_size: i64,
) -> Result<()> {
    let key = key.to_string();
    let value = value.to_vec();
    let dlv_id = dlv_id.to_vec();
    with_conn(pool, move |conn| {
        let tx = conn.unchecked_transaction()?;

        let (capacity, used): (i64, i64) = tx.query_row(
            "SELECT capacity_bytes, used_bytes FROM dlv_slots WHERE dlv_id=?1",
            params![dlv_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        ).map_err(|_| anyhow!("slot not found"))?;

        let prev_size: i64 = tx
            .query_row(
                "SELECT size_bytes FROM objects WHERE key=?1",
                params![key],
                |row| row.get(0),
            )
            .optional()?
            .unwrap_or(0);

        let delta = new_size - prev_size;

        if delta > 0 && used + delta > capacity {
            return Err(anyhow!(
                "capacity_exceeded: used={} delta={} cap={}",
                used,
                delta,
                capacity
            ));
        }

        tx.execute(
            "INSERT INTO objects(key, value, dlv_id, size_bytes) VALUES (?1,?2,?3,?4)
             ON CONFLICT (key) DO UPDATE SET value=excluded.value, size_bytes=excluded.size_bytes, dlv_id=excluded.dlv_id",
            params![key, value, dlv_id, new_size],
        )?;

        if delta != 0 {
            tx.execute(
                "UPDATE dlv_slots SET used_bytes = used_bytes + ?2 WHERE dlv_id = ?1",
                params![dlv_id, delta],
            )?;
        }

        tx.commit()?;
        Ok(())
    })
    .await
}

pub async fn list_objects_page(
    pool: &DBPool,
    prefix: Option<&str>,
    cursor: Option<&str>,
    limit: i64,
) -> Result<Vec<(String, Vec<u8>, i64)>> {
    let prefix = prefix.map(|s| s.to_string());
    let cursor = cursor.map(|s| s.to_string());
    let limit = limit.clamp(1, 1000);

    with_conn(pool, move |conn| {
        let rows: Vec<(String, Vec<u8>, i64)> = match (prefix.as_deref(), cursor.as_deref()) {
            (Some(p), Some(c)) => {
                let like = format!("{}%", p);
                let mut stmt = conn.prepare_cached(
                    "SELECT key, dlv_id, size_bytes FROM objects WHERE key LIKE ?1 AND key > ?2 ORDER BY key ASC LIMIT ?3",
                )?;
                let result = stmt.query_map(params![like, c, limit], |row| {
                    Ok((row.get(0)?, row.get(1)?, row.get(2)?))
                })?.collect::<std::result::Result<Vec<_>, _>>()?;
                result
            }
            (Some(p), None) => {
                let like = format!("{}%", p);
                let mut stmt = conn.prepare_cached(
                    "SELECT key, dlv_id, size_bytes FROM objects WHERE key LIKE ?1 ORDER BY key ASC LIMIT ?2",
                )?;
                let result = stmt.query_map(params![like, limit], |row| {
                    Ok((row.get(0)?, row.get(1)?, row.get(2)?))
                })?.collect::<std::result::Result<Vec<_>, _>>()?;
                result
            }
            (None, Some(c)) => {
                let mut stmt = conn.prepare_cached(
                    "SELECT key, dlv_id, size_bytes FROM objects WHERE key > ?1 ORDER BY key ASC LIMIT ?2",
                )?;
                let result = stmt.query_map(params![c, limit], |row| {
                    Ok((row.get(0)?, row.get(1)?, row.get(2)?))
                })?.collect::<std::result::Result<Vec<_>, _>>()?;
                result
            }
            (None, None) => {
                let mut stmt = conn.prepare_cached(
                    "SELECT key, dlv_id, size_bytes FROM objects ORDER BY key ASC LIMIT ?1",
                )?;
                let result = stmt.query_map(params![limit], |row| {
                    Ok((row.get(0)?, row.get(1)?, row.get(2)?))
                })?.collect::<std::result::Result<Vec<_>, _>>()?;
                result
            }
        };
        Ok(rows)
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

pub async fn spool_insert_with_expiration(
    pool: &DBPool,
    device_id: &str,
    message_id: &str,
    envelope: &[u8],
    expires_at_iter: Option<i64>,
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
            "INSERT OR IGNORE INTO inbox_spool(device_id, message_id, envelope, seq_num, expires_at_iter)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![device_id, message_id, envelope, seq, expires_at_iter],
        )?;
        tx.commit()?;
        Ok(())
    })
    .await
}

pub async fn spool_list_unacked_from_seq(
    pool: &DBPool,
    device_id: &str,
    from_seq: i64,
    limit: i64,
) -> Result<Vec<(Vec<u8>, i64)>> {
    let device_id = device_id.to_string();
    with_conn(pool, move |conn| {
        let mut stmt = conn.prepare_cached(
            "SELECT envelope, seq_num FROM inbox_spool
             WHERE device_id=?1 AND acked=0 AND seq_num >= ?2
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

pub async fn spool_list(
    pool: &DBPool,
    device_id: &str,
    include_acked: bool,
    limit: i64,
) -> Result<Vec<Vec<u8>>> {
    let device_id = device_id.to_string();
    with_conn(pool, move |conn| {
        let rows: Vec<Vec<u8>> = if include_acked {
            let mut stmt = conn.prepare_cached(
                "SELECT envelope FROM inbox_spool WHERE device_id=?1 ORDER BY id ASC LIMIT ?2",
            )?;
            let result = stmt.query_map(params![device_id, limit], |row| row.get(0))?
                .collect::<std::result::Result<Vec<_>, _>>()?;
            result
        } else {
            let mut stmt = conn.prepare_cached(
                "SELECT envelope FROM inbox_spool WHERE device_id=?1 AND acked=0 ORDER BY id ASC LIMIT ?2",
            )?;
            let result = stmt.query_map(params![device_id, limit], |row| row.get(0))?
                .collect::<std::result::Result<Vec<_>, _>>()?;
            result
        };
        Ok(rows)
    })
    .await
}

pub async fn spool_ack(pool: &DBPool, device_id: &str, message_ids: &[String]) -> Result<u64> {
    if message_ids.is_empty() {
        return Ok(0);
    }
    let device_id = device_id.to_string();
    let message_ids = message_ids.to_vec();
    with_conn(pool, move |conn| {
        let mut total: u64 = 0;
        for mid in &message_ids {
            let n = conn.execute(
                "UPDATE inbox_spool SET acked=1 WHERE device_id=?1 AND message_id=?2",
                params![device_id, mid],
            )?;
            total += n as u64;
        }
        Ok(total)
    })
    .await
}

pub async fn spool_lookup_by_message_id(
    pool: &DBPool,
    message_id: &str,
) -> Result<Option<(Vec<u8>, bool)>> {
    let message_id = message_id.to_string();
    with_conn(pool, move |conn| {
        let row = conn.query_row(
            "SELECT envelope, acked FROM inbox_spool WHERE message_id = ?1 LIMIT 1",
            params![message_id],
            |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)? != 0)),
        );

        match row {
            Ok(record) => Ok(Some(record)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    })
    .await
}

pub async fn cleanup_expired_objects_and_spool(
    pool: &DBPool,
    timing: &dyn TimingStrategy,
    current_iter: i64,
) -> Result<(u64, u64)> {
    let expiration_threshold = timing.calculate_expiration_iter(current_iter, 0).await;

    with_conn(pool, move |conn| {
        let count: i64 = conn.query_row("SELECT COUNT(*) FROM objects", [], |row| row.get(0))?;
        let size: i64 = conn.query_row(
            "SELECT COALESCE(SUM(size_bytes), 0) FROM objects",
            [],
            |row| row.get(0),
        )?;

        if count < (BEV as i64) && size < (BBYTES as i64) {
            return Ok((0, 0));
        }

        let objects_deleted = conn.execute(
            "DELETE FROM objects WHERE iter_expires IS NOT NULL AND iter_expires < ?1",
            params![expiration_threshold],
        )? as u64;

        let spool_deleted = conn.execute(
            "DELETE FROM inbox_spool WHERE expires_at_iter IS NOT NULL AND expires_at_iter < ?1",
            params![expiration_threshold],
        )? as u64;

        let acked_cleanup_iter = current_iter - 1000;
        let acked_deleted = conn.execute(
            "DELETE FROM inbox_spool WHERE acked = 1 AND seq_num < ?1",
            params![acked_cleanup_iter],
        )? as u64;

        Ok((objects_deleted, spool_deleted + acked_deleted))
    })
    .await
}

pub async fn delete_slot_object(pool: &DBPool, _dlv_id: &[u8], key: &str) -> Result<u64> {
    let key = key.to_string();
    with_conn(pool, move |conn| {
        let tx = conn.unchecked_transaction()?;

        let row: Option<(Vec<u8>, i64)> = tx
            .query_row(
                "SELECT dlv_id, size_bytes FROM objects WHERE key = ?1",
                params![key],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;

        let Some((dlv_id, size_bytes)) = row else {
            tx.commit()?;
            return Ok(0);
        };

        let deleted = tx.execute("DELETE FROM objects WHERE key = ?1", params![key])? as u64;

        if deleted > 0 && size_bytes > 0 {
            tx.execute(
                "UPDATE dlv_slots SET used_bytes = MAX(used_bytes - ?2, 0) WHERE dlv_id = ?1",
                params![dlv_id, size_bytes],
            )?;
        }

        tx.commit()?;
        Ok(deleted)
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

#[allow(clippy::too_many_arguments)]
pub async fn register_device(
    pool: &DBPool,
    device_id: &str,
    genesis_hash: &[u8],
    pubkey: &[u8],
    token_hash: &[u8],
    kyber_public_key: &[u8],
    kyber_binding_sig: &[u8],
) -> Result<u64> {
    let device_id = device_id.to_string();
    let genesis_hash = genesis_hash.to_vec();
    let pubkey = pubkey.to_vec();
    let token_hash = token_hash.to_vec();
    let kyber_public_key = kyber_public_key.to_vec();
    let kyber_binding_sig = kyber_binding_sig.to_vec();
    with_conn(pool, move |conn| {
        let rows = conn.execute(
            "INSERT OR IGNORE INTO devices
                (device_id, genesis_hash, pubkey, token_hash, kyber_public_key, kyber_binding_sig, revoked)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0)",
            params![
                device_id,
                genesis_hash,
                pubkey,
                token_hash,
                kyber_public_key,
                kyber_binding_sig
            ],
        )?;
        Ok(rows as u64)
    })
    .await
}

/// A device's registered identity row:
/// `(genesis_hash, pubkey, kyber_public_key, kyber_binding_sig)`.
pub type DeviceIdentityRow = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>);

/// Get a device's identity: (genesis_hash, pubkey, kyber_public_key, kyber_binding_sig).
pub async fn get_device(pool: &DBPool, device_id: &str) -> Result<Option<DeviceIdentityRow>> {
    let device_id = device_id.to_string();
    with_conn(pool, move |conn| {
        let result: Option<DeviceIdentityRow> = conn
            .query_row(
                "SELECT genesis_hash, pubkey, kyber_public_key, kyber_binding_sig
                 FROM devices WHERE device_id = ?1",
                params![device_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()?;
        Ok(result)
    })
    .await
}

pub async fn update_device_token_hash(
    pool: &DBPool,
    device_id: &str,
    token_hash: &[u8],
) -> Result<()> {
    let device_id = device_id.to_string();
    let token_hash = token_hash.to_vec();
    with_conn(pool, move |conn| {
        conn.execute(
            "UPDATE devices SET token_hash = ?1 WHERE device_id = ?2",
            params![token_hash, device_id],
        )?;
        Ok(())
    })
    .await
}

pub async fn lookup_device_auth(
    pool: &DBPool,
    device_id: &str,
) -> Result<Option<(Vec<u8>, Vec<u8>, bool)>> {
    let device_id = device_id.to_string();
    with_conn(pool, move |conn| {
        let result: Option<(Vec<u8>, Vec<u8>, bool)> = conn
            .query_row(
                "SELECT pubkey, token_hash, revoked FROM devices WHERE device_id = ?1",
                params![device_id],
                |row| {
                    let revoked: i32 = row.get(2)?;
                    Ok((row.get(0)?, row.get(1)?, revoked != 0))
                },
            )
            .optional()?;
        Ok(result)
    })
    .await
}

pub async fn insert_inbox_receipt(
    pool: &DBPool,
    device_id: &str,
    message_id: &str,
) -> Result<bool> {
    let device_id = device_id.to_string();
    let message_id = message_id.to_string();
    with_conn(pool, move |conn| {
        let rows = conn.execute(
            "INSERT OR IGNORE INTO inbox_receipts(device_id, message_id) VALUES (?1, ?2)",
            params![device_id, message_id],
        )?;
        Ok(rows > 0)
    })
    .await
}

pub async fn prune_inbox_receipts(pool: &DBPool, device_id: &str, keep_count: i64) -> Result<()> {
    let device_id = device_id.to_string();
    with_conn(pool, move |conn| {
        let _ = conn.execute(
            "DELETE FROM inbox_receipts
             WHERE device_id = ?1 AND id < (
               SELECT id FROM inbox_receipts
               WHERE device_id = ?1
               ORDER BY id DESC
               LIMIT 1 OFFSET ?2
             )",
            params![device_id, keep_count],
        );
        Ok(())
    })
    .await
}

// ===================== PaidK Spend-Gate =====================

pub async fn store_payment_receipt(
    pool: &DBPool,
    device_id: &str,
    operator_node_id: &[u8],
    amount: i64,
    receipt_addr: &str,
    receipt_bytes: &[u8],
) -> Result<()> {
    let device_id = device_id.to_string();
    let operator_node_id = operator_node_id.to_vec();
    let receipt_addr = receipt_addr.to_string();
    let receipt_bytes = receipt_bytes.to_vec();
    with_conn(pool, move |conn| {
        conn.execute(
            "INSERT OR IGNORE INTO payment_receipts
             (device_id, operator_node_id, amount, receipt_addr, receipt_bytes)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                device_id,
                operator_node_id,
                amount,
                receipt_addr,
                receipt_bytes
            ],
        )?;
        Ok(())
    })
    .await
}

pub async fn count_distinct_paid_operators(
    pool: &DBPool,
    device_id: &str,
    flat_rate: i64,
) -> Result<i64> {
    let device_id = device_id.to_string();
    with_conn(pool, move |conn| {
        let count: i64 = conn.query_row(
            "SELECT COUNT(DISTINCT operator_node_id) FROM payment_receipts
             WHERE device_id = ?1 AND amount >= ?2",
            params![device_id, flat_rate],
            |row| row.get(0),
        )?;
        Ok(count)
    })
    .await
}

pub async fn mark_paidk_satisfied(pool: &DBPool, device_id: &str) -> Result<()> {
    let device_id = device_id.to_string();
    with_conn(pool, move |conn| {
        conn.execute(
            "UPDATE devices SET paidk_satisfied = 1 WHERE device_id = ?1",
            params![device_id],
        )?;
        Ok(())
    })
    .await
}

pub async fn is_paidk_satisfied(pool: &DBPool, device_id: &str) -> Result<bool> {
    let device_id = device_id.to_string();
    with_conn(pool, move |conn| {
        let result: Option<i32> = conn
            .query_row(
                "SELECT paidk_satisfied FROM devices WHERE device_id = ?1",
                params![device_id],
                |row| row.get(0),
            )
            .optional()?;
        Ok(result.map(|v| v != 0).unwrap_or(false))
    })
    .await
}

// ===================== Node Registry & Signals =====================

pub async fn upsert_registry_node(pool: &DBPool, node_id: &[u8], first_cycle: i64) -> Result<()> {
    let node_id = node_id.to_vec();
    with_conn(pool, move |conn| {
        conn.execute(
            "INSERT OR IGNORE INTO node_registry (node_id, first_cycle) VALUES (?1, ?2)",
            params![node_id, first_cycle],
        )?;
        Ok(())
    })
    .await
}

pub async fn get_active_registry_node_ids(pool: &DBPool) -> Result<Vec<Vec<u8>>> {
    with_conn(pool, |conn| {
        let mut stmt = conn.prepare_cached(
            "SELECT node_id FROM node_registry WHERE active = 1 ORDER BY node_id ASC",
        )?;
        let rows = stmt
            .query_map([], |row| row.get::<_, Vec<u8>>(0))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    })
    .await
}

pub async fn get_active_registry_nodes(pool: &DBPool) -> Result<Vec<(Vec<u8>, i64, f64)>> {
    with_conn(pool, |conn| {
        let mut stmt = conn.prepare_cached(
            "SELECT node_id, first_cycle, utilization_avg FROM node_registry
             WHERE active = 1 ORDER BY node_id ASC",
        )?;
        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, f64>(2)?,
                ))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    })
    .await
}

pub async fn deactivate_registry_node(pool: &DBPool, node_id: &[u8]) -> Result<()> {
    let node_id = node_id.to_vec();
    with_conn(pool, move |conn| {
        conn.execute(
            "UPDATE node_registry SET active = 0 WHERE node_id = ?1",
            params![node_id],
        )?;
        Ok(())
    })
    .await
}

pub async fn update_registry_node_utilization(
    pool: &DBPool,
    node_id: &[u8],
    utilization_avg: f64,
) -> Result<()> {
    let node_id = node_id.to_vec();
    with_conn(pool, move |conn| {
        conn.execute(
            "UPDATE node_registry SET utilization_avg = ?2 WHERE node_id = ?1",
            params![node_id, utilization_avg],
        )?;
        Ok(())
    })
    .await
}

/// Parameters for storing a capacity signal. Mirrors the pg.rs definition to
/// satisfy the 7-argument clippy limit on both backends.
#[derive(Debug, Clone, Copy)]
pub struct CapacitySignalParams<'a> {
    pub signal_addr: &'a str,
    pub node_id: &'a [u8],
    pub signal_type: i16,
    pub capacity: i64,
    pub cycle_window_start: i64,
    pub cycle_window_end: i64,
    pub signal_bytes: &'a [u8],
}

pub async fn store_capacity_signal(pool: &DBPool, p: &CapacitySignalParams<'_>) -> Result<()> {
    let signal_addr = p.signal_addr.to_string();
    let node_id = p.node_id.to_vec();
    let signal_type = p.signal_type;
    let capacity = p.capacity;
    let cycle_window_start = p.cycle_window_start;
    let cycle_window_end = p.cycle_window_end;
    let signal_bytes = p.signal_bytes.to_vec();
    with_conn(pool, move |conn| {
        conn.execute(
            "INSERT OR IGNORE INTO capacity_signals
             (signal_addr, node_id, signal_type, capacity, cycle_window_start, cycle_window_end, signal_bytes)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                signal_addr,
                node_id,
                signal_type as i32,
                capacity,
                cycle_window_start,
                cycle_window_end,
                signal_bytes
            ],
        )?;
        Ok(())
    })
    .await
}

pub async fn count_up_signals(pool: &DBPool, window_start: i64, window_end: i64) -> Result<i64> {
    with_conn(pool, move |conn| {
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM capacity_signals
             WHERE signal_type = 1 AND cycle_window_end >= ?1 AND cycle_window_end <= ?2",
            params![window_start, window_end],
            |row| row.get(0),
        )?;
        Ok(count)
    })
    .await
}

pub async fn count_down_signals_excluding_grace(
    pool: &DBPool,
    window_start: i64,
    window_end: i64,
    current_cycle: i64,
    grace_cycles: i64,
) -> Result<i64> {
    with_conn(pool, move |conn| {
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM capacity_signals cs
             WHERE cs.signal_type = 2
               AND cs.cycle_window_end >= ?1
               AND cs.cycle_window_end <= ?2
               AND NOT EXISTS (
                 SELECT 1 FROM node_registry nr
                 WHERE nr.node_id = cs.node_id
                   AND nr.active = 1
                   AND nr.first_cycle + ?4 > ?3
               )",
            params![window_start, window_end, current_cycle, grace_cycles],
            |row| row.get(0),
        )?;
        Ok(count)
    })
    .await
}

pub async fn store_applicant(
    pool: &DBPool,
    applicant_addr: &str,
    seed_app: &[u8],
    stake_dlv: &[u8],
    capacity: i64,
    applicant_bytes: &[u8],
) -> Result<()> {
    let applicant_addr = applicant_addr.to_string();
    let seed_app = seed_app.to_vec();
    let stake_dlv = stake_dlv.to_vec();
    let applicant_bytes = applicant_bytes.to_vec();
    with_conn(pool, move |conn| {
        conn.execute(
            "INSERT OR IGNORE INTO applicants
             (applicant_addr, seed_app, stake_dlv, capacity, applicant_bytes)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                applicant_addr,
                seed_app,
                stake_dlv,
                capacity,
                applicant_bytes
            ],
        )?;
        Ok(())
    })
    .await
}

pub async fn list_pending_applicants(
    pool: &DBPool,
) -> Result<Vec<(String, Vec<u8>, Vec<u8>, i64)>> {
    with_conn(pool, |conn| {
        let mut stmt = conn.prepare_cached(
            "SELECT applicant_addr, seed_app, stake_dlv, capacity FROM applicants
             ORDER BY applicant_addr ASC",
        )?;
        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    })
    .await
}

pub async fn remove_applicant(pool: &DBPool, applicant_addr: &str) -> Result<()> {
    let applicant_addr = applicant_addr.to_string();
    with_conn(pool, move |conn| {
        conn.execute(
            "DELETE FROM applicants WHERE applicant_addr = ?1",
            params![applicant_addr],
        )?;
        Ok(())
    })
    .await
}

// ===================== DrainProof & Stake Exit =====================

pub async fn store_drain_proof(
    pool: &DBPool,
    proof_addr: &str,
    node_id: &[u8],
    start_cycle: i64,
    end_cycle: i64,
    verified_local: bool,
    proof_bytes: &[u8],
) -> Result<()> {
    let proof_addr = proof_addr.to_string();
    let node_id = node_id.to_vec();
    let proof_bytes = proof_bytes.to_vec();
    let verified_local_i = if verified_local { 1i32 } else { 0i32 };
    with_conn(pool, move |conn| {
        conn.execute(
            "INSERT OR IGNORE INTO drain_proofs
             (proof_addr, node_id, start_cycle, end_cycle, verified_local, proof_bytes)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                proof_addr,
                node_id,
                start_cycle,
                end_cycle,
                verified_local_i,
                proof_bytes
            ],
        )?;
        Ok(())
    })
    .await
}

pub async fn get_drain_proof_for_node(pool: &DBPool, node_id: &[u8]) -> Result<Option<Vec<u8>>> {
    let node_id = node_id.to_vec();
    with_conn(pool, move |conn| {
        let result: Option<Vec<u8>> = conn
            .query_row(
                "SELECT proof_bytes FROM drain_proofs WHERE node_id = ?1
                 ORDER BY end_cycle DESC LIMIT 1",
                params![node_id],
                |row| row.get(0),
            )
            .optional()?;
        Ok(result)
    })
    .await
}

pub async fn verify_bytecommit_chain_empty(
    pool: &DBPool,
    node_id: &[u8],
    start_cycle: i64,
    required_d: i64,
) -> Result<bool> {
    let node_id = node_id.to_vec();
    with_conn(pool, move |conn| {
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM bytecommit_chain
             WHERE node_id = ?1 AND cycle_index >= ?2 AND cycle_index < ?2 + ?3",
            params![node_id, start_cycle, required_d],
            |row| row.get(0),
        )?;
        Ok(count >= required_d)
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn headers_encode_decode_roundtrip_and_sorting() {
        let headers = vec![
            ("X-Test".to_string(), b"b".to_vec()),
            ("x-test".to_string(), b"a".to_vec()),
            (
                "Content-Type".to_string(),
                b"application/octet-stream".to_vec(),
            ),
        ];
        let enc = encode_headers_deterministic(&headers);
        let dec = match decode_headers_deterministic(&enc) {
            Ok(decoded) => decoded,
            Err(err) => panic!("header decode should succeed: {err:?}"),
        };

        assert_eq!(dec[0].0, "content-type");
        assert_eq!(dec[1].0, "x-test");
        assert_eq!(dec[1].1, b"a".to_vec());
        assert_eq!(dec[2].0, "x-test");
        assert_eq!(dec[2].1, b"b".to_vec());
    }

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
