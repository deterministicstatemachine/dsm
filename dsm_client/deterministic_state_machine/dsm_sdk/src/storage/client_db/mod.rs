// SPDX-License-Identifier: MIT OR Apache-2.0
//! DSM Client Persistent Storage Layer — drop-in, binary-first (no serde / no JSON / no base64)

use anyhow::{anyhow, Result};
use log::{info, warn};
use rusqlite::{params, Connection, OptionalExtension};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};

pub use crate::storage::codecs::{
    deserialize_operation, encode_genesis_record_bytes, generate_hash_chain_proof_bytes,
    hash_blake3_bytes, meta_from_blob, meta_to_blob, read_len_u32, read_string, read_u64, read_u8,
    read_vec, serialize_operation, smt_proof_bytes,
};

// --- Submodules (domain-specific) ---

pub mod anchor_enrollments;
pub mod b0x_consumed;
pub mod b0x_sealed;
pub(crate) mod bcr;
mod bilateral_sessions;
pub mod bilateral_tip_sync;
mod bitcoin_accounts;
mod ble_chunk_buffer;
pub mod canonical_apply;
mod canonical_rebuild;
pub mod cert_chain;
mod cert_resync;
pub mod completion_proofs;
mod contacts;
pub mod counterparty_canonical_heads;
pub mod economic_admission;
pub mod economic_lineage;
pub mod frozen_publication_artifact; // publish-exact-bytes-to-quorum (namespaced; no glob re-export)
mod genesis;
mod manifold_seeds;
pub mod native_reserve;
mod nonces;
mod online_outbox;
pub mod own_directory_entry;
mod projection_repair;
pub mod publication;
pub mod recipient_receipt_fold;
pub mod recipient_staging;
pub mod recovery;
pub mod route_writes;
pub mod sender_outbox;
pub mod sender_proposal;
pub mod sofi_vault_head; // the vault head and evidence store (spec §44.4)
pub mod storage_sync_runs;
mod system_peers;
pub mod token_registry;
mod tokens;
mod transactions;
pub mod types;
mod vault_records;
mod vaults;
mod withdrawals;

// --- Wildcard re-exports (preserves all existing import paths) ---

pub use types::*;
pub use bcr::*;
pub use bilateral_sessions::*;
pub use bitcoin_accounts::*;
pub use ble_chunk_buffer::*;
pub use canonical_apply::*;
pub use cert_chain::*;
pub use recipient_receipt_fold::*;
pub use canonical_rebuild::*;
pub use cert_resync::*;
pub use projection_repair::*;
pub use sender_outbox::*;
pub use sender_proposal::*;
pub use contacts::*;
pub use counterparty_canonical_heads::*;
pub use genesis::*;
pub use manifold_seeds::*;
pub use nonces::*;
pub use online_outbox::*;
pub use vault_records::*;
pub use system_peers::*;
pub use tokens::*;
pub use transactions::*;
pub use withdrawals::*;
pub use vaults::*;

// =========================== DB plumbing ===========================

static DB_CONNECTION: RwLock<Option<Arc<Mutex<Connection>>>> = RwLock::new(None);
const DB_FILE_NAME: &str = "dsm_client.db";

/// Per-reset generation counter (unit tests only). Incremented by
/// `reset_database_for_tests()` so every reset+reinit cycle opens a new
/// database file, never one a lingering connection still holds.
#[cfg(test)]
static TEST_DB_GENERATION: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
#[cfg(test)]
static TEST_DB_LIFECYCLE_LOCK: Mutex<()> = Mutex::new(());

// --- two-device test harness: named DB "slots" in one process -------------
//
// A single process has ONE `DB_CONNECTION`. The bilateral protocol tests need
// two devices (A and B) whose durable state (cert_chain_heads is keyed by the
// SYMMETRIC relationship key, so A's and B's Local heads collide in one DB)
// must persist across many round-trips. `switch_test_database_slot(slot)` parks
// the live connection under its slot and installs the target slot's own
// database file, so `get_connection()` resolves to a distinct DB per slot.
//
// STRICTLY SERIALIZED: exactly one slot is active while production code runs;
// A-side and B-side calls must never overlap in-process, because AppState,
// the cached wallet seed, and other identity context are process-global. This
// harness proves protocol SEQUENCING, not concurrency.
#[cfg(test)]
static TEST_DB_SLOT: RwLock<Option<&'static str>> = RwLock::new(None);
#[cfg(test)]
static TEST_DB_PARKED: Mutex<
    Option<std::collections::HashMap<&'static str, Arc<Mutex<Connection>>>>,
> = Mutex::new(None);

/// Activate a named database slot for the current thread of a test. Parks the
/// currently installed connection (if any) under its slot, then installs the
/// target slot's connection — opening its database file on first use. Returns after the slot is active; the
/// next `get_connection()` sees the slot's DB.
#[cfg(test)]
pub(crate) fn switch_test_database_slot(slot: &'static str) {
    let _g = TEST_DB_LIFECYCLE_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());

    let prev_slot = *TEST_DB_SLOT.read().unwrap_or_else(|e| e.into_inner());
    if prev_slot == Some(slot) {
        return;
    }
    let current = DB_CONNECTION
        .write()
        .unwrap_or_else(|e| e.into_inner())
        .take();

    let mut parked = TEST_DB_PARKED.lock().unwrap_or_else(|e| e.into_inner());
    let map = parked.get_or_insert_with(std::collections::HashMap::new);
    if let (Some(ps), Some(conn)) = (prev_slot, current) {
        map.insert(ps, conn);
    }
    *TEST_DB_SLOT.write().unwrap_or_else(|e| e.into_inner()) = Some(slot);
    if let Some(conn) = map.get(slot).cloned() {
        *DB_CONNECTION.write().unwrap_or_else(|e| e.into_inner()) = Some(conn);
    }
    // else: leave DB_CONNECTION empty so the next get_connection() opens the
    // slot's URI and initializes its schema.
}

pub fn init_database() -> Result<()> {
    {
        #[cfg(test)]
        let _test_db_lifecycle_guard = TEST_DB_LIFECYCLE_LOCK
            .lock()
            .map_err(|e| anyhow!("Test DB lifecycle lock poisoned: {e}"))?;

        {
            let guard = DB_CONNECTION
                .read()
                .map_err(|e| anyhow!("DB lock poisoned: {e}"))?;
            if guard.is_some() {
                // init_database() can be called defensively from many hot paths.
                // Avoid log spam that drowns out protocol-critical traces.
                return Ok(());
            }
        }

        let db_path = get_database_path()?;
        info!("[DSM_SDK] Initializing database at: {:?}", db_path);
        if let Some(parent) = db_path.parent() {
            std::fs::create_dir_all(parent)?;
            info!("[DSM_SDK] Created parent directory: {:?}", parent);
        }

        let conn = Connection::open(&db_path)?;
        info!("[DSM_SDK] Database connection opened successfully");
        conn.execute("PRAGMA foreign_keys = ON;", [])?;
        create_schema(&conn)?;
        {
            let mut guard = DB_CONNECTION
                .write()
                .map_err(|e| anyhow!("DB lock poisoned: {e}"))?;
            if guard.is_some() {
                // Another caller initialized concurrently; reuse existing connection.
                return Ok(());
            }
            *guard = Some(Arc::new(Mutex::new(conn)));
        }
    }

    // Recovery capsule + prefs tables (NFC ring backup)
    if let Err(e) = recovery::ensure_recovery_tables() {
        warn!("Recovery table creation failed (non-fatal): {e:?}");
    }

    if let Err(e) = cleanup_orphan_chunk_buffers() {
        warn!("BLE chunk buffer cleanup failed (non-fatal): {e:?}");
    }

    Ok(())
}

/// Check if database has been initialized.
pub fn is_database_initialized() -> bool {
    DB_CONNECTION.read().is_ok_and(|g| g.is_some())
}

/// Empty the device database and drop its connection, for tests: the SDK's
/// unit tests, and its integration tests through `test-utils`. Every table's
/// rows are deleted; under the unit tests the next `init_database` also opens
/// a new generation's file, and any parked two-device slot is dropped.
///
/// Serializes with `init_database` via `TEST_DB_LIFECYCLE_LOCK`, so an
/// `init_database` never observes a dropped connection with the old
/// generation still current.
#[cfg(any(test, feature = "test-utils"))]
#[allow(clippy::panic)] // a reset that fails leaves the next test on stale rows; it must stop
pub fn reset_database_for_tests() {
    #[cfg(test)]
    let lifecycle = TEST_DB_LIFECYCLE_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());

    {
        let guard = DB_CONNECTION.read().unwrap_or_else(|e| e.into_inner());
        if let Some(arc_conn) = guard.as_ref() {
            let conn = arc_conn.lock().unwrap_or_else(|e| e.into_inner());
            let tables: Vec<String> = conn
                .prepare(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
                )
                .and_then(|mut stmt| {
                    stmt.query_map([], |row| row.get::<_, String>(0))?
                        .collect::<rusqlite::Result<Vec<String>>>()
                })
                .unwrap_or_else(|e| panic!("reset_database_for_tests: list tables: {e}"));
            // Rows go in any table order: references between tables are not
            // checked while the database is emptied.
            conn.execute_batch("PRAGMA foreign_keys = OFF;")
                .unwrap_or_else(|e| panic!("reset_database_for_tests: foreign keys off: {e}"));
            for table in &tables {
                conn.execute(&format!("DELETE FROM \"{table}\""), [])
                    .unwrap_or_else(|e| panic!("reset_database_for_tests: empty {table}: {e}"));
            }
            conn.execute_batch("PRAGMA foreign_keys = ON;")
                .unwrap_or_else(|e| panic!("reset_database_for_tests: foreign keys on: {e}"));
        }
    }
    *DB_CONNECTION.write().unwrap_or_else(|e| e.into_inner()) = None;

    #[cfg(test)]
    {
        // Drop any parked two-device slots and clear the active slot so a fresh
        // reset starts from the default (no-slot) database.
        *TEST_DB_PARKED.lock().unwrap_or_else(|e| e.into_inner()) = None;
        *TEST_DB_SLOT.write().unwrap_or_else(|e| e.into_inner()) = None;
        TEST_DB_GENERATION.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        drop(lifecycle);
    }
}

pub fn get_db_size() -> Result<u64> {
    let path = get_database_path()?;
    if !path.exists() {
        return Ok(0);
    }
    let metadata = std::fs::metadata(path)?;
    Ok(metadata.len())
}

/// The device database: a file in the storage base directory, which startup
/// sets before anything touches storage. Under the SDK's unit tests each
/// database generation and each two-device slot is a file of its own there.
fn get_database_path() -> Result<PathBuf> {
    let base = crate::storage_utils::get_storage_base_dir().ok_or_else(|| {
        anyhow!("Storage base directory not set. Call initStorageBaseDir() at startup.")
    })?;

    #[cfg(test)]
    {
        let gen = TEST_DB_GENERATION.load(std::sync::atomic::Ordering::Relaxed);
        let slot = TEST_DB_SLOT
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .map(|s| format!("_{s}"))
            .unwrap_or_default();
        Ok(base.join(format!("{gen}{slot}_{DB_FILE_NAME}")))
    }

    #[cfg(not(test))]
    {
        Ok(base.join(DB_FILE_NAME))
    }
}

/// Current client-database schema generation.
///
/// DSM beta carries NO migrations: incompatible schemas are reset, never
/// upgraded in place. Bump this whenever a change would make an older database
/// structurally invalid (a new NOT NULL column, a renamed/removed table, an
/// altered key). See [`enforce_schema_version`].
///
/// 3: bilateral finality barrier — B's canonical pair on
/// `canonical_apply_identity` / `acceptance_fold_journal` /
/// `accepted_transition_marker` (NOT NULL), plus the tables and columns the
/// barrier's later commits add on the same generation.
///
/// 4: DLV consume-once claim — `vault_generation_consumption`
/// (`UNIQUE(vault_id, parent_sequence)` + `source_commitment`). This is durable
/// protocol state that decides settlement replay-vs-conflict identity, so v3 and
/// v4 do NOT mean the same durable contract even though the DDL is additive — the
/// version, not the happenstance that `CREATE TABLE IF NOT EXISTS` can run on a v3
/// file, is the authority on what the schema means. Reset-and-reprovision, no
/// migration, per the beta policy.
///
/// 5: publication durability + canonical storage set — `frozen_publication_artifact`
/// (exact bytes a canonical advance froze, keyed `(object_key, content_digest)`,
/// bound to the `storage_set_id` they were frozen for) and
/// `frozen_publication_artifact_members` (one current acceptance observation per
/// member); `amm_vault_records.storage_set_id BLOB NOT NULL` (the set a vault was
/// born under — a local copy of the value the vault's signed anchor binds);
/// `settlement_slot_claim_local` (this device's frozen settlement-slot claim
/// envelopes, replayed byte-identically — the register compares exact bytes);
/// `dlv_close_intent` (the exact bytes a close will publish/claim/advance,
/// written before any external step so recovery resumes instead of re-signing).
/// Also durable protocol state that decides what "published", "which set" and
/// "which claim" mean; same rule as v4 — the version is the authority, no shim.
/// 8: ERA faucet claim flow — `economic_root_claim_local` (the frozen economic-root claim envelope per
/// position, signed ONCE and durably retained BEFORE the first
/// register-member write); `economic_admitted_v2` (the device's admitted
/// economic position + root — the durable coordinate 3.4 deferred, written in
/// the same tx that clears the pending admission); `economic_leaf_cache`
/// (producer-side R_econ leaves, strategy A: a CACHE whose recomputed root
/// must equal the admitted root on load, with witness replay as recovery
/// truth — never an authority). Durable protocol state; same rule, no shim.
///
/// v9 (3.5b PR1): `economic_pending_admissions` gains `c_dsm_plus` — the v2
/// economic operation id binds the accepted successor's chain-state
/// commitment, and recovery cannot re-derive it from the head, so it is
/// durable admission state. A stored admission is post-acceptance by
/// construction (`Prepared` is never durable).
///
/// v10 (3.5b PR2): `peer_economic_lineage` — the device-local memo of peer
/// economic coordinates THIS verifier validated (its own conclusions, never
/// authority over a live register read).
///
/// v11 (3.5b PR3): `sender_outbox` gains the HELD status
/// `economic_admission_pending` — committed but non-deliverable until the
/// terminal admission transaction promotes it (ECON_ADMITTED atomically
/// releases the outbox to delivery).
///
/// v12 (3.5b PR4): recipient-side admission. `economic_pending_admissions`
/// gains `embedded_parent` (with `c_dsm_plus` it is the accepted successor's
/// `(parent, tip)` pair, which acceptance evidence binds its B-side pair to);
/// new `ek_cert_step_chain` (the device's per-relationship per-SIGNER
/// content-addressed EK step ancestry — what makes acceptance bundles
/// foreign-walkable); new `immutable_stored_memo` (exact immutable
/// addresses proven Stored on the canonical set — EK/evidence closure
/// durability is per exact address, NEVER inferred from an economic-position
/// watermark); `peer_economic_lineage` gains `closure_stored` (economic
/// DAG only); `recipient_outbound_reply` gains `held` (the B→A release is
/// frozen at accept and promoted to deliverable in the terminal admission
/// transaction — ECON_ADMITTED releases it atomically).
///
/// v16: `economic_admitted_v2.claim_ref` — the digest of the claim this
/// device's lineage accepted at its admitted position (SoFi Amendment S9),
/// which a setup's ClaimRef must equal; `route_chain_write` and
/// `route_chain_write_slot` — every route-chain write with the slot each
/// position produced (storage spec §9), replacing the reserve carry queue;
/// `completion_proof` and `completion_proof_slot` — the completion proofs
/// this device relies on (storage spec §9 rule 11);
/// `frozen_publication_artifact` keyed by content address alone, published
/// once read back `Stored`, and its member-acceptance table removed;
/// `immutable_stored_memo` replaces the quorum memo.
///
/// v17: `economic_admitted_history` — every position this device's lineage
/// admitted, in the admitted row's shape, so the claim it accepted at a
/// setup's position is still in hand once later positions are admitted
/// (SoFi Amendment S9); `own_directory_entry`, the device directory entry
/// this device last signed, replacing the per-node registry verification
/// table; `token_registry` keeps `genesis_supply` and `creator_device_id`;
/// `recipient_staging` has no rejection column; `storage_sync_runs` counts
/// the storage syncs that completed.
///
/// v18: no time and no counters. Every created/updated/spent/attempted column
/// is gone (they held a clock that never advanced); insertion order is the
/// rowid. `transactions.chain_height`/`step_index`,
/// `balance_projections.source_state_number` and `pending_transactions` are
/// gone.
pub const CLIENT_DB_SCHEMA_VERSION: i64 = 18;

/// A 32-byte column, exactly. Any other length is a corrupt row and an error —
/// never padded, never truncated.
pub(crate) fn column_32(row: &rusqlite::Row<'_>, i: usize) -> rusqlite::Result<[u8; 32]> {
    let v: Vec<u8> = row.get(i)?;
    <[u8; 32]>::try_from(v.as_slice()).map_err(|_| {
        rusqlite::Error::FromSqlConversionFailure(
            i,
            rusqlite::types::Type::Blob,
            format!("column {i} holds {} bytes, not 32", v.len()).into(),
        )
    })
}

/// Honest incompatibility detection — NOT legacy support.
///
/// With migration shims removed, an older database would otherwise stumble into
/// opaque "no such column" failures deep inside unrelated queries. This checks
/// `PRAGMA user_version` up front and fails with an explicit, actionable
/// condition instead. A fresh (empty) database is stamped with the current
/// version; a matching database passes; anything else is reported as requiring
/// a reset.
fn enforce_schema_version(conn: &Connection) -> Result<()> {
    let found: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;

    // An unstamped database is either brand new or predates versioning. Treat
    // "has no tables" as new and stamp it; anything else is pre-versioning and
    // must be reset rather than guessed at.
    if found == 0 {
        let table_count: i64 = conn.query_row(
            "SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'",
            [],
            |r| r.get(0),
        )?;
        if table_count > 0 {
            return Err(anyhow!(
                "SCHEMA RESET REQUIRED: client database predates schema versioning \
                 (expected version {CLIENT_DB_SCHEMA_VERSION}). DSM beta does not migrate — \
                 wipe the app database and re-provision from the wallet seed."
            ));
        }
        conn.execute_batch(&format!(
            "PRAGMA user_version = {CLIENT_DB_SCHEMA_VERSION};"
        ))?;
        return Ok(());
    }

    if found != CLIENT_DB_SCHEMA_VERSION {
        return Err(anyhow!(
            "SCHEMA RESET REQUIRED: client database is version {found}, this build expects \
             {CLIENT_DB_SCHEMA_VERSION}. DSM beta does not migrate — wipe the app database \
             and re-provision from the wallet seed."
        ));
    }
    Ok(())
}

fn create_schema(conn: &Connection) -> Result<()> {
    enforce_schema_version(conn)?;
    // Creating schema can race when two connections initialize one database
    // file concurrently. Retry on busy/locking errors.
    let mut attempts = 0u32;
    loop {
        let res = conn.execute_batch(
            r#"
        CREATE TABLE IF NOT EXISTS genesis_records(
            genesis_id        TEXT PRIMARY KEY,
            device_id         TEXT NOT NULL,
            mpc_proof         TEXT NOT NULL,
            device_birth_binding      TEXT NOT NULL,
            merkle_root       TEXT NOT NULL,
            participant_count INTEGER NOT NULL,
            chain_tip         TEXT NOT NULL,
            publication_hash  TEXT NOT NULL,
            storage_nodes     TEXT NOT NULL,
            entropy_hash      TEXT NOT NULL,
            protocol_version  TEXT NOT NULL,
            hash_chain_proof  BLOB,
            smt_proof         BLOB,
            verification_step INTEGER,
            genesis_nonce     TEXT NOT NULL DEFAULT '',
            genesis_profile   TEXT NOT NULL DEFAULT '',
            -- The network id the genesis was CREATED under. Required to
            -- re-derive the GRK / authority chain (Genesis v3): the
            -- derivation is seeded by (wallet_seed, network_id, index,
            -- version), and the seed alone cannot recover a value the
            -- user chose at creation time.
            network_id        TEXT NOT NULL DEFAULT 'dsm-testnet'
        );

        -- Identity publication lifecycle (§ "local genesis durable != identity ready").
        -- A device is only `published` once a quorum of storage nodes has been
        -- read back and confirmed to hold the exact identity tuple. Local genesis
        -- stays durable regardless; this table records how far publication got so
        -- startup can resume it without the user visiting the storage screen.
        CREATE TABLE IF NOT EXISTS identity_publication(
            device_id       TEXT PRIMARY KEY,
            genesis_hash    TEXT NOT NULL,
            state           TEXT NOT NULL,
            quorum_required INTEGER NOT NULL,
            last_error      TEXT NOT NULL DEFAULT ''
        );

        -- v17: this device's own directory entry, the last one it signed.
        CREATE TABLE IF NOT EXISTS own_directory_entry(
            id         INTEGER PRIMARY KEY CHECK (id = 1),
            entry      BLOB NOT NULL
        );

        -- v17: how many storage.sync runs completed on this device.
        CREATE TABLE IF NOT EXISTS storage_sync_runs(
            id        INTEGER PRIMARY KEY CHECK (id = 1),
            completed INTEGER NOT NULL
        );

        -- FROZEN PUBLICATION ARTIFACTS: the exact bytes of an immutable object a
        -- canonical advance froze (in the SAME transaction as the head write),
        -- owed to the storage set they were frozen FOR until that set holds
        -- them as `Stored` (storage spec §5 rule 6: three members return the
        -- exact bytes), established by reading them back. The object key is
        -- the object's content address, so one key names one byte string.
        CREATE TABLE IF NOT EXISTS frozen_publication_artifact(
            insertion_ordinal INTEGER PRIMARY KEY AUTOINCREMENT,
            object_key        TEXT NOT NULL UNIQUE,
            payload           BLOB NOT NULL,
            bound_root        BLOB NOT NULL,
            purpose           TEXT NOT NULL,
            storage_set_id    BLOB NOT NULL,
            state             TEXT NOT NULL CHECK (state IN
                                ('frozen','publication_pending','stored')),
            last_error        TEXT NOT NULL DEFAULT ''
        );

        -- SoFi v8: the persistent DLV node store is GONE (spec §44.4). Every
        -- line of it was dark, and the vault head past its genesis needs the
        -- leaf PREIMAGES a later acquisition consumes, which a node store
        -- cannot return. Beta takes clean cuts, so the tables go with the
        -- code rather than waiting for a migration nobody will write.
        DROP TABLE IF EXISTS sofi_smt_nodes;
        DROP TABLE IF EXISTS sofi_smt_pins;
        DROP TABLE IF EXISTS sofi_smt_nodes_v2;
        DROP TABLE IF EXISTS sofi_smt_pins_v2;

        -- v16: the vault head and evidence store (spec §44.4). The post
        -- state a resolved transition SELECTED, kept so the next trade
        -- against that vault has evidence to stand on. It decides no
        -- canonicality: `advance_resolved` already selected the state.
        --
        -- The roots are a chain, one row per generation, kept forever because
        -- a parent's status is asked about a GENERATION. The leaves are the
        -- CURRENT head's only and are replaced wholesale, because evidence
        -- needs leaf PREIMAGES and a mixture of two generations is not a tree.
        CREATE TABLE IF NOT EXISTS sofi_vault_root(
            vault_id   BLOB NOT NULL CHECK (length(vault_id) = 32),
            generation INTEGER NOT NULL CHECK (generation >= 0),
            root       BLOB NOT NULL CHECK (length(root) = 32),
            PRIMARY KEY (vault_id, generation)
        ) WITHOUT ROWID;
        CREATE TABLE IF NOT EXISTS sofi_vault_leaf(
            vault_id   BLOB NOT NULL CHECK (length(vault_id) = 32),
            leaf_key   BLOB NOT NULL CHECK (length(leaf_key) = 32),
            leaf_value BLOB NOT NULL CHECK (length(leaf_value) = 32),
            kind       INTEGER NOT NULL,
            preimage   BLOB NOT NULL,
            PRIMARY KEY (vault_id, leaf_key)
        ) WITHOUT ROWID;

        -- v15: the native ERA reserve (R4). This device's frozen release at
        -- one parent root — exact bytes, written before the first member
        -- write, replayed verbatim on every retry, never regenerated.
        CREATE TABLE IF NOT EXISTS native_reserve_release_local(
            reserve_id    BLOB NOT NULL CHECK (length(reserve_id) = 32),
            parent_root   BLOB NOT NULL CHECK (length(parent_root) = 32),
            envelope      BLOB NOT NULL,     -- exact NativeReserveReleaseV1 bytes
            PRIMARY KEY (reserve_id, parent_root)
        );

        -- v15: the reserve lineage memo — every FINAL release a walk
        -- established, with the state it succeeded. Finality is permanent,
        -- so a memoised state is a sound start for the next walk. A cache of
        -- Core's conclusions, never authority over a cell.
        CREATE TABLE IF NOT EXISTS native_reserve_lineage_memo(
            reserve_id         BLOB NOT NULL CHECK (length(reserve_id) = 32),
            generation         INTEGER NOT NULL CHECK (generation > 0),
            parent_remaining   INTEGER NOT NULL,
            remaining          INTEGER NOT NULL,
            recipient_genesis  BLOB NOT NULL CHECK (length(recipient_genesis) = 32),
            recipient_devid    BLOB NOT NULL CHECK (length(recipient_devid) = 32),
            recipient_position INTEGER NOT NULL,
            envelope           BLOB NOT NULL,
            PRIMARY KEY (reserve_id, generation)
        );

        -- Every value this device wrote along a cell's route (storage spec
        -- §9), with the slot each route position produced, so a write whose
        -- seats did not all answer is CONTINUED along the same chain rather
        -- than started again: a second copy at the leader carries another
        -- leader record, and no chain built on it ever counts.
        CREATE TABLE IF NOT EXISTS route_chain_write(
            namespace      BLOB NOT NULL,
            cell_key       BLOB NOT NULL CHECK (length(cell_key) = 32),
            value_digest   BLOB NOT NULL CHECK (length(value_digest) = 32),
            value          BLOB NOT NULL,
            seed           BLOB NOT NULL CHECK (length(seed) = 32),
            storage_set_id BLOB NOT NULL CHECK (length(storage_set_id) = 32),
            PRIMARY KEY (namespace, cell_key, value_digest)
        );
        -- The completion proofs this device relies on (storage spec §9 rule
        -- 11): the client keeps each one; nothing else stores it. Each slot
        -- is the exact ChainSlotV1 bytes of one route position.
        CREATE TABLE IF NOT EXISTS completion_proof(
            namespace      BLOB NOT NULL,
            cell_key       BLOB NOT NULL CHECK (length(cell_key) = 32),
            value_digest   BLOB NOT NULL CHECK (length(value_digest) = 32),
            value          BLOB NOT NULL,
            digest         BLOB NOT NULL CHECK (length(digest) = 32),
            PRIMARY KEY (namespace, cell_key, value_digest)
        );
        CREATE TABLE IF NOT EXISTS completion_proof_slot(
            namespace      BLOB NOT NULL,
            cell_key       BLOB NOT NULL CHECK (length(cell_key) = 32),
            value_digest   BLOB NOT NULL CHECK (length(value_digest) = 32),
            position       INTEGER NOT NULL CHECK (position >= 0),
            slot           BLOB NOT NULL,
            PRIMARY KEY (namespace, cell_key, value_digest, position)
        );
        CREATE TABLE IF NOT EXISTS route_chain_write_slot(
            namespace      BLOB NOT NULL,
            cell_key       BLOB NOT NULL CHECK (length(cell_key) = 32),
            value_digest   BLOB NOT NULL CHECK (length(value_digest) = 32),
            position       INTEGER NOT NULL CHECK (position >= 0),
            slot           BLOB NOT NULL,        -- exact ChainSlotV1 bytes
            PRIMARY KEY (namespace, cell_key, value_digest, position)
        );

        -- v8: the frozen economic-root claim envelope for one position.
        -- Signed ONCE, durably retained BEFORE the first register-member
        -- write; a byte-different re-encode is a DIFFERENT value at a
        -- write-once cell.
        CREATE TABLE IF NOT EXISTS economic_root_claim_local(
            economic_position INTEGER PRIMARY KEY,
            k_root            BLOB NOT NULL, -- 32B, derived, stored for reads
            envelope          BLOB NOT NULL -- exact EconomicRootClaimV1 bytes
        );

        -- v8: the admitted economic coordinate — the durable state 3.4
        -- deferred until it had a producer. Exactly one row (id=1); written
        -- in the SAME transaction that clears the pending admission, so
        -- "admitted" and "no longer pending" cannot disagree.
        -- The admitted position carries its CLAIM KIND: a conditional
        -- position commits two roots and has selected none, so a bare
        -- (position, root) pair cannot express it.
        CREATE TABLE IF NOT EXISTS economic_admitted_v2(
            id                INTEGER PRIMARY KEY CHECK (id = 1),
            economic_position INTEGER NOT NULL,
            -- 0 single-root, 1 resolved SoFi, 2 unresolved SoFi
            claim_kind        INTEGER NOT NULL,
            -- The USABLE root: present for kinds 0 and 1, NULL for kind 2,
            -- because an unresolved position has selected none.
            economic_root     BLOB,          -- 32B or NULL
            fulfillment_id    BLOB,          -- 32B, kinds 1 and 2
            realize_root      BLOB,          -- 32B, kind 2
            void_root         BLOB,          -- 32B, kind 2
            -- The digest of the claim the lineage accepted at the position:
            -- present for kinds 0 and 1, NULL for kind 2.
            claim_ref         BLOB          -- 32B or NULL
        );
        DROP TABLE IF EXISTS economic_admitted;

        -- v17: every admitted position, in economic_admitted_v2's shape. The
        -- row for a position is written in the same transaction as
        -- economic_admitted_v2; a conditional position later resolved is
        -- rewritten in its resolved shape.
        CREATE TABLE IF NOT EXISTS economic_admitted_history(
            economic_position INTEGER PRIMARY KEY,
            claim_kind        INTEGER NOT NULL,
            economic_root     BLOB,
            fulfillment_id    BLOB,
            realize_root      BLOB,
            void_root         BLOB,
            claim_ref         BLOB
        );

        -- v8: producer-side R_econ leaves (strategy A). A CACHE, never an
        -- authority: on load its recomputed root MUST equal economic_admitted_v2
        -- root, else it is discarded and rebuilt by replaying admitted
        -- witnesses (strategy B, the recovery truth). Written in the same tx
        -- as economic_admitted_v2.
        CREATE TABLE IF NOT EXISTS economic_leaf_cache(
            leaf_key   BLOB PRIMARY KEY,     -- 32B derived key
            leaf_value BLOB NOT NULL,        -- 32B economic_leaf_value
            state_ccb  BLOB NOT NULL        -- exact leaf-state CCB bytes
        );

        -- Device-local memo of peer economic coordinates THIS verifier
        -- validated (5H validated caching). A cache of the verifier's OWN
        -- conclusions: never authority over a live register read, and an
        -- Invalid verdict from a cached start deletes the peer's rows and
        -- re-walks from the activation root.
        CREATE TABLE IF NOT EXISTS peer_economic_lineage(
            peer_genesis        BLOB NOT NULL,      -- 32B
            peer_devid          BLOB NOT NULL,      -- 32B
            validated_position  INTEGER NOT NULL,
            validated_root      BLOB NOT NULL,      -- 32B
            -- ECONOMIC-DAG durability watermark ONLY: 1 means every object of
            -- the evidence closure this validation consumed was read back
            -- `Stored`. It says NOTHING about EK-step ancestry, which
            -- advances independently through relationship steps (including
            -- BLE steps that never touch R_econ) — EK durability is memoized
            -- per exact address in immutable_stored_memo, never inferred
            -- from an economic position.
            closure_stored   INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY(peer_genesis, peer_devid, validated_position)
        );

        -- The device's per-relationship per-SIGNER content-addressed EK step
        -- ancestry (3.5b PR4). Keyed by SIGNER identity, never receipt role:
        -- role reversal and BLE steps advance the same signer chain. This is
        -- what makes acceptance bundles foreign-walkable — the bundle
        -- references each side's predecessor step object by address.
        CREATE TABLE IF NOT EXISTS ek_cert_step_chain(
            rel_key      BLOB NOT NULL,             -- 32B
            signer_devid BLOB NOT NULL,             -- 32B
            step_ordinal INTEGER NOT NULL,
            step_addr    BLOB NOT NULL,             -- 32B EkCertStepV1 inner addr
            ek_pk        BLOB NOT NULL,             -- the pk this step certified
            PRIMARY KEY(rel_key, signer_devid, step_ordinal)
        );

        -- Exact immutable objects read back as `Stored` on the canonical set
        -- (storage spec §5 rule 6). Per exact address: a later admission may
        -- skip putting an object ONLY when it is listed here.
        CREATE TABLE IF NOT EXISTS immutable_stored_memo(
            namespace TEXT NOT NULL,
            addr      BLOB NOT NULL,                -- 32B inner digest
            PRIMARY KEY(namespace, addr)
        );

        CREATE TABLE IF NOT EXISTS contacts(
            contact_id                  TEXT PRIMARY KEY,
            device_id                   BLOB NOT NULL,
            alias                       TEXT NOT NULL,
            genesis_hash                BLOB NOT NULL,
            public_key                  BLOB,
            kyber_public_key            BLOB,
            chain_tip                   BLOB,
            verified                    INTEGER NOT NULL,
            verification_proof          BLOB,
            metadata                    BLOB,
            ble_address                 TEXT,
            status                      TEXT NOT NULL,
            needs_online_reconcile      INTEGER NOT NULL,
            local_bilateral_chain_tip   BLOB,
            previous_chain_tip          BLOB,
            device_tree_root            BLOB,
            observed_remote_chain_tip   BLOB,
            observed_remote_tip_source   INTEGER
        );

        -- Storage-node auth tokens are gone with writer authorization
        -- (storage spec §4); an older database drops its table here.
        DROP TABLE IF EXISTS auth_tokens;

        -- Which b0x messages this device has consumed: the device's own
        -- state, never a node's (b0x_consumed.rs).
        CREATE TABLE IF NOT EXISTS b0x_consumed(
            address     TEXT NOT NULL,
            message_id  TEXT NOT NULL,
            PRIMARY KEY (address, message_id)
        );
        CREATE TABLE IF NOT EXISTS b0x_read_position(
            address     TEXT NOT NULL,
            endpoint    TEXT NOT NULL,
            next_seq    INTEGER NOT NULL,
            PRIMARY KEY (address, endpoint)
        );
        -- The one sealed form of each outgoing spool payload, by message id
        -- (DSM Amendment A7; b0x_sealed.rs).
        CREATE TABLE IF NOT EXISTS b0x_sealed(
            message_id  TEXT PRIMARY KEY,
            sealed      BLOB NOT NULL
        );

        CREATE TABLE IF NOT EXISTS pending_online_outbox(
            counterparty_device_id BLOB PRIMARY KEY,
            message_id             TEXT NOT NULL,
            parent_tip             BLOB NOT NULL,
            next_tip               BLOB NOT NULL
        );

        -- Recipient B-side acceptance-receipt fold journal (§16.6). One row per
        -- consumed step (relationship_key, parent_tip): the exact countersigned
        -- receipt bytes + the pre-step / new local B cert head + encrypted ek_sk_b,
        -- written FIRST as durable evidence. An incomplete ('pending') row must
        -- block every new op on the relationship until recovery converges it via
        -- CAS phases (head advance, outbound-reply insert, mark complete).
        -- Pre-release schema cut (§16.6 fold v2): the acceptance journal + marker
        -- gained explicit A/B root pairs before ever shipping wired. The old-shape
        -- tables never held live rows — drop the old names (bcr_states precedent).
        DROP TABLE IF EXISTS recipient_acceptance_journal;
        DROP TABLE IF EXISTS accepted_transition;

        -- status: 'prepared' -> 'applied' -> 'complete' (+ 'rejected'). The receipt
        -- is generated + persisted at 'prepared' (BEFORE apply); the B/A cert heads
        -- and outbox are produced only after the transition is durably 'applied'.
        -- receipt_*_root_a = party A's roots claimed by the inbound receipt (bound
        -- by the semantic commitment the recipient countersigns).
        CREATE TABLE IF NOT EXISTS acceptance_fold_journal(
            relationship_key             BLOB NOT NULL,
            parent_tip                   BLOB NOT NULL,
            child_tip                    BLOB NOT NULL,
            counterparty_device_id       BLOB NOT NULL,
            commitment                   BLOB NOT NULL,
            receipt_parent_root_a        BLOB NOT NULL,
            receipt_child_root_a         BLOB NOT NULL,
            precommit_digest             BLOB NOT NULL,
            artifact_hash                BLOB NOT NULL,
            expected_local_b_head        BLOB,
            new_local_b_head             BLOB NOT NULL,
            new_local_b_sk_enc           BLOB,
            expected_counterparty_a_head BLOB,
            new_counterparty_a_head      BLOB NOT NULL,
            receipt_bytes                BLOB NOT NULL,
            -- SYMMETRIC-space projection CAS pair captured at PREPARE. The
            -- authority pair above is ASYMMETRIC (signed receipt); these two are
            -- the routing/addressing lineage and are never compared across.
            projection_parent_tip        BLOB NOT NULL,
            projection_target_tip        BLOB NOT NULL,
            -- THIS device's (B's) canonical relationship pair for the applied
            -- step, from the AdvanceOutcome the journal was written with, in the
            -- SAME transaction as the canonical apply record. sig_b authenticates
            -- it (B-canonical target); the sender pins the child as B's head.
            applied_parent_tip_b         BLOB NOT NULL,
            applied_child_tip_b          BLOB NOT NULL,
            -- The exact signed RecipientEconomicReleaseV1 wire bytes, frozen
            -- in the SAME accept transaction (3.5b PR4). The B->A reply
            -- carries THIS; bare sig_b cannot finalize the sender.
            release_bytes                BLOB,
            -- Finality barrier (recipient gate): 1 once the SENDER's verified
            -- RelationshipFinalizedV1 for this transition landed. Only the
            -- certificate handler flips it. While any non-rejected row on a
            -- relationship is 0, this device may not originate on it.
            peer_finalized               INTEGER NOT NULL DEFAULT 0
                                         CHECK(peer_finalized IN (0, 1)),
            status                       TEXT NOT NULL,
            PRIMARY KEY (relationship_key, parent_tip)
        );
        CREATE INDEX IF NOT EXISTS idx_acceptance_fold_journal_commitment
            ON acceptance_fold_journal(relationship_key, commitment);

        -- Immutable accepted-transition marker, keyed by (relationship_key, parent_tip):
        -- the recipient's durable attestation that it applied EXACTLY this transition.
        -- child_tip alone does NOT bind the state roots or the prepared receipt
        -- commitment, so phase 2 (prepared -> applied) promotes ONLY on a
        -- field-for-field match of this marker against the journal — never on tip
        -- equality alone. Written atomically with the recipient's canonical tip
        -- advance in the accept path.
        -- Canonical apply identity/record (§16.6 single-commit apply). Written INSIDE
        -- the full-state apply transaction; the durable proof that ONE exact
        -- authenticated parent was consumed and replaced by ONE exact successor.
        -- canonical_apply_id = BLAKE3("DSM/canonical-apply-id/v1" || pre-execution
        -- request identity, NO roots). Loaded verbatim on duplicate re-delivery
        -- (AlreadyAppliedSameOperation) — never reconstructed from mutable state.
        -- record_hash = BLAKE3("DSM/canonical-apply-record/v1" || id || B-roots).
        CREATE TABLE IF NOT EXISTS canonical_apply_identity(
            canonical_apply_id     BLOB PRIMARY KEY,
            relationship_key       BLOB NOT NULL,
            parent_tip             BLOB NOT NULL,
            child_tip              BLOB NOT NULL,
            precommit_digest       BLOB NOT NULL,
            operation_digest       BLOB NOT NULL,
            sender_device          BLOB NOT NULL,
            recipient_device       BLOB NOT NULL,
            nonce_hash             BLOB NOT NULL,
            applied_parent_root_b  BLOB NOT NULL,
            applied_child_root_b   BLOB NOT NULL,
            -- B's canonical relationship pair for this apply (see the journal).
            applied_parent_tip_b   BLOB NOT NULL,
            applied_child_tip_b    BLOB NOT NULL,
            record_hash            BLOB NOT NULL,
            UNIQUE (relationship_key, parent_tip),
            UNIQUE (nonce_hash)
        );

        -- Immutable accepted-transition marker: finalization evidence written
        -- atomically WITH the contacts.chain_tip PROJECTION sync (never part of
        -- the core apply transaction). Binds all three layers — the accepted
        -- state transition with BOTH root pairs (A's receipt-claimed roots AND
        -- B's authoritative applied roots from the CanonicalApplyRecord), the
        -- semantic receipt commitment, and the exact persisted countersigned
        -- artifact hash. Phase-2 promotion requires a field-for-field match
        -- against the journal — never tip equality alone.
        CREATE TABLE IF NOT EXISTS accepted_transition_marker(
            relationship_key               BLOB NOT NULL,
            parent_tip                     BLOB NOT NULL,
            child_tip                      BLOB NOT NULL,
            receipt_parent_root_a          BLOB NOT NULL,
            receipt_child_root_a           BLOB NOT NULL,
            applied_parent_root_b          BLOB NOT NULL,
            applied_child_root_b           BLOB NOT NULL,
            applied_parent_tip_b           BLOB NOT NULL,
            applied_child_tip_b            BLOB NOT NULL,
            precommit_digest               BLOB NOT NULL,
            prepared_receipt_commitment    BLOB NOT NULL,
            prepared_receipt_artifact_hash BLOB NOT NULL,
            sender_device                  BLOB NOT NULL,
            recipient_device               BLOB NOT NULL,
            PRIMARY KEY (relationship_key, parent_tip)
        );

        -- Durable outbound-reply record: the exact receipt bytes to (re)post to
        -- the sender's reply window, keyed by receipt commitment. Store-before-send;
        -- reposted until GC. Transport wiring is deferred (design step 6).
        CREATE TABLE IF NOT EXISTS sender_online_proposal(
            relationship_key       BLOB NOT NULL,
            canonical_parent       BLOB NOT NULL,   -- ASYM canonical parent (signed receipt space)
            canonical_child        BLOB NOT NULL,   -- ASYM canonical child
            projection_parent      BLOB NOT NULL,   -- SYM gate/wire routing space
            projection_target      BLOB NOT NULL,
            commitment             BLOB NOT NULL,
            operation_digest       BLOB NOT NULL,
            nonce_hash             BLOB NOT NULL,
            message_id             TEXT,
            tx_id                  TEXT NOT NULL,
            counterparty_device_id BLOB NOT NULL,
            amount                 INTEGER NOT NULL,
            token_id               TEXT NOT NULL,
            status                 TEXT NOT NULL,
            PRIMARY KEY (relationship_key, canonical_parent)
        );
        CREATE UNIQUE INDEX IF NOT EXISTS idx_sender_proposal_message
            ON sender_online_proposal(message_id) WHERE message_id IS NOT NULL;

        -- §16.6 durable sender outbox. Committed together with the canonical
        -- advance BEFORE any network call, so a local failure can never strand a
        -- deliverable message against a rolled-back debit. Carries the EXACT
        -- envelope bytes (retries resubmit the identical artifact, never a
        -- rebuild) and outlives finalization as `gc_pending` so the remaining
        -- lifecycle work stays reachable.
        CREATE TABLE IF NOT EXISTS cert_resync_state(
            relationship_key   BLOB NOT NULL PRIMARY KEY,
            -- 0 = CLEAR (ordinary sending allowed), 1 = REQUIRED, 2 = PENDING.
            -- Any non-zero value BLOCKS ordinary sends on this relationship.
            state              INTEGER NOT NULL DEFAULT 0 CHECK(state IN (0, 1, 2)),
            -- Monotonic per-relationship epoch. A resync tuple whose epoch is not
            -- strictly greater than this is rejected (anti-replay).
            epoch              INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS cert_chain_resync_audit(
            relationship_key              BLOB NOT NULL,
            -- The PRESERVED accepted commitment this restart is anchored to
            -- (content identity — one resync per agreed accepted transition).
            preserved_acceptance_commitment BLOB NOT NULL,
            accepted_parent_tip           BLOB NOT NULL,
            accepted_child_tip            BLOB NOT NULL,
            -- Digest of the jointly-authorized restart statement.
            joint_auth_hash               BLOB NOT NULL,
            epoch                         INTEGER NOT NULL,
            old_local_head                BLOB,
            old_counterparty_head         BLOB,
            new_local_head                BLOB NOT NULL,
            new_counterparty_head         BLOB NOT NULL,
            reason_code                   TEXT NOT NULL,
            PRIMARY KEY (relationship_key, preserved_acceptance_commitment)
        );

        CREATE TABLE IF NOT EXISTS projection_repair_queue(
            device_id   TEXT NOT NULL,
            token_id    TEXT NOT NULL,
            reason      TEXT NOT NULL,
            PRIMARY KEY (device_id, token_id)
        );

        -- Anchored token policies. A policy may exist WITHOUT a token: the
        -- developer paste-raw-bytes path publishes one on its own, so this has
        -- a separate lifetime from token_registry.
        --
        -- `policy_commit` IS the content hash: BLAKE3(TAG_DSM_POLICY,
        -- policy_bytes). Storing it as the primary key makes the table
        -- self-verifying — a row whose bytes do not hash to its key is
        -- detectable without any external authority.
        CREATE TABLE IF NOT EXISTS token_policies(
            policy_commit  BLOB PRIMARY KEY,   -- 32B content hash
            policy_bytes   BLOB NOT NULL      -- TokenPolicyV3-encoded
        );

        -- Tokens created on this device.
        --
        -- Deliberately carries NO circulating-supply column. Circulating
        -- supply is derived from the canonical BCR chain, not cached here: a
        -- mutable counter would be a second authority that a restored snapshot
        -- could disagree with, and the supply cap would then be enforceable
        -- against the wrong number.
        CREATE TABLE IF NOT EXISTS token_registry(
            token_id        TEXT NOT NULL PRIMARY KEY,
            policy_commit   BLOB NOT NULL,
            ticker          TEXT NOT NULL,
            alias           TEXT NOT NULL,
            decimals        INTEGER NOT NULL CHECK (decimals BETWEEN 0 AND 18),
            genesis_supply    BLOB NOT NULL,   -- 16B big-endian u128
            creator_device_id BLOB NOT NULL,   -- 32B, the policy's creator
            UNIQUE (policy_commit)
        );
        CREATE UNIQUE INDEX IF NOT EXISTS idx_token_registry_ticker
            ON token_registry(ticker);

        CREATE TABLE IF NOT EXISTS sender_outbox(
            relationship_key    BLOB NOT NULL,
            canonical_parent    BLOB NOT NULL,   -- ASYM canonical parent (proposal identity)
            canonical_child     BLOB NOT NULL,
            commitment          BLOB NOT NULL,   -- receipt commitment = finalization identity
            projection_parent   BLOB NOT NULL,   -- SYM routing/gate space
            projection_target   BLOB NOT NULL,
            routing_address     TEXT NOT NULL,
            submission_id       TEXT NOT NULL,   -- deterministic; equals the node message_id
            envelope_bytes      BLOB NOT NULL,   -- exact submitted bytes
            proposal_nonce      BLOB NOT NULL,   -- completes the durable identity
            -- Local cert-head CAS expectation. NULL is meaningful ONLY when
            -- is_first_ek_step = 1; an unexplained NULL is never read as genesis.
            local_expected_prev BLOB,
            is_first_ek_step    INTEGER NOT NULL CHECK(is_first_ek_step IN (0, 1)),
            status              TEXT NOT NULL,
            message_ids         TEXT,            -- GC metadata ONLY, never authority
            PRIMARY KEY (relationship_key, canonical_parent, proposal_nonce),
            UNIQUE (commitment),
            UNIQUE (submission_id),
            CHECK (status IN (
                'economic_admission_pending',
                'pending_submit', 'submitting', 'submitted',
                'submission_uncertain', 'finalization_checkpoint_pending',
                'gc_pending', 'complete'
            ))
        );

        -- ADR 0003: additional frozen artifacts belonging to ONE outbox proposal.
        --
        -- The transfer artifact keeps living in `sender_outbox.envelope_bytes`.
        -- This table holds every OTHER artifact the same proposal will emit --
        -- today the A-side receipt evidence, later the B-side countersign delta.
        --
        -- One proposal owns the deterministic ids and exact bytes of all of its
        -- artifacts, and they are written in the SAME transaction as the
        -- canonical advance. That makes the invariant structural rather than
        -- remembered: after the local debit commits, either every deliverable
        -- artifact is durably reconstructible byte-for-byte, or none is.
        --
        -- The FK is enforced (PRAGMA foreign_keys = ON), so an artifact cannot
        -- outlive or precede its proposal, and ON DELETE CASCADE keeps GC from
        -- stranding orphans.
        CREATE TABLE IF NOT EXISTS sender_outbox_artifacts(
            relationship_key    BLOB NOT NULL,
            canonical_parent    BLOB NOT NULL,
            proposal_nonce      BLOB NOT NULL,
            role                TEXT NOT NULL,
            submission_id       TEXT NOT NULL,   -- deterministic; the node message_id
            envelope_bytes      BLOB NOT NULL,   -- exact submitted bytes; retry replays these
            content_digest      BLOB NOT NULL,   -- role-domain-separated address of the payload
            -- Frozen route for artifacts that do NOT ride the owning outbox's
            -- route (the finality certificate goes to the RECIPIENT's route);
            -- NULL ⇒ the owning outbox route.
            routing_address     TEXT,
            PRIMARY KEY (relationship_key, canonical_parent, proposal_nonce, role),
            UNIQUE (submission_id),
            FOREIGN KEY (relationship_key, canonical_parent, proposal_nonce)
                REFERENCES sender_outbox(relationship_key, canonical_parent, proposal_nonce)
                ON DELETE CASCADE,
            CHECK (role IN ('evidence_a', 'countersign_b', 'relationship_finalized'))
        );

        -- ADR 0003 step 3: the recipient's durable staging area.
        --
        -- A split transfer arrives as two independent artifacts. Neither half
        -- alone authorises anything, so each is staged durably and NOTHING is
        -- acknowledged or applied until both are present, digest-bound and
        -- verified. Arrival order is not part of identity: the row is keyed by
        -- the logical transfer correlation id, and whichever half arrives first
        -- creates it.
        --
        -- Exact received bytes are stored for both halves. Pairing and
        -- verification operate on those frozen bytes, never on a protobuf
        -- reconstructed from them -- a re-encode is how "the bytes I verified"
        -- silently stops being "the bytes that arrived".
        --
        -- There is no rejected state. A pair that does not verify does not
        -- execute, and a transfer that does not execute changes no state and
        -- records nothing negative (DSM Amendment A1).
        CREATE TABLE IF NOT EXISTS recipient_staging(
            correlation_key          TEXT PRIMARY KEY,
            state                    TEXT NOT NULL,
            -- transfer half (exact received bytes)
            transfer_bytes           BLOB,
            -- the evidence reference the transfer carries (proto field 12)
            expected_evidence_digest BLOB,
            -- evidence half (exact received bytes) + the digest computed over them
            evidence_bytes           BLOB,
            evidence_digest          BLOB,
            -- The b0x inbox address the FIRST half arrived on. Kept in the
            -- recipient's poll set while the pair is incomplete or unACKed, so
            -- a partner artifact replayed by the sender under the same frozen
            -- route is still received after the relationship tip advances.
            -- Both halves must arrive on the same route (set-or-require-equal);
            -- released to NULL only when this key's ACKs succeed.
            retained_route           TEXT,
            CHECK (state IN (
                'staged_transfer', 'staged_evidence', 'ready_to_verify',
                'accepted'
            ))
        );

        CREATE TABLE IF NOT EXISTS recipient_outbound_reply(
            commitment             BLOB PRIMARY KEY,
            relationship_key       BLOB NOT NULL,
            counterparty_device_id BLOB NOT NULL,
            child_tip              BLOB NOT NULL,
            receipt_bytes          BLOB NOT NULL,
            -- The signed RecipientEconomicReleaseV1 wire bytes, frozen in
            -- the accept transaction. The sender finalizes on the RELEASE,
            -- not on bare sig_b.
            release_bytes          BLOB,
            -- HELD (1) until ECON_ADMITTED: the terminal admission
            -- transaction promotes held rows to deliverable atomically.
            held                   INTEGER NOT NULL DEFAULT 0,
            submitted              INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS balance_projections(
            balance_key         TEXT NOT NULL PRIMARY KEY,
            device_id           TEXT NOT NULL,
            token_id            TEXT NOT NULL,
            policy_commit       TEXT NOT NULL,
            available           INTEGER NOT NULL DEFAULT 0 CHECK(available >= 0),
            locked              INTEGER NOT NULL DEFAULT 0 CHECK(locked >= 0),
            source_state_hash   TEXT NOT NULL,
            UNIQUE (device_id, token_id)
        );

        CREATE INDEX IF NOT EXISTS idx_balance_projections_device_token
            ON balance_projections(device_id, token_id);

        CREATE TABLE IF NOT EXISTS spent_nonces(
            nonce_hash  BLOB PRIMARY KEY,
            tx_id       TEXT NOT NULL,
            sender_id   TEXT NOT NULL,
            amount      INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS settings(
            key         TEXT PRIMARY KEY,
            value       TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS bcr_reports(
            report_id   INTEGER PRIMARY KEY AUTOINCREMENT,
            report      BLOB NOT NULL
        );

        -- Per-relationship chain state archive (§2.2/§4.2).
        -- Authoritative per-advance history keyed by chain_tip (h_{n+1}).
        -- The device-monolith `bcr_states` table is fully removed —
        -- canonical history lives here, current head lives in
        -- `bcr_device_heads` below.
        CREATE TABLE IF NOT EXISTS bcr_chain_states(
            device_id        BLOB NOT NULL,    -- 32B (DevID_A)
            rel_key          BLOB NOT NULL,    -- 32B (k_{A↔B} per §2.2)
            chain_tip        BLOB NOT NULL,    -- 32B (h_{n+1} = compute_chain_tip())
            embedded_parent  BLOB NOT NULL,    -- 32B (h_n on this chain)
            state_bytes      BLOB NOT NULL,    -- canonical RelationshipChainState bytes
            published        INTEGER NOT NULL,
            PRIMARY KEY (device_id, chain_tip)
        );

        CREATE INDEX IF NOT EXISTS idx_bcr_chain_by_rel
            ON bcr_chain_states(device_id, rel_key);

        -- Device head cache (§2.2). Non-authoritative latest snapshot of the
        -- canonical DeviceState (SMT root + balances + tips). UPSERTed on
        -- every successful advance and at genesis. Authoritative source
        -- remains the bcr_chain_states log + the in-memory StateMachine.
        CREATE TABLE IF NOT EXISTS bcr_device_heads(
            device_id   BLOB PRIMARY KEY,      -- 32B
            smt_root    BLOB NOT NULL,         -- 32B (r_A — stored for sanity check)
            head_bytes  BLOB NOT NULL         -- canonical DeviceState bytes
        );

        -- The economic admission in flight, if any. AT MOST ONE per device:
        -- the position cannot advance while pending, so a second concurrent
        -- admission is not a thing that can exist. PRIMARY KEY(device_id)
        -- enforces that structurally rather than by convention.
        --
        -- Written in the SAME transaction as the head advance that created it
        -- (see dual_write_advance_outcome_with_extra). That atomicity is the
        -- durability invariant: a value-bearing local acceptance must not
        -- become durable unless every input needed to recover the EXACT,
        -- byte-identical admission evidence is durable with it. If these could
        -- commit separately, a crash between them would leave either fenced
        -- value with no record of why, or a fence with no accepted value.
        --
        -- Deliberately NOT inside head_bytes: that would need a
        -- DEVICE_STATE_VERSION bump, which under the beta no-legacy rule means
        -- wiping every existing head. DeviceState::restore takes it as a
        -- REQUIRED argument instead, so every rebuild path must supply it.
        CREATE TABLE IF NOT EXISTS economic_pending_admissions(
            device_id               BLOB PRIMARY KEY,   -- 32B
            kind                    INTEGER NOT NULL,   -- 0 dsm, 1 load, 2 unload, 3 sofi fulfillment
            fenced_asset            BLOB,               -- 32B, NULL for kind 0
            lifecycle_state         INTEGER NOT NULL,   -- 0..4, forward only
            economic_position       INTEGER NOT NULL,
            pre_economic_root       BLOB NOT NULL,      -- 32B
            post_economic_root      BLOB NOT NULL,      -- 32B
            operation_digest        BLOB NOT NULL,      -- 32B
            accepted_substrate_addr BLOB NOT NULL,      -- 32B
            admission_manifest_addr BLOB NOT NULL,      -- 32B
            c_dsm_plus              BLOB NOT NULL,      -- 32B, the accepted
                                                        -- successor's chain-state
                                                        -- commitment (v2 econ-op-id
                                                        -- preimage) — recovery
                                                        -- cannot re-derive it
            embedded_parent         BLOB NOT NULL      -- 32B, the successor's own
                                                        -- parent tip: with c_dsm_plus
                                                        -- the (parent, tip) pair the
                                                        -- acceptance B-side binds to
        );

        -- Device head storage is BCR-only (§4.3): no state counter and no
        -- monolithic snapshot keyed by hash.
        DROP TABLE IF EXISTS bcr_states;
        DROP INDEX IF EXISTS idx_bcr_states_device_published;

        CREATE TABLE IF NOT EXISTS bilateral_sessions(
            commitment_hash           BLOB PRIMARY KEY,
            counterparty_device_id    BLOB NOT NULL,
            counterparty_genesis_hash BLOB,
            operation_bytes           BLOB NOT NULL,
            phase                     TEXT NOT NULL,
            local_signature           BLOB,
            counterparty_signature    BLOB,
            sender_ble_address        TEXT,
            stitched_receipt_bytes    BLOB
        );

        -- §5.3 Atomic bilateral commit: persists the confirm envelope atomically
        -- with sender finalization so it survives crashes for re-delivery.
        CREATE TABLE IF NOT EXISTS pending_confirm_delivery(
            commitment_hash        BLOB PRIMARY KEY,
            counterparty_device_id BLOB NOT NULL,
            confirm_envelope       BLOB NOT NULL
        );

        CREATE TABLE IF NOT EXISTS system_peers(
            peer_key       TEXT PRIMARY KEY,
            device_id      BLOB NOT NULL UNIQUE,
            display_name   TEXT NOT NULL,
            peer_type      TEXT NOT NULL,
            chain_tip      BLOB,
            metadata       BLOB
        );
        CREATE INDEX IF NOT EXISTS idx_system_peers_type ON system_peers(peer_type);

        CREATE TABLE IF NOT EXISTS system_peer_events(
            peer_key             TEXT NOT NULL,
            peer_type            TEXT NOT NULL,
            parent_tip           BLOB NOT NULL,
            child_tip            BLOB NOT NULL,
            transition_digest    BLOB NOT NULL,
            source_state_hash    BLOB NOT NULL,
            source_state_number  INTEGER NOT NULL,
            payload_bytes        BLOB NOT NULL,
            PRIMARY KEY(peer_key, child_tip),
            FOREIGN KEY(peer_key) REFERENCES system_peers(peer_key)
        );
        -- §4.3: there is no counter. Two distinct events may legitimately
        -- carry the same `source_state_number` (it is now derived material,
        -- e.g. hash[0]). Drop any pre-migration UNIQUE index, then create a
        -- non-unique companion index for lookup.
        DROP INDEX IF EXISTS idx_system_peer_events_source_state;
        CREATE INDEX IF NOT EXISTS idx_system_peer_events_source_state_nonunique
            ON system_peer_events(peer_key, source_state_number);

        CREATE TABLE IF NOT EXISTS transactions(
            tx_id              TEXT PRIMARY KEY,
            tx_hash            TEXT NOT NULL,
            from_device        TEXT NOT NULL,
            to_device          TEXT NOT NULL,
            amount             INTEGER NOT NULL,
            tx_type            TEXT NOT NULL,
            status             TEXT NOT NULL,
            commitment_hash    TEXT,
            proof_data         BLOB,
            metadata           BLOB
        );

        CREATE INDEX IF NOT EXISTS idx_transactions_from_device
            ON transactions(from_device);

        CREATE INDEX IF NOT EXISTS idx_transactions_to_device
            ON transactions(to_device);

        CREATE TABLE IF NOT EXISTS bilateral_sender_settlements(
            tx_id             TEXT NOT NULL,
            sender_device_id  TEXT NOT NULL,
            PRIMARY KEY(tx_id, sender_device_id)
        );

        CREATE INDEX IF NOT EXISTS idx_bilateral_sender_settlements_device
            ON bilateral_sender_settlements(sender_device_id);

        CREATE UNIQUE INDEX IF NOT EXISTS idx_contacts_device_id
            ON contacts(device_id);

        CREATE INDEX IF NOT EXISTS idx_contacts_alias
            ON contacts(alias);

        CREATE INDEX IF NOT EXISTS idx_contacts_ble_address
            ON contacts(ble_address) WHERE ble_address IS NOT NULL;

        CREATE TABLE IF NOT EXISTS vault_store(
            vault_id         TEXT PRIMARY KEY,
            vault_proto_full BLOB NOT NULL,
            vault_state      TEXT NOT NULL,
            entry_header     BLOB NOT NULL,
            btc_amount_sats  INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS vault_records(
            vault_op_id         TEXT PRIMARY KEY,
            direction           TEXT NOT NULL,
            vault_state         TEXT NOT NULL,
            hash_lock           BLOB NOT NULL,
            vault_id            TEXT,
            btc_amount_sats     INTEGER NOT NULL,
            btc_pubkey          BLOB NOT NULL,
            htlc_script         BLOB,
            htlc_address        TEXT,
            external_commitment BLOB,
            refund_iterations   INTEGER NOT NULL,
            created_at_state    INTEGER NOT NULL,
            entry_header        BLOB,
            parent_vault_id     TEXT,
            successor_depth     INTEGER NOT NULL DEFAULT 0,
            is_fractional_successor INTEGER NOT NULL DEFAULT 0,
            destination_address    TEXT,
            funding_txid           TEXT,
            refund_hash_lock       BLOB,
            exit_amount_sats       INTEGER NOT NULL DEFAULT 0,
            exit_header            BLOB,
            exit_confirm_depth     INTEGER NOT NULL DEFAULT 0,
            entry_txid             BLOB,
            deposit_nonce          BLOB
        );

        CREATE TABLE IF NOT EXISTS manifold_seeds(
            policy_commit BLOB NOT NULL PRIMARY KEY,
            seed          BLOB NOT NULL
        );

        CREATE TABLE IF NOT EXISTS bitcoin_accounts(
            account_id            TEXT PRIMARY KEY,
            label                 TEXT NOT NULL,
            import_kind           TEXT NOT NULL,
            secret_material       BLOB NOT NULL,
            network               INTEGER NOT NULL,
            first_address         TEXT,
            active                INTEGER NOT NULL DEFAULT 0,
            active_receive_index  INTEGER NOT NULL DEFAULT 0
        );

        CREATE INDEX IF NOT EXISTS idx_bitcoin_accounts_active
            ON bitcoin_accounts(active);

        CREATE TABLE IF NOT EXISTS ble_reassembly_state(
            frame_commitment  BLOB NOT NULL,
            chunk_index       INTEGER NOT NULL,
            frame_type        INTEGER NOT NULL,
            total_chunks      INTEGER NOT NULL,
            payload_len       INTEGER NOT NULL,
            chunk_data        BLOB NOT NULL,
            checksum          INTEGER NOT NULL,
            counterparty_id   BLOB,
            PRIMARY KEY (frame_commitment, chunk_index)
        );
        CREATE INDEX IF NOT EXISTS idx_ble_reassembly_frame
            ON ble_reassembly_state(frame_commitment);
        CREATE INDEX IF NOT EXISTS idx_ble_reassembly_counterparty
            ON ble_reassembly_state(counterparty_id) WHERE counterparty_id IS NOT NULL;

        CREATE TABLE IF NOT EXISTS in_flight_withdrawals(
            withdrawal_id    TEXT PRIMARY KEY,
            device_id        TEXT NOT NULL,
            amount_sats      INTEGER NOT NULL CHECK(amount_sats > 0),
            dest_address     TEXT NOT NULL,
            policy_commit    BLOB NOT NULL,
            state            TEXT NOT NULL DEFAULT 'committed',
            redemption_txid  TEXT,
            vault_content_hash BLOB,
            burn_token_id    TEXT,
            burn_amount_sats INTEGER NOT NULL DEFAULT 0,
            settlement_poll_count INTEGER NOT NULL DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_in_flight_withdrawals_device
            ON in_flight_withdrawals(device_id, state);

        CREATE TABLE IF NOT EXISTS in_flight_withdrawal_legs(
            withdrawal_id         TEXT NOT NULL,
            leg_index             INTEGER NOT NULL,
            vault_id              TEXT NOT NULL,
            leg_kind              TEXT NOT NULL,
            amount_sats           INTEGER NOT NULL CHECK(amount_sats >= 0),
            estimated_fee_sats    INTEGER NOT NULL DEFAULT 0,
            estimated_net_sats    INTEGER NOT NULL DEFAULT 0,
            sweep_txid            TEXT,
            successor_vault_id    TEXT,
            successor_vault_op_id TEXT,
            exit_vault_op_id      TEXT,
            state                 TEXT NOT NULL,
            proof_digest          BLOB,
            PRIMARY KEY (withdrawal_id, leg_index),
            FOREIGN KEY (withdrawal_id) REFERENCES in_flight_withdrawals(withdrawal_id)
        );
        CREATE INDEX IF NOT EXISTS idx_in_flight_withdrawal_legs_withdrawal
            ON in_flight_withdrawal_legs(withdrawal_id, state);

        -- Per-relationship cert chain heads (whitepaper §11.1 ek-cert chain).
        -- One row per (relationship_key, side). `side` is 0 for the local
        -- device's chain head (used to sign outgoing certs and to advance
        -- after acceptance) and 1 for the counterparty's chain head (used
        -- to verify incoming certs).
        --
        -- chain_head_pubkey is the SPHINCS+ public key of the prior signer:
        -- AK_pk at step 0, EK_pk_n for n > 0.
        --
        -- chain_head_sk_encrypted is the ChaCha20-Poly1305 ciphertext of
        -- the corresponding SECRET key (for Local rows only; NULL for
        -- Counterparty), encrypted under a key derived from the chain-head wrap key so
        -- extracted ciphertext cannot be used on a different device.
        -- Used at receipt creation time to sign cert_{n+1}; wiped after
        -- consumption when chain_head advances.
        --
        -- step_count tracks the current chain length for this relationship.
        CREATE TABLE IF NOT EXISTS cert_chain_heads(
            relationship_key        BLOB NOT NULL,
            side                    INTEGER NOT NULL CHECK(side IN (0, 1)),
            chain_head_pubkey       BLOB NOT NULL,
            chain_head_sk_encrypted BLOB,
            step_count              INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (relationship_key, side)
        );

        -- The ONE authority for the PEER's canonical relationship head
        -- (bilateral finality barrier). One row per relationship: the head the
        -- peer will sign under when it next originates. Advanced by CAS from
        -- BOTH roles — the signed A pair on inbound apply (in the apply tx),
        -- the sig_b-authenticated B pair on sender finalize (in the finalize
        -- tx). No row ⇔ fresh relationship (genesis seed). The recipient's
        -- pin (`pinned_counterparty_a_head`) reads this table only.
        CREATE TABLE IF NOT EXISTS counterparty_canonical_heads(
            relationship_key       BLOB PRIMARY KEY,
            counterparty_device_id BLOB NOT NULL,
            head_tip               BLOB NOT NULL,
            prev_tip               BLOB NOT NULL,
            source_commitment      BLOB NOT NULL
        );

        -- §11.1 sender-side DEFERRED Local chain-head advance. The new
        -- per-step EK (pubkey + AEAD-encrypted SK, same wrap scheme as
        -- cert_chain_heads) signed into an outbound bilateral confirm is
        -- held here, keyed by the bilateral commitment, until the
        -- receiver's commit-response proves the step was accepted — then
        -- it is promoted into cert_chain_heads.Local. Advancing at
        -- confirm-BUILD time (the previous behavior) moved the Local head
        -- past a step the receiver could still reject (e.g. MissingRelease)
        -- or never see, after which every subsequent transfer signed a
        -- cert the receiver could not chain back to its expected prior
        -- head — permanently wedging the relationship. is_init records
        -- whether the sign fell back to the root AK (relationship genesis,
        -- no Local row yet) so promotion knows to INSERT (step 0) rather
        -- than UPDATE.
        CREATE TABLE IF NOT EXISTS pending_local_cert_heads(
            relationship_key        BLOB NOT NULL,
            commitment_hash         BLOB NOT NULL,
            ek_pubkey               BLOB NOT NULL,
            ek_sk_encrypted         BLOB NOT NULL,
            is_init                 INTEGER NOT NULL CHECK(is_init IN (0, 1)),
            PRIMARY KEY (relationship_key, commitment_hash)
        );

        -- Offline-bearer receiver-side appliance-root lineage (Def. 25 check 2:
        -- "previous root is the receiver's accepted root"). One row per HOLDER
        -- (sender) device: the appliance root the receiver adopted from the last
        -- ACCEPTED release's `next_root`, plus the anchor counter adopted with it.
        -- Written only after the canonical commit succeeds (deferred, like the
        -- §11.1 cert-chain mirrors). Absent row = relationship genesis: the first
        -- release's own `prev_root` is adopted TOFU — its authenticity rests on
        -- the anchor-state commitment proofs + the LIVE authenticated counter
        -- (`H == H0 − (uᵢ+1)`), the same trust root as the first-transfer pin.
        CREATE TABLE IF NOT EXISTS anchor_accepted_roots(
            device_id            BLOB NOT NULL PRIMARY KEY,
            accepted_root        BLOB NOT NULL,
            next_anchor_counter  INTEGER NOT NULL
        );

        -- Offline-bearer anti-clone (Software-Authority / Hardware-Identity): the RECEIVER's
        -- pinned admission of a counterparty's fused anchor, keyed by the counterparty device id —
        -- the persistent backing for `dsm::crypto::anchor_enrollment::AnchorEnrollmentStore`
        -- (v2 FusedAnchorPin shape, `pk_chip` = resident chip Ed25519 key). Must persist so a
        -- restart cannot drop the pinned identity (which would re-open the first-transfer TOFU
        -- window).
        CREATE TABLE IF NOT EXISTS anchor_enrollments(
            device_id          BLOB NOT NULL PRIMARY KEY,
            policy_hash        BLOB NOT NULL,
            bundle             BLOB NOT NULL,
            anchor_id          BLOB NOT NULL,
            enrolled_counter   INTEGER NOT NULL,
            partition_pk       BLOB NOT NULL,
            pk_chip            BLOB NOT NULL,
            uncompromised      INTEGER NOT NULL
        );
        "#
        );
        match res {
            Ok(()) => break,
            Err(e) => {
                let should_retry = match &e {
                    rusqlite::Error::SqliteFailure(err, _opt) => {
                        let code = err.code;
                        code == rusqlite::ErrorCode::DatabaseBusy
                            || code == rusqlite::ErrorCode::DatabaseLocked
                    }
                    _ => false,
                };
                attempts += 1;
                if should_retry && attempts < 10 {
                    std::thread::sleep(std::time::Duration::from_millis(50));
                    continue;
                }
                return Err(anyhow!(e));
            }
        }
    }
    // Now create remaining indices (not part of the retried batch).
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_bilateral_sessions_counterparty ON bilateral_sessions(counterparty_device_id);",
        [],
    )?;
    info!("Schema OK (clockless, binary-first)");
    Ok(())
}

pub(crate) fn get_connection() -> Result<Arc<Mutex<Connection>>> {
    init_database()?;
    let guard = DB_CONNECTION
        .read()
        .map_err(|e| anyhow!("DB lock poisoned: {e}"))?;
    guard.clone().ok_or_else(|| anyhow!("DB not initialised"))
}

// =========================== settings (small helpers) ===========================

pub(super) fn settings_get(conn: &Connection, key: &str) -> Result<Option<String>> {
    let v: Option<String> = conn
        .query_row(
            "SELECT value FROM settings WHERE key = ?1",
            params![key],
            |row| row.get(0),
        )
        .optional()?;
    Ok(v)
}

pub(super) fn settings_set(conn: &Connection, key: &str, value: &str) -> Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO settings(key, value) VALUES (?1, ?2)",
        params![key, value],
    )?;
    Ok(())
}

// =========================== public settings accessors ===========================

/// Get a setting value by key. Public wrapper for use from handlers.
pub fn get_setting(key: &str) -> Result<Option<String>> {
    let arc = get_connection()?;
    let conn = arc.lock().map_err(|e| anyhow!("DB lock poisoned: {e}"))?;
    settings_get(&conn, key)
}

/// Set a setting value by key. Public wrapper for use from handlers.
pub fn set_setting(key: &str, value: &str) -> Result<()> {
    let arc = get_connection()?;
    let conn = arc.lock().map_err(|e| anyhow!("DB lock poisoned: {e}"))?;
    settings_set(&conn, key, value)
}

/// Count total processed transactions (inbox items applied).
pub fn get_transaction_count() -> Result<u64> {
    let arc = get_connection()?;
    let conn = arc.lock().map_err(|e| anyhow!("DB lock poisoned: {e}"))?;
    let count: i64 = conn.query_row("SELECT COUNT(*) FROM transactions", [], |row| row.get(0))?;
    Ok(u64::try_from(count)?)
}

// =========================== tests ===========================

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;
    use std::collections::HashMap;

    /// Helper to clean up test data
    fn cleanup_test_genesis() {
        if let Ok(binding) = get_connection() {
            if let Ok(conn) = binding.lock() {
                // Delete all test data
                let _ = conn.execute("DELETE FROM genesis_records", []);
                // Force a checkpoint to ensure changes are written
                let _ = conn.execute("PRAGMA wal_checkpoint(TRUNCATE)", []);
            }
        }
    }

    #[test]
    fn test_meta_roundtrip() {
        let mut m = HashMap::new();
        m.insert("a".into(), b"1".to_vec());
        m.insert("b".into(), vec![2, 3, 4]);
        let blob = meta_to_blob(&m);
        let back = match meta_from_blob(&blob) {
            Ok(m) => m,
            Err(e) => panic!("meta_from_blob failed: {e}"),
        };
        let av = back.get("a").unwrap_or_else(|| panic!("missing key a"));
        assert_eq!(av, b"1");
        let bv = back.get("b").unwrap_or_else(|| panic!("missing key b"));
        assert_eq!(bv, &vec![2, 3, 4]);
    }

    #[test]
    #[serial]
    fn test_genesis_store_and_read() {
        let _ = init_database();
        cleanup_test_genesis();

        let rec = GenesisRecord {
            genesis_id: "gen-123".into(),
            device_id: "dev-456".into(),
            mpc_proof: "mpc".into(),
            device_birth_binding: "bind".into(),
            merkle_root: "root".into(),
            participant_count: 3,
            progress_marker: "P".into(),
            publication_hash: "pub".into(),
            storage_nodes: vec!["n1".into(), "n2".into()],
            entropy_hash: "e".into(),
            protocol_version: "1.0".into(),
            hash_chain_proof: None,
            smt_proof: None,
            verification_step: None,
            genesis_nonce: String::new(),
            genesis_profile: String::new(),
            network_id: "dsm-test".into(),
        };

        if let Err(e) = store_genesis_record_with_verification(&rec) {
            panic!("store_genesis_record_with_verification failed: {e}");
        }
        let latest_opt = match get_verified_genesis_record() {
            Ok(v) => v,
            Err(e) => panic!("get_verified_genesis_record failed: {e}"),
        };
        let latest = latest_opt.unwrap_or_else(|| panic!("no verified genesis record"));
        assert_eq!(latest.genesis_id, "gen-123");
        assert_eq!(latest.participant_count, 3);
        assert!(latest.hash_chain_proof.is_some());
        assert!(latest.smt_proof.is_some());
    }

    fn seed_contact_for_chain_tip_tests(device_id: [u8; 32], genesis_hash: [u8; 32], status: &str) {
        let binding = get_connection().expect("db connection");
        let conn = binding.lock().expect("db lock");
        let _ = conn.execute("DELETE FROM contacts", []);
        drop(conn);

        let contact = ContactRecord {
            contact_id: crate::util::text_id::encode_base32_crockford(&device_id),
            device_id: device_id.to_vec(),
            alias: "peer".to_string(),
            genesis_hash: genesis_hash.to_vec(),
            public_key: vec![7u8; 32],
            kyber_public_key: Vec::new(),
            current_chain_tip: None,
            verified: true,
            verification_proof: None,
            metadata: HashMap::new(),
            ble_address: None,
            status: status.to_string(),
            needs_online_reconcile: false,
            previous_chain_tip: None,
        };
        store_contact(&contact).expect("store contact");
    }

    #[test]
    #[serial]
    fn test_record_observed_remote_chain_tip_preserves_canonical_bilateral_tips() {
        crate::economic_fixtures::use_test_storage_dir();
        reset_database_for_tests();
        init_database().expect("init db");

        let device_id = [0x41u8; 32];
        let genesis_hash = [0x51u8; 32];
        let local_tip = [0xA1u8; 32];
        let observed_tip = [0xB2u8; 32];

        seed_contact_for_chain_tip_tests(device_id, genesis_hash, "BleCapable");
        update_local_bilateral_chain_tip(&device_id, &local_tip).expect("seed local tip");

        record_observed_remote_chain_tip(
            &device_id,
            &observed_tip,
            ObservedRemoteTipSource::DeferredInbox,
        )
        .expect("record observed tip");

        assert_eq!(get_contact_chain_tip_raw(&device_id), None);
        assert_eq!(get_local_bilateral_chain_tip(&device_id), Some(local_tip));
        assert_eq!(
            get_observed_remote_chain_tip(&device_id).expect("load observed tip"),
            Some(observed_tip)
        );
        assert_eq!(
            get_observed_remote_tip_record(&device_id)
                .expect("load observed tip record")
                .expect("observed tip record exists")
                .source,
            ObservedRemoteTipSource::DeferredInbox
        );
    }

    #[test]
    #[serial]
    fn test_deferred_observed_remote_tip_does_not_block_send_ready_relationship() {
        crate::economic_fixtures::use_test_storage_dir();
        reset_database_for_tests();
        init_database().expect("init db");

        let device_id = [0x42u8; 32];
        let genesis_hash = [0x52u8; 32];
        let canonical_tip = [0x62u8; 32];
        let deferred_tip = [0x72u8; 32];

        seed_contact_for_chain_tip_tests(device_id, genesis_hash, "BleCapable");
        restore_finalized_bilateral_chain_tip(&device_id, &canonical_tip)
            .expect("seed canonical tip");
        record_observed_remote_chain_tip(
            &device_id,
            &deferred_tip,
            ObservedRemoteTipSource::DeferredInbox,
        )
        .expect("record deferred observation");

        let status = crate::handlers::relationship_status::derive_local_send_status_for_device_id(
            &device_id,
        );
        assert!(
            status.send_ready,
            "deferred inbox observation should not hard-block a healthy relationship"
        );
    }

    #[test]
    #[serial]
    fn test_live_peer_claim_blocks_send_ready_relationship() {
        crate::economic_fixtures::use_test_storage_dir();
        reset_database_for_tests();
        init_database().expect("init db");

        let device_id = [0x43u8; 32];
        let genesis_hash = [0x53u8; 32];
        let canonical_tip = [0x63u8; 32];
        let peer_claim_tip = [0x73u8; 32];

        seed_contact_for_chain_tip_tests(device_id, genesis_hash, "BleCapable");
        restore_finalized_bilateral_chain_tip(&device_id, &canonical_tip)
            .expect("seed canonical tip");
        record_observed_remote_chain_tip(
            &device_id,
            &peer_claim_tip,
            ObservedRemoteTipSource::LivePeerClaim,
        )
        .expect("record live peer claim");

        let status = crate::handlers::relationship_status::derive_local_send_status_for_device_id(
            &device_id,
        );
        assert!(
            !status.send_ready,
            "live peer claim mismatch should still block send readiness"
        );
        assert!(
            status
                .send_block_message
                .contains("Live peer reported a different relationship tip"),
            "unexpected block message: {}",
            status.send_block_message
        );
    }

    #[test]
    #[serial]
    fn test_sync_bilateral_tips_clears_deferred_observation_after_success() {
        crate::economic_fixtures::use_test_storage_dir();
        reset_database_for_tests();
        init_database().expect("init db");

        let device_id = [0x44u8; 32];
        let genesis_hash = [0x54u8; 32];
        let target_tip = [0x64u8; 32];
        let stale_local = [0x65u8; 32];
        let deferred_tip = [0x66u8; 32];

        seed_contact_for_chain_tip_tests(device_id, genesis_hash, "BleCapable");
        restore_finalized_bilateral_chain_tip(&device_id, &target_tip).expect("seed canonical");
        update_local_bilateral_chain_tip(&device_id, &stale_local).expect("seed stale local");
        record_observed_remote_chain_tip(
            &device_id,
            &deferred_tip,
            ObservedRemoteTipSource::DeferredInbox,
        )
        .expect("record deferred observation");

        let request = bilateral_tip_sync::TipSyncRequest {
            counterparty_device_id: device_id,
            expected_parent_tip: target_tip,
            target_tip,
        };
        bilateral_tip_sync::sync_bilateral_tips_atomically(&request).expect("sync should succeed");

        assert!(
            get_observed_remote_tip_record(&device_id)
                .expect("load observed tip record")
                .is_none(),
            "authoritative convergence should retire deferred observations"
        );
    }

    #[test]
    #[serial]
    fn test_restore_finalized_bilateral_chain_tip_updates_local_restore_tip() {
        crate::economic_fixtures::use_test_storage_dir();
        reset_database_for_tests();
        init_database().expect("init db");

        let device_id = [0x61u8; 32];
        let genesis_hash = [0x71u8; 32];
        let stale_local_tip = [0x11u8; 32];
        let finalized_tip = [0x22u8; 32];

        seed_contact_for_chain_tip_tests(device_id, genesis_hash, "BleCapable");
        update_local_bilateral_chain_tip(&device_id, &stale_local_tip).expect("seed local tip");
        mark_contact_needs_online_reconcile(&device_id).expect("mark reconcile");

        restore_finalized_bilateral_chain_tip(&device_id, &finalized_tip)
            .expect("restore finalized tip");

        assert_eq!(get_contact_chain_tip_raw(&device_id), Some(finalized_tip));
        assert_eq!(
            get_local_bilateral_chain_tip(&device_id),
            Some(finalized_tip)
        );

        let stored = get_contact_by_device_id(&device_id)
            .expect("load contact")
            .expect("contact exists");
        assert_eq!(stored.status, "BleCapable");
        assert!(!stored.needs_online_reconcile);
    }

    #[test]
    #[serial]
    fn test_try_advance_finalized_bilateral_chain_tip_rejects_stale_parent() {
        crate::economic_fixtures::use_test_storage_dir();
        reset_database_for_tests();
        init_database().expect("init db");

        let device_id = [0x81u8; 32];
        let genesis_hash = [0x91u8; 32];
        let current_tip = [0x33u8; 32];
        let stale_parent = [0x44u8; 32];
        let new_tip = [0x55u8; 32];

        seed_contact_for_chain_tip_tests(device_id, genesis_hash, "BleCapable");
        restore_finalized_bilateral_chain_tip(&device_id, &current_tip).expect("seed current tip");

        let advanced =
            try_advance_finalized_bilateral_chain_tip(&device_id, &stale_parent, &new_tip)
                .expect("advance should not error");

        assert!(!advanced, "stale parent must be rejected");
        assert_eq!(get_contact_chain_tip_raw(&device_id), Some(current_tip));
        assert_eq!(get_local_bilateral_chain_tip(&device_id), Some(current_tip));
    }

    #[test]
    #[serial]
    fn test_record_pending_online_transition_persists_gate_and_local_tip() {
        crate::economic_fixtures::use_test_storage_dir();
        reset_database_for_tests();
        init_database().expect("init db");

        let device_id = [0xA1u8; 32];
        let genesis_hash = [0xB1u8; 32];
        let parent_tip = [0xC1u8; 32];
        let next_tip = [0xD1u8; 32];

        seed_contact_for_chain_tip_tests(device_id, genesis_hash, "BleCapable");
        restore_finalized_bilateral_chain_tip(&device_id, &parent_tip).expect("seed parent tip");

        record_pending_online_transition(&device_id, "0Q4T3ZGMVR8JKPGS", &parent_tip, &next_tip)
            .expect("persist pending transition");

        assert_eq!(get_contact_chain_tip_raw(&device_id), Some(parent_tip));
        assert_eq!(get_local_bilateral_chain_tip(&device_id), Some(next_tip));

        let pending = get_pending_online_outbox(&device_id)
            .expect("load pending row")
            .expect("pending row exists");
        assert_eq!(pending.message_id, "0Q4T3ZGMVR8JKPGS");
        assert_eq!(pending.parent_tip, parent_tip.to_vec());
        assert_eq!(pending.next_tip, next_tip.to_vec());
    }

    #[test]
    #[serial]
    fn test_record_pending_online_transition_rejects_divergent_existing_gate() {
        crate::economic_fixtures::use_test_storage_dir();
        reset_database_for_tests();
        init_database().expect("init db");

        let device_id = [0xB1u8; 32];
        let genesis_hash = [0xC1u8; 32];
        let parent_tip = [0xD1u8; 32];
        let next_tip = [0xE1u8; 32];
        let divergent_next_tip = [0xF1u8; 32];

        seed_contact_for_chain_tip_tests(device_id, genesis_hash, "BleCapable");
        restore_finalized_bilateral_chain_tip(&device_id, &parent_tip).expect("seed parent tip");
        record_pending_online_transition(&device_id, "MSG-1", &parent_tip, &next_tip)
            .expect("persist initial gate");

        let err =
            record_pending_online_transition(&device_id, "MSG-2", &parent_tip, &divergent_next_tip)
                .expect_err("divergent gate must be rejected");
        assert!(err.to_string().contains("different gate"));

        let pending = get_pending_online_outbox(&device_id)
            .expect("load pending row")
            .expect("pending row exists");
        assert_eq!(pending.message_id, "MSG-1");
        assert_eq!(pending.next_tip, next_tip.to_vec());
        assert_eq!(get_local_bilateral_chain_tip(&device_id), Some(next_tip));
    }

    #[test]
    #[serial]
    fn test_restore_finalized_bilateral_chain_tip_rejects_conflicting_existing_tip() {
        crate::economic_fixtures::use_test_storage_dir();
        reset_database_for_tests();
        init_database().expect("init db");

        let device_id = [0x21u8; 32];
        let genesis_hash = [0x31u8; 32];
        let current_tip = [0x41u8; 32];
        let conflicting_tip = [0x51u8; 32];

        seed_contact_for_chain_tip_tests(device_id, genesis_hash, "BleCapable");
        restore_finalized_bilateral_chain_tip(&device_id, &current_tip).expect("seed current tip");

        let err = restore_finalized_bilateral_chain_tip(&device_id, &conflicting_tip)
            .expect_err("conflicting restore must fail");
        assert!(err.to_string().contains("Refusing to overwrite"));
        assert_eq!(get_contact_chain_tip_raw(&device_id), Some(current_tip));
        assert_eq!(get_local_bilateral_chain_tip(&device_id), Some(current_tip));
    }

    #[test]
    #[serial]
    fn test_advance_system_chain_tip_tracks_sovereign_lineage() {
        crate::economic_fixtures::use_test_storage_dir();
        reset_database_for_tests();
        init_database().expect("init db");

        let peer = SystemPeerRecord {
            peer_key: "era-source-dlv".to_string(),
            device_id: [0xABu8; 32].to_vec(),
            display_name: "ERA Source DLV".to_string(),
            peer_type: SystemPeerType::Dlv,
            current_chain_tip: None,
            metadata: HashMap::new(),
        };
        store_system_peer(&peer).expect("store peer");

        let payload_one = b"faucet.claim:first".to_vec();
        let payload_two = b"faucet.claim:second".to_vec();
        let source_hash_one = [0x11u8; 32];
        let source_hash_two = [0x22u8; 32];

        let first = advance_system_chain_tip(
            "era-source-dlv",
            SystemPeerType::Dlv,
            &[0u8; 32],
            &payload_one,
            &source_hash_one,
            5,
        )
        .expect("advance first event");
        let second = advance_system_chain_tip(
            "era-source-dlv",
            SystemPeerType::Dlv,
            &first.child_tip,
            &payload_two,
            &source_hash_two,
            6,
        )
        .expect("advance second event");

        assert_eq!(first.parent_tip, vec![0u8; 32]);
        assert_ne!(first.child_tip, source_hash_one.to_vec());
        assert_eq!(second.parent_tip, first.child_tip);
        assert_ne!(second.child_tip, source_hash_two.to_vec());

        let stored = get_system_peer("era-source-dlv")
            .expect("load peer")
            .expect("peer exists");
        assert_eq!(stored.current_chain_tip, Some(second.child_tip.clone()));

        let events = get_system_peer_events("era-source-dlv").expect("load events");
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].child_tip, first.child_tip);
        assert_eq!(events[1].child_tip, second.child_tip);
    }

    #[test]
    #[serial]
    fn test_store_system_peer_is_insert_only_for_existing_identity() {
        crate::economic_fixtures::use_test_storage_dir();
        reset_database_for_tests();
        init_database().expect("init db");

        let peer = SystemPeerRecord {
            peer_key: "era-source-dlv".to_string(),
            device_id: [0xABu8; 32].to_vec(),
            display_name: "ERA Source DLV".to_string(),
            peer_type: SystemPeerType::Dlv,
            current_chain_tip: None,
            metadata: HashMap::new(),
        };
        store_system_peer(&peer).expect("store peer");
        let advanced = advance_system_chain_tip(
            "era-source-dlv",
            SystemPeerType::Dlv,
            &[0u8; 32],
            b"faucet.claim:first",
            &[0x11u8; 32],
            5,
        )
        .expect("advance peer");

        let attempted_overwrite = SystemPeerRecord {
            peer_key: "era-source-dlv".to_string(),
            device_id: [0xABu8; 32].to_vec(),
            display_name: "mutated".to_string(),
            peer_type: SystemPeerType::Dlv,
            current_chain_tip: None,
            metadata: HashMap::from([("note".to_string(), b"overwrite".to_vec())]),
        };
        let err =
            store_system_peer(&attempted_overwrite).expect_err("duplicate system peer must fail");
        assert!(err.to_string().contains("already exists"));

        let stored = get_system_peer("era-source-dlv")
            .expect("load peer")
            .expect("peer exists");
        assert_eq!(stored.display_name, "ERA Source DLV");
        assert_eq!(stored.current_chain_tip, Some(advanced.child_tip));
        assert!(stored.metadata.is_empty());
    }

    #[test]
    #[serial]
    fn test_advance_system_chain_tip_rejects_stale_expected_parent() {
        crate::economic_fixtures::use_test_storage_dir();
        reset_database_for_tests();
        init_database().expect("init db");

        let peer = SystemPeerRecord {
            peer_key: "era-source-dlv".to_string(),
            device_id: [0xCBu8; 32].to_vec(),
            display_name: "ERA Source DLV".to_string(),
            peer_type: SystemPeerType::Dlv,
            current_chain_tip: None,
            metadata: HashMap::new(),
        };
        store_system_peer(&peer).expect("store peer");

        let first = advance_system_chain_tip(
            "era-source-dlv",
            SystemPeerType::Dlv,
            &[0u8; 32],
            b"faucet.claim:first",
            &[0x61u8; 32],
            7,
        )
        .expect("advance first event");

        let err = advance_system_chain_tip(
            "era-source-dlv",
            SystemPeerType::Dlv,
            &[0xEEu8; 32],
            b"faucet.claim:second",
            &[0x62u8; 32],
            8,
        )
        .expect_err("stale expected parent must fail");
        assert!(err.to_string().contains("expected parent tip"));

        let stored = get_system_peer("era-source-dlv")
            .expect("load peer")
            .expect("peer exists");
        assert_eq!(stored.current_chain_tip, Some(first.child_tip));
    }

    #[test]
    #[serial]
    fn test_advance_system_chain_tip_accepts_duplicate_source_state_number_per_section_4_3() {
        // Per §4.3 there is no `state_number`. The prior test asserted that a
        // duplicate `source_state_number` was rejected — that check was a
        // residual counter check that bricked beta-tester faucet claims when
        // `state.hash[0]` happened to fall (e.g. 2 ≤ 17). Acceptance now
        // depends only on structural parent-tip continuity (verified below
        // by the second advance succeeding from `first.child_tip`).
        crate::economic_fixtures::use_test_storage_dir();
        reset_database_for_tests();
        init_database().expect("init db");

        let peer = SystemPeerRecord {
            peer_key: "era-source-dlv".to_string(),
            device_id: [0xDBu8; 32].to_vec(),
            display_name: "ERA Source DLV".to_string(),
            peer_type: SystemPeerType::Dlv,
            current_chain_tip: None,
            metadata: HashMap::new(),
        };
        store_system_peer(&peer).expect("store peer");

        let first = advance_system_chain_tip(
            "era-source-dlv",
            SystemPeerType::Dlv,
            &[0u8; 32],
            b"faucet.claim:first",
            &[0x71u8; 32],
            9,
        )
        .expect("advance first event");

        // Duplicate source_state_number must NOT block the advance under §4.3.
        let second = advance_system_chain_tip(
            "era-source-dlv",
            SystemPeerType::Dlv,
            &first.child_tip,
            b"faucet.claim:duplicate-number",
            &[0x72u8; 32],
            9,
        )
        .expect("duplicate source_state_number must succeed (§4.3, no counter)");
        assert_eq!(second.parent_tip, first.child_tip);
        assert_eq!(second.source_state_number, 9);
    }

    #[test]
    #[serial]
    fn test_store_contact_upserts_by_device_id_and_repairs_identity_fields() {
        crate::economic_fixtures::use_test_storage_dir();
        reset_database_for_tests();
        init_database().expect("init db");

        let device_id = [0x11u8; 32];
        let original_tip = [0x22u8; 32];
        let original = ContactRecord {
            contact_id: "original-contact".to_string(),
            device_id: device_id.to_vec(),
            alias: "peer".to_string(),
            genesis_hash: [0x33u8; 32].to_vec(),
            public_key: vec![0x44u8; 64],
            kyber_public_key: Vec::new(),
            current_chain_tip: Some(original_tip.to_vec()),
            verified: true,
            verification_proof: None,
            metadata: HashMap::new(),
            ble_address: None,
            status: "Created".to_string(),
            needs_online_reconcile: true,
            previous_chain_tip: None,
        };
        store_contact(&original).expect("store original contact");

        let repaired = ContactRecord {
            contact_id: "new-contact-id".to_string(),
            device_id: device_id.to_vec(),
            alias: "peer-fixed".to_string(),
            genesis_hash: [0x55u8; 32].to_vec(),
            public_key: vec![0x66u8; 64],
            kyber_public_key: Vec::new(),
            current_chain_tip: None,
            verified: true,
            verification_proof: None,
            metadata: HashMap::new(),
            ble_address: Some("11:22:33:44:55:66".to_string()),
            status: "Active".to_string(),
            needs_online_reconcile: false,
            previous_chain_tip: None,
        };
        store_contact(&repaired).expect("repair contact by device id");

        let stored = get_contact_by_device_id(&device_id)
            .expect("load repaired contact")
            .expect("contact exists");
        assert_eq!(stored.contact_id, "original-contact");
        assert_eq!(stored.alias, "peer-fixed");
        assert_eq!(stored.genesis_hash, [0x55u8; 32].to_vec());
        assert_eq!(stored.public_key, vec![0x66u8; 64]);
        assert_eq!(stored.current_chain_tip, Some(original_tip.to_vec()));
        assert_eq!(stored.status, "Active");
        assert!(!stored.needs_online_reconcile);
    }

    // ═══════════════════════════════════════════════════════════════
    // §5.4 Atomic bilateral tip sync tests
    // ═══════════════════════════════════════════════════════════════

    #[test]
    #[serial]
    fn test_sync_bilateral_tips_advance_both_columns_atomically() {
        crate::economic_fixtures::use_test_storage_dir();
        reset_database_for_tests();
        init_database().expect("init db");

        let device_id = [0xE1u8; 32];
        let genesis_hash = [0xF1u8; 32];
        let parent_tip = [0x01u8; 32];
        let new_tip = [0x02u8; 32];

        seed_contact_for_chain_tip_tests(device_id, genesis_hash, "BleCapable");
        restore_finalized_bilateral_chain_tip(&device_id, &parent_tip).expect("seed");

        let request = bilateral_tip_sync::TipSyncRequest {
            counterparty_device_id: device_id,
            expected_parent_tip: parent_tip,
            target_tip: new_tip,
        };
        let outcome = bilateral_tip_sync::sync_bilateral_tips_atomically(&request)
            .expect("sync should succeed");

        assert!(matches!(
            outcome,
            bilateral_tip_sync::TipSyncOutcome::Advanced { .. }
        ));
        assert_eq!(get_contact_chain_tip_raw(&device_id), Some(new_tip));
        assert_eq!(get_local_bilateral_chain_tip(&device_id), Some(new_tip));
    }

    #[test]
    #[serial]
    fn test_sync_bilateral_tips_repairs_stale_local() {
        crate::economic_fixtures::use_test_storage_dir();
        reset_database_for_tests();
        init_database().expect("init db");

        let device_id = [0xE2u8; 32];
        let genesis_hash = [0xF2u8; 32];
        let target_tip = [0x03u8; 32];
        let stale_local = [0x04u8; 32];

        seed_contact_for_chain_tip_tests(device_id, genesis_hash, "BleCapable");
        restore_finalized_bilateral_chain_tip(&device_id, &target_tip).expect("seed canonical");
        update_local_bilateral_chain_tip(&device_id, &stale_local).expect("seed stale local");

        let request = bilateral_tip_sync::TipSyncRequest {
            counterparty_device_id: device_id,
            expected_parent_tip: target_tip,
            target_tip,
        };
        let outcome = bilateral_tip_sync::sync_bilateral_tips_atomically(&request)
            .expect("sync should succeed");

        assert!(matches!(
            outcome,
            bilateral_tip_sync::TipSyncOutcome::RepairedAtTarget { .. }
        ));
        assert_eq!(get_contact_chain_tip_raw(&device_id), Some(target_tip));
        assert_eq!(get_local_bilateral_chain_tip(&device_id), Some(target_tip));
    }

    #[test]
    #[serial]
    fn test_sync_bilateral_tips_already_at_target() {
        crate::economic_fixtures::use_test_storage_dir();
        reset_database_for_tests();
        init_database().expect("init db");

        let device_id = [0xE3u8; 32];
        let genesis_hash = [0xF3u8; 32];
        let tip = [0x05u8; 32];

        seed_contact_for_chain_tip_tests(device_id, genesis_hash, "BleCapable");
        restore_finalized_bilateral_chain_tip(&device_id, &tip).expect("seed");

        let request = bilateral_tip_sync::TipSyncRequest {
            counterparty_device_id: device_id,
            expected_parent_tip: tip,
            target_tip: tip,
        };
        let outcome = bilateral_tip_sync::sync_bilateral_tips_atomically(&request)
            .expect("sync should succeed");

        assert!(matches!(
            outcome,
            bilateral_tip_sync::TipSyncOutcome::AlreadyAtTarget { .. }
        ));
    }

    #[test]
    #[serial]
    fn test_sync_bilateral_tips_parent_mismatch_commits_nothing() {
        crate::economic_fixtures::use_test_storage_dir();
        reset_database_for_tests();
        init_database().expect("init db");

        let device_id = [0xE4u8; 32];
        let genesis_hash = [0xF4u8; 32];
        let current_tip = [0x06u8; 32];
        let wrong_parent = [0x07u8; 32];
        let new_tip = [0x08u8; 32];

        seed_contact_for_chain_tip_tests(device_id, genesis_hash, "BleCapable");
        restore_finalized_bilateral_chain_tip(&device_id, &current_tip).expect("seed");

        let request = bilateral_tip_sync::TipSyncRequest {
            counterparty_device_id: device_id,
            expected_parent_tip: wrong_parent,
            target_tip: new_tip,
        };
        let outcome = bilateral_tip_sync::sync_bilateral_tips_atomically(&request)
            .expect("sync should not error");

        assert!(matches!(
            outcome,
            bilateral_tip_sync::TipSyncOutcome::CanonicalMovedToDifferentTip { .. }
        ));
        // Tips unchanged
        assert_eq!(get_contact_chain_tip_raw(&device_id), Some(current_tip));
        assert_eq!(get_local_bilateral_chain_tip(&device_id), Some(current_tip));
    }

    /// The tip sync NEVER touches the pending online gate (finality barrier:
    /// the ONE deleter is the post-quorum checkpoint release). A gate seeded
    /// beside a tip advance survives the advance untouched.
    #[test]
    #[serial]
    fn test_sync_bilateral_tips_never_touches_the_gate() {
        crate::economic_fixtures::use_test_storage_dir();
        reset_database_for_tests();
        init_database().expect("init db");

        let device_id = [0xE5u8; 32];
        let genesis_hash = [0xF5u8; 32];
        let parent_tip = [0x09u8; 32];
        let next_tip = [0x0Au8; 32];

        seed_contact_for_chain_tip_tests(device_id, genesis_hash, "BleCapable");
        restore_finalized_bilateral_chain_tip(&device_id, &parent_tip).expect("seed");
        store_pending_online_outbox(&device_id, "msg123", &parent_tip, &next_tip)
            .expect("insert gate");

        let request = bilateral_tip_sync::TipSyncRequest {
            counterparty_device_id: device_id,
            expected_parent_tip: parent_tip,
            target_tip: next_tip,
        };
        let outcome = bilateral_tip_sync::sync_bilateral_tips_atomically(&request)
            .expect("sync should succeed");
        assert!(matches!(
            outcome,
            bilateral_tip_sync::TipSyncOutcome::Advanced { .. }
        ));
        assert_eq!(get_contact_chain_tip_raw(&device_id), Some(next_tip));
        assert_eq!(get_local_bilateral_chain_tip(&device_id), Some(next_tip));
        assert_eq!(
            get_pending_online_outbox(&device_id)
                .expect("load")
                .expect("gate survives the tip advance")
                .message_id,
            "msg123"
        );
    }

    #[test]
    #[serial]
    fn test_exact_gate_delete_does_not_kill_newer_gate() {
        crate::economic_fixtures::use_test_storage_dir();
        reset_database_for_tests();
        init_database().expect("init db");

        let device_id = [0xE7u8; 32];
        let old_parent = [0x10u8; 32];
        let old_next = [0x11u8; 32];
        let new_parent = [0x12u8; 32];
        let new_next = [0x13u8; 32];

        // Insert gate A
        let genesis = [0xF7u8; 32];
        seed_contact_for_chain_tip_tests(device_id, genesis, "BleCapable");
        store_pending_online_outbox(&device_id, "old_msg", &old_parent, &old_next)
            .expect("insert gate A");

        // Replace with gate B (simulates concurrent online send)
        clear_pending_online_outbox(&device_id).expect("clear A");
        store_pending_online_outbox(&device_id, "new_msg", &new_parent, &new_next)
            .expect("insert gate B");

        // Attempt exact-match delete using gate A's identity — should NOT delete gate B
        let deleted = clear_pending_online_outbox_if_matches(&device_id, &old_parent, &old_next)
            .expect("exact delete should not error");
        assert!(!deleted, "old gate identity must not match newer gate");

        // Gate B survives
        let gate = get_pending_online_outbox(&device_id)
            .expect("load")
            .expect("gate exists");
        assert_eq!(gate.message_id, "new_msg");
        assert_eq!(gate.parent_tip, new_parent.to_vec());
        assert_eq!(gate.next_tip, new_next.to_vec());
    }

    // ============ §5.4 stale-gate decision (clear_stale_pending_online_gate) ============
    //
    // The test above pins the storage PRIMITIVE: an exact-match delete carrying a
    // stale identity refuses. The BLE handler used to ignore that refusal — it
    // consumed the `Result<bool>` with `if let Err(..)`, so `Ok(false)` read as
    // success and it cleared the in-memory §5.4 modal lock and admitted the
    // offline transfer anyway. These pin the DECISION the handler now consumes.

    // ===================== tagged-hash cut deployment preflight =====================
    //
    // The drain is a CUT BOUNDARY, not an observation. These pin that the
    // preflight refuses in both blocking conditions and permits only when both
    // are clear. Prose in the ADR describes the operator sequence; this is the
    // part a machine enforces.

    #[test]
    fn the_cut_preflight_permits_only_a_fully_clear_state() {
        use crate::storage::client_db::cert_resync::CutPreflight;
        assert!(CutPreflight::Clear.may_upgrade());
        assert!(
            !CutPreflight::OutstandingResyncs(1).may_upgrade(),
            "a relationship mid-resync cannot complete across the cut — its \
             in-flight joint statement was derived under the pre-cut digest"
        );
        // The spool half is NODE-side, and scoped to the holders of the
        // affected traffic rather than to the fleet — see
        // dsm_storage_node::api::infra::hardening::spool_drain_preflight.
        // This enum deliberately does not model a table this process does not own.
    }

    /// ANTI-VACUITY for the B3 arm, and the third of the three B3 checks: a
    /// relationship that still owes a resync must BLOCK the cut. Its in-flight
    /// joint statement was derived under the pre-cut digest and cannot be
    /// completed across it — the two sides would derive different statements.
    #[test]
    #[serial]
    fn an_outstanding_cert_resync_blocks_the_cut() {
        crate::economic_fixtures::use_test_storage_dir();
        reset_database_for_tests();
        init_database().expect("init db");

        let rel = [0x5Au8; 32];
        crate::storage::client_db::cert_resync::mark_cert_resync_required(&rel)
            .expect("mark required");

        let outcome = crate::storage::client_db::cert_resync::tagged_hash_cut_preflight()
            .expect("preflight must not error");
        assert_eq!(
            outcome,
            crate::storage::client_db::cert_resync::CutPreflight::OutstandingResyncs(1)
        );
        assert!(
            !outcome.may_upgrade(),
            "the cut proceeded while a relationship was mid-resync"
        );
    }

    /// B4 CACHE INVENTORY, pinned rather than asserted in prose.
    ///
    /// The trace found NO cached verification verdict for the ML-KEM identity
    /// binding anywhere:
    ///
    ///   - `verify_kyber_identity_binding` has ZERO production callers; only
    ///     `build_local_kyber_identity_binding` is used (b0x_sdk ×2,
    ///     storage_node_sdk ×1).
    ///   - the storage node PERSISTS `kyber_public_key` + `kyber_binding_sig`
    ///     in its device registry and never verifies the signature.
    ///   - `contacts.kyber_public_key` caches the peer's KEY, not the binding
    ///     digest and not a verdict.
    ///   - no Android/Kotlin reference exists at all.
    ///
    /// `contacts.verified` / `verification_proof` are contact-trust fields with
    /// a sticky OR on upsert, written from `ContactRecord`, never from a binding
    /// check. This test pins that independence: storing a contact WITH a Kyber
    /// public key must not mark it verified. If a future change ever routes a
    /// binding verdict into that column, it becomes a B4 cache and this fails.
    #[test]
    #[serial]
    fn storing_a_kyber_public_key_does_not_cache_a_verification_verdict() {
        crate::economic_fixtures::use_test_storage_dir();
        reset_database_for_tests();
        init_database().expect("init db");

        let device_id = [0x6Bu8; 32];
        seed_contact_for_chain_tip_tests(device_id, [0x6Cu8; 32], "BleCapable");

        {
            let binding = get_connection().expect("conn");
            let conn = binding.lock().expect("lock");
            let read_verified = |conn: &rusqlite::Connection| -> i32 {
                conn.query_row(
                    "SELECT verified FROM contacts WHERE device_id = ?1",
                    rusqlite::params![device_id.to_vec()],
                    |r| r.get(0),
                )
                .expect("read verified")
            };

            // Compare BEFORE and AFTER rather than against a literal: the
            // fixture already sets `verified`, so asserting a fixed value would
            // measure the fixture instead of the behaviour.
            let before = read_verified(&conn);
            conn.execute(
                "UPDATE contacts SET kyber_public_key = ?1 WHERE device_id = ?2",
                rusqlite::params![vec![0x6Du8; 1184], device_id.to_vec()],
            )
            .expect("store kyber pk");
            let after = read_verified(&conn);

            assert_eq!(
                before, after,
                "storing a Kyber public key changed contacts.verified — that \
                 column would then be a cached binding verdict and the B4 cut \
                 must invalidate it"
            );

            // And the key really did land, so the comparison above is not
            // vacuous over a no-op UPDATE.
            let stored: Vec<u8> = conn
                .query_row(
                    "SELECT kyber_public_key FROM contacts WHERE device_id = ?1",
                    rusqlite::params![device_id.to_vec()],
                    |r| r.get(0),
                )
                .expect("read kyber pk");
            assert_eq!(stored.len(), 1184, "the Kyber public key was not stored");
        }
    }

    #[test]
    #[serial]
    fn the_cut_preflight_is_clear_on_a_quiesced_database() {
        crate::economic_fixtures::use_test_storage_dir();
        reset_database_for_tests();
        init_database().expect("init db");

        assert_eq!(
            crate::storage::client_db::cert_resync::tagged_hash_cut_preflight()
                .expect("preflight must not error"),
            crate::storage::client_db::cert_resync::CutPreflight::Clear
        );
    }

    /// Only an absent or provably-deleted gate admits. Every ambiguous answer refuses.
    #[test]
    fn only_a_cleared_or_absent_gate_admits_an_offline_transfer() {
        assert!(StaleGateOutcome::NoGate.admits_offline());
        assert!(StaleGateOutcome::Cleared.admits_offline());
        assert!(
            !StaleGateOutcome::StillPending.admits_offline(),
            "a live online gate must not admit an offline transfer"
        );
        assert!(
            !StaleGateOutcome::Raced.admits_offline(),
            "a gate that changed under the clear must refuse — this is the answer the \
             old code discarded"
        );
    }

    /// Finality-barrier staleness: the ONLY thing that keeps a gate alive is an
    /// unsettled or checkpoint-pending online send behind it. Seeds a
    /// `sender_outbox` row for the local↔`cp` relationship in `status`.
    fn seed_outbox_row_for(
        local: [u8; 32],
        cp: [u8; 32],
        projection: ([u8; 32], [u8; 32]),
        status: &str,
        tag: u8,
    ) {
        let rel = dsm::core::bilateral_transaction_manager::compute_smt_key(&local, &cp);
        let binding = get_connection().expect("conn");
        let conn = binding.lock().expect("lock");
        conn.execute(
            "INSERT INTO sender_outbox (relationship_key, canonical_parent, canonical_child, \
             commitment, projection_parent, projection_target, routing_address, submission_id, \
             envelope_bytes, proposal_nonce, local_expected_prev, is_first_ek_step, status, \
             message_ids) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'R', ?7, X'00', ?8, NULL, 1, \
             ?9, NULL)",
            rusqlite::params![
                rel.as_slice(),
                vec![tag; 32],
                vec![tag ^ 1; 32],
                vec![tag ^ 2; 32],
                projection.0.as_slice(),
                projection.1.as_slice(),
                format!("SID{tag}"),
                vec![tag ^ 5; 32],
                status,
            ],
        )
        .expect("seed outbox row");
    }

    /// The gate is read and deleted in ONE transaction: a gate replaced by a
    /// concurrent online send (still unsettled) refuses and survives — the
    /// decision is made against the row actually in the table.
    #[test]
    #[serial]
    fn a_gate_replaced_by_a_concurrent_online_send_still_refuses() {
        crate::economic_fixtures::use_test_storage_dir();
        reset_database_for_tests();
        init_database().expect("init db");
        let local = [0xE0u8; 32];

        let device_id = [0xE8u8; 32];
        let old_parent = [0x20u8; 32];
        let old_next = [0x21u8; 32];
        let new_parent = [0x22u8; 32];
        let new_next = [0x23u8; 32];

        seed_contact_for_chain_tip_tests(device_id, new_parent, "BleCapable");
        store_pending_online_outbox(&device_id, "old_msg", &old_parent, &old_next)
            .expect("insert gate A");
        clear_pending_online_outbox(&device_id).expect("clear A");
        store_pending_online_outbox(&device_id, "new_msg", &new_parent, &new_next)
            .expect("insert gate B");
        seed_outbox_row_for(local, device_id, (new_parent, new_next), "submitted", 0x11);

        let outcome = clear_stale_pending_online_gate(&device_id).expect("decision must not error");
        assert_eq!(outcome, StaleGateOutcome::StillPending);
        assert!(!outcome.admits_offline());
        let gate = get_pending_online_outbox(&device_id)
            .expect("load")
            .expect("gate B must survive");
        assert_eq!(gate.message_id, "new_msg");
    }

    /// ANTI-VACUITY. A gate with NO unsettled or checkpoint-pending online send
    /// behind it is an orphan: cleared and admits. Without this, a decision that
    /// returned `StillPending` unconditionally would satisfy every refusal test.
    #[test]
    #[serial]
    fn a_genuinely_stale_gate_is_cleared_and_admits() {
        crate::economic_fixtures::use_test_storage_dir();
        reset_database_for_tests();
        init_database().expect("init db");
        let local = [0xE0u8; 32];

        let device_id = [0xE9u8; 32];
        let parent = [0x30u8; 32];
        let next = [0x31u8; 32];

        seed_contact_for_chain_tip_tests(device_id, [0x32u8; 32], "BleCapable");
        store_pending_online_outbox(&device_id, "settled_msg", &parent, &next)
            .expect("insert gate");
        // A fully released send (gc_pending) does not hold the gate.
        seed_outbox_row_for(local, device_id, (parent, next), "gc_pending", 0x12);

        let outcome = clear_stale_pending_online_gate(&device_id).expect("decision must not error");
        assert_eq!(outcome, StaleGateOutcome::Cleared);
        assert!(outcome.admits_offline());
        assert!(
            get_pending_online_outbox(&device_id)
                .expect("load")
                .is_none(),
            "a cleared gate must actually be deleted, and the delete must be committed"
        );
    }

    /// A gate whose send is unsettled — OR locally finalized but not yet at
    /// its checkpoint quorum — refuses and survives. The former "chain tip
    /// moved off the gate's parent" rule is gone: after finalization the tip
    /// HAS moved (it sits at the target) while the send is not yet final for
    /// the peer, and that must not admit an offline transfer.
    #[test]
    #[serial]
    fn a_live_gate_refuses_and_survives_including_checkpoint_pending() {
        crate::economic_fixtures::use_test_storage_dir();
        reset_database_for_tests();
        init_database().expect("init db");
        let local = [0xE0u8; 32];

        let device_id = [0xEAu8; 32];
        let parent = [0x40u8; 32];
        let next = [0x41u8; 32];

        // Tip already at the gate's TARGET (post-finalization shape).
        seed_contact_for_chain_tip_tests(device_id, next, "BleCapable");
        store_pending_online_outbox(&device_id, "live_msg", &parent, &next).expect("insert gate");
        seed_outbox_row_for(
            local,
            device_id,
            (parent, next),
            "finalization_checkpoint_pending",
            0x13,
        );

        let outcome = clear_stale_pending_online_gate(&device_id).expect("decision must not error");
        assert_eq!(outcome, StaleGateOutcome::StillPending);
        assert!(!outcome.admits_offline());
        assert!(
            get_pending_online_outbox(&device_id)
                .expect("load")
                .is_some(),
            "a live gate must not be deleted"
        );
    }

    #[test]
    #[serial]
    fn no_gate_admits() {
        crate::economic_fixtures::use_test_storage_dir();
        reset_database_for_tests();
        init_database().expect("init db");

        let device_id = [0xEBu8; 32];
        seed_contact_for_chain_tip_tests(device_id, [0x50u8; 32], "BleCapable");

        let outcome = clear_stale_pending_online_gate(&device_id).expect("decision must not error");
        assert_eq!(outcome, StaleGateOutcome::NoGate);
        assert!(outcome.admits_offline());
    }

    /// A malformed persisted tip is an ERROR, which the handler turns into a
    /// refusal. It used to become `[0u8; 32]` via `unwrap_or`, which guaranteed a
    /// DELETE that matched nothing — leaving the gate row in SQLite while the
    /// caller cleared the in-memory lock and admitted the transfer.
    #[test]
    #[serial]
    fn a_malformed_persisted_tip_is_an_error_not_a_zero_filled_default() {
        crate::economic_fixtures::use_test_storage_dir();
        reset_database_for_tests();
        init_database().expect("init db");

        let device_id = [0xECu8; 32];
        seed_contact_for_chain_tip_tests(device_id, [0x60u8; 32], "BleCapable");

        // Written by raw SQL: every public writer validates length 32, so this is
        // only reachable through external corruption — which is exactly when a
        // silent zero-fill is most dangerous.
        {
            let binding = get_connection().expect("conn");
            let conn = binding.lock().expect("lock");
            conn.execute(
                "INSERT INTO pending_online_outbox
                   (counterparty_device_id, message_id, parent_tip, next_tip)
                 VALUES (?1, ?2, ?3, ?4)",
                rusqlite::params![
                    device_id.to_vec(),
                    "corrupt_msg",
                    vec![0x61u8; 8], // short parent_tip
                    vec![0x62u8; 32]
                ],
            )
            .expect("insert corrupt row");
        }

        let err = clear_stale_pending_online_gate(&device_id)
            .expect_err("a malformed persisted tip must be an error");
        assert!(
            err.to_string().contains("parent_tip"),
            "the error must name the malformed field, got: {err}"
        );
    }

    #[test]
    #[serial]
    fn test_success_invariant_chain_tip_equals_local_bilateral() {
        crate::economic_fixtures::use_test_storage_dir();
        reset_database_for_tests();
        init_database().expect("init db");

        let device_id = [0xE8u8; 32];
        let genesis = [0xF8u8; 32];
        let tip_a = [0x20u8; 32];
        let tip_b = [0x21u8; 32];
        let tip_c = [0x22u8; 32];

        seed_contact_for_chain_tip_tests(device_id, genesis, "BleCapable");
        restore_finalized_bilateral_chain_tip(&device_id, &tip_a).expect("seed");

        // Advance A→B
        let req1 = bilateral_tip_sync::TipSyncRequest {
            counterparty_device_id: device_id,
            expected_parent_tip: tip_a,
            target_tip: tip_b,
        };
        bilateral_tip_sync::sync_bilateral_tips_atomically(&req1).expect("advance A→B");
        assert_eq!(get_contact_chain_tip_raw(&device_id), Some(tip_b));
        assert_eq!(get_local_bilateral_chain_tip(&device_id), Some(tip_b));

        // Advance B→C
        let req2 = bilateral_tip_sync::TipSyncRequest {
            counterparty_device_id: device_id,
            expected_parent_tip: tip_b,
            target_tip: tip_c,
        };
        bilateral_tip_sync::sync_bilateral_tips_atomically(&req2).expect("advance B→C");
        assert_eq!(get_contact_chain_tip_raw(&device_id), Some(tip_c));
        assert_eq!(get_local_bilateral_chain_tip(&device_id), Some(tip_c));

        // Invariant: both columns equal at every step
    }

    /// Receiver-admit fold: the database gets the FusedAnchorPin-shaped `anchor_enrollments`
    /// (`pk_chip`, no counter-era columns, no `anchor_frontiers` table).
    #[test]
    #[serial]
    fn anchor_enrollments_schema_is_fused_shape() {
        crate::economic_fixtures::use_test_storage_dir();
        reset_database_for_tests();
        init_database().expect("init db");

        let binding = get_connection().expect("db connection");
        let conn = binding.lock().expect("db lock");

        let columns = |conn: &Connection| -> Vec<String> {
            let mut stmt = conn
                .prepare("PRAGMA table_info(anchor_enrollments)")
                .expect("table_info");
            let cols = stmt
                .query_map([], |row| row.get::<_, String>(1))
                .expect("query");
            cols.map(|c| c.expect("col")).collect()
        };

        // Fresh DB: v2 shape, no v1 counter-era or legacy columns, no anchor_frontiers table.
        let cols = columns(&conn);
        for want in [
            "device_id",
            "policy_hash",
            "bundle",
            "anchor_id",
            "enrolled_counter",
            "partition_pk",
            "pk_chip",
            "uncompromised",
        ] {
            assert!(cols.iter().any(|c| c == want), "missing column {want}");
        }
        for gone in [
            "id_anchor",
            "commitment_c",
            "leaf_spki",
            "frontier_root",
            "verifier_slot",
            "chip_static_pubkey",
        ] {
            assert!(
                !cols.iter().any(|c| c == gone),
                "legacy column {gone} present"
            );
        }
        let frontier_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='anchor_frontiers'",
                [],
                |r| r.get(0),
            )
            .expect("sqlite_master");
        assert_eq!(frontier_count, 0, "anchor_frontiers table present");
    }

    /// Beta has NO migrations: a database from an older schema generation must
    /// fail with an explicit "SCHEMA RESET REQUIRED" condition, never stumble
    /// into an opaque missing-column error deep in an unrelated query.
    #[test]
    fn stale_schema_version_fails_closed_with_reset_required() {
        let conn = Connection::open_in_memory().expect("in-memory db");
        // A populated database stamped with an older generation.
        conn.execute_batch("CREATE TABLE marker(x INTEGER); PRAGMA user_version = 1;")
            .expect("seed stale db");

        let err = enforce_schema_version(&conn).expect_err("stale schema must fail closed");
        let msg = err.to_string();
        assert!(msg.contains("SCHEMA RESET REQUIRED"), "unexpected: {msg}");
        assert!(msg.contains("does not migrate"), "unexpected: {msg}");
    }

    /// A populated but UNVERSIONED database predates versioning and is equally
    /// incompatible — it must not be silently adopted by stamping it.
    #[test]
    fn unversioned_populated_schema_fails_closed() {
        let conn = Connection::open_in_memory().expect("in-memory db");
        conn.execute_batch("CREATE TABLE marker(x INTEGER);")
            .expect("seed unversioned db");
        let err = enforce_schema_version(&conn).expect_err("unversioned db must fail closed");
        assert!(err.to_string().contains("SCHEMA RESET REQUIRED"));
    }

    /// A brand-new (empty) database is stamped with the current generation and
    /// accepted — this is the fresh-install path.
    #[test]
    fn fresh_database_is_stamped_and_accepted() {
        let conn = Connection::open_in_memory().expect("in-memory db");
        enforce_schema_version(&conn).expect("fresh db must be accepted");
        let v: i64 = conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .expect("user_version");
        assert_eq!(v, CLIENT_DB_SCHEMA_VERSION);
        // Idempotent on re-open.
        enforce_schema_version(&conn).expect("second open must pass");
    }
}
