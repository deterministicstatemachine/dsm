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

mod auth_tokens;
mod bcr;
mod bilateral_sessions;
mod bitcoin_accounts;
mod ble_chunk_buffer;
mod contacts;
mod dlv_receipts;
mod export;
mod genesis;
mod manifold_seeds;
mod nonces;
mod online_outbox;
mod pending_transactions;
pub mod recovery;
mod stitched_receipts;
mod system_peers;
mod tokens;
mod transactions;
pub mod types;
mod vault_records;
mod vaults;
mod wallet_init;
mod wallet_state;
mod withdrawals;

// --- Wildcard re-exports (preserves all existing import paths) ---

pub use types::*;
pub use auth_tokens::*;
pub use bcr::*;
pub use bilateral_sessions::*;
pub use bitcoin_accounts::*;
pub use ble_chunk_buffer::*;
pub use contacts::*;
pub use dlv_receipts::*;
pub use export::*;
pub use genesis::*;
pub use manifold_seeds::*;
pub use nonces::*;
pub use online_outbox::*;
pub use pending_transactions::*;
pub use stitched_receipts::*;
pub use vault_records::*;
pub use system_peers::*;
pub use tokens::*;
pub use transactions::*;
pub use withdrawals::*;
pub use vaults::*;
pub use wallet_init::*;
pub use wallet_state::*;

// =========================== DB plumbing ===========================

static DB_CONNECTION: RwLock<Option<Arc<Mutex<Connection>>>> = RwLock::new(None);
const DB_FILE_NAME: &str = "dsm_client.db";

/// Per-reset generation counter (test builds only). Incremented by
/// `reset_database_for_tests()` so every reset+reinit cycle opens a
/// brand-new named in-memory SQLite database, preventing
/// SQLITE_LOCKED_SHAREDCACHE races caused by concurrent or lingering
/// test connections that still hold the previous shared-cache handle.
#[cfg(test)]
static TEST_DB_GENERATION: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

pub fn init_database() -> Result<()> {
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

    let conn = {
        let db_str = db_path.to_string_lossy();
        if db_str.starts_with("file:") {
            // Required for SQLite URI filenames, e.g. file:...mode=memory&cache=shared
            Connection::open_with_flags(
                db_str.as_ref(),
                rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE
                    | rusqlite::OpenFlags::SQLITE_OPEN_CREATE
                    | rusqlite::OpenFlags::SQLITE_OPEN_URI,
            )?
        } else {
            Connection::open(&db_path)?
        }
    };
    info!("[DSM_SDK] Database connection opened successfully");
    conn.execute("PRAGMA foreign_keys = ON;", [])?;
    create_schema(&conn)?;
    replace_incompatible_transactions_schema(&conn)?;
    ensure_vault_records_lineage_columns(&conn)?;
    ensure_bitcoin_accounts_active_receive_index(&conn)?;
    ensure_contacts_device_tree_root(&conn)?;
    ensure_stitched_receipts_sig_b_nullable(&conn)?;
    migrate_legacy_withdrawal_states(&conn)?;

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

    // Recovery capsule + prefs tables (NFC ring backup)
    if let Err(e) = recovery::ensure_recovery_tables() {
        warn!("Recovery table creation failed (non-fatal): {e:?}");
    }

    if let Err(e) = recover_pending_transactions() {
        warn!("Pending-tx recovery failed: {e:?}");
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

/// Reset the database connection singleton for testing.
///
/// Acquires a write lock, drops the current connection, then bumps
/// `TEST_DB_GENERATION` so the next `init_database()` call opens a
/// completely fresh named in-memory SQLite database. This prevents
/// SQLITE_LOCKED_SHAREDCACHE errors that occur when a concurrent test
/// still holds an Arc clone to the previous shared-cache connection.
pub fn reset_database_for_tests() {
    if let Ok(mut guard) = DB_CONNECTION.write() {
        *guard = None;
    }
    #[cfg(test)]
    {
        TEST_DB_GENERATION.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
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

fn get_database_path() -> Result<PathBuf> {
    if std::env::var("DSM_SDK_TEST_MODE").is_ok() {
        let pid = std::process::id();
        #[cfg(test)]
        let uri = {
            let gen = TEST_DB_GENERATION.load(std::sync::atomic::Ordering::Relaxed);
            format!("file:dsm_sdk_test_{pid}_{gen}?mode=memory&cache=shared")
        };
        #[cfg(not(test))]
        let uri = format!("file:dsm_sdk_test_{pid}?mode=memory&cache=shared");
        return Ok(PathBuf::from(uri));
    }

    #[cfg(all(target_os = "android", not(test)))]
    {
        let base = crate::storage_utils::get_storage_base_dir().ok_or_else(|| {
            anyhow!("Storage base directory not set. Call initStorageBaseDir() at startup.")
        })?;
        Ok(base.join(DB_FILE_NAME))
    }

    #[cfg(all(not(target_os = "android"), not(test)))]
    {
        let data_dir = dirs::data_dir()
            .ok_or_else(|| anyhow!("No user data dir"))?
            .join("dsm_wallet");
        Ok(data_dir.join(DB_FILE_NAME))
    }

    #[cfg(test)]
    {
        // Each reset_database_for_tests() increments TEST_DB_GENERATION so
        // every reset+reinit cycle uses a fresh named in-memory SQLite URI,
        // preventing SQLITE_LOCKED_SHAREDCACHE races with other test connections.
        let pid = std::process::id();
        let gen = TEST_DB_GENERATION.load(std::sync::atomic::Ordering::Relaxed);
        Ok(PathBuf::from(format!(
            "file:dsm_sdk_test_{pid}_{gen}?mode=memory&cache=shared"
        )))
    }
}

fn create_schema(conn: &Connection) -> Result<()> {
    // Creating schema can race when multiple test tasks initialize the DB
    // concurrently (shared in-memory SQLite URI). Retry on busy/locking
    // errors to avoid transient test failures.
    let mut attempts = 0u32;
    loop {
        let res = conn.execute_batch(
            r#"
        CREATE TABLE IF NOT EXISTS genesis_records(
            genesis_id        TEXT PRIMARY KEY,
            device_id         TEXT NOT NULL,
            mpc_proof         TEXT NOT NULL,
            dbrw_binding      TEXT NOT NULL,
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
            created_at        INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS contacts(
            contact_id                  TEXT PRIMARY KEY,
            device_id                   BLOB NOT NULL,
            alias                       TEXT NOT NULL,
            genesis_hash                BLOB NOT NULL,
            public_key                  BLOB,
            chain_tip                   BLOB,
            added_at                    INTEGER NOT NULL,
            verified                    INTEGER NOT NULL,
            verification_proof          BLOB,
            metadata                    BLOB,
            ble_address                 TEXT,
            status                      TEXT NOT NULL,
            needs_online_reconcile      INTEGER NOT NULL,
            last_seen_online_counter    INTEGER NOT NULL,
            last_seen_ble_counter       INTEGER NOT NULL,
            local_bilateral_chain_tip   BLOB,
            previous_chain_tip          BLOB
        );

        CREATE TABLE IF NOT EXISTS auth_tokens(
            endpoint    TEXT NOT NULL,
            device_id   TEXT NOT NULL,
            genesis     TEXT NOT NULL,
            token       TEXT NOT NULL,
            created_at  INTEGER NOT NULL,
            PRIMARY KEY (endpoint, device_id, genesis)
        );

        CREATE TABLE IF NOT EXISTS pending_transactions(
            tx_id       TEXT PRIMARY KEY,
            payload     BLOB NOT NULL,
            state       TEXT NOT NULL,
            retry_count INTEGER NOT NULL DEFAULT 0,
            created_at  INTEGER NOT NULL,
            updated_at  INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS pending_online_outbox(
            counterparty_device_id BLOB PRIMARY KEY,
            message_id             TEXT NOT NULL,
            parent_tip             BLOB NOT NULL,
            next_tip               BLOB NOT NULL,
            created_at             INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS wallet_state(
            wallet_id       TEXT PRIMARY KEY,
            device_id       TEXT NOT NULL,
            genesis_id      TEXT NOT NULL,
            chain_tip       BLOB,
            chain_height    INTEGER NOT NULL,
            merkle_root     BLOB,
            balance         INTEGER NOT NULL,
            created_at      INTEGER NOT NULL,
            updated_at      INTEGER NOT NULL,
            status          TEXT NOT NULL,
            metadata        BLOB
        );

        CREATE TABLE IF NOT EXISTS token_balances(
            device_id   TEXT NOT NULL,
            token_id    TEXT NOT NULL,
            available   INTEGER NOT NULL DEFAULT 0 CHECK(available >= 0),
            locked      INTEGER NOT NULL DEFAULT 0 CHECK(locked >= 0),
            updated_at  INTEGER NOT NULL,
            PRIMARY KEY (device_id, token_id)
        );

        CREATE TABLE IF NOT EXISTS spent_nonces(
            nonce_hash  BLOB PRIMARY KEY,
            tx_id       TEXT NOT NULL,
            sender_id   TEXT NOT NULL,
            amount      INTEGER NOT NULL,
            spent_at    INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS settings(
            key         TEXT PRIMARY KEY,
            value       TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS bcr_reports(
            report_id   INTEGER PRIMARY KEY AUTOINCREMENT,
            report      BLOB NOT NULL,
            created_at  INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS bcr_states(
            device_id       BLOB NOT NULL,
            state_number    INTEGER NOT NULL,
            state_hash      BLOB NOT NULL,
            prev_state_hash BLOB NOT NULL,
            state_bytes     BLOB NOT NULL,
            published       INTEGER NOT NULL,
            created_at      INTEGER NOT NULL,
            PRIMARY KEY (device_id, state_hash)
        );

        CREATE INDEX IF NOT EXISTS idx_bcr_states_device_number
            ON bcr_states(device_id, state_number);

        CREATE INDEX IF NOT EXISTS idx_bcr_states_device_published
            ON bcr_states(device_id, published);

        CREATE TABLE IF NOT EXISTS bilateral_sessions(
            commitment_hash           BLOB PRIMARY KEY,
            counterparty_device_id    BLOB NOT NULL,
            counterparty_genesis_hash BLOB,
            operation_bytes           BLOB NOT NULL,
            phase                     TEXT NOT NULL,
            local_signature           BLOB,
            counterparty_signature    BLOB,
            created_at_step           INTEGER NOT NULL,
            sender_ble_address        TEXT,
            updated_at                INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS transactions(
            tx_id              TEXT PRIMARY KEY,
            tx_hash            TEXT NOT NULL,
            from_device        TEXT NOT NULL,
            to_device          TEXT NOT NULL,
            amount             INTEGER NOT NULL,
            tx_type            TEXT NOT NULL,
            status             TEXT NOT NULL,
            chain_height       INTEGER NOT NULL,
            step_index         INTEGER NOT NULL,
            commitment_hash    TEXT,
            proof_data         BLOB,
            metadata           BLOB,
            created_at         INTEGER NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_transactions_from_device
            ON transactions(from_device);

        CREATE INDEX IF NOT EXISTS idx_transactions_to_device
            ON transactions(to_device);

        CREATE INDEX IF NOT EXISTS idx_transactions_created
            ON transactions(created_at DESC);

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
            btc_amount_sats  INTEGER NOT NULL,
            created_at       INTEGER NOT NULL
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
            active_receive_index  INTEGER NOT NULL DEFAULT 0,
            created_at            INTEGER NOT NULL,
            updated_at            INTEGER NOT NULL
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
            created_at_tick   INTEGER NOT NULL,
            PRIMARY KEY (frame_commitment, chunk_index)
        );
        CREATE INDEX IF NOT EXISTS idx_ble_reassembly_frame
            ON ble_reassembly_state(frame_commitment);
        CREATE INDEX IF NOT EXISTS idx_ble_reassembly_counterparty
            ON ble_reassembly_state(counterparty_id) WHERE counterparty_id IS NOT NULL;

        CREATE TABLE IF NOT EXISTS dlv_receipts(
            sigma           BLOB PRIMARY KEY,
            vault_id        TEXT NOT NULL,
            genesis         BLOB NOT NULL,
            devid_a         BLOB NOT NULL,
            devid_b         BLOB NOT NULL,
            receipt_cbor    BLOB NOT NULL,
            sig_a           BLOB NOT NULL,
            sig_b           BLOB,
            created_at      INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_dlv_receipts_vault ON dlv_receipts(vault_id);
        CREATE INDEX IF NOT EXISTS idx_dlv_receipts_genesis ON dlv_receipts(genesis);

        CREATE TABLE IF NOT EXISTS stitched_receipts (
            tx_hash       BLOB NOT NULL PRIMARY KEY,
            h_n           BLOB NOT NULL,
            h_n1          BLOB NOT NULL,
            device_id_a   BLOB NOT NULL,
            device_id_b   BLOB NOT NULL,
            sig_a         BLOB NOT NULL,
            sig_b         BLOB,
            receipt_commit BLOB NOT NULL,
            smt_root_pre  BLOB,
            smt_root_post BLOB
        );
        CREATE INDEX IF NOT EXISTS idx_stitched_receipts_devid_a ON stitched_receipts(device_id_a);
        CREATE INDEX IF NOT EXISTS idx_stitched_receipts_devid_b ON stitched_receipts(device_id_b);

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
            settlement_poll_count INTEGER NOT NULL DEFAULT 0,
            created_at       INTEGER NOT NULL,
            updated_at       INTEGER NOT NULL
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
            created_at            INTEGER NOT NULL,
            updated_at            INTEGER NOT NULL,
            PRIMARY KEY (withdrawal_id, leg_index),
            FOREIGN KEY (withdrawal_id) REFERENCES in_flight_withdrawals(withdrawal_id)
        );
        CREATE INDEX IF NOT EXISTS idx_in_flight_withdrawal_legs_withdrawal
            ON in_flight_withdrawal_legs(withdrawal_id, state);
        "#,
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
        "CREATE INDEX IF NOT EXISTS idx_bilateral_sessions_created ON bilateral_sessions(created_at_step DESC);",
        [],
    )?;
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_bilateral_sessions_counterparty ON bilateral_sessions(counterparty_device_id);",
        [],
    )?;
    info!("Schema OK (clockless, binary-first)");
    Ok(())
}

fn ensure_bilateral_sessions_created_at_step(conn: &Connection) -> Result<()> {
    let mut stmt = conn.prepare("PRAGMA table_info(bilateral_sessions)")?;
    let cols = stmt.query_map([], |row| row.get::<_, String>(1))?;
    for col in cols {
        if col? == "created_at_step" {
            return Ok(());
        }
    }

    conn.execute(
        "ALTER TABLE bilateral_sessions ADD COLUMN created_at_step INTEGER NOT NULL DEFAULT 0;",
        [],
    )?;
    Ok(())
}

fn replace_incompatible_transactions_schema(conn: &Connection) -> Result<()> {
    let mut has_created_at = false;
    let mut has_unix_ts = false;

    let mut stmt = conn.prepare("PRAGMA table_info(transactions)")?;
    let cols = stmt.query_map([], |row| row.get::<_, String>(1))?;
    for col in cols {
        match col?.as_str() {
            "created_at" => has_created_at = true,
            "unix_ts" => has_unix_ts = true,
            _ => {}
        }
    }

    if has_created_at && !has_unix_ts {
        return Ok(());
    }

    warn!(
        "Replacing incompatible transactions schema (created_at={}, unix_ts={})",
        has_created_at, has_unix_ts
    );
    conn.execute_batch(
        r#"
        DROP INDEX IF EXISTS idx_transactions_from_device;
        DROP INDEX IF EXISTS idx_transactions_to_device;
        DROP INDEX IF EXISTS idx_transactions_created;
        DROP TABLE IF EXISTS transactions;

        CREATE TABLE transactions(
            tx_id              TEXT PRIMARY KEY,
            tx_hash            TEXT NOT NULL,
            from_device        TEXT NOT NULL,
            to_device          TEXT NOT NULL,
            amount             INTEGER NOT NULL,
            tx_type            TEXT NOT NULL,
            status             TEXT NOT NULL,
            chain_height       INTEGER NOT NULL,
            step_index         INTEGER NOT NULL,
            commitment_hash    TEXT,
            proof_data         BLOB,
            metadata           BLOB,
            created_at         INTEGER NOT NULL
        );

        CREATE INDEX idx_transactions_from_device
            ON transactions(from_device);
        CREATE INDEX idx_transactions_to_device
            ON transactions(to_device);
        CREATE INDEX idx_transactions_created
            ON transactions(created_at DESC);
        "#,
    )?;

    Ok(())
}

fn ensure_vault_records_lineage_columns(conn: &Connection) -> Result<()> {
    let mut has_parent_vault_id = false;
    let mut has_successor_depth = false;
    let mut has_is_fractional_successor = false;
    let mut has_destination_address = false;
    let mut has_funding_txid = false;
    let mut has_refund_hash_lock = false;
    let mut has_exit_amount_sats = false;
    let mut has_exit_header = false;
    let mut has_exit_confirm_depth = false;
    let mut has_entry_txid = false;
    let mut has_deposit_nonce = false;

    let mut stmt = conn.prepare("PRAGMA table_info(vault_records)")?;
    let cols = stmt.query_map([], |row| row.get::<_, String>(1))?;
    for col in cols {
        match col?.as_str() {
            "parent_vault_id" => has_parent_vault_id = true,
            "successor_depth" => has_successor_depth = true,
            "is_fractional_successor" => has_is_fractional_successor = true,
            "destination_address" => has_destination_address = true,
            "funding_txid" => has_funding_txid = true,
            "refund_hash_lock" => has_refund_hash_lock = true,
            "exit_amount_sats" => has_exit_amount_sats = true,
            "exit_header" => has_exit_header = true,
            "exit_confirm_depth" => has_exit_confirm_depth = true,
            "entry_txid" => has_entry_txid = true,
            "deposit_nonce" => has_deposit_nonce = true,
            _ => {}
        }
    }

    if !has_parent_vault_id {
        conn.execute(
            "ALTER TABLE vault_records ADD COLUMN parent_vault_id TEXT",
            [],
        )?;
    }
    if !has_successor_depth {
        conn.execute(
            "ALTER TABLE vault_records ADD COLUMN successor_depth INTEGER NOT NULL DEFAULT 0",
            [],
        )?;
    }
    if !has_is_fractional_successor {
        conn.execute(
            "ALTER TABLE vault_records ADD COLUMN is_fractional_successor INTEGER NOT NULL DEFAULT 0",
            [],
        )?;
    }
    if !has_destination_address {
        conn.execute(
            "ALTER TABLE vault_records ADD COLUMN destination_address TEXT",
            [],
        )?;
    }
    if !has_funding_txid {
        conn.execute("ALTER TABLE vault_records ADD COLUMN funding_txid TEXT", [])?;
    }
    if !has_refund_hash_lock {
        conn.execute(
            "ALTER TABLE vault_records ADD COLUMN refund_hash_lock BLOB",
            [],
        )?;
    }
    if !has_exit_amount_sats {
        conn.execute(
            "ALTER TABLE vault_records ADD COLUMN exit_amount_sats INTEGER NOT NULL DEFAULT 0",
            [],
        )?;
    }
    if !has_exit_header {
        conn.execute("ALTER TABLE vault_records ADD COLUMN exit_header BLOB", [])?;
    }
    if !has_exit_confirm_depth {
        conn.execute(
            "ALTER TABLE vault_records ADD COLUMN exit_confirm_depth INTEGER NOT NULL DEFAULT 0",
            [],
        )?;
    }
    if !has_entry_txid {
        conn.execute("ALTER TABLE vault_records ADD COLUMN entry_txid BLOB", [])?;
    }
    if !has_deposit_nonce {
        conn.execute(
            "ALTER TABLE vault_records ADD COLUMN deposit_nonce BLOB",
            [],
        )?;
    }

    Ok(())
}

fn ensure_bitcoin_accounts_active_receive_index(conn: &Connection) -> Result<()> {
    let mut stmt = conn.prepare("PRAGMA table_info(bitcoin_accounts)")?;
    let cols = stmt.query_map([], |row| row.get::<_, String>(1))?;
    for col in cols {
        if col? == "active_receive_index" {
            return Ok(());
        }
    }
    conn.execute(
        "ALTER TABLE bitcoin_accounts ADD COLUMN active_receive_index INTEGER NOT NULL DEFAULT 0",
        [],
    )?;
    Ok(())
}

fn ensure_contacts_device_tree_root(conn: &Connection) -> Result<()> {
    let mut stmt = conn.prepare("PRAGMA table_info(contacts)")?;
    let cols = stmt.query_map([], |row| row.get::<_, String>(1))?;
    for col in cols {
        if col? == "device_tree_root" {
            return Ok(());
        }
    }
    match conn.execute("ALTER TABLE contacts ADD COLUMN device_tree_root BLOB", []) {
        Ok(_) => Ok(()),
        Err(e) if e.to_string().contains("duplicate column name") => Ok(()),
        Err(e) => Err(e.into()),
    }
}

fn migrate_legacy_withdrawal_states(conn: &Connection) -> Result<()> {
    conn.execute(
        "UPDATE in_flight_withdrawals
         SET state = 'finalized'
         WHERE state = 'settled'",
        [],
    )?;
    conn.execute(
        "UPDATE in_flight_withdrawals
         SET state = 'committed'
         WHERE state = 'partial_failure'",
        [],
    )?;
    Ok(())
}

/// Migrate existing `stitched_receipts` tables where `sig_b` was created as `NOT NULL`.
/// Fresh schemas (post-solo-signature) define `sig_b BLOB` (nullable), but
/// `CREATE TABLE IF NOT EXISTS` is a no-op on existing databases. SQLite does not
/// support `ALTER COLUMN`, so we recreate the table if `sig_b` is still NOT NULL.
fn ensure_stitched_receipts_sig_b_nullable(conn: &Connection) -> Result<()> {
    // PRAGMA table_info returns: cid, name, type, notnull, dflt_value, pk
    let mut stmt = conn.prepare("PRAGMA table_info(stitched_receipts)")?;
    let mut sig_b_notnull = false;
    let rows = stmt.query_map([], |row| {
        Ok((row.get::<_, String>(1)?, row.get::<_, i32>(3)?))
    })?;
    for row in rows {
        let (name, notnull) = row?;
        if name == "sig_b" {
            sig_b_notnull = notnull != 0;
            break;
        }
    }
    if !sig_b_notnull {
        return Ok(()); // Already nullable or table doesn't exist yet
    }

    log::info!("[DSM_SDK] Migrating stitched_receipts: sig_b NOT NULL → nullable");
    conn.execute_batch(
        "BEGIN;
         ALTER TABLE stitched_receipts RENAME TO _stitched_receipts_old;
         CREATE TABLE stitched_receipts (
             tx_hash       BLOB NOT NULL PRIMARY KEY,
             h_n           BLOB NOT NULL,
             h_n1          BLOB NOT NULL,
             device_id_a   BLOB NOT NULL,
             device_id_b   BLOB NOT NULL,
             sig_a         BLOB NOT NULL,
             sig_b         BLOB,
             receipt_commit BLOB NOT NULL,
             smt_root_pre  BLOB,
             smt_root_post BLOB
         );
         INSERT INTO stitched_receipts
             SELECT tx_hash, h_n, h_n1, device_id_a, device_id_b,
                    sig_a, sig_b, receipt_commit, smt_root_pre, smt_root_post
             FROM _stitched_receipts_old;
         DROP TABLE _stitched_receipts_old;
         CREATE INDEX IF NOT EXISTS idx_stitched_receipts_devid_a ON stitched_receipts(device_id_a);
         CREATE INDEX IF NOT EXISTS idx_stitched_receipts_devid_b ON stitched_receipts(device_id_b);
         COMMIT;",
    )?;
    log::info!("[DSM_SDK] stitched_receipts sig_b migration complete");
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
                let _ = conn.execute("DELETE FROM wallet_state", []);
                let _ = conn.execute("DELETE FROM pending_transactions", []);
                // Force a checkpoint to ensure changes are written
                let _ = conn.execute("PRAGMA wal_checkpoint(TRUNCATE)", []);
            }
        }
    }

    #[test]
    #[serial]
    fn test_replace_incompatible_transactions_schema_removes_unix_ts_column() {
        unsafe {
            std::env::set_var("DSM_SDK_TEST_MODE", "1");
        }
        reset_database_for_tests();
        init_database().expect("init db");

        let binding = get_connection().expect("db connection");
        let conn = binding.lock().expect("db lock");
        conn.execute_batch(
            r#"
            DROP INDEX IF EXISTS idx_transactions_from_device;
            DROP INDEX IF EXISTS idx_transactions_to_device;
            DROP INDEX IF EXISTS idx_transactions_created;
            DROP TABLE IF EXISTS transactions;
            CREATE TABLE transactions(
                tx_id           TEXT PRIMARY KEY,
                tx_hash         TEXT NOT NULL,
                from_device     TEXT NOT NULL,
                to_device       TEXT NOT NULL,
                amount          INTEGER NOT NULL,
                tx_type         TEXT NOT NULL,
                status          TEXT NOT NULL,
                chain_height    INTEGER NOT NULL,
                step_index      INTEGER NOT NULL,
                commitment_hash TEXT,
                proof_data      BLOB,
                metadata        BLOB,
                unix_ts       INTEGER NOT NULL
            );
            INSERT INTO transactions(
                tx_id, tx_hash, from_device, to_device, amount, tx_type, status,
                chain_height, step_index, commitment_hash, proof_data, metadata, unix_ts
            ) VALUES (
                'legacy-tx', 'hash', 'from', 'to', 1, 'legacy', 'confirmed',
                1, 1, NULL, NULL, NULL, 123
            );
            "#,
        )
        .expect("seed legacy transactions table");

        replace_incompatible_transactions_schema(&conn).expect("replace transactions schema");

        let mut stmt = conn
            .prepare("PRAGMA table_info(transactions)")
            .expect("table info");
        let cols = stmt
            .query_map([], |row| row.get::<_, String>(1))
            .expect("query cols")
            .collect::<Result<Vec<_>, _>>()
            .expect("collect cols");
        assert!(cols.iter().any(|col| col == "created_at"));
        assert!(!cols.iter().any(|col| col == "unix_ts"));

        let tx_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM transactions", [], |row| row.get(0))
            .expect("count transactions");
        assert_eq!(tx_count, 0, "legacy transactions should be dropped");

        drop(stmt);
        drop(conn);

        store_transaction(&TransactionRecord {
            tx_id: "tx-new".to_string(),
            tx_hash: "hash-new".to_string(),
            from_device: "from".to_string(),
            to_device: "to".to_string(),
            amount: 7,
            tx_type: "send".to_string(),
            status: "confirmed".to_string(),
            chain_height: 1,
            step_index: 1,
            commitment_hash: None,
            proof_data: None,
            metadata: HashMap::new(),
            created_at: 0,
        })
        .expect("store transaction with replacement schema");
    }

    #[test]
    #[serial]
    fn test_migrate_legacy_withdrawal_states_rewrites_settled_and_partial_failure() {
        unsafe {
            std::env::set_var("DSM_SDK_TEST_MODE", "1");
        }
        reset_database_for_tests();
        init_database().expect("init db");

        let binding = get_connection().expect("db connection");
        let conn = binding.lock().expect("db lock");
        conn.execute(
            "INSERT INTO in_flight_withdrawals(
                withdrawal_id, device_id, amount_sats, dest_address, policy_commit,
                state, burn_token_id, burn_amount_sats, created_at, updated_at
            ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?9)",
            params![
                "legacy-settled",
                "device-a",
                1_000i64,
                "tb1qlegacy",
                crate::policy::builtins::DBTC_POLICY_COMMIT.as_slice(),
                "settled",
                "dBTC",
                1_000i64,
                1i64
            ],
        )
        .expect("insert settled row");
        conn.execute(
            "INSERT INTO in_flight_withdrawals(
                withdrawal_id, device_id, amount_sats, dest_address, policy_commit,
                state, burn_token_id, burn_amount_sats, created_at, updated_at
            ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?9)",
            params![
                "legacy-partial",
                "device-a",
                2_000i64,
                "tb1qlegacy",
                crate::policy::builtins::DBTC_POLICY_COMMIT.as_slice(),
                "partial_failure",
                "dBTC",
                2_000i64,
                2i64
            ],
        )
        .expect("insert partial_failure row");

        migrate_legacy_withdrawal_states(&conn).expect("migrate legacy withdrawal states");

        let settled_state: String = conn
            .query_row(
                "SELECT state FROM in_flight_withdrawals WHERE withdrawal_id = 'legacy-settled'",
                [],
                |row| row.get(0),
            )
            .expect("load settled row");
        let partial_state: String = conn
            .query_row(
                "SELECT state FROM in_flight_withdrawals WHERE withdrawal_id = 'legacy-partial'",
                [],
                |row| row.get(0),
            )
            .expect("load partial row");

        assert_eq!(settled_state, "finalized");
        assert_eq!(partial_state, "committed");
    }

    #[test]
    #[serial]
    fn test_auth_tokens_purged_on_identity_binding_change() {
        // Ensure DB initialized
        let binding = match get_connection() {
            Ok(b) => b,
            Err(e) => panic!("db connection failed: {:?}", e),
        };
        let conn = match binding.lock() {
            Ok(c) => c,
            Err(e) => panic!("db lock failed: {:?}", e),
        };

        // Start from a clean slate
        let _ = conn.execute("DELETE FROM auth_tokens", []);
        let _ = conn.execute("DELETE FROM settings WHERE key = \"auth_binding_v2\"", []);

        // Seed a token
        conn.execute(
            "INSERT OR REPLACE INTO auth_tokens(endpoint, device_id, genesis, token, created_at) VALUES (?1, ?2, ?3, ?4, ?5)",
            params!["http://node1", "DEV2", "GEN2", "TOK2", 1i64],
        )
        .unwrap();

        // Avoid holding the DB lock across ensure_auth_tokens_bound_to_identity(),
        // which also locks the global connection. Holding it here can deadlock.
        drop(conn);

        // First binding set should NOT purge
        ensure_auth_tokens_bound_to_identity("DEV2", "GEN2").unwrap();
        let conn = binding.lock().unwrap();
        let count1: i64 = conn
            .query_row("SELECT COUNT(*) FROM auth_tokens", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count1, 1);

        drop(conn);

        // Changing binding should purge
        ensure_auth_tokens_bound_to_identity("DEV3", "GEN3").unwrap();
        let conn = binding.lock().unwrap();
        let count2: i64 = conn
            .query_row("SELECT COUNT(*) FROM auth_tokens", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count2, 0);
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
    fn test_pending_tx_lifecycle() {
        let _ = init_database();
        // Use a unique tx_id to avoid race conditions with parallel tests
        let tx_id = format!(
            "test_pending_lc_{}",
            crate::util::deterministic_time::tick()
        );
        let payload = b"\x08\x96\x01";
        if let Err(e) = store_pending_transaction(&tx_id, payload) {
            panic!("store_pending_transaction failed: {e}");
        }
        let pendings = match get_pending_transactions(Some("CREATED")) {
            Ok(v) => v,
            Err(e) => panic!("get_pending_transactions failed: {e}"),
        };
        assert!(pendings.iter().any(|p| p.tx_id == tx_id));
        if let Err(e) = mark_pending_transaction_state(&tx_id, "COMMITTED") {
            panic!("mark_pending_transaction_state failed: {e}");
        }
        let committed = match get_pending_transactions(Some("COMMITTED")) {
            Ok(v) => v,
            Err(e) => panic!("get_pending_transactions failed: {e}"),
        };
        assert!(committed.iter().any(|p| p.tx_id == tx_id));
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
            dbrw_binding: "bind".into(),
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

    #[test]
    #[serial]
    fn test_wallet_init_and_verify() {
        let _ = init_database();
        cleanup_test_genesis();

        let gen = GenesisRecord {
            genesis_id: "gid".into(),
            device_id: "did".into(),
            mpc_proof: "mpc".into(),
            dbrw_binding: "bind".into(),
            merkle_root: "root".into(),
            participant_count: 5,
            progress_marker: "Ps".into(),
            publication_hash: "pub".into(),
            storage_nodes: vec!["a".into()],
            entropy_hash: "ent".into(),
            protocol_version: "1.2.3".into(),
            hash_chain_proof: None,
            smt_proof: None,
            verification_step: None,
        };

        if let Err(e) = store_genesis_record_with_verification(&gen) {
            panic!("store_genesis_record_with_verification failed: {e}");
        }
        let info = match initialize_wallet_from_verified_genesis(&gen) {
            Ok(v) => v,
            Err(e) => panic!("initialize_wallet_from_verified_genesis failed: {e}"),
        };
        assert_eq!(info.protocol_version, "1.2.3");

        let verify = match verify_wallet_against_stored_genesis() {
            Ok(v) => v,
            Err(e) => panic!("verify_wallet_against_stored_genesis failed: {e}"),
        };
        assert!(verify.verified);
        assert!(verify.merkle_proof.is_some());
    }

    #[test]
    #[serial]
    fn test_get_wallet_state_reads_binary_hash_columns() {
        unsafe {
            std::env::set_var("DSM_SDK_TEST_MODE", "1");
        }
        reset_database_for_tests();
        init_database().expect("init db");

        let binding = get_connection().expect("db connection");
        let conn = binding.lock().expect("db lock");
        conn.execute("DELETE FROM wallet_state", [])
            .expect("clear wallet_state");

        let device_id = "DEVICE123";
        let chain_tip = [0x41u8; 32];
        let merkle_root = [0x52u8; 32];
        conn.execute(
            "INSERT INTO wallet_state (
                wallet_id, device_id, genesis_id, chain_tip, chain_height,
                merkle_root, balance, created_at, updated_at, status, metadata
            ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
            params![
                format!("wallet_{device_id}"),
                device_id,
                "GENESIS123",
                chain_tip.to_vec(),
                7i64,
                merkle_root.to_vec(),
                99i64,
                1i64,
                2i64,
                "active",
                Vec::<u8>::new(),
            ],
        )
        .expect("insert binary wallet_state");
        drop(conn);

        let wallet = get_wallet_state(device_id)
            .expect("load wallet_state")
            .expect("wallet_state exists");
        assert_eq!(
            wallet.chain_tip,
            crate::util::text_id::encode_base32_crockford(&chain_tip)
        );
        assert_eq!(
            wallet.merkle_root,
            crate::util::text_id::encode_base32_crockford(&merkle_root)
        );
        assert_eq!(wallet.balance, 99);
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
            current_chain_tip: None,
            added_at: 1,
            verified: true,
            verification_proof: None,
            metadata: HashMap::new(),
            ble_address: None,
            status: status.to_string(),
            needs_online_reconcile: false,
            last_seen_online_counter: 0,
            last_seen_ble_counter: 0,
            previous_chain_tip: None,
        };
        store_contact(&contact).expect("store contact");
    }

    #[test]
    #[serial]
    fn test_update_contact_chain_tip_after_bilateral_preserves_local_restore_tip() {
        unsafe {
            std::env::set_var("DSM_SDK_TEST_MODE", "1");
        }
        reset_database_for_tests();
        init_database().expect("init db");

        let device_id = [0x41u8; 32];
        let genesis_hash = [0x51u8; 32];
        let local_tip = [0xA1u8; 32];
        let observed_tip = [0xB2u8; 32];

        seed_contact_for_chain_tip_tests(device_id, genesis_hash, "BleCapable");
        update_local_bilateral_chain_tip(&device_id, &local_tip).expect("seed local tip");

        update_contact_chain_tip_after_bilateral(&device_id, &observed_tip)
            .expect("update observed tip");

        assert_eq!(get_contact_chain_tip_raw(&device_id), Some(observed_tip));
        assert_eq!(get_local_bilateral_chain_tip(&device_id), Some(local_tip));
    }

    #[test]
    #[serial]
    fn test_update_finalized_bilateral_chain_tip_updates_local_restore_tip() {
        unsafe {
            std::env::set_var("DSM_SDK_TEST_MODE", "1");
        }
        reset_database_for_tests();
        init_database().expect("init db");

        let device_id = [0x61u8; 32];
        let genesis_hash = [0x71u8; 32];
        let stale_local_tip = [0x11u8; 32];
        let finalized_tip = [0x22u8; 32];

        seed_contact_for_chain_tip_tests(device_id, genesis_hash, "BleCapable");
        update_local_bilateral_chain_tip(&device_id, &stale_local_tip).expect("seed local tip");
        mark_contact_needs_online_reconcile(&device_id).expect("mark reconcile");

        update_finalized_bilateral_chain_tip(&device_id, &finalized_tip)
            .expect("update finalized tip");

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
        unsafe {
            std::env::set_var("DSM_SDK_TEST_MODE", "1");
        }
        reset_database_for_tests();
        init_database().expect("init db");

        let device_id = [0x81u8; 32];
        let genesis_hash = [0x91u8; 32];
        let current_tip = [0x33u8; 32];
        let stale_parent = [0x44u8; 32];
        let new_tip = [0x55u8; 32];

        seed_contact_for_chain_tip_tests(device_id, genesis_hash, "BleCapable");
        update_finalized_bilateral_chain_tip(&device_id, &current_tip).expect("seed current tip");

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
        unsafe {
            std::env::set_var("DSM_SDK_TEST_MODE", "1");
        }
        reset_database_for_tests();
        init_database().expect("init db");

        let device_id = [0xA1u8; 32];
        let genesis_hash = [0xB1u8; 32];
        let parent_tip = [0xC1u8; 32];
        let next_tip = [0xD1u8; 32];

        seed_contact_for_chain_tip_tests(device_id, genesis_hash, "BleCapable");
        update_finalized_bilateral_chain_tip(&device_id, &parent_tip).expect("seed parent tip");

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
    fn test_store_contact_upserts_by_device_id_and_repairs_identity_fields() {
        unsafe {
            std::env::set_var("DSM_SDK_TEST_MODE", "1");
        }
        reset_database_for_tests();
        init_database().expect("init db");

        let device_id = [0x11u8; 32];
        let original_tip = [0x22u8; 32];
        let original = ContactRecord {
            contact_id: "legacy-contact".to_string(),
            device_id: device_id.to_vec(),
            alias: "peer".to_string(),
            genesis_hash: [0x33u8; 32].to_vec(),
            public_key: vec![0x44u8; 64],
            current_chain_tip: Some(original_tip.to_vec()),
            added_at: 7,
            verified: true,
            verification_proof: None,
            metadata: HashMap::new(),
            ble_address: None,
            status: "Created".to_string(),
            needs_online_reconcile: true,
            last_seen_online_counter: 1,
            last_seen_ble_counter: 2,
            previous_chain_tip: None,
        };
        store_contact(&original).expect("store original contact");

        let repaired = ContactRecord {
            contact_id: "new-contact-id".to_string(),
            device_id: device_id.to_vec(),
            alias: "peer-fixed".to_string(),
            genesis_hash: [0x55u8; 32].to_vec(),
            public_key: vec![0x66u8; 64],
            current_chain_tip: None,
            added_at: 999,
            verified: true,
            verification_proof: None,
            metadata: HashMap::new(),
            ble_address: Some("11:22:33:44:55:66".to_string()),
            status: "Active".to_string(),
            needs_online_reconcile: false,
            last_seen_online_counter: 8,
            last_seen_ble_counter: 9,
            previous_chain_tip: None,
        };
        store_contact(&repaired).expect("repair contact by device id");

        let stored = get_contact_by_device_id(&device_id)
            .expect("load repaired contact")
            .expect("contact exists");
        assert_eq!(stored.contact_id, "legacy-contact");
        assert_eq!(stored.alias, "peer-fixed");
        assert_eq!(stored.genesis_hash, [0x55u8; 32].to_vec());
        assert_eq!(stored.public_key, vec![0x66u8; 64]);
        assert_eq!(stored.current_chain_tip, Some(original_tip.to_vec()));
        assert_eq!(stored.added_at, 7);
        assert_eq!(stored.status, "Active");
        assert!(!stored.needs_online_reconcile);
    }
}
