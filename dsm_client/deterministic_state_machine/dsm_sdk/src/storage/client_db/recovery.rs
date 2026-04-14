// SPDX-License-Identifier: MIT OR Apache-2.0
//! Recovery capsule persistence and preferences.
//!
//! Tables:
//! - `recovery_capsules`: stores encrypted capsule bytes indexed by capsule_index
//! - `recovery_prefs`: key/value store for recovery settings (enabled, configured, etc.)

use anyhow::{anyhow, Result};
use log::debug;
use rusqlite::params;

use super::get_connection;
use crate::util::deterministic_time::tick;

const PENDING_CAPSULE_INDEX_KEY: &str = "pending_capsule_index";

/// Ensure the recovery tables exist (called from schema migration path).
pub fn ensure_recovery_tables() -> Result<()> {
    let binding = get_connection()?;
    let conn = binding
        .lock()
        .map_err(|_| anyhow!("Database lock poisoned"))?;

    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS recovery_capsules(
            capsule_index     INTEGER PRIMARY KEY,
            encrypted_bytes   BLOB NOT NULL,
            smt_root          BLOB NOT NULL,
            created_tick      INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS recovery_prefs(
            key   TEXT PRIMARY KEY,
            value BLOB NOT NULL
        );

        CREATE TABLE IF NOT EXISTS recovery_sync_status(
            device_id   BLOB NOT NULL PRIMARY KEY,
            synced      INTEGER NOT NULL DEFAULT 0,
            sync_tick   INTEGER
        );

        CREATE TABLE IF NOT EXISTS recovered_chain_tips(
            device_id   BLOB NOT NULL PRIMARY KEY,
            height      INTEGER NOT NULL,
            head_hash   BLOB NOT NULL
        );
        "#,
    )?;

    Ok(())
}

/// Store an encrypted recovery capsule.
pub fn store_recovery_capsule(
    capsule_index: u64,
    encrypted_bytes: &[u8],
    smt_root: &[u8],
) -> Result<()> {
    if encrypted_bytes.is_empty() {
        return Err(anyhow!("encrypted_bytes cannot be empty"));
    }
    if smt_root.len() != 32 {
        return Err(anyhow!("smt_root must be 32 bytes, got {}", smt_root.len()));
    }

    let binding = get_connection()?;
    let conn = binding
        .lock()
        .map_err(|_| anyhow!("Database lock poisoned"))?;
    let now = tick();

    conn.execute(
        "INSERT OR REPLACE INTO recovery_capsules(capsule_index, encrypted_bytes, smt_root, created_tick)
         VALUES (?1, ?2, ?3, ?4)",
        params![capsule_index as i64, encrypted_bytes, smt_root, now as i64],
    )?;

    debug!(
        "[CLIENT_DB] Stored recovery capsule index={}",
        capsule_index
    );
    Ok(())
}

/// Get the latest (highest capsule_index) recovery capsule.
pub fn get_latest_recovery_capsule() -> Result<Option<(u64, Vec<u8>)>> {
    let binding = get_connection()?;
    let conn = binding
        .lock()
        .map_err(|_| anyhow!("Database lock poisoned"))?;

    let mut stmt = conn.prepare(
        "SELECT capsule_index, encrypted_bytes FROM recovery_capsules
         ORDER BY capsule_index DESC LIMIT 1",
    )?;

    let result = stmt
        .query_row([], |row| {
            let idx: i64 = row.get(0)?;
            let bytes: Vec<u8> = row.get(1)?;
            Ok((idx as u64, bytes))
        })
        .optional()?;

    Ok(result)
}

/// Mark a stored capsule as pending for the next NFC write.
pub fn mark_pending_recovery_capsule(capsule_index: u64) -> Result<()> {
    let binding = get_connection()?;
    let conn = binding
        .lock()
        .map_err(|_| anyhow!("Database lock poisoned"))?;

    let exists: i64 = conn.query_row(
        "SELECT COUNT(*) FROM recovery_capsules WHERE capsule_index = ?1",
        params![capsule_index as i64],
        |row| row.get(0),
    )?;
    if exists == 0 {
        return Err(anyhow!(
            "cannot mark missing recovery capsule {} as pending",
            capsule_index
        ));
    }

    drop(conn);
    set_recovery_pref(PENDING_CAPSULE_INDEX_KEY, &capsule_index.to_le_bytes())
}

/// Clear the pending NFC-write capsule marker.
pub fn clear_pending_recovery_capsule() -> Result<()> {
    let binding = get_connection()?;
    let conn = binding
        .lock()
        .map_err(|_| anyhow!("Database lock poisoned"))?;
    conn.execute(
        "DELETE FROM recovery_prefs WHERE key = ?1",
        params![PENDING_CAPSULE_INDEX_KEY],
    )?;
    Ok(())
}

/// Get the exact capsule currently pending for NFC write.
pub fn get_pending_recovery_capsule() -> Result<Option<(u64, Vec<u8>)>> {
    let Some(bytes) = get_recovery_pref(PENDING_CAPSULE_INDEX_KEY)? else {
        return Ok(None);
    };
    if bytes.len() != 8 {
        return Err(anyhow!(
            "pending capsule index pref must be 8 bytes, got {}",
            bytes.len()
        ));
    }
    let mut idx_bytes = [0u8; 8];
    idx_bytes.copy_from_slice(&bytes);
    let capsule_index = u64::from_le_bytes(idx_bytes);

    let binding = get_connection()?;
    let conn = binding
        .lock()
        .map_err(|_| anyhow!("Database lock poisoned"))?;
    let capsule = conn
        .query_row(
            "SELECT encrypted_bytes FROM recovery_capsules WHERE capsule_index = ?1",
            params![capsule_index as i64],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .optional()?;

    if let Some(encrypted_bytes) = capsule {
        return Ok(Some((capsule_index, encrypted_bytes)));
    }

    drop(conn);
    clear_pending_recovery_capsule()?;
    Ok(None)
}

/// Metadata about a stored capsule (for dashboard display, no decryption).
pub struct CapsuleMetadata {
    pub capsule_index: u64,
    pub smt_root: Vec<u8>,
    pub created_tick: u64,
    pub counterparty_count: u64,
}

/// Get metadata for the latest capsule (no decryption needed).
pub fn get_latest_capsule_metadata() -> Result<Option<CapsuleMetadata>> {
    let binding = get_connection()?;
    let conn = binding
        .lock()
        .map_err(|_| anyhow!("Database lock poisoned"))?;

    let result = conn
        .query_row(
            "SELECT capsule_index, smt_root, created_tick FROM recovery_capsules
             ORDER BY capsule_index DESC LIMIT 1",
            [],
            |row| {
                let idx: i64 = row.get(0)?;
                let smt_root: Vec<u8> = row.get(1)?;
                let tick: i64 = row.get(2)?;
                Ok(CapsuleMetadata {
                    capsule_index: idx as u64,
                    smt_root,
                    created_tick: tick as u64,
                    // Counterparty count is inside the encrypted capsule; we store it
                    // as a separate column or derive from the recovery_sync_status table.
                    // For now, use sync status table count as a proxy.
                    counterparty_count: 0, // Filled below
                })
            },
        )
        .optional()?;

    match result {
        Some(mut meta) => {
            let stored_count: Option<Vec<u8>> = conn
                .query_row(
                    "SELECT value FROM recovery_prefs WHERE key = 'latest_capsule_counterparty_count'",
                    [],
                    |row| row.get(0),
                )
                .optional()
                .unwrap_or(None);

            if let Some(bytes) = stored_count {
                if bytes.len() == 8 {
                    if let Ok(arr) = <[u8; 8]>::try_from(bytes.as_slice()) {
                        meta.counterparty_count = u64::from_le_bytes(arr);
                        return Ok(Some(meta));
                    }
                }
            }

            // Fall back to staged recovered tips if present, then verified contacts.
            let staged_count: i64 = conn
                .query_row("SELECT COUNT(*) FROM recovered_chain_tips", [], |row| {
                    row.get(0)
                })
                .unwrap_or(0);
            if staged_count > 0 {
                meta.counterparty_count = staged_count as u64;
                return Ok(Some(meta));
            }

            let contacts: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM contacts WHERE verified = 1",
                    [],
                    |row| row.get(0),
                )
                .unwrap_or(0);
            meta.counterparty_count = contacts as u64;
            Ok(Some(meta))
        }
        None => Ok(None),
    }
}

/// Get the total number of stored capsules.
pub fn get_capsule_count() -> Result<u64> {
    let binding = get_connection()?;
    let conn = binding
        .lock()
        .map_err(|_| anyhow!("Database lock poisoned"))?;

    let count: i64 = conn.query_row("SELECT COUNT(*) FROM recovery_capsules", [], |row| {
        row.get(0)
    })?;

    Ok(count as u64)
}

/// Get the highest capsule index, or 0 if no capsules exist.
pub fn get_max_capsule_index() -> Result<u64> {
    let binding = get_connection()?;
    let conn = binding
        .lock()
        .map_err(|_| anyhow!("Database lock poisoned"))?;

    let idx: i64 = conn.query_row(
        "SELECT COALESCE(MAX(capsule_index), 0) FROM recovery_capsules",
        [],
        |row| row.get(0),
    )?;

    Ok(idx as u64)
}

/// Set a recovery preference (binary value).
pub fn set_recovery_pref(key: &str, value: &[u8]) -> Result<()> {
    let binding = get_connection()?;
    let conn = binding
        .lock()
        .map_err(|_| anyhow!("Database lock poisoned"))?;

    conn.execute(
        "INSERT OR REPLACE INTO recovery_prefs(key, value) VALUES (?1, ?2)",
        params![key, value],
    )?;

    Ok(())
}

/// Get a recovery preference.
pub fn get_recovery_pref(key: &str) -> Result<Option<Vec<u8>>> {
    let binding = get_connection()?;
    let conn = binding
        .lock()
        .map_err(|_| anyhow!("Database lock poisoned"))?;

    let result: Option<Vec<u8>> = conn
        .query_row(
            "SELECT value FROM recovery_prefs WHERE key = ?1",
            params![key],
            |row| row.get(0),
        )
        .optional()?;

    Ok(result)
}

/// Check if NFC backup is enabled.
pub fn is_nfc_backup_enabled() -> bool {
    get_recovery_pref("nfc_backup_enabled")
        .ok()
        .flatten()
        .map(|v| v == [1u8])
        .unwrap_or(false)
}

/// Check if NFC backup was ever configured (mnemonic was set up).
pub fn is_nfc_backup_configured() -> bool {
    get_recovery_pref("nfc_backup_configured")
        .ok()
        .flatten()
        .map(|v| v == [1u8])
        .unwrap_or(false)
}

/// Set NFC backup enabled state.
pub fn set_nfc_backup_enabled(enabled: bool) -> Result<()> {
    set_recovery_pref("nfc_backup_enabled", &[if enabled { 1u8 } else { 0u8 }])
}

/// Set NFC backup configured state.
pub fn set_nfc_backup_configured(configured: bool) -> Result<()> {
    set_recovery_pref(
        "nfc_backup_configured",
        &[if configured { 1u8 } else { 0u8 }],
    )
}

/// Check if NFC auto-write-on-transaction is enabled.
pub fn is_nfc_auto_write_enabled() -> bool {
    get_recovery_pref("nfc_auto_write_prompt")
        .ok()
        .flatten()
        .map(|v| v == [1u8])
        .unwrap_or(false)
}

/// Set NFC auto-write-on-transaction enabled state.
pub fn set_nfc_auto_write_enabled(enabled: bool) -> Result<()> {
    set_recovery_pref("nfc_auto_write_prompt", &[if enabled { 1u8 } else { 0u8 }])
}

/// Store the exact counterparty count for the latest capsule preview.
pub fn set_latest_capsule_counterparty_count(count: u64) -> Result<()> {
    set_recovery_pref("latest_capsule_counterparty_count", &count.to_le_bytes())
}

/// Delete all capsules except the latest N (cleanup).
pub fn prune_old_capsules(keep_latest_n: u64) -> Result<u64> {
    let binding = get_connection()?;
    let conn = binding
        .lock()
        .map_err(|_| anyhow!("Database lock poisoned"))?;

    let deleted = conn.execute(
        "DELETE FROM recovery_capsules WHERE capsule_index NOT IN (
            SELECT capsule_index FROM recovery_capsules ORDER BY capsule_index DESC LIMIT ?1
        )",
        params![keep_latest_n as i64],
    )?;

    let pending_pref: Option<Vec<u8>> = conn
        .query_row(
            "SELECT value FROM recovery_prefs WHERE key = ?1",
            params![PENDING_CAPSULE_INDEX_KEY],
            |row| row.get(0),
        )
        .optional()?;

    if let Some(bytes) = pending_pref {
        if bytes.len() == 8 {
            let mut idx_bytes = [0u8; 8];
            idx_bytes.copy_from_slice(&bytes);
            let pending_index = u64::from_le_bytes(idx_bytes);
            let exists: i64 = conn.query_row(
                "SELECT COUNT(*) FROM recovery_capsules WHERE capsule_index = ?1",
                params![pending_index as i64],
                |row| row.get(0),
            )?;
            if exists == 0 {
                drop(conn);
                clear_pending_recovery_capsule()?;
                return Ok(deleted as u64);
            }
        }
    }

    Ok(deleted as u64)
}

use rusqlite::OptionalExtension;

// ============================================================================
// Recovery Sync Gate — tombstone must reach ALL contacts before resume
// ============================================================================

/// Ensure the recovery_sync_status table exists.
pub fn ensure_recovery_sync_table() -> Result<()> {
    let binding = get_connection()?;
    let conn = binding
        .lock()
        .map_err(|_| anyhow!("Database lock poisoned"))?;

    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS recovery_sync_status(
            device_id   BLOB NOT NULL PRIMARY KEY,
            synced      INTEGER NOT NULL DEFAULT 0,
            sync_tick   INTEGER
        );
        "#,
    )?;

    Ok(())
}

/// Initialize sync tracking for all counterparties from a recovered capsule.
/// Sets all to synced=0 (pending).
pub fn init_recovery_sync_status(counterparty_device_ids: &[[u8; 32]]) -> Result<()> {
    let binding = get_connection()?;
    let conn = binding
        .lock()
        .map_err(|_| anyhow!("Database lock poisoned"))?;

    // Clear any existing sync status
    conn.execute("DELETE FROM recovery_sync_status", [])?;

    let mut stmt = conn.prepare(
        "INSERT INTO recovery_sync_status(device_id, synced, sync_tick) VALUES (?1, 0, NULL)",
    )?;

    for device_id in counterparty_device_ids {
        stmt.execute(params![device_id.as_slice()])?;
    }

    debug!(
        "[CLIENT_DB] Initialized recovery sync status for {} counterparties",
        counterparty_device_ids.len()
    );
    Ok(())
}

/// Mark a counterparty as having synced the tombstone.
pub fn mark_counterparty_synced(device_id: &[u8; 32], sync_tick_val: u64) -> Result<()> {
    let binding = get_connection()?;
    let conn = binding
        .lock()
        .map_err(|_| anyhow!("Database lock poisoned"))?;

    conn.execute(
        "UPDATE recovery_sync_status SET synced = 1, sync_tick = ?1 WHERE device_id = ?2",
        params![sync_tick_val as i64, device_id.as_slice()],
    )?;

    debug!(
        "[CLIENT_DB] Marked counterparty as tombstone-synced at tick {}",
        sync_tick_val
    );
    Ok(())
}

/// Get all counterparty DevIDs that have NOT yet synced the tombstone.
pub fn get_unsynced_counterparties() -> Result<Vec<[u8; 32]>> {
    let binding = get_connection()?;
    let conn = binding
        .lock()
        .map_err(|_| anyhow!("Database lock poisoned"))?;

    let mut stmt = conn.prepare("SELECT device_id FROM recovery_sync_status WHERE synced = 0")?;

    let rows = stmt.query_map([], |row| {
        let bytes: Vec<u8> = row.get(0)?;
        Ok(bytes)
    })?;

    let mut result = Vec::new();
    for bytes in rows.flatten() {
        if bytes.len() == 32 {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            result.push(arr);
        }
    }

    Ok(result)
}

/// Check if ALL counterparties have synced the tombstone.
/// Returns true only when every entry has synced=1.
/// Returns true if the table is empty (no counterparties to sync).
pub fn all_counterparties_synced() -> Result<bool> {
    let binding = get_connection()?;
    let conn = binding
        .lock()
        .map_err(|_| anyhow!("Database lock poisoned"))?;

    let unsynced_count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM recovery_sync_status WHERE synced = 0",
        [],
        |row| row.get(0),
    )?;

    Ok(unsynced_count == 0)
}

/// Get sync progress: (synced_count, total_count).
pub fn get_sync_progress() -> Result<(u64, u64)> {
    let binding = get_connection()?;
    let conn = binding
        .lock()
        .map_err(|_| anyhow!("Database lock poisoned"))?;

    let total: i64 = conn.query_row("SELECT COUNT(*) FROM recovery_sync_status", [], |row| {
        row.get(0)
    })?;

    let synced: i64 = conn.query_row(
        "SELECT COUNT(*) FROM recovery_sync_status WHERE synced = 1",
        [],
        |row| row.get(0),
    )?;

    Ok((synced as u64, total as u64))
}

/// Clear all sync status (for reset or new recovery cycle).
pub fn clear_recovery_sync_status() -> Result<()> {
    let binding = get_connection()?;
    let conn = binding
        .lock()
        .map_err(|_| anyhow!("Database lock poisoned"))?;

    conn.execute("DELETE FROM recovery_sync_status", [])?;
    Ok(())
}

/// Staged recovered chain tip used for crash-safe tombstone/resume recovery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveredChainTip {
    pub device_id: [u8; 32],
    pub height: u64,
    pub head_hash: [u8; 32],
}

/// Replace the staged recovered chain tips with the newly imported capsule tips.
pub fn store_recovered_chain_tips(tips: &[RecoveredChainTip]) -> Result<()> {
    ensure_recovery_tables()?;
    let binding = get_connection()?;
    let mut conn = binding
        .lock()
        .map_err(|_| anyhow!("Database lock poisoned"))?;

    let tx = conn.transaction()?;
    tx.execute("DELETE FROM recovered_chain_tips", [])?;

    if !tips.is_empty() {
        let mut stmt = tx.prepare(
            "INSERT INTO recovered_chain_tips(device_id, height, head_hash) VALUES (?1, ?2, ?3)",
        )?;
        for tip in tips {
            stmt.execute(params![
                tip.device_id.as_slice(),
                tip.height as i64,
                tip.head_hash.as_slice()
            ])?;
        }
    }

    tx.commit()?;
    Ok(())
}

/// Return all staged recovered chain tips from the most recently imported capsule.
pub fn get_recovered_chain_tips() -> Result<Vec<RecoveredChainTip>> {
    ensure_recovery_tables()?;
    let binding = get_connection()?;
    let conn = binding
        .lock()
        .map_err(|_| anyhow!("Database lock poisoned"))?;

    let mut stmt = conn.prepare(
        "SELECT device_id, height, head_hash FROM recovered_chain_tips ORDER BY device_id ASC",
    )?;

    let rows = stmt.query_map([], |row| {
        let device_id: Vec<u8> = row.get(0)?;
        let height: i64 = row.get(1)?;
        let head_hash: Vec<u8> = row.get(2)?;
        Ok((device_id, height, head_hash))
    })?;

    let mut tips = Vec::new();
    for row in rows {
        let (device_id, height, head_hash) = row?;
        if device_id.len() != 32 {
            return Err(anyhow!(
                "recovered_chain_tips.device_id must be 32 bytes, got {}",
                device_id.len()
            ));
        }
        if head_hash.len() != 32 {
            return Err(anyhow!(
                "recovered_chain_tips.head_hash must be 32 bytes, got {}",
                head_hash.len()
            ));
        }

        let mut device_id_arr = [0u8; 32];
        device_id_arr.copy_from_slice(&device_id);
        let mut head_hash_arr = [0u8; 32];
        head_hash_arr.copy_from_slice(&head_hash);

        tips.push(RecoveredChainTip {
            device_id: device_id_arr,
            height: height as u64,
            head_hash: head_hash_arr,
        });
    }

    Ok(tips)
}

/// Clear all staged recovered chain tips.
pub fn clear_recovered_chain_tips() -> Result<()> {
    ensure_recovery_tables()?;
    let binding = get_connection()?;
    let conn = binding
        .lock()
        .map_err(|_| anyhow!("Database lock poisoned"))?;

    conn.execute("DELETE FROM recovered_chain_tips", [])?;
    Ok(())
}

// ============================================================================
// Tombstone Persistence — store receipts and track tombstoned devices
// ============================================================================

/// Ensure the tombstoned_devices table exists (called from schema migration path).
pub fn ensure_tombstone_tables() -> Result<()> {
    let binding = get_connection()?;
    let conn = binding
        .lock()
        .map_err(|_| anyhow!("Database lock poisoned"))?;

    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS tombstoned_devices(
            device_id       BLOB NOT NULL PRIMARY KEY,
            tombstone_hash  BLOB NOT NULL,
            discovered_tick INTEGER NOT NULL
        );
        "#,
    )?;

    Ok(())
}

/// Store the tombstone receipt bytes for later relay to counterparties.
pub fn store_tombstone_receipt(receipt_bytes: &[u8]) -> Result<()> {
    set_recovery_pref("tombstone_receipt", receipt_bytes)
}

/// Get the stored tombstone receipt bytes.
pub fn get_tombstone_receipt() -> Result<Option<Vec<u8>>> {
    get_recovery_pref("tombstone_receipt")
}

/// Store the counterparty device IDs extracted from a decrypted capsule.
/// Device IDs are stored as concatenated 32-byte arrays.
pub fn store_capsule_counterparty_ids(device_ids: &[[u8; 32]]) -> Result<()> {
    let mut blob = Vec::with_capacity(device_ids.len() * 32);
    for id in device_ids {
        blob.extend_from_slice(id);
    }
    set_recovery_pref("capsule_counterparty_ids", &blob)
}

/// Get the counterparty device IDs stored during capsule decryption.
pub fn get_capsule_counterparty_ids() -> Result<Vec<[u8; 32]>> {
    let blob = get_recovery_pref("capsule_counterparty_ids")?.unwrap_or_default();
    if blob.len() % 32 != 0 {
        return Err(anyhow!(
            "capsule_counterparty_ids blob length {} not divisible by 32",
            blob.len()
        ));
    }
    let mut ids = Vec::with_capacity(blob.len() / 32);
    for chunk in blob.chunks_exact(32) {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(chunk);
        ids.push(arr);
    }
    Ok(ids)
}

/// Store the tombstone hash for the recovering device (our old device).
pub fn store_tombstone_hash(tombstone_hash: &[u8]) -> Result<()> {
    set_recovery_pref("tombstone_hash", tombstone_hash)
}

/// Get the stored tombstone hash.
pub fn get_tombstone_hash() -> Result<Option<Vec<u8>>> {
    get_recovery_pref("tombstone_hash")
}

/// Store a succession receipt for the new device.
pub fn store_succession_receipt(receipt_bytes: &[u8]) -> Result<()> {
    set_recovery_pref("succession_receipt", receipt_bytes)
}

/// Get the stored succession receipt.
pub fn get_succession_receipt() -> Result<Option<Vec<u8>>> {
    get_recovery_pref("succession_receipt")
}

/// Record a device ID as tombstoned (rejected for future bilateral interactions).
pub fn store_tombstoned_device(
    device_id: &[u8; 32],
    tombstone_hash: &[u8],
    tick: u64,
) -> Result<()> {
    ensure_tombstone_tables()?;
    let binding = get_connection()?;
    let conn = binding
        .lock()
        .map_err(|_| anyhow!("Database lock poisoned"))?;

    conn.execute(
        "INSERT OR REPLACE INTO tombstoned_devices(device_id, tombstone_hash, discovered_tick)
         VALUES (?1, ?2, ?3)",
        params![device_id.as_slice(), tombstone_hash, tick as i64],
    )?;

    debug!("[CLIENT_DB] Stored tombstoned device at tick {}", tick);
    Ok(())
}

/// Check if a device ID has been tombstoned.
pub fn is_device_tombstoned(device_id: &[u8; 32]) -> bool {
    let result = (|| -> Result<bool> {
        ensure_tombstone_tables()?;
        let binding = get_connection()?;
        let conn = binding
            .lock()
            .map_err(|_| anyhow!("Database lock poisoned"))?;

        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM tombstoned_devices WHERE device_id = ?1",
            params![device_id.as_slice()],
            |row| row.get(0),
        )?;
        Ok(count > 0)
    })();
    result.unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    fn setup_test_db() {
        // Use in-memory DB for tests
        std::env::set_var("DSM_SDK_TEST_MODE", "1");
        crate::storage::client_db::reset_database_for_tests();
        if let Err(e) = crate::storage::client_db::init_database() {
            let msg = e.to_string();
            if !msg.contains("duplicate column name: device_tree_root") {
                panic!("init db: {e}");
            }
        }
        ensure_recovery_tables().expect("ensure recovery tables");
    }

    #[test]
    #[serial]
    fn test_store_and_retrieve_capsule() {
        setup_test_db();
        let smt_root = [42u8; 32];
        let capsule_bytes = b"encrypted_capsule_data";

        store_recovery_capsule(1, capsule_bytes, &smt_root).expect("store");

        let latest = get_latest_recovery_capsule().expect("get latest");
        assert!(latest.is_some());
        let (idx, bytes) = latest.expect("should have capsule");
        assert_eq!(idx, 1);
        assert_eq!(bytes, capsule_bytes);
    }

    #[test]
    #[serial]
    fn test_capsule_count_and_max_index() {
        setup_test_db();
        let smt_root = [42u8; 32];

        assert_eq!(get_capsule_count().expect("count"), 0);
        assert_eq!(get_max_capsule_index().expect("max"), 0);

        store_recovery_capsule(5, b"cap5", &smt_root).expect("store");
        store_recovery_capsule(10, b"cap10", &smt_root).expect("store");

        assert_eq!(get_capsule_count().expect("count"), 2);
        assert_eq!(get_max_capsule_index().expect("max"), 10);
    }

    #[test]
    #[serial]
    fn test_pending_capsule_marker_clears_without_deleting_capsule() {
        setup_test_db();
        let smt_root = [7u8; 32];

        store_recovery_capsule(1, b"cap1", &smt_root).expect("store cap1");
        store_recovery_capsule(2, b"cap2", &smt_root).expect("store cap2");
        mark_pending_recovery_capsule(2).expect("mark pending");

        let pending = get_pending_recovery_capsule().expect("read pending");
        assert_eq!(pending, Some((2, b"cap2".to_vec())));

        clear_pending_recovery_capsule().expect("clear pending");
        assert!(get_pending_recovery_capsule()
            .expect("pending cleared")
            .is_none());

        let latest = get_latest_recovery_capsule().expect("latest");
        assert_eq!(latest, Some((2, b"cap2".to_vec())));
    }

    #[test]
    #[serial]
    fn test_recovery_prefs() {
        setup_test_db();

        assert!(!is_nfc_backup_enabled());
        assert!(!is_nfc_backup_configured());

        set_nfc_backup_enabled(true).expect("set enabled");
        set_nfc_backup_configured(true).expect("set configured");

        assert!(is_nfc_backup_enabled());
        assert!(is_nfc_backup_configured());

        set_nfc_backup_enabled(false).expect("set disabled");
        assert!(!is_nfc_backup_enabled());
        assert!(is_nfc_backup_configured()); // configured stays true
    }

    #[test]
    #[serial]
    fn test_store_and_clear_recovered_chain_tips() {
        setup_test_db();

        let tips = vec![
            RecoveredChainTip {
                device_id: [1u8; 32],
                height: 7,
                head_hash: [2u8; 32],
            },
            RecoveredChainTip {
                device_id: [3u8; 32],
                height: 9,
                head_hash: [4u8; 32],
            },
        ];

        store_recovered_chain_tips(&tips).expect("store tips");
        let stored = get_recovered_chain_tips().expect("read tips");
        assert_eq!(stored, tips);

        clear_recovered_chain_tips().expect("clear tips");
        assert!(get_recovered_chain_tips().expect("read cleared").is_empty());
    }
}
