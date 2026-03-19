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
            // Use recovery_sync_status count as counterparty count if available,
            // otherwise fall back to the contacts table.
            let count: i64 = conn
                .query_row("SELECT COUNT(*) FROM recovery_sync_status", [], |row| {
                    row.get(0)
                })
                .unwrap_or(0);
            if count > 0 {
                meta.counterparty_count = count as u64;
            } else {
                // Fall back to bilateral contacts count
                let contacts: i64 = conn
                    .query_row(
                        "SELECT COUNT(*) FROM contacts WHERE verified = 1",
                        [],
                        |row| row.get(0),
                    )
                    .unwrap_or(0);
                meta.counterparty_count = contacts as u64;
            }
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

    fn setup_test_db() {
        // Use in-memory DB for tests
        std::env::set_var("DSM_SDK_TEST_MODE", "1");
        crate::storage::client_db::reset_database_for_tests();
        crate::storage::client_db::init_database().expect("init db");
        ensure_recovery_tables().expect("ensure recovery tables");
    }

    #[test]
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
}
