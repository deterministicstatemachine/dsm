// SPDX-License-Identifier: MIT OR Apache-2.0
//! Vault store persistence (Invariant 18 §12.2.2).

use anyhow::Result;
use rusqlite::{params, OptionalExtension};

use super::get_connection;
use crate::util::deterministic_time::tick;

/// Insert or update a vault store entry.
/// `entry_header` is the 80-byte Bitcoin block header cached at entry time (Invariant 19, §12.2.3).
/// `btc_amount_sats` is the HTLC lock amount used for vault selection on transfer.
pub fn put_vault(
    vault_id: &str,
    vault_proto_full: &[u8],
    vault_state: &str,
    entry_header: &[u8; 80],
    btc_amount_sats: u64,
) -> Result<()> {
    let now = tick();
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|poisoned| {
        log::warn!("DB lock poisoned in put_vault, recovering");
        poisoned.into_inner()
    });
    conn.execute(
        "INSERT OR REPLACE INTO vault_store(vault_id, vault_proto_full, vault_state, entry_header, btc_amount_sats, created_at)
         VALUES(?1, ?2, ?3, ?4, ?5, ?6)",
        params![vault_id, vault_proto_full as &[u8], vault_state, entry_header as &[u8], btc_amount_sats as i64, now as i64],
    )?;
    Ok(())
}

/// Get a stored vault by ID.
/// Returns (vault_proto_full, vault_state, entry_header [80 bytes], btc_amount_sats).
pub fn get_vault(vault_id: &str) -> Result<Option<(Vec<u8>, String, [u8; 80], u64)>> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|poisoned| {
        log::warn!("DB lock poisoned in get_vault, recovering");
        poisoned.into_inner()
    });
    let row = conn
        .query_row(
            "SELECT vault_proto_full, vault_state, entry_header, btc_amount_sats FROM vault_store WHERE vault_id = ?1",
            params![vault_id],
            |row| {
                let proto: Vec<u8> = row.get(0)?;
                let state: String = row.get(1)?;
                let hdr_raw: Vec<u8> = row.get(2)?;
                let sats: i64 = row.get(3)?;
                Ok((proto, state, hdr_raw, sats))
            },
        )
        .optional()?;
    if let Some((proto, state, hdr_raw, sats)) = row {
        if hdr_raw.len() != 80 {
            return Err(rusqlite::Error::InvalidColumnType(
                2,
                "entry_header".to_string(),
                rusqlite::types::Type::Blob,
            )
            .into());
        }
        let mut hdr = [0u8; 80];
        hdr.copy_from_slice(&hdr_raw);
        Ok(Some((proto, state, hdr, sats as u64)))
    } else {
        Ok(None)
    }
}

/// List all **active/limbo** vaults with `btc_amount_sats >= min_sats`, ordered by `created_at ASC` (oldest first).
/// Filters out "received", "transferred", "invalidated", "unlocked", and "claimed" vaults.
pub fn list_vaults_by_amount(min_sats: u64) -> Result<Vec<String>> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|poisoned| {
        log::warn!("DB lock poisoned in list_vaults_by_amount, recovering");
        poisoned.into_inner()
    });
    let mut stmt = conn.prepare(
        "SELECT vault_id FROM vault_store WHERE btc_amount_sats >= ?1 AND vault_state IN ('active', 'limbo') ORDER BY created_at ASC",
    )?;
    let ids = stmt.query_map(params![min_sats as i64], |row| row.get::<_, String>(0))?;
    let mut result = Vec::new();
    for id in ids {
        result.push(id?);
    }
    Ok(result)
}

/// Find the smallest active/limbo vault with at least `min_amount_sats`.
///
/// dBTC transfers are satoshi-granular (§8, §10) — the vault is collateral
/// backing, not the transfer unit. This finds the smallest sufficient vault
/// (>= requested amount), preferring older vaults
/// when amounts are equal.
pub fn find_oldest_active_vault(min_amount_sats: u64) -> Result<Option<String>> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|poisoned| {
        log::warn!("DB lock poisoned in find_oldest_active_vault, recovering");
        poisoned.into_inner()
    });
    conn.query_row(
        "SELECT vault_id FROM vault_store
         WHERE btc_amount_sats >= ?1 AND vault_state IN ('active', 'limbo')
         ORDER BY btc_amount_sats ASC, created_at ASC LIMIT 1",
        params![min_amount_sats as i64],
        |row| row.get(0),
    )
    .optional()
    .map_err(Into::into)
}

/// Return the `btc_amount_sats` of the smallest sufficient active/limbo vault.
///
/// dBTC transfers are satoshi-granular (§8, §10) — the vault is collateral
/// backing, not the transfer unit. This finds the smallest sufficient vault
/// (>= requested amount), preferring older vaults
/// when amounts are equal.
pub fn find_vault_sats_for_transfer(min_amount_sats: u64) -> Result<Option<u64>> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|poisoned| {
        log::warn!("DB lock poisoned in find_vault_sats_for_transfer, recovering");
        poisoned.into_inner()
    });
    conn.query_row(
        "SELECT btc_amount_sats FROM vault_store
         WHERE btc_amount_sats >= ?1 AND vault_state IN ('active', 'limbo')
         ORDER BY btc_amount_sats ASC, created_at ASC LIMIT 1",
        params![min_amount_sats as i64],
        |row| row.get::<_, i64>(0).map(|v| v as u64),
    )
    .optional()
    .map_err(Into::into)
}

/// List ALL vault IDs (regardless of state) for restore-from-persistence.
/// Unlike `list_vaults_by_amount` which filters to active/limbo only,
/// this returns every vault so the DLVManager can be fully rehydrated.
pub fn list_all_vault_ids() -> Result<Vec<String>> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|poisoned| {
        log::warn!("DB lock poisoned in list_all_vault_ids, recovering");
        poisoned.into_inner()
    });
    let mut stmt = conn.prepare("SELECT vault_id FROM vault_store ORDER BY created_at ASC")?;
    let ids = stmt.query_map([], |row| row.get::<_, String>(0))?;
    let mut result = Vec::new();
    for id in ids {
        result.push(id?);
    }
    Ok(result)
}

/// Remove a vault from the store.
pub fn remove_vault(vault_id: &str) -> Result<()> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|poisoned| {
        log::warn!("DB lock poisoned in remove_vault, recovering");
        poisoned.into_inner()
    });
    conn.execute(
        "DELETE FROM vault_store WHERE vault_id = ?1",
        params![vault_id],
    )?;
    Ok(())
}

/// Remove the smallest active/limbo vault with at least `min_amount_sats`.
/// Called on sender after bilateral commit to prevent double-spend.
/// Uses the same selection order as `find_oldest_active_vault`.
/// Returns the removed vault_id if found.
/// Get the oldest active vault matching the requested amount (for packing vault anchor).
/// Returns (vault_id, vault_proto_full, vault_state, entry_header).
pub fn get_oldest_active_vault_for_amount(
    min_amount_sats: u64,
) -> Result<Option<(String, Vec<u8>, String, Vec<u8>)>> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|poisoned| {
        log::warn!("DB lock poisoned in get_oldest_active_vault_for_amount, recovering");
        poisoned.into_inner()
    });
    conn.query_row(
        "SELECT vault_id, vault_proto_full, vault_state, entry_header FROM vault_store
         WHERE btc_amount_sats >= ?1 AND vault_state IN ('active', 'limbo')
         ORDER BY btc_amount_sats ASC, created_at ASC LIMIT 1",
        params![min_amount_sats as i64],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
    )
    .optional()
    .map_err(Into::into)
}

pub fn remove_oldest_active_vault(min_amount_sats: u64) -> Result<Option<String>> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|poisoned| {
        log::warn!("DB lock poisoned in remove_oldest_active_vault, recovering");
        poisoned.into_inner()
    });
    let vault_id: Option<String> = conn
        .query_row(
            "SELECT vault_id FROM vault_store
             WHERE btc_amount_sats >= ?1 AND vault_state IN ('active', 'limbo')
             ORDER BY btc_amount_sats ASC, created_at ASC LIMIT 1",
            params![min_amount_sats as i64],
            |row| row.get(0),
        )
        .optional()?;
    if let Some(ref vid) = vault_id {
        conn.execute("DELETE FROM vault_store WHERE vault_id = ?1", params![vid])?;
    }
    Ok(vault_id)
}

/// Delete ALL rows from vault_store, vault_records, in_flight_withdrawals,
/// in_flight_withdrawal_legs, and DLV receipts.
/// Used for full vault data wipe (e.g., after policy commit migration).
pub fn wipe_all_vault_data() -> Result<u64> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|poisoned| {
        log::warn!("DB lock poisoned in wipe_all_vault_data, recovering");
        poisoned.into_inner()
    });
    let mut total = 0u64;
    total += conn.execute("DELETE FROM vault_store", [])? as u64;
    total += conn.execute("DELETE FROM vault_records", [])? as u64;
    total += conn.execute("DELETE FROM in_flight_withdrawals", [])? as u64;
    total += conn.execute("DELETE FROM in_flight_withdrawal_legs", [])? as u64;
    // Delete DLV receipts (vault completion proofs from old policy)
    total += conn.execute("DELETE FROM dlv_receipts", [])? as u64;
    log::info!("[wipe] deleted {total} total rows from vault/dBTC tables");
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    fn init_test_db() {
        unsafe { std::env::set_var("DSM_SDK_TEST_MODE", "1") };
        crate::storage::client_db::reset_database_for_tests();
        crate::storage::client_db::init_database().expect("init db");
    }

    fn dummy_header() -> [u8; 80] {
        [0xAA; 80]
    }

    #[test]
    #[serial]
    fn put_and_get_vault_roundtrip() {
        init_test_db();
        let hdr = dummy_header();
        put_vault("v-1", b"proto-bytes", "active", &hdr, 100_000).unwrap();

        let (proto, state, loaded_hdr, sats) = get_vault("v-1").unwrap().unwrap();
        assert_eq!(proto, b"proto-bytes");
        assert_eq!(state, "active");
        assert_eq!(loaded_hdr, hdr);
        assert_eq!(sats, 100_000);
    }

    #[test]
    #[serial]
    fn get_nonexistent_vault_returns_none() {
        init_test_db();
        assert!(get_vault("nonexistent").unwrap().is_none());
    }

    #[test]
    #[serial]
    fn list_vaults_by_amount_filters_active_limbo() {
        init_test_db();
        let hdr = dummy_header();
        put_vault("v-a", b"p", "active", &hdr, 50_000).unwrap();
        put_vault("v-b", b"p", "limbo", &hdr, 100_000).unwrap();
        put_vault("v-c", b"p", "transferred", &hdr, 200_000).unwrap();

        let ids = list_vaults_by_amount(0).unwrap();
        assert_eq!(ids.len(), 2);
        assert!(ids.contains(&"v-a".to_string()));
        assert!(ids.contains(&"v-b".to_string()));
    }

    #[test]
    #[serial]
    fn find_oldest_active_vault_selects_smallest_sufficient() {
        init_test_db();
        let hdr = dummy_header();
        put_vault("v-sm", b"p", "active", &hdr, 50_000).unwrap();
        put_vault("v-lg", b"p", "active", &hdr, 200_000).unwrap();

        let found = find_oldest_active_vault(60_000).unwrap().unwrap();
        assert_eq!(found, "v-lg");
    }

    #[test]
    #[serial]
    fn remove_vault_deletes_entry() {
        init_test_db();
        let hdr = dummy_header();
        put_vault("v-del", b"p", "active", &hdr, 10_000).unwrap();
        remove_vault("v-del").unwrap();
        assert!(get_vault("v-del").unwrap().is_none());
    }

    #[test]
    #[serial]
    fn remove_oldest_active_vault_returns_removed_id() {
        init_test_db();
        let hdr = dummy_header();
        put_vault("v-ro1", b"p", "active", &hdr, 80_000).unwrap();
        put_vault("v-ro2", b"p", "active", &hdr, 90_000).unwrap();

        let removed = remove_oldest_active_vault(80_000).unwrap().unwrap();
        assert_eq!(removed, "v-ro1");
        assert!(get_vault("v-ro1").unwrap().is_none());
    }

    #[test]
    #[serial]
    fn list_all_vault_ids_includes_all_states() {
        init_test_db();
        let hdr = dummy_header();
        put_vault("v-all1", b"p", "active", &hdr, 10_000).unwrap();
        put_vault("v-all2", b"p", "transferred", &hdr, 20_000).unwrap();
        put_vault("v-all3", b"p", "invalidated", &hdr, 30_000).unwrap();

        let all = list_all_vault_ids().unwrap();
        assert_eq!(all.len(), 3);
    }

    #[test]
    #[serial]
    fn wipe_all_vault_data_clears_everything() {
        init_test_db();
        let hdr = dummy_header();
        put_vault("v-w1", b"p", "active", &hdr, 10_000).unwrap();
        put_vault("v-w2", b"p", "active", &hdr, 20_000).unwrap();

        let deleted = wipe_all_vault_data().unwrap();
        assert!(deleted >= 2);
        assert!(list_all_vault_ids().unwrap().is_empty());
    }

    #[test]
    #[serial]
    fn find_vault_sats_for_transfer_returns_smallest_sufficient() {
        init_test_db();
        let hdr = dummy_header();
        put_vault("v-fs1", b"p", "active", &hdr, 50_000).unwrap();
        put_vault("v-fs2", b"p", "active", &hdr, 100_000).unwrap();

        let sats = find_vault_sats_for_transfer(60_000).unwrap().unwrap();
        assert_eq!(sats, 100_000);
    }

    #[test]
    #[serial]
    fn find_vault_sats_for_transfer_returns_none_when_insufficient() {
        init_test_db();
        let hdr = dummy_header();
        put_vault("v-fs3", b"p", "active", &hdr, 10_000).unwrap();

        assert!(find_vault_sats_for_transfer(50_000).unwrap().is_none());
    }

    #[test]
    #[serial]
    fn get_oldest_active_vault_for_amount_returns_full_record() {
        init_test_db();
        let hdr = dummy_header();
        put_vault("v-oa", b"proto-data", "active", &hdr, 75_000).unwrap();

        let (vault_id, proto, state, entry_hdr) =
            get_oldest_active_vault_for_amount(50_000).unwrap().unwrap();
        assert_eq!(vault_id, "v-oa");
        assert_eq!(proto, b"proto-data");
        assert_eq!(state, "active");
        assert_eq!(entry_hdr.len(), 80);
    }

    #[test]
    #[serial]
    fn put_vault_upserts_on_conflict() {
        init_test_db();
        let hdr = dummy_header();
        put_vault("v-up", b"old-proto", "active", &hdr, 10_000).unwrap();
        put_vault("v-up", b"new-proto", "limbo", &hdr, 20_000).unwrap();

        let (proto, state, _, sats) = get_vault("v-up").unwrap().unwrap();
        assert_eq!(proto, b"new-proto");
        assert_eq!(state, "limbo");
        assert_eq!(sats, 20_000);
    }

    #[test]
    #[serial]
    fn find_oldest_active_vault_returns_none_when_empty() {
        init_test_db();
        assert!(find_oldest_active_vault(1).unwrap().is_none());
    }

    #[test]
    #[serial]
    fn list_vaults_by_amount_respects_min_sats() {
        init_test_db();
        let hdr = dummy_header();
        put_vault("v-min1", b"p", "active", &hdr, 10_000).unwrap();
        put_vault("v-min2", b"p", "active", &hdr, 50_000).unwrap();
        put_vault("v-min3", b"p", "limbo", &hdr, 100_000).unwrap();

        let ids = list_vaults_by_amount(50_000).unwrap();
        assert_eq!(ids.len(), 2);
        assert!(ids.contains(&"v-min2".to_string()));
        assert!(ids.contains(&"v-min3".to_string()));
    }
}
