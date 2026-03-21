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
