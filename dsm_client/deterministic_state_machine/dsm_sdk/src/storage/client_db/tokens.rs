// SPDX-License-Identifier: MIT OR Apache-2.0
//! Non-ERA token balance persistence.

use anyhow::Result;
use rusqlite::params;

use super::get_connection;
use crate::util::deterministic_time::tick;

/// Upsert a non-ERA token balance for a device.
/// Uses INSERT OR REPLACE on the composite primary key (device_id, token_id).
pub fn upsert_token_balance(
    device_id: &str,
    token_id: &str,
    available: u64,
    locked: u64,
) -> Result<()> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    let now = tick();
    conn.execute(
        "INSERT OR REPLACE INTO token_balances (device_id, token_id, available, locked, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            device_id,
            token_id,
            available as i64,
            locked as i64,
            now as i64
        ],
    )?;
    log::info!(
        "[token_balances] upsert: device={} token={} available={} locked={}",
        &device_id[..20.min(device_id.len())],
        token_id,
        available,
        locked,
    );
    Ok(())
}

/// Get all non-ERA token balances for a device.
/// Returns Vec of (token_id, available, locked).
pub fn get_token_balances(device_id: &str) -> Result<Vec<(String, u64, u64)>> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    let mut stmt = conn
        .prepare("SELECT token_id, available, locked FROM token_balances WHERE device_id = ?1")?;
    let rows = stmt
        .query_map(params![device_id], |row| {
            let token_id: String = row.get(0)?;
            let available: i64 = row.get(1)?;
            let locked: i64 = row.get(2)?;
            Ok((token_id, available as u64, locked as u64))
        })?
        .filter_map(|r| r.ok())
        .collect();
    Ok(rows)
}

/// Get a single token balance for a device.
/// Returns (available, locked) if found.
pub fn get_token_balance(device_id: &str, token_id: &str) -> Result<Option<(u64, u64)>> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    let result = conn.query_row(
        "SELECT available, locked FROM token_balances WHERE device_id = ?1 AND token_id = ?2",
        params![device_id, token_id],
        |row| {
            let available: i64 = row.get(0)?;
            let locked: i64 = row.get(1)?;
            Ok((available as u64, locked as u64))
        },
    );
    match result {
        Ok(v) => Ok(Some(v)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// Move `amount` from available to locked for the given token.
/// Fails if available < amount (prevents over-lock / double-spend).
/// Used by fractional exit to hold dBTC while sweep is in-flight.
pub fn lock_dbtc_for_exit(device_id: &str, token_id: &str, amount: u64) -> Result<()> {
    // Explicit boundary check before DB cast
    let safe_amount = i64::try_from(amount)
        .map_err(|_| anyhow::anyhow!("Amount exceeds maximum safely locking threshold"))?;

    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    let rows = conn.execute(
        "UPDATE token_balances SET available = available - ?1, locked = locked + ?1
         WHERE device_id = ?2 AND token_id = ?3 AND available >= ?1",
        params![safe_amount, device_id, token_id],
    )?;
    if rows == 0 {
        return Err(anyhow::anyhow!(
            "insufficient available balance to lock {amount} sats"
        ));
    }
    log::info!(
        "[token_balances] locked {amount} sats for exit: device={} token={token_id}",
        &device_id[..20.min(device_id.len())]
    );
    Ok(())
}

/// After successful burn, remove the locked amount (it has been burned on-chain).
pub fn finalize_exit_burn(device_id: &str, token_id: &str, amount: u64) -> Result<()> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    conn.execute(
        "UPDATE token_balances SET locked = locked - ?1
         WHERE device_id = ?2 AND token_id = ?3 AND locked >= ?1",
        params![amount as i64, device_id, token_id],
    )?;
    log::info!(
        "[token_balances] finalized burn of {amount} sats: device={} token={token_id}",
        &device_id[..20.min(device_id.len())]
    );
    Ok(())
}

/// Release locked amount back to available (sweep failed or crash recovery rollback).
pub fn release_locked_to_available(device_id: &str, token_id: &str, amount: u64) -> Result<()> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    conn.execute(
        "UPDATE token_balances SET available = available + ?1, locked = locked - ?1
         WHERE device_id = ?2 AND token_id = ?3 AND locked >= ?1",
        params![amount as i64, device_id, token_id],
    )?;
    log::info!(
        "[token_balances] released {amount} sats back to available: device={} token={token_id}",
        &device_id[..20.min(device_id.len())]
    );
    Ok(())
}
