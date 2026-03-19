// SPDX-License-Identifier: MIT OR Apache-2.0
//! Bilateral session persistence.

use anyhow::{anyhow, Result};
use log::debug;
use rusqlite::params;

use super::get_connection;
use super::types::BilateralSessionRecord;
use crate::util::deterministic_time::tick;
use crate::util::text_id::encode_base32_crockford;

/// Get a database connection Arc
fn get_db_connection() -> Result<std::sync::Arc<std::sync::Mutex<rusqlite::Connection>>> {
    get_connection()
}

/// Store or update a bilateral session
pub fn store_bilateral_session(session: &BilateralSessionRecord) -> Result<()> {
    // Validate inputs
    if session.commitment_hash.is_empty() || session.commitment_hash.len() > 32 {
        return Err(anyhow!(
            "Invalid commitment_hash length: {} bytes (must be 1-32)",
            session.commitment_hash.len()
        ));
    }
    if session.counterparty_device_id.len() != 32 {
        return Err(anyhow!(
            "Invalid counterparty_device_id length: {} bytes (must be exactly 32)",
            session.counterparty_device_id.len()
        ));
    }
    if session.operation_bytes.is_empty() {
        return Err(anyhow!("Invalid operation_bytes: cannot be empty"));
    }
    if ![
        "prepare",
        "accept",
        "commit",
        "preparing",
        "prepared",
        "pending_user_action",
        "accepted",
        "rejected",
        "confirm_pending",
        "committed",
        "failed",
    ]
    .contains(&session.phase.as_str())
    {
        return Err(anyhow!(
            "Invalid phase: '{}' (must be one of prepare/accept/commit/preparing/prepared/pending_user_action/accepted/rejected/confirm_pending/committed/failed)",
            session.phase
        ));
    }

    let binding = get_db_connection()?;
    let conn = binding
        .lock()
        .map_err(|_| anyhow!("Database lock poisoned - concurrent access error"))?;
    let now = tick();

    conn.execute("BEGIN IMMEDIATE", [])?;
    let result = conn.execute(
        "INSERT INTO bilateral_sessions(
            commitment_hash, counterparty_device_id, counterparty_genesis_hash, operation_bytes, phase,
            local_signature, counterparty_signature, created_at_step,
                sender_ble_address, updated_at)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
         ON CONFLICT(commitment_hash) DO UPDATE SET
            phase = excluded.phase,
            local_signature = excluded.local_signature,
            counterparty_signature = excluded.counterparty_signature,
            counterparty_genesis_hash = excluded.counterparty_genesis_hash,
            sender_ble_address = excluded.sender_ble_address,
            updated_at = excluded.updated_at",
        params![
            &session.commitment_hash,
            &session.counterparty_device_id,
            &session.counterparty_genesis_hash,
            &session.operation_bytes,
            &session.phase,
            &session.local_signature,
            &session.counterparty_signature,
            session.created_at_step as i64,
            &session.sender_ble_address,
            now as i64,
        ],
    );
    match result {
        Ok(_) => {
            conn.execute("COMMIT", [])?;
        }
        Err(e) => {
            let _ = conn.execute("ROLLBACK", []);
            return Err(anyhow!("Failed to store bilateral session: {}", e));
        }
    }

    debug!(
        "[CLIENT_DB] Stored bilateral session: phase={} commitment={}",
        session.phase,
        encode_base32_crockford(&session.commitment_hash[..8.min(session.commitment_hash.len())])
    );
    Ok(())
}

/// Get all bilateral sessions (for restoration on startup)
pub fn get_all_bilateral_sessions() -> Result<Vec<BilateralSessionRecord>> {
    let binding = get_db_connection()?;
    let conn = binding
        .lock()
        .map_err(|_| anyhow!("Database lock poisoned - concurrent access error"))?;
    let mut stmt = conn.prepare(
        "SELECT commitment_hash, counterparty_device_id, operation_bytes, phase,
               counterparty_genesis_hash, local_signature, counterparty_signature, created_at_step,
               sender_ble_address
         FROM bilateral_sessions
           ORDER BY created_at_step DESC",
    )?;

    let iter = stmt.query_map([], |row| {
        Ok(BilateralSessionRecord {
            commitment_hash: row.get(0)?,
            counterparty_device_id: row.get(1)?,
            operation_bytes: row.get(2)?,
            phase: row.get(3)?,
            counterparty_genesis_hash: row.get(4)?,
            local_signature: row.get(5)?,
            counterparty_signature: row.get(6)?,
            created_at_step: row.get::<_, i64>(7)? as u64,
            sender_ble_address: row.get(8)?,
        })
    })?;

    let mut sessions = Vec::new();
    for s in iter {
        sessions.push(s?);
    }
    Ok(sessions)
}

/// Delete a bilateral session by commitment hash
pub fn delete_bilateral_session(commitment_hash: &[u8]) -> Result<()> {
    let binding = get_db_connection()?;
    let conn = binding
        .lock()
        .map_err(|_| anyhow!("Database lock poisoned - concurrent access error"))?;
    conn.execute(
        "DELETE FROM bilateral_sessions WHERE commitment_hash = ?1",
        params![commitment_hash],
    )?;
    Ok(())
}

/// Clean up expired bilateral sessions
pub fn cleanup_expired_bilateral_sessions(current_ticks: u64) -> Result<usize> {
    // Clockless protocol: bilateral sessions do not expire by any local notion of duration.
    // Cleanup must be driven by explicit state transitions, not by a ticking counter.
    let _ = current_ticks;
    Ok(0)
}
