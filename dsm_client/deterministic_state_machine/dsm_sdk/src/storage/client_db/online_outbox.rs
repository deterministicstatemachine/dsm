// SPDX-License-Identifier: MIT OR Apache-2.0
//! Persisted sender-side online transition gating.

use anyhow::{anyhow, Result};
use rusqlite::params;

use super::get_connection;
use super::types::PendingOnlineOutboxRecord;
use crate::util::deterministic_time::tick;

pub fn store_pending_online_outbox(
    counterparty_device_id: &[u8],
    message_id: &str,
    parent_tip: &[u8],
    next_tip: &[u8],
) -> Result<()> {
    if counterparty_device_id.len() != 32 {
        return Err(anyhow!("Invalid counterparty_device_id length"));
    }
    if parent_tip.len() != 32 {
        return Err(anyhow!("Invalid parent_tip length"));
    }
    if next_tip.len() != 32 {
        return Err(anyhow!("Invalid next_tip length"));
    }
    if message_id.trim().is_empty() {
        return Err(anyhow!("message_id cannot be empty"));
    }

    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|poisoned| {
        log::warn!("DB lock poisoned, recovering");
        poisoned.into_inner()
    });

    conn.execute(
        "INSERT INTO pending_online_outbox (
            counterparty_device_id, message_id, parent_tip, next_tip, created_at
         ) VALUES (?1, ?2, ?3, ?4, ?5)
         ON CONFLICT(counterparty_device_id) DO UPDATE SET
            message_id = excluded.message_id,
            parent_tip = excluded.parent_tip,
            next_tip = excluded.next_tip,
            created_at = excluded.created_at",
        params![
            counterparty_device_id,
            message_id,
            parent_tip,
            next_tip,
            tick() as i64,
        ],
    )?;

    Ok(())
}

/// Atomically persist a sender-side online gate for a delivered transition.
///
/// This records the outstanding b0x `message_id` and the sender's local
/// successor tip in one transaction, so the next send can fail closed after
/// app restarts until the recipient has ACKed the previous step.
pub fn record_pending_online_transition(
    counterparty_device_id: &[u8],
    message_id: &str,
    parent_tip: &[u8],
    next_tip: &[u8],
) -> Result<()> {
    if counterparty_device_id.len() != 32 {
        return Err(anyhow!("Invalid counterparty_device_id length"));
    }
    if parent_tip.len() != 32 {
        return Err(anyhow!("Invalid parent_tip length"));
    }
    if next_tip.len() != 32 {
        return Err(anyhow!("Invalid next_tip length"));
    }
    if message_id.trim().is_empty() {
        return Err(anyhow!("message_id cannot be empty"));
    }

    let binding = get_connection()?;
    let mut conn = binding.lock().unwrap_or_else(|poisoned| {
        log::warn!("DB lock poisoned, recovering");
        poisoned.into_inner()
    });

    let tx = conn.transaction()?;
    let updated = tx.execute(
        "UPDATE contacts
            SET local_bilateral_chain_tip = ?1
          WHERE device_id = ?2",
        params![next_tip, counterparty_device_id],
    )?;
    if updated == 0 {
        return Err(anyhow!(
            "Cannot persist pending online transition for unknown contact"
        ));
    }

    tx.execute(
        "INSERT INTO pending_online_outbox (
            counterparty_device_id, message_id, parent_tip, next_tip, created_at
         ) VALUES (?1, ?2, ?3, ?4, ?5)
         ON CONFLICT(counterparty_device_id) DO UPDATE SET
            message_id = excluded.message_id,
            parent_tip = excluded.parent_tip,
            next_tip = excluded.next_tip,
            created_at = excluded.created_at",
        params![
            counterparty_device_id,
            message_id,
            parent_tip,
            next_tip,
            tick() as i64,
        ],
    )?;

    tx.commit()?;
    Ok(())
}

pub fn get_pending_online_outbox(
    counterparty_device_id: &[u8],
) -> Result<Option<PendingOnlineOutboxRecord>> {
    if counterparty_device_id.len() != 32 {
        return Err(anyhow!("Invalid counterparty_device_id length"));
    }

    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|poisoned| {
        log::warn!("DB lock poisoned, recovering");
        poisoned.into_inner()
    });

    let row = conn.query_row(
        "SELECT counterparty_device_id, message_id, parent_tip, next_tip, created_at
           FROM pending_online_outbox
          WHERE counterparty_device_id = ?1",
        params![counterparty_device_id],
        |row| {
            Ok(PendingOnlineOutboxRecord {
                counterparty_device_id: row.get(0)?,
                message_id: row.get(1)?,
                parent_tip: row.get(2)?,
                next_tip: row.get(3)?,
                created_at: row.get::<_, i64>(4)? as u64,
            })
        },
    );

    match row {
        Ok(record) => Ok(Some(record)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(anyhow!("pending_online_outbox query failed: {e}")),
    }
}

/// Return all pending outbox entries so callers can sweep stale gates.
pub fn get_all_pending_online_outbox() -> Result<Vec<PendingOnlineOutboxRecord>> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|poisoned| {
        log::warn!("DB lock poisoned, recovering");
        poisoned.into_inner()
    });

    let mut stmt = conn.prepare(
        "SELECT counterparty_device_id, message_id, parent_tip, next_tip, created_at
           FROM pending_online_outbox",
    )?;

    let rows = stmt.query_map([], |row| {
        Ok(PendingOnlineOutboxRecord {
            counterparty_device_id: row.get(0)?,
            message_id: row.get(1)?,
            parent_tip: row.get(2)?,
            next_tip: row.get(3)?,
            created_at: row.get::<_, i64>(4)? as u64,
        })
    })?;

    let mut records = Vec::new();
    for row in rows {
        records.push(row?);
    }
    Ok(records)
}

pub fn clear_pending_online_outbox(counterparty_device_id: &[u8]) -> Result<()> {
    if counterparty_device_id.len() != 32 {
        return Err(anyhow!("Invalid counterparty_device_id length"));
    }

    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|poisoned| {
        log::warn!("DB lock poisoned, recovering");
        poisoned.into_inner()
    });

    conn.execute(
        "DELETE FROM pending_online_outbox WHERE counterparty_device_id = ?1",
        params![counterparty_device_id],
    )?;

    Ok(())
}
