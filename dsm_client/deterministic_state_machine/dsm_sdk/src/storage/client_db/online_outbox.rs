// SPDX-License-Identifier: MIT OR Apache-2.0
//! Persisted sender-side online transition gating.

use anyhow::{anyhow, Result};
use rusqlite::{params, Connection, OptionalExtension};

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
    if parent_tip == next_tip {
        return Err(anyhow!(
            "Pending online outbox requires next_tip != parent_tip"
        ));
    }

    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|poisoned| {
        log::warn!("DB lock poisoned, recovering");
        poisoned.into_inner()
    });

    let existing: Option<(String, Vec<u8>, Vec<u8>)> = conn
        .query_row(
            "SELECT message_id, parent_tip, next_tip
               FROM pending_online_outbox
              WHERE counterparty_device_id = ?1",
            params![counterparty_device_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    if let Some((existing_message_id, existing_parent_tip, existing_next_tip)) = existing {
        if existing_message_id == message_id
            && existing_parent_tip == parent_tip
            && existing_next_tip == next_tip
        {
            return Ok(());
        }
        return Err(anyhow!(
            "Pending online outbox already contains a different gate for this counterparty"
        ));
    }

    conn.execute(
        "INSERT INTO pending_online_outbox (
            counterparty_device_id, message_id, parent_tip, next_tip, created_at
         ) VALUES (?1, ?2, ?3, ?4, ?5)",
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
    if parent_tip == next_tip {
        return Err(anyhow!(
            "Pending online transition requires next_tip different from parent_tip"
        ));
    }

    let binding = get_connection()?;
    let mut conn = binding.lock().unwrap_or_else(|poisoned| {
        log::warn!("DB lock poisoned, recovering");
        poisoned.into_inner()
    });

    let tx = conn.transaction()?;
    record_pending_online_transition_with_conn(
        &tx,
        counterparty_device_id,
        message_id,
        parent_tip,
        next_tip,
    )?;
    tx.commit()?;
    Ok(())
}

/// Same gate write, INSIDE a caller-owned transaction.
///
/// §16.6 defect zero: the gate must be committed together with the canonical
/// advance, the proposal, the pending EK head, and the outbox row — one
/// transaction, before anything is deliverable. This variant therefore takes
/// `&Connection` (a `&Transaction` derefs to one) and never calls
/// `get_connection()`: the advance already holds the single global connection
/// mutex, so opening another here would deadlock.
///
/// Validation and semantics are identical to the self-opening wrapper above;
/// only the transaction ownership differs.
pub fn record_pending_online_transition_with_conn(
    tx: &Connection,
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
    if parent_tip == next_tip {
        return Err(anyhow!(
            "Pending online transition requires next_tip different from parent_tip"
        ));
    }

    let existing_gate: Option<(String, Vec<u8>, Vec<u8>)> = tx
        .query_row(
            "SELECT message_id, parent_tip, next_tip
               FROM pending_online_outbox
              WHERE counterparty_device_id = ?1",
            params![counterparty_device_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    let existing_gate_is_identical = matches!(
        existing_gate.as_ref(),
        Some((existing_message_id, existing_parent_tip, existing_next_tip))
            if existing_message_id == message_id
                && existing_parent_tip == parent_tip
                && existing_next_tip == next_tip
    );
    if existing_gate.is_some() && !existing_gate_is_identical {
        return Err(anyhow!(
            "Pending online transition already exists with a different gate for this counterparty"
        ));
    }

    let contact_row: Option<(Option<Vec<u8>>, Option<Vec<u8>>)> = tx
        .query_row(
            "SELECT chain_tip, local_bilateral_chain_tip
               FROM contacts
              WHERE device_id = ?1",
            params![counterparty_device_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let (current_chain_tip, current_local_tip) = match contact_row {
        Some(row) => row,
        None => {
            return Err(anyhow!(
                "Cannot persist pending online transition for unknown contact"
            ));
        }
    };

    let stored_parent = current_chain_tip.unwrap_or_else(|| vec![0u8; 32]);
    if stored_parent.len() != 32 {
        return Err(anyhow!(
            "Stored finalized chain tip has invalid length {}",
            stored_parent.len()
        ));
    }
    if stored_parent != parent_tip {
        return Err(anyhow!(
            "Pending online transition parent does not match finalized canonical chain tip"
        ));
    }

    if let Some(local_tip) = current_local_tip {
        if local_tip.len() != 32 {
            return Err(anyhow!(
                "Stored local bilateral chain tip has invalid length {}",
                local_tip.len()
            ));
        }
        if local_tip != parent_tip && !(existing_gate_is_identical && local_tip == next_tip) {
            return Err(anyhow!(
                "Pending online transition would overwrite a divergent local bilateral chain tip"
            ));
        }
    }

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

    if existing_gate.is_none() {
        tx.execute(
            "INSERT INTO pending_online_outbox (
                counterparty_device_id, message_id, parent_tip, next_tip, created_at
             ) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                counterparty_device_id,
                message_id,
                parent_tip,
                next_tip,
                tick() as i64,
            ],
        )?;
    }

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

/// Exact-match gate delete: only clears the gate if counterparty, parent_tip,
/// and next_tip ALL match the stored row. Prevents TOCTOU races where a BLE
/// cleanup path could accidentally delete a freshly-created gate from a
/// concurrent online send.
///
/// Returns `Ok(true)` if the exact row was deleted, `Ok(false)` if no match.
/// Exact-match gate delete INSIDE a caller-owned transaction (§16.6 defect 1).
pub fn clear_pending_online_outbox_if_matches_with_conn(
    conn: &Connection,
    counterparty_device_id: &[u8],
    expected_parent_tip: &[u8],
    expected_next_tip: &[u8],
) -> Result<bool> {
    if counterparty_device_id.len() != 32
        || expected_parent_tip.len() != 32
        || expected_next_tip.len() != 32
    {
        return Err(anyhow!("Invalid identifier length for gate clear"));
    }
    let rows = conn.execute(
        "DELETE FROM pending_online_outbox WHERE counterparty_device_id = ?1 AND parent_tip = ?2 AND next_tip = ?3",
        params![counterparty_device_id, expected_parent_tip, expected_next_tip],
    )?;
    Ok(rows > 0)
}

/// The §5.4 stale-gate decision. Total, so a caller cannot drop the answer.
///
/// This exists because the previous shape returned `Result<bool>` and the BLE
/// handler consumed it with `if let Err(..)`. `Ok(false)` — "the row you read is
/// no longer the row in the table" — read as success, and the handler went on to
/// clear the in-memory modal lock and admit the offline transfer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StaleGateOutcome {
    /// No gate row for this counterparty. Nothing blocks the offline transfer.
    NoGate,
    /// The gate was stale and its exact row was deleted. The in-memory lock may
    /// be cleared.
    Cleared,
    /// The chain has not moved past the gate's `parent_tip`: a prior online
    /// transfer is genuinely still awaiting catch-up.
    StillPending,
    /// The row changed between the read and the delete inside the transaction.
    /// Unreachable while the read and the delete share one transaction, which is
    /// the point — it is kept, and refuses, so that a future refactor which
    /// splits them fails closed instead of silently admitting.
    Raced,
}

impl StaleGateOutcome {
    /// Whether the offline transfer may proceed. Only a gate that is absent or
    /// provably cleared admits; every ambiguous answer refuses.
    pub fn admits_offline(&self) -> bool {
        matches!(self, StaleGateOutcome::NoGate | StaleGateOutcome::Cleared)
    }
}

/// Read the gate, decide whether it is stale, and delete it — atomically.
///
/// The read, the staleness decision and the exact-match delete all run inside
/// ONE transaction on ONE connection. Previously the caller did the three steps
/// as separate calls, releasing the global connection mutex between them, so a
/// concurrent online send could settle the old gate and arm a new one in the
/// window; the exact-match delete then matched nothing, the newer gate survived
/// unread, and the caller cleared the in-memory lock anyway.
///
/// `sender_reported_tip` is the counterparty's self-reported chain tip from the
/// prepare request. The gate is stale iff either that tip or our persisted view
/// of it has moved off the gate's `parent_tip`.
///
/// Tips are parsed strictly: a stored row whose `parent_tip` or `next_tip` is not
/// exactly 32 bytes is an error, not a zero-filled default. Substituting
/// `[0u8; 32]` guaranteed a non-matching DELETE, which left the persisted gate in
/// place while the caller cleared the in-memory lock — the worst of both.
pub fn clear_stale_pending_online_gate(
    counterparty_device_id: &[u8],
    sender_reported_tip: Option<[u8; 32]>,
) -> Result<StaleGateOutcome> {
    if counterparty_device_id.len() != 32 {
        return Err(anyhow!("Invalid counterparty_device_id length"));
    }

    let binding = get_connection()?;
    let mut conn = binding.lock().unwrap_or_else(|poisoned| {
        log::warn!("DB lock poisoned, recovering");
        poisoned.into_inner()
    });
    let tx = conn.transaction()?;

    let pending: Option<PendingOnlineOutboxRecord> = tx
        .query_row(
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
        )
        .optional()?;

    let Some(pending) = pending else {
        return Ok(StaleGateOutcome::NoGate);
    };

    // Strict, like the HTTP sibling in handlers/bilateral_routes.rs.
    let gate_parent: [u8; 32] = pending
        .parent_tip
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("persisted online gate has a malformed parent_tip"))?;
    let gate_next: [u8; 32] = pending
        .next_tip
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("persisted online gate has a malformed next_tip"))?;

    // Our persisted view of the counterparty's tip, read in the SAME transaction.
    let persisted_tip: Option<[u8; 32]> = tx
        .query_row(
            "SELECT chain_tip FROM contacts WHERE device_id = ?1",
            params![counterparty_device_id],
            |row| row.get::<_, Option<Vec<u8>>>(0),
        )
        .optional()?
        .flatten()
        .and_then(|v| v.as_slice().try_into().ok());

    // The gate's parent_tip was the tip BEFORE the gated send. If the current tip
    // has moved off it, the chain advanced and the gate is stale.
    let already_advanced = (sender_reported_tip.is_some()
        && sender_reported_tip != Some(gate_parent))
        || (persisted_tip.is_some() && persisted_tip != Some(gate_parent));

    if !already_advanced {
        return Ok(StaleGateOutcome::StillPending);
    }

    let deleted = clear_pending_online_outbox_if_matches_with_conn(
        &tx,
        counterparty_device_id,
        &gate_parent,
        &gate_next,
    )?;
    if !deleted {
        // Cannot happen inside this transaction — we read the row here. Refuse
        // rather than assume; see StaleGateOutcome::Raced.
        return Ok(StaleGateOutcome::Raced);
    }

    tx.commit()?;
    Ok(StaleGateOutcome::Cleared)
}

pub fn clear_pending_online_outbox_if_matches(
    counterparty_device_id: &[u8],
    expected_parent_tip: &[u8],
    expected_next_tip: &[u8],
) -> Result<bool> {
    if counterparty_device_id.len() != 32 {
        return Err(anyhow!("Invalid counterparty_device_id length"));
    }
    if expected_parent_tip.len() != 32 {
        return Err(anyhow!("Invalid expected_parent_tip length"));
    }
    if expected_next_tip.len() != 32 {
        return Err(anyhow!("Invalid expected_next_tip length"));
    }

    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|poisoned| {
        log::warn!("DB lock poisoned, recovering");
        poisoned.into_inner()
    });

    let rows = conn.execute(
        "DELETE FROM pending_online_outbox WHERE counterparty_device_id = ?1 AND parent_tip = ?2 AND next_tip = ?3",
        params![counterparty_device_id, expected_parent_tip, expected_next_tip],
    )?;

    Ok(rows > 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn store_rejects_short_counterparty_device_id() {
        let err =
            store_pending_online_outbox(&[0u8; 16], "msg-1", &[1u8; 32], &[2u8; 32]).unwrap_err();
        assert!(err.to_string().contains("counterparty_device_id"));
    }

    #[test]
    fn store_rejects_short_parent_tip() {
        let err =
            store_pending_online_outbox(&[0u8; 32], "msg-1", &[1u8; 16], &[2u8; 32]).unwrap_err();
        assert!(err.to_string().contains("parent_tip"));
    }

    #[test]
    fn store_rejects_short_next_tip() {
        let err =
            store_pending_online_outbox(&[0u8; 32], "msg-1", &[1u8; 32], &[2u8; 16]).unwrap_err();
        assert!(err.to_string().contains("next_tip"));
    }

    #[test]
    fn store_rejects_empty_message_id() {
        let err =
            store_pending_online_outbox(&[0u8; 32], "  ", &[1u8; 32], &[2u8; 32]).unwrap_err();
        assert!(err.to_string().contains("message_id"));
    }

    #[test]
    fn store_rejects_identical_parent_and_next_tip() {
        let tip = [0xAAu8; 32];
        let err = store_pending_online_outbox(&[0u8; 32], "msg-1", &tip, &tip).unwrap_err();
        assert!(err.to_string().contains("next_tip != parent_tip"));
    }

    #[test]
    fn record_rejects_short_counterparty_device_id() {
        let err = record_pending_online_transition(&[0u8; 16], "msg-1", &[1u8; 32], &[2u8; 32])
            .unwrap_err();
        assert!(err.to_string().contains("counterparty_device_id"));
    }

    #[test]
    fn record_rejects_empty_message_id() {
        let err =
            record_pending_online_transition(&[0u8; 32], " ", &[1u8; 32], &[2u8; 32]).unwrap_err();
        assert!(err.to_string().contains("message_id"));
    }

    #[test]
    fn record_rejects_identical_tips() {
        let tip = [0xBBu8; 32];
        let err = record_pending_online_transition(&[0u8; 32], "msg-1", &tip, &tip).unwrap_err();
        assert!(err
            .to_string()
            .contains("next_tip different from parent_tip"));
    }

    #[test]
    fn get_pending_rejects_wrong_device_id_length() {
        let err = get_pending_online_outbox(&[0u8; 10]).unwrap_err();
        assert!(err.to_string().contains("counterparty_device_id"));
    }

    #[test]
    fn clear_pending_rejects_wrong_device_id_length() {
        let err = clear_pending_online_outbox(&[0u8; 10]).unwrap_err();
        assert!(err.to_string().contains("counterparty_device_id"));
    }

    #[test]
    fn record_rejects_short_parent_tip() {
        let err = record_pending_online_transition(&[0u8; 32], "msg-1", &[1u8; 16], &[2u8; 32])
            .unwrap_err();
        assert!(err.to_string().contains("parent_tip"));
    }

    #[test]
    fn record_rejects_short_next_tip() {
        let err = record_pending_online_transition(&[0u8; 32], "msg-1", &[1u8; 32], &[2u8; 16])
            .unwrap_err();
        assert!(err.to_string().contains("next_tip"));
    }

    use serial_test::serial;

    fn init_test_db() {
        unsafe { std::env::set_var("DSM_SDK_TEST_MODE", "1") };
        crate::storage::client_db::reset_database_for_tests();
        crate::storage::client_db::init_database().expect("init db");
    }

    #[test]
    #[serial]
    fn store_and_get_pending_online_outbox_roundtrip() {
        init_test_db();
        let cp = [0xAAu8; 32];
        let parent = [0x11u8; 32];
        let next = [0x22u8; 32];
        store_pending_online_outbox(&cp, "msg-rt", &parent, &next).unwrap();

        let loaded = get_pending_online_outbox(&cp).unwrap().unwrap();
        assert_eq!(loaded.message_id, "msg-rt");
        assert_eq!(loaded.parent_tip, parent);
        assert_eq!(loaded.next_tip, next);
    }

    #[test]
    #[serial]
    fn store_pending_idempotent_for_identical_gate() {
        init_test_db();
        let cp = [0xBBu8; 32];
        let parent = [0x33u8; 32];
        let next = [0x44u8; 32];
        store_pending_online_outbox(&cp, "msg-idem", &parent, &next).unwrap();
        store_pending_online_outbox(&cp, "msg-idem", &parent, &next).unwrap();

        let loaded = get_pending_online_outbox(&cp).unwrap().unwrap();
        assert_eq!(loaded.message_id, "msg-idem");
    }

    #[test]
    #[serial]
    fn store_pending_rejects_different_gate_for_same_counterparty() {
        init_test_db();
        let cp = [0xCCu8; 32];
        store_pending_online_outbox(&cp, "msg-1", &[0x11u8; 32], &[0x22u8; 32]).unwrap();
        let err =
            store_pending_online_outbox(&cp, "msg-2", &[0x33u8; 32], &[0x44u8; 32]).unwrap_err();
        assert!(err.to_string().contains("different gate"));
    }

    #[test]
    #[serial]
    fn clear_and_verify_pending_online_outbox() {
        init_test_db();
        let cp = [0xDDu8; 32];
        store_pending_online_outbox(&cp, "msg-clr", &[0x55u8; 32], &[0x66u8; 32]).unwrap();
        clear_pending_online_outbox(&cp).unwrap();

        assert!(get_pending_online_outbox(&cp).unwrap().is_none());
    }

    #[test]
    #[serial]
    fn get_all_pending_online_outbox_returns_all() {
        init_test_db();
        let cp1 = [0xE1u8; 32];
        let cp2 = [0xE2u8; 32];
        store_pending_online_outbox(&cp1, "msg-a", &[0x01u8; 32], &[0x02u8; 32]).unwrap();
        store_pending_online_outbox(&cp2, "msg-b", &[0x03u8; 32], &[0x04u8; 32]).unwrap();

        let all = get_all_pending_online_outbox().unwrap();
        assert_eq!(all.len(), 2);
    }

    #[test]
    #[serial]
    fn get_pending_online_outbox_returns_none_when_empty() {
        init_test_db();
        assert!(get_pending_online_outbox(&[0xFFu8; 32]).unwrap().is_none());
    }
}
