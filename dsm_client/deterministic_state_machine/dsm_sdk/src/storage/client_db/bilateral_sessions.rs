// SPDX-License-Identifier: MIT OR Apache-2.0
//! Bilateral session persistence.

use anyhow::{anyhow, Result};
use log::debug;
use rusqlite::{params, OptionalExtension};

use super::get_connection;
use super::types::BilateralSessionRecord;
use crate::util::text_id::encode_base32_crockford;

/// Get a database connection Arc
fn get_db_connection() -> Result<std::sync::Arc<std::sync::Mutex<rusqlite::Connection>>> {
    get_connection()
}

const SESSION_COLUMNS: &str = "commitment_hash, counterparty_device_id, operation_bytes, phase,
    counterparty_genesis_hash, local_signature, counterparty_signature, sender_ble_address,
    stitched_receipt_bytes, counter_signed_receipt, parent_tip, receiver_challenge,
    sent_child_root, anchor_leaf_key, anchor_leaf_value, spend_anchor_bundle, spend_asset,
    spend_amount";

fn session_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<BilateralSessionRecord> {
    Ok(BilateralSessionRecord {
        commitment_hash: row.get(0)?,
        counterparty_device_id: row.get(1)?,
        operation_bytes: row.get(2)?,
        phase: row.get(3)?,
        counterparty_genesis_hash: row.get(4)?,
        local_signature: row.get(5)?,
        counterparty_signature: row.get(6)?,
        sender_ble_address: row.get(7)?,
        stitched_receipt_bytes: row.get(8)?,
        counter_signed_receipt: row.get(9)?,
        parent_tip: row.get(10)?,
        receiver_challenge: row.get(11)?,
        sent_child_root: row.get(12)?,
        anchor_leaf_key: row.get(13)?,
        anchor_leaf_value: row.get(14)?,
        spend_anchor_bundle: row.get(15)?,
        spend_asset: row.get(16)?,
        spend_amount: row.get(17)?,
    })
}

/// Store or update a bilateral session in its own transaction.
pub fn store_bilateral_session(session: &BilateralSessionRecord) -> Result<()> {
    let binding = get_db_connection()?;
    let mut conn = binding
        .lock()
        .map_err(|_| anyhow!("Database lock poisoned - concurrent access error"))?;
    let tx = conn.transaction()?;
    store_bilateral_session_with_conn(&tx, session)?;
    tx.commit()?;
    debug!(
        "[CLIENT_DB] Stored bilateral session: phase={} commitment={}",
        session.phase,
        encode_base32_crockford(&session.commitment_hash[..8.min(session.commitment_hash.len())])
    );
    Ok(())
}

/// Store or update a bilateral session inside `conn`, the transaction the
/// session's step state commits in. A commit input once written is kept: an
/// update that does not carry it leaves it as it was.
pub fn store_bilateral_session_with_conn(
    conn: &rusqlite::Connection,
    session: &BilateralSessionRecord,
) -> Result<()> {
    if session.commitment_hash.len() != 32 {
        return Err(anyhow!(
            "Invalid commitment_hash length: {} bytes (must be exactly 32)",
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
    if let Some(counterparty_genesis_hash) = session.counterparty_genesis_hash.as_ref() {
        if counterparty_genesis_hash.len() != 32 {
            return Err(anyhow!(
                "Invalid counterparty_genesis_hash length: {} bytes (must be exactly 32)",
                counterparty_genesis_hash.len()
            ));
        }
    }
    if ![
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
        return Err(anyhow!("Invalid phase: '{}'", session.phase));
    }
    conn.execute(
        "INSERT INTO bilateral_sessions(
            commitment_hash, counterparty_device_id, operation_bytes, phase,
            counterparty_genesis_hash, local_signature, counterparty_signature, sender_ble_address,
            stitched_receipt_bytes, counter_signed_receipt, parent_tip, receiver_challenge,
            sent_child_root, anchor_leaf_key, anchor_leaf_value, spend_anchor_bundle, spend_asset,
            spend_amount)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18)
         ON CONFLICT(commitment_hash) DO UPDATE SET
            phase = excluded.phase,
            local_signature = excluded.local_signature,
            counterparty_signature = excluded.counterparty_signature,
            counterparty_genesis_hash = excluded.counterparty_genesis_hash,
            sender_ble_address = excluded.sender_ble_address,
            stitched_receipt_bytes = COALESCE(excluded.stitched_receipt_bytes, bilateral_sessions.stitched_receipt_bytes),
            counter_signed_receipt = COALESCE(excluded.counter_signed_receipt, bilateral_sessions.counter_signed_receipt),
            parent_tip = COALESCE(excluded.parent_tip, bilateral_sessions.parent_tip),
            receiver_challenge = COALESCE(excluded.receiver_challenge, bilateral_sessions.receiver_challenge),
            sent_child_root = COALESCE(excluded.sent_child_root, bilateral_sessions.sent_child_root),
            anchor_leaf_key = COALESCE(excluded.anchor_leaf_key, bilateral_sessions.anchor_leaf_key),
            anchor_leaf_value = COALESCE(excluded.anchor_leaf_value, bilateral_sessions.anchor_leaf_value),
            spend_anchor_bundle = COALESCE(excluded.spend_anchor_bundle, bilateral_sessions.spend_anchor_bundle),
            spend_asset = COALESCE(excluded.spend_asset, bilateral_sessions.spend_asset),
            spend_amount = COALESCE(excluded.spend_amount, bilateral_sessions.spend_amount)",
        params![
            &session.commitment_hash,
            &session.counterparty_device_id,
            &session.operation_bytes,
            &session.phase,
            &session.counterparty_genesis_hash,
            &session.local_signature,
            &session.counterparty_signature,
            &session.sender_ble_address,
            &session.stitched_receipt_bytes,
            &session.counter_signed_receipt,
            &session.parent_tip,
            &session.receiver_challenge,
            &session.sent_child_root,
            &session.anchor_leaf_key,
            &session.anchor_leaf_value,
            &session.spend_anchor_bundle,
            &session.spend_asset,
            &session.spend_amount,
        ],
    )?;
    Ok(())
}

/// Get all bilateral sessions (for restoration on startup)
pub fn get_all_bilateral_sessions() -> Result<Vec<BilateralSessionRecord>> {
    let binding = get_db_connection()?;
    let conn = binding
        .lock()
        .map_err(|_| anyhow!("Database lock poisoned - concurrent access error"))?;
    let mut stmt = conn.prepare(&format!(
        "SELECT {SESSION_COLUMNS} FROM bilateral_sessions ORDER BY rowid DESC"
    ))?;
    let rows = stmt.query_map([], session_from_row)?;
    Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
}

/// Get a single bilateral session by commitment hash.
pub fn get_bilateral_session(commitment_hash: &[u8]) -> Result<Option<BilateralSessionRecord>> {
    let binding = get_db_connection()?;
    let conn = binding
        .lock()
        .map_err(|_| anyhow!("Database lock poisoned - concurrent access error"))?;
    conn.query_row(
        &format!("SELECT {SESSION_COLUMNS} FROM bilateral_sessions WHERE commitment_hash = ?1"),
        params![commitment_hash],
        session_from_row,
    )
    .optional()
    .map_err(Into::into)
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

/// Delete a bilateral session inside `conn`, the transaction its step commits in.
pub fn delete_bilateral_session_with_conn(
    conn: &rusqlite::Connection,
    commitment_hash: &[u8],
) -> Result<()> {
    conn.execute(
        "DELETE FROM bilateral_sessions WHERE commitment_hash = ?1",
        params![commitment_hash],
    )?;
    Ok(())
}

/// Update a bilateral session's phase without deleting it.
/// Used to persist terminal phases (failed, rejected) so the frontend
/// poller can read them via bilateral.pending_list.
pub fn update_bilateral_session_phase(commitment_hash: &[u8], phase: &str) -> Result<()> {
    let binding = get_db_connection()?;
    let conn = binding
        .lock()
        .map_err(|_| anyhow!("Database lock poisoned - concurrent access error"))?;
    conn.execute(
        "UPDATE bilateral_sessions SET phase = ?1 WHERE commitment_hash = ?2",
        params![phase, commitment_hash],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    fn init_test_db() {
        crate::economic_fixtures::use_test_storage_dir();
        crate::storage::client_db::reset_database_for_tests();
        crate::storage::client_db::init_database().expect("init db");
    }

    fn make_session(phase: &str) -> BilateralSessionRecord {
        BilateralSessionRecord {
            commitment_hash: vec![0x11; 32],
            counterparty_device_id: vec![0x22; 32],
            counterparty_genesis_hash: Some(vec![0x33; 32]),
            operation_bytes: vec![0x44; 16],
            phase: phase.to_string(),
            local_signature: Some(vec![0x55; 64]),
            counterparty_signature: None,
            sender_ble_address: None,
            stitched_receipt_bytes: None,
            counter_signed_receipt: None,
            parent_tip: None,
            receiver_challenge: None,
            sent_child_root: None,
            anchor_leaf_key: None,
            anchor_leaf_value: None,
            spend_anchor_bundle: None,
            spend_asset: None,
            spend_amount: None,
        }
    }

    #[test]
    fn store_bilateral_session_rejects_empty_commitment_hash() {
        let mut s = make_session("prepared");
        s.commitment_hash = vec![];
        let err = store_bilateral_session(&s).unwrap_err();
        assert!(err.to_string().contains("commitment_hash"));
    }

    #[test]
    fn store_bilateral_session_rejects_oversized_commitment_hash() {
        let mut s = make_session("prepared");
        s.commitment_hash = vec![0; 33];
        let err = store_bilateral_session(&s).unwrap_err();
        assert!(err.to_string().contains("commitment_hash"));
    }

    #[test]
    fn store_bilateral_session_rejects_short_commitment_hash() {
        let mut s = make_session("prepared");
        s.commitment_hash = vec![0; 31];
        let err = store_bilateral_session(&s).unwrap_err();
        assert!(err.to_string().contains("commitment_hash"));
    }

    #[test]
    fn store_bilateral_session_rejects_wrong_counterparty_length() {
        let mut s = make_session("prepared");
        s.counterparty_device_id = vec![0; 16];
        let err = store_bilateral_session(&s).unwrap_err();
        assert!(err.to_string().contains("counterparty_device_id"));
    }

    #[test]
    fn store_bilateral_session_rejects_empty_operation_bytes() {
        let mut s = make_session("prepared");
        s.operation_bytes = vec![];
        let err = store_bilateral_session(&s).unwrap_err();
        assert!(err.to_string().contains("operation_bytes"));
    }

    #[test]
    fn store_bilateral_session_rejects_wrong_counterparty_genesis_length() {
        let mut s = make_session("prepared");
        s.counterparty_genesis_hash = Some(vec![0; 31]);
        let err = store_bilateral_session(&s).unwrap_err();
        assert!(err.to_string().contains("counterparty_genesis_hash"));
    }

    #[test]
    fn store_bilateral_session_rejects_invalid_phase() {
        let s = make_session("invalid_phase");
        let err = store_bilateral_session(&s).unwrap_err();
        assert!(err.to_string().contains("Invalid phase"));
    }

    #[test]
    #[serial]
    fn store_bilateral_session_refuses_the_retired_phase_names() {
        init_test_db();
        for phase in ["prepare", "accept", "commit"] {
            let err = store_bilateral_session(&make_session(phase)).unwrap_err();
            assert!(err.to_string().contains("Invalid phase"), "{phase}: {err}");
        }
    }

    #[test]
    #[serial]
    fn store_bilateral_session_accepts_all_valid_phases() {
        init_test_db();

        let valid_phases = [
            "preparing",
            "prepared",
            "pending_user_action",
            "accepted",
            "rejected",
            "confirm_pending",
            "committed",
            "failed",
        ];
        for phase in valid_phases {
            let s = make_session(phase);
            let result = store_bilateral_session(&s);
            if let Err(e) = &result {
                assert!(
                    !e.to_string().contains("Invalid phase"),
                    "phase {} rejected",
                    phase
                );
            }
        }
    }

    #[test]
    #[serial]
    fn store_and_get_all_bilateral_sessions() {
        init_test_db();
        let s = make_session("prepared");
        store_bilateral_session(&s).unwrap();

        let all = get_all_bilateral_sessions().unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].phase, "prepared");
        assert_eq!(all[0].commitment_hash, vec![0x11; 32]);
    }

    #[test]
    #[serial]
    fn delete_bilateral_session_removes_entry() {
        init_test_db();
        let s = make_session("committed");
        store_bilateral_session(&s).unwrap();

        delete_bilateral_session(&[0x11; 32]).unwrap();
        let all = get_all_bilateral_sessions().unwrap();
        assert!(all.is_empty());
    }

    #[test]
    #[serial]
    fn store_bilateral_session_upserts_phase_on_conflict() {
        init_test_db();
        let s = make_session("prepared");
        store_bilateral_session(&s).unwrap();

        let mut updated = s.clone();
        updated.phase = "committed".to_string();
        updated.counterparty_signature = Some(vec![0x66; 64]);
        store_bilateral_session(&updated).unwrap();

        let all = get_all_bilateral_sessions().unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].phase, "committed");
        assert_eq!(all[0].counterparty_signature, Some(vec![0x66; 64]));
    }

    #[test]
    #[serial]
    fn store_multiple_bilateral_sessions() {
        init_test_db();
        let s1 = make_session("prepared");
        store_bilateral_session(&s1).unwrap();

        let mut s2 = make_session("accepted");
        s2.commitment_hash = vec![0x99; 32];
        store_bilateral_session(&s2).unwrap();

        let all = get_all_bilateral_sessions().unwrap();
        assert_eq!(all.len(), 2);
    }

    #[test]
    #[serial]
    fn delete_nonexistent_bilateral_session_is_noop() {
        init_test_db();
        delete_bilateral_session(&[0xFF; 32]).unwrap();
        let all = get_all_bilateral_sessions().unwrap();
        assert!(all.is_empty());
    }

    #[test]
    #[serial]
    fn bilateral_session_preserves_ble_address() {
        init_test_db();
        let mut s = make_session("prepared");
        s.sender_ble_address = Some("AA:BB:CC:DD:EE:FF".to_string());
        store_bilateral_session(&s).unwrap();

        let all = get_all_bilateral_sessions().unwrap();
        assert_eq!(
            all[0].sender_ble_address.as_deref(),
            Some("AA:BB:CC:DD:EE:FF")
        );
    }

    /// Regression test: the sender-cached signed stitched receipt (with §11.1
    /// per-step EK signing artifacts already stamped) must round-trip through
    /// SQLite so post-crash recovery in `finalize_sender_step`
    /// can reuse it verbatim instead of attempting an unsigned rebuild.
    #[test]
    #[serial]
    fn bilateral_session_preserves_stitched_receipt_bytes() {
        init_test_db();
        let mut s = make_session("confirm_pending");
        let receipt_bytes = vec![0x99; 4096]; // arbitrary opaque payload
        s.stitched_receipt_bytes = Some(receipt_bytes.clone());
        store_bilateral_session(&s).unwrap();

        let restored = get_bilateral_session(&[0x11; 32])
            .unwrap()
            .expect("session row should exist");
        assert_eq!(
            restored.stitched_receipt_bytes,
            Some(receipt_bytes),
            "signed stitched receipt should round-trip through SQLite"
        );
    }

    /// Regression test: an upsert that does not provide `stitched_receipt_bytes`
    /// (e.g. a phase-only update like Accepted → ConfirmPending arriving from a
    /// code path that does not have the receipt in hand) must NOT clobber the
    /// previously-cached signed bytes. Loss here would force the recovery path
    /// to fall back to an unsigned rebuild.
    #[test]
    #[serial]
    fn bilateral_session_upsert_preserves_existing_stitched_receipt_bytes() {
        init_test_db();
        let mut original = make_session("confirm_pending");
        let receipt_bytes = vec![0x77; 1024];
        original.stitched_receipt_bytes = Some(receipt_bytes.clone());
        store_bilateral_session(&original).unwrap();

        // Simulate a later upsert that doesn't carry the receipt (e.g. a
        // phase-only persistence call from a different code path).
        let mut phase_only = make_session("committed");
        phase_only.stitched_receipt_bytes = None;
        store_bilateral_session(&phase_only).unwrap();

        let restored = get_bilateral_session(&[0x11; 32])
            .unwrap()
            .expect("session row should still exist");
        assert_eq!(
            restored.phase, "committed",
            "phase should be updated by upsert"
        );
        assert_eq!(
            restored.stitched_receipt_bytes,
            Some(receipt_bytes),
            "previously-cached signed receipt must survive an upsert with None"
        );
    }
}
