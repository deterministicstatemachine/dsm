// SPDX-License-Identifier: MIT OR Apache-2.0
//! Bilateral session persistence.

use anyhow::{anyhow, Result};
use log::debug;
use rusqlite::{params, OptionalExtension};

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

/// Get a single bilateral session by commitment hash.
pub fn get_bilateral_session(commitment_hash: &[u8]) -> Result<Option<BilateralSessionRecord>> {
    let binding = get_db_connection()?;
    let conn = binding
        .lock()
        .map_err(|_| anyhow!("Database lock poisoned - concurrent access error"))?;

    conn.query_row(
        "SELECT commitment_hash, counterparty_device_id, operation_bytes, phase,
                counterparty_genesis_hash, local_signature, counterparty_signature, created_at_step,
                sender_ble_address
           FROM bilateral_sessions
          WHERE commitment_hash = ?1",
        params![commitment_hash],
        |row| {
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
        },
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

/// Clean up expired bilateral sessions
pub fn cleanup_expired_bilateral_sessions(current_ticks: u64) -> Result<usize> {
    // Clockless protocol: bilateral sessions do not expire by any local notion of duration.
    // Cleanup must be driven by explicit state transitions, not by a ticking counter.
    let _ = current_ticks;
    Ok(0)
}

// ═══════════════════════════════════════════════════════════════════════
// §5.3 Pending Confirm Delivery — crash-safe receipt persistence
// ═══════════════════════════════════════════════════════════════════════

/// Store a confirm envelope for re-delivery. Called atomically with sender
/// finalization so the receipt survives crashes.
pub fn store_pending_confirm_delivery(
    commitment_hash: &[u8],
    counterparty_device_id: &[u8],
    confirm_envelope: &[u8],
) -> Result<()> {
    if commitment_hash.len() != 32 || counterparty_device_id.len() != 32 {
        return Err(anyhow!("Invalid hash or device_id length"));
    }
    let binding = get_db_connection()?;
    let conn = binding
        .lock()
        .map_err(|_| anyhow!("Database lock poisoned"))?;
    let tick_val = tick() as i64;
    conn.execute(
        "INSERT OR REPLACE INTO pending_confirm_delivery (commitment_hash, counterparty_device_id, confirm_envelope, created_at_tick) VALUES (?1, ?2, ?3, ?4)",
        params![commitment_hash, counterparty_device_id, confirm_envelope, tick_val],
    )?;
    Ok(())
}

/// Get pending confirm envelopes for a counterparty (for re-delivery on reconnect).
pub fn get_pending_confirm_deliveries(
    counterparty_device_id: &[u8],
) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
    if counterparty_device_id.len() != 32 {
        return Err(anyhow!("Invalid device_id length"));
    }
    let binding = get_db_connection()?;
    let conn = binding
        .lock()
        .map_err(|_| anyhow!("Database lock poisoned"))?;
    let mut stmt = conn.prepare(
        "SELECT commitment_hash, confirm_envelope FROM pending_confirm_delivery WHERE counterparty_device_id = ?1",
    )?;
    let rows = stmt
        .query_map(params![counterparty_device_id], |row| {
            Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?))
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    Ok(rows)
}

/// Get a pending confirm envelope by commitment hash.
pub fn get_pending_confirm_delivery(
    commitment_hash: &[u8],
) -> Result<Option<(Vec<u8>, Vec<u8>)>> {
    if commitment_hash.len() != 32 {
        return Err(anyhow!("Invalid commitment_hash length"));
    }

    let binding = get_db_connection()?;
    let conn = binding
        .lock()
        .map_err(|_| anyhow!("Database lock poisoned"))?;

    conn.query_row(
        "SELECT counterparty_device_id, confirm_envelope
           FROM pending_confirm_delivery
          WHERE commitment_hash = ?1",
        params![commitment_hash],
        |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?)),
    )
    .optional()
    .map_err(Into::into)
}

/// Delete a pending confirm delivery after successful BLE delivery.
pub fn delete_pending_confirm_delivery(commitment_hash: &[u8]) -> Result<()> {
    if commitment_hash.len() != 32 {
        return Err(anyhow!("Invalid commitment_hash length"));
    }
    let binding = get_db_connection()?;
    let conn = binding
        .lock()
        .map_err(|_| anyhow!("Database lock poisoned"))?;
    conn.execute(
        "DELETE FROM pending_confirm_delivery WHERE commitment_hash = ?1",
        params![commitment_hash],
    )?;
    Ok(())
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

    fn make_session(phase: &str) -> BilateralSessionRecord {
        BilateralSessionRecord {
            commitment_hash: vec![0x11; 32],
            counterparty_device_id: vec![0x22; 32],
            counterparty_genesis_hash: Some(vec![0x33; 32]),
            operation_bytes: vec![0x44; 16],
            phase: phase.to_string(),
            local_signature: Some(vec![0x55; 64]),
            counterparty_signature: None,
            created_at_step: 1,
            sender_ble_address: None,
        }
    }

    #[test]
    fn store_bilateral_session_rejects_empty_commitment_hash() {
        let mut s = make_session("prepare");
        s.commitment_hash = vec![];
        let err = store_bilateral_session(&s).unwrap_err();
        assert!(err.to_string().contains("commitment_hash"));
    }

    #[test]
    fn store_bilateral_session_rejects_oversized_commitment_hash() {
        let mut s = make_session("prepare");
        s.commitment_hash = vec![0; 33];
        let err = store_bilateral_session(&s).unwrap_err();
        assert!(err.to_string().contains("commitment_hash"));
    }

    #[test]
    fn store_bilateral_session_rejects_wrong_counterparty_length() {
        let mut s = make_session("prepare");
        s.counterparty_device_id = vec![0; 16];
        let err = store_bilateral_session(&s).unwrap_err();
        assert!(err.to_string().contains("counterparty_device_id"));
    }

    #[test]
    fn store_bilateral_session_rejects_empty_operation_bytes() {
        let mut s = make_session("prepare");
        s.operation_bytes = vec![];
        let err = store_bilateral_session(&s).unwrap_err();
        assert!(err.to_string().contains("operation_bytes"));
    }

    #[test]
    fn store_bilateral_session_rejects_invalid_phase() {
        let s = make_session("invalid_phase");
        let err = store_bilateral_session(&s).unwrap_err();
        assert!(err.to_string().contains("Invalid phase"));
    }

    #[test]
    fn store_bilateral_session_accepts_all_valid_phases() {
        let valid_phases = [
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
    fn cleanup_expired_returns_zero() {
        assert_eq!(cleanup_expired_bilateral_sessions(999).unwrap(), 0);
    }

    #[test]
    #[serial]
    fn store_and_get_all_bilateral_sessions() {
        init_test_db();
        let s = make_session("prepare");
        store_bilateral_session(&s).unwrap();

        let all = get_all_bilateral_sessions().unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].phase, "prepare");
        assert_eq!(all[0].commitment_hash, vec![0x11; 32]);
    }

    #[test]
    #[serial]
    fn delete_bilateral_session_removes_entry() {
        init_test_db();
        let s = make_session("commit");
        store_bilateral_session(&s).unwrap();

        delete_bilateral_session(&vec![0x11; 32]).unwrap();
        let all = get_all_bilateral_sessions().unwrap();
        assert!(all.is_empty());
    }

    #[test]
    #[serial]
    fn store_bilateral_session_upserts_phase_on_conflict() {
        init_test_db();
        let s = make_session("prepare");
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
        let s1 = make_session("prepare");
        store_bilateral_session(&s1).unwrap();

        let mut s2 = make_session("accept");
        s2.commitment_hash = vec![0x99; 32];
        store_bilateral_session(&s2).unwrap();

        let all = get_all_bilateral_sessions().unwrap();
        assert_eq!(all.len(), 2);
    }

    #[test]
    #[serial]
    fn delete_nonexistent_bilateral_session_is_noop() {
        init_test_db();
        delete_bilateral_session(&vec![0xFF; 32]).unwrap();
        let all = get_all_bilateral_sessions().unwrap();
        assert!(all.is_empty());
    }

    #[test]
    #[serial]
    fn bilateral_session_preserves_ble_address() {
        init_test_db();
        let mut s = make_session("prepare");
        s.sender_ble_address = Some("AA:BB:CC:DD:EE:FF".to_string());
        store_bilateral_session(&s).unwrap();

        let all = get_all_bilateral_sessions().unwrap();
        assert_eq!(
            all[0].sender_ble_address.as_deref(),
            Some("AA:BB:CC:DD:EE:FF")
        );
    }
}
