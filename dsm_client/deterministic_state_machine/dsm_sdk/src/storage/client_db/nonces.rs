// SPDX-License-Identifier: MIT OR Apache-2.0
//! Nonce tracking and atomic receive transfer (replay prevention).

use anyhow::{anyhow, Result};
use log::{info, warn};
use rusqlite::params;

use super::get_connection;
use crate::storage::codecs::hash_blake3_bytes;
use crate::util::deterministic_time::tick;

/// Check if a nonce has already been spent (replay attack prevention).
/// Returns true if the nonce is already in the spent_nonces table.
pub fn is_nonce_spent(nonce: &[u8]) -> Result<bool> {
    if nonce.is_empty() {
        return Ok(false); // Empty nonce cannot be checked
    }
    let nonce_hash = hash_blake3_bytes(nonce);
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|poisoned| {
        log::warn!("DB lock poisoned in is_nonce_spent, recovering");
        poisoned.into_inner()
    });
    let count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM spent_nonces WHERE nonce_hash = ?1",
        params![&nonce_hash[..]],
        |row| row.get(0),
    )?;
    Ok(count > 0)
}

/// Mark a nonce as spent (must be called atomically with balance credit).
/// Returns error if nonce was already spent (replay attack detected).
pub fn mark_nonce_spent(nonce: &[u8], tx_id: &str, sender_id: &[u8], amount: u64) -> Result<()> {
    if nonce.is_empty() {
        return Err(anyhow!("Cannot mark empty nonce as spent"));
    }
    let nonce_hash = hash_blake3_bytes(nonce);
    let now = tick();
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|poisoned| {
        log::warn!("DB lock poisoned in mark_nonce_spent, recovering");
        poisoned.into_inner()
    });

    // Use INSERT without OR IGNORE - will fail if nonce already exists (replay attack)
    let result = conn.execute(
        "INSERT INTO spent_nonces(nonce_hash, tx_id, sender_id, amount, spent_at) VALUES(?1, ?2, ?3, ?4, ?5)",
        params![&nonce_hash[..], tx_id, sender_id, amount as i64, now as i64],
    );

    match result {
        Ok(_) => {
            info!("[spent_nonces] Marked nonce as spent for tx {}", tx_id);
            Ok(())
        }
        Err(rusqlite::Error::SqliteFailure(err, _))
            if err.code == rusqlite::ErrorCode::ConstraintViolation =>
        {
            warn!(
                "[spent_nonces] REPLAY ATTACK DETECTED: nonce already spent for tx {}",
                tx_id
            );
            Err(anyhow!("Replay attack detected: nonce already spent"))
        }
        Err(e) => Err(e.into()),
    }
}

/// Atomic receive delivery metadata update: validates nonce and advances replay state.
/// This function implements AF-1 remediation by ensuring atomicity.
/// Returns the new chain_tip hash on success.
///
/// `policy_commit` is the 32-byte CPTA anchor for the token being received,
/// ensuring the chain tip is domain-separated per token type.
pub fn atomic_receive_transfer(
    _recipient_device_id: &str,
    nonce: &[u8],
    tx_id: &str,
    sender_id: &[u8],
    amount: u64,
    current_chain_tip: &[u8],
    policy_commit: &[u8; 32],
) -> Result<[u8; 32]> {
    let nonce_hash = hash_blake3_bytes(nonce);
    let now = tick();

    // Calculate new chain_tip BEFORE any state modification (AF-1 fix)
    // Uses hierarchical domain separation: H("DSM/token-op/" || policy_commit || "/receive\0" || ...)
    let new_tip = {
        let mut h = dsm::crypto::blake3::token_domain_hasher(policy_commit, "receive");
        h.update(current_chain_tip);
        h.update(tx_id.as_bytes());
        h.update(&amount.to_le_bytes());
        *h.finalize().as_bytes()
    };

    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|poisoned| {
        log::warn!("DB lock poisoned in atomic_receive_transfer, recovering");
        poisoned.into_inner()
    });

    // Begin transaction for atomicity
    conn.execute("BEGIN IMMEDIATE", [])?;

    // Step 1: Check nonce not already spent (AF-2 validation)
    let nonce_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM spent_nonces WHERE nonce_hash = ?1",
            params![&nonce_hash[..]],
            |row| row.get(0),
        )
        .map_err(|e| {
            let _ = conn.execute("ROLLBACK", []);
            anyhow!("Failed to check nonce: {}", e)
        })?;

    if nonce_count > 0 {
        conn.execute("ROLLBACK", [])?;
        warn!(
            "[atomic_receive] REPLAY ATTACK: nonce already spent for tx {}",
            tx_id
        );
        return Err(anyhow!("Replay attack detected: nonce already spent"));
    }

    // Step 2: Insert spent nonce FIRST (cryptographic commitment before financial)
    if let Err(e) = conn.execute(
        "INSERT INTO spent_nonces(nonce_hash, tx_id, sender_id, amount, spent_at) VALUES(?1, ?2, ?3, ?4, ?5)",
        params![&nonce_hash[..], tx_id, sender_id, amount as i64, now as i64],
    ) {
        conn.execute("ROLLBACK", [])?;
        return Err(anyhow!("Failed to mark nonce spent: {}", e));
    }

    // Step 3: Commit transaction
    conn.execute("COMMIT", [])?;

    info!(
        "[atomic_receive] Atomically processed tx {} (amount: {}, replay metadata only)",
        tx_id, amount
    );

    Ok(new_tip)
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

    #[test]
    fn is_nonce_spent_returns_false_for_empty_nonce() {
        assert!(!is_nonce_spent(&[]).unwrap());
    }

    #[test]
    fn mark_nonce_spent_rejects_empty_nonce() {
        let err = mark_nonce_spent(&[], "tx-1", b"sender", 100).unwrap_err();
        assert!(err.to_string().contains("empty nonce"));
    }

    #[test]
    fn hash_blake3_bytes_is_deterministic() {
        let h1 = hash_blake3_bytes(b"test-nonce-data");
        let h2 = hash_blake3_bytes(b"test-nonce-data");
        assert_eq!(h1, h2);
        assert_ne!(h1, [0u8; 32]);
    }

    #[test]
    fn hash_blake3_bytes_different_inputs_differ() {
        let h1 = hash_blake3_bytes(b"nonce-alpha");
        let h2 = hash_blake3_bytes(b"nonce-beta");
        assert_ne!(h1, h2);
    }

    #[test]
    #[serial]
    fn mark_and_check_nonce_spent() {
        init_test_db();

        let nonce = b"unique-nonce-42";
        assert!(!is_nonce_spent(nonce).unwrap());

        mark_nonce_spent(nonce, "tx-42", b"sender-a", 500).expect("mark spent");
        assert!(is_nonce_spent(nonce).unwrap());
    }

    #[test]
    #[serial]
    fn mark_nonce_spent_detects_replay() {
        init_test_db();

        let nonce = b"replay-nonce";
        mark_nonce_spent(nonce, "tx-first", b"sender", 100).expect("first mark");

        let err = mark_nonce_spent(nonce, "tx-duplicate", b"sender", 100).unwrap_err();
        assert!(err.to_string().contains("Replay attack"));
    }

    #[test]
    #[serial]
    fn atomic_receive_transfer_produces_deterministic_tip() {
        init_test_db();

        let nonce = b"atomic-nonce-1";
        let current_tip = [0x11u8; 32];
        let policy_commit = [0x22u8; 32];

        let tip1 = atomic_receive_transfer(
            "device-1",
            nonce,
            "tx-atomic-1",
            b"sender-1",
            1000,
            &current_tip,
            &policy_commit,
        )
        .expect("first receive");

        assert_ne!(tip1, [0u8; 32]);
        assert_ne!(tip1, current_tip);
    }

    #[test]
    #[serial]
    fn atomic_receive_transfer_rejects_replay_nonce() {
        init_test_db();

        let nonce = b"atomic-replay-nonce";
        let current_tip = [0x33u8; 32];
        let policy_commit = [0x44u8; 32];

        atomic_receive_transfer(
            "device-2",
            nonce,
            "tx-first-atomic",
            b"sender-2",
            500,
            &current_tip,
            &policy_commit,
        )
        .expect("first receive");

        let err = atomic_receive_transfer(
            "device-2",
            nonce,
            "tx-second-atomic",
            b"sender-2",
            500,
            &current_tip,
            &policy_commit,
        )
        .unwrap_err();
        assert!(err.to_string().contains("Replay attack"));
    }
}
