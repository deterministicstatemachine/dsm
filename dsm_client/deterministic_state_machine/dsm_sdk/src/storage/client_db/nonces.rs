// SPDX-License-Identifier: MIT OR Apache-2.0
//! Nonce tracking and atomic receive transfer (replay prevention).

use anyhow::{anyhow, Result};
use log::{info, warn};
use rusqlite::params;

use super::get_connection;
use crate::sdk::app_state::AppState;
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

/// Atomic transaction state update: validates nonce, credits balance, updates chain_tip.
/// This function implements AF-1 remediation by ensuring atomicity.
/// Returns the new chain_tip hash on success.
///
/// `policy_commit` is the 32-byte CPTA anchor for the token being received,
/// ensuring the chain tip is domain-separated per token type.
pub fn atomic_receive_transfer(
    recipient_device_id: &str,
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

    // Step 3: Get current balance
    let current_balance: i64 = conn
        .query_row(
            "SELECT balance FROM wallet_state WHERE device_id = ?1",
            params![recipient_device_id],
            |row| row.get(0),
        )
        .unwrap_or(0); // OK: missing wallet row means zero starting balance

    // Step 4: Credit balance
    let new_balance = (current_balance as u64).saturating_add(amount) as i64;
    let rows_affected = conn.execute(
        "UPDATE wallet_state SET balance = ?1, updated_at = ?2 WHERE device_id = ?3",
        params![new_balance, now as i64, recipient_device_id],
    );

    match rows_affected {
        Ok(0) => {
            warn!(
                "[atomic_receive_transfer] No wallet_state row for device {}; inserting new row.",
                recipient_device_id
            );
            let genesis_b32 = AppState::get_genesis_hash()
                .map(|g| crate::util::text_id::encode_base32_crockford(&g))
                .ok_or_else(|| anyhow!("Missing genesis hash for wallet insert"))?;
            // Perform INSERT if UPDATE failed to find row
            if let Err(e) = conn.execute(
                "INSERT INTO wallet_state (wallet_id, device_id, genesis_id, chain_tip, chain_height, merkle_root, balance, created_at, updated_at, status, metadata) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
                params![
                    format!("wallet_{}", recipient_device_id),
                    recipient_device_id,
                    genesis_b32,
                    new_tip.as_slice(),
                    0i64,
                    "",
                    new_balance,
                    now as i64,
                    now as i64,
                    "active",
                    Vec::<u8>::new(),
                ],
             ) {
                conn.execute("ROLLBACK", [])?;
                return Err(anyhow!("Failed to insert new wallet row: {}", e));
             }
        }
        Ok(_) => {
            // Success
        }
        Err(e) => {
            conn.execute("ROLLBACK", [])?;
            return Err(anyhow!("Failed to credit balance: {}", e));
        }
    }

    // Step 5: Commit transaction
    conn.execute("COMMIT", [])?;

    info!(
        "[atomic_receive] Atomically processed tx {} (amount: {}, new_balance: {})",
        tx_id, amount, new_balance
    );

    Ok(new_tip)
}
