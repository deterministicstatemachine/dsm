// SPDX-License-Identifier: MIT OR Apache-2.0
//! Transaction history persistence.

use anyhow::Result;
use log::info;
use rusqlite::{params, Connection, OptionalExtension, Row};

use super::get_connection;
use super::types::TransactionRecord;
use crate::storage::codecs::{meta_from_blob, meta_to_blob};
use crate::util::deterministic_time::tick;

fn upsert_transaction_row(conn: &Connection, tx: &TransactionRecord, now: u64) -> Result<usize> {
    let affected = conn.execute(
        "INSERT INTO transactions (
            tx_id, tx_hash, from_device, to_device, amount, tx_type,
            status, chain_height, step_index, commitment_hash, proof_data, metadata, created_at
        ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)
        ON CONFLICT(tx_id) DO UPDATE SET
            tx_hash = excluded.tx_hash,
            from_device = excluded.from_device,
            to_device = excluded.to_device,
            amount = excluded.amount,
            tx_type = excluded.tx_type,
            status = excluded.status,
            chain_height = excluded.chain_height,
            step_index = CASE
                WHEN excluded.step_index > transactions.step_index THEN excluded.step_index
                ELSE transactions.step_index
            END,
            commitment_hash = COALESCE(transactions.commitment_hash, excluded.commitment_hash),
            proof_data = CASE
                WHEN (transactions.proof_data IS NULL OR length(transactions.proof_data) = 0)
                     AND (excluded.proof_data IS NOT NULL AND length(excluded.proof_data) > 0)
                THEN excluded.proof_data
                ELSE transactions.proof_data
            END,
            metadata = CASE
                WHEN length(excluded.metadata) > 0 THEN excluded.metadata
                ELSE transactions.metadata
            END",
        params![
            tx.tx_id,
            tx.tx_hash,
            tx.from_device,
            tx.to_device,
            tx.amount as i64,
            tx.tx_type,
            tx.status,
            tx.chain_height as i64,
            tx.step_index as i64,
            tx.commitment_hash.as_deref(),
            tx.proof_data.as_deref(),
            meta_to_blob(&tx.metadata),
            now as i64,
        ],
    )?;
    Ok(affected)
}

/// Atomically apply sender-side balance debit and transaction history write.
///
/// Mirrors `apply_receiver_confirm_full_atomic()` but performs
/// a **debit** (subtraction) instead of credit (addition). Enforces the token
/// conservation invariant `B >= 0` at the SQL level — the UPDATE only succeeds
/// if the current balance is sufficient. If the row is missing or balance is
/// insufficient, the function returns an error and the SQLite transaction is
/// rolled back (no partial writes).
pub fn apply_sender_debit_and_store_transaction_atomic(
    sender_device_id: &str,
    token_id: Option<&str>,
    amount: u64,
    tx: &TransactionRecord,
) -> Result<()> {
    let binding = get_connection()?;
    let mut conn = binding.lock().unwrap_or_else(|poisoned| {
        log::warn!(
            "DB lock poisoned in apply_sender_debit_and_store_transaction_atomic, recovering"
        );
        poisoned.into_inner()
    });

    let amount_i64 = i64::try_from(amount)
        .map_err(|_| anyhow::anyhow!("amount exceeds i64 range for SQLite integer"))?;
    let now = tick();
    let txdb = conn.transaction()?;

    let token = token_id.unwrap_or("ERA");
    if token == "ERA" {
        // ERA token: debit wallet_state.balance.
        // Conditional UPDATE enforces B_{n+1} = B_n - Delta, B >= 0 at the SQL level.
        let updated = txdb.execute(
            "UPDATE wallet_state SET balance = balance - ?1, updated_at = ?2
             WHERE device_id = ?3 AND balance >= ?1",
            params![amount_i64, now as i64, sender_device_id],
        )?;

        if updated == 0 {
            let exists: bool = txdb
                .query_row(
                    "SELECT COUNT(*) FROM wallet_state WHERE device_id = ?1",
                    params![sender_device_id],
                    |row| row.get::<_, i64>(0),
                )
                .map(|c| c > 0)
                .unwrap_or(false);

            // Explicit rollback before returning error
            if let Err(rb_err) = txdb.execute_batch("ROLLBACK") {
                log::warn!("Rollback failed after debit check: {}", rb_err);
            }

            if exists {
                return Err(anyhow::anyhow!(
                    "insufficient ERA balance to debit {} for sender {}",
                    amount,
                    sender_device_id
                ));
            } else {
                return Err(anyhow::anyhow!(
                    "no wallet_state row for sender {}",
                    sender_device_id
                ));
            }
        }
    } else {
        // Non-ERA token: debit token_balances.available.
        // Conditional UPDATE enforces available >= amount.
        let updated = txdb.execute(
            "UPDATE token_balances SET available = available - ?1, updated_at = ?2
             WHERE device_id = ?3 AND token_id = ?4 AND available >= ?1",
            params![amount_i64, now as i64, sender_device_id, token],
        )?;

        if updated == 0 {
            let exists: bool = txdb
                .query_row(
                    "SELECT COUNT(*) FROM token_balances WHERE device_id = ?1 AND token_id = ?2",
                    params![sender_device_id, token],
                    |row| row.get::<_, i64>(0),
                )
                .map(|c| c > 0)
                .unwrap_or(false);

            if let Err(rb_err) = txdb.execute_batch("ROLLBACK") {
                log::warn!("Rollback failed after token debit check: {}", rb_err);
            }

            if !exists {
                // Auto-seed missing token row for native assets like dBTC to prevent
                // missing-row panic conditions in bilateral settlement paths.
                if let Err(e) = txdb.execute(
                    "INSERT OR REPLACE INTO token_balances (device_id, token_id, available, locked, updated_at) VALUES (?1, ?2, 0, 0, ?3)",
                    params![sender_device_id, token, now as i64],
                ) {
                    log::warn!("Failed to seed missing token_balances row for {} {}: {}", sender_device_id, token, e);
                } else {
                    log::info!("Seeded missing token_balances row for {} {} to 0", sender_device_id, token);
                }
                return Err(anyhow::anyhow!(
                    "insufficient {} balance to debit {} for sender {} (token row was missing; seeded 0)",
                    token,
                    amount,
                    sender_device_id
                ));
            }

            return Err(anyhow::anyhow!(
                "insufficient {} balance to debit {} for sender {}",
                token,
                amount,
                sender_device_id
            ));
        }
    }

    let affected = upsert_transaction_row(&txdb, tx, now)?;
    txdb.commit()?;

    if affected > 0 {
        info!(
            "Atomic sender debit+store committed: device={} token={} amount={} tx_id={}",
            sender_device_id, token, amount, tx.tx_id
        );
    }

    Ok(())
}

/// Atomically persist chain-tip advancement + receiver balance credit + transaction history.
///
/// This is the full-persistence atomic boundary for BLE receiver confirm (§4.2).
/// If any sub-write fails, the entire SQLite transaction rolls back — no partial
/// state, no chain-tip-without-balance divergence.
///
/// Callers should use `update_anchor_in_memory_public()` for the in-memory anchor
/// update and then call this function for all SQLite writes.
pub fn apply_receiver_confirm_full_atomic(
    counterparty_device_id: &[u8],
    new_chain_tip: &[u8],
    receiver_device_id: &str,
    token_id: Option<&str>,
    amount: u64,
    tx: &TransactionRecord,
) -> Result<()> {
    let binding = get_connection()?;
    let mut conn = binding.lock().unwrap_or_else(|poisoned| {
        log::warn!("DB lock poisoned in apply_receiver_confirm_full_atomic, recovering");
        poisoned.into_inner()
    });

    let now = tick();
    let txdb = conn.transaction()?;

    // 1. Advance chain tip (mirrors update_finalized_bilateral_chain_tip)
    txdb.execute(
        "UPDATE contacts SET
            previous_chain_tip = chain_tip,
            chain_tip = ?1,
            local_bilateral_chain_tip = ?1,
            needs_online_reconcile = 0,
            last_seen_online_counter = ?2,
            status = CASE
                WHEN status = 'BleCapable' THEN 'BleCapable'
                ELSE 'OnlineCapable'
            END
         WHERE device_id = ?3",
        params![new_chain_tip, now as i64, counterparty_device_id],
    )?;

    // 2. Credit balance
    if amount > 0 {
        let amount_i64 = i64::try_from(amount)
            .map_err(|_| anyhow::anyhow!("amount exceeds i64 range for SQLite integer"))?;
        let token = token_id.unwrap_or("ERA");
        if token == "ERA" {
            let updated = txdb.execute(
                "UPDATE wallet_state SET balance = balance + ?1, updated_at = ?2 WHERE device_id = ?3",
                params![amount_i64, now as i64, receiver_device_id],
            )?;

            if updated == 0 {
                let zero_tip = crate::util::text_id::encode_base32_crockford(&[0u8; 32]);
                let genesis_id = txdb
                    .query_row(
                        "SELECT genesis_id, device_id FROM genesis_records ORDER BY created_at DESC LIMIT 1",
                        [],
                        |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
                    )
                    .optional()?
                    .and_then(|(genesis_id, gen_device_id)| {
                        if gen_device_id == receiver_device_id {
                            Some(genesis_id)
                        } else {
                            None
                        }
                    })
                    .unwrap_or_else(|| receiver_device_id.to_string());

                txdb.execute(
                    "INSERT INTO wallet_state (wallet_id, device_id, genesis_id, chain_tip, chain_height, merkle_root, balance, created_at, updated_at, status, metadata) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
                    params![
                        format!("wallet_{}", receiver_device_id),
                        receiver_device_id,
                        genesis_id,
                        zero_tip,
                        0i64,
                        "",
                        amount_i64,
                        now as i64,
                        now as i64,
                        "active",
                        Vec::<u8>::new(),
                    ],
                )?;
            }
        } else {
            txdb.execute(
                "INSERT INTO token_balances (device_id, token_id, available, locked, updated_at)
                 VALUES (?1, ?2, ?3, 0, ?4)
                 ON CONFLICT(device_id, token_id) DO UPDATE SET
                   available = token_balances.available + excluded.available,
                   updated_at = excluded.updated_at",
                params![receiver_device_id, token, amount_i64, now as i64],
            )?;
        }
    }

    // 3. Store transaction history
    let affected = upsert_transaction_row(&txdb, tx, now)?;
    txdb.commit()?;

    if affected > 0 {
        info!(
            "Atomic receiver confirm committed (tip+balance+history): device={} token={:?} amount={} tx_id={}",
            receiver_device_id, token_id, amount, tx.tx_id
        );
    }

    Ok(())
}

pub fn store_transaction(tx: &TransactionRecord) -> Result<()> {
    info!(
        "Storing transaction: {} ({} -> {})",
        tx.tx_id, tx.from_device, tx.to_device
    );
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|poisoned| {
        log::warn!("DB lock poisoned, recovering");
        poisoned.into_inner()
    });
    let now = tick();
    // Upsert by tx_id so we can safely backfill missing proof_data when a transaction
    // is first stored without a receipt and finalized later with stitched bytes.
    // Important: never downgrade proof_data from non-empty to empty.
    let affected = upsert_transaction_row(&conn, tx, now)?;
    if affected > 0 {
        info!("Transaction upserted successfully, amount={}", tx.amount);
    } else {
        info!("Transaction unchanged after upsert: {}", tx.tx_id);
    }

    // Debug: verify the transaction was stored
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM transactions WHERE from_device = ?1 OR to_device = ?1",
            params![tx.from_device],
            |row| row.get(0),
        )
        .unwrap_or(0);
    info!(
        "Total transactions for device {}: {}",
        &tx.from_device[..tx.from_device.len().min(20)],
        count
    );

    Ok(())
}

/// Backfill receipt bytes into an existing transaction record.
///
/// Only updates if the current `proof_data` is NULL or empty, so this is safe
/// to call unconditionally after receipt construction completes.
pub fn update_transaction_proof_data(tx_id: &str, proof_data: &[u8]) -> Result<()> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|poisoned| {
        log::warn!("DB lock poisoned, recovering");
        poisoned.into_inner()
    });
    let affected = conn.execute(
        "UPDATE transactions SET proof_data = ?1 WHERE tx_id = ?2 AND (proof_data IS NULL OR length(proof_data) = 0)",
        params![proof_data, tx_id],
    )?;
    if affected > 0 {
        info!(
            "Receipt backfilled for tx_id={} ({} bytes)",
            tx_id,
            proof_data.len()
        );
    }
    Ok(())
}

pub fn get_transaction_history(
    device_id: Option<&str>,
    limit: Option<usize>,
) -> Result<Vec<TransactionRecord>> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|poisoned| {
        log::warn!("DB lock poisoned, recovering");
        poisoned.into_inner()
    });
    let lim = match limit {
        Some(0) => 100,
        Some(n) => n,
        None => 100,
    };

    // DEBUG: Check total transactions in table
    let total: i64 = conn
        .query_row("SELECT COUNT(*) FROM transactions", [], |r| r.get(0))
        .unwrap_or(0);
    log::info!(
        "[get_transaction_history] Total transactions in table: {}",
        total
    );

    // DEBUG: If we have a device_id filter, also check what devices exist
    if let Some(d) = &device_id {
        let sample: Option<String> = conn
            .query_row("SELECT from_device FROM transactions LIMIT 1", [], |r| {
                r.get(0)
            })
            .ok();
        log::info!(
            "[get_transaction_history] Looking for device: \"{}\", sample from_device in table: {:?}",
            d,
            sample
        );
    }

    let map_row = |row: &Row| -> rusqlite::Result<TransactionRecord> {
        let meta_blob: Vec<u8> = row.get(11)?;
        let metadata = meta_from_blob(&meta_blob).unwrap_or_default();
        Ok(TransactionRecord {
            tx_id: row.get(0)?,
            tx_hash: row.get(1)?,
            from_device: row.get(2)?,
            to_device: row.get(3)?,
            amount: row.get::<_, i64>(4)? as u64,
            tx_type: row.get(5)?,
            status: row.get(6)?,
            chain_height: row.get::<_, i64>(7)? as u64,
            step_index: row.get::<_, i64>(8)? as u64,
            commitment_hash: row.get::<_, Option<Vec<u8>>>(9)?,
            proof_data: row.get::<_, Option<Vec<u8>>>(10)?,
            metadata,
            created_at: row.get::<_, i64>(12)? as u64,
        })
    };

    if let Some(d) = device_id {
        // DEBUG: Test query with explicit string matching
        let test_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM transactions WHERE from_device = ?1 OR to_device = ?1",
                params![d],
                |r| r.get(0),
            )
            .unwrap_or(-1);
        log::info!(
            "[get_transaction_history] Test query for device \"{}\" returned count: {}",
            d,
            test_count
        );

        let query = format!(
            "SELECT tx_id, tx_hash, from_device, to_device, amount, tx_type, status, chain_height, step_index, commitment_hash, proof_data, metadata, created_at FROM transactions WHERE from_device = ?1 OR to_device = ?1 ORDER BY step_index DESC LIMIT {lim}",
        );
        log::info!("[get_transaction_history] Executing main query: {}", query);
        let mut stmt = conn.prepare(&query)?;
        let iter = stmt.query_map(params![d], map_row)?;
        let mut out = Vec::new();
        let mut row_counter = 0;
        for r in iter {
            row_counter += 1;
            match r {
                Ok(item) => {
                    log::info!(
                        "[get_transaction_history] Mapped row successfully: {}",
                        item.tx_id
                    );
                    out.push(item);
                }
                Err(e) => {
                    log::error!("[get_transaction_history] Failed to map row: {:?}", e);
                    // Don't fail the whole request, just skip the bad row
                }
            }
        }
        log::info!(
            "[get_transaction_history] Iterator yielded {} rows",
            row_counter
        );
        Ok(out)
    } else {
        let query = format!(
            "SELECT tx_id, tx_hash, from_device, to_device, amount, tx_type, status, chain_height, step_index, commitment_hash, proof_data, metadata, created_at FROM transactions ORDER BY step_index DESC LIMIT {lim}",
        );
        let mut stmt = conn.prepare(&query)?;
        let iter = stmt.query_map([], map_row)?;
        let mut out = Vec::new();
        for r in iter {
            out.push(r?);
        }
        Ok(out)
    }
}
