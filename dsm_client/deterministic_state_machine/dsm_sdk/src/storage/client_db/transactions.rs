// SPDX-License-Identifier: MIT OR Apache-2.0
//! Transaction history persistence.

use anyhow::Result;
use log::info;
use rusqlite::{params, Connection, Row};

use super::bcr::store_bcr_state_with_conn;
use super::get_connection;
use super::tokens::{upsert_balance_projection_with_conn, BalanceProjectionRecord};
use super::types::TransactionRecord;
use crate::storage::codecs::{meta_from_blob, meta_to_blob};
use crate::util::deterministic_time::tick;
use dsm::types::state_types::State;

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

/// Atomically persist sender-side settlement metadata.
///
/// Canonical DSM state is authoritative for every token, including ERA. This
/// function stores sender-side transaction history only.
pub fn apply_sender_settlement_and_store_transaction_atomic(
    sender_device_id: &str,
    token_id: Option<&str>,
    amount: u64,
    tx: &TransactionRecord,
) -> Result<()> {
    let binding = get_connection()?;
    let mut conn = binding.lock().unwrap_or_else(|poisoned| {
        log::warn!(
            "DB lock poisoned in apply_sender_settlement_and_store_transaction_atomic, recovering"
        );
        poisoned.into_inner()
    });

    let now = tick();
    let txdb = conn.transaction()?;

    let token = token_id.unwrap_or("ERA");

    let affected = upsert_transaction_row(&txdb, tx, now)?;
    txdb.execute(
        "INSERT OR REPLACE INTO bilateral_sender_settlements(
            tx_id, sender_device_id, completed_at
         ) VALUES (?1, ?2, ?3)",
        params![tx.tx_id, sender_device_id, now as i64],
    )?;
    txdb.commit()?;

    if affected > 0 {
        info!(
            "Atomic sender settlement stored: device={} token={} amount={} tx_id={}",
            sender_device_id, token, amount, tx.tx_id
        );
    }

    Ok(())
}

pub fn apply_sender_settlement_bundle_atomic(
    sender_device_id: &str,
    token_id: Option<&str>,
    amount: u64,
    tx: &TransactionRecord,
    settled_state: Option<&State>,
    projection: Option<&BalanceProjectionRecord>,
) -> Result<()> {
    let binding = get_connection()?;
    let mut conn = binding.lock().unwrap_or_else(|poisoned| {
        log::warn!("DB lock poisoned in apply_sender_settlement_bundle_atomic, recovering");
        poisoned.into_inner()
    });

    let now = tick();
    let txdb = conn.transaction()?;
    let token = token_id.unwrap_or("ERA");

    if let Some(state) = settled_state {
        store_bcr_state_with_conn(&txdb, state, true, now)?;
    }
    if let Some(record) = projection {
        upsert_balance_projection_with_conn(&txdb, record)?;
    }

    let affected = upsert_transaction_row(&txdb, tx, now)?;
    txdb.execute(
        "INSERT OR REPLACE INTO bilateral_sender_settlements(
            tx_id, sender_device_id, completed_at
         ) VALUES (?1, ?2, ?3)",
        params![tx.tx_id, sender_device_id, now as i64],
    )?;
    txdb.commit()?;

    if affected > 0 {
        info!(
            "Atomic sender settlement bundle stored: device={} token={} amount={} tx_id={}",
            sender_device_id, token, amount, tx.tx_id
        );
    }

    Ok(())
}

/// Atomically persist chain-tip advancement and receiver-side settlement metadata.
///
/// This is the full-persistence atomic boundary for BLE receiver confirm (§4.2).
/// Canonical DSM state is authoritative for every token, including ERA. This
/// function persists bilateral chain-tip advancement plus transaction history.
///
/// Callers must have a `SmtReplaceResult` from `commit_bilateral_smt_update()`
/// and use `update_anchor_in_memory_from_replace_public()` for the in-memory
/// anchor update before calling this function for all SQLite writes.
pub fn apply_receiver_confirm_and_store_transaction_atomic(
    counterparty_device_id: &[u8],
    new_chain_tip: &[u8],
    receiver_device_id: &str,
    token_id: Option<&str>,
    amount: u64,
    tx: &TransactionRecord,
) -> Result<()> {
    let binding = get_connection()?;
    let mut conn = binding.lock().unwrap_or_else(|poisoned| {
        log::warn!(
            "DB lock poisoned in apply_receiver_confirm_and_store_transaction_atomic, recovering"
        );
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

    // 2. Store transaction history
    let affected = upsert_transaction_row(&txdb, tx, now)?;
    txdb.commit()?;

    if affected > 0 {
        info!(
            "Atomic receiver settlement stored (tip+history): device={} token={:?} amount={} tx_id={}",
            receiver_device_id, token_id, amount, tx.tx_id
        );
    }

    Ok(())
}

pub struct ReceiverConfirmBundle<'a> {
    pub counterparty_device_id: &'a [u8],
    pub new_chain_tip: &'a [u8],
    pub receiver_device_id: &'a str,
    pub token_id: Option<&'a str>,
    pub amount: u64,
    pub tx: &'a TransactionRecord,
    pub settled_state: Option<&'a State>,
    pub projection: Option<&'a BalanceProjectionRecord>,
}

pub fn apply_receiver_confirm_bundle_atomic(bundle: ReceiverConfirmBundle<'_>) -> Result<()> {
    let binding = get_connection()?;
    let mut conn = binding.lock().unwrap_or_else(|poisoned| {
        log::warn!("DB lock poisoned in apply_receiver_confirm_bundle_atomic, recovering");
        poisoned.into_inner()
    });

    let now = tick();
    let txdb = conn.transaction()?;

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
        params![
            bundle.new_chain_tip,
            now as i64,
            bundle.counterparty_device_id
        ],
    )?;

    if let Some(state) = bundle.settled_state {
        store_bcr_state_with_conn(&txdb, state, true, now)?;
    }
    if let Some(record) = bundle.projection {
        upsert_balance_projection_with_conn(&txdb, record)?;
    }

    let affected = upsert_transaction_row(&txdb, bundle.tx, now)?;
    txdb.commit()?;

    if affected > 0 {
        info!(
            "Atomic receiver settlement bundle stored (tip+history+state): device={} token={:?} amount={} tx_id={}",
            bundle.receiver_device_id, bundle.token_id, bundle.amount, bundle.tx.tx_id
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

pub fn rollback_failed_online_send_atomic(
    device_id: &[u8; 32],
    failed_state_hash: &[u8; 32],
    tx_id: &str,
    projection_device_id: &str,
    token_id: &str,
) -> Result<()> {
    let binding = get_connection()?;
    let mut conn = binding.lock().unwrap_or_else(|poisoned| {
        log::warn!("DB lock poisoned in rollback_failed_online_send_atomic, recovering");
        poisoned.into_inner()
    });

    let txdb = conn.transaction()?;
    let removed_bcr = txdb.execute(
        "DELETE FROM bcr_states WHERE device_id = ?1 AND state_hash = ?2",
        params![device_id.as_slice(), failed_state_hash.as_slice()],
    )?;
    let removed_tx = txdb.execute("DELETE FROM transactions WHERE tx_id = ?1", params![tx_id])?;
    let removed_projection = txdb.execute(
        "DELETE FROM balance_projections WHERE device_id = ?1 AND token_id = ?2",
        params![projection_device_id, token_id],
    )?;
    txdb.commit()?;

    info!(
        "Rolled back failed online send artifacts: tx_id={} removed_bcr={} removed_tx={} removed_projection={} token={}",
        tx_id,
        removed_bcr,
        removed_tx,
        removed_projection,
        token_id,
    );

    Ok(())
}

/// Check whether sender-side settlement already completed for a specific local device.
///
/// Sender idempotency must be scoped to the local device, not just `tx_id`.
/// In production each device has its own DB, but single-process integration
/// tests share one SQLite instance, so the receiver's completed transaction row
/// must not suppress the sender's settlement bundle.
pub fn is_sender_settlement_completed(tx_id: &str, sender_device_id: &str) -> bool {
    let binding = match get_connection() {
        Ok(b) => b,
        Err(_) => return false,
    };
    let conn = binding.lock().unwrap_or_else(|poisoned| {
        log::warn!("DB lock poisoned, recovering");
        poisoned.into_inner()
    });
    conn.query_row(
        "SELECT 1 FROM bilateral_sender_settlements
         WHERE tx_id = ?1 AND sender_device_id = ?2
         LIMIT 1",
        params![tx_id, sender_device_id],
        |_| Ok(true),
    )
    .unwrap_or(false)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::client_db::tokens::{upsert_balance_projection, BalanceProjectionRecord};
    use crate::storage::client_db::types::TransactionRecord;
    use crate::storage::client_db::{
        get_balance_projection, get_bcr_states, get_transaction_history, init_database,
        reset_database_for_tests, store_bcr_state,
    };
    use dsm::types::operations::Operation;
    use dsm::types::state_types::{DeviceInfo, State, StateParams};
    use serial_test::serial;
    use std::collections::HashMap;

    #[test]
    #[serial]
    fn rollback_failed_online_send_atomic_removes_failed_artifacts() {
        unsafe {
            std::env::set_var("DSM_SDK_TEST_MODE", "1");
        }
        reset_database_for_tests();
        init_database().expect("init db");

        let device = [0x41u8; 32];
        let device_b32 = crate::util::text_id::encode_base32_crockford(&device);
        let failed_state = State::new(StateParams::new(
            1,
            vec![0xAA],
            Operation::Noop,
            DeviceInfo::new(device, vec![0x22; 64]),
        ));
        store_bcr_state(&failed_state, false).expect("store failed state");

        upsert_balance_projection(&BalanceProjectionRecord {
            balance_key: format!("{}|{}", device_b32, "ERA"),
            device_id: device_b32.clone(),
            token_id: "ERA".to_string(),
            policy_commit: crate::util::text_id::encode_base32_crockford(&[0x33u8; 32]),
            available: 9,
            locked: 0,
            source_state_hash: crate::util::text_id::encode_base32_crockford(&failed_state.hash),
            source_state_number: failed_state.hash[0] as u64,
            updated_at: 0,
        })
        .expect("store projection");

        store_transaction(&TransactionRecord {
            tx_id: "tx-rollback".to_string(),
            tx_hash: crate::util::text_id::encode_base32_crockford(&failed_state.hash),
            from_device: device_b32.clone(),
            to_device: "peer".to_string(),
            amount: 9,
            tx_type: "online".to_string(),
            status: "confirmed".to_string(),
            chain_height: failed_state.hash[0] as u64,
            step_index: 1,
            commitment_hash: None,
            proof_data: None,
            metadata: HashMap::new(),
            created_at: 0,
        })
        .expect("store transaction");

        rollback_failed_online_send_atomic(
            &device,
            &failed_state.hash,
            "tx-rollback",
            &device_b32,
            "ERA",
        )
        .expect("rollback artifacts");

        assert!(
            get_bcr_states(&device, false)
                .expect("load bcr states")
                .into_iter()
                .all(|state| state.hash != failed_state.hash),
            "failed archived state must be removed"
        );
        assert!(
            get_balance_projection(&device_b32, "ERA")
                .expect("load projection")
                .is_none(),
            "failed balance projection must be removed"
        );
        assert!(
            get_transaction_history(Some(&device_b32), Some(20))
                .expect("load tx history")
                .into_iter()
                .all(|tx| tx.tx_id != "tx-rollback"),
            "failed transaction record must be removed"
        );
    }
}
