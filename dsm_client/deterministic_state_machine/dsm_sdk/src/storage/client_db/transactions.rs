// SPDX-License-Identifier: MIT OR Apache-2.0
//! Transaction history persistence.

use anyhow::Result;
use log::info;
use rusqlite::{params, Connection, OptionalExtension, Row};

use super::get_connection;
use super::tokens::{upsert_balance_projection_with_conn, BalanceProjectionRecord};
use super::types::TransactionRecord;
use crate::storage::codecs::{meta_from_blob, meta_to_blob};

fn upsert_transaction_row(conn: &Connection, tx: &TransactionRecord) -> Result<usize> {
    let affected = conn.execute(
        "INSERT INTO transactions (
            tx_id, tx_hash, from_device, to_device, amount, tx_type,
            status, commitment_hash, proof_data, metadata
        ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)
        ON CONFLICT(tx_id) DO UPDATE SET
            tx_hash = excluded.tx_hash,
            from_device = excluded.from_device,
            to_device = excluded.to_device,
            amount = excluded.amount,
            tx_type = excluded.tx_type,
            status = excluded.status,
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
            tx.commitment_hash.as_deref(),
            tx.proof_data.as_deref(),
            meta_to_blob(&tx.metadata),
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

    let txdb = conn.transaction()?;

    let token = token_id.unwrap_or("ERA");

    let affected = upsert_transaction_row(&txdb, tx)?;
    txdb.execute(
        "INSERT OR REPLACE INTO bilateral_sender_settlements(
            tx_id, sender_device_id
         ) VALUES (?1, ?2)",
        params![tx.tx_id, sender_device_id],
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

pub struct BilateralSenderSettlementBundle<'a> {
    pub counterparty_device_id: &'a [u8],
    pub new_chain_tip: &'a [u8],
    pub sender_device_id: &'a str,
    pub token_id: Option<&'a str>,
    pub amount: u64,
    pub tx: &'a TransactionRecord,
    pub projection: Option<&'a BalanceProjectionRecord>,
}

/// Atomic sender-side settlement persistence (§4.2 full-persistence boundary):
/// - Advance contact `chain_tip` + `local_bilateral_chain_tip` to the new symmetric h_{n+1}.
/// - Upsert optional balance projection (display cache; non-authoritative).
/// - Upsert the transaction history row.
/// - Record the sender-settlements idempotency row.
///
/// Single SQLite transaction; fail-closed on any row error. Replaces the
/// previous two-step pattern of `apply_sender_settlement_bundle_atomic`
/// followed by a separate `bilateral_tip_sync::sync_bilateral_tips_atomically`
/// contacts.chain_tip write — those two writes could interleave, leaving a
/// "tip advanced but no history" window.
///
/// Canonical state (chain state + device head) is written upstream at the
/// `AdvanceOutcome` chokepoint (`CoreSDK::execute_on_relationship` →
/// `dual_write_advance_outcome`). This function MUST NOT touch any
/// canonical-state table.
pub fn apply_bilateral_settlement_bundle_atomic(
    bundle: BilateralSenderSettlementBundle<'_>,
) -> Result<()> {
    let binding = get_connection()?;
    let mut conn = binding.lock().unwrap_or_else(|poisoned| {
        log::warn!("DB lock poisoned in apply_bilateral_settlement_bundle_atomic, recovering");
        poisoned.into_inner()
    });

    let txdb = conn.transaction()?;
    let token = bundle.token_id.unwrap_or("ERA");

    // 1. Advance contact chain_tip to the new symmetric h_{n+1}.
    txdb.execute(
        "UPDATE contacts SET
            previous_chain_tip = chain_tip,
            chain_tip = ?1,
            local_bilateral_chain_tip = ?1,
            observed_remote_chain_tip = NULL,
            observed_remote_tip_source = NULL,
            needs_online_reconcile = 0,
            status = CASE
                WHEN status = 'BleCapable' THEN 'BleCapable'
                ELSE 'OnlineCapable'
            END
         WHERE device_id = ?2",
        params![bundle.new_chain_tip, bundle.counterparty_device_id],
    )?;

    // 2. Balance projection (display cache only).
    if let Some(record) = bundle.projection {
        upsert_balance_projection_with_conn(&txdb, record)?;
    }

    // 3. Transaction history row.
    let affected = upsert_transaction_row(&txdb, bundle.tx)?;

    // 4. Sender-settlements idempotency row.
    txdb.execute(
        "INSERT OR REPLACE INTO bilateral_sender_settlements(
            tx_id, sender_device_id
         ) VALUES (?1, ?2)",
        params![bundle.tx.tx_id, bundle.sender_device_id],
    )?;

    txdb.commit()?;

    if affected > 0 {
        info!(
            "Atomic bilateral sender bundle stored (tip+projection+history+bookkeeping): device={} token={} amount={} tx_id={}",
            bundle.sender_device_id, token, bundle.amount, bundle.tx.tx_id
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

    let txdb = conn.transaction()?;

    // 1. Advance chain tip (mirrors update_finalized_bilateral_chain_tip)
    txdb.execute(
        "UPDATE contacts SET
            previous_chain_tip = chain_tip,
            chain_tip = ?1,
            local_bilateral_chain_tip = ?1,
            observed_remote_chain_tip = NULL,
            observed_remote_tip_source = NULL,
            needs_online_reconcile = 0,
            status = CASE
                WHEN status = 'BleCapable' THEN 'BleCapable'
                ELSE 'OnlineCapable'
            END
         WHERE device_id = ?2",
        params![new_chain_tip, counterparty_device_id],
    )?;

    // 2. Store transaction history
    let affected = upsert_transaction_row(&txdb, tx)?;
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
    pub projection: Option<&'a BalanceProjectionRecord>,
}

/// Atomic receiver-side settlement persistence: contact chain-tip CAS,
/// optional balance projection (display cache), and transaction history.
///
/// Canonical state (chain state + device head) is written upstream at the
/// `AdvanceOutcome` chokepoint. This function MUST NOT touch any
/// canonical-state table.
pub fn apply_receiver_confirm_bundle_atomic(bundle: ReceiverConfirmBundle<'_>) -> Result<()> {
    let binding = get_connection()?;
    let mut conn = binding.lock().unwrap_or_else(|poisoned| {
        log::warn!("DB lock poisoned in apply_receiver_confirm_bundle_atomic, recovering");
        poisoned.into_inner()
    });

    let txdb = conn.transaction()?;

    txdb.execute(
        "UPDATE contacts SET
            previous_chain_tip = chain_tip,
            chain_tip = ?1,
            local_bilateral_chain_tip = ?1,
            observed_remote_chain_tip = NULL,
            observed_remote_tip_source = NULL,
            needs_online_reconcile = 0,
            status = CASE
                WHEN status = 'BleCapable' THEN 'BleCapable'
                ELSE 'OnlineCapable'
            END
         WHERE device_id = ?2",
        params![bundle.new_chain_tip, bundle.counterparty_device_id],
    )?;

    if let Some(record) = bundle.projection {
        upsert_balance_projection_with_conn(&txdb, record)?;
    }

    let affected = upsert_transaction_row(&txdb, bundle.tx)?;
    txdb.commit()?;

    if affected > 0 {
        info!(
            "Atomic receiver settlement bundle stored (tip+history): device={} token={:?} amount={} tx_id={}",
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
    // Upsert by tx_id so we can safely backfill missing proof_data when a transaction
    // is first stored without a receipt and finalized later with stitched bytes.
    // Important: never downgrade proof_data from non-empty to empty.
    let affected = upsert_transaction_row(&conn, tx)?;
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

/// Check whether sender-side settlement already completed for a specific local device.
///
/// Sender idempotency must be scoped to the local device, not just `tx_id`.
/// In production each device has its own DB, but single-process integration
/// tests share one SQLite instance, so the receiver's completed transaction row
/// must not suppress the sender's settlement bundle.
/// True if a transaction row for this `tx_id` already exists — i.e. we already
/// applied and recorded this exact transfer. Used to recognize a stale-route
/// re-delivery of an already-accepted transition so it can be re-ACKed (releasing
/// the sender's pending online gate) instead of silently skipped and stranded.
pub fn transaction_exists(tx_id: &str) -> bool {
    let binding = match get_connection() {
        Ok(b) => b,
        Err(_) => return false,
    };
    let conn = binding.lock().unwrap_or_else(|poisoned| {
        log::warn!("DB lock poisoned, recovering");
        poisoned.into_inner()
    });
    conn.query_row(
        "SELECT 1 FROM transactions WHERE tx_id = ?1 LIMIT 1",
        params![tx_id],
        |_| Ok(true),
    )
    .unwrap_or(false)
}

pub fn is_sender_settlement_completed(tx_id: &str, sender_device_id: &str) -> Result<bool> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|poisoned| {
        log::warn!("DB lock poisoned, recovering");
        poisoned.into_inner()
    });
    Ok(conn
        .query_row(
            "SELECT 1 FROM bilateral_sender_settlements
             WHERE tx_id = ?1 AND sender_device_id = ?2
             LIMIT 1",
            params![tx_id, sender_device_id],
            |_| Ok(()),
        )
        .optional()?
        .is_some())
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
        Some(0) | None => 100,
        Some(n) => n,
    };
    let lim = i64::try_from(lim).map_err(|e| anyhow::anyhow!("history limit: {e}"))?;

    let map_row = |row: &Row| -> rusqlite::Result<TransactionRecord> {
        let meta_blob: Vec<u8> = row.get(9)?;
        let metadata = meta_from_blob(&meta_blob).map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(
                9,
                rusqlite::types::Type::Blob,
                format!("transaction metadata: {e}").into(),
            )
        })?;
        let tx_type: String = row.get(5)?;
        let proof_data = match row.get::<_, Option<Vec<u8>>>(8)? {
            Some(_) if tx_type == "unilateral_send" => None,
            other => other,
        };
        Ok(TransactionRecord {
            tx_id: row.get(0)?,
            tx_hash: row.get(1)?,
            from_device: row.get(2)?,
            to_device: row.get(3)?,
            amount: row.get::<_, i64>(4)? as u64,
            tx_type,
            status: row.get(6)?,
            commitment_hash: row.get::<_, Option<Vec<u8>>>(7)?,
            proof_data,
            metadata,
        })
    };

    // Newest first, in the order this device recorded them.
    const COLS: &str = "tx_id, tx_hash, from_device, to_device, amount, tx_type, status, \
                        commitment_hash, proof_data, metadata";
    let rows = match device_id {
        Some(d) => conn
            .prepare(&format!(
                "SELECT {COLS} FROM transactions WHERE from_device = ?1 OR to_device = ?1 \
                 ORDER BY rowid DESC LIMIT ?2"
            ))?
            .query_map(params![d, lim], map_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?,
        None => conn
            .prepare(&format!(
                "SELECT {COLS} FROM transactions ORDER BY rowid DESC LIMIT ?1"
            ))?
            .query_map(params![lim], map_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?,
    };
    Ok(rows)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::client_db::types::TransactionRecord;
    use crate::storage::client_db::{get_transaction_history, init_database, reset_database_for_tests};
    use serial_test::serial;
    use std::collections::HashMap;

    #[test]
    #[serial]
    fn sender_settlement_clears_stale_live_peer_claim() {
        crate::economic_fixtures::use_test_storage_dir();
        reset_database_for_tests();
        init_database().expect("init db");

        let counterparty_device_id = [0x51u8; 32];
        let counterparty_genesis = [0x61u8; 32];
        let stale_tip = [0x71u8; 32];
        let observed_tip = [0x81u8; 32];
        let settled_tip = [0x91u8; 32];
        let local_device = [0xA1u8; 32];
        let local_b32 = crate::util::text_id::encode_base32_crockford(&local_device);
        let counterparty_b32 =
            crate::util::text_id::encode_base32_crockford(&counterparty_device_id);

        crate::storage::client_db::store_contact(&crate::storage::client_db::ContactRecord {
            contact_id: "sender-contact".to_string(),
            device_id: counterparty_device_id.to_vec(),
            alias: "sender-peer".to_string(),
            genesis_hash: counterparty_genesis.to_vec(),
            public_key: vec![0x11; 32],
            kyber_public_key: vec![0x4B; 1184],
            current_chain_tip: Some(stale_tip.to_vec()),
            verified: true,
            verification_proof: None,
            metadata: HashMap::new(),
            ble_address: None,
            status: "BleCapable".to_string(),
            needs_online_reconcile: true,
            previous_chain_tip: None,
        })
        .expect("store contact");
        crate::storage::client_db::update_local_bilateral_chain_tip(
            &counterparty_device_id,
            &stale_tip,
        )
        .expect("seed local tip");
        crate::storage::client_db::record_observed_remote_chain_tip(
            &counterparty_device_id,
            &observed_tip,
            crate::storage::client_db::ObservedRemoteTipSource::LivePeerClaim,
        )
        .expect("record observed tip");

        let tx = TransactionRecord {
            tx_id: "sender-settlement".to_string(),
            tx_hash: crate::util::text_id::encode_base32_crockford(&settled_tip),
            from_device: local_b32.clone(),
            to_device: counterparty_b32,
            amount: 7,
            tx_type: "bilateral_offline".to_string(),
            status: "completed".to_string(),
            commitment_hash: None,
            proof_data: None,
            metadata: HashMap::new(),
        };

        apply_bilateral_settlement_bundle_atomic(BilateralSenderSettlementBundle {
            counterparty_device_id: &counterparty_device_id,
            new_chain_tip: &settled_tip,
            sender_device_id: &local_b32,
            token_id: None,
            amount: 7,
            tx: &tx,
            projection: None,
        })
        .expect("apply sender bundle");

        assert!(
            crate::storage::client_db::get_observed_remote_tip_record(&counterparty_device_id)
                .expect("load observed tip")
                .is_none(),
            "successful sender settlement should retire stale live-peer claims"
        );

        let stored = crate::storage::client_db::get_contact_by_device_id(&counterparty_device_id)
            .expect("load contact")
            .expect("contact exists");
        assert_eq!(stored.current_chain_tip, Some(settled_tip.to_vec()));
        assert!(!stored.needs_online_reconcile);
        assert_eq!(
            crate::storage::client_db::get_local_bilateral_chain_tip(&counterparty_device_id)
                .expect("read tip"),
            Some(settled_tip)
        );
    }

    #[test]
    #[serial]
    fn receiver_settlement_clears_stale_live_peer_claim() {
        crate::economic_fixtures::use_test_storage_dir();
        reset_database_for_tests();
        init_database().expect("init db");

        let counterparty_device_id = [0x52u8; 32];
        let counterparty_genesis = [0x62u8; 32];
        let stale_tip = [0x72u8; 32];
        let observed_tip = [0x82u8; 32];
        let settled_tip = [0x92u8; 32];
        let local_device = [0xA2u8; 32];
        let local_b32 = crate::util::text_id::encode_base32_crockford(&local_device);
        let counterparty_b32 =
            crate::util::text_id::encode_base32_crockford(&counterparty_device_id);

        crate::storage::client_db::store_contact(&crate::storage::client_db::ContactRecord {
            contact_id: "receiver-contact".to_string(),
            device_id: counterparty_device_id.to_vec(),
            alias: "receiver-peer".to_string(),
            genesis_hash: counterparty_genesis.to_vec(),
            public_key: vec![0x22; 32],
            kyber_public_key: vec![0x4B; 1184],
            current_chain_tip: Some(stale_tip.to_vec()),
            verified: true,
            verification_proof: None,
            metadata: HashMap::new(),
            ble_address: None,
            status: "BleCapable".to_string(),
            needs_online_reconcile: true,
            previous_chain_tip: None,
        })
        .expect("store contact");
        crate::storage::client_db::update_local_bilateral_chain_tip(
            &counterparty_device_id,
            &stale_tip,
        )
        .expect("seed local tip");
        crate::storage::client_db::record_observed_remote_chain_tip(
            &counterparty_device_id,
            &observed_tip,
            crate::storage::client_db::ObservedRemoteTipSource::LivePeerClaim,
        )
        .expect("record observed tip");

        let tx = TransactionRecord {
            tx_id: "receiver-settlement".to_string(),
            tx_hash: crate::util::text_id::encode_base32_crockford(&settled_tip),
            from_device: counterparty_b32,
            to_device: local_b32.clone(),
            amount: 9,
            tx_type: "bilateral_offline".to_string(),
            status: "completed".to_string(),
            commitment_hash: None,
            proof_data: None,
            metadata: HashMap::new(),
        };

        apply_receiver_confirm_bundle_atomic(ReceiverConfirmBundle {
            counterparty_device_id: &counterparty_device_id,
            new_chain_tip: &settled_tip,
            receiver_device_id: &local_b32,
            token_id: None,
            amount: 9,
            tx: &tx,
            projection: None,
        })
        .expect("apply receiver bundle");

        assert!(
            crate::storage::client_db::get_observed_remote_tip_record(&counterparty_device_id)
                .expect("load observed tip")
                .is_none(),
            "successful receiver settlement should retire stale live-peer claims"
        );

        let stored = crate::storage::client_db::get_contact_by_device_id(&counterparty_device_id)
            .expect("load contact")
            .expect("contact exists");
        assert_eq!(stored.current_chain_tip, Some(settled_tip.to_vec()));
        assert!(!stored.needs_online_reconcile);
        assert_eq!(
            crate::storage::client_db::get_local_bilateral_chain_tip(&counterparty_device_id)
                .expect("read tip"),
            Some(settled_tip)
        );
    }

    #[test]
    #[serial]
    fn unilateral_history_suppresses_proof_data() {
        crate::economic_fixtures::use_test_storage_dir();
        reset_database_for_tests();
        init_database().expect("init db");

        let device = crate::util::text_id::encode_base32_crockford(&[0x31u8; 32]);
        let counterparty = crate::util::text_id::encode_base32_crockford(&[0x32u8; 32]);

        store_transaction(&TransactionRecord {
            tx_id: "unilateral-proof".to_string(),
            tx_hash: crate::util::text_id::encode_base32_crockford(&[0x41u8; 32]),
            from_device: device.clone(),
            to_device: counterparty,
            amount: 5,
            tx_type: "unilateral_send".to_string(),
            status: "submitted".to_string(),
            commitment_hash: None,
            proof_data: Some(vec![0xAA; 12]),
            metadata: HashMap::new(),
        })
        .expect("store unilateral transaction");

        let history = get_transaction_history(Some(&device), Some(10)).expect("load tx history");
        let unilateral = history
            .into_iter()
            .find(|tx| tx.tx_id == "unilateral-proof")
            .expect("unilateral tx in history");

        assert!(
            unilateral.proof_data.is_none(),
            "unilateral proof_data should not surface in history"
        );
    }
}
