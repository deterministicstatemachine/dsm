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

/// How a relationship step's tip write ended when it did not refuse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TipAdvance {
    /// The tip moved from the step's parent to its child.
    Applied,
    /// The tip is already the step's child, moved there by this same step.
    AlreadyApplied,
}

/// Move the relationship tip with `counterparty` from `parent` to `child`,
/// recording the step `commitment` that moved it — inside `conn`, the
/// transaction the step commits in. Idempotent: when the tip is not
/// `parent`, it is read again, and a tip that is already `child` under the
/// same commitment is [`TipAdvance::AlreadyApplied`]; any other tip is a
/// conflict and nothing is written.
pub(crate) fn advance_relationship_tip_in_tx(
    conn: &Connection,
    counterparty: &[u8; 32],
    parent: &[u8; 32],
    child: &[u8; 32],
    commitment: &[u8; 32],
) -> Result<TipAdvance> {
    let moved = conn.execute(
        "UPDATE contacts SET
            previous_chain_tip = chain_tip,
            chain_tip = ?1,
            local_bilateral_chain_tip = ?1,
            chain_tip_commitment = ?2,
            observed_remote_chain_tip = NULL,
            observed_remote_tip_source = NULL,
            needs_online_reconcile = 0,
            status = CASE
                WHEN status = 'BleCapable' THEN 'BleCapable'
                ELSE 'OnlineCapable'
            END
         WHERE device_id = ?3 AND chain_tip = ?4",
        params![&child[..], &commitment[..], &counterparty[..], &parent[..]],
    )?;
    if moved == 1 {
        return Ok(TipAdvance::Applied);
    }
    let (tip, bound): (Option<Vec<u8>>, Option<Vec<u8>>) = conn
        .query_row(
            "SELECT chain_tip, chain_tip_commitment FROM contacts WHERE device_id = ?1",
            params![&counterparty[..]],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?
        .ok_or_else(|| anyhow::anyhow!("relationship tip: the counterparty is not a contact"))?;
    if tip.as_deref() == Some(&child[..]) && bound.as_deref() == Some(&commitment[..]) {
        return Ok(TipAdvance::AlreadyApplied);
    }
    Err(anyhow::anyhow!(
        "relationship tip conflict: the tip is neither this step's parent nor its child under \
         this step's commitment"
    ))
}

/// A relationship step's effects outside the device head: its tip, its
/// balance projection (a display cache) and its history row.
pub(crate) struct SettledStep<'a> {
    pub counterparty_device_id: &'a [u8; 32],
    pub parent_tip: &'a [u8; 32],
    pub child_tip: &'a [u8; 32],
    pub commitment_hash: &'a [u8; 32],
    pub tx: &'a TransactionRecord,
    pub projection: Option<&'a BalanceProjectionRecord>,
}

/// Write a step's effects inside `conn`, the transaction its canonical
/// advance commits in, so the head and the relationship cannot disagree. A
/// step already applied is refused here: in the same transaction the head
/// would otherwise take it twice.
pub(crate) fn settle_step_in_tx(conn: &Connection, step: &SettledStep<'_>) -> Result<()> {
    match advance_relationship_tip_in_tx(
        conn,
        step.counterparty_device_id,
        step.parent_tip,
        step.child_tip,
        step.commitment_hash,
    )? {
        TipAdvance::Applied => {}
        TipAdvance::AlreadyApplied => {
            return Err(anyhow::anyhow!(
                "relationship step already applied: nothing is written again"
            ))
        }
    }
    if let Some(record) = step.projection {
        upsert_balance_projection_with_conn(conn, record)?;
    }
    upsert_transaction_row(conn, step.tx)?;
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

    /// Runs `f` in one transaction and commits it — as the step's advance does.
    fn in_tx<T>(f: impl FnOnce(&Connection) -> Result<T>) -> Result<T> {
        let binding = get_connection()?;
        let mut conn = binding.lock().unwrap_or_else(|p| p.into_inner());
        let tx = conn.transaction()?;
        let out = f(&tx)?;
        tx.commit()?;
        Ok(out)
    }

    fn contact_at(counterparty: [u8; 32], tip: [u8; 32]) {
        crate::storage::client_db::store_contact(&crate::storage::client_db::ContactRecord {
            contact_id: "peer".to_string(),
            device_id: counterparty.to_vec(),
            alias: "peer".to_string(),
            genesis_hash: vec![0x61u8; 32],
            public_key: vec![0x11; 32],
            kyber_public_key: vec![0x4B; 1184],
            current_chain_tip: Some(tip.to_vec()),
            verified: true,
            verification_proof: None,
            metadata: HashMap::new(),
            ble_address: None,
            status: "BleCapable".to_string(),
            needs_online_reconcile: true,
            previous_chain_tip: None,
        })
        .expect("store contact");
    }

    fn history_row(tx_id: &str) -> TransactionRecord {
        TransactionRecord {
            tx_id: tx_id.to_string(),
            tx_hash: tx_id.to_string(),
            from_device: "from".to_string(),
            to_device: "to".to_string(),
            amount: 7,
            tx_type: "bilateral_offline".to_string(),
            status: "completed".to_string(),
            commitment_hash: None,
            proof_data: None,
            metadata: HashMap::new(),
        }
    }

    /// A settled step moves the relationship tip from its parent to its child
    /// and writes its history row in the same transaction; the reconcile hold
    /// and a stale live-peer claim are retired with it.
    #[test]
    #[serial]
    fn a_settled_step_moves_the_tip_and_writes_its_history_together() {
        crate::economic_fixtures::use_test_storage_dir();
        reset_database_for_tests();
        init_database().expect("init db");
        let counterparty = [0x51u8; 32];
        let (parent, child, commitment) = ([0x71u8; 32], [0x91u8; 32], [0xC1u8; 32]);
        contact_at(counterparty, parent);
        crate::storage::client_db::record_observed_remote_chain_tip(
            &counterparty,
            &[0x81u8; 32],
            crate::storage::client_db::ObservedRemoteTipSource::LivePeerClaim,
        )
        .expect("record observed tip");

        let row = history_row("step-1");
        in_tx(|tx| {
            settle_step_in_tx(
                tx,
                &SettledStep {
                    counterparty_device_id: &counterparty,
                    parent_tip: &parent,
                    child_tip: &child,
                    commitment_hash: &commitment,
                    tx: &row,
                    projection: None,
                },
            )
        })
        .expect("settle the step");

        let stored = crate::storage::client_db::get_contact_by_device_id(&counterparty)
            .expect("load contact")
            .expect("contact exists");
        assert_eq!(stored.current_chain_tip, Some(child.to_vec()));
        assert!(!stored.needs_online_reconcile);
        assert_eq!(
            crate::storage::client_db::get_local_bilateral_chain_tip(&counterparty)
                .expect("read tip"),
            Some(child)
        );
        assert!(
            crate::storage::client_db::get_observed_remote_tip_record(&counterparty)
                .expect("load observed tip")
                .is_none()
        );
        assert!(transaction_exists("step-1"));

        // The same step again is refused as already applied, and writes nothing.
        let again = history_row("step-1-again");
        let err = in_tx(|tx| {
            settle_step_in_tx(
                tx,
                &SettledStep {
                    counterparty_device_id: &counterparty,
                    parent_tip: &parent,
                    child_tip: &child,
                    commitment_hash: &commitment,
                    tx: &again,
                    projection: None,
                },
            )
        })
        .expect_err("a step already applied is not applied again");
        assert!(err.to_string().contains("already applied"), "{err}");
        assert!(!transaction_exists("step-1-again"));
    }

    /// The tip is a compare-and-set bound to the step: it moves only from the
    /// step's parent; a replay of the same step is `AlreadyApplied`; the same
    /// child claimed under another commitment, or a parent the tip no longer
    /// holds, is a conflict and moves nothing. MUTATION CONTROL: dropping the
    /// commitment from the replay check reads the foreign step as already
    /// applied and turns this red.
    #[test]
    #[serial]
    fn the_tip_moves_only_from_the_steps_parent_and_a_replay_is_recognised() {
        crate::economic_fixtures::use_test_storage_dir();
        reset_database_for_tests();
        init_database().expect("init db");
        let counterparty = [0x52u8; 32];
        let (parent, child, commitment) = ([0x72u8; 32], [0x92u8; 32], [0xC2u8; 32]);
        contact_at(counterparty, parent);
        let advance = |p: [u8; 32], c: [u8; 32], k: [u8; 32]| {
            in_tx(|tx| advance_relationship_tip_in_tx(tx, &counterparty, &p, &c, &k))
        };

        assert_eq!(
            advance(parent, child, commitment).expect("from its parent"),
            TipAdvance::Applied
        );
        assert_eq!(
            advance(parent, child, commitment).expect("the same step again"),
            TipAdvance::AlreadyApplied
        );
        let foreign = advance(parent, child, [0xC3u8; 32])
            .expect_err("the same child under another commitment is a conflict");
        assert!(foreign.to_string().contains("conflict"), "{foreign}");
        let stale = advance([0x7Fu8; 32], [0x93u8; 32], [0xC4u8; 32])
            .expect_err("a parent the tip no longer holds is a conflict");
        assert!(stale.to_string().contains("conflict"), "{stale}");
        assert_eq!(
            crate::storage::client_db::get_contact_chain_tip(&counterparty).expect("read"),
            Some(child),
            "a refused step moved the tip"
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
