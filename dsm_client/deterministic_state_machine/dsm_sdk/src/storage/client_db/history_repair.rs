// SPDX-License-Identifier: MIT OR Apache-2.0
//! Durable queue for a history row the process failed to write after its
//! transaction committed.
//!
//! A faucet claim or an online send is real once its advance and its durable
//! bundle commit; the local history row that describes it can still fail to
//! write. Queueing the intent under `(device, token)` (the projection queue)
//! repairs a balance projection, never a history row: the projection sweep
//! rebuilds balances from the canonical head and knows nothing of the row.
//! So the intent here is the row itself, kept until the startup sweep writes
//! it through the same upsert the live path uses. Nothing is derived from the
//! queue but that write; losing a row costs a missing history line, never a
//! wrong balance.

use anyhow::Result;
use rusqlite::params;

use super::transactions::{transaction_from_row, TRANSACTION_COLUMNS};
use super::types::TransactionRecord;
use super::{get_connection, meta_to_blob, store_transaction};

/// Keep `row` to be written by the next sweep. Idempotent on `tx_id`.
pub fn enqueue_history_repair(row: &TransactionRecord, reason: &str) -> Result<()> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    conn.execute(
        "INSERT INTO history_repair_queue (
            tx_id, tx_hash, from_device, to_device, amount, tx_type,
            status, commitment_hash, proof_data, metadata, reason
        ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)
        ON CONFLICT(tx_id) DO UPDATE SET
            tx_hash = excluded.tx_hash,
            from_device = excluded.from_device,
            to_device = excluded.to_device,
            amount = excluded.amount,
            tx_type = excluded.tx_type,
            status = excluded.status,
            commitment_hash = excluded.commitment_hash,
            proof_data = excluded.proof_data,
            metadata = excluded.metadata,
            reason = excluded.reason",
        params![
            row.tx_id,
            row.tx_hash,
            row.from_device,
            row.to_device,
            row.amount as i64,
            row.tx_type,
            row.status,
            row.commitment_hash,
            row.proof_data,
            meta_to_blob(&row.metadata),
            reason,
        ],
    )?;
    Ok(())
}

/// Every row still waiting to be written, in the order it was queued.
pub fn pending_history_repairs() -> Result<Vec<TransactionRecord>> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    let mut stmt = conn.prepare(&format!(
        "SELECT {TRANSACTION_COLUMNS} FROM history_repair_queue ORDER BY rowid"
    ))?;
    let rows = stmt
        .query_map([], transaction_from_row)?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

/// Write every queued row through the live path's upsert and drop the ones
/// that landed. A row that still cannot be written stays for the next sweep.
/// Returns `(written, remaining)`.
pub fn drain_history_repairs() -> Result<(usize, usize)> {
    let pending = pending_history_repairs()?;
    let mut written = 0usize;
    for row in &pending {
        match store_transaction(row) {
            Ok(()) => {
                let binding = get_connection()?;
                let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
                conn.execute(
                    "DELETE FROM history_repair_queue WHERE tx_id = ?1",
                    params![row.tx_id],
                )?;
                written += 1;
            }
            Err(e) => log::warn!(
                "[history-repair] {} still cannot be written ({e}); retained",
                row.tx_id
            ),
        }
    }
    let remaining = pending_history_repairs()?.len();
    Ok((written, remaining))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::client_db::{get_transaction, init_database, reset_database_for_tests};
    use serial_test::serial;
    use std::collections::HashMap;

    fn row(tx_id: &str) -> TransactionRecord {
        let mut metadata = HashMap::new();
        metadata.insert("token_id".to_string(), b"ERA".to_vec());
        TransactionRecord {
            tx_id: tx_id.to_string(),
            tx_hash: format!("hash-{tx_id}"),
            from_device: String::new(),
            to_device: "device-c".to_string(),
            amount: 100,
            tx_type: "faucet".to_string(),
            status: "confirmed".to_string(),
            commitment_hash: None,
            proof_data: None,
            metadata,
        }
    }

    fn block_history_writes(block: bool) {
        let binding = get_connection().expect("connection");
        let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
        let sql = if block {
            "CREATE TRIGGER block_history BEFORE INSERT ON transactions \
             BEGIN SELECT RAISE(ABORT, 'injected history failure'); END;"
        } else {
            "DROP TRIGGER block_history;"
        };
        conn.execute_batch(sql).expect("toggle the trigger");
    }

    /// A history row that failed to write is written by the sweep, exactly
    /// once, as the row it was; while the write still fails it is retained.
    #[test]
    #[serial]
    fn a_queued_history_row_is_written_once_by_the_sweep_and_retained_while_it_cannot_be() {
        crate::economic_fixtures::use_test_storage_dir();
        reset_database_for_tests();
        init_database().expect("init db");

        block_history_writes(true);
        let wanted = row("faucet_1");
        assert!(store_transaction(&wanted).is_err(), "the injected failure");
        enqueue_history_repair(&wanted, "injected history failure").expect("queue");

        assert_eq!(drain_history_repairs().expect("drain"), (0, 1));
        assert!(get_transaction("faucet_1").expect("read").is_none());

        block_history_writes(false);
        assert_eq!(drain_history_repairs().expect("drain"), (1, 0));
        let written = get_transaction("faucet_1").expect("read").expect("written");
        assert_eq!(written.tx_hash, wanted.tx_hash);
        assert_eq!(written.to_device, wanted.to_device);
        assert_eq!(written.amount, wanted.amount);
        assert_eq!(written.tx_type, wanted.tx_type);
        assert_eq!(written.metadata, wanted.metadata);
        assert_eq!(drain_history_repairs().expect("drain"), (0, 0));
    }
}
