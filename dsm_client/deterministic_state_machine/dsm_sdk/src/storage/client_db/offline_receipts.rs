// SPDX-License-Identifier: Apache-2.0

//! Value this device received offline, pending until it is settled online
//! (SA-91; the owner's rule that offline receipts stay unspendable until they
//! are validated online).
//!
//! A bearer step this device received credits nothing: it records the payment
//! here, in the transaction that commits the step, named by the root-advance
//! message `M` the payer's anchor signed. It is neither online balance nor
//! offline allocation, so it can be spent neither way. It is settled by an
//! admitted economic transition of its own once the payer's online history
//! exposes the spend (`economic_admission_flow::admitted_offline_settlement`),
//! which marks it settled in the transaction that makes the settlement
//! durable.

use anyhow::{anyhow, Result};
use rusqlite::{params, OptionalExtension, Transaction};

use super::get_connection;

/// One payment received offline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingOfflineReceipt {
    /// `M`, the root-advance message the payer's anchor signed for the spend.
    pub release_message: [u8; 32],
    pub payer_genesis: [u8; 32],
    pub payer_device: [u8; 32],
    /// The payer's anchor bundle.
    pub bundle: [u8; 32],
    pub asset: [u8; 32],
    pub amount: u64,
    /// The bilateral step that received it.
    pub commitment_hash: [u8; 32],
}

fn digest32(v: Vec<u8>, what: &str) -> Result<[u8; 32]> {
    <[u8; 32]>::try_from(v.as_slice()).map_err(|e| anyhow!("{what} is not 32 bytes: {e}"))
}

/// Record `receipt` as pending, in the transaction of the step that received it.
pub fn record_pending_offline_receipt_in_tx(
    tx: &Transaction<'_>,
    receipt: &PendingOfflineReceipt,
) -> Result<()> {
    tx.execute(
        "INSERT INTO pending_offline_receipt(
             release_message, payer_genesis, payer_devid, bundle, asset, amount,
             commitment_hash, settled_position)
         VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, NULL)",
        params![
            receipt.release_message.as_slice(),
            receipt.payer_genesis.as_slice(),
            receipt.payer_device.as_slice(),
            receipt.bundle.as_slice(),
            receipt.asset.as_slice(),
            i64::try_from(receipt.amount).map_err(|e| anyhow!("amount overflow: {e}"))?,
            receipt.commitment_hash.as_slice(),
        ],
    )?;
    Ok(())
}

type Row = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, i64, Vec<u8>);

fn receipt_of(r: Row) -> Result<PendingOfflineReceipt> {
    Ok(PendingOfflineReceipt {
        release_message: digest32(r.0, "a pending receipt's release message")?,
        payer_genesis: digest32(r.1, "a pending receipt's payer genesis")?,
        payer_device: digest32(r.2, "a pending receipt's payer")?,
        bundle: digest32(r.3, "a pending receipt's bundle")?,
        asset: digest32(r.4, "a pending receipt's asset")?,
        amount: u64::try_from(r.5).map_err(|e| anyhow!("a pending receipt's amount: {e}"))?,
        commitment_hash: digest32(r.6, "a pending receipt's step")?,
    })
}

fn row(r: &rusqlite::Row<'_>) -> rusqlite::Result<Row> {
    Ok((
        r.get(0)?,
        r.get(1)?,
        r.get(2)?,
        r.get(3)?,
        r.get(4)?,
        r.get(5)?,
        r.get(6)?,
    ))
}

const COLUMNS: &str =
    "release_message, payer_genesis, payer_devid, bundle, asset, amount, commitment_hash";

/// Every payment received offline and not yet settled, oldest step first.
pub fn pending_offline_receipts() -> Result<Vec<PendingOfflineReceipt>> {
    let binding = get_connection()?;
    let conn = binding
        .lock()
        .map_err(|e| anyhow!("the client database lock: {e}"))?;
    let mut stmt = conn.prepare(&format!(
        "SELECT {COLUMNS} FROM pending_offline_receipt WHERE settled_position IS NULL
         ORDER BY rowid ASC"
    ))?;
    let rows = stmt
        .query_map([], row)?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    rows.into_iter().map(receipt_of).collect()
}

/// The payment received offline under `release_message`, settled or not;
/// with the position of the settlement that settled it, if one did.
pub fn offline_receipt(
    release_message: &[u8; 32],
) -> Result<Option<(PendingOfflineReceipt, Option<u64>)>> {
    let binding = get_connection()?;
    let conn = binding
        .lock()
        .map_err(|e| anyhow!("the client database lock: {e}"))?;
    let found = conn
        .query_row(
            &format!(
                "SELECT {COLUMNS}, settled_position FROM pending_offline_receipt
                 WHERE release_message = ?1"
            ),
            params![release_message.as_slice()],
            |r| Ok((row(r)?, r.get::<_, Option<i64>>(7)?)),
        )
        .optional()?;
    found
        .map(|(r, settled)| {
            let settled = settled
                .map(|p| u64::try_from(p).map_err(|e| anyhow!("a settlement position: {e}")))
                .transpose()?;
            Ok((receipt_of(r)?, settled))
        })
        .transpose()
}

/// The value of `asset` received offline and not yet settled.
pub fn pending_offline_value(asset: &[u8; 32]) -> Result<u64> {
    pending_offline_receipts()?
        .iter()
        .filter(|r| r.asset == *asset)
        .try_fold(0u64, |total, r| {
            total
                .checked_add(r.amount)
                .ok_or_else(|| anyhow!("pending offline value overflows"))
        })
}

/// Mark the payment under `release_message` settled by the settlement at
/// `economic_position`, in the transaction that makes the settlement durable.
/// Refused unless exactly that payment is pending: a payment is settled once.
pub fn settle_offline_receipt_in_tx(
    tx: &Transaction<'_>,
    release_message: &[u8; 32],
    economic_position: u64,
) -> Result<()> {
    let moved = tx.execute(
        "UPDATE pending_offline_receipt SET settled_position = ?2
         WHERE release_message = ?1 AND settled_position IS NULL",
        params![
            release_message.as_slice(),
            i64::try_from(economic_position).map_err(|e| anyhow!("position overflow: {e}"))?
        ],
    )?;
    match moved {
        1 => Ok(()),
        _ => Err(anyhow!(
            "no pending offline receipt under this release to settle: it is settled already, \
             or was never received"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh() {
        crate::economic_fixtures::use_test_storage_dir();
        crate::storage::client_db::reset_database_for_tests();
    }

    fn received(mark: u8, amount: u64) -> PendingOfflineReceipt {
        PendingOfflineReceipt {
            release_message: [mark; 32],
            payer_genesis: [0x11; 32],
            payer_device: [0x12; 32],
            bundle: [0x13; 32],
            asset: [0x14; 32],
            amount,
            commitment_hash: [mark ^ 0x80; 32],
        }
    }

    fn in_tx(f: impl FnOnce(&Transaction<'_>) -> Result<()>) -> Result<()> {
        let binding = get_connection()?;
        let mut conn = binding
            .lock()
            .map_err(|e| anyhow!("the client database lock: {e}"))?;
        let tx = conn.transaction()?;
        f(&tx)?;
        tx.commit()?;
        Ok(())
    }

    /// SA-91: a payment received offline is pending until it is settled, and
    /// it is settled once. The value pending is what is received and not
    /// settled; a second settlement of the same payment is refused, and one of
    /// a payment never received is refused.
    /// MUTATION CONTROL: dropping `settled_position IS NULL` from the
    /// settlement's update lets the payment be settled twice and turns this red.
    #[test]
    #[serial_test::serial]
    fn a_payment_received_offline_is_pending_until_it_is_settled_once() {
        fresh();
        in_tx(|tx| record_pending_offline_receipt_in_tx(tx, &received(1, 7)))
            .expect("the first payment is recorded");
        in_tx(|tx| record_pending_offline_receipt_in_tx(tx, &received(2, 5)))
            .expect("the second payment is recorded");
        assert_eq!(pending_offline_value(&[0x14; 32]).expect("read"), 12);
        assert_eq!(
            pending_offline_receipts().expect("read"),
            vec![received(1, 7), received(2, 5)]
        );

        in_tx(|tx| settle_offline_receipt_in_tx(tx, &[1; 32], 9)).expect("settled once");
        assert_eq!(pending_offline_value(&[0x14; 32]).expect("read"), 5);
        assert_eq!(
            offline_receipt(&[1; 32]).expect("read"),
            Some((received(1, 7), Some(9)))
        );
        let again = in_tx(|tx| settle_offline_receipt_in_tx(tx, &[1; 32], 10))
            .expect_err("a payment settled again");
        assert!(again.to_string().contains("settled already"), "{again}");
        assert_eq!(
            offline_receipt(&[1; 32]).expect("read"),
            Some((received(1, 7), Some(9))),
            "the first settlement stands"
        );
        in_tx(|tx| settle_offline_receipt_in_tx(tx, &[3; 32], 11))
            .expect_err("a payment never received");

        let twice = in_tx(|tx| record_pending_offline_receipt_in_tx(tx, &received(2, 5)))
            .expect_err("the same payment received twice");
        assert!(twice.to_string().contains("UNIQUE"), "{twice}");
    }
}
