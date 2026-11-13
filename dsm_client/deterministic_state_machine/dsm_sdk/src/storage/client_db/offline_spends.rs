// SPDX-License-Identifier: Apache-2.0
//! This device's own offline account steps that no boundary of its online
//! history has exposed yet, per anchor bundle, in order.
//!
//! A contact holds this device's offline account as the last boundary of its
//! online history left it. Between boundaries the account moves by spends, by
//! its board's receive commits and by the unloads of payments received (owner,
//! 2026-11-07), and the next boundary carries every one of them, in order, as
//! its ancestry. A confirm carries the steps since that boundary, the spends
//! (SA-116) and the receives and unloads among them, and its receiver verifies
//! each as the account's own: a payer that received offline since goes on
//! paying offline from what it loaded (owner, 2026-11-13: "That is not a
//! rule"). A step is recorded in the transaction that commits it, and the
//! boundary that next carries the steps online takes them out with its own
//! admission.

use anyhow::{anyhow, Result};
use rusqlite::{params, Transaction};

use super::get_connection;

/// Record a step of the offline account under `bundle`, after every step recorded before it: `hop`
/// is its `OfflineAccountHop`'s canonical bytes.
pub fn record_own_offline_hop_in_tx(
    tx: &Transaction<'_>,
    bundle: &[u8; 32],
    hop: &dsm::types::offline_chain::AccountHop,
) -> Result<()> {
    tx.execute(
        "INSERT INTO own_offline_hop(bundle, seq, hop)
         VALUES (?1, (SELECT COALESCE(MAX(seq), 0) + 1 FROM own_offline_hop WHERE bundle = ?1), ?2)",
        params![bundle.as_slice(), hop.to_bytes()],
    )?;
    Ok(())
}

/// The steps under `bundle` no boundary has exposed, in order, each an `OfflineAccountHop`'s
/// canonical bytes.
pub fn own_offline_hops(bundle: &[u8; 32]) -> Result<Vec<Vec<u8>>> {
    let binding = get_connection()?;
    let conn = binding
        .lock()
        .map_err(|e| anyhow!("the client database lock: {e}"))?;
    let mut stmt =
        conn.prepare("SELECT hop FROM own_offline_hop WHERE bundle = ?1 ORDER BY seq ASC")?;
    let hops = stmt
        .query_map(params![bundle.as_slice()], |r| r.get::<_, Vec<u8>>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(hops)
}

/// The steps under `bundle` no boundary has exposed, read in the transaction of the boundary that
/// exposes them.
pub fn own_offline_hops_in_tx(tx: &Transaction<'_>, bundle: &[u8; 32]) -> Result<Vec<Vec<u8>>> {
    let mut stmt =
        tx.prepare("SELECT hop FROM own_offline_hop WHERE bundle = ?1 ORDER BY seq ASC")?;
    let hops = stmt
        .query_map(params![bundle.as_slice()], |r| r.get::<_, Vec<u8>>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(hops)
}

/// The boundary that carries `bundle`'s steps online exposes them: they leave the record, in the
/// boundary's own transaction.
pub fn expose_own_offline_hops_in_tx(tx: &Transaction<'_>, bundle: &[u8; 32]) -> Result<usize> {
    Ok(tx.execute(
        "DELETE FROM own_offline_hop WHERE bundle = ?1",
        params![bundle.as_slice()],
    )?)
}

/// Keep `acknowledgement`, the receiver board's receive commit of the step `commitment_hash`, in
/// the transaction that checks it (the payer) or that commits the receive (the receiver).
pub fn keep_acknowledgement_in_tx(
    tx: &Transaction<'_>,
    commitment_hash: &[u8; 32],
    acknowledgement: &[u8],
) -> Result<()> {
    keep(tx, commitment_hash, acknowledgement)
}

/// [`keep_acknowledgement_in_tx`] on its own: the payer keeps the acknowledgement it verified
/// before the step it acknowledges is filed. A step's acknowledgement is kept once; the same one
/// delivered again changes nothing, and another is refused.
pub fn keep_acknowledgement(commitment_hash: &[u8; 32], acknowledgement: &[u8]) -> Result<()> {
    let binding = get_connection()?;
    let conn = binding
        .lock()
        .map_err(|e| anyhow!("the client database lock: {e}"))?;
    keep(&conn, commitment_hash, acknowledgement)
}

fn keep(
    conn: &rusqlite::Connection,
    commitment_hash: &[u8; 32],
    acknowledgement: &[u8],
) -> Result<()> {
    use rusqlite::OptionalExtension;
    let held: Option<Vec<u8>> = conn
        .query_row(
            "SELECT acknowledgement FROM offline_acknowledgement WHERE commitment_hash = ?1",
            params![commitment_hash.as_slice()],
            |r| r.get(0),
        )
        .optional()?;
    match held {
        Some(kept) if kept == acknowledgement => Ok(()),
        Some(_) => Err(anyhow!(
            "another acknowledgement is kept for this step: one step has one receive"
        )),
        None => {
            conn.execute(
                "INSERT INTO offline_acknowledgement(commitment_hash, acknowledgement) \
                 VALUES (?1, ?2)",
                params![commitment_hash.as_slice(), acknowledgement],
            )?;
            Ok(())
        }
    }
}

/// The acknowledgement kept for the step `commitment_hash`, if one is.
pub fn acknowledgement(commitment_hash: &[u8; 32]) -> Result<Option<Vec<u8>>> {
    use rusqlite::OptionalExtension;
    let binding = get_connection()?;
    let conn = binding
        .lock()
        .map_err(|e| anyhow!("the client database lock: {e}"))?;
    Ok(conn
        .query_row(
            "SELECT acknowledgement FROM offline_acknowledgement WHERE commitment_hash = ?1",
            params![commitment_hash.as_slice()],
            |r| r.get::<_, Vec<u8>>(0),
        )
        .optional()?)
}

/// Close the offline accounts under `closed` with the head `head` that no longer holds them, in one
/// transaction: the head, the steps no boundary of theirs will ever carry, and the payments they
/// received offline, which waited in them for an unload that can no longer happen (an account
/// closed at an install is lost with its trial, owner 2026-11-08). Answers how many payments
/// received offline went with them.
pub fn close_offline_accounts(
    head: &dsm::types::device_state::DeviceState,
    closed: &[[u8; 32]],
) -> Result<usize> {
    let binding = get_connection()?;
    let mut conn = binding
        .lock()
        .map_err(|e| anyhow!("the client database lock: {e}"))?;
    let tx = conn.transaction()?;
    super::bcr::update_bcr_device_head_with_conn(&tx, head)?;
    let mut payments = 0;
    for bundle in closed {
        tx.execute(
            "DELETE FROM own_offline_hop WHERE bundle = ?1",
            params![bundle.as_slice()],
        )?;
        payments += tx.execute(
            "DELETE FROM pending_offline_receipt WHERE receiver_bundle = ?1",
            params![bundle.as_slice()],
        )?;
    }
    tx.commit()?;
    Ok(payments)
}
