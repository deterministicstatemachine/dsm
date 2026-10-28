// SPDX-License-Identifier: Apache-2.0

//! This device's own offline-bearer spends that no boundary of its online
//! history has exposed yet, per anchor bundle, in counter order.
//!
//! A receiver holds this device's offline account as the last boundary of its
//! online history left it. A spend made since starts wherever the spends before
//! it brought the account, so each confirm carries this chain from that
//! boundary to the spend (SA-116). A spend is recorded in the transaction that
//! commits the step that made it, and the boundary that next carries the chain
//! online takes the spends out with its own admission.

use anyhow::{anyhow, Result};
use rusqlite::{params, Transaction};

use super::get_connection;

/// Record a spend this device's anchor released: `hop` is its
/// `OfflineSpendHop`, `anchor_counter` the counter it started from.
pub fn record_own_offline_spend_in_tx(
    tx: &Transaction<'_>,
    bundle: &[u8; 32],
    anchor_counter: u64,
    hop: &[u8],
) -> Result<()> {
    let counter = i64::try_from(anchor_counter)
        .map_err(|e| anyhow!("an offline spend's counter {anchor_counter}: {e}"))?;
    tx.execute(
        "INSERT INTO own_offline_spend(bundle, anchor_counter, hop) VALUES (?1, ?2, ?3)",
        params![bundle.as_slice(), counter, hop],
    )?;
    Ok(())
}

/// The spends under `bundle` no boundary has exposed, in counter order.
pub fn own_offline_spends(bundle: &[u8; 32]) -> Result<Vec<Vec<u8>>> {
    let binding = get_connection()?;
    let conn = binding
        .lock()
        .map_err(|e| anyhow!("the client database lock: {e}"))?;
    let mut stmt = conn.prepare(
        "SELECT hop FROM own_offline_spend WHERE bundle = ?1 ORDER BY anchor_counter ASC",
    )?;
    let hops = stmt
        .query_map(params![bundle.as_slice()], |r| r.get::<_, Vec<u8>>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(hops)
}

/// The spends under `bundle` no boundary has exposed, read in the
/// transaction of the boundary that exposes them.
pub fn own_offline_spends_in_tx(tx: &Transaction<'_>, bundle: &[u8; 32]) -> Result<Vec<Vec<u8>>> {
    let mut stmt = tx.prepare(
        "SELECT hop FROM own_offline_spend WHERE bundle = ?1 ORDER BY anchor_counter ASC",
    )?;
    let hops = stmt
        .query_map(params![bundle.as_slice()], |r| r.get::<_, Vec<u8>>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(hops)
}

/// The boundary that carries `bundle`'s spends online exposes them: they leave
/// the chain, in the boundary's own transaction.
pub fn expose_own_offline_spends_in_tx(tx: &Transaction<'_>, bundle: &[u8; 32]) -> Result<usize> {
    Ok(tx.execute(
        "DELETE FROM own_offline_spend WHERE bundle = ?1",
        params![bundle.as_slice()],
    )?)
}
