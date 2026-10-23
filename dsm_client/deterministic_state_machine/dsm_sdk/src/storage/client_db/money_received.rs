// SPDX-License-Identifier: MIT OR Apache-2.0
//! The received transfers the user has not opened the b0x inbox on yet: the
//! count on the app icon and on the b0x button (owner, 2026-10-23).
//!
//! A notice is written in the same database transaction as the history row of
//! a transfer this device verified and applied, so the count is only ever of
//! money that arrived — never of what a node holds or a sync pulled — and a
//! transfer is noticed once however many passes write its row. Notices are
//! numbered in the order they were written; the user's look is the newest
//! number they were shown. Outside the DSM protocol: it decides nothing.

use anyhow::{anyhow, Result};
use rusqlite::{params, Connection, OptionalExtension};

use super::get_connection;
use super::transactions::{transaction_from_row, upsert_transaction_row, TRANSACTION_COLUMNS};
use super::types::TransactionRecord;

/// The received transfers not yet looked at, newest first, and the newest
/// notice among them: what the user is shown, and what [`mark_seen`] is handed
/// back once they were. With nothing waiting, `through` is how far the user
/// has already looked.
pub struct MoneyWaiting {
    pub received: Vec<TransactionRecord>,
    pub through: u64,
}

/// Store a verified received transfer's history row and its notice, in one
/// transaction: neither is written without the other.
pub fn store_received_transfer(tx: &TransactionRecord) -> Result<()> {
    let binding = get_connection()?;
    let mut conn = binding
        .lock()
        .map_err(|e| anyhow!("the client database lock: {e}"))?;
    let db = conn.transaction()?;
    upsert_transaction_row(&db, tx)?;
    db.execute(
        "INSERT OR IGNORE INTO received_notices(tx_id) VALUES (?1)",
        params![tx.tx_id],
    )?;
    db.commit()?;
    Ok(())
}

/// How far the user has looked. The schema writes the one row, at 0 (no
/// notice numbered yet), with the table.
fn seen_through(conn: &Connection) -> Result<i64> {
    Ok(conn.query_row(
        "SELECT seen_through FROM received_notices_seen WHERE id = 1",
        [],
        |row| row.get(0),
    )?)
}

fn notice_number(seq: i64) -> Result<u64> {
    u64::try_from(seq).map_err(|e| anyhow!("notice number {seq} is not a count: {e}"))
}

/// What is waiting: every notice past the user's look, with its history row.
/// A notice whose row the history does not hold is an error, never skipped.
pub fn money_waiting() -> Result<MoneyWaiting> {
    let binding = get_connection()?;
    let conn = binding
        .lock()
        .map_err(|e| anyhow!("the client database lock: {e}"))?;
    let seen = seen_through(&conn)?;
    let notices: Vec<(i64, String)> = conn
        .prepare(
            "SELECT notice_seq, tx_id FROM received_notices
             WHERE notice_seq > ?1 ORDER BY notice_seq DESC",
        )?
        .query_map(params![seen], |row| Ok((row.get(0)?, row.get(1)?)))?
        .collect::<rusqlite::Result<_>>()?;
    let through = notice_number(notices.first().map_or(seen, |(seq, _)| *seq))?;
    let mut received = Vec::with_capacity(notices.len());
    for (seq, tx_id) in notices {
        let row = conn
            .query_row(
                &format!("SELECT {TRANSACTION_COLUMNS} FROM transactions WHERE tx_id = ?1"),
                params![tx_id],
                transaction_from_row,
            )
            .optional()?
            .ok_or_else(|| {
                anyhow!("received notice {seq} names {tx_id}, which the history does not hold")
            })?;
        received.push(row);
    }
    Ok(MoneyWaiting { received, through })
}

/// The user has looked at every notice up to `through` (what [`money_waiting`]
/// answered): those stop counting. A look never goes back, and never past a
/// notice that has been written — one written after the user was shown the
/// list still counts.
pub fn mark_seen(through: u64) -> Result<()> {
    let through =
        i64::try_from(through).map_err(|e| anyhow!("notice number {through} is too large: {e}"))?;
    let binding = get_connection()?;
    let conn = binding
        .lock()
        .map_err(|e| anyhow!("the client database lock: {e}"))?;
    let newest: i64 = conn.query_row(
        "SELECT COALESCE(MAX(notice_seq), 0) FROM received_notices",
        [],
        |row| row.get(0),
    )?;
    if through > newest {
        return Err(anyhow!(
            "received notice {through} has not been written: the newest is {newest}"
        ));
    }
    conn.execute(
        "UPDATE received_notices_seen SET seen_through = MAX(seen_through, ?1) WHERE id = 1",
        params![through],
    )?;
    Ok(())
}
