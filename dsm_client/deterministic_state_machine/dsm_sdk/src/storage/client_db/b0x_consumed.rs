// SPDX-License-Identifier: MIT OR Apache-2.0

//! Which b0x messages this device has consumed — the device's own state.
//!
//! A storage node's spool is append-only: it never marks, hides, expires or
//! removes a message (storage spec §4; owner, 2026-09-23). What a device has
//! already consumed is kept here, on the device, where no one else can change
//! it:
//!
//! - `b0x_consumed`: every message id this device has consumed from an inbox.
//!   A consumer records exactly the messages it processed; a message it left
//!   (one half of a pair still waiting for the other) stays unrecorded and is
//!   read again.
//! - `b0x_read_position`: per inbox and per node, the spool position below
//!   which every message is consumed. Each node numbers its own spool, so a
//!   position belongs to one node. It only moves forward.

use anyhow::{anyhow, Result};
use rusqlite::{params, OptionalExtension};

use super::get_connection;

/// Record `message_ids` (base32 transport ids) as consumed from `address`.
/// Idempotent: recording an id twice changes nothing.
pub fn record_consumed(address: &str, message_ids: &[String]) -> Result<()> {
    if message_ids.is_empty() {
        return Ok(());
    }
    let binding = get_connection()?;
    let mut conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    let tx = conn.transaction()?;
    {
        let mut stmt = tx.prepare_cached(
            "INSERT OR IGNORE INTO b0x_consumed(address, message_id) VALUES (?1, ?2)",
        )?;
        for id in message_ids {
            stmt.execute(params![address, id])?;
        }
    }
    tx.commit()?;
    Ok(())
}

/// Whether `message_id` has been consumed from `address` on this device.
pub fn is_consumed(address: &str, message_id: &str) -> Result<bool> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    let found: Option<i64> = conn
        .query_row(
            "SELECT 1 FROM b0x_consumed WHERE address = ?1 AND message_id = ?2",
            params![address, message_id],
            |r| r.get(0),
        )
        .optional()?;
    Ok(found.is_some())
}

/// The position on `endpoint`'s spool for `address` from which to read: every
/// message below it is consumed. Zero when nothing has been read there.
pub fn read_position(address: &str, endpoint: &str) -> Result<u64> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    let pos: Option<i64> = conn
        .query_row(
            "SELECT next_seq FROM b0x_read_position WHERE address = ?1 AND endpoint = ?2",
            params![address, endpoint],
            |r| r.get(0),
        )
        .optional()?;
    match pos {
        None => Ok(0),
        Some(p) => u64::try_from(p).map_err(|_| anyhow!("b0x_read_position holds a negative position")),
    }
}

/// Move the read position for `address` on `endpoint` forward to `next_seq`.
/// A position never moves back: an older value is ignored.
pub fn advance_read_position(address: &str, endpoint: &str, next_seq: u64) -> Result<()> {
    let next = i64::try_from(next_seq).map_err(|_| anyhow!("b0x read position exceeds i64"))?;
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    conn.execute(
        "INSERT INTO b0x_read_position(address, endpoint, next_seq) VALUES (?1, ?2, ?3)
         ON CONFLICT(address, endpoint) DO UPDATE SET next_seq = excluded.next_seq
         WHERE excluded.next_seq > b0x_read_position.next_seq",
        params![address, endpoint, next],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh() {
        crate::storage::client_db::reset_database_for_tests();
    }

    #[test]
    #[serial_test::serial]
    fn consumed_messages_are_remembered_per_inbox() {
        fresh();
        record_consumed("INBOX-A", &["M1".into(), "M2".into()]).unwrap();
        record_consumed("INBOX-A", &["M1".into()]).unwrap();
        assert!(is_consumed("INBOX-A", "M1").unwrap());
        assert!(is_consumed("INBOX-A", "M2").unwrap());
        assert!(!is_consumed("INBOX-A", "M3").unwrap());
        assert!(!is_consumed("INBOX-B", "M1").unwrap(), "another inbox is its own record");
    }

    #[test]
    #[serial_test::serial]
    fn a_read_position_is_per_node_and_only_moves_forward() {
        fresh();
        assert_eq!(read_position("INBOX-A", "https://n1").unwrap(), 0);
        advance_read_position("INBOX-A", "https://n1", 7).unwrap();
        advance_read_position("INBOX-A", "https://n1", 3).unwrap();
        assert_eq!(read_position("INBOX-A", "https://n1").unwrap(), 7);
        assert_eq!(read_position("INBOX-A", "https://n2").unwrap(), 0, "each node numbers its own spool");
        advance_read_position("INBOX-A", "https://n1", 9).unwrap();
        assert_eq!(read_position("INBOX-A", "https://n1").unwrap(), 9);
    }
}
