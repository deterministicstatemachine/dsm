// SPDX-License-Identifier: MIT OR Apache-2.0

//! Sealed spool payloads kept by message id (DSM Amendment A7).
//!
//! A payload is sealed once: the seal includes a fresh Kyber encapsulation, so
//! sealing again would give different bytes. Every retry and every member of
//! the set must get the SAME bytes for one message id, so the first seal is
//! kept here and reused. A message id seals exactly one payload.

use anyhow::{anyhow, Result};
use rusqlite::{params, OptionalExtension};

use super::get_connection;

/// The sealed bytes already made for `message_id`, if any.
pub fn get_sealed(message_id: &str) -> Result<Option<Vec<u8>>> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    Ok(conn
        .query_row(
            "SELECT sealed FROM b0x_sealed WHERE message_id = ?1",
            params![message_id],
            |r| r.get(0),
        )
        .optional()?)
}

/// Keep `sealed` as THE sealed bytes of `message_id`. The first write stands:
/// keeping different bytes for an id already sealed is refused, because two
/// seals of one message would put two byte strings under one id.
pub fn put_sealed(message_id: &str, sealed: &[u8]) -> Result<()> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    conn.execute(
        "INSERT OR IGNORE INTO b0x_sealed(message_id, sealed) VALUES (?1, ?2)",
        params![message_id, sealed],
    )?;
    let kept: Vec<u8> = conn.query_row(
        "SELECT sealed FROM b0x_sealed WHERE message_id = ?1",
        params![message_id],
        |r| r.get(0),
    )?;
    if kept != sealed {
        return Err(anyhow!("b0x_sealed: {message_id} is already sealed with other bytes"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[serial_test::serial]
    fn the_first_seal_of_a_message_stands() {
        crate::storage::client_db::reset_database_for_tests();
        assert_eq!(get_sealed("M1").unwrap(), None);
        put_sealed("M1", b"sealed-a").unwrap();
        put_sealed("M1", b"sealed-a").unwrap();
        assert!(put_sealed("M1", b"sealed-b").is_err(), "a second, different seal is refused");
        assert_eq!(get_sealed("M1").unwrap().as_deref(), Some(b"sealed-a".as_slice()));
    }
}
