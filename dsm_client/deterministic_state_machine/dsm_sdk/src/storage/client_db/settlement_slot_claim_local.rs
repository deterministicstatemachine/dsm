// SPDX-License-Identifier: MIT OR Apache-2.0

//! This device's own frozen settlement-slot claim envelopes, keyed by the slot
//! they claim.
//!
//! A claim is signed and canonically encoded ONCE; every retry and every
//! recovery replay must submit those exact bytes, because register members
//! compare bytes and a semantically-equal re-encode that differs by a byte
//! reads as a DIFFERENT claimant — refused by every member that already holds
//! ours. Retaining the envelope durably here is what makes "replay the same
//! bytes" a property rather than a hope. Rows are never updated (a slot's
//! claim is what it is) and only ever read back for replay.

use anyhow::Result;
use rusqlite::{params, OptionalExtension};

use super::get_connection;

/// Retain the frozen envelope for `(vault_id, parent_sequence, x)`. A second
/// call with the same key is a no-op (`INSERT OR IGNORE`): the first bytes are
/// the claim.
pub fn put_frozen_claim(
    vault_id: &[u8; 32],
    parent_sequence: u64,
    x: &[u8; 32],
    envelope: &[u8],
) -> Result<()> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    conn.execute(
        "INSERT OR IGNORE INTO settlement_slot_claim_local
            (vault_id, parent_sequence, x, envelope)
         VALUES (?1, ?2, ?3, ?4)",
        params![
            vault_id.as_slice(),
            parent_sequence as i64,
            x.as_slice(),
            envelope
        ],
    )?;
    Ok(())
}

/// The retained envelope for the slot, if this device ever claimed it.
pub fn get_frozen_claim(
    vault_id: &[u8; 32],
    parent_sequence: u64,
    x: &[u8; 32],
) -> Result<Option<Vec<u8>>> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    let row = conn
        .query_row(
            "SELECT envelope FROM settlement_slot_claim_local
              WHERE vault_id = ?1 AND parent_sequence = ?2 AND x = ?3",
            params![vault_id.as_slice(), parent_sequence as i64, x.as_slice()],
            |r| r.get::<_, Vec<u8>>(0),
        )
        .optional()?;
    Ok(row)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    #[test]
    #[serial]
    fn first_bytes_are_retained_and_never_replaced() {
        crate::storage::client_db::reset_database_for_tests();
        crate::storage::client_db::init_database().expect("init");
        assert!(get_frozen_claim(&[1; 32], 3, &[2; 32]).unwrap().is_none());
        put_frozen_claim(&[1; 32], 3, &[2; 32], b"first").unwrap();
        put_frozen_claim(&[1; 32], 3, &[2; 32], b"second").unwrap();
        assert_eq!(
            get_frozen_claim(&[1; 32], 3, &[2; 32]).unwrap().as_deref(),
            Some(&b"first"[..]),
            "a retained claim is never overwritten"
        );
        // A different x is a different slot claim.
        assert!(get_frozen_claim(&[1; 32], 3, &[9; 32]).unwrap().is_none());
    }
}
