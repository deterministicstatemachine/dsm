// SPDX-License-Identifier: MIT OR Apache-2.0

//! What this device's contacts are owed of its own offline boundaries (DSM
//! Amendment A30).
//!
//! A receiver takes an offline payment only from the account it validated
//! itself, so each of this device's loads and unloads has to reach its
//! contacts. A boundary is recorded in the transaction that commits it, and
//! each contact has a mark of how far it has been told, moved only after a
//! notice was delivered. What is owed is read from the two, so it survives a
//! process that stops anywhere between them.

use anyhow::{anyhow, Result};
use rusqlite::{params, OptionalExtension, Transaction};

use super::get_connection;

fn stored(position: u64) -> Result<i64> {
    i64::try_from(position).map_err(|e| anyhow!("an offline boundary's position {position}: {e}"))
}

fn read(position: i64) -> Result<u64> {
    u64::try_from(position).map_err(|e| anyhow!("a stored boundary position {position}: {e}"))
}

/// Record a boundary of this device's own, in the transaction that commits it.
pub fn record_own_boundary_in_tx(tx: &Transaction<'_>, position: u64) -> Result<()> {
    tx.execute(
        "INSERT OR IGNORE INTO own_offline_boundary(economic_position) VALUES (?1)",
        params![stored(position)?],
    )?;
    Ok(())
}

/// What `contact` is owed of this device's boundaries admitted up to
/// `admitted`, in order. A contact told of none is owed only the latest: the
/// account that left is the one a payment starts from, and it validates with
/// nothing behind it recorded. A contact told of some is owed every one since,
/// since each continues the account the one before it left.
pub fn owed_to(contact: &[u8; 32], admitted: u64) -> Result<Vec<u64>> {
    let binding = get_connection()?;
    let conn = binding
        .lock()
        .map_err(|e| anyhow!("the client database lock: {e}"))?;
    let told = conn
        .query_row(
            "SELECT economic_position FROM offline_boundary_told WHERE contact_device = ?1",
            params![contact.as_slice()],
            |r| r.get::<_, i64>(0),
        )
        .optional()?;
    let admitted = stored(admitted)?;
    let positions: Vec<i64> = match told {
        Some(told) => {
            let mut stmt = conn.prepare(
                "SELECT economic_position FROM own_offline_boundary
                 WHERE economic_position > ?1 AND economic_position <= ?2
                 ORDER BY economic_position ASC",
            )?;
            let rows = stmt.query_map(params![told, admitted], |r| r.get::<_, i64>(0))?;
            rows.collect::<rusqlite::Result<_>>()?
        }
        None => conn
            .query_row(
                "SELECT economic_position FROM own_offline_boundary
                 WHERE economic_position <= ?1
                 ORDER BY economic_position DESC LIMIT 1",
                params![admitted],
                |r| r.get::<_, i64>(0),
            )
            .optional()?
            .into_iter()
            .collect(),
    };
    positions.into_iter().map(read).collect()
}

/// Mark `contact` told of this device's boundaries through `position`. The mark
/// only moves forward.
pub fn record_told(contact: &[u8; 32], position: u64) -> Result<()> {
    let binding = get_connection()?;
    let conn = binding
        .lock()
        .map_err(|e| anyhow!("the client database lock: {e}"))?;
    conn.execute(
        "INSERT INTO offline_boundary_told(contact_device, economic_position) VALUES (?1, ?2)
         ON CONFLICT(contact_device) DO UPDATE SET economic_position =
             MAX(economic_position, excluded.economic_position)",
        params![contact.as_slice(), stored(position)?],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh() {
        crate::economic_fixtures::use_test_storage_dir();
        crate::storage::client_db::reset_database_for_tests();
    }

    fn boundary(position: u64) {
        let binding = get_connection().unwrap();
        let mut conn = binding.lock().unwrap();
        let tx = conn.transaction().unwrap();
        record_own_boundary_in_tx(&tx, position).unwrap();
        tx.commit().unwrap();
    }

    /// A contact told of nothing is owed the latest admitted boundary alone; one
    /// told of some is owed every one since, in order; one not admitted yet is
    /// owed to nobody; and the mark never moves back. MUTATION CONTROL: reading
    /// every boundary for a contact told of none, or dropping the admitted
    /// bound, turns this red.
    #[test]
    #[serial_test::serial]
    fn a_contact_is_owed_what_it_has_not_been_told_of_what_is_admitted() {
        fresh();
        let (old, new) = ([0x0A; 32], [0x0B; 32]);
        assert_eq!(owed_to(&new, 100).unwrap(), Vec::<u64>::new());

        boundary(3);
        boundary(5);
        boundary(9);
        assert_eq!(owed_to(&new, 9).unwrap(), [9], "the latest alone");
        assert_eq!(owed_to(&new, 7).unwrap(), [5], "9 is not admitted yet");
        assert_eq!(owed_to(&new, 2).unwrap(), Vec::<u64>::new());

        record_told(&old, 3).unwrap();
        assert_eq!(
            owed_to(&old, 9).unwrap(),
            [5, 9],
            "every one since, in order"
        );
        assert_eq!(owed_to(&old, 7).unwrap(), [5]);
        record_told(&old, 9).unwrap();
        assert_eq!(owed_to(&old, 9).unwrap(), Vec::<u64>::new());

        record_told(&old, 5).unwrap();
        assert_eq!(
            owed_to(&old, 9).unwrap(),
            Vec::<u64>::new(),
            "the mark does not move back"
        );
    }
}
