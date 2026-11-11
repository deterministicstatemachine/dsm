// SPDX-License-Identifier: MIT OR Apache-2.0
//! Where each relationship stands as this device records it (DSM Amendment
//! A33): opened when the contact is added, proposed while this device's
//! ESTABLISH step awaits the other side's countersignature, established once
//! the countersigned step is held, ending while this device's TERMINATE
//! awaits its acknowledgement, ended once a termination is on the chain.
//!
//! Core holds the chain's own lifecycle on the relationship leaf; this row is
//! the device's record of where its proposal stands beside it, and the one
//! thing the send gate and the wallet read.

use anyhow::{anyhow, Result};
use rusqlite::{params, OptionalExtension};

use super::get_connection;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RelationshipState {
    /// The contact is added; no establishment is on the chain yet.
    Opened,
    /// This device made the ESTABLISH step and waits for the countersignature.
    Proposed,
    /// The countersigned ESTABLISH is held: value may move.
    Established,
    /// This device made a TERMINATE step and waits for its acknowledgement;
    /// nothing moves on the relationship from here on.
    Ending,
    /// A termination is on the chain: final.
    Ended,
}

impl RelationshipState {
    pub fn as_str(self) -> &'static str {
        match self {
            RelationshipState::Opened => "opened",
            RelationshipState::Proposed => "proposed",
            RelationshipState::Established => "established",
            RelationshipState::Ending => "ending",
            RelationshipState::Ended => "ended",
        }
    }

    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "opened" => Ok(RelationshipState::Opened),
            "proposed" => Ok(RelationshipState::Proposed),
            "established" => Ok(RelationshipState::Established),
            "ending" => Ok(RelationshipState::Ending),
            "ended" => Ok(RelationshipState::Ended),
            other => Err(anyhow!(
                "contact_relationship holds an unknown state {other:?}"
            )),
        }
    }

    /// Whether value may move on the relationship.
    pub fn admits_value(self) -> bool {
        matches!(self, RelationshipState::Established)
    }

    /// Whether the relationship is over, or on its way to be.
    pub fn is_over(self) -> bool {
        matches!(self, RelationshipState::Ending | RelationshipState::Ended)
    }

    /// Canonical wire value (`RelationshipState` in the proto); `0` is unspecified.
    pub fn to_wire(self) -> i32 {
        match self {
            RelationshipState::Opened => 1,
            RelationshipState::Proposed => 2,
            RelationshipState::Established => 3,
            RelationshipState::Ending => 4,
            RelationshipState::Ended => 5,
        }
    }
}

/// Open the relationship row for a contact being stored, inside the
/// caller's connection: `opened`, unless a row already records where it
/// stands (a contact stored again keeps its state).
pub(crate) fn open_relationship_with_conn(
    conn: &rusqlite::Connection,
    device_id: &[u8],
) -> Result<()> {
    conn.execute(
        "INSERT OR IGNORE INTO contact_relationship(device_id, state) VALUES (?1, ?2)",
        params![device_id, RelationshipState::Opened.as_str()],
    )?;
    Ok(())
}

pub fn relationship_state_with_conn(
    conn: &rusqlite::Connection,
    device_id: &[u8],
) -> Result<RelationshipState> {
    let state: Option<String> = conn
        .query_row(
            "SELECT state FROM contact_relationship WHERE device_id = ?1",
            params![device_id],
            |r| r.get(0),
        )
        .optional()?;
    match state {
        Some(s) => RelationshipState::parse(&s),
        None => Err(anyhow!(
            "no relationship row for device {}: the contact was not stored through store_contact",
            crate::util::text_id::encode_base32_crockford(device_id)
        )),
    }
}

/// Where the relationship with `device_id` stands on this device.
pub fn relationship_state(device_id: &[u8]) -> Result<RelationshipState> {
    let binding = get_connection()?;
    let conn = match binding.lock() {
        Ok(conn) => conn,
        Err(poisoned) => poisoned.into_inner(),
    };
    relationship_state_with_conn(&conn, device_id)
}

pub fn set_relationship_state_with_conn(
    conn: &rusqlite::Connection,
    device_id: &[u8],
    state: RelationshipState,
) -> Result<()> {
    let changed = conn.execute(
        "UPDATE contact_relationship SET state = ?2 WHERE device_id = ?1",
        params![device_id, state.as_str()],
    )?;
    if changed != 1 {
        return Err(anyhow!(
            "no relationship row for device {} to set {}",
            crate::util::text_id::encode_base32_crockford(device_id),
            state.as_str()
        ));
    }
    Ok(())
}

pub fn set_relationship_state(device_id: &[u8], state: RelationshipState) -> Result<()> {
    let binding = get_connection()?;
    let conn = match binding.lock() {
        Ok(conn) => conn,
        Err(poisoned) => poisoned.into_inner(),
    };
    set_relationship_state_with_conn(&conn, device_id, state)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_state_names_itself_and_reads_back() {
        for s in [
            RelationshipState::Opened,
            RelationshipState::Proposed,
            RelationshipState::Established,
            RelationshipState::Ending,
            RelationshipState::Ended,
        ] {
            assert_eq!(
                RelationshipState::parse(s.as_str()).expect("its own name"),
                s
            );
        }
        let err = RelationshipState::parse("paired").expect_err("not a state");
        assert!(err.to_string().contains("unknown state"), "{err}");
    }

    #[test]
    #[serial_test::serial]
    fn a_stored_contact_opens_its_relationship_and_the_state_moves() {
        crate::economic_fixtures::use_test_storage_dir();
        super::super::reset_database_for_tests();
        let device = [0x5A; 32];
        super::super::store_contact(&super::super::contacts::tests::make_contact(device, "zed"))
            .expect("stored");
        assert_eq!(
            relationship_state(&device).expect("opened"),
            RelationshipState::Opened
        );
        set_relationship_state(&device, RelationshipState::Proposed).expect("set");
        assert_eq!(
            relationship_state(&device).expect("proposed"),
            RelationshipState::Proposed
        );
        // Storing the contact again keeps where it stands.
        super::super::store_contact(&super::super::contacts::tests::make_contact(device, "zed"))
            .expect("stored again");
        assert_eq!(
            relationship_state(&device).expect("kept"),
            RelationshipState::Proposed
        );
        let unknown = [0x5B; 32];
        let err = relationship_state(&unknown).expect_err("no row");
        assert!(err.to_string().contains("no relationship row"), "{err}");
    }
}
