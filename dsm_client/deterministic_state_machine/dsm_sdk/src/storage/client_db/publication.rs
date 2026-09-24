// SPDX-License-Identifier: MIT OR Apache-2.0
//! Identity-publication lifecycle persistence.
//!
//! The invariant this table exists to enforce:
//!
//! > **local genesis durable != identity ready**
//! > **own directory entry read back from the set = identity ready**
//!
//! Genesis writes a durable local state machine. That is necessary but not
//! sufficient: until enough members can be read back holding this device's
//! directory entry (`sdk::identity_publication`), no peer can reach the
//! device. Recording how far publication got lets startup resume it
//! automatically instead of leaving the user to discover the problem through
//! unrelated symptoms.

use anyhow::Result;
use rusqlite::{params, OptionalExtension};

use super::get_connection;

/// Where a device sits in the publication lifecycle.
///
/// The progression is `LocalGenesisCommitted -> PublicationPending ->
/// Published`. It never moves backwards: once a quorum has been verified the
/// identity is published, and a later transient node outage does not un-publish
/// it (the nodes still hold the tuple; only reachability changed).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublicationState {
    /// Genesis is durable locally, publication has not yet been attempted.
    LocalGenesisCommitted,
    /// Publication attempted, quorum not yet reached. Retryable.
    PublicationPending,
    /// A quorum of nodes returned a read-back matching the full identity tuple.
    Published,
}

impl PublicationState {
    pub fn as_str(self) -> &'static str {
        match self {
            PublicationState::LocalGenesisCommitted => "local_genesis_committed",
            PublicationState::PublicationPending => "publication_pending",
            PublicationState::Published => "published",
        }
    }

    /// The state a stored string names. Anything else is not a state this
    /// table writes, and the row is refused.
    fn from_column(s: &str) -> rusqlite::Result<Self> {
        match s {
            "local_genesis_committed" => Ok(PublicationState::LocalGenesisCommitted),
            "publication_pending" => Ok(PublicationState::PublicationPending),
            "published" => Ok(PublicationState::Published),
            other => Err(rusqlite::Error::FromSqlConversionFailure(
                2,
                rusqlite::types::Type::Text,
                Box::new(std::io::Error::other(format!(
                    "identity_publication.state holds {other:?}, not a publication state"
                ))),
            )),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicationRecord {
    pub device_id: String,
    pub genesis_hash: String,
    pub state: PublicationState,
    pub quorum_required: u32,
    pub last_error: String,
}

/// Quorum required to call an identity published: a strict majority of the
/// configured nodes.
///
/// A majority (not 1, not all) is the right threshold. Counting a single node
/// would leave the identity unresolvable the moment that node is lost, and
/// requiring all of them would make one unreachable node block wallet creation
/// entirely.
pub fn quorum_for(node_count: usize) -> u32 {
    if node_count == 0 {
        return 0;
    }
    (node_count as u32 / 2) + 1
}

pub fn upsert_publication_state(
    device_id: &str,
    genesis_hash: &str,
    state: PublicationState,
    quorum_required: u32,
    last_error: &str,
) -> Result<()> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    conn.execute(
        "INSERT INTO identity_publication
            (device_id, genesis_hash, state, quorum_required, last_error)
         VALUES (?1, ?2, ?3, ?4, ?5)
         ON CONFLICT(device_id) DO UPDATE SET
            genesis_hash    = excluded.genesis_hash,
            state           = excluded.state,
            quorum_required = excluded.quorum_required,
            last_error      = excluded.last_error",
        params![
            device_id,
            genesis_hash,
            state.as_str(),
            quorum_required as i64,
            last_error,
        ],
    )?;
    Ok(())
}

pub fn get_publication_record(device_id: &str) -> Result<Option<PublicationRecord>> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    let rec = conn
        .query_row(
            "SELECT device_id, genesis_hash, state, quorum_required, last_error
             FROM identity_publication WHERE device_id = ?1",
            params![device_id],
            |row| {
                Ok(PublicationRecord {
                    device_id: row.get(0)?,
                    genesis_hash: row.get(1)?,
                    state: PublicationState::from_column(&row.get::<_, String>(2)?)?,
                    quorum_required: row.get::<_, i64>(3)? as u32,
                    last_error: row.get(4)?,
                })
            },
        )
        .optional()?;
    Ok(rec)
}

/// Every device whose identity is not yet published. Startup walks this list
/// and retries publication in the background.
pub fn list_unpublished() -> Result<Vec<PublicationRecord>> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    let mut stmt = conn.prepare(
        "SELECT device_id, genesis_hash, state, quorum_required, last_error
         FROM identity_publication WHERE state != 'published'",
    )?;
    let rows = stmt
        .query_map([], |row| {
            Ok(PublicationRecord {
                device_id: row.get(0)?,
                genesis_hash: row.get(1)?,
                state: PublicationState::from_column(&row.get::<_, String>(2)?)?,
                quorum_required: row.get::<_, i64>(3)? as u32,
                last_error: row.get(4)?,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

/// True once this device's directory entry was read back from enough
/// members (`sdk::identity_publication`). This is the authority for "is the
/// identity ready", not the presence of a local genesis record.
pub fn is_published(device_id: &str) -> Result<bool> {
    Ok(matches!(
        get_publication_record(device_id)?,
        Some(PublicationRecord {
            state: PublicationState::Published,
            ..
        })
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    fn fresh_db() {
        crate::economic_fixtures::use_test_storage_dir();
        crate::storage::client_db::reset_database_for_tests();
        crate::storage::client_db::init_database().expect("init db");
    }

    #[test]
    fn quorum_is_a_strict_majority() {
        assert_eq!(quorum_for(0), 0);
        assert_eq!(quorum_for(1), 1);
        assert_eq!(quorum_for(3), 2);
        assert_eq!(quorum_for(6), 4);
    }

    /// The row records the read-back: only `Published` is published.
    #[test]
    #[serial]
    fn published_only_once_the_row_records_the_read_back() {
        fresh_db();
        let dev = "DEVICE-A";
        upsert_publication_state(dev, "GEN-A", PublicationState::PublicationPending, 3, "")
            .expect("upsert");
        assert!(!is_published(dev).expect("is_published"));
        upsert_publication_state(dev, "GEN-A", PublicationState::Published, 3, "").expect("upsert");
        assert!(is_published(dev).expect("is_published"));
    }

    /// A state string this table never writes is refused, never read as the
    /// least-committed state.
    #[test]
    #[serial]
    fn an_unknown_state_string_is_refused() {
        fresh_db();
        let binding = get_connection().expect("conn");
        {
            let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
            conn.execute(
                "INSERT INTO identity_publication
                    (device_id, genesis_hash, state, quorum_required, last_error)
                 VALUES ('DEV-X', 'GEN-X', 'half-published', 3, '')",
                [],
            )
            .expect("insert");
        }
        assert!(get_publication_record("DEV-X").is_err());
        assert!(list_unpublished().is_err());
    }

    #[test]
    #[serial]
    fn a_local_genesis_record_alone_is_not_published() {
        fresh_db();

        // A device with no row at all is trivially unpublished.
        assert!(
            !is_published("DEVICE-NEVER-PUBLISHED").expect("is_published"),
            "a device with no publication row must not be published"
        );

        // The load-bearing case: genesis HAS committed locally and written its
        // `LocalGenesisCommitted` row, but publication never ran, so no node has
        // read it back. This is the exact state the whole module
        // exists to keep out of "ready" -- durable local genesis is NOT an
        // identity peers can resolve.
        upsert_publication_state(
            "DEVICE-LOCAL-ONLY",
            "GEN-LOCAL",
            PublicationState::LocalGenesisCommitted,
            0,
            "",
        )
        .expect("upsert local-genesis row");
        assert!(
            !is_published("DEVICE-LOCAL-ONLY").expect("is_published"),
            "durable local genesis must not imply a published identity"
        );
    }

    #[test]
    #[serial]
    fn unpublished_devices_are_listed_for_startup_retry() {
        fresh_db();
        upsert_publication_state(
            "DEV-1",
            "G1",
            PublicationState::PublicationPending,
            2,
            "boom",
        )
        .expect("upsert 1");
        upsert_publication_state("DEV-2", "G2", PublicationState::Published, 2, "")
            .expect("upsert 2");

        let pending = list_unpublished().expect("list");
        let ids: Vec<_> = pending.iter().map(|r| r.device_id.as_str()).collect();
        assert!(ids.contains(&"DEV-1"), "pending device must be retried");
        assert!(
            !ids.contains(&"DEV-2"),
            "published device must not be retried"
        );
        assert_eq!(pending[0].last_error, "boom", "failure cause is retained");
    }
}
