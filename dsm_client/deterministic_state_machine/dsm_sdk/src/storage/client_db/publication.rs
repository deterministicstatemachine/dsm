// SPDX-License-Identifier: MIT OR Apache-2.0
//! Identity-publication lifecycle persistence.
//!
//! The invariant this table exists to enforce:
//!
//! > **local genesis durable != identity ready**
//! > **published and read-back verified by quorum = identity ready**
//!
//! Genesis writes a durable local state machine. That is necessary but not
//! sufficient: until a quorum of storage nodes can be *read back* and shown to
//! hold this device's exact identity tuple, no peer can resolve the device and
//! every authenticated write will 401. Recording how far publication got lets
//! startup resume it automatically instead of leaving the user to discover the
//! problem through unrelated symptoms.

use anyhow::Result;
use rusqlite::{params, OptionalExtension};

use super::get_connection;
use crate::util::deterministic_time::tick;

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

    fn from_str(s: &str) -> Self {
        match s {
            "published" => PublicationState::Published,
            "publication_pending" => PublicationState::PublicationPending,
            // Unknown / legacy values are treated as the least-committed state
            // so publication is re-attempted rather than assumed complete.
            _ => PublicationState::LocalGenesisCommitted,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicationRecord {
    pub device_id: String,
    pub genesis_hash: String,
    pub state: PublicationState,
    pub quorum_required: u32,
    pub last_attempt_at: u64,
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
            (device_id, genesis_hash, state, quorum_required, last_attempt_at, last_error)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)
         ON CONFLICT(device_id) DO UPDATE SET
            genesis_hash    = excluded.genesis_hash,
            state           = excluded.state,
            quorum_required = excluded.quorum_required,
            last_attempt_at = excluded.last_attempt_at,
            last_error      = excluded.last_error",
        params![
            device_id,
            genesis_hash,
            state.as_str(),
            quorum_required as i64,
            tick() as i64,
            last_error,
        ],
    )?;
    Ok(())
}

/// Record that `node_url` returned a read-back matching the full identity
/// tuple. Only verified nodes count toward quorum.
pub fn record_verified_node(device_id: &str, node_url: &str) -> Result<()> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    conn.execute(
        "INSERT INTO identity_publication_nodes (device_id, node_url, verified_at)
         VALUES (?1, ?2, ?3)
         ON CONFLICT(device_id, node_url) DO UPDATE SET verified_at = excluded.verified_at",
        params![device_id, node_url, tick() as i64],
    )?;
    Ok(())
}

/// Drop a node's verification. Called when a read-back that previously matched
/// now fails to — the node no longer demonstrably holds the identity, so it
/// must stop counting toward quorum.
pub fn clear_verified_node(device_id: &str, node_url: &str) -> Result<()> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    conn.execute(
        "DELETE FROM identity_publication_nodes WHERE device_id = ?1 AND node_url = ?2",
        params![device_id, node_url],
    )?;
    Ok(())
}

pub fn count_verified_nodes(device_id: &str) -> Result<u32> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    let n: i64 = conn.query_row(
        "SELECT COUNT(*) FROM identity_publication_nodes WHERE device_id = ?1",
        params![device_id],
        |row| row.get(0),
    )?;
    Ok(n as u32)
}

pub fn get_publication_record(device_id: &str) -> Result<Option<PublicationRecord>> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    let rec = conn
        .query_row(
            "SELECT device_id, genesis_hash, state, quorum_required, last_attempt_at, last_error
             FROM identity_publication WHERE device_id = ?1",
            params![device_id],
            |row| {
                Ok(PublicationRecord {
                    device_id: row.get(0)?,
                    genesis_hash: row.get(1)?,
                    state: PublicationState::from_str(&row.get::<_, String>(2)?),
                    quorum_required: row.get::<_, i64>(3)? as u32,
                    last_attempt_at: row.get::<_, i64>(4)? as u64,
                    last_error: row.get(5)?,
                })
            },
        )
        .optional()?;
    Ok(rec)
}

/// Give every locally-committed genesis a publication row if it lacks one.
///
/// Devices whose genesis predates this table have no row at all. Without this
/// backfill they are invisible to [`list_unpublished`] and so never retried,
/// while [`is_published`] correctly reports false — leaving them parked in
/// `publication_pending` forever with nothing driving them out of it. That is
/// strictly worse than the old best-effort behaviour, so the backfill is a
/// precondition of the retry, not an optimisation.
///
/// Seeds `LocalGenesisCommitted` (never `Published`): the row asserts only that
/// genesis is durable locally. Whether any node holds the identity is decided by
/// read-back, and `quorum_required = 0` cannot satisfy `is_published`.
///
/// Returns how many rows were created.
pub fn backfill_publication_rows_for_local_identities() -> Result<usize> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    let inserted = conn.execute(
        "INSERT INTO identity_publication
            (device_id, genesis_hash, state, quorum_required, last_attempt_at, last_error)
         SELECT g.device_id, g.genesis_id, ?1, 0, ?2, ''
         FROM genesis_records g
         WHERE NOT EXISTS (
             SELECT 1 FROM identity_publication p WHERE p.device_id = g.device_id
         )",
        params![
            PublicationState::LocalGenesisCommitted.as_str(),
            tick() as i64
        ],
    )?;
    Ok(inserted)
}

/// Every device whose identity is not yet published. Startup walks this list
/// and retries publication in the background.
pub fn list_unpublished() -> Result<Vec<PublicationRecord>> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    let mut stmt = conn.prepare(
        "SELECT device_id, genesis_hash, state, quorum_required, last_attempt_at, last_error
         FROM identity_publication WHERE state != 'published'",
    )?;
    let rows = stmt
        .query_map([], |row| {
            Ok(PublicationRecord {
                device_id: row.get(0)?,
                genesis_hash: row.get(1)?,
                state: PublicationState::from_str(&row.get::<_, String>(2)?),
                quorum_required: row.get::<_, i64>(3)? as u32,
                last_attempt_at: row.get::<_, i64>(4)? as u64,
                last_error: row.get(5)?,
            })
        })?
        .filter_map(|r| r.ok())
        .collect();
    Ok(rows)
}

/// True once a quorum of nodes has been read-back verified for this device.
/// This is the authority for "is the identity ready", not the presence of a
/// local genesis record.
pub fn is_published(device_id: &str) -> Result<bool> {
    match get_publication_record(device_id)? {
        Some(rec) => {
            // Re-derive from the node table rather than trusting the cached
            // state string: the row and the node set are written separately, so
            // the node count is the harder evidence.
            Ok(count_verified_nodes(device_id)? >= rec.quorum_required && rec.quorum_required > 0)
        }
        None => Ok(false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    fn fresh_db() {
        unsafe {
            std::env::set_var("DSM_SDK_TEST_MODE", "1");
        }
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

    #[test]
    #[serial]
    fn unpublished_until_quorum_of_nodes_verified() {
        fresh_db();
        let dev = "DEVICE-A";
        upsert_publication_state(dev, "GEN-A", PublicationState::PublicationPending, 2, "")
            .expect("upsert");

        // Zero verified nodes -> not published.
        assert!(!is_published(dev).expect("is_published"));

        // One verified node is still short of quorum-of-3.
        record_verified_node(dev, "https://node-1:8080").expect("verify 1");
        assert_eq!(count_verified_nodes(dev).expect("count"), 1);
        assert!(!is_published(dev).expect("is_published"));

        // Second node reaches quorum.
        record_verified_node(dev, "https://node-2:8080").expect("verify 2");
        assert!(is_published(dev).expect("is_published"));

        // Re-verifying the same node is idempotent and cannot inflate quorum.
        record_verified_node(dev, "https://node-2:8080").expect("verify 2 again");
        assert_eq!(count_verified_nodes(dev).expect("count"), 2);
    }

    #[test]
    #[serial]
    fn losing_a_readback_drops_the_node_below_quorum() {
        fresh_db();
        let dev = "DEVICE-B";
        upsert_publication_state(dev, "GEN-B", PublicationState::PublicationPending, 2, "")
            .expect("upsert");
        record_verified_node(dev, "https://node-1:8080").expect("verify 1");
        record_verified_node(dev, "https://node-2:8080").expect("verify 2");
        assert!(is_published(dev).expect("published"));

        clear_verified_node(dev, "https://node-2:8080").expect("clear");
        assert!(
            !is_published(dev).expect("is_published"),
            "a node whose read-back stopped matching must stop counting toward quorum"
        );
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
        // been read-back verified. This is the exact state the whole module
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
        assert_eq!(
            count_verified_nodes("DEVICE-LOCAL-ONLY").expect("count"),
            0,
            "no node should be verified before publication runs"
        );
        assert!(
            !is_published("DEVICE-LOCAL-ONLY").expect("is_published"),
            "durable local genesis must not imply a published identity"
        );

        // Nor does merely *claiming* Published in the row: quorum is re-derived
        // from the verified-node table, so a corrupted/forged state string
        // cannot promote an identity that no node has confirmed.
        upsert_publication_state(
            "DEVICE-LOCAL-ONLY",
            "GEN-LOCAL",
            PublicationState::Published,
            2,
            "",
        )
        .expect("upsert forged published row");
        assert!(
            !is_published("DEVICE-LOCAL-ONLY").expect("is_published"),
            "a Published state string with zero verified nodes must not count as published"
        );
    }

    /// Insert a genesis record the way a pre-publication-table device would
    /// have: durable local genesis, no `identity_publication` row.
    fn insert_legacy_genesis(device_id: &str, genesis_id: &str) {
        let binding = get_connection().expect("conn");
        let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
        conn.execute(
            "INSERT INTO genesis_records
                (genesis_id, device_id, mpc_proof, device_birth_binding, merkle_root,
                 participant_count, chain_tip, publication_hash, storage_nodes,
                 entropy_hash, protocol_version, created_at)
             VALUES (?1, ?2, '', '', '', 0, '', ?1, '', '', 'v3', 0)",
            params![genesis_id, device_id],
        )
        .expect("insert legacy genesis");
    }

    #[test]
    #[serial]
    fn preexisting_identities_are_backfilled_and_then_retried() {
        fresh_db();
        // Exactly the live 9FF case: genesis committed before the publication
        // table existed, so there is no publication row for it.
        insert_legacy_genesis("DEV-LEGACY", "GEN-LEGACY");
        assert!(
            get_publication_record("DEV-LEGACY").expect("get").is_none(),
            "precondition: legacy device has no publication row"
        );
        assert!(
            !list_unpublished()
                .expect("list")
                .iter()
                .any(|r| r.device_id == "DEV-LEGACY"),
            "precondition: without backfill the legacy device is invisible to the retry, \
             which is the bug -- it would sit publication_pending forever"
        );

        let n = backfill_publication_rows_for_local_identities().expect("backfill");
        assert_eq!(n, 1, "the legacy identity must be seeded");

        let rec = get_publication_record("DEV-LEGACY")
            .expect("get")
            .expect("row exists");
        assert_eq!(rec.state, PublicationState::LocalGenesisCommitted);
        assert_eq!(rec.genesis_hash, "GEN-LEGACY");
        assert!(
            !is_published("DEV-LEGACY").expect("is_published"),
            "backfill records local commitment only -- it must never imply publication"
        );
        assert!(
            list_unpublished()
                .expect("list")
                .iter()
                .any(|r| r.device_id == "DEV-LEGACY"),
            "after backfill the legacy device must be picked up by the startup retry"
        );

        // Idempotent: re-running must not duplicate or reset anything.
        assert_eq!(
            backfill_publication_rows_for_local_identities().expect("backfill again"),
            0,
            "backfill must not re-seed a device that already has a row"
        );
    }

    #[test]
    #[serial]
    fn backfill_never_overwrites_an_already_published_identity() {
        fresh_db();
        insert_legacy_genesis("DEV-PUB", "GEN-PUB");
        upsert_publication_state("DEV-PUB", "GEN-PUB", PublicationState::Published, 2, "")
            .expect("upsert");
        record_verified_node("DEV-PUB", "https://node-1:8080").expect("v1");
        record_verified_node("DEV-PUB", "https://node-2:8080").expect("v2");
        assert!(is_published("DEV-PUB").expect("published"));

        assert_eq!(
            backfill_publication_rows_for_local_identities().expect("backfill"),
            0
        );
        assert!(
            is_published("DEV-PUB").expect("still published"),
            "backfill must not downgrade a published identity to LocalGenesisCommitted"
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
