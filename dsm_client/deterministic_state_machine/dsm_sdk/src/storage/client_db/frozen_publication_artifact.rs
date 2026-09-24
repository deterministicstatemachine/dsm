// SPDX-License-Identifier: MIT OR Apache-2.0

//! Frozen publication artifacts: the exact bytes of an immutable object a
//! canonical advance produced, owed to the storage set they were frozen for.
//!
//! > **canonically committed ≠ published**
//! > **the frozen bytes `Stored` on the set they were frozen for = published**
//!
//! A canonical advance produces objects others must be able to fetch —
//! witnesses, manifests, evidence, anchors — bound to the root that advance
//! committed. Those bytes are built and signed BEFORE the advance is
//! persisted, and frozen HERE inside the same SQLite transaction as the head
//! write ([`freeze_artifact_with_conn`]): if construction fails nothing
//! commits; if the device dies after commit the exact bytes are on disk, and
//! the sweep (`handlers::artifact_republish`) puts them to the set until
//! reading them back establishes `Stored` (storage spec §5 rule 6: three
//! members return the exact bytes). Nothing is regenerated or re-signed from
//! a later head.
//!
//! An artifact's key is its object's content address,
//! `immutable::{namespace}::{addr}`, checked against the bytes when it is
//! frozen, so one key names exactly one byte string. Every row binds the
//! storage set it was frozen for; the sweep resolves that set and never
//! substitutes another.

use anyhow::{anyhow, Result};
use rusqlite::{params, Connection, OptionalExtension};

use super::get_connection;

/// Where an artifact sits in its forward-only lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArtifactState {
    /// Frozen in the canonical transaction; not put to the set yet.
    Frozen,
    /// Put at least once; `Stored` not established yet. Retried.
    PublicationPending,
    /// Read back `Stored` on the set it was frozen for.
    Stored,
}

impl ArtifactState {
    pub fn as_str(self) -> &'static str {
        match self {
            ArtifactState::Frozen => "frozen",
            ArtifactState::PublicationPending => "publication_pending",
            ArtifactState::Stored => "stored",
        }
    }

    fn parse(s: &str) -> Option<Self> {
        match s {
            "frozen" => Some(ArtifactState::Frozen),
            "publication_pending" => Some(ArtifactState::PublicationPending),
            "stored" => Some(ArtifactState::Stored),
            other => {
                log::error!("frozen artifact: unknown state {other:?}");
                None
            }
        }
    }
}

/// One frozen artifact row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrozenArtifact {
    pub insertion_ordinal: i64,
    pub object_key: String,
    pub payload: Vec<u8>,
    pub bound_root: [u8; 32],
    pub purpose: String,
    pub storage_set_id: [u8; 32],
    pub state: ArtifactState,
    pub last_error: String,
}

/// Split an `immutable::{namespace}::{addr_b32}` key into its namespace and
/// address. The namespace contains `/` but never `::`, so the last `::`
/// separates them.
pub fn parse_immutable_object_key(
    key: &str,
) -> Option<(dsm::crypto::domain::TaggedHashDomain<'_>, [u8; 32])> {
    let rest = key.strip_prefix("immutable::")?;
    let split = rest.rfind("::")?;
    let namespace =
        dsm::crypto::domain::TaggedHashDomain::try_new(&rest.as_bytes()[..split]).ok()?;
    let addr = crate::util::text_id::decode_base32_crockford(&rest[split + 2..])?
        .try_into()
        .ok()?;
    Some((namespace, addr))
}

/// Freeze `payload` under `object_key` INSIDE the caller's transaction, bound
/// to the storage set `storage_set_id` and the root `bound_root` the payload
/// commits to. The key must be the payload's own content address under its
/// namespace. Freezing the same key again is a no-op: the key fixes the
/// bytes.
///
/// Runs on the caller's `Connection`/transaction: `Err` from here rolls the
/// canonical advance back with it.
pub fn freeze_artifact_with_conn(
    conn: &Connection,
    storage_set_id: &[u8; 32],
    object_key: &str,
    payload: &[u8],
    bound_root: &[u8; 32],
    purpose: &str,
) -> Result<()> {
    if payload.is_empty() {
        return Err(anyhow!("freeze_artifact: empty payload for {object_key}"));
    }
    let (namespace, addr) = parse_immutable_object_key(object_key)
        .ok_or_else(|| anyhow!("freeze_artifact: {object_key} is not an object address"))?;
    if dsm::storage_object::immutable_addr(namespace, payload) != addr {
        return Err(anyhow!(
            "freeze_artifact: the payload is not the object at {object_key}"
        ));
    }
    conn.execute(
        "INSERT OR IGNORE INTO frozen_publication_artifact
            (object_key, payload, bound_root, purpose, storage_set_id, state, last_error)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, '')",
        params![
            object_key,
            payload,
            bound_root.as_slice(),
            purpose,
            storage_set_id.as_slice(),
            ArtifactState::Frozen.as_str(),
        ],
    )?;
    Ok(())
}

/// Advance an artifact's state, forward-only: `stored` never regresses.
/// Returns `true` if the row changed.
pub fn upsert_artifact_publication_state(
    object_key: &str,
    state: ArtifactState,
    last_error: &str,
) -> Result<bool> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    let n = conn.execute(
        "UPDATE frozen_publication_artifact
            SET state = ?2, last_error = ?3
          WHERE object_key = ?1 AND state != 'stored'",
        params![object_key, state.as_str(), last_error],
    )?;
    Ok(n > 0)
}

fn digest_column(r: &rusqlite::Row<'_>, index: usize) -> rusqlite::Result<[u8; 32]> {
    let bytes: Vec<u8> = r.get(index)?;
    <[u8; 32]>::try_from(bytes.as_slice()).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(index, rusqlite::types::Type::Blob, Box::new(e))
    })
}

fn row_to_artifact(r: &rusqlite::Row<'_>) -> rusqlite::Result<FrozenArtifact> {
    let state_text: String = r.get(6)?;
    let state = ArtifactState::parse(&state_text).ok_or_else(|| {
        rusqlite::Error::FromSqlConversionFailure(
            6,
            rusqlite::types::Type::Text,
            format!("unknown artifact state {state_text:?}").into(),
        )
    })?;
    Ok(FrozenArtifact {
        insertion_ordinal: r.get(0)?,
        object_key: r.get(1)?,
        payload: r.get(2)?,
        bound_root: digest_column(r, 3)?,
        purpose: r.get(4)?,
        storage_set_id: digest_column(r, 5)?,
        state,
        last_error: r.get(7)?,
    })
}

const SELECT_COLS: &str =
    "insertion_ordinal, object_key, payload, bound_root, purpose, storage_set_id, state, last_error";

/// The artifact row for `object_key`.
pub fn get_artifact(object_key: &str) -> Result<Option<FrozenArtifact>> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    Ok(conn
        .query_row(
            &format!("SELECT {SELECT_COLS} FROM frozen_publication_artifact WHERE object_key = ?1"),
            params![object_key],
            row_to_artifact,
        )
        .optional()?)
}

/// The newest payload whose key starts with `prefix` (a namespace) and whose
/// purpose is `purpose`: how admission recovery finds its own frozen objects
/// without re-deriving addresses from bytes it does not have yet. The
/// caller's address-equality check is the honesty backstop.
pub fn find_current_payload_with_prefix_and_purpose(
    prefix: &str,
    purpose: &str,
) -> Result<Option<Vec<u8>>> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    Ok(conn
        .query_row(
            "SELECT payload FROM frozen_publication_artifact
              WHERE object_key LIKE ?1 || '%' AND purpose = ?2
              ORDER BY insertion_ordinal DESC LIMIT 1",
            params![prefix, purpose],
            |r| r.get::<_, Vec<u8>>(0),
        )
        .optional()?)
}

/// Every artifact not yet read back `Stored`, oldest first, at most `limit`.
pub fn list_unpublished_artifacts(limit: u32) -> Result<Vec<FrozenArtifact>> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    let mut stmt = conn.prepare(&format!(
        "SELECT {SELECT_COLS} FROM frozen_publication_artifact
          WHERE state IN ('frozen', 'publication_pending')
          ORDER BY insertion_ordinal ASC
          LIMIT ?1"
    ))?;
    let rows = stmt.query_map(params![i64::from(limit)], row_to_artifact)?;
    Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::client_db::{get_connection, reset_database_for_tests};
    use serial_test::serial;

    const NS: dsm::crypto::domain::TaggedHashDomain<'static> =
        dsm::common::domain_tags::TAG_DSM_ECONOMIC_TRANSITION_WITNESS_OBJ;

    fn key_of(payload: &[u8]) -> String {
        crate::sdk::economic_registers::immutable_object_key(NS, payload)
    }

    fn freeze(set: &[u8; 32], payload: &[u8]) -> String {
        let key = key_of(payload);
        let binding = get_connection().expect("db");
        let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
        freeze_artifact_with_conn(&conn, set, &key, payload, &[0x11; 32], "test").expect("freeze");
        key
    }

    #[test]
    #[serial]
    fn an_artifact_is_frozen_under_its_own_content_address() {
        reset_database_for_tests();
        let set = [0xA1u8; 32];
        let key = freeze(&set, b"hello");
        let row = get_artifact(&key).unwrap().expect("row");
        assert_eq!(row.payload, b"hello");
        assert_eq!(row.storage_set_id, set, "the frozen set rides the row");
        assert_eq!(row.state, ArtifactState::Frozen);
        assert_eq!(freeze(&set, b"hello"), key, "freezing again is a no-op");
        assert_eq!(list_unpublished_artifacts(16).unwrap().len(), 1);
    }

    #[test]
    #[serial]
    fn bytes_that_are_not_the_object_at_the_key_are_refused() {
        reset_database_for_tests();
        let binding = get_connection().expect("db");
        let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
        let key = key_of(b"the object");
        assert!(
            freeze_artifact_with_conn(&conn, &[0xA1; 32], &key, b"other bytes", &[0; 32], "t")
                .is_err()
        );
        assert!(
            freeze_artifact_with_conn(&conn, &[0xA1; 32], "k/plain", b"bytes", &[0; 32], "t")
                .is_err(),
            "a key that is not an object address"
        );
    }

    #[test]
    #[serial]
    fn a_failing_transaction_leaves_no_row() {
        reset_database_for_tests();
        let key = key_of(b"bytes");
        {
            let binding = get_connection().expect("db");
            let mut conn = binding.lock().unwrap_or_else(|p| p.into_inner());
            let tx = conn.transaction().expect("tx");
            freeze_artifact_with_conn(&tx, &[0xA1; 32], &key, b"bytes", &[0; 32], "test")
                .expect("freeze inside tx");
            tx.rollback().expect("rollback");
        }
        assert!(get_artifact(&key).unwrap().is_none());
    }

    #[test]
    #[serial]
    fn stored_never_regresses() {
        reset_database_for_tests();
        let key = freeze(&[0xA1; 32], b"x");
        assert!(upsert_artifact_publication_state(&key, ArtifactState::Stored, "").unwrap());
        assert!(
            !upsert_artifact_publication_state(&key, ArtifactState::PublicationPending, "late")
                .unwrap(),
            "stored is terminal"
        );
        assert_eq!(
            get_artifact(&key).unwrap().unwrap().state,
            ArtifactState::Stored
        );
        assert!(list_unpublished_artifacts(16).unwrap().is_empty());
    }

    #[test]
    #[serial]
    fn unpublished_work_is_ordered_by_insertion_ordinal() {
        reset_database_for_tests();
        let set = [0xA1u8; 32];
        let first = freeze(&set, b"1");
        let second = freeze(&set, b"2");
        freeze(&set, b"3");
        let keys: Vec<String> = list_unpublished_artifacts(2)
            .unwrap()
            .into_iter()
            .map(|a| a.object_key)
            .collect();
        assert_eq!(keys, vec![first, second], "oldest first, bounded");
    }
}
