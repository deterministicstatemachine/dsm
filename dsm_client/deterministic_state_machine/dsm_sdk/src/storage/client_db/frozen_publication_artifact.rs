// SPDX-License-Identifier: MIT OR Apache-2.0

//! Frozen publication artifacts — publish-an-exact-object-to-a-quorum, and
//! nothing else.
//!
//! The invariant this table exists to enforce:
//!
//! > **canonically committed ≠ published**
//! > **the exact frozen bytes accepted by a quorum of the canonical set = published**
//!
//! A canonical advance (a vault's birth or death) produces objects the market
//! must be able to fetch — signed anchors and proofs bound to the ROOT that
//! advance committed. Those bytes are built and signed BEFORE the advance is
//! persisted, and frozen HERE inside the same SQLite transaction as the head
//! write ([`freeze_artifact_with_conn`]): if construction fails, nothing
//! commits; if the device dies after commit, the exact bytes are on disk and
//! the ONE generic sweep replays them, byte-identically, until a quorum of the
//! set they were frozen for holds them. Nothing is ever regenerated or
//! re-signed from a later head.
//!
//! What this is NOT: an outbox. There is no recipient, no routing address, no
//! acceptance, no ACK-driven GC, no countersign, no peer-progress. Quorum here
//! means *delivery complete*, never protocol authority — the canonical
//! transition already decided what is true; publication only makes it
//! discoverable. The layer is ignorant of what it carries: `purpose` is an
//! opaque label for operators, not a dispatch key.
//!
//! Model: the identity-publication lifecycle (`publication.rs`) — quorum is
//! re-derived from the member set, never stored; nodes that accepted count,
//! forward-only state. Two deliberate deltas:
//!
//! * rows are keyed by `(object_key, content_digest)`, not `object_key`
//!   alone: `…/latest` mirror keys are re-published across generations (birth
//!   at seq 0, terminal at K+1), so a new digest under an existing key
//!   SUPERSEDES the older row (terminal, never swept) instead of colliding;
//! * every row binds the **canonical storage set** it was frozen for
//!   (`storage_set_id`). The sweep resolves THAT set through the catalog and
//!   never substitutes another; "the currently configured fleet" is exactly the
//!   local-config authority the register removed. Quorum is always
//!   `quorum_for(|S|)` over the resolved set — never a stored integer.
//!
//! No clock columns in logic: unpublished work is ordered by a local monotonic
//! insertion ordinal.

use anyhow::{anyhow, Result};
use rusqlite::{params, Connection, OptionalExtension};

use super::get_connection;
use dsm::common::domain_tags::TAG_DSM_FROZEN_ARTIFACT_V1;
use dsm::crypto::blake3::dsm_domain_hasher;

/// Where an artifact sits in its (forward-only) lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArtifactState {
    /// Frozen in the canonical transaction; no publication attempt recorded yet.
    Frozen,
    /// At least one attempt made, quorum not yet reached. Retryable.
    PublicationPending,
    /// A quorum of the frozen set accepted these exact bytes.
    Published,
    /// A newer digest was frozen under the same object key. Terminal; never
    /// replayed.
    Superseded,
}

impl ArtifactState {
    pub fn as_str(self) -> &'static str {
        match self {
            ArtifactState::Frozen => "frozen",
            ArtifactState::PublicationPending => "publication_pending",
            ArtifactState::Published => "published",
            ArtifactState::Superseded => "superseded",
        }
    }

    fn from_str(s: &str) -> Self {
        match s {
            "published" => ArtifactState::Published,
            "publication_pending" => ArtifactState::PublicationPending,
            "superseded" => ArtifactState::Superseded,
            // Unknown values are the LEAST-committed state, so publication is
            // re-attempted rather than assumed complete.
            _ => ArtifactState::Frozen,
        }
    }
}

/// One frozen artifact row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrozenArtifact {
    pub insertion_ordinal: i64,
    pub object_key: String,
    pub content_digest: [u8; 32],
    pub payload: Vec<u8>,
    pub bound_root: [u8; 32],
    pub purpose: String,
    pub storage_set_id: [u8; 32],
    pub state: ArtifactState,
    pub last_error: String,
}

/// The content digest is DERIVED from the bytes — there is no API that accepts
/// a caller-supplied digest, so bytes and digest cannot disagree.
/// `H(TAG ‖ 0x00 ‖ object_key ‖ 0x00 ‖ payload)`: the key is folded in so the
/// same bytes under two keys are two distinct artifacts (each is its own
/// durable object with its own quorum).
pub fn content_digest(object_key: &str, payload: &[u8]) -> [u8; 32] {
    let mut h = dsm_domain_hasher(TAG_DSM_FROZEN_ARTIFACT_V1);
    h.update(object_key.as_bytes());
    h.update(&[0u8]);
    h.update(payload);
    *h.finalize().as_bytes()
}

/// Freeze `payload` for `object_key` INSIDE the caller's transaction, bound to
/// the canonical set `storage_set_id` and the root `bound_root` the payload
/// commits to. Returns the derived content digest.
///
/// Semantics:
/// * a second freeze of the same `(key, digest)` is an idempotent no-op (the
///   bytes are the same by construction, since the digest is a function of
///   them);
/// * new bytes under an existing key mark every non-published, non-superseded
///   prior row for that key `superseded` — a `…/latest` mirror moved on; the
///   old generation is never replayed. (An already-`published` prior row is
///   also superseded: it stays published as history, but `is_artifact_published`
///   answers for the LATEST row.)
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
) -> Result<[u8; 32]> {
    if object_key.is_empty() {
        return Err(anyhow!("freeze_artifact: empty object key"));
    }
    if payload.is_empty() {
        return Err(anyhow!("freeze_artifact: empty payload for {object_key}"));
    }
    let digest = content_digest(object_key, payload);

    // Idempotent re-freeze of the identical artifact.
    let existing: Option<i64> = conn
        .query_row(
            "SELECT insertion_ordinal FROM frozen_publication_artifact
             WHERE object_key = ?1 AND content_digest = ?2",
            params![object_key, digest.as_slice()],
            |r| r.get(0),
        )
        .optional()?;
    if existing.is_some() {
        return Ok(digest);
    }

    // A new generation under this key supersedes every prior row for the key.
    conn.execute(
        "UPDATE frozen_publication_artifact
            SET state = 'superseded'
          WHERE object_key = ?1 AND content_digest != ?2",
        params![object_key, digest.as_slice()],
    )?;
    // Old acceptance observations do not carry forward: they were for other
    // bytes. (Rows keyed (object_key, member_id) hold ONE current observation
    // per member; a stale `accepted_digest` simply never matches the new digest.)

    conn.execute(
        "INSERT INTO frozen_publication_artifact
            (object_key, content_digest, payload, bound_root, purpose, storage_set_id,
             state, last_error)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, '')",
        params![
            object_key,
            digest.as_slice(),
            payload,
            bound_root.as_slice(),
            purpose,
            storage_set_id.as_slice(),
            ArtifactState::Frozen.as_str(),
        ],
    )?;
    Ok(digest)
}

/// Record that member `member_id` accepted the artifact whose content digest is
/// `accepted_digest` for `object_key` — the member's ONE current observation
/// for that key. Only rows whose `accepted_digest` equals a row's
/// `content_digest` count toward that row's quorum.
pub fn record_accepting_member(
    object_key: &str,
    member_id: &str,
    accepted_digest: &[u8; 32],
) -> Result<()> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    conn.execute(
        "INSERT INTO frozen_publication_artifact_members (object_key, member_id, accepted_digest)
         VALUES (?1, ?2, ?3)
         ON CONFLICT(object_key, member_id) DO UPDATE SET
            accepted_digest = excluded.accepted_digest",
        params![object_key, member_id, accepted_digest.as_slice()],
    )?;
    Ok(())
}

/// Members whose current observation for `object_key` is EXACTLY
/// `content_digest`. A member holding different bytes under the key never
/// counts.
pub fn count_accepting_members(object_key: &str, content_digest: &[u8; 32]) -> Result<u32> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    let n: i64 = conn.query_row(
        "SELECT COUNT(*) FROM frozen_publication_artifact_members
          WHERE object_key = ?1 AND accepted_digest = ?2",
        params![object_key, content_digest.as_slice()],
        |r| r.get(0),
    )?;
    Ok(n as u32)
}

/// Advance an artifact's state, forward-only: `published` and `superseded`
/// never regress. Returns `true` if a row changed.
pub fn upsert_artifact_publication_state(
    object_key: &str,
    content_digest: &[u8; 32],
    state: ArtifactState,
    last_error: &str,
) -> Result<bool> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    let n = conn.execute(
        "UPDATE frozen_publication_artifact
            SET state = ?3, last_error = ?4
          WHERE object_key = ?1 AND content_digest = ?2
            AND state NOT IN ('published', 'superseded')",
        params![
            object_key,
            content_digest.as_slice(),
            state.as_str(),
            last_error
        ],
    )?;
    Ok(n > 0)
}

fn row_to_artifact(r: &rusqlite::Row<'_>) -> rusqlite::Result<FrozenArtifact> {
    let fixed = |v: Vec<u8>| -> [u8; 32] {
        let mut out = [0u8; 32];
        if v.len() == 32 {
            out.copy_from_slice(&v);
        }
        out
    };
    Ok(FrozenArtifact {
        insertion_ordinal: r.get(0)?,
        object_key: r.get(1)?,
        content_digest: fixed(r.get::<_, Vec<u8>>(2)?),
        payload: r.get(3)?,
        bound_root: fixed(r.get::<_, Vec<u8>>(4)?),
        purpose: r.get(5)?,
        storage_set_id: fixed(r.get::<_, Vec<u8>>(6)?),
        state: ArtifactState::from_str(&r.get::<_, String>(7)?),
        last_error: r.get(8)?,
    })
}

const SELECT_COLS: &str = "insertion_ordinal, object_key, content_digest, payload, bound_root, \
                           purpose, storage_set_id, state, last_error";

/// The artifact row for `(object_key, content_digest)`.
pub fn get_artifact(object_key: &str, content_digest: &[u8; 32]) -> Result<Option<FrozenArtifact>> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    let rec = conn
        .query_row(
            &format!(
                "SELECT {SELECT_COLS} FROM frozen_publication_artifact
                  WHERE object_key = ?1 AND content_digest = ?2"
            ),
            params![object_key, content_digest.as_slice()],
            row_to_artifact,
        )
        .optional()?;
    Ok(rec)
}

/// The LATEST (highest ordinal) artifact row under `object_key`, whatever its
/// state.
pub fn get_latest_artifact_for_key(object_key: &str) -> Result<Option<FrozenArtifact>> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    let rec = conn
        .query_row(
            &format!(
                "SELECT {SELECT_COLS} FROM frozen_publication_artifact
                  WHERE object_key = ?1
                  ORDER BY insertion_ordinal DESC LIMIT 1"
            ),
            params![object_key],
            row_to_artifact,
        )
        .optional()?;
    Ok(rec)
}

/// Every artifact still owed to its quorum, oldest first, bounded. Superseded
/// and published rows are excluded — nothing here is ever a second copy of a
/// fact, only bytes not yet delivered.
/// The exact frozen payload for `object_key`'s CURRENT (non-superseded) row.
/// Recovery reads THIS — never a regenerated object.
pub fn get_current_artifact_payload(object_key: &str) -> Result<Option<Vec<u8>>> {
    let binding = crate::storage::client_db::get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    let row = conn
        .query_row(
            "SELECT payload FROM frozen_publication_artifact
              WHERE object_key = ?1 AND state != 'superseded'
              ORDER BY insertion_ordinal DESC LIMIT 1",
            rusqlite::params![object_key],
            |r| r.get::<_, Vec<u8>>(0),
        )
        .optional()?;
    Ok(row)
}

/// The newest current payload whose object_key starts with `prefix` — used by
/// admission recovery to find the frozen witness without re-deriving its
/// address from bytes it does not yet have.
pub fn find_current_payload_with_prefix(prefix: &str) -> Result<Option<Vec<u8>>> {
    let binding = crate::storage::client_db::get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    let row = conn
        .query_row(
            "SELECT payload FROM frozen_publication_artifact
              WHERE object_key LIKE ?1 || '%' AND state != 'superseded'
              ORDER BY insertion_ordinal DESC LIMIT 1",
            rusqlite::params![prefix],
            |r| r.get::<_, Vec<u8>>(0),
        )
        .optional()?;
    Ok(row)
}

pub fn list_unpublished_artifacts(limit: u32) -> Result<Vec<FrozenArtifact>> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    let mut stmt = conn.prepare(&format!(
        "SELECT {SELECT_COLS} FROM frozen_publication_artifact
          WHERE state IN ('frozen', 'publication_pending')
          ORDER BY insertion_ordinal ASC
          LIMIT ?1"
    ))?;
    let rows = stmt
        .query_map(params![limit as i64], row_to_artifact)?
        .filter_map(|r| r.ok())
        .collect();
    Ok(rows)
}

/// `true` iff the LATEST artifact frozen under `object_key` is published.
/// (A key whose latest generation is still pending is not published, even if
/// an older generation was.)
pub fn is_artifact_published(object_key: &str) -> Result<bool> {
    Ok(matches!(
        get_latest_artifact_for_key(object_key)?,
        Some(FrozenArtifact {
            state: ArtifactState::Published,
            ..
        })
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::client_db::{get_connection, reset_database_for_tests};
    use serial_test::serial;

    fn freeze(set: &[u8; 32], key: &str, payload: &[u8]) -> [u8; 32] {
        let binding = get_connection().expect("db");
        let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
        freeze_artifact_with_conn(&conn, set, key, payload, &[0x11; 32], "test").expect("freeze")
    }

    #[test]
    #[serial]
    fn digest_is_derived_from_the_bytes_and_key() {
        reset_database_for_tests();
        let set = [0xA1u8; 32];
        let d = freeze(&set, "k/one", b"hello");
        assert_eq!(d, content_digest("k/one", b"hello"));
        // Same bytes, different key ⇒ a different artifact.
        assert_ne!(d, content_digest("k/two", b"hello"));
        let row = get_artifact("k/one", &d).unwrap().expect("row");
        assert_eq!(row.payload, b"hello");
        assert_eq!(row.storage_set_id, set, "the frozen set rides the row");
        assert_eq!(row.state, ArtifactState::Frozen);
        // Idempotent re-freeze: still one row, same digest.
        let d2 = freeze(&set, "k/one", b"hello");
        assert_eq!(d, d2);
        assert_eq!(list_unpublished_artifacts(16).unwrap().len(), 1);
    }

    #[test]
    #[serial]
    fn a_failing_transaction_leaves_no_row() {
        reset_database_for_tests();
        {
            let binding = get_connection().expect("db");
            let mut conn = binding.lock().unwrap_or_else(|p| p.into_inner());
            let tx = conn.transaction().expect("tx");
            freeze_artifact_with_conn(&tx, &[0xA1; 32], "k/tx", b"bytes", &[0; 32], "test")
                .expect("freeze inside tx");
            tx.rollback().expect("rollback");
        }
        assert!(get_latest_artifact_for_key("k/tx").unwrap().is_none());
    }

    #[test]
    #[serial]
    fn quorum_counts_only_members_that_accepted_these_exact_bytes() {
        reset_database_for_tests();
        let set = [0xA1u8; 32];
        let d = freeze(&set, "k/q", b"v1");
        record_accepting_member("k/q", "m1", &d).unwrap();
        record_accepting_member("k/q", "m2", &content_digest("k/q", b"stale")).unwrap();
        record_accepting_member("k/q", "m3", &d).unwrap();
        assert_eq!(
            count_accepting_members("k/q", &d).unwrap(),
            2,
            "the stale-digest member does not count"
        );
    }

    #[test]
    #[serial]
    fn new_bytes_under_a_key_supersede_and_the_sweep_never_sees_the_old_row() {
        reset_database_for_tests();
        let set = [0xA1u8; 32];
        let d0 = freeze(&set, "k/latest", b"gen0");
        assert!(
            upsert_artifact_publication_state("k/latest", &d0, ArtifactState::Published, "")
                .unwrap()
        );
        assert!(is_artifact_published("k/latest").unwrap());
        // A member accepted gen0.
        record_accepting_member("k/latest", "m1", &d0).unwrap();

        let d1 = freeze(&set, "k/latest", b"gen1");
        assert_ne!(d0, d1);
        let old = get_artifact("k/latest", &d0).unwrap().unwrap();
        assert_eq!(old.state, ArtifactState::Superseded, "gen0 superseded");
        assert!(
            !is_artifact_published("k/latest").unwrap(),
            "the LATEST generation is what 'published' answers for"
        );
        // Old acceptances do not carry forward to the new digest.
        assert_eq!(count_accepting_members("k/latest", &d1).unwrap(), 0);
        let pending = list_unpublished_artifacts(16).unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(
            pending[0].content_digest, d1,
            "only gen1 is owed to its quorum"
        );
    }

    #[test]
    #[serial]
    fn state_never_regresses_from_published_or_superseded() {
        reset_database_for_tests();
        let set = [0xA1u8; 32];
        let d = freeze(&set, "k/fwd", b"x");
        assert!(
            upsert_artifact_publication_state("k/fwd", &d, ArtifactState::Published, "").unwrap()
        );
        assert!(
            !upsert_artifact_publication_state(
                "k/fwd",
                &d,
                ArtifactState::PublicationPending,
                "late error"
            )
            .unwrap(),
            "published is terminal"
        );
        assert_eq!(
            get_artifact("k/fwd", &d).unwrap().unwrap().state,
            ArtifactState::Published
        );
        assert!(list_unpublished_artifacts(16).unwrap().is_empty());
    }

    #[test]
    #[serial]
    fn unpublished_work_is_ordered_by_insertion_ordinal() {
        reset_database_for_tests();
        let set = [0xA1u8; 32];
        freeze(&set, "k/b", b"1");
        freeze(&set, "k/a", b"2");
        freeze(&set, "k/c", b"3");
        let keys: Vec<String> = list_unpublished_artifacts(2)
            .unwrap()
            .into_iter()
            .map(|a| a.object_key)
            .collect();
        assert_eq!(
            keys,
            vec!["k/b".to_string(), "k/a".to_string()],
            "oldest first, bounded"
        );
    }
}
