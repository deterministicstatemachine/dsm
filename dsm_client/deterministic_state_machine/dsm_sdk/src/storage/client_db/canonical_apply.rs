// SPDX-License-Identifier: MIT OR Apache-2.0
//! Canonical apply identity/record (§16.6 single-commit apply).
//!
//! The durable proof that ONE exact authenticated parent state was consumed and
//! replaced by ONE exact authenticated successor. Written INSIDE the full-state
//! apply transaction (with the DeviceState successor, BCR archive, device head,
//! nonce consumption, and recovery index — all exist or none do).
//!
//! Two hashes, kept conceptually separate:
//! - `canonical_apply_id` — over the PRE-EXECUTION request identity (NO roots;
//!   roots are outputs). The lookup key: a duplicate re-delivery derives the same
//!   id and loads the record verbatim, with NO re-execution.
//! - `canonical_apply_record_hash` — over the id plus the executing device's (B's)
//!   authoritative applied roots. Complete-result integrity for the stored row.
//!
//! Every load re-validates: field lengths, both recomputed hashes. Fail closed on
//! any mismatch — a corrupt record must never drive projection sync or receipt
//! completion.

use super::get_connection;
use crate::util::deterministic_time::tick;
use anyhow::{anyhow, Result};
use rusqlite::{params, OptionalExtension};

/// The persisted canonical apply record. Loaded verbatim on the duplicate path —
/// NEVER reconstructed from mutable state (the relationship may advance again).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalApplyRecord {
    pub relationship_key: [u8; 32],
    pub parent_tip: [u8; 32],
    pub child_tip: [u8; 32],
    /// `C_pre` — precommit over parent + op + entropy (specifically C_pre, not a
    /// digest of the whole transition).
    pub precommit_digest: [u8; 32],
    /// BLAKE3 of the canonical operation bytes.
    pub operation_digest: [u8; 32],
    pub sender_device: [u8; 32],
    pub recipient_device: [u8; 32],
    /// BLAKE3 of the op nonce — recipient-device-wide replay scope (matches the
    /// existing `spent_nonces` rule; no relationship/sender scoping).
    pub nonce_hash: [u8; 32],
    /// The EXECUTING device's (B's) authoritative pre-state root produced by the
    /// state mutation (`advance_outcome.parent_r_a`).
    pub applied_parent_root_b: [u8; 32],
    /// The EXECUTING device's (B's) authoritative post-state root
    /// (`advance_outcome.child_r_a`).
    pub applied_child_root_b: [u8; 32],
}

impl CanonicalApplyRecord {
    /// Pre-execution request identity hash — the lookup key. Excludes roots
    /// (outputs) by construction.
    pub fn canonical_apply_id(&self) -> [u8; 32] {
        compute_canonical_apply_id(
            &self.relationship_key,
            &self.parent_tip,
            &self.child_tip,
            &self.precommit_digest,
            &self.operation_digest,
            &self.sender_device,
            &self.recipient_device,
            &self.nonce_hash,
        )
    }

    /// Complete-result integrity hash: id + authoritative applied B roots.
    pub fn record_hash(&self) -> [u8; 32] {
        let id = self.canonical_apply_id();
        let mut h = dsm::crypto::blake3::dsm_domain_hasher(dsm::tagged_domain!(
            b"DSM/canonical-apply-record/v1"
        ));
        h.update(&id);
        h.update(&self.applied_parent_root_b);
        h.update(&self.applied_child_root_b);
        let mut out = [0u8; 32];
        out.copy_from_slice(&h.finalize().as_bytes()[..32]);
        out
    }
}

/// `canonical_apply_id` from the pre-execution request identity (NO roots).
#[allow(clippy::too_many_arguments)]
pub fn compute_canonical_apply_id(
    relationship_key: &[u8; 32],
    parent_tip: &[u8; 32],
    child_tip: &[u8; 32],
    precommit_digest: &[u8; 32],
    operation_digest: &[u8; 32],
    sender_device: &[u8; 32],
    recipient_device: &[u8; 32],
    nonce_hash: &[u8; 32],
) -> [u8; 32] {
    let mut h =
        dsm::crypto::blake3::dsm_domain_hasher(dsm::tagged_domain!(b"DSM/canonical-apply-id/v1"));
    h.update(relationship_key);
    h.update(parent_tip);
    h.update(child_tip);
    h.update(precommit_digest);
    h.update(operation_digest);
    h.update(sender_device);
    h.update(recipient_device);
    h.update(nonce_hash);
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize().as_bytes()[..32]);
    out
}

/// Outcome of the in-transaction insert.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CanonicalApplyInsertOutcome {
    /// Fresh insert — this transaction owns the apply.
    Inserted,
    /// A row with the EXACT same `canonical_apply_id` already exists (verified
    /// field-for-field + record-hash). The loaded record is returned.
    DuplicateSameOperation(Box<CanonicalApplyRecord>),
    /// A row collides on a UNIQUE constraint (same relationship+parent, or same
    /// nonce) but carries a DIFFERENT identity — fail closed.
    Conflict,
}

/// Insert the canonical apply record INSIDE the caller's transaction (`&tx`).
/// NEVER `INSERT OR IGNORE`: an exact-duplicate row returns the loaded record;
/// a constraint collision with different fields returns `Conflict`. The caller
/// rolls back its transaction on `Conflict` (and discards any prepared
/// successor); on `DuplicateSameOperation` the caller must NOT re-execute.
pub fn insert_canonical_apply_identity_with_conn(
    conn: &rusqlite::Connection,
    rec: &CanonicalApplyRecord,
) -> Result<CanonicalApplyInsertOutcome> {
    let id = rec.canonical_apply_id();
    let record_hash = rec.record_hash();

    // Explicit pre-checks (under the same tx snapshot) so an exact duplicate is
    // classified BEFORE the INSERT throws a constraint error.
    if let Some(existing) = load_by_id_locked(conn, &id)? {
        return Ok(CanonicalApplyInsertOutcome::DuplicateSameOperation(
            Box::new(existing),
        ));
    }
    let collision: Option<i64> = conn
        .query_row(
            "SELECT 1 FROM canonical_apply_identity
             WHERE (relationship_key = ?1 AND parent_tip = ?2) OR nonce_hash = ?3
             LIMIT 1",
            params![
                rec.relationship_key.as_slice(),
                rec.parent_tip.as_slice(),
                rec.nonce_hash.as_slice()
            ],
            |r| r.get(0),
        )
        .optional()?;
    if collision.is_some() {
        return Ok(CanonicalApplyInsertOutcome::Conflict);
    }

    match conn.execute(
        "INSERT INTO canonical_apply_identity (
            canonical_apply_id, relationship_key, parent_tip, child_tip,
            precommit_digest, operation_digest, sender_device, recipient_device,
            nonce_hash, applied_parent_root_b, applied_child_root_b, record_hash, created_at
         ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)",
        params![
            id.as_slice(),
            rec.relationship_key.as_slice(),
            rec.parent_tip.as_slice(),
            rec.child_tip.as_slice(),
            rec.precommit_digest.as_slice(),
            rec.operation_digest.as_slice(),
            rec.sender_device.as_slice(),
            rec.recipient_device.as_slice(),
            rec.nonce_hash.as_slice(),
            rec.applied_parent_root_b.as_slice(),
            rec.applied_child_root_b.as_slice(),
            record_hash.as_slice(),
            tick() as i64,
        ],
    ) {
        Ok(_) => Ok(CanonicalApplyInsertOutcome::Inserted),
        // Losing racer: the UNIQUE constraints are the ultimate authority. Re-read
        // to classify the winner's row.
        Err(rusqlite::Error::SqliteFailure(err, _))
            if err.code == rusqlite::ErrorCode::ConstraintViolation =>
        {
            match load_by_id_locked(conn, &id)? {
                Some(existing) => Ok(CanonicalApplyInsertOutcome::DuplicateSameOperation(
                    Box::new(existing),
                )),
                None => Ok(CanonicalApplyInsertOutcome::Conflict),
            }
        }
        Err(e) => Err(e.into()),
    }
}

fn arr32(v: Vec<u8>, what: &str) -> Result<[u8; 32]> {
    v.as_slice()
        .try_into()
        .map_err(|_| anyhow!("canonical apply record: {what} is not 32 bytes"))
}

/// Constant-time-ish 32-byte comparison (no early exit).
fn ct_eq32(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for i in 0..32 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

/// Row → record with MANDATORY integrity verification: validate lengths,
/// recompute `canonical_apply_id`, recompute `record_hash`, compare both
/// (constant-time), fail closed on any mismatch.
fn hydrate_verified(
    stored_id: Vec<u8>,
    stored_record_hash: Vec<u8>,
    fields: (
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
    ),
) -> Result<CanonicalApplyRecord> {
    let rec = CanonicalApplyRecord {
        relationship_key: arr32(fields.0, "relationship_key")?,
        parent_tip: arr32(fields.1, "parent_tip")?,
        child_tip: arr32(fields.2, "child_tip")?,
        precommit_digest: arr32(fields.3, "precommit_digest")?,
        operation_digest: arr32(fields.4, "operation_digest")?,
        sender_device: arr32(fields.5, "sender_device")?,
        recipient_device: arr32(fields.6, "recipient_device")?,
        nonce_hash: arr32(fields.7, "nonce_hash")?,
        applied_parent_root_b: arr32(fields.8, "applied_parent_root_b")?,
        applied_child_root_b: arr32(fields.9, "applied_child_root_b")?,
    };
    let stored_id: [u8; 32] = arr32(stored_id, "canonical_apply_id")?;
    let stored_record_hash: [u8; 32] = arr32(stored_record_hash, "record_hash")?;
    if !ct_eq32(&rec.canonical_apply_id(), &stored_id) {
        return Err(anyhow!(
            "canonical apply record FAILED integrity: canonical_apply_id mismatch — fail closed"
        ));
    }
    if !ct_eq32(&rec.record_hash(), &stored_record_hash) {
        return Err(anyhow!(
            "canonical apply record FAILED integrity: record_hash mismatch — fail closed"
        ));
    }
    Ok(rec)
}

const RECORD_COLS: &str = "canonical_apply_id, record_hash, relationship_key, parent_tip, \
     child_tip, precommit_digest, operation_digest, sender_device, recipient_device, \
     nonce_hash, applied_parent_root_b, applied_child_root_b";

#[allow(clippy::type_complexity)]
fn row_to_parts(
    row: &rusqlite::Row,
) -> rusqlite::Result<(
    Vec<u8>,
    Vec<u8>,
    (
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
    ),
)> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        (
            row.get(2)?,
            row.get(3)?,
            row.get(4)?,
            row.get(5)?,
            row.get(6)?,
            row.get(7)?,
            row.get(8)?,
            row.get(9)?,
            row.get(10)?,
            row.get(11)?,
        ),
    ))
}

fn load_by_id_locked(
    conn: &rusqlite::Connection,
    id: &[u8; 32],
) -> Result<Option<CanonicalApplyRecord>> {
    let parts = conn
        .query_row(
            &format!(
                "SELECT {RECORD_COLS} FROM canonical_apply_identity WHERE canonical_apply_id = ?1"
            ),
            params![id.as_slice()],
            row_to_parts,
        )
        .optional()?;
    match parts {
        Some((sid, shash, fields)) => Ok(Some(hydrate_verified(sid, shash, fields)?)),
        None => Ok(None),
    }
}

/// Load the verified record for a consumed step, by relationship + parent.
pub fn get_canonical_apply_identity(
    relationship_key: &[u8; 32],
    parent_tip: &[u8; 32],
) -> Result<Option<CanonicalApplyRecord>> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    let parts = conn
        .query_row(
            &format!(
                "SELECT {RECORD_COLS} FROM canonical_apply_identity \
                 WHERE relationship_key = ?1 AND parent_tip = ?2"
            ),
            params![relationship_key.as_slice(), parent_tip.as_slice()],
            row_to_parts,
        )
        .optional()?;
    match parts {
        Some((sid, shash, fields)) => Ok(Some(hydrate_verified(sid, shash, fields)?)),
        None => Ok(None),
    }
}

/// The counterparty's (A-side) lineage head as pinned by the transitions THIS
/// device has durably applied for the relationship (§16.6 authority sourcing).
///
/// This is the space-correct successor check. A relationship chain tip is a
/// per-device value (see `CoreSDK::execute_on_relationship_guarded`), so the
/// recipient can never recompute the sender's child. What it CAN do is PIN the
/// sender's asymmetric head: every stored `child_tip` is a signature-verified
/// A-side value, so the head is the one applied child that no other applied
/// record consumes as its parent. The next honest proposal must start exactly
/// there — a stale, replayed, reordered, or forked sender lineage does not.
///
/// Returns `None` when nothing has been applied yet; the caller pins the
/// spec-canonical genesis seed instead (the one tip both sides derive
/// identically, by sorted (genesis, devid) pair).
///
/// A relationship with more than one such head is a forked local history and
/// fails closed rather than guessing.
pub fn pinned_counterparty_a_head(relationship_key: &[u8; 32]) -> Result<Option<[u8; 32]>> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    let mut stmt = conn.prepare(
        "SELECT a.child_tip FROM canonical_apply_identity a \
         WHERE a.relationship_key = ?1 \
           AND NOT EXISTS ( \
                 SELECT 1 FROM canonical_apply_identity b \
                 WHERE b.relationship_key = ?1 AND b.parent_tip = a.child_tip \
           )",
    )?;
    let heads: Vec<Vec<u8>> = stmt
        .query_map(params![relationship_key.as_slice()], |r| {
            r.get::<_, Vec<u8>>(0)
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    match heads.len() {
        0 => Ok(None),
        1 => {
            let h = &heads[0];
            if h.len() != 32 {
                return Err(anyhow!(
                    "pinned A-side head is {} bytes, expected 32 (corrupt row)",
                    h.len()
                ));
            }
            let mut out = [0u8; 32];
            out.copy_from_slice(h);
            Ok(Some(out))
        }
        n => Err(anyhow!(
            "relationship has {n} A-side lineage heads — forked applied history, fail closed"
        )),
    }
}

/// Load the verified record by its pre-execution identity id.
pub fn get_canonical_apply_identity_by_id(id: &[u8; 32]) -> Result<Option<CanonicalApplyRecord>> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    load_by_id_locked(&conn, id)
}

/// Pre-execution classification of an apply request (§16.6 lookup-before-execute).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CanonicalApplyLookup {
    /// No record on any uniqueness dimension — fresh, proceed to execution.
    Fresh,
    /// The EXACT identity already applied — return the loaded verified record;
    /// NO state execution, NO re-credit.
    Duplicate(Box<CanonicalApplyRecord>),
    /// A different identity already consumed this (relationship, parent) or this
    /// nonce — fail closed, no mutation.
    Conflict,
}

/// Classify an apply request BEFORE any state inspection or execution: exact
/// `canonical_apply_id` match → `Duplicate(loaded record)`; a row colliding on
/// `(relationship_key, parent_tip)` or `nonce_hash` with a different identity →
/// `Conflict`; nothing → `Fresh`.
pub fn lookup_canonical_apply_status(
    id: &[u8; 32],
    relationship_key: &[u8; 32],
    parent_tip: &[u8; 32],
    nonce_hash: &[u8; 32],
) -> Result<CanonicalApplyLookup> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    if let Some(existing) = load_by_id_locked(&conn, id)? {
        return Ok(CanonicalApplyLookup::Duplicate(Box::new(existing)));
    }
    let collision: Option<i64> = conn
        .query_row(
            "SELECT 1 FROM canonical_apply_identity
             WHERE (relationship_key = ?1 AND parent_tip = ?2) OR nonce_hash = ?3
             LIMIT 1",
            params![
                relationship_key.as_slice(),
                parent_tip.as_slice(),
                nonce_hash.as_slice()
            ],
            |r| r.get(0),
        )
        .optional()?;
    if collision.is_some() {
        return Ok(CanonicalApplyLookup::Conflict);
    }
    Ok(CanonicalApplyLookup::Fresh)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    fn init_test_db() {
        unsafe { std::env::set_var("DSM_SDK_TEST_MODE", "1") };
        crate::storage::client_db::reset_database_for_tests();
        crate::storage::client_db::init_database().expect("init db");
    }

    fn rec(rel: u8, parent: u8, nonce: u8) -> CanonicalApplyRecord {
        CanonicalApplyRecord {
            relationship_key: [rel; 32],
            parent_tip: [parent; 32],
            child_tip: [0x03u8; 32],
            precommit_digest: [0x04u8; 32],
            operation_digest: [0x05u8; 32],
            sender_device: [0x06u8; 32],
            recipient_device: [0x07u8; 32],
            nonce_hash: [nonce; 32],
            applied_parent_root_b: [0x08u8; 32],
            applied_child_root_b: [0x09u8; 32],
        }
    }

    fn with_tx<T>(f: impl FnOnce(&rusqlite::Connection) -> Result<T>) -> Result<T> {
        let binding = crate::storage::client_db::get_connection()?;
        let mut conn = binding.lock().unwrap_or_else(|p| p.into_inner());
        let tx = conn.transaction()?;
        let out = f(&tx)?;
        tx.commit()?;
        Ok(out)
    }

    #[test]
    #[serial]
    fn insert_then_exact_duplicate_returns_original_record() {
        init_test_db();
        let r = rec(0x11, 0x12, 0x13);
        let out1 = with_tx(|c| insert_canonical_apply_identity_with_conn(c, &r)).unwrap();
        assert_eq!(out1, CanonicalApplyInsertOutcome::Inserted);
        // Exact duplicate → loaded original, verified.
        let out2 = with_tx(|c| insert_canonical_apply_identity_with_conn(c, &r)).unwrap();
        assert_eq!(
            out2,
            CanonicalApplyInsertOutcome::DuplicateSameOperation(Box::new(r.clone()))
        );
        // Reader by (rel, parent) also verifies.
        let loaded = get_canonical_apply_identity(&r.relationship_key, &r.parent_tip)
            .unwrap()
            .unwrap();
        assert_eq!(loaded, r);
    }

    #[test]
    #[serial]
    fn different_identity_reusing_nonce_or_parent_is_conflict() {
        init_test_db();
        let r = rec(0x21, 0x22, 0x23);
        with_tx(|c| insert_canonical_apply_identity_with_conn(c, &r)).unwrap();
        // Same nonce, different relationship/parent → Conflict.
        let mut nonce_reuse = rec(0x31, 0x32, 0x23);
        nonce_reuse.child_tip = [0xEEu8; 32];
        let out = with_tx(|c| insert_canonical_apply_identity_with_conn(c, &nonce_reuse)).unwrap();
        assert_eq!(out, CanonicalApplyInsertOutcome::Conflict);
        // Same (rel, parent), different op/child → Conflict.
        let mut second_child = rec(0x21, 0x22, 0x99);
        second_child.child_tip = [0xDDu8; 32];
        let out2 =
            with_tx(|c| insert_canonical_apply_identity_with_conn(c, &second_child)).unwrap();
        assert_eq!(out2, CanonicalApplyInsertOutcome::Conflict);
    }

    #[test]
    #[serial]
    fn corrupted_record_fails_closed_on_load() {
        init_test_db();
        let r = rec(0x41, 0x42, 0x43);
        with_tx(|c| insert_canonical_apply_identity_with_conn(c, &r)).unwrap();
        // Corrupt a root field in place (simulates disk/state tamper).
        {
            let binding = crate::storage::client_db::get_connection().unwrap();
            let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
            conn.execute(
                "UPDATE canonical_apply_identity SET applied_child_root_b = ?1 WHERE relationship_key = ?2",
                params![[0xFFu8; 32].as_slice(), r.relationship_key.as_slice()],
            )
            .unwrap();
        }
        let err = get_canonical_apply_identity(&r.relationship_key, &r.parent_tip).unwrap_err();
        assert!(err.to_string().contains("FAILED integrity"));
    }

    #[test]
    fn id_excludes_roots_record_hash_binds_them() {
        let a = rec(0x51, 0x52, 0x53);
        let mut b = a.clone();
        b.applied_child_root_b = [0xABu8; 32];
        // Same pre-execution identity → same id.
        assert_eq!(a.canonical_apply_id(), b.canonical_apply_id());
        // Different applied roots → different record hash.
        assert_ne!(a.record_hash(), b.record_hash());
    }
}
