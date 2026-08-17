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
    /// The EXECUTING device's (B's) canonical relationship pair for this apply
    /// (`advance_outcome.relationship_pair()`): its local lineage head before
    /// (`applied_parent_tip_b`) and after (`applied_child_tip_b`) the step. The
    /// child is the exact parent B will sign under when it next originates on
    /// this relationship; it is what B's countersignature authenticates to A.
    pub applied_parent_tip_b: [u8; 32],
    pub applied_child_tip_b: [u8; 32],
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
        h.update(&self.applied_parent_tip_b);
        h.update(&self.applied_child_tip_b);
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
            nonce_hash, applied_parent_root_b, applied_child_root_b,
            applied_parent_tip_b, applied_child_tip_b, record_hash, created_at
         ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15)",
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
            rec.applied_parent_tip_b.as_slice(),
            rec.applied_child_tip_b.as_slice(),
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
    fields: RecordFields,
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
        applied_parent_tip_b: arr32(fields.10, "applied_parent_tip_b")?,
        applied_child_tip_b: arr32(fields.11, "applied_child_tip_b")?,
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
     nonce_hash, applied_parent_root_b, applied_child_root_b, \
     applied_parent_tip_b, applied_child_tip_b";

/// The raw stored columns of one record, in `RECORD_COLS` order after the two
/// hashes: relationship_key, parent_tip, child_tip, precommit_digest,
/// operation_digest, sender_device, recipient_device, nonce_hash,
/// applied_parent_root_b, applied_child_root_b, applied_parent_tip_b,
/// applied_child_tip_b.
type RecordFields = (
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
    Vec<u8>,
    Vec<u8>,
);

fn row_to_parts(row: &rusqlite::Row) -> rusqlite::Result<(Vec<u8>, Vec<u8>, RecordFields)> {
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
            row.get(12)?,
            row.get(13)?,
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

/// The counterparty's (A-side) canonical head this device pins for the next
/// inbound step — read from `counterparty_canonical_heads`, the ONE authority
/// (advanced by CAS from both roles: the signed pair on inbound apply, the
/// `sig_b`-authenticated pair on sender finalize).
///
/// A relationship chain tip is a per-device value: the peer's head advances on
/// its applies of THIS device's sends as well as on its own sends, so it can
/// never be derived from what this device applied. The history-derived query
/// this replaced fell back to the genesis seed after the peer had applied two
/// transfers (the role-reversal failure) and forked at generation three.
///
/// `None` ⇔ no row: a fresh relationship — the caller pins the spec-canonical
/// genesis seed. Under beta (schema reset, no migration) "no row" and "no
/// applied history" coincide; a relationship with applied history and no
/// head row is corruption and fails closed rather than guessing.
pub fn pinned_counterparty_a_head(relationship_key: &[u8; 32]) -> Result<Option<[u8; 32]>> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    if let Some(head) =
        super::counterparty_canonical_heads::load_counterparty_canonical_head_with_conn(
            &conn,
            relationship_key,
        )?
    {
        return Ok(Some(head));
    }
    let applied: i64 = conn.query_row(
        "SELECT COUNT(*) FROM canonical_apply_identity WHERE relationship_key = ?1",
        params![relationship_key.as_slice()],
        |r| r.get(0),
    )?;
    if applied != 0 {
        return Err(anyhow!(
            "relationship has {applied} applied transition(s) but no counterparty canonical \
             head row — fail closed"
        ));
    }
    Ok(None)
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
            applied_parent_tip_b: [0x0Bu8; 32],
            applied_child_tip_b: [0x0Cu8; 32],
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

    // =====================================================================
    // REPLAY MATRIX (ADR 0003, pre-3c security gate).
    //
    // THE QUESTION: can the same already-valid signed operation + A-side
    // evidence be delivered under a FRESH transport correlation identity, after
    // one successful acceptance, and cause a SECOND semantic apply?
    //
    // THE ANSWER: no -- but by LAYERED DEFENCE, not by this identity alone.
    // Read that carefully before changing anything here, because the obvious
    // reading is wrong in a way that a single mutation test will not catch.
    //
    // What THIS module contributes: `canonical_apply_id` hashes only
    // AUTHENTICATED material -- relationship, parent/child tips, precommit and
    // operation digests, both device ids, and the nonce. No transport metadata
    // (transaction id, correlation key, envelope message id) is an input, so a
    // replay under any number of fresh correlation ids collapses onto the SAME
    // identity and is classified `Duplicate`. The tests below prove exactly
    // that -- a CLASSIFICATION property, at the outermost of five layers.
    //
    // What actually stops a double credit, established by a per-layer mutation
    // ladder against `CoreSDK::apply_incoming_transfer_full_state`:
    //
    //   L1  this pre-execution lookup (canonical_apply_id)
    //   L2  A-side head pin: signed parent must equal the pinned counterparty head
    //   L3  in-tx `is_nonce_spent` pre-check          (race window only)
    //   L4  in-tx canonical-apply insert -> Err        (race window only)
    //   L5  `spent_nonces` UNIQUE **at the INSERT**   <-- AUTHORITATIVE
    //
    // Bypassing L1 alone turns the duplicate test red, but the replay is
    // refused by L2 and no second mutation occurs -- so a mutation test that
    // stops at L1 credits this identity with a guarantee it does not provide.
    // Bypassing L1+L2+L3+L4 together leaves the suite GREEN. Only weakening the
    // L5 writer (`INSERT` -> `INSERT OR IGNORE` in `mark_nonce_spent_with_conn`)
    // produces a genuine second `Applied`. The read-then-check at L3 is TOCTOU
    // decoration; the WRITE is what holds.
    //
    //   same authenticated operation
    //   + arbitrary fresh transport correlation ids
    //   = one canonical apply
    //     one semantic acceptance identity
    //     possibly repeated delivery acknowledgements
    //     but NEVER a second value-bearing result
    //
    // Honest coverage note: L3 and L4 have no uniquely-observing test. They
    // guard a concurrent-apply race that a single-threaded test cannot create,
    // beneath authoritative UNIQUE constraints. Do not describe them as covered.
    // =====================================================================

    /// The identity is a pure function of authenticated material. This is the
    /// property every other replay test rests on -- and the limit of what this
    /// module guarantees on its own (see the L1..L5 note above).
    #[test]
    fn the_apply_identity_ignores_transport_metadata_entirely() {
        let a = rec(0xA1, 0xB1, 0xC1);
        // Byte-identical operation, delivered "again" -- nothing about transport
        // is an input, so there is no way to express a different correlation id
        // in this identity at all.
        let b = rec(0xA1, 0xB1, 0xC1);
        assert_eq!(
            a.canonical_apply_id(),
            b.canonical_apply_id(),
            "the same authenticated operation must have ONE identity regardless of delivery"
        );

        // ...and any change to authenticated material DOES change it.
        assert_ne!(
            a.canonical_apply_id(),
            rec(0xA2, 0xB1, 0xC1).canonical_apply_id()
        );
        assert_ne!(
            a.canonical_apply_id(),
            rec(0xA1, 0xB2, 0xC1).canonical_apply_id()
        );
        assert_ne!(
            a.canonical_apply_id(),
            rec(0xA1, 0xB1, 0xC2).canonical_apply_id()
        );
    }

    /// Exact replay under a fresh correlation -> Duplicate, never a second apply.
    #[test]
    #[serial]
    fn exact_replay_under_a_fresh_correlation_is_a_duplicate() {
        init_test_db();
        let r = rec(0xD1, 0xD2, 0xD3);

        {
            // Scoped: the connection mutex is NOT reentrant, and
            // `lookup_canonical_apply_status` takes it itself. Holding it across
            // that call hangs silently -- no panic, no error, just a stuck test.
            let binding = get_connection().expect("conn");
            let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
            insert_canonical_apply_identity_with_conn(&conn, &r).expect("first apply");
        }

        // The replay: same authenticated material, arriving under whatever fresh
        // transport identity an attacker or a retry chooses.
        match lookup_canonical_apply_status(
            &r.canonical_apply_id(),
            &r.relationship_key,
            &r.parent_tip,
            &r.nonce_hash,
        )
        .expect("lookup")
        {
            CanonicalApplyLookup::Duplicate(stored) => {
                assert_eq!(
                    stored.canonical_apply_id(),
                    r.canonical_apply_id(),
                    "the duplicate must converge on the SAME canonical record"
                );
            }
            other => panic!("expected Duplicate, got {other:?}"),
        }
    }

    /// The guard lives in canonical-apply storage, not in transport staging, so
    /// reaping a staging row cannot defeat it.
    #[test]
    #[serial]
    fn dedup_survives_reaping_the_transport_staging_row() {
        init_test_db();
        let r = rec(0xE1, 0xE2, 0xE3);
        {
            let binding = get_connection().expect("conn");
            let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
            insert_canonical_apply_identity_with_conn(&conn, &r).expect("first apply");
        }

        // Simulate the transport layer forgetting everything it knew: the
        // recipient staging table is emptied. The canonical record is a
        // different table with a different lifetime.
        {
            let binding = get_connection().expect("conn");
            let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
            conn.execute("DELETE FROM recipient_staging", [])
                .expect("reap staging");
        }

        assert!(
            matches!(
                lookup_canonical_apply_status(
                    &r.canonical_apply_id(),
                    &r.relationship_key,
                    &r.parent_tip,
                    &r.nonce_hash
                )
                .expect("lookup"),
                CanonicalApplyLookup::Duplicate(_)
            ),
            "dedup must not depend on transport staging retention"
        );
    }

    /// Same nonce, DIFFERENT operation identity -> Conflict, fail closed.
    #[test]
    #[serial]
    fn the_same_nonce_with_a_different_operation_conflicts() {
        init_test_db();
        let first = rec(0xF1, 0xF2, 0xF3);
        {
            let binding = get_connection().expect("conn");
            let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
            insert_canonical_apply_identity_with_conn(&conn, &first).expect("first apply");
        }

        // Different relationship and parent -- a genuinely different transition --
        // but reusing the nonce.
        let impostor = rec(0xAA, 0xBB, 0xF3);
        assert_ne!(impostor.canonical_apply_id(), first.canonical_apply_id());
        assert!(
            matches!(
                lookup_canonical_apply_status(
                    &impostor.canonical_apply_id(),
                    &impostor.relationship_key,
                    &impostor.parent_tip,
                    &impostor.nonce_hash
                )
                .expect("lookup"),
                CanonicalApplyLookup::Conflict
            ),
            "a different identity reusing a spent nonce must fail closed"
        );
    }

    /// Same (relationship, parent) with a conflicting transition -> Conflict.
    #[test]
    #[serial]
    fn the_same_relationship_and_parent_with_a_different_transition_conflicts() {
        init_test_db();
        let first = rec(0x11, 0x22, 0x33);
        {
            let binding = get_connection().expect("conn");
            let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
            insert_canonical_apply_identity_with_conn(&conn, &first).expect("first apply");
        }

        let forked = rec(0x11, 0x22, 0x99); // same rel+parent, different nonce
        assert_ne!(forked.canonical_apply_id(), first.canonical_apply_id());
        assert!(
            matches!(
                lookup_canonical_apply_status(
                    &forked.canonical_apply_id(),
                    &forked.relationship_key,
                    &forked.parent_tip,
                    &forked.nonce_hash
                )
                .expect("lookup"),
                CanonicalApplyLookup::Conflict
            ),
            "a fork on the same (relationship, parent) must fail closed"
        );
    }
}
