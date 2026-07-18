// SPDX-License-Identifier: MIT OR Apache-2.0
//! Durable state for the recipient B-side acceptance-receipt fold (§16.6).
//!
//! Three durable phases (see design doc): the receipt is generated + persisted
//! BEFORE application; the cert heads + outbox are produced only AFTER the
//! transition is durably applied. Recovery NEVER signs.
//!
//!   prepared -> applied -> complete   (+ rejected)
//!
//! Phase 1 PREPARE  : `insert_prepared_acceptance_journal` — exact receipt bytes +
//!                    pre-step B head + new B head (ek_pk_b) + encrypted ek_sk_b +
//!                    the A-head expectation (ek_pk_a). No head advance, no outbox.
//! Phase 2 APPLIED  : `promote_prepared_to_applied` — promote only once the exact
//!                    transition is verifiably applied (recipient canonical tip ==
//!                    child_tip, which binds parent->child), else `NotYetApplied`.
//! Phase 3 COMPLETE : `complete_applied_acceptance` — CAS-advance the A counterparty
//!                    head + the B local head, install the outbox, mark complete,
//!                    wipe the encrypted ek_sk_b. Only runs on an `applied` journal.
//!                    Every phase is idempotent.

use super::cert_chain::{
    cas_advance_counterparty_cert_chain_head, cas_advance_local_cert_chain_head_with_sk,
    decrypt_chain_sk, CasHeadOutcome, CertChainSide,
};
use super::get_connection;
use crate::util::deterministic_time::tick;
use anyhow::{anyhow, Result};
use rusqlite::{params, OptionalExtension};

pub const STATUS_PREPARED: &str = "prepared";
pub const STATUS_APPLIED: &str = "applied";
pub const STATUS_COMPLETE: &str = "complete";
pub const STATUS_REJECTED: &str = "rejected";

/// A recipient acceptance-fold journal row.
///
/// `Debug` is hand-written to REDACT `new_local_b_sk_enc`: the encrypted EK
/// secret must never appear in logs, errors, traces, or debug formatting.
#[derive(Clone, PartialEq, Eq)]
pub struct RecipientAcceptanceJournal {
    pub relationship_key: [u8; 32],
    pub parent_tip: [u8; 32],
    pub child_tip: [u8; 32],
    pub counterparty_device_id: [u8; 32],
    pub commitment: [u8; 32],
    pub receipt_parent_root_a: [u8; 32],
    pub receipt_child_root_a: [u8; 32],
    /// Canonical pre-commit digest — specifically `C_pre` (precommit over parent +
    /// op + entropy), NOT a digest of the whole accepted transition.
    pub precommit_digest: [u8; 32],
    /// `BLAKE3("DSM/acceptance-artifact/v1" || exact_persisted_full_receipt_bytes)`.
    /// Binds the EXACT signed EK artifact (sig_b / ek_pk_b / ek_cert_b / kyber_ct_b
    /// and any non-commitment envelope fields), separate from the semantic
    /// `commitment`. Computed over `receipt_bytes` verbatim — never reserialized.
    pub prepared_receipt_artifact_hash: [u8; 32],
    /// Pre-step local B cert head (predecessor). `None` at relationship genesis.
    pub expected_local_b_head: Option<Vec<u8>>,
    /// New local B cert head (`ek_pk_b`).
    pub new_local_b_head: Vec<u8>,
    /// New EK secret key (`ek_sk_b`), ENCRYPTED; `None` once wiped on complete.
    pub new_local_b_sk_enc: Option<Vec<u8>>,
    /// Pre-step counterparty (A) cert head. `None` at relationship genesis.
    pub expected_counterparty_a_head: Option<Vec<u8>>,
    /// New counterparty (A) cert head (`ek_pk_a` from the inbound receipt).
    pub new_counterparty_a_head: Vec<u8>,
    /// Exact canonical `StitchedReceiptV2::to_full_protobuf` bytes (with `sig_b`).
    pub receipt_bytes: Vec<u8>,
    pub status: String,
    pub created_at: u64,
}

impl std::fmt::Debug for RecipientAcceptanceJournal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecipientAcceptanceJournal")
            .field("relationship_key", &hex_prefix(&self.relationship_key))
            .field("parent_tip", &hex_prefix(&self.parent_tip))
            .field("child_tip", &hex_prefix(&self.child_tip))
            .field("commitment", &hex_prefix(&self.commitment))
            .field(
                "expected_local_b_head",
                &self.expected_local_b_head.as_ref().map(|h| h.len()),
            )
            .field("new_local_b_head_len", &self.new_local_b_head.len())
            .field(
                "new_local_b_sk_enc",
                &self.new_local_b_sk_enc.as_ref().map(|_| "<redacted>"),
            )
            .field("new_counterparty_a_head_len", &self.new_counterparty_a_head.len())
            .field("receipt_bytes_len", &self.receipt_bytes.len())
            .field("status", &self.status)
            .finish()
    }
}

fn hex_prefix(b: &[u8; 32]) -> String {
    format!("{:02x}{:02x}{:02x}{:02x}..", b[0], b[1], b[2], b[3])
}

fn arr32(v: Vec<u8>, what: &str) -> Result<[u8; 32]> {
    v.as_slice()
        .try_into()
        .map_err(|_| anyhow!("{what} is not 32 bytes"))
}

const JOURNAL_COLS: &str = "relationship_key, parent_tip, child_tip, counterparty_device_id, \
     commitment, receipt_parent_root_a, receipt_child_root_a, precommit_digest, artifact_hash, \
     expected_local_b_head, new_local_b_head, new_local_b_sk_enc, \
     expected_counterparty_a_head, new_counterparty_a_head, receipt_bytes, status, created_at";

/// Domain-separated hash binding the EXACT persisted full receipt bytes (signed EK
/// artifact). Hash the precise stored/outbox bytes — never deserialize+reserialize.
pub fn acceptance_artifact_hash(exact_full_receipt_bytes: &[u8]) -> [u8; 32] {
    let mut h = dsm::crypto::blake3::dsm_domain_hasher("DSM/acceptance-artifact/v1");
    h.update(exact_full_receipt_bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize().as_bytes()[..32]);
    out
}

#[allow(clippy::type_complexity)]
fn row_to_journal(
    row: &rusqlite::Row,
) -> rusqlite::Result<RecipientAcceptanceJournal> {
    let g = |i: usize| -> rusqlite::Result<Vec<u8>> { row.get::<_, Vec<u8>>(i) };
    let go = |i: usize| -> rusqlite::Result<Option<Vec<u8>>> { row.get::<_, Option<Vec<u8>>>(i) };
    let to32 = |v: Vec<u8>| -> [u8; 32] {
        let mut a = [0u8; 32];
        let n = v.len().min(32);
        a[..n].copy_from_slice(&v[..n]);
        a
    };
    Ok(RecipientAcceptanceJournal {
        relationship_key: to32(g(0)?),
        parent_tip: to32(g(1)?),
        child_tip: to32(g(2)?),
        counterparty_device_id: to32(g(3)?),
        commitment: to32(g(4)?),
        receipt_parent_root_a: to32(g(5)?),
        receipt_child_root_a: to32(g(6)?),
        precommit_digest: to32(g(7)?),
        prepared_receipt_artifact_hash: to32(g(8)?),
        expected_local_b_head: go(9)?,
        new_local_b_head: g(10)?,
        new_local_b_sk_enc: go(11)?,
        expected_counterparty_a_head: go(12)?,
        new_counterparty_a_head: g(13)?,
        receipt_bytes: g(14)?,
        status: row.get::<_, String>(15)?,
        created_at: row.get::<_, i64>(16)? as u64,
    })
}

/// Phase 1: insert the PREPARED journal row (exact receipt bytes persisted before
/// application). Idempotent for the identical row; FAILS CLOSED on a different
/// commitment/child for the same consumed parent — one consumed step yields
/// exactly one countersigned receipt.
pub fn insert_prepared_acceptance_journal(rec: &RecipientAcceptanceJournal) -> Result<()> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());

    let existing: Option<(Vec<u8>, Vec<u8>)> = conn
        .query_row(
            "SELECT commitment, child_tip FROM acceptance_fold_journal
             WHERE relationship_key = ?1 AND parent_tip = ?2",
            params![rec.relationship_key.as_slice(), rec.parent_tip.as_slice()],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    if let Some((existing_commitment, existing_child)) = existing {
        if existing_commitment.as_slice() == rec.commitment.as_slice()
            && existing_child.as_slice() == rec.child_tip.as_slice()
        {
            return Ok(()); // idempotent re-entry
        }
        return Err(anyhow!(
            "recipient acceptance journal already holds a DIFFERENT receipt for this consumed \
             parent — refusing to derive a second B-side receipt"
        ));
    }

    conn.execute(
        &format!(
            "INSERT INTO acceptance_fold_journal ({JOURNAL_COLS}) \
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17)"
        ),
        params![
            rec.relationship_key.as_slice(),
            rec.parent_tip.as_slice(),
            rec.child_tip.as_slice(),
            rec.counterparty_device_id.as_slice(),
            rec.commitment.as_slice(),
            rec.receipt_parent_root_a.as_slice(),
            rec.receipt_child_root_a.as_slice(),
            rec.precommit_digest.as_slice(),
            rec.prepared_receipt_artifact_hash.as_slice(),
            rec.expected_local_b_head.as_deref(),
            rec.new_local_b_head.as_slice(),
            rec.new_local_b_sk_enc.as_deref(),
            rec.expected_counterparty_a_head.as_deref(),
            rec.new_counterparty_a_head.as_slice(),
            rec.receipt_bytes.as_slice(),
            STATUS_PREPARED,
            tick() as i64,
        ],
    )?;
    Ok(())
}

pub fn get_acceptance_journal(
    relationship_key: &[u8; 32],
    parent_tip: &[u8; 32],
) -> Result<Option<RecipientAcceptanceJournal>> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    Ok(conn
        .query_row(
            &format!(
                "SELECT {JOURNAL_COLS} FROM acceptance_fold_journal \
                 WHERE relationship_key = ?1 AND parent_tip = ?2"
            ),
            params![relationship_key.as_slice(), parent_tip.as_slice()],
            row_to_journal,
        )
        .optional()?)
}

/// All journals not yet complete/rejected — for startup + on-access recovery.
pub fn get_incomplete_acceptance_journals() -> Result<Vec<RecipientAcceptanceJournal>> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    let mut stmt = conn.prepare(&format!(
        "SELECT {JOURNAL_COLS} FROM acceptance_fold_journal \
         WHERE status IN ('prepared','applied')"
    ))?;
    let rows = stmt.query_map([], row_to_journal)?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r?);
    }
    Ok(out)
}

/// Outcome of promoting a prepared journal toward Applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PromoteOutcome {
    /// The exact transition is durably applied; journal is now Applied (or was).
    Applied,
    /// The transition is not (yet) durably applied — the recipient canonical tip
    /// is not at `child_tip`. Do not complete; re-delivery will apply it.
    NotYetApplied,
    /// The journal is Rejected/Aborted — do not proceed.
    Rejected,
}

/// The immutable accepted-transition marker: the recipient's durable attestation
/// that it applied EXACTLY this transition. Written atomically with the canonical
/// tip advance in the accept path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptedTransition {
    pub relationship_key: [u8; 32],
    pub parent_tip: [u8; 32],
    pub child_tip: [u8; 32],
    /// Party A's roots as CLAIMED by the inbound receipt (covered by the
    /// semantic commitment the recipient countersigned). Never conflated with
    /// the applied B roots below.
    pub receipt_parent_root_a: [u8; 32],
    pub receipt_child_root_a: [u8; 32],
    /// The executing device's (B's) AUTHORITATIVE roots, sourced from the
    /// durable `CanonicalApplyRecord` produced by the state mutation itself.
    pub applied_parent_root_b: [u8; 32],
    pub applied_child_root_b: [u8; 32],
    /// `C_pre` (precommit over parent + op + entropy) — NOT the whole transition.
    pub precommit_digest: [u8; 32],
    /// Semantic receipt identity (receipt commitment over fields 1-10).
    pub prepared_receipt_commitment: [u8; 32],
    /// Exact signed EK artifact: `acceptance_artifact_hash(exact full receipt bytes)`.
    pub prepared_receipt_artifact_hash: [u8; 32],
    pub sender_device: [u8; 32],
    pub recipient_device: [u8; 32],
}

/// Persist the accepted-transition marker (idempotent for the identical record;
/// FAILS CLOSED if a different marker already exists for the same consumed parent).
/// The caller MUST write this in the SAME durable step as the recipient's canonical
/// tip advance so a crash cannot leave "applied" without the exact marker.
pub fn record_accepted_transition(m: &AcceptedTransition) -> Result<()> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    record_accepted_transition_in_tx(&conn, m)
}

/// Marker insert against a caller-supplied connection/transaction — used by the
/// projection-sync so the marker commits (or rolls back) WITH the projection
/// update in one client-db transaction. Same immutability semantics: identical
/// existing marker → idempotent no-op; DIFFERENT existing marker → Err (the
/// caller's transaction must roll back).
pub(crate) fn record_accepted_transition_in_tx(
    conn: &rusqlite::Connection,
    m: &AcceptedTransition,
) -> Result<()> {
    let existing = get_accepted_transition_locked(conn, &m.relationship_key, &m.parent_tip)?;
    if let Some(prev) = existing {
        if &prev == m {
            return Ok(());
        }
        return Err(anyhow!(
            "acceptance marker mismatch for the same consumed parent — refusing to \
             overwrite an immutable acceptance record"
        ));
    }
    conn.execute(
        "INSERT INTO accepted_transition_marker (
            relationship_key, parent_tip, child_tip, receipt_parent_root_a, receipt_child_root_a,
            applied_parent_root_b, applied_child_root_b,
            precommit_digest, prepared_receipt_commitment, prepared_receipt_artifact_hash,
            sender_device, recipient_device, created_at
         ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)",
        params![
            m.relationship_key.as_slice(),
            m.parent_tip.as_slice(),
            m.child_tip.as_slice(),
            m.receipt_parent_root_a.as_slice(),
            m.receipt_child_root_a.as_slice(),
            m.applied_parent_root_b.as_slice(),
            m.applied_child_root_b.as_slice(),
            m.precommit_digest.as_slice(),
            m.prepared_receipt_commitment.as_slice(),
            m.prepared_receipt_artifact_hash.as_slice(),
            m.sender_device.as_slice(),
            m.recipient_device.as_slice(),
            tick() as i64,
        ],
    )?;
    Ok(())
}

fn get_accepted_transition_locked(
    conn: &rusqlite::Connection,
    relationship_key: &[u8; 32],
    parent_tip: &[u8; 32],
) -> Result<Option<AcceptedTransition>> {
    let to32 = |v: Vec<u8>| -> [u8; 32] {
        let mut a = [0u8; 32];
        let n = v.len().min(32);
        a[..n].copy_from_slice(&v[..n]);
        a
    };
    Ok(conn
        .query_row(
            "SELECT child_tip, receipt_parent_root_a, receipt_child_root_a, \
             applied_parent_root_b, applied_child_root_b, precommit_digest, \
             prepared_receipt_commitment, prepared_receipt_artifact_hash, \
             sender_device, recipient_device \
             FROM accepted_transition_marker WHERE relationship_key = ?1 AND parent_tip = ?2",
            params![relationship_key.as_slice(), parent_tip.as_slice()],
            |r| {
                Ok(AcceptedTransition {
                    relationship_key: *relationship_key,
                    parent_tip: *parent_tip,
                    child_tip: to32(r.get(0)?),
                    receipt_parent_root_a: to32(r.get(1)?),
                    receipt_child_root_a: to32(r.get(2)?),
                    applied_parent_root_b: to32(r.get(3)?),
                    applied_child_root_b: to32(r.get(4)?),
                    precommit_digest: to32(r.get(5)?),
                    prepared_receipt_commitment: to32(r.get(6)?),
                    prepared_receipt_artifact_hash: to32(r.get(7)?),
                    sender_device: to32(r.get(8)?),
                    recipient_device: to32(r.get(9)?),
                })
            },
        )
        .optional()?)
}

pub fn get_accepted_transition(
    relationship_key: &[u8; 32],
    parent_tip: &[u8; 32],
) -> Result<Option<AcceptedTransition>> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    get_accepted_transition_locked(&conn, relationship_key, parent_tip)
}

/// Phase 2: promote a PREPARED journal to APPLIED, but ONLY on a FIELD-FOR-FIELD
/// match of the immutable `accepted_transition_marker` marker against the journal.
///
/// `child_tip` alone does NOT bind the state roots or the prepared receipt
/// commitment (`child_tip = H(domain ‖ h_n ‖ op ‖ e ‖ C_pre)` — no roots, and
/// `C_pre` is not the receipt commitment). Tip equality could therefore promote a
/// prepared receipt for a transition with different roots/receipt-context that
/// happens to reach the same child tip. So promotion requires the recipient's own
/// durable acceptance marker to match the journal exactly across all THREE layers:
/// (1) the accepted state transition — child_tip, receipt_parent_root_a, receipt_child_root_a,
/// precommit_digest (C_pre); (2) the semantic receipt commitment; and (3) the exact
/// persisted countersigned artifact — `prepared_receipt_artifact_hash`, recomputed
/// verbatim from the journal's stored `receipt_bytes` — plus sender/recipient.
/// Idempotent: already Applied/Complete returns `Applied`.
pub fn promote_prepared_to_applied(
    relationship_key: &[u8; 32],
    parent_tip: &[u8; 32],
) -> Result<PromoteOutcome> {
    let rec = match get_acceptance_journal(relationship_key, parent_tip)? {
        Some(r) => r,
        None => return Err(anyhow!("no acceptance journal to promote")),
    };
    match rec.status.as_str() {
        STATUS_APPLIED | STATUS_COMPLETE => return Ok(PromoteOutcome::Applied),
        STATUS_REJECTED => return Ok(PromoteOutcome::Rejected),
        _ => {}
    }

    let marker = match get_accepted_transition(relationship_key, parent_tip)? {
        Some(m) => m,
        None => return Ok(PromoteOutcome::NotYetApplied),
    };

    // Recompute the exact-artifact hash from the journal's PRECISE stored bytes
    // (verbatim — never deserialized/reserialized). This binds the exact signed EK
    // artifact (sig_b/ek_pk_b/ek_cert_b/kyber_ct_b/envelope), which the semantic
    // commitment does not cover. Require both self-consistency (stored hash matches
    // stored bytes) and marker agreement.
    let recomputed_artifact = acceptance_artifact_hash(&rec.receipt_bytes);

    // Field-for-field match across all three layers: accepted state transition,
    // semantic receipt commitment, and exact persisted countersigned artifact.
    // recipient_device is B (self); the journal tracks the sender as counterparty.
    let matches = marker.child_tip == rec.child_tip
        && marker.receipt_parent_root_a == rec.receipt_parent_root_a
        && marker.receipt_child_root_a == rec.receipt_child_root_a
        && marker.precommit_digest == rec.precommit_digest
        && marker.prepared_receipt_commitment == rec.commitment
        && recomputed_artifact == rec.prepared_receipt_artifact_hash
        && marker.prepared_receipt_artifact_hash == recomputed_artifact
        && marker.sender_device == rec.counterparty_device_id;
    if !matches {
        return Err(anyhow!(
            "accepted_transition_marker marker does not match the prepared journal field-for-field — \
             refusing to promote (fail closed)"
        ));
    }

    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    conn.execute(
        "UPDATE acceptance_fold_journal SET status = ?1
         WHERE relationship_key = ?2 AND parent_tip = ?3 AND status = ?4",
        params![
            STATUS_APPLIED,
            relationship_key.as_slice(),
            parent_tip.as_slice(),
            STATUS_PREPARED
        ],
    )?;
    Ok(PromoteOutcome::Applied)
}

/// Mark a prepared journal Rejected/Aborted — ONLY when the caller has proven the
/// transition was not applied (explicit `apply_operation` failure). Idempotent.
pub fn mark_acceptance_rejected(
    relationship_key: &[u8; 32],
    parent_tip: &[u8; 32],
) -> Result<()> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    conn.execute(
        "UPDATE acceptance_fold_journal SET status = ?1
         WHERE relationship_key = ?2 AND parent_tip = ?3 AND status = ?4",
        params![
            STATUS_REJECTED,
            relationship_key.as_slice(),
            parent_tip.as_slice(),
            STATUS_PREPARED
        ],
    )?;
    Ok(())
}

fn mark_acceptance_journal_complete(
    relationship_key: &[u8; 32],
    parent_tip: &[u8; 32],
) -> Result<()> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    // Wipe the encrypted EK sk once the head is advanced — no longer needed.
    conn.execute(
        "UPDATE acceptance_fold_journal
         SET status = 'complete', new_local_b_sk_enc = NULL
         WHERE relationship_key = ?1 AND parent_tip = ?2",
        params![relationship_key.as_slice(), parent_tip.as_slice()],
    )?;
    Ok(())
}

/// Idempotent insert of the durable outbound-reply record (exact bytes to repost).
pub fn insert_outbound_reply(
    commitment: &[u8; 32],
    relationship_key: &[u8; 32],
    counterparty_device_id: &[u8; 32],
    child_tip: &[u8; 32],
    receipt_bytes: &[u8],
) -> Result<()> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    conn.execute(
        "INSERT OR IGNORE INTO recipient_outbound_reply
            (commitment, relationship_key, counterparty_device_id, child_tip, receipt_bytes, submitted, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, 0, ?6)",
        params![
            commitment.as_slice(),
            relationship_key.as_slice(),
            counterparty_device_id.as_slice(),
            child_tip.as_slice(),
            receipt_bytes,
            tick() as i64,
        ],
    )?;
    Ok(())
}

pub fn outbound_reply_exists(commitment: &[u8; 32]) -> Result<bool> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    Ok(conn
        .query_row(
            "SELECT 1 FROM recipient_outbound_reply WHERE commitment = ?1",
            params![commitment.as_slice()],
            |_| Ok(()),
        )
        .optional()?
        .is_some())
}

pub fn get_outbound_reply_bytes(commitment: &[u8; 32]) -> Result<Option<Vec<u8>>> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    Ok(conn
        .query_row(
            "SELECT receipt_bytes FROM recipient_outbound_reply WHERE commitment = ?1",
            params![commitment.as_slice()],
            |r| r.get::<_, Vec<u8>>(0),
        )
        .optional()?)
}

/// Outcome of the completion phase.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AcceptancePhaseOutcome {
    /// Both cert heads at target, outbox present, journal complete.
    Converged { receipt_bytes: Vec<u8> },
    /// The journal is not yet Applied — completion refused (no head advance, no
    /// outbox). The transition must be durably applied first.
    NotYetApplied,
    /// A CAS phase found a third head value — corruption/concurrent mutation.
    /// Fails closed; the journal is left as-is for inspection.
    Conflict { reason: String },
}

/// Phase 3: complete an APPLIED journal — CAS-advance the counterparty (A) head and
/// the local (B) head, install the outbox, mark complete + wipe the secret. Runs
/// ONLY on an `applied` (or already `complete`) journal; a `prepared` journal
/// returns `NotYetApplied` and mutates nothing. Idempotent (startup + on-access
/// recovery). A third head value fails closed without further writes.
pub fn complete_applied_acceptance(
    rec: &RecipientAcceptanceJournal,
    chain_head_wrap_key: &[u8; 32],
) -> Result<AcceptancePhaseOutcome> {
    // Re-read status: only Applied/Complete may complete.
    let fresh = get_acceptance_journal(&rec.relationship_key, &rec.parent_tip)?;
    match fresh.as_ref().map(|j| j.status.as_str()) {
        Some(STATUS_APPLIED) | Some(STATUS_COMPLETE) => {}
        _ => return Ok(AcceptancePhaseOutcome::NotYetApplied),
    }

    // Phase 3a: CAS-advance the counterparty (A) head.
    match cas_advance_counterparty_cert_chain_head(
        &rec.relationship_key,
        rec.expected_counterparty_a_head.as_deref(),
        &rec.new_counterparty_a_head,
    )? {
        CasHeadOutcome::Advanced { .. }
        | CasHeadOutcome::GenesisInit
        | CasHeadOutcome::AlreadyAtTarget => {}
        CasHeadOutcome::Conflict { current } => {
            return Ok(AcceptancePhaseOutcome::Conflict {
                reason: format!("counterparty A head CAS conflict (len={:?})", current.map(|c| c.len())),
            });
        }
    }

    // Phase 3b: CAS-advance the local (B) head using the stored encrypted sk.
    let ek_sk_b = match rec.new_local_b_sk_enc.as_ref() {
        Some(enc) => decrypt_chain_sk(enc, chain_head_wrap_key)?,
        None => {
            // Secret already wiped ⇒ the B head advance completed on a prior run.
            match super::cert_chain::load_cert_chain_head_pubkey(
                &rec.relationship_key,
                CertChainSide::Local,
            )? {
                Some(cur) if cur == rec.new_local_b_head => Vec::new(),
                other => {
                    return Ok(AcceptancePhaseOutcome::Conflict {
                        reason: format!(
                            "ek_sk_b wiped but local B head not at target (len={:?})",
                            other.map(|c| c.len())
                        ),
                    })
                }
            }
        }
    };
    if !ek_sk_b.is_empty() {
        match cas_advance_local_cert_chain_head_with_sk(
            &rec.relationship_key,
            rec.expected_local_b_head.as_deref(),
            &rec.new_local_b_head,
            &ek_sk_b,
            chain_head_wrap_key,
        )? {
            CasHeadOutcome::Advanced { .. }
            | CasHeadOutcome::GenesisInit
            | CasHeadOutcome::AlreadyAtTarget => {}
            CasHeadOutcome::Conflict { current } => {
                return Ok(AcceptancePhaseOutcome::Conflict {
                    reason: format!("local B head CAS conflict (len={:?})", current.map(|c| c.len())),
                });
            }
        }
    }

    // Phase 3c: idempotent outbox insert. Phase 3d: mark complete + wipe secret.
    insert_outbound_reply(
        &rec.commitment,
        &rec.relationship_key,
        &rec.counterparty_device_id,
        &rec.child_tip,
        &rec.receipt_bytes,
    )?;
    mark_acceptance_journal_complete(&rec.relationship_key, &rec.parent_tip)?;

    Ok(AcceptancePhaseOutcome::Converged {
        receipt_bytes: rec.receipt_bytes.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;
    use crate::storage::client_db::cert_chain::{
        encrypt_chain_sk, load_cert_chain_head_pubkey, CertChainSide,
    };

    const WRAP: [u8; 32] = [0x42u8; 32];

    fn init_test_db() {
        unsafe { std::env::set_var("DSM_SDK_TEST_MODE", "1") };
        crate::storage::client_db::reset_database_for_tests();
        crate::storage::client_db::init_database().expect("init db");
    }

    fn prepared_row(
        rel: [u8; 32],
        parent: [u8; 32],
        child: [u8; 32],
        commitment: [u8; 32],
        ek_pk_b: Vec<u8>,
        ek_sk_b: &[u8],
        ek_pk_a: Vec<u8>,
    ) -> RecipientAcceptanceJournal {
        RecipientAcceptanceJournal {
            relationship_key: rel,
            parent_tip: parent,
            child_tip: child,
            counterparty_device_id: [0x0Au8; 32],
            commitment,
            receipt_parent_root_a: [0x0Bu8; 32],
            receipt_child_root_a: [0x0Cu8; 32],
            precommit_digest: [0x0Du8; 32],
            prepared_receipt_artifact_hash: acceptance_artifact_hash(b"EXACT-RECEIPT-BYTES"),
            expected_local_b_head: None,
            new_local_b_head: ek_pk_b,
            new_local_b_sk_enc: Some(encrypt_chain_sk(ek_sk_b, &WRAP).unwrap()),
            expected_counterparty_a_head: None,
            new_counterparty_a_head: ek_pk_a,
            receipt_bytes: b"EXACT-RECEIPT-BYTES".to_vec(),
            status: STATUS_PREPARED.to_string(),
            created_at: 0,
        }
    }

    /// Record the acceptance marker that matches `rec` field-for-field (simulates
    /// the accept path durably attesting the exact applied transition).
    fn set_applied(rec: &RecipientAcceptanceJournal) {
        record_accepted_transition(&AcceptedTransition {
            relationship_key: rec.relationship_key,
            parent_tip: rec.parent_tip,
            child_tip: rec.child_tip,
            receipt_parent_root_a: rec.receipt_parent_root_a,
            receipt_child_root_a: rec.receipt_child_root_a,
            applied_parent_root_b: [0x1Bu8; 32],
            applied_child_root_b: [0x1Cu8; 32],
            precommit_digest: rec.precommit_digest,
            prepared_receipt_commitment: rec.commitment,
            prepared_receipt_artifact_hash: rec.prepared_receipt_artifact_hash,
            sender_device: rec.counterparty_device_id,
            recipient_device: [0x0Eu8; 32],
        })
        .unwrap();
    }

    #[test]
    #[serial]
    fn prepared_journal_does_not_complete_until_applied() {
        init_test_db();
        let rel = [0x01u8; 32];
        let parent = [0x02u8; 32];
        let child = [0x03u8; 32];
        let rec = prepared_row(rel, parent, child, [0x04u8; 32], vec![0xBBu8; 40], &[0xCCu8; 64], vec![0xAAu8; 40]);
        insert_prepared_acceptance_journal(&rec).unwrap();

        // Not applied: completion refuses, no head advance, no outbox.
        assert_eq!(
            complete_applied_acceptance(&rec, &WRAP).unwrap(),
            AcceptancePhaseOutcome::NotYetApplied
        );
        assert!(load_cert_chain_head_pubkey(&rel, CertChainSide::Local).unwrap().is_none());
        assert!(!outbound_reply_exists(&[0x04u8; 32]).unwrap());
        // promote is NotYetApplied until the canonical tip reaches child.
        assert_eq!(
            promote_prepared_to_applied(&rel, &parent).unwrap(),
            PromoteOutcome::NotYetApplied
        );
    }

    #[test]
    #[serial]
    fn applied_then_complete_converges_both_heads_and_outbox() {
        init_test_db();
        let rel = [0x11u8; 32];
        let parent = [0x12u8; 32];
        let child = [0x13u8; 32];
        let commitment = [0x14u8; 32];
        let ek_pk_b = vec![0xB1u8; 40];
        let ek_pk_a = vec![0xA1u8; 40];
        let rec = prepared_row(rel, parent, child, commitment, ek_pk_b.clone(), &[0xC1u8; 64], ek_pk_a.clone());
        insert_prepared_acceptance_journal(&rec).unwrap();

        // Simulate the transition applied (canonical tip advanced to child).
        set_applied(&rec);
        assert_eq!(promote_prepared_to_applied(&rel, &parent).unwrap(), PromoteOutcome::Applied);

        // Now completion converges both heads + outbox; idempotent on re-run.
        let out = complete_applied_acceptance(&rec, &WRAP).unwrap();
        assert!(matches!(out, AcceptancePhaseOutcome::Converged { .. }));
        assert_eq!(load_cert_chain_head_pubkey(&rel, CertChainSide::Local).unwrap(), Some(ek_pk_b.clone()));
        assert_eq!(load_cert_chain_head_pubkey(&rel, CertChainSide::Counterparty).unwrap(), Some(ek_pk_a));
        assert!(outbound_reply_exists(&commitment).unwrap());
        assert_eq!(get_acceptance_journal(&rel, &parent).unwrap().unwrap().status, STATUS_COMPLETE);

        // Re-run (crash-after-Applied recovery): idempotent, single heads.
        let reloaded = get_acceptance_journal(&rel, &parent).unwrap().unwrap();
        assert!(matches!(complete_applied_acceptance(&reloaded, &WRAP).unwrap(), AcceptancePhaseOutcome::Converged { .. }));
        assert_eq!(load_cert_chain_head_pubkey(&rel, CertChainSide::Local).unwrap(), Some(ek_pk_b));
    }

    #[test]
    #[serial]
    fn crash_after_a_head_only_recovery_completes_b_and_outbox() {
        init_test_db();
        let rel = [0x21u8; 32];
        let parent = [0x22u8; 32];
        let child = [0x23u8; 32];
        let commitment = [0x24u8; 32];
        let ek_pk_b = vec![0xB2u8; 40];
        let ek_pk_a = vec![0xA2u8; 40];
        let rec = prepared_row(rel, parent, child, commitment, ek_pk_b.clone(), &[0xC2u8; 64], ek_pk_a.clone());
        insert_prepared_acceptance_journal(&rec).unwrap();
        set_applied(&rec);
        promote_prepared_to_applied(&rel, &parent).unwrap();

        // Simulate crash after A head advanced only.
        super::super::cert_chain::init_cert_chain_head(&rel, CertChainSide::Counterparty, &ek_pk_a).unwrap();
        assert!(load_cert_chain_head_pubkey(&rel, CertChainSide::Local).unwrap().is_none());

        let out = complete_applied_acceptance(&rec, &WRAP).unwrap();
        assert!(matches!(out, AcceptancePhaseOutcome::Converged { .. }));
        assert_eq!(load_cert_chain_head_pubkey(&rel, CertChainSide::Local).unwrap(), Some(ek_pk_b));
        assert!(outbound_reply_exists(&commitment).unwrap());
        assert_eq!(get_acceptance_journal(&rel, &parent).unwrap().unwrap().status, STATUS_COMPLETE);
    }

    #[test]
    #[serial]
    fn apply_failure_marks_rejected_no_heads_no_outbox() {
        init_test_db();
        let rel = [0x31u8; 32];
        let parent = [0x32u8; 32];
        let commitment = [0x34u8; 32];
        let rec = prepared_row(rel, parent, [0x33u8; 32], commitment, vec![0xB3u8; 40], &[0xC3u8; 64], vec![0xA3u8; 40]);
        insert_prepared_acceptance_journal(&rec).unwrap();

        // apply failed → mark rejected (transition provably not applied).
        mark_acceptance_rejected(&rel, &parent).unwrap();
        assert_eq!(get_acceptance_journal(&rel, &parent).unwrap().unwrap().status, STATUS_REJECTED);
        // Completion refuses a rejected journal; no heads, no outbox.
        assert_eq!(complete_applied_acceptance(&rec, &WRAP).unwrap(), AcceptancePhaseOutcome::NotYetApplied);
        assert!(load_cert_chain_head_pubkey(&rel, CertChainSide::Local).unwrap().is_none());
        assert!(!outbound_reply_exists(&commitment).unwrap());
    }

    #[test]
    #[serial]
    fn promote_fails_closed_when_marker_root_differs_for_same_child() {
        init_test_db();
        let rel = [0x51u8; 32];
        let parent = [0x52u8; 32];
        let child = [0x53u8; 32];
        let commitment = [0x54u8; 32];
        let rec = prepared_row(rel, parent, child, commitment, vec![0xB5u8; 40], &[0xC5u8; 64], vec![0xA5u8; 40]);
        insert_prepared_acceptance_journal(&rec).unwrap();
        // Marker with the SAME child_tip but a DIFFERENT receipt_child_root_a — a distinct
        // transition that reaches the same apparent child state. child_tip does NOT
        // bind the roots, so tip-equality would wrongly promote; the field-for-field
        // marker match MUST fail closed.
        record_accepted_transition(&AcceptedTransition {
            relationship_key: rel,
            parent_tip: parent,
            child_tip: child,
            receipt_parent_root_a: rec.receipt_parent_root_a,
            receipt_child_root_a: [0xEEu8; 32], // WRONG root
            applied_parent_root_b: [0x1Bu8; 32],
            applied_child_root_b: [0x1Cu8; 32],
            precommit_digest: rec.precommit_digest,
            prepared_receipt_commitment: commitment,
            prepared_receipt_artifact_hash: rec.prepared_receipt_artifact_hash,
            sender_device: rec.counterparty_device_id,
            recipient_device: [0x0Eu8; 32],
        })
        .unwrap();
        let err = promote_prepared_to_applied(&rel, &parent).unwrap_err();
        assert!(err.to_string().contains("field-for-field"));
        assert_eq!(
            get_acceptance_journal(&rel, &parent).unwrap().unwrap().status,
            STATUS_PREPARED
        );
    }

    #[test]
    #[serial]
    fn promote_fails_closed_on_artifact_hash_mismatch() {
        init_test_db();
        let rel = [0x59u8; 32];
        let parent = [0x5Au8; 32];
        let child = [0x5Bu8; 32];
        let commitment = [0x5Cu8; 32];
        let rec = prepared_row(rel, parent, child, commitment, vec![0xB9u8; 40], &[0xC9u8; 64], vec![0xA9u8; 40]);
        insert_prepared_acceptance_journal(&rec).unwrap();
        // Marker matches ALL semantic fields but carries a DIFFERENT artifact hash
        // (a different signed EK artifact for the same semantic transition) — must
        // fail closed: the semantic commitment alone does not bind sig_b/ek_pk_b/etc.
        record_accepted_transition(&AcceptedTransition {
            relationship_key: rel,
            parent_tip: parent,
            child_tip: child,
            receipt_parent_root_a: rec.receipt_parent_root_a,
            receipt_child_root_a: rec.receipt_child_root_a,
            applied_parent_root_b: [0x1Bu8; 32],
            applied_child_root_b: [0x1Cu8; 32],
            precommit_digest: rec.precommit_digest,
            prepared_receipt_commitment: commitment,
            prepared_receipt_artifact_hash: [0x77u8; 32], // WRONG artifact hash
            sender_device: rec.counterparty_device_id,
            recipient_device: [0x0Eu8; 32],
        })
        .unwrap();
        let err = promote_prepared_to_applied(&rel, &parent).unwrap_err();
        assert!(err.to_string().contains("field-for-field"));
    }

    #[test]
    #[serial]
    fn promote_notyetapplied_when_no_marker() {
        init_test_db();
        let rel = [0x55u8; 32];
        let parent = [0x56u8; 32];
        let rec = prepared_row(rel, parent, [0x57u8; 32], [0x58u8; 32], vec![0xB6u8; 40], &[0xC6u8; 64], vec![0xA6u8; 40]);
        insert_prepared_acceptance_journal(&rec).unwrap();
        // No accepted-transition marker yet → not applied.
        assert_eq!(promote_prepared_to_applied(&rel, &parent).unwrap(), PromoteOutcome::NotYetApplied);
    }

    #[test]
    #[serial]
    fn different_receipt_for_same_consumed_parent_fails_closed() {
        init_test_db();
        let rel = [0x41u8; 32];
        let parent = [0x42u8; 32];
        let rec1 = prepared_row(rel, parent, [0x43u8; 32], [0x44u8; 32], vec![0xB4u8; 40], &[0xC4u8; 64], vec![0xA4u8; 40]);
        insert_prepared_acceptance_journal(&rec1).unwrap();
        let rec2 = prepared_row(rel, parent, [0x99u8; 32], [0x98u8; 32], vec![0xB4u8; 40], &[0xC4u8; 64], vec![0xA4u8; 40]);
        let err = insert_prepared_acceptance_journal(&rec2).unwrap_err();
        assert!(err.to_string().contains("DIFFERENT receipt"));
        insert_prepared_acceptance_journal(&rec1).unwrap(); // idempotent identical re-insert
    }
}
