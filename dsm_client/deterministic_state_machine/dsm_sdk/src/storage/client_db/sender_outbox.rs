// SPDX-License-Identifier: MIT OR Apache-2.0
//! Durable sender outbox (§16.6 defect-zero): the record that makes an online
//! send survivable.
//!
//! THE ORDERING RULE THIS TABLE EXISTS TO ENFORCE. A transfer becomes
//! externally deliverable the instant a storage node accepts it. If the sender
//! is still writing local state at that moment, a local failure can strand a
//! creditable message against a rolled-back debit — value created from nothing.
//! This row is therefore committed, together with the canonical advance, the
//! proposal, the gate, and the pending EK head, in ONE transaction BEFORE any
//! network call is made. It carries the exact envelope bytes so a retry
//! resubmits the identical artifact instead of rebuilding one from state that
//! may have moved.
//!
//! LIFECYCLE (forward-only once the row exists):
//!
//! ```text
//! (no row)  → abort / rollback permitted
//!   ↓ committed
//! pending_submit → submitting → submitted | submission_uncertain
//!                                   ↓
//!                               gc_pending → complete
//! ```
//!
//! `submitting` is persisted BEFORE the network call is entered, so a crash
//! mid-call can never leave a row that merely *looks* pre-submit. Existence of
//! the row — not its status — is what forbids rollback: a status check races
//! the very crash it is meant to survive.
//!
//! The row also outlives finalization (as `gc_pending`) so the remaining
//! lifecycle work stays reachable. Deleting the only durable record at
//! finalization is precisely what stranded the second transfer on the rig.

use super::get_connection;
use crate::util::deterministic_time::tick;
use anyhow::{anyhow, Result};
use rusqlite::{params, Connection, OptionalExtension};

/// Committed locally but HELD: the sender debit's economic admission has not
/// reached `ECON_ADMITTED`. NEVER returned by [`unsettled_sender_outbox`] and
/// never deliverable by any path — the resubmit sweep must not be able to
/// race a transfer onto the network whose economic ancestry is unregistered.
/// Promoted to `pending_submit` in the SAME transaction that records the
/// admitted coordinate, clears the pending admission and persists the
/// unfenced head, so a crash cannot produce "deliverable but not admitted".
pub const OUTBOX_ECONOMIC_ADMISSION_PENDING: &str = "economic_admission_pending";
/// Committed locally, nothing sent yet.
pub const OUTBOX_PENDING_SUBMIT: &str = "pending_submit";
/// Durably marked immediately BEFORE entering the network call.
pub const OUTBOX_SUBMITTING: &str = "submitting";
/// A storage quorum accepted the envelope.
pub const OUTBOX_SUBMITTED: &str = "submitted";
/// Submission may or may not have landed — reconcile forward, never roll back.
pub const OUTBOX_SUBMISSION_UNCERTAIN: &str = "submission_uncertain";
/// Finalized on the acceptance proof; the `RelationshipFinalizedV1`
/// certificate is frozen but has NOT reached storage quorum. The sender's gate
/// stays armed; the post-quorum sweep is the ONE deleter that moves this row
/// on (to `gc_pending`) and clears the gate, in one transaction.
pub const OUTBOX_FINALIZATION_CHECKPOINT_PENDING: &str = "finalization_checkpoint_pending";
/// Finalized on the acceptance proof; spool copies still need collecting.
pub const OUTBOX_GC_PENDING: &str = "gc_pending";
/// Transport GC done. Terminal.
pub const OUTBOX_COMPLETE: &str = "complete";

/// Which artifact of a proposal a row in `sender_outbox_artifacts` holds.
///
/// The role is not decoration: it is part of the content address (ADR 0003), so
/// an A-side object can never satisfy a reference obtained for a B-side one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArtifactRole {
    /// A-side receipt evidence: the full `ReceiptCommit` the transfer references.
    /// Frozen at send; the exact bytes the sender submits and replays.
    EvidenceA,
    /// B-side countersign delta returned by the recipient (ADR 0003 return
    /// leg). Persisted by the sender inside the finalization transaction: the
    /// exact envelope it verified and finalized on — its record of the
    /// countersignature, since no full receipt ever crosses the wire.
    CountersignB,
    /// The `RelationshipFinalizedV1` certificate the sender issues on
    /// finalization (finality barrier), frozen in the finalize transaction and
    /// replayed by the checkpoint sweep to the recipient's frozen route until
    /// it reaches quorum. Never part of the initial send.
    RelationshipFinalized,
}

impl ArtifactRole {
    pub fn as_str(self) -> &'static str {
        match self {
            ArtifactRole::EvidenceA => "evidence_a",
            ArtifactRole::CountersignB => "countersign_b",
            ArtifactRole::RelationshipFinalized => "relationship_finalized",
        }
    }

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "evidence_a" => Ok(ArtifactRole::EvidenceA),
            "countersign_b" => Ok(ArtifactRole::CountersignB),
            "relationship_finalized" => Ok(ArtifactRole::RelationshipFinalized),
            other => Err(anyhow!("unknown sender_outbox_artifacts.role: {other}")),
        }
    }

    /// Whether this artifact belongs to the INITIAL logical send — what
    /// `deliver_frozen_logical_send` ships and the resubmit sweep replays under
    /// the transfer's route. Only the A-side evidence does; the countersign
    /// delta is received, and the certificate has its own frozen route and its
    /// own sweep.
    pub fn is_initial_send_artifact(self) -> bool {
        matches!(self, ArtifactRole::EvidenceA)
    }
}

/// Content address of an evidence payload, separated by role.
///
/// Hashes the FULL wire bytes, never `ReceiptCommit::compute_commitment()`: the
/// commitment covers fields 1-11 and hard-zeroes 12-20, so a commitment-addressed
/// object could be served with substituted signatures. The digest must bind the
/// exact bytes whose signatures the receiver will verify.
pub fn evidence_content_digest(role: ArtifactRole, full_wire_bytes: &[u8]) -> [u8; 32] {
    match role {
        ArtifactRole::EvidenceA => dsm::crypto::blake3::domain_hash_bytes(
            dsm::common::domain_tags::TAG_DSM_RECEIPT_EVIDENCE_A,
            full_wire_bytes,
        ),
        ArtifactRole::CountersignB => dsm::crypto::blake3::domain_hash_bytes(
            dsm::common::domain_tags::TAG_DSM_RECEIPT_EVIDENCE_B,
            full_wire_bytes,
        ),
        ArtifactRole::RelationshipFinalized => dsm::crypto::blake3::domain_hash_bytes(
            dsm::common::domain_tags::TAG_DSM_RELATIONSHIP_FINALIZED_ARTIFACT,
            full_wire_bytes,
        ),
    }
}

/// One frozen artifact belonging to a proposal, beyond the transfer envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SenderOutboxArtifact {
    /// Owning proposal identity — matches the `sender_outbox` primary key.
    pub relationship_key: [u8; 32],
    pub canonical_parent: [u8; 32],
    pub proposal_nonce: [u8; 32],
    pub role: ArtifactRole,
    /// Deterministic; equals the node `message_id` for THIS artifact.
    pub submission_id: String,
    /// The exact envelope bytes. For `EvidenceA`: what the sender submits — a
    /// retry replays these verbatim rather than rebuilding from state that may
    /// have moved. For `CountersignB`: what the sender RECEIVED and finalized on.
    pub envelope_bytes: Vec<u8>,
    /// Role-domain-separated address of the payload this artifact carries.
    pub content_digest: [u8; 32],
    /// The frozen route this artifact is submitted under, when it is NOT the
    /// owning outbox's route: `Some` for `RelationshipFinalized` (the
    /// recipient's route, frozen at finalize), `None` for the initial-send
    /// artifacts (which ride the transfer's route).
    pub routing_address: Option<String>,
}

/// One online send's durable lifecycle record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SenderOutboxRecord {
    /// Durable proposal identity: `(relationship_key, canonical_parent, proposal_nonce)`.
    pub relationship_key: [u8; 32],
    pub canonical_parent: [u8; 32],
    pub proposal_nonce: [u8; 32],
    pub canonical_child: [u8; 32],
    /// Receipt commitment — the finalization identity, and the full-width value
    /// compared when a truncated submission id collides.
    pub commitment: [u8; 32],
    /// SYMMETRIC routing pair (gate / b0x addressing space).
    pub projection_parent: [u8; 32],
    pub projection_target: [u8; 32],
    pub routing_address: String,
    /// Deterministic, derived from `commitment`; equals the node `message_id`.
    pub submission_id: String,
    /// EXACT bytes submitted. Never rebuilt from current state on retry.
    pub envelope_bytes: Vec<u8>,
    /// Local cert-head CAS expectation. `None` is meaningful ONLY when
    /// `is_first_ek_step` is true; an unexplained `None` is never read as genesis.
    pub local_expected_prev: Option<Vec<u8>>,
    pub is_first_ek_step: bool,
    pub status: String,
    /// Storage message ids, GC metadata ONLY — never finalization authority.
    pub message_ids: Option<String>,
    pub created_at: u64,
}

const COLS: &str = "relationship_key, canonical_parent, canonical_child, commitment, \
     projection_parent, projection_target, routing_address, submission_id, envelope_bytes, \
     proposal_nonce, local_expected_prev, is_first_ek_step, status, message_ids, created_at";

fn to32(v: Vec<u8>, what: &str) -> Result<[u8; 32]> {
    <[u8; 32]>::try_from(v.as_slice()).map_err(|_| anyhow!("{what} is not 32 bytes"))
}

fn row_to_record(row: &rusqlite::Row) -> rusqlite::Result<SenderOutboxRecord> {
    let g = |i: usize| -> rusqlite::Result<Vec<u8>> { row.get::<_, Vec<u8>>(i) };
    let arr = |v: Vec<u8>| -> [u8; 32] {
        let mut a = [0u8; 32];
        let n = v.len().min(32);
        a[..n].copy_from_slice(&v[..n]);
        a
    };
    Ok(SenderOutboxRecord {
        relationship_key: arr(g(0)?),
        canonical_parent: arr(g(1)?),
        canonical_child: arr(g(2)?),
        commitment: arr(g(3)?),
        projection_parent: arr(g(4)?),
        projection_target: arr(g(5)?),
        routing_address: row.get::<_, String>(6)?,
        submission_id: row.get::<_, String>(7)?,
        envelope_bytes: g(8)?,
        proposal_nonce: arr(g(9)?),
        local_expected_prev: row.get::<_, Option<Vec<u8>>>(10)?,
        is_first_ek_step: row.get::<_, i64>(11)? != 0,
        status: row.get::<_, String>(12)?,
        message_ids: row.get::<_, Option<String>>(13)?,
        created_at: row.get::<_, i64>(14)? as u64,
    })
}

/// Deterministic submission id for a transfer, derived from its receipt
/// commitment so it is known BEFORE submission and identical across retries.
///
/// Truncated to 16 bytes because deployed storage nodes hard-require that
/// width (`api/transport/b0x.rs`, `.filter(|bytes| bytes.len() == 16)`). The
/// full 32-byte commitment is retained on this row and is what a 409 is
/// compared against — the truncation is an id, never the equality test.
pub fn derive_submission_id(commitment: &[u8; 32]) -> String {
    let mut h =
        dsm::crypto::blake3::dsm_domain_hasher(dsm::tagged_domain!(b"DSM/b0x-submission-id/v1"));
    h.update(commitment);
    crate::util::text_id::encode_base32_crockford(&h.finalize().as_bytes()[..16])
}

/// Deterministic submission id for a non-transfer artifact (ADR 0003).
///
/// Derived from the artifact's CONTENT DIGEST, which is already
/// role-domain-separated, so the id inherits that separation: an A-side and a
/// B-side artifact of the same transfer can never collide on
/// `UNIQUE(submission_id)`, and neither can collide with the transfer's own id
/// (derived from the commitment under a different tag).
///
/// Truncated to 16 bytes for the same reason as [`derive_submission_id`]:
/// deployed storage nodes hard-require that width. The full digest stays on the
/// row and is what an equality test uses -- the truncation is an id, never the
/// comparison.
pub fn derive_artifact_submission_id(content_digest: &[u8; 32]) -> String {
    let mut h = dsm::crypto::blake3::dsm_domain_hasher(dsm::tagged_domain!(
        b"DSM/b0x-artifact-submission-id/v1"
    ));
    h.update(content_digest);
    crate::util::text_id::encode_base32_crockford(&h.finalize().as_bytes()[..16])
}

/// Insert the lifecycle row INSIDE the caller's advance transaction.
///
/// Takes `&Connection` (a `&Transaction` derefs to one) and never opens its
/// own: the advance already holds the single global connection mutex, so an
/// independent `get_connection()` here would deadlock.
///
/// Idempotent for a byte-identical re-entry; fails closed if a DIFFERENT
/// envelope claims the same identity.
pub fn insert_sender_outbox_with_conn(conn: &Connection, r: &SenderOutboxRecord) -> Result<()> {
    let existing: Option<(Vec<u8>, Vec<u8>)> = conn
        .query_row(
            "SELECT commitment, envelope_bytes FROM sender_outbox
             WHERE relationship_key = ?1 AND canonical_parent = ?2 AND proposal_nonce = ?3",
            params![
                r.relationship_key.as_slice(),
                r.canonical_parent.as_slice(),
                r.proposal_nonce.as_slice()
            ],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    if let Some((commitment, envelope)) = existing {
        if commitment.as_slice() == r.commitment.as_slice() && envelope == r.envelope_bytes {
            return Ok(());
        }
        return Err(anyhow!(
            "a DIFFERENT outbox entry already holds this proposal identity — refusing to \
             overwrite a durable send record"
        ));
    }
    conn.execute(
        &format!(
            "INSERT INTO sender_outbox ({COLS}) \
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15)"
        ),
        params![
            r.relationship_key.as_slice(),
            r.canonical_parent.as_slice(),
            r.canonical_child.as_slice(),
            r.commitment.as_slice(),
            r.projection_parent.as_slice(),
            r.projection_target.as_slice(),
            r.routing_address,
            r.submission_id,
            r.envelope_bytes,
            r.proposal_nonce.as_slice(),
            r.local_expected_prev.as_deref(),
            if r.is_first_ek_step { 1i64 } else { 0i64 },
            r.status,
            r.message_ids.as_deref(),
            tick() as i64,
        ],
    )?;
    Ok(())
}

/// §16.6 defect zero — THE ATOMIC PRE-SUBMIT COMMIT.
///
/// Writes, in ONE transaction, every local record that must exist before the
/// transfer becomes externally deliverable:
///
///   * the sender proposal (canonical authority for this step),
///   * the pending online gate (with its expected-parent validation),
///   * the pending Local EK head (guarded by an expected-previous-head CAS),
///   * this outbox row, carrying the exact submission inputs.
///
/// Either all of it is durable or none of it is. Only after this commits may a
/// network call be made — and from that moment the transfer is FORWARD-ONLY.
///
/// That is now a STRUCTURAL property rather than a rule anyone has to remember:
/// the online-send rollback path has been deleted outright, so there is nothing
/// left that could unwind a committed transfer. A crash can still strand a status
/// mid-update while a quorum has already accepted the message; recovery sweeps the
/// durable row forward and never backward.
///
/// The cert-head CAS runs inside this transaction, so losing the race against
/// the acceptance finalizer aborts the whole commit — nothing is written and
/// nothing was ever sent.
/// Persist one frozen artifact for a proposal.
///
/// MUST be called inside the same transaction as the canonical advance and the
/// `sender_outbox` row. The FK to `sender_outbox` is enforced, so calling this
/// outside that transaction (or before the proposal row exists) fails rather
/// than producing an artifact nobody owns.
pub fn insert_sender_outbox_artifact_with_conn(
    tx: &Connection,
    artifact: &SenderOutboxArtifact,
) -> Result<()> {
    // A re-entry on the same submission id is idempotent ONLY when it carries
    // the identical artifact. The id is 16 bytes truncated from a 32-byte
    // digest, so a collision is a 128-bit possibility rather than an
    // impossibility -- and the storage node resolves `UNIQUE(message_id)` with
    // `ON CONFLICT DO NOTHING`, which ACCEPTS a colliding id silently. Without
    // this check, two different artifacts sharing an id would see the second
    // quietly discarded and its transfer stall with no error anywhere.
    //
    // Same id + same bytes -> no-op. Same id + different bytes -> fail closed.
    if let Some((existing_bytes, existing_digest)) = tx
        .query_row(
            "SELECT envelope_bytes, content_digest FROM sender_outbox_artifacts
             WHERE submission_id = ?1",
            params![artifact.submission_id],
            |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?)),
        )
        .optional()?
    {
        if existing_bytes == artifact.envelope_bytes
            && existing_digest == artifact.content_digest.as_slice()
        {
            return Ok(());
        }
        return Err(anyhow!(
            "sender_outbox_artifacts: submission_id {} already holds a DIFFERENT artifact \
             (stored {} bytes / digest {}, incoming {} bytes / digest {}); refusing to \
             silently replace or drop it",
            artifact.submission_id,
            existing_bytes.len(),
            crate::util::text_id::encode_base32_crockford(&existing_digest),
            artifact.envelope_bytes.len(),
            crate::util::text_id::encode_base32_crockford(&artifact.content_digest),
        ));
    }

    tx.execute(
        "INSERT INTO sender_outbox_artifacts(
            relationship_key, canonical_parent, proposal_nonce, role,
            submission_id, envelope_bytes, content_digest, routing_address, created_at
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            artifact.relationship_key.as_slice(),
            artifact.canonical_parent.as_slice(),
            artifact.proposal_nonce.as_slice(),
            artifact.role.as_str(),
            artifact.submission_id,
            artifact.envelope_bytes,
            artifact.content_digest.as_slice(),
            artifact.routing_address.as_deref(),
            tick() as i64,
        ],
    )?;
    Ok(())
}

/// Every extra artifact belonging to a proposal, for replay.
pub fn load_sender_outbox_artifacts(
    relationship_key: &[u8; 32],
    canonical_parent: &[u8; 32],
    proposal_nonce: &[u8; 32],
) -> Result<Vec<SenderOutboxArtifact>> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    let mut stmt = conn.prepare(
        "SELECT relationship_key, canonical_parent, proposal_nonce, role,
                submission_id, envelope_bytes, content_digest, routing_address
         FROM sender_outbox_artifacts
         WHERE relationship_key = ?1 AND canonical_parent = ?2 AND proposal_nonce = ?3
         ORDER BY role",
    )?;
    let rows = stmt
        .query_map(
            params![
                relationship_key.as_slice(),
                canonical_parent.as_slice(),
                proposal_nonce.as_slice()
            ],
            |row| {
                let to32 = |v: Vec<u8>| -> [u8; 32] {
                    let mut out = [0u8; 32];
                    out.copy_from_slice(&v);
                    out
                };
                Ok((
                    to32(row.get::<_, Vec<u8>>(0)?),
                    to32(row.get::<_, Vec<u8>>(1)?),
                    to32(row.get::<_, Vec<u8>>(2)?),
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, Vec<u8>>(5)?,
                    to32(row.get::<_, Vec<u8>>(6)?),
                    row.get::<_, Option<String>>(7)?,
                ))
            },
        )?
        .collect::<std::result::Result<Vec<_>, _>>()?;

    rows.into_iter()
        .map(|(rk, cp, pn, role, sid, bytes, digest, route)| {
            Ok(SenderOutboxArtifact {
                relationship_key: rk,
                canonical_parent: cp,
                proposal_nonce: pn,
                role: ArtifactRole::from_str(&role)?,
                submission_id: sid,
                envelope_bytes: bytes,
                content_digest: digest,
                routing_address: route,
            })
        })
        .collect()
}

#[allow(clippy::too_many_arguments)]
pub fn commit_send_prerequisites_atomically(
    proposal: &super::sender_proposal::SenderOnlineProposal,
    outbox: &SenderOutboxRecord,
    gate_message_id: &str,
    ek_pubkey: &[u8],
    ek_secret_key: &[u8],
    chain_head_wrap_key: &[u8; 32],
    ek_is_init: bool,
    artifacts: &[SenderOutboxArtifact],
) -> Result<()> {
    let binding = get_connection()?;
    let mut conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    let tx = conn.transaction()?;
    commit_send_prerequisites_with_conn(
        &tx,
        proposal,
        outbox,
        gate_message_id,
        ek_pubkey,
        ek_secret_key,
        chain_head_wrap_key,
        ek_is_init,
        artifacts,
    )?;
    tx.commit()?;
    Ok(())
}

/// The four durable writes of a send, as ONE unit, inside a caller's transaction.
///
/// This is the single implementation. The production send path calls it from
/// `write_extra` so the writes land in the SAME transaction as the canonical
/// advance; [`commit_send_prerequisites_atomically`] wraps it in a transaction of
/// its own for callers that are not already inside one.
///
/// Keeping one body matters: if production inlined these four calls and the tests
/// exercised a separate copy, the tests would be validating a path production no
/// longer takes.
#[allow(clippy::too_many_arguments)]
pub fn commit_send_prerequisites_with_conn(
    tx: &Connection,
    proposal: &super::sender_proposal::SenderOnlineProposal,
    outbox: &SenderOutboxRecord,
    gate_message_id: &str,
    ek_pubkey: &[u8],
    ek_secret_key: &[u8],
    chain_head_wrap_key: &[u8; 32],
    ek_is_init: bool,
    artifacts: &[SenderOutboxArtifact],
) -> Result<()> {
    // Finality barrier, defense in depth IN the transaction: this device may
    // not originate on a relationship while an acceptance it journaled still
    // awaits the peer's certificate. The authority refuses earlier; this makes
    // the write itself impossible.
    if super::recipient_receipt_fold::relationship_awaits_peer_finalization_with_conn(
        tx,
        &proposal.relationship_key,
    )? {
        return Err(anyhow!(
            "send prerequisites: an inbound acceptance on this relationship still awaits the \
             peer's finality certificate — originating is refused (finality barrier)"
        ));
    }

    super::sender_proposal::insert_sender_proposal_with_conn(tx, proposal)?;

    super::cert_chain::stash_pending_local_head_cas_with_conn(
        tx,
        &proposal.relationship_key,
        &proposal.commitment,
        ek_pubkey,
        ek_secret_key,
        chain_head_wrap_key,
        ek_is_init,
        outbox.local_expected_prev.as_deref(),
        outbox.is_first_ek_step,
    )?;

    super::online_outbox::record_pending_online_transition_with_conn(
        tx,
        &proposal.counterparty_device_id,
        gate_message_id,
        &proposal.projection_parent,
        &proposal.projection_target,
    )?;

    insert_sender_outbox_with_conn(tx, outbox)?;

    // ADR 0003: every OTHER artifact this proposal will emit, frozen in the
    // SAME transaction. The outbox row must exist first -- the FK is enforced.
    // After this returns, either every deliverable artifact is durably
    // reconstructible byte-for-byte, or none is.
    for artifact in artifacts {
        insert_sender_outbox_artifact_with_conn(tx, artifact)?;
    }
    Ok(())
}

/// §16.6 DEFECT 1 — ATOMIC ACCEPTANCE-PROOF FINALIZATION.
///
/// Everything one verified acceptance authorises the sender to commit — the
/// inputs of [`finalize_on_acceptance_atomically`], all read from the durable
/// proposal + the verified delta, never from current state.
pub struct AcceptanceFinalization<'a> {
    pub relationship_key: &'a [u8; 32],
    pub canonical_parent: &'a [u8; 32],
    pub proposal_nonce: &'a [u8; 32],
    pub commitment: &'a [u8; 32],
    pub counterparty_device_id: &'a [u8; 32],
    pub projection_parent: &'a [u8; 32],
    pub projection_target: &'a [u8; 32],
    /// The Counterparty EK head observed before finalization (CAS expectation).
    pub expected_counterparty_head: Option<&'a [u8]>,
    /// The recipient's `ek_pk_b` — the new Counterparty EK head.
    pub new_counterparty_head: &'a [u8],
    /// The recipient's canonical pair from the delta, authenticated by `sig_b`:
    /// its head before (`.0`) and after (`.1`) applying this step. CAS'd into
    /// `counterparty_canonical_heads` (`.0` → `.1`) in the same transaction.
    pub peer_pair: ([u8; 32], [u8; 32]),
    /// `initial_chain_tip_from_device_ids(self, peer)` — the pair's `.0` must
    /// equal it when no head row exists yet (the relationship's first step).
    pub genesis_seed: [u8; 32],
    /// The exact delta envelope this finalization was judged on.
    pub countersign_b: &'a SenderOutboxArtifact,
    /// The `RelationshipFinalizedV1` certificate, built and signed BEFORE this
    /// transaction with the pending A EK, frozen here with its own route. The
    /// checkpoint sweep replays these exact bytes until quorum.
    pub finalized: &'a SenderOutboxArtifact,
}

/// The verified countersigned acceptance artifact is the SOLE protocol
/// authority for finalizing an online send. This performs, as ONE literal
/// SQLite transaction:
///
///   1. advance the projection tip (chain_tip = local_bilateral_chain_tip)
///   2. promote the pending Local EK head (keyed by commitment)
///   3. CAS-advance the Counterparty EK head to the recipient's `ek_pk_b`,
///      and the peer's CANONICAL head `peer_pair.0 → peer_pair.1`
///   4. finalize the proposal
///   5. freeze the `RelationshipFinalizedV1` certificate (its own route)
///   6. move the outbox to `finalization_checkpoint_pending`
///
/// The GATE IS NOT RELEASED HERE (finality barrier). Local finalization proves
/// the recipient applied; it does not prove the recipient can be told so. The
/// gate is released by `release_gate_on_finalization_checkpoint_atomically`
/// once the certificate has reached storage quorum — the ONE deleter — so a
/// second same-direction send cannot leave before the peer can learn that the
/// first is final.
///
/// WHY ONE TRANSACTION. An earlier design left (1) and (2) to a separate ACK
/// sweep keyed on a gate that had just been deleted — so the remainder became
/// permanently unreachable and every SECOND transfer on a relationship failed.
/// Splitting this sequence is exactly what caused that regression, so it is
/// not split.
///
/// The outbox status write is a CAS from the unsettled statuses only: a
/// re-entrant finalize after the sweep already released the gate must not
/// drag `gc_pending` back. Idempotent: a redelivered acceptance finds the
/// proposal already finalized and the heads already at target.
pub fn finalize_on_acceptance_atomically(f: &AcceptanceFinalization<'_>) -> Result<()> {
    let AcceptanceFinalization {
        relationship_key,
        canonical_parent,
        proposal_nonce,
        commitment,
        counterparty_device_id,
        projection_parent,
        projection_target,
        expected_counterparty_head,
        new_counterparty_head,
        peer_pair,
        genesis_seed,
        countersign_b,
        finalized,
    } = *f;
    if countersign_b.role != ArtifactRole::CountersignB {
        return Err(anyhow!(
            "acceptance finalization: artifact role must be countersign_b, got {}",
            countersign_b.role.as_str()
        ));
    }
    if finalized.role != ArtifactRole::RelationshipFinalized {
        return Err(anyhow!(
            "acceptance finalization: certificate role must be relationship_finalized, got {}",
            finalized.role.as_str()
        ));
    }
    if finalized.routing_address.is_none() {
        return Err(anyhow!(
            "acceptance finalization: the certificate must carry its frozen route"
        ));
    }
    let binding = get_connection()?;
    let mut conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    let tx = conn.transaction()?;

    // (1) Projection tip: chain_tip and local_bilateral_chain_tip converge on
    // the target. This is the step whose absence stranded transfer #2 behind a
    // "divergent local bilateral chain tip" rejection.
    let request = super::bilateral_tip_sync::TipSyncRequest {
        counterparty_device_id: *counterparty_device_id,
        expected_parent_tip: *projection_parent,
        target_tip: *projection_target,
    };
    match super::bilateral_tip_sync::sync_tip_projections_in_tx(&tx, &request, None)? {
        super::bilateral_tip_sync::TipSyncOutcome::Advanced { .. }
        | super::bilateral_tip_sync::TipSyncOutcome::RepairedAtTarget { .. }
        | super::bilateral_tip_sync::TipSyncOutcome::AlreadyAtTarget { .. } => {}
        other => {
            return Err(anyhow!(
                "acceptance finalization: projection tip refused to converge ({other:?}) — \
                 aborting the whole finalization"
            ));
        }
    }

    // (2) Local EK head, keyed by the commitment the artifact names. The
    // certificate was signed with exactly this pending key moments ago, so a
    // missing row is an error — never a silent skip.
    if super::cert_chain::promote_pending_local_head_with_conn(&tx, relationship_key, commitment)?
        .is_none()
    {
        return Err(anyhow!(
            "acceptance finalization: no pending Local EK head for this commitment — the \
             certificate's signing key is unaccounted for; aborting"
        ));
    }

    // (3) Counterparty EK head. AlreadyAtTarget counts as success ONLY because
    // it means the persisted value already equals this proposal's expected
    // result; any third value is a Conflict and aborts.
    match super::cert_chain::cas_advance_counterparty_cert_chain_head_with_conn(
        &tx,
        relationship_key,
        expected_counterparty_head,
        new_counterparty_head,
    )? {
        super::cert_chain::CasHeadOutcome::Advanced { .. }
        | super::cert_chain::CasHeadOutcome::GenesisInit
        | super::cert_chain::CasHeadOutcome::AlreadyAtTarget => {}
        super::cert_chain::CasHeadOutcome::Conflict { current } => {
            return Err(anyhow!(
                "acceptance finalization: counterparty head conflict (current={:?}..) — \
                 aborting",
                current.as_ref().map(|c| &c[..4.min(c.len())])
            ));
        }
    }

    // (3b) The peer's CANONICAL head: the recipient signed (sig_b) that it
    // applied this step under peer_pair.0 and now sits at peer_pair.1. That is
    // the exact parent it will originate under next; pin it. AlreadyAtTarget
    // (same step re-finalized) is success; a third value aborts — the caller
    // parks the step and the gate is retained.
    match super::counterparty_canonical_heads::cas_advance_counterparty_canonical_head_with_conn(
        &tx,
        relationship_key,
        counterparty_device_id,
        &peer_pair.0,
        &peer_pair.1,
        commitment,
        &genesis_seed,
    )? {
        super::counterparty_canonical_heads::CasCanonicalHeadOutcome::Advanced
        | super::counterparty_canonical_heads::CasCanonicalHeadOutcome::GenesisInit
        | super::counterparty_canonical_heads::CasCanonicalHeadOutcome::AlreadyAtTarget => {}
        super::counterparty_canonical_heads::CasCanonicalHeadOutcome::Conflict { current } => {
            return Err(anyhow!(
                "acceptance finalization: peer canonical head conflict (delta parent {}.., \
                 pinned {}) — aborting",
                crate::util::text_id::encode_base32_crockford(&peer_pair.0[..4]),
                current
                    .map(|c| crate::util::text_id::encode_base32_crockford(&c[..4]) + "..")
                    .unwrap_or_else(|| "none".to_string()),
            ));
        }
    }

    // (4) Proposal terminal.
    super::sender_proposal::mark_sender_proposal_finalized_by_canonical_with_conn(
        &tx,
        relationship_key,
        canonical_parent,
    )?;

    // (5) The certificate, frozen with its own route: the sweep replays these
    // exact bytes under this deterministic id until quorum. And the recipient's
    // countersign delta — the exact envelope this finalization was judged on —
    // beside the frozen A-side evidence: the sender never receives a whole
    // countersigned receipt (ADR 0003 return leg), so this row plus evidence_a
    // IS its record of the countersignature.
    insert_sender_outbox_artifact_with_conn(&tx, finalized)?;
    insert_sender_outbox_artifact_with_conn(&tx, countersign_b)?;

    // (6) Outbox → checkpoint pending, from an UNSETTLED status only. The
    // gate stays; the sweep releases it.
    advance_sender_outbox_status_if_with_conn(
        &tx,
        relationship_key,
        canonical_parent,
        proposal_nonce,
        &[
            OUTBOX_PENDING_SUBMIT,
            OUTBOX_SUBMITTING,
            OUTBOX_SUBMITTED,
            OUTBOX_SUBMISSION_UNCERTAIN,
        ],
        OUTBOX_FINALIZATION_CHECKPOINT_PENDING,
    )?;

    // Retained for the sweep's exact-match release; the projection pair is
    // the gate's identity.
    let _ = (projection_parent, projection_target);

    tx.commit()?;
    Ok(())
}

/// The ONE deleter of the sender's pending online gate (finality barrier):
/// called by the checkpoint sweep AFTER the `RelationshipFinalizedV1`
/// certificate reached storage quorum. ONE transaction: the gate row must
/// match `(counterparty, projection_parent → projection_target)` exactly and
/// its delete must hit exactly one row (else invariant error, nothing
/// written), then the outbox moves `finalization_checkpoint_pending →
/// gc_pending`. Returns `Ok(true)` when the row advanced, `Ok(false)` when it
/// was already past the checkpoint (a concurrent sweep won).
pub fn release_gate_on_finalization_checkpoint_atomically(
    relationship_key: &[u8; 32],
    canonical_parent: &[u8; 32],
    proposal_nonce: &[u8; 32],
    counterparty_device_id: &[u8; 32],
    projection_parent: &[u8; 32],
    projection_target: &[u8; 32],
) -> Result<bool> {
    let binding = get_connection()?;
    let mut conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    let tx = conn.transaction()?;
    let advanced = advance_sender_outbox_status_if_with_conn(
        &tx,
        relationship_key,
        canonical_parent,
        proposal_nonce,
        &[OUTBOX_FINALIZATION_CHECKPOINT_PENDING],
        OUTBOX_GC_PENDING,
    )?;
    if !advanced {
        // Already released by another pass; nothing to delete, nothing to write.
        return Ok(false);
    }
    let deleted = super::online_outbox::clear_pending_online_outbox_if_matches_with_conn(
        &tx,
        counterparty_device_id,
        projection_parent,
        projection_target,
    )?;
    if !deleted {
        return Err(anyhow!(
            "checkpoint release: the sender gate for this step is not present exactly \
             (counterparty {}.., {}.. → {}..) — invariant violated; nothing written",
            crate::util::text_id::encode_base32_crockford(&counterparty_device_id[..4]),
            crate::util::text_id::encode_base32_crockford(&projection_parent[..4]),
            crate::util::text_id::encode_base32_crockford(&projection_target[..4]),
        ));
    }
    tx.commit()?;
    Ok(true)
}

/// Rows whose certificate is frozen but not yet at quorum — what the
/// checkpoint sweep replays.
pub fn finalization_checkpoint_pending_sender_outbox() -> Result<Vec<SenderOutboxRecord>> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|e| e.into_inner());
    let mut stmt = conn.prepare(&format!(
        "SELECT {COLS} FROM sender_outbox WHERE status = ?1 ORDER BY created_at"
    ))?;
    let rows = stmt
        .query_map(
            params![OUTBOX_FINALIZATION_CHECKPOINT_PENDING],
            row_to_record,
        )?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

/// Look up by the finalization identity (the receipt commitment).
pub fn get_sender_outbox_by_commitment(
    commitment: &[u8; 32],
) -> Result<Option<SenderOutboxRecord>> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|e| e.into_inner());
    Ok(conn
        .query_row(
            &format!("SELECT {COLS} FROM sender_outbox WHERE commitment = ?1"),
            params![commitment.as_slice()],
            row_to_record,
        )
        .optional()?)
}

/// Look up by the durable proposal identity.
pub fn get_sender_outbox(
    relationship_key: &[u8; 32],
    canonical_parent: &[u8; 32],
    proposal_nonce: &[u8; 32],
) -> Result<Option<SenderOutboxRecord>> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|e| e.into_inner());
    Ok(conn
        .query_row(
            &format!(
                "SELECT {COLS} FROM sender_outbox \
                 WHERE relationship_key = ?1 AND canonical_parent = ?2 AND proposal_nonce = ?3"
            ),
            params![
                relationship_key.as_slice(),
                canonical_parent.as_slice(),
                proposal_nonce.as_slice()
            ],
            row_to_record,
        )
        .optional()?)
}

/// Does ANY durable send record exist for this identity?
///
/// This is the rollback gate. Rollback is permitted only when this returns
/// `false`; once a row exists the transfer is forward-only regardless of its
/// status, because a crash can strand a row mid-status while the message is
/// already accepted.
/// Advance the lifecycle status by proposal identity.
pub fn set_sender_outbox_status(
    relationship_key: &[u8; 32],
    canonical_parent: &[u8; 32],
    proposal_nonce: &[u8; 32],
    status: &str,
) -> Result<bool> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|e| e.into_inner());
    let n = conn.execute(
        "UPDATE sender_outbox SET status = ?4
         WHERE relationship_key = ?1 AND canonical_parent = ?2 AND proposal_nonce = ?3",
        params![
            relationship_key.as_slice(),
            canonical_parent.as_slice(),
            proposal_nonce.as_slice(),
            status
        ],
    )?;
    Ok(n > 0)
}

/// Same, but inside a caller-owned transaction (used by the atomic finalizer).
pub fn set_sender_outbox_status_with_conn(
    conn: &Connection,
    relationship_key: &[u8; 32],
    canonical_parent: &[u8; 32],
    proposal_nonce: &[u8; 32],
    status: &str,
) -> Result<bool> {
    let n = conn.execute(
        "UPDATE sender_outbox SET status = ?4
         WHERE relationship_key = ?1 AND canonical_parent = ?2 AND proposal_nonce = ?3",
        params![
            relationship_key.as_slice(),
            canonical_parent.as_slice(),
            proposal_nonce.as_slice(),
            status
        ],
    )?;
    Ok(n > 0)
}

/// Proposal identities whose delivery is in flight IN THIS PROCESS.
///
/// Duplicate-traffic suppression only — NOT a correctness mechanism. There is a
/// scheduling window between the durable commit of a send and its insertion
/// here in which the periodic sweep can observe the row first and drive it
/// too. That is harmless by construction: both drivers submit the same
/// deterministic ids with identical frozen bytes (the node collapses them), and
/// both advance status through CAS. What this set buys is that the common case
/// does not pay for two full quorum submissions of a ~118 KB artifact.
static DELIVERY_IN_FLIGHT: std::sync::LazyLock<
    std::sync::Mutex<std::collections::HashSet<([u8; 32], [u8; 32], [u8; 32])>>,
> = std::sync::LazyLock::new(|| std::sync::Mutex::new(std::collections::HashSet::new()));

/// RAII marker for an in-flight delivery. Dropping it releases the slot.
pub struct DeliveryInFlight(([u8; 32], [u8; 32], [u8; 32]));

impl DeliveryInFlight {
    /// Claim the slot. Returns `None` if this process is already delivering
    /// this proposal — the caller should skip, not fail.
    pub fn claim(
        relationship_key: &[u8; 32],
        canonical_parent: &[u8; 32],
        proposal_nonce: &[u8; 32],
    ) -> Option<Self> {
        let key = (*relationship_key, *canonical_parent, *proposal_nonce);
        let mut set = DELIVERY_IN_FLIGHT.lock().unwrap_or_else(|p| p.into_inner());
        if set.insert(key) {
            Some(Self(key))
        } else {
            None
        }
    }
}

impl Drop for DeliveryInFlight {
    fn drop(&mut self) {
        DELIVERY_IN_FLIGHT
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(&self.0);
    }
}

/// Compare-and-set lifecycle advance: `from` → `to`, applied only when the row
/// is currently in one of `from`.
///
/// Why this exists alongside `set_sender_outbox_status`: the plain setter is an
/// unconditional UPDATE, and the delivery path is not the only writer. While a
/// submission is on the wire the recipient can accept and reply, and a
/// concurrent `storage.sync` can run `finalize_on_acceptance_atomically`, which
/// moves the row to `gc_pending`. A delivery result landing after that must NOT
/// drag the row back to `submitted` or `submission_uncertain` — that would leave
/// it outside both the unsettled set and the GC set forever. So every writer
/// that reacts to a delivery outcome names the states it is allowed to leave.
///
/// Returns `true` iff a row transitioned.
pub fn advance_sender_outbox_status_if(
    relationship_key: &[u8; 32],
    canonical_parent: &[u8; 32],
    proposal_nonce: &[u8; 32],
    from: &[&str],
    to: &str,
) -> Result<bool> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|e| e.into_inner());
    advance_sender_outbox_status_if_with_conn(
        &conn,
        relationship_key,
        canonical_parent,
        proposal_nonce,
        from,
        to,
    )
}

/// Same, inside a caller-owned transaction.
pub fn advance_sender_outbox_status_if_with_conn(
    conn: &Connection,
    relationship_key: &[u8; 32],
    canonical_parent: &[u8; 32],
    proposal_nonce: &[u8; 32],
    from: &[&str],
    to: &str,
) -> Result<bool> {
    if from.is_empty() {
        return Ok(false);
    }
    // Build `?5, ?6, ...` for the IN list; rusqlite has no array binding.
    let placeholders: Vec<String> = (0..from.len()).map(|i| format!("?{}", i + 5)).collect();
    let sql = format!(
        "UPDATE sender_outbox SET status = ?4
         WHERE relationship_key = ?1 AND canonical_parent = ?2 AND proposal_nonce = ?3
           AND status IN ({})",
        placeholders.join(", ")
    );
    let mut params: Vec<Box<dyn rusqlite::ToSql>> = vec![
        Box::new(relationship_key.to_vec()),
        Box::new(canonical_parent.to_vec()),
        Box::new(proposal_nonce.to_vec()),
        Box::new(to.to_string()),
    ];
    for s in from {
        params.push(Box::new(s.to_string()));
    }
    let n = conn.execute(
        &sql,
        rusqlite::params_from_iter(params.iter().map(|p| p.as_ref())),
    )?;
    Ok(n > 0)
}

/// Record the storage message ids a submission returned. GC metadata ONLY —
/// finalization keys on the receipt commitment, never on these.
pub fn bind_sender_outbox_message_ids(
    relationship_key: &[u8; 32],
    canonical_parent: &[u8; 32],
    proposal_nonce: &[u8; 32],
    message_ids: &str,
) -> Result<bool> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|e| e.into_inner());
    let n = conn.execute(
        "UPDATE sender_outbox SET message_ids = ?4
         WHERE relationship_key = ?1 AND canonical_parent = ?2 AND proposal_nonce = ?3",
        params![
            relationship_key.as_slice(),
            canonical_parent.as_slice(),
            proposal_nonce.as_slice(),
            message_ids
        ],
    )?;
    Ok(n > 0)
}

/// Rows needing forward reconciliation: committed locally but not yet known to
/// have been accepted. Drives the startup/periodic resubmit sweep.
pub fn unsettled_sender_outbox() -> Result<Vec<SenderOutboxRecord>> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|e| e.into_inner());
    let mut stmt = conn.prepare(&format!(
        "SELECT {COLS} FROM sender_outbox WHERE status IN (?1, ?2, ?3) ORDER BY created_at"
    ))?;
    let rows = stmt
        .query_map(
            params![
                OUTBOX_PENDING_SUBMIT,
                OUTBOX_SUBMITTING,
                OUTBOX_SUBMISSION_UNCERTAIN
            ],
            row_to_record,
        )?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

/// Promote HELD rows to deliverable, inside the caller's transaction — the
/// terminal admission transaction. Admission is device-global and at most one
/// is pending, so this promotes every held row (there is at most one).
pub fn promote_held_outbox_rows_with_conn(conn: &Connection) -> Result<usize> {
    let n = conn.execute(
        "UPDATE sender_outbox SET status = ?1 WHERE status = ?2",
        params![OUTBOX_PENDING_SUBMIT, OUTBOX_ECONOMIC_ADMISSION_PENDING],
    )?;
    Ok(n)
}

/// Recovery sweep: a held row with NO pending admission means the admission
/// reached its terminal state but the same-transaction promotion did not run
/// (possible only across schema evolution or a defensive re-check) — promote.
/// Never promotes while an admission is actually pending.
pub fn promote_held_outbox_rows_if_admitted() -> Result<usize> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|e| e.into_inner());
    let pending: i64 = conn.query_row(
        "SELECT COUNT(*) FROM economic_pending_admissions",
        [],
        |r| r.get(0),
    )?;
    if pending > 0 {
        return Ok(0);
    }
    promote_held_outbox_rows_with_conn(&conn)
}

/// Finalized rows whose spool copies still need collecting.
pub fn gc_pending_sender_outbox() -> Result<Vec<SenderOutboxRecord>> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|e| e.into_inner());
    let mut stmt = conn.prepare(&format!(
        "SELECT {COLS} FROM sender_outbox WHERE status = ?1 ORDER BY created_at"
    ))?;
    let rows = stmt
        .query_map(params![OUTBOX_GC_PENDING], row_to_record)?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

/// Validate a 32-byte field coming from an untrusted/loaded row.
pub fn checked32(v: &[u8], what: &str) -> Result<[u8; 32]> {
    to32(v.to_vec(), what)
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

    fn rec(nonce: u8) -> SenderOutboxRecord {
        SenderOutboxRecord {
            relationship_key: [0x11u8; 32],
            canonical_parent: [0x22u8; 32],
            proposal_nonce: [nonce; 32],
            canonical_child: [0x33u8; 32],
            commitment: [0x44u8 ^ nonce; 32],
            projection_parent: [0xAAu8; 32],
            projection_target: [0xBBu8; 32],
            routing_address: "ROUTE".to_string(),
            submission_id: derive_submission_id(&[0x44u8 ^ nonce; 32]),
            envelope_bytes: vec![0xEEu8; 64],
            local_expected_prev: None,
            is_first_ek_step: true,
            status: OUTBOX_PENDING_SUBMIT.to_string(),
            message_ids: None,
            created_at: 0,
        }
    }

    /// The recipient's countersign delta as the sender retains it at
    /// finalization: role `countersign_b`, keyed to the same proposal.
    fn countersign_b_for(r: &SenderOutboxRecord) -> SenderOutboxArtifact {
        let body = vec![0xB0u8; 96];
        SenderOutboxArtifact {
            relationship_key: r.relationship_key,
            canonical_parent: r.canonical_parent,
            proposal_nonce: r.proposal_nonce,
            role: ArtifactRole::CountersignB,
            submission_id: derive_artifact_submission_id(&evidence_content_digest(
                ArtifactRole::CountersignB,
                &body,
            )),
            envelope_bytes: body.clone(),
            content_digest: evidence_content_digest(ArtifactRole::CountersignB, &body),
            routing_address: None,
        }
    }

    /// The finality certificate as the sender freezes it at finalization:
    /// role `relationship_finalized`, its own (recipient) route.
    fn finalized_for(r: &SenderOutboxRecord) -> SenderOutboxArtifact {
        let body = vec![0xF1u8; 96];
        SenderOutboxArtifact {
            relationship_key: r.relationship_key,
            canonical_parent: r.canonical_parent,
            proposal_nonce: r.proposal_nonce,
            role: ArtifactRole::RelationshipFinalized,
            submission_id: derive_artifact_submission_id(&evidence_content_digest(
                ArtifactRole::RelationshipFinalized,
                &body,
            )),
            envelope_bytes: body.clone(),
            content_digest: evidence_content_digest(ArtifactRole::RelationshipFinalized, &body),
            routing_address: Some("RECIPIENTROUTE".to_string()),
        }
    }

    fn with_conn<T>(f: impl FnOnce(&Connection) -> T) -> T {
        let binding = crate::storage::client_db::get_connection().expect("conn");
        let conn = binding.lock().unwrap_or_else(|e| e.into_inner());
        f(&conn)
    }

    // =====================================================================
    // §16.6 DEFECT 1 — the finalization must be ONE transaction.
    //
    // These build a complete pre-finalization world (contact at the projection
    // parent, gate, proposal, pending Local EK head, submitted outbox row) and
    // then assert the six mutations land together or not at all.
    // =====================================================================

    const CP: [u8; 32] = [0x99u8; 32];
    const T0: [u8; 32] = [0xAAu8; 32];
    const T1: [u8; 32] = [0xBBu8; 32];
    const EK_B: [u8; 8] = [0xB0u8; 8];
    /// The relationship's genesis seed — the peer pair's parent on the first step.
    const SEED: [u8; 32] = [0xA0u8; 32];

    /// Seed everything a send leaves behind just before its acceptance lands.
    fn seed_pre_finalization(r: &SenderOutboxRecord) {
        with_conn(|c| {
            c.execute(
                "INSERT INTO contacts (contact_id, device_id, alias, genesis_hash, chain_tip,
                     added_at, verified, status, needs_online_reconcile,
                     last_seen_online_counter, last_seen_ble_counter, local_bilateral_chain_tip)
                 VALUES ('c1', ?1, 'peer', X'00', ?2, 0, 1, 'active', 0, 0, 0, ?2)",
                rusqlite::params![&CP[..], &T0[..]],
            )
            .expect("seed contact");
        });
        // Faithful ordering: at send time BOTH tips sit at the projection
        // parent. The gate write is what moves `local_bilateral_chain_tip` to
        // the target, leaving the asymmetry (chain_tip=T0, local=T1) that
        // finalization must resolve.
        crate::storage::client_db::record_pending_online_transition(&CP, "MSGID", &T0, &T1)
            .expect("seed gate");
        let proposal = crate::storage::client_db::SenderOnlineProposal {
            relationship_key: r.relationship_key,
            canonical_parent: r.canonical_parent,
            canonical_child: r.canonical_child,
            projection_parent: T0,
            projection_target: T1,
            commitment: r.commitment,
            operation_digest: [0x5Au8; 32],
            nonce_hash: r.proposal_nonce,
            message_id: None,
            tx_id: "tx-1".into(),
            counterparty_device_id: CP,
            amount: 15,
            token_id: "ERA".into(),
            status: crate::storage::client_db::PROPOSAL_PROPOSED.into(),
            created_at: 0,
        };
        crate::storage::client_db::insert_sender_proposal(&proposal).expect("seed proposal");
        crate::storage::client_db::mark_sender_proposal_submitted(
            &r.relationship_key,
            &r.canonical_parent,
            "MSGID",
        )
        .expect("submit proposal");
        crate::storage::client_db::stash_pending_local_head(
            &r.relationship_key,
            &r.commitment,
            &[0xE1u8; 8],
            &[0x55u8; 128],
            &[0x77u8; 32],
            true,
        )
        .expect("seed pending head");
        with_conn(|c| insert_sender_outbox_with_conn(c, r)).expect("seed outbox");
        set_sender_outbox_status(
            &r.relationship_key,
            &r.canonical_parent,
            &r.proposal_nonce,
            OUTBOX_SUBMITTED,
        )
        .expect("submitted");
    }

    fn tips() -> (Vec<u8>, Vec<u8>) {
        with_conn(|c| {
            c.query_row(
                "SELECT chain_tip, local_bilateral_chain_tip FROM contacts WHERE device_id = ?1",
                rusqlite::params![&CP[..]],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("tips")
        })
    }

    fn gate_rows() -> i64 {
        with_conn(|c| {
            c.query_row(
                "SELECT COUNT(*) FROM pending_online_outbox WHERE counterparty_device_id = ?1",
                rusqlite::params![&CP[..]],
                |row| row.get(0),
            )
            .expect("gate count")
        })
    }

    fn statuses(r: &SenderOutboxRecord) -> (String, String) {
        let proposal = crate::storage::client_db::get_sender_proposal_by_commitment(&r.commitment)
            .expect("proposal")
            .expect("present");
        let outbox = get_sender_outbox_by_commitment(&r.commitment)
            .expect("outbox")
            .expect("present");
        (proposal.status, outbox.status)
    }

    /// The happy path: all seven mutations land in one commit.
    #[test]
    #[serial]
    fn finalization_commits_all_six_mutations() {
        init_test_db();
        let r = rec(1);
        seed_pre_finalization(&r);

        finalize_on_acceptance_atomically(&AcceptanceFinalization {
            relationship_key: &r.relationship_key,
            canonical_parent: &r.canonical_parent,
            proposal_nonce: &r.proposal_nonce,
            commitment: &r.commitment,
            counterparty_device_id: &CP,
            projection_parent: &T0,
            projection_target: &T1,
            expected_counterparty_head: None,
            new_counterparty_head: &EK_B,
            peer_pair: (SEED, [0xB1u8; 32]),
            genesis_seed: SEED,
            countersign_b: &countersign_b_for(&r),
            finalized: &finalized_for(&r),
        })
        .expect("finalization");
        assert_eq!(
            crate::storage::client_db::load_counterparty_canonical_head(&r.relationship_key)
                .expect("head"),
            Some([0xB1u8; 32]),
            "the peer's canonical head is pinned at the delta's child"
        );

        let (chain_tip, local_tip) = tips();
        assert_eq!(chain_tip, T1.to_vec(), "projection tip advanced");
        let retained = load_sender_outbox_artifacts(
            &r.relationship_key,
            &r.canonical_parent,
            &r.proposal_nonce,
        )
        .expect("artifacts");
        assert_eq!(
            retained,
            vec![countersign_b_for(&r), finalized_for(&r)],
            "the recipient's countersign delta AND the finality certificate (with its \
             frozen route) are persisted in the same commit"
        );
        assert_eq!(local_tip, T1.to_vec(), "both spaces converge");
        assert_eq!(
            crate::storage::client_db::load_cert_chain_head_pubkey(
                &r.relationship_key,
                crate::storage::client_db::CertChainSide::Local,
            )
            .unwrap()
            .unwrap(),
            vec![0xE1u8; 8],
            "pending Local EK head promoted — this is what makes transfer #2 \
             chain from the EK instead of falling back to the root AK"
        );
        assert_eq!(
            crate::storage::client_db::load_cert_chain_head_pubkey(
                &r.relationship_key,
                crate::storage::client_db::CertChainSide::Counterparty,
            )
            .unwrap()
            .unwrap(),
            EK_B.to_vec(),
            "counterparty head advanced to the recipient's ek_pk_b"
        );
        let (proposal_status, outbox_status) = statuses(&r);
        assert_eq!(
            proposal_status,
            crate::storage::client_db::PROPOSAL_FINALIZED
        );
        assert_eq!(
            gate_rows(),
            1,
            "the gate is NOT released by local finalization (finality barrier)"
        );
        assert_eq!(
            outbox_status, OUTBOX_FINALIZATION_CHECKPOINT_PENDING,
            "the outbox row waits for the certificate to reach quorum"
        );

        // A re-entrant finalize (redelivered delta) must not move the status.
        // ...and the ONE deleter: release on checkpoint quorum, one tx.
        assert!(
            release_gate_on_finalization_checkpoint_atomically(
                &r.relationship_key,
                &r.canonical_parent,
                &r.proposal_nonce,
                &CP,
                &T0,
                &T1,
            )
            .expect("release"),
            "first release advances"
        );
        assert_eq!(gate_rows(), 0, "gate released by the checkpoint sweep");
        assert_eq!(statuses(&r).1, OUTBOX_GC_PENDING);
        assert!(
            !release_gate_on_finalization_checkpoint_atomically(
                &r.relationship_key,
                &r.canonical_parent,
                &r.proposal_nonce,
                &CP,
                &T0,
                &T1,
            )
            .expect("second release"),
            "a second release is a no-op, not an error"
        );
    }

    /// The release is all-or-nothing: with the gate row absent the status must
    /// NOT advance to gc_pending (that would silently forget the release).
    #[test]
    #[serial]
    fn checkpoint_release_refuses_when_the_gate_row_is_missing() {
        init_test_db();
        let r = rec(9);
        seed_pre_finalization(&r);
        finalize_on_acceptance_atomically(&AcceptanceFinalization {
            relationship_key: &r.relationship_key,
            canonical_parent: &r.canonical_parent,
            proposal_nonce: &r.proposal_nonce,
            commitment: &r.commitment,
            counterparty_device_id: &CP,
            projection_parent: &T0,
            projection_target: &T1,
            expected_counterparty_head: None,
            new_counterparty_head: &EK_B,
            peer_pair: (SEED, [0xB1u8; 32]),
            genesis_seed: SEED,
            countersign_b: &countersign_b_for(&r),
            finalized: &finalized_for(&r),
        })
        .expect("finalization");
        // Simulate a foreign deletion of the gate row.
        with_conn(|c| {
            c.execute(
                "DELETE FROM pending_online_outbox WHERE counterparty_device_id = ?1",
                rusqlite::params![&CP[..]],
            )
            .expect("delete gate");
        });
        let err = release_gate_on_finalization_checkpoint_atomically(
            &r.relationship_key,
            &r.canonical_parent,
            &r.proposal_nonce,
            &CP,
            &T0,
            &T1,
        )
        .expect_err("missing gate row is an invariant violation");
        assert!(err.to_string().contains("invariant"), "{err}");
        assert_eq!(
            statuses(&r).1,
            OUTBOX_FINALIZATION_CHECKPOINT_PENDING,
            "status write rolled back with the failed release"
        );
    }

    /// THE ATOMICITY PROOF. The counterparty-head CAS is the third of six
    /// mutations; force it to conflict and the two that already ran (tip
    /// advance, Local head promotion) must be gone too. If this ever passes
    /// with a partially-advanced tip, the finalization has been split again and
    /// the transfer-#2 defect is back in a new shape.
    #[test]
    #[serial]
    fn a_failure_midway_rolls_back_the_whole_finalization() {
        init_test_db();
        let r = rec(2);
        seed_pre_finalization(&r);
        // A head already exists, so passing `None` as the expectation is a
        // genuine CAS conflict rather than a genesis init.
        crate::storage::client_db::init_cert_chain_head(
            &r.relationship_key,
            crate::storage::client_db::CertChainSide::Counterparty,
            &[0xC0u8; 8],
        )
        .expect("seed counterparty head");

        let err = finalize_on_acceptance_atomically(&AcceptanceFinalization {
            relationship_key: &r.relationship_key,
            canonical_parent: &r.canonical_parent,
            proposal_nonce: &r.proposal_nonce,
            commitment: &r.commitment,
            counterparty_device_id: &CP,
            projection_parent: &T0,
            projection_target: &T1,
            expected_counterparty_head: Some(&[0xDEu8; 8]), // stale — conflicts with 0xC0
            new_counterparty_head: &EK_B,
            peer_pair: (SEED, [0xB1u8; 32]),
            genesis_seed: SEED,
            countersign_b: &countersign_b_for(&r),
            finalized: &finalized_for(&r),
        });
        assert!(err.is_err(), "a conflicting head must abort finalization");
        assert_eq!(
            crate::storage::client_db::load_counterparty_canonical_head(&r.relationship_key)
                .expect("head"),
            None,
            "peer canonical head CAS ROLLED BACK"
        );

        let (chain_tip, local_tip) = tips();
        assert_eq!(chain_tip, T0.to_vec(), "tip advance ROLLED BACK");
        assert!(
            load_sender_outbox_artifacts(
                &r.relationship_key,
                &r.canonical_parent,
                &r.proposal_nonce,
            )
            .expect("artifacts")
            .is_empty(),
            "the countersign delta is NOT persisted when finalization aborts"
        );
        assert_eq!(local_tip, T1.to_vec(), "local tip untouched");
        assert_eq!(
            crate::storage::client_db::load_cert_chain_head_pubkey(
                &r.relationship_key,
                crate::storage::client_db::CertChainSide::Local,
            )
            .unwrap(),
            None,
            "Local head promotion ROLLED BACK"
        );
        assert_eq!(
            crate::storage::client_db::load_cert_chain_head_pubkey(
                &r.relationship_key,
                crate::storage::client_db::CertChainSide::Counterparty,
            )
            .unwrap()
            .unwrap(),
            vec![0xC0u8; 8],
            "counterparty head unchanged"
        );
        let (proposal_status, outbox_status) = statuses(&r);
        assert_eq!(
            proposal_status,
            crate::storage::client_db::PROPOSAL_SUBMITTED,
            "proposal NOT finalized"
        );
        assert_eq!(gate_rows(), 1, "gate NOT released");
        assert_eq!(
            outbox_status, OUTBOX_SUBMITTED,
            "outbox still drives a retry — the whole sequence re-runs cleanly"
        );
    }

    /// A redelivered acceptance artifact must never cause a second advance.
    /// The handler short-circuits on `PROPOSAL_FINALIZED` before reaching this
    /// function; at THIS layer a re-entry after the commit is refused (the
    /// pending Local EK head — the certificate's signing key — is gone) and
    /// changes nothing.
    #[test]
    #[serial]
    fn redelivered_acceptance_is_refused_and_advances_nothing() {
        init_test_db();
        let r = rec(3);
        seed_pre_finalization(&r);
        let call = || {
            finalize_on_acceptance_atomically(&AcceptanceFinalization {
                relationship_key: &r.relationship_key,
                canonical_parent: &r.canonical_parent,
                proposal_nonce: &r.proposal_nonce,
                commitment: &r.commitment,
                counterparty_device_id: &CP,
                projection_parent: &T0,
                projection_target: &T1,
                expected_counterparty_head: None,
                new_counterparty_head: &EK_B,
                peer_pair: (SEED, [0xB1u8; 32]),
                genesis_seed: SEED,
                countersign_b: &countersign_b_for(&r),
                finalized: &finalized_for(&r),
            })
        };
        call().expect("first finalization");
        let head_after_first = crate::storage::client_db::load_cert_chain_head(
            &r.relationship_key,
            crate::storage::client_db::CertChainSide::Local,
        )
        .unwrap()
        .unwrap();

        let err = call().expect_err("a re-entrant finalize after the commit is refused");
        assert!(
            err.to_string().contains("no pending Local EK head"),
            "{err}"
        );

        let head_after_second = crate::storage::client_db::load_cert_chain_head(
            &r.relationship_key,
            crate::storage::client_db::CertChainSide::Local,
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            head_after_first.step_count, head_after_second.step_count,
            "a redelivered acceptance must NOT double-advance the cert chain"
        );
        assert_eq!(tips().0, T1.to_vec(), "tip stays at target");
        let (_, outbox_status) = statuses(&r);
        assert_eq!(outbox_status, OUTBOX_FINALIZATION_CHECKPOINT_PENDING);
    }

    /// The submission id must be a pure function of the commitment: known
    /// before submitting, identical on every retry, so the node collapses
    /// retries onto one spool row instead of piling up duplicates.
    #[test]
    fn submission_id_is_deterministic_in_the_commitment() {
        let a = derive_submission_id(&[0x07u8; 32]);
        let b = derive_submission_id(&[0x07u8; 32]);
        let c = derive_submission_id(&[0x08u8; 32]);
        assert_eq!(a, b, "same commitment must yield the same submission id");
        assert_ne!(a, c, "different commitments must not collide");
        let decoded = crate::util::text_id::decode_base32_crockford(&a).expect("base32");
        assert_eq!(
            decoded.len(),
            16,
            "deployed nodes hard-require a 16-byte message id"
        );
    }

    /// Existence of the row is the rollback gate — asserted directly because
    /// the whole value-safety argument rests on it.
    #[test]
    #[serial]
    fn the_outbox_row_is_the_forward_only_marker() {
        init_test_db();
        let r = rec(0x01);
        let exists = |r: &SenderOutboxRecord| {
            get_sender_outbox(&r.relationship_key, &r.canonical_parent, &r.proposal_nonce)
                .unwrap()
                .is_some()
        };
        assert!(
            !exists(&r),
            "before the commit there is no durable record of this send"
        );
        with_conn(|c| insert_sender_outbox_with_conn(c, &r)).unwrap();
        assert!(
            exists(&r),
            "after the commit the transfer is FORWARD-ONLY — this row is what \
             recovery sweeps forward, and nothing exists that could unwind it"
        );
    }

    /// A byte-identical re-entry is a no-op; a DIFFERENT envelope claiming the
    /// same identity must fail closed rather than overwrite a durable record.
    #[test]
    #[serial]
    fn identical_reentry_is_idempotent_divergent_fails_closed() {
        init_test_db();
        let r = rec(0x02);
        with_conn(|c| insert_sender_outbox_with_conn(c, &r)).unwrap();
        with_conn(|c| insert_sender_outbox_with_conn(c, &r))
            .expect("identical re-entry must be idempotent");

        let mut divergent = r.clone();
        divergent.envelope_bytes = vec![0x01u8; 64];
        let err = with_conn(|c| insert_sender_outbox_with_conn(c, &divergent))
            .expect_err("a different envelope must not overwrite the record");
        assert!(err.to_string().contains("DIFFERENT outbox entry"));
    }

    /// The sweep must see everything that is committed-but-unsettled, and stop
    /// seeing it once it reaches a terminal state.
    #[test]
    #[serial]
    fn unsettled_sweep_tracks_the_lifecycle() {
        init_test_db();
        let r = rec(0x03);
        with_conn(|c| insert_sender_outbox_with_conn(c, &r)).unwrap();
        assert_eq!(unsettled_sender_outbox().unwrap().len(), 1);

        for s in [OUTBOX_SUBMITTING, OUTBOX_SUBMISSION_UNCERTAIN] {
            set_sender_outbox_status(
                &r.relationship_key,
                &r.canonical_parent,
                &r.proposal_nonce,
                s,
            )
            .unwrap();
            assert_eq!(
                unsettled_sender_outbox().unwrap().len(),
                1,
                "status {s} still needs forward reconciliation"
            );
        }

        set_sender_outbox_status(
            &r.relationship_key,
            &r.canonical_parent,
            &r.proposal_nonce,
            OUTBOX_GC_PENDING,
        )
        .unwrap();
        assert!(
            unsettled_sender_outbox().unwrap().is_empty(),
            "finalized rows leave the resubmit sweep"
        );
        assert_eq!(
            gc_pending_sender_outbox().unwrap().len(),
            1,
            "...and enter the transport-GC sweep"
        );
    }

    /// The exact bytes must round-trip: a retry resubmits the identical
    /// artifact rather than rebuilding one from state that may have moved.
    #[test]
    #[serial]
    fn envelope_bytes_and_commitment_round_trip() {
        init_test_db();
        let r = rec(0x04);
        with_conn(|c| insert_sender_outbox_with_conn(c, &r)).unwrap();
        let loaded = get_sender_outbox_by_commitment(&r.commitment)
            .unwrap()
            .expect("row by commitment");
        assert_eq!(loaded.envelope_bytes, r.envelope_bytes);
        assert_eq!(loaded.submission_id, r.submission_id);
        assert_eq!(loaded.projection_parent, r.projection_parent);
        assert!(loaded.is_first_ek_step);
        assert!(loaded.local_expected_prev.is_none());
    }

    // ---------------------------------------------------------------------
    // §16.6 DEFECT ZERO — the atomic pre-submit commit.
    //
    // The live hazard was: storage quorum accepted the transfer, a local write
    // then failed, and the sender rolled back its debit while the message
    // stayed creditable on all three nodes. These tests pin the property that
    // removes it: EITHER every local record exists and the transfer is
    // forward-only, OR none of them exists and nothing was ever sent.
    // ---------------------------------------------------------------------

    fn seed_contact(devid: [u8; 32], tip: [u8; 32]) {
        let mut c = crate::storage::client_db::ContactRecord {
            contact_id: "cid-outbox-test".to_string(),
            device_id: devid.to_vec(),
            alias: "peer".to_string(),
            genesis_hash: [0xAAu8; 32].to_vec(),
            public_key: vec![0xBBu8; 64],
            kyber_public_key: vec![0xCCu8; 1184],
            current_chain_tip: Some(tip.to_vec()),
            added_at: 1,
            verified: true,
            verification_proof: None,
            metadata: std::collections::HashMap::new(),
            ble_address: None,
            status: "Created".to_string(),
            needs_online_reconcile: false,
            last_seen_online_counter: 0,
            last_seen_ble_counter: 0,
            previous_chain_tip: None,
        };
        c.current_chain_tip = Some(tip.to_vec());
        crate::storage::client_db::store_contact(&c).expect("seed contact");
    }

    fn proposal_for(
        rel: [u8; 32],
        counterparty: [u8; 32],
        nonce_hash: [u8; 32],
        commitment: [u8; 32],
        proj_parent: [u8; 32],
        proj_target: [u8; 32],
    ) -> super::super::sender_proposal::SenderOnlineProposal {
        super::super::sender_proposal::SenderOnlineProposal {
            relationship_key: rel,
            canonical_parent: [0x71u8; 32],
            canonical_child: [0x72u8; 32],
            projection_parent: proj_parent,
            projection_target: proj_target,
            commitment,
            operation_digest: [0x73u8; 32],
            nonce_hash,
            message_id: None,
            tx_id: "tx:outbox-test".to_string(),
            counterparty_device_id: counterparty,
            amount: 25,
            token_id: "ERA".to_string(),
            status: super::super::sender_proposal::PROPOSAL_PROPOSED.to_string(),
            created_at: 0,
        }
    }

    fn outbox_for(
        p: &super::super::sender_proposal::SenderOnlineProposal,
        expected_prev: Option<Vec<u8>>,
        is_first: bool,
    ) -> SenderOutboxRecord {
        SenderOutboxRecord {
            relationship_key: p.relationship_key,
            canonical_parent: p.canonical_parent,
            proposal_nonce: p.nonce_hash,
            canonical_child: p.canonical_child,
            commitment: p.commitment,
            projection_parent: p.projection_parent,
            projection_target: p.projection_target,
            routing_address: "ROUTE-XYZ".to_string(),
            submission_id: derive_submission_id(&p.commitment),
            envelope_bytes: vec![0xE1u8; 96],
            local_expected_prev: expected_prev,
            is_first_ek_step: is_first,
            status: OUTBOX_PENDING_SUBMIT.to_string(),
            message_ids: None,
            created_at: 0,
        }
    }

    fn artifact_for(
        p: &super::super::sender_proposal::SenderOnlineProposal,
        bytes: Vec<u8>,
    ) -> SenderOutboxArtifact {
        let digest = evidence_content_digest(ArtifactRole::EvidenceA, &bytes);
        SenderOutboxArtifact {
            relationship_key: p.relationship_key,
            canonical_parent: p.canonical_parent,
            proposal_nonce: p.nonce_hash,
            role: ArtifactRole::EvidenceA,
            submission_id: format!("EVID-{}", derive_submission_id(&p.commitment)),
            envelope_bytes: bytes,
            content_digest: digest,
            routing_address: None,
        }
    }

    /// Distinct deterministic ids for the artifacts of one transfer.
    ///
    /// This proves DOMAIN SEPARATION for the tested artifacts -- it does not
    /// prove ids cannot collide. The id is 16 bytes truncated from a 32-byte
    /// digest, so collision is a 128-bit possibility: cryptographically
    /// negligible, not impossible. Correctness therefore cannot rest on
    /// uniqueness alone, because the node resolves `UNIQUE(message_id)` with
    /// `ON CONFLICT DO NOTHING` -- a colliding id is accepted silently rather
    /// than rejected. The content check in
    /// `same_artifact_id_with_different_bytes_fails_closed` is what makes that
    /// safe: same id + different bytes must fail, not disappear.
    #[test]
    fn artifact_submission_ids_are_distinct_per_role_and_from_the_transfer() {
        let commitment = [0x5Cu8; 32];
        let payload = vec![0x11u8; 512];

        let transfer_id = derive_submission_id(&commitment);
        let a_digest = evidence_content_digest(ArtifactRole::EvidenceA, &payload);
        let b_digest = evidence_content_digest(ArtifactRole::CountersignB, &payload);
        let a_id = derive_artifact_submission_id(&a_digest);
        let b_id = derive_artifact_submission_id(&b_digest);

        assert_ne!(a_digest, b_digest, "role must separate the content address");
        assert_ne!(a_id, b_id, "role separation must reach the submission id");
        assert_ne!(
            a_id, transfer_id,
            "artifact id must differ from the transfer id"
        );
        assert_ne!(
            b_id, transfer_id,
            "artifact id must differ from the transfer id"
        );

        // Deterministic: a retry derives the same ids rather than new ones.
        assert_eq!(a_id, derive_artifact_submission_id(&a_digest));
        assert_eq!(
            a_digest,
            evidence_content_digest(ArtifactRole::EvidenceA, &payload)
        );
    }

    /// Same submission id + DIFFERENT bytes must fail closed.
    ///
    /// The id is 16 bytes truncated from a 32-byte digest, so a collision is a
    /// 128-bit possibility rather than an impossibility -- and the storage node
    /// resolves `UNIQUE(message_id)` with `ON CONFLICT DO NOTHING`, which
    /// ACCEPTS a colliding id silently. Uniqueness alone is therefore not a
    /// safety property; the content equality check is.
    ///
    /// Same id + same bytes stays idempotent, so an ordinary retry is unaffected.
    #[test]
    #[serial]
    fn same_artifact_id_with_different_bytes_fails_closed() {
        init_test_db();
        let rel = [0xE1u8; 32];
        let cp = [0xE2u8; 32];
        let (pp, pt) = ([0xE3u8; 32], [0xE4u8; 32]);
        seed_contact(cp, pp);
        let p = proposal_for(rel, cp, [0xE5u8; 32], [0xE6u8; 32], pp, pt);
        let ob = outbox_for(&p, None, true);
        let original = artifact_for(&p, vec![0xAA; 128]);

        commit_send_prerequisites_atomically(
            &p,
            &ob,
            "MSGID-CONFLICT",
            &[0xA1u8; 64],
            &[0xA2u8; 64],
            &[0x42u8; 32],
            true,
            std::slice::from_ref(&original),
        )
        .expect("first commit");

        let binding = get_connection().expect("conn");
        let conn = binding.lock().unwrap_or_else(|e| e.into_inner());

        // Same id, same bytes -> idempotent no-op.
        insert_sender_outbox_artifact_with_conn(&conn, &original)
            .expect("identical re-entry must be idempotent");

        // Same id, DIFFERENT bytes -> fail closed, never silently dropped.
        let mut impostor = original.clone();
        impostor.envelope_bytes = vec![0xBB; 128];
        impostor.content_digest =
            evidence_content_digest(ArtifactRole::EvidenceA, &impostor.envelope_bytes);
        let err = insert_sender_outbox_artifact_with_conn(&conn, &impostor)
            .expect_err("same id with different bytes must fail closed");
        assert!(
            err.to_string()
                .contains("already holds a DIFFERENT artifact"),
            "unexpected error: {err}"
        );
        drop(conn);

        // The original survives untouched.
        let arts =
            load_sender_outbox_artifacts(&rel, &p.canonical_parent, &p.nonce_hash).expect("load");
        assert_eq!(arts.len(), 1);
        assert_eq!(
            arts[0].envelope_bytes, original.envelope_bytes,
            "the stored artifact must not be replaced by a colliding one"
        );
    }

    /// ADR 0003, the first dangerous invariant of the split:
    ///
    /// > After local debit advancement commits, either BOTH deliverable
    /// > artifacts are durably reconstructible byte-for-byte, or neither is.
    ///
    /// Both artifacts are written in the same transaction as the canonical
    /// advance, and the bytes come back verbatim -- a retry replays them rather
    /// than rebuilding from state that may have moved.
    #[test]
    #[serial]
    fn both_artifacts_are_durable_byte_for_byte_after_the_atomic_commit() {
        init_test_db();
        let rel = [0xC1u8; 32];
        let cp = [0xC2u8; 32];
        let (pp, pt) = ([0xC3u8; 32], [0xC4u8; 32]);
        seed_contact(cp, pp);
        let p = proposal_for(rel, cp, [0xC5u8; 32], [0xC6u8; 32], pp, pt);
        let ob = outbox_for(&p, None, true);
        let evidence_bytes: Vec<u8> = (0..4096u32).map(|i| (i % 251) as u8).collect();
        let art = artifact_for(&p, evidence_bytes.clone());

        commit_send_prerequisites_atomically(
            &p,
            &ob,
            "MSGID-ART",
            &[0xA1u8; 64],
            &[0xA2u8; 64],
            &[0x42u8; 32],
            true,
            std::slice::from_ref(&art),
        )
        .expect("atomic commit with artifact");

        // The transfer artifact.
        let stored = get_sender_outbox(&rel, &p.canonical_parent, &p.nonce_hash)
            .expect("load outbox")
            .expect("outbox row exists");
        assert_eq!(
            stored.envelope_bytes, ob.envelope_bytes,
            "transfer artifact must be byte-identical to what was committed"
        );

        // The evidence artifact.
        let arts = load_sender_outbox_artifacts(&rel, &p.canonical_parent, &p.nonce_hash)
            .expect("load artifacts");
        assert_eq!(arts.len(), 1, "exactly the artifact committed");
        assert_eq!(
            arts[0].envelope_bytes, evidence_bytes,
            "evidence artifact must be byte-identical, not rebuilt"
        );
        assert_eq!(arts[0].role, ArtifactRole::EvidenceA);
        assert_eq!(
            arts[0].content_digest,
            evidence_content_digest(ArtifactRole::EvidenceA, &evidence_bytes),
            "content digest must bind the exact stored bytes"
        );
    }

    /// The other half of the invariant: if ANY part of the bundle fails, nothing
    /// is durable -- including the artifact. A duplicate submission_id aborts the
    /// whole transaction, so no artifact can survive a proposal that did not.
    #[test]
    #[serial]
    fn a_failed_bundle_leaves_no_artifact_behind() {
        init_test_db();
        let rel = [0xD1u8; 32];
        let cp = [0xD2u8; 32];
        let (pp, pt) = ([0xD3u8; 32], [0xD4u8; 32]);
        seed_contact(cp, pp);
        let p = proposal_for(rel, cp, [0xD5u8; 32], [0xD6u8; 32], pp, pt);
        let ob = outbox_for(&p, None, true);

        // Two artifacts claiming the SAME submission_id: the second violates
        // UNIQUE(submission_id) and must abort the entire commit.
        let a1 = artifact_for(&p, vec![0x01; 64]);
        let mut a2 = artifact_for(&p, vec![0x02; 64]);
        a2.role = ArtifactRole::CountersignB;

        let err = commit_send_prerequisites_atomically(
            &p,
            &ob,
            "MSGID-DUP",
            &[0xA1u8; 64],
            &[0xA2u8; 64],
            &[0x42u8; 32],
            true,
            &[a1, a2],
        )
        .expect_err("duplicate submission_id must abort the bundle");
        assert!(
            err.to_string()
                .contains("already holds a DIFFERENT artifact"),
            "expected the fail-closed conflict check, got: {err}"
        );

        assert!(
            load_sender_outbox_artifacts(&rel, &p.canonical_parent, &p.nonce_hash)
                .expect("load artifacts")
                .is_empty(),
            "a failed bundle must leave NO artifact durable"
        );
        assert!(
            get_sender_outbox(&rel, &p.canonical_parent, &p.nonce_hash)
                .expect("load outbox")
                .is_none(),
            "a failed bundle must leave no outbox row either -- all or nothing"
        );
    }

    /// HAPPY PATH: all four records land together, and the transfer is
    /// immediately forward-only.
    #[test]
    #[serial]
    fn atomic_commit_persists_all_four_records_together() {
        init_test_db();
        let rel = [0x81u8; 32];
        let cp = [0x82u8; 32];
        let (pp, pt) = ([0x83u8; 32], [0x84u8; 32]);
        seed_contact(cp, pp);
        let p = proposal_for(rel, cp, [0x85u8; 32], [0x86u8; 32], pp, pt);
        let ob = outbox_for(&p, None, true);

        commit_send_prerequisites_atomically(
            &p,
            &ob,
            "MSGID-1",
            &[0xA1u8; 64],
            &[0xA2u8; 64],
            &[0x42u8; 32],
            true,
            &[],
        )
        .expect("atomic commit");

        assert!(
            super::super::sender_proposal::get_sender_proposal(&rel, &p.canonical_parent)
                .unwrap()
                .is_some(),
            "proposal must be durable before anything is sent"
        );
        assert!(
            super::super::online_outbox::get_pending_online_outbox(&cp)
                .unwrap()
                .is_some(),
            "gate must be durable before anything is sent"
        );
        assert!(
            get_sender_outbox(&rel, &p.canonical_parent, &p.nonce_hash)
                .unwrap()
                .is_some(),
            "outbox row is the rollback gate — it must exist"
        );
        let stored = get_sender_outbox_by_commitment(&p.commitment)
            .unwrap()
            .expect("outbox row");
        assert_eq!(
            stored.envelope_bytes, ob.envelope_bytes,
            "exact submission bytes are frozen for byte-identical retry"
        );
    }

    /// GATE WRITE FAILURE: an unknown contact makes the gate write fail, so the
    /// WHOLE transaction must abort — no proposal, no outbox, nothing sent.
    #[test]
    #[serial]
    fn gate_write_failure_aborts_everything_nothing_sent() {
        init_test_db();
        let rel = [0x91u8; 32];
        let cp = [0x92u8; 32]; // deliberately NOT stored as a contact
        let p = proposal_for(
            rel,
            cp,
            [0x95u8; 32],
            [0x96u8; 32],
            [0x93u8; 32],
            [0x94u8; 32],
        );
        let ob = outbox_for(&p, None, true);

        let err = commit_send_prerequisites_atomically(
            &p,
            &ob,
            "MSGID-2",
            &[0xB1u8; 64],
            &[0xB2u8; 64],
            &[0x42u8; 32],
            true,
            &[],
        )
        .expect_err("gate write must fail for an unknown contact");
        assert!(err.to_string().contains("unknown contact"), "got: {err}");

        assert!(
            super::super::sender_proposal::get_sender_proposal(&rel, &p.canonical_parent)
                .unwrap()
                .is_none(),
            "proposal must NOT survive an aborted commit"
        );
        assert!(
            get_sender_outbox(&rel, &p.canonical_parent, &p.nonce_hash)
                .unwrap()
                .is_none(),
            "no outbox row ⇒ rollback stays permitted ⇒ no stranded deliverable"
        );
    }

    /// CERT-HEAD RACE: the Local head moved between signing and commit. The
    /// commit must abort entirely — this is the last point at which losing that
    /// race is free.
    #[test]
    #[serial]
    fn cert_head_race_aborts_the_whole_commit() {
        init_test_db();
        let rel = [0xA1u8; 32];
        let cp = [0xA2u8; 32];
        let (pp, pt) = ([0xA3u8; 32], [0xA4u8; 32]);
        seed_contact(cp, pp);
        // A head exists NOW, but the sender snapshotted a different one.
        super::super::cert_chain::init_local_cert_chain_head_with_sk(
            &rel,
            &[0xEEu8; 64],
            &[0xEFu8; 64],
            &[0x42u8; 32],
        )
        .unwrap();
        let p = proposal_for(rel, cp, [0xA5u8; 32], [0xA6u8; 32], pp, pt);
        let ob = outbox_for(&p, Some(vec![0x11u8; 64]), false); // stale expectation

        let err = commit_send_prerequisites_atomically(
            &p,
            &ob,
            "MSGID-3",
            &[0xC1u8; 64],
            &[0xC2u8; 64],
            &[0x42u8; 32],
            false,
            &[],
        )
        .expect_err("a moved cert head must abort the commit");
        assert!(err.to_string().contains("CAS failed"), "got: {err}");

        assert!(
            get_sender_outbox(&rel, &p.canonical_parent, &p.nonce_hash)
                .unwrap()
                .is_none(),
            "nothing durable ⇒ nothing was ever deliverable"
        );
        assert!(
            super::super::online_outbox::get_pending_online_outbox(&cp)
                .unwrap()
                .is_none(),
            "gate must not survive the aborted commit"
        );
    }

    /// UNCERTAIN OUTCOME: a timeout is NOT proof of non-delivery. The record
    /// must survive and remain visible to the resubmit sweep, carrying the
    /// byte-identical envelope.
    #[test]
    #[serial]
    fn uncertain_submission_is_retained_for_forward_reconciliation() {
        init_test_db();
        let rel = [0xB1u8; 32];
        let cp = [0xB2u8; 32];
        let (pp, pt) = ([0xB3u8; 32], [0xB4u8; 32]);
        seed_contact(cp, pp);
        let p = proposal_for(rel, cp, [0xB5u8; 32], [0xB6u8; 32], pp, pt);
        let ob = outbox_for(&p, None, true);
        commit_send_prerequisites_atomically(
            &p,
            &ob,
            "MSGID-4",
            &[0xD1u8; 64],
            &[0xD2u8; 64],
            &[0x42u8; 32],
            true,
            &[],
        )
        .unwrap();

        // Network entered, outcome unknown.
        set_sender_outbox_status(&rel, &p.canonical_parent, &p.nonce_hash, OUTBOX_SUBMITTING)
            .unwrap();
        set_sender_outbox_status(
            &rel,
            &p.canonical_parent,
            &p.nonce_hash,
            OUTBOX_SUBMISSION_UNCERTAIN,
        )
        .unwrap();

        let pending = unsettled_sender_outbox().unwrap();
        assert_eq!(
            pending.len(),
            1,
            "an uncertain send must be retried, never dropped"
        );
        assert_eq!(
            pending[0].envelope_bytes, ob.envelope_bytes,
            "resubmission replays the EXACT stored bytes"
        );
        assert_eq!(
            pending[0].submission_id, ob.submission_id,
            "same deterministic id ⇒ the node collapses the retry onto one spool row"
        );
        // The debit's justification is still fully intact.
        assert!(
            super::super::sender_proposal::get_sender_proposal(&rel, &p.canonical_parent)
                .unwrap()
                .is_some()
        );
        assert!(super::super::online_outbox::get_pending_online_outbox(&cp)
            .unwrap()
            .is_some());
    }

    /// CRASH AFTER QUORUM: the row was left mid-flight at `submitting`. On
    /// restart it must be picked up and reconciled FORWARD — never rolled back,
    /// because the message may already have been accepted.
    #[test]
    #[serial]
    fn crash_at_submitting_reconciles_forward_on_restart() {
        init_test_db();
        let rel = [0xC1u8; 32];
        let cp = [0xC2u8; 32];
        let (pp, pt) = ([0xC3u8; 32], [0xC4u8; 32]);
        seed_contact(cp, pp);
        let p = proposal_for(rel, cp, [0xC5u8; 32], [0xC6u8; 32], pp, pt);
        let ob = outbox_for(&p, None, true);
        commit_send_prerequisites_atomically(
            &p,
            &ob,
            "MSGID-5",
            &[0xE1u8; 64],
            &[0xE2u8; 64],
            &[0x42u8; 32],
            true,
            &[],
        )
        .unwrap();
        set_sender_outbox_status(&rel, &p.canonical_parent, &p.nonce_hash, OUTBOX_SUBMITTING)
            .unwrap();

        // "Restart": the sweep sees the stranded row.
        let recovered = unsettled_sender_outbox().unwrap();
        assert_eq!(
            recovered.len(),
            1,
            "a crash at `submitting` must be recoverable"
        );
        assert_eq!(recovered[0].status, OUTBOX_SUBMITTING);
        assert!(
            get_sender_outbox(&rel, &p.canonical_parent, &p.nonce_hash)
                .unwrap()
                .is_some(),
            "existence forbids rollback — status alone can be stranded by the crash"
        );
    }

    /// HARDENING (owner review): the row must carry the FINAL wire bytes, not a
    /// recipe for rebuilding them. A resubmit replays these verbatim, so retry
    /// identity cannot drift if envelope construction changes in a later build.
    #[test]
    #[serial]
    fn stored_bytes_are_replayed_verbatim_never_rebuilt() {
        init_test_db();
        let rel = [0xD1u8; 32];
        let cp = [0xD2u8; 32];
        let (pp, pt) = ([0xD3u8; 32], [0xD4u8; 32]);
        seed_contact(cp, pp);
        let p = proposal_for(rel, cp, [0xD5u8; 32], [0xD6u8; 32], pp, pt);

        // Stand in for a real canonical Envelope encoding.
        let final_wire_bytes: Vec<u8> = (0u8..=255).cycle().take(1024).collect();
        let mut ob = outbox_for(&p, None, true);
        ob.envelope_bytes = final_wire_bytes.clone();

        commit_send_prerequisites_atomically(
            &p,
            &ob,
            "MSGID-VERBATIM",
            &[0xF1u8; 64],
            &[0xF2u8; 64],
            &[0x42u8; 32],
            true,
            &[],
        )
        .unwrap();

        set_sender_outbox_status(
            &rel,
            &p.canonical_parent,
            &p.nonce_hash,
            OUTBOX_SUBMISSION_UNCERTAIN,
        )
        .unwrap();

        let pending = unsettled_sender_outbox().unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(
            pending[0].envelope_bytes, final_wire_bytes,
            "the resubmit sweep must replay the exact stored wire bytes"
        );
        assert_eq!(
            pending[0].routing_address, ob.routing_address,
            "and the exact route they were addressed to"
        );
        assert_eq!(
            pending[0].submission_id,
            derive_submission_id(&p.commitment),
            "under the same deterministic id, so the node dedupes the retry"
        );
    }
}
