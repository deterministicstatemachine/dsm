//! The receiver acceptance predicate (§22, Def. 30). An honest receiver accepts
//! a boot-fenced fused root advance only if all twenty-four checks hold.
//!
//! anchor-core performs the cryptographic recomputations and the counter
//! arithmetic itself (transition digest, root-advance message, partition
//! commitment, witness input, `P_hw`, witness message + StepVerify, partition
//! final-cert message, next fused anchor head). The checks that need
//! receiver/DSM knowledge are supplied as traits:
//!   - [`DsmVerifier`] — DSM SMT state commitments + transition proof + boot chain
//!     + partition certificate (the receiver holds the pinned partition pubkey).
//!   - [`CounterVerifier`] — the receiver's own authenticated TROPIC01 counter reads
//!     at the FROM coordinate (pre-commit, `H₀ − uᵢ`) and the TO coordinate
//!     (post-commit, `H₀ − (uᵢ+1)`). A post-only scalar is not sufficient (§4).
//!
//! The receiver never trusts an RP2350 statement, a host `*_claim` field, or a
//! Pico-reported counter (§23).

use crate::boot::BootTicket;
use crate::root_advance::{
    next_anchor_head, partition_commit, partition_final_cert_message, pk_hash,
    root_advance_message, transition_digest, tropic_transfer_input, tropic_witness_message,
    CounterAdvanceBinding, CounterAdvanceEvidence, CounterAdvanceReads, CounterEvidenceError,
    OfflineRelease, Transition,
};
use crate::tropic::WitnessSig;
use crate::util::ct_eq_32;

/// DSM-state + partition verifier the receiver supplies (checks 3, 4, 13, 14, 15, 21).
pub trait DsmVerifier {
    /// (3) The sender **device** SMT root before the transfer (`R_i`) commits the anchor
    /// state `(B, Aᵢ, J_b, uᵢ)`. `appliance_root` is the appliance frontier `hᵢ` the
    /// release binds that committed state to — passed for context; the receiver checks
    /// its own pinned `R_i` (never treats the appliance root as the device SMT root).
    fn sender_device_root_before_commits_anchor_state(
        &self,
        appliance_root: &[u8; 32],
        bundle: &[u8; 32],
        anchor_head: &[u8; 32],
        boot_head: &[u8; 32],
        anchor_counter: u64,
    ) -> bool;

    /// (4) The boot ticket/chain verifies the boot head advance `J_b → J_{b'}`
    /// under the pinned partition pubkey, chained from the committed boot head.
    fn verify_boot_chain(
        &self,
        bundle: &[u8; 32],
        anchor_head: &[u8; 32],
        committed_boot_head: &[u8; 32],
        current_boot_head: &[u8; 32],
        boot_chain: &[BootTicket],
    ) -> bool;

    /// (13) The partition final certificate verifies: `PartVerify(pinned_pk, M^P, σ^P)`.
    fn verify_partition_certificate(&self, m_p: &[u8; 32], sigma_partition: &[u8]) -> bool;

    /// (14) The DSM transition proof verifies `prev_root → next_root`.
    fn verify_transition(&self, t: &Transition) -> bool;

    /// (15) The transfer delivers the claimed object/value to this receiver.
    fn delivers_to_receiver(&self, t: &Transition) -> bool;

    /// (21) The next DSM root commits to `(B, Aᵢ₊₁, J_{b'}, uᵢ+1)`.
    fn sender_device_root_after_commits_anchor_state(
        &self,
        appliance_root: &[u8; 32],
        bundle: &[u8; 32],
        next_anchor_head: &[u8; 32],
        boot_head: &[u8; 32],
        next_anchor_counter: u64,
    ) -> bool;
}

/// The counter-evidence verifier the receiver supplies (checks 17–21). Verifies the
/// transition binding of both reads and returns the two live TROPIC01 counter values
/// `H` the receiver itself read over an authenticated L3 verifier-pairing-slot session
/// — derived from `verifier_transcript`, NOT from the host-supplied
/// `attested_raw_counter`. The two reads are the FROM (pre-commit) and TO (post-commit)
/// ends of one physical advance; a post-only read cannot witness that the sender began
/// at the FROM coordinate `uᵢ` (Remark 22). It must NOT return a bare scalar: both
/// authenticated readings are returned so the predicate can position each against
/// `H₀ − uᵢ` / `H₀ − (uᵢ+1)`.
pub trait CounterVerifier {
    /// Verify `evidence` is bound to this exact transition (the receiver recomputed
    /// `binding` from the accepted transition) and return both authenticated raw reads.
    /// Rejects a wrong anchor id, a wrong/absent binding, a pre/post binding mismatch, a
    /// missing read, or a host scalar with no valid transcript.
    fn verify_counter_advance(
        &self,
        pinned_anchor_id: &[u8; 32],
        evidence: &CounterAdvanceEvidence,
        binding: &CounterAdvanceBinding,
    ) -> Result<CounterAdvanceReads, CounterEvidenceError>;
}

/// Receiver-side context: the values this receiver pinned/supplied, plus the
/// policy gates (checks 2, 6, 16, 22, 23).
pub struct VerifierContext<'a> {
    /// (2) The previous root this receiver accepts for the received object.
    pub accepted_prev_root: &'a [u8; 32],
    /// The enrolled anchor bundle `B` this receiver pinned.
    pub pinned_bundle: &'a [u8; 32],
    /// The enrolled TROPIC01 anchor identity this receiver pinned.
    pub pinned_anchor_id: &'a [u8; 32],
    /// (6) The receiver challenge `r_R` this receiver supplied.
    pub expected_receiver_challenge: &'a [u8; 32],
    /// (16) The authority policy hash bound to the previous state.
    pub expected_policy_hash: &'a [u8; 32],
    /// Enrolled counter `H₀` for the pinned anchor.
    pub enrolled_counter: u64,
    /// The sender **device** SMT root before the transfer (`R_i`) the receiver verified
    /// (from its accepted `rel_proof_parent`) — bound into the counter-advance binding so
    /// the counter movement is tied to the exact device-committed state, never the
    /// appliance frontier alone.
    pub sender_device_root_before: &'a [u8; 32],
    /// The sender **device** SMT root after the transfer (`R_{i+1}`) the receiver verified
    /// (from its accepted `rel_proof_child`) — bound into the counter-advance binding.
    pub sender_device_root_after: &'a [u8; 32],
    /// (22) `true` iff no firmware-boundary / physical-compromise / policy event
    /// invalidates the anchor.
    pub anchor_uncompromised: bool,
}

/// Which Def. 25 check failed.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AcceptError {
    /// (1) Δ / Cert / bundle / anchor disagree.
    NonCanonical,
    /// (2) Previous root is not the receiver's accepted root.
    PrevRootNotAccepted,
    /// (3) Previous DSM state does not commit to `(B, Aᵢ, J_b, uᵢ)`.
    PrevStateUncommitted,
    /// (4) The boot ticket/chain does not verify `J_b → J_{b'}`.
    BootChainInvalid,
    /// (5) `next_anchor_counter != anchor_counter + 1`.
    BadNextAnchorCounter,
    /// (6) Receiver challenge mismatch.
    ChallengeMismatch,
    /// (7) `D` does not recompute from Δ.
    DigestMismatch,
    /// (8) `M` does not recompute from the bound fields.
    MessageMismatch,
    /// (9) `C^P` does not recompute.
    PartitionCommitMismatch,
    /// (10) `X^T` does not recompute.
    WitnessInputMismatch,
    /// (11) `P_hw != H(tag ‖ pk_hw)`.
    PkHashMismatch,
    /// (12) `StepVerify(pk_hw, M^T, σ^T) = 0`.
    WitnessSigInvalid,
    /// (13) `PartVerify(pinned_pk, M^P, σ^P) = 0`.
    PartitionCertInvalid,
    /// (14) DSM transition proof invalid.
    TransitionProofInvalid,
    /// (15) Transfer not delivered to this receiver.
    NotDeliveredToReceiver,
    /// (16) Authority policy hash mismatch.
    PolicyMismatch,
    /// (17) A counter read is absent, inauthentic, or a host scalar with no valid
    /// verifier transcript; or `H₀ − uᵢ` / `H₀ − (uᵢ+1)` underflows the enrolled counter.
    CounterEvidenceInvalid,
    /// (18) Pre-commit counter read is not `H₀ − uᵢ` (the FROM coordinate). A second
    /// successor of the same counter-positioned sender state fails here on sight: the
    /// live counter has already left `uᵢ`.
    CounterFromCoordinateInvalid,
    /// (19) Post-commit counter read is not `H₀ − (uᵢ+1)` (the TO coordinate).
    CounterToCoordinateInvalid,
    /// (20) A read's `anchor_id`/`binding_hash` does not match the binding the receiver
    /// recomputed from the accepted transition (`anchor_id, r_R, D, M, R_i, R_{i+1}, hᵢ,
    /// hᵢ₊₁, uᵢ, uᵢ+1`) — a stale or foreign read cannot be spliced in.
    CounterBindingInvalid,
    /// (21) The pre and post reads carry different bindings — not one physical advance.
    CounterPrePostMismatch,
    /// (22) `Aᵢ₊₁` does not recompute from the fused-anchor-head formula.
    NextAnchorHeadMismatch,
    /// (23) Next DSM state does not commit to `(B, Aᵢ₊₁, J_{b'}, uᵢ+1)`.
    NextStateUncommitted,
    /// (24) Anchor invalidated by a firmware/physical/policy event.
    AnchorCompromised,
}

/// `Accept_off(Pkg) = 1` iff every Def. 25 check holds. Returns the first failing
/// check as an [`AcceptError`].
pub fn accept_offline<S, D, C>(
    rel: &OfflineRelease,
    ctx: &VerifierContext,
    dsm: &D,
    counter: &C,
) -> Result<(), AcceptError>
where
    S: WitnessSig,
    D: DsmVerifier,
    C: CounterVerifier,
{
    let t = rel.transition.as_transition();
    let cert = &rel.cert;
    let ev = &rel.counter;

    // (1) Δ, Cert, bundle, and anchor must describe the same advance.
    if !ct_eq_32(&cert.prev_root, t.prev_root)
        || !ct_eq_32(&cert.next_root, t.next_root)
        || cert.anchor_counter != t.anchor_counter
        || cert.next_anchor_counter != t.next_anchor_counter
        || !ct_eq_32(&cert.anchor_bundle, ctx.pinned_bundle)
        || !ct_eq_32(&cert.anchor_id, ctx.pinned_anchor_id)
    {
        return Err(AcceptError::NonCanonical);
    }

    // (2) Previous root is the receiver's accepted root.
    if !ct_eq_32(t.prev_root, ctx.accepted_prev_root) {
        return Err(AcceptError::PrevRootNotAccepted);
    }

    // (3) The sender device root before the transfer (Rᵢ) commits (B, Aᵢ, J_b, uᵢ);
    // `t.prev_root` is the appliance frontier hᵢ passed for context.
    if !dsm.sender_device_root_before_commits_anchor_state(
        t.prev_root,
        &cert.anchor_bundle,
        &cert.prev_anchor_head,
        &cert.prev_boot_head,
        t.anchor_counter,
    ) {
        return Err(AcceptError::PrevStateUncommitted);
    }

    // (4) Boot chain verifies J_b → J_{b'}.
    if !dsm.verify_boot_chain(
        &cert.anchor_bundle,
        &cert.prev_anchor_head,
        &cert.prev_boot_head,
        &cert.current_boot_head,
        &rel.boot_chain,
    ) {
        return Err(AcceptError::BootChainInvalid);
    }

    // (5) next anchor counter = uᵢ + 1 (checked).
    if t.anchor_counter.checked_add(1) != Some(t.next_anchor_counter) {
        return Err(AcceptError::BadNextAnchorCounter);
    }

    // (6) Receiver challenge matches.
    if !ct_eq_32(&cert.receiver_challenge, ctx.expected_receiver_challenge) {
        return Err(AcceptError::ChallengeMismatch);
    }

    // (7) D recomputes from Δ.
    let d = transition_digest(&t);
    if !ct_eq_32(&d, &cert.transition_digest) {
        return Err(AcceptError::DigestMismatch);
    }

    // (8) M recomputes from the bound fields.
    let m = root_advance_message(
        &t,
        &d,
        &cert.anchor_bundle,
        &cert.prev_anchor_head,
        &cert.current_boot_head,
        &cert.receiver_challenge,
    );
    if !ct_eq_32(&m, &cert.root_advance_message) {
        return Err(AcceptError::MessageMismatch);
    }

    // (9) C^P recomputes.
    let c_p = partition_commit(
        &cert.anchor_bundle,
        &cert.prev_anchor_head,
        &cert.current_boot_head,
        &m,
    );
    if !ct_eq_32(&c_p, &cert.partition_commitment) {
        return Err(AcceptError::PartitionCommitMismatch);
    }

    // (10) X^T recomputes.
    let x_t = tropic_transfer_input(
        &cert.anchor_bundle,
        &cert.prev_anchor_head,
        &cert.current_boot_head,
        &m,
        &c_p,
        cert.transfer_slot,
    );
    if !ct_eq_32(&x_t, &cert.tropic_transfer_input) {
        return Err(AcceptError::WitnessInputMismatch);
    }

    // (11) P_hw = H(tag ‖ pk_hw).
    let p_hw = pk_hash(&cert.pk_hw);
    if !ct_eq_32(&p_hw, &cert.pk_hash) {
        return Err(AcceptError::PkHashMismatch);
    }

    // (12) M^T recomputes; StepVerify(pk_hw, M^T, σ^T) = 1.
    let m_t = tropic_witness_message(&m, &c_p, &x_t, &p_hw);
    if !S::verify(&cert.pk_hw, &m_t, &cert.sigma_tropic) {
        return Err(AcceptError::WitnessSigInvalid);
    }

    // (13) M^P recomputes; PartVerify(pinned_pk, M^P, σ^P) = 1.
    let m_p = partition_final_cert_message(
        &cert.anchor_bundle,
        &cert.prev_anchor_head,
        &cert.current_boot_head,
        &m,
        &c_p,
        &p_hw,
        &cert.sigma_tropic,
        cert.next_anchor_counter,
    );
    if !dsm.verify_partition_certificate(&m_p, &cert.sigma_partition) {
        return Err(AcceptError::PartitionCertInvalid);
    }

    // (14) DSM transition proof verifies hᵢ → hᵢ₊₁.
    if !dsm.verify_transition(&t) {
        return Err(AcceptError::TransitionProofInvalid);
    }

    // (15) Delivered to this receiver.
    if !dsm.delivers_to_receiver(&t) {
        return Err(AcceptError::NotDeliveredToReceiver);
    }

    // (16) Authority policy hash matches the previous state.
    if !ct_eq_32(t.authority_policy_hash, ctx.expected_policy_hash) {
        return Err(AcceptError::PolicyMismatch);
    }

    // (17–21) Transition-bound counter advance. The receiver's own authenticated FROM
    // (pre-commit) and TO (post-commit) reads must witness one physical step of the very
    // chip this release is pinned to, bound to THIS transition. The expected binding is
    // recomputed here from the accepted transition (both root pairs: the sender device
    // roots Rᵢ/Rᵢ₊₁ the receiver verified, and the appliance frontier roots hᵢ/hᵢ₊₁), never
    // taken from a host field. `verify_counter_advance` checks the binding + anchor id +
    // pre/post agreement and returns the two authenticated raw reads; the coordinate
    // checks below position them.
    let expected_pre = ctx
        .enrolled_counter
        .checked_sub(t.anchor_counter)
        .ok_or(AcceptError::CounterEvidenceInvalid)?;
    let expected_post = ctx
        .enrolled_counter
        .checked_sub(t.next_anchor_counter)
        .ok_or(AcceptError::CounterEvidenceInvalid)?;
    let binding = CounterAdvanceBinding {
        anchor_id: *ctx.pinned_anchor_id,
        receiver_challenge: cert.receiver_challenge,
        transition_digest: d,
        root_advance_message: m,
        sender_device_root_before: *ctx.sender_device_root_before,
        sender_device_root_after: *ctx.sender_device_root_after,
        appliance_root_before: cert.prev_root,
        appliance_root_after: cert.next_root,
        anchor_counter: t.anchor_counter,
        next_anchor_counter: t.next_anchor_counter,
    };
    let reads = counter
        .verify_counter_advance(ctx.pinned_anchor_id, ev, &binding)
        .map_err(|e| match e {
            CounterEvidenceError::BindingMismatch => AcceptError::CounterBindingInvalid,
            CounterEvidenceError::PrePostMismatch => AcceptError::CounterPrePostMismatch,
            CounterEvidenceError::Inauthentic => AcceptError::CounterEvidenceInvalid,
        })?;

    // (18) FROM coordinate: the discriminating check. A second successor of the same
    // counter-positioned sender state finds the live counter already at `uᵢ+1` and fails
    // here on sight, before reconciliation (§4, Thm 41).
    if reads.pre_raw_counter != expected_pre {
        return Err(AcceptError::CounterFromCoordinateInvalid);
    }
    // (19) TO coordinate: the counter advanced to `uᵢ+1`. Keeping BOTH ends is mandatory
    // (Remark 22): the FROM read alone is post-commit for an honest transfer.
    if reads.post_raw_counter != expected_post {
        return Err(AcceptError::CounterToCoordinateInvalid);
    }
    let h_post = reads.post_raw_counter;

    // (22) A_{i+1} recomputes from the fused-anchor-head formula (using H_post).
    let a_next = next_anchor_head(
        &cert.anchor_bundle,
        &cert.prev_anchor_head,
        &cert.current_boot_head,
        &m,
        &c_p,
        &cert.sigma_partition,
        &p_hw,
        &cert.sigma_tropic,
        h_post,
    );
    if !ct_eq_32(&a_next, &cert.next_anchor_head) {
        return Err(AcceptError::NextAnchorHeadMismatch);
    }

    // (23) The sender device root after the transfer (Rᵢ₊₁) commits (B, Aᵢ₊₁, J_{b'}, uᵢ+1);
    // `cert.next_root` is the appliance frontier hᵢ₊₁ passed for context.
    if !dsm.sender_device_root_after_commits_anchor_state(
        &cert.next_root,
        &cert.anchor_bundle,
        &cert.next_anchor_head,
        &cert.current_boot_head,
        t.next_anchor_counter,
    ) {
        return Err(AcceptError::NextStateUncommitted);
    }

    // (24) No firmware-boundary / physical-compromise / policy event.
    if !ctx.anchor_uncompromised {
        return Err(AcceptError::AnchorCompromised);
    }

    Ok(())
}
