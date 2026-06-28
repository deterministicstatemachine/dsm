//! The receiver acceptance predicate (§22, Def. 25). An honest receiver accepts
//! a boot-fenced fused root advance only if all twenty-two checks hold.
//!
//! anchor-core performs the cryptographic recomputations and the counter
//! arithmetic itself (transition digest, root-advance message, partition
//! commitment, witness input, `P_hw`, witness message + StepVerify, partition
//! final-cert message, next fused anchor head). The checks that need
//! receiver/DSM knowledge are supplied as traits:
//!   - [`DsmVerifier`] — DSM SMT state commitments + transition proof + boot chain
//!     + partition certificate (the receiver holds the pinned partition pubkey).
//!   - [`CounterVerifier`] — the receiver's own authenticated TROPIC01 counter read.
//!
//! The receiver never trusts an RP2350 statement, a host `*_claim` field, or a
//! Pico-reported counter (§23).

use crate::boot::BootTicket;
use crate::root_advance::{
    next_anchor_head, partition_commit, partition_final_cert_message, pk_hash,
    root_advance_message, transition_digest, tropic_transfer_input, tropic_witness_message,
    CounterEvidence, OfflineRelease, Transition,
};
use crate::tropic::WitnessSig;
use crate::util::ct_eq_32;

/// DSM-state + partition verifier the receiver supplies (checks 3, 4, 13, 14, 15, 21).
pub trait DsmVerifier {
    /// (3) The previous DSM root commits to `(B, Aᵢ, J_b, uᵢ)`.
    fn prev_root_commits_anchor_state(
        &self,
        prev_root: &[u8; 32],
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
    fn next_root_commits_anchor_state(
        &self,
        next_root: &[u8; 32],
        bundle: &[u8; 32],
        next_anchor_head: &[u8; 32],
        boot_head: &[u8; 32],
        next_anchor_counter: u64,
    ) -> bool;
}

/// The counter-evidence verifier the receiver supplies (checks 17–19). Returns the
/// live TROPIC01 counter value the receiver itself read over an authenticated L3
/// verifier-pairing-slot session — derived from `ev.verifier_transcript`, NOT from
/// the host-supplied `ev.live_counter_claim`. `None` if absent/inauthentic.
pub trait CounterVerifier {
    fn read_authentic_counter(&self, anchor_id: &[u8; 32], ev: &CounterEvidence) -> Option<u64>;
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
    /// (17–19) Counter evidence inauthentic or not `H₀ − (uᵢ+1)`.
    CounterEvidenceInvalid,
    /// (20) `Aᵢ₊₁` does not recompute from the fused-anchor-head formula.
    NextAnchorHeadMismatch,
    /// (21) Next DSM state does not commit to `(B, Aᵢ₊₁, J_{b'}, uᵢ+1)`.
    NextStateUncommitted,
    /// (22) Anchor invalidated by a firmware/physical/policy event.
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

    // (3) Previous DSM state commits to (B, Aᵢ, J_b, uᵢ).
    if !dsm.prev_root_commits_anchor_state(
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

    // (17–19) Authenticated counter evidence proves H₀ − (uᵢ+1).
    let expects_live = ctx
        .enrolled_counter
        .checked_sub(t.next_anchor_counter)
        .ok_or(AcceptError::CounterEvidenceInvalid)?;
    let attested = counter
        .read_authentic_counter(ctx.pinned_anchor_id, ev)
        .ok_or(AcceptError::CounterEvidenceInvalid)?;
    if !ct_eq_32(&ev.anchor_id, ctx.pinned_anchor_id) || attested != expects_live {
        return Err(AcceptError::CounterEvidenceInvalid);
    }

    // (20) A_{i+1} recomputes from the fused-anchor-head formula (using H_attested).
    let a_next = next_anchor_head(
        &cert.anchor_bundle,
        &cert.prev_anchor_head,
        &cert.current_boot_head,
        &m,
        &c_p,
        &cert.sigma_partition,
        &p_hw,
        &cert.sigma_tropic,
        attested,
    );
    if !ct_eq_32(&a_next, &cert.next_anchor_head) {
        return Err(AcceptError::NextAnchorHeadMismatch);
    }

    // (21) Next DSM state commits to (B, Aᵢ₊₁, J_{b'}, uᵢ+1).
    if !dsm.next_root_commits_anchor_state(
        &cert.next_root,
        &cert.anchor_bundle,
        &cert.next_anchor_head,
        &cert.current_boot_head,
        t.next_anchor_counter,
    ) {
        return Err(AcceptError::NextStateUncommitted);
    }

    // (22) No firmware-boundary / physical-compromise / policy event.
    if !ctx.anchor_uncompromised {
        return Err(AcceptError::AnchorCompromised);
    }

    Ok(())
}
