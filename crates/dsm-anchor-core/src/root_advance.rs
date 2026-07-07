//! Fused root-advance objects: the DSM transition package `Δ`, the transition
//! digest `D` (§15), the boot-bound root-advance message `M` (§16), the
//! partition/TROPIC cross-binding chain `C^P → X^T → σ^T → M^P → σ^P` (§17), the
//! next fused anchor head `A_{i+1}` (§18), the certificate (§20), and the on-wire
//! release artifacts.
//!
//! NOTE on reconstruction: several spec equations (`M`, `B`, `X^T`, `K^T`,
//! `A_{i+1}`) run off the page margin. The bound-field sets here are reconstructed
//! from Theorem 30, which states the complete binding: the message, partition
//! commitment, TROPIC input, partition certificate, TROPIC witness, and fused
//! anchor head bind `B, A_i (prev fused head), J_{b'} (current boot head), h_i,
//! h_{i+1}, u_i, u_i+1, D, recipient, object, policy, receiver-challenge`. Two
//! deliberate reconciliations vs. the prose, documented inline: (1) `C^P` omits
//! the `partition_epoch`/`partition_nonce` the §33 wire cert does not carry, so
//! the receiver can recompute it from carried fields; (2) variable-length
//! signatures are bound via `commit(σ) = H(σ)` (fixed-width) inside `M^P`/`A_{i+1}`
//! for unambiguous encoding. As the reference implementation, this canonical
//! encoder is the de-facto definition; producer and verifier use the same functions.

extern crate alloc;
use alloc::vec::Vec;

use crate::boot::BootTicket;
use crate::domain;
use crate::enrollment::commit;
use crate::hash::{h, kdf};
use crate::util::{ct_eq_32, push_var, u16_le, u32_le, u64_le};

/// The canonical DSM transition package `Δᵢ₊₁` (the wire `TransitionPackage`).
/// It carries everything the receiver needs to verify `hᵢ → hᵢ₊₁` and to bind
/// the fused state; the appliance does not verify the SMT proofs itself (§1).
pub struct Transition<'a> {
    pub relationship_id: &'a [u8; 32],
    pub object_id: &'a [u8; 32],
    pub sender_device_id: &'a [u8; 32],
    pub recipient_device_id: &'a [u8; 32],
    /// The DSM SMT root `hᵢ` this advance starts from.
    pub prev_root: &'a [u8; 32],
    /// Proposed successor SMT root `hᵢ₊₁`.
    pub next_root: &'a [u8; 32],
    /// Anchor counter `uᵢ = H₀ − H` — the TROPIC01 down-counter index, a plain
    /// integer committed *as a field inside* `prev_root` (not a tree position).
    pub anchor_counter: u64,
    /// Successor anchor counter `uᵢ+1` committed inside `next_root`.
    pub next_anchor_counter: u64,
    pub action_type: u32,
    pub action_fields: &'a [u8],
    pub payload_hash: &'a [u8; 32],
    /// DSM SMT proof of the spent leaf at `hᵢ`.
    pub old_leaf_proof: &'a [u8],
    /// DSM SMT proof of the produced leaf at `hᵢ₊₁`.
    pub new_leaf_proof: &'a [u8],
    pub authority_policy_hash: &'a [u8; 32],
}

/// Canonical byte encoding `enc(Δ)` (proto field order 1..14). Fixed-width
/// fields raw, integers little-endian, variable-length fields u32-length-prefixed.
pub fn enc_transition(t: &Transition) -> Vec<u8> {
    let mut v = Vec::with_capacity(
        8 * 32 + t.action_fields.len() + t.old_leaf_proof.len() + t.new_leaf_proof.len() + 32,
    );
    v.extend_from_slice(t.relationship_id);
    v.extend_from_slice(t.object_id);
    v.extend_from_slice(t.sender_device_id);
    v.extend_from_slice(t.recipient_device_id);
    v.extend_from_slice(t.prev_root);
    v.extend_from_slice(t.next_root);
    v.extend_from_slice(&u64_le(t.anchor_counter));
    v.extend_from_slice(&u64_le(t.next_anchor_counter));
    v.extend_from_slice(&u32_le(t.action_type));
    push_var(&mut v, t.action_fields);
    v.extend_from_slice(t.payload_hash);
    push_var(&mut v, t.old_leaf_proof);
    push_var(&mut v, t.new_leaf_proof);
    v.extend_from_slice(t.authority_policy_hash);
    v
}

/// Transition digest `D = H("DSM/root-advance/transition-digest/v1" ‖ enc(Δ))`.
pub fn transition_digest(t: &Transition) -> [u8; 32] {
    h(domain::TRANSITION_DIGEST_V1, &[&enc_transition(t)])
}

/// Boot-bound root advance message `M` (§16). Bound by both the partition
/// certificate and the TROPIC witness.
#[allow(clippy::too_many_arguments)]
pub fn root_advance_message(
    t: &Transition,
    d: &[u8; 32],
    bundle: &[u8; 32],
    anchor_head: &[u8; 32],
    current_boot_head: &[u8; 32],
    receiver_challenge: &[u8; 32],
) -> [u8; 32] {
    h(
        domain::FUSED_ROOT_ADVANCE_MESSAGE_V1,
        &[
            bundle,
            anchor_head,
            current_boot_head,
            t.prev_root,
            t.next_root,
            &u64_le(t.anchor_counter),
            &u64_le(t.next_anchor_counter),
            d,
            t.recipient_device_id,
            t.object_id,
            t.authority_policy_hash,
            receiver_challenge,
        ],
    )
}

/// Partition commitment `C^P = H(tag ‖ B ‖ Aᵢ ‖ J_{b'} ‖ M)` (§17). Reconciliation:
/// the §33 wire cert carries no `partition_epoch`/`partition_nonce`, so the
/// reference binds without them and the receiver recomputes `C^P` from cert fields.
pub fn partition_commit(
    bundle: &[u8; 32],
    anchor_head: &[u8; 32],
    current_boot_head: &[u8; 32],
    m: &[u8; 32],
) -> [u8; 32] {
    h(
        domain::PARTITION_COMMIT_V1,
        &[bundle, anchor_head, current_boot_head, m],
    )
}

/// TROPIC01 transfer witness input `X^T` (§17) — binds the partition commitment
/// and the transfer slot.
pub fn tropic_transfer_input(
    bundle: &[u8; 32],
    anchor_head: &[u8; 32],
    current_boot_head: &[u8; 32],
    m: &[u8; 32],
    partition_commitment: &[u8; 32],
    q_tx: u16,
) -> [u8; 32] {
    h(
        domain::TROPIC_FUSED_TRANSFER_INPUT_V1,
        &[
            bundle,
            anchor_head,
            current_boot_head,
            m,
            partition_commitment,
            &u16_le(q_tx),
        ],
    )
}

/// TROPIC01 transfer witness signing seed `K^T = HKDF(W^T, tag ‖ …)` (§17),
/// keyed by the MACANDD output. Producer-only (never recomputed by the receiver).
#[allow(clippy::too_many_arguments)]
pub fn transfer_witness_key(
    w_t: &[u8; 32],
    x_t: &[u8; 32],
    m: &[u8; 32],
    bundle: &[u8; 32],
    anchor_head: &[u8; 32],
    current_boot_head: &[u8; 32],
    anchor_id: &[u8; 32],
    q_tx: u16,
) -> [u8; 32] {
    kdf(
        w_t,
        domain::TROPIC_FUSED_TRANSFER_WITNESS_KEY_V1,
        &[
            x_t,
            m,
            bundle,
            anchor_head,
            current_boot_head,
            anchor_id,
            &u16_le(q_tx),
        ],
    )
}

/// Committed public-witness-key handle `P_hw = H("DSM/tropic/pk-hash/v1" ‖ pk_hw)`.
pub fn pk_hash(pk_hw: &[u8]) -> [u8; 32] {
    h(domain::PK_HASH_V1, &[pk_hw])
}

/// TROPIC01 transfer witness message `M^T = H(tag ‖ M ‖ C^P ‖ X^T ‖ P_hw)` (§17)
/// — the digest StepSign covers.
pub fn tropic_witness_message(
    m: &[u8; 32],
    partition_commitment: &[u8; 32],
    x_t: &[u8; 32],
    p_hw: &[u8; 32],
) -> [u8; 32] {
    h(
        domain::TROPIC_FUSED_TRANSFER_WITNESS_MESSAGE_V1,
        &[m, partition_commitment, x_t, p_hw],
    )
}

/// Partition final certificate message `M^P` (§17) — binds the TROPIC witness back
/// into the partition lineage. `σ^T` is bound via `commit(σ^T)` (fixed-width).
#[allow(clippy::too_many_arguments)]
pub fn partition_final_cert_message(
    bundle: &[u8; 32],
    anchor_head: &[u8; 32],
    current_boot_head: &[u8; 32],
    m: &[u8; 32],
    partition_commitment: &[u8; 32],
    p_hw: &[u8; 32],
    sigma_tropic: &[u8],
    next_anchor_counter: u64,
) -> [u8; 32] {
    h(
        domain::PARTITION_FINAL_CERT_V1,
        &[
            bundle,
            anchor_head,
            current_boot_head,
            m,
            partition_commitment,
            p_hw,
            &commit(sigma_tropic),
            &u64_le(next_anchor_counter),
        ],
    )
}

/// Next fused anchor head `A_{i+1}` (§18). Variable-length signatures are bound via
/// `commit(σ)`; `attested_counter = H₀ − (uᵢ+1)` is the post-commit counter value
/// (the producer's reading equals the receiver's authenticated read).
#[allow(clippy::too_many_arguments)]
pub fn next_anchor_head(
    bundle: &[u8; 32],
    anchor_head: &[u8; 32],
    current_boot_head: &[u8; 32],
    m: &[u8; 32],
    partition_commitment: &[u8; 32],
    sigma_partition: &[u8],
    p_hw: &[u8; 32],
    sigma_tropic: &[u8],
    attested_counter: u64,
) -> [u8; 32] {
    h(
        domain::FUSED_ANCHOR_HEAD_V1,
        &[
            bundle,
            anchor_head,
            current_boot_head,
            m,
            partition_commitment,
            &commit(sigma_partition),
            p_hw,
            &commit(sigma_tropic),
            &u64_le(attested_counter),
        ],
    )
}

/// An owned copy of a [`Transition`], stored in the live record and carried in the
/// release so the certificate can be reconstructed without the borrow.
#[derive(Clone)]
pub struct OwnedTransition {
    pub relationship_id: [u8; 32],
    pub object_id: [u8; 32],
    pub sender_device_id: [u8; 32],
    pub recipient_device_id: [u8; 32],
    pub prev_root: [u8; 32],
    pub next_root: [u8; 32],
    pub anchor_counter: u64,
    pub next_anchor_counter: u64,
    pub action_type: u32,
    pub action_fields: Vec<u8>,
    pub payload_hash: [u8; 32],
    pub old_leaf_proof: Vec<u8>,
    pub new_leaf_proof: Vec<u8>,
    pub authority_policy_hash: [u8; 32],
}

impl OwnedTransition {
    pub fn from(t: &Transition) -> Self {
        Self {
            relationship_id: *t.relationship_id,
            object_id: *t.object_id,
            sender_device_id: *t.sender_device_id,
            recipient_device_id: *t.recipient_device_id,
            prev_root: *t.prev_root,
            next_root: *t.next_root,
            anchor_counter: t.anchor_counter,
            next_anchor_counter: t.next_anchor_counter,
            action_type: t.action_type,
            action_fields: t.action_fields.to_vec(),
            payload_hash: *t.payload_hash,
            old_leaf_proof: t.old_leaf_proof.to_vec(),
            new_leaf_proof: t.new_leaf_proof.to_vec(),
            authority_policy_hash: *t.authority_policy_hash,
        }
    }

    pub fn as_transition(&self) -> Transition<'_> {
        Transition {
            relationship_id: &self.relationship_id,
            object_id: &self.object_id,
            sender_device_id: &self.sender_device_id,
            recipient_device_id: &self.recipient_device_id,
            prev_root: &self.prev_root,
            next_root: &self.next_root,
            anchor_counter: self.anchor_counter,
            next_anchor_counter: self.next_anchor_counter,
            action_type: self.action_type,
            action_fields: &self.action_fields,
            payload_hash: &self.payload_hash,
            old_leaf_proof: &self.old_leaf_proof,
            new_leaf_proof: &self.new_leaf_proof,
            authority_policy_hash: &self.authority_policy_hash,
        }
    }
}

/// The fused root advance certificate `Cert` (§20 / wire `RootAdvanceCertificate`).
#[derive(Clone)]
pub struct Certificate {
    pub anchor_bundle: [u8; 32],
    pub prev_anchor_head: [u8; 32],
    pub next_anchor_head: [u8; 32],
    pub prev_boot_head: [u8; 32],
    pub current_boot_head: [u8; 32],
    pub prev_root: [u8; 32],
    pub next_root: [u8; 32],
    pub anchor_counter: u64,
    pub next_anchor_counter: u64,
    pub transition_digest: [u8; 32],
    pub root_advance_message: [u8; 32],
    pub partition_commitment: [u8; 32],
    pub tropic_transfer_input: [u8; 32],
    pub pk_hash: [u8; 32],
    pub pk_hw: Vec<u8>,
    pub sigma_tropic: Vec<u8>,
    pub sigma_partition: Vec<u8>,
    pub anchor_id: [u8; 32],
    pub transfer_slot: u16,
    pub receiver_challenge: [u8; 32],
}

/// One receiver-side authenticated TROPIC01 counter read, pinned to exactly one
/// transition by its `binding_hash` (§13 / wire `CounterReadEvidence`). The receiver
/// obtains the authoritative live counter value `H` from the chip over its own
/// authenticated verifier-pairing-slot session, proven by `verifier_transcript`; the
/// acceptance predicate takes the trusted value from [`crate::accept::CounterVerifier`],
/// NOT from `attested_raw_counter` (an untrusted transport convenience, §33).
/// `binding_hash` equals the [`CounterAdvanceBinding`] the receiver recomputes from the
/// accepted transition, so a stale or foreign read (from another session or transition)
/// cannot be spliced into this one — no per-read transition fields are carried or trusted.
#[derive(Clone)]
pub struct CounterReadEvidence {
    pub anchor_id: [u8; 32],
    /// Untrusted host claim of the live counter `H` for this read; proof comes from
    /// `verifier_transcript` + the predicate's authenticated read, not this field.
    pub attested_raw_counter: u64,
    pub verifier_transcript: Vec<u8>,
    /// The transition-bound counter-advance binding this read is pinned to; must equal
    /// the [`CounterAdvanceBinding`] the receiver recomputes from the accepted transition.
    pub binding_hash: [u8; 32],
}

/// The expected transition-bound counter-advance binding, recomputed by the receiver
/// from the ACCEPTED transition — never taken from a host-supplied field (§13). Its
/// [`hash`](CounterAdvanceBinding::hash) is the value every [`CounterReadEvidence`] and the
/// [`CounterAdvanceEvidence`] envelope must carry. It binds BOTH root pairs — the sender
/// **device** SMT roots `R_i`/`R_{i+1}` (which commit the anchor state `(B, Aᵢ, J_b, uᵢ)`
/// / `(B, A_{i+1}, J_{b'}, uᵢ+1)`) AND the appliance frontier roots `hᵢ`/`hᵢ₊₁` (which the
/// release binds that committed state to) — so the two are never conflated and the counter
/// coordinate is pinned to a globally unique root position.
#[derive(Clone)]
pub struct CounterAdvanceBinding {
    pub anchor_id: [u8; 32],
    pub receiver_challenge: [u8; 32],
    pub transition_digest: [u8; 32],
    pub root_advance_message: [u8; 32],
    pub sender_device_root_before: [u8; 32],
    pub sender_device_root_after: [u8; 32],
    pub appliance_root_before: [u8; 32],
    pub appliance_root_after: [u8; 32],
    pub anchor_counter: u64,
    pub next_anchor_counter: u64,
}

impl CounterAdvanceBinding {
    /// The canonical binding hash — the production TBCA vehicle
    /// ([`crate::tbca::tbca_message`]), so a `CounterAdvanceEvidence` and a TBCA fraud
    /// proof share one canonical encoding.
    pub fn hash(&self) -> [u8; 32] {
        crate::tbca::tbca_message(
            &self.anchor_id,
            &self.receiver_challenge,
            &self.transition_digest,
            &self.root_advance_message,
            &self.sender_device_root_before,
            &self.sender_device_root_after,
            &self.appliance_root_before,
            &self.appliance_root_after,
            self.anchor_counter,
            self.next_anchor_counter,
        )
    }
}

/// The two authenticated raw counter values a
/// [`CounterVerifier`](crate::accept::CounterVerifier) returns for one advance: the FROM
/// read (`H_pre`, pre-commit) and the TO read (`H_post`, post-commit). The predicate
/// checks `H_pre == H₀ − uᵢ` (FROM coordinate) and `H_post == H₀ − (uᵢ+1)` (TO coordinate).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct CounterAdvanceReads {
    pub pre_raw_counter: u64,
    pub post_raw_counter: u64,
}

/// Why a [`CounterAdvanceEvidence`] failed its transition binding, returned by
/// [`CounterVerifier::verify_counter_advance`](crate::accept::CounterVerifier).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CounterEvidenceError {
    /// A per-read/envelope `binding_hash`, or a read's `anchor_id`, does not match the
    /// binding the receiver recomputed from the accepted transition.
    BindingMismatch,
    /// The pre and post reads carry different `binding_hash` values — not one advance.
    PrePostMismatch,
    /// A read is absent, inauthentic, or a host scalar with no valid `verifier_transcript`.
    Inauthentic,
}

/// Transition-bound counter-advance evidence (§13 / wire `CounterAdvanceEvidence`).
/// A single physical advance witnessed at both ends: `pre` at the FROM coordinate
/// (`H_pre = H₀ − uᵢ`) before the commit, `post` at the TO coordinate
/// (`H_post = H₀ − (uᵢ+1)`) after it. All three `binding_hash` fields must equal the
/// [`CounterAdvanceBinding`] the receiver recomputes. A post-only scalar is not accepted
/// (§4, §33): it cannot witness that the sender began at `uᵢ`.
#[derive(Clone)]
pub struct CounterAdvanceEvidence {
    pub pre: CounterReadEvidence,
    pub post: CounterReadEvidence,
    pub binding_hash: [u8; 32],
}

impl CounterAdvanceEvidence {
    /// The pure binding check a receiver's
    /// [`CounterVerifier`](crate::accept::CounterVerifier) runs before returning
    /// authenticated reads: the pre/post bindings agree, both reads and the envelope
    /// carry the expected binding, and both reads name the pinned anchor. `binding` is
    /// recomputed from the accepted transition — never a carried field.
    pub fn check_binding(
        &self,
        pinned_anchor_id: &[u8; 32],
        binding: &CounterAdvanceBinding,
    ) -> Result<(), CounterEvidenceError> {
        // pre and post must witness the SAME advance.
        if !ct_eq_32(&self.pre.binding_hash, &self.post.binding_hash) {
            return Err(CounterEvidenceError::PrePostMismatch);
        }
        let expected = binding.hash();
        if !ct_eq_32(&self.pre.binding_hash, &expected)
            || !ct_eq_32(&self.post.binding_hash, &expected)
            || !ct_eq_32(&self.binding_hash, &expected)
        {
            return Err(CounterEvidenceError::BindingMismatch);
        }
        if !ct_eq_32(&self.pre.anchor_id, pinned_anchor_id)
            || !ct_eq_32(&self.post.anchor_id, pinned_anchor_id)
        {
            return Err(CounterEvidenceError::BindingMismatch);
        }
        Ok(())
    }
}

/// The exported release package `Pkg = (Δ, BootChain, Cert, counter-advance-evidence)`
/// (§20/§32). The producer fills the transition-binding fields of `counter`; the
/// receiver attaches its own authenticated pre/post reads before acceptance.
#[derive(Clone)]
pub struct OfflineRelease {
    pub transition: OwnedTransition,
    pub boot_chain: Vec<BootTicket>,
    pub cert: Certificate,
    pub counter: CounterAdvanceEvidence,
}
