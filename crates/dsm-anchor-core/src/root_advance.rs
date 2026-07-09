//! v2 root-advance objects (Software Authority, Hardware Identity): the transition
//! core `Δ°`, the transition digest `D_{i+1}` (§10), the forward-only offline frontier
//! root advance `h_{i+1}` (§8), the anchor-state leaf `L_i` (§8), the root-advance
//! message `M_{i+1}` (§10), and the on-wire release artifacts.
//!
//! Transfer uniqueness is a software property of the DSM device SMT: one parent root
//! `R_i` admits exactly one accepted successor per receiver (forward-only frontier);
//! cross-receiver forks are Tripwire-exposed on reconciliation. The release binds
//! `M_{i+1}` under three independent signatures — `σ^DSM` (seed-derived DSM device
//! signature over `Δ°`), `σ^chip` (a resident non-exportable Ed25519 key in TROPIC01),
//! `σ^host` (RP2350 partition). No hardware counter read is on the acceptance path; the
//! counter appears only as the signed pair `(u_i, u_i+1)`.
//!
//! The dependency chain is a clean DAG with no fixed point: the transition core `Δ°`
//! deliberately excludes the successor root, so `D_{i+1} → h_{i+1} → L_{i+1} → R_{i+1}
//! → M_{i+1} → σ^chip, σ^host` never closes a cycle.

extern crate alloc;
use alloc::vec::Vec;

use crate::domain;
use crate::hash::h;
use crate::util::{push_var, u32_le, u64_le};

/// The canonical DSM transition package `Δ` (the wire `TransitionPackage`). It carries
/// everything the receiver needs to verify `h_i → h_{i+1}` and to bind the state; the
/// appliance does not verify the SMT proofs itself (the receiver's `DsmVerifier` does).
pub struct Transition<'a> {
    pub relationship_id: &'a [u8; 32],
    pub object_id: &'a [u8; 32],
    pub sender_device_id: &'a [u8; 32],
    pub recipient_device_id: &'a [u8; 32],
    /// The DSM offline frontier root `h_i` this advance starts from.
    pub prev_root: &'a [u8; 32],
    /// Proposed successor frontier root `h_{i+1}` (derived: `H(tag ‖ h_i ‖ D_{i+1})`).
    pub next_root: &'a [u8; 32],
    /// Anchor counter `u_i = H₀ − H` — a plain integer committed as a field inside the
    /// anchor-state leaf of `R_i` (not a tree position).
    pub anchor_counter: u64,
    /// Successor anchor counter `u_i+1` committed inside `R_{i+1}`.
    pub next_anchor_counter: u64,
    pub action_type: u32,
    pub action_fields: &'a [u8],
    pub payload_hash: &'a [u8; 32],
    /// DSM SMT proof of the spent leaf at `R_i`.
    pub old_leaf_proof: &'a [u8],
    /// DSM SMT proof of the produced leaf at `R_{i+1}`.
    pub new_leaf_proof: &'a [u8],
    pub authority_policy_hash: &'a [u8; 32],
}

/// Canonical byte encoding `enc(Δ)` (proto field order 1..14). Fixed-width fields raw,
/// integers little-endian, variable-length fields u32-length-prefixed.
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

/// Canonical encoding of the transition **core** `Δ°` (§10): action, recipient, object,
/// payload, the old-state proof from `R_i`, the counter pair `(u_i, u_i+1)`, the receiver
/// challenge `r_R`, and the pre-state identifiers — but **excluding the successor root**
/// (`next_root` and `new_leaf_proof`). Excluding the successor is what makes the digest
/// chain a DAG rather than a fixed point of the successor it seeds.
pub fn enc_transition_core(t: &Transition, receiver_challenge: &[u8; 32]) -> Vec<u8> {
    let mut v = Vec::with_capacity(6 * 32 + t.action_fields.len() + t.old_leaf_proof.len() + 32);
    v.extend_from_slice(t.relationship_id);
    v.extend_from_slice(t.object_id);
    v.extend_from_slice(t.sender_device_id);
    v.extend_from_slice(t.recipient_device_id);
    v.extend_from_slice(t.prev_root); // h_i (pre-state); successor h_{i+1} is NOT bound here
    v.extend_from_slice(&u64_le(t.anchor_counter));
    v.extend_from_slice(&u64_le(t.next_anchor_counter));
    v.extend_from_slice(&u32_le(t.action_type));
    push_var(&mut v, t.action_fields);
    v.extend_from_slice(t.payload_hash);
    push_var(&mut v, t.old_leaf_proof); // R_i-side proof only
    v.extend_from_slice(t.authority_policy_hash);
    v.extend_from_slice(receiver_challenge);
    v
}

/// Transition digest `D_{i+1} = H("DSM/transition-digest/v2" ‖ enc(Δ°))`.
pub fn transition_digest(t: &Transition, receiver_challenge: &[u8; 32]) -> [u8; 32] {
    h(
        domain::TRANSITION_DIGEST_V2,
        &[&enc_transition_core(t, receiver_challenge)],
    )
}

/// Forward-only offline frontier root advance `h_{i+1} = H("DSM/anchor-root-advance/v2"
/// ‖ h_i ‖ D_{i+1})`. Seeded at birth by `h_0`; advanced exactly once per offline transfer.
pub fn anchor_root_advance(prev_frontier: &[u8; 32], d: &[u8; 32]) -> [u8; 32] {
    h(domain::ANCHOR_ROOT_ADVANCE_V2, &[prev_frontier, d])
}

/// Anchor-state leaf `L_i = H("DSM/anchor-state/v2" ‖ B ‖ h_i ‖ le64(u_i))`, committed
/// inside the device SMT root `R_i`. The receiver's SMT inclusion proof `Π_i` proves this.
pub fn anchor_state_leaf(bundle: &[u8; 32], frontier: &[u8; 32], u: u64) -> [u8; 32] {
    h(domain::ANCHOR_STATE_V2, &[bundle, frontier, &u64_le(u)])
}

/// Root-advance message `M_{i+1}` (§10). Binds both device SMT roots `R_i`/`R_{i+1}`, both
/// frontier roots `h_i`/`h_{i+1}`, the counter pair, the digest, the recipient, and the
/// challenge. All three release signatures cover this exact message.
#[allow(clippy::too_many_arguments)]
pub fn root_advance_message(
    bundle: &[u8; 32],
    sender_device_root_before: &[u8; 32],
    sender_device_root_after: &[u8; 32],
    prev_frontier: &[u8; 32],
    next_frontier: &[u8; 32],
    anchor_counter: u64,
    next_anchor_counter: u64,
    d: &[u8; 32],
    recipient: &[u8; 32],
    receiver_challenge: &[u8; 32],
) -> [u8; 32] {
    h(
        domain::ROOT_ADVANCE_MESSAGE_V2,
        &[
            bundle,
            sender_device_root_before,
            sender_device_root_after,
            prev_frontier,
            next_frontier,
            &u64_le(anchor_counter),
            &u64_le(next_anchor_counter),
            d,
            recipient,
            receiver_challenge,
        ],
    )
}

/// An owned copy of a [`Transition`], stored in the live record and carried in the release
/// so the certificate can be reconstructed without the borrow.
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

/// The v2 release certificate `Cert` (§10, Def. 9). Three independent signatures over one
/// `M_{i+1}`. The chip/host public keys are NOT carried here — they are pinned in the anchor
/// bundle `B` at enrollment and supplied to the acceptance predicate from the receiver's pin.
#[derive(Clone)]
pub struct Certificate {
    pub anchor_bundle: [u8; 32],
    /// Sender device SMT root before the transfer, `R_i` (commits `(B, h_i, u_i)`).
    pub sender_device_root_before: [u8; 32],
    /// Sender device SMT root after the transfer, `R_{i+1}` (commits `(B, h_{i+1}, u_i+1)`).
    pub sender_device_root_after: [u8; 32],
    /// Offline frontier root `h_i`.
    pub prev_frontier: [u8; 32],
    /// Offline frontier root `h_{i+1} = H(tag ‖ h_i ‖ D_{i+1})`.
    pub next_frontier: [u8; 32],
    pub anchor_counter: u64,
    pub next_anchor_counter: u64,
    pub transition_digest: [u8; 32],
    pub root_advance_message: [u8; 32],
    pub anchor_id: [u8; 32],
    /// `σ^chip = ChipSign(M_{i+1})` — resident non-exportable Ed25519 key in TROPIC01.
    pub sigma_chip: Vec<u8>,
    /// `σ^host = HostSign(M_{i+1})` — RP2350 partition-sealed key.
    pub sigma_host: Vec<u8>,
    pub receiver_challenge: [u8; 32],
    pub recipient: [u8; 32],
}

/// The exported release package `Pkg = (Δ, Π_i, Π_{i+1}, Cert, BranchProof[optional])`
/// (§10, Def. 9). `anchor_smt_proof_*` are the device-SMT inclusion proofs for the
/// anchor-state leaf in `R_i` / `R_{i+1}`, verified by the receiver's `DsmVerifier`
/// (the appliance carries them as opaque bytes). `branch_proof` is an ordered list of
/// prior certificates for frontier catch-up (Def. 10); empty for a direct-from-frontier
/// release.
#[derive(Clone)]
pub struct OfflineRelease {
    pub transition: OwnedTransition,
    pub anchor_smt_proof_before: Vec<u8>,
    pub anchor_smt_proof_after: Vec<u8>,
    pub cert: Certificate,
    pub branch_proof: Vec<Certificate>,
}
