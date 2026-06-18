// SPDX-License-Identifier: MIT OR Apache-2.0

//! Bilateral Transaction Manager - Production Implementation (STRICT, bytes-only, no wall-clock)
//!
//! Invariants:
//! - No wall-clock APIs anywhere. Use a deterministic, process-local monotonic counter.
//! - No JSON/GSON at any boundary. No hex/base64 in data structures; bytes-only.
//! - SMT proofs are derived deterministically from state + domain separators + counters.
//! - No placeholders: real key retrieval from verified contacts; fail hard if missing.

use std::collections::HashMap;

use crate::crypto::blake3::dsm_domain_hasher;
use tracing::{info, error};

use crate::core::contact_manager::DsmContactManager;
use crate::commitments::precommit::PreCommitment as CanonicalPreCommitment;
use crate::core::chain_tip_store::{noop_chain_tip_store, ChainTipStore};
use crate::core::state_machine::bilateral::BilateralStateManager;
use crate::crypto::canonical_lp;
use crate::crypto::signatures::SignatureKeyPair;
use crate::merkle::sparse_merkle_tree::{empty_leaf, SmtReplaceResult, SparseMerkleTree};
use crate::types::contact_types::{ChainTipSmtProof, DsmVerifiedContact};
use crate::types::device_state::BalanceDelta;
use crate::types::error::{DeterministicSafetyClass, DsmError};
use crate::types::operations::Operation;
use crate::types::state_types::{PreCommitment, State};
use crate::core::utility::labeling;
use crate::common::domain_tags::{TAG_BILATERAL_SESSION, TAG_SMT_KEY, TAG_TIP};

// -------------------- Cryptographic Progress (strictly increasing, clockless) --------------------
#[inline]
fn mono_commit_height() -> u64 {
    crate::utils::deterministic_time::current_commit_height_blocking()
}

/// Public wrapper for clockless monotone commit height (used by BLE handler for SMT proof fields).
#[inline]
pub fn mono_commit_height_pub() -> u64 {
    crate::utils::deterministic_time::current_commit_height_blocking()
}

// -------------------- Relationship Anchor (bytes-only, single shared tip) --------------------
/// Per whitepaper §16.6: "For each {i,j} ∈ Rel there exists a forward-only chain C_{i,j}"
/// — a single joint mathematical object. ONE shared chain tip h_n^{A↔B} per relationship.
/// Divergence between parties = fork = Tripwire violation (terminal), not reconcilable.
#[derive(Clone, Debug)]
pub struct BilateralRelationshipAnchor {
    pub local_device_id: [u8; 32],
    pub local_genesis_hash: [u8; 32],
    pub remote_device_id: [u8; 32],
    pub remote_genesis_hash: [u8; 32],
    pub mutual_anchor_hash: [u8; 32],
    /// h_n^{A↔B} — THE single shared relationship chain tip.
    /// Both parties MUST agree on this value. Divergence = Tripwire.
    pub chain_tip: [u8; 32],
    /// SMT inclusion proof for this relationship's chain tip
    pub smt_proof: Option<ChainTipSmtProof>,
    pub established_at: u64,
    pub last_sync_at: u64,
}
impl BilateralRelationshipAnchor {
    pub fn new(
        local_device_id: [u8; 32],
        local_genesis_hash: [u8; 32],
        remote_device_id: [u8; 32],
        remote_genesis_hash: [u8; 32],
    ) -> Self {
        let mutual_anchor_hash =
            Self::generate_mutual_anchor_hash(&local_genesis_hash, &remote_genesis_hash);
        let now = mono_commit_height();
        Self {
            local_device_id,
            local_genesis_hash,
            remote_device_id,
            remote_genesis_hash,
            mutual_anchor_hash,
            chain_tip: empty_leaf(),
            smt_proof: None,
            established_at: now,
            last_sync_at: now,
        }
    }
    /// Order-independent mutual anchor = H("DSM_BILATERAL_ANCHOR" || min(genesis) || max(genesis))
    pub fn generate_mutual_anchor_hash(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
        let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
        let mut h = dsm_domain_hasher(TAG_BILATERAL_SESSION);
        canonical_lp::write_lp(&mut h, lo);
        canonical_lp::write_lp(&mut h, hi);
        let out = h.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(out.as_bytes());
        bytes
    }
    #[inline]
    pub fn is_synchronized(&self) -> bool {
        self.chain_tip != empty_leaf() && self.smt_proof.is_some()
    }
}

fn initial_relationship_chain_tip(
    local_device_id: &[u8; 32],
    local_genesis_hash: &[u8; 32],
    remote_device_id: &[u8; 32],
    remote_genesis_hash: &[u8; 32],
) -> [u8; 32] {
    // h_0 = hasher(TAG_BILATERAL_SESSION) || sorted(G_A, DevID_A, G_B, DevID_B)
    // Lexicographic ordering ensures identical output regardless of initiator.
    // compute_initial_chain_tip() in contact_sdk.rs MUST use the same hasher and tag.
    let (genesis_a, device_a, genesis_b, device_b) = if local_device_id < remote_device_id {
        (
            local_genesis_hash,
            local_device_id,
            remote_genesis_hash,
            remote_device_id,
        )
    } else {
        (
            remote_genesis_hash,
            remote_device_id,
            local_genesis_hash,
            local_device_id,
        )
    };

    let mut h = dsm_domain_hasher(TAG_BILATERAL_SESSION);
    h.update(genesis_a);
    h.update(device_a);
    h.update(genesis_b);
    h.update(device_b);
    let out = h.finalize();
    bytes32(out.as_bytes())
}

/// Compute the initial chain tip for a bilateral relationship using device
/// IDs only (genesis hashes zeroed). Suitable for callers that don't have
/// genesis hashes available — the output is still deterministic and symmetric.
pub fn initial_chain_tip_from_device_ids(dev_id_a: &[u8; 32], dev_id_b: &[u8; 32]) -> [u8; 32] {
    initial_relationship_chain_tip(dev_id_a, &[0u8; 32], dev_id_b, &[0u8; 32])
}

/// §18.1: k_{A↔B} = BLAKE3("DSM/smt-key\0" || min(DevID_A, DevID_B) || max(DevID_A, DevID_B))
/// Lexicographic ordering ensures identical key regardless of which party computes it.
pub fn compute_smt_key(dev_id_a: &[u8; 32], dev_id_b: &[u8; 32]) -> [u8; 32] {
    let (min_id, max_id) = if dev_id_a < dev_id_b {
        (dev_id_a, dev_id_b)
    } else {
        (dev_id_b, dev_id_a)
    };
    let mut h = dsm_domain_hasher(TAG_SMT_KEY);
    h.update(min_id);
    h.update(max_id);
    bytes32(h.finalize().as_bytes())
}

/// Canonical bilateral pre-commit digest.
///
/// `C_pre = H("DSM/precommit/commitment-hash/v2\0" || h_n || payload_i || e_i)`.
pub fn compute_precommit(h_n: &[u8; 32], op_bytes: &[u8], entropy: &[u8]) -> [u8; 32] {
    CanonicalPreCommitment::branch_commitment_hash(h_n, op_bytes, entropy)
}

/// §16.6: h_{n+1} = BLAKE3("DSM/tip\0" || h_n || op || e || σ) — successor shared tip
/// Both parties compute this identically from shared inputs. Deterministic.
///
/// Non-attested path: delegates to [`compute_successor_tip_attested`] with no anchor proof, so its
/// bytes are unchanged from the original formula.
pub fn compute_successor_tip(
    h_n: &[u8; 32],
    op_bytes: &[u8],
    entropy: &[u8],
    receipt_digest: &[u8; 32],
) -> [u8; 32] {
    compute_successor_tip_attested(h_n, op_bytes, entropy, receipt_digest, None)
}

/// §16.6 successor tip with an optional offline-bearer anchor-proof tail (append-only-when-present).
///
/// For non-attested transitions (`anchor_proof_hash = None`) this is BYTE-IDENTICAL to the base
/// formula, so every existing tip is unchanged and DSM core / online-checked paths are untouched.
/// For offline-bearer attested transitions the canonical
/// [`crate::attestation::compute_anchor_proof_hash`] digest is appended, binding the attestation
/// into the authoritative bilateral tip — only the 32-byte digest is folded, never a raw
/// `id_anchor || s_n || policy_id` concatenation. The full proof bundle stays on the receipt.
pub fn compute_successor_tip_attested(
    h_n: &[u8; 32],
    op_bytes: &[u8],
    entropy: &[u8],
    receipt_digest: &[u8; 32],
    anchor_proof_hash: Option<&[u8; 32]>,
) -> [u8; 32] {
    let mut h = dsm_domain_hasher(TAG_TIP);
    h.update(h_n);
    h.update(op_bytes);
    h.update(entropy);
    h.update(receipt_digest);
    if let Some(aph) = anchor_proof_hash {
        h.update(aph);
    }
    bytes32(h.finalize().as_bytes())
}

/// Whether an operation declares it requires offline-bearer authority (the canonical per-Operation
/// trigger). Only these transitions run the anchor gate; all others finalize unchanged.
pub fn operation_requires_offline_bearer(op: &crate::types::operations::Operation) -> bool {
    use crate::types::operations::{AuthorityMode, Operation};
    matches!(
        op,
        Operation::Transfer { authority_policy: Some(ap), .. }
            if ap.mode == AuthorityMode::OfflineBearerRequired
    )
}

/// Outcome of the offline-bearer gate: the receipt bundle (carries the proof inputs so the digest
/// is reconstructable) and the `anchor_proof_hash` the caller folds into the attested successor tip.
pub struct OfflineBearerGateOutcome {
    pub island_attestation: crate::types::device_state::IslandAttestation,
    pub anchor_proof_hash: [u8; 32],
}

/// The offline-bearer authority gate. This is the cryptographic gate ONLY — it does not mutate
/// DeviceState (the caller flips `OfflineBearerAttestation::Attested`). It fails closed: any
/// condition below rejects the transition, never a silent downgrade.
///
/// Rejects, in order:
///  1. operation is not an `OfflineBearerRequired` transfer, or no anchor transport is present;
///  2. `value_capability` is not `Yes`;
///  3. anchor identity fetch / signing fails (device unreachable, human rejects, malformed material);
///  4. the anchor signature does not verify host-side;
///  5. the recomputed canonical anchor-set id != the operation's declared `anchor_set_id`.
///
/// On success returns the receipt + the `anchor_proof_hash` to fold; a re-verifier recomputing the
/// digest from the receipt and matching it to the folded tip is reject (6) — see
/// [`anchor_proof_hash_from_receipt`].
#[allow(clippy::too_many_arguments)]
pub async fn run_offline_bearer_gate(
    transport: Option<&std::sync::Arc<dyn crate::crypto::anchor_transport::AnchorTransport>>,
    frontier_store: &std::sync::Arc<dyn crate::core::chain_tip_store::ChainTipStore>,
    op: &crate::types::operations::Operation,
    current_tip: &[u8; 32],
    rel_key: &[u8; 32],
    local_device_id: &[u8; 32],
    entropy: &[u8; 32],
    expiry_tick: u64,
    value_capability: crate::types::device_state::ValueCapability,
) -> Result<OfflineBearerGateOutcome, DsmError> {
    use crate::attestation::{
        canonical_signature_bundle, compute_anchor_proof_hash, compute_anchor_set_id,
        dsm_offline_bearer_payload_hash, dsm_ui_transcript, id_island_from_spki, OfflineBearerMode,
    };
    use crate::crypto::anchor_transport::{verify_anchor_signature, AnchorSignRequest};
    use crate::types::device_state::{IslandAttestation, ValueCapability};
    use crate::types::operations::{AuthorityMode, Operation};

    // (1a) Must be an offline-bearer-required transfer.
    let (to_device_id, amount, token_id, ap) = match op {
        Operation::Transfer {
            to_device_id,
            amount,
            token_id,
            authority_policy: Some(ap),
            ..
        } if ap.mode == AuthorityMode::OfflineBearerRequired => {
            (to_device_id, amount, token_id, ap)
        }
        _ => {
            return Err(DsmError::invalid_operation(
                "offline-bearer gate: operation is not an OFFLINE_BEARER_REQUIRED transfer",
            ))
        }
    };

    // (1b) Transport must be present.
    let transport = transport.ok_or_else(|| {
        DsmError::verification(
            "offline-bearer gate: OFFLINE_BEARER_REQUIRED but no anchor transport (fail-closed)",
        )
    })?;

    // (2) Value capability must be Yes (No/Unknown hard reject).
    if value_capability != ValueCapability::Yes {
        return Err(DsmError::verification(
            "offline-bearer gate: value_capability is not Yes (fail-closed)",
        ));
    }

    // Counterparty must be a 32-byte device id.
    let counterparty_id: [u8; 32] = to_device_id.as_slice().try_into().map_err(|_| {
        DsmError::invalid_operation("offline-bearer gate: to_device_id must be 32 bytes")
    })?;

    let op_bytes = op.to_bytes();
    let payload_hash = dsm_offline_bearer_payload_hash(&op_bytes);
    let amount_u64 = amount.value();

    // (3a) Fetch the device's published identity (the ACTUAL anchor set it signs under).
    let rec = transport.get_identity().await.map_err(|e| {
        DsmError::verification(format!(
            "offline-bearer gate: anchor identity fetch failed: {e} (fail-closed)"
        ))
    })?;

    // (5) Recomputed canonical anchor-set id must equal the policy's declared id — a policy cannot
    // name one anchor set while the device signs under a different concrete identity set.
    let id_anchor_set = compute_anchor_set_id(&[rec.id_anchor]);
    if id_anchor_set != ap.anchor_set_id {
        return Err(DsmError::verification(
            "offline-bearer gate: anchor-set id mismatch vs declared policy (fail-closed)",
        ));
    }

    // The anchor's SINGLE monotonic frontier (ONE per device, keyed by the anchor identity — NOT per
    // relationship; every offline-bearer transition advances this one counter, so a clone must fork
    // it). parent_root = the device's current frontier root; successor_root advances it
    // deterministically (no signature dependency → no circularity). It is its OWN chain, separate
    // from the relationship chain tip (`current_tip`).
    let (parent_root, stored_state) = frontier_store
        .get_anchor_frontier(&rec.id_anchor)
        .unwrap_or(([0u8; 32], 0));
    let state_number = stored_state + 1;
    let operation_hash = payload_hash;
    let successor_root = crate::attestation::dsm_anchor_frontier_successor(
        &parent_root,
        &operation_hash,
        state_number,
    );
    let policy_hash = crate::attestation::dsm_policy_hash(&ap.policy_id, &id_anchor_set);

    // The request the device displays and computes the challenge over.
    let req = AnchorSignRequest {
        h_n: current_tip,
        payload_hash: &payload_hash,
        relationship_id: rel_key,
        device_id: local_device_id,
        value_capability: value_capability.to_wire() as u8,
        offline_bearer_mode: OfflineBearerMode::Required.tag(),
        nonce: entropy.as_slice(),
        expiry_tick,
        amount: amount_u64,
        asset: token_id.as_slice(),
        counterparty_id: &counterparty_id,
        policy_id: &ap.policy_id,
        policy_hash: &policy_hash,
        parent_root: &parent_root,
        successor_root: &successor_root,
        state_number,
    };

    // (3b) Sign on the device.
    let signature = transport.sign(&req).await.map_err(|e| {
        DsmError::verification(format!(
            "offline-bearer gate: anchor signing failed: {e} (fail-closed)"
        ))
    })?;

    // (4) Verify the signature host-side against the pinned identity.
    verify_anchor_signature(&rec, &req, &signature).map_err(|e| {
        DsmError::verification(format!(
            "offline-bearer gate: anchor signature verification failed: {e} (fail-closed)"
        ))
    })?;

    // (4b) Advance the device's SINGLE anchor frontier (CAS, keyed by id_anchor). Fail-closed if the
    // advance is rejected — a stale/forked parent or non-monotonic state means a concurrent or
    // cloned signer touched this device's one frontier.
    let advanced = frontier_store
        .set_anchor_frontier(&rec.id_anchor, parent_root, successor_root, state_number)
        .map_err(|e| {
            DsmError::verification(format!(
                "offline-bearer gate: anchor frontier advance failed: {e} (fail-closed)"
            ))
        })?;
    if !advanced {
        return Err(DsmError::verification(
            "offline-bearer gate: anchor frontier advance rejected — forked/concurrent advance (fail-closed)",
        ));
    }

    // The UI transcript the device bound (recompute the same bytes for the receipt + proof digest).
    let ui_transcript_hash = dsm_ui_transcript(
        amount_u64,
        token_id.as_slice(),
        &counterparty_id,
        current_tip,
        &payload_hash,
        &ap.policy_id,
        &rec.firmware_id,
        rec.screen_template_id,
    );

    let bundle = canonical_signature_bundle(std::slice::from_ref(&signature));
    let anchor_proof_hash =
        compute_anchor_proof_hash(&ap.policy_id, &id_anchor_set, &ui_transcript_hash, &bundle);

    let island_attestation = IslandAttestation {
        id_island: id_island_from_spki(&rec.leaf_spki),
        id_anchor_set,
        ui_transcript_hash,
        signature,
        policy_id: ap.policy_id,
        anchor_pubkey_hash: crate::attestation::dsm_anchor_pubkey_hash(&rec.leaf_spki),
        firmware_hash: rec.firmware_hash,
        policy_hash,
        parent_root,
        successor_root,
        operation_hash,
        state_number,
    };

    Ok(OfflineBearerGateOutcome {
        island_attestation,
        anchor_proof_hash,
    })
}

/// Reconstruct the `anchor_proof_hash` from a receipt's `IslandAttestation` (reject 6: the recomputed
/// digest must equal the one folded into the attested successor tip). Every input comes from the
/// receipt, so the folded tip is independently checkable. (Single-island; dual-island carries
/// multiple signatures.)
pub fn anchor_proof_hash_from_receipt(
    att: &crate::types::device_state::IslandAttestation,
) -> [u8; 32] {
    let bundle =
        crate::attestation::canonical_signature_bundle(std::slice::from_ref(&att.signature));
    crate::attestation::compute_anchor_proof_hash(
        &att.policy_id,
        &att.id_anchor_set,
        &att.ui_transcript_hash,
        &bundle,
    )
}

/// Receiver-side verification of an offline-bearer commit's anchor attestation against a pinned
/// enrollment. Reconstructs the EXACT [`crate::crypto::anchor_transport::AnchorSignRequest`] the
/// device signed — this MUST mirror [`run_offline_bearer_gate`]'s request construction byte-for-byte
/// — verifies it against the pinned identity + firmware + policy + frontier
/// ([`crate::crypto::anchor_enrollment::verify_admitted_offline_bearer`]), then CAS-advances the
/// pinned frontier. Fail-closed: an un-admitted sender, a clone/fresh identity, a non-enrolled
/// firmware, a wrong policy, or a forked/replayed frontier all reject.
///
/// `target_state_number` is the transition's target state — the gate uses it as the signed
/// `expiry_tick`; the frontier `state_number` comes from the attestation itself (a distinct,
/// independent counter). `entropy` is the shared transition entropy the gate folded as the nonce.
#[allow(clippy::too_many_arguments)]
pub fn verify_offline_bearer_receipt(
    enrollment_store: &dyn crate::crypto::anchor_enrollment::AnchorEnrollmentStore,
    sender_device_id: &[u8; 32],
    op: &crate::types::operations::Operation,
    sender_current_tip: &[u8; 32],
    target_state_number: u64,
    entropy: &[u8; 32],
    att: &crate::types::device_state::IslandAttestation,
) -> Result<(), DsmError> {
    use crate::attestation::{dsm_offline_bearer_payload_hash, OfflineBearerMode};
    use crate::crypto::anchor_enrollment::verify_admitted_offline_bearer;
    use crate::crypto::anchor_transport::AnchorSignRequest;
    use crate::types::device_state::ValueCapability;
    use crate::types::operations::{AuthorityMode, Operation};

    // Must be an OFFLINE_BEARER_REQUIRED transfer (mirror the sender gate's (1a)).
    let (to_device_id, amount, token_id, ap) =
        match op {
            Operation::Transfer {
                to_device_id,
                amount,
                token_id,
                authority_policy: Some(ap),
                ..
            } if ap.mode == AuthorityMode::OfflineBearerRequired => {
                (to_device_id, amount, token_id, ap)
            }
            _ => return Err(DsmError::verification(
                "offline-bearer receiver: operation is not OFFLINE_BEARER_REQUIRED (fail-closed)",
            )),
        };
    let counterparty_id: [u8; 32] = to_device_id.as_slice().try_into().map_err(|_| {
        DsmError::invalid_operation("offline-bearer receiver: to_device_id must be 32 bytes")
    })?;

    // The pinned enrollment (anti-reprovision: an un-admitted sender anchor rejects).
    let enr = enrollment_store.get(sender_device_id).ok_or_else(|| {
        DsmError::verification("offline-bearer receiver: sender anchor not admitted (fail-closed)")
    })?;

    let payload_hash = dsm_offline_bearer_payload_hash(&op.to_bytes());
    // rel_key is symmetric (compute_smt_key sorts), so the receiver derives the same key the sender
    // gate used: compute_smt_key(sender, receiver).
    let rel_key = compute_smt_key(sender_device_id, &counterparty_id);

    // Reconstruct the request the device signed. value_capability=Yes and mode=Required are gate
    // invariants (the gate rejects anything else); expiry_tick == the transition target state and
    // nonce == the shared transition entropy. policy_hash is the PINNED value (so the signature must
    // have folded it); the frontier fields come from the attestation and are checked vs the pinned
    // frontier by the verifier.
    let req = AnchorSignRequest {
        h_n: sender_current_tip,
        payload_hash: &payload_hash,
        relationship_id: &rel_key,
        device_id: sender_device_id,
        value_capability: ValueCapability::Yes.to_wire() as u8,
        offline_bearer_mode: OfflineBearerMode::Required.tag(),
        nonce: entropy.as_slice(),
        expiry_tick: target_state_number,
        amount: amount.value(),
        asset: token_id.as_slice(),
        counterparty_id: &counterparty_id,
        policy_id: &ap.policy_id,
        policy_hash: &enr.policy_hash,
        parent_root: &att.parent_root,
        successor_root: &att.successor_root,
        state_number: att.state_number,
    };

    verify_admitted_offline_bearer(&enr, att, &req)?;

    // CAS-advance the pinned frontier (cross-receiver fork detector: a second advance from an
    // already-consumed root reaching this receiver is rejected).
    let advanced = enrollment_store.advance_frontier(
        sender_device_id,
        att.parent_root,
        att.successor_root,
        att.state_number,
    )?;
    if !advanced {
        return Err(DsmError::verification(
            "offline-bearer receiver: frontier fork/replay rejected (fail-closed)",
        ));
    }
    Ok(())
}

// -------------------- Bilateral Pre-Commitment (bytes-only) --------------------
#[derive(Clone, Debug)]
pub struct BilateralPreCommitment {
    pub local_commitment: PreCommitment,
    pub remote_commitment: PreCommitment,
    pub bilateral_commitment_hash: [u8; 32],
    pub local_signature: Vec<u8>,
    pub remote_signature: Vec<u8>,
    pub target_state_number: u64,
    pub operation: Operation,
    pub created_at: u64,
    pub expires_at: u64,
    /// Local chain tip at creation time (Tripwire enforcement: DSM Whitepaper Section 6.1).
    /// At finalize, current tip must match this; otherwise parent was already consumed.
    pub local_chain_tip_at_creation: Option<[u8; 32]>,
}
impl BilateralPreCommitment {
    pub fn new(
        local_commitment: PreCommitment,
        remote_commitment: PreCommitment,
        operation: Operation,
        target_state_number: u64,
        validity_duration: u64,
        local_chain_tip: Option<[u8; 32]>,
    ) -> Result<Self, DsmError> {
        let now = mono_commit_height();
        let bilateral_commitment_hash =
            Self::generate_bilateral_hash(&local_commitment, &remote_commitment, &operation)?;
        Ok(Self {
            local_commitment,
            remote_commitment,
            bilateral_commitment_hash,
            local_signature: Vec::new(),
            remote_signature: Vec::new(),
            target_state_number,
            operation,
            created_at: now,
            expires_at: now.saturating_add(validity_duration),
            local_chain_tip_at_creation: local_chain_tip,
        })
    }
    fn generate_bilateral_hash(
        local: &PreCommitment,
        remote: &PreCommitment,
        op: &Operation,
    ) -> Result<[u8; 32], DsmError> {
        let mut h = dsm_domain_hasher(TAG_BILATERAL_SESSION);
        canonical_lp::write_lp(&mut h, &local.hash);
        canonical_lp::write_lp(&mut h, &remote.hash);
        canonical_lp::write_lp(&mut h, &op.to_bytes());
        let out = h.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(out.as_bytes());
        Ok(bytes)
    }
    pub fn sign_local(&mut self, kp: &SignatureKeyPair) -> Result<(), DsmError> {
        let msg = self.signing_message()?;
        self.local_signature = kp.sign(&msg)?;
        Ok(())
    }
    pub fn set_remote_signature(&mut self, sig: Vec<u8>) {
        self.remote_signature = sig;
    }
    fn signing_message(&self) -> Result<Vec<u8>, DsmError> {
        let mut m = Vec::new();
        m.extend_from_slice(b"DSM/bilateral-pre-commitment\0");

        // Canonical LP delimiting for variable-length fields.
        // NOTE: Vec encoding must match canonical LP: u32-le length prefix + bytes.
        // We inline it here to avoid introducing new exported helpers.
        fn push_lp(out: &mut Vec<u8>, bytes: &[u8]) {
            let len = bytes.len() as u32;
            out.extend_from_slice(&len.to_le_bytes());
            out.extend_from_slice(bytes);
        }

        push_lp(&mut m, &self.bilateral_commitment_hash);
        push_lp(&mut m, &self.local_commitment.hash);
        push_lp(&mut m, &self.remote_commitment.hash);
        push_lp(&mut m, &self.operation.to_bytes());
        m.extend_from_slice(&self.target_state_number.to_le_bytes());
        m.extend_from_slice(&self.created_at.to_le_bytes());
        m.extend_from_slice(&self.expires_at.to_le_bytes());
        Ok(m)
    }
    pub fn verify_local_signature(&self, pk: &[u8]) -> Result<bool, DsmError> {
        crate::crypto::signatures::SignatureKeyPair::verify_raw(
            &self.signing_message()?,
            &self.local_signature,
            pk,
        )
    }
    pub fn verify_remote_signature(&self, pk: &[u8]) -> Result<bool, DsmError> {
        crate::crypto::signatures::SignatureKeyPair::verify_raw(
            &self.signing_message()?,
            &self.remote_signature,
            pk,
        )
    }
    pub fn verify(&self) -> Result<bool, DsmError> {
        let now = mono_commit_height();
        if now > self.expires_at {
            return Ok(false);
        }
        Ok(Self::generate_bilateral_hash(
            &self.local_commitment,
            &self.remote_commitment,
            &self.operation,
        )? == self.bilateral_commitment_hash)
    }
}

// -------------------- Transaction Manager --------------------
#[derive(Clone, Debug)]
pub struct BilateralTransactionResult {
    pub local_state: State,
    pub remote_state: State,
    pub relationship_anchor: BilateralRelationshipAnchor,
    pub transaction_hash: [u8; 32],
    pub completed_offline: bool,
    /// Offline-bearer island attestation receipt — `Some` iff this was an attested
    /// OFFLINE_BEARER_REQUIRED transfer. Carries the proof inputs so a re-verifier can reconstruct
    /// the `anchor_proof_hash` folded into the chain tip.
    pub island_attestation: Option<crate::types::device_state::IslandAttestation>,
}

/// Prepared bilateral advance — handoff from the tripwire-verified
/// precommitment path to the canonical Per-Device SMT advance (§2.2).
///
/// Constructed by [`BilateralTransactionManager::prepare_bilateral_advance`]
/// after §6.1 tripwire + §4.3 acceptance prechecks pass. The caller feeds
/// this into `AppRouter::execute_on_relationship_for_bilateral` to commit
/// the advance atomically via `CoreSDK::execute_on_relationship`.
///
/// Construction does NOT mutate any SMT, any anchor, or the pending
/// precommitment set — commit happens only inside the router, gated by
/// §4.3 acceptance again. The caller must call
/// [`BilateralTransactionManager::consume_pre_commitment`] after the
/// advance commits successfully.
#[derive(Clone, Debug)]
pub struct PreparedBilateralAdvance {
    /// SMT leaf key `k_{A↔B}` for this relationship.
    pub rel_key: [u8; 32],
    /// Counterparty's 32-byte device ID.
    pub counterparty_devid: [u8; 32],
    /// Operation to execute on the bilateral chain.
    pub operation: Operation,
    /// Sender-side balance deltas supplied by the caller.
    pub deltas: Vec<BalanceDelta>,
    /// Parent chain tip `h_n` used for CAS-style linkage during advance.
    pub parent_tip: [u8; 32],
    /// Entropy `e` to be fed into the advance; matches the precommitted value.
    pub entropy: [u8; 32],
    /// Bilateral precommitment hash, for post-commit cleanup via
    /// [`BilateralTransactionManager::consume_pre_commitment`].
    pub pre_commitment_hash: [u8; 32],
}

#[derive(Debug)]
pub struct BilateralTransactionManager {
    contact_manager: DsmContactManager,
    bilateral_state_manager: BilateralStateManager,
    relationships: HashMap<[u8; 32], BilateralRelationshipAnchor>, // key = remote_device_id
    pending_commitments: HashMap<[u8; 32], BilateralPreCommitment>, // key = bilateral_commitment_hash
    signature_keypair: SignatureKeyPair,
    local_device_id: [u8; 32],
    local_genesis_hash: [u8; 32],
    chain_tip_store: std::sync::Arc<dyn ChainTipStore>,
    /// Optional offline-bearer signing anchor (the DeviceAnchor). `None` = no offline-bearer
    /// authority admitted, so OFFLINE_BEARER_REQUIRED transitions hard-reject (fail-closed). Set
    /// via [`BilateralTransactionManager::with_anchor_transport`].
    anchor_transport: Option<std::sync::Arc<dyn crate::crypto::anchor_transport::AnchorTransport>>,
    /// Receiver-side pinned anchor enrollments. An incoming OFFLINE_BEARER_REQUIRED commit from a
    /// sender whose anchor is not admitted here is rejected fail-closed. Default: empty (admit a
    /// counterparty's anchor via [`BilateralTransactionManager::admit_anchor`]).
    enrollment_store: std::sync::Arc<dyn crate::crypto::anchor_enrollment::AnchorEnrollmentStore>,
}

const PROOF_MAX_AGE_COMMIT_HEIGHTS: u64 = 86_400;

impl BilateralTransactionManager {
    pub fn new(
        contact_manager: DsmContactManager,
        signature_keypair: SignatureKeyPair,
        local_device_id: [u8; 32],
        local_genesis_hash: [u8; 32],
    ) -> Self {
        let chain_tip_store = noop_chain_tip_store();
        Self::new_with_chain_tip_store(
            contact_manager,
            signature_keypair,
            local_device_id,
            local_genesis_hash,
            chain_tip_store,
        )
    }

    pub fn new_with_chain_tip_store(
        contact_manager: DsmContactManager,
        signature_keypair: SignatureKeyPair,
        local_device_id: [u8; 32],
        local_genesis_hash: [u8; 32],
        chain_tip_store: std::sync::Arc<dyn ChainTipStore>,
    ) -> Self {
        Self {
            contact_manager,
            bilateral_state_manager: BilateralStateManager::new(),
            relationships: HashMap::new(),
            pending_commitments: HashMap::new(),
            signature_keypair,
            local_device_id,
            local_genesis_hash,
            chain_tip_store,
            anchor_transport: None,
            enrollment_store: std::sync::Arc::new(
                crate::crypto::anchor_enrollment::InMemoryAnchorEnrollmentStore::new(),
            ),
        }
    }

    /// Inject the offline-bearer signing anchor (the admitted hardware island). Builder-style, so
    /// existing constructors are unchanged. Without it, OFFLINE_BEARER_REQUIRED transitions
    /// hard-reject (fail-closed).
    pub fn with_anchor_transport(
        mut self,
        transport: std::sync::Arc<dyn crate::crypto::anchor_transport::AnchorTransport>,
    ) -> Self {
        self.anchor_transport = Some(transport);
        self
    }

    /// Inject a receiver-side anchor enrollment store (SDKs back it with persistent storage).
    pub fn with_enrollment_store(
        mut self,
        store: std::sync::Arc<dyn crate::crypto::anchor_enrollment::AnchorEnrollmentStore>,
    ) -> Self {
        self.enrollment_store = store;
        self
    }

    /// Admit (pin) a counterparty's anchor through the authority path: pin its identity record,
    /// offline-bearer policy hash, and initial frontier `(root, state)`. A later offline-bearer
    /// commit from this sender is accepted ONLY if it advances this pinned frontier under the pinned
    /// identity. Never call this implicitly from a received receipt — that is the anti-reprovision
    /// rule (a fresh self-provisioned identity must not admit itself).
    pub fn admit_anchor(
        &self,
        sender_device_id: [u8; 32],
        record: crate::crypto::anchor_transport::AnchorIdentityRecord,
        policy_hash: [u8; 32],
        initial_root: [u8; 32],
        initial_state: u64,
    ) -> Result<(), DsmError> {
        self.enrollment_store
            .admit(crate::crypto::anchor_enrollment::AnchorEnrollment {
                device_id: sender_device_id,
                record,
                policy_hash,
                frontier_root: initial_root,
                frontier_state: initial_state,
            })
    }

    /// This device's published anchor identity, if an anchor transport is admitted. `None` means no
    /// offline-bearer anchor (no element / no mock) — the device cannot anchor transfers and falls
    /// back to the online-checked path. The identity is the element's (real Safe 7 transport) or the
    /// in-process mock's; the exchange + pinning around it are identical either way.
    pub async fn anchor_identity(
        &self,
    ) -> Option<crate::crypto::anchor_transport::AnchorIdentityRecord> {
        match &self.anchor_transport {
            Some(t) => t.get_identity().await.ok(),
            None => None,
        }
    }

    /// Production policy: a device that HOLDS an offline-bearer anchor stamps OFFLINE_BEARER_REQUIRED
    /// on its plain offline transfers, pinning its own anchor set. A device with no anchor leaves the
    /// transfer plain (online-checked fallback). Not a test hook — the only thing the mock supplies is
    /// the anchor transport; this policy logic is identical with a real element.
    pub async fn apply_offline_bearer_policy(&self, op: &mut crate::types::operations::Operation) {
        use crate::types::operations::{AuthorityMode, AuthorityPolicy, Operation};
        if let Operation::Transfer {
            authority_policy, ..
        } = op
        {
            if authority_policy.is_none() {
                if let Some(rec) = self.anchor_identity().await {
                    *authority_policy = Some(AuthorityPolicy {
                        mode: AuthorityMode::OfflineBearerRequired,
                        policy_id: crate::attestation::dsm_offline_bearer_policy_id(),
                        anchor_set_id: crate::attestation::compute_anchor_set_id(&[rec.id_anchor]),
                    });
                }
            }
        }
    }

    /// Admit a counterparty's anchor only if it is not already admitted (idempotent). Returns
    /// whether an admission was performed. Used so re-seeing a counterparty does not reset its
    /// tracked monotonic frontier back to genesis.
    pub fn admit_anchor_if_absent(
        &self,
        sender_device_id: [u8; 32],
        record: crate::crypto::anchor_transport::AnchorIdentityRecord,
        policy_hash: [u8; 32],
        initial_root: [u8; 32],
        initial_state: u64,
    ) -> Result<bool, DsmError> {
        if self.enrollment_store.get(&sender_device_id).is_some() {
            return Ok(false);
        }
        self.admit_anchor(
            sender_device_id,
            record,
            policy_hash,
            initial_root,
            initial_state,
        )?;
        Ok(true)
    }

    /// Receiver-side enforcement: verify an incoming OFFLINE_BEARER_REQUIRED commit's anchor
    /// attestation against the PINNED enrollment for `sender_device_id`, then CAS-advance the pinned
    /// frontier. Fail-closed — a non-admitted sender, a clone/fresh identity, a non-enrolled
    /// firmware, a wrong policy, or a forked/replayed frontier all reject. The receiver MUST call
    /// this before committing the transfer (releasing goods). The device's on-chip Track-2 frontier
    /// is the primary serializer; this is the receiver identity pin + cross-receiver fork detector.
    pub fn verify_incoming_offline_bearer_commit(
        &self,
        sender_device_id: &[u8; 32],
        op: &Operation,
        sender_current_tip: &[u8; 32],
        target_state_number: u64,
        entropy: &[u8; 32],
        att: &crate::types::device_state::IslandAttestation,
    ) -> Result<(), DsmError> {
        verify_offline_bearer_receipt(
            self.enrollment_store.as_ref(),
            sender_device_id,
            op,
            sender_current_tip,
            target_state_number,
            entropy,
            att,
        )
    }

    /// Sender-side: produce the offline-bearer anchor attestation for a pending precommitment by
    /// running the anchor gate over the transition (signs with the admitted anchor transport and
    /// advances the device's single frontier). Returns `None` when no anchor transport is admitted
    /// or the op is not OFFLINE_BEARER_REQUIRED — so a build with no transport carries no attestation
    /// and the receiver rejects fail-closed. The returned `u64` is the signed `expiry_tick` the
    /// receiver must echo (as `anchor_expiry_tick`) to reconstruct the signature.
    pub async fn attest_offline_bearer_for_commitment(
        &self,
        commitment_hash: &[u8; 32],
        current_tip: &[u8; 32],
        entropy: &[u8; 32],
        value_capability: crate::types::device_state::ValueCapability,
    ) -> Result<Option<(crate::types::device_state::IslandAttestation, u64)>, DsmError> {
        use crate::types::operations::Operation;
        if self.anchor_transport.is_none() {
            return Ok(None);
        }
        let (op, expiry) = match self.pending_commitments.get(commitment_hash) {
            Some(p) => (p.operation.clone(), p.target_state_number),
            None => return Ok(None),
        };
        if !operation_requires_offline_bearer(&op) {
            return Ok(None);
        }
        let counterparty: [u8; 32] = match &op {
            Operation::Transfer { to_device_id, .. } => {
                to_device_id.as_slice().try_into().map_err(|_| {
                    DsmError::invalid_operation(
                        "attest_offline_bearer: to_device_id must be 32 bytes",
                    )
                })?
            }
            _ => return Ok(None),
        };
        let rel_key = compute_smt_key(&self.local_device_id, &counterparty);
        let outcome = run_offline_bearer_gate(
            self.anchor_transport.as_ref(),
            &self.chain_tip_store,
            &op,
            current_tip,
            &rel_key,
            &self.local_device_id,
            entropy,
            expiry,
            value_capability,
        )
        .await?;
        Ok(Some((outcome.island_attestation, expiry)))
    }

    pub fn list_relationships(&self) -> Vec<BilateralRelationshipAnchor> {
        self.relationships.values().cloned().collect()
    }
    pub fn get_relationship(
        &self,
        remote_device_id: &[u8; 32],
    ) -> Option<BilateralRelationshipAnchor> {
        self.relationships.get(remote_device_id).cloned()
    }

    /// Compute the deterministic initial relationship tip (h_0) for a given counterparty.
    pub fn initial_relationship_tip_for(
        &self,
        remote_device_id: &[u8; 32],
    ) -> Result<[u8; 32], DsmError> {
        let contact = self
            .contact_manager
            .get_contact(remote_device_id)
            .ok_or_else(|| DsmError::ContactNotFound("remote device".into()))?;

        Ok(initial_relationship_chain_tip(
            &self.local_device_id,
            &self.local_genesis_hash,
            remote_device_id,
            &contact.genesis_hash,
        ))
    }

    pub fn has_pending_commitment(&self, commitment_hash: &[u8; 32]) -> bool {
        self.pending_commitments.contains_key(commitment_hash)
    }

    pub fn list_pending_commitments(&self) -> Vec<[u8; 32]> {
        self.pending_commitments.keys().cloned().collect()
    }

    /// Get the shared relationship chain tip h_n^{A↔B} for a given counterparty.
    /// Both parties MUST agree on this value; divergence = Tripwire violation.
    pub fn get_chain_tip_for(&self, remote_device_id: &[u8; 32]) -> Option<[u8; 32]> {
        self.relationships
            .get(remote_device_id)
            .map(|a| a.chain_tip)
    }

    /// Advance the shared relationship chain tip forward.
    /// Requires a valid stitched receipt (enforced by caller). Divergence = Tripwire.
    ///
    /// This helper is the single mutation primitive that re-syncs the in-memory
    /// BTM anchor AND contact_manager's contact-cache to a new authoritative tip
    /// (typically pulled from SQLite). Both in-memory caches MUST be updated
    /// atomically here so no caller can leave them asymmetric — otherwise the
    /// intra-device consistency tripwire inside finalize_offline_transfer_with_entropy
    /// fires as a self-inflicted wound.
    ///
    /// The SMT proof on the contact is cleared because this raw-tip sync carries
    /// no proof material; a fresh proof is recorded on the next authoritative
    /// bilateral commit (update_contact_chain_tip_bilateral) or unilateral send
    /// (update_contact_chain_tip_unilateral).
    pub fn advance_chain_tip(&mut self, remote_device_id: &[u8; 32], new_tip: [u8; 32]) {
        // log::info! (NOT tracing!) so this appears in Android logcat for
        // deployment verification — the dsm crate's tracing events are not
        // bridged to android_logger.
        let prev_anchor_short = self
            .relationships
            .get(remote_device_id)
            .map(|a| labeling::hash_to_short_id(&a.chain_tip))
            .unwrap_or_else(|| "None".to_string());
        let prev_contact_short = self
            .contact_manager
            .get_contact(remote_device_id)
            .and_then(|c| c.chain_tip.map(|t| labeling::hash_to_short_id(&t)))
            .unwrap_or_else(|| "None".to_string());
        log::info!(
            "[BTM] advance_chain_tip: anchor={} contact={} -> new={}",
            prev_anchor_short,
            prev_contact_short,
            labeling::hash_to_short_id(&new_tip)
        );
        if let Some(anchor) = self.relationships.get_mut(remote_device_id) {
            info!(
                "[BTM] advance_chain_tip: {} -> {}",
                labeling::hash_to_short_id(&anchor.chain_tip),
                labeling::hash_to_short_id(&new_tip)
            );
            anchor.chain_tip = new_tip;
            anchor.last_sync_at = mono_commit_height();
        }
        if let Some(contact_mut) = self.contact_manager.get_contact_mut(remote_device_id) {
            contact_mut.chain_tip = Some(new_tip);
            contact_mut.chain_tip_smt_proof = None;
        }
    }

    /// Remove pending commitment (testing / reconciliation helper)
    pub fn remove_pending_commitment(
        &mut self,
        commitment_hash: &[u8; 32],
    ) -> Option<BilateralPreCommitment> {
        self.pending_commitments.remove(commitment_hash)
    }

    pub fn get_current_ticks(&self) -> u64 {
        mono_commit_height()
    }

    /// Derive deterministic transition entropy for a bilateral operation.
    pub fn derive_transition_entropy(
        &self,
        remote_device_id: &[u8; 32],
        operation: &Operation,
    ) -> Result<[u8; 32], DsmError> {
        self.bilateral_state_manager
            .derive_transition_entropy_bytes(&self.local_device_id, remote_device_id, operation)
    }

    /// Update anchor from a real SMT-Replace result (§4.2).
    ///
    /// The `replace_result` MUST come from `commit_bilateral_smt_update()` for the
    /// same transition. Validates the result matches before mutating state.
    pub fn update_anchor_from_replace_public(
        &mut self,
        remote_device_id: &[u8; 32],
        anchor: &mut BilateralRelationshipAnchor,
        new_chain_tip: [u8; 32],
        replace_result: &SmtReplaceResult,
    ) -> Result<(), DsmError> {
        self.update_anchor_from_replace(remote_device_id, anchor, new_chain_tip, replace_result)
    }

    /// Update anchor in-memory from a real SMT-Replace result (§4.2).
    ///
    /// Same validation as `update_anchor_from_replace_public` but skips SQLite.
    /// Caller MUST persist atomically with balance writes afterward.
    /// The `replace_result` MUST come from `commit_bilateral_smt_update()`.
    pub fn update_anchor_in_memory_from_replace_public(
        &mut self,
        remote_device_id: &[u8; 32],
        anchor: &mut BilateralRelationshipAnchor,
        new_chain_tip: [u8; 32],
        replace_result: &SmtReplaceResult,
    ) -> Result<(), DsmError> {
        self.update_anchor_in_memory_from_replace(
            remote_device_id,
            anchor,
            new_chain_tip,
            replace_result,
        )
    }

    /// Store real Per-Device SMT proof in the relationship anchor after BLE SMT-Replace.
    /// Called by BLE handler after computing the genuine inclusion proof (§B3).
    /// Perform atomic SMT-Replace for a bilateral relationship (§4.2).
    ///
    /// Pure SMT mutation: computes the relationship key, calls `smt_replace`,
    /// and returns the result. No anchor updates, no proof storage, no side
    /// effects. The caller consumes the `SmtReplaceResult` via
    /// `update_anchor_from_replace()` to advance anchor/contact state.
    pub fn commit_bilateral_smt_update(
        &mut self,
        smt: &mut SparseMerkleTree,
        remote_device_id: &[u8; 32],
        new_chain_tip: &[u8; 32],
    ) -> Result<SmtReplaceResult, DsmError> {
        let smt_key = compute_smt_key(&self.local_device_id, remote_device_id);

        smt.smt_replace(&smt_key, new_chain_tip)
            .map_err(|e| DsmError::merkle(format!("SMT-Replace failed (§4.2): {e}")))
    }

    /// Compute transaction hash from state pair (public wrapper for receiver-side finalize)
    pub fn tx_hash_public(
        &self,
        local_state: &State,
        remote_state: &State,
    ) -> Result<[u8; 32], DsmError> {
        self.tx_hash(local_state, remote_state)
    }

    #[inline]
    pub fn local_genesis_hash(&self) -> [u8; 32] {
        self.local_genesis_hash
    }

    #[inline]
    pub fn local_device_id(&self) -> [u8; 32] {
        self.local_device_id
    }

    /// Return the local signing public key for inclusion in BLE prepare requests.
    /// This allows offline receivers to verify signatures without prior key exchange.
    pub fn local_signing_public_key(&self) -> Vec<u8> {
        self.signature_keypair.public_key().to_vec()
    }

    /// Return the local AK (long-term attestation) keypair as `(pk, sk)` for
    /// cert-chain construction (whitepaper §11.1). Used at relationship genesis
    /// (step 0) when no per-step chain head exists yet — the receipt-signing
    /// path falls back to AK_sk to sign cert_1.
    ///
    /// Visibility: limited to bilateral-flow callers in the SDK. The AK_sk
    /// material is sensitive — only the receipt-signing flow should touch
    /// it directly.
    pub fn ak_keypair_for_cert_chain(&self) -> (Vec<u8>, Vec<u8>) {
        (
            self.signature_keypair.public_key().to_vec(),
            self.signature_keypair.secret_key().to_vec(),
        )
    }

    /// Sign a commitment hash using the local keypair.
    /// This is used by the BLE handler when registering a sender session for bilateral transfers.
    /// The signature is required for the commit phase.
    ///
    /// Fail-closed: signer errors are surfaced as `DsmError`, never silently converted
    /// to an empty signature blob. See issue #191.
    pub fn sign_commitment(&self, commitment_hash: &[u8; 32]) -> Result<Vec<u8>, DsmError> {
        // §ISSUE-B4 FIX: canonical "DSM/<domain>\0" domain separator format.
        let mut msg = Vec::with_capacity(22 + 32);
        msg.extend_from_slice(b"DSM/bilateral-sign\0");
        msg.extend_from_slice(commitment_hash);

        let sig = self.signature_keypair.sign(&msg).map_err(|e| {
            error!("[BTM] sign_commitment: failed to sign: {}", e);
            e
        })?;
        info!(
            "[BTM] sign_commitment: signed commitment {}... with {} byte signature",
            labeling::hash_to_short_id(commitment_hash),
            sig.len()
        );
        Ok(sig)
    }

    pub fn add_verified_contact(&mut self, c: DsmVerifiedContact) -> Result<(), DsmError> {
        self.contact_manager.add_verified_contact(c)
    }

    /// Check whether a verified contact exists for the given remote device id
    pub fn has_verified_contact(&self, remote_device_id: &[u8; 32]) -> bool {
        self.contact_manager.get_contact(remote_device_id).is_some()
    }

    /// Get contact for offline bilateral transfer (includes BLE address lookup)
    pub fn get_contact(&self, remote_device_id: &[u8; 32]) -> Option<&DsmVerifiedContact> {
        self.contact_manager.get_contact(remote_device_id)
    }

    /// Update a contact's signing public key after receiving it via BLE.
    /// Used by receivers to store the sender's key for signature verification.
    pub fn update_contact_signing_key(
        &mut self,
        remote_device_id: &[u8; 32],
        signing_public_key: Vec<u8>,
    ) -> Result<(), DsmError> {
        info!(
            "[BTM] update_contact_signing_key: device={} key_len={}",
            labeling::hash_to_short_id(remote_device_id),
            signing_public_key.len()
        );
        let result = self
            .contact_manager
            .update_contact_public_key(remote_device_id, signing_public_key);
        // Verify the update took effect
        if let Some(c) = self.contact_manager.get_contact(remote_device_id) {
            info!(
                "[BTM] update_contact_signing_key: AFTER update, contact.public_key.len()={}",
                c.public_key.len()
            );
        }
        result
    }

    pub async fn establish_relationship(
        &mut self,
        remote_device_id: &[u8; 32],
    ) -> Result<BilateralRelationshipAnchor, DsmError> {
        info!(
            "[BTM] establish_relationship: device={}",
            labeling::hash_to_short_id(remote_device_id)
        );
        let contact = self
            .contact_manager
            .get_contact(remote_device_id)
            .ok_or_else(|| DsmError::ContactNotFound("remote device".into()))?;
        info!(
            "[BTM] establish_relationship: contact.alias={}, public_key.len()={}, genesis_verified={}, chain_tip={:?}",
            contact.alias, contact.public_key.len(), contact.genesis_verified_online,
            contact.chain_tip.map(|ct| labeling::hash_to_short_id(&ct))
        );
        if !contact.can_perform_bilateral_transaction() {
            return Err(DsmError::InvalidContact(
                "Contact Genesis not verified online".into(),
            ));
        }
        // Capture chain_tip before contact borrow ends
        let contact_chain_tip = contact.chain_tip;
        let contact_genesis_hash = contact.genesis_hash;
        let remote_pk = Self::extract_contact_signing_key(contact)?; // strict: must exist
        self.bilateral_state_manager
            .ensure_relationship_initialized_bytes(
                &self.local_device_id,
                remote_device_id,
                self.signature_keypair.public_key().to_vec(),
                remote_pk,
            )?;
        let mut anchor = BilateralRelationshipAnchor::new(
            self.local_device_id,
            self.local_genesis_hash,
            *remote_device_id,
            contact_genesis_hash,
        );
        // CRITICAL: Initialize shared relationship chain tip deterministically.
        // h_0 is derived from both parties' genesis + device IDs (lexicographic)
        // and must match on both sides for first-contact binding.
        let initial_tip = initial_relationship_chain_tip(
            &self.local_device_id,
            &self.local_genesis_hash,
            remote_device_id,
            &contact_genesis_hash,
        );

        // Use persisted chain tip if available (from previous session), else h_0.
        let tip = contact_chain_tip.unwrap_or(initial_tip);
        info!(
            "[BTM] establish_relationship: setting chain_tip={} (from_persisted={})",
            labeling::hash_to_short_id(&tip),
            contact_chain_tip.is_some()
        );
        anchor.chain_tip = tip;
        self.relationships.insert(*remote_device_id, anchor.clone());

        // Seed the chain tip store only when no chain tip exists yet.
        // contact_sdk may have already persisted the initial tip during
        // add_contact, in which case contact_chain_tip is Some(...) and the
        // CAS with expected_parent=[0u8;32] would fail (SQLite already
        // stores tip, not zeros). Skip the redundant write to avoid the
        // rejected-CAS warning.
        if contact_chain_tip.is_none() {
            let _ = self
                .chain_tip_store
                .set_contact_chain_tip(remote_device_id, [0u8; 32], tip);
        }

        Ok(anchor)
    }

    /// Ensure a relationship anchor exists for a sender path without requiring
    /// the remote contact to have a signing public key present. This is used
    /// by sender-side flows where the contact may be stored but signing key
    /// is not yet exchanged; we must still create a canonical relationship
    /// anchor and initialize the bilateral state manager so precommitments
    /// can be created and pending in the core manager.
    pub fn ensure_relationship_for_sender(
        &mut self,
        remote_device_id: &[u8; 32],
    ) -> Result<BilateralRelationshipAnchor, DsmError> {
        // If relationship already present, return it
        if let Some(r) = self.relationships.get(remote_device_id) {
            return Ok(r.clone());
        }

        let contact = self
            .contact_manager
            .get_contact(remote_device_id)
            .ok_or_else(|| DsmError::ContactNotFound("remote device".into()))?;

        // Derive remote public key if available; otherwise allow empty vec
        let remote_pk = contact.public_key.clone();

        // Initialize underlying bilateral state manager relationship (idempotent)
        self.bilateral_state_manager
            .ensure_relationship_initialized_bytes(
                &self.local_device_id,
                remote_device_id,
                self.signature_keypair.public_key().to_vec(),
                remote_pk.clone(),
            )?;

        // Build anchor similar to establish_relationship but tolerant of missing signing key
        let mut anchor = BilateralRelationshipAnchor::new(
            self.local_device_id,
            self.local_genesis_hash,
            *remote_device_id,
            contact.genesis_hash,
        );

        // Initialize shared chain tip deterministically (same as establish_relationship)
        let initial_tip = initial_relationship_chain_tip(
            &self.local_device_id,
            &self.local_genesis_hash,
            remote_device_id,
            &contact.genesis_hash,
        );
        anchor.chain_tip = contact.chain_tip.unwrap_or(initial_tip);

        self.relationships.insert(*remote_device_id, anchor.clone());
        Ok(anchor)
    }

    pub async fn create_bilateral_precommitment(
        &mut self,
        remote_device_id: &[u8; 32],
        operation: Operation,
        validity_duration_ticks: u64,
    ) -> Result<BilateralPreCommitment, DsmError> {
        let relationship = self
            .relationships
            .get(remote_device_id)
            .ok_or_else(|| DsmError::RelationshipNotFound("remote device".into()))?;
        // Capture shared chain tip at creation for Tripwire enforcement (DSM Whitepaper Section 6.1)
        let local_chain_tip_at_creation = Some(relationship.chain_tip);
        // Strict protocol: a bilateral precommitment requires the counterparty's
        // signing public key to exist in the verified contact record. Do not
        // silently fall back to an empty key — callers should perform contact
        // exchange/online verification before attempting offline prepare.
        let remote_pk = self.require_contact_signing_key(remote_device_id)?;
        self.bilateral_state_manager
            .ensure_relationship_initialized_bytes(
                &self.local_device_id,
                remote_device_id,
                self.signature_keypair.public_key().to_vec(),
                remote_pk,
            )?;
        let local_state = self
            .bilateral_state_manager
            .get_relationship_state_bytes(&self.local_device_id, remote_device_id)?;
        let remote_state = self
            .bilateral_state_manager
            .get_relationship_state_bytes(remote_device_id, &self.local_device_id)?;
        let local_commitment = PreCommitment {
            operation_type: operation.get_operation_type().to_string(),
            fixed_parameters: HashMap::new(),
            variable_parameters: std::collections::HashSet::new(),
            min_state_number: 1,
            hash: PreCommitment::generate_hash(&local_state.hash, &operation, &[])?,
            signatures: Vec::new(),
            entity_signature: None,
            counterparty_signature: None,
            value: Vec::new(),
            commitment: Vec::new(),
            counterparty_id: *remote_device_id,
        };
        let remote_commitment = PreCommitment {
            operation_type: operation.get_operation_type().to_string(),
            fixed_parameters: HashMap::new(),
            variable_parameters: std::collections::HashSet::new(),
            min_state_number: 1,
            hash: PreCommitment::generate_hash(&remote_state.hash, &operation, &[])?,
            signatures: Vec::new(),
            entity_signature: None,
            counterparty_signature: None,
            value: Vec::new(),
            commitment: Vec::new(),
            counterparty_id: self.local_device_id,
        };
        let mut bilateral = BilateralPreCommitment::new(
            local_commitment,
            remote_commitment,
            operation,
            local_state.hash[0] as u64 + 1,
            validity_duration_ticks,
            local_chain_tip_at_creation,
        )?;
        // Sign the pre-commitment locally so acceptance proof can be transported over BLE
        bilateral.sign_local(&self.signature_keypair)?;
        self.pending_commitments
            .insert(bilateral.bilateral_commitment_hash, bilateral.clone());
        Ok(bilateral)
    }

    /// Update anchor from a real `SmtReplaceResult` (§4.2).
    ///
    /// The replace result MUST come from `commit_bilateral_smt_update()` for the
    /// same transition. This method validates the result matches the expected
    /// transition before mutating anchor/contact state.
    fn update_anchor_from_replace(
        &mut self,
        remote_device_id: &[u8; 32],
        anchor: &mut BilateralRelationshipAnchor,
        new_chain_tip: [u8; 32],
        replace_result: &SmtReplaceResult,
    ) -> Result<(), DsmError> {
        let expected_parent_tip = anchor.chain_tip;
        let expected_key = compute_smt_key(&self.local_device_id, remote_device_id);

        // Validate the replace result matches this transition — invariant with teeth
        if replace_result.child_proof.value != Some(new_chain_tip) {
            return Err(DsmError::merkle(
                "SmtReplaceResult child value != new_chain_tip",
            ));
        }
        if replace_result.child_proof.key != expected_key {
            return Err(DsmError::merkle("SmtReplaceResult key != expected smt_key"));
        }

        // Build proof from the real replace result
        let smt_proof = ChainTipSmtProof {
            smt_root: replace_result.post_root,
            state_hash: new_chain_tip,
            smt_key: expected_key,
            proof_path: replace_result.child_proof.siblings.clone(),
            state_index: mono_commit_height_pub(),
            proof_commit_height: mono_commit_height_pub(),
        };

        // Update contact manager with real proof
        self.contact_manager
            .update_contact_chain_tip_bilateral(remote_device_id, new_chain_tip, smt_proof.clone())
            .map_err(|e| DsmError::InvalidContact(format!("{e:?}")))?;

        anchor.chain_tip = new_chain_tip;
        anchor.last_sync_at = mono_commit_height();
        anchor.smt_proof = Some(smt_proof);
        self.relationships.insert(*remote_device_id, anchor.clone());

        // Persist chain tip (forward-only)
        match self.chain_tip_store.set_contact_chain_tip(
            remote_device_id,
            expected_parent_tip,
            new_chain_tip,
        )? {
            true => {}
            false => {
                return Err(DsmError::deterministic_safety(
                    DeterministicSafetyClass::ParentConsumed,
                    "Tripwire: finalized relationship chain tip parent no longer matches storage",
                ));
            }
        }
        Ok(())
    }

    /// Update anchor in-memory from a real `SmtReplaceResult` (§4.2).
    ///
    /// Same as `update_anchor_from_replace` but skips SQLite persistence.
    /// Caller MUST persist the chain tip to SQLite atomically with balance writes
    /// via the atomic persistence helper.
    fn update_anchor_in_memory_from_replace(
        &mut self,
        remote_device_id: &[u8; 32],
        anchor: &mut BilateralRelationshipAnchor,
        new_chain_tip: [u8; 32],
        replace_result: &SmtReplaceResult,
    ) -> Result<(), DsmError> {
        let expected_key = compute_smt_key(&self.local_device_id, remote_device_id);

        // Validate the replace result
        if replace_result.child_proof.value != Some(new_chain_tip) {
            return Err(DsmError::merkle(
                "SmtReplaceResult child value != new_chain_tip",
            ));
        }
        if replace_result.child_proof.key != expected_key {
            return Err(DsmError::merkle("SmtReplaceResult key != expected smt_key"));
        }

        let smt_proof = ChainTipSmtProof {
            smt_root: replace_result.post_root,
            state_hash: new_chain_tip,
            smt_key: expected_key,
            proof_path: replace_result.child_proof.siblings.clone(),
            state_index: mono_commit_height_pub(),
            proof_commit_height: mono_commit_height_pub(),
        };

        self.contact_manager
            .update_contact_chain_tip_bilateral(remote_device_id, new_chain_tip, smt_proof.clone())
            .map_err(|e| DsmError::InvalidContact(format!("{e:?}")))?;

        anchor.chain_tip = new_chain_tip;
        anchor.last_sync_at = mono_commit_height();
        anchor.smt_proof = Some(smt_proof);
        self.relationships.insert(*remote_device_id, anchor.clone());
        // Intentionally skip chain_tip_store.set_contact_chain_tip() —
        // caller persists atomically with balance write.
        Ok(())
    }

    fn require_contact_signing_key(
        &self,
        remote_device_id: &[u8; 32],
    ) -> Result<Vec<u8>, DsmError> {
        let c = self
            .contact_manager
            .get_contact(remote_device_id)
            .ok_or_else(|| DsmError::RelationshipNotFound("remote device".into()))?;
        Self::extract_contact_signing_key(c)
    }

    fn extract_contact_signing_key(contact: &DsmVerifiedContact) -> Result<Vec<u8>, DsmError> {
        if !contact.public_key.is_empty() {
            Ok(contact.public_key.clone())
        } else {
            Err(DsmError::InvalidContact(
                "Missing remote signing public key".into(),
            ))
        }
    }

    fn tx_hash(&self, local_state: &State, remote_state: &State) -> Result<[u8; 32], DsmError> {
        let mut h = dsm_domain_hasher(TAG_BILATERAL_SESSION);
        h.update(&local_state.hash()?);
        h.update(&remote_state.hash()?);
        let out = h.finalize();
        Ok(bytes32(out.as_bytes()))
    }

    pub fn verify_relationship_integrity(
        &self,
        remote_device_id: &[u8; 32],
    ) -> Result<bool, DsmError> {
        let r = self
            .relationships
            .get(remote_device_id)
            .ok_or_else(|| DsmError::RelationshipNotFound("remote device".into()))?;
        let expected = BilateralRelationshipAnchor::generate_mutual_anchor_hash(
            &r.local_genesis_hash,
            &r.remote_genesis_hash,
        );
        if expected != r.mutual_anchor_hash {
            return Ok(false);
        }
        if let Some(proof) = &r.smt_proof {
            let now = mono_commit_height();
            if now.saturating_sub(proof.proof_commit_height) > PROOF_MAX_AGE_COMMIT_HEIGHTS {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn verify_receiver_acceptance_proof(
        &self,
        remote_device_id: &[u8; 32],
        pre_commitment_hash: &[u8; 32],
        receiver_acceptance_proof: &[u8],
    ) -> Result<(), DsmError> {
        if receiver_acceptance_proof.is_empty() {
            return Err(DsmError::InvalidOperation(
                "receiver acceptance proof required".into(),
            ));
        }

        let counterparty_pubkey = self
            .contact_manager
            .get_contact(remote_device_id)
            .ok_or_else(|| DsmError::InvalidOperation("missing counterparty contact".into()))?
            .public_key
            .clone();

        let mut signature_msg = Vec::with_capacity(22 + 32);
        signature_msg.extend_from_slice(b"DSM/bilateral-sign\0");
        signature_msg.extend_from_slice(pre_commitment_hash);

        let valid = SignatureKeyPair::verify_raw(
            &signature_msg,
            receiver_acceptance_proof,
            &counterparty_pubkey,
        )
        .map_err(|e| {
            DsmError::InvalidOperation(format!("receiver acceptance proof verification error: {e}"))
        })?;

        if !valid {
            return Err(DsmError::InvalidOperation(
                "invalid receiver acceptance proof signature".into(),
            ));
        }

        Ok(())
    }

    pub async fn prepare_offline_transfer(
        &mut self,
        remote_device_id: &[u8; 32],
        operation: Operation,
        validity_duration_ticks: u64,
    ) -> Result<BilateralPreCommitment, DsmError> {
        info!("Phase 1: prepare offline");
        self.create_bilateral_precommitment(remote_device_id, operation, validity_duration_ticks)
            .await
    }

    pub async fn finalize_offline_transfer(
        &mut self,
        remote_device_id: &[u8; 32],
        pre_commitment_hash: &[u8; 32],
        receiver_acceptance_proof: &[u8],
        smt: &mut SparseMerkleTree,
        value_capability: crate::types::device_state::ValueCapability,
    ) -> Result<BilateralTransactionResult, DsmError> {
        self.finalize_offline_transfer_with_entropy(
            remote_device_id,
            pre_commitment_hash,
            receiver_acceptance_proof,
            None,
            smt,
            value_capability,
        )
        .await
    }

    /// Finalize an offline bilateral transfer, optionally using pre-generated entropy.
    ///
    /// When `pre_generated_entropy` is `Some`, it is used instead of generating fresh
    /// entropy.  This is required when the sender pre-computed its post-finalize chain
    /// tip during commit construction (sent as `sender_post_finalize_chain_tip` in the
    /// BilateralCommitRequest) so the actual finalize result matches the pre-computed tip.
    pub async fn finalize_offline_transfer_with_entropy(
        &mut self,
        remote_device_id: &[u8; 32],
        pre_commitment_hash: &[u8; 32],
        receiver_acceptance_proof: &[u8],
        pre_generated_entropy: Option<[u8; 32]>,
        smt: &mut SparseMerkleTree,
        value_capability: crate::types::device_state::ValueCapability,
    ) -> Result<BilateralTransactionResult, DsmError> {
        info!("Phase 2: finalize offline");
        let pre = self
            .pending_commitments
            .get(pre_commitment_hash)
            .ok_or_else(|| {
                DsmError::InvalidOperation("pre-commitment not found or expired".into())
            })?;
        if receiver_acceptance_proof.is_empty() {
            return Err(DsmError::InvalidOperation(
                "receiver acceptance proof required".into(),
            ));
        }
        let mut anchor = self
            .relationships
            .get(remote_device_id)
            .ok_or_else(|| DsmError::RelationshipNotFound("remote device".into()))?
            .clone();

        // Refresh shared chain tip from persistent store before finalization
        if let Some(tip) = self.chain_tip_store.get_contact_chain_tip(remote_device_id) {
            if let Some(anchor_mut) = self.relationships.get_mut(remote_device_id) {
                anchor_mut.chain_tip = tip;
            }
            if let Some(contact_mut) = self.contact_manager.get_contact_mut(remote_device_id) {
                contact_mut.chain_tip = Some(tip);
                contact_mut.chain_tip_smt_proof = None;
            }
            anchor.chain_tip = tip;
        }

        // ===== TRIPWIRE ENFORCEMENT (DSM Whitepaper Section 6.1) =====
        // The parent tip recorded at precommitment creation MUST match the current
        // shared chain tip. If it differs, another transition has already consumed
        // the parent hash, and finalizing would violate the Tripwire theorem.
        if Some(anchor.chain_tip) != pre.local_chain_tip_at_creation {
            let class = DeterministicSafetyClass::ParentConsumed;
            log::warn!(
                "[BTM][TRIPWIRE:precommit-parent-consumed] anchor={} precommit_tip={} class={}",
                labeling::hash_to_short_id(&anchor.chain_tip),
                pre.local_chain_tip_at_creation
                    .map(|t| labeling::hash_to_short_id(&t))
                    .unwrap_or_else(|| "None".to_string()),
                class.as_str()
            );
            error!(
                "[BTM] Deterministic safety rejection [{}]: chain_tip={} precommit_tip={}",
                class.as_str(),
                labeling::hash_to_short_id(&anchor.chain_tip),
                pre.local_chain_tip_at_creation
                    .map(|t| labeling::hash_to_short_id(&t))
                    .unwrap_or_else(|| "None".to_string())
            );
            return Err(DsmError::deterministic_safety(
                class,
                "Tripwire: chain tip advanced since precommitment creation (parent hash already consumed)",
            ));
        }

        // Tripwire: shared chain tip must match persisted contact tip
        if let Some(contact) = self.contact_manager.get_contact(remote_device_id) {
            if let Some(contact_tip) = contact.chain_tip {
                if anchor.chain_tip != contact_tip {
                    log::warn!(
                        "[BTM][TRIPWIRE:finalize] anchor={} contact={} precommit_tip={} store={}",
                        labeling::hash_to_short_id(&anchor.chain_tip),
                        labeling::hash_to_short_id(&contact_tip),
                        pre.local_chain_tip_at_creation
                            .map(|t| labeling::hash_to_short_id(&t))
                            .unwrap_or_else(|| "None".to_string()),
                        self.chain_tip_store
                            .get_contact_chain_tip(remote_device_id)
                            .map(|t| labeling::hash_to_short_id(&t))
                            .unwrap_or_else(|| "None".to_string()),
                    );
                    return Err(DsmError::deterministic_safety(
                        DeterministicSafetyClass::ParentConsumed,
                        "Tripwire: relationship chain tip diverged from persisted value",
                    ));
                }
            }
        } else {
            return Err(DsmError::RelationshipNotFound(
                "remote contact missing for finalize_offline_transfer".into(),
            ));
        }

        let entropy = match pre_generated_entropy {
            Some(e) => e,
            None => self
                .bilateral_state_manager
                .derive_transition_entropy_bytes(
                    &self.local_device_id,
                    remote_device_id,
                    &pre.operation,
                )?,
        };
        let sp = self.bilateral_state_manager.execute_transition_bytes(
            &self.local_device_id,
            remote_device_id,
            pre.operation.clone(),
            entropy,
        )?;
        let current_tip = anchor.chain_tip;
        // C_pre uses the canonical precommit v2 branch formula; both parties
        // derive identical h_{n+1} from the same shared inputs.
        let op_bytes = pre.operation.to_bytes();
        let receipt_sigma = compute_precommit(&current_tip, &op_bytes, &entropy);

        // ===== Phase 5: offline-bearer authority gate =====
        // Runs ONLY for an OFFLINE_BEARER_REQUIRED transfer. Fail-closed: the operation REQUIRES the
        // proof, so any gate error (no admitted anchor, value-capability not Yes, signing/verify
        // failure, anchor-set mismatch) propagates as a HARD reject — never a silent downgrade.
        // Cryptographic gate ONLY; flipping OfflineBearerAttestation::Attested is the
        // DeviceState-owning caller's job (clean split).
        let island_outcome = if operation_requires_offline_bearer(&pre.operation) {
            let rel_key = compute_smt_key(&self.local_device_id, remote_device_id);
            Some(
                run_offline_bearer_gate(
                    self.anchor_transport.as_ref(),
                    &self.chain_tip_store,
                    &pre.operation,
                    &current_tip,
                    &rel_key,
                    &self.local_device_id,
                    &entropy,
                    pre.target_state_number,
                    value_capability,
                )
                .await?,
            )
        } else {
            None
        };

        // Attested transitions fold the canonical anchor-proof digest into the §16.6 successor tip
        // (append-only); non-attested transitions stay byte-identical to before.
        let new_tip = compute_successor_tip_attested(
            &current_tip,
            &op_bytes,
            &entropy,
            &receipt_sigma,
            island_outcome.as_ref().map(|o| &o.anchor_proof_hash),
        );
        let tx_hash = self.tx_hash(&sp.entity_state, &sp.counterparty_state)?;

        // §4.2: SMT-Replace FIRST, then anchor update from the result.
        let replace_result = self.commit_bilateral_smt_update(smt, remote_device_id, &new_tip)?;
        self.update_anchor_from_replace(remote_device_id, &mut anchor, new_tip, &replace_result)?;
        self.pending_commitments.remove(pre_commitment_hash);
        Ok(BilateralTransactionResult {
            local_state: sp.entity_state,
            remote_state: sp.counterparty_state,
            relationship_anchor: anchor.clone(),
            transaction_hash: tx_hash,
            completed_offline: true,
            island_attestation: island_outcome.map(|o| o.island_attestation),
        })
    }

    /// Prepare (but do not commit) a bilateral offline transfer.
    ///
    /// Runs the §6.1 tripwire checks and resolves entropy, then returns a
    /// [`PreparedBilateralAdvance`] handoff that the caller commits via
    /// `AppRouter::execute_on_relationship_for_bilateral` — which routes
    /// through the canonical `prepare_advance_relationship → commit_advance`
    /// chokepoint on the Per-Device SMT (§2.2).
    ///
    /// Body:
    ///   1. Refresh shared chain tip from persistent store.
    ///   2. §6.1 tripwire: anchor tip must equal `local_chain_tip_at_creation`.
    ///   3. Tripwire: anchor tip must equal persisted contact tip.
    ///   4. Entropy resolve (pre-generated wins; fresh otherwise).
    ///   5. Emit `PreparedBilateralAdvance`.
    ///
    /// No SMT mutation. No anchor mutation. No `pending_commitments` removal
    /// — caller calls [`Self::consume_pre_commitment`] after advance commit.
    pub async fn prepare_bilateral_advance(
        &mut self,
        remote_device_id: &[u8; 32],
        pre_commitment_hash: &[u8; 32],
        receiver_acceptance_proof: &[u8],
        pre_generated_entropy: Option<[u8; 32]>,
        sender_deltas: Vec<BalanceDelta>,
    ) -> Result<PreparedBilateralAdvance, DsmError> {
        info!("prepare_bilateral_advance: tripwire + entropy (no SMT/anchor mutation)");

        let pre = self
            .pending_commitments
            .get(pre_commitment_hash)
            .ok_or_else(|| {
                DsmError::InvalidOperation("pre-commitment not found or expired".into())
            })?
            .clone();
        self.verify_receiver_acceptance_proof(
            remote_device_id,
            pre_commitment_hash,
            receiver_acceptance_proof,
        )?;
        let mut anchor = self
            .relationships
            .get(remote_device_id)
            .ok_or_else(|| DsmError::RelationshipNotFound("remote device".into()))?
            .clone();

        // Refresh shared chain tip from persistent store before tripwire.
        if let Some(tip) = self.chain_tip_store.get_contact_chain_tip(remote_device_id) {
            if let Some(anchor_mut) = self.relationships.get_mut(remote_device_id) {
                anchor_mut.chain_tip = tip;
            }
            if let Some(contact_mut) = self.contact_manager.get_contact_mut(remote_device_id) {
                contact_mut.chain_tip = Some(tip);
                contact_mut.chain_tip_smt_proof = None;
            }
            anchor.chain_tip = tip;
        }

        // ===== TRIPWIRE ENFORCEMENT (§6.1) =====
        // Parent tip at precommit creation must equal current anchor tip; else
        // another transition already consumed the parent hash and finalizing
        // would violate the Tripwire theorem.
        if Some(anchor.chain_tip) != pre.local_chain_tip_at_creation {
            let class = DeterministicSafetyClass::ParentConsumed;
            log::warn!(
                "[BTM][TRIPWIRE:precommit-parent-consumed] anchor={} precommit_tip={} class={}",
                labeling::hash_to_short_id(&anchor.chain_tip),
                pre.local_chain_tip_at_creation
                    .map(|t| labeling::hash_to_short_id(&t))
                    .unwrap_or_else(|| "None".to_string()),
                class.as_str()
            );
            error!(
                "[BTM] Deterministic safety rejection [{}]: chain_tip={} precommit_tip={}",
                class.as_str(),
                labeling::hash_to_short_id(&anchor.chain_tip),
                pre.local_chain_tip_at_creation
                    .map(|t| labeling::hash_to_short_id(&t))
                    .unwrap_or_else(|| "None".to_string())
            );
            return Err(DsmError::deterministic_safety(
                class,
                "Tripwire: chain tip advanced since precommitment creation (parent hash already consumed)",
            ));
        }

        // Tripwire: shared chain tip must match persisted contact tip.
        if let Some(contact) = self.contact_manager.get_contact(remote_device_id) {
            if let Some(contact_tip) = contact.chain_tip {
                if anchor.chain_tip != contact_tip {
                    log::warn!(
                        "[BTM][TRIPWIRE:prepare] anchor={} contact={} precommit_tip={} store={}",
                        labeling::hash_to_short_id(&anchor.chain_tip),
                        labeling::hash_to_short_id(&contact_tip),
                        pre.local_chain_tip_at_creation
                            .map(|t| labeling::hash_to_short_id(&t))
                            .unwrap_or_else(|| "None".to_string()),
                        self.chain_tip_store
                            .get_contact_chain_tip(remote_device_id)
                            .map(|t| labeling::hash_to_short_id(&t))
                            .unwrap_or_else(|| "None".to_string()),
                    );
                    return Err(DsmError::deterministic_safety(
                        DeterministicSafetyClass::ParentConsumed,
                        "Tripwire: relationship chain tip diverged from persisted value",
                    ));
                }
            }
        } else {
            return Err(DsmError::RelationshipNotFound(
                "remote contact missing for prepare_bilateral_advance".into(),
            ));
        }

        let entropy = match pre_generated_entropy {
            Some(e) => e,
            None => self
                .bilateral_state_manager
                .derive_transition_entropy_bytes(
                    &self.local_device_id,
                    remote_device_id,
                    &pre.operation,
                )?,
        };
        let rel_key = compute_smt_key(&self.local_device_id, remote_device_id);

        Ok(PreparedBilateralAdvance {
            rel_key,
            counterparty_devid: *remote_device_id,
            operation: pre.operation,
            deltas: sender_deltas,
            parent_tip: anchor.chain_tip,
            entropy,
            pre_commitment_hash: *pre_commitment_hash,
        })
    }

    /// Drop a precommitment from the pending set after its associated
    /// bilateral advance has committed successfully. Call this after
    /// `AppRouter::execute_on_relationship_for_bilateral` returns Ok.
    pub fn consume_pre_commitment(&mut self, pre_commitment_hash: &[u8; 32]) {
        self.pending_commitments.remove(pre_commitment_hash);
    }

    /// Non-mutating preview of the sender's post-finalize SHARED chain tip hash.
    ///
    /// Computes h_{n+1} from h_n, operation bytes, entropy, and canonical C_pre.
    /// Both parties compute the same h_{n+1} from these shared inputs (§16.6).
    /// Used by the BLE handler to pre-compute the sender's post-finalize tip
    /// for inclusion in the BilateralCommitRequest.
    pub fn peek_post_finalize_hash(
        &self,
        remote_device_id: &[u8; 32],
        operation: &Operation,
        entropy: &[u8; 32],
    ) -> Result<[u8; 32], DsmError> {
        let current_tip = self
            .relationships
            .get(remote_device_id)
            .ok_or_else(|| DsmError::RelationshipNotFound("remote device".into()))?
            .chain_tip;
        let op_bytes = operation.to_bytes();
        // §16.6: σ = Cpre derived from shared inputs — symmetric on both sides.
        let receipt_sigma = compute_precommit(&current_tip, &op_bytes, entropy);
        Ok(compute_successor_tip(
            &current_tip,
            &op_bytes,
            entropy,
            &receipt_sigma,
        ))
    }
}

#[inline]
fn bytes32(slice: &[u8]) -> [u8; 32] {
    let mut a = [0u8; 32];
    a.copy_from_slice(&slice[0..32]);
    a
}

// NOTE: This stays as a String because PreCommitment currently requires it.
// It carries no wall-clock/epoch semantics and remains transport-agnostic.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::operations::{Operation, TransactionMode, VerificationType};
    use crate::types::token_types::Balance;
    use tokio; // for #[tokio::test]

    #[test]
    fn successor_tip_attested_is_append_only_and_non_attested_is_byte_identical() {
        let h_n = [1u8; 32];
        let op = b"op-bytes";
        let e = [2u8; 32];
        let sigma = [3u8; 32];
        let proof = [4u8; 32];

        // Non-attested path is byte-identical to the base formula — zero ripple to existing tips.
        let base = compute_successor_tip(&h_n, op, &e, &sigma);
        assert_eq!(
            base,
            compute_successor_tip_attested(&h_n, op, &e, &sigma, None)
        );
        // Pin the bytes: reproduce the original §16.6 formula explicitly.
        let explicit = {
            let mut h = dsm_domain_hasher(TAG_TIP);
            h.update(&h_n);
            h.update(op);
            h.update(&e);
            h.update(&sigma);
            bytes32(h.finalize().as_bytes())
        };
        assert_eq!(base, explicit);
        // Attested path appends the anchor-proof digest → different, deterministic tip.
        let attested = compute_successor_tip_attested(&h_n, op, &e, &sigma, Some(&proof));
        assert_ne!(attested, base);
        assert_eq!(
            attested,
            compute_successor_tip_attested(&h_n, op, &e, &sigma, Some(&proof))
        );
        // A different proof digest → different tip (the attestation is bound into the tip).
        assert_ne!(
            attested,
            compute_successor_tip_attested(&h_n, op, &e, &sigma, Some(&[5u8; 32]))
        );
    }

    #[tokio::test]
    async fn offline_bearer_gate_accepts_valid_proof_and_fails_closed() {
        use crate::attestation::compute_anchor_set_id;
        use crate::crypto::anchor_transport::{AnchorTransport, MockAnchorTransport};
        use crate::types::device_state::ValueCapability;
        use crate::types::operations::{AuthorityMode, AuthorityPolicy};
        use std::sync::Arc;

        let anchor: Arc<dyn AnchorTransport> = Arc::new(MockAnchorTransport::from_seed([7u8; 32]));
        let rec = anchor.get_identity().await.unwrap();
        let policy_id = [0x11u8; 32];
        let anchor_set_id = compute_anchor_set_id(&[rec.id_anchor]);

        let make_op = |ap: Option<AuthorityPolicy>| Operation::Transfer {
            to_device_id: vec![0x22u8; 32],
            amount: Balance::from_parts(10, 0, Some([0u8; 32])),
            token_id: b"ERA".to_vec(),
            policy_commit: [0u8; 32],
            mode: TransactionMode::Bilateral,
            nonce: vec![1, 2, 3],
            verification: VerificationType::Bilateral,
            pre_commit: None,
            recipient: vec![0x22u8; 32],
            to: vec![0x22u8; 32],
            message: String::new(),
            signature: vec![],
            authority_policy: ap,
        };
        let required = AuthorityPolicy {
            mode: AuthorityMode::OfflineBearerRequired,
            policy_id,
            anchor_set_id,
        };
        let op = make_op(Some(required.clone()));
        let (h_n, rel, dev, entropy) = ([0xAAu8; 32], [0xBBu8; 32], [0xCCu8; 32], [0xDDu8; 32]);
        let store = crate::core::chain_tip_store::noop_chain_tip_store();

        // (3) Happy path: a valid anchor proof finalizes.
        let outcome = run_offline_bearer_gate(
            Some(&anchor),
            &store,
            &op,
            &h_n,
            &rel,
            &dev,
            &entropy,
            42,
            ValueCapability::Yes,
        )
        .await
        .expect("valid offline-bearer proof must finalize");
        // (6) The receipt reconstructs the exact anchor_proof_hash folded into the tip.
        assert_eq!(
            anchor_proof_hash_from_receipt(&outcome.island_attestation),
            outcome.anchor_proof_hash
        );
        // (1) Attested tip differs from the non-attested tip (and non-attested stays byte-identical).
        let base_tip = compute_successor_tip(&h_n, b"op", &entropy, &[1u8; 32]);
        let attested_tip = compute_successor_tip_attested(
            &h_n,
            b"op",
            &entropy,
            &[1u8; 32],
            Some(&outcome.anchor_proof_hash),
        );
        assert_ne!(base_tip, attested_tip);

        // (4) Fail-closed: no transport present.
        assert!(run_offline_bearer_gate(
            None,
            &store,
            &op,
            &h_n,
            &rel,
            &dev,
            &entropy,
            42,
            ValueCapability::Yes
        )
        .await
        .is_err());
        // (4) Fail-closed: device rejects / signing fails.
        let rej: Arc<dyn AnchorTransport> = Arc::new(MockAnchorTransport::rejecting([7u8; 32]));
        assert!(run_offline_bearer_gate(
            Some(&rej),
            &store,
            &op,
            &h_n,
            &rel,
            &dev,
            &entropy,
            42,
            ValueCapability::Yes
        )
        .await
        .is_err());
        // (2) Fail-closed: value_capability not Yes.
        for vc in [ValueCapability::No, ValueCapability::Unknown] {
            assert!(run_offline_bearer_gate(
                Some(&anchor),
                &store,
                &op,
                &h_n,
                &rel,
                &dev,
                &entropy,
                42,
                vc
            )
            .await
            .is_err());
        }
        // (5) Fail-closed: policy declares a different anchor_set_id than the device's actual set.
        let wrong_op = make_op(Some(AuthorityPolicy {
            mode: AuthorityMode::OfflineBearerRequired,
            policy_id,
            anchor_set_id: [0x99u8; 32],
        }));
        assert!(run_offline_bearer_gate(
            Some(&anchor),
            &store,
            &wrong_op,
            &h_n,
            &rel,
            &dev,
            &entropy,
            42,
            ValueCapability::Yes
        )
        .await
        .is_err());
        // (1) A non-offline-bearer transfer (no policy) is not gated here.
        let plain = make_op(None);
        assert!(run_offline_bearer_gate(
            Some(&anchor),
            &store,
            &plain,
            &h_n,
            &rel,
            &dev,
            &entropy,
            42,
            ValueCapability::Yes
        )
        .await
        .is_err());

        // (6, tamper) A tampered signature bundle in the receipt changes the reconstructed digest.
        let mut tampered = outcome.island_attestation.clone();
        tampered.signature[0] ^= 0xff;
        assert_ne!(
            anchor_proof_hash_from_receipt(&tampered),
            outcome.anchor_proof_hash
        );
    }

    #[tokio::test]
    async fn receiver_pins_anchor_and_rejects_unadmitted_and_replay() {
        use crate::attestation::compute_anchor_set_id;
        use crate::crypto::anchor_enrollment::{
            AnchorEnrollment, AnchorEnrollmentStore, InMemoryAnchorEnrollmentStore,
        };
        use crate::crypto::anchor_transport::{AnchorTransport, MockAnchorTransport};
        use crate::types::device_state::ValueCapability;
        use crate::types::operations::{AuthorityMode, AuthorityPolicy};
        use std::sync::Arc;

        // Sender produces a genuine attestation through the gate.
        let anchor: Arc<dyn AnchorTransport> = Arc::new(MockAnchorTransport::from_seed([7u8; 32]));
        let rec = anchor.get_identity().await.unwrap();
        let policy_id = [0x11u8; 32];
        let anchor_set_id = compute_anchor_set_id(&[rec.id_anchor]);
        let sender_dev = [0xCCu8; 32];
        let to_dev = [0x22u8; 32];
        let op = Operation::Transfer {
            to_device_id: to_dev.to_vec(),
            amount: Balance::from_parts(10, 0, Some([0u8; 32])),
            token_id: b"ERA".to_vec(),
            policy_commit: [0u8; 32],
            mode: TransactionMode::Bilateral,
            nonce: vec![1, 2, 3],
            verification: VerificationType::Bilateral,
            pre_commit: None,
            recipient: to_dev.to_vec(),
            to: to_dev.to_vec(),
            message: String::new(),
            signature: vec![],
            authority_policy: Some(AuthorityPolicy {
                mode: AuthorityMode::OfflineBearerRequired,
                policy_id,
                anchor_set_id,
            }),
        };
        let h_n = [0xAAu8; 32];
        // rel_key the gate uses in finalize is compute_smt_key(sender, receiver); pass that so the
        // receiver-side reconstruction matches.
        let rel = compute_smt_key(&sender_dev, &to_dev);
        let entropy = [0xDDu8; 32];
        let expiry = 42u64;
        let store = crate::core::chain_tip_store::noop_chain_tip_store();
        let outcome = run_offline_bearer_gate(
            Some(&anchor),
            &store,
            &op,
            &h_n,
            &rel,
            &sender_dev,
            &entropy,
            expiry,
            ValueCapability::Yes,
        )
        .await
        .unwrap();
        let att = outcome.island_attestation;

        // Receiver admits the genuine sender anchor; a genuine commit verifies + advances.
        let receiver = Arc::new(InMemoryAnchorEnrollmentStore::new());
        receiver
            .admit(AnchorEnrollment {
                device_id: sender_dev,
                record: rec.clone(),
                policy_hash: att.policy_hash,
                frontier_root: [0u8; 32],
                frontier_state: 0,
            })
            .unwrap();
        verify_offline_bearer_receipt(
            receiver.as_ref(),
            &sender_dev,
            &op,
            &h_n,
            expiry,
            &entropy,
            &att,
        )
        .expect("genuine commit accepted (reconstruction matches the gate)");

        // Replay of the same (now-consumed) advance is rejected by the frontier CAS.
        assert!(verify_offline_bearer_receipt(
            receiver.as_ref(),
            &sender_dev,
            &op,
            &h_n,
            expiry,
            &entropy,
            &att,
        )
        .is_err());

        // A non-admitted sender is rejected (anti-reprovision / unknown identity).
        let empty = Arc::new(InMemoryAnchorEnrollmentStore::new());
        assert!(verify_offline_bearer_receipt(
            empty.as_ref(),
            &sender_dev,
            &op,
            &h_n,
            expiry,
            &entropy,
            &att,
        )
        .is_err());
    }

    fn make_manager_ids() -> ([u8; 32], [u8; 32]) {
        ([1u8; 32], [2u8; 32])
    }

    fn make_remote_ids() -> ([u8; 32], [u8; 32]) {
        ([9u8; 32], [7u8; 32]) // (device_id, genesis_hash)
    }

    fn make_manager() -> (BilateralTransactionManager, SignatureKeyPair) {
        // Initialize progress context for test
        crate::utils::deterministic_time::reset_for_tests();

        let (local_device_id, local_genesis_hash) = make_manager_ids();
        let contact_manager = DsmContactManager::new(local_device_id, vec![]);
        // Generate proper cryptographic keypair based on device and genesis identity
        let key_entropy = [local_device_id.as_slice(), local_genesis_hash.as_slice()].concat();
        let kp = SignatureKeyPair::generate_from_entropy(&key_entropy)
            .map_err(|e| DsmError::crypto("Failed to generate test keypair", Some(e)))
            .unwrap();
        let manager = BilateralTransactionManager::new(
            contact_manager,
            kp.clone(),
            local_device_id,
            local_genesis_hash,
        );
        (manager, kp)
    }

    fn make_verified_contact(
        alias: &str,
        with_pubkey: bool,
        genesis_verified: bool,
    ) -> DsmVerifiedContact {
        let (remote_device_id, remote_genesis_hash) = make_remote_ids();
        // Generate proper cryptographic keypair based on remote device and genesis identity
        let key_entropy = [remote_device_id.as_slice(), remote_genesis_hash.as_slice()].concat();
        let remote_kp = SignatureKeyPair::generate_from_entropy(&key_entropy)
            .map_err(|e| DsmError::crypto("Failed to generate remote test keypair", Some(e)))
            .unwrap();
        DsmVerifiedContact {
            alias: alias.to_string(),
            device_id: remote_device_id,
            genesis_hash: remote_genesis_hash,
            public_key: if with_pubkey {
                remote_kp.public_key().to_vec()
            } else {
                Vec::new()
            },
            genesis_material: vec![0x42; 64],
            chain_tip: None,
            chain_tip_smt_proof: None,
            genesis_verified_online: genesis_verified,
            verified_at_commit_height: 1,
            added_at_commit_height: 1,
            last_updated_commit_height: 1,
            verifying_storage_nodes: vec![],
            ble_address: None,
        }
    }

    fn signed_transfer_op(kp: &SignatureKeyPair, message: &str, nonce: u8) -> Operation {
        let mut op = Operation::Transfer {
            policy_commit: [0u8; 32],
            token_id: b"ERA".to_vec(),
            to_device_id: vec![9u8; 32],
            amount: Balance::from_state(1, [0u8; 32]),
            mode: TransactionMode::Bilateral,
            nonce: vec![nonce; 8],
            verification: VerificationType::Standard,
            pre_commit: None,
            recipient: vec![9u8; 32],
            to: b"b32recipient".to_vec(),
            message: message.to_string(),
            signature: Vec::new(),
            authority_policy: None,
        };

        let sig = kp.sign(&op.to_bytes()).expect("sign transfer");
        if let Operation::Transfer { signature, .. } = &mut op {
            *signature = sig;
        }

        op
    }

    #[tokio::test]
    async fn btm_new_initial_state() {
        let (manager, _kp) = make_manager();
        assert_eq!(manager.list_relationships().len(), 0);
        assert_eq!(manager.list_pending_commitments().len(), 0);
        assert!(manager.get_current_ticks() > 0);
        assert_eq!(manager.local_genesis_hash(), make_manager_ids().1);
    }

    #[tokio::test]
    async fn establish_relationship_missing_contact() {
        let (mut manager, _kp) = make_manager();
        let remote = make_remote_ids().0;
        let res = manager.establish_relationship(&remote).await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn establish_relationship_requires_genesis_verified() {
        let (mut manager, _kp) = make_manager();
        let contact = make_verified_contact("Alice", true, false);
        // Add contact (pre-verified API allows any, but BTM enforces on use)
        manager.add_verified_contact(contact.clone()).expect("add");
        let res = manager.establish_relationship(&contact.device_id).await;
        assert!(matches!(res, Err(DsmError::InvalidContact(_))));
    }

    #[tokio::test]
    async fn establish_relationship_success_and_integrity() {
        let (mut manager, _kp) = make_manager();
        let contact = make_verified_contact("Bob", true, true);
        let remote_id = contact.device_id;
        let remote_genesis = contact.genesis_hash;
        manager.add_verified_contact(contact).expect("add");

        let anchor = manager
            .establish_relationship(&remote_id)
            .await
            .expect("establish");
        assert_eq!(anchor.local_device_id, make_manager_ids().0);
        assert_eq!(anchor.local_genesis_hash, make_manager_ids().1);
        assert_eq!(anchor.remote_device_id, remote_id);
        assert_eq!(anchor.remote_genesis_hash, remote_genesis);
        // After establishing relationship, the manager sets the shared chain tip to
        // the deterministic initial relationship tip (h_0).
        let initial_tip = initial_relationship_chain_tip(
            &make_manager_ids().0,
            &make_manager_ids().1,
            &remote_id,
            &remote_genesis,
        );
        assert_eq!(anchor.chain_tip, initial_tip);
        let expected = BilateralRelationshipAnchor::generate_mutual_anchor_hash(
            &anchor.local_genesis_hash,
            &anchor.remote_genesis_hash,
        );
        assert_eq!(expected, anchor.mutual_anchor_hash);

        // Stored in manager and integrity verifies
        assert!(manager.get_relationship(&remote_id).is_some());
        assert!(manager.verify_relationship_integrity(&remote_id).unwrap());
    }

    #[tokio::test]
    async fn create_precommitment_without_relationship() {
        let (mut manager, _kp) = make_manager();
        let op = signed_transfer_op(&manager.signature_keypair, "m", 1);
        let res = manager
            .create_bilateral_precommitment(&make_remote_ids().0, op, 100)
            .await;
        assert!(matches!(res, Err(DsmError::RelationshipNotFound(_))));
    }

    #[tokio::test]
    async fn create_precommitment_success_and_pending() {
        let (mut manager, _kp) = make_manager();
        let contact = make_verified_contact("Carol", true, true);
        let remote_id = contact.device_id;
        manager.add_verified_contact(contact).expect("add");
        manager
            .establish_relationship(&remote_id)
            .await
            .expect("establish");

        let op = signed_transfer_op(&manager.signature_keypair, "m", 2);
        let pre = manager
            .create_bilateral_precommitment(&remote_id, op.clone(), 300)
            .await
            .expect("pre");
        assert!(manager.has_pending_commitment(&pre.bilateral_commitment_hash));
        assert!(pre.verify().unwrap());
        assert!(pre
            .verify_local_signature(manager.signature_keypair.public_key())
            .unwrap());
    }

    #[tokio::test]
    async fn finalize_offline_transfer_removes_pending() {
        let (mut manager, _kp) = make_manager();
        let contact = make_verified_contact("Eve", true, true);
        let remote_id = contact.device_id;
        manager.add_verified_contact(contact).expect("add");
        manager
            .establish_relationship(&remote_id)
            .await
            .expect("establish");
        let op = signed_transfer_op(&manager.signature_keypair, "m", 4);
        let pre = manager
            .prepare_offline_transfer(&remote_id, op, 500)
            .await
            .expect("prepare");
        assert!(manager.has_pending_commitment(&pre.bilateral_commitment_hash));

        let mut smt = crate::merkle::sparse_merkle_tree::SparseMerkleTree::new(256);
        let result = manager
            .finalize_offline_transfer(
                &remote_id,
                &pre.bilateral_commitment_hash,
                b"accept",
                &mut smt,
                crate::types::device_state::ValueCapability::Yes,
            )
            .await
            .expect("finalize");
        assert!(result.completed_offline);
        assert!(!manager.has_pending_commitment(&pre.bilateral_commitment_hash));
    }

    #[tokio::test]
    async fn finalize_with_offline_bearer_required_attests_or_fails_closed() {
        use crate::attestation::compute_anchor_set_id;
        use crate::crypto::anchor_transport::{AnchorTransport, MockAnchorTransport};
        use crate::types::device_state::ValueCapability;
        use crate::types::operations::{AuthorityMode, AuthorityPolicy};
        use std::sync::Arc;

        // Admit a hardware anchor and discover its canonical set id.
        let anchor: Arc<dyn AnchorTransport> = Arc::new(MockAnchorTransport::from_seed([7u8; 32]));
        let rec = anchor.get_identity().await.unwrap();
        let policy_id = [0x11u8; 32];
        let anchor_set_id = compute_anchor_set_id(&[rec.id_anchor]);

        // An OFFLINE_BEARER_REQUIRED transfer, signed AFTER the policy is set (bound into the bytes).
        let build_obr_op = |kp: &SignatureKeyPair| -> Operation {
            let mut op = Operation::Transfer {
                policy_commit: [0u8; 32],
                token_id: b"ERA".to_vec(),
                to_device_id: vec![9u8; 32],
                amount: Balance::from_state(1, [0u8; 32]),
                mode: TransactionMode::Bilateral,
                nonce: vec![3u8; 8],
                verification: VerificationType::Standard,
                pre_commit: None,
                recipient: vec![9u8; 32],
                to: b"b32recipient".to_vec(),
                message: "obr".to_string(),
                signature: Vec::new(),
                authority_policy: Some(AuthorityPolicy {
                    mode: AuthorityMode::OfflineBearerRequired,
                    policy_id,
                    anchor_set_id,
                }),
            };
            let sig = kp.sign(&op.to_bytes()).expect("sign");
            if let Operation::Transfer { signature, .. } = &mut op {
                *signature = sig;
            }
            op
        };

        // Happy path: manager WITH the admitted anchor → finalize attests.
        let (m, kp) = make_manager();
        let mut manager = m.with_anchor_transport(anchor.clone());
        let contact = make_verified_contact("Island", true, true);
        let remote_id = contact.device_id;
        manager.add_verified_contact(contact).expect("add");
        manager
            .establish_relationship(&remote_id)
            .await
            .expect("establish");
        let pre = manager
            .prepare_offline_transfer(&remote_id, build_obr_op(&kp), 500)
            .await
            .expect("prepare");
        let mut smt = crate::merkle::sparse_merkle_tree::SparseMerkleTree::new(256);
        let result = manager
            .finalize_offline_transfer(
                &remote_id,
                &pre.bilateral_commitment_hash,
                b"accept",
                &mut smt,
                ValueCapability::Yes,
            )
            .await
            .expect("attested finalize");
        let att = result
            .island_attestation
            .expect("an OFFLINE_BEARER_REQUIRED transfer must carry an attestation receipt");
        assert_eq!(att.id_anchor_set, anchor_set_id);
        assert_eq!(att.policy_id, policy_id);
        // The receipt reconstructs the proof digest folded into the chain tip (reject-6 basis).
        let _ = anchor_proof_hash_from_receipt(&att);

        // Fail-closed: the SAME OBR transfer through a manager with NO admitted anchor hard-rejects
        // (the operation REQUIRES the proof — never a silent downgrade to online).
        let (bare, kp2) = make_manager();
        let mut bare = bare;
        let contact2 = make_verified_contact("NoIsland", true, true);
        let remote2 = contact2.device_id;
        bare.add_verified_contact(contact2).expect("add");
        bare.establish_relationship(&remote2)
            .await
            .expect("establish");
        let pre2 = bare
            .prepare_offline_transfer(&remote2, build_obr_op(&kp2), 500)
            .await
            .expect("prepare");
        let mut smt2 = crate::merkle::sparse_merkle_tree::SparseMerkleTree::new(256);
        let res2 = bare
            .finalize_offline_transfer(
                &remote2,
                &pre2.bilateral_commitment_hash,
                b"accept",
                &mut smt2,
                ValueCapability::Yes,
            )
            .await;
        assert!(
            res2.is_err(),
            "OFFLINE_BEARER_REQUIRED with no admitted anchor must hard-reject (fail-closed)"
        );
    }

    #[tokio::test]
    async fn require_contact_signing_key_missing_pubkey() {
        let (mut manager, _kp) = make_manager();
        let contact = make_verified_contact("Frank", false, true); // no public key
        let remote_id = contact.device_id;
        manager.add_verified_contact(contact).expect("add");
        let res = manager.establish_relationship(&remote_id).await;
        assert!(matches!(res, Err(DsmError::InvalidContact(_))));
    }

    #[tokio::test]
    async fn create_precommitment_requires_signing_key_when_relationship_exists() {
        let (mut manager, _kp) = make_manager();
        // Add contact without public key but keep genesis_verified true so
        // ensure_relationship_for_sender can create a relationship anchor.
        let contact = make_verified_contact("Grace", false, true);
        let remote_id = contact.device_id;
        manager.add_verified_contact(contact).expect("add");

        // Relationship can be initialized tolerantly for sender flows
        manager
            .ensure_relationship_for_sender(&remote_id)
            .expect("ensure rel");

        // But creating a precommitment must require the signing key and therefore fail
        let op = signed_transfer_op(&manager.signature_keypair, "m", 5);
        let res = manager
            .create_bilateral_precommitment(&remote_id, op, 100)
            .await;
        assert!(matches!(res, Err(DsmError::InvalidContact(_))));
    }

    // Regression for issue #191: sign_commitment must be fail-closed.
    // Previous bug: signer errors silently returned `Vec::new()`. The new
    // signature is `Result<Vec<u8>, DsmError>`, so the only way to obtain
    // an empty signature is to construct one explicitly — the function
    // itself cannot emit one. This test pins both the success contract
    // (non-empty bytes wrapped in Ok) and the return-type shape.
    #[tokio::test]
    async fn sign_commitment_returns_non_empty_signature_on_success() {
        let (manager, _kp) = make_manager();
        let commitment_hash = [0xABu8; 32];
        let sig = manager
            .sign_commitment(&commitment_hash)
            .expect("sign_commitment must succeed with a valid keypair");
        assert!(
            !sig.is_empty(),
            "sign_commitment must never return an empty signature on the Ok path"
        );
    }
}
