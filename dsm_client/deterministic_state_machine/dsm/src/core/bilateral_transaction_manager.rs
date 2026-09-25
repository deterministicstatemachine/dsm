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
use crate::core::chain_tip_store::ChainTipStore;
use crate::crypto::canonical_lp;
use crate::crypto::signatures::SignatureKeyPair;
use crate::merkle::sparse_merkle_tree::empty_leaf;
use crate::types::contact_types::DsmVerifiedContact;
use crate::types::device_state::BalanceDelta;
use crate::types::error::{DeterministicSafetyClass, DsmError};
use crate::types::operations::Operation;
use crate::core::utility::labeling;
use crate::common::domain_tags::{
    TAG_BILATERAL_SESSION, TAG_FUSED_ANCHOR_STATE_LEAF, TAG_SMT_KEY, TAG_TIP,
};

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
    /// h_n^{A↔B} — THE single shared relationship chain tip.
    /// Both parties MUST agree on this value. Divergence = Tripwire.
    pub chain_tip: [u8; 32],
}
impl BilateralRelationshipAnchor {
    pub fn new(
        local_device_id: [u8; 32],
        local_genesis_hash: [u8; 32],
        remote_device_id: [u8; 32],
        remote_genesis_hash: [u8; 32],
    ) -> Self {
        Self {
            local_device_id,
            local_genesis_hash,
            remote_device_id,
            remote_genesis_hash,
            chain_tip: empty_leaf(),
        }
    }
}

/// `h_0` of a relationship: `H(DSM/bilateral-session; G_lo ‖ DevID_lo ‖ G_hi ‖ DevID_hi)`,
/// ordered by device id, so both parties derive the same value. The one
/// definition; every caller uses this.
pub fn initial_relationship_chain_tip(
    local_device_id: &[u8; 32],
    local_genesis_hash: &[u8; 32],
    remote_device_id: &[u8; 32],
    remote_genesis_hash: &[u8; 32],
) -> [u8; 32] {
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
    crate::commitments::precommit::branch_commitment_hash(h_n, op_bytes, entropy)
}

/// §16.6: h_{n+1} = BLAKE3("DSM/tip\0" || h_n || op || e || σ) — successor shared tip.
/// Both parties compute this identically from shared inputs. Deterministic and symmetric —
/// it carries no device-private state (the fused anchor state is committed by its own
/// per-device SMT leaf, not folded here).
pub fn compute_successor_tip(
    h_n: &[u8; 32],
    op_bytes: &[u8],
    entropy: &[u8],
    receipt_digest: &[u8; 32],
) -> [u8; 32] {
    let mut h = dsm_domain_hasher(TAG_TIP);
    h.update(h_n);
    h.update(op_bytes);
    h.update(entropy);
    h.update(receipt_digest);
    bytes32(h.finalize().as_bytes())
}

/// SMT key of the single per-device anchor-state leaf: `H("DSM/fused-anchor-state-leaf/v1" ‖ B)`.
///
/// One stable key per device (the fused anchor is device-level — one appliance, one counter),
/// bound to the immutable anchor bundle `B`. Its VALUE is the current v2 anchor-state leaf
/// `anchor_state_leaf(B, h_i, u_i)` (computed by the anchor-core-holding caller), bootstrapped
/// when the anchor is attached and replaced old→successor on every bearer transfer's device-SMT
/// advance. So `R_i` proves `key → L_i` and `R_{i+1}` proves the same `key → L_{i+1}`. Never
/// keyed by relationship id, root, frontier, or counter.
pub fn anchor_state_leaf_key(bundle: &[u8; 32]) -> [u8; 32] {
    let mut h = dsm_domain_hasher(TAG_FUSED_ANCHOR_STATE_LEAF);
    h.update(bundle);
    bytes32(h.finalize().as_bytes())
}

/// Receiver-side (v2 Software-Authority): verify that `device_root` (`R_i`/`R_{i+1}`) commits the
/// given anchor-state leaf VALUE `leaf` — the anchor-core v2 leaf `anchor_state_leaf(B, h_i, u_i)`
/// the acceptance predicate already computed — at the stable per-device key `anchor_state_leaf_key(B)`,
/// via the release's carried SMT inclusion `proof`. Value-agnostic (dsm never recomputes the v2 leaf,
/// so it needs no anchor-core dep). Fail-closed on any mismatch (wrong key/value/root) or an empty
/// proof — so a release with no attached `Π` routes to online recovery.
pub fn verify_anchor_state_leaf(
    device_root: &[u8; 32],
    bundle: &[u8; 32],
    leaf: &[u8; 32],
    proof_bytes: &[u8],
) -> bool {
    use crate::merkle::sparse_merkle_tree::{SmtInclusionProof, SparseMerkleTree};
    let key = anchor_state_leaf_key(bundle);
    let Some(proof) = SmtInclusionProof::from_bytes(proof_bytes) else {
        return false;
    };
    proof.key == key
        && proof.value == Some(*leaf)
        && SparseMerkleTree::verify_proof_against_root(&proof, device_root)
}

/// Producer-side (v2): set the per-device anchor-state leaf to the given VALUE `leaf` (the anchor-core
/// v2 leaf `anchor_state_leaf(B, h_i, u_i)`, computed by the caller — the SDK has anchor-core) at the
/// stable per-device key, and return its inclusion proof against the resulting device root. So the
/// returned proof binds the same root the transfer commits; the receiver checks it with
/// [`verify_anchor_state_leaf`].
pub fn set_anchor_state_leaf_value(
    smt: &mut crate::merkle::sparse_merkle_tree::SparseMerkleTree,
    bundle: &[u8; 32],
    leaf: &[u8; 32],
) -> Result<Vec<u8>, DsmError> {
    let key = anchor_state_leaf_key(bundle);
    smt.update_leaf(&key, leaf);
    let proof = smt
        .get_inclusion_proof(&key, 256)
        .map_err(|e| DsmError::invalid_operation(format!("anchor-state proof: {e}")))?;
    Ok(proof.to_bytes())
}

/// Whether an operation declares it requires offline-bearer authority (the canonical per-Operation
/// trigger). Only these transitions run the anchor gate; all others finalize unchanged.
/// The bytes a party's signature over the step `commitment_hash` covers: the
/// proposer's σ_A and the receiver's acceptance σ_B alike.
pub fn bilateral_sign_message(commitment_hash: &[u8; 32]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(19 + 32);
    msg.extend_from_slice(b"DSM/bilateral-sign\0");
    msg.extend_from_slice(commitment_hash);
    msg
}

pub fn operation_requires_offline_bearer(op: &crate::types::operations::Operation) -> bool {
    use crate::types::operations::{AuthorityMode, Operation};
    matches!(
        op,
        Operation::Transfer { authority_policy: Some(ap), .. }
            if ap.mode == AuthorityMode::OfflineBearerRequired
    )
}

// -------------------- Bilateral Pre-Commitment (bytes-only) --------------------
#[derive(Clone, Debug)]
pub struct BilateralPreCommitment {
    /// `H(DSM/bilateral-session; lp(h_n) ‖ lp(op))`: the step this
    /// precommitment proposes, bound to the relationship tip it extends.
    pub bilateral_commitment_hash: [u8; 32],
    pub operation: Operation,
    /// The relationship tip `h_n` the step extends (Tripwire, §6.1). At
    /// finalize the current tip must still be this one; otherwise the parent
    /// was already consumed.
    pub parent_tip: [u8; 32],
}
impl BilateralPreCommitment {
    pub fn new(parent_tip: [u8; 32], operation: Operation) -> Self {
        let mut h = dsm_domain_hasher(TAG_BILATERAL_SESSION);
        canonical_lp::write_lp(&mut h, &parent_tip);
        canonical_lp::write_lp(&mut h, &operation.to_bytes());
        let mut bilateral_commitment_hash = [0u8; 32];
        bilateral_commitment_hash.copy_from_slice(h.finalize().as_bytes());
        Self {
            bilateral_commitment_hash,
            operation,
            parent_tip,
        }
    }
}

// -------------------- Transaction Manager --------------------
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
    /// Bilateral precommitment hash, for post-commit cleanup via
    /// [`BilateralTransactionManager::consume_pre_commitment`].
    pub pre_commitment_hash: [u8; 32],
    /// Offline-bearer fused-anchor-state leaf update to commit atomically with the relationship
    /// leaf (Software-Authority / Hardware-Identity). `Some` iff this is a bearer transfer whose sender drove the
    /// appliance; the SAME value the sender's `simulate_advance_for_confirm` used to build the wire
    /// proofs, so the canonical committed root matches (both-or-neither). `None` for ordinary transfers.
    pub anchor_leaf: Option<crate::types::device_state::AnchorLeafUpdate>,
    /// Offline-cash allocation debit for an offline-bearer transfer: the value is drawn from the
    /// device-bound allocation instead of the online balance, so `deltas` is empty and this is `Some`.
    /// Carried forward from the confirm-build seam (stashed on the session) — NEVER reconstructed
    /// from `anchor_leaf`, whose key is `H(B)` and cannot recover the bundle. Threaded identically
    /// into the determinism-guard sim and the canonical commit so all three sender roots byte-match.
    pub offline_spend: Option<crate::types::device_state::OfflineSpend>,
}

#[derive(Debug)]
pub struct BilateralTransactionManager {
    contact_manager: DsmContactManager,
    relationships: HashMap<[u8; 32], BilateralRelationshipAnchor>, // key = remote_device_id
    pending_commitments: HashMap<[u8; 32], BilateralPreCommitment>, // key = bilateral_commitment_hash
    signature_keypair: SignatureKeyPair,
    local_device_id: [u8; 32],
    local_genesis_hash: [u8; 32],
    chain_tip_store: std::sync::Arc<dyn ChainTipStore>,
}

impl BilateralTransactionManager {
    pub fn new(
        contact_manager: DsmContactManager,
        signature_keypair: SignatureKeyPair,
        local_device_id: [u8; 32],
        local_genesis_hash: [u8; 32],
        chain_tip_store: std::sync::Arc<dyn ChainTipStore>,
    ) -> Self {
        Self {
            contact_manager,
            relationships: HashMap::new(),
            pending_commitments: HashMap::new(),
            signature_keypair,
            local_device_id,
            local_genesis_hash,
            chain_tip_store,
        }
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
    /// intra-device consistency tripwire inside `prepare_bilateral_advance`
    /// fires as a self-inflicted wound.
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
        }
        if let Some(contact_mut) = self.contact_manager.get_contact_mut(remote_device_id) {
            contact_mut.chain_tip = Some(new_tip);
        }
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
        let sig = self
            .signature_keypair
            .sign(&bilateral_sign_message(commitment_hash))
            .map_err(|e| {
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

    /// The bytes a refusal of the proposal `commitment_hash` signs: the
    /// proposal, the device refusing it and its reason.
    fn rejection_message(
        commitment_hash: &[u8; 32],
        rejector_device_id: &[u8; 32],
        reason: &str,
    ) -> Vec<u8> {
        let mut msg = Vec::with_capacity(21 + 64 + reason.len());
        msg.extend_from_slice(b"DSM/bilateral-reject\0");
        msg.extend_from_slice(commitment_hash);
        msg.extend_from_slice(rejector_device_id);
        msg.extend_from_slice(reason.as_bytes());
        msg
    }

    /// This device's signature refusing the proposal `commitment_hash`.
    pub fn sign_rejection(
        &self,
        commitment_hash: &[u8; 32],
        reason: &str,
    ) -> Result<Vec<u8>, DsmError> {
        self.signature_keypair.sign(&Self::rejection_message(
            commitment_hash,
            &self.local_device_id,
            reason,
        ))
    }

    /// A refusal of a proposal holds only when the device it was sent to
    /// signed it, under the key that device's contact pins.
    pub fn verify_rejection(
        &self,
        rejector_device_id: &[u8; 32],
        commitment_hash: &[u8; 32],
        reason: &str,
        signature: &[u8],
    ) -> Result<(), DsmError> {
        if signature.is_empty() {
            return Err(DsmError::InvalidOperation(
                "a rejection carries its rejector's signature".into(),
            ));
        }
        let pinned_key = &self
            .contact_manager
            .get_contact(rejector_device_id)
            .ok_or_else(|| DsmError::InvalidOperation("the rejector is not a contact".into()))?
            .public_key;
        let valid = SignatureKeyPair::verify_raw(
            &Self::rejection_message(commitment_hash, rejector_device_id, reason),
            signature,
            pinned_key,
        )
        .map_err(|e| DsmError::InvalidOperation(format!("rejection signature: {e}")))?;
        if !valid {
            return Err(DsmError::InvalidOperation(
                "the rejection is not signed by the rejector's pinned key".into(),
            ));
        }
        Ok(())
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
        let contact_genesis_hash = contact.genesis_hash;
        // Strict: a relationship established for bilateral transfer needs the
        // counterparty's signing key, which verifies its acceptance proofs.
        Self::require_signing_key(contact)?;
        // The relationship's tip is the one its store holds: adding the contact
        // committed h_0 there, and each finalized step since has advanced it. A
        // relationship the store does not hold is not established here.
        let tip = self
            .chain_tip_store
            .get_contact_chain_tip(remote_device_id)?
            .ok_or_else(|| {
                DsmError::InvalidState(format!(
                    "relationship {}: the chain-tip store holds no tip; a relationship is \
                     established when its contact is added",
                    labeling::hash_to_short_id(remote_device_id)
                ))
            })?;
        let mut anchor = BilateralRelationshipAnchor::new(
            self.local_device_id,
            self.local_genesis_hash,
            *remote_device_id,
            contact_genesis_hash,
        );
        anchor.chain_tip = tip;
        if let Some(contact) = self.contact_manager.get_contact_mut(remote_device_id) {
            contact.chain_tip = Some(tip);
        }

        self.relationships.insert(*remote_device_id, anchor.clone());
        Ok(anchor)
    }

    pub async fn create_bilateral_precommitment(
        &mut self,
        remote_device_id: &[u8; 32],
        operation: Operation,
    ) -> Result<BilateralPreCommitment, DsmError> {
        let relationship = self
            .relationships
            .get(remote_device_id)
            .ok_or_else(|| DsmError::RelationshipNotFound("remote device".into()))?;
        // The step extends the relationship's current tip (Tripwire, §6.1).
        let parent_tip = relationship.chain_tip;
        // Strict protocol: a bilateral precommitment requires the counterparty's
        // signing public key in the verified contact record — it verifies the
        // acceptance proof this step finalizes on. Contact exchange / online
        // verification comes before an offline prepare.
        self.require_contact_signing_key(remote_device_id)?;
        let bilateral = BilateralPreCommitment::new(parent_tip, operation);
        self.pending_commitments
            .insert(bilateral.bilateral_commitment_hash, bilateral.clone());
        Ok(bilateral)
    }

    fn require_contact_signing_key(&self, remote_device_id: &[u8; 32]) -> Result<(), DsmError> {
        let c = self
            .contact_manager
            .get_contact(remote_device_id)
            .ok_or_else(|| DsmError::RelationshipNotFound("remote device".into()))?;
        Self::require_signing_key(c)
    }

    fn require_signing_key(contact: &DsmVerifiedContact) -> Result<(), DsmError> {
        if contact.public_key.is_empty() {
            return Err(DsmError::InvalidContact(
                "Missing remote signing public key".into(),
            ));
        }
        Ok(())
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

        let valid = SignatureKeyPair::verify_raw(
            &bilateral_sign_message(pre_commitment_hash),
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
    ) -> Result<BilateralPreCommitment, DsmError> {
        info!("Phase 1: prepare offline");
        self.create_bilateral_precommitment(remote_device_id, operation)
            .await
    }

    /// Prepare (but do not commit) a bilateral offline transfer.
    ///
    /// Runs the §6.1 tripwire checks, then returns a
    /// [`PreparedBilateralAdvance`] handoff that the caller commits via
    /// `AppRouter::execute_on_relationship_for_bilateral` — which routes
    /// through the canonical `prepare_advance_relationship → commit_advance`
    /// chokepoint on the Per-Device SMT (§2.2).
    ///
    /// Body:
    ///   1. Refresh shared chain tip from persistent store.
    ///   2. §6.1 tripwire: anchor tip must equal the precommitment's `parent_tip`.
    ///   3. Tripwire: anchor tip must equal persisted contact tip.
    ///   4. Emit `PreparedBilateralAdvance`.
    ///
    /// No entropy is resolved here. The transition's one entropy is derived
    /// by Core inside `DeviceState::advance` (Part VII step 3) when the
    /// handoff is committed; the receipt hashes are computed from that
    /// outcome, never from a value this manager chose.
    ///
    /// No SMT mutation. No anchor mutation. No `pending_commitments` removal
    /// — caller calls [`Self::consume_pre_commitment`] after advance commit.
    #[allow(clippy::too_many_arguments)]
    pub async fn prepare_bilateral_advance(
        &mut self,
        remote_device_id: &[u8; 32],
        pre_commitment_hash: &[u8; 32],
        receiver_acceptance_proof: &[u8],
        sender_deltas: Vec<BalanceDelta>,
        anchor_leaf: Option<crate::types::device_state::AnchorLeafUpdate>,
        offline_spend: Option<crate::types::device_state::OfflineSpend>,
    ) -> Result<PreparedBilateralAdvance, DsmError> {
        info!("prepare_bilateral_advance: tripwire (no SMT/anchor mutation)");

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
        if let Some(tip) = self
            .chain_tip_store
            .get_contact_chain_tip(remote_device_id)?
        {
            if let Some(anchor_mut) = self.relationships.get_mut(remote_device_id) {
                anchor_mut.chain_tip = tip;
            }
            if let Some(contact_mut) = self.contact_manager.get_contact_mut(remote_device_id) {
                contact_mut.chain_tip = Some(tip);
            }
            anchor.chain_tip = tip;
        }

        // ===== TRIPWIRE ENFORCEMENT (§6.1) =====
        // Parent tip at precommit creation must equal current anchor tip; else
        // another transition already consumed the parent hash and finalizing
        // would violate the Tripwire theorem.
        if anchor.chain_tip != pre.parent_tip {
            let class = DeterministicSafetyClass::ParentConsumed;
            log::warn!(
                "[BTM][TRIPWIRE:precommit-parent-consumed] anchor={} precommit_tip={} class={}",
                labeling::hash_to_short_id(&anchor.chain_tip),
                labeling::hash_to_short_id(&pre.parent_tip),
                class.as_str()
            );
            error!(
                "[BTM] Deterministic safety rejection [{}]: chain_tip={} precommit_tip={}",
                class.as_str(),
                labeling::hash_to_short_id(&anchor.chain_tip),
                labeling::hash_to_short_id(&pre.parent_tip)
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
                        labeling::hash_to_short_id(&pre.parent_tip),
                        match self.chain_tip_store.get_contact_chain_tip(remote_device_id) {
                            Ok(Some(t)) => labeling::hash_to_short_id(&t),
                            Ok(None) => "none".to_string(),
                            Err(e) => format!("unreadable: {e}"),
                        },
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

        let rel_key = compute_smt_key(&self.local_device_id, remote_device_id);

        Ok(PreparedBilateralAdvance {
            rel_key,
            counterparty_devid: *remote_device_id,
            operation: pre.operation,
            deltas: sender_deltas,
            parent_tip: anchor.chain_tip,
            pre_commitment_hash: *pre_commitment_hash,
            anchor_leaf,
            offline_spend,
        })
    }

    /// Hold again, after a restart, the precommitment a persisted session
    /// proposed: the step `operation` on `parent_tip`. It is held only if it
    /// is the step the session names — its commitment hash must be
    /// `commitment_hash` — and on a relationship this manager has
    /// established.
    pub fn restore_pre_commitment(
        &mut self,
        remote_device_id: &[u8; 32],
        parent_tip: [u8; 32],
        operation: Operation,
        commitment_hash: &[u8; 32],
    ) -> Result<(), DsmError> {
        if !self.relationships.contains_key(remote_device_id) {
            return Err(DsmError::RelationshipNotFound("remote device".into()));
        }
        let pre = BilateralPreCommitment::new(parent_tip, operation);
        if &pre.bilateral_commitment_hash != commitment_hash {
            return Err(DsmError::invalid_operation(
                "the persisted step does not hash to the session's commitment",
            ));
        }
        self.pending_commitments.insert(*commitment_hash, pre);
        Ok(())
    }

    /// Drop a precommitment from the pending set — after its bilateral
    /// advance commits, or when its session ends without one — returning it
    /// if it was pending.
    pub fn consume_pre_commitment(
        &mut self,
        pre_commitment_hash: &[u8; 32],
    ) -> Option<BilateralPreCommitment> {
        self.pending_commitments.remove(pre_commitment_hash)
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
    use crate::types::operations::{Operation, TransactionMode};
    use crate::types::token_types::Balance;
    use tokio; // for #[tokio::test]

    #[test]
    fn successor_tip_is_the_symmetric_canonical_formula() {
        let h_n = [1u8; 32];
        let op = b"op-bytes";
        let e = [2u8; 32];
        let sigma = [3u8; 32];
        // The successor tip is exactly H("DSM/tip" ‖ h_n ‖ op ‖ e ‖ σ) — no anchor fold.
        let base = compute_successor_tip(&h_n, op, &e, &sigma);
        let explicit = {
            let mut h = dsm_domain_hasher(TAG_TIP);
            h.update(&h_n);
            h.update(op);
            h.update(&e);
            h.update(&sigma);
            bytes32(h.finalize().as_bytes())
        };
        assert_eq!(base, explicit);
    }

    #[test]
    fn anchor_state_leaf_inclusion_round_trips_and_rejects_tamper() {
        use crate::merkle::sparse_merkle_tree::SparseMerkleTree;
        let b = [0xB1u8; 32];
        // Opaque v2 anchor-state leaf VALUES (anchor-core computes the real ones).
        let leaf0 = [0xC0u8; 32];
        let leaf1 = [0xC1u8; 32];

        let mut smt = SparseMerkleTree::new();
        // Bootstrap leaf_0, then the "parent" proof against prev_root.
        let parent_proof = set_anchor_state_leaf_value(&mut smt, &b, &leaf0).expect("set0");
        let prev_root = *smt.root();
        assert!(verify_anchor_state_leaf(
            &prev_root,
            &b,
            &leaf0,
            &parent_proof
        ));

        // Advance the leaf to the successor leaf_1; "child" proof vs next_root.
        let child_proof = set_anchor_state_leaf_value(&mut smt, &b, &leaf1).expect("set1");
        let next_root = *smt.root();
        assert!(verify_anchor_state_leaf(
            &next_root,
            &b,
            &leaf1,
            &child_proof
        ));

        // Fail-closed rejections:
        // wrong leaf value under next_root.
        assert!(!verify_anchor_state_leaf(
            &next_root,
            &b,
            &leaf0,
            &child_proof
        ));
        // right value but wrong root (child proof does not verify under prev_root).
        assert!(!verify_anchor_state_leaf(
            &prev_root,
            &b,
            &leaf1,
            &child_proof
        ));
        // parent (old) state is NOT committed by next_root.
        assert!(!verify_anchor_state_leaf(
            &next_root,
            &b,
            &leaf0,
            &parent_proof
        ));
        // wrong bundle (wrong leaf KEY) rejects even with the right value + root.
        assert!(!verify_anchor_state_leaf(
            &next_root,
            &[9u8; 32],
            &leaf1,
            &child_proof
        ));
        // an empty proof rejects (a release with no attached proof routes online).
        assert!(!verify_anchor_state_leaf(&next_root, &b, &leaf1, &[]));
    }

    #[test]
    fn anchor_state_leaf_key_is_stable_per_bundle() {
        let b = [1u8; 32];
        let k = anchor_state_leaf_key(&b);
        // One stable key per device bundle (value changes, key does not).
        assert_eq!(k, anchor_state_leaf_key(&b));
        // Different bundle -> different key.
        assert_ne!(k, anchor_state_leaf_key(&[2u8; 32]));
    }

    fn make_manager_ids() -> ([u8; 32], [u8; 32]) {
        ([1u8; 32], [2u8; 32])
    }

    fn make_remote_ids() -> ([u8; 32], [u8; 32]) {
        ([9u8; 32], [7u8; 32]) // (device_id, genesis_hash)
    }

    type MemoryStore = crate::core::chain_tip_store::memory::InMemoryChainTipStore;

    fn make_manager() -> (BilateralTransactionManager, SignatureKeyPair) {
        let (manager, kp, _store) = make_manager_with_store();
        (manager, kp)
    }

    fn make_manager_with_store() -> (
        BilateralTransactionManager,
        SignatureKeyPair,
        std::sync::Arc<MemoryStore>,
    ) {
        let (local_device_id, local_genesis_hash) = make_manager_ids();
        let contact_manager = DsmContactManager::new(local_device_id);
        // Generate proper cryptographic keypair based on device and genesis identity
        let key_entropy = [local_device_id.as_slice(), local_genesis_hash.as_slice()].concat();
        let kp = SignatureKeyPair::generate_from_entropy(&key_entropy)
            .map_err(|e| DsmError::crypto("Failed to generate test keypair", Some(e)))
            .unwrap();
        let store = std::sync::Arc::new(MemoryStore::new());
        let manager = BilateralTransactionManager::new(
            contact_manager,
            kp.clone(),
            local_device_id,
            local_genesis_hash,
            store.clone(),
        );
        (manager, kp, store)
    }

    /// The contact is added the way the SDK adds one: cached for the manager,
    /// and its relationship recorded in the store at the h_0 both sides derive.
    fn add_contact(
        manager: &mut BilateralTransactionManager,
        store: &MemoryStore,
        contact: DsmVerifiedContact,
    ) -> [u8; 32] {
        let (local_device_id, local_genesis_hash) = make_manager_ids();
        let h_0 = initial_relationship_chain_tip(
            &local_device_id,
            &local_genesis_hash,
            &contact.device_id,
            &contact.genesis_hash,
        );
        store.record_contact_added(contact.device_id, h_0);
        manager.add_verified_contact(contact).expect("add");
        h_0
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
            chain_tip: None,
            genesis_verified_online: genesis_verified,
            verifying_storage_nodes: vec![],
            ble_address: None,
        }
    }

    fn signed_transfer_op(kp: &SignatureKeyPair, message: &str, nonce: u8) -> Operation {
        let mut op = Operation::Transfer {
            policy_commit: [0u8; 32],
            token_id: b"ERA".to_vec(),
            to_device_id: vec![9u8; 32],
            amount: Balance::amount(1),
            mode: TransactionMode::Bilateral,
            nonce: vec![nonce; 8],
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

    /// A relationship its store does not hold is not established, and
    /// establishing writes no tip of its own: nothing is seeded.
    #[tokio::test]
    async fn establish_relationship_refuses_a_relationship_its_store_does_not_hold() {
        let (mut manager, _kp, store) = make_manager_with_store();
        let contact = make_verified_contact("Bob", true, true);
        let remote_id = contact.device_id;
        manager.add_verified_contact(contact).expect("add");

        assert!(
            manager.establish_relationship(&remote_id).await.is_err(),
            "a relationship the store does not hold must be refused"
        );
        assert!(
            manager.get_relationship(&remote_id).is_none(),
            "a refused relationship leaves no anchor behind"
        );
        assert!(
            store
                .get_contact_chain_tip(&remote_id)
                .expect("read")
                .is_none(),
            "establishing seeded a tip"
        );
    }

    /// The relationship is established on the tip its store holds, not on
    /// the h_0 the manager could derive for itself.
    #[tokio::test]
    async fn establish_relationship_takes_the_tip_its_store_holds() {
        let (mut manager, _kp, store) = make_manager_with_store();
        let contact = make_verified_contact("Bob", true, true);
        let remote_id = contact.device_id;
        let remote_genesis = contact.genesis_hash;
        let h_0 = add_contact(&mut manager, &store, contact);
        let h_1 = [0x5A; 32];
        assert!(store
            .set_contact_chain_tip(&remote_id, h_0, h_1)
            .expect("advance"));

        let anchor = manager
            .establish_relationship(&remote_id)
            .await
            .expect("establish");
        assert_eq!(anchor.local_device_id, make_manager_ids().0);
        assert_eq!(anchor.local_genesis_hash, make_manager_ids().1);
        assert_eq!(anchor.remote_device_id, remote_id);
        assert_eq!(anchor.remote_genesis_hash, remote_genesis);
        assert_eq!(anchor.chain_tip, h_1);
        assert_eq!(manager.get_chain_tip_for(&remote_id), Some(h_1));
    }

    #[tokio::test]
    async fn create_precommitment_without_relationship() {
        let (mut manager, _kp) = make_manager();
        let op = signed_transfer_op(&manager.signature_keypair, "m", 1);
        let res = manager
            .create_bilateral_precommitment(&make_remote_ids().0, op)
            .await;
        assert!(matches!(res, Err(DsmError::RelationshipNotFound(_))));
    }

    #[tokio::test]
    async fn create_precommitment_success_and_pending() {
        let (mut manager, _kp, store) = make_manager_with_store();
        let contact = make_verified_contact("Carol", true, true);
        let remote_id = contact.device_id;
        add_contact(&mut manager, &store, contact);
        manager
            .establish_relationship(&remote_id)
            .await
            .expect("establish");

        let op = signed_transfer_op(&manager.signature_keypair, "m", 2);
        let pre = manager
            .create_bilateral_precommitment(&remote_id, op.clone())
            .await
            .expect("pre");
        assert!(manager.has_pending_commitment(&pre.bilateral_commitment_hash));
    }

    /// A restarted manager holds a persisted step's precommitment again only
    /// when the step hashes to the session's commitment; a parent tip or an
    /// operation that is not the one committed to is refused, and nothing is
    /// held.
    #[tokio::test]
    async fn a_precommitment_is_restored_only_as_the_step_it_committed_to() {
        let (mut manager, _kp, store) = make_manager_with_store();
        let contact = make_verified_contact("Remote", true, true);
        let remote = contact.device_id;
        add_contact(&mut manager, &store, contact);
        manager
            .establish_relationship(&remote)
            .await
            .expect("establish");
        let pre = manager
            .create_bilateral_precommitment(&remote, Operation::Noop)
            .await
            .expect("precommit");
        let commitment = pre.bilateral_commitment_hash;

        let (mut restarted, _kp, restarted_store) = make_manager_with_store();
        let contact = make_verified_contact("Remote", true, true);
        add_contact(&mut restarted, &restarted_store, contact);
        restarted
            .establish_relationship(&remote)
            .await
            .expect("establish");
        let other_tip = [0x5Au8; 32];
        assert!(restarted
            .restore_pre_commitment(&remote, other_tip, Operation::Noop, &commitment)
            .is_err());
        assert!(!restarted.has_pending_commitment(&commitment));

        restarted
            .restore_pre_commitment(&remote, pre.parent_tip, Operation::Noop, &commitment)
            .expect("the persisted step is the one committed to");
        assert!(restarted.has_pending_commitment(&commitment));
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
        let (mut manager, _kp, store) = make_manager_with_store();
        let contact = make_verified_contact("Grace", true, true);
        let remote_id = contact.device_id;
        add_contact(&mut manager, &store, contact);
        manager
            .establish_relationship(&remote_id)
            .await
            .expect("establish");

        // The cached contact is replaced by one without its signing key: the
        // relationship stands, and no precommitment is made without the key.
        manager
            .add_verified_contact(make_verified_contact("Grace", false, true))
            .expect("re-add");
        let op = signed_transfer_op(&manager.signature_keypair, "m", 5);
        let res = manager.create_bilateral_precommitment(&remote_id, op).await;
        assert!(matches!(res, Err(DsmError::InvalidContact(_))));
    }

    /// A rejection verifies only under the rejector's pinned key, over the
    /// proposal, the rejector and the reason it signed.
    #[tokio::test]
    async fn a_rejection_verifies_only_as_its_rejector_signed_it() {
        let (receiver, _kp) = make_manager();
        let (receiver_id, _) = make_manager_ids();
        let receiver_kp = SignatureKeyPair::generate_from_entropy(
            &[receiver_id.as_slice(), make_manager_ids().1.as_slice()].concat(),
        )
        .expect("receiver keys");
        let commitment = [0x31u8; 32];
        let signature = receiver
            .sign_rejection(&commitment, "no")
            .expect("sign the rejection");

        // The proposer, holding the receiver as a contact under its pinned key.
        let (proposer_id, proposer_genesis) = make_remote_ids();
        let proposer_kp = SignatureKeyPair::generate_from_entropy(b"rejection-proposer").unwrap();
        let mut proposer = BilateralTransactionManager::new(
            DsmContactManager::new(proposer_id),
            proposer_kp.clone(),
            proposer_id,
            proposer_genesis,
            std::sync::Arc::new(MemoryStore::new()),
        );
        proposer
            .add_verified_contact(DsmVerifiedContact {
                alias: "receiver".into(),
                device_id: receiver_id,
                genesis_hash: make_manager_ids().1,
                public_key: receiver_kp.public_key().to_vec(),
                chain_tip: None,
                genesis_verified_online: true,
                verifying_storage_nodes: vec![],
                ble_address: None,
            })
            .expect("add the receiver");

        proposer
            .verify_rejection(&receiver_id, &commitment, "no", &signature)
            .expect("the receiver's own rejection verifies");
        assert!(proposer
            .verify_rejection(&receiver_id, &commitment, "no", &[])
            .is_err());
        assert!(proposer
            .verify_rejection(&receiver_id, &commitment, "changed", &signature)
            .is_err());
        assert!(proposer
            .verify_rejection(&receiver_id, &[0x32u8; 32], "no", &signature)
            .is_err());
        let forged = proposer_kp
            .sign(&BilateralTransactionManager::rejection_message(
                &commitment,
                &receiver_id,
                "no",
            ))
            .unwrap();
        assert!(
            proposer
                .verify_rejection(&receiver_id, &commitment, "no", &forged)
                .is_err(),
            "a rejection signed by any key but the rejector's pinned one verified"
        );
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
