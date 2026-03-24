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
use crate::core::chain_tip_store::{ChainTipStore, noop_chain_tip_store};
use crate::core::state_machine::bilateral::BilateralStateManager;
use crate::core::state_machine::relationship::RelationshipStatePair as StatePair;
use crate::crypto::canonical_lp;
use crate::crypto::signatures::SignatureKeyPair;
use crate::merkle::sparse_merkle_tree::{empty_leaf, SmtReplaceResult, SparseMerkleTree};
use crate::types::contact_types::{ChainTipSmtProof, DsmVerifiedContact};
use crate::types::error::{DeterministicSafetyClass, DsmError};
use crate::types::operations::Operation;
use crate::types::state_types::{PreCommitment, State};
use crate::core::utility::labeling;

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
        let mut h = dsm_domain_hasher("DSM/bilateral-session");
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
    // h_0 = dsm_domain_hasher("DSM/bilateral-session") || sorted(G_A, DevID_A, G_B, DevID_B)
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

    let mut h = dsm_domain_hasher("DSM/bilateral-session");
    h.update(genesis_a);
    h.update(device_a);
    h.update(genesis_b);
    h.update(device_b);
    let out = h.finalize();
    bytes32(out.as_bytes())
}

/// §18.1: k_{A↔B} = BLAKE3("DSM/smt-key\0" || min(DevID_A, DevID_B) || max(DevID_A, DevID_B))
/// Lexicographic ordering ensures identical key regardless of which party computes it.
pub fn compute_smt_key(dev_id_a: &[u8; 32], dev_id_b: &[u8; 32]) -> [u8; 32] {
    let (min_id, max_id) = if dev_id_a < dev_id_b {
        (dev_id_a, dev_id_b)
    } else {
        (dev_id_b, dev_id_a)
    };
    let mut h = dsm_domain_hasher("DSM/smt-key");
    h.update(min_id);
    h.update(max_id);
    bytes32(h.finalize().as_bytes())
}

/// §16.6: C_pre = BLAKE3("DSM/pre\0" || h_n || op || e) — pre-commit digest
pub fn compute_precommit(h_n: &[u8; 32], op_bytes: &[u8], entropy: &[u8]) -> [u8; 32] {
    let mut h = dsm_domain_hasher("DSM/pre");
    h.update(h_n);
    h.update(op_bytes);
    h.update(entropy);
    bytes32(h.finalize().as_bytes())
}

/// §16.6: h_{n+1} = BLAKE3("DSM/tip\0" || h_n || op || e || σ) — successor shared tip
/// Both parties compute this identically from shared inputs. Deterministic.
pub fn compute_successor_tip(
    h_n: &[u8; 32],
    op_bytes: &[u8],
    entropy: &[u8],
    receipt_digest: &[u8; 32],
) -> [u8; 32] {
    let mut h = dsm_domain_hasher("DSM/tip");
    h.update(h_n);
    h.update(op_bytes);
    h.update(entropy);
    h.update(receipt_digest);
    bytes32(h.finalize().as_bytes())
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
        let mut h = dsm_domain_hasher("DSM/bilateral-session");
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
    pub fn advance_chain_tip(&mut self, remote_device_id: &[u8; 32], new_tip: [u8; 32]) {
        if let Some(anchor) = self.relationships.get_mut(remote_device_id) {
            info!(
                "[BTM] advance_chain_tip: {} -> {}",
                labeling::hash_to_short_id(&anchor.chain_tip),
                labeling::hash_to_short_id(&new_tip)
            );
            anchor.chain_tip = new_tip;
            anchor.last_sync_at = mono_commit_height();
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

    /// Generate entropy for state transitions (public wrapper for receiver-side finalize)
    pub fn generate_entropy(&self) -> Result<[u8; 32], DsmError> {
        self.bilateral_state_manager.generate_entropy()
    }

    /// Execute a bilateral state transition (public wrapper for receiver-side finalize)
    pub fn execute_transition_bytes(
        &mut self,
        local_device_id: &[u8; 32],
        remote_device_id: &[u8; 32],
        operation: Operation,
        entropy: [u8; 32],
    ) -> Result<StatePair, DsmError> {
        self.bilateral_state_manager.execute_transition_bytes(
            local_device_id,
            remote_device_id,
            operation,
            entropy,
        )
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

    /// Sign a commitment hash using the local keypair.
    /// This is used by the BLE handler when registering a sender session for bilateral transfers.
    /// The signature is required for the commit phase.
    pub fn sign_commitment(&self, commitment_hash: &[u8; 32]) -> Vec<u8> {
        // §ISSUE-B4 FIX: canonical "DSM/<domain>\0" domain separator format.
        let mut msg = Vec::with_capacity(22 + 32);
        msg.extend_from_slice(b"DSM/bilateral-sign\0");
        msg.extend_from_slice(commitment_hash);

        match self.signature_keypair.sign(&msg) {
            Ok(sig) => {
                info!(
                    "[BTM] sign_commitment: signed commitment {}... with {} byte signature",
                    labeling::hash_to_short_id(commitment_hash),
                    sig.len()
                );
                sig
            }
            Err(e) => {
                error!("[BTM] sign_commitment: failed to sign: {}", e);
                Vec::new()
            }
        }
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
        smt: &mut crate::merkle::sparse_merkle_tree::SparseMerkleTree,
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
        // §4.2: Seed the Per-Device SMT leaf to h0 so the first replace is
        // h0 → h1, not empty → h1. The parent proof must show h_n ∈ r_A.
        let smt_key = compute_smt_key(&self.local_device_id, remote_device_id);
        smt.update_leaf(&smt_key, &tip)
            .map_err(|e| DsmError::merkle(format!("Failed to seed SMT leaf for h0: {e}")))?;

        anchor.chain_tip = tip;
        self.relationships.insert(*remote_device_id, anchor.clone());

        // Seed the chain tip store so the first set_contact_chain_tip succeeds.
        // The store expects expected_parent == stored; if no entry exists yet,
        // stored defaults to [0u8;32], so we must write the initial tip first.
        let _ = self.chain_tip_store.set_contact_chain_tip(
            remote_device_id,
            [0u8; 32], // no previous tip in store
            tip,
        );

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
            min_state_number: local_state.state_number + 1,
            hash: PreCommitment::generate_hash(&local_state, &operation, &[])?,
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
            min_state_number: remote_state.state_number + 1,
            hash: PreCommitment::generate_hash(&remote_state, &operation, &[])?,
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
            local_state.state_number + 1,
            validity_duration_ticks,
            local_chain_tip_at_creation,
        )?;
        // Sign the pre-commitment locally so acceptance proof can be transported over BLE
        bilateral.sign_local(&self.signature_keypair)?;
        self.pending_commitments
            .insert(bilateral.bilateral_commitment_hash, bilateral.clone());
        Ok(bilateral)
    }

    /// Execute a bilateral transaction with real SMT-Replace (§4.2).
    ///
    /// The caller MUST provide `&mut SparseMerkleTree`. The replace happens
    /// atomically with the anchor update — no speculative proofs.
    pub async fn execute_bilateral_transaction(
        &mut self,
        remote_device_id: &[u8; 32],
        operation: Operation,
        offline: bool,
        smt: &mut SparseMerkleTree,
    ) -> Result<BilateralTransactionResult, DsmError> {
        let mut anchor = self
            .relationships
            .get(remote_device_id)
            .ok_or_else(|| DsmError::RelationshipNotFound("remote device".into()))?
            .clone();
        if offline {
            self.exec_offline(remote_device_id, operation, &mut anchor, smt)
                .await
        } else {
            self.exec_online(remote_device_id, operation, &mut anchor, smt)
                .await
        }
    }

    async fn exec_offline(
        &mut self,
        remote_device_id: &[u8; 32],
        operation: Operation,
        anchor: &mut BilateralRelationshipAnchor,
        smt: &mut SparseMerkleTree,
    ) -> Result<BilateralTransactionResult, DsmError> {
        // Tripwire: shared chain_tip must match persisted contact tip
        if let Some(contact) = self.contact_manager.get_contact(remote_device_id) {
            if let Some(contact_tip) = contact.chain_tip {
                if anchor.chain_tip != contact_tip {
                    return Err(DsmError::deterministic_safety(
                        DeterministicSafetyClass::ParentConsumed,
                        "Tripwire: relationship chain tip diverged from persisted value",
                    ));
                }
            }
        } else {
            return Err(DsmError::RelationshipNotFound(
                "remote contact missing for exec_offline".into(),
            ));
        }

        let _ = self
            .create_bilateral_precommitment(remote_device_id, operation.clone(), 300)
            .await?;
        let entropy = self.bilateral_state_manager.generate_entropy()?;
        let sp: StatePair = self.bilateral_state_manager.execute_transition_bytes(
            &self.local_device_id,
            remote_device_id,
            operation.clone(),
            entropy,
        )?;
        let current_tip = anchor.chain_tip;
        let receipt_sigma = compute_precommit(&current_tip, &operation.to_bytes(), &entropy);
        let new_tip = compute_successor_tip(
            &current_tip,
            &operation.to_bytes(),
            &entropy,
            &receipt_sigma,
        );
        let tx_hash = self.tx_hash(&sp.entity_state, &sp.counterparty_state)?;

        // §4.2: SMT-Replace FIRST, then anchor update from the result.
        let replace_result = self.commit_bilateral_smt_update(smt, remote_device_id, &new_tip)?;
        self.update_anchor_from_replace(remote_device_id, anchor, new_tip, &replace_result)?;

        Ok(BilateralTransactionResult {
            local_state: sp.entity_state,
            remote_state: sp.counterparty_state,
            relationship_anchor: anchor.clone(),
            transaction_hash: tx_hash,
            completed_offline: true,
        })
    }

    async fn exec_online(
        &mut self,
        remote_device_id: &[u8; 32],
        operation: Operation,
        anchor: &mut BilateralRelationshipAnchor,
        smt: &mut SparseMerkleTree,
    ) -> Result<BilateralTransactionResult, DsmError> {
        // Tripwire: shared chain_tip must match persisted contact tip
        if let Some(contact) = self.contact_manager.get_contact(remote_device_id) {
            if let Some(contact_tip) = contact.chain_tip {
                if anchor.chain_tip != contact_tip {
                    return Err(DsmError::deterministic_safety(
                        DeterministicSafetyClass::ParentConsumed,
                        "Tripwire: relationship chain tip diverged from persisted value",
                    ));
                }
            }
        } else {
            return Err(DsmError::RelationshipNotFound(
                "remote contact missing for exec_online".into(),
            ));
        }

        let entropy = self.bilateral_state_manager.generate_entropy()?;
        let sp: StatePair = self.bilateral_state_manager.execute_transition_bytes(
            &self.local_device_id,
            remote_device_id,
            operation.clone(),
            entropy,
        )?;
        let current_tip = anchor.chain_tip;
        let receipt_sigma = compute_precommit(&current_tip, &operation.to_bytes(), &entropy);
        let new_tip = compute_successor_tip(
            &current_tip,
            &operation.to_bytes(),
            &entropy,
            &receipt_sigma,
        );
        let tx_hash = self.tx_hash(&sp.entity_state, &sp.counterparty_state)?;

        // §4.2: SMT-Replace FIRST, then anchor update from the result.
        let replace_result = self.commit_bilateral_smt_update(smt, remote_device_id, &new_tip)?;
        self.update_anchor_from_replace(remote_device_id, anchor, new_tip, &replace_result)?;

        Ok(BilateralTransactionResult {
            local_state: sp.entity_state,
            remote_state: sp.counterparty_state,
            relationship_anchor: anchor.clone(),
            transaction_hash: tx_hash,
            completed_offline: false,
        })
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
        let mut h = dsm_domain_hasher("DSM/bilateral-session");
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
    ) -> Result<BilateralTransactionResult, DsmError> {
        self.finalize_offline_transfer_with_entropy(
            remote_device_id,
            pre_commitment_hash,
            receiver_acceptance_proof,
            None,
            smt,
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
            anchor.chain_tip = tip;
        }

        // ===== TRIPWIRE ENFORCEMENT (DSM Whitepaper Section 6.1) =====
        // The parent tip recorded at precommitment creation MUST match the current
        // shared chain tip. If it differs, another transition has already consumed
        // the parent hash, and finalizing would violate the Tripwire theorem.
        if Some(anchor.chain_tip) != pre.local_chain_tip_at_creation {
            let class = DeterministicSafetyClass::ParentConsumed;
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
            None => self.bilateral_state_manager.generate_entropy()?,
        };
        let sp = self.bilateral_state_manager.execute_transition_bytes(
            &self.local_device_id,
            remote_device_id,
            pre.operation.clone(),
            entropy,
        )?;
        let current_tip = anchor.chain_tip;
        // §16.6: σ = Cpre = BLAKE3("DSM/pre\0" || h_n || op || entropy) — symmetric,
        // both parties derive identical h_{n+1} from the same shared inputs.
        let receipt_sigma = compute_precommit(&current_tip, &pre.operation.to_bytes(), &entropy);
        let new_tip = compute_successor_tip(
            &current_tip,
            &pre.operation.to_bytes(),
            &entropy,
            &receipt_sigma,
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
        })
    }

    /// Non-mutating preview of the sender's post-finalize SHARED chain tip hash.
    ///
    /// Computes h_{n+1} = BLAKE3("DSM/tip\0" || h_n || op || entropy || σ) where
    /// σ = Cpre = BLAKE3("DSM/pre\0" || h_n || op || entropy).
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
    use std::sync::{Arc, Mutex};
    use tokio; // for #[tokio::test]

    #[derive(Default)]
    struct TestChainTipStore {
        tips: Mutex<HashMap<[u8; 32], [u8; 32]>>,
    }

    impl crate::core::chain_tip_store::ChainTipStore for TestChainTipStore {
        fn get_contact_chain_tip(&self, device_id: &[u8; 32]) -> Option<[u8; 32]> {
            self.tips
                .lock()
                .ok()
                .and_then(|m| m.get(device_id).copied())
        }

        fn set_contact_chain_tip(
            &self,
            device_id: &[u8; 32],
            expected_parent_tip: [u8; 32],
            new_tip: [u8; 32],
        ) -> Result<bool, DsmError> {
            if let Ok(mut m) = self.tips.lock() {
                let current = m.get(device_id).copied().unwrap_or([0u8; 32]);
                if current != expected_parent_tip {
                    return Ok(false);
                }
                m.insert(*device_id, new_tip);
                return Ok(true);
            }
            Err(DsmError::InvalidState(
                "TestChainTipStore mutex poisoned".to_string(),
            ))
        }
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
            token_id: b"ERA".to_vec(),
            to_device_id: vec![9u8; 32],
            amount: Balance::from_state(1, [0u8; 32], 0),
            mode: TransactionMode::Bilateral,
            nonce: vec![nonce; 8],
            verification: VerificationType::Standard,
            pre_commit: None,
            recipient: vec![9u8; 32],
            to: b"b32recipient".to_vec(),
            message: message.to_string(),
            signature: Vec::new(),
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
        let mut smt = crate::merkle::sparse_merkle_tree::SparseMerkleTree::new(256);
        let res = manager.establish_relationship(&remote, &mut smt).await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn establish_relationship_requires_genesis_verified() {
        let (mut manager, _kp) = make_manager();
        let contact = make_verified_contact("Alice", true, false);
        // Add contact (pre-verified API allows any, but BTM enforces on use)
        manager.add_verified_contact(contact.clone()).expect("add");
        let mut smt = crate::merkle::sparse_merkle_tree::SparseMerkleTree::new(256);
        let res = manager
            .establish_relationship(&contact.device_id, &mut smt)
            .await;
        assert!(matches!(res, Err(DsmError::InvalidContact(_))));
    }

    #[tokio::test]
    async fn establish_relationship_success_and_integrity() {
        let (mut manager, _kp) = make_manager();
        let contact = make_verified_contact("Bob", true, true);
        let remote_id = contact.device_id;
        let remote_genesis = contact.genesis_hash;
        manager.add_verified_contact(contact).expect("add");

        let mut smt = crate::merkle::sparse_merkle_tree::SparseMerkleTree::new(256);
        let anchor = manager
            .establish_relationship(&remote_id, &mut smt)
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
        let mut smt = crate::merkle::sparse_merkle_tree::SparseMerkleTree::new(256);
        manager
            .establish_relationship(&remote_id, &mut smt)
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
    async fn execute_transaction_offline_updates_anchor_and_contact() {
        let (mut manager, _kp) = make_manager();
        let contact = make_verified_contact("Dave", true, true);
        let remote_id = contact.device_id;
        let remote_genesis = contact.genesis_hash;
        manager.add_verified_contact(contact).expect("add");
        let mut smt = crate::merkle::sparse_merkle_tree::SparseMerkleTree::new(256);
        let anchor = manager
            .establish_relationship(&remote_id, &mut smt)
            .await
            .expect("establish");
        // Establish relationship now uses deterministic initial relationship tip (h_0)
        let initial_tip = initial_relationship_chain_tip(
            &make_manager_ids().0,
            &make_manager_ids().1,
            &remote_id,
            &remote_genesis,
        );
        assert_eq!(anchor.chain_tip, initial_tip);

        let op = signed_transfer_op(&manager.signature_keypair, "m", 3);
        let mut smt = crate::merkle::sparse_merkle_tree::SparseMerkleTree::new(256);
        manager
            .execute_bilateral_transaction(&remote_id, op, true, &mut smt)
            .await
            .expect("exec");
        let updated = manager.get_relationship(&remote_id).expect("rel");
        // After transition, shared chain tip must have advanced from h_0
        assert_ne!(updated.chain_tip, initial_tip);
        // §4.2: anchor proof is derived from SmtReplaceResult. No later override pattern.
        assert!(
            updated.smt_proof.is_some(),
            "anchor must have real SMT proof after transition"
        );
        let proof = updated.smt_proof.as_ref().unwrap();
        assert_eq!(
            proof.state_hash, updated.chain_tip,
            "proof state_hash must match chain tip"
        );
        assert_ne!(proof.smt_root, [0u8; 32], "proof root must not be zero");
        assert!(manager.has_verified_contact(&remote_id));
    }

    #[tokio::test]
    async fn update_anchor_persists_shared_tip_for_contact() {
        crate::utils::deterministic_time::reset_for_tests();

        let (local_device_id, local_genesis_hash) = make_manager_ids();
        let contact_manager = DsmContactManager::new(local_device_id, vec![]);
        let key_entropy = [local_device_id.as_slice(), local_genesis_hash.as_slice()].concat();
        let kp = SignatureKeyPair::generate_from_entropy(&key_entropy)
            .map_err(|e| DsmError::crypto("Failed to generate test keypair", Some(e)))
            .unwrap();

        let chain_tip_store = Arc::new(TestChainTipStore::default());
        let mut manager = BilateralTransactionManager::new_with_chain_tip_store(
            contact_manager,
            kp,
            local_device_id,
            local_genesis_hash,
            chain_tip_store.clone(),
        );

        let contact = make_verified_contact("RemoteTip", true, true);
        let remote_id = contact.device_id;
        manager.add_verified_contact(contact).expect("add");
        let mut smt = crate::merkle::sparse_merkle_tree::SparseMerkleTree::new(256);
        manager
            .establish_relationship(&remote_id, &mut smt)
            .await
            .expect("establish");

        let op = signed_transfer_op(&manager.signature_keypair, "m", 33);
        let mut smt = crate::merkle::sparse_merkle_tree::SparseMerkleTree::new(256);
        manager
            .execute_bilateral_transaction(&remote_id, op, true, &mut smt)
            .await
            .expect("exec");

        let rel = manager.get_relationship(&remote_id).expect("relationship");
        let persisted = chain_tip_store
            .get_contact_chain_tip(&remote_id)
            .expect("persisted contact tip");

        // Persisted tip must match the shared relationship chain tip
        assert_eq!(persisted, rel.chain_tip);
    }

    #[tokio::test]
    async fn finalize_offline_transfer_removes_pending() {
        let (mut manager, _kp) = make_manager();
        let contact = make_verified_contact("Eve", true, true);
        let remote_id = contact.device_id;
        manager.add_verified_contact(contact).expect("add");
        let mut smt = crate::merkle::sparse_merkle_tree::SparseMerkleTree::new(256);
        manager
            .establish_relationship(&remote_id, &mut smt)
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
            )
            .await
            .expect("finalize");
        assert!(result.completed_offline);
        assert!(!manager.has_pending_commitment(&pre.bilateral_commitment_hash));
    }

    #[tokio::test]
    async fn require_contact_signing_key_missing_pubkey() {
        let (mut manager, _kp) = make_manager();
        let contact = make_verified_contact("Frank", false, true); // no public key
        let remote_id = contact.device_id;
        manager.add_verified_contact(contact).expect("add");
        let mut smt = crate::merkle::sparse_merkle_tree::SparseMerkleTree::new(256);
        let res = manager.establish_relationship(&remote_id, &mut smt).await;
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
}
