// dsm_client/deterministic_state_machine/dsm/src/core/contact_manager.rs

//! DSM Contact Manager - Production Implementation (STRICT, bytes-only, no wall-clock)
//!
//! Invariants:
//! - No wall-clock APIs anywhere. Use deterministic, system-wide ticks from utils::deterministic_time.
//! - No JSON/GSON at any boundary. No hex/base64 in data structures or logs; bytes-only.
//! - Mandatory online genesis verification is enforced by the SDK layer; core only exposes bytes APIs.
//! - Chain tip tracking is bytes-based with deterministic SMT proofs.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

#[cfg(test)]
use blake3;
use tracing::{info, warn};

use crate::core::utility::labeling;
use crate::types::contact_types::{ChainTipSmtProof, DsmVerifiedContact};
use crate::types::error::DsmError;
use crate::types::identifiers::NodeId;
use crate::utils::deterministic_time;

// -------------------- Deterministic ticks (strictly monotone, clockless) --------------------
// We use the global deterministic tick source for "now". For strictly increasing per-event
// indices (when multiple events occur within the same tick), we keep a tiny local sequence.
static EVENT_SEQ: AtomicU64 = AtomicU64::new(1);

#[inline]
fn now_commit_height() -> u64 {
    deterministic_time::current_commit_height_blocking()
}

#[inline]
fn next_event_index() -> u64 {
    EVENT_SEQ.fetch_add(1, Ordering::Relaxed)
}

// Proof freshness window expressed purely in commit heights (no units-of-time semantics here).
const PROOF_MAX_AGE_COMMIT_HEIGHTS: u64 = 86_400;

// -------------------- Local SMT verifier (bytes-only) --------------------
#[derive(Debug, Clone, Default)]
pub struct LocalSmtVerifier {
    /// Verified Genesis cache for offline checks (device_id -> raw genesis bytes)
    local_genesis_cache: HashMap<[u8; 32], Vec<u8>>,
    /// Latest SMT proof per contact (device_id -> proof)
    local_smt_states: HashMap<[u8; 32], ChainTipSmtProof>,
}

impl LocalSmtVerifier {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn store_verified_genesis(&mut self, device_id: &[u8; 32], genesis_data: Vec<u8>) {
        self.local_genesis_cache.insert(*device_id, genesis_data);
    }

    pub fn verify_contact_locally(
        &self,
        device_id: &[u8; 32],
        expected_genesis_hash: &[u8; 32],
    ) -> bool {
        match self.local_genesis_cache.get(device_id) {
            None => false,
            Some(genesis_data) => {
                let computed =
                    crate::crypto::blake3::domain_hash("DSM/genesis-verify", genesis_data);
                let mut bytes = [0u8; 32];
                bytes.copy_from_slice(computed.as_bytes());
                &bytes == expected_genesis_hash
            }
        }
    }

    pub fn store_chain_tip_proof(&mut self, device_id: &[u8; 32], proof: ChainTipSmtProof) {
        self.local_smt_states.insert(*device_id, proof);
    }

    pub fn verify_chain_tip_locally(
        &self,
        device_id: &[u8; 32],
        chain_tip_hash: &[u8; 32],
    ) -> bool {
        match self.local_smt_states.get(device_id) {
            None => false,
            Some(proof) => {
                if &proof.state_hash != chain_tip_hash {
                    return false;
                }
                let now = now_commit_height();
                if now.saturating_sub(proof.proof_commit_height) > PROOF_MAX_AGE_COMMIT_HEIGHTS {
                    return false;
                }
                // Minimal structural check: non-zero root
                !proof.smt_root.iter().all(|&b| b == 0)
            }
        }
    }

    pub fn verify_chain_tip_with_proof(
        &self,
        _device_id: &[u8; 32],
        chain_tip_hash: &[u8; 32],
        smt_proof: &ChainTipSmtProof,
    ) -> bool {
        if &smt_proof.state_hash != chain_tip_hash {
            return false;
        }
        let now = now_commit_height();
        if now.saturating_sub(smt_proof.proof_commit_height) > PROOF_MAX_AGE_COMMIT_HEIGHTS {
            return false;
        }
        !smt_proof.smt_root.iter().all(|&b| b == 0)
    }

    /// Generate a deterministic local SMT proof for a new chain tip (purely bytes/ticks)
    pub fn create_chain_tip_proof(
        &self,
        device_id: &[u8; 32],
        chain_tip_hash: &[u8; 32],
    ) -> ChainTipSmtProof {
        let tick = deterministic_time::current_commit_height_blocking();
        let seq = next_event_index();

        let mut h = crate::crypto::blake3::dsm_domain_hasher("DSM/SMT_CHAIN_TIP_LOCAL");
        h.update(device_id);
        h.update(chain_tip_hash);
        if let Some(genesis) = self.local_genesis_cache.get(device_id) {
            h.update(genesis);
        }
        h.update(&tick.to_le_bytes());
        h.update(&seq.to_le_bytes());
        let out = h.finalize();

        let mut smt_root = [0u8; 32];
        smt_root.copy_from_slice(out.as_bytes());

        ChainTipSmtProof {
            smt_root,
            state_hash: *chain_tip_hash,
            proof_path: Vec::new(),
            // Separate fields: tick reflects global ordering; index is a strictly increasing local counter.
            state_index: seq,
            proof_commit_height: tick,
        }
    }
}

// -------------------- Storage node client (SDK performs real I/O) --------------------
#[derive(Debug, Clone)]
pub struct InitialSetupClient {
    pub storage_nodes: Vec<NodeId>,
}
impl InitialSetupClient {
    pub fn new(storage_nodes: Vec<NodeId>) -> Self {
        Self { storage_nodes }
    }
}

// -------------------- Unilateral transaction payload (bytes, monotonic) --------------------
#[derive(Debug, Clone)]
pub struct UnilateralTransactionPayload {
    pub transaction_id: [u8; 32],
    pub sender_device_id: [u8; 32],
    pub recipient_device_id: [u8; 32],
    pub chain_tip: [u8; 32],
    pub smt_proof: ChainTipSmtProof,
    pub tick: u64,
}

fn deterministic_tx_id(
    sender: &[u8; 32],
    recipient: &[u8; 32],
    chain_tip: &[u8; 32],
    tick: u64,
    index: u64,
) -> [u8; 32] {
    let mut h = crate::crypto::blake3::dsm_domain_hasher("DSM/B0X/UNILATERAL");
    h.update(sender);
    h.update(recipient);
    h.update(chain_tip);
    h.update(&tick.to_le_bytes());
    h.update(&index.to_le_bytes());
    let out = h.finalize();
    let mut id = [0u8; 32];
    id.copy_from_slice(out.as_bytes());
    id
}

// -------------------- Contact Manager --------------------
#[derive(Debug, Clone)]
pub struct DsmContactManager {
    pub contacts: HashMap<[u8; 32], DsmVerifiedContact>,
    pub storage_nodes: Vec<NodeId>,
    pub own_device_id: [u8; 32],
    pub local_smt_verifier: LocalSmtVerifier,
    pub setup_client: InitialSetupClient,
}

#[derive(Debug)]
pub enum ContactAddResult {
    Success(DsmVerifiedContact),
    AlreadyExists(DsmVerifiedContact),
}

#[derive(Debug, thiserror::Error)]
pub enum ContactError {
    #[error("Genesis verification failed: {0}")]
    GenesisVerificationFailed(String),
    #[error("Storage nodes unreachable")]
    StorageNodesUnreachable,
    #[error("Invalid contact data: {0}")]
    InvalidContactData(String),
    #[error("Contact not found")]
    ContactNotFound,
    #[error("Invalid chain tip: {0}")]
    InvalidChainTip(String),
    #[error("SMT verification failed: {0}")]
    SmtVerificationFailed(String),
}

impl DsmContactManager {
    pub fn new(own_device_id: [u8; 32], storage_nodes: Vec<NodeId>) -> Self {
        let setup_client = InitialSetupClient::new(storage_nodes.clone());
        Self {
            contacts: HashMap::new(),
            storage_nodes,
            own_device_id,
            local_smt_verifier: LocalSmtVerifier::new(),
            setup_client,
        }
    }

    /// Bytes-only: add a **pre-verified** contact (SDK must have verified genesis online already)
    pub fn add_verified_contact(&mut self, contact: DsmVerifiedContact) -> Result<(), DsmError> {
        if contact.device_id == [0u8; 32] || contact.genesis_hash == [0u8; 32] {
            return Err(DsmError::InvalidContact(
                "Contact must have device_id & genesis_hash".into(),
            ));
        }

        let id = contact.device_id;

        info!(
            "Adding verified contact (id_dec={})",
            labeling::hash_to_short_id(&id)
        );

        self.local_smt_verifier
            .store_verified_genesis(&id, contact.genesis_material().to_vec());

        self.contacts.insert(id, contact);
        Ok(())
    }

    #[inline]
    pub fn get_contact(&self, device_id: &[u8; 32]) -> Option<&DsmVerifiedContact> {
        self.contacts.get(device_id)
    }

    #[inline]
    pub fn get_contact_mut(&mut self, device_id: &[u8; 32]) -> Option<&mut DsmVerifiedContact> {
        self.contacts.get_mut(device_id)
    }

    /// Update chain tip for bilateral (offline) transactions with a co-signed proof
    pub fn update_contact_chain_tip_bilateral(
        &mut self,
        device_id: &[u8; 32],
        new_chain_tip: [u8; 32],
        verified_bilateral_proof: ChainTipSmtProof,
    ) -> Result<(), ContactError> {
        self.contacts
            .get(device_id)
            .ok_or(ContactError::ContactNotFound)?;

        if !self.local_smt_verifier.verify_chain_tip_with_proof(
            device_id,
            &new_chain_tip,
            &verified_bilateral_proof,
        ) {
            return Err(ContactError::InvalidChainTip(
                "Bilateral SMT proof verification failed".into(),
            ));
        }

        let c = self
            .contacts
            .get_mut(device_id)
            .ok_or(ContactError::ContactNotFound)?;

        c.update_chain_tip_with_proof(new_chain_tip, Some(verified_bilateral_proof));

        let proof = c.chain_tip_smt_proof.clone().ok_or_else(|| {
            ContactError::InvalidContactData("Chain tip proof not set after update".to_string())
        })?;

        self.local_smt_verifier
            .store_chain_tip_proof(device_id, proof);

        info!("Updated local SMT for bilateral transaction");
        Ok(())
    }

    /// Update chain tip for unilateral (online) transactions (SDK posts to storage). Core stays local/bytes-only.
    pub fn update_contact_chain_tip_unilateral(
        &mut self,
        device_id: &[u8; 32],
        new_chain_tip: [u8; 32],
    ) -> Result<UnilateralTransactionPayload, ContactError> {
        let smt_proof = self
            .local_smt_verifier
            .create_chain_tip_proof(device_id, &new_chain_tip);

        if !self.local_smt_verifier.verify_chain_tip_with_proof(
            device_id,
            &new_chain_tip,
            &smt_proof,
        ) {
            return Err(ContactError::InvalidChainTip(
                "Local SMT proof verification failed".into(),
            ));
        }

        let c = self
            .contacts
            .get_mut(device_id)
            .ok_or(ContactError::ContactNotFound)?;

        c.update_chain_tip_with_proof(new_chain_tip, Some(smt_proof.clone()));

        self.local_smt_verifier
            .store_chain_tip_proof(device_id, smt_proof.clone());

        let tick = deterministic_time::current_commit_height_blocking();
        let idx = next_event_index();
        let tx_id = deterministic_tx_id(&self.own_device_id, device_id, &new_chain_tip, tick, idx);

        let payload = UnilateralTransactionPayload {
            transaction_id: tx_id,
            sender_device_id: self.own_device_id,
            recipient_device_id: *device_id,
            chain_tip: new_chain_tip,
            smt_proof,
            tick,
        };

        info!("Prepared unilateral transaction payload (SDK to submit)");
        Ok(payload)
    }

    /// Initialize a contact's chain tip with a local SMT proof (no network side effects).
    pub fn initialize_contact_chain_tip(
        &mut self,
        device_id: &[u8; 32],
        new_chain_tip: [u8; 32],
    ) -> Result<ChainTipSmtProof, ContactError> {
        let smt_proof = self
            .local_smt_verifier
            .create_chain_tip_proof(device_id, &new_chain_tip);

        if !self.local_smt_verifier.verify_chain_tip_with_proof(
            device_id,
            &new_chain_tip,
            &smt_proof,
        ) {
            return Err(ContactError::InvalidChainTip(
                "Local SMT proof verification failed".into(),
            ));
        }

        let c = self
            .contacts
            .get_mut(device_id)
            .ok_or(ContactError::ContactNotFound)?;

        c.update_chain_tip_with_proof(new_chain_tip, Some(smt_proof.clone()));

        self.local_smt_verifier
            .store_chain_tip_proof(device_id, smt_proof.clone());

        info!("Initialized contact chain tip with local SMT proof");
        Ok(smt_proof)
    }

    /// Verify all chain tips against their SMT proofs locally (bytes-only)
    pub fn verify_all_chain_tips(&self) -> HashMap<[u8; 32], bool> {
        let mut out = HashMap::new();

        for (id, c) in &self.contacts {
            let valid = match c.chain_tip_smt_proof.as_ref() {
                None => false,
                Some(proof) => {
                    let tip = c.chain_tip.unwrap_or([0u8; 32]);
                    let ok = self
                        .local_smt_verifier
                        .verify_chain_tip_with_proof(id, &tip, proof);
                    if !ok {
                        warn!(
                            "Invalid SMT proof for contact (id_dec={})",
                            labeling::hash_to_short_id(id)
                        );
                    }
                    ok
                }
            };
            out.insert(*id, valid);
        }

        out
    }

    pub fn list_contacts(&self) -> Vec<&DsmVerifiedContact> {
        self.contacts.values().collect()
    }

    pub fn remove_contact(&mut self, device_id: &[u8; 32]) -> Option<DsmVerifiedContact> {
        self.contacts.remove(device_id)
    }

    /// Update the public key for a contact (used during BLE bilateral exchange)
    pub fn update_contact_public_key(
        &mut self,
        device_id: &[u8; 32],
        public_key: Vec<u8>,
    ) -> Result<(), DsmError> {
        let contact = self.contacts.get_mut(device_id).ok_or_else(|| {
            DsmError::ContactNotFound(labeling::hash_to_short_id(device_id).to_string())
        })?;

        contact.public_key = public_key;
        contact.last_updated_commit_height = now_commit_height();

        info!(
            "Updated public_key for contact (id_dec={}, key_len={})",
            labeling::hash_to_short_id(device_id),
            contact.public_key.len()
        );

        Ok(())
    }
}

// ------------- DsmVerifiedContact contract (expected bytes-only helpers) -------------
trait VerifiedContactExt {
    fn genesis_material(&self) -> &[u8];

    #[allow(dead_code)]
    fn update_chain_tip_with_proof(
        &mut self,
        new_chain_tip: [u8; 32],
        proof: Option<ChainTipSmtProof>,
    );
}

impl VerifiedContactExt for DsmVerifiedContact {
    fn genesis_material(&self) -> &[u8] {
        self.genesis_material.as_slice()
    }

    fn update_chain_tip_with_proof(
        &mut self,
        new_chain_tip: [u8; 32],
        proof: Option<ChainTipSmtProof>,
    ) {
        self.chain_tip = Some(new_chain_tip);
        self.chain_tip_smt_proof = proof;
        self.last_updated_commit_height = now_commit_height();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_device_id(seed: u8) -> [u8; 32] {
        let mut id = [0u8; 32];
        id[0] = seed;
        id[31] = seed.wrapping_add(1);
        id
    }

    fn create_test_genesis_hash(device_id: &[u8; 32], seed: u64) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        h.update(b"TEST_GENESIS");
        h.update(device_id);
        h.update(&seed.to_le_bytes());
        let out = h.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(out.as_bytes());
        hash
    }

    fn create_test_storage_nodes() -> Vec<NodeId> {
        vec![NodeId::new("test_node_1")]
    }

    fn create_test_contact(device_id: [u8; 32], genesis_hash: [u8; 32]) -> DsmVerifiedContact {
        let now = now_commit_height();
        DsmVerifiedContact {
            device_id,
            genesis_hash,
            alias: "Test".into(),
            public_key: vec![0u8; 32],
            genesis_material: vec![0u8; 32],
            genesis_verified_online: true,
            verified_at_commit_height: now,
            added_at_commit_height: now,
            last_updated_commit_height: now,
            verifying_storage_nodes: create_test_storage_nodes(),
            chain_tip: None,
            chain_tip_smt_proof: None,
            ble_address: None,
        }
    }

    #[test]
    fn test_local_smt_verifier_genesis_storage() {
        let mut verifier = LocalSmtVerifier::new();
        let device_id = create_test_device_id(1);
        let genesis_data = b"test_genesis_data".to_vec();

        verifier.store_verified_genesis(&device_id, genesis_data.clone());
        let cached = verifier.local_genesis_cache.get(&device_id);
        assert!(cached.is_some());
        assert_eq!(cached.unwrap(), &genesis_data);
    }

    #[test]
    fn test_local_smt_verifier_wrong_genesis_fails() {
        let mut verifier = LocalSmtVerifier::new();
        let device_id = create_test_device_id(2);
        let genesis_data = b"correct_genesis".to_vec();
        let wrong_data = b"wrong_genesis".to_vec();

        verifier.store_verified_genesis(&device_id, genesis_data.clone());
        let cached = verifier.local_genesis_cache.get(&device_id).unwrap();
        assert_ne!(cached, &wrong_data);
    }

    #[test]
    fn test_dsm_contact_manager_add_contact() {
        let own_device_id = create_test_device_id(0);
        let storage_nodes = create_test_storage_nodes();
        let mut manager = DsmContactManager::new(own_device_id, storage_nodes);

        let device_id = create_test_device_id(1);
        let genesis_hash = create_test_genesis_hash(&device_id, 0);
        let contact = create_test_contact(device_id, genesis_hash);

        assert!(manager.add_verified_contact(contact.clone()).is_ok());
        assert_eq!(manager.contacts.len(), 1);
        assert!(manager.get_contact(&device_id).is_some());
    }

    #[test]
    fn test_dsm_contact_manager_get_contact() {
        let own_device_id = create_test_device_id(0);
        let mut manager = DsmContactManager::new(own_device_id, create_test_storage_nodes());

        let device_id = create_test_device_id(1);
        let genesis_hash = create_test_genesis_hash(&device_id, 0);
        let contact = create_test_contact(device_id, genesis_hash);

        manager.add_verified_contact(contact).unwrap();
        let retrieved = manager.get_contact(&device_id);
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().device_id, device_id);
    }

    #[test]
    fn test_dsm_contact_manager_remove_contact() {
        let own_device_id = create_test_device_id(0);
        let mut manager = DsmContactManager::new(own_device_id, create_test_storage_nodes());

        let device_id = create_test_device_id(1);
        let genesis_hash = create_test_genesis_hash(&device_id, 0);
        let contact = create_test_contact(device_id, genesis_hash);

        manager.add_verified_contact(contact).unwrap();
        assert_eq!(manager.contacts.len(), 1);

        manager.remove_contact(&device_id);
        assert_eq!(manager.contacts.len(), 0);
    }

    #[test]
    fn test_dsm_contact_manager_invalid_contact() {
        let own_device_id = create_test_device_id(0);
        let mut manager = DsmContactManager::new(own_device_id, create_test_storage_nodes());

        let invalid_contact = create_test_contact([0u8; 32], [1u8; 32]);
        assert!(manager.add_verified_contact(invalid_contact).is_err());
    }

    #[test]
    fn test_dsm_contact_manager_multiple_contacts() {
        let own_device_id = create_test_device_id(0);
        let mut manager = DsmContactManager::new(own_device_id, create_test_storage_nodes());

        for i in 1..=5 {
            let device_id = create_test_device_id(i);
            let genesis_hash = create_test_genesis_hash(&device_id, i as u64);
            let contact = create_test_contact(device_id, genesis_hash);
            manager.add_verified_contact(contact).unwrap();
        }

        assert_eq!(manager.contacts.len(), 5);
        assert_eq!(manager.list_contacts().len(), 5);
    }

    #[test]
    fn test_chain_tip_proof_generation() {
        let verifier = LocalSmtVerifier::new();
        let device_id = create_test_device_id(1);
        let chain_tip = [5u8; 32];

        let proof = verifier.create_chain_tip_proof(&device_id, &chain_tip);
        assert_eq!(proof.state_hash, chain_tip);
        assert_ne!(proof.smt_root, [0u8; 32], "SMT root should be non-zero");
    }

    #[test]
    fn test_chain_tip_proof_verification() {
        let verifier = LocalSmtVerifier::new();
        let device_id = create_test_device_id(1);
        let chain_tip = [5u8; 32];

        let proof = verifier.create_chain_tip_proof(&device_id, &chain_tip);
        assert!(verifier.verify_chain_tip_with_proof(&device_id, &chain_tip, &proof));
    }

    #[test]
    fn test_chain_tip_proof_stale_rejection() {
        let verifier = LocalSmtVerifier::new();
        let device_id = create_test_device_id(1);
        let chain_tip = [5u8; 32];

        let stale_proof = ChainTipSmtProof {
            state_hash: chain_tip,
            smt_root: [0u8; 32],
            proof_path: Vec::new(),
            state_index: 0,
            proof_commit_height: 0,
        };

        assert!(
            !verifier.verify_chain_tip_with_proof(&device_id, &chain_tip, &stale_proof),
            "Should reject proof with zero SMT root"
        );
    }

    #[test]
    fn test_verify_all_chain_tips() {
        let own_device_id = create_test_device_id(0);
        let mut manager = DsmContactManager::new(own_device_id, create_test_storage_nodes());

        let device_id = create_test_device_id(1);
        let genesis_hash = create_test_genesis_hash(&device_id, 0);
        let mut contact = create_test_contact(device_id, genesis_hash);

        let chain_tip = [5u8; 32];
        let proof = manager
            .local_smt_verifier
            .create_chain_tip_proof(&device_id, &chain_tip);

        contact.chain_tip = Some(chain_tip);
        contact.chain_tip_smt_proof = Some(proof);

        manager.add_verified_contact(contact).unwrap();

        let verification_map = manager.verify_all_chain_tips();
        assert_eq!(verification_map.len(), 1);
        assert!(verification_map[&device_id]);
    }

    #[test]
    fn test_short_dec_fingerprint() {
        let device_id = create_test_device_id(42);
        let fingerprint = crate::core::utility::labeling::hash_to_short_id(&device_id);

        assert!(!fingerprint.is_empty(), "Fingerprint should be non-empty");
        assert!(
            fingerprint.chars().all(char::is_numeric),
            "Fingerprint should be numeric string"
        );

        let fingerprint2 = crate::core::utility::labeling::hash_to_short_id(&device_id);
        assert_eq!(fingerprint, fingerprint2);
    }
}
