//! Checkpoint Module
//!
//! This module implements checkpoint functionality for DSM state machine,
//! allowing for efficient state verification and recovery from sparse indices.

use crate::core::identity::Identity;

use crate::core::state_machine::state::State as DsmState;

use crate::crypto::sphincs;

// NOTE: Generic MerkleTree is used here for checkpointing utilities only.
// For π_dev (Device Tree) hashing/proofs, always use crate::common::device_tree.
use crate::merkle::tree::MerkleTree;

use crate::types::error::DsmError;

use crate::utils::deterministic_time as dt;

/// Checkpoint represents a validated state at a specific point
/// in the state hash chain that has been posted to decentralized storage.
///
/// Per §4.3 no counter participates in identity — the checkpoint is
/// identified by its 32-byte `state_hash` (§2.1 adjacency).
#[derive(Debug, Clone)]
pub struct Checkpoint {
    /// Unique identifier for this checkpoint
    pub id: String,

    /// Hash of the state (checkpoint identity)
    pub state_hash: [u8; 32],

    /// Genesis hash of the identity
    pub genesis_hash: [u8; 32],

    /// Tick when checkpoint was created (deterministic)
    pub tick: u64,

    /// Device ID that created this checkpoint
    pub device_id: String,

    /// Signature over checkpoint data
    pub signature: Vec<u8>,

    /// Sparse Merkle Tree proof for efficient verification
    pub merkle_proof: Option<Vec<u8>>,

    /// Whether this is an invalidation checkpoint
    pub is_invalidation: bool,

    /// Reason for invalidation (if is_invalidation is true)
    pub invalidation_reason: Option<String>,
}

impl Checkpoint {
    /// Create a new checkpoint from a state
    pub fn new(
        state: &DsmState,
        identity: &Identity,
        device_id: &str,
        is_invalidation: bool,
        invalidation_reason: Option<String>,
    ) -> Result<Self, DsmError> {
        // Use deterministic logical time for checkpoint tick
        // dt::tick() returns a tuple ([u8; 32], u64); extract the u64 tick.
        let (_dt_genesis_hash, tick) = dt::tick();

        // Create checkpoint ID using canonical genesis bytes (already computed in genesis state)
        let mut genesis_hash = [0u8; 32];
        if identity.master_genesis.hash.len() >= 32 {
            genesis_hash.copy_from_slice(&identity.master_genesis.hash[0..32]);
        } else {
            return Err(DsmError::invalid_operation("Genesis hash too short"));
        }

        // Convert state hash to fixed size array
        let mut state_hash = [0u8; 32];

        // Compute the state hash and propagate errors appropriately
        let state_hash_vec = state.hash().map_err(|e| {
            DsmError::crypto("Failed to hash state for checkpoint", Some(Box::new(e)))
        })?;

        // Ensure we have at least 32 bytes and copy into the fixed-size array
        if state_hash_vec.len() >= 32 {
            state_hash.copy_from_slice(&state_hash_vec[0..32]);
        } else {
            return Err(DsmError::invalid_operation("State hash too short"));
        }

        // Identifier uses the state hash (content-addressed, §2.1), not a counter.
        let id = format!(
            "checkpoint_{:x}{:x}_{tick}_{device_id}",
            state_hash[0], state_hash[1]
        );

        // Create the unsigned checkpoint
        let mut checkpoint = Self {
            id,
            state_hash,
            genesis_hash,
            tick,
            device_id: device_id.to_string(),
            signature: Vec::new(),
            merkle_proof: None,
            is_invalidation,
            invalidation_reason,
        };

        // Now we can sign it
        // Convert the signing key to bytes for signing
        let signing_key_bytes = identity.master_genesis.get_signing_key_bytes()?;
        checkpoint.sign(&signing_key_bytes)?;

        Ok(checkpoint)
    }

    /// Sign the checkpoint with a signing key
    pub fn sign(&mut self, signing_key: &[u8]) -> Result<(), DsmError> {
        // Generate data to sign
        let data = self.get_signing_data();

        // Sign the data
        self.signature = sphincs::sphincs_sign(&data, signing_key)
            .map_err(|e| DsmError::crypto("Failed to sign checkpoint", Some(Box::new(e))))?;

        Ok(())
    }

    /// Verify the checkpoint's signature
    pub fn verify_signature(&self, public_key: &[u8]) -> Result<bool, DsmError> {
        // Generate data that was signed
        let data = self.get_signing_data();

        // Verify signature
        sphincs::sphincs_verify(&data, &self.signature, public_key).map_err(|e| {
            DsmError::crypto("Failed to verify checkpoint signature", Some(Box::new(e)))
        })
    }

    /// Get data for signing/verification
    fn get_signing_data(&self) -> Vec<u8> {
        let mut data = Vec::new();

        // Add state hash (32 bytes) — content-addressed identity.
        data.extend_from_slice(&self.state_hash);

        // Add genesis hash (32 bytes)
        data.extend_from_slice(&self.genesis_hash);

        // Add tick (8 bytes)
        data.extend_from_slice(&self.tick.to_be_bytes());

        // Add device ID
        data.extend_from_slice(self.device_id.as_bytes());

        // Add invalidation flag
        data.push(if self.is_invalidation { 1 } else { 0 });

        // Add invalidation reason if present
        if let Some(reason) = &self.invalidation_reason {
            data.extend_from_slice(reason.as_bytes());
        }

        data
    }

    /// Add a Merkle proof to this checkpoint
    pub fn add_merkle_proof(&mut self, proof: Vec<u8>) {
        self.merkle_proof = Some(proof);
    }

    /// Create an invalidation checkpoint
    pub fn create_invalidation(
        state: &DsmState,
        identity: &Identity,
        device_id: &str,
        reason: &str,
    ) -> Result<Self, DsmError> {
        Self::new(state, identity, device_id, true, Some(reason.to_string()))
    }

    /// Verify state against this checkpoint
    pub fn verify_state(&self, state: &DsmState) -> Result<bool, DsmError> {
        // Get state hash
        let state_hash = state.hash()?;

        // Convert to fixed size array for comparison
        let mut state_hash_array = [0u8; 32];
        if state_hash.len() >= 32 {
            state_hash_array.copy_from_slice(&state_hash[0..32]);
        } else {
            return Ok(false);
        }

        // Compare state hash (the content-addressed identity)
        Ok(self.state_hash == state_hash_array)
    }
}

/// CheckpointManager handles creation and verification of checkpoints
#[derive(Debug)]
#[allow(dead_code)]
pub struct CheckpointManager {
    /// Checkpoint merkle tree for verification
    merkle_tree: MerkleTree,
}

impl Default for CheckpointManager {
    fn default() -> Self {
        Self::new()
    }
}

impl CheckpointManager {
    /// Create a new checkpoint manager
    pub fn new() -> Self {
        Self {
            merkle_tree: MerkleTree::new(Vec::new()),
        }
    }

    /// Create a checkpoint from a state
    pub fn create_checkpoint(
        &mut self,
        state: &DsmState,
        identity: &Identity,
        device_id: &str,
        invalidation: bool,
        reason: Option<String>,
    ) -> Result<Checkpoint, DsmError> {
        Checkpoint::new(state, identity, device_id, invalidation, reason)
    }

    /// Verify a checkpoint
    pub fn verify_checkpoint(
        &self,
        checkpoint: &Checkpoint,
        state: &DsmState,
        identity: &Identity,
    ) -> Result<bool, DsmError> {
        // Verify the signature with the public key from the identity
        let public_key_bytes = identity.master_genesis.get_public_key_bytes()?;

        if !checkpoint.verify_signature(&public_key_bytes)? {
            return Ok(false);
        }

        // Verify the state hash and number
        checkpoint.verify_state(state)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::operations::Operation;
    use crate::types::state_types::{DeviceInfo, StateParams};

    // ── Helpers ──────────────────────────────────────────────────────

    fn dev_info() -> DeviceInfo {
        DeviceInfo::new([0x11; 32], vec![0x22; 64])
    }

    /// Build a test DsmState. `seed` is just a distinguishing label for the
    /// entropy; it plays no role in acceptance predicates.
    fn make_dsm_state(seed: u64) -> DsmState {
        let mut entropy = vec![0xAAu8; 16];
        entropy.extend_from_slice(&seed.to_le_bytes());
        let mut s = DsmState::new(StateParams::new(entropy, Operation::Noop, dev_info()));
        let hash_vec = s.compute_hash().unwrap();
        s.hash.copy_from_slice(&hash_vec[..32]);
        s
    }

    // ── Checkpoint::get_signing_data ────────────────────────────────

    #[test]
    fn signing_data_deterministic() {
        let cp = Checkpoint {
            id: "cp_1".into(),            state_hash: [0xAA; 32],
            genesis_hash: [0xBB; 32],
            tick: 100,
            device_id: "device_a".into(),
            signature: vec![],
            merkle_proof: None,
            is_invalidation: false,
            invalidation_reason: None,
        };
        let d1 = cp.get_signing_data();
        let d2 = cp.get_signing_data();
        assert_eq!(d1, d2);
        assert!(!d1.is_empty());
    }

    #[test]
    fn signing_data_includes_state_hash() {
        let cp = Checkpoint {
            id: "cp".into(),
            state_hash: [0xCC; 32],
            genesis_hash: [0; 32],
            tick: 0,
            device_id: "".into(),
            signature: vec![],
            merkle_proof: None,
            is_invalidation: false,
            invalidation_reason: None,
        };
        let data = cp.get_signing_data();
        assert_eq!(&data[0..32], &[0xCC; 32]);
    }

    #[test]
    fn signing_data_includes_genesis_hash() {
        let cp = Checkpoint {
            id: "cp".into(),
            state_hash: [0; 32],
            genesis_hash: [0xDD; 32],
            tick: 0,
            device_id: "".into(),
            signature: vec![],
            merkle_proof: None,
            is_invalidation: false,
            invalidation_reason: None,
        };
        let data = cp.get_signing_data();
        assert_eq!(&data[32..64], &[0xDD; 32]);
    }

    #[test]
    fn signing_data_includes_invalidation_flag() {
        let cp_normal = Checkpoint {
            id: "cp".into(),            state_hash: [0; 32],
            genesis_hash: [0; 32],
            tick: 0,
            device_id: "".into(),
            signature: vec![],
            merkle_proof: None,
            is_invalidation: false,
            invalidation_reason: None,
        };
        let cp_invalid = Checkpoint {
            id: "cp".into(),            state_hash: [0; 32],
            genesis_hash: [0; 32],
            tick: 0,
            device_id: "".into(),
            signature: vec![],
            merkle_proof: None,
            is_invalidation: true,
            invalidation_reason: Some("compromised".into()),
        };
        let d1 = cp_normal.get_signing_data();
        let d2 = cp_invalid.get_signing_data();
        assert_ne!(d1, d2);
    }

    // ── Checkpoint::add_merkle_proof ────────────────────────────────

    #[test]
    fn add_merkle_proof() {
        let mut cp = Checkpoint {
            id: "cp".into(),            state_hash: [0; 32],
            genesis_hash: [0; 32],
            tick: 0,
            device_id: "".into(),
            signature: vec![],
            merkle_proof: None,
            is_invalidation: false,
            invalidation_reason: None,
        };
        assert!(cp.merkle_proof.is_none());
        cp.add_merkle_proof(vec![1, 2, 3]);
        assert_eq!(cp.merkle_proof, Some(vec![1, 2, 3]));
    }

    // ── Checkpoint::verify_state ────────────────────────────────────

    #[test]
    fn verify_state_matching() {
        let state = make_dsm_state(10);
        let mut state_hash = [0u8; 32];
        let h = state.hash().unwrap();
        state_hash.copy_from_slice(&h[0..32]);

        let cp = Checkpoint {
            id: "cp".into(),            state_hash,
            genesis_hash: [0; 32],
            tick: 0,
            device_id: "".into(),
            signature: vec![],
            merkle_proof: None,
            is_invalidation: false,
            invalidation_reason: None,
        };
        assert!(cp.verify_state(&state).unwrap());
    }

    #[test]
    fn verify_state_wrong_hash() {
        let state = make_dsm_state(10);

        let cp = Checkpoint {
            id: "cp".into(),            state_hash: [0xFF; 32], // wrong
            genesis_hash: [0; 32],
            tick: 0,
            device_id: "".into(),
            signature: vec![],
            merkle_proof: None,
            is_invalidation: false,
            invalidation_reason: None,
        };
        assert!(!cp.verify_state(&state).unwrap());
    }

    // ── Checkpoint with Identity (bypasses sign for pure logic tests) ─

    #[test]
    fn checkpoint_verify_state_with_manual_construction() {
        let state = make_dsm_state(5);
        let hash_vec = state.hash().unwrap();
        let mut state_hash = [0u8; 32];
        state_hash.copy_from_slice(&hash_vec[..32]);

        let cp = Checkpoint {
            id: "cp_5".into(),            state_hash,
            genesis_hash: [0; 32],
            tick: 1,
            device_id: "test_device".into(),
            signature: vec![],
            merkle_proof: None,
            is_invalidation: false,
            invalidation_reason: None,
        };

        assert_eq!(cp.device_id, "test_device");
        assert!(!cp.is_invalidation);
        assert!(cp.invalidation_reason.is_none());
        assert!(cp.verify_state(&state).unwrap());
    }

    #[test]
    fn checkpoint_invalidation_fields() {
        let cp = Checkpoint {
            id: "cp_inv".into(),            state_hash: [0; 32],
            genesis_hash: [0; 32],
            tick: 1,
            device_id: "dev".into(),
            signature: vec![],
            merkle_proof: None,
            is_invalidation: true,
            invalidation_reason: Some("key compromised".into()),
        };
        assert!(cp.is_invalidation);
        assert_eq!(cp.invalidation_reason.as_deref(), Some("key compromised"));
    }

    // ── CheckpointManager ───────────────────────────────────────────

    #[test]
    fn checkpoint_manager_default() {
        let mgr = CheckpointManager::default();
        let dbg = format!("{:?}", mgr);
        assert!(dbg.contains("CheckpointManager"));
    }

    #[test]
    fn checkpoint_manager_new() {
        let _mgr = CheckpointManager::new();
    }

    // ── Checkpoint struct fields ────────────────────────────────────

    #[test]
    fn checkpoint_clone() {
        let cp = Checkpoint {
            id: "cp_1".into(),            state_hash: [0x01; 32],
            genesis_hash: [0x02; 32],
            tick: 42,
            device_id: "dev".into(),
            signature: vec![0x03; 10],
            merkle_proof: Some(vec![0x04; 5]),
            is_invalidation: true,
            invalidation_reason: Some("test".into()),
        };
        let cp2 = cp.clone();
        assert_eq!(cp.id, cp2.id);
        assert_eq!(cp.state_hash, cp2.state_hash);
        assert_eq!(cp.merkle_proof, cp2.merkle_proof);
        assert_eq!(cp.invalidation_reason, cp2.invalidation_reason);
    }

    #[test]
    fn checkpoint_debug_trait() {
        let cp = Checkpoint {
            id: "cp_dbg".into(),            state_hash: [0xFF; 32],
            genesis_hash: [0; 32],
            tick: 0,
            device_id: "d".into(),
            signature: vec![],
            merkle_proof: None,
            is_invalidation: false,
            invalidation_reason: None,
        };
        let dbg = format!("{:?}", cp);
        assert!(dbg.contains("cp_dbg"));
        assert!(dbg.contains("state_hash"));
    }

    #[test]
    fn signing_data_varies_with_device_id() {
        let cp_a = Checkpoint {
            id: "cp".into(),            state_hash: [0; 32],
            genesis_hash: [0; 32],
            tick: 0,
            device_id: "dev_a".into(),
            signature: vec![],
            merkle_proof: None,
            is_invalidation: false,
            invalidation_reason: None,
        };
        let cp_b = Checkpoint {
            id: "cp".into(),            state_hash: [0; 32],
            genesis_hash: [0; 32],
            tick: 0,
            device_id: "dev_b".into(),
            signature: vec![],
            merkle_proof: None,
            is_invalidation: false,
            invalidation_reason: None,
        };
        assert_ne!(cp_a.get_signing_data(), cp_b.get_signing_data());
    }

    #[test]
    fn signing_data_varies_with_tick() {
        let make = |tick: u64| Checkpoint {
            id: "cp".into(),            state_hash: [0; 32],
            genesis_hash: [0; 32],
            tick,
            device_id: "dev".into(),
            signature: vec![],
            merkle_proof: None,
            is_invalidation: false,
            invalidation_reason: None,
        };
        assert_ne!(make(1).get_signing_data(), make(2).get_signing_data());
    }
}
