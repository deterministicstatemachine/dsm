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
/// in the state hash chain that has been posted to decentralized storage
#[derive(Debug, Clone)]
pub struct Checkpoint {
    /// Unique identifier for this checkpoint
    pub id: String,

    /// State number this checkpoint represents
    pub state_number: u64,

    /// Hash of the state
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

        let id = format!(
            "checkpoint_{state_number}_{tick}_{device_id}",
            state_number = state.state_number,
            tick = tick,
            device_id = device_id
        );

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

        // Create the unsigned checkpoint
        let mut checkpoint = Self {
            id,
            state_number: state.state_number,
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

        // Add state number (8 bytes)
        data.extend_from_slice(&self.state_number.to_be_bytes());

        // Add state hash (32 bytes)
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

        // Compare state hash and state number
        Ok(self.state_hash == state_hash_array && self.state_number == state.state_number)
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
