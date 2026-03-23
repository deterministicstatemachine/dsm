//! Sparse Index Implementation
//!
//! This module implements the sparse index functionality described in whitepaper Section 10.2.
//! It provides efficient state lookups through checkpoint storage and management.

use crate::merkle::sparse_merkle_tree::SparseMerkleTreeImpl;
use crate::types::error::DsmError;
use crate::types::state_types::State;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

/// The `SparseIndexManager` maintains checkpoints at regular intervals for efficient state lookups.
///
/// As described in the whitepaper Section 10.2, the sparse index maintains checkpoints at regular intervals:
/// SI = {S₀, Sₖ, S₂ₖ, ..., Sₙₖ} where k is the checkpoint interval.
///
/// This enables O(log n) lookup for checkpoint states and efficient traversal for non-checkpoint states.
#[derive(Clone)]
pub struct SparseIndexManager {
    /// Map of state number to checkpointed state
    checkpoints: Arc<RwLock<HashMap<u64, State>>>,

    /// Map of state hash to state number for reverse lookups
    hash_to_number: Arc<RwLock<HashMap<[u8; 32], u64>>>,

    /// The checkpoint interval (k)
    checkpoint_interval: u64,

    /// Optional Sparse Merkle Tree integration for inclusion proofs
    merkle_tree: Option<Arc<RwLock<SparseMerkleTreeImpl>>>,

    /// Maximum checkpoint age to keep (for pruning)
    max_checkpoint_age: Option<u64>,

    /// Current highest state number
    highest_state: Arc<RwLock<u64>>,
}

impl SparseIndexManager {
    /// Create a new sparse index manager with the specified checkpoint interval
    ///
    /// # Arguments
    /// * `checkpoint_interval` - The interval (k) at which to store checkpoints
    /// * `with_merkle_tree` - Whether to integrate with a Sparse Merkle Tree for inclusion proofs
    /// * `merkle_tree_height` - The height of the Merkle tree (if enabled)
    /// * `max_checkpoint_age` - Optional maximum age of checkpoints to keep
    pub fn new(
        checkpoint_interval: u64,
        with_merkle_tree: bool,
        merkle_tree_height: Option<u32>,
        max_checkpoint_age: Option<u64>,
    ) -> Self {
        let merkle_tree = if with_merkle_tree {
            Some(Arc::new(RwLock::new(SparseMerkleTreeImpl::new(
                merkle_tree_height.unwrap_or(20),
            ))))
        } else {
            None
        };

        SparseIndexManager {
            checkpoints: Arc::new(RwLock::new(HashMap::new())),
            hash_to_number: Arc::new(RwLock::new(HashMap::new())),
            checkpoint_interval,
            merkle_tree,
            max_checkpoint_age,
            highest_state: Arc::new(RwLock::new(0)),
        }
    }

    /// Determine if a state number is a checkpoint according to the interval
    ///
    /// # Arguments
    /// * `state_number` - The state number to check
    ///
    /// # Returns
    /// * `bool` - Whether the state is a checkpoint
    pub fn is_checkpoint(&self, state_number: u64) -> bool {
        state_number.is_multiple_of(self.checkpoint_interval) || state_number == 0
    }

    /// Add a state to the sparse index, storing it if it's a checkpoint
    ///
    /// # Arguments
    /// * `state` - The state to add
    ///
    /// # Returns
    /// * `Result<(), DsmError>` - Success or an error
    pub fn add_state(&self, state: State) -> Result<(), DsmError> {
        let state_number = state.state_number;
        let state_hash = state.hash()?;

        // Update mapping of hash to state number for reverse lookups
        {
            let mut hash_map = self
                .hash_to_number
                .write()
                .map_err(|_| DsmError::LockError)?;
            hash_map.insert(state_hash, state_number);
        }

        // Update highest state number
        {
            let mut highest = self
                .highest_state
                .write()
                .map_err(|_| DsmError::LockError)?;
            if state_number > *highest {
                *highest = state_number;
            }
        }

        // Store checkpoint if applicable
        if self.is_checkpoint(state_number) {
            let mut checkpoints = self.checkpoints.write().map_err(|_| DsmError::LockError)?;
            checkpoints.insert(state_number, state.clone());

            // Add to Merkle tree if enabled
            if let Some(ref tree) = self.merkle_tree {
                let mut tree = tree.write().map_err(|_| DsmError::LockError)?;
                tree.insert(state_number, &state_hash)?;
            }

            // Prune old checkpoints if max age is set
            if let Some(max_age) = self.max_checkpoint_age {
                let highest = self.get_highest_state_number()?;
                if highest > max_age {
                    let cutoff = highest - max_age;
                    checkpoints.retain(|&num, _| {
                        num == 0 || num > cutoff || num % (self.checkpoint_interval * 10) == 0
                    });
                }
            }
        }

        Ok(())
    }

    /// Get the highest state number currently tracked
    ///
    /// # Returns
    /// * `Result<u64, DsmError>` - The highest state number
    pub fn get_highest_state_number(&self) -> Result<u64, DsmError> {
        let highest = self.highest_state.read().map_err(|_| DsmError::LockError)?;
        Ok(*highest)
    }

    /// Get a state by its number using sparse index for efficient lookup
    ///
    /// As described in the whitepaper Section 10.2:
    /// 1. Find the nearest checkpoint before the target state
    /// 2. Traverse forward from that checkpoint
    ///
    /// # Arguments
    /// * `state_number` - The state number to retrieve
    /// * `fetch_state_callback` - Function to retrieve states not in the sparse index
    ///
    /// # Returns
    /// * `Result<Option<State>, DsmError>` - The state if found, or None
    pub fn get_state_by_number<F>(
        &self,
        state_number: u64,
        fetch_state_callback: F,
    ) -> Result<Option<State>, DsmError>
    where
        F: Fn(u64) -> Result<Option<State>, DsmError>,
    {
        // First check if the requested state is a checkpoint
        {
            let checkpoints = self.checkpoints.read().map_err(|_| DsmError::LockError)?;

            if let Some(state) = checkpoints.get(&state_number) {
                return Ok(Some(state.clone()));
            }
        }

        // Find the nearest checkpoint before the target state
        let checkpoint_number = self.get_nearest_checkpoint_before(state_number)?;

        let checkpoint_num = match checkpoint_number {
            Some(num) => num,
            None => return Ok(None),
        };

        // Get the checkpoint state
        let checkpoint_state = {
            let checkpoints = self.checkpoints.read().map_err(|_| DsmError::LockError)?;

            if let Some(state) = checkpoints.get(&checkpoint_num) {
                state.clone()
            } else {
                // This shouldn't happen if the index is consistent
                return Err(DsmError::invalid_operation(format!(
                    "Checkpoint state {checkpoint_num} not found in sparse index"
                )));
            }
        };

        // If the checkpoint is the requested state, return it
        if checkpoint_num == state_number {
            return Ok(Some(checkpoint_state));
        }

        // Otherwise, traverse forward from checkpoint
        let mut current_state = checkpoint_state;

        for next_num in (checkpoint_num + 1)..=state_number {
            match fetch_state_callback(next_num)? {
                Some(state) => {
                    // Verify hash chain continuity
                    if state.prev_state_hash != current_state.hash()? {
                        return Err(DsmError::invalid_operation(format!(
                            "Hash chain discontinuity at state {next_num}"
                        )));
                    }

                    current_state = state;

                    // We've reached the requested state
                    if next_num == state_number {
                        return Ok(Some(current_state));
                    }
                }
                None => {
                    // State not found in primary storage
                    return Ok(None);
                }
            }
        }

        // Should never reach here
        Ok(None)
    }

    /// Get the nearest checkpoint state number before the given state number
    ///
    /// # Arguments
    /// * `state_number` - The target state number
    ///
    /// # Returns
    /// * `Result<Option<u64>, DsmError>` - The nearest checkpoint number, if any
    fn get_nearest_checkpoint_before(&self, state_number: u64) -> Result<Option<u64>, DsmError> {
        let checkpoints = self.checkpoints.read().map_err(|_| DsmError::LockError)?;

        Ok(checkpoints
            .keys()
            .filter(|&&k| k <= state_number)
            .max()
            .copied())
    }

    /// Generate a Merkle inclusion proof for a state
    ///
    /// # Arguments
    /// * `state_number` - The state number to generate a proof for
    ///
    /// # Returns
    /// * `Result<Option<crate::types::state_types::MerkleProof>, DsmError>` - The Merkle proof, if available
    pub fn generate_merkle_proof(
        &self,
        state_number: u64,
    ) -> Result<Option<crate::types::state_types::MerkleProof>, DsmError> {
        if let Some(ref tree) = self.merkle_tree {
            let tree = tree.read().map_err(|_| DsmError::LockError)?;

            let proof = tree.get_proof(state_number)?;
            Ok(Some(proof))
        } else {
            Ok(None)
        }
    }

    /// Verify a Merkle proof for a state
    ///
    /// # Arguments
    /// * `state` - The state to verify
    /// * `proof` - The Merkle proof
    ///
    /// # Returns
    /// * `Result<bool, DsmError>` - Whether the proof is valid
    pub fn verify_merkle_proof(
        &self,
        state: &State,
        proof: &crate::types::state_types::MerkleProof,
    ) -> Result<bool, DsmError> {
        if let Some(ref tree) = self.merkle_tree {
            let tree = tree.read().map_err(|_| DsmError::LockError)?;

            let state_hash = state.hash()?;
            let root_hash = tree.root();

            crate::merkle::sparse_merkle_tree::verify_proof(*root_hash, &state_hash, proof)
        } else {
            Ok(false)
        }
    }
}
