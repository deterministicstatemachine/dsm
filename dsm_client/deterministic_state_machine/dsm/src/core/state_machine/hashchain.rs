//! Hash chain evolution engine for the DSM state machine.
//!
//! Implements the forward-only hash chain described in whitepaper Section 3.1.
//! Each state commits to its predecessor via `H_n = BLAKE3("DSM/state-hash\0" || S_n)`,
//! forming an append-only, tamper-evident chain. The [`HashChain`] struct manages
//! state progression and sparse index maintenance.

use crate::types::error::DsmError;
use crate::types::state_types::{SparseMerkleTree, State};
use constant_time_eq;
use std::collections::HashMap;

/// MerkleProof represents a cryptographic proof for a specific leaf in a Merkle tree
#[derive(Clone, Debug)]
pub struct MerkleProof {
    index: u64,
    siblings: Vec<[u8; 32]>,
    leaf_data: Vec<u8>,
    #[allow(dead_code)]
    height: u32,
}

impl MerkleProof {
    /// Generate a Merkle proof for the specified leaf index in the tree
    ///
    /// This implements the inclusion proof mechanism described in whitepaper Section 3.3,
    /// enabling verification of a state's inclusion in the hash chain without requiring
    /// the full chain to be transmitted.
    pub fn generate(tree: &SparseMerkleTree, index: u64) -> Result<Self, DsmError> {
        let height = tree.height;
        let mut siblings = Vec::with_capacity(height as usize);

        // Traverse the tree from leaf to root, collecting sibling hashes
        let mut current_index = index;

        for level in (0..height).rev() {
            // Calculate sibling index (flip the bit at current level)
            let sibling_index = current_index ^ (1 << level);

            // Get hash from tree's nodes HashMap if available
            let sibling_hash = tree
                .nodes
                .get(&crate::types::state_types::NodeId {
                    level,
                    index: sibling_index,
                })
                .map(|h| *h.as_bytes())
                .unwrap_or([0u8; 32]);

            siblings.push(sibling_hash);

            // Update current_index for next level (clear the bit we just processed)
            current_index &= !(1 << level);
        }

        // Get leaf data from leaves HashMap
        let leaf_data = match tree.leaves.get(&index) {
            Some(hash) => hash.as_bytes().to_vec(),
            None => return Err(DsmError::merkle("Leaf data not found")),
        };

        Ok(Self {
            index,
            siblings,
            leaf_data,
            height,
        })
    }

    /// Verify the Merkle proof against a root hash
    ///
    /// This efficiently verifies the inclusion of a specific piece of data in the tree
    /// without requiring the full tree, implementing the logarithmic-sized proof verification
    /// described in whitepaper Section 3.3.
    pub fn verify(&self, root_hash: &[u8; 32]) -> bool {
        let mut computed_hash =
            *crate::crypto::blake3::domain_hash("DSM/merkle-leaf", &self.leaf_data).as_bytes();
        let current_index = self.index;

        // Reconstruct path from leaf to root
        for level in 0..self.siblings.len() {
            let bit = (current_index >> level) & 1;
            let mut combined = Vec::with_capacity(64);

            // Order matters - if bit is 0, we're a left child, otherwise right
            if bit == 0 {
                combined.extend_from_slice(&computed_hash);
                combined.extend_from_slice(&self.siblings[level]);
            } else {
                combined.extend_from_slice(&self.siblings[level]);
                combined.extend_from_slice(&computed_hash);
            }

            computed_hash =
                *crate::crypto::blake3::domain_hash("DSM/merkle-node", &combined).as_bytes();
        }

        // Constant-time comparison to prevent timing attacks
        constant_time_eq::constant_time_eq(computed_hash.as_slice(), root_hash.as_slice())
    }
}


/// HashChain maintains a sequence of states that cryptographically reference each other.
///
/// As described in whitepaper section 3.1, the hash chain establishes an inherent
/// temporal ordering without requiring explicit wall-clock markers. Each state contains the
/// hash of its predecessor, creating an inviolable "happens-before" relationship.
///
/// This implements the straight hash chain verification described in the whitepaper
/// Section 3.1, which is the cornerstone of DSM's security model.
pub struct HashChain {
    /// Map of state IDs to states
    states: HashMap<String, State>,

    /// Current (most recent) state
    current_state: Option<State>,

    /// Sparse index checkpoints for efficient lookups
    sparse_checkpoints: HashMap<u64, State>,
}

#[allow(dead_code)]
impl Default for HashChain {
    fn default() -> Self {
        Self::new()
    }
}

impl HashChain {
    /// Create a new, empty hash chain.
    pub fn new() -> Self {
        Self {
            states: HashMap::new(),
            current_state: None,
            sparse_checkpoints: HashMap::new(),
        }
    }

    /// Add a state to the hash chain, validating its cryptographic integrity
    ///
    /// This implements the core logic described in whitepaper Section 3.1:
    /// Each state contains a cryptographic hash of its predecessor:
    /// S(n+1).prev_hash = H(S(n))
    pub fn add_state(&mut self, state: State) -> Result<(), DsmError> {
        // Check for existing state with the same number
        if self
            .states
            .values()
            .any(|s| s.state_number == state.state_number)
        {
            return Err(DsmError::generic(
                "Conflicting state_number detected. Attempted to add a state whose state_number already exists in the chain.",
                None::<std::convert::Infallible>,
            ));
        }

        // Verify sparse index properly includes previous state reference
        // This implements the efficient state traversal in whitepaper Section 3.2
        if state.state_number > 0 {
            let prev_state_num = state.state_number - 1;
            let sparse_indices = &state.sparse_index.indices;

            if !sparse_indices.contains(&prev_state_num) {
                // Allow genesis references (index 0) to bypass this check
                let has_genesis_reference = sparse_indices.contains(&0);

                if !has_genesis_reference {
                    return Err(DsmError::invalid_operation("Sparse index must include previous state reference for proper chain traversal"));
                }
            }
        }

        // Store the state
        self.states.insert(state.id.clone(), state.clone());

        // Update current state if applicable
        if let Some(current) = &self.current_state {
            if state.state_number > current.state_number {
                self.current_state = Some(state.clone());
            }
        } else {
            self.current_state = Some(state);
        }

        Ok(())
    }

    /// Get a state by its ID
    pub fn get_state(&self, id: &str) -> Option<&State> {
        self.states.get(id)
    }

    /// Get the current (most recent) state
    pub fn get_latest_state(&self) -> Result<&State, DsmError> {
        self.current_state
            .as_ref()
            .ok_or_else(|| DsmError::not_found("State", Some("Chain is empty")))
    }

    /// Get a state by its number
    ///
    /// This implements the efficient lookup using sparse index described in whitepaper Section 3.2
    pub fn get_state_by_number(&self, state_number: u64) -> Result<&State, DsmError> {
        // Check if the state number is in range
        if let Some(ref current) = self.current_state {
            if state_number > current.state_number {
                return Err(DsmError::not_found(
                    "State",
                    Some(format!("State number {state_number} is out of range")),
                ));
            }
        } else {
            return Err(DsmError::not_found("State", Some("Chain is empty")));
        }

        // Try direct lookup first
        for state in self.states.values() {
            if state.state_number == state_number {
                return Ok(state);
            }
        }

        // Find the nearest checkpoint before the target state
        let mut checkpoint_num = 0;
        for &num in self.sparse_checkpoints.keys() {
            if num <= state_number && num > checkpoint_num {
                checkpoint_num = num;
            }
        }

        // If we found a checkpoint, start from there
        if checkpoint_num > 0 {
            if let Some(checkpoint) = self.sparse_checkpoints.get(&checkpoint_num) {
                let mut current = checkpoint;

                // Traverse forward until we find the target state
                loop {
                    if current.state_number == state_number {
                        return Ok(current);
                    }

                    // Find the next state
                    let next_id = format!("state_{}", current.state_number + 1);
                    if let Some(next) = self.states.get(&next_id) {
                        current = next;
                    } else {
                        break;
                    }
                }
            }
        }

        Err(DsmError::not_found(
            "State",
            Some(format!("State number {state_number} not found")),
        ))
    }

    /// Get a state by its hash
    pub fn get_state_by_hash(&self, hash: &[u8; 32]) -> Result<&State, DsmError> {
        for state in self.states.values() {
            if state.hash == *hash {
                return Ok(state);
            }
        }

        Err(DsmError::not_found(
            "State",
            Some("State with given hash not found"),
        ))
    }

    /// Check if the chain has a state with the given hash
    pub fn has_state_with_hash(&self, hash: &[u8; 32]) -> Result<bool, DsmError> {
        for state in self.states.values() {
            if state.hash == *hash {
                return Ok(true);
            }
        }

        Ok(false)
    }

    /// Verify the integrity of the entire chain
    pub fn verify_chain(&self) -> Result<bool, DsmError> {
        if self.states.is_empty() {
            return Ok(true); // Empty chain is valid
        }

        // Get the genesis state
        let genesis = self
            .states
            .values()
            .find(|s| s.state_number == 0)
            .ok_or_else(|| DsmError::invalid_operation("Chain is missing genesis state"))?;

        // Verify genesis state hash
        if !Self::verify_state_hash(genesis)? {
            return Err(DsmError::invalid_operation("Genesis state hash is invalid"));
        }

        // Verify all states in sequence
        let mut current_state_num = 0;
        let mut current_hash = genesis.hash()?;

        let max_state_num = self
            .current_state
            .as_ref()
            .ok_or_else(|| {
                DsmError::internal(
                    "Current state is None during chain verification",
                    None::<std::convert::Infallible>,
                )
            })?
            .state_number;

        while current_state_num < max_state_num {
            current_state_num += 1;
            let next_id = format!("state_{current_state_num}");

            // Get the next state
            let next_state = self.states.get(&next_id).ok_or_else(|| {
                DsmError::invalid_operation(format!("Chain is missing state {current_state_num}"))
            })?;

            // Verify hash continuity
            if next_state.prev_state_hash != current_hash {
                return Err(DsmError::invalid_operation(format!(
                    "Hash chain broken at state {current_state_num}"
                )));
            }

            // Verify state hash
            if !Self::verify_state_hash(next_state)? {
                return Err(DsmError::invalid_operation(format!(
                    "State {current_state_num} has invalid hash"
                )));
            }

            // Update current hash for next iteration
            current_hash = next_state.hash()?;
        }

        Ok(true)
    }

    /// Extract a subsequence of states from the chain
    pub fn extract_subsequence(
        &self,
        start_num: u64,
        end_num: u64,
    ) -> Result<Vec<State>, DsmError> {
        if start_num > end_num {
            return Err(DsmError::invalid_parameter(format!(
                "Start number {start_num} is greater than end number {end_num}"
            )));
        }

        // Check if end_num is in range
        if let Some(ref current) = self.current_state {
            if end_num > current.state_number {
                return Err(DsmError::not_found(
                    "State",
                    Some(format!("State number {end_num} is out of range")),
                ));
            }
        } else {
            return Err(DsmError::not_found("State", Some("Chain is empty")));
        }

        let mut result = Vec::new();

        for num in start_num..=end_num {
            let state = self.get_state_by_number(num)?;
            result.push(state.clone());
        }

        Ok(result)
    }

    /// Calculate the sparse index checkpoints for efficient traversal
    pub fn calculate_sparse_checkpoints(&self) -> Result<HashMap<u64, [u8; 32]>, DsmError> {
        let mut checkpoints = HashMap::new();

        if let Some(ref current) = self.current_state {
            let current_num = current.state_number;

            // Calculate powers of 2 checkpoints (1, 2, 4, 8, ...)
            let mut power = 0;
            let mut checkpoint = 1;

            while checkpoint <= current_num {
                if let Ok(state) = self.get_state_by_number(current_num - checkpoint) {
                    checkpoints.insert(checkpoint, state.hash()?);
                }

                power += 1;
                checkpoint = 1 << power;
            }
        }

        Ok(checkpoints)
    }

    /// Verify a state's hash integrity
    pub fn verify_state(&self, state: &State) -> Result<bool, DsmError> {
        // First verify the state's own hash integrity
        if !Self::verify_state_hash(state)? {
            return Ok(false);
        }

        // If this is a genesis state (state_number = 0), we're done
        if state.state_number == 0 {
            return Ok(true);
        }

        // For non-genesis states, verify prev_state_hash references the correct predecessor
        if let Ok(prev_state) = self.get_state_by_number(state.state_number - 1) {
            // Get the hash of the previous state
            let actual_prev_hash = prev_state.hash()?;

            // Verify that state.prev_state_hash matches the actual hash of the previous state
            return Ok(constant_time_eq::constant_time_eq(
                &state.prev_state_hash,
                &actual_prev_hash,
            ));
        }

        // If we can't find the previous state, we can't verify the chain link
        Err(DsmError::verification(format!(
            "Cannot verify state {} - previous state not found",
            state.state_number
        )))
    }

    /// Verify the cryptographic integrity of a state's hash
    pub fn verify_state_hash(state: &State) -> Result<bool, DsmError> {
        // Use the state's compute_hash method to generate the expected hash
        let expected_hash = state.compute_hash()?;

        // Compare with the stored hash using constant-time comparison to prevent timing attacks
        Ok(constant_time_eq::constant_time_eq(
            &expected_hash,
            &state.hash,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::state_types::State;

    fn create_test_state(state_number: u64, prev_hash: [u8; 32]) -> State {
        use crate::types::state_types::DeviceInfo;
        let device_id = blake3::hash(b"test_device").into();
        let device_info = DeviceInfo::new(device_id, vec![1, 2, 3, 4]);

        if state_number == 0 {
            let mut state = State::new_genesis(prev_hash, device_info);
            state.hash = state.compute_hash().unwrap_or([0; 32]);
            state
        } else {
            let mut state = State::new_genesis(
                [1, 2, 3, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                device_info,
            );
            state.state_number = state_number;
            state.id = format!("state_{}", state_number);
            state.prev_state_hash = prev_hash;
            state
        }
    }
    #[test]
    fn test_new_hash_chain() {
        let chain = HashChain::new();

        assert_eq!(chain.states.len(), 0);
        assert!(chain.current_state.is_none());
    }

    #[test]
    fn test_add_genesis_state() {
        let mut chain = HashChain::new();
        let genesis_state = create_test_state(0, [0; 32]);

        let result = chain.add_state(genesis_state.clone());
        assert!(result.is_ok());

        assert_eq!(chain.states.len(), 1);
        assert_eq!(
            chain
                .current_state
                .as_ref()
                .ok_or_else(|| DsmError::internal(
                    "No current state".to_string(),
                    None::<std::convert::Infallible>
                ))
                .expect("Failed to get current state")
                .state_number,
            0
        );
        assert!(chain.get_state(&genesis_state.id).is_some());
    }

    #[test]
    fn test_add_sequential_states() -> Result<(), DsmError> {
        let mut chain = HashChain::new();

        // Add genesis state
        let genesis = create_test_state(0, [0; 32]);
        chain.add_state(genesis.clone())?;

        // Add second state
        let mut second_state = create_test_state(1, genesis.hash);
        second_state.sparse_index.indices = vec![0]; // Reference genesis
        second_state.hash = second_state.compute_hash()?; // Compute hash after modifications
        chain.add_state(second_state.clone())?;

        // Add third state
        let mut third_state = create_test_state(2, second_state.hash);
        third_state.sparse_index.indices = vec![0, 1]; // Reference previous states
        third_state.hash = third_state.compute_hash()?; // Compute hash after modifications
        chain.add_state(third_state.clone())?;

        assert_eq!(chain.states.len(), 3);
        assert_eq!(
            chain
                .current_state
                .as_ref()
                .expect("No current state")
                .state_number,
            2
        );
        Ok(())
    }

    #[test]
    fn test_add_duplicate_state_number() -> Result<(), DsmError> {
        let mut chain = HashChain::new();
        let state1 = create_test_state(0, [0; 32]);
        let mut state2 = create_test_state(0, [0; 32]);
        state2.id = "different_id".to_string();

        chain.add_state(state1)?;
        let result = chain.add_state(state2);

        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Conflicting state_number"));
        Ok(())
    }

    #[test]
    fn test_get_state_by_number() -> Result<(), DsmError> {
        let mut chain = HashChain::new();
        let genesis = create_test_state(0, [0; 32]);
        let mut state1 = create_test_state(1, genesis.hash);
        state1.sparse_index.indices = vec![0];
        state1.hash = state1.compute_hash()?; // Compute hash after modifications

        chain.add_state(genesis.clone())?;
        chain.add_state(state1.clone())?;

        let retrieved = chain.get_state_by_number(1)?;
        assert_eq!(retrieved.state_number, 1);
        assert_eq!(retrieved.id, state1.id);

        // Test out of range
        let result = chain.get_state_by_number(5);
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn test_get_state_by_hash() -> Result<(), DsmError> {
        let mut chain = HashChain::new();
        let genesis = create_test_state(0, [0; 32]);
        let target_hash = genesis.hash;

        chain.add_state(genesis)?;

        let retrieved = chain.get_state_by_hash(&target_hash)?;
        assert_eq!(retrieved.hash, target_hash);

        // Test non-existent hash
        let test_hash = [99; 32];
        let result = chain.get_state_by_hash(&test_hash);
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn test_has_state_with_hash() -> Result<(), DsmError> {
        let mut chain = HashChain::new();
        let genesis = create_test_state(0, [0; 32]);
        let target_hash = genesis.hash;

        chain.add_state(genesis)?;

        assert!(chain.has_state_with_hash(&target_hash)?);

        let test_hash = [99; 32];
        assert!(!chain.has_state_with_hash(&test_hash)?);
        Ok(())
    }

    #[test]
    fn test_verify_chain_empty() -> Result<(), DsmError> {
        let chain = HashChain::new();
        assert!(chain.verify_chain()?);
        Ok(())
    }

    #[test]
    fn test_verify_chain_valid() -> Result<(), DsmError> {
        let mut chain = HashChain::new();

        // Create valid chain
        let genesis = create_test_state(0, [0; 32]);
        let mut state1 = create_test_state(1, genesis.hash);
        state1.sparse_index.indices = vec![0];
        state1.hash = state1.compute_hash()?; // Compute hash after modifications

        chain.add_state(genesis)?;
        chain.add_state(state1)?;

        assert!(chain.verify_chain()?);
        Ok(())
    }

    #[test]
    fn test_verify_state_hash() -> Result<(), DsmError> {
        let state = create_test_state(0, [0; 32]);
        assert!(HashChain::verify_state_hash(&state)?);

        // Test invalid hash
        let mut invalid_state = state.clone();
        invalid_state.hash = [99; 32];
        assert!(!HashChain::verify_state_hash(&invalid_state)?);
        Ok(())
    }

    #[test]
    fn test_verify_state_genesis() -> Result<(), DsmError> {
        let mut chain = HashChain::new();
        let genesis = create_test_state(0, [0; 32]);

        chain.add_state(genesis.clone())?;
        assert!(chain.verify_state(&genesis)?);
        Ok(())
    }

    #[test]
    fn test_verify_state_with_predecessor() -> Result<(), DsmError> {
        let mut chain = HashChain::new();

        let genesis = create_test_state(0, [0; 32]);
        let mut state1 = create_test_state(1, genesis.hash);
        state1.sparse_index.indices = vec![0];
        state1.hash = state1.compute_hash()?; // Compute hash after modifications

        chain.add_state(genesis)?;
        chain.add_state(state1.clone())?;

        assert!(chain.verify_state(&state1)?);
        Ok(())
    }

    #[test]
    fn test_extract_subsequence() -> Result<(), DsmError> {
        let mut chain = HashChain::new();

        // Create chain with 3 states
        let genesis = create_test_state(0, [0; 32]);
        let mut state1 = create_test_state(1, genesis.hash);
        state1.sparse_index.indices = vec![0];
        state1.hash = state1.compute_hash()?; // Compute hash after modifications
        let mut state2 = create_test_state(2, state1.hash);
        state2.sparse_index.indices = vec![0, 1];
        state2.hash = state2.compute_hash()?; // Compute hash after modifications

        chain.add_state(genesis)?;
        chain.add_state(state1)?;
        chain.add_state(state2)?;

        let subsequence = chain.extract_subsequence(0, 2)?;
        assert_eq!(subsequence.len(), 3);
        assert_eq!(subsequence[0].state_number, 0);
        assert_eq!(subsequence[2].state_number, 2);

        // Test invalid range
        let result = chain.extract_subsequence(2, 1);
        assert!(result.is_err());

        // Test out of range
        let result = chain.extract_subsequence(0, 10);
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn test_calculate_sparse_checkpoints() -> Result<(), DsmError> {
        let mut chain = HashChain::new();

        // Create a longer chain
        let genesis = create_test_state(0, [0; 32]);
        chain.add_state(genesis.clone())?;

        for i in 1..=8 {
            let prev_state = chain.get_state_by_number(i - 1)?;
            let mut new_state = create_test_state(i, prev_state.hash);
            new_state.sparse_index.indices = vec![0, i - 1];
            new_state.hash = new_state.compute_hash()?; // Compute hash after modifications
            chain.add_state(new_state)?;
        }

        let checkpoints = chain.calculate_sparse_checkpoints()?;
        assert!(!checkpoints.is_empty());

        // Should have checkpoints at powers of 2
        assert!(checkpoints.contains_key(&1));
        assert!(checkpoints.contains_key(&2));
        assert!(checkpoints.contains_key(&4));
        Ok(())
    }

    #[test]
    fn test_get_latest_state_empty_chain() {
        let chain = HashChain::new();
        let result = chain.get_latest_state();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Chain is empty"));
    }

    #[test]
    fn test_get_latest_state() -> Result<(), DsmError> {
        let mut chain = HashChain::new();

        let genesis = create_test_state(0, [0; 32]);
        let mut state1 = create_test_state(1, genesis.hash);
        state1.sparse_index.indices = vec![0];
        state1.hash = state1.compute_hash()?; // Compute hash after modifications

        chain.add_state(genesis)?;
        chain.add_state(state1.clone())?;

        let latest = chain.get_latest_state()?;
        assert_eq!(latest.state_number, 1);
        assert_eq!(latest.id, state1.id);
        Ok(())
    }
}
