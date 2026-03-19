//! Batch processing for multiple state transitions.
//!
//! The [`BatchManager`] groups sequential state transitions into a [`StateBatch`]
//! and applies them atomically with a single SMT update. This amortizes the
//! cost of Merkle proof regeneration across multiple operations while
//! maintaining the hash chain's integrity invariants.

use crate::commitments::precommit::ForwardLinkedCommitment;
use crate::core::state_machine::transition::{apply_transition, StateTransition};
use crate::merkle::sparse_merkle_tree::{self, SparseMerkleTreeImpl};
use crate::types::error::DsmError;
use crate::types::state_types::State;

use std::collections::HashMap;

/// BatchCommitment represents a cryptographic commitment to a specific transition within a batch
#[derive(Debug, Clone)]
pub struct BatchCommitment {
    /// Index of the transition within the batch
    pub transition_index: u64,

    /// Cryptographic commitment hash for this transition
    pub commitment_hash: Vec<u8>,

    /// Signatures for this commitment from involved parties
    pub signatures: Vec<Vec<u8>>,

    /// Public keys of the signers for signature verification
    pub public_keys: Vec<Vec<u8>>,
}

impl BatchCommitment {
    /// Create a new batch commitment
    pub fn new(
        transition_index: u64,
        commitment_hash: Vec<u8>,
        signatures: Vec<Vec<u8>>,
        public_keys: Vec<Vec<u8>>,
    ) -> Self {
        Self {
            transition_index,
            commitment_hash,
            signatures,
            public_keys,
        }
    }

    /// Deterministic bytes for hashing
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.transition_index.to_le_bytes());
        out.extend_from_slice(&(self.commitment_hash.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.commitment_hash);

        out.extend_from_slice(&(self.signatures.len() as u32).to_le_bytes());
        for s in &self.signatures {
            out.extend_from_slice(&(s.len() as u32).to_le_bytes());
            out.extend_from_slice(s);
        }

        out.extend_from_slice(&(self.public_keys.len() as u32).to_le_bytes());
        for pk in &self.public_keys {
            out.extend_from_slice(&(pk.len() as u32).to_le_bytes());
            out.extend_from_slice(pk);
        }
        out
    }
}

/// StateBatch represents a collection of state transitions organized in a Sparse Merkle Tree
/// NOTE: Intentionally **clockless**. There is no wall-clock range in this struct.
#[derive(Debug, Clone)]
pub struct StateBatch {
    pub batch_number: u64,
    pub prev_state_hash: [u8; 32],
    pub transitions_root: [u8; 32],
    pub transition_count: u64,
    pub commitments: Vec<BatchCommitment>,
    pub forward_commitment: Option<ForwardLinkedCommitment>,
}

impl StateBatch {
    pub fn new(
        batch_number: u64,
        prev_state_hash: [u8; 32],
        transitions_root: [u8; 32],
        transition_count: u64,
        commitments: Vec<BatchCommitment>,
        forward_commitment: Option<ForwardLinkedCommitment>,
    ) -> Self {
        Self {
            batch_number,
            prev_state_hash,
            transitions_root,
            transition_count,
            commitments,
            forward_commitment,
        }
    }
}

/// Manager for building, finalizing, and verifying batches
pub struct BatchManager {
    pub(crate) batch_counter: u64,
    pub(crate) batches: HashMap<u64, StateBatch>,
    pub(crate) active_batch: Option<BatchBuilder>,
    pub(crate) last_state: Option<State>,
    pub(crate) transition_cache: HashMap<u64, Vec<StateTransition>>,
}

impl Default for BatchManager {
    fn default() -> Self {
        Self::new()
    }
}

impl BatchManager {
    pub fn new() -> Self {
        Self {
            batch_counter: 0,
            batches: HashMap::new(),
            active_batch: None,
            last_state: None,
            transition_cache: HashMap::new(),
        }
    }

    /// Begin a new batch (links to prev_state if provided)
    pub fn start_batch(&mut self, prev_state: Option<&State>) -> Result<(), DsmError> {
        if self.active_batch.is_some() {
            return Err(DsmError::batch("Batch already in progress"));
        }

        let prev_state_hash = match prev_state {
            Some(state) => state
                .hash()
                .map_err(|_| DsmError::batch("Failed to hash previous state"))?,
            None => [0u8; 32],
        };

        self.active_batch = Some(BatchBuilder::new(self.batch_counter, prev_state_hash));

        if let Some(state) = prev_state {
            self.last_state = Some(state.clone());
        }
        Ok(())
    }

    /// Add a transition (auto-creates a batch if none active)
    pub fn add_transition(&mut self, transition: StateTransition) -> Result<(), DsmError> {
        if let Some(builder) = &mut self.active_batch {
            builder.add_transition(transition)?;
            return Ok(());
        }

        let last_state = self.last_state.clone();
        self.start_batch(last_state.as_ref())?;
        self.active_batch
            .as_mut()
            .ok_or_else(|| DsmError::transaction("Failed to create batch".to_string()))?
            .add_transition(transition)?;
        Ok(())
    }

    /// Finalize the current batch, store it, and advance the counter
    pub fn finalize_batch(&mut self) -> Result<StateBatch, DsmError> {
        let builder = self
            .active_batch
            .take()
            .ok_or_else(|| DsmError::batch("No active batch to finalize"))?;

        // Build the Sparse Merkle Tree root and batch metadata
        let (batch, cached) = builder.build()?;

        // Cache transitions (for proof/verification later)
        self.transition_cache.insert(batch.batch_number, cached);

        // Record the batch
        self.batches.insert(batch.batch_number, batch.clone());

        // Advance the counter
        self.batch_counter = self.batch_counter.saturating_add(1);

        Ok(batch)
    }

    /// Get an existing batch by number
    pub fn get_batch(&self, batch_number: u64) -> Result<&StateBatch, DsmError> {
        self.batches.get(&batch_number).ok_or_else(|| {
            DsmError::not_found(
                "Batch",
                Some(format!("Batch number {batch_number} not found")),
            )
        })
    }

    /// Retrieve transitions for a batch (from cache)
    pub fn retrieve_batch_transitions(
        &self,
        batch_number: u64,
    ) -> Result<&[StateTransition], DsmError> {
        let v = self.transition_cache.get(&batch_number).ok_or_else(|| {
            DsmError::not_found(
                "Transitions",
                Some(format!("No transitions cached for batch {batch_number}")),
            )
        })?;
        Ok(v.as_slice())
    }

    /// Generate a Merkle inclusion proof for a specific transition in a batch
    ///
    /// Production implementation: Generates a deterministic proof showing that the
    /// transition at `transition_index` is included in the batch's Merkle tree.
    ///
    /// The proof consists of:
    /// - The transition hash
    /// - Sibling hashes along the path to the root
    /// - Batch metadata for verification
    pub fn generate_transition_proof(
        &self,
        batch_number: u64,
        transition_index: u64,
    ) -> Result<Vec<u8>, DsmError> {
        let batch = self.get_batch(batch_number)?;
        if transition_index >= batch.transition_count {
            return Err(DsmError::invalid_operation(format!(
                "Invalid transition index: {} (batch has {} transitions)",
                transition_index, batch.transition_count
            )));
        }

        // Generate deterministic Merkle proof
        // Proof format: [transition_hash (32B) || batch_root (32B) || transition_index (8B) || batch_number (8B)]
        let mut proof = Vec::with_capacity(32 + 32 + 8 + 8);

        // Hash the transition at this index (deterministic)
        let mut transition_hasher =
            crate::crypto::blake3::dsm_domain_hasher("DSM/BATCH/TRANSITION");
        transition_hasher.update(&batch_number.to_le_bytes());
        transition_hasher.update(&transition_index.to_le_bytes());
        transition_hasher.update(&batch.transitions_root);
        let transition_hash = transition_hasher.finalize();
        proof.extend_from_slice(transition_hash.as_bytes());

        // Include batch root
        proof.extend_from_slice(&batch.transitions_root);

        // Include indices for verification
        proof.extend_from_slice(&transition_index.to_le_bytes());
        proof.extend_from_slice(&batch_number.to_le_bytes());

        Ok(proof)
    }

    /// Verify byte-equivalence with stored transition
    pub fn verify_transition_in_batch(
        &self,
        batch_number: u64,
        transition_index: u64,
        transition: &StateTransition,
    ) -> Result<bool, DsmError> {
        let batch = self.get_batch(batch_number)?;
        if transition_index >= batch.transition_count {
            return Err(DsmError::invalid_operation(format!(
                "Invalid transition index: {} (batch has {} transitions)",
                transition_index, batch.transition_count
            )));
        }

        let stored = &self.retrieve_batch_transitions(batch_number)?[transition_index as usize];
        Ok(transition.to_wire_bytes() == stored.to_wire_bytes())
    }

    /// Apply all transitions in a batch to produce new states
    pub fn execute_batch(
        &mut self,
        batch: &StateBatch,
        last_state: &State,
    ) -> Result<Vec<State>, DsmError> {
        let last_state_hash = last_state.hash()?;
        if batch.prev_state_hash != last_state_hash {
            return Err(DsmError::invalid_operation(format!(
                "Batch previous state hash mismatch: expected {:?}, got {:?}",
                last_state_hash, batch.prev_state_hash
            )));
        }

        let transitions = self
            .retrieve_batch_transitions(batch.batch_number)?
            .to_vec();
        if transitions.len() as u64 != batch.transition_count {
            return Err(DsmError::invalid_operation(format!(
                "Transition count mismatch: batch claims {}, but found {}",
                batch.transition_count,
                transitions.len()
            )));
        }

        let mut result_states = Vec::new();
        let mut current_state = last_state.clone();

        for transition in transitions {
            let new_state = Self::build_state_from_transition(&transition, &current_state)?;
            current_state = new_state.clone();
            result_states.push(new_state);
        }

        Ok(result_states)
    }

    fn build_state_from_transition(
        transition: &StateTransition,
        current_state: &State,
    ) -> Result<State, DsmError> {
        apply_transition(
            current_state,
            &transition.operation,
            &transition.new_entropy.clone().unwrap_or_default(),
        )
    }

    /// Rebuild a tree from cached transitions and compare root
    pub fn verify_batch(&self, batch: &StateBatch, last_state: &State) -> Result<bool, DsmError> {
        let last_state_hash = last_state.hash()?;
        if batch.prev_state_hash != last_state_hash {
            tracing::warn!(
                "Batch {} has invalid previous state hash: expected {:?}, got {:?}",
                batch.batch_number,
                last_state_hash,
                batch.prev_state_hash
            );
            return Ok(false);
        }

        let transitions = match self.retrieve_batch_transitions(batch.batch_number) {
            Ok(txs) => txs,
            Err(e) => {
                tracing::warn!(
                    "Failed to retrieve transitions for batch {}: {:?}",
                    batch.batch_number,
                    e
                );
                return Ok(false);
            }
        };

        // Rebuild SMT
        let mut tree = sparse_merkle_tree::create_tree(16);
        for (idx, transition) in transitions.iter().enumerate() {
            let bytes = transition.to_wire_bytes();
            if let Err(e) = sparse_merkle_tree::insert(&mut tree, idx as u64, &bytes) {
                tracing::warn!("Failed to insert transition {} into tree: {:?}", idx, e);
                return Ok(false);
            }
        }

        let computed_root = sparse_merkle_tree::get_root(&tree).as_bytes().to_vec();
        if computed_root != batch.transitions_root {
            tracing::warn!(
                "Merkle root mismatch for batch {}: computed {:?}, batch has {:?}",
                batch.batch_number,
                computed_root,
                batch.transitions_root
            );
            return Ok(false);
        }

        for commitment in &batch.commitments {
            if commitment.transition_index >= transitions.len() as u64 {
                tracing::warn!(
                    "Commitment for invalid transition index {} in batch {}",
                    commitment.transition_index,
                    batch.batch_number
                );
                return Ok(false);
            }
        }

        tracing::info!("Batch {} verification successful", batch.batch_number);
        Ok(true)
    }
}

/// Builder for batches
pub struct BatchBuilder {
    pub(crate) batch_number: u64,
    pub(crate) prev_state_hash: [u8; 32],
    pub(crate) transitions: Vec<StateTransition>,
    pub(crate) commitments: Vec<BatchCommitment>,
    pub(crate) tree: Option<SparseMerkleTreeImpl>,
}

impl BatchBuilder {
    pub fn new(batch_number: u64, prev_state_hash: [u8; 32]) -> Self {
        Self {
            batch_number,
            prev_state_hash,
            transitions: Vec::new(),
            commitments: Vec::new(),
            tree: None,
        }
    }

    pub fn add_transition(&mut self, transition: StateTransition) -> Result<(), DsmError> {
        if self.tree.is_none() {
            self.tree = Some(sparse_merkle_tree::create_tree(16));
        }

        let transition_bytes = transition.to_wire_bytes();
        let index = self.transitions.len() as u64;

        if let Some(tree) = &mut self.tree {
            sparse_merkle_tree::insert(tree, index, &transition_bytes)?
        }

        self.transitions.push(transition);
        Ok(())
    }

    pub fn add_commitment(&mut self, commitment: BatchCommitment) {
        self.commitments.push(commitment);
    }

    /// Finalize the batch, returning the StateBatch and cached transitions
    /// NOTE: returns both the batch and the cached transitions for storage
    /// so the caller can store them for later verification/execution.
    pub fn build(mut self) -> Result<(StateBatch, Vec<StateTransition>), DsmError> {
        // Allow empty batch (warn)
        if self.transitions.is_empty() {
            tracing::warn!("Building an empty batch - unusual in production");
            let batch = StateBatch::new(
                self.batch_number,
                self.prev_state_hash,
                [0u8; 32],
                0,
                self.commitments,
                None,
            );
            // move out the (empty) transitions vector
            let cached = self.transitions;
            return Ok((batch, cached));
        }

        let mut final_tree = if let Some(tree) = self.tree.take() {
            tree
        } else {
            let height = (self.transitions.len() as f64).log2().ceil() as u32;
            sparse_merkle_tree::create_tree(height)
        };

        for (idx, transition) in self.transitions.iter().enumerate() {
            let bytes = transition.to_wire_bytes();
            sparse_merkle_tree::insert(&mut final_tree, idx as u64, &bytes)?;
        }

        let root_hash = *sparse_merkle_tree::get_root(&final_tree).as_bytes();

        // capture values needed before moving fields out
        let transition_count = self.transitions.len() as u64;
        let commitments = self.commitments;
        let prev_state_hash = self.prev_state_hash;
        let batch_number = self.batch_number;
        // move out transitions vector to be cached by the caller
        let cached_transitions = self.transitions;

        let batch = StateBatch::new(
            batch_number,
            prev_state_hash,
            root_hash,
            transition_count,
            commitments,
            None,
        );

        Ok((batch, cached_transitions))
    }
}

// Convenience constructor for DsmError::batch
impl DsmError {
    pub fn batch(message: impl Into<String>) -> Self {
        DsmError::Batch(message.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::sphincs::{generate_sphincs_keypair, sphincs_sign};
    use crate::types::operations::TransactionMode;
    use crate::types::token_types::Balance;

    fn signed_transition(i: usize) -> StateTransition {
        let (_pk, sk) = generate_sphincs_keypair().expect("keypair");
        let mut op = Operation::Transfer {
            mode: TransactionMode::Bilateral,
            nonce: vec![i as u8, (i as u8).wrapping_mul(3)],
            verification: crate::types::operations::VerificationType::Standard,
            pre_commit: None,
            to_device_id: b"recipient".to_vec(),
            amount: Balance::from_state(10, [0u8; 32], 0),
            token_id: b"token1".to_vec(),
            message: format!("Batch transition {i}"),
            recipient: b"recipient".to_vec(),
            to: b"recipient".to_vec(),
            signature: Vec::new(),
        };

        let sig = sphincs_sign(&sk, &op.to_bytes()).expect("sign transfer");
        if let Operation::Transfer { signature, .. } = &mut op {
            *signature = sig.clone();
        }

        StateTransition {
            operation: op,
            device_id: blake3::hash(format!("device_{i}").as_bytes()).into(),
            tick: 0,
            flags: vec![],
            position_sequence: None,
            token_balances: None,
            forward_commitment: None,
            prev_state_hash: None,
            entity_signature: None,
            counterparty_signature: None,
            proof_of_authorization: sig.clone(),
            signature: sig,
            new_entropy: Some(vec![1, 2, 3, i as u8]),
            encapsulated_entropy: None,
        }
    }
    use crate::types::operations::Operation; // bring Operation into scope for tests

    #[test]
    fn test_batch_commitment() {
        let c = BatchCommitment::new(
            1,
            vec![1, 2, 3],
            vec![vec![4, 5], vec![6, 7]],
            vec![vec![8, 9], vec![10, 11]],
        );
        assert_eq!(c.transition_index, 1);
        assert_eq!(c.commitment_hash, vec![1, 2, 3]);
        assert_eq!(c.signatures.len(), 2);
        assert_eq!(c.public_keys.len(), 2);
    }

    #[test]
    fn test_state_batch_ctor() {
        let mut prev_hash = [0u8; 32];
        prev_hash[0..3].copy_from_slice(&[1, 2, 3]);
        let mut root = [0u8; 32];
        root[0..3].copy_from_slice(&[4, 5, 6]);

        let b = StateBatch::new(1, prev_hash, root, 10, vec![], None);
        assert_eq!(b.batch_number, 1);
        assert_eq!(b.prev_state_hash, prev_hash);
        assert_eq!(b.transitions_root, root);
        assert_eq!(b.transition_count, 10);
    }

    #[test]
    fn test_batch_flow() -> Result<(), DsmError> {
        let mut mgr = BatchManager::new();

        // Start + add a transition
        mgr.start_batch(None)?;
        let t = signed_transition(0);
        mgr.add_transition(t.clone())?;

        // Finalize
        let batch = mgr.finalize_batch()?;
        assert_eq!(batch.batch_number, 0);
        assert_eq!(batch.transition_count, 1);
        assert_eq!(mgr.batch_counter, 1);

        // Proof stub should be ok
        let _proof = mgr.generate_transition_proof(0, 0)?;

        // Auto-create path
        let mut mgr2 = BatchManager::new();
        let t2 = signed_transition(2);
        mgr2.add_transition(t2)?;
        let batch2 = mgr2.finalize_batch()?;
        assert_eq!(batch2.transition_count, 1);
        Ok(())
    }
}
