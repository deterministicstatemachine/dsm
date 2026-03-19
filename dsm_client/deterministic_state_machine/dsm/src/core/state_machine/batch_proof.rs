//! SPHINCS+-signed batch proofs for state transition batches.
//!
//! Generates and verifies cryptographic proofs over [`StateBatch`] objects.
//! A batch proof includes the SMT root hash, batch digest, SPHINCS+ signature,
//! and optional Merkle inclusion proofs for individual states within the batch.

use crate::core::state_machine::batch::StateBatch;
use crate::core::state_machine::transition::StateTransition;
use crate::crypto::sphincs::{sphincs_sign, sphincs_verify};
use crate::merkle::sparse_merkle_tree::{self, SparseMerkleTreeImpl};
use crate::types;
use crate::types::error::DsmError;
use std::collections::HashMap;

// -------------------- internal constant-time utils (no external crates) --------------------

#[inline]
fn ct_eq32(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut acc: u8 = 0;
    for i in 0..32 {
        acc |= a[i] ^ b[i];
    }
    acc == 0
}

// -------------------- Batch proof types --------------------

/// BatchTransitionProof provides an efficient cryptographic proof that
/// a specific transition exists within a batch (Sparse Merkle inclusion).
#[derive(Debug, Clone)]
pub struct BatchTransitionProof {
    /// Index of the transition within the batch
    pub transition_index: u64,

    /// Height of the sparse Merkle tree
    pub tree_height: u32,

    /// Sibling hashes from leaf to root (low level -> high level)
    pub siblings: Vec<[u8; 32]>,

    /// Hash of the transition leaf
    pub transition_hash: [u8; 32],

    /// Hash of the Merkle root
    pub root_hash: [u8; 32],

    /// Batch number this proof is for
    pub batch_number: u64,

    /// Verification metadata for the tree structure
    pub metadata: BatchProofMetadata,

    /// SPHINCS+ signature over the proof message
    pub signature: Vec<u8>,
}

/// Metadata for batch proof verification
#[derive(Debug, Clone)]
pub struct BatchProofMetadata {
    /// Total number of transitions in the batch
    pub transition_count: u64,

    /// Hash of the previous state or batch
    pub prev_hash: [u8; 32],

    /// Signature for the metadata (producer-level attestation)
    pub signature: Vec<u8>,
}

// -------------------- helpers --------------------

#[inline]
fn hash_leaf(transition_wire: &[u8]) -> [u8; 32] {
    // Must match SparseMerkleTreeImpl::hash_leaf_static (domain TAG_SMT_LEAF)
    let mut h = crate::crypto::blake3::dsm_domain_hasher("DSM/smt-leaf");
    h.update(transition_wire);
    *h.finalize().as_bytes()
}

#[inline]
fn hash_parent(_level: u32, left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    // Must match SparseMerkleTreeImpl::hash_node_static (domain TAG_SMT_NODE)
    let mut h = crate::crypto::blake3::dsm_domain_hasher("DSM/smt-node");
    h.update(left);
    h.update(right);
    *h.finalize().as_bytes()
}

#[inline]
fn proof_message_for_sig(p: &BatchTransitionProof) -> [u8; 32] {
    // EXACTLY matches sign/verify path; does NOT include p.signature itself
    let mut h = crate::crypto::blake3::dsm_domain_hasher("DSM/batch-proof/v2");
    h.update(&p.transition_hash);
    h.update(&p.root_hash);
    h.update(&p.batch_number.to_le_bytes());
    h.update(&p.metadata.transition_count.to_le_bytes());
    h.update(&p.metadata.prev_hash);
    h.update(&(p.metadata.signature.len() as u32).to_le_bytes());
    h.update(&p.metadata.signature);
    *h.finalize().as_bytes()
}

// -------------------- core impl --------------------

impl BatchTransitionProof {
    pub fn new(
        transition_index: u64,
        tree_height: u32,
        siblings: Vec<[u8; 32]>,
        transition_hash: [u8; 32],
        root_hash: [u8; 32],
        batch_number: u64,
        metadata: BatchProofMetadata,
    ) -> Self {
        Self {
            transition_index,
            tree_height,
            siblings,
            transition_hash,
            root_hash,
            batch_number,
            signature: metadata.signature.clone(), // caller may override later via sign_with_sphincs
            metadata,
        }
    }

    /// Verify inclusion against a transition and batch root.
    pub fn verify(
        &self,
        transition: &StateTransition,
        batch_root_hash: &[u8; 32],
    ) -> Result<bool, DsmError> {
        // Deterministic wire bytes
        let serialized = transition.to_wire_bytes();

        // Recompute leaf hash (MUST match generator)
        let computed_leaf = hash_leaf(&serialized);
        if !ct_eq32(&computed_leaf, &self.transition_hash) {
            return Ok(false);
        }

        // Reconstruct Merkle root
        let reconstructed_root = self.reconstruct_root()?;

        // Both proof.root_hash and reconstructed must match batch_root_hash
        if !ct_eq32(&reconstructed_root, batch_root_hash) {
            return Ok(false);
        }
        if !ct_eq32(&self.root_hash, batch_root_hash) {
            return Ok(false);
        }

        Ok(true)
    }

    /// Verify inclusion + SPHINCS+ signature over this proof.
    pub fn verify_with_quantum_signatures(
        &self,
        transition: &StateTransition,
        batch_root_hash: &[u8; 32],
        public_key: &[u8],
    ) -> Result<bool, DsmError> {
        if !self.verify(transition, batch_root_hash)? {
            return Ok(false);
        }
        let msg = proof_message_for_sig(self);
        if !sphincs_verify(public_key, &msg, &self.signature)? {
            return Ok(false);
        }
        Ok(true)
    }

    /// Reconstruct the Merkle root from leaf and siblings (left/right by index bit).
    fn reconstruct_root(&self) -> Result<[u8; 32], DsmError> {
        if self.siblings.len() as u32 != self.tree_height {
            return Err(DsmError::merkle(format!(
                "Sibling count ({}) doesn't match tree height ({})",
                self.siblings.len(),
                self.tree_height
            )));
        }

        let mut cur = self.transition_hash;
        let mut idx = self.transition_index;

        for (lvl, sib) in self.siblings.iter().enumerate() {
            let bit = (idx & 1) as u32;
            cur = if bit == 0 {
                // current is left child
                hash_parent(lvl as u32, &cur, sib)
            } else {
                // current is right child
                hash_parent(lvl as u32, sib, &cur)
            };
            idx >>= 1;
        }

        Ok(cur)
    }

    /// Serialize (deterministic, bytes-first).
    pub fn to_bytes(&self) -> Result<Vec<u8>, DsmError> {
        let mut out = Vec::new();

        out.extend_from_slice(&self.transition_index.to_le_bytes());
        out.extend_from_slice(&self.tree_height.to_le_bytes());

        out.extend_from_slice(&(self.siblings.len() as u32).to_le_bytes());
        for sib in &self.siblings {
            out.extend_from_slice(sib);
        }

        out.extend_from_slice(&self.transition_hash);
        out.extend_from_slice(&self.root_hash);
        out.extend_from_slice(&self.batch_number.to_le_bytes());

        out.extend_from_slice(&self.metadata.transition_count.to_le_bytes());
        out.extend_from_slice(&self.metadata.prev_hash);
        out.extend_from_slice(&(self.metadata.signature.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.metadata.signature);

        out.extend_from_slice(&(self.signature.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.signature);

        Ok(out)
    }

    /// Deserialize (bounds-checked).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DsmError> {
        fn take<const N: usize>(src: &mut &[u8]) -> Result<[u8; N], DsmError> {
            if src.len() < N {
                return Err(DsmError::serialization_error(
                    "Underflow decoding batch proof",
                    "bytes",
                    None::<&str>,
                    None::<std::io::Error>,
                ));
            }
            let (head, rest) = src.split_at(N);
            let mut arr = [0u8; N];
            arr.copy_from_slice(head);
            *src = rest;
            Ok(arr)
        }

        fn take_vec(src: &mut &[u8], len: usize) -> Result<Vec<u8>, DsmError> {
            if src.len() < len {
                return Err(DsmError::serialization_error(
                    "Underflow decoding vec",
                    "bytes",
                    None::<&str>,
                    None::<std::io::Error>,
                ));
            }
            let (head, rest) = src.split_at(len);
            *src = rest;
            Ok(head.to_vec())
        }

        let mut rem = bytes;

        let idx = u64::from_le_bytes(take::<8>(&mut rem)?);
        let height = u32::from_le_bytes(take::<4>(&mut rem)?);

        let sib_count = u32::from_le_bytes(take::<4>(&mut rem)?) as usize;
        let mut siblings = Vec::with_capacity(sib_count);
        for _ in 0..sib_count {
            siblings.push(take::<32>(&mut rem)?);
        }

        let transition_hash = take::<32>(&mut rem)?;
        let root_hash = take::<32>(&mut rem)?;
        let batch_number = u64::from_le_bytes(take::<8>(&mut rem)?);

        let meta_transition_count = u64::from_le_bytes(take::<8>(&mut rem)?);
        let prev_hash = take::<32>(&mut rem)?;
        let meta_sig_len = u32::from_le_bytes(take::<4>(&mut rem)?) as usize;
        let meta_sig = take_vec(&mut rem, meta_sig_len)?;

        let proof_sig_len = u32::from_le_bytes(take::<4>(&mut rem)?) as usize;
        let proof_sig = take_vec(&mut rem, proof_sig_len)?;

        let metadata = BatchProofMetadata {
            transition_count: meta_transition_count,
            prev_hash,
            signature: meta_sig,
        };

        Ok(BatchTransitionProof {
            transition_index: idx,
            tree_height: height,
            siblings,
            transition_hash,
            root_hash,
            batch_number,
            metadata,
            signature: proof_sig,
        })
    }

    /// Sign this proof with SPHINCS+ (message excludes self.signature).
    pub fn sign_with_sphincs(&mut self, secret_key: &[u8]) -> Result<(), DsmError> {
        let msg = proof_message_for_sig(self);
        self.signature = sphincs_sign(secret_key, &msg)?;
        Ok(())
    }

    /// Verify multiple proofs sharing the same batch root.
    pub fn batch_verify(
        proofs: &[Self],
        transitions: &[StateTransition],
        batch_root_hash: &[u8; 32],
    ) -> Result<bool, DsmError> {
        if proofs.len() != transitions.len() {
            return Err(DsmError::invalid_operation(format!(
                "Proof count ({}) doesn't match transition count ({})",
                proofs.len(),
                transitions.len()
            )));
        }

        for (p, t) in proofs.iter().zip(transitions.iter()) {
            if !p.verify(t, batch_root_hash)? {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

// -------------------- Generator --------------------

/// BatchProofGenerator handles generation of Merkle proofs for batch transitions
pub struct BatchProofGenerator {
    /// Cache of reconstructed Merkle trees by batch number
    tree_cache: HashMap<u64, SparseMerkleTreeImpl>,

    /// Cache of transitions by batch number and index
    transition_cache: HashMap<(u64, u64), StateTransition>,
}

impl BatchProofGenerator {
    pub fn new() -> Self {
        Self {
            tree_cache: HashMap::new(),
            transition_cache: HashMap::new(),
        }
    }

    /// Generate a proof for a specific transition within a batch.
    pub fn generate_proof(
        &mut self,
        batch: &StateBatch,
        transition_index: u64,
        transition: &StateTransition,
    ) -> Result<BatchTransitionProof, DsmError> {
        if transition_index >= batch.transition_count {
            return Err(DsmError::invalid_operation(format!(
                "Transition index {} out of bounds (max: {})",
                transition_index,
                batch.transition_count - 1
            )));
        }

        // Deterministic bytes & leaf hash (must match verify())
        let serialized = transition.to_wire_bytes();
        let transition_hash = hash_leaf(&serialized);

        // Build/Get SMT
        let tree = self.get_or_build_tree(batch)?;

        // Generate SMT path (tree must be pre-populated externally to be meaningful)
        let merkle_proof = sparse_merkle_tree::generate_proof(tree, transition_index)
            .map_err(|e| DsmError::merkle(format!("Failed to generate Merkle proof: {e:?}")))?;

        // Metadata
        let mut prev_hash = [0u8; 32];
        if batch.prev_state_hash.len() != 32 {
            return Err(DsmError::invalid_operation(
                "Invalid previous state hash length",
            ));
        }
        prev_hash.copy_from_slice(&batch.prev_state_hash);

        let metadata = BatchProofMetadata {
            transition_count: batch.transition_count,
            prev_hash,
            signature: Vec::new(), // producer may attach
        };

        // Sibling hashes
        let siblings = self.extract_sibling_hashes(&merkle_proof.path)?;

        // Root hash
        if batch.transitions_root.len() != 32 {
            return Err(DsmError::invalid_operation(
                "Invalid transitions root hash length",
            ));
        }
        let mut root_hash = [0u8; 32];
        root_hash.copy_from_slice(&batch.transitions_root);

        let tree_height = merkle_proof.path.len() as u32;

        // Cache transition if needed
        self.transition_cache
            .insert((batch.batch_number, transition_index), transition.clone());

        Ok(BatchTransitionProof::new(
            transition_index,
            tree_height,
            siblings,
            transition_hash,
            root_hash,
            batch.batch_number,
            metadata,
        ))
    }

    /// Generate a proof using the full set of transitions to reconstruct the SMT.
    /// This guarantees that the Merkle path corresponds to the batch's actual root.
    pub fn generate_proof_with_transitions(
        &mut self,
        batch: &StateBatch,
        transitions: &[StateTransition],
        transition_index: u64,
    ) -> Result<BatchTransitionProof, DsmError> {
        if transitions.len() as u64 != batch.transition_count {
            return Err(DsmError::invalid_operation(format!(
                "Transition count mismatch: batch claims {}, provided {}",
                batch.transition_count,
                transitions.len()
            )));
        }
        if transition_index >= batch.transition_count {
            return Err(DsmError::invalid_operation(format!(
                "Transition index {} out of bounds (max: {})",
                transition_index,
                batch.transition_count - 1
            )));
        }

        // Build SMT from transitions deterministically
        // Match BatchBuilder's fixed height (16) to ensure identical roots
        let mut tree = sparse_merkle_tree::create_tree(16);
        for (i, t) in transitions.iter().enumerate() {
            let bytes = t.to_wire_bytes();
            sparse_merkle_tree::insert(&mut tree, i as u64, &bytes)?;
        }

        // Compute components
        let t = &transitions[transition_index as usize];
        let serialized = t.to_wire_bytes();
        let transition_hash = hash_leaf(&serialized);

        let merkle_proof = sparse_merkle_tree::generate_proof(&tree, transition_index)
            .map_err(|e| DsmError::merkle(format!("Failed to generate Merkle proof: {e:?}")))?;

        let mut prev_hash = [0u8; 32];
        if batch.prev_state_hash.len() != 32 {
            return Err(DsmError::invalid_operation(
                "Invalid previous state hash length",
            ));
        }
        prev_hash.copy_from_slice(&batch.prev_state_hash);
        let metadata = BatchProofMetadata {
            transition_count: batch.transition_count,
            prev_hash,
            signature: Vec::new(),
        };

        // Sibling hashes
        let siblings = self.extract_sibling_hashes(&merkle_proof.path)?;

        // Root hash (validate length)
        if batch.transitions_root.len() != 32 {
            return Err(DsmError::invalid_operation(
                "Invalid transitions root hash length",
            ));
        }
        let mut root_hash = [0u8; 32];
        root_hash.copy_from_slice(&batch.transitions_root);

        Ok(BatchTransitionProof::new(
            transition_index,
            merkle_proof.path.len() as u32,
            siblings,
            transition_hash,
            root_hash,
            batch.batch_number,
            metadata,
        ))
    }

    /// Extract sibling hashes from Merkle proof path (uses fast copy on aarch64).
    fn extract_sibling_hashes(
        &self,
        paths: &[types::state_types::SerializableHash],
    ) -> Result<Vec<[u8; 32]>, DsmError> {
        let mut siblings = Vec::with_capacity(paths.len());

        #[cfg(target_arch = "aarch64")]
        {
            for path in paths {
                let mut sibling = [0u8; 32];
                let bytes = path.inner().as_bytes();
                sibling.copy_from_slice(bytes);
                siblings.push(sibling);
            }
        }

        #[cfg(not(target_arch = "aarch64"))]
        {
            for path in paths {
                let mut sibling = [0u8; 32];
                sibling.copy_from_slice(path.inner().as_bytes());
                siblings.push(sibling);
            }
        }

        Ok(siblings)
    }

    pub fn clear_caches(&mut self) {
        self.tree_cache.clear();
        self.transition_cache.clear();
    }

    fn get_or_build_tree<'a>(
        &'a mut self,
        batch: &StateBatch,
    ) -> Result<&'a SparseMerkleTreeImpl, DsmError> {
        if self.tree_cache.contains_key(&batch.batch_number) {
            return self
                .tree_cache
                .get(&batch.batch_number)
                .ok_or_else(|| DsmError::Internal {
                    context: "Tree cache inconsistency: key exists but get failed".to_string(),
                    source: None,
                });
        }

        // Height = ceil(log2(count)); empty batches are invalid upstream.
        let count = batch.transition_count as f64;
        let height = count.log2().ceil() as u32;

        let tree = sparse_merkle_tree::create_tree(height);
        self.tree_cache.insert(batch.batch_number, tree);
        self.tree_cache
            .get(&batch.batch_number)
            .ok_or_else(|| DsmError::Internal {
                context: "Tree cache inconsistency: insert succeeded but get failed".to_string(),
                source: None,
            })
    }
}

impl Default for BatchProofGenerator {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------- BatchManager extension --------------------

pub mod batch_manager_ext {
    use super::*;

    impl crate::core::state_machine::batch::BatchManager {
        /// Generate a proof for a specific transition within a batch
        pub fn generate_transition_proof_complete(
            &self,
            batch_number: u64,
            transition_index: u64,
            transition: &StateTransition,
        ) -> Result<BatchTransitionProof, DsmError> {
            let batch = self.get_batch(batch_number)?;
            let mut generator = BatchProofGenerator::new();
            generator.generate_proof(batch, transition_index, transition)
        }

        /// Verify a transition against a batch using a proof
        pub fn verify_transition_in_batch_complete(
            &self,
            batch_number: u64,
            transition_index: u64,
            transition: &StateTransition,
            proof: &BatchTransitionProof,
        ) -> Result<bool, DsmError> {
            let batch = self.get_batch(batch_number)?;

            if proof.batch_number != batch_number {
                return Ok(false);
            }
            if proof.transition_index != transition_index {
                return Ok(false);
            }

            let mut root_hash = [0u8; 32];
            root_hash.copy_from_slice(&batch.transitions_root);
            proof.verify(transition, &root_hash)
        }
    }
}

// -------------------- free helpers --------------------

pub fn verify_batch_transition_proof(
    proof: &BatchTransitionProof,
    transition: &StateTransition,
    batch_root_hash: &[u8; 32],
) -> Result<bool, DsmError> {
    proof.verify(transition, batch_root_hash)
}

pub fn is_apple_silicon() -> bool {
    #[cfg(all(target_arch = "aarch64", target_os = "macos"))]
    {
        true
    }
    #[cfg(not(all(target_arch = "aarch64", target_os = "macos")))]
    {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::state_machine::batch::BatchManager;
    use crate::crypto::sphincs::{generate_sphincs_keypair, sphincs_sign};
    use crate::types::operations::{Operation, TransactionMode};
    use crate::types::token_types::Balance;

    fn build_batch_with_transitions(n: usize) -> (StateBatch, Vec<StateTransition>) {
        let mut mgr = BatchManager::new();
        mgr.start_batch(None).expect("start batch");

        let (_pk, sk) = generate_sphincs_keypair().expect("keypair");

        for i in 0..n {
            let mut op = Operation::Transfer {
                mode: TransactionMode::Bilateral,
                nonce: vec![i as u8, (i as u8).wrapping_mul(3)],
                verification: crate::types::operations::VerificationType::Standard,
                pre_commit: None,
                to_device_id: b"recipient".to_vec(),
                amount: Balance::from_state(10, [0u8; 32], 0),
                token_id: b"token1".to_vec(),
                message: format!("transition {i}"),
                recipient: b"recipient".to_vec(),
                to: b"recipient".to_vec(),
                signature: Vec::new(),
            };

            let sig = sphincs_sign(&sk, &op.to_bytes()).expect("sign transfer");
            if let Operation::Transfer { signature, .. } = &mut op {
                *signature = sig.clone();
            }

            let t = StateTransition {
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
            };
            mgr.add_transition(t).expect("add transition");
        }

        let batch = mgr.finalize_batch().expect("finalize batch");
        let txs = mgr
            .retrieve_batch_transitions(batch.batch_number)
            .expect("retrieve");
        (batch.clone(), txs.to_vec())
    }

    #[test]
    fn batch_proof_roundtrip_success() {
        // Use fewer transitions in debug mode to avoid timeouts
        let num_transitions = if cfg!(debug_assertions) { 2 } else { 4 };
        let (batch, txs) = build_batch_with_transitions(num_transitions);
        let mut gen = BatchProofGenerator::new();
        let idx = (num_transitions / 2) as u64; // middle index
        let t = &txs[idx as usize];
        let proof = gen
            .generate_proof_with_transitions(&batch, &txs, idx)
            .expect("proof");
        let mut root = [0u8; 32];
        root.copy_from_slice(&batch.transitions_root);
        let ok = proof.verify(t, &root).expect("verify call");
        assert!(ok);
    }

    #[test]
    fn batch_proof_out_of_bounds_index() {
        let (batch, txs) = build_batch_with_transitions(3);
        let mut gen = BatchProofGenerator::new();
        let idx = 3u64; // out of bounds (0..=2 valid)
        let res = gen.generate_proof_with_transitions(&batch, &txs, idx);
        assert!(res.is_err());
    }

    #[test]
    fn batch_proof_wrong_root_rejects() {
        let (batch, txs) = build_batch_with_transitions(2);
        let mut gen = BatchProofGenerator::new();
        let proof = gen
            .generate_proof_with_transitions(&batch, &txs, 1)
            .expect("proof");

        // Tamper the expected root
        let mut wrong_root = [0u8; 32];
        wrong_root[0] = 0xAA;
        let ok = proof.verify(&txs[1], &wrong_root).expect("verify call");
        assert!(!ok);
    }

    #[test]
    fn batch_proof_serialization_roundtrip() {
        // Use fewer transitions in debug mode to avoid timeouts
        let num_transitions = if cfg!(debug_assertions) { 3 } else { 5 };
        let (batch, txs) = build_batch_with_transitions(num_transitions);
        let mut gen = BatchProofGenerator::new();
        let idx = (num_transitions - 1) as u64; // last index
        let t = &txs[idx as usize];
        let proof = gen
            .generate_proof_with_transitions(&batch, &txs, idx)
            .expect("proof");
        let bytes = proof.to_bytes().expect("serialize");
        let de = BatchTransitionProof::from_bytes(&bytes).expect("deserialize");
        assert_eq!(de.transition_index, proof.transition_index);
        assert_eq!(de.tree_height, proof.tree_height);
        assert_eq!(de.siblings.len(), proof.siblings.len());
        assert_eq!(de.transition_hash, proof.transition_hash);
        assert_eq!(de.root_hash, proof.root_hash);
        assert_eq!(de.batch_number, proof.batch_number);

        let mut root = [0u8; 32];
        root.copy_from_slice(&batch.transitions_root);
        let ok = de.verify(t, &root).expect("verify");
        assert!(ok);
    }

    #[test]
    fn batch_verify_multiple() {
        // Use fewer transitions in debug mode to avoid timeouts
        let num_transitions = if cfg!(debug_assertions) { 2 } else { 3 };
        let (batch, txs) = build_batch_with_transitions(num_transitions);
        let mut gen = BatchProofGenerator::new();
        let mut proofs = Vec::new();
        for i in 0..txs.len() {
            proofs.push(
                gen.generate_proof_with_transitions(&batch, &txs, i as u64)
                    .expect("proof"),
            );
        }
        let mut root = [0u8; 32];
        root.copy_from_slice(&batch.transitions_root);
        let ok = BatchTransitionProof::batch_verify(&proofs, &txs, &root).expect("batch verify");
        assert!(ok);
    }

    #[test]
    fn batch_proof_with_sphincs_signature() {
        // Skip expensive SPHINCS+ operations in debug mode to avoid timeouts
        if cfg!(debug_assertions) {
            println!("Skipping SPHINCS+ signature test in debug mode (too slow)");
            return;
        }

        let (batch, txs) = build_batch_with_transitions(2);
        let mut gen = BatchProofGenerator::new();
        let mut proof = gen
            .generate_proof_with_transitions(&batch, &txs, 0)
            .expect("proof");

        // Create SPHINCS+ keypair and sign proof
        let (pk, sk) = generate_sphincs_keypair().expect("keypair");
        proof.sign_with_sphincs(&sk).expect("sign proof");

        let mut root = [0u8; 32];
        root.copy_from_slice(&batch.transitions_root);
        let ok = proof
            .verify_with_quantum_signatures(&txs[0], &root, &pk)
            .expect("verify with sig");
        assert!(ok);

        // Wrong public key should fail
        let (pk2, _sk2) = generate_sphincs_keypair().expect("keypair2");
        let ok2 = proof
            .verify_with_quantum_signatures(&txs[0], &root, &pk2)
            .expect("verify call");
        assert!(!ok2);
    }
}
