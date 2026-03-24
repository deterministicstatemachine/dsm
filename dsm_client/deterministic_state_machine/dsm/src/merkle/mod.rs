//! # DSM Merkle Module
//!
//! ## Trees in This Module
//!
//! ### Classic Merkle Tree (device/master/bilateral)
//! - Use `tree::{MerkleTree, MerkleProof}` for per-device, master, and bilateral relationship trees.
//! - API: `MerkleTree::new`, `MerkleTree::add_leaf`, `MerkleTree::root_hash`,
//!   `MerkleTree::generate_proof`, `MerkleTree::verify_proof`.
//!
//! ### Per-Device Sparse Merkle Tree (§2.2)
//! - Use `sparse_merkle_tree::{SparseMerkleTree, SmtInclusionProof}` for 256-bit key SMT.
//! - Each leaf represents one bilateral relationship's chain tip `h_n^{A↔B}`.
//! - Domain separation (normative):
//!   - Leaf: `BLAKE3("DSM/smt-leaf\0" || value)`
//!   - Internal: `BLAKE3("DSM/smt-node\0" || left || right)`
//!   - Zero leaf: `[0u8; 32]` (32 zero bytes)
//! - API: `SparseMerkleTree::new`, `update_leaf`, `get_inclusion_proof`,
//!   `verify_inclusion_proof`, `verify_proof_against_root`.
//!
//! ### Emissions Trees
//! - Emission-specific trees (ShardCountSMT, SpentProofSMT, SAA) live in the
//!   `emissions` module, not here. See `crate::emissions` for details.
//!
//! ## API Separation
//! - Each tree type has its own API. Do not mix classic and sparse tree types.

// --- Classic Merkle Tree API (device/master/bilateral) ---
pub mod tree;
pub use tree::{MerkleTree, MerkleProof};

// --- Per-Device Sparse Merkle Tree (§2.2) ---
pub mod sparse_merkle_tree;

// --- Tests ---
#[cfg(test)]
mod empty_leaf_tests;

// --- Classic Merkle Tree API helpers (optional, for convenience) ---
/// Create a new Merkle tree for a device or relationship.
/// Returns the 32-byte root hash. All leaves must be 32 bytes (BLAKE3 output).
pub fn create_merkle_tree(leaves: &[Vec<u8>]) -> [u8; 32] {
    let tree = MerkleTree::new(leaves.to_vec());
    tree.root_hash().unwrap_or([0u8; 32])
}

/// Generate a Merkle proof for a given leaf index in a device or relationship tree.
pub fn generate_merkle_proof(leaves: &[Vec<u8>], leaf_index: usize) -> Option<MerkleProof> {
    let tree = MerkleTree::new(leaves.to_vec());
    Some(tree.generate_proof(leaf_index))
}

/// Verify a Merkle proof for a leaf and root in a device or relationship tree.
pub fn verify_merkle_proof(root: &[u8; 32], leaf: &[u8; 32], proof: &MerkleProof) -> bool {
    MerkleTree::verify_proof(root, leaf, &proof.path, proof.leaf_index)
}
