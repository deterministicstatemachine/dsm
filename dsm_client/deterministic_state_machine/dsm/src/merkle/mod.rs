// SPDX-License-Identifier: MIT OR Apache-2.0

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
