//! # DSM Merkle Module: Protocol Math, Security, and Usage
//!
//! ## Protocol Math & Security (DSM v2.1)
//! - **Forward-Only Hash Chain:**
//!   - State evolution: `S_n = H(S_{n-1} || R_n)` (irreversible, quantum-resistant, BLAKE3)
//!   - Bilateral isolation: `S_A' = H(S_A || tx)`, `S_B' = H(S_B || tx)` (lockstep, no global consensus)
//! - **Sparse Merkle Tree (SMT):**
//!   - Efficient, sub-linear inclusion proofs for state/token updates
//!   - Root: `SMT_root = H({ H(S_0), H(S_1), ..., H(S_n) })`
//!   - Proof: `VerifyInclusion(SMT_root, H(S_i), π)`
//! - **Security Guarantees:**
//!   - Tamper-proof, forward-only, no rollbacks/forks
//!   - Double-spend impossible (one valid forward path)
//!   - All validation is local, cryptographic, and post-quantum
//!   - No miners, no gas, no global consensus
//! - **Offline Capability:**
//!   - All state transitions and proofs can be performed offline; sync is optional
//!
//! ## DSM Merkle API Overview
//!
//! ### Classic Merkle Tree (device/master/bilateral)
//! - Use `tree::{MerkleTree, MerkleProof}` for per-device, master, and bilateral relationship trees.
//! - API: `MerkleTree::new`, `MerkleTree::add_leaf`, `MerkleTree::root_hash`, `MerkleTree::generate_proof`, `MerkleTree::verify_proof`.
//! - Use for local state, recovery, and bilateral sync (see DSM protocol).
//!
//! ### Sparse Merkle Tree (SMT)
//! - Use `sparse_merkle_tree::{SparseMerkleTreeImpl, ...}` for efficient state/token proofs.
//! - API: `SparseMerkleTreeImpl::new`, `insert`, `get_proof`, `verify_proof`, `root`.
//! - Use for scalable, sub-linear proofs of state or token balances.
//!
//! ### API Separation
//! - Each tree type has its own API and logic. Do not mix types between classic and sparse trees.
//! - See DSM Protocol Implementation Guide for full details and usage patterns.
//!
//! ## Example: Forward-Only State Transition (Pseudocode)
//! ```text
//! S_{n+1} = H(S_n || tx || randomness)
//! SMT_{root} = updateSMT(SMT_{root}, tx)
//! ```
//!
//! ## Example: Merkle Proof Verification (Pseudocode)
//! ```text
//! is_valid = MerkleTree::verify_proof(root, leaf, proof.path, proof.leaf_index)
//! ```
//!
//! ## See Also
//! - DSM Protocol Implementation Guide (DSM-SHORT-paper-math.txt)
//! - dsm_contacts.rs, dsm_storage.rs for contact and state management flows
//!
//! ---

// --- Classic Merkle Tree API (device/master/bilateral) ---
pub mod tree;
pub use tree::{MerkleTree, MerkleProof};

// --- Sparse Merkle Tree API (state/token proofs) ---
pub mod sparse_merkle_tree;
pub use sparse_merkle_tree::SparseMerkleTreeImpl;

// --- Classic Merkle Tree API helpers (optional, for convenience) ---
/// Initialize Merkle tree subsystem (DSM context).
/// Call once per device or test harness.
pub fn init_merkle_trees() {
    println!("DSM Merkle tree module initialized");
}

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
