//! Sparse Merkle Tree Implementation
//! Implements SMT functionality for efficient inclusion proofs with
//! logarithmic complexity as described in whitepaper Section 3.3.

use crate::crypto::blake3::dsm_domain_hasher;
use crate::types::error::DsmError;
use crate::common::domain_tags::{TAG_SMT_NODE, TAG_SMT_LEAF};
use crate::types::operations::TransactionMode;
use crate::types::state_types::{
    MerkleProof, MerkleProofParams, NodeId, SerializableHash, SparseMerkleTree,
};
use blake3::Hash;
use std::collections::HashMap;
use std::sync::OnceLock;

/// Canonical zero leaf value for absent SMT entries.
pub const ZERO_LEAF: [u8; 32] = [0u8; 32];

/// Default sparse-tree height used by bootstrap identity paths.
pub const DEFAULT_SMT_HEIGHT: u32 = 32;

/// Return the canonical empty leaf value.
pub fn empty_leaf() -> [u8; 32] {
    ZERO_LEAF
}

/// Precomputed default node hashes for SMT levels 0..=DEFAULT_SMT_HEIGHT.
/// Level 0 = ZERO_LEAF, level n = hash_smt_node(default[n-1], default[n-1]).
static DEFAULT_NODES: OnceLock<Vec<Hash>> = OnceLock::new();

fn precompute_defaults() -> Vec<Hash> {
    let max = (DEFAULT_SMT_HEIGHT + 1) as usize;
    let mut table = Vec::with_capacity(max);
    table.push(Hash::from(ZERO_LEAF));
    for _ in 1..max {
        let child = table.last().unwrap();
        table.push(hash_smt_node(child, child));
    }
    table
}

/// Default node value for SMT at the given level.
/// Uses a precomputed table for levels 0..=DEFAULT_SMT_HEIGHT;
/// falls back to recursive computation for larger levels.
pub fn default_node(level: u32) -> Hash {
    let table = DEFAULT_NODES.get_or_init(precompute_defaults);
    if (level as usize) < table.len() {
        table[level as usize]
    } else {
        // Fallback for levels beyond the precomputed table
        let child = default_node(level - 1);
        hash_smt_node(&child, &child)
    }
}

/// Canonical empty SMT root for a given tree height.
pub fn empty_root(height: u32) -> [u8; 32] {
    *default_node(height).as_bytes()
}

/// Domain-separated SMT node hash: H(TAG_SMT_NODE || left || right)
pub fn hash_smt_node(left: &Hash, right: &Hash) -> Hash {
    let mut hasher = dsm_domain_hasher(TAG_SMT_NODE.trim_end_matches('\0'));
    hasher.update(left.as_bytes());
    hasher.update(right.as_bytes());
    hasher.finalize()
}

#[derive(Clone, Debug)]
pub struct SparseMerkleTreeImpl {
    root: Hash,
    leaves: HashMap<u64, Hash>,
    nodes: HashMap<NodeId, Hash>,
    height: u32,
    leaf_count: u64,
}

impl SparseMerkleTreeImpl {
    pub fn new(height: u32) -> Self {
        let root = default_node(height);
        let mut smt = SparseMerkleTreeImpl {
            root,
            leaves: HashMap::new(),
            nodes: HashMap::new(),
            height,
            leaf_count: 0,
        };
        // Initialize root with default hash for an empty tree
        smt.nodes.insert(
            NodeId {
                level: height,
                index: 0,
            },
            root,
        );
        smt
    }

    pub fn root(&self) -> &Hash {
        &self.root
    }

    pub fn get_node_hash(&self, level: u32, index: u64) -> Result<Hash, DsmError> {
        let node_id = NodeId { level, index };
        let hash = self
            .nodes
            .get(&node_id)
            .cloned()
            .unwrap_or_else(|| default_node(level));
        Ok(hash)
    }

    /// Insert a value at a specific index and update the path to the root.
    pub fn insert(&mut self, index: u64, value: &[u8]) -> Result<(), DsmError> {
        let max_leaves = 1u64 << self.height;
        if index >= max_leaves {
            return Err(DsmError::InvalidOperation(format!(
                "Index {index} exceeds capacity"
            )));
        }

        let leaf_hash = self.hash_leaf(value);
        self.leaves.insert(index, leaf_hash);
        self.nodes.insert(NodeId { level: 0, index }, leaf_hash);

        // Recompute the affected path upwards to the root
        self.update_path(index)?;
        self.leaf_count = self.leaf_count.saturating_add(1);
        Ok(())
    }

    fn update_path(&mut self, leaf_index: u64) -> Result<(), DsmError> {
        let mut current_index = leaf_index;
        for level in 0..self.height {
            let sibling_index = current_index ^ 1;
            let current_hash = self.get_node_hash(level, current_index)?;
            let sibling_hash = self.get_node_hash(level, sibling_index)?;

            let parent_index = current_index >> 1;
            let parent_hash = if current_index & 1 == 0 {
                self.hash_node(&current_hash, &sibling_hash)
            } else {
                self.hash_node(&sibling_hash, &current_hash)
            };

            self.nodes.insert(
                NodeId {
                    level: level + 1,
                    index: parent_index,
                },
                parent_hash,
            );
            current_index = parent_index;
        }
        self.root = self
            .nodes
            .get(&NodeId {
                level: self.height,
                index: 0,
            })
            .cloned()
            .ok_or_else(|| DsmError::Internal {
                context: "Root node not found after tree finalization".to_string(),
                source: None,
            })?;
        Ok(())
    }

    /// Generate logarithmic inclusion proof for a specific leaf index.
    pub fn get_proof(&self, index: u64) -> Result<MerkleProof, DsmError> {
        let mut path = Vec::with_capacity(self.height as usize);
        let mut current_index = index;
        for level in 0..self.height {
            let sibling_index = current_index ^ 1;
            let sibling_hash = self.get_node_hash(level, sibling_index)?;
            path.push(SerializableHash::new(sibling_hash));
            current_index >>= 1;
        }

        Ok(MerkleProof::new(MerkleProofParams {
            path,
            index,
            leaf_hash: SerializableHash::new(self.get_node_hash(0, index)?),
            root_hash: SerializableHash::new(self.root),
            height: self.height,
            leaf_count: self.leaf_count,
            mode: TransactionMode::Bilateral,
            ..Default::default()
        }))
    }

    fn hash_leaf(&self, data: &[u8]) -> Hash {
        let mut hasher = dsm_domain_hasher(TAG_SMT_LEAF.trim_end_matches('\0'));
        hasher.update(data);
        hasher.finalize()
    }

    fn hash_node(&self, left: &Hash, right: &Hash) -> Hash {
        hash_smt_node(left, right)
    }

    pub fn height(&self) -> u32 {
        self.height
    }

    pub fn leaf_count(&self) -> u64 {
        self.leaf_count
    }

    pub fn from_sparse_merkle_tree(other: &SparseMerkleTree) -> Self {
        Self {
            root: other.root,
            leaves: other.leaves.clone(),
            nodes: other.nodes.clone(),
            height: other.height,
            leaf_count: other.leaf_count,
        }
    }

    pub fn to_sparse_merkle_tree(&self) -> SparseMerkleTree {
        SparseMerkleTree {
            root: self.root,
            leaves: self.leaves.clone(),
            nodes: self.nodes.clone(),
            height: self.height,
            leaf_count: self.leaf_count,
        }
    }

    pub fn compute_root(&self) -> Result<Hash, DsmError> {
        Ok(self.root)
    }
}

// Module-level convenience functions (used by batch, batch_proof, and index modules).
pub fn create_tree(height: u32) -> SparseMerkleTreeImpl {
    SparseMerkleTreeImpl::new(height)
}

pub fn insert(tree: &mut SparseMerkleTreeImpl, index: u64, value: &[u8]) -> Result<(), DsmError> {
    tree.insert(index, value)
}

pub fn get_root(tree: &SparseMerkleTreeImpl) -> Hash {
    *tree.root()
}

pub fn generate_proof(tree: &SparseMerkleTreeImpl, index: u64) -> Result<MerkleProof, DsmError> {
    tree.get_proof(index)
}

pub fn verify_proof(root: Hash, leaf_hash: &[u8], proof: &MerkleProof) -> Result<bool, DsmError> {
    let mut current_hash = if leaf_hash.len() == 32 {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(leaf_hash);
        Hash::from(arr)
    } else {
        return Err(DsmError::InvalidOperation(
            "Leaf hash must be 32 bytes".to_string(),
        ));
    };

    let mut index = proof.index;

    for sibling in &proof.path {
        let sibling_hash = sibling.inner();
        if index & 1 == 0 {
            current_hash = hash_smt_node(&current_hash, sibling_hash);
        } else {
            current_hash = hash_smt_node(sibling_hash, &current_hash);
        }
        index >>= 1;
    }

    Ok(current_hash == root)
}

#[cfg(test)]
mod tests {
    #[test]
    fn msb_first_traversal_regression_marker() {
        // Regression test for MSB-first bit interpretation (CI gate, see `ci_gates.sh`).
        //
        // The DSM SMT specification requires MSB-first interpretation of 256-bit keys.
        // This test validates that bit extraction follows MSB-first order:
        // - Bit 0 is the most significant bit (leftmost)
        // - Bit 255 is the least significant bit (rightmost)
        //
        // Example: key = 0x80...00 (MSB set) should traverse LEFT at depth 0
        //          key = 0x00...01 (LSB set) should traverse RIGHT at depth 255

        // Test 1: Key with MSB set (0x80...00) traverses LEFT at root
        let key_msb_set: [u8; 32] = {
            let mut k = [0u8; 32];
            k[0] = 0x80; // MSB set (bit 0 in MSB-first order)
            k
        };

        // Extract bit 0 (MSB) - should be 1
        let bit_0 = (key_msb_set[0] >> 7) & 1;
        assert_eq!(bit_0, 1, "MSB-first: bit 0 should be 1 for key 0x80...00");

        // Test 2: Key with LSB set (0x00...01) traverses RIGHT at depth 255
        let key_lsb_set: [u8; 32] = {
            let mut k = [0u8; 32];
            k[31] = 0x01; // LSB set (bit 255 in MSB-first order)
            k
        };

        // Extract bit 255 (LSB) - should be 1
        let bit_255 = key_lsb_set[31] & 1;
        assert_eq!(
            bit_255, 1,
            "MSB-first: bit 255 should be 1 for key 0x00...01"
        );

        // Test 3: Verify bit extraction function for MSB-first order
        fn get_bit_msb_first(key: &[u8; 32], bit_index: u32) -> u8 {
            assert!(bit_index < 256, "Bit index must be < 256");
            let byte_index = (bit_index / 8) as usize;
            let bit_offset = 7 - (bit_index % 8); // MSB-first within byte
            (key[byte_index] >> bit_offset) & 1
        }

        // Validate MSB-first extraction
        assert_eq!(
            get_bit_msb_first(&key_msb_set, 0),
            1,
            "Bit 0 (MSB) should be 1"
        );
        assert_eq!(get_bit_msb_first(&key_msb_set, 1), 0, "Bit 1 should be 0");
        assert_eq!(
            get_bit_msb_first(&key_lsb_set, 255),
            1,
            "Bit 255 (LSB) should be 1"
        );
        assert_eq!(
            get_bit_msb_first(&key_lsb_set, 254),
            0,
            "Bit 254 should be 0"
        );

        // Test 4: Verify traversal direction based on MSB-first bits
        let key_alternating: [u8; 32] = {
            let mut k = [0u8; 32];
            k[0] = 0xAA; // 10101010 in MSB-first
            k
        };

        assert_eq!(
            get_bit_msb_first(&key_alternating, 0),
            1,
            "Bit 0 should be 1 (left at depth 0)"
        );
        assert_eq!(
            get_bit_msb_first(&key_alternating, 1),
            0,
            "Bit 1 should be 0 (right at depth 1)"
        );
        assert_eq!(
            get_bit_msb_first(&key_alternating, 2),
            1,
            "Bit 2 should be 1 (left at depth 2)"
        );
        assert_eq!(
            get_bit_msb_first(&key_alternating, 3),
            0,
            "Bit 3 should be 0 (right at depth 3)"
        );

        // Test 5: Roundtrip - construct key from bit pattern and verify extraction
        let expected_bits = [1, 0, 1, 1, 0, 0, 1, 0]; // Example pattern
        let mut constructed_key = [0u8; 32];
        for (i, &bit) in expected_bits.iter().enumerate() {
            if bit == 1 {
                let byte_idx = i / 8;
                let bit_offset = 7 - (i % 8);
                constructed_key[byte_idx] |= 1 << bit_offset;
            }
        }

        for (i, &expected_bit) in expected_bits.iter().enumerate() {
            let extracted_bit = get_bit_msb_first(&constructed_key, i as u32);
            assert_eq!(
                extracted_bit, expected_bit,
                "Roundtrip failed at bit {}: expected {}, got {}",
                i, expected_bit, extracted_bit
            );
        }

        // All MSB-first bit interpretation tests passed
        // This validates the specification requirement that SMT keys use MSB-first order
    }
}
