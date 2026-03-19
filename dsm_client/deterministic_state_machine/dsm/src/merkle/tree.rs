//! Generic Merkle tree utility (untagged, non-domain-separated).
//!
//! **WARNING**: Do NOT use this for Device Tree (`π_dev`). For `π_dev`, use
//! `crate::common::device_tree` which applies domain-separated BLAKE3 hashing
//! and a canonical empty root per spec. This module provides basic Merkle
//! tree construction and proof verification for non-protocol purposes.

#[cfg(test)]
use blake3;
use crate::crypto::blake3::dsm_domain_hasher;

/// Constant-time-ish equality without external deps.
/// No wall clock, no hex/json/base64/serde, just plain bytes.
#[inline]
fn secure_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

/// Merkle tree node
#[derive(Debug, Clone)]
pub struct MerkleNode {
    hash: [u8; 32],
    left: Option<Box<MerkleNode>>,
    right: Option<Box<MerkleNode>>,
}

/// Merkle tree
#[derive(Debug, Clone)]
pub struct MerkleTree {
    root: Option<MerkleNode>,
    leaves: Vec<[u8; 32]>,
}

/// Merkle proof structure
#[derive(Debug, Clone)]
pub struct MerkleProof {
    pub path: Vec<[u8; 32]>,
    pub leaf_index: usize,
}

impl MerkleProof {
    pub fn new(path: Vec<[u8; 32]>, leaf_index: usize) -> Self {
        MerkleProof { path, leaf_index }
    }

    pub fn verify(&self, root_hash: &[u8], leaf_hash: &[u8]) -> bool {
        let mut hash = [0u8; 32];
        if leaf_hash.len() >= 32 {
            hash.copy_from_slice(&leaf_hash[0..32]);
        } else {
            let mut hasher = dsm_domain_hasher("DSM/merkle-leaf");
            hasher.update(leaf_hash);
            let result = hasher.finalize();
            hash.copy_from_slice(result.as_bytes());
        }

        let mut root = [0u8; 32];
        if root_hash.len() >= 32 {
            root.copy_from_slice(&root_hash[0..32]);
        } else {
            let mut hasher = dsm_domain_hasher("DSM/merkle-leaf");
            hasher.update(root_hash);
            let result = hasher.finalize();
            root.copy_from_slice(result.as_bytes());
        }

        MerkleTree::verify_proof(&root, &hash, &self.path, self.leaf_index)
    }
}

impl MerkleNode {
    fn new(hash: [u8; 32]) -> Self {
        MerkleNode {
            hash,
            left: None,
            right: None,
        }
    }

    fn combine_hashes(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
        let mut hasher = dsm_domain_hasher("DSM/merkle-node");
        hasher.update(left);
        hasher.update(right);
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(result.as_bytes());
        hash
    }
}

impl MerkleTree {
    /// Create a new Merkle tree with the given leaves (raw bytes or 32-byte hashes).
    pub fn new(leaves: Vec<Vec<u8>>) -> Self {
        let mut tree = Self {
            root: None,
            leaves: Vec::new(),
        };

        for leaf in leaves {
            let hash = if leaf.len() == 32 {
                let mut h = [0u8; 32];
                h.copy_from_slice(&leaf);
                h
            } else {
                *crate::crypto::blake3::domain_hash("DSM/merkle-leaf", &leaf).as_bytes()
            };
            tree.add_leaf(hash);
        }

        tree
    }

    /// Create a new empty Merkle tree
    #[allow(dead_code)]
    pub fn new_empty() -> Self {
        MerkleTree {
            root: None,
            leaves: Vec::new(),
        }
    }

    /// Add a leaf to the tree and rebuild
    pub fn add_leaf(&mut self, leaf_hash: [u8; 32]) {
        self.leaves.push(leaf_hash);
        self.rebuild();
    }

    /// Rebuild the entire tree from leaves
    fn rebuild(&mut self) {
        if self.leaves.is_empty() {
            self.root = None;
            return;
        }

        // Defensive: ensure all leaves are 32 bytes (already enforced above)
        for &hash in &self.leaves {
            assert_eq!(hash.len(), 32, "Merkle leaf must be 32 bytes (BLAKE3 hash)");
        }

        let mut current_level: Vec<MerkleNode> =
            self.leaves.iter().copied().map(MerkleNode::new).collect();

        if current_level.len() == 1 {
            self.root = Some(current_level[0].clone());
            return;
        }

        while current_level.len() > 1 {
            let mut next_level = Vec::new();

            for i in (0..current_level.len()).step_by(2) {
                if i + 1 < current_level.len() {
                    // Pair
                    let combined = MerkleNode::combine_hashes(
                        &current_level[i].hash,
                        &current_level[i + 1].hash,
                    );
                    let mut parent = MerkleNode::new(combined);
                    parent.left = Some(Box::new(current_level[i].clone()));
                    parent.right = Some(Box::new(current_level[i + 1].clone()));
                    next_level.push(parent);
                } else {
                    // Odd leaf -> duplicate
                    let combined =
                        MerkleNode::combine_hashes(&current_level[i].hash, &current_level[i].hash);
                    let mut parent = MerkleNode::new(combined);
                    parent.left = Some(Box::new(current_level[i].clone()));
                    parent.right = Some(Box::new(current_level[i].clone()));
                    next_level.push(parent);
                }
            }
            current_level = next_level;
        }

        self.root = Some(current_level.remove(0));
    }

    /// Get the Merkle root hash
    pub fn root_hash(&self) -> Option<[u8; 32]> {
        self.root.as_ref().map(|node| node.hash)
    }

    #[allow(dead_code)]
    fn get_tree_height(&self) -> usize {
        if self.leaves.is_empty() {
            return 0;
        }
        let leaf_count = self.leaves.len();
        (leaf_count - 1).next_power_of_two().trailing_zeros() as usize + 1
    }

    /// Generate a proof for a leaf using proper indices
    pub fn generate_proof(&self, leaf_index: usize) -> MerkleProof {
        if leaf_index >= self.leaves.len() {
            return MerkleProof::new(Vec::new(), leaf_index);
        }

        let mut proof = Vec::new();
        let mut current_index = leaf_index;
        let mut level_nodes = self.leaves.clone();

        while level_nodes.len() > 1 {
            // Sibling index
            let sibling_index = if current_index.is_multiple_of(2) {
                current_index + 1
            } else {
                current_index - 1
            };

            // For odd number of nodes, duplicate last node if needed
            if sibling_index >= level_nodes.len() {
                proof.push(level_nodes[level_nodes.len() - 1]);
            } else {
                proof.push(level_nodes[sibling_index]);
            }

            // Build parent level
            let mut next_level = Vec::new();
            for i in (0..level_nodes.len()).step_by(2) {
                let right_index = i + 1;
                let left = level_nodes[i];
                let right = if right_index < level_nodes.len() {
                    level_nodes[right_index]
                } else {
                    // duplicate last
                    level_nodes[i]
                };

                let combined = MerkleNode::combine_hashes(&left, &right);
                next_level.push(combined);
            }

            level_nodes = next_level;
            current_index /= 2;
        }

        MerkleProof::new(proof, leaf_index)
    }

    /// Verify a proof (left/right determined by index parity at each level)
    pub fn verify_proof(
        root_hash: &[u8; 32],
        leaf_hash: &[u8; 32],
        proof: &[[u8; 32]],
        leaf_index: usize,
    ) -> bool {
        let mut current_hash = *leaf_hash;
        let mut current_index = leaf_index;

        for sibling_hash in proof {
            let (left, right) = if current_index.is_multiple_of(2) {
                (current_hash, *sibling_hash)
            } else {
                (*sibling_hash, current_hash)
            };

            current_hash = MerkleNode::combine_hashes(&left, &right);
            current_index /= 2;
        }

        secure_eq(&current_hash, root_hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash_data(data: &[u8]) -> [u8; 32] {
        let h = blake3::hash(data);
        let mut out = [0u8; 32];
        out.copy_from_slice(h.as_bytes());
        out
    }

    #[test]
    fn test_empty_tree() {
        let tree = MerkleTree::new(Vec::new());
        assert!(tree.root.is_none());
        assert!(tree.root_hash().is_none());
        assert_eq!(tree.leaves.len(), 0);
    }

    #[test]
    fn test_single_leaf_tree() {
        let leaf = hash_data(b"test data");
        let mut tree = MerkleTree::new(Vec::new());
        tree.add_leaf(hash_data(b"test data"));

        assert!(tree.root.is_some());
        assert_eq!(tree.root_hash(), Some(leaf));
        assert_eq!(tree.leaves.len(), 1);
    }

    #[test]
    fn test_two_leaf_tree() {
        let leaf1 = hash_data(b"data1");
        let leaf2 = hash_data(b"data2");

        let mut tree = MerkleTree::new(Vec::new());
        tree.add_leaf(hash_data(b"data1"));
        tree.add_leaf(hash_data(b"data2"));

        let expected_root = MerkleNode::combine_hashes(&leaf1, &leaf2);

        assert_eq!(tree.root_hash(), Some(expected_root));
        assert_eq!(tree.leaves.len(), 2);
    }

    #[test]
    fn test_proof_generation_and_verification() {
        let leaf2 = hash_data(b"data2");

        let mut tree = MerkleTree::new(Vec::new());
        tree.add_leaf(hash_data(b"data1"));
        tree.add_leaf(hash_data(b"data2"));
        tree.add_leaf(hash_data(b"data3"));
        tree.add_leaf(hash_data(b"data4"));

        let root_hash = tree.root_hash().expect("Expected root hash");
        println!("Root hash (bytes): {:?}", root_hash);
        println!("Leaf2 hash (bytes): {:?}", leaf2);

        let leaf3 = hash_data(b"data3");

        let proof = tree.generate_proof(1);
        println!("Proof path length: {}", proof.path.len());
        for (i, hash) in proof.path.iter().enumerate() {
            println!("Proof element {} (bytes): {:?}", i, hash);
        }

        assert!(MerkleTree::verify_proof(
            &root_hash,
            &leaf2,
            &proof.path,
            proof.leaf_index
        ));
        assert!(!MerkleTree::verify_proof(
            &root_hash,
            &leaf3,
            &proof.path,
            proof.leaf_index
        ));
    }

    #[test]
    fn test_invalid_proof_index() {
        let tree = MerkleTree::new(Vec::new());
        let proof = tree.generate_proof(1);
        assert_eq!(proof.path.len(), 0);
    }

    #[test]
    fn test_odd_number_of_leaves() {
        let leaf3 = hash_data(b"data3");

        let mut tree = MerkleTree::new(Vec::new());
        tree.add_leaf(hash_data(b"data1"));
        tree.add_leaf(hash_data(b"data2"));
        tree.add_leaf(hash_data(b"data3"));

        assert_eq!(tree.leaves.len(), 3);

        let root_hash = tree.root_hash().expect("Expected root hash");
        println!("Root hash (bytes): {:?}", root_hash);
        println!("Leaf3 hash (bytes): {:?}", leaf3);

        let proof = tree.generate_proof(2);
        println!("Proof path length: {}", proof.path.len());
        for (i, hash) in proof.path.iter().enumerate() {
            println!("Proof element {} (bytes): {:?}", i, hash);
        }

        // With odd-leaf duplication, proof must verify
        let combined_0_1 = MerkleNode::combine_hashes(&tree.leaves[0], &tree.leaves[1]);
        let combined_2_2 = MerkleNode::combine_hashes(&tree.leaves[2], &tree.leaves[2]);
        let expected_root = MerkleNode::combine_hashes(&combined_0_1, &combined_2_2);
        println!("Expected root (bytes): {:?}", expected_root);
        println!("Actual root   (bytes): {:?}", root_hash);

        assert!(MerkleTree::verify_proof(
            &root_hash,
            &leaf3,
            &proof.path,
            proof.leaf_index
        ));
    }
}
