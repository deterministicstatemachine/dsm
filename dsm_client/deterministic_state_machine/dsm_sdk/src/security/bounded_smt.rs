// SPDX-License-Identifier: MIT OR Apache-2.0
//! # Bounded Sparse Merkle Tree for Per-Device Relationship Tracking
//!
//! 256-bit sparse Merkle tree with bounded leaf count. Each leaf represents
//! one bilateral relationship's chain tip `h_n^{A↔B}`. Leaves are stored
//! in a HashMap (never evicted for proof correctness); internal nodes are
//! recomputed on demand from leaves + precomputed default hashes.
//!
//! Domain separation matches core (`dsm/src/merkle/sparse_merkle_tree.rs`):
//!   leaf:     `BLAKE3("DSM/smt-leaf\0" || value)`
//!   internal: `BLAKE3("DSM/smt-node\0" || left || right)`
//!   empty:    `BLAKE3("DSM/smt-empty-leaf\0" || "DSM_EMPTY_LEAF_V2")`
//!
//! Bit extraction: MSB-first — `(key[bit_index / 8] >> (7 - bit_index % 8)) & 1`.

use std::collections::{HashMap, VecDeque};

use dsm::crypto::blake3::dsm_domain_hasher;

/// Extract bit `bit_index` from a 256-bit key in MSB-first order.
/// Bit 0 is the MSB of byte 0; bit 255 is the LSB of byte 31.
#[inline]
fn get_bit(key: &[u8; 32], bit_index: usize) -> u8 {
    let byte_index = bit_index / 8;
    let bit_offset = 7 - (bit_index % 8);
    (key[byte_index] >> bit_offset) & 1
}

/// Bounded sparse Merkle tree with 256-bit keys.
pub struct BoundedSmt {
    /// Sparse leaf storage: key → value. Bounded by `max_leaves`.
    leaves: HashMap<[u8; 32], [u8; 32]>,
    /// Precomputed default hash at each tree level (index 0 = root, 256 = leaf).
    /// `defaults[256] = hash_leaf(empty_leaf_value)`
    /// `defaults[i]   = hash_internal(defaults[i+1], defaults[i+1])`
    defaults: Box<[[u8; 32]; 257]>,
    /// Current root hash.
    root: [u8; 32],
    /// Maximum number of stored leaves.
    max_leaves: usize,
    /// Eviction order (front = oldest key).
    eviction_order: VecDeque<[u8; 32]>,
}

impl BoundedSmt {
    /// Create a new bounded SMT with the given maximum leaf count.
    pub fn new(max_leaves: usize) -> Self {
        let mut defaults = Box::new([[0u8; 32]; 257]);

        // Level 256 = leaf level: hash of the empty leaf value
        defaults[256] = Self::hash_leaf(&Self::empty_leaf_value());

        // Build bottom-up: defaults[i] = hash_internal(defaults[i+1], defaults[i+1])
        for i in (0..256).rev() {
            let child = defaults[i + 1];
            defaults[i] = Self::hash_internal(&child, &child);
        }

        let root = defaults[0];

        Self {
            leaves: HashMap::new(),
            defaults,
            root,
            max_leaves,
            eviction_order: VecDeque::new(),
        }
    }

    /// Domain-separated empty leaf value, matching core's `empty_leaf()`.
    fn empty_leaf_value() -> [u8; 32] {
        let mut hasher = dsm_domain_hasher("DSM/smt-empty-leaf");
        hasher.update(b"DSM_EMPTY_LEAF_V2");
        *hasher.finalize().as_bytes()
    }

    /// Hash a leaf node: `BLAKE3("DSM/smt-leaf\0" || value)`.
    fn hash_leaf(value: &[u8; 32]) -> [u8; 32] {
        let mut hasher = dsm_domain_hasher("DSM/smt-leaf");
        hasher.update(value);
        *hasher.finalize().as_bytes()
    }

    /// Hash an internal node: `BLAKE3("DSM/smt-node\0" || left || right)`.
    fn hash_internal(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
        let mut hasher = dsm_domain_hasher("DSM/smt-node");
        hasher.update(left);
        hasher.update(right);
        *hasher.finalize().as_bytes()
    }

    /// Update a leaf value and recompute the root.
    pub fn update_leaf(&mut self, key: &[u8; 32], value: &[u8; 32]) -> Result<(), &'static str> {
        // Remove old position in eviction order if key already exists
        if self.leaves.contains_key(key) {
            self.eviction_order.retain(|k| k != key);
        }

        // Insert / update
        self.leaves.insert(*key, *value);
        self.eviction_order.push_back(*key);

        // Evict oldest if over capacity
        while self.leaves.len() > self.max_leaves {
            if let Some(oldest) = self.eviction_order.pop_front() {
                self.leaves.remove(&oldest);
            } else {
                break;
            }
        }

        // Recompute root from all leaves
        self.root = self.compute_subtree_hash(0);
        Ok(())
    }

    /// Recursively compute the hash of the subtree rooted at `level`.
    /// `level` 0 = root, `level` 256 = leaf level.
    ///
    /// At leaf level (256), returns hash_leaf(value) if a leaf matches the
    /// path prefix, otherwise returns defaults[256].
    ///
    /// At internal levels, splits leaves into left/right groups by the bit
    /// at `level`, recurses, and combines with hash_internal.
    fn compute_subtree_hash(&self, level: usize) -> [u8; 32] {
        if self.leaves.is_empty() {
            return self.defaults[0];
        }
        self.compute_subtree(level, &self.leaves.keys().copied().collect::<Vec<_>>())
    }

    /// Compute subtree hash for a subset of leaf keys at the given level.
    fn compute_subtree(&self, level: usize, keys: &[[u8; 32]]) -> [u8; 32] {
        if keys.is_empty() {
            return self.defaults[level];
        }

        if level == 256 {
            // Leaf level: there should be exactly one key (collision impossible for 256-bit keys)
            debug_assert!(keys.len() == 1, "hash collision at leaf level");
            let value = self.leaves.get(&keys[0]).copied().unwrap_or([0u8; 32]);
            return Self::hash_leaf(&value);
        }

        // Split keys into left (bit=0) and right (bit=1) at this level
        let mut left_keys = Vec::new();
        let mut right_keys = Vec::new();
        for key in keys {
            if get_bit(key, level) == 0 {
                left_keys.push(*key);
            } else {
                right_keys.push(*key);
            }
        }

        let left_hash = if left_keys.is_empty() {
            self.defaults[level + 1]
        } else {
            self.compute_subtree(level + 1, &left_keys)
        };

        let right_hash = if right_keys.is_empty() {
            self.defaults[level + 1]
        } else {
            self.compute_subtree(level + 1, &right_keys)
        };

        Self::hash_internal(&left_hash, &right_hash)
    }

    /// Generate a bounded inclusion proof for the given key.
    ///
    /// Collects 256 sibling hashes from leaf (index 0) to root (index 255).
    /// Sibling at level `i` is the hash of the subtree on the opposite side
    /// of the key's bit at that level.
    pub fn get_inclusion_proof(
        &self,
        key: &[u8; 32],
        max_proof_size: usize,
    ) -> Result<BoundedInclusionProof, &'static str> {
        let value = self.leaves.get(key).copied();
        if value.is_none() {
            return Err("Key not found in SMT");
        }

        let all_keys: Vec<[u8; 32]> = self.leaves.keys().copied().collect();
        let mut siblings = Vec::with_capacity(256);

        // Walk from root (level 0) to leaf (level 255), collecting siblings
        self.collect_siblings(0, &all_keys, key, &mut siblings);

        // Siblings are collected root-to-leaf; reverse to get leaf-to-root order
        // for consistency with verify_proof_against_root
        siblings.reverse();

        if siblings.len() > max_proof_size {
            return Err("Proof size limit exceeded");
        }

        Ok(BoundedInclusionProof {
            key: *key,
            value,
            siblings,
        })
    }

    /// Recursively collect sibling hashes along the path to `target_key`.
    fn collect_siblings(
        &self,
        level: usize,
        keys: &[[u8; 32]],
        target_key: &[u8; 32],
        siblings: &mut Vec<[u8; 32]>,
    ) {
        if level >= 256 {
            return; // Reached leaf level
        }

        // Split keys into left (bit=0) and right (bit=1)
        let mut left_keys = Vec::new();
        let mut right_keys = Vec::new();
        for key in keys {
            if get_bit(key, level) == 0 {
                left_keys.push(*key);
            } else {
                right_keys.push(*key);
            }
        }

        let target_bit = get_bit(target_key, level);

        if target_bit == 0 {
            // Target goes left; sibling is the right subtree hash
            let sibling_hash = if right_keys.is_empty() {
                self.defaults[level + 1]
            } else {
                self.compute_subtree(level + 1, &right_keys)
            };
            siblings.push(sibling_hash);
            // Recurse into the left subtree
            self.collect_siblings(level + 1, &left_keys, target_key, siblings);
        } else {
            // Target goes right; sibling is the left subtree hash
            let sibling_hash = if left_keys.is_empty() {
                self.defaults[level + 1]
            } else {
                self.compute_subtree(level + 1, &left_keys)
            };
            siblings.push(sibling_hash);
            // Recurse into the right subtree
            self.collect_siblings(level + 1, &right_keys, target_key, siblings);
        }
    }

    /// Verify a bounded inclusion proof against this SMT's root.
    pub fn verify_inclusion_proof(&self, proof: &BoundedInclusionProof) -> bool {
        Self::verify_proof_against_root(proof, &self.root)
    }

    /// Verify a proof against an explicit root hash (no BoundedSmt instance needed).
    ///
    /// Used by the receiver in the BLE bilateral 3-step protocol to verify the
    /// sender's SMT inclusion proofs against the sender's claimed `r'_A` root.
    /// Per §18.7 acceptance checklist items 2 + 4.
    pub fn verify_proof_against_root(
        proof: &BoundedInclusionProof,
        expected_root: &[u8; 32],
    ) -> bool {
        let value = match proof.value {
            Some(v) => v,
            None => return false, // Non-inclusion proof
        };

        let mut current_hash = Self::hash_leaf(&value);

        // Siblings are leaf-to-root order: sibling[0] is at the deepest level (255),
        // sibling[last] is at level 0 (root).
        // Bit extraction: sibling[i] corresponds to level (255 - i) in MSB-first.
        for (i, sibling) in proof.siblings.iter().enumerate() {
            // Level counting: sibling[0] = level 255, sibling[1] = level 254, ...
            let level = 255 - i;
            let bit = get_bit(&proof.key, level);

            if bit == 0 {
                current_hash = Self::hash_internal(&current_hash, sibling);
            } else {
                current_hash = Self::hash_internal(sibling, &current_hash);
            }
        }

        current_hash == *expected_root
    }

    /// Get current root.
    pub fn root(&self) -> &[u8; 32] {
        &self.root
    }

    /// Get statistics: (current_leaf_count, max_leaves).
    pub fn cache_stats(&self) -> (usize, usize) {
        (self.leaves.len(), self.max_leaves)
    }

    /// Clear all leaves (for memory pressure recovery).
    pub fn clear_cache(&mut self) {
        self.leaves.clear();
        self.eviction_order.clear();
        self.root = self.defaults[0];
    }
}

/// Bounded inclusion proof with size limits.
#[derive(Debug, Clone)]
pub struct BoundedInclusionProof {
    pub key: [u8; 32],
    pub value: Option<[u8; 32]>,
    /// Sibling hashes ordered leaf-to-root: `siblings[0]` is at level 255,
    /// `siblings[255]` is at level 0 (root's sibling direction).
    pub siblings: Vec<[u8; 32]>,
}

impl BoundedInclusionProof {
    /// Get proof size in bytes.
    pub fn size_bytes(&self) -> usize {
        32 + // key
        1 + // value present flag
        if self.value.is_some() { 32 } else { 0 } + // value
        4 + self.siblings.len() * 32 // siblings
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bounded_smt_update() {
        let mut smt = BoundedSmt::new(256);

        let key = [1u8; 32];
        let value = [42u8; 32];

        smt.update_leaf(&key, &value).unwrap();

        let proof = smt.get_inclusion_proof(&key, 256).unwrap();
        assert!(smt.verify_inclusion_proof(&proof));
        assert_eq!(proof.value, Some(value));
        assert_eq!(proof.siblings.len(), 256);
    }

    #[test]
    fn test_verify_proof_against_root() {
        let mut smt = BoundedSmt::new(256);

        let key = [7u8; 32];
        let value = [99u8; 32];
        smt.update_leaf(&key, &value).unwrap();

        let proof = smt.get_inclusion_proof(&key, 256).unwrap();
        let root = *smt.root();

        // Static verification against the correct root succeeds
        assert!(BoundedSmt::verify_proof_against_root(&proof, &root));

        // Static verification against a wrong root fails
        let bad_root = [0xFFu8; 32];
        assert!(!BoundedSmt::verify_proof_against_root(&proof, &bad_root));

        // Instance method still works
        assert!(smt.verify_inclusion_proof(&proof));
    }

    #[test]
    fn test_multi_leaf_update() {
        let mut smt = BoundedSmt::new(256);

        // Insert 3 leaves with distinct keys
        let keys: [[u8; 32]; 3] = [
            {
                let mut k = [0u8; 32];
                k[0] = 0xAA;
                k
            },
            {
                let mut k = [0u8; 32];
                k[0] = 0x55;
                k
            },
            {
                let mut k = [0u8; 32];
                k[0] = 0xFF;
                k
            },
        ];
        let values: [[u8; 32]; 3] = [[10u8; 32], [20u8; 32], [30u8; 32]];

        for (key, value) in keys.iter().zip(values.iter()) {
            smt.update_leaf(key, value).unwrap();
        }

        // All 3 proofs should verify
        for (key, value) in keys.iter().zip(values.iter()) {
            let proof = smt.get_inclusion_proof(key, 256).unwrap();
            assert_eq!(proof.value, Some(*value));
            assert!(
                smt.verify_inclusion_proof(&proof),
                "Proof failed for key {:?}",
                &key[..4]
            );

            // Also verify via static method
            let root = *smt.root();
            assert!(BoundedSmt::verify_proof_against_root(&proof, &root));
        }
    }

    #[test]
    fn test_leaf_update_changes_root() {
        let mut smt = BoundedSmt::new(256);

        let key = [1u8; 32];
        let value1 = [42u8; 32];
        let value2 = [99u8; 32];

        smt.update_leaf(&key, &value1).unwrap();
        let root1 = *smt.root();

        smt.update_leaf(&key, &value2).unwrap();
        let root2 = *smt.root();

        // Roots should differ after value change
        assert_ne!(root1, root2);

        // Proof for new value should verify
        let proof = smt.get_inclusion_proof(&key, 256).unwrap();
        assert_eq!(proof.value, Some(value2));
        assert!(smt.verify_inclusion_proof(&proof));
    }

    #[test]
    fn test_cache_bounds() {
        let mut smt = BoundedSmt::new(3);

        // Insert 5 leaves — oldest 2 should be evicted
        for i in 0..5u8 {
            let mut key = [0u8; 32];
            key[0] = i;
            let value = [i; 32];
            smt.update_leaf(&key, &value).unwrap();
        }

        // Should have exactly 3 leaves
        let (size, max) = smt.cache_stats();
        assert_eq!(size, 3);
        assert_eq!(max, 3);

        // Newest 3 (keys 2, 3, 4) should have valid proofs
        for i in 2..5u8 {
            let mut key = [0u8; 32];
            key[0] = i;
            let proof = smt.get_inclusion_proof(&key, 256);
            assert!(proof.is_ok(), "Proof should exist for key {}", i);
            assert!(smt.verify_inclusion_proof(&proof.unwrap()));
        }

        // Oldest 2 (keys 0, 1) should be gone
        for i in 0..2u8 {
            let mut key = [0u8; 32];
            key[0] = i;
            let result = smt.get_inclusion_proof(&key, 256);
            assert!(result.is_err(), "Key {} should have been evicted", i);
        }
    }

    #[test]
    fn test_empty_tree_root_is_deterministic() {
        let smt1 = BoundedSmt::new(256);
        let smt2 = BoundedSmt::new(100);

        // Empty trees with different max_leaves should have the same root
        assert_eq!(smt1.root(), smt2.root());
    }

    #[test]
    fn test_proof_size_bounding() {
        let mut smt = BoundedSmt::new(256);

        let key = [1u8; 32];
        let value = [42u8; 32];
        smt.update_leaf(&key, &value).unwrap();

        // Request very small proof — should fail
        let result = smt.get_inclusion_proof(&key, 1);
        assert!(result.is_err());
    }

    #[test]
    fn test_msb_first_bit_extraction() {
        // Validate bit extraction matches core's convention
        let mut key = [0u8; 32];
        key[0] = 0x80; // MSB set → bit 0 = 1

        assert_eq!(get_bit(&key, 0), 1, "Bit 0 (MSB of byte 0) should be 1");
        assert_eq!(get_bit(&key, 1), 0, "Bit 1 should be 0");

        let mut key2 = [0u8; 32];
        key2[31] = 0x01; // LSB set → bit 255 = 1

        assert_eq!(
            get_bit(&key2, 255),
            1,
            "Bit 255 (LSB of byte 31) should be 1"
        );
        assert_eq!(get_bit(&key2, 254), 0, "Bit 254 should be 0");
    }
}
