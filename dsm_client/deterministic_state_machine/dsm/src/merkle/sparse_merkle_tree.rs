// SPDX-License-Identifier: MIT OR Apache-2.0
//! # Per-Device Sparse Merkle Tree (§2.2)
//!
//! 256-bit sparse Merkle tree for per-device relationship tracking.
//! Each leaf represents one bilateral relationship's chain tip `h_n^{A↔B}`.
//!
//! Leaves are stored in a HashMap keyed by 256-bit relationship identifiers
//! computed as `BLAKE3("DSM/smt-key\0" || min(DevID_A, DevID_B) || max(DevID_A, DevID_B))`.
//! When the leaf count exceeds `max_leaves`, the oldest leaf is evicted (FIFO).
//!
//! Domain separation (normative, §2.2):
//!   leaf:     `BLAKE3("DSM/smt-leaf\0" || value)`
//!   internal: `BLAKE3("DSM/smt-node\0" || left || right)`
//!   zero:     `ZERO_LEAF = [0u8; 32]` (32 zero bytes for absent keys)
//!
//! Bit extraction: MSB-first — `(key[bit_index / 8] >> (7 - bit_index % 8)) & 1`.
//!
//! Default nodes:
//!   `DEFAULT[0] = hash_smt_leaf(ZERO_LEAF)`
//!   `DEFAULT[d+1] = hash_smt_node(DEFAULT[d], DEFAULT[d])  ∀d≥0`

use std::collections::{HashMap, VecDeque};
use std::sync::OnceLock;

use crate::crypto::blake3::dsm_domain_hasher;

// ───────────────────────────────────────────────────────────────────
// Constants and free functions (public API for other modules)
// ───────────────────────────────────────────────────────────────────

/// Canonical zero leaf value for absent SMT entries (§2.2).
/// `ZERO_LEAF := 0x00 repeated 32 times`.
pub const ZERO_LEAF: [u8; 32] = [0u8; 32];

/// Default sparse-tree height: 256 bits for the full key space.
pub const DEFAULT_SMT_HEIGHT: u32 = 256;

/// Return the canonical empty leaf value.
#[inline]
pub fn empty_leaf() -> [u8; 32] {
    ZERO_LEAF
}

/// Domain-separated SMT leaf hash: `BLAKE3("DSM/smt-leaf\0" || value)`.
///
/// Per spec §2.2: `Leaf(X) := BLAKE3-256("DSM/smt-leaf\0" || X)`.
pub fn hash_smt_leaf(value: &[u8; 32]) -> [u8; 32] {
    let mut hasher = dsm_domain_hasher("DSM/smt-leaf");
    hasher.update(value);
    *hasher.finalize().as_bytes()
}

/// Domain-separated SMT internal node hash: `BLAKE3("DSM/smt-node\0" || left || right)`.
///
/// Per spec §2.2: `Node(L, R) := BLAKE3-256("DSM/smt-node\0" || L || R)`.
pub fn hash_smt_node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = dsm_domain_hasher("DSM/smt-node");
    hasher.update(left);
    hasher.update(right);
    *hasher.finalize().as_bytes()
}

/// Precomputed default node hashes for SMT levels 0..=256.
/// Level 0 = hash_smt_leaf(ZERO_LEAF), level n = hash_smt_node(default[n-1], default[n-1]).
static DEFAULT_NODES: OnceLock<Vec<[u8; 32]>> = OnceLock::new();

fn precompute_defaults() -> Vec<[u8; 32]> {
    let max = (DEFAULT_SMT_HEIGHT as usize) + 1;
    let mut table = Vec::with_capacity(max);
    // Level 0 (leaf level): hash of the zero leaf
    table.push(hash_smt_leaf(&ZERO_LEAF));
    for _ in 1..max {
        let child = *table.last().unwrap();
        table.push(hash_smt_node(&child, &child));
    }
    table
}

/// Default node value for SMT at the given level.
/// Level 0 = leaf default, level 256 = root default for an empty tree.
pub fn default_node(level: u32) -> [u8; 32] {
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
    default_node(height)
}

/// Extract bit `bit_index` from a 256-bit key in MSB-first order.
/// Bit 0 is the MSB of byte 0; bit 255 is the LSB of byte 31.
#[inline]
pub fn get_bit(key: &[u8; 32], bit_index: usize) -> u8 {
    let byte_index = bit_index / 8;
    let bit_offset = 7 - (bit_index % 8);
    (key[byte_index] >> bit_offset) & 1
}

// ───────────────────────────────────────────────────────────────────
// SparseMerkleTree — the canonical Per-Device SMT (§2.2)
// ───────────────────────────────────────────────────────────────────

/// Per-Device Sparse Merkle Tree with 256-bit keys and bounded leaf count.
///
/// This is the canonical SMT described in §2.2 of the whitepaper. Each device
/// maintains one of these trees indexing its bilateral relationships. Keys are
/// 256-bit relationship identifiers; values are 32-byte chain tip digests.
pub struct SparseMerkleTree {
    /// Sparse leaf storage: relationship key → chain tip. Bounded by `max_leaves`.
    leaves: HashMap<[u8; 32], [u8; 32]>,
    /// Precomputed default hash at each tree level.
    /// Index 0 = root level default, index 256 = leaf level default.
    /// `defaults[256] = hash_smt_leaf(ZERO_LEAF)`
    /// `defaults[i]   = hash_smt_node(defaults[i+1], defaults[i+1])`
    defaults: Box<[[u8; 32]; 257]>,
    /// Current root hash.
    root: [u8; 32],
    /// Maximum number of stored leaves before FIFO eviction.
    max_leaves: usize,
    /// Eviction order (front = oldest key).
    eviction_order: VecDeque<[u8; 32]>,
}

impl SparseMerkleTree {
    /// Create a new Per-Device SMT with the given maximum leaf count.
    pub fn new(max_leaves: usize) -> Self {
        let mut defaults = Box::new([[0u8; 32]; 257]);

        // Level 256 = leaf level: hash_smt_leaf(ZERO_LEAF)
        defaults[256] = hash_smt_leaf(&ZERO_LEAF);

        // Build bottom-up: defaults[i] = hash_smt_node(defaults[i+1], defaults[i+1])
        for i in (0..256).rev() {
            let child = defaults[i + 1];
            defaults[i] = hash_smt_node(&child, &child);
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

    /// Update a leaf value and recompute the root.
    ///
    /// The key must be a 256-bit relationship identifier computed via
    /// `compute_smt_key(DevID_A, DevID_B)`.
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
            // Leaf level: exactly one key (collision impossible for 256-bit keys)
            debug_assert!(keys.len() == 1, "hash collision at leaf level");
            let value = self.leaves.get(&keys[0]).copied().unwrap_or(ZERO_LEAF);
            return hash_smt_leaf(&value);
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

        hash_smt_node(&left_hash, &right_hash)
    }

    /// Generate an inclusion proof for the given key.
    ///
    /// Collects 256 sibling hashes ordered leaf-to-root.
    /// Sibling at index `i` corresponds to level `(255 - i)` in MSB-first order.
    pub fn get_inclusion_proof(
        &self,
        key: &[u8; 32],
        max_proof_size: usize,
    ) -> Result<SmtInclusionProof, &'static str> {
        let value = self.leaves.get(key).copied();
        if value.is_none() {
            return Err("Key not found in SMT");
        }

        let all_keys: Vec<[u8; 32]> = self.leaves.keys().copied().collect();
        let mut siblings = Vec::with_capacity(256);

        // Walk from root (level 0) to leaf (level 255), collecting siblings
        self.collect_siblings(0, &all_keys, key, &mut siblings);

        // Siblings are collected root-to-leaf; reverse to get leaf-to-root order
        siblings.reverse();

        if siblings.len() > max_proof_size {
            return Err("Proof size limit exceeded");
        }

        Ok(SmtInclusionProof {
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
            self.collect_siblings(level + 1, &left_keys, target_key, siblings);
        } else {
            // Target goes right; sibling is the left subtree hash
            let sibling_hash = if left_keys.is_empty() {
                self.defaults[level + 1]
            } else {
                self.compute_subtree(level + 1, &left_keys)
            };
            siblings.push(sibling_hash);
            self.collect_siblings(level + 1, &right_keys, target_key, siblings);
        }
    }

    /// Verify an inclusion proof against this SMT's root.
    pub fn verify_inclusion_proof(&self, proof: &SmtInclusionProof) -> bool {
        Self::verify_proof_against_root(proof, &self.root)
    }

    /// Verify a proof against an explicit root hash (no tree instance needed).
    ///
    /// Used by the receiver in the BLE bilateral 3-step protocol to verify the
    /// sender's SMT inclusion proofs against the sender's claimed `r'_A` root.
    /// Per §4.3 acceptance checklist items 2 + 4.
    pub fn verify_proof_against_root(proof: &SmtInclusionProof, expected_root: &[u8; 32]) -> bool {
        let value = match proof.value {
            Some(v) => v,
            None => return false,
        };

        let mut current_hash = hash_smt_leaf(&value);

        // Siblings are leaf-to-root order: sibling[0] is at the deepest level (255),
        // sibling[last] is at level 0 (root).
        for (i, sibling) in proof.siblings.iter().enumerate() {
            let level = 255 - i;
            let bit = get_bit(&proof.key, level);

            if bit == 0 {
                current_hash = hash_smt_node(&current_hash, sibling);
            } else {
                current_hash = hash_smt_node(sibling, &current_hash);
            }
        }

        current_hash == *expected_root
    }

    /// Get current root.
    pub fn root(&self) -> &[u8; 32] {
        &self.root
    }

    /// Check whether a key has a non-default leaf in the tree.
    pub fn contains_key(&self, key: &[u8; 32]) -> bool {
        self.leaves.contains_key(key)
    }

    /// Number of non-default leaves currently stored.
    pub fn leaf_count(&self) -> usize {
        self.leaves.len()
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

    /// Atomic SMT-Replace: update leaf from old value to `new_value`,
    /// returning pre/post roots and inclusion proofs for both.
    ///
    /// This is the canonical §4.2 operation. Hard-fails if update_leaf fails
    /// (receipt MUST contain valid r'_A).
    ///
    /// For first-ever transactions where the key has no prior leaf, the parent
    /// proof will have `value: None` (ZERO_LEAF / non-inclusion).
    pub fn smt_replace(
        &mut self,
        key: &[u8; 32],
        new_value: &[u8; 32],
    ) -> Result<SmtReplaceResult, &'static str> {
        let pre_root = self.root;

        // Parent proof: inclusion of h_n (or ZERO_LEAF for first tx).
        // If key doesn't exist yet, construct a default non-inclusion proof.
        let parent_proof = self
            .get_inclusion_proof(key, 256)
            .unwrap_or(SmtInclusionProof {
                key: *key,
                value: None,
                siblings: Vec::new(),
            });

        self.update_leaf(key, new_value)?;

        let post_root = self.root;

        // Child proof: inclusion of h_{n+1} — must succeed since we just inserted.
        let child_proof = self.get_inclusion_proof(key, 256)?;

        Ok(SmtReplaceResult {
            pre_root,
            post_root,
            parent_proof,
            child_proof,
        })
    }
}

// ───────────────────────────────────────────────────────────────────
// SMT-Replace result (§4.2)
// ───────────────────────────────────────────────────────────────────

/// Result of an atomic SMT-Replace operation (§4.2).
///
/// Contains the pre/post roots and inclusion proofs needed to construct
/// a ReceiptCommit with valid `parent_root`, `child_root`, `rel_proof_parent`,
/// and `rel_proof_child` fields.
#[derive(Debug, Clone)]
pub struct SmtReplaceResult {
    /// SMT root before the update (r_A).
    pub pre_root: [u8; 32],
    /// SMT root after the update (r'_A).
    pub post_root: [u8; 32],
    /// Inclusion proof for h_n ∈ r_A (value=None for first-ever tx).
    pub parent_proof: SmtInclusionProof,
    /// Inclusion proof for h_{n+1} ∈ r'_A.
    pub child_proof: SmtInclusionProof,
}

// ───────────────────────────────────────────────────────────────────
// Inclusion proof
// ───────────────────────────────────────────────────────────────────

/// SMT inclusion proof with 256-bit key and leaf-to-root sibling path.
#[derive(Debug, Clone)]
pub struct SmtInclusionProof {
    /// The 256-bit relationship key this proof is for.
    pub key: [u8; 32],
    /// The chain tip value at this key, or `None` for non-inclusion.
    pub value: Option<[u8; 32]>,
    /// Sibling hashes ordered leaf-to-root: `siblings[0]` is at level 255,
    /// `siblings[255]` is at level 0 (root's sibling direction).
    pub siblings: Vec<[u8; 32]>,
}

impl SmtInclusionProof {
    /// Get proof size in bytes.
    pub fn size_bytes(&self) -> usize {
        32 + // key
        1 + // value present flag
        if self.value.is_some() { 32 } else { 0 } + // value
        4 + self.siblings.len() * 32 // siblings
    }

    /// Serialize to bytes: [32-byte key][1-byte has_value][optional 32-byte value][4-byte LE count][32-byte siblings...]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(self.size_bytes());
        buf.extend_from_slice(&self.key);
        buf.push(self.value.is_some() as u8);
        if let Some(v) = &self.value {
            buf.extend_from_slice(v);
        }
        buf.extend_from_slice(&(self.siblings.len() as u32).to_le_bytes());
        for s in &self.siblings {
            buf.extend_from_slice(s);
        }
        buf
    }

    /// Deserialize from bytes. Returns `None` on malformed input.
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 33 {
            return None;
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&data[..32]);
        let has_value = data[32] != 0;
        let mut offset = 33;
        let value = if has_value {
            if data.len() < offset + 32 {
                return None;
            }
            let mut v = [0u8; 32];
            v.copy_from_slice(&data[offset..offset + 32]);
            offset += 32;
            Some(v)
        } else {
            None
        };
        if data.len() < offset + 4 {
            return None;
        }
        let count = u32::from_le_bytes(data[offset..offset + 4].try_into().ok()?) as usize;
        offset += 4;
        if data.len() < offset + count * 32 {
            return None;
        }
        let mut siblings = Vec::with_capacity(count);
        for i in 0..count {
            let mut s = [0u8; 32];
            s.copy_from_slice(&data[offset + i * 32..offset + (i + 1) * 32]);
            siblings.push(s);
        }
        Some(SmtInclusionProof {
            key,
            value,
            siblings,
        })
    }
}

// ───────────────────────────────────────────────────────────────────
// Tests
// ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_leaf_is_32_zero_bytes() {
        assert_eq!(ZERO_LEAF, [0u8; 32]);
        assert_eq!(empty_leaf(), ZERO_LEAF);
    }

    #[test]
    fn empty_tree_root_is_deterministic() {
        let smt1 = SparseMerkleTree::new(256);
        let smt2 = SparseMerkleTree::new(100);
        // Empty trees with different max_leaves have the same root
        assert_eq!(smt1.root(), smt2.root());
    }

    #[test]
    fn empty_tree_root_matches_default_chain() {
        let smt = SparseMerkleTree::new(256);
        assert_eq!(*smt.root(), empty_root(256));
    }

    #[test]
    fn default_node_chain_consistency() {
        // Verify the default chain: default[0] = hash_leaf(ZERO_LEAF),
        // default[n] = hash_node(default[n-1], default[n-1])
        let d0 = default_node(0);
        assert_eq!(d0, hash_smt_leaf(&ZERO_LEAF));

        let d1 = default_node(1);
        assert_eq!(d1, hash_smt_node(&d0, &d0));

        let d2 = default_node(2);
        assert_eq!(d2, hash_smt_node(&d1, &d1));
    }

    #[test]
    fn update_and_prove() {
        let mut smt = SparseMerkleTree::new(256);

        let key = [1u8; 32];
        let value = [42u8; 32];

        smt.update_leaf(&key, &value).unwrap();

        let proof = smt.get_inclusion_proof(&key, 256).unwrap();
        assert!(smt.verify_inclusion_proof(&proof));
        assert_eq!(proof.value, Some(value));
        assert_eq!(proof.siblings.len(), 256);
    }

    #[test]
    fn verify_proof_against_root_static() {
        let mut smt = SparseMerkleTree::new(256);

        let key = [7u8; 32];
        let value = [99u8; 32];
        smt.update_leaf(&key, &value).unwrap();

        let proof = smt.get_inclusion_proof(&key, 256).unwrap();
        let root = *smt.root();

        // Correct root succeeds
        assert!(SparseMerkleTree::verify_proof_against_root(&proof, &root));

        // Wrong root fails
        let bad_root = [0xFFu8; 32];
        assert!(!SparseMerkleTree::verify_proof_against_root(
            &proof, &bad_root
        ));
    }

    #[test]
    fn multi_leaf_proofs() {
        let mut smt = SparseMerkleTree::new(256);

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

        for (key, value) in keys.iter().zip(values.iter()) {
            let proof = smt.get_inclusion_proof(key, 256).unwrap();
            assert_eq!(proof.value, Some(*value));
            assert!(
                smt.verify_inclusion_proof(&proof),
                "Proof failed for key {:?}",
                &key[..4]
            );

            let root = *smt.root();
            assert!(SparseMerkleTree::verify_proof_against_root(&proof, &root));
        }
    }

    #[test]
    fn leaf_update_changes_root() {
        let mut smt = SparseMerkleTree::new(256);

        let key = [1u8; 32];
        let value1 = [42u8; 32];
        let value2 = [99u8; 32];

        smt.update_leaf(&key, &value1).unwrap();
        let root1 = *smt.root();

        smt.update_leaf(&key, &value2).unwrap();
        let root2 = *smt.root();

        assert_ne!(root1, root2);

        let proof = smt.get_inclusion_proof(&key, 256).unwrap();
        assert_eq!(proof.value, Some(value2));
        assert!(smt.verify_inclusion_proof(&proof));
    }

    #[test]
    fn cache_eviction_fifo() {
        let mut smt = SparseMerkleTree::new(3);

        // Insert 5 leaves — oldest 2 should be evicted
        for i in 0..5u8 {
            let mut key = [0u8; 32];
            key[0] = i;
            let value = [i; 32];
            smt.update_leaf(&key, &value).unwrap();
        }

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
    fn proof_size_bounding() {
        let mut smt = SparseMerkleTree::new(256);

        let key = [1u8; 32];
        let value = [42u8; 32];
        smt.update_leaf(&key, &value).unwrap();

        // Request very small proof — should fail
        let result = smt.get_inclusion_proof(&key, 1);
        assert!(result.is_err());
    }

    #[test]
    fn msb_first_bit_extraction() {
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

    #[test]
    fn msb_first_traversal_regression() {
        // Key with MSB set traverses LEFT at root (bit 0 = 1)
        let key_msb: [u8; 32] = {
            let mut k = [0u8; 32];
            k[0] = 0x80;
            k
        };
        assert_eq!(get_bit(&key_msb, 0), 1);

        // Key with LSB set traverses at depth 255 (bit 255 = 1)
        let key_lsb: [u8; 32] = {
            let mut k = [0u8; 32];
            k[31] = 0x01;
            k
        };
        assert_eq!(get_bit(&key_lsb, 255), 1);

        // Alternating pattern 0xAA = 10101010
        let key_alt: [u8; 32] = {
            let mut k = [0u8; 32];
            k[0] = 0xAA;
            k
        };
        assert_eq!(get_bit(&key_alt, 0), 1);
        assert_eq!(get_bit(&key_alt, 1), 0);
        assert_eq!(get_bit(&key_alt, 2), 1);
        assert_eq!(get_bit(&key_alt, 3), 0);

        // Roundtrip: construct key from bit pattern and verify
        let expected_bits = [1, 0, 1, 1, 0, 0, 1, 0];
        let mut constructed_key = [0u8; 32];
        for (i, &bit) in expected_bits.iter().enumerate() {
            if bit == 1 {
                let byte_idx = i / 8;
                let bit_offset = 7 - (i % 8);
                constructed_key[byte_idx] |= 1 << bit_offset;
            }
        }
        for (i, &expected_bit) in expected_bits.iter().enumerate() {
            assert_eq!(
                get_bit(&constructed_key, i),
                expected_bit,
                "Roundtrip failed at bit {}",
                i
            );
        }
    }
}
