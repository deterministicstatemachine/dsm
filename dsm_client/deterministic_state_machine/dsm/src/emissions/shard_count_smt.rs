//! ShardCountSMT: proof-carrying global counts (emissions spec §3.5)
//!
//! A complete binary tree over shard prefixes up to depth `b`.
//! Each node corresponds to a prefix `p` of length `k ≤ b` and stores
//! `count(p) = Σ |L_s|` for all shards `s` extending `p`.
//!
//! Leaves at depth `b` store `count(s) = |L_s|` (per-shard activation count).
//! The root at depth 0 stores the global total `N = count(ε)`.
//!
//! Heap indexing: root = 1, left child = 2*i, right child = 2*i + 1.
//! Shard leaves live at heap indices `2^b .. 2^(b+1) - 1`.
//!
//! # Storage
//!
//! These trees live on storage nodes (as part of the Source DLV state),
//! not locally on devices. Devices verify proofs against committed roots.
//!
//! # Domain Separation
//!
//! Currently uses the generic `DSM/smt-leaf` and `DSM/smt-node` domains.
//! Future: add DJTE-specific domain separation (`DJTE/count-leaf`, `DJTE/count-node`)
//! when parameterized domain support is implemented. This was discussed with Brandon
//! and will be part of the broader domain parameterization effort.

use crate::merkle::sparse_merkle_tree::{hash_smt_leaf, hash_smt_node};
use crate::types::error::DsmError;
use std::collections::HashMap;

/// Shard Count SMT
///
/// Maps prefix (as heap index) to count.
/// Heap index: 1 is root. 2 is left child, 3 is right child, etc.
/// Leaves for shards live at depth `shard_depth`: heap = 2^b + shard_idx.
#[derive(Clone, Debug)]
pub struct ShardCountSmt {
    pub shard_depth: u8,
    pub counts: HashMap<u64, u64>, // heap_index -> count
}

impl ShardCountSmt {
    pub fn new(shard_depth: u8) -> Self {
        Self {
            shard_depth,
            counts: HashMap::new(),
        }
    }

    /// Compute the Merkle root from heap-indexed counts using bottom-up hashing.
    ///
    /// Leaf nodes hash their count value; internal nodes hash their children.
    // Uses generic DSM/smt-leaf and DSM/smt-node pending parameterized domain support
    pub fn root(&self) -> [u8; 32] {
        self.compute_node_hash(1)
    }

    fn compute_node_hash(&self, heap_index: u64) -> [u8; 32] {
        // depth_of_node: root (heap=1) is depth 0, children of root are depth 1, etc.
        let depth_of_node = (64 - heap_index.leading_zeros()) as u8 - 1;

        if depth_of_node >= self.shard_depth {
            // Leaf: hash the count value
            let count = self.get_count(heap_index);
            let mut val = [0u8; 32];
            val[0..8].copy_from_slice(&count.to_le_bytes());
            hash_smt_leaf(&val)
        } else {
            // Internal: hash children
            let left = self.compute_node_hash(heap_index * 2);
            let right = self.compute_node_hash(heap_index * 2 + 1);
            hash_smt_node(&left, &right)
        }
    }

    pub fn get_count(&self, heap_index: u64) -> u64 {
        *self.counts.get(&heap_index).unwrap_or(&0)
    }

    /// Total activated identities (root count = count(ε)).
    pub fn total(&self) -> u64 {
        self.get_count(1)
    }

    /// Increment the count for a shard and all ancestor nodes up to root.
    pub fn increment(&mut self, shard_index: u64) -> Result<(), DsmError> {
        // Walk from the shard leaf up to root, incrementing each node.
        let mut current_prefix = shard_index;
        for depth in (0..=self.shard_depth).rev() {
            let heap_index = (1u64 << depth) + current_prefix;
            let new_count = self.get_count(heap_index).saturating_add(1);
            self.counts.insert(heap_index, new_count);
            current_prefix >>= 1;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_smt_has_zero_total() {
        let smt = ShardCountSmt::new(2);
        assert_eq!(smt.total(), 0);
        assert_eq!(smt.shard_depth, 2);
    }

    #[test]
    fn get_count_returns_zero_for_absent_keys() {
        let smt = ShardCountSmt::new(3);
        assert_eq!(smt.get_count(1), 0);
        assert_eq!(smt.get_count(42), 0);
        assert_eq!(smt.get_count(u64::MAX), 0);
    }

    #[test]
    fn increment_updates_leaf_and_ancestors() {
        let mut smt = ShardCountSmt::new(2);
        // depth=2 → leaves at heap indices 4,5,6,7 (shard_index 0,1,2,3)
        smt.increment(0).unwrap();

        // Leaf at heap_index = 2^2 + 0 = 4
        assert_eq!(smt.get_count(4), 1);
        // Parent at heap_index = 2^1 + 0 = 2
        assert_eq!(smt.get_count(2), 1);
        // Root at heap_index = 2^0 + 0 = 1
        assert_eq!(smt.get_count(1), 1);
        assert_eq!(smt.total(), 1);
    }

    #[test]
    fn increment_multiple_shards_accumulates_correctly() {
        let mut smt = ShardCountSmt::new(2);
        smt.increment(0).unwrap();
        smt.increment(1).unwrap();
        smt.increment(0).unwrap();

        // Shard 0 leaf (heap 4): incremented twice
        assert_eq!(smt.get_count(4), 2);
        // Shard 1 leaf (heap 5): incremented once
        assert_eq!(smt.get_count(5), 1);
        // Left subtree (heap 2): both shard 0 and 1 roll up here
        assert_eq!(smt.get_count(2), 3);
        // Root (heap 1): total
        assert_eq!(smt.total(), 3);
    }

    #[test]
    fn root_is_deterministic() {
        let mut smt1 = ShardCountSmt::new(2);
        smt1.increment(0).unwrap();
        smt1.increment(1).unwrap();

        let mut smt2 = ShardCountSmt::new(2);
        smt2.increment(0).unwrap();
        smt2.increment(1).unwrap();

        assert_eq!(smt1.root(), smt2.root());
    }

    #[test]
    fn root_changes_on_increment() {
        let mut smt = ShardCountSmt::new(2);
        let root_before = smt.root();

        smt.increment(0).unwrap();
        let root_after = smt.root();

        assert_ne!(root_before, root_after);
    }

    #[test]
    fn root_differs_for_different_shards() {
        let mut smt_a = ShardCountSmt::new(2);
        smt_a.increment(0).unwrap();

        let mut smt_b = ShardCountSmt::new(2);
        smt_b.increment(1).unwrap();

        assert_ne!(smt_a.root(), smt_b.root());
    }

    #[test]
    fn depth_one_has_two_shards() {
        let mut smt = ShardCountSmt::new(1);
        // depth=1 → leaves at heap indices 2,3 (shard_index 0,1)
        smt.increment(0).unwrap();
        smt.increment(1).unwrap();

        assert_eq!(smt.get_count(2), 1); // left leaf
        assert_eq!(smt.get_count(3), 1); // right leaf
        assert_eq!(smt.total(), 2);
    }

    #[test]
    fn root_not_all_zeros() {
        let smt = ShardCountSmt::new(2);
        let root = smt.root();
        // Even with zero counts, the Merkle hashing should produce a non-trivial root
        assert_ne!(root, [0u8; 32]);
    }
}
