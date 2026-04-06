//! Shard Activation Accumulator / SAA (emissions spec §3.4)
//!
//! Per-shard append-only accumulator whose leaves are activated identities:
//!   `SAA_s: L_s[i] = H("DJTE.ACTIVE" || id_i)`
//!
//! The accumulator provides `acc_root_{e,s}` and inclusion proofs of `(i, L_s[i])`.
//!
//! This is NOT a Sparse Merkle Tree — it's an append-only structure (MMR or
//! append-only Merkle tree). Currently implemented as a simple binary Merkle tree
//! over the leaf vector.
//!
//! # Storage
//!
//! These accumulators live on storage nodes (as part of the Source DLV state),
//! not locally on devices. Devices verify proofs against committed roots.
//!
//! # Domain Separation
//!
//! - Leaf values use `DJTE.ACTIVE` domain (per emissions spec §3.4)
//! - Internal nodes currently use `DSM/djte-shard-merkle` domain
//! - Future: use `DJTE/saa-node` when parameterized domains are implemented

use crate::crypto::blake3::{domain_hash_bytes, dsm_domain_hasher};

/// Shard Activation Accumulator
///
/// Append-only list of activated identities, stored as:
///   leaf = H("DJTE.ACTIVE", id)
#[derive(Clone, Debug)]
pub struct ShardActivationAccumulator {
    pub leaves: Vec<[u8; 32]>,
}

impl ShardActivationAccumulator {
    pub fn new() -> Self {
        Self { leaves: Vec::new() }
    }

    pub fn append(&mut self, id: [u8; 32]) {
        let leaf = domain_hash_bytes("DJTE.ACTIVE", &id);
        self.leaves.push(leaf);
    }

    pub fn root(&self) -> [u8; 32] {
        if self.leaves.is_empty() {
            return [0u8; 32];
        }
        let mut current_level = self.leaves.clone();
        while current_level.len() > 1 {
            let mut next_level = Vec::with_capacity(current_level.len().div_ceil(2));
            for chunk in current_level.chunks(2) {
                let mut hasher = dsm_domain_hasher("DSM/djte-shard-merkle");
                hasher.update(&chunk[0]);
                if chunk.len() == 2 {
                    hasher.update(&chunk[1]);
                } else {
                    hasher.update(&chunk[0]);
                }
                let res = hasher.finalize();
                let mut h = [0u8; 32];
                h.copy_from_slice(res.as_bytes());
                next_level.push(h);
            }
            current_level = next_level;
        }
        current_level[0]
    }

    pub fn get_leaf(&self, index: usize) -> Option<[u8; 32]> {
        self.leaves.get(index).cloned()
    }

    pub fn len(&self) -> usize {
        self.leaves.len()
    }

    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }
}

impl Default for ShardActivationAccumulator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_accumulator_is_empty() {
        let acc = ShardActivationAccumulator::new();
        assert!(acc.is_empty());
        assert_eq!(acc.len(), 0);
        assert_eq!(acc.root(), [0u8; 32]);
    }

    #[test]
    fn default_equals_new() {
        let from_new = ShardActivationAccumulator::new();
        let from_default = ShardActivationAccumulator::default();
        assert_eq!(from_new.leaves, from_default.leaves);
        assert_eq!(from_new.root(), from_default.root());
    }

    #[test]
    fn append_increases_len() {
        let mut acc = ShardActivationAccumulator::new();
        acc.append([0xAA; 32]);
        assert_eq!(acc.len(), 1);
        assert!(!acc.is_empty());

        acc.append([0xBB; 32]);
        assert_eq!(acc.len(), 2);
    }

    #[test]
    fn get_leaf_returns_correct_values() {
        let mut acc = ShardActivationAccumulator::new();
        let id = [0x01; 32];
        acc.append(id);

        let leaf = acc.get_leaf(0);
        assert!(leaf.is_some());
        let expected = domain_hash_bytes("DJTE.ACTIVE", &id);
        assert_eq!(leaf.unwrap(), expected);

        assert!(acc.get_leaf(1).is_none());
        assert!(acc.get_leaf(999).is_none());
    }

    #[test]
    fn root_single_leaf_is_deterministic() {
        let mut acc = ShardActivationAccumulator::new();
        acc.append([0x42; 32]);
        let root1 = acc.root();

        let mut acc2 = ShardActivationAccumulator::new();
        acc2.append([0x42; 32]);
        let root2 = acc2.root();

        assert_eq!(root1, root2);
        assert_ne!(root1, [0u8; 32]);
    }

    #[test]
    fn root_changes_with_different_ids() {
        let mut acc_a = ShardActivationAccumulator::new();
        acc_a.append([0x01; 32]);
        let root_a = acc_a.root();

        let mut acc_b = ShardActivationAccumulator::new();
        acc_b.append([0x02; 32]);
        let root_b = acc_b.root();

        assert_ne!(root_a, root_b);
    }

    #[test]
    fn root_changes_when_leaf_appended() {
        let mut acc = ShardActivationAccumulator::new();
        acc.append([0x01; 32]);
        let root_before = acc.root();

        acc.append([0x02; 32]);
        let root_after = acc.root();

        assert_ne!(root_before, root_after);
    }

    #[test]
    fn root_with_odd_number_of_leaves_duplicates_last() {
        let mut acc = ShardActivationAccumulator::new();
        acc.append([0x01; 32]);
        acc.append([0x02; 32]);
        acc.append([0x03; 32]);
        assert_eq!(acc.len(), 3);
        let root = acc.root();
        assert_ne!(root, [0u8; 32]);
    }

    #[test]
    fn root_with_power_of_two_leaves() {
        let mut acc = ShardActivationAccumulator::new();
        for i in 0..4u8 {
            acc.append([i; 32]);
        }
        assert_eq!(acc.len(), 4);
        let root = acc.root();
        assert_ne!(root, [0u8; 32]);
    }

    #[test]
    fn leaf_is_domain_hashed() {
        let id = [0xFF; 32];
        let mut acc = ShardActivationAccumulator::new();
        acc.append(id);

        let stored = acc.get_leaf(0).unwrap();
        assert_ne!(stored, id, "leaf must be domain-hashed, not raw id");
        assert_eq!(stored, domain_hash_bytes("DJTE.ACTIVE", &id));
    }
}
