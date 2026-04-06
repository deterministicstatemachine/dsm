//! SpentProofSMT: single-use JAP consumption tracking (emissions spec §3.6)
//!
//! An SMT mapping `jap_hash → 1` if consumed, else absent.
//! Root at emission state `e` is `spent_root_e`.
//!
//! Emission transitions carry:
//! - Non-membership proof under `spent_root_e` that `jap_hash` is absent (before)
//! - Membership proof under `spent_root_{e+1}` that `jap_hash → 1` is present (after)
//!
//! # Current Implementation
//!
//! Uses a flat `HashMap<[u8; 32], bool>` with sorted-concatenation root.
//! This is a placeholder — it does not produce real SMT inclusion/non-inclusion proofs.
//!
//! # Planned Upgrade
//!
//! Convert to a proper 256-bit SMT using `merkle::sparse_merkle_tree::SparseMerkleTree`
//! with DJTE-specific domain separation (`DJTE/spent-leaf`, `DJTE/spent-node`).
//! The 256-bit key SMT is the correct structure here since `jap_hash` values are
//! 32-byte BLAKE3 digests.
//!
//! # Storage
//!
//! These trees live on storage nodes (as part of the Source DLV state),
//! not locally on devices. Devices verify proofs against committed roots.

use crate::crypto::blake3::dsm_domain_hasher;
use std::collections::HashMap;

/// Spent Proof SMT
///
/// Maps jap_hash -> 1 (represented as a deterministic commitment over sorted keys).
#[derive(Clone, Debug)]
pub struct SpentProofSmt {
    pub spent: HashMap<[u8; 32], bool>,
}

impl SpentProofSmt {
    pub fn new() -> Self {
        Self {
            spent: HashMap::new(),
        }
    }

    pub fn mark_spent(&mut self, jap_hash: [u8; 32]) {
        self.spent.insert(jap_hash, true);
    }

    pub fn is_spent(&self, jap_hash: &[u8; 32]) -> bool {
        self.spent.contains_key(jap_hash)
    }

    pub fn len(&self) -> usize {
        self.spent.len()
    }

    pub fn is_empty(&self) -> bool {
        self.spent.is_empty()
    }

    /// Compute a deterministic root commitment over sorted spent keys.
    ///
    /// NOTE: This is NOT a proper SMT root — it's a sorted-concatenation hash.
    /// See module-level "Planned Upgrade" for the upgrade path.
    pub fn root(&self) -> [u8; 32] {
        let mut keys: Vec<[u8; 32]> = self.spent.keys().cloned().collect();
        keys.sort();

        let mut hasher = dsm_domain_hasher("DSM/djte-spent-proof");
        for k in keys {
            hasher.update(&k);
        }
        let res = hasher.finalize();
        let mut h = [0u8; 32];
        h.copy_from_slice(res.as_bytes());
        h
    }
}

impl Default for SpentProofSmt {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_smt_is_empty() {
        let smt = SpentProofSmt::new();
        assert!(smt.is_empty());
        assert_eq!(smt.len(), 0);
    }

    #[test]
    fn default_equals_new() {
        let from_new = SpentProofSmt::new();
        let from_default = SpentProofSmt::default();
        assert_eq!(from_new.spent.len(), from_default.spent.len());
        assert_eq!(from_new.root(), from_default.root());
    }

    #[test]
    fn mark_spent_tracks_jap_hash() {
        let mut smt = SpentProofSmt::new();
        let jap = [0xAA; 32];

        assert!(!smt.is_spent(&jap));
        smt.mark_spent(jap);
        assert!(smt.is_spent(&jap));
        assert_eq!(smt.len(), 1);
        assert!(!smt.is_empty());
    }

    #[test]
    fn is_spent_returns_false_for_unknown() {
        let smt = SpentProofSmt::new();
        assert!(!smt.is_spent(&[0x01; 32]));
        assert!(!smt.is_spent(&[0x00; 32]));
    }

    #[test]
    fn multiple_marks_are_idempotent_on_len() {
        let mut smt = SpentProofSmt::new();
        let jap = [0x42; 32];
        smt.mark_spent(jap);
        smt.mark_spent(jap);
        assert_eq!(smt.len(), 1);
        assert!(smt.is_spent(&jap));
    }

    #[test]
    fn root_empty_is_deterministic() {
        let smt1 = SpentProofSmt::new();
        let smt2 = SpentProofSmt::new();
        assert_eq!(smt1.root(), smt2.root());
    }

    #[test]
    fn root_changes_when_jap_marked() {
        let mut smt = SpentProofSmt::new();
        let root_empty = smt.root();

        smt.mark_spent([0x01; 32]);
        let root_one = smt.root();
        assert_ne!(root_empty, root_one);

        smt.mark_spent([0x02; 32]);
        let root_two = smt.root();
        assert_ne!(root_one, root_two);
    }

    #[test]
    fn root_is_order_independent() {
        let mut smt_a = SpentProofSmt::new();
        smt_a.mark_spent([0x01; 32]);
        smt_a.mark_spent([0x02; 32]);

        let mut smt_b = SpentProofSmt::new();
        smt_b.mark_spent([0x02; 32]);
        smt_b.mark_spent([0x01; 32]);

        assert_eq!(
            smt_a.root(),
            smt_b.root(),
            "root should be deterministic regardless of insertion order"
        );
    }

    #[test]
    fn root_differs_for_different_keys() {
        let mut smt_a = SpentProofSmt::new();
        smt_a.mark_spent([0xAA; 32]);

        let mut smt_b = SpentProofSmt::new();
        smt_b.mark_spent([0xBB; 32]);

        assert_ne!(smt_a.root(), smt_b.root());
    }

    #[test]
    fn many_entries_tracked_correctly() {
        let mut smt = SpentProofSmt::new();
        for i in 0..100u8 {
            let mut key = [0u8; 32];
            key[0] = i;
            smt.mark_spent(key);
        }
        assert_eq!(smt.len(), 100);

        let mut check_key = [0u8; 32];
        check_key[0] = 50;
        assert!(smt.is_spent(&check_key));

        check_key[0] = 200;
        assert!(!smt.is_spent(&check_key));
    }
}
