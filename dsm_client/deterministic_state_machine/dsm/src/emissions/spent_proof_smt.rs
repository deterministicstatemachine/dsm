//! SpentProofSMT: single-use JAP consumption tracking (emissions spec §3.6)
//!
//! An SMT mapping `jap_hash → 1` if consumed, else absent.
//! Root at emission state `e` is `spent_root_e`.
//!
//! Emission transitions carry:
//! - Non-membership proof under `spent_root_e` that `jap_hash` is absent (before)
//! - Membership proof under `spent_root_{e+1}` that `jap_hash → 1` is present (after)
//!
//! # Storage
//!
//! These trees live on storage nodes (as part of the Source DLV state),
//! not locally on devices. Devices verify proofs against committed roots.

use crate::crypto::blake3::domain_hash_bytes;
use crate::merkle::sparse_merkle_tree::{SparseMerkleTree, SmtInclusionProof, ZERO_LEAF};
use crate::types::error::DsmError;
use std::collections::HashMap;

/// Spent Proof SMT
///
/// Maps jap_hash -> a deterministic spent marker in a 256-bit sparse Merkle tree.
#[derive(Clone)]
pub struct SpentProofSmt {
    pub spent: HashMap<[u8; 32], bool>,
    tree: SparseMerkleTree,
}

impl SpentProofSmt {
    pub fn new() -> Self {
        Self {
            spent: HashMap::new(),
            tree: SparseMerkleTree::new(usize::MAX),
        }
    }

    pub fn mark_spent(&mut self, jap_hash: [u8; 32]) {
        if self.spent.contains_key(&jap_hash) {
            return;
        }
        self.spent.insert(jap_hash, true);
        let value = spent_leaf_value(&jap_hash);
        self.tree
            .update_leaf(&jap_hash, &value)
            .expect("spent proof SMT update must not fail");
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

    pub fn root(&self) -> [u8; 32] {
        *self.tree.root()
    }

    pub fn proof(&self, jap_hash: &[u8; 32]) -> Result<SmtInclusionProof, DsmError> {
        self.tree
            .get_inclusion_proof(jap_hash, 256)
            .map_err(|e| DsmError::Verification(format!("SpentProofSMT proof failed: {e}")))
    }

    pub fn verify_absent(proof: &SmtInclusionProof, root: &[u8; 32], jap_hash: &[u8; 32]) -> bool {
        proof.key == *jap_hash
            && proof.value == Some(ZERO_LEAF)
            && SparseMerkleTree::verify_proof_against_root(proof, root)
    }

    pub fn verify_spent(proof: &SmtInclusionProof, root: &[u8; 32], jap_hash: &[u8; 32]) -> bool {
        proof.key == *jap_hash
            && proof.value == Some(spent_leaf_value(jap_hash))
            && SparseMerkleTree::verify_proof_against_root(proof, root)
    }
}

impl Default for SpentProofSmt {
    fn default() -> Self {
        Self::new()
    }
}

fn spent_leaf_value(jap_hash: &[u8; 32]) -> [u8; 32] {
    domain_hash_bytes("DJTE.SPENT", jap_hash)
}

impl std::fmt::Debug for SpentProofSmt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SpentProofSmt")
            .field("spent_len", &self.spent.len())
            .field("root", &self.root())
            .finish()
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
    fn spent_proofs_verify_absent_then_spent() {
        let jap = [0x33; 32];
        let mut smt = SpentProofSmt::new();

        let absent_root = smt.root();
        let absent = smt.proof(&jap).unwrap();
        assert!(SpentProofSmt::verify_absent(&absent, &absent_root, &jap));
        assert!(!SpentProofSmt::verify_spent(&absent, &absent_root, &jap));

        smt.mark_spent(jap);
        let spent_root = smt.root();
        let spent = smt.proof(&jap).unwrap();
        assert!(SpentProofSmt::verify_spent(&spent, &spent_root, &jap));
        assert!(!SpentProofSmt::verify_absent(&spent, &spent_root, &jap));
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
