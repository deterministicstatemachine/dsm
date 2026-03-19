//! Tests for domain-separated empty leaf sentinel
use crate::merkle::sparse_merkle_tree::{empty_leaf, ZERO_LEAF};

#[test]
fn empty_leaf_not_zero_vector() {
    let sentinel = empty_leaf();
    assert_ne!(sentinel, ZERO_LEAF, "empty_leaf should differ from ZERO_LEAF[0..32]");
    // Determinism: multiple calls yield same value
    assert_eq!(sentinel, empty_leaf(), "empty_leaf must be deterministic across invocations");
}

#[test]
fn sparse_tree_root_uses_empty_leaf() {
    let tree = crate::merkle::sparse_merkle_tree::SparseMerkleTreeImpl::new(4);
    assert_eq!(tree.root().as_bytes(), &empty_leaf(), "new SMT root should use empty_leaf sentinel");
}