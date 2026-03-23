//! Tests for canonical empty SMT defaults.
use crate::merkle::sparse_merkle_tree::{empty_leaf, empty_root, SparseMerkleTree, ZERO_LEAF};

#[test]
fn empty_leaf_is_zero_leaf() {
    let sentinel = empty_leaf();
    assert_eq!(sentinel, ZERO_LEAF, "empty_leaf must equal ZERO_LEAF");
    assert_eq!(
        sentinel,
        empty_leaf(),
        "empty_leaf must be deterministic across invocations"
    );
}

#[test]
fn sparse_tree_root_uses_canonical_empty_root() {
    // SparseMerkleTree uses 256-bit height by default
    let tree = SparseMerkleTree::new(1024);
    assert_eq!(
        *tree.root(),
        empty_root(256),
        "new SMT root should use the canonical empty-tree root"
    );
}
