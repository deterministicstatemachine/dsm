// SPDX-License-Identifier: Apache-2.0

//! The `R_econ` sparse Merkle tree.
//!
//! ## Why this is not the per-device relationship SMT
//!
//! Two reasons, either of which alone would be sufficient.
//!
//! First, [`crate::merkle::sparse_merkle_tree::SparseMerkleTree`] is a
//! **bounded FIFO cache**: `update_leaf` evicts the oldest key once the leaf
//! count exceeds `max_leaves`, and the tree is sized by `max_relationships`.
//! Silent eviction is tolerable for relationship tips, which can be refetched.
//! It is not tolerable for economic state, where an evicted leaf is a balance
//! that vanished from the root with no record that it ever existed. This tree
//! never evicts.
//!
//! Second, that tree's leaf hash commits the value and **not the key**, so a
//! proof is portable across positions holding the same value. For relationship
//! tips that is nearly harmless. Here two different assets routinely hold the
//! same amount, so a key-blind leaf hash would let a proof for one asset be
//! replayed as a proof for another. [`econ_leaf`] binds the key.
//!
//! ## Absent leaves
//!
//! An absent leaf is the literal all-zero digest, **not** a hash of anything.
//! It has to be key-independent: a 256-deep tree is only computable at all
//! because empty subtrees collapse into a precomputed default chain, and a
//! key-dependent empty leaf has no such chain. Since every present leaf is a
//! BLAKE3 output, all-zero is unreachable as a present value.

use std::collections::HashMap;
use std::sync::OnceLock;

use crate::common::domain_tags::{TAG_DSM_ECONOMIC_SMT_LEAF, TAG_DSM_ECONOMIC_SMT_NODE};
use crate::crypto::blake3::dsm_domain_hasher;
use crate::merkle::sparse_merkle_tree::get_bit;

/// Full 256-bit key space. Fixed, never a parameter: a shorter tree is a
/// different tree, and a proof that verifies against one must not verify
/// against the other.
pub const ECONOMIC_SMT_HEIGHT: usize = 256;

/// The value at a leaf position holding nothing.
pub const ABSENT_LEAF: [u8; 32] = [0u8; 32];

/// `econ_leaf(k, v) = H_dom(DSM/economic-smt-leaf/v1, k ‖ v)`.
pub fn econ_leaf(key: &[u8; 32], value: &[u8; 32]) -> [u8; 32] {
    let mut h = dsm_domain_hasher(TAG_DSM_ECONOMIC_SMT_LEAF);
    h.update(key);
    h.update(value);
    *h.finalize().as_bytes()
}

/// `econ_node(l, r) = H_dom(DSM/economic-smt-node/v1, l ‖ r)`.
pub fn econ_node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = dsm_domain_hasher(TAG_DSM_ECONOMIC_SMT_NODE);
    h.update(left);
    h.update(right);
    *h.finalize().as_bytes()
}

/// The node value at a leaf position: [`ABSENT_LEAF`] when the leaf holds
/// nothing, otherwise the key-bound leaf hash of its `economic_leaf_value`.
pub fn leaf_node(key: &[u8; 32], value: Option<&[u8; 32]>) -> [u8; 32] {
    match value {
        None => ABSENT_LEAF,
        Some(v) => econ_leaf(key, v),
    }
}

static DEFAULTS: OnceLock<Vec<[u8; 32]>> = OnceLock::new();

/// The value of a fully empty subtree of the given height. `default_node(0)`
/// is [`ABSENT_LEAF`]; `default_node(256)` is the empty root.
pub fn default_node(height: usize) -> [u8; 32] {
    let table = DEFAULTS.get_or_init(|| {
        let mut t = Vec::with_capacity(ECONOMIC_SMT_HEIGHT + 1);
        t.push(ABSENT_LEAF);
        for _ in 1..=ECONOMIC_SMT_HEIGHT {
            let child = t[t.len() - 1];
            t.push(econ_node(&child, &child));
        }
        t
    });
    table[height.min(ECONOMIC_SMT_HEIGHT)]
}

/// `ValidatedEconomicRoot(0)` — the canonical empty economic root.
///
/// Verifier-derived, never trader-chosen. This is the base case that makes the
/// validated lineage non-circular for a fresh identity; it is emphatically
/// **not** a bootstrap for a device that already holds value, because calling
/// existing balances "position 0" would re-create self-rooting at the base.
pub fn empty_economic_root() -> [u8; 32] {
    default_node(ECONOMIC_SMT_HEIGHT)
}

/// Fold a leaf node up its authentication path to a root.
///
/// `siblings` is leaf-to-root: `siblings[0]` is the sibling at the deepest
/// level (bit 255), `siblings[255]` the one adjacent to the root. This matches
/// the relationship SMT's proof ordering, so the two are not silently
/// transposable in a reviewer's head.
pub fn root_from_path(
    key: &[u8; 32],
    leaf: &[u8; 32],
    siblings: &[[u8; 32]; ECONOMIC_SMT_HEIGHT],
) -> [u8; 32] {
    let mut current = *leaf;
    for (i, sibling) in siblings.iter().enumerate() {
        let level = ECONOMIC_SMT_HEIGHT - 1 - i;
        current = if get_bit(key, level) == 0 {
            econ_node(&current, sibling)
        } else {
            econ_node(sibling, &current)
        };
    }
    current
}

/// A materialized, **non-evicting** `R_econ`.
///
/// Producer-side only: a verifier never needs one, because it recomputes roots
/// from the mutation paths a witness carries. Keeping the verifier free of the
/// tree is what lets a foreign device validate an economic transition without
/// holding the trader's state.
#[derive(Debug, Clone, Default)]
pub struct EconomicSmt {
    leaves: HashMap<[u8; 32], [u8; 32]>,
}

impl EconomicSmt {
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert or replace a leaf value (an `economic_leaf_value`).
    pub fn insert(&mut self, key: [u8; 32], value: [u8; 32]) {
        self.leaves.insert(key, value);
    }

    /// Remove a leaf. This is how a balance reaches zero: the leaf goes away
    /// rather than holding a zero.
    pub fn remove(&mut self, key: &[u8; 32]) {
        self.leaves.remove(key);
    }

    pub fn get(&self, key: &[u8; 32]) -> Option<&[u8; 32]> {
        self.leaves.get(key)
    }

    pub fn len(&self) -> usize {
        self.leaves.len()
    }

    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    pub fn root(&self) -> [u8; 32] {
        let keys: Vec<[u8; 32]> = self.leaves.keys().copied().collect();
        self.subtree(0, &keys)
    }

    /// The authentication path for `key`, present or absent, in the
    /// leaf-to-root order [`root_from_path`] expects.
    pub fn siblings(&self, key: &[u8; 32]) -> [[u8; 32]; ECONOMIC_SMT_HEIGHT] {
        let all: Vec<[u8; 32]> = self.leaves.keys().copied().collect();
        let mut out = [[0u8; 32]; ECONOMIC_SMT_HEIGHT];
        // Collected root-to-leaf, then written in reverse.
        let mut level_keys = all;
        for level in 0..ECONOMIC_SMT_HEIGHT {
            let (mut left, mut right) = (Vec::new(), Vec::new());
            for k in &level_keys {
                if get_bit(k, level) == 0 {
                    left.push(*k);
                } else {
                    right.push(*k);
                }
            }
            let (mine, theirs) = if get_bit(key, level) == 0 {
                (left, right)
            } else {
                (right, left)
            };
            out[ECONOMIC_SMT_HEIGHT - 1 - level] = self.subtree(level + 1, &theirs);
            level_keys = mine;
        }
        out
    }

    /// Hash of the subtree rooted at `level`, containing exactly `keys`.
    fn subtree(&self, level: usize, keys: &[[u8; 32]]) -> [u8; 32] {
        if keys.is_empty() {
            return default_node(ECONOMIC_SMT_HEIGHT - level);
        }
        if level == ECONOMIC_SMT_HEIGHT {
            // Distinct 256-bit keys cannot share a leaf position.
            let k = keys[0];
            return leaf_node(&k, self.leaves.get(&k));
        }
        let (mut left, mut right) = (Vec::new(), Vec::new());
        for k in keys {
            if get_bit(k, level) == 0 {
                left.push(*k);
            } else {
                right.push(*k);
            }
        }
        econ_node(
            &self.subtree(level + 1, &left),
            &self.subtree(level + 1, &right),
        )
    }
}
