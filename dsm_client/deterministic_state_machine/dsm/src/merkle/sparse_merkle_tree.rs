// SPDX-License-Identifier: MIT OR Apache-2.0
//! # Per-Device Sparse Merkle Tree (§2.2)
//!
//! 256-bit sparse Merkle tree for per-device relationship tracking.
//! Each leaf represents one bilateral relationship's chain tip `h_n^{A↔B}`.
//!
//! Leaves are stored in a HashMap keyed by 256-bit relationship identifiers
//! computed as `BLAKE3("DSM/smt-key\0" || min(DevID_A, DevID_B) || max(DevID_A, DevID_B))`.
//! A commitment tree never drops a leaf: every relationship head the device
//! holds stays in the root it commits (MR-DSM-0116, MR-DSM-0121).
//!
//! The root is a pure function of the leaves. The tree keeps the hashes of its
//! non-empty nodes, path-compressed, so a write rehashes one leaf-to-root path
//! and a device's cost per step does not grow with its leaf count.
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

use std::collections::HashMap;
use std::sync::OnceLock;

use crate::common::domain_tags::{TAG_SMT_LEAF, TAG_SMT_NODE};
use crate::crypto::blake3::dsm_domain_hasher;
use crate::types::error::DsmError;

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
    let mut hasher = dsm_domain_hasher(TAG_SMT_LEAF);
    hasher.update(value);
    *hasher.finalize().as_bytes()
}

/// Domain-separated SMT internal node hash: `BLAKE3("DSM/smt-node\0" || left || right)`.
///
/// Per spec §2.2: `Node(L, R) := BLAKE3-256("DSM/smt-node\0" || L || R)`.
pub fn hash_smt_node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = dsm_domain_hasher(TAG_SMT_NODE);
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
        let child = table[table.len() - 1];
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

/// How the device tree hashes, for the one batch fold and the one path
/// encoding ([`crate::merkle::batch_fold`], [`crate::merkle::smt_path`]): a
/// leaf commits its value only (the key is its position), and a leaf holding
/// nothing is the tree's empty leaf, `default_node(0)`.
pub struct DeviceSmtHashes;

impl crate::merkle::batch_fold::SmtHashes for DeviceSmtHashes {
    fn leaf(_key: &[u8; 32], value: Option<&[u8; 32]>) -> [u8; 32] {
        match value {
            Some(v) => hash_smt_leaf(v),
            None => default_node(0),
        }
    }
    fn node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
        hash_smt_node(left, right)
    }
    fn default_node(height: usize) -> [u8; 32] {
        default_node(height as u32)
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

/// Fold a leaf hash up a leaf-to-root sibling path at `key`: the root that
/// path commits the leaf under. Directions come from the key (MSB-first,
/// deepest level first), never from the path.
fn fold_path(key: &[u8; 32], leaf_hash: [u8; 32], siblings: &[[u8; 32]]) -> [u8; 32] {
    let mut acc = leaf_hash;
    for (i, sibling) in siblings.iter().enumerate() {
        acc = if get_bit(key, 255 - i) == 0 {
            hash_smt_node(&acc, sibling)
        } else {
            hash_smt_node(sibling, &acc)
        };
    }
    acc
}

// ───────────────────────────────────────────────────────────────────
// SparseMerkleTree — the canonical Per-Device SMT (§2.2)
// ───────────────────────────────────────────────────────────────────

/// The level of the leaves; level 0 is the root.
const LEAF_LEVEL: usize = DEFAULT_SMT_HEIGHT as usize;

/// The first bit, MSB-first, where `a` and `b` differ; `None` when they are
/// the same key.
fn first_difference(a: &[u8; 32], b: &[u8; 32]) -> Option<usize> {
    a.iter()
        .zip(b.iter())
        .enumerate()
        .find_map(|(byte, (x, y))| {
            let diff = x ^ y;
            (diff != 0).then(|| byte * 8 + diff.leading_zeros() as usize)
        })
}

/// A non-empty subtree in the tree's node set. The set is path-compressed: a
/// run of levels where every key below goes the same way is one edge, and
/// every level of it has the empty subtree for its other child. So the set
/// holds one leaf per key and one branch per level where the keys separate,
/// `2n - 1` nodes for `n` leaves at any depth.
#[derive(Clone, Copy)]
enum Node {
    /// Index into [`SparseMerkleTree::leaf_nodes`].
    Leaf(usize),
    /// Index into [`SparseMerkleTree::branches`].
    Branch(usize),
}

/// A level where the keys below separate: every key under the branch shares
/// the bits before `level`, and both values of bit `level` occur.
#[derive(Clone, Copy)]
struct Branch {
    /// The node's level (0 = root). Its children are at `level + 1`.
    level: usize,
    /// A key under the branch, for the bits every key under it shares.
    key: [u8; 32],
    /// The subtrees whose keys have bit `level` 0 and 1.
    children: [Node; 2],
    /// Each child's hash at `level + 1`: the node's two inputs.
    child_hashes: [[u8; 32]; 2],
}

/// Per-Device Sparse Merkle Tree with 256-bit keys.
///
/// This is the canonical SMT described in §2.2 of the whitepaper. Each device
/// maintains one of these trees indexing its bilateral relationships. Keys are
/// 256-bit relationship identifiers; values are 32-byte chain tip digests.
///
/// The root is a pure function of the leaves. The tree keeps the hashes of
/// its non-empty nodes, path-compressed, so that a write rehashes at most two
/// leaf-to-root paths (its own, and on a new key the edge it splits) whatever
/// the number of leaves, and a proof reads its siblings from the kept hashes.
#[derive(Clone)]
pub struct SparseMerkleTree {
    /// Sparse leaf storage: relationship key → chain tip. Unbounded: the root
    /// commits every leaf the tree holds.
    leaves: HashMap<[u8; 32], [u8; 32]>,
    /// Each held key with its leaf hash `hash_smt_leaf(value)`.
    leaf_nodes: Vec<([u8; 32], [u8; 32])>,
    /// Every level where the held keys separate.
    branches: Vec<Branch>,
    /// The subtree at the root; `None` while the tree holds no leaf.
    top: Option<Node>,
    /// Precomputed default hash at each tree level.
    /// Index 0 = root level default, index 256 = leaf level default.
    /// `defaults[256] = hash_smt_leaf(ZERO_LEAF)`
    /// `defaults[i]   = hash_smt_node(defaults[i+1], defaults[i+1])`
    defaults: Box<[[u8; 32]; 257]>,
    /// Current root hash.
    root: [u8; 32],
}

impl Default for SparseMerkleTree {
    fn default() -> Self {
        Self::new()
    }
}

impl SparseMerkleTree {
    /// Create an empty Per-Device SMT.
    pub fn new() -> Self {
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
            leaf_nodes: Vec::new(),
            branches: Vec::new(),
            top: None,
            defaults,
            root,
        }
    }

    /// Build a tree holding exactly `leaves`, hashing each node once. A
    /// later duplicate key replaces an earlier one.
    pub fn from_leaves(leaves: impl IntoIterator<Item = ([u8; 32], [u8; 32])>) -> Self {
        let mut tree = Self::new();
        for (key, value) in leaves {
            tree.leaves.insert(key, value);
        }
        let mut sorted: Vec<([u8; 32], [u8; 32])> = tree
            .leaves
            .iter()
            .map(|(key, value)| (*key, *value))
            .collect();
        sorted.sort_unstable_by_key(|(key, _)| *key);
        if !sorted.is_empty() {
            let (top, root) = tree.build(&sorted, 0);
            tree.top = Some(top);
            tree.root = root;
        }
        tree
    }

    /// Update a leaf value and recompute the root over the leaf's path.
    ///
    /// The key must be a 256-bit relationship identifier computed via
    /// `compute_smt_key(DevID_A, DevID_B)`.
    pub fn update_leaf(&mut self, key: &[u8; 32], value: &[u8; 32]) {
        self.leaves.insert(*key, *value);
        let leaf_hash = hash_smt_leaf(value);
        let (top, root) = match self.top {
            Some(top) => self.write(top, 0, key, leaf_hash),
            None => (
                self.push_leaf(key, leaf_hash),
                self.lift(key, leaf_hash, LEAF_LEVEL, 0),
            ),
        };
        self.top = Some(top);
        self.root = root;
    }

    /// The subtree over `leaves` (sorted by key, distinct, sharing every bit
    /// before `at`), and its hash at level `at`.
    fn build(&mut self, leaves: &[([u8; 32], [u8; 32])], at: usize) -> (Node, [u8; 32]) {
        let (first, value) = leaves[0];
        // Sorted keys all share the bits the first and last share, and split
        // at the first bit those two do not.
        match first_difference(&first, &leaves[leaves.len() - 1].0) {
            None => {
                let leaf_hash = hash_smt_leaf(&value);
                (
                    self.push_leaf(&first, leaf_hash),
                    self.lift(&first, leaf_hash, LEAF_LEVEL, at),
                )
            }
            Some(split) => {
                let mid = leaves.partition_point(|(key, _)| get_bit(key, split) == 0);
                let (left, left_hash) = self.build(&leaves[..mid], split + 1);
                let (right, right_hash) = self.build(&leaves[mid..], split + 1);
                let branch = self.push_branch(Branch {
                    level: split,
                    key: first,
                    children: [left, right],
                    child_hashes: [left_hash, right_hash],
                });
                let hash = self.lift(&first, hash_smt_node(&left_hash, &right_hash), split, at);
                (branch, hash)
            }
        }
    }

    /// Write `key`'s leaf hash into the subtree `node`, whose keys share
    /// every bit of `key` before `at`. Returns the subtree now in its place
    /// and that subtree's hash at level `at`.
    fn write(
        &mut self,
        node: Node,
        at: usize,
        key: &[u8; 32],
        leaf_hash: [u8; 32],
    ) -> (Node, [u8; 32]) {
        let node_key = *self.node_key(node);
        let node_level = self.node_level(node);
        match first_difference(key, &node_key).filter(|bit| *bit < node_level) {
            // The key leaves the subtree's edge at `split`: a new branch there
            // holds the subtree on one side and the new leaf on the other.
            Some(split) => {
                let old_side = self.lift(&node_key, self.node_hash(node), node_level, split + 1);
                let new_side = self.lift(key, leaf_hash, LEAF_LEVEL, split + 1);
                let leaf = self.push_leaf(key, leaf_hash);
                let (children, child_hashes) = if get_bit(key, split) == 0 {
                    ([leaf, node], [new_side, old_side])
                } else {
                    ([node, leaf], [old_side, new_side])
                };
                let branch = self.push_branch(Branch {
                    level: split,
                    key: node_key,
                    children,
                    child_hashes,
                });
                let hash = self.lift(
                    &node_key,
                    hash_smt_node(&child_hashes[0], &child_hashes[1]),
                    split,
                    at,
                );
                (branch, hash)
            }
            // The key is in the subtree: the leaf itself, or below a branch.
            None => {
                match node {
                    Node::Leaf(index) => self.leaf_nodes[index].1 = leaf_hash,
                    Node::Branch(index) => {
                        let Branch {
                            level, children, ..
                        } = self.branches[index];
                        let side = usize::from(get_bit(key, level));
                        let (child, child_hash) =
                            self.write(children[side], level + 1, key, leaf_hash);
                        self.branches[index].children[side] = child;
                        self.branches[index].child_hashes[side] = child_hash;
                    }
                }
                let hash = self.lift(&node_key, self.node_hash(node), node_level, at);
                (node, hash)
            }
        }
    }

    fn push_leaf(&mut self, key: &[u8; 32], leaf_hash: [u8; 32]) -> Node {
        self.leaf_nodes.push((*key, leaf_hash));
        Node::Leaf(self.leaf_nodes.len() - 1)
    }

    fn push_branch(&mut self, branch: Branch) -> Node {
        self.branches.push(branch);
        Node::Branch(self.branches.len() - 1)
    }

    /// A key under `node`: the bits every key under it shares.
    fn node_key(&self, node: Node) -> &[u8; 32] {
        match node {
            Node::Leaf(index) => &self.leaf_nodes[index].0,
            Node::Branch(index) => &self.branches[index].key,
        }
    }

    /// The level of `node` itself, below its edge.
    fn node_level(&self, node: Node) -> usize {
        match node {
            Node::Leaf(_) => LEAF_LEVEL,
            Node::Branch(index) => self.branches[index].level,
        }
    }

    /// The hash of `node` at its own level.
    fn node_hash(&self, node: Node) -> [u8; 32] {
        match node {
            Node::Leaf(index) => self.leaf_nodes[index].1,
            Node::Branch(index) => {
                let [left, right] = &self.branches[index].child_hashes;
                hash_smt_node(left, right)
            }
        }
    }

    /// Carry `hash`, the subtree at level `from` on `key`'s path, up to level
    /// `to` (`to <= from`) through levels whose other child is empty.
    fn lift(&self, key: &[u8; 32], mut hash: [u8; 32], from: usize, to: usize) -> [u8; 32] {
        for level in (to..from).rev() {
            let empty = &self.defaults[level + 1];
            hash = if get_bit(key, level) == 0 {
                hash_smt_node(&hash, empty)
            } else {
                hash_smt_node(empty, &hash)
            };
        }
        hash
    }

    /// Generate an inclusion proof for the given key.
    ///
    /// Collects 256 sibling hashes ordered leaf-to-root.
    /// Sibling at index `i` corresponds to level `(255 - i)` in MSB-first order.
    ///
    /// For absent keys the proof value is `ZERO_LEAF` — the canonical default
    /// leaf.  The sibling path is still valid and `verify_proof_against_root`
    /// will recompute `hash_smt_leaf(ZERO_LEAF)` at the leaf position, walk the
    /// siblings up, and match the root: the non-inclusion proof a write to a
    /// key the tree does not hold is folded from.
    pub fn get_inclusion_proof(
        &self,
        key: &[u8; 32],
        max_proof_size: usize,
    ) -> Result<SmtInclusionProof, &'static str> {
        // Absent keys get ZERO_LEAF — a valid non-inclusion proof.
        let value = Some(self.leaves.get(key).copied().unwrap_or(ZERO_LEAF));

        // The sibling at each level, root to leaf: the empty subtree, except
        // where the path passes a branch or leaves a held subtree's edge.
        let mut siblings: Vec<[u8; 32]> = self.defaults[1..].to_vec();
        let mut next = self.top;
        while let Some(node) = next {
            let node_key = self.node_key(node);
            let node_level = self.node_level(node);
            next = match first_difference(key, node_key).filter(|bit| *bit < node_level) {
                Some(split) => {
                    siblings[split] =
                        self.lift(node_key, self.node_hash(node), node_level, split + 1);
                    None
                }
                None => match node {
                    Node::Leaf(_) => None,
                    Node::Branch(index) => {
                        let branch = &self.branches[index];
                        let side = usize::from(get_bit(key, branch.level));
                        siblings[branch.level] = branch.child_hashes[1 - side];
                        Some(branch.children[side])
                    }
                },
            };
        }

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

        // The SMT is fixed-depth: a path has exactly 256 siblings. A shorter
        // one would commit the leaf under a root of some other height (a tree
        // that is not this one); a longer one would underflow `255 - i`.
        if proof.siblings.len() != DEFAULT_SMT_HEIGHT as usize {
            return false;
        }
        fold_path(&proof.key, hash_smt_leaf(&value), &proof.siblings) == *expected_root
    }

    /// Apply a step's writes as ONE move of the tree, and return each write
    /// as a fold entry: its key, the value it held and the value written,
    /// and its path against the root the tree had BEFORE any of the writes
    /// (the one pre-root every entry of a write set is stated against).
    /// Entries come back sorted by key; a key written twice is refused, since
    /// a write set names each key once.
    pub fn apply_writes(
        &mut self,
        writes: &[([u8; 32], [u8; 32])],
    ) -> Result<Vec<crate::merkle::batch_fold::FoldEntry>, DsmError> {
        let mut entries = Vec::with_capacity(writes.len());
        for (key, value) in writes {
            let proof = self
                .get_inclusion_proof(key, DEFAULT_SMT_HEIGHT as usize)
                .map_err(|e| DsmError::invalid_operation(format!("a write's path: {e}")))?;
            let path: Box<[[u8; 32]; crate::merkle::batch_fold::FOLD_HEIGHT]> =
                proof.siblings.into_boxed_slice().try_into().map_err(|_| {
                    DsmError::invalid_operation("a write's path is not 256 siblings")
                })?;
            entries.push(crate::merkle::batch_fold::FoldEntry {
                key: *key,
                pre: self.leaves.get(key).copied(),
                post: Some(*value),
                path,
            });
        }
        entries.sort_by_key(|e| e.key);
        if entries.windows(2).any(|w| w[0].key == w[1].key) {
            return Err(DsmError::invalid_operation(
                "a write set names one key twice",
            ));
        }
        for (key, value) in writes {
            self.update_leaf(key, value);
        }
        Ok(entries)
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
        // In u64: on a 32-bit target `count * 32` wraps for a hostile count,
        // and a wrapped length would pass this check while the copies below
        // index past the input.
        let needed = offset as u64 + count as u64 * 32;
        if (data.len() as u64) < needed {
            return None;
        }
        let mut siblings = Vec::with_capacity(count);
        for i in 0..count {
            let mut s = [0u8; 32];
            s.copy_from_slice(&data[offset + i * 32..offset + (i + 1) * 32]);
            siblings.push(s);
        }
        // Canonical decode requires full byte exhaustion: reject trailing bytes
        // so a proof has exactly one byte encoding. (issue #450)
        if needed != data.len() as u64 {
            return None;
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
    use proptest::prelude::*;

    /// An inclusion proof that names more siblings than it carries is
    /// refused. The count `2^27` has a byte length that wraps to 0 on a
    /// 32-bit target, so a length check in `usize` would accept it there.
    #[test]
    fn an_inclusion_proof_naming_more_siblings_than_it_carries_is_refused() {
        for count in [0x0800_0000u32, u32::MAX] {
            let mut bytes = vec![0x5A; 32];
            bytes.push(0x00);
            bytes.extend_from_slice(&count.to_le_bytes());
            assert!(
                SmtInclusionProof::from_bytes(&bytes).is_none(),
                "count {count:#x}"
            );
        }
    }

    /// The tree as it was computed before it kept its nodes: every leaf, split
    /// at each of the 256 levels, on every call. The reference each kept root
    /// and path is checked against.
    struct Recomputed<'a> {
        leaves: &'a HashMap<[u8; 32], [u8; 32]>,
        defaults: &'a [[u8; 32]; 257],
    }

    impl Recomputed<'_> {
        fn root(&self) -> [u8; 32] {
            let keys: Vec<[u8; 32]> = self.leaves.keys().copied().collect();
            self.subtree(0, &keys)
        }

        fn subtree(&self, level: usize, keys: &[[u8; 32]]) -> [u8; 32] {
            if keys.is_empty() {
                return self.defaults[level];
            }
            if level == 256 {
                return hash_smt_leaf(&self.leaves[&keys[0]]);
            }
            let (left, right): (Vec<[u8; 32]>, Vec<[u8; 32]>) = keys
                .iter()
                .copied()
                .partition(|key| get_bit(key, level) == 0);
            hash_smt_node(
                &self.subtree(level + 1, &left),
                &self.subtree(level + 1, &right),
            )
        }

        /// Leaf-to-root siblings of `target`.
        fn siblings(&self, target: &[u8; 32]) -> Vec<[u8; 32]> {
            let mut keys: Vec<[u8; 32]> = self.leaves.keys().copied().collect();
            let mut siblings = Vec::with_capacity(256);
            for level in 0..256 {
                let (along, other): (Vec<[u8; 32]>, Vec<[u8; 32]>) = keys
                    .iter()
                    .copied()
                    .partition(|key| get_bit(key, level) == get_bit(target, level));
                siblings.push(self.subtree(level + 1, &other));
                keys = along;
            }
            siblings.reverse();
            siblings
        }
    }

    /// A key agreeing with `base` on its first `shared` bits and with `tail`
    /// after them. Keys drawn this way separate at every depth, down to two
    /// that differ in their last bit only, so every branch level and edge
    /// length occurs.
    fn key_near(base: &[u8; 32], shared: usize, tail: &[u8; 32]) -> [u8; 32] {
        let mut key = *tail;
        for bit in 0..shared {
            let mask = 0x80u8 >> (bit % 8);
            key[bit / 8] = (key[bit / 8] & !mask) | (base[bit / 8] & mask);
        }
        key
    }

    /// A leaf value, the zero leaf among them: a held key whose leaf hashes
    /// as an empty one.
    fn a_value() -> impl Strategy<Value = [u8; 32]> {
        prop_oneof![Just(ZERO_LEAF), any::<[u8; 32]>()]
    }

    /// A sequence of writes: new keys near one base key, interleaved with
    /// rewrites of keys already written.
    fn writes() -> impl Strategy<Value = Vec<([u8; 32], [u8; 32])>> {
        let draw = (
            0usize..=256,
            any::<[u8; 32]>(),
            a_value(),
            proptest::option::of(any::<prop::sample::Index>()),
        );
        (any::<[u8; 32]>(), prop::collection::vec(draw, 1..40)).prop_map(|(base, draws)| {
            let mut writes: Vec<([u8; 32], [u8; 32])> = Vec::with_capacity(draws.len());
            for (shared, tail, value, rewrite) in draws {
                let key = match rewrite {
                    Some(index) if !writes.is_empty() => writes[index.index(writes.len())].0,
                    _ => key_near(&base, shared, &tail),
                };
                writes.push((key, value));
            }
            writes
        })
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(if cfg!(debug_assertions) { 32 } else { 256 }))]

        /// After every write the root is the one the full recomputation over
        /// the leaves written so far gives, and building those leaves at once
        /// gives it too.
        #[test]
        fn a_written_root_is_the_recomputed_root(writes in writes()) {
            let mut tree = SparseMerkleTree::new();
            let mut leaves = HashMap::new();
            for (key, value) in &writes {
                tree.update_leaf(key, value);
                leaves.insert(*key, *value);
                let recomputed = Recomputed { leaves: &leaves, defaults: &tree.defaults };
                prop_assert_eq!(*tree.root(), recomputed.root());
            }
            prop_assert_eq!(tree.leaf_count(), leaves.len());
            let built = SparseMerkleTree::from_leaves(writes.iter().copied());
            prop_assert_eq!(*built.root(), *tree.root());
        }

        /// A path, to a held key or to one the tree does not hold, is the path
        /// the full recomputation gives, and it folds to the root.
        #[test]
        fn a_kept_path_is_the_recomputed_path(
            writes in writes(),
            tail in any::<[u8; 32]>(),
            shared in 0usize..=256,
        ) {
            let tree = SparseMerkleTree::from_leaves(writes.iter().copied());
            let recomputed = Recomputed { leaves: &tree.leaves, defaults: &tree.defaults };
            let near = key_near(&writes[0].0, shared, &tail);
            for key in tree.leaves.keys().take(12).chain([tail, near].iter()) {
                let proof = tree.get_inclusion_proof(key, 256).expect("a path");
                prop_assert_eq!(&proof.siblings, &recomputed.siblings(key));
                prop_assert!(tree.verify_inclusion_proof(&proof));
            }
        }
    }

    /// Past the size of any small tree: a thousand uniformly drawn leaves,
    /// written one at a time and built at once, give the recomputed root.
    #[test]
    fn a_large_tree_keeps_the_recomputed_root() {
        let leaves: Vec<([u8; 32], [u8; 32])> = (0u64..1000)
            .map(|i| {
                let mut seed = [7u8; 32];
                seed[..8].copy_from_slice(&i.to_le_bytes());
                (hash_smt_leaf(&seed), hash_smt_node(&seed, &seed))
            })
            .collect();
        let mut written = SparseMerkleTree::new();
        for (key, value) in &leaves {
            written.update_leaf(key, value);
        }
        let built = SparseMerkleTree::from_leaves(leaves.iter().copied());
        let recomputed = Recomputed {
            leaves: &built.leaves,
            defaults: &built.defaults,
        };
        assert_eq!(*written.root(), recomputed.root());
        assert_eq!(*built.root(), recomputed.root());
        let (key, _) = leaves[500];
        assert_eq!(
            written
                .get_inclusion_proof(&key, 256)
                .expect("a path")
                .siblings,
            recomputed.siblings(&key)
        );
    }

    #[test]
    fn zero_leaf_is_32_zero_bytes() {
        assert_eq!(ZERO_LEAF, [0u8; 32]);
        assert_eq!(empty_leaf(), ZERO_LEAF);
    }

    #[test]
    fn inclusion_proof_trailing_bytes_rejected() {
        let proof = SmtInclusionProof {
            key: [1u8; 32],
            value: Some([2u8; 32]),
            siblings: vec![[3u8; 32], [4u8; 32]],
        };
        let mut bytes = proof.to_bytes();
        // Exact bytes decode fine; trailing bytes are non-canonical (issue #450).
        assert!(SmtInclusionProof::from_bytes(&bytes).is_some());
        bytes.push(0x00);
        assert!(SmtInclusionProof::from_bytes(&bytes).is_none());
    }

    #[test]
    fn empty_tree_root_matches_default_chain() {
        let smt = SparseMerkleTree::new();
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
        let mut smt = SparseMerkleTree::new();

        let key = [1u8; 32];
        let value = [42u8; 32];

        smt.update_leaf(&key, &value);

        let proof = smt.get_inclusion_proof(&key, 256).unwrap();
        assert!(smt.verify_inclusion_proof(&proof));
        assert_eq!(proof.value, Some(value));
        assert_eq!(proof.siblings.len(), 256);
    }

    #[test]
    fn verify_proof_against_root_static() {
        let mut smt = SparseMerkleTree::new();

        let key = [7u8; 32];
        let value = [99u8; 32];
        smt.update_leaf(&key, &value);

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
        let mut smt = SparseMerkleTree::new();

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
            smt.update_leaf(key, value);
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
        let mut smt = SparseMerkleTree::new();

        let key = [1u8; 32];
        let value1 = [42u8; 32];
        let value2 = [99u8; 32];

        smt.update_leaf(&key, &value1);
        let root1 = *smt.root();

        smt.update_leaf(&key, &value2);
        let root2 = *smt.root();

        assert_ne!(root1, root2);

        let proof = smt.get_inclusion_proof(&key, 256).unwrap();
        assert_eq!(proof.value, Some(value2));
        assert!(smt.verify_inclusion_proof(&proof));
    }

    #[test]
    fn proof_size_bounding() {
        let mut smt = SparseMerkleTree::new();

        let key = [1u8; 32];
        let value = [42u8; 32];
        smt.update_leaf(&key, &value);

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
