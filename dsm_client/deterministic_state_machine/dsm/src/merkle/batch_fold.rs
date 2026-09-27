// SPDX-License-Identifier: Apache-2.0

//! One batch fold: many leaves, one pre-root, one post-root — for any 256-level
//! sparse Merkle tree, given how that tree hashes ([`SmtHashes`]).
//!
//! A write set states every entry's authentication path against ONE root — the
//! pre-root — and the verifier must turn that set into the post-root without
//! holding the tree. Folding the entries one at a time does not do it: after the
//! first write the tree has moved, so the second entry's path is stated against a
//! root that no longer exists.
//!
//! So this folds them together. The entries are sorted by key, and the tree is
//! rebuilt top-down: where the keys separate, each side is folded from the
//! entries themselves; where they do not, the missing sibling comes from the
//! paths. Both roots come out of the same shape, so the post-root is what the
//! tree holds after ALL the writes, in one pass.
//!
//! ## What makes it sound, and what makes it canonical
//!
//! The two roots the fold yields are always those of one tree: the tree its
//! entries' values and the siblings it reads describe. [`verify_batch`]
//! requires that tree's pre-root to be the claimed one, and that is what makes
//! the post-root the claimed tree after the writes
//! (`lean4/DSMStepTransition.lean`, `fold_sound`).
//!
//! The fold does not read every sibling it is given: where the keys separate,
//! each side comes from its own entries, and where they do not, it reads the
//! first entry's. The siblings it does not read must still be the tree's, and
//! this checks them ([`FoldError::InconsistentPath`]), so every path a write
//! set carries is the tree's own path at its key (`fold_canonical`). Without
//! the check a sibling the fold never reads would be free: the same move would
//! have many encodings, and a proof carrying it would be malleable
//! (`lax_fold_is_not_canonical`).
//!
//! ## What it does not know
//!
//! Leaf types. An entry is a key, an optional pre-value, an optional
//! post-value and a path; `None` is a leaf holding nothing, so non-inclusion
//! and insertion are the same arithmetic as any other write. What a value
//! means is the caller's business.

use crate::merkle::sparse_merkle_tree::get_bit;

/// Every tree this fold serves has the full 256-bit key space.
pub const FOLD_HEIGHT: usize = 256;

/// How a sparse Merkle tree hashes. A path is leaf-to-root: `path[i]` is the
/// sibling at height `i` (the root of a subtree `i` levels tall), `path[0]`
/// next to the leaf.
pub trait SmtHashes {
    /// The node at a leaf position: `value` is `None` for a leaf holding
    /// nothing.
    fn leaf(key: &[u8; 32], value: Option<&[u8; 32]>) -> [u8; 32];
    /// An internal node over its two children.
    fn node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32];
    /// The root of an empty subtree of `height` (0 is an empty leaf position).
    fn default_node(height: usize) -> [u8; 32];
}

/// One key's contribution to a write set, with its full path against the
/// write set's pre-root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FoldEntry {
    pub key: [u8; 32],
    /// The leaf's value before the writes; `None` is a leaf holding nothing.
    pub pre: Option<[u8; 32]>,
    /// The leaf's value after them. A read carries the same value as `pre`.
    pub post: Option<[u8; 32]>,
    /// Leaf-to-root siblings against the pre-root.
    pub path: Box<[[u8; 32]; FOLD_HEIGHT]>,
}

/// Both roots of one fold.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Folded {
    pub pre_root: [u8; 32],
    pub post_root: [u8; 32],
}

/// Why a set of entries is not one tree's worth of paths.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FoldError {
    /// A write set states at least one entry.
    NoEntries,
    /// Entries are not strictly ascending by key. Duplicates are included: a
    /// write set names each key once, and the fold never picks a winner.
    KeysNotAscending { index: usize },
    /// An entry's sibling contradicts what the other entries at that point
    /// compute, so the paths are not all of one tree.
    InconsistentPath { depth: usize },
    /// The entries fold to a different root than the one claimed.
    PreRootMismatch {
        claimed: [u8; 32],
        computed: [u8; 32],
    },
}

impl core::fmt::Display for FoldError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NoEntries => write!(f, "a write set states no entries"),
            Self::KeysNotAscending { index } => write!(
                f,
                "entry {index} is not strictly after its predecessor \
                 (duplicates are invalid, never collapsed)"
            ),
            Self::InconsistentPath { depth } => write!(
                f,
                "the sibling at depth {depth} contradicts the other entries: \
                 these paths are not all of one tree"
            ),
            Self::PreRootMismatch { .. } => {
                write!(f, "the entries do not fold to the claimed pre-root")
            }
        }
    }
}

impl std::error::Error for FoldError {}

/// The sibling an entry names for the step taken at `depth` (0 is the root).
fn sibling_at(entry: &FoldEntry, depth: usize) -> [u8; 32] {
    entry.path[FOLD_HEIGHT - 1 - depth]
}

/// Fold one entry alone, from its leaf up to the subtree rooted at `depth`,
/// under both its values at once.
fn fold_single<H: SmtHashes>(entry: &FoldEntry, depth: usize) -> ([u8; 32], [u8; 32]) {
    let mut pre = H::leaf(&entry.key, entry.pre.as_ref());
    let mut post = H::leaf(&entry.key, entry.post.as_ref());
    for level in (depth..FOLD_HEIGHT).rev() {
        let sibling = sibling_at(entry, level);
        let (l_pre, r_pre, l_post, r_post) = if get_bit(&entry.key, level) == 0 {
            (pre, sibling, post, sibling)
        } else {
            (sibling, pre, sibling, post)
        };
        pre = H::node(&l_pre, &r_pre);
        post = H::node(&l_post, &r_post);
    }
    (pre, post)
}

/// The subtree rooted at `depth` covering `entries`, under the pre-values and
/// the post-values together.
///
/// One walk, two values. It has to be one walk: the paths are stated against
/// the PRE-root, so only the pre side may be checked against them. Checking
/// the post side too would demand that a sibling predict what the other entries
/// are about to write, which is exactly what a batch of writes changes.
///
/// `entries` is sorted by key and non-empty, so at every depth it splits into a
/// low side and a high side by one bit.
fn subtree<H: SmtHashes>(
    depth: usize,
    entries: &[&FoldEntry],
) -> Result<([u8; 32], [u8; 32]), FoldError> {
    if entries.len() == 1 {
        return Ok(fold_single::<H>(entries[0], depth));
    }
    // More than one entry cannot reach leaf depth: the keys would be equal,
    // and equal keys were refused before the walk started.
    debug_assert!(depth < FOLD_HEIGHT);
    let split = entries.partition_point(|e| get_bit(&e.key, depth) == 0);
    let (low, high) = entries.split_at(split);
    if low.is_empty() || high.is_empty() {
        // The keys do not separate here, so the untouched side is whatever the
        // paths say — and they must all say the same thing. It is untouched by
        // definition, so it is the same in both roots.
        let sibling = sibling_at(entries[0], depth);
        if entries.iter().any(|e| sibling_at(e, depth) != sibling) {
            return Err(FoldError::InconsistentPath { depth });
        }
        let (pre, post) = subtree::<H>(depth + 1, entries)?;
        return Ok(if low.is_empty() {
            (H::node(&sibling, &pre), H::node(&sibling, &post))
        } else {
            (H::node(&pre, &sibling), H::node(&post, &sibling))
        });
    }
    let (low_pre, low_post) = subtree::<H>(depth + 1, low)?;
    let (high_pre, high_post) = subtree::<H>(depth + 1, high)?;
    // Where the keys separate, each side's path already names the other side
    // AS IT WAS. The fold reads neither of these siblings; the check is what
    // keeps them the tree's, so the proof has one encoding.
    if low.iter().any(|e| sibling_at(e, depth) != high_pre)
        || high.iter().any(|e| sibling_at(e, depth) != low_pre)
    {
        return Err(FoldError::InconsistentPath { depth });
    }
    Ok((H::node(&low_pre, &high_pre), H::node(&low_post, &high_post)))
}

/// Fold a write set's entries into its pre- and post-roots.
///
/// Every entry's path is against the SAME pre-root, and the post-root accounts
/// for every write at once. A read contributes the same value to both roots,
/// which is what makes it binding rather than decorative.
pub fn batch_fold<H: SmtHashes>(entries: &[FoldEntry]) -> Result<Folded, FoldError> {
    if entries.is_empty() {
        return Err(FoldError::NoEntries);
    }
    for (i, w) in entries.windows(2).enumerate() {
        if w[0].key >= w[1].key {
            return Err(FoldError::KeysNotAscending { index: i + 1 });
        }
    }
    let refs: Vec<&FoldEntry> = entries.iter().collect();
    let (pre_root, post_root) = subtree::<H>(0, &refs)?;
    Ok(Folded {
        pre_root,
        post_root,
    })
}

/// Fold against a claimed pre-root, returning the post-root. This is the form
/// a verifier uses: the claim is checked, never trusted.
pub fn verify_batch<H: SmtHashes>(
    pre_root: &[u8; 32],
    entries: &[FoldEntry],
) -> Result<[u8; 32], FoldError> {
    let folded = batch_fold::<H>(entries)?;
    if folded.pre_root != *pre_root {
        return Err(FoldError::PreRootMismatch {
            claimed: *pre_root,
            computed: folded.pre_root,
        });
    }
    Ok(folded.post_root)
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)] // test asserts; a failure here is the signal
mod tests {
    use super::*;
    use crate::merkle::sparse_merkle_tree::{DeviceSmtHashes, SparseMerkleTree};

    /// Distinct keys spread over the key space (an xorshift walk); the tree
    /// decides every root and path from them.
    fn key(i: u64) -> [u8; 32] {
        let mut k = [0u8; 32];
        let mut x = i.wrapping_add(1).wrapping_mul(0x9E37_79B9_7F4A_7C15);
        for chunk in k.chunks_mut(8) {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            chunk.copy_from_slice(&x.to_be_bytes());
        }
        k
    }

    /// The entry the device tree states for `k` before a write of `post`.
    fn entry(tree: &SparseMerkleTree, k: [u8; 32], post: [u8; 32]) -> FoldEntry {
        let proof = tree.get_inclusion_proof(&k, 256).unwrap();
        FoldEntry {
            key: k,
            pre: proof.value,
            post: Some(post),
            path: Box::new(proof.siblings.try_into().unwrap()),
        }
    }

    /// Writes to present and absent keys, alone and together, fold from the
    /// tree's root to exactly the root the tree holds after applying them.
    #[test]
    fn a_device_write_set_folds_to_the_tree_after_the_writes() {
        let tree = SparseMerkleTree::from_leaves((0..60u64).map(|i| (key(i), key(i + 10_000))));
        for writes in [
            vec![(key(3), key(20_003))],
            vec![(key(90_000), key(20_004))],
            vec![
                (key(3), key(20_005)),
                (key(17), key(20_006)),
                (key(90_001), key(20_007)),
            ],
        ] {
            let mut entries: Vec<FoldEntry> =
                writes.iter().map(|(k, v)| entry(&tree, *k, *v)).collect();
            entries.sort_by_key(|e| e.key);
            let mut after = tree.clone();
            for (k, v) in &writes {
                after.update_leaf(k, v);
            }
            assert_eq!(
                verify_batch::<DeviceSmtHashes>(tree.root(), &entries).unwrap(),
                *after.root()
            );
        }
    }

    /// Paths taken from two different device trees do not fold together, even
    /// when the trees differ only at the other entry's own leaf. Every sibling
    /// above the point where the two keys separate is then the same in both
    /// trees, so only the check at the separation can see it.
    #[test]
    fn device_paths_of_two_trees_are_refused() {
        let tree = SparseMerkleTree::from_leaves((0..60u64).map(|i| (key(i), key(i + 10_000))));
        let mut other = tree.clone();
        other.update_leaf(&key(17), &key(30_000));
        let mut entries = vec![
            entry(&tree, key(3), key(20_003)),
            entry(&other, key(17), key(20_004)),
        ];
        entries.sort_by_key(|e| e.key);
        assert!(matches!(
            batch_fold::<DeviceSmtHashes>(&entries),
            Err(FoldError::InconsistentPath { .. })
        ));
    }
}
