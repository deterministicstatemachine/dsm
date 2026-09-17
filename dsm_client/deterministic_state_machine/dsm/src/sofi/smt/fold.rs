// SPDX-License-Identifier: Apache-2.0

//! One batch fold: many leaves, one pre-root, one post-root.
//!
//! A core (`T°`, `V°`) states every entry's authentication path against ONE
//! root — the core's `pre_root` — and the verifier must turn that set into the
//! post-root without holding the tree. Folding the entries one at a time does
//! not do it: after the first write the tree has moved, so the second entry's
//! path is stated against a root that no longer exists. Sequential ascending
//! paths also make every leaf after an E-dependent one E-dependent, which is
//! exactly the ordering problem P15-7 removes.
//!
//! So this folds them together. The entries are sorted by key, and the tree is
//! rebuilt top-down: where the keys separate, each side is folded from the
//! entries themselves; where they do not, the missing sibling comes from the
//! paths. Both roots come out of the same shape, so the post-root is what the
//! tree holds after ALL the writes, in one pass.
//!
//! ## What makes it sound
//!
//! Wherever two entries separate, each one's path already names what the other
//! side must be — and this checks it ([`FoldError::InconsistentPath`]).
//! Without that check a caller could hand in paths taken from different trees
//! and get a post-root that no single tree ever held. The check is what turns
//! "these paths are individually well-formed" into "these paths are of one
//! tree".
//!
//! ## What it does not know
//!
//! Leaf types. An entry is a key, an optional pre-value, an optional
//! post-value and a path; `None` is a leaf holding nothing, so non-inclusion
//! and insertion are the same arithmetic as any other write. Whether a value
//! is a vault state, a relationship leaf or a balance is the caller's
//! business, and BindExt has already filled any E-dependent post by the time
//! the fold sees it.

use crate::economic::tree::{econ_node, leaf_node, ECONOMIC_SMT_HEIGHT};
use crate::merkle::sparse_merkle_tree::get_bit;

/// One key's contribution to a core, with its full path against the core's
/// `pre_root`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FoldEntry {
    pub key: [u8; 32],
    /// The leaf's value before the operation; `None` is a leaf holding nothing.
    pub pre: Option<[u8; 32]>,
    /// The leaf's value after it. A read carries the same value as `pre`.
    pub post: Option<[u8; 32]>,
    /// Leaf-to-root siblings, exactly as `root_from_path` folds them.
    pub path: Box<[[u8; 32]; ECONOMIC_SMT_HEIGHT]>,
}

/// Both roots of one fold.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Folded {
    pub pre_root: [u8; 32],
    pub post_root: [u8; 32],
}

/// Why a set of entries is not one core's worth of paths.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FoldError {
    /// A core states at least one entry.
    NoEntries,
    /// Entries are not strictly ascending by key. Duplicates are included: a
    /// write set names each key once, and the fold never picks a winner.
    KeysNotAscending { index: usize },
    /// An entry's sibling contradicts what the other entries at that point
    /// compute, so the paths are not all of one tree.
    InconsistentPath { depth: usize },
    /// The entries fold to a different root than the core claims.
    PreRootMismatch {
        claimed: [u8; 32],
        computed: [u8; 32],
    },
}

impl core::fmt::Display for FoldError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NoEntries => write!(f, "a core states no entries"),
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

/// The sibling an entry names for the step taken at `depth`.
fn sibling_at(entry: &FoldEntry, depth: usize) -> [u8; 32] {
    entry.path[ECONOMIC_SMT_HEIGHT - 1 - depth]
}

/// Fold one entry alone, from its leaf up to the subtree rooted at `depth`,
/// under both its values at once.
fn fold_single(entry: &FoldEntry, depth: usize) -> ([u8; 32], [u8; 32]) {
    let mut pre = leaf_node(&entry.key, entry.pre.as_ref());
    let mut post = leaf_node(&entry.key, entry.post.as_ref());
    for level in (depth..ECONOMIC_SMT_HEIGHT).rev() {
        let sibling = sibling_at(entry, level);
        let (l_pre, r_pre, l_post, r_post) = if get_bit(&entry.key, level) == 0 {
            (pre, sibling, post, sibling)
        } else {
            (sibling, pre, sibling, post)
        };
        pre = econ_node(&l_pre, &r_pre);
        post = econ_node(&l_post, &r_post);
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
fn subtree(depth: usize, entries: &[&FoldEntry]) -> Result<([u8; 32], [u8; 32]), FoldError> {
    if entries.len() == 1 {
        return Ok(fold_single(entries[0], depth));
    }
    // More than one entry cannot reach leaf depth: the keys would be equal,
    // and equal keys were refused before the walk started.
    debug_assert!(depth < ECONOMIC_SMT_HEIGHT);
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
        let (pre, post) = subtree(depth + 1, entries)?;
        return Ok(if low.is_empty() {
            (econ_node(&sibling, &pre), econ_node(&sibling, &post))
        } else {
            (econ_node(&pre, &sibling), econ_node(&post, &sibling))
        });
    }
    let (low_pre, low_post) = subtree(depth + 1, low)?;
    let (high_pre, high_post) = subtree(depth + 1, high)?;
    // Where the keys separate, each side's path already names the other side
    // AS IT WAS. This is the check that makes one fold out of many paths.
    if low.iter().any(|e| sibling_at(e, depth) != high_pre)
        || high.iter().any(|e| sibling_at(e, depth) != low_pre)
    {
        return Err(FoldError::InconsistentPath { depth });
    }
    Ok((
        econ_node(&low_pre, &high_pre),
        econ_node(&low_post, &high_post),
    ))
}

/// Fold a core's entries into its pre- and post-roots.
///
/// Every entry's path is against the SAME pre-root, and the post-root accounts
/// for every write at once. A read contributes the same value to both roots,
/// which is what makes it binding rather than decorative.
pub fn batch_fold(entries: &[FoldEntry]) -> Result<Folded, FoldError> {
    if entries.is_empty() {
        return Err(FoldError::NoEntries);
    }
    for (i, w) in entries.windows(2).enumerate() {
        if w[0].key >= w[1].key {
            return Err(FoldError::KeysNotAscending { index: i + 1 });
        }
    }
    let refs: Vec<&FoldEntry> = entries.iter().collect();
    let (pre_root, post_root) = subtree(0, &refs)?;
    Ok(Folded {
        pre_root,
        post_root,
    })
}

/// Fold against a claimed pre-root, returning the post-root. This is the form
/// a verifier uses: the claim is checked, never trusted.
pub fn verify_batch(pre_root: &[u8; 32], entries: &[FoldEntry]) -> Result<[u8; 32], FoldError> {
    let folded = batch_fold(entries)?;
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
    use crate::economic::tree::{empty_economic_root, root_from_path, EconomicSmt};
    use proptest::prelude::*;

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

    fn value(i: u64) -> [u8; 32] {
        let mut v = [0x5Au8; 32];
        v[..8].copy_from_slice(&i.to_be_bytes());
        v
    }

    fn entry(tree: &EconomicSmt, k: [u8; 32], post: Option<[u8; 32]>) -> FoldEntry {
        FoldEntry {
            key: k,
            pre: tree.get(&k).copied(),
            post,
            path: Box::new(tree.siblings(&k)),
        }
    }

    fn sorted(mut entries: Vec<FoldEntry>) -> Vec<FoldEntry> {
        entries.sort_by_key(|e| e.key);
        entries
    }

    /// One entry folds to exactly what the single-path verifier computes, for
    /// an inclusion and for a non-inclusion.
    #[test]
    fn one_entry_agrees_with_the_single_path_verifier() {
        let mut tree = EconomicSmt::new();
        for i in 0..40u64 {
            tree.insert(key(i), value(i));
        }
        let present = key(7);
        let absent = key(4_000);
        for (k, pre) in [(present, Some(value(7))), (absent, None)] {
            let e = entry(&tree, k, pre);
            let folded = batch_fold(std::slice::from_ref(&e)).unwrap();
            assert_eq!(folded.pre_root, tree.root());
            assert_eq!(
                folded.pre_root,
                root_from_path(
                    &k,
                    &crate::economic::tree::leaf_node(&k, pre.as_ref()),
                    &e.path
                )
            );
            // Nothing written: the two roots agree.
            assert_eq!(folded.post_root, folded.pre_root);
        }
    }

    /// The property the cores rest on: for ANY mix of writes, removals, reads
    /// and absences, the batch post-root is the root the reference tree holds
    /// after the same operations.
    #[test]
    fn the_batch_fold_equals_the_reference_tree_for_every_entry_mix() {
        proptest!(|(
            seed_count in 0usize..24,
            ops in prop::collection::vec((0u64..48, 0u8..4), 1..10),
        )| {
            let mut tree = EconomicSmt::new();
            for i in 0..seed_count as u64 {
                tree.insert(key(i), value(i));
            }
            let pre_root = tree.root();

            // One entry per distinct key, each stated against the SAME pre-root.
            let mut chosen: Vec<(u64, u8)> = Vec::new();
            for (k, op) in ops {
                if !chosen.iter().any(|(existing, _)| *existing == k) {
                    chosen.push((k, op));
                }
            }
            let entries: Vec<FoldEntry> = chosen
                .iter()
                .map(|(i, op)| {
                    let k = key(*i);
                    let post = match op {
                        // write a fresh value
                        0 => Some(value(i + 1_000)),
                        // remove it (a no-op when it was already absent)
                        1 => None,
                        // read: unchanged
                        2 => tree.get(&k).copied(),
                        // write the value it already has, or insert one
                        _ => Some(tree.get(&k).copied().unwrap_or(value(*i))),
                    };
                    entry(&tree, k, post)
                })
                .collect();
            let entries = sorted(entries);

            let folded = batch_fold(&entries).unwrap();
            prop_assert_eq!(folded.pre_root, pre_root);
            prop_assert_eq!(verify_batch(&pre_root, &entries).unwrap(), folded.post_root);

            // Apply the same operations to the reference and compare.
            for e in &entries {
                match e.post {
                    Some(v) => tree.insert(e.key, v),
                    None => tree.remove(&e.key),
                }
            }
            prop_assert_eq!(folded.post_root, tree.root());
        });
    }

    /// The same property on an empty tree, where every entry is an insertion
    /// into nothing.
    #[test]
    fn inserting_into_an_empty_tree_folds_to_the_reference_root() {
        let mut tree = EconomicSmt::new();
        let entries = sorted(
            (0..8u64)
                .map(|i| entry(&tree, key(i), Some(value(i))))
                .collect(),
        );
        let folded = batch_fold(&entries).unwrap();
        assert_eq!(folded.pre_root, empty_economic_root());
        for i in 0..8u64 {
            tree.insert(key(i), value(i));
        }
        assert_eq!(folded.post_root, tree.root());
    }

    /// Removing every leaf returns the empty root, in one fold.
    #[test]
    fn removing_every_leaf_folds_back_to_the_empty_root() {
        let mut tree = EconomicSmt::new();
        for i in 0..6u64 {
            tree.insert(key(i), value(i));
        }
        let entries = sorted((0..6u64).map(|i| entry(&tree, key(i), None)).collect());
        assert_eq!(
            batch_fold(&entries).unwrap().post_root,
            empty_economic_root()
        );
    }

    /// A read is binding: it contributes to both roots, so a core cannot claim
    /// a value it did not prove.
    #[test]
    fn a_read_binds_its_value_into_both_roots() {
        let mut tree = EconomicSmt::new();
        for i in 0..12u64 {
            tree.insert(key(i), value(i));
        }
        let read = entry(&tree, key(3), Some(value(3)));
        let mut lying = read.clone();
        lying.pre = Some(value(99));
        lying.post = Some(value(99));
        assert_eq!(batch_fold(&[read]).unwrap().pre_root, tree.root());
        assert_ne!(batch_fold(&[lying]).unwrap().pre_root, tree.root());
    }

    /// THE SOUNDNESS CHECK: paths taken from two different trees do not fold.
    /// Without it a caller could mix paths and land on a root no tree held.
    #[test]
    fn paths_from_two_different_trees_are_refused() {
        let mut first = EconomicSmt::new();
        let mut second = EconomicSmt::new();
        for i in 0..10u64 {
            first.insert(key(i), value(i));
            second.insert(key(i), value(i));
        }
        // The trees differ in a leaf neither entry names.
        second.insert(key(500), value(500));

        let a = entry(&first, key(1), Some(value(1_001)));
        let b = entry(&second, key(2), Some(value(1_002)));
        let mixed = sorted(vec![a, b]);
        assert!(matches!(
            batch_fold(&mixed),
            Err(FoldError::InconsistentPath { .. })
        ));
    }

    /// A single tampered sibling is caught wherever the keys separate.
    #[test]
    fn a_tampered_sibling_is_refused() {
        let mut tree = EconomicSmt::new();
        for i in 0..16u64 {
            tree.insert(key(i), value(i));
        }
        let mut entries = sorted(vec![
            entry(&tree, key(1), Some(value(101))),
            entry(&tree, key(2), Some(value(102))),
            entry(&tree, key(3), Some(value(103))),
        ]);
        assert!(batch_fold(&entries).is_ok());
        // Bend the sibling that names the far side of the tree.
        entries[0].path[ECONOMIC_SMT_HEIGHT - 1][0] ^= 0xFF;
        assert!(matches!(
            batch_fold(&entries),
            Err(FoldError::InconsistentPath { depth: 0 })
        ));
    }

    /// A tampered sibling BELOW every separation still moves the root, so it
    /// cannot pass as the pre-root a core claims.
    #[test]
    fn a_tampered_deep_sibling_changes_the_root() {
        let mut tree = EconomicSmt::new();
        for i in 0..16u64 {
            tree.insert(key(i), value(i));
        }
        let mut one = entry(&tree, key(5), Some(value(105)));
        one.path[0][0] ^= 0xFF;
        let folded = batch_fold(std::slice::from_ref(&one)).unwrap();
        assert_ne!(folded.pre_root, tree.root());
        assert_eq!(
            verify_batch(&tree.root(), std::slice::from_ref(&one)),
            Err(FoldError::PreRootMismatch {
                claimed: tree.root(),
                computed: folded.pre_root,
            })
        );
    }

    #[test]
    fn entries_must_be_strictly_ascending_and_present() {
        let mut tree = EconomicSmt::new();
        for i in 0..8u64 {
            tree.insert(key(i), value(i));
        }
        assert_eq!(batch_fold(&[]), Err(FoldError::NoEntries));

        let a = entry(&tree, key(1), Some(value(1)));
        let b = entry(&tree, key(2), Some(value(2)));
        let (lo, hi) = if a.key < b.key {
            (a.clone(), b.clone())
        } else {
            (b.clone(), a.clone())
        };
        assert!(matches!(
            batch_fold(&[hi.clone(), lo.clone()]),
            Err(FoldError::KeysNotAscending { index: 1 })
        ));
        // A duplicate key is not collapsed; the fold never picks a winner.
        assert!(matches!(
            batch_fold(&[lo.clone(), lo]),
            Err(FoldError::KeysNotAscending { index: 1 })
        ));
    }

    /// The order entries are folded in does not change either root: one batch,
    /// not a sequence.
    #[test]
    fn the_fold_is_independent_of_how_the_writes_are_grouped() {
        let mut tree = EconomicSmt::new();
        for i in 0..20u64 {
            tree.insert(key(i), value(i));
        }
        let entries = sorted(vec![
            entry(&tree, key(2), Some(value(202))),
            entry(&tree, key(9), None),
            entry(&tree, key(4_000), Some(value(4_000))),
            entry(&tree, key(13), Some(value(13))),
        ]);
        let folded = batch_fold(&entries).unwrap();

        // The same writes, applied one at a time to the reference.
        for e in &entries {
            match e.post {
                Some(v) => tree.insert(e.key, v),
                None => tree.remove(&e.key),
            }
        }
        assert_eq!(folded.post_root, tree.root());
    }
}
