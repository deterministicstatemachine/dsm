// SPDX-License-Identifier: Apache-2.0

//! The economic tree's instance of the one batch fold
//! ([`crate::merkle::batch_fold`]): many leaves, one pre-root, one post-root.
//!
//! A core (`T°`, `V°`) states every entry's authentication path against ONE
//! root — the core's `pre_root` — and the verifier turns that set into the
//! post-root without holding the tree. BindExt has already filled any
//! E-dependent post by the time the fold sees an entry.

use crate::economic::tree::{default_node, econ_node, leaf_node, ECONOMIC_SMT_HEIGHT};
use crate::merkle::batch_fold::{self, SmtHashes, FOLD_HEIGHT};

pub use crate::merkle::batch_fold::{AdvanceError, Advanced, FoldEntry, FoldError, Folded};

// The economic tree is a 256-level tree; the fold's paths are exactly its paths.
const _: () = assert!(ECONOMIC_SMT_HEIGHT == FOLD_HEIGHT);

/// How the economic tree hashes: a key-bound leaf, `ABSENT_LEAF` for a leaf
/// holding nothing.
pub struct EconomicHashes;

impl SmtHashes for EconomicHashes {
    fn leaf(key: &[u8; 32], value: Option<&[u8; 32]>) -> [u8; 32] {
        leaf_node(key, value)
    }
    fn node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
        econ_node(left, right)
    }
    fn default_node(height: usize) -> [u8; 32] {
        default_node(height)
    }
}

/// Fold against a claimed pre-root, returning the post-root.
pub fn verify_batch(pre_root: &[u8; 32], entries: &[FoldEntry]) -> Result<[u8; 32], FoldError> {
    batch_fold::verify_batch::<EconomicHashes>(pre_root, entries)
}

/// Advance one held economic leaf and its path from `pre_root` to
/// `post_root` through a write set ([`batch_fold::advance_path`]).
pub fn advance_path(
    pre_root: &[u8; 32],
    post_root: &[u8; 32],
    entries: &[FoldEntry],
    key: &[u8; 32],
    held: Option<&[u8; 32]>,
    path: &[[u8; 32]; FOLD_HEIGHT],
) -> Result<Advanced, AdvanceError> {
    batch_fold::advance_path::<EconomicHashes>(pre_root, post_root, entries, key, held, path)
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)] // test asserts; a failure here is the signal
mod tests {
    use super::*;
    use crate::economic::tree::{empty_economic_root, root_from_path, EconomicSmt};
    use proptest::prelude::*;

    /// The one fold over the economic tree's hashes: what `verify_batch`
    /// runs, with its pre-root returned instead of checked.
    fn batch_fold(entries: &[FoldEntry]) -> Result<Folded, FoldError> {
        batch_fold::batch_fold::<EconomicHashes>(entries)
    }

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

    /// Two trees that differ only at one entry's own leaf agree on every
    /// sibling above the point where the entries' keys separate; the paths
    /// are still of two trees, and the check at the separation refuses them.
    #[test]
    fn paths_from_trees_that_differ_only_at_an_entrys_own_leaf_are_refused() {
        let mut first = EconomicSmt::new();
        for i in 0..10u64 {
            first.insert(key(i), value(i));
        }
        let mut second = first.clone();
        second.insert(key(2), value(900));

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

    /// Writes to apply in one set: each key and the value it is left
    /// holding, `None` for a removal.
    type Writes = Vec<([u8; 32], Option<[u8; 32]>)>;

    /// The write set that moves `tree` by `writes`, each stated against the
    /// tree before them, sorted.
    fn write_set(tree: &EconomicSmt, writes: &[([u8; 32], Option<[u8; 32]>)]) -> Vec<FoldEntry> {
        sorted(writes.iter().map(|(k, v)| entry(tree, *k, *v)).collect())
    }

    fn apply(tree: &mut EconomicSmt, entries: &[FoldEntry]) {
        for e in entries {
            match e.post {
                Some(v) => tree.insert(e.key, v),
                None => tree.remove(&e.key),
            }
        }
    }

    /// Advance the held `(k, value, path)` through `rounds` write sets, and
    /// after every one compare it with what the reference tree holds.
    fn advance_through(mut tree: EconomicSmt, held_key: [u8; 32], rounds: &[Writes]) {
        let mut value = tree.get(&held_key).copied();
        let mut path = Box::new(tree.siblings(&held_key));
        for writes in rounds {
            let pre_root = tree.root();
            let entries = write_set(&tree, writes);
            let post_root = verify_batch(&pre_root, &entries).unwrap();
            let advanced = advance_path(
                &pre_root,
                &post_root,
                &entries,
                &held_key,
                value.as_ref(),
                &path,
            )
            .unwrap();
            apply(&mut tree, &entries);
            assert_eq!(post_root, tree.root());
            assert_eq!(advanced.value, tree.get(&held_key).copied());
            assert_eq!(*advanced.path, tree.siblings(&held_key));
            value = advanced.value;
            path = advanced.path;
        }
    }

    /// A leaf held at a baseline ten write sets back, none of which wrote it,
    /// advances to exactly the reference tree's path after each.
    #[test]
    fn a_held_leaf_advances_through_ten_write_sets_it_is_not_in() {
        let mut tree = EconomicSmt::new();
        for i in 0..40u64 {
            tree.insert(key(i), value(i));
        }
        let rounds: Vec<_> = (0..10u64)
            .map(|r| {
                vec![
                    (key(100 + r), Some(value(100 + r))),
                    (key(r), Some(value(500 + r))),
                ]
            })
            .collect();
        advance_through(tree, key(37), &rounds);
    }

    /// The same from an absent leaf: its non-inclusion path advances, and the
    /// leaf stays absent.
    #[test]
    fn an_absent_leaf_advances_through_ten_write_sets() {
        let mut tree = EconomicSmt::new();
        for i in 0..40u64 {
            tree.insert(key(i), value(i));
        }
        let rounds: Vec<_> = (0..10u64)
            .map(|r| vec![(key(100 + r), Some(value(100 + r)))])
            .collect();
        advance_through(tree, key(9_999), &rounds);
    }

    /// A write set that writes the held leaf itself — first inserting it,
    /// then changing it beside other writes — carries its post-value forward.
    #[test]
    fn a_write_to_the_held_leaf_becomes_its_value() {
        let mut tree = EconomicSmt::new();
        for i in 0..24u64 {
            tree.insert(key(i), value(i));
        }
        let held = key(7_777);
        advance_through(
            tree,
            held,
            &[
                vec![(key(1), Some(value(901)))],
                vec![(held, Some(value(7_777))), (key(2), Some(value(902)))],
                vec![
                    (key(3), None),
                    (held, Some(value(7_778))),
                    (key(4_000), Some(value(4))),
                ],
                vec![(key(5), Some(value(905)))],
            ],
        );
    }

    /// Many writes in one set, on both sides of the held key at many depths.
    #[test]
    fn many_writes_in_one_set_advance_the_held_path() {
        let mut tree = EconomicSmt::new();
        for i in 0..64u64 {
            tree.insert(key(i), value(i));
        }
        let writes: Vec<_> = (0..30u64)
            .map(|i| match i % 3 {
                0 => (key(i), None),
                1 => (key(i), Some(value(2_000 + i))),
                _ => (key(3_000 + i), Some(value(i))),
            })
            .collect();
        advance_through(tree, key(31), &[writes]);
    }

    /// One corrupted sibling in a write set's entry is refused, never
    /// advanced past. The control: the same write set, intact, advances.
    #[test]
    fn a_corrupted_write_set_sibling_is_refused() {
        let mut tree = EconomicSmt::new();
        for i in 0..32u64 {
            tree.insert(key(i), value(i));
        }
        let held = key(4);
        let pre_root = tree.root();
        let mut entries = write_set(&tree, &[(key(9), Some(value(909))), (key(17), None)]);
        let post_root = verify_batch(&pre_root, &entries).unwrap();
        let path = tree.siblings(&held);
        let held_value = tree.get(&held).copied();
        let intact = advance_path(
            &pre_root,
            &post_root,
            &entries,
            &held,
            held_value.as_ref(),
            &path,
        )
        .expect("the intact write set advances the held path");
        assert_eq!(intact.value, held_value);
        for at in [0usize, 128, ECONOMIC_SMT_HEIGHT - 1] {
            let original = entries[0].path[at];
            entries[0].path[at][3] ^= 0x40;
            let refused = advance_path(
                &pre_root,
                &post_root,
                &entries,
                &held,
                held_value.as_ref(),
                &path,
            )
            .expect_err("a corrupted sibling is refused");
            assert!(matches!(
                refused,
                AdvanceError::Fold(
                    FoldError::InconsistentPath { .. } | FoldError::PreRootMismatch { .. }
                )
            ));
            entries[0].path[at] = original;
        }
    }

    /// A held path that is not under the pre-root, a write set whose pre-value
    /// at the held key is not the held one, and a post-root the write set does
    /// not reach are each refused.
    #[test]
    fn an_advance_off_its_roots_is_refused() {
        let mut tree = EconomicSmt::new();
        for i in 0..16u64 {
            tree.insert(key(i), value(i));
        }
        let held = key(6);
        let pre_root = tree.root();
        let path = tree.siblings(&held);
        let entries = write_set(&tree, &[(held, Some(value(606))), (key(1), None)]);
        let post_root = verify_batch(&pre_root, &entries).unwrap();
        let held_value = value(6);
        assert_eq!(
            advance_path(&pre_root, &post_root, &entries, &held, None, &path),
            Err(AdvanceError::NotUnderPreRoot)
        );
        let mut lying = entries.clone();
        let mine = lying.iter_mut().find(|e| e.key == held).unwrap();
        mine.pre = Some(value(66));
        // The lying pre-value is not the tree's, so the write set is no
        // longer one tree's worth of paths under the pre-root.
        let refused = advance_path(
            &pre_root,
            &post_root,
            &lying,
            &held,
            Some(&held_value),
            &path,
        )
        .expect_err("a write set that lies about the held leaf is refused");
        assert!(matches!(refused, AdvanceError::Fold(..)));
        assert_eq!(
            advance_path(
                &pre_root,
                &pre_root,
                &entries,
                &held,
                Some(&held_value),
                &path
            ),
            Err(AdvanceError::NotUnderPostRoot)
        );
        let advanced = advance_path(
            &pre_root,
            &post_root,
            &entries,
            &held,
            Some(&held_value),
            &path,
        )
        .expect("the honest advance");
        assert_eq!(advanced.value, Some(value(606)));
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
