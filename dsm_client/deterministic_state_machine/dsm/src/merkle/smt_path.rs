// SPDX-License-Identifier: Apache-2.0

//! The one wire form of a 256-level sparse Merkle authentication path.
//!
//! Most of a path is the tree's own empty subtrees: a sibling that is the
//! default node for its height tells a verifier nothing it does not already
//! know. So a path is sent as the set of heights whose sibling is NOT the
//! default there, and those siblings, lowest height first. Decoding puts the
//! default back at every other height and yields exactly the full path the
//! fold consumes ([`crate::merkle::batch_fold`]); verification is unchanged.
//!
//! There is one encoding and it is canonical, so a path has exactly one:
//! - the height set is exactly 256 bits, MSB-first like a key;
//! - the siblings are exactly 32 bytes for each height the set names, and
//!   nothing else;
//! - a sibling equal to the default at its height is never carried — it must
//!   be left out, so carrying it is refused.

use super::batch_fold::{SmtHashes, FOLD_HEIGHT};
use super::sparse_merkle_tree::get_bit;

/// Bytes of the height set: one bit per height.
pub const HEIGHT_SET_BYTES: usize = FOLD_HEIGHT / 8;

/// A path in its one wire form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncodedPath {
    /// Bit `i` (MSB-first) is set exactly when the sibling at height `i` is
    /// not the tree's default at that height.
    pub explicit_heights: [u8; HEIGHT_SET_BYTES],
    /// Those siblings, lowest height first, 32 bytes each.
    pub siblings: Vec<u8>,
}

/// Why bytes are not a path in its one wire form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathError {
    /// The height set is not exactly [`HEIGHT_SET_BYTES`] bytes.
    HeightSetLength { got: usize },
    /// The siblings are not exactly 32 bytes for each height the set names.
    SiblingBytes { named: usize, got: usize },
    /// A carried sibling is the default at its height; the one encoding
    /// leaves it out.
    DefaultCarried { height: usize },
}

impl core::fmt::Display for PathError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::HeightSetLength { got } => write!(
                f,
                "a path's height set is {HEIGHT_SET_BYTES} bytes, not {got}"
            ),
            Self::SiblingBytes { named, got } => write!(
                f,
                "a path whose height set names {named} siblings carries {} bytes of them, not {got}",
                named * 32
            ),
            Self::DefaultCarried { height } => write!(
                f,
                "the sibling at height {height} is the tree's default there and is carried; \
                 the one encoding leaves it out"
            ),
        }
    }
}

impl std::error::Error for PathError {}

fn is_set(heights: &[u8; HEIGHT_SET_BYTES], height: usize) -> bool {
    get_bit(heights, height) == 1
}

/// Encode a full leaf-to-root path of tree `H` in its one wire form.
pub fn encode<H: SmtHashes>(path: &[[u8; 32]; FOLD_HEIGHT]) -> EncodedPath {
    let mut explicit_heights = [0u8; HEIGHT_SET_BYTES];
    let mut siblings = Vec::new();
    for (height, sibling) in path.iter().enumerate() {
        if *sibling != H::default_node(height) {
            explicit_heights[height / 8] |= 1 << (7 - height % 8);
            siblings.extend_from_slice(sibling);
        }
    }
    EncodedPath {
        explicit_heights,
        siblings,
    }
}

/// Decode a path of tree `H` from its wire parts into the full leaf-to-root
/// path, refusing every form that is not the one encoding.
pub fn decode<H: SmtHashes>(
    explicit_heights: &[u8],
    siblings: &[u8],
) -> Result<Box<[[u8; 32]; FOLD_HEIGHT]>, PathError> {
    let heights: &[u8; HEIGHT_SET_BYTES] =
        explicit_heights
            .try_into()
            .map_err(|_| PathError::HeightSetLength {
                got: explicit_heights.len(),
            })?;
    let named: Vec<usize> = (0..FOLD_HEIGHT).filter(|&h| is_set(heights, h)).collect();
    let (carried, rest) = siblings.as_chunks::<32>();
    if !rest.is_empty() || carried.len() != named.len() {
        return Err(PathError::SiblingBytes {
            named: named.len(),
            got: siblings.len(),
        });
    }
    if let Some((&height, _)) = named
        .iter()
        .zip(carried)
        .find(|(&height, sibling)| **sibling == H::default_node(height))
    {
        return Err(PathError::DefaultCarried { height });
    }
    let mut next = 0;
    Ok(Box::new(std::array::from_fn(|height| {
        if is_set(heights, height) {
            let sibling = carried[next];
            next += 1;
            sibling
        } else {
            H::default_node(height)
        }
    })))
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)] // test asserts; a failure here is the signal
mod tests {
    use super::*;
    use crate::economic::tree::EconomicSmt;
    use crate::merkle::batch_fold::{verify_batch, FoldEntry};
    use crate::merkle::sparse_merkle_tree::{DeviceSmtHashes, SparseMerkleTree};
    use crate::sofi::smt::fold::EconomicHashes;

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

    fn device_tree(n: u64) -> SparseMerkleTree {
        SparseMerkleTree::from_leaves((0..n).map(|i| (key(i), key(i + 10_000))))
    }

    fn device_path(tree: &SparseMerkleTree, k: &[u8; 32]) -> Box<[[u8; 32]; FOLD_HEIGHT]> {
        let siblings = tree.get_inclusion_proof(k, 256).unwrap().siblings;
        Box::new(siblings.try_into().unwrap())
    }

    /// A decoded path's leaf, folded, is the tree's root.
    fn folds_to_root(tree: &SparseMerkleTree, k: [u8; 32], path: Box<[[u8; 32]; FOLD_HEIGHT]>) {
        let value = tree.get_inclusion_proof(&k, 256).unwrap().value;
        let entry = FoldEntry {
            key: k,
            pre: value,
            post: value,
            path,
        };
        assert_eq!(
            verify_batch::<DeviceSmtHashes>(tree.root(), std::slice::from_ref(&entry)).unwrap(),
            *tree.root()
        );
    }

    #[test]
    fn a_device_path_decodes_to_itself_and_folds_to_the_root() {
        let tree = device_tree(40);
        for k in [key(3), key(31), key(90_000)] {
            let full = device_path(&tree, &k);
            let encoded = encode::<DeviceSmtHashes>(&full);
            let decoded =
                decode::<DeviceSmtHashes>(&encoded.explicit_heights, &encoded.siblings).unwrap();
            assert_eq!(decoded, full);
            folds_to_root(&tree, k, decoded);
        }
    }

    #[test]
    fn an_economic_path_decodes_to_itself() {
        let mut tree = EconomicSmt::new();
        for i in 0..40u64 {
            tree.insert(key(i), key(i + 10_000));
        }
        for k in [key(5), key(70_000)] {
            let full = Box::new(tree.siblings(&k));
            let encoded = encode::<EconomicHashes>(&full);
            assert_eq!(
                decode::<EconomicHashes>(&encoded.explicit_heights, &encoded.siblings).unwrap(),
                full
            );
        }
    }

    /// Only the heights where the keys actually diverge carry a sibling: a
    /// path in a 40-leaf tree carries a handful, not 256.
    #[test]
    fn a_path_carries_only_the_siblings_the_tree_does_not_default() {
        let tree = device_tree(40);
        let full = device_path(&tree, &key(3));
        let encoded = encode::<DeviceSmtHashes>(&full);
        let carried = encoded.siblings.len() / 32;
        let not_default = (0..FOLD_HEIGHT)
            .filter(|&h| full[h] != DeviceSmtHashes::default_node(h))
            .count();
        assert_eq!(carried, not_default);
        assert!(carried < 16, "{carried}");
    }

    #[test]
    fn an_empty_trees_path_carries_nothing() {
        let tree = SparseMerkleTree::new();
        let encoded = encode::<DeviceSmtHashes>(&device_path(&tree, &key(1)));
        assert_eq!(encoded.explicit_heights, [0u8; HEIGHT_SET_BYTES]);
        assert!(encoded.siblings.is_empty());
    }

    #[test]
    fn a_height_set_of_any_other_length_is_refused() {
        let tree = device_tree(8);
        let encoded = encode::<DeviceSmtHashes>(&device_path(&tree, &key(2)));
        for len in [0, HEIGHT_SET_BYTES - 1, HEIGHT_SET_BYTES + 1] {
            let mut heights = encoded.explicit_heights.to_vec();
            heights.resize(len, 0);
            assert_eq!(
                decode::<DeviceSmtHashes>(&heights, &encoded.siblings),
                Err(PathError::HeightSetLength { got: len })
            );
        }
    }

    #[test]
    fn truncated_or_trailing_sibling_bytes_are_refused() {
        let tree = device_tree(8);
        let encoded = encode::<DeviceSmtHashes>(&device_path(&tree, &key(2)));
        let named = encoded.siblings.len() / 32;
        assert!(named > 0);
        let h = &encoded.explicit_heights;
        let s = &encoded.siblings;
        for siblings in [
            s[..s.len() - 32].to_vec(),
            s[..s.len() - 1].to_vec(),
            [s.as_slice(), &[0u8]].concat(),
            [s.as_slice(), &s[..32]].concat(),
        ] {
            assert_eq!(
                decode::<DeviceSmtHashes>(h, &siblings),
                Err(PathError::SiblingBytes {
                    named,
                    got: siblings.len()
                })
            );
        }
    }

    /// Naming one more height than the siblings carried, or one fewer, is a
    /// count mismatch.
    #[test]
    fn a_height_set_that_names_a_different_count_is_refused() {
        let tree = device_tree(8);
        let encoded = encode::<DeviceSmtHashes>(&device_path(&tree, &key(2)));
        let named = encoded.siblings.len() / 32;
        let first_unset = (0..FOLD_HEIGHT)
            .find(|&h| !is_set(&encoded.explicit_heights, h))
            .unwrap();
        let mut more = encoded.explicit_heights;
        more[first_unset / 8] |= 1 << (7 - first_unset % 8);
        assert_eq!(
            decode::<DeviceSmtHashes>(&more, &encoded.siblings),
            Err(PathError::SiblingBytes {
                named: named + 1,
                got: encoded.siblings.len()
            })
        );
    }

    /// The default at a height may not be carried, even though expanding it
    /// would give the same full path: that would be a second encoding.
    #[test]
    fn a_default_sibling_carried_is_refused() {
        let tree = device_tree(8);
        let encoded = encode::<DeviceSmtHashes>(&device_path(&tree, &key(2)));
        let height = (0..FOLD_HEIGHT)
            .find(|&h| !is_set(&encoded.explicit_heights, h))
            .unwrap();
        let mut heights = encoded.explicit_heights;
        heights[height / 8] |= 1 << (7 - height % 8);
        // Carried in its place in the lowest-height-first order.
        let before = (0..height)
            .filter(|&h| is_set(&encoded.explicit_heights, h))
            .count();
        let mut siblings = encoded.siblings.clone();
        let default = DeviceSmtHashes::default_node(height);
        siblings.splice(before * 32..before * 32, default);
        assert_eq!(
            decode::<DeviceSmtHashes>(&heights, &siblings),
            Err(PathError::DefaultCarried { height })
        );
    }

    /// A carried sibling moved to another height decodes — to a different
    /// path, which does not fold to the tree's root. A height cannot be named
    /// twice: the set has one bit for it.
    #[test]
    fn a_sibling_carried_at_another_height_folds_to_another_root() {
        let tree = device_tree(40);
        let k = key(3);
        let full = device_path(&tree, &k);
        let encoded = encode::<DeviceSmtHashes>(&full);
        let lowest = (0..FOLD_HEIGHT)
            .find(|&h| is_set(&encoded.explicit_heights, h))
            .unwrap();
        let elsewhere = (lowest + 1..FOLD_HEIGHT)
            .find(|&h| !is_set(&encoded.explicit_heights, h))
            .unwrap();
        let mut heights = encoded.explicit_heights;
        heights[lowest / 8] &= !(1 << (7 - lowest % 8));
        heights[elsewhere / 8] |= 1 << (7 - elsewhere % 8);
        let moved = decode::<DeviceSmtHashes>(&heights, &encoded.siblings).unwrap();
        assert_ne!(moved, full);
        let value = tree.get_inclusion_proof(&k, 256).unwrap().value;
        let entry = FoldEntry {
            key: k,
            pre: value,
            post: value,
            path: moved,
        };
        assert!(verify_batch::<DeviceSmtHashes>(tree.root(), &[entry]).is_err());
    }

    /// Any bit of a carried sibling flipped changes what the path folds to.
    #[test]
    fn a_mutated_sibling_folds_to_another_root() {
        let tree = device_tree(40);
        let k = key(3);
        let encoded = encode::<DeviceSmtHashes>(&device_path(&tree, &k));
        let value = tree.get_inclusion_proof(&k, 256).unwrap().value;
        for byte in (0..encoded.siblings.len()).step_by(7) {
            let mut siblings = encoded.siblings.clone();
            siblings[byte] ^= 0x01;
            let path = decode::<DeviceSmtHashes>(&encoded.explicit_heights, &siblings).unwrap();
            let entry = FoldEntry {
                key: k,
                pre: value,
                post: value,
                path,
            };
            assert!(
                verify_batch::<DeviceSmtHashes>(tree.root(), &[entry]).is_err(),
                "byte {byte}"
            );
        }
    }

    /// A decoded path under a leaf value other than the tree's is not the
    /// tree's root.
    #[test]
    fn a_path_under_another_leaf_value_is_not_the_root() {
        let tree = device_tree(40);
        let k = key(3);
        let encoded = encode::<DeviceSmtHashes>(&device_path(&tree, &k));
        let path = decode::<DeviceSmtHashes>(&encoded.explicit_heights, &encoded.siblings).unwrap();
        let other = tree.get_inclusion_proof(&key(4), 256).unwrap().value;
        let entry = FoldEntry {
            key: k,
            pre: other,
            post: other,
            path,
        };
        assert!(verify_batch::<DeviceSmtHashes>(tree.root(), &[entry]).is_err());
    }
}
