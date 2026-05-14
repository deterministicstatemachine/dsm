//! Standard Merkle Device Tree utilities (non-sparse) used for π_dev proofs.
//! Leaves are 32-byte DevID values, sorted lexicographically big-endian.
//! Internal nodes are BLAKE3 hashes with domain tag TAG_DEV_MERKLE.
//! An explicit empty-root tag is used for the empty tree.

use super::domain_tags::{TAG_DEV_EMPTY, TAG_DEV_LEAF, TAG_DEV_MERKLE, TAG_DEV_PAD};
use crate::crypto::blake3::dsm_domain_hasher;

/// Compute the device tree internal node hash H(L || R) with domain separation.
pub fn hash_node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = dsm_domain_hasher(TAG_DEV_MERKLE);
    hasher.update(left);
    hasher.update(right);
    let mut out = [0u8; 32];
    out.copy_from_slice(hasher.finalize().as_bytes());
    out
}

/// Compute the leaf hash for a DevID value (32 bytes), domain separated.
pub fn hash_leaf(dev_id: &[u8; 32]) -> [u8; 32] {
    let mut hasher = dsm_domain_hasher(TAG_DEV_LEAF);
    hasher.update(dev_id);
    let mut out = [0u8; 32];
    out.copy_from_slice(hasher.finalize().as_bytes());
    out
}

/// Return the canonical empty root hash for the Device Tree.
pub fn empty_root() -> [u8; 32] {
    let hasher = dsm_domain_hasher(TAG_DEV_EMPTY);
    *hasher.finalize().as_bytes()
}

/// Canonical padding leaf for odd-count Merkle levels (Issue #182
/// Finding #4 resolution). Replaces the previous self-duplication
/// pattern so that `[A, B, C]` and `[A, B, C, C]` produce distinct
/// roots. The distinct `DSM/dev-tree-pad` domain tag — separate from
/// `DSM/dev-leaf` — guarantees the pad cannot collide with any
/// legitimate `hash_leaf(devid)` value.
pub fn pad_leaf() -> [u8; 32] {
    let hasher = dsm_domain_hasher(TAG_DEV_PAD);
    *hasher.finalize().as_bytes()
}

/// Inclusion proof for a simple (non-sparse) Merkle tree.
/// Siblings are ordered from root->leaf or leaf->root depending on `leaf_to_root` flag.
#[derive(Clone, Debug)]
pub struct DevTreeProof {
    /// Sibling 32-byte hashes, walking from leaf to root (LSB index is 0)
    pub siblings: Vec<[u8; 32]>,
    /// true if `siblings` are ordered leaf->root; false if root->leaf
    pub leaf_to_root: bool,
    /// 0 = left child at this level, 1 = right child; one bit per level (LSB is leaf level)
    pub path_bits: Vec<bool>,
}

impl DevTreeProof {
    /// Verify inclusion of `dev_id` under `expected_root` using the proof.
    pub fn verify(&self, dev_id: &[u8; 32], expected_root: &[u8; 32]) -> bool {
        // Start from the leaf hash
        let mut acc = hash_leaf(dev_id);
        // Iterate levels
        let it: Box<dyn Iterator<Item = (usize, &[u8; 32])>> = if self.leaf_to_root {
            Box::new(self.siblings.iter().enumerate())
        } else {
            Box::new(self.siblings.iter().rev().enumerate())
        };
        for (i, sib) in it {
            let bit = self.path_bits.get(i).copied().unwrap_or(false);
            // bit=false => current acc is left, sib is right; bit=true => acc is right
            let (l, r) = if !bit { (&acc, sib) } else { (sib, &acc) };
            acc = hash_node(l, r);
        }
        &acc == expected_root
    }

    /// Serialize proof to bytes
    /// Format: `[num_siblings: u32][leaf_to_root: u8][path_bits_len: u32][path_bits_packed][siblings...]`
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();

        // Number of siblings
        buf.extend_from_slice(&(self.siblings.len() as u32).to_le_bytes());

        // leaf_to_root flag
        buf.push(if self.leaf_to_root { 1 } else { 0 });

        // Pack path_bits into bytes
        let mut packed_bits = vec![0u8; self.path_bits.len().div_ceil(8)];
        for (i, &bit) in self.path_bits.iter().enumerate() {
            if bit {
                packed_bits[i / 8] |= 1 << (i % 8);
            }
        }
        buf.extend_from_slice(&(self.path_bits.len() as u32).to_le_bytes());
        buf.extend_from_slice(&packed_bits);

        // Siblings (each 32 bytes)
        for sib in &self.siblings {
            buf.extend_from_slice(sib);
        }

        buf
    }

    /// Deserialize proof from bytes
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 9 {
            return None; // Need at least num_siblings(4) + flag(1) + path_bits_len(4)
        }

        let mut offset = 0;

        // Read num_siblings
        let mut num_siblings_bytes = [0u8; 4];
        num_siblings_bytes.copy_from_slice(&data[offset..offset + 4]);
        let num_siblings = u32::from_le_bytes(num_siblings_bytes) as usize;
        offset += 4;

        // Read leaf_to_root flag
        let leaf_to_root = data[offset] != 0;
        offset += 1;

        // Read path_bits length
        let mut path_bits_len_bytes = [0u8; 4];
        path_bits_len_bytes.copy_from_slice(&data[offset..offset + 4]);
        let path_bits_len = u32::from_le_bytes(path_bits_len_bytes) as usize;
        offset += 4;

        // Read packed path_bits
        let packed_len = path_bits_len.div_ceil(8);
        if offset + packed_len > data.len() {
            return None;
        }
        let packed_bits = &data[offset..offset + packed_len];
        offset += packed_len;

        let mut path_bits = Vec::with_capacity(path_bits_len);
        for i in 0..path_bits_len {
            let bit = (packed_bits[i / 8] & (1 << (i % 8))) != 0;
            path_bits.push(bit);
        }

        // Read siblings
        if offset + num_siblings * 32 != data.len() {
            return None; // Size mismatch
        }

        let mut siblings = Vec::with_capacity(num_siblings);
        for _ in 0..num_siblings {
            let mut sib = [0u8; 32];
            sib.copy_from_slice(&data[offset..offset + 32]);
            siblings.push(sib);
            offset += 32;
        }

        Some(DevTreeProof {
            siblings,
            leaf_to_root,
            path_bits,
        })
    }
}

// ---------------------------------------------------------------------------
// DeviceTree builder — standard binary Merkle tree over sorted DevIDs.
// ---------------------------------------------------------------------------

/// Device Tree builder for one genesis account (§2.2, §2.3).
///
/// Leaves are DevIDs sorted lexicographically. Root is R_G.
/// For N=0: root = empty_root()
/// For N=1: root = hash_leaf(devid) — empty proof
/// For N>1: sorted leaves, standard balanced binary Merkle construction
pub struct DeviceTree {
    /// Sorted, deduplicated leaves (DevIDs).
    leaves: Vec<[u8; 32]>,
    /// Precomputed root hash R_G.
    root: [u8; 32],
}

impl DeviceTree {
    /// Build a Device Tree from a set of DevIDs.
    pub fn new(mut device_ids: Vec<[u8; 32]>) -> Self {
        device_ids.sort();
        device_ids.dedup();
        let root = match device_ids.len() {
            0 => empty_root(),
            1 => hash_leaf(&device_ids[0]),
            _ => Self::compute_merkle_root(&device_ids),
        };
        Self {
            leaves: device_ids,
            root,
        }
    }

    /// Convenience: single-device tree (current default).
    pub fn single(dev_id: [u8; 32]) -> Self {
        Self::new(vec![dev_id])
    }

    /// Get the Device Tree root R_G.
    pub fn root(&self) -> [u8; 32] {
        self.root
    }

    /// Number of devices in the tree.
    pub fn len(&self) -> usize {
        self.leaves.len()
    }

    /// Whether the tree is empty.
    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    /// Generate an inclusion proof for `dev_id`.
    /// Returns `None` if `dev_id` is not a member of this tree.
    pub fn proof(&self, dev_id: &[u8; 32]) -> Option<DevTreeProof> {
        let idx = self.leaves.iter().position(|l| l == dev_id)?;
        if self.leaves.len() == 1 {
            // Single-device: empty proof is correct.
            // verify_device_tree_inclusion_proof_bytes() accepts this when
            // root == hash_leaf(devid).
            return Some(DevTreeProof {
                siblings: Vec::new(),
                path_bits: Vec::new(),
                leaf_to_root: true,
            });
        }
        Some(Self::build_merkle_proof(&self.leaves, idx))
    }

    // --- Private: balanced binary Merkle tree construction ---

    fn compute_merkle_root(sorted_leaves: &[[u8; 32]]) -> [u8; 32] {
        let mut level: Vec<[u8; 32]> = sorted_leaves.iter().map(hash_leaf).collect();
        while level.len() > 1 {
            let mut next = Vec::with_capacity(level.len().div_ceil(2));
            for chunk in level.chunks(2) {
                if chunk.len() == 2 {
                    next.push(hash_node(&chunk[0], &chunk[1]));
                } else {
                    // Odd promotion: pair with the canonical padding
                    // leaf (Issue #182 Finding #4) instead of duplicating
                    // the lone child. Different domain tag prevents any
                    // collision with a real DevID-derived leaf.
                    next.push(hash_node(&chunk[0], &pad_leaf()));
                }
            }
            level = next;
        }
        level[0]
    }

    fn build_merkle_proof(sorted_leaves: &[[u8; 32]], leaf_index: usize) -> DevTreeProof {
        let mut level: Vec<[u8; 32]> = sorted_leaves.iter().map(hash_leaf).collect();
        let mut siblings = Vec::new();
        let mut path_bits = Vec::new();
        let mut idx = leaf_index;

        while level.len() > 1 {
            let sib_idx = if idx.is_multiple_of(2) {
                idx + 1
            } else {
                idx - 1
            };
            let sib = if sib_idx < level.len() {
                level[sib_idx]
            } else {
                // Odd promotion at this level: sibling is the canonical
                // padding leaf, NOT the lone child duplicated.
                pad_leaf()
            };
            siblings.push(sib);
            path_bits.push(!idx.is_multiple_of(2)); // true = right child

            let mut next = Vec::with_capacity(level.len().div_ceil(2));
            for chunk in level.chunks(2) {
                if chunk.len() == 2 {
                    next.push(hash_node(&chunk[0], &chunk[1]));
                } else {
                    next.push(hash_node(&chunk[0], &pad_leaf()));
                }
            }
            level = next;
            idx /= 2;
        }

        DevTreeProof {
            siblings,
            path_bits,
            leaf_to_root: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_single_device_tree() {
        let devid = [42u8; 32];
        let tree = DeviceTree::single(devid);
        assert_eq!(tree.root(), hash_leaf(&devid));
        assert_eq!(tree.len(), 1);

        let proof = tree.proof(&devid).expect("proof for member");
        assert!(proof.siblings.is_empty());
        assert!(proof.path_bits.is_empty());
        assert!(proof.verify(&devid, &tree.root()));
    }

    #[test]
    fn test_empty_tree() {
        let tree = DeviceTree::new(vec![]);
        assert_eq!(tree.root(), empty_root());
        assert!(tree.is_empty());
    }

    #[test]
    fn test_two_device_tree() {
        let dev_a = [1u8; 32];
        let dev_b = [2u8; 32];
        let tree = DeviceTree::new(vec![dev_a, dev_b]);
        let expected_root = hash_node(&hash_leaf(&dev_a), &hash_leaf(&dev_b));
        assert_eq!(tree.root(), expected_root);
        assert_eq!(tree.len(), 2);

        let proof_a = tree.proof(&dev_a).expect("proof for dev_a");
        assert!(proof_a.verify(&dev_a, &tree.root()));

        let proof_b = tree.proof(&dev_b).expect("proof for dev_b");
        assert!(proof_b.verify(&dev_b, &tree.root()));
    }

    #[test]
    fn test_three_device_tree() {
        let dev_a = [1u8; 32];
        let dev_b = [2u8; 32];
        let dev_c = [3u8; 32];
        // Pass unsorted — constructor sorts
        let tree = DeviceTree::new(vec![dev_c, dev_a, dev_b]);
        assert_eq!(tree.len(), 3);

        for dev in &[dev_a, dev_b, dev_c] {
            let proof = tree.proof(dev).expect("proof for member");
            assert!(
                proof.verify(dev, &tree.root()),
                "proof verification failed for dev {:?}",
                &dev[..4]
            );
        }
    }

    #[test]
    fn test_dedup() {
        let dev_a = [1u8; 32];
        let tree = DeviceTree::new(vec![dev_a, dev_a, dev_a]);
        assert_eq!(tree.len(), 1);
        assert_eq!(tree.root(), hash_leaf(&dev_a));
    }

    #[test]
    fn test_nonmember_returns_none() {
        let dev_a = [1u8; 32];
        let tree = DeviceTree::single(dev_a);
        let dev_b = [2u8; 32];
        assert!(tree.proof(&dev_b).is_none());
    }

    #[test]
    fn test_proof_serialization_roundtrip() {
        let dev_a = [1u8; 32];
        let dev_b = [2u8; 32];
        let tree = DeviceTree::new(vec![dev_a, dev_b]);
        let proof = tree.proof(&dev_a).expect("proof");
        let bytes = proof.to_bytes();
        let parsed = DevTreeProof::from_bytes(&bytes).expect("parse");
        assert!(parsed.verify(&dev_a, &tree.root()));
    }

    #[test]
    fn test_four_device_tree_balanced() {
        let devs: Vec<[u8; 32]> = (0u8..4).map(|i| [i + 1; 32]).collect();
        let tree = DeviceTree::new(devs.clone());
        assert_eq!(tree.len(), 4);

        for dev in &devs {
            let proof = tree.proof(dev).expect("proof for member");
            assert!(proof.verify(dev, &tree.root()));
            // 4 leaves → 2 levels → 2 siblings
            assert_eq!(proof.siblings.len(), 2);
        }
    }

    /// Regression for Issue #182 Finding #4: odd-leaf self-duplication.
    ///
    /// Before the fix, `[A, B, C]` and `[A, B, C, C]` produced the same
    /// root because the odd-promoted leaf was hashed against itself
    /// (`hash_node(C, C)` at level 0). After the fix, the lone leaf at
    /// any odd-count level is paired with the canonical padding leaf
    /// (`pad_leaf()`) instead, which has a distinct domain tag and
    /// therefore cannot collide with any real `hash_leaf(devid)` value.
    /// This restores `(R_G, device_count)` uniqueness.
    #[test]
    fn three_device_root_differs_from_padded_four_device_root() {
        let dev_a = [1u8; 32];
        let dev_b = [2u8; 32];
        let dev_c = [3u8; 32];

        // 3-device tree using the production builder (now uses pad_leaf).
        let tree3 = DeviceTree::new(vec![dev_a, dev_b, dev_c]);

        // Synthesize the OLD-style "duplicate the lone leaf" root for
        // [A, B, C] manually, mirroring the pre-fix build:
        //   level 0: hash_leaf(A), hash_leaf(B), hash_leaf(C)
        //   level 1: hash_node(hL_A, hL_B), hash_node(hL_C, hL_C)  ← old
        //   level 2: hash_node(level1[0], level1[1])
        let h_a = hash_leaf(&dev_a);
        let h_b = hash_leaf(&dev_b);
        let h_c = hash_leaf(&dev_c);
        let n_ab = hash_node(&h_a, &h_b);
        let n_cc_old = hash_node(&h_c, &h_c);
        let root_old = hash_node(&n_ab, &n_cc_old);

        assert_ne!(
            tree3.root(),
            root_old,
            "Issue #182 Finding #4: 3-device tree root must differ from the \
             pre-fix self-duplication root for [A, B, C]"
        );

        // Also verify: the 3-device root MUST equal the canonical
        // pad-leaf construction, NOT the self-dup construction.
        let n_c_pad = hash_node(&h_c, &pad_leaf());
        let root_canonical = hash_node(&n_ab, &n_c_pad);
        assert_eq!(
            tree3.root(),
            root_canonical,
            "3-device tree root must use pad_leaf for the lone leaf"
        );

        // Inclusion proofs against the new root must verify.
        for dev in &[dev_a, dev_b, dev_c] {
            let proof = tree3.proof(dev).expect("member");
            assert!(
                proof.verify(dev, &tree3.root()),
                "post-fix proof must verify for dev {:?}",
                &dev[..4]
            );
        }
    }

    /// Pin the canonical padding-leaf value so external implementations
    /// (Lean models, second-language ports, tests in other crates) can
    /// reproduce the Device Tree root byte-exact.
    #[test]
    fn pad_leaf_is_canonical_and_distinct_from_devid_hashes() {
        // pad_leaf is deterministic.
        assert_eq!(pad_leaf(), pad_leaf());

        // pad_leaf MUST differ from hash_leaf(any DevID) — domain tag
        // separation is what makes the odd-leaf fix sound.
        let zero_devid_leaf = hash_leaf(&[0u8; 32]);
        let max_devid_leaf = hash_leaf(&[0xFF; 32]);
        let mid_devid_leaf = hash_leaf(&[0x42; 32]);
        assert_ne!(pad_leaf(), zero_devid_leaf);
        assert_ne!(pad_leaf(), max_devid_leaf);
        assert_ne!(pad_leaf(), mid_devid_leaf);
        // And distinct from the empty-tree root sentinel.
        assert_ne!(pad_leaf(), empty_root());
    }
}
