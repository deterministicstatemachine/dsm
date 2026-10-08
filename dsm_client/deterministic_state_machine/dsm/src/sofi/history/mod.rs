// SPDX-License-Identifier: Apache-2.0

//! A vault's history (SoFi Amendment S26).
//!
//! An append-only Merkle tree per vault whose leaf at position `g` is the
//! vault's root `R_g`, for every generation from the genesis to the head.
//! Its root `H_n` is the commitment of a [`VaultHistoryHeadV1`] — the
//! generation and the peaks of the tree — and an owner's frontier commits
//! it beside `R_n`, so an authenticated baseline authenticates every root
//! the vault ever had. A reader at a baseline proves `R_g` for any `g` below
//! it from that head alone, with a path of at most 64 nodes and typically
//! `log2(n)`, and never replays the vault's history to reach it.
//!
//! A node is fetched by its own hash: its bytes are exactly `left ‖ right`
//! under the node tag, which is also the immutable-store namespace, so the
//! store's inner digest of those bytes is the node's hash. A completed
//! subtree never changes, so every node is published once and reused by
//! every later head.

use crate::crypto::blake3::dsm_domain_hasher;
use crate::common::domain_tags::{
    TAG_DSM_SOFI_VAULT_HISTORY_HEAD, TAG_DSM_SOFI_VAULT_HISTORY_LEAF,
    TAG_DSM_SOFI_VAULT_HISTORY_LOCATOR, TAG_DSM_SOFI_VAULT_HISTORY_NODE,
};
use crate::crypto::domain::TaggedHashDomain;

use super::wire::{SofiWireError, VaultHistoryHeadV1};

type D32 = [u8; 32];

#[cfg(test)]
mod tests;

fn h(tag: TaggedHashDomain<'static>, parts: &[&[u8]]) -> D32 {
    let mut hasher = dsm_domain_hasher(tag);
    for p in parts {
        hasher.update(p);
    }
    *hasher.finalize().as_bytes()
}

/// The exact bytes of the leaf at position `generation` of `vault_id`'s
/// history: `v ‖ u64be(g) ‖ R_g`. Published under the leaf tag, so their
/// store digest is [`leaf_hash`].
pub fn leaf_bytes(vault_id: &D32, generation: u64, root: &D32) -> Vec<u8> {
    [&vault_id[..], &generation.to_be_bytes(), &root[..]].concat()
}

/// The 32 bytes at `at` of a slice whose length the caller checked.
fn d32(bytes: &[u8], at: usize) -> D32 {
    std::array::from_fn(|i| bytes[at + i])
}

/// A history leaf's bytes, read back: `(v, g, R_g)`, or `None` for bytes of
/// any other length.
pub fn decode_leaf(bytes: &[u8]) -> Option<(D32, u64, D32)> {
    if bytes.len() != 72 {
        return None;
    }
    let generation = u64::from_be_bytes(std::array::from_fn(|i| bytes[32 + i]));
    Some((d32(bytes, 0), generation, d32(bytes, 40)))
}

/// An interior node's bytes, read back: `(left, right)`, or `None` for
/// bytes of any other length.
pub fn decode_node(bytes: &[u8]) -> Option<(D32, D32)> {
    if bytes.len() != 64 {
        return None;
    }
    Some((d32(bytes, 0), d32(bytes, 32)))
}

/// `H(vault-history-leaf/v1; v ‖ u64be(g) ‖ R_g)`.
pub fn leaf_hash(vault_id: &D32, generation: u64, root: &D32) -> D32 {
    h(
        TAG_DSM_SOFI_VAULT_HISTORY_LEAF,
        &[&leaf_bytes(vault_id, generation, root)],
    )
}

/// The exact bytes of an interior node: `left ‖ right`.
pub fn node_bytes(left: &D32, right: &D32) -> Vec<u8> {
    [&left[..], &right[..]].concat()
}

/// `H(vault-history-node/v1; left ‖ right)`.
pub fn node_hash(left: &D32, right: &D32) -> D32 {
    h(TAG_DSM_SOFI_VAULT_HISTORY_NODE, &[&node_bytes(left, right)])
}

/// `H_n = H(vault-history-head/v1; CCB(VaultHistoryHeadV1))`: the history
/// root a frontier commits.
pub fn history_root(head: &VaultHistoryHeadV1) -> Result<D32, SofiWireError> {
    Ok(h(TAG_DSM_SOFI_VAULT_HISTORY_HEAD, &[&head.encode()?]))
}

/// `H(vault-history-locator/v1; v ‖ R)`: where the leaf naming root `R` of
/// vault `v` is indexed. Discovery only.
pub fn history_locator(vault_id: &D32, root: &D32) -> D32 {
    h(TAG_DSM_SOFI_VAULT_HISTORY_LOCATOR, &[vault_id, root])
}

/// A vault's history as its owner appends to it: the peaks, left to right,
/// each with its height.
#[derive(Debug, Clone)]
pub struct HistoryBuilder {
    vault_id: D32,
    leaves: u64,
    peaks: Vec<(u32, D32)>,
}

/// What appending one generation made: the leaf's bytes, and every interior
/// node it completed, each as `(hash, bytes)` — the objects a history that
/// reaches this generation is read from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Appended {
    pub leaf: Vec<u8>,
    pub nodes: Vec<(D32, Vec<u8>)>,
}

impl HistoryBuilder {
    /// An empty history of `vault_id`.
    pub fn new(vault_id: D32) -> Self {
        Self {
            vault_id,
            leaves: 0,
            peaks: Vec::new(),
        }
    }

    /// Append `R_g` at the next generation.
    pub fn append(&mut self, root: &D32) -> Appended {
        let generation = self.leaves;
        let leaf = leaf_bytes(&self.vault_id, generation, root);
        self.peaks
            .push((0, leaf_hash(&self.vault_id, generation, root)));
        self.leaves += 1;
        let mut nodes = Vec::new();
        while let [.., (left_height, left), (right_height, right)] = self.peaks[..] {
            if left_height != right_height {
                break;
            }
            let node = node_hash(&left, &right);
            nodes.push((node, node_bytes(&left, &right)));
            self.peaks.truncate(self.peaks.len() - 2);
            self.peaks.push((left_height + 1, node));
        }
        Appended { leaf, nodes }
    }

    /// The head at the last generation appended, or `None` while nothing is.
    pub fn head(&self) -> Option<VaultHistoryHeadV1> {
        let generation = self.leaves.checked_sub(1)?;
        Some(VaultHistoryHeadV1 {
            vault_id: self.vault_id,
            generation,
            peaks: self.peaks.iter().map(|(.., peak)| *peak).collect(),
        })
    }
}

/// `R_g` of a vault, proven by a path under an authenticated history head.
/// Built only by [`prove`]; a chain admits a root below its baseline only
/// as one of these.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProvenRoot {
    vault_id: D32,
    generation: u64,
    root: D32,
}

impl ProvenRoot {
    pub fn vault_id(&self) -> &D32 {
        &self.vault_id
    }
    pub fn generation(&self) -> u64 {
        self.generation
    }
    pub fn root(&self) -> &D32 {
        &self.root
    }
}

/// Why `R_g` is not proven under a head.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NotProven {
    /// The head is another vault's, or `g` is past its generation.
    OutsideTheHead,
    /// A node on the path is not in hand.
    NodeUnavailable(D32),
    /// The path does not end at the leaf `(v, g, R)`: the history holds
    /// another root at `g`.
    Contradicted,
}

/// Prove that `vault_id`'s history under `head` holds `root` at
/// `generation`, reading each node on the path from its peak down by its
/// hash through `node`. Every node read is checked against the hash it was
/// asked for, so `node` vouches for nothing.
pub fn prove<E>(
    head: &VaultHistoryHeadV1,
    vault_id: &D32,
    generation: u64,
    root: &D32,
    mut node: impl FnMut(&D32) -> Result<Option<Vec<u8>>, E>,
) -> Result<Result<ProvenRoot, NotProven>, E> {
    if head.vault_id != *vault_id || generation > head.generation {
        return Ok(Err(NotProven::OutsideTheHead));
    }
    let leaves = u128::from(head.generation) + 1;
    // The peak covering `generation`: peaks are the set bits of the leaf
    // count, highest first, each covering 2^height consecutive leaves.
    let mut start = 0u128;
    let mut peaks = head.peaks.iter();
    let mut covering = None;
    for height in (0..64u32).rev() {
        let width = 1u128 << height;
        if leaves & width == 0 {
            continue;
        }
        let Some(peak) = peaks.next() else {
            return Ok(Err(NotProven::OutsideTheHead));
        };
        if u128::from(generation) < start + width {
            covering = Some((height, *peak, u128::from(generation) - start));
            break;
        }
        start += width;
    }
    let Some((height, mut at, offset)) = covering else {
        return Ok(Err(NotProven::OutsideTheHead));
    };
    for level in (0..height).rev() {
        let Some((left, right)) = node(&at)?.as_deref().and_then(decode_node) else {
            return Ok(Err(NotProven::NodeUnavailable(at)));
        };
        if node_hash(&left, &right) != at {
            return Ok(Err(NotProven::NodeUnavailable(at)));
        }
        at = match (offset >> level) & 1 {
            0 => left,
            _ => right,
        };
    }
    if at != leaf_hash(vault_id, generation, root) {
        return Ok(Err(NotProven::Contradicted));
    }
    Ok(Ok(ProvenRoot {
        vault_id: *vault_id,
        generation,
        root: *root,
    }))
}
