// SPDX-License-Identifier: Apache-2.0

//! Operations on the persistent tree: apply, read, prove, collect.
//!
//! ## Canonical shape
//!
//! Every leaf set has exactly one node set. An empty subtree is the default for
//! its height and is never stored; a subtree holding one leaf is a `Single` at
//! that height, never an `Internal` over a default; a subtree holding two or
//! more leaves is an `Internal`. [`apply`] restores this shape after every
//! mutation — a removal that leaves one leaf lifts it — so the same leaves reach
//! the same nodes whatever order or batching produced them.

use std::collections::HashSet;

use crate::economic::tree::{default_node, leaf_node, root_from_path, ECONOMIC_SMT_HEIGHT};
use crate::merkle::sparse_merkle_tree::get_bit;

use super::node::{single_subtree_hash, split_bit, Node};
use super::store::NodeStore;
use super::SmtError;

/// One write to one key: `Some` sets the leaf value, `None` removes the leaf.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Mutation {
    pub key: [u8; 32],
    pub value: Option<[u8; 32]>,
}

/// A successor tree built from a parent root: its root and the nodes it adds.
/// Nothing is stored until [`commit_shadow`].
///
/// **This type is the trust boundary of the whole tree.** Its fields are
/// private and only [`apply`] builds one, because canonicality of a node graph
/// cannot be re-established from the outside: `Single(h)` and an `Internal(h)`
/// over `Single(h-1)` plus a default have the same Merkle value, and a valid
/// stored subtree can be grafted under the wrong prefix. A store therefore
/// trusts the builder's product, and checks only what it can — that the staged
/// frontier is closed (see [`super::store::validate_staged_frontier`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Shadow {
    parent: [u8; 32],
    root: [u8; 32],
    new_nodes: Vec<Node>,
}

impl Shadow {
    /// The root this shadow was built from.
    pub fn parent(&self) -> [u8; 32] {
        self.parent
    }

    /// The successor root.
    pub fn root(&self) -> [u8; 32] {
        self.root
    }

    /// The nodes this shadow adds; every other node is shared with the parent.
    pub fn new_nodes(&self) -> &[Node] {
        &self.new_nodes
    }

    /// Fabricate a shadow that [`apply`] would never produce, for the store
    /// tests that prove a malformed commit input is refused with no side
    /// effects.
    ///
    /// The gate is `any(test, feature = "testing")` rather than plain `test`
    /// because the durable store lives in `dsm_sdk`, whose tests are a separate
    /// compilation unit: a `cfg(test)` seam here is invisible to them. A normal
    /// build resolves no dev-dependencies, so this stays out of every
    /// production artifact — `ci/sofi_shadow_nonforgeable.sh` proves it.
    #[cfg(any(test, feature = "testing"))]
    pub fn forge_for_tests(parent: [u8; 32], root: [u8; 32], new_nodes: Vec<Node>) -> Shadow {
        Shadow {
            parent,
            root,
            new_nodes,
        }
    }
}

/// An inclusion (`value` is `Some`) or non-inclusion (`None`) proof, as the
/// leaf-to-root sibling path [`root_from_path`] folds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proof {
    pub value: Option<[u8; 32]>,
    pub siblings: Box<[[u8; 32]; ECONOMIC_SMT_HEIGHT]>,
}

/// A subtree at a known height while a batch is applied. `Stored` is an
/// existing node not yet read.
#[derive(Debug, Clone, Copy)]
enum Sub {
    Empty,
    Stored([u8; 32]),
    Single { key: [u8; 32], value: [u8; 32] },
    Internal { left: [u8; 32], right: [u8; 32] },
}

/// An existing child by address, known empty when it is the default for its
/// height — so the canonical join sees an empty side without a store read.
fn child(height: usize, address: [u8; 32]) -> Sub {
    if address == default_node(height) {
        Sub::Empty
    } else {
        Sub::Stored(address)
    }
}

fn load<S: NodeStore + ?Sized>(
    store: &S,
    height: usize,
    address: &[u8; 32],
) -> Result<Sub, SmtError> {
    if *address == default_node(height) {
        return Ok(Sub::Empty);
    }
    match store.get_node(address)? {
        None => Err(SmtError::MissingNode),
        Some(Node::Internal { left, right }) => {
            if height == 0 {
                return Err(SmtError::CorruptNode {
                    reason: "internal node at leaf height",
                });
            }
            Ok(Sub::Internal { left, right })
        }
        Some(Node::Single {
            height: h,
            key,
            value,
        }) => {
            if usize::from(h) != height {
                return Err(SmtError::CorruptNode {
                    reason: "single-leaf node at the wrong height",
                });
            }
            Ok(Sub::Single { key, value })
        }
    }
}

struct Builder<'s, S: NodeStore + ?Sized> {
    store: &'s S,
    new_nodes: Vec<Node>,
    emitted: HashSet<[u8; 32]>,
}

impl<S: NodeStore + ?Sized> Builder<'_, S> {
    fn emit(&mut self, node: Node) -> [u8; 32] {
        let address = node.address();
        if self.emitted.insert(address) {
            self.new_nodes.push(node);
        }
        address
    }

    fn materialize(&mut self, height: usize, sub: Sub) -> Result<[u8; 32], SmtError> {
        Ok(match sub {
            Sub::Empty => default_node(height),
            Sub::Stored(address) => address,
            Sub::Single { key, value } => self.emit(Node::Single {
                height: u16::try_from(height).map_err(|_| SmtError::CorruptNode {
                    reason: "height exceeds the tree",
                })?,
                key,
                value,
            }),
            Sub::Internal { left, right } => self.emit(Node::Internal { left, right }),
        })
    }

    fn resolve(&self, height: usize, sub: Sub) -> Result<Sub, SmtError> {
        match sub {
            Sub::Stored(address) => load(self.store, height, &address),
            other => Ok(other),
        }
    }

    /// Join two children of a node at `height` into the canonical shape.
    fn combine(&mut self, height: usize, left: Sub, right: Sub) -> Result<Sub, SmtError> {
        let left = if matches!(right, Sub::Empty) {
            self.resolve(height - 1, left)?
        } else {
            left
        };
        let right = if matches!(left, Sub::Empty) {
            self.resolve(height - 1, right)?
        } else {
            right
        };
        Ok(match (left, right) {
            (Sub::Empty, Sub::Empty) => Sub::Empty,
            (Sub::Empty, Sub::Single { key, value }) | (Sub::Single { key, value }, Sub::Empty) => {
                Sub::Single { key, value }
            }
            (l, r) => {
                let left = self.materialize(height - 1, l)?;
                let right = self.materialize(height - 1, r)?;
                Sub::Internal { left, right }
            }
        })
    }

    /// The canonical subtree of `height` holding exactly `leaves` (sorted, distinct).
    fn subtree_of_leaves(
        &mut self,
        height: usize,
        leaves: &[([u8; 32], [u8; 32])],
    ) -> Result<Sub, SmtError> {
        match leaves {
            [] => Ok(Sub::Empty),
            [(key, value)] => Ok(Sub::Single {
                key: *key,
                value: *value,
            }),
            _ => {
                if height == 0 {
                    return Err(SmtError::DuplicateMutationKey);
                }
                let bit = split_bit(height);
                let split = leaves.partition_point(|(k, _)| get_bit(k, bit) == 0);
                let left = self.subtree_of_leaves(height - 1, &leaves[..split])?;
                let right = self.subtree_of_leaves(height - 1, &leaves[split..])?;
                self.combine(height, left, right)
            }
        }
    }

    /// Apply sorted, distinct mutations to `current`, a subtree of `height`.
    fn build(
        &mut self,
        height: usize,
        current: Sub,
        mutations: &[Mutation],
    ) -> Result<Sub, SmtError> {
        if mutations.is_empty() {
            return Ok(current);
        }
        match self.resolve(height, current)? {
            Sub::Empty => {
                let leaves: Vec<([u8; 32], [u8; 32])> = mutations
                    .iter()
                    .filter_map(|m| m.value.map(|v| (m.key, v)))
                    .collect();
                self.subtree_of_leaves(height, &leaves)
            }
            Sub::Single { key, value } => {
                let mut leaves: Vec<([u8; 32], [u8; 32])> = Vec::with_capacity(mutations.len() + 1);
                let mut replaced = false;
                for m in mutations {
                    replaced |= m.key == key;
                    if let Some(v) = m.value {
                        leaves.push((m.key, v));
                    }
                }
                if !replaced {
                    leaves.push((key, value));
                    leaves.sort_by_key(|leaf| leaf.0);
                }
                self.subtree_of_leaves(height, &leaves)
            }
            Sub::Internal { left, right } => {
                let bit = split_bit(height);
                let split = mutations.partition_point(|m| get_bit(&m.key, bit) == 0);
                let l = self.build(height - 1, child(height - 1, left), &mutations[..split])?;
                let r = self.build(height - 1, child(height - 1, right), &mutations[split..])?;
                self.combine(height, l, r)
            }
            Sub::Stored(_) => Err(SmtError::CorruptNode {
                reason: "unresolved subtree",
            }),
        }
    }
}

/// Build the successor of `root` under `mutations`, sharing every unchanged
/// node with it. A batch naming one key twice is refused.
pub fn apply<S: NodeStore + ?Sized>(
    store: &S,
    root: &[u8; 32],
    mutations: &[Mutation],
) -> Result<Shadow, SmtError> {
    let mut sorted = mutations.to_vec();
    sorted.sort_by_key(|m| m.key);
    if sorted.windows(2).any(|w| w[0].key == w[1].key) {
        return Err(SmtError::DuplicateMutationKey);
    }
    let mut builder = Builder {
        store,
        new_nodes: Vec::new(),
        emitted: HashSet::new(),
    };
    let sub = builder.build(ECONOMIC_SMT_HEIGHT, Sub::Stored(*root), &sorted)?;
    let new_root = builder.materialize(ECONOMIC_SMT_HEIGHT, sub)?;
    Ok(Shadow {
        parent: *root,
        root: new_root,
        new_nodes: builder.new_nodes,
    })
}

/// Persist a shadow's nodes and pin its root, atomically.
pub fn commit_shadow<S: NodeStore + ?Sized>(
    store: &mut S,
    shadow: &Shadow,
) -> Result<(), SmtError> {
    store.commit(shadow)
}

/// The leaf value at `key` under `root`.
pub fn get<S: NodeStore + ?Sized>(
    store: &S,
    root: &[u8; 32],
    key: &[u8; 32],
) -> Result<Option<[u8; 32]>, SmtError> {
    let mut height = ECONOMIC_SMT_HEIGHT;
    let mut address = *root;
    loop {
        match load(store, height, &address)? {
            Sub::Empty => return Ok(None),
            Sub::Single { key: k, value } => return Ok((k == *key).then_some(value)),
            Sub::Internal { left, right } => {
                address = if get_bit(key, split_bit(height)) == 0 {
                    left
                } else {
                    right
                };
                height -= 1;
            }
            Sub::Stored(_) => {
                return Err(SmtError::CorruptNode {
                    reason: "unresolved subtree",
                })
            }
        }
    }
}

/// An inclusion or non-inclusion proof for `key` under `root`.
pub fn prove<S: NodeStore + ?Sized>(
    store: &S,
    root: &[u8; 32],
    key: &[u8; 32],
) -> Result<Proof, SmtError> {
    let mut siblings = Box::new([[0u8; 32]; ECONOMIC_SMT_HEIGHT]);
    let mut height = ECONOMIC_SMT_HEIGHT;
    let mut address = *root;
    let mut value = None;
    loop {
        match load(store, height, &address)? {
            Sub::Empty => {
                for h in 1..=height {
                    siblings[h - 1] = default_node(h - 1);
                }
                break;
            }
            Sub::Single { key: k, value: v } => {
                if k == *key {
                    value = Some(v);
                    for h in 1..=height {
                        siblings[h - 1] = default_node(h - 1);
                    }
                } else {
                    // The one leaf here shares the path down to where the keys
                    // part; below that the proven key's side is empty.
                    for h in (1..=height).rev() {
                        let bit = split_bit(h);
                        if get_bit(&k, bit) != get_bit(key, bit) {
                            siblings[h - 1] = single_subtree_hash(h - 1, &k, &v);
                            for lower in 1..h {
                                siblings[lower - 1] = default_node(lower - 1);
                            }
                            break;
                        }
                        siblings[h - 1] = default_node(h - 1);
                    }
                }
                break;
            }
            Sub::Internal { left, right } => {
                if get_bit(key, split_bit(height)) == 0 {
                    siblings[height - 1] = right;
                    address = left;
                } else {
                    siblings[height - 1] = left;
                    address = right;
                }
                height -= 1;
            }
            Sub::Stored(_) => {
                return Err(SmtError::CorruptNode {
                    reason: "unresolved subtree",
                })
            }
        }
    }
    Ok(Proof { value, siblings })
}

/// Whether `siblings` proves `key` holds `value` (or nothing) under `root`.
pub fn verify(
    root: &[u8; 32],
    key: &[u8; 32],
    value: Option<&[u8; 32]>,
    siblings: &[[u8; 32]; ECONOMIC_SMT_HEIGHT],
) -> bool {
    root_from_path(key, &leaf_node(key, value), siblings) == *root
}

/// Every stored node reachable from `roots`. A missing node is an error, never
/// a pruned branch.
pub fn reachable<S: NodeStore + ?Sized>(
    store: &S,
    roots: &[[u8; 32]],
) -> Result<HashSet<[u8; 32]>, SmtError> {
    let mut live = HashSet::new();
    let mut stack: Vec<(usize, [u8; 32])> =
        roots.iter().map(|r| (ECONOMIC_SMT_HEIGHT, *r)).collect();
    while let Some((height, address)) = stack.pop() {
        if address == default_node(height) || live.contains(&address) {
            continue;
        }
        match store.get_node(&address)? {
            None => return Err(SmtError::MissingNode),
            Some(Node::Internal { left, right }) => {
                if height == 0 {
                    return Err(SmtError::CorruptNode {
                        reason: "internal node at leaf height",
                    });
                }
                stack.push((height - 1, left));
                stack.push((height - 1, right));
            }
            Some(Node::Single { height: h, .. }) => {
                if usize::from(h) != height {
                    return Err(SmtError::CorruptNode {
                        reason: "single-leaf node at the wrong height",
                    });
                }
            }
        }
        live.insert(address);
    }
    Ok(live)
}

/// Remove every node no pinned root reaches. Refuses — removing nothing — if a
/// pinned root is not fully stored. Returns how many nodes were removed.
pub fn collect_garbage<S: NodeStore + ?Sized>(store: &mut S) -> Result<usize, SmtError> {
    let roots = store.pinned_roots()?;
    let live = reachable(&*store, &roots)?;
    let dead: Vec<[u8; 32]> = store
        .node_addresses()?
        .into_iter()
        .filter(|a| !live.contains(a))
        .collect();
    store.remove_nodes(&dead)?;
    Ok(dead.len())
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)] // test asserts; a failure here is the signal
mod tests {
    use super::*;
    use crate::economic::tree::{empty_economic_root, EconomicSmt};
    use crate::sofi::smt::MemoryNodeStore;
    use proptest::prelude::*;

    fn set(key: [u8; 32], value: [u8; 32]) -> Mutation {
        Mutation {
            key,
            value: Some(value),
        }
    }

    fn remove(key: [u8; 32]) -> Mutation {
        Mutation { key, value: None }
    }

    /// Distinct keys with a spread of shared prefixes (xorshift, no clock).
    fn keys(n: usize, seed: u64) -> Vec<[u8; 32]> {
        let mut state = seed | 1;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let mut out: Vec<[u8; 32]> = Vec::with_capacity(n);
        while out.len() < n {
            let mut k = [0u8; 32];
            for chunk in k.chunks_mut(8) {
                chunk.copy_from_slice(&next().to_be_bytes()[..chunk.len()]);
            }
            if out.len() % 3 == 1 {
                // Share a long prefix with the previous key: deep internal chains.
                let prev = out[out.len() - 1];
                k[..29].copy_from_slice(&prev[..29]);
            }
            if !out.contains(&k) {
                out.push(k);
            }
        }
        out
    }

    fn value(i: usize) -> [u8; 32] {
        let mut v = [0u8; 32];
        v[..8].copy_from_slice(&(i as u64).to_be_bytes());
        v[31] = 0xA5;
        v
    }

    fn assert_matches_reference(
        store: &MemoryNodeStore,
        root: &[u8; 32],
        reference: &EconomicSmt,
        probes: &[[u8; 32]],
    ) {
        assert_eq!(*root, reference.root(), "root");
        for key in probes {
            assert_eq!(
                get(store, root, key).unwrap(),
                reference.get(key).copied(),
                "get"
            );
            let proof = prove(store, root, key).unwrap();
            assert_eq!(proof.value, reference.get(key).copied(), "proof value");
            assert_eq!(*proof.siblings, reference.siblings(key), "siblings");
            assert!(verify(root, key, proof.value.as_ref(), &proof.siblings));
        }
    }

    #[test]
    fn the_empty_tree_is_the_empty_economic_root() {
        let store = MemoryNodeStore::new();
        let empty = empty_economic_root();
        let shadow = apply(&store, &empty, &[]).unwrap();
        assert_eq!(shadow.root(), empty);
        assert!(shadow.new_nodes().is_empty());
        let key = [7u8; 32];
        let proof = prove(&store, &empty, &key).unwrap();
        assert_eq!(proof.value, None);
        assert!(verify(&empty, &key, None, &proof.siblings));
    }

    #[test]
    fn roots_and_proofs_equal_the_reference_tree_across_batches() {
        let ks = keys(40, 0x5EED);
        let mut store = MemoryNodeStore::new();
        let mut reference = EconomicSmt::new();
        let mut root = empty_economic_root();
        // Batch 1: insert the first 25.
        let batch: Vec<Mutation> = ks[..25]
            .iter()
            .enumerate()
            .map(|(i, k)| set(*k, value(i)))
            .collect();
        for m in &batch {
            reference.insert(m.key, m.value.unwrap());
        }
        let shadow = apply(&store, &root, &batch).unwrap();
        commit_shadow(&mut store, &shadow).unwrap();
        root = shadow.root();
        assert_matches_reference(&store, &root, &reference, &ks);
        // Batch 2: update five, remove seven, insert the rest.
        let mut batch = Vec::new();
        for (i, k) in ks[..5].iter().enumerate() {
            batch.push(set(*k, value(100 + i)));
            reference.insert(*k, value(100 + i));
        }
        for k in &ks[5..12] {
            batch.push(remove(*k));
            reference.remove(k);
        }
        for (i, k) in ks[25..].iter().enumerate() {
            batch.push(set(*k, value(200 + i)));
            reference.insert(*k, value(200 + i));
        }
        let shadow = apply(&store, &root, &batch).unwrap();
        commit_shadow(&mut store, &shadow).unwrap();
        root = shadow.root();
        assert_matches_reference(&store, &root, &reference, &ks);
    }

    #[test]
    fn removing_every_leaf_returns_the_empty_root() {
        let ks = keys(12, 0xC0FFEE);
        let mut store = MemoryNodeStore::new();
        let insert: Vec<Mutation> = ks
            .iter()
            .enumerate()
            .map(|(i, k)| set(*k, value(i)))
            .collect();
        let full = apply(&store, &empty_economic_root(), &insert).unwrap();
        commit_shadow(&mut store, &full).unwrap();
        let removals: Vec<Mutation> = ks.iter().map(|k| remove(*k)).collect();
        let emptied = apply(&store, &full.root(), &removals).unwrap();
        assert_eq!(emptied.root(), empty_economic_root());
        assert!(emptied.new_nodes().is_empty());
    }

    /// The same leaves reach the same nodes, however they were batched.
    #[test]
    fn shape_is_canonical_regardless_of_batching() {
        let ks = keys(30, 0xFACADE);
        let mut one = MemoryNodeStore::new();
        let all: Vec<Mutation> = ks
            .iter()
            .enumerate()
            .map(|(i, k)| set(*k, value(i)))
            .collect();
        let direct = apply(&one, &empty_economic_root(), &all).unwrap();
        commit_shadow(&mut one, &direct).unwrap();

        let mut many = MemoryNodeStore::new();
        let mut root = empty_economic_root();
        // Insert in reverse, one at a time, with a detour through extra leaves
        // that are then removed.
        let extra = keys(6, 0xBADD);
        let detour: Vec<Mutation> = extra.iter().map(|k| set(*k, [0xEE; 32])).collect();
        let s = apply(&many, &root, &detour).unwrap();
        commit_shadow(&mut many, &s).unwrap();
        root = s.root();
        for (i, k) in ks.iter().enumerate().rev() {
            let s = apply(&many, &root, &[set(*k, value(i))]).unwrap();
            commit_shadow(&mut many, &s).unwrap();
            root = s.root();
        }
        let undo: Vec<Mutation> = extra.iter().map(|k| remove(*k)).collect();
        let s = apply(&many, &root, &undo).unwrap();
        commit_shadow(&mut many, &s).unwrap();
        root = s.root();

        assert_eq!(root, direct.root());
        assert_eq!(
            reachable(&many, &[root]).unwrap(),
            reachable(&one, &[direct.root()]).unwrap(),
            "same leaves, same node set"
        );
    }

    /// A one-leaf shadow of a large parent adds exactly its path: the internal
    /// nodes above the leaf and the leaf's own node.
    #[test]
    fn a_shadow_shares_every_unchanged_node_with_its_parent() {
        let ks = keys(1000, 0xABCDEF);
        let mut store = MemoryNodeStore::new();
        let all: Vec<Mutation> = ks
            .iter()
            .enumerate()
            .map(|(i, k)| set(*k, value(i)))
            .collect();
        let parent = apply(&store, &empty_economic_root(), &all).unwrap();
        commit_shadow(&mut store, &parent).unwrap();
        let parent_nodes = reachable(&store, &[parent.root()]).unwrap();

        let target = ks[517];
        let mut internal_depth = 0usize;
        let mut height = ECONOMIC_SMT_HEIGHT;
        let mut address = parent.root();
        while let Some(Node::Internal { left, right }) = store.get_node(&address).unwrap() {
            internal_depth += 1;
            address = if get_bit(&target, split_bit(height)) == 0 {
                left
            } else {
                right
            };
            height -= 1;
        }

        let shadow = apply(&store, &parent.root(), &[set(target, [0x77; 32])]).unwrap();
        assert_eq!(shadow.new_nodes().len(), internal_depth + 1);
        commit_shadow(&mut store, &shadow).unwrap();
        let shadow_nodes = reachable(&store, &[shadow.root()]).unwrap();
        assert_eq!(
            shadow_nodes.difference(&parent_nodes).count(),
            internal_depth + 1
        );
        assert_eq!(parent_nodes.len(), shadow_nodes.len());
    }

    /// A removal that leaves one leaf in a subtree lifts it: the result is the
    /// node set of a tree built directly from the survivors.
    #[test]
    fn a_removal_that_leaves_one_leaf_lifts_it() {
        let a = [0x40; 32];
        let mut b = a;
        b[31] ^= 1; // a and b part only at the last bit: a 255-deep chain
        let c = [0xC0; 32];
        let mut store = MemoryNodeStore::new();
        let three = apply(
            &store,
            &empty_economic_root(),
            &[set(a, [1; 32]), set(b, [2; 32]), set(c, [3; 32])],
        )
        .unwrap();
        commit_shadow(&mut store, &three).unwrap();
        let two = apply(&store, &three.root(), &[remove(b)]).unwrap();
        commit_shadow(&mut store, &two).unwrap();

        let mut direct = MemoryNodeStore::new();
        let expected = apply(
            &direct,
            &empty_economic_root(),
            &[set(a, [1; 32]), set(c, [3; 32])],
        )
        .unwrap();
        commit_shadow(&mut direct, &expected).unwrap();

        assert_eq!(two.root(), expected.root());
        assert_eq!(
            reachable(&store, &[two.root()]).unwrap(),
            reachable(&direct, &[expected.root()]).unwrap()
        );
        assert_eq!(
            two.new_nodes().len(),
            2,
            "the root and a's lifted leaf node, nothing else"
        );
    }

    #[test]
    fn a_batch_naming_one_key_twice_is_refused() {
        let store = MemoryNodeStore::new();
        let k = [0x31; 32];
        assert_eq!(
            apply(
                &store,
                &empty_economic_root(),
                &[set(k, [1; 32]), set(k, [2; 32])]
            ),
            Err(SmtError::DuplicateMutationKey)
        );
        assert_eq!(
            apply(
                &store,
                &empty_economic_root(),
                &[set(k, [1; 32]), remove(k)]
            ),
            Err(SmtError::DuplicateMutationKey)
        );
    }

    #[test]
    fn a_tampered_proof_does_not_verify() {
        let ks = keys(20, 0x1234);
        let mut store = MemoryNodeStore::new();
        let all: Vec<Mutation> = ks
            .iter()
            .enumerate()
            .map(|(i, k)| set(*k, value(i)))
            .collect();
        let tree = apply(&store, &empty_economic_root(), &all).unwrap();
        commit_shadow(&mut store, &tree).unwrap();

        let present = ks[3];
        let proof = prove(&store, &tree.root(), &present).unwrap();
        assert!(verify(
            &tree.root(),
            &present,
            Some(&value(3)),
            &proof.siblings
        ));
        assert!(
            !verify(&tree.root(), &present, Some(&value(4)), &proof.siblings),
            "wrong value"
        );
        assert!(
            !verify(&tree.root(), &present, None, &proof.siblings),
            "claimed absent"
        );
        let mut bent = proof.siblings.clone();
        bent[255][0] ^= 1;
        assert!(
            !verify(&tree.root(), &present, Some(&value(3)), &bent),
            "bent sibling"
        );

        let absent = [0xFE; 32];
        let proof = prove(&store, &tree.root(), &absent).unwrap();
        assert_eq!(proof.value, None);
        assert!(verify(&tree.root(), &absent, None, &proof.siblings));
        assert!(!verify(
            &tree.root(),
            &absent,
            Some(&[0u8; 32]),
            &proof.siblings
        ));
    }

    /// Collection removes exactly what no pinned root reaches.
    #[test]
    fn collection_keeps_pinned_roots_and_removes_the_rest() {
        let ks = keys(200, 0x777);
        let mut store = MemoryNodeStore::new();
        let all: Vec<Mutation> = ks
            .iter()
            .enumerate()
            .map(|(i, k)| set(*k, value(i)))
            .collect();
        let parent = apply(&store, &empty_economic_root(), &all).unwrap();
        commit_shadow(&mut store, &parent).unwrap();
        let shadow = apply(
            &store,
            &parent.root(),
            &[set(ks[9], [0x55; 32]), remove(ks[10])],
        )
        .unwrap();
        commit_shadow(&mut store, &shadow).unwrap();

        let parent_nodes = reachable(&store, &[parent.root()]).unwrap();
        let shadow_only = reachable(&store, &[shadow.root()])
            .unwrap()
            .difference(&parent_nodes)
            .count();
        assert!(shadow_only > 0);

        store.unpin(&shadow.root()).unwrap();
        assert_eq!(collect_garbage(&mut store).unwrap(), shadow_only);
        assert_eq!(store.node_count(), parent_nodes.len());
        for (i, k) in ks.iter().enumerate() {
            let proof = prove(&store, &parent.root(), k).unwrap();
            assert!(verify(&parent.root(), k, Some(&value(i)), &proof.siblings));
        }
        assert_eq!(
            get(&store, &shadow.root(), &ks[9]),
            Err(SmtError::MissingNode)
        );

        store.unpin(&parent.root()).unwrap();
        assert_eq!(collect_garbage(&mut store).unwrap(), parent_nodes.len());
        assert_eq!(store.node_count(), 0);
        assert_eq!(store.unpin(&parent.root()), Err(SmtError::NotPinned));
    }

    #[test]
    fn collection_refuses_when_a_pinned_root_is_incomplete() {
        let ks = keys(10, 0x99);
        let mut store = MemoryNodeStore::new();
        let all: Vec<Mutation> = ks
            .iter()
            .enumerate()
            .map(|(i, k)| set(*k, value(i)))
            .collect();
        let tree = apply(&store, &empty_economic_root(), &all).unwrap();
        commit_shadow(&mut store, &tree).unwrap();
        let other = apply(&store, &empty_economic_root(), &[set([0x42; 32], [1; 32])]).unwrap();
        commit_shadow(&mut store, &other).unwrap();
        // Lose one node of the pinned tree.
        let Some(Node::Internal { left, .. }) = store.get_node(&tree.root()).unwrap() else {
            panic!("a ten-leaf root is internal");
        };
        store.remove_nodes(&[left]).unwrap();
        let before = store.node_count();
        assert_eq!(collect_garbage(&mut store), Err(SmtError::MissingNode));
        assert_eq!(
            store.node_count(),
            before,
            "nothing removed, not even the other tree"
        );
    }

    fn arb_key() -> impl Strategy<Value = [u8; 32]> {
        prop_oneof![
            any::<[u8; 32]>(),
            // Keys that share 29 leading bytes: long internal chains.
            (any::<[u8; 3]>()).prop_map(|tail| {
                let mut k = [0x3C; 32];
                k[29..].copy_from_slice(&tail);
                k
            }),
        ]
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(48))]

        /// Any sequence of batches, over any keys, agrees with the reference
        /// tree after every batch — roots, values, and both proof kinds.
        #[test]
        fn every_batch_sequence_agrees_with_the_reference(
            batches in prop::collection::vec(
                prop::collection::vec((arb_key(), prop::option::of(any::<[u8; 32]>())), 0..8),
                1..5,
            ),
            probe in arb_key(),
        ) {
            let mut store = MemoryNodeStore::new();
            let mut reference = EconomicSmt::new();
            let mut root = empty_economic_root();
            let mut touched: Vec<[u8; 32]> = vec![probe];
            for batch in batches {
                let mut seen = HashSet::new();
                let muts: Vec<Mutation> = batch
                    .into_iter()
                    .filter(|(k, _)| seen.insert(*k))
                    .map(|(key, value)| Mutation { key, value })
                    .collect();
                for m in &muts {
                    match m.value {
                        Some(v) => reference.insert(m.key, v),
                        None => reference.remove(&m.key),
                    }
                    touched.push(m.key);
                }
                let shadow = apply(&store, &root, &muts).unwrap();
                commit_shadow(&mut store, &shadow).unwrap();
                root = shadow.root();
                prop_assert_eq!(root, reference.root());
                for key in &touched {
                    let proof = prove(&store, &root, key).unwrap();
                    prop_assert_eq!(proof.value, reference.get(key).copied());
                    prop_assert!(verify(&root, key, proof.value.as_ref(), &proof.siblings));
                }
            }
        }
    }
}
