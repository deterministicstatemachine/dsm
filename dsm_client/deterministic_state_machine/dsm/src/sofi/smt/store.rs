// SPDX-License-Identifier: Apache-2.0

//! Where nodes live, and what keeps them alive.
//!
//! A store holds content-addressed nodes and a pin count per root. The two are
//! written together: [`NodeStore::commit`] persists a new tree's nodes AND pins
//! its root in one atomic step, so there is no instant at which a root's nodes
//! exist unpinned (collectable) or its pin exists without its nodes. Garbage
//! collection keeps every node reachable from a pinned root and nothing else.
//!
//! A commit takes a [`Shadow`], never a loose node list: canonicality comes from
//! the builder that produced it ([`super::tree::apply`]), because no check over
//! a public node graph can establish it. What a store CAN check is that what it
//! is about to write is closed — [`validate_staged_frontier`] — which catches
//! corruption, a lost dependency, and a graft onto nodes that are not there.
//!
//! Readers traverse immutable nodes. A reader that must survive a concurrent
//! collection pins the root it reads first.

use std::collections::{HashMap, HashSet};

use crate::economic::tree::{default_node, empty_economic_root, ECONOMIC_SMT_HEIGHT};

use super::node::Node;
use super::tree::Shadow;
use super::SmtError;

pub trait NodeStore {
    /// The node stored under `address`, verified against it.
    fn get_node(&self, address: &[u8; 32]) -> Result<Option<Node>, SmtError>;

    /// Atomically persist a shadow's new nodes (write-once by address) and add
    /// one pin to its root. On error nothing is persisted.
    ///
    /// An implementation MUST call [`validate_staged_frontier`] before it
    /// writes anything.
    fn commit(&mut self, shadow: &Shadow) -> Result<(), SmtError>;

    /// Add one pin to a root whose nodes are already stored.
    fn pin(&mut self, root: &[u8; 32]) -> Result<(), SmtError>;

    /// Remove one pin. Refused for a root with no pin.
    fn unpin(&mut self, root: &[u8; 32]) -> Result<(), SmtError>;

    fn pinned_roots(&self) -> Result<Vec<[u8; 32]>, SmtError>;

    fn node_addresses(&self) -> Result<Vec<[u8; 32]>, SmtError>;

    fn remove_nodes(&mut self, addresses: &[[u8; 32]]) -> Result<(), SmtError>;
}

/// Walk what a commit is about to write, from its root down, and refuse it
/// unless every dependency is present.
///
/// This is a defence, NOT a canonicality proof — that comes from
/// [`super::tree::apply`] alone. It establishes exactly one thing: after the
/// commit, the root reaches no address the store does not hold.
///
/// The walk starts at the shadow's root at [`ECONOMIC_SMT_HEIGHT`] and, for
/// each subtree:
/// - the default for the expected height is the empty subtree, and complete;
/// - a staged node is checked at that height — a `Single` must carry exactly
///   it, an `Internal` cannot sit at height 0 — and each non-default child is
///   walked at height − 1;
/// - a non-default address that is not staged must already be stored. A stored
///   node is a trusted frontier point: the commit that stored it established
///   its own closure the same way.
///
/// So the cost is proportional to the staged structure, never to the tree. A
/// missing dependency, including the root itself, is [`SmtError::MissingNode`];
/// a node at an impossible height is [`SmtError::CorruptNode`].
pub fn validate_staged_frontier<S: NodeStore + ?Sized>(
    store: &S,
    shadow: &Shadow,
) -> Result<(), SmtError> {
    let staged: HashMap<[u8; 32], Node> = shadow
        .new_nodes()
        .iter()
        .map(|node| (node.address(), *node))
        .collect();
    let mut seen: HashSet<([u8; 32], usize)> = HashSet::new();
    let mut frontier: Vec<([u8; 32], usize)> = vec![(shadow.root(), ECONOMIC_SMT_HEIGHT)];
    while let Some((address, height)) = frontier.pop() {
        if address == default_node(height) || !seen.insert((address, height)) {
            continue;
        }
        match staged.get(&address) {
            None => {
                if store.get_node(&address)?.is_none() {
                    return Err(SmtError::MissingNode);
                }
            }
            Some(Node::Single { height: at, .. }) => {
                if usize::from(*at) != height {
                    return Err(SmtError::CorruptNode {
                        reason: "staged single-leaf node is not at the height it is reached from",
                    });
                }
            }
            Some(Node::Internal { left, right }) => {
                if height == 0 {
                    return Err(SmtError::CorruptNode {
                        reason: "staged internal node sits at leaf height",
                    });
                }
                frontier.push((*left, height - 1));
                frontier.push((*right, height - 1));
            }
        }
    }
    Ok(())
}

/// An in-memory store with the same contract as the durable one.
#[derive(Debug, Default, Clone)]
pub struct MemoryNodeStore {
    nodes: HashMap<[u8; 32], Node>,
    pins: HashMap<[u8; 32], u64>,
}

impl MemoryNodeStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    pub fn pin_count(&self, root: &[u8; 32]) -> u64 {
        self.pins.get(root).copied().unwrap_or(0)
    }
}

impl NodeStore for MemoryNodeStore {
    fn get_node(&self, address: &[u8; 32]) -> Result<Option<Node>, SmtError> {
        match self.nodes.get(address) {
            None => Ok(None),
            Some(node) => Node::decode_at(address, &node.encode()).map(Some),
        }
    }

    fn commit(&mut self, shadow: &Shadow) -> Result<(), SmtError> {
        // Validate everything first: a refused commit leaves no trace.
        validate_staged_frontier(self, shadow)?;
        let nodes = shadow.new_nodes();
        let mut staged: Vec<([u8; 32], Node)> = Vec::with_capacity(nodes.len());
        let mut seen: HashSet<[u8; 32]> = HashSet::with_capacity(nodes.len());
        for node in nodes {
            let address = node.address();
            if let Some(existing) = self.nodes.get(&address) {
                if existing != node {
                    return Err(SmtError::ConflictingNode);
                }
            } else if seen.insert(address) {
                staged.push((address, *node));
            }
        }
        for (address, node) in staged {
            self.nodes.insert(address, node);
        }
        *self.pins.entry(shadow.root()).or_insert(0) += 1;
        Ok(())
    }

    fn pin(&mut self, root: &[u8; 32]) -> Result<(), SmtError> {
        if *root != empty_economic_root() && !self.nodes.contains_key(root) {
            return Err(SmtError::MissingNode);
        }
        *self.pins.entry(*root).or_insert(0) += 1;
        Ok(())
    }

    fn unpin(&mut self, root: &[u8; 32]) -> Result<(), SmtError> {
        match self.pins.get_mut(root) {
            None => Err(SmtError::NotPinned),
            Some(count) => {
                *count -= 1;
                if *count == 0 {
                    self.pins.remove(root);
                }
                Ok(())
            }
        }
    }

    fn pinned_roots(&self) -> Result<Vec<[u8; 32]>, SmtError> {
        Ok(self.pins.keys().copied().collect())
    }

    fn node_addresses(&self) -> Result<Vec<[u8; 32]>, SmtError> {
        Ok(self.nodes.keys().copied().collect())
    }

    fn remove_nodes(&mut self, addresses: &[[u8; 32]]) -> Result<(), SmtError> {
        for address in addresses {
            self.nodes.remove(address);
        }
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)] // test asserts; a failure here is the signal
mod tests {
    use super::*;
    use crate::sofi::smt::tree::{apply, commit_shadow, Mutation};

    fn single(height: u16, byte: u8) -> Node {
        Node::Single {
            height,
            key: [byte; 32],
            value: [byte ^ 0xFF; 32],
        }
    }

    /// A key whose top bit chooses `side`, so a pair of them sits under one
    /// internal node at the root.
    fn keyed(side: u8, byte: u8) -> [u8; 32] {
        let mut k = [byte; 32];
        k[0] = if side == 0 { 0x00 } else { 0x80 };
        k
    }

    fn forge(root: [u8; 32], nodes: Vec<Node>) -> Shadow {
        Shadow::forge_for_tests(empty_economic_root(), root, nodes)
    }

    /// Two single-leaf subtrees under an internal root, and that root.
    fn pair_at(height: u16, byte: u8) -> (Node, Node, Node) {
        let left = Node::Single {
            height,
            key: keyed(0, byte),
            value: [byte; 32],
        };
        let right = Node::Single {
            height,
            key: keyed(1, byte),
            value: [byte ^ 0x0F; 32],
        };
        let root = Node::Internal {
            left: left.address(),
            right: right.address(),
        };
        (root, left, right)
    }

    /// A refused commit persists no node and no pin.
    #[test]
    fn a_refused_commit_leaves_no_trace() {
        let mut store = MemoryNodeStore::new();
        let a = single(256, 1);
        let b = single(256, 2);
        // A different node already sits at a's address.
        store.nodes.insert(a.address(), b);
        let root = single(256, 3);
        assert_eq!(
            store.commit(&forge(root.address(), vec![root, a])),
            Err(SmtError::ConflictingNode)
        );
        assert_eq!(store.node_count(), 1);
        assert_eq!(store.pin_count(&root.address()), 0);
        assert!(store.get_node(&root.address()).unwrap().is_none());
    }

    #[test]
    fn a_node_under_the_wrong_address_reads_as_corrupt() {
        let mut store = MemoryNodeStore::new();
        let a = single(20, 5);
        store.nodes.insert(a.address(), single(21, 5));
        assert!(matches!(
            store.get_node(&a.address()),
            Err(SmtError::CorruptNode { .. })
        ));
    }

    #[test]
    fn pin_requires_a_stored_root() {
        let mut store = MemoryNodeStore::new();
        assert_eq!(store.pin(&[0x42; 32]), Err(SmtError::MissingNode));
        store.pin(&empty_economic_root()).unwrap();
        let root = single(256, 9);
        store.commit(&forge(root.address(), vec![root])).unwrap();
        store.pin(&root.address()).unwrap();
        assert_eq!(store.pin_count(&root.address()), 2);
    }

    /// A root nothing reaches is refused, and nothing is written.
    #[test]
    fn a_commit_of_an_unknown_root_is_refused() {
        let mut store = MemoryNodeStore::new();
        let root = [0x5E; 32];
        assert_eq!(
            store.commit(&forge(root, Vec::new())),
            Err(SmtError::MissingNode)
        );
        assert_eq!(store.node_count(), 0);
        assert!(store.pinned_roots().unwrap().is_empty());
    }

    /// The empty root needs no node, and a root already stored needs none either.
    #[test]
    fn the_empty_root_and_an_already_stored_root_commit() {
        let mut store = MemoryNodeStore::new();
        store
            .commit(&forge(empty_economic_root(), Vec::new()))
            .unwrap();
        assert_eq!(store.node_count(), 0);
        assert_eq!(store.pin_count(&empty_economic_root()), 1);

        let built = apply(
            &store,
            &empty_economic_root(),
            &[Mutation {
                key: [0x11; 32],
                value: Some([0x22; 32]),
            }],
        )
        .unwrap();
        commit_shadow(&mut store, &built).unwrap();
        // Same root again, staging nothing: its nodes are the stored frontier.
        store.commit(&forge(built.root(), Vec::new())).unwrap();
        assert_eq!(store.pin_count(&built.root()), 2);
    }

    /// A complete staged frontier is accepted; dropping one child of the root
    /// is refused with nothing written.
    #[test]
    fn a_staged_internal_needs_both_of_its_children() {
        let (root, left, right) = pair_at(255, 0x31);

        let mut complete = MemoryNodeStore::new();
        complete
            .commit(&forge(root.address(), vec![root, left, right]))
            .unwrap();
        assert_eq!(complete.node_count(), 3);
        assert_eq!(complete.pin_count(&root.address()), 1);

        let mut partial = MemoryNodeStore::new();
        assert_eq!(
            partial.commit(&forge(root.address(), vec![root, left])),
            Err(SmtError::MissingNode)
        );
        assert_eq!(partial.node_count(), 0);
        assert!(partial.pinned_roots().unwrap().is_empty());
    }

    /// The walk is recursive: a grandchild missing under a staged child is
    /// refused too.
    #[test]
    fn a_missing_grandchild_is_refused() {
        let (inner, grandchild, missing) = pair_at(254, 0x47);
        let sibling = Node::Single {
            height: 255,
            key: keyed(1, 0x63),
            value: [0x63; 32],
        };
        let root = Node::Internal {
            left: inner.address(),
            right: sibling.address(),
        };

        let mut store = MemoryNodeStore::new();
        assert_eq!(
            store.commit(&forge(
                root.address(),
                vec![root, inner, sibling, grandchild],
            )),
            Err(SmtError::MissingNode)
        );
        assert_eq!(store.node_count(), 0);
        assert!(store.pinned_roots().unwrap().is_empty());

        // With the grandchild staged, the same frontier is closed.
        store
            .commit(&forge(
                root.address(),
                vec![root, inner, sibling, grandchild, missing],
            ))
            .unwrap();
        assert_eq!(store.node_count(), 5);
    }

    /// A staged node must carry the height it is reached from.
    #[test]
    fn a_staged_single_at_the_wrong_height_is_corrupt() {
        let mut store = MemoryNodeStore::new();
        // A leaf folded to 254 cannot be the child of the root, which is at 255.
        let shallow = Node::Single {
            height: 254,
            key: keyed(0, 0x7A),
            value: [0x7A; 32],
        };
        let right = Node::Single {
            height: 255,
            key: keyed(1, 0x7A),
            value: [0x0A; 32],
        };
        let root = Node::Internal {
            left: shallow.address(),
            right: right.address(),
        };
        assert!(matches!(
            store.commit(&forge(root.address(), vec![root, shallow, right])),
            Err(SmtError::CorruptNode { .. })
        ));
        assert_eq!(store.node_count(), 0);
        assert!(store.pinned_roots().unwrap().is_empty());
    }

    /// An internal node cannot sit where a leaf sits. Reaching height 0 takes
    /// a full 256-step descent, so the case is a chain of internals with
    /// default right siblings and the bad node at the bottom.
    #[test]
    fn a_staged_internal_at_leaf_height_is_corrupt() {
        let mut store = MemoryNodeStore::new();
        let bottom = Node::Internal {
            left: [3; 32],
            right: [4; 32],
        };
        let mut staged = vec![bottom];
        let mut node = bottom;
        for height in 1..=ECONOMIC_SMT_HEIGHT {
            node = Node::Internal {
                left: node.address(),
                right: default_node(height - 1),
            };
            staged.push(node);
        }
        assert!(matches!(
            store.commit(&forge(node.address(), staged)),
            Err(SmtError::CorruptNode { .. })
        ));
        assert_eq!(store.node_count(), 0);
        assert!(store.pinned_roots().unwrap().is_empty());
    }
}
