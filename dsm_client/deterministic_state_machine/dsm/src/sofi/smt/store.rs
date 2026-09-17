// SPDX-License-Identifier: Apache-2.0

//! Where nodes live, and what keeps them alive.
//!
//! A store holds content-addressed nodes and a pin count per root. The two are
//! written together: [`NodeStore::commit`] persists a new tree's nodes AND pins
//! its root in one atomic step, so there is no instant at which a root's nodes
//! exist unpinned (collectable) or its pin exists without its nodes. Garbage
//! collection keeps every node reachable from a pinned root and nothing else.
//!
//! Readers traverse immutable nodes. A reader that must survive a concurrent
//! collection pins the root it reads first.

use std::collections::{HashMap, HashSet};

use crate::economic::tree::empty_economic_root;

use super::node::Node;
use super::SmtError;

pub trait NodeStore {
    /// The node stored under `address`, verified against it.
    fn get_node(&self, address: &[u8; 32]) -> Result<Option<Node>, SmtError>;

    /// Atomically persist `nodes` (write-once by address) and add one pin to
    /// `root`. On error nothing is persisted.
    fn commit(&mut self, nodes: &[Node], root: &[u8; 32]) -> Result<(), SmtError>;

    /// Add one pin to a root whose nodes are already stored.
    fn pin(&mut self, root: &[u8; 32]) -> Result<(), SmtError>;

    /// Remove one pin. Refused for a root with no pin.
    fn unpin(&mut self, root: &[u8; 32]) -> Result<(), SmtError>;

    fn pinned_roots(&self) -> Result<Vec<[u8; 32]>, SmtError>;

    fn node_addresses(&self) -> Result<Vec<[u8; 32]>, SmtError>;

    fn remove_nodes(&mut self, addresses: &[[u8; 32]]) -> Result<(), SmtError>;
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

    fn commit(&mut self, nodes: &[Node], root: &[u8; 32]) -> Result<(), SmtError> {
        // Validate everything first: a refused commit leaves no trace.
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
        *self.pins.entry(*root).or_insert(0) += 1;
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

    fn single(height: u16, byte: u8) -> Node {
        Node::Single {
            height,
            key: [byte; 32],
            value: [byte ^ 0xFF; 32],
        }
    }

    /// A refused commit persists no node and no pin.
    #[test]
    fn a_refused_commit_leaves_no_trace() {
        let mut store = MemoryNodeStore::new();
        let a = single(10, 1);
        let b = single(10, 2);
        // A different node already sits at a's address.
        store.nodes.insert(a.address(), b);
        let root = [0x0A; 32];
        assert_eq!(
            store.commit(&[single(10, 3), a], &root),
            Err(SmtError::ConflictingNode)
        );
        assert_eq!(store.node_count(), 1);
        assert_eq!(store.pin_count(&root), 0);
        assert!(store.get_node(&single(10, 3).address()).unwrap().is_none());
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
        store.commit(&[root], &root.address()).unwrap();
        store.pin(&root.address()).unwrap();
        assert_eq!(store.pin_count(&root.address()), 2);
    }
}
