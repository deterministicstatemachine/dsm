// SPDX-License-Identifier: Apache-2.0

//! Canonical nodes of the persistent DLV tree, and their addresses.
//!
//! A node's address IS its Merkle value in the `R_econ` tree
//! ([`crate::economic::tree`]): there is no second hash and no second domain.
//! Two node kinds are stored; an empty subtree is never stored, because its
//! value is the key-independent default for its height.
//!
//! ```text
//! Internal  0x01 ‖ left(32) ‖ right(32)                        65 bytes
//! Single    0x02 ‖ u16_be(height) ‖ key(32) ‖ value(32)          67 bytes
//! ```
//!
//! `Internal` is a subtree holding two or more leaves; its address is
//! `econ_node(left, right)`. `Single` is a subtree of the given height holding
//! exactly one leaf; its address is that leaf folded up to the height against
//! default siblings, which is exactly what the full 256-deep tree computes for
//! it. Without `Single`, one leaf would cost 256 stored nodes.
//!
//! Decoding is strict, and [`Node::decode_at`] refuses bytes whose recomputed
//! address differs from the one they were stored under.

use crate::economic::tree::{default_node, econ_leaf, econ_node, ECONOMIC_SMT_HEIGHT};
use crate::merkle::sparse_merkle_tree::get_bit;

use super::SmtError;

pub const NODE_KIND_INTERNAL: u8 = 0x01;
pub const NODE_KIND_SINGLE: u8 = 0x02;
pub const INTERNAL_NODE_LEN: usize = 65;
pub const SINGLE_NODE_LEN: usize = 67;

/// A stored node. Its height is known from where it is reached; `Single`
/// also carries it, so a record is verifiable on its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Node {
    Internal {
        left: [u8; 32],
        right: [u8; 32],
    },
    Single {
        height: u16,
        key: [u8; 32],
        value: [u8; 32],
    },
}

/// The key bit a node of height `height` (1..=256) splits its leaves on.
pub(crate) fn split_bit(height: usize) -> usize {
    ECONOMIC_SMT_HEIGHT - height
}

/// The value of a subtree of `height` holding exactly one leaf.
pub fn single_subtree_hash(height: usize, key: &[u8; 32], value: &[u8; 32]) -> [u8; 32] {
    let mut current = econ_leaf(key, value);
    for h in 1..=height {
        let sibling = default_node(h - 1);
        current = if get_bit(key, split_bit(h)) == 0 {
            econ_node(&current, &sibling)
        } else {
            econ_node(&sibling, &current)
        };
    }
    current
}

impl Node {
    /// The node's address: its Merkle value.
    pub fn address(&self) -> [u8; 32] {
        match self {
            Node::Internal { left, right } => econ_node(left, right),
            Node::Single { height, key, value } => {
                single_subtree_hash(usize::from(*height), key, value)
            }
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        match self {
            Node::Internal { left, right } => {
                let mut out = Vec::with_capacity(INTERNAL_NODE_LEN);
                out.push(NODE_KIND_INTERNAL);
                out.extend_from_slice(left);
                out.extend_from_slice(right);
                out
            }
            Node::Single { height, key, value } => {
                let mut out = Vec::with_capacity(SINGLE_NODE_LEN);
                out.push(NODE_KIND_SINGLE);
                out.extend_from_slice(&height.to_be_bytes());
                out.extend_from_slice(key);
                out.extend_from_slice(value);
                out
            }
        }
    }

    /// Strict decode: known kind, exact length, height within the tree.
    pub fn decode(bytes: &[u8]) -> Result<Node, SmtError> {
        let fixed = |b: &[u8]| -> [u8; 32] {
            let mut a = [0u8; 32];
            a.copy_from_slice(b);
            a
        };
        match bytes.first().copied() {
            Some(NODE_KIND_INTERNAL) if bytes.len() == INTERNAL_NODE_LEN => Ok(Node::Internal {
                left: fixed(&bytes[1..33]),
                right: fixed(&bytes[33..65]),
            }),
            Some(NODE_KIND_SINGLE) if bytes.len() == SINGLE_NODE_LEN => {
                let height = u16::from_be_bytes([bytes[1], bytes[2]]);
                if usize::from(height) > ECONOMIC_SMT_HEIGHT {
                    return Err(SmtError::MalformedNode {
                        reason: "single-leaf node height exceeds the tree",
                    });
                }
                Ok(Node::Single {
                    height,
                    key: fixed(&bytes[3..35]),
                    value: fixed(&bytes[35..67]),
                })
            }
            Some(NODE_KIND_INTERNAL) | Some(NODE_KIND_SINGLE) => Err(SmtError::MalformedNode {
                reason: "node length does not match its kind",
            }),
            _ => Err(SmtError::MalformedNode {
                reason: "unknown node kind",
            }),
        }
    }

    /// Decode bytes stored under `address`, refusing them unless they hash to it.
    pub fn decode_at(address: &[u8; 32], bytes: &[u8]) -> Result<Node, SmtError> {
        let node = Node::decode(bytes)?;
        if node.address() != *address {
            return Err(SmtError::CorruptNode {
                reason: "stored node does not hash to its address",
            });
        }
        Ok(node)
    }
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)] // test asserts; a failure here is the signal
mod tests {
    use super::*;
    use crate::economic::tree::EconomicSmt;

    #[test]
    fn single_at_the_root_is_the_one_leaf_tree_root() {
        let key = [0x5A; 32];
        let value = [0x17; 32];
        let mut reference = EconomicSmt::new();
        reference.insert(key, value);
        let node = Node::Single {
            height: 256,
            key,
            value,
        };
        assert_eq!(node.address(), reference.root());
    }

    #[test]
    fn encoding_round_trips_both_kinds() {
        for node in [
            Node::Internal {
                left: [1; 32],
                right: [2; 32],
            },
            Node::Single {
                height: 17,
                key: [3; 32],
                value: [4; 32],
            },
        ] {
            let bytes = node.encode();
            assert_eq!(Node::decode(&bytes).unwrap(), node);
            assert_eq!(Node::decode_at(&node.address(), &bytes).unwrap(), node);
        }
    }

    #[test]
    fn decode_refuses_malformed_bytes() {
        let single = Node::Single {
            height: 3,
            key: [9; 32],
            value: [8; 32],
        }
        .encode();
        assert!(Node::decode(&single[..66]).is_err(), "truncated");
        let mut long = single.clone();
        long.push(0);
        assert!(Node::decode(&long).is_err(), "trailing byte");
        let mut kind = single.clone();
        kind[0] = 0x03;
        assert!(Node::decode(&kind).is_err(), "unknown kind");
        let mut high = single;
        high[1..3].copy_from_slice(&257u16.to_be_bytes());
        assert!(Node::decode(&high).is_err(), "height above the tree");
    }

    #[test]
    fn decode_at_refuses_bytes_under_the_wrong_address() {
        let node = Node::Single {
            height: 40,
            key: [0x21; 32],
            value: [0x42; 32],
        };
        let other = Node::Single {
            height: 41,
            key: [0x21; 32],
            value: [0x42; 32],
        };
        assert!(matches!(
            Node::decode_at(&other.address(), &node.encode()),
            Err(SmtError::CorruptNode { .. })
        ));
    }
}
