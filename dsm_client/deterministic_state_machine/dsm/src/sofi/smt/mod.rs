// SPDX-License-Identifier: Apache-2.0

//! The persistent DLV tree: `R_n = Root(SMT(V_n))`, with structural sharing.
//!
//! Semantics are exactly [`crate::economic::tree`]'s: 256-bit keys, the
//! key-bound `econ_leaf`, `econ_node`, and the all-zero absent leaf. A root
//! computed here equals [`crate::economic::tree::EconomicSmt::root`] over the
//! same leaves, and a proof here is the sibling path
//! [`crate::economic::tree::root_from_path`] already verifies.
//!
//! What changes is representation. `EconomicSmt` is an in-memory map rehashed on
//! every call. This tree is a set of immutable, content-addressed nodes: applying
//! a batch of mutations to a root materializes only the changed paths and reuses
//! every other node, so each trader's full successor shadow of the same DLV
//! parent costs a handful of nodes rather than a copy of the vault
//! ([`tree::apply`]). Nodes and the pin that keeps a root alive are committed
//! together ([`store::NodeStore::commit`]), which takes the builder's opaque
//! [`tree::Shadow`] because no check over a loose node graph could establish
//! that it is canonical; collection keeps what pinned roots reach
//! ([`tree::collect_garbage`]).
//!
//! Dark: nothing in the node, the SDK or the state machine calls it yet.

pub mod node;
pub mod store;
pub mod tree;

pub use node::Node;
pub use store::{validate_staged_frontier, MemoryNodeStore, NodeStore};
pub use tree::{
    apply, collect_garbage, commit_shadow, get, prove, reachable, verify, Mutation, Proof, Shadow,
};

/// Why a tree operation could not complete. None of these is a statement about
/// economic validity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SmtError {
    /// A node a root refers to is not in the store.
    MissingNode,
    /// Stored bytes do not hash to the address they are stored under, or a node
    /// sits at a height its kind cannot occupy.
    CorruptNode { reason: &'static str },
    /// Bytes are not a canonical node encoding.
    MalformedNode { reason: &'static str },
    /// A second, different node claims an address already stored.
    ConflictingNode,
    /// One batch mutates one key twice. A write set names each key once; the
    /// tree never picks a winner.
    DuplicateMutationKey,
    /// An unpin for a root that holds no pin.
    NotPinned,
    /// The durable backend failed.
    Store(String),
}

impl core::fmt::Display for SmtError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::MissingNode => write!(f, "a node the root refers to is not stored"),
            Self::CorruptNode { reason } => write!(f, "corrupt node: {reason}"),
            Self::MalformedNode { reason } => write!(f, "malformed node: {reason}"),
            Self::ConflictingNode => write!(f, "a different node is stored at this address"),
            Self::DuplicateMutationKey => write!(f, "a mutation batch names one key twice"),
            Self::NotPinned => write!(f, "the root holds no pin"),
            Self::Store(e) => write!(f, "node store: {e}"),
        }
    }
}

impl std::error::Error for SmtError {}
