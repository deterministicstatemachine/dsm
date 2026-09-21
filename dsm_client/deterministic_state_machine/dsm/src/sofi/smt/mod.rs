// SPDX-License-Identifier: Apache-2.0
//! The verifier's side of the DLV tree: one batch fold.
//!
//! Semantics are exactly [`crate::economic::tree`]'s: 256-bit keys, the
//! key-bound `econ_leaf`, `econ_node`, and the all-zero absent leaf. A core
//! states every entry's path against ONE root, and [`fold`] turns them into
//! the post-root without holding the tree at all.
//!
//! WHAT WAS HERE AND WHY IT IS GONE. A persistent content-addressed node
//! store — `apply`, `commit_shadow`, `prove`, `get`, `verify`, `reachable`,
//! `collect_garbage`, a `NodeStore` trait and a SQLite implementation — sat
//! beside this, sharing structure between a vault's successor shadows. Every
//! line of it was dark: its own module doc said so, and the reachability gate
//! only disagreed because it matched names like `get` and `verify` against
//! unrelated functions elsewhere in the workspace.
//!
//! Owner ruling, spec §44.4: replace the responsibility, not the dead
//! implementation. The vault head past its genesis needs the leaf PREIMAGES a
//! later acquisition consumes — a `VaultStateLeaf`, a relationship leaf — and
//! a node store returns leaf VALUES, so wiring it would not have made one
//! past-genesis trade work. The persistent vault head and evidence store that
//! replaces it records the post state a resolved transition selected; it
//! decides no canonicality, because `advance_resolved` already did.
pub mod fold;

pub use fold::{batch_fold, verify_batch, FoldEntry, FoldError, Folded};
