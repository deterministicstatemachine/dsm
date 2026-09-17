// SPDX-License-Identifier: Apache-2.0

//! SoFi v8 — the unilateral trader operation, wire layer.
//!
//! ```text
//! TraderPrecommit P → DLVPolicyFulfillment G_1 … G_n → TraderFulfillment F
//!                   → deterministic atomic realization
//! ```
//!
//! One trader operation, not n bilateral transactions. `P` is the trader's
//! unilateral, non-economic pre-commit. Each `G_j` is deterministic evidence
//! that the operation fulfills the precommitted policy of one referenced DLV
//! parent state; it has no issuer, anyone may compute it, and it never locks a
//! parent. `F` is the trader's exercise, irreversible once registered. One
//! external commitment `E` binds every consequence.
//!
//! ## What this module is
//!
//! The byte-exact wire registry and the pure derivations: field tables and
//! strict codecs ([`wire`]), domain-separated keys and identities
//! ([`derive`]), the routing permutation ([`fisher_yates`]), successor-cell
//! arithmetic ([`arith`]), three-valued validation composition and the
//! mechanical fulfillment-against-precommit checks ([`conformance`]), and the
//! persistent DLV tree with structurally shared shadows ([`smt`]).
//!
//! ## What it is not
//!
//! Dark. Nothing in the node, the SDK or the state machine calls it yet, and
//! nothing here evaluates DLV policy, balances, canonicality or storage
//! finality — those are later phases. Storage members never evaluate
//! economics; this layer gives them exact bytes and exact keys, nothing more.

pub mod arith;
pub mod conformance;
pub mod derive;
pub mod fisher_yates;
pub mod resolution;
pub mod smt;
pub mod wire;
