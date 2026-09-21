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
//! ([`derive`]), the seeded permutation ([`fisher_yates`]) and the leader of
//! a cell over the committed set ([`leader`]), successor-cell
//! arithmetic ([`arith`]), the storage facts for objects and indexes
//! ([`storage`]), three-valued validation composition and the mechanical
//! fulfillment-against-precommit checks ([`conformance`]), what a producer
//! publishes and how a reader recognizes it ([`publication`]), the exercise
//! boundary derived from the two position cells ([`registration`]), the
//! exercise object and what counts at a successor key ([`exercise`]), and the
//! persistent DLV tree with structurally shared shadows ([`smt`]).
//!
//! ## What it is not
//!
//! Dark. Nothing in the node, the SDK or the state machine calls it yet, and
//! nothing here evaluates DLV policy, balances, canonicality or storage
//! finality — those are later phases. Storage members never evaluate
//! economics; this layer gives them exact bytes and exact keys, nothing more.

pub mod admission;
pub mod arith;
pub mod conformance;
pub mod derive;
pub mod exercise;
pub mod fisher_yates;
pub mod leader;
pub mod lineage;
pub mod publication;
pub mod registration;
pub mod resolution;
pub mod signature;
pub mod smt;
pub mod storage;
pub mod validation;
pub mod wire;
