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
//! The trader operation from its wire objects to its resolution: the field
//! tables and strict codecs ([`wire`]), domain-separated keys and identities
//! ([`derive`]), the seeded permutation that routes a cell over the committed
//! set ([`fisher_yates`]), the storage facts for objects and indexes
//! ([`storage`]), what a producer publishes and how a reader recognizes it
//! ([`publication`]), the position pair ([`registration`]), the exercise
//! ([`exercise`]), signatures ([`signature`]), the binary predicates
//! `FulfillmentConformance` ([`conformance`]) and `RouteValidation`
//! ([`validation`]), the facts and the resolution ladder ([`facts`],
//! [`resolution`]), the verifier over the SDK's reads ([`resolve`]), the join
//! to the economic lineage ([`lineage`]), escrow and computed escrow vaults
//! ([`escrow`], [`computed`]), the owner baseline and vault history
//! ([`frontier`], [`history`]), beta admission ([`admission`]) and the batch
//! fold ([`smt`]).
//!
//! ## What it is not
//!
//! It does no I/O: the SDK answers its reads. Storage members never evaluate
//! economics.

pub mod admission;
pub mod computed;
pub mod conformance;
pub mod derive;
pub mod escrow;
pub mod exercise;
pub mod facts;
pub mod fisher_yates;
pub mod frontier;
pub mod history;
pub mod lineage;
pub mod publication;
pub mod registration;
pub mod resolution;
pub mod resolve;
pub mod signature;
pub mod smt;
pub mod storage;
pub mod validation;
pub mod wire;
