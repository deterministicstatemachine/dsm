// SPDX-License-Identifier: MIT OR Apache-2.0

//! Production verification namespace for DSM.
//!
//! Issue #162 cleanup: this module is the single home for **runtime**
//! verification used by the protocol — receipt verification, over the one
//! relationship path `merkle::sparse_merkle_tree::verify_smt_replace` checks.
//! Property-test / invariant-checking
//! scaffolding that used to live alongside production code at the top level
//! has moved to [`formal_infra`] so the two concerns no longer share a
//! namespace.
//!
//! Quick map:
//!
//! | Submodule                  | Purpose                                          |
//! |----------------------------|--------------------------------------------------|
//! | [`receipt_verification`]   | Stitched-receipt acceptance (§4.3, §11.1)        |
//! | [`formal_infra`]           | Proptest / invariant scaffolding (non-runtime)   |

pub mod formal_infra;
pub mod receipt_verification;
