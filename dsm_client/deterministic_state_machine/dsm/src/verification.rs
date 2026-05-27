//! Production verification namespace for DSM.
//!
//! Issue #162 cleanup: this module is the single home for **runtime**
//! verification used by the protocol — receipt verification, proof primitives,
//! and SMT replacement witnesses. Property-test / invariant-checking
//! scaffolding that used to live alongside production code at the top level
//! has moved to [`formal_infra`] so the two concerns no longer share a
//! namespace.
//!
//! Quick map:
//!
//! | Submodule                  | Purpose                                          |
//! |----------------------------|--------------------------------------------------|
//! | [`proof_primitives`]       | SMT inclusion / non-inclusion / device-tree proofs |
//! | [`receipt_verification`]   | Stitched-receipt acceptance (§4.3, §11.1)        |
//! | [`smt_replace_witness`]    | SMT replace witness (§6 tripwire)                |
//! | [`formal_infra`]           | Proptest / invariant scaffolding (non-runtime)   |
//!
//! Transition/identity verifiers live under [`crate::core::verification`]; the
//! two namespaces are intentionally distinct — `dsm::verification::*` is
//! consumed by the receipt acceptance pipeline, `dsm::core::verification::*`
//! is consumed by the bilateral transition machinery.

pub mod formal_infra;
pub mod proof_primitives;
pub mod receipt_verification;
pub mod smt_replace_witness;
