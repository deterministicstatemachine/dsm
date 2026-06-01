// SPDX-License-Identifier: MIT OR Apache-2.0

//! Core verification mechanisms for DSM state transitions.
//!
//! Whitepaper §30 dual-mode verification (bilateral + unilateral) is now
//! implemented inline in `transition::verify_transition_integrity` and
//! `state_machine::verify_state` against `DeviceState`'s SMT inclusion
//! proofs (§4.2). The standalone `DualModeVerifier` struct that took two
//! `&State` snapshots is gone — it had zero callers outside its own tests
//! and the migration to per-relationship SMT-Replace verification made
//! its array-of-State approach obsolete.
//!
//! Issue #162 split note: this `core::verification` namespace is intentionally
//! distinct from the top-level [`crate::verification`] (receipt acceptance,
//! proof primitives, SMT-replace witness). Production receipt verification
//! lives at the top level; this module hosts transition/identity helpers
//! that operate on `DeviceState`. The two trees do not overlap on the
//! protocol path.
//!
//! At the time of split, [`IdentityVerifier`] has no production callers —
//! the identity-claim path runs through bilateral relationship establishment
//! and storage-node genesis lookups. The struct is retained as a stable
//! seam for future identity-verification work; tests exercise its
//! `verify_identity_claim` API.

pub mod identity_verifier;

pub use identity_verifier::IdentityVerifier;
