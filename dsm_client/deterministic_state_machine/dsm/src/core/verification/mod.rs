//! Core verification mechanisms for DSM state transitions.
//!
//! Whitepaper §30 dual-mode verification (bilateral + unilateral) is now
//! implemented inline in `transition::verify_transition_integrity` and
//! `state_machine::verify_state` against `DeviceState`'s SMT inclusion
//! proofs (§4.2). The standalone `DualModeVerifier` struct that took two
//! `&State` snapshots is gone — it had zero callers outside its own tests
//! and the migration to per-relationship SMT-Replace verification made
//! its array-of-State approach obsolete.

pub mod identity_verifier;

pub use identity_verifier::IdentityVerifier;
