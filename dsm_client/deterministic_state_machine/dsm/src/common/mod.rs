// SPDX-License-Identifier: MIT OR Apache-2.0

//! # Common Module
//!
//! Dependency-free, circular-import-safe primitives shared across DSM.
//!
//! Hard constraints (enforced here, expected system-wide):
//! - No wall-clock time (no durations, timeouts, or backoffs). All logic is tick-based and deterministic.
//! - No hex/json/base64/serde encodings for identifiers or binary values.
//! - Binary-only helpers; canonicality first.

/// Centralized canonical encoding for cryptographic commitments
pub mod canonical_encoding;
/// Deterministic ID generation (no UUID, no wall-clock)
pub mod deterministic_id;
/// Additional-device admission (§16.3 — existing device admits a new device into the tree)
pub mod device_admission;
pub mod device_tree;
/// Domain tag constants for BLAKE3 domain-separated hashing
pub mod domain_tags;
