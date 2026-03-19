// SPDX-License-Identifier: MIT OR Apache-2.0
//! Manifold seed — deterministic per-policy seed for bearer-derived η.
//!
//! η = BLAKE3("DSM/dbtc-bearer-eta\0" || manifold_seed || deposit_nonce)
//! seed = BLAKE3("DSM/manifold-seed\0" || policy_commit)
//!
//! dBTC is a built-in CPTA. The seed is pure math — deterministic from
//! the policy commit. Every device running DSM computes the same seed
//! for the same policy. No database, no propagation, no per-device
//! randomness.

use anyhow::Result;

/// Derive the manifold seed for a policy commit.
///
/// seed = BLAKE3("DSM/manifold-seed\0" || policy_commit)
///
/// Deterministic: same policy commit → same seed on every device.
pub fn get_or_create_manifold_seed(policy_commit: &[u8]) -> Result<[u8; 32]> {
    let seed = *dsm::crypto::blake3::domain_hash("DSM/manifold-seed", policy_commit).as_bytes();
    Ok(seed)
}
