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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_same_input() {
        let commit = b"policy-commit-abc";
        let s1 = get_or_create_manifold_seed(commit).unwrap();
        let s2 = get_or_create_manifold_seed(commit).unwrap();
        assert_eq!(s1, s2);
    }

    #[test]
    fn different_inputs_produce_different_seeds() {
        let s1 = get_or_create_manifold_seed(b"commit-A").unwrap();
        let s2 = get_or_create_manifold_seed(b"commit-B").unwrap();
        assert_ne!(s1, s2);
    }

    #[test]
    fn output_is_32_bytes() {
        let s = get_or_create_manifold_seed(b"any").unwrap();
        assert_eq!(s.len(), 32);
    }

    #[test]
    fn empty_input_is_valid() {
        let s = get_or_create_manifold_seed(b"").unwrap();
        assert_eq!(s.len(), 32);
        // Still deterministic
        let s2 = get_or_create_manifold_seed(b"").unwrap();
        assert_eq!(s, s2);
    }

    #[test]
    fn empty_vs_nonempty_differ() {
        let empty = get_or_create_manifold_seed(b"").unwrap();
        let nonempty = get_or_create_manifold_seed(b"\x00").unwrap();
        assert_ne!(empty, nonempty);
    }

    #[test]
    fn matches_raw_blake3_domain_hash() {
        let commit = b"test-policy";
        let seed = get_or_create_manifold_seed(commit).unwrap();
        let expected = *dsm::crypto::blake3::domain_hash("DSM/manifold-seed", commit).as_bytes();
        assert_eq!(seed, expected);
    }

    #[test]
    fn not_all_zeros() {
        let s = get_or_create_manifold_seed(b"real-policy").unwrap();
        assert!(s.iter().any(|&b| b != 0));
    }
}
