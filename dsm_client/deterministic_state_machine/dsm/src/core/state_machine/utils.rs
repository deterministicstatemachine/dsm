//! Utility functions for the DSM state machine
//!
//! This module contains common utility functions used across the state machine
//! implementation, ensuring consistent behavior and reducing duplication.

use blake3;

/// Perform constant-time equality comparison to prevent timing attacks
///
/// This function implements constant-time comparison for cryptographic values,
/// ensuring that timing information cannot be used to infer partial matches.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut result: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }

    result == 0
}

/// Domain-separated BLAKE3 hash for general state machine operations.
///
/// Uses the `"DSM/state-hash"` domain tag per the whitepaper mandate that all
/// production hashing must be domain-separated: `BLAKE3("DSM/<domain>\0" || data)`.
pub fn hash_blake3(data: &[u8]) -> blake3::Hash {
    crate::crypto::blake3::domain_hash("DSM/state-hash", data)
}

// verify_state_hash(&State) deleted: only caller was relationship.rs::validate_transition
// (also dead). HashChain has its own verify_state_hash impl for chain-internal use.

/// Calculate the next entropy based on current entropy, operation, and state number
///
/// Implements the deterministic entropy evolution from whitepaper §11 eq. 14:
/// `e_{n+1} = H("DSM/next-entropy" || e_n || op || H(S_n))`. Per §4.3 no
/// counter participates — adjacency comes from the parent hash.
pub fn calculate_next_entropy(
    current_entropy: &[u8],
    operation_bytes: &[u8],
    parent_hash: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = crate::crypto::blake3::dsm_domain_hasher("DSM/next-entropy");
    hasher.update(current_entropy);
    hasher.update(operation_bytes);
    hasher.update(parent_hash);

    *hasher.finalize().as_bytes()
}

// create_test_transition() deleted: zero callers (no other tests imported it).

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constant_time_eq() {
        let a = [1, 2, 3, 4];
        let b = [1, 2, 3, 4];
        let c = [1, 2, 3, 5];

        assert!(constant_time_eq(&a, &b));
        assert!(!constant_time_eq(&a, &c));
        assert!(!constant_time_eq(&a, &[1, 2, 3]));
    }

    #[test]
    fn test_hash_blake3() {
        let data = b"test data";
        let hash = hash_blake3(data);

        // hash_blake3 uses domain_hash("DSM/state-hash", data) internally
        let expected = crate::crypto::blake3::domain_hash("DSM/state-hash", data);
        assert_eq!(hash.as_bytes(), expected.as_bytes());
    }
}
