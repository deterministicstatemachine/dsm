//! Higher-level, semantically named hash operations for the DSM protocol.
//!
//! This module builds on the lower-level primitives in [`super::blake3`] and
//! exposes semantically named hashing wrappers used by higher-level callers.
//!
//! All functions use domain-separated BLAKE3 under the hood.
//!
//! Per §4.3 (counterless model): functions that took a `state_number`
//! parameter (`calculate_next_entropy`, `calculate_state_hash`) have been
//! deleted. Entropy evolution per §11 eq.14 uses
//! `H("DSM/state-entropy" || prev_entropy || op || prev_hash)` — see
//! `crate::core::state_machine::utils::calculate_next_entropy` for the
//! correct counterless implementation.

pub use blake3::Hash as HashOutput;

/// Hash data using Blake3
///
/// This implementation follows the whitepaper section 3.1 for straight hash chain verification
///
/// # Arguments
/// * `data` - The data to hash
///
/// # Returns
/// * `HashOutput` - Blake3 hash of the data
pub fn blake3(data: &[u8]) -> HashOutput {
    crate::crypto::blake3::domain_hash("DSM/hash-data", data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blake3_hashing() {
        let data = b"test data";
        let hash = blake3(data);

        // Test hash is not empty
        assert!(!hash.as_bytes().is_empty());

        // Test determinism (same input gives same output)
        let hash2 = blake3(data);
        assert_eq!(hash, hash2);

        // Test different input gives different output
        let different_data = b"different data";
        let different_hash = blake3(different_data);
        assert_ne!(hash, different_hash);
    }

    #[test]
    fn test_blake3_hash_to_bytes() {
        let data = b"test bytes";
        let digest = blake3(data);
        assert_eq!(digest.as_bytes().len(), 32);
    }
}
