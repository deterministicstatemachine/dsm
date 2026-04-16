//! Higher-level, semantically named hash operations for the DSM protocol.
//!
//! This module builds on the lower-level primitives in [`super::blake3`] and
//! exposes functions that map directly to concepts in the DSM whitepaper:
//!
//! - **Verification seed** ([`generate_verification_seed`]) -- provides seeds
//!   for the random-walk verification approach (sections 13--14).
//! - **Hash combination** ([`combine_hashes`]) -- merges multiple hashes into
//!   a single digest for composite structures.
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

/// Hash data and return as bytes
///
/// # Arguments
/// * `data` - The data to hash
///
/// # Returns
/// * `Vec<u8>` - Blake3 hash of the data as bytes
pub fn hash_to_bytes(data: &[u8]) -> Vec<u8> {
    blake3(data).as_bytes().to_vec()
}

/// Generate a verification seed for random walk verification
///
/// This implements the random walk verification approach from whitepaper sections
/// 13 and 14, which provides efficient verification without hardware TEE.
pub fn generate_verification_seed(state_hash: &[u8], additional_entropy: &[u8]) -> HashOutput {
    let mut hasher = crate::crypto::blake3::dsm_domain_hasher("DSM/verification-seed");
    hasher.update(state_hash);
    hasher.update(additional_entropy);
    hasher.finalize()
}

/// Combine multiple hashes into a single hash
///
/// # Arguments
/// * `hashes` - Hashes to combine
///
/// # Returns
/// * `HashOutput` - Combined hash
pub fn combine_hashes(hashes: &[HashOutput]) -> HashOutput {
    let mut hash_builder = crate::crypto::blake3::dsm_domain_hasher("DSM/combine-hashes");

    for hash in hashes {
        // Create a reference to the hash bytes that lasts for the entire update operation
        let hash_bytes_ref = hash.as_bytes();
        hash_builder.update(hash_bytes_ref);
    }

    hash_builder.finalize()
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
    fn test_combine_hashes() {
        let hash1 = blake3(b"data1");
        let hash2 = blake3(b"data2");
        let hash3 = blake3(b"data3");

        let combined = combine_hashes(&[hash1, hash2, hash3]);

        // Test determinism (same input gives same output)
        let combined2 = combine_hashes(&[hash1, hash2, hash3]);
        assert_eq!(combined, combined2);

        // Test different input gives different output
        let different_combined = combine_hashes(&[hash1, hash3, hash2]);
        assert_ne!(combined, different_combined);
    }
}
