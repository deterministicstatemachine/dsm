//! Domain-separated BLAKE3-256 hashing for the DSM protocol.
//!
//! Every hash computation in the DSM protocol is domain-separated to prevent
//! cross-context collisions. The canonical form is:
//!
//! ```text
//! BLAKE3-256("DSM/<domain>\0" || data)
//! ```
//!
//! where `\0` is a literal NUL byte appended after the domain tag.
//!
//! # Hierarchical Token Domain Separation
//!
//! Token operations use a 3-level hierarchy where the CPTA `policy_commit`
//! (32-byte anchor hash) serves as a cryptographic sub-domain:
//!
//! ```text
//! H("DSM/token-op/" || policy_commit || "/" || verb || "\0" || data)
//!    Major Domain      Sub-domain       Sub-subdomain       Payload
//! ```
//!
//! This makes cross-token hash collisions mathematically impossible. See
//! [`token_domain_hasher`], [`token_domain_hash`], [`token_domain_hash_bytes`].
//!
//! # Key Functions
//!
//! - [`dsm_domain_hasher`] -- returns a [`Hasher`] pre-loaded with the domain tag.
//! - [`domain_hash`] -- one-shot domain-separated hash returning [`struct@Hash`].
//! - [`domain_hash_bytes`] -- one-shot domain-separated hash returning `[u8; 32]`.
//! - [`token_domain_hasher`] -- hierarchical hasher for token operations.
//! - [`token_domain_hash`] -- one-shot hierarchical token hash.
//! - [`token_domain_hash_bytes`] -- one-shot hierarchical token hash returning bytes.
//! - [`hash_blake3`] -- plain (non-domain-separated) BLAKE3 hash.
//! - [`generate_deterministic_entropy`] -- entropy evolution for state transitions.
//! - [`create_random_walk_seed`] -- seed derivation for hash chain verification.
//!
//! # Thread Safety
//!
//! A thread-local [`Hasher`] cache is provided for high-throughput concurrent
//! scenarios. The [`generate_deterministic_entropy_concurrent`] function uses
//! the same domain tag and produces identical output to the non-concurrent
//! variant for identical inputs.

// Re-export Blake3 types for use throughout the DSM crypto module
pub use blake3::{hash, Hash, Hasher};

/// Hash the input data using the Blake3 algorithm.
///
/// This is the primary hashing function used throughout the DSM system
/// as specified in the whitepaper Section 3.5.
///
/// # Arguments
/// * `data` - The data to be hashed
///
/// # Returns
/// * `Hash` - The Blake3 hash of the input data
pub fn hash_blake3(data: &[u8]) -> Hash {
    let mut hasher = Hasher::new();
    hasher.update(data);
    hasher.finalize()
}

/// NOTE: Base64 helpers are forbidden in Core. Keep any convenience encoders under tests only.
#[cfg(test)]
pub fn hash_blake3_as_base64(data: &[u8]) -> String {
    let hash = blake3::hash(data);
    base64_encode_for_test(hash.as_bytes())
}

#[cfg(test)]
fn base64_encode_for_test(input: &[u8]) -> String {
    const BASE64_CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::new();
    let mut i = 0;
    while i < input.len() {
        let b0 = input[i] as u32;
        let b1 = if i + 1 < input.len() {
            input[i + 1] as u32
        } else {
            0
        };
        let b2 = if i + 2 < input.len() {
            input[i + 2] as u32
        } else {
            0
        };
        let triple = (b0 << 16) | (b1 << 8) | b2;
        result.push(BASE64_CHARS[((triple >> 18) & 63) as usize] as char);
        result.push(BASE64_CHARS[((triple >> 12) & 63) as usize] as char);
        if i + 1 < input.len() {
            result.push(BASE64_CHARS[((triple >> 6) & 63) as usize] as char);
        } else {
            result.push('=');
        }
        if i + 2 < input.len() {
            result.push(BASE64_CHARS[(triple & 63) as usize] as char);
        } else {
            result.push('=');
        }
        i += 3;
    }
    result
}

/// Generate a deterministic entropy for state transition.
///
/// This is used to implement the entropy evolution described in the whitepaper section 6:
/// en+1 = H(en || opn+1 || (n+1))
///
/// # Arguments
/// * `current_entropy` - Current state entropy
/// * `operation` - Operation for the transition
/// * `next_state_number` - Next state number
///
/// # Returns
/// * `Hash` - The deterministic entropy
pub fn generate_deterministic_entropy(
    current_entropy: &[u8],
    operation: &[u8],
    next_state_number: u64,
) -> Hash {
    let mut hasher = dsm_domain_hasher("DSM/state-entropy");

    hasher.update(current_entropy);
    hasher.update(operation);
    hasher.update(&next_state_number.to_le_bytes());

    hasher.finalize()
}

// Thread-local hasher cache for improved performance in concurrent environments
// This prevents repeated allocation/deallocation of hashers in high-throughput scenarios
thread_local! {
    static HASHER_CACHE: std::cell::RefCell<Hasher> = std::cell::RefCell::new(Hasher::new());
}

/// High-performance variant of generate_deterministic_entropy for concurrent benchmarks
/// Uses thread-local storage to avoid repeated hasher allocation
///
/// IMPORTANT: This function must produce exactly the same results as the non-concurrent version
/// to ensure consistent behavior between transition creation and verification paths.
/// DETERMINISM GUARANTEE:
/// While this function uses thread-local storage for performance optimization,
/// it maintains deterministic behavior by:
/// 1. Always resetting the hasher before use
/// 2. Processing data in the exact same order as the non-concurrent version
/// 3. Using the same cryptographic operations
///
/// The thread-local storage is purely a performance optimization that avoids
/// repeated hasher allocation in high-throughput scenarios. The output is
/// guaranteed to be identical to generate_deterministic_entropy() for the
/// same inputs.
pub fn generate_deterministic_entropy_concurrent(
    current_entropy: &[u8],
    operation: &[u8],
    next_state_number: u64,
) -> Hash {
    // Must match generate_deterministic_entropy exactly — use non-cached path
    // to include the domain tag. The thread-local cache cannot be pre-seeded
    // with the domain prefix because reset() clears it.
    generate_deterministic_entropy(current_entropy, operation, next_state_number)
}

/// Create a seed for hash chain verification.
///
/// This is used to create a seed for the deterministic random walk
/// as described in whitepaper Section 3.1.
///
/// # Arguments
/// * `state_hash` - Hash of the current state
/// * `operation` - Operation data
/// * `entropy` - New entropy value
///
/// # Returns
/// * `Hash` - The generated seed
pub fn create_random_walk_seed(state_hash: &[u8], operation: &[u8], entropy: &[u8]) -> Hash {
    let mut hasher = dsm_domain_hasher("DSM/random-walk-seed");

    hasher.update(state_hash);
    hasher.update(operation);
    hasher.update(entropy);

    hasher.finalize()
}

/// Hash raw bytes using plain (non-domain-separated) BLAKE3 and return the
/// digest as a `Vec<u8>`.
///
/// This is a convenience wrapper around [`blake3::hash`]. For protocol-path
/// hashing, prefer [`domain_hash`] or [`domain_hash_bytes`] to ensure proper
/// domain separation.
///
/// # Returns
///
/// A 32-byte BLAKE3 digest as `Vec<u8>`.
pub fn hash_bytes(input: &[u8]) -> Vec<u8> {
    hash(input).as_bytes().to_vec()
}

/// Create a fresh, non-domain-separated BLAKE3 [`Hasher`].
///
/// Callers that need domain separation should use [`dsm_domain_hasher`] instead.
pub fn new_hasher() -> Hasher {
    Hasher::new()
}

/// Create a domain-separated BLAKE3 hasher.
///
/// Returns a `Hasher` pre-loaded with the domain tag (including NUL terminator).
/// Callers chain `.update()` calls then `.finalize()`.
///
/// The `tag` must follow the `"DSM/<domain>"` convention. The NUL terminator is
/// appended automatically.
///
/// # Panics
/// Debug-asserts that `tag` starts with `"DSM/"`.
pub fn dsm_domain_hasher(tag: &str) -> Hasher {
    debug_assert!(
        tag.starts_with("DSM/") || tag.starts_with("DJTE."),
        "domain tag must start with \"DSM/\" or \"DJTE.\", got: {tag}"
    );
    let mut h = Hasher::new();
    h.update(tag.as_bytes());
    h.update(&[0u8]);
    h
}

/// Domain-separated hash function as specified in whitepaper
/// H(tag || data) where tag includes null terminator
pub fn domain_hash(tag: &str, data: &[u8]) -> Hash {
    let mut hasher = dsm_domain_hasher(tag);
    hasher.update(data);
    hasher.finalize()
}

#[cfg(test)]
mod tests_domain_hash {
    use super::*;

    #[test]
    fn domain_hash_includes_nul_terminator() {
        // Without a NUL, the two would be ambiguous in naive concatenation:
        // tag="DSM/ab", data="Cxyz"  vs tag="DSM/abC", data="xyz".
        // With NUL included, these MUST produce different digests.
        let h1 = domain_hash("DSM/ab", b"Cxyz");
        let h2 = domain_hash("DSM/abC", b"xyz");
        assert_ne!(h1.as_bytes(), h2.as_bytes());
    }
}

/// Domain-separated hash returning bytes
pub fn domain_hash_bytes(tag: &str, data: &[u8]) -> [u8; 32] {
    *domain_hash(tag, data).as_bytes()
}

// ---------------------------------------------------------------------------
// Hierarchical token domain separation
// ---------------------------------------------------------------------------

/// Create a hierarchical domain-separated hasher for token operations.
///
/// Produces prefix:
/// ```text
/// "DSM/token-op/" || policy_commit || "/" || verb || "\0"
/// ```
///
/// Different `policy_commit` values produce entirely different hash domains,
/// making cross-token hash collisions mathematically impossible. The `verb`
/// further isolates different operation types (transfer, mint, burn, etc.)
/// within the same token's domain.
///
/// # Arguments
/// * `policy_commit` - 32-byte CPTA anchor hash (the token's policy identity)
/// * `verb` - Operation type (e.g., "transfer", "mint", "burn", "balance-key")
///
/// # Panics
/// Debug-asserts that `verb` is non-empty and contains no NUL or `/` characters.
pub fn token_domain_hasher(policy_commit: &[u8; 32], verb: &str) -> Hasher {
    debug_assert!(!verb.is_empty(), "verb must not be empty");
    debug_assert!(
        !verb.contains('\0') && !verb.contains('/'),
        "verb must not contain NUL or '/' characters, got: {verb}"
    );
    let mut h = Hasher::new();
    h.update(b"DSM/token-op/"); // 13 bytes -- major domain
    h.update(policy_commit); // 32 bytes -- sub-domain (asset/policy)
    h.update(b"/"); // 1 byte  -- separator
    h.update(verb.as_bytes()); // variable -- sub-subdomain (verb/action)
    h.update(&[0u8]); // 1 byte  -- NUL terminator
    h
}

/// One-shot hierarchical domain hash for token operations.
///
/// Computes `BLAKE3("DSM/token-op/" || policy_commit || "/" || verb || "\0" || data)`.
///
/// # Arguments
/// * `policy_commit` - 32-byte CPTA anchor hash
/// * `verb` - Operation type (e.g., "transfer", "mint", "burn")
/// * `data` - Payload to hash
pub fn token_domain_hash(policy_commit: &[u8; 32], verb: &str, data: &[u8]) -> Hash {
    let mut hasher = token_domain_hasher(policy_commit, verb);
    hasher.update(data);
    hasher.finalize()
}

/// One-shot hierarchical domain hash returning raw bytes.
///
/// Same as [`token_domain_hash`] but returns `[u8; 32]` directly.
pub fn token_domain_hash_bytes(policy_commit: &[u8; 32], verb: &str, data: &[u8]) -> [u8; 32] {
    *token_domain_hash(policy_commit, verb, data).as_bytes()
}

#[cfg(test)]
mod tests_token_domain {
    use super::*;

    fn test_policy_a() -> [u8; 32] {
        let mut pc = [0u8; 32];
        pc[0] = 0xAA;
        pc[31] = 0x01;
        pc
    }

    fn test_policy_b() -> [u8; 32] {
        let mut pc = [0u8; 32];
        pc[0] = 0xBB;
        pc[31] = 0x02;
        pc
    }

    #[test]
    fn cross_token_isolation() {
        // Different policy_commit, same verb and data -> different hashes
        let data = b"100 units to device xyz";
        let h1 = token_domain_hash(&test_policy_a(), "transfer", data);
        let h2 = token_domain_hash(&test_policy_b(), "transfer", data);
        assert_ne!(h1.as_bytes(), h2.as_bytes());
    }

    #[test]
    fn cross_verb_isolation() {
        // Same policy_commit and data, different verb -> different hashes
        let pc = test_policy_a();
        let data = b"some payload";
        let h1 = token_domain_hash(&pc, "transfer", data);
        let h2 = token_domain_hash(&pc, "mint", data);
        assert_ne!(h1.as_bytes(), h2.as_bytes());
    }

    #[test]
    fn nul_unambiguity() {
        // verb="ab", data=b"Cxyz" vs verb="abC", data=b"xyz"
        // The NUL terminator after the verb must prevent ambiguity.
        let pc = test_policy_a();
        let h1 = token_domain_hash(&pc, "ab", b"Cxyz");
        let h2 = token_domain_hash(&pc, "abC", b"xyz");
        assert_ne!(h1.as_bytes(), h2.as_bytes());
    }

    #[test]
    fn non_collision_with_flat_domain() {
        // Hierarchical hash must differ from any flat domain_hash
        let pc = test_policy_a();
        let data = b"payload";
        let hierarchical = token_domain_hash(&pc, "transfer", data);
        let flat = domain_hash("DSM/token-op", data);
        assert_ne!(hierarchical.as_bytes(), flat.as_bytes());
    }

    #[test]
    fn determinism() {
        // Identical inputs must always produce identical outputs
        let pc = test_policy_a();
        let data = b"deterministic payload";
        let h1 = token_domain_hash(&pc, "balance-key", data);
        let h2 = token_domain_hash(&pc, "balance-key", data);
        assert_eq!(h1.as_bytes(), h2.as_bytes());
    }

    #[test]
    fn empty_data() {
        // Empty data produces a well-defined 32-byte hash
        let pc = test_policy_a();
        let h = token_domain_hash(&pc, "transfer", &[]);
        assert_eq!(h.as_bytes().len(), 32);
        // Must differ from non-empty data
        let h2 = token_domain_hash(&pc, "transfer", b"x");
        assert_ne!(h.as_bytes(), h2.as_bytes());
    }

    #[test]
    fn bytes_variant_matches_hash_variant() {
        let pc = test_policy_a();
        let data = b"consistency check";
        let h = token_domain_hash(&pc, "burn", data);
        let hb = token_domain_hash_bytes(&pc, "burn", data);
        assert_eq!(h.as_bytes(), &hb);
        assert_eq!(hb.len(), 32);
    }

    #[test]
    fn streaming_matches_one_shot() {
        // Streaming (token_domain_hasher + update) must equal one-shot (token_domain_hash)
        let pc = test_policy_b();
        let data = b"streaming test data";
        let one_shot = token_domain_hash(&pc, "receive", data);
        let mut hasher = token_domain_hasher(&pc, "receive");
        hasher.update(data);
        let streaming = hasher.finalize();
        assert_eq!(one_shot, streaming);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn test_hash_blake3() {
        let data1 = b"test data";
        let data2 = b"different data";

        let hash1 = hash_blake3(data1);
        let hash2 = hash_blake3(data2);

        // Same input should produce the same hash
        assert_eq!(hash_blake3(data1), hash1);

        // Different inputs should produce different hashes
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_generate_deterministic_entropy() {
        let entropy = b"initial entropy";
        let operation = b"test operation";
        let state_number = 1;

        let result1 = generate_deterministic_entropy(entropy, operation, state_number);
        let result2 = generate_deterministic_entropy(entropy, operation, state_number);

        // Same input should produce the same result
        assert_eq!(result1, result2);

        // Different inputs should produce different results
        let result3 = generate_deterministic_entropy(entropy, b"different operation", state_number);
        assert_ne!(result1, result3);

        let result4 = generate_deterministic_entropy(entropy, operation, 2);
        assert_ne!(result1, result4);
    }

    #[test]
    fn test_create_random_walk_seed() {
        let state_hash = b"state hash";
        let operation = b"operation";
        let entropy = b"entropy";

        let seed1 = create_random_walk_seed(state_hash, operation, entropy);
        let seed2 = create_random_walk_seed(state_hash, operation, entropy);

        // Same input should produce the same seed
        assert_eq!(seed1, seed2);

        // Different inputs should produce different seeds
        let seed3 = create_random_walk_seed(b"different hash", operation, entropy);
        assert_ne!(seed1, seed3);
    }

    #[test]
    fn empty_input_hash_matches_reference() {
        // Hash of empty input should be well-defined and match library reference
        let one_shot = hash_blake3(b"");
        let reference = blake3::hash(b"");
        assert_eq!(one_shot, reference);
        assert_eq!(one_shot.as_bytes().len(), 32);
    }

    #[test]
    fn streaming_vs_one_shot_equivalence_small_and_large() {
        // Build test inputs
        let small = b"The quick brown fox jumps over the lazy dog";
        let mut large = vec![0u8; 1_048_576]; // 1 MiB
        for (i, b) in large.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(31).wrapping_add(7);
        }

        // Helper to check streaming equals one-shot
        fn assert_streaming_eq(data: &[u8]) {
            // One-shot
            let one_shot = blake3::hash(data);

            // Streaming with uneven chunk sizes
            let mut hasher = new_hasher();
            let mut offset = 0usize;
            let chunk_sizes = [13usize, 257, 4096, 3, 8191, 1];
            let mut idx = 0;
            while offset < data.len() {
                let take = chunk_sizes[idx % chunk_sizes.len()].min(data.len() - offset);
                hasher.update(&data[offset..offset + take]);
                offset += take;
                idx += 1;
            }
            let streaming = hasher.finalize();
            assert_eq!(one_shot, streaming, "streaming must equal one-shot");
        }

        assert_streaming_eq(small);
        assert_streaming_eq(&large);
    }

    #[test]
    fn domain_hash_bytes_matches_hash() {
        let tag = "DSM/test";
        let data = b"payload";
        let h = domain_hash(tag, data);
        let hb = domain_hash_bytes(tag, data);
        assert_eq!(h.as_bytes(), &hb);
        assert_eq!(hb.len(), 32);
    }

    #[test]
    fn domain_separation_different_tags_produce_different_hashes() {
        let data = b"same-data";
        let h1 = domain_hash("DSM/tag1", data);
        let h2 = domain_hash("DSM/tag2", data);
        assert_ne!(h1.as_bytes(), h2.as_bytes());
    }

    #[test]
    fn hash_bytes_matches_reference() {
        let input = b"byte-test";
        let v = hash_bytes(input);
        let r = blake3::hash(input).as_bytes().to_vec();
        assert_eq!(v, r);
        assert_eq!(v.len(), 32);
    }

    #[test]
    fn deterministic_entropy_concurrent_matches_non_concurrent() {
        let entropy = b"entropy";
        let op = b"operation";
        let n = 42u64;
        let a = generate_deterministic_entropy(entropy, op, n);
        let b = generate_deterministic_entropy_concurrent(entropy, op, n);
        assert_eq!(a, b);
    }

    #[test]
    fn deterministic_entropy_concurrent_thread_safety() {
        // Run the concurrent function from multiple threads and ensure determinism
        let entropy = b"entropy".to_vec();
        let op = b"operation".to_vec();
        let n = 7u64;

        let mut handles = Vec::new();
        for _ in 0..8 {
            let e = entropy.clone();
            let o = op.clone();
            let handle =
                thread::spawn(move || generate_deterministic_entropy_concurrent(&e, &o, n));
            handles.push(handle);
        }

        let mut results = Vec::with_capacity(handles.len());
        for h in handles {
            let v = match h.join() {
                Ok(v) => v,
                Err(_) => panic!("generate_deterministic_entropy_concurrent worker panicked"),
            };
            results.push(v);
        }
        for w in results.windows(2) {
            assert_eq!(w[0], w[1]);
        }

        // Different input must produce different outputs
        let diff = generate_deterministic_entropy_concurrent(&entropy, &op, n + 1);
        assert_ne!(results[0], diff);
    }
}
