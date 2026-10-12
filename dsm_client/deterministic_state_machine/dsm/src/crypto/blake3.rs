// SPDX-License-Identifier: MIT OR Apache-2.0

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
//!
//! # Thread Safety
//!
//! All hashers are stack-allocated and free of shared mutable state.

// Re-export Blake3 types for use throughout the DSM crypto module
pub use blake3::{Hash, Hasher};

use crate::crypto::domain::TaggedHashDomain;

/// Create a domain-separated BLAKE3 hasher.
///
/// Returns a `Hasher` pre-loaded with the domain tag (including NUL terminator).
/// Callers chain `.update()` calls then `.finalize()`.
///
/// The `tag` must follow the `"DSM/<domain>"` convention. The NUL terminator is
/// appended automatically.
///
/// # Panics
/// Panics if `tag` does not start with `"DSM/"` or `"DJTE."`.
pub fn dsm_domain_hasher(tag: TaggedHashDomain<'_>) -> Hasher {
    assert!(
        tag.source_bytes().starts_with(b"DSM/") || tag.source_bytes().starts_with(b"DJTE."),
        "domain tag must start with \"DSM/\" or \"DJTE.\", got: {:?}",
        String::from_utf8_lossy(tag.source_bytes())
    );
    let mut h = Hasher::new();
    h.update(tag.source_bytes());
    h.update(&[0u8]);
    h
}

/// Domain-separated **keyed** BLAKE3 hasher: keyed BLAKE3 with `key` as the
/// 32-byte key, then the domain tag (with the same `tag || 0x00` separation as
/// [`dsm_domain_hasher`]) folded into the message.
///
/// This is the per-step KDF primitive of whitepaper §11.1/§12: "keyed BLAKE3
/// with the secret as the key (NOT HKDF)". The secret key is the master seed
/// `Smaster`; the tag plus the caller's subsequent `update()`s form the
/// versioned, algorithm- and chain-bound context.
///
/// # Panics
/// Panics if `tag` does not start with `"DSM/"` or `"DJTE."`.
pub fn dsm_domain_hasher_keyed(tag: TaggedHashDomain<'_>, key: &[u8; 32]) -> Hasher {
    assert!(
        tag.source_bytes().starts_with(b"DSM/") || tag.source_bytes().starts_with(b"DJTE."),
        "domain tag must start with \"DSM/\" or \"DJTE.\", got: {:?}",
        String::from_utf8_lossy(tag.source_bytes())
    );
    let mut h = Hasher::new_keyed(key);
    h.update(tag.source_bytes());
    h.update(&[0u8]);
    h
}

/// THE canonical tagged-hash encoder: `domain || 0x00`, appended here and
/// nowhere else.
///
/// Takes a validated [`TaggedHashDomain`], so a domain carrying its own NUL
/// cannot reach this function — it fails at construction (at compile time for
/// `from_static`). See `docs/adr/0001-three-domain-separation-constructions.md`.
///
/// Callers MUST NOT append a delimiter themselves. Every hand-inlined
/// `update(tag); update(&[0]);` pair in the repository is being replaced by this.
pub fn tagged_hasher(domain: crate::crypto::domain::TaggedHashDomain<'_>) -> Hasher {
    let mut h = Hasher::new();
    h.update(domain.source_bytes());
    h.update(&[0u8]);
    h
}

/// Domain-separated hash function as specified in whitepaper
/// H(tag || data) where tag includes null terminator
pub fn domain_hash(tag: TaggedHashDomain<'_>, data: &[u8]) -> Hash {
    let mut hasher = dsm_domain_hasher(tag);
    hasher.update(data);
    hasher.finalize()
}

#[cfg(test)]
mod tests_domain_hash {
    use super::*;

    const TAG_DSM_AB_FIXTURE: crate::crypto::domain::TaggedHashDomain<'static> =
        crate::tagged_domain!(b"DSM/ab");
    const TAG_DSM_ABC_FIXTURE: crate::crypto::domain::TaggedHashDomain<'static> =
        crate::tagged_domain!(b"DSM/abC");
    // No longer a valid tag by prefix, but still representable — the prefix
    // rule is a debug_assert in the hasher, not part of the type.
    const TAG_NOT_DSM_FIXTURE: crate::crypto::domain::TaggedHashDomain<'static> =
        crate::tagged_domain!(b"not-dsm");

    #[test]
    fn domain_hash_includes_nul_terminator() {
        // Without a NUL, the two would be ambiguous in naive concatenation:
        // tag="DSM/ab", data="Cxyz"  vs tag="DSM/abC", data="xyz".
        // With NUL included, these MUST produce different digests.
        let h1 = domain_hash(TAG_DSM_AB_FIXTURE, b"Cxyz");
        let h2 = domain_hash(TAG_DSM_ABC_FIXTURE, b"xyz");
        assert_ne!(h1.as_bytes(), h2.as_bytes());
    }

    #[test]
    #[should_panic(expected = "domain tag must start")]
    fn domain_hash_rejects_non_dsm_tag() {
        let _ = domain_hash(TAG_NOT_DSM_FIXTURE, b"payload");
    }
}

/// Domain-separated hash returning bytes
pub fn domain_hash_bytes(tag: TaggedHashDomain<'_>, data: &[u8]) -> [u8; 32] {
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
/// * `verb` - Operation type (e.g., "transfer", "lock", "burn", "balance-key")
///
/// # Panics
/// Panics if `verb` is empty or contains NUL or `/` characters.
pub fn token_domain_hasher(policy_commit: &[u8; 32], verb: &str) -> Hasher {
    assert!(!verb.is_empty(), "verb must not be empty");
    assert!(
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
/// * `verb` - Operation type (e.g., "transfer", "lock", "burn")
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
        let h2 = token_domain_hash(&pc, "burn", data);
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
        let flat = domain_hash(crate::common::domain_tags::TAG_DSM_TOKEN_OP, data);
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

    #[test]
    #[should_panic(expected = "verb must not be empty")]
    fn token_domain_rejects_empty_verb() {
        let _ = token_domain_hasher(&test_policy_a(), "");
    }

    #[test]
    #[should_panic(expected = "verb must not contain NUL or '/' characters")]
    fn token_domain_rejects_slash_in_verb() {
        let _ = token_domain_hasher(&test_policy_a(), "bad/verb");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
            let mut hasher = Hasher::new();
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
        let tag = crate::tagged_domain!(b"DSM/test");
        let data = b"payload";
        let h = domain_hash(tag, data);
        let hb = domain_hash_bytes(tag, data);
        assert_eq!(h.as_bytes(), &hb);
        assert_eq!(hb.len(), 32);
    }

    #[test]
    fn domain_separation_different_tags_produce_different_hashes() {
        let data = b"same-data";
        let h1 = domain_hash(crate::common::domain_tags::TAG_DSM_TAG1, data);
        let h2 = domain_hash(crate::common::domain_tags::TAG_DSM_TAG2, data);
        assert_ne!(h1.as_bytes(), h2.as_bytes());
    }
}
