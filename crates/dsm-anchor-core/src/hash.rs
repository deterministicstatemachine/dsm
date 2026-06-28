//! `H` = BLAKE3-256 and the domain-separated KDF, matching the paper's
//! `H("DSM/.../v1" ‖ …)` and `HKDF(secret, context="DSM/.../v1" ‖ …)` notation.
//!
//! All structured inputs are canonical fixed-width byte fields, so the domain
//! string as a prefix plus fixed-length fields is unambiguous (no length
//! prefixing needed). Integers use little-endian, matching DSM conventions.

use blake3::Hasher;

/// `H(domain ‖ f0 ‖ f1 ‖ …)` — domain-separated BLAKE3-256.
pub fn h(domain: &str, fields: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(domain.as_bytes());
    for f in fields {
        hasher.update(f);
    }
    *hasher.finalize().as_bytes()
}

/// Domain-separated KDF: keyed BLAKE3 with `secret` as the 32-byte key and
/// `domain ‖ fields` as the message. Used for the root-advance witness key
/// material `K`, keyed by the MACANDD output `W` (the paper's
/// `HKDF(secret=W, context=…)`, Def. 17).
pub fn kdf(secret: &[u8; 32], domain: &str, fields: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Hasher::new_keyed(secret);
    hasher.update(domain.as_bytes());
    for f in fields {
        hasher.update(f);
    }
    *hasher.finalize().as_bytes()
}
