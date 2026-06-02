// SPDX-License-Identifier: MIT OR Apache-2.0

//! Non-canonical labeling utilities for human-readable output.
//!
//! # ARCHITECTURAL WARNING
//! This module is explicitly EXCLUDED from the cryptographic boundary.
//! Functions here produce non-canonical, lossy string representations
//! (e.g. decimal short IDs) intended ONLY for logging, debugging, and UI.
//!
//! NEVER use output from this module in:
//! - Hash chains
//! - Signatures
//! - Merkle proofs
//! - State serialization

/// Convert a raw 32-byte digest to a short decimal label.
///
/// This helper is intentionally lossy and only for diagnostics.
pub fn hash_to_short_id(hash: &[u8; 32]) -> String {
    let mut lo = [0u8; 8];
    lo.copy_from_slice(&hash[0..8]);
    u64::from_le_bytes(lo).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_to_short_id_deterministic() {
        let h = [0xAA; 32];
        let s1 = hash_to_short_id(&h);
        let s2 = hash_to_short_id(&h);
        assert_eq!(s1, s2);
    }

    #[test]
    fn hash_to_short_id_uses_first_8_bytes() {
        let mut h = [0u8; 32];
        h[0..8].copy_from_slice(&777u64.to_le_bytes());
        assert_eq!(hash_to_short_id(&h), "777");
    }

    #[test]
    fn hash_to_short_id_zero_hash() {
        assert_eq!(hash_to_short_id(&[0u8; 32]), "0");
    }

    #[test]
    fn hash_to_short_id_max_value() {
        let mut h = [0u8; 32];
        h[0..8].copy_from_slice(&u64::MAX.to_le_bytes());
        assert_eq!(hash_to_short_id(&h), u64::MAX.to_string());
    }

    #[test]
    fn different_hashes_produce_different_labels() {
        let h_a = [0x01; 32];
        let h_b = [0x02; 32];
        assert_ne!(hash_to_short_id(&h_a), hash_to_short_id(&h_b));
    }
}
