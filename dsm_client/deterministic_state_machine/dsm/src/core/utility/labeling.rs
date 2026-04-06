//! Non-canonical labeling utilities for human-readable output.
//!
//! # ARCHITECTURAL WARNING
//! This module is explicitly EXCLUDED from the cryptographic boundary.
//! Functions here produce non-canonical, non-deterministic string representations
//! (e.g. decimal IDs, short hashes) intended ONLY for logging, debugging, and UI.
//!
//! NEVER use output from this module in:
//! - Hash chains
//! - Signatures
//! - Merkle proofs
//! - State serialization
//!
//! Any import of this module within core consensus logic is an audit violation.

use crate::core::identity::Identity;

/// Convert an Identity to a human-readable string label (decimal-only).
/// Derived from first 16 bytes of genesis hash.
pub fn identity_to_string(identity: &Identity) -> String {
    let h = &identity.master_genesis.hash;
    let (a, b) = if h.len() >= 16 {
        let mut lo = [0u8; 8];
        let mut hi = [0u8; 8];
        lo.copy_from_slice(&h[0..8]);
        hi.copy_from_slice(&h[8..16]);
        (u64::from_le_bytes(lo), u64::from_le_bytes(hi))
    } else {
        (0, 0)
    };
    format!("{}-{}", a, b)
}

/// Convert an Identity to a short decimal label (first 8 bytes).
/// For logs/UI only.
pub fn identity_short_id(identity: &Identity) -> String {
    let h = &identity.master_genesis.hash;
    let num = if h.len() >= 8 {
        let mut lo = [0u8; 8];
        lo.copy_from_slice(&h[0..8]);
        u64::from_le_bytes(lo)
    } else {
        0u64
    };
    num.to_string()
}

/// Convert a raw 32-byte hash to a short decimal label.
pub fn hash_to_short_id(hash: &[u8]) -> String {
    let num = if hash.len() >= 8 {
        let mut lo = [0u8; 8];
        lo.copy_from_slice(&hash[0..8]);
        u64::from_le_bytes(lo)
    } else {
        0u64
    };
    num.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::identity::Identity;

    fn make_identity_with_hash(hash: [u8; 32]) -> Identity {
        let mut genesis =
            crate::core::identity::genesis::GenesisState::new().expect("genesis creation");
        genesis.hash = hash;
        Identity::with_genesis("test".into(), genesis)
    }

    #[test]
    fn identity_to_string_deterministic() {
        let id = make_identity_with_hash([0xAA; 32]);
        let s1 = identity_to_string(&id);
        let s2 = identity_to_string(&id);
        assert_eq!(s1, s2);
    }

    #[test]
    fn identity_to_string_uses_first_16_bytes() {
        let mut h = [0u8; 32];
        h[0..8].copy_from_slice(&42u64.to_le_bytes());
        h[8..16].copy_from_slice(&99u64.to_le_bytes());
        let id = make_identity_with_hash(h);
        assert_eq!(identity_to_string(&id), "42-99");
    }

    #[test]
    fn identity_to_string_zero_hash() {
        let id = make_identity_with_hash([0u8; 32]);
        assert_eq!(identity_to_string(&id), "0-0");
    }

    #[test]
    fn identity_short_id_deterministic() {
        let id = make_identity_with_hash([0xBB; 32]);
        let s1 = identity_short_id(&id);
        let s2 = identity_short_id(&id);
        assert_eq!(s1, s2);
    }

    #[test]
    fn identity_short_id_uses_first_8_bytes() {
        let mut h = [0u8; 32];
        h[0..8].copy_from_slice(&12345u64.to_le_bytes());
        let id = make_identity_with_hash(h);
        assert_eq!(identity_short_id(&id), "12345");
    }

    #[test]
    fn identity_short_id_zero_hash() {
        let id = make_identity_with_hash([0u8; 32]);
        assert_eq!(identity_short_id(&id), "0");
    }

    #[test]
    fn hash_to_short_id_full_32_bytes() {
        let mut h = [0u8; 32];
        h[0..8].copy_from_slice(&777u64.to_le_bytes());
        assert_eq!(hash_to_short_id(&h), "777");
    }

    #[test]
    fn hash_to_short_id_exactly_8_bytes() {
        let bytes = 999u64.to_le_bytes();
        assert_eq!(hash_to_short_id(&bytes), "999");
    }

    #[test]
    fn hash_to_short_id_short_input_returns_zero() {
        assert_eq!(hash_to_short_id(&[1, 2, 3]), "0");
    }

    #[test]
    fn hash_to_short_id_empty_input_returns_zero() {
        assert_eq!(hash_to_short_id(&[]), "0");
    }

    #[test]
    fn hash_to_short_id_max_value() {
        let bytes = u64::MAX.to_le_bytes();
        assert_eq!(hash_to_short_id(&bytes), u64::MAX.to_string());
    }

    #[test]
    fn different_hashes_produce_different_labels() {
        let id_a = make_identity_with_hash([0x01; 32]);
        let id_b = make_identity_with_hash([0x02; 32]);
        assert_ne!(identity_to_string(&id_a), identity_to_string(&id_b));
        assert_ne!(identity_short_id(&id_a), identity_short_id(&id_b));
    }
}
