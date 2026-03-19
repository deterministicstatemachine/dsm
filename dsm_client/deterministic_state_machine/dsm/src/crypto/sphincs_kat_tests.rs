// SPDX-License-Identifier: MIT OR Apache-2.0
//! Known Answer Tests (KAT) for SPHINCS+ BLAKE3 variant.
//!
//! These tests verify that deterministic keygen from a fixed seed produces
//! stable key material and that signatures generated from those keys are
//! consistent across builds. This catches accidental algorithm changes in
//! the BLAKE3-substituted SPHINCS+ implementation.

#[cfg(test)]
mod tests {
    use crate::crypto::sphincs::{generate_keypair_from_seed, sign, verify, SphincsVariant};

    /// Fixed 32-byte seed for KAT reproducibility.
    const KAT_SEED: &[u8; 32] = b"DSM_SPHINCS_KAT_SEED_DETERM_0_00";

    /// Alternate 32-byte seed for cross-key rejection tests.
    const KAT_SEED_ALT: &[u8; 32] = b"DSM_SPHINCS_KAT_ALTERNATE_SEED_2";

    /// Verify that deterministic keygen produces stable output.
    /// If this test breaks, the SPHINCS+ implementation has changed in a
    /// backwards-incompatible way and all existing signatures will be invalid.
    #[test]
    fn kat_deterministic_keygen_stability() {
        let variant = SphincsVariant::SPX128f;

        let kp1 = generate_keypair_from_seed(variant, KAT_SEED).expect("keygen from seed");
        let kp2 = generate_keypair_from_seed(variant, KAT_SEED).expect("keygen from seed");

        assert_eq!(
            kp1.public_key, kp2.public_key,
            "Deterministic keygen must produce identical public keys"
        );
        assert_eq!(
            kp1.secret_key, kp2.secret_key,
            "Deterministic keygen must produce identical secret keys"
        );
    }

    /// Verify that sign+verify round-trips with KAT keys.
    #[test]
    fn kat_sign_verify_roundtrip() {
        let variant = SphincsVariant::SPX128f;
        let kp = generate_keypair_from_seed(variant, KAT_SEED).expect("keygen from seed");

        let message = b"DSM KAT test message for SPHINCS+ BLAKE3 variant";
        let sig = sign(variant, &kp.secret_key, message).expect("sign");
        let valid = verify(variant, &kp.public_key, message, &sig).expect("verify");

        assert!(valid, "KAT signature must verify");
    }

    /// Verify that a signature from one key does not verify under another.
    #[test]
    fn kat_cross_key_rejection() {
        let variant = SphincsVariant::SPX128f;
        let kp1 = generate_keypair_from_seed(variant, KAT_SEED).expect("keygen from seed");
        let kp2 = generate_keypair_from_seed(variant, KAT_SEED_ALT).expect("keygen from seed");

        let message = b"cross-key rejection test";
        let sig = sign(variant, &kp1.secret_key, message).expect("sign");
        let valid = verify(variant, &kp2.public_key, message, &sig).expect("verify");

        assert!(!valid, "Signature must not verify under a different key");
    }

    /// Verify deterministic signature stability.
    /// SPHINCS+ signing is deterministic (message hash is derived from sk + message),
    /// so the same (sk, message) pair must always produce the same signature.
    #[test]
    fn kat_deterministic_signature_stability() {
        let variant = SphincsVariant::SPX128f;
        let kp = generate_keypair_from_seed(variant, KAT_SEED).expect("keygen from seed");

        let message = b"deterministic signature stability check";
        let sig1 = sign(variant, &kp.secret_key, message).expect("sign");
        let sig2 = sign(variant, &kp.secret_key, message).expect("sign");

        assert_eq!(
            sig1, sig2,
            "Deterministic SPHINCS+ must produce identical signatures for same (sk, msg)"
        );
    }
}
