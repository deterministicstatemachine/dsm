// SPDX-License-Identifier: MIT OR Apache-2.0
//! Frozen regression vectors for the SPHINCS+ BLAKE3 variant.
//!
//! **These are NOT known-answer tests in the usual sense.** A KAT validates an
//! implementation against vectors produced by someone else. That is not
//! available here: this construction substitutes BLAKE3 for SHA2/SHAKE and uses
//! its own address word layout, so no reference implementation and no published
//! vector set will ever agree with it. Only the parameter sizes match the
//! standardised sets.
//!
//! What these vectors do provide is a tripwire: the expected values below are
//! frozen in the source, so any change to key generation or signing — intended
//! or accidental — turns this file red instead of silently producing different
//! keys for the same mnemonic.
//!
//! This distinction is not pedantic. Until the FORS address collision was fixed
//! (all `k` trees drawing from one pool of secrets), this file was named for
//! known-answer testing but every assertion in it compared the implementation
//! against itself: keygen twice from one seed, signing twice with one key, a
//! sign/verify round trip. None of those can see a defect that the signer and
//! the verifier share, and none of them saw that one. Vectors frozen in the
//! source are the weakest form of independence, but they are not zero.
//!
//! If a test here fails, the construction changed. Every key and signature the
//! repository produces changed with it, and the same mnemonic now yields a
//! different identity. Find out why before updating a vector.

#[cfg(test)]
mod tests {
    use crate::crypto::sphincs::{generate_keypair_from_seed, sign, verify, SphincsVariant};

    /// Fixed 32-byte seed for reproducibility.
    const KAT_SEED: &[u8; 32] = b"DSM_SPHINCS_KAT_SEED_DETERM_0_00";

    /// Alternate 32-byte seed for cross-key rejection tests.
    const KAT_SEED_ALT: &[u8; 32] = b"DSM_SPHINCS_KAT_ALTERNATE_SEED_2";

    const STABILITY_MESSAGE: &[u8] = b"deterministic signature stability check";

    /// BLAKE3 of the SPX128f public key generated from `KAT_SEED`.
    const EXPECTED_PK_DIGEST: [u8; 32] = [
        64, 146, 171, 113, 244, 142, 178, 154, 171, 240, 228, 155, 136, 169, 181, 119, 230, 130,
        35, 175, 55, 255, 20, 226, 154, 224, 226, 231, 32, 0, 36, 7,
    ];

    /// BLAKE3 of the SPX128f secret key generated from `KAT_SEED`.
    const EXPECTED_SK_DIGEST: [u8; 32] = [
        248, 125, 193, 105, 173, 195, 250, 105, 210, 59, 184, 188, 166, 194, 109, 50, 29, 140, 165,
        122, 225, 65, 199, 103, 248, 102, 213, 23, 56, 13, 160, 49,
    ];

    /// BLAKE3 of the SPX128f signature over `STABILITY_MESSAGE` under `KAT_SEED`.
    const EXPECTED_SIG_DIGEST: [u8; 32] = [
        162, 212, 43, 213, 0, 239, 112, 150, 241, 118, 235, 172, 0, 20, 114, 181, 40, 2, 91, 154,
        85, 236, 89, 228, 218, 74, 103, 132, 209, 110, 252, 204,
    ];

    /// Key generation from a fixed seed must produce the SAME BYTES it produced
    /// when these vectors were frozen — not merely the same bytes twice in one
    /// process, which is what this test used to check.
    #[test]
    fn kat_keygen_matches_frozen_vector() {
        let kp = generate_keypair_from_seed(SphincsVariant::SPX128f, KAT_SEED)
            .expect("keygen from seed");

        assert_eq!(
            *blake3::hash(&kp.public_key).as_bytes(),
            EXPECTED_PK_DIGEST,
            "SPX128f public key for the fixed seed changed — key generation is \
             not what it was when this vector was frozen, so every identity \
             derived from a mnemonic has moved"
        );
        assert_eq!(
            *blake3::hash(&kp.secret_key).as_bytes(),
            EXPECTED_SK_DIGEST,
            "SPX128f secret key for the fixed seed changed"
        );
    }

    /// Signing must produce the SAME BYTES it produced when frozen. Determinism
    /// within one process is implied by this and is strictly weaker.
    #[test]
    fn kat_signature_matches_frozen_vector() {
        let variant = SphincsVariant::SPX128f;
        let kp = generate_keypair_from_seed(variant, KAT_SEED).expect("keygen from seed");
        let sig = sign(variant, &kp.secret_key, STABILITY_MESSAGE).expect("sign");

        assert_eq!(
            *blake3::hash(&sig).as_bytes(),
            EXPECTED_SIG_DIGEST,
            "SPX128f signature for the fixed (seed, message) changed — signing \
             is not what it was when this vector was frozen"
        );
    }

    /// Verify that sign+verify round-trips with the frozen keys.
    ///
    /// Kept for coverage, but note what it cannot do: the signer and the
    /// verifier share every address construction, so a defect in that shared
    /// code passes here. The FORS collision did.
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
}
