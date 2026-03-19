// SPDX-License-Identifier: MIT OR Apache-2.0
//! Property-based tests for SPHINCS+ sign/verify round-trip,
//! non-malleability, size consistency, and deterministic keygen.

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use proptest::prelude::ProptestConfig;

    use crate::crypto::sphincs::{
        generate_keypair, generate_keypair_from_seed, sign, sizes, verify, SphincsVariant,
    };

    /// All variants we want to test. Limited to 128-bit "fast" for speed in CI.
    fn test_variant() -> SphincsVariant {
        SphincsVariant::SPX128f
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(if cfg!(debug_assertions) { 3 } else { 10 }))]

        /// Round-trip: sign(sk, msg) then verify(pk, msg, sig) succeeds.
        #[test]
        fn pbt_sphincs_roundtrip(msg in proptest::collection::vec(any::<u8>(), 0..=512)) {
            let kp = generate_keypair(test_variant()).expect("keygen");
            let sig = sign(test_variant(), &kp.secret_key, &msg).expect("sign");
            let ok = verify(test_variant(), &kp.public_key, &msg, &sig).expect("verify");
            prop_assert!(ok, "verify must succeed for valid signature");
        }

        /// Non-malleability: flipping a single bit in the message makes verify fail.
        #[test]
        fn pbt_sphincs_message_tamper(
            msg in proptest::collection::vec(any::<u8>(), 1..=256),
            flip_idx in any::<prop::sample::Index>(),
        ) {
            let kp = generate_keypair(test_variant()).expect("keygen");
            let sig = sign(test_variant(), &kp.secret_key, &msg).expect("sign");

            let mut tampered = msg.clone();
            let idx = flip_idx.index(tampered.len());
            tampered[idx] ^= 0x01;

            let result = verify(test_variant(), &kp.public_key, &tampered, &sig).expect("verify call");
            prop_assert!(!result, "verify must fail for tampered message");
        }

        /// Non-malleability: corrupting the signature randomizer `R` (first n
        /// bytes) makes verify fail.  SPHINCS+ WOTS+ chains tolerate many
        /// single-byte flips inside the authentication path, but the leading
        /// randomizer `R` feeds into the message hash that determines all FORS
        /// indices — corrupting it is always fatal.
        #[test]
        fn pbt_sphincs_signature_tamper(
            msg in proptest::collection::vec(any::<u8>(), 1..=256),
            noise in proptest::collection::vec(any::<u8>(), 16..=16),
        ) {
            let v = test_variant();
            let (_, _, _) = sizes(v);
            let kp = generate_keypair(v).expect("keygen");
            let sig = sign(v, &kp.secret_key, &msg).expect("sign");

            // XOR the first n=16 bytes (the randomizer R) with random noise.
            // `prop_assume` that at least one noise byte is non-zero so the
            // signature actually changes.
            prop_assume!(noise.iter().any(|b| *b != 0));
            let mut tampered_sig = sig.clone();
            for (i, &n) in noise.iter().enumerate() {
                tampered_sig[i] ^= n;
            }

            let result = verify(v, &kp.public_key, &msg, &tampered_sig);
            // Either verify returns Ok(false) or Err — both acceptable.
            if let Ok(valid) = result {
                prop_assert!(!valid, "verify must fail for tampered signature randomizer");
            }
        }

        /// Size consistency: keypair, signature sizes match declared parameters.
        #[test]
        fn pbt_sphincs_size_consistency(msg in proptest::collection::vec(any::<u8>(), 1..=128)) {
            let v = test_variant();
            let (pk_len, sk_len, sig_len) = sizes(v);
            let kp = generate_keypair(v).expect("keygen");
            prop_assert_eq!(kp.public_key.len(), pk_len, "pk size mismatch");
            prop_assert_eq!(kp.secret_key.len(), sk_len, "sk size mismatch");

            let sig = sign(v, &kp.secret_key, &msg).expect("sign");
            prop_assert_eq!(sig.len(), sig_len, "sig size mismatch");
        }

        /// Deterministic keygen: same seed always produces the same keypair.
        #[test]
        fn pbt_sphincs_deterministic_keygen(seed in any::<[u8; 32]>()) {
            let v = test_variant();
            let kp1 = generate_keypair_from_seed(v, &seed).expect("keygen1");
            let kp2 = generate_keypair_from_seed(v, &seed).expect("keygen2");
            prop_assert_eq!(&kp1.public_key, &kp2.public_key, "pk must be deterministic");
            prop_assert_eq!(&kp1.secret_key, &kp2.secret_key, "sk must be deterministic");
        }
    }
}
