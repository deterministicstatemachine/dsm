// SPDX-License-Identifier: MIT OR Apache-2.0
//! Property-based tests for ML-KEM-768 (Kyber) KEM round-trip,
//! shared-secret consistency, deterministic keygen, and AES-GCM round-trip.

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use proptest::prelude::ProptestConfig;

    use crate::crypto::kyber::{
        aes_decrypt, aes_encrypt, generate_kyber_keypair, generate_kyber_keypair_from_entropy,
        kyber_decapsulate, kyber_encapsulate,
    };

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(if cfg!(debug_assertions) { 3 } else { 10 }))]

        /// KEM round-trip: encapsulate then decapsulate yields the same shared secret.
        #[test]
        fn pbt_kyber_kem_roundtrip(_dummy in 0u8..1u8) {
            let kp = generate_kyber_keypair().expect("keygen");
            let (shared_secret_enc, ciphertext) =
                kyber_encapsulate(&kp.public_key).expect("encapsulate");
            let shared_secret_dec =
                kyber_decapsulate(&kp.secret_key, &ciphertext).expect("decapsulate");
            prop_assert_eq!(
                shared_secret_enc,
                shared_secret_dec,
                "encap and decap shared secrets must match"
            );
        }

        /// Deterministic keygen: same entropy + context always produces the same keypair.
        #[test]
        fn pbt_kyber_deterministic_keygen(
            entropy in proptest::collection::vec(any::<u8>(), 32..=64),
        ) {
            let (pk1, sk1) =
                generate_kyber_keypair_from_entropy(&entropy, "test").expect("keygen1");
            let (pk2, sk2) =
                generate_kyber_keypair_from_entropy(&entropy, "test").expect("keygen2");
            prop_assert_eq!(&pk1, &pk2, "pk must match");
            prop_assert_eq!(&sk1, &sk2, "sk must match");
        }

        /// Different entropy produces different keypairs.
        #[test]
        fn pbt_kyber_different_entropy(
            entropy1 in proptest::collection::vec(any::<u8>(), 32..=32),
            entropy2 in proptest::collection::vec(any::<u8>(), 32..=32),
        ) {
            prop_assume!(entropy1 != entropy2);
            let (pk1, _) =
                generate_kyber_keypair_from_entropy(&entropy1, "test").expect("keygen1");
            let (pk2, _) =
                generate_kyber_keypair_from_entropy(&entropy2, "test").expect("keygen2");
            prop_assert_ne!(&pk1, &pk2, "different entropy must produce different keys");
        }

        /// AES-GCM round-trip: encrypt then decrypt recovers the plaintext.
        #[test]
        fn pbt_aes_gcm_roundtrip(
            plaintext in proptest::collection::vec(any::<u8>(), 0..=1024),
            key in any::<[u8; 32]>(),
            nonce in any::<[u8; 12]>(),
        ) {
            let ct = aes_encrypt(&key, &nonce, &plaintext).expect("encrypt");
            let recovered = aes_decrypt(&key, &nonce, &ct).expect("decrypt");
            prop_assert_eq!(recovered, plaintext, "decrypt must recover plaintext");
        }

        /// AES-GCM tamper detection: flipping a bit in ciphertext causes decrypt failure.
        #[test]
        fn pbt_aes_gcm_tamper_detection(
            plaintext in proptest::collection::vec(any::<u8>(), 1..=256),
            key in any::<[u8; 32]>(),
            nonce in any::<[u8; 12]>(),
            flip_idx in any::<prop::sample::Index>(),
        ) {
            let ct = aes_encrypt(&key, &nonce, &plaintext).expect("encrypt");
            // Ciphertext includes auth tag; flip one bit
            let mut tampered = ct.clone();
            let idx = flip_idx.index(tampered.len());
            tampered[idx] ^= 0x01;
            let result = aes_decrypt(&key, &nonce, &tampered);
            prop_assert!(result.is_err(), "decrypt must fail for tampered ciphertext");
        }

        /// AES-GCM wrong key: decrypting with wrong key fails.
        #[test]
        fn pbt_aes_gcm_wrong_key(
            plaintext in proptest::collection::vec(any::<u8>(), 1..=256),
            key1 in any::<[u8; 32]>(),
            key2 in any::<[u8; 32]>(),
            nonce in any::<[u8; 12]>(),
        ) {
            prop_assume!(key1 != key2);
            let ct = aes_encrypt(&key1, &nonce, &plaintext).expect("encrypt");
            let result = aes_decrypt(&key2, &nonce, &ct);
            prop_assert!(result.is_err(), "decrypt with wrong key must fail");
        }
    }
}
