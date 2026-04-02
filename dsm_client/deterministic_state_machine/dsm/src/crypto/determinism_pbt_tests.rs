//! Micro-level property-based tests for determinism-critical primitives.
//!
//! These tests intentionally target small building blocks (uniform sampling,
//! seeded key generation, binding derivations) instead of only macro state.
//!
//! STRICT: no wall-clock, no UUID randomness.

#[cfg(test)]
mod tests {
    use crate::crypto::cdbrw_binding;
    use crate::crypto::sphincs::{generate_keypair_from_seed, SphincsVariant};
    use crate::crypto::kyber::{
        generate_kyber_keypair_from_entropy, generate_deterministic_kyber_keypair,
    };
    use crate::crypto::rng::{generate_deterministic_random, mix_entropy};
    use crate::crypto::canonical_lp::{hash_lp1, hash_lp2, hash_lp3};
    use crate::crypto::blake3::{domain_hash, generate_deterministic_entropy};
    use crate::crypto::signatures::SignatureKeyPair;
    use crate::emissions::uniform_index;
    use proptest::prelude::*;
    use proptest::prelude::ProptestConfig;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(if cfg!(debug_assertions) { 3 } else { 10 }))]

        #[test]
        fn pbt_uniform_index_is_deterministic_and_in_range(seed in any::<[u8;32]>(), n in 2u64..=u64::MAX) {
            let idx1 = uniform_index(&seed, n).unwrap();
            let idx2 = uniform_index(&seed, n).unwrap();
            assert!(idx1 < n);
            assert_eq!(idx1, idx2);
        }

        #[test]
        fn pbt_sphincs_seeded_keygen_is_deterministic(seed in any::<[u8;32]>()) {
            // Use one representative variant; others are covered by unit tests.
            let v = SphincsVariant::SPX256s;
            let kp1 = generate_keypair_from_seed(v, &seed).expect("seeded keygen must succeed");
            let kp2 = generate_keypair_from_seed(v, &seed).expect("seeded keygen must succeed");
            assert_eq!(&kp1.public_key, &kp2.public_key);
            assert_eq!(&kp1.secret_key, &kp2.secret_key);
        }

        #[test]
        fn pbt_cdbrw_binding_is_deterministic(
            hw in proptest::collection::vec(any::<u8>(), 1..=128),
            env in proptest::collection::vec(any::<u8>(), 1..=128),
            salt in proptest::collection::vec(any::<u8>(), 1..=128),
        ) {
            let b1 = cdbrw_binding::derive_cdbrw_binding_key(&hw, &env, &salt).expect("valid inputs");
            let b2 = cdbrw_binding::derive_cdbrw_binding_key(&hw, &env, &salt).expect("valid inputs");
            assert_eq!(b1.len(), 32);
            assert_eq!(b2.len(), 32);
            assert_eq!(b1, b2);
        }

        #[test]
        fn pbt_kyber_keypair_from_entropy_is_deterministic(entropy in any::<[u8;32]>()) {
            let (pk1, sk1) = generate_kyber_keypair_from_entropy(&entropy, "").expect("kyber keygen must succeed");
            let (pk2, sk2) = generate_kyber_keypair_from_entropy(&entropy, "").expect("kyber keygen must succeed");
            assert_eq!(pk1, pk2);
            assert_eq!(sk1, sk2);
        }

        #[test]
        fn pbt_kyber_deterministic_keypair_is_deterministic(seed in any::<[u8;32]>(), context in ".*") {
            let kp1 = generate_deterministic_kyber_keypair(&seed, &context).expect("deterministic kyber keygen must succeed");
            let kp2 = generate_deterministic_kyber_keypair(&seed, &context).expect("deterministic kyber keygen must succeed");
            assert_eq!(kp1, kp2);
        }

        #[test]
        fn pbt_rng_deterministic_random_is_deterministic(seed in any::<[u8;32]>(), len in 1usize..=1024) {
            let r1 = generate_deterministic_random(&seed, len);
            let r2 = generate_deterministic_random(&seed, len);
            assert_eq!(r1.len(), len);
            assert_eq!(r2.len(), len);
            assert_eq!(r1, r2);
        }

        #[test]
        fn pbt_rng_mix_entropy_is_deterministic(
            sources in proptest::collection::vec(proptest::collection::vec(any::<u8>(), 1..=64), 1..=8),
            output_len in 1usize..=1024
        ) {
            let sources_refs: Vec<&[u8]> = sources.iter().map(|s| s.as_slice()).collect();
            let r1 = mix_entropy(&sources_refs, output_len);
            let r2 = mix_entropy(&sources_refs, output_len);
            assert_eq!(r1.len(), output_len);
            assert_eq!(r2.len(), output_len);
            assert_eq!(r1, r2);
        }

        #[test]
        fn pbt_canonical_lp1_is_deterministic(domain in any::<[u8;8]>(), a in proptest::collection::vec(any::<u8>(), 0..=256)) {
            assert_eq!(
                hash_lp1(&domain, &a).unwrap(),
                hash_lp1(&domain, &a).unwrap()
            );
        }

        #[test]
        fn pbt_canonical_lp2_is_deterministic(
            domain in any::<[u8;8]>(),
            a in proptest::collection::vec(any::<u8>(), 0..=256),
            b in proptest::collection::vec(any::<u8>(), 0..=256)
        ) {
            assert_eq!(
                hash_lp2(&domain, &a, &b).unwrap(),
                hash_lp2(&domain, &a, &b).unwrap()
            );
        }

        #[test]
        fn pbt_canonical_lp3_is_deterministic(
            domain in any::<[u8;8]>(),
            a in proptest::collection::vec(any::<u8>(), 0..=256),
            b in proptest::collection::vec(any::<u8>(), 0..=256),
            c in proptest::collection::vec(any::<u8>(), 0..=256)
        ) {
            assert_eq!(
                hash_lp3(&domain, &a, &b, &c).unwrap(),
                hash_lp3(&domain, &a, &b, &c).unwrap()
            );
        }

        #[test]
        fn pbt_blake3_domain_hash_is_deterministic(suffix in "[a-zA-Z0-9_-]{1,32}", data in proptest::collection::vec(any::<u8>(), 0..=256)) {
            let tag = format!("DSM/{}", suffix);
            let h1 = domain_hash(&tag, &data);
            let h2 = domain_hash(&tag, &data);
            assert_eq!(h1, h2);
        }

        #[test]
        fn pbt_blake3_generate_deterministic_entropy_is_deterministic(
            current_entropy in proptest::collection::vec(any::<u8>(), 1..=64),
            operation in proptest::collection::vec(any::<u8>(), 1..=64),
            next_state_number in 0u64..=u64::MAX
        ) {
            let e1 = generate_deterministic_entropy(&current_entropy, &operation, next_state_number);
            let e2 = generate_deterministic_entropy(&current_entropy, &operation, next_state_number);
            assert_eq!(e1, e2);
        }

        #[test]
        fn pbt_signatures_generate_from_entropy_is_deterministic(entropy in any::<[u8;32]>()) {
            let kp1 = SignatureKeyPair::generate_from_entropy(&entropy).expect("signature keygen must succeed");
            let kp2 = SignatureKeyPair::generate_from_entropy(&entropy).expect("signature keygen must succeed");
            assert_eq!(kp1.public_key(), kp2.public_key());
        }
    }
}
