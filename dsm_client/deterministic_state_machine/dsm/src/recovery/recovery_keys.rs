// SPDX-License-Identifier: MIT OR Apache-2.0

//! The recovery secrets of key schedule KS1 (`core::identity::key_schedule`): two sibling
//! Expands of the wallet-root PRK, `PRK_w = Extract("DSM/kdf/wallet-root/v1", wallet_seed)`.
//! Every recovery secret comes from the same wallet-root Extract as the identity, so a
//! wallet restored from its phrase derives the same secrets as the wallet that made them.

use crate::core::identity::key_schedule::{recovery_aead_key, recovery_authority_seed, wallet_prk};
use crate::types::error::DsmError;

/// The recovery AEAD key K_R: `Expand(PRK_w, "DSM/recovery-aead/v2")`. The owner's
/// 2026-11-01 ruling removed its one consumer, the ring capsule, and kept the derivation.
pub fn derive_recovery_key(wallet_seed: &[u8]) -> Result<[u8; 32], DsmError> {
    if wallet_seed.is_empty() {
        return Err(DsmError::invalid_parameter(
            "recovery key: empty wallet seed",
        ));
    }
    Ok(recovery_aead_key(&wallet_prk(wallet_seed)))
}

/// The seed of the recovery-authority SPHINCS+ keypair: `Expand(PRK_w,
/// "DSM/recovery-authority/v2")`, a sibling of K_R. It is fed to
/// `generate_keypair_from_seed()`; the resulting keypair is the recovery authority, the root
/// of trust for tombstone and succession signing. Its public key is published.
pub fn derive_recovery_authority_seed(wallet_seed: &[u8]) -> Result<[u8; 32], DsmError> {
    if wallet_seed.is_empty() {
        return Err(DsmError::invalid_parameter(
            "recovery authority: empty wallet seed",
        ));
    }
    Ok(recovery_authority_seed(&wallet_prk(wallet_seed)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn refuses_an_empty_seed(derive: fn(&[u8]) -> Result<[u8; 32], DsmError>, what: &str) {
        match derive(&[]) {
            Err(e) => assert!(
                e.to_string().contains("empty wallet seed"),
                "{what}: the refusal names the empty seed: {e}"
            ),
            Ok(_) => panic!("{what}: an empty seed derived a secret"),
        }
    }

    #[test]
    fn an_empty_seed_derives_no_recovery_secret() {
        refuses_an_empty_seed(derive_recovery_key, "K_R");
        refuses_an_empty_seed(derive_recovery_authority_seed, "the authority seed");
    }

    #[test]
    fn the_two_recovery_secrets_are_distinct_functions_of_the_seed() {
        let seed_a = [0x5Au8; 64];
        let seed_b = [0xA5u8; 64];
        let key_a = derive_recovery_key(&seed_a).expect("K_R");
        let authority_a = derive_recovery_authority_seed(&seed_a).expect("authority seed");
        assert_ne!(key_a, authority_a, "the two Expands of one PRK_w differ");
        assert_eq!(key_a, derive_recovery_key(&seed_a).expect("K_R again"));
        assert_ne!(
            key_a,
            derive_recovery_key(&seed_b).expect("K_R of another seed")
        );
        assert_ne!(
            authority_a,
            derive_recovery_authority_seed(&seed_b).expect("authority seed of another seed")
        );
    }
}
