//! SPHINCS+ ephemeral key chain for C-DBRW verification protocol.
//!
//! Implements Alg. 3 steps 6-8 from the C-DBRW paper Rev 2.0:
//! - Derive ephemeral seed from hash chain state + Kyber shared secret + K_DBRW
//! - Generate ephemeral SPHINCS+ keypair (SPX256f) from that seed
//! - Sign the verification response (gamma || ct || challenge)
//!
//! # Domain Tags
//!
//! | Tag | Usage |
//! |-----|-------|
//! | `DSM/ek\0` | Ephemeral key seed derivation |

use crate::crypto::blake3::dsm_domain_hasher;
use crate::crypto::sphincs::{generate_keypair_from_seed, sign, sphincs_verify, SphincsVariant};
use crate::types::error::DsmError;

/// Derive the ephemeral key seed E_{n+1}.
///
/// `E_{n+1} = BLAKE3("DSM/ek\0" || h_n || C_pre || k_step || K_DBRW)`
///
/// - `h_n`: current hash chain tip (32 bytes)
/// - `c_pre`: pre-commitment hash (32 bytes)
/// - `k_step`: Kyber step key derived from shared secret (32 bytes)
/// - `k_dbrw`: C-DBRW binding key (32 bytes)
pub fn derive_ephemeral_seed(
    h_n: &[u8; 32],
    c_pre: &[u8; 32],
    k_step: &[u8; 32],
    k_dbrw: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = dsm_domain_hasher("DSM/ek");
    hasher.update(h_n);
    hasher.update(c_pre);
    hasher.update(k_step);
    hasher.update(k_dbrw);
    *hasher.finalize().as_bytes()
}

/// Generate an ephemeral SPHINCS+ keypair from a seed.
///
/// Uses SPX256f for fast keygen in the verification protocol.
/// Returns `(public_key, secret_key)`.
pub fn generate_ephemeral_keypair(seed: &[u8; 32]) -> Result<(Vec<u8>, Vec<u8>), DsmError> {
    let kp = generate_keypair_from_seed(SphincsVariant::SPX256f, seed)?;
    Ok((kp.public_key.clone(), kp.secret_key.clone()))
}

/// Sign the C-DBRW verification response.
///
/// `sigma = SPHINCS+.Sign(EK_sk, gamma || ct || c)`
///
/// - `ek_sk`: ephemeral secret key
/// - `gamma`: verification response hash (32 bytes)
/// - `ct`: Kyber ciphertext
/// - `challenge`: verifier challenge bytes
pub fn sign_cdbrw_response(
    ek_sk: &[u8],
    gamma: &[u8; 32],
    ct: &[u8],
    challenge: &[u8],
) -> Result<Vec<u8>, DsmError> {
    let mut msg = Vec::with_capacity(32 + ct.len() + challenge.len());
    msg.extend_from_slice(gamma);
    msg.extend_from_slice(ct);
    msg.extend_from_slice(challenge);
    sign(SphincsVariant::SPX256f, ek_sk, &msg)
}

pub fn sign_cdbrw_response_with_context(
    h_n: &[u8; 32],
    c_pre: &[u8; 32],
    k_step: &[u8; 32],
    k_dbrw: &[u8; 32],
    gamma: &[u8; 32],
    ct: &[u8],
    challenge: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), DsmError> {
    let seed = derive_ephemeral_seed(h_n, c_pre, k_step, k_dbrw);
    let (ek_pk, ek_sk) = generate_ephemeral_keypair(&seed)?;
    let signature = sign_cdbrw_response(&ek_sk, gamma, ct, challenge)?;
    Ok((signature, ek_pk))
}

pub fn verify_cdbrw_response_signature(
    ek_pk: &[u8],
    gamma: &[u8; 32],
    ct: &[u8],
    challenge: &[u8],
    signature: &[u8],
) -> Result<bool, DsmError> {
    let mut msg = Vec::with_capacity(32 + ct.len() + challenge.len());
    msg.extend_from_slice(gamma);
    msg.extend_from_slice(ct);
    msg.extend_from_slice(challenge);
    sphincs_verify(ek_pk, &msg, signature)
}

/// Derive the Kyber step key from the shared secret.
///
/// `k_step = BLAKE3("DSM/kyber-ss\0" || ss)`
pub fn derive_kyber_step_key(shared_secret: &[u8]) -> [u8; 32] {
    let mut hasher = dsm_domain_hasher("DSM/kyber-ss");
    hasher.update(shared_secret);
    *hasher.finalize().as_bytes()
}

/// Derive deterministic coins for Kyber encapsulation.
///
/// `coins = BLAKE3("DSM/kyber-coins\0" || h_n || C_pre || DevID || K_DBRW)[0:32]`
pub fn derive_kyber_coins(
    h_n: &[u8; 32],
    c_pre: &[u8; 32],
    dev_id: &[u8; 32],
    k_dbrw: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = dsm_domain_hasher("DSM/kyber-coins");
    hasher.update(h_n);
    hasher.update(c_pre);
    hasher.update(dev_id);
    hasher.update(k_dbrw);
    *hasher.finalize().as_bytes()
}

// ================================= Tests ====================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ephemeral_seed_deterministic() {
        let h_n = [1u8; 32];
        let c_pre = [2u8; 32];
        let k_step = [3u8; 32];
        let k_dbrw = [4u8; 32];
        let s1 = derive_ephemeral_seed(&h_n, &c_pre, &k_step, &k_dbrw);
        let s2 = derive_ephemeral_seed(&h_n, &c_pre, &k_step, &k_dbrw);
        assert_eq!(s1, s2);
        assert_eq!(s1.len(), 32);
    }

    #[test]
    fn ephemeral_keypair_deterministic() {
        let seed = [0xABu8; 32];
        let (pk1, sk1) = generate_ephemeral_keypair(&seed).expect("keygen");
        let (pk2, sk2) = generate_ephemeral_keypair(&seed).expect("keygen");
        assert_eq!(pk1, pk2);
        assert_eq!(sk1, sk2);
    }

    #[test]
    fn kyber_step_key_deterministic() {
        let ss = [0xCDu8; 32];
        let k1 = derive_kyber_step_key(&ss);
        let k2 = derive_kyber_step_key(&ss);
        assert_eq!(k1, k2);
    }

    #[test]
    fn kyber_coins_deterministic() {
        let h_n = [1u8; 32];
        let c_pre = [2u8; 32];
        let dev_id = [3u8; 32];
        let k_dbrw = [4u8; 32];
        let c1 = derive_kyber_coins(&h_n, &c_pre, &dev_id, &k_dbrw);
        let c2 = derive_kyber_coins(&h_n, &c_pre, &dev_id, &k_dbrw);
        assert_eq!(c1, c2);
    }

    #[test]
    fn sign_and_verify_cdbrw_response_round_trip() {
        let h_n = [1u8; 32];
        let c_pre = [2u8; 32];
        let k_step = [3u8; 32];
        let k_dbrw = [4u8; 32];
        let gamma = [5u8; 32];
        let ciphertext = vec![6u8; 1088];
        let challenge = vec![7u8; 32];

        let (signature, ephemeral_pk) = sign_cdbrw_response_with_context(
            &h_n,
            &c_pre,
            &k_step,
            &k_dbrw,
            &gamma,
            &ciphertext,
            &challenge,
        )
        .expect("sign");

        assert!(verify_cdbrw_response_signature(
            &ephemeral_pk,
            &gamma,
            &ciphertext,
            &challenge,
            &signature
        )
        .expect("verify"));

        let bad_challenge = vec![8u8; 32];
        assert!(!verify_cdbrw_response_signature(
            &ephemeral_pk,
            &gamma,
            &ciphertext,
            &bad_challenge,
            &signature
        )
        .expect("verify bad challenge"));
    }
}
