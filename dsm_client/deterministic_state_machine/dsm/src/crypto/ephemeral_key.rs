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
//! | `DSM/ek-cert\0` | Per-step ephemeral-key certification (whitepaper §11.1) |

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

// ============================ Ephemeral cert chain =============================
//
// Whitepaper §11.1 (Ephemeral certification, normative):
//
//     cert_{n+1} = Sign_{SK_n}( BLAKE3-256("DSM/ek-cert\0" || EK_pk_{n+1} || h_n) )
//
// Each per-step ephemeral SPHINCS+ key is certified by the previous signer
// (AK for n=0, else EK_n). Verification replays the chain back to AK_pk and
// checks Device-Tree inclusion of the AK-bound DevID. This is what gives a
// receipt verifier cryptographic AK-rooted authorization for the per-step
// ephemeral that signed the receipt body.
//
// Placement: the cert is carried in the receipt envelope, not in the
// canonical ReceiptCommit form (whose 10-field list is frozen by §4.2.1).

/// Compute the certification hash:
/// `BLAKE3-256("DSM/ek-cert\0" || EK_pk_{n+1} || h_n)`.
pub fn derive_ek_cert_hash(ek_pk_next: &[u8], h_n: &[u8; 32]) -> [u8; 32] {
    let mut hasher = dsm_domain_hasher("DSM/ek-cert");
    hasher.update(ek_pk_next);
    hasher.update(h_n);
    *hasher.finalize().as_bytes()
}

/// Sign a cert for the next step's ephemeral key with the previous signer's
/// secret key (AK at n=0, else EK_n). Uses SPHINCS+ SPX256f per §11.1.
pub fn sign_ek_cert(
    prev_sk: &[u8],
    ek_pk_next: &[u8],
    h_n: &[u8; 32],
) -> Result<Vec<u8>, DsmError> {
    let cert_hash = derive_ek_cert_hash(ek_pk_next, h_n);
    sign(SphincsVariant::SPX256f, prev_sk, &cert_hash)
}

/// Verify a cert for the next step's ephemeral key against the previous
/// signer's public key (AK at n=0, else EK_n).
pub fn verify_ek_cert(
    prev_pk: &[u8],
    ek_pk_next: &[u8],
    h_n: &[u8; 32],
    cert: &[u8],
) -> Result<bool, DsmError> {
    let cert_hash = derive_ek_cert_hash(ek_pk_next, h_n);
    sphincs_verify(prev_pk, &cert_hash, cert)
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
    fn ek_cert_hash_deterministic() {
        let ek_pk = [0xAAu8; 64];
        let h_n = [0x55u8; 32];
        let h1 = derive_ek_cert_hash(&ek_pk, &h_n);
        let h2 = derive_ek_cert_hash(&ek_pk, &h_n);
        assert_eq!(h1, h2);
    }

    #[test]
    fn ek_cert_hash_diverges_on_pk_change() {
        let h_n = [0x55u8; 32];
        let h_pk1 = derive_ek_cert_hash(&[0x01u8; 64], &h_n);
        let h_pk2 = derive_ek_cert_hash(&[0x02u8; 64], &h_n);
        assert_ne!(h_pk1, h_pk2);
    }

    #[test]
    fn ek_cert_hash_diverges_on_parent_tip_change() {
        let ek_pk = [0xAAu8; 64];
        let h_a = derive_ek_cert_hash(&ek_pk, &[0x11u8; 32]);
        let h_b = derive_ek_cert_hash(&ek_pk, &[0x22u8; 32]);
        assert_ne!(h_a, h_b);
    }

    /// Whitepaper §11.1 ephemeral cert round-trip: signer SK_n certifies
    /// EK_pk_{n+1} bound to h_n; verifier checks against the signer's PK.
    #[test]
    fn ek_cert_sign_and_verify_round_trip() {
        // Generate the "previous signer" keypair (the AK or EK_n).
        let prev_seed = [0x11u8; 32];
        let (prev_pk, prev_sk) = generate_ephemeral_keypair(&prev_seed).expect("prev keygen");

        // Generate the "next" ephemeral keypair to be certified.
        let next_seed = [0x22u8; 32];
        let (next_pk, _) = generate_ephemeral_keypair(&next_seed).expect("next keygen");

        let h_n = [0x33u8; 32];

        let cert = sign_ek_cert(&prev_sk, &next_pk, &h_n).expect("sign cert");
        assert!(verify_ek_cert(&prev_pk, &next_pk, &h_n, &cert).expect("verify cert"));
    }

    /// A cert valid for one parent tip MUST NOT verify under a different
    /// parent tip — the cert's binding to h_n is what links the per-step
    /// EK to a specific position in the chain.
    #[test]
    fn ek_cert_rejects_wrong_parent_tip() {
        let prev_seed = [0x11u8; 32];
        let (prev_pk, prev_sk) = generate_ephemeral_keypair(&prev_seed).expect("prev keygen");
        let next_seed = [0x22u8; 32];
        let (next_pk, _) = generate_ephemeral_keypair(&next_seed).expect("next keygen");

        let h_n = [0x33u8; 32];
        let h_other = [0x44u8; 32];

        let cert = sign_ek_cert(&prev_sk, &next_pk, &h_n).expect("sign cert");
        assert!(!verify_ek_cert(&prev_pk, &next_pk, &h_other, &cert).expect("verify cert"));
    }

    /// A cert MUST NOT verify under a substituted EK_pk — the cert binds
    /// EK_pk_{n+1} cryptographically; substituting another key fails.
    #[test]
    fn ek_cert_rejects_substituted_ek_pk() {
        let prev_seed = [0x11u8; 32];
        let (prev_pk, prev_sk) = generate_ephemeral_keypair(&prev_seed).expect("prev keygen");
        let real_seed = [0x22u8; 32];
        let (real_pk, _) = generate_ephemeral_keypair(&real_seed).expect("real keygen");
        let attacker_seed = [0x99u8; 32];
        let (attacker_pk, _) = generate_ephemeral_keypair(&attacker_seed).expect("attacker keygen");

        let h_n = [0x33u8; 32];
        let cert = sign_ek_cert(&prev_sk, &real_pk, &h_n).expect("sign cert");
        assert!(!verify_ek_cert(&prev_pk, &attacker_pk, &h_n, &cert).expect("verify"));
    }

    /// A cert signed by an unauthorized SK MUST NOT verify against the
    /// expected previous-signer PK. This is the core forgery resistance
    /// the cert chain provides.
    #[test]
    fn ek_cert_rejects_unauthorized_signer() {
        let real_prev_seed = [0x11u8; 32];
        let (real_prev_pk, _) = generate_ephemeral_keypair(&real_prev_seed).expect("real keygen");
        let attacker_seed = [0x99u8; 32];
        let (_, attacker_sk) = generate_ephemeral_keypair(&attacker_seed).expect("attacker keygen");

        let next_seed = [0x22u8; 32];
        let (next_pk, _) = generate_ephemeral_keypair(&next_seed).expect("next keygen");

        let h_n = [0x33u8; 32];
        let forged_cert = sign_ek_cert(&attacker_sk, &next_pk, &h_n).expect("sign forged cert");
        assert!(!verify_ek_cert(&real_prev_pk, &next_pk, &h_n, &forged_cert).expect("verify"));
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
