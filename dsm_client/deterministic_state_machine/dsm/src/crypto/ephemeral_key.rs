// SPDX-License-Identifier: MIT OR Apache-2.0

//! SPHINCS+ per-step ephemeral key chain (whitepaper §11.1/§12).
//!
//! The per-step seed is keyed BLAKE3 keyed by the device master seed `Smaster`
//! (NOT HKDF — see §12 note on KDF primitives), over versioned, algorithm- and
//! chain-bound context. From it a per-step SPHINCS+ (SPX256f) keypair is
//! generated and certified by the previous signer (AK at step 0, else EK_n).
//! The per-step EK chain binds AUTHORSHIP only; anti-clone is supplied
//! separately by the secure-element attestation (see the anti-clone spec).
//!
//! # Domain Tags
//!
//! | Tag | Usage |
//! |-----|-------|
//! | `DSM/ek/v1\0` | Per-step ephemeral key seed (keyed by Smaster) |
//! | `DSM/kyber-coins/v1\0` | Deterministic ML-KEM-768 coins (keyed by Smaster) |
//! | `DSM/ek-cert\0` | Per-step ephemeral-key certification (whitepaper §11.1) |

use crate::crypto::blake3::{dsm_domain_hasher, dsm_domain_hasher_keyed};
use crate::crypto::sphincs::{generate_keypair_from_seed, sign, sphincs_verify, SphincsVariant};
use crate::types::error::DsmError;

/// Canonical per-step signature suite identifier (SPHINCS+ SPX256f), bound into
/// the EK seed context as `alg_id` per whitepaper §11.1 Eq.14.
pub const ALG_ID_SPX256F: &[u8] = b"SPX256f";
/// Canonical KEM suite identifier (ML-KEM-768), bound into the coins context as
/// `kyber_alg_id` per whitepaper §12.
pub const KYBER_ALG_ID_MLKEM768: &[u8] = b"ML-KEM-768";

/// Derive the per-step ephemeral key seed E_{n+1} (whitepaper §11.1/§12 Eq.14).
///
/// `E_{n+1} = keyed-BLAKE3(key = Smaster,
///            "DSM/ek/v1\0" || alg_id || chain_id || h_n || C_pre || k_step)`
///
/// - `s_master`: device master seed Smaster (the keyed-BLAKE3 key; the secret root)
/// - `alg_id`: per-step signature suite id (e.g. [`ALG_ID_SPX256F`])
/// - `chain_id`: relationship / chain identifier (32 bytes)
/// - `h_n`: current hash chain tip (32 bytes)
/// - `c_pre`: pre-commitment hash (32 bytes)
/// - `k_step`: Kyber step key derived from the shared secret (32 bytes)
pub fn derive_ephemeral_seed(
    s_master: &[u8; 32],
    alg_id: &[u8],
    chain_id: &[u8; 32],
    h_n: &[u8; 32],
    c_pre: &[u8; 32],
    k_step: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = dsm_domain_hasher_keyed(crate::common::domain_tags::TAG_DSM_EK_V1, s_master);
    hasher.update(alg_id);
    hasher.update(chain_id);
    hasher.update(h_n);
    hasher.update(c_pre);
    hasher.update(k_step);
    *hasher.finalize().as_bytes()
}

/// Generate an ephemeral SPHINCS+ keypair from a seed.
///
/// Uses SPX256f for fast keygen. Returns `(public_key, secret_key)`.
pub fn generate_ephemeral_keypair(seed: &[u8; 32]) -> Result<(Vec<u8>, Vec<u8>), DsmError> {
    let kp = generate_keypair_from_seed(SphincsVariant::SPX256f, seed)?;
    Ok((kp.public_key.clone(), kp.secret_key.clone()))
}

/// Derive the Kyber step key from the shared secret.
///
/// `k_step = BLAKE3("DSM/kyber-ss\0" || ss)`
pub fn derive_kyber_step_key(shared_secret: &[u8]) -> [u8; 32] {
    let mut hasher = dsm_domain_hasher(crate::common::domain_tags::TAG_DSM_KYBER_SS);
    hasher.update(shared_secret);
    *hasher.finalize().as_bytes()
}

/// Derive deterministic coins for ML-KEM-768 encapsulation (whitepaper §12).
///
/// `coins = keyed-BLAKE3(key = Smaster,
///   "DSM/kyber-coins/v1\0" || kyber_alg_id || recipient_kem_pub_hash || h_n || C_pre || DevID)`
///
/// - `s_master`: device master seed Smaster (the keyed-BLAKE3 key)
/// - `kyber_alg_id`: KEM suite id (e.g. [`KYBER_ALG_ID_MLKEM768`])
/// - `recipient_kem_pub_hash`: BLAKE3 of the recipient's KEM public key (32 bytes)
/// - `h_n`, `c_pre`: parent tip and pre-commitment (32 bytes each)
/// - `dev_id`: sender device id (32 bytes)
pub fn derive_kyber_coins(
    s_master: &[u8; 32],
    kyber_alg_id: &[u8],
    recipient_kem_pub_hash: &[u8; 32],
    h_n: &[u8; 32],
    c_pre: &[u8; 32],
    dev_id: &[u8; 32],
) -> [u8; 32] {
    let mut hasher =
        dsm_domain_hasher_keyed(crate::common::domain_tags::TAG_DSM_KYBER_COINS_V1, s_master);
    hasher.update(kyber_alg_id);
    hasher.update(recipient_kem_pub_hash);
    hasher.update(h_n);
    hasher.update(c_pre);
    hasher.update(dev_id);
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
    let mut hasher = dsm_domain_hasher(crate::common::domain_tags::TAG_DSM_EK_CERT);
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
        let s_master = [4u8; 32];
        let chain_id = [9u8; 32];
        let h_n = [1u8; 32];
        let c_pre = [2u8; 32];
        let k_step = [3u8; 32];
        let s1 = derive_ephemeral_seed(&s_master, ALG_ID_SPX256F, &chain_id, &h_n, &c_pre, &k_step);
        let s2 = derive_ephemeral_seed(&s_master, ALG_ID_SPX256F, &chain_id, &h_n, &c_pre, &k_step);
        assert_eq!(s1, s2);
        assert_eq!(s1.len(), 32);
    }

    #[test]
    fn ephemeral_seed_diverges_on_master_seed() {
        let chain_id = [9u8; 32];
        let h_n = [1u8; 32];
        let c_pre = [2u8; 32];
        let k_step = [3u8; 32];
        let a = derive_ephemeral_seed(&[4u8; 32], ALG_ID_SPX256F, &chain_id, &h_n, &c_pre, &k_step);
        let b = derive_ephemeral_seed(&[5u8; 32], ALG_ID_SPX256F, &chain_id, &h_n, &c_pre, &k_step);
        assert_ne!(
            a, b,
            "EK seed must depend on Smaster (the keyed-BLAKE3 key)"
        );
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
        let s_master = [4u8; 32];
        let recipient_kem_pub_hash = [7u8; 32];
        let h_n = [1u8; 32];
        let c_pre = [2u8; 32];
        let dev_id = [3u8; 32];
        let c1 = derive_kyber_coins(
            &s_master,
            KYBER_ALG_ID_MLKEM768,
            &recipient_kem_pub_hash,
            &h_n,
            &c_pre,
            &dev_id,
        );
        let c2 = derive_kyber_coins(
            &s_master,
            KYBER_ALG_ID_MLKEM768,
            &recipient_kem_pub_hash,
            &h_n,
            &c_pre,
            &dev_id,
        );
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
}
