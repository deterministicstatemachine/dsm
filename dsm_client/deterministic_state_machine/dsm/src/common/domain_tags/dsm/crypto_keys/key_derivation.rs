// SPDX-License-Identifier: MIT OR Apache-2.0

//! DSM namespace tags: key derivation and key material

pub const TAG_DSM_CERT_CHAIN_SK_AEAD: &str = "DSM/cert-chain-sk-aead";
/// Per-step ephemeral-key seed derivation (whitepaper §11.1/§12 Eq.14), keyed
/// by Smaster: `keyed-BLAKE3(Smaster, "DSM/ek/v1" || alg_id || chain_id || h_n
/// || C_pre || k_step)`.
pub const TAG_DSM_EK_V1: &str = "DSM/ek/v1";
pub const TAG_DSM_EK_CERT: &str = "DSM/ek-cert";
pub const TAG_DSM_HASH_MULTIPLE: &str = "DSM/hash-multiple";
/// Deterministic ML-KEM-768 encapsulation coins (whitepaper §12), keyed by
/// Smaster: `keyed-BLAKE3(Smaster, "DSM/kyber-coins/v1" || kyber_alg_id ||
/// recipient_kem_pub_hash || h_n || C_pre || DevID)`.
pub const TAG_DSM_KYBER_COINS_V1: &str = "DSM/kyber-coins/v1";
pub const TAG_DSM_KYBER_SS: &str = "DSM/kyber-ss";
pub const TAG_DSM_ML_KEM_KEYGEN_D: &str = "DSM/ml-kem-keygen-d";
pub const TAG_DSM_ML_KEM_KEYGEN_Z: &str = "DSM/ml-kem-keygen-z";
pub const TAG_DSM_ML_KEM_SEED: &str = "DSM/ml-kem-seed";
pub const TAG_DSM_NEXT_ENTROPY: &str = "DSM/next-entropy";
pub const TAG_DSM_SPHINCS_KDF: &str = "DSM/sphincs-kdf";
pub const TAG_DSM_SPHINCS_SEED: &str = "DSM/sphincs-seed";
pub const TAG_DSM_STEP_SALT: &str = "DSM/step-salt";
