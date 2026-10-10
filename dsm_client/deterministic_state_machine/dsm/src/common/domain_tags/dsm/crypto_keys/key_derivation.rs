// SPDX-License-Identifier: MIT OR Apache-2.0

//! DSM namespace tags: key derivation and key material

use crate::crypto::domain::TaggedHashDomain;

pub const TAG_DSM_CERT_CHAIN_SK_AEAD: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/cert-chain-sk-aead");
/// Per-step ephemeral-key seed derivation (whitepaper §11.1/§12 Eq.14), keyed
/// by Smaster: `keyed-BLAKE3(Smaster, "DSM/ek/v1" || alg_id || chain_id || h_n
/// || C_pre || k_step)`.
pub const TAG_DSM_EK_V1: TaggedHashDomain<'static> = TaggedHashDomain::from_static(b"DSM/ek/v1");
pub const TAG_DSM_EK_CERT: TaggedHashDomain<'static> = crate::tagged_domain!(b"DSM/ek-cert");
pub const TAG_DSM_HASH_MULTIPLE: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/hash-multiple");
/// Deterministic ML-KEM-768 encapsulation coins (whitepaper §12), keyed by
/// Smaster: `keyed-BLAKE3(Smaster, "DSM/kyber-coins/v1" || kyber_alg_id ||
/// recipient_kem_pub_hash || h_n || C_pre || DevID)`.
pub const TAG_DSM_KYBER_COINS_V1: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/kyber-coins/v1");
/// Hash of the recipient ML-KEM public key folded into the deterministic coins
/// derivation: `recipient_kem_pub_hash = BLAKE3("DSM/kyber-recipient-pub/v1" || kem_pub)`.
pub const TAG_DSM_KYBER_RECIPIENT_PUB_V1: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/kyber-recipient-pub/v1");
pub const TAG_DSM_KYBER_SS: TaggedHashDomain<'static> = crate::tagged_domain!(b"DSM/kyber-ss");
/// The key a spool payload is sealed under (DSM Amendment A7):
/// `K = H(tag ‖ 0x00 ‖ shared_secret ‖ message_id)`, one per payload.
pub const TAG_DSM_SPOOL_SEAL: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/spool-seal/v1");
/// The cell a device's directory entries live in: `H(tag ‖ 0x00 ‖ genesis ‖ device_id)`.
pub const TAG_DSM_DEVICE_DIRECTORY_KEY: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/device-directory-key/v1");
/// The digest a device's AK signs for its own directory entry.
pub const TAG_DSM_DEVICE_DIRECTORY_ENTRY: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/device-directory-entry/v1");
pub const TAG_DSM_ML_KEM_KEYGEN_D: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/ml-kem-keygen-d");
pub const TAG_DSM_ML_KEM_KEYGEN_Z: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/ml-kem-keygen-z");
pub const TAG_DSM_ML_KEM_SEED: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/ml-kem-seed");
pub const TAG_DSM_NEXT_ENTROPY: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/next-entropy");
pub const TAG_DSM_SPHINCS_SEED: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/sphincs-seed");
pub const TAG_DSM_STEP_SALT: TaggedHashDomain<'static> = crate::tagged_domain!(b"DSM/step-salt");

// --- Key schedule KS1 (`core::identity::key_schedule`): Extract-then-Expand. ---
// Three Extracts under fixed protocol salts; every derivation is an Expand whose
// `info` starts with one of the labels below and 0x00. `s0`, `Smaster`, the
// device seed and the PRKs are NEVER persisted; they re-derive from the BIP39
// wallet seed. Authorship + recovery continuity only, NOT anti-clone (a seed
// copy holds Smaster and can sign; anti-clone is the fused anchor).
/// Extract salt at the wallet root: `PRK_w = Extract(this ‖ 0x00, wallet_seed)`.
pub const TAG_DSM_KDF_WALLET_ROOT_V1: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/kdf/wallet-root/v1");
/// Extract salt under the device seed: `PRK_d = Extract(this ‖ 0x00, device_seed)`.
pub const TAG_DSM_KDF_DEVICE_ROOT_V1: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/kdf/device-root/v1");
/// Extract salt under `s0`: `PRK_s0 = Extract(this ‖ 0x00, s0)`.
pub const TAG_DSM_KDF_S0_ROOT_V1: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/kdf/s0-root/v1");
/// `s0 = Expand(PRK_w, "DSM/s0/v3" ‖ 0x00 ‖ G ‖ device_slot ‖ authority_policy_hash)`.
pub const TAG_DSM_S0_V3: TaggedHashDomain<'static> = crate::tagged_domain!(b"DSM/s0/v3");
/// `Smaster = Expand(PRK_s0, "DSM/Smaster/v3" ‖ 0x00 ‖ G ‖ DevID ‖ authority_policy_hash)`.
pub const TAG_DSM_SMASTER_V3: TaggedHashDomain<'static> = crate::tagged_domain!(b"DSM/Smaster/v3");
/// `device_seed = Expand(PRK_w, "DSM/device-seed/v3" ‖ 0x00 ‖ G ‖ device_slot)`.
pub const TAG_DSM_DEVICE_SEED_V3: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/device-seed/v3");
/// `AK_seed = Expand(PRK_d, "DSM/device-ak/v3" ‖ 0x00 ‖ authority_policy_hash)`; the
/// device signing/attestation keypair is `SPHINCS+.KeyGen(AK_seed)`. Rooted in the
/// device seed (NOT Smaster) so it does not depend on DevID, which is
/// `H("DSM/devid" ‖ AK_pk ‖ AttA)` and would otherwise be circular.
pub const TAG_DSM_DEVICE_AK_V3: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/device-ak/v3");
/// Device-birth attestation digest `AttA = Expand(PRK_w, "DSM/atta/v3" ‖ 0x00 ‖ G ‖
/// device_slot)`. PUBLIC; folds into `DevID = H("DSM/devid" ‖ AK_pk ‖ AttA)`, so DevID is
/// reproducible from the mnemonic alone. A NON-load-bearing lineage tag: anti-clone is
/// the fused anchor alone.
pub const TAG_DSM_ATTA_V3: TaggedHashDomain<'static> = crate::tagged_domain!(b"DSM/atta/v3");
/// AEAD key for per-relationship chain-head SK storage at rest:
/// `K_at-rest = Expand(PRK_s0, "DSM/chain-head-at-rest/v3" ‖ 0x00 ‖ G ‖ DevID)`, a
/// sibling of Smaster under `s0`'s Extract: exposing it does not expose Smaster.
pub const TAG_DSM_CHAIN_HEAD_AT_REST_V3: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/chain-head-at-rest/v3");
/// SDK context entropy: `Expand(PRK_w, "DSM/sdk-entropy/v3" ‖ 0x00 ‖ DevID ‖ G)`.
pub const TAG_DSM_SDK_ENTROPY_V3: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/sdk-entropy/v3");
/// The recovery ring's AEAD key: `Expand(PRK_w, "DSM/recovery-aead/v2" ‖ 0x00)`.
pub const TAG_DSM_RECOVERY_AEAD_V2: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/recovery-aead/v2");
/// The recovery-authority SPHINCS+ seed: `Expand(PRK_w, "DSM/recovery-authority/v2" ‖ 0x00)`.
pub const TAG_DSM_RECOVERY_AUTHORITY_V2: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/recovery-authority/v2");
/// The ML-KEM identity seed, keyed by Smaster like the per-step EK seeds:
/// `keyed-BLAKE3(Smaster, "DSM/ml-kem-identity/v1" ‖ 0x00 ‖ "ML-KEM-768")`.
pub const TAG_DSM_ML_KEM_IDENTITY_V1: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/ml-kem-identity/v1");
