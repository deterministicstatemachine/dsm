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
pub const TAG_DSM_ML_KEM_KEYGEN_D: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/ml-kem-keygen-d");
pub const TAG_DSM_ML_KEM_KEYGEN_Z: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/ml-kem-keygen-z");
pub const TAG_DSM_ML_KEM_SEED: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/ml-kem-seed");
pub const TAG_DSM_NEXT_ENTROPY: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/next-entropy");
pub const TAG_DSM_SPHINCS_KDF: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/sphincs-kdf");
pub const TAG_DSM_SPHINCS_SEED: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/sphincs-seed");
pub const TAG_DSM_STEP_SALT: TaggedHashDomain<'static> = crate::tagged_domain!(b"DSM/step-salt");

// --- Genesis v2 mnemonic-rooted key tree (mnemonic -> wallet_seed -> s0 -> Smaster) ---
// The canonical deterministic key tree. `s0`/`Smaster` are NEVER persisted; they are
// re-derived from the BIP39 wallet seed via the recovery path. Authorship + recovery
// continuity only — NOT anti-clone (a seed copy holds Smaster and can sign; anti-clone
// is the fused anchor).
/// `s0 = keyed-BLAKE3(wallet_seed, "DSM/s0/v2" || G || device_slot_id || authority_policy_hash)`.
pub const TAG_DSM_S0_V2: TaggedHashDomain<'static> = TaggedHashDomain::from_static(b"DSM/s0/v2");
/// `Smaster = keyed-BLAKE3(s0, "DSM/Smaster/v2" || G || DevID || authority_policy_hash)`.
pub const TAG_DSM_SMASTER_V2: TaggedHashDomain<'static> = crate::tagged_domain!(b"DSM/Smaster/v2");
/// `device_seed = keyed-BLAKE3(wallet_seed, "DSM/device-seed/v2" || G || device_slot_id)`.
pub const TAG_DSM_DEVICE_SEED_V2: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/device-seed/v2");
/// `AK_seed = keyed-BLAKE3(device_seed, "DSM/device-ak/v2" || authority_policy_hash)`;
/// the device signing/attestation keypair is `SPHINCS+.KeyGen(AK_seed)`. Derived from
/// `device_seed` (NOT Smaster) so it does not depend on DevID — DevID is
/// `H("DSM/devid" || AK_pk || AttA)`, which would otherwise be circular.
pub const TAG_DSM_DEVICE_AK_V2: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/device-ak/v2");
/// Device-birth attestation digest `AttA = keyed-BLAKE3(wallet_seed, "DSM/atta/v2" || G || device_slot)`.
/// `AttA` folds into `DevID = H("DSM/devid" || AK_pk || AttA)`. Deriving it deterministically from the
/// wallet seed makes `DevID` reproducible from the mnemonic alone (recovery), with NO silicon
/// fingerprint and NO random root. It is a NON-load-bearing lineage tag — anti-clone is the Boot
/// Fenced Fused Anchor alone (a seed copy reproduces `AttA`/`DevID` and that is acceptable).
pub const TAG_DSM_ATTA_V2: TaggedHashDomain<'static> = crate::tagged_domain!(b"DSM/atta/v2");
/// AEAD key for per-relationship chain-head SK storage at rest:
/// `K_at-rest = keyed-BLAKE3(s0, "DSM/chain-head-at-rest/v2" || G || DevID)`. Rooted in
/// `s0` (the recovery path), domain-separated from authorship (`Smaster`), so a copied
/// database is undecryptable without the wallet seed and a leak of one root does not
/// expose the other. Replaces the former C-DBRW binding key for SK-at-rest.
pub const TAG_DSM_CHAIN_HEAD_AT_REST_V2: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/chain-head-at-rest/v2");
