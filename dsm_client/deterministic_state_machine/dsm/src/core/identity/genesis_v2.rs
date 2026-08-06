// SPDX-License-Identifier: MIT OR Apache-2.0

//! Genesis v2 — the canonical mnemonic-rooted, deterministic key tree.
//!
//! Replaces the n-of-n commit-reveal / storage-node multipart-entropy genesis as the
//! DEFAULT path (that profile is retained as [`GenesisEntropyProfile::CommitRevealMpcV1`]
//! for optional high-assurance/legacy use). Genesis v2 needs no storage nodes and roots
//! the entire deterministic key tree in the device's BIP39 wallet seed:
//!
//! ```text
//! mnemonic -> wallet_seed
//!   genesis_nonce = KDF(wallet_seed, "DSM/genesis-public-nonce/v2" || network_id || wallet_index)   [PUBLIC]
//!   G            = H("DSM/genesis/v2" || genesis_nonce || network_id || genesis_version)
//!   s0           = KDF(wallet_seed, "DSM/s0/v2" || G || device_slot || authority_policy_hash)
//!   device_seed  = KDF(wallet_seed, "DSM/device-seed/v2" || G || device_slot)
//!   AK_seed      = KDF(device_seed, "DSM/device-ak/v2" || authority_policy_hash)
//!   AK keypair   = SPHINCS+.KeyGen(AK_seed)                 (device signing/attestation key)
//!   DevID        = H("DSM/devid" || AK_pk || AttA)
//!   Smaster      = KDF(s0, "DSM/Smaster/v2" || G || DevID || authority_policy_hash)
//! ```
//!
//! `genesis_nonce` is public (stored in the GenesisRecord) so `G` is deterministically
//! recoverable from the mnemonic WITHOUT exposing `wallet_seed`. The AK (signing) keypair
//! is rooted in `device_seed` (NOT `Smaster`) so it does not depend on `DevID` — `DevID`
//! folds `AK_pk`, which would otherwise be circular. `Smaster` roots authorship + recovery
//! continuity ONLY (per-step EK, deterministic ML-KEM coins, b0x salts); it is NEVER
//! persisted and re-derived from the wallet seed on demand. `Smaster` does NOT establish
//! anti-cloning — a seed copy holds it and can sign; anti-clone is the fused
//! Anchor alone.

use crate::crypto::domain::TaggedHashDomain;

use zeroize::Zeroize;

use crate::common::domain_tags::{
    TAG_DSM_DEVICE_AK_V2, TAG_DSM_DEVICE_SEED_V2, TAG_DSM_DEVID, TAG_DSM_GENESIS_NONCE_V2,
    TAG_DSM_GENESIS_V2, TAG_DSM_S0_V2, TAG_DSM_SMASTER_V2,
};
use crate::crypto::blake3::dsm_domain_hasher;
use crate::crypto::signatures::SignatureKeyPair;
use crate::types::error::DsmError;

/// Which entropy profile produced a genesis. `MnemonicV2` is canonical (Layer A);
/// `CommitRevealMpcV1` is the optional n-of-n storage-node ceremony retained for
/// high-assurance/legacy use. Ordinary wallet creation MUST NOT require storage nodes.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum GenesisEntropyProfile {
    /// Canonical: mnemonic-rooted, deterministic, no storage-node entropy.
    #[default]
    MnemonicV2,
    /// Optional: n-of-n commit-reveal multipart entropy (legacy / high-assurance).
    CommitRevealMpcV1,
}

/// HKDF-BLAKE3 KDF: `KDF(secret, "<domain>\0" , parts...) -> 32 bytes`. The domain tag
/// (terminated by `0x00`, mirroring `dsm_domain_hasher`) is the HKDF salt; `secret` is the
/// IKM (any length — `wallet_seed` is the 64-byte BIP39 seed); `parts` are the bound
/// context. Mirrors the master-seed family's use of `hkdf::extract_and_expand`.
fn kdf32(secret: &[u8], domain: TaggedHashDomain<'_>, parts: &[&[u8]]) -> [u8; 32] {
    debug_assert!(
        domain.source_bytes().starts_with(b"DSM/"),
        "domain tag must start with DSM/"
    );
    let mut salt = Vec::with_capacity(domain.source_bytes().len() + 1);
    salt.extend_from_slice(domain.source_bytes());
    salt.push(0u8);
    let mut info: Vec<u8> = Vec::new();
    for p in parts {
        info.extend_from_slice(p);
    }
    let mut okm = crate::crypto::hkdf::extract_and_expand(&salt, secret, &info, 32);
    let mut out = [0u8; 32];
    out.copy_from_slice(&okm);
    okm.zeroize();
    salt.zeroize();
    info.zeroize();
    out
}

/// Public genesis nonce — `KDF(wallet_seed, "DSM/genesis-public-nonce/v2" || network_id || wallet_index)`.
/// PUBLIC value stored in the GenesisRecord; makes `G` recoverable from the mnemonic
/// without exposing `wallet_seed`.
pub fn derive_genesis_nonce(wallet_seed: &[u8], network_id: &[u8], wallet_index: u32) -> [u8; 32] {
    kdf32(
        wallet_seed,
        TAG_DSM_GENESIS_NONCE_V2,
        &[network_id, &wallet_index.to_le_bytes()],
    )
}

/// Genesis digest `G = H("DSM/genesis/v2" || genesis_nonce || network_id || genesis_version)`.
/// Public + deterministic; folds only public inputs (the secret `wallet_seed`/`s0` are excluded).
pub fn derive_genesis_g(
    genesis_nonce: &[u8; 32],
    network_id: &[u8],
    genesis_version: u32,
) -> [u8; 32] {
    let mut h = dsm_domain_hasher(TAG_DSM_GENESIS_V2);
    h.update(genesis_nonce);
    h.update(network_id);
    h.update(&genesis_version.to_le_bytes());
    *h.finalize().as_bytes()
}

/// Secret root `s0 = KDF(wallet_seed, "DSM/s0/v2" || G || device_slot || authority_policy_hash)`.
/// NEVER persisted; re-derived from the wallet seed on demand.
pub fn derive_s0(
    wallet_seed: &[u8],
    g: &[u8; 32],
    device_slot: u32,
    authority_policy_hash: &[u8; 32],
) -> [u8; 32] {
    kdf32(
        wallet_seed,
        TAG_DSM_S0_V2,
        &[g, &device_slot.to_le_bytes(), authority_policy_hash],
    )
}

/// Device seed `device_seed = KDF(wallet_seed, "DSM/device-seed/v2" || G || device_slot)`.
/// Roots the device signing (AK) keypair — independent of `DevID` to break the
/// `DevID = H(... AK_pk ...)` circularity.
pub fn derive_device_seed(wallet_seed: &[u8], g: &[u8; 32], device_slot: u32) -> [u8; 32] {
    kdf32(
        wallet_seed,
        TAG_DSM_DEVICE_SEED_V2,
        &[g, &device_slot.to_le_bytes()],
    )
}

/// AK (device signing/attestation) seed `AK_seed = KDF(device_seed, "DSM/device-ak/v2" || authority_policy_hash)`.
pub fn derive_ak_seed(device_seed: &[u8; 32], authority_policy_hash: &[u8; 32]) -> [u8; 32] {
    kdf32(device_seed, TAG_DSM_DEVICE_AK_V2, &[authority_policy_hash])
}

/// Derive the device signing/attestation (AK) SPHINCS+ keypair:
/// `AK = SPHINCS+.KeyGen(AK_seed)`, `AK_seed = derive_ak_seed(derive_device_seed(wallet_seed, G, device_slot), authority_policy_hash)`.
///
/// The SINGLE canonical AK derivation, called by BOTH genesis ([`derive_genesis_v2`]) and SDK
/// re-derivation (wallet-init + recovery), so a re-derived key is byte-identical to the one
/// genesis registered. Rooted in `device_seed` (NOT `Smaster`) to avoid the DevID circularity.
/// `wallet_seed`/intermediate seeds are zeroized after use.
pub fn derive_device_ak_keypair(
    wallet_seed: &[u8],
    g: &[u8; 32],
    device_slot: u32,
    authority_policy_hash: &[u8; 32],
) -> Result<SignatureKeyPair, DsmError> {
    let mut device_seed = derive_device_seed(wallet_seed, g, device_slot);
    let mut ak_seed = derive_ak_seed(&device_seed, authority_policy_hash);
    device_seed.zeroize();
    let ak = SignatureKeyPair::generate_from_entropy(&ak_seed);
    ak_seed.zeroize();
    ak
}

/// Stable device identifier `DevID = H("DSM/devid" || AK_pk || AttA)` (whitepaper §2.4).
pub fn derive_devid(ak_pk: &[u8], atta: &[u8; 32]) -> [u8; 32] {
    let mut h = dsm_domain_hasher(TAG_DSM_DEVID);
    h.update(ak_pk);
    h.update(atta);
    *h.finalize().as_bytes()
}

/// Device-birth attestation digest `AttA = KDF(wallet_seed, "DSM/atta/v2" || G || device_slot)`.
///
/// `AttA` folds into `DevID`. Deriving it from the wallet seed makes `DevID` reproducible from the
/// mnemonic alone (recovery), with no silicon fingerprint and no random root. It is a NON-load-bearing
/// lineage tag; anti-clone is the fused anchor alone (a seed copy reproduces it, which is
/// acceptable). Public — may be stored in the GenesisRecord.
pub fn derive_atta(wallet_seed: &[u8], g: &[u8; 32], device_slot: u32) -> [u8; 32] {
    kdf32(
        wallet_seed,
        crate::common::domain_tags::TAG_DSM_ATTA_V2,
        &[g, &device_slot.to_le_bytes()],
    )
}

/// Master seed `Smaster = KDF(s0, "DSM/Smaster/v2" || G || DevID || authority_policy_hash)`.
/// Roots per-step EK seeds, deterministic ML-KEM coins, and ordinary deterministic wallet
/// material (authorship + recovery continuity). NEVER persisted; NOT an anti-clone primitive.
pub fn derive_smaster(
    s0: &[u8; 32],
    g: &[u8; 32],
    devid: &[u8; 32],
    authority_policy_hash: &[u8; 32],
) -> [u8; 32] {
    kdf32(s0, TAG_DSM_SMASTER_V2, &[g, devid, authority_policy_hash])
}

/// The full deterministic Genesis v2 derivation result. Secrets (`s0`, `smaster`,
/// `ak_secret`) are zeroized on drop.
#[derive(Clone, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct GenesisV2 {
    /// Public genesis nonce (store in GenesisRecord).
    #[zeroize(skip)]
    pub genesis_nonce: [u8; 32],
    /// Genesis digest `G`.
    #[zeroize(skip)]
    pub g: [u8; 32],
    /// Stable device id.
    #[zeroize(skip)]
    pub devid: [u8; 32],
    /// Device signing/attestation public key (SPHINCS+).
    #[zeroize(skip)]
    pub ak_public: Vec<u8>,
    /// Device signing/attestation secret key (SPHINCS+) — SECRET.
    pub ak_secret: Vec<u8>,
    /// Secret root `s0` — SECRET; do not persist.
    pub s0: [u8; 32],
    /// Master seed `Smaster` — SECRET; do not persist. Use for EK/ML-KEM/b0x derivations.
    pub smaster: [u8; 32],
}

/// Run the canonical Genesis v2 chain end to end from the BIP39 `wallet_seed`.
///
/// `network_id` / `wallet_index` / `device_slot` / `genesis_version` parameterize the public
/// genesis context; `authority_policy_hash` binds the device's authority policy; `atta` is the
/// platform attestation digest folded into `DevID`. Deterministic: identical inputs always
/// reproduce identical outputs (so signing + recovery re-derive without persistence).
#[allow(clippy::too_many_arguments)]
pub fn derive_genesis_v2(
    wallet_seed: &[u8],
    network_id: &[u8],
    wallet_index: u32,
    device_slot: u32,
    genesis_version: u32,
    authority_policy_hash: &[u8; 32],
    atta: &[u8; 32],
) -> Result<GenesisV2, DsmError> {
    if wallet_seed.is_empty() {
        return Err(DsmError::invalid_parameter(
            "genesis v2: wallet_seed is empty",
        ));
    }
    let genesis_nonce = derive_genesis_nonce(wallet_seed, network_id, wallet_index);
    let g = derive_genesis_g(&genesis_nonce, network_id, genesis_version);
    let s0 = derive_s0(wallet_seed, &g, device_slot, authority_policy_hash);

    let ak = derive_device_ak_keypair(wallet_seed, &g, device_slot, authority_policy_hash)?;

    let devid = derive_devid(&ak.public_key, atta);
    let smaster = derive_smaster(&s0, &g, &devid, authority_policy_hash);

    Ok(GenesisV2 {
        genesis_nonce,
        g,
        devid,
        ak_public: ak.public_key.clone(),
        ak_secret: ak.secret_key.clone(),
        s0,
        smaster,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEED: &[u8] = b"test-bip39-wallet-seed-64-bytes-............................xxxx";
    const NET: &[u8] = b"dsm-test";
    const APH: [u8; 32] = [0x11; 32];
    const ATTA: [u8; 32] = [0x22; 32];

    #[test]
    fn genesis_v2_is_deterministic() {
        let a = derive_genesis_v2(SEED, NET, 0, 0, 2, &APH, &ATTA).unwrap();
        let b = derive_genesis_v2(SEED, NET, 0, 0, 2, &APH, &ATTA).unwrap();
        assert_eq!(a.genesis_nonce, b.genesis_nonce);
        assert_eq!(a.g, b.g);
        assert_eq!(a.devid, b.devid);
        assert_eq!(a.ak_public, b.ak_public);
        assert_eq!(a.s0, b.s0);
        assert_eq!(a.smaster, b.smaster);
    }

    #[test]
    fn genesis_v2_diverges_on_wallet_seed() {
        let a = derive_genesis_v2(SEED, NET, 0, 0, 2, &APH, &ATTA).unwrap();
        let b = derive_genesis_v2(
            b"a-different-wallet-seed-of-some-length-................",
            NET,
            0,
            0,
            2,
            &APH,
            &ATTA,
        )
        .unwrap();
        assert_ne!(a.s0, b.s0);
        assert_ne!(a.smaster, b.smaster);
        assert_ne!(a.ak_public, b.ak_public);
        assert_ne!(a.g, b.g);
    }

    #[test]
    fn genesis_v2_diverges_on_device_slot() {
        let a = derive_genesis_v2(SEED, NET, 0, 0, 2, &APH, &ATTA).unwrap();
        let b = derive_genesis_v2(SEED, NET, 0, 1, 2, &APH, &ATTA).unwrap();
        // Same wallet => same G + genesis_nonce, but a distinct device under the same wallet.
        assert_eq!(a.g, b.g);
        assert_ne!(a.s0, b.s0);
        assert_ne!(a.ak_public, b.ak_public);
        assert_ne!(a.devid, b.devid);
    }

    #[test]
    fn smaster_is_not_the_ak_seed_and_devid_binds_ak_pk() {
        let v = derive_genesis_v2(SEED, NET, 0, 0, 2, &APH, &ATTA).unwrap();
        // DevID must recompute from AK_pk + AttA (no circular dependency on Smaster).
        assert_eq!(v.devid, derive_devid(&v.ak_public, &ATTA));
        // Smaster recomputes from s0 + G + DevID.
        assert_eq!(v.smaster, derive_smaster(&v.s0, &v.g, &v.devid, &APH));
    }

    #[test]
    fn empty_wallet_seed_rejected() {
        assert!(derive_genesis_v2(b"", NET, 0, 0, 2, &APH, &ATTA).is_err());
    }
}
