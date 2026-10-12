// SPDX-License-Identifier: MIT OR Apache-2.0

//! Genesis v2 — the mnemonic-rooted, deterministic key tree. Every secret in it
//! comes from the BIP39 wallet seed through key schedule KS1
//! ([`crate::core::identity::key_schedule`]), one Extract at the wallet root and
//! labelled Expands below it:
//!
//! ```text
//! mnemonic -> wallet_seed ; PRK_w = Extract("DSM/kdf/wallet-root/v1", wallet_seed)
//!   genesis_nonce = Expand(PRK_w, "DSM/genesis-public-nonce/v3" ‖ lp(network_id) ‖ wallet_index)   [PUBLIC]
//!   G            = H("DSM/genesis/v2" || genesis_nonce || network_id || genesis_version)
//!   s0           = Expand(PRK_w, "DSM/s0/v3" ‖ G ‖ device_slot ‖ authority_policy_hash)
//!   device_seed  = Expand(PRK_w, "DSM/device-seed/v3" ‖ G ‖ device_slot)
//!   AK_seed      = Expand(Extract("DSM/kdf/device-root/v1", device_seed), "DSM/device-ak/v3" ‖ aph)
//!   AK keypair   = SPHINCS+.KeyGen(AK_seed)                 (device signing/attestation key)
//!   DevID        = H("DSM/devid" || AK_pk || AttA)
//!   Smaster      = Expand(Extract("DSM/kdf/s0-root/v1", s0), "DSM/Smaster/v3" ‖ G ‖ DevID ‖ aph)
//! ```
//!
//! `genesis_nonce` is public (stored in the GenesisRecord) so `G` is deterministically
//! recoverable from the mnemonic WITHOUT exposing `wallet_seed`. The AK (signing) keypair
//! is rooted in `device_seed` (NOT `Smaster`) so it does not depend on `DevID` — `DevID`
//! folds `AK_pk`, which would otherwise be circular. `Smaster` roots authorship + recovery
//! continuity ONLY (per-step EK, the ML-KEM identity key and coins); it is NEVER
//! persisted and re-derived from the wallet seed on demand. `Smaster` does NOT establish
//! anti-cloning — a seed copy holds it and can sign; anti-clone is the fused
//! Anchor alone.
//!
//! Before KS1 every node here was `HKDF(salt = its domain tag, IKM = parent secret)`; see
//! `key_schedule` for why that was replaced. Identities derived that way are not migrated.

use zeroize::Zeroize;

use crate::common::domain_tags::{TAG_DSM_DEVID, TAG_DSM_GENESIS_V2};
use crate::core::identity::key_schedule;
use crate::crypto::blake3::dsm_domain_hasher;
use crate::crypto::signatures::SignatureKeyPair;
use crate::types::error::DsmError;

/// Which derivation produced a genesis. Both are mnemonic-rooted and
/// deterministic, and both derive every secret through key schedule KS1.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum GenesisEntropyProfile {
    /// Genesis v2: `G` commits the public nonce, network and version.
    #[default]
    MnemonicV2,
    /// Genesis v3: `G` commits the Genesis Root Key.
    MnemonicV3,
}

/// Canonical hash of the genesis-time authority policy, bound into `Smaster`
/// as public context. The genesis policy is the default self-sovereign,
/// online-checked policy (no offline anchor pinned; enrollment happens later
/// through a transition, without re-deriving `Smaster`).
pub fn genesis_authority_policy_hash() -> [u8; 32] {
    use crate::types::operations::{AuthorityMode, AuthorityPolicy};
    let default = AuthorityPolicy {
        mode: AuthorityMode::OnlineChecked,
        policy_id: [0u8; 32],
        anchor_set_id: [0u8; 32],
    };
    let mut bytes = Vec::new();
    default.append_canonical(&mut bytes);
    let mut h =
        crate::crypto::blake3::dsm_domain_hasher(crate::tagged_domain!(b"DSM/authority-policy/v1"));
    h.update(&bytes);
    *h.finalize().as_bytes()
}

/// Public genesis nonce — `Expand(PRK_w, "DSM/genesis-public-nonce/v3" ‖ lp(network_id) ‖ wallet_index)` (KS1).
/// PUBLIC value stored in the GenesisRecord; makes `G` recoverable from the mnemonic
/// without exposing `wallet_seed`.
pub fn derive_genesis_nonce(wallet_seed: &[u8], network_id: &[u8], wallet_index: u32) -> [u8; 32] {
    key_schedule::genesis_nonce(
        &key_schedule::wallet_prk(wallet_seed),
        network_id,
        wallet_index,
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

/// Secret root `s0 = Expand(PRK_w, "DSM/s0/v3" ‖ G ‖ device_slot ‖ authority_policy_hash)` (KS1).
/// NEVER persisted; re-derived from the wallet seed on demand.
pub fn derive_s0(
    wallet_seed: &[u8],
    g: &[u8; 32],
    device_slot: u32,
    authority_policy_hash: &[u8; 32],
) -> [u8; 32] {
    key_schedule::s0(
        &key_schedule::wallet_prk(wallet_seed),
        g,
        device_slot,
        authority_policy_hash,
    )
}

/// Device seed `device_seed = Expand(PRK_w, "DSM/device-seed/v3" ‖ G ‖ device_slot)` (KS1).
/// Roots the device signing (AK) keypair — independent of `DevID` to break the
/// `DevID = H(... AK_pk ...)` circularity.
pub fn derive_device_seed(wallet_seed: &[u8], g: &[u8; 32], device_slot: u32) -> [u8; 32] {
    key_schedule::device_seed(&key_schedule::wallet_prk(wallet_seed), g, device_slot)
}

/// AK (device signing/attestation) seed
/// `AK_seed = Expand(Extract("DSM/kdf/device-root/v1", device_seed), "DSM/device-ak/v3" ‖ aph)` (KS1).
pub fn derive_ak_seed(device_seed: &[u8; 32], authority_policy_hash: &[u8; 32]) -> [u8; 32] {
    key_schedule::ak_seed(device_seed, authority_policy_hash)
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

/// Device-birth attestation digest `AttA = Expand(PRK_w, "DSM/atta/v3" ‖ G ‖ device_slot)` (KS1).
///
/// `AttA` folds into `DevID`. Deriving it from the wallet seed makes `DevID` reproducible from the
/// mnemonic alone (recovery), with no silicon fingerprint and no random root. It is a NON-load-bearing
/// lineage tag; anti-clone is the fused anchor alone (a seed copy reproduces it, which is
/// acceptable). Public — may be stored in the GenesisRecord.
pub fn derive_atta(wallet_seed: &[u8], g: &[u8; 32], device_slot: u32) -> [u8; 32] {
    key_schedule::atta(&key_schedule::wallet_prk(wallet_seed), g, device_slot)
}

/// Master seed `Smaster = Expand(Extract("DSM/kdf/s0-root/v1", s0), "DSM/Smaster/v3" ‖ G ‖ DevID ‖
/// aph)` (KS1). The keyed-BLAKE3 key of the per-step EK seeds, the ML-KEM identity key and the
/// ML-KEM coins, and of nothing else (authorship + recovery continuity). NEVER persisted; NOT an
/// anti-clone primitive.
pub fn derive_smaster(
    s0: &[u8; 32],
    g: &[u8; 32],
    devid: &[u8; 32],
    authority_policy_hash: &[u8; 32],
) -> [u8; 32] {
    key_schedule::smaster(s0, g, devid, authority_policy_hash)
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
