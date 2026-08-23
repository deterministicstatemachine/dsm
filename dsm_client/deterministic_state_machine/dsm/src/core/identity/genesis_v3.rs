// SPDX-License-Identifier: MIT OR Apache-2.0

//! Genesis v3 — the GRK-rooted identity.
//!
//! Identical to the v2 key tree in every derivation downstream of `G`; what
//! changes is `G` itself, which now commits a **Genesis Root Key**:
//!
//! ```text
//! mnemonic -> wallet_seed
//!   genesis_nonce = KDF(wallet_seed, "DSM/genesis-public-nonce/v2" || network_id || wallet_index)   [PUBLIC]
//!   GRK_seed      = KDF(wallet_seed, "DSM/genesis-root-authority/v1"
//!                                    || network_id || wallet_index || genesis_version)
//!   GRK           = SPHINCS+.KeyGen(GRK_seed)              (root authority; signs delegations ONLY)
//!   G             = H_dom("DSM/genesis/v3", CCB(GenesisParamsV3))
//!   ... s0 / device_seed / AK / AttA / DevID / Smaster exactly as v2, folding the new G
//! ```
//!
//! ## Why the GRK exists, and why it sits where it sits
//!
//! The v2 tree is strictly ordered `wallet_seed → genesis_nonce → G →
//! device_seed → AK → DevID`: every device-scoped key already depends on `G`,
//! so folding `AK_pk` into `G`'s preimage is circular **by construction**. The
//! GRK is the pre-genesis role that constraint forces. A verifier holding
//! `g_o` authenticates `GRK_pk` by recomputing `G` — nothing else — which is
//! the non-circular `g_o → R_G` edge.
//!
//! [`derive_grk_seed`] takes **no `g` parameter**. That is the structural form
//! of the non-circularity proof obligation: the circular derivation is
//! unwritable, not merely unwritten.
//!
//! ## Role constraint
//!
//! The GRK is **not** a device key, not a recovery key, not an anti-clone key,
//! and not a spending key. It signs Device Tree root-progression delegations
//! and nothing else. A GRK signature must never be accepted as owner authority
//! for a value operation, and the GRK must never appear as a device leaf.
//!
//! ## No migration
//!
//! A v2 identity cannot be upgraded: its `G` is a hash of a preimage that
//! contained no key, and no later act can make it commit one. Re-provision
//! under `genesis_version >= 3`. This is a fact about hashing, not a policy.

use zeroize::Zeroize;

use crate::ccb::{genesis_v3_commitment, sigalg, GenesisParamsV3};
use crate::common::domain_tags::TAG_DSM_GENESIS_ROOT_AUTHORITY_V1;
use crate::core::identity::genesis_v2::{
    derive_atta, derive_device_ak_keypair, derive_devid, derive_genesis_nonce, derive_s0,
    derive_smaster, kdf32,
};
use crate::crypto::signatures::SignatureKeyPair;
use crate::types::error::DsmError;

/// `GRK_seed = KDF(wallet_seed, "DSM/genesis-root-authority/v1" ‖ network_id
/// ‖ wallet_index ‖ genesis_version)`.
///
/// **No `g` parameter, deliberately** — see the module docs. `genesis_version`
/// is a plain caller parameter, not a derivative of `G`, so including it keeps
/// the graph acyclic while making the GRK per-identity: without it, one
/// mnemonic would reuse the same root authority across v3 and any future v4,
/// and re-provisioning would not re-root the thing it exists to re-root.
///
/// Integer encodings match the sibling derivations in this family
/// (`derive_genesis_nonce` et al.): little-endian.
pub fn derive_grk_seed(
    wallet_seed: &[u8],
    network_id: &[u8],
    wallet_index: u32,
    genesis_version: u32,
) -> [u8; 32] {
    kdf32(
        wallet_seed,
        TAG_DSM_GENESIS_ROOT_AUTHORITY_V1,
        &[
            network_id,
            &wallet_index.to_le_bytes(),
            &genesis_version.to_le_bytes(),
        ],
    )
}

/// Derive the Genesis Root Key pair: `GRK = SPHINCS+.KeyGen(GRK_seed)`.
///
/// Deterministic, so the GRK is fully re-derivable from the mnemonic alone —
/// it survives device loss with no additional backup artifact. The seed is
/// zeroized after keygen; the secret key is **never persisted**, re-derived on
/// demand exactly like `s0` and `Smaster`.
pub fn derive_grk_keypair(
    wallet_seed: &[u8],
    network_id: &[u8],
    wallet_index: u32,
    genesis_version: u32,
) -> Result<SignatureKeyPair, DsmError> {
    let mut seed = derive_grk_seed(wallet_seed, network_id, wallet_index, genesis_version);
    let kp = SignatureKeyPair::generate_from_entropy(&seed);
    seed.zeroize();
    kp
}

/// The full deterministic Genesis v3 derivation result. Secrets are zeroized
/// on drop.
#[derive(Clone, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct GenesisV3 {
    /// Public genesis nonce (store in the GenesisRecord).
    #[zeroize(skip)]
    pub genesis_nonce: [u8; 32],
    /// Genesis digest `G` — commits `GRK_pk`.
    #[zeroize(skip)]
    pub g: [u8; 32],
    /// Genesis Root Key public half (SPHINCS+ SPX256f, 64 bytes).
    #[zeroize(skip)]
    pub grk_public: Vec<u8>,
    /// Genesis Root Key secret half — SECRET; never persisted; signs
    /// root-progression delegations only.
    pub grk_secret: Vec<u8>,
    /// Stable device id.
    #[zeroize(skip)]
    pub devid: [u8; 32],
    /// Device signing/attestation public key (SPHINCS+).
    #[zeroize(skip)]
    pub ak_public: Vec<u8>,
    /// Device signing/attestation secret key — SECRET.
    pub ak_secret: Vec<u8>,
    /// Secret root `s0` — SECRET; do not persist.
    pub s0: [u8; 32],
    /// Master seed `Smaster` — SECRET; do not persist.
    pub smaster: [u8; 32],
}

/// Run the canonical Genesis v3 chain end to end from the BIP39 `wallet_seed`.
///
/// Refuses `genesis_version < 3` fail-closed: a v3-preimage `G` claiming an
/// earlier version would be a well-formed encoding of a contradiction.
#[allow(clippy::too_many_arguments)]
pub fn derive_genesis_v3(
    wallet_seed: &[u8],
    network_id: &[u8],
    wallet_index: u32,
    device_slot: u32,
    genesis_version: u32,
    authority_policy_hash: &[u8; 32],
    atta: &[u8; 32],
) -> Result<GenesisV3, DsmError> {
    if wallet_seed.is_empty() {
        return Err(DsmError::invalid_parameter(
            "genesis v3: wallet_seed is empty",
        ));
    }
    if genesis_version < 3 {
        return Err(DsmError::invalid_parameter(format!(
            "genesis v3: genesis_version must be >= 3, got {genesis_version}"
        )));
    }

    // Pre-genesis material: the nonce (v2 derivation, unchanged) and the GRK.
    // Neither depends on `G`, which does not exist yet.
    let genesis_nonce = derive_genesis_nonce(wallet_seed, network_id, wallet_index);
    let grk = derive_grk_keypair(wallet_seed, network_id, wallet_index, genesis_version)?;

    // G commits the exact GRK public key through the CCB object.
    let params = GenesisParamsV3::new(
        genesis_nonce,
        network_id,
        genesis_version,
        sigalg::SPHINCS_PLUS_SPX256F,
        &grk.public_key,
    )
    .map_err(|e| DsmError::invalid_parameter(format!("genesis v3: {e}")))?;
    let g = genesis_v3_commitment(&params)
        .map_err(|e| DsmError::invalid_parameter(format!("genesis v3: {e}")))?;

    // Downstream of G, the tree is the v2 tree verbatim.
    let s0 = derive_s0(wallet_seed, &g, device_slot, authority_policy_hash);
    let ak = derive_device_ak_keypair(wallet_seed, &g, device_slot, authority_policy_hash)?;
    let devid = derive_devid(&ak.public_key, atta);
    let smaster = derive_smaster(&s0, &g, &devid, authority_policy_hash);

    Ok(GenesisV3 {
        genesis_nonce,
        g,
        grk_public: grk.public_key.clone(),
        grk_secret: grk.secret_key.clone(),
        devid,
        ak_public: ak.public_key.clone(),
        ak_secret: ak.secret_key.clone(),
        s0,
        smaster,
    })
}

/// Genesis v3 with a self-derived (recoverable) `AttA`, mirroring
/// [`crate::core::identity::genesis::create_genesis_v2_self_attested`]: the
/// only secret input is the BIP39 `wallet_seed`.
pub fn derive_genesis_v3_self_attested(
    wallet_seed: &[u8],
    network_id: &[u8],
    wallet_index: u32,
    device_slot: u32,
    genesis_version: u32,
    authority_policy_hash: &[u8; 32],
) -> Result<GenesisV3, DsmError> {
    // AttA folds G, so G must exist first — but AttA is not an input to G,
    // so the two-pass shape here is ordering, not circularity. Derive the
    // pre-genesis material, compute G, then AttA, then the full chain.
    if genesis_version < 3 {
        return Err(DsmError::invalid_parameter(format!(
            "genesis v3: genesis_version must be >= 3, got {genesis_version}"
        )));
    }
    let genesis_nonce = derive_genesis_nonce(wallet_seed, network_id, wallet_index);
    let grk = derive_grk_keypair(wallet_seed, network_id, wallet_index, genesis_version)?;
    let params = GenesisParamsV3::new(
        genesis_nonce,
        network_id,
        genesis_version,
        sigalg::SPHINCS_PLUS_SPX256F,
        &grk.public_key,
    )
    .map_err(|e| DsmError::invalid_parameter(format!("genesis v3: {e}")))?;
    let g = genesis_v3_commitment(&params)
        .map_err(|e| DsmError::invalid_parameter(format!("genesis v3: {e}")))?;
    let atta = derive_atta(wallet_seed, &g, device_slot);
    derive_genesis_v3(
        wallet_seed,
        network_id,
        wallet_index,
        device_slot,
        genesis_version,
        authority_policy_hash,
        &atta,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEED: &[u8] = b"test-bip39-wallet-seed-64-bytes-............................xxxx";
    const NET: &[u8] = b"dsm-test";
    const APH: [u8; 32] = [0x11; 32];

    /// Proof obligation: recoverability. The GRK re-derived from the mnemonic
    /// alone is byte-identical to the one genesis committed.
    #[test]
    fn grk_is_recoverable_from_the_seed_alone() {
        let a = derive_grk_keypair(SEED, NET, 0, 3).expect("grk");
        let b = derive_grk_keypair(SEED, NET, 0, 3).expect("grk");
        assert_eq!(a.public_key, b.public_key);
        assert_eq!(a.secret_key, b.secret_key);
        assert_eq!(a.public_key.len(), 64, "SPX256f pk is 64 bytes");
    }

    /// Proof obligation: version binding. The same mnemonic, network and
    /// wallet index under versions 3 and 4 produce different GRK keypairs —
    /// otherwise a v3-compromised GRK would carry into a v4 identity and
    /// re-provisioning would re-root nothing.
    #[test]
    fn genesis_version_binds_the_grk() {
        let v3 = derive_grk_keypair(SEED, NET, 0, 3).expect("grk");
        let v4 = derive_grk_keypair(SEED, NET, 0, 4).expect("grk");
        assert_ne!(v3.public_key, v4.public_key);
    }

    /// Proof obligation: genesis binding is sensitive to the key. Flipping
    /// one byte of `GRK_pk` changes `G`.
    #[test]
    fn flipping_one_grk_pk_byte_changes_g() {
        let nonce = derive_genesis_nonce(SEED, NET, 0);
        let grk = derive_grk_keypair(SEED, NET, 0, 3).expect("grk");
        let params =
            GenesisParamsV3::new(nonce, NET, 3, sigalg::SPHINCS_PLUS_SPX256F, &grk.public_key)
                .expect("params");
        let g = genesis_v3_commitment(&params).expect("g");

        let mut flipped = grk.public_key.clone();
        flipped[0] ^= 0x01;
        let params2 = GenesisParamsV3::new(nonce, NET, 3, sigalg::SPHINCS_PLUS_SPX256F, &flipped)
            .expect("params");
        let g2 = genesis_v3_commitment(&params2).expect("g");
        assert_ne!(g, g2);
    }

    /// The whole chain is deterministic, and its `G` differs from v2's for
    /// identical inputs — different domain, and a key in the preimage.
    #[test]
    fn v3_is_deterministic_and_distinct_from_v2() {
        let a = derive_genesis_v3_self_attested(SEED, NET, 0, 0, 3, &APH).expect("v3");
        let b = derive_genesis_v3_self_attested(SEED, NET, 0, 0, 3, &APH).expect("v3");
        assert_eq!(a.g, b.g);
        assert_eq!(a.devid, b.devid);
        assert_eq!(a.grk_public, b.grk_public);

        let nonce = derive_genesis_nonce(SEED, NET, 0);
        let v2_g = crate::core::identity::genesis_v2::derive_genesis_g(&nonce, NET, 3);
        assert_ne!(a.g, v2_g, "same inputs must not collide across versions");
    }

    /// `genesis_version < 3` is refused fail-closed, on both entry points.
    #[test]
    fn pre_v3_versions_are_refused() {
        assert!(derive_genesis_v3(SEED, NET, 0, 0, 2, &APH, &[0x22; 32]).is_err());
        assert!(derive_genesis_v3_self_attested(SEED, NET, 0, 0, 2, &APH).is_err());
    }

    /// A mis-sized key is refused by the CCB constructor rather than encoded.
    #[test]
    fn a_wrong_length_key_is_refused() {
        let nonce = derive_genesis_nonce(SEED, NET, 0);
        assert!(
            GenesisParamsV3::new(nonce, NET, 3, sigalg::SPHINCS_PLUS_SPX256F, &[0u8; 32]).is_err(),
            "32 bytes is not a SPX256f public key"
        );
        assert!(
            GenesisParamsV3::new(nonce, NET, 3, 0x0002, &[0u8; 64]).is_err(),
            "0x0002 is not a declared signature_alg"
        );
    }
}
