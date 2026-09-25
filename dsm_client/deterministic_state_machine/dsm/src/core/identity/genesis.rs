// SPDX-License-Identifier: MIT OR Apache-2.0

// File: dsm/src/core/identity/genesis.rs
//! The device's genesis state and its creation from the BIP39 wallet seed
//! (Genesis v3, mnemonic-rooted and self-attested).

use crate::types::error::DsmError;

#[derive(Debug, Clone, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct SigningKey {
    pub public_key: Vec<u8>,
    pub secret_key: Vec<u8>,
}

#[derive(Debug, Clone, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct KyberKey {
    pub public_key: Vec<u8>,
    pub secret_key: Vec<u8>,
}

/// A device's genesis: `G`, the public nonce it was derived under, the device
/// id, and the device's signing (AK) and Kyber keypairs, all re-derivable from
/// the wallet seed.
#[derive(Debug, Clone)]
pub struct GenesisState {
    /// `G`.
    pub hash: [u8; 32],
    /// The public genesis nonce `G` commits.
    pub genesis_nonce: [u8; 32],
    /// `DevID`.
    pub device_id: [u8; 32],
    pub signing_key: SigningKey,
    pub kyber_keypair: KyberKey,
}

impl zeroize::ZeroizeOnDrop for GenesisState {}
impl zeroize::Zeroize for GenesisState {
    fn zeroize(&mut self) {
        self.signing_key.zeroize();
        self.kyber_keypair.zeroize();
    }
}

impl std::fmt::Display for GenesisState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "GenesisState(hash={:?})", self.hash)
    }
}

/// Result of canonical genesis creation: the in-memory [`GenesisState`] plus the PUBLIC
/// `genesis_nonce` and the [`crate::core::identity::genesis_v2::GenesisEntropyProfile`] the
/// caller persists into the GenesisRecord (so `G` is recoverable from the mnemonic).
pub struct GenesisCreationOutcome {
    pub state: GenesisState,
    pub genesis_nonce: [u8; 32],
    pub profile: crate::core::identity::genesis_v2::GenesisEntropyProfile,
}

/// Canonical mnemonic-rooted **Genesis v3** with a self-derived (recoverable)
/// device-birth `AttA` — the SDK/Android wallet-creation entry point.
///
/// `G = H_dom(DSM/genesis/v3, CCB(GenesisParamsV3))` commits the Genesis Root
/// Key, so a foreign verifier can authenticate the owner's device-authority
/// chain from `G` alone (the P0–P6 predicate). Downstream of `G` the key tree
/// is the v2 tree verbatim: AK, DevID, `s0`, `Smaster`, Kyber. The GRK secret
/// is never persisted — like `s0`, it re-derives from the mnemonic on demand.
/// The only secret input is the BIP39 `wallet_seed`.
pub fn create_genesis_v3_self_attested(
    wallet_seed: &[u8],
    network_id: &[u8],
    wallet_index: u32,
    device_slot: u32,
    genesis_version: u32,
    authority_policy_hash: &[u8; 32],
) -> Result<GenesisCreationOutcome, DsmError> {
    let v3 = crate::core::identity::genesis_v3::derive_genesis_v3_self_attested(
        wallet_seed,
        network_id,
        wallet_index,
        device_slot,
        genesis_version,
        authority_policy_hash,
    )?;

    // ML-KEM (Kyber) keypair from Smaster — the same context the master-keypair derivation uses.
    let (kyber_public, kyber_secret) =
        crate::crypto::kyber::generate_kyber_keypair_from_entropy(&v3.smaster, "DSM/kyber\0")?;

    let state = GenesisState {
        hash: v3.g,
        genesis_nonce: v3.genesis_nonce,
        device_id: v3.devid,
        signing_key: SigningKey {
            public_key: v3.ak_public.clone(),
            secret_key: v3.ak_secret.clone(),
        },
        kyber_keypair: KyberKey {
            public_key: kyber_public,
            secret_key: kyber_secret,
        },
    };

    Ok(GenesisCreationOutcome {
        state,
        genesis_nonce: v3.genesis_nonce,
        profile: crate::core::identity::genesis_v2::GenesisEntropyProfile::MnemonicV3,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_genesis_v3_self_attested_is_deterministic_and_recoverable() {
        use crate::core::identity::genesis_v2::GenesisEntropyProfile;
        use crate::core::identity::genesis_v3::derive_genesis_v3_self_attested;
        let seed = b"bip39-wallet-seed-self-attested-test-............................";
        let net = b"dsm-test";
        let aph = [0x33u8; 32];

        // The canonical Android/SDK wallet-creation entry: only the wallet seed is secret.
        let a =
            create_genesis_v3_self_attested(seed, net, 0, 0, 3, &aph).expect("self-attested v3");
        let b =
            create_genesis_v3_self_attested(seed, net, 0, 0, 3, &aph).expect("self-attested v3");
        assert_eq!(a.profile, GenesisEntropyProfile::MnemonicV3);
        assert_eq!(a.state.hash, b.state.hash);
        assert_eq!(a.state.device_id, b.state.device_id);
        assert_eq!(a.genesis_nonce, b.genesis_nonce);
        assert_eq!(
            a.state.signing_key.public_key,
            b.state.signing_key.public_key
        );
        assert_eq!(
            a.state.kyber_keypair.public_key,
            b.state.kyber_keypair.public_key
        );

        // GenesisState matches the underlying v3 chain (G, DevID, AK pk) — the
        // same chain the P0-P6 resolver authenticates against.
        let v3 = derive_genesis_v3_self_attested(seed, net, 0, 0, 3, &aph).expect("chain");
        assert_eq!(a.state.hash, v3.g);
        assert_eq!(a.state.device_id, v3.devid);
        assert_eq!(a.state.signing_key.public_key, v3.ak_public);
        assert_eq!(a.genesis_nonce, v3.genesis_nonce);
        assert_eq!(a.state.genesis_nonce, v3.genesis_nonce);

        // A different wallet seed yields a different genesis + identity.
        let c = create_genesis_v3_self_attested(
            b"another-self-attested-seed-of-length-....",
            net,
            0,
            0,
            3,
            &aph,
        )
        .expect("self-attested v3");
        assert_ne!(a.state.hash, c.state.hash);
        assert_ne!(a.state.device_id, c.state.device_id);
    }

    /// `genesis_version < 3` is refused fail-closed at the creation entry
    /// point, not just inside the derivation.
    #[test]
    fn create_genesis_v3_refuses_earlier_versions() {
        let seed = b"bip39-wallet-seed-version-gate-test-............................";
        assert!(create_genesis_v3_self_attested(seed, b"dsm-test", 0, 0, 2, &[0x11; 32]).is_err());
    }
}
