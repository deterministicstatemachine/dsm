// SPDX-License-Identifier: Apache-2.0

//! A lineage of the native reserve for a test: real releases, signed by one
//! claimant key that derives the device id each release names, each release
//! succeeding the state before it. What a walk of a reserve that many
//! claims reached would establish.

use dsm::economic::native_reserve::{
    decode_and_verify_release, release_constructible, sign_release, NativeReserveReleaseBody,
    NativeReserveState, ReleaseSource, ERA_FAUCET_PAYOUT,
};

/// A faucet claimant: a real identity derived from a wallet seed, with its own
/// signed directory entry, built as a wallet builds the one it publishes. A
/// release carries the entry; its bytes decide the claimant's entitlement
/// (SA-63).
pub struct Claimant {
    pub genesis: [u8; 32],
    pub devid: [u8; 32],
    pub att_a: [u8; 32],
    pub ak_public_key: Vec<u8>,
    pub ak_secret_key: Vec<u8>,
    pub directory_entry: Vec<u8>,
}

impl Claimant {
    /// The release's source: this claimant, by its key, its AttA and its
    /// directory entry.
    pub fn source(&self) -> ReleaseSource {
        ReleaseSource::FaucetClaimant {
            claimant_public_key: self.ak_public_key.clone(),
            claimant_att_a: self.att_a,
            claimant_directory_entry: self.directory_entry.clone(),
        }
    }
}

/// The claimant of the wallet seed `[seed; 64]`.
pub fn claimant(seed: u8) -> Claimant {
    let wallet_seed = [seed; 64];
    let inputs = crate::sdk::identity_presentation::OwnerIdentityInputs::beta(b"dsm-testnet");
    let genesis = dsm::core::identity::genesis_v3::derive_genesis_v3_self_attested(
        &wallet_seed,
        inputs.network_id,
        inputs.wallet_index,
        inputs.device_slot,
        inputs.genesis_version,
        &dsm::core::identity::genesis_v2::genesis_authority_policy_hash(),
    )
    .expect("the claimant's genesis");
    let entry = crate::sdk::device_directory::build_own_entry(
        &wallet_seed,
        inputs,
        &genesis.g,
        vec![seed; dsm::core::identity::directory::KYBER_PUBLIC_KEY_LEN],
        1,
    )
    .expect("the claimant's directory entry");
    Claimant {
        genesis: genesis.g,
        devid: genesis.devid,
        att_a: entry.body.att_a,
        ak_public_key: genesis.ak_public.clone(),
        ak_secret_key: genesis.ak_secret.clone(),
        directory_entry: entry.encode(),
    }
}

/// `generations` releases of the reserve whose genesis is `genesis`, in
/// generation order: release `g` is built on the state at `g − 1`.
pub fn signed_releases(genesis: &NativeReserveState, generations: u64) -> Vec<Vec<u8>> {
    let claimant = claimant(0x5D);
    let mut parent = *genesis;
    let mut releases = Vec::new();
    for position in 1..=generations {
        let body = NativeReserveReleaseBody {
            reserve_id: *parent.reserve_id(),
            parent_root: parent.root(),
            generation: parent.generation() + 1,
            amount: ERA_FAUCET_PAYOUT,
            recipient_genesis: claimant.genesis,
            recipient_devid: claimant.devid,
            recipient_economic_position: position,
            recipient_operation_digest: [0x5C; 32],
            storage_set_id: *parent.storage_set_id(),
            source: claimant.source(),
        };
        let envelope = sign_release(&body, &claimant.ak_secret_key).expect("a release");
        let release = decode_and_verify_release(&envelope).expect("the release verifies");
        parent = release_constructible(&parent, &release).expect("it succeeds the state before it");
        releases.push(envelope);
    }
    releases
}
