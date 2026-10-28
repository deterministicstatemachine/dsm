// SPDX-License-Identifier: Apache-2.0

//! A lineage of the native reserve for a test: real releases, signed by one
//! claimant key that derives the device id each release names, each release
//! succeeding the state before it. What a walk of a reserve that many
//! claims reached would establish.

use dsm::economic::native_reserve::{
    decode_and_verify_release, release_constructible, sign_release, NativeReserveReleaseBody,
    NativeReserveState, ReleaseSource, ERA_FAUCET_PAYOUT,
};

/// `generations` releases of the reserve whose genesis is `genesis`, in
/// generation order: release `g` is built on the state at `g − 1`.
pub fn signed_releases(genesis: &NativeReserveState, generations: u64) -> Vec<Vec<u8>> {
    let (public_key, secret_key) =
        dsm::crypto::sphincs::generate_sphincs_keypair().expect("a claimant key");
    let att_a = [0x5D; 32];
    let recipient_devid = dsm::core::identity::genesis_v2::derive_devid(&public_key, &att_a);
    let mut parent = *genesis;
    let mut releases = Vec::new();
    for position in 1..=generations {
        let body = NativeReserveReleaseBody {
            reserve_id: *parent.reserve_id(),
            parent_root: parent.root(),
            generation: parent.generation() + 1,
            amount: ERA_FAUCET_PAYOUT,
            recipient_genesis: [0x5A; 32],
            recipient_devid,
            recipient_economic_position: position,
            recipient_operation_digest: [0x5C; 32],
            storage_set_id: *parent.storage_set_id(),
            source: ReleaseSource::FaucetClaimant {
                claimant_public_key: public_key.clone(),
                claimant_att_a: att_a,
            },
        };
        let envelope = sign_release(&body, &secret_key).expect("a release");
        let release = decode_and_verify_release(&envelope).expect("the release verifies");
        parent = release_constructible(&parent, &release).expect("it succeeds the state before it");
        releases.push(envelope);
    }
    releases
}
