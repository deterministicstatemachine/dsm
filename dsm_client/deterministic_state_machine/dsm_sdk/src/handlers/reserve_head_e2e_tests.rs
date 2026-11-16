// SPDX-License-Identifier: MIT OR Apache-2.0

//! The network's one ERA reserve against a wallet that signs more than one
//! claim at its head, on storage nodes.
//!
//! ERA leaves the reserve by release: a claimant signs a release that
//! succeeds the reserve's head and writes it at the head's successor cell,
//! leader first. The first release at the leader holds the cell and every
//! other one there is nothing (storage spec §9, route chains, rule 3). A
//! release names its claimant's own position, which nothing at the cell
//! checks, so one wallet can sign any number of releases that all succeed
//! the same head. Every step here is a production route on the
//! device that takes it; the wallet signing many claims signs each with its
//! own key, as its one honest claim is signed.

use dsm::economic::native_reserve::{
    decode_and_verify_release, release_constructible, sign_release, NativeReserveReleaseBody,
    ReleaseSource, SuccessorCell, WalkStop, ERA_FAUCET_PAYOUT,
};
use serial_test::serial;

use super::connect_escrow_e2e_tests::put_at_the_leader;
use crate::economic_fixtures::{whole_era, NETWORK};
use crate::test_support::two_device::{Pair, TestDevice};

/// What this device keeps of one seat's log at a cell at most
/// (`route_seats::HELD_LOG_BUDGET`).
const ONE_SEATS_LOG: usize = 8 * 1024 * 1024;

/// One faucet claim by `d`, with a held admission resumed as the device
/// resumes it; why it did not complete, when it did not.
async fn claim(d: &TestDevice) -> Result<(), String> {
    d.enter();
    let core = d.router().core_sdk.clone();
    let mut outcome = crate::sdk::faucet_claim_flow::claim_era_faucet(&core, NETWORK)
        .await
        .map(drop);
    for resumed in 1..=4u64 {
        let Err(why) = &outcome else {
            break;
        };
        let held = core
            .device_head()
            .and_then(|head| head.pending_economic_admission().cloned());
        let Some(pending) = held else {
            return Err(why.to_string());
        };
        tokio::time::sleep(std::time::Duration::from_millis(250 * resumed)).await;
        outcome =
            crate::sdk::economic_admission_flow::resume_pending_admission(&core, NETWORK, pending)
                .await
                .map(drop);
    }
    outcome.map_err(|e| e.to_string())
}

/// A wallet's many claims at the reserve's head stop no other wallet's claim.
///
/// A claims from the faucet, as the harness funds it. C, a wallet of its own
/// on the set, walks the reserve to its head and signs, with its own key and
/// its own directory entry, a little over one seat's log budget of releases
/// that each succeed that head, differing only in the position of its own
/// each names. It writes them at the head's successor cell, at its leader,
/// through the member's ordinary cell route. B then claims from the faucet.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn one_wallets_many_claims_at_the_reserve_head_stop_no_other_claim() {
    let p = Pair::boot(100, 0).await;
    assert_eq!(p.a.era_balance(), whole_era(100), "the faucet pays A");

    let mut c = TestDevice::create("C", 0x0C);
    c.boot(&p.fleet).await;
    c.enter();
    let set = crate::sdk::storage_set::canonical_set(NETWORK).expect("the pinned set");
    let runtime = tokio::runtime::Handle::current();
    let stop = tokio::task::block_in_place(|| {
        crate::sdk::native_reserve::walk_reserve(&set, NETWORK, &runtime)
    })
    .expect("C walks the reserve");
    let WalkStop::Head(head) = stop else {
        panic!("C's walk stopped short of the reserve's head: {stop:?}");
    };
    let parent = *head.state();

    let (public_key, secret_key) =
        crate::sdk::signing_authority::current_keypair().expect("C's own key");
    let att_a = crate::sdk::signing_authority::current_att_a().expect("C's own AttA");
    let directory_entry = crate::storage::client_db::own_directory_entry::load()
        .expect("C's store")
        .expect("C published its directory entry when it started");
    // The operation a claim of the head's next generation is, as every
    // wallet's claim names it.
    let operation = dsm::economic::admission::dsm_operation_digest(
        &dsm::types::operations::Operation::FaucetClaim {
            reserve_id: *parent.reserve_id(),
            generation: parent.generation() + 1,
        }
        .to_bytes(),
    );
    let mut claims = Vec::new();
    let mut bytes = 0usize;
    while bytes <= ONE_SEATS_LOG {
        let body = NativeReserveReleaseBody {
            reserve_id: *parent.reserve_id(),
            parent_root: parent.root(),
            generation: parent.generation() + 1,
            amount: ERA_FAUCET_PAYOUT,
            recipient_genesis: c.genesis,
            recipient_devid: c.device_id,
            recipient_economic_position: 1 + claims.len() as u64,
            recipient_operation_digest: operation,
            storage_set_id: *parent.storage_set_id(),
            source: ReleaseSource::FaucetClaimant {
                claimant_public_key: public_key.clone(),
                claimant_att_a: att_a,
                claimant_directory_entry: directory_entry.clone(),
            },
        };
        let envelope = sign_release(&body, &secret_key).expect("C signs a release");
        let release = decode_and_verify_release(&envelope).expect("the release verifies");
        release_constructible(&parent, &release).expect("the release succeeds the head");
        bytes += envelope.len();
        claims.push(envelope);
    }
    let cell = SuccessorCell::of(
        &parent,
        &crate::sdk::storage_set::as_ccb_members(&set).expect("the set's members"),
    )
    .expect("the head's successor cell");
    put_at_the_leader(&set, cell.routed(), &claims).await;

    let claimed = claim(&p.b).await;
    assert_eq!(
        (claimed.clone(), p.b.era_balance()),
        (Ok(()), whole_era(100)),
        "{} releases ({bytes} bytes) one wallet signed at the reserve's head stopped another \
         wallet's claim: {claimed:?}",
        claims.len()
    );
}
