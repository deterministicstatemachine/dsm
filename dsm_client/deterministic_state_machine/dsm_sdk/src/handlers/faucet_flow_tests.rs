// SPDX-License-Identifier: Apache-2.0

//! End-to-end tests for the ERA faucet claim flow on the network's pinned set
//! of storage nodes: a generation of the native reserve won leader first,
//! fence-coupled advance, evidence frozen and published, root registered,
//! verifier-validated, admitted.
//!
//! Every claimant is a device created as wallet creation creates it; every
//! fault is a node that stops serving.
//!
//! `flavor = "multi_thread"` is required: the live resolver bridges the sync
//! verifier to async quorum reads via `block_in_place`.

use serial_test::serial;

use dsm::economic::native_reserve::{
    NativeReserveState, SuccessorCell, WalkStop, ERA_RESERVE_GENESIS_SUPPLY,
};

use crate::economic_fixtures::NETWORK;
use crate::sdk::faucet_claim_flow::claim_era_faucet;
use crate::sdk::storage_set::{as_ccb_members, canonical_set};
use crate::storage::client_db;
use crate::test_support::one_device::Device;
use crate::test_support::two_device::Pair;

fn era() -> [u8; 32] {
    dsm::core::token::token_state_manager::era_policy_commit()
}

fn reserve_genesis() -> NativeReserveState {
    crate::sdk::native_reserve::genesis_state(NETWORK).expect("reserve genesis")
}

/// The seats of `R_0`'s successor cell after its first two, in route order:
/// taking them down lets a write reach the leader and one more seat, and no
/// further — a chain of two links, which is never final (storage spec §9).
fn seats_past_the_second_of_the_first_release() -> Vec<String> {
    let set = canonical_set(NETWORK).expect("canonical set");
    let members = as_ccb_members(&set).expect("members");
    let cell = SuccessorCell::of(&reserve_genesis(), &members).expect("successor cell");
    cell.routed().route().seats()[2..]
        .iter()
        .map(|id| String::from_utf8(id.clone()).expect("member ids are UTF-8"))
        .collect()
}

/// Walk the reserve from its genesis to its head, as a verifier would.
async fn reserve_head() -> NativeReserveState {
    let handle = tokio::runtime::Handle::current();
    let stop = tokio::task::spawn_blocking(move || {
        let set = canonical_set(NETWORK).expect("canonical set");
        crate::sdk::native_reserve::walk_reserve(&set, NETWORK, &handle)
    })
    .await
    .expect("join")
    .expect("walk");
    match stop {
        WalkStop::Head(state) => state,
        other => panic!("the reserve walk stopped short of its head: {other:?}"),
    }
}

/// The release final at `generation`, as a verifier reads it.
async fn release_at(generation: u64) -> dsm::economic::provenance::ReserveReleaseWin {
    let handle = tokio::runtime::Handle::current();
    let reserve_id = reserve_genesis().reserve_id;
    tokio::task::spawn_blocking(move || {
        let set = canonical_set(NETWORK).expect("canonical set");
        crate::sdk::native_reserve::release_at(&set, NETWORK, &handle, &reserve_id, generation)
    })
    .await
    .expect("join")
    .expect("read the release")
    .unwrap_or_else(|| panic!("no release is final at generation {generation}"))
}

fn recipient_of(win: &dsm::economic::provenance::ReserveReleaseWin) -> [u8; 32] {
    dsm::economic::native_reserve::decode_and_verify_release(&win.envelope_bytes)
        .expect("a final release verifies")
        .body
        .recipient_devid
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_full_claim_credits_100_era_and_admits_position_1() {
    let d = Device::start(0xA1).await;
    let outcome = claim_era_faucet(d.core(), NETWORK)
        .await
        .expect("claim succeeds");
    assert_eq!(outcome.tokens_received, 100);
    assert_eq!(outcome.economic_position, 1);

    let head = d.core().device_head().expect("head");
    assert_eq!(head.balance(&era()), 100, "exactly +100, conservation");
    assert!(
        head.pending_economic_admission().is_none(),
        "admitted ⇒ unfenced"
    );
    let (position, _root) = client_db::economic_lineage::get_admitted_coordinate()
        .expect("read admitted")
        .expect("admitted recorded");
    assert_eq!(position, 1);
    assert_eq!(
        recipient_of(&release_at(1).await),
        d.identity.device_id,
        "generation 1 names the claimant"
    );
}

/// SoFi §51 and the shortcut audit of 2026-09-25: a release of the whole
/// remaining supply, signed by a key nobody proved and written final along
/// the whole route of the reserve's first successor cell before anyone
/// claims, is not a release the claim policy allows. It holds nothing: the
/// claimant takes generation 1, and the reserve gave up exactly one payout.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_release_of_the_whole_supply_holds_nothing_and_the_claim_lands() {
    let d = Device::start(0xA1).await;
    let set = canonical_set(NETWORK).expect("canonical set");
    let r0 = reserve_genesis();
    let (pk, sk) = dsm::crypto::sphincs::generate_sphincs_keypair().expect("a key");
    let drain = dsm::economic::native_reserve::sign_release(
        &dsm::economic::native_reserve::NativeReserveReleaseBody {
            reserve_id: r0.reserve_id,
            parent_root: r0.root(),
            generation: 1,
            amount: r0.remaining_supply,
            recipient_genesis: [0x5A; 32],
            recipient_devid: [0x5B; 32],
            recipient_economic_position: 1,
            recipient_operation_digest: [0x5C; 32],
            storage_set_id: r0.storage_set_id,
            source: dsm::economic::native_reserve::ReleaseSource::FaucetClaimant {
                claimant_public_key: pk,
            },
        },
        &sk,
    )
    .expect("signed");
    let write = crate::sdk::native_reserve::write_release(&set, &r0, &drain)
        .await
        .expect("the nodes keep whatever they are given");
    assert!(write.reached_leader());

    let outcome = claim_era_faucet(d.core(), NETWORK)
        .await
        .expect("the claim lands");
    assert_eq!(outcome.tokens_received, 100);
    assert_eq!(
        recipient_of(&release_at(1).await),
        d.identity.device_id,
        "generation 1 is the claimant's, not the drain's"
    );
    let head = reserve_head().await;
    assert_eq!(head.generation, 1);
    assert_eq!(head.remaining_supply, ERA_RESERVE_GENESIS_SUPPLY - 100);
}

/// The route claims for the device that makes the request, and for no other:
/// a request naming another device is refused before anything is claimed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn the_claim_route_claims_only_for_the_device_that_makes_it() {
    use crate::bridge::{AppInvoke, AppRouter};
    use dsm::types::proto as generated;
    use prost::Message;
    let d = Device::start(0xA8).await;
    let request = |device_id: Vec<u8>| AppInvoke {
        method: "faucet.claim".to_string(),
        args: generated::ArgPack {
            schema_hash: None,
            codec: generated::Codec::Proto as i32,
            body: generated::FaucetClaimRequest { device_id }.encode_to_vec(),
        }
        .encode_to_vec(),
    };
    let own = d.router.device_id_bytes.to_vec();
    let mut other = own.clone();
    other[0] ^= 0x01;

    let refused = d.router.invoke(request(other)).await;
    assert!(!refused.success, "a claim naming another device is refused");
    assert!(
        refused
            .error_message
            .as_deref()
            .is_some_and(|m| m.contains("names another device")),
        "the refusal names why: {:?}",
        refused.error_message
    );
    assert_eq!(d.era_balance(), 0, "nothing was claimed");

    let claimed = d.router.invoke(request(own)).await;
    assert!(claimed.success, "faucet.claim: {:?}", claimed.error_message);
    let envelope = crate::handlers::response_helpers::decode_local_envelope(&claimed.data)
        .expect("a local answer");
    match envelope.payload {
        Some(generated::envelope::Payload::FaucetClaimResponse(r)) => {
            assert!(r.success);
            assert_eq!(
                r.tokens_received,
                dsm::economic::native_reserve::ERA_FAUCET_PAYOUT
            );
        }
        other => panic!("faucet.claim answered {other:?}"),
    }
    assert_eq!(
        d.era_balance(),
        dsm::economic::native_reserve::ERA_FAUCET_PAYOUT
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_repeat_claimant_succeeds_on_the_next_generation() {
    let d = Device::start(0xA2).await;
    let one = claim_era_faucet(d.core(), NETWORK)
        .await
        .expect("first claim");
    assert_eq!(one.economic_position, 1);
    let two = claim_era_faucet(d.core(), NETWORK)
        .await
        .expect("second claim");
    assert_eq!(two.economic_position, 2, "each claim advances the position");
    assert_eq!(d.era_balance(), 200, "two claims, exactly 200");
    assert_eq!(reserve_head().await.generation, 2);
}

/// Another claimant's release took generation 1 first: the next claim walks
/// to the moved head and wins generation 2, and the reserve moved by exactly
/// the two releases.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn another_claimants_release_moves_the_head_and_the_next_claim_takes_the_generation_after() {
    let p = Pair::boot(0, 0).await;
    p.b.fund_admitted(100).await;

    p.a.enter();
    let outcome = claim_era_faucet(&p.a.router().core_sdk, NETWORK)
        .await
        .expect("A claims the next generation");
    assert_eq!(outcome.tokens_received, 100);
    assert_eq!(outcome.economic_position, 1, "A's own first position");
    assert_eq!(p.a.era_balance(), 100);

    assert_eq!(recipient_of(&release_at(1).await), p.b.device_id);
    assert_eq!(recipient_of(&release_at(2).await), p.a.device_id);
    let head = reserve_head().await;
    assert_eq!(head.generation, 2);
    assert_eq!(head.remaining_supply, ERA_RESERVE_GENESIS_SUPPLY - 200);
}

/// A claim whose release reached only the leader and one more seat leaves a
/// chain of two links: settled, never final. It bricks nothing. The next
/// claimant carries that chain along the rest of its route (storage spec §9:
/// any party MAY), and takes the generation after; the first claimant, back,
/// finishes on the generation its own release holds, with the bytes it froze.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_release_cut_short_after_the_leader_is_carried_by_the_next_claimant_and_bricks_nothing() {
    let mut p = Pair::boot(0, 0).await;
    let cut = seats_past_the_second_of_the_first_release();
    let r0 = reserve_genesis();

    p.nodes.take_down(&cut).await;
    p.a.enter();
    let cut_short = claim_era_faucet(&p.a.router().core_sdk, NETWORK).await;
    assert!(
        cut_short.is_err(),
        "a release with two links is not final, so the claim cannot finish"
    );
    let frozen = client_db::native_reserve::get_frozen_release(&r0.reserve_id, &r0.root())
        .expect("read the frozen release")
        .expect("the release was frozen before it was written");
    assert_eq!(p.a.era_balance(), 0, "nothing was credited");
    assert!(
        p.a.router()
            .core_sdk
            .device_head()
            .expect("head")
            .pending_economic_admission()
            .is_none(),
        "nothing was advanced"
    );

    p.nodes.bring_up(&cut).await;
    p.b.enter();
    let b_claim = claim_era_faucet(&p.b.router().core_sdk, NETWORK)
        .await
        .expect("B's claim is not bricked by A's short chain");
    assert_eq!(b_claim.economic_position, 1);
    assert_eq!(p.b.era_balance(), 100);
    let first = release_at(1).await;
    assert_eq!(first.envelope_bytes, frozen, "generation 1 is A's release");
    assert_eq!(recipient_of(&release_at(2).await), p.b.device_id);

    p.a.enter();
    let resumed = claim_era_faucet(&p.a.router().core_sdk, NETWORK)
        .await
        .expect("A finishes on its own generation");
    assert_eq!(resumed.tokens_received, 100);
    assert_eq!(resumed.economic_position, 1);
    assert_eq!(p.a.era_balance(), 100);
    let head = reserve_head().await;
    assert_eq!(head.generation, 2, "A released once, B once");
    assert_eq!(head.remaining_supply, ERA_RESERVE_GENESIS_SUPPLY - 200);
}

/// The claimant alone: its release cut short after the leader, its retry
/// carries its own chain to finality and completes on that generation with
/// the frozen bytes — never releasing a second time for the same position.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_claim_cut_short_resumes_on_its_own_release_byte_identically() {
    let mut d = Device::start(0xA4).await;
    let cut = seats_past_the_second_of_the_first_release();
    let r0 = reserve_genesis();

    d.nodes.take_down(&cut).await;
    assert!(
        claim_era_faucet(d.core(), NETWORK).await.is_err(),
        "a release with two links is not final"
    );
    let frozen = client_db::native_reserve::get_frozen_release(&r0.reserve_id, &r0.root())
        .expect("read the frozen release")
        .expect("the release was frozen before it was written");

    d.nodes.bring_up(&cut).await;
    let outcome = claim_era_faucet(d.core(), NETWORK)
        .await
        .expect("resumed claim");
    assert_eq!(outcome.tokens_received, 100);
    assert_eq!(outcome.economic_position, 1);
    assert_eq!(
        release_at(1).await.envelope_bytes,
        frozen,
        "the resumed claim used the frozen release"
    );
    assert_eq!(reserve_head().await.generation, 1, "released once");
    assert_eq!(d.era_balance(), 100);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn admissions_are_never_double_finished_and_positions_stay_monotonic() {
    // The admitted store, the register, and the head must agree after every
    // completed admission: re-entering the flow when nothing is pending
    // starts the NEXT admission, never re-finishes or forks the last one.
    let d = Device::start(0xA5).await;
    claim_era_faucet(d.core(), NETWORK).await.expect("claim 1");
    let second = claim_era_faucet(d.core(), NETWORK).await.expect("claim 2");
    assert_eq!(second.economic_position, 2);
    let third = claim_era_faucet(d.core(), NETWORK).await.expect("claim 3");
    assert_eq!(third.economic_position, 3);
    assert_eq!(d.era_balance(), 300);
    let (position, _root) = client_db::economic_lineage::get_admitted_coordinate()
        .expect("read admitted")
        .expect("admitted");
    assert_eq!(position, 3);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_faucet_lineage_is_walkable_by_a_foreign_verifier() {
    // After a live claim, the SAME resolver a FOREIGN device would use must
    // walk this lineage from the registers and immutable store alone —
    // register winner, manifest, P0–P6 authority evidence (recovering AK +
    // network), sigma_dsm successor evidence, and the full advance_validated
    // conjuncts.
    let d = Device::start(0xB7).await;
    let outcome = claim_era_faucet(d.core(), NETWORK).await.expect("claim");
    assert_eq!(outcome.economic_position, 1);
    let head = d.core().device_head().expect("head");
    let (genesis, devid) = (head.genesis_digest(), head.devid());
    let (_, admitted_root) = client_db::economic_lineage::get_admitted_coordinate()
        .expect("read admitted")
        .expect("admitted");

    // A foreign walk: nothing below reads local admission state — the
    // resolver's cache is cleared first so the walk is from position 0.
    client_db::economic_lineage::clear_peer_lineage(&genesis, &devid)
        .expect("clear the peer lineage cache");
    let handle = tokio::runtime::Handle::current();
    let peer = tokio::task::spawn_blocking(move || {
        use dsm::economic::provenance::ProvenanceResolver;
        let set = canonical_set(NETWORK).expect("canonical set");
        let resolver = crate::sdk::economic_registers::LiveRegisterResolver {
            set: &set,
            runtime: handle,
            expected_network_id: NETWORK.to_vec(),
        };
        resolver.validated_peer_transition(&genesis, &devid, 1)
    })
    .await
    .expect("join")
    .expect("a faucet lineage MUST be foreign-walkable");
    assert_eq!(peer.validated_root().economic_position(), 1);
    assert_eq!(
        peer.validated_root().economic_root(),
        admitted_root,
        "the foreign walk and the local admission agree byte-for-byte"
    );
    assert!(matches!(
        peer.verified_operation(),
        dsm::types::operations::Operation::FaucetClaim { .. }
    ));
}
