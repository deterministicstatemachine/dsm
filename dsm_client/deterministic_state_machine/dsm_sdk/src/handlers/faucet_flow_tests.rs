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
    reserve_genesis_supply, NativeReserveState, SuccessorCell, WalkStop,
};

use crate::bridge::{AppInvoke, AppQuery, AppRouter};
use crate::economic_fixtures::{whole_era, NETWORK};
use crate::generated;
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
        WalkStop::Head(head) => *head.state(),
        other => panic!("the reserve walk stopped short of its head: {other:?}"),
    }
}

/// The release final at `generation`, as a verifier reads it.
async fn release_at(generation: u64) -> dsm::economic::provenance::ReserveReleaseWin {
    let handle = tokio::runtime::Handle::current();
    let reserve_id = *reserve_genesis().reserve_id();
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
    assert_eq!(outcome.tokens_received, whole_era(100));
    assert_eq!(outcome.economic_position, 1);

    let head = d.core().device_head().expect("head");
    assert_eq!(
        head.balance(&era()),
        whole_era(100),
        "exactly +100 ERA, conservation"
    );
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

    // The wallet's history lists the claim: 100 ERA in, from the reserve —
    // no sender device — under the release's operation digest. No claim
    // wrote a history row before.
    let history = wallet_history(&d.router).await;
    assert_eq!(history.transactions.len(), 1, "one row: the claim");
    let claim = &history.transactions[0];
    assert_eq!(
        claim.tx_type,
        generated::TransactionType::TxTypeFaucet as i32
    );
    assert_eq!(claim.amount, whole_era(100));
    assert_eq!(claim.direction, generated::AmountDirection::Credit as i32);
    assert_eq!(claim.display_amount, "100.00");
    assert_eq!(claim.token_id, "ERA");
    assert!(claim.from_device_id.is_empty(), "the source is the reserve");
    assert_eq!(claim.to_device_id, d.identity.device_id.to_vec());
    assert_eq!(claim.recipient, "ERA reserve (faucet)");
    assert_eq!(claim.status, "confirmed");
    assert_eq!(claim.tx_hash.len(), 32, "the release's operation digest");
    assert_eq!(
        claim.id,
        format!(
            "tx_{}",
            crate::util::text_id::encode_base32_crockford(&claim.tx_hash)
        )
    );
}

/// The wallet's history as `wallet.history` answers it.
async fn wallet_history(
    router: &crate::handlers::app_router_impl::AppRouterImpl,
) -> generated::WalletHistoryResponse {
    use prost::Message;
    let mut body = Vec::with_capacity(16);
    body.extend_from_slice(&16u64.to_le_bytes());
    body.extend_from_slice(&0u64.to_le_bytes());
    let answer = router
        .query(AppQuery {
            path: "wallet.history".to_string(),
            params: generated::ArgPack {
                codec: generated::Codec::Proto as i32,
                body,
                ..Default::default()
            }
            .encode_to_vec(),
        })
        .await;
    assert!(answer.success, "wallet.history: {:?}", answer.error_message);
    let env = generated::Envelope::decode(&answer.data[1..]).expect("a framed envelope");
    match env.payload {
        Some(generated::envelope::Payload::WalletHistoryResponse(h)) => h,
        other => panic!("wallet.history answers a WalletHistoryResponse, not {other:?}"),
    }
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
    // A key of its own, and the device id it derives: the release's signer
    // IS the device it names, so only the release rule's amount refuses it.
    let (pk, sk) = dsm::crypto::sphincs::generate_sphincs_keypair().expect("a key");
    let att_a = [0x5D; 32];
    let drain = dsm::economic::native_reserve::sign_release(
        &dsm::economic::native_reserve::NativeReserveReleaseBody {
            reserve_id: *r0.reserve_id(),
            parent_root: r0.root(),
            generation: 1,
            amount: r0.remaining_supply(),
            recipient_genesis: [0x5A; 32],
            recipient_devid: dsm::core::identity::genesis_v2::derive_devid(&pk, &att_a),
            recipient_economic_position: 1,
            recipient_operation_digest: [0x5C; 32],
            storage_set_id: *r0.storage_set_id(),
            source: dsm::economic::native_reserve::ReleaseSource::FaucetClaimant {
                claimant_public_key: pk,
                claimant_att_a: att_a,
            },
        },
        &sk,
    )
    .expect("signed");
    let write = crate::sdk::native_reserve::write_release(&set, &r0, &drain)
        .await
        .expect("the nodes keep whatever they are given");
    assert_eq!(write.leader(), crate::sdk::route_seats::AtLeader::Link);

    let outcome = claim_era_faucet(d.core(), NETWORK)
        .await
        .expect("the claim lands");
    assert_eq!(outcome.tokens_received, whole_era(100));
    assert_eq!(
        recipient_of(&release_at(1).await),
        d.identity.device_id,
        "generation 1 is the claimant's, not the drain's"
    );
    let head = reserve_head().await;
    assert_eq!(head.generation(), 1);
    assert_eq!(
        head.remaining_supply(),
        reserve_genesis_supply().expect("ERA's genesis supply") - whole_era(100)
    );
}

/// Owner ruling 2026-09-25: a faucet release occupies a reserve cell only
/// when its signer is the device it credits. A payout release naming the
/// claimant's own device, signed by another key, written final along the
/// whole route of the first successor cell before the claimant claims, holds
/// nothing: the claimant takes generation 1 with its own release.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_release_naming_a_device_its_key_does_not_derive_holds_nothing() {
    let d = Device::start(0xA1).await;
    let set = canonical_set(NETWORK).expect("canonical set");
    let r0 = reserve_genesis();
    let (pk, sk) = dsm::crypto::sphincs::generate_sphincs_keypair().expect("a key");
    let impostor = dsm::economic::native_reserve::sign_release(
        &dsm::economic::native_reserve::NativeReserveReleaseBody {
            reserve_id: *r0.reserve_id(),
            parent_root: r0.root(),
            generation: 1,
            amount: dsm::economic::native_reserve::ERA_FAUCET_PAYOUT,
            recipient_genesis: d.identity.genesis,
            recipient_devid: d.identity.device_id,
            recipient_economic_position: 1,
            recipient_operation_digest: [0x5C; 32],
            storage_set_id: *r0.storage_set_id(),
            source: dsm::economic::native_reserve::ReleaseSource::FaucetClaimant {
                claimant_public_key: pk,
                claimant_att_a: [0x5D; 32],
            },
        },
        &sk,
    )
    .expect("signed");
    let write = crate::sdk::native_reserve::write_release(&set, &r0, &impostor)
        .await
        .expect("the nodes keep whatever they are given");
    assert_eq!(write.leader(), crate::sdk::route_seats::AtLeader::Link);

    let outcome = claim_era_faucet(d.core(), NETWORK)
        .await
        .expect("the claim lands");
    assert_eq!(outcome.tokens_received, whole_era(100));
    let won = release_at(1).await;
    assert_ne!(
        won.envelope_bytes, impostor,
        "the impostor's release holds nothing"
    );
    assert_eq!(recipient_of(&won), d.identity.device_id);
}

/// A payout release of generation 1 from `r0`, signed by a fresh key for the
/// device that key derives with `att_a`: one the claim policy allows. The
/// release and the device it credits.
fn payout_release(r0: &NativeReserveState, att_a: [u8; 32]) -> (Vec<u8>, [u8; 32]) {
    let (pk, sk) = dsm::crypto::sphincs::generate_sphincs_keypair().expect("a key");
    let devid = dsm::core::identity::genesis_v2::derive_devid(&pk, &att_a);
    let release = dsm::economic::native_reserve::sign_release(
        &dsm::economic::native_reserve::NativeReserveReleaseBody {
            reserve_id: *r0.reserve_id(),
            parent_root: r0.root(),
            generation: 1,
            amount: dsm::economic::native_reserve::ERA_FAUCET_PAYOUT,
            recipient_genesis: [0x5A; 32],
            recipient_devid: devid,
            recipient_economic_position: 1,
            recipient_operation_digest: [0x5C; 32],
            storage_set_id: *r0.storage_set_id(),
            source: dsm::economic::native_reserve::ReleaseSource::FaucetClaimant {
                claimant_public_key: pk,
                claimant_att_a: att_a,
            },
        },
        &sk,
    )
    .expect("signed");
    (release, devid)
}

/// MR-STOR-0134, the faucet's race at a reserve cell. Two claimants release
/// generation 1 at once, and the winner's release is first at the leader of
/// the reserve's first successor cell when the loser's reaches the faucet's
/// writer. The writer records the cell taken, with the winner's leader
/// record, and puts nothing of the losing release on any member. A claim
/// then walks to the moved head and takes the generation after.
/// MUTATION CONTROL: reading another release first at the leader as an open
/// cell puts the losing release at the leader and carries it along the
/// route; this turns red.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_release_beaten_to_the_reserve_leader_is_recorded_taken() {
    use crate::sdk::route_seats::AtLeader;
    use dsm::route_chain::{ChainSlot, RouteEntry};
    let d = Device::start(0xA9).await;
    let set = canonical_set(NETWORK).expect("canonical set");
    let r0 = reserve_genesis();
    let (winner, winner_devid) = payout_release(&r0, [0x5D; 32]);
    let (loser, _) = payout_release(&r0, [0x5E; 32]);

    let won = crate::sdk::native_reserve::write_release(&set, &r0, &winner)
        .await
        .expect("the winner's release is written");
    let Some(ChainSlot::Link(winner_link)) = won.slots.first().cloned() else {
        panic!("the winner is first at the leader: {:?}", won.slots);
    };
    let lost = crate::sdk::native_reserve::write_release(&set, &r0, &loser)
        .await
        .expect("the loser's write is reported");
    assert_eq!(lost.leader(), AtLeader::Taken);
    assert_eq!(lost.slots, vec![ChainSlot::Taken(winner_link)]);
    let cell =
        SuccessorCell::of(&r0, &as_ccb_members(&set).expect("members")).expect("successor cell");
    let held = crate::sdk::storage_node_sdk::SetClient::new(&set)
        .expect("a client of the set")
        .held_at(cell.routed().namespace(), cell.routed().key())
        .await;
    for (member, values) in held.iter().enumerate() {
        let values = values.as_ref().expect("every member answers");
        assert!(
            values
                .iter()
                .filter_map(|bytes| RouteEntry::decode(bytes))
                .all(|entry| entry.value != loser),
            "member {member} holds the losing release"
        );
    }
    assert_eq!(recipient_of(&release_at(1).await), winner_devid);

    let outcome = claim_era_faucet(d.core(), NETWORK)
        .await
        .expect("the claim lands");
    assert_eq!(outcome.tokens_received, whole_era(100));
    assert_eq!(recipient_of(&release_at(2).await), d.identity.device_id);
}

/// MR-STOR-0134, the faucet's own race. Another claimant's release lands at
/// the leader of the reserve's first successor cell between this claim's
/// walk, which found the cell open, and its write. The claim's write is taken
/// there. The claim does not stop on it as on a leader that did not answer:
/// it walks again, carries the other release's chain, which reached only the
/// leader, to finality, and takes generation 2. Nothing of its own release
/// for generation 1 is carried past that cell's leader.
/// MUTATION CONTROL: answering the taken write as an unreachable leader fails
/// the claim; this turns red.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_release_landing_between_the_walk_and_the_write_moves_the_claim_on() {
    use dsm::route_chain::RouteEntry;
    let d = Device::start(0xAA).await;
    let set = canonical_set(NETWORK).expect("canonical set");
    let r0 = reserve_genesis();
    let cell =
        SuccessorCell::of(&r0, &as_ccb_members(&set).expect("members")).expect("successor cell");
    let route = cell.routed().route();
    let leader = String::from_utf8(route.leader().to_vec()).expect("member ids are UTF-8");
    let (rival, rival_devid) = payout_release(&r0, [0x5F; 32]);
    let entry = dsm::route_chain::leader_copy(cell.routed(), &rival);
    d.nodes.race_next_put(
        &leader,
        crate::test_support::rival::rival_put(
            &set,
            &leader,
            (entry.namespace.clone(), entry.key, entry.encode()),
        ),
    );

    let outcome = claim_era_faucet(d.core(), NETWORK)
        .await
        .expect("the claim lands");
    assert!(
        !d.nodes.rival_armed(&leader),
        "the other release landed during the claim"
    );
    assert_eq!(outcome.tokens_received, whole_era(100));
    assert_eq!(recipient_of(&release_at(1).await), rival_devid);
    assert_eq!(recipient_of(&release_at(2).await), d.identity.device_id);
    let client = crate::sdk::storage_node_sdk::SetClient::new(&set).expect("a client of the set");
    let held = client
        .held_at(cell.routed().namespace(), cell.routed().key())
        .await;
    let past_the_leader = client
        .members()
        .iter()
        .zip(&held)
        .filter(|(member, _)| member.member_id().as_bytes() != route.leader());
    for (member, values) in past_the_leader {
        let values = values.as_ref().expect("every member answers");
        assert!(
            values
                .iter()
                .filter_map(|bytes| RouteEntry::decode(bytes))
                .all(|entry| entry.value == rival),
            "{} holds a generation-1 release other than the one that won",
            member.member_id()
        );
    }
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
    assert_eq!(
        d.era_balance(),
        whole_era(200),
        "two claims, exactly 200 ERA"
    );
    assert_eq!(reserve_head().await.generation(), 2);
}

/// A walk reads the reserve's cells ahead of it together. After three
/// claims, a device that keeps nothing of the reserve locates the next
/// generations from the leader's copies and reads their cells at once: every
/// final cell is then kept, and the walk that follows reaches the head
/// without asking any member for those cells again — only the open head
/// cell is read.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_reserve_walk_reads_the_cells_ahead_of_it_together() {
    let d = Device::start(0xA4).await;
    for _ in 0..3 {
        claim_era_faucet(d.core(), NETWORK).await.expect("a claim");
    }
    {
        let binding = client_db::get_connection().expect("the store");
        let conn = binding.lock().expect("the store is not poisoned");
        conn.execute("DELETE FROM native_reserve_lineage_memo", [])
            .expect("forget the walked lineage");
    }
    crate::sdk::final_reads::forget_everything();

    let set = canonical_set(NETWORK).expect("canonical set");
    let members = as_ccb_members(&set).expect("members");
    let mut states = vec![reserve_genesis()];
    for generation in 1..=3 {
        let win = release_at(generation).await;
        let release = dsm::economic::native_reserve::decode_and_verify_release(&win.envelope_bytes)
            .expect("a final release verifies");
        let child = dsm::economic::native_reserve::release_constructible(
            states.last().expect("a state"),
            &release,
        )
        .expect("each release succeeds the state before it");
        states.push(child);
    }
    let cell_of = |state: &NativeReserveState| {
        SuccessorCell::of(state, &members).expect("the successor cell")
    };
    {
        let binding = client_db::get_connection().expect("the store");
        let conn = binding.lock().expect("the store is not poisoned");
        conn.execute("DELETE FROM native_reserve_lineage_memo", [])
            .expect("forget the lineage the reads above walked");
    }
    crate::sdk::final_reads::forget_everything();

    crate::sdk::native_reserve::read_ahead(
        &set,
        &states[0],
        crate::sdk::native_reserve::RESERVE_LOOKAHEAD,
    )
    .await
    .expect("the cells ahead are read");
    for (generation, state) in states[..3].iter().enumerate() {
        assert!(
            crate::sdk::final_reads::final_cell(cell_of(state).routed()).is_some(),
            "the cell of generation {} was read ahead and kept final",
            generation + 1
        );
    }

    for node in &d.nodes.nodes {
        node.forget_requests();
    }
    assert_eq!(reserve_head().await.generation(), 3);
    let asked: Vec<String> = d.nodes.nodes.iter().flat_map(|n| n.requests()).collect();
    for state in &states[..3] {
        let read = format!(
            "GET /api/v2/cell/{}",
            crate::util::text_id::encode_base32_crockford(cell_of(state).routed().key())
        );
        assert!(
            !asked.contains(&read),
            "the walk read generation {}'s cell again",
            state.generation() + 1
        );
    }
}

/// Forget the reserve lineage this process walked: its memo and every read
/// kept final — a device that keeps nothing of the reserve.
fn forget_the_reserve() {
    {
        let binding = client_db::get_connection().expect("the store");
        let conn = binding.lock().expect("the store is not poisoned");
        conn.execute("DELETE FROM native_reserve_lineage_memo", [])
            .expect("forget the walked lineage");
    }
    crate::sdk::final_reads::forget_everything();
}

/// The memoised lineage, generation by generation: what a walk established.
fn walked_lineage() -> Vec<(u64, [u8; 32])> {
    let mut walked = Vec::new();
    client_db::native_reserve::fold_memoised_lineage(&reserve_genesis(), |_, state, _, _| {
        walked.push((state.generation(), state.root()));
        Ok(std::ops::ControlFlow::Continue(()))
    })
    .expect("the memo");
    walked
}

/// A walker owes the epoch index the hint of every generation it established
/// unless that very hint was found, and the sweep publishes them: a later
/// reader reads each generation's root there. What it owes is what it
/// established.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_reserve_walker_publishes_a_hint_for_each_generation_it_established() {
    use dsm::shared_lineage::LineageKind;
    let d = Device::start(0xA5).await;
    for _ in 0..3 {
        claim_era_faucet(d.core(), NETWORK).await.expect("a claim");
    }
    forget_the_reserve();
    assert_eq!(reserve_head().await.generation(), 3);
    let established = walked_lineage();
    assert_eq!(established.len(), 3);
    crate::handlers::artifact_republish::publish_lineage_debt()
        .await
        .expect("the sweep publishes what is owed");

    let set = canonical_set(NETWORK).expect("canonical set");
    let found = crate::sdk::lineage_discovery::discover(
        &set,
        LineageKind::Reserve,
        reserve_genesis().reserve_id(),
        0,
    )
    .await;
    for (generation, root) in &established {
        assert_eq!(
            found.roots_at(*generation).collect::<Vec<_>>(),
            vec![root],
            "generation {generation} is hinted, naming the root the walk established"
        );
    }
}

/// Discovery carries no authority (SoFi Amendment S23). The epoch index of
/// the reserve holds, beside the hints a walker published, a hint naming a
/// root generation 2 never had and a hint naming generation 1,000,000. A
/// device that keeps nothing of the reserve reads them all, and its walk
/// establishes exactly the lineage a walk without any hint establishes:
/// the same generations, the same roots, the same head.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn lying_reserve_hints_change_nothing_a_walk_establishes() {
    use dsm::shared_lineage::{GenerationHintV1, LineageKind};
    let d = Device::start(0xA6).await;
    for _ in 0..3 {
        claim_era_faucet(d.core(), NETWORK).await.expect("a claim");
    }
    forget_the_reserve();
    reserve_head().await;
    let honest = walked_lineage();
    crate::handlers::artifact_republish::publish_lineage_debt()
        .await
        .expect("the sweep publishes what is owed");

    let set = canonical_set(NETWORK).expect("canonical set");
    let reserve_id = *reserve_genesis().reserve_id();
    for (generation, root) in [(2u64, [0x6F; 32]), (1_000_000u64, [0x70; 32])] {
        let lie = GenerationHintV1::new(
            LineageKind::Reserve,
            reserve_id,
            generation,
            root,
            [0x71; 32],
            [0x72; 32],
        )
        .expect("a hint");
        append_hint(&set, &lie).await;
    }
    let found =
        crate::sdk::lineage_discovery::discover(&set, LineageKind::Reserve, &reserve_id, 0).await;
    assert_eq!(
        found.roots_at(2).count(),
        2,
        "the lie is read beside the honest hint: discovery decides nothing"
    );

    forget_the_reserve();
    let head = reserve_head().await;
    assert_eq!(
        head.generation(),
        3,
        "the head is where the reserve is, not where a hint says"
    );
    assert_eq!(
        walked_lineage(),
        honest,
        "the walk established exactly what it established without the lies"
    );
}

/// Releases enough that the cells their hints name hold more than one walk's
/// read-ahead window: each named cell's read keeps the release from every
/// seat that holds it.
const RELEASES_PAST_THE_WINDOW: u64 = 140;

/// MR-DSM-0310, MR-DSM-0312: what a walk reads early never decides what it
/// establishes. A walk reads ahead the cells the epoch index names within a
/// window of `READ_AHEAD_BYTES`; a cell whose read the window cut short is a
/// cell the walk reads again itself. Every generation of a reserve longer
/// than the window holds is hinted, so a device that keeps nothing of it
/// reads ahead until the window is spent, some cells only in part. Its walk
/// still reaches the head and establishes exactly the lineage the claimant's
/// walks did.
///
/// MUTATION CONTROL: taking a read-ahead read Core did not resolve final
/// (`reserve_ahead_unresolved`) turns this red.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_walk_past_what_its_read_ahead_holds_establishes_the_whole_lineage() {
    use dsm::shared_lineage::LineageKind;
    let d = Device::start(0xAA).await;
    for _ in 0..RELEASES_PAST_THE_WINDOW {
        claim_era_faucet(d.core(), NETWORK).await.expect("a claim");
    }
    assert_eq!(reserve_head().await.generation(), RELEASES_PAST_THE_WINDOW);
    let established = walked_lineage();
    crate::handlers::artifact_republish::publish_lineage_debt()
        .await
        .expect("the sweep publishes what is owed");
    let set = canonical_set(NETWORK).expect("canonical set");
    let found = crate::sdk::lineage_discovery::discover(
        &set,
        LineageKind::Reserve,
        reserve_genesis().reserve_id(),
        0,
    )
    .await;
    for (generation, root) in &established {
        assert!(
            found.roots_at(*generation).any(|named| named == root),
            "generation {generation} is hinted, so the walk reads its cell ahead"
        );
    }

    forget_the_reserve();
    let head = reserve_head().await;
    assert_eq!(
        head.generation(),
        RELEASES_PAST_THE_WINDOW,
        "the walk reaches the head past what it read ahead"
    );
    assert_eq!(
        walked_lineage(),
        established,
        "the walk established exactly what the claimant's walks did"
    );
}

/// Put `hint` and append it to its epoch's index, as anyone may.
async fn append_hint(
    set: &crate::sdk::storage_set::StorageSet,
    hint: &dsm::shared_lineage::GenerationHintV1,
) {
    use dsm::shared_lineage::{epoch_locator, epoch_of};
    let (addr, took) = crate::sdk::storage_io::put_immutable(
        set,
        dsm::common::domain_tags::TAG_DSM_SHARED_LINEAGE_OBJECT,
        &hint.encode(),
    )
    .await
    .expect("anyone may put an object");
    assert!(took > 0);
    crate::sdk::storage_io::append_to_index(
        set,
        dsm::common::domain_tags::TAG_DSM_SHARED_LINEAGE_EPOCH_LOCATOR.source_bytes(),
        &epoch_locator(hint.kind(), hint.lineage_id(), epoch_of(hint.generation())),
        &addr,
    )
    .await
    .expect("anyone may append");
}

/// A hint anyone appends names whatever root it likes. A walker owes the
/// epoch index the hint of each generation it established unless that very
/// hint was found: a hint naming another root at the generation is not the
/// generation's own (SoFi Amendment S23), as another checkpoint for a start
/// is not the segment's own (`owe_checkpoint`). The reserve's index holds a
/// lie at generation 3, appended after the release at 3 and before any walk
/// established it. A walk and the sweep later, the index names generation
/// 3's own root beside the lie.
///
/// MUTATION CONTROL: owing a hint only for a generation no hint names
/// (`owe_hint_any_root`) turns this red.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_lying_hint_does_not_stop_a_walker_owing_the_generations_own() {
    use dsm::shared_lineage::{GenerationHintV1, LineageKind};
    let d = Device::start(0xA9).await;
    // Each claim walks before it releases, so after the third no walk has
    // established generation 3 and nothing owes its hint.
    for _ in 0..3 {
        claim_era_faucet(d.core(), NETWORK).await.expect("a claim");
    }
    let set = canonical_set(NETWORK).expect("canonical set");
    let reserve_id = *reserve_genesis().reserve_id();
    let lie = GenerationHintV1::new(
        LineageKind::Reserve,
        reserve_id,
        3,
        [0x6D; 32],
        [0x71; 32],
        [0x72; 32],
    )
    .expect("a hint");
    append_hint(&set, &lie).await;

    assert_eq!(reserve_head().await.generation(), 3);
    let established = walked_lineage();
    assert_eq!(established.len(), 3);
    crate::handlers::artifact_republish::publish_lineage_debt()
        .await
        .expect("the sweep publishes what is owed");

    let found =
        crate::sdk::lineage_discovery::discover(&set, LineageKind::Reserve, &reserve_id, 0).await;
    assert!(
        found.roots_at(3).any(|named| named == lie.claimed_root()),
        "the lie stays in the index: discovery decides nothing"
    );
    for (generation, root) in &established {
        assert!(
            found.roots_at(*generation).any(|named| named == root),
            "generation {generation}'s own root is hinted, whatever else is"
        );
    }
}

/// SA-69. Anyone may append a checkpoint, and every root a walk is handed is
/// a cell it reads. The reserve's epoch index holds a checkpoint naming 33
/// roots the reserve never had, under a start digest no walk computed. A
/// device that keeps nothing of the reserve walks to the head and reads the
/// cell of none of them: a checkpoint names cells only for the segment that
/// starts at a head the device established (S23, a fresh reader, step 2).
/// MUTATION CONTROL: admitting checkpoints without `eligible_at` turns this
/// red.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_checkpoint_no_walk_established_names_no_cell_the_walk_reads() {
    use dsm::shared_lineage::{epoch_locator, CheckpointV1, LineageKind, EPOCH_GENERATIONS};
    let d = Device::start(0xA8).await;
    for _ in 0..2 {
        claim_era_faucet(d.core(), NETWORK).await.expect("a claim");
    }
    let set = canonical_set(NETWORK).expect("canonical set");
    let reserve_id = *reserve_genesis().reserve_id();
    let made_up: Vec<[u8; 32]> = (0..=EPOCH_GENERATIONS)
        .map(|i| {
            let mut root = [0x6E; 32];
            root[0] = i as u8;
            root
        })
        .collect();
    let lie = CheckpointV1::new(
        LineageKind::Reserve,
        reserve_id,
        0,
        [0x73; 32],
        [0x74; 32],
        made_up.clone(),
        [0x75; 32],
    )
    .expect("a checkpoint anyone may write");
    let (addr, took) = crate::sdk::storage_io::put_immutable(
        &set,
        dsm::common::domain_tags::TAG_DSM_SHARED_LINEAGE_OBJECT,
        &lie.encode(),
    )
    .await
    .expect("anyone may put an object");
    assert!(took > 0);
    crate::sdk::storage_io::append_to_index(
        &set,
        dsm::common::domain_tags::TAG_DSM_SHARED_LINEAGE_EPOCH_LOCATOR.source_bytes(),
        &epoch_locator(LineageKind::Reserve, &reserve_id, 0),
        &addr,
    )
    .await
    .expect("anyone may append");

    forget_the_reserve();
    for node in &d.nodes.nodes {
        node.forget_requests();
    }
    assert_eq!(reserve_head().await.generation(), 2);
    let asked: Vec<String> = d.nodes.nodes.iter().flat_map(|n| n.requests()).collect();
    for root in &made_up {
        let read = format!(
            "GET /api/v2/cell/{}",
            crate::util::text_id::encode_base32_crockford(
                &dsm::economic::native_reserve::reserve_cell_key(&reserve_id, root)
            )
        );
        assert!(
            !asked.contains(&read),
            "the walk read the cell of a root only the checkpoint named"
        );
    }
}

/// The epoch index is predictable and anyone may append to it. Flooded past
/// what a reader reads per epoch, the epoch's discovery is unavailable: the
/// walk reads that epoch's cells itself, and establishes the same head.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_flooded_epoch_index_makes_discovery_unavailable_and_nothing_else() {
    use dsm::shared_lineage::{epoch_locator, LineageKind};
    let d = Device::start(0xA7).await;
    for _ in 0..2 {
        claim_era_faucet(d.core(), NETWORK).await.expect("a claim");
    }
    let set = canonical_set(NETWORK).expect("canonical set");
    let reserve_id = *reserve_genesis().reserve_id();
    let locator = epoch_locator(LineageKind::Reserve, &reserve_id, 0);
    for n in 0..=crate::sdk::lineage_discovery::CANDIDATES_PER_EPOCH {
        let junk = format!("not a hint, {n}").into_bytes();
        let (addr, _) = crate::sdk::storage_io::put_immutable(
            &set,
            dsm::common::domain_tags::TAG_DSM_SHARED_LINEAGE_OBJECT,
            &junk,
        )
        .await
        .expect("anyone may put an object");
        crate::sdk::storage_io::append_to_index(
            &set,
            dsm::common::domain_tags::TAG_DSM_SHARED_LINEAGE_EPOCH_LOCATOR.source_bytes(),
            &locator,
            &addr,
        )
        .await
        .expect("anyone may append");
    }
    forget_the_reserve();
    let head = reserve_head().await;
    assert_eq!(
        head.generation(),
        2,
        "the walk reaches the head without discovery"
    );
    assert_eq!(walked_lineage().len(), 2);
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
    assert_eq!(outcome.tokens_received, whole_era(100));
    assert_eq!(outcome.economic_position, 1, "A's own first position");
    assert_eq!(p.a.era_balance(), whole_era(100));

    assert_eq!(recipient_of(&release_at(1).await), p.b.device_id);
    assert_eq!(recipient_of(&release_at(2).await), p.a.device_id);
    let head = reserve_head().await;
    assert_eq!(head.generation(), 2);
    assert_eq!(
        head.remaining_supply(),
        reserve_genesis_supply().expect("ERA's genesis supply") - whole_era(200)
    );
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
    let frozen = client_db::native_reserve::get_frozen_release(r0.reserve_id(), &r0.root())
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
    assert_eq!(p.b.era_balance(), whole_era(100));
    let first = release_at(1).await;
    assert_eq!(first.envelope_bytes, frozen, "generation 1 is A's release");
    assert_eq!(recipient_of(&release_at(2).await), p.b.device_id);

    p.a.enter();
    let resumed = claim_era_faucet(&p.a.router().core_sdk, NETWORK)
        .await
        .expect("A finishes on its own generation");
    assert_eq!(resumed.tokens_received, whole_era(100));
    assert_eq!(resumed.economic_position, 1);
    assert_eq!(p.a.era_balance(), whole_era(100));
    let head = reserve_head().await;
    assert_eq!(head.generation(), 2, "A released once, B once");
    assert_eq!(
        head.remaining_supply(),
        reserve_genesis_supply().expect("ERA's genesis supply") - whole_era(200)
    );
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
    let frozen = client_db::native_reserve::get_frozen_release(r0.reserve_id(), &r0.root())
        .expect("read the frozen release")
        .expect("the release was frozen before it was written");

    d.nodes.bring_up(&cut).await;
    let outcome = claim_era_faucet(d.core(), NETWORK)
        .await
        .expect("resumed claim");
    assert_eq!(outcome.tokens_received, whole_era(100));
    assert_eq!(outcome.economic_position, 1);
    assert_eq!(
        release_at(1).await.envelope_bytes,
        frozen,
        "the resumed claim used the frozen release"
    );
    assert_eq!(reserve_head().await.generation(), 1, "released once");
    assert_eq!(d.era_balance(), whole_era(100));
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
    assert_eq!(d.era_balance(), whole_era(300));
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

    // A foreign walk: nothing below reads local admission state. A device
    // records no frontier for itself, so the walk is from position 0.
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
        Some(dsm::types::operations::Operation::FaucetClaim { .. })
    ));
}

// ── A device's first admission, held after its advance ────────────────────
//
// The advance and the pending admission commit in one transaction, so a
// first admission held at any later step leaves the device with its credit on
// the head (fenced) and nothing admitted. Resuming it must reach the
// activation root it was built on, whichever production path resumes it.

/// The seats of this device's first root cell `K_root(1)` after its first
/// two, in route order, and the cell's key. Refusing their writes lets the
/// first root claim reach the leader and one more seat and no further: a chain
/// of two links, which is never final (storage spec §9).
fn seats_past_the_second_of_the_first_root_cell(d: &Device) -> (Vec<String>, [u8; 32]) {
    let set = canonical_set(NETWORK).expect("canonical set");
    let cell = crate::sdk::economic_registers::root_cell(
        &set,
        NETWORK,
        &d.identity.genesis,
        &d.identity.device_id,
        1,
        &dsm::economic::tree::empty_economic_root(),
    )
    .expect("K_root(1)");
    let seats = cell.routed().route().seats()[2..]
        .iter()
        .map(|id| String::from_utf8(id.clone()).expect("member ids are UTF-8"))
        .collect();
    (seats, *cell.routed().key())
}

/// Run `d`'s first claim while its root claim cannot become final, so the
/// claim is held for resume after its advance credited the head; then let the
/// members take writes again. Returns the held admission.
async fn hold_the_first_claim(d: &Device) -> dsm::economic::admission::PendingEconomicAdmission {
    let (seats, key) = seats_past_the_second_of_the_first_root_cell(d);
    for seat in &seats {
        d.nodes.refuse_cell_writes(seat, &[key]).await;
    }
    let held = match claim_era_faucet(d.core(), NETWORK).await {
        Ok(outcome) => panic!(
            "a root claim of two links is not final, yet the claim admitted position {}",
            outcome.economic_position
        ),
        Err(e) => e.to_string(),
    };
    assert!(held.contains("the claim is not final yet"), "{held}");
    let head = d.core().device_head().expect("head");
    let pending = head
        .pending_economic_admission()
        .cloned()
        .expect("the first claim is held for resume");
    assert_eq!(pending.economic_position, 1, "the first admission");
    assert_eq!(
        pending.pre_economic_root,
        dsm::economic::tree::empty_economic_root(),
        "built on the activation root"
    );
    assert_eq!(
        head.balance(&era()),
        whole_era(100),
        "the held advance has already credited the head"
    );
    assert!(
        client_db::economic_lineage::get_admitted_coordinate()
            .expect("read admitted")
            .is_none(),
        "nothing is admitted yet"
    );
    for seat in &seats {
        d.nodes.accept_cell_writes(seat).await;
    }
    pending
}

/// `core`'s lineage is admitted at `position` and nothing is pending.
fn admitted_at(core: &crate::sdk::core_sdk::CoreSDK, position: u64) {
    assert!(
        core.device_head()
            .expect("head")
            .pending_economic_admission()
            .is_none(),
        "admitted ⇒ unfenced"
    );
    let (admitted, _root) = client_db::economic_lineage::get_admitted_coordinate()
        .expect("read admitted")
        .expect("admitted recorded");
    assert_eq!(admitted, position);
}

/// A held first claim is finished by resuming it: its predecessor is the
/// activation root, though the head already holds the claim's own credit.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_held_first_claim_is_finished_by_resuming_it() {
    let d = Device::start(0xA9).await;
    let pending = hold_the_first_claim(&d).await;
    let admitted =
        crate::sdk::economic_admission_flow::resume_pending_admission(d.core(), NETWORK, pending)
            .await
            .expect("the held first claim resumes");
    assert_eq!(admitted.economic_position, 1);
    admitted_at(d.core(), 1);
    assert_eq!(d.era_balance(), whole_era(100), "credited once");
    assert_eq!(recipient_of(&release_at(1).await), d.identity.device_id);
}

/// The next claim finishes a held first claim before it claims again: the
/// held one lands at position 1 and the new one at position 2.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_held_first_claim_is_finished_by_the_next_claim() {
    let d = Device::start(0xAA).await;
    hold_the_first_claim(&d).await;
    let next = claim_era_faucet(d.core(), NETWORK)
        .await
        .expect("the next claim finishes the held one, then claims");
    assert_eq!(next.economic_position, 2);
    admitted_at(d.core(), 2);
    assert_eq!(d.era_balance(), whole_era(200));
    assert_eq!(
        reserve_head().await.generation(),
        2,
        "released twice, once each"
    );
}

/// After a restart the sync finishes a first claim the previous run left held
/// (the stranded-admission sweep).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_held_first_claim_is_finished_by_the_sync_after_a_restart() {
    use dsm::types::proto;
    use prost::Message;
    let d = Device::start(0xAB).await;
    hold_the_first_claim(&d).await;
    let restarted = crate::economic_fixtures::restart_router(&d.fleet);
    let answered = restarted
        .invoke(AppInvoke {
            method: "storage.sync".to_string(),
            args: proto::ArgPack {
                codec: proto::Codec::Proto as i32,
                body: crate::sdk::inbox_poller::poll_sync_request().encode_to_vec(),
                schema_hash: None,
            }
            .encode_to_vec(),
        })
        .await;
    assert!(
        answered.success,
        "storage.sync: {:?}",
        answered.error_message
    );
    let sync = match crate::handlers::response_helpers::decode_local_envelope(&answered.data)
        .expect("storage.sync answers an envelope")
        .payload
    {
        Some(proto::envelope::Payload::StorageSyncResponse(resp)) => resp,
        other => panic!("storage.sync answered {other:?}"),
    };
    assert!(
        !sync.errors.iter().any(|e| e.contains("stranded admission")),
        "{:?}",
        sync.errors
    );
    admitted_at(&restarted.core_sdk, 1);
    assert_eq!(
        restarted
            .core_sdk
            .device_head()
            .expect("head")
            .balance(&era()),
        whole_era(100),
        "credited once"
    );
}

/// SA-70. A release frozen for an earlier position is not reused at a later
/// one. A claim whose release never reached the reserve cell's leader leaves
/// it frozen at that head, naming the position the device was about to take.
/// Once the device has admitted at that position by other means (here, a
/// payment it received), the next claim at the same head signs its own
/// release for its new position and finishes there. Reusing the frozen bytes
/// registered a root claim that failed its own provenance check, and fenced
/// the wallet for good.
/// MUTATION CONTROL: reusing whatever is frozen at the parent root, as the
/// claim did, turns this red.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_release_frozen_for_an_earlier_position_is_not_reused_at_a_later_one() {
    use dsm::economic::native_reserve::{
        sign_release, NativeReserveReleaseBody, ReleaseSource, ERA_FAUCET_PAYOUT,
    };
    let p = Pair::boot(0, 100).await;
    let sent = p.b.send(&p.a, whole_era(10)).await;
    assert!(sent.success, "{:?}", sent.error_message);
    let applied = p.a.sync().await;
    assert!(applied.success, "{:?}", applied.errors);

    p.a.enter();
    let core = &p.a.router().core_sdk;
    let taken = crate::sdk::economic_admission_flow::validated_root_or_activate(core)
        .expect("A's validated root")
        .economic_position();
    assert!(
        taken >= 1,
        "A admitted the payment at a position of its own"
    );

    // What a claim made before that admission froze: a release at the reserve
    // head for the position A has since taken, its write never at the leader.
    let head = reserve_head().await;
    let generation = head.generation() + 1;
    let device_head = core.device_head().expect("A's head");
    let (public_key, secret_key) =
        crate::sdk::signing_authority::current_keypair().expect("A's keys");
    let att_a = crate::sdk::signing_authority::current_att_a().expect("A's AttA");
    let op = dsm::types::operations::Operation::FaucetClaim {
        reserve_id: *head.reserve_id(),
        generation,
    };
    let earlier = NativeReserveReleaseBody {
        reserve_id: *head.reserve_id(),
        parent_root: head.root(),
        generation,
        amount: ERA_FAUCET_PAYOUT,
        recipient_genesis: device_head.genesis_digest(),
        recipient_devid: device_head.devid(),
        recipient_economic_position: taken,
        recipient_operation_digest: dsm::economic::admission::dsm_operation_digest(&op.to_bytes()),
        storage_set_id: canonical_set(NETWORK).expect("canonical set").id(),
        source: ReleaseSource::FaucetClaimant {
            claimant_public_key: public_key,
            claimant_att_a: att_a,
        },
    };
    let frozen = sign_release(&earlier, &secret_key).expect("sign the earlier release");
    client_db::native_reserve::freeze_release(head.reserve_id(), &head.root(), &frozen)
        .expect("freeze it");

    let outcome = claim_era_faucet(core, NETWORK)
        .await
        .expect("the claim finishes at A's own next position");
    assert_eq!(outcome.economic_position, taken + 1);
    assert_eq!(outcome.tokens_received, whole_era(100));
    assert_eq!(p.a.era_balance(), whole_era(110));
}

/// SA-90. An advance with no admission plan that fails leaves the head's
/// pending admission as it found it. Here the first claim is held (its
/// admission pending on the head) and an offline step the fence refuses is
/// attempted; the held admission is still the head's afterwards. Clearing it
/// on that failure let the next admission be built at the same position and
/// overwrite the held one.
/// MUTATION CONTROL: clearing the pending admission on every failed advance,
/// as the advance did, turns this red.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_failed_advance_keeps_the_pending_admission_it_did_not_make() {
    use dsm::types::device_state::{BalanceDelta, BalanceDirection};
    let d = Device::start(0xAC).await;
    let held = hold_the_first_claim(&d).await;
    let refused = d.core().execute_offline_step(
        [0x71; 32],
        [0x72; 32],
        dsm::types::operations::Operation::Generic {
            operation_type: b"zero-effect-step".to_vec(),
            data: vec![0x01],
            message: String::new(),
            signature: Vec::new(),
        },
        &[BalanceDelta {
            policy_commit: era(),
            direction: BalanceDirection::Debit,
            amount: 1,
        }],
        None,
        None,
        &|_, _| {
            Err(dsm::types::error::DsmError::invalid_operation(
                "the advance is refused before its transaction opens",
            ))
        },
    );
    refused.expect_err("the step is refused");
    assert_eq!(
        d.core()
            .device_head()
            .expect("the head")
            .pending_economic_admission()
            .cloned(),
        Some(held),
        "the held admission is still the head's"
    );
}

/// Generation `generation`'s memo row: its envelope and the reads kept with
/// it.
fn memo_row(generation: u64) -> (Vec<u8>, Vec<u8>) {
    let binding = client_db::get_connection().expect("the store");
    let conn = binding.lock().expect("the store is not poisoned");
    conn.query_row(
        "SELECT envelope, cell_reads FROM native_reserve_lineage_memo WHERE generation = ?1",
        [generation as i64],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )
    .expect("the memo row")
}

/// Set generation `generation`'s memo row's `column` to `bytes`.
fn set_memo_column(generation: u64, column: &str, bytes: &[u8]) {
    let binding = client_db::get_connection().expect("the store");
    let conn = binding.lock().expect("the store is not poisoned");
    conn.execute(
        &format!("UPDATE native_reserve_lineage_memo SET {column} = ?1 WHERE generation = ?2"),
        rusqlite::params![bytes, generation as i64],
    )
    .expect("the memo row is changed");
}

/// DSM Amendment A15, MR-DSM-0315: a verifier is answered from the head
/// this device's walks established. With generation 4's memo row gone, a
/// memoised release on the chain comes with the chain's heads before and
/// after it, and a release memoised past the gap is not established, so a
/// verifier walks for it instead.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_memoised_release_past_a_gap_is_not_an_established_release() {
    use crate::sdk::native_reserve::established_release_at;
    let d = Device::start(0xAB).await;
    for _ in 0..5 {
        claim_era_faucet(d.core(), NETWORK).await.expect("a claim");
    }
    assert_eq!(reserve_head().await.generation(), 5);
    let set = canonical_set(NETWORK).expect("canonical set");
    let genesis = reserve_genesis();
    let whole = established_release_at(&set, &genesis, 3)
        .expect("the memo loads")
        .expect("generation 3 is on the chain");
    {
        let binding = client_db::get_connection().expect("the store");
        let conn = binding.lock().expect("the store is not poisoned");
        conn.execute(
            "DELETE FROM native_reserve_lineage_memo WHERE generation = 4",
            [],
        )
        .expect("generation 4's row is gone");
    }
    assert_eq!(
        established_release_at(&set, &genesis, 3).expect("the memo loads"),
        Some(whole),
        "a release before the gap is answered with the chain's heads around it"
    );
    assert_eq!(
        established_release_at(&set, &genesis, 5).expect("the memo loads"),
        None,
        "a release memoised past the gap is not established"
    );
    assert_eq!(
        established_release_at(&set, &genesis, 4).expect("the memo loads"),
        None
    );
}

/// How one memo row is made something Core does not establish.
enum Corruption {
    /// The release's envelope, in place of the one memoised.
    Envelope(Vec<u8>),
    /// The reads kept with the release, in place of the ones memoised.
    Reads(Vec<u8>),
    /// The release's kept completion proof, gone.
    NoProof,
}

/// DSM Amendment A15, MR-DSM-0310, MR-DSM-0315: a memoised release is
/// established again by Core on load from what the memo keeps (the release,
/// the reads of its cell that showed it final, and its kept completion
/// proof), never taken as a root. After three claims, generation 2's row is
/// changed one way at a time, and restored after each:
/// - its envelope forged;
/// - its envelope a real release of another parent, generation 1's;
/// - its reads with every seat after the leader unread, which no longer show
///   the release final;
/// - its reads gone;
/// - its completion proof gone.
///
/// Each time the real loader refuses at generation 2 and answers nothing.
/// Restored, the memo loads as it did.
///
/// MUTATION CONTROL: taking a memoised release without proving it final from
/// the reads kept with it (`reserve_memo_unproven`) turns the unread-seats
/// case red.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_forged_memo_row_is_refused_on_load_and_enters_no_chain() {
    use crate::sdk::native_reserve::established_release_at;
    use dsm::economic::native_reserve::SuccessorCell;
    use dsm::route_chain::CellEvidence;
    let d = Device::start(0xAC).await;
    for _ in 0..3 {
        claim_era_faucet(d.core(), NETWORK).await.expect("a claim");
    }
    assert_eq!(reserve_head().await.generation(), 3);
    let set = canonical_set(NETWORK).expect("canonical set");
    let genesis = reserve_genesis();
    let honest = established_release_at(&set, &genesis, 3)
        .expect("the honest memo loads")
        .expect("generation 3 is on the chain");

    let (envelope, reads) = memo_row(2);
    let (other_parents, _) = memo_row(1);
    let mut bent = envelope.clone();
    let last = bent.len() - 1;
    bent[last] ^= 0x01;
    let members = as_ccb_members(&set).expect("the set's members");
    let cell = SuccessorCell::of(&genesis.at_generation(1).expect("generation 1"), &members)
        .expect("generation 2's cell");
    let mut unread = CellEvidence::decode_kept(cell.routed(), &reads, &cell.keeps())
        .expect("the kept reads decode");
    for seat in unread.seats.iter_mut().skip(1) {
        seat.values = None;
    }
    let kept_proof = client_db::completion_proofs::get(cell.routed(), &envelope)
        .expect("the proof store")
        .expect("the release's completion proof is kept");

    for (what, corruption) in [
        ("a forged envelope", Corruption::Envelope(bent)),
        (
            "another parent's release",
            Corruption::Envelope(other_parents),
        ),
        (
            "reads with the seats after the leader unread",
            Corruption::Reads(unread.encode_kept()),
        ),
        ("no reads", Corruption::Reads(Vec::new())),
        ("no completion proof", Corruption::NoProof),
    ] {
        match &corruption {
            Corruption::Envelope(bytes) => set_memo_column(2, "envelope", bytes),
            Corruption::Reads(bytes) => set_memo_column(2, "cell_reads", bytes),
            Corruption::NoProof => {
                let binding = client_db::get_connection().expect("the store");
                let conn = binding.lock().expect("the store is not poisoned");
                conn.execute(
                    "DELETE FROM completion_proof_slot WHERE value_digest = ?1",
                    [dsm::storage_cell::entry_digest(&envelope).as_slice()],
                )
                .expect("the proof's slots are gone");
                conn.execute(
                    "DELETE FROM completion_proof WHERE value_digest = ?1",
                    [dsm::storage_cell::entry_digest(&envelope).as_slice()],
                )
                .expect("the proof is gone");
            }
        }
        match established_release_at(&set, &genesis, 3) {
            Err(refused) => assert!(
                refused.to_string().contains("generation 2"),
                "{what}: the refusal names the generation: {refused}"
            ),
            Ok(answer) => panic!("{what} was loaded into the lineage: {answer:?}"),
        }
        match corruption {
            Corruption::Envelope(..) => set_memo_column(2, "envelope", &envelope),
            Corruption::Reads(..) => set_memo_column(2, "cell_reads", &reads),
            Corruption::NoProof => client_db::completion_proofs::keep(
                cell.routed(),
                &kept_proof.digest,
                &kept_proof.proof,
            )
            .expect("the proof is kept again"),
        }
    }
    assert_eq!(
        established_release_at(&set, &genesis, 3)
            .expect("the restored memo loads")
            .expect("generation 3 is on the chain"),
        honest
    );
}
