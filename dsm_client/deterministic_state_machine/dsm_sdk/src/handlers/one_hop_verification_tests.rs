// SPDX-License-Identifier: Apache-2.0

//! One-hop verification (DSM Amendment A14; owner paper, Definition 57) on
//! the storage nodes. A verifier validates a peer's step from the step's own
//! parent: it finds the peer's claims under the register key of the
//! position, takes each to the cell routed from the parent its own witness
//! names, accepts the one final there, and validates the step from that
//! parent. A credit's source is the source's one step. Nothing behind the
//! parent is read, so acceptance costs the same at first contact as later.

use serial_test::serial;

use crate::economic_fixtures::NETWORK;
use crate::storage::client_db;
use crate::test_support::one_device::Device;
use crate::test_support::two_device::{Pair, TestDevice};
use dsm::economic::claim_envelope::RegisteredEconomicClaim;
use dsm::economic::provenance::{PeerLineageFailure, ValidatedPeerTransition};
/// `peer`'s step at `position`, verified one hop by the entered device, as
/// its provenance checks verify it.
async fn verify(
    genesis: [u8; 32],
    devid: [u8; 32],
    position: u64,
) -> Result<ValidatedPeerTransition, PeerLineageFailure> {
    let handle = tokio::runtime::Handle::current();
    tokio::task::spawn_blocking(move || {
        use dsm::economic::provenance::ProvenanceResolver;
        let set = crate::sdk::storage_set::canonical_set(NETWORK).expect("canonical set");
        crate::sdk::economic_registers::LiveRegisterResolver {
            set: &set,
            runtime: handle,
            expected_network_id: NETWORK.to_vec(),
        }
        .validated_peer_transition(&genesis, &devid, position)
    })
    .await
    .expect("join")
}

/// The request a member logs for a read of the root cell of
/// `(genesis, devid)` at `position`, routed from `parent_root`.
fn cell_read(
    genesis: &[u8; 32],
    devid: &[u8; 32],
    position: u64,
    parent_root: &[u8; 32],
) -> String {
    let set = crate::sdk::storage_set::canonical_set(NETWORK).expect("canonical set");
    let cell = crate::sdk::economic_registers::root_cell(
        &set,
        NETWORK,
        genesis,
        devid,
        position,
        parent_root,
    )
    .expect("the root cell");
    format!(
        "GET /api/v2/cell/{}",
        crate::util::text_id::encode_base32_crockford(cell.routed().key())
    )
}

/// Every request the members were asked since they last forgot.
fn requests(nodes: &crate::test_support::nodes::NodeSet) -> Vec<String> {
    nodes.nodes.iter().flat_map(|n| n.requests()).collect()
}

/// The entered device's admitted root at `position`, and the manifest its
/// frozen claim there names.
fn admitted(position: u64) -> ([u8; 32], [u8; 32]) {
    let root = match client_db::economic_lineage::get_admitted_at(position)
        .expect("admitted history")
        .expect("an admitted position")
    {
        dsm::economic::lineage::AdmittedEconomicPosition::SingleRoot { economic_root, .. } => {
            economic_root
        }
        other => panic!("position {position} is a single-root position, got {other:?}"),
    };
    let (_, claim) = client_db::economic_lineage::get_frozen_root_claim(position)
        .expect("frozen claims")
        .expect("the claim frozen at the position");
    let manifest = match dsm::economic::claim_envelope::decode_registered_economic_claim(&claim)
        .expect("the frozen claim decodes")
    {
        RegisteredEconomicClaim::SingleRoot(claim) => claim.body().admission_manifest_addr,
        RegisteredEconomicClaim::ConditionalSofi(_) => {
            panic!("position {position} is a single-root position")
        }
    };
    (root, manifest)
}

/// C's three-device setup: A and B as a pair, C booted on the same fleet,
/// all three contacts of each other, and C funded.
async fn three_devices() -> (Pair, TestDevice) {
    let p = Pair::boot(100, 0).await;
    let mut c = TestDevice::create("C", 0x0C);
    c.boot(&p.fleet).await;
    for peer in [&p.a, &p.b] {
        c.add_contact(peer).await;
        peer.add_contact(&c).await;
    }
    c.fund_admitted(100).await;
    (p, c)
}

/// C pays A `amount`, A takes it in, and the position C admitted the debit
/// at.
async fn c_pays_a(p: &Pair, c: &TestDevice, amount: u64) -> u64 {
    let sent = c.send(&p.a, amount).await;
    assert!(sent.success, "{:?}", sent.error_message);
    let credited = p.a.sync().await;
    assert!(credited.success, "{:?}", credited.errors);
    c.enter();
    client_db::economic_lineage::get_admitted_coordinate()
        .expect("read")
        .expect("C admitted its debit to A")
        .0
}

/// `receiver` takes in what was sent to it, as a process that remembers
/// nothing it validated before: the root cells its resolver was asked for
/// meanwhile, counted by routed key.
async fn accept(receiver: &TestDevice) -> std::collections::HashMap<[u8; 32], usize> {
    crate::sdk::economic_registers::validated_peers().forget();
    crate::sdk::economic_registers::asked_cells::take();
    let received = receiver.sync().await;
    assert!(received.success, "{:?}", received.errors);
    crate::sdk::economic_registers::asked_cells::take()
}

/// How many times the cell `key` was asked for.
fn asks(asked: &std::collections::HashMap<[u8; 32], usize>, key: &[u8; 32]) -> usize {
    asked.get(key).map_or(0, |n| *n)
}

/// `device`'s root register key at `position`: what its resolver is asked
/// for, by unrouted probe and by routed read alike, at that position.
fn key_at(device: &TestDevice, position: u64) -> [u8; 32] {
    dsm::economic::register::economic_root_register_key(
        &device.genesis,
        &device.device_id,
        position,
    )
}

/// The positions of `device`, among `1..=through`, whose register key was
/// asked for, with how many times.
fn positions_asked(
    asked: &std::collections::HashMap<[u8; 32], usize>,
    device: &TestDevice,
    through: u64,
) -> Vec<(u64, usize)> {
    (1..=through)
        .filter_map(|position| {
            let n = asks(asked, &key_at(device, position));
            (n > 0).then_some((position, n))
        })
        .collect()
}

/// A claim whose own witness was built on another root than the one its
/// cell is routed from is never accepted (DSM Amendment A14). A device
/// registers, under its own key, a claim at position 2 that names its first
/// step's manifest, whose witness was built on the activation root, and a
/// root no step of its produced, along the cell routed from its real root at
/// 1. The claim is final there and its signature verifies. Checked one hop,
/// it is not final at the cell routed from the parent its witness names, and
/// its step is not accepted.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_claim_whose_witness_names_another_parent_is_never_accepted() {
    use crate::sdk::economic_registers::{
        register_economic_root, root_claim_settlement, root_cell, RootClaimSettlement,
    };
    let d = Device::funded(0xA8).await;
    let head = d.core().device_head().expect("head");
    let (genesis, devid) = (head.genesis_digest(), head.devid());
    let (first_root, first_manifest) = admitted(1);
    let invented = dsm::crypto::blake3::domain_hash_bytes(
        dsm::common::domain_tags::TAG_DSM_TEST_TIP,
        b"a balance no step of this device produced",
    );
    let set = crate::sdk::storage_set::canonical_set(NETWORK).expect("canonical set");
    let profile =
        dsm::economic::register::resolve_root_register_profile(NETWORK).expect("register profile");
    let body = dsm::economic::claim::EconomicRootClaimBody::new(
        genesis,
        devid,
        2,
        invented,
        first_manifest,
        profile.storage_set_id,
        dsm::ccb::genesis::sigalg::SPHINCS_PLUS_SPX256F,
        &crate::sdk::signing_authority::current_public_key().expect("the device's AK"),
        crate::sdk::signing_authority::current_att_a().expect("the device's AttA"),
    )
    .expect("a claim body");
    let claim = dsm::economic::claim_envelope::sign_economic_root_claim(
        &body,
        &crate::sdk::signing_authority::current_secret_key().expect("the device's AK secret"),
    )
    .expect("the device signs its claim");
    let cell = root_cell(&set, NETWORK, &genesis, &devid, 2, &first_root).expect("the cell at 2");
    register_economic_root(&set, &cell, &claim)
        .await
        .expect("the claim is written along its route");
    assert_eq!(
        root_claim_settlement(&set, &cell, &claim)
            .await
            .expect("the cell reads"),
        RootClaimSettlement::Final,
        "the claim holds position 2 along the route from root 1, final"
    );

    crate::sdk::economic_registers::validated_peers().forget();
    crate::sdk::economic_registers::asked_cells::take();
    match verify(genesis, devid, 2).await {
        Err(PeerLineageFailure::Incomplete(why)) => assert!(
            why.contains("position 2"),
            "the claim is not final at the cell routed from its witness's parent: {why}"
        ),
        other => panic!(
            "a claim final only along a route its own witness does not name is never \
             accepted: {other:?}"
        ),
    }
    let asked = crate::sdk::economic_registers::asked_cells::take();
    let key_1 = dsm::economic::register::economic_root_register_key(&genesis, &devid, 1);
    assert_eq!(
        asks(&asked, &key_1),
        0,
        "nothing behind the checked position is read"
    );
}

/// Acceptance costs the same at first contact as at the hundredth transfer
/// (DSM Amendment A14). A pays B three times; B takes each in as a process
/// that remembers nothing. Every acceptance asks for A's register key at
/// A's paying position only, the same number of times, and for none of A's
/// earlier positions, however far A has gone.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn every_acceptance_reads_only_the_senders_paying_position() {
    let p = Pair::boot(100, 0).await;
    let mut per_acceptance = None;
    for round in 1..=3u64 {
        let sent = p.a.send(&p.b, 5).await;
        assert!(sent.success, "{:?}", sent.error_message);
        p.a.enter();
        let (paid_at, _) = client_db::economic_lineage::get_admitted_coordinate()
            .expect("read")
            .expect("A admitted its debit");
        let asked = accept(&p.b).await;
        assert_eq!(p.b.era_balance(), 5 * round);
        let read = positions_asked(&asked, &p.a, paid_at + 1);
        assert_eq!(
            read.iter()
                .map(|(position, _)| *position)
                .collect::<Vec<_>>(),
            vec![paid_at],
            "acceptance {round} read A at its paying position {paid_at} only: {read:?}"
        );
        let cost = read[0].1;
        assert_eq!(
            *per_acceptance.get_or_insert(cost),
            cost,
            "acceptance {round} at position {paid_at} cost what the first one did"
        );
    }
}

/// A credit's source is one step (DSM Amendment A14). C pays A, and A pays
/// B. B accepts A's payment reading only A's paying step, a debit, and
/// nothing of C. Asked for A's credit step itself, a verifier reads that
/// step and its source's one step, C's paying position, and none of C's or
/// A's earlier positions.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_credits_source_is_one_step() {
    let (p, c) = three_devices().await;
    let c_paid_at = c_pays_a(&p, &c, 30).await;
    p.a.enter();
    let (a_credited_at, _) = client_db::economic_lineage::get_admitted_coordinate()
        .expect("read")
        .expect("A admitted its credit");
    let sent = p.a.send(&p.b, 20).await;
    assert!(sent.success, "{:?}", sent.error_message);
    p.a.enter();
    let (a_paid_at, _) = client_db::economic_lineage::get_admitted_coordinate()
        .expect("read")
        .expect("A admitted its debit");

    let asked = accept(&p.b).await;
    assert_eq!(p.b.era_balance(), 20);
    assert_eq!(
        positions_asked(&asked, &p.a, a_paid_at + 1)
            .iter()
            .map(|(position, _)| *position)
            .collect::<Vec<_>>(),
        vec![a_paid_at],
        "B read A at its paying step only"
    );
    assert!(
        positions_asked(&asked, &c, c_paid_at + 1).is_empty(),
        "B read nothing of C: A's paying step is a debit and names no source"
    );

    p.b.enter();
    crate::sdk::economic_registers::validated_peers().forget();
    crate::sdk::economic_registers::asked_cells::take();
    let credit = verify(p.a.genesis, p.a.device_id, a_credited_at)
        .await
        .expect("A's credit step validates one hop, with its source");
    assert_eq!(credit.validated_root().economic_position(), a_credited_at);
    let asked = crate::sdk::economic_registers::asked_cells::take();
    assert_eq!(
        positions_asked(&asked, &p.a, a_paid_at + 1)
            .iter()
            .map(|(position, _)| *position)
            .collect::<Vec<_>>(),
        vec![a_credited_at],
        "A's credit step only"
    );
    assert_eq!(
        positions_asked(&asked, &c, c_paid_at + 1)
            .iter()
            .map(|(position, _)| *position)
            .collect::<Vec<_>>(),
        vec![c_paid_at],
        "C's paying step only, the source of A's credit"
    );
}

/// The request a member logs for a read of the native reserve's successor
/// cell of `parent`.
fn successor_read(parent: &dsm::economic::native_reserve::NativeReserveState) -> String {
    let set = crate::sdk::storage_set::canonical_set(NETWORK).expect("canonical set");
    let members = crate::sdk::storage_set::as_ccb_members(&set).expect("members");
    let cell = dsm::economic::native_reserve::SuccessorCell::of(parent, &members)
        .expect("the successor cell");
    format!(
        "GET /api/v2/cell/{}",
        crate::util::text_id::encode_base32_crockford(cell.routed().key())
    )
}

/// A cell whose value is final holds it for good (storage spec §9, finality
/// 2), so a process reads it from the seats once. The device's claim at its
/// first position and the reserve's first release are final: a second
/// settlement read of the claim, and a second read of the release, ask no
/// member for anything; the answers are the same.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_final_cell_is_read_from_its_seats_once() {
    use crate::sdk::economic_registers::{root_cell, root_claim_settlement, RootClaimSettlement};
    use crate::sdk::native_reserve::{genesis_state, read_successor};
    use dsm::economic::native_reserve::SuccessorRead;
    let d = Device::funded(0xF5).await;
    crate::sdk::final_reads::forget_everything();
    let head = d.core().device_head().expect("head");
    let (genesis, devid) = (head.genesis_digest(), head.devid());
    let set = crate::sdk::storage_set::canonical_set(NETWORK).expect("canonical set");
    let cell = root_cell(
        &set,
        NETWORK,
        &genesis,
        &devid,
        1,
        &dsm::economic::tree::empty_economic_root(),
    )
    .expect("the root cell at 1");
    let (_, claim) = client_db::economic_lineage::get_frozen_root_claim(1)
        .expect("frozen claims")
        .expect("the claim frozen at 1");
    let r0 = genesis_state(NETWORK).expect("R_0");
    let release = |read: &SuccessorRead| match read {
        SuccessorRead::Final { release, child } => (release.envelope_bytes.clone(), *child),
        other => panic!("the reserve's first release is final: {other:?}"),
    };

    for node in &d.nodes.nodes {
        node.forget_requests();
    }
    assert_eq!(
        root_claim_settlement(&set, &cell, &claim)
            .await
            .expect("the cell reads"),
        RootClaimSettlement::Final
    );
    let first = release(&read_successor(&set, &r0).await.expect("the reserve cell"));
    assert!(
        requests(&d.nodes).contains(&successor_read(&r0)),
        "the first reads ask the seats"
    );

    for node in &d.nodes.nodes {
        node.forget_requests();
    }
    assert_eq!(
        root_claim_settlement(&set, &cell, &claim)
            .await
            .expect("the cell reads"),
        RootClaimSettlement::Final
    );
    assert_eq!(
        release(&read_successor(&set, &r0).await.expect("the reserve cell")),
        first
    );
    assert_eq!(
        requests(&d.nodes),
        Vec::<String>::new(),
        "a final cell read again asks no member"
    );
}

/// A faucet claim reads the reserve cell it wins once to learn that it won:
/// the completion proof is built from that reading, and the release is
/// memoised at once, so the claim's own verification of its credit reads
/// neither that cell again nor the head after it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_faucet_claim_reads_the_cell_it_won_once() {
    use crate::sdk::native_reserve::{genesis_state, read_successor};
    use dsm::economic::native_reserve::SuccessorRead;
    let d = Device::start(0xF6).await;
    crate::sdk::final_reads::forget_everything();
    for node in &d.nodes.nodes {
        node.forget_requests();
    }
    assert_eq!(
        crate::economic_fixtures::claim_era(&d.router).await,
        1,
        "the claim is economic position 1"
    );
    let asked = requests(&d.nodes);
    let r0 = genesis_state(NETWORK).expect("R_0");
    let set = crate::sdk::storage_set::canonical_set(NETWORK).expect("canonical set");
    let r1 = match read_successor(&set, &r0).await.expect("the reserve cell") {
        SuccessorRead::Final { child, .. } => child,
        other => panic!("the claim's release is final: {other:?}"),
    };
    // Two readings over the route's seats — the walk that found the cell
    // open, the read that found the release final — and the writer's
    // pre-read at the leader.
    let won = successor_read(&r0);
    let seats = asked.iter().filter(|r| **r == won).count();
    let members = d.nodes.nodes.len();
    assert!(
        seats <= 2 * members + 1,
        "the cell the claim won was asked for {seats} times over {members} seats"
    );
    let past = successor_read(&r1);
    assert!(
        !asked.contains(&past),
        "the claim read the reserve's head past its own release"
    );
    assert_eq!(d.era_balance(), crate::economic_fixtures::whole_era(100));
}

/// An admission publishes its own evidence, whatever older debt the device
/// holds. Eight unrelated frozen objects, older than the claim, fill the
/// sweep's batch; the claim's own evidence is published by its manifest's
/// key before the sweep, so the claim is admitted in the same pass, and the
/// older objects are still published by the sweep.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn an_admission_publishes_its_own_evidence_behind_an_older_backlog() {
    use crate::storage::client_db::frozen_publication_artifact as fpa;
    let d = Device::start(0xF7).await;
    let set = crate::sdk::storage_set::canonical_set(NETWORK).expect("canonical set");
    let namespace = dsm::common::domain_tags::TAG_DSM_ECONOMIC_TRANSITION_WITNESS_OBJ;
    let batch = crate::handlers::artifact_republish::ARTIFACT_REPUBLISH_ROWS_PER_POLL;
    let older: Vec<String> = (0..batch)
        .map(|n| {
            let payload = format!("an older object owed to the set, {n}").into_bytes();
            let key = crate::sdk::economic_registers::immutable_object_key(namespace, &payload);
            let binding = client_db::get_connection().expect("the store");
            let conn = match binding.lock() {
                Ok(conn) => conn,
                Err(poisoned) => poisoned.into_inner(),
            };
            fpa::freeze_artifact_with_conn(&conn, &set.id(), &key, &payload, &[0x0D; 32], "older")
                .expect("frozen");
            key
        })
        .collect();

    let claimed = crate::sdk::faucet_claim_flow::claim_era_faucet(d.core(), NETWORK)
        .await
        .expect("the claim is admitted in the pass that publishes its evidence");
    assert_eq!(claimed.economic_position, 1);
    for key in &older {
        let row = fpa::get_artifact(key).expect("the store").expect("the row");
        assert_eq!(
            row.state,
            fpa::ArtifactState::Stored,
            "{key} is published too"
        );
    }
}

/// A holdings status checks the holder's root at the proven position once for
/// the process, one hop, and reads the next root cell on every poll: the
/// proof is current only while that cell is empty, and only a read made now
/// says so. A pays B and proves its ERA at the position it reached; B checks
/// the proof three times, as the game's account polls a status. A's key at
/// the proven position is asked for on the first poll only and no earlier
/// position of A's ever; the next root cell is read each time. Once A pays
/// C, that cell is taken, and the same proof is no longer current.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_holdings_status_checks_the_root_once_and_reads_the_next_cell_every_time() {
    use crate::sdk::connect::holdings;
    let (p, c) = three_devices().await;
    let sent = p.a.send(&p.b, 10).await;
    assert!(sent.success, "{:?}", sent.error_message);
    p.a.enter();
    let (proven, root) = client_db::economic_lineage::get_admitted_coordinate()
        .expect("read")
        .expect("A admitted its debit");
    let era = crate::policy::builtin_policy_commit("ERA").expect("ERA policy");
    let proof = holdings::prove(&p.a.router().core_sdk, &[era]).expect("A's proof");
    assert_eq!(proof.position, proven);
    let next_cell = cell_read(&p.a.genesis, &p.a.device_id, proven + 1, &root);

    p.b.enter();
    crate::sdk::economic_registers::validated_peers().forget();
    crate::sdk::economic_registers::asked_cells::take();
    let mut fresh = None;
    for poll in 1..=3u64 {
        for node in &p.nodes.nodes {
            node.forget_requests();
        }
        let verified = holdings::verify(&proof, &p.a.genesis, &p.a.device_id, &[era])
            .await
            .expect("A's proof is current");
        assert_eq!(verified.position, proven);
        if let Some(first) = &fresh {
            assert_eq!(
                &verified, first,
                "a later poll proves what the first proved"
            );
        }
        fresh.get_or_insert(verified);
        let asked = crate::sdk::economic_registers::asked_cells::take();
        let read = positions_asked(&asked, &p.a, proven);
        if poll == 1 {
            assert_eq!(
                read.iter()
                    .map(|(position, _)| *position)
                    .collect::<Vec<_>>(),
                vec![proven],
                "poll 1: A's root at the proven position is checked one hop: {read:?}"
            );
        } else {
            assert!(
                read.is_empty(),
                "poll {poll}: the root at the proven position is kept: {read:?}"
            );
        }
        assert!(
            requests(&p.nodes).contains(&next_cell),
            "poll {poll}: the next root cell is read again"
        );
    }

    let sent = p.a.send(&c, 5).await;
    assert!(sent.success, "{:?}", sent.error_message);
    p.b.enter();
    let moved = holdings::verify(&proof, &p.a.genesis, &p.a.device_id, &[era]).await;
    assert!(
        matches!(moved, Err(holdings::Refusal::NotCurrent(..))),
        "the holder moved past the proof: {moved:?}"
    );
}
