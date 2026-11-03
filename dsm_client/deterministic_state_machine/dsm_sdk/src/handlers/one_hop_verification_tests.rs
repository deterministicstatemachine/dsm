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

/// `receiver` takes in what was sent to it: the root cells its resolver was
/// asked for meanwhile, counted by routed key.
async fn accept(receiver: &TestDevice) -> std::collections::HashMap<[u8; 32], usize> {
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

/// A claim whose own witness was built on another root than the one the
/// verifier validated before it is never accepted (DSM Amendment A19, audit
/// finding SA-02). A pays B, then registers, under its own key, a claim at
/// the next position that is its paying debit again: that step's manifest,
/// whose witness was built on A's root before the payment, and the root the
/// payment produced. The claim sits along the cell routed from A's real root
/// at the paying position, is final there, its signature verifies, and its
/// debit is valid from the root its own witness names. Walked from B's
/// frontier for A, B validates the paying step, reads the next claim from the
/// cell routed from the root it validated there, and refuses its step: the
/// witness does not start from that root.
/// MUTATION CONTROL: validating the step from the root its own witness names
/// (A14's parent) turns this red: the debit is validated a second time.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_claim_repeating_the_paying_step_at_the_next_position_is_never_accepted() {
    use crate::sdk::economic_registers::{
        register_economic_root, root_cell, root_claim_settlement, RootClaimSettlement,
    };
    let p = Pair::boot(100, 0).await;
    let sent = p.a.send(&p.b, 10).await;
    assert!(sent.success, "{:?}", sent.error_message);
    let paid_at = admitted_position(&p.a);
    let (paid_root, paid_manifest) = admitted(paid_at);
    let again = paid_at + 1;
    let set = crate::sdk::storage_set::canonical_set(NETWORK).expect("canonical set");
    let profile =
        dsm::economic::register::resolve_root_register_profile(NETWORK).expect("register profile");
    let body = dsm::economic::claim::EconomicRootClaimBody::new(
        p.a.genesis,
        p.a.device_id,
        again,
        paid_root,
        paid_manifest,
        profile.storage_set_id,
        dsm::ccb::genesis::sigalg::SPHINCS_PLUS_SPX256F,
        &crate::sdk::signing_authority::current_public_key().expect("A's AK"),
        crate::sdk::signing_authority::current_att_a().expect("A's AttA"),
    )
    .expect("a claim body");
    let claim = dsm::economic::claim_envelope::sign_economic_root_claim(
        &body,
        &crate::sdk::signing_authority::current_secret_key().expect("A's AK secret"),
    )
    .expect("A signs its claim");
    let cell = root_cell(
        &set,
        NETWORK,
        &p.a.genesis,
        &p.a.device_id,
        again,
        &paid_root,
    )
    .expect("the cell after the paying position");
    register_economic_root(&set, &cell, &claim)
        .await
        .expect("the claim is written along its route");
    assert_eq!(
        root_claim_settlement(&set, &cell, &claim)
            .await
            .expect("the cell reads"),
        RootClaimSettlement::Final,
        "the claim holds the next position along the route from A's paying root, final"
    );

    p.b.enter();
    match verify(p.a.genesis, p.a.device_id, again).await {
        Err(PeerLineageFailure::Invalid(why)) => assert!(
            why.contains(&format!("validation at {again}"))
                && why.contains("the witness does not start from the validated predecessor"),
            "the step at {again} is refused, its witness built on another root: {why}"
        ),
        other => panic!(
            "a claim whose witness names a root the verifier did not validate before it is \
             never accepted: {other:?}"
        ),
    }
}

/// `device`'s positions, among `1..=through`, that were read.
fn read_of(
    asked: &std::collections::HashMap<[u8; 32], usize>,
    device: &TestDevice,
    through: u64,
) -> Vec<u64> {
    positions_asked(asked, device, through)
        .into_iter()
        .map(|(position, _)| position)
        .collect()
}

/// `device`'s admitted position, entered.
fn admitted_position(device: &TestDevice) -> u64 {
    device.enter();
    client_db::economic_lineage::get_admitted_coordinate()
        .expect("read")
        .expect("an admitted position")
        .0
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

/// A contact with a history pays in one step, as any sender does (DSM
/// Amendment A14). C is funded before B adds it; when C then pays B, B's
/// acceptance reads C's paying position and nothing of C before it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_contact_with_a_history_pays_in_one_step_after_the_add() {
    let p = Pair::boot(100, 0).await;
    let mut c = TestDevice::create("C", 0x0C);
    c.boot(&p.fleet).await;
    c.add_contact(&p.b).await;
    c.fund_admitted(100).await;
    p.b.add_contact(&c).await;

    let sent = c.send(&p.b, 10).await;
    assert!(sent.success, "{:?}", sent.error_message);
    let paid_at = admitted_position(&c);
    let asked = accept(&p.b).await;
    assert_eq!(p.b.era_balance(), 10);
    assert_eq!(
        read_of(&asked, &c, paid_at + 1),
        vec![paid_at],
        "B read C at its paying position only"
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
    // open, the read that found the release final — the writer's reads of
    // the leader's log before its put and after it, the second deciding
    // whether another value got there first (MR-STOR-0134, owner ruling 4),
    // and its read of each later seat's log, which bears out the record that
    // seat returned before it is carried (SA-98).
    let won = successor_read(&r0);
    let seats = asked.iter().filter(|r| **r == won).count();
    let members = d.nodes.nodes.len();
    assert!(
        seats <= 2 * members + 2 + (members - 1),
        "the cell the claim won was asked for {seats} times over {members} seats"
    );
    let past = successor_read(&r1);
    assert!(
        !asked.contains(&past),
        "the claim read the reserve's head past its own release"
    );
    assert_eq!(d.era_balance(), crate::economic_fixtures::whole_era(100));
}

/// SA-134. An admission publishes its own evidence and waits on nothing
/// else the device owes the set. Eight unrelated frozen objects older than
/// the claim fill the sweep's batch, and one more is frozen for a storage set
/// no catalog names, so nothing can ever publish it; the claim's own evidence
/// is published by its manifest's key and the claim is admitted in the same
/// pass, beside the object no set takes.
/// MUTATION CONTROL: holding the admission until the device's whole table is
/// `Stored`, as the finish did, leaves the claim held by the object no set
/// takes and turns this red.
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
    let stuck = {
        let payload = b"an object owed to a set no catalog names".to_vec();
        let key = crate::sdk::economic_registers::immutable_object_key(namespace, &payload);
        let binding = client_db::get_connection().expect("the store");
        let conn = match binding.lock() {
            Ok(conn) => conn,
            Err(poisoned) => poisoned.into_inner(),
        };
        fpa::freeze_artifact_with_conn(&conn, &[0xEE; 32], &key, &payload, &[0x0E; 32], "stuck")
            .expect("frozen");
        key
    };

    let claimed = crate::sdk::faucet_claim_flow::claim_era_faucet(d.core(), NETWORK)
        .await
        .expect("the claim is admitted in the pass that publishes its evidence");
    assert_eq!(claimed.economic_position, 1);
    assert_eq!(
        u32::try_from(older.len()).expect("a batch of rows"),
        batch,
        "the older objects fill the sweep's batch"
    );
    let row = fpa::get_artifact(&stuck)
        .expect("the store")
        .expect("the row");
    assert_ne!(
        row.state,
        fpa::ArtifactState::Stored,
        "no set takes the object, and the claim was admitted beside it"
    );
}

/// A holdings status checks the holder's root at the proven position one hop,
/// and reads the next root cell on every poll: the proof is current only while
/// that cell is empty, and only a read made now says so (SA-92). A pays B and
/// proves its ERA at the position it reached; B checks the proof three times,
/// as the game's account polls a status. Each poll asks for A at the proven
/// position only, and for no earlier position of A's. The next root cell is
/// read each time. Once A pays C, that cell is taken, and the same proof is no
/// longer current.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_holdings_status_checks_the_root_one_hop_and_reads_the_next_cell_every_time() {
    use crate::sdk::connect::holdings;
    let (p, c) = three_devices().await;
    let sent = p.a.send(&p.b, 10).await;
    assert!(sent.success, "{:?}", sent.error_message);
    accept(&p.b).await;
    p.a.enter();
    let (proven, root) = client_db::economic_lineage::get_admitted_coordinate()
        .expect("read")
        .expect("A admitted its debit");
    let era = dsm::core::token::builtin_policy_commit_for_token("ERA").expect("ERA policy");
    let proof = holdings::prove(&p.a.router().core_sdk, &[era]).expect("A's proof");
    assert_eq!(proof.position, proven);
    let next_cell = cell_read(&p.a.genesis, &p.a.device_id, proven + 1, &root);

    p.b.enter();
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
        assert_eq!(
            read_of(&asked, &p.a, proven),
            vec![proven],
            "poll {poll}: A's root at the proven position is checked one hop"
        );
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

/// A claim off the validated chain changes nothing (DSM Amendment A19;
/// SA-92). B validates A's paying step. A then registers a second claim at
/// that position, final along the cell routed from a root two positions back,
/// a root B never validated at the position before. B reads a position only
/// at the cell routed from the root it validated before it, so that claim is
/// not on its chain: asked again, as a verifier asking for the first time
/// would be, B validates the same step to the same root.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_claim_off_the_validated_chain_changes_nothing() {
    use crate::sdk::economic_registers::{
        register_economic_root, root_cell, root_claim_settlement, RootClaimSettlement,
    };
    let p = Pair::boot(100, 0).await;
    let sent = p.a.send(&p.b, 10).await;
    assert!(sent.success, "{:?}", sent.error_message);
    p.a.enter();
    let (paid_at, _) = client_db::economic_lineage::get_admitted_coordinate()
        .expect("read")
        .expect("A admitted its debit");
    assert!(paid_at >= 2, "A's paying step follows its funding");

    p.b.enter();
    let before = verify(p.a.genesis, p.a.device_id, paid_at)
        .await
        .expect("A's paying step is valid");

    // A's second claim at its paying position names the manifest of its step
    // before, whose witness was built on the root two positions back, and is
    // final along the cell routed from that root.
    p.a.enter();
    let (_, earlier_manifest) = admitted(paid_at - 1);
    let two_back = match paid_at - 2 {
        0 => dsm::economic::tree::empty_economic_root(),
        at => admitted(at).0,
    };
    let invented = dsm::crypto::blake3::domain_hash_bytes(
        dsm::common::domain_tags::TAG_DSM_TEST_TIP,
        b"a second claim at the paying position",
    );
    let set = crate::sdk::storage_set::canonical_set(NETWORK).expect("canonical set");
    let profile =
        dsm::economic::register::resolve_root_register_profile(NETWORK).expect("register profile");
    let body = dsm::economic::claim::EconomicRootClaimBody::new(
        p.a.genesis,
        p.a.device_id,
        paid_at,
        invented,
        earlier_manifest,
        profile.storage_set_id,
        dsm::ccb::genesis::sigalg::SPHINCS_PLUS_SPX256F,
        &crate::sdk::signing_authority::current_public_key().expect("A's AK"),
        crate::sdk::signing_authority::current_att_a().expect("A's AttA"),
    )
    .expect("a claim body");
    let claim = dsm::economic::claim_envelope::sign_economic_root_claim(
        &body,
        &crate::sdk::signing_authority::current_secret_key().expect("A's AK secret"),
    )
    .expect("A signs it");
    let cell = root_cell(
        &set,
        NETWORK,
        &p.a.genesis,
        &p.a.device_id,
        paid_at,
        &two_back,
    )
    .expect("the cell routed from the root two back");
    register_economic_root(&set, &cell, &claim)
        .await
        .expect("the claim is written along its route");
    assert_eq!(
        root_claim_settlement(&set, &cell, &claim)
            .await
            .expect("the cell reads"),
        RootClaimSettlement::Final
    );

    p.b.enter();
    let after = verify(p.a.genesis, p.a.device_id, paid_at)
        .await
        .expect("a claim off the validated chain changes nothing");
    assert_eq!(after.validated_root(), before.validated_root());
}

/// A read checks the step it asks about and nothing else (DSM Amendment A14).
/// A pays C twice, and B, which accepts nothing from A, validates A's first
/// paying step, as a SetupValid read or a holdings check reads a trader's root,
/// and then A's second. Each read asks for A at that position alone.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_read_checks_only_the_step_it_asks_about() {
    let (p, c) = three_devices().await;
    let sent = p.a.send(&c, 5).await;
    assert!(sent.success, "{:?}", sent.error_message);
    let paid_at = admitted_position(&p.a);

    p.b.enter();
    crate::sdk::economic_registers::asked_cells::take();
    verify(p.a.genesis, p.a.device_id, paid_at)
        .await
        .expect("A's paying step is valid");
    let first = read_of(
        &crate::sdk::economic_registers::asked_cells::take(),
        &p.a,
        paid_at,
    );
    assert_eq!(first, vec![paid_at], "the read validates that step alone");

    // C takes in A's first payment, which A's relationship with C waits for
    // before it sends again.
    accept(&c).await;
    let sent = p.a.send(&c, 5).await;
    assert!(sent.success, "{:?}", sent.error_message);
    let paid_again = admitted_position(&p.a);
    p.b.enter();
    // A's own send logged the reads of its claim; only B's read counts.
    crate::sdk::economic_registers::asked_cells::take();
    verify(p.a.genesis, p.a.device_id, paid_again)
        .await
        .expect("A's second paying step is valid");
    let again = read_of(
        &crate::sdk::economic_registers::asked_cells::take(),
        &p.a,
        paid_again,
    );
    assert_eq!(
        again,
        vec![paid_again],
        "the second read validates A's new step alone"
    );
}

/// A payment that follows the payer's transactions in another relationship is
/// accepted (plan R05). A pays C, C takes it in, then A pays B. A's step for C
/// lies behind A's paying position: B reads only the paying step, and the
/// transactions of a relationship B is not a party to are no reason to refuse.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_payment_after_the_payers_dealings_with_others_is_accepted() {
    let (p, c) = three_devices().await;
    let sent = p.a.send(&c, 20).await;
    assert!(sent.success, "{:?}", sent.error_message);
    let with_c_at = admitted_position(&p.a);
    accept(&c).await;
    let sent = p.a.send(&p.b, 10).await;
    assert!(sent.success, "{:?}", sent.error_message);
    let paid_at = admitted_position(&p.a);
    assert!(
        with_c_at < paid_at,
        "A's step for C precedes its payment to B"
    );

    let asked = accept(&p.b).await;
    assert_eq!(p.b.era_balance(), 10, "B takes the payment in");
    let read = read_of(&asked, &p.a, paid_at + 1);
    assert_eq!(read, vec![paid_at], "B read A's payment to B alone");
}

/// The same payment is accepted, with the same committed effect, whichever
/// receiver takes it (plan R06). D adds A after A's funding; B added A before.
/// A pays D, then pays B the same amount. Both accept, both admit their credit
/// as their first position, and each reads A at the paying step alone.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn the_same_payment_costs_every_receiver_one_step() {
    let p = Pair::boot(100, 0).await;
    let mut d = TestDevice::create("D", 0x0D);
    d.boot(&p.fleet).await;
    d.add_contact(&p.a).await;
    p.a.add_contact(&d).await;

    let sent = p.a.send(&d, 10).await;
    assert!(sent.success, "{:?}", sent.error_message);
    let to_d_at = admitted_position(&p.a);
    let asked = accept(&d).await;
    let d_read = read_of(&asked, &p.a, to_d_at + 1);

    let sent = p.a.send(&p.b, 10).await;
    assert!(sent.success, "{:?}", sent.error_message);
    let to_b_at = admitted_position(&p.a);
    let asked = accept(&p.b).await;
    let b_read = read_of(&asked, &p.a, to_b_at + 1);

    assert_eq!(d.era_balance(), 10);
    assert_eq!(p.b.era_balance(), 10);
    assert_eq!(
        admitted_position(&d),
        admitted_position(&p.b),
        "both admit the credit as the same position of their own"
    );
    assert_eq!(d_read, vec![to_d_at], "D validates A's step to D alone");
    assert_eq!(b_read, vec![to_b_at], "B validates A's step to B alone");
}

/// What an acceptance costs, whatever the payer's history (DSM Amendment A14,
/// plan Phase 5, current verifier only). A pays C `n` times, C taking each in,
/// then pays B, which holds nothing of A. B's first acceptance validates A's
/// paying position alone, the next payment costs one position, and so does a
/// second look at a position already accepted. `n` is `DSM_HISTORY_N`, six by
/// default; the numbers print for the record.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn acceptance_cost_is_one_position_whatever_the_history() {
    let unseen: u64 = match std::env::var("DSM_HISTORY_N") {
        Ok(count) => count.parse().expect("DSM_HISTORY_N is a count"),
        Err(std::env::VarError::NotPresent) => 6,
        Err(e) => panic!("DSM_HISTORY_N is not readable: {e}"),
    };
    // Funding comes in multiples of the faucet payout.
    let p = Pair::boot((unseen + 20).div_ceil(100) * 100, 0).await;
    let mut c = TestDevice::create("C", 0x0C);
    c.boot(&p.fleet).await;
    c.add_contact(&p.a).await;
    p.a.add_contact(&c).await;
    for _ in 0..unseen {
        let sent = p.a.send(&c, 1).await;
        assert!(sent.success, "{:?}", sent.error_message);
        accept(&c).await;
    }
    let sent = p.a.send(&p.b, 1).await;
    assert!(sent.success, "{:?}", sent.error_message);
    let paid_at = admitted_position(&p.a);

    let started = std::time::Instant::now();
    let asked = accept(&p.b).await;
    let cold_ms = started.elapsed().as_millis();
    let cold_reads: usize = asked.values().sum();
    let cold = read_of(&asked, &p.a, paid_at + 1);
    assert_eq!(p.b.era_balance(), 1);
    assert_eq!(
        cold,
        vec![paid_at],
        "B, holding nothing of A, validates A's paying position alone"
    );

    let sent = p.a.send(&p.b, 1).await;
    assert!(sent.success, "{:?}", sent.error_message);
    let paid_again = admitted_position(&p.a);
    let started = std::time::Instant::now();
    let asked = accept(&p.b).await;
    let warm_ms = started.elapsed().as_millis();
    let warm_reads: usize = asked.values().sum();
    assert_eq!(p.b.era_balance(), 2);
    assert_eq!(
        read_of(&asked, &p.a, paid_again + 1),
        vec![paid_again],
        "the next payment costs one position"
    );

    crate::sdk::economic_registers::asked_cells::take();
    p.b.enter();
    let started = std::time::Instant::now();
    verify(p.a.genesis, p.a.device_id, paid_again)
        .await
        .expect("an accepted position verifies again");
    let again_ms = started.elapsed().as_millis();
    let again = crate::sdk::economic_registers::asked_cells::take();
    let again_reads: usize = again.values().sum();
    assert_eq!(
        read_of(&again, &p.a, paid_again + 1),
        vec![paid_again],
        "a second look at an accepted position costs one position"
    );
    println!(
        "[history] unseen={unseen} cold: positions={} reads={cold_reads} ms={cold_ms} | warm: \
         positions=1 reads={warm_reads} ms={warm_ms} | repeated: positions=1 reads={again_reads} \
         ms={again_ms}",
        cold.len()
    );
}
