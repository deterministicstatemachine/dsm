// SPDX-License-Identifier: Apache-2.0

//! Frontier-relative verification (DSM Amendment A8, owner rulings
//! 2026-09-30 and 2026-10-01) on the storage nodes. A verifier starts at its
//! own frontier for a peer, validates every step from there from that step's
//! own evidence, validates a credit's source through the source's own
//! segment back to a frontier it holds for the source, records the
//! frontiers it reached with the acceptance, and reads nothing behind a
//! frontier.

use serial_test::serial;

use crate::economic_fixtures::NETWORK;
use crate::storage::client_db;
use crate::test_support::one_device::Device;
use crate::test_support::two_device::{Pair, TestDevice};
use dsm::economic::claim_envelope::RegisteredEconomicClaim;
use dsm::economic::provenance::{PeerLineageFailure, ValidatedPeerTransition};

/// `peer`'s lineage at `position`, verified by the entered device from its
/// frontier for the peer, as its provenance checks verify it.
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

/// The request a member logs for a read of the immutable object `inner`
/// under `namespace`.
fn object_read(
    namespace: dsm::crypto::domain::TaggedHashDomain<'static>,
    inner: &[u8; 32],
) -> String {
    format!(
        "GET /api/v2/immutable/{}",
        crate::util::text_id::encode_base32_crockford(
            &dsm::storage_object::immutable_addr_from_inner(namespace, inner)
        )
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

/// An authenticated root is not a valid transition. A device registers,
/// under its own key, a claim at position 2 that names its first step's
/// manifest and a root no step of its produced. The claim is final at its
/// cell and its signature verifies. A verifier meeting the device first
/// validates every step from the activation root, refuses the lineage at
/// position 2, where the transition does not produce the root, and reads
/// nothing past it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_root_no_transition_explains_is_refused_where_it_sits() {
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
        "the claim holds position 2, final"
    );

    for node in &d.nodes.nodes {
        node.forget_requests();
    }
    let refused = verify(genesis, devid, 3).await;
    assert!(
        matches!(&refused, Err(PeerLineageFailure::Invalid(m)) if m.starts_with("validation at 2:")),
        "the lineage is refused at the step whose transition does not produce its root: {refused:?}"
    );
    let past = cell_read(&genesis, &devid, 3, &invented);
    assert!(
        !requests(&d.nodes).contains(&past),
        "nothing past the refused position is read"
    );
}

/// A receiver reads nothing of a peer behind its frontier. B accepts A's
/// transfer, and A's coordinate that acceptance verified becomes B's
/// frontier for A. When A pays again, B verifies from there: it reads A's
/// cell past the frontier and none of A's cells at or behind it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_receiver_reads_nothing_behind_its_frontier() {
    let p = Pair::boot(100, 0).await;
    let sent = p.a.send(&p.b, 10).await;
    assert!(sent.success, "{:?}", sent.error_message);
    let first = p.b.sync().await;
    assert!(first.success, "{:?}", first.errors);
    assert_eq!(p.b.era_balance(), 10);

    p.a.enter();
    let (paid_at, _) = client_db::economic_lineage::get_admitted_coordinate()
        .expect("read")
        .expect("A admitted its debit");
    let mut parent = dsm::economic::tree::empty_economic_root();
    let mut behind = Vec::new();
    for position in 1..=paid_at {
        behind.push(cell_read(&p.a.genesis, &p.a.device_id, position, &parent));
        parent = admitted(position).0;
    }
    let past = cell_read(&p.a.genesis, &p.a.device_id, paid_at + 1, &parent);
    p.b.enter();
    let frontier =
        client_db::economic_lineage::frontier_below(&p.a.genesis, &p.a.device_id, paid_at + 1)
            .expect("the frontier store")
            .expect("B's frontier for A");
    assert_eq!(
        frontier.economic_position(),
        paid_at,
        "B's frontier for A is the coordinate its acceptance verified"
    );

    let again = p.a.send(&p.b, 5).await;
    assert!(again.success, "{:?}", again.error_message);
    for node in &p.nodes.nodes {
        node.forget_requests();
    }
    let second = p.b.sync().await;
    assert!(second.success, "{:?}", second.errors);
    assert_eq!(p.b.era_balance(), 15);
    let asked = requests(&p.nodes);
    for read in &behind {
        assert!(
            !asked.contains(read),
            "B read A's cell behind its frontier: {read}"
        );
    }
    assert!(asked.contains(&past), "B read A's cell past its frontier");
}

/// A credit's source is held to account through its own segment (DSM
/// Amendment A8 as corrected for sources, owner 2026-10-01). C pays A, and A
/// pays B; B meets both first. B validates A's credit step and, for its
/// source, C's whole segment from C's activation root: C's step at 1 is
/// validated from its own evidence, its witness and successor evidence read,
/// before C's paying step at 2. A root C only registered would prove nothing
/// about where its value came from.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_credits_source_is_validated_through_its_own_segment() {
    use dsm::common::domain_tags::{
        TAG_DSM_ECONOMIC_ADMISSION_MANIFEST, TAG_DSM_ECONOMIC_SUCCESSOR_EVIDENCE,
        TAG_DSM_ECONOMIC_TRANSITION_WITNESS_OBJ,
    };
    let p = Pair::boot(100, 0).await;
    let mut c = TestDevice::create("C", 0x0C);
    c.boot(&p.fleet).await;
    c.add_contact(&p.a).await;
    p.a.add_contact(&c).await;
    c.fund_admitted(100).await;
    let paid = c.send(&p.a, 30).await;
    assert!(paid.success, "{:?}", paid.error_message);
    let credited = p.a.sync().await;
    assert!(credited.success, "{:?}", credited.errors);
    assert_eq!(
        p.a.era_balance(),
        crate::economic_fixtures::whole_era(100) + 30
    );
    let sent = p.a.send(&p.b, 20).await;
    assert!(sent.success, "{:?}", sent.error_message);

    c.enter();
    let (_, first_manifest) = admitted(1);
    let set = crate::sdk::storage_set::canonical_set(NETWORK).expect("canonical set");
    let manifest = dsm::economic::decode::decode_admission_manifest(
        &crate::sdk::storage_io::fetch_immutable(
            &set,
            TAG_DSM_ECONOMIC_ADMISSION_MANIFEST,
            &first_manifest,
        )
        .await
        .expect("the fetch")
        .expect("C's first manifest is held"),
    )
    .expect("the manifest decodes");
    let dsm::economic::claim::AdmissionSubstrate::DsmSuccessor { evidence_addr } =
        manifest.substrate
    else {
        panic!("C's faucet claim rides a DSM successor");
    };
    let the_sources_first_step = [
        object_read(
            TAG_DSM_ECONOMIC_TRANSITION_WITNESS_OBJ,
            &manifest.transition_witness_addr,
        ),
        object_read(TAG_DSM_ECONOMIC_SUCCESSOR_EVIDENCE, &evidence_addr),
    ];
    let chained = cell_read(
        &c.genesis,
        &c.device_id,
        1,
        &dsm::economic::tree::empty_economic_root(),
    );
    let authenticated = object_read(TAG_DSM_ECONOMIC_ADMISSION_MANIFEST, &first_manifest);

    for node in &p.nodes.nodes {
        node.forget_requests();
    }
    let received = p.b.sync().await;
    assert!(received.success, "{:?}", received.errors);
    assert_eq!(p.b.era_balance(), 20);
    let asked = requests(&p.nodes);
    assert!(asked.contains(&chained), "B read C's root chain");
    assert!(
        asked.contains(&authenticated),
        "B authenticated C's claim at 1 by its manifest"
    );
    for read in &the_sources_first_step {
        assert!(
            asked.contains(read),
            "B did not validate the source's step at 1 from its evidence: {read}"
        );
    }
}

/// A source's segment stops at the frontier the receiver already holds for
/// it (owner 2026-10-01: "validate that source identity's economic segment
/// backward until reaching a frontier that this verifier has already fully
/// validated"). C pays B first, so B holds a frontier for C at C's paying
/// step. Then C pays A, and A pays B. Validating A's credit, B walks C from
/// that frontier: it reads C's cell past it, and none of C's cells at or
/// behind it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_sources_segment_stops_at_the_frontier_the_receiver_holds() {
    let p = Pair::boot(100, 0).await;
    let mut c = TestDevice::create("C", 0x0C);
    c.boot(&p.fleet).await;
    for peer in [&p.a, &p.b] {
        c.add_contact(peer).await;
        peer.add_contact(&c).await;
    }
    c.fund_admitted(100).await;
    let to_b = c.send(&p.b, 7).await;
    assert!(to_b.success, "{:?}", to_b.error_message);
    let first = p.b.sync().await;
    assert!(first.success, "{:?}", first.errors);
    assert_eq!(p.b.era_balance(), 7);

    c.enter();
    let (paid_b_at, _) = client_db::economic_lineage::get_admitted_coordinate()
        .expect("read")
        .expect("C admitted its debit to B");
    p.b.enter();
    let frontier =
        client_db::economic_lineage::frontier_below(&c.genesis, &c.device_id, paid_b_at + 1)
            .expect("the frontier store")
            .expect("B's frontier for C");
    assert_eq!(frontier.economic_position(), paid_b_at);

    let to_a = c.send(&p.a, 30).await;
    assert!(to_a.success, "{:?}", to_a.error_message);
    let credited = p.a.sync().await;
    assert!(credited.success, "{:?}", credited.errors);
    let sent = p.a.send(&p.b, 20).await;
    assert!(sent.success, "{:?}", sent.error_message);

    c.enter();
    let mut parent = dsm::economic::tree::empty_economic_root();
    let mut behind = Vec::new();
    for position in 1..=paid_b_at {
        behind.push(cell_read(&c.genesis, &c.device_id, position, &parent));
        parent = admitted(position).0;
    }
    let past = cell_read(&c.genesis, &c.device_id, paid_b_at + 1, &parent);
    for node in &p.nodes.nodes {
        node.forget_requests();
    }
    let received = p.b.sync().await;
    assert!(received.success, "{:?}", received.errors);
    assert_eq!(p.b.era_balance(), 27);
    let asked = requests(&p.nodes);
    assert!(
        asked.contains(&past),
        "B read C's paying step to A, past its frontier"
    );
    for read in &behind {
        assert!(
            !asked.contains(read),
            "B read C's cell behind the frontier it holds for C: {read}"
        );
    }
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

/// The reads of C's root cells at positions `1..=through`, in C's own
/// order, as the members log them.
fn cs_cells_through(c: &TestDevice, through: u64) -> Vec<String> {
    c.enter();
    let mut parent = dsm::economic::tree::empty_economic_root();
    let mut reads = Vec::new();
    for position in 1..=through {
        reads.push(cell_read(&c.genesis, &c.device_id, position, &parent));
        parent = admitted(position).0;
    }
    reads
}

/// A source's frontier is cached with the acceptance (owner 2026-10-01:
/// "Cache/update validated frontiers so subsequent interactions validate
/// only the new suffix"). C has never paid B. C pays A and A pays B: B
/// validates C's segment to the paying step and records its frontier for C
/// there with the acceptance. C pays A again and A pays B again: B walks C
/// from that frontier, reading C's cells past it and none at or behind it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_sources_frontier_is_recorded_and_the_next_credit_walks_only_its_suffix() {
    let (p, c) = three_devices().await;
    let first_source = c_pays_a(&p, &c, 30).await;
    let sent = p.a.send(&p.b, 20).await;
    assert!(sent.success, "{:?}", sent.error_message);
    let received = p.b.sync().await;
    assert!(received.success, "{:?}", received.errors);
    assert_eq!(p.b.era_balance(), 20);
    p.b.enter();
    let frontier =
        client_db::economic_lineage::frontier_below(&c.genesis, &c.device_id, first_source + 1)
            .expect("the frontier store")
            .expect("B's frontier for C, recorded from the source's segment alone");
    assert_eq!(
        frontier.economic_position(),
        first_source,
        "B's frontier for C is the source step its acceptance validated"
    );

    let second_source = c_pays_a(&p, &c, 10).await;
    let again = p.a.send(&p.b, 5).await;
    assert!(again.success, "{:?}", again.error_message);
    let behind = cs_cells_through(&c, first_source);
    let past = cs_cells_through(&c, second_source)
        .pop()
        .expect("C's cell at its second paying step");
    for node in &p.nodes.nodes {
        node.forget_requests();
    }
    let received = p.b.sync().await;
    assert!(received.success, "{:?}", received.errors);
    assert_eq!(p.b.era_balance(), 25);
    let asked = requests(&p.nodes);
    assert!(
        asked.contains(&past),
        "B read C's second paying step, past its frontier"
    );
    for read in &behind {
        assert!(
            !asked.contains(read),
            "B read C's cell at or behind the frontier its first acceptance recorded: {read}"
        );
    }
}

/// One walk validates a source's segment once. C pays A twice, and A pays
/// B out of both: validating A's segment, B walks C to the first paying
/// step, and the walk to the second starts there. Every member is asked for
/// each of C's cells at or behind the first paying step exactly as often as
/// for C's second paying step, which any walk reads once: never once more
/// for the second source.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn one_walk_validates_a_sources_segment_once() {
    let (p, c) = three_devices().await;
    let first_source = c_pays_a(&p, &c, 30).await;
    let second_source = c_pays_a(&p, &c, 10).await;
    assert!(second_source > first_source);
    let sent = p.a.send(&p.b, 35).await;
    assert!(sent.success, "{:?}", sent.error_message);
    let behind = cs_cells_through(&c, first_source);
    let second = cs_cells_through(&c, second_source)
        .pop()
        .expect("C's cell at its second paying step");
    for node in &p.nodes.nodes {
        node.forget_requests();
    }
    let received = p.b.sync().await;
    assert!(received.success, "{:?}", received.errors);
    assert_eq!(p.b.era_balance(), 35);
    let per_member = |read: &String| -> Vec<usize> {
        p.nodes
            .nodes
            .iter()
            .map(|n| n.requests().iter().filter(|r| *r == read).count())
            .collect()
    };
    let once = per_member(&second);
    assert!(
        once.iter().any(|n| *n > 0),
        "B validated C's second paying step"
    );
    for read in &behind {
        assert_eq!(
            per_member(read),
            once,
            "B walked C's segment through {read} more often than C's second paying step"
        );
    }
}

/// A position once validated is validated: its lineage is fixed by the steps
/// that committed to it. A pays B; a verifier asked again for A's lineage at
/// the same position answers from what this process already validated, with
/// the same validated root and no second walk (a walk re-verifies every
/// step's signatures, from the activation root for a peer met only by
/// verification). Once that memory is gone, the next question walks again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_validated_position_is_not_walked_again_by_the_same_process() {
    let p = Pair::boot(100, 0).await;
    let sent = p.a.send(&p.b, 10).await;
    assert!(sent.success, "{:?}", sent.error_message);
    p.a.enter();
    let (paid_at, _) = client_db::economic_lineage::get_admitted_coordinate()
        .expect("read")
        .expect("A admitted its debit");
    let validated_root = |v: &ValidatedPeerTransition| v.validated_root().economic_root();
    let peers = crate::sdk::economic_registers::validated_peers();
    p.b.enter();
    peers.forget();
    let before = peers.walks();
    let first = verify(p.a.genesis, p.a.device_id, paid_at).await.expect("A's lineage validates");
    assert_eq!(peers.walks(), before + 1, "the first question walks");

    let again = verify(p.a.genesis, p.a.device_id, paid_at).await.expect("validated again");
    assert_eq!(validated_root(&again), validated_root(&first));
    assert_eq!(peers.walks(), before + 1, "a validated position is not walked again");

    peers.forget();
    let walked = verify(p.a.genesis, p.a.device_id, paid_at).await.expect("walked again");
    assert_eq!(validated_root(&walked), validated_root(&first));
    assert_eq!(peers.walks(), before + 2, "with nothing remembered, the question walks");
}

/// A walk starts where this process already validated the peer. A pays B and
/// then C, and neither takes the payment in, so no device here recorded a
/// frontier for A. B validates A at the first payment; the walk to the
/// second starts there, not at A's activation root, and validates the same
/// root a walk from the activation root does.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_walk_starts_at_the_position_the_process_validated_below_it() {
    use dsm::economic::peer_lineage::PeerFrontiers;
    let (p, c) = three_devices().await;
    let paid = |p: &Pair| {
        p.a.enter();
        client_db::economic_lineage::get_admitted_coordinate()
            .expect("read")
            .expect("A admitted its debit")
            .0
    };
    let sent = p.a.send(&p.b, 10).await;
    assert!(sent.success, "{:?}", sent.error_message);
    let first = paid(&p);
    let sent = p.a.send(&c, 5).await;
    assert!(sent.success, "{:?}", sent.error_message);
    let second = paid(&p);
    assert!(second > first);
    p.b.enter();
    let peers = crate::sdk::economic_registers::validated_peers();
    peers.forget();
    let start = || {
        crate::sdk::economic_registers::RememberedFrontiers { network: NETWORK }
            .frontier_below(&p.a.genesis, &p.a.device_id, second)
            .expect("the frontiers")
            .map(|f| f.economic_position())
    };
    assert_eq!(start(), None, "B holds no frontier for A: a walk starts at its activation root");
    verify(p.a.genesis, p.a.device_id, first)
        .await
        .expect("A's lineage validates at its first payment");
    assert_eq!(start(), Some(first), "the walk to the second payment starts at the first");
    let from_memory = verify(p.a.genesis, p.a.device_id, second)
        .await
        .expect("A's lineage validates at its second payment");

    peers.forget();
    let from_activation = verify(p.a.genesis, p.a.device_id, second)
        .await
        .expect("A's lineage validates from its activation root");
    assert_eq!(
        from_memory.validated_root().economic_root(),
        from_activation.validated_root().economic_root(),
        "the walk from what the process validated reaches the same root"
    );
}

/// A device's own lineage is never walked: its admitted history is its
/// frontier for itself. A pays B and then C; from A, the frontier for A below
/// its second payment is its first, and A's lineage validates there to the
/// root A admitted. From B, which accepted nothing of A's, there is none.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_devices_own_lineage_starts_at_its_own_admitted_history() {
    use dsm::economic::peer_lineage::PeerFrontiers;
    let (p, c) = three_devices().await;
    let paid = |p: &Pair| {
        p.a.enter();
        client_db::economic_lineage::get_admitted_coordinate()
            .expect("read")
            .expect("A admitted its debit")
    };
    let sent = p.a.send(&p.b, 10).await;
    assert!(sent.success, "{:?}", sent.error_message);
    let (first, _) = paid(&p);
    let sent = p.a.send(&c, 5).await;
    assert!(sent.success, "{:?}", sent.error_message);
    let (second, second_root) = paid(&p);
    assert!(second > first);
    crate::sdk::economic_registers::validated_peers().forget();
    let start = || {
        crate::sdk::economic_registers::StoredFrontiers
            .frontier_below(&p.a.genesis, &p.a.device_id, second)
            .expect("the frontiers")
            .map(|f| f.economic_position())
    };
    p.a.enter();
    assert_eq!(start(), Some(first), "A's own lineage starts at its own first payment");
    let own = verify(p.a.genesis, p.a.device_id, second)
        .await
        .expect("A's own lineage validates");
    assert_eq!(own.validated_root().economic_root(), second_root);
    p.b.enter();
    assert_eq!(start(), None, "B holds no frontier for A");
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
        SuccessorRead::Final { release, child } => (release.envelope_bytes.clone(), child.clone()),
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
