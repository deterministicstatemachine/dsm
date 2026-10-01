// SPDX-License-Identifier: Apache-2.0

//! Frontier-relative verification (DSM Amendment A8, owner ruling
//! 2026-09-30) on the storage nodes. A verifier starts at its own frontier
//! for a peer, validates every step from there from that step's own
//! evidence, checks a credit's source one hop back and no further, and reads
//! nothing behind its frontier.

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

/// A credit's source is validated one hop back and no further. C pays A,
/// and A pays B; B meets both first. B validates A's credit step, and for
/// its source validates C's paying step from its own evidence, over C's
/// root chain from C's activation root: C's claim at 1 is read and
/// authenticated by its manifest, and none of the evidence behind C's step
/// at 1 is read.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_credits_source_is_validated_one_hop_back_and_no_further() {
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
    let behind_the_hop = [
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
    for read in &behind_the_hop {
        assert!(
            !asked.contains(read),
            "B read the evidence behind the one-hop source: {read}"
        );
    }
}
