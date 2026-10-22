// SPDX-License-Identifier: Apache-2.0

//! Counterfeit value offered to a receiver that has never seen the payer.
//!
//! A payer runs software it compiled itself. It can build a step the rules do
//! not allow, sign it with its real key, publish its evidence and register its
//! claim, and the storage nodes take it: they store, they do not validate. What
//! stops the value is the receiver's own walk (DSM Amendment A19, restoring
//! A8): every step it has not validated, each from the root validated before
//! it, and every credit's source through the source's own segment to a real
//! online debit. These tests build each counterfeit with the producer's own
//! builders, as modified software would, publish it to the network's storage
//! nodes, and ask a device that holds nothing of the payer.

use serial_test::serial;

use crate::economic_fixtures::NETWORK;
use crate::sdk::economic_admission_flow::{
    authority_material, build_dsm_admission, producer_tree_and_pre_state,
    validated_root_or_activate, AdmittedPreState, DsmAdmissionParts,
};
use crate::storage::client_db;
use crate::test_support::two_device::{Pair, TestDevice};
use dsm::common::domain_tags::{
    TAG_DSM_ECONOMIC_ADMISSION_MANIFEST, TAG_DSM_ECONOMIC_AUTHORITY_EVIDENCE,
    TAG_DSM_ECONOMIC_SUCCESSOR_EVIDENCE, TAG_DSM_ECONOMIC_TRANSITION_WITNESS_OBJ,
    TAG_DSM_PEER_TRANSFER_ACCEPTANCE,
};
use dsm::economic::provenance::{PeerLineageFailure, ValidatedPeerTransition};
use dsm::economic::write_set::CreditSourceFacts;
use dsm::types::device_state::RelationshipChainState;
use dsm::types::operations::Operation;

/// `payer`'s step at `position`, as the entered device's provenance checks
/// validate it from its own frontier for the payer.
async fn verify(
    payer: &TestDevice,
    position: u64,
) -> Result<ValidatedPeerTransition, PeerLineageFailure> {
    let (genesis, devid) = (payer.genesis, payer.device_id);
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

/// ERA base units in one faucet payout.
fn payout() -> u64 {
    dsm::economic::native_reserve::ERA_FAUCET_PAYOUT
}

/// `from`'s online transfer of `amount` ERA to `to`, signed with `from`'s
/// real key as its send signs one.
fn signed_transfer(from: &TestDevice, to: &TestDevice, amount: u64) -> Operation {
    from.enter();
    let contact = client_db::get_contact_by_device_id(&to.device_id)
        .expect("contacts")
        .expect("the payee is a contact");
    let tip = crate::handlers::app_router_impl::contact_relationship_tip(&contact)
        .expect("the relationship tip");
    let terms = dsm::types::operations::TransferTerms::new(
        b"ERA".to_vec(),
        crate::handlers::app_router_impl::transfer_nonce(&tip, amount, "ERA", &to.device_id),
        dsm::types::operations::TransactionMode::Unilateral,
        String::new(),
    );
    let unsigned = Operation::Transfer {
        to_device_id: to.device_id.to_vec(),
        amount: dsm::types::token_types::Balance::amount(amount),
        policy_commit: dsm::core::token::era_policy::era_policy_commit(),
        terms_commitment: terms.commitment(),
        signature: Vec::new(),
        authority_policy: None,
    };
    let canonical = unsigned.to_bytes();
    let signature = dsm::crypto::sphincs::sphincs_sign(
        &crate::sdk::signing_authority::current_secret_key().expect("the signing key"),
        &canonical,
    )
    .expect("signs");
    Operation::decode_and_bind_signed(
        &canonical,
        &signature,
        &crate::sdk::signing_authority::current_public_key().expect("the public key"),
    )
    .expect("the signature binds")
}

/// `own`'s relationship step with `peer` over `operation`.
fn chain_state(
    own: &TestDevice,
    peer: &TestDevice,
    operation: &Operation,
    entropy: u8,
) -> RelationshipChainState {
    own.enter();
    let contact = client_db::get_contact_by_device_id(&peer.device_id)
        .expect("contacts")
        .expect("the peer is a contact");
    RelationshipChainState {
        rel_key: dsm::core::bilateral_transaction_manager::compute_smt_key(
            &own.device_id,
            &peer.device_id,
        ),
        embedded_parent: crate::handlers::app_router_impl::contact_relationship_tip(&contact)
            .expect("the relationship tip"),
        counterparty_devid: peer.device_id,
        operation: operation.clone(),
        entropy: vec![entropy; 32],
        encapsulated_entropy: None,
        entity_sig: None,
        counterparty_sig: None,
    }
}

/// Put every artifact of `parts` on the network's set, and register, under
/// `device`'s own key, the claim naming them at `position` along the cell
/// routed from `parent_root`. Asserts the claim is final there: the nodes
/// took a step nobody validated.
async fn publish_and_register(
    device: &TestDevice,
    position: u64,
    parent_root: &[u8; 32],
    parts: &DsmAdmissionParts,
) {
    use crate::sdk::economic_registers::{
        register_economic_root, root_cell, root_claim_settlement, RootClaimSettlement,
    };
    device.enter();
    let set = crate::sdk::storage_set::canonical_set(NETWORK).expect("canonical set");
    for (_, bytes, purpose) in &parts.artifacts {
        let namespace = match *purpose {
            "economic-transition-witness" => TAG_DSM_ECONOMIC_TRANSITION_WITNESS_OBJ,
            "economic-admission-manifest" => TAG_DSM_ECONOMIC_ADMISSION_MANIFEST,
            "economic-dsm-successor-evidence" => TAG_DSM_ECONOMIC_SUCCESSOR_EVIDENCE,
            "economic-authority-evidence" => TAG_DSM_ECONOMIC_AUTHORITY_EVIDENCE,
            "peer-transfer-acceptance" => TAG_DSM_PEER_TRANSFER_ACCEPTANCE,
            other => panic!("an artifact this test does not publish: {other}"),
        };
        crate::sdk::storage_io::put_immutable(&set, namespace, bytes)
            .await
            .expect("the artifact is put");
    }
    let profile =
        dsm::economic::register::resolve_root_register_profile(NETWORK).expect("register profile");
    let body = dsm::economic::claim::EconomicRootClaimBody::new(
        device.genesis,
        device.device_id,
        position,
        parts.coords.post_economic_root,
        parts.coords.admission_manifest_addr,
        profile.storage_set_id,
        dsm::ccb::genesis::sigalg::SPHINCS_PLUS_SPX256F,
        &crate::sdk::signing_authority::current_public_key().expect("the AK"),
        crate::sdk::signing_authority::current_att_a().expect("the AttA"),
    )
    .expect("a claim body");
    let claim = dsm::economic::claim_envelope::sign_economic_root_claim(
        &body,
        &crate::sdk::signing_authority::current_secret_key().expect("the AK secret"),
    )
    .expect("the claim is signed");
    let cell = root_cell(
        &set,
        NETWORK,
        &device.genesis,
        &device.device_id,
        position,
        parent_root,
    )
    .expect("the root cell");
    register_economic_root(&set, &cell, &claim)
        .await
        .expect("the claim is written along its route");
    assert_eq!(
        root_claim_settlement(&set, &cell, &claim)
            .await
            .expect("the cell reads"),
        RootClaimSettlement::Final,
        "the counterfeit step at {position} is final at its cell: the nodes did not validate it"
    );
}

/// What `payer`'s counterfeit first step produced.
struct Counterfeit {
    activation_root: [u8; 32],
    parts: DsmAdmissionParts,
    tree: dsm::economic::tree::EconomicSmt,
}

/// `payer`'s first step: a credit of `amount` ERA that names, as its source,
/// `source`'s step at `source_position` — whatever is there. `source` signs
/// the transfer the credit carries; nothing obliges it to have debited it.
async fn counterfeit_credit(
    payer: &TestDevice,
    source: &TestDevice,
    source_position: u64,
    amount: u64,
) -> Counterfeit {
    let transfer = signed_transfer(source, payer, amount);
    payer.enter();
    let core = payer.router().core_sdk.clone();
    let validated = validated_root_or_activate(&core).expect("the payer's activation root");
    assert_eq!(validated.economic_position(), 0, "the payer is new");
    let (mut tree, pre_state) = producer_tree_and_pre_state(&validated).expect("the tree");
    let authority = authority_material(NETWORK, &payer.genesis).expect("authority evidence");
    let bundle = {
        use prost::Message;
        dsm::types::proto::PeerTransferAcceptanceEvidenceV1 {
            transfer_request_bytes: dsm::types::proto::OnlineTransferRequest {
                canonical_operation_bytes: transfer.with_cleared_signature().to_bytes(),
                ..Default::default()
            }
            .encode_to_vec(),
            ..Default::default()
        }
        .encode_to_vec()
    };
    let facts = CreditSourceFacts::PeerDebit {
        peer_genesis: source.genesis,
        peer_devid: source.device_id,
        peer_economic_position: source_position,
        peer_debit_mutation_index: 0,
        acceptance_evidence_addr: dsm::economic::peer_acceptance::acceptance_evidence_addr(
            &bundle,
        ),
    };
    let artifacts = vec![(
        crate::sdk::economic_registers::immutable_object_key(
            TAG_DSM_PEER_TRANSFER_ACCEPTANCE,
            &bundle,
        ),
        bundle,
        "peer-transfer-acceptance",
    )];
    let state = chain_state(payer, source, &transfer, 0x31);
    payer.enter();
    let parts = build_dsm_admission(
        &payer.genesis,
        &payer.device_id,
        &state,
        &transfer,
        &pre_state,
        &mut tree,
        &facts,
        &authority,
        artifacts,
    )
    .expect("the producer's builders build what they are given");
    let activation_root = validated.economic_root();
    publish_and_register(payer, 1, &activation_root, &parts).await;
    Counterfeit {
        activation_root,
        parts,
        tree,
    }
}

/// A source, a counterfeiting payer and a receiver new to both, all on one
/// fleet. The source holds one faucet claim, at position 1, and nothing else.
async fn three_parties() -> (Pair, TestDevice) {
    let p = Pair::boot(100, 0).await;
    let mut c = TestDevice::create("C", 0x0C);
    c.boot(&p.fleet).await;
    c.add_contact(&p.b).await;
    p.b.add_contact(&c).await;
    (p, c)
}

/// A payer's history that starts with a credit no one debited, followed by an
/// ordinary debit of that value to a receiver that holds nothing of the payer,
/// is never accepted. The source signed the transfer the credit carries and
/// registered nothing at the position the credit names. Every hash in the
/// payer's history is consistent and every claim is final at its cell; the
/// value never came out of anyone's balance.
///
/// MUTATION CONTROL: validating each unseen step of the payer's history only
/// from the root its claim states (skipping `full_step` in `next_point`)
/// turns this red: the receiver accepts the debit of value that never existed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_payment_of_value_no_one_debited_is_never_accepted_by_a_receiver_new_to_the_payer() {
    let (p, c) = three_parties().await;
    let (source, payer) = (&p.a, &p.b);
    source.enter();
    let source_at = client_db::economic_lineage::get_admitted_coordinate()
        .expect("read")
        .expect("the source's faucet claim")
        .0;
    let amount = 10 * payout();
    let first = counterfeit_credit(payer, source, source_at + 1, amount).await;

    // The payer's next step debits that value to the receiver, built on the
    // root the counterfeit credit produced, exactly as an honest debit is.
    let debit = signed_transfer(payer, &c, amount);
    let state = chain_state(payer, &c, &debit, 0x32);
    payer.enter();
    let authority = authority_material(NETWORK, &payer.genesis).expect("authority evidence");
    let mut tree = first.tree;
    let pre_state = AdmittedPreState {
        balances: [(dsm::core::token::era_policy::era_policy_commit(), amount)]
            .into_iter()
            .collect(),
        economic_position: 2,
    };
    let second = build_dsm_admission(
        &payer.genesis,
        &payer.device_id,
        &state,
        &debit,
        &pre_state,
        &mut tree,
        &CreditSourceFacts::None,
        &authority,
        Vec::new(),
    )
    .expect("an ordinary debit of the credited value");
    publish_and_register(payer, 2, &first.parts.coords.post_economic_root, &second).await;
    assert_ne!(
        first.activation_root, first.parts.coords.post_economic_root,
        "the counterfeit credit moved the payer's root"
    );

    c.enter();
    match verify(payer, 2).await {
        Ok(step) => panic!(
            "a receiver new to the payer accepted a debit of value no one debited, at root {:?}",
            step.validated_root()
        ),
        Err(failure) => {
            let why = format!("{failure:?}");
            assert!(
                why.contains(&format!("{}", source_at + 1)),
                "the walk stops at the credit's source, the position the source never \
                 debited at: {why}"
            );
        }
    }
}

/// A credit whose source is the source's faucet claim, a step that debited
/// nobody, is never accepted by a receiver new to the payer.
///
/// MUTATION CONTROL: removing the requirement that a credit's source step be
/// an online transfer (in `full_step` for `StepRole::Source`, and its twin in
/// `prevalidate_sender_debit`) turns this red.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_credit_whose_source_is_a_faucet_claim_is_never_accepted() {
    let (p, c) = three_parties().await;
    let (source, payer) = (&p.a, &p.b);
    source.enter();
    let faucet_at = client_db::economic_lineage::get_admitted_coordinate()
        .expect("read")
        .expect("the source's faucet claim")
        .0;
    counterfeit_credit(payer, source, faucet_at, 10 * payout()).await;

    c.enter();
    match verify(payer, 1).await {
        Err(PeerLineageFailure::Invalid(why)) => assert!(
            why.contains("not an online transfer"),
            "the credit's source is refused as a debit: {why}"
        ),
        other => panic!("a credit sourced from a faucet claim is never accepted: {other:?}"),
    }
}

/// A credit whose source is a peer's activation root, position 0, which holds
/// no debit, is never accepted.
///
/// MUTATION CONTROL: removing the position-0 refusal in `source_step` turns
/// this red, or shows another check stops it first, which is recorded with
/// the run.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_credit_whose_source_is_an_activation_root_is_never_accepted() {
    let (p, c) = three_parties().await;
    let (source, payer) = (&p.a, &p.b);
    counterfeit_credit(payer, source, 0, 10 * payout()).await;

    c.enter();
    match verify(payer, 1).await {
        Err(PeerLineageFailure::Invalid(why)) => assert!(
            why.contains("position 0 is the activation root"),
            "the activation root funds nothing: {why}"
        ),
        other => panic!("a credit sourced from an activation root is never accepted: {other:?}"),
    }
}
