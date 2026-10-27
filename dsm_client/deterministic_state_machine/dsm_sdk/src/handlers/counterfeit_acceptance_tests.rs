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
    signed_token_transfer(
        from,
        to,
        dsm::core::token::era_policy::era_policy_commit(),
        "ERA",
        amount,
    )
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

/// `own`'s step on its own self-loop relationship over `operation`: the
/// relationship a burn or a token creation advances.
fn self_loop_state(own: &TestDevice, operation: &Operation, entropy: u8) -> RelationshipChainState {
    own.enter();
    let rel_key =
        dsm::core::bilateral_transaction_manager::compute_smt_key(&own.device_id, &own.device_id);
    let Some(embedded_parent) = own
        .router()
        .core_sdk
        .device_head()
        .expect("the head")
        .chain_tip(&rel_key)
    else {
        panic!("the self-loop has a tip: the device has advanced it");
    };
    RelationshipChainState {
        rel_key,
        embedded_parent,
        counterparty_devid: own.device_id,
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
        acceptance_evidence_addr: dsm::economic::peer_acceptance::acceptance_evidence_addr(&bundle),
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
    c.add_contact(&p.a).await;
    p.a.add_contact(&c).await;
    (p, c)
}

/// Where [`next_step`] registered the payer's step, and the index in its
/// witness of the mutation whose balance fell: what a payee's locator names.
struct Registered {
    position: u64,
    debit_mutation_index: u32,
}

/// `payer`'s next step at its real admitted root: the relationship step
/// `state` over its operation, with the write set `write_set_operation`
/// produces. An honest producer builds the write set from the operation it
/// signs; software that does not can build it from another. Published and
/// registered along the cell routed from that root.
async fn next_step(
    payer: &TestDevice,
    state: RelationshipChainState,
    write_set_operation: &Operation,
) -> Registered {
    use dsm::economic::admission::{
        dsm_economic_operation_id, dsm_operation_digest, AcceptedAdmissionCoords,
        AcceptedSubstrateCoords,
    };
    use dsm::economic::claim::{AdmissionSubstrate, EconomicAdmissionManifest};
    use dsm::storage_object::immutable_inner;
    let operation = &state.operation;
    payer.enter();
    let core = payer.router().core_sdk.clone();
    let validated = validated_root_or_activate(&core).expect("the payer's admitted root");
    let (mut tree, pre_state) = producer_tree_and_pre_state(&validated).expect("the tree");
    let authority = authority_material(NETWORK, &payer.genesis).expect("authority evidence");
    let pre_root = tree.root();
    let c_dsm_plus = state.compute_chain_tip();
    let op_bytes = operation.to_bytes();
    let econ_op_id = dsm_economic_operation_id(&payer.genesis, &payer.device_id, &c_dsm_plus);
    let built = dsm::economic::write_set::build_write_set(
        write_set_operation,
        &payer.genesis,
        &payer.device_id,
        &econ_op_id,
        &pre_state.as_write_set_pre_state(),
        &mut tree,
        &CreditSourceFacts::None,
    )
    .expect("the write set of the other operation");
    let debit_mutation_index = built
        .mutations
        .iter()
        .position(|m| {
            m.post_state.as_ref().and_then(|s| s.credit_amount())
                < m.pre_state.as_ref().and_then(|s| s.credit_amount())
        })
        .map(u32::try_from)
        .expect("the write set debits the payer")
        .expect("the index fits");
    let witness = dsm::economic::witness::EconomicTransitionWitness::new(
        pre_root,
        built.post_root,
        econ_op_id,
        dsm_operation_digest(&op_bytes),
        built.mutations,
        built.credit_sources,
    )
    .expect("a witness");
    let witness_bytes = witness.encode().expect("the witness encodes");
    let successor_bytes = dsm::economic::successor_evidence::sign_dsm_successor_evidence(
        &state.rel_key,
        &state.embedded_parent,
        &state.counterparty_devid,
        &op_bytes,
        &state.entropy,
        state.encapsulated_entropy.as_deref(),
        &payer.genesis,
        &payer.device_id,
        &crate::sdk::signing_authority::current_secret_key().expect("the AK secret"),
    )
    .expect("the successor evidence");
    let substrate_addr =
        dsm::economic::successor_evidence::successor_evidence_addr(&successor_bytes);
    let manifest = EconomicAdmissionManifest::new(
        authority.position,
        immutable_inner(TAG_DSM_ECONOMIC_TRANSITION_WITNESS_OBJ, &witness_bytes),
        authority.addr,
        AdmissionSubstrate::DsmSuccessor {
            evidence_addr: substrate_addr,
        },
        witness.derived_provenance_index(),
    )
    .expect("a manifest");
    let manifest_bytes = manifest.encode().expect("the manifest encodes");
    let parts = DsmAdmissionParts {
        coords: AcceptedAdmissionCoords {
            post_economic_root: built.post_root,
            accepted_substrate_addr: substrate_addr,
            admission_manifest_addr: manifest.addr().expect("the manifest's address"),
            substrate: AcceptedSubstrateCoords::Successor {
                c_dsm_plus,
                embedded_parent: state.embedded_parent,
            },
        },
        witness,
        manifest,
        artifacts: vec![
            (String::new(), witness_bytes, "economic-transition-witness"),
            (String::new(), manifest_bytes, "economic-admission-manifest"),
            (
                String::new(),
                successor_bytes,
                "economic-dsm-successor-evidence",
            ),
            (
                String::new(),
                authority.bytes,
                "economic-authority-evidence",
            ),
        ],
        debit_mutation_index: None,
    };
    let position = pre_state.economic_position;
    publish_and_register(payer, position, &validated.economic_root(), &parts).await;
    Registered {
        position,
        debit_mutation_index,
    }
}

/// `from`'s online transfer of `amount` of the token `policy_commit` to `to`,
/// signed with `from`'s real key.
fn signed_token_transfer(
    from: &TestDevice,
    to: &TestDevice,
    policy_commit: [u8; 32],
    ticker: &str,
    amount: u64,
) -> Operation {
    from.enter();
    let contact = client_db::get_contact_by_device_id(&to.device_id)
        .expect("contacts")
        .expect("the payee is a contact");
    let tip = crate::handlers::app_router_impl::contact_relationship_tip(&contact)
        .expect("the relationship tip");
    let terms = dsm::types::operations::TransferTerms::new(
        ticker.as_bytes().to_vec(),
        crate::handlers::app_router_impl::transfer_nonce(&tip, amount, ticker, &to.device_id),
        dsm::types::operations::TransactionMode::Unilateral,
        String::new(),
    );
    let unsigned = Operation::Transfer {
        to_device_id: to.device_id.to_vec(),
        amount: dsm::types::token_types::Balance::amount(amount),
        policy_commit,
        token_policy: crate::sdk::economic_registers::carried_token_policy(&policy_commit)
            .expect("the payer holds its token's committed policy"),
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
    let (activation_root, credited_root) =
        (first.activation_root, first.parts.coords.post_economic_root);
    assert_ne!(
        activation_root, credited_root,
        "the counterfeit credit moved the payer's root"
    );
    // The payer's next step debits that value to the receiver, built on the
    // root the counterfeit credit produced, exactly as an honest debit is.
    counterfeit_debit(payer, &c, first, amount).await;

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

/// The payer's next step: an ordinary debit of `amount` ERA to `payee`,
/// built on the root `first` produced, published and registered at position
/// 2. Returns the debit, its relationship step and what it built.
async fn counterfeit_debit(
    payer: &TestDevice,
    payee: &TestDevice,
    first: Counterfeit,
    amount: u64,
) -> (Operation, RelationshipChainState, DsmAdmissionParts) {
    let debit = signed_transfer(payer, payee, amount);
    let state = chain_state(payer, payee, &debit, 0x32);
    payer.enter();
    let authority = authority_material(NETWORK, &payer.genesis).expect("authority evidence");
    let mut tree = first.tree;
    let pre_state = AdmittedPreState {
        balances: [(dsm::core::token::era_policy::era_policy_commit(), amount)]
            .into_iter()
            .collect(),
        economic_position: 2,
    };
    let parts = build_dsm_admission(
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
    publish_and_register(payer, 2, &first.parts.coords.post_economic_root, &parts).await;
    (debit, state, parts)
}

/// The whole acceptance. The counterfeiting payer hands a receiver that has
/// never seen it a payment of value no one debited: its signed transfer, the
/// locator of its registered debit and a receipt naming that debit's
/// relationship step, which is what a payee's sync takes from each payment.
/// The receiver's own acceptance (`prevalidate_incoming_transfer_admission`,
/// the step every payment its sync picks up goes through before anything is
/// written) refuses it, and nothing durable is left: no pending admission, no
/// admitted credit, no balance.
///
/// MUTATION CONTROL: skipping `full_step` for the payer's unseen steps in
/// `next_point` turns this red: the receiver's acceptance prepares the credit.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_new_receivers_acceptance_refuses_a_payment_of_value_no_one_debited() {
    use crate::sdk::economic_admission_flow::{
        prevalidate_incoming_transfer_admission, IncomingTransfer,
    };
    use crate::storage::client_db::recipient_staging::LocatorHint;
    let (p, c) = three_parties().await;
    let (source, payer) = (&p.a, &p.b);
    source.enter();
    let source_at = client_db::economic_lineage::get_admitted_coordinate()
        .expect("read")
        .expect("the source's faucet claim")
        .0;
    let amount = 10 * payout();
    let first = counterfeit_credit(payer, source, source_at + 1, amount).await;
    let (debit, state, parts) = counterfeit_debit(payer, &c, first, amount).await;
    let receipt = dsm::types::receipt_types::StitchedReceiptV2::new(
        payer.genesis,
        payer.device_id,
        c.device_id,
        state.embedded_parent,
        state.compute_chain_tip(),
        [0x51; 32],
        [0x52; 32],
        [0x32; 32],
        Vec::new(),
        Vec::new(),
    )
    .to_full_protobuf()
    .expect("the receipt encodes");
    let Operation::Transfer { signature, .. } = &debit else {
        panic!("the debit is a transfer")
    };

    c.enter();
    let refusal = prevalidate_incoming_transfer_admission(
        &c.router().core_sdk,
        &payer.genesis,
        &payer.device_id,
        &payer.ak_pk,
        &IncomingTransfer {
            canonical_operation_bytes: &debit.with_cleared_signature().to_bytes(),
            signature,
            hint: LocatorHint {
                economic_position: 2,
                debit_mutation_index: parts.debit_mutation_index.expect("the debit's index"),
            },
            evidence_bytes: &receipt,
        },
        &c.rel_key_with(payer),
    )
    .await
    .map(|_| ())
    .expect_err("a payment of value no one debited is never prepared for admission");
    assert!(
        format!("{refusal}").contains(&format!("{}", source_at + 1)),
        "refused at the credit's source, the position the source never debited at: {refusal}"
    );
    c.enter();
    assert!(
        c.router()
            .core_sdk
            .device_head()
            .expect("a head")
            .pending_economic_admission()
            .is_none(),
        "no pending admission"
    );
    assert!(
        client_db::economic_lineage::get_admitted_coordinate()
            .expect("read")
            .is_none(),
        "no admitted credit"
    );
    assert_eq!(c.era_balance(), 0, "no balance");
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

/// A transfer of a token whose committed policy does not let it transfer is
/// never accepted, however valid the payer's history and the step's debit.
/// The payer created the token itself, honestly, with transfers turned off,
/// and then debits some of it to a receiver new to it. Its own wallet and
/// Core's builder refuse the send, so it builds the step itself: the signed
/// transfer carries the token's own committed policy, and the debit is the one a burn
/// of the same amount writes. The receiver's provenance walk refuses the step,
/// and so does its whole acceptance (`prevalidate_incoming_transfer_admission`,
/// which every payment its sync picks up goes through before anything is
/// written), from the signed transfer, the locator of the registered debit
/// and a receipt naming the step: nothing durable is left (owner question 9:
/// the enforcement is Core's, past the payer's SDK).
///
/// MUTATION CONTROL: removing the `transferable` refusal from the write set's
/// Transfer arm turns this red: the receiver accepts the transfer.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_transfer_of_a_token_whose_policy_forbids_transfers_is_never_accepted() {
    use crate::bridge::{AppInvoke, AppRouter};
    use prost::Message;
    let (p, c) = three_parties().await;
    let payer = &p.a;
    payer.enter();
    let created = payer
        .router()
        .invoke(AppInvoke {
            method: "token.create".into(),
            args: dsm::types::proto::ArgPack {
                codec: dsm::types::proto::Codec::Proto as i32,
                body: super::sender_admission_tests::non_transferable_request("BOUND")
                    .encode_to_vec(),
                ..Default::default()
            }
            .encode_to_vec(),
        })
        .await;
    assert!(
        created.success,
        "the token is created: {:?}",
        created.error_message
    );
    payer.enter();
    let bound = client_db::token_registry::get_token_by_ticker("BOUND")
        .expect("registry read")
        .expect("BOUND is registered")
        .policy_commit;
    let transfer = signed_token_transfer(payer, &c, bound, "BOUND", 5);
    let same_debit = Operation::Burn {
        amount: dsm::types::token_types::Balance::amount(5),
        token_id: b"BOUND".to_vec(),
        policy_commit: bound,
        token_policy: crate::sdk::economic_registers::carried_token_policy(&bound)
            .expect("the payer holds BOUND's committed policy"),
        message: String::new(),
    };
    let state = chain_state(payer, &c, &transfer, 0x33);
    let step = next_step(payer, state.clone(), &same_debit).await;

    c.enter();
    match verify(payer, step.position).await {
        Err(PeerLineageFailure::Invalid(why)) => assert!(
            why.contains("does not let it move between holders"),
            "refused by the token's committed policy: {why}"
        ),
        other => panic!("a transfer the token's policy forbids is never accepted: {other:?}"),
    }

    use crate::sdk::economic_admission_flow::{
        prevalidate_incoming_transfer_admission, IncomingTransfer,
    };
    use crate::storage::client_db::recipient_staging::LocatorHint;
    let receipt = dsm::types::receipt_types::StitchedReceiptV2::new(
        payer.genesis,
        payer.device_id,
        c.device_id,
        state.embedded_parent,
        state.compute_chain_tip(),
        [0x51; 32],
        [0x52; 32],
        [0x33; 32],
        Vec::new(),
        Vec::new(),
    )
    .to_full_protobuf()
    .expect("the receipt encodes");
    let Operation::Transfer { signature, .. } = &transfer else {
        panic!("the step is a transfer")
    };
    c.enter();
    let refusal = prevalidate_incoming_transfer_admission(
        &c.router().core_sdk,
        &payer.genesis,
        &payer.device_id,
        &payer.ak_pk,
        &IncomingTransfer {
            canonical_operation_bytes: &transfer.with_cleared_signature().to_bytes(),
            signature,
            hint: LocatorHint {
                economic_position: step.position,
                debit_mutation_index: step.debit_mutation_index,
            },
            evidence_bytes: &receipt,
        },
        &c.rel_key_with(payer),
    )
    .await
    .map(drop)
    .expect_err("a transfer the token's policy forbids is never prepared for admission");
    assert!(
        format!("{refusal}").contains("does not let it move between holders"),
        "the acceptance is refused by the token's committed policy: {refusal}"
    );
    c.enter();
    let head = c.router().core_sdk.device_head().expect("a head");
    assert!(
        head.pending_economic_admission().is_none(),
        "no pending admission"
    );
    assert!(
        client_db::economic_lineage::get_admitted_coordinate()
            .expect("read")
            .is_none(),
        "no admitted credit"
    );
    assert_eq!(head.balance(&bound), 0, "no BOUND");
}

/// A burn of a token whose committed policy does not let it be burned is
/// never accepted (DSM §61, MR-DSM-0191: no operation bypasses the asset's
/// committed policy). The payer created the token itself, honestly, with
/// burns turned off, and then burns some of it. Its own wallet and Core's
/// builder refuse the burn, so it builds the step itself: the signed burn
/// carries the token's own committed policy, and the debit is the one a transfer of
/// the same amount writes. A receiver new to the payer walks its history.
///
/// MUTATION CONTROL: removing the `burn_enabled` refusal from the write set's
/// Burn arm turns this red: the receiver accepts the burn.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_burn_of_a_token_whose_policy_forbids_burns_is_never_accepted() {
    use crate::bridge::{AppInvoke, AppRouter};
    use prost::Message;
    let (p, c) = three_parties().await;
    let payer = &p.a;
    payer.enter();
    let created = payer
        .router()
        .invoke(AppInvoke {
            method: "token.create".into(),
            args: dsm::types::proto::ArgPack {
                codec: dsm::types::proto::Codec::Proto as i32,
                body: super::sender_admission_tests::non_burnable_request("KEPT").encode_to_vec(),
                ..Default::default()
            }
            .encode_to_vec(),
        })
        .await;
    assert!(
        created.success,
        "the token is created: {:?}",
        created.error_message
    );
    payer.enter();
    let kept = client_db::token_registry::get_token_by_ticker("KEPT")
        .expect("registry read")
        .expect("KEPT is registered")
        .policy_commit;
    let burn = Operation::Burn {
        amount: dsm::types::token_types::Balance::amount(5),
        token_id: b"KEPT".to_vec(),
        policy_commit: kept,
        token_policy: crate::sdk::economic_registers::carried_token_policy(&kept)
            .expect("the payer holds KEPT's committed policy"),
        message: "burn 5 KEPT".to_string(),
    };
    let same_debit = signed_token_transfer(payer, &c, kept, "KEPT", 5);
    let step = next_step(payer, self_loop_state(payer, &burn, 0x34), &same_debit).await;

    c.enter();
    match verify(payer, step.position).await {
        Err(PeerLineageFailure::Invalid(why)) => assert!(
            why.contains("does not let it be burned"),
            "refused by the token's committed policy: {why}"
        ),
        other => panic!("a burn the token's policy forbids is never accepted: {other:?}"),
    }
}

/// A debit that takes less from the payer than the transfer it signs sends
/// is never accepted. The payer signs a transfer of all its ERA to a receiver
/// new to it, and builds the step's write set from a transfer of one base
/// unit: the receiver would be credited the whole amount while the payer
/// keeps all but one unit of it.
///
/// MUTATION CONTROL: skipping the debit-delta check in the write-set
/// verification turns this red: the receiver accepts the debit.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_debit_that_takes_less_than_it_sends_is_never_accepted() {
    let (p, c) = three_parties().await;
    let payer = &p.a;
    let whole = signed_transfer(payer, &c, payout());
    let one = signed_transfer(payer, &c, 1);
    let step = next_step(payer, chain_state(payer, &c, &whole, 0x33), &one).await;

    c.enter();
    match verify(payer, step.position).await {
        Err(PeerLineageFailure::Invalid(why)) => assert!(
            why.contains("debit delta is not exactly the operation amount"),
            "refused: the debit is not the amount sent: {why}"
        ),
        other => panic!("a debit smaller than the amount sent is never accepted: {other:?}"),
    }
}
