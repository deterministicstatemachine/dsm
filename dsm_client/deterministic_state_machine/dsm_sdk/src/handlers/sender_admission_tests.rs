// SPDX-License-Identifier: Apache-2.0

//! The generalized admission seam under ordinary operations: an admitted burn
//! and an admitted token creation through their routes, the multi-step
//! foreign walk, the admission serialization (correction B), and the
//! held-outbox rule (correction A).
//!
//! Every device is created as wallet creation creates it, on the network's
//! pinned set of storage nodes; every fault is a node that stops serving.

use prost::Message;
use serial_test::serial;

use crate::bridge::{AppInvoke, AppResult, AppRouter};
use crate::economic_fixtures::{self, NETWORK};
use crate::handlers::app_router_impl::AppRouterImpl;
use crate::sdk::economic_admission_flow::resume_pending_admission;
use crate::storage::client_db;
use crate::test_support::one_device::Device;
use crate::test_support::two_device::{assert_incomplete, Pair};

fn era() -> [u8; 32] {
    dsm::core::token::token_state_manager::era_policy_commit()
}

async fn invoke<M: Message>(router: &AppRouterImpl, method: &str, body: &M) -> AppResult {
    router
        .invoke(AppInvoke {
            method: method.into(),
            args: crate::generated::ArgPack {
                codec: crate::generated::Codec::Proto as i32,
                body: body.encode_to_vec(),
                ..Default::default()
            }
            .encode_to_vec(),
        })
        .await
}

fn burn_request(token_id: &str, amount: u64) -> dsm::types::proto::TokenBurnRequest {
    dsm::types::proto::TokenBurnRequest {
        token_id: token_id.into(),
        amount,
        message: format!("burn {amount} {token_id}"),
    }
}

fn create_request(
    ticker: &str,
    decimals: u32,
    genesis_supply: u128,
) -> crate::generated::TokenCreateRequest {
    crate::generated::TokenCreateRequest {
        ticker: ticker.into(),
        alias: format!("{ticker} Token"),
        decimals,
        genesis_supply_u128: genesis_supply.to_be_bytes().to_vec(),
        burn_enabled: true,
        transferable: true,
        threshold: 1,
        description: String::new(),
        icon_url: String::new(),
        allowlist_device_ids: Vec::new(),
    }
}

/// A token whose policy refuses every transfer.
fn non_transferable_request(ticker: &str) -> crate::generated::TokenCreateRequest {
    let mut request = create_request(ticker, 2, 1_000);
    request.transferable = false;
    request
}

fn payload(result: &AppResult) -> crate::generated::envelope::Payload {
    assert!(result.success, "{:?}", result.error_message);
    crate::generated::Envelope::decode(&result.data[1..])
        .expect("envelope")
        .payload
        .expect("payload")
}

fn admitted_position() -> u64 {
    economic_fixtures::admitted_position().expect("the device is activated")
}

/// A foreign walk of `position` of this device's lineage. A device records
/// no frontier for itself, so the walk starts at its activation root, as a
/// verifier meeting it first would, and nothing below reads local admission
/// state.
async fn foreign_walk(
    genesis: [u8; 32],
    devid: [u8; 32],
    position: u64,
) -> dsm::economic::provenance::ValidatedPeerTransition {
    let handle = tokio::runtime::Handle::current();
    tokio::task::spawn_blocking(move || {
        use dsm::economic::provenance::ProvenanceResolver;
        let set = crate::sdk::storage_set::canonical_set(NETWORK).expect("canonical set");
        let resolver = crate::sdk::economic_registers::LiveRegisterResolver {
            set: &set,
            runtime: handle,
            expected_network_id: NETWORK.to_vec(),
        };
        resolver.validated_peer_transition(&genesis, &devid, position)
    })
    .await
    .expect("join")
    .unwrap_or_else(|e| panic!("position {position} MUST be foreign-walkable: {e:?}"))
}

/// Every envelope the fleet holds in its spools, over every node.
async fn fleet_spool_count(p: &Pair) -> usize {
    let mut count = 0;
    for node in &p.nodes.nodes {
        count += node.spool().await.len();
    }
    count
}

fn outbox_status(rel: &[u8; 32]) -> String {
    let binding = client_db::get_connection().expect("device db");
    let conn = binding.lock().unwrap_or_else(|e| e.into_inner());
    conn.query_row(
        "SELECT status FROM sender_outbox WHERE relationship_key = ?1",
        rusqlite::params![rel.as_slice()],
        |r| r.get(0),
    )
    .expect("the outbox row")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn an_admitted_burn_advances_the_lineage_and_is_foreign_walkable() {
    // Faucet position 1 (+100.00 ERA), then an ADMITTED burn of 40 base units
    // at position 2.
    // Then the decisive check: a FOREIGN walk of positions 1..2, crossing a
    // reserve release AND a pure debit in one lineage.
    let d = Device::funded(0xC1).await;
    let burned = invoke(&d.router, "token.burn", &burn_request("ERA", 40)).await;
    match payload(&burned) {
        crate::generated::envelope::Payload::TokenBurnResponse(r) => {
            assert_eq!(r.new_balance, economic_fixtures::whole_era(100) - 40)
        }
        other => panic!("expected TokenBurnResponse, got {other:?}"),
    }
    assert_eq!(d.era_balance(), economic_fixtures::whole_era(100) - 40);
    let head = d.core().device_head().expect("head");
    assert!(head.pending_economic_admission().is_none(), "unfenced");
    let (position, admitted_root) = client_db::economic_lineage::get_admitted_coordinate()
        .expect("read admitted")
        .expect("admitted");
    assert_eq!(position, 2);

    let peer = foreign_walk(head.genesis_digest(), head.devid(), 2).await;
    assert_eq!(peer.validated_root().economic_position(), 2);
    assert_eq!(peer.validated_root().economic_root(), admitted_root);
    assert!(matches!(
        peer.verified_operation(),
        dsm::types::operations::Operation::Burn { .. }
    ));
}

/// Correction B: the seam CAS-checks the admitted predecessor UNDER the lock.
/// An admission staged at position 2, overtaken by another admission that
/// took position 2 first, must refuse — never overwrite.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_stale_admission_snapshot_is_refused_not_committed() {
    let d = Device::funded(0xC2).await;
    let (op, deltas) = d
        .router
        .burn_operation(&burn_request("ERA", 1))
        .expect("the burn this device signs");
    let staged = crate::sdk::economic_admission_flow::stage_admission(
        d.core(),
        &op,
        dsm::economic::write_set::CreditSourceFacts::None,
        Vec::new(),
        None,
    )
    .await
    .expect("stage at position 2");
    assert_eq!(staged.prepared.economic_position, 2);

    // Another admission takes position 2 first.
    let overtaking = invoke(&d.router, "token.burn", &burn_request("ERA", 10)).await;
    assert!(overtaking.success, "{:?}", overtaking.error_message);
    assert_eq!(admitted_position(), 2);
    let head_before = d.core().device_head().expect("head").root();

    let err = d
        .core()
        .admitted_advance(
            op,
            &deltas,
            staged.prepared,
            |_| {
                Err(dsm::types::error::DsmError::invalid_operation(
                    "the witness of a refused admission must never be built",
                ))
            },
            &staged.set.id(),
            None,
        )
        .expect_err("a stale predecessor must refuse");
    assert!(
        err.to_string()
            .contains("does not extend the admitted coordinate"),
        "got: {err}"
    );
    assert_eq!(admitted_position(), 2, "nothing admitted");
    assert_eq!(
        d.core().device_head().expect("head").root(),
        head_before,
        "nothing advanced"
    );
    assert_eq!(
        d.era_balance(),
        economic_fixtures::whole_era(100) - 10,
        "only the overtaking burn debited"
    );
}

/// A refused advance leaves NOTHING: no head movement, no fence, no admitted
/// movement, no frozen artifact. A burn beyond the balance is refused by the
/// conservation guard inside the advance, before anything durable.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_refused_advance_leaves_no_trace() {
    let d = Device::funded(0xC3).await;
    let head_root_before = d.core().device_head().expect("head").root();
    let unpublished_before =
        client_db::frozen_publication_artifact::list_unpublished_artifacts(u32::MAX)
            .expect("frozen artifacts")
            .len();

    let refused = invoke(
        &d.router,
        "token.burn",
        &burn_request("ERA", economic_fixtures::whole_era(100) + 1),
    )
    .await;
    assert!(
        !refused.success,
        "a burn beyond the balance must be refused"
    );

    let head = d.core().device_head().expect("head");
    assert_eq!(head.root(), head_root_before, "no advance survived");
    assert!(
        head.pending_economic_admission().is_none(),
        "no fence survived"
    );
    assert_eq!(admitted_position(), 1, "no admitted movement");
    assert_eq!(d.era_balance(), economic_fixtures::whole_era(100));
    assert_eq!(
        client_db::frozen_publication_artifact::list_unpublished_artifacts(u32::MAX)
            .expect("frozen artifacts")
            .len(),
        unpublished_before,
        "no artifact was frozen"
    );
}

/// Faucet claim, burn, token creation, burn of the created token — four
/// admissions, three kinds of witness content, one strictly monotonic
/// lineage.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn sequential_admissions_stay_monotonic_across_operation_kinds() {
    let d = Device::funded(0xC4).await;
    let fee = dsm::core::token::TOKEN_CREATION_FEE_ERA;

    let burned = invoke(&d.router, "token.burn", &burn_request("ERA", 10)).await;
    assert!(burned.success, "{:?}", burned.error_message);
    assert_eq!(admitted_position(), 2);

    let created = invoke(&d.router, "token.create", &create_request("SEQ", 0, 500)).await;
    assert!(created.success, "{:?}", created.error_message);
    assert_eq!(admitted_position(), 3);

    let seq = client_db::token_registry::get_token_by_ticker("SEQ")
        .expect("registry read")
        .expect("SEQ registered");
    let burned = invoke(&d.router, "token.burn", &burn_request(&seq.token_id, 20)).await;
    assert!(burned.success, "{:?}", burned.error_message);
    assert_eq!(admitted_position(), 4);

    let head = d.core().device_head().expect("head");
    assert_eq!(
        head.balance(&era()),
        economic_fixtures::whole_era(100) - 10 - fee
    );
    assert_eq!(head.balance(&seq.policy_commit), 480);
}

/// A transfer names its token exactly. A request naming none is not an ERA
/// transfer, and a ticker is not case-folded into one it does not spell: both
/// are refused, and nothing moves.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_transfer_naming_no_token_or_a_misspelled_one_is_refused_and_nothing_moves() {
    let p = Pair::boot(100, 0).await;
    let request = |token_id: &str| crate::generated::OnlineTransferSmartRequest {
        recipient_device_id: p.b.device_id.to_vec(),
        amount: "10".to_string(),
        token_id: token_id.to_string(),
        memo: String::new(),
    };

    let unnamed = p.a.invoke("wallet.sendSmart", &request("")).await;
    assert!(!unnamed.success, "an omitted token is not ERA");
    let msg = unnamed.error_message.unwrap_or_default();
    assert!(msg.contains("names no token"), "got: {msg}");
    assert_eq!(p.a.era_balance(), economic_fixtures::whole_era(100));

    let folded = p.a.invoke("wallet.sendSmart", &request("era")).await;
    assert!(!folded.success, "`era` does not name ERA");
    assert_eq!(p.a.era_balance(), economic_fixtures::whole_era(100));
    assert_eq!(p.b.era_balance(), 0);
}

/// Every wire change owes its inverse immediately. The request a real send
/// delivers survives decode → encode byte for byte, and its signature still
/// verifies over its operation bytes under the key B holds for A. Its locator
/// hints, which the sender writes, survive the round trip with values
/// distinctive enough that a dropped field cannot alias a default.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn online_transfer_request_locators_round_trip_on_the_wire() {
    let p = Pair::boot(100, 0).await;
    let sent = p.a.send(&p.b, 10).await;
    assert!(sent.success, "{:?}", sent.error_message);
    let one = crate::test_support::arrivals::the_one_transfer(&p.b, &p.fleet).await;
    let delivered = crate::generated::OnlineTransferRequest::decode(one.transfer_bytes.as_slice())
        .expect("the delivered request decodes");
    assert_eq!(
        delivered.encode_to_vec(),
        one.transfer_bytes,
        "the delivered request re-encodes byte-identically"
    );
    p.b.enter();
    let ak = super::storage_routes::resolve_trusted_sender_ak(&one.header_sender)
        .expect("B holds A's key");
    dsm::types::operations::Operation::decode_and_bind_signed(
        &delivered.canonical_operation_bytes,
        &delivered.signature,
        &ak,
    )
    .expect("the decoded transfer verifies under A's key");

    let req = crate::generated::OnlineTransferRequest {
        sender_economic_position: 0x0102_0304_0506_0708,
        sender_debit_mutation_index: 0x0A0B_0C0D,
        ..delivered
    };
    let bytes = req.encode_to_vec();
    let back = crate::generated::OnlineTransferRequest::decode(bytes.as_slice())
        .expect("decode must succeed");
    assert_eq!(back, req, "every field must survive the round trip");
    assert_eq!(back.sender_economic_position, 0x0102_0304_0506_0708);
    assert_eq!(back.sender_debit_mutation_index, 0x0A0B_0C0D);
    assert_eq!(
        back.encode_to_vec(),
        bytes,
        "re-encode must be byte-identical"
    );
}

/// SoFi §54: the burn flag governs burns, and nothing else does. A token
/// created with burns disabled refuses `token.burn` as an operation its
/// policy does not permit, and nothing moves; the same route on a
/// burn-enabled created token is admitted
/// (`sequential_admissions_stay_monotonic_across_operation_kinds`).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_burn_disabled_token_refuses_its_burn() {
    let d = Device::funded(0xC6).await;
    let mut request = create_request("NOBN", 2, 1_000);
    request.burn_enabled = false;
    let created = invoke(&d.router, "token.create", &request).await;
    match payload(&created) {
        crate::generated::envelope::Payload::TokenCreateResponse(_) => {}
        other => panic!("expected TokenCreateResponse, got {other:?}"),
    }
    let row = client_db::token_registry::get_token_by_ticker("NOBN")
        .expect("registry read")
        .expect("registry row committed with the advance");
    // 1_000 units at two decimals: the whole supply, in base units.
    let supply = 1_000 * 100;
    let head = d.core().device_head().expect("head");
    assert_eq!(
        head.balance(&row.policy_commit),
        supply,
        "the whole supply, released"
    );
    let position = admitted_position();

    let burned = invoke(&d.router, "token.burn", &burn_request("NOBN", 25)).await;
    assert!(
        !burned.success,
        "a burn-disabled token must refuse its burn: {:?}",
        burned.error_message
    );
    let why = burned.error_message.clone().unwrap_or_default();
    assert!(
        why.contains("Operation not permitted"),
        "refused by the policy's operation restriction, not for another reason: {why}"
    );
    let head = d.core().device_head().expect("head");
    assert_eq!(head.balance(&row.policy_commit), supply, "nothing moved");
    assert_eq!(admitted_position(), position, "no position was admitted");
    assert!(
        head.pending_economic_admission().is_none(),
        "nothing left pending"
    );
}

/// Pre-audit item 6 (§6.63): a send pays the contact the user chose, never
/// whichever contact its alias finds. A holds two contacts named "B": B,
/// added first, and C, added under the same alias. The user pays each in
/// turn, 10 ERA to C and then 20 ERA to B, and the wallet sends the request
/// the frontend builds for each choice ([`chosen_contact_request`]). Each is
/// paid what was sent to it. Resolving by alias, in whatever order, sends
/// both payments to the same contact.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_send_pays_the_contact_chosen_not_the_first_of_its_alias() {
    let p = Pair::boot(100, 0).await;
    let mut c = crate::test_support::two_device::TestDevice::create("C", 0x0C);
    c.boot(&p.fleet).await;
    c.add_contact(&p.a).await;
    let same_alias =
        p.a.invoke(
            "contacts.addManual",
            &crate::generated::ContactManualAddRequest {
                alias: p.b.slot.to_string(),
                device_id: c.device_id.to_vec(),
                genesis_hash: c.genesis.to_vec(),
                signing_public_key: c.ak_pk.clone(),
            },
        )
        .await;
    assert!(
        same_alias.success,
        "A adds C under B's alias: {:?}",
        same_alias.error_message
    );

    for (chosen, amount) in [(&c, "10"), (&p.b, "20")] {
        let sent =
            p.a.invoke(
                "wallet.sendSmart",
                &chosen_contact_request(&p.a, chosen, amount),
            )
            .await;
        assert!(
            sent.success,
            "the send to {}: {:?}",
            chosen.slot, sent.error_message
        );
    }
    c.sync().await;
    p.b.sync().await;
    assert_eq!(
        c.era_balance(),
        economic_fixtures::whole_era(10),
        "C is paid what was sent to C"
    );
    assert_eq!(
        p.b.era_balance(),
        economic_fixtures::whole_era(20),
        "B is paid what was sent to B"
    );
}

/// The request the frontend builds when the user chooses `contact` in the
/// send screen (`SendTab.tsx` → `dsm/transactions.ts`): ERA, the amount as
/// typed, and the recipient by the chosen contact's device id, the key the
/// send screen selects it by.
fn chosen_contact_request(
    sender: &crate::test_support::two_device::TestDevice,
    contact: &crate::test_support::two_device::TestDevice,
    amount: &str,
) -> crate::generated::OnlineTransferSmartRequest {
    sender.enter();
    let chosen = client_db::get_contact_by_device_id(&contact.device_id)
        .expect("A's contacts")
        .expect("the chosen contact");
    crate::generated::OnlineTransferSmartRequest {
        recipient_device_id: chosen.device_id,
        amount: amount.to_string(),
        token_id: "ERA".to_string(),
        memo: String::new(),
    }
}

/// MR-DSM-0074, Amendment A3: a device sends only over relationships it
/// has pre-added. A device A never added as a contact cannot be sent to:
/// `wallet.sendSmart` refuses it, nothing is debited, no position is
/// admitted and nothing is left pending.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_send_to_a_device_that_is_not_a_contact_moves_nothing() {
    let p = Pair::boot(100, 0).await;
    let stranger = crate::test_support::two_device::TestDevice::create("C", 0x0C);
    p.a.enter();
    assert!(
        client_db::get_contact_by_device_id(&stranger.device_id)
            .expect("A's contacts")
            .is_none(),
        "C is not A's contact"
    );
    let position = admitted_position();

    let sent = p.a.send(&stranger, 10).await;
    assert!(
        !sent.success,
        "a device that is not a contact cannot be sent to: {:?}",
        sent.error_message
    );
    let Some(why) = sent.error_message.clone() else {
        panic!("a refused send names its reason")
    };
    assert!(
        why.contains("must be an added contact"),
        "refused because C is not a contact, not for another reason: {why}"
    );
    p.a.enter();
    assert_eq!(
        p.a.era_balance(),
        economic_fixtures::whole_era(100),
        "nothing was debited"
    );
    assert_eq!(admitted_position(), position, "no position was admitted");
    let head = p.a.router().core_sdk.device_head().expect("head");
    assert!(
        head.pending_economic_admission().is_none(),
        "nothing left pending"
    );
}

/// SoFi §49: `transferable` governs every transfer. A token created
/// non-transferable refuses `wallet.send` as an operation its policy does not
/// permit, and nothing moves; a transferable created token moves through the
/// same handler (`token_adoption_tests::an_adopted_token_resolves_on_the_receiving_device`).
/// The receiving device refuses it too, whatever its sender checked: B's
/// canonical apply of a transfer A signed, with B's pinned head for A as its
/// parent, runs the token's committed policy before any acceptance is built
/// (G7: the policy is honoured on every transfer, at both ends).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_non_transferable_token_refuses_its_transfer() {
    let p = Pair::boot(100, 0).await;
    let created = invoke(
        p.a.router(),
        "token.create",
        &non_transferable_request("NOTX"),
    )
    .await;
    match payload(&created) {
        crate::generated::envelope::Payload::TokenCreateResponse(_) => {}
        other => panic!("expected TokenCreateResponse, got {other:?}"),
    }
    p.a.enter();
    let row = client_db::token_registry::get_token_by_ticker("NOTX")
        .expect("registry read")
        .expect("registry row committed with the advance");
    let supply = 1_000 * 100;
    let head = p.a.router().core_sdk.device_head().expect("head");
    assert_eq!(
        head.balance(&row.policy_commit),
        supply,
        "the whole supply, released"
    );
    let position = admitted_position();

    let sent = p.a.send_token(&p.b, "NOTX", 25).await;
    assert!(
        !sent.success,
        "a non-transferable token must refuse its transfer: {:?}",
        sent.error_message
    );
    let why = sent.error_message.clone().unwrap_or_default();
    assert!(
        why.contains("Operation not permitted"),
        "refused by the policy's operation restriction, not for another reason: {why}"
    );
    p.a.enter();
    let head = p.a.router().core_sdk.device_head().expect("head");
    assert_eq!(head.balance(&row.policy_commit), supply, "nothing moved");
    assert_eq!(admitted_position(), position, "no position was admitted");
    assert!(
        head.pending_economic_admission().is_none(),
        "nothing left pending"
    );

    p.b.enter();
    let adopted = p
        .b
        .router()
        .query(crate::bridge::AppQuery {
            path: "tokens.addByAnchor".to_string(),
            params: crate::util::text_id::encode_base32_crockford(&row.policy_commit).into_bytes(),
        })
        .await;
    assert!(
        adopted.success,
        "B adopts NOTX: {:?}",
        adopted.error_message
    );
    p.a.enter();
    let b_contact = client_db::get_contact_by_device_id(&p.b.device_id)
        .expect("A's contacts")
        .expect("A holds B as a contact");
    let tip = crate::handlers::app_router_impl::contact_relationship_tip(&b_contact)
        .expect("A's relationship tip with B");
    let unsigned = dsm::types::operations::Operation::Transfer {
        to_device_id: p.b.device_id.to_vec(),
        amount: dsm::types::token_types::Balance::amount(25),
        token_id: b"NOTX".to_vec(),
        policy_commit: row.policy_commit,
        mode: dsm::types::operations::TransactionMode::Unilateral,
        nonce: crate::handlers::app_router_impl::transfer_nonce(&tip, 25, "NOTX", &p.b.device_id),
        recipient: b_contact.public_key.clone(),
        to: crate::util::text_id::encode_base32_crockford(&p.b.device_id).into_bytes(),
        message: String::new(),
        signature: Vec::new(),
        authority_policy: None,
    };
    let canonical = unsigned.to_bytes();
    let a_key = crate::sdk::signing_authority::current_public_key().expect("A's key");
    let signature = dsm::crypto::sphincs::sphincs_sign(
        &crate::sdk::signing_authority::current_secret_key().expect("A's signing key"),
        &canonical,
    )
    .expect("A signs");
    let signed =
        dsm::types::operations::Operation::decode_and_bind_signed(&canonical, &signature, &a_key)
            .expect("A's signature binds");

    p.b.enter();
    let rel_key =
        dsm::core::bilateral_transaction_manager::compute_smt_key(&p.b.device_id, &p.a.device_id);
    let parent = dsm::core::bilateral_transaction_manager::initial_chain_tip_from_device_ids(
        &p.b.device_id,
        &p.a.device_id,
    );
    let entropy = dsm::crypto::blake3::domain_hash_bytes(
        dsm::common::domain_tags::TAG_DSM_TEST_TIP,
        &canonical,
    );
    let child = crate::sdk::core_sdk::successor_child_tip(
        &rel_key,
        &parent,
        &p.b.device_id,
        &signed.to_bytes(),
        &entropy,
    );
    let refused = p.b.router().core_sdk.apply_incoming_transfer_staged(
        signed,
        &crate::types::identifiers::TransactionId::new("notx-to-b"),
        &crate::util::text_id::encode_base32_crockford(&p.a.device_id),
        &canonical,
        parent,
        child,
        entropy,
        |_, _| {
            Err::<(), _>(dsm::types::error::DsmError::invalid_operation(
                "reached acceptance: the policy did not refuse",
            ))
        },
        |_, _, _| {
            Err(dsm::types::error::DsmError::invalid_operation(
                "reached the accept transaction: the policy did not refuse",
            ))
        },
        None,
    );
    let why = match refused {
        Err(e) => e.to_string(),
        Ok(outcome) => panic!("B applied a non-transferable transfer: {outcome:?}"),
    };
    assert!(
        why.contains("Operation not permitted"),
        "B refuses by the policy's operation restriction: {why}"
    );
    let b_head = p.b.router().core_sdk.device_head().expect("B's head");
    assert_eq!(b_head.balance(&row.policy_commit), 0, "nothing reached B");
}

/// G13, MR-DSM-0029: the receiver reads the payer's register only after every
/// check it can decide from what it holds. A hostile sender does what its
/// wallet refuses to do: it signs a transfer of its non-transferable token to
/// B, advances its own head over it, and signs the step's receipt with its
/// per-step EK. Both halves reach B's boundary and bind. B's sync refuses the
/// pair by the token's committed policy, which B holds, and no member is asked
/// for a cell while it does: nothing of the sender's register is read for a
/// transfer B refuses in hand.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_transfer_its_policy_refuses_is_refused_before_the_senders_register_is_read() {
    use crate::handlers::recipient_dispatch::{ingest_evidence_half, ingest_transfer_half};
    use crate::storage::client_db::recipient_staging::{self, PairState};
    use crate::test_support::receipts::Party;
    use dsm::types::device_state::{BalanceDelta, BalanceDirection};
    use dsm::types::receipt_types::{compute_receipt_challenge_response_target, StitchedReceiptV2};

    let p = Pair::boot(100, 0).await;
    let created = invoke(
        p.a.router(),
        "token.create",
        &non_transferable_request("NOTX"),
    )
    .await;
    match payload(&created) {
        crate::generated::envelope::Payload::TokenCreateResponse(_) => {}
        other => panic!("expected TokenCreateResponse, got {other:?}"),
    }
    p.a.enter();
    let row = client_db::token_registry::get_token_by_ticker("NOTX")
        .expect("registry read")
        .expect("registry row committed with the advance");
    let sender_position = admitted_position() + 1;
    p.b.enter();
    let adopted = p
        .b
        .router()
        .query(crate::bridge::AppQuery {
            path: "tokens.addByAnchor".to_string(),
            params: crate::util::text_id::encode_base32_crockford(&row.policy_commit).into_bytes(),
        })
        .await;
    assert!(
        adopted.success,
        "B adopts NOTX: {:?}",
        adopted.error_message
    );

    // A's transfer, signed as its send would sign it.
    p.a.enter();
    let b_contact = client_db::get_contact_by_device_id(&p.b.device_id)
        .expect("A's contacts")
        .expect("A holds B as a contact");
    let tip = crate::handlers::app_router_impl::contact_relationship_tip(&b_contact)
        .expect("A's relationship tip with B");
    let unsigned = dsm::types::operations::Operation::Transfer {
        to_device_id: p.b.device_id.to_vec(),
        amount: dsm::types::token_types::Balance::amount(25),
        token_id: b"NOTX".to_vec(),
        policy_commit: row.policy_commit,
        mode: dsm::types::operations::TransactionMode::Unilateral,
        nonce: crate::handlers::app_router_impl::transfer_nonce(&tip, 25, "NOTX", &p.b.device_id),
        recipient: b_contact.public_key.clone(),
        to: crate::util::text_id::encode_base32_crockford(&p.b.device_id).into_bytes(),
        message: String::new(),
        signature: Vec::new(),
        authority_policy: None,
    };
    let canonical = unsigned.to_bytes();
    let a_key = crate::sdk::signing_authority::current_public_key().expect("A's key");
    let signature = dsm::crypto::sphincs::sphincs_sign(
        &crate::sdk::signing_authority::current_secret_key().expect("A's signing key"),
        &canonical,
    )
    .expect("A signs");
    let signed =
        dsm::types::operations::Operation::decode_and_bind_signed(&canonical, &signature, &a_key)
            .expect("A's signature binds");

    // A's own step over it, and the step's receipt, signed by A's per-step EK
    // as its wallet signs a send's receipt.
    let rel_key =
        dsm::core::bilateral_transaction_manager::compute_smt_key(&p.a.device_id, &p.b.device_id);
    let outcome =
        p.a.router()
            .core_sdk
            .device_head()
            .expect("A's head")
            .advance(
                rel_key,
                p.b.device_id,
                signed.clone(),
                &[BalanceDelta {
                    policy_commit: row.policy_commit,
                    direction: BalanceDirection::Debit,
                    amount: 25,
                }],
                None,
                None,
            )
            .expect("A's head advances over its own transfer");
    let mut receipt = StitchedReceiptV2::of_step(
        p.a.genesis,
        p.a.device_id,
        p.b.device_id,
        &outcome,
        None,
        &crate::sdk::app_state::AppState::get_device_tree_commitment()
            .expect("A's Device Tree commitment"),
    )
    .expect("the step's receipt");
    let (a, b) = (Party::from_seed(0x0A), Party::from_seed(0x0B));
    assert_eq!(a.device_id(), p.a.device_id, "the harness's A is seed 0x0A");
    let commitment = receipt.compute_commitment().expect("the commitment");
    let target = compute_receipt_challenge_response_target(&commitment, &commitment);
    let c_pre = dsm::core::bilateral_transaction_manager::compute_precommit(
        &tip,
        &canonical,
        &outcome.transition_entropy(),
    );
    let answer = a.answer(&b, &receipt.parent_tip, &c_pre, &target);
    receipt.set_ek_pk_a(answer.ek_pk);
    receipt.set_ek_cert_a(answer.ek_cert);
    receipt.set_kyber_ct_a(answer.kyber_ct);
    receipt.add_sig_a(answer.sig);
    let receipt_bytes = receipt.to_full_protobuf().expect("the signed receipt");
    let transfer_bytes = dsm::types::proto::OnlineTransferRequest {
        signature,
        canonical_operation_bytes: canonical,
        sender_economic_position: sender_position,
        sender_debit_mutation_index: 0,
    }
    .encode_to_vec();

    // Both halves reach B's boundary on B's route for A, and bind.
    p.b.enter();
    let a_contact = client_db::get_contact_by_device_id(&p.a.device_id)
        .expect("B's contacts")
        .expect("B holds A as a contact");
    let route = crate::sdk::b0x_sdk::B0xSDK::compute_b0x_address(
        &p.b.genesis,
        &p.b.device_id,
        &crate::handlers::app_router_impl::contact_relationship_tip(&a_contact)
            .expect("B's relationship tip with A"),
    )
    .expect("B's route for A");
    ingest_transfer_half(
        &transfer_bytes,
        &crate::util::text_id::encode_base32_crockford(&p.a.device_id),
        &route,
        &client_db::derive_submission_id(&commitment),
    )
    .expect("the transfer half is ingested");
    ingest_evidence_half(
        &receipt_bytes,
        &route,
        &crate::util::text_id::encode_base32_crockford(&commitment[..16]),
    )
    .expect("the evidence half is ingested");
    let pairs = recipient_staging::pairs_in_flight().expect("pairs");
    assert!(
        matches!(pairs.as_slice(), [pair] if pair.state == PairState::Bound),
        "the pair binds"
    );

    for node in &p.nodes.nodes {
        node.forget_requests();
    }
    let synced = p.b.sync().await;
    for node in &p.nodes.nodes {
        for request in node.requests() {
            assert!(
                !request.starts_with("GET /api/v2/cell/"),
                "{} was asked for a cell while B refused a transfer it holds the policy for: \
                 {request}",
                node.member_id
            );
        }
    }
    assert!(
        synced
            .errors
            .iter()
            .any(|e| e.contains("Operation not permitted")),
        "B refuses by the policy's operation restriction: {:?}",
        synced.errors
    );
    p.b.enter();
    let b_head = p.b.router().core_sdk.device_head().expect("B's head");
    assert_eq!(b_head.balance(&row.policy_commit), 0, "nothing reached B");
}

/// Token creation through its route, end to end: the fee debit and the
/// genesis-supply release to the creator are ONE admitted position, the
/// anchor is the content hash of the stored policy, an identical resubmission
/// reconciles, and the admitted burn route takes the next position.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn token_routes_admit_create_and_burn_end_to_end() {
    let d = Device::funded(0xC5).await;
    let fee = dsm::core::token::TOKEN_CREATION_FEE_ERA;

    let created = invoke(&d.router, "token.create", &create_request("ADMT", 2, 1_000)).await;
    let resp = match payload(&created) {
        crate::generated::envelope::Payload::TokenCreateResponse(t) => t,
        other => panic!("expected TokenCreateResponse, got {other:?}"),
    };
    assert_eq!(
        d.era_balance(),
        economic_fixtures::whole_era(100) - fee,
        "exactly the fee, burned"
    );
    assert_eq!(
        admitted_position(),
        2,
        "the creation is an admitted position"
    );
    let head = d.core().device_head().expect("head");
    assert!(head.pending_economic_admission().is_none(), "unfenced");
    let row = client_db::token_registry::get_token_by_ticker("ADMT")
        .expect("registry read")
        .expect("registry row committed with the advance");
    assert_eq!(
        row.genesis_supply, 100_000,
        "1,000 at two decimals, in base units"
    );
    assert_eq!(row.creator_device_id, d.identity.device_id);
    assert_eq!(
        head.balance(&row.policy_commit),
        100_000,
        "the whole genesis supply was released to the creator"
    );

    // The anchor is the content hash of the policy Rust packed: re-derive it
    // from the stored policy bytes.
    assert_eq!(resp.policy_anchor.len(), 32, "anchor is 32 bytes");
    let (stored_anchor, stored_policy) = client_db::token_registry::all_policies()
        .expect("policies")
        .into_iter()
        .find(|(a, _)| a.as_slice() == resp.policy_anchor.as_slice())
        .expect("the created token's policy is stored under its anchor");
    assert_eq!(
        dsm::crypto::blake3::domain_hash_bytes(
            dsm::common::domain_tags::TAG_DSM_POLICY,
            &stored_policy,
        ),
        stored_anchor,
        "stored policy must hash to the anchor the route returned"
    );

    // An identical resubmission reconciles: same id, no second fee, no advance.
    let again = invoke(&d.router, "token.create", &create_request("ADMT", 2, 1_000)).await;
    let resp2 = match payload(&again) {
        crate::generated::envelope::Payload::TokenCreateResponse(t) => t,
        other => panic!("expected TokenCreateResponse, got {other:?}"),
    };
    assert_eq!(resp2.token_id, resp.token_id, "one commitment, one token");
    assert_eq!(
        d.era_balance(),
        economic_fixtures::whole_era(100) - fee,
        "no second fee"
    );
    assert_eq!(
        admitted_position(),
        2,
        "a reconciled resubmission admits nothing"
    );

    // The admitted burn ROUTE (position 3).
    let burned = invoke(&d.router, "token.burn", &burn_request("ERA", 25)).await;
    assert!(burned.success, "{:?}", burned.error_message);
    assert_eq!(
        d.era_balance(),
        economic_fixtures::whole_era(100) - fee - 25
    );
    assert_eq!(
        admitted_position(),
        3,
        "the route burn advanced the lineage"
    );
}

/// MR-DSM-0030: every value-moving advance registers its root at the next
/// economic position. A transfer's sender registers the root of the position
/// its debit occupies, and a FOREIGN verifier walking the sender's lineage
/// with no local shortcuts validates that position as the transfer itself.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_transfer_registers_the_senders_root_at_the_next_position() {
    let p = Pair::boot(100, 0).await;
    p.a.enter();
    let before = admitted_position();
    let sent = p.a.send(&p.b, 10).await;
    assert!(sent.success, "{:?}", sent.error_message);
    let b_sync = p.b.sync().await;
    assert!(b_sync.success, "{:?}", b_sync.errors);
    let a_sync = p.a.sync().await;
    assert!(a_sync.success, "{:?}", a_sync.errors);
    assert_eq!(p.a.era_balance(), economic_fixtures::whole_era(100) - 10);

    p.a.enter();
    let (position, admitted_root) = client_db::economic_lineage::get_admitted_coordinate()
        .expect("read admitted")
        .expect("admitted");
    assert_eq!(
        position,
        before + 1,
        "the transfer is the next admitted position"
    );
    let head = p.a.router().core_sdk.device_head().expect("head");
    let peer = foreign_walk(head.genesis_digest(), head.devid(), position).await;
    assert_eq!(peer.validated_root().economic_position(), position);
    assert_eq!(peer.validated_root().economic_root(), admitted_root);
    assert!(
        matches!(
            peer.verified_operation(),
            dsm::types::operations::Operation::Transfer { .. }
        ),
        "the walked operation is the transfer itself"
    );
}

/// The creation's release is walkable by a FOREIGN verifier with no local
/// shortcuts: position 2 validates as the CreateToken itself.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_token_creation_is_foreign_walkable() {
    let d = Device::funded(0xC6).await;
    let created = invoke(&d.router, "token.create", &create_request("WALK", 0, 250)).await;
    assert!(created.success, "{:?}", created.error_message);
    let (position, admitted_root) = client_db::economic_lineage::get_admitted_coordinate()
        .expect("read admitted")
        .expect("admitted");
    assert_eq!(position, 2);

    let head = d.core().device_head().expect("head");
    let peer = foreign_walk(head.genesis_digest(), head.devid(), 2).await;
    assert_eq!(peer.validated_root().economic_position(), 2);
    assert_eq!(peer.validated_root().economic_root(), admitted_root);
    assert!(
        matches!(
            peer.verified_operation(),
            dsm::types::operations::Operation::CreateToken { .. }
        ),
        "the walked operation is the creation itself"
    );
}

/// A creation whose admission cannot finish (the fleet below quorum) is HELD:
/// the advance, its pending admission and its frozen evidence all exist
/// durably. Resume completes the SAME admission from the frozen bytes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_failed_finish_holds_the_creation_and_resume_completes_the_same_admission() {
    let mut d = Device::funded(0xC7).await;
    let fee = dsm::core::token::TOKEN_CREATION_FEE_ERA;
    let down = economic_fixtures::members_to_break_quorum();

    d.nodes.take_down(&down).await;
    let held = invoke(&d.router, "token.create", &create_request("HELD", 0, 300)).await;
    assert!(
        !held.success,
        "a creation that cannot be admitted must not report success"
    );
    let pending = d
        .core()
        .device_head()
        .expect("head")
        .pending_economic_admission()
        .cloned()
        .expect("the creation is HELD behind its pending admission");
    assert_eq!(pending.economic_position, 2);
    assert_eq!(admitted_position(), 1, "nothing admitted");
    assert_eq!(
        d.era_balance(),
        economic_fixtures::whole_era(100) - fee,
        "forward-only: the committed fee stands"
    );
    let frozen = client_db::frozen_publication_artifact::list_unpublished_artifacts(u32::MAX)
        .expect("frozen artifacts");
    assert!(
        !frozen.is_empty(),
        "the creation's evidence is frozen for resume"
    );

    d.nodes.bring_up(&down).await;
    let resumed = resume_pending_admission(d.core(), NETWORK, pending.clone())
        .await
        .expect("resume completes the held creation");
    assert_eq!(
        resumed.economic_position, 2,
        "admitted at its signed position"
    );
    assert!(
        d.core()
            .device_head()
            .expect("head")
            .pending_economic_admission()
            .is_none(),
        "unfenced after resume"
    );
    let row = client_db::token_registry::get_token_by_ticker("HELD")
        .expect("registry read")
        .expect("the registry row committed with the advance");
    assert_eq!(
        d.core()
            .device_head()
            .expect("head")
            .balance(&row.policy_commit),
        300,
        "the released supply stands"
    );
    let head = d.core().device_head().expect("head");
    let walked = foreign_walk(head.genesis_digest(), head.devid(), 2).await;
    assert_eq!(
        walked.validated_root().economic_position(),
        2,
        "the resumed admission is the one the fleet holds"
    );
}

/// COMPARE-AND-FINISH (ownership ruled 2026-09-15). A resume of an admission
/// that is already admitted returns that admission's outcome and writes
/// nothing. A stale resume held across a NEWER pending admission leaves that
/// admission, and the admitted coordinate, exactly as they were.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_stale_resume_returns_the_admitted_outcome_and_leaves_a_newer_admission_alone() {
    let mut p = Pair::boot(100, 0).await;
    let down = economic_fixtures::members_to_break_quorum();

    // An admission held at position 2, then finished by a resume.
    p.nodes.take_down(&down).await;
    assert!(!p.a.send(&p.b, 10).await.success, "the first send is held");
    p.a.enter();
    let core = p.a.router().core_sdk.clone();
    let stale = core
        .device_head()
        .expect("head")
        .pending_economic_admission()
        .cloned()
        .expect("the first admission rides the head");
    p.nodes.bring_up(&down).await;
    let first = resume_pending_admission(&core, NETWORK, stale.clone())
        .await
        .expect("the resume finishes the held admission");
    p.a.enter();
    assert_eq!(first.economic_position, 2);
    assert_eq!(admitted_position(), 2);

    // A DUPLICATE resume of the same admission: its outcome, nothing written.
    let again = resume_pending_admission(&core, NETWORK, stale.clone())
        .await
        .expect("a duplicate resume returns the admitted outcome");
    p.a.enter();
    assert_eq!(again.economic_position, first.economic_position);
    assert_eq!(admitted_position(), 2, "the duplicate moved nothing");

    // Deliver and finalize the first transfer, so the relationship is clear
    // for the next send.
    let resent = p.a.sync().await;
    assert!(resent.success, "{:?}", resent.errors);
    let applied = p.b.sync().await;
    assert!(applied.success, "{:?}", applied.errors);
    assert_eq!(p.b.era_balance(), 10, "B received the first transfer");
    let finalized = p.a.sync().await;
    assert!(finalized.success, "{:?}", finalized.errors);
    let released = p.b.sync().await;
    assert!(released.success, "{:?}", released.errors);

    // A NEWER admission held at position 3.
    p.nodes.take_down(&down).await;
    let held_again = p.a.send(&p.b, 5).await;
    assert!(
        !held_again.success,
        "the second send must not report success"
    );
    let msg = held_again.error_message.unwrap_or_default();
    assert!(
        msg.contains("HELD for resume"),
        "the second send is held for resume, got: {msg}"
    );
    p.a.enter();
    let newer = core
        .device_head()
        .expect("head")
        .pending_economic_admission()
        .cloned()
        .expect("the newer admission rides the head");
    assert_eq!(newer.economic_position, 3);

    // The STALE resume, held across it: the old outcome, the newer untouched.
    let stale_again = resume_pending_admission(&core, NETWORK, stale)
        .await
        .expect("a stale resume of an admitted admission returns its outcome");
    p.a.enter();
    assert_eq!(stale_again.economic_position, 2);
    let kept = core
        .device_head()
        .expect("head")
        .pending_economic_admission()
        .cloned()
        .expect("the newer admission is still pending");
    assert_eq!(
        (kept.economic_position, kept.operation_digest),
        (newer.economic_position, newer.operation_digest),
        "the newer pending admission is untouched"
    );
    assert_eq!(
        admitted_position(),
        2,
        "the admitted coordinate did not move"
    );
    p.nodes.bring_up(&down).await;
}

/// Correction A end to end: a send whose admission CANNOT finish (the fleet
/// below quorum) commits the debit forward-only, HOLDS the outbox row, and
/// emits ZERO transfer bytes — even when the resubmit sweep runs in the held
/// window. Recovery then completes the SAME admission from the frozen
/// artifacts, promotes the row, and the transfer delivers.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_failed_finish_holds_the_outbox_and_resume_completes_the_same_admission() {
    let mut p = Pair::boot(100, 0).await;
    let rel = p.a.rel_key_with(&p.b);
    let spooled_before = fleet_spool_count(&p).await;

    // Losing n − q + 1 members makes evidence publication impossible, so
    // finish_admission dies AFTER the staged commit.
    let down = economic_fixtures::members_to_break_quorum();
    p.nodes.take_down(&down).await;
    let refused = p.a.send(&p.b, 10).await;
    assert!(!refused.success, "the send must not report success");
    let msg = refused.error_message.unwrap_or_default();
    assert!(
        msg.contains("HELD for resume") && msg.contains("nothing was delivered"),
        "the refusal names the held admission, got: {msg}"
    );
    assert_eq!(
        p.a.era_balance(),
        economic_fixtures::whole_era(100) - 10,
        "forward-only: the committed debit stands"
    );
    assert_eq!(
        fleet_spool_count(&p).await,
        spooled_before,
        "zero transfer bytes emitted by the send itself"
    );

    p.a.enter();
    assert_eq!(
        outbox_status(&rel),
        client_db::OUTBOX_ECONOMIC_ADMISSION_PENDING
    );
    let core = p.a.router().core_sdk.clone();
    let pending = core
        .device_head()
        .expect("head")
        .pending_economic_admission()
        .cloned()
        .expect("the admission rides the head for resume");
    assert_eq!(admitted_position(), 1, "nothing admitted");

    // THE RACE (correction A's control): run the resubmit sweep in the held
    // window — it must not see the row, so nothing reaches any node.
    let swept = p.a.sync().await;
    assert_incomplete(&swept);
    assert_eq!(
        fleet_spool_count(&p).await,
        spooled_before,
        "the sweep in the held window emits ZERO transfer bytes"
    );

    // Recovery: the fleet serves again; finish the SAME admission from frozen
    // state.
    p.nodes.bring_up(&down).await;
    resume_pending_admission(&core, NETWORK, pending)
        .await
        .expect("resume completes the same admission");
    p.a.enter();
    assert_eq!(
        admitted_position(),
        2,
        "the SAME admission admitted at position 2"
    );
    assert!(
        core.device_head()
            .expect("head")
            .pending_economic_admission()
            .is_none(),
        "unfenced after resume"
    );
    assert_ne!(
        outbox_status(&rel),
        client_db::OUTBOX_ECONOMIC_ADMISSION_PENDING,
        "the terminal admission promoted the held row"
    );

    // And the promoted row now DELIVERS.
    let resent = p.a.sync().await;
    assert!(resent.success, "{:?}", resent.errors);
    assert!(
        fleet_spool_count(&p).await > spooled_before,
        "the promoted row is deliverable"
    );
    let applied = p.b.sync().await;
    assert!(applied.success, "{:?}", applied.errors);
    assert_eq!(p.b.era_balance(), 10, "B received the held transfer once");
}

/// A vault genesis names the position of the creation that carries it: the
/// successor of the predecessor the creation was built on. A creation built
/// on a predecessor the device no longer stands on — here a held token
/// creation that staging resumes on its way in, moving the predecessor — is
/// refused BEFORE its advance: nothing is admitted at a position the genesis
/// does not name, the head carries nothing pending, and the same creation
/// built again on the current predecessor is admitted at the position its new
/// genesis names.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_creation_built_on_a_predecessor_the_device_no_longer_stands_on_is_refused_before_its_advance(
) {
    let mut d = Device::funded(0xCA).await;
    let down = economic_fixtures::members_to_break_quorum();

    // A token creation held behind its pending admission at position 2.
    d.nodes.take_down(&down).await;
    let held = invoke(&d.router, "token.create", &create_request("HELD", 0, 300)).await;
    assert!(
        !held.success,
        "a creation that cannot be admitted must not report success"
    );
    assert!(
        economic_fixtures::pending_state(&d.router).is_some(),
        "the creation is held behind its pending admission"
    );
    assert_eq!(admitted_position(), 1);
    d.nodes.bring_up(&down).await;

    let held_token = client_db::token_registry::get_token_by_ticker("HELD")
        .expect("registry read")
        .expect("the held creation registered HELD")
        .policy_commit;
    let (token_a, token_b, reserve_a, reserve_b) = if era() < held_token {
        (era(), held_token, 10, 100)
    } else {
        (held_token, era(), 100, 10)
    };
    // The reserves as the user enters them: token units of each token.
    let entered = |token: &[u8; 32], base: u64| {
        let (.., decimals) =
            crate::handlers::wallet_routes::token_of_commit(token).expect("a known token");
        crate::handlers::wallet_routes::format_base_units_for_display(base, decimals)
    };
    let request = crate::generated::SofiCreateVaultRequest {
        token_a_policy_commit: token_a.to_vec(),
        token_b_policy_commit: token_b.to_vec(),
        reserve_a_entered: entered(&token_a, reserve_a),
        reserve_b_entered: entered(&token_b, reserve_b),
        fee_bps: 30,
    };

    // Built on position 1, the admitted predecessor when the genesis was
    // made; staging resumes the held creation first, so the device stands
    // on position 2 by the time the vault creation would advance.
    let refused = invoke(&d.router, "sofi.createVault", &request).await;
    assert!(
        !refused.success,
        "a creation whose genesis names a position the device is past went through: {:?}",
        refused.data
    );
    let message = refused.error_message.unwrap_or_default();
    assert!(
        message.contains("built on position 1") && message.contains("stands on is position 2"),
        "refused for another reason: {message}"
    );
    assert_eq!(
        admitted_position(),
        2,
        "the held creation resumed and nothing else was admitted"
    );
    assert!(
        d.core()
            .device_head()
            .expect("head")
            .pending_economic_admission()
            .is_none(),
        "the refused creation left nothing pending"
    );

    // Built again on position 2: admitted at 3, the position its genesis names.
    let created = invoke(&d.router, "sofi.createVault", &request).await;
    match payload(&created) {
        crate::generated::envelope::Payload::SofiVaultCreatedResponse(v) => {
            assert_eq!(v.position, 3)
        }
        other => panic!("sofi.createVault answered {other:?}"),
    }
    assert_eq!(admitted_position(), 3);
}
