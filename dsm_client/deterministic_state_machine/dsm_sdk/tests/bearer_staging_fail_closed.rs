// SPDX-License-Identifier: MIT OR Apache-2.0
//! FAIL-CLOSED PROOF for bearer staging failure (supersedes the issue-#639
//! `MissingRelease` reachability proof).
//!
//! Historically, when offline-bearer staging failed the sender FELL OPEN: it proceeded
//! carrying an ordinary online `Debit` with an empty release, and only the receiver's
//! `OfflineRecover::MissingRelease` refusal (`anchor_accept.rs`, unit-tested there)
//! stranded it. The 2026-08-28 bearer-only cut deleted that fallback: staging failure is
//! now a NAMED sender-side refusal inside the confirm build, and the unsafe confirm is
//! unconstructible. This test drives the same live no-appliance path and proves BOTH
//! halves: the refusal fires (reachability), and nothing the sender owns crosses into
//! AUTHORITATIVE state. Every assertion reads DURABLE state back out of the database,
//! never the prepared object.
//!
//! WHY THIS IS AN INTEGRATION TEST, NOT A UNIT TEST. `tests/` compiles the crate WITHOUT
//! `cfg(test)`, so `core_sdk.rs:2528`'s `#[cfg(not(test))] hardware_appliance_or_fail`
//! applies and returns `Err(OFFLINE_BEARER_NO_APPLIANCE_MSG)` unconditionally. Staging
//! therefore fails BY CONSTRUCTION with no anchor factory installed — hermetic, and with
//! no process-global factory to leak into neighbouring tests. Inside `cfg(test)` the
//! `#[cfg(test)]` arm returns a working in-process mock and staging would SUCCEED, so the
//! same test written as a unit test would silently exercise nothing.
//!
//! The sender is a REAL testnet identity whose ERA came from a real faucet admission —
//! the head the bilateral confirm debits is the canonical head the router persisted, so
//! "nothing moved" is asserted against value that was actually there to move.

#![allow(clippy::disallowed_methods)]

use std::sync::Arc;

use serial_test::serial;
use tokio::sync::RwLock;

use dsm::core::bilateral_transaction_manager::{
    initial_chain_tip_from_device_ids, BilateralTransactionManager,
};
use dsm::core::contact_manager::DsmContactManager;
use dsm::crypto::signatures::SignatureKeyPair;
use dsm::types::device_state::{BalanceDelta, BalanceDirection};
use dsm::types::identifiers::NodeId;
use dsm::types::operations::{canonical_offline_bearer_policy, Operation, TransactionMode};
use dsm::types::token_types::Balance;

use dsm_sdk::bluetooth::bilateral_ble_handler::{BilateralBleHandler, BilateralPhase};
use dsm_sdk::economic_fixtures;
use dsm_sdk::storage::client_db;

/// The receiver never holds canonical state here, so a placeholder identity is
/// all it needs; the SENDER is the real, funded device.
const RECEIVER: [u8; 32] = [0xB2; 32];
const RECEIVER_GENESIS: [u8; 32] = [0xC3; 32];
/// What one faucet claim yields — the sender's whole balance.
const SENDER_ERA: u64 = dsm::economic::faucet::ERA_FAUCET_PAYOUT;
const SEND_AMOUNT: u64 = 50;

fn era_policy() -> [u8; 32] {
    dsm::core::token::builtin_policy_commit_for_token("ERA").expect("ERA policy commit")
}

fn keypair(seed: u8) -> SignatureKeyPair {
    SignatureKeyPair::generate_from_entropy(&[seed; 32]).expect("keypair")
}

/// The funded sender: a real testnet identity on a fresh database, its router built
/// on an EMPTY head carrying that identity, then funded through the REAL faucet
/// admission (0x0030) and persisted by the router's own commit path.
struct Sender {
    keypair: SignatureKeyPair,
    devid: [u8; 32],
    genesis: [u8; 32],
    router: dsm_sdk::handlers::app_router_impl::AppRouterImpl,
    _fleet: economic_fixtures::FleetGuard,
}

fn funded_sender() -> Sender {
    let _ = dsm_sdk::storage_utils::set_storage_base_dir(std::path::PathBuf::from(
        "./.dsm_testdata_missing_release",
    ));
    // Offline mode on: the bilateral storage the BLE handler's confirm path
    // consults exists only when the router is built with it.
    let (router, keypair, fleet) = economic_fixtures::empty_router_with(0xA1, true);
    let head = router.core_sdk.device_head().expect("the empty head");
    let (devid, genesis) = (head.devid(), head.genesis_digest());
    let position = economic_fixtures::claim_era(&router);
    assert_eq!(
        position, 1,
        "the faucet claim is the sender's economic position 1"
    );

    Sender {
        keypair,
        devid,
        genesis,
        router,
        _fleet: fleet,
    }
}

/// Persist a counterparty as a client_db contact WITH a Kyber public key.
///
/// Per-step EK signing (§11) encapsulates against the counterparty's ML-KEM-768 key when
/// building the receipt, and refuses a contact that has none. Without this the flow dies
/// at `handle_prepare_response` long before staging, and the test would prove nothing.
fn store_contact_with_kyber(device: [u8; 32], genesis: [u8; 32], signing_pk: Vec<u8>, alias: &str) {
    let kyber = dsm::crypto::kyber::generate_kyber_keypair().expect("kyber keypair");
    client_db::store_contact(&client_db::ContactRecord {
        contact_id: alias.to_string(),
        device_id: device.to_vec(),
        alias: alias.to_string(),
        genesis_hash: genesis.to_vec(),
        public_key: signing_pk,
        kyber_public_key: kyber.public_key.clone(),
        current_chain_tip: None,
        added_at: 0,
        verified: true,
        verification_proof: None,
        metadata: std::collections::HashMap::new(),
        ble_address: None,
        status: "active".to_string(),
        needs_online_reconcile: false,
        last_seen_online_counter: 0,
        last_seen_ble_counter: 0,
        previous_chain_tip: None,
    })
    .expect("store contact with kyber key");
}

fn handler_for(
    device: [u8; 32],
    own_genesis: [u8; 32],
    counterparty: [u8; 32],
    counterparty_genesis: [u8; 32],
    kp: SignatureKeyPair,
    counterparty_pk: Vec<u8>,
) -> BilateralBleHandler {
    let mut contacts = DsmContactManager::new(device, vec![NodeId::new("local")]);
    contacts
        .add_verified_contact(dsm::types::contact_types::DsmVerifiedContact {
            alias: "peer".to_string(),
            device_id: counterparty,
            genesis_hash: counterparty_genesis,
            public_key: counterparty_pk,
            genesis_material: vec![0; 32],
            chain_tip: None,
            chain_tip_smt_proof: None,
            genesis_verified_online: true,
            verified_at_commit_height: 1,
            added_at_commit_height: 1,
            last_updated_commit_height: 1,
            verifying_storage_nodes: vec![],
            ble_address: None,
        })
        .expect("verified contact");

    let mgr = BilateralTransactionManager::new(contacts, kp, device, own_genesis);
    let mgr = Arc::new(RwLock::new(mgr));
    futures::executor::block_on(async {
        mgr.write()
            .await
            .establish_relationship(&counterparty)
            .await
            .expect("relationship");
    });
    BilateralBleHandler::new(mgr, device)
}

/// The one operation shape that reaches the staging path: a `Transfer` carrying the
/// CANONICAL offline-bearer authority policy. `operation_requires_offline_bearer`
/// (bilateral_transaction_manager.rs:240-247) matches on exactly this, and the receiver
/// additionally refuses any non-canonical `policy_id`, so it is built by the constructor
/// rather than by hand.
fn bearer_transfer() -> Operation {
    Operation::Transfer {
        to_device_id: RECEIVER.to_vec(),
        amount: Balance::from_state(SEND_AMOUNT, [0u8; 32]),
        token_id: b"ERA".to_vec(),
        policy_commit: era_policy(),
        mode: TransactionMode::Bilateral,
        nonce: vec![0x42; 32],
        verification: dsm::types::operations::VerificationType::Standard,
        pre_commit: None,
        message: "bearer".to_string(),
        recipient: RECEIVER.to_vec(),
        to: RECEIVER.to_vec(),
        signature: Vec::new(),
        authority_policy: Some(canonical_offline_bearer_policy()),
    }
}

/// A snapshot of everything that must not move.
#[derive(Debug, PartialEq, Eq)]
struct DurableSenderState {
    head_root: [u8; 32],
    era_balance: u64,
    chain_state_rows: usize,
}

fn snapshot_sender(sender: &[u8; 32]) -> DurableSenderState {
    let head = client_db::load_bcr_device_head(sender)
        .expect("head query must not error")
        .expect("the sender head MUST exist — without it every assertion is vacuous");
    DurableSenderState {
        head_root: head.root(),
        era_balance: head.balance(&era_policy()),
        chain_state_rows: client_db::get_bcr_chain_states(sender, false)
            .expect("chain-state query")
            .len(),
    }
}

/// THE PROOF.
///
/// Staging fails, the SENDER refuses to build the confirm (the deleted fail-open path
/// used to proceed here), and NOTHING the sender owns moves: same head root, same
/// balance, no new chain-state row, session never committed.
///
/// Multi-threaded on purpose: the faucet fixture blocks on the SDK's own runtime,
/// which a current-thread test runtime cannot host.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial]
async fn a_failed_bearer_staging_refuses_the_send_and_strands_no_debit() {
    let receiver_kp = keypair(0xB2);

    let sender = tokio::task::block_in_place(funded_sender);
    let sender_pk = sender.keypair.public_key().to_vec();
    let sender_devid = sender.devid;
    assert_eq!(
        snapshot_sender(&sender_devid).era_balance,
        SENDER_ERA,
        "precondition: the sender actually holds spendable, admitted ERA, so a debit is \
         possible"
    );

    dsm_sdk::bridge::install_app_router(Arc::new(sender.router)).expect("install app_router");

    let sender_handler = handler_for(
        sender_devid,
        sender.genesis,
        RECEIVER,
        RECEIVER_GENESIS,
        sender.keypair.clone(),
        receiver_kp.public_key.clone(),
    );
    let receiver = handler_for(
        RECEIVER,
        RECEIVER_GENESIS,
        sender_devid,
        sender.genesis,
        keypair(0xB2),
        sender_pk.clone(),
    );

    store_contact_with_kyber(
        RECEIVER,
        RECEIVER_GENESIS,
        receiver_kp.public_key.clone(),
        "receiver",
    );
    store_contact_with_kyber(sender_devid, sender.genesis, sender_pk.clone(), "sender");

    let before = snapshot_sender(&sender_devid);
    assert_eq!(before.era_balance, SENDER_ERA);

    // --- 3-step bilateral, driven directly (the BLE transport is not what is on trial) ---
    let (prepare_bytes, commitment) = sender_handler
        .prepare_bilateral_transaction(RECEIVER, bearer_transfer(), 300)
        .await
        .expect("prepare");

    let _ = receiver
        .handle_prepare_request(&prepare_bytes, None)
        .await
        .expect("receiver accepts the prepare");

    // The receiver's accept carries the `receiver_challenge` without which the sender
    // never even attempts staging (handler :3564 falls to `_ => None` at :3623).
    let accept_bytes = receiver
        .create_prepare_accept_envelope(commitment)
        .await
        .expect("accept envelope");

    dsm_sdk::sdk::app_state::AppState::set_identity_info(
        sender_devid.to_vec(),
        sender_pk.clone(),
        sender.genesis.to_vec(),
        vec![0u8; 32],
    );
    // Absorbing the accept IS what builds the confirm (it drives send_bilateral_confirm
    // internally). Staging fails inside it — no anchor appliance, and `tests/` compiles the
    // crate without cfg(test) — and the 2026-08-28 bearer-only cut makes that a NAMED
    // sender-side refusal: the confirm is never built, no online Debit survives anywhere,
    // and no bytes reach the receiver. (The receiver-side MissingRelease refusal that used
    // to strand the fail-open confirm remains unit-tested in `anchor_accept.rs`.)
    let err = sender_handler
        .handle_prepare_response(&accept_bytes)
        .await
        .expect_err("a bearer send whose staging failed MUST refuse at the sender");
    let msg = format!("{err}");
    assert!(
        msg.contains("offline-bearer staging failed"),
        "the refusal must be the named staging error — any other failure means the test \
         never reached the fail-closed seam. Got: {msg}"
    );

    // --- THE FOUR ASSERTIONS, all on durable state ---
    let after = snapshot_sender(&sender_devid);

    assert_eq!(
        after.head_root, before.head_root,
        "BLOCKER: the sender's persisted device head root moved — a debit crossed into \
         authoritative state while the receiver credited nothing"
    );
    assert_eq!(
        after.era_balance, before.era_balance,
        "BLOCKER: the sender's ERA balance changed ({} -> {}) with no receiver credit",
        before.era_balance, after.era_balance
    );
    assert_eq!(
        after.chain_state_rows, before.chain_state_rows,
        "BLOCKER: a new bcr_chain_states row was written — the advance was committed"
    );

    let phase = sender_handler.get_session_phase(&commitment).await;
    assert_ne!(
        phase,
        Some(BilateralPhase::Committed),
        "BLOCKER: the sender session reached Committed without a receiver acknowledgment"
    );

    assert_eq!(after, before, "no durable sender state may move at all");
}

/// POSITIVE CONTROL — proves the three durable probes are live.
///
/// The proof above asserts that nothing moved. That assertion is only worth anything if
/// `snapshot_sender()` would NOTICE movement. This performs a real committed advance
/// through the same durable writes the bilateral commit uses
/// (`update_bcr_device_head` + `store_bcr_chain_state`, the pair
/// `dual_write_advance_outcome_with_extra` commits in one transaction) and requires every
/// probe to change.
///
/// Without this, a snapshot that silently returned constants would make the proof pass
/// while detecting nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial]
async fn the_durable_probes_detect_a_real_commit() {
    let sender = tokio::task::block_in_place(funded_sender);
    let sender_devid = sender.devid;
    let head = client_db::load_bcr_device_head(&sender_devid)
        .expect("head query")
        .expect("the funded head is persisted");
    let before = snapshot_sender(&sender_devid);
    assert_eq!(before.era_balance, SENDER_ERA, "control precondition");

    // A real committed advance, persisted exactly as a committed advance persists.
    //
    // The probes do not care WHICH advance moved the state, only that a committed
    // one moves all three: head root, ERA balance, chain-state row. A debiting
    // transfer does that without issuing anything.
    let rel =
        dsm::core::bilateral_transaction_manager::compute_smt_key(&sender_devid, &sender_devid);
    let outcome = head
        .advance(
            rel,
            sender_devid,
            Operation::Transfer {
                to_device_id: [0xBBu8; 32].to_vec(),
                amount: Balance::from_state(7, [0u8; 32]),
                token_id: b"ERA".to_vec(),
                policy_commit: era_policy(),
                mode: dsm::types::operations::TransactionMode::Unilateral,
                nonce: vec![],
                verification: dsm::types::operations::VerificationType::Standard,
                pre_commit: None,
                recipient: vec![],
                to: vec![],
                message: "control".to_string(),
                signature: vec![],
                authority_policy: None,
            },
            vec![0x22; 32],
            None,
            &[BalanceDelta {
                policy_commit: era_policy(),
                direction: BalanceDirection::Debit,
                amount: 7,
            }],
            Some(initial_chain_tip_from_device_ids(
                &sender_devid,
                &sender_devid,
            )),
            None,
            None,
            None,
        )
        .expect("control advance");
    client_db::update_bcr_device_head(&outcome.new_device_state).expect("persist head");
    client_db::store_bcr_chain_state(&sender_devid, &outcome.new_chain_state, false)
        .expect("persist chain state");

    let after = snapshot_sender(&sender_devid);
    assert_ne!(
        after.head_root, before.head_root,
        "probe 1 is dead: a committed advance did not move the head root"
    );
    assert_eq!(
        after.era_balance,
        before.era_balance - 7,
        "probe 2 is dead: a committed advance did not move the balance"
    );
    assert_eq!(
        after.chain_state_rows,
        before.chain_state_rows + 1,
        "probe 3 is dead: a committed advance did not add a chain-state row"
    );
}
