// SPDX-License-Identifier: MIT OR Apache-2.0
//! REACHABILITY PROOF for the `MissingRelease` sender-debit path (issue #639).
//!
//! When offline-bearer staging fails, `bilateral_ble_handler.rs:3613-3620` logs and sets
//! `staged_bearer = None`. `offline_spend` then stays `None`, so the branch at `:3656`
//! does NOT clear `sender_deltas` — the sender proceeds carrying an ordinary online
//! `Debit`. The receiver, for a bearer-required operation, then rejects with
//! `OfflineRecover::MissingRelease` (`anchor_accept.rs:262-264`).
//!
//! The question this test answers is NOT whether that `Debit` exists on the in-flight
//! object — it does, and that is fine. It is whether the `Debit` can cross into
//! AUTHORITATIVE state while the receiver credits nothing. So every assertion reads
//! DURABLE state back out of the database, never the prepared object.
//!
//! WHY THIS IS AN INTEGRATION TEST, NOT A UNIT TEST. `tests/` compiles the crate WITHOUT
//! `cfg(test)`, so `core_sdk.rs:2528`'s `#[cfg(not(test))] hardware_appliance_or_fail`
//! applies and returns `Err(OFFLINE_BEARER_NO_APPLIANCE_MSG)` unconditionally. Staging
//! therefore fails BY CONSTRUCTION with no anchor factory installed — hermetic, and with
//! no process-global factory to leak into neighbouring tests. Inside `cfg(test)` the
//! `#[cfg(test)]` arm returns a working in-process mock and staging would SUCCEED, so the
//! same test written as a unit test would silently exercise nothing.

#![allow(clippy::disallowed_methods)]

use std::sync::Arc;

use serial_test::serial;
use tokio::sync::RwLock;

use dsm::core::bilateral_transaction_manager::{
    initial_chain_tip_from_device_ids, BilateralTransactionManager,
};
use dsm::core::contact_manager::DsmContactManager;
use dsm::crypto::signatures::SignatureKeyPair;
use dsm::types::device_state::{BalanceDelta, BalanceDirection, DeviceState};
use dsm::types::identifiers::NodeId;
use dsm::types::operations::{canonical_offline_bearer_policy, Operation, TransactionMode};
use dsm::types::token_types::Balance;

use dsm_sdk::bluetooth::bilateral_ble_handler::{BilateralBleHandler, BilateralPhase};
use dsm_sdk::storage::client_db;

const SENDER: [u8; 32] = [0xA1; 32];
const RECEIVER: [u8; 32] = [0xB2; 32];
const GENESIS: [u8; 32] = [0xC3; 32];
const SEED_ERA: u64 = 500;
const SEND_AMOUNT: u64 = 100;

fn era_policy() -> [u8; 32] {
    dsm::core::token::builtin_policy_commit_for_token("ERA").expect("ERA policy commit")
}

fn keypair(seed: u8) -> SignatureKeyPair {
    SignatureKeyPair::generate_from_entropy(&[seed; 32]).expect("keypair")
}

/// Everything global this test touches, reset so a neighbouring test cannot pre-seed it.
fn install_identity(device_id: [u8; 32], public_key: Vec<u8>) {
    unsafe {
        std::env::set_var("DSM_SDK_TEST_MODE", "1");
        std::env::remove_var("DSM_ENV_CONFIG_PATH");
    }
    let _ = dsm_sdk::storage_utils::set_storage_base_dir(std::path::PathBuf::from(
        "./.dsm_testdata_missing_release",
    ));
    // The router builds a WalletSDK, which refuses to construct against a locked wallet.
    dsm_sdk::set_wallet_seed_for_testing(vec![0x5E; 32]);
    dsm_sdk::sdk::app_state::AppState::set_identity_info(
        device_id.to_vec(),
        public_key,
        GENESIS.to_vec(),
        vec![0u8; 32],
    );
    dsm_sdk::sdk::app_state::AppState::set_has_identity(true);
}

/// Seed the sender's CANONICAL head with spendable ERA via a self-mint advance, and
/// persist it. The head — not the SQL projection — is what
/// `simulate_advance_for_confirm` debits, so seeding only `balance_projections` would
/// leave the sender with nothing to debit and the test would pass vacuously.
fn seed_sender_head_with_era() -> DeviceState {
    let kp = keypair(0xA1);
    let base = DeviceState::new(GENESIS, SENDER, kp.public_key.clone(), 1024);
    let rel = dsm::core::bilateral_transaction_manager::compute_smt_key(&SENDER, &SENDER);
    let head = base
        .advance(
            rel,
            SENDER,
            Operation::Mint {
                amount: Balance::from_state(SEED_ERA, [0u8; 32]),
                token_id: b"ERA".to_vec(),
                policy_commit: era_policy(),
                authorized_by: b"self".to_vec(),
                proof_of_authorization: Vec::new(),
                message: "seed".to_string(),
            },
            vec![0x11; 32],
            None,
            &[BalanceDelta {
                policy_commit: era_policy(),
                direction: BalanceDirection::Credit,
                amount: SEED_ERA,
            }],
            Some(initial_chain_tip_from_device_ids(&SENDER, &SENDER)),
            None,
            None,
            None,
        )
        .expect("seed mint advance")
        .new_device_state;
    client_db::update_bcr_device_head(&head).expect("persist seeded head");
    head
}

/// Persist the counterparty as a client_db contact WITH a Kyber public key.
///
/// Per-step EK signing (§11) encapsulates against the counterparty's ML-KEM-768 key when
/// building the receipt, and refuses a contact that has none. Without this the flow dies
/// at `handle_prepare_response` long before staging, and the test would prove nothing.
fn store_contact_with_kyber(device: [u8; 32], signing_pk: Vec<u8>, alias: &str) {
    let kyber = dsm::crypto::kyber::generate_kyber_keypair().expect("kyber keypair");
    client_db::store_contact(&client_db::ContactRecord {
        contact_id: alias.to_string(),
        device_id: device.to_vec(),
        alias: alias.to_string(),
        genesis_hash: GENESIS.to_vec(),
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
    counterparty: [u8; 32],
    kp: SignatureKeyPair,
    counterparty_pk: Vec<u8>,
) -> BilateralBleHandler {
    let mut contacts = DsmContactManager::new(device, vec![NodeId::new("local")]);
    contacts
        .add_verified_contact(dsm::types::contact_types::DsmVerifiedContact {
            alias: "peer".to_string(),
            device_id: counterparty,
            genesis_hash: GENESIS,
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

    let mgr = BilateralTransactionManager::new(contacts, kp, device, GENESIS);
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

fn snapshot_sender() -> DurableSenderState {
    let head = client_db::load_bcr_device_head(&SENDER)
        .expect("head query must not error")
        .expect("the sender head MUST exist — without it every assertion is vacuous");
    DurableSenderState {
        head_root: head.root(),
        era_balance: head.balance(&era_policy()),
        chain_state_rows: client_db::get_bcr_chain_states(&SENDER, false)
            .expect("chain-state query")
            .len(),
    }
}

/// THE PROOF.
///
/// Staging fails, the receiver rejects `MissingRelease`, and NOTHING the sender owns
/// moves: same head root, same balance, no new chain-state row, session never committed.
#[tokio::test]
#[serial]
async fn missing_release_leaves_no_sender_debit_in_authoritative_state() {
    let sender_kp = keypair(0xA1);
    let receiver_kp = keypair(0xB2);

    client_db::reset_database_for_tests();
    install_identity(SENDER, sender_kp.public_key.clone());
    client_db::init_database().expect("init db");

    // Head first: CoreSDK reads it once at construction, so it must exist before the
    // router is built.
    let seeded = seed_sender_head_with_era();
    assert_eq!(
        seeded.balance(&era_policy()),
        SEED_ERA,
        "precondition: the sender actually holds spendable ERA, so a debit is possible"
    );

    let router = dsm_sdk::handlers::app_router_impl::AppRouterImpl::new(dsm_sdk::init::SdkConfig {
        node_id: "missing-release-reachability".to_string(),
        storage_endpoints: vec![],
        enable_offline: true,
    })
    .expect("router init");
    dsm_sdk::bridge::install_app_router(Arc::new(router)).expect("install app_router");

    let sender = handler_for(
        SENDER,
        RECEIVER,
        keypair(0xA1),
        receiver_kp.public_key.clone(),
    );
    let receiver = handler_for(
        RECEIVER,
        SENDER,
        keypair(0xB2),
        sender_kp.public_key.clone(),
    );

    store_contact_with_kyber(RECEIVER, receiver_kp.public_key.clone(), "receiver");
    store_contact_with_kyber(SENDER, sender_kp.public_key.clone(), "sender");

    let before = snapshot_sender();
    assert_eq!(before.era_balance, SEED_ERA);

    // --- 3-step bilateral, driven directly (the BLE transport is not what is on trial) ---
    let (prepare_bytes, commitment) = sender
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
        SENDER.to_vec(),
        sender_kp.public_key.clone(),
        GENESIS.to_vec(),
        vec![0u8; 32],
    );
    // Absorbing the accept IS what builds the confirm (it drives send_bilateral_confirm
    // internally). Staging fails inside it — no anchor appliance, and `tests/` compiles the
    // crate without cfg(test) — so the ordinary online Debit survives onto the prepared
    // object and the offline release rides EMPTY.
    let (confirm_bytes, _) = sender
        .handle_prepare_response(&accept_bytes)
        .await
        .expect("confirm builds even though staging failed");

    // --- the receiver refuses ---
    dsm_sdk::sdk::app_state::AppState::set_identity_info(
        RECEIVER.to_vec(),
        receiver_kp.public_key.clone(),
        GENESIS.to_vec(),
        vec![0u8; 32],
    );
    let verdict = receiver.handle_confirm_request(&confirm_bytes).await;
    let err = verdict.expect_err("a bearer-required op with an empty release MUST be refused");
    let msg = format!("{err}");
    // EXACT denial, not a family of them. `OfflineRecover::into_dsm_error` renders
    // "offline transfer rejected (recover online): {variant:?}", so this pins the variant
    // to MissingRelease specifically. A loose match here would let the test pass on
    // AnchorNotEnrolled, Malformed, or a Predicate rejection — none of which exercise the
    // path where a Debit was built and then stranded.
    assert!(
        msg.contains("MissingRelease"),
        "the refusal must be MissingRelease specifically — the release rode EMPTY because \
         staging failed. Any other variant means the test never reached the stranded-debit \
         path. Got: {msg}"
    );

    // --- THE FOUR ASSERTIONS, all on durable state ---
    let after = snapshot_sender();

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

    let phase = sender.get_session_phase(&commitment).await;
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
#[tokio::test]
#[serial]
async fn the_durable_probes_detect_a_real_commit() {
    let sender_kp = keypair(0xA1);
    client_db::reset_database_for_tests();
    install_identity(SENDER, sender_kp.public_key.clone());
    client_db::init_database().expect("init db");

    let head = seed_sender_head_with_era();
    let before = snapshot_sender();
    assert_eq!(before.era_balance, SEED_ERA, "control precondition");

    // A second self-mint, persisted exactly as a committed advance persists.
    let rel = dsm::core::bilateral_transaction_manager::compute_smt_key(&SENDER, &SENDER);
    let outcome = head
        .advance(
            rel,
            SENDER,
            Operation::Mint {
                amount: Balance::from_state(7, [0u8; 32]),
                token_id: b"ERA".to_vec(),
                policy_commit: era_policy(),
                authorized_by: b"self".to_vec(),
                proof_of_authorization: Vec::new(),
                message: "control".to_string(),
            },
            vec![0x22; 32],
            None,
            &[BalanceDelta {
                policy_commit: era_policy(),
                direction: BalanceDirection::Credit,
                amount: 7,
            }],
            Some(initial_chain_tip_from_device_ids(&SENDER, &SENDER)),
            None,
            None,
            None,
        )
        .expect("control advance");
    client_db::update_bcr_device_head(&outcome.new_device_state).expect("persist head");
    client_db::store_bcr_chain_state(&SENDER, &outcome.new_chain_state, false)
        .expect("persist chain state");

    let after = snapshot_sender();
    assert_ne!(
        after.head_root, before.head_root,
        "probe 1 is dead: a committed advance did not move the head root"
    );
    assert_eq!(
        after.era_balance,
        before.era_balance + 7,
        "probe 2 is dead: a committed advance did not move the balance"
    );
    assert_eq!(
        after.chain_state_rows,
        before.chain_state_rows + 1,
        "probe 3 is dead: a committed advance did not add a chain-state row"
    );
}
