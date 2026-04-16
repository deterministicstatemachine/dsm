// SPDX-License-Identifier: MIT OR Apache-2.0
//! BLE disconnect / reconnect robustness tests.
//!
//! Validates that:
//! 1. Early-phase sessions (Preparing, Prepared, PendingUserAction) are marked
//!    `Failed` immediately when the BLE link drops, unblocking the 120-second
//!    stale timer so the caller can retry without delay.
//! 2. Accepted / ConfirmPending sessions are also failed on disconnect so the
//!    next attempt restarts from prepare instead of resuming stale state.
//! 3. Multiple sequential back-and-forth transfers (prepare→accept→confirm cycles)
//!    succeed correctly, simulating repeated sender-receiver interactions.
//! 4. A dropped connection mid-prepare is transparent to the next transfer attempt.
#![allow(clippy::disallowed_methods)]

use std::sync::Arc;
use std::time::{Duration, Instant};

use dsm::core::bilateral_transaction_manager::BilateralTransactionManager;
use dsm::core::contact_manager::DsmContactManager;
use dsm::crypto::signatures::SignatureKeyPair;
use dsm::types::identifiers::NodeId;
use dsm::types::operations::{Operation, TransactionMode, VerificationType};
use dsm::types::token_types::Balance;
use dsm_sdk as sdk;
use sdk::bluetooth::bilateral_ble_handler::{BilateralBleHandler, BilateralPhase};
use sdk::bluetooth::bilateral_session::BilateralBleSession;
use sdk::handlers::bilateral_settlement::DefaultBilateralSettlementDelegate;
use sdk::storage::client_db;
use serial_test::serial;
use tokio::sync::RwLock;

fn dev(id: u8) -> [u8; 32] {
    [id; 32]
}

fn make_transfer_op(to: [u8; 32], nonce: u8) -> Operation {
    Operation::Transfer {
        to_device_id: to.to_vec(),
        amount: Balance::from_state(1, [1u8; 32]),
        token_id: b"ERA".to_vec(),
        mode: TransactionMode::Bilateral,
        nonce: vec![nonce],
        verification: VerificationType::Standard,
        pre_commit: None,
        recipient: to.to_vec(),
        to: to.to_vec(),
        message: format!("tx-{nonce}"),
        signature: Vec::new(),
    }
}

fn reset_db() {
    std::env::set_var("DSM_SDK_TEST_MODE", "1");
    let _ =
        dsm_sdk::storage_utils::set_storage_base_dir(std::path::PathBuf::from("./.dsm_testdata"));
    client_db::reset_database_for_tests();
    if let Err(e) = client_db::init_database() {
        eprintln!("[ble_disconnect_reconnect] init_database skipped: {e}");
    }
}

fn seed_bcr_genesis_with_era(device_id: [u8; 32], public_key: &[u8], era_balance: u64) {
    use dsm::types::state_builder::StateBuilder;
    use dsm::types::state_types::DeviceInfo;

    let policy_commit = *dsm_sdk::policy::builtins::NATIVE_POLICY_COMMIT;
    let balance_key =
        dsm::core::token::derive_canonical_balance_key(&policy_commit, public_key, "ERA");

    let mut balances = std::collections::HashMap::new();
    balances.insert(balance_key, Balance::from_state(era_balance, [0u8; 32]));

    let mut state = StateBuilder::new()
        .with_id("genesis".to_string())
        .with_state_number(0)
        .with_entropy(vec![0u8; 32])
        .with_prev_state_hash([0u8; 32])
        .with_operation(Operation::Generic {
            operation_type: b"genesis".to_vec(),
            data: vec![],
            message: String::new(),
            signature: vec![],
        })
        .with_device_info(DeviceInfo {
            device_id,
            public_key: public_key.to_vec(),
            metadata: Vec::new(),
        })
        .with_token_balances(balances)
        .build()
        .expect("genesis state should build");

    state.hash = state.compute_hash().expect("compute hash");
    client_db::store_bcr_state(&state, true).expect("seed BCR genesis");
}

/// Build a symmetric pair of handlers for two devices A and B,
/// with contacts and relationships established on both sides.
async fn make_handler_pair(
    a_dev: [u8; 32],
    a_gen: [u8; 32],
    b_dev: [u8; 32],
    b_gen: [u8; 32],
    a_kp: &SignatureKeyPair,
    b_kp: &SignatureKeyPair,
) -> (BilateralBleHandler, BilateralBleHandler) {
    let a_cm = DsmContactManager::new(a_dev, vec![NodeId::new("n")]);
    let b_cm = DsmContactManager::new(b_dev, vec![NodeId::new("n")]);
    let mut mgr_a = BilateralTransactionManager::new(a_cm, a_kp.clone(), a_dev, a_gen);
    let mut mgr_b = BilateralTransactionManager::new(b_cm, b_kp.clone(), b_dev, b_gen);

    let contact_b = dsm::types::contact_types::DsmVerifiedContact {
        alias: "B".to_string(),
        device_id: b_dev,
        genesis_hash: b_gen,
        public_key: b_kp.public_key().to_vec(),
        genesis_material: vec![0u8; 32],
        chain_tip: None,
        chain_tip_smt_proof: None,
        genesis_verified_online: true,
        verified_at_commit_height: 1,
        added_at_commit_height: 1,
        last_updated_commit_height: 1,
        verifying_storage_nodes: vec![],
        ble_address: Some("BB:BB:BB:BB:BB:BB".to_string()),
    };
    let contact_a = dsm::types::contact_types::DsmVerifiedContact {
        alias: "A".to_string(),
        device_id: a_dev,
        genesis_hash: a_gen,
        public_key: a_kp.public_key().to_vec(),
        genesis_material: vec![0u8; 32],
        chain_tip: None,
        chain_tip_smt_proof: None,
        genesis_verified_online: true,
        verified_at_commit_height: 1,
        added_at_commit_height: 1,
        last_updated_commit_height: 1,
        verifying_storage_nodes: vec![],
        ble_address: Some("AA:AA:AA:AA:AA:AA".to_string()),
    };

    mgr_a.add_verified_contact(contact_b).expect("add B to A");
    mgr_b.add_verified_contact(contact_a).expect("add A to B");
    let mut smt = dsm::merkle::sparse_merkle_tree::SparseMerkleTree::new(256);
    mgr_a
        .establish_relationship(&b_dev, &mut smt)
        .await
        .expect("A->B rel");
    mgr_b
        .establish_relationship(&a_dev, &mut smt)
        .await
        .expect("B->A rel");

    let delegate = Arc::new(DefaultBilateralSettlementDelegate);

    let a_arc = Arc::new(RwLock::new(mgr_a));
    let b_arc = Arc::new(RwLock::new(mgr_b));

    let mut handler_a = BilateralBleHandler::new(a_arc, a_dev);
    let mut handler_b = BilateralBleHandler::new(b_arc, b_dev);
    handler_a.set_settlement_delegate(delegate.clone());
    handler_b.set_settlement_delegate(delegate);

    (handler_a, handler_b)
}

// =============================================================================
// Test 1: handle_peer_disconnected fails early-phase sessions immediately
// =============================================================================
#[tokio::test]
#[serial]
async fn test_disconnect_fails_early_phase_sessions() {
    reset_db();

    let a_dev = dev(0xA1);
    let a_gen = dev(0xA2);
    let b_dev = dev(0xB1);
    let b_gen = dev(0xB2);
    let a_kp = SignatureKeyPair::generate_from_entropy(b"disconnect-test-a").expect("kp-a");
    let b_kp = SignatureKeyPair::generate_from_entropy(b"disconnect-test-b").expect("kp-b");

    let (handler_a, _handler_b) = make_handler_pair(a_dev, a_gen, b_dev, b_gen, &a_kp, &b_kp).await;

    // Simulate a sender-side session stuck in Preparing phase (ble link dropped
    // before the prepare envelope was delivered to the receiver).
    let fake_hash = [0xEEu8; 32];
    let session = BilateralBleSession {
        commitment_hash: fake_hash,
        local_commitment_hash: None,
        counterparty_device_id: b_dev,
        counterparty_genesis_hash: Some(b_gen),
        operation: Operation::Noop,
        phase: BilateralPhase::Preparing,
        local_signature: None,
        counterparty_signature: None,
        created_at_ticks: 1,
        expires_at_ticks: u64::MAX,
        sender_ble_address: Some("BB:BB:BB:BB:BB:BB".to_string()),
        created_at_wall: Instant::now(),
        pre_finalize_entropy: None,
        stitched_receipt_bytes: None,
    };
    handler_a.test_insert_session(session).await;

    // Verify session is in Preparing phase before disconnect
    let phase_before = handler_a.get_session_phase(&fake_hash).await;
    assert_eq!(phase_before, Some(BilateralPhase::Preparing));

    // Simulate BLE link drop from B's address
    let failed = handler_a
        .handle_peer_disconnected("BB:BB:BB:BB:BB:BB")
        .await;
    assert_eq!(failed, 1, "one early-phase session should be failed");

    // Session is failed and dropped from in-memory state, unblocking immediate retry.
    let phase_after = handler_a.get_session_phase(&fake_hash).await;
    assert_eq!(
        phase_after, None,
        "Preparing session must be removed from in-memory state after disconnect failure"
    );
}

// =============================================================================
// Test 2: handle_peer_disconnected fails all in-flight sessions, including
//         Accepted and ConfirmPending.
// =============================================================================
#[tokio::test]
#[serial]
async fn test_disconnect_fails_late_phase_sessions() {
    reset_db();

    let a_dev = dev(0xA3);
    let a_gen = dev(0xA4);
    let b_dev = dev(0xB3);
    let b_gen = dev(0xB4);
    let a_kp = SignatureKeyPair::generate_from_entropy(b"late-phase-a").expect("kp-a");
    let b_kp = SignatureKeyPair::generate_from_entropy(b"late-phase-b").expect("kp-b");

    let (handler_a, _handler_b) = make_handler_pair(a_dev, a_gen, b_dev, b_gen, &a_kp, &b_kp).await;

    // Insert an Accepted session (sender has receiver's signature, link dropped before confirm)
    let accepted_hash = [0xAAu8; 32];
    handler_a
        .test_insert_session(BilateralBleSession {
            commitment_hash: accepted_hash,
            local_commitment_hash: None,
            counterparty_device_id: b_dev,
            counterparty_genesis_hash: Some(b_gen),
            operation: Operation::Noop,
            phase: BilateralPhase::Accepted,
            local_signature: Some(vec![0x01; 64]),
            counterparty_signature: Some(vec![0x02; 64]),
            created_at_ticks: 1,
            expires_at_ticks: u64::MAX,
            sender_ble_address: Some("BB:BB:BB:BB:BB:BB".to_string()),
            created_at_wall: Instant::now(),
            pre_finalize_entropy: None,
            stitched_receipt_bytes: None,
        })
        .await;

    // Insert a ConfirmPending session (confirm sent but delivery not acknowledged)
    let confirm_hash = [0xCCu8; 32];
    handler_a
        .test_insert_session(BilateralBleSession {
            commitment_hash: confirm_hash,
            local_commitment_hash: None,
            counterparty_device_id: b_dev,
            counterparty_genesis_hash: Some(b_gen),
            operation: Operation::Noop,
            phase: BilateralPhase::ConfirmPending,
            local_signature: Some(vec![0x03; 64]),
            counterparty_signature: Some(vec![0x04; 64]),
            created_at_ticks: 2,
            expires_at_ticks: u64::MAX,
            sender_ble_address: Some("BB:BB:BB:BB:BB:BB".to_string()),
            created_at_wall: Instant::now(),
            pre_finalize_entropy: None,
            stitched_receipt_bytes: None,
        })
        .await;

    // Simulate disconnect
    let failed = handler_a
        .handle_peer_disconnected("BB:BB:BB:BB:BB:BB")
        .await;

    assert_eq!(
        failed, 2,
        "all in-flight sessions must be failed on disconnect"
    );

    // Both late-phase sessions must be failed and removed so the next attempt restarts cleanly.
    let accepted_phase = handler_a.get_session_phase(&accepted_hash).await;
    assert_eq!(
        accepted_phase, None,
        "Accepted session must be removed from in-memory state on disconnect"
    );

    let confirm_phase = handler_a.get_session_phase(&confirm_hash).await;
    assert_eq!(
        confirm_phase, None,
        "ConfirmPending session must be removed from in-memory state on disconnect"
    );
}

// =============================================================================
// Test 3: Disconnect + immediate retry (fresh session replaces Failed one)
// =============================================================================
#[tokio::test]
#[serial]
#[ignore = "requires a two-device test harness; current single-process shared SMT singleton breaks parent-proof verification"]
async fn test_disconnect_then_retry_succeeds() {
    reset_db();

    let a_dev = dev(0xA5);
    let a_gen = dev(0xA6);
    let b_dev = dev(0xB5);
    let b_gen = dev(0xB6);
    let a_kp = SignatureKeyPair::generate_from_entropy(b"retry-a").expect("kp-a");
    let b_kp = SignatureKeyPair::generate_from_entropy(b"retry-b").expect("kp-b");

    let (handler_a, handler_b) = make_handler_pair(a_dev, a_gen, b_dev, b_gen, &a_kp, &b_kp).await;

    sdk::sdk::app_state::AppState::set_identity_info(
        a_dev.to_vec(),
        a_kp.public_key().to_vec(),
        a_gen.to_vec(),
        vec![0u8; 32],
    );
    sdk::sdk::app_state::AppState::set_has_identity(true);

    // Seed sender ERA balance in the authoritative archive.
    seed_bcr_genesis_with_era(a_dev, a_kp.public_key(), 10_000);

    // --- Attempt 1: prepare then simulate disconnect before receiver responds ---
    let op1 = make_transfer_op(b_dev, 1);
    let (prepare1, commitment1) = handler_a
        .prepare_bilateral_transaction(b_dev, op1, 300)
        .await
        .expect("prepare attempt 1");
    assert!(!prepare1.is_empty());

    // Simulate link drop mid-prepare by directly inserting a Preparing-phase session
    // with the sender's BLE address set (the real session from prepare_bilateral_transaction
    // doesn't have the address field set on the sender side, so we insert a matching one).
    handler_a
        .test_insert_session(BilateralBleSession {
            commitment_hash: commitment1,
            local_commitment_hash: None,
            counterparty_device_id: b_dev,
            counterparty_genesis_hash: None,
            operation: Operation::Noop,
            phase: BilateralPhase::Preparing,
            local_signature: None,
            counterparty_signature: None,
            created_at_ticks: 1,
            expires_at_ticks: u64::MAX,
            sender_ble_address: Some("BB:BB:BB:BB:BB:BB".to_string()),
            created_at_wall: Instant::now(),
            pre_finalize_entropy: None,
            stitched_receipt_bytes: None,
        })
        .await;
    let failed1 = handler_a
        .handle_peer_disconnected("BB:BB:BB:BB:BB:BB")
        .await;
    assert_eq!(failed1, 1, "first session must be failed on disconnect");

    // --- Attempt 2: After disconnect the stale session is gone; retry immediately ---
    sdk::sdk::app_state::AppState::set_identity_info(
        a_dev.to_vec(),
        a_kp.public_key().to_vec(),
        a_gen.to_vec(),
        vec![0u8; 32],
    );

    let op2 = make_transfer_op(b_dev, 2);
    let (prepare2, commitment2) = handler_a
        .prepare_bilateral_transaction(b_dev, op2, 300)
        .await
        .expect("prepare attempt 2 — must succeed without 120s wait");

    // Receiver handles the second attempt
    handler_b
        .handle_prepare_request(&prepare2, None)
        .await
        .expect("receiver handles 2nd prepare");

    let accept2 = handler_b
        .create_prepare_accept_envelope(commitment2)
        .await
        .expect("accept 2nd");

    sdk::sdk::app_state::AppState::set_identity_info(
        a_dev.to_vec(),
        a_kp.public_key().to_vec(),
        a_gen.to_vec(),
        vec![0u8; 32],
    );
    let (confirm2, _) = handler_a
        .handle_prepare_response(&accept2)
        .await
        .expect("handle accept 2nd");

    sdk::sdk::app_state::AppState::set_identity_info(
        b_dev.to_vec(),
        b_kp.public_key().to_vec(),
        b_gen.to_vec(),
        vec![0u8; 32],
    );
    let ack2 = handler_b
        .handle_confirm_request(&confirm2)
        .await
        .expect("receiver confirms 2nd");

    handler_a
        .handle_commit_response(&ack2)
        .await
        .expect("sender handles 2nd ack");

    let sender_phase = handler_a.get_session_phase(&commitment2).await;
    assert_eq!(
        sender_phase,
        Some(BilateralPhase::Committed),
        "second transfer must commit successfully after first was dropped"
    );
}

// =============================================================================
// Test 4: Multiple sequential back-and-forth transfers (A→B repeated 3×)
// =============================================================================
struct TransferParticipant<'a> {
    handler: &'a BilateralBleHandler,
    dev: [u8; 32],
    gen: [u8; 32],
    pubkey: Vec<u8>,
}

async fn run_one_transfer(
    sender: &TransferParticipant<'_>,
    receiver: &TransferParticipant<'_>,
    nonce: u8,
) {
    sdk::sdk::app_state::AppState::set_identity_info(
        sender.dev.to_vec(),
        sender.pubkey.clone(),
        sender.gen.to_vec(),
        vec![0u8; 32],
    );
    sdk::sdk::app_state::AppState::set_has_identity(true);

    let op = make_transfer_op(receiver.dev, nonce);
    let (prep, commit) = sender
        .handler
        .prepare_bilateral_transaction(receiver.dev, op, 300)
        .await
        .unwrap_or_else(|e| panic!("prepare nonce={nonce}: {e}"));

    receiver
        .handler
        .handle_prepare_request(&prep, None)
        .await
        .unwrap_or_else(|e| panic!("recv prepare nonce={nonce}: {e}"));

    let accept = receiver
        .handler
        .create_prepare_accept_envelope(commit)
        .await
        .unwrap_or_else(|e| panic!("accept nonce={nonce}: {e}"));

    sdk::sdk::app_state::AppState::set_identity_info(
        sender.dev.to_vec(),
        sender.pubkey.clone(),
        sender.gen.to_vec(),
        vec![0u8; 32],
    );
    let (confirm, _) = sender
        .handler
        .handle_prepare_response(&accept)
        .await
        .unwrap_or_else(|e| panic!("handle_response nonce={nonce}: {e}"));

    sdk::sdk::app_state::AppState::set_identity_info(
        receiver.dev.to_vec(),
        receiver.pubkey.clone(),
        receiver.gen.to_vec(),
        vec![0u8; 32],
    );
    let ack = receiver
        .handler
        .handle_confirm_request(&confirm)
        .await
        .unwrap_or_else(|e| panic!("handle_confirm nonce={nonce}: {e}"));

    sender
        .handler
        .handle_commit_response(&ack)
        .await
        .unwrap_or_else(|e| panic!("handle_commit_response nonce={nonce}: {e}"));

    let phase = sender.handler.get_session_phase(&commit).await;
    assert_eq!(
        phase,
        Some(BilateralPhase::Committed),
        "transfer nonce={nonce} must be Committed"
    );
}

#[tokio::test]
#[serial]
#[ignore = "requires a two-device test harness; current single-process shared SMT singleton breaks parent-proof verification"]
async fn test_multiple_sequential_transfers() {
    reset_db();

    let a_dev = dev(0xA7);
    let a_gen = dev(0xA8);
    let b_dev = dev(0xB7);
    let b_gen = dev(0xB8);
    let a_kp = SignatureKeyPair::generate_from_entropy(b"multi-a").expect("kp-a");
    let b_kp = SignatureKeyPair::generate_from_entropy(b"multi-b").expect("kp-b");

    let (handler_a, handler_b) = make_handler_pair(a_dev, a_gen, b_dev, b_gen, &a_kp, &b_kp).await;

    // Seed both ERA balances in the authoritative archive.
    seed_bcr_genesis_with_era(a_dev, a_kp.public_key(), 50_000);
    seed_bcr_genesis_with_era(b_dev, b_kp.public_key(), 50_000);

    // Run 3 sequential A→B transfers with increasing nonces (simulating repeated
    // back-and-forth sessions on the same BLE connection without disconnect).
    let participant_a = TransferParticipant {
        handler: &handler_a,
        dev: a_dev,
        gen: a_gen,
        pubkey: a_kp.public_key().to_vec(),
    };
    let participant_b = TransferParticipant {
        handler: &handler_b,
        dev: b_dev,
        gen: b_gen,
        pubkey: b_kp.public_key().to_vec(),
    };
    for nonce in [10u8, 11, 12] {
        run_one_transfer(&participant_a, &participant_b, nonce).await;
    }
}

// =============================================================================
// Test 5: handle_peer_disconnected for unknown address is a no-op (no panic)
// =============================================================================
#[tokio::test]
#[serial]
async fn test_disconnect_unknown_address_is_noop() {
    reset_db();

    let a_dev = dev(0xA9);
    let a_gen = dev(0xAA);
    let b_dev = dev(0xB9);
    let b_gen = dev(0xBA);
    let a_kp = SignatureKeyPair::generate_from_entropy(b"noop-a").expect("kp-a");
    let b_kp = SignatureKeyPair::generate_from_entropy(b"noop-b").expect("kp-b");

    let (handler_a, _) = make_handler_pair(a_dev, a_gen, b_dev, b_gen, &a_kp, &b_kp).await;

    // No sessions at all — should not panic
    let failed = handler_a
        .handle_peer_disconnected("FF:FF:FF:FF:FF:FF")
        .await;
    assert_eq!(failed, 0);
}

// =============================================================================
// Test 6: PendingUserAction sessions are failed on disconnect
//         (receiver had a pending modal that will never resolve because sender left)
// =============================================================================
#[tokio::test]
#[serial]
async fn test_disconnect_fails_pending_user_action_sessions() {
    reset_db();

    let a_dev = dev(0xAB);
    let a_gen = dev(0xAC);
    let b_dev = dev(0xBB);
    let b_gen = dev(0xBC);
    let a_kp = SignatureKeyPair::generate_from_entropy(b"pua-a").expect("kp-a");
    let b_kp = SignatureKeyPair::generate_from_entropy(b"pua-b").expect("kp-b");

    let (_handler_a, handler_b) = make_handler_pair(a_dev, a_gen, b_dev, b_gen, &a_kp, &b_kp).await;

    // Simulate a receiver-side session stuck in PendingUserAction
    let pua_hash = [0xFFu8; 32];
    handler_b
        .test_insert_session(BilateralBleSession {
            commitment_hash: pua_hash,
            local_commitment_hash: Some([0xFEu8; 32]),
            counterparty_device_id: a_dev,
            counterparty_genesis_hash: Some(a_gen),
            operation: Operation::Noop,
            phase: BilateralPhase::PendingUserAction,
            local_signature: None,
            counterparty_signature: None,
            created_at_ticks: 1,
            expires_at_ticks: u64::MAX,
            sender_ble_address: Some("AA:AA:AA:AA:AA:AA".to_string()),
            created_at_wall: Instant::now(),
            pre_finalize_entropy: None,
            stitched_receipt_bytes: None,
        })
        .await;

    // Sender (A) disconnects
    let failed = handler_b
        .handle_peer_disconnected("AA:AA:AA:AA:AA:AA")
        .await;
    assert_eq!(failed, 1, "PendingUserAction must be failed on disconnect");

    let phase = handler_b.get_session_phase(&pua_hash).await;
    assert_eq!(
        phase, None,
        "PendingUserAction must be removed from in-memory state after sender disconnects"
    );
}

// =============================================================================
// Test 7: Prepared-phase session is failed on disconnect
// =============================================================================
#[tokio::test]
#[serial]
async fn test_disconnect_fails_prepared_phase_sessions() {
    reset_db();

    let a_dev = dev(0xAD);
    let a_gen = dev(0xAE);
    let b_dev = dev(0xBD);
    let b_gen = dev(0xBE);
    let a_kp = SignatureKeyPair::generate_from_entropy(b"prepared-a").expect("kp-a");
    let b_kp = SignatureKeyPair::generate_from_entropy(b"prepared-b").expect("kp-b");

    let (handler_a, _handler_b) = make_handler_pair(a_dev, a_gen, b_dev, b_gen, &a_kp, &b_kp).await;

    // Simulate a sender-side session in the Prepared phase (prepare sent, awaiting response)
    let prepared_hash = [0xDDu8; 32];
    handler_a
        .test_insert_session(BilateralBleSession {
            commitment_hash: prepared_hash,
            local_commitment_hash: None,
            counterparty_device_id: b_dev,
            counterparty_genesis_hash: Some(b_gen),
            operation: Operation::Noop,
            phase: BilateralPhase::Prepared,
            local_signature: Some(vec![0x01; 64]),
            counterparty_signature: None,
            created_at_ticks: 1,
            expires_at_ticks: u64::MAX,
            sender_ble_address: Some("BB:BB:BB:BB:BB:BB".to_string()),
            created_at_wall: Instant::now(),
            pre_finalize_entropy: None,
            stitched_receipt_bytes: None,
        })
        .await;

    let failed = handler_a
        .handle_peer_disconnected("BB:BB:BB:BB:BB:BB")
        .await;
    assert_eq!(failed, 1, "Prepared session must be failed on disconnect");

    let phase = handler_a.get_session_phase(&prepared_hash).await;
    assert_eq!(
        phase, None,
        "Prepared session must be removed from in-memory state after disconnect failure"
    );
}

// =============================================================================
// Test 8: Stale session (> 120 s) is immediately superseded on next prepare
//         without waiting for a disconnect notification.
// =============================================================================
#[tokio::test]
#[serial]
async fn test_stale_session_superseded_on_prepare() {
    reset_db();

    let a_dev = dev(0xB0);
    let a_gen = dev(0xB1);
    let b_dev = dev(0xC0);
    let b_gen = dev(0xC1);
    let a_kp = SignatureKeyPair::generate_from_entropy(b"stale-a").expect("kp-a");
    let b_kp = SignatureKeyPair::generate_from_entropy(b"stale-b").expect("kp-b");

    let (handler_a, _handler_b) = make_handler_pair(a_dev, a_gen, b_dev, b_gen, &a_kp, &b_kp).await;

    // Insert a stale in-flight session (created 130 s ago)
    let stale_hash = [0x55u8; 32];
    handler_a
        .test_insert_session(BilateralBleSession {
            commitment_hash: stale_hash,
            local_commitment_hash: None,
            counterparty_device_id: b_dev,
            counterparty_genesis_hash: Some(b_gen),
            operation: Operation::Noop,
            phase: BilateralPhase::Prepared,
            local_signature: None,
            counterparty_signature: None,
            created_at_ticks: 1,
            expires_at_ticks: u64::MAX,
            sender_ble_address: None,
            created_at_wall: Instant::now() - Duration::from_secs(130),
            pre_finalize_entropy: None,
            stitched_receipt_bytes: None,
        })
        .await;

    sdk::sdk::app_state::AppState::set_identity_info(
        a_dev.to_vec(),
        a_kp.public_key().to_vec(),
        a_gen.to_vec(),
        vec![0u8; 32],
    );
    sdk::sdk::app_state::AppState::set_has_identity(true);
    seed_bcr_genesis_with_era(a_dev, a_kp.public_key(), 10_000);

    // A fresh prepare must supersede the stale session immediately
    let op = make_transfer_op(b_dev, 99);
    let (_prep, fresh_commitment) = handler_a
        .prepare_bilateral_transaction(b_dev, op, 300)
        .await
        .expect("fresh prepare must supersede stale session");

    // Stale session must be gone
    let stale_phase = handler_a.get_session_phase(&stale_hash).await;
    assert!(
        stale_phase.is_none() || stale_phase == Some(BilateralPhase::Failed),
        "stale session must be removed or Failed; got {stale_phase:?}"
    );

    // Fresh session must exist in an in-flight phase
    let fresh_phase = handler_a.get_session_phase(&fresh_commitment).await;
    assert!(
        fresh_phase.is_some(),
        "fresh session must exist after superseding stale one"
    );
    assert_ne!(
        fresh_phase,
        Some(BilateralPhase::Failed),
        "fresh session must not be in Failed phase"
    );
}
