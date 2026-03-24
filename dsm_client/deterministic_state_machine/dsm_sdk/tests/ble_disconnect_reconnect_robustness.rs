// SPDX-License-Identifier: MIT OR Apache-2.0
//! BLE disconnect / reconnect robustness tests.
//!
//! Validates that:
//! 1. Early-phase sessions (Preparing, Prepared, PendingUserAction) are marked
//!    `Failed` immediately when the BLE link drops, unblocking the 120-second
//!    stale timer so the caller can retry without delay.
//! 2. Late-phase sessions (Accepted, ConfirmPending) are preserved on disconnect
//!    so they can be finalized once reconnected.
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
        amount: Balance::from_state(1, [1u8; 32], 0),
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
    mgr_a
        .establish_relationship(&b_dev)
        .await
        .expect("A->B rel");
    mgr_b
        .establish_relationship(&a_dev)
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

    // Session must now be in Failed state, unblocking immediate retry
    let phase_after = handler_a.get_session_phase(&fake_hash).await;
    assert_eq!(
        phase_after,
        Some(BilateralPhase::Failed),
        "Preparing session must be Failed after disconnect"
    );
}

// =============================================================================
// Test 2: handle_peer_disconnected preserves late-phase sessions (Accepted,
//         ConfirmPending) — they carry all crypto material for recovery.
// =============================================================================
#[tokio::test]
#[serial]
async fn test_disconnect_preserves_late_phase_sessions() {
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
        })
        .await;

    // Simulate disconnect
    let failed = handler_a
        .handle_peer_disconnected("BB:BB:BB:BB:BB:BB")
        .await;

    // No late-phase sessions should have been failed
    assert_eq!(
        failed, 0,
        "late-phase sessions must not be failed on disconnect"
    );

    // Both late-phase sessions must remain intact with their original phases
    let accepted_phase = handler_a.get_session_phase(&accepted_hash).await;
    assert_eq!(
        accepted_phase,
        Some(BilateralPhase::Accepted),
        "Accepted session must survive disconnect"
    );

    let confirm_phase = handler_a.get_session_phase(&confirm_hash).await;
    assert_eq!(
        confirm_phase,
        Some(BilateralPhase::ConfirmPending),
        "ConfirmPending session must survive disconnect"
    );
}

// =============================================================================
// Test 3: Disconnect + immediate retry (fresh session replaces Failed one)
// =============================================================================
#[tokio::test]
#[serial]
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

    // Seed sender wallet
    let a_txt = sdk::util::text_id::encode_base32_crockford(&a_dev);
    client_db::update_wallet_balance(&a_txt, 10_000).expect("seed wallet");

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
        .handle_prepare_request(&prepare2)
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
    handler_b
        .handle_confirm_request(&confirm2)
        .await
        .expect("receiver confirms 2nd");

    // Mark confirm delivered on sender side
    handler_a
        .mark_confirm_delivered(commitment2)
        .await
        .expect("mark delivered");

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
#[allow(clippy::too_many_arguments)]
async fn run_one_transfer(
    sender: &BilateralBleHandler,
    receiver: &BilateralBleHandler,
    sender_dev: [u8; 32],
    sender_gen: [u8; 32],
    sender_pub: Vec<u8>,
    receiver_dev: [u8; 32],
    receiver_gen: [u8; 32],
    receiver_pub: Vec<u8>,
    nonce: u8,
) {
    sdk::sdk::app_state::AppState::set_identity_info(
        sender_dev.to_vec(),
        sender_pub.clone(),
        sender_gen.to_vec(),
        vec![0u8; 32],
    );
    sdk::sdk::app_state::AppState::set_has_identity(true);

    let op = make_transfer_op(receiver_dev, nonce);
    let (prep, commit) = sender
        .prepare_bilateral_transaction(receiver_dev, op, 300)
        .await
        .unwrap_or_else(|e| panic!("prepare nonce={nonce}: {e}"));

    receiver
        .handle_prepare_request(&prep)
        .await
        .unwrap_or_else(|e| panic!("recv prepare nonce={nonce}: {e}"));

    let accept = receiver
        .create_prepare_accept_envelope(commit)
        .await
        .unwrap_or_else(|e| panic!("accept nonce={nonce}: {e}"));

    sdk::sdk::app_state::AppState::set_identity_info(
        sender_dev.to_vec(),
        sender_pub,
        sender_gen.to_vec(),
        vec![0u8; 32],
    );
    let (confirm, _) = sender
        .handle_prepare_response(&accept)
        .await
        .unwrap_or_else(|e| panic!("handle_response nonce={nonce}: {e}"));

    sdk::sdk::app_state::AppState::set_identity_info(
        receiver_dev.to_vec(),
        receiver_pub,
        receiver_gen.to_vec(),
        vec![0u8; 32],
    );
    receiver
        .handle_confirm_request(&confirm)
        .await
        .unwrap_or_else(|e| panic!("handle_confirm nonce={nonce}: {e}"));

    sender
        .mark_confirm_delivered(commit)
        .await
        .unwrap_or_else(|e| panic!("mark_delivered nonce={nonce}: {e}"));

    let phase = sender.get_session_phase(&commit).await;
    assert_eq!(
        phase,
        Some(BilateralPhase::Committed),
        "transfer nonce={nonce} must be Committed"
    );
}

#[tokio::test]
#[serial]
async fn test_multiple_sequential_transfers() {
    reset_db();

    let a_dev = dev(0xA7);
    let a_gen = dev(0xA8);
    let b_dev = dev(0xB7);
    let b_gen = dev(0xB8);
    let a_kp = SignatureKeyPair::generate_from_entropy(b"multi-a").expect("kp-a");
    let b_kp = SignatureKeyPair::generate_from_entropy(b"multi-b").expect("kp-b");

    let (handler_a, handler_b) = make_handler_pair(a_dev, a_gen, b_dev, b_gen, &a_kp, &b_kp).await;

    // Seed both wallets
    let a_txt = sdk::util::text_id::encode_base32_crockford(&a_dev);
    let b_txt = sdk::util::text_id::encode_base32_crockford(&b_dev);
    client_db::update_wallet_balance(&a_txt, 50_000).expect("seed A");
    client_db::update_wallet_balance(&b_txt, 50_000).expect("seed B");

    // Run 3 sequential A→B transfers with increasing nonces (simulating repeated
    // back-and-forth sessions on the same BLE connection without disconnect).
    for nonce in [10u8, 11, 12] {
        run_one_transfer(
            &handler_a,
            &handler_b,
            a_dev,
            a_gen,
            a_kp.public_key().to_vec(),
            b_dev,
            b_gen,
            b_kp.public_key().to_vec(),
            nonce,
        )
        .await;
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
        })
        .await;

    // Sender (A) disconnects
    let failed = handler_b
        .handle_peer_disconnected("AA:AA:AA:AA:AA:AA")
        .await;
    assert_eq!(failed, 1, "PendingUserAction must be failed on disconnect");

    let phase = handler_b.get_session_phase(&pua_hash).await;
    assert_eq!(
        phase,
        Some(BilateralPhase::Failed),
        "PendingUserAction must be Failed after sender disconnects"
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
        })
        .await;

    let failed = handler_a
        .handle_peer_disconnected("BB:BB:BB:BB:BB:BB")
        .await;
    assert_eq!(failed, 1, "Prepared session must be failed on disconnect");

    let phase = handler_a.get_session_phase(&prepared_hash).await;
    assert_eq!(
        phase,
        Some(BilateralPhase::Failed),
        "Prepared session must be Failed after disconnect"
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
        })
        .await;

    sdk::sdk::app_state::AppState::set_identity_info(
        a_dev.to_vec(),
        a_kp.public_key().to_vec(),
        a_gen.to_vec(),
        vec![0u8; 32],
    );
    sdk::sdk::app_state::AppState::set_has_identity(true);
    let a_txt = sdk::util::text_id::encode_base32_crockford(&a_dev);
    client_db::update_wallet_balance(&a_txt, 10_000).expect("seed wallet");

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
