// SPDX-License-Identifier: MIT OR Apache-2.0
// Bilateral Event Guarantee Test
// Ensures that the Offline Transaction flow emits the critical JNI events that the Frontend relies on.
// If this test fails, the UI will likely hang indefinitely.

#![allow(clippy::disallowed_methods)]

use std::sync::{Arc, Mutex};
use tokio::sync::RwLock;

use dsm_sdk::storage::client_db;
use dsm_sdk::sdk::storage_node_sdk::{StorageNodeConfig, StorageNodeSDK};
use dsm_sdk::bluetooth::bilateral_ble_handler::BilateralBleHandler;
use dsm_sdk::bluetooth::ble_frame_coordinator::{BleFrameCoordinator, BleFrameType};
use dsm_sdk::storage_utils;
use dsm_sdk::generated;
use prost::Message;

use dsm::core::bilateral_transaction_manager::BilateralTransactionManager;
use dsm::core::contact_manager::DsmContactManager;
use dsm::crypto::signatures::SignatureKeyPair;
use dsm::types::identifiers::NodeId;
use dsm::types::operations::{Operation, TransactionMode, VerificationType};
use dsm::types::token_types::Balance;

fn bytes32(v: Vec<u8>) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&v[..32]);
    out
}

fn configure_local_identity_for_receipts(
    device_id: [u8; 32],
    genesis_hash: [u8; 32],
    public_key: Vec<u8>,
) {
    dsm_sdk::sdk::app_state::AppState::set_identity_info(
        device_id.to_vec(),
        public_key,
        genesis_hash.to_vec(),
        vec![0u8; 32],
    );
    dsm_sdk::sdk::app_state::AppState::set_has_identity(true);

    let stored_root = dsm_sdk::sdk::app_state::AppState::get_device_tree_root()
        .expect("device_tree_root must be derived from local identity");
    let expected_root = dsm::common::device_tree::DeviceTree::single(device_id).root();
    assert_eq!(
        stored_root.as_slice(),
        expected_root.as_slice(),
        "AppState must contain the canonical single-device R_G"
    );
    assert_eq!(
        dsm_sdk::sdk::app_state::AppState::get_genesis_hash(),
        Some(genesis_hash.to_vec()),
        "AppState must expose the local genesis hash for receipt construction"
    );
}

#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn verify_frontend_event_guarantees() {
    println!("[EVENT-TEST] Init storage + MPC genesis");
    std::env::set_var("DSM_SDK_TEST_MODE", "1");

    // Point at real AWS storage nodes (6 nodes across 3 regions) instead of
    // falling through to the hardcoded localhost:8080 fallback.
    let config_path = format!(
        "{}/../../new_frontend/public/dsm_env_config.toml",
        env!("CARGO_MANIFEST_DIR")
    );
    std::env::set_var("DSM_ENV_CONFIG_PATH", &config_path);

    let temp_dir = std::env::temp_dir().join("dsm_bilateral_event_guarantee");
    if temp_dir.exists() {
        let _ = std::fs::remove_dir_all(&temp_dir);
    }
    std::fs::create_dir_all(&temp_dir).expect("temp dir");
    storage_utils::set_storage_base_dir(temp_dir).expect("set storage dir");

    if let Err(e) = client_db::init_database() {
        eprintln!("[bilateral_event_guarantee] init_database skipped (already init): {e}");
    }

    let storage_config = StorageNodeConfig::from_env_config()
        .await
        .expect("storage config (env required)");
    let storage_sdk = StorageNodeSDK::new(storage_config)
        .await
        .expect("StorageNodeSDK init failed");

    // Alice & Bob Genesis
    let mut alice_entropy = vec![10u8; 32];
    getrandom::getrandom(&mut alice_entropy).expect("entropy a");
    let alice_genesis = storage_sdk
        .create_genesis_with_mpc(Some(3), Some(alice_entropy))
        .await
        .expect("alice MPC genesis");

    let mut bob_entropy = vec![11u8; 32];
    getrandom::getrandom(&mut bob_entropy).expect("entropy b");
    let bob_genesis = storage_sdk
        .create_genesis_with_mpc(Some(3), Some(bob_entropy))
        .await
        .expect("bob MPC genesis");

    let alice_dev_id = bytes32(alice_genesis.genesis_device_id);
    let bob_dev_id = bytes32(bob_genesis.genesis_device_id);
    let alice_gen_hash = bytes32(alice_genesis.genesis_hash.expect("alice genesis_hash"));
    let bob_gen_hash = bytes32(bob_genesis.genesis_hash.expect("bob genesis_hash"));

    let alice_kp = SignatureKeyPair::generate_from_entropy(b"event-test-a").expect("kp a");
    let bob_kp = SignatureKeyPair::generate_from_entropy(b"event-test-b").expect("kp b");

    // Managers
    let mut alice_mgr = BilateralTransactionManager::new(
        DsmContactManager::new(alice_dev_id, vec![NodeId::new("n")]),
        alice_kp.clone(),
        alice_dev_id,
        alice_gen_hash,
    );
    let mut bob_mgr = BilateralTransactionManager::new(
        DsmContactManager::new(bob_dev_id, vec![NodeId::new("n")]),
        bob_kp.clone(),
        bob_dev_id,
        bob_gen_hash,
    );

    // Friend them
    alice_mgr
        .add_verified_contact(dsm::types::contact_types::DsmVerifiedContact {
            alias: "Bob".to_string(),
            device_id: bob_dev_id,
            genesis_hash: bob_gen_hash,
            public_key: bob_kp.public_key().to_vec(),
            genesis_material: vec![0u8; 32],
            chain_tip: None,
            chain_tip_smt_proof: None,
            genesis_verified_online: true,
            verified_at_commit_height: 1,
            added_at_commit_height: 1,
            last_updated_commit_height: 1,
            verifying_storage_nodes: vec![],
            ble_address: Some("AA:BB:CC:DD:EE:FF".to_string()),
        })
        .unwrap();

    bob_mgr
        .add_verified_contact(dsm::types::contact_types::DsmVerifiedContact {
            alias: "Alice".to_string(),
            device_id: alice_dev_id,
            genesis_hash: alice_gen_hash,
            public_key: alice_kp.public_key().to_vec(),
            genesis_material: vec![0u8; 32],
            chain_tip: None,
            chain_tip_smt_proof: None,
            genesis_verified_online: true,
            verified_at_commit_height: 1,
            added_at_commit_height: 1,
            last_updated_commit_height: 1,
            verifying_storage_nodes: vec![],
            ble_address: Some("11:22:33:44:55:66".to_string()),
        })
        .unwrap();

    // Establish relationships (required for Offline flow)
    alice_mgr
        .establish_relationship(&bob_dev_id)
        .await
        .expect("alice establish");
    bob_mgr
        .establish_relationship(&alice_dev_id)
        .await
        .expect("bob establish");

    let alice_mgr_shared = Arc::new(RwLock::new(alice_mgr));
    let bob_mgr_shared = Arc::new(RwLock::new(bob_mgr));

    // Seed Alice's wallet with sufficient ERA balance for the transfer.
    // The atomic sender debit enforces B >= 0 at the SQL level — without a
    // wallet_state row, the debit correctly fails.
    let alice_device_txt = dsm_sdk::util::text_id::encode_base32_crockford(&alice_dev_id);
    client_db::update_wallet_balance(&alice_device_txt, 10_000).expect("seed alice wallet balance");

    // --- CRITICAL TEST SETUP: Capture Events on Alice ---
    let captured_events = Arc::new(Mutex::new(Vec::new()));
    let capture_for_cb = captured_events.clone();

    // 1. Create handler RAW
    let mut handler_a_raw = BilateralBleHandler::new(alice_mgr_shared.clone(), alice_dev_id);

    // 2. Attach Listener
    handler_a_raw.set_event_callback(Arc::new(move |bytes: &[u8]| {
        let evt = generated::BilateralEventNotification::decode(bytes).expect("decode event");
        println!("[EVENT-TEST] Captured event: {:?}", evt.event_type);
        capture_for_cb.lock().unwrap().push(evt);
    }));

    // 3. Wrap in Arc
    let handler_a = Arc::new(handler_a_raw);
    let handler_b = Arc::new(BilateralBleHandler::new(bob_mgr_shared.clone(), bob_dev_id));

    let coord_a = Arc::new(BleFrameCoordinator::new(handler_a.clone(), alice_dev_id));
    let coord_b = Arc::new(BleFrameCoordinator::new(handler_b.clone(), bob_dev_id));

    // --- Execute Transfer ---
    let transfer_op = Operation::Transfer {
        to_device_id: bob_dev_id.to_vec(),
        amount: Balance::from_state(100, [1u8; 32], 0),
        token_id: b"ERA".to_vec(),
        mode: TransactionMode::Bilateral,
        nonce: vec![0u8; 8],
        verification: VerificationType::Standard,
        pre_commit: None,
        recipient: bob_dev_id.to_vec(),
        to: b"bob".to_vec(),
        message: "event check".to_string(),
        signature: Vec::new(),
    };

    println!("[EVENT-TEST] Alice initiating transfer...");
    let chunks = coord_a
        .create_prepare_message(bob_dev_id, transfer_op, 60)
        .await
        .expect("prepare");

    // Transport A -> B
    for ch in &chunks {
        let _ = coord_b.handle_ble_chunk(ch).await;
    }

    // Capture commitment hash to verify event validity
    let commitment = {
        let mgr = alice_mgr_shared.read().await;
        let pending = mgr.list_pending_commitments();
        *pending.first().expect("alice pending")
    };

    // Bob Accepts
    let accept_env = handler_b
        .create_prepare_accept_envelope(commitment)
        .await
        .expect("b accept");
    let chunks = coord_b
        .send_bilateral_message(
            alice_dev_id,
            BleFrameType::BilateralPrepareResponse,
            accept_env,
        )
        .await
        .expect("b chunks");

    // Transport B -> A (Accept) — coordinator calls handle_prepare_response which
    // internally calls send_bilateral_confirm. The confirm envelope is returned as response.
    println!("[EVENT-TEST] Alice receiving accept...");
    configure_local_identity_for_receipts(
        alice_dev_id,
        alice_gen_hash,
        alice_kp.public_key().to_vec(),
    );

    let mut maybe_confirm = None;
    for ch in &chunks {
        let got = coord_a.handle_ble_chunk(ch).await;
        match got {
            Ok(Some(result)) => {
                if result.response.is_some() {
                    maybe_confirm = result.response;
                }
            }
            Ok(None) => {} // intermediate chunk, not yet reassembled
            Err(e) => {
                panic!("[EVENT-TEST] handle_ble_chunk error on accept chunk: {e}");
            }
        }
    }

    let confirm_payload = maybe_confirm.expect("confirm envelope from coordinator");

    // Transport A -> B (Confirm) — Bob finalizes, no response needed
    let chunks = coord_a
        .send_bilateral_message(bob_dev_id, BleFrameType::BilateralConfirm, confirm_payload)
        .await
        .expect("a confirm chunks");
    println!("[EVENT-TEST] Bob receiving confirmation...");
    configure_local_identity_for_receipts(bob_dev_id, bob_gen_hash, bob_kp.public_key().to_vec());
    for ch in &chunks {
        let got = coord_b.handle_ble_chunk(ch).await.expect("b recv confirm");
        if let Some(result) = got {
            assert!(
                result.response.is_none(),
                "confirm should not produce a response"
            );
        }
    }

    // Simulate what Kotlin does after BLE delivery succeeds:
    // mark_confirm_delivered() transitions the sender session from ConfirmPending → Committed
    // and emits the TRANSFER_COMPLETE event that the frontend depends on.
    handler_a
        .mark_confirm_delivered(commitment)
        .await
        .expect("mark_confirm_delivered");

    // --- VERIFICATION ---
    let events = captured_events.lock().unwrap();
    println!("[EVENT-TEST] Total captured events: {}", events.len());

    // We expect:
    // 1. maybe PREPARE / PROGRESS events?
    // 2. Definitely BILATERAL_EVENT_TRANSFER_COMPLETE at the end.

    let complete_event = events.iter().find(|e| {
        e.event_type == generated::BilateralEventType::BilateralEventTransferComplete as i32
    });

    assert!(
        complete_event.is_some(),
        "UI Guarantee Failed: No TRANSFER_COMPLETE event emitted!"
    );

    let evt = complete_event.unwrap();
    assert_eq!(
        evt.commitment_hash,
        commitment.to_vec(),
        "Event commitment mismatch"
    );
    // Verify status is "completed" as returned by the actual implementation
    assert_eq!(evt.status, "completed", "Event status mismatch");
    drop(events);

    println!("[EVENT-TEST] ✅ UI Guarantee Verified: Transfer Complete event received.");

    // --- REJECTION TEST ---
    println!("[EVENT-TEST] Initiating Rejection Scenario...");
    let (_reject_prepare_envelope, commitment_2) = handler_a
        .prepare_bilateral_transaction(bob_dev_id, Operation::Noop, 60)
        .await
        .expect("prepare reject session");

    handler_a
        .reject_incoming_prepare(commitment_2, bob_dev_id, Some("User declined".to_string()))
        .await
        .expect("reject incoming prepare");

    // --- VERIFICATION 2 ---
    let events_lock = captured_events.lock().unwrap();
    let rejection_event = events_lock.iter().find(|e| {
        e.event_type == generated::BilateralEventType::BilateralEventRejected as i32
            && e.commitment_hash == commitment_2.to_vec()
    });

    assert!(
        rejection_event.is_some(),
        "UI Guarantee Failed: No REJECT event emitted!"
    );
    let evt = rejection_event.unwrap();
    assert_eq!(evt.status, "rejected");
    assert_eq!(evt.message, "User declined");

    println!("[EVENT-TEST] ✅ UI Guarantee Verified: Transfer Rejected event received.");
}
