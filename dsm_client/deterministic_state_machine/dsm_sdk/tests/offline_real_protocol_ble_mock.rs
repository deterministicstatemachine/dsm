// SPDX-License-Identifier: MIT OR Apache-2.0
// Offline bilateral flow using real MPC genesis + real protocol, with BLE transport mocked deterministically.

#![allow(clippy::disallowed_methods)]

use std::sync::Arc;
use serial_test::serial;
use tokio::sync::RwLock;

use dsm_sdk::storage::client_db;
use dsm_sdk::sdk::storage_node_sdk::{StorageNodeConfig, StorageNodeSDK};
use dsm_sdk::bluetooth::bilateral_ble_handler::BilateralBleHandler;
use dsm_sdk::bluetooth::bilateral_transport_adapter::{
    BilateralTransportAdapter, BleTransportDelegate, TransportInboundMessage,
};
use dsm_sdk::bluetooth::ble_frame_coordinator::{BleFrameCoordinator, BleFrameType, FrameIngressResult};
use dsm_sdk::storage_utils;
use dsm_sdk::util::text_id;
use rand_core06::{OsRng, RngCore};

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

fn seed_era_projection(device_txt: &str, available: u64) {
    client_db::upsert_balance_projection(&client_db::BalanceProjectionRecord {
        balance_key: format!("test:{device_txt}:ERA"),
        device_id: device_txt.to_string(),
        token_id: "ERA".to_string(),
        policy_commit: text_id::encode_base32_crockford(
            dsm_sdk::policy::builtins::NATIVE_POLICY_COMMIT,
        ),
        available,
        locked: 0,
        source_state_hash: text_id::encode_base32_crockford(&[0u8; 32]),
        source_state_number: 0,
        updated_at: 0,
    })
    .expect("seed ERA projection");
}

#[allow(clippy::too_many_arguments)]
async fn offline_transfer_roundtrip(
    coord_sender: Arc<BleFrameCoordinator>,
    coord_receiver: Arc<BleFrameCoordinator>,
    adapter_sender: Arc<BilateralTransportAdapter>,
    adapter_receiver: Arc<BilateralTransportAdapter>,
    receiver_handler: Arc<BilateralBleHandler>,
    sender_mgr: Arc<RwLock<BilateralTransactionManager>>,
    receiver_mgr: Arc<RwLock<BilateralTransactionManager>>,
    sender_id: [u8; 32],
    receiver_id: [u8; 32],
    sender_genesis_hash: [u8; 32],
    receiver_genesis_hash: [u8; 32],
    sender_public_key: Vec<u8>,
    receiver_public_key: Vec<u8>,
    op: Operation,
) -> [u8; 32] {
    let prepare_payload = adapter_sender
        .create_prepare_message(receiver_id, op, 300)
        .await
        .expect("prepare payload");
    let chunks = coord_sender
        .encode_message(BleFrameType::BilateralPrepare, &prepare_payload)
        .expect("prepare chunks");

    for ch in &chunks {
        match coord_receiver.ingest_chunk(ch).await.expect("recv prepare") {
            FrameIngressResult::MessageComplete { message } => {
                let _ = adapter_receiver
                    .on_transport_message(TransportInboundMessage {
                        peer_address: "offline-mock-receiver".to_string(),
                        frame_type: message.frame_type,
                        payload: message.payload,
                    })
                    .await
                    .expect("process prepare");
            }
            FrameIngressResult::NeedMoreChunks | FrameIngressResult::ProtocolControl(_) => {}
        }
    }

    let commitment = {
        let mgr = sender_mgr.read().await;
        let pending = mgr.list_pending_commitments();
        *pending.first().expect("pending commitment on sender")
    };

    let resp_bytes = adapter_receiver
        .create_prepare_accept_envelope(commitment)
        .await
        .expect("accept envelope");

    let resp_chunks = coord_receiver
        .encode_message(BleFrameType::BilateralPrepareResponse, &resp_bytes)
        .expect("prepare resp chunks");

    // Sender processes prepare response → produces confirm envelope (3-step protocol)
    configure_local_identity_for_receipts(sender_id, sender_genesis_hash, sender_public_key);
    let mut maybe_confirm = None;
    for ch in &resp_chunks {
        match coord_sender
            .ingest_chunk(ch)
            .await
            .expect("sender recv prepare resp")
        {
            FrameIngressResult::MessageComplete { message } => {
                let outbound = adapter_sender
                    .on_transport_message(TransportInboundMessage {
                        peer_address: "offline-mock-sender".to_string(),
                        frame_type: message.frame_type,
                        payload: message.payload,
                    })
                    .await
                    .expect("process prepare response");
                maybe_confirm = outbound.into_iter().next().map(|item| item.payload);
            }
            FrameIngressResult::NeedMoreChunks | FrameIngressResult::ProtocolControl(_) => {}
        }
    }

    let confirm_payload = match maybe_confirm {
        Some(bytes) if !bytes.is_empty() => bytes,
        _ => panic!("confirm envelope missing from sender coordinator"),
    };

    // Send confirm to receiver (3-step protocol step 3)
    let confirm_chunks = coord_sender
        .encode_message(BleFrameType::BilateralConfirm, &confirm_payload)
        .expect("confirm chunks");

    configure_local_identity_for_receipts(receiver_id, receiver_genesis_hash, receiver_public_key);
    let mut maybe_ack = None;
    for ch in &confirm_chunks {
        match coord_receiver.ingest_chunk(ch).await.expect("recv confirm") {
            FrameIngressResult::MessageComplete { message } => {
                maybe_ack = Some(
                    receiver_handler
                        .handle_confirm_request(&message.payload)
                        .await
                        .expect("process confirm"),
                );
            }
            FrameIngressResult::NeedMoreChunks | FrameIngressResult::ProtocolControl(_) => {}
        }
    }

    let ack_payload = maybe_ack.expect("receiver commit response ack");
    let ack_chunks = coord_receiver
        .encode_message(BleFrameType::BilateralCommitResponse, &ack_payload)
        .expect("commit response chunks");
    for ch in &ack_chunks {
        match coord_sender
            .ingest_chunk(ch)
            .await
            .expect("recv commit response")
        {
            FrameIngressResult::MessageComplete { message } => {
                let outbound = adapter_sender
                    .on_transport_message(TransportInboundMessage {
                        peer_address: "offline-mock-sender".to_string(),
                        frame_type: message.frame_type,
                        payload: message.payload,
                    })
                    .await
                    .expect("process commit response");
                assert!(
                    outbound.is_empty(),
                    "commit response should not produce a response"
                );
            }
            FrameIngressResult::NeedMoreChunks | FrameIngressResult::ProtocolControl(_) => {}
        }
    }

    // Both sides finalized after 3-step confirm
    {
        let mgr = sender_mgr.read().await;
        assert!(!mgr.has_pending_commitment(&commitment));
        drop(mgr);
        let mgr = receiver_mgr.read().await;
        assert!(!mgr.has_pending_commitment(&commitment));
    }

    // In the shared-tip model, both peers have the same chain tip
    let sender_tip = {
        let mgr = sender_mgr.read().await;
        mgr.get_chain_tip_for(&receiver_id)
            .expect("sender local tip for receiver")
    };
    {
        let mut mgr = receiver_mgr.write().await;
        let mut c = mgr
            .get_contact(&sender_id)
            .expect("receiver contact sender")
            .clone();
        c.chain_tip = Some(sender_tip);
        mgr.add_verified_contact(c)
            .expect("update receiver remote tip");
    }

    commitment
}

#[tokio::test]
#[serial]
#[ignore = "requires live AWS storage nodes for MPC genesis"]
async fn offline_real_protocol_ble_mock_roundtrip() {
    println!("[OFFLINE] init test storage + MPC genesis");
    // Point at the real env config TOML so StorageNodeConfig picks up the
    // production HTTPS endpoints and build_ca_aware_client loads the CA cert.
    let env_config_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../frontend/public/dsm_env_config.toml");
    std::env::set_var(
        "DSM_ENV_CONFIG_PATH",
        env_config_path.to_str().expect("config path"),
    );
    std::env::set_var("DSM_SDK_TEST_MODE", "1");

    // Ensure test storage is isolated
    let temp_dir = std::env::temp_dir().join("dsm_offline_real_protocol_ble_mock");
    if temp_dir.exists() {
        let _ = std::fs::remove_dir_all(&temp_dir);
    }
    std::fs::create_dir_all(&temp_dir).expect("temp dir");
    storage_utils::set_storage_base_dir(temp_dir).expect("set storage dir");

    // Ensure DB schema is initialized (tolerate OnceLock re-entry from sibling tests).
    client_db::reset_database_for_tests();
    if let Err(e) = client_db::init_database() {
        eprintln!("[OFFLINE] init_database skipped (already init): {e}");
    }

    // Storage config (real protocol path: MPC genesis uses storage nodes)
    let storage_config = StorageNodeConfig::from_env_config()
        .await
        .expect("storage config missing (env config required)");
    let storage_sdk = StorageNodeSDK::new(storage_config)
        .await
        .expect("StorageNodeSDK init failed");

    // Create Alice genesis via MPC
    let mut os_rng = OsRng;
    let mut alice_entropy = vec![0u8; 32];
    os_rng.fill_bytes(&mut alice_entropy);
    let alice_genesis = storage_sdk
        .create_genesis_with_mpc(Some(3), Some(alice_entropy))
        .await
        .expect("alice MPC genesis failed");
    let alice_dev_id = bytes32(alice_genesis.genesis_device_id);
    let alice_gen_hash = bytes32(
        alice_genesis
            .genesis_hash
            .expect("alice genesis_hash missing"),
    );

    // Create Bob genesis via MPC
    let mut bob_entropy = vec![1u8; 32];
    os_rng.fill_bytes(&mut bob_entropy);
    let bob_genesis = storage_sdk
        .create_genesis_with_mpc(Some(3), Some(bob_entropy))
        .await
        .expect("bob MPC genesis failed");
    let bob_dev_id = bytes32(bob_genesis.genesis_device_id);
    let bob_gen_hash = bytes32(bob_genesis.genesis_hash.expect("bob genesis_hash missing"));

    // Real SPHINCS+ keypairs for both devices
    let alice_kp = SignatureKeyPair::generate_from_entropy(b"offline-real-a").expect("kp a");
    let bob_kp = SignatureKeyPair::generate_from_entropy(b"offline-real-b").expect("kp b");

    // Contact managers
    let alice_cm = DsmContactManager::new(alice_dev_id, vec![NodeId::new("n")]);
    let bob_cm = DsmContactManager::new(bob_dev_id, vec![NodeId::new("n")]);

    // Bilateral transaction managers (real genesis + keys)
    let mut alice_mgr =
        BilateralTransactionManager::new(alice_cm, alice_kp.clone(), alice_dev_id, alice_gen_hash);
    let mut bob_mgr =
        BilateralTransactionManager::new(bob_cm, bob_kp.clone(), bob_dev_id, bob_gen_hash);

    // Add verified contacts
    let contact_b = dsm::types::contact_types::DsmVerifiedContact {
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
        ble_address: None,
    };
    let contact_a = dsm::types::contact_types::DsmVerifiedContact {
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
        ble_address: None,
    };

    alice_mgr.add_verified_contact(contact_b).unwrap();
    bob_mgr.add_verified_contact(contact_a).unwrap();

    // Establish relationships
    let mut smt = dsm::merkle::sparse_merkle_tree::SparseMerkleTree::new(256);
    alice_mgr
        .establish_relationship(&bob_dev_id, &mut smt)
        .await
        .unwrap();
    bob_mgr
        .establish_relationship(&alice_dev_id, &mut smt)
        .await
        .unwrap();

    let alice_mgr = Arc::new(RwLock::new(alice_mgr));
    let bob_mgr = Arc::new(RwLock::new(bob_mgr));

    // Seed Alice's ERA balance via projection storage.
    let alice_device_txt = text_id::encode_base32_crockford(&alice_dev_id);
    seed_era_projection(&alice_device_txt, 10_000);

    // BLE handler + frame coordinators (mock transport via direct chunk exchange)
    let handler_a = Arc::new(BilateralBleHandler::new(alice_mgr.clone(), alice_dev_id));
    let handler_b = Arc::new(BilateralBleHandler::new(bob_mgr.clone(), bob_dev_id));
    let adapter_a = Arc::new(BilateralTransportAdapter::new(handler_a.clone()));
    let adapter_b = Arc::new(BilateralTransportAdapter::new(handler_b.clone()));
    let coord_a = Arc::new(BleFrameCoordinator::new(alice_dev_id));
    let coord_b = Arc::new(BleFrameCoordinator::new(bob_dev_id));

    println!(
        "[OFFLINE] alice_dev={} bob_dev={}",
        text_id::encode_base32_crockford(&alice_dev_id),
        text_id::encode_base32_crockford(&bob_dev_id)
    );

    // Transfer operation (real protocol op)
    let amount = Balance::from_state(10, [1u8; 32], 0);
    let transfer_op = Operation::Transfer {
        to_device_id: bob_dev_id.to_vec(),
        amount,
        token_id: b"ERA".to_vec(),
        mode: TransactionMode::Bilateral,
        nonce: vec![0u8; 8],
        verification: VerificationType::Standard,
        pre_commit: None,
        recipient: bob_dev_id.to_vec(),
        to: b"bob".to_vec(),
        message: "offline pay".to_string(),
        signature: Vec::new(),
    };

    // === Prepare ===
    println!("[OFFLINE] prepare -> chunk");
    let prepare_payload = adapter_a
        .create_prepare_message(bob_dev_id, transfer_op.clone(), 300)
        .await
        .expect("prepare payload");
    let chunks = coord_a
        .encode_message(BleFrameType::BilateralPrepare, &prepare_payload)
        .expect("prepare chunks");
    println!("[OFFLINE] prepare chunks={}", chunks.len());

    for ch in &chunks {
        match coord_b.ingest_chunk(ch).await.expect("b recv") {
            FrameIngressResult::MessageComplete { message } => {
                let _ = adapter_b
                    .on_transport_message(TransportInboundMessage {
                        peer_address: "offline-b".to_string(),
                        frame_type: message.frame_type,
                        payload: message.payload,
                    })
                    .await
                    .expect("b process prepare");
            }
            FrameIngressResult::NeedMoreChunks | FrameIngressResult::ProtocolControl(_) => {}
        }
    }
    println!("[OFFLINE] prepare received and staged for manual accept");

    let commitment = {
        let mgr = alice_mgr.read().await;
        let pending = mgr.list_pending_commitments();
        *pending.first().expect("pending commitment on Alice")
    };

    let resp_bytes = handler_b
        .create_prepare_accept_envelope(commitment)
        .await
        .expect("accept envelope");

    // Send prepare response to A
    let resp_chunks = coord_b
        .encode_message(BleFrameType::BilateralPrepareResponse, &resp_bytes)
        .expect("resp chunks");
    println!("[OFFLINE] prepare response chunks={}", resp_chunks.len());
    // Coordinator calls handle_prepare_response → send_bilateral_confirm → returns confirm bytes
    configure_local_identity_for_receipts(
        alice_dev_id,
        alice_gen_hash,
        alice_kp.public_key().to_vec(),
    );
    let mut maybe_confirm = None;
    for ch in &resp_chunks {
        match coord_a.ingest_chunk(ch).await.expect("a recv resp") {
            FrameIngressResult::MessageComplete { message } => {
                let outbound = adapter_a
                    .on_transport_message(TransportInboundMessage {
                        peer_address: "offline-a".to_string(),
                        frame_type: message.frame_type,
                        payload: message.payload,
                    })
                    .await
                    .expect("a process prepare response");
                maybe_confirm = outbound.into_iter().next().map(|item| item.payload);
            }
            FrameIngressResult::NeedMoreChunks | FrameIngressResult::ProtocolControl(_) => {}
        }
    }

    let commitment = {
        let mgr = alice_mgr.read().await;
        let pending = mgr.list_pending_commitments();
        // After send_bilateral_confirm, commitment may be cleared; use session lookup
        if pending.is_empty() {
            // Already committed — confirm was produced, need commitment hash for assertions
            [0u8; 32] // placeholder, actual verification is below via chain tips
        } else {
            *pending.first().expect("pending commitment")
        }
    };

    let confirm_payload = maybe_confirm.expect("confirm envelope from coordinator");
    println!("[OFFLINE] confirm payload bytes={}", confirm_payload.len());
    let confirm_chunks = coord_a
        .encode_message(BleFrameType::BilateralConfirm, &confirm_payload)
        .expect("confirm chunks");
    println!("[OFFLINE] confirm chunks={}", confirm_chunks.len());

    configure_local_identity_for_receipts(bob_dev_id, bob_gen_hash, bob_kp.public_key().to_vec());
    let mut maybe_ack = None;
    for ch in &confirm_chunks {
        match coord_b.ingest_chunk(ch).await.expect("b recv confirm") {
            FrameIngressResult::MessageComplete { message } => {
                maybe_ack = Some(
                    handler_b
                        .handle_confirm_request(&message.payload)
                        .await
                        .expect("b process confirm"),
                );
            }
            FrameIngressResult::NeedMoreChunks | FrameIngressResult::ProtocolControl(_) => {}
        }
    }

    let ack_payload = maybe_ack.expect("receiver commit response ack");
    let ack_chunks = coord_b
        .encode_message(BleFrameType::BilateralCommitResponse, &ack_payload)
        .expect("commit response chunks");
    for ch in &ack_chunks {
        match coord_a
            .ingest_chunk(ch)
            .await
            .expect("a recv commit response")
        {
            FrameIngressResult::MessageComplete { message } => {
                let outbound = adapter_a
                    .on_transport_message(TransportInboundMessage {
                        peer_address: "offline-a".to_string(),
                        frame_type: message.frame_type,
                        payload: message.payload,
                    })
                    .await
                    .expect("a process commit response");
                assert!(
                    outbound.is_empty(),
                    "commit response should not produce a response"
                );
            }
            FrameIngressResult::NeedMoreChunks | FrameIngressResult::ProtocolControl(_) => {}
        }
    }

    // Both sides finalized after 3-step confirm
    {
        let mgr = alice_mgr.read().await;
        assert!(!mgr.has_pending_commitment(&commitment));
        let alice_local = mgr
            .get_chain_tip_for(&bob_dev_id)
            .expect("alice local chain tip");
        println!("[OFFLINE] alice local tip={:02x?}", &alice_local[..8]);
        assert!(alice_local != [0u8; 32], "alice local tip must be nonzero");
        drop(mgr);

        let mgr_b = bob_mgr.read().await;
        assert!(!mgr_b.has_pending_commitment(&commitment));
        let bob_local = mgr_b
            .get_chain_tip_for(&alice_dev_id)
            .expect("bob local chain tip");
        println!("[OFFLINE] bob local tip={:02x?}", &bob_local[..8]);
        assert!(bob_local != [0u8; 32], "bob local tip must be nonzero");
    }

    println!("[OFFLINE] bilateral mock completed");
}

#[tokio::test]
#[serial]
#[ignore = "requires live AWS storage nodes for MPC genesis"]
async fn offline_real_protocol_ble_mock_multi_relationship_multi_tx() {
    println!("[OFFLINE-MULTI] init test storage + MPC genesis");
    let env_config_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../frontend/public/dsm_env_config.toml");
    std::env::set_var(
        "DSM_ENV_CONFIG_PATH",
        env_config_path.to_str().expect("config path"),
    );
    std::env::set_var("DSM_SDK_TEST_MODE", "1");

    let temp_dir = std::env::temp_dir().join("dsm_offline_real_protocol_ble_mock_multi");
    if temp_dir.exists() {
        let _ = std::fs::remove_dir_all(&temp_dir);
    }
    std::fs::create_dir_all(&temp_dir).expect("temp dir");
    // OnceLock: Ok(false) if already set by another test in this process — safe to continue.
    let _ = storage_utils::set_storage_base_dir(temp_dir);
    client_db::reset_database_for_tests();
    if let Err(e) = client_db::init_database() {
        eprintln!("[OFFLINE-MULTI] init_database skipped (already init): {e}");
    }

    let storage_config = StorageNodeConfig::from_env_config()
        .await
        .expect("storage config missing (env config required)");
    let storage_sdk = StorageNodeSDK::new(storage_config)
        .await
        .expect("StorageNodeSDK init failed");

    let mut os_rng = OsRng;
    let mut alice_entropy = vec![0u8; 32];
    let mut bob_entropy = vec![1u8; 32];
    let mut carol_entropy = vec![2u8; 32];
    os_rng.fill_bytes(&mut alice_entropy);
    os_rng.fill_bytes(&mut bob_entropy);
    os_rng.fill_bytes(&mut carol_entropy);

    let alice_genesis = storage_sdk
        .create_genesis_with_mpc(Some(3), Some(alice_entropy))
        .await
        .expect("alice MPC genesis failed");
    let bob_genesis = storage_sdk
        .create_genesis_with_mpc(Some(3), Some(bob_entropy))
        .await
        .expect("bob MPC genesis failed");
    let carol_genesis = storage_sdk
        .create_genesis_with_mpc(Some(3), Some(carol_entropy))
        .await
        .expect("carol MPC genesis failed");

    let alice_dev_id = bytes32(alice_genesis.genesis_device_id);
    let bob_dev_id = bytes32(bob_genesis.genesis_device_id);
    let carol_dev_id = bytes32(carol_genesis.genesis_device_id);
    let alice_gen_hash = bytes32(alice_genesis.genesis_hash.expect("alice genesis_hash"));
    let bob_gen_hash = bytes32(bob_genesis.genesis_hash.expect("bob genesis_hash"));
    let carol_gen_hash = bytes32(carol_genesis.genesis_hash.expect("carol genesis_hash"));

    let alice_kp = SignatureKeyPair::generate_from_entropy(b"offline-multi-a").expect("kp a");
    let bob_kp = SignatureKeyPair::generate_from_entropy(b"offline-multi-b").expect("kp b");
    let carol_kp = SignatureKeyPair::generate_from_entropy(b"offline-multi-c").expect("kp c");

    let alice_cm = DsmContactManager::new(alice_dev_id, vec![NodeId::new("n")]);
    let bob_cm = DsmContactManager::new(bob_dev_id, vec![NodeId::new("n")]);
    let carol_cm = DsmContactManager::new(carol_dev_id, vec![NodeId::new("n")]);

    let mut alice_mgr =
        BilateralTransactionManager::new(alice_cm, alice_kp.clone(), alice_dev_id, alice_gen_hash);
    let mut bob_mgr =
        BilateralTransactionManager::new(bob_cm, bob_kp.clone(), bob_dev_id, bob_gen_hash);
    let mut carol_mgr =
        BilateralTransactionManager::new(carol_cm, carol_kp.clone(), carol_dev_id, carol_gen_hash);

    let contact_b = dsm::types::contact_types::DsmVerifiedContact {
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
        ble_address: None,
    };
    let contact_c = dsm::types::contact_types::DsmVerifiedContact {
        alias: "Carol".to_string(),
        device_id: carol_dev_id,
        genesis_hash: carol_gen_hash,
        public_key: carol_kp.public_key().to_vec(),
        genesis_material: vec![0u8; 32],
        chain_tip: None,
        chain_tip_smt_proof: None,
        genesis_verified_online: true,
        verified_at_commit_height: 1,
        added_at_commit_height: 1,
        last_updated_commit_height: 1,
        verifying_storage_nodes: vec![],
        ble_address: None,
    };
    let contact_a_for_b = dsm::types::contact_types::DsmVerifiedContact {
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
        ble_address: None,
    };
    let contact_a_for_c = contact_a_for_b.clone();

    alice_mgr.add_verified_contact(contact_b).unwrap();
    alice_mgr.add_verified_contact(contact_c).unwrap();
    bob_mgr.add_verified_contact(contact_a_for_b).unwrap();
    carol_mgr.add_verified_contact(contact_a_for_c).unwrap();

    let mut smt = dsm::merkle::sparse_merkle_tree::SparseMerkleTree::new(256);
    alice_mgr
        .establish_relationship(&bob_dev_id, &mut smt)
        .await
        .unwrap();
    alice_mgr
        .establish_relationship(&carol_dev_id, &mut smt)
        .await
        .unwrap();
    bob_mgr
        .establish_relationship(&alice_dev_id, &mut smt)
        .await
        .unwrap();
    carol_mgr
        .establish_relationship(&alice_dev_id, &mut smt)
        .await
        .unwrap();

    let alice_mgr = Arc::new(RwLock::new(alice_mgr));
    let bob_mgr = Arc::new(RwLock::new(bob_mgr));
    let carol_mgr = Arc::new(RwLock::new(carol_mgr));

    // Seed Alice's ERA balance via projection storage.
    let alice_device_txt = text_id::encode_base32_crockford(&alice_dev_id);
    seed_era_projection(&alice_device_txt, 10_000);

    let handler_a = Arc::new(BilateralBleHandler::new(alice_mgr.clone(), alice_dev_id));
    let handler_b = Arc::new(BilateralBleHandler::new(bob_mgr.clone(), bob_dev_id));
    let handler_c = Arc::new(BilateralBleHandler::new(carol_mgr.clone(), carol_dev_id));
    let adapter_a = Arc::new(BilateralTransportAdapter::new(handler_a.clone()));
    let adapter_b = Arc::new(BilateralTransportAdapter::new(handler_b.clone()));
    let adapter_c = Arc::new(BilateralTransportAdapter::new(handler_c.clone()));
    let coord_a = Arc::new(BleFrameCoordinator::new(alice_dev_id));
    let coord_b = Arc::new(BleFrameCoordinator::new(bob_dev_id));
    let coord_c = Arc::new(BleFrameCoordinator::new(carol_dev_id));

    // Sync initial remote chain tips to avoid prepare hash mismatches.
    let alice_tip_for_b = {
        let mgr = alice_mgr.read().await;
        mgr.get_chain_tip_for(&bob_dev_id)
            .expect("alice local tip for bob")
    };
    let alice_tip_for_c = {
        let mgr = alice_mgr.read().await;
        mgr.get_chain_tip_for(&carol_dev_id)
            .expect("alice local tip for carol")
    };
    let bob_tip_for_a = {
        let mgr = bob_mgr.read().await;
        mgr.get_chain_tip_for(&alice_dev_id)
            .expect("bob local tip for alice")
    };
    let carol_tip_for_a = {
        let mgr = carol_mgr.read().await;
        mgr.get_chain_tip_for(&alice_dev_id)
            .expect("carol local tip for alice")
    };

    {
        let mut mgr = alice_mgr.write().await;
        // manually sync contacts
        let mut c = mgr
            .get_contact(&bob_dev_id)
            .expect("alice contact bob")
            .clone();
        c.chain_tip = Some(bob_tip_for_a);
        mgr.add_verified_contact(c).expect("update contact bob");

        let mut c = mgr
            .get_contact(&carol_dev_id)
            .expect("alice contact carol")
            .clone();
        c.chain_tip = Some(carol_tip_for_a);
        mgr.add_verified_contact(c).expect("update contact carol");
    }
    {
        let mut mgr = bob_mgr.write().await;
        let mut c = mgr
            .get_contact(&alice_dev_id)
            .expect("bob contact alice")
            .clone();
        c.chain_tip = Some(alice_tip_for_b);
        mgr.add_verified_contact(c).expect("update contact alice");
    }
    {
        let mut mgr = carol_mgr.write().await;
        let mut c = mgr
            .get_contact(&alice_dev_id)
            .expect("carol contact alice")
            .clone();
        c.chain_tip = Some(alice_tip_for_c);
        mgr.add_verified_contact(c).expect("update contact alice");
    }

    let op_ab_1 = Operation::Transfer {
        to_device_id: bob_dev_id.to_vec(),
        amount: Balance::from_state(10, [1u8; 32], 0),
        token_id: b"ERA".to_vec(),
        mode: TransactionMode::Bilateral,
        nonce: vec![0u8; 8],
        verification: VerificationType::Standard,
        pre_commit: None,
        recipient: bob_dev_id.to_vec(),
        to: b"bob".to_vec(),
        message: "ab-1".to_string(),
        signature: Vec::new(),
    };
    let op_ab_2 = Operation::Transfer {
        to_device_id: bob_dev_id.to_vec(),
        amount: Balance::from_state(20, [2u8; 32], 0),
        token_id: b"ERA".to_vec(),
        mode: TransactionMode::Bilateral,
        nonce: vec![1u8; 8],
        verification: VerificationType::Standard,
        pre_commit: None,
        recipient: bob_dev_id.to_vec(),
        to: b"bob".to_vec(),
        message: "ab-2".to_string(),
        signature: Vec::new(),
    };
    let op_ac_1 = Operation::Transfer {
        to_device_id: carol_dev_id.to_vec(),
        amount: Balance::from_state(30, [3u8; 32], 0),
        token_id: b"ERA".to_vec(),
        mode: TransactionMode::Bilateral,
        nonce: vec![2u8; 8],
        verification: VerificationType::Standard,
        pre_commit: None,
        recipient: carol_dev_id.to_vec(),
        to: b"carol".to_vec(),
        message: "ac-1".to_string(),
        signature: Vec::new(),
    };
    let op_ac_2 = Operation::Transfer {
        to_device_id: carol_dev_id.to_vec(),
        amount: Balance::from_state(40, [4u8; 32], 0),
        token_id: b"ERA".to_vec(),
        mode: TransactionMode::Bilateral,
        nonce: vec![3u8; 8],
        verification: VerificationType::Standard,
        pre_commit: None,
        recipient: carol_dev_id.to_vec(),
        to: b"carol".to_vec(),
        message: "ac-2".to_string(),
        signature: Vec::new(),
    };

    offline_transfer_roundtrip(
        coord_a.clone(),
        coord_b.clone(),
        adapter_a.clone(),
        adapter_b.clone(),
        handler_b.clone(),
        alice_mgr.clone(),
        bob_mgr.clone(),
        alice_dev_id,
        bob_dev_id,
        alice_gen_hash,
        bob_gen_hash,
        alice_kp.public_key().to_vec(),
        bob_kp.public_key().to_vec(),
        op_ab_1,
    )
    .await;

    let ab_tip_1 = {
        let mgr = alice_mgr.read().await;
        mgr.get_chain_tip_for(&bob_dev_id)
            .expect("alice tip for bob")
    };

    offline_transfer_roundtrip(
        coord_a.clone(),
        coord_b.clone(),
        adapter_a.clone(),
        adapter_b.clone(),
        handler_b.clone(),
        alice_mgr.clone(),
        bob_mgr.clone(),
        alice_dev_id,
        bob_dev_id,
        alice_gen_hash,
        bob_gen_hash,
        alice_kp.public_key().to_vec(),
        bob_kp.public_key().to_vec(),
        op_ab_2,
    )
    .await;

    let ab_tip_2 = {
        let mgr = alice_mgr.read().await;
        mgr.get_chain_tip_for(&bob_dev_id)
            .expect("alice tip for bob")
    };
    assert_ne!(ab_tip_1, ab_tip_2, "A<->B tip should advance");

    offline_transfer_roundtrip(
        coord_a.clone(),
        coord_c.clone(),
        adapter_a.clone(),
        adapter_c.clone(),
        handler_c.clone(),
        alice_mgr.clone(),
        carol_mgr.clone(),
        alice_dev_id,
        carol_dev_id,
        alice_gen_hash,
        carol_gen_hash,
        alice_kp.public_key().to_vec(),
        carol_kp.public_key().to_vec(),
        op_ac_1,
    )
    .await;

    let ac_tip_1 = {
        let mgr = alice_mgr.read().await;
        mgr.get_chain_tip_for(&carol_dev_id)
            .expect("alice tip for carol")
    };

    offline_transfer_roundtrip(
        coord_a.clone(),
        coord_c.clone(),
        adapter_a.clone(),
        adapter_c.clone(),
        handler_c.clone(),
        alice_mgr.clone(),
        carol_mgr.clone(),
        alice_dev_id,
        carol_dev_id,
        alice_gen_hash,
        carol_gen_hash,
        alice_kp.public_key().to_vec(),
        carol_kp.public_key().to_vec(),
        op_ac_2,
    )
    .await;

    let ac_tip_2 = {
        let mgr = alice_mgr.read().await;
        mgr.get_chain_tip_for(&carol_dev_id)
            .expect("alice tip for carol")
    };
    assert_ne!(ac_tip_1, ac_tip_2, "A<->C tip should advance");

    let ab_tip_final = ab_tip_2;
    let ac_tip_final = ac_tip_2;
    assert_ne!(
        ab_tip_final, ac_tip_final,
        "A tips should differ per relationship"
    );

    let bob_tip = {
        let mgr = bob_mgr.read().await;
        mgr.get_chain_tip_for(&alice_dev_id)
            .expect("bob tip for alice")
    };
    let carol_tip = {
        let mgr = carol_mgr.read().await;
        mgr.get_chain_tip_for(&alice_dev_id)
            .expect("carol tip for alice")
    };
    assert!(bob_tip != [0u8; 32], "bob tip must be nonzero");
    assert!(carol_tip != [0u8; 32], "carol tip must be nonzero");

    println!("[OFFLINE-MULTI] multi-relationship multi-tx completed");
}
