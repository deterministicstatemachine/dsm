#![allow(clippy::disallowed_methods)]

use dsm_sdk::sdk::b0x_sdk::{B0xSDK, B0xSubmissionParams};
use dsm_sdk::sdk::core_sdk::CoreSDK;
use dsm_sdk::sdk::storage_node_sdk::StorageNodeConfig;
use dsm_sdk::types::state_types::DeviceInfo;
use dsm_sdk::util::text_id;
use dsm_sdk::storage_utils;
use dsm::types::operations::{Operation, TransactionMode, VerificationType};
use dsm::types::token_types::Balance;

use std::sync::Arc;

fn device_info_from_bytes(device_id: [u8; 32]) -> DeviceInfo {
    DeviceInfo::new(device_id, device_id.to_vec())
}

fn initial_relationship_tip(
    sender_device: [u8; 32],
    sender_genesis: [u8; 32],
    receiver_device: [u8; 32],
    receiver_genesis: [u8; 32],
) -> [u8; 32] {
    let (genesis_a, device_a, genesis_b, device_b) = if sender_device < receiver_device {
        (
            sender_genesis,
            sender_device,
            receiver_genesis,
            receiver_device,
        )
    } else {
        (
            receiver_genesis,
            receiver_device,
            sender_genesis,
            sender_device,
        )
    };

    let mut hasher = dsm::crypto::blake3::dsm_domain_hasher("DSM/bilateral-session");
    hasher.update(&genesis_a);
    hasher.update(&device_a);
    hasher.update(&genesis_b);
    hasher.update(&device_b);

    let mut tip = [0u8; 32];
    tip.copy_from_slice(hasher.finalize().as_bytes());
    tip
}

#[tokio::test]
#[ignore = "requires live storage node at http://127.0.0.1:8080"]
async fn test_b0x_integration_full_flow() {
    // Setup storage base dir
    let temp_dir = std::env::temp_dir().join("dsm_test_b0x");
    if temp_dir.exists() {
        std::fs::remove_dir_all(&temp_dir).expect("Failed to clean temp dir");
    }
    println!("Setting storage base dir to: {:?}", temp_dir);
    match storage_utils::set_storage_base_dir(temp_dir.clone()) {
        Ok(v) => println!("set_storage_base_dir returned: {}", v),
        Err(e) => panic!("set_storage_base_dir failed: {:?}", e),
    }

    let mock_storage_url = "http://127.0.0.1:8080".to_string();
    let _client = reqwest::Client::new();

    // 1. Initialize CoreSDK
    let core_sdk = Arc::new(CoreSDK::new().expect("Failed to init CoreSDK"));
    let my_device_id = core_sdk.get_device_identity().device_id.to_vec();
    let my_device_b32 = text_id::encode_base32_crockford(&my_device_id);

    // 2. Initialize B0xSDK
    let mut b0x_sdk = B0xSDK::new(
        my_device_b32.clone(),
        core_sdk.clone(),
        vec![mock_storage_url.clone()],
    )
    .expect("Failed to init B0xSDK");

    // 3. Prepare Operation - SEND TO SELF so we can retrieve it
    let recipient_id_bytes = my_device_id.clone();
    let recipient_b32 = my_device_b32.clone();
    let recipient_genesis_hash = vec![0xCC; 32];
    let recipient_genesis_b32 = text_id::encode_base32_crockford(&recipient_genesis_hash);

    let dummy_hash = [0u8; 32];
    let amount = Balance::from_state(100, dummy_hash);

    let op = Operation::Transfer {
        to_device_id: recipient_id_bytes.clone(),
        amount,
        token_id: b"native".to_vec(),
        mode: TransactionMode::Bilateral,
        nonce: vec![0u8; 12],
        verification: VerificationType::Standard,
        pre_commit: None,
        recipient: recipient_id_bytes.clone(),
        to: b"recipient_alias".to_vec(),
        message: "hello b0x self".to_string(),
        signature: vec![0; 64],
    };

    // 4. Construct B0xSubmissionParams
    let sender_genesis_hash = vec![0xAA; 32];
    let sender_genesis_b32 = text_id::encode_base32_crockford(&sender_genesis_hash);
    let sender_tip = vec![0xDD; 32];
    let sender_tip_b32 = text_id::encode_base32_crockford(&sender_tip);
    let routing_address =
        B0xSDK::compute_b0x_address(&recipient_genesis_hash, &recipient_id_bytes, &sender_tip)
            .expect("routing address");

    let submission = B0xSubmissionParams {
        recipient_device_id: recipient_b32.clone(),
        recipient_genesis_hash: recipient_genesis_b32,
        transaction: op,
        signature: vec![], // Empty signature for b0x submission
        sender_genesis_hash: sender_genesis_b32,
        sender_chain_tip: sender_tip_b32.clone(),
        sender_signing_public_key: vec![0xEE; 64],
        ttl_seconds: 0,
        seq: 1,
        next_chain_tip: Some(sender_tip.clone()),
        receipt_commit: vec![],
        routing_address: routing_address.clone(),
        canonical_operation_bytes: vec![],
    };

    // 5. Submit
    let tx_id = match b0x_sdk.submit_to_b0x(submission).await {
        Ok(id) => {
            println!("Submission accepted. TxID: {:?}", id);
            id
        }
        Err(e) => {
            let err_str = e.to_string();
            if err_str.contains("Connection refused")
                || err_str.contains("Network error")
                || err_str.contains("error sending request")
                || err_str.contains("submit quorum not met")
            {
                eprintln!("Storage nodes not running, skipping verify. Error: {:?}", e);
                return;
            } else {
                panic!("B0x submit error: {:?}", e);
            }
        }
    };

    // 6. Retrieve (Expect to see it)
    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

    let entries = b0x_sdk
        .retrieve_from_b0x_v2(&routing_address, 10)
        .await
        .expect("Retrieve failed");
    println!("Retrieved {} entries", entries.len());

    let _found = entries.iter().find(|e| {
        text_id::encode_base32_crockford(&e.signature)
            == text_id::encode_base32_crockford(&[1, 2, 3])
    }); // Check signature match or similar
        // Note: B0xEntry doesn't have exact same ID as TxID returned by submit (submit returns message_id, B0xEntry has transaction_id which is envelope message_id).
        // Actually submit_to_b0x returns message_id_b32.
        // B0xEntry.transaction_id IS message_id encoded base32.
        // So we can check id match.

    let has_message = entries.iter().any(|e| e.transaction_id == tx_id);
    assert!(
        has_message,
        "Retrieve did not find the submitted message ID"
    );

    let next_tip_b32 = text_id::encode_base32_crockford(&sender_tip);
    let fetched = entries
        .iter()
        .find(|e| e.transaction_id == tx_id)
        .expect("submitted entry missing");
    assert_eq!(
        fetched.next_chain_tip, next_tip_b32,
        "next_chain_tip should match the submitted post_state_hash"
    );

    // 7. Acknowledge
    b0x_sdk
        .acknowledge_b0x_v2(&routing_address, vec![tx_id.clone()])
        .await
        .expect("Ack failed");
    println!("Acknowledged message");

    // 8. Retrieve again (Expect it gone or marked)
    // The storage node might delete it OR just mark it consumed.
    // Currently storage node delete-on-ack behavior depends on implementation (often delete).
    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
    let entries_after = b0x_sdk
        .retrieve_from_b0x_v2(&routing_address, 10)
        .await
        .expect("Retrieve2 failed");
    let still_there = entries_after.iter().any(|e| e.transaction_id == tx_id);
    assert!(!still_there, "Message should be gone after ACK");
}

#[tokio::test]
#[ignore = "requires live AWS storage nodes plus DSM_ENV_CONFIG_PATH with CA cert"]
async fn test_b0x_live_recipient_roundtrip() {
    let temp_dir = std::env::temp_dir().join("dsm_test_b0x_live_sender_receiver");
    if temp_dir.exists() {
        std::fs::remove_dir_all(&temp_dir).expect("Failed to clean temp dir");
    }
    std::fs::create_dir_all(&temp_dir).expect("Failed to create temp dir");
    storage_utils::set_storage_base_dir(temp_dir.clone()).expect("set storage base dir");

    let cfg = StorageNodeConfig::from_env_config()
        .await
        .expect("AWS env config must be available");
    assert!(
        !cfg.node_urls.is_empty(),
        "AWS env config must contain storage nodes"
    );

    let sender_device = [0xA1u8; 32];
    let receiver_device = [0xB2u8; 32];

    let sender_core = Arc::new(
        CoreSDK::new_with_device(device_info_from_bytes(sender_device)).expect("sender core init"),
    );
    sender_core
        .initialize_with_genesis_state()
        .expect("sender genesis init");
    let sender_genesis: [u8; 32] = sender_core
        .local_genesis_hash()
        .await
        .expect("sender genesis hash")
        .try_into()
        .expect("sender genesis len");

    let receiver_core = Arc::new(
        CoreSDK::new_with_device(device_info_from_bytes(receiver_device))
            .expect("receiver core init"),
    );
    receiver_core
        .initialize_with_genesis_state()
        .expect("receiver genesis init");
    let receiver_genesis: [u8; 32] = receiver_core
        .local_genesis_hash()
        .await
        .expect("receiver genesis hash")
        .try_into()
        .expect("receiver genesis len");

    let sender_b32 = text_id::encode_base32_crockford(&sender_device);
    let receiver_b32 = text_id::encode_base32_crockford(&receiver_device);
    let initial_tip = initial_relationship_tip(
        sender_device,
        sender_genesis,
        receiver_device,
        receiver_genesis,
    );
    let mut next_tip_hasher = dsm::crypto::blake3::dsm_domain_hasher("DSM/test-next-tip");
    next_tip_hasher.update(&initial_tip);
    let next_tip = *next_tip_hasher.finalize().as_bytes();
    let routing_address =
        B0xSDK::compute_b0x_address(&receiver_genesis, &receiver_device, &initial_tip)
            .expect("routing address");

    let mut sender_b0x = B0xSDK::new(
        sender_b32.clone(),
        sender_core.clone(),
        cfg.node_urls.clone(),
    )
    .expect("sender b0x");
    let mut receiver_b0x = B0xSDK::new(
        receiver_b32.clone(),
        receiver_core.clone(),
        cfg.node_urls.clone(),
    )
    .expect("receiver b0x");

    sender_b0x
        .register_device()
        .await
        .expect("sender registration");
    receiver_b0x
        .register_device()
        .await
        .expect("receiver registration");

    let amount = Balance::from_state(7, [0u8; 32]);
    let op = Operation::Transfer {
        to_device_id: receiver_device.to_vec(),
        amount,
        token_id: b"ERA".to_vec(),
        mode: TransactionMode::Unilateral,
        nonce: vec![9u8; 12],
        verification: VerificationType::Standard,
        pre_commit: None,
        recipient: receiver_device.to_vec(),
        to: receiver_b32.as_bytes().to_vec(),
        message: "live recipient route test".to_string(),
        signature: vec![0x5Au8; 64],
    };

    let submission = B0xSubmissionParams {
        recipient_device_id: receiver_b32.clone(),
        recipient_genesis_hash: text_id::encode_base32_crockford(&receiver_genesis),
        transaction: op,
        signature: vec![0x5Au8; 64],
        sender_genesis_hash: text_id::encode_base32_crockford(&sender_genesis),
        sender_chain_tip: text_id::encode_base32_crockford(&initial_tip),
        sender_signing_public_key: vec![0x33u8; 64],
        ttl_seconds: 0,
        seq: 1,
        next_chain_tip: Some(next_tip.to_vec()),
        receipt_commit: vec![],
        routing_address: routing_address.clone(),
        canonical_operation_bytes: vec![],
    };

    let tx_id = sender_b0x
        .submit_to_b0x(submission)
        .await
        .expect("sender submit");
    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

    let retrieved = receiver_b0x
        .retrieve_from_b0x_v2(&routing_address, 10)
        .await
        .expect("receiver retrieve");
    let entry = retrieved
        .iter()
        .find(|entry| entry.transaction_id == tx_id)
        .expect("receiver must see submitted tx");
    assert_eq!(entry.recipient_device_id, receiver_b32);
    assert_eq!(entry.sender_device_id, sender_b32);
    assert_eq!(
        entry.next_chain_tip,
        text_id::encode_base32_crockford(&next_tip),
        "receiver should observe the posted successor tip",
    );

    receiver_b0x
        .acknowledge_b0x_v2(&routing_address, vec![tx_id.clone()])
        .await
        .expect("receiver ack");
    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

    let entries_after_ack = receiver_b0x
        .retrieve_from_b0x_v2(&routing_address, 10)
        .await
        .expect("receiver retrieve after ack");
    assert!(
        entries_after_ack
            .iter()
            .all(|entry| entry.transaction_id != tx_id),
        "receiver inbox should no longer expose the ACKed message",
    );
}
