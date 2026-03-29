// Minimal E2E: submit to own inbox, then retrieve and ack.
#![allow(clippy::disallowed_methods)]

use std::sync::Arc;

use dsm_sdk::sdk::b0x_sdk::{B0xSDK, B0xSubmissionParams};
use dsm_sdk::sdk::core_sdk::CoreSDK;
use dsm_sdk::util::text_id;

#[tokio::main]
async fn main() {
    // Storage nodes the local dev setup uses (multi-node)
    // Use multiple endpoints to exercise quorum replication and merging.
    let endpoints = vec![
        "http://127.0.0.1:8080".to_string(),
        "http://127.0.0.1:8081".to_string(),
        "http://127.0.0.1:8082".to_string(),
        "http://127.0.0.1:8083".to_string(),
        "http://127.0.0.1:8084".to_string(),
    ];

    // Ensure a storage base dir exists (SDK utilities expect it in many code paths)
    let _ = dsm_sdk::storage_utils::set_storage_base_dir(std::path::PathBuf::from(
        "./.dsm_testdata_e2e",
    ));

    let core = Arc::new(CoreSDK::new().expect("CoreSDK init"));
    // Initialize a deterministic genesis so get_current_state works
    core.initialize_with_genesis_state()
        .expect("init genesis state");

    // Create a synthetic 32-byte device id for this E2E
    let dev_bytes = *blake3::hash(b"e2e-device").as_bytes();
    let device_b32 = text_id::encode_base32_crockford(&dev_bytes);

    let mut b0x = B0xSDK::new(device_b32.clone(), core.clone(), endpoints).expect("B0xSDK init");

    // Self as recipient
    let to_device_id = dev_bytes.to_vec();
    let to_device_b32 = text_id::encode_base32_crockford(&to_device_id);
    let genesis = core.local_genesis_hash().await.expect("genesis");
    let genesis_b32 = text_id::encode_base32_crockford(&genesis);

    // Use current state hash as a stand-in for sender/relationship chain tip (self)
    let chain_state = core.get_current_state().expect("current state");
    let recipient_chain_tip_b32 = text_id::encode_base32_crockford(&chain_state.hash);
    let routing_address =
        B0xSDK::compute_b0x_address(&genesis, &to_device_id, &chain_state.hash).expect("routing");

    // Build an Operation::Transfer to ourselves
    let balance_anchor = dsm::crypto::blake3::domain_hash("DSM/balance-anchor", &[]);
    let op = dsm::types::operations::Operation::Transfer {
        to_device_id: to_device_id.clone(),
        amount: dsm::types::token_types::Balance::from_state(1u64, *balance_anchor.as_bytes(), 0),
        token_id: b"ERA".to_vec(),
        mode: dsm::types::operations::TransactionMode::Unilateral,
        nonce: vec![0u8; 32],
        verification: dsm::types::operations::VerificationType::Standard,
        pre_commit: None,
        recipient: to_device_id.clone(),
        to: to_device_b32.clone().into_bytes(),
        message: "e2e".to_string(),
        signature: vec![],
    };

    let params = B0xSubmissionParams {
        recipient_device_id: to_device_b32.clone(),
        recipient_genesis_hash: genesis_b32.clone(),
        transaction: op,
        signature: vec![],
        sender_signing_public_key: Vec::new(),
        sender_genesis_hash: genesis_b32.clone(),
        sender_chain_tip: recipient_chain_tip_b32.clone(),
        ttl_seconds: 3600,
        seq: 0, // Example uses seq=0 for simplicity
        next_chain_tip: Some(chain_state.hash.to_vec()),
        receipt_commit: vec![],
        routing_address: routing_address.clone(),
        canonical_operation_bytes: vec![],
    };

    println!("Submitting to b0x (self)");
    let msg_id = match b0x.submit_to_b0x(params).await {
        Ok(id) => id,
        Err(e) => {
            eprintln!("submit_to_b0x error: {:?}", e);
            std::process::exit(1);
        }
    };
    println!("Submitted message_id={}", msg_id);

    // Retrieve
    let entries = match b0x.retrieve_from_b0x_v2(&routing_address, 20).await {
        Ok(v) => v,
        Err(e) => {
            eprintln!("retrieve error: {:?}", e);
            std::process::exit(2);
        }
    };
    println!("Retrieved {} entries", entries.len());

    let found: Vec<String> = entries.iter().map(|e| e.transaction_id.clone()).collect();
    if !found.contains(&msg_id) {
        eprintln!("ERROR: submitted message not found in inbox");
        std::process::exit(3);
    }
    println!("Found submitted message in inbox");

    // Ack
    if let Err(e) = b0x
        .acknowledge_b0x_v2(&routing_address, vec![msg_id.clone()])
        .await
    {
        eprintln!("ack error: {:?}", e);
        std::process::exit(4);
    }
    println!("Acked {}", msg_id);
}
