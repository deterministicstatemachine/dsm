// SPDX-License-Identifier: MIT OR Apache-2.0
// Quick BLE smoke tests: fast and deterministic, protobuf-only.

#![allow(clippy::disallowed_methods)]

use std::sync::Arc;

use prost::Message;
use tokio::sync::RwLock;

use dsm_sdk as sdk;
use sdk::bluetooth::bilateral_transport_adapter::{
    BilateralTransportAdapter, BleTransportDelegate, TransportInboundMessage,
};
use sdk::bluetooth::ble_frame_coordinator::{BleFrameCoordinator, BleFrameType, FrameIngressResult};
use sdk::bluetooth::bilateral_ble_handler::BilateralBleHandler;
use dsm::core::bilateral_transaction_manager::BilateralTransactionManager;

#[tokio::test]
async fn ble_smoke_basic_chunk_roundtrip() {
    // Build a simple single-chunk BLE frame and verify reassembly returns original payload
    let payload = vec![0xAB; 64];

    // Minimal BLE handler + coordinator
    let device_id = [0u8; 32];
    let genesis_hash = [0u8; 32];
    let keypair = dsm::crypto::signatures::SignatureKeyPair::generate_from_entropy(&[0x01; 32])
        .unwrap_or_else(|e| panic!("generate keypair failed: {e}"));
    let contact_manager = dsm::core::contact_manager::DsmContactManager::new(device_id, vec![]);
    let _manager = Arc::new(RwLock::new(BilateralTransactionManager::new(
        contact_manager,
        keypair,
        device_id,
        genesis_hash,
    )));

    let coord = BleFrameCoordinator::new(device_id);
    let chunks = coord
        .chunk_message(BleFrameType::Unspecified, &payload)
        .unwrap_or_else(|e| panic!("chunk_message failed: {e}"));
    assert_eq!(chunks.len(), 1);

    let ingress = coord
        .ingest_chunk(&chunks[0])
        .await
        .unwrap_or_else(|e| panic!("ingest_chunk failed: {e}"));
    match ingress {
        FrameIngressResult::MessageComplete { message } => {
            assert_eq!(message.payload, payload);
        }
        other => panic!("expected complete message, got {other:?}"),
    }
}

// This test requires bilateral contact verification and end-to-end coordinator semantics.
// On non-Android/non-BLE builds, skip to avoid environment-specific failures.
#[cfg_attr(not(all(target_os = "android", feature = "bluetooth")), ignore)]
#[tokio::test]
async fn ble_smoke_prepare_roundtrip() {
    // Test prepare message chunking and reassembly (without full bilateral validation)
    let device_id = [0x11; 32];
    let recipient_id = [0x33; 32];
    let genesis_hash = [0x22; 32];
    let keypair = dsm::crypto::signatures::SignatureKeyPair::generate_from_entropy(&[0x02; 32])
        .unwrap_or_else(|e| panic!("generate keypair failed: {e}"));
    let mut contact_manager = dsm::core::contact_manager::DsmContactManager::new(
        device_id,
        vec![dsm::types::identifiers::NodeId::new("local")],
    );

    // Add recipient as verified contact first (bilateral requires verified contacts)
    let contact = dsm::types::contact_types::DsmVerifiedContact {
        alias: "test_contact".to_string(),
        device_id: recipient_id,
        genesis_hash,
        public_key: vec![0; 32],
        genesis_material: vec![0; 32],
        chain_tip: None,
        chain_tip_smt_proof: None,
        genesis_verified_online: true,
        verified_at_commit_height: 1,
        added_at_commit_height: 1,
        last_updated_commit_height: 1,
        verifying_storage_nodes: vec![],
        ble_address: None,
    };
    contact_manager
        .add_verified_contact(contact)
        .unwrap_or_else(|e| panic!("add contact failed: {e}"));

    let mut manager =
        BilateralTransactionManager::new(contact_manager, keypair, device_id, genesis_hash);

    // Establish bilateral relationship before attempting prepare
    manager
        .establish_relationship(&recipient_id)
        .await
        .unwrap_or_else(|e| panic!("establish relationship failed: {e}"));

    let manager = Arc::new(RwLock::new(manager));

    let handler = Arc::new(BilateralBleHandler::new(manager, device_id));
    let adapter = BilateralTransportAdapter::new(handler);
    let coord = BleFrameCoordinator::new(device_id);

    let prepare_payload = adapter
        .create_prepare_message(recipient_id, dsm::types::operations::Operation::Noop, 1)
        .await
        .unwrap_or_else(|e| panic!("prepare payload failed: {e}"));
    let chunks = coord
        .encode_message(BleFrameType::BilateralPrepare, &prepare_payload)
        .unwrap_or_else(|e| panic!("prepare chunks failed: {e}"));

    // Reassemble by feeding the chunks back to the coordinator
    let mut assembled = None;
    for ch in &chunks {
        let maybe = coord
            .ingest_chunk(ch)
            .await
            .unwrap_or_else(|e| panic!("ingest chunk failed: {e}"));
        if let FrameIngressResult::MessageComplete { message } = maybe {
            assembled = Some(message);
        }
    }
    let assembled = assembled.unwrap_or_else(|| panic!("prepare must assemble"));

    let response = adapter
        .on_transport_message(TransportInboundMessage {
            peer_address: "ble-smoke-peer".to_string(),
            frame_type: assembled.frame_type,
            payload: assembled.payload,
        })
        .await
        .unwrap_or_else(|e| panic!("prepare processing failed: {e}"));
    assert!(
        !response.is_empty(),
        "assembled prepare should produce a response"
    );

    // Verify we can frame a response (even if we don't process it fully)
    let mock_response = vec![0x01, 0x02, 0x03]; // minimal payload
    let encoded_chunks = coord
        .chunk_message(BleFrameType::BilateralPrepareResponse, &mock_response)
        .unwrap_or_else(|e| panic!("chunk_message failed: {e}"));
    let encoded_len = encoded_chunks[0].len();
    assert!(encoded_len > 0);
}

#[tokio::test]
async fn ble_smoke_multi_chunk_roundtrip() {
    // Exercise multi-chunk framing (> MAX_BLE_CHUNK_SIZE = 180) and verify
    // reassembly + fallback path returns original payload.
    let device_id = [0x55; 32];
    let genesis_hash = [0x66; 32];
    let keypair = dsm::crypto::signatures::SignatureKeyPair::generate_from_entropy(&[0x03; 32])
        .unwrap_or_else(|e| panic!("generate keypair failed: {e}"));

    // Large payload (pseudo-random pattern) > 3 chunks (e.g., 560 bytes)
    let mut payload = Vec::with_capacity(560);
    for i in 0..560u32 {
        payload.push((i.wrapping_mul(1315423911) & 0xFF) as u8);
    }

    // Minimal contact manager (no verified contact ensures fallback triggers for BilateralPrepare)
    let contact_manager = dsm::core::contact_manager::DsmContactManager::new(device_id, vec![]);
    let _manager = Arc::new(RwLock::new(BilateralTransactionManager::new(
        contact_manager,
        keypair,
        device_id,
        genesis_hash,
    )));

    let coord = BleFrameCoordinator::new(device_id);

    // Chunk using coordinator (BilateralPrepare type)
    // Use Unspecified to exercise pure chunking/reassembly without bilateral processing
    let chunks = coord
        .chunk_message(BleFrameType::Unspecified, &payload)
        .unwrap_or_else(|e| panic!("chunking failed: {e}"));
    assert!(chunks.len() > 1, "must produce multiple chunks");

    // Feed chunks sequentially; only final should produce Some(..) reassembled payload
    let mut assembled = None;
    for (idx, ch) in chunks.iter().enumerate() {
        let maybe = coord
            .ingest_chunk(ch)
            .await
            .unwrap_or_else(|e| panic!("ingest chunk failed: {e}"));
        if idx < chunks.len() - 1 {
            assert!(
                matches!(maybe, FrameIngressResult::NeedMoreChunks),
                "intermediate chunk should not assemble yet"
            );
        } else {
            assert!(
                matches!(maybe, FrameIngressResult::MessageComplete { .. }),
                "last chunk should assemble"
            );
            if let FrameIngressResult::MessageComplete { message } = maybe {
                assembled = Some(message);
            }
        }
    }

    let assembled = assembled.unwrap_or_else(|| panic!("assembled payload missing"));
    assert_eq!(assembled.payload, payload);
}

#[tokio::test]
async fn ble_checksum_mismatch_fails() {
    use sdk::bluetooth::ble_frame_coordinator::BleFrameCoordinator;
    use sdk::generated::{BleChunk, BleFrameType};
    use std::sync::Arc;
    use tokio::sync::RwLock;
    use dsm::core::bilateral_transaction_manager::BilateralTransactionManager;
    use dsm::crypto::signatures::SignatureKeyPair;
    use dsm::core::contact_manager::DsmContactManager;

    let device_id = [0xAA; 32];
    let genesis_hash = [0xBB; 32];
    let keypair = SignatureKeyPair::generate_from_entropy(&[0x11; 32])
        .unwrap_or_else(|e| panic!("generate keypair failed: {e}"));
    let contact_manager = DsmContactManager::new(device_id, vec![]); // no contacts
    let _manager = Arc::new(RwLock::new(BilateralTransactionManager::new(
        contact_manager,
        keypair,
        device_id,
        genesis_hash,
    )));
    let coord = BleFrameCoordinator::new(device_id);

    // Small payload producing single chunk (easier corruption)
    let payload: Vec<u8> = (0..64u8).collect();
    let chunks = coord
        .chunk_message(BleFrameType::Unspecified, &payload)
        .unwrap_or_else(|e| panic!("chunking failed: {e}"));
    assert_eq!(chunks.len(), 1, "expected single chunk for small payload");

    // Decode, corrupt data byte, re-encode without fixing checksum (header checksum now mismatches)
    let original = &chunks[0];
    let mut chunk =
        BleChunk::decode(&original[..]).unwrap_or_else(|e| panic!("decode BleChunk failed: {e}"));
    assert!(chunk.header.is_some());
    // Flip one byte
    if let Some(first) = chunk.data.get_mut(0) {
        *first ^= 0xFF;
    }
    let mut corrupted_buf = Vec::new();
    chunk
        .encode(&mut corrupted_buf)
        .unwrap_or_else(|e| panic!("encode corrupted chunk failed: {e}"));

    // Feeding corrupted chunk should yield checksum mismatch error
    let err = match coord.ingest_chunk(&corrupted_buf).await {
        Ok(_) => panic!("expected checksum error"),
        Err(e) => e,
    };
    let msg = format!("{err}");
    assert!(
        msg.contains("checksum mismatch"),
        "error should reference checksum mismatch, got: {}",
        msg
    );
}
