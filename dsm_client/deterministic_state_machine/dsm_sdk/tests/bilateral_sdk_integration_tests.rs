// SPDX-License-Identifier: MIT OR Apache-2.0
//! Integration tests for bilateral SDK initialization and injection
#![allow(clippy::disallowed_methods)]

use dsm_sdk::bridge::{
    bilateral_handler, install_bilateral_handler, BiAccept, BiCommit, BiPrepare, BiTransfer,
    BilateralHandler,
};
use dsm_sdk::generated as pb;
use dsm_sdk::handlers::BiImpl;
use dsm_sdk::init::SdkConfig;
use prost::Message;
use std::sync::Arc;

fn error_contains(msg: &Option<String>, needle: &str) -> bool {
    msg.as_deref().map(|m| m.contains(needle)).unwrap_or(false)
}

fn init_test_storage() {
    // Hermetic: route any storage usage to a deterministic per-test dir.
    std::env::set_var("DSM_SDK_TEST_MODE", "1");
    let _ =
        dsm_sdk::storage_utils::set_storage_base_dir(std::path::PathBuf::from("./.dsm_testdata"));
}

/// Create a test SDK config
fn test_config() -> SdkConfig {
    SdkConfig {
        node_id: "test-node".to_string(),
        storage_endpoints: vec!["http://127.0.0.1:8080".to_string()],
        enable_offline: true,
    }
}

#[test]
fn biimpl_can_be_created() {
    init_test_storage();
    let config = test_config();
    let bi = BiImpl::new(config);
    // Should not panic
    drop(bi);
}

#[test]
fn biimpl_can_be_installed_as_handler() {
    init_test_storage();
    let config = test_config();
    let bi = Arc::new(BiImpl::new(config));
    install_bilateral_handler(bi.clone());

    // Verify it's installed
    assert!(bilateral_handler().is_some());
}

#[test]
fn biimpl_implements_as_any() {
    init_test_storage();
    let config = test_config();
    let bi = Arc::new(BiImpl::new(config));

    // Cast to trait object
    let handler: Arc<dyn BilateralHandler> = bi.clone();

    // Verify as_any works
    let any_ref = handler.as_any();
    assert!(any_ref.downcast_ref::<BiImpl>().is_some());
}

#[tokio::test]
async fn biimpl_prepare_validates_empty_operation_data() {
    init_test_storage();
    let config = test_config();
    let bi = BiImpl::new(config);

    // Create a BilateralPrepareRequest with empty operation_data
    let req = pb::BilateralPrepareRequest {
        counterparty_device_id: vec![1, 2, 3],
        operation_data: vec![], // Empty - should fail
        validity_iterations: 100,
        expected_genesis_hash: None,
        expected_counterparty_state_hash: None,
        ble_address: String::new(),
        sender_device_id: vec![0u8; 32],
        sender_genesis_hash: Some(pb::Hash32 { v: vec![0u8; 32] }),
        sender_signing_public_key: vec![0u8; 32],
        sender_chain_tip: None,
        ..Default::default()
    };

    let payload = req.encode_to_vec();
    let result = bi.prepare(BiPrepare { payload }).await;

    assert!(!result.success);
    assert!(result.error_message.is_some());
    assert!(error_contains(
        &result.error_message,
        "operation_data is empty"
    ));
}

#[tokio::test]
async fn biimpl_prepare_validates_operation_data_format() {
    init_test_storage();
    let config = test_config();
    let bi = BiImpl::new(config);

    // On non-Android builds, the prepare function just hashes operation_data
    // without parsing it as OnlineTransferRequest. So even "invalid" bytes
    // will succeed. On Android with Bluetooth, this would fail with
    // "Failed to decode OnlineTransferRequest".
    let req = pb::BilateralPrepareRequest {
        counterparty_device_id: vec![1, 2, 3],
        operation_data: vec![0xFF, 0xFF, 0xFF], // Would be invalid on Android
        validity_iterations: 100,
        expected_genesis_hash: None,
        expected_counterparty_state_hash: None,
        ble_address: String::new(),
        sender_device_id: vec![0u8; 32],
        sender_genesis_hash: Some(pb::Hash32 { v: vec![0u8; 32] }),
        sender_signing_public_key: vec![0u8; 64],
        sender_chain_tip: None,
        ..Default::default()
    };

    let payload = req.encode_to_vec();
    let result = bi.prepare(BiPrepare { payload }).await;

    // On non-Android, this should succeed (we just hash the bytes)
    assert!(
        result.success,
        "non-Android prepare should succeed with any operation_data bytes"
    );
}

#[tokio::test]
async fn biimpl_prepare_validates_device_id_length() {
    init_test_storage();
    let config = test_config();
    let bi = BiImpl::new(config);

    // On non-Android builds, the prepare function just hashes operation_data
    // without validating OnlineTransferRequest structure. This test verifies
    // that prepare succeeds even with invalid counterparty_device_id on non-Android.
    // On Android, this would fail with "to_device_id must be 32 bytes".
    let req = pb::BilateralPrepareRequest {
        counterparty_device_id: vec![1; 3], // invalid length (ignored on non-Android)
        operation_data: vec![1, 2, 3, 4],
        validity_iterations: 100,
        expected_genesis_hash: None,
        expected_counterparty_state_hash: None,
        ble_address: String::new(),
        sender_device_id: vec![0u8; 32],
        sender_genesis_hash: Some(pb::Hash32 { v: vec![0u8; 32] }),
        sender_signing_public_key: vec![0u8; 64],
        sender_chain_tip: None,
        ..Default::default()
    };

    let payload = req.encode_to_vec();
    let result = bi.prepare(BiPrepare { payload }).await;

    // On non-Android, this should succeed since we just hash operation_data
    assert!(
        result.success,
        "non-Android prepare should succeed with raw operation_data"
    );
}

#[tokio::test]
async fn biimpl_prepare_computes_deterministic_commitment() {
    init_test_storage();
    let config = test_config();
    let bi = BiImpl::new(config);

    // operation_data is arbitrary payload; BiImpl must commit deterministically over it
    let operation_data = vec![9u8, 8, 7, 6];

    let req = pb::BilateralPrepareRequest {
        counterparty_device_id: vec![0xBB; 32],
        operation_data: operation_data.clone(),
        validity_iterations: 100,
        expected_genesis_hash: None,
        expected_counterparty_state_hash: None,
        ble_address: String::new(),
        sender_device_id: vec![0u8; 32],
        sender_genesis_hash: Some(pb::Hash32 { v: vec![0u8; 32] }),
        sender_signing_public_key: vec![0u8; 64],
        sender_chain_tip: None,
        ..Default::default()
    };

    let payload = req.encode_to_vec();

    // Call prepare twice with same data
    let first = bi
        .prepare(BiPrepare {
            payload: payload.clone(),
        })
        .await;
    let second = bi.prepare(BiPrepare { payload }).await;

    assert!(first.success, "first prepare must succeed");
    assert!(second.success, "second prepare must succeed");

    let first_resp = pb::BilateralPrepareResponse::decode(&*first.result_data)
        .unwrap_or_else(|e| panic!("decode first prepare response failed: {e}"));
    let second_resp = pb::BilateralPrepareResponse::decode(&*second.result_data)
        .unwrap_or_else(|e| panic!("decode second prepare response failed: {e}"));

    // Commitment should be deterministic (same for same operation_data)
    assert_eq!(first_resp.commitment_hash, second_resp.commitment_hash);

    // Non-Android prepare uses a domain-separated deterministic commitment over
    // the raw operation bytes. Plain `blake3::hash` would violate DSM's
    // domain-separation invariant.
    let expected_commitment =
        dsm::crypto::blake3::domain_hash("DSM/bilateral-op-commit", &operation_data);
    assert_eq!(
        first_resp
            .commitment_hash
            .as_ref()
            .unwrap_or_else(|| panic!("missing commitment_hash in first response"))
            .v,
        expected_commitment.as_bytes().to_vec()
    );
}

#[tokio::test]
async fn biimpl_accept_validates_commitment_hash_presence() {
    init_test_storage();
    let config = test_config();
    let bi = BiImpl::new(config);

    // Missing commitment_hash
    let req = pb::BilateralAcceptRequest {
        counterparty_device_id: vec![0xAA; 32],
        commitment_hash: None, // Missing
        local_signature: vec![],
        expected_counterparty_state_hash: None,
        expected_local_state_hash: None,
    };

    let payload = req.encode_to_vec();
    let result = bi.accept(BiAccept { payload }).await;

    assert!(!result.success);
    assert!(error_contains(
        &result.error_message,
        "commitment_hash missing"
    ));
}

#[tokio::test]
async fn biimpl_accept_validates_commitment_hash_length() {
    init_test_storage();
    let config = test_config();
    let bi = BiImpl::new(config);

    // Wrong commitment_hash length
    let req = pb::BilateralAcceptRequest {
        counterparty_device_id: vec![0xAA; 32],
        commitment_hash: Some(pb::Hash32 { v: vec![1, 2, 3] }), // Only 3 bytes
        local_signature: vec![],
        expected_counterparty_state_hash: None,
        expected_local_state_hash: None,
    };

    let payload = req.encode_to_vec();
    let result = bi.accept(BiAccept { payload }).await;

    assert!(!result.success);
    assert!(error_contains(
        &result.error_message,
        "commitment_hash must be 32 bytes"
    ));
}

#[tokio::test]
async fn biimpl_accept_succeeds_with_valid_commitment() {
    let config = test_config();
    let bi = BiImpl::new(config);

    let req = pb::BilateralAcceptRequest {
        counterparty_device_id: vec![0xAA; 32],
        commitment_hash: Some(pb::Hash32 { v: vec![0xFF; 32] }),
        local_signature: vec![],
        expected_counterparty_state_hash: None,
        expected_local_state_hash: None,
    };

    let payload = req.encode_to_vec();
    let result = bi.accept(BiAccept { payload }).await;

    // No synthetics: accept must fail-closed unless performed by the BLE session engine.
    assert!(!result.success);
    assert!(error_contains(
        &result.error_message,
        "bilateral.accept disabled"
    ));
}

#[tokio::test]
async fn biimpl_commit_validates_commitment_hash_presence() {
    let config = test_config();
    let bi = BiImpl::new(config);

    let req = pb::BilateralCommitRequest {
        counterparty_device_id: vec![0xAA; 32],
        commitment_hash: None, // Missing
        local_signature: vec![],
        counterparty_sig: vec![],
        expected_local_state_hash: Some(pb::Hash32 { v: vec![0u8; 32] }),
        expected_counterparty_state_hash: Some(pb::Hash32 { v: vec![0u8; 32] }),
        sender_post_finalize_chain_tip: None,
    };

    let payload = req.encode_to_vec();
    let result = bi.commit(BiCommit { payload }).await;

    assert!(!result.success);
    assert!(error_contains(
        &result.error_message,
        "commitment_hash missing"
    ));
}

#[tokio::test]
async fn biimpl_commit_validates_commitment_hash_length() {
    let config = test_config();
    let bi = BiImpl::new(config);

    let req = pb::BilateralCommitRequest {
        counterparty_device_id: vec![0xAA; 32],
        commitment_hash: Some(pb::Hash32 { v: vec![1, 2] }), // Only 2 bytes
        local_signature: vec![],
        counterparty_sig: vec![],
        expected_local_state_hash: Some(pb::Hash32 { v: vec![0u8; 32] }),
        expected_counterparty_state_hash: Some(pb::Hash32 { v: vec![0u8; 32] }),
        sender_post_finalize_chain_tip: None,
    };

    let payload = req.encode_to_vec();
    let result = bi.commit(BiCommit { payload }).await;

    assert!(!result.success);
    assert!(error_contains(
        &result.error_message,
        "commitment_hash must be 32 bytes"
    ));
}

#[tokio::test]
async fn biimpl_commit_echoes_commitment_hash() {
    let config = test_config();
    let bi = BiImpl::new(config);

    let commitment = vec![0xCC; 32];
    let req = pb::BilateralCommitRequest {
        counterparty_device_id: vec![0xAA; 32],
        commitment_hash: Some(pb::Hash32 {
            v: commitment.clone(),
        }),
        local_signature: vec![0x01; 64],  // Must be non-empty
        counterparty_sig: vec![0x02; 64], // Must be non-empty
        expected_local_state_hash: Some(pb::Hash32 { v: vec![0u8; 32] }),
        expected_counterparty_state_hash: Some(pb::Hash32 { v: vec![0u8; 32] }),
        sender_post_finalize_chain_tip: None,
    };

    let payload = req.encode_to_vec();
    let result = bi.commit(BiCommit { payload }).await;

    // No synthetics: commit must fail-closed unless performed by the BLE session engine.
    assert!(!result.success);
    assert!(error_contains(
        &result.error_message,
        "bilateral.commit disabled"
    ));
}

#[tokio::test]
async fn biimpl_transfer_validates_commitment_hash_presence() {
    let config = test_config();
    let bi = BiImpl::new(config);

    let req = pb::BilateralTransferRequest {
        counterparty_device_id: vec![0xAA; 32],
        commitment_hash: None, // Missing
        counterparty_sig: vec![],
        operation_data: vec![],
        expected_genesis_hash: Some(pb::Hash32 { v: vec![0u8; 32] }),
        expected_counterparty_state_hash: Some(pb::Hash32 { v: vec![0u8; 32] }),
        expected_local_state_hash: Some(pb::Hash32 { v: vec![0u8; 32] }),
    };

    let payload = req.encode_to_vec();
    let result = bi.transfer(BiTransfer { payload }).await;

    assert!(!result.success);
    assert!(error_contains(
        &result.error_message,
        "commitment_hash missing"
    ));
}

#[tokio::test]
async fn biimpl_transfer_validates_commitment_hash_length() {
    let config = test_config();
    let bi = BiImpl::new(config);

    let req = pb::BilateralTransferRequest {
        counterparty_device_id: vec![0xAA; 32],
        commitment_hash: Some(pb::Hash32 { v: vec![1; 16] }), // Only 16 bytes
        counterparty_sig: vec![],
        operation_data: vec![],
        expected_genesis_hash: Some(pb::Hash32 { v: vec![0u8; 32] }),
        expected_counterparty_state_hash: Some(pb::Hash32 { v: vec![0u8; 32] }),
        expected_local_state_hash: Some(pb::Hash32 { v: vec![0u8; 32] }),
    };

    let payload = req.encode_to_vec();
    let result = bi.transfer(BiTransfer { payload }).await;

    assert!(!result.success);
    assert!(error_contains(
        &result.error_message,
        "commitment_hash must be 32 bytes"
    ));
}

#[tokio::test]
async fn biimpl_transfer_succeeds_with_valid_commitment() {
    let config = test_config();
    let bi = BiImpl::new(config);

    let req = pb::BilateralTransferRequest {
        counterparty_device_id: vec![0xAA; 32],
        commitment_hash: Some(pb::Hash32 { v: vec![0xFF; 32] }),
        counterparty_sig: vec![1],
        operation_data: vec![1, 0, 0, 0, 0, 0, 0, 0], // amount=1 (LE)
        expected_genesis_hash: Some(pb::Hash32 { v: vec![0u8; 32] }),
        expected_counterparty_state_hash: Some(pb::Hash32 { v: vec![0u8; 32] }),
        expected_local_state_hash: Some(pb::Hash32 { v: vec![0u8; 32] }),
    };

    let payload = req.encode_to_vec();
    let result = bi.transfer(BiTransfer { payload }).await;

    // No synthetics: transfer must fail-closed unless performed by the BLE session engine.
    assert!(!result.success);
    assert!(error_contains(
        &result.error_message,
        "bilateral.transfer disabled"
    ));
}

/// Transfer should fail when operation_data encodes zero amount (first 8 LE == 0)
#[tokio::test]
async fn biimpl_transfer_rejects_zero_amount() {
    let config = test_config();
    let bi = BiImpl::new(config);

    let req = pb::BilateralTransferRequest {
        counterparty_device_id: vec![0xAA; 32],
        commitment_hash: Some(pb::Hash32 { v: vec![0xEE; 32] }),
        counterparty_sig: vec![1],
        operation_data: vec![0, 0, 0, 0, 0, 0, 0, 0], // amount=0
        expected_genesis_hash: Some(pb::Hash32 { v: vec![0u8; 32] }),
        expected_counterparty_state_hash: Some(pb::Hash32 { v: vec![0u8; 32] }),
        expected_local_state_hash: Some(pb::Hash32 { v: vec![0u8; 32] }),
    };

    let res = bi
        .transfer(BiTransfer {
            payload: req.encode_to_vec(),
        })
        .await;
    assert!(!res.success);
    assert!(error_contains(
        &res.error_message,
        "amount must be non-zero"
    ));
}

/// Transfer should fail when counterparty_sig is empty
#[tokio::test]
async fn biimpl_transfer_rejects_empty_counterparty_sig() {
    let config = test_config();
    let bi = BiImpl::new(config);

    let req = pb::BilateralTransferRequest {
        counterparty_device_id: vec![0xAA; 32],
        commitment_hash: Some(pb::Hash32 { v: vec![0xDD; 32] }),
        counterparty_sig: vec![],                     // invalid
        operation_data: vec![1, 0, 0, 0, 0, 0, 0, 0], // amount=1
        expected_genesis_hash: Some(pb::Hash32 { v: vec![0u8; 32] }),
        expected_counterparty_state_hash: Some(pb::Hash32 { v: vec![0u8; 32] }),
        expected_local_state_hash: Some(pb::Hash32 { v: vec![0u8; 32] }),
    };

    let res = bi
        .transfer(BiTransfer {
            payload: req.encode_to_vec(),
        })
        .await;
    assert!(!res.success);
    assert!(error_contains(
        &res.error_message,
        "counterparty_sig must be non-empty"
    ));
}

#[tokio::test]
async fn biimpl_prepare_invalid_protobuf_fails() {
    let config = test_config();
    let bi = BiImpl::new(config);

    // Invalid protobuf payload for BilateralPrepareRequest itself
    let result = bi
        .prepare(BiPrepare {
            payload: vec![0xFF; 10],
        })
        .await;

    assert!(!result.success);
    assert!(error_contains(
        &result.error_message,
        "decode BilateralPrepareRequest failed"
    ));
}

#[tokio::test]
async fn biimpl_accept_invalid_protobuf_fails() {
    let config = test_config();
    let bi = BiImpl::new(config);

    let result = bi
        .accept(BiAccept {
            payload: vec![0xFF; 10],
        })
        .await;

    assert!(!result.success);
    assert!(error_contains(
        &result.error_message,
        "decode BilateralAcceptRequest failed"
    ));
}

#[tokio::test]
async fn biimpl_commit_invalid_protobuf_fails() {
    let config = test_config();
    let bi = BiImpl::new(config);

    let result = bi
        .commit(BiCommit {
            payload: vec![0xFF; 10],
        })
        .await;

    assert!(!result.success);
    assert!(error_contains(
        &result.error_message,
        "decode BilateralCommitRequest failed"
    ));
}

#[tokio::test]
async fn biimpl_transfer_invalid_protobuf_fails() {
    let config = test_config();
    let bi = BiImpl::new(config);

    let result = bi
        .transfer(BiTransfer {
            payload: vec![0xFF; 10],
        })
        .await;

    assert!(!result.success);
    assert!(error_contains(
        &result.error_message,
        "decode BilateralTransferRequest failed"
    ));
}

/// Test that commitment computation is consistent across multiple calls
#[tokio::test]
async fn commitment_is_deterministic_across_handlers() {
    let config = test_config();
    let bi = BiImpl::new(config);

    // Fixed operation payload
    let operation_data = vec![5u8, 6, 7, 8];

    let mut commitments = Vec::new();
    for _ in 0..5 {
        let req = pb::BilateralPrepareRequest {
            counterparty_device_id: vec![0x99; 32],
            operation_data: operation_data.clone(),
            validity_iterations: 200,
            expected_genesis_hash: None,
            expected_counterparty_state_hash: None,
            ble_address: String::new(),
            sender_device_id: vec![0u8; 32],
            sender_genesis_hash: Some(pb::Hash32 { v: vec![0u8; 32] }),
            sender_signing_public_key: vec![0u8; 64],
            sender_chain_tip: None,
            ..Default::default()
        };

        let result = bi
            .prepare(BiPrepare {
                payload: req.encode_to_vec(),
            })
            .await;

        assert!(result.success, "prepare should succeed");

        let resp = pb::BilateralPrepareResponse::decode(&*result.result_data)
            .unwrap_or_else(|e| panic!("decode prepare response failed: {e}"));
        commitments.push(
            resp.commitment_hash
                .unwrap_or_else(|| panic!("missing commitment_hash in prepare response"))
                .v,
        );
    }

    // All commitments should be identical
    assert_eq!(commitments.len(), 5);
    for i in 1..commitments.len() {
        assert_eq!(
            commitments[0], commitments[i],
            "Commitment at index {} differs",
            i
        );
    }
}
