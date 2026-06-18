//! Integration Tests for DSM Bilateral Transaction Flow (clean refactor)
//! - Byte-first; no serde/JSON/base64 in logic
//! - Deterministic keys/IDs using blake3
//! - Separate contact managers for relationship vs tx managers to avoid Clone bounds

#![allow(clippy::disallowed_methods)] // unwrap/expect usage acceptable in deterministic integration tests

use dsm::core::bilateral_relationship_manager::ContactEstablishmentRequest;
use dsm::core::bilateral_transaction_manager::BilateralTransactionManager;
use dsm::core::contact_manager::DsmContactManager;
use dsm::crypto::signatures::SignatureKeyPair;
use dsm::types::identifiers::NodeId;
use dsm::types::operations::{Operation, TransactionMode, VerificationType};
use dsm::types::token_types::Balance;

#[tokio::test]
async fn test_bilateral_transaction_manager_creation() {
    let keypair = SignatureKeyPair::generate_from_entropy(b"it/mgr").expect("keygen");

    let device_id_arr: [u8; 32] = {
        let h = blake3::hash(b"test_device_123");
        let mut a = [0u8; 32];
        a.copy_from_slice(h.as_bytes());
        a
    };
    let contact_manager =
        DsmContactManager::new(device_id_arr, vec![NodeId::new("storage_node_1")]);

    let local_genesis_arr: [u8; 32] = {
        let h = blake3::hash(b"local_genesis");
        let mut a = [0u8; 32];
        a.copy_from_slice(h.as_bytes());
        a
    };

    let manager = BilateralTransactionManager::new(
        contact_manager,
        keypair,
        device_id_arr,
        local_genesis_arr,
    );

    assert_eq!(
        manager.list_relationships().len(),
        0,
        "New manager should have no relationships"
    );
}

#[tokio::test]
async fn test_contact_establishment_request_creation() {
    let keypair = SignatureKeyPair::generate_from_entropy(b"it/contact").expect("keygen");

    let dev_arr: [u8; 32] = {
        let h = blake3::hash(b"device_123");
        let mut a = [0u8; 32];
        a.copy_from_slice(h.as_bytes());
        a
    };
    let gen_arr: [u8; 32] = {
        let h = blake3::hash(b"genesis_abc");
        let mut a = [0u8; 32];
        a.copy_from_slice(h.as_bytes());
        a
    };

    let request = ContactEstablishmentRequest::new(
        dev_arr,
        gen_arr,
        keypair.public_key().to_vec(),
        "TestUser".to_string(),
        Some("Hello!".to_string()),
        &keypair,
    )
    .expect("create request");

    assert_eq!(request.local_device_id, dev_arr);
    assert_eq!(request.contact_alias, "TestUser");
    assert!(!request.signature.is_empty(), "Request should be signed");

    assert!(
        request
            .verify_signature(keypair.public_key())
            .expect("verify"),
        "Request signature should be valid"
    );
}

#[tokio::test]
async fn test_bilateral_relationship_anchor_generation() {
    use dsm::core::bilateral_transaction_manager::BilateralRelationshipAnchor;

    let dev_a: [u8; 32] = {
        let h = blake3::hash(b"device_a");
        let mut a = [0u8; 32];
        a.copy_from_slice(h.as_bytes());
        a
    };
    let gen_a: [u8; 32] = {
        let h = blake3::hash(b"genesis_a");
        let mut a = [0u8; 32];
        a.copy_from_slice(h.as_bytes());
        a
    };
    let dev_b: [u8; 32] = {
        let h = blake3::hash(b"device_b");
        let mut a = [0u8; 32];
        a.copy_from_slice(h.as_bytes());
        a
    };
    let gen_b: [u8; 32] = {
        let h = blake3::hash(b"genesis_b");
        let mut a = [0u8; 32];
        a.copy_from_slice(h.as_bytes());
        a
    };

    let anchor1 = BilateralRelationshipAnchor::new(dev_a, gen_a, dev_b, gen_b);
    let anchor2 = BilateralRelationshipAnchor::new(dev_b, gen_b, dev_a, gen_a);

    assert_eq!(
        anchor1.mutual_anchor_hash, anchor2.mutual_anchor_hash,
        "Mutual anchors must be deterministic and order-independent"
    );
    assert!(
        !anchor1.is_synchronized(),
        "New anchor should not start synchronized"
    );
}

#[test]
fn test_operation_serialization() {
    let op = Operation::Transfer {
        policy_commit: [0u8; 32],
        to_device_id: b"recipient_123".to_vec(),
        amount: {
            let mut b = Balance::zero();
            b.update_add(100);
            b
        },
        token_id: b"DSM_TOKEN".to_vec(),
        mode: TransactionMode::Bilateral,
        nonce: vec![1, 2, 3, 4],
        verification: VerificationType::Bilateral,
        pre_commit: None,
        recipient: b"Bob".to_vec(),
        to: b"recipient_123".to_vec(),
        message: "Test transfer".to_string(),
        signature: vec![],
        authority_policy: None,
    };

    assert_eq!(op.get_operation_type(), "transfer");
    let bytes = op.to_bytes();
    assert!(
        !bytes.is_empty(),
        "Operation should serialize to non-empty bytes"
    );
}
