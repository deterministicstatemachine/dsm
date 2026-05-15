//! Integration Tests for DSM Bilateral Transaction Flow (clean refactor)
//! - Byte-first; no serde/JSON/base64 in logic
//! - Deterministic keys/IDs using blake3
//! - Separate contact managers for relationship vs tx managers to avoid Clone bounds

#![allow(clippy::disallowed_methods)] // unwrap/expect usage acceptable in deterministic integration tests

use dsm::core::bilateral_relationship_manager::{
    BilateralRelationshipManager, ContactEstablishmentRequest,
};
use dsm::core::bilateral_transaction_manager::BilateralTransactionManager;
use dsm::core::contact_manager::DsmContactManager;
use dsm::crypto::signatures::SignatureKeyPair;
use dsm::types::identifiers::NodeId;
use dsm::types::operations::{Operation, TransactionMode, VerificationType};
use dsm::types::token_types::Balance;

// Minimal human label for a device (UI-only; not used in any hash/commitment)
fn label_for(id: &[u8; 32]) -> String {
    let mut s = String::from("dev:");
    for b in id.iter().take(8) {
        use core::fmt::Write;
        let _ = write!(&mut s, "{:03}", b);
    }
    s
}

#[tokio::test]
async fn test_complete_bilateral_transaction_flow() {
    // Deterministic demo keypairs
    let alice_keypair = SignatureKeyPair::generate_from_entropy(b"it/alice").expect("alice keygen");
    let bob_keypair = SignatureKeyPair::generate_from_entropy(b"it/bob").expect("bob keygen");

    // 32-byte device IDs
    let alice_device_id: [u8; 32] = {
        let h = blake3::hash(b"alice_test_device");
        let mut a = [0u8; 32];
        a.copy_from_slice(h.as_bytes());
        a
    };
    let bob_device_id: [u8; 32] = {
        let h = blake3::hash(b"bob_test_device");
        let mut a = [0u8; 32];
        a.copy_from_slice(h.as_bytes());
        a
    };

    // 32-byte genesis roots
    let alice_genesis: [u8; 32] = {
        let h = blake3::hash(b"alice_genesis_test_hash");
        let mut a = [0u8; 32];
        a.copy_from_slice(h.as_bytes());
        a
    };
    let bob_genesis: [u8; 32] = {
        let h = blake3::hash(b"bob_genesis_test_hash");
        let mut a = [0u8; 32];
        a.copy_from_slice(h.as_bytes());
        a
    };

    // Shared storage node set
    let nodes = vec![NodeId::new("storage_node_1"), NodeId::new("storage_node_2")];

    // Contact managers (distinct instances for tx vs relationship layers)
    let alice_contacts_tx = DsmContactManager::new(alice_device_id, nodes.clone());
    let bob_contacts_tx = DsmContactManager::new(bob_device_id, nodes.clone());
    let alice_contacts_rel = DsmContactManager::new(alice_device_id, nodes.clone());
    let bob_contacts_rel = DsmContactManager::new(bob_device_id, nodes.clone());

    // Bilateral transaction managers
    let alice_btx_manager = BilateralTransactionManager::new(
        alice_contacts_tx,
        alice_keypair.clone(),
        alice_device_id,
        alice_genesis,
    );
    let bob_btx_manager = BilateralTransactionManager::new(
        bob_contacts_tx,
        bob_keypair.clone(),
        bob_device_id,
        bob_genesis,
    );

    // Relationship managers own their own contact managers + the tx managers
    let mut alice_manager = BilateralRelationshipManager::new(
        alice_contacts_rel,
        alice_btx_manager,
        alice_keypair.clone(),
        alice_device_id,
        alice_genesis,
    );
    let mut bob_manager = BilateralRelationshipManager::new(
        bob_contacts_rel,
        bob_btx_manager,
        bob_keypair.clone(),
        bob_device_id,
        bob_genesis,
    );

    // 1) Contact establishment
    let contact_request = ContactEstablishmentRequest::new(
        alice_device_id,
        alice_genesis,
        alice_keypair.public_key().to_vec(),
        "Alice".to_string(),
        Some("Test contact request".to_string()),
        &alice_keypair,
    )
    .expect("create contact request");

    let _outgoing_hash = alice_manager
        .register_outgoing_contact_request(&contact_request)
        .expect("register outgoing");

    let request_hash = bob_manager
        .handle_contact_establishment_request(contact_request.clone())
        .await
        .expect("handle contact request");

    let (_ok, contact_response) = bob_manager
        .accept_contact_request_with_response(&request_hash, Some("Welcome Alice!".to_string()))
        .await
        .expect("accept contact");

    alice_manager
        .handle_contact_establishment_response(contact_response)
        .await
        .expect("alice finalize contact");

    // 2) Relationship establishment
    let alice_relationship = alice_manager
        .get_bilateral_tx_manager_mut()
        .establish_relationship(&bob_device_id)
        .await
        .expect("alice establish relationship");

    let bob_relationship = bob_manager
        .get_bilateral_tx_manager_mut()
        .establish_relationship(&alice_device_id)
        .await
        .expect("bob establish relationship");

    assert_eq!(
        alice_relationship.mutual_anchor_hash, bob_relationship.mutual_anchor_hash,
        "Mutual anchor hashes should match"
    );

    // 3) Pre-commitment creation
    let to_label = label_for(&bob_device_id);
    let mut transfer_operation = Operation::Transfer {
        to_device_id: to_label.clone().into_bytes(),
        amount: {
            let mut b = Balance::zero();
            b.update_add(50);
            b
        },
        token_id: b"TEST_TOKEN".to_vec(),
        mode: TransactionMode::Bilateral,
        nonce: vec![1, 2, 3, 4],
        verification: VerificationType::Bilateral,
        pre_commit: None,
        recipient: b"Bob".to_vec(),
        to: to_label.clone().into_bytes(),
        message: "Test transfer".to_string(),
        signature: vec![],
    };
    // Sign the transfer operation with Alice's keypair
    let transfer_bytes = transfer_operation.to_bytes();
    let transfer_sig = alice_keypair.sign(&transfer_bytes).expect("sign transfer");
    if let Operation::Transfer { signature, .. } = &mut transfer_operation {
        *signature = transfer_sig;
    }

    let alice_precommitment = alice_manager
        .get_bilateral_tx_manager_mut()
        .create_bilateral_precommitment(&bob_device_id, transfer_operation.clone(), 300)
        .await
        .expect("alice precommit");

    let bob_precommitment = bob_manager
        .get_bilateral_tx_manager_mut()
        .create_bilateral_precommitment(&alice_device_id, transfer_operation.clone(), 300)
        .await
        .expect("bob precommit");

    assert!(alice_precommitment.verify().expect("alice pc verify"));
    assert!(bob_precommitment.verify().expect("bob pc verify"));

    // 4) Bilateral transaction execution (Bluetooth)
    let mut smt = dsm::merkle::sparse_merkle_tree::SparseMerkleTree::new(256);
    let alice_tx_result = alice_manager
        .get_bilateral_tx_manager_mut()
        .execute_bilateral_transaction(&bob_device_id, transfer_operation.clone(), true, &mut smt)
        .await
        .expect("alice exec");

    let bob_tx_result = bob_manager
        .get_bilateral_tx_manager_mut()
        .execute_bilateral_transaction(&alice_device_id, transfer_operation, true, &mut smt)
        .await
        .expect("bob exec");

    assert!(
        alice_tx_result.completed_offline,
        "Alice should complete offline"
    );
    assert!(
        bob_tx_result.completed_offline,
        "Bob should complete offline"
    );
    assert!(
        alice_tx_result.relationship_anchor.is_synchronized(),
        "Alice anchor synchronized"
    );
    assert!(
        bob_tx_result.relationship_anchor.is_synchronized(),
        "Bob anchor synchronized"
    );

    // 5) Relationship integrity verification
    let alice_integrity = alice_manager
        .get_bilateral_tx_manager()
        .verify_relationship_integrity(&bob_device_id)
        .expect("alice integrity");
    let bob_integrity = bob_manager
        .get_bilateral_tx_manager()
        .verify_relationship_integrity(&alice_device_id)
        .expect("bob integrity");

    assert!(alice_integrity, "Alice integrity should be valid");
    assert!(bob_integrity, "Bob integrity should be valid");
}

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
    };

    assert_eq!(op.get_operation_type(), "transfer");
    let bytes = op.to_bytes();
    assert!(
        !bytes.is_empty(),
        "Operation should serialize to non-empty bytes"
    );
}
