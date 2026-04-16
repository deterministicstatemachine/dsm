#![allow(clippy::disallowed_methods)]

use std::collections::HashMap;
use std::env;

use dsm::core::bilateral_transaction_manager::BilateralTransactionManager;
use dsm::core::contact_manager::DsmContactManager;
use dsm::crypto::signatures::SignatureKeyPair;
use dsm::types::contact_types::DsmVerifiedContact;
use dsm::types::error::DeterministicSafetyClass;
use dsm::types::operations::{Operation, TransactionMode, VerificationType};
use dsm::types::token_types::Balance;
use dsm_sdk::sdk::chain_tip_store::SqliteChainTipStore;
use dsm_sdk::storage::client_db::{
    self, get_contact_chain_tip, get_local_bilateral_chain_tip, get_pending_online_outbox,
    record_pending_online_transition, restore_finalized_bilateral_chain_tip, ContactRecord,
};
use dsm_sdk::util::text_id::encode_base32_crockford;
use serial_test::serial;
use tempfile::TempDir;

fn make_transfer_op(
    remote_device_id: [u8; 32],
    amount: u64,
    nonce: Vec<u8>,
    message: &str,
) -> Operation {
    Operation::Transfer {
        to_device_id: remote_device_id.to_vec(),
        amount: Balance::from_state(amount, [0u8; 32]),
        token_id: b"token_1".to_vec(),
        mode: TransactionMode::Bilateral,
        nonce,
        verification: VerificationType::Standard,
        pre_commit: None,
        recipient: remote_device_id.to_vec(),
        to: b"Bob".to_vec(),
        message: message.into(),
        signature: vec![0u8; 64],
    }
}

fn store_online_capable_contact(
    device_id: [u8; 32],
    genesis_hash: [u8; 32],
    alias: &str,
) -> String {
    let contact_id = encode_base32_crockford(&device_id);
    let _ = client_db::remove_contact(&contact_id);
    let contact_record = ContactRecord {
        contact_id: contact_id.clone(),
        device_id: device_id.to_vec(),
        alias: alias.into(),
        genesis_hash: genesis_hash.to_vec(),
        public_key: vec![0u8; 32],
        current_chain_tip: None,
        added_at: 1,
        verified: true,
        verification_proof: None,
        metadata: HashMap::new(),
        ble_address: None,
        status: "OnlineCapable".into(),
        needs_online_reconcile: false,
        last_seen_online_counter: 0,
        last_seen_ble_counter: 0,
        previous_chain_tip: None,
    };
    client_db::store_contact(&contact_record).unwrap();
    contact_id
}

/// Test 1: Offline-vs-Offline Tripwire (same BilateralTransactionManager)
/// Two sibling precommitments may capture the same parent, but once one finalize
/// consumes that parent, the stale sibling must be rejected by Tripwire.
#[tokio::test]
#[serial]
async fn test_offline_offline_tripwire() {
    let alice_dir = TempDir::new().unwrap();
    let alice_db_path = alice_dir.path().join("dsm_tripwire.db");

    unsafe {
        env::set_var("DSM_SDK_TEST_MODE", "1");
        env::set_var("DSM_DB_PATH", alice_db_path.to_str().unwrap());
    }
    client_db::reset_database_for_tests();
    client_db::init_database().unwrap();

    let alice_keypair = SignatureKeyPair::new().unwrap();
    let alice_device_id = [1u8; 32];
    let bob_device_id = [2u8; 32];
    let bob_genesis_hash = [3u8; 32];

    let cm = DsmContactManager::new(alice_device_id, vec![]);
    let chain_tip_store = std::sync::Arc::new(SqliteChainTipStore::new());
    let mut alice_btm = BilateralTransactionManager::new_with_chain_tip_store(
        cm,
        alice_keypair,
        alice_device_id,
        [0u8; 32],
        chain_tip_store,
    );

    // Add Bob as contact
    let bob_contact = DsmVerifiedContact {
        alias: "Bob".into(),
        device_id: bob_device_id,
        genesis_hash: bob_genesis_hash,
        public_key: vec![0u8; 32],
        genesis_material: vec![],
        chain_tip: None,
        chain_tip_smt_proof: None,
        genesis_verified_online: true,
        verified_at_commit_height: 1,
        added_at_commit_height: 1,
        last_updated_commit_height: 1,
        verifying_storage_nodes: vec![],
        ble_address: None,
    };
    alice_btm.add_verified_contact(bob_contact).unwrap();
    let mut smt = dsm::merkle::sparse_merkle_tree::SparseMerkleTree::new(256);
    let anchor = alice_btm
        .establish_relationship(&bob_device_id, &mut smt)
        .await
        .unwrap();
    let initial_tip = anchor.chain_tip;
    store_online_capable_contact(bob_device_id, bob_genesis_hash, "Bob");
    restore_finalized_bilateral_chain_tip(&bob_device_id, &initial_tip).unwrap();

    let precommit1 = alice_btm
        .prepare_offline_transfer(
            &bob_device_id,
            make_transfer_op(bob_device_id, 50, vec![1, 2, 3, 4], "Offline tx 1"),
            3600,
        )
        .await
        .unwrap();
    let precommit2 = alice_btm
        .prepare_offline_transfer(
            &bob_device_id,
            make_transfer_op(bob_device_id, 30, vec![5, 6, 7, 8], "Offline tx 2"),
            3600,
        )
        .await
        .unwrap();

    assert_eq!(precommit1.local_chain_tip_at_creation, Some(initial_tip));
    assert_eq!(precommit2.local_chain_tip_at_creation, Some(initial_tip));
    assert!(
        alice_btm.has_pending_commitment(&precommit1.bilateral_commitment_hash),
        "first precommitment should remain pending until finalize"
    );
    assert!(
        alice_btm.has_pending_commitment(&precommit2.bilateral_commitment_hash),
        "second precommitment should remain pending until it is either finalized or explicitly removed"
    );

    let mut smt = dsm::merkle::sparse_merkle_tree::SparseMerkleTree::new(256);
    let result1 = alice_btm
        .finalize_offline_transfer(
            &bob_device_id,
            &precommit1.bilateral_commitment_hash,
            &[1u8; 32],
            &mut smt,
        )
        .await;

    let first_result = result1.expect("first finalize should consume the shared parent tip");
    assert_ne!(
        first_result.relationship_anchor.chain_tip, initial_tip,
        "first finalize must advance the bilateral chain tip"
    );
    assert_eq!(
        get_contact_chain_tip(&bob_device_id),
        Some(first_result.relationship_anchor.chain_tip),
        "successful finalize must persist the new canonical tip"
    );
    assert!(
        !alice_btm.has_pending_commitment(&precommit1.bilateral_commitment_hash),
        "finalized precommitment should be cleared from the pending set"
    );

    let result2 = alice_btm
        .finalize_offline_transfer(
            &bob_device_id,
            &precommit2.bilateral_commitment_hash,
            &[2u8; 32],
            &mut smt,
        )
        .await;

    match result2 {
        Ok(_) => {
            panic!(
                "INVARIANT VIOLATION: Second finalize succeeded but parent was already consumed!"
            );
        }
        Err(e) => {
            let err_str = e.to_string();
            assert!(
                err_str.contains("Tripwire")
                    && (err_str.contains("advanced since precommitment creation")
                        || err_str.contains("parent hash already consumed")
                        || err_str.contains(DeterministicSafetyClass::ParentConsumed.as_str())),
                "stale finalize should fail with a Tripwire / ParentConsumed error, got: {}",
                err_str
            );
            assert!(
                alice_btm.has_pending_commitment(&precommit2.bilateral_commitment_hash),
                "rejected stale precommitment should remain pending for explicit cleanup / inspection"
            );
            assert_eq!(
                alice_btm.get_chain_tip_for(&bob_device_id),
                Some(first_result.relationship_anchor.chain_tip),
                "rejecting a stale sibling finalize must not mutate the current relationship tip"
            );
        }
    }
}

/// Test 2: Mixed Protocol Modal Lock (Offline precommit, then Online send)
///
/// Sequence:
/// 1) Prepare offline precommit (captures parent tip h_n)
/// 2) Deliver an online transition, which now records a pending outbox gate
///    and advances only the sender's local restore tip to h_{n+1}
/// 3) Canonical finalized tip stays at h_n until recipient ACK / sync catch-up
#[tokio::test]
#[serial]
async fn test_mixed_protocol_modal_lock() {
    let alice_dir = TempDir::new().unwrap();
    let alice_db_path = alice_dir.path().join("dsm.db");

    unsafe {
        env::set_var("DSM_SDK_TEST_MODE", "1");
        env::set_var("DSM_DB_PATH", alice_db_path.to_str().unwrap());
    }
    client_db::reset_database_for_tests();
    client_db::init_database().unwrap();

    let alice_keypair = SignatureKeyPair::new().unwrap();
    let alice_device_id = [1u8; 32];
    let cm = DsmContactManager::new(alice_device_id, vec![]);
    let chain_tip_store = std::sync::Arc::new(SqliteChainTipStore::new());
    let mut alice_offline = BilateralTransactionManager::new_with_chain_tip_store(
        cm,
        alice_keypair,
        alice_device_id,
        [0u8; 32],
        chain_tip_store,
    );

    let bob_device_id = [2u8; 32];
    let bob_genesis_hash = [3u8; 32];

    let bob_contact = DsmVerifiedContact {
        alias: "Bob".into(),
        device_id: bob_device_id,
        genesis_hash: bob_genesis_hash,
        public_key: vec![0u8; 32],
        genesis_material: vec![],
        chain_tip: None,
        chain_tip_smt_proof: None,
        genesis_verified_online: true,
        verified_at_commit_height: 1,
        added_at_commit_height: 1,
        last_updated_commit_height: 1,
        verifying_storage_nodes: vec![],
        ble_address: None,
    };
    alice_offline.add_verified_contact(bob_contact).unwrap();
    let mut smt = dsm::merkle::sparse_merkle_tree::SparseMerkleTree::new(256);
    let anchor = alice_offline
        .establish_relationship(&bob_device_id, &mut smt)
        .await;
    let initial_tip = anchor.unwrap().chain_tip;
    store_online_capable_contact(bob_device_id, bob_genesis_hash, "Bob");
    restore_finalized_bilateral_chain_tip(&bob_device_id, &initial_tip).unwrap();

    let prepare_result = alice_offline
        .prepare_offline_transfer(
            &bob_device_id,
            make_transfer_op(bob_device_id, 50, vec![1, 2, 3, 4], "Offline tx"),
            3600,
        )
        .await;
    let precommit =
        prepare_result.expect("offline prepare should capture the current canonical tip");
    assert_eq!(precommit.local_chain_tip_at_creation, Some(initial_tip));

    let next_tip = [9u8; 32];
    record_pending_online_transition(&bob_device_id, "MSG-1", &initial_tip, &next_tip)
        .expect("a delivered online send should persist a single pending outbox gate");

    assert_eq!(
        client_db::get_contact_chain_tip(&bob_device_id),
        Some(initial_tip),
        "pending online delivery must not advance the canonical finalized tip until ACK"
    );
    assert_eq!(
        get_local_bilateral_chain_tip(&bob_device_id),
        Some(next_tip),
        "sender-side mixed-mode delivery should advance only the local restore tip"
    );

    let pending = get_pending_online_outbox(&bob_device_id)
        .expect("pending outbox lookup should succeed")
        .expect("pending outbox gate should exist");
    assert_eq!(pending.message_id, "MSG-1");
    assert_eq!(pending.parent_tip, initial_tip.to_vec());
    assert_eq!(pending.next_tip, next_tip.to_vec());

    let divergent_next_tip = [7u8; 32];
    let err = record_pending_online_transition(
        &bob_device_id,
        "MSG-2",
        &initial_tip,
        &divergent_next_tip,
    )
    .expect_err("a relationship may have only one outstanding online gate at a time");
    assert!(
        err.to_string().contains("different gate"),
        "divergent second online gate should be rejected, got: {err}"
    );
}
