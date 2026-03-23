// SPDX-License-Identifier: MIT OR Apache-2.0
// Full offline bilateral flow unit test (prepare -> accept -> commit -> finalize)

// TODO: Replace unwrap_or_else calls with proper Result-returning test structure
// This allowance is temporary until the test is refactored to return Result<(), Error>
#![allow(clippy::disallowed_methods)]

use std::sync::Arc;
use tokio::sync::RwLock;

use dsm_sdk as sdk;
use sdk::bluetooth::bilateral_ble_handler::BilateralBleHandler;
use sdk::handlers::bilateral_settlement::DefaultBilateralSettlementDelegate;
use dsm::core::bilateral_transaction_manager::BilateralTransactionManager;
use dsm::types::operations::Operation;
use dsm::types::token_types::Balance;
use dsm_sdk::storage::client_db;
use dsm_sdk::util::text_id;
use serial_test::serial;

fn dev(id: u8) -> [u8; 32] {
    [id; 32]
}

fn configure_local_identity_for_receipts(
    device_id: [u8; 32],
    genesis_hash: [u8; 32],
    public_key: Vec<u8>,
) {
    sdk::sdk::app_state::AppState::set_identity_info(
        device_id.to_vec(),
        public_key,
        genesis_hash.to_vec(),
        vec![0u8; 32],
    );
    sdk::sdk::app_state::AppState::set_has_identity(true);

    let stored_root = sdk::sdk::app_state::AppState::get_device_tree_root()
        .expect("device_tree_root must be derived from local identity");
    let expected_root = dsm::common::device_tree::DeviceTree::single(device_id).root();
    assert_eq!(
        stored_root.as_slice(),
        expected_root.as_slice(),
        "AppState must contain the canonical single-device R_G"
    );
    assert_eq!(
        sdk::sdk::app_state::AppState::get_genesis_hash(),
        Some(genesis_hash.to_vec()),
        "AppState must expose the local genesis hash for receipt construction"
    );
}

/// Archive a genesis state with ERA balance to BCR so that the settlement
/// layer's `latest_archived_state` returns a state with funds.
fn seed_bcr_genesis_with_era(device_id: [u8; 32], public_key: &[u8], era_balance: u64) {
    use dsm::types::state_builder::StateBuilder;
    use dsm::types::state_types::DeviceInfo;

    let policy_commit = *dsm_sdk::policy::builtins::NATIVE_POLICY_COMMIT;
    let balance_key =
        dsm::core::token::derive_canonical_balance_key(&policy_commit, public_key, "ERA");

    let mut balances = std::collections::HashMap::new();
    balances.insert(balance_key, Balance::from_state(era_balance, [0u8; 32], 0));

    let mut state = StateBuilder::new()
        .with_id("genesis".to_string())
        .with_state_number(0)
        .with_entropy(vec![0u8; 32])
        .with_prev_state_hash([0u8; 32])
        .with_operation(Operation::Generic {
            operation_type: b"genesis".to_vec(),
            data: vec![],
            message: String::new(),
            signature: vec![],
        })
        .with_device_info(DeviceInfo {
            device_id,
            public_key: public_key.to_vec(),
            metadata: Vec::new(),
        })
        .with_token_balances(balances)
        .build()
        .expect("genesis state should build");

    state.hash = state.compute_hash().expect("compute hash");
    client_db::store_bcr_state(&state, true).expect("seed BCR genesis");
}

#[tokio::test]
#[serial]
async fn bilateral_offline_prepare_accept_commit_finalize_flow() {
    // Use in-memory DB for tests (avoids stale on-disk DB issues).
    std::env::set_var("DSM_SDK_TEST_MODE", "1");
    let _ =
        dsm_sdk::storage_utils::set_storage_base_dir(std::path::PathBuf::from("./.dsm_testdata"));
    client_db::reset_database_for_tests();
    if let Err(e) = client_db::init_database() {
        eprintln!("[bilateral_full_offline_flow] init_database skipped (already init): {e}");
    }

    // Setup devices and managers
    let a_dev = dev(0xA1);
    let b_dev = dev(0xB2);
    let a_gen = dev(0xA2);
    let b_gen = dev(0xB3);

    let a_kp = dsm::crypto::signatures::SignatureKeyPair::generate_from_entropy(b"a-kp")
        .unwrap_or_else(|e| panic!("a keypair failed: {e}"));
    let b_kp = dsm::crypto::signatures::SignatureKeyPair::generate_from_entropy(b"b-kp")
        .unwrap_or_else(|e| panic!("b keypair failed: {e}"));

    let a_cm = dsm::core::contact_manager::DsmContactManager::new(
        a_dev,
        vec![dsm::types::identifiers::NodeId::new("n")],
    );
    let b_cm = dsm::core::contact_manager::DsmContactManager::new(
        b_dev,
        vec![dsm::types::identifiers::NodeId::new("n")],
    );

    let mut mgr_a = BilateralTransactionManager::new(a_cm, a_kp.clone(), a_dev, a_gen);
    let mut mgr_b = BilateralTransactionManager::new(b_cm, b_kp.clone(), b_dev, b_gen);

    // Add verified contacts to each manager for the other device (with signing keys)
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
        ble_address: None,
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
        ble_address: None,
    };

    mgr_a
        .add_verified_contact(contact_b.clone())
        .unwrap_or_else(|e| panic!("add contact b failed: {e}"));
    mgr_b
        .add_verified_contact(contact_a.clone())
        .unwrap_or_else(|e| panic!("add contact a failed: {e}"));

    // Establish relationships on both sides (ensures chain tips + keys set)
    mgr_a
        .establish_relationship(&b_dev)
        .await
        .unwrap_or_else(|e| panic!("establish relationship a->b failed: {e}"));
    mgr_b
        .establish_relationship(&a_dev)
        .await
        .unwrap_or_else(|e| panic!("establish relationship b->a failed: {e}"));

    let a = Arc::new(RwLock::new(mgr_a));
    let b = Arc::new(RwLock::new(mgr_b));

    // Seed sender's ERA balance in BCR (authoritative for settlement).
    // The balance projection is synced automatically by the settlement layer
    // after reconciliation, using the canonical balance key.
    seed_bcr_genesis_with_era(a_dev, a_kp.public_key(), 10_000);

    let delegate = Arc::new(DefaultBilateralSettlementDelegate);
    let mut handler_a = BilateralBleHandler::new(a.clone(), a_dev);
    handler_a.set_settlement_delegate(delegate.clone());
    let mut handler_b = BilateralBleHandler::new(b.clone(), b_dev);
    handler_b.set_settlement_delegate(delegate.clone());

    // Use a Transfer operation to exercise balance update on receiver
    let balance = Balance::from_state(10, [1u8; 32], 0);
    let transfer_op = Operation::Transfer {
        to_device_id: b"to_b".to_vec(),
        amount: balance,
        token_id: b"".to_vec(),
        mode: dsm::types::operations::TransactionMode::Bilateral,
        nonce: vec![0u8; 8],
        verification: dsm::types::operations::VerificationType::Standard,
        pre_commit: None,
        recipient: b"recipient".to_vec(),
        to: b"to".to_vec(),
        message: "pay".to_string(),
        signature: Vec::new(),
    };

    // Sender prepares
    let (prepare_bytes, commitment) = handler_a
        .prepare_bilateral_transaction(b_dev, transfer_op.clone(), 300)
        .await
        .unwrap_or_else(|e| panic!("prepare failed: {e}"));

    // Ensure manager A has pending commitment
    {
        let ma = a.read().await;
        assert!(ma.has_pending_commitment(&commitment));
    }

    // Receiver handles prepare request
    handler_b
        .handle_prepare_request(&prepare_bytes, None)
        .await
        .unwrap_or_else(|e| panic!("handle_prepare_request failed: {e}"));

    // Receiver accepts and builds response (origin commit hash used here)
    let accept_envelope = handler_b
        .create_prepare_accept_envelope(commitment)
        .await
        .unwrap_or_else(|e| panic!("create_accept failed: {e}"));

    // Sender handles prepare response -> builds confirm envelope (3-step protocol step 3)
    configure_local_identity_for_receipts(a_dev, a_gen, a_kp.public_key().to_vec());
    let (confirm_envelope, _meta) = handler_a
        .handle_prepare_response(&accept_envelope)
        .await
        .unwrap_or_else(|e| panic!("handle_prepare_response failed: {e}"));

    // Receiver handles confirm request and both sides finalize
    configure_local_identity_for_receipts(b_dev, b_gen, b_kp.public_key().to_vec());
    let _meta = handler_b
        .handle_confirm_request(&confirm_envelope)
        .await
        .unwrap_or_else(|e| panic!("handle_confirm_request failed: {e}"));

    // Sender already finalized in send_bilateral_confirm(); ensure commitment cleared
    {
        let ma = a.read().await;
        assert!(!ma.has_pending_commitment(&commitment));
    }

    // Receiver settlement is persisted as bilateral chain advancement plus
    // transaction history. Balance projections are derived lazily from
    // canonical state/cache reads and are no longer required to exist here.
    let device_txt = text_id::encode_base32_crockford(&b_dev);
    let history = client_db::get_transaction_history(Some(&device_txt), Some(20))
        .expect("receiver transaction history");
    assert!(
        history.iter().any(|tx| {
            tx.amount == 10
                && tx.from_device == text_id::encode_base32_crockford(&a_dev)
                && tx.to_device == device_txt
                && !tx.metadata.contains_key("token_id")
        }),
        "receiver transaction history should record the settled ERA transfer"
    );
}

// Ensure sender/receiver see identical chain tips and transaction hash across layers
#[tokio::test]
#[serial]
async fn bilateral_offline_state_consistency_across_peers() {
    // Use in-memory DB for tests.
    std::env::set_var("DSM_SDK_TEST_MODE", "1");
    let _ =
        dsm_sdk::storage_utils::set_storage_base_dir(std::path::PathBuf::from("./.dsm_testdata"));
    client_db::reset_database_for_tests();
    if let Err(e) = client_db::init_database() {
        eprintln!("[bilateral_full_offline_flow] init_database skipped (already init): {e}");
    }

    let a_dev = dev(0xC1);
    let b_dev = dev(0xD2);
    let a_gen = dev(0xC2);
    let b_gen = dev(0xD3);

    let a_kp = dsm::crypto::signatures::SignatureKeyPair::generate_from_entropy(b"a-kp")
        .unwrap_or_else(|e| panic!("a keypair failed: {e}"));
    let b_kp = dsm::crypto::signatures::SignatureKeyPair::generate_from_entropy(b"b-kp")
        .unwrap_or_else(|e| panic!("b keypair failed: {e}"));

    let a_cm = dsm::core::contact_manager::DsmContactManager::new(
        a_dev,
        vec![dsm::types::identifiers::NodeId::new("n")],
    );
    let b_cm = dsm::core::contact_manager::DsmContactManager::new(
        b_dev,
        vec![dsm::types::identifiers::NodeId::new("n")],
    );

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
        ble_address: None,
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
        ble_address: None,
    };

    mgr_a
        .add_verified_contact(contact_b.clone())
        .unwrap_or_else(|e| panic!("add contact b failed: {e}"));
    mgr_b
        .add_verified_contact(contact_a.clone())
        .unwrap_or_else(|e| panic!("add contact a failed: {e}"));

    mgr_a
        .establish_relationship(&b_dev)
        .await
        .unwrap_or_else(|e| panic!("establish relationship a->b failed: {e}"));
    mgr_b
        .establish_relationship(&a_dev)
        .await
        .unwrap_or_else(|e| panic!("establish relationship b->a failed: {e}"));

    let a = Arc::new(RwLock::new(mgr_a));
    let b = Arc::new(RwLock::new(mgr_b));

    // Seed sender's ERA balance in BCR (authoritative for settlement).
    seed_bcr_genesis_with_era(a_dev, a_kp.public_key(), 1_000);

    let delegate = Arc::new(DefaultBilateralSettlementDelegate);
    let mut handler_a = BilateralBleHandler::new(a.clone(), a_dev);
    handler_a.set_settlement_delegate(delegate.clone());
    let mut handler_b = BilateralBleHandler::new(b.clone(), b_dev);
    handler_b.set_settlement_delegate(delegate.clone());

    let balance = Balance::from_state(5, [2u8; 32], 0);
    let transfer_op = Operation::Transfer {
        to_device_id: b"to_b".to_vec(),
        amount: balance,
        token_id: b"".to_vec(),
        mode: dsm::types::operations::TransactionMode::Bilateral,
        nonce: vec![0u8; 8],
        verification: dsm::types::operations::VerificationType::Standard,
        pre_commit: None,
        recipient: b"recipient".to_vec(),
        to: b"to".to_vec(),
        message: "pay".to_string(),
        signature: Vec::new(),
    };

    let (prepare_bytes, commitment) = handler_a
        .prepare_bilateral_transaction(b_dev, transfer_op.clone(), 300)
        .await
        .unwrap_or_else(|e| panic!("prepare failed: {e}"));

    handler_b
        .handle_prepare_request(&prepare_bytes, None)
        .await
        .unwrap_or_else(|e| panic!("handle_prepare_request failed: {e}"));

    let accept_envelope = handler_b
        .create_prepare_accept_envelope(commitment)
        .await
        .unwrap_or_else(|e| panic!("create_accept failed: {e}"));

    // Sender handles prepare response -> builds confirm envelope (3-step protocol step 3)
    configure_local_identity_for_receipts(a_dev, a_gen, a_kp.public_key().to_vec());
    let (confirm_envelope, _meta) = handler_a
        .handle_prepare_response(&accept_envelope)
        .await
        .unwrap_or_else(|e| panic!("handle_prepare_response failed: {e}"));

    // Receiver handles confirm request — both sides finalize
    configure_local_identity_for_receipts(b_dev, b_gen, b_kp.public_key().to_vec());
    let _meta = handler_b
        .handle_confirm_request(&confirm_envelope)
        .await
        .unwrap_or_else(|e| panic!("handle_confirm_request failed: {e}"));

    let a_anchor = {
        a.read()
            .await
            .get_relationship(&b_dev)
            .unwrap_or_else(|| panic!("a relationship missing"))
    };
    let b_anchor = {
        b.read()
            .await
            .get_relationship(&a_dev)
            .unwrap_or_else(|| panic!("b relationship missing"))
    };

    let a_tip = a_anchor.chain_tip;
    let b_tip = b_anchor.chain_tip;

    // Both peers must agree on the shared chain tip after 3-step confirm
    assert_eq!(
        a_tip, b_tip,
        "shared chain tips must match after bilateral confirm"
    );

    // Both peers must also clear their pending commitments after confirm.
    assert!(
        a.read().await.list_pending_commitments().is_empty(),
        "sender pending commitments should be cleared after confirm"
    );
    assert!(
        b.read().await.list_pending_commitments().is_empty(),
        "receiver pending commitments should be cleared after confirm"
    );

    // Mutual anchor hash identical on both sides
    assert_eq!(a_anchor.mutual_anchor_hash, b_anchor.mutual_anchor_hash);

    let a_device_txt = text_id::encode_base32_crockford(&a_dev);
    let b_device_txt = text_id::encode_base32_crockford(&b_dev);
    let commitment_txt = text_id::encode_base32_crockford(&commitment);
    let a_history =
        client_db::get_transaction_history(Some(&a_device_txt), Some(20)).expect("sender history");
    let b_history = client_db::get_transaction_history(Some(&b_device_txt), Some(20))
        .expect("receiver history");
    let a_tx = a_history
        .iter()
        .find(|tx| tx.tx_id == commitment_txt)
        .unwrap_or_else(|| panic!("sender history missing bilateral tx"));
    let b_tx = b_history
        .iter()
        .find(|tx| tx.tx_id == commitment_txt)
        .unwrap_or_else(|| panic!("receiver history missing bilateral tx"));
    assert_eq!(
        a_tx.tx_hash, b_tx.tx_hash,
        "sender and receiver must record the same bilateral tx hash"
    );

    // Relationship integrity verifier should pass on both peers
    assert!(a
        .read()
        .await
        .verify_relationship_integrity(&b_dev)
        .unwrap_or_else(|e| panic!("verify relationship integrity on a failed: {e}")));
    b.read()
        .await
        .verify_relationship_integrity(&a_dev)
        .unwrap_or_else(|e| panic!("verify relationship integrity on b failed: {:?}", e));
}
