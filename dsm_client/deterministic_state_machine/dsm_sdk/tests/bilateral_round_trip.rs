// SPDX-License-Identifier: MIT OR Apache-2.0
//! Bilateral offline transfer integration tests for shared single-process mode.
//!
//! These tests use fresh setups per transfer direction so they keep validating
//! bilateral protocol completion, receiver-side settlement, and shared
//! transaction-history visibility without depending on sender-local persistence
//! semantics that differ from two fully independent device databases.

#![allow(clippy::disallowed_methods)]

use std::sync::Arc;
use tokio::sync::RwLock;

use dsm::core::bilateral_transaction_manager::BilateralTransactionManager;
use dsm::types::operations::Operation;
use dsm::types::token_types::Balance;
use dsm_sdk as sdk;
use dsm_sdk::storage::client_db;
use dsm_sdk::util::text_id;
use sdk::bluetooth::bilateral_ble_handler::BilateralBleHandler;
use sdk::handlers::bilateral_settlement::DefaultBilateralSettlementDelegate;
use serial_test::serial;

// ---------------------------------------------------------------------------
// Test infrastructure (mirrors bilateral_full_offline_flow.rs)
// ---------------------------------------------------------------------------

fn dev(id: u8) -> [u8; 32] {
    [id; 32]
}

struct TestAppRouter {
    device_states:
        std::sync::RwLock<std::collections::HashMap<[u8; 32], dsm::types::state_types::State>>,
}

impl TestAppRouter {
    fn new() -> Self {
        Self {
            device_states: std::sync::RwLock::new(std::collections::HashMap::new()),
        }
    }

    fn set_device_state(&self, state: dsm::types::state_types::State) {
        self.device_states
            .write()
            .unwrap()
            .insert(state.device_info.device_id, state);
    }
}

#[async_trait::async_trait]
impl sdk::bridge::AppRouter for TestAppRouter {
    async fn query(&self, _q: sdk::bridge::AppQuery) -> sdk::bridge::AppResult {
        sdk::bridge::AppResult {
            success: false,
            data: vec![],
            error_message: Some("not implemented in test".into()),
        }
    }
    async fn invoke(&self, _i: sdk::bridge::AppInvoke) -> sdk::bridge::AppResult {
        sdk::bridge::AppResult {
            success: false,
            data: vec![],
            error_message: Some("not implemented in test".into()),
        }
    }
    fn get_device_current_state(&self) -> Option<dsm::types::state_types::State> {
        let device_id = sdk::sdk::app_state::AppState::get_device_id()?;
        let device_id: [u8; 32] = device_id.try_into().ok()?;
        self.device_states.read().ok()?.get(&device_id).cloned()
    }
    fn push_device_state(&self, state: &dsm::types::state_types::State) {
        self.device_states
            .write()
            .unwrap()
            .insert(state.device_info.device_id, state.clone());
    }
    fn sync_balance_cache(&self) {
        // In production this reloads from BCR archive; in tests the push_device_state
        // above is sufficient since we read directly from get_device_current_state.
    }
}

fn configure_local_identity_for_receipts(
    device_id: [u8; 32],
    genesis_hash: [u8; 32],
    public_key: Vec<u8>,
) -> Result<(), Box<dyn std::error::Error>> {
    sdk::sdk::app_state::AppState::set_identity_info(
        device_id.to_vec(),
        public_key,
        genesis_hash.to_vec(),
        vec![0u8; 32],
    );
    sdk::sdk::app_state::AppState::set_has_identity(true);
    Ok(())
}

fn seed_device_state(
    router: &TestAppRouter,
    device_id: [u8; 32],
    public_key: &[u8],
    token_id: &str,
    policy_commit: &[u8; 32],
    balance_amount: u64,
) {
    use dsm::types::state_builder::StateBuilder;
    use dsm::types::state_types::DeviceInfo;

    let balance_key =
        dsm::core::token::derive_canonical_balance_key(policy_commit, public_key, token_id);

    let mut balances = std::collections::HashMap::new();
    balances.insert(
        balance_key,
        Balance::from_state(balance_amount, [0u8; 32], 0),
    );

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
    router.set_device_state(state);
}

#[allow(dead_code)]
struct TwoDeviceSetup {
    handler_a: BilateralBleHandler,
    handler_b: BilateralBleHandler,
    a: Arc<RwLock<BilateralTransactionManager>>,
    b: Arc<RwLock<BilateralTransactionManager>>,
    a_dev: [u8; 32],
    b_dev: [u8; 32],
    a_gen: [u8; 32],
    b_gen: [u8; 32],
    a_kp: dsm::crypto::signatures::SignatureKeyPair,
    b_kp: dsm::crypto::signatures::SignatureKeyPair,
    #[allow(dead_code)]
    router: Arc<TestAppRouter>,
}

async fn setup_two_devices_era(a_id: u8, b_id: u8, a_era: u64, b_era: u64) -> TwoDeviceSetup {
    assert_ne!(a_id, b_id, "Device IDs for A and B must be distinct");
    let a_dev = dev(a_id);
    let b_dev = dev(b_id);
    let a_gen = dev(a_id.wrapping_add(0x10));
    let b_gen = dev(b_id.wrapping_add(0x10));

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
        .add_verified_contact(contact_b)
        .unwrap_or_else(|e| panic!("add contact b failed: {e}"));
    mgr_b
        .add_verified_contact(contact_a)
        .unwrap_or_else(|e| panic!("add contact a failed: {e}"));

    let smt_a = Arc::new(RwLock::new(
        dsm::merkle::sparse_merkle_tree::SparseMerkleTree::new(256),
    ));
    let smt_b = Arc::new(RwLock::new(
        dsm::merkle::sparse_merkle_tree::SparseMerkleTree::new(256),
    ));

    {
        let mut guard = smt_a.write().await;
        mgr_a
            .establish_relationship(&b_dev, &mut guard)
            .await
            .unwrap_or_else(|e| panic!("establish relationship a->b failed: {e}"));
    }
    {
        let mut guard = smt_b.write().await;
        mgr_b
            .establish_relationship(&a_dev, &mut guard)
            .await
            .unwrap_or_else(|e| panic!("establish relationship b->a failed: {e}"));
    }

    let a = Arc::new(RwLock::new(mgr_a));
    let b = Arc::new(RwLock::new(mgr_b));

    let router = Arc::new(TestAppRouter::new());
    sdk::bridge::install_app_router(router.clone()).expect("install test router");

    let policy_commit = *dsm_sdk::policy::builtins::NATIVE_POLICY_COMMIT;
    seed_device_state(
        &router,
        a_dev,
        a_kp.public_key(),
        "ERA",
        &policy_commit,
        a_era,
    );
    seed_device_state(
        &router,
        b_dev,
        b_kp.public_key(),
        "ERA",
        &policy_commit,
        b_era,
    );

    let delegate = Arc::new(DefaultBilateralSettlementDelegate);
    let mut handler_a = BilateralBleHandler::new_with_smt(a.clone(), a_dev, smt_a);
    handler_a.set_settlement_delegate(delegate.clone());
    let mut handler_b = BilateralBleHandler::new_with_smt(b.clone(), b_dev, smt_b);
    handler_b.set_settlement_delegate(delegate.clone());

    TwoDeviceSetup {
        handler_a,
        handler_b,
        a,
        b,
        a_dev,
        b_dev,
        a_gen,
        b_gen,
        a_kp,
        b_kp,
        router,
    }
}

async fn setup_two_devices_dbtc(a_id: u8, b_id: u8, a_dbtc: u64, b_dbtc: u64) -> TwoDeviceSetup {
    assert_ne!(a_id, b_id, "Device IDs for A and B must be distinct");
    let a_dev = dev(a_id);
    let b_dev = dev(b_id);
    let a_gen = dev(a_id.wrapping_add(0x10));
    let b_gen = dev(b_id.wrapping_add(0x10));

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
        .add_verified_contact(contact_b)
        .unwrap_or_else(|e| panic!("add contact b failed: {e}"));
    mgr_b
        .add_verified_contact(contact_a)
        .unwrap_or_else(|e| panic!("add contact a failed: {e}"));

    let smt_a = Arc::new(RwLock::new(
        dsm::merkle::sparse_merkle_tree::SparseMerkleTree::new(256),
    ));
    let smt_b = Arc::new(RwLock::new(
        dsm::merkle::sparse_merkle_tree::SparseMerkleTree::new(256),
    ));

    {
        let mut guard = smt_a.write().await;
        mgr_a
            .establish_relationship(&b_dev, &mut guard)
            .await
            .unwrap_or_else(|e| panic!("establish relationship a->b failed: {e}"));
    }
    {
        let mut guard = smt_b.write().await;
        mgr_b
            .establish_relationship(&a_dev, &mut guard)
            .await
            .unwrap_or_else(|e| panic!("establish relationship b->a failed: {e}"));
    }

    let a = Arc::new(RwLock::new(mgr_a));
    let b = Arc::new(RwLock::new(mgr_b));

    let router = Arc::new(TestAppRouter::new());
    sdk::bridge::install_app_router(router.clone()).expect("install test router");

    let dbtc_policy = *dsm_sdk::policy::builtins::DBTC_POLICY_COMMIT;
    seed_device_state(
        &router,
        a_dev,
        a_kp.public_key(),
        "dBTC",
        &dbtc_policy,
        a_dbtc,
    );
    seed_device_state(
        &router,
        b_dev,
        b_kp.public_key(),
        "dBTC",
        &dbtc_policy,
        b_dbtc,
    );

    let delegate = Arc::new(DefaultBilateralSettlementDelegate);
    let mut handler_a = BilateralBleHandler::new_with_smt(a.clone(), a_dev, smt_a);
    handler_a.set_settlement_delegate(delegate.clone());
    let mut handler_b = BilateralBleHandler::new_with_smt(b.clone(), b_dev, smt_b);
    handler_b.set_settlement_delegate(delegate.clone());

    TwoDeviceSetup {
        handler_a,
        handler_b,
        a,
        b,
        a_dev,
        b_dev,
        a_gen,
        b_gen,
        a_kp,
        b_kp,
        router,
    }
}

fn init_test_db() {
    std::env::set_var("DSM_SDK_TEST_MODE", "1");
    let _ = dsm_sdk::storage_utils::set_storage_base_dir(std::path::PathBuf::from(
        "./.dsm_round_trip_testdata",
    ));
    client_db::reset_database_for_tests();
    if let Err(e) = client_db::init_database() {
        eprintln!("[bilateral_round_trip] init_database skipped (already init): {e}");
    }
}

// ---------------------------------------------------------------------------
// Helper: execute a full 3-phase bilateral transfer (sender → receiver)
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
async fn execute_bilateral_transfer(
    handler_sender: &BilateralBleHandler,
    handler_receiver: &BilateralBleHandler,
    sender_dev: [u8; 32],
    sender_gen: [u8; 32],
    sender_pk: Vec<u8>,
    receiver_dev: [u8; 32],
    receiver_gen: [u8; 32],
    receiver_pk: Vec<u8>,
    amount: u64,
    token_id: &[u8],
) -> [u8; 32] {
    let balance = Balance::from_state(amount, [1u8; 32], 0);
    let transfer_op = Operation::Transfer {
        to_device_id: receiver_dev.to_vec(),
        amount: balance,
        token_id: token_id.to_vec(),
        mode: dsm::types::operations::TransactionMode::Bilateral,
        nonce: vec![0u8; 8],
        verification: dsm::types::operations::VerificationType::Standard,
        pre_commit: None,
        recipient: receiver_pk.clone(),
        to: receiver_dev.to_vec(),
        message: "round-trip-transfer".to_string(),
        signature: Vec::new(),
    };

    // Phase 1: Prepare
    let (prepare_bytes, commitment) = handler_sender
        .prepare_bilateral_transaction(receiver_dev, transfer_op, 300)
        .await
        .unwrap_or_else(|e| panic!("prepare failed: {e}"));

    // Phase 2: Accept
    handler_receiver
        .handle_prepare_request(&prepare_bytes, None)
        .await
        .unwrap_or_else(|e| panic!("handle_prepare_request failed: {e}"));

    let accept_envelope = handler_receiver
        .create_prepare_accept_envelope(commitment)
        .await
        .unwrap_or_else(|e| panic!("create_accept failed: {e}"));

    // Phase 3: Confirm (sender finalizes)
    configure_local_identity_for_receipts(sender_dev, sender_gen, sender_pk.clone())
        .unwrap_or_else(|e| panic!("configure identity for sender failed: {e}"));
    let (confirm_envelope, _meta) = handler_sender
        .handle_prepare_response(&accept_envelope)
        .await
        .unwrap_or_else(|e| panic!("handle_prepare_response failed: {e}"));

    // Phase 3: Confirm (receiver finalizes)
    configure_local_identity_for_receipts(receiver_dev, receiver_gen, receiver_pk)
        .unwrap_or_else(|e| panic!("configure identity for receiver failed: {e}"));
    let commit_response = handler_receiver
        .handle_confirm_request(&confirm_envelope)
        .await
        .unwrap_or_else(|e| panic!("handle_confirm_request failed: {e}"));

    // Phase 3b: Sender processes the commit response so this helper executes
    // the full bilateral offline flow before assertions inspect settlement state.
    configure_local_identity_for_receipts(sender_dev, sender_gen, sender_pk)
        .unwrap_or_else(|e| panic!("configure identity for sender (commit response) failed: {e}"));
    handler_sender
        .handle_commit_response(&commit_response)
        .await
        .unwrap_or_else(|e| panic!("handle_commit_response failed: {e}"));

    // Clean up committed sessions so consecutive transfers don't hit
    // "existing bilateral session in progress" collision.
    handler_sender.clear_terminal_sessions().await;
    handler_receiver.clear_terminal_sessions().await;

    commitment
}

fn assert_receiver_projection(receiver_device_txt: &str, token_id: &str, expected_available: u64) {
    let projection = client_db::get_balance_projection(receiver_device_txt, token_id)
        .unwrap_or_else(|e| panic!("receiver {token_id} projection query failed: {e}"))
        .unwrap_or_else(|| {
            panic!("receiver {token_id} projection must exist in shared single-process mode")
        });
    assert_eq!(
        projection.available, expected_available,
        "receiver {token_id} projection should be {expected_available}, got {}",
        projection.available
    );
}

fn history_contains_transfer(
    history: &[client_db::TransactionRecord],
    commitment_txt: &str,
    sender_device_txt: &str,
    receiver_device_txt: &str,
    amount: u64,
    token_id: Option<&str>,
) -> bool {
    history.iter().any(|tx| {
        tx.tx_id == commitment_txt
            && tx.from_device == sender_device_txt
            && tx.to_device == receiver_device_txt
            && tx.amount == amount
            && match token_id {
                Some(token) => {
                    tx.metadata.get("token_id").map(Vec::as_slice) == Some(token.as_bytes())
                }
                None => !tx.metadata.contains_key("token_id"),
            }
    })
}

fn assert_shared_history_visibility(
    sender_device_txt: &str,
    receiver_device_txt: &str,
    commitment: &[u8; 32],
    amount: u64,
    token_id: Option<&str>,
) {
    let sender_history = client_db::get_transaction_history(Some(sender_device_txt), Some(20))
        .expect("sender transaction history");
    let receiver_history = client_db::get_transaction_history(Some(receiver_device_txt), Some(20))
        .expect("receiver transaction history");
    let commitment_txt = text_id::encode_base32_crockford(commitment);

    assert!(
        history_contains_transfer(
            &sender_history,
            &commitment_txt,
            sender_device_txt,
            receiver_device_txt,
            amount,
            token_id,
        ),
        "sender-visible history must contain transfer {}",
        commitment_txt
    );
    assert!(
        history_contains_transfer(
            &receiver_history,
            &commitment_txt,
            sender_device_txt,
            receiver_device_txt,
            amount,
            token_id,
        ),
        "receiver-visible history must contain transfer {}",
        commitment_txt
    );
}

async fn assert_single_direction_era_transfer(
    a_id: u8,
    b_id: u8,
    a_era: u64,
    b_era: u64,
    sender_is_a: bool,
    amount: u64,
) {
    init_test_db();

    let s = setup_two_devices_era(a_id, b_id, a_era, b_era).await;
    let a_device_txt = text_id::encode_base32_crockford(&s.a_dev);
    let b_device_txt = text_id::encode_base32_crockford(&s.b_dev);

    let (
        handler_sender,
        handler_receiver,
        sender_dev,
        sender_gen,
        sender_pk,
        receiver_dev,
        receiver_gen,
        receiver_pk,
        sender_device_txt,
        receiver_device_txt,
    ) = if sender_is_a {
        (
            &s.handler_a,
            &s.handler_b,
            s.a_dev,
            s.a_gen,
            s.a_kp.public_key().to_vec(),
            s.b_dev,
            s.b_gen,
            s.b_kp.public_key().to_vec(),
            a_device_txt,
            b_device_txt,
        )
    } else {
        (
            &s.handler_b,
            &s.handler_a,
            s.b_dev,
            s.b_gen,
            s.b_kp.public_key().to_vec(),
            s.a_dev,
            s.a_gen,
            s.a_kp.public_key().to_vec(),
            b_device_txt,
            a_device_txt,
        )
    };

    let commitment = execute_bilateral_transfer(
        handler_sender,
        handler_receiver,
        sender_dev,
        sender_gen,
        sender_pk,
        receiver_dev,
        receiver_gen,
        receiver_pk,
        amount,
        b"",
    )
    .await;

    assert_receiver_projection(&receiver_device_txt, "ERA", amount);
    assert_shared_history_visibility(
        &sender_device_txt,
        &receiver_device_txt,
        &commitment,
        amount,
        None,
    );
}

async fn assert_single_direction_dbtc_transfer(
    a_id: u8,
    b_id: u8,
    a_dbtc: u64,
    b_dbtc: u64,
    sender_is_a: bool,
    amount: u64,
) {
    init_test_db();

    let s = setup_two_devices_dbtc(a_id, b_id, a_dbtc, b_dbtc).await;
    let a_device_txt = text_id::encode_base32_crockford(&s.a_dev);
    let b_device_txt = text_id::encode_base32_crockford(&s.b_dev);

    let (
        handler_sender,
        handler_receiver,
        sender_dev,
        sender_gen,
        sender_pk,
        receiver_dev,
        receiver_gen,
        receiver_pk,
        sender_device_txt,
        receiver_device_txt,
    ) = if sender_is_a {
        (
            &s.handler_a,
            &s.handler_b,
            s.a_dev,
            s.a_gen,
            s.a_kp.public_key().to_vec(),
            s.b_dev,
            s.b_gen,
            s.b_kp.public_key().to_vec(),
            a_device_txt,
            b_device_txt,
        )
    } else {
        (
            &s.handler_b,
            &s.handler_a,
            s.b_dev,
            s.b_gen,
            s.b_kp.public_key().to_vec(),
            s.a_dev,
            s.a_gen,
            s.a_kp.public_key().to_vec(),
            b_device_txt,
            a_device_txt,
        )
    };

    let commitment = execute_bilateral_transfer(
        handler_sender,
        handler_receiver,
        sender_dev,
        sender_gen,
        sender_pk,
        receiver_dev,
        receiver_gen,
        receiver_pk,
        amount,
        b"dBTC",
    )
    .await;

    assert_receiver_projection(&receiver_device_txt, "dBTC", amount);
    assert_shared_history_visibility(
        &sender_device_txt,
        &receiver_device_txt,
        &commitment,
        amount,
        Some("dBTC"),
    );
}

// ===========================================================================
// Test 1: Fresh-setup ERA transfers in each direction.
// ===========================================================================

#[tokio::test]
#[serial]
async fn offline_era_single_direction_a_to_b_receiver_projection_and_shared_history() {
    assert_single_direction_era_transfer(0xA1, 0xB2, 10_000, 0, true, 10).await;
}

#[tokio::test]
#[serial]
async fn offline_era_single_direction_b_to_a_receiver_projection_and_shared_history() {
    assert_single_direction_era_transfer(0xA3, 0xB4, 0, 5, false, 5).await;
}

// ===========================================================================
// Test 2: Fresh-setup dBTC transfers in each direction.
// ===========================================================================

#[tokio::test]
#[serial]
async fn offline_dbtc_single_direction_a_to_b_receiver_projection_and_shared_history() {
    assert_single_direction_dbtc_transfer(0xC3, 0xD4, 100, 0, true, 30).await;
}

#[tokio::test]
#[serial]
async fn offline_dbtc_single_direction_b_to_a_receiver_projection_and_shared_history() {
    assert_single_direction_dbtc_transfer(0xC5, 0xD6, 0, 10, false, 10).await;
}

// ===========================================================================
// Test 3: Repeated fresh-setup same-direction transfers.
// ===========================================================================

#[tokio::test]
#[serial]
async fn offline_era_repeated_fresh_setup_same_direction_receiver_projection_and_shared_history() {
    for i in 0..3u32 {
        let a_id = 0xE5u8.wrapping_add((i * 2) as u8);
        let b_id = 0xF6u8.wrapping_add((i * 2) as u8);
        assert_single_direction_era_transfer(a_id, b_id, 10_000, 0, true, 5).await;
    }
}
