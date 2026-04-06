// SPDX-License-Identifier: MIT OR Apache-2.0
//! Round-trip bilateral transfer integration tests.
//!
//! Verifies balance synchronization across multiple transfers in both
//! directions — A→B then B→A — and consecutive same-direction transfers.

#![allow(clippy::disallowed_methods)]

use std::sync::Arc;
use tokio::sync::RwLock;

use dsm::core::bilateral_transaction_manager::BilateralTransactionManager;
use dsm::core::contact_manager::DsmContactManager;
use dsm::types::contact_types::DsmVerifiedContact;
use dsm::types::identifiers::NodeId;
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

    let chain_tip_store = Arc::new(dsm_sdk::sdk::chain_tip_store::SqliteChainTipStore::new())
        as Arc<dyn dsm::core::chain_tip_store::ChainTipStore>;
    let mut mgr_a = BilateralTransactionManager::new_with_chain_tip_store(
        a_cm,
        a_kp.clone(),
        a_dev,
        a_gen,
        chain_tip_store.clone(),
    );
    let mut mgr_b = BilateralTransactionManager::new_with_chain_tip_store(
        b_cm,
        b_kp.clone(),
        b_dev,
        b_gen,
        chain_tip_store,
    );

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

    // Capture the deterministic initial bilateral chain tips before moving the
    // managers into Arcs. In production, contacts are persisted with this tip
    // during pairing; recovery paths rely on it as the expected_parent_tip.
    let a_initial_tip = mgr_a
        .get_chain_tip_for(&b_dev)
        .expect("a→b initial chain tip");
    let b_initial_tip = mgr_b
        .get_chain_tip_for(&a_dev)
        .expect("b→a initial chain tip");

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

    persist_contact_pair_to_client_db(
        a_dev,
        a_gen,
        a_kp.public_key(),
        a_initial_tip,
        b_dev,
        b_gen,
        b_kp.public_key(),
        b_initial_tip,
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

    let chain_tip_store = Arc::new(dsm_sdk::sdk::chain_tip_store::SqliteChainTipStore::new())
        as Arc<dyn dsm::core::chain_tip_store::ChainTipStore>;
    let mut mgr_a = BilateralTransactionManager::new_with_chain_tip_store(
        a_cm,
        a_kp.clone(),
        a_dev,
        a_gen,
        chain_tip_store.clone(),
    );
    let mut mgr_b = BilateralTransactionManager::new_with_chain_tip_store(
        b_cm,
        b_kp.clone(),
        b_dev,
        b_gen,
        chain_tip_store,
    );

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

    let a_initial_tip = mgr_a
        .get_chain_tip_for(&b_dev)
        .expect("a→b initial chain tip");
    let b_initial_tip = mgr_b
        .get_chain_tip_for(&a_dev)
        .expect("b→a initial chain tip");

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

    persist_contact_pair_to_client_db(
        a_dev,
        a_gen,
        a_kp.public_key(),
        a_initial_tip,
        b_dev,
        b_gen,
        b_kp.public_key(),
        b_initial_tip,
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

/// Persist a reciprocal pair of contacts to client_db so later lookups
/// (get_contact_chain_tip, get_balance_projection) resolve correctly.
/// Mirrors the real-world pairing flow which stores contacts before any
/// transfer — including the deterministic initial bilateral chain tip that
/// sender recovery paths use as expected_parent_tip.
#[allow(clippy::too_many_arguments)]
fn persist_contact_pair_to_client_db(
    a_dev: [u8; 32],
    a_gen: [u8; 32],
    a_pk: &[u8],
    a_initial_tip: [u8; 32],
    b_dev: [u8; 32],
    b_gen: [u8; 32],
    b_pk: &[u8],
    b_initial_tip: [u8; 32],
) {
    use dsm_sdk::storage::client_db::types::ContactRecord;

    let make_record = |alias: &str,
                       device_id: [u8; 32],
                       genesis_hash: [u8; 32],
                       public_key: &[u8],
                       initial_tip: [u8; 32]|
     -> ContactRecord {
        ContactRecord {
            contact_id: text_id::encode_base32_crockford(&device_id),
            device_id: device_id.to_vec(),
            alias: alias.to_string(),
            genesis_hash: genesis_hash.to_vec(),
            public_key: public_key.to_vec(),
            current_chain_tip: Some(initial_tip.to_vec()),
            added_at: 0,
            verified: true,
            verification_proof: None,
            metadata: std::collections::HashMap::new(),
            ble_address: None,
            status: "OnlineCapable".to_string(),
            needs_online_reconcile: false,
            last_seen_online_counter: 0,
            last_seen_ble_counter: 0,
            previous_chain_tip: None,
        }
    };

    // A's view of B (A's initial tip for the A↔B relationship from A's side)
    client_db::store_contact(&make_record("B", b_dev, b_gen, b_pk, a_initial_tip))
        .expect("persist contact B on A side");
    // B's view of A (B's initial tip for the A↔B relationship from B's side)
    client_db::store_contact(&make_record("A", a_dev, a_gen, a_pk, b_initial_tip))
        .expect("persist contact A on B side");
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

    // Phase 3: Confirm (receiver finalizes; returns commit response ack for sender)
    configure_local_identity_for_receipts(receiver_dev, receiver_gen, receiver_pk)
        .unwrap_or_else(|e| panic!("configure identity for receiver failed: {e}"));
    let commit_response = handler_receiver
        .handle_confirm_request(&confirm_envelope)
        .await
        .unwrap_or_else(|e| panic!("handle_confirm_request failed: {e}"));

    // Phase 3b: Sender processes commit response (finalizes sender settlement
    // + writes sender balance projection + canonical chain tip).
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

// ===========================================================================
// Test 1: A sends 10 ERA to B, then B sends 5 ERA back to A
// ===========================================================================

#[tokio::test]
#[serial]
async fn round_trip_offline_a_sends_b_then_b_sends_a() {
    init_test_db();

    let initial_a: u64 = 10_000;
    let s = setup_two_devices_era(0xA1, 0xB2, initial_a, 0).await;

    let a_device_txt = text_id::encode_base32_crockford(&s.a_dev);
    let b_device_txt = text_id::encode_base32_crockford(&s.b_dev);

    // ── Transfer 1: A sends 10 ERA to B ───────────────────────────────────
    let commitment_1 = execute_bilateral_transfer(
        &s.handler_a,
        &s.handler_b,
        s.a_dev,
        s.a_gen,
        s.a_kp.public_key().to_vec(),
        s.b_dev,
        s.b_gen,
        s.b_kp.public_key().to_vec(),
        10,
        b"",
    )
    .await;

    // Verify balances after first transfer: A = 10000 - 10 = 9990, B = 10
    let a_proj_1 = client_db::get_balance_projection(&a_device_txt, "ERA")
        .expect("sender projection query")
        .expect("sender ERA projection must exist after first transfer");
    assert_eq!(
        a_proj_1.available,
        initial_a - 10,
        "after first transfer: A should have {}, got {}",
        initial_a - 10,
        a_proj_1.available
    );

    let b_proj_1 = client_db::get_balance_projection(&b_device_txt, "ERA")
        .expect("receiver projection query")
        .expect("receiver ERA projection must exist after first transfer");
    assert_eq!(
        b_proj_1.available, 10,
        "after first transfer: B should have 10, got {}",
        b_proj_1.available
    );

    // ── Transfer 2: B sends 5 ERA back to A ──────────────────────────────
    let commitment_2 = execute_bilateral_transfer(
        &s.handler_b,
        &s.handler_a,
        s.b_dev,
        s.b_gen,
        s.b_kp.public_key().to_vec(),
        s.a_dev,
        s.a_gen,
        s.a_kp.public_key().to_vec(),
        5,
        b"",
    )
    .await;

    // Verify balances after second transfer: A = 9990 + 5 = 9995, B = 10 - 5 = 5
    let a_proj_2 = client_db::get_balance_projection(&a_device_txt, "ERA")
        .expect("sender projection query after round-trip")
        .expect("A ERA projection must exist after round-trip");
    assert_eq!(
        a_proj_2.available,
        initial_a - 10 + 5,
        "after round-trip: A should have {}, got {}",
        initial_a - 10 + 5,
        a_proj_2.available
    );

    let b_proj_2 = client_db::get_balance_projection(&b_device_txt, "ERA")
        .expect("receiver projection query after round-trip")
        .expect("B ERA projection must exist after round-trip");
    assert_eq!(
        b_proj_2.available, 5,
        "after round-trip: B should have 5, got {}",
        b_proj_2.available
    );

    // ── Verify transaction histories show both transfers ──────────────────
    let a_history = client_db::get_transaction_history(Some(&a_device_txt), Some(20))
        .expect("A transaction history");
    let b_history = client_db::get_transaction_history(Some(&b_device_txt), Some(20))
        .expect("B transaction history");

    let commitment_1_txt = text_id::encode_base32_crockford(&commitment_1);
    let commitment_2_txt = text_id::encode_base32_crockford(&commitment_2);

    assert!(
        a_history.iter().any(|tx| tx.tx_id == commitment_1_txt),
        "A history must contain the first transfer (A->B)"
    );
    assert!(
        a_history.iter().any(|tx| tx.tx_id == commitment_2_txt),
        "A history must contain the second transfer (B->A)"
    );
    assert!(
        b_history.iter().any(|tx| tx.tx_id == commitment_1_txt),
        "B history must contain the first transfer (A->B)"
    );
    assert!(
        b_history.iter().any(|tx| tx.tx_id == commitment_2_txt),
        "B history must contain the second transfer (B->A)"
    );
}

#[tokio::test]
#[serial]
async fn sender_restart_recovers_persisted_confirm_and_realigns_chain_tips() {
    init_test_db();

    let s = setup_two_devices_era(0xC7, 0xD8, 10_000, 0).await;

    let transfer_op = Operation::Transfer {
        to_device_id: s.b_dev.to_vec(),
        amount: Balance::from_state(7, [1u8; 32], 0),
        token_id: b"ERA".to_vec(),
        mode: dsm::types::operations::TransactionMode::Bilateral,
        nonce: vec![9u8; 8],
        verification: dsm::types::operations::VerificationType::Standard,
        pre_commit: None,
        recipient: s.b_kp.public_key().to_vec(),
        to: s.b_dev.to_vec(),
        message: "restart-recovery".to_string(),
        signature: Vec::new(),
    };

    let (prepare_bytes, commitment) = s
        .handler_a
        .prepare_bilateral_transaction(s.b_dev, transfer_op, 300)
        .await
        .unwrap_or_else(|e| panic!("prepare failed: {e}"));

    s.handler_b
        .handle_prepare_request(&prepare_bytes, None)
        .await
        .unwrap_or_else(|e| panic!("receiver handle_prepare_request failed: {e}"));

    let accept_envelope = s
        .handler_b
        .create_prepare_accept_envelope(commitment)
        .await
        .unwrap_or_else(|e| panic!("create_prepare_accept_envelope failed: {e}"));

    configure_local_identity_for_receipts(s.a_dev, s.a_gen, s.a_kp.public_key().to_vec())
        .unwrap_or_else(|e| panic!("configure sender identity failed: {e}"));
    let (confirm_envelope, _) = s
        .handler_a
        .handle_prepare_response(&accept_envelope)
        .await
        .unwrap_or_else(|e| panic!("handle_prepare_response failed: {e}"));

    // Sender's canonical chain_tip for B is written during handle_commit_response
    // (apply_sender_settlement_bundle_atomic). At this point, pre-commit-response,
    // the tip is legitimately NULL — capture it as Option and verify expectations
    // accordingly.
    let sender_tip_before_restart = client_db::get_contact_chain_tip(&s.b_dev);

    let restarted_contact_manager = DsmContactManager::new(s.a_dev, vec![NodeId::new("n")]);
    let mut restarted_manager = BilateralTransactionManager::new(
        restarted_contact_manager,
        s.a_kp.clone(),
        s.a_dev,
        s.a_gen,
    );
    restarted_manager
        .add_verified_contact(DsmVerifiedContact {
            alias: "B".to_string(),
            device_id: s.b_dev,
            genesis_hash: s.b_gen,
            public_key: s.b_kp.public_key().to_vec(),
            genesis_material: vec![0u8; 32],
            chain_tip: sender_tip_before_restart,
            chain_tip_smt_proof: None,
            genesis_verified_online: true,
            verified_at_commit_height: 1,
            added_at_commit_height: 1,
            last_updated_commit_height: 1,
            verifying_storage_nodes: vec![],
            ble_address: None,
        })
        .unwrap_or_else(|e| panic!("add restarted contact failed: {e}"));

    let restarted_manager = Arc::new(RwLock::new(restarted_manager));
    let mut restarted_handler = BilateralBleHandler::new(restarted_manager, s.a_dev);
    restarted_handler.set_settlement_delegate(Arc::new(DefaultBilateralSettlementDelegate));

    let restored = restarted_handler
        .restore_sessions_from_storage()
        .await
        .unwrap_or_else(|e| panic!("restore_sessions_from_storage failed: {e}"));
    assert_eq!(
        restored, 0,
        "startup should not rehydrate interrupted bilateral sessions into memory"
    );

    let confirm_redelivery = restarted_handler
        .get_pending_confirm_for_counterparty(&s.b_dev)
        .await
        .expect("persisted confirm should survive restart");
    assert_eq!(confirm_redelivery, confirm_envelope);

    // In single-process tests both devices share one DB. The receiver's
    // handle_confirm_request deletes the bilateral_session row that the sender
    // still needs for crash-recovery. Snapshot and restore it to simulate the
    // production invariant where each device owns its own DB.
    let session_snapshot =
        client_db::get_bilateral_session(&commitment).expect("get_bilateral_session snapshot");

    configure_local_identity_for_receipts(s.b_dev, s.b_gen, s.b_kp.public_key().to_vec())
        .unwrap_or_else(|e| panic!("configure receiver identity failed: {e}"));
    let ack = s
        .handler_b
        .handle_confirm_request(&confirm_redelivery)
        .await
        .unwrap_or_else(|e| panic!("receiver handle_confirm_request failed: {e}"));

    // Restore sender-owned session row that the shared-DB receiver deleted.
    if let Some(snapshot) = session_snapshot.as_ref() {
        client_db::store_bilateral_session(snapshot).expect("restore sender session snapshot");
    }

    let receiver_tip_after_confirm =
        client_db::get_contact_chain_tip(&s.a_dev).expect("receiver canonical tip after confirm");
    let sender_tip_before_ack_recovery = client_db::get_contact_chain_tip(&s.b_dev);
    assert_eq!(
        sender_tip_before_ack_recovery, sender_tip_before_restart,
        "sender canonical tip should still match pre-restart snapshot before ack recovery"
    );
    assert_ne!(
        sender_tip_before_ack_recovery,
        Some(receiver_tip_after_confirm),
        "sender tip must still be stale (not yet advanced to receiver's new tip)"
    );

    configure_local_identity_for_receipts(s.a_dev, s.a_gen, s.a_kp.public_key().to_vec())
        .unwrap_or_else(|e| panic!("configure restarted sender identity failed: {e}"));
    restarted_handler
        .handle_commit_response(&ack)
        .await
        .unwrap_or_else(|e| panic!("restarted sender handle_commit_response failed: {e}"));

    let sender_tip_after_recovery =
        client_db::get_contact_chain_tip(&s.b_dev).expect("sender tip after recovery");
    let receiver_tip_after_recovery =
        client_db::get_contact_chain_tip(&s.a_dev).expect("receiver tip after recovery");

    assert_ne!(
        Some(sender_tip_after_recovery),
        sender_tip_before_restart,
        "sender tip must have advanced after recovery"
    );
    assert_eq!(sender_tip_after_recovery, receiver_tip_after_recovery);
    assert!(
        restarted_handler
            .get_pending_confirm_for_counterparty(&s.b_dev)
            .await
            .is_none(),
        "recovered sender commit should clear the persisted confirm envelope"
    );
}

// ===========================================================================
// Test 2: dBTC round-trip — A sends 30 dBTC to B, B sends 10 back
// ===========================================================================

#[tokio::test]
#[serial]
async fn round_trip_offline_dbtc_a_sends_b_then_b_sends_a() {
    init_test_db();

    let initial_a_dbtc: u64 = 100;
    let s = setup_two_devices_dbtc(0xC3, 0xD4, initial_a_dbtc, 0).await;

    let a_device_txt = text_id::encode_base32_crockford(&s.a_dev);
    let b_device_txt = text_id::encode_base32_crockford(&s.b_dev);

    // ── Transfer 1: A sends 30 dBTC to B ──────────────────────────────────
    let commitment_1 = execute_bilateral_transfer(
        &s.handler_a,
        &s.handler_b,
        s.a_dev,
        s.a_gen,
        s.a_kp.public_key().to_vec(),
        s.b_dev,
        s.b_gen,
        s.b_kp.public_key().to_vec(),
        30,
        b"dBTC",
    )
    .await;

    // Verify balances after first transfer: A = 100 - 30 = 70, B = 30
    let a_proj_1 = client_db::get_balance_projection(&a_device_txt, "dBTC")
        .expect("sender dBTC projection query")
        .expect("sender dBTC projection must exist after first transfer");
    assert_eq!(
        a_proj_1.available,
        initial_a_dbtc - 30,
        "after first dBTC transfer: A should have {}, got {}",
        initial_a_dbtc - 30,
        a_proj_1.available
    );

    let b_proj_1 = client_db::get_balance_projection(&b_device_txt, "dBTC")
        .expect("receiver dBTC projection query")
        .expect("receiver dBTC projection must exist after first transfer");
    assert_eq!(
        b_proj_1.available, 30,
        "after first dBTC transfer: B should have 30, got {}",
        b_proj_1.available
    );

    // ── Transfer 2: B sends 10 dBTC back to A ────────────────────────────
    let commitment_2 = execute_bilateral_transfer(
        &s.handler_b,
        &s.handler_a,
        s.b_dev,
        s.b_gen,
        s.b_kp.public_key().to_vec(),
        s.a_dev,
        s.a_gen,
        s.a_kp.public_key().to_vec(),
        10,
        b"dBTC",
    )
    .await;

    // Verify balances after round-trip: A = 70 + 10 = 80, B = 30 - 10 = 20
    let a_proj_2 = client_db::get_balance_projection(&a_device_txt, "dBTC")
        .expect("A dBTC projection query after round-trip")
        .expect("A dBTC projection must exist after round-trip");
    assert_eq!(
        a_proj_2.available,
        initial_a_dbtc - 30 + 10,
        "after dBTC round-trip: A should have {}, got {}",
        initial_a_dbtc - 30 + 10,
        a_proj_2.available
    );

    let b_proj_2 = client_db::get_balance_projection(&b_device_txt, "dBTC")
        .expect("B dBTC projection query after round-trip")
        .expect("B dBTC projection must exist after round-trip");
    assert_eq!(
        b_proj_2.available, 20,
        "after dBTC round-trip: B should have 20, got {}",
        b_proj_2.available
    );

    // ── Verify transaction histories show both dBTC transfers ─────────────
    let a_history = client_db::get_transaction_history(Some(&a_device_txt), Some(20))
        .expect("A transaction history");
    let b_history = client_db::get_transaction_history(Some(&b_device_txt), Some(20))
        .expect("B transaction history");

    let commitment_1_txt = text_id::encode_base32_crockford(&commitment_1);
    let commitment_2_txt = text_id::encode_base32_crockford(&commitment_2);

    assert!(
        a_history.iter().any(|tx| tx.tx_id == commitment_1_txt),
        "A history must contain the first dBTC transfer (A->B)"
    );
    assert!(
        a_history.iter().any(|tx| tx.tx_id == commitment_2_txt),
        "A history must contain the second dBTC transfer (B->A)"
    );
    assert!(
        b_history.iter().any(|tx| tx.tx_id == commitment_1_txt),
        "B history must contain the first dBTC transfer (A->B)"
    );
    assert!(
        b_history.iter().any(|tx| tx.tx_id == commitment_2_txt),
        "B history must contain the second dBTC transfer (B->A)"
    );
}

// ===========================================================================
// Test 3: Three consecutive same-direction transfers (A sends 5 ERA to B x3)
// ===========================================================================

#[tokio::test]
#[serial]
async fn round_trip_consecutive_same_direction() {
    init_test_db();

    let initial_a: u64 = 10_000;
    let s = setup_two_devices_era(0xE5, 0xF6, initial_a, 0).await;

    let a_device_txt = text_id::encode_base32_crockford(&s.a_dev);
    let b_device_txt = text_id::encode_base32_crockford(&s.b_dev);

    let mut commitments: Vec<[u8; 32]> = Vec::with_capacity(3);

    // ── Three consecutive transfers: A sends 5 ERA to B each time ─────────
    for i in 0..3u32 {
        let commitment = execute_bilateral_transfer(
            &s.handler_a,
            &s.handler_b,
            s.a_dev,
            s.a_gen,
            s.a_kp.public_key().to_vec(),
            s.b_dev,
            s.b_gen,
            s.b_kp.public_key().to_vec(),
            5,
            b"",
        )
        .await;
        commitments.push(commitment);

        // Verify cumulative balances after each iteration
        let expected_a = initial_a - 5 * (i as u64 + 1);
        let expected_b = 5 * (i as u64 + 1);

        let a_proj = client_db::get_balance_projection(&a_device_txt, "ERA")
            .expect("A projection query")
            .expect("A ERA projection must exist");
        assert_eq!(
            a_proj.available,
            expected_a,
            "after transfer {}: A should have {}, got {}",
            i + 1,
            expected_a,
            a_proj.available
        );

        let b_proj = client_db::get_balance_projection(&b_device_txt, "ERA")
            .expect("B projection query")
            .expect("B ERA projection must exist");
        assert_eq!(
            b_proj.available,
            expected_b,
            "after transfer {}: B should have {}, got {}",
            i + 1,
            expected_b,
            b_proj.available
        );
    }

    // ── Final balance check: A lost 15, B gained 15 ──────────────────────
    let a_final = client_db::get_balance_projection(&a_device_txt, "ERA")
        .expect("final A projection")
        .expect("A ERA projection must exist");
    assert_eq!(
        a_final.available,
        initial_a - 15,
        "final: A should have {}, got {}",
        initial_a - 15,
        a_final.available
    );

    let b_final = client_db::get_balance_projection(&b_device_txt, "ERA")
        .expect("final B projection")
        .expect("B ERA projection must exist");
    assert_eq!(
        b_final.available, 15,
        "final: B should have 15, got {}",
        b_final.available
    );

    // ── Verify all 3 transactions appear in both histories ────────────────
    let a_history = client_db::get_transaction_history(Some(&a_device_txt), Some(20))
        .expect("A transaction history");
    let b_history = client_db::get_transaction_history(Some(&b_device_txt), Some(20))
        .expect("B transaction history");

    for (idx, commitment) in commitments.iter().enumerate() {
        let commitment_txt = text_id::encode_base32_crockford(commitment);
        assert!(
            a_history.iter().any(|tx| tx.tx_id == commitment_txt),
            "A history must contain transfer {} (commitment {})",
            idx + 1,
            commitment_txt
        );
        assert!(
            b_history.iter().any(|tx| tx.tx_id == commitment_txt),
            "B history must contain transfer {} (commitment {})",
            idx + 1,
            commitment_txt
        );
    }
}
