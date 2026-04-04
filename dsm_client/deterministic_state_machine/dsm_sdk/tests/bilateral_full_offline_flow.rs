// SPDX-License-Identifier: MIT OR Apache-2.0
//! Full offline bilateral flow integration tests.
//!
//! Each "device" gets its own Per-Device SMT (§2.2) — the SMT is a compact
//! commitment to current relationship heads.  Device A's SMT has leaf k_{A↔B},
//! Device B's SMT has leaf k_{B↔A}.  Same relationship key, same chain tip
//! value, two independent trees on two independent devices.  Using a shared
//! singleton would corrupt proofs when one device's SMT-Replace changes the
//! root that the other device's receipt verification expects (Tripwire §6.1).

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
// Test infrastructure
// ---------------------------------------------------------------------------

fn dev(id: u8) -> [u8; 32] {
    [id; 32]
}

/// Minimal AppRouter for tests — returns a pre-seeded device canonical state
/// so that `build_canonical_settled_state` can read B_n from the device tip.
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

    let stored_root = sdk::sdk::app_state::AppState::get_device_tree_root()
        .ok_or("device_tree_root must be derived from local identity")?;
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
    Ok(())
}

/// Build a genesis state with ERA balance, mirror it into BCR for projection
/// queries, and install it as the device canonical state via the TestAppRouter.
fn seed_device_state_with_era(
    router: &TestAppRouter,
    device_id: [u8; 32],
    public_key: &[u8],
    era_balance: u64,
) {
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

    // Mirror the canonical seed into BCR so projection/history queries see the
    // same authoritative device state the settlement delegate starts from.
    client_db::store_bcr_state(&state, true).expect("seed BCR genesis");

    // Set as the device canonical state (authoritative for settlement).
    router.set_device_state(state);
}

/// Common setup: two devices with keypairs, contact managers, bilateral
/// transaction managers, relationships established on separate SMTs,
/// and BLE handlers with per-device SMTs + settlement delegates.
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

async fn setup_two_devices(a_id: u8, b_id: u8, sender_era: u64) -> TwoDeviceSetup {
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

    // Each device has its own Per-Device SMT (§2.2).
    let smt_a = Arc::new(RwLock::new(
        dsm::merkle::sparse_merkle_tree::SparseMerkleTree::new(256),
    ));
    let smt_b = Arc::new(RwLock::new(
        dsm::merkle::sparse_merkle_tree::SparseMerkleTree::new(256),
    ));

    // Establish relationships — each manager uses its own device's SMT.
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

    // Install test router and seed canonical device states for both peers.
    let router = Arc::new(TestAppRouter::new());
    sdk::bridge::install_app_router(router.clone()).expect("install test router");
    seed_device_state_with_era(&router, a_dev, a_kp.public_key(), sender_era);
    seed_device_state_with_era(&router, b_dev, b_kp.public_key(), 0);

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
    let _ =
        dsm_sdk::storage_utils::set_storage_base_dir(std::path::PathBuf::from("./.dsm_testdata"));
    client_db::reset_database_for_tests();
    if let Err(e) = client_db::init_database() {
        eprintln!("[bilateral_full_offline_flow] init_database skipped (already init): {e}");
    }
}

// ---------------------------------------------------------------------------
// Test 1: Full 3-phase flow + balance verification
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn bilateral_offline_prepare_accept_commit_finalize_flow() {
    init_test_db();

    let s = setup_two_devices(0xA1, 0xB2, 10_000).await;
    let handler_a = s.handler_a;
    let handler_b = s.handler_b;

    let balance = Balance::from_state(10, [1u8; 32], 0);
    let transfer_op = Operation::Transfer {
        to_device_id: s.b_dev.to_vec(),
        amount: balance,
        token_id: b"".to_vec(),
        mode: dsm::types::operations::TransactionMode::Bilateral,
        nonce: vec![0u8; 8],
        verification: dsm::types::operations::VerificationType::Standard,
        pre_commit: None,
        recipient: s.b_kp.public_key().to_vec(),
        to: s.b_dev.to_vec(),
        message: "pay".to_string(),
        signature: Vec::new(),
    };

    // Phase 1: Prepare
    let (prepare_bytes, commitment) = handler_a
        .prepare_bilateral_transaction(s.b_dev, transfer_op.clone(), 300)
        .await
        .unwrap_or_else(|e| panic!("prepare failed: {e}"));

    {
        let ma = s.a.read().await;
        assert!(ma.has_pending_commitment(&commitment));
    }

    // Phase 2: Accept
    handler_b
        .handle_prepare_request(&prepare_bytes, None)
        .await
        .unwrap_or_else(|e| panic!("handle_prepare_request failed: {e}"));

    let accept_envelope = handler_b
        .create_prepare_accept_envelope(commitment)
        .await
        .unwrap_or_else(|e| panic!("create_accept failed: {e}"));

    // Phase 3: Confirm (sender finalizes + settlement)
    configure_local_identity_for_receipts(s.a_dev, s.a_gen, s.a_kp.public_key().to_vec())
        .unwrap_or_else(|e| panic!("configure identity for a failed: {e}"));
    let (confirm_envelope, _meta) = handler_a
        .handle_prepare_response(&accept_envelope)
        .await
        .unwrap_or_else(|e| panic!("handle_prepare_response failed: {e}"));

    // Phase 3: Confirm (receiver finalizes + settlement)
    configure_local_identity_for_receipts(s.b_dev, s.b_gen, s.b_kp.public_key().to_vec())
        .unwrap_or_else(|e| panic!("configure identity for b failed: {e}"));
    let commit_response = handler_b
        .handle_confirm_request(&confirm_envelope)
        .await
        .unwrap_or_else(|e| panic!("handle_confirm_request failed: {e}"));

    // Phase 3b: Sender processes commit response (finalizes + settlement)
    configure_local_identity_for_receipts(s.a_dev, s.a_gen, s.a_kp.public_key().to_vec())
        .unwrap_or_else(|e| panic!("configure identity for a (commit response) failed: {e}"));
    handler_a
        .handle_commit_response(&commit_response)
        .await
        .unwrap_or_else(|e| panic!("handle_commit_response failed: {e}"));

    // ── Verification: commitment cleared ─────────────────────────────────
    {
        let ma = s.a.read().await;
        assert!(
            !ma.has_pending_commitment(&commitment),
            "sender pending commitment should be cleared"
        );
    }

    // ── Verification: sender balance (10,000 - 10 = 9,990) ──────────────
    let a_device_txt = text_id::encode_base32_crockford(&s.a_dev);
    let sender_projection =
        client_db::get_balance_projection(&a_device_txt, "ERA").expect("sender projection query");
    assert!(
        sender_projection.is_some(),
        "sender ERA balance projection must exist after settlement"
    );
    let sender_proj = sender_projection.unwrap();
    assert_eq!(
        sender_proj.available, 9_990,
        "sender ERA balance should be 10,000 - 10 = 9,990"
    );

    // ── Verification: receiver balance (0 + 10 = 10) ───────────────────
    let b_device_txt = text_id::encode_base32_crockford(&s.b_dev);
    let receiver_projection =
        client_db::get_balance_projection(&b_device_txt, "ERA").expect("receiver projection query");
    assert!(
        receiver_projection.is_some(),
        "receiver ERA balance projection must exist after settlement"
    );
    let receiver_proj = receiver_projection.unwrap();
    assert_eq!(
        receiver_proj.available, 10,
        "receiver ERA balance should be credited by the bilateral settlement"
    );

    // ── Verification: BCR state has correct device_id and sn ─────────────
    let sender_bcr = client_db::get_bcr_states(&s.a_dev, false).expect("sender BCR states");
    let sender_latest = sender_bcr.last().expect("sender must have BCR state");
    assert_eq!(
        sender_latest.state_number, 1,
        "sender BCR state_number should be genesis(0) + 1"
    );
    assert_eq!(
        sender_latest.device_info.device_id, s.a_dev,
        "sender BCR state must have raw device_id, not domain-hashed"
    );

    // ── Verification: receiver transaction history ───────────────────────
    let history = client_db::get_transaction_history(Some(&b_device_txt), Some(20))
        .expect("receiver transaction history");
    assert!(
        history.iter().any(|tx| {
            tx.amount == 10
                && tx.from_device == a_device_txt
                && tx.to_device == b_device_txt
                && !tx.metadata.contains_key("token_id")
        }),
        "receiver transaction history should record the settled ERA transfer"
    );
}

// ---------------------------------------------------------------------------
// Test 2: State consistency across peers (chain tips, tx hashes, integrity)
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn bilateral_offline_state_consistency_across_peers() {
    init_test_db();

    let s = setup_two_devices(0xC1, 0xD2, 1_000).await;
    let handler_a = s.handler_a;
    let handler_b = s.handler_b;

    let balance = Balance::from_state(5, [2u8; 32], 0);
    let transfer_op = Operation::Transfer {
        to_device_id: s.b_dev.to_vec(),
        amount: balance,
        token_id: b"".to_vec(),
        mode: dsm::types::operations::TransactionMode::Bilateral,
        nonce: vec![0u8; 8],
        verification: dsm::types::operations::VerificationType::Standard,
        pre_commit: None,
        recipient: s.b_kp.public_key().to_vec(),
        to: s.b_dev.to_vec(),
        message: "pay".to_string(),
        signature: Vec::new(),
    };

    let (prepare_bytes, commitment) = handler_a
        .prepare_bilateral_transaction(s.b_dev, transfer_op.clone(), 300)
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

    configure_local_identity_for_receipts(s.a_dev, s.a_gen, s.a_kp.public_key().to_vec())
        .unwrap_or_else(|e| panic!("configure identity for a failed: {e}"));
    let (confirm_envelope, _meta) = handler_a
        .handle_prepare_response(&accept_envelope)
        .await
        .unwrap_or_else(|e| panic!("handle_prepare_response failed: {e}"));

    configure_local_identity_for_receipts(s.b_dev, s.b_gen, s.b_kp.public_key().to_vec())
        .unwrap_or_else(|e| panic!("configure identity for b failed: {e}"));
    let commit_response = handler_b
        .handle_confirm_request(&confirm_envelope)
        .await
        .unwrap_or_else(|e| panic!("handle_confirm_request failed: {e}"));

    // Sender processes commit response (finalizes + settlement)
    configure_local_identity_for_receipts(s.a_dev, s.a_gen, s.a_kp.public_key().to_vec())
        .unwrap_or_else(|e| panic!("configure identity for a (commit response) failed: {e}"));
    handler_a
        .handle_commit_response(&commit_response)
        .await
        .unwrap_or_else(|e| panic!("handle_commit_response failed: {e}"));

    // ── Chain tip consistency ────────────────────────────────────────────
    let a_anchor =
        s.a.read()
            .await
            .get_relationship(&s.b_dev)
            .unwrap_or_else(|| panic!("a relationship missing"));
    let b_anchor =
        s.b.read()
            .await
            .get_relationship(&s.a_dev)
            .unwrap_or_else(|| panic!("b relationship missing"));

    assert_eq!(
        a_anchor.chain_tip, b_anchor.chain_tip,
        "shared chain tips must match after bilateral confirm"
    );
    assert_eq!(
        a_anchor.mutual_anchor_hash, b_anchor.mutual_anchor_hash,
        "mutual anchor hash must match"
    );

    // ── Pending commitments cleared ─────────────────────────────────────
    assert!(s.a.read().await.list_pending_commitments().is_empty());
    assert!(s.b.read().await.list_pending_commitments().is_empty());

    // ── Transaction history consistency ──────────────────────────────────
    let a_device_txt = text_id::encode_base32_crockford(&s.a_dev);
    let b_device_txt = text_id::encode_base32_crockford(&s.b_dev);
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

    // ── Relationship integrity ──────────────────────────────────────────
    assert!(s
        .a
        .read()
        .await
        .verify_relationship_integrity(&s.b_dev)
        .unwrap_or_else(|e| panic!("verify relationship integrity on a failed: {e}")));
    assert!(s
        .b
        .read()
        .await
        .verify_relationship_integrity(&s.a_dev)
        .unwrap_or_else(|e| panic!("verify relationship integrity on b failed: {:?}", e)));
}
