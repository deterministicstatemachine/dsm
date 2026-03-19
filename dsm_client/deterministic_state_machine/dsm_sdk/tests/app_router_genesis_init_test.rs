#![allow(clippy::disallowed_methods)]

// Production-only test: AppRouterImpl automatically initializes genesis state
// This ensures "No current state available" error doesn't occur on faucet claims

use dsm_sdk::handlers::AppRouterImpl;
use dsm_sdk::init::SdkConfig;
use std::path::PathBuf;

fn init_test_storage() {
    std::env::set_var("DSM_SDK_TEST_MODE", "1");
    // Use a deterministic local path for test isolation; AppState requires this once.
    let _ = dsm_sdk::storage_utils::set_storage_base_dir(PathBuf::from("./.dsm_testdata"));
    // Force non-zero device identity so BitcoinKeyStore::from_entropy doesn't reject zero entropy.
    dsm_sdk::sdk::app_state::AppState::set_identity_info(
        vec![0xAA; 32], // device_id (non-zero)
        vec![0xBB; 32], // public_key
        vec![0xCC; 32], // genesis_hash
        vec![0xDD; 32], // smt_root
    );
}

#[test]
fn app_router_initializes_genesis_state_on_construction() {
    init_test_storage();
    // Create AppRouterImpl with minimal config
    let router = AppRouterImpl::new(SdkConfig {
        node_id: "test_node".to_string(),
        storage_endpoints: vec![],
        enable_offline: false,
    })
    .expect("AppRouterImpl::new should succeed in test");

    // Verify that the core SDK has been initialized with a genesis state
    // This should not panic or return an error
    let state_result = router.core_sdk.get_current_state();

    assert!(
        state_result.is_ok(),
        "CoreSDK should have genesis state after AppRouterImpl construction. Error: {:?}",
        state_result.err()
    );

    let state = state_result.unwrap();
    assert!(
        !state.hash.is_empty(),
        "Genesis state should have a non-empty hash"
    );

    println!("✓ AppRouterImpl successfully initialized genesis state");
    println!("  State hash length: {} bytes", state.hash.len());
    println!("  State number: {}", state.state_number);
}

#[test]
fn app_router_state_persists_across_operations() {
    init_test_storage();
    let router = AppRouterImpl::new(SdkConfig {
        node_id: "test_node_persist".to_string(),
        storage_endpoints: vec![],
        enable_offline: false,
    })
    .expect("AppRouterImpl::new should succeed in test");

    // Get initial state
    let state1 = router
        .core_sdk
        .get_current_state()
        .expect("Should have initial state");

    // Perform another state access
    let state2 = router
        .core_sdk
        .get_current_state()
        .expect("Should still have state");

    // State should be consistent
    assert_eq!(
        state1.hash, state2.hash,
        "State hash should remain consistent"
    );
    assert_eq!(
        state1.state_number, state2.state_number,
        "State index should remain consistent"
    );

    println!("✓ State persists across multiple operations");
}
