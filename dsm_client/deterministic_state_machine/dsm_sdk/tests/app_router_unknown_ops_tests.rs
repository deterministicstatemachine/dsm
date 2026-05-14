#![allow(clippy::disallowed_methods)]

use dsm_sdk::handlers::AppRouterImpl;
use dsm_sdk::bridge::{AppQuery, AppInvoke, AppRouter as _};
use dsm_sdk::init::SdkConfig;
use serial_test::serial;
use std::path::PathBuf;

fn init_test_storage() {
    std::env::set_var("DSM_SDK_TEST_MODE", "1");
    let _ = dsm_sdk::storage_utils::set_storage_base_dir(PathBuf::from("./.dsm_testdata"));
    // Force non-zero device identity so BitcoinKeyStore::from_entropy doesn't reject zero entropy.
    dsm_sdk::sdk::app_state::AppState::set_identity_info(
        vec![0xAA; 32],
        vec![0xBB; 32],
        vec![0xCC; 32],
        vec![0xDD; 32],
    );
    // Install a deterministic 32-byte C-DBRW binding key so the canonical
    // signing authority can derive a keypair during AppRouter::new().
    // DBRW enforcement is ON, so without this the router fails to construct.
    dsm_sdk::set_cdbrw_binding_key_for_testing(vec![0xEE; 32]);
}

#[tokio::test]
#[serial]
async fn unknown_query_path_returns_fallback() {
    init_test_storage();
    let cfg = SdkConfig {
        node_id: "dev-node".to_string(),
        storage_endpoints: vec!["http://127.0.0.1:8080".to_string()],
        enable_offline: true,
    };
    let router = AppRouterImpl::new(cfg).expect("AppRouterImpl::new should succeed in test");

    let res = router
        .query(AppQuery {
            path: "foo.unknown".into(),
            params: vec![],
        })
        .await;
    assert!(!res.success);
    assert_eq!(
        res.error_message.as_deref(),
        Some("unknown query path: foo.unknown")
    );
}

#[tokio::test]
#[serial]
async fn unknown_invoke_method_returns_fallback() {
    init_test_storage();
    let cfg = SdkConfig {
        node_id: "dev-node".to_string(),
        storage_endpoints: vec!["http://127.0.0.1:8080".to_string()],
        enable_offline: true,
    };
    let router = AppRouterImpl::new(cfg).expect("AppRouterImpl::new should succeed in test");

    let res = router
        .invoke(AppInvoke {
            method: "no.such.method".into(),
            args: vec![],
        })
        .await;
    assert!(!res.success);
    let err_msg = res
        .error_message
        .as_deref()
        .expect("should have error_message");
    assert!(
        err_msg.contains("unknown invoke method") && err_msg.contains("no.such.method"),
        "unexpected error: {err_msg}"
    );
}
