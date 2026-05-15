// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(clippy::disallowed_methods)]

use dsm_sdk::bridge::{AppInvoke, AppRouter};
use dsm_sdk::generated;
use dsm_sdk::handlers::app_router_impl::AppRouterImpl;
use dsm_sdk::init::SdkConfig;
use dsm_sdk::runtime;
use prost::Message;
use std::path::PathBuf;

fn init_test_storage() {
    std::env::set_var("DSM_SDK_TEST_MODE", "1");
    let _ = dsm_sdk::storage_utils::set_storage_base_dir(PathBuf::from("./.dsm_testdata"));
    dsm_sdk::sdk::app_state::AppState::set_identity_info(
        vec![0xAA; 32],
        vec![0xBB; 32],
        vec![0xCC; 32],
        vec![0xDD; 32],
    );
    // Install a deterministic 32-byte C-DBRW binding key so the canonical
    // signing authority can derive a keypair during AppRouter::new().
    dsm_sdk::set_cdbrw_binding_key_for_testing(vec![0xEE; 32]);
}

#[test]
fn faucet_clean_returns_ok() {
    // Initialize runtime for async execution
    runtime::dsm_init_runtime();
    init_test_storage();

    // Minimal config (offline disabled)
    let cfg = SdkConfig {
        node_id: "test-device".to_string(),
        storage_endpoints: vec![],
        enable_offline: false,
    };
    let router = AppRouterImpl::new(cfg).expect("AppRouterImpl::new should succeed in test");

    // Build an empty ArgPack (codec/proto, empty body)
    let arg_pack = generated::ArgPack {
        schema_hash: Some(generated::Hash32 { v: vec![0u8; 32] }),
        codec: generated::Codec::Proto as i32,
        body: Vec::new(),
    };
    let mut args_bytes = Vec::new();
    arg_pack.encode(&mut args_bytes).unwrap();

    // Invoke faucet.clean
    let inv = AppInvoke {
        method: "faucet.clean".to_string(),
        args: args_bytes,
    };
    let res = runtime::get_runtime().block_on(async { router.invoke(inv).await });
    assert!(
        res.success,
        "faucet.clean invoke should succeed: {:?}",
        res.error_message
    );

    assert_eq!(
        res.data.first(),
        Some(&0x03),
        "expected FramedEnvelopeV3 prefix"
    );
    let env = dsm_sdk::envelope::from_canonical_bytes(&res.data[1..]).expect("decode Envelope v3");
    let resp: generated::AppStateResponse = match env.payload.expect("envelope payload") {
        generated::envelope::Payload::AppStateResponse(r) => r,
        other => panic!("unexpected envelope payload: {:?}", other),
    };
    assert_eq!(resp.key, "faucet.clean");
    assert_eq!(resp.value.as_deref(), Some("cleanup_completed"));
}
