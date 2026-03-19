// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(clippy::disallowed_methods)]

use dsm::types::proto as generated;
use dsm_sdk::bridge::{AppInvoke, AppRouter};
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

    // Decode AppStateResponse. New router returns a framed Envelope v3 (leading 0x03)
    // while older code returned an ArgPack/ResultPack. Support both for tests.
    let resp: generated::AppStateResponse = if !res.data.is_empty() && res.data[0] == 0x03 {
        // Framed Envelope v3: first byte is 0x03
        let env = generated::Envelope::decode(&res.data[1..]).expect("decode Envelope v3");
        match env.payload.expect("envelope payload") {
            generated::envelope::Payload::AppStateResponse(r) => r,
            other => panic!("unexpected envelope payload: {:?}", other),
        }
    } else {
        // Fallback: legacy ResultPack/ArgPack body
        let pack = generated::ResultPack::decode(&*res.data).expect("decode ResultPack");
        generated::AppStateResponse::decode(&*pack.body).expect("decode AppStateResponse")
    };
    assert_eq!(resp.key, "faucet.clean");
    assert_eq!(resp.value.as_deref(), Some("cleanup_completed"));
}
