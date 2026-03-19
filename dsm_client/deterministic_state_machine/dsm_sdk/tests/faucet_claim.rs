// SPDX-License-Identifier: MIT OR Apache-2.0
#![allow(clippy::disallowed_methods)]

use prost::Message;

use dsm::types::proto as generated;
use dsm_sdk::runtime;
use dsm_sdk::init::SdkConfig;
use dsm_sdk::handlers::app_router_impl::AppRouterImpl;
use dsm_sdk::bridge::{AppInvoke, AppQuery, AppRouter};
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
fn faucet_claim_increases_era_balance() {
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

    // Build FaucetClaimRequest ArgPack
    let req = generated::FaucetClaimRequest {
        device_id: vec![0u8; 32],
    };
    let mut body = Vec::new();
    req.encode(&mut body).unwrap();
    let arg_pack = generated::ArgPack {
        schema_hash: Some(generated::Hash32 { v: vec![0u8; 32] }),
        codec: generated::Codec::Proto as i32,
        body,
    };
    let mut args_bytes = Vec::new();
    arg_pack.encode(&mut args_bytes).unwrap();

    // Invoke faucet.claim
    let inv = AppInvoke {
        method: "faucet.claim".to_string(),
        args: args_bytes,
    };
    let res = runtime::get_runtime().block_on(async { router.invoke(inv).await });
    assert!(
        res.success,
        "faucet.claim invoke should succeed: {:?}",
        res.error_message
    );

    // Query balance.list
    let q_args = generated::ArgPack {
        schema_hash: Some(generated::Hash32 { v: vec![0u8; 32] }),
        codec: generated::Codec::Proto as i32,
        body: Vec::new(),
    };
    let mut q_bytes = Vec::new();
    q_args.encode(&mut q_bytes).unwrap();
    let q = AppQuery {
        path: "balance.list".to_string(),
        params: q_bytes,
    };
    let qres = runtime::get_runtime().block_on(async { router.query(q).await });
    assert!(
        qres.success,
        "balance.list should succeed: {:?}",
        qres.error_message
    );

    // Decode FramedEnvelopeV3 response
    assert!(!qres.data.is_empty(), "response bytes must not be empty");
    assert_eq!(qres.data[0], 0x03, "expected FramedEnvelopeV3 prefix");
    let env = generated::Envelope::decode(&qres.data[1..]).expect("decode Envelope");
    assert_eq!(env.version, 3);
    let list = match env.payload {
        Some(generated::envelope::Payload::BalancesListResponse(r)) => r,
        other => panic!("unexpected payload: {:?}", other),
    };

    let era_ok = list
        .balances
        .iter()
        .any(|b| b.token_id == "ERA" && b.available > 0);
    assert!(era_ok, "ERA balance should be > 0 after faucet claim");
}
