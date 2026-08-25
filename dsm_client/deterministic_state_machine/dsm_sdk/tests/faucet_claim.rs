// SPDX-License-Identifier: MIT OR Apache-2.0
#![allow(clippy::disallowed_methods)]

//! The builtin faucet is UNAVAILABLE, and this file asserts that rather than
//! testing a grant that must no longer happen.
//!
//! These tests used to assert that `faucet.claim` increased an ERA balance. That
//! behaviour was the defect: the route minted builtin ERA on nothing more than a
//! caller-supplied `device_id` plus a local cooldown — no independently verifiable
//! right to issue. `DeviceState::advance` now refuses builtin issuance outright,
//! so the grant cannot happen at any layer, and the route says so explicitly.
//!
//! The companion test that used two faucet claims as a MECHANISM to check
//! bilateral-tip isolation is retired with the grant: its premise was that a claim
//! advances state, which is exactly what no longer occurs. Tip isolation is
//! exercised by the transfer suites, which advance state through real transitions.
//!
//! Restoring a faucet means defining an authenticated issuance predicate whose
//! evidence the accepting transition validates — at which point these assertions
//! should be replaced by ones about that predicate, not by re-enabling a grant.

use prost::Message;

use dsm_sdk::bridge::{AppInvoke, AppQuery, AppRouter};
use dsm_sdk::generated;
use dsm_sdk::handlers::app_router_impl::AppRouterImpl;
use dsm_sdk::init::SdkConfig;
use dsm_sdk::runtime;
use dsm_sdk::storage::client_db::reset_database_for_tests;
use std::path::PathBuf;

fn init_test_storage() {
    std::env::set_var("DSM_SDK_TEST_MODE", "1");
    reset_database_for_tests();
    let _ = dsm_sdk::storage_utils::set_storage_base_dir(PathBuf::from("./.dsm_testdata"));
    dsm_sdk::sdk::app_state::AppState::set_identity_info(
        vec![0xAA; 32],
        vec![0xBB; 32],
        vec![0xCC; 32],
        vec![0xDD; 32],
    );
    dsm_sdk::set_wallet_seed_for_testing(vec![0xEE; 32]);
}

fn router() -> AppRouterImpl {
    runtime::dsm_init_runtime();
    init_test_storage();
    AppRouterImpl::new(SdkConfig {
        node_id: "test-device".to_string(),
        storage_endpoints: vec![],
        enable_offline: false,
    })
    .expect("AppRouterImpl::new should succeed in test")
}

fn pack(body: Vec<u8>) -> Vec<u8> {
    generated::ArgPack {
        schema_hash: Some(generated::Hash32 { v: vec![0u8; 32] }),
        codec: generated::Codec::Proto as i32,
        body,
    }
    .encode_to_vec()
}

fn claim_request() -> Vec<u8> {
    pack(
        generated::FaucetClaimRequest {
            device_id: vec![0u8; 32],
        }
        .encode_to_vec(),
    )
}

/// `faucet.claim` refuses, and says why.
///
/// Asserting on the SPECIFIC reason matters: a bare `!success` would pass just as
/// happily if the route broke for an unrelated reason, which is how a refusal gets
/// credited for work it is not doing.
#[test]
#[serial_test::serial]
fn faucet_claim_is_refused_because_builtin_issuance_is_unauthenticated() {
    let r = router();
    let res = runtime::get_runtime().block_on(async {
        r.invoke(AppInvoke {
            method: "faucet.claim".to_string(),
            args: claim_request(),
        })
        .await
    });

    assert!(!res.success, "the builtin faucet must not grant ERA");
    let msg = res.error_message.unwrap_or_default();
    assert!(
        msg.contains("builtin faucet issuance unavailable"),
        "the refusal must name the missing authenticated issuance predicate, got: {msg}"
    );
}

/// `faucet.check_nearby` advertises the same thing the claim will do.
///
/// A check that reported "available" while every claim refused would send callers
/// into a guaranteed failure and read like a transient outage rather than a
/// deliberate shutdown.
#[test]
#[serial_test::serial]
fn faucet_check_nearby_reports_unavailable_rather_than_advertising_a_grant() {
    let r = router();
    let res = runtime::get_runtime().block_on(async {
        r.query(AppQuery {
            path: "faucet.check_nearby".to_string(),
            params: claim_request(),
        })
        .await
    });

    assert!(
        res.success,
        "the check itself answers; it is the ANSWER that is negative"
    );
    let env = generated::Envelope::decode(&res.data[1..]).expect("envelope");
    match env.payload {
        Some(generated::envelope::Payload::FaucetClaimResponse(f)) => {
            assert!(!f.success, "must not advertise an available faucet");
            assert_eq!(f.tokens_received, 0);
            assert!(
                f.message.contains("builtin faucet issuance unavailable"),
                "must name the reason, got: {}",
                f.message
            );
        }
        other => panic!("unexpected payload {other:?}"),
    }
}
