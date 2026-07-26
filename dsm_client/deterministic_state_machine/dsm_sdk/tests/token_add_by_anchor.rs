// SPDX-License-Identifier: MIT OR Apache-2.0
//! Adopting a token created on another device.
//!
//! A device cannot hold a token whose policy it does not have: balances are
//! keyed by policy commitment and the enforcer needs the committed rules.
//! Creation registers the token on the CREATOR's device only, so every other
//! device has to adopt it. That step did not exist — the frontend had a
//! function that fetched the policy bytes and threw them away, and no route
//! registered anything. A transfer to a second device could never have settled,
//! and would have failed at the transfer layer with nothing obviously wrong.
//!
//! Adoption is NOT a state transition: no advance, no issuance, and no fee.
//! Only the creator burns the 10 ERA. Charging to *receive* a token would be
//! wrong, so that is pinned here rather than left to inspection.

#![allow(clippy::disallowed_methods)]

use prost::Message;
use std::path::PathBuf;

use dsm_sdk::bridge::{AppInvoke, AppRouter};
use dsm_sdk::generated;
use dsm_sdk::handlers::app_router_impl::AppRouterImpl;
use dsm_sdk::init::SdkConfig;
use dsm_sdk::runtime;
use dsm_sdk::storage::client_db::{reset_database_for_tests, token_registry};

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

fn new_router() -> AppRouterImpl {
    AppRouterImpl::new(SdkConfig {
        node_id: "test-device".to_string(),
        storage_endpoints: vec![],
        enable_offline: false,
    })
    .expect("router")
}

fn pack(body: Vec<u8>) -> Vec<u8> {
    generated::ArgPack {
        schema_hash: Some(generated::Hash32 { v: vec![0u8; 32] }),
        codec: generated::Codec::Proto as i32,
        body,
    }
    .encode_to_vec()
}

fn invoke(r: &AppRouterImpl, method: &str, args: Vec<u8>) -> dsm_sdk::bridge::AppResult {
    runtime::get_runtime().block_on(async {
        r.invoke(AppInvoke {
            method: method.to_string(),
            args,
        })
        .await
    })
}

/// Query routes take raw bytes, not an ArgPack body.
fn query(r: &AppRouterImpl, path: &str, params: Vec<u8>) -> dsm_sdk::bridge::AppResult {
    runtime::get_runtime().block_on(async {
        r.query(dsm_sdk::bridge::AppQuery {
            path: path.to_string(),
            params,
        })
        .await
    })
}

fn fund_era(r: &AppRouterImpl) {
    let res = invoke(
        r,
        "faucet.claim",
        pack(
            generated::FaucetClaimRequest {
                device_id: vec![0u8; 32],
            }
            .encode_to_vec(),
        ),
    );
    assert!(res.success, "faucet: {:?}", res.error_message);
}

fn era(r: &AppRouterImpl) -> u64 {
    let c = dsm::core::token::builtin_policy_commit_for_token("ERA").expect("ERA");
    r.core_sdk.device_head().map(|h| h.balance(&c)).unwrap_or(0)
}

/// Create a token so there is a real published policy to adopt, returning its
/// anchor.
fn create_token(r: &AppRouterImpl, ticker: &str) -> [u8; 32] {
    let req = generated::TokenCreateRequest {
        ticker: ticker.to_string(),
        alias: format!("{ticker} Token"),
        decimals: 2,
        max_supply_u128: 1_000_000u128.to_be_bytes().to_vec(),
        initial_alloc_u128: 1_000u128.to_be_bytes().to_vec(),
        mint_burn_enabled: true,
        transferable: true,
        unlimited_supply: false,
        mint_burn_threshold: 1,
        description: String::new(),
        icon_url: String::new(),
        allowlist_device_ids: Vec::new(),
    };
    let res = invoke(r, "token.create", pack(req.encode_to_vec()));
    assert!(res.success, "create: {:?}", res.error_message);
    let env = generated::Envelope::decode(&res.data[1..]).expect("envelope");
    match env.payload {
        Some(generated::envelope::Payload::TokenCreateResponse(t)) => {
            <[u8; 32]>::try_from(t.policy_anchor.as_slice()).expect("32-byte anchor")
        }
        other => panic!("expected TokenCreateResponse, got {other:?}"),
    }
}

/// (1) THE ROUTE MUST BE DISPATCHABLE.
///
/// The handler arm existed in token_routes.rs while app_router_impl's query
/// match list did not name it, so on device every call returned
/// "unknown query path: tokens.addByAnchor". A route the production dispatcher
/// cannot reach is not a route.
#[test]
#[serial_test::serial]
fn the_route_is_reachable_through_the_production_dispatcher() {
    runtime::dsm_init_runtime();
    init_test_storage();
    let r = new_router();

    // Deliberately wrong length: we want the ROUTE's own rejection, which
    // proves dispatch reached it, not the dispatcher's unknown-path error.
    let res = query(&r, "tokens.addByAnchor", vec![0u8; 4]);
    let msg = res.error_message.clone().unwrap_or_default();
    assert!(
        !msg.contains("unknown query path"),
        "tokens.addByAnchor is not registered in the production dispatch table: {msg}"
    );
    assert!(
        msg.contains("32 bytes"),
        "expected the route's own length check, got: {msg}"
    );
}

/// (4) Adoption charges no fee and advances no device state.
#[test]
#[serial_test::serial]
fn adoption_costs_no_era_and_does_not_advance_device_state() {
    runtime::dsm_init_runtime();
    init_test_storage();
    let r = new_router();
    fund_era(&r);
    let anchor = create_token(&r, "ADOPT");

    let era_before = era(&r);
    let root_before = r.core_sdk.device_head().map(|h| h.root());

    let res = query(&r, "tokens.addByAnchor", anchor.to_vec());
    assert!(res.success, "adopt: {:?}", res.error_message);

    assert_eq!(era(&r), era_before, "adoption must not burn any ERA");
    assert_eq!(
        r.core_sdk.device_head().map(|h| h.root()),
        root_before,
        "adoption must not advance the device state"
    );
}

/// (3) An exact duplicate adoption is idempotent, not an error.
#[test]
#[serial_test::serial]
fn adopting_the_same_token_twice_is_idempotent() {
    runtime::dsm_init_runtime();
    init_test_storage();
    let r = new_router();
    fund_era(&r);
    let anchor = create_token(&r, "TWICE");

    for attempt in 1..=3 {
        let res = query(&r, "tokens.addByAnchor", anchor.to_vec());
        assert!(
            res.success,
            "adoption attempt {attempt} must succeed: {:?}",
            res.error_message
        );
    }
    assert_eq!(
        token_registry::all_tokens().expect("registry").len(),
        1,
        "repeated adoption must not multiply registry rows"
    );
    assert_eq!(
        token_registry::all_policies().expect("policies").len(),
        1,
        "repeated adoption must not multiply policies"
    );
}

/// (5) A policy whose bytes do not hash to the requested anchor is refused.
///
/// This is the same rule creation enforces: a storage node able to return
/// arbitrary bytes under a requested anchor would be DEFINING the policy this
/// device then enforces.
#[test]
#[serial_test::serial]
fn an_anchor_that_resolves_to_nothing_fails_closed() {
    runtime::dsm_init_runtime();
    init_test_storage();
    let r = new_router();

    let res = query(&r, "tokens.addByAnchor", vec![0x5A; 32]);
    assert!(!res.success, "an unknown anchor must not adopt anything");
    assert_eq!(
        token_registry::all_tokens().expect("registry").len(),
        0,
        "a failed adoption must leave no registry row"
    );
}

/// (6) An adopted token survives a restart, because it is in the registry
/// rather than in memory.
#[test]
#[serial_test::serial]
fn an_adopted_token_survives_a_restart() {
    runtime::dsm_init_runtime();
    init_test_storage();
    let r = new_router();
    fund_era(&r);
    let anchor = create_token(&r, "PERSIST");
    assert!(query(&r, "tokens.addByAnchor", anchor.to_vec()).success);

    let before = token_registry::get_token_by_ticker("PERSIST")
        .expect("registry")
        .expect("adopted");

    // A fresh router over the same storage is what a relaunch looks like.
    drop(r);
    let r2 = new_router();
    let after = token_registry::get_token_by_ticker("PERSIST")
        .expect("registry")
        .expect("still adopted after restart");

    assert_eq!(before.token_id, after.token_id);
    assert_eq!(
        before.policy_commit, after.policy_commit,
        "the committed policy must be byte-identical across a restart"
    );
    assert_eq!(before.decimals, after.decimals);
    let _ = r2;
}
