// SPDX-License-Identifier: MIT OR Apache-2.0
//! Canonical amounts are integer base units; the UI speaks display units.
//!
//! THE HARDWARE FAILURE. A transfer of a token created with "1,000" at
//! decimals=2 failed with:
//!
//!   wallet.send: local state update failed:
//!   Invalid operation: advance: balance underflow on debit (insufficient funds)
//!
//! on a balance the wallet displayed as 1000. The log named the cause exactly:
//! `amount=25000 token=RIGB`. The send path converted the typed 250 into base
//! units (250 x 10^2), which is right; creation had credited `initial_alloc`
//! RAW, which is wrong. The token held 1_000 base units — 10.00 RIGB — while
//! every screen said 1000. The two sides disagreed about what a unit was.
//!
//! The invariant now: conversion happens EXACTLY ONCE, at the Rust boundary,
//! and everything downstream — policy bytes and the CPTA anchor, CreateToken,
//! conservation, the registry, the supply cap — carries base units. A policy
//! that committed a display number would make the enforced cap depend on how a
//! UI chose to render it.
//!
//! Integer arithmetic throughout, checked. No floating point ever touches an
//! amount.

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

fn fund_era(r: &AppRouterImpl) {
    assert!(
        invoke(
            r,
            "faucet.claim",
            pack(
                generated::FaucetClaimRequest {
                    device_id: vec![0u8; 32]
                }
                .encode_to_vec()
            )
        )
        .success
    );
}

/// Create with DISPLAY-unit quantities, exactly as the wizard sends them.
fn create(
    r: &AppRouterImpl,
    ticker: &str,
    decimals: u32,
    display_max: u128,
    display_alloc: u128,
) -> dsm_sdk::bridge::AppResult {
    let req = generated::TokenCreateRequest {
        ticker: ticker.to_string(),
        alias: format!("{ticker} Token"),
        decimals,
        max_supply_u128: display_max.to_be_bytes().to_vec(),
        initial_alloc_u128: display_alloc.to_be_bytes().to_vec(),
        mint_burn_enabled: true,
        transferable: true,
        unlimited_supply: false,
        mint_burn_threshold: 1,
        description: String::new(),
        icon_url: String::new(),
        allowlist_device_ids: Vec::new(),
    };
    invoke(r, "token.create", pack(req.encode_to_vec()))
}

fn token_id_of(res: &dsm_sdk::bridge::AppResult) -> String {
    let env = generated::Envelope::decode(&res.data[1..]).expect("envelope");
    match env.payload.clone() {
        Some(generated::envelope::Payload::TokenCreateResponse(t)) => t.token_id,
        other => panic!("unexpected {other:?}"),
    }
}

/// Canonical balance in BASE UNITS.
fn base_units(r: &AppRouterImpl, token_id: &str) -> u64 {
    let commit = token_registry::get_token(token_id)
        .expect("registry")
        .expect("token")
        .policy_commit;
    r.core_sdk
        .device_head()
        .map(|h| h.balance(&commit))
        .unwrap_or(0)
}

/// THE REPRODUCTION: decimals=2, display 1,000 -> canonical 100,000.
#[test]
#[serial_test::serial]
fn display_units_are_scaled_to_base_units_at_creation() {
    runtime::dsm_init_runtime();
    init_test_storage();
    let r = new_router();
    fund_era(&r);

    let res = create(&r, "SCALE2", 2, 1_000_000, 1_000);
    assert!(res.success, "create: {:?}", res.error_message);
    let id = token_id_of(&res);

    assert_eq!(
        base_units(&r, &id),
        100_000,
        "display 1,000 at 2 decimals must credit 100,000 base units"
    );
    let row = token_registry::get_token(&id)
        .expect("registry")
        .expect("row");
    assert_eq!(
        row.max_supply, 100_000_000,
        "the registry must record the BASE-UNIT cap, not the display number"
    );
}

/// decimals = 0 is the identity case: display and base units coincide.
#[test]
#[serial_test::serial]
fn zero_decimals_needs_no_scaling() {
    runtime::dsm_init_runtime();
    init_test_storage();
    let r = new_router();
    fund_era(&r);

    let res = create(&r, "SCALE0", 0, 1_000_000, 1_000);
    assert!(res.success, "create: {:?}", res.error_message);
    let id = token_id_of(&res);

    assert_eq!(base_units(&r, &id), 1_000);
    let row = token_registry::get_token(&id)
        .expect("registry")
        .expect("row");
    assert_eq!(row.max_supply, 1_000_000);
}

/// A high decimals value still scales exactly, with no precision loss —
/// integer arithmetic, never floating point.
#[test]
#[serial_test::serial]
fn high_decimals_scale_exactly() {
    runtime::dsm_init_runtime();
    init_test_storage();
    let r = new_router();
    fund_era(&r);

    let res = create(&r, "SCALE8", 8, 1_000, 1);
    assert!(res.success, "create: {:?}", res.error_message);
    let id = token_id_of(&res);

    assert_eq!(
        base_units(&r, &id),
        100_000_000,
        "1 unit at 8 decimals is exactly 10^8 base units"
    );
    let row = token_registry::get_token(&id)
        .expect("registry")
        .expect("row");
    assert_eq!(row.max_supply, 100_000_000_000);
}

/// A cap that overflows once scaled is refused BEFORE anything is committed.
#[test]
#[serial_test::serial]
fn a_quantity_that_overflows_when_scaled_is_refused() {
    runtime::dsm_init_runtime();
    init_test_storage();
    let r = new_router();
    fund_era(&r);

    let root_before = r.core_sdk.device_head().map(|h| h.root());
    let res = create(&r, "HUGE", 18, u128::MAX / 10, 1);
    assert!(!res.success, "an overflowing cap must be refused");
    assert_eq!(
        r.core_sdk.device_head().map(|h| h.root()),
        root_before,
        "a refused creation must not advance state"
    );
    assert_eq!(
        token_registry::all_tokens().expect("registry").len(),
        0,
        "and must leave no registry row"
    );
}

/// initial_alloc <= max_supply is checked in the SAME units, after scaling.
#[test]
#[serial_test::serial]
fn an_allocation_above_the_cap_is_refused() {
    runtime::dsm_init_runtime();
    init_test_storage();
    let r = new_router();
    fund_era(&r);

    let res = create(&r, "OVERAL", 2, 100, 101);
    assert!(
        !res.success,
        "an allocation larger than the cap must be refused"
    );
    assert_eq!(token_registry::all_tokens().expect("registry").len(), 0);
}

/// Supply accounting stays in base units end to end: create, mint, burn.
#[test]
#[serial_test::serial]
fn supply_accounting_stays_in_base_units() {
    runtime::dsm_init_runtime();
    init_test_storage();
    let r = new_router();
    fund_era(&r);

    let res = create(&r, "ACCT", 2, 10_000, 1_000);
    assert!(res.success, "create: {:?}", res.error_message);
    let id = token_id_of(&res);
    assert_eq!(base_units(&r, &id), 100_000, "1,000 display = 100,000 base");

    // Mint and burn routes take BASE units, matching canonical state.
    let mint = invoke(
        &r,
        "token.mint",
        pack(
            generated::TokenMintRequest {
                token_id: id.clone(),
                amount: 50_000,
                message: "mint".into(),
            }
            .encode_to_vec(),
        ),
    );
    assert!(mint.success, "mint: {:?}", mint.error_message);
    assert_eq!(base_units(&r, &id), 150_000);

    let burn = invoke(
        &r,
        "token.burn",
        pack(
            generated::TokenBurnRequest {
                token_id: id.clone(),
                amount: 25_000,
                message: "burn".into(),
            }
            .encode_to_vec(),
        ),
    );
    assert!(burn.success, "burn: {:?}", burn.error_message);
    assert_eq!(
        base_units(&r, &id),
        125_000,
        "create + mint - burn, all in base units"
    );
}

/// The supply cap is enforced against the SCALED cap. Under the old semantics
/// the cap was 10^decimals too small and would have refused a legitimate mint.
#[test]
#[serial_test::serial]
fn the_cap_is_enforced_against_the_scaled_value() {
    runtime::dsm_init_runtime();
    init_test_storage();
    let r = new_router();
    fund_era(&r);

    // Cap 1,000 display at 2 decimals = 100,000 base units.
    let res = create(&r, "CAPSC", 2, 1_000, 100);
    assert!(res.success, "create: {:?}", res.error_message);
    let id = token_id_of(&res);
    assert_eq!(base_units(&r, &id), 10_000);

    // 80,000 base units keeps us at 90,000 — inside the 100,000 cap. This is
    // the mint the unscaled cap would have wrongly refused.
    let ok = invoke(
        &r,
        "token.mint",
        pack(
            generated::TokenMintRequest {
                token_id: id.clone(),
                amount: 80_000,
                message: "within cap".into(),
            }
            .encode_to_vec(),
        ),
    );
    assert!(
        ok.success,
        "a mint inside the scaled cap must be allowed: {:?}",
        ok.error_message
    );
    assert_eq!(base_units(&r, &id), 90_000);

    // And 20,000 more would exceed 100,000, so it is refused.
    let over = invoke(
        &r,
        "token.mint",
        pack(
            generated::TokenMintRequest {
                token_id: id.clone(),
                amount: 20_000,
                message: "past cap".into(),
            }
            .encode_to_vec(),
        ),
    );
    assert!(!over.success, "a mint past the scaled cap must be refused");
    assert_eq!(
        base_units(&r, &id),
        90_000,
        "a refused mint credits nothing"
    );
}
