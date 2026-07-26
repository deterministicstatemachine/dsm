// SPDX-License-Identifier: MIT OR Apache-2.0
//! `token.mint` / `token.burn` end to end.
//!
//! Neither route existed at any layer before — the only mint was the one-shot
//! allocation inside creation — so none of the mint/burn policy could be
//! exercised, let alone proven. This is the acceptance matrix:
//!
//!   * an authorized mint succeeds and credits the token's OWN asset;
//!   * a mint that would exceed max supply is refused, and one landing exactly
//!     on the cap is allowed;
//!   * a burn succeeds and debits;
//!   * a burn larger than the balance is refused by the conservation guard;
//!   * an unknown token fails closed rather than minting something unnamed.

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
    let cfg = SdkConfig {
        node_id: "test-device".to_string(),
        storage_endpoints: vec![],
        enable_offline: false,
    };
    AppRouterImpl::new(cfg).expect("AppRouterImpl::new should succeed in test")
}

fn pack(body: Vec<u8>) -> Vec<u8> {
    generated::ArgPack {
        schema_hash: Some(generated::Hash32 { v: vec![0u8; 32] }),
        codec: generated::Codec::Proto as i32,
        body,
    }
    .encode_to_vec()
}

fn invoke(router: &AppRouterImpl, method: &str, args: Vec<u8>) -> dsm_sdk::bridge::AppResult {
    runtime::get_runtime().block_on(async {
        router
            .invoke(AppInvoke {
                method: method.to_string(),
                args,
            })
            .await
    })
}

fn fund_era(router: &AppRouterImpl) {
    let res = invoke(
        router,
        "faucet.claim",
        pack(
            generated::FaucetClaimRequest {
                device_id: vec![0u8; 32],
            }
            .encode_to_vec(),
        ),
    );
    assert!(res.success, "faucet claim failed: {:?}", res.error_message);
}

/// Create a token with a known cap and allocation, returning its token_id.
fn create_token(router: &AppRouterImpl, ticker: &str, max_supply: u128, alloc: u128) -> String {
    let req = generated::TokenCreateRequest {
        ticker: ticker.to_string(),
        alias: format!("{ticker} Token"),
        decimals: 0,
        max_supply_u128: max_supply.to_be_bytes().to_vec(),
        initial_alloc_u128: alloc.to_be_bytes().to_vec(),
        mint_burn_enabled: true,
        transferable: true,
        unlimited_supply: false,
        mint_burn_threshold: 1,
        description: String::new(),
        icon_url: String::new(),
        allowlist_device_ids: Vec::new(),
    };
    let res = invoke(router, "token.create", pack(req.encode_to_vec()));
    assert!(res.success, "create failed: {:?}", res.error_message);
    let env = generated::Envelope::decode(&res.data[1..]).expect("envelope");
    match env.payload {
        Some(generated::envelope::Payload::TokenCreateResponse(r)) => r.token_id,
        other => panic!("expected TokenCreateResponse, got {other:?}"),
    }
}

fn mint(router: &AppRouterImpl, token_id: &str, amount: u64) -> dsm_sdk::bridge::AppResult {
    invoke(
        router,
        "token.mint",
        pack(
            generated::TokenMintRequest {
                token_id: token_id.to_string(),
                amount,
                message: "test mint".into(),
            }
            .encode_to_vec(),
        ),
    )
}

fn burn(router: &AppRouterImpl, token_id: &str, amount: u64) -> dsm_sdk::bridge::AppResult {
    invoke(
        router,
        "token.burn",
        pack(
            generated::TokenBurnRequest {
                token_id: token_id.to_string(),
                amount,
                message: "test burn".into(),
            }
            .encode_to_vec(),
        ),
    )
}

fn balance_of(router: &AppRouterImpl, token_id: &str) -> u64 {
    let commit = token_registry::get_token(token_id)
        .expect("registry read")
        .expect("token exists")
        .policy_commit;
    router
        .core_sdk
        .device_head()
        .map(|h| h.balance(&commit))
        .unwrap_or(0)
}

fn era_balance(router: &AppRouterImpl) -> u64 {
    let commit = dsm::core::token::builtin_policy_commit_for_token("ERA").expect("ERA builtin");
    router
        .core_sdk
        .device_head()
        .map(|h| h.balance(&commit))
        .unwrap_or(0)
}

/// An authorized mint succeeds and credits the token's own asset — never ERA.
#[test]
#[serial_test::serial]
fn authorized_mint_succeeds_and_credits_the_right_asset() {
    runtime::dsm_init_runtime();
    init_test_storage();
    let r = new_router();
    fund_era(&r);
    let token = create_token(&r, "MINTA", 1_000, 100);

    let era_before = era_balance(&r);
    let res = mint(&r, &token, 50);
    assert!(res.success, "mint failed: {:?}", res.error_message);

    assert_eq!(balance_of(&r, &token), 150, "mint must credit the token");
    assert_eq!(
        era_balance(&r),
        era_before,
        "a mint of another token must never move ERA"
    );
}

/// The supply cap is enforced: a mint that would exceed it is refused, one
/// landing exactly on it is allowed.
#[test]
#[serial_test::serial]
fn mint_respects_the_supply_cap() {
    runtime::dsm_init_runtime();
    init_test_storage();
    let r = new_router();
    fund_era(&r);
    let token = create_token(&r, "CAPD", 1_000, 900);

    let over = mint(&r, &token, 101);
    assert!(!over.success, "a mint past the cap must be refused");
    assert_eq!(
        balance_of(&r, &token),
        900,
        "a refused mint credits nothing"
    );

    let exact = mint(&r, &token, 100);
    assert!(
        exact.success,
        "a mint landing exactly on the cap must be allowed: {:?}",
        exact.error_message
    );
    assert_eq!(balance_of(&r, &token), 1_000);
}

/// A burn debits the caller's balance.
#[test]
#[serial_test::serial]
fn authorized_burn_succeeds() {
    runtime::dsm_init_runtime();
    init_test_storage();
    let r = new_router();
    fund_era(&r);
    let token = create_token(&r, "BURNA", 1_000, 500);

    let res = burn(&r, &token, 200);
    assert!(res.success, "burn failed: {:?}", res.error_message);
    assert_eq!(balance_of(&r, &token), 300);
}

/// Burn > balance is refused by the conservation guard's checked_sub, which
/// runs before the durable write — so nothing is destroyed.
#[test]
#[serial_test::serial]
fn burn_beyond_balance_is_refused() {
    runtime::dsm_init_runtime();
    init_test_storage();
    let r = new_router();
    fund_era(&r);
    let token = create_token(&r, "BURNB", 1_000, 100);

    let res = burn(&r, &token, 101);
    assert!(!res.success, "burning more than held must be refused");
    assert_eq!(
        balance_of(&r, &token),
        100,
        "a refused burn must destroy nothing"
    );
}

/// An unknown token fails closed rather than minting an unnamed asset.
#[test]
#[serial_test::serial]
fn mint_of_an_unknown_token_fails_closed() {
    runtime::dsm_init_runtime();
    init_test_storage();
    let r = new_router();
    fund_era(&r);

    let res = mint(&r, "NOSUCHTOKEN", 10);
    assert!(!res.success, "an unknown token must not be mintable");
}

/// Zero-amount operations are rejected rather than producing an empty advance.
#[test]
#[serial_test::serial]
fn zero_amount_is_rejected() {
    runtime::dsm_init_runtime();
    init_test_storage();
    let r = new_router();
    fund_era(&r);
    let token = create_token(&r, "ZEROA", 1_000, 10);

    assert!(!mint(&r, &token, 0).success);
    assert!(!burn(&r, &token, 0).success);
}

/// Mint then burn round-trips exactly — supply accounting stays consistent.
#[test]
#[serial_test::serial]
fn mint_then_burn_round_trips() {
    runtime::dsm_init_runtime();
    init_test_storage();
    let r = new_router();
    fund_era(&r);
    let token = create_token(&r, "RTRIP", 10_000, 1_000);

    assert!(mint(&r, &token, 500).success);
    assert_eq!(balance_of(&r, &token), 1_500);
    assert!(burn(&r, &token, 500).success);
    assert_eq!(
        balance_of(&r, &token),
        1_000,
        "a mint followed by an equal burn must return to the starting balance"
    );
}
