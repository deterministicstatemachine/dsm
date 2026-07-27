// SPDX-License-Identifier: MIT OR Apache-2.0
//! The 10 ERA creation fee, burned atomically with the token.
//!
//! Creation destroys ERA and issues the new asset in ONE canonical advance —
//! one SMT root, one CAS. Either the token exists and the fee was paid, or
//! neither happened. There is no compensating step to get wrong.
//!
//! The properties pinned here:
//!   * the fee is charged, and burned (no counterparty is credited);
//!   * insufficient ERA rejects BEFORE anything commits — a failed creation
//!     burns nothing and advances nothing;
//!   * a duplicate creation charges once;
//!   * creation still advances canonical state when the allocation is zero,
//!     so the token exists on the chain either way.

#![allow(clippy::disallowed_methods)]

use prost::Message;
use std::path::PathBuf;

use dsm_sdk::bridge::{AppInvoke, AppRouter};
use dsm_sdk::generated;
use dsm_sdk::handlers::app_router_impl::AppRouterImpl;
use dsm_sdk::init::SdkConfig;
use dsm_sdk::runtime;
use dsm_sdk::storage::client_db::{reset_database_for_tests, token_registry};

const FEE: u64 = dsm::core::token::TOKEN_CREATION_FEE_ERA;

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

fn create_request(ticker: &str, initial_alloc: u128) -> Vec<u8> {
    let req = generated::TokenCreateRequest {
        ticker: ticker.to_string(),
        alias: format!("{ticker} Token"),
        decimals: 2,
        max_supply_u128: 1_000_000u128.to_be_bytes().to_vec(),
        initial_alloc_u128: initial_alloc.to_be_bytes().to_vec(),
        mint_burn_enabled: true,
        transferable: true,
        unlimited_supply: false,
        mint_burn_threshold: 1,
        description: String::new(),
        icon_url: String::new(),
        allowlist_device_ids: Vec::new(),
    };
    generated::ArgPack {
        schema_hash: Some(generated::Hash32 { v: vec![0u8; 32] }),
        codec: generated::Codec::Proto as i32,
        body: req.encode_to_vec(),
    }
    .encode_to_vec()
}

/// Claim ERA from the faucet so the device can afford the fee.
fn fund_era(router: &AppRouterImpl) {
    let req = generated::FaucetClaimRequest {
        device_id: vec![0u8; 32],
    };
    let args = generated::ArgPack {
        schema_hash: Some(generated::Hash32 { v: vec![0u8; 32] }),
        codec: generated::Codec::Proto as i32,
        body: req.encode_to_vec(),
    }
    .encode_to_vec();
    let res = invoke(router, "faucet.claim", args);
    assert!(res.success, "faucet claim failed: {:?}", res.error_message);
}

fn era_balance(router: &AppRouterImpl) -> u64 {
    let commit = dsm::core::token::builtin_policy_commit_for_token("ERA").expect("ERA builtin");
    router
        .core_sdk
        .device_head()
        .map(|h| h.balance(&commit))
        .unwrap_or(0)
}

fn head_root(router: &AppRouterImpl) -> [u8; 32] {
    router
        .core_sdk
        .device_head()
        .map(|h| h.root())
        .unwrap_or([0u8; 32])
}

/// The fee is charged and BURNED — ERA drops by exactly the fee, and the new
/// token is credited its allocation, from one advance.
#[test]
#[serial_test::serial]
fn creation_burns_exactly_the_fee_and_credits_the_allocation() {
    runtime::dsm_init_runtime();
    init_test_storage();
    let r = new_router();
    fund_era(&r);

    let before = era_balance(&r);
    assert!(before >= FEE, "fixture must fund at least the fee");

    let res = invoke(&r, "token.create", create_request("FEEA", 250));
    assert!(res.success, "create failed: {:?}", res.error_message);

    let after = era_balance(&r);
    assert_eq!(
        after,
        before - FEE,
        "ERA must drop by exactly the {FEE} ERA creation fee"
    );

    // The new asset was credited its allocation in the same advance.
    let row = token_registry::get_token_by_ticker("FEEA")
        .expect("registry read")
        .expect("token recorded");
    let issued = r
        .core_sdk
        .device_head()
        .map(|h| h.balance(&row.policy_commit))
        .unwrap_or(0);
    // Base units. The request carries DISPLAY units, and Rust scales once at
    // the boundary, so 250 at decimals=2 is 25_000 canonical. This assertion
    // read 250 until creation stopped crediting the display number raw — the
    // mismatch that made a transfer of a token the wallet showed as 1000 fail
    // with a balance underflow.
    assert_eq!(issued, 25_000, "initial allocation must be credited");
}

/// FAILED CREATION BURNS NOTHING. With insufficient ERA the create must reject
/// before anything commits: balance unchanged, device head unmoved, no token.
#[test]
#[serial_test::serial]
fn insufficient_era_rejects_and_burns_nothing() {
    runtime::dsm_init_runtime();
    init_test_storage();
    let r = new_router();
    // Deliberately NOT funded.

    let before_era = era_balance(&r);
    let before_root = head_root(&r);
    assert!(before_era < FEE, "fixture must start below the fee");

    let res = invoke(&r, "token.create", create_request("POOR", 10));
    assert!(!res.success, "creation must reject without the fee");
    let msg = res.error_message.unwrap_or_default();
    assert!(
        msg.contains("insufficient ERA"),
        "expected an insufficient-ERA rejection, got: {msg}"
    );

    assert_eq!(era_balance(&r), before_era, "no ERA may be burned");
    assert_eq!(
        head_root(&r),
        before_root,
        "canonical head must not advance"
    );
    assert!(
        token_registry::get_token_by_ticker("POOR")
            .expect("read")
            .is_none(),
        "no token row may survive a failed creation"
    );
}

/// A duplicate creation must charge the fee ONCE. The registry's unique
/// constraints reject the second attempt before any advance.
#[test]
#[serial_test::serial]
fn duplicate_creation_charges_the_fee_once() {
    runtime::dsm_init_runtime();
    init_test_storage();
    let r = new_router();
    fund_era(&r);

    let before = era_balance(&r);
    assert!(invoke(&r, "token.create", create_request("DUPE", 5)).success);
    let after_first = era_balance(&r);
    assert_eq!(after_first, before - FEE);

    // An IDENTICAL resubmission is the retry a user makes when the first
    // attempt's reply was lost. It is answered from canonical state — the
    // token id IS the creation commitment — so it reports success and pays
    // nothing. Rejecting it, as this once asserted, made a committed creation
    // present as two failures on hardware. A *different* creation claiming the
    // same ticker is still a hard conflict; that is pinned in
    // token_create_reconciliation.rs.
    let second = invoke(&r, "token.create", create_request("DUPE", 5));
    assert!(
        second.success,
        "an identical resubmission must reconcile, not fail: {:?}",
        second.error_message
    );
    assert_eq!(
        era_balance(&r),
        after_first,
        "and it must not charge a second fee"
    );
}

/// Creation is a canonical event even with no initial allocation — the fee is
/// still burned and the chain still advances, so the token is recoverable.
#[test]
#[serial_test::serial]
fn zero_allocation_still_advances_and_charges() {
    runtime::dsm_init_runtime();
    init_test_storage();
    let r = new_router();
    fund_era(&r);

    let before_era = era_balance(&r);
    let before_root = head_root(&r);

    let res = invoke(&r, "token.create", create_request("ZERO", 0));
    assert!(res.success, "create failed: {:?}", res.error_message);

    assert_eq!(era_balance(&r), before_era - FEE, "fee still charged");
    assert_ne!(
        head_root(&r),
        before_root,
        "creation must advance canonical state even at zero allocation"
    );
}

/// CLASSIFICATION GUARD. Creation destroys ERA, so it is value EGRESS and its
/// egress asset is ERA — not the newly issued token. Misclassifying it as
/// ingress (as it was while nothing constructed the variant) would let a
/// create-with-fee bypass the recovery egress gate entirely.
#[test]
fn create_token_is_value_egress_over_era() {
    use dsm::types::operations::{EgressAsset, Operation};
    let op = Operation::CreateToken {
        token_id: b"TOK".to_vec(),
        initial_supply: dsm::types::token_types::Balance::from_state(5, [0u8; 32]),
        policy_commit: [0x42; 32],
        fee_amount: FEE,
        name: "Token".into(),
        symbol: "TOK".into(),
        decimals: 2,
        metadata_uri: None,
        signature: Vec::new(),
    };
    assert!(
        op.is_value_egress(),
        "token creation burns ERA and must be classified as value egress"
    );
    match op.egress_asset() {
        EgressAsset::Asset { token_id, amount } => {
            assert_eq!(token_id, b"ERA".to_vec(), "the asset that LEAVES is ERA");
            assert_eq!(amount, FEE);
        }
        other => panic!("expected the ERA fee as the egress asset, got {other:?}"),
    }
}
