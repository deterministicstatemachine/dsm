// SPDX-License-Identifier: MIT OR Apache-2.0
//! The 10 ERA creation fee — refusal contracts.
//!
//! 3.5b made the creation fee an ADMITTED economic debit, and integration
//! tests have no fake register fleet (`cfg(test)`-only), so no creation can
//! COMMIT here any more. What this suite pins is the fail-closed half of fee
//! atomicity: a creation that cannot be admitted burns nothing, advances
//! nothing, and leaves no registry row. The commit-side properties (fee
//! burned once, reconciliation, anchor contract) moved to the lib e2e
//! `handlers::sender_admission_tests::token_routes_admit_fee_only_create_and_burn_end_to_end`.
//!
//! Two properties of the surrounding design shape what these tests assert.
//!
//! UNITS. `TokenCreateRequest` carries DISPLAY units, because a person typed
//! them. Rust scales to base units exactly once, at this boundary, and
//! everything downstream — the policy bytes, the CPTA anchor, CreateToken,
//! conservation, the registry cap — is base units. So a request for 250 at
//! decimals=2 credits 25_000, and the assertions here are in base units.
//!
//! IDENTITY. `token_id = BLAKE3(TAG_DSM_TOKEN_ID, policy_anchor ‖ ticker)`,
//! so the id IS the creation commitment. Resubmitting the same commitment
//! names the same token and is answered from canonical state; it is not a
//! second creation to be refused. What must never happen is a second fee, a
//! second advance, or a second row.
//!
//! The properties pinned here:
//!   * the fee is charged, and burned (no counterparty is credited);
//!   * insufficient ERA rejects BEFORE anything commits — a failed creation
//!     burns nothing and advances nothing;
//!   * an identical resubmission reconciles: one fee, one advance, one row;
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

/// A creation request in DISPLAY units, exactly as the wizard sends them.
/// `DECIMALS` is what turns those into the base units canonical state holds.
const DECIMALS: u32 = 2;

fn create_request(ticker: &str, display_alloc: u128) -> Vec<u8> {
    let req = generated::TokenCreateRequest {
        ticker: ticker.to_string(),
        alias: format!("{ticker} Token"),
        decimals: DECIMALS,
        max_supply_u128: 1_000_000u128.to_be_bytes().to_vec(),
        initial_alloc_u128: display_alloc.to_be_bytes().to_vec(),
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
    // Seed the fixture balance DIRECTLY. This used to call `faucet.claim`, which
    // minted builtin ERA on nothing more than a caller-supplied device_id — the
    // same unauthorized-issuance defect the accepting-layer gate now refuses. That
    // refusal is total: it applies in tests exactly as in production, so a fixture
    // cannot mint and must not try (no `faucet.claim`, no `wallet.mint_for_self`,
    // no `Operation::Mint`).
    //
    // 100 base units — the amount the old faucet granted (`claim_amount: 100`), so
    // balance assertions downstream are unchanged.
    dsm_sdk::handlers::app_router_impl::install_balance_for_testing(
        router,
        dsm::core::token::builtin_policy_commit_for_token("ERA").expect("ERA commit"),
        100,
    )
    .expect("seed the fixture ERA balance");
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

/// A creation whose fee debit cannot be ADMITTED (no reachable register
/// fleet here) must fail closed: no fee burned, no head advance, no row.
#[test]
#[serial_test::serial]
fn an_unadmittable_creation_fails_closed_and_burns_nothing() {
    runtime::dsm_init_runtime();
    init_test_storage();
    let r = new_router();
    fund_era(&r);

    let before_era = era_balance(&r);
    let before_root = head_root(&r);
    assert!(
        before_era >= FEE,
        "fixture funds the fee — the refusal must not be affordability"
    );

    let res = invoke(&r, "token.create", create_request("FEEA", 0));
    assert!(
        !res.success,
        "a fee debit with no admittable economic lineage must be refused"
    );
    assert_eq!(era_balance(&r), before_era, "no ERA may be burned");
    assert_eq!(
        head_root(&r),
        before_root,
        "canonical head must not advance"
    );
    assert!(
        token_registry::get_token_by_ticker("FEEA")
            .expect("read")
            .is_none(),
        "no registry row may survive a refused creation"
    );
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
