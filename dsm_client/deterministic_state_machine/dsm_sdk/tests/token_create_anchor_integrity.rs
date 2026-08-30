// SPDX-License-Identifier: MIT OR Apache-2.0
//! Anchor-integrity and fail-closed guards for `token.create`.
//!
//! The policy anchor is content-addressed BY DEFINITION —
//! `BLAKE3(TAG_DSM_POLICY, policy_bytes)` — and it becomes the
//! `policy_commit` on the issuance `BalanceDelta`. Whoever names that anchor
//! names the asset that gets credited, so the anchor is derived in Rust and
//! nowhere else:
//!
//! * A storage node cannot name it — the publish path derives locally and
//!   treats a node's 32-byte reply purely as an echo to be verified.
//! * A client cannot name it — `TokenCreateRequest` has no anchor field
//!   (field 5 is reserved). Rust packs the policy and hashes what it packed.
//!
//! These tests pin that contract end to end through the real route.

#![allow(clippy::disallowed_methods)]

use prost::Message;
use std::path::PathBuf;

use dsm_sdk::bridge::{AppInvoke, AppRouter};
use dsm_sdk::generated;
use dsm_sdk::handlers::app_router_impl::AppRouterImpl;
use dsm_sdk::init::SdkConfig;
use dsm_sdk::runtime;
use dsm_sdk::storage::client_db::reset_database_for_tests;

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
    let cfg = SdkConfig {
        node_id: "test-device".to_string(),
        storage_endpoints: vec![],
        enable_offline: false,
    };
    AppRouterImpl::new(cfg).expect("AppRouterImpl::new should succeed in test")
}

fn create_request(ticker: &str, max_supply: u128, initial_alloc: u128) -> Vec<u8> {
    let req = generated::TokenCreateRequest {
        ticker: ticker.to_string(),
        alias: "Integrity Test Token".to_string(),
        decimals: 8,
        max_supply_u128: max_supply.to_be_bytes().to_vec(),
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

/// Creation now costs ERA, so every fixture must fund the device first.
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

/// The publish route must return the LOCAL content hash, never a node-supplied
/// value. With no storage nodes configured this holds trivially; the assertion
/// pins the contract so a future change that adopts a remote anchor fails here.
#[test]
#[serial_test::serial]
fn publish_returns_the_local_content_hash() {
    let r = router();
    fund_era(&r);
    let proto = generated::TokenPolicyV3 {
        policy_bytes: vec![0x01, 0x02, 0x03, 0x04],
    }
    .encode_to_vec();

    let res = invoke(&r, "tokens.publishPolicy", proto.clone());
    assert!(res.success, "publish should succeed");

    let expected =
        dsm::crypto::blake3::domain_hash_bytes(dsm::common::domain_tags::TAG_DSM_POLICY, &proto);
    assert_eq!(
        res.data,
        expected.to_vec(),
        "publish MUST return BLAKE3(TAG_DSM_POLICY, policy_bytes) — the anchor is \
         content-addressed and no storage node may name it"
    );
}

// The end-to-end "create derives its own anchor" test moved to the lib e2e
// `handlers::sender_admission_tests::token_routes_admit_fee_only_create_and_burn_end_to_end`:
// under 3.5b a creation's fee is an ADMITTED economic debit, and integration
// tests have no fake register fleet, so no creation can commit here.

/// A token whose allocation exceeds its cap must be rejected by Rust, not just
/// by the wizard — the old code checked this only in TypeScript.
#[test]
#[serial_test::serial]
fn create_rejects_initial_alloc_above_max_supply() {
    let r = router();
    fund_era(&r);
    let res = invoke(&r, "token.create", create_request("OVER", 100, 101));
    assert!(
        !res.success,
        "allocation above the cap must be rejected in Rust"
    );
    let msg = res.error_message.clone().unwrap_or_default();
    assert!(
        msg.contains("initial allocation exceeds max supply"),
        "must be the cap comparison, not a later capability gate, got: {msg}"
    );
}

/// Ticker validation is protocol, not presentation.
#[test]
#[serial_test::serial]
fn create_rejects_bad_ticker() {
    let r = router();
    fund_era(&r);
    let res = invoke(&r, "token.create", create_request("X", 1_000, 1));
    assert!(!res.success, "a 1-char ticker must be rejected");
}
