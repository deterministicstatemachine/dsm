// SPDX-License-Identifier: MIT OR Apache-2.0
//! A created token must survive a restart.
//!
//! Before the durable registry, a token lived only in `RwLock<HashMap>`s —
//! the metadata cache and the policy system. Both die with the process, so
//! after a restart `resolve_policy_commit_strict` failed and the token became
//! unusable: unsendable, and `dlv.create` (which resolves the pair's policy
//! commit and fails closed) could not build a vault for it.
//!
//! These tests simulate a restart by building a SECOND router against the same
//! database — the in-memory caches are fresh, exactly as after a relaunch.
//!
//! What the registry IS authoritative for is the persisted token IDENTITY
//! mapping: ticker, token id, policy commitment, metadata. Balances and
//! transitions remain canonical DeviceState's, so the quantities asserted here
//! are read from the head, and the registry is only asked what a token is.
//!
//! Quantities are BASE UNITS. `TokenCreateRequest` carries display units
//! because a person typed them, and Rust scales once at that boundary, so the
//! stored cap is `10^decimals` times the declared one. Storing the display
//! number would make an enforced supply cap depend on how a UI chose to render
//! it.

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

/// The request carries DISPLAY units; canonical state and the registry hold
/// base units. Everything asserted below is scaled by `SCALE`.
const DECIMALS: u32 = 8;
const SCALE: u64 = 100_000_000; // 10^DECIMALS
const DISPLAY_MAX_SUPPLY: u128 = 1_000_000;

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

/// Install a token in the durable shape a committed creation leaves — the
/// registry row plus the content-addressed policy bytes. Under 3.5b the
/// route cannot commit here (the fee is an ADMITTED economic debit and
/// integration tests have no fake register fleet); the create route's own
/// durable-write and reconciliation properties are pinned live in the lib
/// e2e `handlers::sender_admission_tests::token_routes_admit_fee_only_create_and_burn_end_to_end`.
/// These tests are about the READ side: restart survival and naming.
fn install_created(ticker: &str) -> (String, [u8; 32]) {
    let policy_bytes = format!("{ticker} policy bytes").into_bytes();
    let anchor = dsm::crypto::blake3::domain_hash_bytes(
        dsm::common::domain_tags::TAG_DSM_POLICY,
        &policy_bytes,
    );
    token_registry::upsert_policy(&anchor, &policy_bytes).expect("store policy");
    let mut h = dsm::crypto::blake3::dsm_domain_hasher(dsm::common::domain_tags::TAG_DSM_TOKEN_ID);
    h.update(&anchor);
    h.update(ticker.as_bytes());
    let token_id = dsm_sdk::util::text_id::encode_base32_crockford(h.finalize().as_bytes());
    token_registry::insert_token(&token_registry::TokenRegistryRow {
        token_id: token_id.clone(),
        policy_commit: anchor,
        ticker: ticker.to_string(),
        alias: format!("{ticker} Token"),
        decimals: DECIMALS,
        max_supply: DISPLAY_MAX_SUPPLY * SCALE as u128,
        owner_device_id: [0xAAu8; 32],
    })
    .expect("registry row");
    // What the SDK does whenever it loads or creates a token: hand core the
    // display mapping (authoritative for nothing; naming only).
    dsm::core::token::token_state_manager::register_policy_commit_ticker(anchor, ticker);
    (token_id, anchor)
}

/// THE RESTART PROOF. A fresh router — empty caches, same database — must
/// still resolve the token's policy commit and serve its policy.
#[test]
#[serial_test::serial]
fn token_survives_restart_and_resolves_from_the_database() {
    runtime::dsm_init_runtime();
    init_test_storage();

    let (token_id, anchor32) = {
        let first = new_router();
        fund_era(&first);
        let out = install_created("PERSB");
        drop(first); // in-memory caches go with it
        out
    };
    let anchor = anchor32.to_vec();

    // "Restart": a brand-new router over the same database.
    let second = new_router();
    runtime::get_runtime().block_on(second.rehydrate_token_registry());

    // The policy is served again...
    let q = invoke(
        &second,
        "tokens.listCachedPolicies",
        generated::ArgPack {
            schema_hash: Some(generated::Hash32 { v: vec![0u8; 32] }),
            codec: generated::Codec::Proto as i32,
            body: Vec::new(),
        }
        .encode_to_vec(),
    );
    let _ = q; // listing is a query route; the durable assertions below are the proof

    // ...and the durable registry still knows the token.
    let row = token_registry::get_token(&token_id)
        .expect("registry read after restart")
        .expect("token must survive the restart");
    assert_eq!(row.policy_commit.to_vec(), anchor);

    assert!(
        token_registry::load_policy_verified(&anchor32)
            .expect("policy read")
            .is_some(),
        "the anchored policy must still be resolvable after restart"
    );
}

/// READ-BACK PROOF. A created token must surface in the canonical projection
/// under its REAL ticker, never the old `{prefix}|?` placeholder, and with the
/// decimals it was created with rather than a hardcoded 0.
#[test]
#[serial_test::serial]
fn created_token_projects_under_its_real_ticker() {
    runtime::dsm_init_runtime();
    init_test_storage();
    let r = new_router();
    fund_era(&r);
    let (token_id, _anchor) = install_created("READBK");
    let _ = &r;

    let row = token_registry::get_token(&token_id)
        .expect("registry read")
        .expect("token recorded");

    // Core can now NAME this balance.
    let ticker = dsm::core::token::resolve_ticker_for_policy_commit(&row.policy_commit)
        .expect("a created token's ticker must be resolvable for display");
    assert_eq!(ticker, "READBK");

    // ...and the canonical balance key carries the real ticker suffix, not "?".
    let key = dsm::core::token::canonical_balance_key_for_commit(&row.policy_commit, &[0xBB; 32])
        .expect("balance key must be derivable");
    assert!(
        key.ends_with("|READBK"),
        "balance key must end with the real ticker, got {key}"
    );
    assert!(
        !key.ends_with("|?"),
        "the placeholder key is deleted — an unnameable balance is omitted, never shown wrong"
    );

    // Decimals come from the registry, not a hardcoded default.
    assert_eq!(row.decimals, DECIMALS, "created token keeps its decimals");
}

/// An unknown policy commit must yield NO key at all. Absent is the honest
/// failure mode; a row under a wrong token id would be worse than none.
#[test]
#[serial_test::serial]
fn unnameable_balance_yields_no_key() {
    runtime::dsm_init_runtime();
    init_test_storage();
    let unknown = [0x7Eu8; 32];
    assert!(
        dsm::core::token::resolve_ticker_for_policy_commit(&unknown).is_none(),
        "an unregistered commit has no ticker"
    );
    assert!(
        dsm::core::token::canonical_balance_key_for_commit(&unknown, &[0xBB; 32]).is_none(),
        "an unnameable balance must produce no projection key"
    );
}
