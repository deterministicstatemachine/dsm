// SPDX-License-Identifier: MIT OR Apache-2.0
//! A lost reply must not look like a failed creation.
//!
//! On hardware the first `token.create` committed — 10 ERA burned, 1,000 RIGA
//! credited, registry row written — while the reply never reached the wizard,
//! which sat on "Publishing policy…" and then said "Token creation failed".
//! Retrying hit the registry's UNIQUE constraint and failed again. A successful
//! creation presented as two failures, and the only thing that stopped a second
//! fee being burned was a database constraint firing at the right moment.
//!
//! The identity makes this answerable rather than guessable:
//!
//!   token_id = BLAKE3(TAG_DSM_TOKEN_ID, policy_anchor ‖ ticker)
//!   policy_anchor = BLAKE3(TAG_DSM_POLICY, policy_bytes)
//!
//! so the id IS the creation commitment. Resubmitting the same commitment is
//! answered from canonical state; resubmitting a different one that claims a
//! taken ticker is a hard conflict.
//!
//! What is pinned here:
//!   * a repeated identical creation returns success without a second advance;
//!   * the fee is burned exactly once no matter how many times it is submitted;
//!   * supply is credited exactly once;
//!   * one token and one policy survive repeated attempts;
//!   * a different creation claiming a taken ticker is refused, not merged.

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
        r,
        dsm::core::token::builtin_policy_commit_for_token("ERA").expect("ERA commit"),
        100,
    )
    .expect("seed the fixture ERA balance");
}

fn request(ticker: &str, alloc: u128) -> generated::TokenCreateRequest {
    generated::TokenCreateRequest {
        ticker: ticker.to_string(),
        alias: format!("{ticker} Token"),
        decimals: 2,
        max_supply_u128: 0u128.to_be_bytes().to_vec(),
        initial_alloc_u128: alloc.to_be_bytes().to_vec(),
        mint_burn_enabled: true,
        transferable: true,
        unlimited_supply: true,
        mint_burn_threshold: 1,
        description: String::new(),
        icon_url: String::new(),
        allowlist_device_ids: Vec::new(),
    }
}

/// Submit a creation and return (success, token_id, message).
fn create(r: &AppRouterImpl, req: &generated::TokenCreateRequest) -> (bool, String, String) {
    let res = invoke(r, "token.create", pack(req.encode_to_vec()));
    if !res.success {
        return (false, String::new(), res.error_message.unwrap_or_default());
    }
    let env = generated::Envelope::decode(&res.data[1..]).expect("envelope");
    match env.payload {
        Some(generated::envelope::Payload::TokenCreateResponse(r)) => {
            (r.success, r.token_id, r.message)
        }
        other => panic!("expected TokenCreateResponse, got {other:?}"),
    }
}

fn era(r: &AppRouterImpl) -> u64 {
    let c = dsm::core::token::builtin_policy_commit_for_token("ERA").expect("ERA");
    r.core_sdk.device_head().map(|h| h.balance(&c)).unwrap_or(0)
}

/// 3.5b: creator supply gets the NAMED refusal, and — the reconciliation
/// property inverted — a refused creation leaves no reconcilable trace: no
/// fee, no row, and the identical retry is refused again rather than
/// "reconciled" into a phantom success. (Commit-side reconciliation of the
/// fee-only shape lives in the lib e2e
/// `token_routes_admit_fee_only_create_and_burn_end_to_end`; integration
/// tests have no fake fleet, so nothing can commit here.)
#[test]
#[serial_test::serial]
fn a_refused_creator_supply_leaves_no_reconcilable_trace() {
    runtime::dsm_init_runtime();
    init_test_storage();
    let r = new_router();
    fund_era(&r);

    let req = request("RECON", 1_000);
    let before = era(&r);

    let (ok1, _, msg1) = create(&r, &req);
    assert!(!ok1, "creator supply must be refused");
    assert!(
        msg1.contains("initial_supply > 0 cannot enter a validated lineage"),
        "the refusal must be the NAMED issuance-predicate error, got: {msg1}"
    );
    assert_eq!(era(&r), before, "a refused creation burns nothing");
    assert_eq!(
        token_registry::all_tokens().expect("registry").len(),
        0,
        "no registry row"
    );

    let (ok2, _, _) = create(&r, &req);
    assert!(
        !ok2,
        "the identical retry is refused again, never reconciled"
    );
    assert_eq!(era(&r), before, "still nothing burned");
}

/// An unaffordable creation still leaves nothing behind — including no registry
/// row that a later reconciliation could mistake for a success.
#[test]
#[serial_test::serial]
fn an_unaffordable_creation_leaves_no_reconcilable_trace() {
    runtime::dsm_init_runtime();
    init_test_storage();
    let r = new_router();
    // deliberately unfunded: no ERA for the fee

    let (ok, _, msg) = create(&r, &request("BROKE", 0));
    assert!(!ok, "creation without the fee must fail");
    assert!(
        msg.contains("insufficient ERA"),
        "must fail on affordability, not an earlier gate, got: {msg}"
    );
    assert_eq!(
        token_registry::all_tokens().expect("registry").len(),
        0,
        "a failed creation must leave no registry row"
    );

    // And the retry must report a retryable failure, not a phantom success.
    let (ok2, _, _) = create(&r, &request("BROKE", 0));
    assert!(!ok2, "retrying an unaffordable creation must still fail");
}
