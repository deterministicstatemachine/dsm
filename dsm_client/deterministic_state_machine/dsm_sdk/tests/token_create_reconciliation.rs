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

fn request(ticker: &str, max: u128, alloc: u128) -> generated::TokenCreateRequest {
    generated::TokenCreateRequest {
        ticker: ticker.to_string(),
        alias: format!("{ticker} Token"),
        decimals: 2,
        max_supply_u128: max.to_be_bytes().to_vec(),
        initial_alloc_u128: alloc.to_be_bytes().to_vec(),
        mint_burn_enabled: true,
        transferable: true,
        unlimited_supply: false,
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

fn balance_of(r: &AppRouterImpl, token_id: &str) -> u64 {
    let c = token_registry::get_token(token_id)
        .expect("registry")
        .expect("token")
        .policy_commit;
    r.core_sdk.device_head().map(|h| h.balance(&c)).unwrap_or(0)
}

/// THE HARDWARE CASE. The commit lands, the reply is lost, the caller retries
/// the identical request. It must be told the truth — that the token exists —
/// and it must not pay again.
#[test]
#[serial_test::serial]
fn a_repeated_identical_creation_reports_success_and_charges_one_fee() {
    runtime::dsm_init_runtime();
    init_test_storage();
    let r = new_router();
    fund_era(&r);

    let req = request("RECON", 1_000_000, 1_000);
    let before = era(&r);

    let (ok1, id1, _) = create(&r, &req);
    assert!(ok1, "first creation must succeed");
    let after_first = era(&r);
    assert_eq!(
        before - after_first,
        10,
        "creation must burn exactly 10 ERA"
    );

    // The retry a user makes when the first attempt appears to have failed.
    let (ok2, id2, msg2) = create(&r, &req);
    assert!(
        ok2,
        "an identical resubmission must report success, not failure"
    );
    assert_eq!(id1, id2, "the same commitment must yield the same token id");
    assert_eq!(
        era(&r),
        after_first,
        "a resubmission must not burn a second fee: {msg2}"
    );
    // Base units: the request carries display units and Rust scales once at
    // the boundary, so 1,000 at decimals=2 is 100,000 canonical.
    assert_eq!(
        balance_of(&r, &id1),
        100_000,
        "supply must be credited exactly once, in base units"
    );
}

/// However many times it is submitted, canonical state holds one of everything.
#[test]
#[serial_test::serial]
fn one_token_one_policy_one_fee_across_repeated_attempts() {
    runtime::dsm_init_runtime();
    init_test_storage();
    let r = new_router();
    fund_era(&r);

    let req = request("MANYX", 500_000, 250);
    let before = era(&r);

    let mut ids = Vec::new();
    for _ in 0..4 {
        let (ok, id, msg) = create(&r, &req);
        assert!(ok, "every identical attempt must report success: {msg}");
        ids.push(id);
    }

    assert!(
        ids.windows(2).all(|w| w[0] == w[1]),
        "one identity throughout"
    );
    assert_eq!(before - era(&r), 10, "exactly one fee across four attempts");
    assert_eq!(
        balance_of(&r, &ids[0]),
        25_000,
        "one allocation, in base units (250 display at 2 decimals)"
    );
    assert_eq!(
        token_registry::all_tokens().expect("registry").len(),
        1,
        "exactly one registry row"
    );
    assert_eq!(
        token_registry::all_policies().expect("policies").len(),
        1,
        "exactly one policy"
    );
}

/// A DIFFERENT creation that wants a taken ticker is a conflict. Merging it
/// into the existing token would silently give the caller something other than
/// what they committed to.
#[test]
#[serial_test::serial]
fn a_conflicting_creation_on_a_taken_ticker_is_refused() {
    runtime::dsm_init_runtime();
    init_test_storage();
    let r = new_router();
    fund_era(&r);

    let (ok, _, _) = create(&r, &request("CLASH", 1_000, 100));
    assert!(ok);
    let after_first = era(&r);

    // Same ticker, different supply — a different commitment entirely.
    let (ok2, _, msg) = create(&r, &request("CLASH", 999_999, 100));
    assert!(!ok2, "a different creation must not take a claimed ticker");
    assert!(
        msg.to_lowercase().contains("ticker") || msg.to_lowercase().contains("conflict"),
        "the refusal should say the ticker is taken, got: {msg}"
    );
    assert_eq!(era(&r), after_first, "a refused creation burns nothing");
    assert_eq!(
        token_registry::all_tokens().expect("registry").len(),
        1,
        "the conflicting attempt must not add a row"
    );
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

    let (ok, _, _) = create(&r, &request("BROKE", 1_000, 10));
    assert!(!ok, "creation without the fee must fail");
    assert_eq!(
        token_registry::all_tokens().expect("registry").len(),
        0,
        "a failed creation must leave no registry row"
    );

    // And the retry must report a retryable failure, not a phantom success.
    let (ok2, _, _) = create(&r, &request("BROKE", 1_000, 10));
    assert!(!ok2, "retrying an unaffordable creation must still fail");
}
