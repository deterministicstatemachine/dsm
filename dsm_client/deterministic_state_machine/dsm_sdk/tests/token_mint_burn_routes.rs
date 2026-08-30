// SPDX-License-Identifier: MIT OR Apache-2.0
//! `token.mint` / `token.burn` / `token.create` refusal contracts.
//!
//! 3.5b made every value debit an ADMITTED economic transition, and integration
//! tests have no fake fleet (the `fake_registers`/`fake_fleet` seams are
//! `cfg(test)`-only), so no admitted operation can run here. What this suite
//! pins is therefore the REFUSAL surface:
//!
//!   * creation with `initial_supply > 0` gets the named issuance-predicate
//!     refusal (owner ruling — creator supply waits for `0x0029`);
//!   * a fee-bearing creation with no economic ancestry fails closed;
//!   * minting an unknown token fails closed;
//!   * a burn that cannot be admitted is refused, never performed locally.
//!
//! Admitted happy paths (faucet-funded burn, foreign walk) live in the lib
//! tests: `handlers::sender_admission_tests`.

#![allow(clippy::disallowed_methods)]

use prost::Message;
use serial_test::serial;
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

/// Attempt a CAPPED token creation — the shape beta refuses.
fn try_create_capped_token(
    router: &AppRouterImpl,
    ticker: &str,
    max_supply: u128,
) -> dsm_sdk::bridge::AppResult {
    let req = generated::TokenCreateRequest {
        ticker: ticker.to_string(),
        alias: format!("{ticker} Token"),
        decimals: 0,
        max_supply_u128: max_supply.to_be_bytes().to_vec(),
        initial_alloc_u128: 0u128.to_be_bytes().to_vec(),
        mint_burn_enabled: true,
        transferable: true,
        unlimited_supply: false,
        mint_burn_threshold: 1,
        description: String::new(),
        icon_url: String::new(),
        allowlist_device_ids: Vec::new(),
    };
    invoke(router, "token.create", pack(req.encode_to_vec()))
}

/// Attempt a token creation, returning the raw route result.
fn try_create_token(
    router: &AppRouterImpl,
    ticker: &str,
    alloc: u128,
) -> dsm_sdk::bridge::AppResult {
    let req = generated::TokenCreateRequest {
        ticker: ticker.to_string(),
        alias: format!("{ticker} Token"),
        decimals: 0,
        max_supply_u128: 0u128.to_be_bytes().to_vec(),
        initial_alloc_u128: alloc.to_be_bytes().to_vec(),
        mint_burn_enabled: true,
        transferable: true,
        unlimited_supply: true,
        mint_burn_threshold: 1,
        description: String::new(),
        icon_url: String::new(),
        allowlist_device_ids: Vec::new(),
    };
    invoke(router, "token.create", pack(req.encode_to_vec()))
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

#[test]
#[serial]
fn creation_with_initial_supply_gets_the_named_refusal() {
    // 3.5b (owner ruling): the new asset's supply credit has no
    // authenticated issuance/source predicate, so creator supply is REFUSED
    // with the exact named error — token metadata + the ERA fee are the
    // supported creation shape until 0x0029 exists.
    init_test_storage();
    let router = new_router();
    fund_era(&router);
    let res = try_create_token(&router, "TSTA", 1_000);
    assert!(!res.success, "creator supply must be refused");
    let msg = res.error_message.unwrap_or_default();
    assert!(
        msg.contains("initial_supply > 0 cannot enter a validated lineage"),
        "the refusal must be the NAMED issuance-predicate error, got: {msg}"
    );
}

#[test]
#[serial]
fn fee_bearing_creation_without_economic_ancestry_fails_closed() {
    // The creation fee is an ADMITTED economic debit now. This fixture's ERA
    // was installed directly (no lineage), so the admission cannot debit it
    // — the route must fail CLOSED rather than create a token whose fee was
    // never registered. The admitted-creation happy path lives in the lib
    // tests over the fake fleet (sender_admission_tests).
    init_test_storage();
    let router = new_router();
    fund_era(&router);
    let res = try_create_token(&router, "TSTB", 0);
    assert!(
        !res.success,
        "a fee debit with no economic ancestry must not be admittable"
    );
}

/// `token.mint` refuses BEFORE it resolves anything, and says why.
///
/// This used to assert that an unknown ticker fails closed. It cannot test that
/// any more: the route now refuses issuance outright, before token resolution
/// is reached, so an unknown ticker and a perfectly good one take the identical
/// path. Asserting `!success` on an unknown ticker would therefore be vacuous —
/// green whether or not resolution works at all.
///
/// What is still true and worth pinning is that the refusal is the ISSUANCE
/// one, for a KNOWN token as much as an unknown one, and that it names the
/// missing predicate rather than failing for an incidental reason.
#[test]
#[serial]
fn mint_refuses_issuance_before_it_resolves_the_token() {
    init_test_storage();
    let router = new_router();
    fund_era(&router);
    for ticker in ["ERA", "no-such-token"] {
        let res = mint(&router, ticker, 10);
        assert!(!res.success, "minting {ticker} must fail");
        let msg = res.error_message.as_deref().unwrap_or_default();
        assert!(
            msg.contains("0x0029"),
            "the refusal names the missing issuance predicate for {ticker}: {msg}"
        );
    }
}

#[test]
#[serial]
fn burn_requires_an_admitted_economic_lineage() {
    // token.burn is an ADMITTED debit: ancestry-less fixture value cannot
    // fund it, and the refusal is fail-closed rather than a silent local
    // burn that would desynchronize R_econ. Admitted-burn coverage (with a
    // real faucet-funded lineage and the foreign walk) lives in
    // sender_admission_tests.
    init_test_storage();
    let router = new_router();
    fund_era(&router);
    let res = burn(&router, "ERA", 10);
    assert!(
        !res.success,
        "an unadmittable burn must be refused, not performed locally"
    );
}

// The pre-3.5b lifecycle tests (create-with-allocation, mint-to-cap,
// mint-then-burn round trips) asserted a capability the owner has ruled OUT
// until the issuance predicate (0x0029) exists: creator supply cannot enter a
// validated lineage, so custom-token mint/burn currently has no economically
// admissible path. Deleted rather than weakened — a green test for a removed
// capability is how it silently returns.

/// A FINITE SUPPLY CAP IS REFUSED AT CREATION, BEFORE ANY SIDE EFFECT.
///
/// A token policy is immutable once anchored. Anchoring one whose positive
/// supply can never enter `R_econ` would create an asset that looks supported
/// and is permanently unissuable, discoverable only at mint time. So the
/// refusal happens at the moment the choice is made — and it must leave
/// nothing behind: no policy anchor, no registry entry, no ERA fee debit, no
/// state transition.
///
/// This is a BETA CAPABILITY refusal, not a reinterpretation of `max_supply`:
/// the encoding and its parser are untouched, and the gate lifts unchanged
/// when a globally non-duplicable supply predicate exists.
#[test]
#[serial]
fn a_capped_token_is_refused_at_creation_and_leaves_nothing_behind() {
    init_test_storage();
    let router = new_router();
    fund_era(&router);

    let era = dsm::core::token::builtin_policy_commit_for_token("ERA").expect("ERA commit");
    let before = router
        .core_sdk
        .device_head()
        .map(|h| h.balance(&era))
        .unwrap_or(0);
    let res = try_create_capped_token(&router, "CAPPED", 1_000_000);
    assert!(!res.success, "a finite max_supply must be refused");
    let msg = res.error_message.as_deref().unwrap_or_default();
    assert!(
        msg.contains("CAPPED_TOKEN_ISSUANCE_UNSUPPORTED_IN_BETA"),
        "the refusal names the beta capability limit: {msg}"
    );
    // NO SIDE EFFECT. The fee is the observable one: if the refusal happened
    // after the debit, this is what would show it.
    assert_eq!(
        router
            .core_sdk
            .device_head()
            .map(|h| h.balance(&era))
            .unwrap_or(0),
        before,
        "a refused creation must not debit the ERA fee"
    );

    // POSITIVE CONTROL. This fixture has no admission environment, so an
    // uncapped creation cannot SUCCEED here — it fails later, on the economic
    // admission. What it proves is the part that matters: the identical
    // request without the cap gets PAST the cap gate, so the refusal above is
    // the cap rule and not something wrong with the request.
    let uncapped = try_create_token(&router, "UNCAPPED", 0);
    let umsg = uncapped.error_message.as_deref().unwrap_or_default();
    assert!(
        !umsg.contains("CAPPED_TOKEN_ISSUANCE_UNSUPPORTED_IN_BETA"),
        "an uncapped request must not hit the cap gate: {umsg}"
    );
}
