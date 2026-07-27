// SPDX-License-Identifier: MIT OR Apache-2.0
//! Every balance row carries the metadata needed to render it.
//!
//! THE HARDWARE FAILURE. Canonical scaling was correct — RIGB held 100_000 base
//! units at decimals 2 — and the wallet still displayed "100000 RIGB". The wire
//! record was the reason: projection-backed rows were pushed straight into the
//! response and never passed through `enrich_balance_metadata`, which only ever
//! ran on the zero-balance rows `ensure_default_visible_balances` synthesises.
//!
//! So a token you actually HELD went out with decimals 0 and the frontend had
//! nothing to format with, while a token you held NONE of was described
//! correctly. Enrichment now happens at the encoding boundary, where no
//! producer path can skip it.
//!
//! `available` stays in BASE UNITS on the wire — that is canonical. `decimals`
//! is what lets a reader apply the inverse conversion exactly once.

#![allow(clippy::disallowed_methods)]

use prost::Message;
use std::path::PathBuf;

use dsm_sdk::bridge::{AppInvoke, AppQuery, AppRouter};
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

fn create(r: &AppRouterImpl, ticker: &str, decimals: u32, alloc: u128) -> String {
    let req = generated::TokenCreateRequest {
        ticker: ticker.to_string(),
        alias: format!("{ticker} Token"),
        decimals,
        max_supply_u128: 1_000_000u128.to_be_bytes().to_vec(),
        initial_alloc_u128: alloc.to_be_bytes().to_vec(),
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
        Some(generated::envelope::Payload::TokenCreateResponse(t)) => t.token_id,
        other => panic!("unexpected {other:?}"),
    }
}

/// The ACTUAL wire records, decoded from the encoded response.
fn wire_rows(r: &AppRouterImpl) -> Vec<generated::BalanceGetResponse> {
    let res = runtime::get_runtime().block_on(async {
        r.query(AppQuery {
            path: "balance.list".to_string(),
            params: Vec::new(),
        })
        .await
    });
    assert!(res.success, "balance.list: {:?}", res.error_message);
    let env = generated::Envelope::decode(&res.data[1..]).expect("envelope");
    match env.payload {
        Some(generated::envelope::Payload::BalancesListResponse(b)) => b.balances,
        other => panic!("expected BalancesListResponse, got {other:?}"),
    }
}

fn row<'a>(
    rows: &'a [generated::BalanceGetResponse],
    token_id: &str,
) -> &'a generated::BalanceGetResponse {
    rows.iter()
        .find(|r| r.token_id.eq_ignore_ascii_case(token_id))
        .unwrap_or_else(|| panic!("{token_id} missing from balance.list"))
}

/// THE REPRODUCTION: a token with a NONZERO projection must carry its decimals.
#[test]
#[serial_test::serial]
fn a_held_custom_token_carries_its_decimals_on_the_wire() {
    runtime::dsm_init_runtime();
    init_test_storage();
    let r = new_router();
    r.install_policy_resolver();
    fund_era(&r);
    create(&r, "RIGB", 2, 1_000);

    let rows = wire_rows(&r);
    let rigb = row(&rows, "RIGB");

    assert_eq!(
        rigb.available, 100_000,
        "the wire carries canonical BASE UNITS"
    );
    assert_eq!(
        rigb.decimals, 2,
        "and the decimals needed to render them — this was 0, so the wallet \
         showed 100000 instead of 1,000.00"
    );
    assert_eq!(rigb.symbol, "RIGB");
    // And the rendered form, because that is what the wallet displays. The
    // frontend used to derive this itself; a second implementation of the unit
    // rule is a second thing that can disagree with canonical state, so the
    // conversion has one owner here in Rust and travels on the wire.
    assert_eq!(rigb.display_amount, "1000.00");
}

/// A zero-balance adopted token is described too — it always was, which is why
/// the defect was easy to miss.
#[test]
#[serial_test::serial]
fn a_zero_balance_registered_token_carries_its_decimals() {
    runtime::dsm_init_runtime();
    init_test_storage();
    let r = new_router();

    // A receiver's registry row: registered, never held.
    token_registry::insert_token(&token_registry::TokenRegistryRow {
        token_id: "ADOPTEDTOKENID".to_string(),
        policy_commit: [0x3Cu8; 32],
        ticker: "ADOPT".to_string(),
        alias: "Adopted".to_string(),
        decimals: 4,
        max_supply: 1_000,
        owner_device_id: [0u8; 32],
    })
    .expect("register");

    let rows = wire_rows(&r);
    let adopt = row(&rows, "ADOPT");
    assert_eq!(adopt.available, 0);
    assert_eq!(adopt.decimals, 4);
    assert_eq!(adopt.display_amount, "0.0000");
}

/// Metadata survives a restart, because it is resolved from the registry at
/// encode time rather than cached in the process.
#[test]
#[serial_test::serial]
fn decimals_survive_a_restart_for_a_held_token() {
    runtime::dsm_init_runtime();
    init_test_storage();
    let r = new_router();
    r.install_policy_resolver();
    fund_era(&r);
    create(&r, "PERSIS", 2, 500);
    drop(r);

    let r2 = new_router();
    r2.install_policy_resolver();
    let rows = wire_rows(&r2);
    let t = row(&rows, "PERSIS");
    assert_eq!(t.available, 50_000, "500 display at 2 decimals");
    assert_eq!(t.decimals, 2, "decimals must survive the restart");
    assert_eq!(t.display_amount, "500.00", "and so must the rendering");
}

/// Builtins keep their existing, exact values — this change must not disturb
/// them.
#[test]
#[serial_test::serial]
fn builtin_tokens_keep_their_metadata() {
    runtime::dsm_init_runtime();
    init_test_storage();
    let r = new_router();
    fund_era(&r);

    let rows = wire_rows(&r);
    let era = row(&rows, "ERA");
    assert_eq!(era.decimals, 0, "ERA is whole units");
    assert_eq!(era.symbol, "ERA");
    assert_eq!(
        era.display_amount,
        era.available.to_string(),
        "at 0 decimals the display form is the base units, with no point"
    );

    let dbtc = row(&rows, "dBTC");
    assert_eq!(dbtc.decimals, 8, "dBTC is satoshis");
    assert_eq!(dbtc.symbol, "dBTC");
}

/// A token with 0 decimals is unaffected: base units and display coincide.
#[test]
#[serial_test::serial]
fn a_zero_decimal_custom_token_is_unchanged() {
    runtime::dsm_init_runtime();
    init_test_storage();
    let r = new_router();
    r.install_policy_resolver();
    fund_era(&r);
    create(&r, "WHOLE", 0, 750);

    let rows = wire_rows(&r);
    let w = row(&rows, "WHOLE");
    assert_eq!(w.available, 750);
    assert_eq!(w.decimals, 0);
    assert_eq!(w.display_amount, "750", "no spurious decimal point");
}
