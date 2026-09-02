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
use dsm_sdk::runtime;
use dsm_sdk::storage::client_db::token_registry;

/// A router on a REAL testnet identity, funded through a REAL faucet admission
/// (0x0030), replacing a fabricated identity plus a directly-written balance.
///
/// The old pair installed [0xAA;32]/[0xBB;32]/[0xCC;32] with no genesis record —
/// so no network was committed and no admission could ever run — and then wrote
/// 100 ERA straight onto the head. That balance had no economic lineage, and
/// since debits are not fenced it was fully spendable through canonical
/// acceptance. 100 is also exactly the faucet's payout, so assertions written
/// against it are unchanged.
fn funded_router(seed: u8) -> (AppRouterImpl, dsm_sdk::economic_fixtures::FleetGuard) {
    let _ = dsm_sdk::storage_utils::set_storage_base_dir(PathBuf::from("./.dsm_testdata"));
    dsm_sdk::economic_fixtures::funded_router(seed)
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

// The creation-credit scaling tests (display alloc -> base-unit credit) and
// the mint/burn base-unit accounting tests are DELETED with their capability:
// creator supply is refused (issuance goes through `token.mint` under a
// 0x0029 authorization), and this integration fixture has no fleet to admit
// a mint through.
// The cap-scaling half of the contract (display cap -> BASE-unit registry
// cap) is no longer pinned on a SUCCESSFUL creation anywhere: a capped policy
// is refused in beta, so no creation that reaches the registry carries a cap
// to scale. What stays pinned here is the arithmetic itself, through the two
// refusals that still run on the capped path before the capability gate —
// overflow-on-scale and cap-vs-allocation, both in scaled units. When the cap
// gate lifts, a successful-creation assertion belongs back in the route e2e.

/// A cap that overflows once scaled is refused BEFORE anything is committed.
#[test]
#[serial_test::serial]
fn a_quantity_that_overflows_when_scaled_is_refused() {
    runtime::dsm_init_runtime();
    let (r, _fleet) = funded_router(0x85);

    let root_before = r.core_sdk.device_head().map(|h| h.root());
    let res = create(&r, "HUGE", 18, u128::MAX / 10, 1);
    assert!(!res.success, "an overflowing cap must be refused");
    // Assert the REASON, not just the refusal. Capped creation is also
    // refused as a beta capability, and that gate sits just after this one —
    // without this the test would keep passing if the overflow check were
    // deleted, having silently become a test of the capability gate.
    let msg = res.error_message.clone().unwrap_or_default();
    assert!(
        msg.contains("overflows at 18 decimals"),
        "must be refused by the scaling check, got: {msg}"
    );
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
    let (r, _fleet) = funded_router(0x85);

    let res = create(&r, "OVERAL", 2, 100, 101);
    assert!(
        !res.success,
        "an allocation larger than the cap must be refused"
    );
    let msg = res.error_message.clone().unwrap_or_default();
    assert!(
        msg.contains("initial allocation exceeds max supply"),
        "must be refused by the cap comparison, got: {msg}"
    );
    assert_eq!(token_registry::all_tokens().expect("registry").len(), 0);
}
