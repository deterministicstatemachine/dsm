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

use dsm_sdk::bridge::{AppQuery, AppRouter};
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

/// Hold a custom token the LEGITIMATE way: create it and mint into it, both
/// admitted (0x0029 authorized issuance -> 0x0023).
///
/// This replaced a three-layer fabrication — a registry row owned by a device
/// that does not exist ([0xAA;32]), a balance written straight onto the head,
/// and a hand-built projection row. The old doc justified it with "the creation
/// fee is an ADMITTED economic debit integration tests cannot run (no fake
/// register fleet)"; that is no longer true, which is what made the fabrication
/// removable rather than merely undesirable.
///
/// `token.mint` takes BASE units, so the display allocation is scaled here —
/// the same conversion the old fixture did before writing the balance directly.
fn install_held(r: &AppRouterImpl, ticker: &str, decimals: u32, display_alloc: u128) {
    let base = u64::try_from(display_alloc * 10u128.pow(decimals)).expect("base units fit u64");
    dsm_sdk::economic_fixtures::mint_asset(r, ticker, decimals, base);
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
    let (r, _fleet) = funded_router(0x81);
    r.install_policy_resolver();
    install_held(&r, "RIGB", 2, 1_000);

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
    // The anchor a creator needs in order to hand this token to a peer. It was
    // shown on the ADOPTING device and nowhere on the CREATING one, so getting
    // it off-device meant deriving it by hand — and a hand-rolled Base32 pads
    // the wrong group, yielding a plausible string that resolves to nothing.
    let row = token_registry::get_token_by_ticker("RIGB")
        .expect("registry")
        .expect("row");
    assert_eq!(
        rigb.policy_anchor_b32,
        dsm_sdk::util::text_id::encode_base32_crockford(&row.policy_commit),
        "the wire anchor must be the canonical encoding of the registry's commit"
    );
    assert_eq!(
        dsm_sdk::util::text_id::decode_base32_crockford(&rigb.policy_anchor_b32)
            .expect("anchor decodes"),
        row.policy_commit.to_vec(),
        "and it must round-trip to the exact 32 bytes"
    );
    assert!(
        rigb.policy_anchor_b32.starts_with(&rigb.anchor_fingerprint),
        "the fingerprint is a head of the anchor, not a separate value"
    );
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
    let (r, _fleet) = funded_router(0x81);

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
    // Holding none of a token does not make its identity unknowable.
    assert_eq!(
        dsm_sdk::util::text_id::decode_base32_crockford(&adopt.policy_anchor_b32)
            .expect("anchor decodes"),
        vec![0x3Cu8; 32],
    );
    assert_eq!(adopt.display_amount, "0.0000");
}

/// Metadata survives a restart, because it is resolved from the registry at
/// encode time rather than cached in the process.
#[test]
#[serial_test::serial]
fn decimals_survive_a_restart_for_a_held_token() {
    runtime::dsm_init_runtime();
    let (r, _fleet) = funded_router(0x81);
    r.install_policy_resolver();
    install_held(&r, "PERSIS", 2, 500);
    drop(r);

    let r2 = dsm_sdk::economic_fixtures::restart_router();
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
    let (r, _fleet) = funded_router(0x81);

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

    // Protocol assets carry their builtin commit, so every token on the screen
    // can show where its rules come from — not just the user-created ones.
    for (ticker, r) in [("ERA", era), ("dBTC", dbtc)] {
        let want = dsm::core::token::builtin_policy_commit_for_token(ticker)
            .unwrap_or_else(|| panic!("{ticker} is builtin"));
        assert_eq!(
            dsm_sdk::util::text_id::decode_base32_crockford(&r.policy_anchor_b32)
                .unwrap_or_else(|| panic!("{ticker} anchor decodes")),
            want.to_vec(),
            "{ticker} must carry its protocol-defined anchor"
        );
    }
}

/// A token with 0 decimals is unaffected: base units and display coincide.
#[test]
#[serial_test::serial]
fn a_zero_decimal_custom_token_is_unchanged() {
    runtime::dsm_init_runtime();
    let (r, _fleet) = funded_router(0x81);
    r.install_policy_resolver();
    install_held(&r, "WHOLE", 0, 750);

    let rows = wire_rows(&r);
    let w = row(&rows, "WHOLE");
    assert_eq!(w.available, 750);
    assert_eq!(w.decimals, 0);
    assert_eq!(w.display_amount, "750", "no spurious decimal point");
}
