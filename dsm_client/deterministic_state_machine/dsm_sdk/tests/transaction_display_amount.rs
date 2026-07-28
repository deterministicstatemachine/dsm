// SPDX-License-Identifier: MIT OR Apache-2.0
//! A transaction is rendered from the token's own decimals.
//!
//! THE DEFECT. Amount rendering lived in TypeScript, against a hardcoded table
//! that listed dBTC and BTC at 8 decimals and answered 0 for everything else.
//! It could not know about CPTA tokens, because they are created after it was
//! written. So a token created with 2 decimals rendered as whole units in the
//! transfer dialog, the transaction list and contact history: a transfer of
//! 250.00 RIGB — canonically 25_000 base units — displayed as "25000".
//!
//! This is the same defect that showed a balance of 100_000 base units as
//! "100000", reached by a different route, and it is why the conversion has
//! exactly one owner. `amount` and `amount_signed` stay canonical base units;
//! `display_amount` is rendered here, from registry decimals, at the encoding
//! boundary every producer crosses.

#![allow(clippy::disallowed_methods)]

use std::path::PathBuf;

// The router's proto module. `dsm_sdk::generated` is a SECOND generated copy
// of the same schema; the two are distinct types to rustc, which is a seam
// worth collapsing but not from inside a test.
use dsm::types::proto as generated;
use dsm_sdk::handlers::wallet_routes::{
    decimals_for_token, enrich_transaction_display, format_base_units_for_display,
    format_signed_base_units_for_display,
};
use dsm_sdk::storage::client_db::{reset_database_for_tests, token_registry};

fn init_test_storage() {
    std::env::set_var("DSM_SDK_TEST_MODE", "1");
    reset_database_for_tests();
    let _ = dsm_sdk::storage_utils::set_storage_base_dir(PathBuf::from("./.dsm_testdata"));
}

fn register(ticker: &str, decimals: u32) {
    token_registry::insert_token(&token_registry::TokenRegistryRow {
        token_id: format!("{ticker}TOKENID"),
        policy_commit: [0x7Au8; 32],
        ticker: ticker.to_string(),
        alias: format!("{ticker} Token"),
        decimals,
        max_supply: 1_000_000,
        owner_device_id: [0u8; 32],
    })
    .expect("register");
}

fn tx(token_id: &str, amount: u64, signed: i64) -> generated::TransactionInfo {
    generated::TransactionInfo {
        token_id: token_id.to_string(),
        amount,
        amount_signed: signed,
        ..Default::default()
    }
}

/// THE REPRODUCTION: a created token's decimals come from the registry.
#[test]
#[serial_test::serial]
fn a_created_tokens_transfer_renders_with_its_own_decimals() {
    init_test_storage();
    register("RIGB", 2);

    let mut outgoing = tx("RIGB", 25_000, -25_000);
    enrich_transaction_display(&mut outgoing);
    assert_eq!(
        outgoing.display_amount, "-250.00",
        "25_000 base units at 2 decimals is 250.00 — the deleted table said 25000"
    );
    assert_eq!(
        outgoing.amount, 25_000,
        "canonical base units are untouched"
    );
    assert_eq!(outgoing.amount_signed, -25_000);

    let mut incoming = tx("RIGB", 25_000, 25_000);
    enrich_transaction_display(&mut incoming);
    assert_eq!(
        incoming.display_amount, "250.00",
        "incoming carries no sign"
    );
}

/// Protocol-defined tokens keep their existing meaning.
#[test]
#[serial_test::serial]
fn builtin_tokens_render_as_before() {
    init_test_storage();

    let mut era = tx("ERA", 100, -100);
    enrich_transaction_display(&mut era);
    assert_eq!(era.display_amount, "-100", "ERA is whole units");

    let mut dbtc = tx("dBTC", 100_000_000, 100_000_000);
    enrich_transaction_display(&mut dbtc);
    assert_eq!(dbtc.display_amount, "1.00000000", "dBTC is satoshis");
}

/// History predating signed accounting carries `amount_signed == 0`. Rendering
/// those as "0" would erase every old row from the ledger view.
#[test]
#[serial_test::serial]
fn an_unsigned_historical_row_renders_its_magnitude() {
    init_test_storage();
    register("OLDTOK", 2);

    let mut old = tx("OLDTOK", 25_000, 0);
    enrich_transaction_display(&mut old);
    assert_eq!(old.display_amount, "250.00");
}

/// An unknown token is rendered as whole units — the honest answer when there
/// is no authority for a scale. It must never guess 8 the way the table did.
#[test]
#[serial_test::serial]
fn an_unregistered_token_is_not_given_an_invented_scale() {
    init_test_storage();
    assert_eq!(decimals_for_token("NEVERSEEN"), 0);

    let mut unknown = tx("NEVERSEEN", 12_345, 12_345);
    enrich_transaction_display(&mut unknown);
    assert_eq!(unknown.display_amount, "12345");
}

/// Both directions of the conversion agree, for every scale, at the boundaries
/// where a hand-rolled implementation goes wrong.
#[test]
fn rendering_is_exact_at_the_awkward_magnitudes() {
    // Fewer digits than decimals: the leading zeros must be produced.
    assert_eq!(format_base_units_for_display(5, 8), "0.00000005");
    assert_eq!(format_base_units_for_display(0, 2), "0.00");
    // Exactly one whole unit.
    assert_eq!(format_base_units_for_display(100, 2), "1.00");
    // No fractional part is still written out, so the scale is visible.
    assert_eq!(format_base_units_for_display(100_000, 2), "1000.00");
    // Whole-unit tokens get no decimal point at all.
    assert_eq!(format_base_units_for_display(750, 0), "750");
    // u64::MAX must not overflow or lose a digit.
    assert_eq!(
        format_base_units_for_display(u64::MAX, 2),
        "184467440737095516.15"
    );
    // Signed rendering only prefixes; it never alters the magnitude.
    assert_eq!(
        format_signed_base_units_for_display(-100_000, 2),
        "-1000.00"
    );
    assert_eq!(format_signed_base_units_for_display(0, 2), "0.00");
    // i64::MIN cannot be negated in place; unsigned_abs must handle it.
    assert_eq!(
        format_signed_base_units_for_display(i64::MIN, 0),
        "-9223372036854775808"
    );
}
