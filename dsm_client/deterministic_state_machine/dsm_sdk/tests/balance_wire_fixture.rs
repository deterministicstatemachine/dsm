// SPDX-License-Identifier: MIT OR Apache-2.0
//! Emit the exact bytes the WebView receives, so TypeScript can decode them.
//!
//! The bridge used to narrow BalanceGetResponse into a two-field
//! TokenBalanceEntry, and the JNI layer re-inflated it with
//! `..Default::default()`. token_id and available survived; symbol, decimals,
//! locked and token_name were blanked in flight. Every layer looked correct in
//! isolation, and the loss only appeared by comparing the Rust log and the
//! decoded object from ONE invocation.
//!
//! So the contract is pinned across the language boundary rather than on either
//! side of it: this writes real encoded bytes, and a TypeScript test decodes
//! them with the generated decoder and requires all six fields.
//!
//! Run with DSM_WIRE_FIXTURE_OUT set to have it write the file.

#![allow(clippy::disallowed_methods)]

use dsm_sdk::handlers::wallet_routes::format_base_units_for_display as crate_format;
use prost::Message;

#[test]
fn emit_balances_list_fixture() {
    let row = dsm_sdk::generated::BalanceGetResponse {
        token_id: "RIGB".to_string(),
        available: 100_000,
        locked: 0,
        symbol: "RIGB".to_string(),
        decimals: 2,
        token_name: "RigBravo".to_string(),
        // Rendered by Rust. The frontend prints this string and computes
        // nothing: 100_000 base units at 2 decimals is 1000.00.
        display_amount: crate_format(100_000, 2),
    };
    let list = dsm_sdk::generated::BalancesListResponse {
        balances: vec![row],
    };

    // Framed envelope v3: 0x03 prefix + Envelope, exactly as the bridge returns.
    let env = dsm_sdk::generated::Envelope {
        version: 3,
        payload: Some(dsm_sdk::generated::envelope::Payload::BalancesListResponse(
            list,
        )),
        ..Default::default()
    };
    let mut framed = vec![0x03u8];
    framed.extend_from_slice(&env.encode_to_vec());

    // Round-trip in Rust first: if this fails the fixture itself is wrong.
    let back = dsm_sdk::generated::Envelope::decode(&framed[1..]).expect("decode");
    match back.payload {
        Some(dsm_sdk::generated::envelope::Payload::BalancesListResponse(l)) => {
            let b = &l.balances[0];
            assert_eq!(b.token_id, "RIGB");
            assert_eq!(b.available, 100_000);
            assert_eq!(b.symbol, "RIGB", "symbol must survive encoding");
            assert_eq!(b.decimals, 2, "decimals must survive encoding");
            assert_eq!(b.token_name, "RigBravo");
        }
        other => panic!("unexpected payload {other:?}"),
    }

    if let Ok(path) = std::env::var("DSM_WIRE_FIXTURE_OUT") {
        std::fs::write(&path, &framed).expect("write fixture");
        println!("wrote {} bytes to {path}", framed.len());
    }
}
