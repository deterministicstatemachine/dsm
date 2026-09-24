// SPDX-License-Identifier: MIT OR Apache-2.0

//! Every `balance.list` row carries what the wallet needs to render it.
//!
//! THE HARDWARE FAILURE. Canonical scaling was correct — RIGB held 100_000
//! base units at decimals 2 — and the wallet still displayed "100000 RIGB":
//! projection-backed rows reached the wire without their metadata. Every row
//! here is read off the route's actual answer, for tokens created through
//! `token.create` and adopted through `tokens.addByAnchor` on real nodes.

use serial_test::serial;

use crate::bridge::{AppQuery, AppRouter};
use crate::economic_fixtures;
use crate::handlers::app_router_impl::AppRouterImpl;
use crate::storage::client_db::token_registry;
use crate::test_support::one_device::Device;
use crate::test_support::two_device::Pair;
use dsm::types::proto as generated;

/// The ACTUAL wire records, decoded from the route's answer.
async fn wire_rows(router: &AppRouterImpl) -> Vec<generated::BalanceGetResponse> {
    let res = router
        .query(AppQuery {
            path: "balance.list".to_string(),
            params: Vec::new(),
        })
        .await;
    assert!(res.success, "balance.list: {:?}", res.error_message);
    let envelope = crate::handlers::response_helpers::decode_local_envelope(&res.data)
        .expect("balance.list answers locally");
    match envelope.payload {
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

/// THE REPRODUCTION: a held token carries its decimals, its anchor — the
/// canonical encoding of the registry's commit, round-tripping to its 32
/// bytes, with the fingerprint a head of it — and its rendered amount, whose
/// unit rule has one owner, here in Rust.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_held_custom_token_carries_its_decimals_on_the_wire() {
    let d = Device::funded(0x81).await;
    economic_fixtures::create_asset(&d.router, "RIGB", 2, 1_000).await;

    let rows = wire_rows(&d.router).await;
    let rigb = row(&rows, "RIGB");
    assert_eq!(rigb.available, 100_000, "canonical BASE UNITS");
    assert_eq!(rigb.decimals, 2);
    assert_eq!(rigb.symbol, "RIGB");
    let registered = token_registry::get_token_by_ticker("RIGB")
        .expect("registry")
        .expect("row");
    assert_eq!(
        rigb.policy_anchor_b32,
        crate::util::text_id::encode_base32_crockford(&registered.policy_commit)
    );
    assert_eq!(
        crate::util::text_id::decode_base32_crockford(&rigb.policy_anchor_b32)
            .expect("anchor decodes"),
        registered.policy_commit.to_vec()
    );
    assert!(rigb.policy_anchor_b32.starts_with(&rigb.anchor_fingerprint));
    assert_eq!(rigb.display_amount, "1000.00");
    assert_eq!(
        rigb.icon_url, "",
        "a policy that names no icon carries none"
    );
}

/// A token this device adopted and holds none of is described too: holding
/// none of a token does not make its identity unknowable.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn an_adopted_zero_balance_token_carries_its_decimals() {
    let p = Pair::boot(100, 0).await;
    p.a.enter();
    let anchor = economic_fixtures::create_asset(p.a.router(), "ADOPT", 4, 1_000).await;
    p.b.enter();
    let adopted =
        p.b.router()
            .query(AppQuery {
                path: "tokens.addByAnchor".to_string(),
                params: crate::util::text_id::encode_base32_crockford(&anchor).into_bytes(),
            })
            .await;
    assert!(adopted.success, "{:?}", adopted.error_message);

    let rows = wire_rows(p.b.router()).await;
    let adopt = row(&rows, "ADOPT");
    assert_eq!(adopt.available, 0);
    assert_eq!(adopt.decimals, 4);
    assert_eq!(
        crate::util::text_id::decode_base32_crockford(&adopt.policy_anchor_b32)
            .expect("anchor decodes"),
        anchor.to_vec()
    );
    assert_eq!(adopt.display_amount, "0.0000");
}

/// Metadata is resolved from the registry at encode time, not cached in the
/// process, so it survives a restart.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn decimals_survive_a_restart_for_a_held_token() {
    let d = Device::funded(0x82).await;
    economic_fixtures::create_asset(&d.router, "PERSIS", 2, 500).await;
    let restarted = economic_fixtures::restart_router(&d.fleet);
    let rows = wire_rows(&restarted).await;
    let t = row(&rows, "PERSIS");
    assert_eq!(t.available, 50_000, "500 display at 2 decimals");
    assert_eq!(t.decimals, 2);
    assert_eq!(t.display_amount, "500.00");
}

/// Builtins keep their exact values: ERA whole units, dBTC in satoshis, no
/// policy icon, and each its protocol-defined anchor.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn builtin_tokens_keep_their_metadata() {
    let d = Device::funded(0x83).await;
    let rows = wire_rows(&d.router).await;
    let era = row(&rows, "ERA");
    assert_eq!(era.decimals, 0);
    assert_eq!(era.symbol, "ERA");
    assert_eq!(era.available, 100);
    assert_eq!(era.display_amount, "100");
    let dbtc = row(&rows, "dBTC");
    assert_eq!(dbtc.decimals, 8);
    assert_eq!(dbtc.symbol, "dBTC");
    assert_eq!(era.icon_url, "");
    assert_eq!(dbtc.icon_url, "");
    for (ticker, r) in [("ERA", era), ("dBTC", dbtc)] {
        let want = dsm::core::token::builtin_policy_commit_for_token(ticker)
            .unwrap_or_else(|| panic!("{ticker} is builtin"));
        assert_eq!(
            crate::util::text_id::decode_base32_crockford(&r.policy_anchor_b32)
                .unwrap_or_else(|| panic!("{ticker} anchor decodes")),
            want.to_vec()
        );
    }
}

/// At 0 decimals base units and display coincide: no spurious point.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_zero_decimal_custom_token_is_unchanged() {
    let d = Device::funded(0x84).await;
    economic_fixtures::create_asset(&d.router, "WHOLE", 0, 750).await;
    let rows = wire_rows(&d.router).await;
    let w = row(&rows, "WHOLE");
    assert_eq!(w.available, 750);
    assert_eq!(w.decimals, 0);
    assert_eq!(w.display_amount, "750");
}

/// A token's coin artwork is its policy's icon field and reaches the wire
/// exactly as the policy states it, beside the anchor it was read from.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_created_token_carries_its_policy_icon_on_the_wire() {
    let d = Device::funded(0x90).await;
    let artwork = format!(
        "dsm:coin:v1:{}",
        crate::util::text_id::encode_base32_crockford(&[0xA5u8; 2048])
    );
    economic_fixtures::create_asset_with_icon(&d.router, "COIN", 2, 1_000, &artwork).await;
    let rows = wire_rows(&d.router).await;
    let coin = row(&rows, "COIN");
    assert_eq!(coin.icon_url, artwork);
    assert!(!coin.policy_anchor_b32.is_empty());
}
