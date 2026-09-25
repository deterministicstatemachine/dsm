// SPDX-License-Identifier: Apache-2.0

//! `token.create` on a device created as wallet creation creates it, on the
//! network's pinned set of storage nodes.
//!
//! A creation is one admitted advance: the ERA fee debit and the release of
//! the whole genesis supply to the creator, with the registry row in the same
//! transaction (SoFi §51). What is pinned here is what the route decides
//! before and around that advance: a creation the device cannot pay for moves
//! nothing; the id is the creation commitment, so a repeat is answered from
//! canonical state and a different token claiming the ticker is refused; the
//! client's display quantity is scaled to base units exactly once; a threshold
//! the policy cannot hold is refused; and the amounts a transaction shows come
//! from the token's own decimals.

use prost::Message;
use serial_test::serial;

use dsm::types::proto as generated;

use crate::bridge::{AppInvoke, AppResult, AppRouter};
use crate::handlers::app_router_impl::AppRouterImpl;
use crate::storage::client_db::token_registry;
use crate::test_support::one_device::Device;

fn request(ticker: &str, decimals: u32, supply: u128) -> generated::TokenCreateRequest {
    generated::TokenCreateRequest {
        ticker: ticker.to_string(),
        alias: format!("{ticker} token"),
        decimals,
        genesis_supply_u128: supply.to_be_bytes().to_vec(),
        burn_enabled: true,
        transferable: true,
        threshold: 1,
        ..Default::default()
    }
}

async fn create(router: &AppRouterImpl, req: &generated::TokenCreateRequest) -> AppResult {
    router
        .invoke(AppInvoke {
            method: "token.create".to_string(),
            args: generated::ArgPack {
                schema_hash: None,
                codec: generated::Codec::Proto as i32,
                body: req.encode_to_vec(),
            }
            .encode_to_vec(),
        })
        .await
}

fn created(result: &AppResult) -> generated::TokenCreateResponse {
    assert!(result.success, "token.create: {:?}", result.error_message);
    match crate::handlers::response_helpers::decode_local_envelope(&result.data)
        .expect("a local answer")
        .payload
    {
        Some(generated::envelope::Payload::TokenCreateResponse(r)) => r,
        other => panic!("token.create answered {other:?}"),
    }
}

fn refusal(result: &AppResult) -> String {
    assert!(!result.success, "the creation was expected to be refused");
    result
        .error_message
        .clone()
        .expect("a refusal names its reason")
}

/// What a creation can move: the head, the fee asset, and the registry.
fn footprint(d: &Device) -> ([u8; 32], u64, usize) {
    (
        d.core().device_head().expect("a head").root(),
        d.era_balance(),
        token_registry::all_tokens().expect("registry").len(),
    )
}

/// A device without the creation fee is refused before anything commits: no
/// advance, no debit, no registry row.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn an_unaffordable_creation_moves_nothing_and_registers_nothing() {
    let d = Device::start(0xC1).await;
    let before = footprint(&d);
    let msg = refusal(&create(&d.router, &request("POOR", 0, 1_000)).await);
    assert!(msg.contains("insufficient ERA"), "{msg}");
    assert_eq!(footprint(&d), before);
    assert!(token_registry::get_token_by_ticker("POOR")
        .expect("registry")
        .is_none());
}

/// The token id is the creation commitment. The same creation again is
/// answered from canonical state — one fee, one advance, one row — and a
/// different token claiming the same ticker is refused, not merged.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_repeated_creation_is_answered_from_canonical_state_and_a_taken_ticker_is_refused() {
    let d = Device::funded(0xC2).await;
    let first = created(&create(&d.router, &request("RIGA", 0, 1_000)).await);
    let after_first = footprint(&d);
    assert_eq!(
        after_first.1,
        dsm::economic::native_reserve::ERA_FAUCET_PAYOUT - dsm::core::token::TOKEN_CREATION_FEE_ERA,
        "the fee is charged once"
    );

    let again = created(&create(&d.router, &request("RIGA", 0, 1_000)).await);
    assert_eq!(again.token_id, first.token_id);
    assert_eq!(again.policy_anchor, first.policy_anchor);
    assert_eq!(footprint(&d), after_first, "a repeat moves nothing");

    let msg = refusal(&create(&d.router, &request("RIGA", 0, 2_000)).await);
    assert!(msg.contains("already held by a different token"), "{msg}");
    assert_eq!(footprint(&d), after_first, "a refused claim moves nothing");
    let row = token_registry::get_token_by_ticker("RIGA")
        .expect("registry")
        .expect("the first token keeps its ticker");
    assert_eq!(row.token_id, first.token_id);
}

/// The client speaks display units. The route scales once, and the policy,
/// the release, the balance and the registry all hold base units.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_display_quantity_is_scaled_to_base_units_once() {
    let d = Device::funded(0xC3).await;
    let response = created(&create(&d.router, &request("RIGB", 2, 250)).await);
    let row = token_registry::get_token_by_ticker("RIGB")
        .expect("registry")
        .expect("registered");
    assert_eq!(row.token_id, response.token_id);
    assert_eq!(row.decimals, 2);
    assert_eq!(row.genesis_supply, 25_000);
    let head = d.core().device_head().expect("a head");
    assert_eq!(head.balance(&row.policy_commit), 25_000);

    // A quantity that does not fit once scaled is refused before anything
    // commits.
    let before = footprint(&d);
    let msg = refusal(&create(&d.router, &request("HUGE", 18, u128::MAX / 10)).await);
    assert!(msg.contains("overflows"), "{msg}");
    assert_eq!(footprint(&d), before);
}

/// The threshold is the client's, and a value the policy cannot hold is
/// refused rather than moved into range.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_threshold_the_policy_cannot_hold_is_refused() {
    let d = Device::funded(0xC4).await;
    let before = footprint(&d);
    for threshold in [0, 256] {
        let msg = refusal(
            &create(
                &d.router,
                &generated::TokenCreateRequest {
                    threshold,
                    ..request("THRS", 0, 1_000)
                },
            )
            .await,
        );
        assert!(msg.contains("threshold"), "{msg}");
    }
    assert_eq!(footprint(&d), before);
}

/// A transaction in a created token shows its amount at that token's own
/// decimals; the canonical base units are untouched.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_created_tokens_amounts_render_at_its_own_decimals() {
    use crate::handlers::wallet_routes::enrich_transaction_display;
    let d = Device::funded(0xC5).await;
    created(&create(&d.router, &request("RIGC", 2, 1_000)).await);
    let tx = |amount: u64, amount_signed: i64| generated::TransactionInfo {
        token_id: "RIGC".to_string(),
        amount,
        amount_signed,
        ..Default::default()
    };

    let mut outgoing = tx(25_000, -25_000);
    enrich_transaction_display(&mut outgoing).expect("the token's decimals are known");
    assert_eq!(outgoing.display_amount, "-250.00");
    assert_eq!((outgoing.amount, outgoing.amount_signed), (25_000, -25_000));

    let mut incoming = tx(25_000, 25_000);
    enrich_transaction_display(&mut incoming).expect("the token's decimals are known");
    assert_eq!(incoming.display_amount, "250.00");

    let mut era = generated::TransactionInfo {
        token_id: "ERA".to_string(),
        amount: 100,
        amount_signed: -100,
        ..Default::default()
    };
    enrich_transaction_display(&mut era).expect("the token's decimals are known");
    assert_eq!(era.display_amount, "-100", "ERA is whole units");
}

/// The policy a created token enforces lives in durable storage, not in the
/// process that created it: after the creator restarts, a send of the token
/// resolves and enforces its policy, and the receiver that adopted it is
/// credited.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_created_token_is_sent_after_its_creator_restarts() {
    use crate::test_support::two_device::Pair;
    let mut p = Pair::boot(100, 0).await;
    p.a.enter();
    let pc = crate::economic_fixtures::create_asset(p.a.router(), "RIGD", 0, 1_000).await;
    p.b.enter();
    let adopted =
        p.b.router()
            .query(crate::bridge::AppQuery {
                path: "tokens.addByAnchor".to_string(),
                params: crate::util::text_id::encode_base32_crockford(&pc).into_bytes(),
            })
            .await;
    assert!(
        adopted.success,
        "B adopts RIGD: {:?}",
        adopted.error_message
    );

    // A new router over A's database: every in-memory policy cache is gone.
    p.a.boot(&p.fleet).await;
    let sent = p.a.send_token(&p.b, "RIGD", 100).await;
    assert!(sent.success, "{:?}", sent.error_message);
    let synced = p.b.sync().await;
    assert!(synced.success, "{:?}", synced.errors);
    p.b.enter();
    assert_eq!(
        p.b.router()
            .core_sdk
            .device_head()
            .expect("B head")
            .balance(&pc),
        100
    );
}
