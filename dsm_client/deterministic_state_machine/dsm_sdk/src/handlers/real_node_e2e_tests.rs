// SPDX-License-Identifier: MIT OR Apache-2.0

//! End-to-end tests on real storage nodes (owner, 2026-09-23: no fakes).
//!
//! Every test runs two devices through the production handlers against five
//! real nodes (`test_support::real_nodes`), and checks outcomes where they
//! live: balances in each device's canonical state, and what each node holds
//! in its own database.

use dsm::types::proto as generated;
use generated::envelope::Payload;
use prost::Message;
use serial_test::serial;

use crate::bridge::{AppInvoke, AppResult, AppRouter as _};
use crate::test_support::two_device::{Pair, TestDevice};

fn args<M: Message>(m: &M) -> Vec<u8> {
    generated::ArgPack {
        codec: generated::Codec::Proto as i32,
        body: m.encode_to_vec(),
        ..Default::default()
    }
    .encode_to_vec()
}

async fn invoke(d: &TestDevice, method: &str, args: Vec<u8>) -> AppResult {
    d.enter();
    d.router()
        .invoke(AppInvoke {
            method: method.to_string(),
            args,
        })
        .await
}

/// The payload of a successful route answer (framing byte, then an Envelope).
fn payload(r: &AppResult) -> Payload {
    assert!(r.success, "route failed: {:?}", r.error_message);
    let env = generated::Envelope::decode(&r.data[1..]).expect("framed envelope");
    env.payload.expect("payload")
}

fn balance(d: &TestDevice, policy_commit: &[u8; 32]) -> u64 {
    d.enter();
    d.router()
        .core_sdk
        .device_head()
        .map(|h| h.balance(policy_commit))
        .unwrap_or(0)
}

fn era() -> [u8; 32] {
    crate::policy::builtin_policy_commit("ERA").expect("ERA policy")
}

/// Create a token on `d` and return its policy commit.
async fn create_token(d: &TestDevice, ticker: &str, supply: u128) -> [u8; 32] {
    let r = invoke(
        d,
        "token.create",
        args(&generated::TokenCreateRequest {
            ticker: ticker.to_string(),
            alias: format!("{ticker} token"),
            decimals: 0,
            genesis_supply_u128: supply.to_be_bytes().to_vec(),
            burn_enabled: true,
            transferable: true,
            threshold: 1,
            ..Default::default()
        }),
    )
    .await;
    assert!(r.success, "token.create: {:?}", r.error_message);
    d.enter();
    crate::storage::client_db::token_registry::get_token_by_ticker(ticker)
        .expect("registry read")
        .expect("created token is registered")
        .policy_commit
}

/// DSM Amendment A7: a transfer arrives, and no node ever held anything but
/// sealed, header-less envelopes — the memo is nowhere in any node's bytes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_transfer_reaches_the_nodes_only_sealed_and_arrives() {
    let p = Pair::boot(100, 0).await;
    let sent = p.a.send(&p.b, 10).await;
    assert!(sent.success, "{:?}", sent.error_message);
    let b_sync = p.b.sync().await;
    assert!(b_sync.success, "{:?}", b_sync.errors);
    let a_sync = p.a.sync().await;
    assert!(a_sync.success, "{:?}", a_sync.errors);
    assert_eq!(p.a.era_balance(), 90);
    assert_eq!(p.b.era_balance(), 10);

    let memo = b"A->B #0";
    let mut held = 0usize;
    for node in &p.nodes.nodes {
        for raw in node.spooled_envelopes() {
            held += 1;
            let env = generated::Envelope::decode(raw.as_slice()).expect("stored envelope");
            assert!(env.headers.is_none(), "{} holds an envelope with headers", node.member_id);
            assert!(
                matches!(env.payload, Some(Payload::Sealed(_))),
                "{} holds an unsealed payload",
                node.member_id
            );
            assert!(
                !raw.windows(memo.len()).any(|w| w == memo),
                "{} can read the memo",
                node.member_id
            );
        }
    }
    assert!(held > 0, "the transfer went through the nodes");
}

/// SoFi §51 (`ReleaseRule::AllAtCreation`): creating a token puts its whole
/// genesis supply in the creator's balance, in the creating transition.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_created_token_releases_its_whole_genesis_supply_to_its_creator() {
    let p = Pair::boot(200, 0).await;
    let tkn = create_token(&p.a, "TKN", 1_000).await;
    assert_eq!(balance(&p.a, &tkn), 1_000);
}

/// SoFi §27–§32 end to end through the routes: a vault is created, a trader
/// sets up with it and trades, and the position resolves Realized with the
/// balances moved.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_sofi_trade_executes_end_to_end() {
    let p = Pair::boot(500, 200).await;
    let tkn = create_token(&p.a, "TKN", 10_000).await;
    let era = era();
    let (token_a, token_b, reserve_a, reserve_b) =
        if era < tkn { (era, tkn, 100, 1_000) } else { (tkn, era, 1_000, 100) };

    let vault_id = match payload(
        &invoke(
            &p.a,
            "sofi.createVault",
            args(&generated::SofiCreateVaultRequest {
                token_a_policy_commit: token_a.to_vec(),
                token_b_policy_commit: token_b.to_vec(),
                reserve_a,
                reserve_b,
                fee_bps: 30,
            }),
        )
        .await,
    ) {
        Payload::SofiVaultCreatedResponse(v) => v.vault_id,
        other => panic!("sofi.createVault answered {other:?}"),
    };

    payload(
        &invoke(
            &p.b,
            "sofi.setup",
            args(&generated::SofiSetupRequest { vault_id: vault_id.clone() }),
        )
        .await,
    );

    let mut state = match payload(
        &invoke(
            &p.b,
            "sofi.trade",
            args(&generated::SofiTradeRequest {
                vault_id,
                token_in_policy_commit: era.to_vec(),
                amount_in: 10,
                min_amount_out: 1,
            }),
        )
        .await,
    ) {
        Payload::SofiPositionResponse(r) => r.state,
        other => panic!("sofi.trade answered {other:?}"),
    };
    if state != generated::SofiPositionState::Realized as i32 {
        state = match payload(&invoke(&p.b, "sofi.resolve", args(&generated::SofiResolveRequest {})).await) {
            Payload::SofiPositionResponse(r) => r.state,
            other => panic!("sofi.resolve answered {other:?}"),
        };
    }
    assert_eq!(state, generated::SofiPositionState::Realized as i32);
    assert_eq!(balance(&p.b, &era), 190, "the trader paid 10 ERA");
    assert!(balance(&p.b, &tkn) > 0, "the trader received TKN");
}

/// Offline, end to end: value moves into the designated offline accounting,
/// is spent over Bluetooth, and comes back online as a free state change
/// (owner, 2026-09-23), where it spends like any online value.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn offline_value_goes_out_and_comes_back() {
    let p = Pair::boot(100, 0).await;
    let offline = |r: &AppResult| match payload(r) {
        Payload::OfflineCashResponse(o) => o,
        other => panic!("offline cash answered {other:?}"),
    };

    let loaded = offline(
        &invoke(
            &p.a,
            "wallet.loadOffline",
            args(&generated::OfflineCashRequest { token_id: "ERA".into(), amount: 40 }),
        )
        .await,
    );
    assert_eq!((loaded.online_balance, loaded.allocation_balance), (60, 40));

    // A pays B 10 over Bluetooth, no network: the two devices' real BLE
    // handlers exchange the bearer frames in process.
    p.a.pay_offline_over_ble(&p.b, 10).await;

    let returned = offline(
        &invoke(
            &p.a,
            "wallet.unloadOffline",
            args(&generated::OfflineCashRequest { token_id: "ERA".into(), amount: 30 }),
        )
        .await,
    );
    assert_eq!((returned.online_balance, returned.allocation_balance), (90, 0));

    let b_back = offline(
        &invoke(
            &p.b,
            "wallet.unloadOffline",
            args(&generated::OfflineCashRequest { token_id: "ERA".into(), amount: 10 }),
        )
        .await,
    );
    assert_eq!(b_back.online_balance, 10);

    // What came back online spends online.
    let sent = p.b.send(&p.a, 10).await;
    assert!(sent.success, "{:?}", sent.error_message);
}
