// SPDX-License-Identifier: MIT OR Apache-2.0

//! End-to-end tests on storage nodes (owner, 2026-09-23: no fakes).
//!
//! Every test runs two devices through the production handlers against the
//! pinned set's nodes on Postgres (`test_support::nodes`), and checks outcomes where they
//! live: balances in each device's canonical state, and what each node holds
//! in its own database.

use dsm::types::proto as generated;
use generated::envelope::Payload;
use prost::Message;
use serial_test::serial;

use crate::bridge::{AppInvoke, AppQuery, AppResult, AppRouter as _};
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
        .expect("a booted device has a head")
        .balance(policy_commit)
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

/// The sender's `wallet.history` answer: the frontend's query, limit 16,
/// offset 0.
async fn history(d: &TestDevice) -> Vec<u8> {
    let mut body = Vec::with_capacity(16);
    body.extend_from_slice(&16u64.to_le_bytes());
    body.extend_from_slice(&0u64.to_le_bytes());
    let params = generated::ArgPack {
        codec: generated::Codec::Proto as i32,
        body,
        ..Default::default()
    }
    .encode_to_vec();
    d.enter();
    let r = d
        .router()
        .query(AppQuery {
            path: "wallet.history".to_string(),
            params,
        })
        .await;
    assert!(r.success, "wallet.history: {:?}", r.error_message);
    r.data
}

/// DSM Amendment A7: a transfer arrives, and no node ever held anything but
/// sealed, header-less envelopes — the memo is nowhere in any node's bytes.
///
/// The memo searched for is the one the harness sent (its first send is
/// `A->B #1`), shown by finding it in the sender's own history first: a
/// search for bytes that were never sent proves nothing.
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

    let memo = format!("{}->{} #1", p.a.slot, p.b.slot).into_bytes();
    let memo = memo.as_slice();
    let sender_history = history(&p.a).await;
    assert!(
        sender_history.windows(memo.len()).any(|w| w == memo),
        "the sender's history does not carry the memo it sent"
    );
    let mut held = 0usize;
    for node in &p.nodes.nodes {
        for spooled in node.spool().await {
            held += 1;
            let raw = spooled.envelope;
            let env = generated::Envelope::decode(raw.as_slice()).expect("stored envelope");
            assert!(
                env.headers.is_none(),
                "{} holds an envelope with headers",
                node.member_id
            );
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
    let (token_a, token_b, reserve_a, reserve_b) = if era < tkn {
        (era, tkn, 100, 1_000)
    } else {
        (tkn, era, 1_000, 100)
    };

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

    // Adoption precedes receipt (owner ruling 2026-09-13): the trader adds
    // TKN before it can receive any.
    p.b.enter();
    let adopted =
        p.b.router()
            .query(crate::bridge::AppQuery {
                path: "tokens.addByAnchor".to_string(),
                params: crate::util::text_id::encode_base32_crockford(&tkn).into_bytes(),
            })
            .await;
    assert!(adopted.success, "B adopts TKN: {:?}", adopted.error_message);

    payload(
        &invoke(
            &p.b,
            "sofi.setup",
            args(&generated::SofiSetupRequest {
                vault_id: vault_id.clone(),
            }),
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
        state = match payload(
            &invoke(
                &p.b,
                "sofi.resolve",
                args(&generated::SofiResolveRequest {}),
            )
            .await,
        ) {
            Payload::SofiPositionResponse(r) => r.state,
            other => panic!("sofi.resolve answered {other:?}"),
        };
    }
    assert_eq!(state, generated::SofiPositionState::Realized as i32);
    // The vault priced the trade at its reserves: 10 ERA in against 100 ERA
    // and 1000 TKN, at 30 bps.
    let out = dsm::dlv::route_commit::constant_product_output(10, 100, 1_000, 30)
        .expect("the vault prices the trade");
    assert_eq!(balance(&p.b, &era), 190, "the trader paid 10 ERA");
    assert_eq!(
        balance(&p.b, &tkn),
        out,
        "the trader received what the vault priced"
    );
    // The head and the admitted economic root agree about what B holds.
    p.b.enter();
    let head = p.b.router().core_sdk.device_head().expect("B has a head");
    let leaves =
        crate::storage::client_db::economic_lineage::load_leaf_cache().expect("B's leaf cache");
    let (g, dev) = (head.genesis(), head.devid());
    for token in [era, tkn] {
        let key = dsm::economic::keys::balance_key(&g, &dev, &token);
        let leaf = leaves
            .iter()
            .find(|(k, ..)| *k == key)
            .expect("the admitted root holds the balance leaf");
        let held = dsm::economic::state::EconomicLeafState::Balance(
            dsm::economic::state::EconomicBalanceState {
                policy_commit: token,
                amount: head.balance(&token),
            },
        );
        assert_eq!(
            (leaf.1, leaf.2.clone()),
            (
                held.leaf_value().expect("a leaf value"),
                held.encode().expect("a canonical leaf state")
            ),
            "the head holds what the admitted root holds"
        );
    }
}
