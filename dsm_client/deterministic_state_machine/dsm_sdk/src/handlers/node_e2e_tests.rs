// SPDX-License-Identifier: MIT OR Apache-2.0

//! End-to-end tests on storage nodes (owner, 2026-09-23: no fakes).
//!
//! Every test runs two devices through the production handlers against the
//! pinned set's nodes on Postgres (`test_support::nodes`), and checks outcomes where they
//! live: balances in each device's canonical state, and what each node holds
//! in its own database.

use std::collections::BTreeMap;

use dsm::economic::lineage::AdmittedEconomicPosition;
use dsm::route_chain::{CellFact, ChainState};
use dsm::sofi::conformance::{
    conformance_invalid_in_hand, derive_policy_fulfillments, FulfillmentConformanceError,
};
use dsm::sofi::derive;
use dsm::sofi::exercise::{recognize_exercise, RecognizedExercise};
use dsm::sofi::publication::Publication;
use dsm::sofi::resolution::WalkOutcome;
use dsm::sofi::resolve::WALK_BUDGET;
use dsm::sofi::wire::{
    AttemptEntry, DlvPolicyFulfillmentBody, PrecommitLeg, SofiExercise, TraderFulfillmentBody,
    TraderPrecommitBody,
};
use dsm::types::proto as generated;
use generated::envelope::Payload;
use prost::Message;
use serial_test::serial;

use crate::bridge::{AppInvoke, AppQuery, AppResult, AppRouter as _};
use crate::economic_fixtures::NETWORK;
use crate::sdk::sofi_advance::{complete_pending_fulfillment, Completion, NotTaken};
use crate::sdk::sofi_exercise::{attempt_cell, write_exercise};
use crate::sdk::sofi_reads::VerifierContext;
use crate::sdk::sofi_register::position_cells;
use crate::sdk::storage_set::canonical_set;
use crate::storage::client_db::economic_lineage;
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

/// The rows of `d`'s `wallet.history`, decoded.
async fn history_rows(d: &TestDevice) -> Vec<generated::TransactionInfo> {
    let data = history(d).await;
    match generated::Envelope::decode(&data[1..])
        .expect("framed envelope")
        .payload
        .expect("payload")
    {
        Payload::WalletHistoryResponse(r) => r.transactions,
        other => panic!("wallet.history answered {other:?}"),
    }
}

/// How many setups `d`'s history records (SoFi Amendment S16: each is a
/// transaction of its own).
async fn setups(d: &TestDevice) -> usize {
    let setup = generated::TransactionType::TxTypeSofiSetup as i32;
    history_rows(d)
        .await
        .iter()
        .filter(|row| row.tx_type == setup)
        .count()
}

/// What `d`'s `balance.list` reports it can spend of `ticker`: the view the
/// wallet renders.
async fn listed(d: &TestDevice, ticker: &str) -> u64 {
    d.enter();
    let r = d
        .router()
        .query(AppQuery {
            path: "balance.list".to_string(),
            params: Vec::new(),
        })
        .await;
    let balances = match payload(&r) {
        Payload::BalancesListResponse(r) => r.balances,
        other => panic!("balance.list answered {other:?}"),
    };
    match balances.iter().find(|b| b.token_id == ticker) {
        Some(row) => row.available,
        None => panic!("balance.list names no {ticker}"),
    }
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
    assert_eq!(
        p.a.era_balance(),
        crate::economic_fixtures::whole_era(100) - 10
    );
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

/// DSM Amendment A1, storage spec §3, §4 and §8 (owner ruling 2026-09-25):
/// an inbox read that did not cover every delivery is not a complete sync. A
/// delivery lands on the register quorum of members, so a read covers every
/// delivery only once `members - quorum + 1` of them answer. With fewer up,
/// B's sync reports a partial read; with none up, it reports that no member
/// answered; either way it fails and is not counted as a completed run. With
/// every member back, the same sync pulls the transfer.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn an_inbox_read_that_did_not_cover_every_delivery_is_not_a_complete_sync() {
    let mut p = Pair::boot(100, 0).await;
    let sent = p.a.send(&p.b, 10).await;
    assert!(sent.success, "{:?}", sent.error_message);
    let everyone: Vec<String> = p.nodes.members().into_iter().map(|(id, ..)| id).collect();
    let quorum = canonical_set(NETWORK).expect("the pinned set").quorum() as usize;
    let needed = everyone.len() - quorum + 1;
    let count = || crate::storage::client_db::storage_sync_runs::completed().expect("count");

    // Fewer members up than a read needs to meet every delivery.
    let down: Vec<String> = everyone[..everyone.len() - (needed - 1)].to_vec();
    p.nodes.take_down(&down).await;
    p.b.enter();
    let before = count();
    let partial = p.b.sync().await;
    assert!(!partial.success, "a partial read reported a complete sync");
    assert!(
        partial.errors.iter().any(|e| e.contains("partial")),
        "{:?}",
        partial.errors
    );
    p.b.enter();
    assert_eq!(count(), before, "a partial run is not counted as completed");

    // No member up.
    let rest: Vec<String> = everyone[everyone.len() - (needed - 1)..].to_vec();
    p.nodes.take_down(&rest).await;
    let outage = p.b.sync().await;
    assert!(!outage.success, "a sync that read nothing reported success");
    assert_eq!(outage.pulled, 0);
    assert!(
        outage
            .errors
            .iter()
            .any(|e| e.contains("no storage node answered")),
        "{:?}",
        outage.errors
    );
    p.b.enter();
    assert_eq!(count(), before, "a failed run is not counted as completed");

    p.nodes.bring_up(&everyone).await;
    let back = p.b.sync().await;
    assert!(back.success, "{:?}", back.errors);
    assert_eq!(p.b.era_balance(), 10);
    p.b.enter();
    assert_eq!(count(), before + 1);
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

/// A market: A's token and A's vault holding ERA against it, with B adopted
/// to the token and set up to trade in the vault.
struct Market {
    vault_id: [u8; 32],
    era: [u8; 32],
    tkn: [u8; 32],
}

/// `base` units of `token` as the user enters them on `d`: token units, with
/// the decimals of the token's committed policy.
fn entered(d: &TestDevice, token: &[u8; 32], base: u64) -> String {
    d.enter();
    let (.., decimals) = super::wallet_routes::token_of_commit(token).expect("a known token");
    super::wallet_routes::format_base_units_for_display(base, decimals)
}

/// `d`'s `sofi.createVault` on two tokens at their reserves, at 30 bps, the
/// pair in the order §28 requires (`token_a < token_b`). The vault id.
async fn create_vault(d: &TestDevice, x: ([u8; 32], u64), y: ([u8; 32], u64)) -> [u8; 32] {
    let ((token_a, reserve_a), (token_b, reserve_b)) = if x.0 < y.0 { (x, y) } else { (y, x) };
    let request = generated::SofiCreateVaultRequest {
        token_a_policy_commit: token_a.to_vec(),
        token_b_policy_commit: token_b.to_vec(),
        reserve_a_entered: entered(d, &token_a, reserve_a),
        reserve_b_entered: entered(d, &token_b, reserve_b),
        fee_bps: 30,
    };
    let vault_id = match payload(&invoke(d, "sofi.createVault", args(&request)).await) {
        Payload::SofiVaultCreatedResponse(v) => v.vault_id,
        other => panic!("sofi.createVault answered {other:?}"),
    };
    vault_id
        .as_slice()
        .try_into()
        .expect("a vault id is 32 bytes")
}

/// `d` adds `token` by its anchor. Adoption precedes receipt (owner ruling
/// 2026-09-13): a trader adds a token before it can receive any.
async fn adopt(d: &TestDevice, token: &[u8; 32]) {
    d.enter();
    let adopted = d
        .router()
        .query(crate::bridge::AppQuery {
            path: "tokens.addByAnchor".to_string(),
            params: crate::util::text_id::encode_base32_crockford(token).into_bytes(),
        })
        .await;
    assert!(
        adopted.success,
        "{} adopts the token: {:?}",
        d.slot, adopted.error_message
    );
}

/// `d` sets up with `vault_id` ahead of what it does next, with the
/// production `set_up_with` a trade runs first (SoFi Amendment S16): a test
/// that needs the setup's position behind it, not inside its first trade.
async fn set_up(d: &TestDevice, vault_id: &[u8; 32]) {
    d.enter();
    let set = canonical_set(NETWORK).expect("the pinned set");
    crate::sdk::sofi_flow::set_up_with(
        &d.router().core_sdk,
        &set,
        &[*vault_id],
        &dsm::sofi::resolve::AcceptedGeneses::default(),
    )
    .await
    .expect("the setup is admitted");
}

/// A creates the token and the vault (100 base units of ERA against 1000 of
/// TKN, at 30 bps) and B adopts the token: a market B has not set up with.
async fn open_market_unset(p: &Pair) -> Market {
    let tkn = create_token(&p.a, "TKN", 10_000).await;
    let era = era();
    let vault_id = create_vault(&p.a, (era, 100), (tkn, 1_000)).await;
    adopt(&p.b, &tkn).await;
    Market { vault_id, era, tkn }
}

/// [`open_market_unset`], and B sets up with the vault before anything else.
async fn open_market(p: &Pair) -> Market {
    let m = open_market_unset(p).await;
    set_up(&p.b, &m.vault_id).await;
    m
}

/// B's one-hop trade of `amount_in` ERA for TKN in the market.
fn trade_request(p: &Pair, m: &Market, amount_in: u64) -> generated::SofiTradeRequest {
    generated::SofiTradeRequest {
        vault_id: m.vault_id.to_vec(),
        token_in_policy_commit: m.era.to_vec(),
        amount_in_entered: entered(&p.b, &m.era, amount_in),
        min_amount_out_entered: entered(&p.b, &m.tkn, 1),
        token_out_policy_commit: m.tkn.to_vec(),
    }
}

/// The position and its state, as a route reports them.
fn position_of(r: &AppResult, route: &str) -> (u64, i32) {
    match payload(r) {
        Payload::SofiPositionResponse(r) => (r.position, r.state),
        other => panic!("{route} answered {other:?}"),
    }
}

/// B's `sofi.resolve`.
async fn resolve(p: &Pair) -> (u64, i32) {
    position_of(
        &invoke(
            &p.b,
            "sofi.resolve",
            args(&generated::SofiResolveRequest {}),
        )
        .await,
        "sofi.resolve",
    )
}

/// `d` takes a position through `route` and it resolves Realized, through
/// `sofi.resolve` if the route's own rounds did not get there. The position.
async fn realized_through(d: &TestDevice, route: &str, request: Vec<u8>) -> u64 {
    let realized = generated::SofiPositionState::Realized as i32;
    let (position, state) = position_of(&invoke(d, route, request).await, route);
    if state == realized {
        return position;
    }
    let resolved = position_of(
        &invoke(d, "sofi.resolve", args(&generated::SofiResolveRequest {})).await,
        "sofi.resolve",
    );
    assert_eq!(resolved, (position, realized), "{route} on {}", d.slot);
    position
}

/// B trades `amount_in` ERA in the market and the position resolves
/// Realized. The position.
async fn realized_trade(p: &Pair, m: &Market, amount_in: u64) -> u64 {
    realized_through(&p.b, "sofi.trade", args(&trade_request(p, m, amount_in))).await
}

/// What a device stands on for a resolution, as `sofi_advance` assembles it:
/// its identity, and the conditional position it resolved, if that is what
/// it stands on.
fn standing_of(d: &TestDevice) -> (([u8; 32], [u8; 32]), Option<AdmittedEconomicPosition>) {
    d.enter();
    let admitted = economic_lineage::get_admitted()
        .expect("read admitted")
        .expect("an admitted position");
    // The position this device resolved itself, for Core to read what it
    // selected when a P names it as its parent.
    let parent =
        matches!(admitted, AdmittedEconomicPosition::ResolvedSofi { .. }).then_some(admitted);
    ((d.genesis, d.device_id), parent)
}

fn pending_position(d: &TestDevice) -> Option<u64> {
    d.enter();
    d.router()
        .core_sdk
        .device_head()
        .expect("a booted device has a head")
        .pending_economic_admission()
        .map(|pending| pending.economic_position)
}

fn admitted_position(d: &TestDevice) -> u64 {
    d.enter();
    economic_lineage::get_admitted_coordinate()
        .expect("read admitted")
        .expect("an admitted position")
        .0
}

fn member_name(member: &[u8]) -> String {
    String::from_utf8(member.to_vec()).expect("member ids are UTF-8")
}

/// The head and the admitted economic root of `d` agree about what it holds
/// of each token.
fn head_agrees_with_admitted_root(d: &TestDevice, tokens: &[[u8; 32]]) {
    d.enter();
    let head = d.router().core_sdk.device_head().expect("a head");
    let leaves =
        crate::storage::client_db::economic_lineage::load_leaf_cache().expect("the leaf cache");
    let (g, dev) = (head.genesis(), head.devid());
    for token in tokens {
        let key = dsm::economic::keys::balance_key(&g, &dev, token);
        let leaf = leaves
            .iter()
            .find(|(k, ..)| *k == key)
            .expect("the admitted root holds the balance leaf");
        let held = dsm::economic::state::EconomicLeafState::Balance(
            dsm::economic::state::EconomicBalanceState {
                policy_commit: *token,
                amount: head.balance(token),
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

/// SoFi §27–§32 end to end through the routes: a vault is created, a trader
/// sets up with it and trades, and the position resolves Realized with the
/// balances moved.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_sofi_trade_executes_end_to_end() {
    let p = Pair::boot(500, 200).await;
    let m = open_market(&p).await;
    realized_trade(&p, &m, 10).await;
    // The vault priced the trade at its reserves: 10 base units of ERA in
    // against 100 of ERA and 1000 of TKN, at 30 bps.
    let out = dsm::dlv::route_commit::constant_product_output(10, 100, 1_000, 30)
        .expect("the vault prices the trade");
    assert_eq!(
        balance(&p.b, &m.era),
        crate::economic_fixtures::whole_era(200) - 10,
        "the trader paid 10 base units"
    );
    assert_eq!(
        balance(&p.b, &m.tkn),
        out,
        "the trader received what the vault priced"
    );
    head_agrees_with_admitted_root(&p.b, &[m.era, m.tkn]);
}

/// MR-SOFI-0241, SoFi Amendment S14: a vault key held final by an exercise
/// whose fulfillment can never register — a rival claim took the trader's
/// position first — is skipped on that fact alone. The walk reads the key's
/// cell and the trader's position pair, and asks for none of the exercise's
/// validation evidence; the next key is live.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_key_whose_fulfillment_can_never_register_is_skipped_without_its_evidence() {
    let p = Pair::boot(500, 200).await;
    let m = open_market(&p).await;
    let set = canonical_set(NETWORK).expect("the pinned set");

    // A rival claim takes B's next position before B trades.
    let q = admitted_position(&p.b) + 1;
    let (.., root) = {
        p.b.enter();
        economic_lineage::get_admitted_coordinate()
            .expect("read admitted")
            .expect("an admitted position")
    };
    let pair = position_cells(&set, &p.b.genesis, &p.b.device_id, q, &root)
        .expect("B's next position pair");
    let rival = dsm::sofi::wire::SofiResolutionClaim {
        genesis: p.b.genesis,
        device_id: p.b.device_id,
        position: q,
        fulfillment_id: [0x77; 32],
        realize_root: [0x78; 32],
        void_root: root,
    }
    .encode();
    let taken = crate::sdk::route_seats::write_recorded(&set, pair.root().routed(), &rival)
        .await
        .expect("any party may write a claim");
    assert!(
        taken.reached_leader(),
        "the rival claim holds B's root cell"
    );

    // B trades: its fulfillment lands, its claim arrives after the rival's,
    // and its exercise holds the vault's first key.
    invoke(&p.b, "sofi.trade", args(&trade_request(&p, &m, 10))).await;

    // A, the vault's owner, walks the vault's first parent.
    let (own, parents) = standing_of(&p.a);
    let ctx = VerifierContext::new(&set, Some(own), parents.as_ref()).expect("a verifier");
    let verifier = ctx.verifier();
    let chain = verifier.chain(&m.vault_id).expect("the vault's chain");
    let r0 = chain.roots()[0];
    let held = verifier
        .read_attempt_cell(&m.vault_id, &r0, 0)
        .expect("read")
        .expect("decided");
    let exercise = held
        .exercise()
        .cloned()
        .expect("B's exercise holds the vault's first key");
    assert_eq!(
        held.fact(),
        CellFact::Held {
            id: *exercise.external_commitment(),
            state: ChainState::Final,
        }
    );
    let registration = verifier
        .read_registration(&p.b.genesis, &p.b.device_id, q, &root)
        .expect("read")
        .expect("decided");
    assert!(
        matches!(
            registration.registration(),
            dsm::sofi::registration::Registration::NeverRegistered { .. }
        ),
        "B's fulfillment can never register: {:?}",
        registration.registration()
    );

    for node in &p.nodes.nodes {
        node.forget_requests();
    }
    let chains = BTreeMap::from([(m.vault_id, chain)]);
    let walked = verifier
        .walk_parent(&chains, &m.vault_id, &r0, 0, WALK_BUDGET)
        .expect("the walk");
    assert_eq!(walked.outcome, WalkOutcome::Unresolved { attempt: 1 });
    assert_eq!(walked.not_established, None);

    // What the walk asked the nodes for: the vault's first two keys, B's
    // position pair, the chains that decide them, and the precommit the
    // registration read names — never the exercise's validation evidence.
    let path = |key: &[u8; 32]| crate::util::text_id::encode_base32_crockford(key);
    let cells = [
        *attempt_cell(&set, &m.vault_id, &r0, 0)
            .expect("the first key")
            .routed()
            .key(),
        *attempt_cell(&set, &m.vault_id, &r0, 1)
            .expect("the next key")
            .routed()
            .key(),
        *pair.fulfillment().key(),
        *pair.root().routed().key(),
    ]
    .map(|key| format!("GET /api/v2/cell/{}", path(&key)));
    let precommit = Publication::Precommit {
        body: &exercise.precommit().body,
        signature: &exercise.precommit().signature,
    }
    .address()
    .expect("P's address");
    let precommit_read = format!("GET /api/v2/immutable/{}", path(&precommit));
    let mut indexes = std::collections::BTreeSet::new();
    for node in &p.nodes.nodes {
        for request in node.requests() {
            if request.starts_with("GET /api/v2/index/") {
                indexes.insert(request);
            } else {
                assert!(
                    cells.contains(&request)
                        || request == precommit_read
                        || request.contains("/api/v2/bytecommit/")
                        || request == "GET /api/v2/health",
                    "{} was asked for more than the key, the pair and P: {request}",
                    node.member_id
                );
            }
        }
    }
    assert!(indexes.len() <= 1, "one index read, P's: {indexes:?}");
}

/// A trader who has traded can still pay (P15-9). B's history holds a SoFi
/// position, realized; B then pays A ordinary ERA, and A accepts it. A's walk
/// of B's lineage passes the resolved SoFi position on Core's own verdict of
/// the exercise, and the payment's source is B's later single-root position,
/// not the SoFi position (the owner's 2026-09-18 ruling).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_trader_who_has_traded_can_pay() {
    let p = Pair::boot(500, 200).await;
    let m = open_market(&p).await;
    realized_trade(&p, &m, 10).await;
    let a_before = p.a.era_balance();
    let b_before = p.b.era_balance();
    let sent = p.b.send(&p.a, 5).await;
    assert!(sent.success, "{:?}", sent.error_message);
    let a_sync = p.a.sync().await;
    assert!(a_sync.success, "{:?}", a_sync.errors);
    let b_sync = p.b.sync().await;
    assert!(b_sync.success, "{:?}", b_sync.errors);
    assert_eq!(p.b.era_balance(), b_before - 5, "the trader paid");
    assert_eq!(
        p.a.era_balance(),
        a_before + 5,
        "the payee accepted the payment"
    );
}

/// B's own exercise re-aimed at the vault's next generation: `P` names the
/// next parent root, `F` names attempt 0 there, the witnesses derive from the
/// re-aimed `P`, and `sign` signs both new bodies' digests. Signed by B, every
/// signature verifies, so it is one operation's exercise signed by the trader
/// it names; and its own bytes refute it, because `P`'s legs are no longer
/// the legs its `P(E)` derives (conformance item 7).
fn reaimed(
    honest: &RecognizedExercise,
    vault_id: &[u8; 32],
    parent_root: &[u8; 32],
    sign: &dyn Fn([u8; 32]) -> Vec<u8>,
) -> SofiExercise {
    let p = &honest.precommit().body;
    let legs: Vec<PrecommitLeg> = p
        .legs()
        .iter()
        .map(|leg| PrecommitLeg {
            parent_root: if leg.vault_id == *vault_id {
                *parent_root
            } else {
                leg.parent_root
            },
            ..*leg
        })
        .collect();
    let precommit = TraderPrecommitBody::new(
        *p.genesis(),
        *p.device_id(),
        p.position(),
        *p.parent_claim_ref(),
        *p.external_commitment(),
        legs,
        *p.realize_root(),
        *p.void_root(),
        *p.storage_set_id(),
        p.signature_alg(),
        p.claimant_public_key(),
    )
    .expect("a well-formed P");
    let canonical = derive::canonical_legs(honest.preimage()).expect("P(E) derives its legs");
    let shadows: Vec<[u8; 32]> = precommit
        .legs()
        .iter()
        .map(|leg| {
            canonical
                .iter()
                .find(|l| l.vault_id == leg.vault_id)
                .expect("a leg P(E) derives")
                .shadow_core
        })
        .collect();
    let witnesses =
        derive_policy_fulfillments(&precommit, &shadows).expect("the canonical witnesses");
    let mut ids: Vec<[u8; 32]> = witnesses
        .iter()
        .map(derive::policy_fulfillment_id)
        .collect();
    ids.sort();
    let f = &honest.fulfillment().body;
    let attempts: Vec<AttemptEntry> = f
        .attempts()
        .iter()
        .map(|a| AttemptEntry {
            attempt: if a.vault_id == *vault_id {
                0
            } else {
                a.attempt
            },
            ..*a
        })
        .collect();
    let fulfillment = TraderFulfillmentBody::new(
        derive::precommit_id(&precommit),
        ids,
        attempts,
        f.position(),
        f.signature_alg(),
        f.claimant_public_key(),
    )
    .expect("a well-formed F");
    let fulfillment_signature = sign(derive::fulfillment_signing_digest(&fulfillment));
    let precommit_signature = sign(derive::precommit_signing_digest(&precommit));
    SofiExercise::new(
        Publication::Fulfillment {
            body: &fulfillment,
            signature: &fulfillment_signature,
        }
        .object_bytes()
        .expect("an F envelope"),
        Publication::Precommit {
            body: &precommit,
            signature: &precommit_signature,
        }
        .object_bytes()
        .expect("a P envelope"),
        honest.preimage().encode().expect("P(E) bytes"),
        witnesses
            .iter()
            .map(DlvPolicyFulfillmentBody::encode)
            .collect(),
        honest.closure().to_vec(),
    )
    .expect("an exercise")
}

/// MR-DSM-0041, SoFi §23–§24: an attempt key held final by an exercise its
/// own bytes refute is skipped on those bytes alone. The walk reads the key
/// to find the exercise and nothing else about it — no registration, no
/// object, no other cell — and the next trade against the vault takes the
/// next key.
///
/// The exercise is B's own, re-aimed at the vault's next generation and
/// signed again by B ([`reaimed`]); nothing of it is registered or published
/// anywhere, so any read about it would find nothing to establish, and the
/// nodes' request logs show that none was made.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_key_held_by_an_exercise_its_own_bytes_refute_is_skipped_on_those_bytes_alone() {
    let p = Pair::boot(500, 200).await;
    let m = open_market(&p).await;
    realized_trade(&p, &m, 10).await;
    let out1 = dsm::dlv::route_commit::constant_product_output(10, 100, 1_000, 30)
        .expect("the vault prices the trade");
    let set = canonical_set(NETWORK).expect("the pinned set");

    // The vault's chain as B established it: the genesis root and the
    // generation B's trade produced.
    let (own, parents) = standing_of(&p.b);
    let ctx = VerifierContext::new(&set, Some(own), parents.as_ref()).expect("a verifier");
    let verifier = ctx.verifier();
    let chain = verifier.chain(&m.vault_id).expect("the vault's chain");
    assert_eq!(chain.roots().len(), 2, "genesis and one consumption");
    let (r0, r1) = (chain.roots()[0], chain.roots()[1]);

    // B's exercise, read back from the key it consumed, and re-aimed.
    let honest = verifier
        .read_attempt_cell(&m.vault_id, &r0, 0)
        .expect("read")
        .expect("decided")
        .into_exercise()
        .expect("B's exercise holds the key it consumed");
    p.b.enter();
    let secret_key = crate::sdk::signing_authority::current_secret_key().expect("B's signing key");
    let hostile = reaimed(&honest, &m.vault_id, &r1, &|digest| {
        dsm::crypto::sphincs::sphincs_sign(&secret_key, &digest).expect("B signs")
    });
    let recognized = recognize_exercise(&hostile.encode())
        .expect("the re-aimed bytes are one operation's exercise");
    let refuted = conformance_invalid_in_hand(
        recognized.precommit(),
        &recognized.fulfillment().body,
        &recognized.fulfillment().signature,
        recognized.preimage(),
        recognized.closure(),
    );
    assert!(
        matches!(
            refuted,
            Some(FulfillmentConformanceError::LegsDoNotMatchPreimage)
        ),
        "P's legs are not the legs its P(E) derives: {refuted:?}"
    );
    let writes = write_exercise(&set, &hostile, &recognized)
        .await
        .expect("any party may write an exercise");
    assert!(writes.iter().all(|w| w.reached_leader), "{writes:?}");
    let held = verifier
        .read_attempt_cell(&m.vault_id, &r1, 0)
        .expect("read")
        .expect("decided");
    assert_eq!(
        held.fact(),
        CellFact::Held {
            id: *recognized.external_commitment(),
            state: ChainState::Final,
        },
        "the re-aimed exercise holds the next generation's first key, final"
    );

    // The walk at the next generation, by a verifier that has read nothing
    // yet — this one keeps the held key's final reads — with every node's
    // request log cleared: what the walk reads, the nodes are asked.
    let walking = VerifierContext::new(&set, Some(own), parents.as_ref()).expect("a verifier");
    for node in &p.nodes.nodes {
        node.forget_requests();
    }
    let chains = BTreeMap::from([(m.vault_id, chain)]);
    let walked = walking
        .verifier()
        .walk_parent(&chains, &m.vault_id, &r1, 0, WALK_BUDGET)
        .expect("the walk");
    assert_eq!(walked.outcome, WalkOutcome::Unresolved { attempt: 1 });
    assert_eq!(walked.not_established, None);
    assert!(walked.consumed.is_none());

    // The nodes were asked for the two attempt keys and the ByteCommit
    // material that decides them, and for nothing else: no registration
    // cell, no index, no object.
    let cell_read = |attempt: u64| {
        let cell = attempt_cell(&set, &m.vault_id, &r1, attempt).expect("the attempt key");
        format!(
            "GET /api/v2/cell/{}",
            crate::util::text_id::encode_base32_crockford(cell.routed().key())
        )
    };
    let (k0, k1) = (cell_read(0), cell_read(1));
    let mut cells_read = Vec::new();
    for node in &p.nodes.nodes {
        for request in node.requests() {
            if request.starts_with("GET /api/v2/cell/") {
                assert!(
                    request == k0 || request == k1,
                    "{} was asked for another cell: {request}",
                    node.member_id
                );
                cells_read.push(request);
            } else {
                assert!(
                    request.contains("/api/v2/bytecommit/") || request == "GET /api/v2/health",
                    "{} was asked for more than a cell's chain: {request}",
                    node.member_id
                );
            }
        }
    }
    assert!(cells_read.contains(&k0), "the held key was read");
    assert!(cells_read.contains(&k1), "the next key was read");

    // The next trade takes the next key, and the vault prices it at the
    // reserves B's first trade left.
    let q2 = realized_trade(&p, &m, 10).await;
    let next = verifier
        .read_attempt_cell(&m.vault_id, &r1, 1)
        .expect("read")
        .expect("decided")
        .into_exercise()
        .expect("B's second exercise holds the next key");
    assert_eq!(next.fulfillment().body.position(), q2);
    assert_eq!(next.fulfillment().body.attempts()[0].attempt, 1);
    let out2 = dsm::dlv::route_commit::constant_product_output(10, 110, 1_000 - out1, 30)
        .expect("the vault prices the second trade");
    assert_eq!(
        balance(&p.b, &m.era),
        crate::economic_fixtures::whole_era(200) - 20
    );
    assert_eq!(balance(&p.b, &m.tkn), out1 + out2);
    head_agrees_with_admitted_root(&p.b, &[m.era, m.tkn]);
}

/// SoFi §17.5 and §9, storage spec §9 rule 3: bytes shaped like an exercise
/// whose signatures do not verify are nothing at a successor key. B's own
/// exercise, re-aimed at the vault's next generation with signatures that
/// verify under no key, is written final along the whole route of that
/// generation's first key; the key still reads open, and B's next trade takes
/// attempt 0 there and realizes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn an_unsigned_exercise_at_a_successor_key_takes_nothing() {
    let p = Pair::boot(500, 200).await;
    let m = open_market(&p).await;
    realized_trade(&p, &m, 10).await;
    let set = canonical_set(NETWORK).expect("the pinned set");
    let (own, parents) = standing_of(&p.b);
    let ctx = VerifierContext::new(&set, Some(own), parents.as_ref()).expect("a verifier");
    let verifier = ctx.verifier();
    let chain = verifier.chain(&m.vault_id).expect("the vault's chain");
    assert_eq!(chain.roots().len(), 2, "genesis and one consumption");
    let (r0, r1) = (chain.roots()[0], chain.roots()[1]);
    let honest = verifier
        .read_attempt_cell(&m.vault_id, &r0, 0)
        .expect("read")
        .expect("decided")
        .into_exercise()
        .expect("B's exercise holds the key it consumed");

    let unsigned = reaimed(&honest, &m.vault_id, &r1, &|_| vec![0x77; 8]);
    assert!(recognize_exercise(&unsigned.encode()).is_none());
    let cell = attempt_cell(&set, &m.vault_id, &r1, 0).expect("the first key at R1");
    let write = crate::sdk::route_seats::write_recorded(&set, cell.routed(), &unsigned.encode())
        .await
        .expect("the nodes keep whatever they are given");
    assert!(write.reached_leader());
    let read = verifier
        .read_attempt_cell(&m.vault_id, &r1, 0)
        .expect("read")
        .expect("decided");
    assert_eq!(read.fact(), CellFact::Open, "unsigned bytes hold nothing");

    let q2 = realized_trade(&p, &m, 10).await;
    let second = verifier
        .read_attempt_cell(&m.vault_id, &r1, 0)
        .expect("read")
        .expect("decided")
        .into_exercise()
        .expect("B's second exercise holds the first key at R1");
    assert_eq!(second.fulfillment().body.position(), q2);
    assert_eq!(
        balance(&p.b, &m.era),
        crate::economic_fixtures::whole_era(200) - 20
    );
    head_agrees_with_admitted_root(&p.b, &[m.era, m.tkn]);
}

/// B's own completion of its pending position, stages 7 and 8 from what
/// storage holds: what the network took, or what it did not.
async fn complete(p: &Pair) -> Completion {
    let set = canonical_set(NETWORK).expect("the pinned set");
    p.b.enter();
    complete_pending_fulfillment(
        &p.b.router().core_sdk,
        &set,
        &dsm::sofi::resolve::AcceptedGeneses::default(),
    )
    .await
    .expect("a stage the network did not take is its status, not an error")
}

/// SoFi Amendment S7 and storage §3, §6: a trade cut short by a member's
/// failed write is the network status until the write can land, and nothing
/// negative is recorded meanwhile. The position pair's leader refuses the
/// pair when B trades: the head advances and the install cannot reach the
/// leader, so the trade is `RetriesExhausted` at its position — fenced,
/// nothing admitted, no balance moved — and completion names the pair's
/// leader as what the network did not take. When that store takes writes
/// again and the first leg's key is refused at its own leader, completion
/// names that leg and the reads find no exercise: `RetriesExhausted`, still
/// pending, nothing moved. When every write lands, completion is written and
/// the position realizes. A resolve with nothing pending is refused: an
/// error, never the network status.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_trade_cut_short_by_a_refused_write_is_the_network_status_until_it_lands() {
    let p = Pair::boot(500, 200).await;
    let m = open_market(&p).await;
    let set = canonical_set(NETWORK).expect("the pinned set");
    let realized = generated::SofiPositionState::Realized as i32;
    let exhausted = generated::SofiPositionState::RetriesExhausted as i32;

    // The two cells the trade writes: B's position pair at its next
    // position, and the vault's first attempt key at its genesis root.
    let position = admitted_position(&p.b);
    let q = position + 1;
    let (.., root) = {
        p.b.enter();
        economic_lineage::get_admitted_coordinate()
            .expect("read admitted")
            .expect("an admitted position")
    };
    let pair = position_cells(&set, &p.b.genesis, &p.b.device_id, q, &root)
        .expect("B's next position pair");
    let pair_leader = member_name(pair.fulfillment().route().leader());
    let (own, parents) = standing_of(&p.b);
    let ctx = VerifierContext::new(&set, Some(own), parents.as_ref()).expect("a verifier");
    let verifier = ctx.verifier();
    let chain = verifier.chain(&m.vault_id).expect("the vault's chain");
    assert_eq!(chain.roots().len(), 1, "the vault is at its genesis");
    let attempt =
        attempt_cell(&set, &m.vault_id, &chain.roots()[0], 0).expect("the first attempt key");
    let attempt_leader = member_name(attempt.routed().route().leader());

    // 1. The pair's leader refuses the pair: the trade is the network status
    // at q, fenced, and completion names the pair's leader.
    p.nodes
        .refuse_cell_writes(
            &pair_leader,
            &[*pair.fulfillment().key(), *pair.root().routed().key()],
        )
        .await;
    let r = invoke(&p.b, "sofi.trade", args(&trade_request(&p, &m, 10))).await;
    assert_eq!(position_of(&r, "sofi.trade"), (q, exhausted));
    assert_eq!(pending_position(&p.b), Some(q));
    assert_eq!(admitted_position(&p.b), position);
    assert_eq!(
        balance(&p.b, &m.era),
        crate::economic_fixtures::whole_era(200)
    );
    assert_eq!(
        complete(&p).await,
        Completion::NotTaken {
            position: q,
            why: NotTaken::PairLeaderUnreached
        }
    );

    // 2. The pair lands and the first leg's key is refused at its leader:
    // completion names the leg, and the reads find no exercise — the
    // network status, recording nothing.
    p.nodes.accept_cell_writes(&pair_leader).await;
    p.nodes
        .refuse_cell_writes(&attempt_leader, &[*attempt.routed().key()])
        .await;
    assert_eq!(
        complete(&p).await,
        Completion::NotTaken {
            position: q,
            why: NotTaken::LegLeaderUnreached(vec![m.vault_id])
        }
    );
    assert_eq!(resolve(&p).await, (q, exhausted));
    assert_eq!(pending_position(&p.b), Some(q));
    assert_eq!(admitted_position(&p.b), position);
    assert_eq!(
        balance(&p.b, &m.era),
        crate::economic_fixtures::whole_era(200)
    );
    assert_eq!(balance(&p.b, &m.tkn), 0);

    // 3. Every write lands: completion is written and the position realizes.
    p.nodes.accept_cell_writes(&attempt_leader).await;
    assert!(matches!(complete(&p).await, Completion::Written(..)));
    assert_eq!(resolve(&p).await, (q, realized));
    assert_eq!(pending_position(&p.b), None);
    assert_eq!(admitted_position(&p.b), q);
    let out = dsm::dlv::route_commit::constant_product_output(10, 100, 1_000, 30)
        .expect("the vault prices the trade");
    assert_eq!(
        balance(&p.b, &m.era),
        crate::economic_fixtures::whole_era(200) - 10
    );
    assert_eq!(balance(&p.b, &m.tkn), out);
    head_agrees_with_admitted_root(&p.b, &[m.era, m.tkn]);

    // 4. Nothing pending: a resolve is refused, not reported as the network
    // status of a position.
    let r = invoke(
        &p.b,
        "sofi.resolve",
        args(&generated::SofiResolveRequest {}),
    )
    .await;
    assert!(
        !r.success,
        "a resolve with nothing pending answered {:?}",
        r.data
    );
}

/// SoFi §30, Amendment S16 and storage §4: a route search over vaults the
/// reads do not establish says so. B, never set up with A's vault, is quoted
/// one hop ERA→TKN, found through the two tokens' indexes, the search
/// complete; with the fleet below quorum the search finds no route and says
/// it is partial — never an empty route reported as a complete search; with
/// the fleet back, the one hop again, complete.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_route_search_that_cannot_see_its_vaults_says_so() {
    let mut p = Pair::boot(500, 200).await;
    let m = open_market_unset(&p).await;
    let request = generated::SofiFindRouteRequest {
        token_in_policy_commit: m.era.to_vec(),
        token_out_policy_commit: m.tkn.to_vec(),
        amount_in_entered: entered(&p.b, &m.era, 10),
    };
    let found = |r: &AppResult| match payload(r) {
        Payload::SofiFindRouteResponse(r) => (r.hops, r.search),
        other => panic!("sofi.findRoute answered {other:?}"),
    };
    let complete = generated::SofiSearch::Complete as i32;
    let partial = generated::SofiSearch::Partial as i32;
    let out = dsm::dlv::route_commit::constant_product_output(10, 100, 1_000, 30)
        .expect("the vault prices the hop");
    let (route, search) = found(&invoke(&p.b, "sofi.findRoute", args(&request)).await);
    assert_eq!(search, complete, "every vault of the two tokens was seen");
    assert_eq!(route.len(), 1, "one hop through A's vault");
    assert_eq!(route[0].vault_id, m.vault_id.to_vec());
    assert_eq!((route[0].amount_in, route[0].amount_out), (10, out));

    let down = crate::economic_fixtures::members_to_break_quorum();
    p.nodes.take_down(&down).await;
    let (route, search) = found(&invoke(&p.b, "sofi.findRoute", args(&request)).await);
    assert_eq!(
        (route.len(), search),
        (0, partial),
        "no route, from a search that says it could not see every vault"
    );

    p.nodes.bring_up(&down).await;
    let (route, search) = found(&invoke(&p.b, "sofi.findRoute", args(&request)).await);
    assert_eq!(search, complete);
    assert_eq!(route.len(), 1, "the hop is found again");
    assert_eq!(route[0].amount_out, out);
}

/// CONFORMANCE §6.39, SoFi Amendment S12: once a trader has traded through a
/// vault, the owner's close still resolves. The owner judges the trader's
/// exercise from the exercise's own bytes: the trader's balance before the
/// trade travels in it, so the owner needs nothing of the trader's.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_vault_traded_through_closes_for_its_owner() {
    let p = Pair::boot(500, 200).await;
    let m = open_market(&p).await;
    set_up(&p.a, &m.vault_id).await;
    let out = dsm::dlv::route_commit::constant_product_output(10, 100, 1_000, 30)
        .expect("the vault prices the trade");
    realized_trade(&p, &m, 10).await;
    assert_eq!(balance(&p.b, &m.tkn), out, "B holds what the trade priced");

    let era_before = balance(&p.a, &m.era);
    let tkn_before = balance(&p.a, &m.tkn);
    realized_through(
        &p.a,
        "sofi.close",
        args(&generated::SofiCloseRequest {
            vault_id: m.vault_id.to_vec(),
        }),
    )
    .await;
    assert_eq!(
        balance(&p.a, &m.era),
        era_before + 110,
        "the vault's ERA: its reserve and all of B's input"
    );
    assert_eq!(
        balance(&p.a, &m.tkn),
        tkn_before + 1_000 - out,
        "and the TKN B did not take"
    );
}

/// SoFi Amendment S16: discovery carries no authority. Under ERA's vault
/// token locator, beside A's real ERA/TKN vault, sit what anyone may append:
/// bytes that are no genesis; the genesis of a vault B claims to own but
/// never created; and the genesis of A's real TKN/TKB vault, which does not
/// trade ERA. B's verifier keeps the one vault of ERA and passes over the
/// rest, and its search is still complete: what it passed over was
/// established, and refuted.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn discovery_passes_over_what_is_not_a_vault_of_the_token() {
    use crate::sdk::storage_node_sdk::SetClient;
    use dsm::common::domain_tags::TAG_DSM_SOFI_VAULT_TOKEN_LOCATOR;
    use dsm::crypto::domain::TaggedHashDomain;
    use dsm::sofi::resolve::VaultGenesis;
    use dsm::sofi::storage::Discovered;

    let p = Pair::boot(500, 200).await;
    let era = era();
    let tkn = create_token(&p.a, "TKN", 10_000).await;
    let tkb = create_token(&p.a, "TKB", 10_000).await;
    let first = create_vault(&p.a, (era, 100), (tkn, 1_000)).await;
    let second = create_vault(&p.a, (tkn, 1_000), (tkb, 1_000)).await;
    let set = canonical_set(NETWORK).expect("the pinned set");
    let client = SetClient::new(&set).expect("a client of the set");
    let index = TAG_DSM_SOFI_VAULT_TOKEN_LOCATOR.source_bytes();
    let era_locator = derive::vault_token_locator(&era);

    let (own, parents) = standing_of(&p.b);
    let ctx = VerifierContext::new(&set, Some(own), parents.as_ref()).expect("a verifier");
    let verifier = ctx.verifier();
    let accepted = |vault: &[u8; 32]| match verifier.vault_genesis(vault).expect("a read") {
        VaultGenesis::Accepted(accepted) => accepted,
        other => panic!("A's vault is accepted, not {other:?}"),
    };

    // Bytes that are no genesis.
    let domain = TaggedHashDomain::try_new(b"DSM/test/not-a-genesis").expect("domain");
    let junk = b"these bytes decode as no vault genesis";
    assert_eq!(client.put_immutable(domain, junk).await, 5);
    let junk_addr = dsm::storage_object::immutable_addr(domain, junk);
    assert_eq!(
        client.append_index(index, &era_locator, &junk_addr).await,
        5
    );

    // A genesis naming B as its owner at a position B's lineage already
    // holds, where B created no vault.
    let real = accepted(&first);
    let forge = |position: u64| {
        let mut forged = real.preimage().clone();
        forged.owner_genesis = p.b.genesis;
        forged.owner_device_id = p.b.device_id;
        forged.create_position = position;
        forged.state.owner_genesis = p.b.genesis;
        forged.state.owner_device_id = p.b.device_id;
        forged.state.create_position = position;
        forged
    };
    let reached = admitted_position(&p.b);
    let forged = forge(reached);
    crate::sdk::sofi_publish::publish(
        &set,
        &Publication::VaultGenesis {
            preimage: &forged,
            market: real.market(),
        },
    )
    .await
    .expect("anyone may publish a genesis");

    // A real vault that does not trade ERA, appended under ERA's locator.
    let other = accepted(&second);
    let other_addr = Publication::VaultGenesis {
        preimage: other.preimage(),
        market: other.market(),
    }
    .address()
    .expect("an address");
    assert_eq!(
        client.append_index(index, &era_locator, &other_addr).await,
        5
    );

    let found = verifier.vaults_of_token(&era).expect("the discovery reads");
    let Discovered::Complete(found) = found else {
        panic!("every candidate was established and refuted or kept: {found:?}")
    };
    assert_eq!(
        found.iter().map(|v| *v.vault_id()).collect::<Vec<_>>(),
        vec![first],
        "the one vault of ERA"
    );
    // The TKN index names both of A's vaults, each a vault of TKN.
    let Discovered::Complete(of_tkn) = verifier.vaults_of_token(&tkn).expect("the discovery reads")
    else {
        panic!("the TKN index was established")
    };
    let mut of_tkn: Vec<_> = of_tkn.iter().map(|v| *v.vault_id()).collect();
    of_tkn.sort();
    let mut both = vec![first, second];
    both.sort();
    assert_eq!(of_tkn, both);

    // A genesis naming a position B's lineage has not reached is not
    // established: B could still create that very vault there. The search
    // says it is partial, and still finds the vault of ERA.
    let ahead = forge(reached + 5);
    crate::sdk::sofi_publish::publish(
        &set,
        &Publication::VaultGenesis {
            preimage: &ahead,
            market: real.market(),
        },
    )
    .await
    .expect("anyone may publish a genesis");
    let Discovered::Partial(found) = verifier.vaults_of_token(&era).expect("the discovery reads")
    else {
        panic!("a candidate the reads cannot decide leaves the discovery partial")
    };
    assert_eq!(
        found.iter().map(|v| *v.vault_id()).collect::<Vec<_>>(),
        vec![first],
        "and the vault of ERA is found all the same"
    );
}

/// Phone-rig rulings, 2026-10-01: a realized trade shows in the wallet at
/// once, and every token and SoFi event writes its history row. B creates a
/// token (its ERA fee leaves a projection behind), then trades through A's
/// vault, which it has never set up with: `balance.list` reports what the
/// head holds without a restart, and B's history names the token's
/// creation, the setup and the trade, each with every token it moved. A's
/// history names the vault's creation, and its close credits both tokens.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_realized_trade_shows_in_balances_and_history_at_once() {
    let p = Pair::boot(500, 200).await;
    let m = open_market_unset(&p).await;
    let tkb = create_token(&p.b, "TKB", 5_000).await;
    let fee = dsm::core::token::TOKEN_CREATION_FEE_ERA;
    assert_eq!(
        listed(&p.b, "ERA").await,
        crate::economic_fixtures::whole_era(200) - fee,
        "the fee shows at once"
    );

    let out = dsm::dlv::route_commit::constant_product_output(10, 100, 1_000, 30)
        .expect("the vault prices the trade");
    realized_trade(&p, &m, 10).await;
    assert_eq!(
        (listed(&p.b, "ERA").await, listed(&p.b, "TKN").await),
        (balance(&p.b, &m.era), balance(&p.b, &m.tkn)),
        "the wallet shows what the head holds"
    );
    assert_eq!(
        listed(&p.b, "ERA").await,
        crate::economic_fixtures::whole_era(200) - 10 - fee
    );
    assert_eq!(listed(&p.b, "TKN").await, out);

    let moves = |row: &generated::TransactionInfo| -> Vec<(Vec<u8>, i64)> {
        row.moves
            .iter()
            .map(|m| (m.policy_commit.clone(), m.amount_signed))
            .collect()
    };
    let of = |rows: &[generated::TransactionInfo], kind: generated::TransactionType| {
        rows.iter()
            .filter(|row| row.tx_type == kind as i32)
            .cloned()
            .collect::<Vec<_>>()
    };
    let b_rows = history_rows(&p.b).await;
    let created = of(&b_rows, generated::TransactionType::TxTypeTokenCreate);
    assert_eq!(created.len(), 1, "B's token creation");
    assert_eq!(
        moves(&created[0]),
        vec![(m.era.to_vec(), -(fee as i64)), (tkb.to_vec(), 5_000)],
        "the fee paid and the supply credited"
    );
    let setup = of(&b_rows, generated::TransactionType::TxTypeSofiSetup);
    assert_eq!(setup.len(), 1, "the setup the trade admitted first");
    assert!(setup[0].moves.is_empty(), "a setup moves no token");
    let traded = of(&b_rows, generated::TransactionType::TxTypeSofiTrade);
    assert_eq!(traded.len(), 1, "the trade");
    let mut trade_moves = moves(&traded[0]);
    trade_moves.sort();
    let mut expected = vec![(m.era.to_vec(), -10), (m.tkn.to_vec(), out as i64)];
    expected.sort();
    assert_eq!(trade_moves, expected, "the ERA paid and the TKN received");
    assert!(
        traded[0].moves.iter().all(|m| !m.display_amount.is_empty()),
        "each movement rendered for display"
    );

    let a_rows = history_rows(&p.a).await;
    let vault = of(&a_rows, generated::TransactionType::TxTypeVaultCreate);
    assert_eq!(vault.len(), 1, "A's vault creation");
    let mut vault_moves = moves(&vault[0]);
    vault_moves.sort();
    let mut paid_in = vec![(m.era.to_vec(), -100), (m.tkn.to_vec(), -1_000)];
    paid_in.sort();
    assert_eq!(vault_moves, paid_in, "both reserves paid in");

    realized_through(
        &p.a,
        "sofi.close",
        args(&generated::SofiCloseRequest {
            vault_id: m.vault_id.to_vec(),
        }),
    )
    .await;
    let closed = of(
        &history_rows(&p.a).await,
        generated::TransactionType::TxTypeSofiClose,
    );
    assert_eq!(closed.len(), 1, "A's close");
    let mut close_moves = moves(&closed[0]);
    close_moves.sort();
    let mut released = vec![
        (m.era.to_vec(), 110),
        (m.tkn.to_vec(), (1_000 - out) as i64),
    ];
    released.sort();
    assert_eq!(close_moves, released, "both reserves credited");
    assert_eq!(
        (listed(&p.a, "ERA").await, listed(&p.a, "TKN").await),
        (balance(&p.a, &m.era), balance(&p.a, &m.tkn)),
        "and the owner's wallet shows them at once"
    );
}

/// SoFi Amendment S19: one order filled through two vaults of the same
/// pair. A opens two ERA/TKN vaults; B, set up with neither, asks for an
/// amount that fills better split across both. The search proposes both
/// vaults, each hop ERA→TKN, the inputs summing to B's amount and giving more
/// than either vault alone; the route sets up with each and realizes, B's ERA
/// is debited the whole amount and its TKN credited the sum, and each vault
/// moved by its own leg — and a walker that is not B (the owner) sees both
/// legs, past B's conditional positions.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn one_order_fills_through_two_vaults_of_the_same_pair() {
    let p = Pair::boot(500, 200).await;
    let era = era();
    let tkn = create_token(&p.a, "TKN", 10_000).await;
    let one = create_vault(&p.a, (era, 100), (tkn, 1_000)).await;
    let two = create_vault(&p.a, (era, 100), (tkn, 1_000)).await;
    adopt(&p.b, &tkn).await;

    let amount = 60;
    let route = match payload(
        &invoke(
            &p.b,
            "sofi.findRoute",
            args(&generated::SofiFindRouteRequest {
                token_in_policy_commit: era.to_vec(),
                token_out_policy_commit: tkn.to_vec(),
                amount_in_entered: entered(&p.b, &era, amount),
            }),
        )
        .await,
    ) {
        Payload::SofiFindRouteResponse(r) => r,
        other => panic!("sofi.findRoute answered {other:?}"),
    };
    let quoted = route.hops.clone();
    assert_eq!(quoted.len(), 2, "split across the two vaults");
    let mut vaults: Vec<Vec<u8>> = quoted.iter().map(|h| h.vault_id.clone()).collect();
    vaults.sort();
    let mut both = vec![one.to_vec(), two.to_vec()];
    both.sort();
    assert_eq!(vaults, both);
    for hop in &quoted {
        assert_eq!(
            (
                hop.token_in_policy_commit.clone(),
                hop.token_out_policy_commit.clone()
            ),
            (era.to_vec(), tkn.to_vec()),
            "every leg trades the one pair"
        );
    }
    assert_eq!(quoted.iter().map(|h| h.amount_in).sum::<u64>(), amount);
    let total: u64 = quoted.iter().map(|h| h.amount_out).sum();
    let alone = dsm::dlv::route_commit::constant_product_output(amount, 100, 1_000, 30)
        .expect("one vault prices the whole amount");
    assert!(
        total > alone,
        "the split gives {total}, one vault alone {alone}"
    );
    assert_eq!(
        (route.shape, route.amount_in, route.amount_out),
        (generated::SofiRouteShape::Split as i32, amount, total),
        "the route is quoted as one split: what it takes and the sum it gives"
    );
    assert_eq!(route.amount_out_display, entered(&p.b, &tkn, total));

    realized_through(
        &p.b,
        "sofi.route",
        args(&generated::SofiRouteRequest {
            vault_ids: quoted.iter().map(|h| h.vault_id.clone()).collect(),
            token_in_policy_commit: era.to_vec(),
            amount_in_entered: entered(&p.b, &era, amount),
            min_amount_out_entered: entered(&p.b, &tkn, total),
            token_out_policy_commit: tkn.to_vec(),
        }),
    )
    .await;
    assert_eq!(setups(&p.b).await, 2, "B set up with each vault first");
    let traded: Vec<_> = history_rows(&p.b)
        .await
        .into_iter()
        .filter(|row| row.tx_type == generated::TransactionType::TxTypeSofiTrade as i32)
        .collect();
    assert_eq!(traded.len(), 1, "one row for the one order");
    let mut named: Vec<&str> = traded[0].recipient.split(", ").collect();
    named.sort_unstable();
    let ids = [
        crate::util::text_id::encode_base32_crockford(&one),
        crate::util::text_id::encode_base32_crockford(&two),
    ];
    let mut both_named: Vec<&str> = ids.iter().map(String::as_str).collect();
    both_named.sort_unstable();
    assert_eq!(
        named, both_named,
        "the row names both vaults the order filled through"
    );
    assert_eq!(
        balance(&p.b, &era),
        crate::economic_fixtures::whole_era(200) - amount,
        "the whole amount paid"
    );
    assert_eq!(balance(&p.b, &tkn), total, "the sum of both legs received");

    let held =
        match payload(&invoke(&p.a, "sofi.vaults", args(&generated::SofiVaultsRequest {})).await) {
            Payload::SofiVaultsResponse(r) => r.vaults,
            other => panic!("sofi.vaults answered {other:?}"),
        };
    for hop in &quoted {
        let vault = held
            .iter()
            .find(|v| v.vault_id == hop.vault_id)
            .expect("the owner lists the vault");
        let (era_reserve, tkn_reserve) = if era < tkn {
            (vault.reserve_a, vault.reserve_b)
        } else {
            (vault.reserve_b, vault.reserve_a)
        };
        assert_eq!(
            (era_reserve, tkn_reserve, vault.generation),
            (100 + hop.amount_in, 1_000 - hop.amount_out, 1),
            "each vault moved by its own leg"
        );
    }
}

/// SoFi §27 (MR-SOFI-0255) as Amendment S16 leaves it: the app reaches SoFi
/// through exactly its eight routes. Each, sent through the production
/// router, reaches its producer and answers with the result §27 names:
/// - `sofi.createVault`: A opens a vault on ERA/TKN and one on TKN/TKB.
/// - `sofi.findRoute`: B, set up with neither, is quoted ERA→TKN→TKB: two
///   hops found through the tokens' indexes, each priced at its vault's head.
/// - `sofi.route`: B takes those two hops, setting up with each vault first,
///   and receives what they priced.
/// - `sofi.relay`: A carries B's route position with nothing from B: the
///   position pair's two cells and each hop's key.
/// - `sofi.trade`: B takes the one hop ERA→TKN at its quote, reusing its
///   setup.
/// - `sofi.close`: A closes its TKN/TKB vault, setting up with it first, and
///   receives both reserves.
/// - `sofi.vaults`: A sees both its vaults at their heads.
/// - `sofi.resolve`: resolves each position its route's own rounds left
///   pending, and with nothing pending its producer refuses.
///
/// A ninth `sofi.` method reaches no SoFi route: the router refuses it, and
/// `sofi.setup` is no longer one.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn every_sofi_route_reaches_its_producer() {
    let p = Pair::boot(500, 200).await;
    let era = era();
    let tkn = create_token(&p.a, "TKN", 10_000).await;
    let tkb = create_token(&p.a, "TKB", 10_000).await;
    let first = create_vault(&p.a, (era, 100), (tkn, 1_000)).await;
    let second = create_vault(&p.a, (tkn, 1_000), (tkb, 1_000)).await;
    assert_eq!(balance(&p.a, &tkn), 8_000, "A funded both vaults' TKN");
    assert_eq!(balance(&p.a, &tkb), 9_000, "and the second's TKB");
    for token in [&tkn, &tkb] {
        adopt(&p.b, token).await;
    }

    let routed = |r: &AppResult| match payload(r) {
        Payload::SofiFindRouteResponse(r) => r,
        other => panic!("sofi.findRoute answered {other:?}"),
    };
    let hops = |r: &AppResult| routed(r).hops;
    let search = |token_out: &[u8; 32]| {
        args(&generated::SofiFindRouteRequest {
            token_in_policy_commit: era.to_vec(),
            token_out_policy_commit: token_out.to_vec(),
            amount_in_entered: entered(&p.b, &era, 10),
        })
    };
    let one = dsm::dlv::route_commit::constant_product_output(10, 100, 1_000, 30)
        .expect("the first vault prices its hop");
    let two = dsm::dlv::route_commit::constant_product_output(one, 1_000, 1_000, 30)
        .expect("the second vault prices its hop");
    let chain = routed(&invoke(&p.b, "sofi.findRoute", search(&tkb)).await);
    assert_eq!(
        (chain.shape, chain.amount_in, chain.amount_out),
        (generated::SofiRouteShape::Chain as i32, 10, two),
        "a chain gives its last hop's output"
    );
    let quoted: Vec<_> = chain
        .hops
        .into_iter()
        .map(|h| {
            (
                h.vault_id,
                h.token_in_policy_commit,
                h.token_out_policy_commit,
                h.amount_in,
                h.amount_out,
            )
        })
        .collect();
    assert_eq!(
        quoted,
        vec![
            (first.to_vec(), era.to_vec(), tkn.to_vec(), 10, one),
            (second.to_vec(), tkn.to_vec(), tkb.to_vec(), one, two),
        ],
        "ERA→TKN→TKB through the two vaults, with no setup behind the quote"
    );
    assert_eq!(setups(&p.b).await, 0, "a quote sets up with nothing");

    let routed = realized_through(
        &p.b,
        "sofi.route",
        args(&generated::SofiRouteRequest {
            vault_ids: vec![first.to_vec(), second.to_vec()],
            token_in_policy_commit: era.to_vec(),
            amount_in_entered: entered(&p.b, &era, 10),
            min_amount_out_entered: entered(&p.b, &tkb, two),
            token_out_policy_commit: tkb.to_vec(),
        }),
    )
    .await;
    assert_eq!(
        setups(&p.b).await,
        2,
        "the route set up with each vault first"
    );
    assert_eq!(
        balance(&p.b, &era),
        crate::economic_fixtures::whole_era(200) - 10,
        "the route took 10 base units"
    );
    assert_eq!(balance(&p.b, &tkb), two, "and gave what its hops priced");
    assert_eq!(balance(&p.b, &tkn), 0, "and kept nothing on the way");

    let relayed = match payload(
        &invoke(
            &p.a,
            "sofi.relay",
            args(&generated::SofiRelayRequest {
                trader_genesis: p.b.genesis.to_vec(),
                trader_device_id: p.b.device_id.to_vec(),
                position: routed,
            }),
        )
        .await,
    ) {
        Payload::SofiRelayResponse(r) => r.cells_written,
        other => panic!("sofi.relay answered {other:?}"),
    };
    assert_eq!(
        relayed, 4,
        "the position pair's two cells and both hops' keys"
    );

    let quote = hops(&invoke(&p.b, "sofi.findRoute", search(&tkn)).await);
    assert_eq!(quote.len(), 1, "one hop ERA→TKN");
    let bought = quote[0].amount_out;
    realized_through(
        &p.b,
        "sofi.trade",
        args(&generated::SofiTradeRequest {
            vault_id: first.to_vec(),
            token_in_policy_commit: era.to_vec(),
            amount_in_entered: entered(&p.b, &era, 10),
            min_amount_out_entered: entered(&p.b, &tkn, bought),
            token_out_policy_commit: tkn.to_vec(),
        }),
    )
    .await;
    assert_eq!(setups(&p.b).await, 2, "the trade reused its setup");
    assert_eq!(
        balance(&p.b, &era),
        crate::economic_fixtures::whole_era(200) - 20,
        "the trade took 10 more"
    );
    assert_eq!(balance(&p.b, &tkn), bought, "and gave what it was quoted");

    realized_through(
        &p.a,
        "sofi.close",
        args(&generated::SofiCloseRequest {
            vault_id: second.to_vec(),
        }),
    )
    .await;
    assert_eq!(setups(&p.a).await, 1, "the owner's close set up first");
    assert_eq!(
        balance(&p.a, &tkb),
        10_000 - two,
        "the close released every TKB B does not hold"
    );
    assert_eq!(
        balance(&p.a, &tkn),
        8_000 + 1_000 + one,
        "and the vault's TKN: its reserve and the first hop's output"
    );

    let vaults =
        match payload(&invoke(&p.a, "sofi.vaults", args(&generated::SofiVaultsRequest {})).await) {
            Payload::SofiVaultsResponse(r) => r.vaults,
            other => panic!("sofi.vaults answered {other:?}"),
        };
    let seen: BTreeMap<Vec<u8>, (u64, u64, u64, i32)> = vaults
        .into_iter()
        .map(|v| {
            (
                v.vault_id,
                (v.reserve_a, v.reserve_b, v.generation, v.status),
            )
        })
        .collect();
    let first_reserves = if era < tkn {
        (100 + 20, 1_000 - one - bought)
    } else {
        (1_000 - one - bought, 100 + 20)
    };
    assert_eq!(
        seen,
        BTreeMap::from([
            (
                first.to_vec(),
                (
                    first_reserves.0,
                    first_reserves.1,
                    2,
                    generated::SofiVaultStatus::Active as i32
                )
            ),
            (
                second.to_vec(),
                (0, 0, 2, generated::SofiVaultStatus::Retired as i32)
            ),
        ]),
        "A's two vaults at their heads: the first traded through twice, the second closed"
    );

    let nothing_pending = invoke(
        &p.b,
        "sofi.resolve",
        args(&generated::SofiResolveRequest {}),
    )
    .await;
    let Some(refusal) = nothing_pending.error_message else {
        panic!(
            "a resolve with nothing pending answered {:?}",
            nothing_pending.data
        )
    };
    assert!(
        refusal.starts_with("sofi.resolve: ")
            && refusal.contains("no pending admission: nothing to resolve"),
        "sofi.resolve's producer refuses: {refusal}"
    );

    let unknown = invoke(&p.b, "sofi.quote", args(&generated::SofiResolveRequest {})).await;
    let Some(refusal) = unknown.error_message else {
        panic!("sofi.quote answered {:?}", unknown.data)
    };
    assert!(
        refusal.starts_with("unknown invoke method: 'sofi.quote'"),
        "the router refuses a method that is no SoFi route: {refusal}"
    );
}

/// The reads of a live verifier, counting the owner lineages it walks and
/// the genesis locators it scans. Every read is the live one.
struct CountingReads<'a> {
    live: &'a crate::sdk::sofi_reads::LiveSofiReads<'a>,
    owner_walks: std::sync::atomic::AtomicUsize,
    genesis_scans: std::sync::atomic::AtomicUsize,
}

impl CountingReads<'_> {
    fn counts(&self) -> (usize, usize) {
        use std::sync::atomic::Ordering::SeqCst;
        (
            self.owner_walks.load(SeqCst),
            self.genesis_scans.load(SeqCst),
        )
    }
}

impl dsm::sofi::resolve::SofiReads for CountingReads<'_> {
    fn cell(
        &self,
        cell: &dsm::route_chain::RoutedCell,
    ) -> Result<dsm::route_chain::CellEvidence, dsm::sofi::resolve::ReadFailure> {
        self.live.cell(cell)
    }
    fn precommit(
        &self,
        id: &[u8; 32],
    ) -> Result<
        dsm::sofi::storage::Resolved<
            dsm::sofi::publication::Signed<dsm::sofi::wire::TraderPrecommitBody>,
        >,
        dsm::sofi::resolve::ReadFailure,
    > {
        self.live.precommit(id)
    }
    fn fulfillment(
        &self,
        id: &[u8; 32],
    ) -> Result<
        dsm::sofi::storage::Resolved<
            dsm::sofi::publication::Signed<dsm::sofi::wire::TraderFulfillmentBody>,
        >,
        dsm::sofi::resolve::ReadFailure,
    > {
        self.live.fulfillment(id)
    }
    fn setup_bytes(
        &self,
        setup_ref: &[u8; 32],
    ) -> Result<dsm::sofi::storage::Resolved<Vec<u8>>, dsm::sofi::resolve::ReadFailure> {
        self.live.setup_bytes(setup_ref)
    }
    fn stored_bytes(
        &self,
        addr: &[u8; 32],
    ) -> Result<Option<Vec<u8>>, dsm::sofi::resolve::ReadFailure> {
        self.live.stored_bytes(addr)
    }
    fn token_policy_bytes(
        &self,
        policy_commit: &[u8; 32],
    ) -> Result<Vec<u8>, dsm::sofi::resolve::ReadFailure> {
        self.live.token_policy_bytes(policy_commit)
    }
    fn vault_genesis_candidates(
        &self,
        vault_id: &[u8; 32],
    ) -> Result<
        dsm::sofi::storage::Discovered<(dsm::sofi::wire::VaultGenesisPreimage, Vec<u8>)>,
        dsm::sofi::resolve::ReadFailure,
    > {
        self.genesis_scans
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.live.vault_genesis_candidates(vault_id)
    }
    fn vault_token_candidates(
        &self,
        token: &[u8; 32],
    ) -> Result<dsm::sofi::storage::Discovered<[u8; 32]>, dsm::sofi::resolve::ReadFailure> {
        self.live.vault_token_candidates(token)
    }
    fn vault_owner(
        &self,
        genesis: &[u8; 32],
        device_id: &[u8; 32],
        position: u64,
    ) -> Result<
        dsm::economic::provenance::ValidatedPeerTransition,
        dsm::economic::provenance::PeerLineageFailure,
    > {
        self.owner_walks
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.live.vault_owner(genesis, device_id, position)
    }
    fn vault_leaves_at(
        &self,
        vault_id: &[u8; 32],
        root: &[u8; 32],
        keys: &std::collections::BTreeSet<[u8; 32]>,
    ) -> Result<Option<dsm::sofi::resolve::VaultLeaves>, dsm::sofi::resolve::ReadFailure> {
        self.live.vault_leaves_at(vault_id, root, keys)
    }
    fn trader_root_at(
        &self,
        genesis: &[u8; 32],
        device_id: &[u8; 32],
        position: u64,
    ) -> Result<
        (
            dsm::economic::lineage::ValidatedEconomicRoot,
            dsm::sofi::wire::ParentClaimRef,
        ),
        dsm::economic::provenance::PeerLineageFailure,
    > {
        self.live.trader_root_at(genesis, device_id, position)
    }
    fn accepted_claim_at(
        &self,
        genesis: &[u8; 32],
        device_id: &[u8; 32],
        position: u64,
    ) -> Result<dsm::economic::lineage::AcceptedClaim, dsm::economic::provenance::PeerLineageFailure>
    {
        self.live.accepted_claim_at(genesis, device_id, position)
    }
    fn recorded_generations(
        &self,
        vault_id: &[u8; 32],
    ) -> Result<Vec<dsm::sofi::resolve::RecordedGenerationRow>, dsm::sofi::resolve::ReadFailure>
    {
        self.live.recorded_generations(vault_id)
    }
    fn record_generation(
        &self,
        post: &dsm::sofi::validation::VaultPostState,
    ) -> Result<(), dsm::sofi::resolve::ReadFailure> {
        self.live.record_generation(post)
    }
    fn keep_completion(
        &self,
        cell: &dsm::route_chain::RoutedCell,
        evidence: &dsm::route_chain::CellEvidence,
        proof: &dsm::route_chain::CompletionProof,
    ) -> Result<(), dsm::sofi::resolve::ReadFailure> {
        self.live.keep_completion(cell, evidence, proof)
    }
}

/// A quote's verifiers read a vault's genesis from the network once. The
/// rig's quote took minutes because discovery under each of the pair's
/// tokens, the chain and the head each read the genesis again: a scan of its
/// locator and a walk of its owner's lineage every time. B discovers A's
/// vault under ERA and under TKN, walks its chain, and asks for its genesis
/// once more; the owner's lineage is walked once, the locator is read each
/// time, and the vault is still found under both tokens.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_request_reads_each_vaults_genesis_once() {
    let p = Pair::boot(500, 200).await;
    let m = open_market_unset(&p).await;
    p.b.enter();
    let set = canonical_set(NETWORK).expect("the pinned set");
    let live = crate::sdk::sofi_reads::LiveSofiReads::new(&set, None).expect("live reads");
    let reads = CountingReads {
        live: &live,
        owner_walks: std::sync::atomic::AtomicUsize::new(0),
        genesis_scans: std::sync::atomic::AtomicUsize::new(0),
    };
    let members = crate::sdk::storage_set::as_ccb_members(&set).expect("the set's members");
    let network = crate::sdk::economic_admission_flow::committed_network_id().expect("network");
    let verifier = dsm::sofi::resolve::Verifier::new(
        &reads,
        &members,
        set.id(),
        &network,
        None,
        dsm::sofi::resolve::AcceptedGeneses::default(),
    );
    let found = |token: &[u8; 32]| match verifier.vaults_of_token(token) {
        Ok(dsm::sofi::storage::Discovered::Complete(vaults)) => {
            vaults.iter().map(|v| *v.vault_id()).collect::<Vec<_>>()
        }
        other => panic!("discovery under a token: {other:?}"),
    };
    assert_eq!(found(&m.era), vec![m.vault_id], "found under ERA");
    assert_eq!(found(&m.tkn), vec![m.vault_id], "and under TKN");
    let chain = verifier.chain(&m.vault_id).expect("the vault's chain");
    assert!(chain.head().is_some(), "walked to its head");
    assert!(matches!(
        verifier.vault_genesis(&m.vault_id),
        Ok(dsm::sofi::resolve::VaultGenesis::Accepted(..))
    ));
    assert_eq!(
        reads.counts(),
        (1, 4),
        "one walk of the owner's lineage; the genesis locator read each time it was asked"
    );
}

/// One operation's verifiers share the vault geneses it accepted, and a new
/// operation's do not. On the rig a trade built three contexts — the check,
/// the plan at the heads, the settle — and each walked both vault owners'
/// lineages from activation: two minutes of a four-and-a-half-minute trade.
/// Two verifiers sharing one operation's memo walk the owner's lineage once
/// and read the genesis locator each time; a verifier of a new operation
/// walks it again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn an_operations_verifiers_share_the_geneses_it_accepted() {
    let p = Pair::boot(500, 200).await;
    let m = open_market_unset(&p).await;
    p.b.enter();
    let set = canonical_set(NETWORK).expect("the pinned set");
    let live = crate::sdk::sofi_reads::LiveSofiReads::new(&set, None).expect("live reads");
    let reads = CountingReads {
        live: &live,
        owner_walks: std::sync::atomic::AtomicUsize::new(0),
        genesis_scans: std::sync::atomic::AtomicUsize::new(0),
    };
    let members = crate::sdk::storage_set::as_ccb_members(&set).expect("the set's members");
    let network = crate::sdk::economic_admission_flow::committed_network_id().expect("network");
    let verifier = |accepted: &dsm::sofi::resolve::AcceptedGeneses| {
        dsm::sofi::resolve::Verifier::new(
            &reads,
            &members,
            set.id(),
            &network,
            None,
            accepted.clone(),
        )
    };
    let accepted_by = |v: &dsm::sofi::resolve::Verifier<'_, CountingReads<'_>>| {
        matches!(
            v.vault_genesis(&m.vault_id),
            Ok(dsm::sofi::resolve::VaultGenesis::Accepted(..))
        )
    };
    let operation = dsm::sofi::resolve::AcceptedGeneses::default();
    assert!(accepted_by(&verifier(&operation)), "the check");
    assert!(accepted_by(&verifier(&operation)), "the settle");
    assert_eq!(
        reads.counts(),
        (1, 2),
        "one operation: the owner's lineage walked once, the locator read twice"
    );
    assert!(accepted_by(&verifier(
        &dsm::sofi::resolve::AcceptedGeneses::default()
    )));
    assert_eq!(
        reads.counts(),
        (2, 3),
        "a new operation walks the owner's lineage again"
    );
}

/// One resolution asks each node once for a cell holding a final value, an
/// index or an object. On the rig one settle read 33 cells, 6 of them
/// distinct: the walk of each leg's vault and the facts it established
/// re-read what the resolution had read already, the precommit was fetched
/// twice, each step of the vault owner's lineage fetched again an object the
/// steps share, and each vault's genesis locator was scanned four times. A
/// cell still open is read again each time it is asked for — anyone may
/// write it meanwhile — and here those are each vault's next key.
///
/// B's order is split across two vaults A opened one after the other, so
/// its resolution walks A's lineage twice — to the position each vault was
/// opened at — over the same cells and objects below the first. B's first
/// order realizes and sets it up with both; its second is left pending —
/// its position pair's leader refuses the pair — then the pair lands and
/// the fulfillment completes. One resolution of it realizes the position and
/// asks no node twice for anything but an open key.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn one_resolution_asks_each_node_for_a_final_cell_or_an_object_once() {
    let p = Pair::boot(500, 200).await;
    let era = era();
    let tkn = create_token(&p.a, "TKN", 10_000).await;
    let one = create_vault(&p.a, (era, 100), (tkn, 1_000)).await;
    let two = create_vault(&p.a, (era, 100), (tkn, 1_000)).await;
    adopt(&p.b, &tkn).await;
    let split = |amount: u64| {
        let b = &p.b;
        async move {
            let hops = match payload(
                &invoke(
                    b,
                    "sofi.findRoute",
                    args(&generated::SofiFindRouteRequest {
                        token_in_policy_commit: era.to_vec(),
                        token_out_policy_commit: tkn.to_vec(),
                        amount_in_entered: entered(b, &era, amount),
                    }),
                )
                .await,
            ) {
                Payload::SofiFindRouteResponse(r) => r.hops,
                other => panic!("sofi.findRoute answered {other:?}"),
            };
            let mut vaults: Vec<Vec<u8>> = hops.iter().map(|h| h.vault_id.clone()).collect();
            vaults.sort();
            let mut both = vec![one.to_vec(), two.to_vec()];
            both.sort();
            assert_eq!(vaults, both, "the order splits across A's two vaults");
            args(&generated::SofiRouteRequest {
                vault_ids: hops.iter().map(|h| h.vault_id.clone()).collect(),
                token_in_policy_commit: era.to_vec(),
                amount_in_entered: entered(b, &era, amount),
                min_amount_out_entered: entered(b, &tkn, 1),
                token_out_policy_commit: tkn.to_vec(),
            })
        }
    };
    realized_through(&p.b, "sofi.route", split(60).await).await;
    assert_eq!(setups(&p.b).await, 2, "B set up with both vaults");

    let set = canonical_set(NETWORK).expect("the pinned set");
    let exhausted = generated::SofiPositionState::RetriesExhausted as i32;
    let q = admitted_position(&p.b) + 1;
    let (.., root) = {
        p.b.enter();
        economic_lineage::get_admitted_coordinate()
            .expect("read admitted")
            .expect("an admitted position")
    };
    let pair = position_cells(&set, &p.b.genesis, &p.b.device_id, q, &root)
        .expect("B's next position pair");
    let pair_leader = member_name(pair.fulfillment().route().leader());
    p.nodes
        .refuse_cell_writes(
            &pair_leader,
            &[*pair.fulfillment().key(), *pair.root().routed().key()],
        )
        .await;
    let r = invoke(&p.b, "sofi.route", split(60).await).await;
    assert_eq!(position_of(&r, "sofi.route"), (q, exhausted));
    p.nodes.accept_cell_writes(&pair_leader).await;
    assert!(matches!(complete(&p).await, Completion::Written(..)));

    for node in &p.nodes.nodes {
        node.forget_requests();
    }
    p.b.enter();
    let advanced = crate::sdk::sofi_advance::resolve_pending_position(
        &p.b.router().core_sdk,
        &set,
        &dsm::sofi::resolve::AcceptedGeneses::default(),
    )
    .await
    .expect("the resolution");
    assert!(
        matches!(
            advanced,
            crate::sdk::sofi_advance::Advanced::Installed {
                resolution: dsm::sofi::resolution::Resolution::Realized,
                ..
            }
        ),
        "one resolution realizes the position: {advanced:?}"
    );
    let asked: Vec<(String, BTreeMap<String, usize>)> = p
        .nodes
        .nodes
        .iter()
        .map(|node| {
            let mut asked: BTreeMap<String, usize> = BTreeMap::new();
            for request in node.requests() {
                if [
                    "GET /api/v2/cell/",
                    "GET /api/v2/immutable/",
                    "GET /api/v2/index/",
                ]
                .iter()
                .any(|read| request.starts_with(read))
                {
                    *asked.entry(request).or_insert(0) += 1;
                }
            }
            (node.member_id.clone(), asked)
        })
        .collect();

    // Each vault's next key: the first attempt key at the generation this
    // position's exercise produced, open, as a verifier that has read
    // nothing yet finds it.
    let (own, parents) = standing_of(&p.b);
    let reading = VerifierContext::new(&set, Some(own), parents.as_ref()).expect("a verifier");
    let verifier = reading.verifier();
    let mut open = Vec::new();
    for vault_id in [one, two] {
        let chain = verifier.chain(&vault_id).expect("the vault's chain");
        let head = *chain.roots().last().expect("the vault's head");
        assert_eq!(
            verifier
                .read_attempt_cell(&vault_id, &head, 0)
                .expect("read")
                .expect("decided")
                .fact(),
            CellFact::Open,
            "the vault's next key is open"
        );
        let next = attempt_cell(&set, &vault_id, &head, 0).expect("the next key");
        open.push(format!(
            "GET /api/v2/cell/{}",
            crate::util::text_id::encode_base32_crockford(next.routed().key())
        ));
    }
    for (member, asked) in &asked {
        let again: Vec<_> = asked
            .iter()
            .filter(|(request, times)| **times > 1 && !open.contains(request))
            .collect();
        assert!(
            again.is_empty(),
            "{member} was asked again for what the resolution had read: {again:?}"
        );
    }
}
