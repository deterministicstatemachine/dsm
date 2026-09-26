// SPDX-License-Identifier: MIT OR Apache-2.0

//! End-to-end tests on storage nodes (owner, 2026-09-23: no fakes).
//!
//! Every test runs two devices through the production handlers against the
//! pinned set's nodes on Postgres (`test_support::nodes`), and checks outcomes where they
//! live: balances in each device's canonical state, and what each node holds
//! in its own database.

use std::collections::BTreeMap;

use dsm::economic::lineage::{AdmittedEconomicPosition, ValidatedEconomicRoot};
use dsm::route_chain::{CellFact, ChainState};
use dsm::sofi::conformance::{
    conformance_invalid_in_hand, derive_policy_fulfillments, FulfillmentConformanceError,
};
use dsm::sofi::derive;
use dsm::sofi::exercise::{recognize_exercise, RecognizedExercise};
use dsm::sofi::publication::Publication;
use dsm::sofi::resolution::WalkOutcome;
use dsm::sofi::resolve::{LocalLeaves, WALK_BUDGET};
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
use crate::sdk::sofi_reads::{local_leaves_of_validated, VerifierContext};
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

/// A creates the token and the vault (100 ERA against 1000 TKN at 30 bps);
/// B adopts the token and sets up. Adoption precedes receipt (owner ruling
/// 2026-09-13): the trader adds TKN before it can receive any.
async fn open_market(p: &Pair) -> Market {
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
    let vault_id: [u8; 32] = vault_id
        .as_slice()
        .try_into()
        .expect("a vault id is 32 bytes");
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
                vault_id: vault_id.to_vec(),
            }),
        )
        .await,
    );
    Market { vault_id, era, tkn }
}

fn trade_request(m: &Market, amount_in: u64) -> generated::SofiTradeRequest {
    generated::SofiTradeRequest {
        vault_id: m.vault_id.to_vec(),
        token_in_policy_commit: m.era.to_vec(),
        amount_in,
        min_amount_out: 1,
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

/// B trades `amount_in` ERA in the market and the position resolves
/// Realized, through `sofi.resolve` if the trade's own rounds did not get
/// there. The position.
async fn realized_trade(p: &Pair, m: &Market, amount_in: u64) -> u64 {
    let realized = generated::SofiPositionState::Realized as i32;
    let (position, state) = position_of(
        &invoke(&p.b, "sofi.trade", args(&trade_request(m, amount_in))).await,
        "sofi.trade",
    );
    if state == realized {
        return position;
    }
    let (resolved, state) = resolve(p).await;
    assert_eq!((resolved, state), (position, realized));
    position
}

/// What a device stands on for a resolution, as `sofi_advance` assembles it:
/// its own leaves at its validated predecessor, and the conditional position
/// it resolved, if that is what it stands on.
fn standing_of(d: &TestDevice) -> (LocalLeaves, Option<AdmittedEconomicPosition>) {
    d.enter();
    let admitted = economic_lineage::get_admitted()
        .expect("read admitted")
        .expect("an admitted position");
    let validated = ValidatedEconomicRoot::rehydrate_from_admitted_store(admitted)
        .expect("a resolved predecessor");
    let local =
        local_leaves_of_validated(&d.genesis, &d.device_id, &validated).expect("own leaves");
    // The position this device resolved itself, for Core to read what it
    // selected when a P names it as its parent.
    let parent =
        matches!(admitted, AdmittedEconomicPosition::ResolvedSofi { .. }).then_some(admitted);
    (local, parent)
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
    // The vault priced the trade at its reserves: 10 ERA in against 100 ERA
    // and 1000 TKN, at 30 bps.
    let out = dsm::dlv::route_commit::constant_product_output(10, 100, 1_000, 30)
        .expect("the vault prices the trade");
    assert_eq!(balance(&p.b, &m.era), 190, "the trader paid 10 ERA");
    assert_eq!(
        balance(&p.b, &m.tkn),
        out,
        "the trader received what the vault priced"
    );
    head_agrees_with_admitted_root(&p.b, &[m.era, m.tkn]);
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
    let p = &honest.precommit.body;
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
    let canonical = derive::canonical_legs(&honest.preimage).expect("P(E) derives its legs");
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
    let f = &honest.fulfillment.body;
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
        honest.preimage.encode().expect("P(E) bytes"),
        witnesses
            .iter()
            .map(DlvPolicyFulfillmentBody::encode)
            .collect(),
        honest.closure.clone(),
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
    let (local, parents) = standing_of(&p.b);
    let ctx = VerifierContext::new(&set, Some(&local), parents.as_ref()).expect("a verifier");
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
        &recognized.precommit,
        &recognized.fulfillment.body,
        &recognized.fulfillment.signature,
        &recognized.preimage,
        &recognized.closure,
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
            id: recognized.external_commitment,
            state: ChainState::Final,
        },
        "the re-aimed exercise holds the next generation's first key, final"
    );

    // The walk at the next generation, with every node's request log cleared.
    for node in &p.nodes.nodes {
        node.forget_requests();
    }
    let chains = BTreeMap::from([(m.vault_id, chain)]);
    let walked = verifier
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
    assert_eq!(next.fulfillment.body.position(), q2);
    assert_eq!(next.fulfillment.body.attempts()[0].attempt, 1);
    let out2 = dsm::dlv::route_commit::constant_product_output(10, 110, 1_000 - out1, 30)
        .expect("the vault prices the second trade");
    assert_eq!(balance(&p.b, &m.era), 180);
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
    let (local, parents) = standing_of(&p.b);
    let ctx = VerifierContext::new(&set, Some(&local), parents.as_ref()).expect("a verifier");
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
    assert_eq!(second.fulfillment.body.position(), q2);
    assert_eq!(balance(&p.b, &m.era), 180);
    head_agrees_with_admitted_root(&p.b, &[m.era, m.tkn]);
}

/// B's own completion of its pending position, stages 7 and 8 from what
/// storage holds: what the network took, or what it did not.
async fn complete(p: &Pair) -> Completion {
    let set = canonical_set(NETWORK).expect("the pinned set");
    p.b.enter();
    complete_pending_fulfillment(&p.b.router().core_sdk, &set)
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
    let (local, parents) = standing_of(&p.b);
    let ctx = VerifierContext::new(&set, Some(&local), parents.as_ref()).expect("a verifier");
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
    let r = invoke(&p.b, "sofi.trade", args(&trade_request(&m, 10))).await;
    assert_eq!(position_of(&r, "sofi.trade"), (q, exhausted));
    assert_eq!(pending_position(&p.b), Some(q));
    assert_eq!(admitted_position(&p.b), position);
    assert_eq!(balance(&p.b, &m.era), 200);
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
    assert_eq!(balance(&p.b, &m.era), 200);
    assert_eq!(balance(&p.b, &m.tkn), 0);

    // 3. Every write lands: completion is written and the position realizes.
    p.nodes.accept_cell_writes(&attempt_leader).await;
    assert!(matches!(complete(&p).await, Completion::Written(..)));
    assert_eq!(resolve(&p).await, (q, realized));
    assert_eq!(pending_position(&p.b), None);
    assert_eq!(admitted_position(&p.b), q);
    let out = dsm::dlv::route_commit::constant_product_output(10, 100, 1_000, 30)
        .expect("the vault prices the trade");
    assert_eq!(balance(&p.b, &m.era), 190);
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

/// SoFi §30 and storage §4: a route search that cannot establish the head of
/// a vault this device is set up with is an error, not a search that found no
/// route. B, set up with A's vault, is quoted one hop ERA→TKN at the vault's
/// head; with the fleet below quorum the head cannot be established and the
/// search is refused rather than answered empty; with the fleet back, the one
/// hop again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_route_search_that_cannot_see_a_vault_is_an_error_not_an_empty_route() {
    let mut p = Pair::boot(500, 200).await;
    let m = open_market(&p).await;
    let request = generated::SofiFindRouteRequest {
        token_in_policy_commit: m.era.to_vec(),
        token_out_policy_commit: m.tkn.to_vec(),
        amount_in: 10,
    };
    let hops = |r: &AppResult| match payload(r) {
        Payload::SofiFindRouteResponse(r) => r.hops,
        other => panic!("sofi.findRoute answered {other:?}"),
    };
    let out = dsm::dlv::route_commit::constant_product_output(10, 100, 1_000, 30)
        .expect("the vault prices the hop");
    let route = hops(&invoke(&p.b, "sofi.findRoute", args(&request)).await);
    assert_eq!(route.len(), 1, "one hop through A's vault");
    assert_eq!(route[0].vault_id, m.vault_id.to_vec());
    assert_eq!((route[0].amount_in, route[0].amount_out), (10, out));

    let down = crate::economic_fixtures::members_to_break_quorum();
    p.nodes.take_down(&down).await;
    let refused = invoke(&p.b, "sofi.findRoute", args(&request)).await;
    assert!(
        !refused.success,
        "a search that could not see the vault answered {:?}",
        refused.data
    );

    p.nodes.bring_up(&down).await;
    let route = hops(&invoke(&p.b, "sofi.findRoute", args(&request)).await);
    assert_eq!(route.len(), 1, "the hop is found again");
    assert_eq!(route[0].amount_out, out);
}
