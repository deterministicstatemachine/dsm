// SPDX-License-Identifier: MIT OR Apache-2.0

//! A computed match staked and played through DSM Connect (SoFi Amendment
//! S22), on storage nodes.
//!
//! Three devices on the pinned set's nodes: R is a game's own account, A and
//! B are two players' wallets, each connected to R under a grant holding a
//! duel scope: ERA stakes up to a cap, in matches decided by the
//! `wildstate-duel` program. R asks each wallet for its session key, builds
//! the setup, and asks each to lock, to ready, to sign each of its moves, to
//! settle and to collect. Every one of those runs under the grant without the
//! player. R relays only what the wallets answered, and counts each lock, the
//! Start, the settlement and the collection only from the cells and vaults its
//! own account reads.

use dsm::sofi::computed;
use dsm::sofi::wire::{EntryKind, MatchSide, TranscriptEntry};
use dsm::types::proto as generated;
use generated::connect_app_request_intent_v1::Kind;
use generated::app_response_body_v1::Result as Answer;
use generated::connect_reply_v1::Reply;
use prost::Message;
use serial_test::serial;

use super::computed_escrow_e2e_tests::{frozen, salt, setup_with_keys};
use super::connect_e2e_tests::{
    args_raw, carried_out, fact, reply, request, status, wallet_log, ForwardRelay,
};
use super::node_e2e_tests::{args, balance, era, invoke};
use crate::economic_fixtures::whole_era;
use crate::test_support::two_device::{Pair, TestDevice};

type D32 = [u8; 32];

async fn game(p: &Pair) -> TestDevice {
    let mut r = TestDevice::create("R", 0x0C);
    r.boot(&p.fleet).await;
    r
}

/// R's offer: a duel scope staking up to 30 ERA a time and 60 ERA in all, in
/// matches the registered `wildstate-duel` decides.
async fn offer(r: &TestDevice, relay: &ForwardRelay) -> String {
    let made = invoke(
        r,
        "connect.app.offer",
        args(&generated::ConnectAppOfferRequestV1 {
            display_name: "Wildstate".into(),
            endpoint: relay.endpoint.clone(),
            cert_pin: relay.pin.to_vec(),
            scopes: vec![generated::ConnectScopeV1 {
                kind: generated::ConnectScopeKind::Duel as i32,
                policy_commits: Vec::new(),
                caps: vec![generated::ConnectCapV1 {
                    policy_commit: era().to_vec(),
                    per_request: whole_era(30),
                    total: whole_era(60),
                }],
                programs: vec![wildstate_duel::program_hash().to_vec()],
            }],
            token_anchors: Vec::new(),
        }),
    )
    .await;
    let Reply::Offer(offer) = reply(&made) else {
        panic!("connect.app.offer answered another reply");
    };
    let digest: D32 = offer.offer_digest.as_slice().try_into().expect("a digest");
    relay.held().offer = Some((digest, offer.offer.clone()));
    offer.code
}

async fn connect(r: &TestDevice, wallet: &TestDevice, relay: &ForwardRelay, code: &str) -> D32 {
    let previewed = super::connect_e2e_tests::query(
        wallet,
        "connect.preview",
        args(&generated::ConnectPreviewRequestV1 { code: code.into() }),
    )
    .await;
    let Reply::Preview(preview) = reply(&previewed) else {
        panic!("connect.preview answered another reply");
    };
    assert_eq!(preview.scope_lines.len(), 1);
    assert!(
        preview.scope_lines[0].starts_with(
            "Stake up to 30.00 ERA a time, 60.00 ERA in all, in battles decided by program \
             wildstate-duel v1 ("
        ),
        "{}",
        preview.scope_lines[0]
    );
    let approved = invoke(
        wallet,
        "connect.approve",
        args(&generated::ConnectApproveRequestV1 {
            offer_digest: preview.offer_digest.clone(),
            granted: Vec::new(),
        }),
    )
    .await;
    let Reply::Session(wallet_side) = reply(&approved) else {
        panic!("connect.approve answered another reply");
    };
    let accept = relay
        .held()
        .accepts
        .pop()
        .expect("the wallet posted its accept");
    let Reply::Session(_) = reply(&invoke(r, "connect.app.accept", args_raw(accept)).await) else {
        panic!("connect.app.accept answered another reply");
    };
    wallet_side
        .session_id
        .as_slice()
        .try_into()
        .expect("a session id")
}

/// R asks `wallet` for `kind`; the wallet syncs and carries it out under its
/// grant; R takes the answer. What R's account then establishes.
async fn ask(
    r: &TestDevice,
    wallet: &TestDevice,
    relay: &ForwardRelay,
    sid: &D32,
    kind: Kind,
) -> generated::ConnectAppStatusV1 {
    let seq = request(r, relay, sid, kind).await;
    let Reply::Sessions(synced) = reply(&invoke(wallet, "connect.sync", Vec::new()).await) else {
        panic!("connect.sync answered another reply");
    };
    for s in &synced.sessions {
        assert_eq!(s.last_error, "", "the sync did not complete");
    }
    let answers = std::mem::take(&mut relay.held().responses);
    for answer in answers {
        reply(&invoke(r, "connect.app.respond", args_raw(answer)).await);
    }
    carried_out(wallet, sid, seq).await;
    status(r, sid, seq).await
}

/// R relays one entry: `wallet` signs it after `preceding`. The signed entry.
async fn play(
    r: &TestDevice,
    wallet: &TestDevice,
    relay: &ForwardRelay,
    sid: &D32,
    cell: &D32,
    preceding: &[generated::ConnectDuelSignedEntryV1],
    entry: Vec<u8>,
) -> generated::ConnectDuelSignedEntryV1 {
    let s = ask(
        r,
        wallet,
        relay,
        sid,
        Kind::DuelSign(generated::ConnectDuelSignV1 {
            match_cell: cell.to_vec(),
            preceding: preceding.to_vec(),
            entry: entry.clone(),
        }),
    )
    .await;
    let Answer::DuelSign(signed) = answered(&s) else {
        panic!("the wallet answered another result");
    };
    generated::ConnectDuelSignedEntryV1 {
        entry,
        signature: signed.signature,
    }
}

/// The result the wallet answered with, read from its signed answer body.
fn answered(s: &generated::ConnectAppStatusV1) -> Answer {
    generated::AppResponseBodyV1::decode(s.answer_body.as_slice())
        .expect("the wallet's answer")
        .result
        .expect("a result")
}

fn entry(index: u32, side: MatchSide, kind: EntryKind) -> Vec<u8> {
    TranscriptEntry::new(index, side, kind)
        .expect("an entry")
        .encode()
}

/// The game stakes, starts and plays a match through both grants; B resigns
/// after a turn, A settles, and A collects both stakes. R establishes each
/// lock, the Start, the outcome and the collection from DSM itself.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_match_decided_by_the_program_is_played_and_paid_through_the_grant() {
    let p = Pair::boot(100, 100).await;
    let r = game(&p).await;
    let relay = ForwardRelay::start().await;
    let code = offer(&r, &relay).await;
    let sid_a = connect(&r, &p.a, &relay, &code).await;
    let sid_b = connect(&r, &p.b, &relay, &code).await;
    let stake = whole_era(25);
    let nonce = [0x41; 32];

    let key = |s: generated::ConnectAppStatusV1| match answered(&s) {
        Answer::DuelSessionKey(k) => k.session_public_key,
        other => panic!("the wallet answered {other:?}"),
    };
    let session_key = Kind::DuelSessionKey(generated::ConnectDuelSessionKeyV1 {
        match_nonce: nonce.to_vec(),
    });
    let key_a = key(ask(&r, &p.a, &relay, &sid_a, session_key.clone()).await);
    let key_b = key(ask(&r, &p.b, &relay, &sid_b, session_key).await);
    let setup = setup_with_keys(&p.a, &p.b, nonce, &key_a, &key_b);

    let lock = |side: u32, opponent: &TestDevice, counterpart: Vec<u8>| {
        Kind::DuelLock(generated::ConnectDuelLockV1 {
            setup: setup.clone(),
            side,
            policy_commit: era().to_vec(),
            amount: stake,
            opponent_genesis: opponent.genesis.to_vec(),
            opponent_device_id: opponent.device_id.to_vec(),
            counterpart_vault_id: counterpart,
            memo: "arena".into(),
        })
    };
    let locked_a = ask(&r, &p.a, &relay, &sid_a, lock(1, &p.b, Vec::new())).await;
    assert_eq!(
        fact(&locked_a),
        generated::ConnectFact::DuelLocked,
        "{}",
        locked_a.fact_detail
    );
    let a_vault = locked_a.escrow_vault_ids[0].clone();
    let cell: D32 = locked_a
        .escrow_verdict_cell
        .as_slice()
        .try_into()
        .expect("the match cell");
    let locked_b = ask(&r, &p.b, &relay, &sid_b, lock(2, &p.a, a_vault.clone())).await;
    assert_eq!(
        fact(&locked_b),
        generated::ConnectFact::DuelLocked,
        "{}",
        locked_b.fact_detail
    );
    assert_eq!(locked_b.escrow_verdict_cell, cell.to_vec());
    let b_vault = locked_b.escrow_vault_ids[0].clone();
    assert!(wallet_log(&p.a, &sid_a, 2)
        .await
        .summary
        .starts_with("Stake 25.00 ERA in a battle decided by program wildstate-duel v1 ("));

    // A readies; B readies with A's ready and writes the Start.
    let ready = |opponent_ready: Vec<u8>| {
        Kind::DuelReady(generated::ConnectDuelReadyV1 {
            match_cell: cell.to_vec(),
            opponent_ready,
        })
    };
    let ready_a = ask(&r, &p.a, &relay, &sid_a, ready(Vec::new())).await;
    assert_eq!(
        fact(&ready_a),
        generated::ConnectFact::None,
        "{}",
        ready_a.fact_detail
    );
    let Answer::DuelReady(ready_a) = answered(&ready_a) else {
        panic!("A answered another result");
    };
    let ready_signature = ready_a.ready_signature;
    let started = ask(&r, &p.b, &relay, &sid_b, ready(ready_signature)).await;
    assert_eq!(
        fact(&started),
        generated::ConnectFact::DuelStarted,
        "{}",
        started.fact_detail
    );

    // One turn, each entry signed by its own wallet under the grant.
    let (_, turns) = frozen();
    let (move_a, move_b) = (turns[0].a.encode(), turns[0].b.encode());
    let commit = |index: u32, side: MatchSide, played: &[u8]| {
        entry(
            index,
            side,
            EntryKind::Commit {
                commitment: computed::move_commitment(&salt(1, side), played),
            },
        )
    };
    let reveal = |index: u32, side: MatchSide, played: &[u8]| {
        entry(
            index,
            side,
            EntryKind::Reveal {
                salt: salt(1, side),
                played: played.to_vec(),
            },
        )
    };
    let e1 = play(
        &r,
        &p.a,
        &relay,
        &sid_a,
        &cell,
        &[],
        commit(1, MatchSide::A, &move_a),
    )
    .await;
    let e2 = play(
        &r,
        &p.b,
        &relay,
        &sid_b,
        &cell,
        &[e1],
        commit(2, MatchSide::B, &move_b),
    )
    .await;
    let e3 = play(
        &r,
        &p.a,
        &relay,
        &sid_a,
        &cell,
        &[e2],
        reveal(3, MatchSide::A, &move_a),
    )
    .await;
    let e4 = play(
        &r,
        &p.b,
        &relay,
        &sid_b,
        &cell,
        &[e3],
        reveal(4, MatchSide::B, &move_b),
    )
    .await;
    let e5 = play(
        &r,
        &p.b,
        &relay,
        &sid_b,
        &cell,
        &[],
        entry(5, MatchSide::B, EntryKind::Resign),
    )
    .await;

    // A settles with B's last entries; R reads a-wins from the match cell.
    let settled = ask(
        &r,
        &p.a,
        &relay,
        &sid_a,
        Kind::DuelSettle(generated::ConnectDuelSettleV1 {
            match_cell: cell.to_vec(),
            entries: vec![e4, e5],
        }),
    )
    .await;
    assert_eq!(
        fact(&settled),
        generated::ConnectFact::DuelSettled,
        "{}",
        settled.fact_detail
    );
    let cells = settled.duel_cells.expect("the match's cells");
    assert_eq!(cells.outcome, b"a-wins".to_vec());
    assert_eq!(
        cells.outcome_state,
        generated::EscrowVerdictState::Final as i32
    );

    // A collects both stakes; R establishes the release from the vaults.
    let collected = ask(
        &r,
        &p.a,
        &relay,
        &sid_a,
        Kind::DuelCollect(generated::ConnectDuelCollectV1 {
            vault_ids: vec![a_vault, b_vault],
        }),
    )
    .await;
    assert_eq!(
        fact(&collected),
        generated::ConnectFact::EscrowReleased,
        "{}",
        collected.fact_detail
    );
    assert_eq!(balance(&p.a, &era()), whole_era(100) + stake);
    assert_eq!(balance(&p.b, &era()), whole_era(100) - stake);
}
