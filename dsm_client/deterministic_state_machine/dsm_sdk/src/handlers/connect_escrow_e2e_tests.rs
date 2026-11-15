// SPDX-License-Identifier: MIT OR Apache-2.0

//! A match a connected application referees, staked through DSM Connect
//! (DSM Amendment A12), on storage nodes.
//!
//! Three devices on the pinned set's nodes: R is a game's own account, A and
//! B are two players' wallets, each connected to R under a grant that holds
//! an escrow scope. R asks each wallet to lock a stake for one match, naming
//! only the match, the stake, the side and the opponent; each wallet builds
//! the escrow terms itself from the match template. R decides the result as
//! an escrow signer (`escrow.adjudicate`), and asks the winner to collect.
//! Every step is a production route on the device that takes it, and the
//! test's store-and-forward relay (`connect_e2e_tests::ForwardRelay`) carries
//! only signed bytes between them.

use dsm::types::proto as generated;
use generated::connect_app_request_intent_v1::Kind;
use generated::connect_reply_v1::Reply;
use generated::envelope::Payload;
use serial_test::serial;

use super::connect_e2e_tests::{
    args_raw, carried_out, fact, outcome, query, reply, request, status, wallet_log, ForwardRelay,
    FREE_REQUESTS,
};
use super::node_e2e_tests::{args, balance, era, invoke, payload};
use crate::economic_fixtures::whole_era;
use crate::test_support::two_device::{Pair, TestDevice};

/// The game's account: a third device on the pair's nodes. It holds nothing;
/// it asks, decides and checks.
async fn game(p: &Pair) -> TestDevice {
    let mut r = TestDevice::create("R", 0x0C);
    r.boot(&p.fleet).await;
    r
}

/// R's offer through `relay`: an escrow scope locking up to 30 ERA a time and
/// 60 ERA in all. The code.
async fn offer(r: &TestDevice, relay: &ForwardRelay) -> String {
    let made = invoke(
        r,
        "connect.app.offer",
        args(&generated::ConnectAppOfferRequestV1 {
            display_name: "Arena".into(),
            endpoint: relay.endpoint.clone(),
            cert_pin: relay.pin.to_vec(),
            scopes: vec![generated::ConnectScopeV1 {
                kind: generated::ConnectScopeKind::Escrow as i32,
                policy_commits: Vec::new(),
                caps: vec![generated::ConnectCapV1 {
                    policy_commit: era().to_vec(),
                    per_request: whole_era(30),
                    total: whole_era(60),
                }],
                programs: Vec::new(),
            }],
            token_anchors: Vec::new(),
            free_requests: FREE_REQUESTS,
        }),
    )
    .await;
    let Reply::Offer(offer) = reply(&made) else {
        panic!("connect.app.offer answered another reply");
    };
    let digest: [u8; 32] = offer.offer_digest.as_slice().try_into().expect("a digest");
    relay.held().offer = Some((digest, offer.offer.clone()));
    offer.code
}

/// `wallet` previews and approves R's code; R takes the accept. The session.
async fn connect(
    r: &TestDevice,
    wallet: &TestDevice,
    relay: &ForwardRelay,
    code: &str,
) -> [u8; 32] {
    connect_shown(
        r,
        wallet,
        relay,
        code,
        "Lock stakes for matches: up to 30.00 ERA a time, 60.00 ERA in all",
    )
    .await
}

/// The same, for an offer whose preview shows `scope_line` for its scope.
async fn connect_shown(
    r: &TestDevice,
    wallet: &TestDevice,
    relay: &ForwardRelay,
    code: &str,
    scope_line: &str,
) -> [u8; 32] {
    let previewed = query(
        wallet,
        "connect.preview",
        args(&generated::ConnectPreviewRequestV1 { code: code.into() }),
    )
    .await;
    let Reply::Preview(preview) = reply(&previewed) else {
        panic!("connect.preview answered another reply");
    };
    assert_eq!(
        preview.scope_lines,
        vec![
            scope_line.to_string(),
            format!(
                "Up to {FREE_REQUESTS} requests that spend nothing; after them, each waits for you"
            ),
        ]
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
    let Reply::Session(app_side) = reply(&invoke(r, "connect.app.accept", args_raw(accept)).await)
    else {
        panic!("connect.app.accept answered another reply");
    };
    assert_eq!(app_side.session_id, wallet_side.session_id);
    wallet_side
        .session_id
        .as_slice()
        .try_into()
        .expect("a session id")
}

/// `wallet`'s `connect.sync`; then R takes every answer the relay kept.
async fn sync(wallet: &TestDevice, r: &TestDevice, relay: &ForwardRelay) -> String {
    let Reply::Sessions(synced) = reply(&invoke(wallet, "connect.sync", Vec::new()).await) else {
        panic!("connect.sync answered another reply");
    };
    let answers = std::mem::take(&mut relay.held().responses);
    for answer in answers {
        reply(&invoke(r, "connect.app.respond", args_raw(answer)).await);
    }
    synced
        .sessions
        .iter()
        .map(|s| s.last_error.clone())
        .collect::<Vec<_>>()
        .join("; ")
}

/// The wallet of R's session `sid`, as R's account lists it to the application
/// (`connect.app.sessions`): the identity and key R names it by. The listing
/// must carry what the account holds from the card the wallet's accept carried.
async fn player_of(r: &TestDevice, sid: &[u8; 32]) -> generated::ConnectSessionV1 {
    let Reply::Sessions(listed) = reply(&query(r, "connect.app.sessions", Vec::new()).await) else {
        panic!("connect.app.sessions answered no session list");
    };
    let listed = listed
        .sessions
        .into_iter()
        .find(|s| s.session_id == sid.to_vec())
        .expect("R lists its session with the wallet");
    r.enter();
    let held = crate::storage::client_db::connect::app_session(sid)
        .expect("R's sessions")
        .expect("R's session with the wallet");
    assert_eq!(
        (
            listed.peer_device_id.as_slice(),
            listed.peer_genesis.as_slice(),
            listed.peer_signing_key.as_slice()
        ),
        (
            held.wallet_device_id.as_slice(),
            held.wallet_genesis.as_slice(),
            held.wallet_ak.as_slice()
        ),
        "the listing names the wallet as the account holds it"
    );
    listed
}

/// R's request that its session `sid`'s wallet lock `stake` ERA for the
/// match `external`, playing `side` against `opponent`.
fn lock(
    external: &[u8],
    stake: u64,
    side: u32,
    opponent: &generated::ConnectSessionV1,
    counterpart: Option<&[u8]>,
) -> Kind {
    Kind::EscrowLock(generated::ConnectEscrowLockV1 {
        external: external.to_vec(),
        policy_commit: era().to_vec(),
        amount: stake,
        side,
        opponent_genesis: opponent.peer_genesis.clone(),
        opponent_device_id: opponent.peer_device_id.clone(),
        opponent_signing_key: opponent.peer_signing_key.clone(),
        counterpart_vault_id: match counterpart {
            Some(v) => v.to_vec(),
            None => Vec::new(),
        },
        memo: "arena final".into(),
    })
}

fn collect(vaults: &[&[u8]]) -> Kind {
    Kind::EscrowRelease(generated::ConnectEscrowReleaseV1 {
        vault_ids: vaults.iter().map(|v| v.to_vec()).collect(),
    })
}

async fn adjudicate(r: &TestDevice, vault_id: &[u8], decided: &[u8]) {
    let answered = invoke(
        r,
        "escrow.adjudicate",
        args(&generated::EscrowOutcomeRequest {
            vault_id: vault_id.to_vec(),
            outcome: decided.to_vec(),
        }),
    )
    .await;
    match payload(&answered) {
        Payload::EscrowVerdictResponse(v) => assert_eq!(
            (v.state, v.outcome.as_slice()),
            (generated::EscrowVerdictState::Final as i32, decided),
            "the cell's verdict: {v:?}"
        ),
        other => panic!("escrow.adjudicate answered {other:?}"),
    }
}

/// The wallet failed request `seq`, by its own log, saying `why`.
async fn failed(wallet: &TestDevice, sid: &[u8; 32], seq: u64, why: &str) {
    let entry = wallet_log(wallet, sid, seq).await;
    assert_eq!(
        generated::ConnectOutcome::try_from(entry.outcome),
        Ok(generated::ConnectOutcome::Failed),
        "request {seq} ({}): {}",
        entry.summary,
        entry.detail
    );
    assert!(entry.detail.contains(why), "{}", entry.detail);
}

/// R's account established that its session `sid`'s request `seq` locked a
/// stake: the vault and the verdict cell it found.
async fn locked(r: &TestDevice, sid: &[u8; 32], seq: u64, stake: u64) -> (Vec<u8>, Vec<u8>) {
    let s = status(r, sid, seq).await;
    assert_eq!(
        fact(&s),
        generated::ConnectFact::EscrowLocked,
        "{}",
        s.fact_detail
    );
    assert_eq!(s.escrow_amount, stake);
    assert_eq!(s.escrow_vault_ids.len(), 1);
    (s.escrow_vault_ids[0].clone(), s.escrow_verdict_cell.clone())
}

/// A game referees a match its two players staked through their grants. A
/// locks first; B locks against A's vault, and the two stakes share one
/// verdict cell. Neither wallet takes a branch or a recipient from the game:
/// each builds the template itself. The game decides `a-wins`; asked to
/// collect, B's wallet releases nothing, and A's takes both stakes once. The
/// game counts each lock and the collection only from the vaults its own
/// account walks:
/// - B's lock is not counted from A's vault, though it sits on the same cell;
/// - B's failed collect is not counted once A has released both vaults;
/// - an answer signed by A saying it locked a stake it never locked counts
///   for nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_match_the_game_referees_pays_the_winner_both_stakes() {
    let p = Pair::boot(100, 100).await;
    let r = game(&p).await;
    let relay = ForwardRelay::start().await;
    // Each player connects through a code of their own: an offer connects
    // one wallet (SA-79).
    let code_a = offer(&r, &relay).await;
    let sid_a = connect(&r, &p.a, &relay, &code_a).await;
    let code_b = offer(&r, &relay).await;
    let sid_b = connect(&r, &p.b, &relay, &code_b).await;
    let (as_a, as_b) = (player_of(&r, &sid_a).await, player_of(&r, &sid_b).await);
    let stake = whole_era(25);
    let external = b"arena match 1: A v B";

    let lock_a = request(&r, &relay, &sid_a, lock(external, stake, 1, &as_b, None)).await;
    assert_eq!(sync(&p.a, &r, &relay).await, "");
    carried_out(&p.a, &sid_a, lock_a).await;
    assert_eq!(
        wallet_log(&p.a, &sid_a, lock_a).await.summary,
        "Lock 25.00 ERA for a match (arena final)"
    );
    assert_eq!(balance(&p.a, &era()), whole_era(100) - stake);
    let (a_vault, cell) = locked(&r, &sid_a, lock_a, stake).await;

    // B's lock, asked and not yet carried out: A's vault on the same cell
    // is not B's stake.
    let lock_b = request(
        &r,
        &relay,
        &sid_b,
        lock(external, stake, 2, &as_a, Some(&a_vault)),
    )
    .await;
    let early = status(&r, &sid_b, lock_b).await;
    assert_eq!(
        fact(&early),
        generated::ConnectFact::None,
        "{}",
        early.fact_detail
    );
    assert_eq!(sync(&p.b, &r, &relay).await, "");
    carried_out(&p.b, &sid_b, lock_b).await;
    assert_eq!(balance(&p.b, &era()), whole_era(100) - stake);
    let (b_vault, b_cell) = locked(&r, &sid_b, lock_b, stake).await;
    assert_eq!(
        b_cell, cell,
        "the two stakes of a match share one verdict cell"
    );
    assert_ne!(b_vault, a_vault);

    adjudicate(&r, &a_vault, b"a-wins").await;

    // The loser's wallet, asked to collect, releases nothing.
    let collect_b = request(&r, &relay, &sid_b, collect(&[&a_vault, &b_vault])).await;
    assert_eq!(sync(&p.b, &r, &relay).await, "");
    failed(&p.b, &sid_b, collect_b, "pays another identity").await;
    assert_eq!(balance(&p.b, &era()), whole_era(100) - stake);

    let collect_a = request(&r, &relay, &sid_a, collect(&[&a_vault, &b_vault])).await;
    assert_eq!(sync(&p.a, &r, &relay).await, "");
    carried_out(&p.a, &sid_a, collect_a).await;
    assert_eq!(balance(&p.a, &era()), whole_era(100) + stake);
    assert_eq!(balance(&p.b, &era()), whole_era(100) - stake);
    let collected = status(&r, &sid_a, collect_a).await;
    assert_eq!(
        fact(&collected),
        generated::ConnectFact::EscrowReleased,
        "{}",
        collected.fact_detail
    );
    assert_eq!(
        collected.escrow_vault_ids,
        vec![a_vault.clone(), b_vault.clone()]
    );
    assert_eq!(collected.escrow_verdict_cell, cell);

    // B's collect failed; the vaults A released do not count for B.
    let not_b = status(&r, &sid_b, collect_b).await;
    assert_eq!(outcome(&not_b), generated::ConnectOutcome::Failed);
    assert_eq!(
        fact(&not_b),
        generated::ConnectFact::None,
        "{}",
        not_b.fact_detail
    );

    // A's wallet signs "locked" for a second match it never locked.
    let lock_again = request(
        &r,
        &relay,
        &sid_a,
        lock(b"arena match 2: A v B", stake, 1, &as_b, None),
    )
    .await;
    p.a.enter();
    let claimed = crate::sdk::connect::wallet::signed_response(&generated::AppResponseBodyV1 {
        session_id: sid_a.to_vec(),
        seq: lock_again,
        outcome: generated::ConnectOutcome::CarriedOut as i32,
        reason: String::new(),
        result: Some(generated::app_response_body_v1::Result::EscrowLock(
            generated::ConnectEscrowLockResultV1 {
                vault_id: a_vault.clone(),
                verdict_cell: cell.clone(),
                external_commitment: dsm::sofi::escrow::external_commitment(
                    b"arena match 2: A v B",
                )
                .to_vec(),
                position: 1,
            },
        )),
    })
    .expect("the wallet signs");
    reply(&invoke(&r, "connect.app.respond", args_raw(claimed)).await);
    let unlocked = status(&r, &sid_a, lock_again).await;
    assert_eq!(outcome(&unlocked), generated::ConnectOutcome::CarriedOut);
    assert_eq!(
        fact(&unlocked),
        generated::ConnectFact::None,
        "an answer saying locked grants nothing: {}",
        unlocked.fact_detail
    );
    assert!(unlocked.escrow_vault_ids.is_empty());
}

/// A match nobody joined is voided, and the stake goes back. A locks; B,
/// asked to lock a smaller stake against A's, refuses; the game decides
/// `void`, and A's wallet collects its own stake.
///
/// Two more things the game cannot do through the grant:
/// - have a wallet collect a vault that is not a match it decides: A's own
///   escrow vault, decided by A and paying A, stays locked;
/// - have a wallet lock past the grant's cap: the lock waits for the player,
///   and nothing is locked.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_match_nobody_joined_is_voided_and_the_stake_returns() {
    let p = Pair::boot(100, 100).await;
    let r = game(&p).await;
    let relay = ForwardRelay::start().await;
    // Each player connects through a code of their own: an offer connects
    // one wallet (SA-79).
    let code_a = offer(&r, &relay).await;
    let sid_a = connect(&r, &p.a, &relay, &code_a).await;
    let code_b = offer(&r, &relay).await;
    let sid_b = connect(&r, &p.b, &relay, &code_b).await;
    let as_b = player_of(&r, &sid_b).await;
    let stake = whole_era(20);

    let lock_a = request(
        &r,
        &relay,
        &sid_a,
        lock(b"arena match 3: A v nobody", stake, 1, &as_b, None),
    )
    .await;
    assert_eq!(sync(&p.a, &r, &relay).await, "");
    let (a_vault, _) = locked(&r, &sid_a, lock_a, stake).await;
    assert_eq!(balance(&p.a, &era()), whole_era(100) - stake);

    // Half A's stake, against A's vault: B's wallet locks nothing.
    let as_a = player_of(&r, &sid_a).await;
    let smaller = request(
        &r,
        &relay,
        &sid_b,
        lock(
            b"arena match 3: A v nobody",
            whole_era(10),
            2,
            &as_a,
            Some(&a_vault),
        ),
    )
    .await;
    assert_eq!(sync(&p.b, &r, &relay).await, "");
    failed(
        &p.b,
        &sid_b,
        smaller,
        "not the 10.00 ERA this stake matches",
    )
    .await;
    assert_eq!(balance(&p.b, &era()), whole_era(100));

    adjudicate(&r, &a_vault, b"void").await;
    let refund = request(&r, &relay, &sid_a, collect(&[&a_vault])).await;
    assert_eq!(sync(&p.a, &r, &relay).await, "");
    carried_out(&p.a, &sid_a, refund).await;
    assert_eq!(balance(&p.a, &era()), whole_era(100));
    let refunded = status(&r, &sid_a, refund).await;
    assert_eq!(
        fact(&refunded),
        generated::ConnectFact::EscrowReleased,
        "{}",
        refunded.fact_detail
    );

    // A's own escrow vault: one outcome A decides, paying A, decided final.
    let me = party(&p.a).await;
    let own = match payload(
        &invoke(
            &p.a,
            "escrow.create",
            args(&generated::EscrowCreateRequest {
                external: b"A's own agreement".to_vec(),
                token_policy_commit: era().to_vec(),
                amount_entered: "5".into(),
                branches: vec![generated::EscrowBranchV1 {
                    outcome: b"done".to_vec(),
                    signers: vec![me.signer.clone().expect("A's signer")],
                    recipient_genesis: me.genesis.clone(),
                    recipient_device_id: me.device_id.clone(),
                }],
                counterpart_vault_id: Vec::new(),
            }),
        )
        .await,
    ) {
        Payload::EscrowCreatedResponse(created) => created,
        other => panic!("escrow.create answered {other:?}"),
    };
    adjudicate(&p.a, &own.vault_id, b"done").await;
    assert_eq!(balance(&p.a, &era()), whole_era(95));
    let foreign = request(&r, &relay, &sid_a, collect(&[&own.vault_id])).await;
    assert_eq!(sync(&p.a, &r, &relay).await, "");
    failed(
        &p.a,
        &sid_a,
        foreign,
        "is not a match this application decides",
    )
    .await;
    assert_eq!(
        balance(&p.a, &era()),
        whole_era(95),
        "A's own vault stays locked"
    );

    // Past the cap of 30 ERA a time: it waits on the device.
    let past_cap = request(
        &r,
        &relay,
        &sid_a,
        lock(b"arena match 4: A v B", whole_era(40), 1, &as_b, None),
    )
    .await;
    assert_eq!(sync(&p.a, &r, &relay).await, "");
    let Reply::Pending(pending) = reply(&query(&p.a, "connect.pending", Vec::new()).await) else {
        panic!("connect.pending answered another reply");
    };
    assert_eq!(pending.pending.len(), 1);
    assert_eq!(pending.pending[0].seq, past_cap);
    assert!(
        pending.pending[0].reason.contains("per request"),
        "{}",
        pending.pending[0].reason
    );
    assert_eq!(balance(&p.a, &era()), whole_era(95), "nothing was locked");
    let waiting = status(&r, &sid_a, past_cap).await;
    assert_eq!(
        outcome(&waiting),
        generated::ConnectOutcome::AwaitingApproval
    );
    assert_eq!(fact(&waiting), generated::ConnectFact::None);
}

/// `d` as an escrow party: its identity and signing key.
async fn party(d: &TestDevice) -> generated::EscrowPartyResponse {
    match payload(&invoke(d, "escrow.party", args(&generated::EscrowPartyRequest {})).await) {
        Payload::EscrowPartyResponse(me) => me,
        other => panic!("escrow.party answered {other:?}"),
    }
}

/// Side B locks only against a vault that is the match's stake with B as B.
/// A builds a vault of its own on the match's verdict cell, with the game's
/// outcome table, every branch of it paying A; the game asks B to lock
/// against it. The cell is the match's, the stake is the same, and B's
/// wallet still locks nothing: on `b-wins` that vault would pay A.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn side_b_locks_only_against_a_stake_that_pays_it_on_b_wins() {
    let p = Pair::boot(100, 100).await;
    let r = game(&p).await;
    let relay = ForwardRelay::start().await;
    // Each player connects through a code of their own: an offer connects
    // one wallet (SA-79).
    let code_a = offer(&r, &relay).await;
    let sid_a = connect(&r, &p.a, &relay, &code_a).await;
    let code_b = offer(&r, &relay).await;
    let sid_b = connect(&r, &p.b, &relay, &code_b).await;
    let as_a = player_of(&r, &sid_a).await;
    let (pa, pb, pr) = (party(&p.a).await, party(&p.b).await, party(&r).await);
    let signer = |x: &generated::EscrowPartyResponse| x.signer.clone().expect("a signer");
    let mut players = vec![signer(&pa), signer(&pb)];
    players.sort_by(|x, y| {
        (x.signature_alg, x.public_key.len(), &x.public_key).cmp(&(
            y.signature_alg,
            y.public_key.len(),
            &y.public_key,
        ))
    });
    let to_a =
        |outcome: &[u8], signers: Vec<generated::EscrowSignerV1>| generated::EscrowBranchV1 {
            outcome: outcome.to_vec(),
            signers,
            recipient_genesis: pa.genesis.clone(),
            recipient_device_id: pa.device_id.clone(),
        };
    let external = b"arena match 5: A v B";
    let rigged = match payload(
        &invoke(
            &p.a,
            "escrow.create",
            args(&generated::EscrowCreateRequest {
                external: external.to_vec(),
                token_policy_commit: era().to_vec(),
                amount_entered: "20".into(),
                branches: vec![
                    to_a(b"a-wins", vec![signer(&pr)]),
                    to_a(b"b-wins", vec![signer(&pr)]),
                    to_a(b"cancel", players),
                    to_a(b"void", vec![signer(&pr)]),
                ],
                counterpart_vault_id: Vec::new(),
            }),
        )
        .await,
    ) {
        Payload::EscrowCreatedResponse(created) => created,
        other => panic!("escrow.create answered {other:?}"),
    };

    let against = request(
        &r,
        &relay,
        &sid_b,
        lock(external, whole_era(20), 2, &as_a, Some(&rigged.vault_id)),
    )
    .await;
    assert_eq!(sync(&p.b, &r, &relay).await, "");
    failed(
        &p.b,
        &sid_b,
        against,
        "is not this match's stake with this wallet as B",
    )
    .await;
    assert_eq!(balance(&p.b, &era()), whole_era(100), "B locked nothing");
    let none = status(&r, &sid_b, against).await;
    assert_eq!(
        fact(&none),
        generated::ConnectFact::None,
        "{}",
        none.fact_detail
    );
}

/// One match both players staked, as R's account established it.
struct Staked {
    sid_a: [u8; 32],
    sid_b: [u8; 32],
    lock_a: u64,
    lock_b: u64,
    a_vault: Vec<u8>,
    b_vault: Vec<u8>,
}

/// A locks 25 ERA for a match against B, and B locks 25 ERA against A's vault,
/// each asked by R through its own session.
async fn both_staked(p: &Pair, r: &TestDevice, relay: &ForwardRelay) -> Staked {
    // Each player connects through a code of their own: an offer connects
    // one wallet (SA-79).
    let code_a = offer(r, relay).await;
    let sid_a = connect(r, &p.a, relay, &code_a).await;
    let code_b = offer(r, relay).await;
    let sid_b = connect(r, &p.b, relay, &code_b).await;
    let (as_a, as_b) = (player_of(r, &sid_a).await, player_of(r, &sid_b).await);
    let stake = whole_era(25);
    let external = b"arena match 1: A v B";
    let lock_a = request(r, relay, &sid_a, lock(external, stake, 1, &as_b, None)).await;
    assert_eq!(sync(&p.a, r, relay).await, "");
    carried_out(&p.a, &sid_a, lock_a).await;
    let (a_vault, ..) = locked(r, &sid_a, lock_a, stake).await;
    let lock_b = request(
        r,
        relay,
        &sid_b,
        lock(external, stake, 2, &as_a, Some(&a_vault)),
    )
    .await;
    assert_eq!(sync(&p.b, r, relay).await, "");
    carried_out(&p.b, &sid_b, lock_b).await;
    let (b_vault, ..) = locked(r, &sid_b, lock_b, stake).await;
    Staked {
        sid_a,
        sid_b,
        lock_a,
        lock_b,
        a_vault,
        b_vault,
    }
}

/// The read a walk of `vault`'s chain makes at its head, entered as R: the
/// first attempt key of the root its head stands on. It is open while the
/// vault is Active, so every walk to the head reads it again.
fn head_read(set: &crate::sdk::storage_set::StorageSet, vault: &[u8]) -> String {
    let vault: [u8; 32] = vault.try_into().expect("a vault id");
    let ctx = crate::sdk::sofi_reads::VerifierContext::new(set, None, None).expect("a verifier");
    let verifier = ctx.verifier();
    let chain = verifier.chain(&vault).expect("the vault's chain");
    let (.., head) = chain.head().expect("an accepted vault has a head");
    let key = verifier
        .attempt_cell(&vault, &head, 0)
        .expect("the head's first key");
    format!(
        "GET /api/v2/cell/{}",
        crate::util::text_id::encode_base32_crockford(key.routed().key())
    )
}

/// Every request the members were asked since they last forgot.
fn asked(p: &Pair) -> Vec<String> {
    p.nodes.nodes.iter().flat_map(|n| n.requests()).collect()
}

/// A stake's status walks only the wallet's own vault on the match's verdict
/// cell. Both players staked on one cell; R's status of each lock walks that
/// wallet's vault to its head, and never the opponent's, which is not the
/// wallet's stake whatever it holds.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_stakes_status_walks_only_the_wallets_own_vault() {
    let p = Pair::boot(100, 100).await;
    let r = game(&p).await;
    let relay = ForwardRelay::start().await;
    let staked = both_staked(&p, &r, &relay).await;
    r.enter();
    let set = crate::sdk::storage_set::canonical_set(crate::economic_fixtures::NETWORK)
        .expect("the pinned set");
    let a_head = head_read(&set, &staked.a_vault);
    let b_head = head_read(&set, &staked.b_vault);
    for (sid, seq, own, other) in [
        (&staked.sid_a, staked.lock_a, &a_head, &b_head),
        (&staked.sid_b, staked.lock_b, &b_head, &a_head),
    ] {
        for node in &p.nodes.nodes {
            node.forget_requests();
        }
        locked(&r, sid, seq, whole_era(25)).await;
        let asked = asked(&p);
        assert!(
            asked.contains(own),
            "the wallet's vault is walked to its head"
        );
        assert!(
            !asked.contains(other),
            "the opponent's vault is not walked for the wallet's stake"
        );
    }
}

/// A collect's status reads each vault and its verdict through one context,
/// and once it established the release it answers from its record: a
/// Retired vault and a final verdict are permanent. A collects both stakes;
/// R's first status reads each vault's genesis once from each member, and
/// later polls read nothing and say exactly what the first said. A second
/// request naming the same vaults is not answered by the first one's
/// record: it is read again, and established the same.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_collects_status_is_read_once_and_answered_from_its_record() {
    let p = Pair::boot(100, 100).await;
    let r = game(&p).await;
    let relay = ForwardRelay::start().await;
    let staked = both_staked(&p, &r, &relay).await;
    adjudicate(&r, &staked.a_vault, b"a-wins").await;
    let vaults = [staked.a_vault.as_slice(), staked.b_vault.as_slice()];
    let collect_a = request(&r, &relay, &staked.sid_a, collect(&vaults)).await;
    assert_eq!(sync(&p.a, &r, &relay).await, "");
    carried_out(&p.a, &staked.sid_a, collect_a).await;

    for node in &p.nodes.nodes {
        node.forget_requests();
    }
    let first = status(&r, &staked.sid_a, collect_a).await;
    assert_eq!(
        fact(&first),
        generated::ConnectFact::EscrowReleased,
        "{}",
        first.fact_detail
    );
    for vault in vaults {
        let vault: [u8; 32] = vault.try_into().expect("a vault id");
        let genesis_scan = format!(
            "GET /api/v2/index/{}",
            crate::util::text_id::encode_base32_crockford(
                &dsm::sofi::derive::vault_genesis_locator(&vault)
            )
        );
        for node in &p.nodes.nodes {
            let scans = node
                .requests()
                .iter()
                .filter(|r| r.starts_with(&genesis_scan))
                .count();
            assert!(
                scans <= 1,
                "{} was asked for vault {genesis_scan}'s genesis {scans} times: the vault and its \
                 verdict are read through one context",
                node.member_id
            );
        }
    }

    for poll in 1..=2 {
        for node in &p.nodes.nodes {
            node.forget_requests();
        }
        let again = status(&r, &staked.sid_a, collect_a).await;
        assert_eq!(
            again, first,
            "poll {poll}: the record says what the reads said"
        );
        // Reads only: a cell or index GET. An index append (a POST) another
        // party's earlier step lands while the poll runs is a write, not this
        // status reading anything again.
        let read: Vec<String> = asked(&p)
            .into_iter()
            .filter(|r| r.starts_with("GET /api/v2/cell/") || r.starts_with("GET /api/v2/index/"))
            .collect();
        assert_eq!(
            read,
            Vec::<String>::new(),
            "poll {poll}: nothing is read again"
        );
    }

    let collect_again = request(&r, &relay, &staked.sid_a, collect(&vaults)).await;
    let other = status(&r, &staked.sid_a, collect_again).await;
    assert_eq!(
        fact(&other),
        generated::ConnectFact::EscrowReleased,
        "{}",
        other.fact_detail
    );
    assert_eq!(
        (
            other.escrow_vault_ids,
            other.escrow_verdict_cell,
            other.fact_detail
        ),
        (
            first.escrow_vault_ids.clone(),
            first.escrow_verdict_cell.clone(),
            first.fact_detail.clone()
        )
    );
}

// ── contributions (DSM Amendment A35) ───────────────────────────────────────

/// R's offer through `relay`: a contribute scope committing up to 30 ERA a
/// time and 60 ERA in all. The code.
async fn contribution_offer(r: &TestDevice, relay: &ForwardRelay) -> String {
    let made = invoke(
        r,
        "connect.app.offer",
        args(&generated::ConnectAppOfferRequestV1 {
            display_name: "Territories".into(),
            endpoint: relay.endpoint.clone(),
            cert_pin: relay.pin.to_vec(),
            scopes: vec![generated::ConnectScopeV1 {
                kind: generated::ConnectScopeKind::Contribute as i32,
                policy_commits: Vec::new(),
                caps: vec![generated::ConnectCapV1 {
                    policy_commit: era().to_vec(),
                    per_request: whole_era(30),
                    total: whole_era(60),
                }],
                programs: Vec::new(),
            }],
            token_anchors: Vec::new(),
            free_requests: FREE_REQUESTS,
        }),
    )
    .await;
    let Reply::Offer(offer) = reply(&made) else {
        panic!("connect.app.offer answered another reply");
    };
    let digest: [u8; 32] = offer.offer_digest.as_slice().try_into().expect("a digest");
    relay.held().offer = Some((digest, offer.offer.clone()));
    offer.code
}

/// What a wallet shows for the contribute scope of [`contribution_offer`].
const CONTRIBUTE_LINE: &str =
    "Commit what you own to what this app names, yours to take back: up to 30.00 ERA \
                               a time, 60.00 ERA in all";

fn contribute(external: &[u8], amount: u64) -> Kind {
    Kind::Contribute(generated::ConnectContributeV1 {
        external: external.to_vec(),
        policy_commit: era().to_vec(),
        amount,
        memo: "watchtower".into(),
    })
}

fn take_back(vaults: &[&[u8]]) -> Kind {
    Kind::ContributionRelease(generated::ConnectContributionReleaseV1 {
        vault_ids: vaults.iter().map(|v| v.to_vec()).collect(),
    })
}

/// R's account established that its session `sid`'s request `seq` committed
/// `amount`: the vault it found.
async fn contributed(r: &TestDevice, sid: &[u8; 32], seq: u64, amount: u64) -> Vec<u8> {
    let s = status(r, sid, seq).await;
    assert_eq!(
        fact(&s),
        generated::ConnectFact::Contributed,
        "{}",
        s.fact_detail
    );
    assert_eq!(s.escrow_amount, amount);
    assert_eq!(s.escrow_vault_ids.len(), 1);
    s.escrow_vault_ids[0].clone()
}

/// R's account established that request `seq` took its vaults back, on
/// `decided`.
async fn taken_back(r: &TestDevice, sid: &[u8; 32], seq: u64, decided: &str) {
    let s = status(r, sid, seq).await;
    assert_eq!(
        fact(&s),
        generated::ConnectFact::ContributionReleased,
        "{}",
        s.fact_detail
    );
    assert!(s.fact_detail.contains(decided), "{}", s.fact_detail);
}

/// A member commits an amount to a structure through their grant, and takes
/// it back themselves. The wallet builds the terms from the contribution
/// template; the game names only the commitment, the object and the amount.
/// While the vault is Active the amount is out of the wallet's balance; the
/// wallet's own `withdraw` returns it, with nothing asked of the game. The
/// game counts the commitment and the return only from the vault its own
/// account walks. A vault that is not a contribution is not taken back
/// through the grant, and a commitment past the cap waits on the device.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_contribution_is_committed_under_the_grant_and_taken_back_by_its_owner() {
    let p = Pair::boot(100, 100).await;
    let r = game(&p).await;
    let relay = ForwardRelay::start().await;
    let code = contribution_offer(&r, &relay).await;
    let sid = connect_shown(&r, &p.a, &relay, &code, CONTRIBUTE_LINE).await;
    let amount = whole_era(20);

    let asked = request(&r, &relay, &sid, contribute(b"faction 4 / tower 9", amount)).await;
    assert_eq!(sync(&p.a, &r, &relay).await, "");
    carried_out(&p.a, &sid, asked).await;
    let vault = contributed(&r, &sid, asked, amount).await;
    assert_eq!(balance(&p.a, &era()), whole_era(100) - amount);

    let back = request(&r, &relay, &sid, take_back(&[&vault])).await;
    assert_eq!(sync(&p.a, &r, &relay).await, "");
    carried_out(&p.a, &sid, back).await;
    assert_eq!(balance(&p.a, &era()), whole_era(100));
    taken_back(&r, &sid, back, "withdraw").await;

    // A's own escrow vault, not a contribution: not the application's to
    // have released.
    let me = party(&p.a).await;
    let own = match payload(
        &invoke(
            &p.a,
            "escrow.create",
            args(&generated::EscrowCreateRequest {
                external: b"A's own agreement".to_vec(),
                token_policy_commit: era().to_vec(),
                amount_entered: "5".into(),
                branches: vec![generated::EscrowBranchV1 {
                    outcome: b"done".to_vec(),
                    signers: vec![me.signer.clone().expect("A's signer")],
                    recipient_genesis: me.genesis.clone(),
                    recipient_device_id: me.device_id.clone(),
                }],
                counterpart_vault_id: Vec::new(),
            }),
        )
        .await,
    ) {
        Payload::EscrowCreatedResponse(created) => created,
        other => panic!("escrow.create answered {other:?}"),
    };
    let foreign = request(&r, &relay, &sid, take_back(&[&own.vault_id])).await;
    assert_eq!(sync(&p.a, &r, &relay).await, "");
    failed(
        &p.a,
        &sid,
        foreign,
        "is not a contribution this application returns",
    )
    .await;
    assert_eq!(
        balance(&p.a, &era()),
        whole_era(95),
        "A's own vault stays locked"
    );

    // Past the cap of 30 ERA a time: it waits on the device.
    let past_cap = request(
        &r,
        &relay,
        &sid,
        contribute(b"faction 4 / wall 2", whole_era(40)),
    )
    .await;
    assert_eq!(sync(&p.a, &r, &relay).await, "");
    let Reply::Pending(pending) = reply(&query(&p.a, "connect.pending", Vec::new()).await) else {
        panic!("connect.pending answered another reply");
    };
    assert_eq!(pending.pending.len(), 1);
    assert_eq!(pending.pending[0].seq, past_cap);
    assert_eq!(
        balance(&p.a, &era()),
        whole_era(95),
        "nothing was committed"
    );
    assert_eq!(
        fact(&status(&r, &sid, past_cap).await),
        generated::ConnectFact::None
    );
}

/// The game returns a contribution: it decides `return` with its own key,
/// and the amount goes back to the member who committed it and to nobody
/// else. The game can decide when; the template gives it no outcome that
/// pays another identity, and `withdraw` is not the game's to decide.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn the_game_returns_a_contribution_to_its_owner_and_decides_nothing_else() {
    let p = Pair::boot(100, 100).await;
    let r = game(&p).await;
    let relay = ForwardRelay::start().await;
    let code = contribution_offer(&r, &relay).await;
    let sid = connect_shown(&r, &p.a, &relay, &code, CONTRIBUTE_LINE).await;
    let amount = whole_era(25);

    let asked = request(&r, &relay, &sid, contribute(b"faction 4 / tower 9", amount)).await;
    assert_eq!(sync(&p.a, &r, &relay).await, "");
    let vault = contributed(&r, &sid, asked, amount).await;
    assert_eq!(balance(&p.a, &era()), whole_era(100) - amount);

    // The owner's outcome is not the game's: its key does not complete it.
    let refused = invoke(
        &r,
        "escrow.adjudicate",
        args(&generated::EscrowOutcomeRequest {
            vault_id: vault.clone(),
            outcome: b"withdraw".to_vec(),
        }),
    )
    .await;
    let why = refused
        .error_message
        .clone()
        .expect("the game's withdraw is refused, with the reason");
    assert!(
        why.contains("the gathered signatures do not decide \"withdraw\""),
        "{why}"
    );

    adjudicate(&r, &vault, b"return").await;
    assert_eq!(
        balance(&p.a, &era()),
        whole_era(100) - amount,
        "a return is decided, not yet released"
    );
    let back = request(&r, &relay, &sid, take_back(&[&vault])).await;
    assert_eq!(sync(&p.a, &r, &relay).await, "");
    carried_out(&p.a, &sid, back).await;
    assert_eq!(balance(&p.a, &era()), whole_era(100));
    assert_eq!(balance(&r, &era()), 0, "the game holds nothing of it");
    taken_back(&r, &sid, back, "return").await;
}

// ── application cells (DSM Amendment A35) ───────────────────────────────────

/// R's offer through `relay`: a state scope. The code.
async fn state_offer(r: &TestDevice, relay: &ForwardRelay) -> String {
    let made = invoke(
        r,
        "connect.app.offer",
        args(&generated::ConnectAppOfferRequestV1 {
            display_name: "Territories".into(),
            endpoint: relay.endpoint.clone(),
            cert_pin: relay.pin.to_vec(),
            scopes: vec![generated::ConnectScopeV1 {
                kind: generated::ConnectScopeKind::AppCell as i32,
                policy_commits: Vec::new(),
                caps: Vec::new(),
                programs: Vec::new(),
            }],
            token_anchors: Vec::new(),
            free_requests: FREE_REQUESTS,
        }),
    )
    .await;
    let Reply::Offer(offer) = reply(&made) else {
        panic!("connect.app.offer answered another reply");
    };
    let digest: [u8; 32] = offer.offer_digest.as_slice().try_into().expect("a digest");
    relay.held().offer = Some((digest, offer.offer.clone()));
    offer.code
}

const STATE_LINE: &str = "Sign and store changes to this app's shared state, as you";

fn cell_write(name: &[u8], writers: &[&generated::ConnectSessionV1], payload: &[u8]) -> Kind {
    Kind::AppCellWrite(generated::ConnectAppCellWriteV1 {
        name: name.to_vec(),
        writer_keys: writers.iter().map(|w| w.peer_signing_key.clone()).collect(),
        payload: payload.to_vec(),
    })
}

/// Two members of one faction each write the faction's next step through
/// their grants, at the one cell the game names for both of them. The first
/// write at the cell's leader holds it; the second member's write, validly
/// signed by a writer of the same set, never does. The game counts a write
/// only from the cell its own account derives and reads: A's is a fact with
/// the step the next cell commits, B's is reported as another writer's
/// holding the cell. A write for a cell whose writers leave the wallet out
/// is refused before it is asked.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn the_first_members_write_holds_a_cell_and_a_second_members_never_does() {
    let p = Pair::boot(100, 100).await;
    let r = game(&p).await;
    let relay = ForwardRelay::start().await;
    let code_a = state_offer(&r, &relay).await;
    let sid_a = connect_shown(&r, &p.a, &relay, &code_a, STATE_LINE).await;
    let code_b = state_offer(&r, &relay).await;
    let sid_b = connect_shown(&r, &p.b, &relay, &code_b, STATE_LINE).await;
    let as_a = player_of(&r, &sid_a).await;
    let as_b = player_of(&r, &sid_b).await;
    let members = [&as_a, &as_b];

    let by_a = request(
        &r,
        &relay,
        &sid_a,
        cell_write(b"faction 4 / step 1", &members, b"place watchtower at 4,9"),
    )
    .await;
    assert_eq!(sync(&p.a, &r, &relay).await, "");
    carried_out(&p.a, &sid_a, by_a).await;
    let held = status(&r, &sid_a, by_a).await;
    assert_eq!(
        fact(&held),
        generated::ConnectFact::AppCellHeld,
        "{}",
        held.fact_detail
    );
    assert_eq!(held.app_cell.len(), 32);
    assert_eq!(
        held.app_cell_step.len(),
        32,
        "a final occupant has its step"
    );

    // B writes another change at the same cell: its wallet signs and stores
    // it, and the cell stays A's.
    let by_b = request(
        &r,
        &relay,
        &sid_b,
        cell_write(b"faction 4 / step 1", &members, b"place wall at 2,2"),
    )
    .await;
    assert_eq!(sync(&p.b, &r, &relay).await, "");
    carried_out(&p.b, &sid_b, by_b).await;
    let lost = status(&r, &sid_b, by_b).await;
    assert_eq!(
        fact(&lost),
        generated::ConnectFact::None,
        "{}",
        lost.fact_detail
    );
    assert!(
        lost.fact_detail
            .contains("another writer's write holds the cell"),
        "{}",
        lost.fact_detail
    );
    assert_eq!(lost.app_cell, held.app_cell, "both wrote the one cell");
    assert_eq!(
        lost.app_cell_step, held.app_cell_step,
        "and it has one step"
    );
    let still = status(&r, &sid_a, by_a).await;
    assert_eq!(fact(&still), generated::ConnectFact::AppCellHeld);
    assert_eq!(still.app_cell_step, held.app_cell_step);

    // The next step is another cell, and B's write holds it.
    let next = request(
        &r,
        &relay,
        &sid_b,
        cell_write(b"faction 4 / step 2", &members, b"place wall at 2,2"),
    )
    .await;
    assert_eq!(sync(&p.b, &r, &relay).await, "");
    let second = status(&r, &sid_b, next).await;
    assert_eq!(
        fact(&second),
        generated::ConnectFact::AppCellHeld,
        "{}",
        second.fact_detail
    );
    assert_ne!(second.app_cell, held.app_cell);

    // A cell B does not write: the game's own account refuses to ask.
    let refused = invoke(
        &r,
        "connect.app.request",
        args(&generated::ConnectAppRequestIntentV1 {
            session_id: sid_b.to_vec(),
            kind: Some(cell_write(b"faction 4 / step 3", &[&as_a], b"raze")),
        }),
    )
    .await;
    let why = refused
        .error_message
        .clone()
        .expect("a write the wallet cannot sign is refused, with the reason");
    assert!(why.contains("not one of the cell's writers"), "{why}");
}

// ── a stranger's bytes at an application cell (storage spec §9, rule 3) ─────

/// What this device keeps of one seat's log at a cell at most
/// (`route_seats::HELD_LOG_BUDGET`).
const ONE_SEATS_LOG: usize = 8 * 1024 * 1024;

/// What someone holding no key of a cell can put at it: writes whose own
/// bytes derive the cell, carrying bytes no writer signed where the
/// signature goes. Everything they are built from is public: the
/// application's genesis, the cell's name and the writers' public keys.
/// Distinct ones, each as large as a write may be, until they pass `over`
/// bytes in all.
fn a_strangers_writes(
    application: [u8; 32],
    name: &[u8],
    writers: &dsm::app_cell::WriterSet,
    over: usize,
) -> Vec<Vec<u8>> {
    let unsigned = vec![0xA5; dsm::app_cell::MAX_SIGNATURE_BYTES];
    let mut made = Vec::new();
    let mut bytes = 0usize;
    while bytes <= over {
        let mut payload = vec![0x5A; dsm::app_cell::MAX_PAYLOAD_BYTES];
        payload[..8].copy_from_slice(&(made.len() as u64).to_be_bytes());
        let write = dsm::app_cell::AppCellWrite::new(
            application,
            name,
            writers.clone(),
            0,
            &payload,
            &unsigned,
        )
        .expect("bytes within a write's bounds")
        .encode();
        bytes += write.len();
        made.push(write);
    }
    made
}

/// As many bytes as `like`, the same sizes, that are no write at all.
fn bytes_that_are_no_write(like: &[Vec<u8>]) -> Vec<Vec<u8>> {
    like.iter()
        .enumerate()
        .map(|(n, write)| {
            let mut bytes = vec![0xEE; write.len()];
            bytes[..8].copy_from_slice(&(n as u64).to_be_bytes());
            bytes
        })
        .collect()
}

/// The cell `application` names `name` for `writers`, derived from public
/// values alone, over the network's pinned set.
fn cell_from_public_values(
    set: &crate::sdk::storage_set::StorageSet,
    application: &[u8; 32],
    name: &[u8],
    writers: &dsm::app_cell::WriterSet,
) -> dsm::app_cell::AppCell {
    let key = crate::sdk::app_cell_flow::cell_of(application, name, writers);
    dsm::app_cell::AppCell::new(
        &key,
        &crate::sdk::storage_set::as_ccb_members(set).expect("the set's members"),
        &set.id(),
    )
    .expect("the cell over the pinned set")
}

/// Put `values` at `cell`'s leader the way any client of the set can: the
/// member's cell route, which asks for no key and no signature.
pub(super) async fn put_at_the_leader(
    set: &crate::sdk::storage_set::StorageSet,
    routed: &dsm::route_chain::RoutedCell,
    values: &[Vec<u8>],
) {
    let client = crate::sdk::storage_node_sdk::SetClient::new(set).expect("a client of the set");
    let leader = client
        .member(routed.route().leader())
        .expect("the leader is a member of the set");
    let entries: Vec<crate::sdk::route_seats::CellPut> = values
        .iter()
        .map(|value| {
            let entry = dsm::route_chain::RouteEntry::at_leader(
                routed.namespace().to_vec(),
                *routed.key(),
                value.clone(),
                routed.route(),
            );
            (routed.namespace().to_vec(), *routed.key(), entry.encode())
        })
        .collect();
    // A member takes at most 1 MiB a request.
    let mut batch: Vec<crate::sdk::route_seats::CellPut> = Vec::new();
    let mut batch_bytes = 0usize;
    for entry in entries {
        if batch_bytes + entry.2.len() > 900 * 1024 {
            leader
                .put_cells(&batch)
                .await
                .expect("a member keeps any bytes it is given at a cell");
            batch.clear();
            batch_bytes = 0;
        }
        batch_bytes += entry.2.len();
        batch.push(entry);
    }
    if let Some(..) = batch.first() {
        leader
            .put_cells(&batch)
            .await
            .expect("a member keeps any bytes it is given at a cell");
    }
}

/// Storage spec §9, route chains, rule 3: bytes at a seat that are no
/// recognized object naming the cell never count, and block nothing.
///
/// A stranger to a faction, holding no key of its cells, derives the cell of
/// the faction's next step from public values and puts a little over one
/// seat's log budget of well-formed writes there that no writer signed,
/// through the node's ordinary cell route. A member's wallet then writes the
/// step through its grant. The step must hold the cell, final, exactly as it
/// does at a cell where the stranger put as many bytes that are no write.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_strangers_unsigned_writes_at_a_cell_block_no_members_write() {
    let p = Pair::boot(100, 100).await;
    let r = game(&p).await;
    let relay = ForwardRelay::start().await;
    let code_a = state_offer(&r, &relay).await;
    let sid_a = connect_shown(&r, &p.a, &relay, &code_a, STATE_LINE).await;
    let code_b = state_offer(&r, &relay).await;
    let sid_b = connect_shown(&r, &p.b, &relay, &code_b, STATE_LINE).await;
    let as_a = player_of(&r, &sid_a).await;
    let as_b = player_of(&r, &sid_b).await;
    let members = [&as_a, &as_b];

    // What the stranger knows: the game's genesis, the two wallets' public
    // keys, and the names the game gives its cells.
    r.enter();
    let set = crate::sdk::storage_set::canonical_set(crate::economic_fixtures::NETWORK)
        .expect("the pinned set");
    let writers = crate::sdk::app_cell_flow::writers(&[
        as_a.peer_signing_key.clone(),
        as_b.peer_signing_key.clone(),
    ])
    .expect("the faction's writers");

    // Step 1, untouched: held and final, at the cell the stranger derives.
    let first = request(
        &r,
        &relay,
        &sid_a,
        cell_write(b"faction 4 / step 1", &members, b"place watchtower at 4,9"),
    )
    .await;
    assert_eq!(sync(&p.a, &r, &relay).await, "");
    let held = status(&r, &sid_a, first).await;
    assert_eq!(
        fact(&held),
        generated::ConnectFact::AppCellHeld,
        "{}",
        held.fact_detail
    );
    assert_eq!(
        held.app_cell,
        cell_from_public_values(&set, &r.genesis, b"faction 4 / step 1", &writers)
            .key()
            .to_vec(),
        "public values derive the faction's cell"
    );

    // Step 3's cell: the stranger puts bytes that are no write. They block
    // nothing.
    let unsigned = a_strangers_writes(r.genesis, b"faction 4 / step 2", &writers, ONE_SEATS_LOG);
    let third_cell = cell_from_public_values(&set, &r.genesis, b"faction 4 / step 3", &writers);
    put_at_the_leader(
        &set,
        third_cell.routed(),
        &bytes_that_are_no_write(&unsigned),
    )
    .await;
    let third = request(
        &r,
        &relay,
        &sid_a,
        cell_write(b"faction 4 / step 3", &members, b"raise gate at 1,1"),
    )
    .await;
    let third_sync = sync(&p.a, &r, &relay).await;
    let third_status = status(&r, &sid_a, third).await;
    assert_eq!(
        fact(&third_status),
        generated::ConnectFact::AppCellHeld,
        "bytes that are no write blocked a member: sync {third_sync:?}; {}",
        third_status.fact_detail
    );

    // Step 2's cell: the stranger puts as many bytes, as writes for the cell
    // that no writer signed.
    let second_cell = cell_from_public_values(&set, &r.genesis, b"faction 4 / step 2", &writers);
    put_at_the_leader(&set, second_cell.routed(), &unsigned).await;
    let second = request(
        &r,
        &relay,
        &sid_b,
        cell_write(b"faction 4 / step 2", &members, b"place wall at 2,2"),
    )
    .await;
    let second_sync = sync(&p.b, &r, &relay).await;
    let wallet = wallet_log(&p.b, &sid_b, second).await;
    let second_status = status(&r, &sid_b, second).await;
    assert_eq!(
        fact(&second_status),
        generated::ConnectFact::AppCellHeld,
        "{} unsigned writes ({} bytes) from a stranger at the cell's leader blocked a member's \
         write. The wallet's sync: {second_sync:?}. The wallet's log: {} / {}. The game's \
         reading: {}",
        unsigned.len(),
        unsigned.iter().map(Vec::len).sum::<usize>(),
        wallet.summary,
        wallet.detail,
        second_status.fact_detail
    );
}

// ── a losing player's bytes at a match's verdict cell ───────────────────────

/// What a player of a match can put at its verdict cell without the game's
/// key: verdicts whose `Y` and outcome table derive the cell, carrying bytes
/// nobody signed where the signatures go, under keys that decide nothing.
/// The player's own wallet built the terms, so it holds `Y` and the table.
/// Distinct ones, each as large as a verdict may be, until they pass `over`
/// bytes in all.
fn a_players_unsigned_verdicts(terms: &dsm::sofi::wire::EscrowTerms, over: usize) -> Vec<Vec<u8>> {
    let mut made = Vec::new();
    let mut bytes = 0usize;
    while bytes <= over {
        let signatures = (1..=dsm::sofi::wire::ESCROW_MAX_SIGNERS as u8)
            .map(|n| {
                let signer = crate::sdk::connect::wager::signer(&[n; 64]).expect("a key's width");
                let mut unsigned = vec![0xA5; 64 * 1024];
                unsigned[..8].copy_from_slice(&(made.len() as u64).to_be_bytes());
                dsm::sofi::wire::VerdictSignature::new(signer, &unsigned)
                    .expect("bytes within a signature's bounds")
            })
            .collect();
        let verdict = dsm::sofi::wire::EscrowVerdict::new(
            *terms.external_commitment(),
            terms.outcome_table(),
            crate::sdk::connect::wager::B_WINS,
            signatures,
        )
        .expect("bytes within a verdict's bounds")
        .encode();
        bytes += verdict.len();
        made.push(verdict);
    }
    made
}

/// Storage spec §9, route chains, rule 3, at a verdict cell (SoFi §19.9):
/// bytes that are no recognized verdict never count, and block nothing.
///
/// Two players stake a match the game referees. B, who expects to lose,
/// derives the match's verdict cell from the terms its own wallet built and
/// puts a little over one seat's log budget of well-formed verdicts there
/// that nobody signed, through the node's ordinary cell route. The game then
/// decides `a-wins` and A collects. A must be paid both stakes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_losing_players_unsigned_verdicts_do_not_keep_the_winner_from_the_stakes() {
    use crate::sdk::connect::grant::Side;
    use crate::sdk::connect::wager;

    let p = Pair::boot(100, 100).await;
    let r = game(&p).await;
    let relay = ForwardRelay::start().await;
    let code_a = offer(&r, &relay).await;
    let sid_a = connect(&r, &p.a, &relay, &code_a).await;
    let code_b = offer(&r, &relay).await;
    let sid_b = connect(&r, &p.b, &relay, &code_b).await;
    let (as_a, as_b) = (player_of(&r, &sid_a).await, player_of(&r, &sid_b).await);
    let stake = whole_era(25);
    let external = b"arena match 9: A v B";

    let lock_a = request(&r, &relay, &sid_a, lock(external, stake, 1, &as_b, None)).await;
    assert_eq!(sync(&p.a, &r, &relay).await, "");
    carried_out(&p.a, &sid_a, lock_a).await;
    let (a_vault, cell) = locked(&r, &sid_a, lock_a, stake).await;
    let lock_b = request(
        &r,
        &relay,
        &sid_b,
        lock(external, stake, 2, &as_a, Some(&a_vault)),
    )
    .await;
    assert_eq!(sync(&p.b, &r, &relay).await, "");
    carried_out(&p.b, &sid_b, lock_b).await;
    let (b_vault, b_cell) = locked(&r, &sid_b, lock_b, stake).await;
    assert_eq!(b_cell, cell);
    assert_eq!(balance(&p.a, &era()), whole_era(100) - stake);
    assert_eq!(balance(&p.b, &era()), whole_era(100) - stake);

    // B's wallet built these terms for its own stake: the match, the two
    // players and the game's key.
    let player = |s: &generated::ConnectSessionV1| wager::Player {
        genesis: s.peer_genesis.as_slice().try_into().expect("a genesis"),
        device_id: s.peer_device_id.as_slice().try_into().expect("a device"),
        signer: wager::signer(&s.peer_signing_key).expect("a player's key"),
    };
    let referee = wager::Referee {
        device_id: r.device_id,
        signer: wager::signer(&r.ak_pk).expect("the game's key"),
    };
    let terms = wager::terms(
        external,
        era(),
        Side::B,
        &player(&as_b),
        &player(&as_a),
        &referee,
    )
    .expect("the match template");
    let verdict_cell = dsm::sofi::escrow::verdict_cell_of(&terms);
    assert_eq!(
        verdict_cell.to_vec(),
        cell,
        "the terms B's wallet built derive the match's verdict cell"
    );

    r.enter();
    let set = crate::sdk::storage_set::canonical_set(crate::economic_fixtures::NETWORK)
        .expect("the pinned set");
    let routed = dsm::sofi::escrow::VerdictCell::new(
        &verdict_cell,
        &crate::sdk::storage_set::as_ccb_members(&set).expect("the set's members"),
        &set.id(),
    )
    .expect("the verdict cell over the pinned set");
    let unsigned = a_players_unsigned_verdicts(&terms, ONE_SEATS_LOG);
    put_at_the_leader(&set, routed.routed(), &unsigned).await;

    // The game decides, and the winner collects.
    let decided = invoke(
        &r,
        "escrow.adjudicate",
        args(&generated::EscrowOutcomeRequest {
            vault_id: a_vault.clone(),
            outcome: b"a-wins".to_vec(),
        }),
    )
    .await;
    let collect_a = request(&r, &relay, &sid_a, collect(&[&a_vault, &b_vault])).await;
    let collect_sync = sync(&p.a, &r, &relay).await;
    let wallet = wallet_log(&p.a, &sid_a, collect_a).await;
    let collected = status(&r, &sid_a, collect_a).await;
    assert_eq!(
        balance(&p.a, &era()),
        whole_era(100) + stake,
        "{} unsigned verdicts ({} bytes) from the losing player at the verdict cell's leader          kept the winner from the stakes. The game's adjudication answered: {:?}. The winner's          sync: {collect_sync:?}. The winner's log: {} / {}. The game's reading: {}",
        unsigned.len(),
        unsigned.iter().map(Vec::len).sum::<usize>(),
        decided.error_message,
        wallet.summary,
        wallet.detail,
        collected.fact_detail
    );
}
