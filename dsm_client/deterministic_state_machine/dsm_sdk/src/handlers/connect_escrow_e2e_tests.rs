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
            }],
            token_anchors: Vec::new(),
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
        vec!["Lock stakes for matches: up to 30.00 ERA a time, 60.00 ERA in all".to_string()]
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
        (listed.peer_device_id.as_slice(), listed.peer_genesis.as_slice(), listed.peer_signing_key.as_slice()),
        (held.wallet_device_id.as_slice(), held.wallet_genesis.as_slice(), held.wallet_ak.as_slice()),
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
    let code = offer(&r, &relay).await;
    let sid_a = connect(&r, &p.a, &relay, &code).await;
    let sid_b = connect(&r, &p.b, &relay, &code).await;
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
    let code = offer(&r, &relay).await;
    let sid_a = connect(&r, &p.a, &relay, &code).await;
    let sid_b = connect(&r, &p.b, &relay, &code).await;
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
    let code = offer(&r, &relay).await;
    let sid_a = connect(&r, &p.a, &relay, &code).await;
    let sid_b = connect(&r, &p.b, &relay, &code).await;
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
    let code = offer(r, relay).await;
    let sid_a = connect(r, &p.a, relay, &code).await;
    let sid_b = connect(r, &p.b, relay, &code).await;
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
        let read: Vec<String> = asked(&p)
            .into_iter()
            .filter(|r| r.contains("/api/v2/cell/") || r.contains("/api/v2/index/"))
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
