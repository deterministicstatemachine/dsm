// SPDX-License-Identifier: MIT OR Apache-2.0

//! DSM Connect on storage nodes (DSM Amendment A11): what the real connection
//! cannot hold still.
//!
//! The connection as deployed — the application's own host and relay, the
//! wallet's listener and both inbox pollers, nothing carried by hand — is
//! `crates/dsm-app-host/tests/real_connection.rs`. These tests hold what it
//! cannot: an ordering the test forces, and a relay that misbehaves.
//!
//! Two devices on the pinned set's nodes on Postgres (`test_support::nodes`):
//! A is a Web2 application's own account, B a player's wallet. Every step is
//! a production route on the device that takes it. Between them sits the
//! test's store-and-forward relay over TLS: it serves the offer and the
//! requests A signed and keeps what B posts, and the test carries what it
//! kept to A when the test decides. A relay is only transport under A11, so
//! one that replays, withholds or forges is the adversary both sides must
//! withstand.

use std::sync::{Arc, Mutex};

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use dsm::types::proto as generated;
use generated::connect_reply_v1::Reply;
use generated::envelope::Payload;
use prost::Message;
use serial_test::serial;

use super::node_e2e_tests::{adopt, args, balance, create_token, era, invoke, payload};
use crate::bridge::{AppQuery, AppRouter as _};
use crate::test_support::two_device::{Pair, TestDevice};
use crate::util::text_id::{decode_base32_crockford, encode_base32_crockford};

/// What the relay serves for the requests read.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Serve {
    /// The requests above the read's `after`, as an honest relay does.
    Above,
    /// Every request the session has, whatever `after` asks: a relay that
    /// replays what the wallet already processed.
    Everything,
}

pub(super) struct Held {
    pub(super) offer: Option<([u8; 32], Vec<u8>)>,
    pub(super) accepts: Vec<Vec<u8>>,
    pub(super) requests: Vec<Vec<u8>>,
    pub(super) responses: Vec<Vec<u8>>,
    serve: Serve,
    /// Whether the relay takes answers, or is down and refuses every one, as an unreachable application's would.
    answers: Reach,
    /// What a stalled answer waits on.
    stalled: Arc<tokio::sync::Notify>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Reach {
    Up,
    Down,
    /// It takes the wallet's notices that it ended a session, and holds
    /// every other answer unanswered until the test lets it go: an
    /// application's endpoint that stalls.
    Stall,
}

type Shared = Arc<Mutex<Held>>;

/// A store-and-forward relay on a self-signed certificate.
pub(super) struct ForwardRelay {
    pub(super) endpoint: String,
    pub(super) pin: [u8; 32],
    held: Shared,
    _handle: axum_server::Handle<std::net::SocketAddr>,
}

fn id32(text: &str) -> [u8; 32] {
    let bytes = decode_base32_crockford(&text.to_ascii_uppercase()).expect("a Base32 id");
    bytes.as_slice().try_into().expect("a 32-byte id")
}

async fn serve_offer(State(held): State<Shared>, Path(digest): Path<String>) -> impl IntoResponse {
    let held = held.lock().expect("the relay");
    match &held.offer {
        Some((d, offer)) if *d == id32(&digest) => (StatusCode::OK, offer.clone()),
        _ => (StatusCode::NOT_FOUND, Vec::new()),
    }
}

async fn keep_accept(State(held): State<Shared>, body: Bytes) -> StatusCode {
    held.lock().expect("the relay").accepts.push(body.to_vec());
    StatusCode::OK
}

async fn serve_requests(
    State(held): State<Shared>,
    Path((session, after)): Path<(String, u64)>,
) -> Vec<u8> {
    let session = id32(&session);
    let held = held.lock().expect("the relay");
    let requests = held
        .requests
        .iter()
        .map(|bytes| generated::AppRequestV1::decode(bytes.as_slice()).expect("a request"))
        .filter(|r| {
            let body = generated::AppRequestBodyV1::decode(r.body.as_slice()).expect("a body");
            body.session_id.as_slice() == session.as_slice()
                && (held.serve == Serve::Everything || body.seq > after)
        })
        .collect();
    generated::AppRequestBatchV1 { requests }.encode_to_vec()
}

async fn keep_response(State(held): State<Shared>, body: Bytes) -> StatusCode {
    let stalled = {
        let mut kept = held.lock().expect("the relay");
        let seq = generated::AppResponseV1::decode(body.as_ref())
            .and_then(|r| generated::AppResponseBodyV1::decode(r.body.as_slice()))
            .map(|b| b.seq);
        match (kept.answers, seq) {
            (Reach::Down, _) => return StatusCode::SERVICE_UNAVAILABLE,
            (Reach::Stall, Ok(seq)) if seq != crate::handlers::connect_routes::DISCONNECT_SEQ => {
                kept.stalled.clone()
            }
            (Reach::Up | Reach::Stall, _) => {
                kept.responses.push(body.to_vec());
                return StatusCode::OK;
            }
        }
    };
    stalled.notified().await;
    StatusCode::SERVICE_UNAVAILABLE
}

impl ForwardRelay {
    pub(super) async fn start() -> Self {
        crate::sdk::tls_transport_sdk::ensure_rustls_crypto_provider();
        let made = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into(), "localhost".into()])
            .expect("the relay's certificate");
        let cert = made.cert.der().to_vec();
        let pin = crate::sdk::connect::signed::cert_pin(&cert);
        let config = axum_server::tls_rustls::RustlsConfig::from_der(
            vec![cert],
            made.signing_key.serialize_der(),
        )
        .await
        .expect("the relay's TLS config");
        let held: Shared = Arc::new(Mutex::new(Held {
            offer: None,
            accepts: Vec::new(),
            requests: Vec::new(),
            responses: Vec::new(),
            answers: Reach::Up,
            serve: Serve::Above,
            stalled: Arc::new(tokio::sync::Notify::new()),
        }));
        let app = axum::Router::new()
            .route("/connect/offer/{digest}", get(serve_offer))
            .route("/connect/accept", post(keep_accept))
            .route("/connect/requests/{session}/{after}", get(serve_requests))
            .route("/connect/responses", post(keep_response))
            .with_state(held.clone());
        let handle: axum_server::Handle<std::net::SocketAddr> = axum_server::Handle::new();
        let server = axum_server::bind_rustls("127.0.0.1:0".parse().expect("an address"), config)
            .handle(handle.clone());
        tokio::spawn(async move { server.serve(app.into_make_service()).await });
        let addr = handle.listening().await.expect("the relay listens");
        Self {
            endpoint: format!("https://127.0.0.1:{}", addr.port()),
            pin,
            held,
            _handle: handle,
        }
    }

    /// The relay taking answers again, or down (the application unreachable).
    pub(super) fn answers(&self, reach: Reach) {
        self.held().answers = reach;
    }

    /// Let the stalled answer go, now or as soon as it arrives: it is
    /// refused.
    pub(super) fn release_stalled(&self) {
        self.held().stalled.notify_one();
    }

    pub(super) fn held(&self) -> std::sync::MutexGuard<'_, Held> {
        self.held.lock().expect("the relay")
    }
}

pub(super) fn reply(r: &crate::bridge::AppResult) -> Reply {
    match payload(r) {
        Payload::ConnectReply(generated::ConnectReplyV1 { reply: Some(reply) }) => reply,
        other => panic!("a connect route answered {other:?}"),
    }
}

pub(super) async fn query(d: &TestDevice, path: &str, params: Vec<u8>) -> crate::bridge::AppResult {
    d.enter();
    d.router()
        .query(AppQuery {
            path: path.to_string(),
            params,
        })
        .await
}

fn cap(token: &[u8; 32], per_request: u64, total: u64) -> generated::ConnectCapV1 {
    generated::ConnectCapV1 {
        policy_commit: token.to_vec(),
        per_request,
        total,
    }
}

/// The scopes a game asks for: accept the objects it issues, take payment in
/// its coin, swap the coin against ERA spending ERA, see the coin, and see
/// which of the wallet's contacts play (DSM Amendment A16).
fn game_scopes(wild: &[u8; 32]) -> Vec<generated::ConnectScopeV1> {
    vec![
        generated::ConnectScopeV1 {
            kind: generated::ConnectScopeKind::AcceptIssued as i32,
            ..Default::default()
        },
        generated::ConnectScopeV1 {
            kind: generated::ConnectScopeKind::Pay as i32,
            caps: vec![cap(wild, 10, 30)],
            ..Default::default()
        },
        generated::ConnectScopeV1 {
            kind: generated::ConnectScopeKind::Swap as i32,
            policy_commits: vec![wild.to_vec(), era().to_vec()],
            caps: vec![cap(&era(), 1_000, 2_000)],
            programs: Vec::new(),
        },
        generated::ConnectScopeV1 {
            kind: generated::ConnectScopeKind::Holdings as i32,
            policy_commits: vec![wild.to_vec()],
            ..Default::default()
        },
        generated::ConnectScopeV1 {
            kind: generated::ConnectScopeKind::Contacts as i32,
            ..Default::default()
        },
    ]
}

/// A's offer through `relay`, which then serves it. The code.
async fn offer(
    a: &TestDevice,
    relay: &ForwardRelay,
    wild: &[u8; 32],
) -> generated::ConnectAppOfferV1 {
    let made = invoke(
        a,
        "connect.app.offer",
        args(&generated::ConnectAppOfferRequestV1 {
            display_name: "Wildstate".into(),
            endpoint: relay.endpoint.clone(),
            cert_pin: relay.pin.to_vec(),
            scopes: game_scopes(wild),
            token_anchors: vec![wild.to_vec()],
        }),
    )
    .await;
    let Reply::Offer(offer) = reply(&made) else {
        panic!("connect.app.offer answered another reply");
    };
    let digest: [u8; 32] = offer.offer_digest.as_slice().try_into().expect("a digest");
    relay.held().offer = Some((digest, offer.offer.clone()));
    offer
}

/// B previews and approves the code; A takes the accept the relay kept. The
/// session id.
async fn connect(p: &Pair, relay: &ForwardRelay, code: &str) -> [u8; 32] {
    connect_to_coin(p, relay, code, "WILD").await
}

/// [`connect`], for a game whose coin is `ticker`.
async fn connect_to_coin(p: &Pair, relay: &ForwardRelay, code: &str, ticker: &str) -> [u8; 32] {
    let previewed = query(
        &p.b,
        "connect.preview",
        args(&generated::ConnectPreviewRequestV1 { code: code.into() }),
    )
    .await;
    let Reply::Preview(preview) = reply(&previewed) else {
        panic!("connect.preview answered another reply");
    };
    assert_eq!(preview.display_name, "Wildstate");
    assert_eq!(preview.app_device_id, p.a.device_id.to_vec());
    // The wallet has not rooted the game's coin yet, and still names it: the
    // approval screen reads the policy the anchor commits to.
    assert!(
        preview
            .scope_lines
            .iter()
            .any(|l| l.contains(&format!("10 {ticker} a time"))),
        "{:?}",
        preview.scope_lines
    );
    let approved = invoke(
        &p.b,
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
    let accepted = invoke(&p.a, "connect.app.accept", args_raw(accept)).await;
    let Reply::Session(app_side) = reply(&accepted) else {
        panic!("connect.app.accept answered another reply");
    };
    assert_eq!(app_side.session_id, wallet_side.session_id);
    assert_eq!(app_side.peer_device_id, p.b.device_id.to_vec());
    wallet_side
        .session_id
        .as_slice()
        .try_into()
        .expect("a session id")
}

/// An `ArgPack` around bytes already encoded.
pub(super) fn args_raw(body: Vec<u8>) -> Vec<u8> {
    generated::ArgPack {
        codec: generated::Codec::Proto as i32,
        body,
        ..Default::default()
    }
    .encode_to_vec()
}

/// A signs a request, and the relay serves it. Its sequence number.
pub(super) async fn request(
    a: &TestDevice,
    relay: &ForwardRelay,
    session: &[u8; 32],
    kind: generated::connect_app_request_intent_v1::Kind,
) -> u64 {
    let signed = invoke(
        a,
        "connect.app.request",
        args(&generated::ConnectAppRequestIntentV1 {
            session_id: session.to_vec(),
            kind: Some(kind),
        }),
    )
    .await;
    let Reply::Request(made) = reply(&signed) else {
        panic!("connect.app.request answered another reply");
    };
    let served = query(
        a,
        "connect.app.requests",
        args(&generated::ConnectAppRequestsQueryV1 {
            session_id: session.to_vec(),
            after: made.seq - 1,
        }),
    )
    .await;
    let Reply::Requests(batch) = reply(&served) else {
        panic!("connect.app.requests answered another reply");
    };
    assert_eq!(batch.requests.len(), 1);
    relay
        .held()
        .requests
        .push(batch.requests[0].encode_to_vec());
    made.seq
}

/// B's `connect.sync`; then A takes every answer the relay kept.
async fn sync_and_deliver(p: &Pair, relay: &ForwardRelay) -> generated::ConnectSessionsV1 {
    let synced = invoke(&p.b, "connect.sync", Vec::new()).await;
    let Reply::Sessions(sessions) = reply(&synced) else {
        panic!("connect.sync answered another reply");
    };
    let answers = std::mem::take(&mut relay.held().responses);
    for answer in answers {
        let taken = invoke(&p.a, "connect.app.respond", args_raw(answer)).await;
        reply(&taken);
    }
    sessions
}

/// B's `connect.sync` and A taking the answers, with every request the
/// relay served processed: the sync completed.
async fn sync_clean(p: &Pair, relay: &ForwardRelay) {
    let synced = sync_and_deliver(p, relay).await;
    for s in &synced.sessions {
        assert_eq!(s.last_error, "", "the sync did not complete");
    }
}

/// The wallet's own log of what it did with request `seq`.
pub(super) async fn wallet_log(
    b: &TestDevice,
    session: &[u8; 32],
    seq: u64,
) -> generated::ConnectLogEntryV1 {
    let logged = query(
        b,
        "connect.log",
        args(&generated::ConnectSessionRefV1 {
            session_id: session.to_vec(),
        }),
    )
    .await;
    let Reply::Log(log) = reply(&logged) else {
        panic!("connect.log answered another reply");
    };
    log.entries
        .into_iter()
        .find(|e| e.seq == seq)
        .expect("the wallet logged the request")
}

/// The wallet carried out request `seq`, by its own log.
pub(super) async fn carried_out(b: &TestDevice, session: &[u8; 32], seq: u64) {
    let entry = wallet_log(b, session, seq).await;
    assert_eq!(
        generated::ConnectOutcome::try_from(entry.outcome),
        Ok(generated::ConnectOutcome::CarriedOut),
        "request {seq} ({}): {}",
        entry.summary,
        entry.detail
    );
}

pub(super) async fn status(
    a: &TestDevice,
    session: &[u8; 32],
    seq: u64,
) -> generated::ConnectAppStatusV1 {
    let checked = invoke(
        a,
        "connect.app.status",
        args(&generated::ConnectRequestRefV1 {
            session_id: session.to_vec(),
            seq,
        }),
    )
    .await;
    let Reply::Status(status) = reply(&checked) else {
        panic!("connect.app.status answered another reply");
    };
    status
}

pub(super) fn fact(s: &generated::ConnectAppStatusV1) -> generated::ConnectFact {
    generated::ConnectFact::try_from(s.fact).expect("a known fact")
}

pub(super) fn outcome(s: &generated::ConnectAppStatusV1) -> generated::ConnectOutcome {
    generated::ConnectOutcome::try_from(s.outcome).expect("a known outcome")
}

/// A payment under the grant, asked while the wallet has received from the
/// game and the game has not yet taken the countersign: it waits, unanswered
/// and unspent, and the first sync after the relationship settles carries it
/// out. The game counts it only from the transfer its own account accepted.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_payment_under_the_grant_waits_while_the_relationship_settles() {
    let p = Pair::boot(500, 200).await;
    let wild = create_token(&p.a, "WILD", 1_000_000).await;
    let relay = ForwardRelay::start().await;
    let made = offer(&p.a, &relay, &wild).await;
    let session = connect(&p, &relay, &made.code).await;
    let sent = p.a.send_token(&p.b, "WILD", 50).await;
    assert!(sent.success, "{:?}", sent.error_message);
    p.b.sync().await;
    assert_eq!(balance(&p.b, &wild), 50);

    let pay = request(
        &p.a,
        &relay,
        &session,
        generated::connect_app_request_intent_v1::Kind::Pay(generated::ConnectPayV1 {
            policy_commit: wild.to_vec(),
            amount: 3,
            memo: "a capsule".into(),
        }),
    )
    .await;
    let waited = sync_and_deliver(&p, &relay).await;
    // The wallet answered nothing: its own log holds no entry for the payment.
    let logged = query(
        &p.b,
        "connect.log",
        args(&generated::ConnectSessionRefV1 {
            session_id: session.to_vec(),
        }),
    )
    .await;
    let Reply::Log(log) = reply(&logged) else {
        panic!("connect.log answered another reply");
    };
    assert!(
        log.entries.iter().all(|e| e.seq != pay),
        "{:?}",
        log.entries
    );
    assert!(
        waited.sessions[0]
            .last_error
            .contains("the relationship with the application is settling"),
        "{}",
        waited.sessions[0].last_error
    );
    assert_eq!(balance(&p.b, &wild), 50);

    settle(&p).await;
    sync_clean(&p, &relay).await;
    carried_out(&p.b, &session, pay).await;
    assert_eq!(balance(&p.b, &wild), 47);
    let paid = status(&p.a, &session, pay).await;
    assert_eq!(
        fact(&paid),
        generated::ConnectFact::Paid,
        "{}",
        paid.fact_detail
    );
    assert_eq!(balance(&p.a, &wild), 1_000_000 - 50 + 3);
}

/// A relay that serves every request the session has, whatever the wallet
/// asks for: a request the wallet already carried out is never carried out
/// again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_relay_replaying_every_request_runs_nothing_twice() {
    let p = Pair::boot(500, 200).await;
    let wild = create_token(&p.a, "WILD", 1_000_000).await;
    let relay = ForwardRelay::start().await;
    let made = offer(&p.a, &relay, &wild).await;
    let session = connect(&p, &relay, &made.code).await;
    let sent = p.a.send_token(&p.b, "WILD", 20).await;
    assert!(sent.success, "{:?}", sent.error_message);
    p.b.sync().await;
    settle(&p).await;

    let pay = request(
        &p.a,
        &relay,
        &session,
        generated::connect_app_request_intent_v1::Kind::Pay(generated::ConnectPayV1 {
            policy_commit: wild.to_vec(),
            amount: 3,
            memo: String::new(),
        }),
    )
    .await;
    sync_clean(&p, &relay).await;
    carried_out(&p.b, &session, pay).await;
    assert_eq!(balance(&p.b, &wild), 17);
    // Settled, so a payment run again would go through.
    settle(&p).await;

    relay.held().serve = Serve::Everything;
    let replayed = sync_and_deliver(&p, &relay).await;
    assert_eq!(balance(&p.b, &wild), 17, "no payment ran again");
    assert_eq!(replayed.sessions[0].last_error, "");
}

/// A coin's identity is its policy commit (SoFi §47). A payment under the
/// grant pays in the coin the grant names, so the wallet's ERA never moves
/// for it, and the request is not carried out while the wallet holds none of
/// the coin. (No coin a device creates or adopts is named ERA in any case:
/// `token_routes` `a_ticker_naming_a_builtin_is_neither_adopted_nor_created`.)
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_grant_payment_pays_in_the_coin_it_names_never_the_wallets_era() {
    let p = Pair::boot(500, 200).await;
    let named_era = create_token(&p.a, "GEMS", 1_000_000).await;
    assert_ne!(named_era, era(), "the app's coin is not ERA");
    let relay = ForwardRelay::start().await;
    let made = offer(&p.a, &relay, &named_era).await;
    let session = connect_to_coin(&p, &relay, &made.code, "GEMS").await;
    adopt(&p.b, &named_era).await;
    let wallet_era = balance(&p.b, &era());
    let app_era = balance(&p.a, &era());
    assert!(wallet_era > 0, "the wallet holds ERA to lose");

    let pay = request(
        &p.a,
        &relay,
        &session,
        generated::connect_app_request_intent_v1::Kind::Pay(generated::ConnectPayV1 {
            policy_commit: named_era.to_vec(),
            amount: 3,
            memo: String::new(),
        }),
    )
    .await;
    sync_and_deliver(&p, &relay).await;
    settle(&p).await;

    assert_eq!(
        balance(&p.b, &era()),
        wallet_era,
        "the wallet's ERA did not move"
    );
    assert_eq!(balance(&p.a, &era()), app_era, "the app was paid no ERA");
    assert_eq!(balance(&p.b, &named_era), 0);
    let entry = wallet_log(&p.b, &session, pay).await;
    assert_ne!(
        generated::ConnectOutcome::try_from(entry.outcome),
        Ok(generated::ConnectOutcome::CarriedOut),
        "a payment in a coin the wallet holds none of is not carried out: {}",
        entry.detail
    );
}

/// A wallet's answer is never evidence. An answer saying "paid" with no
/// transfer behind it grants nothing, and a holdings proof the wallet forged
/// proves no balance.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_wallets_answer_alone_establishes_nothing() {
    let p = Pair::boot(500, 200).await;
    let wild = create_token(&p.a, "WILD", 1_000_000).await;
    let relay = ForwardRelay::start().await;
    let made = offer(&p.a, &relay, &wild).await;
    let session = connect(&p, &relay, &made.code).await;
    let sent = p.a.send_token(&p.b, "WILD", 20).await;
    assert!(sent.success, "{:?}", sent.error_message);
    p.b.sync().await;

    // "Paid", signed by the wallet, with no transfer.
    let pay = request(
        &p.a,
        &relay,
        &session,
        generated::connect_app_request_intent_v1::Kind::Pay(generated::ConnectPayV1 {
            policy_commit: wild.to_vec(),
            amount: 3,
            memo: String::new(),
        }),
    )
    .await;
    p.b.enter();
    let claimed = crate::sdk::connect::wallet::signed_response(&generated::AppResponseBodyV1 {
        session_id: session.to_vec(),
        seq: pay,
        outcome: generated::ConnectOutcome::CarriedOut as i32,
        reason: String::new(),
        result: None,
    })
    .expect("the wallet signs");
    reply(&invoke(&p.a, "connect.app.respond", args_raw(claimed)).await);
    let unpaid = status(&p.a, &session, pay).await;
    assert_eq!(outcome(&unpaid), generated::ConnectOutcome::CarriedOut);
    assert_eq!(
        fact(&unpaid),
        generated::ConnectFact::None,
        "an answer saying paid grants nothing"
    );

    // A proof of 21 WILD from a wallet holding 20, signed by that wallet.
    let holdings = request(
        &p.a,
        &relay,
        &session,
        generated::connect_app_request_intent_v1::Kind::Holdings(generated::ConnectHoldingsV1 {
            policy_commits: vec![wild.to_vec()],
        }),
    )
    .await;
    p.b.enter();
    let mut proof = crate::sdk::connect::holdings::prove(&p.b.router().core_sdk, &[wild])
        .expect("the wallet's honest proof");
    assert_eq!(proof.holdings[0].amount, 20);
    proof.holdings[0].amount = 21;
    let forged = crate::sdk::connect::wallet::signed_response(&generated::AppResponseBodyV1 {
        session_id: session.to_vec(),
        seq: holdings,
        outcome: generated::ConnectOutcome::CarriedOut as i32,
        reason: String::new(),
        result: Some(generated::app_response_body_v1::Result::Holdings(proof)),
    })
    .expect("the wallet signs");
    reply(&invoke(&p.a, "connect.app.respond", args_raw(forged)).await);
    let refused = status(&p.a, &session, holdings).await;
    assert_eq!(fact(&refused), generated::ConnectFact::None);
    assert!(
        refused.holdings.is_empty(),
        "no balance from a forged proof"
    );
    assert!(
        refused
            .fact_detail
            .contains("does not recompute the validated root"),
        "{}",
        refused.fact_detail
    );

    // An honest proof the wallet has since moved past: it spends after
    // proving, so its next root cell is taken and the proof is not current.
    let stale = request(
        &p.a,
        &relay,
        &session,
        generated::connect_app_request_intent_v1::Kind::Holdings(generated::ConnectHoldingsV1 {
            policy_commits: vec![wild.to_vec()],
        }),
    )
    .await;
    p.b.enter();
    let honest = crate::sdk::connect::holdings::prove(&p.b.router().core_sdk, &[wild])
        .expect("the wallet's honest proof");
    let answered = crate::sdk::connect::wallet::signed_response(&generated::AppResponseBodyV1 {
        session_id: session.to_vec(),
        seq: stale,
        outcome: generated::ConnectOutcome::CarriedOut as i32,
        reason: String::new(),
        result: Some(generated::app_response_body_v1::Result::Holdings(honest)),
    })
    .expect("the wallet signs");
    reply(&invoke(&p.a, "connect.app.respond", args_raw(answered)).await);
    let spent = p.b.send_token(&p.a, "WILD", 5).await;
    assert!(spent.success, "{:?}", spent.error_message);
    let moved_on = status(&p.a, &session, stale).await;
    assert_eq!(fact(&moved_on), generated::ConnectFact::None);
    assert!(
        moved_on.fact_detail.contains("NotCurrent"),
        "{}",
        moved_on.fact_detail
    );
}

/// The code is the trust root. A relay serving another offer than the code
/// names, an offer signed by another key than its card's, and a relay on
/// another certificate than the code pins are each refused before the player
/// sees anything.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_wallet_refuses_an_offer_the_code_does_not_vouch_for() {
    let p = Pair::boot(500, 0).await;
    let wild = create_token(&p.a, "WILD", 1_000_000).await;
    let relay = ForwardRelay::start().await;
    let made = offer(&p.a, &relay, &wild).await;
    let code = crate::sdk::connect::code::parse(&made.code).expect("A's code");

    // Another offer of A's under the first one's digest.
    let other = invoke(
        &p.a,
        "connect.app.offer",
        args(&generated::ConnectAppOfferRequestV1 {
            display_name: "Another".into(),
            endpoint: relay.endpoint.clone(),
            cert_pin: relay.pin.to_vec(),
            scopes: game_scopes(&wild),
            token_anchors: vec![wild.to_vec()],
        }),
    )
    .await;
    let Reply::Offer(other) = reply(&other) else {
        panic!("connect.app.offer answered another reply");
    };
    relay.held().offer = Some((code.offer_digest, other.offer));
    let swapped = query(
        &p.b,
        "connect.preview",
        args(&generated::ConnectPreviewRequestV1 {
            code: made.code.clone(),
        }),
    )
    .await;
    assert!(
        swapped
            .error_message
            .as_deref()
            .is_some_and(|e| e.contains("another offer than the code names")),
        "{:?}",
        swapped.error_message
    );

    // A's own offer body, signed by a key that is not its card's.
    let genuine = generated::AppConnectOfferV1::decode(made.offer.as_slice()).expect("the offer");
    let stranger =
        dsm::crypto::sphincs::generate_keypair(dsm::crypto::sphincs::SphincsVariant::SPX256f)
            .expect("a key");
    let resigned = generated::AppConnectOfferV1 {
        body: genuine.body.clone(),
        signature: dsm::crypto::sphincs::sphincs_sign(
            &stranger.secret_key,
            dsm::crypto::blake3::domain_hash(
                dsm::common::domain_tags::TAG_DSM_CONNECT_OFFER,
                &genuine.body,
            )
            .as_bytes(),
        )
        .expect("a signature"),
    };
    relay.held().offer = Some((code.offer_digest, resigned.encode_to_vec()));
    let unsigned = query(
        &p.b,
        "connect.preview",
        args(&generated::ConnectPreviewRequestV1 {
            code: made.code.clone(),
        }),
    )
    .await;
    assert!(
        unsigned
            .error_message
            .as_deref()
            .is_some_and(|e| e.contains("does not verify under its signer's key")),
        "{:?}",
        unsigned.error_message
    );

    // The genuine offer behind a code pinning another certificate.
    relay.held().offer = Some((code.offer_digest, made.offer.clone()));
    let mut wrong_pin = code.clone();
    wrong_pin.cert_pin = crate::sdk::connect::signed::cert_pin(b"another certificate");
    let pinned = query(
        &p.b,
        "connect.preview",
        args(&generated::ConnectPreviewRequestV1 {
            code: crate::sdk::connect::code::encode(&wrong_pin),
        }),
    )
    .await;
    assert!(
        pinned.error_message.is_some(),
        "a relay on another certificate than the code pins is never read"
    );
    let honest = query(
        &p.b,
        "connect.preview",
        args(&generated::ConnectPreviewRequestV1 { code: made.code }),
    )
    .await;
    let Reply::Preview(preview) = reply(&honest) else {
        panic!("connect.preview answered another reply");
    };
    assert_eq!(preview.offer_digest, code.offer_digest.to_vec());
    assert_eq!(
        encode_base32_crockford(&preview.app_device_id),
        encode_base32_crockford(&p.a.device_id)
    );
}

/// The game's account takes in what it is owed and finalizes, and the
/// wallet takes in the finality, as each one's inbox poller does: the
/// relationship is ready for the wallet's next payment.
async fn settle(p: &Pair) {
    p.a.sync().await;
    p.b.sync().await;
}

/// A holdings request may name an object the wallet never held. The wallet
/// roots nothing: it reads the object's policy. One the game created is
/// inside the grant and proven not held, without asking; one another device
/// created is outside it, and the request waits for the player.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn holdings_of_an_object_never_held_are_covered_only_if_the_game_issued_it() {
    let p = Pair::boot(500, 200).await;
    let wild = create_token(&p.a, "WILD", 1_000_000).await;
    let relay = ForwardRelay::start().await;
    let made = offer(&p.a, &relay, &wild).await;
    let session = connect(&p, &relay, &made.code).await;
    // An object the game issued and never sent this wallet.
    let elsewhere = create_token(&p.a, "EM0009", 1).await;
    let asked = request(
        &p.a,
        &relay,
        &session,
        generated::connect_app_request_intent_v1::Kind::Holdings(generated::ConnectHoldingsV1 {
            policy_commits: vec![wild.to_vec(), elsewhere.to_vec()],
        }),
    )
    .await;
    sync_clean(&p, &relay).await;
    let proven = status(&p.a, &session, asked).await;
    assert_eq!(
        fact(&proven),
        generated::ConnectFact::Holdings,
        "{}",
        proven.fact_detail
    );
    let held: std::collections::BTreeMap<Vec<u8>, u64> = proven
        .holdings
        .iter()
        .map(|h| (h.policy_commit.clone(), h.amount))
        .collect();
    assert_eq!(held.get(elsewhere.as_slice()), Some(&0), "{held:?}");
    p.b.enter();
    assert!(
        crate::storage::client_db::token_registry::get_token_by_policy_commit(&elsewhere)
            .expect("the registry")
            .is_none(),
        "nothing is adopted"
    );

    // An object a third device created, unknown to this wallet: its policy
    // names another creator.
    let mut c = TestDevice::create("C", 0x0C);
    c.boot(&p.fleet).await;
    c.fund_admitted(100).await;
    let theirs = create_token(&c, "THIRD", 5).await;
    let foreign = request(
        &p.a,
        &relay,
        &session,
        generated::connect_app_request_intent_v1::Kind::Holdings(generated::ConnectHoldingsV1 {
            policy_commits: vec![wild.to_vec(), theirs.to_vec()],
        }),
    )
    .await;
    sync_and_deliver(&p, &relay).await;
    let waiting = status(&p.a, &session, foreign).await;
    assert_eq!(
        outcome(&waiting),
        generated::ConnectOutcome::AwaitingApproval,
        "{}",
        waiting.reason
    );
    assert_eq!(fact(&waiting), generated::ConnectFact::None);
}

/// SA-124. An application's request to accept an object another device
/// created is refused for that before anything is rooted: the wallet adopts
/// nothing. It rooted the object first and refused after, so another
/// creator's object stayed adopted, under the grant and without the player.
/// MUTATION CONTROL: rooting the object before its creator is checked, as
/// the wallet did, leaves it in the registry and turns this red.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn an_object_another_device_created_is_never_adopted_for_an_application() {
    let p = Pair::boot(500, 200).await;
    let wild = create_token(&p.a, "WILD", 1_000_000).await;
    let relay = ForwardRelay::start().await;
    let made = offer(&p.a, &relay, &wild).await;
    let session = connect(&p, &relay, &made.code).await;
    let mut c = TestDevice::create("C", 0x0C);
    c.boot(&p.fleet).await;
    c.fund_admitted(100).await;
    let theirs = create_token(&c, "THIRD", 5).await;

    let asked = request(
        &p.a,
        &relay,
        &session,
        generated::connect_app_request_intent_v1::Kind::AcceptIssued(
            generated::ConnectAcceptIssuedV1 {
                anchor: theirs.to_vec(),
            },
        ),
    )
    .await;
    sync_and_deliver(&p, &relay).await;
    let answered = status(&p.a, &session, asked).await;
    assert_ne!(
        outcome(&answered),
        generated::ConnectOutcome::CarriedOut,
        "{}",
        answered.reason
    );
    p.b.enter();
    assert!(
        crate::storage::client_db::token_registry::get_token_by_policy_commit(&theirs)
            .expect("the registry")
            .is_none(),
        "another creator's object is adopted"
    );
}

/// DSM Amendment A16, end to end: the game asks the wallet which of its
/// contacts are who, and the wallet, under the grant's contacts scope and
/// without asking its player, answers with each contact's device id and
/// nothing else — never the game's own account, which it keeps as a contact
/// since it connected. The answer is the wallet's word: it establishes no
/// fact.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn the_game_sees_the_wallets_contacts_as_device_ids_and_never_itself() {
    let p = Pair::boot(500, 200).await;
    let wild = create_token(&p.a, "WILD", 1_000_000).await;
    let relay = ForwardRelay::start().await;
    let made = offer(&p.a, &relay, &wild).await;
    let session = connect(&p, &relay, &made.code).await;
    let mut c = TestDevice::create("C", 0x0C);
    c.boot(&p.fleet).await;
    p.b.add_contact(&c).await;

    let asked = request(
        &p.a,
        &relay,
        &session,
        generated::connect_app_request_intent_v1::Kind::Contacts(generated::ConnectContactsV1 {}),
    )
    .await;
    sync_clean(&p, &relay).await;
    let answered = status(&p.a, &session, asked).await;
    assert_eq!(
        outcome(&answered),
        generated::ConnectOutcome::CarriedOut,
        "{}",
        answered.reason
    );
    assert_eq!(fact(&answered), generated::ConnectFact::None);
    let body = generated::AppResponseBodyV1::decode(answered.answer_body.as_slice())
        .expect("the wallet's answer");
    let Some(generated::app_response_body_v1::Result::Contacts(shared)) = body.result else {
        panic!("the wallet answered another result: {:?}", body.result);
    };
    let ids: Vec<Vec<u8>> = shared.contacts.into_iter().map(|c| c.device_id).collect();
    assert!(ids.contains(&c.device_id.to_vec()), "C is shared: {ids:?}");
    assert!(
        !ids.contains(&p.a.device_id.to_vec()),
        "the game's own account is never shared back to it"
    );
}

/// The answers the relay holds, each delivered to A once.
async fn deliver_each_once(p: &Pair, relay: &ForwardRelay) {
    let answers: std::collections::BTreeSet<Vec<u8>> = std::mem::take(&mut relay.held().responses)
        .into_iter()
        .collect();
    for answer in answers {
        reply(&invoke(&p.a, "connect.app.respond", args_raw(answer)).await);
    }
}

/// A payment the player approves while the relationship with the
/// application is still catching up is not lost: the approval is kept, the
/// request stays on the phone marked approved, and the first sync after the
/// relationship settles carries it out.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_payment_approved_by_hand_waits_while_the_relationship_settles() {
    let p = Pair::boot(500, 200).await;
    let wild = create_token(&p.a, "WILD", 1_000_000).await;
    let relay = ForwardRelay::start().await;
    let made = offer(&p.a, &relay, &wild).await;
    let session = connect(&p, &relay, &made.code).await;
    // The wallet receives from the game; the game has not taken its
    // countersign yet.
    let sent = p.a.send_token(&p.b, "WILD", 20).await;
    assert!(sent.success, "{:?}", sent.error_message);
    p.b.sync().await;

    // Outside the grant: ERA was never payable to the game.
    let outside = request(
        &p.a,
        &relay,
        &session,
        generated::connect_app_request_intent_v1::Kind::Pay(generated::ConnectPayV1 {
            policy_commit: era().to_vec(),
            amount: 1,
            memo: "approved by hand".into(),
        }),
    )
    .await;
    sync_clean(&p, &relay).await;
    let era_held = balance(&p.b, &era());
    let approved = invoke(
        &p.b,
        "connect.respond",
        args(&generated::ConnectRespondRequestV1 {
            session_id: session.to_vec(),
            seq: outside,
            decision: generated::ConnectDecision::Approve as i32,
        }),
    )
    .await;
    let Reply::Decided(decided) = reply(&approved) else {
        panic!("connect.respond answered another reply");
    };
    assert_eq!(
        generated::ConnectOutcome::try_from(decided.outcome),
        Ok(generated::ConnectOutcome::Unspecified),
        "{}",
        decided.line
    );
    assert!(decided.line.contains("approved"), "{}", decided.line);
    assert_eq!(balance(&p.b, &era()), era_held, "nothing is paid yet");
    let pending = query(&p.b, "connect.pending", Vec::new()).await;
    let Reply::Pending(list) = reply(&pending) else {
        panic!("connect.pending answered another reply");
    };
    assert_eq!(list.pending.len(), 1, "the approval is kept");
    assert_eq!(list.pending[0].seq, outside);
    assert!(list.pending[0].approved, "the request shows as approved");

    // The relationship settles, and the next sync carries the payment out.
    settle(&p).await;
    let synced = sync_and_deliver(&p, &relay).await;
    assert_eq!(synced.sessions[0].last_error, "");
    carried_out(&p.b, &session, outside).await;
    assert_eq!(balance(&p.b, &era()), era_held - 1);
    let pending = query(&p.b, "connect.pending", Vec::new()).await;
    let Reply::Pending(list) = reply(&pending) else {
        panic!("connect.pending answered another reply");
    };
    assert!(list.pending.is_empty(), "{:?}", list.pending);
    let paid = status(&p.a, &session, outside).await;
    assert_eq!(
        fact(&paid),
        generated::ConnectFact::Paid,
        "{}",
        paid.fact_detail
    );
}

/// SA-127. An application's endpoint that stalls holds nothing else: a
/// request outside the grant waits for the player, and the notice that it
/// waits goes to an endpoint that never answers; meanwhile the player's
/// disconnect of that very session completes. The notice is sent once the
/// session's lock is released, never under it.
/// MUTATION CONTROL: sending the waiting notice under the session's lock, as
/// `process` did under one lock for every application, holds the disconnect
/// behind the stalled endpoint and turns this red.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_stalled_application_holds_no_disconnect_of_its_session() {
    let p = Pair::boot(500, 200).await;
    let wild = create_token(&p.a, "WILD", 1_000_000).await;
    let relay = ForwardRelay::start().await;
    let made = offer(&p.a, &relay, &wild).await;
    let session = connect(&p, &relay, &made.code).await;
    request(
        &p.a,
        &relay,
        &session,
        generated::connect_app_request_intent_v1::Kind::Pay(generated::ConnectPayV1 {
            policy_commit: era().to_vec(),
            amount: 1,
            memo: "outside the grant".into(),
        }),
    )
    .await;
    relay.answers(Reach::Stall);
    let synced = invoke(&p.b, "connect.sync", Vec::new());
    let disconnected = async {
        // The sync reaches the request and stalls on its notice first.
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        let done = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            invoke(
                &p.b,
                "connect.disconnect",
                args(&generated::ConnectSessionRefV1 {
                    session_id: session.to_vec(),
                }),
            ),
        )
        .await;
        relay.release_stalled();
        done
    };
    let (_, disconnected) = tokio::join!(synced, disconnected);
    let disconnected =
        disconnected.expect("the disconnect is not held behind the stalled endpoint");
    assert!(disconnected.success, "{:?}", disconnected.error_message);
}

/// SA-81. An accept for a session the application already holds is
/// answered from what it holds, before its signature is checked or the
/// wallet's directory read: the same bytes again are that session, and the
/// same accept with its signature changed is refused as another accept for
/// it, not as a bad signature — nothing was verified for it.
/// MUTATION CONTROL: verifying the accept before the session is looked up,
/// as `connect.app.accept` did, answers the changed accept with a signature
/// failure and turns this red.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_replayed_accept_is_answered_before_it_is_verified() {
    let p = Pair::boot(500, 200).await;
    let wild = create_token(&p.a, "WILD", 1_000_000).await;
    let relay = ForwardRelay::start().await;
    let made = offer(&p.a, &relay, &wild).await;
    let session = connect(&p, &relay, &made.code).await;
    p.a.enter();
    let accept = crate::storage::client_db::connect::app_session(&session)
        .expect("the application's sessions")
        .expect("the session")
        .accept;

    let again = invoke(&p.a, "connect.app.accept", args_raw(accept.clone())).await;
    let Reply::Session(view) = reply(&again) else {
        panic!("connect.app.accept answered another reply");
    };
    assert_eq!(view.session_id, session.to_vec());

    let mut changed = generated::AppConnectAcceptV1::decode(accept.as_slice()).expect("an accept");
    changed.signature[0] ^= 0x01;
    let refused = invoke(
        &p.a,
        "connect.app.accept",
        args_raw(changed.encode_to_vec()),
    )
    .await;
    assert!(!refused.success, "a changed accept is not taken");
    let why = refused.error_message.expect("a refusal says why");
    assert!(
        why.contains("holds another accept"),
        "refused before its signature is checked: {why}"
    );
}

/// Two syncs at once, as the listener's and one the player starts: the
/// replay guard is read and the request carried out as one step, so a
/// payment runs once.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn two_syncs_at_once_carry_a_request_out_once() {
    let p = Pair::boot(500, 200).await;
    let wild = create_token(&p.a, "WILD", 1_000_000).await;
    let relay = ForwardRelay::start().await;
    let made = offer(&p.a, &relay, &wild).await;
    let session = connect(&p, &relay, &made.code).await;
    let sent = p.a.send_token(&p.b, "WILD", 20).await;
    assert!(sent.success, "{:?}", sent.error_message);
    p.b.sync().await;
    settle(&p).await;

    let pay = request(
        &p.a,
        &relay,
        &session,
        generated::connect_app_request_intent_v1::Kind::Pay(generated::ConnectPayV1 {
            policy_commit: wild.to_vec(),
            amount: 3,
            memo: String::new(),
        }),
    )
    .await;
    let (first, second) = tokio::join!(
        invoke(&p.b, "connect.sync", Vec::new()),
        invoke(&p.b, "connect.sync", Vec::new())
    );
    reply(&first);
    reply(&second);
    assert_eq!(balance(&p.b, &wild), 17, "the payment ran once");
    deliver_each_once(&p, &relay).await;
    carried_out(&p.b, &session, pay).await;
    let paid = status(&p.a, &session, pay).await;
    assert_eq!(
        fact(&paid),
        generated::ConnectFact::Paid,
        "{}",
        paid.fact_detail
    );
}

/// The player disconnects the application in the wallet: the application is
/// told by the wallet's own signature, its account reports the session ended,
/// it can ask nothing more over it, and a second approval while one session
/// stands is refused (DSM Amendment A11: a grant ends when the player
/// disconnects the application).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_disconnect_in_the_wallet_ends_the_session_on_the_applications_side_too() {
    let p = Pair::boot(500, 200).await;
    let wild = create_token(&p.a, "WILD", 1_000_000).await;
    let relay = ForwardRelay::start().await;
    let made = offer(&p.a, &relay, &wild).await;
    let sid = connect(&p, &relay, &made.code).await;

    // A second code from the same application: refused while the first session stands.
    let again = offer(&p.a, &relay, &wild).await;
    let previewed = query(
        &p.b,
        "connect.preview",
        args(&generated::ConnectPreviewRequestV1 {
            code: again.code.clone(),
        }),
    )
    .await;
    let Reply::Preview(preview) = reply(&previewed) else {
        panic!("connect.preview answered another reply");
    };
    let refused = invoke(
        &p.b,
        "connect.approve",
        args(&generated::ConnectApproveRequestV1 {
            offer_digest: preview.offer_digest.clone(),
            granted: Vec::new(),
        }),
    )
    .await;
    let why = refused
        .error_message
        .clone()
        .expect("a second approval is refused, with a reason");
    assert!(
        why.contains("already connected"),
        "a second session to a connected application: {why}"
    );

    // The application's account sees the session connected, then the wallet disconnects it.
    let listed = query(&p.a, "connect.app.sessions", Vec::new()).await;
    let Reply::Sessions(before) = reply(&listed) else {
        panic!("connect.app.sessions answered another reply");
    };
    assert_eq!(before.sessions.len(), 1);
    assert_eq!(
        before.sessions[0].status,
        generated::ConnectSessionStatus::Connected as i32
    );

    let ended = invoke(
        &p.b,
        "connect.disconnect",
        args(&generated::ConnectSessionRefV1 {
            session_id: sid.to_vec(),
        }),
    )
    .await;
    let Reply::Session(wallet_side) = reply(&ended) else {
        panic!("connect.disconnect answered another reply");
    };
    assert_eq!(
        wallet_side.status,
        generated::ConnectSessionStatus::Disconnected as i32
    );
    assert_eq!(
        wallet_side.last_error, "",
        "the application was told at once"
    );

    // The notice went over the relay, signed; the application's account takes it in.
    let notices = std::mem::take(&mut relay.held().responses);
    assert_eq!(notices.len(), 1, "one signed disconnect notice");
    let notice = generated::AppResponseV1::decode(notices[0].as_slice()).expect("an AppResponseV1");
    let body = generated::AppResponseBodyV1::decode(notice.body.as_slice()).expect("its body");
    assert_eq!(body.seq, 0, "a notice, answering no request");
    let taken = invoke(&p.a, "connect.app.respond", args_raw(notices[0].clone())).await;
    reply(&taken);

    let listed = query(&p.a, "connect.app.sessions", Vec::new()).await;
    let Reply::Sessions(after) = reply(&listed) else {
        panic!("connect.app.sessions answered another reply");
    };
    assert_eq!(
        after.sessions[0].status,
        generated::ConnectSessionStatus::Disconnected as i32
    );

    // Nothing more can be asked over it.
    let asked = invoke(
        &p.a,
        "connect.app.request",
        args(&generated::ConnectAppRequestIntentV1 {
            session_id: sid.to_vec(),
            kind: Some(generated::connect_app_request_intent_v1::Kind::Holdings(
                generated::ConnectHoldingsV1 {
                    policy_commits: Vec::new(),
                },
            )),
        }),
    )
    .await;
    let why = asked
        .error_message
        .clone()
        .expect("a request over an ended session is refused, with a reason");
    assert!(
        why.contains("disconnected"),
        "a request over an ended session: {why}"
    );

    // And the wallet may connect to the application again: a fresh session, the old one ended.
    relay.held().offer = Some((
        again.offer_digest.as_slice().try_into().expect("a digest"),
        again.offer.clone(),
    ));
    let fresh = connect(&p, &relay, &again.code).await;
    assert_ne!(fresh, sid);
}

/// An application unreachable when the player disconnects it is told at the
/// wallet's next sync: the notice is kept, and goes when the relay answers.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn an_unreachable_application_is_told_of_its_disconnect_at_the_next_sync() {
    let p = Pair::boot(500, 200).await;
    let wild = create_token(&p.a, "WILD", 1_000_000).await;
    let relay = ForwardRelay::start().await;
    let made = offer(&p.a, &relay, &wild).await;
    let sid = connect(&p, &relay, &made.code).await;
    relay.answers(Reach::Down);
    let ended = invoke(
        &p.b,
        "connect.disconnect",
        args(&generated::ConnectSessionRefV1 {
            session_id: sid.to_vec(),
        }),
    )
    .await;
    let Reply::Session(wallet_side) = reply(&ended) else {
        panic!("connect.disconnect answered another reply");
    };
    assert_eq!(
        wallet_side.status,
        generated::ConnectSessionStatus::Disconnected as i32
    );
    assert!(
        wallet_side.last_error.contains("not told yet"),
        "{}",
        wallet_side.last_error
    );
    assert!(relay.held().responses.is_empty());
    relay.answers(Reach::Up);
    invoke(&p.b, "connect.sync", Vec::new()).await;
    let notices = std::mem::take(&mut relay.held().responses);
    assert_eq!(notices.len(), 1, "the kept notice went at the sync");
    let taken = invoke(&p.a, "connect.app.respond", args_raw(notices[0].clone())).await;
    reply(&taken);
    let listed = query(&p.a, "connect.app.sessions", Vec::new()).await;
    let Reply::Sessions(after) = reply(&listed) else {
        panic!("connect.app.sessions answered another reply");
    };
    assert_eq!(
        after.sessions[0].status,
        generated::ConnectSessionStatus::Disconnected as i32
    );
}

/// The wallet's PIN lock, engaged on the process's session as the lock
/// screen engages it, and taken off again when the test ends, a failing one
/// included, so no lock outlives the test that set it.
struct WalletLock {
    pin: &'static str,
}

impl WalletLock {
    fn session() -> std::sync::MutexGuard<'static, crate::sdk::session_manager::SessionManager> {
        crate::sdk::session_manager::SESSION_MANAGER
            .lock()
            .expect("the session manager")
    }

    /// Enroll `pin` on the open wallet and lock it.
    fn engage(pin: &'static str) -> Self {
        let mut session = Self::session();
        *session = crate::sdk::session_manager::SessionManager::default();
        session
            .sync_lock_config_from_app_state()
            .expect("the lock settings");
        let on_pause = session.lock_on_pause;
        session.enable_lock("pin", pin, on_pause).expect("enrolled");
        session.lock_now().expect("locked");
        Self { pin }
    }

    fn open(&self) {
        let tried = Self::session().try_unlock(self.pin).expect("tried");
        assert_eq!(tried, crate::sdk::app_lock::Tried::Opened);
    }

    /// Lock the open wallet again.
    fn close(&self) {
        Self::session().lock_now().expect("locked");
    }
}

impl Drop for WalletLock {
    fn drop(&mut self) {
        let mut session = match crate::sdk::session_manager::SESSION_MANAGER.lock() {
            Ok(session) => session,
            Err(e) => {
                log::warn!("the test's lock was not taken off: {e}");
                return;
            }
        };
        if let Err(e) = session.try_unlock(self.pin) {
            log::warn!("the test's lock did not open: {e}");
        }
        let on_pause = session.lock_on_pause;
        if let Err(e) = session.disable_lock(on_pause) {
            log::warn!("the test's lock was not taken off: {e}");
        }
    }
}

/// How many requests wait for the player on `b`.
async fn waiting_for_the_player(b: &TestDevice) -> usize {
    let listed = query(b, "connect.pending", Vec::new()).await;
    let Reply::Pending(list) = reply(&listed) else {
        panic!("connect.pending answered another reply");
    };
    list.pending.len()
}

/// The wallet lock stops a connected application's requests too (owner
/// ruling 2026-10-15, SA-18), whoever asks: here the router's own calls,
/// which never pass the ingress's lock, as the listener makes them. While
/// the wallet is locked a request outside the grant is not even queued for
/// the player or answered "waiting", a payment the player approved is not
/// carried out, and a granted payment does not run. Each waits, and runs
/// once the wallet opens.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_granted_payment_does_not_run_while_the_wallet_is_locked() {
    let p = Pair::boot(500, 200).await;
    let wild = create_token(&p.a, "WILD", 1_000_000).await;
    let relay = ForwardRelay::start().await;
    let made = offer(&p.a, &relay, &wild).await;
    let session = connect(&p, &relay, &made.code).await;
    let sent = p.a.send_token(&p.b, "WILD", 50).await;
    assert!(sent.success, "{:?}", sent.error_message);
    p.b.sync().await;
    settle(&p).await;
    let pay = |amount: u64| {
        generated::connect_app_request_intent_v1::Kind::Pay(generated::ConnectPayV1 {
            policy_commit: wild.to_vec(),
            amount,
            memo: String::new(),
        })
    };

    p.b.enter();
    let lock = WalletLock::engage("2468");
    // Above the grant's 10 a time: it needs the player.
    let outside = request(&p.a, &relay, &session, pay(15)).await;
    let granted = request(&p.a, &relay, &session, pay(3)).await;
    let synced = invoke(&p.b, "connect.sync", Vec::new()).await;
    let Reply::Sessions(held) = reply(&synced) else {
        panic!("connect.sync answered another reply");
    };
    assert!(
        held.sessions[0].last_error.contains("the wallet is locked"),
        "{}",
        held.sessions[0].last_error
    );
    assert!(
        relay.held().responses.is_empty(),
        "the application is told nothing while the wallet is locked"
    );
    assert_eq!(
        waiting_for_the_player(&p.b).await,
        0,
        "nothing is queued for the player"
    );

    // Open: the request outside the grant waits for the player.
    lock.open();
    sync_and_deliver(&p, &relay).await;
    assert_eq!(waiting_for_the_player(&p.b).await, 1);

    // The player's approval, sent while the wallet is locked again, is kept
    // and not carried out.
    lock.close();
    let approved = invoke(
        &p.b,
        "connect.respond",
        args(&generated::ConnectRespondRequestV1 {
            session_id: session.to_vec(),
            seq: outside,
            decision: generated::ConnectDecision::Approve as i32,
        }),
    )
    .await;
    let Reply::Decided(decided) = reply(&approved) else {
        panic!("connect.respond answered another reply");
    };
    assert!(
        decided.line.contains("the wallet is locked"),
        "{}",
        decided.line
    );
    assert_eq!(balance(&p.b, &wild), 50, "no payment ran while locked");

    // Open: the approved payment, then the granted one.
    lock.open();
    sync_and_deliver(&p, &relay).await;
    carried_out(&p.b, &session, outside).await;
    settle(&p).await;
    sync_clean(&p, &relay).await;
    carried_out(&p.b, &session, granted).await;
    assert_eq!(balance(&p.b, &wild), 50 - 15 - 3);
}

/// A payment whose debit committed counts against its grant whatever became
/// of its delivery (SA-19). With the fleet below quorum the send commits the
/// debit and holds its admission for resume, so nothing is delivered yet;
/// the debit stands (§16.6), and the grant's lifetime total is charged for it
/// as for any payment carried out.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_committed_payment_counts_against_the_grant_whatever_its_delivery() {
    let mut p = Pair::boot(500, 200).await;
    let wild = create_token(&p.a, "WILD", 1_000_000).await;
    let relay = ForwardRelay::start().await;
    let made = offer(&p.a, &relay, &wild).await;
    let session = connect(&p, &relay, &made.code).await;
    let sent = p.a.send_token(&p.b, "WILD", 20).await;
    assert!(sent.success, "{:?}", sent.error_message);
    p.b.sync().await;
    settle(&p).await;

    let pay = request(
        &p.a,
        &relay,
        &session,
        generated::connect_app_request_intent_v1::Kind::Pay(generated::ConnectPayV1 {
            policy_commit: wild.to_vec(),
            amount: 10,
            memo: String::new(),
        }),
    )
    .await;
    let down = crate::economic_fixtures::members_to_break_quorum();
    p.nodes.take_down(&down).await;
    let synced = invoke(&p.b, "connect.sync", Vec::new()).await;
    p.nodes.bring_up(&down).await;
    reply(&synced);

    assert_eq!(balance(&p.b, &wild), 10, "the committed debit stands");
    let entry = wallet_log(&p.b, &session, pay).await;
    assert_eq!(
        generated::ConnectOutcome::try_from(entry.outcome),
        Ok(generated::ConnectOutcome::CarriedOut),
        "a committed debit is a payment made: {}",
        entry.detail
    );
    assert!(
        entry
            .detail
            .contains("its delivery is still being carried forward"),
        "the payment was committed, not delivered: {}",
        entry.detail
    );
    p.b.enter();
    let spent = crate::storage::client_db::connect::spent_all(&session).expect("the grant's spend");
    assert_eq!(
        spent,
        vec![(wild, 10)],
        "the committed debit counts against the grant"
    );
}

/// DSM Amendment A11, MR-DSM-0292: a grant's spending is bounded by its
/// scope's cap in total. The pay scope allows 10 WILD a time and 30 in all;
/// three payments of 10 spend it. The fourth is not carried out under the
/// grant: nothing more is paid, the grant's spend stays at its total, and the
/// wallet's log does not record it carried out. Whether the grant then ends
/// or the request waits for the player is the owner's reading of A11
/// (§6.105 A3); this holds under every reading.
///
/// MUTATION CONTROL: `grant::within` admitting a request past the cap's total
/// turns this red: the fourth payment runs.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_payment_past_the_grants_total_is_not_carried_out_under_it() {
    let p = Pair::boot(500, 200).await;
    let wild = create_token(&p.a, "WILD", 1_000_000).await;
    let relay = ForwardRelay::start().await;
    let made = offer(&p.a, &relay, &wild).await;
    let session = connect(&p, &relay, &made.code).await;
    let sent = p.a.send_token(&p.b, "WILD", 50).await;
    assert!(sent.success, "{:?}", sent.error_message);
    p.b.sync().await;
    settle(&p).await;
    let pay = || {
        generated::connect_app_request_intent_v1::Kind::Pay(generated::ConnectPayV1 {
            policy_commit: wild.to_vec(),
            amount: 10,
            memo: String::new(),
        })
    };

    for paid in 1..=3u64 {
        let seq = request(&p.a, &relay, &session, pay()).await;
        sync_clean(&p, &relay).await;
        carried_out(&p.b, &session, seq).await;
        assert_eq!(balance(&p.b, &wild), 50 - 10 * paid);
        settle(&p).await;
    }
    p.b.enter();
    assert_eq!(
        crate::storage::client_db::connect::spent_all(&session).expect("the grant's spend"),
        vec![(wild, 30)],
        "three payments spent the pay scope's total"
    );

    let past = request(&p.a, &relay, &session, pay()).await;
    sync_and_deliver(&p, &relay).await;
    assert_eq!(balance(&p.b, &wild), 20, "nothing past the total is paid");
    p.b.enter();
    assert_eq!(
        crate::storage::client_db::connect::spent_all(&session).expect("the grant's spend"),
        vec![(wild, 30)],
        "the grant's spend stays at its total"
    );
    let logged = query(
        &p.b,
        "connect.log",
        args(&generated::ConnectSessionRefV1 {
            session_id: session.to_vec(),
        }),
    )
    .await;
    let Reply::Log(log) = reply(&logged) else {
        panic!("connect.log answered another reply");
    };
    for entry in log.entries.iter().filter(|e| e.seq == past) {
        assert_ne!(
            generated::ConnectOutcome::try_from(entry.outcome),
            Ok(generated::ConnectOutcome::CarriedOut),
            "the payment past the total was carried out: {}",
            entry.detail
        );
    }
}

/// One signed request moves value once and counts once against its grant,
/// whatever stops it from being recorded as processed (SA-60). Here the
/// write that records it fails after the payment committed: a trigger the
/// test installs on the wallet's log refuses the row. The payment was bound
/// to the request in its own transaction, so the next sync records it as
/// carried out and pays nothing again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_request_whose_record_failed_after_it_paid_is_never_paid_again() {
    let p = Pair::boot(500, 200).await;
    let wild = create_token(&p.a, "WILD", 1_000_000).await;
    let relay = ForwardRelay::start().await;
    let made = offer(&p.a, &relay, &wild).await;
    let session = connect(&p, &relay, &made.code).await;
    let sent = p.a.send_token(&p.b, "WILD", 20).await;
    assert!(sent.success, "{:?}", sent.error_message);
    p.b.sync().await;
    settle(&p).await;

    let pay = request(
        &p.a,
        &relay,
        &session,
        generated::connect_app_request_intent_v1::Kind::Pay(generated::ConnectPayV1 {
            policy_commit: wild.to_vec(),
            amount: 3,
            memo: String::new(),
        }),
    )
    .await;
    let wallet_db = |sql: &str| {
        p.b.enter();
        crate::storage::client_db::get_connection()
            .expect("the wallet's database")
            .lock()
            .expect("the connection")
            .execute_batch(sql)
            .expect("the wallet's database answers");
    };
    wallet_db(&format!(
        "CREATE TRIGGER the_record_fails BEFORE INSERT ON connect_log WHEN NEW.seq = {pay} \
         BEGIN SELECT RAISE(ABORT, 'the record write failed'); END;"
    ));
    let synced = invoke(&p.b, "connect.sync", Vec::new()).await;
    wallet_db("DROP TRIGGER the_record_fails");
    let Reply::Sessions(failed) = reply(&synced) else {
        panic!("connect.sync answered another reply");
    };
    assert!(
        failed.sessions[0]
            .last_error
            .contains("the record write failed"),
        "{}",
        failed.sessions[0].last_error
    );
    assert_eq!(balance(&p.b, &wild), 17, "the payment committed");
    p.b.enter();
    let counted = || crate::storage::client_db::connect::spent_all(&session).expect("the spend");
    assert_eq!(counted(), vec![(wild, 3)], "counted with the payment");

    settle(&p).await;
    sync_clean(&p, &relay).await;
    assert_eq!(balance(&p.b, &wild), 17, "nothing was paid again");
    let entry = wallet_log(&p.b, &session, pay).await;
    assert_eq!(
        generated::ConnectOutcome::try_from(entry.outcome),
        Ok(generated::ConnectOutcome::CarriedOut),
        "{}",
        entry.detail
    );
    assert!(
        entry.detail.contains("it is not carried out again"),
        "{}",
        entry.detail
    );
    p.b.enter();
    assert_eq!(counted(), vec![(wild, 3)], "counted once");
    assert_eq!(
        balance(&p.a, &wild),
        1_000_000 - 20 + 3,
        "the game was paid once"
    );
}

/// SA-123. A read of the requests of a session this account never made is
/// refused at once, so the relay answers it `404` rather than holding it
/// open for its whole wait; a read of a session it made is answered.
/// MUTATION CONTROL: answering a read for any session with the requests
/// stored under it, as the account did, answers this one with an empty batch
/// and turns this red.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_read_of_requests_for_no_session_is_refused() {
    let p = Pair::boot(500, 200).await;
    let wild = create_token(&p.a, "WILD", 1_000_000).await;
    let relay = ForwardRelay::start().await;
    let made = offer(&p.a, &relay, &wild).await;
    let session = connect(&p, &relay, &made.code).await;
    let read = |session_id: [u8; 32]| {
        args(&generated::ConnectAppRequestsQueryV1 {
            session_id: session_id.to_vec(),
            after: 0,
        })
    };

    let Reply::Requests(batch) = reply(&query(&p.a, "connect.app.requests", read(session)).await)
    else {
        panic!("connect.app.requests answered another reply");
    };
    assert!(batch.requests.is_empty(), "{batch:?}");

    let unknown = query(&p.a, "connect.app.requests", read([0x5E; 32])).await;
    assert!(
        !unknown.success,
        "a read for no session was answered: {:?}",
        unknown.data
    );
    assert!(
        unknown
            .error_message
            .as_deref()
            .is_some_and(|why| why.contains("no such session")),
        "{:?}",
        unknown.error_message
    );
}

/// SA-126. A payment the application asks for first takes in what the
/// wallet's inbox holds (the send's own sync). A transfer another contact
/// sent, accepted there, is that contact's operation: only the payment's
/// debit is bound to the request, and the grant counts the request's spend
/// with the debit, never with the transfer taken in.
/// MUTATION CONTROL: running the send's sync inside the request's binding,
/// as the wallet did, binds the transfer taken in as the request's first
/// operation and turns this red.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_transfer_taken_in_while_a_request_pays_is_not_the_requests() {
    let p = Pair::boot(500, 200).await;
    let wild = create_token(&p.a, "WILD", 1_000_000).await;
    let relay = ForwardRelay::start().await;
    let made = offer(&p.a, &relay, &wild).await;
    let session = connect(&p, &relay, &made.code).await;
    let sent = p.a.send_token(&p.b, "WILD", 20).await;
    assert!(sent.success, "{:?}", sent.error_message);
    p.b.sync().await;
    settle(&p).await;

    // Another contact pays the wallet; the transfer waits in its inbox.
    let mut c = TestDevice::create("C", 0x0C);
    c.boot(&p.fleet).await;
    c.fund_admitted(100).await;
    c.add_contact(&p.b).await;
    p.b.add_contact(&c).await;
    let era_before = p.b.era_balance();
    let paid_in = c.send(&p.b, 500).await;
    assert!(paid_in.success, "{:?}", paid_in.error_message);
    assert_eq!(p.b.era_balance(), era_before, "nothing taken in yet");

    let pay = request(
        &p.a,
        &relay,
        &session,
        generated::connect_app_request_intent_v1::Kind::Pay(generated::ConnectPayV1 {
            policy_commit: wild.to_vec(),
            amount: 3,
            memo: String::new(),
        }),
    )
    .await;
    sync_clean(&p, &relay).await;
    carried_out(&p.b, &session, pay).await;
    assert_eq!(balance(&p.b, &wild), 17);
    assert_eq!(
        p.b.era_balance(),
        era_before + 500,
        "the payment's own sync took the transfer in"
    );

    p.b.enter();
    let bound = crate::storage::client_db::connect::bound_operations(&session, pay)
        .expect("the request's operations");
    // The debit alone: the transfer taken in before it is not bound.
    assert_eq!(bound.len(), 1, "the request committed one debit: {bound:?}");
    assert_eq!(
        crate::storage::client_db::connect::spent_all(&session).expect("the grant's spend"),
        vec![(wild, 3)]
    );
}

/// SA-129. A request approved by hand whose run committed its payment and
/// then failed to record it, declined afterwards, is recorded carried out:
/// the payment committed, and declining it changes nothing about that. The
/// decline recorded a refusal over a committed payment.
/// MUTATION CONTROL: declining without reading what the request already
/// committed, as the wallet did, records it declined and turns this red.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn declining_a_request_its_crashed_run_carried_out_records_it_carried_out() {
    let p = Pair::boot(500, 200).await;
    let wild = create_token(&p.a, "WILD", 1_000_000).await;
    let relay = ForwardRelay::start().await;
    let made = offer(&p.a, &relay, &wild).await;
    let session = connect(&p, &relay, &made.code).await;
    settle(&p).await;

    // Outside the grant: ERA was never payable to the game.
    let outside = request(
        &p.a,
        &relay,
        &session,
        generated::connect_app_request_intent_v1::Kind::Pay(generated::ConnectPayV1 {
            policy_commit: era().to_vec(),
            amount: 1,
            memo: "approved by hand".into(),
        }),
    )
    .await;
    sync_clean(&p, &relay).await;
    let era_held = balance(&p.b, &era());
    let wallet_db = |sql: &str| {
        p.b.enter();
        crate::storage::client_db::get_connection()
            .expect("the wallet's database")
            .lock()
            .expect("the connection")
            .execute_batch(sql)
            .expect("the wallet's database answers");
    };
    wallet_db(&format!(
        "CREATE TRIGGER the_record_fails BEFORE INSERT ON connect_log WHEN NEW.seq = {outside} \
         BEGIN SELECT RAISE(ABORT, 'the record write failed'); END;"
    ));
    let respond = |decision: generated::ConnectDecision| {
        invoke(
            &p.b,
            "connect.respond",
            args(&generated::ConnectRespondRequestV1 {
                session_id: session.to_vec(),
                seq: outside,
                decision: decision as i32,
            }),
        )
    };
    let crashed = respond(generated::ConnectDecision::Approve).await;
    wallet_db("DROP TRIGGER the_record_fails");
    assert!(!crashed.success, "the approved run's record failed");
    assert_eq!(balance(&p.b, &era()), era_held - 1, "the payment committed");

    let declined = respond(generated::ConnectDecision::Decline).await;
    let Reply::Decided(decided) = reply(&declined) else {
        panic!("connect.respond answered another reply");
    };
    assert_eq!(
        generated::ConnectOutcome::try_from(decided.outcome),
        Ok(generated::ConnectOutcome::CarriedOut),
        "{}",
        decided.line
    );
    let entry = wallet_log(&p.b, &session, outside).await;
    assert_eq!(
        generated::ConnectOutcome::try_from(entry.outcome),
        Ok(generated::ConnectOutcome::CarriedOut),
        "{}",
        entry.detail
    );
    assert_eq!(balance(&p.b, &era()), era_held - 1, "nothing more was paid");
}
