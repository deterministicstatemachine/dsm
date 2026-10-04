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

use super::node_e2e_tests::{args, balance, create_token, era, invoke, payload};
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

struct Held {
    offer: Option<([u8; 32], Vec<u8>)>,
    accepts: Vec<Vec<u8>>,
    requests: Vec<Vec<u8>>,
    responses: Vec<Vec<u8>>,
    serve: Serve,
}

type Shared = Arc<Mutex<Held>>;

/// A store-and-forward relay on a self-signed certificate.
struct ForwardRelay {
    endpoint: String,
    pin: [u8; 32],
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
    held.lock()
        .expect("the relay")
        .responses
        .push(body.to_vec());
    StatusCode::OK
}

impl ForwardRelay {
    async fn start() -> Self {
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
            serve: Serve::Above,
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

    fn held(&self) -> std::sync::MutexGuard<'_, Held> {
        self.held.lock().expect("the relay")
    }
}

fn reply(r: &crate::bridge::AppResult) -> Reply {
    match payload(r) {
        Payload::ConnectReply(generated::ConnectReplyV1 { reply: Some(reply) }) => reply,
        other => panic!("a connect route answered {other:?}"),
    }
}

async fn query(d: &TestDevice, path: &str, params: Vec<u8>) -> crate::bridge::AppResult {
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
/// its coin, swap the coin against ERA spending ERA, see the coin.
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
        },
        generated::ConnectScopeV1 {
            kind: generated::ConnectScopeKind::Holdings as i32,
            policy_commits: vec![wild.to_vec()],
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
            .any(|l| l.contains("10 WILD a time")),
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
fn args_raw(body: Vec<u8>) -> Vec<u8> {
    generated::ArgPack {
        codec: generated::Codec::Proto as i32,
        body,
        ..Default::default()
    }
    .encode_to_vec()
}

/// A signs a request, and the relay serves it. Its sequence number.
async fn request(
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
async fn wallet_log(b: &TestDevice, session: &[u8; 32], seq: u64) -> generated::ConnectLogEntryV1 {
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
async fn carried_out(b: &TestDevice, session: &[u8; 32], seq: u64) {
    let entry = wallet_log(b, session, seq).await;
    assert_eq!(
        generated::ConnectOutcome::try_from(entry.outcome),
        Ok(generated::ConnectOutcome::CarriedOut),
        "request {seq} ({}): {}",
        entry.summary,
        entry.detail
    );
}

async fn status(a: &TestDevice, session: &[u8; 32], seq: u64) -> generated::ConnectAppStatusV1 {
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

fn fact(s: &generated::ConnectAppStatusV1) -> generated::ConnectFact {
    generated::ConnectFact::try_from(s.fact).expect("a known fact")
}

fn outcome(s: &generated::ConnectAppStatusV1) -> generated::ConnectOutcome {
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
