// SPDX-License-Identifier: MIT OR Apache-2.0

//! The DSM Connect relay a wallet reaches (DSM Amendment A11), over TLS
//! bound to the pin its connect code names. Transport, never evidence: every
//! object it carries is signed and checked by the SDK's `connect` routes, and
//! nothing a wallet posts is a fact about DSM.
//!
//! - `GET /connect/offer/{digest}`: the signed offer a code names.
//! - `POST /connect/accept`: a wallet's signed accept.
//! - `GET /connect/requests/{session}/{after}`: the session's requests above
//!   `after`, held a while when there are none yet.
//! - `POST /connect/responses`: a wallet's signed answer.

use std::collections::HashMap;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::{ConnectInfo, Path, State as Extract};
use axum::http::StatusCode;
use axum::response::Response;
use axum::routing::{get, post};
use axum::Router;
use dsm_sdk::generated as pb;
use prost::Message;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::activity::Record;
use crate::dispatch::{arg_pack, connect_reply, Call, Sdk};
use crate::game::{protobuf, refused};
use dsm_sdk::util::text_id::{decode_base32_crockford, encode_base32_crockford};

#[derive(Clone)]
pub struct State {
    pub sdk: Sdk,
    pub record: Arc<Record>,
    pub requests_changed: Arc<tokio::sync::Notify>,
}

/// How many times a request read with nothing to answer waits, and how long
/// each wait may be: a transport bound, never a validity rule.
const HOLD_ROUNDS: usize = 10;
const HOLD_ROUND: Duration = Duration::from_secs(2);

/// What one wallet, or anyone else who reaches the relay, can hold on it,
/// and for how long. Transport bounds, never validity rules.
#[derive(Debug, Clone, Copy)]
pub struct Bounds {
    /// How long a connection has to send a request's headers, the next
    /// request's included once it has answered one.
    pub header_read: Duration,
    /// How long one request may take before it is answered `408`; a held
    /// read of requests fits inside it.
    pub request_time: Duration,
    /// Requests worked on at once. One more is answered `503` at once.
    pub in_flight: usize,
    /// Requests one peer may have worked on at once, of `in_flight`. One
    /// more from it is answered `503` at once, whatever the others hold.
    pub per_peer_in_flight: usize,
    /// Connections held at once, a TLS handshake in progress included. One
    /// more is closed as it arrives.
    pub connections: usize,
    /// Connections one peer may hold at once, of `connections`.
    pub per_peer_connections: usize,
    /// How long a connection may pass no bytes either way before it is
    /// closed, whichever HTTP version it speaks. Longer than `request_time`,
    /// so a request held for its answer is never cut off by it.
    pub idle: Duration,
}

impl Bounds {
    /// The deployed relay's bounds.
    /// Every connected wallet keeps one read of its session's requests held,
    /// so the in-flight bound is sized for wallets, not for SDK calls: those
    /// wait in the SDK's own bounded queue.
    /// A peer is one address (an IPv6 one by its /64), so wallets behind
    /// one NAT share its share.
    pub const DEPLOYED: Bounds = Bounds {
        header_read: Duration::from_secs(10),
        request_time: Duration::from_secs(30),
        in_flight: 512,
        per_peer_in_flight: 32,
        connections: 768,
        per_peer_connections: 32,
        idle: Duration::from_secs(45),
    };
}

/// Who holds a share of the relay: one IPv4 address, or one IPv6 /64, the
/// least an IPv6 peer is given to choose addresses from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Peer {
    V4([u8; 4]),
    V6([u8; 8]),
}

impl Peer {
    fn of(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V4(v4) => Peer::V4(v4.octets()),
            IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
                Some(v4) => Peer::V4(v4.octets()),
                None => {
                    let octets = v6.octets();
                    let mut prefix = [0u8; 8];
                    prefix.copy_from_slice(&octets[..8]);
                    Peer::V6(prefix)
                }
            },
        }
    }
}

/// Why a share was not given.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Full {
    /// Every share of the relay is held.
    Relay,
    /// The peer holds every share it may.
    Peer,
}

/// A bounded resource of the relay, held in shares: at most `total` at once,
/// at most `per_peer` of them by one peer.
struct Shares {
    total: usize,
    per_peer: usize,
    held: Mutex<Holding>,
}

#[derive(Default)]
struct Holding {
    total: usize,
    by_peer: HashMap<Peer, usize>,
}

impl Shares {
    fn new(total: usize, per_peer: usize) -> Arc<Self> {
        Arc::new(Shares {
            total,
            per_peer,
            held: Mutex::new(Holding::default()),
        })
    }

    fn held(&self) -> std::sync::MutexGuard<'_, Holding> {
        // The counts are whole after every step that holds the lock: a
        // panic elsewhere leaves nothing half-written to refuse.
        match self.held.lock() {
            Ok(held) => held,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    /// A share for `peer`, given back when it drops.
    fn take(self: &Arc<Self>, peer: Peer) -> Result<Share, Full> {
        let mut held = self.held();
        if held.total >= self.total {
            return Err(Full::Relay);
        }
        let by_peer = held.by_peer.entry(peer).or_insert(0);
        if *by_peer >= self.per_peer {
            return Err(Full::Peer);
        }
        *by_peer += 1;
        held.total += 1;
        Ok(Share {
            shares: self.clone(),
            peer,
        })
    }
}

/// One share of the relay, given back when it drops.
struct Share {
    shares: Arc<Shares>,
    peer: Peer,
}

impl Drop for Share {
    fn drop(&mut self) {
        let mut held = self.shares.held();
        held.total -= 1;
        if let Some(by_peer) = held.by_peer.get_mut(&self.peer) {
            *by_peer -= 1;
            if *by_peer == 0 {
                held.by_peer.remove(&self.peer);
            }
        }
    }
}

/// Answer `503` at once to a request over the relay's in-flight bound, or
/// over its peer's share of it (SA-123).
async fn within_bound(
    Extract(slots): Extract<Arc<Shares>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    let _working = match slots.take(Peer::of(peer.ip())) {
        Ok(share) => share,
        Err(Full::Relay) => {
            return refused(
                StatusCode::SERVICE_UNAVAILABLE,
                "the relay is busy; try again".into(),
            )
        }
        Err(Full::Peer) => {
            return refused(
                StatusCode::SERVICE_UNAVAILABLE,
                "this address has as many requests in flight as the relay works on for one \
                 peer; try again once one is answered"
                    .into(),
            )
        }
    };
    next.run(request).await
}

/// A connection the relay holds: its share of the relay's connections,
/// given back when it closes, and its idle bound. A read or write that
/// waits past `idle` since the last byte moved either way fails, and the
/// connection with it (SA-122).
struct Bounded<T> {
    io: T,
    _share: Share,
    idle: Duration,
    quiet: Pin<Box<tokio::time::Sleep>>,
}

impl<T> Bounded<T> {
    fn new(io: T, share: Share, idle: Duration) -> Self {
        Bounded {
            io,
            _share: share,
            idle,
            quiet: Box::pin(tokio::time::sleep(idle)),
        }
    }

    /// Bytes moved: the idle bound starts again.
    fn moved(&mut self) {
        let next = tokio::time::Instant::now() + self.idle;
        self.quiet.as_mut().reset(next);
    }

    /// The connection waits: past the idle bound, it fails.
    fn waits<R>(&mut self, cx: &mut Context<'_>) -> Poll<std::io::Result<R>> {
        match self.quiet.as_mut().poll(cx) {
            Poll::Ready(()) => Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!("no bytes moved for {:?}", self.idle),
            ))),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for Bounded<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        match Pin::new(&mut self.io).poll_read(cx, buf) {
            Poll::Pending => self.waits(cx),
            Poll::Ready(Ok(())) => {
                if buf.filled().len() > before {
                    self.moved();
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
        }
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for Bounded<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match Pin::new(&mut self.io).poll_write(cx, buf) {
            Poll::Pending => self.waits(cx),
            Poll::Ready(Ok(written)) => {
                if written > 0 {
                    self.moved();
                }
                Poll::Ready(Ok(written))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match Pin::new(&mut self.io).poll_flush(cx) {
            Poll::Pending => self.waits(cx),
            done => done,
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}

/// Admits a connection to the relay while its peer, and the relay, have a
/// connection share left; closes it as it arrives otherwise (SA-122).
#[derive(Clone)]
struct Admit {
    connections: Arc<Shares>,
    idle: Duration,
}

impl<S> axum_server::accept::Accept<tokio::net::TcpStream, S> for Admit {
    type Stream = Bounded<tokio::net::TcpStream>;
    type Service = S;
    type Future = std::future::Ready<std::io::Result<(Self::Stream, S)>>;

    fn accept(&self, stream: tokio::net::TcpStream, service: S) -> Self::Future {
        let admitted =
            stream
                .peer_addr()
                .and_then(|peer| match self.connections.take(Peer::of(peer.ip())) {
                    Ok(share) => Ok((Bounded::new(stream, share, self.idle), service)),
                    Err(full) => Err(std::io::Error::new(
                        std::io::ErrorKind::ConnectionRefused,
                        format!("{peer}: no connection share left ({full:?})"),
                    )),
                });
        std::future::ready(admitted)
    }
}

pub fn router(state: State, bounds: Bounds) -> Router {
    Router::new()
        .route("/connect/offer/{digest}", get(offer))
        .route("/connect/accept", post(accept))
        .route("/connect/requests/{session}/{after}", get(requests))
        .route("/connect/responses", post(respond))
        .with_state(state)
        .layer(axum::middleware::from_fn_with_state(
            Shares::new(bounds.in_flight, bounds.per_peer_in_flight),
            within_bound,
        ))
        .layer(tower_http::timeout::TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            bounds.request_time,
        ))
}

/// Serve the relay for `state` on `listener` over `tls` until it fails,
/// every connection and request held to `bounds`. The binary serves through
/// exactly this.
pub async fn serve(
    listener: std::net::TcpListener,
    tls: axum_server::tls_rustls::RustlsConfig,
    state: State,
    bounds: Bounds,
) -> std::io::Result<()> {
    if bounds.idle <= bounds.request_time {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "an idle bound of {:?} would cut off a request held up to {:?}",
                bounds.idle, bounds.request_time
            ),
        ));
    }
    let admit = Admit {
        connections: Shares::new(bounds.connections, bounds.per_peer_connections),
        idle: bounds.idle,
    };
    let mut server = axum_server::from_tcp_rustls(listener, tls)?.map(|tls| tls.acceptor(admit));
    server
        .http_builder()
        .http1()
        .timer(hyper_util::rt::TokioTimer::new())
        .header_read_timeout(bounds.header_read);
    server
        .serve(router(state, bounds).into_make_service_with_connect_info::<SocketAddr>())
        .await
}

fn id32(text: &str, what: &str) -> Result<[u8; 32], String> {
    let bytes = decode_base32_crockford(&text.to_ascii_uppercase())
        .ok_or_else(|| format!("{what} is not Base32 Crockford"))?;
    <[u8; 32]>::try_from(bytes.as_slice()).map_err(|e| format!("{what}: {e}"))
}

fn short(bytes: &[u8]) -> String {
    encode_base32_crockford(bytes).chars().take(10).collect()
}

async fn offer(Extract(state): Extract<State>, Path(digest): Path<String>) -> Response {
    let digest = match id32(&digest, "the offer digest") {
        Ok(d) => d,
        Err(e) => return refused(StatusCode::BAD_REQUEST, e),
    };
    let call = Call::query(
        "connect.app.offerOf",
        arg_pack(
            pb::ConnectOfferRefV1 {
                offer_digest: digest.to_vec(),
            }
            .encode_to_vec(),
        ),
    );
    let reply = match state.sdk.call(call).await {
        Ok(done) => connect_reply(done.response),
        Err(e) => return refused(StatusCode::SERVICE_UNAVAILABLE, e),
    };
    match reply {
        Ok(pb::connect_reply_v1::Reply::Offer(o)) => {
            state.record.relay(
                "relay: offer",
                format!("a wallet fetched offer {}", short(&digest)),
                Ok(format!("{} signed bytes", o.offer.len())),
            );
            protobuf(o.offer)
        }
        Ok(other) => refused(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("connect.app.offerOf answered {other:?}"),
        ),
        Err(e) => refused(StatusCode::NOT_FOUND, e),
    }
}

async fn accept(Extract(state): Extract<State>, body: Bytes) -> Response {
    let call = Call::invoke("connect.app.accept", arg_pack(body.to_vec()));
    let reply = match state.sdk.call(call).await {
        Ok(done) => connect_reply(done.response),
        Err(e) => return refused(StatusCode::SERVICE_UNAVAILABLE, e),
    };
    match reply {
        Ok(pb::connect_reply_v1::Reply::Session(s)) => {
            state.record.relay(
                "relay: accept",
                format!("{} accepted the offer", s.display_name),
                Ok(format!(
                    "session {}: its card resolved on the pinned set; it is a contact, the relationship is established",
                    short(&s.session_id)
                )),
            );
            protobuf(s.encode_to_vec())
        }
        Ok(other) => refused(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("connect.app.accept answered {other:?}"),
        ),
        Err(e) => {
            state
                .record
                .relay("relay: accept", "a wallet's accept".into(), Err(e.clone()));
            refused(StatusCode::FORBIDDEN, e)
        }
    }
}

async fn requests(
    Extract(state): Extract<State>,
    Path((session, after)): Path<(String, u64)>,
) -> Response {
    let session = match id32(&session, "the session") {
        Ok(s) => s,
        Err(e) => return refused(StatusCode::BAD_REQUEST, e),
    };
    let args = arg_pack(
        pb::ConnectAppRequestsQueryV1 {
            session_id: session.to_vec(),
            after,
        }
        .encode_to_vec(),
    );
    for _round in 0..HOLD_ROUNDS {
        // Registered before the read, so a request signed after it wakes us.
        let changed = state.requests_changed.notified();
        let reply = match state
            .sdk
            .call(Call::query("connect.app.requests", args.clone()))
            .await
        {
            Ok(done) => connect_reply(done.response),
            Err(e) => return refused(StatusCode::SERVICE_UNAVAILABLE, e),
        };
        match reply {
            Ok(pb::connect_reply_v1::Reply::Requests(batch)) => {
                if !batch.requests.is_empty() {
                    state.record.relay(
                        "relay: requests",
                        format!(
                            "the wallet of session {} fetched its requests",
                            short(&session)
                        ),
                        Ok(format!(
                            "{} signed requests above #{after}",
                            batch.requests.len()
                        )),
                    );
                    return protobuf(batch.encode_to_vec());
                }
            }
            Ok(other) => {
                return refused(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("connect.app.requests answered {other:?}"),
                )
            }
            Err(e) => return refused(StatusCode::NOT_FOUND, e),
        }
        if let Err(elapsed) = tokio::time::timeout(HOLD_ROUND, changed).await {
            log::debug!("[relay] a held read waits on: {elapsed}");
        }
    }
    protobuf(pb::AppRequestBatchV1::default().encode_to_vec())
}

async fn respond(Extract(state): Extract<State>, body: Bytes) -> Response {
    let summary = match pb::AppResponseV1::decode(body.as_ref())
        .map_err(|e| e.to_string())
        .and_then(|r| pb::AppResponseBodyV1::decode(r.body.as_slice()).map_err(|e| e.to_string()))
    {
        Ok(b) => format!(
            "the wallet answered request #{}: {:?}{}",
            b.seq,
            pb::ConnectOutcome::try_from(b.outcome),
            match b.reason.as_str() {
                "" => String::new(),
                why => format!(" ({why})"),
            }
        ),
        Err(e) => format!("an unreadable answer: {e}"),
    };
    let call = Call::invoke("connect.app.respond", arg_pack(body.to_vec()));
    let reply = match state.sdk.call(call).await {
        Ok(done) => connect_reply(done.response),
        Err(e) => return refused(StatusCode::SERVICE_UNAVAILABLE, e),
    };
    match reply {
        Ok(pb::connect_reply_v1::Reply::Request(r)) => {
            state.record.relay(
                "relay: answer",
                summary,
                Ok("a signed notification, kept; it establishes nothing about DSM".into()),
            );
            protobuf(r.encode_to_vec())
        }
        Ok(other) => refused(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("connect.app.respond answered {other:?}"),
        ),
        Err(e) => {
            state.record.relay("relay: answer", summary, Err(e.clone()));
            refused(StatusCode::FORBIDDEN, e)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    /// The relay's state over an SDK whose queue is held and never read: a
    /// request's SDK call waits there for as long as the test runs.
    fn state() -> (State, std::sync::mpsc::Receiver<crate::dispatch::Job>) {
        let (sdk, untaken) = Sdk::with_queue(8);
        let state = State {
            sdk,
            record: Arc::new(Record::new(crate::identity::Account {
                device_id: [0x11; 32],
            })),
            requests_changed: Arc::new(tokio::sync::Notify::new()),
        };
        (state, untaken)
    }

    /// A peer at `ip`, as the server's connection info names it.
    fn peer(ip: [u8; 4]) -> SocketAddr {
        SocketAddr::from((ip, 40_000))
    }

    /// An offer fetch from `from`.
    fn offer_request(from: SocketAddr) -> Result<Request<Body>, String> {
        let mut request = Request::get(format!(
            "/connect/offer/{}",
            encode_base32_crockford(&[0x33; 32])
        ))
        .body(Body::empty())
        .map_err(|e| format!("request: {e}"))?;
        request.extensions_mut().insert(ConnectInfo(from));
        Ok(request)
    }

    async fn text(answer: Response) -> Result<String, String> {
        let bytes = axum::body::to_bytes(answer.into_body(), 4096)
            .await
            .map_err(|e| format!("the answer's body: {e}"))?;
        String::from_utf8(bytes.to_vec()).map_err(|e| format!("the answer's text: {e}"))
    }

    /// With room for one request and one held (its SDK call never taken by a
    /// worker), the next is answered `503` at once, and the held one `408`
    /// once the request time has passed.
    #[test]
    fn a_busy_relay_answers_at_once_and_a_held_request_is_cut_off() -> Result<(), String> {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| format!("the runtime: {e}"))?
            .block_on(async {
                let request_time = Duration::from_secs(1);
                let (state, _untaken) = state();
                let app = router(
                    state,
                    Bounds {
                        in_flight: 1,
                        request_time,
                        ..Bounds::DEPLOYED
                    },
                );
                let started = std::time::Instant::now();
                let held = tokio::spawn(app.clone().oneshot(offer_request(peer([10, 0, 0, 1]))?));
                tokio::time::sleep(Duration::from_millis(200)).await;
                let busy = tokio::time::timeout(
                    Duration::from_millis(500),
                    app.clone().oneshot(offer_request(peer([10, 0, 0, 1]))?),
                )
                .await
                .map_err(|e| format!("a request over the relay's bound was held: {e}"))?
                .map_err(|e| format!("answer: {e}"))?;
                assert_eq!(busy.status(), StatusCode::SERVICE_UNAVAILABLE);
                let held = tokio::time::timeout(Duration::from_secs(10), held)
                    .await
                    .map_err(|e| format!("the held request was never cut off: {e}"))?
                    .map_err(|e| format!("task: {e}"))?
                    .map_err(|e| format!("answer: {e}"))?;
                assert_eq!(held.status(), StatusCode::REQUEST_TIMEOUT);
                assert!(started.elapsed() >= request_time);
                Ok(())
            })
    }
    /// SA-123. A peer holding its share of the relay's request slots is
    /// answered `503` at once for one more, while another peer's request is
    /// still taken: no one address holds the slots every wallet's held read
    /// needs.
    /// MUTATION CONTROL: bounding requests by the relay's total alone, as the
    /// relay did, takes the first peer's second request and turns this red.
    #[test]
    fn one_peer_holds_no_more_than_its_share_of_the_relays_requests() -> Result<(), String> {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| format!("the runtime: {e}"))?
            .block_on(async {
                let (state, _untaken) = state();
                let app = router(
                    state,
                    Bounds {
                        in_flight: 4,
                        per_peer_in_flight: 1,
                        ..Bounds::DEPLOYED
                    },
                );
                let (one, other) = (peer([10, 0, 0, 1]), peer([10, 0, 0, 2]));
                let _held = tokio::spawn(app.clone().oneshot(offer_request(one)?));
                tokio::time::sleep(Duration::from_millis(200)).await;
                let second = tokio::time::timeout(
                    Duration::from_millis(500),
                    app.clone().oneshot(offer_request(one)?),
                )
                .await
                .map_err(|e| format!("a request over the peer's share was held: {e}"))?
                .map_err(|e| format!("answer: {e}"))?;
                assert_eq!(second.status(), StatusCode::SERVICE_UNAVAILABLE);
                let why = text(second).await?;
                assert!(why.contains("this address"), "{why}");
                // Another peer's request is taken, and held like the first.
                match tokio::time::timeout(
                    Duration::from_millis(500),
                    app.clone().oneshot(offer_request(other)?),
                )
                .await
                {
                    Ok(answer) => Err(format!(
                        "another peer's request was answered at once: {answer:?}"
                    )),
                    Err(held) => {
                        log::debug!("another peer's request is held: {held}");
                        Ok(())
                    }
                }
            })
    }

    /// HTTP/2 spoken over TLS to the relay, as a wallet's client speaks it:
    /// the client preface, then frames.
    mod h2 {
        use std::io::{Read, Write};
        use std::net::{SocketAddr, TcpStream};
        use std::sync::Arc;
        use std::time::Duration;

        pub type Conn = rustls::StreamOwned<rustls::ClientConnection, TcpStream>;

        const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
        const SETTINGS: u8 = 0x4;
        const PING: u8 = 0x6;
        const ACK: u8 = 0x1;

        fn frame(kind: u8, flags: u8, payload: &[u8]) -> Vec<u8> {
            let len = payload.len().to_be_bytes();
            let mut bytes = vec![len[5], len[6], len[7], kind, flags, 0, 0, 0, 0];
            bytes.extend_from_slice(payload);
            bytes
        }

        /// The next frame: its type, flags and payload.
        fn read_frame(conn: &mut Conn) -> std::io::Result<(u8, u8, Vec<u8>)> {
            let mut head = [0u8; 9];
            conn.read_exact(&mut head)?;
            let len = usize::from(head[0]) << 16 | usize::from(head[1]) << 8 | usize::from(head[2]);
            let mut payload = vec![0u8; len];
            conn.read_exact(&mut payload)?;
            Ok((head[3], head[4], payload))
        }

        /// A client trusting exactly the relay's certificate.
        pub fn client(cert: &[u8]) -> Result<Arc<rustls::ClientConfig>, String> {
            let mut roots = rustls::RootCertStore::empty();
            roots
                .add(rustls::pki_types::CertificateDer::from(cert.to_vec()))
                .map_err(|e| format!("the relay's certificate: {e}"))?;
            let mut config = rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth();
            config.alpn_protocols = vec![b"h2".to_vec()];
            Ok(Arc::new(config))
        }

        /// A connection to the relay at `addr` that has spoken HTTP/2: the
        /// TLS handshake, the preface and the settings both ways.
        pub fn open(addr: SocketAddr, client: Arc<rustls::ClientConfig>) -> Result<Conn, String> {
            let tcp = TcpStream::connect(addr).map_err(|e| format!("connect: {e}"))?;
            tcp.set_read_timeout(Some(Duration::from_secs(10)))
                .map_err(|e| format!("read timeout: {e}"))?;
            let name = rustls::pki_types::ServerName::try_from("localhost")
                .map_err(|e| format!("the relay's name: {e}"))?;
            let tls = rustls::ClientConnection::new(client, name)
                .map_err(|e| format!("the TLS client: {e}"))?;
            let mut conn = rustls::StreamOwned::new(tls, tcp);
            conn.write_all(PREFACE)
                .and_then(|()| conn.write_all(&frame(SETTINGS, 0, &[])))
                .and_then(|()| conn.flush())
                .map_err(|e| format!("the client preface: {e}"))?;
            let (kind, flags, ..) =
                read_frame(&mut conn).map_err(|e| format!("the server's settings: {e}"))?;
            if (kind, flags) != (SETTINGS, 0) {
                return Err(format!("the server opened with frame {kind}/{flags}"));
            }
            conn.write_all(&frame(SETTINGS, ACK, &[]))
                .and_then(|()| conn.flush())
                .map_err(|e| format!("acknowledging the settings: {e}"))?;
            Ok(conn)
        }

        /// Whether the relay still answers on `conn`: a ping it acknowledges.
        pub fn answers(conn: &mut Conn) -> Result<(), String> {
            conn.write_all(&frame(PING, 0, b"relay-ok"))
                .and_then(|()| conn.flush())
                .map_err(|e| format!("ping: {e}"))?;
            loop {
                let (kind, flags, payload) =
                    read_frame(conn).map_err(|e| format!("the ping's answer: {e}"))?;
                if (kind, flags, payload.as_slice()) == (PING, ACK, b"relay-ok".as_slice()) {
                    return Ok(());
                }
            }
        }

        /// Read what the relay sends on `conn` until it closes it: `Ok` once
        /// closed, `Err` if it was still open when the read gave up.
        pub fn until_closed(conn: &mut Conn) -> Result<(), String> {
            loop {
                match read_frame(conn) {
                    Ok(..) => continue,
                    Err(e) => {
                        return match e.kind() {
                            std::io::ErrorKind::UnexpectedEof
                            | std::io::ErrorKind::ConnectionReset
                            | std::io::ErrorKind::ConnectionAborted
                            | std::io::ErrorKind::BrokenPipe => Ok(()),
                            _ => Err(format!("the connection is still open: {e}")),
                        }
                    }
                }
            }
        }
    }

    /// The relay served by [`serve`] on a loopback port, as the binary
    /// serves it: its address and its certificate.
    async fn served(bounds: Bounds) -> Result<(SocketAddr, Vec<u8>), String> {
        dsm_sdk::sdk::tls_transport_sdk::ensure_rustls_crypto_provider();
        let made = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
            .map_err(|e| format!("the certificate: {e}"))?;
        let cert = made.cert.der().to_vec();
        let tls = axum_server::tls_rustls::RustlsConfig::from_der(
            vec![cert.clone()],
            made.signing_key.serialize_der(),
        )
        .await
        .map_err(|e| format!("the TLS identity: {e}"))?;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .map_err(|e| format!("bind: {e}"))?;
        let addr = listener.local_addr().map_err(|e| format!("address: {e}"))?;
        let listener = listener
            .into_std()
            .map_err(|e| format!("the listener: {e}"))?;
        let (state, untaken) = state();
        tokio::spawn(async move {
            // The queue stays open while the relay serves.
            let _queue = untaken;
            if let Err(e) = serve(listener, tls, state, bounds).await {
                log::error!("[relay test] the relay stopped: {e}");
            }
        });
        Ok((addr, cert))
    }

    /// A runtime with worker threads, so the relay serves while a blocking
    /// client waits on it.
    fn multi_thread() -> Result<tokio::runtime::Runtime, String> {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .map_err(|e| format!("the runtime: {e}"))
    }

    /// Run `work` on a thread of its own, as a blocking client does.
    async fn blocking<R: Send + 'static>(
        work: impl FnOnce() -> Result<R, String> + Send + 'static,
    ) -> Result<R, String> {
        tokio::task::spawn_blocking(work)
            .await
            .map_err(|e| format!("the client thread: {e}"))?
    }

    /// SA-122. One peer holds no more connections than its share: one more
    /// is closed as it arrives, while the ones it holds go on answering, and
    /// a share comes back when its connection closes.
    /// MUTATION CONTROL: serving without the connection bound, as the relay
    /// did, completes the extra connection and turns this red.
    #[test]
    fn a_peer_holds_no_more_connections_than_its_share() -> Result<(), String> {
        multi_thread()?.block_on(async {
            let (addr, cert) = served(Bounds {
                connections: 8,
                per_peer_connections: 2,
                ..Bounds::DEPLOYED
            })
            .await?;
            let client = h2::client(&cert)?;
            blocking(move || {
                let mut first = h2::open(addr, client.clone())?;
                let mut second = h2::open(addr, client.clone())?;
                match h2::open(addr, client.clone()) {
                    Ok(..) => return Err("a third connection from one peer was served".into()),
                    // Closed as it arrived: the handshake never completes.
                    Err(why) => assert!(
                        why.starts_with("the client preface")
                            || why.starts_with("the server's settings"),
                        "{why}"
                    ),
                }
                h2::answers(&mut first)?;
                h2::answers(&mut second)?;
                drop(first);
                // The closed connection's share comes back once the relay sees it close.
                let mut tries = 0;
                let mut again = loop {
                    match h2::open(addr, client.clone()) {
                        Ok(conn) => break conn,
                        Err(why) if tries < 20 => {
                            tries += 1;
                            log::debug!("the share is not back yet: {why}");
                            std::thread::sleep(Duration::from_millis(100));
                        }
                        Err(why) => {
                            return Err(format!(
                                "the closed connection's share never came back: {why}"
                            ))
                        }
                    }
                };
                h2::answers(&mut again)
            })
            .await
        })
    }

    /// SA-122. An HTTP/2 connection that sends nothing is closed once it has
    /// been idle for the idle bound, not before.
    /// MUTATION CONTROL: serving without the idle bound, as the relay did,
    /// keeps the connection open and turns this red.
    #[test]
    fn an_idle_http2_connection_is_closed() -> Result<(), String> {
        multi_thread()?.block_on(async {
            let idle = Duration::from_secs(2);
            let (addr, cert) = served(Bounds {
                request_time: Duration::from_secs(1),
                idle,
                ..Bounds::DEPLOYED
            })
            .await?;
            let client = h2::client(&cert)?;
            blocking(move || {
                let mut conn = h2::open(addr, client)?;
                let quiet = std::time::Instant::now();
                h2::until_closed(&mut conn)?;
                let after = quiet.elapsed();
                assert!(
                    after >= idle - Duration::from_millis(200),
                    "closed after {after:?}"
                );
                Ok(())
            })
            .await
        })
    }

    /// An idle bound inside the request time would cut off held reads: the
    /// relay refuses to serve with one.
    #[test]
    fn an_idle_bound_inside_the_request_time_is_refused() -> Result<(), String> {
        multi_thread()?.block_on(async {
            let listener =
                std::net::TcpListener::bind("127.0.0.1:0").map_err(|e| format!("bind: {e}"))?;
            dsm_sdk::sdk::tls_transport_sdk::ensure_rustls_crypto_provider();
            let made = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
                .map_err(|e| format!("the certificate: {e}"))?;
            let tls = axum_server::tls_rustls::RustlsConfig::from_der(
                vec![made.cert.der().to_vec()],
                made.signing_key.serialize_der(),
            )
            .await
            .map_err(|e| format!("the TLS identity: {e}"))?;
            let (state, _untaken) = state();
            let refused = serve(
                listener,
                tls,
                state,
                Bounds {
                    idle: Bounds::DEPLOYED.request_time,
                    ..Bounds::DEPLOYED
                },
            )
            .await;
            assert_eq!(
                refused.map_err(|e| e.kind()),
                Err(std::io::ErrorKind::InvalidInput)
            );
            Ok(())
        })
    }
}
