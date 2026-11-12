// SPDX-License-Identifier: MIT OR Apache-2.0

//! Transport liveness: how long one connection may hold the node (storage
//! spec §1 rule 4; owner decision, 2026-10-16).
//!
//! This is the one node source that reads a clock, and it reads one for
//! connection and I/O liveness alone:
//!
//! - a connection with no request in flight for [`ConnectionBounds::idle`]
//!   is closed, whatever bytes its peer keeps exchanging (an HTTP/2 peer
//!   answering pings holds no request);
//! - a response whose write makes no progress for
//!   [`ConnectionBounds::write_stall`] ends its connection, so a client that
//!   asks and never reads holds nothing;
//! - a request body that arrives more slowly than [`BODY_MIN_RATE`], once
//!   [`BODY_RATE_GRACE`] has passed, is cut off, so a client trickling bytes
//!   frees its slot.
//!
//! Nothing here decides validity, ordering, finality, retention or what is
//! stored. A connection or request cut off here changes nothing, exactly as
//! an unreachable node changes nothing; its client reads the node as
//! unavailable. No protocol module is named here.
//!
//! [`ConnectionBounds::idle`]: crate::ConnectionBounds::idle
//! [`ConnectionBounds::write_stall`]: crate::ConnectionBounds::write_stall

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use axum::body::HttpBody;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::{Instant, Sleep};

/// The slowest a request body may arrive, in bytes a second, once
/// [`BODY_RATE_GRACE`] has passed: a phone on a poor network sends faster.
pub const BODY_MIN_RATE: u64 = 1024;

/// How long a request body has before it is held to [`BODY_MIN_RATE`].
pub const BODY_RATE_GRACE: Duration = Duration::from_secs(5);

/// What one connection is doing: the requests on it that are not yet
/// answered whole, and a count bumped whenever a request starts or ends.
#[derive(Debug, Default)]
struct ConnectionUse {
    in_flight: AtomicUsize,
    activity: AtomicU64,
}

/// One request on a connection, counted from when it reaches the node until
/// its response is written whole or abandoned.
struct InFlight(Arc<ConnectionUse>);

impl InFlight {
    fn start(connection: &Arc<ConnectionUse>) -> Self {
        connection.in_flight.fetch_add(1, Ordering::SeqCst);
        connection.activity.fetch_add(1, Ordering::SeqCst);
        Self(connection.clone())
    }
}

impl Drop for InFlight {
    fn drop(&mut self) {
        self.0.in_flight.fetch_sub(1, Ordering::SeqCst);
        self.0.activity.fetch_add(1, Ordering::SeqCst);
    }
}

/// The peer a connection is counted against for its share of the node's
/// connections: an IPv4 address, or the /64 an IPv6 address is in, since one
/// IPv6 host is handed a whole /64 and picks any address in it. An IPv4
/// address carried in IPv6 (a dual-stack listener) is that IPv4 address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Peer {
    V4(std::net::Ipv4Addr),
    V6Prefix([u8; 8]),
}

impl Peer {
    pub fn of(address: std::net::IpAddr) -> Self {
        match address {
            std::net::IpAddr::V4(v4) => Self::V4(v4),
            std::net::IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
                Some(v4) => Self::V4(v4),
                None => {
                    let mut prefix = [0u8; 8];
                    prefix.copy_from_slice(&v6.octets()[..8]);
                    Self::V6Prefix(prefix)
                }
            },
        }
    }
}

/// A stream whose remote end the node can name, so the connection counts
/// against that peer's share.
pub trait PeerAddressed {
    fn peer(&self) -> io::Result<Peer>;
}

impl PeerAddressed for tokio::net::TcpStream {
    fn peer(&self) -> io::Result<Peer> {
        Ok(Peer::of(self.peer_addr()?.ip()))
    }
}

/// The connections each peer holds open. A peer's count is gone once its
/// last connection closes.
type PeerCounts = Arc<std::sync::Mutex<std::collections::HashMap<Peer, usize>>>;

/// One connection's place in its peer's share, given back when the
/// connection closes.
struct PeerShare {
    peers: PeerCounts,
    peer: Peer,
}

impl Drop for PeerShare {
    fn drop(&mut self) {
        let mut held = LiveConnections::counts(&self.peers);
        if let Some(count) = held.get_mut(&self.peer) {
            *count -= 1;
            if *count == 0 {
                held.remove(&self.peer);
            }
        }
    }
}

/// Holds at most [`crate::ConnectionBounds::max_open`] connections open at
/// once, at most [`crate::ConnectionBounds::max_per_peer`] of them from any
/// one peer ([`Peer`]), and keeps each one's liveness bounds. It runs before
/// the TLS handshake, so a connection over either bound costs the node an
/// accept and nothing more: it is closed at once, and its client meets what
/// it meets at a node that is unavailable. A peer holding its whole share
/// leaves the rest of the node's connections to everyone else.
#[derive(Clone)]
pub struct LiveConnections {
    open: Arc<tokio::sync::Semaphore>,
    peers: PeerCounts,
    max_per_peer: usize,
    idle: Duration,
    write_stall: Duration,
}

impl LiveConnections {
    pub fn new(bounds: &crate::ConnectionBounds) -> Self {
        Self {
            open: Arc::new(tokio::sync::Semaphore::new(bounds.max_open)),
            peers: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
            max_per_peer: bounds.max_per_peer,
            idle: bounds.idle,
            write_stall: bounds.write_stall,
        }
    }

    /// The per-peer counts. A panic while they were held leaves every count
    /// whole (each is one integer written in place), so they are read as
    /// they stand.
    fn counts(
        peers: &std::sync::Mutex<std::collections::HashMap<Peer, usize>>,
    ) -> std::sync::MutexGuard<'_, std::collections::HashMap<Peer, usize>> {
        match peers.lock() {
            Ok(counts) => counts,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    /// A place among the node's connections and in `peer`'s share, or why
    /// there is none.
    fn admit(&self, peer: Peer) -> io::Result<(tokio::sync::OwnedSemaphorePermit, PeerShare)> {
        let mut held = Self::counts(&self.peers);
        if let Some(count) = held.get(&peer).filter(|n| **n >= self.max_per_peer) {
            return Err(io::Error::other(format!(
                "{peer:?} holds as many connections as one peer may: {count}"
            )));
        }
        let open = self.open.clone().try_acquire_owned().map_err(|full| {
            io::Error::other(format!(
                "the node holds as many connections as it may: {full}"
            ))
        })?;
        *held.entry(peer).or_insert(0) += 1;
        Ok((
            open,
            PeerShare {
                peers: self.peers.clone(),
                peer,
            },
        ))
    }
}

impl<I: PeerAddressed, S> axum_server::accept::Accept<I, S> for LiveConnections {
    type Stream = LiveConnection<I>;
    type Service = Counted<S>;
    type Future = std::future::Ready<io::Result<(LiveConnection<I>, Counted<S>)>>;

    fn accept(&self, stream: I, service: S) -> Self::Future {
        std::future::ready(
            stream
                .peer()
                .and_then(|peer| self.admit(peer).map(|held| (peer, held)))
                .map(|(peer, (open, share))| {
                    let connection = Arc::new(ConnectionUse::default());
                    (
                        LiveConnection {
                            stream,
                            _open: open,
                            _share: share,
                            connection: connection.clone(),
                            idle: self.idle,
                            write_stall: self.write_stall,
                            idle_timer: None,
                            write_timer: None,
                        },
                        Counted {
                            inner: service,
                            connection,
                            peer,
                        },
                    )
                }),
        )
    }
}

/// A connection, counted against the node's bound and its peer's share for
/// as long as it is open, and closed when it sits idle or a response's write stalls.
pub struct LiveConnection<S> {
    stream: S,
    _open: tokio::sync::OwnedSemaphorePermit,
    _share: PeerShare,
    connection: Arc<ConnectionUse>,
    idle: Duration,
    write_stall: Duration,
    /// The idle deadline, and the activity count it was set at.
    idle_timer: Option<(u64, Pin<Box<Sleep>>)>,
    /// The deadline of a write that has made no progress since it was set.
    write_timer: Option<Pin<Box<Sleep>>>,
}

impl<S> LiveConnection<S> {
    /// `Err` once the connection has had no request in flight for its idle
    /// bound. While a request is in flight there is no idle deadline; when
    /// the last one ends, a new one starts.
    fn idle_passed(&mut self, cx: &mut Context<'_>) -> io::Result<()> {
        if self.connection.in_flight.load(Ordering::SeqCst) > 0 {
            self.idle_timer = None;
            return Ok(());
        }
        let activity = self.connection.activity.load(Ordering::SeqCst);
        let stale = !matches!(&self.idle_timer, Some((set_at, _)) if *set_at == activity);
        if stale {
            self.idle_timer = Some((activity, Box::pin(tokio::time::sleep(self.idle))));
        }
        let Some((_, timer)) = &mut self.idle_timer else {
            return Ok(());
        };
        match timer.as_mut().poll(cx) {
            Poll::Ready(()) => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "the connection had no request for its idle bound",
            )),
            Poll::Pending => Ok(()),
        }
    }

    /// The outcome of a write: progress clears the stall deadline; no
    /// progress sets it, and is an error once it passes.
    fn write_progress<T>(
        &mut self,
        cx: &mut Context<'_>,
        written: Poll<io::Result<T>>,
    ) -> Poll<io::Result<T>> {
        match written {
            Poll::Pending => {
                let write_stall = self.write_stall;
                let timer = self
                    .write_timer
                    .get_or_insert_with(|| Box::pin(tokio::time::sleep(write_stall)));
                match timer.as_mut().poll(cx) {
                    Poll::Ready(()) => Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "a response's write made no progress for the write bound",
                    ))),
                    Poll::Pending => Poll::Pending,
                }
            }
            ready => {
                self.write_timer = None;
                ready
            }
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for LiveConnection<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if let Err(idle) = this.idle_passed(cx) {
            return Poll::Ready(Err(idle));
        }
        Pin::new(&mut this.stream).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for LiveConnection<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let written = Pin::new(&mut this.stream).poll_write(cx, buf);
        this.write_progress(cx, written)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let written = Pin::new(&mut this.stream).poll_write_vectored(cx, bufs);
        this.write_progress(cx, written)
    }

    fn is_write_vectored(&self) -> bool {
        self.stream.is_write_vectored()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let flushed = Pin::new(&mut this.stream).poll_flush(cx);
        this.write_progress(cx, flushed)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let shut = Pin::new(&mut this.stream).poll_shutdown(cx);
        this.write_progress(cx, shut)
    }
}

/// The node's service on one connection, counting each request as in flight
/// until its response is written whole or abandoned, and naming the
/// connection's peer to the app (a [`Peer`] among the request's extensions),
/// so a route can count what it holds against that peer's share.
#[derive(Clone)]
pub struct Counted<S> {
    inner: S,
    connection: Arc<ConnectionUse>,
    peer: Peer,
}

type CountedFuture<B, E> =
    Pin<Box<dyn Future<Output = Result<axum::http::Response<CountedBody<B>>, E>> + Send>>;

impl<S, Q, B> tower::Service<axum::http::Request<Q>> for Counted<S>
where
    S: tower::Service<axum::http::Request<Q>, Response = axum::http::Response<B>>,
    S::Future: Send + 'static,
    S::Error: 'static,
    B: 'static,
{
    type Response = axum::http::Response<CountedBody<B>>;
    type Error = S::Error;
    type Future = CountedFuture<B, S::Error>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut request: axum::http::Request<Q>) -> Self::Future {
        let in_flight = InFlight::start(&self.connection);
        request.extensions_mut().insert(self.peer);
        let answering = self.inner.call(request);
        Box::pin(async move {
            let response = answering.await?;
            Ok(response.map(|body| CountedBody {
                body,
                _in_flight: in_flight,
            }))
        })
    }
}

/// A response body, its request in flight until the body is written whole or
/// dropped.
pub struct CountedBody<B> {
    body: B,
    _in_flight: InFlight,
}

impl<B: HttpBody + Unpin> HttpBody for CountedBody<B> {
    type Data = B::Data;
    type Error = B::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
        Pin::new(&mut self.get_mut().body).poll_frame(cx)
    }

    fn is_end_stream(&self) -> bool {
        self.body.is_end_stream()
    }

    fn size_hint(&self) -> http_body::SizeHint {
        self.body.size_hint()
    }
}

/// The most of a response's body handed to the connection at a time. The
/// HTTP library asks for a body's next part only once the connection has room
/// for some of it, so a body handed over in parts of this size stays with the
/// request, and with the slot it holds ([`RequestSlots`]), until its reader
/// has taken all but the last part. Handed over whole, it would sit in the
/// connection's buffers, counted by nothing, for as long as its reader left
/// it there.
pub const RESPONSE_PART_BYTES: usize = 16 * 1024;

/// The requests the node serves at once, each counted from when it reaches
/// the app until its response is written or abandoned, and each peer's share
/// of them ([`Peer`]). A request waits for a slot, as long as the request
/// timeout outside this allows; a request from a peer already holding its
/// whole share is answered `503` at once, so one peer's requests, however
/// slowly it sends or reads them, leave the rest of the slots to everyone
/// else. A request whose connection names no peer (the app served without
/// the node's listener) is counted against the node's slots alone.
#[derive(Clone)]
pub struct RequestSlots {
    slots: Arc<tokio::sync::Semaphore>,
    peers: PeerCounts,
    max_per_peer: usize,
}

impl RequestSlots {
    pub fn new(slots: usize, max_per_peer: usize) -> Self {
        Self {
            slots: Arc::new(tokio::sync::Semaphore::new(slots)),
            peers: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
            max_per_peer,
        }
    }

    /// A place in `peer`'s share, or `None` when it holds its whole share.
    fn share(&self, peer: Peer) -> Option<PeerShare> {
        let mut held = LiveConnections::counts(&self.peers);
        if held.get(&peer).is_some_and(|n| *n >= self.max_per_peer) {
            return None;
        }
        *held.entry(peer).or_insert(0) += 1;
        Some(PeerShare {
            peers: self.peers.clone(),
            peer,
        })
    }
}

impl<S> tower::Layer<S> for RequestSlots {
    type Service = Slotted<S>;

    fn layer(&self, inner: S) -> Self::Service {
        Slotted {
            inner,
            slots: self.clone(),
        }
    }
}

/// A service whose every request holds one of the node's [`RequestSlots`].
#[derive(Clone)]
pub struct Slotted<S> {
    inner: S,
    slots: RequestSlots,
}

type SlottedFuture<E> =
    Pin<Box<dyn Future<Output = Result<axum::http::Response<axum::body::Body>, E>> + Send>>;

impl<S> tower::Service<axum::extract::Request> for Slotted<S>
where
    S: tower::Service<axum::extract::Request, Response = axum::http::Response<axum::body::Body>>
        + Clone
        + Send
        + 'static,
    S::Future: Send + 'static,
    S::Error: 'static,
{
    type Response = axum::http::Response<axum::body::Body>;
    type Error = S::Error;
    type Future = SlottedFuture<S::Error>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: axum::extract::Request) -> Self::Future {
        let unavailable = || {
            let mut response = axum::http::Response::new(axum::body::Body::empty());
            *response.status_mut() = axum::http::StatusCode::SERVICE_UNAVAILABLE;
            response
        };
        let share = match request.extensions().get::<Peer>().copied() {
            Some(peer) => match self.slots.share(peer) {
                Some(share) => Some(share),
                None => {
                    log::info!("{peer:?} holds as many requests as one peer may");
                    return Box::pin(async move { Ok(unavailable()) });
                }
            },
            None => None,
        };
        let slots = self.slots.slots.clone();
        // The service that was polled ready serves this request; its clone
        // waits for the next.
        let ready = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, ready);
        Box::pin(async move {
            let slot = match slots.acquire_owned().await {
                Ok(slot) => slot,
                Err(closed) => {
                    log::error!("the node's request slots are closed: {closed}");
                    return Ok(unavailable());
                }
            };
            let response = inner.call(request).await?;
            // A response with no body has nothing left to write: its slot
            // is free as soon as it is answered.
            if response.body().is_end_stream() {
                return Ok(response);
            }
            Ok(response.map(|body| {
                axum::body::Body::new(SlotBody {
                    body,
                    part: axum::body::Bytes::new(),
                    _slot: slot,
                    _share: share,
                })
            }))
        })
    }
}

/// A response body that keeps its request's slot, and its peer's share, until
/// it is written or dropped, and is handed to the connection
/// [`RESPONSE_PART_BYTES`] at a time.
struct SlotBody {
    body: axum::body::Body,
    part: axum::body::Bytes,
    _slot: tokio::sync::OwnedSemaphorePermit,
    _share: Option<PeerShare>,
}

impl SlotBody {
    fn next_part(&mut self) -> axum::body::Bytes {
        let take = self.part.len().min(RESPONSE_PART_BYTES);
        self.part.split_to(take)
    }
}

impl HttpBody for SlotBody {
    type Data = axum::body::Bytes;
    type Error = axum::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        if !this.part.is_empty() {
            return Poll::Ready(Some(Ok(http_body::Frame::data(this.next_part()))));
        }
        match Pin::new(&mut this.body).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => match frame.into_data() {
                Ok(data) => {
                    this.part = data;
                    Poll::Ready(Some(Ok(http_body::Frame::data(this.next_part()))))
                }
                Err(trailers) => Poll::Ready(Some(Ok(trailers))),
            },
            other => other,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.part.is_empty() && self.body.is_end_stream()
    }

    fn size_hint(&self) -> http_body::SizeHint {
        let mut hint = self.body.size_hint();
        let held = self.part.len() as u64;
        hint.set_lower(hint.lower().saturating_add(held));
        if let Some(upper) = hint.upper() {
            hint.set_upper(upper.saturating_add(held));
        }
        hint
    }
}

/// A request body held to [`BODY_MIN_RATE`] once [`BODY_RATE_GRACE`] has
/// passed since the request reached the node. Each frame that arrives is
/// checked against the time taken so far; a body that stops arriving
/// altogether is cut off by the node's body idle bound
/// ([`crate::BODY_IDLE`]).
pub struct MinRateBody<B> {
    body: B,
    started: Instant,
    received: u64,
}

/// A body that arrived more slowly than [`BODY_MIN_RATE`].
#[derive(Debug)]
pub struct TooSlow {
    received: u64,
    after: Duration,
}

impl std::fmt::Display for TooSlow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "the request body sent {} bytes in {:?}, slower than {BODY_MIN_RATE} bytes a second",
            self.received, self.after
        )
    }
}

impl std::error::Error for TooSlow {}

impl<B> MinRateBody<B> {
    fn new(body: B) -> Self {
        Self {
            body,
            started: Instant::now(),
            received: 0,
        }
    }

    /// `Err` when the body is behind the rate it is held to.
    fn behind(&self) -> Result<(), TooSlow> {
        let after = self.started.elapsed();
        let Some(held) = after.checked_sub(BODY_RATE_GRACE) else {
            return Ok(());
        };
        let owed = u128::from(BODY_MIN_RATE) * held.as_millis() / 1000;
        if u128::from(self.received) < owed {
            return Err(TooSlow {
                received: self.received,
                after,
            });
        }
        Ok(())
    }
}

impl<B> HttpBody for MinRateBody<B>
where
    B: HttpBody<Data = axum::body::Bytes> + Unpin,
    B::Error: Into<axum::BoxError>,
{
    type Data = axum::body::Bytes;
    type Error = axum::BoxError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        let polled = Pin::new(&mut this.body).poll_frame(cx);
        if let Poll::Ready(Some(Ok(frame))) = &polled {
            if let Some(data) = frame.data_ref() {
                this.received = this.received.saturating_add(data.len() as u64);
            }
        }
        if let Poll::Ready(None) = &polled {
            return Poll::Ready(None);
        }
        if let Err(slow) = this.behind() {
            return Poll::Ready(Some(Err(slow.into())));
        }
        polled.map(|frame| frame.map(|frame| frame.map_err(Into::into)))
    }

    fn is_end_stream(&self) -> bool {
        self.body.is_end_stream()
    }

    fn size_hint(&self) -> http_body::SizeHint {
        self.body.size_hint()
    }
}

/// Hold every request body to [`BODY_MIN_RATE`] ([`MinRateBody`]).
#[derive(Debug, Clone, Copy, Default)]
pub struct MinRateLayer;

impl<S> tower::Layer<S> for MinRateLayer {
    type Service = MinRate<S>;

    fn layer(&self, inner: S) -> Self::Service {
        MinRate { inner }
    }
}

/// The service [`MinRateLayer`] makes.
#[derive(Debug, Clone)]
pub struct MinRate<S> {
    inner: S,
}

impl<S, B> tower::Service<axum::http::Request<B>> for MinRate<S>
where
    S: tower::Service<axum::http::Request<MinRateBody<B>>>,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = S::Future;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: axum::http::Request<B>) -> Self::Future {
        self.inner.call(request.map(MinRateBody::new))
    }
}

#[cfg(test)]
mod tests {
    use super::Peer;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    /// An IPv4 peer is its address, carried in IPv6 or not; an IPv6 peer is
    /// its /64, so the addresses one host picks from its prefix share one
    /// count, and another /64 is another peer.
    #[test]
    fn a_peer_is_its_ipv4_address_or_its_ipv6_64() {
        let v4 = Ipv4Addr::new(203, 0, 113, 7);
        assert_eq!(Peer::of(IpAddr::V4(v4)), Peer::V4(v4));
        assert_eq!(
            Peer::of(IpAddr::V6(v4.to_ipv6_mapped())),
            Peer::V4(v4),
            "an IPv4 address on a dual-stack listener is that IPv4 peer"
        );
        assert_ne!(
            Peer::of(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 8))),
            Peer::V4(v4)
        );

        let host = |last: u16| IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 1, 2, 0, 0, 0, last));
        assert_eq!(
            Peer::of(host(1)),
            Peer::of(host(0xffff)),
            "two addresses in one /64 are one peer"
        );
        assert_ne!(
            Peer::of(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 1, 3, 0, 0, 0, 1))),
            Peer::of(host(1)),
            "another /64 is another peer"
        );
    }
}
