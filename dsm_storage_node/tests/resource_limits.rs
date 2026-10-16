// SPDX-License-Identifier: Apache-2.0
//! What one client can hold on a node, and for how long. A request in flight
//! counts once against one limit for the whole node, whichever route it is
//! on; a request is answered within the node's request time, its body
//! included, and a body that stops arriving frees its slot well before that;
//! a closer waiting its turn holds no database connection; a connection that
//! never finishes sending a request's headers is closed, and so is an HTTP/2
//! connection whose peer stops answering pings; and the node holds no more
//! connections open than its bound. Each test holds the resource the way a
//! hostile client would and checks what everyone else still gets.

mod common;

use axum::body::{Body, Bytes};
use axum::http::{Request, StatusCode};
use dsm_storage_node::{build_app, db, AppLimits, AppState};
use std::sync::Arc;
use std::time::Duration;
use tower::ServiceExt;

/// A node over a fresh store named `store`, its app built with `limits`.
async fn node(store: &str, limits: AppLimits) -> axum::Router {
    let pool = common::fresh_store(store).await;
    let state = Arc::new(common::ok_or_panic(
        AppState::new("member".to_string(), pool, common::set_client()),
        "app state",
    ));
    build_app(state, limits)
}

fn limits(concurrency_limit: usize, request_timeout: Duration) -> AppLimits {
    AppLimits {
        body_limit_bytes: 1_048_576,
        concurrency_limit,
        request_timeout,
        wait_bound: dsm_storage_node::api::transport::b0x::MAX_WAIT,
    }
}

/// The deployed node's connection bounds, holding at most `max_open`
/// connections.
fn bounds(max_open: usize) -> dsm_storage_node::ConnectionBounds {
    dsm_storage_node::ConnectionBounds {
        header_read: Duration::from_secs(10),
        h2_ping_every: dsm_storage_node::H2_PING_EVERY,
        h2_ping_answer: dsm_storage_node::H2_PING_ANSWER,
        idle: dsm_storage_node::CONNECTION_IDLE,
        write_stall: dsm_storage_node::WRITE_STALL,
        max_open,
    }
}

/// The sending half of a request body that arrives only when it is dropped.
type HeldBody = futures::channel::mpsc::Sender<Result<Bytes, std::io::Error>>;

/// A spool submission whose body has not arrived, and the sender that holds
/// it back for as long as it is kept.
fn held_submission() -> (HeldBody, Request<Body>) {
    let (sender, body) = futures::channel::mpsc::channel(1);
    let recipient = dsm::utils::text_id::encode_base32_crockford(&[0x5Au8; 32]);
    let request = common::ok_or_panic(
        Request::builder()
            .method("POST")
            .uri("/api/v2/b0x/submit")
            .header("content-type", "application/octet-stream")
            .header("x-dsm-recipient", recipient)
            .body(Body::from_stream(body)),
        "request",
    );
    (sender, request)
}

fn health() -> Request<Body> {
    common::ok_or_panic(
        Request::builder()
            .method("GET")
            .uri("/api/v2/health")
            .body(Body::empty()),
        "request",
    )
}

/// With room for one request in flight, a request held on the spool route
/// keeps a request on the health route waiting: the limit is one count for
/// the node, not one per route. Once the held body arrives, the waiting
/// request is answered.
#[test]
fn one_count_of_requests_in_flight_holds_across_every_route() {
    common::runtime().block_on(async {
        let app = node("rl_one_count", limits(1, Duration::from_secs(60))).await;
        let (sender, held) = held_submission();
        let holder = tokio::spawn(app.clone().oneshot(held));
        // The held request takes the one slot and waits for its body.
        tokio::time::sleep(Duration::from_millis(200)).await;
        let waiting = tokio::spawn(app.clone().oneshot(health()));
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert!(
            !waiting.is_finished(),
            "a request on another route was served while the node's one slot was held"
        );

        drop(sender);
        let answered = match tokio::time::timeout(Duration::from_secs(10), waiting).await {
            Ok(joined) => common::ok_or_panic(common::ok_or_panic(joined, "task"), "answer"),
            Err(elapsed) => panic!("the waiting request was never served: {elapsed}"),
        };
        assert_eq!(answered.status(), StatusCode::OK);
        let held = common::ok_or_panic(common::ok_or_panic(holder.await, "task"), "answer");
        assert_eq!(held.status(), StatusCode::NO_CONTENT);
    });
}

/// A request whose body never arrives is answered `408` once the node's
/// request time has passed, instead of holding its slot and its connection
/// for as long as the client keeps it open.
#[test]
fn a_request_whose_body_never_arrives_is_answered_408() {
    common::runtime().block_on(async {
        let app = node("rl_timeout", limits(256, Duration::from_secs(1))).await;
        let (sender, held) = held_submission();
        let answer = match tokio::time::timeout(Duration::from_secs(10), app.oneshot(held)).await {
            Ok(answer) => common::ok_or_panic(answer, "the app answers"),
            Err(elapsed) => panic!("a request whose body never arrived held the node: {elapsed}"),
        };
        assert_eq!(answer.status(), StatusCode::REQUEST_TIMEOUT);
        drop(sender);
    });
}

/// Closers that must wait their turn hold no database connection while they
/// wait. With the close lock held elsewhere and more closers queued than the
/// pool has connections, a read still gets a connection at once.
#[test]
fn closers_waiting_their_turn_leave_the_pool_to_everyone_else() {
    common::runtime().block_on(async {
        let pool = common::fresh_store("rl_closers").await;
        // Another holder of the close lock keeps every closer waiting.
        let blocker = common::ok_or_panic(pool.get().await, "a connection");
        common::ok_or_panic(
            blocker
                .execute("SELECT pg_advisory_lock($1)", &[&db::CLOSE_LOCK])
                .await,
            "take the close lock",
        );
        let closing = Arc::new(db::CommittedCells::default());
        let closers: Vec<_> = (0..db::POOL_MAX_SIZE + 4)
            .map(|_| {
                let (pool, closing) = (pool.clone(), closing.clone());
                tokio::spawn(async move { db::close_cycle(&pool, &closing, b"member").await })
            })
            .collect();
        tokio::time::sleep(Duration::from_millis(500)).await;

        let read = tokio::time::timeout(
            Duration::from_secs(5),
            db::get_cell_entries(&pool, b"DSM/resource-limits", &[0x11; 32]),
        )
        .await;
        match read {
            Ok(entries) => assert_eq!(common::ok_or_panic(entries, "the read").len(), 0),
            Err(elapsed) => panic!("a read waited for a connection the closers held: {elapsed}"),
        }

        common::ok_or_panic(
            blocker
                .execute("SELECT pg_advisory_unlock($1)", &[&db::CLOSE_LOCK])
                .await,
            "release the close lock",
        );
        for closer in closers {
            common::ok_or_panic(common::ok_or_panic(closer.await, "task"), "the close");
        }
    });
}

/// A connection that opens and never finishes sending a request's headers is
/// closed once the header time has passed, and not before: a connection that
/// ends early ended for some other reason (a server that cannot keep the
/// bound drops it at once). The node's own server is started with the node's
/// own connection bounds, over plain HTTP: the bound is set on the connection
/// builder, the same one the node's TLS listener uses.
#[test]
fn a_connection_that_never_finishes_its_headers_is_closed() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    common::runtime().block_on(async {
        let app = node("rl_headers", limits(256, Duration::from_secs(60))).await;
        // Tokio's listener, handed over as the server takes it: already in
        // the non-blocking mode the server needs.
        let listener =
            common::ok_or_panic(tokio::net::TcpListener::bind("127.0.0.1:0").await, "bind");
        let address = common::ok_or_panic(listener.local_addr(), "address");
        let listener = common::ok_or_panic(listener.into_std(), "the listener");
        let mut server = common::ok_or_panic(axum_server::from_tcp(listener), "a server");
        let header_time = Duration::from_secs(1);
        dsm_storage_node::bound_connections(
            server.http_builder(),
            &dsm_storage_node::ConnectionBounds {
                header_read: header_time,
                ..bounds(16)
            },
        );
        tokio::spawn(server.serve(app.into_make_service()));

        let mut socket =
            common::ok_or_panic(tokio::net::TcpStream::connect(address).await, "connect");
        common::ok_or_panic(
            socket
                .write_all(b"GET /api/v2/health HTTP/1.1\r\nhost: node\r\n")
                .await,
            "half of a request's headers",
        );
        let opened = tokio::time::Instant::now();
        let mut rest = Vec::new();
        let read =
            tokio::time::timeout(Duration::from_secs(10), socket.read_to_end(&mut rest)).await;
        let held = opened.elapsed();
        assert!(
            held >= header_time.mul_f32(0.9),
            "the connection ended after {held:?}, before the header time of {header_time:?}"
        );
        match read {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => assert!(
                matches!(
                    e.kind(),
                    std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::BrokenPipe
                ),
                "the connection ended in an error that is not the node closing it: {e}"
            ),
            Err(elapsed) => {
                panic!("a connection that never finished its headers was held open: {elapsed}")
            }
        }
    });
}

/// A device's wait on its spools is held on purpose, so it sits outside the
/// node's request time and its count of requests in flight. With one slot and
/// a one-second request time, a wait held for its 2.5-second bound is answered
/// `204` once the bound passes, not `408` at the request time, and a health
/// check made while it is held is served at once.
#[test]
fn a_held_wait_takes_no_slot_and_outlasts_the_request_time() {
    common::runtime().block_on(async {
        let app = node(
            "rl_wait",
            AppLimits {
                wait_bound: Duration::from_millis(2_500),
                ..limits(1, Duration::from_secs(1))
            },
        )
        .await;
        let request = dsm::types::proto::B0xWaitRequest {
            marks: vec![dsm::types::proto::B0xWaitMark {
                address: dsm::utils::text_id::encode_base32_crockford(&[0x5Bu8; 32]),
                from_seq: 1,
            }],
        };
        let wait = common::ok_or_panic(
            Request::builder()
                .method("POST")
                .uri("/api/v2/b0x/wait")
                .header("content-type", "application/octet-stream")
                .body(Body::from(prost::Message::encode_to_vec(&request))),
            "request",
        );
        let started = std::time::Instant::now();
        let held = tokio::spawn(app.clone().oneshot(wait));
        tokio::time::sleep(Duration::from_millis(200)).await;

        let health = match tokio::time::timeout(Duration::from_secs(2), app.oneshot(health())).await
        {
            Ok(answer) => common::ok_or_panic(answer, "the app answers"),
            Err(elapsed) => panic!("a held wait kept the node's one slot: {elapsed}"),
        };
        assert_eq!(health.status(), StatusCode::OK);

        let answer = match tokio::time::timeout(Duration::from_secs(10), held).await {
            Ok(joined) => common::ok_or_panic(common::ok_or_panic(joined, "task"), "answer"),
            Err(elapsed) => panic!("the wait was never answered: {elapsed}"),
        };
        assert_eq!(answer.status(), StatusCode::NO_CONTENT);
        assert!(
            started.elapsed() >= Duration::from_millis(2_500),
            "the wait was cut short of its bound"
        );
    });
}

/// A request whose body starts and then stops arriving is cut off once the
/// body has been idle for [`dsm_storage_node::BODY_IDLE`], long before the
/// node's request time: its slot is free again for everyone else.
#[test]
fn a_body_that_stops_arriving_is_cut_off_before_the_request_time() {
    use futures::SinkExt;
    common::runtime().block_on(async {
        let app = node("rl_body_idle", limits(256, Duration::from_secs(600))).await;
        let (mut sender, held) = held_submission();
        common::ok_or_panic(
            sender
                .send(Ok(Bytes::from_static(b"the first bytes")))
                .await,
            "the body's first bytes",
        );
        let started = std::time::Instant::now();
        let within = dsm_storage_node::BODY_IDLE + Duration::from_secs(10);
        let answer = match tokio::time::timeout(within, app.oneshot(held)).await {
            Ok(answer) => common::ok_or_panic(answer, "the app answers"),
            Err(elapsed) => panic!("a body that stopped arriving held its slot: {elapsed}"),
        };
        assert_eq!(answer.status(), StatusCode::BAD_REQUEST);
        assert!(
            started.elapsed() >= dsm_storage_node::BODY_IDLE.mul_f32(0.9),
            "the body was cut off after {:?}, before it was idle for {:?}",
            started.elapsed(),
            dsm_storage_node::BODY_IDLE
        );
        drop(sender);
    });
}

/// The node holds at most its bound of connections open: with room for two
/// and two held (opened and never sent a byte), a third is closed as soon as
/// it is accepted; once one of the two ends, a new connection is held again.
/// The node's own TLS server is started, as the binary starts it.
#[test]
fn a_node_holds_no_more_connections_than_its_bound() {
    use tokio::io::AsyncReadExt;
    common::runtime().block_on(async {
        let app = node("rl_cap", limits(256, Duration::from_secs(60))).await;
        let listener =
            common::ok_or_panic(tokio::net::TcpListener::bind("127.0.0.1:0").await, "bind");
        let address = common::ok_or_panic(listener.local_addr(), "address");
        let listener = common::ok_or_panic(listener.into_std(), "the listener");
        let server = dsm_storage_node::node_server(
            common::ok_or_panic(axum_server::from_tcp(listener), "a server"),
            common::node_tls().await,
            &bounds(2),
        );
        tokio::spawn(server.serve(app.into_make_service()));
        let connect = move || async move {
            common::ok_or_panic(tokio::net::TcpStream::connect(address).await, "connect")
        };

        let mut held = vec![connect().await, connect().await];
        tokio::time::sleep(Duration::from_millis(300)).await;
        let mut third = connect().await;
        let mut rest = Vec::new();
        match tokio::time::timeout(Duration::from_secs(3), third.read_to_end(&mut rest)).await {
            Ok(Ok(_)) => assert!(rest.is_empty(), "the node answered a connection over its bound"),
            Ok(Err(e)) => assert!(
                matches!(
                    e.kind(),
                    std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::BrokenPipe
                ),
                "the connection over the bound ended in an error that is not the node closing it: {e}"
            ),
            Err(elapsed) => panic!("a connection over the node's bound was held open: {elapsed}"),
        }

        drop(held.pop());
        tokio::time::sleep(Duration::from_millis(300)).await;
        let mut fourth = connect().await;
        let mut byte = [0u8; 1];
        match tokio::time::timeout(Duration::from_secs(1), fourth.read(&mut byte)).await {
            Err(_held_open) => {}
            Ok(read) => {
                panic!("a connection within the bound, once one ended, was not held: {read:?}")
            }
        }
        drop(held);
    });
}

/// An HTTP/2 connection whose peer stops answering the node's pings is
/// closed once a ping goes unanswered, instead of being held for as long as
/// the peer keeps the socket open. The peer here opens HTTP/2 and then never
/// writes again. The bounds are set on the connection builder, the same one
/// the node's TLS listener uses.
#[test]
fn an_http2_peer_that_stops_answering_pings_is_closed() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    common::runtime().block_on(async {
        let app = node("rl_h2_ping", limits(256, Duration::from_secs(60))).await;
        let listener =
            common::ok_or_panic(tokio::net::TcpListener::bind("127.0.0.1:0").await, "bind");
        let address = common::ok_or_panic(listener.local_addr(), "address");
        let listener = common::ok_or_panic(listener.into_std(), "the listener");
        let mut server = common::ok_or_panic(axum_server::from_tcp(listener), "a server");
        let ping = Duration::from_secs(1);
        dsm_storage_node::bound_connections(
            server.http_builder(),
            &dsm_storage_node::ConnectionBounds {
                h2_ping_every: ping,
                h2_ping_answer: ping,
                ..bounds(16)
            },
        );
        tokio::spawn(server.serve(app.into_make_service()));

        let mut socket =
            common::ok_or_panic(tokio::net::TcpStream::connect(address).await, "connect");
        // The HTTP/2 connection preface and an empty SETTINGS frame; nothing
        // after it, not even the acknowledgements HTTP/2 asks for.
        let mut opening = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
        opening.extend_from_slice(&[0, 0, 0, 0x04, 0, 0, 0, 0, 0]);
        common::ok_or_panic(socket.write_all(&opening).await, "open HTTP/2");
        let opened = std::time::Instant::now();
        let mut rest = Vec::new();
        let read =
            tokio::time::timeout(Duration::from_secs(15), socket.read_to_end(&mut rest)).await;
        let held = opened.elapsed();
        match read {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => assert!(
                matches!(
                    e.kind(),
                    std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::BrokenPipe
                ),
                "the connection ended in an error that is not the node closing it: {e}"
            ),
            Err(elapsed) => {
                panic!("an HTTP/2 peer that answers no ping was held open: {elapsed}")
            }
        }
        assert!(
            held >= ping.mul_f32(0.9),
            "the connection ended after {held:?}, before a ping could go unanswered"
        );
    });
}

/// The node's plain-TCP server on a loopback port with `bounds`: the same
/// acceptor and connection builder the TLS listener uses
/// ([`dsm_storage_node::node_server`]), without the TLS between them.
async fn served_plain(
    app: axum::Router,
    bounds: dsm_storage_node::ConnectionBounds,
) -> std::net::SocketAddr {
    let listener = common::ok_or_panic(tokio::net::TcpListener::bind("127.0.0.1:0").await, "bind");
    let address = common::ok_or_panic(listener.local_addr(), "address");
    let listener = common::ok_or_panic(listener.into_std(), "the listener");
    let mut server = common::ok_or_panic(axum_server::from_tcp(listener), "a server")
        .acceptor(dsm_storage_node::liveness::LiveConnections::new(&bounds));
    dsm_storage_node::bound_connections(server.http_builder(), &bounds);
    tokio::spawn(server.serve(app.into_make_service()));
    address
}

/// An HTTP/2 connection that holds no request is closed once its idle bound
/// passes, though its peer answers every ping: what keeps a connection is a
/// request in flight, not traffic. The peer opens HTTP/2, acknowledges the
/// node's settings and pings, and asks nothing.
#[test]
fn an_http2_connection_with_no_request_is_closed_once_idle() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    common::runtime().block_on(async {
        let app = node("rl_h2_idle", limits(256, Duration::from_secs(60))).await;
        let idle = Duration::from_secs(2);
        let address = served_plain(
            app,
            dsm_storage_node::ConnectionBounds {
                h2_ping_every: Duration::from_millis(500),
                h2_ping_answer: Duration::from_secs(1),
                idle,
                ..bounds(16)
            },
        )
        .await;
        let mut socket =
            common::ok_or_panic(tokio::net::TcpStream::connect(address).await, "connect");
        let mut opening = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
        opening.extend_from_slice(&[0, 0, 0, 0x04, 0, 0, 0, 0, 0]);
        common::ok_or_panic(socket.write_all(&opening).await, "open HTTP/2");
        let opened = std::time::Instant::now();
        // Answer every frame HTTP/2 asks an answer for, until the node closes.
        let answered = async {
            let mut pings = 0usize;
            loop {
                let mut header = [0u8; 9];
                if let Err(e) = socket.read_exact(&mut header).await {
                    return (pings, e.kind());
                }
                let length = usize::from(header[0]) << 16
                    | usize::from(header[1]) << 8
                    | usize::from(header[2]);
                let (kind, flags) = (header[3], header[4]);
                let mut payload = vec![0u8; length];
                if let Err(e) = socket.read_exact(&mut payload).await {
                    return (pings, e.kind());
                }
                let reply: Option<Vec<u8>> = match (kind, flags & 1) {
                    // SETTINGS, not an acknowledgement: acknowledge it.
                    (0x04, 0) => Some(vec![0, 0, 0, 0x04, 1, 0, 0, 0, 0]),
                    // PING, not an acknowledgement: answer it.
                    (0x06, 0) => {
                        pings += 1;
                        let mut ack = vec![0, 0, 8, 0x06, 1, 0, 0, 0, 0];
                        ack.extend_from_slice(&payload);
                        Some(ack)
                    }
                    _ => None,
                };
                if let Some(reply) = reply {
                    if let Err(e) = socket.write_all(&reply).await {
                        return (pings, e.kind());
                    }
                }
            }
        };
        let (pings, ended) = match tokio::time::timeout(Duration::from_secs(10), answered).await {
            Ok(ended) => ended,
            Err(elapsed) => panic!("an HTTP/2 connection with no request was held open: {elapsed}"),
        };
        let held = opened.elapsed();
        assert!(
            matches!(
                ended,
                std::io::ErrorKind::UnexpectedEof
                    | std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::BrokenPipe
            ),
            "the connection ended in an error that is not the node closing it: {ended:?}"
        );
        assert!(
            held >= idle.mul_f32(0.9),
            "the connection ended after {held:?}, before its idle bound of {idle:?}"
        );
        assert!(
            pings > 0,
            "the peer answered the node's pings, so pings did not close it"
        );
    });
}

/// A response whose write makes no progress ends its connection once the
/// write bound passes: a client that asks for a large answer and never reads
/// it holds the node no longer. Its socket's receive buffer is kept small,
/// so the answer cannot all wait in the kernel.
#[test]
fn a_response_nobody_reads_ends_its_connection_once_its_write_stalls() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    common::runtime().block_on(async {
        let app = node("rl_write_stall", limits(256, Duration::from_secs(60))).await;
        // A spool holding a full retrieve batch of large envelopes.
        let spool = dsm::utils::text_id::encode_base32_crockford(&[0x5Cu8; 32]);
        let envelope = vec![0xE5u8; 120 * 1024];
        for _ in 0..dsm::spool::MAX_BATCH_RETRIEVE {
            let submit = common::ok_or_panic(
                Request::builder()
                    .method("POST")
                    .uri("/api/v2/b0x/submit")
                    .header("content-type", "application/octet-stream")
                    .header("x-dsm-recipient", spool.as_str())
                    .body(Body::from(envelope.clone())),
                "request",
            );
            let answer = common::ok_or_panic(app.clone().oneshot(submit).await, "submit");
            assert_eq!(answer.status(), StatusCode::NO_CONTENT);
        }
        let full = dsm::spool::MAX_BATCH_RETRIEVE * envelope.len();

        let stall = Duration::from_secs(1);
        let address = served_plain(
            app,
            dsm_storage_node::ConnectionBounds {
                write_stall: stall,
                ..bounds(16)
            },
        )
        .await;
        let socket = common::ok_or_panic(tokio::net::TcpSocket::new_v4(), "a socket");
        common::ok_or_panic(socket.set_recv_buffer_size(4096), "a small receive buffer");
        let mut socket = common::ok_or_panic(socket.connect(address).await, "connect");
        let ask = format!(
            "GET /api/v2/b0x/retrieve/0 HTTP/1.1\r\nhost: node\r\nx-dsm-b0x-address: {spool}\r\n\r\n"
        );
        common::ok_or_panic(socket.write_all(ask.as_bytes()).await, "ask");
        // Read nothing while the node's write stalls past its bound.
        tokio::time::sleep(stall * 4).await;
        let mut got = Vec::new();
        let ended = tokio::time::timeout(Duration::from_secs(20), socket.read_to_end(&mut got)).await;
        match ended {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => assert!(
                matches!(
                    e.kind(),
                    std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::BrokenPipe
                ),
                "the connection ended in an error that is not the node ending it: {e}"
            ),
            Err(elapsed) => panic!("the stalled connection was held open: {elapsed}"),
        }
        assert!(
            got.len() < full,
            "the whole {full}-byte answer was written to a client that read none of it for {:?}",
            stall * 4
        );
    });
}

/// A request body that keeps arriving, but more slowly than
/// [`dsm_storage_node::liveness::BODY_MIN_RATE`], is cut off once its grace
/// has passed, though each byte comes well inside the body idle bound and the
/// request time is far off: its slot is free again.
#[test]
fn a_body_that_trickles_in_is_cut_off_once_its_grace_has_passed() {
    use dsm_storage_node::liveness::BODY_RATE_GRACE;
    use futures::SinkExt;
    common::runtime().block_on(async {
        let app = node("rl_body_rate", limits(256, Duration::from_secs(600))).await;
        let (mut sender, held) = held_submission();
        let trickle = tokio::spawn(async move {
            loop {
                if let Err(closed) = sender.send(Ok(Bytes::from_static(b"x"))).await {
                    // The node stopped reading the body: the trickle ends.
                    assert!(closed.is_disconnected(), "{closed}");
                    return;
                }
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        });
        let started = std::time::Instant::now();
        let within = BODY_RATE_GRACE + Duration::from_secs(10);
        let answer = match tokio::time::timeout(within, app.oneshot(held)).await {
            Ok(answer) => common::ok_or_panic(answer, "the app answers"),
            Err(elapsed) => panic!("a trickling body held its slot: {elapsed}"),
        };
        assert_eq!(answer.status(), StatusCode::BAD_REQUEST);
        assert!(
            started.elapsed() >= BODY_RATE_GRACE.mul_f32(0.9),
            "the body was cut off after {:?}, inside its grace",
            started.elapsed()
        );
        trickle.abort();
    });
}
