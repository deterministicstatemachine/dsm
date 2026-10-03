// SPDX-License-Identifier: Apache-2.0
//! What one client can hold on a node, and for how long. A request in flight
//! counts once against one limit for the whole node, whichever route it is
//! on; a request is answered within the node's request time, its body
//! included; a closer waiting its turn holds no database connection; and a
//! connection that never finishes sending a request's headers is closed. Each
//! test holds the resource the way a hostile client would and checks what
//! everyone else still gets.

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
        let closing = Arc::new(tokio::sync::Mutex::new(()));
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
        dsm_storage_node::bound_connections(server.http_builder(), header_time);
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
