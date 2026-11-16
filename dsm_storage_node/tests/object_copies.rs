// SPDX-License-Identifier: MIT OR Apache-2.0
//! The members distribute an object among themselves (storage spec §5 rule
//! 7): a member that takes a put copies the object to each set-mate before it
//! answers. A copy not made does not fail the put: the writer puts it itself.
//! Real nodes over real HTTPS, each serving a certificate from its CA and
//! pinned to the others'.

mod common;

use std::sync::Arc;

use axum::{body::Body, http::Request, http::StatusCode, Router};
use common::ok_or_panic;
use dsm_storage_node::{db, AppState, NodeStorageSet};
use tower::ServiceExt;

const NS: &str = "DSM/object-copies-contract";

/// A node over a fresh store named `store`, a member of `set`, knowing its
/// set-mates only at the `endpoints` its own configuration names.
async fn node(store: &str, id: &str, set: &[&str], endpoints: &[(&str, &str)]) -> Router {
    let pool: Arc<db::DBPool> = common::fresh_store(store).await;
    let state = ok_or_panic(AppState::new(id.to_string(), pool), "app state");
    let members: Vec<(String, [u8; 32])> = set.iter().map(|m| (m.to_string(), [7u8; 32])).collect();
    let configured = endpoints
        .iter()
        .map(|(m, e)| (m.to_string(), e.to_string(), Some(common::node_ca_pem())))
        .collect();
    let set = ok_or_panic(
        ok_or_panic(NodeStorageSet::new(members, id, [7u8; 32]), "set")
            .with_set_mates(id, configured),
        "set-mates",
    );
    common::served(Arc::new(state.with_storage_set(set)))
}

/// Whom a put is for.
#[derive(Clone, Copy, PartialEq, Eq)]
enum For {
    /// The whole set: the member copies it to each set-mate.
    TheSet,
    /// This member alone, marked so: a set-mate's copy, passed on to no one.
    ThisMember,
}

/// What the node answered a put of `payload`.
async fn put(app: &Router, payload: &[u8], whom: For) -> StatusCode {
    let mut req = Request::post("/api/v2/immutable/put").header("x-namespace", NS);
    if whom == For::ThisMember {
        req = req.header("x-dsm-set-copy", "1");
    }
    let req = ok_or_panic(req.body(Body::from(payload.to_vec())), "request");
    ok_or_panic(app.clone().oneshot(req).await, "oneshot").status()
}

/// Whether the node serves the object `payload` makes.
async fn holds(app: &Router, payload: &[u8]) -> StatusCode {
    let domain = ok_or_panic(
        dsm::crypto::domain::TaggedHashDomain::try_new(NS.as_bytes()),
        "domain",
    );
    let addr = dsm::storage_object::immutable_addr(domain, payload);
    let req = ok_or_panic(
        Request::get(format!(
            "/api/v2/immutable/{}",
            dsm::utils::text_id::encode_base32_crockford(&addr)
        ))
        .body(Body::empty()),
        "request",
    );
    ok_or_panic(app.clone().oneshot(req).await, "oneshot").status()
}

/// A put at A reaches B and C through A, and A's answer names no one. A put
/// marked as for A alone stays at A. A copy B takes is marked, so B passes it
/// on to no one: an object A put alone at B is held by B and not by C.
#[test]
fn a_member_copies_what_it_takes_to_each_set_mate() {
    common::runtime().block_on(async {
        let ((la, ua), (lb, ub), (lc, uc)) = (
            common::tls_listener().await,
            common::tls_listener().await,
            common::tls_listener().await,
        );
        let set = ["dsm-node-a", "dsm-node-b", "dsm-node-c"];
        let a = node(
            "oc_a",
            "dsm-node-a",
            &set,
            &[("dsm-node-b", &ub), ("dsm-node-c", &uc)],
        )
        .await;
        let b = node(
            "oc_b",
            "dsm-node-b",
            &set,
            &[("dsm-node-a", &ua), ("dsm-node-c", &uc)],
        )
        .await;
        let c = node(
            "oc_c",
            "dsm-node-c",
            &set,
            &[("dsm-node-a", &ua), ("dsm-node-b", &ub)],
        )
        .await;
        common::serve_tls(la, a.clone()).await;
        common::serve_tls(lb, b.clone()).await;
        common::serve_tls(lc, c.clone()).await;

        assert_eq!(
            put(&a, b"for the set", For::TheSet).await,
            StatusCode::CREATED,
            "every set-mate took its copy"
        );
        for (member, app) in [("A", &a), ("B", &b), ("C", &c)] {
            assert_eq!(holds(app, b"for the set").await, StatusCode::OK, "{member}");
        }

        assert_eq!(
            put(&a, b"for A alone", For::ThisMember).await,
            StatusCode::CREATED
        );
        assert_eq!(holds(&a, b"for A alone").await, StatusCode::OK);
        assert_eq!(holds(&b, b"for A alone").await, StatusCode::NOT_FOUND);
        assert_eq!(holds(&c, b"for A alone").await, StatusCode::NOT_FOUND);

        assert_eq!(
            put(&b, b"a copy at B", For::ThisMember).await,
            StatusCode::CREATED
        );
        assert_eq!(holds(&c, b"a copy at B").await, StatusCode::NOT_FOUND);
    });
}

/// A set-mate that is not reachable does not fail the put: the member holds
/// the object and the reachable set-mate holds its copy, and a put again is
/// answered the same.
#[test]
fn a_set_mate_that_does_not_take_its_copy_fails_no_put() {
    common::runtime().block_on(async {
        let ((la, ua), (lb, ub)) = (common::tls_listener().await, common::tls_listener().await);
        // C's endpoint is configured, and nothing listens there.
        let uc = {
            let (lc, uc) = common::tls_listener().await;
            drop(lc);
            uc
        };
        let set = ["dsm-node-a", "dsm-node-b", "dsm-node-c"];
        let a = node(
            "oc_miss_a",
            "dsm-node-a",
            &set,
            &[("dsm-node-b", &ub), ("dsm-node-c", &uc)],
        )
        .await;
        let b = node(
            "oc_miss_b",
            "dsm-node-b",
            &set,
            &[("dsm-node-a", &ua), ("dsm-node-c", &uc)],
        )
        .await;
        common::serve_tls(la, a.clone()).await;
        common::serve_tls(lb, b.clone()).await;

        assert_eq!(
            put(&a, b"C is down", For::TheSet).await,
            StatusCode::CREATED
        );
        assert_eq!(holds(&a, b"C is down").await, StatusCode::OK);
        assert_eq!(holds(&b, b"C is down").await, StatusCode::OK);

        // Put again, the object already held: A copies again, and answers.
        assert_eq!(put(&a, b"C is down", For::TheSet).await, StatusCode::OK);
    });
}

/// A member answers a `HEAD` of an object with whether it holds it, and no
/// bytes: the question a writer asks each member after a put for the set.
#[test]
fn a_member_answers_a_head_with_whether_it_holds_the_object() {
    common::runtime().block_on(async {
        let a = node("oc_head_a", "dsm-node-a", &["dsm-node-a"], &[]).await;
        assert_eq!(put(&a, b"held", For::ThisMember).await, StatusCode::CREATED);
        let domain = ok_or_panic(
            dsm::crypto::domain::TaggedHashDomain::try_new(NS.as_bytes()),
            "domain",
        );
        for (payload, status) in [
            (&b"held"[..], StatusCode::OK),
            (&b"never put"[..], StatusCode::NOT_FOUND),
        ] {
            let addr = dsm::storage_object::immutable_addr(domain, payload);
            let req = ok_or_panic(
                Request::head(format!(
                    "/api/v2/immutable/{}",
                    dsm::utils::text_id::encode_base32_crockford(&addr)
                ))
                .body(Body::empty()),
                "request",
            );
            let resp = ok_or_panic(a.clone().oneshot(req).await, "oneshot");
            assert_eq!(resp.status(), status);
            let body = ok_or_panic(
                axum::body::to_bytes(resp.into_body(), usize::MAX).await,
                "body",
            );
            assert!(body.is_empty(), "a HEAD answers no bytes");
        }
    });
}

/// A copy is passed on to no one. A reaches B but not C; B reaches C. A put
/// for the set at A reaches B as a copy, and B does not pass it to C.
#[test]
fn a_set_mate_passes_a_copy_on_to_no_one() {
    common::runtime().block_on(async {
        let ((la, ua), (lb, ub), (lc, uc)) = (
            common::tls_listener().await,
            common::tls_listener().await,
            common::tls_listener().await,
        );
        let unreachable = {
            let (dropped, at) = common::tls_listener().await;
            drop(dropped);
            at
        };
        let set = ["dsm-node-a", "dsm-node-b", "dsm-node-c"];
        let a = node(
            "oc_relay_a",
            "dsm-node-a",
            &set,
            &[("dsm-node-b", &ub), ("dsm-node-c", &unreachable)],
        )
        .await;
        let b = node(
            "oc_relay_b",
            "dsm-node-b",
            &set,
            &[("dsm-node-a", &ua), ("dsm-node-c", &uc)],
        )
        .await;
        let c = node(
            "oc_relay_c",
            "dsm-node-c",
            &set,
            &[("dsm-node-a", &ua), ("dsm-node-b", &ub)],
        )
        .await;
        common::serve_tls(la, a.clone()).await;
        common::serve_tls(lb, b.clone()).await;
        common::serve_tls(lc, c.clone()).await;

        assert_eq!(
            put(&a, b"through A", For::TheSet).await,
            StatusCode::CREATED
        );
        assert_eq!(holds(&a, b"through A").await, StatusCode::OK);
        assert_eq!(holds(&b, b"through A").await, StatusCode::OK);
        assert_eq!(
            holds(&c, b"through A").await,
            StatusCode::NOT_FOUND,
            "B passed A's copy on"
        );
    });
}

/// A set-mate that takes copies and never answers them: how many it holds
/// unanswered now, and the most at once.
#[derive(Default)]
struct Stalled {
    now: std::sync::atomic::AtomicUsize,
    most: std::sync::atomic::AtomicUsize,
}

/// A set-mate at a TLS listener whose object puts are held and never
/// answered, counted in `stalled`.
async fn stalled_set_mate(stalled: Arc<Stalled>) -> String {
    use std::sync::atomic::Ordering;
    let (listener, at) = common::tls_listener().await;
    let app = Router::new().route(
        "/api/v2/immutable/put",
        axum::routing::post(move || {
            let stalled = stalled.clone();
            async move {
                let now = stalled.now.fetch_add(1, Ordering::SeqCst) + 1;
                stalled.most.fetch_max(now, Ordering::SeqCst);
                tokio::time::sleep(std::time::Duration::from_secs(60)).await;
                StatusCode::CREATED
            }
        }),
    );
    common::serve_tls(listener, app).await;
    at
}

/// A set-mate that never answers holds a put for the set no longer than the
/// copy deadline: the put is answered, and the reachable set-mate holds the
/// object.
#[test]
fn a_stalled_set_mate_holds_a_put_no_longer_than_the_copy_deadline() {
    common::runtime().block_on(async {
        let stalled = Arc::new(Stalled::default());
        let uc = stalled_set_mate(stalled.clone()).await;
        let (lb, ub) = common::tls_listener().await;
        let set = ["dsm-node-a", "dsm-node-b", "dsm-node-c"];
        let a = node(
            "oc_stall_a",
            "dsm-node-a",
            &set,
            &[("dsm-node-b", &ub), ("dsm-node-c", &uc)],
        )
        .await;
        // B only holds what it is given: a set of its own.
        let b = node("oc_stall_b", "dsm-node-b", &["dsm-node-b"], &[]).await;
        common::serve_tls(lb, b.clone()).await;

        let bound =
            dsm_storage_node::set_client::SET_MATE_COPY_TIMEOUT + std::time::Duration::from_secs(3);
        let answered = tokio::time::timeout(bound, put(&a, b"C stalls", For::TheSet)).await;
        assert_eq!(
            ok_or_panic(answered, "the put is answered within the copy deadline"),
            StatusCode::CREATED
        );
        assert_eq!(holds(&b, b"C stalls").await, StatusCode::OK);
    });
}

/// A node has at most `SET_MATE_COPIES_IN_FLIGHT` copies in flight to one
/// set-mate: more puts for the set at once than that each answer, and the
/// stalled set-mate never holds more of their copies at once.
#[test]
fn copies_in_flight_to_one_set_mate_stay_under_the_cap() {
    common::runtime().block_on(async {
        use std::sync::atomic::Ordering;
        let cap = dsm_storage_node::set_client::SET_MATE_COPIES_IN_FLIGHT;
        let stalled = Arc::new(Stalled::default());
        let uc = stalled_set_mate(stalled.clone()).await;
        let set = ["dsm-node-a", "dsm-node-c"];
        let a = node("oc_cap_a", "dsm-node-a", &set, &[("dsm-node-c", &uc)]).await;

        let payloads: Vec<Vec<u8>> = (0..cap + 4)
            .map(|i| format!("put {i}").into_bytes())
            .collect();
        let answers =
            futures::future::join_all(payloads.iter().map(|p| put(&a, p, For::TheSet))).await;
        assert!(
            answers.iter().all(|s| *s == StatusCode::CREATED),
            "every put is answered: {answers:?}"
        );
        let most = stalled.most.load(Ordering::SeqCst);
        assert!(most > 0, "no copy reached the set-mate");
        assert!(
            most <= cap,
            "{most} copies in flight to one set-mate, over {cap}"
        );
    });
}
