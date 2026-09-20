// SPDX-License-Identifier: MIT OR Apache-2.0
//! POSITIVE CONTROL for the demolition: the surviving immutable store still
//! does the one thing a member does with an object — take bytes, return the
//! same bytes. Driven through the real routers the binary serves, on the
//! in-memory backend so it never skips.
//!
//! The node computes the address from the bytes and interprets nothing. A
//! read recomputes the address from the stored tuple and refuses to serve a
//! row that no longer hashes to its own key. Neither side decodes the payload,
//! so the payload here is deliberately arbitrary: not a protocol object.

// The in-memory harness is the SQLite backend; under the Postgres feature
// `db::create_pool` is the Postgres pool and `:memory:` is not a DSN.
#![cfg(feature = "local-dev")]
#![allow(clippy::disallowed_methods)]

use std::sync::Arc;

use axum::{body::Body, http::Request, http::StatusCode, Extension, Router};
use dsm_sdk::util::text_id;
use dsm_storage_node::{
    api, db,
    replication::{ReplicationConfig, ReplicationManager},
    AppState,
};
use tower::ServiceExt;

async fn member() -> Router {
    let endpoint = "http://member.local:8080".to_string();
    let pool = Arc::new(db::create_pool(":memory:", true).expect("pool"));
    db::init_db(&pool).await.expect("init db");
    let rm = Arc::new(
        ReplicationManager::new_for_tests(
            ReplicationConfig {
                replication_factor: 3,
                gossip_interval_ticks: 100,
                failure_timeout_ticks: 300,
                gossip_fanout: 3,
                max_concurrent_jobs: 10,
            },
            "member".to_string(),
            endpoint.clone(),
        )
        .expect("replication manager"),
    );
    let state = Arc::new(AppState::new(
        "member".to_string(),
        &endpoint,
        None,
        pool,
        rm,
    ));
    Router::new()
        .merge(api::objects::immutable::create_read_router(state.clone()))
        .merge(api::objects::immutable::create_write_router())
        .layer(Extension(state))
}

async fn put(app: &Router, namespace: &str, bytes: &[u8]) -> (StatusCode, String) {
    let req = Request::builder()
        .method("POST")
        .uri("/api/v2/immutable/put")
        .header("x-namespace", namespace)
        .body(Body::from(bytes.to_vec()))
        .expect("request");
    let resp = app.clone().oneshot(req).await.expect("oneshot");
    let status = resp.status();
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("body");
    (
        status,
        String::from_utf8(body.to_vec()).expect("address is text"),
    )
}

async fn get(app: &Router, addr: &str) -> (StatusCode, Option<String>, Vec<u8>) {
    let req = Request::builder()
        .method("GET")
        .uri(format!("/api/v2/immutable/{addr}"))
        .body(Body::empty())
        .expect("request");
    let resp = app.clone().oneshot(req).await.expect("oneshot");
    let status = resp.status();
    let ns = resp
        .headers()
        .get("x-namespace")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("body");
    (status, ns, body.to_vec())
}

/// Bytes in, the same bytes out, under the address the node derived from
/// them — and that address is exactly the registry's content address, so a
/// reader that recomputes it from the returned bytes lands on the same key.
#[tokio::test]
async fn bytes_put_into_the_immutable_store_come_back_byte_identical() {
    let app = member().await;
    let payload: Vec<u8> = (0u8..=255).cycle().take(3_001).collect();
    let namespace = "DSM/demolition-positive-control";

    let (status, addr) = put(&app, namespace, &payload).await;
    assert_eq!(status, StatusCode::CREATED, "first put stores");

    let expected = dsm::storage_object::immutable_addr(
        dsm::crypto::domain::TaggedHashDomain::try_new(namespace.as_bytes()).expect("tag"),
        &payload,
    );
    assert_eq!(
        addr,
        text_id::encode_base32_crockford(&expected),
        "the node's address is the registry's content address of the bytes"
    );

    let (status, ns, got) = get(&app, &addr).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        ns.as_deref(),
        Some(namespace),
        "the namespace comes back with the bytes"
    );
    assert_eq!(got, payload, "byte identical");
}

/// Storing the same bytes again is an ack, not a conflict, and changes
/// nothing about what a reader gets.
#[tokio::test]
async fn re_putting_identical_bytes_acks_and_the_read_is_unchanged() {
    let app = member().await;
    let payload = b"the same object, twice".to_vec();
    let namespace = "DSM/demolition-positive-control";

    let (first, addr) = put(&app, namespace, &payload).await;
    assert_eq!(first, StatusCode::CREATED);
    let (again, addr_again) = put(&app, namespace, &payload).await;
    assert_eq!(again, StatusCode::OK, "identical bytes re-put is an ack");
    assert_eq!(addr, addr_again);

    let (status, _, got) = get(&app, &addr).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(got, payload);
}

/// An address nothing was put under is absent, not invented.
#[tokio::test]
async fn an_unknown_address_is_not_found() {
    let app = member().await;
    let never = text_id::encode_base32_crockford(&[0x5Eu8; 32]);
    let (status, _, got) = get(&app, &never).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(got.is_empty());
}
