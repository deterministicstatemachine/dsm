// SPDX-License-Identifier: MIT OR Apache-2.0
//! The keyed-cell and index contract, executed against the real routers.
//!
//! A member keeps every value it is given for a key, in arrival order, and
//! never refuses, replaces or compares. Absence is asserted by shape: `200`
//! with an empty list. An index is append-only and pages from the last `seq`.
//! Nothing here decodes a value; the payloads are arbitrary bytes on purpose.

#![cfg(feature = "local-dev")]
#![allow(clippy::disallowed_methods)]

use std::sync::Arc;

use axum::{body::Body, http::Request, http::StatusCode, Router};
use dsm_sdk::util::text_id;
use dsm_storage_node::{
    db,
    replication::{ReplicationConfig, ReplicationManager},
    AppState,
};
use prost::Message;
use tower::ServiceExt;

const NS: &str = "DSM/cells-contract";

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
    // The binary's own assembly (R2): what this suite drives is what is served.
    dsm_storage_node::storage_contract_router(state)
}

fn key(tag: u8) -> String {
    text_id::encode_base32_crockford(&[tag; 32])
}

async fn put(app: &Router, ns: Option<&str>, key: &str, bytes: &[u8]) -> StatusCode {
    let mut req = Request::builder()
        .method("POST")
        .uri(format!("/api/v2/cell/{key}"));
    if let Some(ns) = ns {
        req = req.header("x-namespace", ns);
    }
    let req = req.body(Body::from(bytes.to_vec())).expect("request");
    app.clone().oneshot(req).await.expect("oneshot").status()
}

async fn get(app: &Router, key: &str) -> (StatusCode, Vec<Vec<u8>>) {
    let req = Request::builder()
        .method("GET")
        .uri(format!("/api/v2/cell/{key}"))
        .header("x-namespace", NS)
        .body(Body::empty())
        .expect("request");
    let resp = app.clone().oneshot(req).await.expect("oneshot");
    let status = resp.status();
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("body");
    let values = if status == StatusCode::OK {
        dsm::types::proto::CellValuesV1::decode(body.as_ref())
            .expect("CellValuesV1")
            .values
    } else {
        Vec::new()
    };
    (status, values)
}

async fn append(app: &Router, locator: &str, addr: &[u8]) -> StatusCode {
    let req = Request::builder()
        .method("POST")
        .uri(format!("/api/v2/index/{locator}"))
        .header("x-namespace", NS)
        .body(Body::from(addr.to_vec()))
        .expect("request");
    app.clone().oneshot(req).await.expect("oneshot").status()
}

async fn page(app: &Router, locator: &str, query: &str) -> Vec<(i64, Vec<u8>)> {
    let req = Request::builder()
        .method("GET")
        .uri(format!("/api/v2/index/{locator}{query}"))
        .header("x-namespace", NS)
        .body(Body::empty())
        .expect("request");
    let resp = app.clone().oneshot(req).await.expect("oneshot");
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("body");
    dsm::types::proto::IndexPageV1::decode(body.as_ref())
        .expect("IndexPageV1")
        .entries
        .into_iter()
        .map(|e| (e.seq, e.addr))
        .collect()
}

/// The property the old registers broke: a second, different value at a
/// key is KEPT, after the first. Nothing is refused and nothing is compared.
async fn put_batch(app: &Router, entries: Vec<(Vec<u8>, [u8; 32], Vec<u8>)>) -> StatusCode {
    let batch = dsm::types::proto::CellPutsV1 {
        entries: entries
            .into_iter()
            .map(|(namespace, key, value)| dsm::types::proto::CellPutV1 {
                namespace,
                key: key.to_vec(),
                value,
            })
            .collect(),
    };
    let req = Request::builder()
        .method("POST")
        .uri("/api/v2/cells")
        .body(Body::from(batch.encode_to_vec()))
        .expect("request");
    app.clone().oneshot(req).await.expect("oneshot").status()
}

/// Part II §17.4: the two position cells are taken in ONE local transaction
/// on the served assembly — both after anything already there, or, for a
/// batch that names no cell, neither.
#[tokio::test]
async fn a_batch_put_takes_every_key_or_none_on_the_served_assembly() {
    let app = member().await;
    let (k1, k2) = (key(0x21), key(0x22));
    assert_eq!(
        put(&app, Some(NS), &k1, b"already here").await,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        put_batch(
            &app,
            vec![
                (NS.as_bytes().to_vec(), [0x21; 32], b"half one".to_vec()),
                (NS.as_bytes().to_vec(), [0x22; 32], b"half two".to_vec()),
            ],
        )
        .await,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        get(&app, &k1).await.1,
        vec![b"already here".to_vec(), b"half one".to_vec()]
    );
    assert_eq!(get(&app, &k2).await.1, vec![b"half two".to_vec()]);

    // A batch with an entry that names no cell is refused whole: the shape
    // is checked before anything is written.
    let (k3, k4) = (key(0x23), key(0x24));
    assert_eq!(
        put_batch(
            &app,
            vec![
                (
                    NS.as_bytes().to_vec(),
                    [0x23; 32],
                    b"would be held".to_vec()
                ),
                (
                    b"not a namespace".to_vec(),
                    [0x24; 32],
                    b"names no cell".to_vec()
                ),
            ],
        )
        .await,
        StatusCode::BAD_REQUEST
    );
    assert!(get(&app, &k3).await.1.is_empty(), "none, not one");
    assert!(get(&app, &k4).await.1.is_empty());
}

#[tokio::test]
async fn a_second_value_at_a_key_is_kept_after_the_first_never_refused() {
    let app = member().await;
    let k = key(0x01);
    assert_eq!(
        put(&app, Some(NS), &k, b"first").await,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        put(&app, Some(NS), &k, b"second, different").await,
        StatusCode::NO_CONTENT,
        "a contested key is not a refusal"
    );
    let (status, values) = get(&app, &k).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        values,
        vec![b"first".to_vec(), b"second, different".to_vec()],
        "both values, in arrival order"
    );
}

/// Identical bytes twice are two arrivals. The member does not compare.
#[tokio::test]
async fn an_identical_value_put_twice_is_held_twice() {
    let app = member().await;
    let k = key(0x02);
    put(&app, Some(NS), &k, b"same").await;
    put(&app, Some(NS), &k, b"same").await;
    let (_, values) = get(&app, &k).await;
    assert_eq!(values, vec![b"same".to_vec(), b"same".to_vec()]);
}

/// Absence is asserted by shape, not by status: an empty list under `200`.
#[tokio::test]
async fn a_key_nothing_was_put_under_reads_as_an_empty_list_with_200() {
    let app = member().await;
    let (status, values) = get(&app, &key(0x5E)).await;
    assert_eq!(status, StatusCode::OK);
    assert!(values.is_empty());
}

/// The namespace scopes the key: the same key under another namespace is
/// another cell.
#[tokio::test]
async fn a_namespace_scopes_the_key() {
    let app = member().await;
    let k = key(0x03);
    put(&app, Some(NS), &k, b"in NS").await;
    put(&app, Some("DSM/other"), &k, b"in other").await;
    let (_, values) = get(&app, &k).await;
    assert_eq!(values, vec![b"in NS".to_vec()]);
}

/// An index is append-only and pages from the last `seq`.
#[tokio::test]
async fn an_index_pages_in_append_order_from_the_last_seq() {
    let app = member().await;
    let loc = key(0x10);
    let addrs = [[0xA1u8; 32], [0xA2u8; 32], [0xA3u8; 32]];
    for a in &addrs {
        assert_eq!(append(&app, &loc, a).await, StatusCode::NO_CONTENT);
    }
    let first = page(&app, &loc, "?limit=2").await;
    assert_eq!(
        first.iter().map(|(_, a)| a.clone()).collect::<Vec<_>>(),
        vec![addrs[0].to_vec(), addrs[1].to_vec()]
    );
    let last_seq = first[1].0;
    let rest = page(&app, &loc, &format!("?after={last_seq}")).await;
    assert_eq!(
        rest.iter().map(|(_, a)| a.clone()).collect::<Vec<_>>(),
        vec![addrs[2].to_vec()]
    );
    let none = page(&app, &loc, &format!("?after={}", rest[0].0)).await;
    assert!(
        none.is_empty(),
        "past the end is an empty page, not an error"
    );
}

/// The only refusals are bounds, and they are about the request's shape,
/// never its meaning.
#[tokio::test]
async fn only_malformed_requests_are_refused() {
    let app = member().await;
    let k = key(0x04);
    assert_eq!(
        put(&app, Some(NS), &k, b"").await,
        StatusCode::BAD_REQUEST,
        "empty body"
    );
    assert_eq!(
        put(&app, None, &k, b"x").await,
        StatusCode::BAD_REQUEST,
        "no namespace"
    );
    assert_eq!(
        put(&app, Some("no-prefix"), &k, b"x").await,
        StatusCode::BAD_REQUEST,
        "namespace outside the hasher's contract"
    );
    assert_eq!(
        put(&app, Some(NS), "not-base32!!", b"x").await,
        StatusCode::BAD_REQUEST,
        "key is not a 32-byte digest"
    );
    assert_eq!(
        append(&app, &key(0x11), b"short").await,
        StatusCode::BAD_REQUEST,
        "an index entry is exactly 32 bytes"
    );
}
