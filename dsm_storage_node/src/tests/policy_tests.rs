//! Integration tests for binary-only policy endpoints.
//! These tests will be skipped if the test database isn't available.

use axum::{body::Bytes, http::StatusCode};
use dsm_storage_node::{
    api, db,
    replication::{ReplicationConfig, ReplicationManager},
    AppState,
};
use std::sync::Arc;
use tower::ServiceExt; // for .oneshot

fn ok_or_panic<T, E: std::fmt::Debug>(result: Result<T, E>, context: &str) -> T {
    match result {
        Ok(value) => value,
        Err(err) => panic!("{context}: {err:?}"),
    }
}

fn some_or_panic<T>(value: Option<T>, context: &str) -> T {
    match value {
        Some(value) => value,
        None => panic!("{context}"),
    }
}

// Helper to build a minimal app with only the policy routes mounted.
async fn build_policy_app() -> Option<axum::Router> {
    // Create a pool; it won't connect until used.
    let database_url = std::env::var("DSM_DATABASE_URL")
        .unwrap_or_else(|_| "postgresql://localhost:5432/dsm_storage".to_string());
    let pool = match dsm_storage_node::db::create_pool(&database_url, true) {
        Ok(p) => p,
        Err(_) => return None,
    };
    // Probe connectivity and ensure schema; if it fails, skip tests.
    if db::init_db(&pool).await.is_err() {
        return None;
    }
    let replication_config = ReplicationConfig {
        replication_factor: 3,
        gossip_interval_ticks: 100,
        failure_timeout_ticks: 300,
        gossip_fanout: 3,
        max_concurrent_jobs: 10,
    };
    let replication_manager = match ReplicationManager::new_for_tests(
        replication_config,
        "test-node".to_string(),
        "http://localhost:8080".to_string(),
    ) {
        Ok(manager) => Arc::new(manager),
        Err(err) => {
            eprintln!("skipping: failed to create replication manager: {err}");
            return None;
        }
    };
    let state = AppState::new("test-node".to_string(), None, Arc::new(pool), replication_manager);
    let app = axum::Router::new()
        .merge(api::policy::create_router())
        .with_state(state);
    Some(app)
}

#[tokio::test]
async fn policy_round_trip_binary_ok() {
    let Some(app) = build_policy_app().await else {
        eprintln!("skipping: DB not available");
        return;
    };

    // Prepare canonical policy bytes
    let policy_bytes = Bytes::from_static(b"allow:always\nversion:1\n");

    // POST /api/v2/policy -> returns 32-byte anchor (binary)
    let response = ok_or_panic(
        axum::http::Request::builder()
            .method("POST")
            .uri("/api/v2/policy")
            .header(axum::http::header::CONTENT_TYPE, "application/octet-stream")
            .body(axum::body::Body::from(policy_bytes.clone())),
        "failed to build policy create request",
    );

    let response = ok_or_panic(
        app.clone().oneshot(response).await,
        "failed to send policy create request",
    );
    assert_eq!(response.status(), StatusCode::OK);
    let headers = response.headers();
    assert_eq!(
        some_or_panic(
            headers.get(axum::http::header::CONTENT_TYPE),
            "missing content-type header",
        ),
        "application/octet-stream"
    );
    assert_eq!(
        some_or_panic(
            headers.get(axum::http::header::CONTENT_LENGTH),
            "missing content-length header",
        ),
        "32"
    );
    let bytes = ok_or_panic(
        hyper::body::to_bytes(response.into_body()).await,
        "failed to read policy create response body",
    );
    assert_eq!(bytes.len(), 32);
    let mut anchor = [0u8; 32];
    anchor.copy_from_slice(&bytes);

    // POST /api/v2/policy/get with the 32-byte anchor -> returns original bytes
    let get_req = ok_or_panic(
        axum::http::Request::builder()
            .method("POST")
            .uri("/api/v2/policy/get")
            .header(axum::http::header::CONTENT_TYPE, "application/octet-stream")
            .body(axum::body::Body::from(Bytes::from(anchor.to_vec()))),
        "failed to build policy get request",
    );
    let get_resp = ok_or_panic(app.oneshot(get_req).await, "failed to send policy get request");
    assert_eq!(get_resp.status(), StatusCode::OK);
    let get_headers = get_resp.headers();
    assert_eq!(
        some_or_panic(
            get_headers.get(axum::http::header::CONTENT_TYPE),
            "missing content-type header on policy get",
        ),
        "application/octet-stream"
    );
    let got = ok_or_panic(
        hyper::body::to_bytes(get_resp.into_body()).await,
        "failed to read policy get response body",
    );
    assert_eq!(got.as_ref(), b"allow:always\nversion:1\n");
}

#[tokio::test]
async fn policy_get_bad_anchor_len_rejected() {
    let Some(app) = build_policy_app().await else {
        eprintln!("skipping: DB not available");
        return;
    };

    // Send non-32-byte body
    let req = ok_or_panic(
        axum::http::Request::builder()
            .method("POST")
            .uri("/api/v2/policy/get")
            .header(axum::http::header::CONTENT_TYPE, "application/octet-stream")
            .body(axum::body::Body::from(Bytes::from_static(b"short"))),
        "failed to build bad-anchor request",
    );
    let resp = ok_or_panic(app.oneshot(req).await, "failed to send bad-anchor request");
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn policy_put_empty_body_rejected() {
    let Some(app) = build_policy_app().await else {
        eprintln!("skipping: DB not available");
        return;
    };

    let req = ok_or_panic(
        axum::http::Request::builder()
            .method("POST")
            .uri("/api/v2/policy")
            .header(axum::http::header::CONTENT_TYPE, "application/octet-stream")
            .body(axum::body::Body::from(Bytes::new())),
        "failed to build empty-policy request",
    );
    let resp = ok_or_panic(app.oneshot(req).await, "failed to send empty-policy request");
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}
