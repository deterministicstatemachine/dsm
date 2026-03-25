//! Integration tests for binary-only policy endpoints.
//! These tests will be skipped if the test database isn't available.

use axum::{body::Bytes, http::StatusCode};
use dsm_storage_node::{api, db, AppState, replication::{ReplicationConfig, ReplicationManager}};
use std::sync::Arc;
use tower::ServiceExt; // for .oneshot

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
    let replication_manager = Arc::new(ReplicationManager::new_for_tests(
        replication_config,
        "test-node".to_string(),
        "http://localhost:8080".to_string(),
    ).expect("Failed to create replication manager"));
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
    let response =
        axum::http::Request::builder()
            .method("POST")
            .uri("/api/v2/policy")
            .header(axum::http::header::CONTENT_TYPE, "application/octet-stream")
            .body(axum::body::Body::from(policy_bytes.clone()))
            .unwrap();

    let response = app.clone().oneshot(response).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let headers = response.headers();
    assert_eq!(headers.get(axum::http::header::CONTENT_TYPE).unwrap(), "application/octet-stream");
    assert_eq!(headers.get(axum::http::header::CONTENT_LENGTH).unwrap(), "32");
    let bytes = hyper::body::to_bytes(response.into_body()).await.unwrap();
    assert_eq!(bytes.len(), 32);
    let mut anchor = [0u8; 32];
    anchor.copy_from_slice(&bytes);

    // POST /api/v2/policy/get with the 32-byte anchor -> returns original bytes
    let get_req = axum::http::Request::builder()
        .method("POST")
        .uri("/api/v2/policy/get")
        .header(axum::http::header::CONTENT_TYPE, "application/octet-stream")
        .body(axum::body::Body::from(Bytes::from(anchor.to_vec())))
        .unwrap();
    let get_resp = app.oneshot(get_req).await.unwrap();
    assert_eq!(get_resp.status(), StatusCode::OK);
    let get_headers = get_resp.headers();
    assert_eq!(get_headers.get(axum::http::header::CONTENT_TYPE).unwrap(), "application/octet-stream");
    let got = hyper::body::to_bytes(get_resp.into_body()).await.unwrap();
    assert_eq!(got.as_ref(), b"allow:always\nversion:1\n");
}

#[tokio::test]
async fn policy_get_bad_anchor_len_rejected() {
    let Some(app) = build_policy_app().await else {
        eprintln!("skipping: DB not available");
        return;
    };

    // Send non-32-byte body
    let req = axum::http::Request::builder()
        .method("POST")
        .uri("/api/v2/policy/get")
        .header(axum::http::header::CONTENT_TYPE, "application/octet-stream")
        .body(axum::body::Body::from(Bytes::from_static(b"short")))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn policy_put_empty_body_rejected() {
    let Some(app) = build_policy_app().await else {
        eprintln!("skipping: DB not available");
        return;
    };

    let req = axum::http::Request::builder()
        .method("POST")
        .uri("/api/v2/policy")
        .header(axum::http::header::CONTENT_TYPE, "application/octet-stream")
        .body(axum::body::Body::from(Bytes::new()))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}
