//! Integration tests for object store endpoints.
//! Skips when Postgres test database is unavailable.

#![allow(clippy::disallowed_methods)]

use axum::{body::Bytes, http::StatusCode, Extension};
use dsm_storage_node::{
    api, db,
    replication::{ReplicationConfig, ReplicationManager},
    AppState,
};
use rand::Rng;
use std::sync::Arc;
use tower::ServiceExt; // for .oneshot

async fn build_object_app() -> Option<axum::Router> {
    let database_url = std::env::var("DSM_DATABASE_URL")
        .unwrap_or_else(|_| "postgresql://localhost:5432/dsm_storage".to_string());
    let pool = match dsm_storage_node::db::create_pool(&database_url, true) {
        Ok(p) => p,
        Err(_) => return None,
    };
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
    let replication_manager = Arc::new(
        ReplicationManager::new_for_tests(
            replication_config,
            "test-node".to_string(),
            "http://localhost:8080".to_string(),
        )
        .unwrap_or_else(|e| panic!("Failed to create replication manager: {e}")),
    );
    let state = AppState::new(
        "test-node".to_string(),
        None,
        Arc::new(pool),
        replication_manager,
    );
    let state_arc = Arc::new(state);
    // Merge both read and write routers (tests bypass auth middleware)
    let app = axum::Router::new()
        .merge(api::objects::store::create_router(state_arc.clone()))
        .merge(api::objects::store::create_write_router())
        .layer(Extension(state_arc));
    Some(app)
}

#[tokio::test]
async fn put_rejects_empty_body_and_missing_headers() {
    let Some(app) = build_object_app().await else {
        eprintln!("skipping: DB not available");
        return;
    };

    // Empty body -> 400
    let req = axum::http::Request::builder()
        .method("POST")
        .uri("/api/v2/object/put")
        .header(axum::http::header::CONTENT_TYPE, "application/octet-stream")
        .body(axum::body::Body::from(Bytes::new()))
        .unwrap_or_else(|e| panic!("request build failed: {e}"));
    let resp = app
        .clone()
        .oneshot(req)
        .await
        .unwrap_or_else(|e| panic!("oneshot failed: {e}"));
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    // Missing required headers -> 400 (bad dlv-id/path)
    let req2 = axum::http::Request::builder()
        .method("POST")
        .uri("/api/v2/object/put")
        .header(axum::http::header::CONTENT_TYPE, "application/octet-stream")
        .body(axum::body::Body::from(Bytes::from_static(b"hi")))
        .unwrap_or_else(|e| panic!("request build failed: {e}"));
    let resp2 = app
        .clone()
        .oneshot(req2)
        .await
        .unwrap_or_else(|e| panic!("oneshot failed: {e}"));
    assert_eq!(resp2.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn put_requires_slot_or_bootstrap_headers() {
    let Some(app) = build_object_app().await else {
        eprintln!("skipping: DB not available");
        return;
    };

    // Generate random DLV ID to avoid collisions
    let mut rng = rand::thread_rng();
    let dlv_bytes: [u8; 32] = rng.gen();
    let dlv_hex = dlv_bytes
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>();

    // Without capacity/stake and slot absent -> 428 Precondition Required
    let req = axum::http::Request::builder()
        .method("POST")
        .uri("/api/v2/object/put")
        .header(axum::http::header::CONTENT_TYPE, "application/octet-stream")
        .header("x-dlv-id", &dlv_hex)
        .header("x-path", "foo/bar")
        .body(axum::body::Body::from(Bytes::from_static(b"hello")))
        .unwrap_or_else(|e| panic!("request build failed: {e}"));
    let resp = app
        .clone()
        .oneshot(req)
        .await
        .unwrap_or_else(|e| panic!("oneshot failed: {e}"));
    assert_eq!(resp.status(), StatusCode::PRECONDITION_REQUIRED);

    // With capacity+stake -> creates slot and returns 200 with x-object-address
    let req2 = axum::http::Request::builder()
        .method("POST")
        .uri("/api/v2/object/put")
        .header(axum::http::header::CONTENT_TYPE, "application/octet-stream")
        .header("x-dlv-id", &dlv_hex)
        .header("x-path", "foo/bar")
        .header("x-capacity-bytes", "1024")
        .header("x-stake-hash", &"22".repeat(32))
        .body(axum::body::Body::from(Bytes::from_static(b"hello")))
        .unwrap_or_else(|e| panic!("request build failed: {e}"));
    let resp2 = app
        .clone()
        .oneshot(req2)
        .await
        .unwrap_or_else(|e| panic!("oneshot failed: {e}"));
    assert_eq!(resp2.status(), StatusCode::OK);
    let headers = resp2.headers();
    let addr = headers
        .get("x-object-address")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(!addr.is_empty());

    // GET by a random address should 404
    let get_req = axum::http::Request::builder()
        .method("GET")
        .uri(format!("/api/v2/object/by-addr/{}", "aa".repeat(32)))
        .body(axum::body::Body::empty())
        .unwrap_or_else(|e| panic!("request build failed: {e}"));
    let get_resp = app
        .clone()
        .oneshot(get_req)
        .await
        .unwrap_or_else(|e| panic!("oneshot failed: {e}"));
    assert_eq!(get_resp.status(), StatusCode::NOT_FOUND);
}
