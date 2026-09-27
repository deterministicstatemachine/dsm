// SPDX-License-Identifier: Apache-2.0
//! `/api/v2/health` answers ok only over a live Postgres: it checks a
//! connection out of the pool and runs a query on it, so a node whose store is
//! down reports 503, never "ok".

// `#[tokio::test]` builds its runtime with `expect`, as every suite here does.
#![allow(clippy::disallowed_methods)]

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use dsm_storage_node::AppState;
use std::sync::Arc;
use tower::ServiceExt;

async fn health_of(app: &axum::Router) -> (StatusCode, String) {
    let req = common::ok_or_panic(
        Request::builder()
            .method("GET")
            .uri("/api/v2/health")
            .body(Body::empty()),
        "request",
    );
    let resp = common::ok_or_panic(app.clone().oneshot(req).await, "oneshot");
    let status = resp.status();
    let body = common::ok_or_panic(
        axum::body::to_bytes(resp.into_body(), usize::MAX).await,
        "body",
    );
    (status, String::from_utf8_lossy(&body).to_string())
}

#[tokio::test]
async fn the_health_route_answers_ok_only_over_a_live_postgres() {
    let pool = common::fresh_store("health").await;
    let state = Arc::new(common::ok_or_panic(
        AppState::new("member".to_string(), pool, common::set_client()),
        "app state",
    ));
    let app = common::served(state.clone());

    let (status, body) = health_of(&app).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "ok");

    // The store goes away under the running node: no connection can be
    // checked out, and health says so.
    state.db_pool.close();
    let (status, body) = health_of(&app).await;
    // Both halves in one comparison, so a failure prints the whole answer.
    assert_eq!(
        (status, body.get(..10)),
        (StatusCode::SERVICE_UNAVAILABLE, Some("postgres: "))
    );
}
