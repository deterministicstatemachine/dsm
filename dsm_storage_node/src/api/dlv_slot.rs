// SPDX-License-Identifier: Apache-2.0
//! DLV Slot management (deterministic, clockless)
//! - PUT creates the slot idempotently with capacity and stake hash.
//! - GET returns 16 bytes: capacity_bytes(be64) || used_bytes(be64).
//! - Raw bytes only; no JSON, no wall-clock markers.

#[cfg(test)]
use crate::replication::{ReplicationConfig, ReplicationManager};
use axum::{
    body::Bytes,
    extract::{Extension, Path},
    http::{HeaderMap, HeaderValue, StatusCode},
    response::IntoResponse,
    routing::put,
    Router,
};
use std::sync::Arc;

use crate::db;
use crate::AppState;
use dsm_sdk::util::text_id;

const HDR_CAPACITY: &str = "x-capacity-bytes"; // i64
const HDR_STAKE_HASH: &str = "x-stake-hash"; // base32 bytes

pub fn create_router(state: Arc<AppState>) -> Router<()> {
    Router::new()
        .route("/api/v2/dlv/{dlv}/slot", put(put_slot).get(get_slot))
        .layer(Extension(state))
}

/// Create or idempotently ensure a DLV slot exists.
/// Required headers: x-capacity-bytes, x-stake-hash (base32)
pub async fn put_slot(
    Extension(state): Extension<Arc<AppState>>,
    Path(dlv): Path<String>,
    headers: HeaderMap,
    _body: Bytes,
) -> Result<impl IntoResponse, StatusCode> {
    let dlv_b = text_id::decode_base32_crockford(&dlv).ok_or(StatusCode::BAD_REQUEST)?;
    if dlv_b.len() != 32 {
        return Err(StatusCode::BAD_REQUEST);
    }

    let capacity = headers
        .get(HDR_CAPACITY)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<i64>().ok())
        .ok_or(StatusCode::BAD_REQUEST)?;
    let stake = headers
        .get(HDR_STAKE_HASH)
        .and_then(|v| v.to_str().ok())
        .and_then(text_id::decode_base32_crockford)
        .ok_or(StatusCode::BAD_REQUEST)?;

    let pool = &*state.db_pool;
    db::create_slot(pool, &dlv_b, capacity, &stake)
        .await
        .map_err(|e| {
            log::warn!("dlv_slot: create_slot DB error: {e}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    Ok(StatusCode::OK)
}

/// Get a DLV slot's capacity/used as 16 bytes: capacity(be64) || used(be64)
pub async fn get_slot(
    Extension(state): Extension<Arc<AppState>>,
    Path(dlv): Path<String>,
) -> Result<impl IntoResponse, StatusCode> {
    let dlv_b = text_id::decode_base32_crockford(&dlv).ok_or(StatusCode::BAD_REQUEST)?;
    if dlv_b.len() != 32 {
        return Err(StatusCode::BAD_REQUEST);
    }

    let (capacity_bytes, used_bytes) = db::get_dlv_slot_capacity(&state.db_pool, &dlv_b)
        .await
        .map_err(|e| {
            log::warn!("dlv_slot: get_dlv_slot_capacity DB error: {e}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?
        .ok_or(StatusCode::NOT_FOUND)?;

    let mut out = [0u8; 16];
    out[..8].copy_from_slice(&capacity_bytes.to_be_bytes());
    out[8..].copy_from_slice(&used_bytes.to_be_bytes());
    let mut headers = HeaderMap::new();
    headers.insert(
        axum::http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    Ok((StatusCode::OK, headers, out.to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt as _; // for oneshot

    async fn maybe_app() -> Option<axum::Router> {
        if std::env::var("DSM_RUN_DB_TESTS").ok().as_deref() != Some("1") {
            return None;
        }
        let database_url = std::env::var("DSM_DATABASE_URL")
            .unwrap_or_else(|_| "postgresql://localhost:5432/dsm_storage".to_string());
        let pool = crate::db::create_pool(&database_url, false).ok()?;
        crate::db::init_db(&pool).await.ok()?;
        let replication_config = ReplicationConfig {
            replication_factor: 3,
            gossip_interval_ticks: 100,
            failure_timeout_ticks: 300,
            gossip_fanout: 3,
            max_concurrent_jobs: 10,
        };
        let replication_manager = Arc::new(
            ReplicationManager::new(
                replication_config,
                "test-node".to_string(),
                "http://localhost:8080".to_string(),
                std::path::Path::new("certs/node.crt"),
            )
            .unwrap_or_else(|e| panic!("Failed to create replication manager: {e}")),
        );
        let state = AppState::new(
            "test-node".into(),
            None,
            std::sync::Arc::new(pool),
            replication_manager,
        );
        Some(create_router(std::sync::Arc::new(state)))
    }

    #[test]
    fn create_and_get_slot_smoke() {
        let rt = tokio::runtime::Runtime::new()
            .unwrap_or_else(|e| panic!("failed to create runtime: {e}"));
        rt.block_on(async {
            let Some(app) = maybe_app().await else {
                return;
            };
            let dlv = [3u8; 32];
            let dlv_b32 = text_id::encode_base32_crockford(&dlv);
            let stake = vec![5u8; 32];
            let stake_b32 = text_id::encode_base32_crockford(&stake);

            // Create slot
            let req_put = Request::builder()
                .method("PUT")
                .uri(format!("/api/v2/dlv/{}/slot", dlv_b32))
                .header(HDR_CAPACITY, "1024")
                .header(HDR_STAKE_HASH, stake_b32)
                .body(Body::empty())
                .unwrap_or_else(|e| panic!("request build failed: {e}"));
            let resp_put = app
                .clone()
                .oneshot(req_put)
                .await
                .unwrap_or_else(|e| panic!("oneshot failed: {e}"));
            assert!(matches!(
                resp_put.status(),
                StatusCode::OK | StatusCode::CREATED
            ));

            // Get slot
            let req_get = Request::builder()
                .method("GET")
                .uri(format!("/api/v2/dlv/{}/slot", dlv_b32))
                .body(Body::empty())
                .unwrap_or_else(|e| panic!("request build failed: {e}"));
            let resp_get = app
                .clone()
                .oneshot(req_get)
                .await
                .unwrap_or_else(|e| panic!("oneshot failed: {e}"));
            assert_eq!(resp_get.status(), StatusCode::OK);
            let bytes = axum::body::to_bytes(resp_get.into_body(), usize::MAX)
                .await
                .unwrap_or_else(|e| panic!("read body failed: {e}"));
            assert_eq!(bytes.len(), 16);
        });
    }
}
