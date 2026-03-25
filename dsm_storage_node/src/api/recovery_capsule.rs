// SPDX-License-Identifier: Apache-2.0
//! Recovery Capsule mirror (deterministic, raw bytes)
//! - Address := H("DSM/recovery/capsule" || content)
//! - Capacity enforcement via provided DLV slot
//! - Raw bytes only; no JSON.

#[cfg(test)]
use crate::replication::{ReplicationConfig, ReplicationManager};
use axum::{
    body::Bytes,
    extract::{Extension, Path},
    http::{HeaderMap, HeaderValue, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Router,
};
use std::sync::Arc;

use super::hardening::blake3_tagged;
use crate::db;
use crate::AppState;
use dsm_sdk::util::text_id;

const HDR_DLV_ID: &str = "x-dlv-id"; // base32 32B DLV partition id
const HDR_CAPACITY: &str = "x-capacity-bytes"; // optional i64 for new slot
const HDR_STAKE_HASH: &str = "x-stake-hash"; // optional base32 bytes for new slot
const HDR_OBJ_ADDR: &str = "x-object-address"; // response header

#[inline]
fn capsule_addr(content: &[u8]) -> String {
    let digest = blake3_tagged("DSM/recovery/capsule", content);
    text_id::encode_base32_crockford(&digest)
}

pub fn create_router(state: Arc<AppState>) -> Router<()> {
    Router::new()
        .route("/api/v2/recovery/capsule/publish", post(publish_capsule))
        .route("/api/v2/recovery/capsule/by-addr/{addr}", get(get_by_addr))
        .layer(Extension(state))
}

/// Publish a Recovery Capsule under a deterministic address.
/// Required header: x-dlv-id (for capacity accounting)
/// Optional: x-capacity-bytes and x-stake-hash to bootstrap slot
pub async fn publish_capsule(
    Extension(state): Extension<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, StatusCode> {
    if body.is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }

    // Required dlv id
    let dlv_id_b = headers
        .get(HDR_DLV_ID)
        .and_then(|v| v.to_str().ok())
        .and_then(text_id::decode_base32_crockford)
        .ok_or(StatusCode::BAD_REQUEST)?;

    let capacity_opt = headers
        .get(HDR_CAPACITY)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<i64>().ok());
    let stake_hash_opt = headers
        .get(HDR_STAKE_HASH)
        .and_then(|v| v.to_str().ok())
        .and_then(text_id::decode_base32_crockford);

    // Ensure slot exists if caller provided bootstrap
    let pool = &*state.db_pool;
    let mut exists = db::slot_exists(pool, &dlv_id_b).await.map_err(|e| {
        log::warn!("recovery_capsule: slot_exists DB error: {e}");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    if !exists {
        match (capacity_opt, stake_hash_opt.as_ref()) {
            (Some(cap), Some(stake)) => {
                db::create_slot(pool, &dlv_id_b, cap, stake)
                    .await
                    .map_err(|e| {
                        log::warn!("recovery_capsule: create_slot DB error: {e}");
                        StatusCode::INTERNAL_SERVER_ERROR
                    })?;
                exists = db::slot_exists(pool, &dlv_id_b).await.map_err(|e| {
                    log::warn!("recovery_capsule: slot_exists (post-create) DB error: {e}");
                    StatusCode::INTERNAL_SERVER_ERROR
                })?;
            }
            _ => return Err(StatusCode::PRECONDITION_REQUIRED),
        }
    }
    if !exists {
        log::warn!("recovery_capsule: slot still does not exist after creation attempt");
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }

    // Deterministic address independent of DLV
    let addr = capsule_addr(&body);

    // Store with atomic capacity check
    let new_size: i64 = body.len() as i64;
    db::upsert_object_with_capacity_check(pool, &addr, body.as_ref(), &dlv_id_b, new_size)
        .await
        .map_err(|e| {
            if e.to_string().contains("capacity_exceeded") {
                StatusCode::INSUFFICIENT_STORAGE
            } else {
                StatusCode::INTERNAL_SERVER_ERROR
            }
        })?;

    let mut out = HeaderMap::new();
    let _ = out.insert(
        HDR_OBJ_ADDR,
        HeaderValue::from_str(&addr).unwrap_or_else(|_| HeaderValue::from_static("")),
    );
    Ok((StatusCode::OK, out))
}

/// Fetch raw capsule bytes by address
pub async fn get_by_addr(
    Extension(state): Extension<Arc<AppState>>,
    Path(addr): Path<String>,
) -> Result<impl IntoResponse, StatusCode> {
    let bytes = db::get_object_by_key(&state.db_pool, &addr)
        .await
        .map_err(|e| {
            log::warn!("recovery_capsule: get_by_addr DB error for {addr}: {e}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?
        .ok_or(StatusCode::NOT_FOUND)?;
    let mut headers = HeaderMap::new();
    headers.insert(
        axum::http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    Ok((StatusCode::OK, headers, bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Request;
    use tower::ServiceExt; // oneshot

    async fn maybe_state_and_app() -> Option<(Arc<AppState>, axum::Router)> {
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
            ReplicationManager::new_for_tests(
                replication_config,
                "test-node".to_string(),
                "http://localhost:8080".to_string(),
            )
            .unwrap_or_else(|e| panic!("Failed to create replication manager: {e}")),
        );
        let state = AppState::new(
            "test-node".into(),
            None,
            std::sync::Arc::new(pool),
            replication_manager,
        );
        let state_arc = std::sync::Arc::new(state);
        let app = create_router(state_arc.clone());
        Some((state_arc, app))
    }

    #[test]
    fn publish_and_fetch_capsule_smoke() {
        let rt = tokio::runtime::Runtime::new()
            .unwrap_or_else(|e| panic!("failed to create runtime: {e}"));
        rt.block_on(async {
            let Some((state, app)) = maybe_state_and_app().await else {
                return;
            };
            // Create slot first
            let dlv = [7u8; 32];
            let dlv_b32 = text_id::encode_base32_crockford(&dlv);
            let stake = vec![9u8; 32];
            let stake_b32 = text_id::encode_base32_crockford(&stake);
            let req_slot = Request::builder()
                .method("PUT")
                .uri(format!("/api/v2/dlv/{}/slot", dlv_b32))
                .header("x-capacity-bytes", "16384")
                .header("x-stake-hash", stake_b32)
                .body(axum::body::Body::from(Vec::<u8>::new()))
                .unwrap_or_else(|e| panic!("request build failed: {e}"));
            // Build a tiny router for slot ops
            let slot_app = crate::api::dlv_slot::create_router(state.clone());
            let resp_slot = slot_app
                .clone()
                .oneshot(req_slot)
                .await
                .unwrap_or_else(|e| panic!("oneshot failed: {e}"));
            assert_eq!(resp_slot.status(), StatusCode::OK);

            // Publish capsule
            let capsule = b"hello-capsule".to_vec();
            let req_pub = Request::builder()
                .method("POST")
                .uri("/api/v2/recovery/capsule/publish")
                .header(axum::http::header::CONTENT_TYPE, "application/octet-stream")
                .header("x-dlv-id", dlv_b32.clone())
                .body(axum::body::Body::from(capsule.clone()))
                .unwrap_or_else(|e| panic!("request build failed: {e}"));
            let resp_pub = app
                .clone()
                .oneshot(req_pub)
                .await
                .unwrap_or_else(|e| panic!("oneshot failed: {e}"));
            assert_eq!(resp_pub.status(), StatusCode::OK);
            let addr = resp_pub
                .headers()
                .get("x-object-address")
                .unwrap_or_else(|| panic!("x-object-address header missing"))
                .to_str()
                .unwrap_or_else(|e| panic!("header to_str failed: {e}"))
                .to_string();

            // Fetch capsule by addr
            let req_get = Request::builder()
                .method("GET")
                .uri(format!("/api/v2/recovery/capsule/by-addr/{}", addr))
                .body(axum::body::Body::empty())
                .unwrap_or_else(|e| panic!("request build failed: {e}"));
            let resp_get = app
                .clone()
                .oneshot(req_get)
                .await
                .unwrap_or_else(|e| panic!("oneshot failed: {e}"));
            assert_eq!(resp_get.status(), StatusCode::OK);
            use axum::body::to_bytes;
            let bytes = to_bytes(resp_get.into_body(), usize::MAX)
                .await
                .unwrap_or_else(|e| panic!("read body failed: {e}"));
            assert_eq!(bytes.as_ref(), capsule.as_slice());
        });
    }
}
