//! `GET /api/v2/node/info` — exposes this storage node's
//! Genesis-MPC participation public key plus identification metadata
//! so SDK clients can discover candidate MPC contributors.
//!
//! Response shape: `dsm::types::proto::NodeMpcInfoV1` (proto-only,
//! clockless, no JSON). See
//! `docs/plans/2026-04-24-genesis-mpc-and-device-tree.md` Task A.2.
//!
//! This endpoint is **read-only and public** — the MPC public key is
//! already meant to be known by any party offering an MPC session.

use std::sync::Arc;

use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Extension, Router};
use prost::Message;

use dsm::types::proto as pb;

const MPC_PROTOCOL_VERSION: u32 = 1;

pub fn create_router(state: Arc<crate::AppState>) -> Router<()> {
    Router::new()
        .route("/api/v2/node/info", get(get_node_info))
        .layer(Extension(state))
}

/// `GET /api/v2/node/info` — protobuf-encoded `NodeMpcInfoV1`.
async fn get_node_info(
    Extension(state): Extension<Arc<crate::AppState>>,
) -> Result<impl IntoResponse, StatusCode> {
    let mpc_public_key = match &state.mpc_key {
        Some(key) => key.public_key.clone(),
        // No MPC key configured: respond 503 rather than serving an
        // empty key that clients might trust. Test harnesses that mount
        // this router without an mpc_key see this code; production paths
        // always load the key in main.rs before mounting routes.
        None => {
            log::warn!("/api/v2/node/info requested but mpc_key is not configured");
            return Err(StatusCode::SERVICE_UNAVAILABLE);
        }
    };

    let resp = pb::NodeMpcInfoV1 {
        node_id: state.node_id.to_base32(),
        mpc_public_key,
        // Capacity advertising is out of scope for A.2; expose -1
        // until storage tracking lands. Down-stream MPC orchestration
        // only requires node_id + pubkey to pick contributors.
        capacity_bytes: -1,
        mpc_protocol_version: MPC_PROTOCOL_VERSION,
    };

    let mut buf = Vec::with_capacity(resp.encoded_len());
    resp.encode(&mut buf)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok((
        StatusCode::OK,
        [("content-type", "application/octet-stream")],
        buf,
    ))
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)]
mod tests {
    use super::*;
    use crate::identity::StorageNodeMpcKey;
    use crate::replication::{ReplicationConfig, ReplicationManager};
    use crate::AppState;
    use axum::body::Body;
    use axum::http::Request;
    use std::sync::Arc;
    use tower::ServiceExt;

    fn test_replication_manager() -> Arc<ReplicationManager> {
        let cfg = ReplicationConfig {
            replication_factor: 1,
            gossip_interval_ticks: 1000,
            failure_timeout_ticks: 1000,
            gossip_fanout: 1,
            max_concurrent_jobs: 1,
        };
        Arc::new(
            ReplicationManager::new_for_tests(
                cfg,
                "test-node".to_string(),
                "http://localhost:8080".to_string(),
            )
            .expect("test replication manager"),
        )
    }

    async fn test_state_with_mpc_key() -> Arc<AppState> {
        let pool = crate::db::create_pool(":memory:", true).expect("test pool");
        crate::db::init_db(&pool).await.expect("init_db");
        let dir = tempfile::tempdir().expect("tempdir");
        let key = crate::identity::load_or_generate_mpc_key(dir.path()).expect("mpc key");
        // tempdir is dropped at end of test; the SK is already in memory.
        let state = AppState::new(
            "test-node".to_string(),
            "http://localhost:8080",
            None,
            Arc::new(pool),
            test_replication_manager(),
        )
        .with_mpc_key(Arc::new(key));
        Arc::new(state)
    }

    #[tokio::test]
    async fn node_info_returns_mpc_pubkey_and_node_id() {
        let state = test_state_with_mpc_key().await;
        let expected_node_id = state.node_id.to_base32();
        let expected_pk = state
            .mpc_key
            .as_ref()
            .expect("mpc key set in test")
            .public_key
            .clone();
        let app = create_router(state);

        let resp = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/api/v2/node/info")
                    .body(Body::empty())
                    .expect("build request"),
            )
            .await
            .expect("oneshot");
        assert_eq!(resp.status(), StatusCode::OK);

        let bytes = axum::body::to_bytes(resp.into_body(), 1_048_576)
            .await
            .expect("read body");
        let decoded = pb::NodeMpcInfoV1::decode(bytes.as_ref()).expect("decode");

        assert_eq!(decoded.node_id, expected_node_id);
        assert_eq!(decoded.mpc_public_key, expected_pk);
        assert_eq!(decoded.mpc_protocol_version, MPC_PROTOCOL_VERSION);
    }

    #[tokio::test]
    async fn node_info_returns_503_without_mpc_key() {
        // Build an AppState WITHOUT calling with_mpc_key.
        let pool = crate::db::create_pool(":memory:", true).expect("test pool");
        crate::db::init_db(&pool).await.expect("init_db");
        let state = Arc::new(AppState::new(
            "test-node".to_string(),
            "http://localhost:8080",
            None,
            Arc::new(pool),
            test_replication_manager(),
        ));
        let app = create_router(state);

        let resp = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/api/v2/node/info")
                    .body(Body::empty())
                    .expect("build request"),
            )
            .await
            .expect("oneshot");
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    // Suppress the unused `StorageNodeMpcKey` import warning on the
    // off chance of feature-gated builds dropping the test fns.
    fn _type_used(_: StorageNodeMpcKey) {}
}
