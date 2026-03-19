//! Node discovery endpoint — returns alive peer addresses for SDK auto-discovery.
//!
//! Protobuf-only, clockless, index-only. Responds with `DiscoverLocalResponse`
//! containing the current set of alive node addresses from the gossip protocol.

use std::sync::Arc;

use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Extension, Router};
use prost::Message;

use dsm::types::proto as pb;

/// Register the discovery route.
pub fn create_router(state: Arc<crate::AppState>) -> Router<()> {
    Router::new()
        .route("/api/v2/nodes/discover", get(discover_nodes))
        .layer(Extension(state))
}

/// `GET /api/v2/nodes/discover` — returns alive node addresses as protobuf.
///
/// SDK `StorageNodeDiscovery::discover_from_endpoint()` expects a
/// `DiscoverLocalResponse { discovered_nodes, discovery_method, event_counter }`.
async fn discover_nodes(
    Extension(state): Extension<Arc<crate::AppState>>,
) -> Result<impl IntoResponse, StatusCode> {
    let alive = state.replication_manager.get_alive_nodes();
    let discovered: Vec<String> = alive.iter().map(|n| n.address.clone()).collect();

    let resp = pb::DiscoverLocalResponse {
        discovered_nodes: discovered,
        discovery_method: "gossip".to_string(),
        event_counter: 0,
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
