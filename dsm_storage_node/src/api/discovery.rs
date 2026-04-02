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

#[cfg(test)]
mod tests {
    use dsm::types::proto as pb;
    use prost::Message;

    #[test]
    fn discover_local_response_roundtrip() {
        let resp = pb::DiscoverLocalResponse {
            discovered_nodes: vec!["http://10.0.0.1:3000".into(), "http://10.0.0.2:3000".into()],
            discovery_method: "gossip".to_string(),
            event_counter: 0,
        };
        let mut buf = Vec::new();
        resp.encode(&mut buf).unwrap();
        let decoded = pb::DiscoverLocalResponse::decode(buf.as_slice()).unwrap();
        assert_eq!(decoded.discovered_nodes.len(), 2);
        assert_eq!(decoded.discovery_method, "gossip");
        assert_eq!(decoded.event_counter, 0);
    }

    #[test]
    fn discover_local_response_empty() {
        let resp = pb::DiscoverLocalResponse {
            discovered_nodes: vec![],
            discovery_method: "gossip".to_string(),
            event_counter: 0,
        };
        let mut buf = Vec::new();
        resp.encode(&mut buf).unwrap();
        let decoded = pb::DiscoverLocalResponse::decode(buf.as_slice()).unwrap();
        assert!(decoded.discovered_nodes.is_empty());
    }

    #[test]
    fn discover_local_response_preserves_order() {
        let nodes = vec![
            "http://node-c:3000".to_string(),
            "http://node-a:3000".to_string(),
            "http://node-b:3000".to_string(),
        ];
        let resp = pb::DiscoverLocalResponse {
            discovered_nodes: nodes.clone(),
            discovery_method: "gossip".to_string(),
            event_counter: 7,
        };
        let mut buf = Vec::new();
        resp.encode(&mut buf).unwrap();
        let decoded = pb::DiscoverLocalResponse::decode(buf.as_slice()).unwrap();
        assert_eq!(decoded.discovered_nodes, nodes);
        assert_eq!(decoded.event_counter, 7);
    }
}
