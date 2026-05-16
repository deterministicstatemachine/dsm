//! Node discovery endpoint — returns alive peer addresses for SDK auto-discovery.
//!
//! Protobuf-only, clockless, index-only. Responds with `DiscoverLocalResponse`
//! containing the current set of alive node addresses (plus their claimed
//! 32-byte `node_id`s) from the gossip protocol.
//!
//! Also exposes `GET /api/v2/node/identity`, which returns THIS node's
//! self-reported 32-byte `node_id`. Orchestrators use it to cross-verify
//! `(address, claimed_node_id)` pairs returned by discovery —
//! adversarial-stage-6 defense against an operator advertising multiple
//! `node_id`s under one address.

use std::sync::Arc;

use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Extension, Router};
use prost::Message;

use dsm::types::proto as pb;

use crate::replication::StorageNodeId;

/// Register the discovery + node-identity routes.
pub fn create_router(state: Arc<crate::AppState>) -> Router<()> {
    Router::new()
        .route("/api/v2/nodes/discover", get(discover_nodes))
        .route("/api/v2/node/identity", get(node_identity))
        .layer(Extension(state))
}

/// `GET /api/v2/nodes/discover` — returns alive node addresses as protobuf.
///
/// SDK `StorageNodeDiscovery::discover_from_endpoint()` expects a
/// `DiscoverLocalResponse`. Both `discovered_nodes` (address-only) and
/// `discovered_node_infos` (address + 32-byte node_id) are populated;
/// the latter is the canonical form for new callers.
async fn discover_nodes(
    Extension(state): Extension<Arc<crate::AppState>>,
) -> Result<impl IntoResponse, StatusCode> {
    let alive = state.replication_manager.get_alive_nodes();
    let discovered: Vec<String> = alive.iter().map(|n| n.address.clone()).collect();
    let infos: Vec<pb::DiscoveredNodeV1> = alive
        .iter()
        .map(|n| {
            let id = StorageNodeId::from_base32_or_derive(&n.node_id, n.address.as_bytes());
            pb::DiscoveredNodeV1 {
                address: n.address.clone(),
                node_id: id.as_bytes().to_vec(),
            }
        })
        .collect();

    let resp = pb::DiscoverLocalResponse {
        discovered_nodes: discovered,
        discovery_method: "gossip".to_string(),
        event_counter: 0,
        discovered_node_infos: infos,
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

/// `GET /api/v2/node/identity` — this node's self-reported 32-byte
/// `node_id`. Orchestrators picking participants by ID cross-verify
/// the discovered (address, node_id) pair by GET-ing this endpoint
/// at the address and confirming the returned id matches.
async fn node_identity(
    Extension(state): Extension<Arc<crate::AppState>>,
) -> Result<impl IntoResponse, StatusCode> {
    let resp = pb::NodeIdentityV1 {
        node_id: state.node_id.as_bytes().to_vec(),
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
    use dsm::types::proto as pb;
    use prost::Message;

    #[test]
    fn discover_local_response_roundtrip() {
        let resp = pb::DiscoverLocalResponse {
            discovered_nodes: vec!["http://10.0.0.1:3000".into(), "http://10.0.0.2:3000".into()],
            discovery_method: "gossip".to_string(),
            event_counter: 0,
            discovered_node_infos: vec![],
        };
        let mut buf = Vec::new();
        assert!(resp.encode(&mut buf).is_ok());
        let decoded = match pb::DiscoverLocalResponse::decode(buf.as_slice()) {
            Ok(decoded) => decoded,
            Err(err) => panic!("discover response should decode: {err}"),
        };
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
            discovered_node_infos: vec![],
        };
        let mut buf = Vec::new();
        assert!(resp.encode(&mut buf).is_ok());
        let decoded = match pb::DiscoverLocalResponse::decode(buf.as_slice()) {
            Ok(decoded) => decoded,
            Err(err) => panic!("empty discover response should decode: {err}"),
        };
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
            discovered_node_infos: vec![],
        };
        let mut buf = Vec::new();
        assert!(resp.encode(&mut buf).is_ok());
        let decoded = match pb::DiscoverLocalResponse::decode(buf.as_slice()) {
            Ok(decoded) => decoded,
            Err(err) => panic!("ordered discover response should decode: {err}"),
        };
        assert_eq!(decoded.discovered_nodes, nodes);
        assert_eq!(decoded.event_counter, 7);
    }
}
