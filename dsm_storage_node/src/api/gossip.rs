//! Gossip protocol API for node state synchronization
//!
//! This module provides HTTP endpoints for the gossip protocol used by
//! the production replication system.

use crate::AppState;
use axum::body::Bytes;
use axum::extract::Extension;
use axum::http::{HeaderMap, StatusCode};
use axum::middleware::Next;
use axum::response::IntoResponse;
use axum::Router;
use dsm::types::proto as pb;
use prost::Message;
use std::env;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use subtle::ConstantTimeEq;

const GOSSIP_TOKEN_HEADER: &str = "x-dsm-gossip-token";
const GOSSIP_TOKEN_ENV: &str = "DSM_GOSSIP_TOKEN";

fn token_matches(provided: &str, expected: &str) -> bool {
    provided.as_bytes().ct_eq(expected.as_bytes()).into()
}

async fn require_gossip_token(headers: HeaderMap) -> Result<(), StatusCode> {
    let expected = env::var(GOSSIP_TOKEN_ENV).unwrap_or_default();
    if expected.trim().is_empty() {
        if cfg!(debug_assertions) {
            log::warn!(
                "gossip auth disabled: {} not set (debug build)",
                GOSSIP_TOKEN_ENV
            );
            return Ok(());
        }
        log::error!(
            "gossip auth disabled in release: {} not set",
            GOSSIP_TOKEN_ENV
        );
        return Err(StatusCode::UNAUTHORIZED);
    }

    let provided = headers
        .get(GOSSIP_TOKEN_HEADER)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if token_matches(provided, &expected) {
        Ok(())
    } else {
        Err(StatusCode::UNAUTHORIZED)
    }
}

async fn gossip_auth(
    req: axum::http::Request<axum::body::Body>,
    next: Next,
) -> Result<axum::response::Response, StatusCode> {
    require_gossip_token(req.headers().clone()).await?;
    Ok(next.run(req).await)
}

/// Gossip endpoint for receiving node state updates
pub async fn gossip_receive(
    Extension(state): Extension<Arc<AppState>>,
    body: Bytes,
) -> impl IntoResponse {
    let gossip = match pb::GossipMessageV1::decode(body) {
        Ok(msg) => msg,
        Err(_) => return StatusCode::BAD_REQUEST,
    };

    let mut current_tick = state.current_tick.load(Ordering::SeqCst);
    if gossip.sender_tick > current_tick {
        state
            .current_tick
            .store(gossip.sender_tick, Ordering::SeqCst);
        current_tick = gossip.sender_tick;
    }

    // Process the gossip message
    state
        .replication_manager
        .process_gossip(gossip, current_tick)
        .await;

    // Return success
    StatusCode::OK
}

/// Get current node states (for debugging/monitoring)
pub async fn gossip_status(
    Extension(state): Extension<Arc<AppState>>,
) -> Result<impl IntoResponse, StatusCode> {
    let alive_nodes = state.replication_manager.get_alive_nodes();
    let status = pb::GossipStatusV1 {
        alive_nodes_count: alive_nodes.len() as u32,
        nodes: alive_nodes,
    };
    let mut buf = Vec::with_capacity(status.encoded_len());
    if status.encode(&mut buf).is_err() {
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }
    Ok((
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "application/octet-stream")],
        buf,
    ))
}

/// Register gossip routes
pub fn gossip_routes(state: Arc<AppState>) -> Router<()> {
    Router::new()
        .route("/gossip", axum::routing::post(gossip_receive))
        .route("/gossip/status", axum::routing::get(gossip_status))
        .layer(axum::middleware::from_fn(gossip_auth))
        .layer(Extension(state))
}

#[cfg(test)]
mod tests {
    use super::*;
    use prost::Message;

    #[test]
    fn token_matches_equal() {
        assert!(token_matches("my-gossip-secret", "my-gossip-secret"));
    }

    #[test]
    fn token_matches_not_equal() {
        assert!(!token_matches("my-gossip-secret", "wrong-token"));
    }

    #[test]
    fn token_matches_empty_strings() {
        assert!(token_matches("", ""));
        assert!(!token_matches("a", ""));
        assert!(!token_matches("", "b"));
    }

    #[test]
    fn token_matches_constant_time_property() {
        let t1 = token_matches("aaaa", "aaab");
        let t2 = token_matches("aaaa", "bbbb");
        assert!(!t1);
        assert!(!t2);
    }

    #[test]
    fn gossip_message_v1_roundtrip() {
        let msg = pb::GossipMessageV1 {
            sender_node_id: "node-1".to_string(),
            sender_tick: 42,
            node_states: vec![],
        };
        let mut buf = Vec::new();
        msg.encode(&mut buf).unwrap();
        let decoded = pb::GossipMessageV1::decode(buf.as_slice()).unwrap();
        assert_eq!(decoded.sender_node_id, "node-1");
        assert_eq!(decoded.sender_tick, 42);
    }

    #[test]
    fn gossip_status_v1_roundtrip() {
        let status = pb::GossipStatusV1 {
            alive_nodes_count: 3,
            nodes: vec![],
        };
        let mut buf = Vec::new();
        status.encode(&mut buf).unwrap();
        let decoded = pb::GossipStatusV1::decode(buf.as_slice()).unwrap();
        assert_eq!(decoded.alive_nodes_count, 3);
    }

    #[test]
    fn gossip_message_decode_invalid_bytes() {
        let bad = vec![0xFF, 0xFF, 0xFF];
        let result = pb::GossipMessageV1::decode(bad.as_slice());
        assert!(result.is_err());
    }
}
