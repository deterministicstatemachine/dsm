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
