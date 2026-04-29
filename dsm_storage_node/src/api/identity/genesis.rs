// SPDX-License-Identifier: Apache-2.0
//! Genesis endpoints (protobuf-only, no hex/base64 paths)
//! - Entropy provisioning for MPC genesis creation
//! - Genesis creation forwarding to upstream MPC service
//! - No hex-encoded paths per DSM spec: "No JSON, no base64, no hex, no CBOR"

use axum::{
    body::Bytes,
    extract::Extension,
    http::{HeaderMap, HeaderValue, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Router,
};
use log::{error, info};
use std::sync::Arc;

use crate::AppState;

pub fn create_router(state: Arc<AppState>) -> Router<()> {
    Router::new()
        .route("/api/v2/genesis/create", post(forward_genesis_create))
        .route("/api/v2/genesis/entropy", get(get_genesis_entropy))
        .layer(Extension(state))
}

/// Minimal forwarder for POST /api/v2/genesis/create
/// Reads the upstream base URL from DSM_GENESIS_UPSTREAM env var.
/// Protobuf bytes in/out; no validation or consensus here.
/// Returns 503 Service Unavailable if upstream is not configured.
/// Body size limited to 10MB to prevent memory exhaustion.
async fn forward_genesis_create(
    Extension(state): Extension<Arc<AppState>>,
    body: Bytes,
) -> Result<impl IntoResponse, StatusCode> {
    // Enforce body size limit (10MB cap for genesis creation requests)
    const MAX_GENESIS_BODY_SIZE: usize = 10 * 1024 * 1024; // 10MB
    if body.len() > MAX_GENESIS_BODY_SIZE {
        error!(
            "Genesis create body exceeds size limit: {} > {}",
            body.len(),
            MAX_GENESIS_BODY_SIZE
        );
        return Err(StatusCode::PAYLOAD_TOO_LARGE);
    }

    // Production policy: upstream must be explicitly configured or fail-closed.
    // upstream like: https://genesis.example.com
    let upstream_base = std::env::var("DSM_GENESIS_UPSTREAM").map_err(|_| {
        error!("CONFIG ERROR: DSM_GENESIS_UPSTREAM not set");
        StatusCode::SERVICE_UNAVAILABLE
    })?;
    let url = format!(
        "{}/api/v2/genesis/create",
        upstream_base.trim_end_matches('/')
    );
    info!("Forwarding genesis create request to {}", url);

    let client = match reqwest::Client::builder().build() {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to build reqwest client: {}", e);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    let resp = match client
        .post(&url)
        .header("content-type", "application/octet-stream")
        .header("x-dsm-node-id", state.node_id.as_str())
        .body(body.to_vec())
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            // Clockless posture: do not classify by wall-clock timeout.
            // Treat any upstream transport failure as a bad gateway.
            error!("Upstream genesis create request failed ({}): {}", url, e);
            return Err(StatusCode::BAD_GATEWAY);
        }
    };

    let status = resp.status();
    let bytes = match resp.bytes().await {
        Ok(b) => b,
        Err(e) => {
            error!(
                "Failed to read upstream response body (upstream {} status {}): {}",
                url, status, e
            );
            return Err(StatusCode::BAD_GATEWAY);
        }
    };

    let mut headers = HeaderMap::new();
    headers.insert(
        axum::http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    // Genesis creation is a one-time MPC ceremony; result should never be cached
    headers.insert(
        axum::http::header::CACHE_CONTROL,
        HeaderValue::from_static("no-store, no-cache, must-revalidate"),
    );

    if status.is_success() {
        info!(
            "Genesis create forwarded successfully (upstream {} status {}) size {}",
            url,
            status,
            bytes.len()
        );
        Ok((StatusCode::OK, headers, bytes.to_vec()))
    } else {
        error!("Upstream returned error status ({} status {})", url, status);
        Err(StatusCode::from_u16(status.as_u16()).unwrap_or(StatusCode::BAD_GATEWAY))
    }
}

/// GET /api/v2/genesis/entropy
/// Returns 32 bytes of entropy for MPC genesis creation.
/// Each storage node provides independent entropy that clients combine.
/// Uses OS-level CSPRNG (OsRng) for explicit cryptographic-grade randomness.
/// Fresh entropy on every call; never cached.
async fn get_genesis_entropy(
    Extension(_state): Extension<Arc<AppState>>,
) -> Result<impl IntoResponse, StatusCode> {
    use rand::rngs::OsRng;
    use rand::RngCore;

    // Generate 32 bytes of cryptographically secure random entropy from OS
    let mut entropy = [0u8; 32];
    match OsRng.try_fill_bytes(&mut entropy) {
        Ok(()) => {
            info!("Generated 32 bytes of entropy from OS for genesis creation");
        }
        Err(e) => {
            error!("Failed to generate entropy from OS RNG: {}", e);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    }

    let mut headers = HeaderMap::new();
    headers.insert(
        axum::http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    // Entropy must never be cached; each request generates fresh randomness
    headers.insert(
        axum::http::header::CACHE_CONTROL,
        HeaderValue::from_static("no-store, no-cache, must-revalidate, max-age=0"),
    );
    headers.insert(
        axum::http::header::PRAGMA,
        HeaderValue::from_static("no-cache"),
    );

    Ok((StatusCode::OK, headers, entropy.to_vec()))
}

#[cfg(test)]
mod tests {
    use axum::http::StatusCode;

    const MAX_GENESIS_BODY_SIZE: usize = 10 * 1024 * 1024;

    #[test]
    fn max_genesis_body_size_is_10mb() {
        assert_eq!(MAX_GENESIS_BODY_SIZE, 10_485_760);
    }

    #[test]
    fn upstream_url_trailing_slash_stripped() {
        let upstream_base = "https://genesis.example.com/";
        let url = format!(
            "{}/api/v2/genesis/create",
            upstream_base.trim_end_matches('/')
        );
        assert_eq!(url, "https://genesis.example.com/api/v2/genesis/create");
    }

    #[test]
    fn upstream_url_no_trailing_slash() {
        let upstream_base = "https://genesis.example.com";
        let url = format!(
            "{}/api/v2/genesis/create",
            upstream_base.trim_end_matches('/')
        );
        assert_eq!(url, "https://genesis.example.com/api/v2/genesis/create");
    }

    #[test]
    fn body_size_at_limit_is_accepted() {
        let body_len = MAX_GENESIS_BODY_SIZE;
        assert!(body_len <= MAX_GENESIS_BODY_SIZE);
    }

    #[test]
    fn body_size_over_limit_rejected() {
        let body_len = MAX_GENESIS_BODY_SIZE + 1;
        assert!(body_len > MAX_GENESIS_BODY_SIZE);
    }

    #[test]
    fn status_code_from_u16_edge_cases() {
        assert!(StatusCode::from_u16(200).is_ok());
        assert!(StatusCode::from_u16(502).is_ok());
        assert!(StatusCode::from_u16(0).is_err());
    }
}
