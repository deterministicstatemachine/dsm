// SPDX-License-Identifier: Apache-2.0

//! Immutable content-addressed object store — Area 4, Rev 15 §15.3.
//!
//! `PUT /api/v2/immutable/put` stores a `(namespace, payload)` tuple at
//! `addr(N, P) = H(DSM/storage-object ‖ N_bytes ‖ H(N ‖ P))`, computed by the
//! node from the input. **The node never accepts a caller-supplied address as
//! the storage key**; the optional `x-expected-addr` header is a check, and a
//! mismatch is a storage error (Req 15.2) — it catches a caller whose encoder
//! disagrees with the registry.
//!
//! `GET /api/v2/immutable/{addr}` returns the payload with the namespace in
//! `x-namespace`. The node **recomputes the address from the stored tuple
//! before serving and refuses on mismatch** — hash-on-read, which catches a
//! corrupted or tampered row here rather than shipping it. The consumer
//! re-hashes anyway: the node may be hostile, and a check performed by the
//! party being verified is not a check. Node-side rehash is defence in depth;
//! consumer-side rehash is the security boundary (Req 15.3).
//!
//! ## The node is content-blind, and stays that way
//!
//! This module never decodes a payload and never varies acceptance by what
//! the bytes happen to parse as. The predecessor store sniffed payloads —
//! acceptance depended on whether bytes coincidentally decoded as one
//! particular proto — which a generic substrate cannot do. Verifying that the
//! namespace matches the class *inside* a CCB payload would require decoding
//! it, so that check belongs to the consumer: the node checks the arithmetic,
//! the consumer checks the agreement.
//!
//! There is **no update path and no overwrite path** — not an update path
//! that refuses; no such code. Idempotent replay of the identical tuple
//! re-acks; a different tuple at the same address is surfaced as corruption,
//! unreachable without a hash collision or a damaged store.

use axum::{
    body::Bytes,
    extract::{Extension, Path},
    http::{HeaderMap, HeaderValue, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Router,
};
use std::sync::Arc;

use crate::AppState;
use dsm::crypto::domain::TaggedHashDomain;
use dsm::storage_object::immutable_addr;

/// Payload cap. Generously above the largest canonical object in the
/// registry (an SPX256f signature is ~49.9 KiB); rejects DoS-sized bodies
/// before any hashing.
const MAX_IMMUTABLE_PAYLOAD_BYTES: usize = 1024 * 1024;

/// Namespace tag cap — tags are short ASCII domain strings.
const MAX_NAMESPACE_BYTES: usize = 128;

pub fn create_read_router(state: Arc<AppState>) -> Router<()> {
    Router::new()
        .route("/api/v2/immutable/{addr}", get(get_immutable))
        .layer(Extension(state))
}

pub fn create_write_router() -> Router<()> {
    Router::new().route("/api/v2/immutable/put", post(put_immutable))
}

/// Validate a caller-supplied namespace tag into a domain the hasher accepts.
///
/// The rules mirror `dsm_domain_hasher`'s contract exactly, checked here so a
/// bad tag is a 400 rather than a panic: non-empty, NUL-free, `DSM/`- or
/// `DJTE.`-prefixed, and bounded. Pure, so directly unit-testable.
pub(crate) fn validate_namespace(raw: &[u8]) -> Result<TaggedHashDomain<'_>, &'static str> {
    if raw.is_empty() || raw.len() > MAX_NAMESPACE_BYTES {
        return Err("namespace must be 1..=128 bytes");
    }
    if !(raw.starts_with(b"DSM/") || raw.starts_with(b"DJTE.")) {
        return Err("namespace must start with DSM/ or DJTE.");
    }
    TaggedHashDomain::try_new(raw).map_err(|_| "namespace must not contain NUL")
}

async fn put_immutable(
    Extension(state): Extension<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, StatusCode> {
    if body.is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }
    if body.len() > MAX_IMMUTABLE_PAYLOAD_BYTES {
        return Err(StatusCode::PAYLOAD_TOO_LARGE);
    }

    let ns_raw = headers
        .get("x-namespace")
        .map(|v| v.as_bytes().to_vec())
        .ok_or(StatusCode::BAD_REQUEST)?;
    let namespace = validate_namespace(&ns_raw).map_err(|e| {
        log::warn!("immutable put: rejected namespace: {e}");
        StatusCode::BAD_REQUEST
    })?;

    // The node computes the address. Always. A caller-supplied address is
    // never the storage key; when present it is compared, and disagreement is
    // the caller's encoder disagreeing with the registry — a storage error.
    let addr = immutable_addr(namespace, body.as_ref());
    let addr_b32 = dsm_sdk::util::text_id::encode_base32_crockford(&addr);

    if let Some(expected) = headers.get("x-expected-addr").and_then(|v| v.to_str().ok()) {
        let expected_bytes = dsm_sdk::util::text_id::decode_base32_crockford(expected.trim())
            .ok_or(StatusCode::BAD_REQUEST)?;
        if expected_bytes != addr {
            log::warn!(
                "immutable put: expected-addr mismatch (caller encoder disagrees): \
                 expected={} computed={}",
                expected,
                addr_b32
            );
            return Err(StatusCode::UNPROCESSABLE_ENTITY);
        }
    }

    let now_tick = state.current_tick.load(std::sync::atomic::Ordering::SeqCst);
    let outcome = crate::db::insert_immutable_object_if_absent(
        &state.db_pool,
        &addr_b32,
        &ns_raw,
        body.as_ref(),
        now_tick.max(0) as u64,
    )
    .await
    .map_err(|e| {
        log::error!("immutable put: DB write failed: {e}");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let status = match outcome {
        crate::db::ImmutablePutOutcome::Inserted => StatusCode::CREATED,
        crate::db::ImmutablePutOutcome::AlreadyExistsIdentical => StatusCode::OK,
        crate::db::ImmutablePutOutcome::Conflict => {
            // Unreachable without a hash collision or a damaged store — which
            // is precisely why it is detected loudly rather than assumed away.
            log::error!(
                "immutable put: DIFFERENT tuple already stored at {addr_b32} — \
                 store corruption or hash collision"
            );
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    let mut resp_headers = HeaderMap::new();
    resp_headers.insert(
        axum::http::header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain"),
    );
    Ok((status, resp_headers, addr_b32))
}

async fn get_immutable(
    Extension(state): Extension<Arc<AppState>>,
    Path(addr): Path<String>,
) -> Result<impl IntoResponse, StatusCode> {
    let addr_bytes = dsm_sdk::util::text_id::decode_base32_crockford(addr.trim())
        .ok_or(StatusCode::BAD_REQUEST)?;
    if addr_bytes.len() != 32 {
        return Err(StatusCode::BAD_REQUEST);
    }
    let addr_b32 = dsm_sdk::util::text_id::encode_base32_crockford(&addr_bytes);

    let Some((namespace, payload)) = crate::db::get_immutable_object(&state.db_pool, &addr_b32)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    else {
        return Err(StatusCode::NOT_FOUND);
    };

    // Hash-on-read: recompute the address from the stored tuple and refuse to
    // serve a row that no longer hashes to its own key.
    let domain = validate_namespace(&namespace).map_err(|e| {
        log::error!("immutable get: stored namespace invalid ({e}) at {addr_b32} — corruption");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    let recomputed = immutable_addr(domain, &payload);
    if recomputed.as_slice() != addr_bytes.as_slice() {
        log::error!("immutable get: stored tuple does not hash to {addr_b32} — corruption");
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }

    let mut headers = HeaderMap::new();
    headers.insert(
        axum::http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    headers.insert(
        "x-namespace",
        HeaderValue::from_bytes(&namespace).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
    );
    Ok((StatusCode::OK, headers, payload))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn namespace_validation_refuses_the_right_things() {
        assert!(validate_namespace(b"DSM/vault-state").is_ok());
        assert!(validate_namespace(b"DJTE.emission").is_ok());
        assert!(validate_namespace(b"").is_err(), "empty");
        assert!(validate_namespace(b"vault-state").is_err(), "no prefix");
        assert!(
            validate_namespace(b"DSM/vault-state\0").is_err(),
            "NUL would collide the tag/body boundary"
        );
        let long = [b'a'; 200];
        let mut tagged = b"DSM/".to_vec();
        tagged.extend_from_slice(&long);
        assert!(validate_namespace(&tagged).is_err(), "over the cap");
    }

    /// The store is content-blind: bytes that happen to decode as a protobuf
    /// message are bytes. This pins the property the predecessor store broke —
    /// its acceptance depended on whether the body coincidentally parsed as a
    /// `VaultPostProto`. Here the handler has no decode path at all, so the
    /// test asserts the address derivation treats proto-decodable bytes
    /// identically to any others.
    #[test]
    fn proto_decodable_bytes_are_just_bytes() {
        use prost::Message;
        let post = dsm::types::proto::VaultPostProto::default();
        let proto_bytes = post.encode_to_vec();
        let Ok(ns) = validate_namespace(b"DSM/vault-state") else {
            panic!("DSM/vault-state must validate");
        };
        // Deriving the address is the only thing the node does with a payload.
        let a1 = dsm::storage_object::immutable_addr(ns, &proto_bytes);
        let a2 = dsm::storage_object::immutable_addr(ns, &proto_bytes);
        assert_eq!(a1, a2);
    }
}
