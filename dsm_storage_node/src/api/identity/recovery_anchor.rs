// SPDX-License-Identifier: Apache-2.0
//! Recovery-authority anchor mirror — single-assignment, keyed by genesis (§0.5 bind-once).
//!
//! `PUT /api/v2/recovery/authority-anchor/{genesis}` stores a device's
//! `RecoveryAuthorityAnchorProto` under single-assignment semantics:
//!
//! 1. Body is non-empty and within [`MAX_ANCHOR_BYTES`].
//! 2. Body parses as a [`dsm::types::proto::RecoveryAuthorityAnchorProto`].
//! 3. `genesis_id` / `device_id` / `authority_pubkey_commit` are each exactly
//!    32 bytes; `genesis_id` equals the `{genesis}` path; both signatures are
//!    non-empty and within the SPHINCS+ bound.
//! 4. The FIRST valid anchor for a genesis wins and is immutable. An identical
//!    replay (same canonical anchor bytes) is idempotent (200); a DIFFERENT
//!    anchor for the same genesis is rejected with 409 Conflict.
//!
//! This is a **bounded, single-assignment store only**. Storage does NOT verify
//! the anchor's signatures or decide recovery validity — that is entirely
//! client-side (genesis/device-tree verification + `RecoveryAuthorityAnchor::verify`).
//! Storage guarantees only that a genesis cannot be re-bound to a different
//! recovery authority once a first anchor lands (so a later device-holding
//! attacker cannot overwrite a legitimately-enrolled authority).

use axum::{
    body::Bytes,
    extract::{Extension, Path},
    http::{HeaderValue, StatusCode},
    response::IntoResponse,
    routing::put,
    Router,
};
use prost::Message;
use std::sync::Arc;

use crate::api::infra::hardening::blake3_tagged;
use crate::AppState;
use dsm::types::proto as generated;

/// Two SPHINCS+ SPX256f signatures (~49.9 KiB each) plus three 32-byte fields
/// fit well under 256 KiB; cap there to reject DoS payloads before decode.
const MAX_ANCHOR_BYTES: usize = 256 * 1024;

/// Per-signature upper bound, matching the proto `dsm_max_len` contract (prost
/// does not enforce it, so the handler does).
const MAX_SIG_BYTES: usize = 65_535;

/// Domain tag for the stored-anchor content hash (idempotency key).
const ANCHOR_STORE_TAG: &str = "DSM/recovery/authority-anchor-store";

pub fn create_router(state: Arc<AppState>) -> Router<()> {
    Router::new()
        .route(
            "/api/v2/recovery/authority-anchor/{genesis}",
            put(put_anchor).get(get_anchor),
        )
        .layer(Extension(state))
}

/// Structured rejection reasons for [`validate_anchor`], kept out of the route
/// handler so unit tests can drive every branch without axum.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum AnchorValidationError {
    Empty,
    TooLarge,
    Malformed(String),
    FieldLen { field: &'static str, actual: usize },
    GenesisMismatch,
    EmptySig { which: &'static str },
    SigTooLarge { which: &'static str, actual: usize },
}

impl AnchorValidationError {
    pub(crate) fn http_status(&self) -> StatusCode {
        match self {
            AnchorValidationError::TooLarge | AnchorValidationError::SigTooLarge { .. } => {
                StatusCode::PAYLOAD_TOO_LARGE
            }
            _ => StatusCode::BAD_REQUEST,
        }
    }

    pub(crate) fn reason(&self) -> String {
        match self {
            AnchorValidationError::Empty => "empty body".into(),
            AnchorValidationError::TooLarge => "body exceeds MAX_ANCHOR_BYTES".into(),
            AnchorValidationError::Malformed(e) => {
                format!("malformed RecoveryAuthorityAnchorProto: {e}")
            }
            AnchorValidationError::FieldLen { field, actual } => {
                format!("field `{field}` is {actual} bytes, expected 32")
            }
            AnchorValidationError::GenesisMismatch => {
                "anchor genesis_id does not match the {genesis} path".into()
            }
            AnchorValidationError::EmptySig { which } => format!("empty {which} signature"),
            AnchorValidationError::SigTooLarge { which, actual } => {
                format!("{which} signature is {actual} bytes, exceeds bound")
            }
        }
    }
}

/// A structurally-valid anchor ready for single-assignment storage.
#[derive(Debug)]
pub(crate) struct ValidatedAnchor {
    /// Canonical re-encoded proto bytes (idempotency is on canonical content).
    pub(crate) canonical_bytes: Vec<u8>,
    /// Content hash of `canonical_bytes` — the single-assignment idempotency key.
    pub(crate) anchor_hash: [u8; 32],
}

/// Bounded structural validation (no signature verification — that is client-side).
/// `expected_genesis` is the 32-byte genesis decoded from the `{genesis}` path.
pub(crate) fn validate_anchor(
    body: &[u8],
    expected_genesis: &[u8],
) -> Result<ValidatedAnchor, AnchorValidationError> {
    if body.is_empty() {
        return Err(AnchorValidationError::Empty);
    }
    if body.len() > MAX_ANCHOR_BYTES {
        return Err(AnchorValidationError::TooLarge);
    }
    let anchor = generated::RecoveryAuthorityAnchorProto::decode(body)
        .map_err(|e| AnchorValidationError::Malformed(e.to_string()))?;

    for (field, bytes) in [
        ("genesis_id", &anchor.genesis_id),
        ("device_id", &anchor.device_id),
        ("authority_pubkey_commit", &anchor.authority_pubkey_commit),
    ] {
        if bytes.len() != 32 {
            return Err(AnchorValidationError::FieldLen {
                field,
                actual: bytes.len(),
            });
        }
    }
    if anchor.genesis_id != expected_genesis {
        return Err(AnchorValidationError::GenesisMismatch);
    }
    for (which, sig) in [
        ("device", &anchor.device_signature),
        ("authority", &anchor.authority_signature),
    ] {
        if sig.is_empty() {
            return Err(AnchorValidationError::EmptySig { which });
        }
        if sig.len() > MAX_SIG_BYTES {
            return Err(AnchorValidationError::SigTooLarge {
                which,
                actual: sig.len(),
            });
        }
    }

    // Canonicalize: re-encode the decoded proto so idempotency is on canonical
    // content, not on byte-for-byte input framing.
    let canonical_bytes = anchor.encode_to_vec();
    let anchor_hash = blake3_tagged(ANCHOR_STORE_TAG, &canonical_bytes);
    Ok(ValidatedAnchor {
        canonical_bytes,
        anchor_hash,
    })
}

async fn put_anchor(
    Extension(state): Extension<Arc<AppState>>,
    Path(genesis): Path<String>,
    body: Bytes,
) -> Result<impl IntoResponse, StatusCode> {
    let genesis_b =
        dsm_sdk::util::text_id::decode_base32_crockford(&genesis).ok_or(StatusCode::BAD_REQUEST)?;
    if genesis_b.len() != 32 {
        return Err(StatusCode::BAD_REQUEST);
    }

    let validated = match validate_anchor(body.as_ref(), &genesis_b) {
        Ok(v) => v,
        Err(e) => {
            log::warn!(
                "PUT /recovery/authority-anchor for genesis={}: rejected: {}",
                genesis,
                e.reason()
            );
            return Err(e.http_status());
        }
    };

    // Canonical Base32 form so future GETs that decode the same path land on the
    // same row.
    let genesis_key = dsm_sdk::util::text_id::encode_base32_crockford(&genesis_b);
    let now_tick = state.current_tick.load(std::sync::atomic::Ordering::SeqCst);
    let outcome = crate::db::insert_recovery_authority_anchor_if_absent(
        &state.db_pool,
        &genesis_key,
        &validated.anchor_hash,
        &validated.canonical_bytes,
        now_tick.max(0) as u64,
    )
    .await
    .map_err(|e| {
        log::error!(
            "PUT /recovery/authority-anchor for genesis={}: DB write failed: {}",
            genesis,
            e
        );
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    match outcome {
        crate::db::RecoveryAnchorUpsertOutcome::Inserted => {
            log::info!("PUT /recovery/authority-anchor for genesis={}: inserted", genesis);
            Ok(StatusCode::CREATED)
        }
        crate::db::RecoveryAnchorUpsertOutcome::AlreadyExistsIdentical => {
            log::info!(
                "PUT /recovery/authority-anchor for genesis={}: idempotent (identical anchor exists)",
                genesis
            );
            Ok(StatusCode::OK)
        }
        crate::db::RecoveryAnchorUpsertOutcome::Conflict => {
            log::warn!(
                "PUT /recovery/authority-anchor for genesis={}: rejected — a different anchor is already bound (bind-once)",
                genesis
            );
            Err(StatusCode::CONFLICT)
        }
    }
}

async fn get_anchor(
    Extension(state): Extension<Arc<AppState>>,
    Path(genesis): Path<String>,
) -> Result<impl IntoResponse, StatusCode> {
    let genesis_b =
        dsm_sdk::util::text_id::decode_base32_crockford(&genesis).ok_or(StatusCode::BAD_REQUEST)?;
    let genesis_key = dsm_sdk::util::text_id::encode_base32_crockford(&genesis_b);
    let payload = crate::db::get_recovery_authority_anchor_payload(&state.db_pool, &genesis_key)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;

    let mut headers = axum::http::HeaderMap::new();
    headers.insert(
        axum::http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    Ok((StatusCode::OK, headers, payload))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_anchor_bytes(genesis: &[u8; 32]) -> Vec<u8> {
        generated::RecoveryAuthorityAnchorProto {
            genesis_id: genesis.to_vec(),
            device_id: vec![0xD0; 32],
            authority_pubkey_commit: vec![0xAC; 32],
            device_signature: vec![0x01; 64],
            authority_signature: vec![0x02; 64],
        }
        .encode_to_vec()
    }

    #[test]
    fn valid_anchor_passes_and_hash_is_canonical() {
        let g = [0x6E; 32];
        let body = valid_anchor_bytes(&g);
        let v = validate_anchor(&body, &g).expect("valid");
        // Canonical re-encode round-trips and the hash is over the canonical bytes.
        assert_eq!(v.anchor_hash, blake3_tagged(ANCHOR_STORE_TAG, &v.canonical_bytes));
        // Re-validating the canonical bytes yields the same hash (idempotency key stable).
        let v2 = validate_anchor(&v.canonical_bytes, &g).expect("valid2");
        assert_eq!(v.anchor_hash, v2.anchor_hash);
    }

    #[test]
    fn empty_body_rejected() {
        let g = [0x6E; 32];
        assert_eq!(validate_anchor(&[], &g).unwrap_err(), AnchorValidationError::Empty);
    }

    #[test]
    fn malformed_proto_rejected() {
        let g = [0x6E; 32];
        let err = validate_anchor(b"not a protobuf at all \xff\xff", &g).unwrap_err();
        assert!(matches!(err, AnchorValidationError::Malformed(_)));
        assert_eq!(err.http_status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn wrong_length_genesis_field_rejected() {
        let g = [0x6E; 32];
        let body = generated::RecoveryAuthorityAnchorProto {
            genesis_id: vec![0x6E; 31], // not 32
            device_id: vec![0xD0; 32],
            authority_pubkey_commit: vec![0xAC; 32],
            device_signature: vec![0x01; 64],
            authority_signature: vec![0x02; 64],
        }
        .encode_to_vec();
        assert!(matches!(
            validate_anchor(&body, &g).unwrap_err(),
            AnchorValidationError::FieldLen { field: "genesis_id", .. }
        ));
    }

    #[test]
    fn genesis_path_mismatch_rejected() {
        let g = [0x6E; 32];
        let body = valid_anchor_bytes(&g);
        // Validate against a DIFFERENT expected genesis than the one in the proto.
        assert_eq!(
            validate_anchor(&body, &[0xAA; 32]).unwrap_err(),
            AnchorValidationError::GenesisMismatch
        );
    }

    #[test]
    fn empty_signature_rejected() {
        let g = [0x6E; 32];
        let body = generated::RecoveryAuthorityAnchorProto {
            genesis_id: g.to_vec(),
            device_id: vec![0xD0; 32],
            authority_pubkey_commit: vec![0xAC; 32],
            device_signature: vec![], // empty
            authority_signature: vec![0x02; 64],
        }
        .encode_to_vec();
        assert_eq!(
            validate_anchor(&body, &g).unwrap_err(),
            AnchorValidationError::EmptySig { which: "device" }
        );
    }
}
