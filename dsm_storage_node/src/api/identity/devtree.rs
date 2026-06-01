// SPDX-License-Identifier: Apache-2.0
//! Identity mirrors: Device Tree root and inclusion proofs (protobuf-only, raw bytes).
//!
//! `PUT /api/v2/identity/{genesis}/devtree/root` is a *bounded* validator
//! for the Device Tree state. The Phase B.4 (issue #275) policy is:
//!
//! 1. Body is non-empty and within [`MAX_DEVTREE_STATE_BYTES`].
//! 2. Body parses as a [`dsm::types::proto::DeviceTreeStateV1`] proto
//!    with an inner `tree` summary present.
//! 3. The summary's `root_hash` is exactly 32 bytes and non-zero.
//! 4. The summary's `device_count >= 1` and equals `device_ids.len()`,
//!    and every `device_ids` element is exactly 32 bytes.
//! 5. `version_number > prior_version_number` (enforced atomically
//!    inside the DB via `upsert_device_tree_state_if_monotonic`).
//!
//! The validator is bounded: it does **not** verify Merkle structure,
//! signatures, or DevID derivation — those are client-side concerns
//! (Phase 3 enrollment hardening). All it guarantees is that the
//! published anchor is well-formed and monotonic so downstream
//! consumers (GET /devtree/root, GET /devtree/proof in Phase B.5) read
//! a consistent state per genesis.

use axum::{
    body::Bytes,
    extract::{Extension, Path, RawQuery},
    http::{HeaderValue, StatusCode},
    response::IntoResponse,
    routing::get,
    Router,
};
use prost::Message;
use std::sync::Arc;

use crate::api::infra::hardening::blake3_tagged;
use crate::AppState;
use dsm::types::proto as generated;

/// Upper bound for the persisted DeviceTreeStateV1 payload. Each leaf is
/// 32 bytes; with proto overhead, 1024 devices fit comfortably within
/// 64 KiB. We cap at 128 KiB to leave headroom and reject obvious DoS
/// payloads at the boundary before decode.
const MAX_DEVTREE_STATE_BYTES: usize = 128 * 1024;

fn key_root(genesis_b: &[u8]) -> String {
    let k = blake3_tagged("DSM/identity/devtree/root", genesis_b);
    dsm_sdk::util::text_id::encode_base32_crockford(&k)
}

pub fn create_router(state: Arc<AppState>) -> Router<()> {
    Router::new()
        .route(
            "/api/v2/identity/{genesis}/devtree/root",
            get(get_root).put(put_root),
        )
        // PUT /devtree/proof was removed in Phase B.5 (issue #276).
        // The endpoint still routes so out-of-date callers receive a
        // 405 with the post-migration explanation rather than a 404
        // that silently dead-letters.
        .route(
            "/api/v2/identity/{genesis}/devtree/proof",
            get(get_proof).put(put_proof_removed),
        )
        .layer(Extension(state))
}

async fn get_root(
    Extension(state): Extension<Arc<AppState>>,
    Path(genesis): Path<String>,
) -> Result<impl IntoResponse, StatusCode> {
    // GET reads from the bounded-validator table first; falls back to
    // the legacy /devtree/root KV slot only if no validated state has
    // been published yet, so pre-Phase-B.4 callers still see whatever
    // bytes they wrote. New writes only land in `device_tree_states`.
    let genesis_b =
        dsm_sdk::util::text_id::decode_base32_crockford(&genesis).ok_or(StatusCode::BAD_REQUEST)?;
    let genesis_key = dsm_sdk::util::text_id::encode_base32_crockford(&genesis_b);
    let payload = crate::db::get_device_tree_state_payload(&state.db_pool, &genesis_key)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let bytes = match payload {
        Some(b) => b,
        None => crate::db::get_object_by_key(&state.db_pool, &key_root(&genesis_b))
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
            .ok_or(StatusCode::NOT_FOUND)?,
    };

    let mut headers = axum::http::HeaderMap::new();
    headers.insert(
        axum::http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    Ok((StatusCode::OK, headers, bytes))
}

/// Structured rejection reasons for `validate_devtree_state` so the
/// route handler can map each cause to a stable HTTP status + reason
/// log. Keeping the enum out of the route function lets the unit tests
/// drive every branch without going through axum.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DevTreeValidationError {
    /// Body failed prost decoding (CHECK 1).
    Malformed(String),
    /// Inner `DeviceTreeV1` summary field is missing (CHECK 1).
    MissingTree,
    /// `root_hash` length != 32 bytes (CHECK 2).
    RootHashLength { actual: usize },
    /// `root_hash` is all zeros (CHECK 2).
    RootHashAllZeros,
    /// `device_count < 1` (CHECK 3 lower bound).
    DeviceCountZero,
    /// `device_count != device_ids.len()` (CHECK 3 consistency).
    DeviceCountMismatch { declared: u32, actual: usize },
    /// Some `device_ids` entry is not exactly 32 bytes (CHECK 3).
    DeviceIdLength { index: usize, actual: usize },
}

impl DevTreeValidationError {
    pub(crate) fn http_status(&self) -> StatusCode {
        // All validation failures are client-input errors -> 400.
        StatusCode::BAD_REQUEST
    }

    pub(crate) fn reason(&self) -> String {
        match self {
            DevTreeValidationError::Malformed(e) => format!("malformed DeviceTreeStateV1: {e}"),
            DevTreeValidationError::MissingTree => "missing DeviceTreeStateV1.tree".into(),
            DevTreeValidationError::RootHashLength { actual } => {
                format!("root_hash must be 32 bytes, got {actual}")
            }
            DevTreeValidationError::RootHashAllZeros => "root_hash must not be all zeros".into(),
            DevTreeValidationError::DeviceCountZero => "device_count must be >= 1".into(),
            DevTreeValidationError::DeviceCountMismatch { declared, actual } => {
                format!("device_count {declared} does not match device_ids.len() {actual}")
            }
            DevTreeValidationError::DeviceIdLength { index, actual } => {
                format!("device_ids[{index}] must be 32 bytes, got {actual}")
            }
        }
    }
}

/// Successful validation extract — what the route handler hands to the
/// atomic-monotonic upsert layer.
#[derive(Debug, Clone)]
pub(crate) struct ValidatedDevTreeState {
    pub version_number: u64,
    pub device_count: u32,
    pub root_hash: [u8; 32],
}

/// Run CHECKs 1–4 on a candidate DeviceTreeStateV1 body. Returns the
/// extracted summary on success; structured error on rejection.
/// Pure: no I/O, so directly unit-testable for every branch.
pub(crate) fn validate_devtree_state(
    body: &[u8],
) -> Result<ValidatedDevTreeState, DevTreeValidationError> {
    // CHECK 1: decode
    let state = generated::DeviceTreeStateV1::decode(body)
        .map_err(|e| DevTreeValidationError::Malformed(e.to_string()))?;
    let tree = state.tree.ok_or(DevTreeValidationError::MissingTree)?;

    // CHECK 2: root_hash is exactly 32 bytes and non-zero
    if tree.root_hash.len() != 32 {
        return Err(DevTreeValidationError::RootHashLength {
            actual: tree.root_hash.len(),
        });
    }
    if tree.root_hash.iter().all(|&b| b == 0) {
        return Err(DevTreeValidationError::RootHashAllZeros);
    }
    let mut root_hash = [0u8; 32];
    root_hash.copy_from_slice(&tree.root_hash);

    // CHECK 3: device_count >= 1, matches device_ids.len(), all 32 bytes
    if tree.device_count == 0 {
        return Err(DevTreeValidationError::DeviceCountZero);
    }
    if (tree.device_count as usize) != state.device_ids.len() {
        return Err(DevTreeValidationError::DeviceCountMismatch {
            declared: tree.device_count,
            actual: state.device_ids.len(),
        });
    }
    for (i, id) in state.device_ids.iter().enumerate() {
        if id.len() != 32 {
            return Err(DevTreeValidationError::DeviceIdLength {
                index: i,
                actual: id.len(),
            });
        }
    }

    // CHECK 4 (version_number monotonicity) is enforced atomically by
    // `upsert_device_tree_state_if_monotonic` in the DB layer; we cannot
    // do it here without a TOCTOU race against concurrent writers.

    Ok(ValidatedDevTreeState {
        version_number: tree.version_number,
        device_count: tree.device_count,
        root_hash,
    })
}

async fn put_root(
    Extension(state): Extension<Arc<AppState>>,
    Path(genesis): Path<String>,
    body: Bytes,
) -> Result<impl IntoResponse, StatusCode> {
    // Size guard before decode so the validator never has to allocate
    // against an attacker-controlled blob.
    if body.is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }
    if body.len() > MAX_DEVTREE_STATE_BYTES {
        return Err(StatusCode::PAYLOAD_TOO_LARGE);
    }

    let genesis_b =
        dsm_sdk::util::text_id::decode_base32_crockford(&genesis).ok_or(StatusCode::BAD_REQUEST)?;
    if genesis_b.len() != 32 {
        return Err(StatusCode::BAD_REQUEST);
    }

    // CHECKs 1–3 (structure + shape).
    let validated = match validate_devtree_state(body.as_ref()) {
        Ok(v) => v,
        Err(e) => {
            log::warn!(
                "PUT /devtree/root for genesis={}: rejected: {}",
                genesis,
                e.reason()
            );
            return Err(e.http_status());
        }
    };

    // Use the canonical 32-byte-Base32 form for the table key so future
    // GETs that decode the same genesis path land on the same row.
    let genesis_key = dsm_sdk::util::text_id::encode_base32_crockford(&genesis_b);

    // CHECK 4 (monotonic version) is enforced atomically here.
    let now_tick = state.current_tick.load(std::sync::atomic::Ordering::SeqCst);
    let outcome = crate::db::upsert_device_tree_state_if_monotonic(
        &state.db_pool,
        &genesis_key,
        validated.version_number,
        validated.device_count,
        &validated.root_hash,
        body.as_ref(),
        now_tick.max(0) as u64,
    )
    .await
    .map_err(|e| {
        log::error!(
            "PUT /devtree/root for genesis={}: DB write failed: {}",
            genesis,
            e
        );
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    match outcome {
        crate::db::DeviceTreeUpsertOutcome::Inserted => {
            log::info!(
                "PUT /devtree/root for genesis={}: inserted version_number={}",
                genesis,
                validated.version_number
            );
            Ok(StatusCode::CREATED)
        }
        crate::db::DeviceTreeUpsertOutcome::Updated { prior_version } => {
            log::info!(
                "PUT /devtree/root for genesis={}: updated version_number={} (was {})",
                genesis,
                validated.version_number,
                prior_version
            );
            Ok(StatusCode::OK)
        }
        crate::db::DeviceTreeUpsertOutcome::RejectedStale { prior_version } => {
            log::warn!(
                "PUT /devtree/root for genesis={}: rejected stale version_number={} (current={})",
                genesis,
                validated.version_number,
                prior_version
            );
            // 409 Conflict matches the semantics: the resource exists at
            // a higher version, so the client's request is incompatible
            // with the current state.
            Err(StatusCode::CONFLICT)
        }
    }
}

/// Derive a `DeviceInclusionProofV1` for the requested DevID against
/// the genesis's currently-published Device Tree (Phase B.5, issue
/// #276).
///
/// Trust model: the storage node never accepts caller-supplied proof
/// bytes. The proof is rebuilt deterministically on every GET from
/// the persisted `DeviceTreeStateV1.device_ids`, so two GETs against
/// the same persisted state yield byte-identical proof bytes and the
/// returned `root_hash` always matches `DeviceTreeStateV1.tree.root_hash`.
///
/// HTTP semantics:
/// - 200 OK + `DeviceInclusionProofV1` proto bytes if the device is a
///   member of the current tree.
/// - 400 Bad Request if `genesis` or `devid` is missing / malformed.
/// - 404 Not Found if no tree has been published for this genesis
///   *or* the device is not currently a member.
/// - 500 Internal if the persisted state cannot be decoded (data
///   corruption).
async fn get_proof(
    Extension(state): Extension<Arc<AppState>>,
    Path(genesis): Path<String>,
    RawQuery(raw): RawQuery,
) -> Result<impl IntoResponse, StatusCode> {
    let genesis_b =
        dsm_sdk::util::text_id::decode_base32_crockford(&genesis).ok_or(StatusCode::BAD_REQUEST)?;
    if genesis_b.len() != 32 {
        return Err(StatusCode::BAD_REQUEST);
    }
    let devid_b = parse_devid(raw.as_deref())?;
    if devid_b.len() != 32 {
        return Err(StatusCode::BAD_REQUEST);
    }
    let mut devid_arr = [0u8; 32];
    devid_arr.copy_from_slice(&devid_b);

    let genesis_key = dsm_sdk::util::text_id::encode_base32_crockford(&genesis_b);
    let payload = crate::db::get_device_tree_state_payload(&state.db_pool, &genesis_key)
        .await
        .map_err(|e| {
            log::error!(
                "GET /devtree/proof for genesis={}: DB read failed: {}",
                genesis,
                e
            );
            StatusCode::INTERNAL_SERVER_ERROR
        })?
        .ok_or(StatusCode::NOT_FOUND)?;

    let proof_bytes = derive_inclusion_proof(&payload, &devid_arr).map_err(|e| {
        log::warn!(
            "GET /devtree/proof for genesis={} devid={}: {}",
            genesis,
            dsm_sdk::util::text_id::encode_base32_crockford(&devid_arr),
            e.reason()
        );
        e.http_status()
    })?;

    let mut headers = axum::http::HeaderMap::new();
    headers.insert(
        axum::http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    Ok((StatusCode::OK, headers, proof_bytes))
}

/// `PUT /devtree/proof` is removed (Phase B.5, issue #276).
///
/// Inclusion proofs are now derived on GET from the storage node's
/// persisted `DeviceTreeStateV1`. Accepting caller-supplied proofs
/// would let an arbitrary client install bytes that subsequent
/// readers would consume as authoritative; derive-on-GET is the only
/// path where the served proof is provably consistent with the
/// validated published anchor.
///
/// Returns `405 Method Not Allowed` for every call so out-of-date
/// callers fail loudly instead of silently storing bytes that will
/// never be read (the prior endpoint stored proofs under a key the
/// new GET never reads).
async fn put_proof_removed() -> impl IntoResponse {
    (
        StatusCode::METHOD_NOT_ALLOWED,
        [(axum::http::header::ALLOW, HeaderValue::from_static("GET"))],
        "PUT /devtree/proof was removed in Phase B.5 (issue #276); \
         inclusion proofs are derived on GET from the persisted \
         DeviceTreeStateV1. See docs/plans/2026-04-24-genesis-mpc-and-device-tree.md.",
    )
}

/// Structured rejection reasons for `derive_inclusion_proof`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DevTreeProofError {
    /// Persisted DeviceTreeStateV1 failed prost decoding (data
    /// corruption — the validator rejected malformed inputs at PUT).
    CorruptState(String),
    /// Persisted state's `tree` summary is missing (data corruption).
    CorruptStateMissingTree,
    /// Any persisted `device_ids` element is not 32 bytes (corruption).
    CorruptStateDeviceIdLength { index: usize, actual: usize },
    /// The requested DevID is not currently a member of the published
    /// Device Tree.
    DevIdNotInTree,
    /// `DeviceTree::proof` declined to produce a proof. With
    /// `DeviceTree::new` having already canonicalised the leaf list
    /// this can only happen if the leaf list is empty; we still
    /// surface it distinctly from `DevIdNotInTree` so corruption can
    /// be distinguished from absence.
    ProofUnavailable,
}

impl DevTreeProofError {
    pub(crate) fn http_status(&self) -> StatusCode {
        match self {
            DevTreeProofError::CorruptState(_)
            | DevTreeProofError::CorruptStateMissingTree
            | DevTreeProofError::CorruptStateDeviceIdLength { .. }
            | DevTreeProofError::ProofUnavailable => StatusCode::INTERNAL_SERVER_ERROR,
            DevTreeProofError::DevIdNotInTree => StatusCode::NOT_FOUND,
        }
    }

    pub(crate) fn reason(&self) -> String {
        match self {
            DevTreeProofError::CorruptState(e) => format!("corrupt persisted state: {e}"),
            DevTreeProofError::CorruptStateMissingTree => {
                "corrupt persisted state: tree summary missing".into()
            }
            DevTreeProofError::CorruptStateDeviceIdLength { index, actual } => format!(
                "corrupt persisted state: device_ids[{index}] is {actual} bytes, expected 32"
            ),
            DevTreeProofError::DevIdNotInTree => "device_id is not in the current tree".into(),
            DevTreeProofError::ProofUnavailable => {
                "DeviceTree could not produce a proof for this device".into()
            }
        }
    }
}

/// Decode a persisted [`generated::DeviceTreeStateV1`], rebuild the
/// `DeviceTree` deterministically from the canonical leaf list, and
/// emit a [`generated::DeviceInclusionProofV1`] for `target_devid`.
///
/// Pure: no I/O. The proof's `siblings`, `path_bits`, and `root_hash`
/// are completely determined by the persisted leaf list, so this is
/// directly unit-testable against the leaf vectors `DeviceTree`
/// already covers.
pub(crate) fn derive_inclusion_proof(
    persisted_payload: &[u8],
    target_devid: &[u8; 32],
) -> Result<Vec<u8>, DevTreeProofError> {
    let state = generated::DeviceTreeStateV1::decode(persisted_payload)
        .map_err(|e| DevTreeProofError::CorruptState(e.to_string()))?;
    let _summary = state
        .tree
        .as_ref()
        .ok_or(DevTreeProofError::CorruptStateMissingTree)?;

    let mut devids: Vec<[u8; 32]> = Vec::with_capacity(state.device_ids.len());
    for (i, id) in state.device_ids.iter().enumerate() {
        if id.len() != 32 {
            return Err(DevTreeProofError::CorruptStateDeviceIdLength {
                index: i,
                actual: id.len(),
            });
        }
        let mut buf = [0u8; 32];
        buf.copy_from_slice(id);
        devids.push(buf);
    }

    let tree = dsm::common::device_tree::DeviceTree::new(devids);

    // Fast-fail with a NotFound (404) before invoking DeviceTree::proof
    // so callers can distinguish "device not in tree" from
    // "DeviceTree internal error" by HTTP status alone.
    if tree.proof(target_devid).is_none() {
        return Err(DevTreeProofError::DevIdNotInTree);
    }
    let dev_proof = tree
        .proof(target_devid)
        .ok_or(DevTreeProofError::ProofUnavailable)?;

    // Use the canonical Phase B.1 encoder so storage-node-served and
    // SDK-derived proof bytes stay byte-identical for the same input
    // (see also `dsm_sdk::sdk::storage_node_sdk` Phase B.7 path).
    Ok(dev_proof.to_v1_proto_bytes(target_devid, &tree.root()))
}

fn parse_devid(raw: Option<&str>) -> Result<Vec<u8>, StatusCode> {
    let raw = raw.ok_or(StatusCode::BAD_REQUEST)?;
    for pair in raw.split('&') {
        let mut it = pair.splitn(2, '=');
        let key = it.next().unwrap_or("");
        let val = it.next().unwrap_or("");
        if key == "devid" {
            let val = decode_percent(val)?;
            return dsm_sdk::util::text_id::decode_base32_crockford(&val)
                .ok_or(StatusCode::BAD_REQUEST);
        }
    }
    Err(StatusCode::BAD_REQUEST)
}

fn decode_percent(input: &str) -> Result<String, StatusCode> {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                if i + 2 >= bytes.len() {
                    return Err(StatusCode::BAD_REQUEST);
                }
                let hi = from_hex(bytes[i + 1])?;
                let lo = from_hex(bytes[i + 2])?;
                out.push((hi << 4) | lo);
                i += 3;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8(out).map_err(|_| StatusCode::BAD_REQUEST)
}

fn from_hex(b: u8) -> Result<u8, StatusCode> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(StatusCode::BAD_REQUEST),
    }
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)]
mod tests {
    use super::*;

    #[test]
    fn key_root_is_deterministic() {
        let genesis = [0xABu8; 32];
        let k1 = key_root(&genesis);
        let k2 = key_root(&genesis);
        assert_eq!(k1, k2, "same genesis must produce same root key");
    }

    #[test]
    fn key_root_differs_for_different_genesis() {
        let g1 = [0x01u8; 32];
        let g2 = [0x02u8; 32];
        assert_ne!(key_root(&g1), key_root(&g2));
    }

    // key_proof was removed alongside the PUT /devtree/proof endpoint
    // (Phase B.5, issue #276). Inclusion proofs are now derived on GET
    // from the persisted DeviceTreeStateV1, so the storage node no
    // longer needs an opaque proof-keyed KV slot.

    #[test]
    fn parse_devid_extracts_value() {
        let b32 = dsm_sdk::util::text_id::encode_base32_crockford(&[0x42u8; 32]);
        let raw = format!("devid={b32}");
        assert_eq!(parse_devid(Some(&raw)), Ok(vec![0x42u8; 32]));
    }

    #[test]
    fn parse_devid_missing_param_is_error() {
        assert!(parse_devid(None).is_err());
        assert!(parse_devid(Some("other=abc")).is_err());
    }

    #[test]
    fn parse_devid_with_multiple_params() {
        let b32 = dsm_sdk::util::text_id::encode_base32_crockford(&[0x33u8; 32]);
        let raw = format!("foo=bar&devid={b32}&baz=qux");
        assert_eq!(parse_devid(Some(&raw)), Ok(vec![0x33u8; 32]));
    }

    #[test]
    fn decode_percent_passthrough() {
        assert_eq!(decode_percent("hello"), Ok("hello".to_string()));
    }

    #[test]
    fn decode_percent_hex_sequences() {
        assert_eq!(decode_percent("a%20b"), Ok("a b".to_string()));
        assert_eq!(decode_percent("%41%42%43"), Ok("ABC".to_string()));
    }

    #[test]
    fn decode_percent_plus_becomes_space() {
        assert_eq!(decode_percent("a+b"), Ok("a b".to_string()));
    }

    #[test]
    fn decode_percent_truncated_hex_is_error() {
        assert!(decode_percent("%2").is_err());
        assert!(decode_percent("%").is_err());
    }

    #[test]
    fn from_hex_digits() {
        assert_eq!(from_hex(b'0'), Ok(0));
        assert_eq!(from_hex(b'9'), Ok(9));
        assert_eq!(from_hex(b'a'), Ok(10));
        assert_eq!(from_hex(b'f'), Ok(15));
        assert_eq!(from_hex(b'A'), Ok(10));
        assert_eq!(from_hex(b'F'), Ok(15));
    }

    #[test]
    fn from_hex_invalid() {
        assert!(from_hex(b'g').is_err());
        assert!(from_hex(b'G').is_err());
        assert!(from_hex(b' ').is_err());
    }

    #[test]
    fn size_constants_are_reasonable() {
        assert_eq!(MAX_DEVTREE_STATE_BYTES, 128 * 1024);
    }

    // -----------------------------------------------------------------
    // Phase B.4 (issue #275) — `validate_devtree_state` covers CHECK 1–3.
    // CHECK 4 (monotonic version_number) is enforced atomically inside
    // the DB layer and is exercised by the
    // `upsert_device_tree_state_if_monotonic` integration test in
    // `dsm_storage_node::db::sqlite` below.
    // -----------------------------------------------------------------

    fn build_state(
        device_ids: Vec<[u8; 32]>,
        version: u64,
        override_root: Option<[u8; 32]>,
    ) -> generated::DeviceTreeStateV1 {
        let tree = dsm::common::device_tree::DeviceTree::new(device_ids.clone());
        let root_hash = override_root.unwrap_or_else(|| tree.root());
        generated::DeviceTreeStateV1 {
            tree: Some(generated::DeviceTreeV1 {
                schema_version: 1,
                root_hash: root_hash.to_vec(),
                device_count: tree.len() as u32,
                version_number: version,
            }),
            device_ids: tree.leaves().iter().map(|id| id.to_vec()).collect(),
        }
    }

    #[test]
    fn validator_accepts_well_formed_state() {
        let state = build_state(vec![[0x11u8; 32], [0x22u8; 32]], 7, None);
        let bytes = state.encode_to_vec();

        let v = validate_devtree_state(&bytes).expect("well-formed state must validate");
        assert_eq!(v.version_number, 7);
        assert_eq!(v.device_count, 2);
        let expected_root =
            dsm::common::device_tree::DeviceTree::new(vec![[0x11u8; 32], [0x22u8; 32]]).root();
        assert_eq!(v.root_hash, expected_root);
    }

    #[test]
    fn validator_rejects_malformed_proto() {
        let bytes = b"not a valid DeviceTreeStateV1".to_vec();
        let err = validate_devtree_state(&bytes).expect_err("malformed must reject");
        assert!(matches!(err, DevTreeValidationError::Malformed(_)));
        assert_eq!(err.http_status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn validator_rejects_missing_tree_summary() {
        let state = generated::DeviceTreeStateV1 {
            tree: None,
            device_ids: vec![],
        };
        let bytes = state.encode_to_vec();
        let err = validate_devtree_state(&bytes).expect_err("missing tree must reject");
        assert_eq!(err, DevTreeValidationError::MissingTree);
    }

    #[test]
    fn validator_rejects_root_hash_wrong_length() {
        let mut state = build_state(vec![[0x11u8; 32]], 1, None);
        // Truncate root_hash to 16 bytes.
        if let Some(t) = state.tree.as_mut() {
            t.root_hash = vec![0x42u8; 16];
        }
        let bytes = state.encode_to_vec();
        let err = validate_devtree_state(&bytes).expect_err("wrong-length root must reject");
        assert!(
            matches!(err, DevTreeValidationError::RootHashLength { actual: 16 }),
            "got {err:?}"
        );
    }

    #[test]
    fn validator_rejects_all_zero_root_hash() {
        let state = build_state(vec![[0x11u8; 32]], 1, Some([0u8; 32]));
        let bytes = state.encode_to_vec();
        let err = validate_devtree_state(&bytes).expect_err("zero root must reject");
        assert_eq!(err, DevTreeValidationError::RootHashAllZeros);
    }

    #[test]
    fn validator_rejects_zero_device_count() {
        // Construct an empty tree summary by hand (DeviceTree::new
        // would have already rejected an empty leaf list).
        let state = generated::DeviceTreeStateV1 {
            tree: Some(generated::DeviceTreeV1 {
                schema_version: 1,
                root_hash: vec![0x99u8; 32], // non-zero so we reach CHECK 3
                device_count: 0,
                version_number: 1,
            }),
            device_ids: vec![],
        };
        let bytes = state.encode_to_vec();
        let err = validate_devtree_state(&bytes).expect_err("zero device_count must reject");
        assert_eq!(err, DevTreeValidationError::DeviceCountZero);
    }

    #[test]
    fn validator_rejects_device_count_mismatch() {
        // declared = 3, actual = 2.
        let state = generated::DeviceTreeStateV1 {
            tree: Some(generated::DeviceTreeV1 {
                schema_version: 1,
                root_hash: vec![0x99u8; 32],
                device_count: 3,
                version_number: 1,
            }),
            device_ids: vec![vec![0x11u8; 32], vec![0x22u8; 32]],
        };
        let bytes = state.encode_to_vec();
        let err = validate_devtree_state(&bytes).expect_err("count mismatch must reject");
        assert!(
            matches!(
                err,
                DevTreeValidationError::DeviceCountMismatch {
                    declared: 3,
                    actual: 2,
                }
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn validator_rejects_device_id_wrong_length() {
        let state = generated::DeviceTreeStateV1 {
            tree: Some(generated::DeviceTreeV1 {
                schema_version: 1,
                root_hash: vec![0x99u8; 32],
                device_count: 2,
                version_number: 1,
            }),
            device_ids: vec![vec![0x11u8; 32], vec![0x22u8; 31]], // second is 31 bytes
        };
        let bytes = state.encode_to_vec();
        let err = validate_devtree_state(&bytes).expect_err("wrong-length device_id must reject");
        assert!(
            matches!(
                err,
                DevTreeValidationError::DeviceIdLength {
                    index: 1,
                    actual: 31,
                }
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn validator_rejects_empty_body() {
        // An empty body decodes as an all-defaults DeviceTreeStateV1
        // with `tree: None`, which the next check rejects as MissingTree.
        let err = validate_devtree_state(&[]).expect_err("empty body must reject");
        assert_eq!(err, DevTreeValidationError::MissingTree);
    }

    #[test]
    fn http_status_is_always_bad_request_for_validation_failures() {
        for e in [
            DevTreeValidationError::Malformed("x".into()),
            DevTreeValidationError::MissingTree,
            DevTreeValidationError::RootHashLength { actual: 16 },
            DevTreeValidationError::RootHashAllZeros,
            DevTreeValidationError::DeviceCountZero,
            DevTreeValidationError::DeviceCountMismatch {
                declared: 3,
                actual: 2,
            },
            DevTreeValidationError::DeviceIdLength {
                index: 0,
                actual: 31,
            },
        ] {
            assert_eq!(e.http_status(), StatusCode::BAD_REQUEST);
        }
    }

    // -----------------------------------------------------------------
    // Phase B.5 (issue #276) — derive_inclusion_proof:
    // Inclusion proofs are reconstructed deterministically on GET from
    // the persisted `DeviceTreeStateV1`. The storage node never accepts
    // caller-supplied proof bytes; the only sanctioned path is this
    // pure derivation.
    // -----------------------------------------------------------------

    #[test]
    fn proof_derivation_returns_valid_proof_for_member() {
        let dev_a = [0x11u8; 32];
        let dev_b = [0x22u8; 32];
        let state = build_state(vec![dev_a, dev_b], 1, None);
        let payload = state.encode_to_vec();

        let proof_bytes = derive_inclusion_proof(&payload, &dev_a).expect("proof for member");

        let proof = generated::DeviceInclusionProofV1::decode(proof_bytes.as_slice())
            .expect("decode proof");
        assert_eq!(proof.device_id, dev_a.to_vec());

        // Reconstruct DevTreeProof from the encoded bits and verify
        // against the published root.
        let mut path_bits = Vec::with_capacity(proof.path_bits_len as usize);
        for i in 0..(proof.path_bits_len as usize) {
            let byte = proof.path_bits[i / 8];
            path_bits.push((byte & (1 << (i % 8))) != 0);
        }
        let siblings: Vec<[u8; 32]> = proof
            .siblings
            .iter()
            .map(|s| {
                let mut a = [0u8; 32];
                a.copy_from_slice(s);
                a
            })
            .collect();
        let dev_proof = dsm::common::device_tree::DevTreeProof {
            siblings,
            path_bits,
            leaf_to_root: true,
        };

        let mut expected_root = [0u8; 32];
        expected_root.copy_from_slice(&proof.root_hash);
        assert!(
            dev_proof.verify(&dev_a, &expected_root),
            "derived proof must verify against the published root"
        );
        // And the root in the proof must match the one in the persisted state.
        let canonical_root = dsm::common::device_tree::DeviceTree::new(vec![dev_a, dev_b]).root();
        assert_eq!(expected_root, canonical_root);
    }

    #[test]
    fn proof_derivation_is_byte_deterministic() {
        let dev_a = [0x11u8; 32];
        let dev_b = [0x22u8; 32];
        let dev_c = [0x33u8; 32];
        let state = build_state(vec![dev_a, dev_b, dev_c], 5, None);
        let payload = state.encode_to_vec();

        let p1 = derive_inclusion_proof(&payload, &dev_b).expect("proof 1");
        let p2 = derive_inclusion_proof(&payload, &dev_b).expect("proof 2");
        assert_eq!(p1, p2, "repeated GETs must return byte-identical proofs");
    }

    #[test]
    fn proof_derivation_returns_not_found_for_non_member() {
        let dev_a = [0x11u8; 32];
        let dev_b = [0x22u8; 32];
        let stranger = [0x99u8; 32];
        let state = build_state(vec![dev_a, dev_b], 1, None);
        let payload = state.encode_to_vec();

        let err = derive_inclusion_proof(&payload, &stranger).expect_err("stranger rejected");
        assert_eq!(err, DevTreeProofError::DevIdNotInTree);
        assert_eq!(err.http_status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn proof_derivation_returns_correct_sibling_count_for_balanced_tree() {
        // 4 leaves → 2 siblings (ceil(log2(4)) = 2)
        let devs: Vec<[u8; 32]> = (1u8..=4).map(|i| [i; 32]).collect();
        let state = build_state(devs.clone(), 1, None);
        let payload = state.encode_to_vec();

        for d in &devs {
            let proof_bytes = derive_inclusion_proof(&payload, d).expect("proof");
            let proof =
                generated::DeviceInclusionProofV1::decode(proof_bytes.as_slice()).expect("decode");
            assert_eq!(
                proof.siblings.len(),
                2,
                "4-leaf balanced tree must yield 2 siblings"
            );
            assert_eq!(proof.path_bits_len, 2);
        }
    }

    #[test]
    fn proof_derivation_single_leaf_yields_empty_proof() {
        let dev_a = [0x11u8; 32];
        let state = build_state(vec![dev_a], 1, None);
        let payload = state.encode_to_vec();

        let proof_bytes = derive_inclusion_proof(&payload, &dev_a).expect("proof");
        let proof =
            generated::DeviceInclusionProofV1::decode(proof_bytes.as_slice()).expect("decode");
        assert!(proof.siblings.is_empty());
        assert_eq!(proof.path_bits_len, 0);
        // single-leaf: root = hash_leaf(dev)
        let expected_root = dsm::common::device_tree::DeviceTree::single(dev_a).root();
        assert_eq!(proof.root_hash, expected_root.to_vec());
    }

    #[test]
    fn proof_derivation_rejects_corrupt_state_bytes() {
        let err =
            derive_inclusion_proof(b"garbage", &[0x11u8; 32]).expect_err("corrupt state rejected");
        assert!(matches!(err, DevTreeProofError::CorruptState(_)));
        assert_eq!(err.http_status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn proof_derivation_rejects_missing_tree_summary() {
        let state = generated::DeviceTreeStateV1 {
            tree: None,
            device_ids: vec![vec![0x11u8; 32]],
        };
        let payload = state.encode_to_vec();
        let err =
            derive_inclusion_proof(&payload, &[0x11u8; 32]).expect_err("missing tree rejected");
        assert_eq!(err, DevTreeProofError::CorruptStateMissingTree);
    }

    #[test]
    fn proof_derivation_rejects_non_32_byte_device_ids() {
        let state = generated::DeviceTreeStateV1 {
            tree: Some(generated::DeviceTreeV1 {
                schema_version: 1,
                root_hash: vec![0u8; 32],
                device_count: 1,
                version_number: 1,
            }),
            device_ids: vec![vec![0x11u8; 31]],
        };
        let payload = state.encode_to_vec();
        let err = derive_inclusion_proof(&payload, &[0x11u8; 32])
            .expect_err("bad device_id length rejected");
        assert!(matches!(
            err,
            DevTreeProofError::CorruptStateDeviceIdLength {
                index: 0,
                actual: 31,
            }
        ));
    }

    #[test]
    fn proof_derivation_matches_canonical_devtree_proof() {
        // Cross-check: storage-node derived proof bytes must match what
        // a client running DeviceTree::new(...).proof(...).to_bytes()
        // would produce on the same canonical leaf list.
        let dev_a = [0x11u8; 32];
        let dev_b = [0x22u8; 32];
        let dev_c = [0x33u8; 32];
        let state = build_state(vec![dev_a, dev_b, dev_c], 1, None);
        let payload = state.encode_to_vec();

        let proof_bytes = derive_inclusion_proof(&payload, &dev_b).expect("proof");
        let proof =
            generated::DeviceInclusionProofV1::decode(proof_bytes.as_slice()).expect("decode");

        let tree = dsm::common::device_tree::DeviceTree::new(vec![dev_a, dev_b, dev_c]);
        let dev_proof = tree.proof(&dev_b).expect("canonical proof");
        let expected_siblings: Vec<Vec<u8>> =
            dev_proof.siblings.iter().map(|s| s.to_vec()).collect();
        assert_eq!(proof.siblings, expected_siblings);
        assert_eq!(proof.path_bits_len as usize, dev_proof.path_bits.len());
        assert_eq!(proof.root_hash, tree.root().to_vec());
    }
}
