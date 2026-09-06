// SPDX-License-Identifier: MIT OR Apache-2.0

//! Generic conditional-binding interface — SoFi Rev 15 §15.5, the node half
//! of `QuorumBind`.
//!
//! This node is APPLICATION-BLIND here, by construction and by rule (§22
//! #12). It holds opaque generic binding records under opaque resource keys
//! and offers exactly two operations: `CompareExchangeMany`, which replaces
//! a whole strictly-sorted key set atomically or not at all, and
//! `ReadBinding`, which reports what it holds. It inspects only the generic
//! storage fields the decision needs — schema, round ordering, the exact
//! expected digest of the prior record set, key-set equality — and never
//! decodes the value a record points at, never checks a claimant, never
//! checks a storage set, never knows a vault, a trade, or `q`. Class K owns
//! all of that (§15.6); a member that "helped" would be asserting authority
//! the specification withholds from it.
//!
//! Every answer names the member that gave it twice: the node id (the
//! identity echo layer) and the REGISTER INCARNATION this node is serving —
//! the same pair the read side already requires, now on write
//! acknowledgements too. A write ack counts toward a quorum only when both
//! match what the caller committed (Req 15.8); node identity alone cannot
//! distinguish a rebuilt register from the one a vault named.

use std::sync::Arc;

use axum::{
    body::Bytes,
    extract::Extension,
    http::{header, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
    Router,
};
use dsm::storage::binding_record::{
    decode_compare_exchange, decode_read_binding, record_set_digest, SetCell,
};
use dsm::types::proto as generated;
use dsm_sdk::util::text_id;
use prost::Message;

use crate::{db, AppState};

/// The register incarnation this node is serving, Base32-Crockford. Stamped
/// on EVERY answer both operations give.
pub const INCARNATION_HEADER: &str = "x-dsm-register-incarnation";

/// Write half: `CompareExchangeMany`. Mounted behind device auth by the
/// binary — a write must come from a registered device — but the node does
/// NOT relate the caller to the record: there is no claimant to check.
pub fn create_write_router() -> Router<()> {
    Router::new().route("/api/v2/storage/binding/cas", post(post_compare_exchange))
}

/// Read half: `ReadBinding`. Public.
pub fn create_read_router(state: Arc<AppState>) -> Router<()> {
    Router::new()
        .route("/api/v2/storage/binding/read", post(post_read_binding))
        .layer(Extension(state))
}

fn proto_response(status: StatusCode, bytes: Vec<u8>, incarnation: &[u8; 32]) -> Response {
    let mut resp = (status, bytes).into_response();
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    if let Ok(v) = HeaderValue::from_str(&text_id::encode_base32_crockford(incarnation)) {
        resp.headers_mut().insert(INCARNATION_HEADER, v);
    }
    resp
}

/// A node with no established register incarnation cannot testify: it has
/// no register history to speak for. This is unreachable after startup —
/// the binary establishes the incarnation before serving — and refused
/// rather than defaulted so a test harness that forgot it fails loudly.
fn established_incarnation(state: &AppState) -> Option<[u8; 32]> {
    state.own_register_incarnation
}

async fn post_compare_exchange(
    Extension(state): Extension<Arc<AppState>>,
    body: Bytes,
) -> Response {
    use generated::compare_exchange_many_response_v1::Outcome;
    let Some(incarnation) = established_incarnation(&state) else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let member_id = state.configured_member_id.as_bytes().to_vec();
    let answer = |status: StatusCode, outcome: Outcome, digest: [u8; 32]| {
        let msg = generated::CompareExchangeManyResponseV1 {
            outcome: outcome as i32,
            resulting_digest: digest.to_vec(),
            member_id: member_id.clone(),
            register_incarnation: incarnation.to_vec(),
        };
        proto_response(status, msg.encode_to_vec(), &incarnation)
    };

    // Storage-domain checks first: canonical bytes, a valid strictly-sorted
    // key set, and a replacement whose keyset_digest names these keys. None
    // of this reads the value payload.
    let cx = match decode_compare_exchange(&body) {
        Ok(cx) => cx,
        Err(e) => {
            log::warn!("binding cas: invalid storage encoding: {e}");
            return answer(StatusCode::OK, Outcome::InvalidStorageEncoding, [0u8; 32]);
        }
    };
    let replacement_digest = cx.replacement.digest();
    match db::compare_exchange_many(
        &state.db_pool,
        &cx.keys,
        &cx.expected_digest,
        &cx.replacement_bytes,
        &replacement_digest,
        cx.replacement.round,
    )
    .await
    {
        Ok(db::CasOutcome::Applied { resulting_digest }) => {
            answer(StatusCode::OK, Outcome::Applied, resulting_digest)
        }
        Ok(db::CasOutcome::ExpectationMismatch { current_digest }) => {
            answer(StatusCode::OK, Outcome::ExpectationMismatch, current_digest)
        }
        Err(e) => {
            log::warn!("binding cas: {e}");
            answer(
                StatusCode::SERVICE_UNAVAILABLE,
                Outcome::Unavailable,
                [0u8; 32],
            )
        }
    }
}

async fn post_read_binding(Extension(state): Extension<Arc<AppState>>, body: Bytes) -> Response {
    let Some(incarnation) = established_incarnation(&state) else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let keys = match decode_read_binding(&body) {
        Ok(k) => k,
        Err(e) => {
            log::warn!("binding read: invalid storage encoding: {e}");
            return proto_response(StatusCode::BAD_REQUEST, Vec::new(), &incarnation);
        }
    };
    let held = match db::read_bindings(&state.db_pool, &keys).await {
        Ok(h) => h,
        Err(e) => {
            log::warn!("binding read: {e}");
            return proto_response(StatusCode::SERVICE_UNAVAILABLE, Vec::new(), &incarnation);
        }
    };
    let cells: Vec<SetCell> = keys
        .iter()
        .zip(held.iter())
        .map(|(k, h)| SetCell {
            key: *k,
            record_digest: h.as_ref().map(|b| b.record_digest),
        })
        .collect();
    let set_digest = record_set_digest(&cells);
    let msg = generated::ReadBindingResponseV1 {
        cells: keys
            .iter()
            .zip(held)
            .map(|(k, h)| generated::BindingCellV1 {
                key: k.to_vec(),
                record: h.and_then(|b| {
                    generated::GenericBindingRecordV1::decode(b.record_bytes.as_slice()).ok()
                }),
            })
            .collect(),
        set_digest: set_digest.to_vec(),
        member_id: state.configured_member_id.as_bytes().to_vec(),
        register_incarnation: incarnation.to_vec(),
    };
    proto_response(StatusCode::OK, msg.encode_to_vec(), &incarnation)
}

#[cfg(test)]
mod tests {
    //! Endpoint semantics ON WHICHEVER BACKEND IS COMPILED: the four
    //! storage-domain outcomes, both halves of the identity stamp on every
    //! answer, asserted absence on reads, and the refusal to testify without
    //! an established incarnation. The record's MEANING is never inspected
    //! here because the node never inspects it.
    #![allow(clippy::disallowed_methods)] // unwrap/expect acceptable in deterministic tests
    use super::*;
    use crate::db::write_once_properties::{test_pool, unique_key};
    use crate::replication::{ReplicationConfig, ReplicationManager};
    use dsm::storage::binding_record::{
        empty_set_digest, keyset_digest, BindingRecord, Round, BINDING_RECORD_SCHEMA_V1,
    };
    use generated::compare_exchange_many_response_v1::Outcome;

    const INC: [u8; 32] = [0x1C; 32];

    async fn node(with_incarnation: bool) -> Arc<AppState> {
        let pool = Arc::new(test_pool());
        db::init_db(&pool).await.expect("init");
        let rm = Arc::new(
            ReplicationManager::new_for_tests(
                ReplicationConfig {
                    replication_factor: 3,
                    gossip_interval_ticks: 100,
                    failure_timeout_ticks: 300,
                    gossip_fanout: 3,
                    max_concurrent_jobs: 10,
                },
                "n1".to_string(),
                "http://localhost:8080".to_string(),
            )
            .expect("replication manager for tests"),
        );
        let state = AppState::new("n1".into(), "127.0.0.1:1", None, pool, rm);
        Arc::new(if with_incarnation {
            state.with_register_incarnation(INC)
        } else {
            state
        })
    }

    fn record(keys: &[[u8; 32]], counter: u64, proposer: u8, value: u8) -> BindingRecord {
        BindingRecord {
            schema: BINDING_RECORD_SCHEMA_V1,
            round: Round {
                counter,
                proposer_id: [proposer; 32],
            },
            tx_id: [0xAA; 32],
            keyset_digest: keyset_digest(keys),
            value_digest: [value; 32],
            value_addr: [value; 32],
            status: 1,
        }
    }

    fn cas_body(keys: &[[u8; 32]], expected: [u8; 32], r: &BindingRecord) -> Bytes {
        let req = generated::CompareExchangeManyRequestV1 {
            keys: keys.iter().map(|k| k.to_vec()).collect(),
            expected_digest: expected.to_vec(),
            replacement: Some(generated::GenericBindingRecordV1::decode(&r.encode()[..]).unwrap()),
        };
        Bytes::from(req.encode_to_vec())
    }

    async fn cas(
        state: &Arc<AppState>,
        body: Bytes,
    ) -> (
        StatusCode,
        generated::CompareExchangeManyResponseV1,
        Option<String>,
    ) {
        let resp = post_compare_exchange(Extension(state.clone()), body).await;
        let status = resp.status();
        let inc = resp
            .headers()
            .get(INCARNATION_HEADER)
            .map(|v| v.to_str().unwrap().to_string());
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let msg = generated::CompareExchangeManyResponseV1::decode(&bytes[..]).unwrap();
        (status, msg, inc)
    }

    async fn read(
        state: &Arc<AppState>,
        keys: &[[u8; 32]],
    ) -> (StatusCode, Option<generated::ReadBindingResponseV1>) {
        let req = generated::ReadBindingRequestV1 {
            keys: keys.iter().map(|k| k.to_vec()).collect(),
        };
        let resp =
            post_read_binding(Extension(state.clone()), Bytes::from(req.encode_to_vec())).await;
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        (
            status,
            generated::ReadBindingResponseV1::decode(&bytes[..]).ok(),
        )
    }

    #[tokio::test]
    async fn cas_applies_from_empty_re_acks_identical_and_refuses_stale_or_lower_round() {
        let state = node(true).await;
        let keys = [unique_key(0x51), unique_key(0x52)];
        let keys = {
            let mut k = keys;
            k.sort();
            k
        };
        let a = record(&keys, 1, 1, 0xA1);

        // First writer, from the digest of nothing: APPLIED, and the answer
        // names this member and its incarnation in BOTH the body and header.
        let (st, msg, hdr) = cas(&state, cas_body(&keys, empty_set_digest(&keys), &a)).await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(msg.outcome, Outcome::Applied as i32);
        assert_eq!(msg.member_id, b"n1".to_vec());
        assert_eq!(msg.register_incarnation, INC.to_vec());
        assert_eq!(
            hdr.as_deref(),
            Some(text_id::encode_base32_crockford(&INC).as_str())
        );
        let after_a: [u8; 32] = msg.resulting_digest.clone().try_into().unwrap();

        // Identical replay re-acks even with a stale expectation.
        let (_, msg, _) = cas(&state, cas_body(&keys, empty_set_digest(&keys), &a)).await;
        assert_eq!(
            msg.outcome,
            Outcome::Applied as i32,
            "byte-identical replay re-acks"
        );
        assert_eq!(msg.resulting_digest, after_a.to_vec());

        // A different value with the stale (empty) expectation is refused and
        // told the digest it must read against.
        let b = record(&keys, 2, 2, 0xB2);
        let (_, msg, _) = cas(&state, cas_body(&keys, empty_set_digest(&keys), &b)).await;
        assert_eq!(msg.outcome, Outcome::ExpectationMismatch as i32);
        assert_eq!(
            msg.resulting_digest,
            after_a.to_vec(),
            "the current digest is reported"
        );

        // Right expectation, but a round that does not supersede: refused.
        let low = record(&keys, 0, 9, 0xB2);
        let (_, msg, _) = cas(&state, cas_body(&keys, after_a, &low)).await;
        assert_eq!(msg.outcome, Outcome::ExpectationMismatch as i32);

        // Right expectation AND a higher round: B supersedes A on every key.
        let (_, msg, _) = cas(&state, cas_body(&keys, after_a, &b)).await;
        assert_eq!(msg.outcome, Outcome::Applied as i32);
        let (_, r) = read(&state, &keys).await;
        let r = r.unwrap();
        assert_eq!(r.cells.len(), 2);
        for c in &r.cells {
            let rec = c.record.as_ref().expect("held on every key");
            assert_eq!(rec.value_digest, [0xB2; 32].to_vec());
            assert_eq!(rec.round_counter, 2);
        }
        assert_eq!(r.set_digest, msg.resulting_digest);
        assert_eq!(r.register_incarnation, INC.to_vec());
    }

    #[tokio::test]
    async fn storage_domain_refusals_are_invalid_storage_encoding_and_write_nothing() {
        let state = node(true).await;
        let keys = {
            let mut k = [unique_key(0x53), unique_key(0x54)];
            k.sort();
            k
        };
        let a = record(&keys, 1, 1, 0xA1);

        // Non-canonical bytes.
        let mut padded = cas_body(&keys, empty_set_digest(&keys), &a).to_vec();
        padded.push(0);
        let (st, msg, _) = cas(&state, Bytes::from(padded)).await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(msg.outcome, Outcome::InvalidStorageEncoding as i32);

        // Unsorted keys.
        let mut rev = keys;
        rev.reverse();
        let (_, msg, _) = cas(&state, cas_body(&rev, empty_set_digest(&keys), &a)).await;
        assert_eq!(msg.outcome, Outcome::InvalidStorageEncoding as i32);

        // A record whose keyset_digest names OTHER keys.
        let other = [unique_key(0x55), unique_key(0x56)];
        let foreign = record(&other, 1, 1, 0xA1);
        let (_, msg, _) = cas(&state, cas_body(&keys, empty_set_digest(&keys), &foreign)).await;
        assert_eq!(msg.outcome, Outcome::InvalidStorageEncoding as i32);

        // None of the refusals wrote anything: absence is asserted per key.
        let (st, r) = read(&state, &keys).await;
        assert_eq!(st, StatusCode::OK);
        let r = r.unwrap();
        assert!(r.cells.iter().all(|c| c.record.is_none()), "nothing held");
        assert_eq!(r.set_digest, empty_set_digest(&keys).to_vec());
    }

    #[tokio::test]
    async fn a_node_without_an_established_incarnation_refuses_to_testify() {
        let state = node(false).await;
        let keys = [unique_key(0x57)];
        let a = record(&keys, 1, 1, 0xA1);
        let resp = post_compare_exchange(
            Extension(state.clone()),
            cas_body(&keys, empty_set_digest(&keys), &a),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        let (st, _) = read(&state, &keys).await;
        assert_eq!(st, StatusCode::SERVICE_UNAVAILABLE);
    }
}
