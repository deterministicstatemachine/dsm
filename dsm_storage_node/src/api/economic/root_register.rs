// SPDX-License-Identifier: Apache-2.0

//! The economic root register — the node side of the write-once cell one
//! identity's economic root occupies at one position (client protocol landed
//! in PR #727; this is its first server implementation).
//!
//! ## Registered is not validated
//!
//! Storing a claim here establishes NON-EQUIVOCATION and nothing else: this
//! identity named one root at this position and can never name a second. A
//! malicious trader registers an arbitrary root perfectly consistently, and
//! this node stores it. Whether the root is the result of a valid transition
//! is the VERIFIER's question, and no answer this node gives bears on it.
//!
//! ## K_root is recomputed, never accepted
//!
//! The cell key is derived from the DECODED claim body —
//! `H(tag ‖ G ‖ DevID ‖ u64_be(position))` — so a caller cannot aim a valid
//! envelope at an arbitrary cell. K_root is derivable by anyone (its inputs
//! are public), so the ATTRIBUTION checks are the whole anti-preemption
//! mechanism: claimant key AND trader devid must be the authenticated
//! caller's, per the #727 spec's stronger two-part check.

use axum::{
    body::Bytes,
    extract::{Extension, Path},
    http::{HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Router,
};
use std::sync::Arc;

use crate::auth::DeviceContext;
use crate::db;
use crate::AppState;
use dsm::economic::claim_envelope::{
    decode_and_verify_economic_root_claim, economic_root_claim_envelope_digest,
    verify_claim_attribution, ClaimEnvelopeError,
};
use dsm::economic::register::{economic_root_register_key, AttributionError, AuthenticatedCaller};
use dsm_sdk::util::text_id;

/// One SPHINCS+ signature + a CCB body with one key field.
const MAX_CLAIM_BYTES: usize = 160 * 1024;

pub const OUTCOME_HEADER: &str = "x-dsm-economic-root-outcome";
pub const HELD_DIGEST_HEADER: &str = "x-dsm-economic-root-held-digest";
pub const CLAIM_DIGEST_HEADER: &str = "x-dsm-economic-root-digest";

/// The device-authenticated write half. Mounted behind `auth::device_auth`.
pub fn create_write_router() -> Router<()> {
    Router::new().route("/api/v2/economic-root/claim", post(post_claim))
}

/// The public read half. The path key is the base32 K_root — a READER derives
/// it the same way the node does, from (G, DevID, position).
pub fn create_read_router(state: Arc<AppState>) -> Router<()> {
    Router::new()
        .route("/api/v2/economic-root/{k_root}", get(get_claim))
        .layer(Extension(state))
}

fn outcome(status: StatusCode, outcome: &'static str) -> Response {
    let mut resp = status.into_response();
    resp.headers_mut()
        .insert(OUTCOME_HEADER, HeaderValue::from_static(outcome));
    resp
}

/// Write-once root registration.
pub async fn post_claim(
    Extension(state): Extension<Arc<AppState>>,
    Extension(caller): Extension<DeviceContext>,
    body: Bytes,
) -> Response {
    if body.is_empty() || body.len() > MAX_CLAIM_BYTES {
        return outcome(StatusCode::BAD_REQUEST, "malformed");
    }
    let verified = match decode_and_verify_economic_root_claim(&body) {
        Ok(v) => v,
        Err(ClaimEnvelopeError::SignatureInvalid) => {
            return outcome(StatusCode::FORBIDDEN, "signature-invalid");
        }
        Err(_) => return outcome(StatusCode::BAD_REQUEST, "malformed"),
    };
    // ATTRIBUTION per the #727 spec — the protocol's own check, not a local
    // reimplementation. Two parts (key AND devid) because K_root is publicly
    // derivable and a one-part check would let an authenticated third party
    // burn a victim's next position.
    let caller_devid = text_id::decode_base32_crockford(&caller.device_id)
        .filter(|v| v.len() == 32)
        .and_then(|v| <[u8; 32]>::try_from(v.as_slice()).ok());
    let Some(caller_devid) = caller_devid else {
        return outcome(StatusCode::BAD_REQUEST, "caller-id-malformed");
    };
    let Some(set) = state.storage_set.as_ref() else {
        return outcome(StatusCode::SERVICE_UNAVAILABLE, "no-storage-set");
    };
    let auth_caller = AuthenticatedCaller {
        public_key: caller.public_key.clone(),
        device_id: caller_devid,
    };
    match verify_claim_attribution(&verified, &auth_caller, &set.id) {
        Ok(()) => {}
        Err(AttributionError::ClaimantIsNotCaller) => {
            return outcome(StatusCode::FORBIDDEN, "claimant-not-caller");
        }
        Err(AttributionError::DeviceIsNotCaller) => {
            return outcome(StatusCode::FORBIDDEN, "device-not-caller");
        }
        Err(AttributionError::WrongStorageSet { .. }) => {
            return outcome(StatusCode::UNPROCESSABLE_ENTITY, "foreign-set");
        }
        Err(AttributionError::SignatureInvalid) => {
            return outcome(StatusCode::FORBIDDEN, "signature-invalid");
        }
    }

    // The cell, from the body — never from the caller.
    let k_root = economic_root_register_key(
        &verified.body.trader_genesis,
        &verified.body.trader_devid,
        verified.body.economic_position,
    );
    let digest = economic_root_claim_envelope_digest(&body);
    match db::claim_economic_root(
        &state.db_pool,
        &k_root,
        &body,
        &digest,
        &verified.body.claimant_public_key,
        &verified.body.root_register_storage_set_id,
    )
    .await
    {
        Ok(db::OneShotOutcome::Accepted) => outcome(StatusCode::OK, "accepted"),
        Ok(db::OneShotOutcome::AlreadyHeldIdentical) => outcome(StatusCode::OK, "held-identical"),
        Ok(db::OneShotOutcome::Refused { held_digest }) => {
            let mut resp = outcome(StatusCode::CONFLICT, "refused");
            if let Ok(v) = HeaderValue::from_str(&text_id::encode_base32_crockford(&held_digest)) {
                resp.headers_mut().insert(HELD_DIGEST_HEADER, v);
            }
            resp
        }
        Err(e) => {
            log::warn!("economic-root claim: register write failed: {e}");
            outcome(StatusCode::INTERNAL_SERVER_ERROR, "error")
        }
    }
}

/// The claim this node holds for one cell: exact envelope bytes + digest.
pub async fn get_claim(
    Extension(state): Extension<Arc<AppState>>,
    Path(k_root_b32): Path<String>,
) -> Response {
    let Some(k_root) = text_id::decode_base32_crockford(&k_root_b32) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    if k_root.len() != 32 {
        return StatusCode::BAD_REQUEST.into_response();
    }
    match db::get_economic_root_claim(&state.db_pool, &k_root).await {
        Ok(Some((bytes, digest))) => {
            let mut resp = (StatusCode::OK, bytes).into_response();
            resp.headers_mut().insert(
                axum::http::header::CONTENT_TYPE,
                HeaderValue::from_static("application/octet-stream"),
            );
            if let Ok(v) = HeaderValue::from_str(&text_id::encode_base32_crockford(&digest)) {
                resp.headers_mut().insert(CLAIM_DIGEST_HEADER, v);
            }
            resp
        }
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(e) => {
            log::warn!("economic-root read failed: {e}");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

#[cfg(all(test, feature = "local-dev"))]
mod tests {
    //! K_root recomputation, three-way attribution, and write-once semantics.
    use super::*;
    use crate::db;
    use crate::replication::{ReplicationConfig, ReplicationManager};
    use dsm::ccb::genesis::sigalg;
    use dsm::economic::claim::EconomicRootClaimBody;
    use dsm::economic::claim_envelope::sign_economic_root_claim;

    fn test_state(pool: Arc<db::DBPool>, set: crate::NodeStorageSet) -> Arc<AppState> {
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
        Arc::new(AppState::new("n1".into(), "127.0.0.1:1", None, pool, rm).with_storage_set(set))
    }

    fn claim(pk: &[u8], devid: [u8; 32], set: [u8; 32], position: u64) -> EconomicRootClaimBody {
        EconomicRootClaimBody::new(
            [0xA1; 32],
            devid,
            position,
            [0xA2; 32],
            [0xA3; 32],
            set,
            sigalg::SPHINCS_PLUS_SPX256F,
            pk,
        )
        .expect("valid body")
    }

    fn caller_for(devid: [u8; 32], pk: &[u8]) -> DeviceContext {
        DeviceContext {
            device_id: text_id::encode_base32_crockford(&devid),
            public_key: pk.to_vec(),
        }
    }

    #[tokio::test]
    async fn endpoint_recomputes_the_cell_and_enforces_three_way_attribution() {
        let pool = Arc::new(db::create_pool(":memory:", true).expect("pool"));
        db::init_db(&pool).await.expect("init");
        let set =
            crate::NodeStorageSet::new(vec!["n1".into(), "n2".into(), "n3".into()], "n1").unwrap();
        let state = test_state(pool.clone(), set.clone());

        let (pk, sk) = dsm::crypto::sphincs::generate_sphincs_keypair().unwrap();
        let devid = [0xB1; 32];
        let caller = caller_for(devid, &pk);
        let body = claim(&pk, devid, set.id, 3);
        let env = sign_economic_root_claim(&body, &sk).unwrap();

        // Wrong device: the two-part check is what stops an authenticated
        // third party burning a victim's cell — K_root is derivable by anyone.
        let r = post_claim(
            Extension(state.clone()),
            Extension(caller_for([0xB2; 32], &pk)),
            Bytes::from(env.clone()),
        )
        .await;
        assert_eq!(r.status(), StatusCode::FORBIDDEN);
        assert_eq!(r.headers()[OUTCOME_HEADER], "device-not-caller");

        // Wrong key.
        let (pk2, _) = dsm::crypto::sphincs::generate_sphincs_keypair().unwrap();
        let r = post_claim(
            Extension(state.clone()),
            Extension(DeviceContext {
                device_id: text_id::encode_base32_crockford(&devid),
                public_key: pk2,
            }),
            Bytes::from(env.clone()),
        )
        .await;
        assert_eq!(r.headers()[OUTCOME_HEADER], "claimant-not-caller");

        // Accept; the cell is the DERIVED K_root, reachable by re-derivation.
        let r = post_claim(
            Extension(state.clone()),
            Extension(caller.clone()),
            Bytes::from(env.clone()),
        )
        .await;
        assert_eq!(r.headers()[OUTCOME_HEADER], "accepted");
        let k = economic_root_register_key(&[0xA1; 32], &devid, 3);
        let got = get_claim(
            Extension(state.clone()),
            Path(text_id::encode_base32_crockford(&k)),
        )
        .await;
        assert_eq!(got.status(), StatusCode::OK);

        // A DIFFERENT record for the same cell: refused with the held digest.
        // (Client-side this is the catastrophic quarantine case — the node's
        // job is only to never let it become two stored values.)
        let body_b = EconomicRootClaimBody::new(
            [0xA1; 32],
            devid,
            3,
            [0xEE; 32],
            [0xA3; 32],
            set.id,
            sigalg::SPHINCS_PLUS_SPX256F,
            &pk,
        )
        .unwrap();
        let env_b = sign_economic_root_claim(&body_b, &sk).unwrap();
        let r = post_claim(
            Extension(state.clone()),
            Extension(caller.clone()),
            Bytes::from(env_b),
        )
        .await;
        assert_eq!(r.status(), StatusCode::CONFLICT);
        assert_eq!(r.headers()[OUTCOME_HEADER], "refused");
        assert!(r.headers().contains_key(HELD_DIGEST_HEADER));

        // The NEXT position is an independent cell.
        let body4 = claim(&pk, devid, set.id, 4);
        let env4 = sign_economic_root_claim(&body4, &sk).unwrap();
        let r = post_claim(Extension(state), Extension(caller), Bytes::from(env4)).await;
        assert_eq!(r.headers()[OUTCOME_HEADER], "accepted");
    }
}
