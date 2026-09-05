// SPDX-License-Identifier: Apache-2.0

//! The ERA faucet-ticket register — one write-once cell per ticket of the
//! network's finite bootstrap allocation.
//!
//! There is deliberately NO faucet head here: no sequence, no remaining
//! counter, no parent commitment. Each of the 800M tickets is an independent
//! cell, so a contested or poisoned ticket costs exactly that ticket and the
//! faucet cannot be bricked at a shared coordinate.
//!
//! ## What this node judges, and what it never does
//!
//! COORDINATE VALIDITY and ATTRIBUTION only:
//!
//! - the claim decodes strictly and its signature verifies (the claimant's
//!   own envelope, exact bytes);
//! - the claimant's key AND device id are the authenticated caller's — the
//!   register is write-once, so without this a third party could consume
//!   tickets under someone else's identity;
//! - the set is this node's own; the faucet id is THE canonical
//!   `era_faucet_id(configured network)` and the ticket index exists
//!   (< 800M). Rejecting a coordinate that does not exist in the protocol is
//!   not judging economics — it denies an invented faucet universe any place
//!   to write.
//!
//! Balances, provenance, admission: never. Verifiers judge those.

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
use dsm::economic::faucet::{
    decode_and_verify_faucet_ticket_claim, faucet_claim_evidence_addr,
    verify_faucet_claim_attribution, FaucetAttributionError, FaucetClaimError,
};
use dsm::economic::register::{AuthenticatedCaller, MAX_CLAIM_BYTES};
use dsm_sdk::util::text_id;

pub const OUTCOME_HEADER: &str = "x-dsm-faucet-ticket-outcome";
pub const HELD_DIGEST_HEADER: &str = "x-dsm-faucet-ticket-held-digest";
pub const CLAIM_DIGEST_HEADER: &str = "x-dsm-faucet-ticket-digest";

/// The device-authenticated write half. Mounted behind `auth::device_auth`.
pub fn create_write_router() -> Router<()> {
    Router::new().route("/api/v2/faucet-ticket/claim", post(post_claim))
}

/// The public read half.
pub fn create_read_router(state: Arc<AppState>) -> Router<()> {
    Router::new()
        .route(
            "/api/v2/faucet-ticket/{faucet_id}/{ticket_index}",
            get(get_claim),
        )
        .layer(Extension(state))
}

fn outcome(status: StatusCode, outcome: &'static str) -> Response {
    let mut resp = status.into_response();
    resp.headers_mut()
        .insert(OUTCOME_HEADER, HeaderValue::from_static(outcome));
    resp
}

/// Write-once ticket consumption.
///
/// Check order: size → strict decode + signature → attribution (key AND
/// devid) → set → network configured → CANONICAL faucet id → range → the ONE
/// atomic write. Every refusal happens before the write; nothing is retried,
/// updated or deleted. The attribution and coordinate checks are the
/// protocol's own `verify_faucet_claim_attribution` — the same function the
/// in-process register double calls — not a local reimplementation.
pub async fn post_claim(
    Extension(state): Extension<Arc<AppState>>,
    Extension(caller): Extension<DeviceContext>,
    body: Bytes,
) -> Response {
    if body.is_empty() || body.len() > MAX_CLAIM_BYTES {
        return outcome(StatusCode::BAD_REQUEST, "malformed");
    }
    let verified = match decode_and_verify_faucet_ticket_claim(&body) {
        Ok(v) => v,
        Err(FaucetClaimError::SignatureInvalid) => {
            return outcome(StatusCode::FORBIDDEN, "signature-invalid");
        }
        Err(_) => return outcome(StatusCode::BAD_REQUEST, "malformed"),
    };
    let caller_devid = text_id::decode_base32_crockford(&caller.device_id)
        .filter(|v| v.len() == 32)
        .and_then(|v| <[u8; 32]>::try_from(v.as_slice()).ok());
    let Some(caller_devid) = caller_devid else {
        return outcome(StatusCode::BAD_REQUEST, "caller-id-malformed");
    };
    let auth_caller = AuthenticatedCaller {
        public_key: caller.public_key.clone(),
        device_id: caller_devid,
    };
    match verify_faucet_claim_attribution(
        &verified,
        &auth_caller,
        state.storage_set.as_ref().map(|s| &s.id),
        state.network_id.as_ref().map(|n| n.as_slice()),
    ) {
        Ok(()) => {}
        Err(FaucetAttributionError::ClaimantIsNotCaller) => {
            return outcome(StatusCode::FORBIDDEN, "claimant-not-caller");
        }
        Err(FaucetAttributionError::DeviceIsNotCaller) => {
            return outcome(StatusCode::FORBIDDEN, "device-not-caller");
        }
        Err(FaucetAttributionError::StorageSetUnconfigured) => {
            return outcome(StatusCode::SERVICE_UNAVAILABLE, "no-storage-set");
        }
        Err(FaucetAttributionError::WrongStorageSet { .. }) => {
            return outcome(StatusCode::UNPROCESSABLE_ENTITY, "foreign-set");
        }
        Err(FaucetAttributionError::NetworkUnconfigured) => {
            return outcome(StatusCode::SERVICE_UNAVAILABLE, "no-network");
        }
        Err(FaucetAttributionError::NoncanonicalFaucet) => {
            return outcome(StatusCode::UNPROCESSABLE_ENTITY, "noncanonical-faucet");
        }
        Err(FaucetAttributionError::TicketOutOfRange) => {
            return outcome(StatusCode::UNPROCESSABLE_ENTITY, "ticket-out-of-range");
        }
    }

    let digest = faucet_claim_evidence_addr(&body);
    match db::claim_faucet_ticket(
        &state.db_pool,
        &verified.body.faucet_id,
        verified.body.ticket_index,
        &body,
        &digest,
        &verified.body.claimant_public_key,
        &verified.body.storage_set_id,
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
            log::warn!("faucet-ticket claim: register write failed: {e}");
            outcome(StatusCode::INTERNAL_SERVER_ERROR, "error")
        }
    }
}

/// The winning claim this node holds for one ticket: exact envelope bytes +
/// digest. The `x-dsm-node-id` echo on this response is what makes it
/// countable toward a quorum read.
pub async fn get_claim(
    Extension(state): Extension<Arc<AppState>>,
    Path((faucet_b32, ticket_index)): Path<(String, u64)>,
) -> Response {
    let Some(faucet_id) = text_id::decode_base32_crockford(&faucet_b32) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    if faucet_id.len() != 32 {
        return StatusCode::BAD_REQUEST.into_response();
    }
    match db::get_faucet_ticket_claim(&state.db_pool, &faucet_id, ticket_index).await {
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
            log::warn!("faucet-ticket read failed: {e}");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

#[cfg(all(test, feature = "local-dev"))]
mod tests {
    //! Coordinate validity, attribution, write-once semantics — and THE
    //! availability property the ticket model exists for: a poisoned ticket
    //! costs exactly that ticket.
    use super::*;
    use crate::db;
    use crate::replication::{ReplicationConfig, ReplicationManager};
    use dsm::economic::faucet::{
        era_faucet_id, sign_faucet_ticket_claim, FaucetTicketClaimBody, ERA_FAUCET_TICKET_COUNT,
    };

    const NETWORK: &[u8] = b"dsm-testnet";

    fn state_with(
        pool: Arc<db::DBPool>,
        set: Option<crate::NodeStorageSet>,
        network: bool,
    ) -> Arc<AppState> {
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
        let mut st = AppState::new("n1".into(), "127.0.0.1:1", None, pool, rm);
        if let Some(s) = set {
            st = st.with_storage_set(s);
        }
        if network {
            st = st.with_network_id(NETWORK.to_vec());
        }
        Arc::new(st)
    }

    fn claim_body(
        pk: &[u8],
        devid: [u8; 32],
        set: [u8; 32],
        faucet_id: [u8; 32],
        ticket_index: u64,
    ) -> FaucetTicketClaimBody {
        FaucetTicketClaimBody {
            faucet_id,
            ticket_index,
            claimant_genesis: [0x51; 32],
            claimant_devid: devid,
            claimant_economic_position: 1,
            recipient_operation_digest: [0x52; 32],
            claimant_public_key: pk.to_vec(),
            storage_set_id: set,
        }
    }

    fn caller_for(devid: [u8; 32], pk: &[u8]) -> DeviceContext {
        DeviceContext {
            device_id: text_id::encode_base32_crockford(&devid),
            public_key: pk.to_vec(),
        }
    }

    #[tokio::test]
    async fn endpoint_enforces_coordinates_attribution_and_writes_once() {
        let pool = Arc::new(db::create_pool(":memory:", true).expect("pool"));
        db::init_db(&pool).await.expect("init");
        let set = crate::NodeStorageSet::new(
            vec![
                ("n1".into(), [0xC1; 32]),
                ("n2".into(), [0xC2; 32]),
                ("n3".into(), [0xC3; 32]),
            ],
            "n1",
            [0xC1; 32],
        )
        .unwrap();
        let state = state_with(pool.clone(), Some(set.clone()), true);

        let (pk, sk) = dsm::crypto::sphincs::generate_sphincs_keypair().unwrap();
        let devid = [0x61; 32];
        let caller = caller_for(devid, &pk);
        let canonical = era_faucet_id(NETWORK);

        // Noncanonical faucet id: a fully valid claim under an INVENTED id
        // gets no cell — the invented-universe attack has nowhere to write.
        let env =
            sign_faucet_ticket_claim(&claim_body(&pk, devid, set.id, [0xF4; 32], 7), &sk).unwrap();
        let r = post_claim(
            Extension(state.clone()),
            Extension(caller.clone()),
            Bytes::from(env),
        )
        .await;
        assert_eq!(r.status(), StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(r.headers()[OUTCOME_HEADER], "noncanonical-faucet");

        // Out-of-range ticket: not a coordinate that exists.
        let env = sign_faucet_ticket_claim(
            &claim_body(&pk, devid, set.id, canonical, ERA_FAUCET_TICKET_COUNT),
            &sk,
        )
        .unwrap();
        let r = post_claim(
            Extension(state.clone()),
            Extension(caller.clone()),
            Bytes::from(env),
        )
        .await;
        assert_eq!(r.status(), StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(r.headers()[OUTCOME_HEADER], "ticket-out-of-range");

        // Attribution: right key, WRONG device.
        let env =
            sign_faucet_ticket_claim(&claim_body(&pk, devid, set.id, canonical, 7), &sk).unwrap();
        let wrong_dev = caller_for([0x62; 32], &pk);
        let r = post_claim(
            Extension(state.clone()),
            Extension(wrong_dev),
            Bytes::from(env.clone()),
        )
        .await;
        assert_eq!(r.status(), StatusCode::FORBIDDEN);
        assert_eq!(r.headers()[OUTCOME_HEADER], "device-not-caller");

        // Accept, re-ack, refuse-different.
        let r = post_claim(
            Extension(state.clone()),
            Extension(caller.clone()),
            Bytes::from(env.clone()),
        )
        .await;
        assert_eq!(r.status(), StatusCode::OK);
        assert_eq!(r.headers()[OUTCOME_HEADER], "accepted");
        let r = post_claim(
            Extension(state.clone()),
            Extension(caller.clone()),
            Bytes::from(env.clone()),
        )
        .await;
        assert_eq!(r.headers()[OUTCOME_HEADER], "held-identical");

        let (pk2, sk2) = dsm::crypto::sphincs::generate_sphincs_keypair().unwrap();
        let devid2 = [0x63; 32];
        let env2 = sign_faucet_ticket_claim(&claim_body(&pk2, devid2, set.id, canonical, 7), &sk2)
            .unwrap();
        let r = post_claim(
            Extension(state.clone()),
            Extension(caller_for(devid2, &pk2)),
            Bytes::from(env2),
        )
        .await;
        assert_eq!(r.status(), StatusCode::CONFLICT);
        assert_eq!(r.headers()[OUTCOME_HEADER], "refused");
        assert!(r.headers().contains_key(HELD_DIGEST_HEADER));

        // The read half returns the exact winner bytes + digest.
        let got = get_claim(
            Extension(state.clone()),
            Path((text_id::encode_base32_crockford(&canonical), 7u64)),
        )
        .await;
        assert_eq!(got.status(), StatusCode::OK);
        assert!(got.headers().contains_key(CLAIM_DIGEST_HEADER));
    }

    /// THE regression control for ticket independence. An attacker parks a
    /// valid-but-never-validating claim on ticket i; a victim's claim on
    /// ticket j succeeds. If this ever fails, shared state crept back in and
    /// the global-head liveness defect has returned. (It proves ticket
    /// INDEPENDENCE — not claimant liveness under an adversary racing every
    /// ticket the victim derives, which V1 explicitly does not promise.)
    #[tokio::test]
    async fn poisoned_ticket_does_not_brick_the_faucet() {
        let pool = Arc::new(db::create_pool(":memory:", true).expect("pool"));
        db::init_db(&pool).await.expect("init");
        let set = crate::NodeStorageSet::new(
            vec![
                ("n1".into(), [0xC1; 32]),
                ("n2".into(), [0xC2; 32]),
                ("n3".into(), [0xC3; 32]),
            ],
            "n1",
            [0xC1; 32],
        )
        .unwrap();
        let state = state_with(pool.clone(), Some(set.clone()), true);
        let canonical = era_faucet_id(NETWORK);

        // Attacker consumes ticket i with a claim whose recipient digest will
        // never validate economically. The node stores it — content-blind
        // beyond coordinates — and that is FINE: it cost the attacker a
        // ticket.
        let (pk_a, sk_a) = dsm::crypto::sphincs::generate_sphincs_keypair().unwrap();
        let dev_a = [0x71; 32];
        let poison =
            sign_faucet_ticket_claim(&claim_body(&pk_a, dev_a, set.id, canonical, 100), &sk_a)
                .unwrap();
        let r = post_claim(
            Extension(state.clone()),
            Extension(caller_for(dev_a, &pk_a)),
            Bytes::from(poison),
        )
        .await;
        assert_eq!(r.headers()[OUTCOME_HEADER], "accepted");

        // Victim's claim on a DIFFERENT ticket is untouched.
        let (pk_v, sk_v) = dsm::crypto::sphincs::generate_sphincs_keypair().unwrap();
        let dev_v = [0x72; 32];
        let claim =
            sign_faucet_ticket_claim(&claim_body(&pk_v, dev_v, set.id, canonical, 101), &sk_v)
                .unwrap();
        let r = post_claim(
            Extension(state.clone()),
            Extension(caller_for(dev_v, &pk_v)),
            Bytes::from(claim),
        )
        .await;
        assert_eq!(
            r.headers()[OUTCOME_HEADER],
            "accepted",
            "a poisoned ticket must cost exactly that ticket — nothing else"
        );
    }

    /// Fail-closed configuration: no set and no network each refuse before
    /// any write.
    #[tokio::test]
    async fn unconfigured_node_refuses_rather_than_defaulting() {
        let pool = Arc::new(db::create_pool(":memory:", true).expect("pool"));
        db::init_db(&pool).await.expect("init");
        let set = crate::NodeStorageSet::new(
            vec![
                ("n1".into(), [0xC1; 32]),
                ("n2".into(), [0xC2; 32]),
                ("n3".into(), [0xC3; 32]),
            ],
            "n1",
            [0xC1; 32],
        )
        .unwrap();

        let (pk, sk) = dsm::crypto::sphincs::generate_sphincs_keypair().unwrap();
        let devid = [0x81; 32];
        let env = sign_faucet_ticket_claim(
            &claim_body(&pk, devid, set.id, era_faucet_id(NETWORK), 9),
            &sk,
        )
        .unwrap();

        // No storage set.
        let state = state_with(pool.clone(), None, true);
        let r = post_claim(
            Extension(state),
            Extension(caller_for(devid, &pk)),
            Bytes::from(env.clone()),
        )
        .await;
        assert_eq!(r.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(r.headers()[OUTCOME_HEADER], "no-storage-set");

        // Set but no network: the canonical faucet id is underivable, so the
        // register is inactive rather than guessing.
        let state = state_with(pool.clone(), Some(set), false);
        let r = post_claim(
            Extension(state),
            Extension(caller_for(devid, &pk)),
            Bytes::from(env),
        )
        .await;
        assert_eq!(r.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(r.headers()[OUTCOME_HEADER], "no-network");
    }

    /// 16 racers, one ticket, different bytes: exactly one acceptance at the
    /// DB layer (the endpoint adds only refusals above it).
    #[tokio::test]
    async fn concurrent_racers_on_one_ticket_yield_exactly_one_acceptance() {
        let pool = db::create_pool(":memory:", true).expect("pool");
        db::init_db(&pool).await.expect("init");
        let mut handles = Vec::new();
        for i in 0..16u8 {
            let pool = pool.clone();
            handles.push(tokio::spawn(async move {
                let bytes = vec![i; 64];
                let digest = faucet_claim_evidence_addr(&bytes);
                db::claim_faucet_ticket(&pool, &[0x91; 32], 5, &bytes, &digest, b"pk", &[0x6B; 32])
                    .await
                    .unwrap()
            }));
        }
        let mut accepted = 0;
        for h in handles {
            if matches!(h.await.unwrap(), db::OneShotOutcome::Accepted) {
                accepted += 1;
            }
        }
        assert_eq!(accepted, 1, "exactly one racer may win a ticket");
    }
}
