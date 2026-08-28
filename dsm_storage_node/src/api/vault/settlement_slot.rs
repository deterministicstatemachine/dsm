// SPDX-License-Identifier: MIT OR Apache-2.0
//! Settlement-slot claim register — a distributed, crash-fault-tolerant,
//! ONE-SHOT quorum register keyed `(vault_id, parent_sequence)`.
//!
//! WHAT THIS IS. Traders and a closing owner are mutually-unknown actors who
//! may race to consume the same public vault parent. Each submits its signed
//! claim envelope to every member of the vault's canonical storage set; a
//! member performs WRITE-ONCE CONDITIONAL ACCEPTANCE — first bytes for the slot
//! win, identical bytes re-ack, different bytes are refused with the held
//! digest — in ONE atomic write transaction over the unique key. A claimant
//! wins only when a quorum of the set accepted the SAME bytes. Because quorums
//! over one canonical set intersect and a member holds one value per slot,
//! two conflicting claimants cannot both win. This node's non-equivocation
//! (never acknowledging two values for one slot, surviving restart) is
//! therefore part of DLV's no-double-consumption safety argument. For THIS
//! endpoint the "dumb indexer" description of a storage node is not accurate.
//!
//! WHAT THIS IS NOT. It is not DSM consensus and it does not determine
//! transaction validity: the canonical DSM transition decides whether a
//! settlement or close is valid; this node never judges that. It verifies
//! claimant ATTRIBUTION only — the body's `claimant_public_key` must be the
//! authenticated caller's registered key and the signature must verify — so an
//! authenticated caller cannot claim as somebody else. It also refuses a claim
//! whose `storage_set_id` is not this node's own set: with the vault↔set
//! binding in the vault's signed anchor, only the birth set's members can
//! count for that vault.
//!
//! THREAT MODEL, STATED. The quorum safety argument assumes member nodes are
//! durably non-equivocating for a slot — a member cannot acknowledge two
//! different values for the same `(vault_id, parent_sequence)`, and that fact
//! survives process restart AND storage lifecycle: restoring this table from a
//! snapshot that predates a held claim, replacing a member without preserving
//! its register, or any rollback of the register is a SAFETY violation, not an
//! availability event. There is no update and no delete path. Under the beta
//! client model (protocol-conforming clients) this yields exclusivity; a
//! modified authenticated client that skips the claim is a Byzantine-client
//! case the beta model excludes. Griefing — any authenticated device claiming a
//! known slot and vanishing — is a permanent AMM denial-of-service for that
//! vault: accepted for the controlled beta fleet, a launch blocker for a public
//! market.
//!
//! Wire: `POST /api/v2/settlement-slot/claim` (device-auth) with the exact
//! `SettlementSlotClaimV2` envelope bytes as the body; `GET
//! /api/v2/settlement-slot/{vault_b32}/{parent_sequence}` (public) returns the
//! held envelope bytes. Outcomes travel in `x-dsm-slot-outcome`.

use axum::{
    body::Bytes,
    extract::{Extension, Path},
    http::{header, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Router,
};
use std::sync::Arc;

use crate::auth::DeviceContext;
use crate::db;
use crate::AppState;
use dsm::dlv::settlement_slot_claim::{decode_and_verify_settlement_slot_claim, ClaimError};
use dsm_sdk::util::text_id;

/// One SPHINCS+ SPX256f signature (~49.9 KiB) + a key + five small fields fit
/// well under this; cap to reject DoS payloads before decode.
const MAX_CLAIM_BYTES: usize = 160 * 1024;

pub const OUTCOME_HEADER: &str = "x-dsm-slot-outcome";
pub const HELD_DIGEST_HEADER: &str = "x-dsm-slot-held-digest";
pub const CLAIM_DIGEST_HEADER: &str = "x-dsm-slot-digest";

/// The device-authenticated write half. Mounted behind `auth::device_auth`.
pub fn create_write_router() -> Router<()> {
    Router::new().route("/api/v2/settlement-slot/claim", post(post_claim))
}

/// The public read half.
pub fn create_read_router(state: Arc<AppState>) -> Router<()> {
    Router::new()
        .route(
            "/api/v2/settlement-slot/{vault}/{parent_sequence}",
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

/// Write-once claim.
///
/// Order of checks: size → strict decode + signature (the envelope is the
/// claimant's exact bytes) → attribution (body key == caller key) → set
/// (body set == this node's set) → the ONE atomic write. Every refusal happens
/// before the write; nothing here is retried, updated or deleted.
pub async fn post_claim(
    Extension(state): Extension<Arc<AppState>>,
    Extension(caller): Extension<DeviceContext>,
    body: Bytes,
) -> Response {
    if body.is_empty() || body.len() > MAX_CLAIM_BYTES {
        return outcome(StatusCode::BAD_REQUEST, "malformed");
    }
    let verified = match decode_and_verify_settlement_slot_claim(&body) {
        Ok(v) => v,
        Err(ClaimError::SignatureInvalid) => {
            return outcome(StatusCode::FORBIDDEN, "signature-invalid");
        }
        Err(_) => return outcome(StatusCode::BAD_REQUEST, "malformed"),
    };
    // ATTRIBUTION, not validity: the key inside the signed body must be the
    // key the caller authenticated as. An authenticated device cannot claim on
    // behalf of another key.
    if verified.body.claimant_public_key != caller.public_key {
        return outcome(StatusCode::FORBIDDEN, "claimant-not-caller");
    }
    // THE SET. This node acknowledges only claims for the set it belongs to;
    // no set configured ⇒ the register is inactive here (fail closed).
    let Some(set) = state.storage_set.as_ref() else {
        return outcome(StatusCode::SERVICE_UNAVAILABLE, "no-storage-set");
    };
    if verified.body.storage_set_id != set.id {
        return outcome(StatusCode::UNPROCESSABLE_ENTITY, "foreign-set");
    }

    match db::claim_settlement_slot(
        &state.db_pool,
        &verified.body.vault_id,
        verified.body.parent_sequence,
        &body,
        &verified.envelope_digest,
        &verified.body.claimant_public_key,
        &verified.body.storage_set_id,
    )
    .await
    {
        Ok(db::SlotClaimOutcome::Accepted) => outcome(StatusCode::OK, "accepted"),
        Ok(db::SlotClaimOutcome::AlreadyHeldIdentical) => outcome(StatusCode::OK, "held-identical"),
        Ok(db::SlotClaimOutcome::Refused { held_digest }) => {
            let mut resp = outcome(StatusCode::CONFLICT, "refused");
            if let Ok(v) = HeaderValue::from_str(&text_id::encode_base32_crockford(&held_digest)) {
                resp.headers_mut().insert(HELD_DIGEST_HEADER, v);
            }
            resp
        }
        Err(e) => {
            log::warn!("settlement-slot claim: register write failed: {e}");
            outcome(StatusCode::INTERNAL_SERVER_ERROR, "error")
        }
    }
}

/// The claim this node holds for the slot: exact envelope bytes + digest.
pub async fn get_claim(
    Extension(state): Extension<Arc<AppState>>,
    Path((vault_b32, parent_sequence)): Path<(String, u64)>,
) -> Response {
    let Some(vault_id) = text_id::decode_base32_crockford(&vault_b32) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    if vault_id.len() != 32 {
        return StatusCode::BAD_REQUEST.into_response();
    }
    match db::get_settlement_slot_claim(&state.db_pool, &vault_id, parent_sequence).await {
        Ok(Some((bytes, digest))) => {
            let mut resp = (StatusCode::OK, bytes).into_response();
            resp.headers_mut().insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/octet-stream"),
            );
            if let Ok(v) = HeaderValue::from_str(&text_id::encode_base32_crockford(&digest)) {
                resp.headers_mut().insert(CLAIM_DIGEST_HEADER, v);
            }
            resp
        }
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(e) => {
            log::warn!("settlement-slot get: {e}");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

#[cfg(all(test, feature = "local-dev"))]
mod tests {
    //! Register properties on the SQLite backend: write-once in one atomic
    //! transaction (concurrent racers → exactly one accepted), restart
    //! persistence (a re-opened database still refuses B and re-acks A),
    //! attribution and set enforcement at the endpoint.
    use super::*;
    use crate::db;
    use dsm::dlv::settlement_slot_claim::{
        claim_envelope_digest, sign_settlement_slot_claim, SettlementSlotClaimBody,
    };

    fn body(pk: &[u8], set: [u8; 32], seq: u64, x: u8) -> SettlementSlotClaimBody {
        SettlementSlotClaimBody {
            vault_id: [0x11; 32],
            parent_sequence: seq,
            x: [x; 32],
            claimant_public_key: pk.to_vec(),
            storage_set_id: set,
            parent_binding_c_n: [0x7D; 32],
        }
    }

    #[tokio::test]
    async fn write_once_first_bytes_win_identical_reack_different_refused() {
        let pool = db::create_pool(":memory:", true).expect("pool");
        db::init_db(&pool).await.expect("init");
        let a = b"claim-A".to_vec();
        let b = b"claim-B".to_vec();
        let da = *blake3::hash(&a).as_bytes();
        let db_ = *blake3::hash(&b).as_bytes();
        let r1 = db::claim_settlement_slot(&pool, &[0x11; 32], 7, &a, &da, b"pkA", &[0x6B; 32])
            .await
            .unwrap();
        assert_eq!(r1, db::SlotClaimOutcome::Accepted);
        let r2 = db::claim_settlement_slot(&pool, &[0x11; 32], 7, &a, &da, b"pkA", &[0x6B; 32])
            .await
            .unwrap();
        assert_eq!(
            r2,
            db::SlotClaimOutcome::AlreadyHeldIdentical,
            "idempotent re-ack"
        );
        let r3 = db::claim_settlement_slot(&pool, &[0x11; 32], 7, &b, &db_, b"pkB", &[0x6B; 32])
            .await
            .unwrap();
        assert_eq!(
            r3,
            db::SlotClaimOutcome::Refused {
                held_digest: da.to_vec()
            },
            "different bytes for a held slot are refused with the held digest"
        );
        // Another slot is independent.
        let r4 = db::claim_settlement_slot(&pool, &[0x11; 32], 8, &b, &db_, b"pkB", &[0x6B; 32])
            .await
            .unwrap();
        assert_eq!(r4, db::SlotClaimOutcome::Accepted);
        let held = db::get_settlement_slot_claim(&pool, &[0x11; 32], 7)
            .await
            .unwrap()
            .expect("held");
        assert_eq!(held.0, a);
        assert_eq!(held.1, da.to_vec());
    }

    /// N racers with different bytes for one slot: exactly one accepted, every
    /// other refused with the winner's digest. The write is one atomic
    /// transaction over the unique key — never check-then-insert.
    #[tokio::test]
    async fn concurrent_racers_on_one_slot_yield_exactly_one_acceptance() {
        let pool = db::create_pool(":memory:", true).expect("pool");
        db::init_db(&pool).await.expect("init");
        let mut handles = Vec::new();
        for i in 0..16u8 {
            let pool = pool.clone();
            handles.push(tokio::spawn(async move {
                let bytes = vec![i; 40];
                let d = *blake3::hash(&bytes).as_bytes();
                db::claim_settlement_slot(&pool, &[0x22; 32], 3, &bytes, &d, b"pk", &[0x6B; 32])
                    .await
                    .unwrap()
            }));
        }
        let mut accepted = 0;
        let mut refused_digests = std::collections::BTreeSet::new();
        for h in handles {
            match h.await.unwrap() {
                db::SlotClaimOutcome::Accepted => accepted += 1,
                db::SlotClaimOutcome::Refused { held_digest } => {
                    refused_digests.insert(held_digest);
                }
                db::SlotClaimOutcome::AlreadyHeldIdentical => {
                    panic!("distinct bytes cannot be identical")
                }
            }
        }
        assert_eq!(accepted, 1, "exactly one racer wins the slot");
        assert_eq!(
            refused_digests.len(),
            1,
            "every loser is refused with THE winner's digest"
        );
        let held = db::get_settlement_slot_claim(&pool, &[0x22; 32], 3)
            .await
            .unwrap()
            .expect("held");
        assert_eq!(refused_digests.into_iter().next().unwrap(), held.1);
    }

    /// Restart persistence: after the process (here: the connection) is
    /// re-opened on the same file, A still holds and B is still refused.
    #[tokio::test]
    async fn a_held_claim_survives_reopening_the_database() {
        let dir = std::env::temp_dir().join(format!(
            "dsm-slot-register-{}",
            text_id::encode_base32_crockford(&blake3::hash(b"restart").as_bytes()[..8])
        ));
        let _ = std::fs::remove_file(&dir);
        let path = dir.to_string_lossy().to_string();
        let a = b"claim-A".to_vec();
        let da = *blake3::hash(&a).as_bytes();
        {
            let pool = db::create_pool(&path, true).expect("pool");
            db::init_db(&pool).await.expect("init");
            assert_eq!(
                db::claim_settlement_slot(&pool, &[0x33; 32], 1, &a, &da, b"pkA", &[0x6B; 32])
                    .await
                    .unwrap(),
                db::SlotClaimOutcome::Accepted
            );
        }
        // "Restart": a fresh pool on the same file.
        let pool = db::create_pool(&path, true).expect("pool");
        db::init_db(&pool).await.expect("init");
        let b = b"claim-B".to_vec();
        let db_ = *blake3::hash(&b).as_bytes();
        assert_eq!(
            db::claim_settlement_slot(&pool, &[0x33; 32], 1, &b, &db_, b"pkB", &[0x6B; 32])
                .await
                .unwrap(),
            db::SlotClaimOutcome::Refused {
                held_digest: da.to_vec()
            },
            "B is still refused after restart"
        );
        assert_eq!(
            db::claim_settlement_slot(&pool, &[0x33; 32], 1, &a, &da, b"pkA", &[0x6B; 32])
                .await
                .unwrap(),
            db::SlotClaimOutcome::AlreadyHeldIdentical,
            "A still re-acks after restart"
        );
        let _ = std::fs::remove_file(&path);
    }

    /// Endpoint semantics: attribution (body key == caller key), set
    /// enforcement, and the outcome header on accept / re-ack / refuse.
    #[tokio::test]
    async fn endpoint_enforces_attribution_and_set_then_writes_once() {
        use crate::replication::{ReplicationConfig, ReplicationManager};
        let pool = Arc::new(db::create_pool(":memory:", true).expect("pool"));
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
        let set =
            crate::NodeStorageSet::new(vec!["n1".into(), "n2".into(), "n3".into()], "n1").unwrap();
        let state = Arc::new(
            AppState::new("n1".into(), "127.0.0.1:1", None, pool, rm).with_storage_set(set.clone()),
        );

        let (pk, sk) = dsm::crypto::sphincs::generate_sphincs_keypair().unwrap();
        let (pk2, sk2) = dsm::crypto::sphincs::generate_sphincs_keypair().unwrap();
        let caller = DeviceContext {
            device_id: "dev".into(),
            public_key: pk.clone(),
        };
        let env_a = sign_settlement_slot_claim(&body(&pk, set.id, 5, 0xA1), &sk).unwrap();

        // Attribution: caller authenticated as pk2 cannot submit pk's claim.
        let stranger = DeviceContext {
            device_id: "dev2".into(),
            public_key: pk2.clone(),
        };
        let r = post_claim(
            Extension(state.clone()),
            Extension(stranger),
            Bytes::from(env_a.clone()),
        )
        .await;
        assert_eq!(r.status(), StatusCode::FORBIDDEN);
        assert_eq!(r.headers()[OUTCOME_HEADER], "claimant-not-caller");

        // Foreign set: refused before any write.
        let mut other = set.id;
        other[0] ^= 0xff;
        let env_foreign = sign_settlement_slot_claim(&body(&pk, other, 5, 0xA1), &sk).unwrap();
        let r = post_claim(
            Extension(state.clone()),
            Extension(caller.clone()),
            Bytes::from(env_foreign),
        )
        .await;
        assert_eq!(r.status(), StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(r.headers()[OUTCOME_HEADER], "foreign-set");
        assert!(
            db::get_settlement_slot_claim(&state.db_pool, &[0x11; 32], 5)
                .await
                .unwrap()
                .is_none(),
            "nothing was written by the refusals"
        );

        // The real claim: accepted, then re-acked, then a competitor refused.
        let r = post_claim(
            Extension(state.clone()),
            Extension(caller.clone()),
            Bytes::from(env_a.clone()),
        )
        .await;
        assert_eq!(r.status(), StatusCode::OK);
        assert_eq!(r.headers()[OUTCOME_HEADER], "accepted");
        let r = post_claim(
            Extension(state.clone()),
            Extension(caller.clone()),
            Bytes::from(env_a.clone()),
        )
        .await;
        assert_eq!(r.headers()[OUTCOME_HEADER], "held-identical");
        let caller2 = DeviceContext {
            device_id: "dev2".into(),
            public_key: pk2.clone(),
        };
        let env_b = sign_settlement_slot_claim(&body(&pk2, set.id, 5, 0xB2), &sk2).unwrap();
        let r = post_claim(
            Extension(state.clone()),
            Extension(caller2),
            Bytes::from(env_b),
        )
        .await;
        assert_eq!(r.status(), StatusCode::CONFLICT);
        assert_eq!(r.headers()[OUTCOME_HEADER], "refused");
        assert_eq!(
            r.headers()[HELD_DIGEST_HEADER],
            text_id::encode_base32_crockford(&claim_envelope_digest(&env_a)).as_str()
        );

        // A malformed body never reaches the register.
        let r = post_claim(
            Extension(state.clone()),
            Extension(caller),
            Bytes::from_static(b"\xff\xff\xff"),
        )
        .await;
        assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    }
}
