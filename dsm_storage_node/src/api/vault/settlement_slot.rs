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
/// The register incarnation this node is serving, Base32-Crockford.
///
/// Echoed on EVERY register read. A reader that committed a different
/// incarnation for this member counts the answer as `Unavailable` — never as
/// a value and never as an absence — because a rebuilt register can honestly
/// report "nothing here" for a cell the incarnation the vault committed once
/// held, and node identity alone cannot tell the two apart.
pub const INCARNATION_HEADER: &str = "x-dsm-register-incarnation";
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
    // The incarnation is stamped on EVERY answer this handler gives, held or
    // absent alike. Stamping only the "held" case would leave the dangerous
    // one — a rebuilt member reporting emptiness — indistinguishable from the
    // real member reporting it.
    let incarnation = state
        .storage_set
        .as_ref()
        .map(|set| text_id::encode_base32_crockford(&set.own_incarnation));
    let stamp = |resp: &mut Response| {
        if let Some(v) = incarnation
            .as_deref()
            .and_then(|s| HeaderValue::from_str(s).ok())
        {
            resp.headers_mut().insert(INCARNATION_HEADER, v);
        }
    };
    match db::get_settlement_slot_claim(&state.db_pool, &vault_id, parent_sequence).await {
        Ok(Some((bytes, digest))) => {
            let mut resp = (StatusCode::OK, bytes).into_response();
            resp.headers_mut().insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/octet-stream"),
            );
            resp.headers_mut()
                .insert(OUTCOME_HEADER, HeaderValue::from_static("held"));
            if let Ok(v) = HeaderValue::from_str(&text_id::encode_base32_crockford(&digest)) {
                resp.headers_mut().insert(CLAIM_DIGEST_HEADER, v);
            }
            stamp(&mut resp);
            resp
        }
        // AN ABSENCE IS ASSERTED, NEVER INFERRED FROM A STATUS CODE. A bare
        // 404 is something any part of this process can emit — a route miss
        // reaches the router's fallback, which the outermost identity-echo
        // layer still decorates — so a reader that took `404` for "no row"
        // would accept a process-level miss as this member testifying that
        // the cell is empty. The header is that testimony; the status alone
        // is not. The write side has always worked this way.
        Ok(None) => {
            let mut resp = StatusCode::NOT_FOUND.into_response();
            resp.headers_mut()
                .insert(OUTCOME_HEADER, HeaderValue::from_static("absent"));
            stamp(&mut resp);
            resp
        }
        Err(e) => {
            log::warn!("settlement-slot get: {e}");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    //! Endpoint semantics for the settlement-slot register, ON WHICHEVER
    //! BACKEND IS COMPILED: attribution (the body's claimant key must be the
    //! authenticated caller), storage-set enforcement, and the outcome header
    //! on accept / re-ack / refuse.
    //!
    //! The register's own write-once and restart properties are stated once
    //! for all three one-shot registers in `crate::db::write_once_properties`,
    //! not repeated here.
    #![allow(clippy::disallowed_methods)] // unwrap/expect acceptable in deterministic tests
    use super::*;
    use crate::db;
    use crate::db::write_once_properties::{test_pool, unique_key};
    use dsm::dlv::settlement_slot_claim::{
        claim_envelope_digest, sign_settlement_slot_claim, SettlementSlotClaimBody,
    };

    fn body(vault: [u8; 32], pk: &[u8], set: [u8; 32], seq: u64, x: u8) -> SettlementSlotClaimBody {
        SettlementSlotClaimBody {
            vault_id: vault,
            parent_sequence: seq,
            x: [x; 32],
            claimant_public_key: pk.to_vec(),
            storage_set_id: set,
            parent_binding_c_n: [0x7D; 32],
        }
    }

    /// EVERY ANSWER CARRIES THE INCARNATION, held and absent alike.
    ///
    /// The absent case is the one that matters: a member that rebuilt its
    /// register answers "nothing here" perfectly honestly, and a reader that
    /// could not tell which register history said so would count that as
    /// emptiness for a cell the committed incarnation once held. Stamping
    /// only the `held` answer would leave exactly that case unmarked.
    #[tokio::test]
    async fn every_read_answer_names_the_register_incarnation_serving_it() {
        use crate::replication::{ReplicationConfig, ReplicationManager};
        let vault = unique_key(0x55);
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
        let expected = dsm_sdk::util::text_id::encode_base32_crockford(&[0xC1u8; 32]);
        let state = Arc::new(
            AppState::new("n1".into(), "127.0.0.1:1", None, pool, rm).with_storage_set(set),
        );

        // ABSENT: the cell has never been claimed.
        let r = get_claim(
            Extension(state.clone()),
            axum::extract::Path((text_id::encode_base32_crockford(&vault), 9u64)),
        )
        .await;
        assert_eq!(r.status(), StatusCode::NOT_FOUND);
        assert_eq!(r.headers()[OUTCOME_HEADER], "absent");
        assert_eq!(
            r.headers()[INCARNATION_HEADER],
            expected.as_str(),
            "an absence must say WHICH register history is asserting it"
        );

        // HELD: the same stamp, on the other branch.
        let claim = b"claim-bytes".to_vec();
        let digest = *blake3::hash(&claim).as_bytes();
        db::claim_settlement_slot(
            &state.db_pool,
            &vault,
            9,
            &claim,
            &digest,
            b"pk",
            &[0x6B; 32],
        )
        .await
        .expect("claim");
        let r = get_claim(
            Extension(state.clone()),
            axum::extract::Path((text_id::encode_base32_crockford(&vault), 9u64)),
        )
        .await;
        assert_eq!(r.status(), StatusCode::OK);
        assert_eq!(r.headers()[OUTCOME_HEADER], "held");
        assert_eq!(r.headers()[INCARNATION_HEADER], expected.as_str());
    }

    /// Endpoint semantics: attribution (body key == caller key), set
    /// enforcement, and the outcome header on accept / re-ack / refuse.
    #[tokio::test]
    async fn endpoint_enforces_attribution_and_set_then_writes_once() {
        use crate::replication::{ReplicationConfig, ReplicationManager};
        let vault = unique_key(0x44);
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
        let state = Arc::new(
            AppState::new("n1".into(), "127.0.0.1:1", None, pool, rm).with_storage_set(set.clone()),
        );

        let (pk, sk) = dsm::crypto::sphincs::generate_sphincs_keypair().unwrap();
        let (pk2, sk2) = dsm::crypto::sphincs::generate_sphincs_keypair().unwrap();
        let caller = DeviceContext {
            device_id: "dev".into(),
            public_key: pk.clone(),
        };
        let env_a = sign_settlement_slot_claim(&body(vault, &pk, set.id, 5, 0xA1), &sk).unwrap();

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
        let env_foreign =
            sign_settlement_slot_claim(&body(vault, &pk, other, 5, 0xA1), &sk).unwrap();
        let r = post_claim(
            Extension(state.clone()),
            Extension(caller.clone()),
            Bytes::from(env_foreign),
        )
        .await;
        assert_eq!(r.status(), StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(r.headers()[OUTCOME_HEADER], "foreign-set");
        assert!(
            db::get_settlement_slot_claim(&state.db_pool, &vault, 5)
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
        let env_b = sign_settlement_slot_claim(&body(vault, &pk2, set.id, 5, 0xB2), &sk2).unwrap();
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
