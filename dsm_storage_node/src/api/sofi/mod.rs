// SPDX-License-Identifier: Apache-2.0

//! SoFi `P` and `G` — content-addressed, write-once, and never exercise.
//!
//! A trader pre-commit `P` and a DLV policy-fulfillment witness `G_j` are
//! objects, not positions. Storing either **installs nothing at `K_root`,
//! occupies no economic position, and is not exercise** (F2 stage 1 and 2).
//! The exercise boundary is `FulfillmentRegistered(F)`, which lives in the
//! fulfillment register and not here.
//!
//! ## Why these are not in `api/objects/immutable.rs`
//!
//! That store is deliberately **content-blind** — it never decodes a payload,
//! because a predecessor store sniffed payloads and varied acceptance by what
//! bytes happened to parse as. But §2 gives `P` and `G` content-specific
//! ingress: `P` is "signature + key binding", and `G` is "re-hash + binding to
//! a stored `P` leg", which is a CROSS-OBJECT check a generic substrate cannot
//! make. So these get their own module and the generic store stays blind.
//!
//! ## The address is the BODY's identity
//!
//! `PrecommitId` and `PolicyFulfillmentId` are derived from the canonical body.
//! For `P` that means an alternate valid signature envelope over the same body
//! is the SAME object at the SAME address, so re-storing it acks rather than
//! conflicting — an honest relayer never races the trader. There is no
//! `Refused` outcome here at all: a register cell can be contested, a
//! content address cannot.
//!
//! ## What is NOT checked here, and why
//!
//! §2 forbids a member from judging economics, policy, validity, canonicality
//! or liveness, and this module judges none of them. It also does not check
//! the parts of P conformance that recompute `E` — the leg set against
//! `P(E)/Γ`, `R_realize`, `R_void` — because those need `P(E)` and `𝒞^pre`,
//! which §2 requires at **F** ingress, not here. A `G`'s policy is never
//! evaluated: the node checks the binding arithmetic, the consumer checks the
//! policy.

use axum::{
    body::Bytes,
    extract::{Extension, Path},
    http::{HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Router,
};
use std::sync::Arc;

use crate::{db, AppState};
use dsm::ccb::class;
use dsm::economic::claim_envelope::{
    decode_registered_economic_claim, economic_root_claim_envelope_digest, RegisteredEconomicClaim,
};
use dsm::economic::register::economic_root_register_key;
use dsm::sofi::conformance::{check_fulfillment_against_precommit, FulfillmentConformanceError};
use dsm::sofi::derive;
use dsm::sofi::signature::{verify_signed_object, SignedSofiBody};
use dsm::sofi::wire::{
    DlvPolicyFulfillmentBody, ParentClaimRef, SignedSofiObject, TraderFulfillmentBody,
    TraderPrecommitBody,
};
use dsm_sdk::util::text_id;

/// Generous cap: the largest object here is a `P` envelope carrying an
/// SPX256f signature (49,856 bytes) plus its body.
const MAX_SOFI_OBJECT_BYTES: usize = 512 * 1024;

fn outcome(code: StatusCode, reason: &str) -> Response {
    let mut resp = code.into_response();
    if let Ok(v) = HeaderValue::from_str(reason) {
        resp.headers_mut().insert("x-dsm-outcome", v);
    }
    resp
}

pub fn create_read_router(state: Arc<AppState>) -> Router<()> {
    Router::new()
        .route("/api/v2/sofi/precommit/{id}", get(get_precommit))
        .route("/api/v2/sofi/fulfillment/{k_ful}", get(get_fulfillment))
        .route(
            "/api/v2/sofi/policy-fulfillment/{id}",
            get(get_policy_fulfillment),
        )
        .layer(Extension(state))
}

pub fn create_write_router(state: Arc<AppState>) -> Router<()> {
    Router::new()
        .route("/api/v2/sofi/precommit", post(post_precommit))
        .route("/api/v2/sofi/fulfillment", post(post_fulfillment))
        .route(
            "/api/v2/sofi/policy-fulfillment",
            post(post_policy_fulfillment),
        )
        .layer(Extension(state))
}

/// `P` ingress: signature + key binding + the conformance a member can make.
///
/// **Any caller may relay, so there is no `DeviceContext` extractor here.**
/// `P` is not authorized by who posts it — it is authorized by the trader's
/// signature under the key the parent claim proves. Taking the caller's
/// identity as an argument would imply it were an input to acceptance, and the
/// next reader would reasonably start checking it. The route still sits behind
/// the transport's auth layer; that is a bearer question, not an authority
/// one.
pub async fn post_precommit(Extension(state): Extension<Arc<AppState>>, body: Bytes) -> Response {
    if body.is_empty() || body.len() > MAX_SOFI_OBJECT_BYTES {
        return outcome(StatusCode::BAD_REQUEST, "malformed");
    }
    let Ok(envelope) = SignedSofiObject::decode(&body) else {
        return outcome(StatusCode::BAD_REQUEST, "malformed");
    };
    if envelope.body_class() != class::SOFI_TRADER_PRECOMMIT_BODY {
        return outcome(StatusCode::BAD_REQUEST, "not-a-precommit");
    }
    // Decoded to LOCATE the parent claim, never to accept anything: the key
    // this picks is then required to be the one the body commits, by
    // `verify_signed_object`. A body lying about its coordinates only names a
    // parent it cannot be bound to.
    let Ok(peek) = dsm::sofi::wire::TraderPrecommitBody::decode(envelope.body_ccb()) else {
        return outcome(StatusCode::BAD_REQUEST, "malformed");
    };
    let Some(set) = state.storage_set.as_ref() else {
        return outcome(StatusCode::SERVICE_UNAVAILABLE, "no-storage-set");
    };
    if *peek.storage_set_id() != set.id {
        return outcome(StatusCode::UNPROCESSABLE_ENTITY, "foreign-set");
    }

    // THE KEY BINDING. `verify_precommit` checks that the holder of the key
    // `P` commits signed it; binding that key to the trader's identity is a
    // different question, and this is where the parent claim is in hand.
    let claim_ref = match peek.parent_claim_ref() {
        ParentClaimRef::SingleRoot { claim_ref } => *claim_ref,
        // The key for a conditional parent is the one `P_p` committed, reached
        // through the registered `F` that installed `C_p` — and the fulfillment
        // register does not exist until E2-2. Refused by name rather than
        // accepted unbound: an unbound `P` is exactly what the two-part
        // attribution elsewhere exists to prevent.
        ParentClaimRef::Conditional { .. } => {
            return outcome(
                StatusCode::NOT_IMPLEMENTED,
                "conditional-parent-needs-the-fulfillment-register",
            )
        }
    };
    let k_root = economic_root_register_key(peek.genesis(), peek.device_id(), peek.position());
    let held = match db::get_economic_root_claim(&state.db_pool, &k_root).await {
        Ok(Some((bytes, _digest))) => bytes,
        Ok(None) => return outcome(StatusCode::UNPROCESSABLE_ENTITY, "parent-claim-not-held"),
        Err(_) => return outcome(StatusCode::INTERNAL_SERVER_ERROR, "storage"),
    };
    if economic_root_claim_envelope_digest(&held) != claim_ref {
        return outcome(
            StatusCode::UNPROCESSABLE_ENTITY,
            "parent-claim-is-not-the-named-one",
        );
    }
    let signer = match decode_registered_economic_claim(&held) {
        Ok(RegisteredEconomicClaim::SingleRoot(c)) => c.body().claimant_public_key.clone(),
        // A conditional cell proves no key; it is unreachable here because the
        // ref arm above already refused, and it is refused again rather than
        // unwrapped.
        Ok(RegisteredEconomicClaim::ConditionalSofi(_)) => {
            return outcome(
                StatusCode::NOT_IMPLEMENTED,
                "conditional-parent-needs-the-fulfillment-register",
            )
        }
        Err(_) => {
            return outcome(
                StatusCode::INTERNAL_SERVER_ERROR,
                "held-claim-does-not-decode",
            )
        }
    };

    let verified = match verify_signed_object(&envelope, &signer) {
        Ok(v) => v,
        Err(e) => return outcome(StatusCode::FORBIDDEN, &format!("{e}")),
    };
    let SignedSofiBody::Precommit(precommit) = verified else {
        return outcome(StatusCode::BAD_REQUEST, "not-a-precommit");
    };

    let id = derive::precommit_id(&precommit);
    match db::put_sofi_precommit(&state.db_pool, &id, &body).await {
        Ok(db::ObjectPutOutcome::Stored) => outcome(StatusCode::OK, "stored"),
        Ok(db::ObjectPutOutcome::AlreadyHeld) => outcome(StatusCode::OK, "already-held"),
        Err(_) => outcome(StatusCode::INTERNAL_SERVER_ERROR, "storage"),
    }
}

/// `G` ingress: re-hash and bind to a stored `P` leg. No policy is evaluated.
pub async fn post_policy_fulfillment(
    Extension(state): Extension<Arc<AppState>>,
    body: Bytes,
) -> Response {
    if body.is_empty() || body.len() > MAX_SOFI_OBJECT_BYTES {
        return outcome(StatusCode::BAD_REQUEST, "malformed");
    }
    let Ok(witness) = DlvPolicyFulfillmentBody::decode(&body) else {
        return outcome(StatusCode::BAD_REQUEST, "malformed");
    };
    // Canonical or nothing: the identity is over these bytes, so a second
    // encoding of one witness would be a second address for one object.
    if witness.encode() != body {
        return outcome(StatusCode::BAD_REQUEST, "not-canonical");
    }

    let Ok(Some(p_envelope)) = db::get_sofi_precommit(&state.db_pool, &witness.precommit_id).await
    else {
        return outcome(StatusCode::UNPROCESSABLE_ENTITY, "precommit-not-held");
    };
    let Ok(env) = SignedSofiObject::decode(&p_envelope) else {
        return outcome(
            StatusCode::INTERNAL_SERVER_ERROR,
            "held-precommit-does-not-decode",
        );
    };
    let Ok(precommit) = dsm::sofi::wire::TraderPrecommitBody::decode(env.body_ccb()) else {
        return outcome(
            StatusCode::INTERNAL_SERVER_ERROR,
            "held-precommit-does-not-decode",
        );
    };

    // BINDING TO A STORED LEG (§2). The witness must name this P's external
    // commitment and one of its legs. The shadow it carries is NOT derivable
    // here — it comes from E — so it is bound into the identity and checked by
    // the consumer, not invented by the node.
    if witness.external_commitment != *precommit.external_commitment() {
        return outcome(
            StatusCode::UNPROCESSABLE_ENTITY,
            "witness-names-another-commitment",
        );
    }
    if !precommit
        .legs()
        .iter()
        .any(|leg| leg.vault_id == witness.vault_id && leg.parent_root == witness.parent_root)
    {
        return outcome(StatusCode::UNPROCESSABLE_ENTITY, "witness-matches-no-leg");
    }

    let id = derive::policy_fulfillment_id(&witness);
    match db::put_sofi_policy_fulfillment(&state.db_pool, &id, &witness.precommit_id, &body).await {
        Ok(db::ObjectPutOutcome::Stored) => outcome(StatusCode::OK, "stored"),
        Ok(db::ObjectPutOutcome::AlreadyHeld) => outcome(StatusCode::OK, "already-held"),
        Err(_) => outcome(StatusCode::INTERNAL_SERVER_ERROR, "storage"),
    }
}

async fn serve(bytes: Option<Vec<u8>>) -> Response {
    match bytes {
        Some(b) => (StatusCode::OK, b).into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

pub async fn get_precommit(
    Extension(state): Extension<Arc<AppState>>,
    Path(id_b32): Path<String>,
) -> Response {
    let Some(id) = text_id::decode_base32_crockford(&id_b32).filter(|v| v.len() == 32) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    match db::get_sofi_precommit(&state.db_pool, &id).await {
        Ok(found) => serve(found).await,
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

pub async fn get_policy_fulfillment(
    Extension(state): Extension<Arc<AppState>>,
    Path(id_b32): Path<String>,
) -> Response {
    let Some(id) = text_id::decode_base32_crockford(&id_b32).filter(|v| v.len() == 32) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    match db::get_sofi_policy_fulfillment(&state.db_pool, &id).await {
        Ok(found) => serve(found).await,
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

/// A STABLE outcome name per conformance refusal.
///
/// Not `format!("{e:?}")`: a debug rendering is not a protocol surface, it
/// changes whenever the enum does, and it is not greppable from a client. Each
/// refusal gets a name that means the same thing tomorrow.
fn conformance_outcome(e: &FulfillmentConformanceError) -> &'static str {
    match e {
        FulfillmentConformanceError::PrecommitMismatch => "fulfillment-names-another-precommit",
        FulfillmentConformanceError::PositionNotSuccessor { .. } => "position-is-not-the-successor",
        FulfillmentConformanceError::KeyMismatch => "key-is-not-the-precommits",
        FulfillmentConformanceError::ShadowCountMismatch { .. } => "shadow-count-mismatch",
        FulfillmentConformanceError::PolicyFulfillmentSetNotCanonical => {
            "policy-fulfillment-set-is-not-canonical"
        }
        FulfillmentConformanceError::AttemptsDoNotCoverLegs => "attempts-do-not-cover-legs",
        FulfillmentConformanceError::Wire(_) => "successor-position-does-not-exist",
    }
}

/// `F` ingress: signature, conformance against a STORED `P` and STORED
/// witnesses, then `K_ful(q)` and `C_q` at `K_root(q)` in ONE transaction.
///
/// **This is the exercise boundary.** Everything before it — publishing `P`,
/// computing witnesses, even handing `F` to one member — is not exercise. A
/// successful return here is, and it is irreversible.
///
/// The canonical witness set is RECONSTRUCTED from the `G` objects this member
/// holds, not taken from `F`'s own list. §2 requires the set to equal
/// `Canon[PolicyFulfillmentId_j(P, j)]` for every leg of `P`, "each derived
/// from P's leg and stored" — so a member that does not hold a witness for
/// some leg cannot conclude the set is complete, and says so rather than
/// trusting the list it was handed.
pub async fn post_fulfillment(Extension(state): Extension<Arc<AppState>>, body: Bytes) -> Response {
    if body.is_empty() || body.len() > MAX_SOFI_OBJECT_BYTES {
        return outcome(StatusCode::BAD_REQUEST, "malformed");
    }
    let Ok(envelope) = SignedSofiObject::decode(&body) else {
        return outcome(StatusCode::BAD_REQUEST, "malformed");
    };
    if envelope.body_class() != class::SOFI_TRADER_FULFILLMENT_BODY {
        return outcome(StatusCode::BAD_REQUEST, "not-a-fulfillment");
    }
    let Ok(peek) = TraderFulfillmentBody::decode(envelope.body_ccb()) else {
        return outcome(StatusCode::BAD_REQUEST, "malformed");
    };
    let Some(set) = state.storage_set.as_ref() else {
        return outcome(StatusCode::SERVICE_UNAVAILABLE, "no-storage-set");
    };

    // The referenced P must be HELD. A fulfillment of a pre-commit this member
    // has never seen is not something it can find conforming.
    let Ok(Some(p_envelope)) = db::get_sofi_precommit(&state.db_pool, peek.precommit_id()).await
    else {
        return outcome(StatusCode::UNPROCESSABLE_ENTITY, "precommit-not-held");
    };
    let Ok(p_env) = SignedSofiObject::decode(&p_envelope) else {
        return outcome(
            StatusCode::INTERNAL_SERVER_ERROR,
            "held-precommit-does-not-decode",
        );
    };
    let Ok(precommit) = TraderPrecommitBody::decode(p_env.body_ccb()) else {
        return outcome(
            StatusCode::INTERNAL_SERVER_ERROR,
            "held-precommit-does-not-decode",
        );
    };

    // F is signed by the key P committed — that is the whole of F's key
    // binding, and it is why F is not self-verifying.
    let verified = match verify_signed_object(&envelope, precommit.claimant_public_key()) {
        Ok(v) => v,
        Err(e) => return outcome(StatusCode::FORBIDDEN, &format!("{e}")),
    };
    let SignedSofiBody::Fulfillment(fulfillment) = verified else {
        return outcome(StatusCode::BAD_REQUEST, "not-a-fulfillment");
    };

    // Reconstruct the canonical set from STORED witnesses, in P's leg order.
    let held = match db::list_sofi_policy_fulfillments(&state.db_pool, peek.precommit_id()).await {
        Ok(rows) => rows,
        Err(_) => return outcome(StatusCode::INTERNAL_SERVER_ERROR, "storage"),
    };
    let witnesses: Vec<DlvPolicyFulfillmentBody> = held
        .iter()
        .filter_map(|b| DlvPolicyFulfillmentBody::decode(b).ok())
        .collect();
    let mut shadows = Vec::with_capacity(precommit.legs().len());
    for leg in precommit.legs() {
        let Some(w) = witnesses
            .iter()
            .find(|w| w.vault_id == leg.vault_id && w.parent_root == leg.parent_root)
        else {
            return outcome(
                StatusCode::UNPROCESSABLE_ENTITY,
                "policy-fulfillment-not-held",
            );
        };
        shadows.push(w.shadow_core);
    }

    if let Err(e) = check_fulfillment_against_precommit(&precommit, &fulfillment, &shadows) {
        return outcome(StatusCode::UNPROCESSABLE_ENTITY, conformance_outcome(&e));
    }

    // C_q is DERIVED from (P, F) here, in the member, which is why it is never
    // posted and why it needs no signature of its own.
    let claim = derive::resolution_claim(&precommit, &fulfillment);
    let q = fulfillment.position();
    let k_ful = derive::fulfillment_register_key(precommit.genesis(), precommit.device_id(), q);
    let k_root = economic_root_register_key(precommit.genesis(), precommit.device_id(), q);
    let fid = derive::fulfillment_id(&fulfillment);

    match db::register_fulfillment_with_claim(
        &state.db_pool,
        &k_ful,
        &fid,
        &body,
        &k_root,
        &claim.encode(),
        &set.id,
    )
    .await
    {
        Ok(db::FulfillmentRegistration::Registered) => outcome(StatusCode::OK, "registered"),
        Ok(db::FulfillmentRegistration::AlreadyRegistered) => {
            outcome(StatusCode::OK, "already-registered")
        }
        Ok(db::FulfillmentRegistration::PositionTaken { .. }) => {
            outcome(StatusCode::CONFLICT, "position-taken")
        }
        Ok(db::FulfillmentRegistration::RootCellTaken { .. }) => {
            outcome(StatusCode::CONFLICT, "root-cell-taken")
        }
        Err(_) => outcome(StatusCode::INTERNAL_SERVER_ERROR, "storage"),
    }
}

pub async fn get_fulfillment(
    Extension(state): Extension<Arc<AppState>>,
    Path(k_ful_b32): Path<String>,
) -> Response {
    let Some(k) = text_id::decode_base32_crockford(&k_ful_b32).filter(|v| v.len() == 32) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    match db::get_sofi_fulfillment(&state.db_pool, &k).await {
        Ok(found) => serve(found).await,
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}
