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

pub mod registration;

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
    DlvPolicyFulfillmentBody, ParentClaimRef, SettlementPreimage, SignedSofiObject,
    TraderFulfillmentBody, TraderPrecommitBody,
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
        .route("/api/v2/sofi/preimage/{e}", get(get_preimage))
        .route("/api/v2/sofi/precommit/{id}", get(get_precommit))
        .route("/api/v2/sofi/fulfillment/{k_ful}", get(get_fulfillment))
        .route(
            "/api/v2/sofi/fulfillment/{k_ful}/registration",
            get(get_registration),
        )
        .route("/api/v2/sofi/cell/{k_cell}", get(get_cell))
        .route(
            "/api/v2/sofi/policy-fulfillment/{id}",
            get(get_policy_fulfillment),
        )
        .layer(Extension(state))
}

pub fn create_write_router(state: Arc<AppState>) -> Router<()> {
    Router::new()
        .route("/api/v2/sofi/preimage", post(post_preimage))
        .route("/api/v2/sofi/precommit", post(post_precommit))
        .route("/api/v2/sofi/fulfillment", post(post_fulfillment))
        .route(
            "/api/v2/sofi/fulfillment/{k_ful}/registration",
            post(post_registration),
        )
        .route("/api/v2/sofi/cell/{fulfillment}/{vault}", post(post_cell))
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

    // BINDING TO `P(E)` (§2). The witness must name this P's external
    // commitment and carry the exact leg — shadow included — that the
    // settlement preimage implies.
    if witness.external_commitment != *precommit.external_commitment() {
        return outcome(
            StatusCode::UNPROCESSABLE_ENTITY,
            "witness-names-another-commitment",
        );
    }
    // THE SHADOW IS BOUND TO `P(E)`, not merely to a leg coordinate. §2: the
    // witness must match a stored P leg AND `P(E)`.
    //
    // `policy_fulfillment_id` hashes the whole body, `shadow_core` included,
    // so a witness differing only in its shadow lands at a DIFFERENT address
    // and used to store successfully beside the honest one. F ingress then had
    // several candidates for one leg and no basis for choosing, which let
    // anyone able to relay make an honest `F` refusable — and, because the
    // choice came from an unordered read, let two members answer differently
    // about one identical `F`.
    //
    // `P(E)` is the authority: `c°_{V,j}` is `dlv_core_digest` over the `V°_j`
    // the preimage carries, so for a given `E` there is exactly one admissible
    // shadow per leg. A same-coordinate decoy is now not storable at all.
    let canonical = match canonical_legs_for(&state, &precommit).await {
        Ok(legs) => legs,
        Err(resp) => return *resp,
    };
    if !canonical.iter().any(|leg| {
        leg.vault_id == witness.vault_id
            && leg.parent_root == witness.parent_root
            && leg.shadow_core == witness.shadow_core
    }) {
        return outcome(
            StatusCode::UNPROCESSABLE_ENTITY,
            "witness-is-not-the-one-e-commits",
        );
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

    // ── The canonical witness set is DERIVED, not dereferenced ─────────────
    //
    // §2's F conformance: `PolicyFulfillmentSet` "must equal
    // `Canon[PolicyFulfillmentId_j(P, j)]` for every P leg, EACH DERIVED FROM
    // P'S LEG AND STORED". The member computes the expected identities; it does
    // not fetch whatever `F` named and check that back against itself.
    //
    // Fetching by the declared ids would have been CIRCULAR: the derivation
    // rebuilds each body from (pid, E, leg, shadow), so sourcing the shadow
    // from the body `F` named makes the comparison true by construction, and a
    // mutation flipping one shadow byte would stay green. The conjunct §2
    // places at ingress becomes a tautology, and a trader could register an `F`
    // over shadows `E` never committed — turning a 422 into a permanently
    // Invalid position at `q`.
    //
    // `P(E)` breaks the circle: the preimage, not the witness, says which
    // shadow `E` commits. Extra stored witnesses are then irrelevant garbage
    // rather than candidates in an unordered election.
    let canonical = match canonical_legs_for(&state, &precommit).await {
        Ok(legs) => legs,
        Err(resp) => return *resp,
    };
    // P's legs must BE `P(E)`'s legs — §2's "legs = P(E)/Γ", cheap once the
    // preimage is in hand.
    let mut shadows = Vec::with_capacity(precommit.legs().len());
    for leg in precommit.legs() {
        let Some(c) = canonical.iter().find(|c| c.vault_id == leg.vault_id) else {
            return outcome(
                StatusCode::UNPROCESSABLE_ENTITY,
                "precommit-leg-is-not-in-the-preimage",
            );
        };
        if c.parent_root != leg.parent_root || c.setup_ref != leg.setup_ref {
            return outcome(
                StatusCode::UNPROCESSABLE_ENTITY,
                "precommit-leg-disagrees-with-the-preimage",
            );
        }
        shadows.push(c.shadow_core);
    }
    // Every witness the derivation names must be HELD here. A member missing
    // one cannot conclude the set is complete, whatever `F` declares.
    let Ok(derived) = dsm::sofi::conformance::derive_policy_fulfillments(&precommit, &shadows)
    else {
        return outcome(
            StatusCode::UNPROCESSABLE_ENTITY,
            "policy-fulfillment-set-does-not-derive",
        );
    };
    for body in &derived {
        let id = derive::policy_fulfillment_id(body);
        match db::get_sofi_policy_fulfillment(&state.db_pool, &id).await {
            Ok(Some(_)) => {}
            Ok(None) => {
                return outcome(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "policy-fulfillment-not-held",
                )
            }
            Err(_) => return outcome(StatusCode::INTERNAL_SERVER_ERROR, "storage"),
        }
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

/// Ask this member to establish `FulfillmentRegistered(F)` by READING the
/// committed set.
///
/// **It takes no account of who holds what from the caller.** A caller able to
/// assert "three members hold this" could manufacture the exercise fact for a
/// fulfillment nobody registered, and the record is monotone, so it could
/// never be taken back. The member reads; the caller only asks it to look.
///
/// **Today it can only read itself,** so it declines at a quorum of three and
/// reports the count it actually observed. The peer client arrives in E2-5 and
/// supplies the other answers to this same decision; nothing about the rule
/// changes when it does, which is why the rule is here rather than there.
pub async fn post_registration(
    Extension(state): Extension<Arc<AppState>>,
    Path(k_ful_b32): Path<String>,
) -> Response {
    let Some(k_ful) = text_id::decode_base32_crockford(&k_ful_b32).filter(|v| v.len() == 32) else {
        return outcome(StatusCode::BAD_REQUEST, "malformed");
    };
    let Some(set) = state.storage_set.as_ref() else {
        return outcome(StatusCode::SERVICE_UNAVAILABLE, "no-storage-set");
    };
    // This member's own holding, which is ONE answer and not a quorum.
    let held = match db::get_sofi_fulfillment(&state.db_pool, &k_ful).await {
        Ok(Some(envelope)) => envelope,
        Ok(None) => return outcome(StatusCode::NOT_FOUND, "not-held-here"),
        Err(_) => return outcome(StatusCode::INTERNAL_SERVER_ERROR, "storage"),
    };
    let Ok(env) = SignedSofiObject::decode(&held) else {
        return outcome(
            StatusCode::INTERNAL_SERVER_ERROR,
            "held-fulfillment-does-not-decode",
        );
    };
    let Ok(fulfillment) = TraderFulfillmentBody::decode(env.body_ccb()) else {
        return outcome(
            StatusCode::INTERNAL_SERVER_ERROR,
            "held-fulfillment-does-not-decode",
        );
    };
    let fid = derive::fulfillment_id(&fulfillment);

    let mut answers = Vec::new();
    // Identify OURSELVES in the committed set by the incarnation we serve —
    // the same axis the echo rule counts on, and the one this node's database
    // actually holds.
    if let Some((id, inc)) = set
        .members
        .iter()
        .find(|(_, inc)| *inc == set.own_incarnation)
        .cloned()
    {
        answers.push(registration::HolderAnswer {
            asked: dsm_sdk::sdk::storage_set::StorageMember {
                member_id: id.clone(),
                register_incarnation_id: inc,
                endpoint: String::new(),
            },
            echoed: dsm_sdk::sdk::storage_node_sdk::MemberEcho {
                node_id: Some(id),
                register_incarnation: Some(inc),
            },
            holds: Some(fid),
        });
    }

    if !registration::holders_establish_registration(&answers, &fid, registration::HOLDER_QUORUM) {
        let mut resp = outcome(StatusCode::CONFLICT, "holders-below-quorum");
        if let Ok(v) = HeaderValue::from_str(&answers.len().to_string()) {
            resp.headers_mut().insert("x-dsm-holders", v);
        }
        return resp;
    }
    match db::record_fulfillment_registered(&state.db_pool, &fid, answers.len() as i64).await {
        Ok(()) => outcome(StatusCode::OK, "registered"),
        Err(_) => outcome(StatusCode::INTERNAL_SERVER_ERROR, "storage"),
    }
}

/// Whether this member has recorded the exercise fact for the `F` at this
/// position. A member that HOLDS `F` but has not established a quorum answers
/// 404 here — which is the whole distinction.
pub async fn get_registration(
    Extension(state): Extension<Arc<AppState>>,
    Path(k_ful_b32): Path<String>,
) -> Response {
    let Some(k_ful) = text_id::decode_base32_crockford(&k_ful_b32).filter(|v| v.len() == 32) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let Ok(Some(held)) = db::get_sofi_fulfillment(&state.db_pool, &k_ful).await else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let (Ok(env),) = (SignedSofiObject::decode(&held),) else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    let Ok(fulfillment) = TraderFulfillmentBody::decode(env.body_ccb()) else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    let fid = derive::fulfillment_id(&fulfillment);
    match db::is_fulfillment_registered(&state.db_pool, &fid).await {
        Ok(true) => (StatusCode::OK, fid.to_vec()).into_response(),
        Ok(false) => StatusCode::NOT_FOUND.into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

/// Write the successor cell for one leg of a REGISTERED fulfillment.
///
/// **Before `Registered(F)` no successor cell for `E` is admissible anywhere**
/// (F2). That is the gate, and it is the reason a cell cannot be used to
/// bootstrap an exercise that never happened.
///
/// **The member derives the key; the caller never supplies one.** The caller
/// names a fulfillment and a vault, and the key comes from the `P` leg and the
/// attempt that `F` itself fixed — the same discipline as the root register
/// ("the cell, from the body — never from the caller") and the immutable store.
/// A caller able to choose `K^(a)` could park a value at a key no fulfillment
/// authorises.
///
/// Any caller may write: completion is not the trader's privilege, and after
/// registration the trader has no remaining discretion.
pub async fn post_cell(
    Extension(state): Extension<Arc<AppState>>,
    Path((fulfillment_b32, vault_b32)): Path<(String, String)>,
    body: Bytes,
) -> Response {
    let (Some(fid), Some(vault)) = (
        text_id::decode_base32_crockford(&fulfillment_b32).filter(|v| v.len() == 32),
        text_id::decode_base32_crockford(&vault_b32).filter(|v| v.len() == 32),
    ) else {
        return outcome(StatusCode::BAD_REQUEST, "malformed");
    };
    if body.len() != 32 {
        return outcome(StatusCode::BAD_REQUEST, "value-is-not-a-digest");
    }

    // THE GATE, before anything is derived or written.
    match db::is_fulfillment_registered(&state.db_pool, &fid).await {
        Ok(true) => {}
        Ok(false) => return outcome(StatusCode::CONFLICT, "fulfillment-not-registered"),
        Err(_) => return outcome(StatusCode::INTERNAL_SERVER_ERROR, "storage"),
    }
    let Ok(Some(f_envelope)) = db::get_sofi_fulfillment_by_id(&state.db_pool, &fid).await else {
        return outcome(StatusCode::UNPROCESSABLE_ENTITY, "fulfillment-not-held");
    };
    let Ok(f_env) = SignedSofiObject::decode(&f_envelope) else {
        return outcome(
            StatusCode::INTERNAL_SERVER_ERROR,
            "held-fulfillment-does-not-decode",
        );
    };
    let Ok(fulfillment) = TraderFulfillmentBody::decode(f_env.body_ccb()) else {
        return outcome(
            StatusCode::INTERNAL_SERVER_ERROR,
            "held-fulfillment-does-not-decode",
        );
    };
    let Ok(Some(p_envelope)) =
        db::get_sofi_precommit(&state.db_pool, fulfillment.precommit_id()).await
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

    let vault: [u8; 32] = match vault.as_slice().try_into() {
        Ok(v) => v,
        Err(_) => return outcome(StatusCode::BAD_REQUEST, "malformed"),
    };
    let Some(leg) = precommit.legs().iter().find(|l| l.vault_id == vault) else {
        return outcome(StatusCode::UNPROCESSABLE_ENTITY, "vault-is-not-a-leg");
    };
    let Some(entry) = fulfillment.attempts().iter().find(|a| a.vault_id == vault) else {
        return outcome(StatusCode::UNPROCESSABLE_ENTITY, "vault-has-no-attempt");
    };
    // THE PROJECTION IS NOT YET CHECKABLE. F7 requires `a > 0` to carry
    // `SuccessorResolution(K^(a-1))`, and typed resolution records arrive in
    // E2-5. Refused by name rather than admitted unprojected: a later attempt
    // admitted without its predecessor resolved is a cell nobody can order.
    if entry.attempt > 0 {
        return outcome(
            StatusCode::NOT_IMPLEMENTED,
            "later-attempts-need-the-resolution-records",
        );
    }

    // The value is EXACTLY E, which `P` commits. A cell holding anything else
    // is not this operation's successor.
    if body.as_ref() != precommit.external_commitment().as_slice() {
        return outcome(
            StatusCode::UNPROCESSABLE_ENTITY,
            "value-is-not-this-operations-e",
        );
    }

    let k_cell = derive::successor_attempt_key(&leg.vault_id, &leg.parent_root, entry.attempt);
    match db::put_sofi_successor_cell(&state.db_pool, &k_cell, &fid, &body).await {
        Ok(db::SuccessorCellPutOutcome::Stored) => outcome(StatusCode::OK, "stored"),
        Ok(db::SuccessorCellPutOutcome::AlreadyHeld) => outcome(StatusCode::OK, "already-held"),
        // CONTENTION, NOT SUCCESS. Another operation reached this leg first
        // and the cell holds its `E`, not the one just posted. Answering 200
        // here told the loser its value was present, which is the opposite of
        // what happened — and SoFi is deliberately non-locking, so two traders
        // racing one DLV parent is expected rather than exceptional.
        Ok(db::SuccessorCellPutOutcome::Contested { held_e }) => {
            let mut resp = outcome(StatusCode::CONFLICT, "cell-taken");
            if let Ok(v) = HeaderValue::from_str(&text_id::encode_base32_crockford(&held_e)) {
                resp.headers_mut().insert("x-dsm-held-e", v);
            }
            resp
        }
        Err(_) => outcome(StatusCode::INTERNAL_SERVER_ERROR, "storage"),
    }
}

pub async fn get_cell(
    Extension(state): Extension<Arc<AppState>>,
    Path(k_cell_b32): Path<String>,
) -> Response {
    let Some(k) = text_id::decode_base32_crockford(&k_cell_b32).filter(|v| v.len() == 32) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    match db::get_sofi_successor_cell(&state.db_pool, &k).await {
        Ok(found) => serve(found).await,
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

/// Store `P(E)`, the settlement preimage, at the `E` it RECOMPUTES to.
///
/// **The key is derived, never supplied.** The node decodes the preimage and
/// recomputes `E` from it; a caller cannot name the address, so it cannot park
/// a preimage under someone else's commitment.
///
/// This object is the AUTHORITY for `c°_{V,j}`. Without it a member cannot
/// know which shadow `E` commits, and the checks below degrade to "some
/// witness claims this leg" — which is exactly how a same-coordinate decoy
/// became storable and F ingress became an unordered election over an
/// attacker-populated set.
pub async fn post_preimage(Extension(state): Extension<Arc<AppState>>, body: Bytes) -> Response {
    if body.is_empty() || body.len() > MAX_SOFI_OBJECT_BYTES {
        return outcome(StatusCode::BAD_REQUEST, "malformed");
    }
    let Ok(preimage) = SettlementPreimage::decode(&body) else {
        return outcome(StatusCode::BAD_REQUEST, "malformed");
    };
    // Canonical or nothing: the address is over these bytes.
    let Ok(reencoded) = preimage.encode() else {
        return outcome(StatusCode::BAD_REQUEST, "malformed");
    };
    if reencoded != body {
        return outcome(StatusCode::BAD_REQUEST, "not-canonical");
    }
    let Ok(e) = derive::recompute_e(&preimage) else {
        return outcome(
            StatusCode::UNPROCESSABLE_ENTITY,
            "preimage-does-not-recompute",
        );
    };
    match db::put_sofi_settlement_preimage(&state.db_pool, &e, &body).await {
        Ok(db::ObjectPutOutcome::Stored) => outcome(StatusCode::OK, "stored"),
        Ok(db::ObjectPutOutcome::AlreadyHeld) => outcome(StatusCode::OK, "already-held"),
        Err(_) => outcome(StatusCode::INTERNAL_SERVER_ERROR, "storage"),
    }
}

pub async fn get_preimage(
    Extension(state): Extension<Arc<AppState>>,
    Path(e_b32): Path<String>,
) -> Response {
    let Some(e) = text_id::decode_base32_crockford(&e_b32).filter(|v| v.len() == 32) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    match db::get_sofi_settlement_preimage(&state.db_pool, &e).await {
        Ok(found) => serve(found).await,
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

/// The canonical legs `P(E)` implies for this pre-commit, or a named refusal.
///
/// One helper, used by BOTH G ingress and F ingress, so the two cannot drift
/// about which shadow is canonical.
async fn canonical_legs_for(
    state: &AppState,
    precommit: &TraderPrecommitBody,
) -> Result<Vec<dsm::sofi::wire::RouteLegEntry>, Box<Response>> {
    let refuse = |code: StatusCode, reason: &str| Box::new(outcome(code, reason));
    let held =
        match db::get_sofi_settlement_preimage(&state.db_pool, precommit.external_commitment())
            .await
        {
            Ok(Some(bytes)) => bytes,
            Ok(None) => {
                return Err(refuse(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "settlement-preimage-not-held",
                ))
            }
            Err(_) => return Err(refuse(StatusCode::INTERNAL_SERVER_ERROR, "storage")),
        };
    let Ok(preimage) = SettlementPreimage::decode(&held) else {
        return Err(refuse(
            StatusCode::INTERNAL_SERVER_ERROR,
            "held-preimage-does-not-decode",
        ));
    };
    derive::canonical_legs(&preimage).map_err(|_| {
        refuse(
            StatusCode::INTERNAL_SERVER_ERROR,
            "held-preimage-has-no-canonical-legs",
        )
    })
}
