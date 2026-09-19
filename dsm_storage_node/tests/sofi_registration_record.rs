// SPDX-License-Identifier: MIT OR Apache-2.0
//! `FulfillmentRegistered(F)` against the REAL node routers: the exercise
//! fact, and the distinction it draws from merely holding `F`.
//!
//! A member that accepted `F` holds it. The exercise fact is the SYSTEM
//! statement that a quorum of the committed set holds it, and until a member
//! has READ that quorum it must not record it — publication to one member is
//! not exercise (R11-4).

#![cfg(feature = "local-dev")]
#![allow(clippy::disallowed_methods)]

use std::sync::Arc;

use axum::body::Body;
use axum::http::Request;
use tower::ServiceExt;

use dsm::ccb::{class, sigalg};
use dsm::crypto::sphincs::{generate_sphincs_keypair, sphincs_sign};
use dsm::economic::claim::EconomicRootClaimBody;
use dsm::economic::claim_envelope::{
    economic_root_claim_envelope_digest, sign_economic_root_claim,
};
use dsm::economic::register::economic_root_register_key;
use dsm::sofi::conformance::derive_policy_fulfillments;
use dsm::sofi::derive;
use dsm::sofi::wire::{
    AttemptEntry, DlvPolicyFulfillmentBody, ParentClaimRef, PrecommitLeg, SignedSofiObject,
    TraderFulfillmentBody, TraderPrecommitBody,
};
use dsm::sofi::wire::{
    CoreEntry, DlvCore, PreEClosureIndex, SettlementBody, SettlementPreimage, SwapHop, TraderCore,
};
use dsm_storage_node::replication::{ReplicationConfig, ReplicationManager};
use dsm_storage_node::{db, AppState, NodeStorageSet};

const G: [u8; 32] = [0x11; 32];
const DEV: [u8; 32] = [0x22; 32];
const POS: u64 = 5;
const VAULT: [u8; 32] = [0xC1; 32];
const PARENT_ROOT: [u8; 32] = [0x62; 32];
const SETUP_REF: [u8; 32] = [0x55; 32];

const MEMBER: &str = "dsm-node-1";

fn member_incarnation(id: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    let b = id.as_bytes();
    out[..b.len().min(32)].copy_from_slice(&b[..b.len().min(32)]);
    out
}

struct Node {
    router: axum::Router,
    pool: Arc<db::DBPool>,
    set_id: [u8; 32],
}

async fn node() -> Node {
    let pool = Arc::new(db::create_pool(":memory:", true).expect("pool"));
    db::init_db(&pool).await.expect("init db");
    let rm = Arc::new(
        ReplicationManager::new_for_tests(
            ReplicationConfig {
                replication_factor: 3,
                gossip_interval_ticks: 100,
                failure_timeout_ticks: 300,
                gossip_fanout: 3,
                max_concurrent_jobs: 10,
            },
            MEMBER.to_string(),
            "http://dsm-node-1.local:8080".to_string(),
        )
        .expect("replication manager"),
    );
    let state = AppState::new(
        MEMBER.to_string(),
        "http://dsm-node-1.local:8080",
        None,
        pool.clone(),
        rm,
    )
    .with_storage_set(
        NodeStorageSet::new(
            vec![(MEMBER.to_string(), member_incarnation(MEMBER))],
            MEMBER,
            member_incarnation(MEMBER),
        )
        .expect("node set"),
    );
    let set_id = state.storage_set.as_ref().expect("set").id;
    let state = Arc::new(state);
    let router = dsm_storage_node::api::sofi::create_write_router(state.clone())
        .merge(dsm_storage_node::api::sofi::create_read_router(state));
    Node {
        router,
        pool,
        set_id,
    }
}

async fn post(node: &Node, path: &str, body: Vec<u8>) -> (u16, String) {
    let req = Request::builder()
        .method("POST")
        .uri(path)
        .body(Body::from(body))
        .expect("request");
    let resp = node.router.clone().oneshot(req).await.expect("answers");
    let status = resp.status().as_u16();
    let reason = resp
        .headers()
        .get("x-dsm-outcome")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    (status, reason)
}

// ── `P(E)`, the authority for every shadow ──────────────────────────────────
//
// These fixtures no longer invent `E` or a shadow. A real settlement preimage
// is built, `E` is recomputed from it, and the leg — parent root, setup ref
// and shadow — is whatever `canonical_legs` says it is. That is the same
// derivation the member now checks against, so a fixture cannot assert a leg
// the protocol would not produce.

fn preimage_for(trader_salt: u8) -> SettlementPreimage {
    let core = DlvCore::new(
        VAULT,
        [0x62; 32],
        G,
        DEV,
        [0x63; 32],
        vec![CoreEntry::Mutation {
            key: [0x71; 32],
            pre: [0x41; 32],
            post: [0x42; 32],
            path: (0..256u32).map(|i| [(i % 251) as u8; 32]).collect(),
        }],
    )
    .expect("a well-formed dlv core");
    let swap = SettlementBody::Swap {
        token_in: [0x51; 32],
        amount_in: 100,
        token_out: [0x52; 32],
        exact_out: 90,
        hops: vec![SwapHop {
            vault_id: VAULT,
            parent_root: PARENT_ROOT,
            setup_ref: SETUP_REF,
            token_in: [0x51; 32],
            amount_in: 100,
            token_out: [0x52; 32],
            amount_out: 90,
        }],
        trader_core: [0xD1; 32],
        dlv_cores: vec![VAULT],
        closure: PreEClosureIndex::new(Vec::new()).expect("empty closure"),
    };
    let trader = TraderCore::new(
        G,
        DEV,
        9,
        [trader_salt; 32],
        vec![CoreEntry::Mutation {
            key: [0x71; 32],
            pre: [0x41; 32],
            post: [0x42; 32],
            path: (0..256u32).map(|i| [(i % 251) as u8; 32]).collect(),
        }],
    )
    .expect("a well-formed trader core");
    SettlementPreimage::new(swap, trader, vec![core]).expect("a well-formed preimage")
}

fn preimage() -> SettlementPreimage {
    preimage_for(0x61)
}

/// `E`, recomputed from the preimage — never a constant.
fn external_commitment_of(p: &SettlementPreimage) -> [u8; 32] {
    derive::recompute_e(p).expect("E recomputes")
}

fn external_commitment() -> [u8; 32] {
    external_commitment_of(&preimage())
}

/// The one canonical leg `P(E)` implies, shadow included.
fn canonical_leg_of(p: &SettlementPreimage) -> dsm::sofi::wire::RouteLegEntry {
    derive::canonical_legs(p).expect("canonical legs")[0]
}

fn canonical_leg() -> dsm::sofi::wire::RouteLegEntry {
    canonical_leg_of(&preimage())
}

/// Store `P(E)` on this member. Every later ingress needs it.
async fn seed_preimage_of(n: &Node, p: &SettlementPreimage) {
    let bytes = p.encode().expect("encode preimage");
    assert_eq!(
        post(n, "/api/v2/sofi/preimage", bytes).await,
        (200, "stored".to_string()),
        "the preimage must store before anything can bind to it"
    );
}

async fn seed_preimage(n: &Node) {
    seed_preimage_of(n, &preimage()).await
}

/// Seed the parent claim the key binding reads, and return (envelope digest,
/// the keypair it proves).
async fn seed_parent_claim(node: &Node) -> ([u8; 32], Vec<u8>, Vec<u8>) {
    seed_preimage(node).await;
    let (pk, sk) = generate_sphincs_keypair().expect("keys");
    let body = EconomicRootClaimBody {
        trader_genesis: G,
        trader_devid: DEV,
        economic_position: POS,
        post_economic_root: [0x77; 32],
        admission_manifest_addr: [0x78; 32],
        root_register_storage_set_id: node.set_id,
        signature_alg: sigalg::SPHINCS_PLUS_SPX256F,
        claimant_public_key: pk.clone(),
    };
    let envelope = sign_economic_root_claim(&body, &sk).expect("sign claim");
    let digest = economic_root_claim_envelope_digest(&envelope);
    let k_root = economic_root_register_key(&G, &DEV, POS);
    db::claim_economic_root(&node.pool, &k_root, &envelope, &digest, &pk, &node.set_id)
        .await
        .expect("seed the parent cell");
    (digest, pk, sk)
}

fn precommit(claim_ref: [u8; 32], set_id: [u8; 32], pk: &[u8]) -> TraderPrecommitBody {
    TraderPrecommitBody::new(
        G,
        DEV,
        POS,
        ParentClaimRef::SingleRoot { claim_ref },
        external_commitment(),
        vec![PrecommitLeg {
            vault_id: canonical_leg().vault_id,
            parent_root: canonical_leg().parent_root,
            setup_ref: canonical_leg().setup_ref,
        }],
        [0xA1; 32],
        [0x61; 32],
        set_id,
        sigalg::SPHINCS_PLUS_SPX256F,
        pk,
    )
    .expect("a well-formed precommit")
}

fn envelope_for(body: &TraderPrecommitBody, sk: &[u8]) -> Vec<u8> {
    let sig = sphincs_sign(sk, &derive::precommit_signing_digest(body)).expect("sign");
    SignedSofiObject::new(
        class::SOFI_TRADER_PRECOMMIT_BODY,
        &body.encode(),
        sigalg::SPHINCS_PLUS_SPX256F,
        &sig,
    )
    .expect("envelope")
    .encode()
}

fn witness_for(p: &TraderPrecommitBody) -> DlvPolicyFulfillmentBody {
    DlvPolicyFulfillmentBody {
        precommit_id: derive::precommit_id(p),
        external_commitment: external_commitment(),
        vault_id: VAULT,
        parent_root: canonical_leg().parent_root,
        shadow_core: canonical_leg().shadow_core,
    }
}

fn fulfillment_for(p: &TraderPrecommitBody, pk: &[u8]) -> TraderFulfillmentBody {
    let mut set: Vec<[u8; 32]> =
        dsm::sofi::conformance::derive_policy_fulfillments(p, &[canonical_leg().shadow_core])
            .expect("canonical set")
            .iter()
            .map(derive::policy_fulfillment_id)
            .collect();
    set.sort();
    TraderFulfillmentBody::new(
        derive::precommit_id(p),
        set,
        vec![AttemptEntry {
            vault_id: VAULT,
            attempt: 0,
        }],
        POS + 1,
        sigalg::SPHINCS_PLUS_SPX256F,
        pk,
    )
    .expect("a well-formed fulfillment")
}

fn f_envelope(f: &TraderFulfillmentBody, sk: &[u8]) -> Vec<u8> {
    let sig = sphincs_sign(sk, &derive::fulfillment_signing_digest(f)).expect("sign");
    SignedSofiObject::new(
        class::SOFI_TRADER_FULFILLMENT_BODY,
        &f.encode(),
        sigalg::SPHINCS_PLUS_SPX256F,
        &sig,
    )
    .expect("envelope")
    .encode()
}

async fn get(n: &Node, path: &str) -> u16 {
    let req = Request::builder()
        .method("GET")
        .uri(path)
        .body(Body::empty())
        .expect("request");
    n.router
        .clone()
        .oneshot(req)
        .await
        .expect("answers")
        .status()
        .as_u16()
}

/// Register `F` on this member and return the registration path for it.
async fn registered_here(n: &Node) -> String {
    let (claim_ref, pk, sk) = seed_parent_claim(n).await;
    let p = precommit(claim_ref, n.set_id, &pk);
    assert_eq!(
        post(n, "/api/v2/sofi/precommit", envelope_for(&p, &sk))
            .await
            .0,
        200
    );
    assert_eq!(
        post(
            n,
            "/api/v2/sofi/policy-fulfillment",
            witness_for(&p).encode()
        )
        .await
        .0,
        200
    );
    let f = fulfillment_for(&p, &pk);
    assert_eq!(
        post(n, "/api/v2/sofi/fulfillment", f_envelope(&f, &sk))
            .await
            .1,
        "registered"
    );
    let k_ful = derive::fulfillment_register_key(&G, &DEV, POS + 1);
    format!(
        "/api/v2/sofi/fulfillment/{}/registration",
        dsm_sdk::util::text_id::encode_base32_crockford(&k_ful)
    )
}

/// THE DISTINCTION THIS PHASE EXISTS TO DRAW. This member holds `F` — it
/// accepted it and installed `C_q` — and the exercise fact is still absent,
/// because one holder is not a quorum.
#[tokio::test]
async fn holding_a_fulfillment_is_not_the_exercise_fact() {
    let n = node().await;
    let path = registered_here(&n).await;

    // Held: yes. Registered: no.
    let k_ful = derive::fulfillment_register_key(&G, &DEV, POS + 1);
    assert!(
        db::get_sofi_fulfillment(&n.pool, &k_ful)
            .await
            .expect("read")
            .is_some(),
        "the member holds F"
    );
    assert_eq!(
        get(&n, &path).await,
        404,
        "and has NOT recorded the exercise fact"
    );
}

/// Asking the member to establish it does not manufacture it: with only its
/// own answer available it declines, and reports the count it actually
/// observed rather than the one it needs.
#[tokio::test]
async fn one_holder_declines_and_reports_what_it_saw() {
    let n = node().await;
    let path = registered_here(&n).await;
    let (status, reason) = post(&n, &path, Vec::new()).await;
    assert_eq!((status, reason.as_str()), (409, "holders-below-quorum"));
    assert_eq!(get(&n, &path).await, 404, "declining writes nothing");
}

/// A position this member does not hold has nothing to establish.
#[tokio::test]
async fn a_position_this_member_does_not_hold_has_no_registration() {
    let n = node().await;
    let k_ful = derive::fulfillment_register_key(&G, &DEV, 99);
    let path = format!(
        "/api/v2/sofi/fulfillment/{}/registration",
        dsm_sdk::util::text_id::encode_base32_crockford(&k_ful)
    );
    let (status, reason) = post(&n, &path, Vec::new()).await;
    assert_eq!((status, reason.as_str()), (404, "not-held-here"));
    assert_eq!(get(&n, &path).await, 404);
}

/// THE RECORD IS MONOTONE. Once written it stands, and a later observation —
/// even a smaller one — does not revise or remove it.
#[tokio::test]
async fn the_record_is_monotone_once_written() {
    let n = node().await;
    let path = registered_here(&n).await;
    let k_ful = derive::fulfillment_register_key(&G, &DEV, POS + 1);
    let held = db::get_sofi_fulfillment(&n.pool, &k_ful)
        .await
        .expect("read")
        .expect("held");
    let f = TraderFulfillmentBody::decode(
        SignedSofiObject::decode(&held)
            .expect("envelope")
            .body_ccb(),
    )
    .expect("body");
    let fid = derive::fulfillment_id(&f);

    // Written directly, standing in for the quorum E2-5 will observe.
    db::record_fulfillment_registered(&n.pool, &fid, 3)
        .await
        .expect("record");
    assert_eq!(get(&n, &path).await, 200);

    // A later, smaller observation changes nothing.
    db::record_fulfillment_registered(&n.pool, &fid, 1)
        .await
        .expect("record again");
    assert!(
        db::is_fulfillment_registered(&n.pool, &fid)
            .await
            .expect("read"),
        "the exercise fact is never withdrawn"
    );
    assert_eq!(get(&n, &path).await, 200);
}
