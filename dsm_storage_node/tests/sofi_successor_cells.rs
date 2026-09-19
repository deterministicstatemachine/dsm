// SPDX-License-Identifier: MIT OR Apache-2.0
//! Successor cells against the REAL node routers: the registration gate,
//! and the key the MEMBER derives rather than the one a caller names.
//!
//! "Before F registration no successor cell for E is admissible anywhere"
//! (F2). A cell admitted earlier would let a fulfillment that was never
//! exercised leave evidence that it was.

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
use dsm_storage_node::replication::{ReplicationConfig, ReplicationManager};
use dsm_storage_node::{db, AppState, NodeStorageSet};

const G: [u8; 32] = [0x11; 32];
const DEV: [u8; 32] = [0x22; 32];
const POS: u64 = 5;
const VAULT: [u8; 32] = [0xC1; 32];
const PARENT_ROOT: [u8; 32] = [0x62; 32];
const E: [u8; 32] = [0x0E; 32];
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

/// Seed the parent claim the key binding reads, and return (envelope digest,
/// the keypair it proves).
async fn seed_parent_claim(node: &Node) -> ([u8; 32], Vec<u8>, Vec<u8>) {
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
        E,
        vec![PrecommitLeg {
            vault_id: VAULT,
            parent_root: PARENT_ROOT,
            setup_ref: [0x55; 32],
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

const SHADOW: [u8; 32] = [0x9A; 32];

fn witness_for(p: &TraderPrecommitBody) -> DlvPolicyFulfillmentBody {
    DlvPolicyFulfillmentBody {
        precommit_id: derive::precommit_id(p),
        external_commitment: E,
        vault_id: VAULT,
        parent_root: PARENT_ROOT,
        shadow_core: SHADOW,
    }
}

fn fulfillment_for(p: &TraderPrecommitBody, pk: &[u8], attempt: u64) -> TraderFulfillmentBody {
    let mut set: Vec<[u8; 32]> = dsm::sofi::conformance::derive_policy_fulfillments(p, &[SHADOW])
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
            attempt,
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

fn b32(v: &[u8]) -> String {
    dsm_sdk::util::text_id::encode_base32_crockford(v)
}

/// Accept P, its witness and F, and return `(fulfillment_id, cell path)`.
async fn accepted(n: &Node, attempt: u64) -> ([u8; 32], String) {
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
    let f = fulfillment_for(&p, &pk, attempt);
    assert_eq!(
        post(n, "/api/v2/sofi/fulfillment", f_envelope(&f, &sk))
            .await
            .1,
        "registered"
    );
    let fid = derive::fulfillment_id(&f);
    let path = format!("/api/v2/sofi/cell/{}/{}", b32(&fid), b32(&VAULT));
    (fid, path)
}

/// Stand in for the quorum E2-5 will observe.
async fn record_the_exercise_fact(n: &Node, fid: &[u8; 32]) {
    db::record_fulfillment_registered(&n.pool, fid, 3)
        .await
        .expect("record");
}

/// THE GATE. The member holds `F` and has installed `C_q`, and a cell is
/// still not admissible, because the exercise fact has not been established.
#[tokio::test]
async fn a_cell_before_registration_is_refused() {
    let n = node().await;
    let (_fid, path) = accepted(&n, 0).await;
    let (status, reason) = post(&n, &path, E.to_vec()).await;
    assert_eq!(
        (status, reason.as_str()),
        (409, "fulfillment-not-registered")
    );

    let k_cell = derive::successor_attempt_key(&VAULT, &PARENT_ROOT, 0);
    assert!(
        db::get_sofi_successor_cell(&n.pool, &k_cell)
            .await
            .expect("read")
            .is_none(),
        "a refused cell writes nothing"
    );
}

/// Once registered, the cell is admissible — and it lands at the key the
/// MEMBER derived from the leg and the attempt, holding exactly `E`.
#[tokio::test]
async fn a_registered_fulfillment_admits_its_cell_at_the_derived_key() {
    let n = node().await;
    let (fid, path) = accepted(&n, 0).await;
    record_the_exercise_fact(&n, &fid).await;

    let (status, reason) = post(&n, &path, E.to_vec()).await;
    assert_eq!((status, reason.as_str()), (200, "stored"));

    let k_cell = derive::successor_attempt_key(&VAULT, &PARENT_ROOT, 0);
    assert_eq!(
        db::get_sofi_successor_cell(&n.pool, &k_cell)
            .await
            .expect("read")
            .expect("held"),
        E.to_vec(),
        "the cell holds exactly E"
    );
    // Write-once, and an identical rewrite acks.
    assert_eq!(post(&n, &path, E.to_vec()).await.1, "already-held");
}

/// THE VALUE IS EXACTLY `E`. A cell holding anything else is not this
/// operation's successor, however well-formed it looks.
#[tokio::test]
async fn a_cell_value_that_is_not_e_is_refused() {
    let n = node().await;
    let (fid, path) = accepted(&n, 0).await;
    record_the_exercise_fact(&n, &fid).await;
    let (status, reason) = post(&n, &path, vec![0xAB; 32]).await;
    assert_eq!(
        (status, reason.as_str()),
        (422, "value-is-not-this-operations-e")
    );
}

/// A vault that is not a leg of this fulfillment's pre-commit has no cell
/// here, so there is no key to derive.
#[tokio::test]
async fn a_vault_that_is_not_a_leg_has_no_cell() {
    let n = node().await;
    let (fid, _path) = accepted(&n, 0).await;
    record_the_exercise_fact(&n, &fid).await;
    let path = format!("/api/v2/sofi/cell/{}/{}", b32(&fid), b32(&[0xDD; 32]));
    let (status, reason) = post(&n, &path, E.to_vec()).await;
    assert_eq!((status, reason.as_str()), (422, "vault-is-not-a-leg"));
}

/// A LATER ATTEMPT IS REFUSED BY NAME, not admitted unprojected. F7 requires
/// `a > 0` to carry `SuccessorResolution(K^(a-1))`, and typed resolution
/// records arrive in E2-5.
#[tokio::test]
async fn a_later_attempt_waits_for_the_resolution_records() {
    let n = node().await;
    let (fid, path) = accepted(&n, 1).await;
    record_the_exercise_fact(&n, &fid).await;
    let (status, reason) = post(&n, &path, E.to_vec()).await;
    assert_eq!(
        (status, reason.as_str()),
        (501, "later-attempts-need-the-resolution-records")
    );
}

/// A fulfillment this member does not hold cannot have a cell, even if some
/// registration record were present for its id.
#[tokio::test]
async fn a_cell_for_an_unheld_fulfillment_is_refused() {
    let n = node().await;
    let stranger = [0xAB; 32];
    record_the_exercise_fact(&n, &stranger).await;
    let path = format!("/api/v2/sofi/cell/{}/{}", b32(&stranger), b32(&VAULT));
    let (status, reason) = post(&n, &path, E.to_vec()).await;
    assert_eq!((status, reason.as_str()), (422, "fulfillment-not-held"));
}
