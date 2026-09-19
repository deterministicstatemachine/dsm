// SPDX-License-Identifier: MIT OR Apache-2.0
//! `F` registration against the REAL node routers: conformance, the atomic
//! pair, and the rollback that makes it atomic.
//!
//! Registration is THE EXERCISE BOUNDARY, and it establishes two facts at
//! once: `K_ful(q) = F` and `C_q` at `K_root(q)`. They are written in ONE
//! durable transaction, and the test that matters is the one proving the
//! first does not survive when the second cannot happen.

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
    let mut set: Vec<[u8; 32]> = derive_policy_fulfillments(p, &[SHADOW])
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

/// Seed a node with a bound `P` and its witness, ready for `F`.
async fn ready(n: &Node) -> (TraderPrecommitBody, Vec<u8>, Vec<u8>) {
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
    (p, pk, sk)
}

/// Registration establishes BOTH facts. Neither exists before it and both
/// exist after.
#[tokio::test]
async fn registration_installs_the_fulfillment_and_its_conditional_claim() {
    let n = node().await;
    let (p, pk, sk) = ready(&n).await;
    let f = fulfillment_for(&p, &pk, 0);

    let k_ful = derive::fulfillment_register_key(&G, &DEV, POS + 1);
    let k_root = economic_root_register_key(&G, &DEV, POS + 1);
    assert!(db::get_sofi_fulfillment(&n.pool, &k_ful)
        .await
        .expect("read")
        .is_none());
    assert!(db::get_economic_root_claim(&n.pool, &k_root)
        .await
        .expect("read")
        .is_none());

    let (status, reason) = post(&n, "/api/v2/sofi/fulfillment", f_envelope(&f, &sk)).await;
    assert_eq!((status, reason.as_str()), (200, "registered"));

    assert!(db::get_sofi_fulfillment(&n.pool, &k_ful)
        .await
        .expect("read")
        .is_some());
    let (cell, digest) = db::get_economic_root_claim(&n.pool, &k_root)
        .await
        .expect("read")
        .expect("C_q is installed");
    // The cell holds the DERIVED C_q, and is identified by the fulfillment
    // that installed it.
    assert_eq!(cell, derive::resolution_claim(&p, &f).encode());
    assert_eq!(digest, derive::fulfillment_id(&f).to_vec());
}

/// THE ATOMICITY PROOF. When the successor's root cell is already taken by
/// something that is not this `C_q`, registration refuses — and the
/// fulfillment row does NOT survive. A crash between two sequential writes
/// would leave exactly this shape: an `F` registered whose `C_q` never
/// arrived, so every descendant fence reads an empty cell for a position that
/// IS exercised.
#[tokio::test]
async fn a_taken_root_cell_rolls_the_fulfillment_back() {
    let n = node().await;
    let (p, pk, sk) = ready(&n).await;

    // Someone else already holds q's root cell.
    let k_root = economic_root_register_key(&G, &DEV, POS + 1);
    db::claim_economic_root(
        &n.pool,
        &k_root,
        b"a foreign cell",
        &[0xFE; 32],
        &[0xAA; 64],
        &n.set_id,
    )
    .await
    .expect("seed the contested cell");

    let f = fulfillment_for(&p, &pk, 0);
    let (status, reason) = post(&n, "/api/v2/sofi/fulfillment", f_envelope(&f, &sk)).await;
    assert_eq!((status, reason.as_str()), (409, "root-cell-taken"));

    let k_ful = derive::fulfillment_register_key(&G, &DEV, POS + 1);
    assert!(
        db::get_sofi_fulfillment(&n.pool, &k_ful)
            .await
            .expect("read")
            .is_none(),
        "the fulfillment must not survive a refused C_q: F-without-C_q is unrecoverable"
    );
}

/// Re-registering the same `F` acks. Registration is write-once, and a
/// relayer that repeats it has changed nothing.
#[tokio::test]
async fn re_registering_the_same_fulfillment_acks() {
    let n = node().await;
    let (p, pk, sk) = ready(&n).await;
    let f = fulfillment_for(&p, &pk, 0);
    assert_eq!(
        post(&n, "/api/v2/sofi/fulfillment", f_envelope(&f, &sk))
            .await
            .1,
        "registered"
    );
    assert_eq!(
        post(&n, "/api/v2/sofi/fulfillment", f_envelope(&f, &sk))
            .await
            .1,
        "already-registered"
    );
}

/// AT MOST ONE REGISTERED `F` PER POSITION. A second, different fulfillment
/// of the same `P` is refused, and the first one's cell is untouched.
#[tokio::test]
async fn a_second_fulfillment_at_one_position_is_refused() {
    let n = node().await;
    let (p, pk, sk) = ready(&n).await;
    let first = fulfillment_for(&p, &pk, 0);
    assert_eq!(
        post(&n, "/api/v2/sofi/fulfillment", f_envelope(&first, &sk))
            .await
            .1,
        "registered"
    );
    // Same P, a different attempt vector: a different F at the same q.
    let second = fulfillment_for(&p, &pk, 1);
    assert_ne!(
        derive::fulfillment_id(&second),
        derive::fulfillment_id(&first)
    );
    let (status, reason) = post(&n, "/api/v2/sofi/fulfillment", f_envelope(&second, &sk)).await;
    assert_eq!((status, reason.as_str()), (409, "position-taken"));

    let k_root = economic_root_register_key(&G, &DEV, POS + 1);
    let (_, digest) = db::get_economic_root_claim(&n.pool, &k_root)
        .await
        .expect("read")
        .expect("held");
    assert_eq!(
        digest,
        derive::fulfillment_id(&first).to_vec(),
        "the winner's C_q stands"
    );
}

/// A member that does not hold every witness cannot conclude the set is
/// complete, and says so instead of trusting the list `F` carries.
#[tokio::test]
async fn a_fulfillment_without_the_stored_witnesses_is_refused() {
    let n = node().await;
    let (claim_ref, pk, sk) = seed_parent_claim(&n).await;
    let p = precommit(claim_ref, n.set_id, &pk);
    assert_eq!(
        post(&n, "/api/v2/sofi/precommit", envelope_for(&p, &sk))
            .await
            .0,
        200
    );
    // No witness stored.
    let f = fulfillment_for(&p, &pk, 0);
    let (status, reason) = post(&n, "/api/v2/sofi/fulfillment", f_envelope(&f, &sk)).await;
    assert_eq!(
        (status, reason.as_str()),
        (422, "policy-fulfillment-not-held")
    );
}

/// A fulfillment of a pre-commit this member has never seen is not something
/// it can find conforming.
#[tokio::test]
async fn a_fulfillment_without_its_precommit_is_refused() {
    let n = node().await;
    let (claim_ref, pk, sk) = seed_parent_claim(&n).await;
    let p = precommit(claim_ref, n.set_id, &pk);
    let f = fulfillment_for(&p, &pk, 0);
    let (status, reason) = post(&n, "/api/v2/sofi/fulfillment", f_envelope(&f, &sk)).await;
    assert_eq!((status, reason.as_str()), (422, "precommit-not-held"));
}

/// `F` is signed by the key `P` committed, and by nothing else.
#[tokio::test]
async fn a_fulfillment_signed_by_another_key_is_refused() {
    let n = node().await;
    let (p, pk, _sk) = ready(&n).await;
    let (_other_pk, other_sk) = generate_sphincs_keypair().expect("keys");
    let f = fulfillment_for(&p, &pk, 0);
    let (status, _reason) = post(&n, "/api/v2/sofi/fulfillment", f_envelope(&f, &other_sk)).await;
    assert_eq!(status, 403);
}
