// SPDX-License-Identifier: MIT OR Apache-2.0
//! `P` and `G` against the REAL node routers: ingress, binding, idempotence.
//!
//! Driven in-process over an in-memory SQLite pool, through the same router
//! functions the binary serves. Every acceptance and every refusal below is
//! the member's own decision, not a double's.

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
use dsm::sofi::derive;
use dsm::sofi::wire::{
    DlvPolicyFulfillmentBody, ParentClaimRef, PrecommitLeg, SignedSofiObject, TraderPrecommitBody,
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

/// A signed `P` bound to the parent claim is stored, served back byte for
/// byte, and a SECOND valid envelope over the same body acks instead of
/// conflicting — the address is the body's, so an honest relayer never races
/// the trader.
#[tokio::test]
async fn a_bound_precommit_is_stored_and_republishing_it_acks() {
    let n = node().await;
    let (claim_ref, pk, sk) = seed_parent_claim(&n).await;
    let body = precommit(claim_ref, n.set_id, &pk);

    let (status, reason) = post(&n, "/api/v2/sofi/precommit", envelope_for(&body, &sk)).await;
    assert_eq!((status, reason.as_str()), (200, "stored"));

    // A different valid signature over the SAME body.
    let (status, reason) = post(&n, "/api/v2/sofi/precommit", envelope_for(&body, &sk)).await;
    assert_eq!((status, reason.as_str()), (200, "already-held"));

    let id = derive::precommit_id(&body);
    let served = db::get_sofi_precommit(&n.pool, &id)
        .await
        .expect("read")
        .expect("held");
    assert_eq!(
        SignedSofiObject::decode(&served)
            .expect("decodes")
            .body_ccb(),
        body.encode(),
        "what is served carries the same canonical body"
    );
}

/// THE KEY BINDING. A `P` whose own signature is perfectly valid is still
/// refused when the parent claim proves a different key: `P` is authorized by
/// the identity that holds the position, not by whoever can sign.
#[tokio::test]
async fn a_precommit_signed_by_another_key_is_refused() {
    let n = node().await;
    let (claim_ref, _pk, _sk) = seed_parent_claim(&n).await;
    let (other_pk, other_sk) = generate_sphincs_keypair().expect("keys");
    let body = precommit(claim_ref, n.set_id, &other_pk);
    let (status, _reason) =
        post(&n, "/api/v2/sofi/precommit", envelope_for(&body, &other_sk)).await;
    assert_eq!(status, 403, "a valid signature by the wrong identity");
}

/// A `P` naming a parent claim this member does not hold is refused: the key
/// binding has nothing to read, and accepting unbound is exactly what the
/// two-part attribution elsewhere exists to prevent.
#[tokio::test]
async fn a_precommit_without_its_parent_claim_is_refused() {
    let n = node().await;
    let (pk, sk) = generate_sphincs_keypair().expect("keys");
    let body = precommit([0xAB; 32], n.set_id, &pk);
    let (status, reason) = post(&n, "/api/v2/sofi/precommit", envelope_for(&body, &sk)).await;
    assert_eq!((status, reason.as_str()), (422, "parent-claim-not-held"));
}

/// A foreign storage set is refused before anything else is considered.
#[tokio::test]
async fn a_precommit_for_a_foreign_set_is_refused() {
    let n = node().await;
    let (claim_ref, pk, sk) = seed_parent_claim(&n).await;
    let body = precommit(claim_ref, [0xFF; 32], &pk);
    let (status, reason) = post(&n, "/api/v2/sofi/precommit", envelope_for(&body, &sk)).await;
    assert_eq!((status, reason.as_str()), (422, "foreign-set"));
}

/// `G` binds to a STORED `P` leg. The node checks the binding arithmetic and
/// never the policy.
#[tokio::test]
async fn a_witness_binds_to_a_stored_leg() {
    let n = node().await;
    let (claim_ref, pk, sk) = seed_parent_claim(&n).await;
    let body = precommit(claim_ref, n.set_id, &pk);
    assert_eq!(
        post(&n, "/api/v2/sofi/precommit", envelope_for(&body, &sk))
            .await
            .0,
        200
    );

    let witness = DlvPolicyFulfillmentBody {
        precommit_id: derive::precommit_id(&body),
        external_commitment: E,
        vault_id: VAULT,
        parent_root: PARENT_ROOT,
        shadow_core: [0x9A; 32],
    };
    let (status, reason) = post(&n, "/api/v2/sofi/policy-fulfillment", witness.encode()).await;
    assert_eq!((status, reason.as_str()), (200, "stored"));

    // A witness naming a leg this P does not have.
    let stray = DlvPolicyFulfillmentBody {
        vault_id: [0xDD; 32],
        ..witness
    };
    let (status, reason) = post(&n, "/api/v2/sofi/policy-fulfillment", stray.encode()).await;
    assert_eq!((status, reason.as_str()), (422, "witness-matches-no-leg"));

    // A witness naming another commitment.
    let other_e = DlvPolicyFulfillmentBody {
        external_commitment: [0xEE; 32],
        ..witness
    };
    let (status, reason) = post(&n, "/api/v2/sofi/policy-fulfillment", other_e.encode()).await;
    assert_eq!(
        (status, reason.as_str()),
        (422, "witness-names-another-commitment")
    );
}

/// A witness whose `P` this member does not hold is refused. `G` is bound to a
/// STORED leg, not to an asserted one.
#[tokio::test]
async fn a_witness_without_its_precommit_is_refused() {
    let n = node().await;
    let witness = DlvPolicyFulfillmentBody {
        precommit_id: [0xAB; 32],
        external_commitment: E,
        vault_id: VAULT,
        parent_root: PARENT_ROOT,
        shadow_core: [0x9A; 32],
    };
    let (status, reason) = post(&n, "/api/v2/sofi/policy-fulfillment", witness.encode()).await;
    assert_eq!((status, reason.as_str()), (422, "precommit-not-held"));
}

/// NEITHER STORE TOUCHES AN ECONOMIC POSITION. Storing `P` and `G` installs
/// nothing at `K_root`, which is what makes publication not exercise.
#[tokio::test]
async fn storing_p_and_g_installs_nothing_at_k_root() {
    let n = node().await;
    let (claim_ref, pk, sk) = seed_parent_claim(&n).await;
    let body = precommit(claim_ref, n.set_id, &pk);
    post(&n, "/api/v2/sofi/precommit", envelope_for(&body, &sk)).await;
    let witness = DlvPolicyFulfillmentBody {
        precommit_id: derive::precommit_id(&body),
        external_commitment: E,
        vault_id: VAULT,
        parent_root: PARENT_ROOT,
        shadow_core: [0x9A; 32],
    };
    post(&n, "/api/v2/sofi/policy-fulfillment", witness.encode()).await;

    // The successor position is untouched: no cell was installed at q = p + 1.
    let k_next = economic_root_register_key(&G, &DEV, POS + 1);
    assert!(
        db::get_economic_root_claim(&n.pool, &k_next)
            .await
            .expect("read")
            .is_none(),
        "publishing P and G must occupy no economic position"
    );
}
