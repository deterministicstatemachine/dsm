// SPDX-License-Identifier: MIT OR Apache-2.0
//! `P(E)` is the authority for every shadow: the three adversarial cases.
//!
//! `policy_fulfillment_id` hashes the whole witness body, `shadow_core`
//! included, so witnesses differing only in their shadow have different
//! content addresses and once coexisted for one leg. F ingress then chose
//! between them with an unordered `.find()`, which let anyone able to relay
//! deny an honest `F`, and let two members answer differently about one
//! identical `F`.
//!
//! `P(E)` settles it: `c°_{V,j}` is `dlv_core_digest` over the `V°_j` the
//! preimage carries, so for a given `E` there is exactly one admissible shadow
//! per leg. The member derives the canonical set; it never elects one.

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

/// Accept P and its canonical witness, and return the signed F envelope parts.
async fn ready(n: &Node) -> (TraderPrecommitBody, Vec<u8>, Vec<u8>) {
    let (claim_ref, pk, sk) = seed_parent_claim(n).await;
    let p = precommit(claim_ref, n.set_id, &pk);
    assert_eq!(
        post(n, "/api/v2/sofi/precommit", envelope_for(&p, &sk))
            .await
            .0,
        200
    );
    (p, pk, sk)
}

fn witness_for(p: &TraderPrecommitBody) -> DlvPolicyFulfillmentBody {
    let leg = canonical_leg();
    DlvPolicyFulfillmentBody {
        precommit_id: derive::precommit_id(p),
        external_commitment: external_commitment(),
        vault_id: leg.vault_id,
        parent_root: leg.parent_root,
        shadow_core: leg.shadow_core,
    }
}

/// A witness for the same leg carrying a shadow `E` does not commit.
fn decoy_for(p: &TraderPrecommitBody) -> DlvPolicyFulfillmentBody {
    DlvPolicyFulfillmentBody {
        shadow_core: [0x9A; 32],
        ..witness_for(p)
    }
}

fn fulfillment_over(p: &TraderPrecommitBody, shadow: [u8; 32], pk: &[u8]) -> TraderFulfillmentBody {
    let mut set: Vec<[u8; 32]> = dsm::sofi::conformance::derive_policy_fulfillments(p, &[shadow])
        .expect("derivable")
        .iter()
        .map(derive::policy_fulfillment_id)
        .collect();
    set.sort();
    TraderFulfillmentBody::new(
        derive::precommit_id(p),
        set,
        vec![AttemptEntry {
            vault_id: canonical_leg().vault_id,
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

/// CASE 1. An honest witness stored, a same-coordinate decoy attempted: the
/// decoy is not storable at all, and the valid `F` registers.
#[tokio::test]
async fn a_decoy_cannot_be_stored_and_the_valid_f_registers() {
    let n = node().await;
    let (p, pk, sk) = ready(&n).await;

    assert_eq!(
        post(
            &n,
            "/api/v2/sofi/policy-fulfillment",
            witness_for(&p).encode()
        )
        .await
        .1,
        "stored"
    );
    let (status, reason) = post(
        &n,
        "/api/v2/sofi/policy-fulfillment",
        decoy_for(&p).encode(),
    )
    .await;
    assert_eq!(
        (status, reason.as_str()),
        (422, "witness-is-not-the-one-e-commits"),
        "a shadow E does not commit is not storable"
    );

    let f = fulfillment_over(&p, canonical_leg().shadow_core, &pk);
    assert_eq!(
        post(&n, "/api/v2/sofi/fulfillment", f_envelope(&f, &sk))
            .await
            .1,
        "registered"
    );
}

/// ORDER INDEPENDENCE. The same dataset applied in opposite orders gives the
/// same answer — the property the unordered `.find()` destroyed.
#[tokio::test]
async fn the_answer_does_not_depend_on_insertion_order() {
    // decoy attempted FIRST, then the honest witness.
    let a = node().await;
    let (pa, pka, ska) = ready(&a).await;
    assert_eq!(
        post(
            &a,
            "/api/v2/sofi/policy-fulfillment",
            decoy_for(&pa).encode()
        )
        .await
        .0,
        422
    );
    assert_eq!(
        post(
            &a,
            "/api/v2/sofi/policy-fulfillment",
            witness_for(&pa).encode()
        )
        .await
        .0,
        200
    );
    let fa = fulfillment_over(&pa, canonical_leg().shadow_core, &pka);
    let first = post(&a, "/api/v2/sofi/fulfillment", f_envelope(&fa, &ska)).await;

    // honest witness FIRST, then the decoy attempted.
    let b = node().await;
    let (pb, pkb, skb) = ready(&b).await;
    assert_eq!(
        post(
            &b,
            "/api/v2/sofi/policy-fulfillment",
            witness_for(&pb).encode()
        )
        .await
        .0,
        200
    );
    assert_eq!(
        post(
            &b,
            "/api/v2/sofi/policy-fulfillment",
            decoy_for(&pb).encode()
        )
        .await
        .0,
        422
    );
    let fb = fulfillment_over(&pb, canonical_leg().shadow_core, &pkb);
    let second = post(&b, "/api/v2/sofi/fulfillment", f_envelope(&fb, &skb)).await;

    assert_eq!(first, second, "two members must not disagree about one F");
    assert_eq!(first.1, "registered");
}

/// CASE 2. An `F` built over a shadow `E` does not commit declares a set the
/// member's own derivation does not produce.
#[tokio::test]
async fn an_f_over_a_non_canonical_shadow_is_refused() {
    let n = node().await;
    let (p, pk, sk) = ready(&n).await;
    assert_eq!(
        post(
            &n,
            "/api/v2/sofi/policy-fulfillment",
            witness_for(&p).encode()
        )
        .await
        .0,
        200
    );

    let f = fulfillment_over(&p, [0x9A; 32], &pk);
    let (status, reason) = post(&n, "/api/v2/sofi/fulfillment", f_envelope(&f, &sk)).await;
    assert_eq!(
        (status, reason.as_str()),
        (422, "policy-fulfillment-set-is-not-canonical"),
        "the member derives the set; it does not accept the one it was handed"
    );
}

/// CASE 3. The canonical witness is not held here, so this member cannot
/// conclude the set is complete — whatever `F` declares.
#[tokio::test]
async fn an_f_whose_canonical_witness_is_not_held_is_refused() {
    let n = node().await;
    let (p, pk, sk) = ready(&n).await;
    // No witness posted.
    let f = fulfillment_over(&p, canonical_leg().shadow_core, &pk);
    let (status, reason) = post(&n, "/api/v2/sofi/fulfillment", f_envelope(&f, &sk)).await;
    assert_eq!(
        (status, reason.as_str()),
        (422, "policy-fulfillment-not-held")
    );
}

/// Without `P(E)` a member has no authority for the shadow and must say so
/// rather than fall back to believing a witness.
#[tokio::test]
async fn without_the_preimage_a_member_refuses_by_name() {
    let n = node().await;
    // A parent claim, but deliberately NO preimage.
    let (pk, sk) = generate_sphincs_keypair().expect("keys");
    let body = EconomicRootClaimBody {
        trader_genesis: G,
        trader_devid: DEV,
        economic_position: POS,
        post_economic_root: [0x77; 32],
        admission_manifest_addr: [0x78; 32],
        root_register_storage_set_id: n.set_id,
        signature_alg: sigalg::SPHINCS_PLUS_SPX256F,
        claimant_public_key: pk.clone(),
    };
    let envelope = sign_economic_root_claim(&body, &sk).expect("sign");
    let digest = economic_root_claim_envelope_digest(&envelope);
    let k_root = economic_root_register_key(&G, &DEV, POS);
    db::claim_economic_root(&n.pool, &k_root, &envelope, &digest, &pk, &n.set_id)
        .await
        .expect("seed");
    let p = precommit(digest, n.set_id, &pk);
    assert_eq!(
        post(&n, "/api/v2/sofi/precommit", envelope_for(&p, &sk))
            .await
            .0,
        200
    );

    let (status, reason) = post(
        &n,
        "/api/v2/sofi/policy-fulfillment",
        witness_for(&p).encode(),
    )
    .await;
    assert_eq!(
        (status, reason.as_str()),
        (422, "settlement-preimage-not-held")
    );
}
