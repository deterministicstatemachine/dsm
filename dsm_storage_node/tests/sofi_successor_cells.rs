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

fn fulfillment_for(p: &TraderPrecommitBody, pk: &[u8], attempt: u64) -> TraderFulfillmentBody {
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
    let (status, reason) = post(&n, &path, external_commitment().to_vec()).await;
    assert_eq!(
        (status, reason.as_str()),
        (409, "fulfillment-not-registered")
    );

    let k_cell =
        derive::successor_attempt_key(&canonical_leg().vault_id, &canonical_leg().parent_root, 0);
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

    let (status, reason) = post(&n, &path, external_commitment().to_vec()).await;
    assert_eq!((status, reason.as_str()), (200, "stored"));

    let k_cell =
        derive::successor_attempt_key(&canonical_leg().vault_id, &canonical_leg().parent_root, 0);
    assert_eq!(
        db::get_sofi_successor_cell(&n.pool, &k_cell)
            .await
            .expect("read")
            .expect("held"),
        external_commitment().to_vec(),
        "the cell holds exactly E"
    );
    // Write-once, and an identical rewrite acks.
    assert_eq!(
        post(&n, &path, external_commitment().to_vec()).await.1,
        "already-held"
    );
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
    let (status, reason) = post(&n, &path, external_commitment().to_vec()).await;
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
    let (status, reason) = post(&n, &path, external_commitment().to_vec()).await;
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
    let (status, reason) = post(&n, &path, external_commitment().to_vec()).await;
    assert_eq!((status, reason.as_str()), (422, "fulfillment-not-held"));
}

// ── two traders, one DLV leg ────────────────────────────────────────────────
//
// SoFi is deliberately non-locking: a policy-fulfillment witness never
// prevents another consumption of the same DLV parent. So two UNRELATED
// traders can both target `(VAULT, PARENT_ROOT)` and both register their own
// fulfillment at their OWN position — and their successor cells collide,
// because `K^(a)` is derived from the leg and the attempt and from nothing
// that distinguishes the two operations.

const G2: [u8; 32] = [0x31; 32];
const DEV2: [u8; 32] = [0x32; 32];
/// The second trader's preimage: the SAME DLV leg, a different trader core,
/// therefore a different `E`. That is exactly the field `K^(a)` omits.
fn preimage2() -> SettlementPreimage {
    preimage_for(0x7E)
}

async fn seed_parent_claim_for(
    node: &Node,
    g: [u8; 32],
    dev: [u8; 32],
) -> ([u8; 32], Vec<u8>, Vec<u8>) {
    let (pk, sk) = generate_sphincs_keypair().expect("keys");
    let body = EconomicRootClaimBody {
        trader_genesis: g,
        trader_devid: dev,
        economic_position: POS,
        post_economic_root: [0x77; 32],
        admission_manifest_addr: [0x78; 32],
        root_register_storage_set_id: node.set_id,
        signature_alg: sigalg::SPHINCS_PLUS_SPX256F,
        claimant_public_key: pk.clone(),
    };
    let envelope = sign_economic_root_claim(&body, &sk).expect("sign claim");
    let digest = economic_root_claim_envelope_digest(&envelope);
    let k_root = economic_root_register_key(&g, &dev, POS);
    db::claim_economic_root(&node.pool, &k_root, &envelope, &digest, &pk, &node.set_id)
        .await
        .expect("seed the parent cell");
    (digest, pk, sk)
}

#[allow(clippy::too_many_arguments)]
fn precommit_for(
    g: [u8; 32],
    dev: [u8; 32],
    pre: &SettlementPreimage,
    claim_ref: [u8; 32],
    set_id: [u8; 32],
    pk: &[u8],
) -> TraderPrecommitBody {
    let leg = canonical_leg_of(pre);
    TraderPrecommitBody::new(
        g,
        dev,
        POS,
        ParentClaimRef::SingleRoot { claim_ref },
        external_commitment_of(pre),
        // THE SAME DLV LEG as the first trader's — same vault, same parent
        // root — which is why their successor cells collide.
        vec![PrecommitLeg {
            vault_id: leg.vault_id,
            parent_root: leg.parent_root,
            setup_ref: leg.setup_ref,
        }],
        [0xA1; 32],
        [0x61; 32],
        set_id,
        sigalg::SPHINCS_PLUS_SPX256F,
        pk,
    )
    .expect("a well-formed precommit")
}

/// Accept and register a whole operation for one trader, returning its cell
/// path and the `E` it commits.
async fn operation_for(
    n: &Node,
    g: [u8; 32],
    dev: [u8; 32],
    pre: &SettlementPreimage,
) -> (String, [u8; 32]) {
    seed_preimage_of(n, pre).await;
    let e = external_commitment_of(pre);
    let leg = canonical_leg_of(pre);
    let (claim_ref, pk, sk) = seed_parent_claim_for(n, g, dev).await;
    let p = precommit_for(g, dev, pre, claim_ref, n.set_id, &pk);
    assert_eq!(
        post(n, "/api/v2/sofi/precommit", envelope_for(&p, &sk))
            .await
            .0,
        200
    );
    let witness = DlvPolicyFulfillmentBody {
        precommit_id: derive::precommit_id(&p),
        external_commitment: e,
        vault_id: VAULT,
        parent_root: canonical_leg().parent_root,
        shadow_core: canonical_leg().shadow_core,
    };
    assert_eq!(
        post(n, "/api/v2/sofi/policy-fulfillment", witness.encode())
            .await
            .0,
        200
    );
    let f = fulfillment_for(&p, &pk, 0);
    assert_eq!(
        post(n, "/api/v2/sofi/fulfillment", f_envelope(&f, &sk))
            .await
            .1,
        "registered"
    );
    let fid = derive::fulfillment_id(&f);
    db::record_fulfillment_registered(&n.pool, &fid, 3)
        .await
        .expect("record the exercise fact");
    (
        format!("/api/v2/sofi/cell/{}/{}", b32(&fid), b32(&VAULT)),
        e,
    )
}

/// THE DEFECT THIS FIXES. Two registered fulfillments from DIFFERENT traders
/// reach one `K^(a)` with different `E`. The first lands; the second is
/// CONTENTION and must be told so. Before the fix the loser received
/// HTTP 200 `already-held` — an affirmative claim that the cell holds the `E`
/// it just posted — while the cell held the winner's.
#[tokio::test]
async fn two_operations_on_one_leg_contend_and_the_loser_is_told() {
    let n = node().await;
    let (path_a, e_a) = operation_for(&n, G, DEV, &preimage()).await;
    let (path_b, e_b) = operation_for(&n, G2, DEV2, &preimage2()).await;
    assert_ne!(e_a, e_b, "the two operations commit different E");

    // Both derive the SAME cell key: the leg and attempt are identical.
    let k_cell =
        derive::successor_attempt_key(&canonical_leg().vault_id, &canonical_leg().parent_root, 0);

    assert_eq!(
        post(&n, &path_a, e_a.to_vec()).await,
        (200, "stored".to_string())
    );
    let (status, reason) = post(&n, &path_b, e_b.to_vec()).await;
    assert_eq!(
        (status, reason.as_str()),
        (409, "cell-taken"),
        "the loser must learn it did not land"
    );

    assert_eq!(
        db::get_sofi_successor_cell(&n.pool, &k_cell)
            .await
            .expect("read")
            .expect("held"),
        e_a.to_vec(),
        "the cell still holds the FIRST writer's E"
    );
}

/// The idempotent case is unaffected: re-posting the same `E` at the same cell
/// still acks, so an honest relayer repeating a write is not told it lost.
#[tokio::test]
async fn re_posting_the_same_e_still_acks() {
    let n = node().await;
    let (path, e) = operation_for(&n, G, DEV, &preimage()).await;
    assert_eq!(post(&n, &path, e.to_vec()).await.1, "stored");
    assert_eq!(post(&n, &path, e.to_vec()).await.1, "already-held");
}
