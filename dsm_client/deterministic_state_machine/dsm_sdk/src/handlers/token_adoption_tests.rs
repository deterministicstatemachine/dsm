// SPDX-License-Identifier: MIT OR Apache-2.0

//! Holding a token created on another device: adoption by its CPTA anchor,
//! resolution of the adopted policy on the receiving device, and forgetting an
//! identity so a superseded ticker can be adopted again.
//!
//! Every token here is created through `token.create` on a device created as
//! wallet creation creates it, on the network's pinned set of storage nodes;
//! every adoption goes through `tokens.addByAnchor`, which fetches the policy
//! from the fleet by its anchor. Nothing writes a registry row or a policy by
//! hand.

use prost::Message;
use serial_test::serial;

use crate::bridge::{AppInvoke, AppQuery, AppResult, AppRouter};
use crate::economic_fixtures;
use crate::handlers::app_router_impl::AppRouterImpl;
use crate::storage::client_db::token_registry;
use crate::test_support::one_device::Device;
use crate::test_support::two_device::{Pair, TestDevice};

/// Adopt from the TEXT a user supplied — a bare Base32 anchor or a scanned
/// `dsm:token/v1:` payload. Decoding it is Rust's job.
async fn adopt(router: &AppRouterImpl, text: &str) -> AppResult {
    router
        .query(AppQuery {
            path: "tokens.addByAnchor".to_string(),
            params: text.as_bytes().to_vec(),
        })
        .await
}

async fn forget(router: &AppRouterImpl, key: &str) -> AppResult {
    router
        .invoke(AppInvoke {
            method: "token.forget".to_string(),
            args: crate::generated::ArgPack {
                codec: crate::generated::Codec::Proto as i32,
                body: crate::generated::TokenForgetRequest {
                    token_id: key.to_string(),
                }
                .encode_to_vec(),
                ..Default::default()
            }
            .encode_to_vec(),
        })
        .await
}

fn anchor_text(anchor: &[u8; 32]) -> String {
    crate::util::text_id::encode_base32_crockford(anchor)
}

/// The token id an anchor and ticker derive, as the route derives it.
fn derive_token_id(anchor: &[u8; 32], ticker: &str) -> String {
    let mut h = dsm::crypto::blake3::dsm_domain_hasher(dsm::common::domain_tags::TAG_DSM_TOKEN_ID);
    h.update(anchor);
    h.update(ticker.as_bytes());
    crate::util::text_id::encode_base32_crockford(h.finalize().as_bytes())
}

fn era_of(router: &AppRouterImpl) -> u64 {
    router
        .core_sdk
        .device_head()
        .expect("a created device has a head")
        .balance(&dsm::core::token::token_state_manager::era_policy_commit())
}

/// A creates `ticker`; B, which never created it, adopts it through the
/// route. B is left entered.
async fn created_on_a_adopted_on_b(ticker: &str) -> (Pair, [u8; 32]) {
    let p = Pair::boot(100, 0).await;
    p.a.enter();
    let anchor = economic_fixtures::create_asset(p.a.router(), ticker, 2, 1_000).await;
    p.b.enter();
    let adopted = adopt(p.b.router(), &anchor_text(&anchor)).await;
    assert!(
        adopted.success,
        "B adopts {ticker}: {:?}",
        adopted.error_message
    );
    (p, anchor)
}

/// THE HARDWARE FAILURE (8XK → D3): the receiver of a created token held no
/// `CreateToken` of its own, and the resolver looked only there. An adopted
/// token must resolve on the RECEIVING device — to the anchor its policy
/// hashes to — by ticker and by token id.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn an_adopted_token_resolves_on_the_receiving_device() {
    let (p, anchor) = created_on_a_adopted_on_b("RIGB").await;
    let core = &p.b.router().core_sdk;
    assert_eq!(
        core.resolve_policy_commit_strict(b"RIGB")
            .expect("an adopted token resolves on the receiving device"),
        anchor
    );
    let token_id = derive_token_id(&anchor, "RIGB");
    assert_eq!(
        core.resolve_policy_commit_strict(token_id.as_bytes())
            .expect("resolve by token id"),
        anchor
    );
}

/// SELF-CERTIFYING, NOT TRUSTED. The registry holds the policy bytes under
/// their commitment; if the stored bytes stop hashing to it — a damaged
/// database — the token no longer resolves. A mutable cache is never granted
/// authority over the policy that governs an asset.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_policy_whose_stored_bytes_do_not_hash_to_its_commit_does_not_resolve() {
    let (p, anchor) = created_on_a_adopted_on_b("LIAR").await;
    {
        let binding = crate::storage::client_db::get_connection().expect("conn");
        let conn = binding
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let damaged = conn
            .execute(
                "UPDATE token_policies SET policy_bytes = ?1 WHERE policy_commit = ?2",
                rusqlite::params![
                    b"bytes that hash to something else".as_slice(),
                    anchor.as_slice()
                ],
            )
            .expect("damage the stored policy");
        assert_eq!(damaged, 1, "B held the adopted policy");
    }
    assert!(
        p.b.router()
            .core_sdk
            .resolve_policy_commit_strict(b"LIAR")
            .is_err(),
        "a row that no longer carries the real policy must not resolve"
    );
}

/// Builtins resolve from the builtin table; an unknown token fails closed —
/// resolution never invents an anchor.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn builtins_resolve_and_an_unknown_token_fails_closed() {
    let d = Device::start(0xA1).await;
    assert_eq!(
        d.core()
            .resolve_policy_commit_strict(b"ERA")
            .expect("ERA is builtin"),
        dsm::core::token::builtin_policy_commit_for_token("ERA").expect("ERA")
    );
    assert!(d.core().resolve_policy_commit_strict(b"NEVERSEEN").is_err());
}

/// EVERY token query route is reachable through the production dispatcher:
/// the failure where a handler arm exists but the dispatch table does not name
/// it has happened twice.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn every_token_query_route_is_reachable_through_the_dispatcher() {
    let d = Device::start(0x83).await;
    for path in [
        "tokens.getPolicy",
        "tokens.listCachedPolicies",
        "tokens.getFeeSchedule",
        "tokens.addByAnchor",
        "token.adoptionQr",
    ] {
        let res = d
            .router
            .query(AppQuery {
                path: path.to_string(),
                params: Vec::new(),
            })
            .await;
        let msg = res.error_message.unwrap_or_default();
        assert!(
            !msg.contains("unknown query path"),
            "{path} is not registered in the production dispatch table: {msg}"
        );
    }
    let res = adopt(&d.router, "ZZZZ").await;
    let msg = res.error_message.unwrap_or_default();
    assert!(
        msg.contains("32 bytes"),
        "tokens.addByAnchor's own length check answers, got: {msg}"
    );
}

/// Adoption is COMMITTED STATE and costs no ERA. The receiver's head advances
/// by the adoption leaf; the creator's head carried it from the creation, so
/// adopting its own token again is idempotent — no fee, no second advance —
/// and repeated adoption never multiplies registry rows or policies.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn adoption_is_committed_free_and_idempotent() {
    let (p, anchor) = created_on_a_adopted_on_b("ADOPT").await;
    let b_head = p.b.router().core_sdk.device_head().expect("B head");
    assert!(
        b_head.has_adopted(&anchor),
        "the leaf is on the receiver's head"
    );
    assert_eq!(p.b.era_balance(), 0, "the receiver paid nothing");

    p.a.enter();
    let creator = p.a.router();
    assert!(creator
        .core_sdk
        .device_head()
        .expect("A head")
        .has_adopted(&anchor));
    let era_before = era_of(creator);
    let root_before = creator.core_sdk.device_head().expect("A head").root();
    for attempt in 1..=3 {
        let res = adopt(creator, &anchor_text(&anchor)).await;
        assert!(res.success, "attempt {attempt}: {:?}", res.error_message);
    }
    assert_eq!(era_of(creator), era_before, "adoption burns no ERA");
    assert_eq!(
        creator.core_sdk.device_head().expect("A head").root(),
        root_before,
        "an already-adopted token is not re-advanced"
    );
    assert_eq!(token_registry::all_tokens().expect("registry").len(), 1);
    assert_eq!(token_registry::all_policies().expect("policies").len(), 1);
}

/// An anchor no member holds a policy for adopts nothing and leaves no row.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn an_anchor_that_resolves_to_nothing_fails_closed() {
    let d = Device::start(0x84).await;
    let unpublished = dsm::crypto::blake3::domain_hash_bytes(
        dsm::common::domain_tags::TAG_DSM_POLICY,
        b"a policy no device ever published",
    );
    let res = adopt(&d.router, &anchor_text(&unpublished)).await;
    assert!(!res.success, "an unpublished anchor adopts nothing");
    assert!(token_registry::all_tokens().expect("registry").is_empty());
}

/// An adopted token survives a restart: it lives in the registry, not in
/// memory.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn an_adopted_token_survives_a_restart() {
    let (p, anchor) = created_on_a_adopted_on_b("PERSIST").await;
    let before = token_registry::get_token_by_ticker("PERSIST")
        .expect("registry")
        .expect("adopted");
    let restarted = economic_fixtures::restart_router(&p.fleet);
    let after = token_registry::get_token_by_ticker("PERSIST")
        .expect("registry")
        .expect("still adopted after restart");
    assert_eq!(before.token_id, after.token_id);
    assert_eq!(before.policy_commit, after.policy_commit);
    assert_eq!(before.decimals, after.decimals);
    assert_eq!(
        restarted
            .core_sdk
            .resolve_policy_commit_strict(b"PERSIST")
            .expect("the restarted device resolves it"),
        anchor
    );
}

/// A scanned `dsm:token/v1:` payload adopts the same token a typed anchor
/// does; a payload whose claimed ticker or token id disagrees with what its
/// anchor publishes is refused, not silently corrected.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_scanned_payload_adopts_and_a_lying_payload_is_refused() {
    let p = Pair::boot(100, 0).await;
    p.a.enter();
    let anchor = economic_fixtures::create_asset(p.a.router(), "SCANME", 2, 1_000).await;
    let token_id = derive_token_id(&anchor, "SCANME");
    p.b.enter();

    let lying_ticker =
        crate::handlers::token_routes::build_adoption_uri(&anchor, "NOTREAL", &token_id);
    let res = adopt(p.b.router(), &lying_ticker).await;
    assert!(!res.success, "a mismatched ticker must be refused");
    let msg = res.error_message.unwrap_or_default();
    assert!(
        msg.contains("NOTREAL") && msg.contains("SCANME"),
        "got: {msg}"
    );
    assert!(token_registry::get_token_by_ticker("NOTREAL")
        .expect("registry")
        .is_none());

    let lying_id = crate::handlers::token_routes::build_adoption_uri(&anchor, "SCANME", "WRONGID");
    assert!(!adopt(p.b.router(), &lying_id).await.success);

    let uri = crate::handlers::token_routes::build_adoption_uri(&anchor, "SCANME", &token_id);
    let res = adopt(p.b.router(), &uri).await;
    assert!(res.success, "scanned adopt: {:?}", res.error_message);
    let row = token_registry::get_token_by_ticker("SCANME")
        .expect("registry")
        .expect("token");
    assert_eq!(row.policy_commit, anchor);
    assert_eq!(row.token_id, token_id);
}

/// THE DEAD END (D3): a device held an adopted RIGB whose creator was wiped
/// and whose ticker was re-created by another device — a different policy,
/// so a different token. Adopting the live RIGB was refused (the ticker was
/// taken) with no way out. Forgetting the zero-balance identity frees the
/// ticker, and the live token adopts.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn forgetting_a_superseded_zero_balance_token_frees_its_ticker() {
    let (p, superseded) = created_on_a_adopted_on_b("RIGB").await;
    let mut c = TestDevice::create("C", 0x0C);
    c.boot(&p.fleet).await;
    c.fund_admitted(100).await;
    c.enter();
    let live = economic_fixtures::create_asset(c.router(), "RIGB", 2, 1_000).await;
    assert_ne!(live, superseded, "another creator is another policy");

    p.b.enter();
    let refused = adopt(p.b.router(), &anchor_text(&live)).await;
    assert!(
        !refused.success,
        "the ticker is taken by the superseded token"
    );

    let forgotten = forget(p.b.router(), "RIGB").await;
    assert!(forgotten.success, "forget: {:?}", forgotten.error_message);
    assert!(token_registry::get_token_by_ticker("RIGB")
        .expect("read")
        .is_none());

    let adopted = adopt(p.b.router(), &anchor_text(&live)).await;
    assert!(
        adopted.success,
        "adopt the live RIGB: {:?}",
        adopted.error_message
    );
    assert_eq!(
        token_registry::get_token_by_ticker("RIGB")
            .expect("read")
            .expect("row")
            .policy_commit,
        live
    );
}

/// Forgetting removes the NAMING only, and never an asset the device holds:
/// canonical balances decide. A creator holding its supply cannot forget it;
/// protocol assets are never forgettable; an unknown name is an error, not a
/// silent success; and a token can be forgotten by its id.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn forget_refuses_held_protocol_and_unknown_tokens_and_takes_an_id() {
    let (p, anchor) = created_on_a_adopted_on_b("HELD").await;

    p.a.enter();
    let held = forget(p.a.router(), "HELD").await;
    assert!(!held.success, "a held token must not be forgettable");
    let msg = held.error_message.unwrap_or_default();
    assert!(
        msg.contains("100000") && msg.to_lowercase().contains("still holds"),
        "the refusal names the held base units, got: {msg}"
    );
    assert!(token_registry::get_token_by_ticker("HELD")
        .expect("read")
        .is_some());

    for builtin in ["ERA", "dBTC"] {
        let res = forget(p.a.router(), builtin).await;
        assert!(!res.success, "{builtin} must not be forgettable");
        assert!(res
            .error_message
            .unwrap_or_default()
            .contains("protocol asset"));
    }

    let unknown = forget(p.a.router(), "NEVERSEEN").await;
    assert!(!unknown.success);
    assert!(unknown
        .error_message
        .unwrap_or_default()
        .contains("no token named"));

    p.b.enter();
    let by_id = forget(p.b.router(), &derive_token_id(&anchor, "HELD")).await;
    assert!(by_id.success, "forget by id: {:?}", by_id.error_message);
    assert!(token_registry::get_token_by_ticker("HELD")
        .expect("read")
        .is_none());
}
