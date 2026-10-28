// SPDX-License-Identifier: MIT OR Apache-2.0

//! Holding a token created on another device: adoption by its CPTA anchor,
//! resolution of the adopted policy on the receiving device, and the
//! permanence of an adoption: a ticker this device holds never names another
//! token.
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
        .invoke(AppInvoke {
            method: "tokens.addByAnchor".to_string(),
            args: text.as_bytes().to_vec(),
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
    // The answer names the token it registered — id, ticker and the anchor
    // re-derived from the fetched bytes — as fields, not as prose: the screen
    // shows these, and it used to scrape the ticker out of the message.
    let answer = adopted_token(&adopted);
    assert_eq!(answer.ticker, ticker);
    assert_eq!(answer.token_id, derive_token_id(&anchor, ticker));
    assert_eq!(answer.policy_anchor, anchor.to_vec());
    (p, anchor)
}

/// The `TokenCreateResponse` a successful adoption answers with.
fn adopted_token(result: &AppResult) -> crate::generated::TokenCreateResponse {
    let env = crate::generated::Envelope::decode(&result.data[1..]).expect("a framed envelope");
    match env.payload {
        Some(crate::generated::envelope::Payload::TokenCreateResponse(resp)) => resp,
        other => panic!("an adoption answers a TokenCreateResponse, not {other:?}"),
    }
}

/// THE HARDWARE FAILURE (8XK → D3): the receiver of a created token held no
/// `CreateToken` of its own, and the resolver looked only there. An adopted
/// token must resolve on the RECEIVING device — to the anchor its policy
/// hashes to — by ticker and by token id.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn an_adopted_token_resolves_on_the_receiving_device() {
    let (p, anchor) = created_on_a_adopted_on_b("RIGB").await;
    p.b.enter();
    assert_eq!(
        crate::policy::resolve_policy_commit_strict(b"RIGB")
            .expect("an adopted token resolves on the receiving device"),
        anchor
    );
    let token_id = derive_token_id(&anchor, "RIGB");
    assert_eq!(
        crate::policy::resolve_policy_commit_strict(token_id.as_bytes())
            .expect("resolve by token id"),
        anchor
    );
}

/// Adoption registers a token exactly when its state stands behind it. B
/// already holds a row under the token id A's anchor derives, written
/// straight into the store under another ticker and adopted by nothing, so
/// the adoption's own row cannot be written: the adoption is refused whole,
/// B's head does not adopt the token, and the row stays what it was.
/// MUTATION CONTROL: writing the row after the adoption commits, outside its
/// transaction, turns this red.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn an_adoption_whose_registry_row_cannot_be_written_adopts_nothing() {
    let p = Pair::boot(100, 0).await;
    p.a.enter();
    let anchor = economic_fixtures::create_asset(p.a.router(), "ROLL", 2, 1_000).await;
    p.b.enter();
    let token_id = derive_token_id(&anchor, "ROLL");
    token_registry::insert_token(&token_registry::TokenRegistryRow {
        token_id: token_id.clone(),
        policy_commit: [0x5E; 32],
        ticker: "STALE".to_string(),
        alias: "a row no adoption wrote".to_string(),
        decimals: 2,
        genesis_supply: 1_000,
        creator_device_id: [0x5F; 32],
    })
    .expect("the row in the way");

    let refused = adopt(p.b.router(), &anchor_text(&anchor)).await;
    assert!(
        !refused.success,
        "an adoption whose row cannot be written is refused"
    );
    let head = p.b.router().core_sdk.device_head().expect("a head");
    assert!(
        !head.has_adopted(&anchor),
        "B's head adopts nothing it registered no row for"
    );
    let row = token_registry::get_token(&token_id)
        .expect("registry")
        .expect("the row in the way");
    assert_eq!(row.ticker, "STALE");
}

/// `balance.get` for `token_id`, as the wallet asks it.
async fn balance_get(router: &AppRouterImpl, token_id: &str) -> AppResult {
    router
        .query(AppQuery {
            path: "balance.get".to_string(),
            params: dsm::types::proto::ArgPack {
                schema_hash: None,
                codec: dsm::types::proto::Codec::Proto as i32,
                body: token_id.as_bytes().to_vec(),
            }
            .encode_to_vec(),
        })
        .await
}

fn balance_of(result: &AppResult) -> dsm::types::proto::BalanceGetResponse {
    assert!(result.success, "balance.get: {:?}", result.error_message);
    match crate::handlers::response_helpers::decode_local_envelope(&result.data)
        .expect("a local answer")
        .payload
    {
        Some(dsm::types::proto::envelope::Payload::BalanceGetResponse(r)) => r,
        other => panic!("balance.get answered {other:?}"),
    }
}

/// A balance the projection store holds but cannot decode is an error, never
/// a zero. B adopted the token and holds none of it, so the read leaves the
/// head for the projection store: with no row there, zero is established
/// over a readable head and store; with a row Rust cannot decode, the answer
/// is the failure. (The reader used to log "ignoring invalid projection row"
/// and answer 0.)
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_balance_whose_projection_row_does_not_decode_is_an_error_not_zero() {
    let (p, anchor) = created_on_a_adopted_on_b("RIGC").await;
    let router = p.b.router();

    let none = balance_get(router, "RIGC").await;
    assert_eq!(
        balance_of(&none).available,
        0,
        "no row, no holding: an established zero"
    );

    {
        let binding = crate::storage::client_db::get_connection().expect("conn");
        let conn = binding
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let inserted = conn
            .execute(
                "INSERT INTO balance_projections \
                 (balance_key, device_id, token_id, policy_commit, available, locked, source_state_hash) \
                 VALUES (?1, ?2, ?3, ?4, 'not a number', 0, ?5)",
                rusqlite::params![
                    "a row for RIGC",
                    crate::util::text_id::encode_base32_crockford(&router.device_id_bytes),
                    "RIGC",
                    crate::util::text_id::encode_base32_crockford(&anchor),
                    crate::util::text_id::encode_base32_crockford(&[0x5Au8; 32]),
                ],
            )
            .expect("a row the store holds and Rust cannot decode");
        assert_eq!(inserted, 1);
    }

    let broken = balance_get(router, "RIGC").await;
    assert!(
        !broken.success,
        "a projection row that does not decode is the answer's failure, not 0: {:?}",
        broken.error_message
    );
    let why = broken.error_message.unwrap_or_default();
    assert!(why.contains("projection"), "{why}");
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
    p.b.enter();
    let refused = crate::policy::resolve_policy_commit_strict(b"LIAR")
        .expect_err("a row that no longer carries the real policy must not resolve");
    assert!(
        matches!(refused, dsm::types::error::DsmError::Storage { .. }),
        "bytes that do not re-hash are a storage error, not an uninstalled token: {refused}"
    );
}

/// Builtins resolve from the builtin table; an unknown token fails closed —
/// resolution never invents an anchor.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn builtins_resolve_and_an_unknown_token_fails_closed() {
    let _device = Device::start(0xA1).await;
    assert_eq!(
        crate::policy::resolve_policy_commit_strict(b"ERA").expect("ERA is builtin"),
        dsm::core::token::builtin_policy_commit_for_token("ERA").expect("ERA")
    );
    let unknown = crate::policy::resolve_policy_commit_strict(b"NEVERSEEN")
        .expect_err("an unknown token fails closed");
    assert!(
        matches!(unknown, dsm::types::error::DsmError::NotFound { .. }),
        "a token with no registry row is not installed, not a storage error: {unknown}"
    );
}

/// A protocol asset is held by every device by construction and is never
/// adopted by its anchor: ERA's commitment is refused as what it is, and no
/// registry row is written for it (SoFi Amendment S11).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_protocol_asset_is_never_adopted_by_its_anchor() {
    let d = Device::start(0xE7).await;
    let era = dsm::core::token::token_state_manager::era_policy_commit();
    let refused = adopt(&d.router, &anchor_text(&era)).await;
    assert!(!refused.success, "ERA was adopted by its anchor");
    let why = refused.error_message.unwrap_or_default();
    assert!(
        why.contains("protocol asset"),
        "refused for another reason: {why}"
    );
    assert!(token_registry::get_token_by_ticker("ERA")
        .expect("the registry is readable")
        .is_none());
}

/// EVERY token query route is reachable through the production dispatcher:
/// the failure where a handler arm exists but the dispatch table does not name
/// it has happened twice. `tokens.addByAnchor` writes the registry, so it is
/// an invoke; its own check answering below shows the invoke reaches it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn every_token_query_route_is_reachable_through_the_dispatcher() {
    let d = Device::start(0x83).await;
    for path in [
        "tokens.getPolicy",
        "tokens.listCachedPolicies",
        "tokens.getFeeSchedule",
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
    let _restarted = economic_fixtures::restart_router(&p.fleet);
    let after = token_registry::get_token_by_ticker("PERSIST")
        .expect("registry")
        .expect("still adopted after restart");
    assert_eq!(before.token_id, after.token_id);
    assert_eq!(before.policy_commit, after.policy_commit);
    assert_eq!(before.decimals, after.decimals);
    assert_eq!(
        crate::policy::resolve_policy_commit_strict(b"PERSIST")
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

/// SoFi Amendment S28 (MR-SOFI-0305): nothing reserves a ticker across the
/// network, and a device holds one token per ticker. A and B each create a
/// token named TWIN, independently: both creations stand, as two tokens,
/// two policy commits, each held by its own creator. On each device the
/// ticker still names one token: B, holding its own TWIN, refuses A's, and A
/// cannot create a second TWIN.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn two_devices_each_create_a_token_under_one_ticker_and_each_holds_its_own() {
    let p = Pair::boot(100, 100).await;
    p.a.enter();
    let a_twin = economic_fixtures::create_asset(p.a.router(), "TWIN", 2, 1_000).await;
    p.b.enter();
    let b_twin = economic_fixtures::create_asset(p.b.router(), "TWIN", 2, 1_000).await;
    assert_ne!(a_twin, b_twin, "two creations are two tokens");
    for (d, held) in [(&p.a, a_twin), (&p.b, b_twin)] {
        d.enter();
        assert_eq!(
            token_registry::get_token_by_ticker("TWIN")
                .expect("read")
                .expect("row")
                .policy_commit,
            held,
            "{} holds its own TWIN",
            d.slot
        );
    }

    // What a refusal before anything is written leaves as it was: the
    // device's ERA and its admitted position.
    let standing = |d: &TestDevice| {
        (
            super::node_e2e_tests::balance(d, &super::node_e2e_tests::era()),
            super::node_e2e_tests::admitted_position(d),
        )
    };
    let b_before = standing(&p.b);
    p.b.enter();
    let refused = adopt(p.b.router(), &anchor_text(&a_twin)).await;
    assert!(!refused.success, "B already holds a TWIN");
    let reason = refused.error_message.expect("a refusal carries its reason");
    assert!(reason.contains("TICKER_CONFLICT"), "{reason}");
    assert_eq!(standing(&p.b), b_before, "B's refusal wrote nothing");

    let a_before = standing(&p.a);
    // Another policy under the same ticker: only the alias differs.
    let mut another = super::sender_admission_tests::create_request("TWIN", 2, 1_000);
    another.alias = "Another twin".into();
    let second =
        super::node_e2e_tests::invoke(&p.a, "token.create", super::node_e2e_tests::args(&another))
            .await;
    assert!(!second.success, "A already holds a TWIN");
    let why = second.error_message.expect("a refusal carries its reason");
    assert!(why.contains("already held by a different token"), "{why}");
    assert_eq!(standing(&p.a), a_before, "A's refusal spent nothing");
    assert_eq!(
        token_registry::get_token_by_ticker("TWIN")
            .expect("read")
            .expect("row")
            .policy_commit,
        a_twin,
        "A's TWIN is still the one it created"
    );
}

/// Adoption is permanent (SA-148): a device holding RIGB never adopts a
/// different token that another creator named RIGB. The ticker would then
/// name two assets, and a transfer could credit the wrong one.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_ticker_held_by_one_token_never_names_another() {
    let (p, held) = created_on_a_adopted_on_b("RIGB").await;
    let mut c = TestDevice::create("C", 0x0C);
    c.boot(&p.fleet).await;
    c.fund_admitted(100).await;
    c.enter();
    let other = economic_fixtures::create_asset(c.router(), "RIGB", 2, 1_000).await;
    assert_ne!(other, held, "another creator is another policy");

    p.b.enter();
    let refused = adopt(p.b.router(), &anchor_text(&other)).await;
    assert!(!refused.success, "the ticker is held by another token");
    let reason = refused.error_message.expect("a refusal carries its reason");
    assert!(reason.contains("TICKER_CONFLICT"), "{reason}");
    assert_eq!(
        token_registry::get_token_by_ticker("RIGB")
            .expect("read")
            .expect("row")
            .policy_commit,
        held
    );
}
