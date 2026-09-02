// SPDX-License-Identifier: MIT OR Apache-2.0
//! Adopting a token created on another device.
//!
//! A device cannot hold a token whose policy it does not have: balances are
//! keyed by policy commitment and the enforcer needs the committed rules.
//! Creation registers the token on the CREATOR's device only, so every other
//! device has to adopt it. That step did not exist — the frontend had a
//! function that fetched the policy bytes and threw them away, and no route
//! registered anything. A transfer to a second device could never have settled,
//! and would have failed at the transfer layer with nothing obviously wrong.
//!
//! Adoption is NOT a state transition: no advance, no issuance, and no fee.
//! Only the creator burns the 10 ERA. Charging to *receive* a token would be
//! wrong, so that is pinned here rather than left to inspection.

#![allow(clippy::disallowed_methods)]

use prost::Message;
use std::path::PathBuf;

use dsm_sdk::bridge::AppRouter;
use dsm_sdk::generated;
use dsm_sdk::handlers::app_router_impl::AppRouterImpl;
use dsm_sdk::runtime;
use dsm_sdk::storage::client_db::token_registry;

/// A router on a REAL testnet identity, funded through a REAL faucet admission
/// (0x0030), replacing a fabricated identity plus a directly-written balance.
///
/// The old pair installed [0xAA;32]/[0xBB;32]/[0xCC;32] with no genesis record —
/// so no network was committed and no admission could ever run — and then wrote
/// 100 ERA straight onto the head. That balance had no economic lineage, and
/// since debits are not fenced it was fully spendable through canonical
/// acceptance. 100 is also exactly the faucet's payout, so assertions written
/// against it are unchanged.
fn funded_router(seed: u8) -> (AppRouterImpl, dsm_sdk::economic_fixtures::FleetGuard) {
    let _ = dsm_sdk::storage_utils::set_storage_base_dir(PathBuf::from("./.dsm_testdata"));
    dsm_sdk::economic_fixtures::funded_router(seed)
}

/// Adopt from the TEXT a user supplied — a bare Base32 anchor or a scanned
/// `dsm:token/v1:` payload. The route takes text, not 32 raw bytes, because
/// decoding it is Rust's job: a client that decodes Base32 itself is a second
/// implementation of an encoding whose trailing-group padding is easy to get
/// wrong, and a wrong anchor is indistinguishable from an unpublished policy.
fn adopt(r: &AppRouterImpl, text: &str) -> dsm_sdk::bridge::AppResult {
    query(r, "tokens.addByAnchor", text.as_bytes().to_vec())
}

fn anchor_text(anchor: &[u8; 32]) -> String {
    dsm_sdk::util::text_id::encode_base32_crockford(anchor)
}

/// Query routes take raw bytes, not an ArgPack body.
fn query(r: &AppRouterImpl, path: &str, params: Vec<u8>) -> dsm_sdk::bridge::AppResult {
    runtime::get_runtime().block_on(async {
        r.query(dsm_sdk::bridge::AppQuery {
            path: path.to_string(),
            params,
        })
        .await
    })
}

fn era(r: &AppRouterImpl) -> u64 {
    let c = dsm::core::token::builtin_policy_commit_for_token("ERA").expect("ERA");
    r.core_sdk.device_head().map(|h| h.balance(&c)).unwrap_or(0)
}

/// PUBLISH a real policy to adopt, returning its anchor — the durable shape
/// `token.create` persists, built directly: under 3.5b the creation fee is an
/// ADMITTED economic debit integration tests cannot run (no fake register
/// fleet; the admitted create e2e lives in `handlers::sender_admission_tests`),
/// and adoption only needs the published policy bytes, which is truer to the
/// "another device created it" story anyway: no registry row exists locally
/// until adoption writes one.
fn create_token(_r: &AppRouterImpl, ticker: &str) -> [u8; 32] {
    let signer = vec![0xBBu8; 32];
    let alias = format!("{ticker} Token");
    let mut pb: Vec<u8> = vec![
        3,           // TOKEN_POLICY_VERSION
        0,           // TOKEN_KIND_FUNGIBLE
        0x01 | 0x02, // mint_burn + transferable
        1,           // mint_burn_threshold
        1,           // signer count
    ];
    pb.extend_from_slice(&(signer.len() as u16).to_be_bytes());
    pb.extend_from_slice(&signer);
    pb.push(ticker.len() as u8);
    pb.extend_from_slice(ticker.as_bytes());
    pb.extend_from_slice(&(alias.len() as u16).to_be_bytes());
    pb.extend_from_slice(alias.as_bytes());
    pb.push(2); // decimals
    pb.extend_from_slice(&1_000_000u128.to_be_bytes());
    pb.extend_from_slice(&1_000u128.to_be_bytes());
    pb.extend_from_slice(&0u16.to_be_bytes()); // description
    pb.extend_from_slice(&0u16.to_be_bytes()); // icon
    pb.push(0); // ALLOWLIST_KIND_NONE
    pb.extend_from_slice(&0u16.to_be_bytes());

    let proto = generated::TokenPolicyV3 { policy_bytes: pb }.encode_to_vec();
    let anchor =
        dsm::crypto::blake3::domain_hash_bytes(dsm::common::domain_tags::TAG_DSM_POLICY, &proto);
    token_registry::upsert_policy(&anchor, &proto).expect("publish policy bytes");
    anchor
}

/// EVERY token query route must be reachable through the production dispatcher.
///
/// This exact failure has now happened twice: the handler arm exists inside
/// `token_routes.rs` while `app_router_impl`'s query match does not name it, so
/// on device the call returns "unknown query path" and the feature is dead
/// while every unit test passes. Adding a route without adding it here is the
/// mistake; this enumerates them so the omission fails in CI instead of on a
/// handset.
#[test]
#[serial_test::serial]
fn every_token_query_route_is_reachable_through_the_dispatcher() {
    runtime::dsm_init_runtime();
    let (r, _fleet) = funded_router(0x83);

    for path in [
        "tokens.getPolicy",
        "tokens.listCachedPolicies",
        "tokens.getFeeSchedule",
        "tokens.addByAnchor",
        "token.adoptionQr",
    ] {
        let res = query(&r, path, Vec::new());
        let msg = res.error_message.clone().unwrap_or_default();
        assert!(
            !msg.contains("unknown query path"),
            "{path} is not registered in the production dispatch table: {msg}"
        );
    }
}

/// (1) THE ROUTE MUST BE DISPATCHABLE.
///
/// The handler arm existed in token_routes.rs while app_router_impl's query
/// match list did not name it, so on device every call returned
/// "unknown query path: tokens.addByAnchor". A route the production dispatcher
/// cannot reach is not a route.
#[test]
#[serial_test::serial]
fn the_route_is_reachable_through_the_production_dispatcher() {
    runtime::dsm_init_runtime();
    let (r, _fleet) = funded_router(0x83);

    // Deliberately wrong length: we want the ROUTE's own rejection, which
    // proves dispatch reached it, not the dispatcher's unknown-path error.
    let res = adopt(&r, "ZZZZ");
    let msg = res.error_message.clone().unwrap_or_default();
    assert!(
        !msg.contains("unknown query path"),
        "tokens.addByAnchor is not registered in the production dispatch table: {msg}"
    );
    assert!(
        msg.contains("32 bytes"),
        "expected the route's own length check, got: {msg}"
    );
}

/// (4) Adoption charges no fee and advances no device state.
#[test]
#[serial_test::serial]
fn adoption_costs_no_era_and_does_not_advance_device_state() {
    runtime::dsm_init_runtime();
    let (r, _fleet) = funded_router(0x83);
    let anchor = create_token(&r, "ADOPT");

    let era_before = era(&r);
    let root_before = r.core_sdk.device_head().map(|h| h.root());

    let res = adopt(&r, &anchor_text(&anchor));
    assert!(res.success, "adopt: {:?}", res.error_message);

    assert_eq!(era(&r), era_before, "adoption must not burn any ERA");
    assert_eq!(
        r.core_sdk.device_head().map(|h| h.root()),
        root_before,
        "adoption must not advance the device state"
    );
}

/// (3) An exact duplicate adoption is idempotent, not an error.
#[test]
#[serial_test::serial]
fn adopting_the_same_token_twice_is_idempotent() {
    runtime::dsm_init_runtime();
    let (r, _fleet) = funded_router(0x83);
    let anchor = create_token(&r, "TWICE");

    for attempt in 1..=3 {
        let res = adopt(&r, &anchor_text(&anchor));
        assert!(
            res.success,
            "adoption attempt {attempt} must succeed: {:?}",
            res.error_message
        );
    }
    assert_eq!(
        token_registry::all_tokens().expect("registry").len(),
        1,
        "repeated adoption must not multiply registry rows"
    );
    assert_eq!(
        token_registry::all_policies().expect("policies").len(),
        1,
        "repeated adoption must not multiply policies"
    );
}

/// (5) A policy whose bytes do not hash to the requested anchor is refused.
///
/// This is the same rule creation enforces: a storage node able to return
/// arbitrary bytes under a requested anchor would be DEFINING the policy this
/// device then enforces.
#[test]
#[serial_test::serial]
fn an_anchor_that_resolves_to_nothing_fails_closed() {
    runtime::dsm_init_runtime();
    let (r, _fleet) = funded_router(0x83);

    let res = adopt(&r, &anchor_text(&[0x5A; 32]));
    assert!(!res.success, "an unknown anchor must not adopt anything");
    assert_eq!(
        token_registry::all_tokens().expect("registry").len(),
        0,
        "a failed adoption must leave no registry row"
    );
}

/// (6) An adopted token survives a restart, because it is in the registry
/// rather than in memory.
#[test]
#[serial_test::serial]
fn an_adopted_token_survives_a_restart() {
    runtime::dsm_init_runtime();
    let (r, _fleet) = funded_router(0x83);
    let anchor = create_token(&r, "PERSIST");
    assert!(adopt(&r, &anchor_text(&anchor)).success);

    let before = token_registry::get_token_by_ticker("PERSIST")
        .expect("registry")
        .expect("adopted");

    // A fresh router over the same storage is what a relaunch looks like.
    drop(r);
    let r2 = dsm_sdk::economic_fixtures::restart_router();
    let after = token_registry::get_token_by_ticker("PERSIST")
        .expect("registry")
        .expect("still adopted after restart");

    assert_eq!(before.token_id, after.token_id);
    assert_eq!(
        before.policy_commit, after.policy_commit,
        "the committed policy must be byte-identical across a restart"
    );
    assert_eq!(before.decimals, after.decimals);
    let _ = r2;
}

/// The token id an anchor and ticker derive, exactly as the route derives it.
fn derive_token_id(anchor: &[u8; 32], ticker: &str) -> String {
    let mut h = dsm::crypto::blake3::dsm_domain_hasher(dsm::common::domain_tags::TAG_DSM_TOKEN_ID);
    h.update(anchor);
    h.update(ticker.as_bytes());
    dsm_sdk::util::text_id::encode_base32_crockford(h.finalize().as_bytes())
}

/// A SCANNED payload resolves to the same token a typed anchor does.
///
/// The QR carries the canonical raw anchor plus the ticker and token id it is
/// expected to resolve to. Those are claims, not authority — the anchor still
/// has to hash the fetched policy — but they let a scanner refuse a code whose
/// visible name disagrees with what it would actually add.
#[test]
#[serial_test::serial]
fn a_scanned_payload_adopts_the_same_token_as_the_bare_anchor() {
    runtime::dsm_init_runtime();
    let (r, _fleet) = funded_router(0x83);
    let anchor = create_token(&r, "SCANME");
    let token_id = derive_token_id(&anchor, "SCANME");

    let uri = dsm_sdk::handlers::token_routes::build_adoption_uri(&anchor, "SCANME", &token_id);
    let res = adopt(&r, &uri);
    assert!(res.success, "scanned adopt: {:?}", res.error_message);

    let row = token_registry::get_token_by_ticker("SCANME")
        .expect("registry")
        .expect("token");
    assert_eq!(row.policy_commit, anchor, "same anchor, same token");
    assert_eq!(row.token_id, token_id);
}

/// A payload whose claimed ticker disagrees with the published policy is
/// REFUSED, not silently corrected. The anchor decides which token is adopted,
/// so a mismatch cannot substitute an asset — but it means the user is being
/// shown a different name than the policy carries, and adopting under a name
/// they did not read is not something to do quietly.
#[test]
#[serial_test::serial]
fn a_payload_that_lies_about_its_ticker_is_refused() {
    runtime::dsm_init_runtime();
    let (r, _fleet) = funded_router(0x83);
    let anchor = create_token(&r, "HONEST");
    let token_id = derive_token_id(&anchor, "HONEST");

    let lying = dsm_sdk::handlers::token_routes::build_adoption_uri(&anchor, "NOTREAL", &token_id);
    let res = adopt(&r, &lying);
    assert!(!res.success, "a mismatched ticker must be refused");
    let msg = res.error_message.unwrap_or_default();
    assert!(
        msg.contains("NOTREAL") && msg.contains("HONEST"),
        "the refusal should name both what was claimed and what is published, got: {msg}"
    );
    assert!(
        token_registry::get_token_by_ticker("NOTREAL")
            .expect("registry")
            .is_none(),
        "and must not have registered the name it claimed"
    );
}

/// Likewise a payload whose token id is not the one its own anchor derives.
#[test]
#[serial_test::serial]
fn a_payload_that_lies_about_its_token_id_is_refused() {
    runtime::dsm_init_runtime();
    let (r, _fleet) = funded_router(0x83);
    let anchor = create_token(&r, "IDCHK");

    let lying = dsm_sdk::handlers::token_routes::build_adoption_uri(&anchor, "IDCHK", "WRONGID");
    assert!(
        !adopt(&r, &lying).success,
        "a mismatched token id must be refused"
    );
}
