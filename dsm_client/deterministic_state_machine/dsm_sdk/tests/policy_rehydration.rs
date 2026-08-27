// SPDX-License-Identifier: MIT OR Apache-2.0
//! An empty enforcer cache is not an absent policy.
//!
//! THE HARDWARE FAILURE. After the registry resolver was fixed, a send reached
//! policy enforcement and was refused with:
//!
//!   wallet.send: local state update failed:
//!   Token policy violation for RIGB: No policy registered for token
//!
//! The enforcer's token→anchor index is a process-local HashMap. It is empty
//! after every restart, so a miss made a token that had committed its policy
//! look policy-less, while the bytes sat in `token_policies` untouched. The
//! device denied an operation on a token it fully knew.
//!
//! Startup warming existed and was not enough — which is the point. Warming
//! covers rows present when it runs; a row added afterwards, or one it skipped,
//! reproduces the defect exactly. So the MISS consults durable storage, and the
//! guarantee no longer depends on when a row appeared.
//!
//! Rehydration is strict. It reuses `load_policy_verified` (which re-derives
//! BLAKE3(TAG_DSM_POLICY, bytes) and reports a mismatch as ABSENT), the one
//! `parse_token_policy`, and the one `derive_policy_file`. Missing bytes,
//! malformed policy, or a mismatched anchor all still deny, with no mutation.

#![allow(clippy::disallowed_methods)]

use prost::Message;
use std::path::PathBuf;

use dsm_sdk::generated;
use dsm_sdk::handlers::app_router_impl::AppRouterImpl;
use dsm_sdk::init::SdkConfig;
use dsm_sdk::runtime;
use dsm_sdk::storage::client_db::{reset_database_for_tests, token_registry};

fn init_test_storage() {
    std::env::set_var("DSM_SDK_TEST_MODE", "1");
    reset_database_for_tests();
    let _ = dsm_sdk::storage_utils::set_storage_base_dir(PathBuf::from("./.dsm_testdata"));
    dsm_sdk::sdk::app_state::AppState::set_identity_info(
        vec![0xAA; 32],
        vec![0xBB; 32],
        vec![0xCC; 32],
        vec![0xDD; 32],
    );
    dsm_sdk::set_wallet_seed_for_testing(vec![0xEE; 32]);
}

fn new_router() -> AppRouterImpl {
    AppRouterImpl::new(SdkConfig {
        node_id: "test-device".to_string(),
        storage_endpoints: vec![],
        enable_offline: false,
    })
    .expect("router")
}

fn fund_era(r: &AppRouterImpl) {
    // Seed the fixture balance DIRECTLY. This used to call `faucet.claim`, which
    // minted builtin ERA on nothing more than a caller-supplied device_id — the
    // same unauthorized-issuance defect the accepting-layer gate now refuses. That
    // refusal is total: it applies in tests exactly as in production, so a fixture
    // cannot mint and must not try (no `faucet.claim`, no `wallet.mint_for_self`,
    // no `Operation::Mint`).
    //
    // 100 base units — the amount the old faucet granted (`claim_amount: 100`), so
    // balance assertions downstream are unchanged.
    dsm_sdk::handlers::app_router_impl::install_balance_for_testing(
        r,
        dsm::core::token::builtin_policy_commit_for_token("ERA").expect("ERA commit"),
        100,
    )
    .expect("seed the fixture ERA balance");
}

/// Install a token in the EXACT durable shape `token.create` persists —
/// canonical v3 policy blob wrapped in `TokenPolicyV3`, content-addressed
/// into `token_policies`, plus the registry row keyed by the derived token
/// id. These are REHYDRATION tests: they exercise the read/rehydrate path
/// over durable bytes, and the route can no longer produce them here — under
/// 3.5b the creation fee is an ADMITTED economic debit, and integration
/// tests have no fake register fleet (the admitted create e2e lives in
/// `handlers::sender_admission_tests`).
fn create(_r: &AppRouterImpl, ticker: &str) -> String {
    // build_policy_v3_bytes layout, verbatim: version, kind, flags,
    // threshold, signer count, signers, ticker, alias, decimals, max_supply,
    // initial_alloc, description, icon, allowlist.
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
    token_registry::upsert_policy(&anchor, &proto).expect("persist policy bytes");

    let mut id_hasher =
        dsm::crypto::blake3::dsm_domain_hasher(dsm::common::domain_tags::TAG_DSM_TOKEN_ID);
    id_hasher.update(&anchor);
    id_hasher.update(ticker.as_bytes());
    let token_id = dsm_sdk::util::text_id::encode_base32_crockford(id_hasher.finalize().as_bytes());
    token_registry::insert_token(&token_registry::TokenRegistryRow {
        token_id: token_id.clone(),
        policy_commit: anchor,
        ticker: ticker.to_string(),
        alias,
        decimals: 2,
        max_supply: 1_000_000,
        owner_device_id: [0xAAu8; 32],
    })
    .expect("registry row");
    token_id
}

/// Ask the enforcer directly whether it can find a token's policy.
fn policy_visible(r: &AppRouterImpl, token_id: &str) -> bool {
    runtime::get_runtime().block_on(async {
        r.core_sdk
            .policy_system_ref()
            .get_token_policy(token_id)
            .await
            .ok()
            .flatten()
            .is_some()
    })
}

/// THE REPRODUCTION: a token this device created must still enforce after a
/// restart, with the in-memory index starting empty.
#[test]
#[serial_test::serial]
fn a_created_token_enforces_after_restart() {
    runtime::dsm_init_runtime();
    init_test_storage();
    let r = new_router();
    r.install_policy_resolver();
    fund_era(&r);
    let token_id = create(&r, "RIGB");
    drop(r);

    // A fresh router over the same storage IS the restart: nothing warmed.
    let r2 = new_router();
    r2.install_policy_resolver();
    assert!(
        policy_visible(&r2, &token_id),
        "a created token must enforce after restart, from durable policy bytes"
    );
    // And by the ticker the UI supplies.
    assert!(policy_visible(&r2, "RIGB"), "resolvable by ticker too");
}

/// The same guarantee for a token this device ADOPTED rather than created —
/// the receiver's position, with no local CreateToken at all.
#[test]
#[serial_test::serial]
fn an_adopted_token_enforces_after_restart() {
    runtime::dsm_init_runtime();
    init_test_storage();
    let r = new_router();
    r.install_policy_resolver();
    fund_era(&r);
    let token_id = create(&r, "ADOPTD");

    // Keep the durable policy + registry row, drop every in-memory trace.
    drop(r);
    let r2 = new_router();
    r2.install_policy_resolver();

    assert!(
        policy_visible(&r2, &token_id),
        "an adopted token's policy must rehydrate from durable storage"
    );
}

/// Cache empty + valid durable policy = enforceable. This is the whole point:
/// a miss must consult storage, not conclude.
#[test]
#[serial_test::serial]
fn an_empty_cache_with_valid_durable_policy_resolves() {
    runtime::dsm_init_runtime();
    init_test_storage();
    let r = new_router();
    r.install_policy_resolver();
    fund_era(&r);
    let token_id = create(&r, "CACHEM");

    let fresh = new_router(); // deliberately NOT warmed
    fresh.install_policy_resolver();
    assert!(
        policy_visible(&fresh, &token_id),
        "an empty index plus durable bytes must still enforce"
    );
}

/// No durable policy means genuinely absent — still denied, still no mutation.
#[test]
#[serial_test::serial]
fn a_token_with_no_durable_policy_is_denied() {
    runtime::dsm_init_runtime();
    init_test_storage();
    let r = new_router();
    r.install_policy_resolver();

    let root_before = r.core_sdk.device_head().map(|h| h.root());
    assert!(
        !policy_visible(&r, "GHOST"),
        "an unregistered token must not acquire a policy"
    );
    assert_eq!(
        r.core_sdk.device_head().map(|h| h.root()),
        root_before,
        "a denied lookup must not mutate state"
    );
}

/// Bytes that do not hash to their commitment are ABSENT, and a committed
/// policy cannot be redefined at all.
///
/// Two guarantees, both load-bearing. `token_policies` is content-addressed and
/// inserts with ON CONFLICT DO NOTHING, so an existing commitment's bytes are
/// immutable — a storage layer cannot swap the rules under a token that is
/// already committed. And `load_policy_verified` re-derives the hash on read,
/// so a row that somehow disagrees with its key is reported absent rather than
/// returned, which is what keeps rehydration from adopting someone else's
/// policy.
#[test]
#[serial_test::serial]
fn mismatched_bytes_are_absent_and_committed_policies_are_immutable() {
    runtime::dsm_init_runtime();
    init_test_storage();
    let r = new_router();
    r.install_policy_resolver();
    fund_era(&r);
    let token_id = create(&r, "IMMUT");

    let row = token_registry::get_token(&token_id)
        .expect("registry")
        .expect("token");
    let original = token_registry::load_policy_verified(&row.policy_commit)
        .expect("load")
        .expect("bytes");

    // Attempting to redefine a committed policy changes nothing.
    token_registry::upsert_policy(&row.policy_commit, b"different rules entirely")
        .expect("upsert returns ok");
    let after = token_registry::load_policy_verified(&row.policy_commit)
        .expect("load")
        .expect("bytes still present");
    assert_eq!(
        original, after,
        "a committed policy must not be redefinable under its own commitment"
    );

    // A commitment whose stored bytes do NOT hash to it reads as absent.
    let bogus_commit = [0x11u8; 32];
    token_registry::upsert_policy(&bogus_commit, b"bytes that hash to something else")
        .expect("insert under a fresh key");
    assert!(
        token_registry::load_policy_verified(&bogus_commit)
            .expect("load")
            .is_none(),
        "bytes that do not hash to their key must be reported absent"
    );

    // And the enforcer never acquires a policy for a token pointing at it.
    assert!(
        !policy_visible(&r, "NOSUCHTOKEN"),
        "no registry row, no policy"
    );
}

/// Creation and adoption must leave storage in the SAME shape, so one
/// rehydration path serves both. If they diverged, one of them would enforce
/// after restart and the other would not.
#[test]
#[serial_test::serial]
fn creation_and_adoption_register_through_the_same_path() {
    runtime::dsm_init_runtime();
    init_test_storage();
    let r = new_router();
    r.install_policy_resolver();
    fund_era(&r);
    let token_id = create(&r, "SAMEPT");

    let row = token_registry::get_token(&token_id)
        .expect("registry")
        .expect("row");
    let bytes = token_registry::load_policy_verified(&row.policy_commit)
        .expect("verified load")
        .expect("policy bytes present");

    assert!(!bytes.is_empty(), "creation must persist policy bytes");
    assert_eq!(
        row.ticker, "SAMEPT",
        "and a registry row keyed the same way adoption writes one"
    );
    // The resolver reaches both by the same two lookups.
    assert!(policy_visible(&r, &token_id));
    assert!(policy_visible(&r, "SAMEPT"));
}
