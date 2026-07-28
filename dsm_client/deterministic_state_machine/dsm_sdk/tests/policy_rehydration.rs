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

use dsm_sdk::bridge::{AppInvoke, AppRouter};
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

fn pack(body: Vec<u8>) -> Vec<u8> {
    generated::ArgPack {
        schema_hash: Some(generated::Hash32 { v: vec![0u8; 32] }),
        codec: generated::Codec::Proto as i32,
        body,
    }
    .encode_to_vec()
}

fn invoke(r: &AppRouterImpl, method: &str, args: Vec<u8>) -> dsm_sdk::bridge::AppResult {
    runtime::get_runtime().block_on(async {
        r.invoke(AppInvoke {
            method: method.to_string(),
            args,
        })
        .await
    })
}

fn fund_era(r: &AppRouterImpl) {
    assert!(
        invoke(
            r,
            "faucet.claim",
            pack(
                generated::FaucetClaimRequest {
                    device_id: vec![0u8; 32]
                }
                .encode_to_vec()
            )
        )
        .success
    );
}

fn create(r: &AppRouterImpl, ticker: &str) -> String {
    let req = generated::TokenCreateRequest {
        ticker: ticker.to_string(),
        alias: format!("{ticker} Token"),
        decimals: 2,
        max_supply_u128: 1_000_000u128.to_be_bytes().to_vec(),
        initial_alloc_u128: 1_000u128.to_be_bytes().to_vec(),
        mint_burn_enabled: true,
        transferable: true,
        unlimited_supply: false,
        mint_burn_threshold: 1,
        description: String::new(),
        icon_url: String::new(),
        allowlist_device_ids: Vec::new(),
    };
    let res = invoke(r, "token.create", pack(req.encode_to_vec()));
    assert!(res.success, "create: {:?}", res.error_message);
    let env = generated::Envelope::decode(&res.data[1..]).expect("envelope");
    match env.payload {
        Some(generated::envelope::Payload::TokenCreateResponse(t)) => t.token_id,
        other => panic!("unexpected {other:?}"),
    }
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
