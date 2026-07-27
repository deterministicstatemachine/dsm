// SPDX-License-Identifier: MIT OR Apache-2.0
//! Dropping a token's identity, so a superseded ticker can be adopted again.
//!
//! A ticker names one token: adopting a token whose ticker is already claimed
//! by a DIFFERENT one is refused, because "RIGB" meaning two assets would let
//! a transfer credit the wrong one. That guard is right.
//!
//! With no way to drop an identity it was also a dead end. On the rig, D3 had
//! adopted a RIGB that was later superseded — the creating device was wiped
//! and re-created the token, which produced a different policy anchor and
//! therefore a different token id. D3 was then permanently unable to adopt the
//! RIGB that actually existed, and the wallet offered no way out.
//!
//! Forgetting removes the NAMING only. Canonical balances are untouched and
//! decide whether it is allowed: a device must not be able to make an asset it
//! still holds unnameable. Nothing recoverable is lost — the policy is
//! content-addressed and adoption is online, so the same token can be adopted
//! again from its anchor.

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

fn forget(r: &AppRouterImpl, key: &str) -> dsm_sdk::bridge::AppResult {
    invoke(
        r,
        "token.forget",
        pack(
            generated::TokenForgetRequest {
                token_id: key.to_string(),
            }
            .encode_to_vec(),
        ),
    )
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

/// Register an identity the way ADOPTION does: a row and its anchored policy,
/// with no balance and no local creation.
fn adopt(ticker: &str, policy_bytes: &[u8]) -> String {
    let commit = dsm::crypto::blake3::domain_hash_bytes(
        dsm::common::domain_tags::TAG_DSM_POLICY,
        policy_bytes,
    );
    token_registry::upsert_policy(&commit, policy_bytes).expect("store policy");
    // token_id = BLAKE3(TAG_DSM_TOKEN_ID, policy_anchor ‖ ticker), as the
    // protocol derives it — so a different policy really is a different token.
    let mut h = dsm::crypto::blake3::dsm_domain_hasher(dsm::common::domain_tags::TAG_DSM_TOKEN_ID);
    h.update(&commit);
    h.update(ticker.as_bytes());
    let token_id = dsm_sdk::util::text_id::encode_base32_crockford(h.finalize().as_bytes());
    token_registry::insert_token(&token_registry::TokenRegistryRow {
        token_id: token_id.clone(),
        policy_commit: commit,
        ticker: ticker.to_string(),
        alias: format!("{ticker} Token"),
        decimals: 2,
        max_supply: 1_000_000,
        owner_device_id: [0x11; 32],
    })
    .expect("register");
    token_id
}

/// THE REPRODUCTION: a superseded identity is dropped and the ticker frees up.
#[test]
#[serial_test::serial]
fn forgetting_a_zero_balance_token_frees_its_ticker() {
    runtime::dsm_init_runtime();
    init_test_storage();
    let r = new_router();
    let stale = adopt("RIGB", b"the-superseded-policy");

    let res = forget(&r, "RIGB");
    assert!(res.success, "forget failed: {:?}", res.error_message);
    assert!(
        token_registry::get_token(&stale).expect("read").is_none(),
        "the identity row must be gone"
    );
    assert!(
        token_registry::get_token_by_ticker("RIGB")
            .expect("read")
            .is_none(),
        "and the ticker must be free"
    );

    // The ticker is adoptable again — by a DIFFERENT token, which is the whole
    // point: this is the case that was previously a permanent dead end.
    let fresh = adopt("RIGB", b"the-current-policy");
    assert_ne!(fresh, stale, "a different policy is a different token");
    assert_eq!(
        token_registry::get_token_by_ticker("RIGB")
            .expect("read")
            .expect("row")
            .token_id,
        fresh
    );
}

/// A HELD token must not be forgettable: making an asset you own unnameable
/// would strand it. Canonical state decides, not the registry.
#[test]
#[serial_test::serial]
fn a_token_with_a_balance_cannot_be_forgotten() {
    runtime::dsm_init_runtime();
    init_test_storage();
    let r = new_router();
    r.install_policy_resolver();
    fund_era(&r);

    // Create a token so this device actually holds it.
    let create = invoke(
        &r,
        "token.create",
        pack(
            generated::TokenCreateRequest {
                ticker: "HELD".into(),
                alias: "Held".into(),
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
            }
            .encode_to_vec(),
        ),
    );
    assert!(create.success, "create: {:?}", create.error_message);

    let res = forget(&r, "HELD");
    assert!(!res.success, "a held token must not be forgettable");
    let msg = res.error_message.unwrap_or_default();
    assert!(
        msg.contains("100000") && msg.to_lowercase().contains("still holds"),
        "the refusal should name the held base units, got: {msg}"
    );
    assert!(
        token_registry::get_token_by_ticker("HELD")
            .expect("read")
            .is_some(),
        "and the row must survive the refusal"
    );
}

/// Protocol assets are not adopted identities and are never forgettable.
#[test]
#[serial_test::serial]
fn builtin_tokens_cannot_be_forgotten() {
    runtime::dsm_init_runtime();
    init_test_storage();
    let r = new_router();

    for builtin in ["ERA", "dBTC"] {
        let res = forget(&r, builtin);
        assert!(!res.success, "{builtin} must not be forgettable");
        assert!(
            res.error_message
                .unwrap_or_default()
                .contains("protocol asset"),
            "the refusal should say why"
        );
    }
}

/// Forgetting something absent is an error, not a silent success — otherwise a
/// typo would report that a token the user can still see was removed.
#[test]
#[serial_test::serial]
fn forgetting_an_unknown_token_is_refused() {
    runtime::dsm_init_runtime();
    init_test_storage();
    let r = new_router();

    let res = forget(&r, "NEVERSEEN");
    assert!(!res.success);
    let m = res.error_message.unwrap_or_default();
    eprintln!("ACTUAL ERROR: {m}");
    assert!(m.contains("no token named"), "got: {m}");
}

/// It works by token id as well as by ticker.
#[test]
#[serial_test::serial]
fn a_token_can_be_forgotten_by_its_id() {
    runtime::dsm_init_runtime();
    init_test_storage();
    let r = new_router();
    let id = adopt("BYID", b"byid-policy");

    assert!(forget(&r, &id).success);
    assert!(token_registry::get_token(&id).expect("read").is_none());
}
