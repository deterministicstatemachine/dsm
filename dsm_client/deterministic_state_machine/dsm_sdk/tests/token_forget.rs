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
use dsm_sdk::runtime;
use dsm_sdk::storage::client_db::token_registry;

/// A router on a REAL testnet identity, funded through a REAL faucet admission.
///
/// Replaces the old `init_test_storage()` + `new_router()` pair, which installed
/// a fabricated identity ([0xAA;32] / [0xBB;32] / [0xCC;32], no genesis record)
/// and then wrote a balance straight onto the head. That balance
/// had no economic lineage, and because debits are not fenced it was fully
/// spendable through canonical acceptance.
fn funded_router() -> (AppRouterImpl, dsm_sdk::economic_fixtures::FleetGuard) {
    let _ = dsm_sdk::storage_utils::set_storage_base_dir(PathBuf::from("./.dsm_testdata"));
    dsm_sdk::economic_fixtures::funded_router(0x71)
}

/// The same, with no ERA. For tests that never spend.
fn empty_router() -> (AppRouterImpl, dsm_sdk::economic_fixtures::FleetGuard) {
    let _ = dsm_sdk::storage_utils::set_storage_base_dir(PathBuf::from("./.dsm_testdata"));
    dsm_sdk::economic_fixtures::empty_router(0x71)
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
    let (r, _fleet) = empty_router();
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
    let (r, _fleet) = funded_router();
    r.install_policy_resolver();

    // Hold the token the LEGITIMATE way: create it and mint into it, both
    // admitted. The previous fixture adopted a registry row and then wrote the
    // balance straight onto the head, justified by "the fee is an admitted
    // debit integration tests cannot run" — no longer true. The forget rule
    // reads canonical holdings, and now they are canonical.
    dsm_sdk::economic_fixtures::mint_asset(&r, "HELD", 0, 100_000);

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
    let (r, _fleet) = empty_router();

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
    let (r, _fleet) = empty_router();

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
    let (r, _fleet) = empty_router();
    let id = adopt("BYID", b"byid-policy");

    assert!(forget(&r, &id).success);
    assert!(token_registry::get_token(&id).expect("read").is_none());
}
