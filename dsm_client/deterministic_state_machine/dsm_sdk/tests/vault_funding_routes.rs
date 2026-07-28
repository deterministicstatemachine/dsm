// SPDX-License-Identifier: MIT OR Apache-2.0
//! Vault funding and advertisement, through the production routes.
//!
//! This is the route-level half of the declared-reserves removal. The in-module
//! tests prove the accounting; these prove the HANDLERS enforce it — that a
//! device cannot advertise liquidity it never encumbered, and that settlement
//! stays unreachable while a settling device has no authenticated reserves to
//! verify against.
//!
//! Every assertion here goes through `AppRouter`, so a route that is implemented
//! but never registered in `app_router_impl`'s dispatch table fails here rather
//! than on a handset. That omission has now happened twice.

#![allow(clippy::disallowed_methods)]

use prost::Message;
use std::path::PathBuf;

use dsm_sdk::bridge::{AppInvoke, AppQuery, AppRouter};
use dsm_sdk::generated;
use dsm_sdk::handlers::app_router_impl::AppRouterImpl;
use dsm_sdk::init::SdkConfig;
use dsm_sdk::runtime;
use dsm_sdk::storage::client_db::reset_database_for_tests;

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
        node_id: "vault-funding-test".to_string(),
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

fn query(r: &AppRouterImpl, path: &str, params: Vec<u8>) -> dsm_sdk::bridge::AppResult {
    runtime::get_runtime().block_on(async {
        r.query(AppQuery {
            path: path.to_string(),
            params,
        })
        .await
    })
}

/// (4) AN ADVERTISEMENT MUST DESCRIBE ENCUMBERED FUNDS.
///
/// The request's reserve fields are reserved in the proto precisely so a client
/// cannot state its own liquidity, and the handler reads the owner's reserve
/// leaves instead. A vault holding nothing must therefore be unadvertisable —
/// otherwise "reserves" would still be a number a caller supplied, which is the
/// whole condition this cut removes.
#[test]
#[serial_test::serial]
fn an_unfunded_vault_cannot_be_advertised() {
    runtime::dsm_init_runtime();
    init_test_storage();
    let r = new_router();

    let req = generated::PublishRoutingAdvertisementRequest {
        vault_id: vec![0x77u8; 32],
        token_a: vec![0xA1u8; 32],
        token_b: vec![0xB2u8; 32],
        fee_bps: 30,
        unlock_spec_digest: vec![0u8; 32],
        unlock_spec_key: "sofi/spec/test".to_string(),
        owner_public_key: vec![0xABu8; 64],
        ..Default::default()
    };
    let res = invoke(
        &r,
        "route.publishRoutingAdvertisement",
        pack(req.encode_to_vec()),
    );
    assert!(!res.success, "an unfunded vault must not be advertisable");
    let msg = res.error_message.unwrap_or_default();
    assert!(
        msg.contains("no encumbered reserves") || msg.contains("fund it"),
        "the refusal should say the vault holds nothing, got: {msg}"
    );
}

/// A ticker cannot name a reserve leaf, so the pair must be policy commits.
///
/// This is what forces vault pair identity to be the canonical token identity
/// rather than UTF-8 label bytes: two different tokens can share a ticker, and
/// a reserve keyed by a label would be unattributable.
#[test]
#[serial_test::serial]
fn an_advertisement_pair_must_be_policy_commits_not_labels() {
    runtime::dsm_init_runtime();
    init_test_storage();
    let r = new_router();

    let req = generated::PublishRoutingAdvertisementRequest {
        vault_id: vec![0x77u8; 32],
        token_a: b"DEMO_AAA".to_vec(),
        token_b: b"DEMO_BBB".to_vec(),
        fee_bps: 30,
        unlock_spec_digest: vec![0u8; 32],
        unlock_spec_key: "sofi/spec/test".to_string(),
        owner_public_key: vec![0xABu8; 64],
        ..Default::default()
    };
    let res = invoke(
        &r,
        "route.publishRoutingAdvertisement",
        pack(req.encode_to_vec()),
    );
    assert!(!res.success, "label bytes must not be accepted as a pair");
    let msg = res.error_message.unwrap_or_default();
    assert!(
        msg.contains("32-byte policy commits") || msg.contains("not an identity"),
        "the refusal should say why a ticker will not do, got: {msg}"
    );
}

/// (7) SETTLEMENT IS UNREACHABLE, EXPLICITLY.
///
/// A settling device has no local reserves — they are encumbered leaves in the
/// OWNER's device SMT, proved by a `VaultReserveInclusionProofV1` that does not
/// exist yet. The route must say so and refuse, rather than verify a hop against
/// a fabricated zero and let it bind to reserves nobody holds.
#[test]
#[serial_test::serial]
fn routed_settlement_refuses_until_reserve_proofs_exist() {
    runtime::dsm_init_runtime();
    init_test_storage();
    let r = new_router();

    let req = generated::DlvUnlockRoutedV1 {
        vault_id: vec![0x77u8; 32],
        device_id: vec![0xD0u8; 32],
        route_commit_bytes: Vec::new(),
        unlocker_public_key: vec![0xABu8; 64],
        signature: Vec::new(),
    };
    let res = invoke(&r, "dlv.unlockRouted", pack(req.encode_to_vec()));
    assert!(!res.success, "settlement must not proceed");
}

/// A funding leg naming a token this device cannot resolve fails closed rather
/// than encumbering an asset it cannot name.
#[test]
#[serial_test::serial]
fn a_funding_leg_for_an_unknown_token_fails_closed() {
    runtime::dsm_init_runtime();
    init_test_storage();
    let r = new_router();

    let spec = generated::DlvSpecV1 {
        policy_digest: vec![0x11u8; 32],
        ..Default::default()
    };
    let req = generated::DlvInstantiateV1 {
        spec: Some(spec),
        creator_public_key: vec![0xABu8; 64],
        signature: Vec::new(),
        funding_legs: vec![generated::DlvFundingLegV1 {
            token_id: b"NEVERSEEN".to_vec(),
            amount: 1_000,
        }],
    };
    let res = invoke(&r, "dlv.create", pack(req.encode_to_vec()));
    assert!(!res.success, "an unresolvable funding leg must be refused");
}

/// The routes this file exercises must be reachable through the production
/// dispatcher. A handler arm that the router does not name is a dead feature
/// that every unit test still passes.
#[test]
#[serial_test::serial]
fn the_vault_routes_are_reachable_through_the_dispatcher() {
    runtime::dsm_init_runtime();
    init_test_storage();
    let r = new_router();

    for method in [
        "dlv.create",
        "dlv.unlockRouted",
        "route.publishRoutingAdvertisement",
    ] {
        let msg = invoke(&r, method, Vec::new())
            .error_message
            .unwrap_or_default();
        assert!(
            !msg.contains("unknown invoke method"),
            "{method} is not registered in the production dispatch table: {msg}"
        );
    }
    for path in ["dlv.listOwnedAmmVaults", "dlv.getVaultStateAnchor"] {
        let msg = query(&r, path, Vec::new())
            .error_message
            .unwrap_or_default();
        assert!(
            !msg.contains("unknown query path"),
            "{path} is not registered in the production dispatch table: {msg}"
        );
    }
}
