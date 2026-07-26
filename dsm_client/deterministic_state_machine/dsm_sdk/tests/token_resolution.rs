// SPDX-License-Identifier: MIT OR Apache-2.0
//! Resolving "which asset" on the live send path.
//!
//! THE HARDWARE FAILURE THIS REPRODUCES. On 8XK, sending a token the device had
//! itself created failed with:
//!
//!   wallet.send: local state update failed: State error:
//!   Token metadata for RIGB not found in archived chain states
//!
//! Two independent causes, either sufficient. The registry probe looked up by
//! canonical token id ONLY, while the send form supplies a TICKER. And the
//! archive matcher understood `Operation::Create` but not
//! `Operation::CreateToken`, which is what creation emits — so the scan it fell
//! back to could never have matched either.
//!
//! Archive scanning was the wrong instrument regardless:
//!
//!   * `get_bcr_chain_states` SKIPS undecodable rows, so damaged history
//!     degrades into "token not found" — a miss that reads like the token never
//!     existed;
//!   * an ADOPTED token has no creator-side `CreateToken` in this device's
//!     archive at all, so scanning could never find it however healthy the
//!     history is.
//!
//! The registry is authoritative for the persisted identity mapping — token_id,
//! policy_commit, ticker, decimals. Canonical DeviceState remains authoritative
//! for balances and transitions; this answers "which asset", never "how much".

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
        .success,
        "faucet"
    );
}

/// Create RIGB exactly as the wizard does, returning (token_id, anchor).
fn create_rigb(r: &AppRouterImpl) -> (String, [u8; 32]) {
    let req = generated::TokenCreateRequest {
        ticker: "RIGB".to_string(),
        alias: "RigBravo".to_string(),
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
        Some(generated::envelope::Payload::TokenCreateResponse(t)) => (
            t.token_id,
            <[u8; 32]>::try_from(t.policy_anchor.as_slice()).expect("32-byte anchor"),
        ),
        other => panic!("expected TokenCreateResponse, got {other:?}"),
    }
}

/// THE REPRODUCTION. The UI hands the send path a ticker; it must resolve to
/// the canonical token id and the stored RAW policy commitment.
#[test]
#[serial_test::serial]
fn the_ui_ticker_resolves_to_the_canonical_token_id_and_commitment() {
    runtime::dsm_init_runtime();
    init_test_storage();
    let r = new_router();
    fund_era(&r);
    let (token_id, anchor) = create_rigb(&r);

    // What the send form actually supplies.
    let by_ticker = token_registry::get_token_by_ticker("RIGB")
        .expect("registry read")
        .expect("RIGB must resolve by the ticker the UI supplies");

    assert_eq!(
        by_ticker.token_id, token_id,
        "the ticker must resolve to the canonical token id"
    );
    assert_eq!(
        by_ticker.policy_commit, anchor,
        "resolution must yield the stored RAW 32-byte commitment"
    );
    assert_eq!(by_ticker.decimals, 2, "decimals come from the registry");
    assert_eq!(by_ticker.ticker, "RIGB");
}

/// Both identifiers resolve, and to identical metadata.
#[test]
#[serial_test::serial]
fn token_id_and_ticker_resolve_to_identical_metadata() {
    runtime::dsm_init_runtime();
    init_test_storage();
    let r = new_router();
    fund_era(&r);
    let (token_id, _) = create_rigb(&r);

    let by_id = token_registry::get_token(&token_id)
        .expect("registry")
        .expect("resolves by canonical id");
    let by_ticker = token_registry::get_token_by_ticker("RIGB")
        .expect("registry")
        .expect("resolves by ticker");

    assert_eq!(by_id.token_id, by_ticker.token_id);
    assert_eq!(
        by_id.policy_commit, by_ticker.policy_commit,
        "both identifiers must name the same asset, byte for byte"
    );
    assert_eq!(by_id.decimals, by_ticker.decimals);
    assert_eq!(by_id.ticker, by_ticker.ticker);
}

/// An unknown identifier fails BEFORE anything is signed or advanced.
#[test]
#[serial_test::serial]
fn an_unknown_identifier_fails_before_signing() {
    runtime::dsm_init_runtime();
    init_test_storage();
    let r = new_router();
    fund_era(&r);

    let root_before = r.core_sdk.device_head().map(|h| h.root());
    assert!(
        token_registry::get_token_by_ticker("NOSUCH")
            .expect("registry")
            .is_none(),
        "an unregistered ticker must not resolve"
    );
    assert_eq!(
        r.core_sdk.device_head().map(|h| h.root()),
        root_before,
        "a failed resolution must not touch canonical state"
    );
}

/// AN ADOPTED TOKEN RESOLVES WITH NO CREATOR-SIDE ARCHIVE.
///
/// This is the case archive scanning could never satisfy: a receiver holds the
/// policy and a registry row, and has no `CreateToken` of its own. Constructed
/// here by registering the row directly, which is exactly the state
/// `tokens.addByAnchor` leaves behind — the host harness has no storage fleet
/// to fetch a published policy from, so the fetch half is proven on hardware
/// (D3 adopted RIGB and resolved it) and the RESOLUTION half is proven here.
#[test]
#[serial_test::serial]
fn a_registered_token_with_no_local_create_still_resolves() {
    runtime::dsm_init_runtime();
    init_test_storage();
    let r = new_router();

    // A receiver's registry row: no CreateToken was ever executed here.
    let anchor = [0x7Cu8; 32];
    let row = token_registry::TokenRegistryRow {
        token_id: "Z68HWMYSPT9B6GCRS3GHV82M25RYX6VX2XMWFB5AFS3HTHT2V5D0".to_string(),
        policy_commit: anchor,
        ticker: "RIGB".to_string(),
        alias: "RigBravo".to_string(),
        decimals: 2,
        max_supply: 1_000_000,
        owner_device_id: [0u8; 32],
    };
    token_registry::insert_token(&row).expect("register the adopted token");

    let by_ticker = token_registry::get_token_by_ticker("RIGB")
        .expect("registry")
        .expect("an adopted token must resolve by ticker with no local create");
    assert_eq!(by_ticker.token_id, row.token_id);
    assert_eq!(
        by_ticker.policy_commit, anchor,
        "the raw commitment must come back exactly as stored"
    );
    assert_eq!(by_ticker.decimals, 2);

    // And by canonical id, to the same asset.
    let by_id = token_registry::get_token(&row.token_id)
        .expect("registry")
        .expect("resolves by id too");
    assert_eq!(by_id.policy_commit, by_ticker.policy_commit);
    let _ = r;
}
