// SPDX-License-Identifier: MIT OR Apache-2.0
#![allow(clippy::disallowed_methods)]

//! Route contract for the ticket-model ERA faucet.
//!
//! `faucet.claim` is orchestration only: it derives the committed network from
//! the STORED genesis record and drives the deterministic claim flow (ticket
//! win → fence-coupled advance → evidence publication → root registration →
//! foreign-verifier validation). The full lifecycle is exercised end to end in
//! `handlers::faucet_flow_tests` over the fake registers; what this file pins
//! is the route boundary itself:
//!
//! - a device WITHOUT a stored genesis record cannot claim, and the refusal
//!   names that — the committed network comes from the record, never from the
//!   caller, so its absence must fail closed rather than default a network;
//! - `faucet.check_nearby` advertises availability (the ticket model has no
//!   cooldown and no "nearby"), naming the fixed per-claim payout.

use prost::Message;

use dsm_sdk::bridge::{AppInvoke, AppQuery, AppRouter};
use dsm_sdk::generated;
use dsm_sdk::handlers::app_router_impl::AppRouterImpl;
use dsm_sdk::init::SdkConfig;
use dsm_sdk::runtime;
use dsm_sdk::storage::client_db::reset_database_for_tests;
use std::path::PathBuf;

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

fn router() -> AppRouterImpl {
    runtime::dsm_init_runtime();
    init_test_storage();
    AppRouterImpl::new(SdkConfig {
        node_id: "test-device".to_string(),
        storage_endpoints: vec![],
        enable_offline: false,
    })
    .expect("AppRouterImpl::new should succeed in test")
}

fn pack(body: Vec<u8>) -> Vec<u8> {
    generated::ArgPack {
        schema_hash: Some(generated::Hash32 { v: vec![0u8; 32] }),
        codec: generated::Codec::Proto as i32,
        body,
    }
    .encode_to_vec()
}

fn claim_request() -> Vec<u8> {
    pack(
        generated::FaucetClaimRequest {
            device_id: vec![0u8; 32],
        }
        .encode_to_vec(),
    )
}

/// `faucet.claim` with no stored genesis record fails closed, naming the record.
///
/// The committed network is read from the genesis record the identity flow
/// persisted — the caller never chooses it. Asserting on the SPECIFIC reason
/// matters: a bare `!success` would pass just as happily if the route broke for
/// an unrelated reason.
#[test]
#[serial_test::serial]
fn faucet_claim_without_a_stored_genesis_record_fails_closed_naming_it() {
    let r = router();
    let res = runtime::get_runtime().block_on(async {
        r.invoke(AppInvoke {
            method: "faucet.claim".to_string(),
            args: claim_request(),
        })
        .await
    });

    assert!(
        !res.success,
        "a claim must not proceed without the committed network"
    );
    let msg = res.error_message.unwrap_or_default();
    assert!(
        msg.contains("no stored genesis record"),
        "the refusal must name the missing genesis record, got: {msg}"
    );
}

/// `faucet.check_nearby` advertises availability and the fixed payout.
///
/// The ticket model has no cooldown and no proximity: availability is "the
/// flow is wired and the device has an identity". A check that reported
/// unavailable while claims succeed would read like an outage.
#[test]
#[serial_test::serial]
fn faucet_check_nearby_advertises_the_fixed_payout() {
    let r = router();
    let res = runtime::get_runtime().block_on(async {
        r.query(AppQuery {
            path: "faucet.check_nearby".to_string(),
            params: claim_request(),
        })
        .await
    });

    assert!(res.success, "the check itself must answer");
    let env = generated::Envelope::decode(&res.data[1..]).expect("envelope");
    match env.payload {
        Some(generated::envelope::Payload::FaucetClaimResponse(f)) => {
            assert!(f.success, "the ticket faucet is available");
            assert_eq!(f.tokens_received, 0, "the check grants nothing");
            assert!(
                f.message.contains("100"),
                "must name the fixed per-claim payout, got: {}",
                f.message
            );
        }
        other => panic!("unexpected payload {other:?}"),
    }
}
