// SPDX-License-Identifier: MIT OR Apache-2.0
//! THE dBTC PUBLIC-WITNESS FENCE, driven through the real route dispatch.
//!
//! `dbtc_public_data_attack.rs` proves the defect exists. This file proves the
//! fence actually closes it — at every door that manufactures a Bitcoin output
//! behind a publicly-derivable key, and at no door that moves value out of one.
//!
//! Three manufacturing doors, each refusing INDEPENDENTLY:
//!
//! ```text
//! bitcoin.deposit.initiate             open_tap() mints the tap
//! bitcoin.deposit.fund_and_broadcast   puts BTC behind it
//! bitcoin.fractional.exit              pour_partial() re-locks the remainder
//!                                      into a SUCCESSOR tap with the same
//!                                      defect (its fresh deposit_nonce is
//!                                      OsRng, but the advertisement PUBLISHES
//!                                      it and rejects an empty one)
//! ```
//!
//! Independence matters: a fence on tap creation is not a fence on funding, and
//! neither is a fence on successor rotation. Each is a separate way to put
//! satoshis behind a key anyone can derive.
//!
//! MUTATION CONTROL. Delete any one `return err(DBTC_PUBLIC_WITNESS_FENCE...)`
//! and that door's test goes red by reaching real work — the routes are driven
//! with WELL-FORMED requests naming a vault that does not exist, so an unfenced
//! route reports a lookup/validation failure instead of the fence. The
//! `precedes_argument_validation` test pins the ordering from the other side:
//! with empty args an unfenced route reports a decode failure.

#![allow(clippy::disallowed_methods)]

use dsm_sdk::bridge::{AppInvoke, AppRouter as _};
use dsm_sdk::generated;
use dsm_sdk::handlers::AppRouterImpl;
use dsm_sdk::init::SdkConfig;
use prost::Message;
use serial_test::serial;
use std::path::PathBuf;

/// The exact token every fenced door must emit.
const FENCE_TOKEN: &str = "DBTC_PUBLIC_WITNESS_FENCED";

fn router() -> AppRouterImpl {
    std::env::set_var("DSM_SDK_TEST_MODE", "1");
    let _ = dsm_sdk::storage_utils::set_storage_base_dir(PathBuf::from("./.dsm_testdata"));
    dsm_sdk::sdk::app_state::AppState::set_identity_info(
        vec![0xAA; 32],
        vec![0xBB; 32],
        vec![0xCC; 32],
        vec![0xDD; 32],
    );
    dsm_sdk::set_wallet_seed_for_testing(vec![0xEE; 32]);
    AppRouterImpl::new(SdkConfig {
        node_id: "dev-node".to_string(),
        storage_endpoints: vec!["http://127.0.0.1:8080".to_string()],
        enable_offline: true,
    })
    .expect("AppRouterImpl::new should succeed in test")
}

fn pack(body: Vec<u8>) -> Vec<u8> {
    generated::ArgPack {
        schema_hash: None,
        codec: generated::Codec::Proto as i32,
        body,
    }
    .encode_to_vec()
}

async fn invoke(method: &str, args: Vec<u8>) -> (bool, String) {
    let res = router()
        .invoke(AppInvoke {
            method: method.into(),
            args,
        })
        .await;
    let msg = res.error_message.clone().unwrap_or_default();
    (res.success, msg)
}

/// A well-formed BTC->dBTC deposit request. Nothing about it is malformed: if
/// the fence were absent this would proceed to mint a tap.
fn well_formed_deposit() -> Vec<u8> {
    pack(
        generated::DepositRequest {
            vault_op_id: "fence-probe-vault".to_string(),
            direction: "btc_to_dsm".to_string(),
            dsm_amount: 100_000,
            dsm_token_id: "dBTC".to_string(),
            btc_amount_sats: 100_000,
            hash_lock: vec![0x11; 32],
            btc_pubkey: vec![0x02; 33],
            refund_iterations: 144,
            destination_address: String::new(),
            refund_btc_pubkey: vec![0x03; 33],
        }
        .encode_to_vec(),
    )
}

/// DOOR 1 — tap creation.
#[tokio::test]
#[serial]
async fn deposit_initiate_is_fenced() {
    let (ok, msg) = invoke("bitcoin.deposit.initiate", well_formed_deposit()).await;
    assert!(!ok, "tap creation must not succeed while fenced");
    assert!(
        msg.contains(FENCE_TOKEN),
        "deposit.initiate must refuse by name; got: {msg}"
    );
}

/// DOOR 2 — funding an existing tap. Fences INDEPENDENTLY of door 1: a tap
/// record created before the fence (or restored from a backup) must still not
/// be able to lock BTC behind a publicly-derivable key.
///
/// The named vault does not exist, so an unfenced route reports "deposit not
/// found" — that difference is the mutation signal.
#[tokio::test]
#[serial]
async fn fund_and_broadcast_is_fenced_independently() {
    let args = pack(
        generated::DepositRefundRequest {
            vault_op_id: "fence-probe-vault".to_string(),
        }
        .encode_to_vec(),
    );
    let (ok, msg) = invoke("bitcoin.deposit.fund_and_broadcast", args).await;
    assert!(!ok, "funding must not succeed while fenced");
    assert!(
        msg.contains(FENCE_TOKEN),
        "fund_and_broadcast must refuse by name, NOT fall through to a vault \
         lookup; got: {msg}"
    );
    assert!(
        !msg.contains("deposit not found"),
        "the fence must precede the vault lookup, or a real vault would be \
         funded; got: {msg}"
    );
}

/// DOOR 3 — successor rotation. A partial exit is also a manufacturing door,
/// and this one is not in the original threat write-up: `pour_partial()` pays
/// the remainder into a successor P2WSH whose claim key derives from the same
/// public chain, then broadcasts that funding transaction.
#[tokio::test]
#[serial]
async fn fractional_exit_is_fenced_and_names_the_alternative() {
    let args = pack(
        generated::BitcoinFractionalExitRequest {
            source_vault_id: "fence-probe-vault".to_string(),
            exit_amount_sats: 50_000,
            successor_locktime: 0,
            refund_iterations: 144,
            destination_address: "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".to_string(),
            plan_id: "fence-probe-plan".to_string(),
        }
        .encode_to_vec(),
    );
    let (ok, msg) = invoke("bitcoin.fractional.exit", args).await;
    assert!(!ok, "successor rotation must not succeed while fenced");
    assert!(
        msg.contains(FENCE_TOKEN),
        "fractional.exit must refuse by name; got: {msg}"
    );
    assert!(
        msg.contains("bitcoin.full.sweep"),
        "a fenced partial exit must point at the unfenced full exit so funds \
         are never stranded; got: {msg}"
    );
}

/// ORDERING. The fence is the first statement in each arm, so no crafted input
/// reaches any code path that could act. Empty args would fail to decode on an
/// unfenced route; the fence must win instead.
#[tokio::test]
#[serial]
async fn the_fence_precedes_argument_validation() {
    for method in [
        "bitcoin.deposit.initiate",
        "bitcoin.deposit.fund_and_broadcast",
        "bitcoin.fractional.exit",
    ] {
        let (ok, msg) = invoke(method, Vec::new()).await;
        assert!(!ok, "{method} must not succeed on empty args");
        assert!(
            msg.contains(FENCE_TOKEN),
            "{method} must refuse before decoding its arguments; got: {msg}"
        );
        assert!(
            !msg.contains("decode"),
            "{method} reached argument decoding, so the fence is not first; \
             got: {msg}"
        );
    }
}

/// SCOPE CONTROL — the fence must not strand already-funded taps.
///
/// Every exit-direction route stays open: these move value OUT of a vulnerable
/// tap, which reduces exposure. They still fail here (no such vault), and the
/// assertion is precisely that they fail for THAT reason and not the fence.
/// Disposition of already-funded taps is an owner decision this cut does not
/// make, so it must remain possible.
#[tokio::test]
#[serial]
async fn exit_direction_routes_are_not_fenced() {
    let refund = pack(
        generated::DepositRefundRequest {
            vault_op_id: "fence-probe-vault".to_string(),
        }
        .encode_to_vec(),
    );
    for (method, args) in [
        ("bitcoin.deposit.refund", refund.clone()),
        ("bitcoin.full.sweep", refund.clone()),
        ("bitcoin.sweep.recover", refund.clone()),
        ("bitcoin.claim.auto", refund),
    ] {
        let (_, msg) = invoke(method, args).await;
        assert!(
            !msg.contains(FENCE_TOKEN),
            "{method} moves value OUT of a vulnerable tap and must stay open, \
             or already-funded taps are stranded; got: {msg}"
        );
    }
}
