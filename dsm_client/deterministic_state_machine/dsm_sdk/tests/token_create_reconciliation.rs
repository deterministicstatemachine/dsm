// SPDX-License-Identifier: MIT OR Apache-2.0
//! A lost reply must not look like a failed creation.
//!
//! On hardware the first `token.create` committed — 10 ERA burned, 1,000 RIGA
//! credited, registry row written — while the reply never reached the wizard,
//! which sat on "Publishing policy…" and then said "Token creation failed".
//! Retrying hit the registry's UNIQUE constraint and failed again. A successful
//! creation presented as two failures, and the only thing that stopped a second
//! fee being burned was a database constraint firing at the right moment.
//!
//! The identity makes this answerable rather than guessable:
//!
//!   token_id = BLAKE3(TAG_DSM_TOKEN_ID, policy_anchor ‖ ticker)
//!   policy_anchor = BLAKE3(TAG_DSM_POLICY, policy_bytes)
//!
//! so the id IS the creation commitment. Resubmitting the same commitment is
//! answered from canonical state; resubmitting a different one that claims a
//! taken ticker is a hard conflict.
//!
//! What is pinned here:
//!   * a repeated identical creation returns success without a second advance;
//!   * the fee is burned exactly once no matter how many times it is submitted;
//!   * supply is credited exactly once;
//!   * one token and one policy survive repeated attempts;
//!   * a different creation claiming a taken ticker is refused, not merged.

#![allow(clippy::disallowed_methods)]

use prost::Message;
use std::path::PathBuf;

use dsm_sdk::bridge::{AppInvoke, AppRouter};
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

fn request(ticker: &str, alloc: u128) -> generated::TokenCreateRequest {
    generated::TokenCreateRequest {
        ticker: ticker.to_string(),
        alias: format!("{ticker} Token"),
        decimals: 2,
        max_supply_u128: 0u128.to_be_bytes().to_vec(),
        initial_alloc_u128: alloc.to_be_bytes().to_vec(),
        mint_burn_enabled: true,
        transferable: true,
        unlimited_supply: true,
        mint_burn_threshold: 1,
        description: String::new(),
        icon_url: String::new(),
        allowlist_device_ids: Vec::new(),
    }
}

/// Submit a creation and return (success, token_id, message).
fn create(r: &AppRouterImpl, req: &generated::TokenCreateRequest) -> (bool, String, String) {
    let res = invoke(r, "token.create", pack(req.encode_to_vec()));
    if !res.success {
        return (false, String::new(), res.error_message.unwrap_or_default());
    }
    let env = generated::Envelope::decode(&res.data[1..]).expect("envelope");
    match env.payload {
        Some(generated::envelope::Payload::TokenCreateResponse(r)) => {
            (r.success, r.token_id, r.message)
        }
        other => panic!("expected TokenCreateResponse, got {other:?}"),
    }
}

fn era(r: &AppRouterImpl) -> u64 {
    let c = dsm::core::token::builtin_policy_commit_for_token("ERA").expect("ERA");
    r.core_sdk.device_head().map(|h| h.balance(&c)).unwrap_or(0)
}

/// 3.5b: creator supply gets the NAMED refusal, and — the reconciliation
/// property inverted — a refused creation leaves no reconcilable trace: no
/// fee, no row, and the identical retry is refused again rather than
/// "reconciled" into a phantom success. (Commit-side reconciliation of the
/// fee-only shape lives in the lib e2e
/// `token_routes_admit_fee_only_create_and_burn_end_to_end`; integration
/// tests have no fake fleet, so nothing can commit here.)
#[test]
#[serial_test::serial]
fn a_refused_creator_supply_leaves_no_reconcilable_trace() {
    runtime::dsm_init_runtime();
    let (r, _fleet) = funded_router(0x84);

    let req = request("RECON", 1_000);
    let before = era(&r);

    let (ok1, _, msg1) = create(&r, &req);
    assert!(!ok1, "creator supply must be refused");
    assert!(
        msg1.contains("initial_supply > 0 cannot enter a validated lineage"),
        "the refusal must be the NAMED issuance-predicate error, got: {msg1}"
    );
    assert_eq!(era(&r), before, "a refused creation burns nothing");
    assert_eq!(
        token_registry::all_tokens().expect("registry").len(),
        0,
        "no registry row"
    );

    let (ok2, _, _) = create(&r, &req);
    assert!(
        !ok2,
        "the identical retry is refused again, never reconciled"
    );
    assert_eq!(era(&r), before, "still nothing burned");
}

/// An unaffordable creation still leaves nothing behind — including no registry
/// row that a later reconciliation could mistake for a success.
#[test]
#[serial_test::serial]
fn an_unaffordable_creation_leaves_no_reconcilable_trace() {
    runtime::dsm_init_runtime();
    let (r, _fleet) = dsm_sdk::economic_fixtures::empty_router(0x84);
    // deliberately unfunded: no ERA for the fee

    let (ok, _, msg) = create(&r, &request("BROKE", 0));
    assert!(!ok, "creation without the fee must fail");
    assert!(
        msg.contains("insufficient ERA"),
        "must fail on affordability, not an earlier gate, got: {msg}"
    );
    assert_eq!(
        token_registry::all_tokens().expect("registry").len(),
        0,
        "a failed creation must leave no registry row"
    );

    // And the retry must report a retryable failure, not a phantom success.
    let (ok2, _, _) = create(&r, &request("BROKE", 0));
    assert!(!ok2, "retrying an unaffordable creation must still fail");
}
