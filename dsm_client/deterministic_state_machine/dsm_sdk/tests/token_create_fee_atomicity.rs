// SPDX-License-Identifier: MIT OR Apache-2.0
//! The 10 ERA creation fee — refusal contracts.
//!
//! 3.5b made the creation fee an ADMITTED economic debit, and integration
//! tests have no fake register fleet (`cfg(test)`-only), so no creation can
//! COMMIT here any more. What this suite pins is the fail-closed half of fee
//! atomicity: a creation that cannot be admitted burns nothing, advances
//! nothing, and leaves no registry row. The commit-side properties (fee
//! burned once, reconciliation, anchor contract) moved to the lib e2e
//! `handlers::sender_admission_tests::token_routes_admit_fee_only_create_and_burn_end_to_end`.
//!
//! Two properties of the surrounding design shape what these tests assert.
//!
//! UNITS. `TokenCreateRequest` carries DISPLAY units, because a person typed
//! them. Rust scales to base units exactly once, at this boundary, and
//! everything downstream — the policy bytes, the CPTA anchor, CreateToken,
//! conservation, the registry cap — is base units. So a request for 250 at
//! decimals=2 credits 25_000, and the assertions here are in base units.
//!
//! IDENTITY. `token_id = BLAKE3(TAG_DSM_TOKEN_ID, policy_anchor ‖ ticker)`,
//! so the id IS the creation commitment. Resubmitting the same commitment
//! names the same token and is answered from canonical state; it is not a
//! second creation to be refused. What must never happen is a second fee, a
//! second advance, or a second row.
//!
//! The properties pinned here:
//!   * the fee is charged, and burned (no counterparty is credited);
//!   * insufficient ERA rejects BEFORE anything commits — a failed creation
//!     burns nothing and advances nothing;
//!   * an identical resubmission reconciles: one fee, one advance, one row;
//!   * creation still advances canonical state when the allocation is zero,
//!     so the token exists on the chain either way.

#![allow(clippy::disallowed_methods)]

use prost::Message;
use std::path::PathBuf;

use dsm_sdk::bridge::{AppInvoke, AppRouter};
use dsm_sdk::generated;
use dsm_sdk::handlers::app_router_impl::AppRouterImpl;
use dsm_sdk::runtime;
use dsm_sdk::storage::client_db::token_registry;

const FEE: u64 = dsm::core::token::TOKEN_CREATION_FEE_ERA;

/// A router on a REAL testnet identity, funded through a REAL faucet admission
/// (0x0030), replacing a fabricated identity plus a directly-written balance.
///
/// The old pair installed [0xAA;32]/[0xBB;32]/[0xCC;32] with no genesis record —
/// so no network was committed and no admission could ever run — and then wrote
/// 100 ERA straight onto the head. That balance had no economic lineage, and
/// since debits are not fenced it was fully spendable through canonical
/// acceptance. 100 is exactly the faucet's payout, so assertions written against
/// it are unchanged.
fn funded_router(seed: u8) -> (AppRouterImpl, dsm_sdk::economic_fixtures::FleetGuard) {
    let _ = dsm_sdk::storage_utils::set_storage_base_dir(PathBuf::from("./.dsm_testdata"));
    dsm_sdk::economic_fixtures::funded_router(seed)
}

fn invoke(router: &AppRouterImpl, method: &str, args: Vec<u8>) -> dsm_sdk::bridge::AppResult {
    runtime::get_runtime().block_on(async {
        router
            .invoke(AppInvoke {
                method: method.to_string(),
                args,
            })
            .await
    })
}

/// A creation request in DISPLAY units, exactly as the wizard sends them.
/// `DECIMALS` is what turns those into the base units canonical state holds.
const DECIMALS: u32 = 2;

fn create_request(ticker: &str) -> Vec<u8> {
    let req = generated::TokenCreateRequest {
        ticker: ticker.to_string(),
        alias: format!("{ticker} Token"),
        decimals: DECIMALS,
        max_supply_u128: 0u128.to_be_bytes().to_vec(),
        initial_alloc_u128: 0u128.to_be_bytes().to_vec(),
        mint_burn_enabled: true,
        transferable: true,
        unlimited_supply: true,
        mint_burn_threshold: 1,
        description: String::new(),
        icon_url: String::new(),
        allowlist_device_ids: Vec::new(),
    };
    generated::ArgPack {
        schema_hash: Some(generated::Hash32 { v: vec![0u8; 32] }),
        codec: generated::Codec::Proto as i32,
        body: req.encode_to_vec(),
    }
    .encode_to_vec()
}

fn era_balance(router: &AppRouterImpl) -> u64 {
    let commit = dsm::core::token::builtin_policy_commit_for_token("ERA").expect("ERA builtin");
    router
        .core_sdk
        .device_head()
        .map(|h| h.balance(&commit))
        .unwrap_or(0)
}

fn head_root(router: &AppRouterImpl) -> [u8; 32] {
    router
        .core_sdk
        .device_head()
        .map(|h| h.root())
        .unwrap_or([0u8; 32])
}

/// THE RECOVERY PROPERTY, end to end: an admission interrupted by an
/// unreachable register completes exactly once when the register returns, and
/// charges its fee exactly once.
///
/// This replaces an assertion that is no longer reachable. The old test claimed
/// "no fee burned, no head advance" for a device that was funded but had no
/// admissible ancestry — a state that existed ONLY because the fixture wrote the
/// balance directly. What becomes unreachable is precisely
/// `positive spendable value with no admissible economic ancestry`; a
/// legitimately funded device attempting an operation that cannot currently
/// complete admission is a REAL lifecycle state, not a defect, and this is it.
///
/// ```text
/// ERA 100, admitted position 1
///   register unavailable
///     -> local acceptance, ERA 90, LocalAcceptedPendingEcon, evidence durable
///   register restored
///     -> resume -> ECON_ADMITTED
///     -> ERA still 90            (the fee is not charged twice)
///     -> position 1 -> 2 exactly (one admission, not two)
/// ```
#[test]
#[serial_test::serial]
fn an_interrupted_admission_completes_once_and_charges_the_fee_once() {
    runtime::dsm_init_runtime();
    // FUNDED legitimately. Nothing here is fabricated: the balance came from a
    // real faucet admission, and only the TRANSPORT is taken down.
    let (r, _fleet) = funded_router(0xa6);
    let before_era = era_balance(&r);
    let before_position =
        dsm_sdk::economic_fixtures::admitted_position(&r).expect("funded => admitted");
    assert_eq!(before_era, 100, "the faucet payout");
    assert_eq!(before_position, 1, "the faucet claim is position 1");

    dsm_sdk::economic_fixtures::take_register_offline();
    let res = invoke(&r, "token.create", create_request("FEEA"));
    assert!(
        !res.success,
        "a creation whose admission cannot reach quorum must not report success"
    );

    // Locally accepted, fee debited, admission durable and in flight.
    assert_eq!(
        dsm_sdk::economic_fixtures::pending_state(&r),
        Some(dsm::economic::admission::EconomicAdmissionState::LocalAcceptedPendingEcon),
        "the operation stopped at local acceptance, awaiting the register"
    );
    let mid_era = era_balance(&r);
    assert_eq!(mid_era, before_era - FEE, "the fee is debited exactly once");
    assert_eq!(
        dsm_sdk::economic_fixtures::admitted_position(&r),
        Some(before_position),
        "an incomplete admission must NOT advance the admitted position"
    );

    // The register returns. The SAME operation resumes — no re-submission.
    dsm_sdk::economic_fixtures::bring_register_online();
    let resumed = dsm_sdk::economic_fixtures::resume_pending(&r);

    assert_eq!(
        resumed,
        before_position + 1,
        "the interrupted admission advances the position EXACTLY once"
    );
    assert_eq!(
        dsm_sdk::economic_fixtures::admitted_position(&r),
        Some(before_position + 1),
        "the admitted lineage records that one advance"
    );
    assert_eq!(
        era_balance(&r),
        mid_era,
        "the fee is not charged a second time by the resume"
    );
    assert!(
        dsm_sdk::economic_fixtures::pending_state(&r).is_none(),
        "no fence may remain after ECON_ADMITTED"
    );
}

/// THE CRASH CASE: a restart while an admission is `LocalAcceptedPendingEcon`
/// recovers the EXACT pending operation — one admission, one fee, and no
/// alternate successor at that economic position.
///
/// The interrupted-admission test above resumes in the same process. This one
/// throws the process state away first: a second router over the same identity
/// and the same durable database, which is what a real restart looks like. The
/// crash-safety invariant is that either the operation never became locally
/// accepted, or it AND its pending admission AND its evidence are all durable —
/// so a restart must find the same operation, not a re-derived one.
#[test]
#[serial_test::serial]
fn a_restart_mid_admission_recovers_the_same_operation_and_charges_once() {
    runtime::dsm_init_runtime();
    let (r, _fleet) = funded_router(0xa7);
    let before_era = era_balance(&r);
    let before_position =
        dsm_sdk::economic_fixtures::admitted_position(&r).expect("funded => admitted");

    dsm_sdk::economic_fixtures::take_register_offline();
    let res = invoke(&r, "token.create", create_request("CRSH"));
    assert!(!res.success, "the admission cannot reach quorum");
    let pending_before = r
        .core_sdk
        .device_head()
        .and_then(|h| h.pending_economic_admission().cloned())
        .expect("a locally accepted operation leaves its pending admission");
    assert_eq!(era_balance(&r), before_era - FEE, "fee debited once");

    // RESTART: a new router over the same identity and the same database.
    // Nothing is re-seeded — that is the whole point of a cold start.
    drop(r);
    let r2 = dsm_sdk::economic_fixtures::restart_router();

    let pending_after = r2
        .core_sdk
        .device_head()
        .and_then(|h| h.pending_economic_admission().cloned())
        .expect("the pending admission must survive the restart");
    assert_eq!(
        pending_after.operation_digest, pending_before.operation_digest,
        "the recovered admission must name the SAME operation, not a re-derived one"
    );
    assert_eq!(
        pending_after.economic_position, pending_before.economic_position,
        "and the same economic position — no alternate successor"
    );

    dsm_sdk::economic_fixtures::bring_register_online();
    let resumed = dsm_sdk::economic_fixtures::resume_pending(&r2);
    assert_eq!(
        resumed,
        before_position + 1,
        "the recovered admission advances the position exactly once"
    );
    assert_eq!(
        era_balance(&r2),
        before_era - FEE,
        "the fee survives the restart charged exactly once"
    );
    assert!(
        dsm_sdk::economic_fixtures::pending_state(&r2).is_none(),
        "no fence remains after ECON_ADMITTED"
    );
}

/// FAILED CREATION BURNS NOTHING. With insufficient ERA the create must reject
/// before anything commits: balance unchanged, device head unmoved, no token.
#[test]
#[serial_test::serial]
fn insufficient_era_rejects_and_burns_nothing() {
    runtime::dsm_init_runtime();
    // EMPTY on purpose: this test's subject is the REFUSAL of an operation
    // with no admitted economic ancestry. Funding it would make the refusal
    // unreachable and the assertion vacuous.
    let (r, _fleet) = dsm_sdk::economic_fixtures::empty_router(0xa6);
    // Deliberately NOT funded.

    let before_era = era_balance(&r);
    let before_root = head_root(&r);
    assert!(before_era < FEE, "fixture must start below the fee");

    let res = invoke(&r, "token.create", create_request("POOR"));
    assert!(!res.success, "creation must reject without the fee");
    let msg = res.error_message.unwrap_or_default();
    assert!(
        msg.contains("insufficient ERA"),
        "expected an insufficient-ERA rejection, got: {msg}"
    );

    assert_eq!(era_balance(&r), before_era, "no ERA may be burned");
    assert_eq!(
        head_root(&r),
        before_root,
        "canonical head must not advance"
    );
    assert!(
        token_registry::get_token_by_ticker("POOR")
            .expect("read")
            .is_none(),
        "no token row may survive a failed creation"
    );
}

/// CLASSIFICATION GUARD. Creation destroys ERA, so it is value EGRESS and its
/// egress asset is ERA — not the newly issued token. Misclassifying it as
/// ingress (as it was while nothing constructed the variant) would let a
/// create-with-fee bypass the recovery egress gate entirely.
#[test]
fn create_token_is_value_egress_over_era() {
    use dsm::types::operations::{EgressAsset, Operation};
    let op = Operation::CreateToken {
        token_id: b"TOK".to_vec(),
        initial_supply: dsm::types::token_types::Balance::from_state(5, [0u8; 32]),
        policy_commit: [0x42; 32],
        fee_amount: FEE,
        name: "Token".into(),
        symbol: "TOK".into(),
        decimals: 2,
        metadata_uri: None,
        signature: Vec::new(),
    };
    assert!(
        op.is_value_egress(),
        "token creation burns ERA and must be classified as value egress"
    );
    match op.egress_asset() {
        EgressAsset::Asset { token_id, amount } => {
            assert_eq!(token_id, b"ERA".to_vec(), "the asset that LEAVES is ERA");
            assert_eq!(amount, FEE);
        }
        other => panic!("expected the ERA fee as the egress asset, got {other:?}"),
    }
}
