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

/// Canonical AMM predicate bytes for a pair. Reserve-free: a condition carries
/// a rule, never a balance.
fn amm_fulfillment_bytes(a: &[u8; 32], b: &[u8; 32], fee_bps: u32) -> Vec<u8> {
    let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
    let fm = generated::FulfillmentMechanism {
        kind: Some(generated::fulfillment_mechanism::Kind::AmmConstantProduct(
            generated::AmmConstantProduct {
                token_a: lo.to_vec(),
                token_b: hi.to_vec(),
                fee_bps,
            },
        )),
    };
    fm.encode_to_vec()
}

/// A funding leg that does not name a 32-byte policy commit is refused, and
/// refused BEFORE any balance is read or any signature is built.
///
/// This replaces a ticker-resolution failure. The leg used to carry a ticker
/// that `dlv.create` looked up in the local registry — and that lookup is the
/// ambiguity: a ticker can name more than one token, so it could encumber a
/// different asset than the caller meant while every downstream signature still
/// verified. There is no fallback now; identity is either present or the call
/// dies.
#[test]
#[serial_test::serial]
fn a_funding_leg_that_is_not_a_policy_commit_fails_closed() {
    runtime::dsm_init_runtime();
    init_test_storage();
    let r = new_router();

    // A ticker, an empty identity, and near-miss lengths.
    for bad in [
        b"NEVERSEEN".to_vec(),
        Vec::new(),
        vec![0u8; 31],
        vec![0u8; 33],
    ] {
        // A well-formed AMM predicate, so the refusal below is the LEG identity
        // and not an earlier gate. A test that passes on an unrelated error
        // credits a guard for work it is not doing.
        let spec = generated::DlvSpecV1 {
            policy_digest: vec![0x11u8; 32],
            fulfillment_bytes: amm_fulfillment_bytes(&[0x11u8; 32], &[0x22u8; 32], 30),
            ..Default::default()
        };
        let req = generated::DlvInstantiateV1 {
            spec: Some(spec),
            creator_public_key: vec![0xABu8; 64],
            signature: Vec::new(),
            funding_legs: vec![generated::DlvFundingLegV1 {
                policy_commit: bad.clone(),
                amount: 1_000,
            }],
        };
        let res = invoke(&r, "dlv.create", pack(req.encode_to_vec()));
        assert!(
            !res.success,
            "a {}-byte leg identity must be refused",
            bad.len()
        );
        let msg = res.error_message.unwrap_or_default();
        assert!(
            msg.contains("32-byte policy commit"),
            "must fail as an identity error, not incidentally: {msg}"
        );
        assert!(
            msg.contains("never resolved"),
            "the error must say the ticker is not resolved, so nobody re-adds the lookup: {msg}"
        );
    }
}

/// The same ticker on two distinct assets stays distinguishable through the
/// live route: funding one vault cannot be satisfied by the other's commit.
#[test]
#[serial_test::serial]
fn two_assets_sharing_a_ticker_are_not_interchangeable_at_the_route() {
    runtime::dsm_init_runtime();
    init_test_storage();
    let r = new_router();

    // Two tokens a user would both call "RIGB".
    let rigb_one = [0x11u8; 32];
    let rigb_two = [0x22u8; 32];
    assert_ne!(rigb_one, rigb_two);

    // A pair over one of them does not admit the other, at the identity layer
    // the route depends on.
    let era = [0x33u8; 32];
    let pair =
        dsm::dlv::pair_identity::CanonicalPair::parse(&era, &rigb_one).expect("canonical pair");
    assert!(pair.contains(&rigb_one));
    assert!(
        !pair.contains(&rigb_two),
        "a same-ticker asset must not satisfy this vault's pair"
    );

    // And the route refuses legs that are not the vault's own pair. Driven here
    // with a well-formed but unfunded pair so the refusal is the pair check, not
    // a balance shortfall.
    // The vault's predicate declares ERA / RIGB-one.
    let spec = generated::DlvSpecV1 {
        policy_digest: vec![0x11u8; 32],
        fulfillment_bytes: amm_fulfillment_bytes(&era, &rigb_one, 30),
        ..Default::default()
    };
    let req = generated::DlvInstantiateV1 {
        spec: Some(spec),
        creator_public_key: vec![0xABu8; 64],
        signature: Vec::new(),
        funding_legs: vec![
            generated::DlvFundingLegV1 {
                policy_commit: rigb_one.to_vec(),
                amount: 1_000,
            },
            generated::DlvFundingLegV1 {
                policy_commit: rigb_two.to_vec(),
                amount: 1_000,
            },
        ],
    };
    let res = invoke(&r, "dlv.create", pack(req.encode_to_vec()));
    assert!(
        !res.success,
        "two same-ticker assets are two assets; this must not silently create a vault"
    );
}

/// ELIGIBILITY IS CHECKED BEFORE THE SETTLE PATH TERMINATES.
///
/// This was filed as "blocked until the live settle path exists", and tracing
/// the handler showed that was wrong: `verify_route_commit_unlock_eligibility`
/// runs ~100 lines BEFORE the fail-closed return, so a RouteCommit that fails
/// eligibility is refused on those grounds and never reaches it. The AMM
/// re-simulation and anchor-enforcement guards genuinely do sit after the
/// return; this one never did.
///
/// The distinction matters because it is the ordering the guard exists to
/// protect: eligibility must be established before anything advances state, and
/// an implementation that checked it afterwards would still refuse this input —
/// just with a different message, and with the work already done.
#[test]
#[serial_test::serial]
fn eligibility_is_rejected_before_the_settle_path_fails_closed() {
    runtime::dsm_init_runtime();
    init_test_storage();
    let r = new_router();

    // A structurally valid request whose RouteCommit cannot pass eligibility:
    // the initiator signature is absent, so nothing about this route is
    // attributable.
    let rc = generated::RouteCommitV1 {
        version: 1,
        nonce: vec![0x11; 32],
        total_fee_bps: 30,
        initiator_public_key: vec![0xAA; 64],
        initiator_signature: Vec::new(),
        hops: vec![generated::RouteCommitHopV1 {
            vault_id: vec![0x77; 32],
            token_in: vec![0x11; 32],
            token_out: vec![0x22; 32],
            input_amount_u128: 1_000u128.to_be_bytes().to_vec(),
            expected_output_amount_u128: 970u128.to_be_bytes().to_vec(),
            vault_state_anchor_seq: 0,
            ..Default::default()
        }],
        ..Default::default()
    };
    let req = generated::DlvUnlockRoutedV1 {
        vault_id: vec![0x77u8; 32],
        device_id: vec![0x0Au8; 32],
        route_commit_bytes: rc.encode_to_vec(),
        ..Default::default()
    };
    let res = invoke(&r, "dlv.unlockRouted", pack(req.encode_to_vec()));
    assert!(!res.success, "an ineligible route must not settle");
    let msg = res.error_message.unwrap_or_default();
    assert!(
        !msg.contains("fail-closed until reserve proofs"),
        "eligibility must be refused on its own terms, BEFORE the settle path's \
         fail-closed return — got: {msg}"
    );
}

/// The routes this file exercises must be reachable through the production
/// dispatcher. A handler arm that the router does not name is a dead feature
/// that every unit test still passes.
#[test]
#[serial_test::serial]
fn every_sofi_route_is_reachable_through_the_dispatcher() {
    runtime::dsm_init_runtime();
    init_test_storage();
    let r = new_router();

    // ENUMERATED, not sampled. A handler arm and the router's match are two
    // different tables, and adding to one without the other produces a route
    // that is fully implemented, fully unit-tested and dead — every call
    // answering "unknown method". That has shipped twice in this repo
    // (`tokens.addByAnchor`, then `token.adoptionQr`), the second time past a
    // guard that named only the route which broke the first time.
    //
    // The assertion is deliberately weak on purpose: it requires only that the
    // route be KNOWN. An empty argument list legitimately fails validation, and
    // demanding success would mean constructing valid inputs for every route —
    // which is what makes an exhaustive list too expensive to keep exhaustive.
    for method in [
        "dlv.create",
        "dlv.invalidate",
        "dlv.claim",
        "dlv.unlock",
        "dlv.unlockRouted",
        "route.findAndBindBestPath",
        "route.publishExternalCommitment",
        "route.publishRoutingAdvertisement",
        "route.signRouteCommit",
        "route.syncVaultsForPair",
    ] {
        let msg = invoke(&r, method, Vec::new())
            .error_message
            .unwrap_or_default();
        assert!(
            !is_unknown_route(&msg),
            "{method} is not registered in the production dispatch table: {msg}"
        );
    }
    for path in [
        "dlv.listOwnedAmmVaults",
        "dlv.getVaultStateAnchor",
        "route.computeExternalCommitment",
        "route.isExternalCommitmentVisible",
        "route.listAdvertisementsForPair",
    ] {
        let msg = query(&r, path, Vec::new())
            .error_message
            .unwrap_or_default();
        assert!(
            !is_unknown_route(&msg),
            "{path} is not registered in the production dispatch table: {msg}"
        );
    }

    // NON-VACUITY, per namespace. Each dispatch table words its refusal
    // differently ("unknown dlv invoke method", "unknown route invoke method",
    // "unknown query path", "unknown invoke method"), so a matcher tuned to one
    // wording silently passes every route in the others. The first version of
    // this test looked for "unknown invoke method" and could therefore never
    // fail for any `route.*` route, whose table says "unknown route invoke
    // method" — the assertion was dead in exactly the namespace it was added to
    // protect.
    for bogus in [
        "dlv.noSuchMethod",
        "route.noSuchMethod",
        "sofi.noSuchMethod",
    ] {
        let msg = invoke(&r, bogus, Vec::new())
            .error_message
            .unwrap_or_default();
        assert!(
            is_unknown_route(&msg),
            "an unknown route in this namespace must be recognisable, or the loop above passes on silence: {msg}"
        );
    }
    let msg = query(&r, "dlv.noSuchQuery", Vec::new())
        .error_message
        .unwrap_or_default();
    assert!(
        is_unknown_route(&msg),
        "an unknown query path must be recognisable: {msg}"
    );
}

/// Every dispatch table's way of saying "I do not know this route".
///
/// Matching one wording is how the guard this replaces went blind: the phrasing
/// differs per namespace, so a single literal covers one table and silently
/// accepts every route in the rest.
fn is_unknown_route(msg: &str) -> bool {
    let m = msg.to_ascii_lowercase();
    m.contains("unknown")
        && (m.contains("invoke") || m.contains("query path") || m.contains("route"))
}
