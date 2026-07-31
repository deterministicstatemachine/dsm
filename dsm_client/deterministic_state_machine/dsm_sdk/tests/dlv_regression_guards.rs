// SPDX-License-Identifier: MIT OR Apache-2.0
//! Regression guards for the custom tokens + DLV anchoring PR.
//!
//! These tests scan source files for banned patterns so the invariants
//! landed across commits 1–9 cannot be silently reverted by future
//! edits.  They are cheap (no runtime state) and fail with a targeted
//! message pointing at the exact pattern that regressed.
//!
//! Plan references: Part G.4 (negative / regression).

// Test-only file: `expect`-on-Option/Result is the idiomatic shape for
// assertion-driven regression checks.  The workspace's
// `disallowed-methods` clippy config disallows them in production code;
// allow at the file level for tests.
#![allow(clippy::disallowed_methods)]

use std::fs;
use std::path::{Path, PathBuf};

/// Resolve a path relative to `dsm_sdk/`.
fn sdk_path(rel: &str) -> PathBuf {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest_dir).join(rel)
}

/// Resolve a path relative to `dsm/` (sibling crate).
fn core_path(rel: &str) -> PathBuf {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let parent = Path::new(manifest_dir).parent().expect("dsm_sdk parent");
    parent.join("dsm").join(rel)
}

fn read(rel_path: PathBuf) -> String {
    fs::read_to_string(&rel_path)
        .unwrap_or_else(|e| panic!("could not read {}: {e}", rel_path.display()))
}

/// Commit 5 invariant — `dlv.claim` MUST route on the claimant's
/// self-loop (the local device), NOT on the vault creator's device.
/// This guard asserts the handler does not read
/// `vault.creator_public_key` to derive the rel_key.
#[test]
fn dlv_claim_uses_local_rel_key_not_creator_rel_key() {
    let src = read(sdk_path("src/handlers/dlv_routes.rs"));

    // Positive: the claim handler must use the local device's ID for
    // actor routing.  `reference_state.device_info.device_id` is the
    // canonical source.
    assert!(
        src.contains("reference_state.device_info.device_id"),
        "dlv.claim must derive the actor from reference_state.device_info.device_id"
    );

    // Negative: the claim handler MUST NOT build rel_key from the
    // vault creator.  Guard against future accidental routing flips.
    let claim_region_start = src
        .find("async fn dlv_claim")
        .expect("dlv_claim handler present");
    let claim_region_end = src[claim_region_start..]
        .find("\n    /// dlv.")
        .map(|i| claim_region_start + i)
        .unwrap_or(src.len());
    let claim_region = &src[claim_region_start..claim_region_end];
    assert!(
        !claim_region.contains("creator_public_key"),
        "dlv.claim must not read vault.creator_public_key for routing"
    );
    assert!(
        !claim_region.contains("v.creator_public_key"),
        "dlv.claim must not read vault.creator_public_key for routing"
    );
}

/// Track B invariant — `dlv.create` with a non-empty `intended_recipient`
/// MUST publish a posted-DLV advertisement.  A regression that dropped
/// the publish call would leave recipients unable to discover their
/// vaults while creators see a fully committed on-chain state.
#[test]
fn dlv_create_publishes_advertisement_when_intended_recipient_set() {
    let src = read(sdk_path("src/handlers/dlv_routes.rs"));
    assert!(
        src.contains("crate::sdk::posted_dlv_sdk::publish_active_advertisement"),
        "regression: dlv.create no longer invokes publish_active_advertisement"
    );
    assert!(
        src.contains("intended_recipient_opt.as_ref()"),
        "regression: dlv.create publish gate must read intended_recipient_opt"
    );
}

/// Track B invariant — `dlv.claim` MUST publish a claimed-state
/// advertisement so the creator's device (and other observers) can see
/// the vault has been consumed.  The dedup rule (highest
/// updated_state_number wins) depends on this emission to function.
#[test]
fn dlv_claim_publishes_terminal_state_ad() {
    let src = read(sdk_path("src/handlers/dlv_routes.rs"));
    assert!(
        src.contains("crate::sdk::posted_dlv_sdk::publish_terminal_state"),
        "regression: dlv.claim no longer emits a terminal-state advertisement"
    );
    assert!(
        src.contains("LIFECYCLE_CLAIMED"),
        "regression: dlv.claim must tag its terminal ad with LIFECYCLE_CLAIMED"
    );
}

/// Track C.3 invariant — each trade-flow handler MUST delegate to the
/// audited SDK helper (chunk #1 / #2 / #3) rather than re-implementing
/// the logic inline.  A regression that copy-pasted the BLAKE3
/// derivation into a handler would silently bypass the chunk #1 digest
/// binding; one that re-implemented path search would drift from the
/// chunk #2 simulator the chunk #7 gate checks against.
#[test]
fn trade_flow_handlers_delegate_to_audited_sdks() {
    let src = read(sdk_path("src/handlers/route_routes.rs"));
    // The publish and list halves are proven behaviourally by
    // `route_routes::stamping_tests::the_route_and_the_sdk_return_the_same_advertisements`,
    // which publishes through the route and requires the route's listing to
    // carry byte-for-byte the advertisement the SDK returns for the same pair.
    // A call site existing proves nothing about agreement; that test does.
    //
    // These three ride the quote path, which does not execute end to end yet.
    // Their behavioural replacement is output agreement between handler and SDK,
    // and it lands when the quote path is exercised.
    let needles = [
        // sync_vaults_for_pair → routing_sdk::fetch_and_verify_vault_proto
        "crate::sdk::routing_sdk::fetch_and_verify_vault_proto",
        // find_and_bind_best_path → routing_path_sdk::find_and_verify_best_path
        "crate::sdk::routing_path_sdk::find_and_verify_best_path",
        // find_and_bind_best_path → route_commit_sdk::bind_path_to_route_commit
        "crate::sdk::route_commit_sdk::bind_path_to_route_commit",
    ];
    for needle in needles {
        assert!(
            src.contains(needle),
            "regression: trade-flow handler stopped delegating to SDK: {needle}"
        );
    }
}

// RETIRED with the declared-reserves removal.
//
// This asserted that `dlv.unlockRouted` republishes the routing advertisement
// after a settled swap. Both the republish and the settle are gone: reserves are
// now encumbered leaves in the OWNER's device SMT, and a settling device has no
// authenticated reserves to verify a hop against until
// `VaultReserveInclusionProofV1` exists. The route fails closed, which
// `tests/vault_funding_routes.rs::routed_settlement_refuses_until_reserve_proofs_exist`
// states behaviourally. The republish property returns with the settlement work.

// RETIRED: the PROPERTY survives, the string does not.
//
// `dlv.create` still publishes a genesis `VaultStateAnchorV1` for a REQUIRED AMM
// vault, but the digest now comes from `vault.reserves_digest_for(ra, rb)` over
// the amounts just encumbered, rather than from a `compute_reserves_digest` call
// named in this file. Grepping for the symbol therefore failed while the
// behaviour was intact — which is the failure mode of a source-text test.
//
// The digest half is pinned behaviourally in
// `dsm/src/vault/dlv_manager.rs::vault_reserves_digest_is_over_the_reserves_it_is_given`.
// The publish half needs a live-router funded-creation test and is part of the
// work NOT yet claimed complete.

// RETIRED with the declared-reserves removal — same reason as the advertisement
// republish above. There is no settle to advance a sequence on while settlement
// is fail-closed, and asserting on the text of a code path that no longer runs
// is precisely the coverage illusion this suite is being replaced to remove.
