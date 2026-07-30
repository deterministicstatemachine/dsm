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

/// Track A invariant — `dlv.invalidate` and `dlv.claim` MUST decode their
/// requests via the typed `DlvInvalidateV1` / `DlvClaimV1` protos, not via
/// the historical inline `[32-byte vault_id][rest]` body shape.  A
/// regression that re-introduced the inline format would silently accept
/// undersized payloads with no schema enforcement.
#[test]
fn dlv_invalidate_and_claim_decode_typed_protos() {
    let src = read(sdk_path("src/handlers/dlv_routes.rs"));
    assert!(
        src.contains("generated::DlvInvalidateV1::decode"),
        "regression: dlv.invalidate decoder no longer reads DlvInvalidateV1 proto"
    );
    assert!(
        src.contains("generated::DlvClaimV1::decode"),
        "regression: dlv.claim decoder no longer reads DlvClaimV1 proto"
    );
    assert!(
        !src.contains("body must start with 32-byte vault_id"),
        "regression: dlv handlers reverted to the inline [vault_id][rest] format"
    );
}

/// SoFi routing path search — the cost function MUST select on
/// `final_output_amount`, not on summed `fee_bps`.  A pure-fee
/// Dijkstra silently mis-routes when a multi-hop path through deep
/// reserves nets more output than a shallow direct hop with low fee
/// (test `multi_hop_beats_direct_when_output_better`).
#[test]
fn routing_path_search_compares_on_final_output() {
    let src = read(sdk_path("src/sdk/routing_path_sdk.rs"));
    assert!(
        src.contains("final_output_amount > current.final_output_amount"),
        "regression: routing_path_sdk replaced output-maximisation with \
         a different cost rule — verify intent before proceeding"
    );
}

/// SoFi chunk #5 invariant — the eligibility verifier MUST call
/// SPHINCS+ verification on the `initiator_signature`.  Without this
/// step an attacker could forge arbitrary RouteCommits + publish
/// their own X anchor + trick vault owners into unlocking against
/// unauthorised routes.  This guard catches any future edit that
/// removes the signature check.
#[test]
fn route_commit_eligibility_runs_sphincs_signature_verify() {
    let src = read(sdk_path("src/sdk/route_commit_sdk.rs"));
    assert!(
        src.contains("dsm::crypto::sphincs::sphincs_verify"),
        "regression: route_commit_sdk no longer SPHINCS+-verifies \
         initiator_signature — forged-route attack surface re-opened"
    );
    // The signature check must come BEFORE the X-anchor lookup.
    // Otherwise a forged RouteCommit can spam storage queries.
    let sig_pos = src
        .find("dsm::crypto::sphincs::sphincs_verify")
        .expect("sphincs_verify present (asserted above)");
    let anchor_pos = src
        .find("is_external_commitment_visible(&x)")
        .expect("anchor visibility check present");
    assert!(
        sig_pos < anchor_pos,
        "regression: SPHINCS+ verification MUST run before anchor \
         lookup — the gate's ordering protects storage-side resources \
         from forged-route DoS"
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
    let needles = [
        // publish_routing_advertisement → routing_sdk::publish_active_advertisement
        "crate::sdk::routing_sdk::publish_active_advertisement",
        // list_advertisements_for_pair → routing_sdk::load_active_advertisements_for_pair
        "crate::sdk::routing_sdk::load_active_advertisements_for_pair",
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

/// Chunk #6 invariant — `dlv.create` MUST accept-or-compute the
/// content + fulfillment digests.  Frontend calls that omit them
/// (the canonical shape per "all business logic stays in Rust")
/// MUST succeed; frontend calls that supply 32-byte digests MUST
/// be strict-verified against the Rust-computed canonical values.
/// A regression that re-required pre-supplied digests would force
/// the frontend to compute them locally, re-opening the BLAKE3-in-
/// the-wrong-layer hole.
#[test]
fn dlv_create_accepts_empty_or_strict_verifies_supplied_digests() {
    let src = read(sdk_path("src/handlers/dlv_routes.rs"));
    assert!(
        src.contains("0 => {} // accept-or-compute path"),
        "regression: dlv.create no longer accepts empty content_digest \
         (forces frontend BLAKE3 computation)"
    );
    assert!(
        src.contains("must be 0 or 32 bytes"),
        "regression: dlv.create must reject digest lengths other than 0 \
         or 32 bytes — empty (Rust computes) or full (Rust verifies)"
    );
}

/// Chunk #7 invariant — `dlv.unlockRouted` MUST run the AMM
/// re-simulation gate against the VAULT'S CURRENT reserves (not the
/// advertisement's, which may be stale).  This is the difference
/// between "signed-route execution" and "independently re-simulated
/// reserve-math execution".  A regression that removed the call
/// would re-open the stale-reserves attack: a trader could sign a
/// route quoted against deep advertised reserves, then unlock against
/// shallow live reserves and extract the difference.
#[test]
fn dlv_unlock_routed_runs_amm_re_simulation_gate() {
    let src = read(sdk_path("src/handlers/dlv_routes.rs"));
    // Scope the ordering check to the body of `dlv_unlock_routed`
    // specifically — other dlv.* handlers also call
    // `execute_on_relationship` and would otherwise distort the
    // earlier-than check.
    let routed_start = src
        .find("async fn dlv_unlock_routed")
        .expect("dlv_unlock_routed handler present");
    let routed_end = src[routed_start..]
        .find("\n    }\n}")
        .map(|i| routed_start + i)
        .unwrap_or(src.len());
    let routed_body = &src[routed_start..routed_end];

    assert!(
        routed_body.contains("verify_amm_swap_against_reserves"),
        "regression: dlv.unlockRouted no longer calls the AMM re-simulation \
         gate — chunk #7 reserve-math verification is bypassed"
    );
    let resim_pos = routed_body
        .find("verify_amm_swap_against_reserves")
        .expect("re-simulation present");
    // Anchor on the actual call site (`.execute_on_relationship(...`)
    // rather than the bare identifier — doc-comments mention the name
    // before the call, which would distort the ordering check.
    let advance_pos = routed_body
        .find(".execute_on_relationship(rel_key")
        .expect("on-chain advance present in dlv_unlock_routed");
    assert!(
        resim_pos < advance_pos,
        "regression: AMM re-simulation MUST run before execute_on_relationship \
         in dlv_unlock_routed — checking math AFTER the chain advances is \
         too late to reject"
    );
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

/// Track C.4 invariant — `dlv.create` MUST stamp the wallet's
/// SPHINCS+ pk on `creator_public_key` when the field rides empty
/// over the wire AND sign Rust-side when `signature` rides empty.
/// This is the same accept-or-stamp pattern chunk #6 used for
/// `route.signRouteCommit`; without it the AMM owner UI couldn't
/// create vaults without exposing wallet keys to TS.
///
/// The signature is over `LimboVaultDraft::parameters_hash` (the
/// same value `LimboVault::verify()` re-derives at finalize_vault
/// time) — NOT over the DlvInstantiateV1 envelope canonical form.
/// An earlier implementation signed over the envelope, which the
/// chunks-#7 verifier rejected on every accept-or-sign path; that
/// bug was caught only when the first end-to-end real-hardware
/// SoFi trade test ran.
///
/// Three regressions this guard catches:
///   * Empty-pk handling removed → frontend gets a hard error
///     "creator_public_key is required" and the UI breaks.
///   * Empty-sig handling removed → same.
///   * Signing message changed away from `draft.parameters_hash` →
///     finalize_vault would reject all newly-signed vaults.
#[test]
fn dlv_create_stamps_wallet_pk_and_signs_on_empty_fields() {
    let src = read(sdk_path("src/handlers/dlv_routes.rs"));
    assert!(
        src.contains("if req.creator_public_key.is_empty() {"),
        "regression: dlv.create no longer checks for empty creator_public_key \
         (Track C.4 accept-or-stamp surface broken)"
    );
    assert!(
        src.contains("crate::sdk::signing_authority::current_public_key()"),
        "regression: dlv.create accept-or-stamp no longer reaches into \
         signing_authority for the wallet pk"
    );
    assert!(
        src.contains("needs_wallet_sign = req.signature.is_empty()"),
        "regression: dlv.create no longer flags empty signature for wallet-side \
         signing (Track C.4 accept-or-sign surface broken)"
    );
    assert!(
        src.contains("crate::sdk::signing_authority::current_secret_key()"),
        "regression: dlv.create accept-or-sign no longer reaches into \
         signing_authority for the wallet sk"
    );
    assert!(
        src.contains("&draft.parameters_hash"),
        "regression: dlv.create no longer signs over draft.parameters_hash — \
         finalize_vault's vault.verify() would reject every newly-signed vault"
    );
}

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

/// Tier 2 Foundation invariant — the `dlv.unlockRouted` anchor gate
/// must compare against the vault's *internal* sequence and reserves
/// digest (local truth), reject Required vaults that lack the
/// anchor binding, and surface the bypass flag for Optional
/// fall-through cases.  The guard fails if any of those four
/// surfaces regress.
#[test]
fn dlv_unlock_routed_enforces_anchor_against_local_vault_state() {
    let src = read(sdk_path("src/handlers/dlv_routes.rs"));
    // The gate must verify against vault.current_sequence and
    // vault.current_reserves_digest() — NOT against storage.
    assert!(
        src.contains("vault.current_sequence"),
        "gate must compare against vault.current_sequence (local truth)"
    );
    assert!(
        src.contains("current_reserves_digest"),
        "gate must compare against vault.current_reserves_digest()"
    );
    // The Required path must hard-reject missing fields.
    assert!(
        src.contains("anchor binding")
            || src.contains("MissingAnchorBinding")
            || src.contains("requires anchor binding"),
        "gate must reject Required vaults missing anchor fields"
    );
    // The Optional path must surface the bypass flag.
    assert!(
        src.contains("anchor_enforcement_bypassed_optional_vault"),
        "gate must surface bypass flag for Optional fall-through"
    );
}

// RETIRED with the declared-reserves removal — same reason as the advertisement
// republish above. There is no settle to advance a sequence on while settlement
// is fail-closed, and asserting on the text of a code path that no longer runs
// is precisely the coverage illusion this suite is being replaced to remove.
