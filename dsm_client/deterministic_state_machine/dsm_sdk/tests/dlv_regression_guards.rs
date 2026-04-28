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

/// G.4 regression — `token.create` must not emit `dsm.token.<id>`
/// prefs writes.  The writer was removed in commit 4 and the entire
/// `dsm.token.*` keyspace is purged at boot (commit 7).
#[test]
fn no_dsm_token_prefs_writes_in_token_routes() {
    let src = read(sdk_path("src/handlers/token_routes.rs"));
    assert!(
        !src.contains("app_state_set(&format!(\"dsm.token."),
        "regression: token_routes.rs has reintroduced a dsm.token.* prefs write"
    );
    assert!(
        !src.contains("app_state_set(&format!(\"{TOKEN_PREFIX}"),
        "regression: token_routes.rs has reintroduced a TOKEN_PREFIX-based prefs write"
    );
}

/// G.4 regression — `dlv.create` and `detfi.launch` must not write to
/// the retired `dsm.dlv.*` / `dsm.detfi.*` keyspaces.  The whole
/// persist-via-prefs shim is gone (commits 5 + 6 + 7).
#[test]
fn no_dsm_dlv_or_detfi_prefs_writes_in_handlers() {
    for rel in ["src/handlers/dlv_routes.rs", "src/handlers/detfi_routes.rs"] {
        let src = read(sdk_path(rel));
        assert!(
            !src.contains("app_state_set(&format!(\"dsm.dlv."),
            "regression: {rel} has reintroduced a dsm.dlv.* prefs write"
        );
        assert!(
            !src.contains("app_state_set(&format!(\"dsm.detfi."),
            "regression: {rel} has reintroduced a dsm.detfi.* prefs write"
        );
        assert!(
            !src.contains("DLV_PREFIX"),
            "regression: {rel} has reintroduced the retired DLV_PREFIX constant"
        );
        assert!(
            !src.contains("DETFI_PREFIX"),
            "regression: {rel} has reintroduced the retired DETFI_PREFIX constant"
        );
    }
}

/// G.4 regression — the infallible `resolve_policy_commit` placeholder
/// derived `policy_commit` from the token ticker via a BLAKE3 hash.
/// That path was deleted in commit 3; the strict-fail replacement
/// returns `Err` for non-builtin tokens.  This guard scans the source
/// for the deleted derivation string.
#[test]
fn resolve_policy_commit_placeholder_deleted() {
    let src = read(core_path("src/core/token/token_state_manager.rs"));
    assert!(
        !src.contains("domain_hash_bytes(\"DSM/token-policy\\0\", token_id.as_bytes())"),
        "regression: the DSM/token-policy BLAKE3-of-token-id placeholder \
         fallback has been reintroduced in resolve_policy_commit"
    );
}

/// Commit 1 invariant I1.1 — DlvCreateV3 is deleted from tracked
/// source.  Only documentation and plan narratives may mention it as
/// historical context.
#[test]
fn no_dlv_create_v3_in_rust_or_proto_sources() {
    // Rust source files in dsm + dsm_sdk crates.
    for rel in ["src/vault/limbo_vault.rs", "src/vault/dlv_manager.rs"] {
        let src = read(core_path(rel));
        assert!(
            !src.contains("DlvCreateV3"),
            "regression: {rel} reintroduced DlvCreateV3"
        );
    }
    for rel in [
        "src/handlers/dlv_routes.rs",
        "src/handlers/detfi_routes.rs",
        "src/vault/lifecycle.rs",
    ] {
        let src = read(sdk_path(rel));
        assert!(
            !src.contains("DlvCreateV3"),
            "regression: {rel} reintroduced DlvCreateV3"
        );
    }

    // Proto schema (repo-root relative).
    let proto = {
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        let repo_root = Path::new(manifest_dir)
            .parent()
            .and_then(|p| p.parent())
            .and_then(|p| p.parent())
            .expect("resolve repo root");
        repo_root.join("proto").join("dsm_app.proto")
    };
    let proto_src = read(proto);
    assert!(
        !proto_src.contains("DlvCreateV3"),
        "regression: proto/dsm_app.proto reintroduced DlvCreateV3"
    );
    assert!(
        proto_src.contains("DlvInstantiateV1") && proto_src.contains("DlvSpecV1"),
        "regression: proto/dsm_app.proto is missing DlvSpecV1 / DlvInstantiateV1"
    );
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

/// Track B invariant — posted-mode DLV advertisements MUST be keyed by
/// the intended recipient's Kyber PK, not by the creator's.  A swap would
/// silently break the recipient's `posted_dlv.list` query (which polls
/// `dlv/posted/{local_kyber_pk}/`).  This guard asserts the key-builder
/// function uses `recipient_kyber_pk` as its first argument.
#[test]
fn posted_dlv_ad_key_uses_recipient_not_creator() {
    let src = read(sdk_path("src/sdk/posted_dlv_sdk.rs"));
    assert!(
        src.contains("pub(crate) fn advertisement_key(recipient_kyber_pk: &[u8]"),
        "regression: advertisement_key signature must put recipient_kyber_pk first \
         (key format `dlv/posted/{{recipient_b32}}/{{dlv_id_b32}}` is load-bearing \
         for recipient-indexed discovery)"
    );
    assert!(
        src.contains("pub(crate) const POSTED_DLV_AD_ROOT: &str = \"dlv/posted/\";"),
        "regression: POSTED_DLV_AD_ROOT prefix must remain `dlv/posted/`"
    );
    assert!(
        !src.contains("format!(\"dlv/posted/{{}}\", creator"),
        "regression: advertisement key must not be creator-indexed"
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

/// Track B invariant — the digest binding advertisement → VaultPostProto
/// MUST use the `DSM/posted-dlv-ad` BLAKE3 domain tag.  A tag swap would
/// silently break the fetch-verify round trip, causing legitimate
/// recipients to reject all ads.
#[test]
fn posted_dlv_digest_uses_stable_domain_tag() {
    let src = read(sdk_path("src/sdk/posted_dlv_sdk.rs"));
    assert!(
        src.contains("pub(crate) const POSTED_DLV_AD_DOMAIN: &str = \"DSM/posted-dlv-ad\";"),
        "regression: POSTED_DLV_AD_DOMAIN changed — this breaks every \
         previously-published advertisement"
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

/// Track A invariant — the proto schema MUST keep `DlvInvalidateV1` and
/// `DlvClaimV1` as the canonical request shapes.  Removing them would
/// break the dlv_routes decoders without warning.
#[test]
fn proto_schema_carries_typed_dlv_request_messages() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let repo_root = Path::new(manifest_dir)
        .parent()
        .and_then(|p| p.parent())
        .and_then(|p| p.parent())
        .expect("resolve repo root");
    let proto = repo_root.join("proto").join("dsm_app.proto");
    let proto_src = read(proto);
    assert!(
        proto_src.contains("message DlvInvalidateV1 {"),
        "regression: proto/dsm_app.proto is missing DlvInvalidateV1"
    );
    assert!(
        proto_src.contains("message DlvClaimV1 {"),
        "regression: proto/dsm_app.proto is missing DlvClaimV1"
    );
}

/// DeTFi routing discovery — token-pair canonicalisation MUST sort
/// (tokenA, tokenB) lex-lower-first before key construction.  A
/// regression that forgot this would split each pair into two
/// uncorrelated prefixes and the router would only see half the
/// liquidity.
#[test]
fn routing_advertisement_keys_canonicalise_token_pair() {
    let src = read(sdk_path("src/sdk/routing_sdk.rs"));
    assert!(
        src.contains("pub(crate) fn canonical_token_pair"),
        "regression: routing_sdk lost the canonical_token_pair helper"
    );
    assert!(
        src.contains("if a <= b") || src.contains("if a < b"),
        "regression: canonical_token_pair must sort lex-lower-first"
    );
    assert!(
        src.contains("pub(crate) const ROUTING_VAULT_AD_ROOT: &str = \"defi/vault/\";"),
        "regression: ROUTING_VAULT_AD_ROOT prefix changed — this breaks every \
         previously-published routing advertisement"
    );
}

/// DeTFi routing discovery — the digest binding advertisement →
/// vault proto MUST use the `DSM/routing-vault-ad` BLAKE3 domain tag.
/// A tag swap would silently break the fetch-verify round trip,
/// causing routers to reject all DeTFi vaults.
#[test]
fn routing_advertisement_uses_stable_domain_tag() {
    let src = read(sdk_path("src/sdk/routing_sdk.rs"));
    assert!(
        src.contains("pub(crate) const ROUTING_VAULT_AD_DOMAIN: &str = \"DSM/routing-vault-ad\";"),
        "regression: ROUTING_VAULT_AD_DOMAIN changed — this breaks every \
         previously-published routing advertisement"
    );
}

/// DeTFi routing discovery — the proto schema MUST carry
/// `RoutingVaultAdvertisementV1` so the SDK's encode/decode path
/// continues to compile.  Removing it is a wire-format break.
#[test]
fn proto_schema_carries_routing_vault_advertisement() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let repo_root = Path::new(manifest_dir)
        .parent()
        .and_then(|p| p.parent())
        .and_then(|p| p.parent())
        .expect("resolve repo root");
    let proto = repo_root.join("proto").join("dsm_app.proto");
    let proto_src = read(proto);
    assert!(
        proto_src.contains("message RoutingVaultAdvertisementV1 {"),
        "regression: proto/dsm_app.proto is missing RoutingVaultAdvertisementV1"
    );
}

/// DeTFi routing path search — the path-search module MUST stay free
/// of any RouteCommit / atomic-execution coupling.  Chunk #2 is pure
/// discovery + path selection; chunk #3 is where commitment + settlement
/// land.  A regression that imported `RouteCommitV1` (or any settlement
/// helper) into routing_path_sdk would mix algorithmic routing bugs
/// with atomicity bugs and break the layered scope invariant.
#[test]
fn routing_path_sdk_does_not_touch_routecommit_or_settlement() {
    let src = read(sdk_path("src/sdk/routing_path_sdk.rs"));
    assert!(
        !src.contains("RouteCommitV1"),
        "regression: routing_path_sdk imported RouteCommitV1 — chunk #3 work \
         leaked into chunk #2.  Path search must remain pure."
    );
    assert!(
        !src.contains("execute_on_relationship"),
        "regression: routing_path_sdk reached into the state-machine \
         settlement path — chunk #2 must not touch atomic execution."
    );
    assert!(
        !src.contains("Operation::DlvClaim") && !src.contains("Operation::DlvCreate"),
        "regression: routing_path_sdk emitted a state-machine Operation — \
         chunk #2 produces Path candidates only, no on-chain side effects."
    );
}

/// DeTFi routing path search — the cost function MUST select on
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

/// DeTFi chunk #3 invariant — the external-commitment derivation MUST
/// use the `DSM/ext` BLAKE3 domain tag (matches DeTFi spec §3.2:
/// `ExtCommit(X) = H("DSM/ext" || X)`).  A tag swap silently breaks
/// every recipient's X re-derivation, making published anchors
/// uncorrelatable with the RouteCommits they're supposed to bind.
#[test]
fn external_commitment_uses_stable_domain_tag() {
    let src = read(sdk_path("src/sdk/route_commit_sdk.rs"));
    assert!(
        src.contains("pub(crate) const EXT_COMMIT_DOMAIN: &str = \"DSM/ext\";"),
        "regression: EXT_COMMIT_DOMAIN changed — this breaks every \
         previously-published external commitment X"
    );
    assert!(
        src.contains("pub(crate) const EXT_COMMIT_ROOT: &str = \"defi/extcommit/\";"),
        "regression: EXT_COMMIT_ROOT prefix changed — every previously-\
         published anchor would become unfindable"
    );
}

/// DeTFi chunk #3 invariant — the canonical bytes that feed `compute_external_commitment`
/// MUST exclude `initiator_signature`.  Otherwise the trader cannot
/// sign over X (chicken-and-egg: signing changes the bytes which
/// changes X which invalidates the signature).
#[test]
fn external_commitment_excludes_initiator_signature_from_canonical_form() {
    let src = read(sdk_path("src/sdk/route_commit_sdk.rs"));
    assert!(
        src.contains("out.initiator_signature.clear();"),
        "regression: canonicalise_for_commitment no longer zeroes \
         initiator_signature — sign-and-commit invariant broken"
    );
}

/// DeTFi chunk #3 boundary — `route_commit_sdk` is a PURE binder +
/// storage anchor.  Per-hop unlock handler wiring (extending
/// `Operation::DlvUnlock` to verify a RouteCommit + check anchor
/// visibility) is chunk #4 and MUST NOT leak into this module before
/// then.  Mirrors the chunk #2 / chunk #3 boundary guard.
#[test]
fn route_commit_sdk_does_not_emit_state_machine_operations() {
    let src = read(sdk_path("src/sdk/route_commit_sdk.rs"));
    assert!(
        !src.contains("execute_on_relationship"),
        "regression: route_commit_sdk reached into the state-machine \
         settlement path — chunk #4 work leaked into chunk #3."
    );
    assert!(
        !src.contains("Operation::DlvUnlock")
            && !src.contains("Operation::DlvClaim")
            && !src.contains("Operation::DlvCreate"),
        "regression: route_commit_sdk emitted a state-machine \
         Operation — chunk #3 produces RouteCommitV1 + anchor only."
    );
}

/// DeTFi chunk #3 invariant — the proto schema MUST carry both
/// `RouteCommitV1` and `ExternalCommitmentV1` so the SDK encode/decode
/// path stays usable.  Removing either is a wire-format break.
#[test]
fn proto_schema_carries_route_commit_messages() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let repo_root = Path::new(manifest_dir)
        .parent()
        .and_then(|p| p.parent())
        .and_then(|p| p.parent())
        .expect("resolve repo root");
    let proto = repo_root.join("proto").join("dsm_app.proto");
    let proto_src = read(proto);
    assert!(
        proto_src.contains("message RouteCommitV1 {"),
        "regression: proto/dsm_app.proto is missing RouteCommitV1"
    );
    assert!(
        proto_src.contains("message RouteCommitHopV1 {"),
        "regression: proto/dsm_app.proto is missing RouteCommitHopV1"
    );
    assert!(
        proto_src.contains("message ExternalCommitmentV1 {"),
        "regression: proto/dsm_app.proto is missing ExternalCommitmentV1"
    );
}

/// DeTFi chunk #4 invariant — the routed-unlock handler MUST run the
/// SDK eligibility check (vault_id ∈ RouteCommit AND X visible)
/// BEFORE emitting `Operation::DlvUnlock`.  Without the gate, any
/// caller could trigger an unlock by handing the device an arbitrary
/// RouteCommit, defeating the atomic-visibility guarantee.
#[test]
fn dlv_unlock_routed_runs_eligibility_check_before_state_advance() {
    let src = read(sdk_path("src/handlers/dlv_routes.rs"));
    assert!(
        src.contains("verify_route_commit_unlock_eligibility"),
        "regression: dlv.unlockRouted no longer calls the eligibility \
         verifier — atomic-visibility gate is missing"
    );
    // The verifier call must come BEFORE `execute_on_relationship` in
    // the source order — eyeball the handler if this guard fails.
    let verify_pos = src
        .find("verify_route_commit_unlock_eligibility")
        .expect("verifier must be present (asserted above)");
    let mut search_from = 0;
    let mut found_after = false;
    while let Some(pos) = src[search_from..].find("execute_on_relationship") {
        let abs = search_from + pos;
        if abs > verify_pos {
            // Found an `execute_on_relationship` call AFTER the
            // verifier — that's the routed-unlock handler.  Done.
            found_after = true;
            break;
        }
        search_from = abs + "execute_on_relationship".len();
    }
    assert!(
        found_after,
        "regression: dlv.unlockRouted is calling execute_on_relationship \
         BEFORE the eligibility verifier — gate must come first"
    );
}

/// DeTFi chunk #4 invariant — the proto schema MUST carry
/// `DlvUnlockRoutedV1` so the handler decoder continues to compile.
#[test]
fn proto_schema_carries_dlv_unlock_routed() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let repo_root = Path::new(manifest_dir)
        .parent()
        .and_then(|p| p.parent())
        .and_then(|p| p.parent())
        .expect("resolve repo root");
    let proto = repo_root.join("proto").join("dsm_app.proto");
    let proto_src = read(proto);
    assert!(
        proto_src.contains("message DlvUnlockRoutedV1 {"),
        "regression: proto/dsm_app.proto is missing DlvUnlockRoutedV1"
    );
}

/// DeTFi chunk #4 invariant — `dlv.unlockRouted` MUST be wired into
/// the `dlv.*` invoke dispatcher.  An unrouted dispatcher would route
/// the call to `unknown dlv invoke method` despite the handler being
/// implemented.
#[test]
fn dlv_unlock_routed_is_dispatched() {
    let src = read(sdk_path("src/handlers/dlv_routes.rs"));
    assert!(
        src.contains("\"dlv.unlockRouted\" => self.dlv_unlock_routed(i).await,"),
        "regression: dlv.unlockRouted is not wired into handle_dlv_invoke"
    );
}

/// DeTFi chunk #5 invariant — the eligibility verifier MUST call
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

/// DeTFi chunk #5 invariant — the canonical bytes fed to SPHINCS+
/// verify MUST be the SAME canonical form fed to the external
/// commitment X.  Any divergence would let an attacker sign one
/// canonical form while publishing under the other's X — the gate
/// must use a single source of canonicalisation truth.
#[test]
fn route_commit_signature_uses_same_canonical_form_as_x() {
    let src = read(sdk_path("src/sdk/route_commit_sdk.rs"));
    // Both `compute_external_commitment` and the eligibility verifier
    // must call `canonicalise_for_commitment`.  A future edit that
    // bypassed that helper for either path would silently break the
    // sign-and-commit invariant.
    let calls = src.matches("canonicalise_for_commitment(&rc)").count();
    assert!(
        calls >= 2,
        "regression: canonicalise_for_commitment is called fewer than \
         twice — sign path and X-derivation path must both use it"
    );
}

/// Track C.3 invariant — the four trade-flow routes MUST be wired
/// into the `route.*` dispatcher.  Without these, the frontend's
/// `publishRoutingAdvertisement` / `listAdvertisementsForPair` /
/// `syncVaultsForPair` / `findAndBindBestPath` calls would round-trip
/// to "unknown route invoke method" / "unknown route query path"
/// even though the handlers are implemented.
#[test]
fn route_trade_flow_routes_are_dispatched() {
    let src = read(sdk_path("src/handlers/route_routes.rs"));
    let dispatch_edges = [
        (
            "route.publishRoutingAdvertisement",
            "self.route_publish_routing_advertisement(i).await",
        ),
        (
            "route.listAdvertisementsForPair",
            "self.route_list_advertisements_for_pair(q).await",
        ),
        (
            "route.syncVaultsForPair",
            "self.route_sync_vaults_for_pair(i).await",
        ),
        (
            "route.findAndBindBestPath",
            "self.route_find_and_bind_best_path(i).await",
        ),
    ];
    for (route_name, handler_call) in dispatch_edges {
        assert!(
            src.contains(route_name) && src.contains(handler_call),
            "regression: trade-flow dispatch edge missing: {route_name} -> {handler_call}"
        );
    }
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

/// Track C.3 invariant — `route.findAndBindBestPath` MUST leave
/// `initiator_public_key` empty in the unsigned RouteCommit it
/// returns.  The subsequent `route.signRouteCommit` invoke
/// overrides that field with the wallet's pk per chunk #6.  If the
/// bind step stamped any other pk, sign-as-someone-else attacks
/// would re-open: a caller could ask the wallet to sign a route
/// they pre-attributed to anyone else.
#[test]
fn find_and_bind_leaves_initiator_pk_empty_for_sign_to_overwrite() {
    let src = read(sdk_path("src/handlers/route_routes.rs"));
    assert!(
        src.contains("initiator_public_key: &[],"),
        "regression: route.findAndBindBestPath no longer leaves \
         initiator_public_key empty for the sign step to fill in — \
         sign-as-someone-else attack surface re-opened"
    );
}

/// Track C.2 invariant — `route.*` query/invoke routes MUST be wired
/// into the dispatcher.  Without these, the TS bindings in
/// `frontend/src/dsm/route_commit.ts` would round-trip to
/// `unknown route query path` despite the handler being implemented.
#[test]
fn route_query_and_invoke_are_dispatched() {
    let src = read(sdk_path("src/handlers/app_router_impl.rs"));
    assert!(
        src.contains("p if p.starts_with(\"route.\") => self.handle_route_query(q).await,"),
        "regression: route.* query dispatch edge missing from app_router_impl"
    );
    assert!(
        src.contains("m if m.starts_with(\"route.\") => self.handle_route_invoke(i).await,"),
        "regression: route.* invoke dispatch edge missing from app_router_impl"
    );
}

/// "All business logic stays in Rust" invariant — the frontend
/// MUST NOT carry a BLAKE3 implementation.  Track C.1 originally
/// shipped `@noble/hashes` to compute DLV digests inline; chunk #6
/// migrated that to a Rust accept-or-compute path on `dlv.create`.
/// A regression that re-installed the dep or restored
/// `utils/blake3.ts` would re-open the protocol-logic-duplication
/// surface this rule exists to prevent.
#[test]
fn frontend_does_not_carry_blake3() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let repo_root = Path::new(manifest_dir)
        .parent()
        .and_then(|p| p.parent())
        .and_then(|p| p.parent())
        .expect("resolve repo root");
    let pkg = repo_root
        .join("dsm_client")
        .join("frontend")
        .join("package.json");
    let pkg_src = read(pkg);
    assert!(
        !pkg_src.contains("@noble/hashes"),
        "regression: @noble/hashes is back in the frontend — \
         all crypto must stay Rust-side per the architectural rule"
    );
    let blake3_ts = repo_root
        .join("dsm_client")
        .join("frontend")
        .join("src")
        .join("utils")
        .join("blake3.ts");
    assert!(
        !blake3_ts.exists(),
        "regression: utils/blake3.ts has been re-introduced — \
         the frontend must delegate BLAKE3 to Rust over the bridge"
    );
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

/// Chunk #6 invariant — `route.signRouteCommit` MUST sign with the
/// wallet's CURRENT signing key, not whatever the caller stamped on
/// `initiator_public_key`.  Otherwise an attacker could ask the
/// wallet to sign-as-someone-else by submitting a RouteCommit with
/// a forged initiator pk.  The handler must overwrite the field.
#[test]
fn route_sign_route_commit_overwrites_initiator_public_key() {
    let src = read(sdk_path("src/handlers/route_routes.rs"));
    assert!(
        src.contains("rc.initiator_public_key = pk;"),
        "regression: route.signRouteCommit no longer stamps the wallet \
         pk on initiator_public_key — caller-supplied pk would be honoured \
         and sign-as-someone-else attacks become possible"
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

/// Chunk #7 invariant — the re-simulation MUST use the SAME
/// `constant_product_output` function that chunk #2's path search
/// uses.  Any divergence between path-time and unlock-time
/// computation means the trader's signed `expected_output` will
/// systematically fail re-simulation, breaking every routed unlock.
#[test]
fn amm_re_simulation_uses_path_search_simulator() {
    let src = read(sdk_path("src/sdk/route_commit_sdk.rs"));
    assert!(
        src.contains("crate::sdk::routing_path_sdk::constant_product_output"),
        "regression: route_commit_sdk no longer delegates to the path-search \
         simulator — sign-time and unlock-time math could drift"
    );
}

/// Chunk #7 invariant — the post-trade reserve update MUST use the
/// FULL `input_amount` (Uniswap V2 invariant: fee accrues to the
/// pool as LP yield).  A regression that subtracted the fee from
/// the input before adding to the reserve would leak fees out of
/// the pool, breaking the constant-product invariant the simulator
/// relies on.
#[test]
fn amm_reserve_update_uses_full_input_amount() {
    let src = read(sdk_path("src/sdk/route_commit_sdk.rs"));
    assert!(
        src.contains("reserve_in\n        .checked_add(input_amount)"),
        "regression: AMM post-trade reserve update no longer uses the full \
         input_amount — fees would leak out of the pool"
    );
}

/// Tier 1 invariant — `dlv.listOwnedAmmVaults` MUST be wired into the
/// `dlv.*` query dispatch and MUST delegate filtering to the audited
/// signing-authority + DLVManager primitives.  Without this, the AMM
/// monitor screen has no data source.  A regression that
/// re-implemented the filter inline would silently bypass the
/// "wallet pk owns the vault" check.
#[test]
fn dlv_list_owned_amm_vaults_is_dispatched_and_delegates() {
    let routes_src = read(sdk_path("src/handlers/dlv_routes.rs"));
    assert!(
        routes_src
            .contains("\"dlv.listOwnedAmmVaults\" => self.dlv_list_owned_amm_vaults(q).await,"),
        "regression: dlv.listOwnedAmmVaults dispatch edge missing in handle_dlv_query"
    );
    assert!(
        routes_src.contains("crate::sdk::signing_authority::current_public_key()"),
        "regression: dlv.listOwnedAmmVaults no longer reaches into \
         signing_authority for the owner-filter wallet pk"
    );
    assert!(
        routes_src.contains("self.bitcoin_tap.dlv_manager()"),
        "regression: dlv.listOwnedAmmVaults no longer reads vaults from \
         the DLVManager"
    );
    assert!(
        routes_src.contains("crate::sdk::routing_sdk::load_active_advertisements_for_pair"),
        "regression: dlv.listOwnedAmmVaults no longer cross-references \
         the routing-vault advertisements for state_number / advertised flag"
    );

    let app_router_src = read(sdk_path("src/handlers/app_router_impl.rs"));
    assert!(
        app_router_src.contains("p if p.starts_with(\"dlv.\") => self.handle_dlv_query(q).await,"),
        "regression: dlv.* query dispatch edge missing in app_router_impl"
    );
}

/// Republish-on-settled invariant — `dlv.unlockRouted` MUST call
/// `routing_sdk::republish_active_advertisement_with_reserves` after
/// the post-trade vault reserve update so the next trader's quote
/// reflects post-trade liquidity.  Without this, every subsequent
/// trader hits a chunk-#7 `OutputMismatch` rejection until somebody
/// manually republishes — terrible UX.  The republish is best-
/// effort (failure logs but doesn't fail the trade); the regression
/// guard just enforces the call still happens.
#[test]
fn dlv_unlock_routed_republishes_advertisement_after_settled_swap() {
    let src = read(sdk_path("src/handlers/dlv_routes.rs"));
    let routed_start = src
        .find("async fn dlv_unlock_routed")
        .expect("dlv_unlock_routed handler present");
    let routed_body = &src[routed_start..];
    assert!(
        routed_body
            .contains("crate::sdk::routing_sdk::republish_active_advertisement_with_reserves"),
        "regression: dlv.unlockRouted no longer republishes the routing-vault \
         advertisement after a settled swap — every subsequent trader will hit \
         OutputMismatch on a stale quote"
    );
}

/// Track C.5 invariant — both storage publishers MUST honour the
/// accept-or-stamp pattern on the publisher / owner pk field.
/// Frontend dev-tools screens (and any future routing-service
/// integration) pass empty bytes; the handler stamps the wallet's
/// current SPHINCS+ pk before persisting.  A regression that
/// removed either branch would force callers back to placeholder
/// zeros (the prior pre-Track-C.5 hack), violating the rule that
/// every public key on the wire is the wallet's actual key.
#[test]
fn route_publish_routes_stamp_wallet_pk_on_empty() {
    let src = read(sdk_path("src/handlers/route_routes.rs"));
    let needles = [
        // publishExternalCommitment branch
        (
            "publish_external_commitment\\b",
            "if req.publisher_public_key.is_empty() {",
        ),
        (
            "publish_external_commitment\\b",
            "req.publisher_public_key = pk",
        ),
        // publishRoutingAdvertisement branch
        (
            "publish_routing_advertisement\\b",
            "if req.owner_public_key.is_empty() {",
        ),
        (
            "publish_routing_advertisement\\b",
            "req.owner_public_key = pk",
        ),
    ];
    for (_route, needle) in needles {
        assert!(
            src.contains(needle),
            "regression: route accept-or-stamp branch missing: {needle}"
        );
    }
}

/// Track C.4 invariant — `dlv.create` MUST stamp the wallet's
/// SPHINCS+ pk on `creator_public_key` when the field rides empty
/// over the wire AND sign Rust-side when `signature` rides empty.
/// This is the same accept-or-stamp pattern chunk #6 used for
/// `route.signRouteCommit`; without it the AMM owner UI couldn't
/// create vaults without exposing wallet keys to TS.
///
/// Two regressions this guard catches:
///   * Empty-pk handling removed → frontend gets a hard error
///     "creator_public_key is required" and the UI breaks.
///   * Empty-sig handling removed → same.
///   * Self-sign domain tag changed → all previously self-signed
///     vaults fail re-verification.
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
        src.contains("if req.signature.is_empty() {"),
        "regression: dlv.create no longer checks for empty signature \
         (Track C.4 accept-or-sign surface broken)"
    );
    assert!(
        src.contains("crate::sdk::signing_authority::current_secret_key()"),
        "regression: dlv.create accept-or-sign no longer reaches into \
         signing_authority for the wallet sk"
    );
    assert!(
        src.contains("\"DSM/dlv-create-self-sign\""),
        "regression: dlv.create self-sign domain tag changed — \
         previously-self-signed vaults will fail re-verification"
    );
}

/// Chunk #6 invariant — `route.signRouteCommit` MUST canonicalise
/// via the SAME helper that the X-derivation and the eligibility
/// verifier use.  Any divergence in canonicalisation between
/// signing and verification breaks sign-and-commit.
#[test]
fn route_sign_route_commit_uses_canonicalise_for_commitment() {
    let src = read(sdk_path("src/handlers/route_routes.rs"));
    assert!(
        src.contains("canonicalise_for_commitment(&rc)"),
        "regression: route.signRouteCommit no longer uses the shared \
         canonicalise_for_commitment helper — sign and verify could drift"
    );
}

/// Track C.2 invariant — `route_routes` MUST delegate the
/// X-compute / publish / visibility paths to the audited
/// `route_commit_sdk` helpers.  A future edit that re-implemented
/// the BLAKE3 derivation inline (or skipped the SDK's
/// canonicalise→verify pipeline) would silently bypass the chunk #5
/// signature gate.  The guard fails if any of the three
/// route handlers stop calling its corresponding SDK function.
#[test]
fn route_routes_delegate_to_route_commit_sdk() {
    let src = read(sdk_path("src/handlers/route_routes.rs"));
    assert!(
        src.contains("crate::sdk::route_commit_sdk::compute_external_commitment"),
        "regression: route.computeExternalCommitment no longer calls the SDK"
    );
    assert!(
        src.contains("crate::sdk::route_commit_sdk::is_external_commitment_visible"),
        "regression: route.isExternalCommitmentVisible no longer calls the SDK"
    );
    assert!(
        src.contains("crate::sdk::route_commit_sdk::publish_external_commitment"),
        "regression: route.publishExternalCommitment no longer calls the SDK"
    );
}

/// Commit 3 invariant — the strict resolver lives at the TokenSDK
/// layer.  Code that derives `policy_commit` from `TokenMetadata`
/// directly bypasses policy registration and must not come back.
#[test]
fn no_policy_commit_derived_from_metadata_cache() {
    for rel in [
        "src/handlers/token_routes.rs",
        "src/handlers/dlv_routes.rs",
        "src/handlers/detfi_routes.rs",
        "src/handlers/bilateral_settlement.rs",
    ] {
        let src = read(sdk_path(rel));
        assert!(
            !src.contains("policy_commit = metadata.policy_anchor"),
            "regression: {rel} derives policy_commit directly from TokenMetadata"
        );
        assert!(
            !src.contains("from_policy_anchor(&metadata.policy_anchor"),
            "regression: {rel} derives policy_commit directly from TokenMetadata"
        );
    }
}

/// Tier 2 Foundation invariant — `dlv.create` must publish the
/// genesis vault state anchor for AMM (Required / Optional) vaults
/// via the `vault_state_anchor` module.  The guard fails if the
/// publish call, the reserves-digest derivation, or the enforcement
/// dispatch are removed.
#[test]
fn dlv_create_invokes_genesis_anchor_publish_for_required_amm_vault() {
    let src = read(sdk_path("src/handlers/dlv_routes.rs"));
    // The genesis-anchor publish path uses these symbols in dlv_create:
    assert!(
        src.contains("publish_vault_state_anchor"),
        "dlv_routes.rs must call publish_vault_state_anchor for Tier 2 Foundation"
    );
    assert!(
        src.contains("compute_reserves_digest")
            || src.contains("vault_state_anchor::compute_reserves_digest"),
        "dlv_routes.rs must derive reserves_digest via the anchor module"
    );
    assert!(
        src.contains("AnchorEnforcement::Required") || src.contains("AnchorEnforcement::Optional"),
        "dlv_routes.rs must dispatch on anchor_enforcement"
    );
}

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

/// Tier 2 Foundation invariant — after an accepted routed unlock, the
/// vault's internal `current_sequence` must advance by exactly one and
/// a fresh `VaultStateAnchorV1` must be republished for the post-trade
/// state.  The guard fails if either step regresses.
#[test]
fn dlv_unlock_routed_advances_sequence_and_republishes_anchor_on_settle() {
    let src = read(sdk_path("src/handlers/dlv_routes.rs"));
    // After accepted unlock, sequence must advance.
    assert!(
        src.contains("current_sequence.saturating_add(1)") || src.contains("current_sequence += 1"),
        "settle path must advance vault.current_sequence"
    );
    // A second call to `publish_vault_state_anchor` must exist —
    // one in `dlv_create` for genesis, one in `dlv_unlock_routed`
    // for settle.  If only one (or zero) calls exist, either the
    // genesis or the post-settle republish has regressed.
    let count = src.matches("publish_vault_state_anchor").count();
    assert!(
        count >= 2,
        "publish_vault_state_anchor must be called from both dlv_create and dlv_unlock_routed (found {count})"
    );
}
