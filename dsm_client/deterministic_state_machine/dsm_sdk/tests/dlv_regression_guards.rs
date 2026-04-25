// SPDX-License-Identifier: MIT OR Apache-2.0
//! Regression guards for the custom tokens + DLV anchoring PR.
//!
//! These tests scan source files for banned patterns so the invariants
//! landed across commits 1–9 cannot be silently reverted by future
//! edits.  They are cheap (no runtime state) and fail with a targeted
//! message pointing at the exact pattern that regressed.
//!
//! Plan references: Part G.4 (negative / regression).

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
    for rel in [
        "src/handlers/dlv_routes.rs",
        "src/handlers/detfi_routes.rs",
    ] {
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
    for rel in [
        "src/vault/limbo_vault.rs",
        "src/vault/dlv_manager.rs",
    ] {
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
