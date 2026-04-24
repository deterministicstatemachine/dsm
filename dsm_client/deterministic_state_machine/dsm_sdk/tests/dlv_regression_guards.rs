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
