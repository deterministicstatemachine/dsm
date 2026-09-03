// SPDX-License-Identifier: MIT OR Apache-2.0
//! An adopted token must resolve its policy commitment on the RECEIVING device.
//!
//! THE HARDWARE FAILURE. 8XK sent 250.00 RIGB to D3. The sender committed —
//! 100_000 base units down to 75_000, a signed transition submitted to the
//! storage node — and the receiver refused the apply:
//!
//!   [storage.sync] §16.6 full-state apply errored:
//!   State error: Missing canonical policy anchor for token RIGB — no ACK
//!
//! `resolve_policy_commit_strict` looked in exactly two places: the builtin
//! policies, and the per-relationship chain-state archive, hunting for an
//! operation that registered metadata for the token. The device that CREATED
//! RIGB has a `CreateToken` there. A device that ADOPTED it by its CPTA anchor
//! does not, and never will — adoption registers an identity, it is not a
//! transition on the adopting device's chain.
//!
//! So the resolver worked on exactly the device that did not need it, and
//! every first receipt of a created token fail-closed after the sender had
//! already debited.
//!
//! The registry is authoritative for the persisted token IDENTITY mapping, so
//! it is consulted first. It is self-certifying rather than trusted: the
//! stored bytes are re-hashed and must equal the commitment they live under.

#![allow(clippy::disallowed_methods)]

use dsm_sdk::runtime;
use dsm_sdk::storage::client_db::token_registry;

/// Register a token exactly as ADOPTION does on a receiving device: an
/// identity row plus the anchored policy bytes, and NO CreateToken of its own.
fn adopt(ticker: &str, policy_bytes: &[u8]) -> [u8; 32] {
    let commit = dsm::crypto::blake3::domain_hash_bytes(
        dsm::common::domain_tags::TAG_DSM_POLICY,
        policy_bytes,
    );
    token_registry::upsert_policy(&commit, policy_bytes).expect("store policy");
    token_registry::insert_token(&token_registry::TokenRegistryRow {
        token_id: format!("{ticker}TOKENID"),
        policy_commit: commit,
        ticker: ticker.to_string(),
        alias: format!("{ticker} Token"),
        decimals: 2,
        max_supply: 100_000_000,
        owner_device_id: [0x11; 32],
    })
    .expect("register");
    commit
}

/// THE REPRODUCTION: adopted, never created here, and it must resolve.
#[test]
#[serial_test::serial]
fn an_adopted_token_resolves_without_a_local_creation() {
    runtime::dsm_init_runtime();
    // The router initialises the database and installs the identity, so it
    // must come BEFORE anything writes a registry row. No funding: these are
    // policy-RESOLUTION tests and hold no economic value.
    let (r, _fleet) = dsm_sdk::economic_fixtures::empty_router(0xa1);
    let commit = adopt("RIGB", b"rigb-policy-bytes");

    let resolved = r
        .core_sdk
        .resolve_policy_commit_strict(b"RIGB")
        .expect("an adopted token must resolve on the receiving device");
    assert_eq!(
        resolved, commit,
        "and must resolve to the anchor the policy actually hashes to"
    );
}

/// Resolution works by token id as well as by ticker — the incoming operation
/// may name either.
#[test]
#[serial_test::serial]
fn an_adopted_token_resolves_by_token_id_too() {
    runtime::dsm_init_runtime();
    // The router initialises the database and installs the identity, so it
    // must come BEFORE anything writes a registry row. No funding: these are
    // policy-RESOLUTION tests and hold no economic value.
    let (r, _fleet) = dsm_sdk::economic_fixtures::empty_router(0xa1);
    let commit = adopt("BYID", b"byid-policy-bytes");

    assert_eq!(
        r.core_sdk
            .resolve_policy_commit_strict(b"BYIDTOKENID")
            .expect("resolve by token id"),
        commit
    );
}

/// SELF-CERTIFYING, NOT TRUSTED. A registry row whose stored bytes do not hash
/// to the commitment they live under must NOT resolve. Otherwise this would be
/// a mutable cache granted authority over the policy that governs an asset.
#[test]
#[serial_test::serial]
fn a_registry_row_whose_policy_does_not_hash_to_its_commit_does_not_resolve() {
    runtime::dsm_init_runtime();
    // The router initialises the database; the deliberately-inconsistent rows
    // below are an adversarial TEST VECTOR (policy bytes filed under a commit
    // that is not their hash) proving resolution REFUSES them — not fabricated
    // economic value, and nothing here is expected to be accepted.
    let (r, _fleet) = dsm_sdk::economic_fixtures::empty_router(0xa1);

    // An identity row pointing at a commitment with no matching policy bytes.
    token_registry::insert_token(&token_registry::TokenRegistryRow {
        token_id: "LIARTOKENID".to_string(),
        policy_commit: [0x99; 32],
        ticker: "LIAR".to_string(),
        alias: "Liar".to_string(),
        decimals: 2,
        max_supply: 1,
        owner_device_id: [0u8; 32],
    })
    .expect("register");
    // Bytes stored under a commitment that is NOT their hash.
    token_registry::upsert_policy(&[0x99; 32], b"these-bytes-hash-to-something-else")
        .expect("store");

    assert!(
        r.core_sdk.resolve_policy_commit_strict(b"LIAR").is_err(),
        "a row that does not carry the real policy must not resolve"
    );
}

/// Builtins keep resolving from the builtin table, ahead of any registry row.
#[test]
#[serial_test::serial]
fn builtin_tokens_still_resolve() {
    runtime::dsm_init_runtime();
    let (r, _fleet) = dsm_sdk::economic_fixtures::empty_router(0xa1);

    assert_eq!(
        r.core_sdk
            .resolve_policy_commit_strict(b"ERA")
            .expect("ERA is builtin"),
        dsm::core::token::builtin_policy_commit_for_token("ERA").expect("ERA")
    );
}

/// An unknown token still fails closed. Resolution must never invent an anchor.
#[test]
#[serial_test::serial]
fn an_unknown_token_still_fails_closed() {
    runtime::dsm_init_runtime();
    let (r, _fleet) = dsm_sdk::economic_fixtures::empty_router(0xa1);

    assert!(
        r.core_sdk
            .resolve_policy_commit_strict(b"NEVERSEEN")
            .is_err(),
        "an unknown token must fail closed, not resolve to a guess"
    );
}
