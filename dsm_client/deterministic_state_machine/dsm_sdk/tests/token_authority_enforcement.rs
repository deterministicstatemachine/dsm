// SPDX-License-Identifier: MIT OR Apache-2.0
//! Mint/burn authority and supply cap — real enforcement, not policy decoration.
//!
//! Before this, the wizard collected a k-of-N threshold that was parsed and
//! immediately discarded, and there was no signer set ANYWHERE in the data
//! model — so the "N" was undefined and the "k" could not be checked against
//! anything. The only authority verifiers that existed were dead code, and the
//! mint one was unbound anyway: it took the verifying public key from the
//! caller's OWN proof, which authorises anybody able to sign with a key they
//! generated themselves.
//!
//! Since the 0x0029 producer cut, `TokenAuthority` gates BURN and
//! CREATE_TOKEN only: a mint's authority is the policy-signed issuance
//! evidence verified during economic admission, so the mechanism tests here
//! run against "burn" — the operation that still carries the embedded
//! witness — and one test pins the severance itself.
//!
//! These tests exercise the enforcer directly, because that is where the
//! guarantee lives. Each pins a property that the old design failed:
//!
//!   * the verifying key comes from the POLICY, never from the proof;
//!   * the enforcer rebuilds the signed message itself, so a signature over a
//!     different amount/asset/operation cannot be replayed onto this one;
//!   * a k-of-N threshold counts DISTINCT signers;
//!   * the supply cap is evaluated, and fails closed when it cannot be.

#![allow(clippy::disallowed_methods)]

use dsm::core::token::policy::policy_enforcement::{
    token_authorization_preimage, witness_keys, EnforcementContext, PolicyEnforcer,
};
use dsm::types::policy_types::PolicyCondition;

const PC: [u8; 32] = [0x42; 32];
const TOKEN: &[u8] = b"TESTTOK";

fn keypair(seed: u8) -> (Vec<u8>, Vec<u8>) {
    let kp = dsm::crypto::sphincs::generate_keypair_from_seed(
        dsm::crypto::sphincs::SphincsVariant::SPX256f,
        &[seed; 32],
    )
    .expect("deterministic keypair");
    (kp.public_key.clone(), kp.secret_key.clone())
}

/// One `(u32 pk_len, pk, u32 sig_len, sig)` witness record.
fn witness(pk: &[u8], sig: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&(pk.len() as u32).to_le_bytes());
    out.extend_from_slice(pk);
    out.extend_from_slice(&(sig.len() as u32).to_le_bytes());
    out.extend_from_slice(sig);
    out
}

fn sign_for(sk: &[u8], op: &str, amount: u64) -> Vec<u8> {
    let msg = token_authorization_preimage(&PC, op, TOKEN, amount, &[]);
    dsm::crypto::sphincs::sphincs_sign(sk, &msg).expect("sign")
}

fn ctx(op: &str, amount: u64, authorizations: Vec<u8>) -> EnforcementContext {
    let mut c = EnforcementContext::new(op, 0);
    c.data
        .insert(witness_keys::POLICY_COMMIT.to_string(), PC.to_vec());
    c.data
        .insert(witness_keys::TOKEN_ID.to_string(), TOKEN.to_vec());
    c.data.insert(
        witness_keys::AMOUNT.to_string(),
        amount.to_le_bytes().to_vec(),
    );
    c.data
        .insert(witness_keys::AUTHORIZED_BY.to_string(), Vec::new());
    c.data
        .insert(witness_keys::AUTHORIZATIONS.to_string(), authorizations);
    c
}

async fn check(cond: &PolicyCondition, c: &EnforcementContext) -> bool {
    use std::sync::Arc;
    let cache = Arc::new(dsm::core::token::policy::policy_cache::PolicyCache::new(
        dsm::core::token::policy::policy_cache::PolicyCacheConfig::default(),
    ));
    PolicyEnforcer::new(cache)
        .check_condition(cond, c)
        .await
        .expect("enforcement runs")
        .allowed
}

/// The happy path: a signer named in the policy, signing the operation being
/// executed, satisfies a 1-of-1 authority.
#[tokio::test]
async fn authorized_signer_is_allowed() {
    let (pk, sk) = keypair(1);
    let cond = PolicyCondition::TokenAuthority {
        signers: vec![pk.clone()],
        threshold: 1,
    };
    let sig = sign_for(&sk, "burn", 100);
    assert!(check(&cond, &ctx("burn", 100, witness(&pk, &sig))).await);
}

/// THE CORE FLAW, CLOSED. A non-signer presenting a perfectly valid signature
/// over the correct message — signed with a key they generated themselves —
/// must be denied. The old verifier took the public key from this very proof,
/// so it would have accepted.
#[tokio::test]
async fn non_signer_with_a_valid_self_signed_proof_is_denied() {
    let (policy_pk, _policy_sk) = keypair(1);
    let (attacker_pk, attacker_sk) = keypair(9);
    let cond = PolicyCondition::TokenAuthority {
        signers: vec![policy_pk],
        threshold: 1,
    };
    // Cryptographically valid — just not by anyone the policy names.
    let sig = sign_for(&attacker_sk, "burn", 100);
    assert!(
        !check(&cond, &ctx("burn", 100, witness(&attacker_pk, &sig))).await,
        "the verifying key must come from the policy, never from the proof"
    );
}

/// The enforcer rebuilds the signed message from the operation being executed,
/// so a signature over a DIFFERENT amount cannot be replayed onto this one.
#[tokio::test]
async fn signature_over_a_different_amount_is_denied() {
    let (pk, sk) = keypair(1);
    let cond = PolicyCondition::TokenAuthority {
        signers: vec![pk.clone()],
        threshold: 1,
    };
    let sig_for_1 = sign_for(&sk, "burn", 1);
    assert!(
        !check(&cond, &ctx("burn", 1_000_000, witness(&pk, &sig_for_1))).await,
        "a signature authorising 1 must not authorise 1,000,000"
    );
}

/// Nor onto a different operation: the preimage names the op.
#[tokio::test]
async fn signature_for_burn_does_not_authorize_a_create() {
    let (pk, sk) = keypair(1);
    let cond = PolicyCondition::TokenAuthority {
        signers: vec![pk.clone()],
        threshold: 1,
    };
    let burn_sig = sign_for(&sk, "burn", 50);
    assert!(
        !check(&cond, &ctx("create_token", 50, witness(&pk, &burn_sig))).await,
        "a burn authorisation must not authorise a token creation"
    );
}

/// k-of-N counts DISTINCT signers: one signer cannot satisfy a 2-of-2 by
/// presenting two signatures.
#[tokio::test]
async fn threshold_counts_distinct_signers() {
    let (pk1, sk1) = keypair(1);
    let (pk2, sk2) = keypair(2);
    let cond = PolicyCondition::TokenAuthority {
        signers: vec![pk1.clone(), pk2.clone()],
        threshold: 2,
    };

    // One signer, twice → still one distinct signer.
    let mut doubled = witness(&pk1, &sign_for(&sk1, "burn", 7));
    doubled.extend_from_slice(&witness(&pk1, &sign_for(&sk1, "burn", 7)));
    assert!(
        !check(&cond, &ctx("burn", 7, doubled)).await,
        "the same key twice must not satisfy a 2-of-2 threshold"
    );

    // One of two → below threshold.
    assert!(
        !check(
            &cond,
            &ctx("burn", 7, witness(&pk1, &sign_for(&sk1, "burn", 7)))
        )
        .await
    );

    // Both → satisfied.
    let mut both = witness(&pk1, &sign_for(&sk1, "burn", 7));
    both.extend_from_slice(&witness(&pk2, &sign_for(&sk2, "burn", 7)));
    assert!(check(&cond, &ctx("burn", 7, both)).await);
}

/// No witness at all must be denied, not waved through.
#[tokio::test]
async fn missing_authorization_is_denied() {
    let (pk, _sk) = keypair(1);
    let cond = PolicyCondition::TokenAuthority {
        signers: vec![pk],
        threshold: 1,
    };
    let mut c = ctx("burn", 10, Vec::new());
    c.data.remove(witness_keys::AUTHORIZATIONS);
    assert!(!check(&cond, &c).await);
}

/// THE SEVERANCE PIN. `TokenAuthority` does NOT gate "mint" any more: a mint
/// with no witness at all passes this CONDITION, because a mint's authority is
/// the 0x0029 issuance evidence verified during economic admission — and a
/// second, embedded channel beside it is exactly what the producer cut
/// deleted. (The mint itself is still gated: the accepting layer requires the
/// attached admission, whose source the economic verifier proves.)
#[tokio::test]
async fn token_authority_does_not_gate_mint() {
    let (pk, _sk) = keypair(1);
    let cond = PolicyCondition::TokenAuthority {
        signers: vec![pk],
        threshold: 1,
    };
    let mut c = ctx("mint", 10, Vec::new());
    c.data.remove(witness_keys::AUTHORIZATIONS);
    assert!(
        check(&cond, &c).await,
        "TokenAuthority must not demand a witness from an operation whose \
         authorization channel is the 0x0029 admission evidence"
    );
}

// ── supply cap ──────────────────────────────────────────────────────────────

fn supply_ctx(op: &str, amount: u64, circulating: u64) -> EnforcementContext {
    let mut c = EnforcementContext::new(op, 0);
    c.data.insert(
        witness_keys::AMOUNT.to_string(),
        amount.to_le_bytes().to_vec(),
    );
    c.data.insert(
        witness_keys::CIRCULATING.to_string(),
        circulating.to_le_bytes().to_vec(),
    );
    c
}

#[tokio::test]
async fn supply_cap_allows_up_to_and_including_the_cap() {
    let cond = PolicyCondition::SupplyCap {
        max_supply: 1_000,
        unlimited: false,
    };
    assert!(check(&cond, &supply_ctx("mint", 100, 500)).await);
    // Exactly at the cap is permitted — the ceiling is inclusive.
    assert!(check(&cond, &supply_ctx("mint", 500, 500)).await);
}

#[tokio::test]
async fn supply_cap_denies_a_mint_that_would_exceed_it() {
    let cond = PolicyCondition::SupplyCap {
        max_supply: 1_000,
        unlimited: false,
    };
    assert!(!check(&cond, &supply_ctx("mint", 501, 500)).await);
}

#[tokio::test]
async fn unlimited_supply_ignores_the_cap() {
    let cond = PolicyCondition::SupplyCap {
        max_supply: 0,
        unlimited: true,
    };
    assert!(check(&cond, &supply_ctx("mint", u64::MAX, 0)).await);
}

/// Without the derived circulating supply the cap cannot be evaluated, so it
/// must fail closed — guessing would enforce the cap against the wrong number.
#[tokio::test]
async fn supply_cap_fails_closed_without_circulating_supply() {
    let cond = PolicyCondition::SupplyCap {
        max_supply: 1_000,
        unlimited: false,
    };
    let mut c = supply_ctx("mint", 1, 0);
    c.data.remove(witness_keys::CIRCULATING);
    assert!(!check(&cond, &c).await);
}
