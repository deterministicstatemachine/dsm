// SPDX-License-Identifier: MIT OR Apache-2.0
//! The supply cap must not be evaluated against a total derived from history
//! the device could not fully read.
//!
//! `get_bcr_chain_states` fails on a row it cannot decode or whose state does
//! not recompute its stored tip (`bcr::tests::a_corrupt_archived_row_fails_the_load`),
//! so a history with a row missing never yields a total. `derive_circulating_supply`
//! reports that as ABSENCE, never as `0` — which would be maximum headroom
//! exactly when the chain was least trustworthy — and the enforcer refuses a
//! capped operation whose circulating supply it cannot establish (see
//! `supply_cap_fails_closed_without_circulating_supply` in
//! supply_cap_enforcement.rs).
//!
//! This pins the enforcement half: an absent figure denies rather than allows,
//! and the cap arithmetic is exact, so only a wrong total could get through.

#![allow(clippy::disallowed_methods)]

use dsm::core::token::policy::policy_enforcement::{witness_keys, EnforcementContext, PolicyEnforcer};
use dsm::types::policy_types::PolicyCondition;

async fn allowed(cond: &PolicyCondition, c: &EnforcementContext) -> bool {
    PolicyEnforcer::new()
        .check_condition(cond, c)
        .await
        .expect("enforcement runs")
        .allowed
}

/// THE FAIL-OPEN, CLOSED. With circulating supply absent, a capped creation
/// is denied — it is not treated as though nothing had ever been created.
///
/// Before the fix, an unreadable chain yielded `circulating = 0`, which for a
/// 1000-cap token authorised creating the entire supply again on a device
/// whose history said otherwise.
#[tokio::test]
async fn absent_circulating_supply_denies_instead_of_granting_full_headroom() {
    let cond = PolicyCondition::SupplyCap { max_supply: 1_000 };

    let mut ctx = EnforcementContext::new("create_token");
    ctx.data.insert(
        witness_keys::AMOUNT.to_string(),
        1_000u64.to_le_bytes().to_vec(),
    );
    // No CIRCULATING witness: the device could not read its own history.
    assert!(
        !allowed(&cond, &ctx).await,
        "a creation must be refused when circulating supply cannot be established"
    );

    // And the same request with a truthful figure of 0 IS allowed — proving the
    // denial above comes from absence, not from the amount being large.
    ctx.data.insert(
        witness_keys::CIRCULATING.to_string(),
        0u64.to_le_bytes().to_vec(),
    );
    assert!(
        allowed(&cond, &ctx).await,
        "with a known circulating supply of 0, creating exactly the cap is fine"
    );
}

/// An under-counted total is what a dropped CreateToken row produces. Pin that
/// the cap arithmetic itself is inclusive and exact, so the only way to wrongly
/// allow is to feed it a wrong number — which is what refusing partial history
/// stops.
#[tokio::test]
async fn cap_is_exact_so_an_undercount_is_the_only_way_through() {
    let cond = PolicyCondition::SupplyCap { max_supply: 1_000 };
    let ctx = |circulating: u64, amount: u64| {
        let mut c = EnforcementContext::new("create_token");
        c.data.insert(
            witness_keys::AMOUNT.to_string(),
            amount.to_le_bytes().to_vec(),
        );
        c.data.insert(
            witness_keys::CIRCULATING.to_string(),
            circulating.to_le_bytes().to_vec(),
        );
        c
    };

    // Truth: 900 already in circulation, 101 more would exceed the cap.
    assert!(!allowed(&cond, &ctx(900, 101)).await);
    // Exactly on the cap is permitted.
    assert!(allowed(&cond, &ctx(900, 100)).await);
    // An undercount of 200 (one dropped CreateToken) would have let the 101
    // through.
    assert!(
        allowed(&cond, &ctx(700, 101)).await,
        "demonstrates the hazard: the cap is only as honest as the total it is given"
    );
}
