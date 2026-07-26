// SPDX-License-Identifier: MIT OR Apache-2.0
//! The supply cap must not be evaluated against a total derived from history
//! the device could not fully read.
//!
//! `get_bcr_chain_states` skips rows it cannot decode, logging a warning and
//! carrying on. For rendering a history list that is the right call — one bad
//! row should not blank the screen. For deriving an AMOUNT it is a fail-open:
//! a dropped `Mint` lowers the computed circulating supply, and a cap checked
//! against a total that is too low permits a mint that should be refused.
//!
//! `derive_circulating_supply` used to make this strictly worse by returning
//! `0` when the history could not be read at all — reporting maximum headroom
//! exactly when the chain was least trustworthy. It now reports ABSENCE, and
//! the enforcer already refuses a capped operation whose circulating supply it
//! cannot establish (see `supply_cap_fails_closed_without_circulating_supply`
//! in token_authority_enforcement.rs).
//!
//! This pins the two halves that make that guarantee real: the loader tells the
//! truth about what it dropped, and an absent figure denies rather than allows.

#![allow(clippy::disallowed_methods)]

use dsm::core::token::policy::policy_enforcement::{witness_keys, EnforcementContext, PolicyEnforcer};
use dsm::types::policy_types::PolicyCondition;
use dsm_sdk::storage::client_db::{last_load_dropped_rows, reset_database_for_tests};

async fn allowed(cond: &PolicyCondition, c: &EnforcementContext) -> bool {
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

/// A clean load reports nothing dropped, so a derived figure is trustworthy.
#[test]
#[serial_test::serial]
fn a_clean_load_reports_no_dropped_rows() {
    std::env::set_var("DSM_SDK_TEST_MODE", "1");
    reset_database_for_tests();
    let _ = dsm_sdk::storage::client_db::get_bcr_chain_states(&[7u8; 32], false);
    assert_eq!(
        last_load_dropped_rows(),
        0,
        "an empty/clean history must not report dropped rows"
    );
}

/// THE FAIL-OPEN, CLOSED. With circulating supply absent, a capped mint is
/// denied — it is not treated as though nothing had ever been minted.
///
/// Before the fix, an unreadable chain yielded `circulating = 0`, which for a
/// 1000-cap token authorised a mint of the entire supply on a device whose
/// history said otherwise.
#[tokio::test]
async fn absent_circulating_supply_denies_instead_of_granting_full_headroom() {
    let cond = PolicyCondition::SupplyCap {
        max_supply: 1_000,
        unlimited: false,
    };

    let mut ctx = EnforcementContext::new("mint", 0);
    ctx.data.insert(
        witness_keys::AMOUNT.to_string(),
        1_000u64.to_le_bytes().to_vec(),
    );
    // No CIRCULATING witness: the device could not read its own history.
    assert!(
        !allowed(&cond, &ctx).await,
        "a mint must be refused when circulating supply cannot be established"
    );

    // And the same request with a truthful figure of 0 IS allowed — proving the
    // denial above comes from absence, not from the amount being large.
    ctx.data.insert(
        witness_keys::CIRCULATING.to_string(),
        0u64.to_le_bytes().to_vec(),
    );
    assert!(
        allowed(&cond, &ctx).await,
        "with a known circulating supply of 0, minting exactly the cap is fine"
    );
}

/// An under-counted total is what a dropped Mint row produces. Pin that the cap
/// arithmetic itself is inclusive and exact, so the only way to wrongly allow
/// is to feed it a wrong number — which is what refusing partial history stops.
#[tokio::test]
async fn cap_is_exact_so_an_undercount_is_the_only_way_through() {
    let cond = PolicyCondition::SupplyCap {
        max_supply: 1_000,
        unlimited: false,
    };
    let ctx = |circulating: u64, amount: u64| {
        let mut c = EnforcementContext::new("mint", 0);
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

    // Truth: 900 already minted, 101 more would exceed the cap.
    assert!(!allowed(&cond, &ctx(900, 101)).await);
    // Exactly on the cap is permitted.
    assert!(allowed(&cond, &ctx(900, 100)).await);
    // An undercount of 200 (one dropped Mint) would have let the 101 through.
    assert!(
        allowed(&cond, &ctx(700, 101)).await,
        "demonstrates the hazard: the cap is only as honest as the total it is given"
    );
}
