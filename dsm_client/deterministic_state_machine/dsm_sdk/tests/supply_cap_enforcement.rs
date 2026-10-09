// SPDX-License-Identifier: MIT OR Apache-2.0
//! The supply cap, enforced: only creation brings supply into being (SoFi
//! §48), the cap is inclusive and exact, and it fails closed when the
//! circulating supply cannot be established.

#![allow(clippy::disallowed_methods)]

use dsm::core::token::policy::policy_enforcement::{witness_keys, EnforcementContext, PolicyEnforcer};
use dsm::types::policy_types::PolicyCondition;

async fn check(cond: &PolicyCondition, c: &EnforcementContext) -> bool {
    PolicyEnforcer::new()
        .check_condition(cond, c)
        .await
        .expect("enforcement runs")
        .allowed
}

// ── supply cap ──────────────────────────────────────────────────────────────

fn supply_ctx(op: &str, amount: u64, circulating: u64) -> EnforcementContext {
    let mut c = EnforcementContext::new(op);
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
    let cond = PolicyCondition::SupplyCap { max_supply: 1_000 };
    assert!(check(&cond, &supply_ctx("create_token", 100, 500)).await);
    // Exactly at the cap is permitted — the ceiling is inclusive.
    assert!(check(&cond, &supply_ctx("create_token", 500, 500)).await);
}

#[tokio::test]
async fn supply_cap_denies_a_creation_that_would_exceed_it() {
    let cond = PolicyCondition::SupplyCap { max_supply: 1_000 };
    assert!(!check(&cond, &supply_ctx("create_token", 501, 500)).await);
}

/// Only creation brings supply into being (SoFi §48): a transfer or a burn
/// moves or destroys units that already exist, so the cap does not gate them.
#[tokio::test]
async fn supply_cap_gates_only_creation() {
    let cond = PolicyCondition::SupplyCap { max_supply: 1_000 };
    assert!(check(&cond, &supply_ctx("transfer", 5_000, 1_000)).await);
    assert!(check(&cond, &supply_ctx("burn", 5_000, 1_000)).await);
    assert!(!check(&cond, &supply_ctx("create_token", 5_000, 1_000)).await);
}

/// Without the derived circulating supply the cap cannot be evaluated, so it
/// must fail closed — guessing would enforce the cap against the wrong number.
#[tokio::test]
async fn supply_cap_fails_closed_without_circulating_supply() {
    let cond = PolicyCondition::SupplyCap { max_supply: 1_000 };
    let mut c = supply_ctx("create_token", 1, 0);
    c.data.remove(witness_keys::CIRCULATING);
    assert!(!check(&cond, &c).await);
}
