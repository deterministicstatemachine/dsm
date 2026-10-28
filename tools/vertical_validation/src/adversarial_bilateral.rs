// SPDX-License-Identifier: MIT OR Apache-2.0

//! Adversarial bilateral attacks against the path production runs, on real
//! device heads (`DeviceState::advance`). An attack that is accepted is a hard
//! failure.
//!
//! The attacks a receiver decides with Core's `decide_confirm` moved to the
//! SDK's offline step tests, where real bearer pairs run on real nodes: the
//! offline door carries only the offline-bearer transfer, and a confirm takes
//! the sender's anchor-state leaves and the receiver's record of the sender's
//! offline account, which only a walk of the sender's history produces
//! (§6.103). What stays here needs no confirm.

// Validation harness: a device or step that cannot be built is a broken
// harness, and panicking says so.
#![allow(clippy::expect_used)]

use instant::Instant;
use serde::Serialize;

use crate::live_device::{connect, LiveDevice};

// ---------------------------------------------------------------------------
// Result types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub struct AdversarialAttackResult {
    pub attack_name: String,
    pub description: String,
    pub expected_result: String,
    pub actual_result: String,
    pub passed: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct AdversarialSuiteResult {
    pub attacks: Vec<AdversarialAttackResult>,
    pub all_passed: bool,
    pub duration_ms: f64,
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

pub fn collect_adversarial_results() -> AdversarialSuiteResult {
    eprintln!("\n=== ADVERSARIAL BILATERAL TESTS ===\n");
    let start = Instant::now();

    let attacks = vec![attack_balance_underflow()];

    for a in &attacks {
        let icon = if a.passed { "\u{2705}" } else { "\u{274c}" };
        eprintln!("  {icon} {} \u{2014} {}", a.attack_name, a.actual_result);
    }
    eprintln!();

    let all_passed = attacks.iter().all(|a| a.passed);
    AdversarialSuiteResult {
        attacks,
        all_passed,
        duration_ms: start.elapsed().as_secs_f64() * 1000.0,
    }
}

// ---------------------------------------------------------------------------
// Setup
// ---------------------------------------------------------------------------

/// Alice, holding two faucet payouts of ERA, and Bob, contacts.
fn funded_pair() -> (LiveDevice, LiveDevice) {
    let mut alice = LiveDevice::new("adversarial-alice").expect("alice");
    alice.claim_faucet(1).expect("first claim");
    alice.claim_faucet(2).expect("second claim");
    let mut bob = LiveDevice::new("adversarial-bob").expect("bob");
    connect(&mut alice, &mut bob).expect("the two are contacts");
    (alice, bob)
}

fn result(
    name: &str,
    description: &str,
    expected: &str,
    outcome: Result<String, String>,
) -> AdversarialAttackResult {
    let (passed, actual_result) = match outcome {
        Ok(actual) => (true, actual),
        Err(actual) => (false, actual),
    };
    AdversarialAttackResult {
        attack_name: name.into(),
        description: description.into(),
        expected_result: expected.into(),
        actual_result,
        passed,
    }
}

// ---------------------------------------------------------------------------
// Attack 4: spending more than the head holds
// ---------------------------------------------------------------------------

fn attack_balance_underflow() -> AdversarialAttackResult {
    let (alice, bob) = funded_pair();
    let held = alice.era_balance();

    let outcome = (|| {
        let exact = alice
            .transfer(&bob, held, &[0x05; 8])
            .map_err(|e| e.to_string())?;
        alice
            .send(&bob, &exact)
            .map_err(|e| format!("spending exactly the balance was refused: {e}"))?;
        let over = alice
            .transfer(&bob, held + 1, &[0x06; 8])
            .map_err(|e| e.to_string())?;
        match alice.send(&bob, &over) {
            Ok(_) => Err(format!(
                "a debit of {} over a balance of {held} was ACCEPTED",
                held + 1
            )),
            Err(e) => Ok(format!("overspend refused by advance: {e}")),
        }
    })();
    result(
        "balance_underflow",
        "A debit one unit above the head's balance is refused by the advance itself",
        "exact balance spendable, one more refused",
        outcome,
    )
}
