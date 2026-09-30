// SPDX-License-Identifier: MIT OR Apache-2.0

//! Adversarial bilateral attacks against the path production runs.
//!
//! Every attack is made on real device heads (`DeviceState::advance`) and
//! decided as production's receiver decides a step: Core's `decide_prepare`
//! and `decide_confirm` (`dsm::bilateral::offline`), against the shared tip
//! the receiver holds and the keys its contact pins. Each attack first shows
//! the honest step it perturbs is accepted, so a refusal is the receiver
//! refusing the attack and not refusing everything. An attack that is
//! accepted is a hard failure.

// Validation harness: a device or step that cannot be built is a broken
// harness, and panicking says so.
#![allow(clippy::expect_used)]

use instant::Instant;
use serde::Serialize;

use crate::live_device::{commit, connect, marked, Decision, LiveDevice, Stage};

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

    let attacks = vec![
        attack_double_spend(),
        attack_forged_sender_signature(),
        attack_replay(),
        attack_balance_underflow(),
        attack_forged_post_state(),
        attack_receiver_behind(),
    ];

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
// Attack 1: double spend — a second child of one tip (Tripwire)
// ---------------------------------------------------------------------------

fn attack_double_spend() -> AdversarialAttackResult {
    let (mut alice, mut bob) = funded_pair();
    // Two different steps proposed on the SAME tip: two children of one
    // parent, each fully signed.
    let first = alice.propose(&bob, marked(0x01)).expect("first step");
    let second = alice.propose(&bob, marked(0x02)).expect("second step");

    let outcome = (|| {
        if first.expected_tip != second.expected_tip || first.successor_tip == second.successor_tip
        {
            return Err("the two steps are not two children of one tip".into());
        }
        let verified = match bob.decide(&alice, &first) {
            Decision::Accepted(v) => v,
            other => return Err(format!("the honest first step was refused: {other}")),
        };
        commit(&mut alice, &mut bob, first, &verified).map_err(|e| e.to_string())?;
        match bob.decide(&alice, &second) {
            Decision::Accepted(_) => Err("the second child of a committed tip was ACCEPTED".into()),
            Decision::StaleTip => {
                Ok("second child refused: it does not extend the held tip".into())
            }
            other => Err(format!("refused for the wrong reason: {other}")),
        }
    })();
    result(
        "double_spend_second_child",
        "Two fully signed children of one tip: the first commits, the second is refused",
        "first committed, second refused as a stale tip",
        outcome,
    )
}

// ---------------------------------------------------------------------------
// Attack 2: a step signed by someone other than the pinned sender
// ---------------------------------------------------------------------------

fn attack_forged_sender_signature() -> AdversarialAttackResult {
    let (mut alice, bob) = funded_pair();
    let honest = alice.propose(&bob, marked(0x03)).expect("honest step");
    let mallory = LiveDevice::new("adversarial-mallory").expect("mallory");

    let outcome = (|| {
        match bob.decide(&alice, &honest) {
            Decision::Accepted(_) => {}
            other => return Err(format!("the honest step was refused: {other}")),
        }

        // A valid SPHINCS+ signature over the right commitment, by the wrong key.
        let mut wrong_signer = honest.clone();
        wrong_signer.sender_signature = mallory
            .keypair
            .sign(
                &dsm::core::bilateral_transaction_manager::bilateral_sign_message(
                    &honest.commitment_hash,
                ),
            )
            .map_err(|e| e.to_string())?;
        let decided = bob.decide(&alice, &wrong_signer);
        match decided.refusal_at(Stage::Prepare) {
            Some(e) if e.to_string().contains(NOT_SIGNED_BY_PINNED_AK) => {}
            _ => return Err(format!("a step signed by the wrong key: {decided}")),
        }

        // Bytes that are no signature at all, at the production size.
        let mut garbage = honest.clone();
        garbage.sender_signature = vec![0xDE; honest.sender_signature.len()];
        let decided = bob.decide(&alice, &garbage);
        match decided.refusal_at(Stage::Prepare) {
            Some(e) if e.to_string().contains(NOT_SIGNED_BY_PINNED_AK) => {}
            _ => return Err(format!("a garbage signature: {decided}")),
        }

        // A genuinely signed receipt under an EK the sender's chain never
        // certified: Mallory's AK certifies it.
        let foreign = honest
            .clone()
            .with_ek_certified_by(&mallory)
            .map_err(|e| e.to_string())?;
        let decided = bob.decide(&alice, &foreign);
        match decided.refusal_at(Stage::Confirm) {
            Some(e) if e.to_string().contains(EK_NOT_CHAINED) => {
                Ok("wrong-key, garbage and foreign-EK signatures refused".into())
            }
            _ => Err(format!("a receipt under a foreign EK: {decided}")),
        }
    })();
    result(
        "forged_sender_signature",
        "A step whose signature is not the pinned sender's, or whose receipt's EK the sender's chain never certified, is refused",
        "all three forgeries refused, each by the check it defeats",
        outcome,
    )
}

/// `decide_prepare`'s refusal of a proposal its sender's pinned AK did not
/// sign over the commitment.
const NOT_SIGNED_BY_PINNED_AK: &str = "is not signed over its commitment by the pinned AK";
/// `decide_confirm`'s refusal of a receipt whose EK its sender's chain did
/// not certify.
const EK_NOT_CHAINED: &str = "does NOT chain";
/// `decide_confirm`'s refusal of a receipt whose writes do not fold.
const WRITES_DO_NOT_FOLD: &str = "do not fold";

// ---------------------------------------------------------------------------
// Attack 3: replay of a committed step
// ---------------------------------------------------------------------------

fn attack_replay() -> AdversarialAttackResult {
    let (mut alice, mut bob) = funded_pair();
    let step = alice.propose(&bob, marked(0x04)).expect("step");
    let replayed = step.clone();

    let outcome = (|| {
        let verified = match bob.decide(&alice, &step) {
            Decision::Accepted(v) => v,
            other => return Err(format!("the step was refused the first time: {other}")),
        };
        commit(&mut alice, &mut bob, step, &verified).map_err(|e| e.to_string())?;
        match bob.decide(&alice, &replayed) {
            Decision::Accepted(_) => Err("the replayed step was ACCEPTED".into()),
            Decision::StaleTip => Ok("replay refused: it does not extend the held tip".into()),
            other => Err(format!("refused for the wrong reason: {other}")),
        }
    })();
    result(
        "step_replay",
        "A committed step presented again is refused",
        "first committed, replay refused as a stale tip",
        outcome,
    )
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

// ---------------------------------------------------------------------------
// Attack 5: a post-state root the path does not produce
// ---------------------------------------------------------------------------

fn attack_forged_post_state() -> AdversarialAttackResult {
    let (mut alice, bob) = funded_pair();
    let honest = alice.propose(&bob, marked(0x07)).expect("honest step");

    let outcome = (|| {
        match bob.decide(&alice, &honest) {
            Decision::Accepted(_) => {}
            other => return Err(format!("the honest step was refused: {other}")),
        }

        // The sender signs a receipt whose child root is not the one the
        // relationship path folds to: the signature holds, the state does not.
        let mut forged = honest.clone();
        forged.receipt.child_root[0] ^= 0x01;
        let forged = forged.resigned().map_err(|e| e.to_string())?;
        let decided = bob.decide(&alice, &forged);
        match decided.refusal_at(Stage::Confirm) {
            Some(e) if e.to_string().contains(WRITES_DO_NOT_FOLD) => {}
            _ => {
                return Err(format!(
                    "a signed receipt over a forged post-state root: {decided}"
                ))
            }
        }

        // The same with one sibling of the path changed: the writes no
        // longer fold to the pre-state root.
        let mut bent = honest.clone();
        let siblings = &mut bent.receipt.step_writes[0].path.siblings;
        if siblings.is_empty() {
            return Err("the relationship path carries no sibling to bend".into());
        }
        siblings[0] ^= 0x01;
        let bent = bent.resigned().map_err(|e| e.to_string())?;
        let decided = bob.decide(&alice, &bent);
        match decided.refusal_at(Stage::Confirm) {
            Some(e) if e.to_string().contains(WRITES_DO_NOT_FOLD) => {
                Ok(format!("forged post-state and bent path refused: {e}"))
            }
            _ => Err(format!(
                "a signed receipt over a bent relationship path: {decided}"
            )),
        }
    })();
    result(
        "forged_post_state",
        "Signed receipts whose roots the one relationship path does not produce are refused",
        "forged child root and bent path refused by the state rules",
        outcome,
    )
}

// ---------------------------------------------------------------------------
// Attack 6: a step on a tip the receiver does not hold
// ---------------------------------------------------------------------------

fn attack_receiver_behind() -> AdversarialAttackResult {
    let (mut alice, mut bob) = funded_pair();
    // The same device as Bob, restored from before the first step: it holds
    // the relationship's tip as it stood then.
    let mut restored = LiveDevice::new("adversarial-bob").expect("restored bob");
    connect(&mut restored, &mut alice).expect("restored contact");

    let outcome = (|| {
        let first = alice
            .propose(&bob, marked(0x08))
            .map_err(|e| e.to_string())?;
        let verified = match bob.decide(&alice, &first) {
            Decision::Accepted(v) => v,
            other => return Err(format!("the first step was refused: {other}")),
        };
        commit(&mut alice, &mut bob, first, &verified).map_err(|e| e.to_string())?;
        // A genuine, fully signed second step on the tip the first committed.
        let second = alice
            .propose(&bob, marked(0x09))
            .map_err(|e| e.to_string())?;
        match bob.decide(&alice, &second) {
            Decision::Accepted(_) => {}
            other => {
                return Err(format!(
                    "the second step was refused at its own tip: {other}"
                ))
            }
        }
        match restored.decide(&alice, &second) {
            Decision::Accepted(_) => {
                Err("a step on a tip the receiver does not hold was ACCEPTED".into())
            }
            Decision::StaleTip => {
                Ok("refused: it does not extend the tip the receiver holds".into())
            }
            other => Err(format!("refused for the wrong reason: {other}")),
        }
    })();
    result(
        "receiver_behind",
        "A genuine step on a tip the receiver does not hold is refused",
        "accepted at its own tip, refused by a receiver behind it",
        outcome,
    )
}
