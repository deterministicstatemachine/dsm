// SPDX-License-Identifier: MIT OR Apache-2.0

//! Adversarial bilateral attacks against the path production runs.
//!
//! Every attack is made on real device heads (`DeviceState::advance`) and
//! judged by Core's receipt verifier with a parent-consumption tracker, the
//! same objects a recipient holds. Each attack first shows the honest step it
//! perturbs is accepted, so a refusal is the verifier refusing the attack and
//! not refusing everything. An attack that is accepted is a hard failure.

// Validation harness: a device or receipt that cannot be built is a broken
// harness, and panicking says so.
#![allow(clippy::expect_used)]

use instant::Instant;
use serde::Serialize;

use dsm::merkle::sparse_merkle_tree::SmtInclusionProof;
use dsm::types::receipt_types::{ParentConsumptionTracker, StitchedReceiptV2};
use dsm::verification::receipt_verification::verify_stitched_receipt;

use crate::live_device::{connect, stitched_receipt, verification_context, LiveDevice};

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
        attack_forged_signature(),
        attack_replay(),
        attack_balance_underflow(),
        attack_forged_post_state(),
        attack_unexpected_parent_root(),
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

/// Alice, holding two faucet payouts of ERA, and Bob.
fn funded_pair() -> (LiveDevice, LiveDevice) {
    let mut alice = LiveDevice::new("adversarial-alice").expect("alice");
    alice.claim_faucet(1).expect("first claim");
    alice.claim_faucet(2).expect("second claim");
    let mut bob = LiveDevice::new("adversarial-bob").expect("bob");
    connect(&mut alice, &mut bob).expect("the two are contacts");
    (alice, bob)
}

/// Alice's transfer of `amount` to Bob from her current head, and the
/// receipt of it both have signed.
fn signed_step(alice: &LiveDevice, bob: &LiveDevice, amount: u64, nonce: u8) -> StitchedReceiptV2 {
    let op = alice.transfer(bob, amount, &[nonce; 8]).expect("transfer");
    let outcome = alice.send(bob, &op).expect("sender advance");
    stitched_receipt(alice, bob, &outcome).expect("receipt")
}

/// The verifier's judgement: `Ok(())` accepted, `Err(reason)` refused.
fn judge(
    alice: &LiveDevice,
    bob: &LiveDevice,
    receipt: &StitchedReceiptV2,
    tracker: &mut ParentConsumptionTracker,
) -> Result<(), String> {
    let ctx = verification_context(alice, bob, alice.head.root());
    match verify_stitched_receipt(receipt, &ctx, tracker) {
        Ok(acceptance) if acceptance.valid => Ok(()),
        Ok(acceptance) => Err(acceptance.reason.unwrap_or_default()),
        Err(e) => Err(format!("error: {e}")),
    }
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
// Attack 1: double spend — a second child of one parent (Tripwire)
// ---------------------------------------------------------------------------

fn attack_double_spend() -> AdversarialAttackResult {
    let (alice, bob) = funded_pair();
    // Two different transfers built from the SAME head: two children of one
    // parent tip, each fully signed.
    let first = signed_step(&alice, &bob, 150, 0x01);
    let second = signed_step(&alice, &bob, 120, 0x02);
    let mut tracker = ParentConsumptionTracker::new();

    let outcome = (|| {
        if first.parent_tip != second.parent_tip || first.child_tip == second.child_tip {
            return Err("the two spends are not two children of one parent".into());
        }
        judge(&alice, &bob, &first, &mut tracker)
            .map_err(|r| format!("the honest first spend was refused: {r}"))?;
        match judge(&alice, &bob, &second, &mut tracker) {
            Ok(()) => Err("the second child of a consumed parent was ACCEPTED".into()),
            Err(r) if r.contains("Parent uniqueness") => Ok(format!("second child refused: {r}")),
            Err(r) => Err(format!("refused for the wrong reason: {r}")),
        }
    })();
    result(
        "double_spend_second_child",
        "Two fully signed children of one parent tip: the first is accepted, the second refused",
        "first accepted, second refused for parent uniqueness",
        outcome,
    )
}

// ---------------------------------------------------------------------------
// Attack 2: a countersignature by someone other than the counterparty
// ---------------------------------------------------------------------------

fn attack_forged_signature() -> AdversarialAttackResult {
    let (alice, bob) = funded_pair();
    let honest = signed_step(&alice, &bob, 50, 0x03);
    let mallory = LiveDevice::new("adversarial-mallory").expect("mallory");

    let outcome = (|| {
        judge(&alice, &bob, &honest, &mut ParentConsumptionTracker::new())
            .map_err(|r| format!("the honest receipt was refused: {r}"))?;

        // A valid SPHINCS+ signature over the right commitment, by the wrong key.
        let mut wrong_signer = honest.clone();
        wrong_signer.sig_b.clear();
        let commitment = wrong_signer
            .compute_commitment()
            .map_err(|e| format!("commitment: {e}"))?;
        wrong_signer.add_sig_b(
            mallory
                .keypair
                .sign(&commitment)
                .map_err(|e| e.to_string())?,
        );
        if judge(
            &alice,
            &bob,
            &wrong_signer,
            &mut ParentConsumptionTracker::new(),
        )
        .is_ok()
        {
            return Err("a countersignature by the wrong key was ACCEPTED".into());
        }

        // Bytes that are no signature at all, at the production size.
        let mut garbage = honest.clone();
        garbage.sig_b = vec![0xDE; honest.sig_b.len()];
        if judge(&alice, &bob, &garbage, &mut ParentConsumptionTracker::new()).is_ok() {
            return Err("a garbage countersignature was ACCEPTED".into());
        }
        Ok("wrong-key and garbage countersignatures refused".into())
    })();
    result(
        "forged_countersignature",
        "A receipt countersigned by a key that is not the counterparty's is refused",
        "both forgeries refused",
        outcome,
    )
}

// ---------------------------------------------------------------------------
// Attack 3: replay of an accepted receipt
// ---------------------------------------------------------------------------

fn attack_replay() -> AdversarialAttackResult {
    let (alice, bob) = funded_pair();
    let receipt = signed_step(&alice, &bob, 40, 0x04);
    let mut tracker = ParentConsumptionTracker::new();

    let outcome = (|| {
        judge(&alice, &bob, &receipt, &mut tracker)
            .map_err(|r| format!("the receipt was refused the first time: {r}"))?;
        match judge(&alice, &bob, &receipt, &mut tracker) {
            Ok(()) => Err("the replayed receipt was ACCEPTED".into()),
            Err(r) if r.contains("Parent uniqueness") => Ok(format!("replay refused: {r}")),
            Err(r) => Err(format!("refused for the wrong reason: {r}")),
        }
    })();
    result(
        "receipt_replay",
        "An accepted receipt presented again is refused",
        "first accepted, replay refused",
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
    let (alice, bob) = funded_pair();
    let honest = signed_step(&alice, &bob, 30, 0x07);

    let outcome = (|| {
        judge(&alice, &bob, &honest, &mut ParentConsumptionTracker::new())
            .map_err(|r| format!("the honest receipt was refused: {r}"))?;

        // Both parties re-sign a receipt whose child root is not the one the
        // relationship path folds to: the signatures hold, the state does not.
        let mut forged = honest.clone();
        forged.child_root[0] ^= 0x01;
        forged.sig_a.clear();
        forged.sig_b.clear();
        let commitment = forged.compute_commitment().map_err(|e| e.to_string())?;
        forged.add_sig_a(alice.keypair.sign(&commitment).map_err(|e| e.to_string())?);
        forged.add_sig_b(bob.keypair.sign(&commitment).map_err(|e| e.to_string())?);
        if judge(&alice, &bob, &forged, &mut ParentConsumptionTracker::new()).is_ok() {
            return Err("a signed receipt over a forged post-state root was ACCEPTED".into());
        }

        // The same with one sibling of the path changed: the path no longer
        // authenticates the parent tip under the pre-state root.
        let mut bent = honest.clone();
        let mut path = SmtInclusionProof::from_bytes(&bent.rel_proof_parent)
            .ok_or("the receipt's path does not decode")?;
        path.siblings[0][0] ^= 0x01;
        bent.rel_proof_parent = path.to_bytes();
        bent.sig_a.clear();
        bent.sig_b.clear();
        let commitment = bent.compute_commitment().map_err(|e| e.to_string())?;
        bent.add_sig_a(alice.keypair.sign(&commitment).map_err(|e| e.to_string())?);
        bent.add_sig_b(bob.keypair.sign(&commitment).map_err(|e| e.to_string())?);
        match judge(&alice, &bob, &bent, &mut ParentConsumptionTracker::new()) {
            Ok(()) => Err("a signed receipt over a bent relationship path was ACCEPTED".into()),
            Err(r) => Ok(format!("forged post-state and bent path refused: {r}")),
        }
    })();
    result(
        "forged_post_state",
        "Signed receipts whose roots the one relationship path does not produce are refused",
        "forged child root and bent path refused",
        outcome,
    )
}

// ---------------------------------------------------------------------------
// Attack 6: a step presented against a root the verifier does not expect
// ---------------------------------------------------------------------------

fn attack_unexpected_parent_root() -> AdversarialAttackResult {
    let (mut alice, bob) = funded_pair();
    let root_before = alice.head.root();
    let op = alice.transfer(&bob, 20, &[0x08; 8]).expect("transfer");
    let first = alice.send(&bob, &op).expect("first advance");
    alice.install(first);
    // A genuine, fully signed second step, presented to a verifier that still
    // expects the chain to stand where it stood before the first.
    let second = signed_step(&alice, &bob, 10, 0x09);

    let outcome = (|| {
        judge(&alice, &bob, &second, &mut ParentConsumptionTracker::new())
            .map_err(|r| format!("the second step was refused at its own root: {r}"))?;
        let stale = verification_context(&alice, &bob, root_before);
        match verify_stitched_receipt(&second, &stale, &mut ParentConsumptionTracker::new()) {
            Ok(a) if a.valid => Err("a step over an unexpected parent root was ACCEPTED".into()),
            Ok(a) => {
                let reason = a.reason.unwrap_or_default();
                if reason.contains("is not the root this verifier expects") {
                    Ok(format!("refused: {reason}"))
                } else {
                    Err(format!("refused for the wrong reason: {reason}"))
                }
            }
            Err(e) => Err(format!("the verifier errored: {e}")),
        }
    })();
    result(
        "unexpected_parent_root",
        "A genuine step over a parent root the verifier does not expect is refused",
        "accepted at its own root, refused at the stale one",
        outcome,
    )
}
