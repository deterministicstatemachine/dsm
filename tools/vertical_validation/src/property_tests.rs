// SPDX-License-Identifier: MIT OR Apache-2.0

//! Property-based tests over the path production runs.
//!
//! Every property drives real device heads (`DeviceState::advance`) with
//! seeded random transfers and checks an invariant against a value the
//! harness derives independently: the tip the parent path must carry, the
//! transition entropy by its formula, the sum of two balances, the verifier's
//! verdict on a second child. TLA+ proves the bounded abstract invariants;
//! this harness checks the concrete transition keeps them.

// Validation harness: panicking on crypto setup failures is correct behavior.
#![allow(clippy::expect_used)]

use instant::Instant;
use rand::Rng;
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use serde::Serialize;

use dsm::common::domain_tags::{TAG_DSM_GENESIS_ENTROPY, TAG_DSM_STATE_ENTROPY};
use dsm::crypto::blake3::dsm_domain_hasher;
use dsm::crypto::sphincs::{sphincs_sign, sphincs_verify};
use dsm::types::receipt_types::ParentConsumptionTracker;
use dsm::verification::receipt_verification::verify_stitched_receipt;

use crate::live_device::{connect, stitched_receipt, verification_context, LiveDevice};

// ---------------------------------------------------------------------------
// Result types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub struct PropertyTestResult {
    pub property_name: String,
    pub iterations: u64,
    pub passed: bool,
    pub failures: Vec<String>,
    pub duration_ms: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct PropertyTestSuiteResult {
    pub results: Vec<PropertyTestResult>,
    pub all_passed: bool,
    pub seed: u64,
    pub duration_ms: f64,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Alice with `claims` faucet payouts of ERA, and Bob with none.
fn funded_pair(claims: u64) -> (LiveDevice, LiveDevice) {
    let mut alice = LiveDevice::new("property-alice").expect("alice");
    for generation in 1..=claims {
        alice.claim_faucet(generation).expect("faucet claim");
    }
    let mut bob = LiveDevice::new("property-bob").expect("bob");
    connect(&mut alice, &mut bob).expect("the two are contacts");
    (alice, bob)
}

fn random_nonce(rng: &mut ChaCha20Rng) -> Vec<u8> {
    (0..8).map(|_| rng.random()).collect()
}

fn finish(
    name: &str,
    iterations: u64,
    failures: Vec<String>,
    start: Instant,
) -> PropertyTestResult {
    PropertyTestResult {
        property_name: name.into(),
        iterations,
        passed: failures.is_empty(),
        failures,
        duration_ms: start.elapsed().as_secs_f64() * 1000.0,
    }
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

pub fn collect_property_test_results(seed: u64, iterations: u64) -> PropertyTestSuiteResult {
    eprintln!("\n=== PROPERTY-BASED TESTS ===\n");
    let suite_start = Instant::now();

    // SPHINCS+ signing dominates; the signing-heavy properties are capped.
    let signed_iters = iterations.min(25);
    let advance_iters = iterations.min(100);

    type Property = fn(u64, u64) -> PropertyTestResult;
    let properties: [(&str, u64, Property); 6] = [
        (
            "relationship_chain_continuity",
            signed_iters,
            relationship_chain_continuity,
        ),
        (
            "transition_entropy_formula",
            signed_iters,
            transition_entropy_formula,
        ),
        (
            "two_device_conservation",
            signed_iters,
            two_device_conservation,
        ),
        ("overspend_refused", advance_iters, overspend_refused),
        ("fork_exclusion", signed_iters, fork_exclusion),
        ("signature_binding", iterations.min(20), signature_binding),
    ];

    let mut results = Vec::new();
    for (idx, (name, iters, property)) in properties.iter().enumerate() {
        eprintln!(
            "  [{}/{}] {name} ({iters} iters)...",
            idx + 1,
            properties.len()
        );
        let r = property(*iters, seed);
        let icon = if r.passed { "\u{2705}" } else { "\u{274c}" };
        eprintln!(
            "  {icon} {name} \u{2014} {} failures in {} iterations ({:.1}ms)",
            r.failures.len(),
            r.iterations,
            r.duration_ms
        );
        results.push(r);
    }

    let all_passed = results.iter().all(|r| r.passed);
    eprintln!();

    PropertyTestSuiteResult {
        results,
        all_passed,
        seed,
        duration_ms: suite_start.elapsed().as_secs_f64() * 1000.0,
    }
}

// ---------------------------------------------------------------------------
// Property 1: each step's parent path carries the tip before it
// ---------------------------------------------------------------------------

fn relationship_chain_continuity(iterations: u64, seed: u64) -> PropertyTestResult {
    let start = Instant::now();
    let mut failures = Vec::new();
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let (mut alice, bob) = funded_pair(1);
    let rel_key = alice.rel_key(&bob);

    for i in 0..iterations {
        let tip_before = alice.tip_with(&bob).expect("established");
        let root_before = alice.head.root();
        let op = alice
            .transfer(&bob, 1, &random_nonce(&mut rng))
            .expect("transfer");
        match alice.send(&bob, &op) {
            Ok(outcome) => {
                if outcome.smt_proofs.parent_proof.value != Some(tip_before) {
                    failures.push(format!(
                        "iter {i}: the parent path does not carry the tip before the step"
                    ));
                }
                if outcome.parent_r_a != root_before {
                    failures.push(format!(
                        "iter {i}: the step does not start from the head's root"
                    ));
                }
                if outcome.new_device_state.chain_tip(&rel_key)
                    != outcome.smt_proofs.child_proof.value
                {
                    failures.push(format!(
                        "iter {i}: the child path does not carry the new tip"
                    ));
                }
                if outcome.smt_proofs.child_proof.value == Some(tip_before) {
                    failures.push(format!("iter {i}: the tip did not move"));
                }
                alice.install(outcome);
            }
            Err(e) => failures.push(format!("iter {i}: advance refused: {e}")),
        }
    }
    finish("relationship_chain_continuity", iterations, failures, start)
}

// ---------------------------------------------------------------------------
// Property 2: the transition entropy is e_{n+1} = H(e_n ‖ op ‖ h_n)
// ---------------------------------------------------------------------------

fn transition_entropy_formula(iterations: u64, seed: u64) -> PropertyTestResult {
    let start = Instant::now();
    let mut failures = Vec::new();
    let mut rng = ChaCha20Rng::seed_from_u64(seed ^ 0x454e_5452);
    let (mut alice, bob) = funded_pair(1);
    let rel_key = alice.rel_key(&bob);

    for i in 0..iterations {
        // e_n and h_n as the spec defines them: the tip's entropy and the tip,
        // or, before the relationship's first step, H(genesis-entropy; root)
        // and the root.
        let (prior_entropy, prior_hash) = match (
            alice.head.tip_entropy(&rel_key),
            alice.head.chain_tip(&rel_key),
        ) {
            (Some(entropy), Some(tip)) => (entropy.to_vec(), tip),
            _ => {
                let root = alice.head.root();
                let mut h = dsm_domain_hasher(TAG_DSM_GENESIS_ENTROPY);
                h.update(&root);
                (h.finalize().as_bytes().to_vec(), root)
            }
        };
        let op = alice
            .transfer(&bob, 1, &random_nonce(&mut rng))
            .expect("transfer");
        let mut h = dsm_domain_hasher(TAG_DSM_STATE_ENTROPY);
        h.update(&prior_entropy);
        h.update(&op.to_bytes());
        h.update(&prior_hash);
        let expected = *h.finalize().as_bytes();

        match alice.send(&bob, &op) {
            Ok(outcome) => {
                if outcome.transition_entropy() != expected {
                    failures.push(format!(
                        "iter {i}: transition entropy differs from its formula"
                    ));
                }
                alice.install(outcome);
            }
            Err(e) => failures.push(format!("iter {i}: advance refused: {e}")),
        }
    }
    finish("transition_entropy_formula", iterations, failures, start)
}

// ---------------------------------------------------------------------------
// Property 3: a transfer moves value between two heads and creates none
// ---------------------------------------------------------------------------

fn two_device_conservation(iterations: u64, seed: u64) -> PropertyTestResult {
    let start = Instant::now();
    let mut failures = Vec::new();
    let mut rng = ChaCha20Rng::seed_from_u64(seed ^ 0x544f_4b45_4e);
    let (mut alice, mut bob) = funded_pair(3);
    bob.claim_faucet(1).expect("bob's claim");
    let total = alice.era_balance() + bob.era_balance();

    for i in 0..iterations {
        // Either direction, any amount the sender holds.
        let alice_sends = rng.random_bool(0.5);
        let (sender, receiver) = if alice_sends {
            (&mut alice, &mut bob)
        } else {
            (&mut bob, &mut alice)
        };
        let held = sender.era_balance();
        if held == 0 {
            continue;
        }
        let amount = rng.random_range(1..=held.min(250));
        let (sender_before, receiver_before) = (sender.era_balance(), receiver.era_balance());
        let op = sender
            .transfer(receiver, amount, &random_nonce(&mut rng))
            .expect("transfer");
        match (sender.send(receiver, &op), receiver.receive(sender, &op)) {
            (Ok(debit), Ok(credit)) => {
                sender.install(debit);
                receiver.install(credit);
                if sender.era_balance() != sender_before - amount {
                    failures.push(format!(
                        "iter {i}: the sender was not debited exactly {amount}"
                    ));
                }
                if receiver.era_balance() != receiver_before + amount {
                    failures.push(format!(
                        "iter {i}: the receiver was not credited exactly {amount}"
                    ));
                }
            }
            (Err(e), _) | (_, Err(e)) => failures.push(format!("iter {i}: advance refused: {e}")),
        }
        if alice.era_balance() + bob.era_balance() != total {
            failures.push(format!(
                "iter {i}: conservation violated: {} + {} != {total}",
                alice.era_balance(),
                bob.era_balance()
            ));
        }
    }
    finish("two_device_conservation", iterations, failures, start)
}

// ---------------------------------------------------------------------------
// Property 4: a debit above the balance is refused and changes nothing
// ---------------------------------------------------------------------------

fn overspend_refused(iterations: u64, seed: u64) -> PropertyTestResult {
    let start = Instant::now();
    let mut failures = Vec::new();
    let mut rng = ChaCha20Rng::seed_from_u64(seed ^ 0x4f56_4552);
    let (alice, bob) = funded_pair(2);
    let held = alice.era_balance();
    let root = alice.head.root();

    for i in 0..iterations {
        let amount = held + rng.random_range(1..=1_000);
        let op = alice
            .transfer(&bob, amount, &random_nonce(&mut rng))
            .expect("transfer");
        if alice.send(&bob, &op).is_ok() {
            failures.push(format!(
                "iter {i}: a debit of {amount} over {held} was accepted"
            ));
        }
        if alice.head.root() != root || alice.era_balance() != held {
            failures.push(format!(
                "iter {i}: the head changed after a refused overspend"
            ));
        }
    }
    finish("overspend_refused", iterations, failures, start)
}

// ---------------------------------------------------------------------------
// Property 5: of two children of one parent, the verifier accepts one
// ---------------------------------------------------------------------------

fn fork_exclusion(iterations: u64, seed: u64) -> PropertyTestResult {
    let start = Instant::now();
    let mut failures = Vec::new();
    let mut rng = ChaCha20Rng::seed_from_u64(seed ^ 0x464f_524b);
    let (mut alice, bob) = funded_pair(1);
    let mut tracker = ParentConsumptionTracker::new();

    for i in 0..iterations {
        let op_a = alice
            .transfer(&bob, 1, &random_nonce(&mut rng))
            .expect("transfer a");
        let op_b = alice
            .transfer(&bob, 2, &random_nonce(&mut rng))
            .expect("transfer b");
        let (Ok(child_a), Ok(child_b)) = (alice.send(&bob, &op_a), alice.send(&bob, &op_b)) else {
            failures.push(format!("iter {i}: advance refused"));
            continue;
        };
        let receipt_a = stitched_receipt(&alice, &bob, &child_a).expect("receipt a");
        let receipt_b = stitched_receipt(&alice, &bob, &child_b).expect("receipt b");
        if receipt_a.child_tip == receipt_b.child_tip {
            failures.push(format!(
                "iter {i}: two different operations produced one child tip"
            ));
        }
        let ctx = verification_context(&alice, &bob, alice.head.root());
        match verify_stitched_receipt(&receipt_a, &ctx, &mut tracker) {
            Ok(a) if a.valid => {}
            Ok(a) => failures.push(format!(
                "iter {i}: the first child was refused: {}",
                a.reason.unwrap_or_default()
            )),
            Err(e) => failures.push(format!("iter {i}: verifier error: {e}")),
        }
        match verify_stitched_receipt(&receipt_b, &ctx, &mut tracker) {
            Ok(a) if a.valid => failures.push(format!(
                "iter {i}: FORK ACCEPTED: a second child of one parent"
            )),
            Ok(_) => {}
            Err(e) => failures.push(format!("iter {i}: verifier error: {e}")),
        }
        alice.install(child_a);
    }
    finish("fork_exclusion", iterations, failures, start)
}

// ---------------------------------------------------------------------------
// Property 6: an operation's signature binds every field it covers
// ---------------------------------------------------------------------------

fn signature_binding(iterations: u64, seed: u64) -> PropertyTestResult {
    let start = Instant::now();
    let mut failures = Vec::new();
    let mut rng = ChaCha20Rng::seed_from_u64(seed ^ 0x5349_47);
    let (alice, bob) = funded_pair(1);
    let pk = alice.keypair.public_key.clone();

    for i in 0..iterations {
        let amount = rng.random_range(1..=100);
        let op = alice
            .transfer(&bob, amount, &random_nonce(&mut rng))
            .expect("transfer");
        let signature = op
            .get_signature()
            .expect("a signed transfer carries its signature");

        match sphincs_verify(&pk, &op.signing_bytes(), &signature) {
            Ok(true) => {}
            other => {
                failures.push(format!(
                    "iter {i}: the honest signature did not verify: {other:?}"
                ));
                continue;
            }
        }

        // The same signature over a transfer of a different amount.
        let altered = alice
            .transfer(&bob, amount + 1, &random_nonce(&mut rng))
            .expect("altered transfer")
            .with_signature(signature.clone());
        if matches!(
            sphincs_verify(&pk, &altered.signing_bytes(), &signature),
            Ok(true)
        ) {
            failures.push(format!(
                "iter {i}: a signature verified over a different transfer"
            ));
        }

        let mut tampered = signature.clone();
        tampered[0] ^= 0xFF;
        if matches!(
            sphincs_verify(&pk, &op.signing_bytes(), &tampered),
            Ok(true)
        ) {
            failures.push(format!("iter {i}: a tampered signature verified"));
        }

        let foreign = sphincs_sign(&bob.keypair.secret_key, &op.signing_bytes()).expect("sign");
        if matches!(sphincs_verify(&pk, &op.signing_bytes(), &foreign), Ok(true)) {
            failures.push(format!(
                "iter {i}: another device's signature verified under this key"
            ));
        }
    }
    finish("signature_binding", iterations, failures, start)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_transfer_verifies_under_its_signer_over_its_signing_bytes() {
        let (alice, bob) = funded_pair(1);
        let op = alice.transfer(&bob, 7, &[1; 8]).expect("transfer");
        let sig = op.get_signature().expect("signature");
        assert!(
            sphincs_verify(&alice.keypair.public_key, &op.signing_bytes(), &sig).expect("verify")
        );
    }
}
