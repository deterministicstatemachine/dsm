// SPDX-License-Identifier: MIT OR Apache-2.0

//! Deterministic implementation traces for direct Rust validation.
//!
//! Unlike TLC model checking, these traces execute the real DSM transition code
//! end-to-end with fixed scenarios and exact expectations.

#![allow(clippy::expect_used)]

use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;

use instant::Instant;
use serde::Serialize;

use dsm::core::bilateral_transaction_manager::compute_smt_key;
use dsm::core::bilateral_transaction_manager::BilateralTransactionManager;
use dsm::core::contact_manager::DsmContactManager;
use dsm::core::token::token_state_manager::era_policy_commit;
use dsm::crypto::blake3::domain_hash_bytes;
use dsm::crypto::kyber::generate_kyber_keypair_from_entropy;
use dsm::crypto::signatures::SignatureKeyPair;
use dsm::crypto::sphincs::{generate_keypair_from_seed, SphincsVariant};
use dsm::economic::native_reserve::ERA_FAUCET_PAYOUT;
use dsm::emissions::{
    select_winner_for_event, verify_emission, EmissionReceipt, EmissionSchedule,
    JoinActivationProof, SourceDlvState,
};
use dsm::merkle::sparse_merkle_tree::SmtInclusionProof;
use dsm::types::contact_types::DsmVerifiedContact;
use dsm::types::device_state::{BalanceDelta, BalanceDirection, DeviceState};
use dsm::types::operations::{Operation, TransactionMode};
use dsm::types::receipt_types::{
    ParentConsumptionTracker, ReceiptVerificationContext, StitchedReceiptV2,
};
use dsm::types::token_types::Balance;
use dsm::vault::{DLVManager, FulfillmentMechanism, VaultState};
use dsm::verification::receipt_verification::verify_stitched_receipt;

use crate::live_device::{
    connect, faucet_claim, stitched_receipt, verification_context, LiveDevice,
};

const TRACE_VARIANT: SphincsVariant = SphincsVariant::SPX256f;
type TraceFn = fn(&[u8; 32], &[u8], &[u8]) -> ImplementationTraceResult;

#[derive(Debug, Clone, Serialize)]
pub struct ImplementationTraceResult {
    pub trace_name: String,
    pub steps: u64,
    pub passed: bool,
    pub failures: Vec<String>,
    pub duration_ms: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ImplementationTraceSuiteResult {
    pub results: Vec<ImplementationTraceResult>,
    pub all_passed: bool,
    pub duration_ms: f64,
}

pub fn collect_implementation_trace_results() -> ImplementationTraceSuiteResult {
    collect_named_implementation_trace_results(&[])
}

pub fn collect_named_implementation_trace_results(
    trace_names: &[&str],
) -> ImplementationTraceSuiteResult {
    eprintln!("\n=== IMPLEMENTATION TRACE REPLAY ===\n");
    let suite_start = Instant::now();
    let seed_bytes = [0x11; 32];

    eprintln!("  Generating SPHINCS+ keypair ({TRACE_VARIANT:?})...");
    let kp = generate_keypair_from_seed(TRACE_VARIANT, &seed_bytes).expect("SPHINCS+ keygen");
    let pk = kp.public_key.clone();
    let sk = kp.secret_key.clone();

    let trace_catalog = implementation_trace_catalog();
    let selected_traces: Vec<(&str, TraceFn)> = if trace_names.is_empty() {
        trace_catalog.to_vec()
    } else {
        trace_names
            .iter()
            .map(|name| {
                trace_catalog
                    .iter()
                    .copied()
                    .find(|(trace_name, _)| trace_name == name)
                    .unwrap_or((name, trace_unknown_binding))
            })
            .collect()
    };

    let mut results = Vec::with_capacity(selected_traces.len());
    for (idx, (_, trace_fn)) in selected_traces.iter().enumerate() {
        let result = trace_fn(&seed_bytes, &pk, &sk);
        let icon = if result.passed { "PASS" } else { "FAIL" };
        eprintln!(
            "  [{}/{}] {} -> {} ({:.1}ms)",
            idx + 1,
            selected_traces.len(),
            result.trace_name,
            icon,
            result.duration_ms
        );
        results.push(result);
    }

    let all_passed = results.iter().all(|r| r.passed);
    let duration_ms = suite_start.elapsed().as_secs_f64() * 1000.0;

    ImplementationTraceSuiteResult {
        results,
        all_passed,
        duration_ms,
    }
}

fn implementation_trace_catalog() -> [(&'static str, TraceFn); 16] {
    [
        (
            "state_machine_transfer_chain",
            trace_state_machine_transfer_chain,
        ),
        (
            "state_machine_signature_rejection",
            trace_state_machine_signature_rejection,
        ),
        (
            "state_machine_fork_divergence",
            trace_state_machine_fork_divergence,
        ),
        (
            "bilateral_precommit_tripwire",
            trace_bilateral_precommit_tripwire,
        ),
        (
            "bilateral_precomputed_finalize_hash",
            trace_bilateral_precomputed_finalize_hash,
        ),
        (
            "tripwire_parent_consumption",
            trace_tripwire_parent_consumption,
        ),
        ("receipt_verifier_tripwire", trace_receipt_verifier_tripwire),
        (
            "tripwire_first_contact_binding",
            trace_tripwire_first_contact_binding,
        ),
        ("djte_emission_happy_path", trace_djte_emission_happy_path),
        (
            "djte_repeated_emission_alignment",
            trace_djte_repeated_emission_alignment,
        ),
        (
            "djte_supply_underflow_rejection",
            trace_djte_supply_underflow_rejection,
        ),
        (
            "dlv_manager_inventory_consistency",
            trace_dlv_manager_inventory_consistency,
        ),
        (
            "token_manager_balance_replay",
            trace_token_manager_balance_replay,
        ),
        (
            "token_manager_overspend_rejection",
            trace_token_manager_overspend_rejection,
        ),
        // --- Offline Finality (Paper Theorems 4.1, 4.2) ---
        (
            "bilateral_full_offline_finality",
            trace_bilateral_full_offline_finality,
        ),
        // --- Non-Interference (Paper Lemma 3.1, Theorem 3.1) ---
        (
            "bilateral_pair_non_interference",
            trace_bilateral_pair_non_interference,
        ),
    ]
}

fn trace_unknown_binding(
    _seed_bytes: &[u8; 32],
    _pk: &[u8],
    _sk: &[u8],
) -> ImplementationTraceResult {
    ImplementationTraceResult {
        trace_name: "unknown_implementation_trace_binding".into(),
        steps: 0,
        passed: false,
        failures: vec!["TLA integration requested an unknown implementation trace".into()],
        duration_ms: 0.0,
    }
}

/// Alice holding one faucet payout of ERA, and Bob, for the trace `label`.
fn trace_pair(label: &str) -> (LiveDevice, LiveDevice) {
    let mut alice = LiveDevice::new(&format!("trace-{label}-alice")).expect("alice");
    alice.claim_faucet(1).expect("faucet claim");
    let mut bob = LiveDevice::new(&format!("trace-{label}-bob")).expect("bob");
    connect(&mut alice, &mut bob).expect("the two are contacts");
    (alice, bob)
}

fn trace_state_machine_transfer_chain(
    _seed_bytes: &[u8; 32],
    _pk: &[u8],
    _sk: &[u8],
) -> ImplementationTraceResult {
    let start = Instant::now();
    let mut failures = Vec::new();
    let (mut alice, bob) = trace_pair("chain");
    let rel_key = alice.rel_key(&bob);

    let amounts = [1u64, 2, 3, 4];
    for (idx, amount) in amounts.iter().enumerate() {
        let tip_before = alice.tip_with(&bob).expect("established");
        let root_before = alice.head.root();
        let balance_before = alice.era_balance();
        let op = match alice.transfer(&bob, *amount, &[(idx as u8) + 1; 8]) {
            Ok(op) => op,
            Err(e) => {
                failures.push(format!("step {idx}: signing failed: {e}"));
                continue;
            }
        };
        match alice.send(&bob, &op) {
            Ok(outcome) => {
                if outcome.parent_r_a != root_before {
                    failures.push(format!(
                        "step {idx}: the step does not start from the head's root"
                    ));
                }
                if outcome.smt_proofs.parent_proof.value != Some(tip_before) {
                    failures.push(format!(
                        "step {idx}: the parent path does not carry the tip before it"
                    ));
                }
                if outcome.new_device_state.chain_tip(&rel_key) == Some(tip_before) {
                    failures.push(format!("step {idx}: the relationship tip did not advance"));
                }
                alice.install(outcome);
                if alice.era_balance() != balance_before - amount {
                    failures.push(format!("step {idx}: the debit is not exactly {amount}"));
                }
            }
            Err(e) => failures.push(format!("step {idx}: advance refused: {e}")),
        }
    }

    if alice.era_balance() != ERA_FAUCET_PAYOUT - amounts.iter().sum::<u64>() {
        failures.push("the chain did not end at the expected balance".into());
    }

    ImplementationTraceResult {
        trace_name: "state_machine_transfer_chain".into(),
        steps: amounts.len() as u64,
        passed: failures.is_empty(),
        failures,
        duration_ms: start.elapsed().as_secs_f64() * 1000.0,
    }
}

/// The recipient's side of a transfer, as production runs it: bind the
/// operation to the sender's key (`Operation::decode_and_bind_signed`), and
/// only then advance on the bound operation.
fn recipient_applies(
    recipient: &LiveDevice,
    sender: &LiveDevice,
    canonical: &[u8],
    signature: &[u8],
) -> Result<dsm::types::device_state::AdvanceOutcome, String> {
    let bound = Operation::decode_and_bind_signed(canonical, signature, &sender.keypair.public_key)
        .map_err(|e| e.to_string())?;
    recipient.receive(sender, &bound).map_err(|e| e.to_string())
}

fn trace_state_machine_signature_rejection(
    _seed_bytes: &[u8; 32],
    _pk: &[u8],
    _sk: &[u8],
) -> ImplementationTraceResult {
    let start = Instant::now();
    let mut failures = Vec::new();
    let (alice, bob) = trace_pair("signature");

    let op = alice.transfer(&bob, 10, &[9; 8]).expect("transfer");
    let canonical = op.signing_bytes();
    let signature = op
        .get_signature()
        .expect("a signed transfer carries its signature");
    let bob_root = bob.head.root();

    match recipient_applies(&bob, &alice, &canonical, &signature) {
        Ok(outcome) => {
            if outcome
                .new_device_state
                .balance(&dsm::core::token::token_state_manager::era_policy_commit())
                != 10
            {
                failures.push("the honest transfer did not credit exactly its amount".into());
            }
        }
        Err(e) => failures.push(format!("the honest transfer was refused: {e}")),
    }

    let mut tampered = signature.clone();
    tampered[0] ^= 0xFF;
    if recipient_applies(&bob, &alice, &canonical, &tampered).is_ok() {
        failures.push("a tampered signature was applied".into());
    }
    let foreign = bob.keypair.sign(&canonical).expect("sign");
    if recipient_applies(&bob, &alice, &canonical, &foreign).is_ok() {
        failures.push("another device's signature was applied as the sender's".into());
    }
    let altered = alice
        .transfer(&bob, 11, &[9; 8])
        .expect("transfer")
        .signing_bytes();
    if recipient_applies(&bob, &alice, &altered, &signature).is_ok() {
        failures.push("the honest signature was applied to a different transfer".into());
    }
    if bob.head.root() != bob_root {
        failures.push("the recipient's head moved".into());
    }

    ImplementationTraceResult {
        trace_name: "state_machine_signature_rejection".into(),
        steps: 4,
        passed: failures.is_empty(),
        failures,
        duration_ms: start.elapsed().as_secs_f64() * 1000.0,
    }
}

fn trace_state_machine_fork_divergence(
    _seed_bytes: &[u8; 32],
    _pk: &[u8],
    _sk: &[u8],
) -> ImplementationTraceResult {
    let start = Instant::now();
    let mut failures = Vec::new();
    let (alice, bob) = trace_pair("fork");
    let parent_tip = alice.tip_with(&bob).expect("established");

    let op_a = alice.transfer(&bob, 1, &[1; 8]).expect("transfer a");
    let op_b = alice.transfer(&bob, 2, &[2; 8]).expect("transfer b");
    match (alice.send(&bob, &op_a), alice.send(&bob, &op_b)) {
        (Ok(child_a), Ok(child_b)) => {
            if child_a.smt_proofs.parent_proof.value != Some(parent_tip)
                || child_b.smt_proofs.parent_proof.value != Some(parent_tip)
            {
                failures.push("the fork children do not share the parent tip".into());
            }
            if child_a.smt_proofs.child_proof.value == child_b.smt_proofs.child_proof.value {
                failures.push("different operations produced the same child tip".into());
            }
            let receipt_a = stitched_receipt(&alice, &bob, &child_a).expect("receipt a");
            let receipt_b = stitched_receipt(&alice, &bob, &child_b).expect("receipt b");
            let ctx = verification_context(&alice, &bob, alice.head.root());
            let mut tracker = ParentConsumptionTracker::new();
            match verify_stitched_receipt(&receipt_a, &ctx, &mut tracker) {
                Ok(a) if a.valid => {}
                Ok(a) => failures.push(format!(
                    "the first child was refused: {}",
                    a.reason.unwrap_or_default()
                )),
                Err(e) => failures.push(format!("verifier error: {e}")),
            }
            match verify_stitched_receipt(&receipt_b, &ctx, &mut tracker) {
                Ok(a) if a.valid => {
                    failures.push("the second child of one parent was accepted".into())
                }
                Ok(_) => {}
                Err(e) => failures.push(format!("verifier error: {e}")),
            }
        }
        (Err(e), _) | (_, Err(e)) => failures.push(format!("advance refused: {e}")),
    }

    ImplementationTraceResult {
        trace_name: "state_machine_fork_divergence".into(),
        steps: 2,
        passed: failures.is_empty(),
        failures,
        duration_ms: start.elapsed().as_secs_f64() * 1000.0,
    }
}

fn trace_bilateral_precommit_tripwire(
    _seed_bytes: &[u8; 32],
    _pk: &[u8],
    _sk: &[u8],
) -> ImplementationTraceResult {
    let start = Instant::now();
    let failures = run_async_trace(async move {
        let mut failures = Vec::new();
        let mut side = match trace_side(TRACE_PAIR1_LOCAL, TRACE_PAIR1_REMOTE) {
            Ok(side) => side,
            Err(e) => return vec![e],
        };
        let remote = side.remote_device_id;
        let expected_initial_tip = match side.manager.initial_relationship_tip_for(&remote) {
            Ok(tip) => tip,
            Err(e) => return vec![format!("initial relationship tip: {e}")],
        };
        match side.manager.establish_relationship(&remote).await {
            Ok(anchor) if anchor.chain_tip == expected_initial_tip => {}
            Ok(_) => {
                failures.push("establish_relationship produced an unexpected initial tip".into())
            }
            Err(e) => return vec![format!("establish_relationship failed: {e}")],
        }

        // Two sibling precommitments capture the same parent h_n.
        let first_pre = match trace_prepare(&mut side, "trace-precommit-1", 0x01).await {
            Ok(pre) => pre,
            Err(e) => return vec![e],
        };
        if !side
            .manager
            .has_pending_commitment(&first_pre.bilateral_commitment_hash)
        {
            failures.push("prepared bilateral precommitment was not marked pending".into());
        }
        if first_pre.parent_tip != expected_initial_tip {
            failures.push("precommitment did not capture the expected parent chain tip".into());
        }
        let second_pre = match trace_prepare(&mut side, "trace-precommit-2", 0x02).await {
            Ok(pre) => pre,
            Err(e) => return vec![e],
        };
        if second_pre.parent_tip != expected_initial_tip {
            failures.push("second precommitment captured the wrong parent chain tip".into());
        }

        // Sibling 1: the receiver accepts, the production prepare passes the
        // tripwire, Core's advance derives the successor, h_n is consumed.
        let first_tip = match trace_commit(&mut side, &first_pre.bilateral_commitment_hash).await {
            Ok(c) => {
                if c.parent_tip != expected_initial_tip {
                    failures.push("first commit did not consume the initial tip".into());
                }
                if c.new_tip == expected_initial_tip {
                    failures.push("first commit did not advance the relationship chain tip".into());
                }
                if side
                    .manager
                    .has_pending_commitment(&first_pre.bilateral_commitment_hash)
                {
                    failures.push("committed bilateral precommitment remained pending".into());
                }
                if side.manager.get_chain_tip_for(&remote) != Some(c.new_tip) {
                    failures.push("manager relationship tip diverged from the commit".into());
                }
                c.new_tip
            }
            Err(e) => return vec![format!("first commit failed: {e}")],
        };

        // Sibling 2: the receiver accepts it just as legitimately, but its
        // parent is consumed. Cryptographic legitimacy does not resurrect it.
        let head_before = side.head.root();
        match trace_commit(&mut side, &second_pre.bilateral_commitment_hash).await {
            Ok(_) => failures
                .push("stale bilateral precommitment committed after parent consumption".into()),
            Err(msg) => {
                if !(msg.contains("Tripwire")
                    && (msg.contains("advanced since precommitment creation")
                        || msg.contains("parent hash already consumed")))
                {
                    failures.push(format!(
                        "stale prepare rejection message was unexpected: {msg}"
                    ));
                }
            }
        }
        if side.head.root() != head_before {
            failures.push("the sender's head advanced on a refused stale commit".into());
        }
        if !side
            .manager
            .has_pending_commitment(&second_pre.bilateral_commitment_hash)
        {
            failures.push("rejected stale precommitment was removed from pending set".into());
        }
        if side.manager.get_chain_tip_for(&remote) != Some(first_tip) {
            failures.push("manager chain tip changed after stale prepare rejection".into());
        }

        failures
    });

    ImplementationTraceResult {
        trace_name: "bilateral_precommit_tripwire".into(),
        steps: 5,
        passed: failures.is_empty(),
        failures,
        duration_ms: start.elapsed().as_secs_f64() * 1000.0,
    }
}

fn trace_djte_emission_happy_path(
    _seed_bytes: &[u8; 32],
    _pk: &[u8],
    _sk: &[u8],
) -> ImplementationTraceResult {
    let start = Instant::now();
    let mut failures = Vec::new();

    let (prev, next, jap, receipt) = build_djte_transition(10, 1);
    let witness = match dsm::emissions::EmissionWitness::from_states(&prev, &next, &jap) {
        Ok(w) => w,
        Err(e) => {
            failures.push(format!(
                "EmissionWitness::from_states errored on happy path: {e}"
            ));
            return ImplementationTraceResult {
                trace_name: "djte_emission_happy_path".into(),
                steps: 0,
                passed: false,
                failures,
                duration_ms: start.elapsed().as_secs_f64() * 1000.0,
            };
        }
    };

    match verify_emission(&prev, &next, &jap, &receipt, &witness) {
        Ok(true) => {}
        Ok(false) => failures.push("verify_emission returned false on the happy path".into()),
        Err(e) => failures.push(format!("verify_emission errored on happy path: {e}")),
    }

    if next.emission_index != prev.emission_index + 1 {
        failures.push("emission index did not advance by one".into());
    }
    if next.remaining_supply != prev.remaining_supply - receipt.amount {
        failures.push("remaining supply did not decrease by the receipt amount".into());
    }
    if next.dlv_tip == prev.dlv_tip {
        failures.push("DLV tip did not advance after emission".into());
    }
    if !next.spent_smt.is_spent(&receipt.jap_hash) {
        failures.push("JAP was not marked spent in the next state".into());
    }

    ImplementationTraceResult {
        trace_name: "djte_emission_happy_path".into(),
        steps: 4,
        passed: failures.is_empty(),
        failures,
        duration_ms: start.elapsed().as_secs_f64() * 1000.0,
    }
}

fn trace_djte_repeated_emission_alignment(
    _seed_bytes: &[u8; 32],
    _pk: &[u8],
    _sk: &[u8],
) -> ImplementationTraceResult {
    let start = Instant::now();
    let mut failures = Vec::new();

    let initial_supply = 2u64;
    let emission_amount = 1u64;
    let mut spent_japs = BTreeSet::new();
    let mut spent_proofs = BTreeMap::new();
    let mut consumed_proofs = BTreeSet::new();

    let initial = SourceDlvState::new_with_schedule(
        EmissionSchedule::new(initial_supply, 2, 64, 2, 1).expect("trace emission schedule"),
    );

    let jap_a = build_test_jap(0x7A, 0x09);
    let (after_first, receipt_a) = apply_djte_transition(&initial, &jap_a, emission_amount);
    match dsm::emissions::EmissionWitness::from_states(&initial, &after_first, &jap_a)
        .and_then(|w| verify_emission(&initial, &after_first, &jap_a, &receipt_a, &w))
    {
        Ok(true) => {}
        Ok(false) => failures.push("first repeated-emission transition returned false".into()),
        Err(e) => failures.push(format!("first repeated-emission transition errored: {e}")),
    }
    spent_japs.insert(receipt_a.jap_hash);
    spent_proofs.insert(receipt_a.jap_hash, receipt_a.digest());
    assert_repeated_djte_alignment(
        "after first emission",
        &after_first,
        initial_supply,
        &spent_japs,
        &spent_proofs,
        &consumed_proofs,
        &mut failures,
    );

    let jap_b = build_test_jap(0x7A, 0x0A);
    let (after_second, receipt_b) = apply_djte_transition(&after_first, &jap_b, emission_amount);
    match dsm::emissions::EmissionWitness::from_states(&after_first, &after_second, &jap_b)
        .and_then(|w| verify_emission(&after_first, &after_second, &jap_b, &receipt_b, &w))
    {
        Ok(true) => {}
        Ok(false) => failures.push("second repeated-emission transition returned false".into()),
        Err(e) => failures.push(format!("second repeated-emission transition errored: {e}")),
    }
    spent_japs.insert(receipt_b.jap_hash);
    spent_proofs.insert(receipt_b.jap_hash, receipt_b.digest());
    assert_repeated_djte_alignment(
        "after second emission",
        &after_second,
        initial_supply,
        &spent_japs,
        &spent_proofs,
        &consumed_proofs,
        &mut failures,
    );

    let proof_a = receipt_a.digest();
    if !spent_proofs.values().any(|proof| proof == &proof_a) {
        failures.push("proof acknowledgment target was not minted".into());
    }
    if !consumed_proofs.insert(proof_a) {
        failures.push("first proof acknowledgment was not recorded".into());
    }
    if consumed_proofs.insert(proof_a) {
        failures.push("duplicate proof acknowledgment mutated the consumed-proof set".into());
    }
    assert_repeated_djte_alignment(
        "after proof acknowledgment",
        &after_second,
        initial_supply,
        &spent_japs,
        &spent_proofs,
        &consumed_proofs,
        &mut failures,
    );

    if after_second.count_smt.total() != 2 {
        failures.push("two repeated activations did not produce two activation instances".into());
    }
    if after_second.remaining_supply != 0 {
        failures.push("repeated emissions did not exhaust the expected supply".into());
    }

    ImplementationTraceResult {
        trace_name: "djte_repeated_emission_alignment".into(),
        steps: 3,
        passed: failures.is_empty(),
        failures,
        duration_ms: start.elapsed().as_secs_f64() * 1000.0,
    }
}

fn trace_djte_supply_underflow_rejection(
    _seed_bytes: &[u8; 32],
    _pk: &[u8],
    _sk: &[u8],
) -> ImplementationTraceResult {
    let start = Instant::now();
    let mut failures = Vec::new();

    let (prev, next, jap, receipt) = build_djte_transition(1, 2);

    match dsm::emissions::EmissionWitness::from_states(&prev, &next, &jap)
        .and_then(|w| verify_emission(&prev, &next, &jap, &receipt, &w))
    {
        Ok(true) => failures.push("verify_emission accepted a supply-underflow transition".into()),
        Ok(false) => {
            failures.push("verify_emission returned false instead of a concrete rejection".into())
        }
        Err(e) => {
            let msg = format!("{e}");
            if !(msg.contains("Supply underflow") || msg.contains("Emission amount mismatch")) {
                failures.push(format!("unexpected DJTE rejection message: {msg}"));
            }
        }
    }

    if prev.remaining_supply != 1 {
        failures.push("previous DJTE supply mutated unexpectedly".into());
    }

    ImplementationTraceResult {
        trace_name: "djte_supply_underflow_rejection".into(),
        steps: 2,
        passed: failures.is_empty(),
        failures,
        duration_ms: start.elapsed().as_secs_f64() * 1000.0,
    }
}

fn trace_dlv_manager_inventory_consistency(
    _seed_bytes: &[u8; 32],
    _pk: &[u8],
    _sk: &[u8],
) -> ImplementationTraceResult {
    let start = Instant::now();
    let failures = run_async_trace(async move {
        let mut failures = Vec::new();
        let manager = DLVManager::new();

        let creator_kp = generate_keypair_from_seed(TRACE_VARIANT, &[0x61; 32])
            .expect("creator SPHINCS keypair");
        let (encryption_pk, _encryption_sk) =
            generate_kyber_keypair_from_entropy(&[0x71; 32], "implementation-trace-vault")
                .expect("vault kyber keypair");
        // The creator's head root is the reference the vault's parameters
        // commit to.
        let reference_root = match LiveDevice::new("trace-dlv-creator") {
            Ok(creator) => creator.head.root(),
            Err(e) => return vec![format!("creator device: {e}")],
        };

        let condition = FulfillmentMechanism::CryptoCondition {
            condition_hash: vec![0xA1; 32],
            public_params: vec![0xB2; 16],
        };

        let draft_a = match manager.prepare_vault(
            &creator_kp.public_key,
            condition.clone(),
            b"trace vault alpha",
            "text/plain",
            None,
            &encryption_pk,
            &reference_root,
            // Not an AMM vault: no DLV-layer policy object to derive a digest from.
            None,
        ) {
            Ok(result) => result,
            Err(e) => return vec![format!("prepare_vault alpha failed: {e}")],
        };
        let creator_signature_a = match dsm::crypto::sphincs::sphincs_sign(
            &creator_kp.secret_key,
            &draft_a.parameters_hash,
        ) {
            Ok(result) => result,
            Err(e) => return vec![format!("sign_vault alpha failed: {e}")],
        };
        let (vault_a, op_a) = match manager.finalize_vault(draft_a, &creator_signature_a).await {
            Ok(result) => result,
            Err(e) => return vec![format!("finalize_vault alpha failed: {e}")],
        };

        let draft_b = match manager.prepare_vault(
            &creator_kp.public_key,
            condition,
            b"trace vault beta",
            "text/plain",
            None,
            &encryption_pk,
            &reference_root,
            // Not an AMM vault: no DLV-layer policy object to derive a digest from.
            None,
        ) {
            Ok(result) => result,
            Err(e) => return vec![format!("prepare_vault beta failed: {e}")],
        };
        let creator_signature_b = match dsm::crypto::sphincs::sphincs_sign(
            &creator_kp.secret_key,
            &draft_b.parameters_hash,
        ) {
            Ok(result) => result,
            Err(e) => return vec![format!("sign_vault beta failed: {e}")],
        };
        let (vault_b, op_b) = match manager.finalize_vault(draft_b, &creator_signature_b).await {
            Ok(result) => result,
            Err(e) => return vec![format!("finalize_vault beta failed: {e}")],
        };

        if vault_a == vault_b {
            failures.push("two different vault contents produced the same vault id".into());
        }

        let listed = match manager.list_vaults().await {
            Ok(vaults) => vaults,
            Err(e) => return vec![format!("list_vaults failed: {e}")],
        };
        if listed.len() != 2 || !listed.contains(&vault_a) || !listed.contains(&vault_b) {
            failures.push("vault inventory listing did not match created vaults".into());
        }

        let limbo = match manager.get_vaults_by_status(VaultState::Limbo).await {
            Ok(vaults) => vaults,
            Err(e) => return vec![format!("get_vaults_by_status failed: {e}")],
        };
        if limbo.len() != 2 {
            failures.push("newly created vaults were not both in Limbo state".into());
        }

        match manager
            .create_vault_post(&vault_a, "validation", Some(7))
            .await
        {
            Ok(post) => {
                if post.is_empty() {
                    failures.push("create_vault_post returned empty bytes".into());
                }
            }
            Err(e) => failures.push(format!("create_vault_post failed: {e}")),
        }

        // DlvCreate is structurally STATE-ONLY (owner directive 2026-08-28):
        // the legacy locked-token fields are deleted; funded creation is
        // DlvCreateFundedV2 through the route, never this manager.
        match op_a {
            Operation::DlvCreate { mode, .. } => {
                if mode != TransactionMode::Unilateral {
                    failures.push("vault create operation did not use unilateral mode".into());
                }
            }
            _ => failures.push("create_vault did not return a DlvCreate operation".into()),
        }

        if !matches!(op_b, Operation::DlvCreate { .. }) {
            failures.push("second create_vault did not return a DlvCreate operation".into());
        }

        failures
    });

    ImplementationTraceResult {
        trace_name: "dlv_manager_inventory_consistency".into(),
        steps: 5,
        passed: failures.is_empty(),
        failures,
        duration_ms: start.elapsed().as_secs_f64() * 1000.0,
    }
}

fn trace_token_manager_balance_replay(
    _seed_bytes: &[u8; 32],
    _pk: &[u8],
    _sk: &[u8],
) -> ImplementationTraceResult {
    let start = Instant::now();
    let mut failures = Vec::new();
    let (mut alice, mut bob) = trace_pair("balance-replay");
    let transfers = [7u64, 13, 19];

    for (idx, amount) in transfers.iter().enumerate() {
        let (alice_before, bob_before) = (alice.era_balance(), bob.era_balance());
        let op = alice
            .transfer(&bob, *amount, &[(idx as u8) + 3; 8])
            .expect("transfer");
        match (alice.send(&bob, &op), bob.receive(&alice, &op)) {
            (Ok(debit), Ok(credit)) => {
                alice.install(debit);
                bob.install(credit);
            }
            (Err(e), _) | (_, Err(e)) => {
                failures.push(format!("step {idx}: advance refused: {e}"));
                continue;
            }
        }
        if alice.era_balance() != alice_before - amount {
            failures.push(format!("step {idx}: sender balance mismatch"));
        }
        if bob.era_balance() != bob_before + amount {
            failures.push(format!("step {idx}: recipient balance mismatch"));
        }
        if alice.era_balance() + bob.era_balance() != ERA_FAUCET_PAYOUT {
            failures.push(format!("step {idx}: conservation violated"));
        }
    }

    if alice.era_balance() != 61 {
        failures.push("final sender balance did not match the trace".into());
    }
    if bob.era_balance() != 39 {
        failures.push("final recipient balance did not match the trace".into());
    }

    ImplementationTraceResult {
        trace_name: "token_manager_balance_replay".into(),
        steps: transfers.len() as u64,
        passed: failures.is_empty(),
        failures,
        duration_ms: start.elapsed().as_secs_f64() * 1000.0,
    }
}

fn trace_token_manager_overspend_rejection(
    _seed_bytes: &[u8; 32],
    _pk: &[u8],
    _sk: &[u8],
) -> ImplementationTraceResult {
    let start = Instant::now();
    let mut failures = Vec::new();
    let (alice, bob) = trace_pair("overspend");
    let held = alice.era_balance();
    let root = alice.head.root();

    let op = alice
        .transfer(&bob, held + 1, &[0xEE; 8])
        .expect("transfer");
    if alice.send(&bob, &op).is_ok() {
        failures.push("an overspend was accepted by the advance".into());
    }
    if alice.head.root() != root || alice.era_balance() != held {
        failures.push("the head changed after a refused overspend".into());
    }

    ImplementationTraceResult {
        trace_name: "token_manager_overspend_rejection".into(),
        steps: 1,
        passed: failures.is_empty(),
        failures,
        duration_ms: start.elapsed().as_secs_f64() * 1000.0,
    }
}

fn trace_tripwire_parent_consumption(
    _seed_bytes: &[u8; 32],
    _pk: &[u8],
    _sk: &[u8],
) -> ImplementationTraceResult {
    let start = Instant::now();
    let mut failures = Vec::new();
    let mut tracker = ParentConsumptionTracker::new();

    let parent = [0x71; 32];
    let child_a = [0x72; 32];
    let child_b = [0x73; 32];

    if let Err(e) = tracker.try_consume(parent, child_a) {
        failures.push(format!("fresh parent rejected unexpectedly: {e}"));
    }

    match tracker.try_consume(parent, child_a) {
        Ok(()) => failures.push("replay was accepted by parent-consumption tracker".into()),
        Err(e) => {
            let msg = format!("{e}");
            if !msg.contains("replay detected") {
                failures.push(format!("replay rejection message was too weak: {msg}"));
            }
        }
    }

    match tracker.try_consume(parent, child_b) {
        Ok(()) => failures.push("fork child was accepted by parent-consumption tracker".into()),
        Err(e) => {
            let msg = format!("{e}");
            if !msg.contains("Fork detected") {
                failures.push(format!("fork rejection message was too weak: {msg}"));
            }
        }
    }

    if tracker.get_child(&parent) != Some(&child_a) {
        failures.push("canonical child mapping was overwritten after fork attempt".into());
    }

    ImplementationTraceResult {
        trace_name: "tripwire_parent_consumption".into(),
        steps: 3,
        passed: failures.is_empty(),
        failures,
        duration_ms: start.elapsed().as_secs_f64() * 1000.0,
    }
}

/// The verifier's reason for refusing `receipt`, or `None` if it accepted.
fn refusal(
    receipt: &StitchedReceiptV2,
    ctx: &ReceiptVerificationContext,
    tracker: &mut ParentConsumptionTracker,
) -> Result<Option<String>, String> {
    match verify_stitched_receipt(receipt, ctx, tracker) {
        Ok(a) if a.valid => Ok(None),
        Ok(a) => Ok(Some(a.reason.unwrap_or_default())),
        Err(e) => Err(format!("verifier error: {e}")),
    }
}

fn trace_receipt_verifier_tripwire(
    _seed_bytes: &[u8; 32],
    _pk: &[u8],
    _sk: &[u8],
) -> ImplementationTraceResult {
    let start = Instant::now();
    let mut failures = Vec::new();
    let (alice, bob) = trace_pair("receipt-tripwire");
    let ctx = verification_context(&alice, &bob, alice.head.root());
    let mut tracker = ParentConsumptionTracker::new();

    let op_a = alice.transfer(&bob, 5, &[0xA1; 8]).expect("transfer a");
    let op_b = alice.transfer(&bob, 6, &[0xB1; 8]).expect("transfer b");
    let child_a = alice.send(&bob, &op_a).expect("advance a");
    let child_b = alice.send(&bob, &op_b).expect("advance b");
    let receipt_a = stitched_receipt(&alice, &bob, &child_a).expect("receipt a");
    let receipt_b = stitched_receipt(&alice, &bob, &child_b).expect("receipt b");

    let mut expect = |label: &str, receipt: &StitchedReceiptV2, want: Option<&str>| match (
        refusal(receipt, &ctx, &mut tracker),
        want,
    ) {
        (Ok(None), None) => {}
        (Ok(None), Some(_)) => failures.push(format!("{label}: ACCEPTED")),
        (Ok(Some(reason)), None) => failures.push(format!("{label}: refused: {reason}")),
        (Ok(Some(reason)), Some(needle)) if reason.contains(needle) => {}
        (Ok(Some(reason)), Some(needle)) => {
            failures.push(format!("{label}: refused without \"{needle}\": {reason}"))
        }
        (Err(e), _) => failures.push(format!("{label}: {e}")),
    };

    expect("the receipt", &receipt_a, None);
    expect("its replay", &receipt_a, Some("replay detected"));
    expect(
        "a second child of the parent",
        &receipt_b,
        Some("Fork detected"),
    );

    // Both parties re-sign a receipt whose path no longer authenticates the
    // parent tip under the pre-state root: one sibling changed.
    let mut bent = receipt_a.clone();
    let mut path =
        SmtInclusionProof::from_bytes(&bent.rel_proof_parent).expect("the receipt's path decodes");
    path.siblings[0][0] ^= 0x01;
    bent.rel_proof_parent = path.to_bytes();
    bent.sig_a.clear();
    bent.sig_b.clear();
    let commitment = bent.compute_commitment().expect("commitment");
    bent.add_sig_a(alice.keypair.sign(&commitment).expect("sig a"));
    bent.add_sig_b(bob.keypair.sign(&commitment).expect("sig b"));
    expect(
        "a signed receipt over a bent path",
        &bent,
        Some("the path does not authenticate the old leaf"),
    );

    if tracker.get_child(&receipt_a.parent_tip) != Some(&receipt_a.child_tip) {
        failures.push("the tracker lost the accepted child after the fork attempt".into());
    }

    ImplementationTraceResult {
        trace_name: "receipt_verifier_tripwire".into(),
        steps: 4,
        passed: failures.is_empty(),
        failures,
        duration_ms: start.elapsed().as_secs_f64() * 1000.0,
    }
}

fn trace_tripwire_first_contact_binding(
    _seed_bytes: &[u8; 32],
    _pk: &[u8],
    _sk: &[u8],
) -> ImplementationTraceResult {
    let start = Instant::now();
    let mut failures = Vec::new();
    let (mut alice, bob) = trace_pair("first-contact");
    let h0 = alice.tip_with(&bob).expect("established");
    let mut tracker = ParentConsumptionTracker::new();

    // First contact: the relationship's first step extends h_0, which the
    // advance seeds into the tree, so its parent path carries h_0.
    let root0 = alice.head.root();
    let first = alice
        .send(
            &bob,
            &alice.transfer(&bob, 3, &[0x51; 8]).expect("transfer"),
        )
        .expect("first step");
    let alternate = alice
        .send(
            &bob,
            &alice.transfer(&bob, 4, &[0x52; 8]).expect("transfer"),
        )
        .expect("alternate first step");
    let first_receipt = stitched_receipt(&alice, &bob, &first).expect("first receipt");
    let alternate_receipt = stitched_receipt(&alice, &bob, &alternate).expect("alternate receipt");
    if first_receipt.parent_tip != h0 {
        failures.push("the first step does not extend the relationship's h_0".into());
    }
    alice.install(first);

    let root1 = alice.head.root();
    let extension = alice
        .send(
            &bob,
            &alice.transfer(&bob, 5, &[0x53; 8]).expect("transfer"),
        )
        .expect("extension step");
    let extension_receipt = stitched_receipt(&alice, &bob, &extension).expect("extension receipt");

    let first_ctx = verification_context(&alice, &bob, root0);
    let extension_ctx = verification_context(&alice, &bob, root1);
    match refusal(&first_receipt, &first_ctx, &mut tracker) {
        Ok(None) => {}
        Ok(Some(r)) => failures.push(format!("the first-contact receipt was refused: {r}")),
        Err(e) => failures.push(e),
    }
    match refusal(&extension_receipt, &extension_ctx, &mut tracker) {
        Ok(None) => {}
        Ok(Some(r)) => failures.push(format!("the extension was refused: {r}")),
        Err(e) => failures.push(e),
    }
    match refusal(&alternate_receipt, &first_ctx, &mut tracker) {
        Ok(None) => failures.push("an alternate first-contact branch was accepted".into()),
        Ok(Some(r)) if r.contains("Fork detected") => {}
        Ok(Some(r)) => failures.push(format!(
            "the alternate branch was refused without a fork: {r}"
        )),
        Err(e) => failures.push(e),
    }

    if tracker.get_child(&h0) != Some(&first_receipt.child_tip) {
        failures.push("first contact did not bind h_0 to the accepted first child".into());
    }
    if tracker.get_child(&first_receipt.child_tip) != Some(&extension_receipt.child_tip) {
        failures.push("the extension did not anchor on the accepted child".into());
    }

    ImplementationTraceResult {
        trace_name: "tripwire_first_contact_binding".into(),
        steps: 3,
        passed: failures.is_empty(),
        failures,
        duration_ms: start.elapsed().as_secs_f64() * 1000.0,
    }
}

fn trace_bilateral_precomputed_finalize_hash(
    _seed_bytes: &[u8; 32],
    _pk: &[u8],
    _sk: &[u8],
) -> ImplementationTraceResult {
    use dsm::core::bilateral_transaction_manager::{compute_precommit, compute_successor_tip};
    let start = Instant::now();
    let failures = run_async_trace(async move {
        let mut failures = Vec::new();
        let mut side = match trace_side(TRACE_PAIR1_LOCAL, TRACE_PAIR1_REMOTE) {
            Ok(side) => side,
            Err(e) => return vec![e],
        };
        let remote = side.remote_device_id;
        let h_n = match side.manager.establish_relationship(&remote).await {
            Ok(anchor) => anchor.chain_tip,
            Err(e) => return vec![format!("establish_relationship failed: {e}")],
        };

        let pre = match trace_prepare(&mut side, "trace-precomputed-finalize", 0x11).await {
            Ok(pre) => pre,
            Err(e) => return vec![e],
        };
        // §39: the ONE transition entropy is Core's derivation on the sender's
        // head — the same function the canonical advance runs — so the sender
        // can predict the committed tip at confirm time.
        let rel_key = compute_smt_key(&side.local_device_id, &remote);
        let entropy = side
            .head
            .derive_transition_entropy(&rel_key, &pre.operation);
        if entropy
            != side
                .head
                .derive_transition_entropy(&rel_key, &pre.operation)
        {
            failures.push("Core's transition entropy derivation is not deterministic".into());
        }
        let op_bytes = pre.operation.to_bytes();
        let sigma = compute_precommit(&h_n, &op_bytes, &entropy);
        let predicted_tip = compute_successor_tip(&h_n, &op_bytes, &entropy, &sigma);

        let mut alternate_entropy = entropy;
        alternate_entropy[0] ^= 0xFF;
        let alternate_sigma = compute_precommit(&h_n, &op_bytes, &alternate_entropy);
        if compute_successor_tip(&h_n, &op_bytes, &alternate_entropy, &alternate_sigma)
            == predicted_tip
        {
            failures
                .push("changing the transition entropy did not change the predicted tip".into());
        }

        let committed = match trace_commit(&mut side, &pre.bilateral_commitment_hash).await {
            Ok(c) => c,
            Err(e) => return vec![format!("commit failed: {e}")],
        };
        if committed.entropy != entropy {
            failures.push("the committed transition entropy differs from the predicted one".into());
        }
        if committed.new_tip != predicted_tip {
            failures.push("predicted post-commit tip did not match the committed tip".into());
        }
        if side.manager.get_chain_tip_for(&remote) != Some(predicted_tip) {
            failures.push("manager did not persist the predicted committed tip".into());
        }
        if side
            .manager
            .has_pending_commitment(&pre.bilateral_commitment_hash)
        {
            failures.push("commit left the precommitment pending".into());
        }

        failures
    });

    ImplementationTraceResult {
        trace_name: "bilateral_precomputed_finalize_hash".into(),
        steps: 4,
        passed: failures.is_empty(),
        failures,
        duration_ms: start.elapsed().as_secs_f64() * 1000.0,
    }
}

// ========================================================================
// OFFLINE FINALITY TRACE (Paper Theorems 4.1, 4.2)
//
// Replays the bilateral commit through the production sequence:
//   1. Establish the relationship
//   2. Prepare + commit (the tip advances: BilateralIrreversibility)
//   3. A second prepare + commit (sequential commits, distinct tips)
//   4. Two siblings of one parent: one commits, the other is refused
//      (TripwireGuaranteesUniqueness)
//   5. Every committed debit is the receiver's credit, on the two heads
//      (TokenConservation)
//
// Maps to DSM_OfflineFinality.tla invariants:
//   BilateralIrreversibility, FullSettlement, TripwireGuaranteesUniqueness,
//   TokenConservation
// ========================================================================
fn trace_bilateral_full_offline_finality(
    _seed_bytes: &[u8; 32],
    _pk: &[u8],
    _sk: &[u8],
) -> ImplementationTraceResult {
    let start = Instant::now();
    let failures = run_async_trace(async move {
        let mut failures = Vec::new();
        let mut side = match trace_side(TRACE_PAIR1_LOCAL, TRACE_PAIR1_REMOTE) {
            Ok(side) => side,
            Err(e) => return vec![e],
        };
        let remote = side.remote_device_id;
        let local = side.local_device_id;
        let mut remote_head = match DeviceState::new(
            TRACE_PAIR1_REMOTE.1,
            remote,
            side.remote_kp.public_key().to_vec(),
        )
        .establish_relationship(local)
        {
            Ok(head) => head,
            Err(e) => return vec![format!("establishing the receiver's relationship: {e}")],
        };
        let era = era_policy_commit();
        let total = side.head.balance(&era) + remote_head.balance(&era);

        // Step 1: Establish relationship
        let initial_tip = match side.manager.initial_relationship_tip_for(&remote) {
            Ok(tip) => tip,
            Err(e) => return vec![format!("initial relationship tip: {e}")],
        };
        match side.manager.establish_relationship(&remote).await {
            Ok(anchor) if anchor.chain_tip == initial_tip => {}
            Ok(_) => failures.push("establish_relationship produced unexpected initial tip".into()),
            Err(e) => return vec![format!("establish_relationship failed: {e}")],
        }

        // Step 2: First prepare + commit (BilateralIrreversibility)
        let pre1 = match trace_prepare(&mut side, "finality-trace-1", 0x01).await {
            Ok(pre) => pre,
            Err(e) => return vec![e],
        };
        if pre1.parent_tip != initial_tip {
            failures.push("first precommitment did not capture initial tip".into());
        }
        let first = match trace_commit(&mut side, &pre1.bilateral_commitment_hash).await {
            Ok(c) => c,
            Err(e) => return vec![format!("first commit failed: {e}")],
        };
        if first.new_tip == initial_tip {
            failures.push("commit did not advance chain tip (irreversibility)".into());
        }
        if side
            .manager
            .has_pending_commitment(&pre1.bilateral_commitment_hash)
        {
            failures.push("first precommitment remained pending after commit".into());
        }
        if let Err(e) = trace_receive(&mut remote_head, &local, &first) {
            failures.push(e);
        }

        // Step 3: Second prepare + commit (sequential commits, distinct tips)
        let pre2 = match trace_prepare(&mut side, "finality-trace-2", 0x02).await {
            Ok(pre) => pre,
            Err(e) => return vec![e],
        };
        if pre2.parent_tip != first.new_tip {
            failures.push("second precommitment captured wrong parent tip".into());
        }
        let second = match trace_commit(&mut side, &pre2.bilateral_commitment_hash).await {
            Ok(c) => c,
            Err(e) => return vec![format!("second commit failed: {e}")],
        };
        if second.new_tip == first.new_tip || second.new_tip == initial_tip {
            failures.push("the second commit did not produce a new tip".into());
        }
        if let Err(e) = trace_receive(&mut remote_head, &local, &second) {
            failures.push(e);
        }

        // Step 4: two siblings of the second tip — one commits, the other
        // finds its parent consumed (TripwireGuaranteesUniqueness).
        let pre3 = match trace_prepare(&mut side, "finality-trace-3", 0x03).await {
            Ok(pre) => pre,
            Err(e) => return vec![e],
        };
        let pre4 = match trace_prepare(&mut side, "finality-trace-4", 0x04).await {
            Ok(pre) => pre,
            Err(e) => return vec![e],
        };
        let third = match trace_commit(&mut side, &pre4.bilateral_commitment_hash).await {
            Ok(c) => c,
            Err(e) => return vec![format!("third commit failed: {e}")],
        };
        if let Err(e) = trace_receive(&mut remote_head, &local, &third) {
            failures.push(e);
        }
        match trace_commit(&mut side, &pre3.bilateral_commitment_hash).await {
            Ok(_) => failures.push("a sibling committed after its parent was consumed".into()),
            Err(msg) => {
                if !(msg.contains("Tripwire")
                    && (msg.contains("advanced since precommitment creation")
                        || msg.contains("parent hash already consumed")))
                {
                    failures.push(format!("tripwire rejection message unexpected: {msg}"));
                }
            }
        }
        if side.manager.get_chain_tip_for(&remote) != Some(third.new_tip) {
            failures.push("the chain tip moved on a refused sibling".into());
        }

        // Step 5: TokenConservation — three commits, three debits, three
        // credits, and no unit created or lost between the two heads.
        let sent = 3 * TRACE_BILATERAL_AMOUNT;
        if remote_head.balance(&era) != sent {
            failures.push(format!(
                "the receiver holds {} after {sent} was committed to it",
                remote_head.balance(&era)
            ));
        }
        if side.head.balance(&era) + remote_head.balance(&era) != total {
            failures.push("token conservation violated across the two heads".into());
        }

        failures
    });

    ImplementationTraceResult {
        trace_name: "bilateral_full_offline_finality".into(),
        steps: 5,
        passed: failures.is_empty(),
        failures,
        duration_ms: start.elapsed().as_secs_f64() * 1000.0,
    }
}

// ========================================================================
// NON-INTERFERENCE TRACE (Paper Lemma 3.1, Theorem 3.1)
//
// Two bilateral managers on disjoint device pairs cannot affect each
// other's state, and each pair's commits move only that pair's balances.
//
// Maps to DSM_NonInterference.tla invariants:
//   NonInterference, ZeroRefreshForInactive, PerPairConservation
// ========================================================================
fn trace_bilateral_pair_non_interference(
    _seed_bytes: &[u8; 32],
    _pk: &[u8],
    _sk: &[u8],
) -> ImplementationTraceResult {
    let start = Instant::now();
    let failures = run_async_trace(async move {
        let mut failures = Vec::new();
        let (mut pair1, mut pair2) = match (
            trace_side(TRACE_PAIR1_LOCAL, TRACE_PAIR1_REMOTE),
            trace_side(TRACE_PAIR2_LOCAL, TRACE_PAIR2_REMOTE),
        ) {
            (Ok(a), Ok(b)) => (a, b),
            (Err(e), _) | (_, Err(e)) => return vec![format!("pair setup: {e}")],
        };
        let (remote1, remote2) = (pair1.remote_device_id, pair2.remote_device_id);
        let era = era_policy_commit();

        // Step 1: Establish both relationships
        let tip1_init = match pair1.manager.establish_relationship(&remote1).await {
            Ok(anchor) => anchor.chain_tip,
            Err(e) => return vec![format!("pair1 establish failed: {e}")],
        };
        let tip2_init = match pair2.manager.establish_relationship(&remote2).await {
            Ok(anchor) => anchor.chain_tip,
            Err(e) => return vec![format!("pair2 establish failed: {e}")],
        };

        // Step 2: Operate on pair 1 only
        let pair2_tip = pair2.manager.get_chain_tip_for(&remote2);
        let pair2_root = pair2.head.root();
        let pair1_balance = pair1.head.balance(&era);
        let pre1 = match trace_prepare(&mut pair1, "ni-trace-pair1", 0x10).await {
            Ok(pre) => pre,
            Err(e) => return vec![e],
        };
        match trace_commit(&mut pair1, &pre1.bilateral_commitment_hash).await {
            Ok(c) if c.new_tip == tip1_init => {
                failures.push("pair1 commit did not advance its tip".into())
            }
            Ok(_) => {}
            Err(e) => return vec![format!("pair1 commit failed: {e}")],
        }

        // Step 3: NonInterference — pair 2 is untouched by pair 1's commit
        if pair2.manager.get_chain_tip_for(&remote2) != pair2_tip {
            failures.push("NonInterference violated: pair2's tip moved on pair1's commit".into());
        }
        if pair2.head.root() != pair2_root {
            failures.push("NonInterference violated: pair2's head moved on pair1's commit".into());
        }

        // Step 4: Operate on pair 2
        let pair1_tip = pair1.manager.get_chain_tip_for(&remote1);
        let pair1_root = pair1.head.root();
        let pair2_balance = pair2.head.balance(&era);
        let pre2 = match trace_prepare(&mut pair2, "ni-trace-pair2", 0x20).await {
            Ok(pre) => pre,
            Err(e) => return vec![e],
        };
        match trace_commit(&mut pair2, &pre2.bilateral_commitment_hash).await {
            Ok(c) if c.new_tip == tip2_init => {
                failures.push("pair2 commit did not advance its tip".into())
            }
            Ok(_) => {}
            Err(e) => return vec![format!("pair2 commit failed: {e}")],
        }

        // Step 5: ZeroRefreshForInactive — pair 1 is untouched by pair 2's commit
        if pair1.manager.get_chain_tip_for(&remote1) != pair1_tip {
            failures.push(
                "ZeroRefreshForInactive violated: pair1's tip moved on pair2's commit".into(),
            );
        }
        if pair1.head.root() != pair1_root {
            failures.push(
                "ZeroRefreshForInactive violated: pair1's head moved on pair2's commit".into(),
            );
        }

        // Step 6: PerPairConservation — each pair's commit debited exactly its
        // own amount from its own sender.
        if pair1.head.balance(&era) != pair1_balance - TRACE_BILATERAL_AMOUNT {
            failures.push("PerPairConservation violated on pair1".into());
        }
        if pair2.head.balance(&era) != pair2_balance - TRACE_BILATERAL_AMOUNT {
            failures.push("PerPairConservation violated on pair2".into());
        }

        failures
    });

    ImplementationTraceResult {
        trace_name: "bilateral_pair_non_interference".into(),
        steps: 6,
        passed: failures.is_empty(),
        failures,
        duration_ms: start.elapsed().as_secs_f64() * 1000.0,
    }
}

fn run_async_trace<T, Fut>(future: Fut) -> T
where
    T: Send + 'static,
    Fut: Future<Output = T> + Send + 'static,
{
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("implementation trace runtime");
        runtime.block_on(future)
    })
    .join()
    .expect("implementation trace thread")
}

/// The two device pairs the bilateral traces run on: `(device_id, genesis)`
/// for each side. Pair 1 is `[0x21..] <-> [0x31..]`, pair 2 `[0x41..] <-> [0x51..]`.
/// Relationship chain tips over process memory, with the store trait's
/// compare-and-set: an update applies only on the expected parent, and an
/// absent tip reads as the zero parent a relationship starts from.
#[derive(Default)]
struct TraceTips {
    tips: std::sync::Mutex<std::collections::HashMap<[u8; 32], [u8; 32]>>,
}

impl dsm::core::chain_tip_store::ChainTipStore for TraceTips {
    fn get_contact_chain_tip(
        &self,
        device_id: &[u8; 32],
    ) -> Result<Option<[u8; 32]>, dsm::types::error::DsmError> {
        Ok(self
            .tips
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(device_id)
            .copied())
    }

    fn set_contact_chain_tip(
        &self,
        device_id: &[u8; 32],
        expected_parent_tip: [u8; 32],
        new_tip: [u8; 32],
    ) -> Result<bool, dsm::types::error::DsmError> {
        let mut tips = self.tips.lock().unwrap_or_else(|p| p.into_inner());
        if tips.get(device_id).copied().unwrap_or([0u8; 32]) != expected_parent_tip {
            return Ok(false);
        }
        tips.insert(*device_id, new_tip);
        Ok(true)
    }
}

const TRACE_PAIR1_LOCAL: ([u8; 32], [u8; 32]) = ([0x21; 32], [0x22; 32]);
const TRACE_PAIR1_REMOTE: ([u8; 32], [u8; 32]) = ([0x31; 32], [0x32; 32]);
const TRACE_PAIR2_LOCAL: ([u8; 32], [u8; 32]) = ([0x41; 32], [0x42; 32]);
const TRACE_PAIR2_REMOTE: ([u8; 32], [u8; 32]) = ([0x51; 32], [0x52; 32]);

/// A trace device's signing keypair, derived from its `(device_id, genesis)`.
fn trace_keypair(side: ([u8; 32], [u8; 32])) -> Result<SignatureKeyPair, String> {
    let entropy = [side.0.as_slice(), side.1.as_slice()].concat();
    SignatureKeyPair::generate_from_entropy(&entropy).map_err(|e| format!("trace keypair: {e}"))
}

/// The receiver's acceptance proof σ_B, exactly what
/// `BilateralTransactionManager::verify_receiver_acceptance_proof` checks:
/// a signature over `"DSM/bilateral-sign\0" || commitment_hash`.
fn receiver_acceptance_sig(kp: &SignatureKeyPair, commitment_hash: &[u8; 32]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(22 + 32);
    msg.extend_from_slice(b"DSM/bilateral-sign\0");
    msg.extend_from_slice(commitment_hash);
    kp.sign(&msg).expect("receiver acceptance signature")
}

/// One side of a bilateral trace pair: the sender's manager over its tip
/// store, its funded device head, and both keypairs.
struct TraceSide {
    manager: BilateralTransactionManager,
    tips: std::sync::Arc<TraceTips>,
    head: DeviceState,
    local_kp: SignatureKeyPair,
    remote_kp: SignatureKeyPair,
    local_device_id: [u8; 32],
    remote_device_id: [u8; 32],
}

/// The sender side of the pair `local ↔ remote`. The counterparty is a
/// verified contact whose genesis was verified online; that verification is
/// the network's, and the traces exercise what follows it.
fn trace_side(
    local: ([u8; 32], [u8; 32]),
    remote: ([u8; 32], [u8; 32]),
) -> Result<TraceSide, String> {
    let local_kp = trace_keypair(local)?;
    let remote_kp = trace_keypair(remote)?;
    let tips = std::sync::Arc::new(TraceTips::default());
    let mut manager = BilateralTransactionManager::new(
        DsmContactManager::new(local.0),
        local_kp.clone(),
        local.0,
        local.1,
        tips.clone(),
    );
    manager
        .add_verified_contact(DsmVerifiedContact {
            alias: "trace-remote".into(),
            device_id: remote.0,
            genesis_hash: remote.1,
            public_key: remote_kp.public_key().to_vec(),
            chain_tip: None,
            genesis_verified_online: true,
            verifying_storage_nodes: vec![],
            ble_address: None,
        })
        .map_err(|e| format!("failed to add the trace contact: {e}"))?;
    // The contact add establishes the relationship on the device head.
    let head = trace_local_head(local, &local_kp)?
        .establish_relationship(remote.0)
        .map_err(|e| format!("establishing the trace relationship: {e}"))?;
    Ok(TraceSide {
        manager,
        tips,
        head,
        local_kp,
        remote_kp,
        local_device_id: local.0,
        remote_device_id: remote.0,
    })
}

/// Commit the pending precommitment `hash` on `side`.
async fn trace_commit(side: &mut TraceSide, hash: &[u8; 32]) -> Result<TraceCommit, String> {
    trace_commit_prepared(
        &mut side.manager,
        &side.tips,
        &mut side.head,
        &side.remote_kp,
        &side.remote_device_id,
        hash,
    )
    .await
}

/// Prepare a signed transfer to the counterparty on `side`.
async fn trace_prepare(
    side: &mut TraceSide,
    message: &str,
    nonce: u8,
) -> Result<dsm::core::bilateral_transaction_manager::BilateralPreCommitment, String> {
    let op = build_signed_bilateral_transfer(&side.local_kp, side.remote_device_id, message, nonce);
    side.manager
        .prepare_offline_transfer(&side.remote_device_id, op)
        .await
        .map_err(|e| format!("prepare_offline_transfer failed: {e}"))
}

/// A trace pair's side: its device head, funded with one faucet payout of ERA.
fn trace_local_head(
    side: ([u8; 32], [u8; 32]),
    kp: &SignatureKeyPair,
) -> Result<DeviceState, String> {
    faucet_claim(
        &DeviceState::new(side.1, side.0, kp.public_key().to_vec()),
        1,
    )
    .map_err(|e| format!("trace head funding: {e}"))
}

/// What one committed bilateral step produced on the trace harness.
struct TraceCommit {
    parent_tip: [u8; 32],
    entropy: [u8; 32],
    new_tip: [u8; 32],
    operation: Operation,
}

/// The ERA each bilateral trace transfer moves.
const TRACE_BILATERAL_AMOUNT: u64 = 1;

/// The sender's commit of a bilateral precommitment, in production's order.
///
/// `prepare_bilateral_advance` runs the §6.1 tripwire against a real receiver
/// acceptance σ_B and hands the advance off with the sender's debit. The
/// device head advances on it — Core derives the transition's one entropy
/// there (Part VII step 3); nothing here chooses it. The symmetric successor
/// tip is `compute_successor_tip(h_n, op, e, C_pre)` over that value, exactly
/// as the BLE finalize computes it. The pair tip is persisted forward-only,
/// as the atomic commit persists it, the precommitment is consumed and the
/// manager's view moves to the new tip. A tripwire refusal comes back as the
/// manager's own error text.
async fn trace_commit_prepared(
    manager: &mut BilateralTransactionManager,
    tips: &TraceTips,
    local_head: &mut DeviceState,
    remote_kp: &SignatureKeyPair,
    remote_device_id: &[u8; 32],
    pre_commitment_hash: &[u8; 32],
) -> Result<TraceCommit, String> {
    use dsm::core::bilateral_transaction_manager::{compute_precommit, compute_successor_tip};
    use dsm::core::chain_tip_store::ChainTipStore;
    let prepared = manager
        .prepare_bilateral_advance(
            remote_device_id,
            pre_commitment_hash,
            &receiver_acceptance_sig(remote_kp, pre_commitment_hash),
            vec![BalanceDelta {
                policy_commit: era_policy_commit(),
                direction: BalanceDirection::Debit,
                amount: TRACE_BILATERAL_AMOUNT,
            }],
            None,
            None,
        )
        .await
        .map_err(|e| e.to_string())?;
    let outcome = local_head
        .advance(
            prepared.rel_key,
            prepared.counterparty_devid,
            prepared.operation.clone(),
            &prepared.deltas,
            None,
            None,
        )
        .map_err(|e| format!("the sender's advance was refused: {e}"))?;
    let entropy = outcome.transition_entropy();
    let op_bytes = prepared.operation.to_bytes();
    let sigma = compute_precommit(&prepared.parent_tip, &op_bytes, &entropy);
    let new_tip = compute_successor_tip(&prepared.parent_tip, &op_bytes, &entropy, &sigma);
    if !tips
        .set_contact_chain_tip(remote_device_id, prepared.parent_tip, new_tip)
        .map_err(|e| e.to_string())?
    {
        return Err("the tip store no longer holds the step's parent".into());
    }
    *local_head = outcome.new_device_state;
    manager.consume_pre_commitment(pre_commitment_hash);
    manager.advance_chain_tip(remote_device_id, new_tip);
    Ok(TraceCommit {
        parent_tip: prepared.parent_tip,
        entropy,
        new_tip,
        operation: prepared.operation,
    })
}

/// The receiver's credit for a committed step, on its own head.
fn trace_receive(
    remote_head: &mut DeviceState,
    local_device_id: &[u8; 32],
    commit: &TraceCommit,
) -> Result<(), String> {
    let remote = remote_head.devid();
    let outcome = remote_head
        .advance(
            compute_smt_key(&remote, local_device_id),
            *local_device_id,
            commit.operation.clone(),
            &[BalanceDelta {
                policy_commit: era_policy_commit(),
                direction: BalanceDirection::Credit,
                amount: TRACE_BILATERAL_AMOUNT,
            }],
            None,
            None,
        )
        .map_err(|e| format!("the receiver's advance was refused: {e}"))?;
    *remote_head = outcome.new_device_state;
    Ok(())
}

fn build_signed_bilateral_transfer(
    kp: &SignatureKeyPair,
    remote_device_id: [u8; 32],
    message: &str,
    nonce: u8,
) -> Operation {
    let op = Operation::Transfer {
        policy_commit: era_policy_commit(),
        token_id: b"ERA".to_vec(),
        to_device_id: remote_device_id.to_vec(),
        amount: Balance::amount(TRACE_BILATERAL_AMOUNT),
        mode: TransactionMode::Bilateral,
        nonce: vec![nonce; 8],
        recipient: remote_device_id.to_vec(),
        to: b"trace-bilateral-recipient".to_vec(),
        message: message.into(),
        signature: Vec::new(),
        authority_policy: None,
    };
    let signature = kp.sign(&op.signing_bytes()).expect("bilateral trace sign");
    op.with_signature(signature)
}

fn build_djte_transition(
    initial_supply: u64,
    emission_amount: u64,
) -> (
    SourceDlvState,
    SourceDlvState,
    JoinActivationProof,
    EmissionReceipt,
) {
    let prev = SourceDlvState::new(2, initial_supply);

    let jap = build_test_jap(0x7A, 0x09);
    let (next, receipt) = apply_djte_transition(&prev, &jap, emission_amount);

    (prev, next, jap, receipt)
}

fn build_test_jap(id_byte: u8, nonce_byte: u8) -> JoinActivationProof {
    // `gate_proof` currently has no verifier: the PaidK structural check was
    // removed because it never evaluated `VerifyPayment(r)` — the receipt
    // schema carries no operator signature, so any device could synthesize a
    // passing bundle, exactly as this fixture used to do.
    JoinActivationProof {
        id: [id_byte; 32],
        gate_proof: Vec::new(),
        nonce: [nonce_byte; 32],
    }
}

fn apply_djte_transition(
    prev: &SourceDlvState,
    jap: &JoinActivationProof,
    emission_amount: u64,
) -> (SourceDlvState, EmissionReceipt) {
    let jap_hash = jap.digest();
    let mut selection_state = prev.clone();
    selection_state
        .add_activation(jap)
        .expect("DJTE activation");
    let emission_index = prev.emission_index + 1;
    let winner_leaf =
        select_winner_for_event(&selection_state, emission_index, &jap_hash).expect("DJTE winner");
    let expected_winner_leaf =
        domain_hash_bytes(dsm::common::domain_tags::TAG_DJTE_ACTIVE, &jap.id);
    assert_eq!(winner_leaf, expected_winner_leaf);

    let receipt = EmissionReceipt {
        emission_index,
        winner_id: jap.id,
        amount: emission_amount,
        jap_hash,
    };

    let mut next = prev.clone();
    next.emission_index = emission_index;
    next.remaining_supply = prev.remaining_supply.saturating_sub(emission_amount);
    next.add_activation(jap)
        .expect("DJTE activation for next state");
    next.spent_smt
        .mark_spent(jap_hash)
        .expect("DJTE spent_smt mark_spent");

    let receipt_digest = receipt.digest();
    let count_root = next.count_smt.root();
    let spent_root = next.spent_smt.root();
    let shard_commit = djte_shard_roots_commitment(&next);
    next.dlv_tip = compute_djte_next_tip(
        &prev.dlv_tip,
        &receipt_digest,
        &count_root,
        &spent_root,
        &shard_commit,
    );

    (next, receipt)
}

fn assert_repeated_djte_alignment(
    label: &str,
    state: &SourceDlvState,
    initial_supply: u64,
    spent_japs: &BTreeSet<[u8; 32]>,
    spent_proofs: &BTreeMap<[u8; 32], [u8; 32]>,
    consumed_proofs: &BTreeSet<[u8; 32]>,
    failures: &mut Vec<String>,
) {
    if state.emission_index != spent_japs.len() as u64 {
        failures.push(format!(
            "{label}: emission_index {} did not match spent_japs size {}",
            state.emission_index,
            spent_japs.len()
        ));
    }

    if state.remaining_supply + state.emission_index != initial_supply {
        failures.push(format!(
            "{label}: remaining_supply {} plus emission_index {} did not reconstruct initial supply {}",
            state.remaining_supply,
            state.emission_index,
            initial_supply
        ));
    }

    let state_spent_japs: BTreeSet<[u8; 32]> = state.spent_smt.spent.keys().cloned().collect();
    if &state_spent_japs != spent_japs {
        failures.push(format!(
            "{label}: spent SMT keys diverged from tracked spent_japs"
        ));
    }

    let proof_japs: BTreeSet<[u8; 32]> = spent_proofs.keys().cloned().collect();
    if &proof_japs != spent_japs {
        failures.push(format!(
            "{label}: minted proof map keys diverged from tracked spent_japs"
        ));
    }

    if spent_proofs.len() != spent_japs.len() {
        failures.push(format!(
            "{label}: minted proof count {} did not match spent_japs count {}",
            spent_proofs.len(),
            spent_japs.len()
        ));
    }

    if consumed_proofs.len() > spent_proofs.len() {
        failures.push(format!(
            "{label}: consumed proof count {} exceeded minted proof count {}",
            consumed_proofs.len(),
            spent_proofs.len()
        ));
    }

    for proof in consumed_proofs {
        if !spent_proofs.values().any(|minted| minted == proof) {
            failures.push(format!(
                "{label}: consumed proof acknowledgment did not correspond to a minted proof"
            ));
        }
    }
}

fn djte_shard_roots_commitment(state: &SourceDlvState) -> [u8; 32] {
    let mut buf = Vec::with_capacity(state.shard_accumulators.len() * 32);
    for acc in &state.shard_accumulators {
        buf.extend_from_slice(&acc.root());
    }
    domain_hash_bytes(dsm::common::domain_tags::TAG_DJTE_SHARDS_ROOT, &buf)
}

fn compute_djte_next_tip(
    prev_tip: &[u8; 32],
    receipt_digest: &[u8; 32],
    count_root: &[u8; 32],
    spent_root: &[u8; 32],
    shard_roots_commitment: &[u8; 32],
) -> [u8; 32] {
    let mut buf = Vec::with_capacity(32 * 5);
    buf.extend_from_slice(prev_tip);
    buf.extend_from_slice(receipt_digest);
    buf.extend_from_slice(count_root);
    buf.extend_from_slice(spent_root);
    buf.extend_from_slice(shard_roots_commitment);
    domain_hash_bytes(dsm::common::domain_tags::TAG_DJTE_DLV_TIP, &buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_implementation_traces_pass() {
        let suite = collect_implementation_trace_results();
        assert!(suite.all_passed, "implementation traces should all pass");
    }

    #[test]
    fn repeated_djte_emission_alignment_trace_passes() {
        let result = trace_djte_repeated_emission_alignment(&[0u8; 32], &[], &[]);
        assert!(result.passed, "{}", result.failures.join("; "));
    }

    #[test]
    fn receipt_verifier_tripwire_trace_passes() {
        let result = trace_receipt_verifier_tripwire(&[0u8; 32], &[], &[]);
        assert!(result.passed, "{}", result.failures.join("; "));
    }

    #[test]
    fn tripwire_first_contact_binding_trace_passes() {
        let result = trace_tripwire_first_contact_binding(&[0u8; 32], &[], &[]);
        assert!(result.passed, "{}", result.failures.join("; "));
    }
}
