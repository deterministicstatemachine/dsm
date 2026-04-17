//! Deterministic implementation traces for direct Rust validation.
//!
//! Unlike TLC model checking, these traces execute the real DSM transition code
//! end-to-end with fixed scenarios and exact expectations.

#![allow(clippy::expect_used)]

use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;

use instant::Instant;
use prost::Message;
use serde::Serialize;

use dsm::common::device_tree::{DevTreeProof, DeviceTree};
use dsm::core::bilateral_transaction_manager::BilateralTransactionManager;
use dsm::core::contact_manager::DsmContactManager;
use dsm::core::state_machine::transition::verify_token_balance_consistency;
use dsm::core::state_machine::StateMachine;
use dsm::core::token::TokenStateManager;
use dsm::crypto::blake3::{domain_hash, domain_hash_bytes, dsm_domain_hasher};
use dsm::crypto::kyber::generate_kyber_keypair_from_entropy;
use dsm::crypto::signatures::SignatureKeyPair;
use dsm::crypto::sphincs::{generate_keypair_from_seed, sphincs_sign, SphincsVariant};
use dsm::emissions::{
    select_winner_for_event, verify_emission, EmissionReceipt, JoinActivationProof, SourceDlvState,
};
use dsm::types::contact_types::DsmVerifiedContact;
use dsm::types::operations::{Operation, TransactionMode, VerificationType};
use dsm::types::policy_types::PolicyFile;
use dsm::types::proto as pb;
use dsm::types::receipt_types::{
    ParentConsumptionTracker, ReceiptVerificationContext, StitchedReceiptV2,
};
use dsm::types::state_types::{DeviceInfo, State};
use dsm::types::token_types::Balance;
use dsm::vault::{DLVManager, FulfillmentMechanism, VaultState};
use dsm::verification::receipt_verification::verify_stitched_receipt;
use dsm::verification::smt_replace_witness::{compute_smt_key, hash_smt_leaf};

const TRACE_VARIANT: SphincsVariant = SphincsVariant::SPX256f;
const TRACE_TOKEN_ID: &str = "VVTRACE";
const TRACE_INITIAL_BALANCE: u64 = 100;
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

struct TokenTraceHarness {
    // Manager is no longer the canonical transition driver (§4.3 shim path)
    // but it still owns the token policy registration used by the harness.
    #[allow(dead_code)]
    manager: TokenStateManager,
    state: State,
    recipient: Vec<u8>,
    sender_key: String,
    recipient_key: String,
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

fn implementation_trace_catalog() -> [(&'static str, TraceFn); 15] {
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

fn trace_state_machine_transfer_chain(
    seed_bytes: &[u8; 32],
    pk: &[u8],
    sk: &[u8],
) -> ImplementationTraceResult {
    let start = Instant::now();
    let mut failures = Vec::new();

    let mut state = create_test_state(seed_bytes, pk);
    let sender_key = builtin_balance_key(pk, "ERA");
    state.token_balances.insert(
        sender_key,
        Balance::from_state(100, state.hash),
    );

    let mut machine = StateMachine::new();
    machine.set_state(state.clone());

    let steps = [1u64, 2, 3, 4];
    for (idx, amount) in steps.iter().enumerate() {
        let nonce = vec![(idx as u8) + 1; 8];
        let op = build_signed_transfer(sk, &state, nonce, *amount, b"ERA".to_vec(), vec![0xCC; 32]);
        let prev_hash = state.hash().expect("current hash");
        let expected_entropy = compute_next_entropy(&state, &op);

        match crate::compat_shim::machine_execute_transition(&mut machine, op) {
            Ok(new_state) => {
                if new_state.prev_state_hash != prev_hash {
                    failures.push(format!("step {idx}: prev_state_hash mismatch"));
                }
                if crate::compat_shim::state_number(&new_state) != crate::compat_shim::state_number(&state) + 1 {
                    failures.push(format!("step {idx}: state_number did not increment"));
                }
                if new_state.entropy != expected_entropy {
                    failures.push(format!("step {idx}: entropy diverged from formula"));
                }
                state = new_state;
            }
            Err(e) => failures.push(format!("step {idx}: execute_transition failed: {e}")),
        }
    }

    if machine.current_state().map(|s| crate::compat_shim::state_number(&s)) != Some(steps.len() as u64) {
        failures.push("machine tip did not end at expected state_number".into());
    }

    ImplementationTraceResult {
        trace_name: "state_machine_transfer_chain".into(),
        steps: steps.len() as u64,
        passed: failures.is_empty(),
        failures,
        duration_ms: start.elapsed().as_secs_f64() * 1000.0,
    }
}

fn trace_state_machine_signature_rejection(
    seed_bytes: &[u8; 32],
    pk: &[u8],
    sk: &[u8],
) -> ImplementationTraceResult {
    let start = Instant::now();
    let mut failures = Vec::new();

    let mut state = create_test_state(seed_bytes, pk);
    let sender_key = builtin_balance_key(pk, "ERA");
    state.token_balances.insert(
        sender_key,
        Balance::from_state(100, state.hash),
    );

    let original_hash = state.hash().expect("original hash");
    let mut machine = StateMachine::new();
    machine.set_state(state.clone());

    let mut op = build_signed_transfer(sk, &state, vec![9; 8], 10, b"ERA".to_vec(), vec![0xCD; 32]);
    if let Operation::Transfer { signature, .. } = &mut op {
        signature[0] ^= 0xFF;
    }

    if crate::compat_shim::machine_execute_transition(&mut machine, op).is_ok() {
        failures.push("tampered signature was accepted by execute_transition".into());
    }

    match machine.current_state() {
        Some(current) => {
            if crate::compat_shim::state_number(&current) != crate::compat_shim::state_number(&state) {
                failures.push("state machine advanced after rejected signature".into());
            }
            if current.hash != original_hash {
                failures.push("state hash changed after rejected signature".into());
            }
        }
        None => failures.push("state machine lost current state after rejection".into()),
    }

    ImplementationTraceResult {
        trace_name: "state_machine_signature_rejection".into(),
        steps: 1,
        passed: failures.is_empty(),
        failures,
        duration_ms: start.elapsed().as_secs_f64() * 1000.0,
    }
}

fn trace_state_machine_fork_divergence(
    seed_bytes: &[u8; 32],
    pk: &[u8],
    sk: &[u8],
) -> ImplementationTraceResult {
    let start = Instant::now();
    let mut failures = Vec::new();

    let mut state = create_test_state(seed_bytes, pk);
    let sender_key = builtin_balance_key(pk, "ERA");
    state.token_balances.insert(
        sender_key,
        Balance::from_state(100, state.hash),
    );
    let prev_hash = state.hash().expect("fork parent hash");

    let mut machine_a = StateMachine::new();
    machine_a.set_state(state.clone());
    let mut machine_b = StateMachine::new();
    machine_b.set_state(state.clone());

    let op_a = build_signed_transfer(sk, &state, vec![1; 8], 1, b"ERA".to_vec(), vec![0xD1; 32]);
    let op_b = build_signed_transfer(sk, &state, vec![2; 8], 2, b"ERA".to_vec(), vec![0xD2; 32]);

    match (
        crate::compat_shim::machine_execute_transition(&mut machine_a, op_a),
        crate::compat_shim::machine_execute_transition(&mut machine_b, op_b),
    ) {
        (Ok(state_a), Ok(state_b)) => {
            if state_a.prev_state_hash != prev_hash || state_b.prev_state_hash != prev_hash {
                failures.push("fork children did not point to the shared parent".into());
            }
            if state_a.hash == state_b.hash {
                failures.push("different operations produced the same child hash".into());
            }
        }
        (Err(e), _) | (_, Err(e)) => failures.push(format!("fork replay failed: {e}")),
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
        let (mut manager, local_kp, remote_device_id) = match build_bilateral_trace_manager() {
            Ok(harness) => harness,
            Err(e) => return vec![e],
        };

        let expected_initial_tip = manager
            .initial_relationship_tip_for(&remote_device_id)
            .expect("initial relationship tip");

        let mut smt = dsm::merkle::sparse_merkle_tree::SparseMerkleTree::new(256);
        match manager
            .establish_relationship(&remote_device_id, &mut smt)
            .await
        {
            Ok(anchor) => {
                if anchor.chain_tip != expected_initial_tip {
                    failures
                        .push("establish_relationship produced an unexpected initial tip".into());
                }
            }
            Err(e) => failures.push(format!("establish_relationship failed: {e}")),
        }

        let first_op =
            build_signed_bilateral_transfer(&local_kp, remote_device_id, "trace-precommit-1", 0x01);
        let first_pre = match manager
            .prepare_offline_transfer(&remote_device_id, first_op.clone(), 500)
            .await
        {
            Ok(pre) => {
                if !manager.has_pending_commitment(&pre.bilateral_commitment_hash) {
                    failures.push("prepared bilateral precommitment was not marked pending".into());
                }
                match pre.verify() {
                    Ok(true) => {}
                    Ok(false) => {
                        failures.push("prepared bilateral precommitment did not verify".into())
                    }
                    Err(e) => failures.push(format!("precommitment verify errored: {e}")),
                }
                match pre.verify_local_signature(local_kp.public_key()) {
                    Ok(true) => {}
                    Ok(false) => {
                        failures.push("local signature on precommitment did not verify".into())
                    }
                    Err(e) => {
                        failures.push(format!("local precommit signature verify errored: {e}"))
                    }
                }
                if pre.local_chain_tip_at_creation != Some(expected_initial_tip) {
                    failures
                        .push("precommitment did not capture the expected parent chain tip".into());
                }
                pre
            }
            Err(e) => return vec![format!("prepare_offline_transfer failed: {e}")],
        };

        let mut smt = dsm::merkle::sparse_merkle_tree::SparseMerkleTree::new(256);
        let first_tip = match manager
            .finalize_offline_transfer(
                &remote_device_id,
                &first_pre.bilateral_commitment_hash,
                b"accept",
                &mut smt,
            )
            .await
        {
            Ok(result) => {
                if !result.completed_offline {
                    failures.push("offline finalize did not report completed_offline".into());
                }
                if result.relationship_anchor.chain_tip == expected_initial_tip {
                    failures
                        .push("offline finalize did not advance the relationship chain tip".into());
                }
                if manager.has_pending_commitment(&first_pre.bilateral_commitment_hash) {
                    failures.push("finalized bilateral precommitment remained pending".into());
                }
                if manager
                    .get_relationship(&remote_device_id)
                    .map(|anchor| anchor.chain_tip)
                    != Some(result.relationship_anchor.chain_tip)
                {
                    failures.push("manager relationship tip diverged from finalize result".into());
                }
                if manager
                    .get_contact(&remote_device_id)
                    .map(DsmVerifiedContact::has_verified_chain_tip)
                    != Some(true)
                {
                    failures.push("contact SMT proof was not updated after finalize".into());
                }
                match manager.verify_relationship_integrity(&remote_device_id) {
                    Ok(true) => {}
                    Ok(false) => {
                        failures.push("relationship integrity failed after finalize".into())
                    }
                    Err(e) => failures.push(format!("relationship integrity check errored: {e}")),
                }
                result.relationship_anchor.chain_tip
            }
            Err(e) => return vec![format!("finalize_offline_transfer failed: {e}")],
        };

        let second_op =
            build_signed_bilateral_transfer(&local_kp, remote_device_id, "trace-precommit-2", 0x02);
        let second_pre = match manager
            .prepare_offline_transfer(&remote_device_id, second_op.clone(), 500)
            .await
        {
            Ok(pre) => {
                if pre.local_chain_tip_at_creation != Some(first_tip) {
                    failures
                        .push("second precommitment captured the wrong parent chain tip".into());
                }
                pre
            }
            Err(e) => return vec![format!("second prepare_offline_transfer failed: {e}")],
        };

        let mut consumed_tip = *domain_hash(
            "DSM/trace-bilateral-parent-consumed",
            &second_pre.bilateral_commitment_hash,
        )
        .as_bytes();
        if consumed_tip == first_tip {
            consumed_tip[0] ^= 0xFF;
        }

        match manager.get_relationship(&remote_device_id) {
            Some(mut anchor) => {
                let mut smt_anchor = dsm::merkle::sparse_merkle_tree::SparseMerkleTree::new(256);
                match manager.commit_bilateral_smt_update(
                    &mut smt_anchor,
                    &remote_device_id,
                    &consumed_tip,
                ) {
                    Ok(replace_result) => {
                        if let Err(e) = manager.update_anchor_from_replace_public(
                            &remote_device_id,
                            &mut anchor,
                            consumed_tip,
                            &replace_result,
                        ) {
                            failures.push(format!(
                                "failed to advance relationship tip before stale finalize: {e}"
                            ));
                        }
                    }
                    Err(e) => failures.push(format!("commit_bilateral_smt_update failed: {e}")),
                }
            }
            None => failures.push("relationship disappeared before stale finalize check".into()),
        }

        match manager
            .finalize_offline_transfer(
                &remote_device_id,
                &second_pre.bilateral_commitment_hash,
                b"accept",
                &mut smt,
            )
            .await
        {
            Ok(_) => failures
                .push("stale bilateral precommitment finalized after parent consumption".into()),
            Err(e) => {
                let msg = format!("{e}");
                if !(msg.contains("Tripwire")
                    && (msg.contains("advanced since precommitment creation")
                        || msg.contains("parent hash already consumed")))
                {
                    failures.push(format!(
                        "stale finalize rejection message was unexpected: {msg}"
                    ));
                }
            }
        }

        if !manager.has_pending_commitment(&second_pre.bilateral_commitment_hash) {
            failures.push("rejected stale precommitment was removed from pending set".into());
        }

        if manager.get_chain_tip_for(&remote_device_id) != Some(consumed_tip) {
            failures.push("manager chain tip changed after stale finalize rejection".into());
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

fn trace_bilateral_precomputed_finalize_hash(
    _seed_bytes: &[u8; 32],
    _pk: &[u8],
    _sk: &[u8],
) -> ImplementationTraceResult {
    let start = Instant::now();
    let failures = run_async_trace(async move {
        let mut failures = Vec::new();
        let (mut manager, local_kp, remote_device_id) = match build_bilateral_trace_manager() {
            Ok(harness) => harness,
            Err(e) => return vec![e],
        };

        let mut smt = dsm::merkle::sparse_merkle_tree::SparseMerkleTree::new(256);
        if let Err(e) = manager
            .establish_relationship(&remote_device_id, &mut smt)
            .await
        {
            return vec![format!("establish_relationship failed: {e}")];
        }

        let operation = build_signed_bilateral_transfer(
            &local_kp,
            remote_device_id,
            "trace-precomputed-finalize",
            0x11,
        );
        let entropy = match manager.generate_entropy() {
            Ok(entropy) => entropy,
            Err(e) => return vec![format!("generate_entropy failed: {e}")],
        };
        let predicted_tip =
            match manager.peek_post_finalize_hash(&remote_device_id, &operation, &entropy) {
                Ok(tip) => tip,
                Err(e) => return vec![format!("peek_post_finalize_hash failed: {e}")],
            };

        let mut alternate_entropy = entropy;
        alternate_entropy[0] ^= 0xFF;
        match manager.peek_post_finalize_hash(&remote_device_id, &operation, &alternate_entropy) {
            Ok(alternate_tip) => {
                if alternate_tip == predicted_tip {
                    failures
                        .push("changing finalize entropy did not change the predicted tip".into());
                }
            }
            Err(e) => failures.push(format!("alternate peek_post_finalize_hash failed: {e}")),
        }

        let pre = match manager
            .prepare_offline_transfer(&remote_device_id, operation.clone(), 500)
            .await
        {
            Ok(pre) => pre,
            Err(e) => return vec![format!("prepare_offline_transfer failed: {e}")],
        };

        let mut smt = dsm::merkle::sparse_merkle_tree::SparseMerkleTree::new(256);
        let result = match manager
            .finalize_offline_transfer_with_entropy(
                &remote_device_id,
                &pre.bilateral_commitment_hash,
                b"accept",
                Some(entropy),
                &mut smt,
            )
            .await
        {
            Ok(result) => result,
            Err(e) => {
                return vec![format!(
                    "finalize_offline_transfer_with_entropy failed: {e}"
                )]
            }
        };

        if !result.completed_offline {
            failures.push("precomputed finalize did not report completed_offline".into());
        }
        if result.relationship_anchor.chain_tip != predicted_tip {
            failures.push("predicted post-finalize tip did not match actual finalized tip".into());
        }
        if manager.get_chain_tip_for(&remote_device_id) != Some(predicted_tip) {
            failures.push("manager did not persist the predicted finalized tip".into());
        }
        if manager.has_pending_commitment(&pre.bilateral_commitment_hash) {
            failures.push("precomputed finalize left the commitment pending".into());
        }
        if manager
            .get_contact(&remote_device_id)
            .map(DsmVerifiedContact::has_verified_chain_tip)
            != Some(true)
        {
            failures.push("contact SMT proof was not updated after precomputed finalize".into());
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

fn trace_djte_emission_happy_path(
    _seed_bytes: &[u8; 32],
    _pk: &[u8],
    _sk: &[u8],
) -> ImplementationTraceResult {
    let start = Instant::now();
    let mut failures = Vec::new();

    let (prev, next, jap, receipt) = build_djte_transition(10, 1);

    match verify_emission(&prev, &next, &jap, &receipt) {
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

    let initial = SourceDlvState::new(2, initial_supply);

    let jap_a = build_test_jap(0x7A, 0x09);
    let (after_first, receipt_a) = apply_djte_transition(&initial, &jap_a, emission_amount);
    match verify_emission(&initial, &after_first, &jap_a, &receipt_a) {
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

    let jap_b = build_test_jap(0x7B, 0x0A);
    let (after_second, receipt_b) = apply_djte_transition(&after_first, &jap_b, emission_amount);
    match verify_emission(&after_first, &after_second, &jap_b, &receipt_b) {
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

    match verify_emission(&prev, &next, &jap, &receipt) {
        Ok(true) => failures.push("verify_emission accepted a supply-underflow transition".into()),
        Ok(false) => {
            failures.push("verify_emission returned false instead of a concrete rejection".into())
        }
        Err(e) => {
            let msg = format!("{e}");
            if !msg.contains("Supply underflow") {
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
        let reference_state = create_test_state(&[0x51; 32], &creator_kp.public_key);

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
            &reference_state,
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
        let (vault_a, op_a) = match manager
            .finalize_vault(draft_a, &creator_signature_a, Some("ERA"), Some(5))
            .await
        {
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
            &reference_state,
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
        let (vault_b, op_b) = match manager
            .finalize_vault(draft_b, &creator_signature_b, None, None)
            .await
        {
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

        match op_a {
            Operation::DlvCreate {
                mode,
                locked_amount,
                token_id,
                ..
            } => {
                if mode != TransactionMode::Unilateral {
                    failures.push("vault create operation did not use unilateral mode".into());
                }
                if token_id.as_deref() != Some(b"ERA".as_slice()) {
                    failures.push("vault create operation lost the locked token id".into());
                }
                if locked_amount.as_ref().map(Balance::value) != Some(5) {
                    failures.push("vault create operation lost the locked amount".into());
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
    seed_bytes: &[u8; 32],
    pk: &[u8],
    sk: &[u8],
) -> ImplementationTraceResult {
    let start = Instant::now();
    let mut failures = Vec::new();
    let mut harness = build_token_harness(seed_bytes, pk);
    let transfers = [7u64, 13, 19];

    for (idx, amount) in transfers.iter().enumerate() {
        let sender_before = balance_for_key(&harness.state, &harness.sender_key);
        let recipient_before = balance_for_key(&harness.state, &harness.recipient_key);
        let op = build_signed_transfer(
            sk,
            &harness.state,
            vec![(idx as u8) + 3; 8],
            *amount,
            TRACE_TOKEN_ID.as_bytes().to_vec(),
            harness.recipient.clone(),
        );
        let new_entropy = compute_next_entropy(&harness.state, &op);

        match crate::compat_shim::manager_create_token_state_transition(
            &harness.state,
            op.clone(),
            new_entropy,
            None,
        ) {
            Ok(new_state) => {
                match verify_token_balance_consistency(&harness.state, &new_state, &op) {
                    Ok(true) => {}
                    Ok(false) => {
                        failures.push(format!("step {idx}: balance consistency returned false"))
                    }
                    Err(e) => {
                        failures.push(format!("step {idx}: consistency verifier errored: {e}"))
                    }
                }

                let sender_after = balance_for_key(&new_state, &harness.sender_key);
                let recipient_after = balance_for_key(&new_state, &harness.recipient_key);
                if sender_after != sender_before.saturating_sub(*amount) {
                    failures.push(format!("step {idx}: sender balance mismatch"));
                }
                if recipient_after != recipient_before + amount {
                    failures.push(format!("step {idx}: recipient balance mismatch"));
                }
                if sender_after + recipient_after != TRACE_INITIAL_BALANCE {
                    failures.push(format!("step {idx}: token conservation violated"));
                }
                harness.state = new_state;
            }
            Err(e) => failures.push(format!("step {idx}: token transition failed: {e}")),
        }
    }

    if balance_for_key(&harness.state, &harness.sender_key) != 61 {
        failures.push("final sender balance did not match expected trace value".into());
    }
    if balance_for_key(&harness.state, &harness.recipient_key) != 39 {
        failures.push("final recipient balance did not match expected trace value".into());
    }

    ImplementationTraceResult {
        trace_name: "token_manager_balance_replay".into(),
        steps: transfers.len() as u64,
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

fn trace_receipt_verifier_tripwire(
    _seed_bytes: &[u8; 32],
    _pk: &[u8],
    _sk: &[u8],
) -> ImplementationTraceResult {
    let start = Instant::now();
    let mut failures = Vec::new();

    let keypair_a =
        SignatureKeyPair::generate_from_entropy(b"implementation-trace-receipt-a").expect("kp a");

    let genesis = *domain_hash("DSM/trace-genesis", b"receipt").as_bytes();
    let devid_a = *domain_hash("DSM/trace-device", b"receipt-a").as_bytes();
    let devid_b = *domain_hash("DSM/trace-device", b"receipt-b").as_bytes();

    let device_tree = DeviceTree::new(vec![devid_a, devid_b]);
    let device_tree_root = device_tree.root();
    let dev_proof = device_tree
        .proof(&devid_a)
        .map(encode_device_tree_proof)
        .expect("device tree proof");

    let parent_tip = [0x41; 32];
    let child_tip_a = [0x42; 32];
    let child_tip_b = [0x43; 32];

    let receipt_a = build_signed_receipt(
        genesis,
        devid_a,
        devid_b,
        parent_tip,
        child_tip_a,
        dev_proof.clone(),
        &keypair_a,
        None,
    );
    let receipt_b = build_signed_receipt(
        genesis,
        devid_a,
        devid_b,
        parent_tip,
        child_tip_b,
        dev_proof,
        &keypair_a,
        None,
    );

    let ctx = ReceiptVerificationContext::new(
        dsm::types::receipt_types::DeviceTreeAcceptanceCommitment::from_root(device_tree_root),
        receipt_a.parent_root,
        keypair_a.public_key.clone(),
        Vec::new(),
    );
    let mut tracker = ParentConsumptionTracker::new();

    match verify_stitched_receipt(&receipt_a, &ctx, &mut tracker) {
        Ok(result) => {
            if !result.valid {
                failures.push(format!(
                    "valid receipt was rejected: {}",
                    result.reason.unwrap_or_else(|| "unknown reason".into())
                ));
            }
        }
        Err(e) => failures.push(format!("receipt verifier errored on valid receipt: {e}")),
    }

    match verify_stitched_receipt(&receipt_a, &ctx, &mut tracker) {
        Ok(result) => {
            if result.valid {
                failures.push("receipt replay was accepted by verifier".into());
            } else {
                let reason = result.reason.unwrap_or_default();
                if !(reason.contains("already consumed") || reason.contains("replay detected")) {
                    failures.push(format!(
                        "receipt replay rejection reason was unexpected: {reason}"
                    ));
                }
            }
        }
        Err(e) => failures.push(format!("receipt verifier errored on replay: {e}")),
    }

    match verify_stitched_receipt(&receipt_b, &ctx, &mut tracker) {
        Ok(result) => {
            if result.valid {
                failures.push("forked receipt was accepted by verifier".into());
            } else {
                let reason = result.reason.unwrap_or_default();
                if !(reason.contains("Fork detected") || reason.contains("conflicting children")) {
                    failures.push(format!("fork rejection reason was unexpected: {reason}"));
                }
            }
        }
        Err(e) => failures.push(format!("receipt verifier errored on fork attempt: {e}")),
    }

    if tracker.get_child(&parent_tip) != Some(&child_tip_a) {
        failures.push("receipt verifier tracker overwrote canonical child after fork".into());
    }

    if !tracker.is_consumed(&parent_tip) {
        failures.push("receipt verifier did not mark the parent as consumed".into());
    }

    ImplementationTraceResult {
        trace_name: "receipt_verifier_tripwire".into(),
        steps: 3,
        passed: failures.is_empty(),
        failures,
        duration_ms: start.elapsed().as_secs_f64() * 1000.0,
    }
}

fn trace_token_manager_overspend_rejection(
    seed_bytes: &[u8; 32],
    pk: &[u8],
    sk: &[u8],
) -> ImplementationTraceResult {
    let start = Instant::now();
    let mut failures = Vec::new();
    let harness = build_token_harness(seed_bytes, pk);
    let sender_before = balance_for_key(&harness.state, &harness.sender_key);
    let recipient_before = balance_for_key(&harness.state, &harness.recipient_key);

    let op = build_signed_transfer(
        sk,
        &harness.state,
        vec![0xEE; 8],
        sender_before + 1,
        TRACE_TOKEN_ID.as_bytes().to_vec(),
        harness.recipient.clone(),
    );
    let new_entropy = compute_next_entropy(&harness.state, &op);

    if crate::compat_shim::manager_create_token_state_transition(
        &harness.state, op, new_entropy, None,
    )
    .is_ok()
    {
        failures.push("overspend was accepted by token transition code".into());
    }

    let sender_after = balance_for_key(&harness.state, &harness.sender_key);
    let recipient_after = balance_for_key(&harness.state, &harness.recipient_key);
    if sender_after != sender_before || recipient_after != recipient_before {
        failures.push("balances changed after rejected overspend".into());
    }

    ImplementationTraceResult {
        trace_name: "token_manager_overspend_rejection".into(),
        steps: 1,
        passed: failures.is_empty(),
        failures,
        duration_ms: start.elapsed().as_secs_f64() * 1000.0,
    }
}

// ========================================================================
// OFFLINE FINALITY TRACE (Paper Theorems 4.1, 4.2)
//
// Replays the full 3-phase bilateral commit through real Rust code:
//   1. Establish relationship
//   2. Prepare + finalize (tip advances, BilateralIrreversibility)
//   3. Second prepare + finalize (sequential commits work)
//   4. Tripwire test (stale precommitment rejected)
//   5. Conservation (relationship integrity preserved)
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
        let (mut manager, local_kp, remote_device_id) = match build_bilateral_trace_manager() {
            Ok(harness) => harness,
            Err(e) => return vec![e],
        };

        // Step 1: Establish relationship
        let initial_tip = manager
            .initial_relationship_tip_for(&remote_device_id)
            .expect("initial relationship tip");

        let mut smt = dsm::merkle::sparse_merkle_tree::SparseMerkleTree::new(256);
        match manager
            .establish_relationship(&remote_device_id, &mut smt)
            .await
        {
            Ok(anchor) => {
                if anchor.chain_tip != initial_tip {
                    failures.push("establish_relationship produced unexpected initial tip".into());
                }
            }
            Err(e) => return vec![format!("establish_relationship failed: {e}")],
        }

        // Step 2: First prepare + finalize (BilateralIrreversibility)
        let op1 =
            build_signed_bilateral_transfer(&local_kp, remote_device_id, "finality-trace-1", 0x01);
        let pre1 = match manager
            .prepare_offline_transfer(&remote_device_id, op1, 500)
            .await
        {
            Ok(pre) => {
                if !manager.has_pending_commitment(&pre.bilateral_commitment_hash) {
                    failures.push("first precommitment not marked pending".into());
                }
                if pre.local_chain_tip_at_creation != Some(initial_tip) {
                    failures.push("first precommitment did not capture initial tip".into());
                }
                pre
            }
            Err(e) => return vec![format!("first prepare failed: {e}")],
        };

        let mut smt = dsm::merkle::sparse_merkle_tree::SparseMerkleTree::new(256);
        let first_tip = match manager
            .finalize_offline_transfer(
                &remote_device_id,
                &pre1.bilateral_commitment_hash,
                b"accept-1",
                &mut smt,
            )
            .await
        {
            Ok(result) => {
                // BilateralIrreversibility: tip advanced past precommitment
                if result.relationship_anchor.chain_tip == initial_tip {
                    failures.push("finalize did not advance chain tip (irreversibility)".into());
                }
                // FullSettlement: completed offline
                if !result.completed_offline {
                    failures.push("finalize did not report completed_offline".into());
                }
                // Pending cleared
                if manager.has_pending_commitment(&pre1.bilateral_commitment_hash) {
                    failures.push("first precommitment remained pending after finalize".into());
                }
                // Relationship integrity
                match manager.verify_relationship_integrity(&remote_device_id) {
                    Ok(true) => {}
                    Ok(false) => {
                        failures.push("relationship integrity failed after first finalize".into())
                    }
                    Err(e) => failures.push(format!("relationship integrity errored: {e}")),
                }
                result.relationship_anchor.chain_tip
            }
            Err(e) => return vec![format!("first finalize failed: {e}")],
        };

        // Step 3: Second prepare + finalize (sequential commits, distinct tips)
        let op2 =
            build_signed_bilateral_transfer(&local_kp, remote_device_id, "finality-trace-2", 0x02);
        let pre2 = match manager
            .prepare_offline_transfer(&remote_device_id, op2, 500)
            .await
        {
            Ok(pre) => {
                if pre.local_chain_tip_at_creation != Some(first_tip) {
                    failures.push("second precommitment captured wrong parent tip".into());
                }
                pre
            }
            Err(e) => return vec![format!("second prepare failed: {e}")],
        };

        let second_tip = match manager
            .finalize_offline_transfer(
                &remote_device_id,
                &pre2.bilateral_commitment_hash,
                b"accept-2",
                &mut smt,
            )
            .await
        {
            Ok(result) => {
                // TripwireGuaranteesUniqueness: second tip differs from first
                if result.relationship_anchor.chain_tip == first_tip {
                    failures.push("second finalize produced same tip as first (uniqueness)".into());
                }
                if result.relationship_anchor.chain_tip == initial_tip {
                    failures.push("second finalize reverted to initial tip".into());
                }
                result.relationship_anchor.chain_tip
            }
            Err(e) => return vec![format!("second finalize failed: {e}")],
        };

        // Step 4: Tripwire test — prepare third, advance tip, attempt stale finalize
        let op3 =
            build_signed_bilateral_transfer(&local_kp, remote_device_id, "finality-trace-3", 0x03);
        let pre3 = match manager
            .prepare_offline_transfer(&remote_device_id, op3, 500)
            .await
        {
            Ok(pre) => pre,
            Err(e) => return vec![format!("third prepare failed: {e}")],
        };

        // Manually advance tip to simulate parent consumption
        let mut consumed_tip = *domain_hash(
            "DSM/trace-finality-parent-consumed",
            &pre3.bilateral_commitment_hash,
        )
        .as_bytes();
        if consumed_tip == second_tip {
            consumed_tip[0] ^= 0xFF;
        }

        match manager.get_relationship(&remote_device_id) {
            Some(mut anchor) => {
                let mut smt_anchor = dsm::merkle::sparse_merkle_tree::SparseMerkleTree::new(256);
                match manager.commit_bilateral_smt_update(
                    &mut smt_anchor,
                    &remote_device_id,
                    &consumed_tip,
                ) {
                    Ok(replace_result) => {
                        if let Err(e) = manager.update_anchor_from_replace_public(
                            &remote_device_id,
                            &mut anchor,
                            consumed_tip,
                            &replace_result,
                        ) {
                            failures.push(format!("failed to advance tip for tripwire test: {e}"));
                        }
                    }
                    Err(e) => failures.push(format!("commit_bilateral_smt_update failed: {e}")),
                }
            }
            None => failures.push("relationship disappeared before tripwire test".into()),
        }

        // Stale finalize MUST fail (TripwireGuaranteesUniqueness)
        match manager
            .finalize_offline_transfer(
                &remote_device_id,
                &pre3.bilateral_commitment_hash,
                b"accept-3",
                &mut smt,
            )
            .await
        {
            Ok(_) => failures.push("stale precommitment finalized after parent consumption".into()),
            Err(e) => {
                let msg = format!("{e}");
                if !(msg.contains("Tripwire")
                    && (msg.contains("advanced since precommitment creation")
                        || msg.contains("parent hash already consumed")))
                {
                    failures.push(format!("tripwire rejection message unexpected: {msg}"));
                }
            }
        }

        // Step 5: Conservation — tip didn't change after rejected stale finalize
        if manager.get_chain_tip_for(&remote_device_id) != Some(consumed_tip) {
            failures.push("chain tip changed after stale finalize rejection".into());
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
// Proves two independent bilateral managers on disjoint device pairs
// cannot affect each other's state.
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

        // Create two independent bilateral managers on disjoint device pairs
        let (mut manager1, kp1, remote1) = match build_bilateral_trace_manager() {
            Ok(h) => h,
            Err(e) => return vec![format!("manager1 setup: {e}")],
        };
        let (mut manager2, kp2, remote2) = match build_bilateral_trace_manager_pair2() {
            Ok(h) => h,
            Err(e) => return vec![format!("manager2 setup: {e}")],
        };

        // Step 1: Establish both relationships
        let mut smt1 = dsm::merkle::sparse_merkle_tree::SparseMerkleTree::new(256);
        let tip1_init = match manager1.establish_relationship(&remote1, &mut smt1).await {
            Ok(anchor) => anchor.chain_tip,
            Err(e) => return vec![format!("manager1 establish failed: {e}")],
        };
        let mut smt2 = dsm::merkle::sparse_merkle_tree::SparseMerkleTree::new(256);
        let tip2_init = match manager2.establish_relationship(&remote2, &mut smt2).await {
            Ok(anchor) => anchor.chain_tip,
            Err(e) => return vec![format!("manager2 establish failed: {e}")],
        };

        // Snapshot manager2 state before operating on manager1
        let m2_tip_before = manager2
            .get_chain_tip_for(&remote2)
            .expect("manager2 chain tip before");
        let m2_rel_before = manager2
            .get_relationship(&remote2)
            .expect("manager2 relationship before")
            .chain_tip;

        // Step 2: Operate on pair 1 only — prepare + finalize
        let op1 = build_signed_bilateral_transfer(&kp1, remote1, "ni-trace-pair1", 0x10);
        let pre1 = match manager1.prepare_offline_transfer(&remote1, op1, 500).await {
            Ok(pre) => pre,
            Err(e) => return vec![format!("manager1 prepare failed: {e}")],
        };
        let mut smt1 = dsm::merkle::sparse_merkle_tree::SparseMerkleTree::new(256);
        let _tip1_after = match manager1
            .finalize_offline_transfer(
                &remote1,
                &pre1.bilateral_commitment_hash,
                b"accept-ni-1",
                &mut smt1,
            )
            .await
        {
            Ok(result) => {
                if result.relationship_anchor.chain_tip == tip1_init {
                    failures.push("manager1 finalize did not advance tip".into());
                }
                result.relationship_anchor.chain_tip
            }
            Err(e) => return vec![format!("manager1 finalize failed: {e}")],
        };

        // Step 3: NonInterference — verify manager2 state is UNCHANGED
        let m2_tip_after_m1_op = manager2
            .get_chain_tip_for(&remote2)
            .expect("manager2 chain tip after m1 op");
        let m2_rel_after_m1_op = manager2
            .get_relationship(&remote2)
            .expect("manager2 relationship after m1 op")
            .chain_tip;

        if m2_tip_after_m1_op != m2_tip_before {
            failures.push(format!(
                "NonInterference violated: manager2 chain tip changed from {:?} to {:?} after manager1 operation",
                &m2_tip_before[..4], &m2_tip_after_m1_op[..4]
            ));
        }
        if m2_rel_after_m1_op != m2_rel_before {
            failures.push(
                "NonInterference violated: manager2 relationship tip changed after manager1 operation".into()
            );
        }

        // Snapshot manager1 state before operating on manager2
        let m1_tip_snapshot = manager1
            .get_chain_tip_for(&remote1)
            .expect("manager1 chain tip snapshot");
        let m1_rel_snapshot = manager1
            .get_relationship(&remote1)
            .expect("manager1 relationship snapshot")
            .chain_tip;

        // Step 4: Operate on pair 2
        let op2 = build_signed_bilateral_transfer(&kp2, remote2, "ni-trace-pair2", 0x20);
        let pre2 = match manager2.prepare_offline_transfer(&remote2, op2, 500).await {
            Ok(pre) => pre,
            Err(e) => return vec![format!("manager2 prepare failed: {e}")],
        };
        let mut smt2 = dsm::merkle::sparse_merkle_tree::SparseMerkleTree::new(256);
        match manager2
            .finalize_offline_transfer(
                &remote2,
                &pre2.bilateral_commitment_hash,
                b"accept-ni-2",
                &mut smt2,
            )
            .await
        {
            Ok(result) => {
                if result.relationship_anchor.chain_tip == tip2_init {
                    failures.push("manager2 finalize did not advance tip".into());
                }
            }
            Err(e) => return vec![format!("manager2 finalize failed: {e}")],
        }

        // Step 5: ZeroRefreshForInactive — manager1 state unchanged after manager2 op
        let m1_tip_after_m2_op = manager1
            .get_chain_tip_for(&remote1)
            .expect("manager1 chain tip after m2 op");
        let m1_rel_after_m2_op = manager1
            .get_relationship(&remote1)
            .expect("manager1 relationship after m2 op")
            .chain_tip;

        if m1_tip_after_m2_op != m1_tip_snapshot {
            failures.push(
                "ZeroRefreshForInactive violated: manager1 chain tip changed after manager2 operation".into()
            );
        }
        if m1_rel_after_m2_op != m1_rel_snapshot {
            failures.push(
                "ZeroRefreshForInactive violated: manager1 relationship tip changed after manager2 operation".into()
            );
        }

        // Step 6: PerPairConservation — each manager's relationship is internally consistent
        match manager1.verify_relationship_integrity(&remote1) {
            Ok(true) => {}
            Ok(false) => failures.push("manager1 relationship integrity failed".into()),
            Err(e) => failures.push(format!("manager1 integrity check errored: {e}")),
        }
        match manager2.verify_relationship_integrity(&remote2) {
            Ok(true) => {}
            Ok(false) => failures.push("manager2 relationship integrity failed".into()),
            Err(e) => failures.push(format!("manager2 integrity check errored: {e}")),
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

fn build_signed_transfer(
    sk: &[u8],
    current_state: &State,
    nonce: Vec<u8>,
    amount: u64,
    token_id: Vec<u8>,
    recipient: Vec<u8>,
) -> Operation {
    let mut op = Operation::Transfer {
        token_id,
        to_device_id: recipient.clone(),
        amount: Balance::from_state(amount, current_state.hash),
        mode: TransactionMode::Unilateral,
        nonce,
        verification: VerificationType::Standard,
        pre_commit: None,
        recipient,
        to: b"trace-recipient".to_vec(),
        message: "implementation trace".into(),
        signature: Vec::new(),
    };

    let signable = op.with_cleared_signature();
    let sig = sphincs_sign(sk, &signable.to_bytes()).expect("SPHINCS+ sign");
    if let Operation::Transfer { signature, .. } = &mut op {
        *signature = sig;
    }

    op
}

fn build_signed_bilateral_transfer(
    kp: &SignatureKeyPair,
    remote_device_id: [u8; 32],
    message: &str,
    nonce: u8,
) -> Operation {
    let mut op = Operation::Transfer {
        token_id: b"ERA".to_vec(),
        to_device_id: remote_device_id.to_vec(),
        amount: Balance::from_state(1, [0u8; 32]),
        mode: TransactionMode::Bilateral,
        nonce: vec![nonce; 8],
        verification: VerificationType::Standard,
        pre_commit: None,
        recipient: remote_device_id.to_vec(),
        to: b"trace-bilateral-recipient".to_vec(),
        message: message.into(),
        signature: Vec::new(),
    };

    let sig = kp.sign(&op.to_bytes()).expect("bilateral trace sign");
    if let Operation::Transfer { signature, .. } = &mut op {
        *signature = sig;
    }

    op
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

fn build_bilateral_trace_manager(
) -> Result<(BilateralTransactionManager, SignatureKeyPair, [u8; 32]), String> {
    dsm::utils::deterministic_time::reset_for_tests();

    let local_device_id = [0x21; 32];
    let local_genesis_hash = [0x22; 32];
    let remote_device_id = [0x31; 32];
    let remote_genesis_hash = [0x32; 32];

    let local_entropy = [local_device_id.as_slice(), local_genesis_hash.as_slice()].concat();
    let remote_entropy = [remote_device_id.as_slice(), remote_genesis_hash.as_slice()].concat();

    let local_kp = SignatureKeyPair::generate_from_entropy(&local_entropy)
        .map_err(|e| format!("local bilateral keypair: {e}"))?;
    let remote_kp = SignatureKeyPair::generate_from_entropy(&remote_entropy)
        .map_err(|e| format!("remote bilateral keypair: {e}"))?;

    let mut manager = BilateralTransactionManager::new(
        DsmContactManager::new(local_device_id, vec![]),
        local_kp.clone(),
        local_device_id,
        local_genesis_hash,
    );

    let contact = DsmVerifiedContact {
        alias: "trace-remote".into(),
        device_id: remote_device_id,
        genesis_hash: remote_genesis_hash,
        public_key: remote_kp.public_key().to_vec(),
        genesis_material: vec![0x42; 64],
        chain_tip: None,
        chain_tip_smt_proof: None,
        genesis_verified_online: true,
        verified_at_commit_height: 1,
        added_at_commit_height: 1,
        last_updated_commit_height: 1,
        verifying_storage_nodes: vec![],
        ble_address: None,
    };

    manager
        .add_verified_contact(contact)
        .map_err(|e| format!("failed to add bilateral trace contact: {e}"))?;

    Ok((manager, local_kp, remote_device_id))
}

/// Build a second bilateral manager on a DISJOINT device pair.
/// Pair 1 uses devices [0x21..] <-> [0x31..], pair 2 uses [0x41..] <-> [0x51..].
/// The two managers share no state — this is the non-interference property.
fn build_bilateral_trace_manager_pair2(
) -> Result<(BilateralTransactionManager, SignatureKeyPair, [u8; 32]), String> {
    dsm::utils::deterministic_time::reset_for_tests();

    let local_device_id = [0x41; 32];
    let local_genesis_hash = [0x42; 32];
    let remote_device_id = [0x51; 32];
    let remote_genesis_hash = [0x52; 32];

    let local_entropy = [local_device_id.as_slice(), local_genesis_hash.as_slice()].concat();
    let remote_entropy = [remote_device_id.as_slice(), remote_genesis_hash.as_slice()].concat();

    let local_kp = SignatureKeyPair::generate_from_entropy(&local_entropy)
        .map_err(|e| format!("pair2 local keypair: {e}"))?;
    let remote_kp = SignatureKeyPair::generate_from_entropy(&remote_entropy)
        .map_err(|e| format!("pair2 remote keypair: {e}"))?;

    let mut manager = BilateralTransactionManager::new(
        DsmContactManager::new(local_device_id, vec![]),
        local_kp.clone(),
        local_device_id,
        local_genesis_hash,
    );

    let contact = DsmVerifiedContact {
        alias: "trace-remote-pair2".into(),
        device_id: remote_device_id,
        genesis_hash: remote_genesis_hash,
        public_key: remote_kp.public_key().to_vec(),
        genesis_material: vec![0x43; 64],
        chain_tip: None,
        chain_tip_smt_proof: None,
        genesis_verified_online: true,
        verified_at_commit_height: 1,
        added_at_commit_height: 1,
        last_updated_commit_height: 1,
        verifying_storage_nodes: vec![],
        ble_address: None,
    };

    manager
        .add_verified_contact(contact)
        .map_err(|e| format!("failed to add pair2 contact: {e}"))?;

    Ok((manager, local_kp, remote_device_id))
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
    let jap = JoinActivationProof {
        id: [id_byte; 32],
        gate_proof: vec![id_byte, id_byte.wrapping_add(1), id_byte.wrapping_add(2)],
        nonce: [nonce_byte; 32],
    };
    jap
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
    let expected_winner_leaf = domain_hash_bytes("DJTE.ACTIVE", &jap.id);
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
    next.spent_smt.mark_spent(jap_hash);

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
    domain_hash_bytes("DJTE.SHARDS.ROOT", &buf)
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
    domain_hash_bytes("DJTE.DLV.TIP", &buf)
}

fn create_test_state(seed_bytes: &[u8; 32], pk: &[u8]) -> State {
    let device_id: [u8; 32] = *domain_hash("DSM/test-device", seed_bytes).as_bytes();
    let device_info = DeviceInfo::new(device_id, pk.to_vec());
    let mut state = State::new_genesis(*seed_bytes, device_info);
    if let Ok(hash) = state.hash() {
        state.hash = hash;
    }
    state
}
fn builtin_balance_key(owner_pk: &[u8], token_id: &str) -> String {
    let policy_commit = dsm::core::token::builtin_policy_commit_for_token(token_id)
        .expect("builtin policy commit missing for implementation trace token");
    dsm::core::token::derive_canonical_balance_key(&policy_commit, owner_pk, token_id)
}

fn build_signed_receipt(
    genesis: [u8; 32],
    devid_a: [u8; 32],
    devid_b: [u8; 32],
    parent_tip: [u8; 32],
    child_tip: [u8; 32],
    dev_proof: Vec<u8>,
    keypair_a: &SignatureKeyPair,
    keypair_b: Option<&SignatureKeyPair>,
) -> StitchedReceiptV2 {
    let smt_key = compute_smt_key(&devid_a, &devid_b);
    let parent_root = hash_smt_leaf(&parent_tip);
    let child_root = hash_smt_leaf(&child_tip);

    let mut receipt = StitchedReceiptV2::new(
        genesis,
        devid_a,
        devid_b,
        parent_tip,
        child_tip,
        parent_root,
        child_root,
        encode_single_leaf_smt_proof(smt_key, parent_tip),
        encode_single_leaf_smt_proof(smt_key, child_tip),
        dev_proof,
    );
    receipt.set_rel_replace_witness(0u32.to_le_bytes().to_vec());

    let commitment = receipt.compute_commitment().expect("receipt commitment");
    receipt.add_sig_a(keypair_a.sign(&commitment).expect("sig a"));
    if let Some(keypair_b) = keypair_b {
        receipt.add_sig_b(keypair_b.sign(&commitment).expect("sig b"));
    }
    receipt
}

fn compute_next_entropy(current_state: &State, operation: &Operation) -> Vec<u8> {
    let op_bytes = operation.to_bytes();
    let next_state_number = crate::compat_shim::state_number(&current_state) + 1;
    let mut hasher = dsm_domain_hasher("DSM/state-entropy");
    hasher.update(&current_state.entropy);
    hasher.update(&op_bytes);
    hasher.update(&next_state_number.to_le_bytes());
    hasher.finalize().as_bytes().to_vec()
}

fn encode_single_leaf_smt_proof(rel_key: [u8; 32], tip: [u8; 32]) -> Vec<u8> {
    pb::SmtProof {
        key: rel_key.to_vec(),
        v_path: Some(pb::smt_proof::VPath::ExistingLeaf(pb::SmtPathLeaf {
            key: rel_key.to_vec(),
            value: tip.to_vec(),
        })),
        siblings: Vec::new(),
    }
    .encode_to_vec()
}

fn encode_device_tree_proof(proof: DevTreeProof) -> Vec<u8> {
    let packed_len = proof.path_bits.len().div_ceil(8);
    let mut packed_bits = vec![0u8; packed_len];
    for (idx, bit) in proof.path_bits.iter().enumerate() {
        if *bit {
            packed_bits[idx / 8] |= 1 << (idx % 8);
        }
    }

    pb::DeviceTreeProof {
        siblings: proof.siblings.iter().map(|s| s.to_vec()).collect(),
        leaf_to_root: proof.leaf_to_root,
        path_bits_len: proof.path_bits.len() as u32,
        path_bits: packed_bits,
    }
    .encode_to_vec()
}

fn build_token_harness(seed_bytes: &[u8; 32], pk: &[u8]) -> TokenTraceHarness {
    let mut policy = PolicyFile::new("Implementation Trace Token", "1.0.0", "vertical-validation");
    policy.add_metadata("token_type", "validation");
    policy.add_metadata("scope", "implementation-trace");
    let policy_anchor = policy.generate_anchor().expect("trace policy anchor");
    let manager = TokenStateManager::new();
    manager.register_token_policy_anchor(TRACE_TOKEN_ID, policy_anchor.0);

    let mut state = create_test_state(seed_bytes, pk);
    let recipient = vec![0xDD; 32];
    let sender_key = manager
        .make_balance_key(pk, TRACE_TOKEN_ID)
        .expect("sender balance key");
    let recipient_key = manager
        .make_balance_key(&recipient, TRACE_TOKEN_ID)
        .expect("recipient balance key");

    state.token_balances.insert(
        sender_key.clone(),
        Balance::from_state(TRACE_INITIAL_BALANCE, state.hash),
    );
    state.token_balances.insert(
        recipient_key.clone(),
        Balance::from_state(0, state.hash),
    );

    TokenTraceHarness {
        manager,
        state,
        recipient,
        sender_key,
        recipient_key,
    }
}

fn balance_for_key(state: &State, key: &str) -> u64 {
    state
        .token_balances
        .get(key)
        .map(Balance::value)
        .unwrap_or(0)
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
}
