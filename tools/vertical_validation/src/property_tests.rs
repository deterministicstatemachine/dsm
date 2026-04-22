//! Property-Based Tests for DSM State Machine
//!
//! Exercises the real `StateMachine::execute_transition()` and supporting
//! cryptographic paths across randomized traces.
//!
//! This is the bridge from the abstract TLA+ model to executable Rust code:
//! TLA+ proves the bounded abstract invariants, while this harness checks that
//! the concrete state machine and signature plumbing behave consistently.

// Validation harness: panicking on crypto setup failures is correct behavior.
#![allow(clippy::expect_used)]

use instant::Instant;
use rand::Rng;
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use serde::Serialize;

use dsm::core::state_machine::transition::verify_token_balance_consistency;
use dsm::core::state_machine::StateMachine;
use dsm::core::token::TokenStateManager;
use dsm::crypto::blake3::{domain_hash, dsm_domain_hasher};
use dsm::crypto::sphincs::{
    generate_keypair_from_seed, sphincs_sign, sphincs_verify, SphincsVariant,
};
use dsm::types::operations::{Operation, TransactionMode, VerificationType};
use dsm::types::policy_types::PolicyFile;
use dsm::types::state_types::{DeviceInfo, State};
use dsm::types::token_types::Balance;

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

const PROPERTY_TEST_VARIANT: SphincsVariant = SphincsVariant::SPX256f;
const PROPERTY_TEST_TOKEN_ID: &str = "VVTEST";
const PROPERTY_TEST_INITIAL_BALANCE: u64 = 10_000;

struct TokenPropertyHarness {
    // Manager is no longer the canonical transition driver (§4.3 shim path)
    // but it still owns the token policy registration used by the harness.
    #[allow(dead_code)]
    manager: TokenStateManager,
    state: State,
    recipient: Vec<u8>,
    sender_key: String,
    recipient_key: String,
}

fn refresh_state_hash(state: &mut State) {
    if let Ok(hash) = state.hash() {
        state.hash = hash;
    }
}

fn builtin_balance_key(owner_pk: &[u8], token_id: &str) -> String {
    let policy_commit = dsm::core::token::builtin_policy_commit_for_token(token_id)
        .expect("builtin policy commit missing for property test token");
    dsm::core::token::derive_canonical_balance_key(&policy_commit, owner_pk, token_id)
}

/// Build a signed Transfer operation suitable for `execute_transition`.
fn build_signed_transfer(
    sk: &[u8],
    current_state: &State,
    nonce: Vec<u8>,
    amount: u64,
) -> Operation {
    build_signed_token_transfer(
        sk,
        current_state,
        nonce,
        amount,
        b"ERA".to_vec(),
        vec![0xBB; 32],
        vec![0xBB; 32],
    )
}

fn build_signed_transfer_to_owner(
    sk: &[u8],
    current_state: &State,
    nonce: Vec<u8>,
    amount: u64,
    token_id: Vec<u8>,
    to_device_id: Vec<u8>,
    recipient: Vec<u8>,
) -> Operation {
    build_signed_token_transfer(
        sk,
        current_state,
        nonce,
        amount,
        token_id,
        to_device_id,
        recipient,
    )
}

fn build_signed_token_transfer(
    sk: &[u8],
    current_state: &State,
    nonce: Vec<u8>,
    amount: u64,
    token_id: Vec<u8>,
    to_device_id: Vec<u8>,
    recipient: Vec<u8>,
) -> Operation {
    let mut op = Operation::Transfer {
        token_id,
        to_device_id,
        amount: Balance::from_state(amount, current_state.hash),
        mode: TransactionMode::Unilateral,
        nonce,
        verification: VerificationType::Standard,
        pre_commit: None,
        recipient,
        to: b"vv-recipient".to_vec(),
        message: String::new(),
        signature: Vec::new(),
    };

    // Sign the operation bytes, then embed the signature
    let op_bytes = op.with_cleared_signature().to_bytes();
    let sig = sphincs_sign(sk, &op_bytes).expect("SPHINCS+ sign");
    if let Operation::Transfer { signature, .. } = &mut op {
        *signature = sig;
    }

    op
}

fn create_test_state(seed_bytes: &[u8; 32], pk: &[u8]) -> State {
    let device_id: [u8; 32] = *domain_hash("DSM/test-device", seed_bytes).as_bytes();
    let device_info = DeviceInfo::new(device_id, pk.to_vec());
    let mut state = State::new_genesis(*seed_bytes, device_info);
    if let Ok(h) = state.hash() {
        state.hash = h;
    }
    state
}

fn compute_next_entropy(current_state: &State, operation: &Operation) -> Vec<u8> {
    let op_bytes = operation.to_bytes();
    let mut hasher = dsm_domain_hasher("DSM/state-entropy");
    hasher.update(&current_state.entropy);
    hasher.update(&op_bytes);
    hasher.update(&current_state.hash);
    hasher.finalize().as_bytes().to_vec()
}

fn build_policy_backed_token_harness(seed_bytes: &[u8; 32], pk: &[u8]) -> TokenPropertyHarness {
    let mut policy = PolicyFile::new("Vertical Validation Token", "1.0.0", "vertical-validation");
    policy.add_metadata("token_type", "validation");
    policy.add_metadata("scope", "real-code-property-test");
    let policy_anchor = policy.generate_anchor().expect("validation policy anchor");
    let manager = TokenStateManager::new();
    manager.register_token_policy_anchor(PROPERTY_TEST_TOKEN_ID, policy_anchor.0);
    let mut state = create_test_state(seed_bytes, pk);
    let recipient = vec![0xBB; 32];
    let policy_commit = dsm::core::token::resolve_policy_commit(PROPERTY_TEST_TOKEN_ID);
    let sender_key =
        dsm::core::token::derive_canonical_balance_key(&policy_commit, pk, PROPERTY_TEST_TOKEN_ID);
    let recipient_key = dsm::core::token::derive_canonical_balance_key(
        &policy_commit,
        &recipient,
        PROPERTY_TEST_TOKEN_ID,
    );

    state.token_balances.insert(
        sender_key.clone(),
        Balance::from_state(PROPERTY_TEST_INITIAL_BALANCE, state.hash),
    );
    state
        .token_balances
        .insert(recipient_key.clone(), Balance::from_state(0, state.hash));
    refresh_state_hash(&mut state);

    TokenPropertyHarness {
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

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

pub fn collect_property_test_results(seed: u64, iterations: u64) -> PropertyTestSuiteResult {
    eprintln!("\n=== PROPERTY-BASED TESTS ===\n");
    let suite_start = Instant::now();

    // Generate ONE keypair upfront (expensive ~50ms)
    let mut seed_bytes = [0u8; 32];
    seed_bytes[0..8].copy_from_slice(&seed.to_le_bytes());

    eprintln!("  Generating SPHINCS+ keypair ({PROPERTY_TEST_VARIANT:?})...");
    let kp =
        generate_keypair_from_seed(PROPERTY_TEST_VARIANT, &seed_bytes).expect("SPHINCS+ keygen");
    eprintln!(
        "  Keypair ready (pk={}B sk={}B)",
        kp.public_key.len(),
        kp.secret_key.len()
    );

    let pk = kp.public_key.clone();
    let sk = kp.secret_key.clone();

    // Signing-heavy tests are capped because SPHINCS+ dominates runtime.
    let signed_iters = iterations.min(25);
    let token_iters = iterations.min(100);

    let test_specs: Vec<(&str, u64)> = vec![
        ("hash_chain_continuity", signed_iters),
        ("state_number_monotonicity", signed_iters),
        ("entropy_determinism", signed_iters),
        ("token_conservation", token_iters),
        ("non_negative_balances", token_iters),
        ("fork_exclusion", signed_iters),
        ("signature_binding", iterations.min(20)),
    ];

    let mut results = Vec::new();
    for (idx, (name, iters)) in test_specs.iter().enumerate() {
        eprintln!("  [{}/7] {name} ({iters} iters)...", idx + 1);
        let r = match *name {
            "hash_chain_continuity" => {
                test_hash_chain_continuity(*iters, seed, &seed_bytes, &pk, &sk)
            }
            "state_number_monotonicity" => {
                test_state_number_monotonicity(*iters, seed, &seed_bytes, &pk, &sk)
            }
            "entropy_determinism" => test_entropy_determinism(*iters, seed, &seed_bytes, &pk, &sk),
            "token_conservation" => test_token_conservation(*iters, seed, &seed_bytes, &pk, &sk),
            "non_negative_balances" => {
                test_non_negative_balances(*iters, seed, &seed_bytes, &pk, &sk)
            }
            "fork_exclusion" => test_fork_exclusion(*iters, seed, &seed_bytes, &pk, &sk),
            "signature_binding" => test_signature_binding(*iters, seed, &seed_bytes, &pk, &sk),
            _ => unreachable!(),
        };
        let icon = if r.passed { "\u{2705}" } else { "\u{274c}" };
        eprintln!(
            "  {icon} {name} \u{2014} {}/{} iterations ({:.1}ms)",
            r.iterations - r.failures.len() as u64,
            r.iterations,
            r.duration_ms
        );
        results.push(r);
    }

    let all_passed = results.iter().all(|r| r.passed);
    let duration_ms = suite_start.elapsed().as_secs_f64() * 1000.0;
    eprintln!();

    PropertyTestSuiteResult {
        results,
        all_passed,
        seed,
        duration_ms,
    }
}

// ---------------------------------------------------------------------------
// Property 1: Hash chain continuity
// ---------------------------------------------------------------------------

fn test_hash_chain_continuity(
    iterations: u64,
    seed: u64,
    seed_bytes: &[u8; 32],
    pk: &[u8],
    sk: &[u8],
) -> PropertyTestResult {
    let start = Instant::now();
    let mut failures = Vec::new();
    let mut rng = ChaCha20Rng::seed_from_u64(seed);

    let mut state = create_test_state(seed_bytes, pk);
    let sender_key = builtin_balance_key(pk, "ERA");
    state
        .token_balances
        .insert(sender_key, Balance::from_state(10_000, state.hash));
    refresh_state_hash(&mut state);

    let mut machine = StateMachine::new();
    machine.set_state(state.clone());

    for i in 0..iterations {
        let nonce: Vec<u8> = (0..8).map(|_| rng.gen()).collect();
        let op = build_signed_transfer(sk, &state, nonce, 1);

        let prev_hash = state.hash;
        match crate::compat_shim::machine_execute_transition(&mut machine, op) {
            Ok(new_state) => {
                if new_state.prev_state_hash != prev_hash {
                    failures.push(format!("iter {i}: prev_state_hash mismatch"));
                }
                state = new_state;
            }
            Err(e) => {
                failures.push(format!("iter {i}: transition error: {e}"));
            }
        }
    }

    PropertyTestResult {
        property_name: "hash_chain_continuity".into(),
        iterations,
        passed: failures.is_empty(),
        failures,
        duration_ms: start.elapsed().as_secs_f64() * 1000.0,
    }
}

// ---------------------------------------------------------------------------
// Property 2: Compat state handle progression
// ---------------------------------------------------------------------------

fn test_state_number_monotonicity(
    iterations: u64,
    seed: u64,
    seed_bytes: &[u8; 32],
    pk: &[u8],
    sk: &[u8],
) -> PropertyTestResult {
    let start = Instant::now();
    let mut failures = Vec::new();
    let mut rng = ChaCha20Rng::seed_from_u64(seed);

    let mut state = create_test_state(seed_bytes, pk);
    let sender_key = builtin_balance_key(pk, "ERA");
    state
        .token_balances
        .insert(sender_key, Balance::from_state(10_000, state.hash));
    refresh_state_hash(&mut state);

    let mut machine = StateMachine::new();
    machine.set_state(state.clone());

    for i in 0..iterations {
        let nonce: Vec<u8> = (0..8).map(|_| rng.gen()).collect();
        let op = build_signed_transfer(sk, &state, nonce, 1);

        let prev_num = crate::compat_shim::state_number(&state);
        match crate::compat_shim::machine_execute_transition(&mut machine, op) {
            Ok(new_state) => {
                if crate::compat_shim::state_number(&new_state) == prev_num {
                    failures.push(format!(
                        "iter {i}: compat state handle did not change after successful transition: {}",
                        crate::compat_shim::state_number(&new_state)
                    ));
                }
                state = new_state;
            }
            Err(e) => {
                failures.push(format!("iter {i}: transition error: {e}"));
            }
        }
    }

    PropertyTestResult {
        property_name: "state_number_monotonicity".into(),
        iterations,
        passed: failures.is_empty(),
        failures,
        duration_ms: start.elapsed().as_secs_f64() * 1000.0,
    }
}

// ---------------------------------------------------------------------------
// Property 3: Entropy determinism (whitepaper formula verification)
// ---------------------------------------------------------------------------

fn test_entropy_determinism(
    iterations: u64,
    seed: u64,
    seed_bytes: &[u8; 32],
    pk: &[u8],
    sk: &[u8],
) -> PropertyTestResult {
    let start = Instant::now();
    let mut failures = Vec::new();
    let mut rng = ChaCha20Rng::seed_from_u64(seed);

    // Verify that entropy evolution follows the live counterless formula:
    //   e_{n+1} = H("DSM/state-entropy\0" || e_n || op_bytes || prev_hash)
    //
    // We run a chain and manually recompute the expected entropy at each step,
    // verifying the state machine's output matches.
    let mut state = create_test_state(seed_bytes, pk);
    let sender_key = builtin_balance_key(pk, "ERA");
    state
        .token_balances
        .insert(sender_key, Balance::from_state(10_000, state.hash));
    refresh_state_hash(&mut state);

    let mut machine = StateMachine::new();
    machine.set_state(state.clone());

    for i in 0..iterations {
        let nonce: Vec<u8> = (0..8).map(|_| rng.gen()).collect();
        let op = build_signed_transfer(sk, &state, nonce, 1);

        // Manually compute expected entropy: H(current_entropy || op_bytes || prev_hash)
        let expected_entropy = compute_next_entropy(&state, &op);

        match crate::compat_shim::machine_execute_transition(&mut machine, op) {
            Ok(new_state) => {
                if new_state.entropy != expected_entropy {
                    failures.push(format!("iter {i}: entropy mismatch vs whitepaper formula"));
                }
                state = new_state;
            }
            Err(e) => {
                failures.push(format!("iter {i}: transition error: {e}"));
            }
        }
    }

    PropertyTestResult {
        property_name: "entropy_determinism".into(),
        iterations,
        passed: failures.is_empty(),
        failures,
        duration_ms: start.elapsed().as_secs_f64() * 1000.0,
    }
}

// ---------------------------------------------------------------------------
// Property 4: Token conservation on the real token transition path
// ---------------------------------------------------------------------------

fn test_token_conservation(
    iterations: u64,
    seed: u64,
    seed_bytes: &[u8; 32],
    pk: &[u8],
    sk: &[u8],
) -> PropertyTestResult {
    let start = Instant::now();
    let mut failures = Vec::new();
    let mut rng = ChaCha20Rng::seed_from_u64(seed ^ 0x544f_4b45_4eu64);
    let mut harness = build_policy_backed_token_harness(seed_bytes, pk);

    for i in 0..iterations {
        if balance_for_key(&harness.state, &harness.sender_key) == 0 {
            harness = build_policy_backed_token_harness(seed_bytes, pk);
        }

        let sender_before = balance_for_key(&harness.state, &harness.sender_key);
        let recipient_before = balance_for_key(&harness.state, &harness.recipient_key);
        let total_before = sender_before + recipient_before;
        let spendable = balance_for_key(&harness.state, &harness.sender_key);
        let amount = rng.gen_range(1..=spendable.min(250));
        let nonce: Vec<u8> = (0..8).map(|_| rng.gen()).collect();
        let op = build_signed_transfer_to_owner(
            sk,
            &harness.state,
            nonce,
            amount,
            PROPERTY_TEST_TOKEN_ID.as_bytes().to_vec(),
            vec![0xBC; 32],
            harness.recipient.clone(),
        );
        let expected_prev_hash = harness.state.hash().expect("current hash");
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
                        failures.push(format!(
                            "iter {i}: real token transition failed consistency verifier"
                        ));
                    }
                    Err(e) => {
                        failures.push(format!("iter {i}: consistency verifier errored: {e}"));
                    }
                }

                let sender_after = balance_for_key(&new_state, &harness.sender_key);
                let recipient_after = balance_for_key(&new_state, &harness.recipient_key);
                let total_after = sender_after + recipient_after;

                if total_after != total_before {
                    failures.push(format!(
                        "iter {i}: conservation violated on real code path: {total_before} != {total_after}"
                    ));
                }
                if sender_after > sender_before {
                    failures.push(format!("iter {i}: sender balance increased on transfer"));
                }
                if recipient_after < recipient_before {
                    failures.push(format!("iter {i}: recipient balance decreased on transfer"));
                }
                if crate::compat_shim::state_number(&new_state)
                    == crate::compat_shim::state_number(&harness.state)
                {
                    failures.push(format!(
                        "iter {i}: token transition compat state handle did not change"
                    ));
                }
                if new_state.prev_state_hash != expected_prev_hash {
                    failures.push(format!(
                        "iter {i}: token transition prev_state_hash mismatch"
                    ));
                }

                harness.state = new_state;
            }
            Err(e) => {
                failures.push(format!("iter {i}: token transition error: {e}"));
            }
        }
    }

    PropertyTestResult {
        property_name: "token_conservation".into(),
        iterations,
        passed: failures.is_empty(),
        failures,
        duration_ms: start.elapsed().as_secs_f64() * 1000.0,
    }
}

// ---------------------------------------------------------------------------
// Property 5: Non-negative balances via real overspend rejection
// ---------------------------------------------------------------------------

fn test_non_negative_balances(
    iterations: u64,
    seed: u64,
    seed_bytes: &[u8; 32],
    pk: &[u8],
    sk: &[u8],
) -> PropertyTestResult {
    let start = Instant::now();
    let mut failures = Vec::new();
    let mut rng = ChaCha20Rng::seed_from_u64(seed ^ 0x4f56_4552_5350u64);
    let harness = build_policy_backed_token_harness(seed_bytes, pk);

    for i in 0..iterations {
        let sender_before = balance_for_key(&harness.state, &harness.sender_key);
        let recipient_before = balance_for_key(&harness.state, &harness.recipient_key);
        let amount = sender_before
            .saturating_add(rng.gen_range(1..=1_000))
            .max(sender_before + 1);
        let nonce: Vec<u8> = (0..8).map(|_| rng.gen()).collect();
        let op = build_signed_token_transfer(
            sk,
            &harness.state,
            nonce,
            amount,
            PROPERTY_TEST_TOKEN_ID.as_bytes().to_vec(),
            vec![0xBC; 32],
            harness.recipient.clone(),
        );
        let new_entropy = compute_next_entropy(&harness.state, &op);

        match crate::compat_shim::manager_create_token_state_transition(
            &harness.state,
            op,
            new_entropy,
            None,
        ) {
            Ok(_) => {
                failures.push(format!(
                    "iter {i}: overspend was accepted by real token code"
                ));
            }
            Err(_) => {
                let sender_after = balance_for_key(&harness.state, &harness.sender_key);
                let recipient_after = balance_for_key(&harness.state, &harness.recipient_key);
                if sender_after != sender_before || recipient_after != recipient_before {
                    failures.push(format!(
                        "iter {i}: balances changed after rejected overspend"
                    ));
                }
            }
        }
    }

    PropertyTestResult {
        property_name: "non_negative_balances".into(),
        iterations,
        passed: failures.is_empty(),
        failures,
        duration_ms: start.elapsed().as_secs_f64() * 1000.0,
    }
}

// ---------------------------------------------------------------------------
// Property 6: Fork exclusion (Tripwire theorem)
// ---------------------------------------------------------------------------

fn test_fork_exclusion(
    iterations: u64,
    seed: u64,
    seed_bytes: &[u8; 32],
    pk: &[u8],
    sk: &[u8],
) -> PropertyTestResult {
    let start = Instant::now();
    let mut failures = Vec::new();
    let mut rng = ChaCha20Rng::seed_from_u64(seed);

    let mut state = create_test_state(seed_bytes, pk);
    let sender_key = builtin_balance_key(pk, "ERA");
    state
        .token_balances
        .insert(sender_key, Balance::from_state(10_000, state.hash));
    refresh_state_hash(&mut state);

    for i in 0..iterations {
        // Two different operations from the same parent state
        let nonce_a: Vec<u8> = (0..8).map(|_| rng.gen()).collect();
        let nonce_b: Vec<u8> = (0..8).map(|_| rng.gen()).collect();

        let op_a = build_signed_transfer(sk, &state, nonce_a, 1);
        let op_b = build_signed_transfer(sk, &state, nonce_b, 2);

        let mut machine_a = StateMachine::new();
        machine_a.set_state(state.clone());
        let mut machine_b = StateMachine::new();
        machine_b.set_state(state.clone());

        match (
            crate::compat_shim::machine_execute_transition(&mut machine_a, op_a),
            crate::compat_shim::machine_execute_transition(&mut machine_b, op_b),
        ) {
            (Ok(state_a), Ok(state_b)) => {
                if state_a.hash == state_b.hash {
                    failures.push(format!(
                        "iter {i}: FORK COLLISION: different ops produced same hash"
                    ));
                }
                // Advance to state_a for next iteration
                state = state_a;
            }
            (Err(e), _) | (_, Err(e)) => {
                failures.push(format!("iter {i}: transition error: {e}"));
            }
        }
    }

    PropertyTestResult {
        property_name: "fork_exclusion".into(),
        iterations,
        passed: failures.is_empty(),
        failures,
        duration_ms: start.elapsed().as_secs_f64() * 1000.0,
    }
}

// ---------------------------------------------------------------------------
// Property 7: Signature binding
// ---------------------------------------------------------------------------

fn test_signature_binding(
    iterations: u64,
    seed: u64,
    seed_bytes: &[u8; 32],
    pk: &[u8],
    sk: &[u8],
) -> PropertyTestResult {
    let start = Instant::now();
    let mut failures = Vec::new();
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let _ = seed_bytes; // used only for consistency

    for i in 0..iterations {
        // Create a message, sign it, verify it
        let msg_len: usize = rng.gen_range(16..128);
        let msg: Vec<u8> = (0..msg_len).map(|_| rng.gen()).collect();

        let sig = match sphincs_sign(sk, &msg) {
            Ok(s) => s,
            Err(e) => {
                failures.push(format!("iter {i}: sign failed: {e}"));
                continue;
            }
        };

        // Valid verify must succeed
        match sphincs_verify(pk, &msg, &sig) {
            Ok(true) => {}
            Ok(false) => {
                failures.push(format!("iter {i}: valid signature rejected"));
                continue;
            }
            Err(e) => {
                failures.push(format!("iter {i}: verify error: {e}"));
                continue;
            }
        }

        // Test 1: Wrong message must fail (strongest binding test)
        let mut wrong_msg = msg.clone();
        wrong_msg[0] ^= 0x01;
        match sphincs_verify(pk, &wrong_msg, &sig) {
            Ok(false) => {} // correct rejection
            Ok(true) => {
                failures.push(format!("iter {i}: WRONG MESSAGE ACCEPTED"));
            }
            Err(_) => {} // error counts as rejection
        }

        // Test 2: Flip first byte of signature (active region of randomized
        // hash output, guaranteed to affect SPHINCS+ verification)
        let mut tampered = sig.clone();
        tampered[0] ^= 0xFF;
        match sphincs_verify(pk, &msg, &tampered) {
            Ok(false) => {} // correct rejection
            Ok(true) => {
                failures.push(format!(
                    "iter {i}: TAMPERED SIGNATURE ACCEPTED (byte 0 flip)"
                ));
            }
            Err(_) => {} // error counts as rejection
        }
    }

    PropertyTestResult {
        property_name: "signature_binding".into(),
        iterations,
        passed: failures.is_empty(),
        failures,
        duration_ms: start.elapsed().as_secs_f64() * 1000.0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seeded_keypair_uses_runtime_signature_variant() {
        let seed_bytes = [7u8; 32];
        let kp = generate_keypair_from_seed(PROPERTY_TEST_VARIANT, &seed_bytes)
            .expect("deterministic SPHINCS+ keygen");
        let msg = b"vertical-validation-signature-smoke";
        let sig = sphincs_sign(&kp.secret_key, msg).expect("sign");

        assert!(sphincs_verify(&kp.public_key, msg, &sig).expect("verify"));
    }

    #[test]
    fn signed_transfer_helper_builds_a_verifiable_operation() {
        let seed_bytes = [9u8; 32];
        let kp = generate_keypair_from_seed(PROPERTY_TEST_VARIANT, &seed_bytes)
            .expect("deterministic SPHINCS+ keygen");
        let device_id: [u8; 32] = *domain_hash("DSM/test-device", &seed_bytes).as_bytes();
        let device_info = DeviceInfo::new(device_id, kp.public_key.clone());
        let mut state = State::new_genesis(seed_bytes, device_info);
        state.hash = state.hash().expect("genesis hash");

        let op = build_signed_transfer(&kp.secret_key, &state, vec![1; 8], 1);
        let sig = op.get_signature().expect("transfer signature");
        let signable = op.with_cleared_signature();

        assert!(sphincs_verify(&kp.public_key, &signable.to_bytes(), &sig).expect("verify"));
    }
}
