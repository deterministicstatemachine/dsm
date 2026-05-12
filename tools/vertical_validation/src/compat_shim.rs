//! Compatibility shims for the vertical-validation tool.
//!
//! Bridges the legacy `StateMachine::execute_transition` and
//! `TokenStateManager::create_token_state_transition` APIs (deleted per §4.3
//! counterless refactor) to the surviving `apply_transition` building block,
//! so the validation harness can keep exercising the same property-test
//! semantics without rewriting every assertion site.
//!
//! These wrappers are NOT canonical: production code goes through
//! `StateMachine::advance_relationship` (the spec-canonical §2.2 / §4.2
//! path). The shims here exist solely to keep TLA+ trace replay and
//! property tests building against the new lib API.

#![allow(dead_code)]

use anyhow::{anyhow, Result as AnyResult};
use dsm::core::state_machine::transition::{apply_transition, create_transition};
use dsm::core::state_machine::StateMachine;
use dsm::crypto::blake3::dsm_domain_hasher;
use dsm::types::error::DsmError;
use dsm::types::operations::Operation;
use dsm::types::state_types::State;

/// `state.state_number` shim. Returns 0 for genesis (zero prev_hash) and
/// otherwise a deterministic u64 derived from the state hash. The legacy
/// counter is gone (§4.3) — this provides a numeric handle for tests that
/// only care about distinguishing states, not about counter monotonicity.
pub fn state_number(state: &State) -> u64 {
    if state.prev_state_hash == [0u8; 32] {
        return 0;
    }
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&state.hash[..8]);
    u64::from_le_bytes(buf)
}

/// Compat shim for `StateMachine::execute_transition` (deleted).
///
/// Builds entropy via §11 eq.14 from the machine's current state, applies
/// the transition via the surviving `apply_transition` helper, and updates
/// the machine's current_state. Returns the new State.
pub fn machine_execute_transition(
    machine: &mut StateMachine,
    operation: Operation,
) -> Result<State, DsmError> {
    let current = machine
        .current_state()
        .ok_or_else(|| DsmError::state_machine("no current state for execute_transition shim"))?;

    // §11 eq.14 entropy
    let op_bytes = operation.to_bytes();
    let new_entropy = {
        let mut h = dsm_domain_hasher("DSM/state-entropy");
        h.update(&current.entropy);
        h.update(&op_bytes);
        h.update(&current.hash);
        *h.finalize().as_bytes()
    };

    let transition = create_transition(&current, operation, &new_entropy)?;
    let new_state = apply_transition(&current, &transition.operation, &new_entropy)?;
    machine.set_state(new_state.clone());
    Ok(new_state)
}

/// Compat shim for `TokenStateManager::create_token_state_transition` (deleted).
///
/// Drives the transition via `apply_transition` directly. Token balance updates
/// flow through the new `DeviceState::advance` path in production; the shim
/// exists only for property-test parity.
pub fn manager_create_token_state_transition(
    current_state: &State,
    operation: Operation,
    new_entropy: Vec<u8>,
    _encapsulated_entropy: Option<Vec<u8>>,
) -> AnyResult<State> {
    let transition = create_transition(current_state, operation, &new_entropy)
        .map_err(|e| anyhow!("compat shim create_transition failed: {e}"))?;
    apply_transition(current_state, &transition.operation, &new_entropy)
        .map_err(|e| anyhow!("compat shim apply_transition failed: {e}"))
}
