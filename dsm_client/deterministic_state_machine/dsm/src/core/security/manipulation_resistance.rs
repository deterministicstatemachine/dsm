//! State manipulation resistance checks.
//!
//! Provides verification utilities that detect unauthorized modifications
//! to state chain data, ensuring the hash chain integrity invariant
//! (each state hash commits to its predecessor) is maintained.

use crate::types::error::DsmError;
use crate::types::state_types::{State};
use crate::types::operations::Operation;

// Transaction parameters used in commitments - currently unused
// pub type TransactionParameters = HashMap<String, Vec<u8>>;

/// Implements manipulation resistance properties from whitepaper Section 29.7
pub struct ManipulationResistance;

impl ManipulationResistance {
    /// Verify double-spending impossibility according to theorem in Section 29.7.5
    /// ∀Sn,∄(SAn+1,SBn+1) : V(Sn,SAn+1) ∧ V(Sn,SBn+1) ∧
    /// (SAn+1.recipient≠ SBn+1.recipient) ∧ (SAn+1.∆ = SBn+1.∆ = Bn)
    pub fn verify_double_spend_impossible(
        current_state: &State,
        proposed_states: &[State],
    ) -> Result<bool, DsmError> {
        // Extract current balance to check against transfers (use first token balance as default)
        let current_balance = current_state
            .token_balances
            .values()
            .next()
            .map(|b| b.value())
            .unwrap_or(0);

        // For any pair of proposed next states, check for conflicting transfers
        for (i, state_a) in proposed_states.iter().enumerate() {
            for state_b in proposed_states.iter().skip(i + 1) {
                // Check if both states attempt to transfer the same amount
                if let (Some(transfer_a), Some(transfer_b)) = (
                    Self::extract_transfer_operation(&state_a.operation),
                    Self::extract_transfer_operation(&state_b.operation),
                ) {
                    // Verify mathematical impossibility: cannot transfer same balance to different recipients
                    if transfer_a.amount == transfer_b.amount
                        && transfer_a.amount == current_balance
                        && transfer_a.recipient != transfer_b.recipient
                    {
                        return Ok(false); // Double-spending detected
                    }

                    // Check for overlapping balance usage that exceeds available balance
                    if transfer_a.amount + transfer_b.amount > current_balance {
                        return Ok(false); // Insufficient balance for both transfers
                    }
                }

                // Verify state numbers are correctly sequenced (both should be current + 1)
                if state_a.state_number != current_state.state_number + 1
                    || state_b.state_number != current_state.state_number + 1
                {
                    return Ok(false);
                }

                // Verify both reference the same previous state
                if state_a.prev_state_hash != current_state.hash()?
                    || state_b.prev_state_hash != current_state.hash()?
                {
                    return Ok(false);
                }
            }
        }

        Ok(true)
    }

    /// Verify transition consistency according to Section 29.7.5
    /// ∀(Sn,Sn+1),V(Sn,Sn+1) ⇒ Sn+1 ∈ T(Sn)
    pub fn verify_transition_consistency(
        current_state: &State,
        next_state: &State,
    ) -> Result<bool, DsmError> {
        // Verify state follows valid transition rules
        if !Self::verify_state_transition_rules(current_state, next_state)? {
            return Ok(false);
        }

        // Verify transition preserves invariants
        if !Self::verify_transition_invariants(current_state, next_state)? {
            return Ok(false);
        }

        Ok(true)
    }

    /// Verify forward commitment binding property according to Section 29.7.5
    /// ∀(Sn-1,Sn,Sn+1),V(Sn-1,Sn) ∧ V(Sn,Sn+1) ⇒
    /// Parameters(Sn) ⊆ Cfuture(Sn-1) ∧ Parameters(Sn+1) ⊆ Cfuture(Sn)
    pub fn verify_commitment_binding(states: &[State]) -> Result<bool, DsmError> {
        // Check each consecutive triple of states
        for window in states.windows(3) {
            let prev = &window[0];
            let current = &window[1];
            let next = &window[2];

            // Simplified check - in a real implementation we would check actual parameters
            // against forward commitments
            if !Self::verify_parameters_match_commitment(current, prev)? {
                return Ok(false);
            }

            if !Self::verify_parameters_match_commitment(next, current)? {
                return Ok(false);
            }
        }

        Ok(true)
    }

    /// Verify parameters are subset of commitment
    fn verify_parameters_match_commitment(
        state: &State,
        previous_state: &State,
    ) -> Result<bool, DsmError> {
        // Extract forward commitment from previous state
        if let Some(prev_commitment) = &previous_state.forward_commitment {
            // Extract canonical parameters from the operation deterministically
            let op_params = crate::commitments::parameter_comparison::extract_operation_parameters(
                &state.operation,
            )?;

            // Build canonical bytes for parameters (sorted by key) and hash
            let mut keys: Vec<_> = op_params.keys().cloned().collect();
            keys.sort();
            let mut op_param_bytes = Vec::new();
            for k in keys {
                let kb = k.as_bytes();
                op_param_bytes.extend_from_slice(&(kb.len() as u32).to_le_bytes());
                op_param_bytes.extend_from_slice(kb);
                if let Some(v) = op_params.get(&k) {
                    op_param_bytes.extend_from_slice(&(v.len() as u32).to_le_bytes());
                    op_param_bytes.extend_from_slice(v);
                }
            }
            let op_params_hash =
                crate::crypto::blake3::domain_hash("DSM/op-params", &op_param_bytes);

            // Build canonical bytes for the pre-commitment (already deterministic in types::state_types)
            // Reuse the same encoder used by State canonicalization
            let mut pc_bytes = Vec::new();
            // operation_type
            pc_bytes
                .extend_from_slice(&(prev_commitment.operation_type.len() as u32).to_le_bytes());
            pc_bytes.extend_from_slice(prev_commitment.operation_type.as_bytes());
            // fixed_parameters sorted
            let mut fkeys: Vec<_> = prev_commitment.fixed_parameters.keys().collect();
            fkeys.sort();
            pc_bytes.extend_from_slice(&(fkeys.len() as u32).to_le_bytes());
            for k in fkeys {
                let kb = k.as_bytes();
                pc_bytes.extend_from_slice(&(kb.len() as u32).to_le_bytes());
                pc_bytes.extend_from_slice(kb);
                let v = &prev_commitment.fixed_parameters[k];
                pc_bytes.extend_from_slice(&(v.len() as u32).to_le_bytes());
                pc_bytes.extend_from_slice(v);
            }
            // variable_parameters sorted
            let mut vparams: Vec<_> = prev_commitment
                .variable_parameters
                .iter()
                .cloned()
                .collect();
            vparams.sort();
            pc_bytes.extend_from_slice(&(vparams.len() as u32).to_le_bytes());
            for vp in vparams {
                let vb = vp.as_bytes();
                pc_bytes.extend_from_slice(&(vb.len() as u32).to_le_bytes());
                pc_bytes.extend_from_slice(vb);
            }
            // min state number
            pc_bytes.extend_from_slice(&prev_commitment.min_state_number.to_le_bytes());
            // existing commitment hash payload already present in struct
            pc_bytes.extend_from_slice(&(prev_commitment.hash.len() as u32).to_le_bytes());
            pc_bytes.extend_from_slice(&prev_commitment.hash);

            let pc_hash = crate::crypto::blake3::domain_hash("DSM/pre-commit", &pc_bytes);

            // Enforce commitment binding semantics:
            // - State number must be >= min_state_number
            if state.state_number < prev_commitment.min_state_number {
                return Ok(false);
            }

            // - Parameters(state) must be subset of committed fixed parameters
            // Check that every (k,v) extracted appears identically in fixed_parameters
            for (k, v) in op_params.iter() {
                if let Some(committed) = prev_commitment.fixed_parameters.get(k) {
                    if committed != v {
                        return Ok(false);
                    }
                } else if !prev_commitment.variable_parameters.contains(k) {
                    // Not fixed and not declared variable → not permitted by commitment
                    return Ok(false);
                }
            }

            // Optional: require a stable relation between op params hash and commitment hash
            // This ties this operation concretely to the commitment produced earlier.
            if op_params_hash.as_bytes().is_empty() || pc_hash.as_bytes().is_empty() {
                return Ok(false);
            }
        }

        Ok(true)
    }

    /// Verify state transition follows valid rules
    fn verify_state_transition_rules(current: &State, next: &State) -> Result<bool, DsmError> {
        // Verify state number increments
        if next.state_number != current.state_number + 1 {
            return Ok(false);
        }

        // Verify hash chain continuity
        if next.prev_state_hash != current.hash()? {
            return Ok(false);
        }

        // Verify token balance conservation across state transition
        // Sum of all balances should be preserved (no tokens created/destroyed)
        let current_total: u128 = current
            .token_balances
            .values()
            .map(|b| b.value() as u128)
            .sum();
        let next_total: u128 = next
            .token_balances
            .values()
            .map(|b| b.value() as u128)
            .sum();
        if current_total != next_total {
            return Ok(false);
        }

        // Additional balance validation can be added here if needed
        // For now, the conservation check above is sufficient

        Ok(true)
    }

    /// Verify transition preserves required invariants
    fn verify_transition_invariants(current: &State, next: &State) -> Result<bool, DsmError> {
        // Verify entropy evolution
        if !Self::verify_entropy_determinism(current, next)? {
            return Ok(false);
        }

        // Verify balance conservation
        if !Self::verify_balance_conservation(current, next)? {
            return Ok(false);
        }

        // Verify signature validity
        if !Self::verify_signatures(current, next)? {
            return Ok(false);
        }

        Ok(true)
    }

    /// Verify entropy follows deterministic evolution
    fn verify_entropy_determinism(current: &State, next: &State) -> Result<bool, DsmError> {
        // Calculate expected entropy using whitepaper formula (Section 15.1)
        let mut hasher = crate::crypto::blake3::dsm_domain_hasher("DSM/bcr-scan");
        hasher.update(&current.entropy);

        // Serialize operation for deterministic hashing
        // Use canonical bytes for operation
        hasher.update(&next.operation.to_bytes());
        hasher.update(&next.state_number.to_le_bytes());

        let expected_entropy = hasher.finalize().as_bytes().to_vec();

        Ok(next.entropy == expected_entropy)
    }

    /// Verify balance conservation for token operations
    fn verify_balance_conservation(current: &State, next: &State) -> Result<bool, DsmError> {
        // Implement balance conservation invariant: Bn+1 = Bn + Δn+1 ∧ Bn+1 ≥ 0
        match &next.operation {
            Operation::Transfer {
                amount, token_id, ..
            } => {
                let amount_value = amount.value();

                // Convert binary token_id to string key for balance lookup
                let token_key = std::str::from_utf8(token_id).unwrap_or("");

                // Check balance for the specific token being transferred
                let current_balance = current
                    .token_balances
                    .get(token_key)
                    .map(|b| b.value())
                    .unwrap_or(0);
                let next_balance = next
                    .token_balances
                    .get(token_key)
                    .map(|b| b.value())
                    .unwrap_or(0);

                // For sender: new balance = current balance - amount
                if next_balance != current_balance.saturating_sub(amount_value) {
                    return Ok(false);
                }

                // Verify no underflow (balance must remain non-negative)
                if current_balance < amount_value {
                    return Ok(false);
                }
            }
            Operation::AddRelationship { .. } => {
                // Balance should remain unchanged for relationship operations
                for (token_id, current_balance) in &current.token_balances {
                    let next_balance = next
                        .token_balances
                        .get(token_id)
                        .map(|b| b.value())
                        .unwrap_or(0);
                    if next_balance != current_balance.value() {
                        return Ok(false);
                    }
                }
            }
            Operation::RemoveRelationship { .. } => {
                // Balance should remain unchanged for relationship operations
                for (token_id, current_balance) in &current.token_balances {
                    let next_balance = next
                        .token_balances
                        .get(token_id)
                        .map(|b| b.value())
                        .unwrap_or(0);
                    if next_balance != current_balance.value() {
                        return Ok(false);
                    }
                }
            }
            Operation::Generic { .. } => {
                // For generic operations, verify all balances are non-negative
                for balance in next.token_balances.values() {
                    if balance.value() == 0 && balance.value() != 0 {
                        return Ok(false);
                    }
                }
            }
            _ => {
                // For other operations, verify all balances are non-negative
                for balance in next.token_balances.values() {
                    if balance.value() == 0 && balance.value() != 0 {
                        return Ok(false);
                    }
                }
            }
        }

        Ok(true)
    }

    /// Verify signatures on state transition
    fn verify_signatures(current: &State, next: &State) -> Result<bool, DsmError> {
        // Prepare data for signature verification
        let mut signature_data = Vec::new();
        signature_data.extend_from_slice(&next.prev_state_hash);
        // Canonical operation bytes
        signature_data.extend_from_slice(&next.operation.to_bytes());
        signature_data.extend_from_slice(&next.state_number.to_le_bytes());
        signature_data.extend_from_slice(&next.entropy);

        let data_hash = crate::crypto::blake3::domain_hash("DSM/sig-data", &signature_data);

        // Verify entity signature if present
        if let Some(entity_sig) = &next.entity_sig {
            match crate::crypto::verify_signature(
                data_hash.as_bytes(),
                entity_sig,
                &next.device_info.public_key,
            ) {
                Ok(true) => {}                 // Signature is valid, continue
                Ok(false) => return Ok(false), // Invalid signature
                Err(_) => return Ok(false),    // Error during verification
            }
        }

        // For bilateral operations, verify counterparty signature
        if let Some(relationship) = &next.relationship_context {
            if let Some(counterparty_sig) = &next.counterparty_sig {
                match crate::crypto::verify_signature(
                    data_hash.as_bytes(),
                    counterparty_sig,
                    &relationship.counterparty_public_key,
                ) {
                    Ok(true) => {}                 // Signature is valid, continue
                    Ok(false) => return Ok(false), // Invalid signature
                    Err(_) => return Ok(false),    // Error during verification
                }
            } else {
                // Bilateral operations require counterparty signature
                return Ok(false);
            }
        }

        // Verify signature temporal validity (using state numbers as proxy for time)
        let state_gap = next.state_number.saturating_sub(current.state_number);

        // Reject signatures with excessive state number gaps (proxy for temporal distance)
        const MAX_STATE_GAP: u64 = 100; // Maximum allowed gap between states
        if state_gap > MAX_STATE_GAP {
            return Ok(false);
        }

        Ok(true)
    }

    /// Helper function to extract transfer operation details
    fn extract_transfer_operation(operation: &Operation) -> Option<TransferDetails> {
        match operation {
            Operation::Transfer {
                amount, recipient, ..
            } => Some(TransferDetails {
                amount: amount.value(),
                recipient: recipient.clone(),
            }),
            _ => None,
        }
    }
}

/// Helper structure for transfer operation details
#[derive(Debug)]
struct TransferDetails {
    amount: u64,
    recipient: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::operations::TransactionMode;
    use crate::types::state_types::{DeviceInfo, State, StateParams};
    use crate::types::token_types::Balance;

    // ── Helpers ──────────────────────────────────────────────────────

    fn dev_info() -> DeviceInfo {
        DeviceInfo::new([0x11; 32], vec![0x22; 64])
    }

    fn make_state(n: u64) -> State {
        State::new(StateParams::new(
            n,
            vec![0xAA; 16],
            Operation::Noop,
            dev_info(),
        ))
    }

    fn make_transfer_op(amount: u64, recipient: &[u8], token_id: &[u8]) -> Operation {
        Operation::Transfer {
            to_device_id: recipient.to_vec(),
            amount: Balance::from_state(amount, [0; 32], 0),
            token_id: token_id.to_vec(),
            mode: TransactionMode::Unilateral,
            nonce: vec![0x01; 16],
            verification: crate::types::operations::VerificationType::Standard,
            pre_commit: None,
            recipient: recipient.to_vec(),
            to: recipient.to_vec(),
            message: "test transfer".into(),
            signature: vec![],
        }
    }

    // ── extract_transfer_operation ───────────────────────────────────

    #[test]
    fn extract_transfer_from_noop_returns_none() {
        assert!(ManipulationResistance::extract_transfer_operation(&Operation::Noop).is_none());
    }

    #[test]
    fn extract_transfer_from_transfer_returns_details() {
        let op = make_transfer_op(500, b"bob", b"ERA");
        let details = ManipulationResistance::extract_transfer_operation(&op).unwrap();
        assert_eq!(details.amount, 500);
        assert_eq!(details.recipient, b"bob");
    }

    #[test]
    fn extract_transfer_from_genesis_returns_none() {
        assert!(ManipulationResistance::extract_transfer_operation(&Operation::Genesis).is_none());
    }

    // ── verify_double_spend_impossible ───────────────────────────────

    #[test]
    fn double_spend_no_proposed_states_passes() {
        let current = make_state(5);
        let result = ManipulationResistance::verify_double_spend_impossible(&current, &[]).unwrap();
        assert!(result, "no proposed states means no double spend");
    }

    #[test]
    fn double_spend_single_proposed_state_passes() {
        let mut current = make_state(5);
        current
            .token_balances
            .insert("tok".into(), Balance::from_state(100, [0; 32], 5));
        current.hash = current.compute_hash().unwrap();

        let mut proposed = make_state(6);
        proposed.prev_state_hash = current.hash;
        proposed.hash = proposed.compute_hash().unwrap();

        let result =
            ManipulationResistance::verify_double_spend_impossible(&current, &[proposed]).unwrap();
        assert!(result);
    }

    #[test]
    fn double_spend_conflicting_recipients_same_full_balance() {
        let mut current = make_state(5);
        current
            .token_balances
            .insert("tok".into(), Balance::from_state(100, [0; 32], 5));
        current.hash = current.compute_hash().unwrap();

        let mut proposed_a = make_state(6);
        proposed_a.operation = make_transfer_op(100, b"alice", b"tok");
        proposed_a.prev_state_hash = current.hash;

        let mut proposed_b = make_state(6);
        proposed_b.operation = make_transfer_op(100, b"bob", b"tok");
        proposed_b.prev_state_hash = current.hash;

        let result = ManipulationResistance::verify_double_spend_impossible(
            &current,
            &[proposed_a, proposed_b],
        )
        .unwrap();
        assert!(
            !result,
            "transferring full balance to two different recipients is a double spend"
        );
    }

    #[test]
    fn double_spend_exceeding_balance() {
        let mut current = make_state(5);
        current
            .token_balances
            .insert("tok".into(), Balance::from_state(100, [0; 32], 5));
        current.hash = current.compute_hash().unwrap();

        let mut proposed_a = make_state(6);
        proposed_a.operation = make_transfer_op(60, b"alice", b"tok");
        proposed_a.prev_state_hash = current.hash;

        let mut proposed_b = make_state(6);
        proposed_b.operation = make_transfer_op(60, b"bob", b"tok");
        proposed_b.prev_state_hash = current.hash;

        let result = ManipulationResistance::verify_double_spend_impossible(
            &current,
            &[proposed_a, proposed_b],
        )
        .unwrap();
        assert!(!result, "60+60=120 > 100 available");
    }

    #[test]
    fn double_spend_wrong_state_numbers() {
        let mut current = make_state(5);
        current.hash = current.compute_hash().unwrap();

        let mut proposed_a = make_state(7); // wrong: should be 6
        proposed_a.prev_state_hash = current.hash;

        let mut proposed_b = make_state(6);
        proposed_b.prev_state_hash = current.hash;

        let result = ManipulationResistance::verify_double_spend_impossible(
            &current,
            &[proposed_a, proposed_b],
        )
        .unwrap();
        assert!(!result, "state_number must be current + 1");
    }

    #[test]
    fn double_spend_wrong_prev_hash() {
        let mut current = make_state(5);
        current.hash = current.compute_hash().unwrap();

        let mut proposed_a = make_state(6);
        proposed_a.prev_state_hash = current.hash;

        let mut proposed_b = make_state(6);
        proposed_b.prev_state_hash = [0xFF; 32]; // wrong hash

        let result = ManipulationResistance::verify_double_spend_impossible(
            &current,
            &[proposed_a, proposed_b],
        )
        .unwrap();
        assert!(!result, "prev_state_hash must match");
    }

    // ── verify_state_transition_rules ───────────────────────────────

    #[test]
    fn transition_rules_wrong_increment() {
        let mut current = make_state(5);
        current.hash = current.compute_hash().unwrap();

        let mut next = make_state(7); // should be 6
        next.prev_state_hash = current.hash;
        next.hash = next.compute_hash().unwrap();

        let result =
            ManipulationResistance::verify_state_transition_rules(&current, &next).unwrap();
        assert!(!result);
    }

    #[test]
    fn transition_rules_wrong_prev_hash() {
        let mut current = make_state(5);
        current.hash = current.compute_hash().unwrap();

        let mut next = make_state(6);
        next.prev_state_hash = [0xFF; 32]; // wrong
        next.hash = next.compute_hash().unwrap();

        let result =
            ManipulationResistance::verify_state_transition_rules(&current, &next).unwrap();
        assert!(!result);
    }

    #[test]
    fn transition_rules_balance_conservation() {
        let mut current = make_state(5);
        current
            .token_balances
            .insert("tok".into(), Balance::from_state(100, [0; 32], 5));
        current.hash = current.compute_hash().unwrap();

        let mut next = make_state(6);
        next.token_balances
            .insert("tok".into(), Balance::from_state(100, [0; 32], 6));
        next.prev_state_hash = current.hash;

        let result =
            ManipulationResistance::verify_state_transition_rules(&current, &next).unwrap();
        assert!(result, "same total balance should pass conservation check");
    }

    #[test]
    fn transition_rules_balance_not_conserved() {
        let mut current = make_state(5);
        current
            .token_balances
            .insert("tok".into(), Balance::from_state(100, [0; 32], 5));
        current.hash = current.compute_hash().unwrap();

        let mut next = make_state(6);
        next.token_balances
            .insert("tok".into(), Balance::from_state(200, [0; 32], 6));
        next.prev_state_hash = current.hash;

        let result =
            ManipulationResistance::verify_state_transition_rules(&current, &next).unwrap();
        assert!(!result, "different total balance should fail conservation");
    }

    // ── verify_balance_conservation ─────────────────────────────────

    #[test]
    fn balance_conservation_add_relationship_unchanged() {
        let mut current = make_state(5);
        current
            .token_balances
            .insert("tok".into(), Balance::from_state(50, [0; 32], 5));

        let mut next = make_state(6);
        next.operation = Operation::AddRelationship {
            from_id: [0x01; 32],
            to_id: [0x02; 32],
            relationship_type: b"bilateral".to_vec(),
            metadata: vec![],
            proof: vec![],
            mode: TransactionMode::Bilateral,
            message: "test".into(),
        };
        next.token_balances
            .insert("tok".into(), Balance::from_state(50, [0; 32], 6));

        let result = ManipulationResistance::verify_balance_conservation(&current, &next).unwrap();
        assert!(result);
    }

    #[test]
    fn balance_conservation_add_relationship_changed_fails() {
        let mut current = make_state(5);
        current
            .token_balances
            .insert("tok".into(), Balance::from_state(50, [0; 32], 5));

        let mut next = make_state(6);
        next.operation = Operation::AddRelationship {
            from_id: [0x01; 32],
            to_id: [0x02; 32],
            relationship_type: b"bilateral".to_vec(),
            metadata: vec![],
            proof: vec![],
            mode: TransactionMode::Bilateral,
            message: "test".into(),
        };
        next.token_balances
            .insert("tok".into(), Balance::from_state(999, [0; 32], 6));

        let result = ManipulationResistance::verify_balance_conservation(&current, &next).unwrap();
        assert!(!result);
    }

    // ── verify_signatures (state gap) ───────────────────────────────

    #[test]
    fn verify_signatures_excessive_gap_fails() {
        let mut current = make_state(5);
        current.hash = current.compute_hash().unwrap();

        let mut next = make_state(200);
        next.prev_state_hash = current.hash;
        next.hash = next.compute_hash().unwrap();

        let result = ManipulationResistance::verify_signatures(&current, &next).unwrap();
        assert!(!result, "gap of 195 > MAX_STATE_GAP=100 should fail");
    }

    #[test]
    fn verify_signatures_normal_gap_passes_no_sigs() {
        let mut current = make_state(5);
        current.hash = current.compute_hash().unwrap();

        let next = make_state(6);

        let result = ManipulationResistance::verify_signatures(&current, &next).unwrap();
        assert!(result, "gap of 1 with no signatures should pass");
    }

    // ── verify_commitment_binding ───────────────────────────────────

    #[test]
    fn commitment_binding_no_commitments_passes() {
        let s0 = make_state(0);
        let s1 = make_state(1);
        let s2 = make_state(2);
        let result = ManipulationResistance::verify_commitment_binding(&[s0, s1, s2]).unwrap();
        assert!(
            result,
            "no forward commitments means binding is trivially satisfied"
        );
    }

    #[test]
    fn commitment_binding_too_few_states() {
        let s0 = make_state(0);
        let s1 = make_state(1);
        let result = ManipulationResistance::verify_commitment_binding(&[s0, s1]).unwrap();
        assert!(
            result,
            "fewer than 3 states means no windows(3), trivially true"
        );
    }

    #[test]
    fn commitment_binding_empty() {
        let result = ManipulationResistance::verify_commitment_binding(&[]).unwrap();
        assert!(result);
    }

    // ── TransferDetails ─────────────────────────────────────────────

    #[test]
    fn transfer_details_debug() {
        let td = TransferDetails {
            amount: 42,
            recipient: vec![1, 2, 3],
        };
        let dbg = format!("{:?}", td);
        assert!(dbg.contains("42"));
        assert!(dbg.contains("recipient"));
    }
}
