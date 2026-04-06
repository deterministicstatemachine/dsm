//! Dual-mode state transition verifier (whitepaper Section 30).
//!
//! Handles both bilateral verification `V(S_n, S_{n+1}, σ_A, σ_B)` requiring
//! signatures from both parties, and unilateral verification
//! `V_uni(S_n, S_{n+1}, σ_A, D_verify(ID_B))` using directory-based identity
//! lookup for the counterparty.

use crate::types::error::DsmError;
use crate::types::operations::{Operation, TransactionMode};
use crate::types::state_types::{State as StateTypesState, PreCommitment};
use crate::types::token_types::Balance;
use crate::crypto;

/// DualModeVerifier implements the verification predicates from whitepaper Section 30
pub struct DualModeVerifier;

impl DualModeVerifier {
    /// Verify a state transition according to its mode and verification type
    pub fn verify_transition(
        current_state: &StateTypesState,
        next_state: &StateTypesState,
        operation: &Operation,
    ) -> Result<bool, DsmError> {
        // Get mode-specific validation logic
        match operation {
            Operation::Transfer { mode, .. } => {
                match mode {
                    TransactionMode::Bilateral => {
                        // V(Sn,Sn+1,σA,σB) = true
                        Self::verify_bilateral_mode(current_state, next_state)
                    }
                    TransactionMode::Unilateral => {
                        // Vuni(Sn,Sn+1,σA,Dverify(IDB)) = true
                        Self::verify_unilateral_mode(current_state, next_state)
                    }
                }
            }
            Operation::RemoveRelationship { .. } => {
                // For remove relationship, use basic transition verification
                Self::verify_basic_transition(current_state, next_state)
            }
            _ => Self::verify_basic_transition(current_state, next_state),
        }
    }

    /// Verify bilateral mode transition according to whitepaper equation (87)
    fn verify_bilateral_mode(
        current_state: &StateTypesState,
        next_state: &StateTypesState,
    ) -> Result<bool, DsmError> {
        // 1. Verify both signatures exist
        if next_state.entity_sig.is_none() || next_state.counterparty_sig.is_none() {
            return Ok(false);
        }

        // 2. Verify signatures are valid for state transition
        if !Self::verify_signatures(current_state, next_state)? {
            return Ok(false);
        }

        // 3. Verify state transition preserves invariants
        Self::verify_transition_invariants(current_state, next_state)
    }

    /// Verify unilateral mode transition according to whitepaper equation (88)
    fn verify_unilateral_mode(
        current_state: &StateTypesState,
        next_state: &StateTypesState,
    ) -> Result<bool, DsmError> {
        // 1. Verify sender signature
        if next_state.entity_sig.is_none() {
            return Ok(false);
        }

        // 2. Verify sender signature is valid
        if !Self::verify_entity_signature(current_state, next_state)? {
            return Ok(false);
        }

        // 3. Verify recipient identity anchor exists in decentralized storage
        if !Self::verify_recipient_identity(next_state)? {
            return Ok(false);
        }

        // 4. Verify state transition preserves invariants
        Self::verify_transition_invariants(current_state, next_state)
    }

    /// Verify a batch of transitions
    pub fn verify_transition_batch(states: &[StateTypesState]) -> Result<bool, DsmError> {
        if states.len() < 2 {
            return Ok(true); // Nothing to verify with 0 or 1 states
        }

        // Verify each pair of consecutive states
        for i in 0..(states.len() - 1) {
            let prev = &states[i];
            let next = &states[i + 1];

            if !Self::verify_transition(prev, next, &next.operation)? {
                return Ok(false);
            }
        }

        Ok(true)
    }

    /// Verify basic transition properties common to all operations
    fn verify_basic_transition(
        current_state: &StateTypesState,
        next_state: &StateTypesState,
    ) -> Result<bool, DsmError> {
        // Delegate to transition invariants verification
        Self::verify_transition_invariants(current_state, next_state)
    }

    fn verify_transition_invariants(
        current_state: &StateTypesState,
        next_state: &StateTypesState,
    ) -> Result<bool, DsmError> {
        // 1. Verify state number monotonically increases
        if next_state.state_number != current_state.state_number + 1 {
            return Ok(false);
        }

        // 2. Verify hash chain continuity
        if next_state.prev_state_hash != current_state.hash()? {
            return Ok(false);
        }

        // 3. Verify token conservation
        if !Self::verify_token_conservation(current_state, next_state)? {
            return Ok(false);
        }

        // 4. Verify entropy evolution using the consolidated implementation
        if !Self::verify_entropy_evolution(current_state, next_state)? {
            return Ok(false);
        }

        Ok(true)
    }

    fn verify_signatures(
        _current_state: &StateTypesState,
        next_state: &StateTypesState,
    ) -> Result<bool, DsmError> {
        // Verify both parties' signatures on state transition
        if let (Some(entity_sig), Some(counterparty_sig)) =
            (&next_state.entity_sig, &next_state.counterparty_sig)
        {
            // Get the state data for verification
            // Compute data for signing (hash of state + metadata)
            let state_data = next_state.hash()?.to_vec();
            // Temporarily skip metadata since get_parameter isn't accessible
            // if let Some(data) = next_state.get_parameter("signing_metadata") {
            //     state_data.extend_from_slice(data);
            // }

            // Verify entity signature
            match crypto::verify_signature(
                &state_data,
                entity_sig,
                &next_state.device_info.public_key,
            ) {
                Ok(valid) => {
                    if !valid {
                        return Ok(false);
                    }
                }
                Err(_) => return Ok(false),
            }

            // Verify counterparty signature if relationship exists
            if let Some(relationship) = &next_state.relationship_context {
                match crypto::verify_signature(
                    &state_data,
                    counterparty_sig,
                    &relationship.counterparty_public_key,
                ) {
                    Ok(valid) => {
                        if !valid {
                            return Ok(false);
                        }
                    }
                    Err(_) => return Ok(false),
                }

                Ok(true)
            } else {
                Ok(false) // No relationship context for bilateral mode
            }
        } else {
            Ok(false) // Missing signatures
        }
    }

    fn verify_entity_signature(
        _current_state: &StateTypesState,
        next_state: &StateTypesState,
    ) -> Result<bool, DsmError> {
        if let Some(signature) = &next_state.entity_sig {
            // Compute data for signing (hash of state + metadata)
            let state_data = next_state.hash()?.to_vec();
            // Temporarily skip metadata since get_parameter isn't accessible
            // if let Some(data) = next_state.get_parameter("signing_metadata") {
            //     state_data.extend_from_slice(data);
            // }

            crypto::verify_signature(&state_data, signature, &next_state.device_info.public_key)
        } else {
            Ok(false)
        }
    }

    /// Verify recipient identity in decentralized storage
    fn verify_recipient_identity(state: &StateTypesState) -> Result<bool, DsmError> {
        // In a real implementation, this would check with decentralized storage
        // For now, we just check if the relationship context contains valid data
        if let Some(relationship) = &state.relationship_context {
            if relationship.counterparty_id.is_empty()
                || relationship.counterparty_public_key.is_empty()
            {
                Ok(false)
            } else {
                Ok(true)
            }
        } else {
            // For non-relationship operations, this is still valid
            Ok(true)
        }
    }

    fn verify_token_conservation(
        current_state: &StateTypesState,
        next_state: &StateTypesState,
    ) -> Result<bool, DsmError> {
        // Verify token balances are conserved according to operation type
        for (token_id, current_balance) in &current_state.token_balances {
            match next_state.token_balances.get(token_id) {
                Some(next_balance) => {
                    // Balance changes must be justified by the operation
                    if current_balance.value() != next_balance.value() {
                        // Verify change is valid according to operation
                        if !Self::verify_balance_change_validity(
                            current_state,
                            next_state,
                            token_id,
                            current_balance.value(),
                            next_balance.value(),
                        )? {
                            return Ok(false);
                        }
                    }
                }
                None => {
                    // Token must still exist unless explicitly removed
                    return Ok(false);
                }
            }
        }
        Ok(true)
    }

    fn verify_balance_change_validity(
        current_state: &StateTypesState,
        next_state: &StateTypesState,
        token_id: &str,
        current_balance: u64,
        next_balance: u64,
    ) -> Result<bool, DsmError> {
        match &next_state.operation {
            Operation::Transfer {
                amount,
                token_id: op_token_id,
                ..
            } => {
                // Verify token ID matches
                if token_id.as_bytes() != op_token_id.as_slice() {
                    return Ok(false);
                }

                // Verify transfer amount matches balance change
                let amount_value = amount.value();
                if next_balance != current_balance - amount_value {
                    return Ok(false);
                }

                // Verify transfer is valid
                Self::verify_transfer_validity(current_state, next_state, token_id, amount)
            }
            _ => Ok(false),
        }
    }

    fn verify_entropy_evolution(
        current_state: &StateTypesState,
        next_state: &StateTypesState,
    ) -> Result<bool, DsmError> {
        // Verify entropy evolution - entropy must change with each state transition
        if next_state.entropy == current_state.entropy {
            return Ok(false);
        }

        Ok(true)
    }

    #[allow(dead_code)]
    fn verify_precommitment_adherence(
        commitment: &PreCommitment,
        next_state: &StateTypesState,
    ) -> Result<bool, DsmError> {
        // Verify pre-commitment conditions are met using available commitment fields
        if next_state.state_number != commitment.min_state_number + 1 {
            return Ok(false);
        }

        if next_state.prev_state_hash != commitment.hash {
            return Ok(false);
        }

        // Removed entropy check because PreCommitment does not include an entropy field
        Ok(true)
    }

    /// Verify transfer validity
    /// This function checks if a transfer operation is valid based on the current and next state.
    /// It ensures that the transfer adheres to the rules defined for token transfers.
    fn verify_transfer_validity(
        current_state: &StateTypesState,
        _next_state: &StateTypesState,
        token_id: &str,
        amount: &Balance,
    ) -> Result<bool, DsmError> {
        // Check if the token ID exists in the current state
        if !current_state.token_balances.contains_key(token_id) {
            return Ok(false);
        }

        // Check if the amount is valid (greater than zero)
        if amount.value() == 0 {
            return Ok(false);
        }

        // Check if the transfer amount does not exceed the current balance
        let current_balance = current_state.token_balances[token_id].value();
        if amount.value() > current_balance {
            return Ok(false);
        }

        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::state_types::{DeviceInfo, State, StateParams, RelationshipContext};

    fn make_device_info() -> DeviceInfo {
        DeviceInfo::new([0x11; 32], vec![0x22; 64])
    }

    fn make_genesis() -> StateTypesState {
        let di = make_device_info();
        let mut state = State::new_genesis([0xAA; 32], di);
        state
            .token_balances
            .insert("ERA".to_string(), Balance::from_state(1000, [0u8; 32], 0));
        state
    }

    fn make_next_state(
        prev: &StateTypesState,
        operation: Operation,
        entropy: Vec<u8>,
    ) -> StateTypesState {
        let di = make_device_info();
        let prev_hash = prev.hash().unwrap();
        let mut params = StateParams::new(prev.state_number + 1, entropy, operation, di);
        params.prev_state_hash = prev_hash;
        let mut s = State::new(params);
        s.token_balances = prev.token_balances.clone();
        s
    }

    #[test]
    fn verify_transition_rejects_non_sequential_state_number() {
        let current = make_genesis();
        let di = make_device_info();
        let prev_hash = current.hash().unwrap();
        let mut params = StateParams::new(
            5, // gap in state numbers
            vec![0xBB; 32],
            Operation::Noop,
            di,
        );
        params.prev_state_hash = prev_hash;
        let mut next = State::new(params);
        next.token_balances = current.token_balances.clone();

        let result =
            DualModeVerifier::verify_transition(&current, &next, &Operation::Noop).unwrap();
        assert!(!result, "should reject non-sequential state numbers");
    }

    #[test]
    fn verify_transition_rejects_wrong_prev_hash() {
        let current = make_genesis();
        let di = make_device_info();
        let mut params = StateParams::new(1, vec![0xCC; 32], Operation::Noop, di);
        params.prev_state_hash = [0xFF; 32]; // wrong hash
        let mut next = State::new(params);
        next.token_balances = current.token_balances.clone();

        let result =
            DualModeVerifier::verify_transition(&current, &next, &Operation::Noop).unwrap();
        assert!(!result, "should reject wrong prev_state_hash");
    }

    #[test]
    fn verify_transition_rejects_same_entropy() {
        let current = make_genesis();
        let di = make_device_info();
        let prev_hash = current.hash().unwrap();
        let mut params = StateParams::new(
            1,
            current.entropy.clone(), // same entropy as current
            Operation::Noop,
            di,
        );
        params.prev_state_hash = prev_hash;
        let mut next = State::new(params);
        next.token_balances = current.token_balances.clone();

        let result =
            DualModeVerifier::verify_transition(&current, &next, &Operation::Noop).unwrap();
        assert!(!result, "should reject identical entropy");
    }

    #[test]
    fn verify_transition_rejects_missing_token() {
        let current = make_genesis();
        let next = make_next_state(&current, Operation::Noop, vec![0xDD; 32]);
        // Remove a token that exists in current
        let mut altered_next = next;
        altered_next.token_balances.clear();

        let result =
            DualModeVerifier::verify_transition(&current, &altered_next, &Operation::Noop).unwrap();
        assert!(!result, "should reject when token disappears");
    }

    #[test]
    fn verify_basic_transition_succeeds_for_valid_pair() {
        let current = make_genesis();
        let next = make_next_state(&current, Operation::Noop, vec![0xEE; 32]);

        let result =
            DualModeVerifier::verify_transition(&current, &next, &Operation::Noop).unwrap();
        assert!(result, "valid basic transition should pass");
    }

    #[test]
    fn verify_bilateral_rejects_missing_sigs() {
        let current = make_genesis();
        let transfer = Operation::Transfer {
            to_device_id: vec![0x33; 32],
            amount: Balance::from_state(10, [0u8; 32], 0),
            token_id: b"ERA".to_vec(),
            mode: TransactionMode::Bilateral,
            nonce: vec![1],
            verification: crate::types::operations::VerificationType::Standard,
            pre_commit: None,
            recipient: vec![0x33; 32],
            to: vec![0x33; 32],
            message: String::new(),
            signature: vec![],
        };
        let next = make_next_state(&current, transfer.clone(), vec![0xFF; 32]);

        let result = DualModeVerifier::verify_transition(&current, &next, &transfer).unwrap();
        assert!(!result, "bilateral transfer without signatures should fail");
    }

    #[test]
    fn verify_unilateral_rejects_missing_entity_sig() {
        let current = make_genesis();
        let transfer = Operation::Transfer {
            to_device_id: vec![0x33; 32],
            amount: Balance::from_state(10, [0u8; 32], 0),
            token_id: b"ERA".to_vec(),
            mode: TransactionMode::Unilateral,
            nonce: vec![1],
            verification: crate::types::operations::VerificationType::Standard,
            pre_commit: None,
            recipient: vec![0x33; 32],
            to: vec![0x33; 32],
            message: String::new(),
            signature: vec![],
        };
        let next = make_next_state(&current, transfer.clone(), vec![0xAA; 32]);

        let result = DualModeVerifier::verify_transition(&current, &next, &transfer).unwrap();
        assert!(!result, "unilateral without entity_sig should fail");
    }

    #[test]
    fn verify_batch_with_empty_or_single() {
        assert!(DualModeVerifier::verify_transition_batch(&[]).unwrap());
        let genesis = make_genesis();
        assert!(DualModeVerifier::verify_transition_batch(&[genesis]).unwrap());
    }

    #[test]
    fn verify_batch_valid_chain() {
        let s0 = make_genesis();
        let s1 = make_next_state(&s0, Operation::Noop, vec![0x11; 32]);
        let s2 = make_next_state(&s1, Operation::Noop, vec![0x22; 32]);

        let result = DualModeVerifier::verify_transition_batch(&[s0, s1, s2]).unwrap();
        assert!(result, "valid chain batch should pass");
    }

    #[test]
    fn verify_recipient_identity_accepts_no_relationship() {
        let state = make_genesis();
        let result = DualModeVerifier::verify_recipient_identity(&state).unwrap();
        assert!(result, "no relationship context is acceptable");
    }

    #[test]
    fn verify_recipient_identity_rejects_empty_counterparty() {
        let mut state = make_genesis();
        state.relationship_context = Some(RelationshipContext::new(
            [0x01; 32],
            [0u8; 32], // empty counterparty_id (all zeros, but non-empty bytes)
            vec![],    // empty counterparty_public_key
        ));
        let result = DualModeVerifier::verify_recipient_identity(&state).unwrap();
        assert!(!result, "empty counterparty public key should fail");
    }
}
