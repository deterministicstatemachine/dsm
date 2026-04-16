//! State transition creation and application for the DSM hash chain.
//!
//! A [`StateTransition`] encapsulates all data needed to evolve the hash chain
//! by one step: the operation, new entropy, random walk positions, and the
//! resulting next state. The [`apply_transition`] function validates invariants
//! (entropy evolution, hash chain linkage, token conservation) and produces
//! the successor state.

use crate::core::state_machine::random_walk::algorithms::{
    generate_positions, generate_seed, RandomWalkConfig,
};
use crate::types::error::DsmError;
use crate::types::operations::{Operation, TransactionMode};
use crate::types::state_types::{PreCommitment, State};
use crate::types::token_types::Balance;

use crate::types::state_types::PositionSequence;
// bincode removed from hot paths; canonical wire formats and proto will replace it.
use crate::crypto::blake3::{domain_hash, dsm_domain_hasher};
use blake3::Hash;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use log;
use prost::Message;

#[cfg(test)]
const TEST_DEVICE_ID: [u8; 32] = [
    0x8a, 0x3d, 0x9f, 0x5a, 0x4e, 0x1c, 0x8b, 0x2e, 0x6f, 0x7d, 0x3c, 0x9a, 0x1b, 0x5e, 0x4f, 0x8d,
    0x2a, 0x9c, 0x3e, 0x7b, 0x1f, 0x6d, 0x8e, 0x4a, 0x5c, 0x9f, 0x2b, 0x7e, 0x3d, 0x1a, 0x8f, 0x6c,
]; // blake3::hash(b"test_device")

#[derive(Clone, Debug)]
pub enum VerificationType {
    Standard,
    Bilateral,
    Directory,
}

#[derive(Clone, Debug)]
pub struct StateTransition {
    pub operation: Operation,
    pub new_entropy: Option<Vec<u8>>,
    pub encapsulated_entropy: Option<Vec<u8>>,
    pub device_id: [u8; 32],
    pub tick: u64,
    pub flags: Vec<String>,
    pub position_sequence: Option<PositionSequence>,
    pub token_balances: Option<HashMap<String, Balance>>,
    pub forward_commitment: Option<PreCommitment>,
    pub prev_state_hash: Option<[u8; 32]>,
    pub entity_signature: Option<Vec<u8>>,
    pub counterparty_signature: Option<Vec<u8>>,
    pub proof_of_authorization: Vec<u8>,
    // Internal-only fields were removed.
    // If a caller needs previous/next states, pass them explicitly rather than embedding them here.
    pub(crate) signature: Vec<u8>,
}

impl StateTransition {
    /// Create a new state transition with the specified parameters
    ///
    /// # Arguments
    ///
    /// * `operation` - The operation to be performed in this transition
    /// * `new_entropy` - Optional entropy to incorporate into the transition
    /// * `encapsulated_entropy` - Optional encapsulated entropy for secure transmission
    /// * `device_id` - The ID of the device initiating the transition
    ///
    /// # Returns
    ///
    /// A new StateTransition instance with current tick and empty flags
    pub fn new(
        operation: Operation,
        new_entropy: Option<Vec<u8>>,
        encapsulated_entropy: Option<Vec<u8>>,
        device_id: &[u8; 32],
    ) -> Self {
        // For protocol compliance, require proof_of_authorization and signature to be provided/generated
        let proof_of_authorization = match operation.get_proof_of_authorization() {
            Some(proof) => proof,
            None => {
                log::warn!("No proof_of_authorization provided for operation");
                vec![]
            }
        };
        let signature = match operation.get_signature() {
            Some(sig) => sig,
            None => {
                log::warn!("No signature provided for operation");
                vec![]
            }
        };

        // Determine deterministic logical tick once.
        // crate::utils::deterministic_time::tick() returns (hash: [u8;32], tick: u64).
        let (_dt_hash, tick) = crate::utils::deterministic_time::tick();

        Self {
            operation,
            new_entropy,
            encapsulated_entropy,
            device_id: *device_id,
            tick,
            flags: Vec::new(),
            position_sequence: None,
            token_balances: None,
            forward_commitment: None,
            prev_state_hash: None, // Initialize to None, will be set by create_transition
            entity_signature: None,
            counterparty_signature: None,
            signature,
            proof_of_authorization,
        }
    }

    /// Deterministic wire-encoding of the StateTransition for hashing/persistence.
    /// Uses canonical protobuf serialization to replace custom binary format.
    pub fn to_wire_bytes(&self) -> Vec<u8> {
        let proto = self.to_canonical_proto();
        proto.encode_to_vec()
    }

    /// Add flags to the state transition
    pub fn with_flags(mut self, flags: Vec<String>) -> Self {
        self.flags = flags;
        self
    }

    /// Add token balance updates, validating according to whitepaper Section 9
    pub fn with_token_balances(mut self, balances: HashMap<String, Balance>) -> Self {
        // All balances are already non-negative since Balance uses an unsigned type
        self.token_balances = Some(balances);
        self
    }

    /// Finalize the transition by validating commitment integrity and generating signatures
    ///
    /// This implements the pre-commitment protocol described in whitepaper Section 8.3
    pub fn finalize(&mut self, current_state: &State) -> Result<(), DsmError> {
        // Verify position sequence exists
        if self.position_sequence.is_none() {
            return Err(DsmError::invalid_operation("Position sequence is missing"));
        }

        // Create hash combining current state and operation
        let mut hasher = dsm_domain_hasher("DSM/transition");
        hasher.update(&current_state.hash);

        // Serialize operation deterministically
        let op_bytes = self.operation.to_bytes();
        hasher.update(&op_bytes);

        // Add entropy
        hasher.update(&self.new_entropy.clone().unwrap_or_default());

        // Validate token balances if present
        if let Some(balances) = &self.token_balances {
            for _balance in balances.values() {
                // Balance is unsigned - no need to check for negative values
            }
        }

        Ok(())
    }

    /// Add forward commitment to future state parameters
    pub fn with_forward_commitment(
        mut self,
        operation_type: &str,
        fixed_params: HashMap<String, Vec<u8>>,
        variable_params: HashSet<String>,
        min_state_number: u64,
        counterparty_id: &str,
    ) -> Self {
        let commitment = PreCommitment {
            operation_type: operation_type.to_string(),
            fixed_parameters: fixed_params,
            variable_parameters: variable_params,
            min_state_number,
            signatures: Vec::new(),
            entity_signature: None,
            counterparty_signature: None,
            hash: [0u8; 32],
            value: Vec::new(),
            commitment: Vec::new(),
            counterparty_id: domain_hash("DSM/counterparty-id", counterparty_id.as_bytes()).into(),
        };
        self.forward_commitment = Some(commitment);
        self
    }

    /// Add entity signature to forward commitment
    pub fn sign_forward_commitment(&mut self, signature: Vec<u8>) -> Result<(), DsmError> {
        if let Some(commitment) = &mut self.forward_commitment {
            commitment.entity_signature = Some(signature);
            Ok(())
        } else {
            Err(DsmError::invalid_operation(
                "No forward commitment exists to sign",
            ))
        }
    }

    /// Add counterparty signature to forward commitment
    pub fn cosign_forward_commitment(&mut self, signature: Vec<u8>) -> Result<(), DsmError> {
        if let Some(commitment) = &mut self.forward_commitment {
            commitment.counterparty_signature = Some(signature);
            Ok(())
        } else {
            Err(DsmError::invalid_operation(
                "No forward commitment exists to cosign",
            ))
        }
    }
}

impl StateTransition {
    /// Convert to CanonicalStateTransitionProto for deterministic serialization
    pub fn to_canonical_proto(&self) -> crate::types::proto::CanonicalStateTransitionProto {
        // Sort flags lexicographically
        let mut flags = self.flags.clone();
        flags.sort();

        // Convert token balances to sorted TokenBalanceEntry list
        let mut token_balances = Vec::new();
        if let Some(balances) = &self.token_balances {
            let mut keys: Vec<_> = balances.keys().cloned().collect();
            keys.sort();
            for key in keys {
                if let Some(balance) = balances.get(&key) {
                    token_balances.push(crate::types::proto::TokenBalanceEntry {
                        token_id: key.clone(),
                        amount: Some(crate::types::proto::U128 {
                            le: balance.value().to_le_bytes().to_vec(),
                        }),
                    });
                }
            }
        }

        // Convert position sequence if present
        let position_sequence = self.position_sequence.as_ref().map(|ps| {
            let positions = ps
                .positions
                .iter()
                .map(|pos_list| crate::types::proto::PositionList {
                    positions: pos_list.clone(),
                })
                .collect();
            crate::types::proto::PositionSequenceProto {
                positions,
                seed: ps.seed.clone(),
            }
        });

        // Convert forward commitment if present
        let forward_commitment = self.forward_commitment.as_ref().map(|fc| {
            // Sort fixed parameters by key
            let mut fixed_params = Vec::new();
            let mut keys: Vec<_> = fc.fixed_parameters.keys().cloned().collect();
            keys.sort();
            for key in keys {
                if let Some(value) = fc.fixed_parameters.get(&key) {
                    fixed_params.push(crate::types::proto::ParamKv {
                        key: key.clone(),
                        value: String::from_utf8_lossy(value).to_string(),
                    });
                }
            }

            // Sort variable parameters
            let mut variable_params: Vec<_> = fc.variable_parameters.iter().cloned().collect();
            variable_params.sort();

            crate::types::proto::PreCommitmentProto {
                operation_type: fc.operation_type.clone(),
                fixed_parameters: fixed_params,
                variable_parameters: variable_params,
                min_state_number: fc.min_state_number,
                hash: Some(crate::types::proto::Hash32 {
                    v: fc.hash.to_vec(),
                }),
                signatures: fc.signatures.clone(),
                entity_signature: fc.entity_signature.clone(),
                counterparty_signature: fc.counterparty_signature.clone(),
                value: fc.value.clone(),
                commitment: fc.commitment.clone(),
                counterparty_id: fc.counterparty_id.to_vec(),
            }
        });

        crate::types::proto::CanonicalStateTransitionProto {
            operation: self.operation.to_bytes(),
            new_entropy: self.new_entropy.clone(),
            encapsulated_entropy: self.encapsulated_entropy.clone(),
            device_id: self.device_id.to_vec(),
            flags,
            position_sequence,
            token_balances,
            forward_commitment,
            prev_state_hash: self.prev_state_hash.map(|h| h.to_vec()),
            entity_signature: self.entity_signature.clone(),
            counterparty_signature: self.counterparty_signature.clone(),
            proof_of_authorization: self.proof_of_authorization.clone(),
            signature: self.signature.clone(),
        }
    }
}

impl Operation {
    /// Check if this operation affects the balance of a specific token
    pub fn affects_balance(&self, token_id: &[u8]) -> bool {
        match self {
            Operation::Transfer {
                token_id: op_token_id,
                ..
            } => op_token_id.as_slice() == token_id,
            Operation::Mint {
                token_id: op_token_id,
                ..
            } => op_token_id.as_slice() == token_id,
            Operation::Burn {
                token_id: op_token_id,
                ..
            } => op_token_id.as_slice() == token_id,
            _ => false,
        }
    }
}

/// Calculate sparse indices for efficient state traversal, implementing the
/// mathematical model from whitepaper Section 3.2
///
/// This creates indices at power-of-2 distances from the current state,
/// with guaranteed inclusion of genesis (0) and direct predecessor for efficient traversal.
///
/// The essence of the sparse indexing scheme is to allow efficient O(log n) state lookups
/// while maintaining cryptographic integrity of the hash chain. By including references to
/// states at power-of-2 distances, we can traverse a state chain of length n in O(log n) time.
pub fn calculate_sparse_indices(state_number: u64) -> Result<Vec<u64>, DsmError> {
    // Implementation for state 0 (genesis) should return empty set
    if state_number == 0 {
        return Ok(Vec::new());
    }

    // Start with basic algorithm from whitepaper Section 3.2
    let mut indices = Vec::new();
    let mut power = 0;

    // For each bit position in the state number, calculate index
    while (1 << power) <= state_number {
        // If the bit at position 'power' is set, calculate the index
        if (state_number & (1 << power)) != 0 {
            let idx = state_number - (1 << power);
            indices.push(idx);
        }
        power += 1;
    }

    // CRITICAL: Ensure essential references are included
    if !indices.contains(&0) {
        indices.push(0);
    }
    if state_number > 1 && !indices.contains(&(state_number - 1)) {
        indices.push(state_number - 1);
    }

    // Ensure indices are sorted for efficient binary search
    indices.sort();

    // Validate critical references
    debug_assert!(
        indices.contains(&0),
        "Genesis (0) must be included in sparse index"
    );
    debug_assert!(
        state_number <= 1 || indices.contains(&(state_number - 1)),
        "Direct predecessor must be included in sparse index"
    );

    Ok(indices)
}

/// Generate position sequence for state transition
pub fn generate_position_sequence(
    current_state: &State,
    operation: &Operation,
    new_entropy: &[u8],
) -> Result<PositionSequence, DsmError> {
    // Serialize the operation for hashing
    let op_data = operation.to_bytes();

    // Create seed from current state hash, operation, and new entropy
    let current_state_hash = current_state.hash()?;
    let hash_obj = Hash::from_bytes(current_state_hash);

    let seed = generate_seed(&hash_obj, &op_data, Some(new_entropy));

    // Generate the position sequence using default config
    let config = RandomWalkConfig::default();
    let positions = generate_positions(&seed, Some(config))?;

    // Convert positions to the expected Vec<Vec<i32>> format
    let position_vectors: Vec<Vec<i32>> = positions.iter().map(|pos| pos.0.clone()).collect();

    // Create the position sequence
    let sequence = PositionSequence {
        positions: position_vectors,
        seed: seed.as_bytes().to_vec(),
    };

    Ok(sequence)
}

/// Create a new state transition with random walk positions
pub fn create_transition(
    current_state: &State,
    operation: Operation,
    new_entropy: &[u8],
) -> Result<StateTransition, DsmError> {
    // Generate position sequence for verification
    let positions = generate_position_sequence(current_state, &operation, new_entropy)?;

    // Create transition with positions
    let mut transition = StateTransition::new(
        operation,
        Some(new_entropy.to_vec()),
        None,
        &current_state.device_info.device_id,
    );

    // Fail-closed: operations that require authorization must carry it.
    // Every signed operation type must have a non-empty signature.
    match &transition.operation {
        Operation::Transfer { .. } => {
            log::info!(
                "[create_transition] Transfer: proof_of_auth.len={} signature.len={}",
                transition.proof_of_authorization.len(),
                transition.signature.len()
            );
            if transition.proof_of_authorization.is_empty() {
                log::error!("[create_transition] Transfer missing proof_of_authorization");
                return Err(DsmError::invalid_operation(
                    "Transfer missing proof_of_authorization (signature)",
                ));
            }
            if transition.signature.is_empty() {
                log::error!("[create_transition] Transfer missing signature");
                return Err(DsmError::invalid_operation("Transfer missing signature"));
            }
        }
        Operation::Mint {
            proof_of_authorization,
            ..
        } if proof_of_authorization.is_empty() => {
            return Err(DsmError::invalid_operation(
                "Mint missing proof_of_authorization",
            ));
        }
        Operation::Burn {
            proof_of_ownership, ..
        } if proof_of_ownership.is_empty() => {
            return Err(DsmError::invalid_operation(
                "Burn missing proof_of_ownership",
            ));
        }
        // Device-key signed operations
        Operation::CreateToken { signature, .. } if signature.is_empty() => {
            return Err(DsmError::invalid_operation("CreateToken missing signature"));
        }
        Operation::Lock { signature, .. } if signature.is_empty() => {
            return Err(DsmError::invalid_operation("Lock missing signature"));
        }
        Operation::Unlock { signature, .. } if signature.is_empty() => {
            return Err(DsmError::invalid_operation("Unlock missing signature"));
        }
        Operation::LockToken { signature, .. } if signature.is_empty() => {
            return Err(DsmError::invalid_operation("LockToken missing signature"));
        }
        Operation::UnlockToken { signature, .. } if signature.is_empty() => {
            return Err(DsmError::invalid_operation("UnlockToken missing signature"));
        }
        Operation::Generic { signature, .. } if signature.is_empty() => {
            return Err(DsmError::invalid_operation("Generic missing signature"));
        }
        // DLV operations (embedded-key signed)
        Operation::DlvCreate { signature, .. } if signature.is_empty() => {
            return Err(DsmError::invalid_operation("DlvCreate missing signature"));
        }
        Operation::DlvUnlock { signature, .. } if signature.is_empty() => {
            return Err(DsmError::invalid_operation("DlvUnlock missing signature"));
        }
        Operation::DlvClaim { signature, .. } if signature.is_empty() => {
            return Err(DsmError::invalid_operation("DlvClaim missing signature"));
        }
        Operation::DlvInvalidate { signature, .. } if signature.is_empty() => {
            return Err(DsmError::invalid_operation(
                "DlvInvalidate missing signature",
            ));
        }
        _ => {}
    }

    // Set position sequence
    transition.position_sequence = Some(positions);

    // Set previous state hash - critical for maintaining hash chain integrity
    transition.prev_state_hash = Some(current_state.hash()?);

    Ok(transition)
}

/// Verify the integrity of a state transition by checking hash chain and entropy evolution
pub fn verify_transition_integrity(
    previous_state: &State,
    current_state: &State,
    operation: &Operation,
) -> Result<bool, DsmError> {
    // Validate state number increment (monotonicity property)
    if current_state.state_number != previous_state.state_number + 1 {
        return Ok(false);
    }

    // Validate hash chain continuity (immutability property)
    let previous_hash = previous_state.hash()?;
    if current_state.prev_state_hash != previous_hash {
        return Ok(false);
    }

    // Verify state hash integrity (self-consistency property)
    let computed_hash = current_state.compute_hash()?;
    if current_state.hash != computed_hash {
        return Ok(false);
    }

    // Verify sparse index contains required entries
    let indices = &current_state.sparse_index.indices;

    if current_state.state_number > 0 && !indices.contains(&0) {
        return Ok(false);
    }
    if current_state.state_number > 1 && !indices.contains(&(previous_state.state_number)) {
        return Ok(false);
    }

    // Verify entropy evolution — must use the same domain tag as generate_transition_entropy()
    let serialized_op = operation.to_bytes();
    {
        let mut hasher = dsm_domain_hasher("DSM/state-entropy");
        hasher.update(&previous_state.entropy);
        hasher.update(&serialized_op);
        hasher.update(&current_state.state_number.to_le_bytes());
        let expected_entropy = hasher.finalize().as_bytes().to_vec();

        if current_state.entropy != expected_entropy {
            return Ok(false);
        }
    }

    // Verify pre-commitment alignment if present
    if let Some(pre_commitment) = &current_state.forward_commitment {
        let mut commitment_data = Vec::new();
        commitment_data.extend_from_slice(&current_state.prev_state_hash);
        commitment_data.extend_from_slice(&serialized_op);
        commitment_data.extend_from_slice(&current_state.entropy);

        let commitment_hash = domain_hash("DSM/state-commit", &commitment_data);

        // Deterministic textual canonicalization until proto is available
        let pre_commitment_bytes = format!("{pre_commitment:?}").into_bytes();
        let pre_commitment_hash = domain_hash("DSM/pre-commit", &pre_commitment_bytes);

        if pre_commitment_hash.as_bytes() != commitment_hash.as_bytes() {
            return Ok(false);
        }
    }

    // Verify token balance consistency for token-affecting operations
    if !verify_token_balance_consistency(previous_state, current_state, operation)? {
        return Ok(false);
    }

    Ok(true)
}

fn token_balance_map_for_verification(state: &State, token_id: &[u8]) -> BTreeMap<String, u64> {
    let token_id_str = String::from_utf8_lossy(token_id);
    let suffix = format!("|{token_id_str}");
    state
        .token_balances
        .iter()
        .filter_map(|(key, balance)| {
            if key.ends_with(&suffix) {
                Some((key.clone(), balance.value()))
            } else {
                None
            }
        })
        .collect()
}

fn token_balance_deltas_for_verification(
    previous_state: &State,
    current_state: &State,
    token_id: &[u8],
) -> BTreeMap<String, i128> {
    let previous = token_balance_map_for_verification(previous_state, token_id);
    let current = token_balance_map_for_verification(current_state, token_id);

    let mut keys: BTreeSet<String> = previous.keys().cloned().collect();
    keys.extend(current.keys().cloned());

    let mut deltas = BTreeMap::new();
    for key in keys {
        let prev = previous.get(&key).copied().unwrap_or(0) as i128;
        let curr = current.get(&key).copied().unwrap_or(0) as i128;
        deltas.insert(key, curr - prev);
    }
    deltas
}

/// Verify token balance consistency according to whitepaper Section 10
pub fn verify_token_balance_consistency(
    previous_state: &State,
    current_state: &State,
    operation: &Operation,
) -> Result<bool, DsmError> {
    match operation {
        Operation::Mint {
            amount, token_id, ..
        } => {
            let current = token_balance_map_for_verification(current_state, token_id);
            if current.is_empty() {
                return Ok(false);
            }
            let deltas =
                token_balance_deltas_for_verification(previous_state, current_state, token_id);
            let positive = deltas
                .values()
                .filter(|delta| **delta > 0)
                .copied()
                .collect::<Vec<_>>();
            let negative = deltas.values().filter(|delta| **delta < 0).count();
            if negative != 0 || positive.len() != 1 || positive[0] != amount.value() as i128 {
                return Ok(false);
            }
        }
        Operation::Burn {
            amount, token_id, ..
        } => {
            let deltas =
                token_balance_deltas_for_verification(previous_state, current_state, token_id);
            let negative = deltas
                .values()
                .filter(|delta| **delta < 0)
                .copied()
                .collect::<Vec<_>>();
            let positive = deltas.values().filter(|delta| **delta > 0).count();
            if positive != 0 || negative.len() != 1 || negative[0] != -(amount.value() as i128) {
                return Ok(false);
            }
        }
        Operation::Transfer {
            amount,
            token_id,
            to_device_id,
            ..
        } => {
            let previous = token_balance_map_for_verification(previous_state, token_id);
            let current = token_balance_map_for_verification(current_state, token_id);
            if previous.is_empty() && current.is_empty() {
                return Ok(true);
            }

            let deltas =
                token_balance_deltas_for_verification(previous_state, current_state, token_id);
            let is_recipient = to_device_id.len() == 32
                && to_device_id.as_slice() == current_state.device_info.device_id.as_slice();
            let expected = if is_recipient {
                amount.value() as i128
            } else {
                -(amount.value() as i128)
            };
            let opposite = -expected;

            let mut expected_count = 0usize;
            let mut opposite_count = 0usize;
            for delta in deltas.values().copied().filter(|delta| *delta != 0) {
                if delta == expected {
                    expected_count += 1;
                } else if delta == opposite {
                    opposite_count += 1;
                } else {
                    return Ok(false);
                }
            }

            if expected_count != 1 || opposite_count > 1 {
                return Ok(false);
            }
        }
        _ => {
            for (key, prev_balance) in &previous_state.token_balances {
                if let Some(next_balance) = current_state.token_balances.get(key) {
                    // Extract token_id from the key for affects_balance check
                    let token_id_str = if let Some((_, t)) = key.split_once('|') {
                        t
                    } else {
                        key.as_str()
                    };
                    if !operation.affects_balance(token_id_str.as_bytes())
                        && prev_balance.value() != next_balance.value()
                    {
                        return Ok(false);
                    }
                } else {
                    return Ok(false);
                }
            }
        }
    }

    Ok(true)
}

/// Apply a transition to produce a new state
pub fn apply_transition(
    current_state: &State,
    operation: &Operation,
    new_entropy: &[u8],
) -> Result<State, DsmError> {
    // Apply the operation based on its type
    match operation {
        Operation::Transfer {
            mode, verification, ..
        } => match mode {
            TransactionMode::Bilateral => {
                // For bilateral mode, require both signatures
                create_next_state(
                    current_state,
                    operation.clone(),
                    new_entropy,
                    &to_local_verification_type(verification),
                    true,
                )
            }
            TransactionMode::Unilateral => {
                // For unilateral mode, verify against decentralized directory
                create_next_state(
                    current_state,
                    operation.clone(),
                    new_entropy,
                    &to_local_verification_type(verification),
                    false,
                )
            }
        },
        // For non-transfer operations, use basic transition
        _ => create_next_state(
            current_state,
            operation.clone(),
            new_entropy,
            &VerificationType::Standard,
            false,
        ),
    }
}

/// Verify bilateral transition relationship consistency
pub fn verify_bilateral_transition(
    current_state: &State,
    next_state: &State,
) -> Result<bool, DsmError> {
    // For bilateral operations, verify relationship state consistency
    if let Some(current_rel) = &current_state.relationship_context {
        if let Some(next_rel) = &next_state.relationship_context {
            // Verify counterparty IDs match
            if current_rel.counterparty_id != next_rel.counterparty_id {
                return Ok(false);
            }

            // Verify state numbers are consistent (should advance)
            if next_rel.counterparty_state_number <= current_rel.counterparty_state_number {
                return Ok(false);
            }
        } else {
            return Ok(false); // Missing relationship context in next state
        }
    }

    Ok(true)
}

/// Verify a SPHINCS+ signature on an operation.
///
/// The canonical signing payload is `operation.with_cleared_signature().to_bytes()`.
/// This function is fail-closed: missing, empty, or invalid signatures all produce
/// errors.
fn verify_operation_signature(
    operation: &Operation,
    public_key: &[u8],
    op_name: &str,
) -> Result<(), DsmError> {
    if public_key.len() != 64 {
        return Err(DsmError::invalid_operation(format!(
            "{op_name} public key must be 64 bytes (SPHINCS+), got {}",
            public_key.len()
        )));
    }
    let signature = operation
        .get_signature()
        .ok_or_else(|| DsmError::invalid_operation(format!("{op_name} missing signature")))?;
    if signature.is_empty() {
        return Err(DsmError::invalid_operation(format!(
            "{op_name} missing signature"
        )));
    }
    let cleared = operation.with_cleared_signature();
    let op_bytes = cleared.to_bytes();
    let verify_hash = domain_hash("DSM/op-verify", &op_bytes);
    log::info!(
        "[verify_operation_signature] {op_name}: op_bytes.len={} hash(first8)={:?} sig.len={} pk.len={}",
        op_bytes.len(),
        &verify_hash.as_bytes()[..8],
        signature.len(),
        public_key.len()
    );
    match crate::crypto::sphincs::sphincs_verify(public_key, &op_bytes, &signature) {
        Ok(true) => {
            log::info!("[verify_operation_signature] {op_name} signature verified OK");
            Ok(())
        }
        Ok(false) => {
            log::error!("[verify_operation_signature] {op_name} signature INVALID");
            Err(DsmError::invalid_operation(format!(
                "{op_name} signature invalid"
            )))
        }
        Err(e) => {
            log::error!("[verify_operation_signature] {op_name} verification error: {e}");
            Err(DsmError::crypto(
                format!("{op_name} signature verification error: {e}"),
                None::<std::io::Error>,
            ))
        }
    }
}

/// Create the next state based on current state, operation and verification requirements
pub fn create_next_state(
    current_state: &State,
    operation: Operation,
    new_entropy: &[u8],
    verification_type: &VerificationType,
    require_bilateral: bool,
) -> Result<State, DsmError> {
    // verification_type is checked per-operation in the signature match below.
    let _ = verification_type;
    // require_bilateral gates apply_token_balance_delta — bilateral BLE
    // transitions skip the in-core delta (settlement handler applies it).

    // ── Fail-closed signature verification ────────────────────────────
    match &operation {
        // ── Transfer ──────────────────────────────────────────────
        Operation::Transfer {
            signature,
            mode,
            to_device_id,
            ..
        } => {
            if signature.is_empty() {
                return Err(DsmError::invalid_operation("Transfer missing signature"));
            }
            let is_local_recipient = to_device_id.len() == 32
                && to_device_id.as_slice() == current_state.device_info.device_id.as_slice();
            if is_local_recipient && matches!(mode, TransactionMode::Unilateral) {
                log::warn!(
                    "Transfer signature verified upstream for incoming unilateral transfer; skipping local key check"
                );
            } else {
                verify_operation_signature(
                    &operation,
                    &current_state.device_info.public_key,
                    "Transfer",
                )?;
            }
        }

        // ── Device-key signed operations ──────────────────────────
        Operation::CreateToken { signature, .. } => {
            if !signature.is_empty() {
                verify_operation_signature(
                    &operation,
                    &current_state.device_info.public_key,
                    "CreateToken",
                )?;
            } else {
                return Err(DsmError::invalid_operation("CreateToken missing signature"));
            }
        }
        Operation::Lock { signature, .. } => {
            if !signature.is_empty() {
                verify_operation_signature(
                    &operation,
                    &current_state.device_info.public_key,
                    "Lock",
                )?;
            } else {
                return Err(DsmError::invalid_operation("Lock missing signature"));
            }
        }
        Operation::Unlock { signature, .. } => {
            if !signature.is_empty() {
                verify_operation_signature(
                    &operation,
                    &current_state.device_info.public_key,
                    "Unlock",
                )?;
            } else {
                return Err(DsmError::invalid_operation("Unlock missing signature"));
            }
        }
        Operation::LockToken { signature, .. } => {
            if !signature.is_empty() {
                verify_operation_signature(
                    &operation,
                    &current_state.device_info.public_key,
                    "LockToken",
                )?;
            } else {
                return Err(DsmError::invalid_operation("LockToken missing signature"));
            }
        }
        Operation::UnlockToken { signature, .. } => {
            if !signature.is_empty() {
                verify_operation_signature(
                    &operation,
                    &current_state.device_info.public_key,
                    "UnlockToken",
                )?;
            } else {
                return Err(DsmError::invalid_operation("UnlockToken missing signature"));
            }
        }
        Operation::Generic { signature, .. } => {
            if !signature.is_empty() {
                verify_operation_signature(
                    &operation,
                    &current_state.device_info.public_key,
                    "Generic",
                )?;
            } else {
                return Err(DsmError::invalid_operation("Generic missing signature"));
            }
        }

        // ── DLV operations (embedded public key is the signer) ────
        //
        // NOTE: Signature verification only — semantic vault-state preconditions
        // (e.g., DlvClaim requires Unlocked, DlvInvalidate requires non-terminal)
        // are enforced by LimboVault methods (activate/unlock/claim/invalidate)
        // at the call site. The State struct does not carry per-vault DLV state,
        // so apply_transition cannot perform vault-state checks directly.
        // See TLA+ DSM_BilateralLiveness.tla VaultUnlock/VaultClaim/VaultInvalidate
        // for the formal precondition guards.
        Operation::DlvCreate {
            signature,
            creator_public_key,
            ..
        } => {
            if signature.is_empty() {
                return Err(DsmError::invalid_operation("DlvCreate missing signature"));
            }
            verify_operation_signature(&operation, creator_public_key, "DlvCreate")?;
        }
        Operation::DlvUnlock {
            signature,
            requester_public_key,
            ..
        } => {
            if signature.is_empty() {
                return Err(DsmError::invalid_operation("DlvUnlock missing signature"));
            }
            verify_operation_signature(&operation, requester_public_key, "DlvUnlock")?;
        }
        Operation::DlvClaim {
            signature,
            claimant_public_key,
            ..
        } => {
            if signature.is_empty() {
                return Err(DsmError::invalid_operation("DlvClaim missing signature"));
            }
            verify_operation_signature(&operation, claimant_public_key, "DlvClaim")?;
        }
        Operation::DlvInvalidate {
            signature,
            creator_public_key,
            ..
        } => {
            if signature.is_empty() {
                return Err(DsmError::invalid_operation(
                    "DlvInvalidate missing signature",
                ));
            }
            verify_operation_signature(&operation, creator_public_key, "DlvInvalidate")?;
        }

        // ── Operations that don't carry signatures ────────────────
        // Mint/Burn carry proof_of_authorization/proof_of_ownership but
        // not a SPHINCS+ signature field on the Operation itself; they are
        // verified by their own proof paths.
        // Noop is a no-op sentinel — unsigned by design.
        // Genesis/Create/Update/Delete are legacy structural ops.
        _ => {}
    }

    let operation_for_balance = operation.clone();

    let mut next_state = current_state.clone();
    next_state.state_number += 1;
    next_state.operation = operation;

    // Set entropy directly from provided entropy
    next_state.entropy = new_entropy.to_vec();

    // Update state ID to canonical format
    next_state.id = format!("state_{}", next_state.state_number);

    // Update the previous state hash
    next_state.prev_state_hash = current_state.hash()?;

    // Calculate and update sparse index
    let sparse_indices = calculate_sparse_indices(next_state.state_number)?;
    next_state.sparse_index = crate::types::state_types::SparseIndex::new(sparse_indices);

    // Apply token balance delta for Transfer/Mint/Burn operations on device-canonical
    // transitions only. Bilateral relationship-chain transitions skip this — the bilateral
    // settlement handler applies the delta to the device canonical state separately.
    if !require_bilateral {
        apply_token_balance_delta(&mut next_state, current_state, &operation_for_balance)?;
    }

    // Compute the hash for the new state after balance mutations
    let computed_hash = next_state.compute_hash()?;
    next_state.hash = computed_hash;

    Ok(next_state)
}

/// Apply token balance delta directly within state transition.
///
/// This function is the SINGLE AUTHORITATIVE place where token balances are mutated.
/// It is called from create_next_state BEFORE hash computation, ensuring:
/// - Balance delta is atomic with state change
/// - Hash commits to updated balances
/// - No post-transition patching required
fn apply_token_balance_delta(
    next_state: &mut State,
    current_state: &State,
    operation: &Operation,
) -> Result<(), DsmError> {
    let decode_dlv_lock = |token_id: &Option<Vec<u8>>,
                           locked_amount: &Option<Balance>,
                           op_name: &str|
     -> Result<Option<(String, Balance)>, DsmError> {
        match (token_id.as_ref(), locked_amount.as_ref()) {
            (None, None) => Ok(None),
            (Some(_), None) | (None, Some(_)) => Err(DsmError::invalid_operation(format!(
                "{op_name} requires both token_id and locked_amount when settling locked tokens"
            ))),
            (Some(token_id), Some(locked_amount)) => {
                let token_id_str = std::str::from_utf8(token_id).map_err(|_| {
                    DsmError::invalid_operation(format!(
                        "{op_name} token_id must be valid UTF-8 bytes"
                    ))
                })?;
                if token_id_str.is_empty() {
                    return Err(DsmError::invalid_operation(format!(
                        "{op_name} token_id must not be empty"
                    )));
                }
                Ok(Some((token_id_str.to_string(), locked_amount.clone())))
            }
        }
    };

    match operation {
        Operation::Transfer {
            token_id,
            to_device_id,
            recipient,
            amount,
            ..
        } => {
            let token_id_str = String::from_utf8_lossy(token_id).to_string();
            // §8 Atomicity: all token ops MUST apply balance deltas in the
            // same state transition. `resolve_policy_commit` must now fail
            // closed when no canonical CPTA anchor exists.
            let policy_commit = crate::core::token::resolve_policy_commit(&token_id_str)?;
            let is_recipient = to_device_id.len() == 32
                && to_device_id.as_slice() == current_state.device_info.device_id.as_slice();

            let sender_key = crate::core::token::derive_canonical_balance_key(
                &policy_commit,
                &current_state.device_info.public_key,
                &token_id_str,
            );
            let sender_balance = next_state
                .token_balances
                .get(&sender_key)
                .cloned()
                .unwrap_or_else(|| {
                    Balance::from_state(0, current_state.hash, current_state.state_number)
                });

            if is_recipient {
                // Credit the LOCAL device's balance key (derived from public_key).
                // The `recipient` field in the op contains the device_id, but balance
                // keys are always derived from public_key. Using recipient directly
                // would credit a phantom key that no balance query ever reads.
                let local_credit_key = crate::core::token::derive_canonical_balance_key(
                    &policy_commit,
                    &current_state.device_info.public_key,
                    &token_id_str,
                );
                let local_balance = next_state
                    .token_balances
                    .get(&local_credit_key)
                    .cloned()
                    .unwrap_or_else(|| {
                        Balance::from_state(0, current_state.hash, current_state.state_number)
                    });
                let new_recipient_value = local_balance
                    .value()
                    .checked_add(amount.value())
                    .ok_or_else(|| {
                        DsmError::invalid_operation("Balance overflow on transfer credit")
                    })?;
                next_state.token_balances.insert(
                    local_credit_key,
                    Balance::from_state(
                        new_recipient_value,
                        current_state.hash,
                        current_state.state_number,
                    ),
                );
            } else {
                if sender_balance.value() < amount.value() {
                    return Err(DsmError::insufficient_balance(
                        token_id_str,
                        sender_balance.value(),
                        amount.value(),
                    ));
                }

                let new_sender_balance = Balance::from_state(
                    sender_balance.value() - amount.value(),
                    current_state.hash,
                    current_state.state_number,
                );

                next_state
                    .token_balances
                    .insert(sender_key, new_sender_balance);
                if !recipient.is_empty() && recipient.as_slice() != to_device_id.as_slice() {
                    let recipient_owner = recipient.as_slice();
                    let recipient_key = crate::core::token::derive_canonical_balance_key(
                        &policy_commit,
                        recipient_owner,
                        &token_id_str,
                    );
                    let recipient_balance = next_state
                        .token_balances
                        .get(&recipient_key)
                        .cloned()
                        .unwrap_or_else(|| {
                            Balance::from_state(0, current_state.hash, current_state.state_number)
                        });
                    let new_recipient_value = recipient_balance
                        .value()
                        .checked_add(amount.value())
                        .ok_or_else(|| {
                            DsmError::invalid_operation("Balance overflow on transfer credit")
                        })?;
                    let new_recipient_balance = Balance::from_state(
                        new_recipient_value,
                        current_state.hash,
                        current_state.state_number,
                    );
                    next_state
                        .token_balances
                        .insert(recipient_key, new_recipient_balance);
                }
            }
        }
        Operation::Mint {
            token_id, amount, ..
        } => {
            let token_id_str = String::from_utf8_lossy(token_id).to_string();
            let policy_commit = crate::core::token::resolve_policy_commit(&token_id_str)?;
            let owner_key = crate::core::token::derive_canonical_balance_key(
                &policy_commit,
                &current_state.device_info.public_key,
                &token_id_str,
            );

            let current_balance = next_state
                .token_balances
                .get(&owner_key)
                .cloned()
                .unwrap_or_else(|| {
                    Balance::from_state(0, current_state.hash, current_state.state_number)
                });
            let new_mint_value = current_balance
                .value()
                .checked_add(amount.value())
                .ok_or_else(|| DsmError::invalid_operation("Balance overflow on mint"))?;

            next_state.token_balances.insert(
                owner_key,
                Balance::from_state(
                    new_mint_value,
                    current_state.hash,
                    current_state.state_number,
                ),
            );
        }
        Operation::Burn {
            token_id, amount, ..
        } => {
            let token_id_str = String::from_utf8_lossy(token_id).to_string();
            let policy_commit = crate::core::token::resolve_policy_commit(&token_id_str)?;
            let owner_key = crate::core::token::derive_canonical_balance_key(
                &policy_commit,
                &current_state.device_info.public_key,
                &token_id_str,
            );

            let owner_balance = next_state
                .token_balances
                .get(&owner_key)
                .cloned()
                .unwrap_or_else(|| {
                    Balance::from_state(0, current_state.hash, current_state.state_number)
                });
            if owner_balance.value() < amount.value() {
                return Err(DsmError::insufficient_balance(
                    token_id_str,
                    owner_balance.value(),
                    amount.value(),
                ));
            }

            next_state.token_balances.insert(
                owner_key,
                Balance::from_state(
                    owner_balance.value() - amount.value(),
                    current_state.hash,
                    current_state.state_number,
                ),
            );
        }
        Operation::DlvCreate {
            token_id,
            locked_amount,
            creator_public_key,
            ..
        } => {
            if let Some((token_id_str, amount)) =
                decode_dlv_lock(token_id, locked_amount, "DlvCreate")?
            {
                if amount.value() > 0 {
                    let policy_commit = crate::core::token::resolve_policy_commit(&token_id_str)?;
                    let creator_key = crate::core::token::derive_canonical_balance_key(
                        &policy_commit,
                        creator_public_key.as_slice(),
                        &token_id_str,
                    );
                    let creator_balance = next_state
                        .token_balances
                        .get(&creator_key)
                        .cloned()
                        .unwrap_or_else(|| {
                            Balance::from_state(0, current_state.hash, current_state.state_number)
                        });
                    if creator_balance.value() < amount.value() {
                        return Err(DsmError::insufficient_balance(
                            token_id_str,
                            creator_balance.value(),
                            amount.value(),
                        ));
                    }
                    next_state.token_balances.insert(
                        creator_key,
                        Balance::from_state(
                            creator_balance.value() - amount.value(),
                            current_state.hash,
                            current_state.state_number,
                        ),
                    );
                }
            }
        }
        Operation::DlvInvalidate {
            creator_public_key,
            token_id,
            locked_amount,
            ..
        } => {
            if let Some((token_id_str, amount)) =
                decode_dlv_lock(token_id, locked_amount, "DlvInvalidate")?
            {
                if amount.value() > 0 {
                    let policy_commit = crate::core::token::resolve_policy_commit(&token_id_str)?;
                    let creator_key = crate::core::token::derive_canonical_balance_key(
                        &policy_commit,
                        creator_public_key.as_slice(),
                        &token_id_str,
                    );
                    let creator_balance = next_state
                        .token_balances
                        .get(&creator_key)
                        .cloned()
                        .unwrap_or_else(|| {
                            Balance::from_state(0, current_state.hash, current_state.state_number)
                        });
                    let restored_value = creator_balance
                        .value()
                        .checked_add(amount.value())
                        .ok_or_else(|| {
                            DsmError::invalid_operation(
                                "Balance overflow on DLV invalidation restore",
                            )
                        })?;
                    next_state.token_balances.insert(
                        creator_key,
                        Balance::from_state(
                            restored_value,
                            current_state.hash,
                            current_state.state_number,
                        ),
                    );
                }
            }
        }
        Operation::DlvClaim {
            claimant_public_key,
            token_id,
            locked_amount,
            ..
        } => {
            if let Some((token_id_str, amount)) =
                decode_dlv_lock(token_id, locked_amount, "DlvClaim")?
            {
                if amount.value() > 0 {
                    let policy_commit = crate::core::token::resolve_policy_commit(&token_id_str)?;
                    let claimant_key = crate::core::token::derive_canonical_balance_key(
                        &policy_commit,
                        claimant_public_key.as_slice(),
                        &token_id_str,
                    );
                    let claimant_balance = next_state
                        .token_balances
                        .get(&claimant_key)
                        .cloned()
                        .unwrap_or_else(|| {
                            Balance::from_state(0, current_state.hash, current_state.state_number)
                        });
                    let released_value = claimant_balance
                        .value()
                        .checked_add(amount.value())
                        .ok_or_else(|| {
                            DsmError::invalid_operation("Balance overflow on DLV claim release")
                        })?;
                    next_state.token_balances.insert(
                        claimant_key,
                        Balance::from_state(
                            released_value,
                            current_state.hash,
                            current_state.state_number,
                        ),
                    );
                }
            }
        }
        _ => {}
    }

    Ok(())
}

/// Convert operations verification type to local verification type
fn to_local_verification_type(
    verification: &crate::types::operations::VerificationType,
) -> VerificationType {
    match verification {
        crate::types::operations::VerificationType::Standard => VerificationType::Standard,
        crate::types::operations::VerificationType::Enhanced => VerificationType::Bilateral,
        crate::types::operations::VerificationType::Custom(_) => VerificationType::Directory,
        crate::types::operations::VerificationType::Bilateral => VerificationType::Bilateral,
        crate::types::operations::VerificationType::Directory => VerificationType::Directory,
        crate::types::operations::VerificationType::StandardBilateral => {
            VerificationType::Bilateral
        }
        crate::types::operations::VerificationType::PreCommitted => VerificationType::Standard,
        crate::types::operations::VerificationType::UnilateralIdentityAnchor => {
            VerificationType::Standard
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::state_types::State;
    use crate::types::operations::{Operation, TransactionMode, VerificationType as OpVerificationType};
    use crate::types::token_types::Balance;
    use crate::crypto::sphincs::{generate_sphincs_keypair, sphincs_sign};
    use std::collections::HashMap;

    fn create_test_state(state_number: u64) -> State {
        use crate::types::state_types::DeviceInfo;

        let device_info = DeviceInfo {
            device_id: TEST_DEVICE_ID,
            public_key: vec![1, 2, 3, 4],
            metadata: Default::default(),
        };

        let mut entropy = [0u8; 32];
        entropy[0..4].copy_from_slice(&[1, 2, 3, 4]);
        let mut state = State::new_genesis(entropy, device_info);
        state.state_number = state_number;
        state.id = format!("state_{}", state_number);

        if state_number > 0 {
            // For non-genesis states, set a proper previous state hash (32 bytes)
            state.prev_state_hash = [1; 32];
        }

        // Generate a proper 32-byte hash using blake3
        let state_data = format!("test_state_{}", state_number);
        state.hash = *blake3::hash(state_data.as_bytes()).as_bytes();

        state
    }

    /// Canonical balance key for a non-ERA token in test states.
    fn test_balance_key(state: &State, token_id: &[u8]) -> String {
        let token_id_str = String::from_utf8_lossy(token_id);
        format!("test:{}|{token_id_str}", state.state_number)
    }

    fn create_test_state_with_keypair(state_number: u64) -> (State, Vec<u8>, Vec<u8>) {
        let (pk, sk) =
            generate_sphincs_keypair().unwrap_or_else(|e| panic!("keypair generation failed: {e}"));
        let mut state = create_test_state(state_number);
        state.device_info.public_key = pk.clone();
        (state, pk, sk)
    }

    fn signed_transfer_op_amount(
        sk: &[u8],
        state_hash: [u8; 32],
        nonce: Vec<u8>,
        message: &str,
        token_id: &str,
        amount: u64,
    ) -> Operation {
        let mut op = Operation::Transfer {
            amount: Balance::from_state(amount, state_hash, 0),
            token_id: token_id.as_bytes().to_vec(),
            to_device_id: b"recipient".to_vec(),
            nonce,
            pre_commit: None,
            recipient: b"recipient".to_vec(),
            message: message.to_string(),
            mode: TransactionMode::Bilateral,
            verification: OpVerificationType::Standard,
            to: b"recipient".to_vec(),
            signature: Vec::new(),
        };

        let bytes = op.to_bytes();
        let sig = sphincs_sign(sk, &bytes).unwrap_or_else(|e| panic!("sign transfer failed: {e}"));
        if let Operation::Transfer { signature, .. } = &mut op {
            *signature = sig;
        }

        op
    }

    fn signed_transfer_op(
        sk: &[u8],
        state_hash: [u8; 32],
        nonce: Vec<u8>,
        message: &str,
    ) -> Operation {
        signed_transfer_op_amount(sk, state_hash, nonce, message, "ERA", 10)
    }

    fn signed_mint_op_amount(sk: &[u8], token_id: &str, amount: u64) -> Operation {
        let mut op = Operation::Mint {
            amount: {
                let mut balance = Balance::zero();
                balance.update_add(amount);
                balance
            },
            token_id: token_id.as_bytes().to_vec(),
            authorized_by: b"authority".to_vec(),
            proof_of_authorization: vec![],
            message: "test mint".to_string(),
        };

        let bytes = op.to_bytes();
        let sig = sphincs_sign(sk, &bytes).unwrap_or_else(|e| panic!("sign mint failed: {e}"));
        if let Operation::Mint {
            proof_of_authorization,
            ..
        } = &mut op
        {
            *proof_of_authorization = sig;
        }

        op
    }

    fn signed_mint_op(sk: &[u8]) -> Operation {
        signed_mint_op_amount(sk, "token2", 100)
    }

    fn signed_burn_op_amount(sk: &[u8], token_id: &str, amount: u64) -> Operation {
        let mut op = Operation::Burn {
            amount: {
                let mut balance = Balance::zero();
                balance.update_add(amount);
                balance
            },
            token_id: token_id.as_bytes().to_vec(),
            proof_of_ownership: vec![],
            message: "test burn".to_string(),
        };

        let bytes = op.to_bytes();
        let sig = sphincs_sign(sk, &bytes).unwrap_or_else(|e| panic!("sign burn failed: {e}"));
        if let Operation::Burn {
            proof_of_ownership, ..
        } = &mut op
        {
            *proof_of_ownership = sig;
        }

        op
    }

    fn signed_update_op(sk: &[u8], identity_id: &str) -> Operation {
        let mut op = Operation::Update {
            message: "test update".to_string(),
            identity_id: identity_id.as_bytes().to_vec(),
            updated_data: vec![1, 2, 3],
            proof: vec![],
            forward_link: None,
        };

        let bytes = op.to_bytes();
        let sig = sphincs_sign(sk, &bytes).unwrap_or_else(|e| panic!("sign update failed: {e}"));
        if let Operation::Update { proof, .. } = &mut op {
            *proof = sig;
        }

        op
    }

    #[test]
    fn test_state_transition_new() {
        let (_state, _pk, sk) = create_test_state_with_keypair(0);
        let operation = signed_transfer_op(&sk, [0u8; 32], vec![1, 2, 3, 4], "signed transfer");
        let entropy = Some(vec![1, 2, 3]);
        let encapsulated_entropy = Some(vec![4, 5, 6]);

        let transition = StateTransition::new(
            operation.clone(),
            entropy.clone(),
            encapsulated_entropy.clone(),
            &blake3::hash(b"test_device").as_bytes().clone(),
        );

        assert_eq!(transition.operation, operation);
        assert_eq!(transition.new_entropy, entropy);
        assert_eq!(transition.encapsulated_entropy, encapsulated_entropy);
        // `StateTransition::new` must preserve the caller-provided device id.
        // This test previously asserted a fixed TEST_DEVICE_ID, which masked real regressions.
        assert_eq!(
            transition.device_id,
            *blake3::hash(b"test_device").as_bytes()
        );
        assert!(transition.flags.is_empty());
        assert!(transition.position_sequence.is_none());
        assert!(transition.token_balances.is_none());
    }

    #[test]
    fn test_state_transition_with_flags() {
        let (_state, _pk, sk) = create_test_state_with_keypair(0);
        let operation = signed_transfer_op(&sk, [0u8; 32], vec![7, 8, 9], "signed transfer");
        let flags = vec!["urgent".to_string(), "verified".to_string()];

        let transition =
            StateTransition::new(operation, None, None, &TEST_DEVICE_ID).with_flags(flags.clone());

        assert_eq!(transition.flags, flags);
    }

    #[test]
    fn test_state_transition_with_token_balances() {
        let (_state, _pk, sk) = create_test_state_with_keypair(0);
        let operation = signed_transfer_op(&sk, [0u8; 32], vec![10, 11, 12], "signed transfer");
        let mut balances = HashMap::new();
        balances.insert("token1".to_string(), {
            let mut balance = Balance::zero();
            balance.update_add(100);
            balance
        });
        balances.insert("token2".to_string(), {
            let mut balance = Balance::zero();
            balance.update_add(50);
            balance
        });

        let transition = StateTransition::new(operation, None, None, &TEST_DEVICE_ID)
            .with_token_balances(balances.clone());

        assert_eq!(transition.token_balances, Some(balances));
    }

    #[test]
    fn test_state_transition_with_forward_commitment() {
        let (_state, _pk, sk) = create_test_state_with_keypair(0);
        let operation = signed_transfer_op(&sk, [0u8; 32], vec![13, 14, 15], "signed transfer");
        let mut fixed_params = HashMap::new();
        fixed_params.insert("param1".to_string(), vec![1, 2, 3]);
        let mut variable_params = HashSet::new();
        variable_params.insert("var1".to_string());

        let transition = StateTransition::new(operation, None, None, &TEST_DEVICE_ID)
            .with_forward_commitment(
                "transfer",
                fixed_params,
                variable_params,
                100,
                "counterparty123",
            );

        assert!(transition.forward_commitment.is_some());
        let commitment = transition
            .forward_commitment
            .unwrap_or_else(|| panic!("forward_commitment must be present in this test"));
        assert_eq!(commitment.operation_type, "transfer");
        assert_eq!(commitment.min_state_number, 100);
        assert_eq!(
            commitment.counterparty_id,
            *crate::crypto::blake3::domain_hash("DSM/counterparty-id", b"counterparty123")
                .as_bytes()
        );
    }

    #[test]
    fn test_finalize_without_position_sequence() {
        let (_state, _pk, sk) = create_test_state_with_keypair(1);
        let op = signed_transfer_op(&sk, [0u8; 32], vec![16, 17, 18], "signed transfer");
        let mut transition = StateTransition::new(op, None, None, &TEST_DEVICE_ID);
        let state = create_test_state(1);

        let result = transition.finalize(&state);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Position sequence is missing"));
    }

    #[test]
    fn test_sign_forward_commitment_without_commitment() {
        let (_state, _pk, sk) = create_test_state_with_keypair(0);
        let op = signed_transfer_op(&sk, [0u8; 32], vec![19, 20, 21], "signed transfer");
        let mut transition = StateTransition::new(op, None, None, &TEST_DEVICE_ID);
        let signature = vec![1, 2, 3, 4];

        let result = transition.sign_forward_commitment(signature);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("No forward commitment exists to sign"));
    }

    #[test]
    fn test_sign_forward_commitment_success() {
        let (_state, _pk, sk) = create_test_state_with_keypair(0);
        let op = signed_transfer_op(&sk, [0u8; 32], vec![22, 23, 24], "signed transfer");
        let mut transition = StateTransition::new(op, None, None, &TEST_DEVICE_ID)
            .with_forward_commitment(
                "transfer",
                HashMap::new(),
                HashSet::new(),
                100,
                "counterparty123",
            );
        let signature = vec![1, 2, 3, 4];

        let result = transition.sign_forward_commitment(signature.clone());
        assert!(result.is_ok());
        assert_eq!(
            transition
                .forward_commitment
                .unwrap_or_else(|| panic!("forward_commitment must be present"))
                .entity_signature,
            Some(signature)
        );
    }

    #[test]
    fn test_cosign_forward_commitment_success() {
        let (_state, _pk, sk) = create_test_state_with_keypair(0);
        let op = signed_transfer_op(&sk, [0u8; 32], vec![25, 26, 27], "signed transfer");
        let mut transition = StateTransition::new(op, None, None, &TEST_DEVICE_ID)
            .with_forward_commitment(
                "transfer",
                HashMap::new(),
                HashSet::new(),
                100,
                "counterparty123",
            );
        let signature = vec![5, 6, 7, 8];

        let result = transition.cosign_forward_commitment(signature.clone());
        assert!(result.is_ok());
        assert_eq!(
            transition
                .forward_commitment
                .unwrap_or_else(|| panic!("forward_commitment must be present"))
                .counterparty_signature,
            Some(signature)
        );
    }

    #[test]
    fn test_operation_affects_balance() {
        let (_state, _pk, sk) = create_test_state_with_keypair(0);
        let transfer_op = signed_transfer_op(&sk, [0u8; 32], vec![28, 29, 30], "test transfer");

        assert!(transfer_op.affects_balance(b"ERA"));
        assert!(!transfer_op.affects_balance(b"token2"));
        let mint_op = signed_mint_op(&sk);

        assert!(mint_op.affects_balance(b"token2"));
        assert!(!mint_op.affects_balance(b"ERA"));
    }

    #[test]
    fn test_calculate_sparse_indices_genesis() {
        let result = calculate_sparse_indices(0);
        assert!(result.is_ok());
        assert!(result
            .unwrap_or_else(|e| panic!("sparse indices should be ok: {e}"))
            .is_empty());
    }

    #[test]
    fn test_calculate_sparse_indices_state_1() {
        let result = calculate_sparse_indices(1);
        assert!(result.is_ok());
        let indices = result.unwrap_or_else(|e| panic!("sparse indices should be ok: {e}"));
        assert!(indices.contains(&0));
        assert_eq!(indices.len(), 1);
    }

    #[test]
    fn test_calculate_sparse_indices_state_2() {
        let result = calculate_sparse_indices(2);
        assert!(result.is_ok());
        let indices = result.unwrap_or_else(|e| panic!("sparse indices should be ok: {e}"));
        assert!(indices.contains(&0)); // genesis
        assert!(indices.contains(&1)); // direct predecessor
    }

    #[test]
    fn test_calculate_sparse_indices_state_8() {
        let result = calculate_sparse_indices(8);
        assert!(result.is_ok());
        let indices = result.unwrap_or_else(|e| panic!("sparse indices should be ok: {e}"));
        assert!(indices.contains(&0)); // genesis
        assert!(indices.contains(&7)); // direct predecessor
                                       // Should also contain power-of-2 distances
    }

    #[test]
    fn test_generate_position_sequence() {
        let (state, _pk, sk) = create_test_state_with_keypair(1);
        let operation = signed_transfer_op(&sk, state.hash, vec![31, 32, 33], "signed transfer");
        let entropy = vec![1, 2, 3, 4];

        let result = generate_position_sequence(&state, &operation, &entropy);
        assert!(result.is_ok());

        let sequence = result.unwrap_or_else(|e| panic!("position sequence should be ok: {e}"));
        assert!(!sequence.positions.is_empty());
        assert!(!sequence.seed.is_empty());
    }

    #[test]
    fn test_create_transition() {
        let (state, _pk, sk) = create_test_state_with_keypair(1);
        let operation = signed_transfer_op(&sk, state.hash, vec![34, 35, 36], "signed transfer");
        let entropy = vec![1, 2, 3, 4];

        let result = create_transition(&state, operation.clone(), &entropy);
        assert!(result.is_ok());

        let transition = result.unwrap_or_else(|e| panic!("transition should be ok: {e}"));
        assert_eq!(transition.operation, operation);
        assert_eq!(transition.new_entropy, Some(entropy));
        assert!(transition.position_sequence.is_some());
        assert!(transition.prev_state_hash.is_some());
    }

    #[test]
    fn test_verify_transition_integrity_invalid_state_number() {
        let (prev_state, _pk, sk) = create_test_state_with_keypair(1);
        let mut current_state = create_test_state(3); // Invalid jump
        current_state.prev_state_hash = prev_state.hash;
        let operation =
            signed_transfer_op(&sk, prev_state.hash, vec![37, 38, 39], "signed transfer");

        let result = verify_transition_integrity(&prev_state, &current_state, &operation);
        assert!(result.is_ok());
        assert!(!result.unwrap_or_else(|e| panic!("verification should return Ok(false): {e}")));
        // Should be false
    }

    #[test]
    fn test_verify_transition_integrity_invalid_hash_chain() {
        let (prev_state, _pk, sk) = create_test_state_with_keypair(1);
        let mut current_state = create_test_state(2);
        current_state.prev_state_hash = [9; 32]; // Wrong hash
        let operation =
            signed_transfer_op(&sk, prev_state.hash, vec![43, 44, 45], "signed transfer");

        let result = verify_transition_integrity(&prev_state, &current_state, &operation);
        assert!(result.is_ok());
        assert!(!result.unwrap_or_else(|e| panic!("verification should return Ok(false): {e}")));
        // Should be false
    }

    #[test]
    fn test_verify_token_balance_consistency_mint() {
        let mut prev_state = create_test_state(1);
        let mut current_state = create_test_state(2);
        let key = test_balance_key(&prev_state, b"token1");

        prev_state.token_balances.insert(key.clone(), {
            let mut balance = Balance::zero();
            balance.update_add(100);
            balance
        });
        current_state.token_balances.insert(key.clone(), {
            let mut balance = Balance::zero();
            balance.update_add(150);
            balance
        });
        let (_state, _pk, sk) = create_test_state_with_keypair(0);
        let mint_op = signed_mint_op_amount(&sk, "token1", 50);

        let result = verify_token_balance_consistency(&prev_state, &current_state, &mint_op);
        assert!(result.is_ok());
        assert!(result.unwrap_or_else(|e| panic!("mint consistency should be ok: {e}")));
    }

    #[test]
    fn test_verify_token_balance_consistency_transfer() {
        let mut prev_state = create_test_state(1);
        let mut current_state = create_test_state(2);
        let key = test_balance_key(&prev_state, b"token1");

        prev_state.token_balances.insert(key.clone(), {
            let mut balance = Balance::zero();
            balance.update_add(100);
            balance
        });
        current_state.token_balances.insert(key.clone(), {
            let mut balance = Balance::zero();
            balance.update_add(50);
            balance
        });
        let (_state, _pk, sk) = create_test_state_with_keypair(0);
        let transfer_op = signed_transfer_op_amount(
            &sk,
            prev_state.hash,
            vec![46, 47, 48],
            "test transfer",
            "token1",
            50,
        );

        let result = verify_token_balance_consistency(&prev_state, &current_state, &transfer_op);
        assert!(result.is_ok());
        assert!(result.unwrap_or_else(|e| panic!("transfer consistency should be ok: {e}")));
    }

    #[test]
    fn test_verify_token_balance_consistency_transfer_recipient_increase() {
        let mut prev_state = create_test_state(1);
        let mut current_state = create_test_state(2);
        let key = test_balance_key(&prev_state, b"token1");

        prev_state.token_balances.insert(key.clone(), {
            let mut balance = Balance::zero();
            balance.update_add(10);
            balance
        });
        current_state.token_balances.insert(key.clone(), {
            let mut balance = Balance::zero();
            balance.update_add(60);
            balance
        });

        let transfer_op = Operation::Transfer {
            amount: Balance::from_state(50, prev_state.hash, 0),
            token_id: b"token1".to_vec(),
            to_device_id: TEST_DEVICE_ID.to_vec(),
            nonce: vec![1, 2, 3],
            pre_commit: None,
            recipient: TEST_DEVICE_ID.to_vec(),
            message: "incoming".to_string(),
            mode: TransactionMode::Unilateral,
            verification: OpVerificationType::Standard,
            to: b"recipient".to_vec(),
            signature: vec![9u8],
        };

        let result = verify_token_balance_consistency(&prev_state, &current_state, &transfer_op);
        assert!(result.is_ok());
        assert!(result.unwrap_or_else(|e| panic!("recipient balance should increase: {e}")));
    }

    #[test]
    fn test_create_next_state() {
        let (mut current_state, _pk, sk) = create_test_state_with_keypair(5);

        // Seed sender balance so the transfer has sufficient funds
        let era_pc = crate::core::token::builtin_policy_commit_for_token("ERA").unwrap();
        let sender_key = crate::core::token::derive_canonical_balance_key(
            &era_pc,
            &current_state.device_info.public_key,
            "ERA",
        );
        current_state
            .token_balances
            .insert(sender_key, Balance::from_state(1000, current_state.hash, 5));

        let operation =
            signed_transfer_op(&sk, current_state.hash, vec![49, 50, 51], "signed transfer");
        let entropy = vec![1, 2, 3, 4];

        let result = create_next_state(
            &current_state,
            operation.clone(),
            &entropy,
            &super::VerificationType::Standard,
            false,
        );

        assert!(result.is_ok());
        let next_state = result.unwrap_or_else(|e| panic!("next state should be ok: {e}"));
        assert_eq!(next_state.state_number, 6);
        assert_eq!(next_state.operation, operation);
        assert_eq!(next_state.entropy, entropy);
        assert_eq!(next_state.id, "state_6");
    }

    #[test]
    fn test_create_next_state_incoming_transfer_adds_balance() {
        // Whitepaper §8: balance delta is applied atomically inside create_next_state.
        // When this device is the recipient (to_device_id == local device_id),
        // apply_token_balance_delta credits using the device's public_key (not device_id),
        // because all balance reads derive keys from public_key.
        let current_state = create_test_state(1);
        let policy_commit =
            crate::core::token::builtin_policy_commit_for_token("ERA").expect("ERA policy commit");
        let recipient_key = crate::core::token::derive_canonical_balance_key(
            &policy_commit,
            &current_state.device_info.public_key,
            "ERA",
        );

        let operation = Operation::Transfer {
            amount: Balance::from_state(10, current_state.hash, 0),
            token_id: b"ERA".to_vec(),
            to_device_id: TEST_DEVICE_ID.to_vec(),
            nonce: vec![1, 2, 3],
            pre_commit: None,
            recipient: TEST_DEVICE_ID.to_vec(),
            message: "incoming".to_string(),
            mode: TransactionMode::Unilateral,
            verification: OpVerificationType::Standard,
            to: b"recipient".to_vec(),
            signature: vec![1u8],
        };

        let entropy = vec![1, 2, 3, 4];
        let next_state = create_next_state(
            &current_state,
            operation,
            &entropy,
            &super::VerificationType::Standard,
            false,
        )
        .unwrap_or_else(|e| panic!("incoming transfer should succeed: {e}"));

        let bal = next_state
            .token_balances
            .get(&recipient_key)
            .unwrap_or_else(|| panic!("recipient balance key should exist after credit"));
        assert_eq!(bal.value(), 10, "receiver should be credited 10 ERA");
    }

    #[test]
    fn test_apply_token_balance_delta_dlv_invalidate_returns_locked_tokens() {
        let current_state = create_test_state(1);
        let mut next_state = current_state.clone();
        let era_pc = crate::core::token::builtin_policy_commit_for_token("ERA").expect("ERA");
        let creator_key = crate::core::token::derive_canonical_balance_key(
            &era_pc,
            &current_state.device_info.public_key,
            "ERA",
        );

        let op = Operation::DlvInvalidate {
            vault_id: vec![0x10; 32],
            reason: "timeout".into(),
            creator_public_key: current_state.device_info.public_key.clone(),
            token_id: Some(b"ERA".to_vec()),
            locked_amount: Some(Balance::from_state(
                15,
                current_state.hash,
                current_state.state_number,
            )),
            signature: vec![0x01; 8],
            mode: TransactionMode::Unilateral,
        };

        apply_token_balance_delta(&mut next_state, &current_state, &op)
            .expect("DLV invalidate balance delta should apply");

        let bal = next_state
            .token_balances
            .get(&creator_key)
            .unwrap_or_else(|| panic!("creator balance key should be credited"));
        assert_eq!(bal.value(), 15);
    }

    #[test]
    fn test_create_next_state_outgoing_transfer_with_device_id_recipient_only_debits_sender() {
        let (mut current_state, _pk, sk) = create_test_state_with_keypair(1);
        let policy_commit =
            crate::core::token::builtin_policy_commit_for_token("ERA").expect("ERA policy commit");
        let sender_key = crate::core::token::derive_canonical_balance_key(
            &policy_commit,
            &current_state.device_info.public_key,
            "ERA",
        );
        let recipient_device_id = [0x55u8; 32];
        let phantom_key = crate::core::token::derive_canonical_balance_key(
            &policy_commit,
            &recipient_device_id,
            "ERA",
        );
        current_state.token_balances.insert(
            sender_key.clone(),
            Balance::from_state(100, current_state.hash, 1),
        );

        let operation = Operation::Transfer {
            amount: Balance::from_state(10, current_state.hash, 1),
            token_id: b"ERA".to_vec(),
            to_device_id: recipient_device_id.to_vec(),
            nonce: vec![1, 2, 3],
            pre_commit: None,
            recipient: recipient_device_id.to_vec(),
            message: "outgoing".to_string(),
            mode: TransactionMode::Unilateral,
            verification: OpVerificationType::Standard,
            to: b"recipient".to_vec(),
            signature: {
                let unsigned = Operation::Transfer {
                    amount: Balance::from_state(10, current_state.hash, 1),
                    token_id: b"ERA".to_vec(),
                    to_device_id: recipient_device_id.to_vec(),
                    nonce: vec![1, 2, 3],
                    pre_commit: None,
                    recipient: recipient_device_id.to_vec(),
                    message: "outgoing".to_string(),
                    mode: TransactionMode::Unilateral,
                    verification: OpVerificationType::Standard,
                    to: b"recipient".to_vec(),
                    signature: Vec::new(),
                };
                crate::crypto::sphincs::sphincs_sign(&sk, &unsigned.to_bytes())
                    .expect("sign outgoing transfer")
            },
        };

        let next_state = create_next_state(
            &current_state,
            operation,
            &[7, 8, 9, 10],
            &super::VerificationType::Standard,
            false,
        )
        .expect("outgoing transfer should succeed");

        assert_eq!(
            next_state
                .token_balances
                .get(&sender_key)
                .expect("sender balance should exist")
                .value(),
            90
        );
        assert!(
            !next_state.token_balances.contains_key(&phantom_key),
            "device-id recipient must not create a phantom recipient balance entry"
        );
    }

    #[test]
    fn test_to_local_verification_type() {
        use crate::types::operations::VerificationType as OpVerificationType;

        assert!(matches!(
            to_local_verification_type(&OpVerificationType::Standard),
            super::VerificationType::Standard
        ));

        assert!(matches!(
            to_local_verification_type(&OpVerificationType::Enhanced),
            super::VerificationType::Bilateral
        ));

        assert!(matches!(
            to_local_verification_type(&OpVerificationType::Directory),
            super::VerificationType::Directory
        ));
    }

    // ===== New Edge Case Tests =====

    #[test]
    fn test_calculate_sparse_indices_large_state_number() {
        // Test with a large state number to ensure power-of-2 algorithm scales
        let result = calculate_sparse_indices(1024);
        assert!(result.is_ok());
        let indices = result.unwrap_or_else(|e| panic!("sparse indices should be ok: {e}"));

        // Must contain genesis and direct predecessor
        assert!(indices.contains(&0), "Must contain genesis");
        assert!(indices.contains(&1023), "Must contain direct predecessor");

        // 1024 in binary is 10000000000, so only one bit is set
        // The algorithm will compute 1024 - 1024 = 0
        // So we should have [0, 1023] after the explicit additions
        assert_eq!(
            indices.len(),
            2,
            "1024 should have exactly 2 indices: 0 and 1023"
        );

        // Verify sorted order
        for i in 1..indices.len() {
            assert!(indices[i - 1] < indices[i], "Indices must be sorted");
        }
    }

    #[test]
    fn test_calculate_sparse_indices_power_of_two_states() {
        // State 16 (binary: 10000) should have specific sparse references
        let result = calculate_sparse_indices(16);
        assert!(result.is_ok());
        let indices = result.unwrap_or_else(|e| panic!("sparse indices should be ok: {e}"));

        assert!(indices.contains(&0)); // genesis
        assert!(indices.contains(&15)); // direct predecessor
    }

    #[test]
    fn test_verify_transition_integrity_missing_genesis_reference() {
        let (prev_state, _pk, sk) = create_test_state_with_keypair(1);
        let mut current_state = create_test_state(6);
        current_state.prev_state_hash = prev_state.hash;
        let operation =
            signed_transfer_op(&sk, prev_state.hash, vec![52, 53, 54], "signed transfer");
        // Manually set sparse indices without genesis
        current_state.sparse_index = crate::types::state_types::SparseIndex::new(vec![5]);
        let result = verify_transition_integrity(&prev_state, &current_state, &operation);

        assert!(result.is_ok());
        assert!(!result.unwrap_or_else(|e| panic!("should return false for missing genesis: {e}")));
    }

    #[test]
    fn test_verify_transition_integrity_missing_predecessor() {
        let (prev_state, _pk, sk) = create_test_state_with_keypair(5);
        let mut current_state = create_test_state(6);
        current_state.prev_state_hash = prev_state.hash;

        // Manually set sparse indices with genesis but without direct predecessor
        current_state.sparse_index = crate::types::state_types::SparseIndex::new(vec![0, 2, 4]);

        let operation =
            signed_transfer_op(&sk, prev_state.hash, vec![55, 56, 57], "signed transfer");
        let result = verify_transition_integrity(&prev_state, &current_state, &operation);

        assert!(result.is_ok());
        assert!(
            !result.unwrap_or_else(|e| panic!("should return false for missing predecessor: {e}"))
        );
    }

    #[test]
    fn test_verify_transition_integrity_invalid_computed_hash() {
        let (prev_state, _pk, sk) = create_test_state_with_keypair(1);
        let mut current_state = create_test_state(2);
        current_state.prev_state_hash = prev_state.hash;

        // Corrupt the hash to not match computed hash
        current_state.hash = [255; 32];

        let operation =
            signed_transfer_op(&sk, prev_state.hash, vec![58, 59, 60], "signed transfer");
        let result = verify_transition_integrity(&prev_state, &current_state, &operation);

        assert!(result.is_ok());
        assert!(!result.unwrap_or_else(|e| panic!("should return false for invalid hash: {e}")));
    }

    #[test]
    fn test_verify_bilateral_transition_missing_relationship_context() {
        let current_state = create_test_state(1);
        let mut next_state = create_test_state(2);

        // Create relationship context for current but not next
        let mut current_with_rel = current_state.clone();
        current_with_rel.relationship_context =
            Some(crate::types::state_types::RelationshipContext {
                entity_id: *blake3::hash(b"entity_device").as_bytes(),
                entity_state_number: 1,
                counterparty_id: *blake3::hash(b"counterparty123").as_bytes(),
                counterparty_state_number: 5,
                counterparty_public_key: vec![1, 2, 3],
                relationship_hash: vec![4, 5, 6],
                active: true,
                chain_tip_id: None,
                last_bilateral_state_hash: None,
            });

        next_state.relationship_context = None;

        let result = verify_bilateral_transition(&current_with_rel, &next_state);
        assert!(result.is_ok());
        assert!(!result.unwrap_or_else(|e| panic!(
            "should return false for missing relationship context: {e}"
        )));
    }

    #[test]
    fn test_verify_bilateral_transition_counterparty_mismatch() {
        let current_state = create_test_state(1);
        let next_state = create_test_state(2);

        let mut current_with_rel = current_state.clone();
        current_with_rel.relationship_context =
            Some(crate::types::state_types::RelationshipContext {
                entity_id: *blake3::hash(b"entity_device").as_bytes(),
                entity_state_number: 1,
                counterparty_id: *blake3::hash(b"counterparty_A").as_bytes(),
                counterparty_state_number: 5,
                counterparty_public_key: vec![1, 2, 3],
                relationship_hash: vec![4, 5, 6],
                active: true,
                chain_tip_id: None,
                last_bilateral_state_hash: None,
            });

        let mut next_with_rel = next_state.clone();
        next_with_rel.relationship_context = Some(crate::types::state_types::RelationshipContext {
            entity_id: *blake3::hash(b"entity_device").as_bytes(),
            entity_state_number: 2,
            counterparty_id: *blake3::hash(b"counterparty_B").as_bytes(), // Different counterparty
            counterparty_state_number: 6,
            counterparty_public_key: vec![1, 2, 3],
            relationship_hash: vec![4, 5, 6],
            active: true,
            chain_tip_id: None,
            last_bilateral_state_hash: None,
        });

        let result = verify_bilateral_transition(&current_with_rel, &next_with_rel);
        assert!(result.is_ok());
        assert!(!result
            .unwrap_or_else(|e| panic!("should return false for counterparty mismatch: {e}")));
    }

    #[test]
    fn test_verify_bilateral_transition_non_advancing_state() {
        let current_state = create_test_state(1);
        let next_state = create_test_state(2);

        let mut current_with_rel = current_state.clone();
        current_with_rel.relationship_context =
            Some(crate::types::state_types::RelationshipContext {
                entity_id: *blake3::hash(b"entity_device").as_bytes(),
                entity_state_number: 1,
                counterparty_id: *blake3::hash(b"counterparty123").as_bytes(),
                counterparty_state_number: 10,
                counterparty_public_key: vec![1, 2, 3],
                relationship_hash: vec![4, 5, 6],
                active: true,
                chain_tip_id: None,
                last_bilateral_state_hash: None,
            });

        let mut next_with_rel = next_state.clone();
        next_with_rel.relationship_context = Some(crate::types::state_types::RelationshipContext {
            entity_id: *blake3::hash(b"entity_device").as_bytes(),
            entity_state_number: 2,
            counterparty_id: *blake3::hash(b"counterparty123").as_bytes(),
            counterparty_state_number: 9, // State number decreased!
            counterparty_public_key: vec![1, 2, 3],
            relationship_hash: vec![4, 5, 6],
            active: true,
            chain_tip_id: None,
            last_bilateral_state_hash: None,
        });

        let result = verify_bilateral_transition(&current_with_rel, &next_with_rel);
        assert!(result.is_ok());
        assert!(!result
            .unwrap_or_else(|e| panic!("should return false for non-advancing state number: {e}")));
    }

    #[test]
    fn test_verify_bilateral_transition_success() {
        let current_state = create_test_state(1);
        let next_state = create_test_state(2);

        let mut current_with_rel = current_state.clone();
        current_with_rel.relationship_context =
            Some(crate::types::state_types::RelationshipContext {
                entity_id: *blake3::hash(b"entity_device").as_bytes(),
                entity_state_number: 1,
                counterparty_id: *blake3::hash(b"counterparty123").as_bytes(),
                counterparty_state_number: 5,
                counterparty_public_key: vec![1, 2, 3],
                relationship_hash: vec![4, 5, 6],
                active: true,
                chain_tip_id: None,
                last_bilateral_state_hash: None,
            });

        let mut next_with_rel = next_state.clone();
        next_with_rel.relationship_context = Some(crate::types::state_types::RelationshipContext {
            entity_id: *blake3::hash(b"entity_device").as_bytes(),
            entity_state_number: 2,
            counterparty_id: *blake3::hash(b"counterparty123").as_bytes(),
            counterparty_state_number: 6, // Advanced correctly
            counterparty_public_key: vec![1, 2, 3],
            relationship_hash: vec![4, 5, 6],
            active: true,
            chain_tip_id: None,
            last_bilateral_state_hash: None,
        });

        let result = verify_bilateral_transition(&current_with_rel, &next_with_rel);
        assert!(result.is_ok());
        assert!(result
            .unwrap_or_else(|e| panic!("should return true for valid bilateral transition: {e}")));
    }

    #[test]
    fn test_verify_token_balance_consistency_burn_operation() {
        let mut prev_state = create_test_state(1);
        let mut current_state = create_test_state(2);

        // Setup balance for burn using canonical pipe-format key
        let key = test_balance_key(&prev_state, b"token1");
        prev_state.token_balances.insert(key.clone(), {
            let mut balance = Balance::zero();
            balance.update_add(100);
            balance
        });
        current_state.token_balances.insert(key, {
            let mut balance = Balance::zero();
            balance.update_add(100);
            balance
        });

        let (_state, _pk, sk) = create_test_state_with_keypair(0);
        let burn_op = signed_burn_op_amount(&sk, "token1", 20);

        let result = verify_token_balance_consistency(&prev_state, &current_state, &burn_op);
        assert!(result.is_ok());
        // Burn falls through to the default case which checks balance preservation
    }

    #[test]
    fn test_verify_token_balance_consistency_missing_token_after_mint() {
        let prev_state = create_test_state(1);
        let current_state = create_test_state(2);

        // Mint operation but token not added to current state
        let (_state, _pk, sk) = create_test_state_with_keypair(0);
        let mint_op = signed_mint_op_amount(&sk, "new_token", 100);

        let result = verify_token_balance_consistency(&prev_state, &current_state, &mint_op);
        assert!(result.is_ok());
        assert!(!result.unwrap_or_else(|e| panic!(
            "should return false when minted token missing from current state: {e}"
        )));
    }

    #[test]
    fn test_verify_token_balance_consistency_incorrect_mint_amount() {
        let mut prev_state = create_test_state(1);
        let mut current_state = create_test_state(2);

        let key = test_balance_key(&prev_state, b"token1");
        prev_state.token_balances.insert(key.clone(), {
            let mut balance = Balance::zero();
            balance.update_add(50);
            balance
        });
        current_state.token_balances.insert(key, {
            let mut balance = Balance::zero();
            balance.update_add(120); // Should be 50 + 100 = 150
            balance
        });

        let (_state, _pk, sk) = create_test_state_with_keypair(0);
        let mint_op = signed_mint_op_amount(&sk, "token1", 100);

        let result = verify_token_balance_consistency(&prev_state, &current_state, &mint_op);
        assert!(result.is_ok());
        assert!(!result
            .unwrap_or_else(|e| panic!("should return false for incorrect mint amount: {e}")));
    }

    #[test]
    fn test_verify_token_balance_consistency_transfer_missing_token() {
        let prev_state = create_test_state(1);
        let current_state = create_test_state(2);

        // Transfer operation but token doesn't exist
        let (_state, _pk, sk) = create_test_state_with_keypair(0);
        let transfer_op = signed_transfer_op_amount(
            &sk,
            prev_state.hash,
            vec![61, 62, 63],
            "test transfer",
            "nonexistent_token",
            50,
        );

        let result = verify_token_balance_consistency(&prev_state, &current_state, &transfer_op);
        assert!(result.is_ok());
        // Should pass when token doesn't exist in either state
    }

    #[test]
    fn test_verify_token_balance_consistency_token_disappears() {
        let mut prev_state = create_test_state(1);
        let current_state = create_test_state(2);

        let key = test_balance_key(&prev_state, b"token1");
        prev_state.token_balances.insert(key, {
            let mut balance = Balance::zero();
            balance.update_add(100);
            balance
        });
        // Token disappears in current state

        let (_state, _pk, sk) = create_test_state_with_keypair(0);
        let noop_op = signed_update_op(&sk, "identity-1");

        let result = verify_token_balance_consistency(&prev_state, &current_state, &noop_op);
        assert!(result.is_ok());
        assert!(!result.unwrap_or_else(|e| panic!(
            "should return false when token disappears without operation: {e}"
        )));
    }

    #[test]
    fn test_apply_transition_bilateral_mode() {
        let (pk, sk) =
            generate_sphincs_keypair().unwrap_or_else(|e| panic!("keypair generation failed: {e}"));

        let mut current_state = create_test_state(5);
        current_state.device_info.public_key = pk.clone();
        let entropy = vec![1, 2, 3, 4];

        let mut transfer_op = Operation::Transfer {
            amount: {
                let mut balance = Balance::zero();
                balance.update_add(25);
                balance
            },
            token_id: b"ERA".to_vec(),
            to_device_id: b"recipient".to_vec(),
            nonce: vec![0, 1, 2, 3],
            pre_commit: None,
            recipient: b"recipient".to_vec(),
            message: "bilateral transfer".to_string(),
            mode: TransactionMode::Bilateral,
            verification: crate::types::operations::VerificationType::Enhanced,
            to: b"recipient".to_vec(),
            signature: Vec::new(),
        };

        // Sign the transfer with the state's device key
        let mut signable = transfer_op.clone();
        if let Operation::Transfer { signature, .. } = &mut signable {
            signature.clear();
        }
        let sig = sphincs_sign(&sk, &signable.to_bytes())
            .unwrap_or_else(|e| panic!("sign transfer failed: {e}"));
        if let Operation::Transfer { signature, .. } = &mut transfer_op {
            *signature = sig;
        }

        let result = apply_transition(&current_state, &transfer_op, &entropy);
        assert!(result.is_ok());

        let next_state = result.unwrap_or_else(|e| panic!("apply_transition should succeed: {e}"));
        assert_eq!(next_state.state_number, 6);
        assert_eq!(next_state.operation, transfer_op);
    }

    #[test]
    fn test_apply_transition_unilateral_mode() {
        let (pk, sk) =
            generate_sphincs_keypair().unwrap_or_else(|e| panic!("keypair generation failed: {e}"));

        let mut current_state = create_test_state(3);
        current_state.device_info.public_key = pk.clone();

        // Seed sender balance so the unilateral transfer has sufficient funds
        let era_pc = crate::core::token::builtin_policy_commit_for_token("ERA").unwrap();
        let sender_key = crate::core::token::derive_canonical_balance_key(&era_pc, &pk, "ERA");
        current_state
            .token_balances
            .insert(sender_key, Balance::from_state(1000, current_state.hash, 3));

        let entropy = vec![4, 5, 6, 7];

        let mut transfer_op = Operation::Transfer {
            amount: {
                let mut balance = Balance::zero();
                balance.update_add(10);
                balance
            },
            token_id: b"ERA".to_vec(),
            to_device_id: b"recipient".to_vec(),
            nonce: vec![0, 1, 2, 3],
            pre_commit: None,
            recipient: b"recipient".to_vec(),
            message: "unilateral transfer".to_string(),
            mode: TransactionMode::Unilateral,
            verification: crate::types::operations::VerificationType::Directory,
            to: b"recipient".to_vec(),
            signature: Vec::new(),
        };

        // Sign the transfer with the state's device key
        let mut signable = transfer_op.clone();
        if let Operation::Transfer { signature, .. } = &mut signable {
            signature.clear();
        }
        let sig = sphincs_sign(&sk, &signable.to_bytes())
            .unwrap_or_else(|e| panic!("sign transfer failed: {e}"));
        if let Operation::Transfer { signature, .. } = &mut transfer_op {
            *signature = sig;
        }

        let result = apply_transition(&current_state, &transfer_op, &entropy);
        assert!(result.is_ok());

        let next_state = result.unwrap_or_else(|e| panic!("apply_transition should succeed: {e}"));
        assert_eq!(next_state.state_number, 4);
    }

    #[test]
    fn test_apply_transition_transfer_signature_verified() {
        let (pk, sk) =
            generate_sphincs_keypair().unwrap_or_else(|e| panic!("keypair generation failed: {e}"));

        let device_info = crate::types::state_types::DeviceInfo {
            device_id: *blake3::hash(b"devA").as_bytes(),
            public_key: pk.clone(),
            metadata: Default::default(),
        };

        let mut current_state = State::new_genesis([0u8; 32], device_info);
        let era_pc =
            crate::core::token::builtin_policy_commit_for_token("ERA").expect("ERA policy commit");
        let sender_key = crate::core::token::derive_canonical_balance_key(&era_pc, &pk, "ERA");
        current_state
            .token_balances
            .insert(sender_key, Balance::from_state(100, current_state.hash, 0));

        let mut op_unsigned = Operation::Transfer {
            token_id: b"ERA".to_vec(),
            to_device_id: vec![9u8; 32],
            amount: Balance::from_state(10, current_state.hash, 0),
            mode: TransactionMode::Unilateral,
            nonce: vec![1u8; 8],
            verification: crate::types::operations::VerificationType::Standard,
            pre_commit: None,
            recipient: vec![9u8; 32],
            to: b"b32recipient".to_vec(),
            message: String::new(),
            signature: Vec::new(),
        };
        let bytes = op_unsigned.to_bytes();
        let sig = sphincs_sign(&sk, &bytes).unwrap_or_else(|e| panic!("sign failed: {e}"));
        if let Operation::Transfer { signature, .. } = &mut op_unsigned {
            *signature = sig;
        }

        let entropy = vec![1, 2, 3, 4];
        let next = apply_transition(&current_state, &op_unsigned, &entropy)
            .unwrap_or_else(|e| panic!("valid signature should succeed: {e}"));
        assert_eq!(next.state_number, current_state.state_number + 1);
    }

    #[test]
    fn test_apply_transition_transfer_invalid_signature_rejected() {
        let (pk, _sk) =
            generate_sphincs_keypair().unwrap_or_else(|e| panic!("keypair generation failed: {e}"));

        let device_info = crate::types::state_types::DeviceInfo {
            device_id: *blake3::hash(b"devA").as_bytes(),
            public_key: pk.clone(),
            metadata: Default::default(),
        };

        let mut current_state = State::new_genesis([0u8; 32], device_info);
        let era_pc =
            crate::core::token::builtin_policy_commit_for_token("ERA").expect("ERA policy commit");
        let sender_key = crate::core::token::derive_canonical_balance_key(&era_pc, &pk, "ERA");
        current_state
            .token_balances
            .insert(sender_key, Balance::from_state(100, current_state.hash, 0));

        let op = Operation::Transfer {
            token_id: b"ERA".to_vec(),
            to_device_id: vec![9u8; 32],
            amount: Balance::from_state(10, current_state.hash, 0),
            mode: TransactionMode::Unilateral,
            nonce: vec![1u8; 8],
            verification: crate::types::operations::VerificationType::Standard,
            pre_commit: None,
            recipient: vec![9u8; 32],
            to: b"b32recipient".to_vec(),
            message: String::new(),
            signature: vec![7u8; 16], // bogus
        };

        let entropy = vec![1, 2, 3, 4];
        let result = apply_transition(&current_state, &op, &entropy);
        assert!(result.is_err(), "invalid signature must be rejected");
    }

    #[test]
    fn test_generate_position_sequence_empty_entropy() {
        let (state, _pk, sk) = create_test_state_with_keypair(2);
        let operation = signed_transfer_op(&sk, state.hash, vec![64, 65, 66], "signed transfer");
        let empty_entropy: Vec<u8> = vec![];

        let result = generate_position_sequence(&state, &operation, &empty_entropy);
        assert!(result.is_ok());

        let sequence = result.unwrap_or_else(|e| panic!("should handle empty entropy: {e}"));
        assert!(!sequence.positions.is_empty());
        assert!(!sequence.seed.is_empty());
    }

    #[test]
    fn test_state_transition_to_wire_bytes() {
        let (_state, _pk, sk) = create_test_state_with_keypair(0);
        let operation = signed_transfer_op(&sk, [0u8; 32], vec![67, 68, 69], "signed transfer");
        let transition = StateTransition::new(
            operation.clone(),
            Some(vec![1, 2, 3]),
            Some(vec![4, 5, 6]),
            &TEST_DEVICE_ID,
        );

        let bytes = transition.to_wire_bytes();

        // Should produce non-empty wire format bytes
        assert!(!bytes.is_empty());

        // Verify deterministic structure - same inputs should produce consistent structure
        let transition2 = StateTransition::new(
            operation.clone(),
            Some(vec![1, 2, 3]),
            Some(vec![4, 5, 6]),
            &TEST_DEVICE_ID,
        );
        let bytes2 = transition2.to_wire_bytes();

        // Both should be non-empty (deterministic time may differ so not strictly equal)
        assert!(!bytes2.is_empty());
    }
}
