//! Core State Machine Module
//!
//! This module implements the core state machine functionality for DSM, including:
//! - Forward-only state transitions
//! - Deterministic state evolution
//! - Pre-commitment verification
//! - Hash-chain verification for efficient validation
//!
//! The state machine ensures that all transitions maintain the system's security properties
//! as described in the whitepaper.

pub mod batch;
pub mod batch_proof;
pub mod bilateral;
pub mod checkpoint;
pub mod hashchain;
pub mod random_walk;
pub mod relationship;
pub mod state;
pub mod state_projection;
pub mod sync_manager;
pub mod transition;
pub mod utils;

pub use crate::core::state_machine::checkpoint::Checkpoint;
use crate::core::state_machine::relationship::validate_relationship_state_transition;
use crate::core::state_machine::relationship::verify_relationship_entropy;
use crate::core::state_machine::relationship::KeyDerivationStrategy;
use crate::core::state_machine::transition::apply_transition;
use crate::crypto::blake3::{domain_hash, dsm_domain_hasher};
use crate::types::error::DsmError;
use crate::types::operations::Operation;
use crate::types::state_types::State;
pub use bilateral::BilateralStateManager;
use blake3::Hash;

pub use random_walk::algorithms::{
    generate_positions, generate_random_walk_coordinates, generate_seed, verify_positions,
    verify_random_walk_coordinates, verify_state_transition as verify_state_transition_random_walk,
    Position, RandomWalkConfig,
};

pub use batch::{BatchBuilder, BatchCommitment, BatchManager, StateBatch};
pub use hashchain::HashChain;
pub use relationship::{RelationshipManager, RelationshipStatePair};
pub use transition::{create_transition, generate_position_sequence, StateTransition};
pub use utils::{constant_time_eq, verify_state_hash}; // Export utility functions and remove hash_blake3 export

/// Type definition for precommitment generation function
type PrecommitmentGenFn = fn(&State, &Operation, &Hash) -> Result<(Hash, Vec<Position>), DsmError>;

/// Core state machine that handles transitions and verification
///
/// This state machine implementation uses the enhanced verification function
/// `verify_transition_integrity` from the transition module which provides
/// comprehensive state transition validation.
#[derive(Clone, Debug)]
pub struct StateMachine {
    /// Current state
    current_state: Option<State>,
    /// Device ID for this state machine instance
    device_id: [u8; 32],
    /// Relationship manager for bilateral state isolation
    #[allow(dead_code)]
    relationship_manager: RelationshipManager,
    /// Apply transition function type
    #[allow(dead_code)]
    apply_transition_fn: fn(&State, &Operation, &[u8]) -> Result<State, DsmError>,
    /// Verify transition function
    #[allow(dead_code)]
    verify_transition: fn(&State, &State, &Operation) -> Result<bool, DsmError>,
    /// Generate transition entropy function
    #[allow(dead_code)]
    generate_entropy: fn(&State, &Operation) -> Result<[u8; 32], DsmError>,
    /// Verify state chain function
    #[allow(dead_code)]
    verify_chain: fn(&[State]) -> Result<bool, DsmError>,
    /// Hash function
    #[allow(dead_code)]
    hash_function: fn(&[u8]) -> blake3::Hash,
    /// Generate precommitment function
    #[allow(dead_code)]
    generate_precommitment: PrecommitmentGenFn,
    /// Verify precommitment function
    #[allow(dead_code)]
    verify_precommitment: fn(&State, &Operation, &[Position]) -> Result<bool, DsmError>,
}

impl StateMachine {
    /// Create a new state machine instance
    pub fn new() -> Self {
        Self::new_with_strategy(KeyDerivationStrategy::Canonical)
    }

    /// Create a new state machine with a specific key derivation strategy
    pub fn new_with_strategy(strategy: KeyDerivationStrategy) -> Self {
        Self::new_with_strategy_and_device_id(strategy, [0u8; 32])
    }

    /// Create a new state machine with a specific key derivation strategy and device ID
    pub fn new_with_strategy_and_device_id(
        strategy: KeyDerivationStrategy,
        device_id: [u8; 32],
    ) -> Self {
        StateMachine {
            current_state: None,
            device_id,
            relationship_manager: RelationshipManager::new(strategy),
            apply_transition_fn: apply_transition,
            verify_transition: verify_transition_integrity,
            generate_entropy: generate_transition_entropy,
            verify_chain: verify_state_chain,
            hash_function: internal_hash_blake3,
            generate_precommitment: |state, operation, hash| {
                // Generate entropy for operation
                let entropy = generate_transition_entropy(state, operation)?;

                // Generate seed for random walk using canonical op bytes (no Serde)
                let op_bytes = operation.to_bytes();

                let seed = random_walk::algorithms::generate_seed(hash, &op_bytes, Some(&entropy));

                // Generate positions from seed
                let positions = random_walk::algorithms::generate_positions(
                    &seed,
                    None::<random_walk::algorithms::RandomWalkConfig>,
                )?;

                Ok((seed, positions))
            },
            verify_precommitment: |state, operation, positions| {
                // Create temporary state machine for verification
                let mut temp_machine = StateMachine::new();
                temp_machine.set_state(state.clone());

                // Re-generate positions
                let (_, generated_positions) = temp_machine.generate_precommitment(operation)?;

                // Verify positions match
                Ok(random_walk::algorithms::verify_positions(
                    &generated_positions,
                    positions,
                ))
            },
        }
    }

    /// Get the current state
    pub fn current_state(&self) -> Option<&State> {
        self.current_state.as_ref()
    }

    /// Set the current state
    pub fn set_state(&mut self, state: State) {
        self.current_state = Some(state);
    }

    /// Initialize the state machine with a genesis state
    ///
    /// This method sets up the state machine with a genesis state,
    /// ensuring the system starts from a valid initial state.
    ///
    /// # Returns
    ///
    /// * `Ok(())` - If initialization was successful
    /// * `Err(DsmError)` - If initialization failed
    pub fn initialize_with_genesis(&mut self) -> Result<(), DsmError> {
        if let Some(genesis_state) = &self.current_state {
            // Validate that this is actually a genesis state
            if genesis_state.state_number != 0 {
                return Err(DsmError::state_machine(
                    "Current state is not a genesis state",
                ));
            }

            // Validate the genesis state structure
            if genesis_state.prev_state_hash != [0u8; 32] {
                return Err(DsmError::state_machine(
                    "Genesis state must have zero previous state hash",
                ));
            }

            // Initialize any necessary internal state based on genesis
            // This could include setting up initial permissions, device registry, etc.

            Ok(())
        } else {
            Err(DsmError::state_machine(
                "No genesis state provided for initialization",
            ))
        }
    }

    /// Execute a state transition with comprehensive validation
    pub fn execute_transition(&mut self, operation: Operation) -> Result<State, DsmError> {
        // Clone the current state to avoid borrowing issues
        let current_state = self.current_state.clone().ok_or_else(|| {
            DsmError::state_machine("No current state exists - initialize with genesis first")
        })?;

        // Validate operation is allowed for current state
        if !is_operation_allowed(&operation, &current_state)? {
            return Err(DsmError::invalid_operation(format!(
                "Operation {operation:?} not allowed in current state"
            )));
        }

        // Generate entropy for new state with validation
        let new_entropy = generate_transition_entropy(&current_state, &operation)
            .map_err(|e| DsmError::state_machine(format!("Failed to generate entropy: {e}")))?;

        // Validate entropy generation produced valid output
        if new_entropy.is_empty() {
            return Err(DsmError::state_machine("Generated entropy is empty"));
        }

        // Create a transition with validation
        let transition = create_transition(&current_state, operation, &new_entropy)
            .map_err(|e| DsmError::state_machine(format!("Failed to create transition: {e}")))?;

        // --- DBRW summary commitment (non-secret) ---
        // If the platform has DBRW initialized, bind a deterministic health summary commitment
        // into the new state's hash preimage.
        //
        // If DBRW is unavailable, fail-closed is handled elsewhere; here we simply omit the
        // commitment (None) and the state hash chain remains compatible.
        // Default: do not bind DBRW unless a platform boundary installs/maintains the signal.
        // The SDK should set this on StateParams during transitions where it has DBRW samples.
        // Core keeps a conservative default (None).
        let dbrw_summary_hash: Option<[u8; 32]> = None;

        // Apply the transition to create a new state
        let mut new_state = transition::create_next_state(
            &current_state,
            transition.operation,
            &new_entropy,
            &transition::VerificationType::Standard,
            false,
        )
        .map_err(|e| DsmError::state_machine(format!("Failed to create next state: {e}")))?;

        // Attach DBRW commitment after structural transition but before final hash-use sites.
        // create_next_state recomputes the hash already; we must re-hash if we change the commitment.
        if let Some(h) = dbrw_summary_hash {
            new_state.dbrw_summary_hash = Some(h);
            let computed_hash = new_state.compute_hash()?;
            new_state.hash = computed_hash;
        }

        // Validate new state before applying
        if new_state.state_number != current_state.state_number + 1 {
            return Err(DsmError::invalid_operation(
                "New state number must be sequential",
            ));
        }

        if new_state.prev_state_hash != current_state.hash()? {
            return Err(DsmError::invalid_operation(
                "New state hash chain is broken",
            ));
        }

        // Log the transition before updating state
        let old_state_num = current_state.state_number;
        let new_state_num = new_state.state_number;

        // Update the current state
        self.set_state(new_state.clone());

        // Advance the global deterministic tick on successful state transition
        let _ = crate::util::deterministic_time::tick_raw();

        tracing::info!(
            "State transition executed: {} -> {}",
            old_state_num,
            new_state_num
        );

        Ok(new_state)
    }

    /// Apply an operation to a state to create a new state directly
    ///
    /// This method is useful when you want to apply an operation to a state without updating
    /// the current state of the state machine. It uses the transition module's apply_transition function
    /// to create a new state from the given state and operation.
    ///
    /// # Arguments
    ///
    /// * `state` - The state to apply the operation to
    /// * `operation` - The operation to apply
    /// * `new_entropy` - The entropy to use for the next state
    ///
    /// # Returns
    ///
    /// A result containing the new state or an error
    pub fn apply_operation(
        &self,
        state: State,
        operation: Operation,
        new_entropy: Vec<u8>,
    ) -> Result<State, DsmError> {
        // Apply the transition to create a new state
        transition::apply_transition(&state, &operation, &new_entropy)
    }

    /// Execute a state transition in the context of a relationship
    pub fn execute_relationship_transition(
        &mut self,
        entity_id: &str,
        counterparty_id: &str,
        operation: Operation,
    ) -> Result<RelationshipStatePair, DsmError> {
        // Generate entropy for new state
        let new_entropy = generate_transition_entropy(
            self.current_state.as_ref().ok_or_else(|| {
                DsmError::state_machine("No current state exists for relationship transition")
            })?,
            &operation,
        )?;

        // Execute the transition using the relationship manager
        self.relationship_manager.execute_relationship_transition(
            &domain_hash("DSM/entity-id", entity_id.as_bytes()).into(),
            &domain_hash("DSM/entity-id", counterparty_id.as_bytes()).into(),
            operation,
            new_entropy,
        )
    }

    /// Verify a state using hash-chain validation
    pub fn verify_state(&self, state: &State) -> Result<bool, DsmError> {
        if let Some(current_state) = &self.current_state {
            // First verify state number is sequential
            if state.state_number != current_state.state_number + 1 {
                return Ok(false);
            }

            // Then verify hash chain integrity
            let prev_hash = current_state.hash()?;
            if state.prev_state_hash != prev_hash {
                return Ok(false);
            }

            // Finally verify transition integrity using the operation from the state
            verify_transition_integrity(current_state, state, &state.operation)
        } else {
            Err(crate::types::error::DsmError::state_machine(
                "No current state exists for verification",
            ))
        }
    }

    /// Generate a pre-commitment for the next state transition
    pub fn generate_precommitment(
        &self,
        operation: &Operation,
    ) -> Result<(Hash, Vec<Position>), DsmError> {
        if let Some(current_state) = &self.current_state {
            let operation_bytes = operation.to_bytes();

            let next_state_number = current_state.state_number + 1;
            let next_state_bytes = next_state_number.to_le_bytes();

            // Create entropy according to whitepaper equation (20) — must use the
            // same domain tag as generate_transition_entropy ("DSM/state-entropy")
            let mut hasher = dsm_domain_hasher("DSM/state-entropy");
            hasher.update(&current_state.entropy);
            hasher.update(&operation_bytes);
            hasher.update(&next_state_bytes);
            let next_entropy = hasher.finalize();

            // Generate seed for random walk according to whitepaper equation (21)
            let current_hash = domain_hash("DSM/chain-hash", &current_state.hash);

            let seed = random_walk::algorithms::generate_seed(
                &current_hash,
                &operation_bytes,
                Some(next_entropy.as_bytes()),
            );

            // Generate positions for verification according to whitepaper equation (22)
            let positions = random_walk::algorithms::generate_positions(
                &seed,
                None::<random_walk::algorithms::RandomWalkConfig>,
            )?;

            Ok((seed, positions))
        } else {
            Err(DsmError::state_machine(
                "No current state exists for pre-commitment",
            ))
        }
    }

    /// Verify a pre-commitment
    pub fn verify_precommitment(
        &self,
        operation: &Operation,
        expected_positions: &[Position],
    ) -> Result<bool, DsmError> {
        let (_, positions) = self.generate_precommitment(operation)?;
        Ok(random_walk::algorithms::verify_positions(
            &positions,
            expected_positions,
        ))
    }

    pub fn create_base_operation(&self) -> Result<Operation, DsmError> {
        Ok(Operation::Create {
            message: "Create base state".to_string(),
            identity_data: Vec::new(),
            public_key: Vec::new(),
            metadata: Vec::new(),
            commitment: Vec::new(),
            proof: Vec::new(),
            mode: crate::types::operations::TransactionMode::Unilateral,
        })
    }

    pub fn update_base_operation(&self) -> Result<Operation, DsmError> {
        Ok(Operation::Update {
            message: "Update base state".to_string(),
            identity_id: Vec::new(),
            updated_data: Vec::new(),
            proof: Vec::new(),
            forward_link: None,
        })
    }

    pub fn add_relationship_operation(&self, counterparty_id: &str) -> Result<Operation, DsmError> {
        let counterparty_id_hash = domain_hash("DSM/entity-id", counterparty_id.as_bytes());
        Ok(Operation::AddRelationship {
            message: format!("Add relationship with {counterparty_id}"),
            from_id: self.device_id,
            to_id: counterparty_id_hash.into(),
            relationship_type: Vec::new(),
            metadata: Vec::new(),
            proof: Vec::new(),
            mode: crate::types::operations::TransactionMode::Unilateral,
        })
    }

    pub fn remove_relationship_operation(
        &self,
        counterparty_id: &str,
    ) -> Result<Operation, DsmError> {
        let counterparty_id_hash = domain_hash("DSM/entity-id", counterparty_id.as_bytes());
        Ok(Operation::RemoveRelationship {
            message: format!("Remove relationship with {counterparty_id}"),
            from_id: self.device_id,
            to_id: counterparty_id_hash.into(),
            relationship_type: Vec::new(),
            proof: Vec::new(),
            mode: crate::types::operations::TransactionMode::Unilateral,
        })
    }

    pub fn generic_operation(
        &self,
        operation_type: &str,
        data: Vec<u8>,
    ) -> Result<Operation, DsmError> {
        Ok(Operation::Generic {
            operation_type: operation_type.as_bytes().to_vec(),
            data,
            message: format!("Generic operation: {operation_type}"),
            signature: vec![],
        })
    }
}

impl Default for StateMachine {
    fn default() -> Self {
        Self::new()
    }
}

/// Generate deterministic entropy for a transition
///
/// This function implements the entropy evolution function from the whitepaper,
/// ensuring deterministic derivation of future state entropy from current state and operation.
pub fn generate_transition_entropy(
    current_state: &State,
    operation: &Operation,
) -> Result<[u8; 32], DsmError> {
    // Canonical operation bytes (no Serde)
    let op_data = operation.to_bytes();

    let next_state_number = current_state.state_number + 1;

    // Generate entropy according to en+1 = H(en || opn+1 || (n+1))
    let mut hasher = dsm_domain_hasher("DSM/state-entropy");
    hasher.update(&current_state.entropy);
    hasher.update(&op_data);
    hasher.update(&next_state_number.to_le_bytes());

    Ok(*hasher.finalize().as_bytes())
}

/// Verify a state transition meets all requirements
pub fn verify_transition_integrity(
    prev_state: &State,
    curr_state: &State,
    next_operation: &Operation,
) -> Result<bool, DsmError> {
    // Verify basic state transition properties
    if !verify_basic_transition(prev_state, curr_state)? {
        return Ok(false);
    }

    // For relationship states, verify relationship transition
    if curr_state.relationship_context.is_some() {
        // Create temporary next state for verification
        let mut next_state = curr_state.clone();
        next_state.operation = next_operation.clone();
        return validate_relationship_state_transition(curr_state, &next_state);
    }

    // For non-relationship states, verify standard transition
    verify_standard_transition(curr_state, next_operation)
}

/// Verify basic transition properties that apply to all state types
fn verify_basic_transition(state1: &State, state2: &State) -> Result<bool, DsmError> {
    // Verify state number increment
    if state2.state_number != state1.state_number + 1 {
        return Ok(false);
    }

    // Verify hash chain continuity
    if state2.prev_state_hash != state1.hash()? {
        return Ok(false);
    }

    // Verify entropy evolution
    if !verify_entropy_evolution(state1, state2)? {
        return Ok(false);
    }

    Ok(true)
}

/// Verify a standard (non-relationship) state transition
fn verify_standard_transition(
    curr_state: &State,
    next_operation: &Operation,
) -> Result<bool, DsmError> {
    // Verify state operation allowed
    if !is_operation_allowed(next_operation, curr_state)? {
        return Ok(false);
    }

    Ok(true)
}

/// Verify entropy evolution between states
fn verify_entropy_evolution(state1: &State, state2: &State) -> Result<bool, DsmError> {
    // For relationship states, use relationship entropy verification
    if state1.relationship_context.is_some() {
        return verify_relationship_entropy(state1, state2, &state2.entropy);
    }

    // For standard states, verify standard entropy evolution
    // Must use the same domain tag as generate_transition_entropy ("DSM/state-entropy")
    let op_bytes = state2.operation.to_bytes();

    let mut hasher = crate::crypto::blake3::dsm_domain_hasher("DSM/state-entropy");
    hasher.update(&state1.entropy);
    hasher.update(&op_bytes);
    hasher.update(&state2.state_number.to_le_bytes());
    let expected_entropy = hasher.finalize().as_bytes().to_vec();

    Ok(crate::core::state_machine::utils::constant_time_eq(
        &state2.entropy,
        &expected_entropy,
    ))
}

/// Check if an operation is allowed for the current state
fn is_operation_allowed(operation: &Operation, current_state: &State) -> Result<bool, DsmError> {
    match operation {
        Operation::Genesis => {
            // Genesis is materialized via State::new_genesis()/SDK bootstrap, not as a
            // transition from an already-present current state.
            Ok(false)
        }
        Operation::Recovery { .. } => {
            // Recovery only allowed if state is marked as compromised
            Ok(current_state
                .flags
                .contains(&crate::types::state_types::StateFlag::Compromised))
        }
        // Any non-genesis operation is allowed once a current state exists.
        // The first post-genesis transition runs from the materialized genesis
        // baseline, which is state #0 in the live chain.
        _ => Ok(true),
    }
}

/// Verify a state chain from genesis to current
fn verify_state_chain(states: &[State]) -> Result<bool, DsmError> {
    if states.is_empty() {
        return Ok(true);
    }

    // Verify continuity and transitions for each state
    for i in 1..states.len() {
        let prev_state = &states[i - 1];
        let curr_state = &states[i];

        // First verify hash chain continuity
        if curr_state.prev_state_hash != prev_state.hash()? {
            return Err(DsmError::invalid_operation(format!(
                "Hash chain broken between states {} and {}",
                prev_state.state_number, curr_state.state_number
            )));
        }

        // Then verify the transition integrity using the operation
        if !verify_transition_integrity(prev_state, curr_state, &curr_state.operation)? {
            return Err(DsmError::invalid_operation(format!(
                "Invalid state transition between states {} and {}",
                prev_state.state_number, curr_state.state_number
            )));
        }
    }

    Ok(true)
}

// Use domain-separated BLAKE3 hashing for state machine operations
#[allow(dead_code)]
fn internal_hash_blake3(data: &[u8]) -> blake3::Hash {
    crate::crypto::blake3::domain_hash("DSM/state-hash", data)
}

#[cfg(test)]
mod state_machine_tests {
    use super::*;
    use crate::types::state_types::DeviceInfo;
    use crate::types::token_types::Balance;
    use crate::{
        crypto::sphincs::{generate_sphincs_keypair, sphincs_sign},
        types::operations::{TransactionMode, VerificationType},
    };

    // Helper function to create a test genesis state
    fn create_test_genesis_state_with_keypair() -> (State, Vec<u8>, Vec<u8>) {
        let (pk, sk) = generate_sphincs_keypair().expect("keypair");
        let device_id = blake3::hash(b"test_device").into();
        let device_info = DeviceInfo::new(device_id, pk.clone());

        let mut entropy = [0u8; 32];
        entropy[0..4].copy_from_slice(&[1, 2, 3, 4]);
        let mut state = State::new_genesis(
            entropy, // Initial entropy
            device_info,
        );

        // Compute and set hash for the initial state
        if let Ok(hash) = state.hash() {
            state.hash = hash;
        }

        state
            .token_balances
            .insert("ERA".to_string(), Balance::from_state(1000, state.hash, 0));

        (state, pk, sk)
    }

    fn signed_transfer(
        sk: &[u8],
        current_state: &State,
        nonce: Vec<u8>,
        message: &str,
    ) -> Operation {
        let mut op = Operation::Transfer {
            token_id: b"ERA".to_vec(),
            to_device_id: vec![9u8; 32],
            amount: Balance::from_state(10, current_state.hash, 0),
            mode: TransactionMode::Unilateral,
            nonce,
            verification: VerificationType::Standard,
            pre_commit: None,
            recipient: vec![9u8; 32],
            to: b"b32recipient".to_vec(),
            message: message.to_string(),
            signature: Vec::new(),
        };

        let bytes = op.to_bytes();
        let sig = sphincs_sign(sk, &bytes).expect("sign transfer");
        if let Operation::Transfer { signature, .. } = &mut op {
            *signature = sig;
        }

        op
    }

    #[test]
    fn test_state_chain_reconstruction() -> Result<(), DsmError> {
        // Create a genesis state for testing
        let (initial_state, _pk, sk) = create_test_genesis_state_with_keypair();

        let mut states = vec![initial_state.clone()];
        let mut current_state = initial_state;

        // Create a chain of states through transitions (fewer in debug mode)
        let num_transitions = if cfg!(debug_assertions) { 1 } else { 3 };
        for i in 0..num_transitions {
            let op = signed_transfer(
                &sk,
                &current_state,
                vec![i as u8; 8],
                &format!("Test transfer {i}"),
            );

            // Generate entropy using the same domain tag as generate_transition_entropy
            let op_bytes = op.to_bytes();
            let next_state_number = current_state.state_number + 1;
            let new_entropy = {
                let mut hasher = crate::crypto::blake3::dsm_domain_hasher("DSM/state-entropy");
                hasher.update(&current_state.entropy);
                hasher.update(&op_bytes);
                hasher.update(&next_state_number.to_le_bytes());
                *hasher.finalize().as_bytes()
            };

            // Create a transition using the random walk
            let transition = create_transition(&current_state, op, &new_entropy)?;

            // Apply the transition to get a new state
            let new_state = apply_transition(&current_state, &transition.operation, &new_entropy)?;

            // Add to our chain and update current state
            states.push(new_state.clone());
            current_state = new_state;
        }

        // Verify the integrity of the entire chain
        assert!(verify_state_chain(&states)?);

        // Try breaking the chain by tampering with an intermediate state
        let mut broken_states = states.clone();
        broken_states[1].entropy = vec![99, 99, 99]; // Tamper with entropy

        // Compute new hash for the tampered state
        if let Ok(hash) = broken_states[1].hash() {
            broken_states[1].hash = hash;
        }

        // Verification should now fail
        assert!(verify_state_chain(&broken_states).is_err());

        Ok(())
    }

    #[test]
    fn test_first_post_genesis_transition_is_allowed() -> Result<(), DsmError> {
        let (genesis_state, _pk, sk) = create_test_genesis_state_with_keypair();
        let device_id = genesis_state.device_info.device_id;
        let op = signed_transfer(
            &sk,
            &genesis_state,
            vec![0u8; 8],
            "first post-genesis transfer",
        );

        let mut state_machine = StateMachine::new_with_strategy_and_device_id(
            KeyDerivationStrategy::Canonical,
            device_id,
        );
        state_machine.set_state(genesis_state);

        let next_state = state_machine.execute_transition(op)?;
        assert_eq!(next_state.state_number, 1);

        Ok(())
    }

    #[test]
    fn test_state_machine_execute_transition() -> Result<(), DsmError> {
        // Create a state machine
        let mut machine = StateMachine::new();

        // Set initial state
        let (initial_state, _pk, sk) = create_test_genesis_state_with_keypair();
        // Clone the state before consuming it
        let initial_state_clone = initial_state.clone();
        machine.set_state(initial_state);

        // Execute a transition
        let op = signed_transfer(
            &sk,
            machine.current_state().unwrap(),
            vec![1u8; 8],
            "Test transfer",
        );

        let new_state = machine.execute_transition(op)?;
        // Verify the new state has been created correctly
        assert_eq!(new_state.state_number, 1);
        assert!(
            machine
                .current_state()
                .ok_or_else(|| DsmError::internal(
                    "No current state".to_string(),
                    None::<std::convert::Infallible>
                ))?
                .state_number
                == 1
        );

        // Verify the current state number
        assert_eq!(
            machine
                .current_state()
                .ok_or_else(|| DsmError::state_machine("No current state"))?
                .state_number,
            1
        );

        // Verify it references the previous state
        assert_eq!(new_state.prev_state_hash, initial_state_clone.hash()?);

        Ok(())
    }

    #[test]
    fn test_precommitment_generation_and_verification() -> Result<(), DsmError> {
        // Create a state machine
        let mut machine = StateMachine::new();

        // Set initial state
        let (initial_state, _pk, sk) = create_test_genesis_state_with_keypair();
        machine.set_state(initial_state);

        // Create an operation
        let op = signed_transfer(
            &sk,
            machine.current_state().unwrap(),
            vec![1u8; 8],
            "Test transfer",
        );

        // Generate precommitment
        let (_, positions) = machine.generate_precommitment(&op)?;

        // Verify precommitment
        assert!(machine.verify_precommitment(&op, &positions)?);

        // Modify operation slightly
        let modified_op = signed_transfer(
            &sk,
            machine.current_state().unwrap(),
            vec![2u8; 8],
            "Test transfer modified",
        );

        // Verification should fail
        assert!(!machine.verify_precommitment(&modified_op, &positions)?);

        Ok(())
    }

    #[test]
    fn test_state_verification_chain() -> Result<(), DsmError> {
        // Build states manually using the same domain tag as generate_transition_entropy
        let (genesis, _pk, sk) = create_test_genesis_state_with_keypair();

        // Create first operation
        let op1 = signed_transfer(&sk, &genesis, vec![1u8; 8], "First transfer");

        // Compute entropy with DSM/state-entropy domain tag matching generate_transition_entropy
        let op1_bytes = op1.to_bytes();
        let entropy1 = {
            let mut hasher = crate::crypto::blake3::dsm_domain_hasher("DSM/state-entropy");
            hasher.update(&genesis.entropy);
            hasher.update(&op1_bytes);
            hasher.update(&(genesis.state_number + 1).to_le_bytes());
            *hasher.finalize().as_bytes()
        };

        let transition1 = create_transition(&genesis, op1, &entropy1)?;
        let state1 = apply_transition(&genesis, &transition1.operation, &entropy1)?;

        // Create second operation
        let op2 = signed_transfer(&sk, &state1, vec![2u8; 8], "Second transfer");

        let op2_bytes = op2.to_bytes();
        let entropy2 = {
            let mut hasher = crate::crypto::blake3::dsm_domain_hasher("DSM/state-entropy");
            hasher.update(&state1.entropy);
            hasher.update(&op2_bytes);
            hasher.update(&(state1.state_number + 1).to_le_bytes());
            *hasher.finalize().as_bytes()
        };

        let transition2 = create_transition(&state1, op2, &entropy2)?;
        let state2 = apply_transition(&state1, &transition2.operation, &entropy2)?;

        // Create a test next state for verification
        let mut next_state = state2.clone();
        next_state.state_number += 1;
        next_state.prev_state_hash = state2.hash()?;

        // Verify state2 from state1 using our refactored verification
        assert!(verify_transition_integrity(
            &state1,
            &state2,
            &next_state.operation
        )?);

        // Now also test the state machine's verify_state method
        // First reset to state1
        let mut test_machine = StateMachine::new();
        test_machine.set_state(state1.clone());

        // Verify state2 from state1 using the state machine
        assert!(test_machine.verify_state(&state2)?);

        // Create invalid state with wrong previous hash
        let mut invalid_state = state2.clone();
        invalid_state.prev_state_hash = [0; 32]; // Wrong hash

        // Verification should fail
        assert!(!test_machine.verify_state(&invalid_state)?);

        Ok(())
    }
}
