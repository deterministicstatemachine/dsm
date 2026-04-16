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

pub mod bilateral;
pub mod checkpoint;
pub mod hashchain;
pub mod random_walk;
pub mod relationship;
pub mod state;
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

pub use hashchain::HashChain;
pub use relationship::{RelationshipManager, RelationshipStatePair};
pub use transition::{create_transition, generate_position_sequence, StateTransition};
pub use utils::{constant_time_eq, verify_state_hash}; // Export utility functions and remove hash_blake3 export

/// Type definition for precommitment generation function
type PrecommitmentGenFn = fn(&State, &Operation, &Hash) -> Result<(Hash, Vec<Position>), DsmError>;

/// Core state machine that handles transitions and verification.
///
/// Holds both the legacy `current_state: Option<State>` (for backward compat
/// during migration) and the spec-canonical `device_state: Option<DeviceState>`
/// which is the Per-Device SMT head (§2.2). New code should use
/// `advance_relationship` which routes through `DeviceState::advance()`.
#[derive(Clone, Debug)]
pub struct StateMachine {
    /// Canonical device state per §2.2: SMT root + device-level balances +
    /// per-relationship chain tips. This IS the device head.
    device_state: Option<crate::types::device_state::DeviceState>,
    /// Legacy current state — kept only for genesis bootstrap and
    /// generate_precommitment fallback. Will be fully removed.
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
            device_state: None,
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

    /// Get the current state (legacy path — prefer `device_head()` for new code).
    pub fn current_state(&self) -> Option<&State> {
        self.current_state.as_ref()
    }

    /// Get the canonical device state (§2.2 SMT head).
    pub fn device_head(&self) -> Option<&crate::types::device_state::DeviceState> {
        self.device_state.as_ref()
    }

    /// Set the current state (legacy path). Also initializes DeviceState if
    /// not yet present — bootstraps the SMT from genesis.
    pub fn set_state(&mut self, state: State) {
        // If DeviceState doesn't exist yet and this looks like genesis,
        // bootstrap it from the State's device info.
        if self.device_state.is_none() {
            let ds = crate::types::device_state::DeviceState::new(
                [0u8; 32], // genesis placeholder — proper genesis set in initialize_with_genesis
                state.device_info.device_id,
                state.device_info.public_key.clone(),
                1024, // max relationships
            );
            self.device_state = Some(ds);
        }
        self.current_state = Some(state);
    }

    /// Advance a specific relationship chain on the device.
    ///
    /// This is the spec-canonical transition path (§2.2, §4.2): names a
    /// relationship, extends that chain by one state, replaces the SMT leaf,
    /// updates device-level balances atomically, and returns the outcome.
    ///
    /// The caller must provide:
    /// - `rel_key`: 32-byte relationship key `k_{A↔B}` per §2.2
    /// - `counterparty_devid`: the other party's DevID
    /// - `operation`: the op being performed
    /// - `deltas`: balance mutations per §8 eq. 10
    /// - `initial_chain_tip`: only for first-ever transactions on this relationship
    pub fn advance_relationship(
        &mut self,
        rel_key: [u8; 32],
        counterparty_devid: [u8; 32],
        operation: Operation,
        deltas: &[crate::types::device_state::BalanceDelta],
        initial_chain_tip: Option<[u8; 32]>,
    ) -> Result<crate::types::device_state::AdvanceOutcome, DsmError> {
        let ds = self.device_state.as_ref().ok_or_else(|| {
            DsmError::state_machine("DeviceState not initialized — call set_state with genesis first")
        })?;

        // Generate entropy from hash-adjacency inputs (§11 eq. 14).
        // Read prior entropy + hash from the DeviceState's tip for this
        // relationship, or from current_state as fallback.
        let (prior_entropy, prior_hash) = if let Some(tip_state) = ds.tip_state(&rel_key) {
            (tip_state.entropy.clone(), tip_state.compute_chain_tip())
        } else if let Some(cs) = &self.current_state {
            (cs.entropy.clone(), cs.hash)
        } else {
            // Fresh genesis — use zeros
            (vec![0u8; 32], [0u8; 32])
        };
        let entropy = {
            let op_data = operation.to_bytes();
            let mut hasher = dsm_domain_hasher("DSM/state-entropy");
            hasher.update(&prior_entropy);
            hasher.update(&op_data);
            hasher.update(&prior_hash);
            *hasher.finalize().as_bytes()
        };

        let outcome = ds.advance(
            rel_key,
            counterparty_devid,
            operation,
            entropy.to_vec(),
            None, // encapsulated_entropy — caller can set if needed
            deltas,
            initial_chain_tip,
            None, // dbrw_summary_hash
        )?;

        // Commit: install the new device state as the head.
        self.device_state = Some(outcome.new_device_state.clone());

        Ok(outcome)
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
            // Genesis is identified by zero parent hash (§2.5).

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

    // execute_transition and apply_operation deleted — all transitions now go
    // through advance_relationship which uses DeviceState::advance (§2.2, §4.2).

    /// Execute a state transition in the context of a relationship.
    /// Uses DeviceState for entropy derivation, falls back to legacy.
    pub fn execute_relationship_transition(
        &mut self,
        entity_id: &str,
        counterparty_id: &str,
        operation: Operation,
    ) -> Result<RelationshipStatePair, DsmError> {
        // Derive entropy from DeviceState root or legacy current_state
        let (prior_entropy, prior_hash) = if let Some(ds) = &self.device_state {
            let root = ds.root();
            let entropy = {
                let mut h = dsm_domain_hasher("DSM/precommit-entropy");
                h.update(&root);
                h.finalize().as_bytes().to_vec()
            };
            (entropy, root)
        } else if let Some(cs) = &self.current_state {
            (cs.entropy.clone(), cs.hash)
        } else {
            return Err(DsmError::state_machine("No state for relationship transition"));
        };

        let op_data = operation.to_bytes();
        let mut hasher = dsm_domain_hasher("DSM/state-entropy");
        hasher.update(&prior_entropy);
        hasher.update(&op_data);
        hasher.update(&prior_hash);
        let new_entropy = *hasher.finalize().as_bytes();

        self.relationship_manager.execute_relationship_transition(
            &domain_hash("DSM/entity-id", entity_id.as_bytes()).into(),
            &domain_hash("DSM/entity-id", counterparty_id.as_bytes()).into(),
            operation,
            new_entropy,
        )
    }

    /// Verify a state using hash-chain validation (§2.1 adjacency only).
    ///
    /// Checks that `state.prev_state_hash` embeds the current device head's
    /// hash. Uses DeviceState's SMT root as the canonical identity.
    pub fn verify_state(&self, state: &State) -> Result<bool, DsmError> {
        // Get the current head hash. DeviceState root is canonical ONLY when
        // relationships have been advanced (non-empty SMT). For legacy states
        // created via set_state(), fall back to current_state.hash().
        let head_hash = if let Some(cs) = &self.current_state {
            cs.hash()?
        } else if let Some(ds) = &self.device_state {
            ds.root()
        } else {
            return Err(DsmError::state_machine("No current state exists for verification"));
        };

        if state.prev_state_hash != head_hash {
            return Ok(false);
        }

        // Self-hash integrity
        let computed = state.compute_hash()?;
        Ok(computed == state.hash)
    }

    /// Generate a pre-commitment for the next state transition.
    ///
    /// Uses the DeviceState's SMT root as the seed input for the random
    /// walk, falling back to legacy current_state if DeviceState isn't ready.
    pub fn generate_precommitment(
        &self,
        operation: &Operation,
    ) -> Result<(Hash, Vec<Position>), DsmError> {
        // Get entropy + hash from DeviceState or legacy
        let (prior_entropy, prior_hash) = if let Some(ds) = &self.device_state {
            // Use SMT root as the "hash" and a derived entropy
            let root = ds.root();
            let entropy = {
                let mut h = dsm_domain_hasher("DSM/precommit-entropy");
                h.update(&root);
                h.finalize().as_bytes().to_vec()
            };
            (entropy, root)
        } else if let Some(cs) = &self.current_state {
            (cs.entropy.clone(), cs.hash)
        } else {
            return Err(DsmError::state_machine("No current state exists for pre-commitment"));
        };

        let operation_bytes = operation.to_bytes();

        let mut hasher = dsm_domain_hasher("DSM/state-entropy");
        hasher.update(&prior_entropy);
        hasher.update(&operation_bytes);
        hasher.update(&prior_hash);
        let next_entropy = hasher.finalize();

        let current_hash = domain_hash("DSM/chain-hash", &prior_hash);
        let seed = random_walk::algorithms::generate_seed(
            &current_hash,
            &operation_bytes,
            Some(next_entropy.as_bytes()),
        );

        let positions = random_walk::algorithms::generate_positions(
            &seed,
            None::<random_walk::algorithms::RandomWalkConfig>,
        )?;

        Ok((seed, positions))
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

/// Generate deterministic entropy for a transition.
///
/// Per §11 eq. 14, entropy is derived from adjacency inputs: the parent entropy,
/// the operation, and the parent state hash. Per §4.3 no counter participates.
pub fn generate_transition_entropy(
    current_state: &State,
    operation: &Operation,
) -> Result<[u8; 32], DsmError> {
    let op_data = operation.to_bytes();

    // Generate entropy: e_{n+1} = H("DSM/state-entropy" || e_n || op || H(S_n))
    let mut hasher = dsm_domain_hasher("DSM/state-entropy");
    hasher.update(&current_state.entropy);
    hasher.update(&op_data);
    hasher.update(&current_state.hash);

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

/// Verify basic transition properties that apply to all state types.
/// Per §4.3 no counter is checked — only hash adjacency and entropy evolution.
fn verify_basic_transition(state1: &State, state2: &State) -> Result<bool, DsmError> {
    // Verify hash chain continuity (§2.1 eq. 1)
    if state2.prev_state_hash != state1.hash()? {
        return Ok(false);
    }

    // Verify entropy evolution (§11 eq. 14)
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

    // For standard states, verify standard entropy evolution.
    // Per §11 eq. 14 and generate_transition_entropy, entropy is derived from
    // (prev_entropy, op, parent_hash) — hash adjacency inputs, no counter.
    let op_bytes = state2.operation.to_bytes();

    let mut hasher = crate::crypto::blake3::dsm_domain_hasher("DSM/state-entropy");
    hasher.update(&state1.entropy);
    hasher.update(&op_bytes);
    hasher.update(&state1.hash);
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

        // First verify hash chain continuity (§2.1 adjacency)
        if curr_state.prev_state_hash != prev_state.hash()? {
            return Err(DsmError::invalid_operation(format!(
                "Hash chain broken between states {:02x?} and {:02x?}",
                &prev_state.hash[..4],
                &curr_state.hash[..4]
            )));
        }

        // Then verify the transition integrity using the operation
        if !verify_transition_integrity(prev_state, curr_state, &curr_state.operation)? {
            return Err(DsmError::invalid_operation(format!(
                "Invalid state transition between states {:02x?} and {:02x?}",
                &prev_state.hash[..4],
                &curr_state.hash[..4]
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

        let era_policy_commit = crate::core::token::builtin_policy_commit_for_token("ERA")
            .expect("ERA builtin policy commit");

        let era_key = crate::core::token::derive_canonical_balance_key(
            &era_policy_commit,
            &state.device_info.public_key,
            "ERA",
        );
        state
            .token_balances
            .insert(era_key, Balance::from_state(1000, state.hash));

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
            amount: Balance::from_state(10, current_state.hash),
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

            // Generate entropy via hash adjacency (§11 eq. 14). No counter.
            let op_bytes = op.to_bytes();
            let new_entropy = {
                let mut hasher = crate::crypto::blake3::dsm_domain_hasher("DSM/state-entropy");
                hasher.update(&current_state.entropy);
                hasher.update(&op_bytes);
                hasher.update(&current_state.hash);
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

        let dev_id = device_id;
        let rel_key = crate::core::bilateral_transaction_manager::compute_smt_key(&dev_id, &dev_id);
        let init_tip = crate::core::bilateral_transaction_manager::initial_chain_tip_from_device_ids(&dev_id, &dev_id);
        let outcome = state_machine.advance_relationship(rel_key, dev_id, op, &[], Some(init_tip))?;
        assert_ne!(outcome.child_r_a, [0u8; 32]);

        Ok(())
    }

    #[test]
    fn test_state_machine_advance_relationship() -> Result<(), DsmError> {
        let mut machine = StateMachine::new();
        let (initial_state, _pk, sk) = create_test_genesis_state_with_keypair();
        let dev_id = initial_state.device_info.device_id;
        machine.set_state(initial_state);

        let op = signed_transfer(
            &sk,
            machine.current_state().ok_or_else(|| DsmError::state_machine("no state"))?,
            vec![1u8; 8],
            "Test transfer",
        );

        let rel_key = crate::core::bilateral_transaction_manager::compute_smt_key(&dev_id, &dev_id);
        let init_tip = crate::core::bilateral_transaction_manager::initial_chain_tip_from_device_ids(&dev_id, &dev_id);
        let outcome = machine.advance_relationship(rel_key, dev_id, op, &[], Some(init_tip))?;

        // Verify the SMT root advanced
        assert_ne!(outcome.parent_r_a, outcome.child_r_a);
        // Verify the device state was updated
        assert_eq!(machine.device_head().map(|d| d.root()), Some(outcome.child_r_a));

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
            hasher.update(&genesis.hash);
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
            hasher.update(&state1.hash);
            *hasher.finalize().as_bytes()
        };

        let transition2 = create_transition(&state1, op2, &entropy2)?;
        let state2 = apply_transition(&state1, &transition2.operation, &entropy2)?;

        // Create a test next state for verification
        let mut next_state = state2.clone();
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
