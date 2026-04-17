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
// hashchain module deleted: HashChain was a per-device full-state-history
// HashMap superseded by (a) DeviceState's per-relationship SMT (§2.2) for
// current-tip tracking and (b) the BCR archive (bcr_states SQL table) for
// authoritative history. HashChainSDK was the only consumer, also deleted.
pub mod random_walk;
pub mod relationship;
pub mod transition;
pub mod utils;

use crate::core::state_machine::relationship::validate_relationship_state_transition;
use crate::core::state_machine::relationship::verify_relationship_entropy;
use crate::core::state_machine::relationship::KeyDerivationStrategy;
use crate::crypto::blake3::{domain_hash, dsm_domain_hasher};
use crate::types::error::DsmError;
use crate::types::operations::Operation;
use crate::types::state_types::State;
pub use bilateral::BilateralStateManager;
use blake3::Hash;

pub use random_walk::algorithms::{
    generate_positions, generate_random_walk_coordinates, generate_seed, verify_positions,
    verify_random_walk_coordinates, Position, RandomWalkConfig,
};

pub use relationship::{RelationshipManager, RelationshipStatePair};
pub use transition::{create_transition, generate_position_sequence, StateTransition};
pub use utils::constant_time_eq;

/// Type definition for precommitment generation function
/// Core state machine — Per-Device SMT head (§2.2).
///
/// All transitions route through `advance_relationship` which uses
/// `DeviceState::advance()`. The `current_state` field is a vestigial
/// fallback for genesis bootstrap; `device_state` IS the canonical head.
#[derive(Clone, Debug)]
pub struct StateMachine {
    /// Canonical device state per §2.2: SMT root + device-level balances +
    /// per-relationship chain tips. This IS the device head.
    device_state: Option<crate::types::device_state::DeviceState>,
    /// Legacy `State` mirror used by migration shims and validation tooling
    /// that still exercise `apply_transition` directly.
    legacy_state: Option<State>,
    /// Relationship manager for bilateral state isolation
    #[allow(dead_code)]
    relationship_manager: RelationshipManager,
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

    /// Create a new state machine with a specific key derivation strategy and device ID.
    /// `_device_id` is now derived from the bootstrap State; this argument is
    /// retained for API compatibility and ignored.
    pub fn new_with_strategy_and_device_id(
        strategy: KeyDerivationStrategy,
        _device_id: [u8; 32],
    ) -> Self {
        StateMachine {
            device_state: None,
            legacy_state: None,
            relationship_manager: RelationshipManager::new(strategy),
        }
    }

    /// Get the canonical device state (§2.2 SMT head).
    pub fn device_head(&self) -> Option<&crate::types::device_state::DeviceState> {
        self.device_state.as_ref()
    }

    /// Get a compatibility State view from DeviceState. Used by legacy
    /// callers during migration; prefer `device_head()` for new code.
    pub fn current_state(&self) -> Option<State> {
        if let Some(state) = &self.legacy_state {
            return Some(state.clone());
        }

        let ds = self.device_state.as_ref()?;
        let device_info = crate::types::state_types::DeviceInfo::new(
            ds.devid(),
            ds.public_key().to_vec(),
        );
        let hash = ds.root();
        let mut token_balances = std::collections::HashMap::new();
        for (pc, val) in ds.balances_snapshot() {
            let prefix = u128::from_le_bytes({
                let mut a = [0u8; 16];
                a.copy_from_slice(&pc[..16]);
                a
            });
            token_balances.insert(
                format!("{prefix}"),
                crate::types::token_types::Balance::from_state(*val, hash),
            );
        }
        Some(State {
            device_info,
            hash,
            token_balances,
            ..State::default()
        })
    }

    /// Initialize with a genesis state. Bootstraps DeviceState from
    /// the State's device info, seeding the SMT root from the State's hash
    /// so legacy callers' verify_state checks have a head_hash to compare.
    pub fn set_state(&mut self, state: State) {
        let state_hash = state.hash()
            .unwrap_or(state.hash);
        self.legacy_state = Some(state.clone());
        if self.device_state.is_none() {
            let mut ds = crate::types::device_state::DeviceState::new(
                [0u8; 32],
                state.device_info.device_id,
                state.device_info.public_key.clone(),
                1024,
            );
            // Seed SMT root with the State's hash for legacy compat.
            ds.bootstrap_legacy_root(state_hash);
            self.device_state = Some(ds);
        } else {
            // Re-seed with new state hash for tests that swap state.
            if let Some(ds) = self.device_state.as_mut() {
                ds.bootstrap_legacy_root(state_hash);
            }
        }
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
        } else {
            // No prior tip — fresh genesis or first relationship. Use SMT root as seed.
            let root = ds.root();
            let entropy = {
                let mut h = dsm_domain_hasher("DSM/genesis-entropy");
                h.update(&root);
                h.finalize().as_bytes().to_vec()
            };
            (entropy, root)
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
        self.legacy_state = None;

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
        if self.device_state.is_some() {
            Ok(())
        } else {
            Err(DsmError::state_machine(
                "No DeviceState — call set_state with genesis first",
            ))
        }
    }

    // execute_transition / apply_operation / execute_relationship_transition
    // all deleted — every transition now goes through advance_relationship
    // which uses DeviceState::advance (§2.2, §4.2).

    /// Verify a state using hash-chain validation (§2.1 adjacency only).
    ///
    /// Checks that `state.prev_state_hash` embeds the current device head's
    /// hash. Uses DeviceState's SMT root as the canonical identity.
    pub fn verify_state(&self, state: &State) -> Result<bool, DsmError> {
        // Get the current head hash. DeviceState root is canonical ONLY when
        // relationships have been advanced (non-empty SMT). For legacy states
        // created via set_state(), fall back to current_state.hash().
        let head_hash = if let Some(ds) = &self.device_state {
            // Prefer legacy anchor if set (legacy compat path); else SMT root.
            ds.legacy_anchor().unwrap_or_else(|| ds.root())
        } else {
            return Err(DsmError::state_machine("No DeviceState for verification"));
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

    // create_base_operation, update_base_operation, add_relationship_operation,
    // remove_relationship_operation, generic_operation deleted: zero callers.
    // Operation builders for these variants live in their own modules / SDK
    // call sites; the StateMachine no longer mints operations on behalf of
    // callers.
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

// verify_state_chain and internal_hash_blake3 deleted — both were dead.
// Verifiers operate on individual chain states via the SMT inclusion proofs
// in AdvanceOutcome rather than walking arrays of legacy State objects.

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
        use crate::core::state_machine::transition::apply_transition;

        // Create a genesis state for testing
        let (initial_state, _pk, sk) = create_test_genesis_state_with_keypair();

        let mut states = vec![initial_state.clone()];
        let mut current_state = initial_state;

        let num_transitions = if cfg!(debug_assertions) { 1 } else { 3 };
        for i in 0..num_transitions {
            let op = signed_transfer(
                &sk,
                &current_state,
                vec![i as u8; 8],
                &format!("Test transfer {i}"),
            );

            // §11 eq.14 entropy derivation
            let op_bytes = op.to_bytes();
            let new_entropy = {
                let mut hasher = crate::crypto::blake3::dsm_domain_hasher("DSM/state-entropy");
                hasher.update(&current_state.entropy);
                hasher.update(&op_bytes);
                hasher.update(&current_state.hash);
                *hasher.finalize().as_bytes()
            };

            let transition = create_transition(&current_state, op, &new_entropy)?;
            let new_state = apply_transition(&current_state, &transition.operation, &new_entropy)?;

            states.push(new_state.clone());
            current_state = new_state;
        }

        // Verify chain integrity via §2.1 hash adjacency (the only canonical
        // chain-integrity rule in the counterless model).
        for win in states.windows(2) {
            assert_eq!(win[1].prev_state_hash, win[0].hash()?,
                "hash adjacency must hold across the constructed chain");
        }

        // Tamper with intermediate state — adjacency must break.
        let mut broken_states = states.clone();
        broken_states[1].entropy = vec![99, 99, 99];
        if let Ok(hash) = broken_states[1].hash() {
            broken_states[1].hash = hash;
        }
        // states[2].prev_state_hash now points to the OLD broken_states[1] hash
        if states.len() >= 3 {
            assert_ne!(broken_states[2].prev_state_hash, broken_states[1].hash,
                "tampered state breaks adjacency to its successor");
        }

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

        let cur = machine.current_state().ok_or_else(|| DsmError::state_machine("no state"))?;
        let op = signed_transfer(&sk, &cur, vec![1u8; 8], "Test transfer");

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

        let cur = machine.current_state().expect("has state");
        let op = signed_transfer(&sk, &cur, vec![1u8; 8], "Test transfer");

        // Generate precommitment
        let (_, positions) = machine.generate_precommitment(&op)?;

        // Verify precommitment
        assert!(machine.verify_precommitment(&op, &positions)?);

        // Modify operation slightly
        let cur2 = machine.current_state().expect("has state");
        let modified_op = signed_transfer(&sk, &cur2, vec![2u8; 8], "Test transfer modified");

        // Verification should fail
        assert!(!machine.verify_precommitment(&modified_op, &positions)?);

        Ok(())
    }

    #[test]
    fn test_state_verification_chain() -> Result<(), DsmError> {
        use crate::core::state_machine::transition::apply_transition;

        // Build states manually using the same domain tag as generate_transition_entropy
        let (genesis, _pk, sk) = create_test_genesis_state_with_keypair();

        // Create first operation
        let op1 = signed_transfer(&sk, &genesis, vec![1u8; 8], "First transfer");

        // Compute entropy with DSM/state-entropy domain tag matching §11 eq.14
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
