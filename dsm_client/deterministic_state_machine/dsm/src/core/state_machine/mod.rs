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

use crate::core::state_machine::relationship::KeyDerivationStrategy;
use crate::crypto::blake3::dsm_domain_hasher;
use crate::types::error::DsmError;
use crate::types::operations::Operation;
use crate::types::state_types::State;
pub use bilateral::BilateralStateManager;

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

    // verify_state(&State) deleted: only callers were its own internal tests
    // (in this module's #[cfg(test)] block). The canonical hash-adjacency
    // verifier is transition::verify_transition_integrity which the same
    // tests already exercise. External code reads DeviceState::root()
    // directly per §2.2 for the canonical head hash.

    // generate_precommitment / verify_precommitment removed: only called by
    // their own in-module test. The §11 pre-commitment story now flows
    // through commitments::precommit::PreCommitment which takes a canonical
    // 32-byte parent hash directly. This shim was a vestigial random-walk
    // wrapper that re-derived seeds from DeviceState's SMT root.

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

// generate_transition_entropy + verify_transition_integrity (and their
// helpers verify_basic_transition / verify_standard_transition /
// verify_entropy_evolution / is_operation_allowed) removed: zero external
// callers. The mod-level free functions were a legacy &[State]-walking
// verification path; the live verification now flows through
// transition::verify_transition_integrity (which operates on individual
// states via §2.1 hash adjacency) and StateMachine::verify_state (which
// uses DeviceState's SMT root as the canonical identity).
//
// Likewise, validate_relationship_state_transition and
// verify_relationship_entropy in relationship.rs (only called from these
// deleted helpers) become dead and are removed alongside.

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

    // test_precommitment_generation_and_verification removed alongside the
    // deleted StateMachine::generate_precommitment / verify_precommitment.

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

        // Verify state2 from state1 using transition::verify_transition_integrity
        // (the canonical hash-adjacency verifier; the mod.rs free-function
        // wrapper and StateMachine::verify_state(&State) shim have both been removed).
        assert!(crate::core::state_machine::transition::verify_transition_integrity(
            &state1,
            &state2,
            &state2.operation,
        )?);

        // Tampered child must fail integrity verification.
        let mut invalid_state = state2.clone();
        invalid_state.prev_state_hash = [0; 32]; // Wrong hash
        assert!(!crate::core::state_machine::transition::verify_transition_integrity(
            &state1,
            &invalid_state,
            &invalid_state.operation,
        )?);

        Ok(())
    }
}
