//! Fluent builder for constructing [`State`] instances.
//!
//! The [`StateBuilder`] provides a step-by-step, ergonomic interface for assembling
//! valid [`State`] objects with all required fields (entropy, device ID, public key)
//! and optional fields (token balances, relationship context, forward commitments,
//! sparse index). If the hash field is left zeroed, `build()` computes the
//! domain-separated BLAKE3 state hash automatically using `"DSM/state-hash"`.
//!
//! Token balance integration follows whitepaper section 9: balances are stored
//! atomically within each state to enforce the conservation invariant
//! `B_{n+1} = B_n + Delta, B >= 0`.

use crate::types::error::DsmError;
use crate::types::operations::Operation;
use crate::types::state_types::{
    PositionSequence, PreCommitment, RelationshipContext, SparseIndex, State, StateFlag,
};
use crate::types::token_types::Balance;
use std::collections::{HashMap, HashSet};

/// Builder pattern for creating State objects in a fluent way
/// Allows for optional fields and token balance integration
pub struct StateBuilder {
    id: String,
    state_number: u64,
    entropy: Vec<u8>,
    encapsulated_entropy: Option<Vec<u8>>,
    prev_state_hash: [u8; 32],
    sparse_index: Option<SparseIndex>,
    operation: Operation,
    device_id: [u8; 32],
    public_key: Vec<u8>,
    hash: [u8; 32],
    flags: HashSet<StateFlag>,
    relationship_context: Option<RelationshipContext>,
    // Token balance integration as specified in whitepaper section 9
    token_balances: HashMap<String, Balance>,
    forward_commitment: Option<PreCommitment>,
    #[allow(dead_code)]
    positions: Vec<Vec<i32>>,
    #[allow(dead_code)]
    position_sequence: Option<PositionSequence>,
    external_data: HashMap<String, Vec<u8>>,
}

impl Default for StateBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl StateBuilder {
    /// Create a new StateBuilder
    pub fn new() -> Self {
        Self {
            id: String::new(),
            state_number: 0,
            entropy: Vec::new(),
            encapsulated_entropy: None,
            prev_state_hash: [0u8; 32],
            sparse_index: None,
            operation: Operation::default(),
            device_id: [0u8; 32],
            public_key: Vec::new(),
            hash: [0u8; 32],
            flags: HashSet::new(),
            relationship_context: None,
            token_balances: HashMap::new(),
            forward_commitment: None,
            positions: Vec::new(),
            // Initialize position_sequence with a default value
            position_sequence: None,
            external_data: HashMap::new(),
        }
    }

    pub fn with_id(mut self, id: String) -> Self {
        self.id = id;
        self
    }

    /// Set the state number
    pub fn with_state_number(mut self, state_number: u64) -> Self {
        self.state_number = state_number;
        self
    }

    /// Set the entropy
    pub fn with_entropy(mut self, entropy: Vec<u8>) -> Self {
        self.entropy = entropy;
        self
    }

    /// Set the encapsulated entropy
    pub fn with_encapsulated_entropy(mut self, encapsulated_entropy: Vec<u8>) -> Self {
        self.encapsulated_entropy = Some(encapsulated_entropy);
        self
    }

    /// Set the forward commitment
    pub fn with_forward_commitment(mut self, commitment: PreCommitment) -> Self {
        self.forward_commitment = Some(commitment);
        self
    }

    /// Set the previous state hash
    pub fn with_prev_hash(mut self, prev_state_hash: [u8; 32]) -> Self {
        self.prev_state_hash = prev_state_hash;
        self
    }

    /// Set the sparse index
    pub fn with_sparse_index(mut self, sparse_index: SparseIndex) -> Self {
        self.sparse_index = Some(sparse_index);
        self
    }

    /// Set the operation
    pub fn with_operation(mut self, operation: Operation) -> Self {
        self.operation = operation;
        self
    }

    /// Set the device ID
    pub fn with_device_id(mut self, device_id: [u8; 32]) -> Self {
        self.device_id = device_id;
        self
    }

    /// Set the public key
    pub fn with_public_key(mut self, public_key: Vec<u8>) -> Self {
        self.public_key = public_key;
        self
    }

    /// Set the device info
    pub fn with_device_info(mut self, device_info: crate::types::state_types::DeviceInfo) -> Self {
        self.device_id = device_info.device_id;
        self.public_key = device_info.public_key.clone();
        self
    }

    /// Add a flag
    pub fn with_flag(mut self, flag: StateFlag) -> Self {
        self.flags.insert(flag);
        self
    }

    /// Add multiple flags
    pub fn with_flags(mut self, flags: HashSet<StateFlag>) -> Self {
        self.flags = flags;
        self
    }

    /// Set token balances for atomic state updates (whitepaper section 9)
    pub fn with_token_balances(mut self, token_balances: HashMap<String, Balance>) -> Self {
        self.token_balances = token_balances;
        self
    }

    /// Add a single token balance entry
    pub fn with_token_balance(mut self, token_id: String, balance: Balance) -> Self {
        self.token_balances.insert(token_id, balance);
        self
    }

    /// Add a parameter to the external data
    pub fn with_parameter(self, _key: &str, _value: Vec<u8>) -> Self {
        let mut new_self = self;
        new_self.external_data.insert(_key.to_string(), _value);
        new_self
    }

    pub fn with_relationship_context(mut self, relationship_context: RelationshipContext) -> Self {
        self.relationship_context = Some(relationship_context);
        self
    }

    pub fn build_relationship_context(mut self) -> Self {
        if self.relationship_context.is_none() {
            let context = RelationshipContext {
                entity_id: self.device_id,
                entity_state_number: 0,
                counterparty_id: [0u8; 32],
                counterparty_state_number: 0,
                counterparty_public_key: Vec::new(),
                relationship_hash: Vec::new(),
                active: true,
                chain_tip_id: None,
                last_bilateral_state_hash: None,
            };
            self.relationship_context = Some(context);
        }
        self
    }

    /// Build relationship context with chain tip information
    pub fn build_relationship_context_with_chain_tip(
        mut self,
        counterparty_id: [u8; 32],
        chain_tip_id: String,
    ) -> Self {
        let context = RelationshipContext::new_with_chain_tip(
            self.device_id,
            counterparty_id,
            Vec::new(), // Default empty public key
            chain_tip_id,
        );
        self.relationship_context = Some(context);
        self
    }

    /// Set the previous state hash
    pub fn with_prev_state_hash(mut self, prev_state_hash: [u8; 32]) -> Self {
        self.prev_state_hash = prev_state_hash;
        self
    }

    /// Set the hash directly
    pub fn with_hash(mut self, hash: [u8; 32]) -> Self {
        self.hash = hash;
        self
    }

    /// Build the State object
    pub fn build(mut self) -> Result<State, DsmError> {
        // Calculate state hash if not set
        if self.hash == [0u8; 32] {
            // Prepare data for hashing
            let mut data = Vec::new();
            data.extend_from_slice(self.id.as_bytes());
            data.extend_from_slice(&self.state_number.to_le_bytes());
            data.extend_from_slice(&self.entropy);

            if let Some(ee) = &self.encapsulated_entropy {
                data.extend_from_slice(ee);
            }

            data.extend_from_slice(&self.prev_state_hash);

            // Deterministic operation bytes (no Serde)
            let serialized_op = self.operation.to_bytes();
            data.extend_from_slice(&serialized_op);

            data.extend_from_slice(&self.device_id);
            data.extend_from_slice(&self.public_key);

            if let Some(ctx) = &self.relationship_context {
                // Deterministic minimal encoding for context fields used in hashing
                data.extend_from_slice(&ctx.entity_id);
                data.extend_from_slice(&ctx.entity_state_number.to_le_bytes());
                data.extend_from_slice(&ctx.counterparty_id);
                data.extend_from_slice(&ctx.counterparty_state_number.to_le_bytes());
                data.extend_from_slice(&ctx.counterparty_public_key);
                if let Some(tip) = &ctx.chain_tip_id {
                    data.extend_from_slice(tip.as_bytes());
                }
                if let Some(h) = &ctx.last_bilateral_state_hash {
                    data.extend_from_slice(h);
                }
            }

            let hash = crate::crypto::blake3::domain_hash("DSM/state-hash", &data);
            // Convert hash to bytes
            let mut hash_bytes = [0u8; 32];
            hash_bytes.copy_from_slice(hash.as_bytes());
            self.hash = hash_bytes;
        }

        // Require mandatory fields
        let entropy = if self.entropy.is_empty() {
            return Err(DsmError::invalid_parameter(
                "Entropy is required for state creation",
            ));
        } else {
            self.entropy
        };

        let prev_state_hash = self.prev_state_hash;

        let sparse_index = self.sparse_index.unwrap_or_else(|| {
            let height = (self.state_number as f64).log2().ceil() as u64;
            SparseIndex::new(vec![height])
        });

        let operation = self.operation;

        if self.device_id.is_empty() {
            return Err(DsmError::invalid_parameter(
                "Device ID is required for state creation",
            ));
        }

        let public_key = if self.public_key.is_empty() {
            return Err(DsmError::invalid_parameter(
                "Public key is required for state creation",
            ));
        } else {
            self.public_key
        };

        // Create StateParams and use State::new for proper construction
        let device_info = crate::types::state_types::DeviceInfo {
            device_id: self.device_id,
            public_key: public_key.clone(),
            metadata: Vec::new(),
        };

        let params = crate::types::state_types::StateParams::new(
            self.state_number,
            entropy,
            operation,
            device_info,
        )
        .with_prev_state_hash(prev_state_hash)
        .with_sparse_index(sparse_index);

        let mut state = crate::types::state_types::State::new(params);
        // Set additional fields that aren't in StateParams::new
        state.id = self.id;
        state.hash = self.hash;
        state.encapsulated_entropy = self.encapsulated_entropy;
        state.flags = self.flags;
        state.token_balances = self.token_balances;
        state.relationship_context = self.relationship_context;
        state.set_external_data(self.external_data);
        Ok(state)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::operations::Operation;
    use crate::types::state_types::StateFlag;

    fn valid_builder() -> StateBuilder {
        StateBuilder::new()
            .with_entropy(vec![0xAA; 32])
            .with_device_id([0x11; 32])
            .with_public_key(vec![0x22; 64])
    }

    // --- Successful builds ---

    #[test]
    fn build_minimal_valid_state() {
        let state = valid_builder().build().unwrap();
        assert_eq!(state.device_info.device_id, [0x11; 32]);
        assert_eq!(state.device_info.public_key, vec![0x22; 64]);
        assert_ne!(state.hash, [0u8; 32]);
    }

    #[test]
    fn build_with_state_number() {
        let state = valid_builder().with_state_number(42).build().unwrap();
        assert_eq!(state.state_number, 42);
    }

    #[test]
    fn build_with_id() {
        let state = valid_builder().with_id("my-state".into()).build().unwrap();
        assert_eq!(state.id, "my-state");
    }

    #[test]
    fn build_with_explicit_hash() {
        let hash = [0xFF; 32];
        let state = valid_builder().with_hash(hash).build().unwrap();
        assert_eq!(state.hash, hash);
    }

    #[test]
    fn build_auto_computed_hash_is_deterministic() {
        let h1 = valid_builder().with_state_number(1).build().unwrap().hash;
        let h2 = valid_builder().with_state_number(1).build().unwrap().hash;
        assert_eq!(h1, h2);
    }

    #[test]
    fn build_different_state_numbers_produce_different_hashes() {
        let h1 = valid_builder().with_state_number(1).build().unwrap().hash;
        let h2 = valid_builder().with_state_number(2).build().unwrap().hash;
        assert_ne!(h1, h2);
    }

    // --- Validation failures ---

    #[test]
    fn build_fails_without_entropy() {
        let result = StateBuilder::new()
            .with_device_id([0x11; 32])
            .with_public_key(vec![0x22; 64])
            .build();
        assert!(result.is_err());
    }

    #[test]
    fn build_fails_without_public_key() {
        let result = StateBuilder::new()
            .with_entropy(vec![0xAA; 32])
            .with_device_id([0x11; 32])
            .build();
        assert!(result.is_err());
    }

    // --- Optional fields ---

    #[test]
    fn build_with_prev_state_hash() {
        let prev = [0xBB; 32];
        let state = valid_builder().with_prev_state_hash(prev).build().unwrap();
        assert_eq!(state.prev_state_hash, prev);
    }

    #[test]
    fn build_with_prev_hash_alias() {
        let prev = [0xCC; 32];
        let state = valid_builder().with_prev_hash(prev).build().unwrap();
        assert_eq!(state.prev_state_hash, prev);
    }

    #[test]
    fn build_with_operation() {
        let state = valid_builder()
            .with_operation(Operation::Genesis)
            .build()
            .unwrap();
        assert!(matches!(state.operation, Operation::Genesis));
    }

    #[test]
    fn build_with_flags() {
        let mut flags = HashSet::new();
        flags.insert(StateFlag::Recovered);
        let state = valid_builder().with_flags(flags.clone()).build().unwrap();
        assert!(state.flags.contains(&StateFlag::Recovered));
    }

    #[test]
    fn build_with_single_flag() {
        let state = valid_builder()
            .with_flag(StateFlag::Synced)
            .build()
            .unwrap();
        assert!(state.flags.contains(&StateFlag::Synced));
    }

    #[test]
    fn build_with_token_balance() {
        let balance = Balance::from_state(500, [0; 32], 1);
        let state = valid_builder()
            .with_token_balance("ERA".into(), balance)
            .build()
            .unwrap();
        assert!(state.token_balances.contains_key("ERA"));
        assert_eq!(state.token_balances["ERA"].value(), 500);
    }

    #[test]
    fn build_with_token_balances_map() {
        let mut balances = HashMap::new();
        balances.insert("ERA".into(), Balance::from_state(100, [0; 32], 1));
        balances.insert("TEST".into(), Balance::from_state(200, [0; 32], 1));
        let state = valid_builder()
            .with_token_balances(balances)
            .build()
            .unwrap();
        assert_eq!(state.token_balances.len(), 2);
    }

    #[test]
    fn build_with_encapsulated_entropy() {
        let state = valid_builder()
            .with_encapsulated_entropy(vec![0xDD; 32])
            .build()
            .unwrap();
        assert_eq!(state.encapsulated_entropy, Some(vec![0xDD; 32]));
    }

    #[test]
    fn build_with_relationship_context() {
        let ctx = RelationshipContext::new([0x11; 32], [0x22; 32], vec![0x33; 64]);
        let state = valid_builder()
            .with_relationship_context(ctx)
            .build()
            .unwrap();
        assert!(state.relationship_context.is_some());
    }

    #[test]
    fn build_relationship_context_auto() {
        let state = valid_builder()
            .build_relationship_context()
            .build()
            .unwrap();
        let ctx = state.relationship_context.unwrap();
        assert_eq!(ctx.entity_id, [0x11; 32]);
        assert!(ctx.active);
    }

    #[test]
    fn build_relationship_context_with_chain_tip() {
        let state = valid_builder()
            .build_relationship_context_with_chain_tip([0x33; 32], "tip-1".into())
            .build()
            .unwrap();
        let ctx = state.relationship_context.unwrap();
        assert_eq!(ctx.counterparty_id, [0x33; 32]);
        assert_eq!(ctx.chain_tip_id, Some("tip-1".into()));
    }

    #[test]
    fn build_with_parameter() {
        let state = valid_builder()
            .with_parameter("key", vec![1, 2, 3])
            .build()
            .unwrap();
        assert_eq!(state.get_parameter("key"), Some(&vec![1u8, 2, 3]));
    }

    #[test]
    fn build_with_device_info() {
        let info = crate::types::state_types::DeviceInfo {
            device_id: [0xAA; 32],
            public_key: vec![0xBB; 64],
            metadata: vec![],
        };
        let state = valid_builder()
            .with_device_info(info)
            .with_entropy(vec![1; 32])
            .build()
            .unwrap();
        assert_eq!(state.device_info.device_id, [0xAA; 32]);
        assert_eq!(state.device_info.public_key, vec![0xBB; 64]);
    }

    // --- Default ---

    #[test]
    fn default_builder_matches_new() {
        let a = StateBuilder::default();
        let b = StateBuilder::new();
        assert_eq!(a.state_number, b.state_number);
        assert_eq!(a.entropy, b.entropy);
        assert_eq!(a.device_id, b.device_id);
    }
}
