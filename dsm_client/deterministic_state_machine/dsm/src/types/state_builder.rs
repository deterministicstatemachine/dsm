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
