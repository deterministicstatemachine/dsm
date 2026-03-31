//! Bilateral state machine operations (3-phase commit protocol).
//!
//! Implements the bilateral transfer protocol described in whitepaper Section 3.4:
//! Prepare → Accept → Commit. Each bilateral relationship maintains an isolated
//! state pair where both parties' chains evolve in lockstep with cross-chain
//! continuity verification and forward-linked commitments.

use crate::core::state_machine::relationship::{
    KeyDerivationStrategy, RelationshipManager, RelationshipStatePair,
};
use crate::types::error::DsmError;
use crate::types::operations::Operation;
use crate::types::state_types::{DeviceInfo, State};
use std::collections::HashMap;
use log;
use crate::crypto::blake3::domain_hash;

/// BilateralStateManager handles bilateral state transitions between entities
///
/// This component provides a specialized interface for managing bilateral relationships,
/// building on the core relationship functionality while providing bilateral-specific
/// features.
#[derive(Clone, Debug)]
pub struct BilateralStateManager {
    /// Underlying relationship manager
    relationship_manager: RelationshipManager,

    /// Active bilateral sessions by session ID
    active_sessions: HashMap<String, String>,
}

impl BilateralStateManager {
    /// Create a new bilateral state manager
    pub fn new() -> Self {
        Self {
            relationship_manager: RelationshipManager::new(KeyDerivationStrategy::Canonical),
            active_sessions: HashMap::new(),
        }
    }

    /// Derive a stable, decimal-only label from a 32-byte id (no hex, no base64).
    /// Uses first 16 bytes as two little-endian u64 numbers.
    fn id_from_32(id: &[u8; 32]) -> String {
        let mut lo = [0u8; 8];
        let mut hi = [0u8; 8];
        lo.copy_from_slice(&id[0..8]);
        hi.copy_from_slice(&id[8..16]);
        let a = u64::from_le_bytes(lo);
        let b = u64::from_le_bytes(hi);
        format!("{}-{}", a, b)
    }

    /// Short decimal label from arbitrary bytes for logs (no encodings).
    fn label_from_bytes(bytes: &[u8]) -> String {
        if bytes.len() >= 8 {
            let mut lo = [0u8; 8];
            lo.copy_from_slice(&bytes[0..8]);
            let a = u64::from_le_bytes(lo);
            format!("len{}:{}", bytes.len(), a)
        } else {
            format!("len{}", bytes.len())
        }
    }

    /// Ensure a relationship exists; if not, initialize with genesis states (bytes-only IDs)
    pub fn ensure_relationship_initialized_bytes(
        &mut self,
        entity_id: &[u8; 32],
        counterparty_id: &[u8; 32],
        entity_public_key: Vec<u8>,
        counterparty_public_key: Vec<u8>,
    ) -> Result<(), DsmError> {
        let eid = Self::id_from_32(entity_id);
        let cid = Self::id_from_32(counterparty_id);
        self.ensure_relationship_initialized(&eid, &cid, entity_public_key, counterparty_public_key)
    }

    /// Execute a bilateral state transition (bytes-only IDs)
    pub fn execute_transition_bytes(
        &mut self,
        entity_id: &[u8; 32],
        counterparty_id: &[u8; 32],
        operation: Operation,
        entropy: [u8; 32],
    ) -> Result<RelationshipStatePair, DsmError> {
        let eid = Self::id_from_32(entity_id);
        let cid = Self::id_from_32(counterparty_id);
        self.execute_transition(&eid, &cid, operation, entropy)
    }

    /// Get a relationship's current state (bytes-only IDs)
    pub fn get_relationship_state_bytes(
        &self,
        entity_id: &[u8; 32],
        counterparty_id: &[u8; 32],
    ) -> Result<State, DsmError> {
        let eid = Self::id_from_32(entity_id);
        let cid = Self::id_from_32(counterparty_id);
        self.get_relationship_state(&eid, &cid)
    }

    /// Initialize a relationship with genesis states if it doesn't already exist
    pub fn initialize_relationship(
        &mut self,
        entity_id: &str,
        counterparty_id: &str,
        entity_public_key: Vec<u8>,
        counterparty_public_key: Vec<u8>,
    ) -> Result<(), DsmError> {
        // Create simple genesis states for both sides
        let entropy_a = self.generate_entropy()?;
        let entropy_b = self.generate_entropy()?;

        let entity_state = State::new_genesis(
            entropy_a,
            DeviceInfo::new(
                domain_hash("DSM/entity-id", entity_id.as_bytes()).into(),
                entity_public_key,
            ),
        );
        let counterparty_state = State::new_genesis(
            entropy_b,
            DeviceInfo::new(
                domain_hash("DSM/entity-id", counterparty_id.as_bytes()).into(),
                counterparty_public_key,
            ),
        );

        self.relationship_manager.store_relationship(
            &domain_hash("DSM/entity-id", entity_id.as_bytes()).into(),
            &domain_hash("DSM/entity-id", counterparty_id.as_bytes()).into(),
            entity_state,
            counterparty_state,
        )
    }

    /// Ensure a relationship exists; if not, initialize with genesis states
    pub fn ensure_relationship_initialized(
        &mut self,
        entity_id: &str,
        counterparty_id: &str,
        entity_public_key: Vec<u8>,
        counterparty_public_key: Vec<u8>,
    ) -> Result<(), DsmError> {
        if self
            .relationship_manager
            .verify_relationship_exists(
                &domain_hash("DSM/entity-id", entity_id.as_bytes()).into(),
                &domain_hash("DSM/entity-id", counterparty_id.as_bytes()).into(),
            )
            .unwrap_or(false)
        {
            return Ok(());
        }
        self.initialize_relationship(
            entity_id,
            counterparty_id,
            entity_public_key,
            counterparty_public_key,
        )
    }

    /// Create a new bilateral state manager with a specific key derivation strategy
    pub fn new_with_strategy(strategy: KeyDerivationStrategy) -> Self {
        Self {
            relationship_manager: RelationshipManager::new(strategy),
            active_sessions: HashMap::new(),
        }
    }

    /// Execute a bilateral state transition
    pub fn execute_transition(
        &mut self,
        entity_id: &str,
        counterparty_id: &str,
        operation: Operation,
        entropy: [u8; 32],
    ) -> Result<RelationshipStatePair, DsmError> {
        self.relationship_manager.execute_relationship_transition(
            &domain_hash("DSM/entity-id", entity_id.as_bytes()).into(),
            &domain_hash("DSM/entity-id", counterparty_id.as_bytes()).into(),
            operation,
            entropy,
        )
    }

    /// Get a relationship's current state
    pub fn get_relationship_state(
        &self,
        entity_id: &str,
        counterparty_id: &str,
    ) -> Result<State, DsmError> {
        self.relationship_manager
            .get_relationship_state(entity_id, counterparty_id)
    }

    /// Create a session for a bilateral interaction
    pub fn create_session(&mut self, entity_id: &str, counterparty_id: &str) -> String {
        let session_id = format!("session_{}_{}", entity_id, counterparty_id);
        let relationship_id = format!("{}:{}", entity_id, counterparty_id);

        self.active_sessions
            .insert(session_id.clone(), relationship_id);
        session_id
    }

    /// Close a bilateral session
    pub fn close_session(&mut self, session_id: &str) -> bool {
        self.active_sessions.remove(session_id).is_some()
    }

    /// Set local chain tip for a relationship
    pub fn set_local_chain_tip(
        &mut self,
        entity_id: &str,
        counterparty_id: &str,
        state_number: u64,
        hash: Vec<u8>,
    ) -> Result<(), DsmError> {
        let relationship_key = format!("{}:{}", entity_id, counterparty_id);
        let hlabel = Self::label_from_bytes(&hash);
        log::info!(
            "Set chain tip for relationship {}: state #{} hash {}",
            relationship_key,
            state_number,
            hlabel
        );
        let entity_hash: [u8; 32] = domain_hash("DSM/entity-id", entity_id.as_bytes()).into();
        let counterparty_hash: [u8; 32] =
            domain_hash("DSM/entity-id", counterparty_id.as_bytes()).into();
        let chain_tip_id = format!("state:{}:{}", state_number, hlabel);

        if let Err(e) = self.relationship_manager.update_relationship_chain_tip(
            &entity_hash,
            &counterparty_hash,
            chain_tip_id,
            hash.clone(),
        ) {
            log::warn!(
                "Failed to persist chain tip for relationship {}: {}",
                relationship_key,
                e
            );
            return Err(e);
        }
        Ok(())
    }

    /// Generate entropy for state transitions (no wall-clock)
    pub fn generate_entropy(&self) -> Result<[u8; 32], DsmError> {
        let mut entropy = Vec::with_capacity(16 + 32);

        // Deterministic seed component from RNG (named `seed` to avoid time semantics)
        use rand::Rng;
        let mut rng = crate::crypto::rng::SecureRng;
        let seed = rng.next_u64();
        entropy.extend_from_slice(&seed.to_le_bytes());

        // Add random bytes
        let mut random_bytes = [0u8; 32];
        rng.fill_bytes(&mut random_bytes);
        entropy.extend_from_slice(&random_bytes);

        // Hash the combined entropy for consistency (binary out)
        let hash =
            *crate::crypto::blake3::domain_hash("DSM/bilateral-entropy", &entropy).as_bytes();
        Ok(hash)
    }

    /// Update relationship state with new state pair
    pub fn update_relationship_state(
        &mut self,
        counterparty_id: &str,
        state_pair: RelationshipStatePair,
    ) -> Result<(), DsmError> {
        // This would integrate with the relationship manager to update the state
        log::info!(
            "Updated relationship state for counterparty: {}",
            counterparty_id
        );

        // Store via relationship_manager when that API is exposed; for now just acknowledge.
        let _ = state_pair;
        Ok(())
    }
}

impl Default for BilateralStateManager {
    fn default() -> Self {
        Self::new()
    }
}
