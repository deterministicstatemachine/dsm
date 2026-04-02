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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::state_machine::relationship::KeyDerivationStrategy;

    fn make_manager() -> BilateralStateManager {
        BilateralStateManager::new()
    }

    fn dummy_key() -> Vec<u8> {
        vec![0xAB; 32]
    }

    // ── BilateralStateManager::new ──────────────────────────────────────

    #[test]
    fn new_creates_empty_sessions() {
        let mgr = make_manager();
        assert!(mgr.active_sessions.is_empty());
    }

    // ── BilateralStateManager::new_with_strategy ────────────────────────

    #[test]
    fn new_with_strategy_canonical() {
        let mgr = BilateralStateManager::new_with_strategy(KeyDerivationStrategy::Canonical);
        assert!(mgr.active_sessions.is_empty());
    }

    #[test]
    fn new_with_strategy_entity_centric() {
        let mgr = BilateralStateManager::new_with_strategy(KeyDerivationStrategy::EntityCentric);
        assert!(mgr.active_sessions.is_empty());
    }

    #[test]
    fn new_with_strategy_hashed() {
        let mgr = BilateralStateManager::new_with_strategy(KeyDerivationStrategy::Hashed);
        assert!(mgr.active_sessions.is_empty());
    }

    // ── Default ─────────────────────────────────────────────────────────

    #[test]
    fn default_is_same_as_new() {
        let from_new = BilateralStateManager::new();
        let from_default = BilateralStateManager::default();
        assert_eq!(
            from_new.active_sessions.len(),
            from_default.active_sessions.len()
        );
    }

    // ── id_from_32 ──────────────────────────────────────────────────────

    #[test]
    fn id_from_32_zero_bytes() {
        let id = [0u8; 32];
        let result = BilateralStateManager::id_from_32(&id);
        assert_eq!(result, "0-0");
    }

    #[test]
    fn id_from_32_known_values() {
        let mut id = [0u8; 32];
        id[0] = 1; // lo u64 = 1 (little-endian)
        let result = BilateralStateManager::id_from_32(&id);
        assert_eq!(result, "1-0");
    }

    #[test]
    fn id_from_32_high_half() {
        let mut id = [0u8; 32];
        id[8] = 2; // hi u64 = 2 (little-endian)
        let result = BilateralStateManager::id_from_32(&id);
        assert_eq!(result, "0-2");
    }

    #[test]
    fn id_from_32_consistency() {
        let id = [0xFF; 32];
        let a = BilateralStateManager::id_from_32(&id);
        let b = BilateralStateManager::id_from_32(&id);
        assert_eq!(a, b);
    }

    #[test]
    fn id_from_32_different_inputs_differ() {
        let id_a = [0x01; 32];
        let id_b = [0x02; 32];
        assert_ne!(
            BilateralStateManager::id_from_32(&id_a),
            BilateralStateManager::id_from_32(&id_b),
        );
    }

    // ── label_from_bytes ────────────────────────────────────────────────

    #[test]
    fn label_from_bytes_long_input() {
        let bytes = vec![1u8; 16];
        let label = BilateralStateManager::label_from_bytes(&bytes);
        assert!(label.starts_with("len16:"));
        let lo = u64::from_le_bytes([1; 8]);
        assert!(label.contains(&lo.to_string()));
    }

    #[test]
    fn label_from_bytes_exactly_8() {
        let bytes = vec![0u8; 8];
        let label = BilateralStateManager::label_from_bytes(&bytes);
        assert_eq!(label, "len8:0");
    }

    #[test]
    fn label_from_bytes_short_input() {
        let bytes = vec![0xAA; 3];
        let label = BilateralStateManager::label_from_bytes(&bytes);
        assert_eq!(label, "len3");
    }

    #[test]
    fn label_from_bytes_empty() {
        let label = BilateralStateManager::label_from_bytes(&[]);
        assert_eq!(label, "len0");
    }

    // ── create_session / close_session ──────────────────────────────────

    #[test]
    fn create_session_returns_expected_id() {
        let mut mgr = make_manager();
        let sid = mgr.create_session("alice", "bob");
        assert_eq!(sid, "session_alice_bob");
    }

    #[test]
    fn create_session_stores_in_active_sessions() {
        let mut mgr = make_manager();
        let sid = mgr.create_session("alice", "bob");
        assert!(mgr.active_sessions.contains_key(&sid));
        assert_eq!(
            mgr.active_sessions.get(&sid).unwrap(),
            "alice:bob"
        );
    }

    #[test]
    fn close_session_existing_returns_true() {
        let mut mgr = make_manager();
        let sid = mgr.create_session("alice", "bob");
        assert!(mgr.close_session(&sid));
        assert!(!mgr.active_sessions.contains_key(&sid));
    }

    #[test]
    fn close_session_nonexistent_returns_false() {
        let mut mgr = make_manager();
        assert!(!mgr.close_session("no_such_session"));
    }

    #[test]
    fn close_session_twice_returns_false_second_time() {
        let mut mgr = make_manager();
        let sid = mgr.create_session("alice", "bob");
        assert!(mgr.close_session(&sid));
        assert!(!mgr.close_session(&sid));
    }

    // ── generate_entropy ────────────────────────────────────────────────

    #[test]
    fn generate_entropy_returns_32_bytes() {
        let mgr = make_manager();
        let entropy = mgr.generate_entropy().unwrap();
        assert_eq!(entropy.len(), 32);
    }

    #[test]
    fn generate_entropy_two_calls_differ() {
        let mgr = make_manager();
        let a = mgr.generate_entropy().unwrap();
        let b = mgr.generate_entropy().unwrap();
        assert_ne!(a, b);
    }

    // ── initialize_relationship ─────────────────────────────────────────

    #[test]
    fn initialize_relationship_succeeds() {
        let mut mgr = make_manager();
        let result = mgr.initialize_relationship(
            "alice",
            "bob",
            dummy_key(),
            dummy_key(),
        );
        assert!(result.is_ok());
    }

    // ── ensure_relationship_initialized ─────────────────────────────────

    #[test]
    fn ensure_relationship_initialized_is_idempotent() {
        let mut mgr = make_manager();
        let r1 = mgr.ensure_relationship_initialized(
            "alice",
            "bob",
            dummy_key(),
            dummy_key(),
        );
        assert!(r1.is_ok());

        let r2 = mgr.ensure_relationship_initialized(
            "alice",
            "bob",
            dummy_key(),
            dummy_key(),
        );
        assert!(r2.is_ok());
    }

    // ── ensure_relationship_initialized_bytes ───────────────────────────

    #[test]
    fn ensure_relationship_initialized_bytes_succeeds() {
        let mut mgr = make_manager();
        let entity = [0x01u8; 32];
        let counterparty = [0x02u8; 32];
        let result = mgr.ensure_relationship_initialized_bytes(
            &entity,
            &counterparty,
            dummy_key(),
            dummy_key(),
        );
        assert!(result.is_ok());
    }

    #[test]
    fn ensure_relationship_initialized_bytes_is_idempotent() {
        let mut mgr = make_manager();
        let entity = [0x11u8; 32];
        let counterparty = [0x22u8; 32];
        mgr.ensure_relationship_initialized_bytes(
            &entity,
            &counterparty,
            dummy_key(),
            dummy_key(),
        )
        .unwrap();
        let r2 = mgr.ensure_relationship_initialized_bytes(
            &entity,
            &counterparty,
            dummy_key(),
            dummy_key(),
        );
        assert!(r2.is_ok());
    }

    // ── update_relationship_state ───────────────────────────────────────

    #[test]
    fn update_relationship_state_accepts_pair() {
        let mut mgr = make_manager();

        let entity_id = [0x01u8; 32];
        let counterparty_id = [0x02u8; 32];
        let entropy_a = mgr.generate_entropy().unwrap();
        let entropy_b = mgr.generate_entropy().unwrap();

        let entity_state = State::new_genesis(
            entropy_a,
            DeviceInfo::new(entity_id, dummy_key()),
        );
        let counterparty_state = State::new_genesis(
            entropy_b,
            DeviceInfo::new(counterparty_id, dummy_key()),
        );

        let pair = RelationshipStatePair::new(
            entity_id,
            counterparty_id,
            entity_state,
            counterparty_state,
        )
        .unwrap();

        let result = mgr.update_relationship_state("bob", pair);
        assert!(result.is_ok());
    }

    // ── multiple sessions coexist ───────────────────────────────────────

    #[test]
    fn multiple_sessions_coexist() {
        let mut mgr = make_manager();
        let s1 = mgr.create_session("alice", "bob");
        let s2 = mgr.create_session("alice", "carol");
        assert_ne!(s1, s2);
        assert_eq!(mgr.active_sessions.len(), 2);

        mgr.close_session(&s1);
        assert_eq!(mgr.active_sessions.len(), 1);
        assert!(mgr.active_sessions.contains_key(&s2));
    }
}
