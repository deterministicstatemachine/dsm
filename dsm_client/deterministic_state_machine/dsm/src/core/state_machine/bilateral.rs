// SPDX-License-Identifier: MIT OR Apache-2.0

//! Bilateral state machine operations (3-phase commit protocol).
//!
//! Implements the bilateral transfer protocol described in whitepaper Section 3.4:
//! Prepare → Accept → Commit. Each bilateral relationship maintains an isolated
//! state pair where both parties' chains evolve in lockstep with cross-chain
//! continuity verification and forward-linked commitments.
//!
//! Trimmed (Apr 2026): the legacy session/chain-tip-tracking surface
//! (`active_sessions`, `create_session`/`close_session`, `set_local_chain_tip`
//! with its `state_number: u64` parameter, `update_relationship_state` stub,
//! `get_relationship_state*`, the string-id `initialize_relationship` /
//! `ensure_relationship_initialized` aliases) all had zero external callers
//! after the §2.2/§4.3 transition. `set_local_chain_tip` was an explicit §4.3
//! violation. The retained surface is the `*_bytes` API actually consumed by
//! `BilateralTransactionManager`.
//!
//! This manager holds NO entropy source. The one entropy of a transition is
//! derived by Core inside `DeviceState::advance` (Part VII step 3); the
//! bootstrap states of a relationship pair are seeded deterministically from
//! the two device ids and nothing here is random.

use crate::core::state_machine::relationship::{KeyDerivationStrategy, RelationshipManager};
use crate::types::error::DsmError;
use crate::types::state_types::{DeviceInfo, State};
use crate::common::domain_tags::TAG_ENTITY_ID;
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
}

impl BilateralStateManager {
    /// Create a new bilateral state manager
    pub fn new() -> Self {
        Self {
            relationship_manager: RelationshipManager::new(KeyDerivationStrategy::Canonical),
        }
    }

    /// Create a new bilateral state manager with a specific key derivation strategy
    pub fn new_with_strategy(strategy: KeyDerivationStrategy) -> Self {
        Self {
            relationship_manager: RelationshipManager::new(strategy),
        }
    }

    /// Derive a stable, decimal-only label from a full 32-byte id (no hex, no base64).
    /// Uses all 32 bytes as four little-endian u64 groups.
    fn id_from_32(id: &[u8; 32]) -> String {
        let mut w0 = [0u8; 8];
        let mut w1 = [0u8; 8];
        let mut w2 = [0u8; 8];
        let mut w3 = [0u8; 8];
        w0.copy_from_slice(&id[0..8]);
        w1.copy_from_slice(&id[8..16]);
        w2.copy_from_slice(&id[16..24]);
        w3.copy_from_slice(&id[24..32]);
        let a = u64::from_le_bytes(w0);
        let b = u64::from_le_bytes(w1);
        let c = u64::from_le_bytes(w2);
        let d = u64::from_le_bytes(w3);
        format!("{}-{}-{}-{}", a, b, c, d)
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
        if self
            .relationship_manager
            .verify_relationship_exists(
                &domain_hash(TAG_ENTITY_ID, eid.as_bytes()).into(),
                &domain_hash(TAG_ENTITY_ID, cid.as_bytes()).into(),
            )
            .unwrap_or(false)
        {
            return Ok(());
        }

        // Initialize with genesis states. The bootstrap entropy of each side
        // is a deterministic function of the pair — the same on every device
        // and on every run. Nothing about this manager is random.
        let entropy_a = Self::bootstrap_entropy(0, entity_id, counterparty_id);
        let entropy_b = Self::bootstrap_entropy(1, entity_id, counterparty_id);

        let entity_state = State::new_genesis(
            entropy_a,
            DeviceInfo::new(
                domain_hash(TAG_ENTITY_ID, eid.as_bytes()).into(),
                entity_public_key,
            ),
        );
        let counterparty_state = State::new_genesis(
            entropy_b,
            DeviceInfo::new(
                domain_hash(TAG_ENTITY_ID, cid.as_bytes()).into(),
                counterparty_public_key,
            ),
        );

        self.relationship_manager.store_relationship(
            &domain_hash(TAG_ENTITY_ID, eid.as_bytes()).into(),
            &domain_hash(TAG_ENTITY_ID, cid.as_bytes()).into(),
            entity_state,
            counterparty_state,
        )
    }

    /// `H(DSM/genesis-entropy; role ‖ entity_id ‖ counterparty_id)`: the
    /// bootstrap entropy of one side of a relationship pair. Deterministic by
    /// construction; this is the ONLY entropy this manager ever produces, and
    /// it is a bootstrap value, never a transition's.
    fn bootstrap_entropy(role: u8, entity_id: &[u8; 32], counterparty_id: &[u8; 32]) -> [u8; 32] {
        let mut h = crate::crypto::blake3::dsm_domain_hasher(
            crate::common::domain_tags::TAG_DSM_GENESIS_ENTROPY,
        );
        h.update(&[role]);
        h.update(entity_id);
        h.update(counterparty_id);
        *h.finalize().as_bytes()
    }

    /// Get a relationship's current entity-side state (bytes-only IDs)
    pub fn get_relationship_state_bytes(
        &self,
        entity_id: &[u8; 32],
        counterparty_id: &[u8; 32],
    ) -> Result<State, DsmError> {
        let eid = Self::id_from_32(entity_id);
        let cid = Self::id_from_32(counterparty_id);
        self.relationship_manager.get_relationship_state(&eid, &cid)
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

    // ── BilateralStateManager::new / new_with_strategy ─────────────────

    #[test]
    fn new_constructs_manager() {
        let _mgr = make_manager();
    }

    #[test]
    fn new_with_strategy_canonical() {
        let _mgr = BilateralStateManager::new_with_strategy(KeyDerivationStrategy::Canonical);
    }

    #[test]
    fn new_with_strategy_entity_centric() {
        let _mgr = BilateralStateManager::new_with_strategy(KeyDerivationStrategy::EntityCentric);
    }

    #[test]
    fn new_with_strategy_hashed() {
        let _mgr = BilateralStateManager::new_with_strategy(KeyDerivationStrategy::Hashed);
    }

    #[test]
    fn default_constructs_manager() {
        let _mgr = BilateralStateManager::default();
    }

    // ── id_from_32 ──────────────────────────────────────────────────────

    #[test]
    fn id_from_32_zero_bytes() {
        let id = [0u8; 32];
        let result = BilateralStateManager::id_from_32(&id);
        assert_eq!(result, "0-0-0-0");
    }

    #[test]
    fn id_from_32_known_values() {
        let mut id = [0u8; 32];
        id[0] = 1; // lo u64 = 1 (little-endian)
        let result = BilateralStateManager::id_from_32(&id);
        assert_eq!(result, "1-0-0-0");
    }

    #[test]
    fn id_from_32_high_half() {
        let mut id = [0u8; 32];
        id[8] = 2; // hi u64 = 2 (little-endian)
        let result = BilateralStateManager::id_from_32(&id);
        assert_eq!(result, "0-2-0-0");
    }

    #[test]
    fn id_from_32_includes_upper_16_bytes() {
        let mut id_a = [0u8; 32];
        let mut id_b = [0u8; 32];
        id_a[16] = 1;
        id_b[16] = 2;

        assert_ne!(
            BilateralStateManager::id_from_32(&id_a),
            BilateralStateManager::id_from_32(&id_b)
        );
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
    fn bootstrap_entropy_is_deterministic_and_role_separated() {
        let e = [0x11u8; 32];
        let c = [0x22u8; 32];
        assert_eq!(
            BilateralStateManager::bootstrap_entropy(0, &e, &c),
            BilateralStateManager::bootstrap_entropy(0, &e, &c)
        );
        assert_ne!(
            BilateralStateManager::bootstrap_entropy(0, &e, &c),
            BilateralStateManager::bootstrap_entropy(1, &e, &c)
        );
        assert_ne!(
            BilateralStateManager::bootstrap_entropy(0, &e, &c),
            BilateralStateManager::bootstrap_entropy(0, &c, &e)
        );
    }

    #[test]
    fn ensure_relationship_initialized_bytes_is_idempotent() {
        let mut mgr = make_manager();
        let entity = [0x11u8; 32];
        let counterparty = [0x22u8; 32];
        mgr.ensure_relationship_initialized_bytes(&entity, &counterparty, dummy_key(), dummy_key())
            .unwrap();
        let r2 = mgr.ensure_relationship_initialized_bytes(
            &entity,
            &counterparty,
            dummy_key(),
            dummy_key(),
        );
        assert!(r2.is_ok());
    }
}
