//! Relationship Management Module
//!
//! This module implements bilateral state isolation for DSM as described in
//! whitepaper section 3.4. It ensures that transactions between specific entities
//! maintain their own isolated context while preserving cryptographic integrity.
//! Temporal ordering is enforced through the hash chain structure itself.

use std::{
    collections::{HashMap, HashSet},
    sync::Mutex,
};

use crate::crypto::blake3::dsm_domain_hasher;
use base32;
use zerocopy::IntoBytes;

use crate::types::{
    error::DsmError,
    operations::Operation,
    state_types::State,
};

#[derive(Debug, Clone)]
pub struct StateTransition {
    pub operation: Operation,
    pub new_entropy: Option<Vec<u8>>,
    pub encapsulated_entropy: Option<Vec<u8>>,
    pub device_id: [u8; 32],
}

impl StateTransition {
    pub fn new(
        operation: Operation,
        new_entropy: Option<Vec<u8>>,
        encapsulated_entropy: Option<Vec<u8>>,
        device_id: &[u8; 32],
    ) -> Self {
        Self {
            operation,
            new_entropy,
            encapsulated_entropy,
            device_id: *device_id,
        }
    }
}

#[derive(Debug, Clone)]
pub struct SmartCommitment {
    pub hash: Vec<u8>,
    pub commitment_type: CommitmentType,
    pub parameters: HashMap<String, String>,
    pub fixed_parameters: HashMap<String, Vec<u8>>,
    pub variable_parameters: HashSet<String>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CommitmentType {
    TimeLocked,
    Conditional,
    Recurring,
}

impl SmartCommitment {
    pub fn new(
        hash: Vec<u8>,
        commitment_type: CommitmentType,
        parameters: HashMap<String, String>,
        fixed_parameters: HashMap<String, Vec<u8>>,
        variable_parameters: HashSet<String>,
    ) -> Self {
        Self {
            hash,
            commitment_type,
            parameters,
            fixed_parameters,
            variable_parameters,
        }
    }
}

/// Forward-linked commitment for future state guarantee
#[derive(Debug, Clone)]
pub struct ForwardLinkedCommitment {
    /// Hash of the next state this commitment links to
    pub next_state_hash: Vec<u8>,
    /// Counterparty ID this commitment involves
    pub counterparty_id: String,
    /// Fixed parameters for the commitment
    pub fixed_parameters: HashMap<String, Vec<u8>>,
    /// Variable parameters allowed to change
    pub variable_parameters: HashSet<String>,
    /// Entity's signature on this commitment
    pub entity_signature: Vec<u8>,
    /// Counterparty's signature on this commitment
    pub counterparty_signature: Vec<u8>,
    /// Hash of the commitment for verification
    pub commitment_hash: Vec<u8>,
    /// Minimum state number this commitment applies to
    pub min_state_number: u64,
}

impl ForwardLinkedCommitment {
    pub fn new(
        next_state_hash: Vec<u8>,
        counterparty_id: String,
        fixed_parameters: HashMap<String, Vec<u8>>,
        variable_parameters: HashSet<String>,
    ) -> Result<Self, DsmError> {
        // Create a new commitment
        let mut commitment = ForwardLinkedCommitment {
            next_state_hash,
            counterparty_id,
            fixed_parameters,
            variable_parameters,
            entity_signature: Vec::new(),
            counterparty_signature: Vec::new(),
            commitment_hash: Vec::new(), // Will be updated
            min_state_number: 0,
        };

        // Calculate commitment hash
        let mut hasher = dsm_domain_hasher("DSM/commitment");
        hasher.update(&commitment.next_state_hash);
        hasher.update(commitment.counterparty_id.as_bytes());

        // Add fixed parameters in sorted order for determinism
        let mut keys: Vec<&String> = commitment.fixed_parameters.keys().collect();
        keys.sort();
        for key in keys {
            hasher.update(key.as_bytes());
            hasher.update(&commitment.fixed_parameters[key]);
        }

        commitment.commitment_hash = hasher.finalize().as_bytes().to_vec();
        Ok(commitment)
    }

    // verify_operation_adherence deleted: zero callers anywhere. Operation
    // type adherence is now enforced at the SDK call-site by matching
    // Operation variants directly, not via the parameter-bag string compare
    // this method did.
}

/// Embedded commitment used within states
#[derive(Debug, Clone)]
pub struct EmbeddedCommitment {
    /// Counterparty ID this commitment involves
    pub counterparty_id: String,
    /// Fixed parameters that can't change
    pub fixed_parameters: HashMap<String, Vec<u8>>,
    /// Variable parameters that are allowed to change
    pub variable_parameters: Vec<String>,
    /// Entity's signature on this commitment
    pub entity_signature: Vec<u8>,
    /// Counterparty's signature on this commitment
    pub counterparty_signature: Vec<u8>,
    /// Hash of the commitment for verification
    pub commitment_hash: Vec<u8>,
    /// Minimum state number this commitment applies to
    pub min_state_number: u64,
}

/// A pair of states representing the bilateral relationship between two entities
/// This implements the core bilateral state isolation concept from whitepaper Section 3.4
#[derive(Debug, Clone)]
pub struct RelationshipStatePair {
    pub entity_id: [u8; 32],
    pub counterparty_id: [u8; 32],
    pub entity_state: State,
    pub counterparty_state: State,
    pub relationship_hash: Vec<u8>,
    pub active: bool,
    /// Chain tip ID for this bilateral relationship
    pub chain_tip_id: Option<String>,
    /// Last bilateral state hash for quick lookup
    pub last_bilateral_state_hash: Option<Vec<u8>>,
}

impl RelationshipStatePair {
    pub fn new(
        entity_id: [u8; 32],
        counterparty_id: [u8; 32],
        entity_state: State,
        counterparty_state: State,
    ) -> Result<Self, DsmError> {
        let mut pair = Self {
            entity_id,
            counterparty_id,
            entity_state,
            counterparty_state,
            relationship_hash: Vec::new(),
            active: true,
            chain_tip_id: None,
            last_bilateral_state_hash: None,
        };
        // Compute relationship hash
        let mut hasher = dsm_domain_hasher("DSM/relationship");
        hasher.update(&pair.entity_state.hash()?);
        hasher.update(&pair.counterparty_state.hash()?);
        pair.relationship_hash = hasher.finalize().as_bytes().to_vec();

        Ok(pair)
    }

    /// Create a new relationship state pair with chain tip information
    pub fn new_with_chain_tip(
        entity_id: [u8; 32],
        counterparty_id: [u8; 32],
        entity_state: State,
        counterparty_state: State,
        chain_tip_id: String,
    ) -> Result<Self, DsmError> {
        let mut pair = Self::new(entity_id, counterparty_id, entity_state, counterparty_state)?;

        // Generate bilateral state hash for this relationship
        let mut bilateral_hasher = dsm_domain_hasher("DSM/bilateral-state");
        bilateral_hasher.update(&pair.entity_state.hash()?);
        bilateral_hasher.update(&pair.counterparty_state.hash()?);
        bilateral_hasher.update(chain_tip_id.as_bytes());
        let bilateral_state_hash = bilateral_hasher.finalize().as_bytes().to_vec();

        pair.chain_tip_id = Some(chain_tip_id);
        pair.last_bilateral_state_hash = Some(bilateral_state_hash);

        Ok(pair)
    }

    // The following methods all had zero external callers — deleted:
    //   compute_relationship_hash
    //   has_pending_unilateral_transactions
    //   get_last_synced_state, set_last_synced_state
    //   update_entity_state
    //   add_pending_transaction, get_pending_unilateral_transactions,
    //   apply_transaction, clear_pending_transactions
    //   build_verification_metadata, validate_operation, handle_operation
    //
    // The pending-transaction queue and last-synced-state tracking lived
    // entirely in `verification_metadata`, which is no longer queried.
    // Per-relationship state advancement now flows through DeviceState::advance
    // (§2.2, §4.2); the legacy RelationshipStatePair remains for the bilateral
    // session pair shape (`new`, `new_with_chain_tip`, `verify_cross_chain_continuity`,
    // `resume`, `generate_bilateral_chain_id`).

    // resume() deleted: only caller was the now-deleted
    // RelationshipManager::resume_relationship. RelationshipContext
    // resumption now flows through the bilateral session restore path in
    // sdk::storage::client_db (contacts table + bilateral_chain_tip).

    // verify_cross_chain_continuity deleted: zero callers anywhere outside
    // its own self-test (test_relationship_state, also deleted). The §4.2
    // stitched receipt + per-relationship SMT inclusion proofs handle
    // bilateral hash-chain adjacency structurally; this RelationshipStatePair
    // method was an obsolete pre-SMT bilateral-pair walker.

    pub fn validate_against_forward_commitment(
        &self,
        operation: &Operation,
    ) -> Result<bool, DsmError> {
        if let Some(commitment) = &self.entity_state.forward_commitment {
            for (key, value) in &commitment.fixed_parameters {
                if key.as_str() == "operation_type" {
                    let op_type = match operation {
                        Operation::Genesis => b"genesis_",
                        Operation::Generic { .. } => b"generic_",
                        Operation::Transfer { .. } => b"transfer",
                        Operation::Mint { .. } => b"mint____",
                        Operation::Burn { .. } => b"burn____",
                        Operation::Create { .. } => b"create__",
                        Operation::Update { .. } => b"update__",
                        Operation::AddRelationship { .. } => b"add_rel_",
                        Operation::CreateRelationship { .. } => b"crt_rel_",
                        Operation::RemoveRelationship { .. } => b"rem_rel_",
                        Operation::Recovery { .. } => b"recovery",
                        Operation::Delete { .. } => b"delete__",
                        Operation::Link { .. } => b"link____",
                        Operation::Unlink { .. } => b"unlink__",
                        Operation::Invalidate { .. } => b"invalid_",
                        Operation::LockToken { .. } => b"lock____",
                        Operation::UnlockToken { .. } => b"unlock__",
                        Operation::Receive { .. } => b"receive_",
                        Operation::Lock { .. } => b"lock____",
                        Operation::Unlock { .. } => b"unlock__",
                        Operation::CreateToken { .. } => b"crt_tok_",
                        Operation::Noop => b"noop____",
                        Operation::DlvCreate { .. } => b"dlv_crt_",
                        Operation::DlvUnlock { .. } => b"dlv_ulk_",
                        Operation::DlvClaim { .. } => b"dlv_clm_",
                        Operation::DlvInvalidate { .. } => b"dlv_inv_",
                    };

                    if value != op_type {
                        return Ok(false);
                    }
                }
            }
        }
        Ok(true)
    }

    /// Update chain tip information for this relationship
    pub fn update_chain_tip(
        &mut self,
        new_chain_tip_id: String,
        new_state_hash: Vec<u8>,
    ) -> Result<(), DsmError> {
        self.chain_tip_id = Some(new_chain_tip_id.clone());
        self.last_bilateral_state_hash = Some(new_state_hash.clone());

        let mut hasher = dsm_domain_hasher("DSM/bilateral-state");
        hasher.update(&self.entity_state.hash()?);
        hasher.update(&self.counterparty_state.hash()?);
        hasher.update(new_chain_tip_id.as_bytes());
        self.relationship_hash = hasher.finalize().as_bytes().to_vec();

        Ok(())
    }

    /// Get the chain tip ID for this bilateral relationship
    pub fn get_chain_tip_id(&self) -> Option<&String> {
        self.chain_tip_id.as_ref()
    }

    // get_last_bilateral_state_hash + compute_bilateral_hash_with_chain_tip +
    // generate_bilateral_chain_id deleted: zero callers anywhere outside
    // their own self-tests. Bilateral chain identification now flows
    // through the 32-byte rel_key derived in
    // bilateral_transaction_manager::compute_smt_key (§2.2 canonical),
    // and §4.2 stitched receipts handle chain-tip integrity structurally.

    // create_chain_tip_verification_hash + verify_bilateral_chain_continuity_with_tip
    // deleted: zero callers anywhere in dsm, dsm_sdk, dsm_storage_node, or tools.
    // Both were RelationshipStatePair methods that hashed (relationship_hash,
    // operation, chain_tip_id, entity_state.hash, counterparty_state.hash) for
    // an old bilateral verify path. The §4.2 stitched receipt + per-relationship
    // SMT inclusion proofs supersede this — chain-tip integrity is verified
    // structurally via SmtInclusionProof, not via an ad-hoc hash digest of
    // RelationshipStatePair fields.
}

// validate_transition + execute_transition deleted: both took &State and had
// zero callers (validate_transition was #[allow(dead_code)], execute_transition
// was a free function shadowed by BilateralStateManager::execute_transition).
// Per-relationship advance now flows through DeviceState::advance (§2.2, §4.2).

// verify_entropy_evolution removed: only caller was the deleted
// validate_relationship_state_transition. §11 eq. 14 entropy verification
// now lives inline in transition::verify_transition_integrity, which derives
// expected entropy from (prev_entropy, op, prev_hash) using the same domain
// tag and compares constant-time.

// validate_relationship_state_transition + verify_relationship_entropy +
// verify_basic_state_properties + verify_commitment_compliance removed:
// only the deleted state_machine::verify_basic_transition / verify_entropy_evolution
// chain (mod.rs) called these. The §2.1/§11 verification now flows through
// transition::verify_transition_integrity which operates on the canonical
// chain state directly via SMT inclusion proofs (§4.2).

/// Represents a canonical relationship key derivation strategy
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum KeyDerivationStrategy {
    /// Canonical ordering of entity and counterparty IDs
    Canonical,
    /// Entity-centric ordering (entity always first)
    EntityCentric,
    /// Cryptographic hash of entity and counterparty IDs (rendered as decimal groups; no hex)
    Hashed,
}

// RelationshipProof struct deleted: only used by the now-deleted
// RelationshipManager::export_relationship_proof + verify_relationship_proof
// methods. Cryptographic relationship proof is now expressed via the
// stitched-receipt SmtInclusionProof (§4.2) carried in ReceiptCommit, not
// via a per-pair (entity_state_hash, counterparty_state_hash, relationship_hash)
// triple.

/// Custom error for relationship manager operations
#[derive(Debug)]
pub struct LockError;

impl std::fmt::Display for LockError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Failed to acquire lock on relationship store")
    }
}

impl std::error::Error for LockError {}

/// Manager for bilateral relationship state pairs
/// Using Mutex instead of RwLock to avoid Send requirement issues
pub struct RelationshipManager {
    relationship_store: Mutex<HashMap<String, RelationshipStatePair>>,
    key_derivation_strategy: KeyDerivationStrategy,
}

impl Clone for RelationshipManager {
    fn clone(&self) -> Self {
        RelationshipManager {
            relationship_store: Mutex::new(
                self.relationship_store
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .clone(),
            ),
            key_derivation_strategy: self.key_derivation_strategy,
        }
    }
}

impl Default for RelationshipManager {
    fn default() -> Self {
        Self::new(KeyDerivationStrategy::Canonical)
    }
}

impl std::fmt::Debug for RelationshipManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "RelationshipManager {{ key_derivation_strategy: {:?} }}",
            self.key_derivation_strategy
        )
    }
}

impl RelationshipManager {
    /// Create a new relationship manager with the specified key derivation strategy
    pub fn new(strategy: KeyDerivationStrategy) -> Self {
        RelationshipManager {
            relationship_store: Mutex::new(HashMap::new()),
            key_derivation_strategy: strategy,
        }
    }

    /// Derive a canonical relationship key using entity and counterparty IDs.
    /// For `Hashed`, renders as "H:<u128_low>:<u128_high>" (decimal; no hex/base64).
    pub fn get_relationship_key(&self, entity_id: &[u8; 32], counterparty_id: &[u8; 32]) -> String {
        match self.key_derivation_strategy {
            KeyDerivationStrategy::Canonical => {
                let entity_str = base32::encode(base32::Alphabet::Crockford, entity_id);
                let counterparty_str = base32::encode(base32::Alphabet::Crockford, counterparty_id);
                let mut ids = [entity_str, counterparty_str];
                ids.sort();
                format!("{}:{}", ids[0], ids[1])
            }
            KeyDerivationStrategy::EntityCentric => {
                let entity_str = base32::encode(base32::Alphabet::Crockford, entity_id);
                let counterparty_str = base32::encode(base32::Alphabet::Crockford, counterparty_id);
                format!("{entity_str}:{counterparty_str}")
            }
            KeyDerivationStrategy::Hashed => {
                let mut h = dsm_domain_hasher("DSM/RELKEY/v2");
                // order-independent mix (domain tag already applied via dsm_domain_hasher)
                if entity_id <= counterparty_id {
                    h.update(entity_id.as_bytes());
                    h.update(counterparty_id.as_bytes());
                } else {
                    h.update(counterparty_id.as_bytes());
                    h.update(entity_id.as_bytes());
                }
                let d = h.finalize();
                let b = d.as_bytes();
                let (l, r) = b.split_at(16);
                let mut arr_l = [0u8; 16];
                arr_l.copy_from_slice(l);
                let a = u128::from_le_bytes(arr_l);
                let mut arr_r = [0u8; 16];
                arr_r.copy_from_slice(r);
                let c = u128::from_le_bytes(arr_r);
                format!("H:{a}:{c}")
            }
        }
    }

    /// Store a relationship state pair with thread-safe access
    pub fn store_relationship(
        &self,
        entity_id: &[u8; 32],
        counterparty_id: &[u8; 32],
        entity_state: State,
        counterparty_state: State,
    ) -> Result<(), DsmError> {
        let key = self.get_relationship_key(entity_id, counterparty_id);
        let pair = RelationshipStatePair::new(
            *entity_id,
            *counterparty_id,
            entity_state,
            counterparty_state,
        )?;

        let mut store = self.relationship_store.lock().map_err(|_| {
            DsmError::invalid_operation("Failed to acquire lock on relationship store")
        })?;

        store.insert(key, pair);
        Ok(())
    }

    // resume_relationship deleted: zero callers anywhere. RelationshipContext
    // resumption now flows through the bilateral session restore path in
    // sdk::storage::client_db (contacts table + bilateral_chain_tip), not
    // through this in-memory RelationshipManager store.

    // update_relationship deleted: zero callers anywhere. The function
    // recomputed cross-chain continuity via verify_cross_chain_continuity
    // and reinserted a fresh RelationshipStatePair, but bilateral state
    // updates now flow through BilateralStateManager::execute_transition
    // (which maintains the per-relationship chain via SMT) rather than
    // through this RelationshipManager::store/update API.

    // create_relationship_with_chain_tip + update_relationship_chain_tip +
    // get_relationship_chain_tip_id deleted: zero callers anywhere. Chain
    // tip tracking lives on the Per-Device SMT (DeviceState.smt) keyed by
    // 32-byte rel_key per §2.2; the prior `chain_tip_id: String` per-pair
    // mechanism is obsolete.

    /// Execute a state transition within a relationship context
    pub fn execute_relationship_transition(
        &self,
        entity_id: &[u8; 32],
        counterparty_id: &[u8; 32],
        operation: Operation,
        new_entropy: [u8; 32],
    ) -> Result<RelationshipStatePair, DsmError> {
        let key = self.get_relationship_key(entity_id, counterparty_id);
        let mut store = self.relationship_store.lock().map_err(|_| {
            DsmError::invalid_operation("Failed to acquire lock on relationship store")
        })?;

        let relationship = store
            .get(&key)
            .ok_or_else(|| {
                DsmError::not_found(
                    "Relationship",
                    Some(format!(
                        "No relationship found between {} and {}",
                        base32::encode(base32::Alphabet::Crockford, entity_id),
                        base32::encode(base32::Alphabet::Crockford, counterparty_id)
                    )),
                )
            })?
            .clone();

        if !relationship.validate_against_forward_commitment(&operation)? {
            return Err(DsmError::invalid_operation(
                "Operation does not comply with forward commitment",
            ));
        }

        let state_transition = StateTransition::new(
            operation.clone(),
            Some(new_entropy.to_vec()),
            None,
            &relationship.entity_state.device_info.device_id,
        );
        let new_entity_state = apply_transition(&state_transition, &relationship.entity_state)?;

        let new_relationship = RelationshipStatePair::new(
            *entity_id,
            *counterparty_id,
            new_entity_state.clone(),
            relationship.counterparty_state.clone(),
        )?;

        store.insert(key, new_relationship.clone());

        Ok(new_relationship)
    }

    /// Verify relationship existence without resuming
    pub fn verify_relationship_exists(
        &self,
        entity_id: &[u8; 32],
        counterparty_id: &[u8; 32],
    ) -> Result<bool, DsmError> {
        let key = self.get_relationship_key(entity_id, counterparty_id);
        let store = self.relationship_store.lock().map_err(|_| {
            DsmError::invalid_operation("Failed to acquire lock on relationship store")
        })?;
        Ok(store.contains_key(&key))
    }

    // export_relationship_proof + verify_relationship_proof + list_entities +
    // find_counterparties deleted: zero callers anywhere. Proof export now
    // flows through ReceiptCommit (§4.2) with embedded SmtInclusionProof;
    // entity/counterparty enumeration lives on the contacts table in
    // sdk::storage::client_db.

    /// Get the latest state for an entity in a specific relationship
    pub fn get_entity_state(
        &self,
        entity_id: &[u8; 32],
        counterparty_id: &[u8; 32],
    ) -> Result<State, DsmError> {
        let key = self.get_relationship_key(entity_id, counterparty_id);
        let store = self.relationship_store.lock().map_err(|_| {
            DsmError::invalid_operation("Failed to acquire lock on relationship store")
        })?;

        if let Some(pair) = store.get(&key) {
            if pair.entity_id == *entity_id {
                Ok(pair.entity_state.clone())
            } else {
                Ok(pair.counterparty_state.clone())
            }
        } else {
            Err(DsmError::not_found(
                "Relationship",
                Some(format!(
                    "No relationship found between {} and {}",
                    base32::encode(base32::Alphabet::Crockford, entity_id),
                    base32::encode(base32::Alphabet::Crockford, counterparty_id)
                )),
            ))
        }
    }

    /// Alias for get_entity_state to maintain API compatibility
    pub fn get_relationship_state(
        &self,
        entity_id: &str,
        counterparty_id: &str,
    ) -> Result<State, DsmError> {
        self.get_entity_state(
            &crate::crypto::blake3::domain_hash("DSM/entity-id", entity_id.as_bytes()).into(),
            &crate::crypto::blake3::domain_hash("DSM/entity-id", counterparty_id.as_bytes()).into(),
        )
    }
}

fn apply_transition(
    transition: &StateTransition,
    current_state: &State,
) -> Result<State, DsmError> {
    let mut new_state = current_state.clone();

    new_state.operation = transition.operation.clone();
    if let Some(new_entropy) = &transition.new_entropy {
        new_state.entropy = new_entropy.clone();
    }
    new_state.prev_state_hash = current_state.hash()?;
    new_state.hash = new_state.compute_hash()?;

    Ok(new_state)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Domain-separated hash for test entity IDs — tag unambiguously marks these as test
    // fixture identifiers, never confused with production identity hashes.
    fn test_entity_id(label: &[u8]) -> [u8; 32] {
        *crate::crypto::blake3::domain_hash("DSM/test-entity-id", label).as_bytes()
    }

    /// Helper function to create a test state. `seed` is a distinguishing
    /// label only — it plays no role in acceptance predicates.
    fn create_test_state(seed: u64, prev_hash: [u8; 32]) -> State {
        let hash = *crate::crypto::blake3::domain_hash(
            "DSM/test-state-hash",
            format!("test_state_{seed}").as_bytes(),
        )
        .as_bytes();
        // Per §11 eq. 14, production entropy comes from (prev_entropy, op, parent_hash);
        // for the test fixture we synthesize a distinguishable seed.
        let entropy = crate::crypto::blake3::domain_hash(
            "DSM/test-entropy",
            format!("entropy_{seed}").as_bytes(),
        )
        .as_bytes()
        .to_vec();
        State {
            prev_state_hash: prev_hash,
            hash,
            entropy,
            ..State::default()
        }
    }

    #[test]
    fn test_relationship_creation() {
        let entity_state = create_test_state(1, [0; 32]);
        let counterparty_state = create_test_state(1, [0; 32]);

        let result = RelationshipStatePair::new(
            test_entity_id(b"entity1"),
            test_entity_id(b"entity2"),
            entity_state,
            counterparty_state,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_relationship_manager() {
        let manager = RelationshipManager::new(KeyDerivationStrategy::Canonical);

        let entity_state = create_test_state(1, [0; 32]);
        let counterparty_state = create_test_state(1, [0; 32]);

        // Store a relationship
        let entity_id = test_entity_id(b"entity1");
        let counterparty_id = test_entity_id(b"entity2");
        let result = manager.store_relationship(
            &entity_id,
            &counterparty_id,
            entity_state,
            counterparty_state,
        );
        assert!(result.is_ok());

        // Verify relationship exists
        let exists = manager
            .verify_relationship_exists(&entity_id, &counterparty_id)
            .map_err(|_| DsmError::internal(0.to_string(), None::<std::convert::Infallible>))
            .unwrap();
        assert!(exists);

        // Canonical keys are symmetric in order
        let canonical_key = manager.get_relationship_key(&entity_id, &counterparty_id);
        let canonical_key2 = manager.get_relationship_key(&counterparty_id, &entity_id);
        assert_eq!(canonical_key, canonical_key2);

        // Hashed key (no hex) returns a decimal-tagged string, stable and non-empty
        let hashed_manager = RelationshipManager::new(KeyDerivationStrategy::Hashed);
        let hashed_key_a = hashed_manager.get_relationship_key(&entity_id, &counterparty_id);
        let hashed_key_b = hashed_manager.get_relationship_key(&counterparty_id, &entity_id);
        assert!(hashed_key_a.starts_with("H:"));
        assert_eq!(hashed_key_a, hashed_key_b); // order-independent
        assert!(!hashed_key_a.is_empty());
    }

    // test_relationship_state deleted: exercised the now-deleted
    // verify_cross_chain_continuity + generate_bilateral_chain_id +
    // update_relationship surfaces. The only piece worth keeping was the
    // entropy-evolution assertion (§11 eq.14), which is now covered by
    // transition::verify_transition_integrity tests in transition.rs.
}
