// SPDX-License-Identifier: MIT OR Apache-2.0

//! Core state types for the DSM protocol.
//!
//! This module defines [`State`] -- the central data type of the Decentralized State
//! Machine protocol. Every node in a straight hash chain is represented as a `State`,
//! cryptographically binding each state transition to its predecessor via
//! domain-separated BLAKE3 hashing.
//!
//! Also included are supporting types for Merkle proofs ([`MerkleProof`]),
//! device identification ([`DeviceInfo`]), sparse indexing ([`SparseIndex`]), and bilateral relationship tracking
//! ([`RelationshipContext`]).
//!
//! All hashing in this module uses `BLAKE3-256("DSM/<domain>\0" || data)` for
//! domain separation as mandated by the protocol specification.

use crate::common::canonical_encoding::CanonicalEncode;
use crate::common::domain_tags::{TAG_DEVICE_ID, TAG_STATE_HASH};
use crate::crypto::blake3::{domain_hash, dsm_domain_hasher};
use crate::types::error::DsmError;
use crate::types::operations::Operation;
use crate::types::operations::TransactionMode;
use crate::types::token_types::Balance;
use std::collections::{HashMap, HashSet};
use std::convert::TryInto;
use std::hash::{Hash as StdHash, Hasher};

/// Parameters for initializing a [`State`].
///
/// Collects all required and optional inputs for constructing a new state node
/// in the hash chain. Uses the builder-style `with_*` methods for optional fields.
///
/// Per whitepaper §4.3, no counter/height/timestamp participates in acceptance
/// predicates. State identity comes from hash adjacency (`prev_state_hash`) and
/// per-transition entropy (§11 eq. 14), not a monotonic counter.
#[derive(Clone, Debug)]
pub struct StateParams {
    /// Entropy value evolved deterministically across state transitions.
    pub entropy: Vec<u8>,
    /// ML-KEM-768 encapsulated entropy for post-quantum key exchange.
    pub encapsulated_entropy: Option<Vec<u8>>,
    /// BLAKE3 hash of the predecessor state in the chain.
    pub prev_state_hash: [u8; 32],
    /// Sparse index referencing prior states for logarithmic traversal.
    pub sparse_index: SparseIndex,
    /// Operation performed in this state transition.
    pub operation: Operation,
    /// Device identification and public key material.
    pub device_info: DeviceInfo,
}

impl StateParams {
    /// Create a new state parameters object
    pub fn new(entropy: Vec<u8>, operation: Operation, device_info: DeviceInfo) -> Self {
        Self {
            entropy,
            encapsulated_entropy: None,
            prev_state_hash: [0u8; 32],
            sparse_index: SparseIndex::default(),
            operation,
            device_info,
        }
    }

    /// Set encapsulated entropy
    pub fn with_encapsulated_entropy(mut self, encapsulated_entropy: Vec<u8>) -> Self {
        self.encapsulated_entropy = Some(encapsulated_entropy);
        self
    }

    /// Set previous state hash
    pub fn with_prev_state_hash(mut self, prev_state_hash: [u8; 32]) -> Self {
        self.prev_state_hash = prev_state_hash;
        self
    }

    /// Set sparse index
    pub fn with_sparse_index(mut self, sparse_index: SparseIndex) -> Self {
        self.sparse_index = sparse_index;
        self
    }
}

/// Device identification and cryptographic information
#[derive(Clone, Debug, Default)]
pub struct DeviceInfo {
    /// Unique identifier for the device (32 bytes, canonical binary)
    pub device_id: [u8; 32],
    /// Public key associated with the device
    pub public_key: Vec<u8>,
    /// Optional metadata associated with the device
    pub metadata: Vec<u8>,
}

// Default implementation is now derived through #[derive(Default)]

impl DeviceInfo {
    /// Create a new DeviceInfo instance
    ///
    /// # Arguments
    /// * `device_id` - Unique identifier for the device (32 bytes)
    /// * `public_key` - Public key associated with the device
    pub fn new(device_id: [u8; 32], public_key: Vec<u8>) -> Self {
        Self {
            device_id,
            public_key,
            metadata: Vec::new(),
        }
    }

    /// Create a deterministic DeviceInfo from a hashed label.
    /// Hashes the label to get the canonical 32-byte device id.
    ///
    /// # Arguments
    /// * `device_id_str` - String identifier (will be hashed)
    /// * `public_key` - Public key associated with the device
    pub fn from_hashed_label(device_label: &str, public_key: Vec<u8>) -> Self {
        let device_id_bytes = domain_hash(TAG_DEVICE_ID, device_label.as_bytes());
        Self {
            device_id: *device_id_bytes.as_bytes(),
            public_key,
            metadata: Vec::new(),
        }
    }

    /// Canonical, deterministic byte encoding (no Serde/bincode)
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        // device_id as fixed 32 bytes (no length prefix needed)
        out.extend_from_slice(&self.device_id);
        // public_key with u32 LE length prefix
        out.extend_from_slice(&(self.public_key.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.public_key);
        // metadata with u32 LE length prefix
        out.extend_from_slice(&(self.metadata.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.metadata);
        out
    }
}

/// SDK-facing state projection derived from
/// [`DeviceState`](crate::types::device_state::DeviceState).
///
/// Use `DeviceState` for the canonical device head and
/// `RelationshipChainState` for per-chain state.
#[derive(Clone, Debug, Default)]
pub struct State {
    /// Unique identifier for this state (opaque label; not in hash).
    pub id: String,

    /// Current entropy value, evolved deterministically as per whitepaper §11.
    pub entropy: Vec<u8>,

    /// Cryptographic hash of this state
    pub hash: [u8; 32],

    /// Hash of the previous state, creating the cryptographic chain as per Section 3.1
    pub prev_state_hash: [u8; 32],

    /// Sparse index for efficient lookups as per whitepaper Section 3.2
    pub sparse_index: SparseIndex,

    /// Operation performed in this state transition
    pub operation: Operation,

    /// Kyber-encapsulated entropy for quantum resistance as per whitepaper Section 6
    pub encapsulated_entropy: Option<Vec<u8>>,

    /// Device information
    pub device_info: DeviceInfo,

    /// State flags for additional metadata
    pub flags: HashSet<StateFlag>,

    /// Token balances integrated directly in state transition as per whitepaper Section 9
    /// Maps token identifiers to balances, format: "owner_id:token_id" -> Balance
    pub token_balances: HashMap<String, Balance>,

    /// Relationship context for tracking state relationships
    pub relationship_context: Option<RelationshipContext>,
}

impl State {
    fn canonical_hash_bytes(&self) -> [u8; 32] {
        if self.hash != [0u8; 32] {
            return self.hash;
        }
        match self.compute_hash() {
            Ok(h) => h,
            Err(_) => self.hash,
        }
    }
}

impl PartialEq for State {
    fn eq(&self, other: &Self) -> bool {
        self.canonical_hash_bytes() == other.canonical_hash_bytes()
    }
}

impl Eq for State {}

impl StdHash for State {
    fn hash<H: Hasher>(&self, state: &mut H) {
        state.write(&self.canonical_hash_bytes());
    }
}

/// Flags that annotate a [`State`] with lifecycle or status metadata.
#[derive(Debug, Clone, Eq, Hash, PartialEq)]
pub enum StateFlag {
    /// State was recovered through the recovery protocol.
    Recovered,
    /// State has been marked as compromised (e.g., key exposure detected).
    Compromised,
    /// State has been explicitly invalidated and must not be accepted.
    Invalidated,
    /// State has been synchronised with storage nodes.
    Synced,
    /// Application-defined custom flag with a descriptive label.
    Custom(String),
}

impl State {
    /// Create a new state using the parameter object pattern
    ///
    /// # Arguments
    /// * `params` - StateParams containing all necessary components for state initialization
    ///
    /// # Returns
    /// A new State initialized with the provided parameters
    pub fn new(params: StateParams) -> Self {
        Self {
            id: String::new(),
            entropy: params.entropy,
            hash: [0u8; 32], // Will be computed after construction
            prev_state_hash: params.prev_state_hash,
            sparse_index: params.sparse_index,
            operation: params.operation,
            encapsulated_entropy: params.encapsulated_entropy,
            device_info: params.device_info,
            flags: HashSet::new(),
            token_balances: HashMap::new(),
            relationship_context: None,
        }
    }

    /// Create a new genesis state.
    ///
    /// # Arguments
    /// * `initial_entropy` - Initial entropy for the genesis state
    /// * `device_info` - Device information
    pub fn new_genesis(initial_entropy: [u8; 32], device_info: DeviceInfo) -> Self {
        let mut flags = HashSet::new();
        flags.insert(StateFlag::Recovered);

        let operation = Operation::Create {
            message: "Genesis state creation".to_string(),
            identity_data: Vec::new(),
            public_key: device_info.public_key.clone(),
            metadata: Vec::new(),
            commitment: Vec::new(),
            proof: Vec::new(),
            mode: TransactionMode::Bilateral,
        };

        Self {
            id: "genesis".to_string(),
            entropy: initial_entropy.to_vec(),
            hash: [0u8; 32],
            prev_state_hash: [0u8; 32],
            sparse_index: SparseIndex::new(Vec::new()),
            operation,
            encapsulated_entropy: None,
            device_info,
            flags,
            token_balances: HashMap::new(), // Initialize empty token balances
            relationship_context: None,
        }
    }

    /// Attach a bilateral relationship context to this state.
    ///
    /// Binds this state to a counterparty for bilateral state tracking by
    /// recording both parties' identifiers and public keys. Per §4.3, no
    /// counter is involved in bilateral acceptance — ordering comes from
    /// per-relationship chain tip adjacency.
    /// Create state with relationship context and chain tip information
    pub fn with_relationship_context_and_chain_tip(
        mut self,
        counterparty_id: [u8; 32],
        counterparty_public_key: Vec<u8>,
        chain_tip_id: String,
    ) -> Self {
        self.relationship_context = Some(RelationshipContext::new_with_chain_tip(
            self.device_info.device_id,
            counterparty_id,
            counterparty_public_key,
            chain_tip_id,
        ));
        self
    }

    // with_relationship_context, in_relationship_with, is_genesis deleted
    // (zero external callers). Direct field access is the canonical path.

    /// Returns `true` if this state has a pending forward commitment (compromised flag).
    pub fn has_pending_commitment(&self) -> bool {
        self.flags.contains(&StateFlag::Compromised)
    }

    // is_invalidated, is_recovered, is_compromised, add_flag deleted —
    // zero external callers. The `flags` field stays for is_genesis()
    // and the Recovery operation gating in is_operation_allowed().

    // add_metadata deleted: external_data field removed (zero callers).

    /// Calculate the hash of this state, as specified in whitepaper Section 3.1
    ///
    /// # Returns
    /// * `Result<[u8; 32], DsmError>` - The calculated hash or an error
    pub fn hash(&self) -> Result<[u8; 32], DsmError> {
        // If hash is already calculated, return it
        if self.hash != [0u8; 32] {
            return Ok(self.hash);
        }
        self.compute_hash()
    }

    /// Compute the canonical hash of this state per §4.2.1.
    ///
    /// Per §4.3, no counter/height/timestamp is included. Ordering is by hash
    /// adjacency via `prev_state_hash` (§2.1 eq. 1). Per-transition entropy
    /// (§11 eq. 14) makes state identity unique even when field values
    /// round-trip.
    pub fn compute_hash(&self) -> Result<[u8; 32], DsmError> {
        let mut hasher = dsm_domain_hasher(TAG_STATE_HASH);

        // Core state properties in deterministic order. No counter.
        hasher.update(&self.prev_state_hash);
        hasher.update(&self.entropy);

        // Optional fields
        if let Some(enc) = &self.encapsulated_entropy {
            hasher.update(enc);
        }

        // Deterministic serialization of operation (canonical bytes)
        let op_bytes = self.operation.to_bytes();
        hasher.update(&op_bytes);

        // Include device info
        hasher.update(&self.device_info.device_id);
        hasher.update(&self.device_info.public_key);

        // Token balances must be sorted for deterministic ordering
        let mut sorted_balances: Vec<(&String, &Balance)> = self.token_balances.iter().collect();
        sorted_balances.sort_by_key(|(k, _)| *k);
        for (token_id, balance) in sorted_balances {
            hasher.update(token_id.as_bytes());
            let balance_bytes = balance.to_le_bytes();
            hasher.update(&balance_bytes);
        }

        Ok(*hasher.finalize().as_bytes())
    }

    /// Compute the pre-finalization hash that excludes token balances.
    /// Per §4.3, no counter is included.
    pub fn pre_finalization_hash(&self) -> Result<Vec<u8>, DsmError> {
        let mut hasher = dsm_domain_hasher(crate::common::domain_tags::TAG_DSM_PRE_FINALIZATION);
        hasher.update(&self.entropy);
        hasher.update(&self.prev_state_hash);
        hasher.update(&self.operation.to_bytes());

        Ok(hasher.finalize().as_bytes().to_vec())
    }
    /// Compute the verification hash that includes token balances for finalized verification
    /// This implements the atomic state update with token integration as per whitepaper Section 9
    pub fn finalized_verification_hash(&self) -> Result<Vec<u8>, DsmError> {
        // Get the pre-finalization hash first
        let pre_hash = self.pre_finalization_hash()?;

        // Now construct the balance verification layer
        let mut balance_data = Vec::new();

        // Add the pre-finalization hash as base layer
        balance_data.extend_from_slice(&pre_hash);

        // Add a domain separator for token balance layer
        balance_data.extend_from_slice(b"TOKEN_BALANCES");

        // Add token balances in a deterministic, canonicalized order (sorted by key)
        // This ensures balance verification while allowing pre-commitment flexibility
        let mut sorted_balances: Vec<(&String, &Balance)> = self.token_balances.iter().collect();
        sorted_balances.sort_by_key(|(k, _)| *k);

        for (token_id, balance) in sorted_balances {
            balance_data.extend_from_slice(token_id.as_bytes());
            balance_data.extend_from_slice(&balance.to_le_bytes());
        }

        // Calculate final hash including balance data
        Ok(domain_hash(
            crate::common::domain_tags::TAG_DSM_BALANCE_COMMIT,
            &balance_data,
        )
        .as_bytes()
        .to_vec())
    }

    // get_parameter deleted: read from now-deleted external_data field.
    // The single SDK caller (token_sdk locked_balances) always returned
    // None because external_data was never populated outside the deleted
    // add_metadata. The caller handles the None case explicitly.

    /// Get the serialized operation bytes
    pub fn get_operation_bytes(&self) -> Vec<u8> {
        // Canonical operation bytes
        self.operation.to_bytes()
    }

    /// Convert state to bytes for hashing and transmission.
    ///
    /// Per §4.3, no counter participates in canonical encoding. Ordering is
    /// via `prev_state_hash` (§2.1 eq. 1).
    ///
    /// # Returns
    /// * `Result<Vec<u8>, DsmError>` - Serialized state bytes
    pub fn to_bytes(&self) -> Result<Vec<u8>, DsmError> {
        // Canonical deterministic encoding for State (transport-agnostic; not protobuf)
        use crate::types::serialization::{put_bytes, put_str, put_u32, put_u8};

        let mut out = Vec::new();

        // Version tag for future evolution
        put_u8(&mut out, 1);

        // Core fields. No counter.
        put_bytes(&mut out, &self.prev_state_hash);
        put_bytes(&mut out, &self.entropy);

        // Optional encapsulated entropy
        match &self.encapsulated_entropy {
            Some(e) => {
                put_u8(&mut out, 1);
                put_bytes(&mut out, e);
            }
            None => put_u8(&mut out, 0),
        }

        // Operation
        let opb = self.operation.to_bytes();
        put_bytes(&mut out, &opb);

        // Device info
        put_bytes(&mut out, &self.device_info.device_id);
        put_bytes(&mut out, &self.device_info.public_key);
        put_bytes(&mut out, &self.device_info.metadata);

        // Token balances (sorted by key)
        let mut entries: Vec<(&String, &Balance)> = self.token_balances.iter().collect();
        entries.sort_by_key(|(k, _)| *k);
        put_u32(&mut out, entries.len() as u32);
        for (k, v) in entries {
            put_str(&mut out, k);
            let vb = v.to_le_bytes();
            put_bytes(&mut out, &vb);
        }

        // matches_parameters and state_type fields removed — they were
        // advisory-only and never participated in any acceptance predicate.
        // The canonical wire format shrinks by `1 + 4 + state_type.len()` bytes.

        Ok(out)
    }
}

impl CanonicalEncode for State {
    fn to_canonical_bytes(&self) -> Result<Vec<u8>, DsmError> {
        self.compute_hash().map(|h| h.to_vec())
    }

    fn domain_tag(&self) -> &'static str {
        "DSM/state"
    }
}

#[cfg(test)]
mod tests {
    use super::{DeviceInfo, State, StateParams};
    use crate::types::operations::Operation;

    // ── helpers ──────────────────────────────────────────────────────

    fn test_device_info() -> DeviceInfo {
        DeviceInfo::new([0x11; 32], vec![0x22; 64])
    }

    fn test_state(n: u64) -> State {
        // n seeds entropy only — NOT a counter for acceptance (§4.3)
        let mut entropy = vec![0xAA; 16];
        entropy.extend_from_slice(&n.to_le_bytes());
        State::new(StateParams::new(
            entropy,
            Operation::Noop,
            test_device_info(),
        ))
    }

    // ── DeviceInfo ──────────────────────────────────────────────────

    #[test]
    fn device_info_new_sets_fields() {
        let di = DeviceInfo::new([0xFF; 32], vec![1, 2, 3]);
        assert_eq!(di.device_id, [0xFF; 32]);
        assert_eq!(di.public_key, vec![1, 2, 3]);
        assert!(di.metadata.is_empty());
    }

    #[test]
    fn device_info_from_hashed_label_deterministic() {
        let a = DeviceInfo::from_hashed_label("alice", vec![10]);
        let b = DeviceInfo::from_hashed_label("alice", vec![10]);
        assert_eq!(a.device_id, b.device_id);
    }

    #[test]
    fn device_info_from_hashed_label_different_labels_differ() {
        let a = DeviceInfo::from_hashed_label("alice", vec![10]);
        let b = DeviceInfo::from_hashed_label("bob", vec![10]);
        assert_ne!(a.device_id, b.device_id);
    }

    #[test]
    fn device_info_to_bytes_deterministic() {
        let di = DeviceInfo::new([0xAB; 32], vec![1, 2, 3, 4]);
        let b1 = di.to_bytes();
        let b2 = di.to_bytes();
        assert_eq!(b1, b2);
        assert!(!b1.is_empty());
    }

    #[test]
    fn device_info_to_bytes_contains_device_id_prefix() {
        let di = DeviceInfo::new([0xCC; 32], vec![0xDD; 8]);
        let bytes = di.to_bytes();
        assert_eq!(&bytes[..32], &[0xCC; 32]);
    }

    // ── SparseIndex ─────────────────────────────────────────────────

    use super::SparseIndex;

    #[test]
    fn sparse_index_new_stores_indices() {
        let si = SparseIndex::new(vec![0, 3, 7]);
        assert_eq!(si.indices, vec![0, 3, 7]);
    }

    #[test]
    fn sparse_index_default_is_empty() {
        let si = SparseIndex::default();
        assert!(si.indices.is_empty());
    }

    #[test]
    fn sparse_index_with_indices_replaces() {
        let si = SparseIndex::new(vec![1]).with_indices(vec![9, 8, 7]);
        assert_eq!(si.indices, vec![9, 8, 7]);
    }

    // Sparse index calculation tests removed — calculate_sparse_indices and
    // value() depended on state_number which was removed per §4.3.

    // ── State construction & basic properties ───────────────────────

    #[test]
    fn state_new_returns_valid_state() {
        let s = test_state(42);
        assert_ne!(s.compute_hash().expect("hash"), [0u8; 32]);
    }

    #[test]
    fn state_new_genesis_properties() {
        let s = State::new_genesis([0xBB; 32], test_device_info());
        assert_eq!(s.id, "genesis");
        // is_genesis() removed; check the Recovered flag directly.
        assert!(s.flags.contains(&StateFlag::Recovered));
        assert_eq!(s.entropy, vec![0xBB; 32]);
    }

    #[test]
    fn state_compute_hash_nonzero() {
        let s = test_state(1);
        let h = s.compute_hash().unwrap();
        assert_ne!(h, [0u8; 32]);
    }

    #[test]
    fn state_compute_hash_deterministic() {
        let a = test_state(5);
        let b = test_state(5);
        assert_eq!(a.compute_hash().unwrap(), b.compute_hash().unwrap());
    }

    #[test]
    fn state_hash_returns_computed_when_zero() {
        let s = test_state(3);
        assert_eq!(s.hash, [0u8; 32]);
        let h = s.hash().unwrap();
        assert_ne!(h, [0u8; 32]);
    }

    #[test]
    fn state_hash_returns_cached_when_set() {
        let mut s = test_state(3);
        s.hash = [0xDD; 32];
        assert_eq!(s.hash().unwrap(), [0xDD; 32]);
    }

    #[test]
    fn state_to_bytes_deterministic() {
        let s = test_state(7);
        let b1 = s.to_bytes().unwrap();
        let b2 = s.to_bytes().unwrap();
        assert_eq!(b1, b2);
    }

    #[test]
    fn state_to_bytes_nonempty() {
        let s = test_state(0);
        let bytes = s.to_bytes().unwrap();
        assert!(!bytes.is_empty());
    }

    // ── State flags ─────────────────────────────────────────────────

    use super::StateFlag;

    #[test]
    fn state_recovered_flag_false_by_default() {
        let s = test_state(1);
        // is_genesis() removed; non-genesis states do not have the Recovered flag.
        assert!(!s.flags.contains(&StateFlag::Recovered));
    }

    #[test]
    fn state_flag_set_directly() {
        let mut s = test_state(2);
        // flags can be set via direct field access (it's pub).
        s.flags.insert(StateFlag::Invalidated);
        assert!(s.flags.contains(&StateFlag::Invalidated));
    }

    #[test]
    fn state_custom_flag() {
        let mut s = test_state(3);
        s.flags.insert(StateFlag::Custom("test_flag".into()));
        assert!(s.flags.contains(&StateFlag::Custom("test_flag".into())));
    }

    #[test]
    fn state_has_pending_commitment_flag() {
        let mut s = test_state(4);
        assert!(!s.has_pending_commitment());
        s.flags.insert(StateFlag::Compromised);
        assert!(s.has_pending_commitment());
    }

    // ── State hashing variants ──────────────────────────────────────

    #[test]
    fn state_pre_finalization_hash_deterministic() {
        let s = test_state(8);
        let h1 = s.pre_finalization_hash().unwrap();
        let h2 = s.pre_finalization_hash().unwrap();
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 32);
    }

    #[test]
    fn state_finalized_verification_hash_deterministic() {
        let s = test_state(8);
        let h1 = s.finalized_verification_hash().unwrap();
        let h2 = s.finalized_verification_hash().unwrap();
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 32);
    }

    #[test]
    fn state_finalized_hash_changes_with_token_balance() {
        let mut s1 = test_state(9);
        let h_no_tokens = s1.finalized_verification_hash().unwrap();

        s1.token_balances.insert(
            "owner:token".to_string(),
            crate::types::token_types::Balance::zero(),
        );
        let h_with_tokens = s1.finalized_verification_hash().unwrap();

        assert_ne!(h_no_tokens, h_with_tokens);
    }

    // ── State PartialEq (hash-based) ────────────────────────────────

    #[test]
    fn state_partial_eq_same_params() {
        let a = test_state(20);
        let b = test_state(20);
        assert_eq!(a, b);
    }

    #[test]
    fn state_partial_eq_different_entropy() {
        let a = test_state(20);
        let b = test_state(21);
        assert_ne!(a, b);
    }

    // Tests for State::value(), State::calculate_sparse_indices(), and
    // State::transition_count() removed — all depended on state_number
    // which was removed per §4.3.

    // ── StateParams builder methods ─────────────────────────────────

    #[test]
    fn state_params_new_defaults() {
        let sp = StateParams::new(vec![1], Operation::Noop, test_device_info());
        assert_eq!(sp.entropy, vec![1]);
        assert!(sp.encapsulated_entropy.is_none());
        assert_eq!(sp.prev_state_hash, [0u8; 32]);
    }

    #[test]
    fn state_params_with_encapsulated_entropy() {
        let sp = StateParams::new(vec![], Operation::Noop, test_device_info())
            .with_encapsulated_entropy(vec![0xEE; 32]);
        assert_eq!(sp.encapsulated_entropy, Some(vec![0xEE; 32]));
    }

    #[test]
    fn state_params_with_prev_state_hash() {
        let sp = StateParams::new(vec![], Operation::Noop, test_device_info())
            .with_prev_state_hash([0xAA; 32]);
        assert_eq!(sp.prev_state_hash, [0xAA; 32]);
    }

    #[test]
    fn state_params_with_sparse_index() {
        let si = SparseIndex::new(vec![1, 2, 3]);
        let sp =
            StateParams::new(vec![], Operation::Noop, test_device_info()).with_sparse_index(si);
        assert_eq!(sp.sparse_index.indices, vec![1, 2, 3]);
    }

    // ── State hash varies with different inputs ─────────────────────

    #[test]
    fn state_hash_varies_with_entropy() {
        let a = State::new(StateParams::new(
            vec![0x00; 16],
            Operation::Noop,
            test_device_info(),
        ));
        let b = State::new(StateParams::new(
            vec![0xFF; 16],
            Operation::Noop,
            test_device_info(),
        ));
        assert_ne!(a.compute_hash().unwrap(), b.compute_hash().unwrap());
    }

    #[test]
    fn state_hash_varies_with_prev_state_hash() {
        let a = State::new(
            StateParams::new(vec![1], Operation::Noop, test_device_info())
                .with_prev_state_hash([0x00; 32]),
        );
        let b = State::new(
            StateParams::new(vec![1], Operation::Noop, test_device_info())
                .with_prev_state_hash([0xFF; 32]),
        );
        assert_ne!(a.compute_hash().unwrap(), b.compute_hash().unwrap());
    }

    // ── State with_relationship_context_and_chain_tip ───────────────

    #[test]
    fn state_with_relationship_context_and_chain_tip() {
        let s = test_state(15).with_relationship_context_and_chain_tip(
            [0xDD; 32],
            vec![0xEE; 32],
            "chain_tip_99".into(),
        );
        let ctx = s.relationship_context.as_ref().unwrap();
        assert_eq!(ctx.get_chain_tip_id(), Some(&"chain_tip_99".to_string()));
    }
}

/// SparseIndex represents a sparse index for efficient lookups
#[derive(Clone, Debug)]
pub struct SparseIndex {
    /// Indices for efficient lookups
    pub indices: Vec<u64>,
}

impl SparseIndex {
    /// Create a new sparse index with the given indices
    pub fn new(indices: Vec<u64>) -> Self {
        Self { indices }
    }

    /// Calculate a deterministic value from the indices
    pub fn value(&self) -> u64 {
        // Hash all indices together to get a deterministic value
        let mut hasher = dsm_domain_hasher(crate::common::domain_tags::TAG_DSM_SPARSE_IDX);
        let mut sorted_indices = self.indices.clone();
        sorted_indices.sort(); // Sort for deterministic ordering

        for idx in sorted_indices {
            hasher.update(&idx.to_le_bytes());
        }

        // Safe conversion with default-to-0 on error
        hasher.finalize().as_bytes()[0..8]
            .try_into()
            .map(u64::from_le_bytes)
            .unwrap_or(0)
    }

    /// Create a new SparseIndex with the given indices
    pub fn with_indices(mut self, indices: Vec<u64>) -> Self {
        self.indices = indices;
        self
    }

    // calculate_sparse_indices and calculate_basic_sparse_indices deleted
    // per §4.3: state_number-based checkpoint indexing has no role in the
    // counterless model. Per-Device SMT keys are 32-byte relationship keys
    // (k_{A↔B}), not integer counters. SparseIndex remains as an opaque
    // Vec<u64> for stored serialized states only — never used in
    // acceptance predicates.
}

impl Default for SparseIndex {
    fn default() -> Self {
        Self::new(Vec::new())
    }
}

// NOTE: The old u64-indexed SparseMerkleTree struct that was here has been removed.
// The canonical Per-Device SMT implementation is in merkle::sparse_merkle_tree::SparseMerkleTree
// which uses 256-bit keys, ZERO_LEAF = [0u8; 32], and spec-compliant domain separation (§2.2).

// Old SparseMerkleTree impl blocks and NodeId removed — see merkle::sparse_merkle_tree

/// Context for bilateral relationship state tracking.
///
/// Records both parties' identifiers and the current chain tip for a
/// bilateral relationship, enabling cryptographic verification of
/// relationship continuity across state transitions. Per §4.3, no state
/// counters are tracked — ordering is by chain-tip hash adjacency.
#[derive(Clone, Debug)]
pub struct RelationshipContext {
    /// Device identifier of the local entity (32 bytes).
    pub entity_id: [u8; 32],
    /// Device identifier of the counterparty (32 bytes).
    pub counterparty_id: [u8; 32],
    /// SPHINCS+ public key of the counterparty.
    pub counterparty_public_key: Vec<u8>,
    /// BLAKE3 hash binding the relationship.
    pub relationship_hash: Vec<u8>,
    /// Whether this bilateral relationship is currently active.
    pub active: bool,
    /// Chain tip ID for this bilateral relationship
    pub chain_tip_id: Option<String>,
    /// Last state hash in the bilateral chain
    pub last_bilateral_state_hash: Option<Vec<u8>>,
}

impl RelationshipContext {
    /// Create a new relationship context
    pub fn new(
        entity_id: [u8; 32],
        counterparty_id: [u8; 32],
        counterparty_public_key: Vec<u8>,
    ) -> Self {
        Self {
            entity_id,
            counterparty_id,
            counterparty_public_key,
            relationship_hash: Vec::new(),
            active: true,
            chain_tip_id: None,
            last_bilateral_state_hash: None,
        }
    }

    /// Create a new relationship context with chain tip information
    pub fn new_with_chain_tip(
        entity_id: [u8; 32],
        counterparty_id: [u8; 32],
        counterparty_public_key: Vec<u8>,
        chain_tip_id: String,
    ) -> Self {
        Self {
            entity_id,
            counterparty_id,
            counterparty_public_key,
            relationship_hash: Vec::new(),
            active: true,
            chain_tip_id: Some(chain_tip_id),
            last_bilateral_state_hash: None,
        }
    }

    /// Update chain tip information
    pub fn update_chain_tip(&mut self, chain_tip_id: String, state_hash: Vec<u8>) {
        self.chain_tip_id = Some(chain_tip_id);
        self.last_bilateral_state_hash = Some(state_hash);
    }

    /// Get the chain tip ID for this relationship
    pub fn get_chain_tip_id(&self) -> Option<&String> {
        self.chain_tip_id.as_ref()
    }
}
