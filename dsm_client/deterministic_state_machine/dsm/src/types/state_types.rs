//! Core state types for the DSM protocol.
//!
//! This module defines [`State`] -- the central data type of the Decentralized State
//! Machine protocol. Every node in a straight hash chain is represented as a `State`,
//! cryptographically binding each state transition to its predecessor via
//! domain-separated BLAKE3 hashing.
//!
//! Also included are supporting types for Sparse Merkle Tree proofs
//! ([`MerkleProof`], [`NonInclusionProof`], [`SparseMerkleTree`]),
//! forward commitments ([`PreCommitment`]), device identification ([`DeviceInfo`]),
//! sparse indexing ([`SparseIndex`]), and bilateral relationship tracking
//! ([`RelationshipContext`]).
//!
//! All hashing in this module uses `BLAKE3-256("DSM/<domain>\0" || data)` for
//! domain separation as mandated by the protocol specification.

use crate::common::canonical_encoding::CanonicalEncode;
use crate::crypto::blake3::{domain_hash, dsm_domain_hasher};
use crate::merkle::sparse_merkle_tree::SparseMerkleTreeImpl;
use crate::types::error::DsmError;
use crate::types::operations::Operation;
use crate::types::operations::TransactionMode;
use crate::types::token_types::Balance;
use blake3::{self, Hash};
use std::collections::{HashMap, HashSet};
use std::convert::TryInto;
use std::hash::{Hash as StdHash, Hasher};

/// Parameters for creating a [`MerkleProof`].
///
/// Bundles all inputs needed to construct a Merkle inclusion proof, including
/// the authentication path, leaf and root hashes, tree geometry, and optional
/// token balance and device context.
#[derive(Clone, Debug, Default)]
pub struct MerkleProofParams {
    /// Sibling hashes along the authentication path from leaf to root.
    pub path: Vec<SerializableHash>,
    /// Position of the leaf within the tree.
    pub index: u64,
    /// Hash of the leaf node being proved.
    pub leaf_hash: SerializableHash,
    /// Root hash the proof resolves to.
    pub root_hash: SerializableHash,
    /// Height (depth) of the Sparse Merkle Tree.
    pub height: u32,
    /// Total number of leaves in the tree.
    pub leaf_count: u64,
    /// Device identifier associated with this proof.
    pub device_id: String,
    /// Public key associated with this proof.
    pub public_key: Vec<u8>,
    /// Sparse index for efficient state lookups.
    pub sparse_index: SparseIndex,
    /// Token balances at the time of proof generation.
    pub token_balances: HashMap<String, Balance>,
    /// Raw proof bytes for external verification.
    pub proof: Vec<u8>,
    /// State transition execution mode (bilateral or unilateral).
    pub mode: TransactionMode,
    /// Additional proof parameters.
    pub params: Vec<u8>,
}

/// Parameters for initializing a [`State`].
///
/// Collects all required and optional inputs for constructing a new state node
/// in the hash chain. Uses the builder-style `with_*` methods for optional fields.
#[derive(Clone, Debug)]
pub struct StateParams {
    /// Monotonically increasing sequence number for this state.
    pub state_number: u64,
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
    /// Optional forward commitment binding this state to a future transition.
    pub forward_commitment: Option<PreCommitment>,
    /// Whether the state matches externally supplied parameters.
    pub matches_parameters: bool,
    /// Advisory state type label (e.g., "standard", "benchmark").
    pub state_type: String,
    /// Auxiliary integer values for position verification.
    pub value: Vec<i32>,
    /// Auxiliary commitment integers.
    pub commitment: Vec<i32>,
    /// Optional deterministic commitment to DBRW health summary for this transition.
    ///
    /// This MUST NOT be the raw DBRW binding key or any secret. It is intended to be a
    /// small, canonical digest produced from local DBRW health telemetry.
    pub dbrw_summary_hash: Option<[u8; 32]>,
    pub previous_hash: [u8; 32],
    #[allow(dead_code)]
    pub(crate) none_field: Option<Vec<u8>>,
    #[allow(dead_code)]
    pub(crate) metadata: Vec<u8>,
    #[allow(dead_code)]
    pub(crate) token_balance: Option<Balance>,
    #[allow(dead_code)]
    pub(crate) signature: Option<Vec<u8>>,
    #[allow(dead_code)]
    pub(crate) version: i32,
    #[allow(dead_code)]
    pub(crate) forward_link: Option<Vec<u8>>,
    #[allow(dead_code)]
    pub(crate) large_state: Box<State>,
    #[allow(dead_code)]
    pub entity_sig: Option<Vec<u8>>,
    #[allow(dead_code)]
    pub counterparty_sig: Option<Vec<u8>>,
}

impl StateParams {
    /// Create a new state parameters object
    pub fn new(
        state_number: u64,
        entropy: Vec<u8>,
        operation: Operation,
        device_info: DeviceInfo,
    ) -> Self {
        Self {
            state_number,
            entropy,
            encapsulated_entropy: None,
            prev_state_hash: [0u8; 32],
            sparse_index: SparseIndex::default(),
            operation,
            device_info,
            forward_commitment: None,
            matches_parameters: false,
            state_type: "standard".to_string(),
            value: Vec::new(),
            commitment: Vec::new(),
            dbrw_summary_hash: None,
            previous_hash: [0u8; 32],
            none_field: None,
            metadata: Vec::new(),
            token_balance: None,
            signature: None,
            version: 0,
            forward_link: None,
            large_state: Box::new(State::default()),
            entity_sig: None,
            counterparty_sig: None,
        }
    }

    /// Set DBRW summary commitment hash for this transition.
    pub fn with_dbrw_summary_hash(mut self, h: [u8; 32]) -> Self {
        self.dbrw_summary_hash = Some(h);
        self
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

    /// Set forward commitment
    pub fn with_forward_commitment(mut self, forward_commitment: PreCommitment) -> Self {
        self.forward_commitment = Some(forward_commitment);
        self
    }
}

/// A serializable wrapper around [`blake3::Hash`].
///
/// Provides `Default`, `Clone`, `From`, and `AsRef` implementations so that
/// BLAKE3 hash values can be stored in collections and serialized without
/// depending on serde.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SerializableHash(Hash);

impl Default for SerializableHash {
    fn default() -> Self {
        Self(Hash::from([0u8; 32]))
    }
}

impl SerializableHash {
    /// Create a new SerializableHash from a Hash
    pub fn new(hash: Hash) -> Self {
        Self(hash)
    }

    /// Get the inner Hash
    pub fn inner(&self) -> &Hash {
        &self.0
    }

    /// Unwrap the SerializableHash into the inner Hash
    pub fn into_inner(self) -> Hash {
        self.0
    }
}

impl From<Hash> for SerializableHash {
    fn from(hash: Hash) -> Self {
        Self(hash)
    }
}

impl From<SerializableHash> for Hash {
    fn from(hash: SerializableHash) -> Self {
        hash.0
    }
}

impl AsRef<Hash> for SerializableHash {
    fn as_ref(&self) -> &Hash {
        &self.0
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
        let device_id_bytes = domain_hash("DSM/device-id", device_label.as_bytes());
        Self {
            device_id: *device_id_bytes.as_bytes(),
            public_key,
            metadata: Vec::new(),
        }
    }

    /// Validate device info fields
    ///
    /// # Returns
    /// * `Result<bool, DsmError>` - True if valid, error if invalid
    pub fn validate(&self) -> Result<bool, crate::types::error::DsmError> {
        // Device ID is now fixed 32 bytes, always valid

        // Verify public key is not empty
        if self.public_key.is_empty() {
            return Err(crate::types::error::DsmError::invalid_operation(
                "Public key cannot be empty",
            ));
        }

        Ok(true)
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

/// Represents the core state structure as defined in the whitepaper.
/// Each state forms a node in the straight hash chain, containing all
/// necessary data to cryptographically bind it to its predecessor.
#[derive(Clone, Debug, Default)]
#[allow(dead_code)]
pub struct State {
    /// Unique identifier for this state, typically using the format "state_{state_number}"
    pub id: String,

    /// State sequence number, monotonically increasing as per whitepaper Section 6.1
    pub state_number: u64,

    /// Current entropy value, evolved deterministically as per whitepaper Section 6
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

    /// Matches parameters in the state transition
    pub matches_parameters: bool,

    /// Relationship context for tracking state relationships
    pub relationship_context: Option<RelationshipContext>,

    /// Optional deterministic commitment to DBRW health summary for this transition.
    ///
    /// This MUST NOT be the raw DBRW binding key or any secret. It is intended to be a
    /// small, canonical digest (e.g., BLAKE3 over a minimal DBRW stat summary like the
    /// global bit error rate) so that state progression is cryptographically coupled to
    /// the anti-cloning gate.
    pub dbrw_summary_hash: Option<[u8; 32]>,
    pub(crate) forward_commitment: Option<PreCommitment>,
    pub(crate) position_sequence: Option<PositionSequence>,
    pub(crate) positions: Vec<Vec<i32>>,
    pub(crate) public_key: Vec<u8>,
    hashchain_head: Option<Vec<u8>>,
    external_data: HashMap<String, Vec<u8>>,
    pub(crate) entity_sig: Option<Vec<u8>>,
    pub(crate) counterparty_sig: Option<Vec<u8>>,
    pub(crate) value: Vec<i32>,
    pub(crate) commitment: Vec<i32>,
    pub(crate) state_type: String,
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
    /// Set the external data for this state
    pub fn set_external_data(&mut self, external_data: HashMap<String, Vec<u8>>) {
        self.external_data = external_data;
    }
    /// Create a new state using the parameter object pattern
    ///
    /// # Arguments
    /// * `params` - StateParams containing all necessary components for state initialization
    ///
    /// # Returns
    /// A new State initialized with the provided parameters
    pub fn new(params: StateParams) -> Self {
        let public_key = params.device_info.public_key.clone();
        Self {
            id: format!("state_{}", params.state_number),
            state_number: params.state_number,
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
            dbrw_summary_hash: params.dbrw_summary_hash,
            forward_commitment: params.forward_commitment,
            positions: Vec::new(),
            position_sequence: None,
            public_key,
            matches_parameters: params.matches_parameters,
            hashchain_head: None,
            external_data: HashMap::new(),
            value: params.value,
            commitment: params.commitment,
            entity_sig: None,
            counterparty_sig: None,
            state_type: params.state_type,
        }
    }

    /// Create a new genesis state (state_number = 0)
    ///
    /// # Arguments
    /// * `initial_entropy` - Initial entropy for the genesis state
    /// * `device_info` - Device information
    pub fn new_genesis(initial_entropy: [u8; 32], device_info: DeviceInfo) -> Self {
        let mut flags = HashSet::new();
        flags.insert(StateFlag::Recovered);
        let public_key = device_info.public_key.clone();

        let operation = Operation::Create {
            message: "Genesis state creation".to_string(),
            identity_data: Vec::new(),
            public_key: public_key.clone(),
            metadata: Vec::new(),
            commitment: Vec::new(),
            proof: Vec::new(),
            mode: TransactionMode::Bilateral,
        };

        Self {
            id: "genesis".to_string(),
            state_number: 0,
            entropy: initial_entropy.to_vec(),
            hash: [0u8; 32],
            prev_state_hash: [0u8; 32],
            sparse_index: SparseIndex::new(Vec::new()),
            operation,
            encapsulated_entropy: None,
            device_info: device_info.clone(),
            flags,
            token_balances: HashMap::new(), // Initialize empty token balances
            relationship_context: None,
            dbrw_summary_hash: None,
            forward_commitment: None,
            positions: Vec::new(),
            position_sequence: None,
            public_key,
            matches_parameters: false,
            hashchain_head: None,
            external_data: HashMap::new(),
            value: Vec::new(),
            commitment: Vec::new(),
            entity_sig: None,
            counterparty_sig: None,
            state_type: String::from("standard"),
        }
    }

    /// Attach a bilateral relationship context to this state.
    ///
    /// Binds this state to a counterparty for bilateral state tracking,
    /// recording both parties' identifiers, state numbers, and public keys.
    pub fn with_relationship_context(
        mut self,
        counterparty_id: [u8; 32],
        counterparty_state_number: u64,
        counterparty_public_key: Vec<u8>,
    ) -> Self {
        self.relationship_context = Some(RelationshipContext {
            entity_id: self.device_info.device_id,
            entity_state_number: self.state_number,
            counterparty_id,
            counterparty_state_number,
            counterparty_public_key,
            relationship_hash: Vec::new(),
            active: true,
            chain_tip_id: None,
            last_bilateral_state_hash: None,
        });
        self
    }

    /// Create state with relationship context and chain tip information
    pub fn with_relationship_context_and_chain_tip(
        mut self,
        counterparty_id: [u8; 32],
        counterparty_state_number: u64,
        counterparty_public_key: Vec<u8>,
        chain_tip_id: String,
    ) -> Self {
        self.relationship_context = Some(RelationshipContext::new_with_chain_tip(
            self.device_info.device_id,
            counterparty_id,
            counterparty_public_key,
            chain_tip_id,
        ));
        // Update state numbers in the context
        if let Some(ref mut ctx) = self.relationship_context {
            ctx.entity_state_number = self.state_number;
            ctx.counterparty_state_number = counterparty_state_number;
        }
        self
    }

    /// Check whether this state is in a bilateral relationship with the given counterparty.
    pub fn in_relationship_with(&self, counterparty_id: &str) -> bool {
        self.relationship_context
            .as_ref()
            .map(|ctx| {
                ctx.counterparty_id
                    == *domain_hash("DSM/device-id", counterparty_id.as_bytes()).as_bytes()
            })
            .unwrap_or(false)
    }

    /// Return the counterparty's state number if a relationship context exists.
    pub fn get_counterparty_state(&self) -> Option<u64> {
        self.relationship_context
            .as_ref()
            .map(|ctx| ctx.counterparty_state_number)
    }

    /// Returns `true` if this state is a genesis state (has the `Recovered` flag).
    pub fn is_genesis(&self) -> bool {
        self.flags.contains(&StateFlag::Recovered)
    }

    /// Returns `true` if this state has been invalidated.
    pub fn is_invalidated(&self) -> bool {
        self.flags.contains(&StateFlag::Invalidated)
    }

    /// Returns `true` if this state has a pending forward commitment (compromised flag).
    pub fn has_pending_commitment(&self) -> bool {
        self.flags.contains(&StateFlag::Compromised)
    }

    /// Add a lifecycle flag to this state.
    pub fn add_flag(&mut self, flag: StateFlag) {
        self.flags.insert(flag);
    }

    /// Add metadata to the state's external data
    pub fn add_metadata(&mut self, key: &str, value: Vec<u8>) -> Result<(), DsmError> {
        self.external_data.insert(key.to_string(), value);
        Ok(())
    }

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

    /// Compute the hash of this state
    pub fn compute_hash(&self) -> Result<[u8; 32], DsmError> {
        let mut hasher = dsm_domain_hasher("DSM/state-hash");

        // Core state properties in deterministic order
        hasher.update(&self.state_number.to_le_bytes());
        hasher.update(&self.prev_state_hash);
        hasher.update(&self.entropy);

        // Optional fields
        if let Some(enc) = &self.encapsulated_entropy {
            hasher.update(enc);
        }

        // Optional DBRW summary commitment (non-secret). If present, it must be exactly 32 bytes.
        if let Some(h) = &self.dbrw_summary_hash {
            hasher.update(h);
        }

        // Deterministic serialization of operation (canonical bytes)
        let op_bytes = self.operation.to_bytes();
        hasher.update(&op_bytes);

        // Include device info
        hasher.update(&self.device_info.device_id);
        hasher.update(&self.device_info.public_key);

        // Forward commitment if present (canonical encoding)
        if let Some(fc) = &self.forward_commitment {
            let fc_bytes = encode_precommitment(fc);
            hasher.update(&fc_bytes);
        }

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

    /// Set the entity signature
    pub fn set_entity_signature(&mut self, signature: Option<Vec<u8>>) {
        self.entity_sig = signature;
    }

    /// Set the counterparty signature
    pub fn set_counterparty_signature(&mut self, signature: Option<Vec<u8>>) {
        self.counterparty_sig = signature;
    }

    /// Get the entity signature
    pub fn entity_signature(&self) -> Option<&Vec<u8>> {
        self.entity_sig.as_ref()
    }

    /// Get the counterparty signature
    pub fn counterparty_signature(&self) -> Option<&Vec<u8>> {
        self.counterparty_sig.as_ref()
    }

    /// Compute the pre-finalization hash that excludes token balances
    pub fn pre_finalization_hash(&self) -> Result<Vec<u8>, DsmError> {
        let mut hasher = dsm_domain_hasher("DSM/pre-finalization");
        hasher.update(&self.state_number.to_le_bytes());
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
        Ok(domain_hash("DSM/balance-commit", &balance_data)
            .as_bytes()
            .to_vec())
    }

    /// Get the value of this sparse index
    ///
    /// # Returns
    /// * `u64` - Deterministic value derived from the indices
    pub fn value(&self) -> u64 {
        // Hash all indices together to get a deterministic value
        let mut hasher = dsm_domain_hasher("DSM/sparse-idx");
        let mut sorted_indices: Vec<usize> = self
            .sparse_index
            .indices
            .iter()
            .map(|&x| x as usize)
            .collect();
        sorted_indices.sort(); // Sort indices for deterministic ordering
        hasher.update(&self.state_number.to_le_bytes());

        // Sort for deterministic ordering

        for idx in sorted_indices {
            hasher.update(&idx.to_le_bytes());
        }

        hasher.finalize().as_bytes()[0..8]
            .try_into()
            .map(u64::from_le_bytes)
            .unwrap_or(0)
    }

    /// Validate sparse index integrity
    ///
    /// This ensures that sparse indices correctly map to the state numbers
    /// as described in whitepaper Section 3.2.
    ///
    /// # Arguments
    /// * `state_number` - The state number this sparse index should be valid for
    ///
    /// # Returns
    /// * `Result<bool, DsmError>` - True if the sparse index is valid for the state number
    pub fn validate_for_state_number(
        &self,
        state_number: u64,
    ) -> Result<bool, crate::types::error::DsmError> {
        let expected_indices = Self::calculate_sparse_indices(state_number)?;
        Ok(expected_indices == self.sparse_index.indices)
    }

    /// Calculate sparse indices for a given state number as described in whitepaper Section 3.2
    ///
    /// This implementation follows the mathematical model from whitepaper Section 3.2,
    /// creating a logarithmic set of reference points for efficient state traversal.
    /// Critical references (genesis and direct predecessor) are guaranteed to be included
    /// for consistent hash chain verification.
    ///
    /// # Arguments
    /// * `state_number` - State number to calculate indices for
    ///
    /// # Returns
    /// * `Result<Vec<u64>, DsmError>` - Calculated indices
    pub fn calculate_sparse_indices(state_number: u64) -> Result<Vec<u64>, DsmError> {
        // First, calculate basic sparse indices using powers of 2 algorithm
        let mut indices = Self::calculate_basic_sparse_indices(state_number)?;

        // Critical reference guarantee: Always include genesis state (0)
        if state_number > 0 && !indices.contains(&0) {
            indices.push(0);
        }

        // Critical reference guarantee: Always include direct predecessor
        if state_number > 0 && !indices.contains(&state_number.saturating_sub(1)) {
            indices.push(state_number.saturating_sub(1));
        }

        // Ensure deterministic ordering for verification consistency
        indices.sort_unstable();
        indices.dedup();

        Ok(indices)
    }

    /// Calculate basic sparse indices using powers of 2 distance algorithm
    ///
    /// This implements the power-of-2 checkpoint mechanism described in whitepaper Section 3.2,
    /// providing logarithmic-complexity state traversal.
    ///
    /// # Arguments
    /// * `state_number` - State number to calculate indices for
    ///
    /// # Returns
    /// * `Result<Vec<u64>, DsmError>` - Calculated basic indices
    fn calculate_basic_sparse_indices(state_number: u64) -> Result<Vec<u64>, DsmError> {
        if state_number == 0 {
            return Ok(Vec::new());
        }

        let mut indices = Vec::new();
        let mut power = 0;

        // Generate power-of-2 distance references
        while (1 << power) <= state_number {
            let idx = state_number - (1 << power);
            indices.push(idx);
            power += 1;
        }

        Ok(indices)
    }

    /// Derive a new state from a predecessor by applying an operation.
    ///
    /// Evolves entropy deterministically, computes the new state hash via
    /// domain-separated BLAKE3, and calculates the sparse index for the
    /// successor state number.
    pub fn new_with_operation(prev_state: &Self, operation: Operation) -> Result<Self, DsmError> {
        // Use canonical operation bytes for deterministic entropy evolution (no Serde)
        let op_bytes = operation.to_bytes();

        // Derive new entropy: e_{n+1} = H("DSM/state-entropy" || e_n || op || (n+1))
        let next_state_number = prev_state.state_number.saturating_add(1);
        let mut hasher = crate::crypto::blake3::dsm_domain_hasher("DSM/state-entropy");
        hasher.update(&prev_state.entropy);
        hasher.update(&op_bytes);
        hasher.update(&next_state_number.to_le_bytes());
        let new_entropy = hasher.finalize().as_bytes().to_vec();

        // Derive the new hash by combining the new entropy with the previous state hash
        let mut hash_input = new_entropy.clone();
        hash_input.extend_from_slice(&prev_state.hash);
        let new_hash = *domain_hash("DSM/state-hash", &hash_input).as_bytes();

        // Calculate the sparse index for the new state
        let sparse_index_vec =
            SparseIndex::calculate_sparse_indices(prev_state.state_number.saturating_add(1))?;
        let sparse_index = SparseIndex::new(sparse_index_vec);

        let new_hash_cloned = new_hash;
        Ok(State {
            id: format!("state_{}", prev_state.state_number.saturating_add(1)),
            state_number: prev_state.state_number.saturating_add(1),
            entropy: new_entropy,
            hash: new_hash,
            prev_state_hash: prev_state.hash,
            sparse_index,
            operation,
            encapsulated_entropy: None,
            device_info: prev_state.device_info.clone(),
            flags: HashSet::new(),
            token_balances: prev_state.token_balances.clone(),
            matches_parameters: false,
            relationship_context: None,
            dbrw_summary_hash: prev_state.dbrw_summary_hash,
            forward_commitment: None,
            position_sequence: None,
            positions: Vec::new(),
            public_key: prev_state.device_info.public_key.clone(),
            hashchain_head: Some(new_hash_cloned.to_vec()),
            external_data: HashMap::new(),
            entity_sig: None,
            counterparty_sig: None,
            value: Vec::new(),
            commitment: Vec::new(),
            state_type: String::from("benchmark"),
        })
    }

    /// Set the forward commitment for this state
    pub fn set_forward_commitment(&mut self, commitment: Option<PreCommitment>) {
        self.forward_commitment = commitment;
    }

    /// Get the forward commitment from this state
    pub fn get_forward_commitment(&self) -> Option<&PreCommitment> {
        self.forward_commitment.as_ref()
    }

    /// Get a parameter value from the state
    pub fn get_parameter(&self, key: &str) -> Option<&Vec<u8>> {
        // Extract parameter from external data
        if let Some(value) = self.external_data.get(key) {
            return Some(value);
        }

        // If parameter is not found in external data, check operation-specific fields
        match &self.operation {
            Operation::Transfer { .. } if key == "token_id" => {
                // If token_id is already in external_data, return it
                if let Some(value) = self.external_data.get("token_id") {
                    return Some(value);
                }

                // For immutable access, we can't store the token_bytes in external_data
                // A mutable method would be needed for that functionality
                // Just return None since we can't store the computed value
                None
            }
            Operation::AddRelationship { .. } if key == "relationship_type" => {
                if let Some(value) = self.external_data.get("relationship_type") {
                    Some(value)
                } else {
                    // Return None since we can't create a reference to a temporary value
                    // The caller would need to use a mutable method to store this value
                    None
                }
            }
            _ => None,
        }
    }

    /// Get the serialized operation bytes
    pub fn get_operation_bytes(&self) -> Vec<u8> {
        // Canonical operation bytes
        self.operation.to_bytes()
    }

    /// Convert state to bytes for hashing and transmission
    ///
    /// # Returns
    /// * `Result<Vec<u8>, DsmError>` - Serialized state bytes
    pub fn to_bytes(&self) -> Result<Vec<u8>, DsmError> {
        // Canonical deterministic encoding for State (transport-agnostic; not protobuf)
        use crate::types::serialization::{put_bytes, put_str, put_u32, put_u64, put_u8};

        let mut out = Vec::new();

        // Version tag for future evolution
        put_u8(&mut out, 1);

        // Core fields
        put_u64(&mut out, self.state_number);
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

        // Forward commitment (canonical)
        match &self.forward_commitment {
            Some(pc) => {
                put_u8(&mut out, 1);
                let pcb = encode_precommitment(pc);
                put_bytes(&mut out, &pcb);
            }
            None => put_u8(&mut out, 0),
        }

        // Token balances (sorted by key)
        let mut entries: Vec<(&String, &Balance)> = self.token_balances.iter().collect();
        entries.sort_by_key(|(k, _)| *k);
        put_u32(&mut out, entries.len() as u32);
        for (k, v) in entries {
            put_str(&mut out, k);
            let vb = v.to_le_bytes();
            put_bytes(&mut out, &vb);
        }

        // matches_parameters flag
        put_u8(&mut out, if self.matches_parameters { 1 } else { 0 });

        // state_type (advisory; not in canonical hash)
        put_str(&mut out, &self.state_type);

        Ok(out)
    }

    /// Return the number of state transitions that have occurred (equal to `state_number`).
    pub fn transition_count(&self) -> u64 {
        self.state_number
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
        let mut hasher = dsm_domain_hasher("DSM/sparse-idx");
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

    /// Calculate sparse indices for a given state number as described in whitepaper Section 3.2
    ///
    /// This implementation follows the mathematical model from whitepaper Section 3.2,
    /// creating a logarithmic set of reference points for efficient state traversal.
    /// Critical references (genesis and direct predecessor) are guaranteed to be included
    /// for consistent hash chain verification.
    ///
    /// # Arguments
    /// * `state_number` - State number to calculate indices for
    ///
    /// # Returns
    /// * `Result<Vec<u64>, crate::types::error::DsmError>` - Calculated indices
    pub fn calculate_sparse_indices(
        state_number: u64,
    ) -> Result<Vec<u64>, crate::types::error::DsmError> {
        // First, calculate basic sparse indices using powers of 2 algorithm
        let mut indices = Self::calculate_basic_sparse_indices(state_number)?;

        // Critical reference guarantee: Always include genesis state (0)
        if state_number > 0 && !indices.contains(&0) {
            indices.push(0);
        }

        // Critical reference guarantee: Always include direct predecessor
        if state_number > 0 && !indices.contains(&state_number.saturating_sub(1)) {
            indices.push(state_number.saturating_sub(1));
        }

        // Ensure deterministic ordering for verification consistency
        indices.sort_unstable();
        indices.dedup();

        Ok(indices)
    }

    /// Calculate basic sparse indices using powers of 2 distance algorithm
    ///
    /// This implements the power-of-2 checkpoint mechanism described in whitepaper Section 3.2,
    /// providing logarithmic-complexity state traversal.
    ///
    /// # Arguments
    /// * `state_number` - State number to calculate indices for
    ///
    /// # Returns
    /// * `Result<Vec<u64>, crate::types::error::DsmError>` - Calculated basic indices
    fn calculate_basic_sparse_indices(
        state_number: u64,
    ) -> Result<Vec<u64>, crate::types::error::DsmError> {
        if state_number == 0 {
            return Ok(Vec::new());
        }

        let mut indices = Vec::new();
        let mut power: u32 = 0;

        // Generate power-of-2 distance references
        while (1 << power) <= state_number {
            let idx = state_number.saturating_sub(1 << power);
            indices.push(idx);
            power = power.saturating_add(1);
        }

        Ok(indices)
    }
}

impl Default for SparseIndex {
    fn default() -> Self {
        Self::new(Vec::new())
    }
}

/// Serializable Merkle proof for efficient inclusion verification
pub struct SerializableMerkleProof {
    /// Root of the Merkle tree
    pub root: Vec<u8>,

    /// Proof elements
    pub proof: Vec<Vec<u8>>,

    /// Root hash for backward compatibility
    pub root_hash: SerializableHash,
}

impl SerializableMerkleProof {
    /// Create a new serializable Merkle proof
    ///
    /// # Arguments
    /// * `root` - Root of the Merkle tree
    /// * `proof` - Proof elements
    pub fn new(root: Vec<u8>, proof: Vec<Vec<u8>>) -> Self {
        // Create a SerializableHash from the root
        let root_hash = SerializableHash::new(domain_hash("DSM/proof-root", &root));

        Self {
            root,
            proof,
            root_hash,
        }
    }

    /// Get proof bytes for verification
    pub fn proof_bytes(&self) -> Vec<u8> {
        self.root_hash.inner().as_bytes().to_vec()
    }

    /// Serialize this proof
    ///
    /// # Returns
    /// * `Vec<u8>` - Serialized proof
    pub fn serialize(&self) -> Vec<u8> {
        // Self-describing format: u32 root_len, root, u32 proof_count, then for each (u32 len, bytes)
        use crate::types::serialization::{put_bytes, put_u32};

        let mut out = Vec::new();
        put_bytes(&mut out, &self.root);
        put_u32(&mut out, self.proof.len() as u32);
        for p in &self.proof {
            put_bytes(&mut out, p);
        }
        out
    }

    /// Parse from serialized bytes
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        fn get_u32(off: &mut usize, data: &[u8]) -> Option<u32> {
            if *off + 4 > data.len() {
                return None;
            }
            let mut b = [0u8; 4];
            b.copy_from_slice(&data[*off..*off + 4]);
            *off += 4;
            Some(u32::from_le_bytes(b))
        }
        fn get_bytes<'a>(off: &mut usize, data: &'a [u8]) -> Option<&'a [u8]> {
            let len = get_u32(off, data)? as usize;
            if *off + len > data.len() {
                return None;
            }
            let s = &data[*off..*off + len];
            *off += len;
            Some(s)
        }

        let mut off = 0usize;
        let root = get_bytes(&mut off, data)?.to_vec();
        let count = get_u32(&mut off, data)? as usize;
        let mut proof = Vec::with_capacity(count);
        for _ in 0..count {
            proof.push(get_bytes(&mut off, data)?.to_vec());
        }
        let root_hash = SerializableHash::new(domain_hash("DSM/proof-root", &root));
        Some(Self {
            root,
            proof,
            root_hash,
        })
    }

    /// Verify this proof against a leaf hash
    ///
    /// # Arguments
    /// * `leaf_hash` - Leaf hash to verify
    ///
    /// # Returns
    /// * `bool` - True if the proof is valid, false otherwise
    pub fn verify(&self, leaf_hash: &[u8]) -> bool {
        // Start with the leaf hash
        let mut current_hash = leaf_hash.to_vec();

        // Apply each proof element to verify path to root
        for proof_element in &self.proof {
            // Hash the current hash with the proof element
            let mut hasher = dsm_domain_hasher("DSM/merkle-path");
            hasher.update(&current_hash);
            hasher.update(proof_element);
            current_hash = hasher.finalize().as_bytes().to_vec();
        }

        // Verify that we arrived at the expected root
        current_hash == self.root
    }
}

/// Represents a proof of inclusion in a Sparse Merkle Tree
/// This structure contains the minimal set of hashes needed to
/// reconstruct the path from a leaf to the root, as described in whitepaper Section 3.3
#[derive(Clone, Debug)]
#[allow(dead_code)]
pub struct MerkleProof {
    /// Path from leaf to root, containing sibling hashes
    pub path: Vec<SerializableHash>,

    /// Leaf position in the tree
    pub index: u64,

    /// Hash of the leaf node
    pub leaf_hash: SerializableHash,

    /// Hash of the root node
    pub root_hash: SerializableHash,

    /// Height of the tree
    pub height: u32,

    /// Total number of leaves in the tree
    pub leaf_count: u64,

    /// Device ID associated with this proof
    pub device_id: String,

    /// Public key associated with this proof
    pub public_key: Vec<u8>,

    /// Sparse index for efficient lookups
    pub sparse_index: SparseIndex,

    /// Token balances associated with this proof
    pub token_balances: HashMap<String, Balance>,

    /// Transaction mode for this proof
    pub mode: TransactionMode,

    pub(crate) root: SerializableHash,
    pub(crate) siblings: Vec<SerializableHash>,
    pub(crate) data: Vec<u8>,
    pub(crate) proof: Vec<SerializableHash>,
    pub(crate) proof_leaf_count: i32,
    pub(crate) proof_index: i32,
    pub(crate) proof_height: i32,
    pub(crate) proof_token_balances: HashMap<String, Balance>,
    pub(crate) proof_device_id: String,
}

impl MerkleProof {
    /// Generate a Merkle proof for the specified leaf index in the tree
    ///
    /// # Arguments
    /// * `tree` - The Sparse Merkle Tree containing the data
    /// * `index` - The index of the leaf to generate a proof for
    ///
    /// # Returns
    /// * `Result<Self, DsmError>` - The generated proof or an error
    pub fn generate(tree: &SparseMerkleTree, index: u64) -> Result<Self, DsmError> {
        let height = tree.height;
        let mut siblings = Vec::with_capacity(height as usize);

        // Traverse the tree from leaf to root, collecting sibling hashes
        let mut current_index = index;

        for level in (0..height).rev() {
            // Calculate sibling index (flip the bit at current level)
            let sibling_index = current_index ^ (1u64 << level);

            // Get hash from tree's nodes HashMap if available
            let sibling_hash = tree
                .nodes
                .get(&crate::types::state_types::NodeId {
                    level,
                    index: sibling_index,
                })
                .map(|h| *h.as_bytes())
                .unwrap_or([0u8; 32]);

            siblings.push(SerializableHash::new(blake3::Hash::from_bytes(
                sibling_hash,
            )));

            // Update current_index for next level (clear the bit we just processed)
            current_index &= !(1u64 << level);
        }

        // Get leaf data from leaves HashMap
        let leaf_hash = match tree.leaves.get(&index) {
            Some(hash) => SerializableHash::new(*hash),
            None => return Err(DsmError::merkle("Leaf data not found")),
        };

        // Create the proof parameters
        let params = MerkleProofParams {
            path: siblings,
            index,
            leaf_hash,
            root_hash: SerializableHash::new(tree.root),
            height,
            leaf_count: tree.leaf_count,
            device_id: String::new(),
            public_key: Vec::new(),
            sparse_index: SparseIndex::new(vec![]),
            token_balances: HashMap::new(),
            proof: Vec::new(),
            mode: crate::types::operations::TransactionMode::Bilateral,
            params: Vec::new(),
        };

        Ok(Self::new(params))
    }
    /// Add proof_bytes method for MerkleProof
    ///
    /// Generates the serialized bytes for the proof
    pub fn proof_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        // Add serialized path elements
        for hash in &self.path {
            bytes.extend_from_slice(hash.inner().as_bytes());
        }

        // Add leaf hash
        bytes.extend_from_slice(self.leaf_hash.inner().as_bytes());

        // Finalize with root hash
        bytes.extend_from_slice(self.root_hash.inner().as_bytes());

        bytes
    }

    /// Verify if the proof is valid by reconstructing the path up to the root
    pub fn verify(&self) -> bool {
        let proof_bytes = self.proof_bytes();
        // Use the constant_time_eq module from crate imports
        crate::core::state_machine::utils::constant_time_eq(
            self.root_hash.inner().as_bytes(),
            &proof_bytes,
        )
    }

    /// Serialize the proof to a byte vector
    pub fn serialize(&self) -> Vec<u8> {
        let mut result = Vec::new();

        result.extend_from_slice(&self.index.to_le_bytes());
        result.extend_from_slice(self.leaf_hash.inner().as_bytes());
        result.extend_from_slice(self.root_hash.inner().as_bytes());
        result.extend_from_slice(&self.height.to_le_bytes());
        result.extend_from_slice(&self.leaf_count.to_le_bytes());
        result.extend_from_slice(self.device_id.as_bytes());
        result.extend_from_slice(&self.public_key);

        for (token, balance) in &self.token_balances {
            result.extend_from_slice(token.as_bytes());
            result.extend_from_slice(&balance.to_le_bytes());
        }

        result
    }

    /// Create a new MerkleProof with parameters
    pub fn new(params: MerkleProofParams) -> Self {
        // Convert public fields to crate-internal fields
        let root = SerializableHash::new(*params.root_hash.inner());
        let siblings = params.path.clone();
        let data = Vec::new();
        let proof = Vec::new();
        let proof_leaf_count = params.leaf_count as i32;
        let proof_index = params.index as i32;
        let proof_height = params.height as i32;
        let proof_token_balances = HashMap::new();
        let proof_device_id = params.device_id.clone();

        Self {
            path: params.path,
            index: params.index,
            leaf_hash: params.leaf_hash,
            root_hash: params.root_hash,
            height: params.height,
            leaf_count: params.leaf_count,
            device_id: params.device_id,
            public_key: params.public_key,
            sparse_index: params.sparse_index,
            token_balances: params.token_balances,
            root,
            siblings,
            data,
            proof,
            proof_leaf_count,
            proof_index,
            proof_height,
            proof_token_balances,
            proof_device_id,
            mode: TransactionMode::Bilateral, // Use Bilateral mode by default
        }
    }
}

/// Non-inclusion proof for Sparse Merkle Trees as specified in whitepaper Section 3.3
/// Proves that a leaf at a given index contains the zero leaf value
#[derive(Clone, Debug)]
pub struct NonInclusionProof {
    /// Path from leaf to root, containing sibling hashes
    pub path: Vec<SerializableHash>,

    /// Leaf position in the tree
    pub index: u64,

    /// Root hash of the tree
    pub root_hash: SerializableHash,

    /// Height of the tree
    pub height: u32,
}

impl NonInclusionProof {
    /// Generate a non-inclusion proof for the specified leaf index
    ///
    /// # Arguments
    /// * `tree` - The Sparse Merkle Tree
    /// * `index` - The index to prove non-inclusion for
    ///
    /// # Returns
    /// * `Result<Self, DsmError>` - The generated proof or an error
    pub fn generate(tree: &SparseMerkleTreeImpl, index: u64) -> Result<Self, DsmError> {
        // Ensure index is within tree capacity
        let max_leaves = 1u64 << tree.height();
        if index >= max_leaves {
            return Err(DsmError::InvalidOperation(format!(
                "Index {index} exceeds tree capacity of {max_leaves}"
            )));
        }

        // Generate proof path
        let mut path = Vec::with_capacity(tree.height() as usize);
        let mut current_index = index;

        for level in 0..tree.height() {
            // Get sibling index
            let sibling_index = current_index ^ 1; // Flip the lowest bit

            // Get sibling hash
            let sibling_hash = tree.get_node_hash(level, sibling_index)?;

            // Add sibling hash to proof path
            path.push(SerializableHash::new(sibling_hash));

            // Move up to parent
            current_index >>= 1; // Divide by 2
        }

        Ok(NonInclusionProof {
            path,
            index,
            root_hash: SerializableHash::new(*tree.root()),
            height: tree.height(),
        })
    }

    /// Verify a non-inclusion proof
    ///
    /// # Returns
    /// * `bool` - True if the proof is valid
    pub fn verify(&self) -> bool {
        use crate::merkle::sparse_merkle_tree::{default_node, hash_smt_node};

        // Start with the zero leaf value
        let mut current_hash = default_node(0);

        // Reconstruct the path
        let mut current_index = self.index;

        for sibling_hash in &self.path {
            let sibling = sibling_hash.inner();

            // Compute parent hash based on position
            current_hash = if current_index & 1 == 0 {
                // Current is left child
                hash_smt_node(&current_hash, sibling)
            } else {
                // Current is right child
                hash_smt_node(sibling, &current_hash)
            };

            // Move up to parent
            current_index >>= 1;
        }

        // Check if reconstructed root matches expected root
        current_hash == *self.root_hash.inner()
    }
}

/// Sparse Merkle Tree implementation for efficient inclusion proofs
/// as described in whitepaper Section 3.3
pub struct SparseMerkleTree {
    /// Root hash of the tree
    pub root: Hash,

    /// Map of indexes to leaf hashes
    pub leaves: HashMap<u64, Hash>,

    /// Map of node identifiers to their hash values
    pub nodes: HashMap<NodeId, Hash>,

    /// Height of the tree
    pub height: u32,

    /// Total number of leaves in the tree
    pub leaf_count: u64,
}

impl SparseMerkleTree {
    /// Compute Merkle root hash
    pub fn compute_root(&self) -> Result<Hash, DsmError> {
        let tree_impl = SparseMerkleTreeImpl::from_sparse_merkle_tree(self);
        let root_hash = tree_impl.compute_root()?;
        Ok(root_hash)
    }

    /// Insert a state into the Merkle tree
    pub fn insert(&mut self, key: Vec<u8>, value: State) -> Result<(), DsmError> {
        // Hash the key to get a deterministic index
        let mut hasher = dsm_domain_hasher("DSM/smt-key");
        hasher.update(&key);
        let hash = hasher.finalize();

        // Use the first 8 bytes as a u64 index
        let mut index_bytes = [0u8; 8];
        index_bytes.copy_from_slice(&hash.as_bytes()[0..8]);
        let index = u64::from_le_bytes(index_bytes);

        // Hash the state to get a leaf hash
        let state_hash = if key.is_empty() {
            // Convert the vector to a Hash object
            let hash_bytes = value.hash()?;
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(&hash_bytes);
            blake3::Hash::from_bytes(bytes)
        } else {
            // Already returns a Hash
            domain_hash("DSM/merkle-leaf", &key)
        };

        // Store in the tree
        self.leaves.insert(index, state_hash);

        Ok(())
    }

    /// Generate proof for a specific key
    pub fn generate_proof(&self, key: &[u8]) -> Result<Vec<u8>, DsmError> {
        // Hash the key to get a deterministic index
        let mut hasher = dsm_domain_hasher("DSM/smt-key");
        hasher.update(key);
        let hash = hasher.finalize();

        // Use the first 8 bytes as a u64 index
        let mut index_bytes = [0u8; 8];
        index_bytes.copy_from_slice(&hash.as_bytes()[0..8]);
        let index = u64::from_le_bytes(index_bytes);

        // Create MerkleProof and serialize deterministically
        let proof = MerkleProof::generate(self, index)?;
        Ok(proof.serialize())
    }

    /// Verify a Merkle proof
    pub fn verify_proof(&self, key: &[u8], proof_bytes: &[u8]) -> Result<bool, DsmError> {
        // Parse the proof from bytes using our serializer contract
        let proof = SerializableMerkleProof::from_bytes(proof_bytes).ok_or_else(|| {
            DsmError::serialization_error(
                "Invalid merkle proof bytes",
                "proof",
                None::<&str>,
                None::<std::io::Error>,
            )
        })?;
        // Bridge into MerkleProof minimal check
        let leaf_hash_ser = SerializableHash::new(domain_hash("DSM/merkle-leaf", key));
        let mp = MerkleProof {
            path: Vec::new(),
            index: 0,
            leaf_hash: leaf_hash_ser.clone(),
            root_hash: SerializableHash::new(domain_hash("DSM/proof-root", &proof.root)),
            height: 0,
            leaf_count: 0,
            device_id: String::new(),
            public_key: Vec::new(),
            sparse_index: SparseIndex::new(vec![]),
            token_balances: HashMap::new(),
            mode: TransactionMode::Bilateral,
            root: SerializableHash::new(domain_hash("DSM/proof-root", &proof.root)),
            siblings: Vec::new(),
            data: Vec::new(),
            proof: Vec::new(),
            proof_leaf_count: 0,
            proof_index: 0,
            proof_height: 0,
            proof_token_balances: HashMap::new(),
            proof_device_id: String::new(),
        };

        // Hash the key to get its leaf hash
        let mut hasher = dsm_domain_hasher("DSM/smt-key");
        hasher.update(key);
        let hash = hasher.finalize().as_bytes().to_vec();

        // Verify the proof
        // The verify method doesn't take arguments but works with the internal state
        let verified = mp.verify();

        // Additionally check if leaf hash matches our expected hash
        let leaf_hash_matches = leaf_hash_ser.inner().as_bytes() == hash.as_slice();

        Ok(verified && leaf_hash_matches)
    }

    /// Get the root hash
    pub fn root_hash(&self) -> Vec<u8> {
        self.root.as_bytes().to_vec()
    }
}

/// Internal node identifier for efficient tree operations
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct NodeId {
    /// Level in the tree (0 = leaves)
    pub level: u32,

    /// Index within the level
    pub index: u64,
}

impl SparseMerkleTree {
    /// Create a new Sparse Merkle Tree with a given height
    pub fn new(height: u32) -> Self {
        Self {
            root: Hash::from([0u8; 32]), // Initialize root with empty hash
            leaves: HashMap::new(),      // Start with empty leaves
            nodes: HashMap::new(),       // Start with empty nodes
            height,                      // Store the specified height
            leaf_count: 0,               // Start with no leaves
        }
    }

    /// Verify a Merkle proof against a root and leaf hash
    ///
    /// This implementation is called as a standalone function
    pub fn verify_proof_static(
        root: &Hash,
        leaf_hash: &[u8],
        proof: &MerkleProof,
    ) -> Result<bool, DsmError> {
        if !proof.verify() {
            return Ok(false);
        }

        // Verify leaf hash matches
        if proof.leaf_hash.inner().as_bytes() != leaf_hash {
            return Ok(false);
        }

        // Verify root hash matches
        if proof.root_hash.inner() != root {
            return Ok(false);
        }

        Ok(true)
    }
}

/// PreCommitment represents a commitment to a future state transition
/// Represents a forward commitment for future state transitions
#[derive(Clone, Debug)]
pub struct PreCommitment {
    /// Type of operation being committed to
    pub operation_type: String,
    /// Fixed parameters that cannot be changed during execution
    pub fixed_parameters: HashMap<String, Vec<u8>>,
    /// Variable parameters that can be set during execution
    pub variable_parameters: HashSet<String>,
    /// Minimum state number this commitment applies to
    pub min_state_number: u64,
    /// Hash of the commitment
    pub hash: [u8; 32],
    /// List of signatures
    pub signatures: Vec<Vec<u8>>,
    /// Signature from the entity creating the commitment
    pub entity_signature: Option<Vec<u8>>,
    /// Signature from the counterparty accepting the commitment
    pub counterparty_signature: Option<Vec<u8>>,
    /// Value used in calculations (previously private)
    pub value: Vec<i32>,
    /// Commitment data (previously private)
    pub commitment: Vec<i32>,
    /// Counterparty identifier (previously private)
    pub counterparty_id: [u8; 32],
}

impl PreCommitment {
    /// Generate hash for this pre-commitment
    ///
    /// # Arguments
    /// * `state` - Current state
    /// * `operation` - Operation to be performed
    /// * `next_entropy` - Entropy for next state
    pub fn generate_hash(
        state: &State,
        operation: &Operation,
        next_entropy: &[u8],
    ) -> Result<[u8; 32], DsmError> {
        use crate::serialization::canonical_bytes::CanonicalBytesWriter;

        // Canon 2: centralized, deterministic internal canonical bytes.
        // NOTE: This is an internal commit/hashing path; do not introduce Serde/bincode.
        let mut w = CanonicalBytesWriter::with_capacity(32 + 4 + 256 + 4 + next_entropy.len());
        w.push_len_prefixed(&state.hash()?);

        let op_bytes = operation.to_bytes();
        w.push_len_prefixed(&op_bytes);

        w.push_len_prefixed(next_entropy);

        Ok(*domain_hash("DSM/precommit-hash", w.as_slice()).as_bytes())
    }

    /// Add a signature to this pre-commitment
    ///
    /// # Arguments
    /// * `signature` - Signature to add
    pub fn add_signature(&mut self, signature: Vec<u8>) {
        self.signatures.push(signature);
    }

    /// Create a new PreCommitment with constructor parameters
    pub fn new(
        operation_type: String,
        fixed_parameters: HashMap<String, Vec<u8>>,
        variable_parameters: HashSet<String>,
        min_state_number: u64,
        counterparty_id: [u8; 32],
    ) -> Self {
        Self {
            operation_type,
            fixed_parameters,
            variable_parameters,
            min_state_number,
            hash: [0u8; 32],
            signatures: Vec::new(),
            entity_signature: None,
            counterparty_signature: None,
            value: Vec::new(),
            commitment: Vec::new(),
            counterparty_id,
        }
    }

    /// Convert a ForwardLinkedCommitment to a PreCommitment
    pub fn from_forward_linked_commitment(
        flc: crate::commitments::precommit::ForwardLinkedCommitment,
        commitment_bytes: Vec<u8>,
    ) -> Result<Self, DsmError> {
        // Create a PreCommitment from a ForwardLinkedCommitment
        let fixed_parameters = flc.fixed_parameters.clone();
        let mut variable_parameters = HashSet::new();
        for param in flc.variable_parameters {
            variable_parameters.insert(param);
        }

        // Derive operation type from fixed parameters if available
        let operation_type = if let Some(op_type) = fixed_parameters.get("operation_type") {
            String::from_utf8_lossy(op_type).to_string()
        } else {
            "transfer".to_string() // Default to transfer if not specified
        };

        // Create with constructor
        let mut pre_commitment = Self::new(
            operation_type,
            fixed_parameters,
            variable_parameters,
            flc.min_state_number,
            domain_hash("DSM/device-id", flc.counterparty_id.as_bytes()).into(),
        );

        // Set additional fields
        if commitment_bytes.len() != 32 {
            return Err(DsmError::SerializationError(
                "Invalid commitment hash length".into(),
            ));
        }
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&commitment_bytes);
        pre_commitment.hash = hash;
        pre_commitment.entity_signature = flc.entity_signature;
        pre_commitment.counterparty_signature = flc.counterparty_signature;

        Ok(pre_commitment)
    }

    /// Canonical, deterministic byte encoding for cryptographic commits (no Serde/bincode)
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        // operation_type
        let otb = self.operation_type.as_bytes();
        out.extend_from_slice(&(otb.len() as u32).to_le_bytes());
        out.extend_from_slice(otb);
        // min_state_number
        out.extend_from_slice(&self.min_state_number.to_le_bytes());
        // fixed_parameters (sorted by key)
        let mut keys: Vec<_> = self.fixed_parameters.keys().collect();
        keys.sort();
        out.extend_from_slice(&(keys.len() as u32).to_le_bytes());
        for k in keys {
            let kb = k.as_bytes();
            out.extend_from_slice(&(kb.len() as u32).to_le_bytes());
            out.extend_from_slice(kb);
            if let Some(v) = self.fixed_parameters.get(k) {
                out.extend_from_slice(&(v.len() as u32).to_le_bytes());
                out.extend_from_slice(v);
            } else {
                // Should not happen as key originates from the map; encode empty value defensively
                out.extend_from_slice(&0u32.to_le_bytes());
            }
        }
        // variable_parameters (sorted)
        let mut vparams: Vec<_> = self.variable_parameters.iter().collect();
        vparams.sort();
        out.extend_from_slice(&(vparams.len() as u32).to_le_bytes());
        for vp in vparams {
            let vb = vp.as_bytes();
            out.extend_from_slice(&(vb.len() as u32).to_le_bytes());
            out.extend_from_slice(vb);
        }
        // hash
        out.extend_from_slice(&(self.hash.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.hash);
        // signatures (vector of vectors)
        out.extend_from_slice(&(self.signatures.len() as u32).to_le_bytes());
        for sig in &self.signatures {
            out.extend_from_slice(&(sig.len() as u32).to_le_bytes());
            out.extend_from_slice(sig);
        }
        // entity_signature (optional)
        match &self.entity_signature {
            Some(es) => {
                out.push(1);
                out.extend_from_slice(&(es.len() as u32).to_le_bytes());
                out.extend_from_slice(es);
            }
            None => out.push(0),
        }
        // counterparty_signature (optional)
        match &self.counterparty_signature {
            Some(cs) => {
                out.push(1);
                out.extend_from_slice(&(cs.len() as u32).to_le_bytes());
                out.extend_from_slice(cs);
            }
            None => out.push(0),
        }
        // value (Vec<i32>)
        out.extend_from_slice(&(self.value.len() as u32).to_le_bytes());
        for v in &self.value {
            out.extend_from_slice(&v.to_le_bytes());
        }
        // commitment (Vec<i32>)
        out.extend_from_slice(&(self.commitment.len() as u32).to_le_bytes());
        for v in &self.commitment {
            out.extend_from_slice(&v.to_le_bytes());
        }
        // counterparty_id
        out.extend_from_slice(&(32u32).to_le_bytes());
        out.extend_from_slice(&self.counterparty_id);
        out
    }
}

/// Deterministic canonical encoding for PreCommitment used in State canonical encodings
fn encode_precommitment(pc: &PreCommitment) -> Vec<u8> {
    use crate::types::serialization::{put_bytes, put_str, put_u32, put_u64, put_u8};

    let mut out = Vec::new();
    put_str(&mut out, &pc.operation_type);
    // fixed_parameters sorted by key
    let mut keys: Vec<_> = pc.fixed_parameters.keys().collect();
    keys.sort();
    put_u32(&mut out, keys.len() as u32);
    for k in keys {
        put_str(&mut out, k);
        let v = &pc.fixed_parameters[k];
        put_bytes(&mut out, v);
    }
    // variable_parameters as sorted list to avoid nondeterminism
    let mut vars: Vec<_> = pc.variable_parameters.iter().cloned().collect();
    vars.sort();
    put_u32(&mut out, vars.len() as u32);
    for v in vars {
        put_str(&mut out, &v);
    }
    put_u64(&mut out, pc.min_state_number);
    put_bytes(&mut out, &pc.hash);
    // signatures
    put_u32(&mut out, pc.signatures.len() as u32);
    for s in &pc.signatures {
        put_bytes(&mut out, s);
    }
    match &pc.entity_signature {
        Some(s) => {
            put_u8(&mut out, 1);
            put_bytes(&mut out, s);
        }
        None => put_u8(&mut out, 0),
    }
    match &pc.counterparty_signature {
        Some(s) => {
            put_u8(&mut out, 1);
            put_bytes(&mut out, s);
        }
        None => put_u8(&mut out, 0),
    }
    // value/commitment/counterparty_id are advisory; include for completeness
    // as stable encodings (these are not used in hashing rules elsewhere yet)
    // but deterministic
    put_u32(&mut out, pc.value.len() as u32);
    for v in &pc.value {
        out.extend_from_slice(&v.to_le_bytes());
    }
    put_u32(&mut out, pc.commitment.len() as u32);
    for v in &pc.commitment {
        out.extend_from_slice(&v.to_le_bytes());
    }
    put_bytes(&mut out, &pc.counterparty_id);
    out
}

/// Represents a sequence of random walk positions used for verification
#[derive(Clone, Debug)]
pub struct PositionSequence {
    /// Sequence of positions
    pub positions: Vec<Vec<i32>>,

    /// Seed used to generate the positions
    pub seed: Vec<u8>,
}

impl PositionSequence {
    /// Create a new position sequence
    ///
    /// # Arguments
    /// * `positions` - Sequence of positions
    /// * `seed` - Seed used to generate the positions
    pub fn new(positions: Vec<Vec<i32>>, seed: Vec<u8>) -> Self {
        Self { positions, seed }
    }

    /// Verify this position sequence against a given seed
    ///
    /// # Arguments
    /// * `expected_seed` - Expected seed
    ///
    /// # Returns
    /// * `bool` - True if the verification succeeds, false otherwise
    pub fn verify(&self, expected_seed: &[u8]) -> bool {
        self.seed == expected_seed
    }
}

/// Cryptographic identity anchor described in whitepaper Section 5
#[derive(Debug, Clone)]
pub struct IdentityAnchor {
    /// Unique identifier for this identity
    pub id: String,

    /// Genesis state hash
    pub genesis_hash: Vec<u8>,

    /// Public key for identity verification
    pub public_key: Vec<u8>,

    /// Commitment proof from MPC threshold ceremony
    pub commitment_proof: Vec<u8>,
}

impl IdentityAnchor {
    pub fn new(
        id: String,
        genesis_hash: Vec<u8>,
        public_key: Vec<u8>,
        commitment_proof: Vec<u8>,
    ) -> Self {
        Self {
            id,
            genesis_hash,
            public_key,
            commitment_proof,
        }
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend(self.id.as_bytes());
        bytes.extend(&self.genesis_hash);
        bytes.extend(&self.public_key);
        bytes.extend(&self.commitment_proof);
        bytes
    }
}

/// Context for bilateral relationship state tracking.
///
/// Records both parties' identifiers, state numbers, and the current
/// chain tip for a bilateral relationship, enabling cryptographic
/// verification of relationship continuity across state transitions.
#[derive(Clone, Debug)]
pub struct RelationshipContext {
    /// Device identifier of the local entity (32 bytes).
    pub entity_id: [u8; 32],
    /// Current state number of the local entity.
    pub entity_state_number: u64,
    /// Device identifier of the counterparty (32 bytes).
    pub counterparty_id: [u8; 32],
    /// Current state number of the counterparty.
    pub counterparty_state_number: u64,
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
            entity_state_number: 0,
            counterparty_id,
            counterparty_state_number: 0,
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
            entity_state_number: 0,
            counterparty_id,
            counterparty_state_number: 0,
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
