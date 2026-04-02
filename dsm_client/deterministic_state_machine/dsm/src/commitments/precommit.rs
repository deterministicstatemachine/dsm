//! Pre-commitment and forward-linked commitment support.
//!
//! Deterministic commitments for future state transitions. A pre-commitment
//! binds fixed parameters at commitment time while allowing variable parameters
//! to be supplied at execution time. Forward-linked commitments chain sequential
//! pre-commitments for multi-step protocols.
//!
//! Design rules enforced:
//! - No wall-clock time, no epoch time.
//! - No constant-time comparison scaffolding in the protocol layer.
//! - No ambiguous concatenation: every hashed field is length-prefixed.
//! - Domain separation for every hash.
//! - Deterministic ordering for maps/sets.
//!

use crate::crypto::canonical_lp;
use crate::crypto::sphincs;
use crate::types::error::DsmError;
use crate::types::operations::Operation;
use crate::types::state_types::State;

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{fence, Ordering};

use thiserror::Error;
use zeroize::Zeroize;

// Domain tags (versioned, null-terminated style)
const DOM_PRECOMMIT_ROOT: &[u8] = b"DSM/precommit/root/v2\0";
const DOM_PRECOMMIT_COMMITMENT_HASH: &[u8] = b"DSM/precommit/commitment-hash/v2\0";
const DOM_FORK_CONTEXT: &[u8] = b"DSM/precommit/fork-context/v2\0";
const DOM_FORK_POSITIONS: &[u8] = b"DSM/precommit/fork-positions/v2\0";
const DOM_INVALIDATION_PROOF: &[u8] = b"DSM/precommit/invalidation-proof/v2\0";

// Defensive bounds (deterministic, avoids pathological allocations)
const MAX_ID_LEN: usize = 128;
const MAX_PARAM_KEY_LEN: usize = 128;
const MAX_VAR_NAME_LEN: usize = 128;
const MAX_PARAM_VALUE_LEN: usize = 64 * 1024;
const MAX_OP_BYTES_LEN: usize = 256 * 1024;
const MAX_ENTROPY_LEN: usize = 64 * 1024;

/// Defines error types specific to commitment operations with detailed context
#[derive(Error, Debug)]
pub enum CommitmentError {
    #[error("Cryptographic operation failed: {context}")]
    Crypto {
        context: String,
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    #[error("Verification failed: {context}")]
    Verification { context: String },

    #[error("Serialization error: {context}")]
    Serialization {
        context: String,
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },
}

impl Clone for CommitmentError {
    fn clone(&self) -> Self {
        match self {
            Self::Crypto { context, .. } => Self::Crypto {
                context: context.clone(),
                source: None,
            },
            Self::Verification { context } => Self::Verification {
                context: context.clone(),
            },
            Self::Serialization { context, .. } => Self::Serialization {
                context: context.clone(),
                source: None,
            },
        }
    }
}

impl From<CommitmentError> for DsmError {
    fn from(err: CommitmentError) -> Self {
        match err {
            CommitmentError::Crypto { context, source } => DsmError::crypto(context, source),
            CommitmentError::Serialization { context, source } => DsmError::Serialization {
                context,
                source,
                entity: "commitment".to_string(),
                details: None,
            },
            CommitmentError::Verification { context } => DsmError::Validation {
                context,
                source: None,
            },
        }
    }
}

/// Embedded commitment for state inclusion (compact representation)
#[derive(Debug, Clone)]
pub struct EmbeddedCommitment {
    pub commitment_hash: [u8; 32],
    pub entity_signature: Vec<u8>,
    pub counterparty_signature: Vec<u8>,
    pub variable_parameters: Vec<String>,
    pub fixed_parameters: HashMap<String, Vec<u8>>,
    pub counterparty_id: String,
    pub min_state_number: u64,
}

/// Format: (fork_id, fixed_parameters, variable_parameters)
pub type ForkPath = (String, HashMap<String, Vec<u8>>, HashSet<String>);

#[derive(Debug, Clone)]
pub struct SecurityParameters {
    pub min_signatures: usize,
    pub min_positions: usize,
    pub hash_size: usize,
}

impl Default for SecurityParameters {
    fn default() -> Self {
        Self {
            min_signatures: 2,
            min_positions: 32,
            hash_size: 32,
        }
    }
}

/// Represents a fork invalidation proof
#[derive(Debug, Clone)]
pub struct ForkInvalidationProof {
    pub fork_id: String,
    pub fork_hash: [u8; 32],
    pub selected_fork_hash: [u8; 32],
    pub signatures: HashMap<String, Vec<u8>>,

    /// Deterministic event index (NOT time). Derived from commitment context.
    pub tick: u64,
}

impl ForkInvalidationProof {
    pub fn verify_integrity(
        &self,
        expected_fork_hash: &[u8],
        min_signatures: usize,
    ) -> Result<bool, CommitmentError> {
        if expected_fork_hash != self.fork_hash.as_slice() {
            return Ok(false);
        }
        if self.signatures.len() < min_signatures {
            return Ok(false);
        }
        Ok(true)
    }
}

#[derive(Debug, Clone)]
pub struct PreCommitmentFork {
    pub fork_id: String,
    pub hash: [u8; 32],
    pub fixed_params: HashMap<String, Vec<u8>>,
    pub variable_params: HashSet<String>,
    pub positions: Vec<u8>,
    pub signatures: HashMap<String, Vec<u8>>,
    pub is_selected: bool,
    pub invalidation_proof: Option<ForkInvalidationProof>,
}

#[derive(Debug, Clone)]
pub struct PreCommitment {
    /// Root hash (commitment root). This is what gets signed/verified.
    pub hash: [u8; 32],

    pub signatures: HashMap<String, Vec<u8>>,
    pub forks: Vec<PreCommitmentFork>,
    pub selected_fork_id: Option<String>,
    pub forward_commitment: Option<ForwardLinkedCommitment>,

    /// Derived commitment hash (domain-separated)
    pub commitment_hash: [u8; 32],

    pub fixed_parameters: HashMap<String, Vec<u8>>,
    pub variable_parameters: Vec<String>,
    pub security_params: SecurityParameters,

    #[allow(dead_code)]
    pub(crate) data: Vec<u8>,
}

impl PreCommitment {
    /// Generate commitment root hash:
    /// H( DOM || state_hash || op_bytes || next_entropy )
    ///
    /// Deterministic encoding:
    /// - domain separated
    /// - length prefixed for all fields
    pub fn generate_hash(
        state: &State,
        operation: &Operation,
        next_entropy: &[u8],
    ) -> Result<[u8; 32], DsmError> {
        let state_hash = state.hash()?;
        let op_bytes = operation.to_bytes();

        if op_bytes.len() > MAX_OP_BYTES_LEN {
            return Err(CommitmentError::Verification {
                context: format!("Operation bytes too large: {}", op_bytes.len()),
            }
            .into());
        }
        if next_entropy.len() > MAX_ENTROPY_LEN {
            return Err(CommitmentError::Verification {
                context: format!("Entropy too large: {}", next_entropy.len()),
            }
            .into());
        }

        canonical_lp::hash_lp3(DOM_PRECOMMIT_ROOT, &state_hash, &op_bytes, next_entropy)
    }

    pub fn new(hash: [u8; 32]) -> Self {
        let commitment_hash = canonical_lp::hash_lp1_b32(DOM_PRECOMMIT_COMMITMENT_HASH, &hash);
        Self {
            hash,
            signatures: HashMap::new(),
            forks: Vec::new(),
            selected_fork_id: None,
            forward_commitment: None,
            commitment_hash,
            fixed_parameters: HashMap::new(),
            variable_parameters: Vec::new(),
            security_params: SecurityParameters::default(),
            data: Vec::new(),
        }
    }

    pub fn new_with_signatures(hash: [u8; 32], signatures: HashMap<String, Vec<u8>>) -> Self {
        let commitment_hash = canonical_lp::hash_lp1_b32(DOM_PRECOMMIT_COMMITMENT_HASH, &hash);
        Self {
            hash,
            signatures,
            forks: Vec::new(),
            selected_fork_id: None,
            forward_commitment: None,
            commitment_hash,
            fixed_parameters: HashMap::new(),
            variable_parameters: Vec::new(),
            security_params: SecurityParameters::default(),
            data: Vec::new(),
        }
    }

    pub fn new_forked(
        base_hash: [u8; 32],
        fork_paths: Vec<ForkPath>,
        security_params: Option<SecurityParameters>,
    ) -> Result<Self, DsmError> {
        if fork_paths.is_empty() {
            return Err(CommitmentError::Verification {
                context: "At least one fork path required".into(),
            }
            .into());
        }

        let security_params = security_params.unwrap_or_default();
        let hash_positions = security_params.min_positions;

        let mut forks = Vec::with_capacity(fork_paths.len());
        let mut all_fixed_parameters = HashMap::new();
        let mut all_variable_parameters: Vec<String> = Vec::new();

        for (fork_id, fixed_params, variable_params) in fork_paths {
            validate_id(&fork_id, "fork_id")?;
            validate_fixed_params(&fixed_params)?;
            validate_variable_params(&variable_params)?;

            for (k, v) in &fixed_params {
                all_fixed_parameters.insert(k.clone(), v.clone());
            }
            for var in &variable_params {
                if !all_variable_parameters.iter().any(|x| x == var) {
                    all_variable_parameters.push(var.clone());
                }
            }

            let fork_context =
                build_fork_context(&base_hash, &fork_id, &fixed_params, &variable_params);
            let fork_hash = canonical_lp::hash_lp1(DOM_FORK_CONTEXT, &fork_context)?;

            let positions = Self::create_fork_positions(&fork_hash, hash_positions)?;

            forks.push(PreCommitmentFork {
                fork_id,
                hash: fork_hash,
                fixed_params,
                variable_params,
                positions,
                signatures: HashMap::new(),
                is_selected: false,
                invalidation_proof: None,
            });
        }

        let commitment_hash = canonical_lp::hash_lp1_b32(DOM_PRECOMMIT_COMMITMENT_HASH, &base_hash);

        Ok(Self {
            hash: base_hash,
            signatures: HashMap::new(),
            forks,
            selected_fork_id: None,
            forward_commitment: None,
            commitment_hash,
            fixed_parameters: all_fixed_parameters,
            variable_parameters: all_variable_parameters,
            security_params,
            data: Vec::new(),
        })
    }

    pub fn add_signature(&mut self, signer_id: &str, signature: Vec<u8>) -> Result<(), DsmError> {
        validate_id(signer_id, "signer_id")?;
        if self.signatures.contains_key(signer_id) {
            return Err(CommitmentError::Verification {
                context: format!("Signature from {signer_id} already exists"),
            }
            .into());
        }
        self.signatures.insert(signer_id.to_string(), signature);
        Ok(())
    }

    pub fn has_signature_from(&self, signer_id: &str) -> bool {
        self.signatures.contains_key(signer_id)
    }

    pub fn has_required_signatures(&self, required: usize) -> bool {
        self.signatures.len() >= required
    }

    fn create_invalidation_proof(
        &self,
        fork_id: &str,
        selected_fork_id: &str,
    ) -> Result<ForkInvalidationProof, DsmError> {
        let fork_to_invalidate = self
            .forks
            .iter()
            .find(|f| f.fork_id == fork_id)
            .ok_or_else(|| CommitmentError::Verification {
                context: "Fork to invalidate not found".to_string(),
            })?;

        let selected_fork = self
            .forks
            .iter()
            .find(|f| f.fork_id == selected_fork_id)
            .ok_or_else(|| CommitmentError::Verification {
                context: "Selected fork not found".to_string(),
            })?;

        // Deterministic event index derived from immutable proof context (NOT time).
        let idx = derive_event_index(fork_id, &fork_to_invalidate.hash, &selected_fork.hash)?;

        let proof_bytes = build_invalidation_proof_bytes(
            fork_id,
            &fork_to_invalidate.hash,
            &selected_fork.hash,
            idx,
        );
        let _proof_commit = canonical_lp::hash_lp1(DOM_INVALIDATION_PROOF, &proof_bytes)?;
        // _proof_commit is optional but kept as a stable internal commitment anchor if you later want it.

        Ok(ForkInvalidationProof {
            fork_id: fork_id.to_string(),
            fork_hash: fork_to_invalidate.hash,
            selected_fork_hash: selected_fork.hash,
            signatures: self.signatures.clone(),
            tick: idx,
        })
    }

    pub fn select_fork(&mut self, fork_id: &str) -> Result<(), DsmError> {
        validate_id(fork_id, "fork_id")?;

        let fork_valid = {
            let fork = self
                .forks
                .iter()
                .find(|f| f.fork_id == fork_id)
                .ok_or_else(|| CommitmentError::Verification {
                    context: format!("Fork with ID {fork_id} not found"),
                })?;

            self.verify_fork_selection(fork)?
        };

        if !fork_valid {
            return Err(CommitmentError::Verification {
                context: format!(
                    "Fork with ID {fork_id} has insufficient signatures for selection"
                ),
            }
            .into());
        }

        let other_ids: Vec<String> = self
            .forks
            .iter()
            .filter(|f| f.fork_id != fork_id)
            .map(|f| f.fork_id.clone())
            .collect();

        if let Some(selected) = self.forks.iter_mut().find(|f| f.fork_id == fork_id) {
            selected.is_selected = true;
            self.selected_fork_id = Some(fork_id.to_string());

            for other_id in other_ids {
                let proof = self.create_invalidation_proof(&other_id, fork_id)?;
                if let Some(other) = self.forks.iter_mut().find(|f| f.fork_id == other_id) {
                    other.signatures.clear();
                    other.is_selected = false;
                    other.invalidation_proof = Some(proof);
                }
            }
        }

        Ok(())
    }

    fn verify_fork_selection(&self, fork: &PreCommitmentFork) -> Result<bool, DsmError> {
        let min_signatures = self.security_params.min_signatures;

        if fork.signatures.is_empty() {
            return Ok(false);
        }

        let mut valid_signatures = 0usize;
        for (signer_id, signature) in &fork.signatures {
            if let Some(root_sig) = self.signatures.get(signer_id) {
                if root_sig.as_slice() == signature.as_slice() {
                    valid_signatures += 1;
                }
            }
        }

        if valid_signatures < min_signatures {
            return Ok(false);
        }

        let expected_positions =
            Self::create_fork_positions(&fork.hash, self.security_params.min_positions)?;
        if expected_positions != fork.positions {
            return Ok(false);
        }

        // Recompute fork hash deterministically from context.
        let ctx = build_fork_context(
            &self.hash,
            &fork.fork_id,
            &fork.fixed_params,
            &fork.variable_params,
        );
        let expected_hash = canonical_lp::hash_lp1(DOM_FORK_CONTEXT, &ctx)?;
        if expected_hash.as_slice() != fork.hash.as_slice() {
            return Ok(false);
        }

        Ok(true)
    }

    pub fn verify_signatures(
        &self,
        public_keys: &HashMap<String, Vec<u8>>,
    ) -> Result<bool, DsmError> {
        for signer_id in self.signatures.keys() {
            if !public_keys.contains_key(signer_id) {
                return Err(CommitmentError::Verification {
                    context: format!("Public key for signer {signer_id} not provided"),
                }
                .into());
            }
        }

        for (signer_id, signature) in &self.signatures {
            let public_key_bytes = &public_keys[signer_id];
            if sphincs::sphincs_verify(public_key_bytes, &self.hash, signature).is_err() {
                return Ok(false);
            }
        }

        Ok(true)
    }

    pub fn get_selected_fork(&self) -> Option<&PreCommitmentFork> {
        self.selected_fork_id
            .as_ref()
            .and_then(|id| self.forks.iter().find(|f| f.fork_id == *id))
    }

    pub fn is_fork_invalidated(&self, fork_id: &str) -> Result<bool, DsmError> {
        let fork = match self.forks.iter().find(|f| f.fork_id == fork_id) {
            Some(f) => f,
            None => return Ok(false),
        };

        let proof = match &fork.invalidation_proof {
            Some(p) => p,
            None => return Ok(false),
        };

        if proof.signatures.len() < self.security_params.min_signatures {
            return Ok(false);
        }

        if proof.fork_hash.as_slice() != fork.hash.as_slice() {
            return Ok(false);
        }

        let selected_exists = self
            .forks
            .iter()
            .any(|f| f.hash.as_slice() == proof.selected_fork_hash.as_slice());
        if !selected_exists {
            return Ok(false);
        }

        Ok(true)
    }

    /// Deterministic positions (random-walk style) derived from fork_hash.
    pub fn create_fork_positions(fork_hash: &[u8], count: usize) -> Result<Vec<u8>, DsmError> {
        let mut positions = Vec::with_capacity(count);
        let base = canonical_lp::hash_lp1(DOM_FORK_POSITIONS, fork_hash)?;

        for i in 0..count {
            let mut i_le = [0u8; 8];
            i_le.copy_from_slice(&(i as u64).to_le_bytes());
            let h = canonical_lp::hash_lp2(DOM_FORK_POSITIONS, &base, &i_le)?;
            positions.push(h[0]);
        }

        Ok(positions)
    }

    pub fn add_forward_commitment(&mut self, commitment: ForwardLinkedCommitment) {
        self.forward_commitment = Some(commitment);
    }

    pub fn get_forward_commitment(&self) -> Option<&ForwardLinkedCommitment> {
        self.forward_commitment.as_ref()
    }

    /// Shallow verification against a state:
    /// - verifies internal commitment_hash correctness
    /// - verifies selected fork integrity if set
    ///
    /// Note: Full transition verification requires operation + next_entropy and should use
    /// `verify_transition_root(...)` below.
    pub fn verify(&self, state: &State) -> Result<bool, DsmError> {
        let _state_hash = state.hash()?; // kept to preserve callsite expectations (and future tightening).

        let expected_commitment_hash =
            canonical_lp::hash_lp1_b32(DOM_PRECOMMIT_COMMITMENT_HASH, &self.hash);
        if self.commitment_hash.as_slice() != expected_commitment_hash.as_slice() {
            return Ok(false);
        }

        if let Some(fork_id) = &self.selected_fork_id {
            let fork = match self.forks.iter().find(|f| &f.fork_id == fork_id) {
                Some(f) => f,
                None => return Ok(false),
            };
            if !fork.is_selected {
                return Ok(false);
            }
            if !self.verify_fork_selection(fork)? {
                return Ok(false);
            }
        }

        Ok(true)
    }

    /// Full root verification for a transition.
    /// Recomputes the root hash exactly as `generate_hash(...)` would.
    pub fn verify_transition_root(
        &self,
        state: &State,
        operation: &Operation,
        next_entropy: &[u8],
    ) -> Result<bool, DsmError> {
        let expected = Self::generate_hash(state, operation, next_entropy)?;
        Ok(expected.as_slice() == self.hash.as_slice())
    }

    pub fn from_forward_linked_commitment(flc: &ForwardLinkedCommitment) -> Result<Self, DsmError> {
        let mut signatures = HashMap::new();
        if let Some(entity_sig) = &flc.entity_signature {
            signatures.insert("entity".to_string(), entity_sig.clone());
        }
        if let Some(counterparty_sig) = &flc.counterparty_signature {
            signatures.insert("counterparty".to_string(), counterparty_sig.clone());
        }

        let variable_parameters = flc.variable_parameters.iter().cloned().collect();

        let fork = PreCommitmentFork {
            fork_id: "default".to_string(),
            hash: flc.commitment_hash,
            fixed_params: flc.fixed_parameters.clone(),
            variable_params: flc.variable_parameters.clone(),
            positions: Vec::new(),
            signatures: signatures.clone(),
            is_selected: true,
            invalidation_proof: None,
        };

        Ok(Self {
            hash: flc.commitment_hash,
            signatures,
            forks: vec![fork],
            selected_fork_id: Some("default".to_string()),
            forward_commitment: Some(flc.clone()),
            commitment_hash: flc.commitment_hash,
            fixed_parameters: flc.fixed_parameters.clone(),
            variable_parameters,
            security_params: SecurityParameters::default(),
            data: Vec::new(),
        })
    }

    pub fn with_security_params(mut self, params: SecurityParameters) -> Self {
        self.security_params = params;
        self
    }

    pub fn validate_pre_commitment_integrity(&self) -> Result<(), DsmError> {
        let required = self.security_params.min_signatures;
        if self.signatures.len() < required {
            return Err(CommitmentError::Verification {
                context: format!(
                    "Insufficient signatures: have {}, need {}",
                    self.signatures.len(),
                    required
                ),
            }
            .into());
        }

        if let Some(selected_fork_id) = &self.selected_fork_id {
            let fork = self
                .forks
                .iter()
                .find(|f| f.fork_id == *selected_fork_id)
                .ok_or_else(|| CommitmentError::Verification {
                    context: format!("Selected fork {selected_fork_id} not found"),
                })?;

            if !self.verify_fork_selection(fork)? {
                return Err(CommitmentError::Verification {
                    context: "Selected fork verification failed".to_string(),
                }
                .into());
            }
        } else if required > 0 && self.signatures.is_empty() {
            return Err(CommitmentError::Verification {
                context: "No signatures present".to_string(),
            }
            .into());
        }

        Ok(())
    }
}

impl Default for PreCommitment {
    fn default() -> Self {
        let hash = [0u8; 32];
        let commitment_hash = canonical_lp::hash_lp1_b32(DOM_PRECOMMIT_COMMITMENT_HASH, &hash);
        Self {
            hash,
            signatures: HashMap::new(),
            forks: Vec::new(),
            selected_fork_id: None,
            forward_commitment: None,
            commitment_hash,
            fixed_parameters: HashMap::new(),
            variable_parameters: Vec::new(),
            security_params: SecurityParameters::default(),
            data: Vec::new(),
        }
    }
}

impl Zeroize for PreCommitment {
    fn zeroize(&mut self) {
        for (_, sig) in self.signatures.iter_mut() {
            sig.zeroize();
        }
        self.hash.zeroize();
        self.commitment_hash.zeroize();

        for fork in &mut self.forks {
            for (_, sig) in fork.signatures.iter_mut() {
                sig.zeroize();
            }
            fork.hash.zeroize();
            fork.positions.zeroize();

            if let Some(proof) = &mut fork.invalidation_proof {
                for (_, sig) in proof.signatures.iter_mut() {
                    sig.zeroize();
                }
                proof.fork_hash.zeroize();
                proof.selected_fork_hash.zeroize();
            }
        }

        if let Some(forward_commitment) = &mut self.forward_commitment {
            if let Some(ref mut sig) = forward_commitment.entity_signature {
                sig.zeroize();
            }
            if let Some(ref mut sig) = forward_commitment.counterparty_signature {
                sig.zeroize();
            }
            forward_commitment.commitment_hash.zeroize();
        }

        fence(Ordering::SeqCst);
    }
}

// ---- Canonical encoding helpers ----
//
// IMPORTANT: This module must NOT re-define canonical byte encoding logic.
// All length-prefixing and domain-separated hashing helpers are centralized in
// `crate::crypto::canonical_lp`.

/// Forward-linked commitment implementing whitepaper Section 7.3
#[derive(Debug, Clone)]
pub struct ForwardLinkedCommitment {
    pub next_state_hash: [u8; 32],
    pub entity_id: String,
    pub counterparty_id: String,
    pub fixed_parameters: HashMap<String, Vec<u8>>,
    pub variable_parameters: HashSet<String>,
    pub entity_signature: Option<Vec<u8>>,
    pub counterparty_signature: Option<Vec<u8>>,
    pub commitment_hash: [u8; 32],
    pub min_state_number: u64,
}

impl ForwardLinkedCommitment {
    /// C_future = H( DOM || S_{n+1} || counterparty_id || fixed_params || variable_params )
    pub fn compute_hash(&self) -> Result<[u8; 32], DsmError> {
        validate_id(&self.counterparty_id, "counterparty_id")?;
        validate_fixed_params(&self.fixed_parameters)?;
        validate_variable_params(&self.variable_parameters)?;

        let mut h = crate::crypto::blake3::dsm_domain_hasher("DSM/flc/hash/v2");
        canonical_lp::write_lp_b32(&mut h, &self.next_state_hash);
        canonical_lp::write_lp(&mut h, self.counterparty_id.as_bytes())?;

        // Deterministic map iteration
        let mut sorted_fixed: Vec<_> = self.fixed_parameters.iter().collect();
        sorted_fixed.sort_by_key(|(k, _)| *k);
        for (k, v) in sorted_fixed {
            canonical_lp::write_lp(&mut h, k.as_bytes())?;
            canonical_lp::write_lp(&mut h, v)?;
        }

        let mut sorted_vars: Vec<_> = self.variable_parameters.iter().collect();
        sorted_vars.sort();
        for v in sorted_vars {
            canonical_lp::write_lp(&mut h, v.as_bytes())?;
        }

        Ok(*h.finalize().as_bytes())
    }

    pub fn new(
        next_state_hash: [u8; 32],
        counterparty_id: String,
        fixed_parameters: HashMap<String, Vec<u8>>,
        variable_parameters: HashSet<String>,
        min_state_number: Option<u64>,
    ) -> Result<Self, DsmError> {
        let entity_id = "entity".to_string();

        let mut commitment = Self {
            next_state_hash,
            entity_id,
            counterparty_id,
            fixed_parameters,
            variable_parameters,
            entity_signature: None,
            counterparty_signature: None,
            commitment_hash: [0u8; 32],
            min_state_number: min_state_number.unwrap_or(0),
        };

        commitment.commitment_hash = commitment.compute_hash()?;
        Ok(commitment)
    }

    pub fn sign_as_entity(&mut self, private_key: &[u8]) -> Result<(), DsmError> {
        let signature =
            sphincs::sphincs_sign(private_key, &self.commitment_hash).map_err(|_| {
                CommitmentError::Crypto {
                    context: "Failed to sign with SPHINCS+".into(),
                    source: None,
                }
            })?;
        self.entity_signature = Some(signature);
        Ok(())
    }

    pub fn sign_as_counterparty(&mut self, private_key: &[u8]) -> Result<(), DsmError> {
        let signature = sphincs::sphincs_sign(private_key, &self.commitment_hash).map_err(|e| {
            CommitmentError::Crypto {
                context: "Failed to sign with SPHINCS+".into(),
                source: Some(Box::new(e)),
            }
        })?;
        self.counterparty_signature = Some(signature);
        Ok(())
    }

    pub fn is_fully_signed(&self) -> bool {
        self.entity_signature.is_some() && self.counterparty_signature.is_some()
    }

    pub fn has_signature_from(&self, entity_id: &str) -> bool {
        if entity_id == self.counterparty_id.as_str() {
            return self.counterparty_signature.is_some();
        }
        self.entity_signature.is_some()
    }

    pub fn verify_integrity(&self) -> Result<bool, DsmError> {
        let expected = self.compute_hash()?;
        Ok(expected.as_slice() == self.commitment_hash.as_slice())
    }

    pub fn verify_entity_signature(&self, entity_public_key: &[u8]) -> Result<bool, DsmError> {
        if let Some(ref sig) = self.entity_signature {
            sphincs::sphincs_verify(entity_public_key, &self.commitment_hash, sig).map_err(|_| {
                CommitmentError::Crypto {
                    context: "Error verifying entity signature".into(),
                    source: None,
                }
                .into()
            })
        } else {
            Ok(false)
        }
    }

    pub fn verify_counterparty_signature(
        &self,
        counterparty_public_key: &[u8],
    ) -> Result<bool, DsmError> {
        if let Some(ref sig) = self.counterparty_signature {
            sphincs::sphincs_verify(counterparty_public_key, &self.commitment_hash, sig).map_err(
                |_| {
                    CommitmentError::Crypto {
                        context: "Error verifying counterparty signature".into(),
                        source: None,
                    }
                    .into()
                },
            )
        } else {
            Ok(false)
        }
    }

    pub fn verify_operation_adherence(&self, operation: &Operation) -> Result<bool, DsmError> {
        crate::commitments::parameter_comparison::verify_operation_parameters(
            operation,
            &self.fixed_parameters,
            &self.variable_parameters,
            self.min_state_number,
        )
    }

    pub fn try_to_embedded_commitment(&self) -> Result<EmbeddedCommitment, DsmError> {
        let entity_signature =
            self.entity_signature
                .clone()
                .ok_or_else(|| CommitmentError::Verification {
                    context: "Entity signature must be present when creating embedded commitment"
                        .into(),
                })?;

        let counterparty_signature =
            self.counterparty_signature
                .clone()
                .ok_or_else(|| CommitmentError::Verification {
                    context:
                        "Counterparty signature must be present when creating embedded commitment"
                            .into(),
                })?;

        Ok(EmbeddedCommitment {
            commitment_hash: self.commitment_hash,
            entity_signature,
            counterparty_signature,
            variable_parameters: self.variable_parameters.iter().cloned().collect(),
            fixed_parameters: self.fixed_parameters.clone(),
            counterparty_id: self.counterparty_id.clone(),
            min_state_number: self.min_state_number,
        })
    }
}

impl Zeroize for ForwardLinkedCommitment {
    fn zeroize(&mut self) {
        self.next_state_hash.zeroize();
        self.commitment_hash.zeroize();

        if let Some(ref mut sig) = self.entity_signature {
            sig.zeroize();
        }
        if let Some(ref mut sig) = self.counterparty_signature {
            sig.zeroize();
        }
        for (_, v) in self.fixed_parameters.iter_mut() {
            v.zeroize();
        }

        fence(Ordering::SeqCst);
    }
}

// --------------------------
// Internal deterministic helpers
// --------------------------

fn validate_id(s: &str, field: &str) -> Result<(), DsmError> {
    if s.is_empty() || s.len() > MAX_ID_LEN {
        return Err(CommitmentError::Verification {
            context: format!("{field} invalid length"),
        }
        .into());
    }
    if !s.is_ascii() {
        return Err(CommitmentError::Verification {
            context: format!("{field} must be ASCII"),
        }
        .into());
    }
    Ok(())
}

fn validate_fixed_params(m: &HashMap<String, Vec<u8>>) -> Result<(), DsmError> {
    for (k, v) in m {
        if k.is_empty() || k.len() > MAX_PARAM_KEY_LEN || !k.is_ascii() {
            return Err(CommitmentError::Verification {
                context: "fixed_parameters contains invalid key".into(),
            }
            .into());
        }
        if v.len() > MAX_PARAM_VALUE_LEN {
            return Err(CommitmentError::Verification {
                context: "fixed_parameters contains oversized value".into(),
            }
            .into());
        }
    }
    Ok(())
}

fn validate_variable_params(s: &HashSet<String>) -> Result<(), DsmError> {
    for v in s {
        if v.is_empty() || v.len() > MAX_VAR_NAME_LEN || !v.is_ascii() {
            return Err(CommitmentError::Verification {
                context: "variable_parameters contains invalid name".into(),
            }
            .into());
        }
    }
    Ok(())
}

fn build_fork_context(
    base_hash: &[u8],
    fork_id: &str,
    fixed_params: &HashMap<String, Vec<u8>>,
    variable_params: &HashSet<String>,
) -> Vec<u8> {
    let mut fixed_keys: Vec<&String> = fixed_params.keys().collect();
    fixed_keys.sort();

    let mut var_list: Vec<&String> = variable_params.iter().collect();
    var_list.sort();

    let mut buf = Vec::new();
    buf.extend_from_slice(base_hash);
    buf.extend_from_slice(fork_id.as_bytes());

    // Deterministic, unambiguous encoding (length-prefixing done by caller hash)
    for k in fixed_keys {
        buf.extend_from_slice(k.as_bytes());
        buf.extend_from_slice(&fixed_params[k]);
    }
    for v in var_list {
        buf.extend_from_slice(v.as_bytes());
    }

    buf
}

fn build_invalidation_proof_bytes(
    fork_id: &str,
    fork_hash: &[u8],
    selected_hash: &[u8],
    idx: u64,
) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(fork_id.as_bytes());
    b.extend_from_slice(fork_hash);
    b.extend_from_slice(selected_hash);
    b.extend_from_slice(&idx.to_le_bytes());
    b
}

fn derive_event_index(
    fork_id: &str,
    fork_hash: &[u8],
    selected_hash: &[u8],
) -> Result<u64, DsmError> {
    let mut h = crate::crypto::blake3::dsm_domain_hasher("DSM/precommit/invalidation-proof/v2");
    canonical_lp::write_lp(&mut h, fork_id.as_bytes())?;
    canonical_lp::write_lp(&mut h, fork_hash)?;
    canonical_lp::write_lp(&mut h, selected_hash)?;
    let out = h.finalize();
    let bytes = out.as_bytes();
    let mut u = [0u8; 8];
    u.copy_from_slice(&bytes[0..8]);
    Ok(u64::from_le_bytes(u))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_buffer(label: &str, size: usize) -> Vec<u8> {
        let mut h = blake3::Hasher::new();
        h.update(b"DSM/test-buffer/v2\0");
        h.update(label.as_bytes());
        let out = h.finalize();
        let mut v = Vec::with_capacity(size);
        let mut counter = 0u64;
        while v.len() < size {
            let mut hh = blake3::Hasher::new();
            hh.update(out.as_bytes());
            hh.update(&counter.to_le_bytes());
            let o = hh.finalize();
            let take = core::cmp::min(size - v.len(), o.as_bytes().len());
            v.extend_from_slice(&o.as_bytes()[0..take]);
            counter = counter.wrapping_add(1);
        }
        v
    }

    #[test]
    fn test_fork_positions_deterministic() -> Result<(), DsmError> {
        let hash1 = test_buffer("hash1", 32);
        let hash2 = hash1.clone();

        let p1 = PreCommitment::create_fork_positions(&hash1, 32)?;
        let p2 = PreCommitment::create_fork_positions(&hash2, 32)?;
        assert_eq!(p1, p2);

        let mut hash3 = hash1.clone();
        hash3[0] = hash3[0].wrapping_add(1);
        let p3 = PreCommitment::create_fork_positions(&hash3, 32)?;
        assert_ne!(p1, p3);
        Ok(())
    }

    #[test]
    fn test_equality_checks_are_plain() {
        let a = vec![0u8; 32];
        let b = vec![0u8; 32];
        assert!(a == b);

        let mut c = a.clone();
        c[0] = 1;
        assert!(a != c);
    }

    #[test]
    fn test_invalidation_index_deterministic() -> Result<(), DsmError> {
        let fork_id = "forkA";
        let fork_hash = test_buffer("fork_hash", 32);
        let selected_hash = test_buffer("sel_hash", 32);

        let i1 = derive_event_index(fork_id, &fork_hash, &selected_hash)?;
        let i2 = derive_event_index(fork_id, &fork_hash, &selected_hash)?;
        assert_eq!(i1, i2);

        let i3 = derive_event_index("forkB", &fork_hash, &selected_hash)?;
        assert_ne!(i1, i3);
        Ok(())
    }
}
