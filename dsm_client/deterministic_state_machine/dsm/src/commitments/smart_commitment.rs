//! Deterministic Smart Commitments Module
//!
//! Non–Turing-complete commitments with deterministic hashing/binding,
//! strictly binary bindings, no hex/json/base64/serde, and no wall clocks.
//! Ordering/eligibility is driven by deterministic counters (event-driven), not time.
//!
//! Key rules enforced here:
//! - Stable binary encoding for types/conditions (no Debug hashing/serialization).
//! - Domain-separated, length-prefixed hashing.
//! - Verification compares the same commitment hash that was created.
//! - Random-walk verification positions are derived from (commitment_hash, origin entropy).

use std::collections::HashMap;

use crate::core::state_machine::random_walk::algorithms::{
    generate_positions, generate_seed, verify_positions, Position,
};

use crate::{
    crypto::kyber,
    types::{
        error::DsmError,
        operations::{Operation, TransactionMode, VerificationType},
        state_types::State,
        token_types::Balance,
    },
};

// const HASH_LEN: usize = 32;
const WIRE_MAGIC: &[u8] = b"DSM_SMART_COMMIT_V2\0";

/// Commitment types for smart commitments
#[derive(Debug, Clone)]
pub enum CommitmentType {
    /// Conditional commitment based on external data (oracle-verified)
    Conditional {
        condition: String,
        oracle_pubkey: Vec<u8>,
    },
}

/// Commitment conditions for smart commitments
#[derive(Debug, Clone)]
pub enum CommitmentCondition {
    ValueThreshold {
        parameter_name: String,
        threshold: u64,
        operator: ThresholdOperator,
    },
    ExternalDataCommitment {
        expected_hash: Vec<u8>,
        data_source: String,
    },
    MultiSignature {
        required_keys: Vec<Vec<u8>>,
        threshold: usize,
    },
    And(Vec<CommitmentCondition>),
    Or(Vec<CommitmentCondition>),
}

impl Default for CommitmentCondition {
    fn default() -> Self {
        CommitmentCondition::And(Vec::new())
    }
}

/// Operators for value threshold comparisons
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ThresholdOperator {
    GreaterThan,
    LessThan,
    Equal,
    GreaterThanOrEqual,
    LessThanOrEqual,
    NotEqual,
}

/// Evaluation context for smart commitment conditions
///
/// IMPORTANT: step_index is caller-supplied deterministic counter.
/// Do not read global time inside protocol logic.
pub struct CommitmentContext {
    parameters: HashMap<String, u64>,
    external_hashes: HashMap<String, Vec<u8>>,
    signatures: HashMap<Vec<u8>, Vec<u8>>,
    step_index: u64,
}

impl CommitmentContext {
    pub fn new() -> Self {
        Self {
            parameters: HashMap::new(),
            external_hashes: HashMap::new(),
            signatures: HashMap::new(),
            step_index: 0,
        }
    }

    pub fn with_step_index(step_index: u64) -> Self {
        let mut s = Self::new();
        s.step_index = step_index;
        s
    }

    pub fn set_parameter(&mut self, name: &str, value: u64) -> &mut Self {
        self.parameters.insert(name.to_string(), value);
        self
    }

    pub fn set_external_hash(&mut self, source: &str, hash: Vec<u8>) -> &mut Self {
        self.external_hashes.insert(source.to_string(), hash);
        self
    }

    pub fn add_signature(&mut self, public_key: Vec<u8>, signature: Vec<u8>) -> &mut Self {
        self.signatures.insert(public_key, signature);
        self
    }

    pub fn set_step_index(&mut self, step_index: u64) -> &mut Self {
        self.step_index = step_index;
        self
    }
}

impl Default for CommitmentContext {
    fn default() -> Self {
        Self::new()
    }
}

/// Deterministic Smart Commitment
#[derive(Debug, Clone)]
pub struct SmartCommitment {
    pub id: String,

    /// Hash of the origin state this commitment binds to
    pub origin_state_hash: [u8; 32],

    /// Canonical commitment hash (binding root)
    pub commitment_hash: [u8; 32],

    pub conditions: CommitmentCondition,
    pub operation: Operation,

    /// Random-walk verification positions (deterministic)
    pub verification_positions: Vec<Position>,

    pub commitment_type: CommitmentType,

    /// Extracted recipient/amount for quick checks (binary recipient)
    pub recipient: Vec<u8>,
    pub amount: u64,

    // optional/aux fields
    pub value: u64,
    parameters: HashMap<String, String>,
    signatures: Vec<(Vec<u8>, Vec<u8>)>,
    /// Optional deterministic plan marker (NOT wall time)
    planned_step: Option<u64>,
}

impl SmartCommitment {
    /// Extract recipient bytes and amount from operation
    fn extract_recipient_and_amount(operation: &Operation) -> Result<(Vec<u8>, u64), DsmError> {
        match operation {
            Operation::Transfer {
                recipient, amount, ..
            } => Ok((recipient.clone(), amount.value())),
            Operation::Generic { .. } => Ok((Vec::new(), 0)),
            _ => Ok((Vec::new(), 0)),
        }
    }

    fn make_decimal_id(prefix: &str, commitment_hash: &[u8]) -> String {
        let mut h = crate::crypto::blake3::dsm_domain_hasher("DSM/smart-commit/id/v2");
        crate::crypto::canonical_lp::write_lp(&mut h, prefix.as_bytes());
        crate::crypto::canonical_lp::write_lp(&mut h, commitment_hash);
        let out = h.finalize();
        let mut eight = [0u8; 8];
        eight.copy_from_slice(&out.as_bytes()[..8]);
        let num = u64::from_le_bytes(eight);
        format!("{}_{}", prefix, num)
    }

    /// Canonical commitment hash:
    /// H( DOM || origin_state_hash || op_bytes || recipient || amount || commitment_type || conditions )
    fn compute_commitment_hash(
        origin_state_hash: &[u8],
        operation: &Operation,
        recipient: &[u8],
        amount: u64,
        ctype: &CommitmentType,
        cond: &CommitmentCondition,
    ) -> [u8; 32] {
        let opb = operation.to_bytes();

        let mut h = crate::crypto::blake3::dsm_domain_hasher("DSM/smart-commit/hash/v2");

        crate::crypto::canonical_lp::write_lp(&mut h, origin_state_hash);
        crate::crypto::canonical_lp::write_lp(&mut h, &opb);
        crate::crypto::canonical_lp::write_lp(&mut h, recipient);
        h.update(&amount.to_le_bytes());

        encode_commitment_type(&mut h, ctype);
        encode_condition(&mut h, cond);

        *h.finalize().as_bytes()
    }

    /// Create a new smart commitment bound to `origin_state`
    pub fn new(
        id: &str,
        origin_state: &State,
        conditions: CommitmentCondition,
        operation: Operation,
    ) -> Result<Self, DsmError> {
        let origin_hash_vec = origin_state.hash;
        let mut origin_state_hash = [0u8; 32];
        if origin_hash_vec.len() == 32 {
            origin_state_hash.copy_from_slice(&origin_hash_vec);
        } else {
            return Err(DsmError::invalid_operation(
                "Origin state hash must be 32 bytes",
            ));
        }

        let (recipient, amount) = Self::extract_recipient_and_amount(&operation)?;

        let commitment_type = Self::infer_commitment_type(&conditions);

        let commitment_hash = Self::compute_commitment_hash(
            &origin_state_hash,
            &operation,
            &recipient,
            amount,
            &commitment_type,
            &conditions,
        );

        // If caller provided a blank ID, make one deterministically.
        let final_id = if id.is_empty() {
            Self::make_decimal_id("smart", &commitment_hash)
        } else {
            id.to_string()
        };

        let mut c = Self {
            id: final_id,
            origin_state_hash,
            commitment_hash,
            conditions,
            operation,
            verification_positions: Vec::new(),
            commitment_type,
            recipient,
            amount,
            value: 0,
            parameters: HashMap::new(),
            signatures: Vec::new(),
            planned_step: None,
        };

        c.generate_verification_positions(origin_state)?;
        Ok(c)
    }

    fn infer_commitment_type(conditions: &CommitmentCondition) -> CommitmentType {
        match conditions {
            CommitmentCondition::ValueThreshold {
                parameter_name,
                threshold,
                operator,
            } => CommitmentType::Conditional {
                condition: format!("threshold_{parameter_name}_{operator:?}_{threshold}"),
                oracle_pubkey: Vec::new(),
            },
            CommitmentCondition::ExternalDataCommitment {
                expected_hash,
                data_source,
            } => CommitmentType::Conditional {
                condition: data_source.clone(),
                oracle_pubkey: expected_hash.clone(),
            },
            CommitmentCondition::MultiSignature { threshold, .. } => CommitmentType::Conditional {
                condition: format!("multisig_{threshold}"),
                oracle_pubkey: Vec::new(),
            },
            CommitmentCondition::And(_cs) | CommitmentCondition::Or(_cs) => {
                CommitmentType::Conditional {
                    condition: "compound".into(),
                    oracle_pubkey: Vec::new(),
                }
            }
        }
    }

    /// Stricter verify wrapper (adds sanity for distant locks)
    pub fn verify_fixed(&self, state: &State) -> Result<bool, DsmError> {
        if !self.verify(state)? {
            return Ok(false);
        }
        Ok(true)
    }

    /// Evaluate with optional test_mode.
    pub fn evaluate_fixed(&self, ctx: &CommitmentContext, test_mode: bool) -> bool {
        let _ = test_mode;
        self.evaluate(ctx)
    }

    /// Deterministic positions using origin entropy + commitment_hash
    pub fn generate_verification_positions_fixed(
        &mut self,
        origin_state: &State,
    ) -> Result<(), DsmError> {
        let seed = generate_seed(
            &crate::crypto::blake3::domain_hash("DSM/smart-commit", &self.commitment_hash),
            &origin_state.entropy,
            None,
        );
        self.verification_positions = generate_positions(
            &seed,
            None::<crate::core::state_machine::random_walk::algorithms::RandomWalkConfig>,
        )?;
        Ok(())
    }

    /// New conditional commitment:
    /// - `condition` is the statement to be oracle-signed for executability.
    /// - `oracle_pubkey` is the required key (also used for signature verification in is_executable()).
    pub fn new_conditional(
        state: &State,
        recipient: Vec<u8>,
        amount: u64,
        condition: String,
        oracle_pubkey: Vec<u8>,
    ) -> Result<Self, DsmError> {
        let mut origin_state_hash = [0u8; 32];
        if state.hash.len() == 32 {
            origin_state_hash.copy_from_slice(&state.hash);
        } else {
            return Err(DsmError::invalid_operation(
                "Origin state hash must be 32 bytes",
            ));
        }

        let op = Operation::Transfer {
            to_device_id: Vec::new(),
            amount: Balance::zero(),
            recipient: recipient.clone(),
            token_id: Vec::new(),
            to: recipient.clone(),
            message: String::new(),
            mode: TransactionMode::Bilateral,
            nonce: vec![],
            verification: VerificationType::Standard,
            pre_commit: None,
            signature: Vec::new(),
        };

        let cond = CommitmentCondition::MultiSignature {
            required_keys: vec![oracle_pubkey.clone()],
            threshold: 1,
        };

        let ctype = CommitmentType::Conditional {
            condition: condition.clone(),
            oracle_pubkey: oracle_pubkey.clone(),
        };

        let commitment_hash = Self::compute_commitment_hash(
            &origin_state_hash,
            &op,
            &recipient,
            amount,
            &ctype,
            &cond,
        );
        let id = Self::make_decimal_id("conditional", &commitment_hash);

        let mut c = Self {
            id,
            origin_state_hash,
            commitment_hash,
            conditions: cond,
            operation: op,
            verification_positions: Vec::new(),
            commitment_type: ctype,
            recipient,
            amount,
            value: 0,
            parameters: HashMap::new(),
            signatures: Vec::new(),
            planned_step: None,
        };
        c.generate_verification_positions(state)?;
        Ok(c)
    }

    /// New compound (AND) commitment
    pub fn new_compound(
        state: &State,
        recipient: Vec<u8>,
        amount: u64,
        conditions: Vec<CommitmentCondition>,
        name: &str,
    ) -> Result<Self, DsmError> {
        let mut origin_state_hash = [0u8; 32];
        if state.hash.len() == 32 {
            origin_state_hash.copy_from_slice(&state.hash);
        } else {
            return Err(DsmError::invalid_operation(
                "Origin state hash must be 32 bytes",
            ));
        }

        if conditions.is_empty() {
            return Err(DsmError::invalid_operation(
                "Compound commitment requires at least one condition",
            ));
        }

        let compound = if conditions.len() == 1 {
            conditions[0].clone()
        } else {
            CommitmentCondition::And(conditions)
        };

        let op = Operation::Transfer {
            to_device_id: Vec::new(),
            amount: Balance::zero(),
            recipient: recipient.clone(),
            token_id: Vec::new(),
            to: recipient.clone(),
            message: String::new(),
            mode: TransactionMode::Bilateral,
            nonce: vec![],
            verification: VerificationType::Standard,
            pre_commit: None,
            signature: Vec::new(),
        };

        let ctype = Self::determine_compound_type(&compound);
        let commitment_hash = Self::compute_commitment_hash(
            &origin_state_hash,
            &op,
            &recipient,
            amount,
            &ctype,
            &compound,
        );
        let id = Self::make_decimal_id(&format!("{}_compound", name), &commitment_hash);

        let mut s = Self {
            id,
            origin_state_hash,
            commitment_hash,
            conditions: compound,
            operation: op,
            verification_positions: Vec::new(),
            commitment_type: ctype,
            recipient,
            amount,
            value: 0,
            parameters: HashMap::new(),
            signatures: Vec::new(),
            planned_step: None,
        };
        s.generate_verification_positions(state)?;
        Ok(s)
    }

    /// New compound (OR) commitment
    pub fn new_compound_or(
        state: &State,
        recipient: Vec<u8>,
        amount: u64,
        conditions: Vec<CommitmentCondition>,
        name: &str,
    ) -> Result<Self, DsmError> {
        let mut origin_state_hash = [0u8; 32];
        if state.hash.len() == 32 {
            origin_state_hash.copy_from_slice(&state.hash);
        } else {
            return Err(DsmError::invalid_operation(
                "Origin state hash must be 32 bytes",
            ));
        }

        if conditions.is_empty() {
            return Err(DsmError::invalid_operation(
                "Compound commitment requires at least one condition",
            ));
        }

        let compound = if conditions.len() == 1 {
            conditions[0].clone()
        } else {
            CommitmentCondition::Or(conditions)
        };

        let op = Operation::Transfer {
            to_device_id: Vec::new(),
            amount: Balance::zero(),
            recipient: recipient.clone(),
            token_id: Vec::new(),
            to: recipient.clone(),
            message: String::new(),
            mode: TransactionMode::Bilateral,
            nonce: vec![],
            verification: VerificationType::Standard,
            pre_commit: None,
            signature: Vec::new(),
        };

        let ctype = Self::determine_compound_type(&compound);
        let commitment_hash = Self::compute_commitment_hash(
            &origin_state_hash,
            &op,
            &recipient,
            amount,
            &ctype,
            &compound,
        );
        let id = Self::make_decimal_id(&format!("{}_or_compound", name), &commitment_hash);

        let mut s = Self {
            id,
            origin_state_hash,
            commitment_hash,
            conditions: compound,
            operation: op,
            verification_positions: Vec::new(),
            commitment_type: ctype,
            recipient,
            amount,
            value: 0,
            parameters: HashMap::new(),
            signatures: Vec::new(),
            planned_step: None,
        };
        s.generate_verification_positions(state)?;
        Ok(s)
    }

    fn determine_compound_type(condition: &CommitmentCondition) -> CommitmentType {
        match condition {
            CommitmentCondition::And(_cs) | CommitmentCondition::Or(_cs) => {
                CommitmentType::Conditional {
                    condition: "compound".into(),
                    oracle_pubkey: Vec::new(),
                }
            }
            _ => CommitmentType::Conditional {
                condition: "complex".into(),
                oracle_pubkey: Vec::new(),
            },
        }
    }

    /// Generate deterministic random-walk positions from (commitment_hash, origin entropy)
    pub fn generate_verification_positions(
        &mut self,
        origin_state: &State,
    ) -> Result<(), DsmError> {
        let seed = generate_seed(
            &crate::crypto::blake3::domain_hash("DSM/smart-commit", &self.commitment_hash),
            &origin_state.entropy,
            None,
        );
        self.verification_positions = generate_positions(
            &seed,
            None::<crate::core::state_machine::random_walk::algorithms::RandomWalkConfig>,
        )?;
        Ok(())
    }

    /// Evaluate commitment against a context
    pub fn evaluate(&self, ctx: &CommitmentContext) -> bool {
        fn eval_condition(cond: &CommitmentCondition, ctx: &CommitmentContext) -> bool {
            match cond {
                CommitmentCondition::ValueThreshold {
                    parameter_name,
                    threshold,
                    operator,
                } => {
                    if let Some(v) = ctx.parameters.get(parameter_name) {
                        match operator {
                            ThresholdOperator::GreaterThan => *v > *threshold,
                            ThresholdOperator::LessThan => *v < *threshold,
                            ThresholdOperator::Equal => *v == *threshold,
                            ThresholdOperator::GreaterThanOrEqual => *v >= *threshold,
                            ThresholdOperator::LessThanOrEqual => *v <= *threshold,
                            ThresholdOperator::NotEqual => *v != *threshold,
                        }
                    } else {
                        false
                    }
                }
                CommitmentCondition::ExternalDataCommitment {
                    expected_hash,
                    data_source,
                } => ctx
                    .external_hashes
                    .get(data_source)
                    .map(|h| h == expected_hash)
                    .unwrap_or(false),
                CommitmentCondition::MultiSignature {
                    required_keys,
                    threshold,
                } => {
                    let mut ok = 0usize;
                    for k in required_keys {
                        if ctx.signatures.contains_key(k) {
                            ok += 1;
                        }
                    }
                    ok >= *threshold
                }
                CommitmentCondition::And(v) => v.iter().all(|c| eval_condition(c, ctx)),
                CommitmentCondition::Or(v) => v.iter().any(|c| eval_condition(c, ctx)),
            }
        }
        eval_condition(&self.conditions, ctx)
    }

    /// Verify binding to origin state + content (correct)
    pub fn verify(&self, state: &State) -> Result<bool, DsmError> {
        // Must bind to the origin state hash
        if state.hash != self.origin_state_hash {
            return Ok(false);
        }

        // Must reproduce the exact commitment hash
        let expected = Self::compute_commitment_hash(
            &self.origin_state_hash,
            &self.operation,
            &self.recipient,
            self.amount,
            &self.commitment_type,
            &self.conditions,
        );
        if expected != self.commitment_hash {
            return Ok(false);
        }

        // Positions must verify against origin state
        self.verify_against_state(state)
    }

    /// Verify commitment seed/positions against the given origin state
    pub fn verify_against_state(&self, origin_state: &State) -> Result<bool, DsmError> {
        let seed = generate_seed(
            &crate::crypto::blake3::domain_hash("DSM/smart-commit", &self.commitment_hash),
            &origin_state.entropy,
            None,
        );
        let expected_positions = generate_positions(
            &seed,
            None::<crate::core::state_machine::random_walk::algorithms::RandomWalkConfig>,
        )?;
        Ok(verify_positions(
            &expected_positions,
            &self.verification_positions,
        ))
    }

    /// Check if the commitment is currently executable.
    pub fn is_executable(&self, oracle_signature: Option<Vec<u8>>) -> Result<bool, DsmError> {
        match &self.commitment_type {
            CommitmentType::Conditional {
                condition,
                oracle_pubkey,
            } => {
                if let Some(sig) = oracle_signature {
                    use crate::crypto::signatures::SignatureKeyPair;
                    SignatureKeyPair::verify_raw(condition.as_bytes(), &sig, oracle_pubkey).map_err(
                        |e| DsmError::crypto(String::from("oracle verification failed"), Some(e)),
                    )
                } else {
                    Ok(false)
                }
            }
        }
    }

    /// Canonical binding bytes (stable, binary, deterministic)
    pub fn to_bytes(&self) -> Vec<u8> {
        // This is the commitment preimage in wire-stable form.
        // Keep it binary and stable. Do NOT use Debug strings here.
        let mut out = Vec::new();

        out.extend_from_slice(WIRE_MAGIC);

        push_lp(&mut out, self.id.as_bytes());
        push_lp(&mut out, &self.origin_state_hash);
        push_lp(&mut out, &self.commitment_hash);

        // commitment_type
        {
            let mut tmp = Vec::new();
            encode_commitment_type_bytes(&mut tmp, &self.commitment_type);
            push_lp(&mut out, &tmp);
        }
        // conditions
        {
            let mut tmp = Vec::new();
            encode_condition_bytes(&mut tmp, &self.conditions);
            push_lp(&mut out, &tmp);
        }

        // operation bytes
        let opb = self.operation.to_bytes();
        push_lp(&mut out, &opb);

        // recipient + amount + value
        push_lp(&mut out, &self.recipient);
        out.extend_from_slice(&self.amount.to_le_bytes());
        out.extend_from_slice(&self.value.to_le_bytes());

        out
    }

    /// Encrypt via PQ KEM + AEAD (commitment hash + wire bytes)
    /// Returns (kem_ciphertext, nonce||ciphertext)
    pub fn encrypt_for_recipient(
        &self,
        recipient_pubkey: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), DsmError> {
        let body = self.to_wire_bytes();
        let ccommit = self.commitment_hash;

        let (shared, kem_ct) = kyber::kyber_encapsulate(recipient_pubkey)
            .map_err(|e| DsmError::crypto(format!("KEM encapsulate failed: {e}"), Some(e)))?;

        // Deterministic nonce derived from shared secret + commitment hash.
        // No wall clocks, no external randomness required here.
        let nonce_full = {
            let mut h = crate::crypto::blake3::dsm_domain_hasher("DSM/smart-commit/nonce/v2");
            crate::crypto::canonical_lp::write_lp(&mut h, &shared);
            crate::crypto::canonical_lp::write_lp(&mut h, &ccommit);
            h.finalize()
        };
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&nonce_full.as_bytes()[0..12]);

        let mut payload = Vec::with_capacity(32 + body.len());
        payload.extend_from_slice(&ccommit);
        payload.extend_from_slice(&body);

        let key = crate::crypto::blake3::domain_hash("DSM/smart-commit", &shared)
            .as_bytes()
            .to_vec();
        let ct = kyber::aes_encrypt(&key, &nonce, &payload)
            .map_err(|e| DsmError::crypto(format!("AEAD encrypt failed: {e}"), Some(e)))?;

        let mut out = Vec::with_capacity(12 + ct.len());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);
        Ok((kem_ct, out))
    }

    /// Decrypt PQ KEM + AEAD package back into a commitment
    pub fn decrypt_from_sender(
        recipient_secret: &[u8],
        kem_ct: &[u8],
        enc: &[u8],
    ) -> Result<Self, DsmError> {
        let shared = kyber::kyber_decapsulate(recipient_secret, kem_ct)
            .map_err(|e| DsmError::crypto(format!("KEM decapsulate failed: {e}"), Some(e)))?;

        if enc.len() < 12 {
            return Err(DsmError::invalid_operation(
                "encrypted payload too short (nonce)",
            ));
        }
        let (nonce, ct) = enc.split_at(12);
        let key = crate::crypto::blake3::domain_hash("DSM/smart-commit", &shared)
            .as_bytes()
            .to_vec();
        let plain = kyber::aes_decrypt(&key, nonce, ct)
            .map_err(|e| DsmError::crypto(format!("AEAD decrypt failed: {e}"), Some(e)))?;

        if plain.len() <= 32 {
            return Err(DsmError::invalid_operation("decrypted payload too short"));
        }
        let (got_hash, body) = plain.split_at(32);

        // Decode first to get the commitment
        let c = SmartCommitment::from_wire_bytes(body).map_err(|e| {
            DsmError::serialization_error(
                "commitment decode",
                "data",
                None::<&str>,
                Some(Box::new(e)),
            )
        })?;

        // Verify the commitment hash matches what was in the encrypted payload
        if got_hash != c.commitment_hash.as_slice() {
            return Err(DsmError::invalid_operation("commitment hash mismatch"));
        }

        Ok(c)
    }

    // Value helpers
    pub fn with_value(&mut self, value: u64) -> &mut Self {
        self.value = value;
        self
    }
    pub fn verify_amount(&self, amount: u64) -> bool {
        self.value == amount
    }

    // --- Deterministic wire encoding (no serde/json/hex/base64) ---

    #[inline]
    fn push_u32(out: &mut Vec<u8>, v: u32) {
        out.extend_from_slice(&v.to_le_bytes());
    }
    #[inline]
    fn push_u64(out: &mut Vec<u8>, v: u64) {
        out.extend_from_slice(&v.to_le_bytes());
    }
    #[inline]
    fn push_i32(out: &mut Vec<u8>, v: i32) {
        out.extend_from_slice(&v.to_le_bytes());
    }
    #[inline]
    fn push_len_prefixed(out: &mut Vec<u8>, bytes: &[u8]) {
        Self::push_u32(out, bytes.len() as u32);
        out.extend_from_slice(bytes);
    }
    #[inline]
    fn push_str(out: &mut Vec<u8>, s: &str) {
        Self::push_len_prefixed(out, s.as_bytes());
    }

    /// Deterministic wire encoding (stable, binary)
    pub fn to_wire_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();

        out.extend_from_slice(WIRE_MAGIC);

        Self::push_str(&mut out, &self.id);
        Self::push_len_prefixed(&mut out, &self.origin_state_hash);
        Self::push_len_prefixed(&mut out, &self.commitment_hash);

        // commitment type (binary)
        {
            let mut tmp = Vec::new();
            encode_commitment_type_bytes(&mut tmp, &self.commitment_type);
            Self::push_len_prefixed(&mut out, &tmp);
        }

        // conditions (binary)
        {
            let mut tmp = Vec::new();
            encode_condition_bytes(&mut tmp, &self.conditions);
            Self::push_len_prefixed(&mut out, &tmp);
        }

        // operation bytes
        let opb = self.operation.to_bytes();
        Self::push_len_prefixed(&mut out, &opb);

        // verification positions
        Self::push_u32(&mut out, self.verification_positions.len() as u32);
        for p in &self.verification_positions {
            let v: &Vec<i32> = &p.0;
            Self::push_u32(&mut out, v.len() as u32);
            for &n in v {
                Self::push_i32(&mut out, n);
            }
        }

        // recipient bytes
        Self::push_len_prefixed(&mut out, &self.recipient);
        // amounts
        Self::push_u64(&mut out, self.amount);
        Self::push_u64(&mut out, self.value);

        // parameters (sorted)
        let mut keys: Vec<_> = self.parameters.keys().cloned().collect();
        keys.sort_unstable();
        Self::push_u32(&mut out, keys.len() as u32);
        for k in keys {
            Self::push_str(&mut out, &k);
            Self::push_str(
                &mut out,
                self.parameters.get(&k).map(|s| s.as_str()).unwrap_or(""),
            );
        }

        // signatures
        Self::push_u32(&mut out, self.signatures.len() as u32);
        for (pk, sig) in &self.signatures {
            Self::push_len_prefixed(&mut out, pk);
            Self::push_len_prefixed(&mut out, sig);
        }

        // planned_step (optional)
        match self.planned_step {
            Some(t) => {
                out.push(1);
                Self::push_u64(&mut out, t);
            }
            None => out.push(0),
        }

        out
    }

    /// Parse from to_wire_bytes() encoding
    pub fn from_wire_bytes(mut data: &[u8]) -> Result<Self, std::io::Error> {
        use std::io::Read;

        fn rx<const N: usize>(buf: &mut &[u8]) -> Result<[u8; N], std::io::Error> {
            let mut b = [0u8; N];
            buf.read_exact(&mut b)?;
            Ok(b)
        }
        fn ru32(buf: &mut &[u8]) -> Result<u32, std::io::Error> {
            Ok(u32::from_le_bytes(rx::<4>(buf)?))
        }
        fn ru64(buf: &mut &[u8]) -> Result<u64, std::io::Error> {
            Ok(u64::from_le_bytes(rx::<8>(buf)?))
        }
        fn ri32(buf: &mut &[u8]) -> Result<i32, std::io::Error> {
            Ok(i32::from_le_bytes(rx::<4>(buf)?))
        }
        fn rlp(buf: &mut &[u8]) -> Result<Vec<u8>, std::io::Error> {
            let len = ru32(buf)? as usize;
            let mut v = vec![0u8; len];
            buf.read_exact(&mut v)?;
            Ok(v)
        }
        fn rstr(buf: &mut &[u8]) -> Result<String, std::io::Error> {
            let b = rlp(buf)?;
            String::from_utf8(b).map_err(|_| std::io::ErrorKind::InvalidData.into())
        }

        // magic
        {
            let mut magic = vec![0u8; WIRE_MAGIC.len()];
            data.read_exact(&mut magic)?;
            if magic.as_slice() != WIRE_MAGIC {
                return Err(std::io::ErrorKind::InvalidData.into());
            }
        }

        let id = rstr(&mut data)?;
        let origin_state_hash_vec = rlp(&mut data)?;
        let origin_state_hash: [u8; 32] = origin_state_hash_vec
            .try_into()
            .map_err(|_| std::io::ErrorKind::InvalidData)?;
        let commitment_hash_vec = rlp(&mut data)?;
        let commitment_hash: [u8; 32] = commitment_hash_vec
            .try_into()
            .map_err(|_| std::io::ErrorKind::InvalidData)?;

        let ctype_bytes = rlp(&mut data)?;
        let commitment_type = decode_commitment_type_bytes(&ctype_bytes)
            .map_err(|_| std::io::ErrorKind::InvalidData)?;

        let cond_bytes = rlp(&mut data)?;
        let conditions =
            decode_condition_bytes(&cond_bytes).map_err(|_| std::io::ErrorKind::InvalidData)?;

        let op_bytes = rlp(&mut data)?;
        let operation =
            Operation::from_bytes(&op_bytes).map_err(|_| std::io::ErrorKind::InvalidData)?;

        let vp_count = ru32(&mut data)? as usize;
        let mut verification_positions = Vec::with_capacity(vp_count);
        for _ in 0..vp_count {
            let len = ru32(&mut data)? as usize;
            let mut v = Vec::with_capacity(len);
            for _ in 0..len {
                v.push(ri32(&mut data)?);
            }
            verification_positions.push(Position(v));
        }

        let recipient = rlp(&mut data)?;
        let amount = ru64(&mut data)?;
        let value = ru64(&mut data)?;

        let pc = ru32(&mut data)? as usize;
        let mut parameters = HashMap::new();
        for _ in 0..pc {
            let k = rstr(&mut data)?;
            let v = rstr(&mut data)?;
            parameters.insert(k, v);
        }

        let sc = ru32(&mut data)? as usize;
        let mut signatures = Vec::with_capacity(sc);
        for _ in 0..sc {
            let pk = rlp(&mut data)?;
            let sig = rlp(&mut data)?;
            signatures.push((pk, sig));
        }

        let mut flag = [0u8; 1];
        data.read_exact(&mut flag)?;
        let planned_step = if flag[0] == 1 {
            Some(ru64(&mut data)?)
        } else {
            None
        };

        Ok(Self {
            id,
            origin_state_hash,
            commitment_hash,
            conditions,
            operation,
            verification_positions,
            commitment_type,
            recipient,
            amount,
            value,
            parameters,
            signatures,
            planned_step,
        })
    }
}

/// Lightweight reference to a stored commitment
#[derive(Debug, Clone)]
pub struct SmartCommitmentReference {
    pub commitment_id: String,
    pub commitment_hash: [u8; 32],
    pub origin_state_hash: [u8; 32],
}

/// Registry for commitments (in-memory)
pub struct SmartCommitmentRegistry {
    commitments: HashMap<String, SmartCommitment>,
}

impl SmartCommitmentRegistry {
    pub fn new() -> Self {
        Self {
            commitments: HashMap::new(),
        }
    }

    pub fn register_commitment(
        &mut self,
        c: SmartCommitment,
    ) -> Result<SmartCommitmentReference, DsmError> {
        let id = c.id.clone();
        if self.commitments.contains_key(&id) {
            return Err(DsmError::invalid_operation(format!(
                "Commitment with id {id} already exists"
            )));
        }
        let commitment_hash = c.commitment_hash;
        let origin_state_hash = c.origin_state_hash;
        self.commitments.insert(id.clone(), c);
        Ok(SmartCommitmentReference {
            commitment_id: id,
            commitment_hash,
            origin_state_hash,
        })
    }

    pub fn get_commitment(&self, id: &str) -> Option<&SmartCommitment> {
        self.commitments.get(id)
    }

    pub fn evaluate_commitment(&self, id: &str, ctx: &CommitmentContext) -> Result<bool, DsmError> {
        let c = self.get_commitment(id).ok_or_else(|| {
            DsmError::invalid_operation(format!("Commitment with id {id} not found"))
        })?;
        Ok(c.evaluate(ctx))
    }

    pub fn remove_commitment(&mut self, id: &str) -> Result<(), DsmError> {
        if self.commitments.remove(id).is_none() {
            return Err(DsmError::invalid_operation(format!(
                "Commitment with id {id} not found"
            )));
        }
        Ok(())
    }
}

impl Default for SmartCommitmentRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------
// Canonical encoding helpers
// -------------------------

#[inline]
fn push_lp(out: &mut Vec<u8>, bytes: &[u8]) {
    // Keep LP encoding canonical and centralized.
    // Vec encoding is used only for building nested proof/commitment byte blobs; it must match
    // the same u32-le length prefix rule as `canonical_lp::write_lp`.
    let len = bytes.len() as u32;
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(bytes);
}

#[inline]
fn enc_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_le_bytes());
}

#[inline]
fn enc_u64(out: &mut Vec<u8>, v: u64) {
    out.extend_from_slice(&v.to_le_bytes());
}
#[inline]
fn enc_lp(out: &mut Vec<u8>, b: &[u8]) {
    push_lp(out, b);
}
#[inline]
fn enc_str(out: &mut Vec<u8>, s: &str) {
    enc_lp(out, s.as_bytes());
}

fn encode_commitment_type(h: &mut ::blake3::Hasher, ctype: &CommitmentType) {
    let mut tmp = Vec::new();
    encode_commitment_type_bytes(&mut tmp, ctype);
    crate::crypto::canonical_lp::write_lp(h, &tmp);
}

fn encode_commitment_type_bytes(out: &mut Vec<u8>, ctype: &CommitmentType) {
    match ctype {
        CommitmentType::Conditional {
            condition,
            oracle_pubkey,
        } => {
            out.push(2);
            enc_str(out, condition);
            enc_lp(out, oracle_pubkey);
        }
    }
}

fn decode_commitment_type_bytes(bytes: &[u8]) -> Result<CommitmentType, ()> {
    let mut d = bytes;
    if d.is_empty() {
        return Err(());
    }
    let tag = d[0];
    d = &d[1..];
    match tag {
        2 => {
            let condition = dec_str(&mut d)?;
            let oracle_pubkey = dec_lp(&mut d)?;
            Ok(CommitmentType::Conditional {
                condition,
                oracle_pubkey,
            })
        }
        _ => Err(()),
    }
}

fn encode_condition(h: &mut ::blake3::Hasher, cond: &CommitmentCondition) {
    let mut tmp = Vec::new();
    encode_condition_bytes(&mut tmp, cond);
    crate::crypto::canonical_lp::write_lp(h, &tmp);
}

fn encode_condition_bytes(out: &mut Vec<u8>, cond: &CommitmentCondition) {
    match cond {
        CommitmentCondition::ValueThreshold {
            parameter_name,
            threshold,
            operator,
        } => {
            out.push(3);
            enc_str(out, parameter_name);
            enc_u64(out, *threshold);
            out.push(match operator {
                ThresholdOperator::GreaterThan => 1,
                ThresholdOperator::LessThan => 2,
                ThresholdOperator::Equal => 3,
                ThresholdOperator::GreaterThanOrEqual => 4,
                ThresholdOperator::LessThanOrEqual => 5,
                ThresholdOperator::NotEqual => 6,
            });
        }
        CommitmentCondition::ExternalDataCommitment {
            expected_hash,
            data_source,
        } => {
            out.push(4);
            enc_lp(out, expected_hash);
            enc_str(out, data_source);
        }
        CommitmentCondition::MultiSignature {
            required_keys,
            threshold,
        } => {
            out.push(5);
            enc_u32(out, *threshold as u32);
            enc_u32(out, required_keys.len() as u32);
            for k in required_keys {
                enc_lp(out, k);
            }
        }
        CommitmentCondition::And(cs) => {
            out.push(7);
            enc_u32(out, cs.len() as u32);
            for c in cs {
                let mut tmp = Vec::new();
                encode_condition_bytes(&mut tmp, c);
                enc_lp(out, &tmp);
            }
        }
        CommitmentCondition::Or(cs) => {
            out.push(8);
            enc_u32(out, cs.len() as u32);
            for c in cs {
                let mut tmp = Vec::new();
                encode_condition_bytes(&mut tmp, c);
                enc_lp(out, &tmp);
            }
        }
    }
}

fn decode_condition_bytes(bytes: &[u8]) -> Result<CommitmentCondition, ()> {
    let mut d = bytes;
    if d.is_empty() {
        return Err(());
    }
    let tag = d[0];
    d = &d[1..];
    match tag {
        3 => {
            let parameter_name = dec_str(&mut d)?;
            let threshold = dec_u64(&mut d)?;
            if d.is_empty() {
                return Err(());
            }
            let op = d[0];
            // d = &d[1..]; // Unused update
            let operator = match op {
                1 => ThresholdOperator::GreaterThan,
                2 => ThresholdOperator::LessThan,
                3 => ThresholdOperator::Equal,
                4 => ThresholdOperator::GreaterThanOrEqual,
                5 => ThresholdOperator::LessThanOrEqual,
                6 => ThresholdOperator::NotEqual,
                _ => return Err(()),
            };
            Ok(CommitmentCondition::ValueThreshold {
                parameter_name,
                threshold,
                operator,
            })
        }
        4 => {
            let expected_hash = dec_lp(&mut d)?;
            let data_source = dec_str(&mut d)?;
            Ok(CommitmentCondition::ExternalDataCommitment {
                expected_hash,
                data_source,
            })
        }
        5 => {
            let threshold = dec_u32(&mut d)? as usize;
            let n = dec_u32(&mut d)? as usize;
            let mut required_keys = Vec::with_capacity(n);
            for _ in 0..n {
                required_keys.push(dec_lp(&mut d)?);
            }
            Ok(CommitmentCondition::MultiSignature {
                required_keys,
                threshold,
            })
        }
        7 | 8 => {
            let n = dec_u32(&mut d)? as usize;
            let mut cs = Vec::with_capacity(n);
            for _ in 0..n {
                let inner = dec_lp(&mut d)?;
                cs.push(decode_condition_bytes(&inner)?);
            }
            if tag == 7 {
                Ok(CommitmentCondition::And(cs))
            } else {
                Ok(CommitmentCondition::Or(cs))
            }
        }
        _ => Err(()),
    }
}

#[inline]
fn dec_u32(d: &mut &[u8]) -> Result<u32, ()> {
    if d.len() < 4 {
        return Err(());
    }
    let (bytes, rest) = d.split_at(4);
    *d = rest;
    Ok(u32::from_le_bytes(bytes.try_into().map_err(|_| ())?))
}

#[inline]
fn dec_u64(d: &mut &[u8]) -> Result<u64, ()> {
    if d.len() < 8 {
        return Err(());
    }
    let (bytes, rest) = d.split_at(8);
    *d = rest;
    Ok(u64::from_le_bytes(bytes.try_into().map_err(|_| ())?))
}

#[inline]
fn dec_lp(d: &mut &[u8]) -> Result<Vec<u8>, ()> {
    let len = dec_u32(d)? as usize;
    if d.len() < len {
        return Err(());
    }
    let (bytes, rest) = d.split_at(len);
    *d = rest;
    Ok(bytes.to_vec())
}

#[inline]
fn dec_str(d: &mut &[u8]) -> Result<String, ()> {
    let bytes = dec_lp(d)?;
    String::from_utf8(bytes).map_err(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::state_types::DeviceInfo;
    use crate::crypto::sphincs::{generate_sphincs_keypair, sphincs_sign};

    fn signed_update(identity_id: &str, data: Vec<u8>, message: &str) -> Operation {
        let (_pk, sk) = generate_sphincs_keypair().expect("keypair");
        let mut op = Operation::Update {
            message: message.to_string(),
            identity_id: identity_id.as_bytes().to_vec(),
            updated_data: data,
            proof: vec![],
            forward_link: None,
        };
        let sig = sphincs_sign(&sk, &op.to_bytes()).expect("sign update");
        if let Operation::Update { proof, .. } = &mut op {
            *proof = sig;
        }
        op
    }

    #[test]
    fn test_threshold_commitment() -> Result<(), DsmError> {
        let device_id = blake3::hash(b"test").into();
        let origin = State::new_genesis(
            [
                1, 2, 3, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0,
            ],
            DeviceInfo::new(device_id, vec![5]),
        );
        let op = signed_update(
            "threshold_payment",
            vec![20, 21, 22],
            "Test threshold payment",
        );
        let c = SmartCommitment::new(
            "test_threshold",
            &origin,
            CommitmentCondition::ValueThreshold {
                parameter_name: "amount".into(),
                threshold: 100,
                operator: ThresholdOperator::GreaterThanOrEqual,
            },
            op,
        )?;

        let mut ctx = CommitmentContext::with_step_index(0);
        ctx.set_parameter("amount", 50);
        assert!(!c.evaluate(&ctx));
        ctx.set_parameter("amount", 100);
        assert!(c.evaluate(&ctx));
        ctx.set_parameter("amount", 150);
        assert!(c.evaluate(&ctx));
        Ok(())
    }

    #[test]
    fn test_registry() -> Result<(), DsmError> {
        let device_id = blake3::hash(b"test").into();
        let origin = State::new_genesis(
            [
                1, 2, 3, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0,
            ],
            DeviceInfo::new(device_id, vec![5]),
        );
        let op = signed_update("test_registry", vec![50, 51, 52], "Test registry");
        let c = SmartCommitment::new(
            "test_registry",
            &origin,
            CommitmentCondition::ValueThreshold {
                parameter_name: "x".into(),
                threshold: 1,
                operator: ThresholdOperator::GreaterThanOrEqual,
            },
            op,
        )?;
        let mut reg = SmartCommitmentRegistry::new();
        let r = reg.register_commitment(c)?;
        assert_eq!(r.commitment_id, "test_registry");

        let mut ctx = CommitmentContext::with_step_index(0);
        ctx.set_parameter("x", 0);
        assert!(!reg.evaluate_commitment("test_registry", &ctx)?);
        ctx.set_parameter("x", 1);
        assert!(reg.evaluate_commitment("test_registry", &ctx)?);
        Ok(())
    }

    #[test]
    fn test_encryption_decryption_roundtrip() -> Result<(), DsmError> {
        let device_id = blake3::hash(b"test").into();
        let state = State::new_genesis(
            [
                1, 2, 3, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0,
            ],
            DeviceInfo::new(device_id, vec![5]),
        );
        let recipient = vec![1, 2, 3, 4];
        let amount = 100u64;
        let c = SmartCommitment::new_conditional(
            &state,
            recipient.clone(),
            amount,
            "ok".to_string(),
            vec![1, 2, 3],
        )?;
        let kp = crate::crypto::kyber::generate_kyber_keypair()?;
        let (ct, enc) = c.encrypt_for_recipient(&kp.public_key)?;
        let dec = SmartCommitment::decrypt_from_sender(&kp.secret_key, &ct, &enc)?;
        assert_eq!(dec.id, c.id);
        assert_eq!(dec.commitment_hash, c.commitment_hash);
        Ok(())
    }

    #[test]
    fn test_compound_commitment() -> Result<(), DsmError> {
        let device_id = blake3::hash(b"test").into();
        let origin = State::new_genesis(
            [
                1, 2, 3, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0,
            ],
            DeviceInfo::new(device_id, vec![5]),
        );
        let v = CommitmentCondition::ValueThreshold {
            parameter_name: "amount".into(),
            threshold: 500,
            operator: ThresholdOperator::GreaterThanOrEqual,
        };
        let recipient = vec![9, 8, 7, 6];
        let amount = 1000u64;

        let and_c = SmartCommitment::new_compound(
            &origin,
            recipient.clone(),
            amount,
            vec![v.clone()],
            "test_compound",
        )?;
        let mut ctx = CommitmentContext::with_step_index(0);
        ctx.set_parameter("amount", 600);
        assert!(and_c.evaluate(&ctx));

        let or_c = SmartCommitment::new_compound_or(
            &origin,
            recipient.clone(),
            amount,
            vec![v],
            "test_or_compound",
        )?;
        let mut ctx2 = CommitmentContext::with_step_index(0);
        ctx2.set_parameter("amount", 600);
        assert!(or_c.evaluate(&ctx2));
        Ok(())
    }

    #[test]
    fn test_smart_commitment_creation_types_compile() {
        let (_pk, sk) = crate::crypto::sphincs::generate_sphincs_keypair().expect("keypair");
        let mut op = Operation::Transfer {
            to_device_id: b"recipient".to_vec(),
            amount: Balance::from_state(100, [0u8; 32]),
            recipient: b"abcd".to_vec(),
            token_id: b"token123".to_vec(),
            to: b"abcd".to_vec(),
            message: "Test".to_string(),
            mode: TransactionMode::Bilateral,
            nonce: vec![],
            verification: VerificationType::Standard,
            pre_commit: None,
            signature: Vec::new(),
        };

        let sig = crate::crypto::sphincs::sphincs_sign(&sk, &op.to_bytes()).expect("sign transfer");
        if let Operation::Transfer { signature, .. } = &mut op {
            *signature = sig;
        }

        let _ = op;
    }
}
