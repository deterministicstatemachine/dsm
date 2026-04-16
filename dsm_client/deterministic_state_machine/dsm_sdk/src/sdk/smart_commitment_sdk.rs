//! # Smart Commitment SDK Module (no `hex` crate, no postcard in hashes)
//!
//! Deterministic, non-Turing smart commitments per DSM §10.
//! - No wall clock usage (deterministic step counters only).
//! - No `hex` crate (local `to_hex` helper).
//! - No postcard/serde for hash preimages; we hash `Sₙ` (state hash) + bytes.
//!
//! ## Hash formulas (unchanged conceptually)
//! * Conditional:   H(Sₙ ‖ recipient ‖ amount ‖ "if"     ‖ condition ‖ O)

use dsm::crypto::blake3::dsm_domain_hasher;
// No wall-clock; deterministic step counters only.
use std::sync::Arc;

use super::core_sdk::CoreSDK;
use dsm::commitments::smart_commitment::{
    CommitmentCondition as DsmCommitmentCondition, SmartCommitment,
};
use dsm::types::error::DsmError;
use dsm::types::operations::{Operation, TransactionMode, VerificationType};
use dsm::types::state_types::State;
use dsm::types::token_types::Balance;

/// Device identifier alias (kept for compatibility with previous code).
type DeviceId = String;

/// Smart commitment conditions as specified in DSM §10.
#[derive(Debug, Clone, PartialEq)]
pub enum SdkCommitmentCondition {
    /// Executes when an external oracle condition is met.
    ConditionalOracle {
        /// Condition expression (e.g., "temperature > 30").
        condition: String,
        /// Oracle identifier.
        oracle_id: String,
    },
}

/// SDK-level representation of a smart commitment.
#[derive(Debug, Clone)]
pub struct SmartCommitmentSdk {
    /// Recipient of the commitment.
    pub recipient: DeviceId,
    /// Amount to transfer.
    pub amount: u64,
    /// Token ID (typically `ROOT` for system ops).
    pub token_id: String,
    /// Condition for the commitment.
    pub condition: SdkCommitmentCondition,
    /// Commitment hash as per §10.
    pub commitment_hash: Vec<u8>,
    /// Optional encrypted payload for secure transport (caller-provided / external transport).
    pub encrypted_payload: Option<Vec<u8>>,
    /// Deterministic creation step index.
    pub step_index: u64,
}

/// SDK for creating/managing smart commitments (DSM §10).
pub struct SmartCommitmentSDK {
    core_sdk: Arc<CoreSDK>,
    executed_commitments: std::collections::HashMap<Vec<u8>, u64>,
}

impl SmartCommitmentSDK {
    /// Create a new SmartCommitmentSDK instance.
    pub fn new(core_sdk: Arc<CoreSDK>) -> Self {
        Self {
            core_sdk,
            executed_commitments: std::collections::HashMap::new(),
        }
    }

    // -------------------------
    // Tiny local utilities
    // -------------------------

    // Hex helpers removed by policy. Use crate::util::text_id::encode/short_id at UI/logging edges when needed.

    /// Deterministic field writer for UTF-8 strings: len(u32 LE) + bytes.
    fn push_str(buf: &mut Vec<u8>, s: &str) {
        let b = s.as_bytes();
        buf.extend_from_slice(&(b.len() as u32).to_le_bytes());
        buf.extend_from_slice(b);
    }

    /// Deterministic field writer for raw bytes: len(u32 LE) + bytes.
    fn push_bytes(buf: &mut Vec<u8>, b: &[u8]) {
        buf.extend_from_slice(&(b.len() as u32).to_le_bytes());
        buf.extend_from_slice(b);
    }

    /// Deterministic fingerprint for an Operation (no serde/postcard; stable ordering).
    fn op_fingerprint(op: &Operation) -> Vec<u8> {
        let mut buf = Vec::new();
        match op {
            Operation::Generic {
                operation_type,
                data,
                message,
                ..
            } => {
                buf.extend_from_slice(b"GEN");
                Self::push_bytes(&mut buf, operation_type);
                buf.extend_from_slice(&(data.len() as u32).to_le_bytes());
                buf.extend_from_slice(data);
                Self::push_str(&mut buf, message);
            }
            Operation::Transfer {
                to_device_id,
                amount,
                token_id,
                mode,
                nonce,
                verification: _,
                pre_commit: _,
                message,
                recipient,
                to,
                signature: _,
            } => {
                buf.extend_from_slice(b"XFER");
                Self::push_bytes(&mut buf, token_id);
                Self::push_bytes(&mut buf, to_device_id);
                Self::push_bytes(&mut buf, recipient);
                Self::push_bytes(&mut buf, to);
                buf.extend_from_slice(&amount.value().to_le_bytes());
                // Mode: 0 = Bilateral, 1 = Unilateral
                buf.push(match mode {
                    TransactionMode::Bilateral => 0u8,
                    TransactionMode::Unilateral => 1u8,
                });
                buf.extend_from_slice(&(nonce.len() as u32).to_le_bytes());
                buf.extend_from_slice(nonce);
                Self::push_str(&mut buf, message);
            }
            Operation::Mint {
                amount,
                token_id,
                authorized_by,
                proof_of_authorization,
                message,
            } => {
                buf.extend_from_slice(b"MINT");
                Self::push_bytes(&mut buf, token_id);
                buf.extend_from_slice(&amount.value().to_le_bytes());
                Self::push_bytes(&mut buf, authorized_by);
                buf.extend_from_slice(&(proof_of_authorization.len() as u32).to_le_bytes());
                buf.extend_from_slice(proof_of_authorization);
                Self::push_str(&mut buf, message);
            }
            Operation::Burn {
                amount,
                token_id,
                proof_of_ownership,
                message,
            } => {
                buf.extend_from_slice(b"BURN");
                Self::push_bytes(&mut buf, token_id);
                buf.extend_from_slice(&amount.value().to_le_bytes());
                buf.extend_from_slice(&(proof_of_ownership.len() as u32).to_le_bytes());
                buf.extend_from_slice(proof_of_ownership);
                Self::push_str(&mut buf, message);
            }
            Operation::Receive {
                token_id,
                from_device_id,
                amount,
                recipient,
                message,
                mode,
                nonce,
                verification: _,
                sender_state_hash,
            } => {
                buf.extend_from_slice(b"RCV");
                Self::push_bytes(&mut buf, token_id);
                Self::push_bytes(&mut buf, from_device_id);
                Self::push_bytes(&mut buf, recipient);
                buf.extend_from_slice(&amount.value().to_le_bytes());
                buf.push(match mode {
                    TransactionMode::Bilateral => 0u8,
                    TransactionMode::Unilateral => 1u8,
                });
                buf.extend_from_slice(&(nonce.len() as u32).to_le_bytes());
                buf.extend_from_slice(nonce);
                if let Some(h) = sender_state_hash {
                    buf.extend_from_slice(&(h.len() as u32).to_le_bytes());
                    buf.extend_from_slice(h);
                } else {
                    buf.extend_from_slice(&0u32.to_le_bytes());
                }
                Self::push_str(&mut buf, message);
            }
            // For other variants we include a stable tag + Debug, as a last resort.
            other => {
                buf.extend_from_slice(b"OP?");
                let dbg = format!("{other:?}");
                Self::push_str(&mut buf, &dbg);
            }
        }
        buf
    }

    // -------------------------
    // Commitment constructors
    // -------------------------

    /// Create a conditional (oracle-based) commitment.
    pub fn create_conditional_commitment(
        &self,
        recipient: &str,
        amount: u64,
        condition: &str,
        oracle_id: &str,
    ) -> Result<SmartCommitmentSdk, DsmError> {
        let current_state = self.core_sdk.get_current_state()?;

        // C_cond = H(Sₙ ∥ recipient ∥ amount ∥ "if" ∥ condition ∥ O)
        let mut hasher = dsm_domain_hasher("DSM/smart-commit-hash");
        hasher.update(&current_state.hash);
        hasher.update(recipient.as_bytes());
        hasher.update(&amount.to_le_bytes());
        hasher.update(b"if");
        hasher.update(condition.as_bytes());
        hasher.update(oracle_id.as_bytes());

        Ok(SmartCommitmentSdk {
            recipient: recipient.to_string(),
            amount,
            token_id: "ROOT".to_string(),
            condition: SdkCommitmentCondition::ConditionalOracle {
                condition: condition.to_string(),
                oracle_id: oracle_id.to_string(),
            },
            commitment_hash: hasher.finalize().as_bytes().to_vec(),
            encrypted_payload: None,
            step_index: 0,
        })
    }

    // -------------------------
    // Execution & verification
    // -------------------------

    /// Build the execution `Operation` for a commitment.
    pub fn execute_commitment(
        &self,
        commitment: &SmartCommitmentSdk,
    ) -> Result<Operation, DsmError> {
        Ok(Operation::Transfer {
            token_id: commitment.token_id.as_bytes().to_vec(),
            amount: Balance::from_state(commitment.amount, [0u8; 32]),
            recipient: commitment.recipient.as_bytes().to_vec(),
            to: commitment.recipient.as_bytes().to_vec(),
            message: "Smart commitment transfer".to_string(),
            to_device_id: commitment.recipient.as_bytes().to_vec(),
            mode: TransactionMode::Bilateral,
            nonce: Vec::new(),
            verification: VerificationType::Standard,
            pre_commit: None,
            signature: Vec::new(),
        })
    }

    /// Record a commitment execution (simple anti-double-execution cache).
    pub fn record_execution(&mut self, commitment: &SmartCommitment) {
        // Value is not used for protocol rules; this is a best-effort process-local cache.
        self.executed_commitments
            .insert(format!("{:?}", commitment.commitment_type).into_bytes(), 1);
    }

    /// Verify a commitment's integrity by recomputing its hash.
    pub fn verify_commitment(&self, commitment: &SmartCommitmentSdk) -> Result<bool, DsmError> {
        let current_state = self.core_sdk.get_current_state()?;

        let calculated = match &commitment.condition {
            SdkCommitmentCondition::ConditionalOracle {
                condition,
                oracle_id,
            } => {
                let mut h = dsm_domain_hasher("DSM/smart-commit-condition");
                h.update(&current_state.hash);
                h.update(commitment.recipient.as_bytes());
                h.update(&commitment.amount.to_le_bytes());
                h.update(b"if");
                h.update(condition.as_bytes());
                h.update(oracle_id.as_bytes());
                h.finalize().as_bytes().to_vec()
            }
        };

        Ok(calculated == commitment.commitment_hash)
    }

    /// Create a deterministic pre-commit forking structure (§11).
    pub fn create_conditional_execution_paths(
        &self,
        paths: Vec<Operation>,
    ) -> Result<Vec<u8>, DsmError> {
        let current_state = self.core_sdk.get_current_state()?;

        // C_fork = H(Sₙ ‖ {path1, path2, ..., pathm})
        let mut h = dsm_domain_hasher("DSM/smart-commit-predicate");
        h.update(&current_state.hash);
        for p in &paths {
            let fp = Self::op_fingerprint(p);
            h.update(&(fp.len() as u32).to_le_bytes());
            h.update(&fp);
        }
        Ok(h.finalize().as_bytes().to_vec())
    }

    /// Deterministically select and verify an execution path.
    pub fn select_execution_path(
        &self,
        fork_commitment: &[u8],
        path_index: usize,
        paths: &[Operation],
    ) -> Result<Operation, DsmError> {
        if path_index >= paths.len() {
            return Err(DsmError::invalid_operation(format!(
                "Invalid path index {} (available: {})",
                path_index,
                paths.len()
            )));
        }

        // Recompute fork commitment and compare.
        let current_state = self.core_sdk.get_current_state()?;
        let mut h = dsm_domain_hasher("DSM/smart-commit-evidence");
        h.update(&current_state.hash);
        for p in paths {
            let fp = Self::op_fingerprint(p);
            h.update(&(fp.len() as u32).to_le_bytes());
            h.update(&fp);
        }
        let calc = h.finalize();
        if calc.as_bytes() != fork_commitment {
            return Err(DsmError::invalid_operation(
                "Fork commitment verification failed",
            ));
        }

        Ok(paths[path_index].clone())
    }

    /// Create an immediate ROOT-token payment commitment (deterministic ID).
    pub fn create_root_payment_commitment(
        &self,
        sender: &str,
        recipient: &str,
        amount: u64,
    ) -> Result<SmartCommitment, DsmError> {
        let current_state = self.core_sdk.get_current_state()?;

        // commitment_hash = H(Sₙ ‖ sender ‖ recipient ‖ amount ‖ "payment")
        let mut h = dsm_domain_hasher("DSM/smart-commit-eval");
        h.update(&current_state.hash);
        h.update(sender.as_bytes());
        h.update(recipient.as_bytes());
        h.update(&amount.to_le_bytes());
        h.update(b"payment");

        let commitment_hash = h.finalize().as_bytes().to_vec();

        // Short deterministic suffix (first 8 bytes -> hex) without the `hex` crate.
        let short = {
            let n = commitment_hash.len().min(8);
            let mut tmp = [0u8; 8];
            tmp[..n].copy_from_slice(&commitment_hash[..n]);
            let short_bytes = &tmp[..n];
            crate::util::text_id::encode_base32_crockford(short_bytes)
        };

        let commitment_id = format!("payment_{sender}_{recipient}_{short}");

        // Minimal, deterministic operation payload; still a Generic op for visibility.
        let op_data = {
            let mut v = Vec::new();
            Self::push_str(&mut v, "payment");
            Self::push_str(&mut v, sender);
            Self::push_str(&mut v, recipient);
            v.extend_from_slice(&amount.to_le_bytes());
            v.extend_from_slice(&commitment_hash); // embed full hash
            v
        };

        let operation = Operation::Generic {
            operation_type: b"payment_commitment".to_vec(),
            data: op_data,
            message: format!(
                "Payment commitment from {sender} to {recipient} for {amount} ROOT (id suffix: {})",
                &short
            ),
            signature: vec![],
        };

        SmartCommitment::new(
            &commitment_id,
            &current_state,
            DsmCommitmentCondition::default(),
            operation,
        )
    }

    /// (Optional) Example of executing a commitment locally.
    #[allow(dead_code)]
    fn execute_smart_commitment(&self, commitment: &SmartCommitmentSdk) -> Result<State, DsmError> {
        let operation = Operation::Transfer {
            to_device_id: commitment.recipient.clone().into_bytes(),
            amount: Balance::from_state(commitment.amount, [0u8; 32]),
            recipient: commitment.recipient.clone().into_bytes(),
            token_id: commitment.token_id.clone().into_bytes(),
            to: commitment.recipient.clone().into_bytes(),
            message: "Smart commitment transfer".to_string(),
            mode: TransactionMode::Bilateral,
            nonce: Vec::new(),
            verification: VerificationType::Standard,
            pre_commit: None,
            signature: Vec::new(),
        };

        // Integrate with CoreSDK transition
        self.core_sdk.execute_dsm_operation(operation)
    }

    /// Create a commitment-creation Operation in the DSM system.
    pub fn create_commitment_operation(&self) -> Result<Operation, DsmError> {
        Ok(Operation::Create {
            message: "Create smart commitment".to_string(),
            identity_data: Vec::new(),
            public_key: Vec::new(),
            metadata: Vec::new(),
            commitment: Vec::new(),
            proof: Vec::new(),
            mode: TransactionMode::Bilateral,
        })
    }

    /// Update a commitment Operation in the DSM system.
    pub fn update_commitment_operation(&self) -> Result<Operation, DsmError> {
        Ok(Operation::Update {
            identity_id: vec![],
            updated_data: vec![],
            proof: vec![],
            forward_link: None,
            message: "Update smart commitment".to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dsm::types::operations::{Operation, TransactionMode, VerificationType};
    use dsm::types::token_types::Balance;

    // ---- push_str / push_bytes determinism ----

    #[test]
    fn push_str_encodes_length_prefixed() {
        let mut buf = Vec::new();
        SmartCommitmentSDK::push_str(&mut buf, "hello");
        assert_eq!(buf.len(), 4 + 5); // u32 LE length + "hello"
        let len = u32::from_le_bytes(buf[..4].try_into().unwrap());
        assert_eq!(len, 5);
        assert_eq!(&buf[4..], b"hello");
    }

    #[test]
    fn push_str_empty_string() {
        let mut buf = Vec::new();
        SmartCommitmentSDK::push_str(&mut buf, "");
        assert_eq!(buf.len(), 4);
        let len = u32::from_le_bytes(buf[..4].try_into().unwrap());
        assert_eq!(len, 0);
    }

    #[test]
    fn push_bytes_encodes_length_prefixed() {
        let mut buf = Vec::new();
        SmartCommitmentSDK::push_bytes(&mut buf, &[0xAA, 0xBB, 0xCC]);
        assert_eq!(buf.len(), 4 + 3);
        let len = u32::from_le_bytes(buf[..4].try_into().unwrap());
        assert_eq!(len, 3);
        assert_eq!(&buf[4..], &[0xAA, 0xBB, 0xCC]);
    }

    #[test]
    fn push_bytes_empty() {
        let mut buf = Vec::new();
        SmartCommitmentSDK::push_bytes(&mut buf, &[]);
        assert_eq!(buf.len(), 4);
        let len = u32::from_le_bytes(buf[..4].try_into().unwrap());
        assert_eq!(len, 0);
    }

    #[test]
    fn push_str_multiple_appends() {
        let mut buf = Vec::new();
        SmartCommitmentSDK::push_str(&mut buf, "abc");
        SmartCommitmentSDK::push_str(&mut buf, "de");
        assert_eq!(buf.len(), (4 + 3) + (4 + 2));
    }

    // ---- op_fingerprint determinism ----

    fn make_generic_op() -> Operation {
        Operation::Generic {
            operation_type: b"test_op".to_vec(),
            data: b"test_data".to_vec(),
            message: "test msg".to_string(),
            signature: vec![],
        }
    }

    fn make_transfer_op() -> Operation {
        Operation::Transfer {
            to_device_id: b"device_A".to_vec(),
            amount: Balance::from_state(1000, [0u8; 32]),
            token_id: b"ROOT".to_vec(),
            mode: TransactionMode::Bilateral,
            nonce: b"nonce1".to_vec(),
            verification: VerificationType::Standard,
            pre_commit: None,
            message: "xfer msg".to_string(),
            recipient: b"recip".to_vec(),
            to: b"to_addr".to_vec(),
            signature: vec![],
        }
    }

    fn make_mint_op() -> Operation {
        Operation::Mint {
            amount: Balance::from_state(500, [0u8; 32]),
            token_id: b"ROOT".to_vec(),
            authorized_by: b"authority".to_vec(),
            proof_of_authorization: b"auth_proof".to_vec(),
            message: "mint".to_string(),
        }
    }

    fn make_burn_op() -> Operation {
        Operation::Burn {
            amount: Balance::from_state(250, [0u8; 32]),
            token_id: b"ROOT".to_vec(),
            proof_of_ownership: b"ownership_proof".to_vec(),
            message: "burn".to_string(),
        }
    }

    fn make_receive_op() -> Operation {
        Operation::Receive {
            token_id: b"ROOT".to_vec(),
            from_device_id: b"sender_dev".to_vec(),
            amount: Balance::from_state(100, [0u8; 32]),
            recipient: b"recipient".to_vec(),
            message: "receive".to_string(),
            mode: TransactionMode::Bilateral,
            nonce: b"nonce".to_vec(),
            verification: VerificationType::Standard,
            sender_state_hash: Some(vec![1u8; 32]),
        }
    }

    #[test]
    fn op_fingerprint_generic_starts_with_gen_tag() {
        let fp = SmartCommitmentSDK::op_fingerprint(&make_generic_op());
        assert!(fp.starts_with(b"GEN"));
    }

    #[test]
    fn op_fingerprint_transfer_starts_with_xfer_tag() {
        let fp = SmartCommitmentSDK::op_fingerprint(&make_transfer_op());
        assert!(fp.starts_with(b"XFER"));
    }

    #[test]
    fn op_fingerprint_mint_starts_with_mint_tag() {
        let fp = SmartCommitmentSDK::op_fingerprint(&make_mint_op());
        assert!(fp.starts_with(b"MINT"));
    }

    #[test]
    fn op_fingerprint_burn_starts_with_burn_tag() {
        let fp = SmartCommitmentSDK::op_fingerprint(&make_burn_op());
        assert!(fp.starts_with(b"BURN"));
    }

    #[test]
    fn op_fingerprint_receive_starts_with_rcv_tag() {
        let fp = SmartCommitmentSDK::op_fingerprint(&make_receive_op());
        assert!(fp.starts_with(b"RCV"));
    }

    #[test]
    fn op_fingerprint_genesis_uses_fallback_tag() {
        let fp = SmartCommitmentSDK::op_fingerprint(&Operation::Genesis);
        assert!(fp.starts_with(b"OP?"));
    }

    #[test]
    fn op_fingerprint_is_deterministic() {
        let op = make_transfer_op();
        let fp1 = SmartCommitmentSDK::op_fingerprint(&op);
        let fp2 = SmartCommitmentSDK::op_fingerprint(&op);
        assert_eq!(fp1, fp2);
    }

    #[test]
    fn op_fingerprint_different_ops_differ() {
        let fp_gen = SmartCommitmentSDK::op_fingerprint(&make_generic_op());
        let fp_xfer = SmartCommitmentSDK::op_fingerprint(&make_transfer_op());
        assert_ne!(fp_gen, fp_xfer);
    }

    #[test]
    fn op_fingerprint_transfer_bilateral_vs_unilateral_differ() {
        let bilateral = make_transfer_op();
        let mut unilateral = make_transfer_op();
        if let Operation::Transfer { ref mut mode, .. } = unilateral {
            *mode = TransactionMode::Unilateral;
        }
        let fp_b = SmartCommitmentSDK::op_fingerprint(&bilateral);
        let fp_u = SmartCommitmentSDK::op_fingerprint(&unilateral);
        assert_ne!(fp_b, fp_u);
    }

    #[test]
    fn op_fingerprint_receive_with_and_without_sender_state_hash() {
        let with_hash = make_receive_op();
        let mut without_hash = make_receive_op();
        if let Operation::Receive {
            ref mut sender_state_hash,
            ..
        } = without_hash
        {
            *sender_state_hash = None;
        }
        let fp_with = SmartCommitmentSDK::op_fingerprint(&with_hash);
        let fp_without = SmartCommitmentSDK::op_fingerprint(&without_hash);
        assert_ne!(fp_with, fp_without);
    }

    #[test]
    fn op_fingerprint_generic_includes_data() {
        let op1 = make_generic_op();
        let mut op2 = make_generic_op();
        if let Operation::Generic { ref mut data, .. } = op2 {
            *data = b"different_data".to_vec();
        }
        let fp1 = SmartCommitmentSDK::op_fingerprint(&op1);
        let fp2 = SmartCommitmentSDK::op_fingerprint(&op2);
        assert_ne!(fp1, fp2);
    }

    // ---- SdkCommitmentCondition ----

    #[test]
    fn sdk_commitment_condition_equality() {
        let c1 = SdkCommitmentCondition::ConditionalOracle {
            condition: "temp > 30".to_string(),
            oracle_id: "weather".to_string(),
        };
        let c2 = SdkCommitmentCondition::ConditionalOracle {
            condition: "temp > 30".to_string(),
            oracle_id: "weather".to_string(),
        };
        assert_eq!(c1, c2);
    }

    #[test]
    fn sdk_commitment_condition_inequality_different_oracle() {
        let c1 = SdkCommitmentCondition::ConditionalOracle {
            condition: "temp > 30".to_string(),
            oracle_id: "weather".to_string(),
        };
        let c2 = SdkCommitmentCondition::ConditionalOracle {
            condition: "temp > 30".to_string(),
            oracle_id: "price".to_string(),
        };
        assert_ne!(c1, c2);
    }

    // ---- SmartCommitmentSdk struct ----

    #[test]
    fn smart_commitment_sdk_struct_fields() {
        let c = SmartCommitmentSdk {
            recipient: "alice".to_string(),
            amount: 100,
            token_id: "ROOT".to_string(),
            condition: SdkCommitmentCondition::ConditionalOracle {
                condition: "x > 5".to_string(),
                oracle_id: "oracle1".to_string(),
            },
            commitment_hash: vec![1, 2, 3],
            encrypted_payload: None,
            step_index: 42,
        };
        assert_eq!(c.recipient, "alice");
        assert_eq!(c.amount, 100);
        assert_eq!(c.step_index, 42);
        assert!(c.encrypted_payload.is_none());
    }

    // ---- SmartCommitmentSdk clone ----

    #[test]
    fn smart_commitment_sdk_clone() {
        let c = SmartCommitmentSdk {
            recipient: "bob".to_string(),
            amount: 500,
            token_id: "ROOT".to_string(),
            condition: SdkCommitmentCondition::ConditionalOracle {
                condition: "price > 100".to_string(),
                oracle_id: "oracle_price".to_string(),
            },
            commitment_hash: vec![10, 20, 30],
            encrypted_payload: Some(vec![0xAA, 0xBB]),
            step_index: 7,
        };
        let cloned = c.clone();
        assert_eq!(cloned.recipient, "bob");
        assert_eq!(cloned.amount, 500);
        assert_eq!(cloned.encrypted_payload, Some(vec![0xAA, 0xBB]));
        assert_eq!(cloned.commitment_hash, vec![10, 20, 30]);
    }

    // ---- execute_commitment ----

    fn make_sdk() -> SmartCommitmentSDK {
        let core = Arc::new(super::CoreSDK::new().unwrap());
        SmartCommitmentSDK::new(core)
    }

    #[test]
    fn execute_commitment_returns_transfer_op() {
        let sdk = make_sdk();
        let commitment = SmartCommitmentSdk {
            recipient: "alice".to_string(),
            amount: 250,
            token_id: "ROOT".to_string(),
            condition: SdkCommitmentCondition::ConditionalOracle {
                condition: "true".to_string(),
                oracle_id: "o".to_string(),
            },
            commitment_hash: vec![],
            encrypted_payload: None,
            step_index: 0,
        };
        let op = sdk.execute_commitment(&commitment).unwrap();
        match op {
            Operation::Transfer {
                amount,
                recipient,
                message,
                mode,
                ..
            } => {
                assert_eq!(amount.value(), 250);
                assert_eq!(recipient, b"alice");
                assert_eq!(message, "Smart commitment transfer");
                assert_eq!(mode, TransactionMode::Bilateral);
            }
            _ => panic!("Expected Transfer operation"),
        }
    }

    #[test]
    fn execute_commitment_zero_amount() {
        let sdk = make_sdk();
        let commitment = SmartCommitmentSdk {
            recipient: "bob".to_string(),
            amount: 0,
            token_id: "TOKEN".to_string(),
            condition: SdkCommitmentCondition::ConditionalOracle {
                condition: "".to_string(),
                oracle_id: "".to_string(),
            },
            commitment_hash: vec![],
            encrypted_payload: None,
            step_index: 0,
        };
        let op = sdk.execute_commitment(&commitment).unwrap();
        match op {
            Operation::Transfer {
                amount, token_id, ..
            } => {
                assert_eq!(amount.value(), 0);
                assert_eq!(token_id, b"TOKEN");
            }
            _ => panic!("Expected Transfer"),
        }
    }

    // ---- create_commitment_operation ----

    #[test]
    fn create_commitment_operation_returns_create_variant() {
        let sdk = make_sdk();
        let op = sdk.create_commitment_operation().unwrap();
        match op {
            Operation::Create { message, .. } => {
                assert_eq!(message, "Create smart commitment");
            }
            _ => panic!("Expected Create operation"),
        }
    }

    // ---- update_commitment_operation ----

    #[test]
    fn update_commitment_operation_returns_update_variant() {
        let sdk = make_sdk();
        let op = sdk.update_commitment_operation().unwrap();
        match op {
            Operation::Update { message, .. } => {
                assert_eq!(message, "Update smart commitment");
            }
            _ => panic!("Expected Update operation"),
        }
    }

    // ---- record_execution ----

    #[test]
    fn record_execution_stores_entry() {
        let core = Arc::new(super::CoreSDK::new().unwrap());
        let mut sdk = SmartCommitmentSDK::new(core);
        assert!(sdk.executed_commitments.is_empty());

        let state = State::default();
        let op = Operation::Generic {
            operation_type: b"test".to_vec(),
            data: vec![],
            message: "test".to_string(),
            signature: vec![],
        };
        let sc = dsm::commitments::smart_commitment::SmartCommitment::new(
            "test_commit",
            &state,
            DsmCommitmentCondition::default(),
            op,
        )
        .unwrap();
        sdk.record_execution(&sc);
        assert!(!sdk.executed_commitments.is_empty());
    }

    // ---- op_fingerprint additional edge cases ----

    #[test]
    fn op_fingerprint_transfer_different_amounts_differ() {
        let op1 = make_transfer_op();
        let mut op2 = make_transfer_op();
        if let Operation::Transfer { ref mut amount, .. } = op2 {
            *amount = Balance::from_state(9999, [0u8; 32]);
        }
        let fp1 = SmartCommitmentSDK::op_fingerprint(&op1);
        let fp2 = SmartCommitmentSDK::op_fingerprint(&op2);
        assert_ne!(fp1, fp2);
    }

    #[test]
    fn op_fingerprint_transfer_different_nonces_differ() {
        let op1 = make_transfer_op();
        let mut op2 = make_transfer_op();
        if let Operation::Transfer { ref mut nonce, .. } = op2 {
            *nonce = b"different_nonce".to_vec();
        }
        let fp1 = SmartCommitmentSDK::op_fingerprint(&op1);
        let fp2 = SmartCommitmentSDK::op_fingerprint(&op2);
        assert_ne!(fp1, fp2);
    }

    #[test]
    fn op_fingerprint_mint_different_amounts_differ() {
        let op1 = make_mint_op();
        let mut op2 = make_mint_op();
        if let Operation::Mint { ref mut amount, .. } = op2 {
            *amount = Balance::from_state(9999, [0u8; 32]);
        }
        let fp1 = SmartCommitmentSDK::op_fingerprint(&op1);
        let fp2 = SmartCommitmentSDK::op_fingerprint(&op2);
        assert_ne!(fp1, fp2);
    }

    #[test]
    fn op_fingerprint_burn_different_messages_differ() {
        let op1 = make_burn_op();
        let mut op2 = make_burn_op();
        if let Operation::Burn {
            ref mut message, ..
        } = op2
        {
            *message = "other burn message".to_string();
        }
        let fp1 = SmartCommitmentSDK::op_fingerprint(&op1);
        let fp2 = SmartCommitmentSDK::op_fingerprint(&op2);
        assert_ne!(fp1, fp2);
    }

    #[test]
    fn op_fingerprint_receive_no_sender_hash_writes_zero_length() {
        let mut op = make_receive_op();
        if let Operation::Receive {
            ref mut sender_state_hash,
            ..
        } = op
        {
            *sender_state_hash = None;
        }
        let fp = SmartCommitmentSDK::op_fingerprint(&op);
        assert!(fp.starts_with(b"RCV"));
        assert!(!fp.is_empty());
    }

    // ---- push_str / push_bytes with large data ----

    #[test]
    fn push_str_large_string() {
        let mut buf = Vec::new();
        let large = "A".repeat(10_000);
        SmartCommitmentSDK::push_str(&mut buf, &large);
        let len = u32::from_le_bytes(buf[..4].try_into().unwrap()) as usize;
        assert_eq!(len, 10_000);
        assert_eq!(buf.len(), 4 + 10_000);
    }

    #[test]
    fn push_bytes_large_data() {
        let mut buf = Vec::new();
        let large = vec![0xBBu8; 5_000];
        SmartCommitmentSDK::push_bytes(&mut buf, &large);
        let len = u32::from_le_bytes(buf[..4].try_into().unwrap()) as usize;
        assert_eq!(len, 5_000);
        assert_eq!(&buf[4..], large.as_slice());
    }

    // ---- SdkCommitmentCondition clone ----

    #[test]
    fn sdk_commitment_condition_clone() {
        let c = SdkCommitmentCondition::ConditionalOracle {
            condition: "temp > 0".to_string(),
            oracle_id: "weather_oracle".to_string(),
        };
        let cloned = c.clone();
        assert_eq!(c, cloned);
    }
}
