//! DLV Pre-Commitment SDK Module (STRICT, fail-closed)
//! - Deterministic hashing (BLAKE3) with canonical ordering
//! - Explicit fork→vault bindings (no guesswork, no stubs)
//! - No alternate paths: required inputs enforced, proofs mandatory

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;
use blake3::Hasher;
use prost::Message;

use dsm::{
    commitments::precommit::{PreCommitment, PreCommitmentFork, SecurityParameters},
    commitments::{create_external_commitment, external_evidence_hash, external_source_id},
    crypto::sphincs,
    types::{error::DsmError, state_types::State},
    vault::{DLVManager, FulfillmentMechanism, FulfillmentProof, VaultState},
};
use crate::sdk::receipts::{compute_protocol_transition_commitment, encode_protocol_transition_payload};

/// High-level SDK for DLV-enhanced pre-commitments
pub struct DlvPreCommitmentSdk {
    _core_sdk: Arc<crate::sdk::core_sdk::CoreSDK>,
    dlv_manager: Arc<DLVManager>,
}

/// Configuration for creating a DLV-enhanced pre-commitment
#[derive(Debug, Clone)]
pub struct DlvPreCommitmentConfig {
    pub base_config: PreCommitmentConfig,
    /// Fork id → fork configuration
    pub dlv_forks: HashMap<String, DlvForkConfig>,
    /// External systems (context strings) to publish commitments to
    pub external_publications: Vec<String>,
}

/// Configuration for a pre-commitment
#[derive(Debug, Clone)]
pub struct PreCommitmentConfig {
    pub fixed_params: HashMap<String, Vec<u8>>,
    pub variable_params: Vec<String>,
    pub security_params: SecurityParameters,
}

/// Configuration for a DLV fork
#[derive(Debug, Clone)]
pub struct DlvForkConfig {
    /// Condition for unlocking this vault (must be bound into fork hash)
    pub unlock_condition: FulfillmentMechanism,
    /// Parameters required for this fork; MUST contain:
    /// - "vault_content" -> bytes
    /// - "mime" -> MIME string bytes
    ///
    /// Optional:
    /// - "recipient_public_key" -> bytes
    pub required_params: HashMap<String, Vec<u8>>,
}

/// Result of creating / executing a DLV pre-commitment
#[derive(Debug, Clone)]
pub struct DlvPreCommitmentResult {
    pub pre_commitment: PreCommitment,
    /// The DLVs created for forks (in create); for execute, includes the selected vault
    pub dlv_ids: Vec<String>,
    /// External commitment hashes by context
    pub external_hashes: HashMap<String, [u8; 32]>,
    /// Selected fork id (only for execute)
    pub selected_fork: Option<String>,
    /// Fork id → vault id (binding established at creation time)
    pub fork_vault_bindings: BTreeMap<String, String>,
}

impl DlvPreCommitmentSdk {
    pub fn new(core_sdk: Arc<crate::sdk::core_sdk::CoreSDK>, dlv_manager: Arc<DLVManager>) -> Self {
        Self {
            _core_sdk: core_sdk,
            dlv_manager,
        }
    }

    /// Create a DLV-enhanced pre-commitment with multiple forks (STRICT)
    pub async fn create_dlv_pre_commitment(
        &self,
        config: DlvPreCommitmentConfig,
        creator_kyber_pk: &[u8],         // Kyber PK for vault content encryption
        reference_state: &State,
    ) -> Result<DlvPreCommitmentResult, DsmError> {
        let creator_signing_keypair = crate::sdk::signing_authority::derive_current_signing_keypair()?;

        // Validate base config early (no alternate paths)
        Self::ensure_non_empty("fixed_params", !config.base_config.fixed_params.is_empty())?;
        self.ensure_variable_params_valid(&config.base_config)?;

        // Build forks: create a DLV per fork and compute canonical fork hashes
        let mut dlv_ids = Vec::new();
        let mut fork_configs: Vec<PreCommitmentFork> = Vec::new();
        let mut fork_vault_bindings: BTreeMap<String, String> = BTreeMap::new();

        for (fork_id, dlv_cfg) in Self::sorted_forks(&config.dlv_forks) {
            // Enforce required parameters
            let content = Self::required_param(&dlv_cfg.required_params, "vault_content")?;
            let mime = Self::required_param(&dlv_cfg.required_params, "mime")?;
            let intended_recipient = dlv_cfg.required_params.get("recipient_public_key").cloned();
            let encryption_key = intended_recipient.as_deref().unwrap_or(creator_kyber_pk);

            // Create vault strictly with provided inputs
            let (vault_id, _op) = self
                .dlv_manager
                .create_vault(
                    (
                        creator_signing_keypair.public_key(),
                        creator_signing_keypair.secret_key(),
                    ),
                    dlv_cfg.unlock_condition.clone(),
                    content,
                    std::str::from_utf8(mime)
                        .map_err(|_| DsmError::invalid_operation("mime must be valid UTF-8"))?,
                    intended_recipient.clone(),
                    encryption_key,
                    reference_state,
                    None,
                    None,
                )
                .await?;

            fork_vault_bindings.insert(fork_id.clone(), vault_id.clone());
            dlv_ids.push(vault_id.clone());

            // Canonicalize required_params for hash binding (BTreeMap → sorted)
            let fixed_for_fork = Self::btree_from(&dlv_cfg.required_params);

            // Compute deterministic fork hash
            let fork_hash = Self::compute_fork_hash(
                &fork_id,
                &vault_id,
                &dlv_cfg.unlock_condition,
                &fixed_for_fork,
                reference_state,
            )?;

            // Assemble fork (no empty hash, no implicit params)
            let fork = PreCommitmentFork {
                fork_id: fork_id.clone(),
                hash: fork_hash,
                fixed_params: fixed_for_fork.into_iter().collect(), // back to HashMap<String, Vec<u8>>
                variable_params: HashSet::new(),
                positions: vec![], // keep as-is per your core type
                signatures: HashMap::new(),
                is_selected: false,
                invalidation_proof: None,
            };
            fork_configs.push(fork);
        }

        // Make the pre-commitment with forks
        let pre_commitment = self
            .create_pre_commitment_with_forks(
                &config.base_config,
                fork_configs,
                reference_state,
            )
            .await?;

        // External commitments (context-bound)
        let mut external_hashes = HashMap::new();
        for ctx in &config.external_publications {
            let source_id = external_source_id(ctx);
            let evidence_hash = external_evidence_hash(&[]);
            let h = create_external_commitment(&pre_commitment.hash, &source_id, &evidence_hash);
            external_hashes.insert(ctx.clone(), h);
        }

        Ok(DlvPreCommitmentResult {
            pre_commitment,
            dlv_ids,
            external_hashes,
            selected_fork: None,
            fork_vault_bindings,
        })
    }

    /// Execute a DLV pre-commitment by selecting a fork (STRICT)
    /// - Requires `fork_vault_bindings` returned at creation.
    /// - Requires either:
    ///   a) `execution_proof: FulfillmentProof` OR
    ///   b) raw proof bytes in `execution_params`:
    ///   "proof_state_transition", "proof_merkle"
    #[allow(clippy::too_many_arguments)]
    pub async fn execute_dlv_pre_commitment(
        &self,
        pre_commitment: &mut PreCommitment,
        selected_fork_id: &str,
        execution_params: &HashMap<String, Vec<u8>>,
        requester_kyber_pk: &[u8],        // Kyber PK checked against intended_recipient
        executor_kyber_sk: &[u8],         // Kyber SK for vault content decapsulation
        reference_state: &State,
        fork_vault_bindings: &BTreeMap<String, String>,
        execution_proof: Option<FulfillmentProof>,
    ) -> Result<DlvPreCommitmentResult, DsmError> {
        let executor_signing_public_key = crate::sdk::signing_authority::current_public_key()?;

        // Validate integrity before execution
        pre_commitment.validate_pre_commitment_integrity()?;

        // Locate fork
        let (idx, _) = pre_commitment
            .forks
            .iter()
            .enumerate()
            .find(|(_, f)| f.fork_id == selected_fork_id)
            .ok_or_else(|| {
                DsmError::invalid_operation("Selected fork not found in pre-commitment")
            })?;

        // Select fork strictly
        pre_commitment.selected_fork_id = Some(selected_fork_id.to_string());
        pre_commitment.forks[idx].is_selected = true;

        // Resolve vault id from binding (no guesses)
        let vault_id = fork_vault_bindings
            .get(selected_fork_id)
            .ok_or_else(|| {
                DsmError::invalid_operation("Missing fork→vault binding for selected fork")
            })?
            .clone();

        // Build or validate proof (no placeholders)
        let proof = if let Some(p) = execution_proof {
            p
        } else {
            self.build_fulfillment_proof(selected_fork_id, execution_params)?
        };

        // Attempt unlock, then claim
        let (unlocked, _unlock_op) = self
            .dlv_manager
            .try_unlock_vault(
                &vault_id,
                proof,
                requester_kyber_pk,
                &executor_signing_public_key,
                reference_state,
            )
            .await?;
        if !unlocked {
            return Err(DsmError::invalid_operation(
                "DLV unlock failed for selected fork",
            ));
        }

        let (_content, _claim_op) = self
            .dlv_manager
            .claim_vault_content(
                &vault_id,
                executor_kyber_sk,
                &executor_signing_public_key,
                reference_state,
            )
            .await?;

        Ok(DlvPreCommitmentResult {
            pre_commitment: pre_commitment.clone(),
            dlv_ids: vec![vault_id],
            external_hashes: HashMap::new(),
            selected_fork: Some(selected_fork_id.to_string()),
            fork_vault_bindings: fork_vault_bindings.clone(),
        })
    }

    /// Create a pre-commitment with forks (signing with SPHINCS)
    async fn create_pre_commitment_with_forks(
        &self,
        cfg: &PreCommitmentConfig,
        mut forks: Vec<PreCommitmentFork>,
        reference_state: &State,
    ) -> Result<PreCommitment, DsmError> {
        // Compute deterministic pre-commit hash
        //   H( state_hash || fixed_params || variable_params || forks(fork_id,hash) )
        let pre_hash = self.generate_pre_commitment_hash(cfg, &forks, reference_state)?;

        // Sign with creator SK
        let mut signatures = HashMap::new();
        let sig = sphincs::sphincs_sign(&crate::sdk::signing_authority::current_secret_key()?, &pre_hash)?;
        signatures.insert("creator".to_string(), sig);

        let mut pc = PreCommitment::new_with_signatures(pre_hash, signatures);
        pc.forks = {
            // Optionally normalize ordering by fork_id for reproducibility
            forks.sort_by(|a, b| a.fork_id.cmp(&b.fork_id));
            forks
        };
        pc.selected_fork_id = None;
        pc.forward_commitment = None;
        pc.fixed_parameters = cfg.fixed_params.clone();
        pc.variable_parameters = cfg.variable_params.clone();
        pc.security_params = cfg.security_params.clone();
        Ok(pc)
    }

    /// Deterministic pre-commitment hash
    fn generate_pre_commitment_hash(
        &self,
        cfg: &PreCommitmentConfig,
        forks: &[PreCommitmentFork],
        reference_state: &State,
    ) -> Result<[u8; 32], DsmError> {
        let mut h = Hasher::new();

        // Reference state commitment
        let state_hash = reference_state.hash()?;
        h.update(&state_hash);

        // Fixed params (sorted by key)
        for (k, v) in Self::btree_from(&cfg.fixed_params).into_iter() {
            h.update(k.as_bytes());
            h.update(&v);
        }

        // Variable params (sorted for determinism)
        let mut vars = cfg.variable_params.clone();
        vars.sort();
        for p in vars {
            h.update(p.as_bytes());
        }

        // Forks (sorted by fork_id)
        let mut forks_sorted = forks.to_vec();
        forks_sorted.sort_by(|a, b| a.fork_id.cmp(&b.fork_id));
        for f in forks_sorted {
            h.update(f.fork_id.as_bytes());
            h.update(&f.hash);
        }

        Ok(*h.finalize().as_bytes())
    }

    /// Build a fulfillment proof from supplied execution_params (STRICT)
    /// Required keys: "proof_state_transition", "proof_merkle"
    fn build_fulfillment_proof(
        &self,
        fork_id: &str,
        execution_params: &HashMap<String, Vec<u8>>,
    ) -> Result<FulfillmentProof, DsmError> {
        let st = Self::required_param(execution_params, "proof_state_transition")?;
        let mp = Self::required_param(execution_params, "proof_merkle")?;

        let stitched_receipt_sigma = match execution_params.get("stitched_receipt_sigma") {
            Some(raw) if raw.len() == 32 => {
                let mut sigma = [0u8; 32];
                sigma.copy_from_slice(raw);
                Some(sigma)
            }
            Some(raw) => {
                return Err(DsmError::invalid_operation(format!(
                    "stitched_receipt_sigma must be 32 bytes (got {})",
                    raw.len()
                )));
            }
            None => {
                let payload = encode_protocol_transition_payload(
                    b"dlv.precommit.execute",
                    &[fork_id.as_bytes(), st, mp],
                );
                Some(compute_protocol_transition_commitment(&payload))
            }
        };

        Ok(FulfillmentProof::PaymentProof {
            state_transition: st.to_vec(),
            merkle_proof: mp.to_vec(),
            stitched_receipt_sigma,
        })
    }

    /// Deterministic fork hash: H(fork_id || vault_id || unlock_condition_fpr || fixed_params)
    fn compute_fork_hash(
        fork_id: &str,
        vault_id: &str,
        cond: &FulfillmentMechanism,
        fixed_params_sorted: &BTreeMap<String, Vec<u8>>,
        reference_state: &State,
    ) -> Result<[u8; 32], DsmError> {
        let mut h = Hasher::new();
        h.update(fork_id.as_bytes());
        h.update(vault_id.as_bytes());
        // Bind condition via its deterministic protobuf serialization
        let fm_proto: dsm::types::proto::FulfillmentMechanism = cond.into();
        let mut cond_bytes = Vec::with_capacity(fm_proto.encoded_len());
        fm_proto.encode(&mut cond_bytes).map_err(|e| {
            DsmError::internal(
                format!("Failed to encode FulfillmentMechanism: {e}"),
                None::<std::io::Error>,
            )
        })?;
        h.update(&cond_bytes);

        // Bind reference state (context)
        let s = reference_state.hash()?;
        h.update(&s);

        // Bind fixed_params (sorted by key)
        for (k, v) in fixed_params_sorted.iter() {
            h.update(k.as_bytes());
            h.update(v);
        }
        Ok(*h.finalize().as_bytes())
    }

    /// Verify the pre-commitment strictly (hash + SPHINCS sigs)
    pub fn verify_dlv_pre_commitment(
        &self,
        pre_commitment: &PreCommitment,
        reference_state: &State,
    ) -> Result<bool, DsmError> {
        // Recompute expected hash
        let cfg = PreCommitmentConfig {
            fixed_params: pre_commitment.fixed_parameters.clone(),
            variable_params: pre_commitment.variable_parameters.clone(),
            security_params: pre_commitment.security_params.clone(),
        };
        let expected =
            self.generate_pre_commitment_hash(&cfg, &pre_commitment.forks, reference_state)?;
        if expected != pre_commitment.hash {
            return Ok(false);
        }

        // Verify all attached signatures under the reference state's device PK
        let pk = &reference_state.device_info.public_key;
        for sig in pre_commitment.signatures.values() {
            let ok = sphincs::sphincs_verify(pk, &pre_commitment.hash, sig)?;
            if !ok {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Batch query DLV status
    pub async fn get_dlv_status(
        &self,
        dlv_ids: &[String],
    ) -> Result<HashMap<String, VaultState>, DsmError> {
        let mut out = HashMap::new();
        for id in dlv_ids {
            let v = self.dlv_manager.get_vault(id).await?;
            let guard = v.lock().await;
            out.insert(id.clone(), guard.state.clone());
        }
        Ok(out)
    }

    /* ---------- helpers (STRICT) ---------- */

    fn ensure_non_empty(label: &str, ok: bool) -> Result<(), DsmError> {
        if ok {
            Ok(())
        } else {
            Err(DsmError::invalid_operation(format!(
                "{label} must not be empty"
            )))
        }
    }

    fn required_param<'a>(
        map: &'a HashMap<String, Vec<u8>>,
        key: &str,
    ) -> Result<&'a [u8], DsmError> {
        map.get(key)
            .map(|v| v.as_slice())
            .ok_or_else(|| DsmError::invalid_operation(format!("missing required param '{key}'")))
    }

    fn btree_from(map: &HashMap<String, Vec<u8>>) -> BTreeMap<String, Vec<u8>> {
        map.iter().map(|(k, v)| (k.clone(), v.clone())).collect()
    }

    fn sorted_forks(forks: &HashMap<String, DlvForkConfig>) -> Vec<(String, &DlvForkConfig)> {
        let mut v: Vec<(String, &DlvForkConfig)> =
            forks.iter().map(|(k, v)| (k.clone(), v)).collect();
        v.sort_by(|a, b| a.0.cmp(&b.0));
        v
    }

    fn ensure_variable_params_valid(&self, cfg: &PreCommitmentConfig) -> Result<(), DsmError> {
        // Deterministic ordering is enforced later; here we just fail on duplicates.
        let mut set = HashSet::new();
        for p in &cfg.variable_params {
            if !set.insert(p) {
                return Err(DsmError::invalid_operation(
                    "duplicate variable parameter name",
                ));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    // ---- ensure_non_empty ----

    #[test]
    fn ensure_non_empty_ok() {
        assert!(DlvPreCommitmentSdk::ensure_non_empty("field", true).is_ok());
    }

    #[test]
    fn ensure_non_empty_err() {
        let err = DlvPreCommitmentSdk::ensure_non_empty("field", false).unwrap_err();
        assert!(format!("{err:?}").contains("must not be empty"));
    }

    #[test]
    fn ensure_non_empty_label_in_error() {
        let err = DlvPreCommitmentSdk::ensure_non_empty("my_label", false).unwrap_err();
        assert!(format!("{err:?}").contains("my_label"));
    }

    // ---- required_param ----

    #[test]
    fn required_param_present() {
        let mut map = HashMap::new();
        map.insert("key1".to_string(), vec![1, 2, 3]);
        let result = DlvPreCommitmentSdk::required_param(&map, "key1").unwrap();
        assert_eq!(result, &[1, 2, 3]);
    }

    #[test]
    fn required_param_missing() {
        let map: HashMap<String, Vec<u8>> = HashMap::new();
        let err = DlvPreCommitmentSdk::required_param(&map, "missing_key").unwrap_err();
        assert!(format!("{err:?}").contains("missing required param"));
        assert!(format!("{err:?}").contains("missing_key"));
    }

    #[test]
    fn required_param_empty_value_is_ok() {
        let mut map = HashMap::new();
        map.insert("key".to_string(), Vec::new());
        let result = DlvPreCommitmentSdk::required_param(&map, "key").unwrap();
        assert!(result.is_empty());
    }

    // ---- btree_from ----

    #[test]
    fn btree_from_preserves_entries() {
        let mut map = HashMap::new();
        map.insert("b".to_string(), vec![2]);
        map.insert("a".to_string(), vec![1]);
        map.insert("c".to_string(), vec![3]);

        let btree = DlvPreCommitmentSdk::btree_from(&map);
        assert_eq!(btree.len(), 3);
        assert_eq!(btree["a"], vec![1]);
        assert_eq!(btree["b"], vec![2]);
        assert_eq!(btree["c"], vec![3]);
    }

    #[test]
    fn btree_from_sorted_iteration_order() {
        let mut map = HashMap::new();
        map.insert("z".to_string(), vec![26]);
        map.insert("a".to_string(), vec![1]);
        map.insert("m".to_string(), vec![13]);

        let btree = DlvPreCommitmentSdk::btree_from(&map);
        let keys: Vec<&String> = btree.keys().collect();
        assert_eq!(keys, vec!["a", "m", "z"]);
    }

    #[test]
    fn btree_from_empty() {
        let map: HashMap<String, Vec<u8>> = HashMap::new();
        let btree = DlvPreCommitmentSdk::btree_from(&map);
        assert!(btree.is_empty());
    }

    // ---- sorted_forks ----

    #[test]
    fn sorted_forks_returns_sorted_by_key() {
        let mut forks = HashMap::new();
        forks.insert(
            "fork_c".to_string(),
            DlvForkConfig {
                unlock_condition: FulfillmentMechanism::Payment {
                    amount: 100,
                    token_id: "ROOT".to_string(),
                    recipient: "r".to_string(),
                    verification_state: vec![],
                },
                required_params: HashMap::new(),
            },
        );
        forks.insert(
            "fork_a".to_string(),
            DlvForkConfig {
                unlock_condition: FulfillmentMechanism::Payment {
                    amount: 200,
                    token_id: "ROOT".to_string(),
                    recipient: "r".to_string(),
                    verification_state: vec![],
                },
                required_params: HashMap::new(),
            },
        );
        forks.insert(
            "fork_b".to_string(),
            DlvForkConfig {
                unlock_condition: FulfillmentMechanism::Payment {
                    amount: 300,
                    token_id: "ROOT".to_string(),
                    recipient: "r".to_string(),
                    verification_state: vec![],
                },
                required_params: HashMap::new(),
            },
        );

        let sorted = DlvPreCommitmentSdk::sorted_forks(&forks);
        let keys: Vec<&str> = sorted.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(keys, vec!["fork_a", "fork_b", "fork_c"]);
    }

    #[test]
    fn sorted_forks_empty() {
        let forks: HashMap<String, DlvForkConfig> = HashMap::new();
        let sorted = DlvPreCommitmentSdk::sorted_forks(&forks);
        assert!(sorted.is_empty());
    }

    #[test]
    fn sorted_forks_single_entry() {
        let mut forks = HashMap::new();
        forks.insert(
            "only".to_string(),
            DlvForkConfig {
                unlock_condition: FulfillmentMechanism::CryptoCondition {
                    condition_hash: vec![0u8; 32],
                    public_params: vec![],
                },
                required_params: HashMap::new(),
            },
        );
        let sorted = DlvPreCommitmentSdk::sorted_forks(&forks);
        assert_eq!(sorted.len(), 1);
        assert_eq!(sorted[0].0, "only");
    }

    // ---- DlvPreCommitmentConfig ----

    #[test]
    fn dlv_pre_commitment_config_struct() {
        let cfg = DlvPreCommitmentConfig {
            base_config: PreCommitmentConfig {
                fixed_params: {
                    let mut m = HashMap::new();
                    m.insert("key".to_string(), vec![1]);
                    m
                },
                variable_params: vec!["var1".to_string()],
                security_params: SecurityParameters::default(),
            },
            dlv_forks: HashMap::new(),
            external_publications: vec!["bitcoin".to_string()],
        };
        assert_eq!(cfg.base_config.fixed_params.len(), 1);
        assert_eq!(cfg.external_publications, vec!["bitcoin"]);
    }

    // ---- DlvPreCommitmentResult ----

    #[test]
    fn dlv_pre_commitment_result_defaults() {
        let result = DlvPreCommitmentResult {
            pre_commitment: PreCommitment::default(),
            dlv_ids: vec!["v1".to_string(), "v2".to_string()],
            external_hashes: HashMap::new(),
            selected_fork: None,
            fork_vault_bindings: BTreeMap::new(),
        };
        assert_eq!(result.dlv_ids.len(), 2);
        assert!(result.selected_fork.is_none());
        assert!(result.fork_vault_bindings.is_empty());
    }

    // ---- DlvForkConfig ----

    #[test]
    fn dlv_fork_config_with_required_params() {
        let mut params = HashMap::new();
        params.insert("vault_content".to_string(), b"secret".to_vec());
        params.insert("mime".to_string(), b"application/octet-stream".to_vec());
        params.insert("recipient_public_key".to_string(), vec![0xAA; 32]);

        let cfg = DlvForkConfig {
            unlock_condition: FulfillmentMechanism::Payment {
                amount: 1000,
                token_id: "ROOT".to_string(),
                recipient: "alice".to_string(),
                verification_state: vec![],
            },
            required_params: params,
        };

        assert_eq!(cfg.required_params.len(), 3);
        assert!(cfg.required_params.contains_key("vault_content"));
        assert!(cfg.required_params.contains_key("mime"));
    }

    // ---- build_fulfillment_proof ----

    fn make_sdk_for_proof_test() -> DlvPreCommitmentSdk {
        let core = Arc::new(crate::sdk::core_sdk::CoreSDK::new().unwrap());
        let dlv = Arc::new(DLVManager::new());
        DlvPreCommitmentSdk::new(core, dlv)
    }

    #[test]
    fn build_fulfillment_proof_with_both_required_params() {
        let sdk = make_sdk_for_proof_test();
        let mut params = HashMap::new();
        params.insert("proof_state_transition".to_string(), vec![1, 2, 3]);
        params.insert("proof_merkle".to_string(), vec![4, 5, 6]);

        let proof = sdk.build_fulfillment_proof("fork_1", &params).unwrap();
        match proof {
            FulfillmentProof::PaymentProof {
                state_transition,
                merkle_proof,
                stitched_receipt_sigma,
            } => {
                assert_eq!(state_transition, vec![1, 2, 3]);
                assert_eq!(merkle_proof, vec![4, 5, 6]);
                assert!(stitched_receipt_sigma.is_some());
            }
            _ => panic!("Expected PaymentProof variant"),
        }
    }

    #[test]
    fn build_fulfillment_proof_with_explicit_sigma() {
        let sdk = make_sdk_for_proof_test();
        let mut params = HashMap::new();
        params.insert("proof_state_transition".to_string(), vec![10]);
        params.insert("proof_merkle".to_string(), vec![20]);
        params.insert("stitched_receipt_sigma".to_string(), vec![0xAA; 32]);

        let proof = sdk.build_fulfillment_proof("fork_2", &params).unwrap();
        match proof {
            FulfillmentProof::PaymentProof {
                stitched_receipt_sigma,
                ..
            } => {
                assert_eq!(stitched_receipt_sigma.unwrap(), [0xAA; 32]);
            }
            _ => panic!("Expected PaymentProof"),
        }
    }

    #[test]
    fn build_fulfillment_proof_sigma_wrong_length() {
        let sdk = make_sdk_for_proof_test();
        let mut params = HashMap::new();
        params.insert("proof_state_transition".to_string(), vec![10]);
        params.insert("proof_merkle".to_string(), vec![20]);
        params.insert("stitched_receipt_sigma".to_string(), vec![0xBB; 16]);

        let err = sdk.build_fulfillment_proof("fork_3", &params).unwrap_err();
        assert!(format!("{err:?}").contains("32 bytes"));
    }

    #[test]
    fn build_fulfillment_proof_missing_state_transition() {
        let sdk = make_sdk_for_proof_test();
        let mut params = HashMap::new();
        params.insert("proof_merkle".to_string(), vec![1]);

        let err = sdk.build_fulfillment_proof("fork_4", &params).unwrap_err();
        assert!(format!("{err:?}").contains("proof_state_transition"));
    }

    #[test]
    fn build_fulfillment_proof_missing_merkle() {
        let sdk = make_sdk_for_proof_test();
        let mut params = HashMap::new();
        params.insert("proof_state_transition".to_string(), vec![1]);

        let err = sdk.build_fulfillment_proof("fork_5", &params).unwrap_err();
        assert!(format!("{err:?}").contains("proof_merkle"));
    }

    #[test]
    fn build_fulfillment_proof_auto_sigma_is_deterministic() {
        let sdk = make_sdk_for_proof_test();
        let mut params = HashMap::new();
        params.insert("proof_state_transition".to_string(), vec![1, 2]);
        params.insert("proof_merkle".to_string(), vec![3, 4]);

        let proof1 = sdk.build_fulfillment_proof("fork_x", &params).unwrap();
        let proof2 = sdk.build_fulfillment_proof("fork_x", &params).unwrap();

        let sigma1 = match proof1 {
            FulfillmentProof::PaymentProof {
                stitched_receipt_sigma,
                ..
            } => stitched_receipt_sigma,
            _ => panic!("expected PaymentProof"),
        };
        let sigma2 = match proof2 {
            FulfillmentProof::PaymentProof {
                stitched_receipt_sigma,
                ..
            } => stitched_receipt_sigma,
            _ => panic!("expected PaymentProof"),
        };
        assert_eq!(sigma1, sigma2);
    }

    #[test]
    fn build_fulfillment_proof_different_fork_ids_yield_different_sigma() {
        let sdk = make_sdk_for_proof_test();
        let mut params = HashMap::new();
        params.insert("proof_state_transition".to_string(), vec![1]);
        params.insert("proof_merkle".to_string(), vec![2]);

        let proof_a = sdk.build_fulfillment_proof("fork_A", &params).unwrap();
        let proof_b = sdk.build_fulfillment_proof("fork_B", &params).unwrap();

        let sigma_a = match proof_a {
            FulfillmentProof::PaymentProof {
                stitched_receipt_sigma,
                ..
            } => stitched_receipt_sigma.unwrap(),
            _ => panic!("expected PaymentProof"),
        };
        let sigma_b = match proof_b {
            FulfillmentProof::PaymentProof {
                stitched_receipt_sigma,
                ..
            } => stitched_receipt_sigma.unwrap(),
            _ => panic!("expected PaymentProof"),
        };
        assert_ne!(sigma_a, sigma_b);
    }

    // ---- ensure_variable_params_valid (via instance) ----

    #[test]
    fn ensure_variable_params_valid_no_duplicates() {
        let sdk = make_sdk_for_proof_test();
        let cfg = PreCommitmentConfig {
            fixed_params: HashMap::new(),
            variable_params: vec!["a".to_string(), "b".to_string(), "c".to_string()],
            security_params: SecurityParameters::default(),
        };
        assert!(sdk.ensure_variable_params_valid(&cfg).is_ok());
    }

    #[test]
    fn ensure_variable_params_valid_empty_list() {
        let sdk = make_sdk_for_proof_test();
        let cfg = PreCommitmentConfig {
            fixed_params: HashMap::new(),
            variable_params: Vec::new(),
            security_params: SecurityParameters::default(),
        };
        assert!(sdk.ensure_variable_params_valid(&cfg).is_ok());
    }

    #[test]
    fn ensure_variable_params_valid_detects_duplicates() {
        let sdk = make_sdk_for_proof_test();
        let cfg = PreCommitmentConfig {
            fixed_params: HashMap::new(),
            variable_params: vec!["x".to_string(), "y".to_string(), "x".to_string()],
            security_params: SecurityParameters::default(),
        };
        let err = sdk.ensure_variable_params_valid(&cfg).unwrap_err();
        assert!(format!("{err:?}").contains("duplicate"));
    }

    // ---- btree_from edge cases ----

    #[test]
    fn btree_from_single_element() {
        let mut map = HashMap::new();
        map.insert("only".to_string(), vec![42]);
        let btree = DlvPreCommitmentSdk::btree_from(&map);
        assert_eq!(btree.len(), 1);
        assert_eq!(btree["only"], vec![42]);
    }

    #[test]
    fn btree_from_large_values() {
        let mut map = HashMap::new();
        map.insert("big".to_string(), vec![0xFFu8; 1024]);
        let btree = DlvPreCommitmentSdk::btree_from(&map);
        assert_eq!(btree["big"].len(), 1024);
    }

    // ---- sorted_forks preserves values ----

    #[test]
    fn sorted_forks_preserves_unlock_conditions() {
        let mut forks = HashMap::new();
        forks.insert(
            "fork_b".to_string(),
            DlvForkConfig {
                unlock_condition: FulfillmentMechanism::Payment {
                    amount: 777,
                    token_id: "ROOT".to_string(),
                    recipient: "bob".to_string(),
                    verification_state: vec![],
                },
                required_params: {
                    let mut m = HashMap::new();
                    m.insert("vault_content".to_string(), b"data".to_vec());
                    m
                },
            },
        );
        forks.insert(
            "fork_a".to_string(),
            DlvForkConfig {
                unlock_condition: FulfillmentMechanism::CryptoCondition {
                    condition_hash: [0xAA; 32].to_vec(),
                    public_params: vec![1, 2, 3],
                },
                required_params: HashMap::new(),
            },
        );

        let sorted = DlvPreCommitmentSdk::sorted_forks(&forks);
        assert_eq!(sorted[0].0, "fork_a");
        assert_eq!(sorted[1].0, "fork_b");
        assert_eq!(sorted[1].1.required_params.len(), 1);
        match &sorted[0].1.unlock_condition {
            FulfillmentMechanism::CryptoCondition { condition_hash, .. } => {
                assert_eq!(*condition_hash, [0xAA; 32]);
            }
            _ => panic!("Expected CryptoCondition"),
        }
    }

    // ---- ensure_non_empty with various labels ----

    #[test]
    fn ensure_non_empty_different_labels() {
        let e1 = DlvPreCommitmentSdk::ensure_non_empty("alpha", false).unwrap_err();
        let e2 = DlvPreCommitmentSdk::ensure_non_empty("beta", false).unwrap_err();
        let msg1 = format!("{e1:?}");
        let msg2 = format!("{e2:?}");
        assert!(msg1.contains("alpha"));
        assert!(msg2.contains("beta"));
        assert!(!msg1.contains("beta"));
    }

    // ---- required_param with multiple keys ----

    #[test]
    fn required_param_picks_correct_key() {
        let mut map = HashMap::new();
        map.insert("a".to_string(), vec![1]);
        map.insert("b".to_string(), vec![2]);
        map.insert("c".to_string(), vec![3]);
        assert_eq!(
            DlvPreCommitmentSdk::required_param(&map, "a").unwrap(),
            &[1]
        );
        assert_eq!(
            DlvPreCommitmentSdk::required_param(&map, "b").unwrap(),
            &[2]
        );
        assert_eq!(
            DlvPreCommitmentSdk::required_param(&map, "c").unwrap(),
            &[3]
        );
    }

    // ---- build_fulfillment_proof with empty byte params ----

    #[test]
    fn build_fulfillment_proof_empty_byte_params() {
        let sdk = make_sdk_for_proof_test();
        let mut params = HashMap::new();
        params.insert("proof_state_transition".to_string(), Vec::new());
        params.insert("proof_merkle".to_string(), Vec::new());
        let proof = sdk.build_fulfillment_proof("f", &params).unwrap();
        match proof {
            FulfillmentProof::PaymentProof {
                state_transition,
                merkle_proof,
                ..
            } => {
                assert!(state_transition.is_empty());
                assert!(merkle_proof.is_empty());
            }
            _ => panic!("Expected PaymentProof"),
        }
    }

    // ---- DlvPreCommitmentResult clone ----

    #[test]
    fn dlv_pre_commitment_result_clone() {
        let mut bindings = BTreeMap::new();
        bindings.insert("fork_a".to_string(), "vault_1".to_string());
        let result = DlvPreCommitmentResult {
            pre_commitment: PreCommitment::default(),
            dlv_ids: vec!["v1".to_string()],
            external_hashes: {
                let mut h = HashMap::new();
                h.insert("btc".to_string(), [0xAB; 32]);
                h
            },
            selected_fork: Some("fork_a".to_string()),
            fork_vault_bindings: bindings,
        };
        let cloned = result.clone();
        assert_eq!(cloned.dlv_ids, vec!["v1"]);
        assert_eq!(cloned.selected_fork, Some("fork_a".to_string()));
        assert_eq!(cloned.fork_vault_bindings.len(), 1);
        assert_eq!(cloned.external_hashes["btc"], [0xAB; 32]);
    }

    // ---- ensure_variable_params_valid single duplicate ----

    #[test]
    fn ensure_variable_params_valid_adjacent_duplicates() {
        let sdk = make_sdk_for_proof_test();
        let cfg = PreCommitmentConfig {
            fixed_params: HashMap::new(),
            variable_params: vec!["a".to_string(), "a".to_string()],
            security_params: SecurityParameters::default(),
        };
        assert!(sdk.ensure_variable_params_valid(&cfg).is_err());
    }

    #[test]
    fn ensure_variable_params_valid_single_element() {
        let sdk = make_sdk_for_proof_test();
        let cfg = PreCommitmentConfig {
            fixed_params: HashMap::new(),
            variable_params: vec!["sole".to_string()],
            security_params: SecurityParameters::default(),
        };
        assert!(sdk.ensure_variable_params_valid(&cfg).is_ok());
    }

    // ---- PreCommitmentConfig ----

    #[test]
    fn pre_commitment_config_clone() {
        let cfg = PreCommitmentConfig {
            fixed_params: {
                let mut m = HashMap::new();
                m.insert("k".to_string(), vec![1, 2]);
                m
            },
            variable_params: vec!["v1".to_string(), "v2".to_string()],
            security_params: SecurityParameters::default(),
        };
        let cloned = cfg.clone();
        assert_eq!(cloned.fixed_params.len(), 1);
        assert_eq!(cloned.variable_params.len(), 2);
    }
}
