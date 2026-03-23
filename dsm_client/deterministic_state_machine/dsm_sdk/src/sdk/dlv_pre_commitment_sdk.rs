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
        creator_keypair: (&[u8], &[u8]), // (SPHINCS+ pk, sk)
        creator_kyber_pk: &[u8],         // Kyber PK for vault content encryption
        reference_state: &State,
    ) -> Result<DlvPreCommitmentResult, DsmError> {
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
                    creator_keypair,
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
                creator_keypair,
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
        executor_keypair: (&[u8], &[u8]), // (SPHINCS+ pk, sk)
        executor_kyber_sk: &[u8],         // Kyber SK for vault content decapsulation
        reference_state: &State,
        fork_vault_bindings: &BTreeMap<String, String>,
        execution_proof: Option<FulfillmentProof>,
    ) -> Result<DlvPreCommitmentResult, DsmError> {
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
                executor_keypair.1, // Kyber key for intended_recipient check
                executor_keypair.0, // SPHINCS+ PK for operation signature verification
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
                executor_keypair.0,
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
        creator_keypair: (&[u8], &[u8]), // (pk, sk)
        reference_state: &State,
    ) -> Result<PreCommitment, DsmError> {
        // Compute deterministic pre-commit hash
        //   H( state_hash || fixed_params || variable_params || forks(fork_id,hash) )
        let pre_hash = self.generate_pre_commitment_hash(cfg, &forks, reference_state)?;

        // Sign with creator SK
        let mut signatures = HashMap::new();
        let sig = sphincs::sphincs_sign(creator_keypair.1, &pre_hash)?;
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
