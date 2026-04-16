//! # Core SDK Module (strict / proto-only / clockless)
//!
//! Deterministic state & crypto semantics only:
//! - No JSON
//! - No wall clocks
//! - No removed APIs
//! - No `bincode`
//!
//! All ambiguous features fail-closed with `DsmError`.

use blake3::{hash, Hasher};
use dsm::crypto::blake3 as dsm_blake3;
use parking_lot::Mutex;
use prost::Message;
use std::sync::atomic::AtomicU64;

use dsm::core::identity::genesis::create_genesis_via_blind_mpc;
use dsm::core::state_machine::StateMachine;
use dsm::core::state_machine::relationship::KeyDerivationStrategy;
use dsm::core::token::policy::TokenPolicySystem;
use dsm::types::error::DsmError;
use dsm::types::operations::Operation as DsmOperation;
use dsm::types::policy_types::PolicyFile;
use dsm::types::state_types::{DeviceInfo, State};
use dsm::types::token_types::TokenMetadata;

use crate::storage::client_db;
use crate::generated::TokenMetadataProto;

use log;

/* ------------------------------- Types ---------------------------------- */

/// External token manager trait
pub trait TokenManagerTrait: Send + Sync {
    fn register_token(&self, token_id: &str) -> Result<(), DsmError>;
    fn get_balance(&self, token_id: &str) -> Result<u64, DsmError>;
}

/// Operation types (binary-only; no JSON or clocks)
#[derive(Debug, Clone)]
pub enum Operation {
    Transfer {
        token_id: Vec<u8>,
        recipient: Vec<u8>,
        amount: u64,
    },
    CreateIdentity {
        device_id: Vec<u8>,
    },
    Generic {
        operation_type: String,
        data: Vec<u8>,
        message: String,
    },
}

/* ------------------------------- CoreSDK -------------------------------- */

pub struct CoreSDK {
    state_machine: Mutex<StateMachine>,
    device_info: DeviceInfo,
    policy_system: TokenPolicySystem,
    audit_ctr: AtomicU64, // monotonic counter, not a clock
}

/* ------------------------------- Helpers -------------------------------- */

fn blake3_cat(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Hasher::new();
    for p in parts {
        h.update(p);
    }
    *h.finalize().as_bytes()
}

fn u64_le(n: u64) -> [u8; 8] {
    n.to_le_bytes()
}

fn device_key_material(di: &DeviceInfo) -> [u8; 32] {
    // deterministic, no serialization dependency
    blake3_cat(&[b"devkey", &di.device_id])
}

#[derive(Clone, PartialEq, ::prost::Message)]
struct TokenRegistryUpdateList {
    #[prost(message, repeated, tag = "1")]
    items: ::prost::alloc::vec::Vec<TokenMetadataProto>,
}

/// Deterministic, transport-agnostic encoding for DSM ops (no bincode, no JSON).
fn encode_dsm_operation_det(op: &dsm::types::operations::Operation) -> Vec<u8> {
    use dsm::types::operations::Operation as O;
    match op {
        O::Transfer {
            token_id,
            to_device_id,
            amount,
            ..
        } => [
            &b"dsm_op/transfer"[..],
            token_id.as_slice(),
            to_device_id.as_slice(),
            &u64_le(amount.value()),
        ]
        .concat(),
        O::Mint {
            token_id, amount, ..
        } => [
            &b"dsm_op/mint"[..],
            token_id.as_slice(),
            &u64_le(amount.value()),
        ]
        .concat(),
        O::Burn {
            token_id, amount, ..
        } => [
            &b"dsm_op/burn"[..],
            token_id.as_slice(),
            &u64_le(amount.value()),
        ]
        .concat(),
        O::Generic {
            operation_type,
            data,
            message,
            ..
        } => [
            &b"dsm_op/generic"[..],
            operation_type.as_slice(),
            message.as_bytes(),
            data.as_slice(),
        ]
        .concat(),
        other => {
            // future-proof deterministic default path
            let s = format!("{other:?}");
            [&b"dsm_op/other"[..], s.as_bytes()].concat()
        }
    }
}

/* ------------------------------- Impl ----------------------------------- */

impl CoreSDK {
    fn restore_latest_archived_state(
        state_machine: &Mutex<StateMachine>,
        device_id: &[u8; 32],
    ) -> Result<(), DsmError> {
        let archived_states =
            crate::storage::client_db::get_bcr_states(device_id, false).map_err(|e| {
                DsmError::state_machine(format!(
                    "Failed to load archived states during startup restore: {e}"
                ))
            })?;

        if let Some(latest_state) = archived_states.last() {
            state_machine.lock().set_state(latest_state.clone());
            log::info!(
                "[CoreSDK] restored archived canonical state_number={} for device {}",
                latest_state.hash[0] as u64,
                crate::util::text_id::encode_base32_crockford(device_id)
            );
        }

        Ok(())
    }

    fn archive_state_snapshot(state: &State) -> Result<(), DsmError> {
        crate::storage::client_db::store_bcr_state(state, false).map_err(|e| {
            DsmError::state_machine(format!(
                "Failed to archive canonical state {} for sparse replay: {e}",
                state.hash[0] as u64
            ))
        })
    }

    /// Initialize CoreSDK with default device identity
    pub fn new() -> Result<Self, DsmError> {
        Self::new_with_device(DeviceInfo::from_hashed_label("default_device", vec![0; 32]))
    }

    /// Initialize CoreSDK with an explicit device identity (preferred for wallet/runtime use).
    ///
    /// Passing the canonical device_id here ensures that token/accounting paths which rely on
    /// `State.device_info` use the caller's real device identifier. This keeps token balances,
    /// mint/transfer senders, and storage keys aligned with the active wallet device.
    pub fn new_with_device(device_info: DeviceInfo) -> Result<Self, DsmError> {
        log::info!(
            "Initializing CoreSDK (strict/proto-only/clockless) for device {}",
            crate::util::text_id::encode_base32_crockford(&device_info.device_id)
        );
        let policy_system = TokenPolicySystem::new()?;
        // Preload standard token policies (ERA) synchronously
        policy_system.preload_standard_policies_blocking()?;

        let state_machine = Mutex::new(StateMachine::new_with_strategy_and_device_id(
            KeyDerivationStrategy::Canonical,
            device_info.device_id,
        ));

        Self::restore_latest_archived_state(&state_machine, &device_info.device_id)?;

        Ok(Self {
            state_machine,
            device_info,
            policy_system,
            audit_ctr: AtomicU64::new(0),
        })
    }

    pub fn get_device_identity(&self) -> DeviceInfo {
        self.device_info.clone()
    }

    /// Sign a dsm `Operation` in-place using the device's SPHINCS+ secret key.
    /// Uses `with_cleared_signature()` / `to_bytes()` for the canonical payload.
    /// Returns the operation with the signature field populated.
    ///
    /// This differs from the legacy `sign_operation()` (async, returns raw bytes)
    /// which uses `encode_dsm_operation_det()` and is only used for audit hashes.
    pub fn sign_operation_sphincs(
        &self,
        mut operation: DsmOperation,
    ) -> Result<DsmOperation, DsmError> {
        let sk = crate::sdk::signing_authority::current_secret_key()?;

        let cleared = operation.with_cleared_signature();
        let payload = cleared.to_bytes();
        let sig = dsm::crypto::sphincs::sphincs_sign(&sk, &payload).map_err(|e| {
            DsmError::crypto(
                format!("Failed to sign operation: {e}"),
                None::<std::io::Error>,
            )
        })?;

        // Set the signature on the operation
        match &mut operation {
            DsmOperation::Transfer { signature, .. }
            | DsmOperation::CreateToken { signature, .. }
            | DsmOperation::Lock { signature, .. }
            | DsmOperation::Unlock { signature, .. }
            | DsmOperation::LockToken { signature, .. }
            | DsmOperation::UnlockToken { signature, .. }
            | DsmOperation::Generic { signature, .. }
            | DsmOperation::DlvCreate { signature, .. }
            | DsmOperation::DlvUnlock { signature, .. }
            | DsmOperation::DlvClaim { signature, .. }
            | DsmOperation::DlvInvalidate { signature, .. } => {
                *signature = sig;
            }
            _ => {
                log::warn!("[CoreSDK] sign_operation called on non-signable operation type");
            }
        }

        Ok(operation)
    }

    /// Sign arbitrary bytes with the device's SPHINCS+ secret key.
    /// Used for receipt counter-signatures where the payload is a 32-byte
    /// commitment hash rather than a full `DsmOperation`.
    pub fn sign_bytes_sphincs(&self, payload: &[u8]) -> Result<Vec<u8>, DsmError> {
        let sk = crate::sdk::signing_authority::current_secret_key()?;

        dsm::crypto::sphincs::sphincs_sign(&sk, payload).map_err(|e| {
            DsmError::crypto(
                format!("SPHINCS+ byte signing failed: {e}"),
                None::<std::io::Error>,
            )
        })
    }

    /// Current tip state (fail-closed if none)
    pub fn get_current_state(&self) -> Result<State, DsmError> {
        self.state_machine
            .lock()
            .current_state()
            .cloned()
            .ok_or_else(|| DsmError::state_machine("No current state available"))
    }

    /// Refresh the in-memory canonical tip from the latest archived sparse-replay
    /// snapshot for this device.
    pub fn restore_latest_archived_state_for_device(&self) -> Result<(), DsmError> {
        Self::restore_latest_archived_state(&self.state_machine, &self.device_info.device_id)
    }

    /// Replace the in-memory canonical tip with a caller-supplied archived state snapshot.
    /// Used by failed-online-send rollback after the bad archived successor has been removed.
    pub fn restore_state_snapshot(&self, state: &State) -> Result<(), DsmError> {
        if state.device_info.device_id != self.device_info.device_id {
            return Err(DsmError::state_machine(
                "restore_state_snapshot: device mismatch",
            ));
        }
        self.state_machine.lock().set_state(state.clone());
        Ok(())
    }

    /// Normalize stale balance key formats in the current state.
    ///
    /// Migrates:
    ///  - `"{u128}|ERA"` → plain `"ERA"` (keep MAX if both exist)
    ///  - `"{device_b32}.{token}"` dot-format entries are removed (pipe-format is authoritative)
    pub fn migrate_token_balance_keys(&self) {
        let mut sm = self.state_machine.lock();
        let state = match sm.current_state().cloned() {
            Some(s) => s,
            None => return,
        };

        let mut updated = state;
        let mut changed = false;

        let canonical_era_key = dsm::core::token::derive_canonical_balance_key(
            crate::policy::builtins::NATIVE_POLICY_COMMIT,
            &updated.device_info.public_key,
            "ERA",
        );

        // Collect keys to remove and entries to migrate
        let mut keys_to_remove: Vec<String> = Vec::new();
        let mut era_max: Option<dsm::types::token_types::Balance> = None;

        for (key, balance) in &updated.token_balances {
            if key == "ERA" {
                keys_to_remove.push(key.clone());
                era_max = Some(match era_max {
                    Some(existing) if existing.value() >= balance.value() => existing,
                    _ => balance.clone(),
                });
                continue;
            }

            // Detect pipe-format ERA keys like "{u128}|ERA"
            if let Some((_, token_id)) = key.split_once('|') {
                if token_id == "ERA" {
                    if key != &canonical_era_key {
                        keys_to_remove.push(key.clone());
                    }
                    era_max = Some(match era_max {
                        Some(existing) if existing.value() >= balance.value() => existing,
                        _ => balance.clone(),
                    });
                }
            }
            // Detect dot-format keys like "{device_b32}.{token}"
            if key.contains('.') && !key.contains('|') {
                keys_to_remove.push(key.clone());
            }
        }

        // Apply removals
        for key in &keys_to_remove {
            updated.token_balances.remove(key);
            changed = true;
        }

        // Merge migrated ERA balance into the canonical balance-key entry
        if let Some(migrated) = era_max {
            let existing = updated
                .token_balances
                .get(&canonical_era_key)
                .map(|b| b.value())
                .unwrap_or(0);
            if migrated.value() > existing {
                updated.token_balances.insert(canonical_era_key, migrated);
                changed = true;
            }
        }

        if changed {
            if let Ok(h) = updated.compute_hash() {
                updated.hash = h;
            }
            sm.set_state(updated);
            log::info!("[CoreSDK] Migrated stale balance keys to canonical format");
        }
    }

    /// Deterministic in-process genesis (for tests/bootstrap only)
    pub fn initialize_with_genesis_state(&self) -> Result<(), DsmError> {
        let mut sm = self.state_machine.lock();
        let initial_entropy = [0u8; 32];
        let mut genesis_state = State::new_genesis(initial_entropy, self.device_info.clone());
        // Precompute and embed the hash so tests and callers see a non-empty hash field
        if let Ok(h) = genesis_state.compute_hash() {
            genesis_state.hash = h;
        }
        sm.set_state(genesis_state);
        Ok(())
    }

    /// Deterministic transition (binary payloads only)
    pub fn execute_transition(&self, operation: Operation) -> Result<State, DsmError> {
        let (op_type, data, message) = match operation {
            Operation::Transfer {
                token_id,
                recipient,
                amount,
            } => {
                if token_id.is_empty() || recipient.is_empty() || amount == 0 {
                    return Err(DsmError::invalid_operation(
                        "Transfer: invalid token/recipient/amount",
                    ));
                }
                let payload = [
                    &b"xfer"[..],
                    token_id.as_slice(),
                    recipient.as_slice(),
                    &u64_le(amount),
                ]
                .concat();
                (b"transfer".to_vec(), payload, "Transfer".to_string())
            }
            Operation::CreateIdentity { device_id } => {
                if device_id.is_empty() {
                    return Err(DsmError::invalid_operation(
                        "CreateIdentity: empty device_id",
                    ));
                }
                let payload = [&b"cid"[..], device_id.as_slice()].concat();
                (
                    b"create_identity".to_vec(),
                    payload,
                    "Create identity".to_string(),
                )
            }
            Operation::Generic {
                operation_type,
                data,
                message,
            } => {
                if operation_type.is_empty() {
                    return Err(DsmError::invalid_operation("Generic: empty operation_type"));
                }
                (operation_type.into_bytes(), data, message)
            }
        };

        let mut dsm_op = DsmOperation::Generic {
            operation_type: op_type,
            data,
            message,
            signature: vec![],
        };

        dsm_op = self.sign_operation_sphincs(dsm_op)?;

        self.state_machine.lock().execute_transition(dsm_op)
    }

    /// Execute a full DSM Operation (preserving signatures and proofs)
    /// This bypasses the simplified CoreSDK::Operation wrapper to ensure
    /// authorization material reaches the state machine intact.
    /// Execute a DSM operation through the state machine and archive the result.
    ///
    /// Returns the post-transition state with correct balances and hash.
    /// Callers are responsible for calling `sync_token_projection_from_state`
    /// (or `sync_token_projection_best_effort`) after this returns, since the
    /// projection sync requires token_id and policy_commit which are
    /// caller-specific context.
    pub fn execute_dsm_operation(
        &self,
        dsm_operation: dsm::types::operations::Operation,
    ) -> Result<State, DsmError> {
        let mut sm = self.state_machine.lock();
        let next_state = sm.execute_transition(dsm_operation.clone())?;
        Self::archive_state_snapshot(&next_state)?;
        Ok(next_state)
    }

    pub fn register_token_manager(
        &self,
        _manager: Box<dyn TokenManagerTrait>,
    ) -> Result<(), DsmError> {
        log::info!("Token manager registered");
        Ok(())
    }

    /// Deterministic state lookup; 0 = genesis
    pub fn get_state_by_number(&self, state_number: u64) -> Result<State, DsmError> {
        if let Some(s) = self.state_machine.lock().current_state() {
            if s.hash[0] as u64 == state_number {
                return Ok(s.clone());
            }
            if state_number == 0 {
                return Err(DsmError::state_machine("No genesis state available"));
            }
        }

        let device_id = self.device_info.device_id;
        let states = crate::storage::client_db::get_bcr_states(&device_id, false).map_err(|e| {
            DsmError::state_machine(format!("Failed to load archived states for lookup: {e}"))
        })?;

        for s in states {
            if s.hash[0] as u64 == state_number {
                return Ok(s);
            }
        }

        Err(DsmError::state_machine(format!(
            "State {state_number} not found"
        )))
    }

    /// Deterministic signer (no clocks, no external randomness)
    pub async fn sign_raw(&self, data: &[u8]) -> Result<Vec<u8>, DsmError> {
        let dev_key = device_key_material(&self.device_info);
        Ok(blake3_cat(&[dev_key.as_ref(), b"sig", data]).to_vec())
    }

    /// Hash state bytes
    pub fn hash_state(&self, state_data: &[u8]) -> Result<Vec<u8>, DsmError> {
        Ok(hash(state_data).as_bytes().to_vec())
    }

    /* -------------------- Proto-only, non-removed paths ---------------- */

    /// MPC genesis (blind MPC) — no wall-clock time
    pub async fn create_genesis_with_passive_contributors(
        &self,
        device_id: Vec<u8>,
        mpc_participants: Vec<Vec<u8>>,
        client_entropy: Option<Vec<u8>>,
    ) -> Result<GenesisInfo, DsmError> {
        if device_id.is_empty() {
            return Err(DsmError::invalid_operation("Device ID cannot be empty"));
        }
        if mpc_participants.is_empty() {
            return Err(DsmError::invalid_operation(
                "At least one MPC participant required",
            ));
        }

        // Prepare arguments for the MPC genesis core call
        // device_id must be exactly 32 bytes
        let device_id_arr: [u8; 32] = device_id
            .as_slice()
            .try_into()
            .map_err(|_| DsmError::invalid_operation("device_id must be 32 bytes"))?;

        // Map participant bytes to NodeId using deterministic hex strings for display; core remains bytes-only
        let storage_nodes: Vec<dsm::types::identifiers::NodeId> = mpc_participants
            .into_iter()
            .map(|p| {
                dsm::types::identifiers::NodeId::new(crate::util::text_id::encode_base32_crockford(
                    &p,
                ))
            })
            .collect();

        let threshold = storage_nodes.len();

        // Await the async MPC genesis function and propagate errors
        let genesis_state =
            create_genesis_via_blind_mpc(device_id_arr, storage_nodes, threshold, client_entropy)
                .await?;
        let public_key = genesis_state.signing_key.public_key.clone();
        let smt_root = genesis_state.merkle_root.unwrap_or(genesis_state.hash);

        log::info!(
            "Genesis created (hash={})",
            crate::util::text_id::encode_base32_crockford(&genesis_state.hash)
        );

        // Install the new genesis as current state and archive it so that
        // bilateral settlement always has a prior BCR state to reconcile against
        // (the contact-add handshake anchors the chain tip; the genesis archive
        // ensures latest_archived_state() is never None).
        {
            let mut sm = self.state_machine.lock();
            let mut s = State::new_genesis(genesis_state.initial_entropy, self.device_info.clone());
            s.hash = genesis_state.hash;
            let snapshot = s.clone();
            sm.set_state(s);
            Self::archive_state_snapshot(&snapshot)?;
        }

        // Optional dev-only seeding (idempotent)
        if let Err(e) = self.maybe_dev_seed_after_genesis().await {
            log::warn!("Dev seeding skipped: {}", e);
        }

        Ok(GenesisInfo {
            genesis_hash: genesis_state.hash.to_vec(),
            device_id,
            public_key,
            smt_root: smt_root.to_vec(),
        })
    }

    /// Dev-only seeding of ERA token for local testing, idempotent via flag file
    async fn maybe_dev_seed_after_genesis(&self) -> Result<(), DsmError> {
        // Gate via env var DSM_DEV_SEED=1
        let enabled = std::env::var("DSM_DEV_SEED")
            .ok()
            .is_some_and(|v| v == "1" || v.eq_ignore_ascii_case("true"));
        if !enabled {
            return Ok(());
        }

        // Determine flag path
        let flag_path = std::env::var("DSM_DEV_SEED_DIR")
            .ok()
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| std::path::PathBuf::from(".dsm_dev"));
        let _ = std::fs::create_dir_all(&flag_path);
        let flag_file = flag_path.join("seeded.flag");
        if flag_file.exists() {
            return Ok(());
        }

        // Construct a Mint operation for ERA
        use dsm::types::operations::Operation as O;
        use dsm::types::token_types::Balance as Bal;

        // Ensure we have a current state
        let _cur = self.get_current_state()?;

        let mut amt = Bal::zero();
        amt.update(1_000_000, true); // 1_000_000 units for local testing

        let mint = O::Mint {
            amount: amt,
            token_id: b"ERA".to_vec(),
            authorized_by: crate::util::text_id::encode_base32_crockford(
                &self.device_info.device_id,
            )
            .into_bytes(),
            proof_of_authorization: blake3_cat(&[b"dev-seed", &self.device_info.device_id])
                .to_vec(),
            message: "dev seed".to_string(),
        };

        // Execute transition in core state machine
        let mut sm = self.state_machine.lock();
        let new_state = sm.execute_transition(mint)?;
        log::info!(
            "Dev seeding applied; new state number {}",
            new_state.hash[0] as u64
        );

        // Write flag to ensure idempotence
        std::fs::write(flag_file, b"seeded=1").map_err(|e| {
            DsmError::internal(
                format!("Failed to write seed flag: {e}"),
                None::<std::convert::Infallible>,
            )
        })?;

        Ok(())
    }

    /// Strict range query; no time, fail-closed if history unsupported
    pub async fn query_state_range(
        &self,
        genesis_hash: Vec<u8>,
        from_position: u64,
        to_position: u64,
        _include_proofs: bool,
    ) -> Result<StateQueryInfo, DsmError> {
        if genesis_hash.is_empty() {
            return Err(DsmError::invalid_operation("Empty genesis hash"));
        }
        if from_position > to_position {
            return Err(DsmError::invalid_operation(
                "Invalid range: from_position > to_position",
            ));
        }

        if from_position != to_position {
            return Err(DsmError::state_machine(
                "Historical range not supported by StateMachine",
            ));
        }

        let state = self.get_current_state()?;
        let sbytes = state.to_bytes()?;
        let current_state_hash = self.hash_state(&sbytes)?;
        let entry = StateEntry {
            position: to_position,
            state_hash: current_state_hash.clone(),
            prev_hash: Vec::new(),
            operation_data: Vec::new(),
            tick: 0, // clockless
            smt_proof: blake3_cat(&[b"proof", &sbytes]).to_vec(),
        };
        let smt_root = blake3_cat(&[b"smt_root", &sbytes]).to_vec();

        Ok(StateQueryInfo {
            current_state_hash,
            current_position: to_position,
            state_entries: vec![entry],
            smt_root,
        })
    }

    /// Contact verification (deterministic challenge/anchor)
    pub async fn verify_and_add_contact(
        &self,
        contact_genesis: Vec<u8>,
        challenge: Vec<u8>,
    ) -> Result<ContactInfo, DsmError> {
        if contact_genesis.is_empty() {
            return Err(DsmError::invalid_operation("Empty contact genesis"));
        }
        if !self.verify_genesis(&contact_genesis).await? {
            return Err(DsmError::invalid_operation("Invalid genesis hash"));
        }
        let public_key = self.extract_public_key_from_genesis(&contact_genesis)?;

        // canonical local id = H("did" || device_id)
        let mut id_data = b"did".to_vec();
        id_data.extend_from_slice(&self.device_info.device_id);
        let local_id = dsm_blake3::domain_hash("DSM/local-id", &id_data)
            .as_bytes()
            .to_vec();

        let bilateral_anchor =
            blake3_cat(&[b"bilateral_anchor", &contact_genesis, &local_id]).to_vec();
        let challenge_response =
            blake3_cat(&[b"challenge_response", &challenge, &local_id]).to_vec();

        Ok(ContactInfo {
            genesis_hash: contact_genesis,
            public_key,
            chain_tip: vec![],
            challenge_response,
            bilateral_anchor,
        })
    }

    /// Validate a token policy strictly; returns file when present
    pub async fn validate_token_policy(
        &self,
        policy_id: &str,
    ) -> Result<Option<PolicyFile>, DsmError> {
        if policy_id.is_empty() {
            return Err(DsmError::invalid_operation("Empty policy_id"));
        }
        if let Some(tp) = self.policy_system.get_token_policy(policy_id).await? {
            // Deterministic local proof material if you need it:
            let _proof = self.generate_policy_verification_proof(
                hash(policy_id.as_bytes()).as_bytes(),
                hash(&self.device_info.device_id).as_bytes(),
            )?;
            return Ok(Some(tp.file));
        }
        Ok(None)
    }

    /* ------------------------ Not provided here (strict) ------------------ */

    pub async fn sync_with_network(&self) -> Result<SyncInfo, DsmError> {
        Err(DsmError::invalid_operation(
            "Network sync not available in CoreSDK",
        ))
    }

    pub async fn get_network_status(&self) -> Result<NetworkStatus, DsmError> {
        Ok(NetworkStatus {
            network_type: "offline".into(),
            connected_peers: 0,
            connection_status: "disconnected".into(),
            is_syncing: false,
            last_sync_time: 0, // clockless
        })
    }

    pub async fn discover_storage_nodes(
        &self,
        _network_type: String,
    ) -> Result<DiscoveryResult, DsmError> {
        Err(DsmError::invalid_operation(
            "Discovery not available in CoreSDK",
        ))
    }

    pub async fn list_contacts(&self) -> Result<Vec<ContactInfo>, DsmError> {
        // Fetch real contacts from local database
        let records = client_db::get_all_contacts().map_err(|e| {
            DsmError::storage(
                format!("Failed to load contacts: {e}"),
                None::<std::io::Error>,
            )
        })?;

        let mut out = Vec::with_capacity(records.len());
        for r in records {
            if r.genesis_hash.len() != 32 {
                continue;
            }

            out.push(ContactInfo {
                genesis_hash: r.genesis_hash,
                public_key: r.public_key,
                chain_tip: r.current_chain_tip.unwrap_or_default(),
                challenge_response: vec![], // Not stored in DB record
                bilateral_anchor: vec![],   // Computed on-demand or during verify
            });
        }
        Ok(out)
    }

    pub async fn get_token_balance(
        &self,
        _token_id: Vec<u8>,
        _genesis_hash: Vec<u8>,
    ) -> Result<TokenBalanceInfo, DsmError> {
        Err(DsmError::invalid_operation(
            "Token balance query not available in CoreSDK",
        ))
    }

    pub async fn get_app_state(&self, _key: String) -> Result<AppStateResult, DsmError> {
        Err(DsmError::invalid_operation(
            "App state get not available in CoreSDK",
        ))
    }
    pub async fn set_app_state(
        &self,
        _key: String,
        _value: String,
    ) -> Result<AppStateResult, DsmError> {
        Err(DsmError::invalid_operation(
            "App state set not available in CoreSDK",
        ))
    }
    pub async fn delete_app_state(&self, _key: String) -> Result<AppStateResult, DsmError> {
        Err(DsmError::invalid_operation(
            "App state delete not available in CoreSDK",
        ))
    }

    pub async fn create_backup(&self) -> Result<BackupResult, DsmError> {
        Err(DsmError::invalid_operation(
            "Backup creation not available in CoreSDK",
        ))
    }
    pub async fn restore_from_backup(
        &self,
        _backup_phrase: String,
    ) -> Result<BackupResult, DsmError> {
        Err(DsmError::invalid_operation(
            "Backup restore not available in CoreSDK",
        ))
    }
    pub async fn verify_backup(&self, _backup_phrase: String) -> Result<BackupResult, DsmError> {
        Err(DsmError::invalid_operation(
            "Backup verify not available in CoreSDK",
        ))
    }

    pub async fn get_setting(&self, _key: String) -> Result<SettingResult, DsmError> {
        Err(DsmError::invalid_operation(
            "Settings get not available in CoreSDK",
        ))
    }
    pub async fn set_setting(
        &self,
        _key: String,
        _value: String,
    ) -> Result<SettingResult, DsmError> {
        Err(DsmError::invalid_operation(
            "Settings set not available in CoreSDK",
        ))
    }
    pub async fn delete_setting(&self, _key: String) -> Result<SettingResult, DsmError> {
        Err(DsmError::invalid_operation(
            "Settings delete not available in CoreSDK",
        ))
    }

    pub async fn handle_bluetooth_operation(
        &self,
        _operation: String,
    ) -> Result<BluetoothResult, DsmError> {
        Err(DsmError::invalid_operation(
            "Bluetooth operations are not available in CoreSDK",
        ))
    }
}

/* ------------------------------ Private helpers ------------------------- */

impl CoreSDK {
    fn validate_transfer_request(
        &self,
        token_id: &[u8],
        recipient_genesis: &[u8],
        amount: u64,
        nonce: &[u8],
        sender_signature: &[u8],
    ) -> Result<(), DsmError> {
        if token_id.is_empty() {
            return Err(DsmError::invalid_operation("Empty token ID"));
        }
        if recipient_genesis.is_empty() {
            return Err(DsmError::invalid_operation("Empty recipient genesis"));
        }
        if amount == 0 {
            return Err(DsmError::invalid_operation("Zero amount transfer"));
        }
        if nonce.is_empty() {
            return Err(DsmError::invalid_operation("Empty nonce"));
        }
        if sender_signature.is_empty() {
            return Err(DsmError::invalid_operation("Empty sender signature"));
        }
        Ok(())
    }

    async fn verify_genesis(&self, genesis_hash: &[u8]) -> Result<bool, DsmError> {
        Ok(!genesis_hash.is_empty())
    }

    fn extract_public_key_from_genesis(&self, genesis_hash: &[u8]) -> Result<Vec<u8>, DsmError> {
        if genesis_hash.len() < 32 {
            return Err(DsmError::invalid_operation("Invalid genesis hash length"));
        }
        Ok(genesis_hash[0..32].to_vec())
    }

    fn generate_policy_verification_proof(
        &self,
        policy_hash: &[u8],
        creator_genesis: &[u8],
    ) -> Result<Vec<u8>, DsmError> {
        Ok(blake3_cat(&[b"policy_verification", policy_hash, creator_genesis]).to_vec())
    }

    fn token_metadata_from_proto(proto: &TokenMetadataProto) -> TokenMetadata {
        TokenMetadata {
            token_id: proto.token_id.clone(),
            name: proto.name.clone(),
            symbol: proto.symbol.clone(),
            description: proto.description.clone().filter(|s| !s.is_empty()),
            icon_url: proto.icon_url.clone().filter(|s| !s.is_empty()),
            decimals: (proto.decimals as u8).min(18),
            token_type: match proto.token_type.to_uppercase().as_str() {
                "NATIVE" => dsm::types::token_types::TokenType::Native,
                "CREATED" => dsm::types::token_types::TokenType::Created,
                "RESTRICTED" => dsm::types::token_types::TokenType::Restricted,
                "WRAPPED" => dsm::types::token_types::TokenType::Wrapped,
                _ => dsm::types::token_types::TokenType::Created,
            },
            owner_id: {
                let bytes = crate::util::text_id::decode_base32_crockford(&proto.owner_id)
                    .unwrap_or_default();
                let mut arr = [0u8; 32];
                if bytes.len() == 32 {
                    arr.copy_from_slice(&bytes);
                }
                arr
            },
            creation_tick: proto.creation_index,
            metadata_uri: proto.metadata_uri.clone().filter(|s| !s.is_empty()),
            policy_anchor: proto.policy_anchor.clone().filter(|s| !s.is_empty()),
            fields: proto
                .fields
                .iter()
                .map(|field| (field.key.clone(), field.value.clone()))
                .collect(),
        }
    }

    fn token_metadata_for_state(&self, state: &State, token_id: &str) -> Option<TokenMetadata> {
        match &state.operation {
            dsm::types::operations::Operation::Create { metadata, .. } => {
                let proto = TokenMetadataProto::decode(metadata.as_slice()).ok()?;
                let token_metadata = Self::token_metadata_from_proto(&proto);
                if token_metadata.token_id == token_id || token_metadata.symbol == token_id {
                    Some(token_metadata)
                } else {
                    None
                }
            }
            dsm::types::operations::Operation::Generic {
                operation_type,
                data,
                ..
            } => {
                if operation_type.as_slice() == b"token_create"
                    || operation_type.as_slice() == b"token_registry_update"
                {
                    if let Ok(registry_update) = TokenRegistryUpdateList::decode(data.as_slice()) {
                        if let Some(proto) = registry_update
                            .items
                            .into_iter()
                            .find(|proto| proto.token_id == token_id || proto.symbol == token_id)
                        {
                            return Some(Self::token_metadata_from_proto(&proto));
                        }
                    }
                    if let Ok(proto) = TokenMetadataProto::decode(data.as_slice()) {
                        let token_metadata = Self::token_metadata_from_proto(&proto);
                        if token_metadata.token_id == token_id || token_metadata.symbol == token_id
                        {
                            return Some(token_metadata);
                        }
                    }
                }
                None
            }
            _ => None,
        }
    }

    fn resolve_policy_commit_strict(&self, token_id: &[u8]) -> Result<[u8; 32], DsmError> {
        let token_id = std::str::from_utf8(token_id)
            .map_err(|_| DsmError::invalid_operation("token_id must be valid UTF-8"))?;

        if let Some(commit) = crate::policy::builtin_policy_commit(token_id) {
            return Ok(commit);
        }

        let current_state = self.get_current_state()?;
        for state_number in (0..=current_state.hash[0] as u64).rev() {
            let state = self.get_state_by_number(state_number)?;
            if let Some(token_metadata) = self.token_metadata_for_state(&state, token_id) {
                return crate::policy::strict_policy_commit_for_token(
                    token_id,
                    token_metadata.policy_anchor.as_deref(),
                );
            }
        }

        Err(DsmError::state(format!(
            "Missing canonical policy anchor for token {token_id}"
        )))
    }

    /// Proto-only signing for DSM ops (no bincode)
    pub async fn sign_operation(
        &self,
        operation: &dsm::types::operations::Operation,
    ) -> Result<Vec<u8>, DsmError> {
        let op_bytes = encode_dsm_operation_det(operation);
        self.sign_raw(&op_bytes).await
    }

    pub async fn local_genesis_hash(&self) -> Result<Vec<u8>, DsmError> {
        // Return the MPC-issued genesis hash from the genesis_records table.
        // This MUST match the genesis hash that contacts store during pairing,
        // otherwise b0x routing addresses will diverge between sender and receiver.
        match crate::storage::client_db::get_verified_genesis_record() {
            Ok(Some(rec)) => match crate::util::text_id::decode_base32_crockford(&rec.genesis_id) {
                Some(bytes) if bytes.len() == 32 => Ok(bytes),
                _ => Err(DsmError::internal(
                    "genesis_records.genesis_id is not a valid 32-byte base32 value",
                    None::<std::convert::Infallible>,
                )),
            },
            Ok(None) => Err(DsmError::internal(
                "no genesis record found; MPC genesis has not been created yet",
                None::<std::convert::Infallible>,
            )),
            Err(e) => Err(DsmError::internal(
                format!("failed to read genesis record: {e}"),
                None::<std::convert::Infallible>,
            )),
        }
    }

    pub async fn local_chain_tip(&self) -> Result<Vec<u8>, DsmError> {
        let state = self.get_current_state()?;
        let state_bytes = state.to_bytes()?;
        self.hash_state(&state_bytes)
    }

    fn sync_token_projection_best_effort(
        &self,
        local_b32: &str,
        token_id: &[u8],
        new_state: &State,
        context: &str,
    ) {
        let token_id_str = String::from_utf8_lossy(token_id);
        let canonical_token_id = if token_id_str.trim().is_empty() {
            "ERA"
        } else {
            token_id_str.as_ref()
        };

        let existing_locked = match client_db::get_locked_balance(local_b32, canonical_token_id) {
            Ok(value) => value,
            Err(error) => {
                log::error!(
                    "[{context}] CRITICAL: failed to read {canonical_token_id} locked balance: {error}"
                );
                0
            }
        };

        let policy_commit = match self.resolve_policy_commit_strict(token_id) {
            Ok(commit) => commit,
            Err(error) => {
                log::error!(
                    "[{context}] CRITICAL: failed to resolve policy commit for {canonical_token_id}: {error}"
                );
                return;
            }
        };

        if let Err(error) = client_db::sync_token_projection_from_state(
            local_b32,
            canonical_token_id,
            &policy_commit,
            new_state,
            existing_locked,
        ) {
            log::error!(
                "[{context}] CRITICAL: failed to sync {canonical_token_id} projection: {error}"
            );
        } else {
            log::info!(
                "[{context}] token projection synced: {canonical_token_id} state_number={}",
                new_state.hash[0] as u64
            );
        }
    }

    /// Apply a decoded Operation with replay protection and state machine integration.
    /// This executes the operation through the state machine for validation and state transition,
    /// then persists the results to the database with idempotency checks.
    pub fn apply_operation_with_replay_protection(
        &self,
        op: dsm::types::operations::Operation,
        tx_id: &crate::types::identifiers::TransactionId,
        _seq: u64,
        sender_device_id: &str,
        sender_chain_tip: &str,
    ) -> Result<(), DsmError> {
        // Fail-closed on obviously malformed inputs.
        if sender_device_id.is_empty() {
            return Err(DsmError::invalid_operation(
                "apply_operation_with_replay_protection: empty sender_device_id",
            ));
        }
        if sender_chain_tip.is_empty() {
            return Err(DsmError::invalid_operation(
                "apply_operation_with_replay_protection: empty sender_chain_tip",
            ));
        }

        // First, execute the operation through the state machine for validation and state transition
        let new_state = self.execute_dsm_operation(op.clone()).map_err(|e| {
            DsmError::invalid_operation(format!(
                "apply_operation_with_replay_protection: state machine execution failed: {}",
                e
            ))
        })?;

        // Then handle database persistence based on operation type
        match op {
            dsm::types::operations::Operation::Transfer {
                nonce,
                amount,
                to_device_id,
                token_id,
                ..
            } => {
                if nonce.is_empty() {
                    return Err(DsmError::invalid_operation(
                        "apply_operation_with_replay_protection: empty transfer nonce",
                    ));
                }
                let amount_val = amount.value();
                if amount_val == 0 {
                    return Err(DsmError::invalid_operation(
                        "apply_operation_with_replay_protection: zero transfer amount",
                    ));
                }

                // Ensure the transfer is addressed to us (recipient-only apply).
                let local_device_id_bytes = crate::sdk::app_state::AppState::get_device_id()
                    .ok_or_else(|| DsmError::state_machine("missing local device_id (AppState)"))?;
                if local_device_id_bytes.len() != 32 {
                    return Err(DsmError::state_machine(
                        "local device_id must be 32 bytes (AppState corrupt)",
                    ));
                }
                if to_device_id.as_slice() != local_device_id_bytes.as_slice() {
                    return Err(DsmError::invalid_operation(
                        "apply_operation_with_replay_protection: transfer not addressed to this device",
                    ));
                }

                // Decode sender id to raw bytes for AF-2 table.
                let sender_id_bytes = crate::util::text_id::decode_base32_crockford(
                    sender_device_id,
                )
                .ok_or_else(|| DsmError::invalid_operation("sender_device_id not valid base32"))?;
                if sender_id_bytes.len() != 32 {
                    return Err(DsmError::invalid_operation(
                        "apply_operation_with_replay_protection: sender_device_id must decode to 32 bytes",
                    ));
                }

                // Replay check: refuse if nonce already spent.
                let already_spent = client_db::is_nonce_spent(&nonce).map_err(|e| {
                    DsmError::internal(
                        format!("nonce check failed: {e}"),
                        None::<std::convert::Infallible>,
                    )
                })?;
                if already_spent {
                    return Err(DsmError::invalid_operation(
                        "apply_operation_with_replay_protection: replay detected (nonce already spent)",
                    ));
                }

                // We don't currently have an authoritative local chain tip for the bilateral inbox
                // path in this function signature. Use the sender-provided chain tip *only* as
                // input to the deterministic tip derivation in atomic_receive_transfer.
                let sender_chain_tip_bytes = crate::util::text_id::decode_base32_crockford(
                    sender_chain_tip,
                )
                .ok_or_else(|| DsmError::invalid_operation("sender_chain_tip not valid base32"))?;
                if sender_chain_tip_bytes.len() != 32 {
                    return Err(DsmError::invalid_operation(
                        "apply_operation_with_replay_protection: sender_chain_tip must decode to 32 bytes",
                    ));
                }

                // Apply atomically in SQLite: marks nonce spent and records receive metadata.
                let local_b32 =
                    crate::util::text_id::encode_base32_crockford(&local_device_id_bytes);
                // Resolve policy_commit for hierarchical domain separation in chain tip.
                let pc = self.resolve_policy_commit_strict(&token_id)?;
                let tx_id_lossy = String::from_utf8_lossy(tx_id.as_bytes());
                let _new_tip = client_db::atomic_receive_transfer(
                    &local_b32,
                    &nonce,
                    &tx_id_lossy,
                    &sender_id_bytes,
                    amount_val,
                    &sender_chain_tip_bytes,
                    &pc,
                )
                .map_err(|e| {
                    DsmError::internal(
                        format!("atomic receive failed: {e}"),
                        None::<std::convert::Infallible>,
                    )
                })?;

                self.sync_token_projection_best_effort(
                    &local_b32,
                    &token_id,
                    &new_state,
                    "apply_operation",
                );

                log::info!(
                    "[apply_operation] ✅ applied transfer tx={} token={} amount={} from={}",
                    String::from_utf8_lossy(tx_id.as_bytes()),
                    String::from_utf8_lossy(&token_id),
                    amount_val,
                    sender_device_id
                );
                Ok(())
            }
            dsm::types::operations::Operation::Receive {
                nonce,
                amount,
                from_device_id,
                token_id,
                ..
            } => {
                if nonce.is_empty() {
                    return Err(DsmError::invalid_operation(
                        "apply_operation_with_replay_protection: empty receive nonce",
                    ));
                }
                let amount_val = amount.value();
                if amount_val == 0 {
                    return Err(DsmError::invalid_operation(
                        "apply_operation_with_replay_protection: zero receive amount",
                    ));
                }

                // Ensure the receive is from the expected sender
                let sender_id_bytes = crate::util::text_id::decode_base32_crockford(
                    sender_device_id,
                )
                .ok_or_else(|| DsmError::invalid_operation("sender_device_id not valid base32"))?;
                if sender_id_bytes.len() != 32 {
                    return Err(DsmError::invalid_operation(
                        "apply_operation_with_replay_protection: sender_device_id must decode to 32 bytes",
                    ));
                }
                let from_device_id_str = String::from_utf8_lossy(&from_device_id);
                let from_device_id_bytes = crate::util::text_id::decode_base32_crockford(
                    &from_device_id_str,
                )
                .ok_or_else(|| DsmError::invalid_operation("from_device_id not valid base32"))?;
                if from_device_id_bytes.len() != 32 {
                    return Err(DsmError::invalid_operation(
                        "apply_operation_with_replay_protection: from_device_id must decode to 32 bytes",
                    ));
                }
                if from_device_id_bytes.as_slice() != sender_id_bytes.as_slice() {
                    return Err(DsmError::invalid_operation(
                        "apply_operation_with_replay_protection: receive from_device_id mismatch",
                    ));
                }

                // Replay check: refuse if nonce already spent.
                let already_spent = client_db::is_nonce_spent(&nonce).map_err(|e| {
                    DsmError::internal(
                        format!("nonce check failed: {e}"),
                        None::<std::convert::Infallible>,
                    )
                })?;
                if already_spent {
                    return Err(DsmError::invalid_operation(
                        "apply_operation_with_replay_protection: replay detected (nonce already spent)",
                    ));
                }

                // Get local device info for balance update
                let local_device_id_bytes = crate::sdk::app_state::AppState::get_device_id()
                    .ok_or_else(|| DsmError::state_machine("missing local device_id (AppState)"))?;
                if local_device_id_bytes.len() != 32 {
                    return Err(DsmError::state_machine(
                        "local device_id must be 32 bytes (AppState corrupt)",
                    ));
                }

                let sender_chain_tip_bytes = crate::util::text_id::decode_base32_crockford(
                    sender_chain_tip,
                )
                .ok_or_else(|| DsmError::invalid_operation("sender_chain_tip not valid base32"))?;
                if sender_chain_tip_bytes.len() != 32 {
                    return Err(DsmError::invalid_operation(
                        "apply_operation_with_replay_protection: sender_chain_tip must decode to 32 bytes",
                    ));
                }

                // Apply atomically in SQLite: marks nonce spent and records receive metadata.
                let local_b32 =
                    crate::util::text_id::encode_base32_crockford(&local_device_id_bytes);
                // Resolve policy_commit for hierarchical domain separation in chain tip.
                let pc = self.resolve_policy_commit_strict(&token_id)?;
                let tx_id_lossy = String::from_utf8_lossy(tx_id.as_bytes());
                let _new_tip = client_db::atomic_receive_transfer(
                    &local_b32,
                    &nonce,
                    &tx_id_lossy,
                    &sender_id_bytes,
                    amount_val,
                    &sender_chain_tip_bytes,
                    &pc,
                )
                .map_err(|e| {
                    DsmError::internal(
                        format!("atomic receive failed: {e}"),
                        None::<std::convert::Infallible>,
                    )
                })?;

                self.sync_token_projection_best_effort(
                    &local_b32,
                    &token_id,
                    &new_state,
                    "apply_operation",
                );

                log::info!(
                    "[apply_operation] ✅ applied receive tx={} token={} amount={} from={}",
                    String::from_utf8_lossy(tx_id.as_bytes()),
                    String::from_utf8_lossy(&token_id),
                    amount_val,
                    sender_device_id
                );
                Ok(())
            }
            dsm::types::operations::Operation::Create { .. } => {
                log::info!(
                    "[apply_operation] ✅ applied create operation tx={} from={}",
                    String::from_utf8_lossy(tx_id.as_bytes()),
                    sender_device_id
                );
                Ok(())
            }
            dsm::types::operations::Operation::AddRelationship {
                from_id: _,
                to_id,
                relationship_type,
                metadata,
                proof,
                mode: _,
                message,
                ..
            } => {
                // Add the sender as a contact if they're adding a relationship with us
                let local_device_id_bytes = crate::sdk::app_state::AppState::get_device_id()
                    .ok_or_else(|| DsmError::state_machine("missing local device_id (AppState)"))?;
                if local_device_id_bytes.len() != 32 {
                    return Err(DsmError::state_machine(
                        "local device_id must be 32 bytes (AppState corrupt)",
                    ));
                }

                // Check if this relationship is addressed to us
                if to_id.as_slice() == local_device_id_bytes.as_slice() {
                    // Create or update contact record
                    let sender_id_bytes =
                        crate::util::text_id::decode_base32_crockford(sender_device_id)
                            .ok_or_else(|| {
                                DsmError::invalid_operation("sender_device_id not valid base32")
                            })?;
                    if sender_id_bytes.len() != 32 {
                        return Err(DsmError::invalid_operation(
                            "apply_operation_with_replay_protection: sender_device_id must decode to 32 bytes",
                        ));
                    }

                    let contact = client_db::ContactRecord {
                        contact_id: format!("contact_{}", sender_device_id),
                        device_id: sender_id_bytes.clone(),
                        alias: String::from_utf8_lossy(relationship_type.as_slice()).into_owned(),
                        genesis_hash: if metadata.len() >= 32 {
                            // Genesis hash embedded in first 32 bytes of metadata
                            metadata[..32].to_vec()
                        } else {
                            // Derive deterministic genesis hash from sender device ID
                            dsm_blake3::domain_hash(
                                "DSM/genesis-counterparty",
                                &[b"genesis/", sender_id_bytes.as_slice()].concat(),
                            )
                            .as_bytes()
                            .to_vec()
                        },
                        public_key: if proof.len() >= 32 {
                            // Public key embedded in first 32 bytes of proof
                            proof[..32].to_vec()
                        } else {
                            vec![]
                        },
                        current_chain_tip: Some(
                            crate::util::text_id::decode_base32_crockford(sender_chain_tip)
                                .ok_or_else(|| {
                                    DsmError::invalid_operation("sender_chain_tip not valid base32")
                                })?,
                        ),
                        added_at: crate::util::deterministic_time::tick(),
                        verified: true,
                        verification_proof: Some(proof.clone()),
                        metadata: {
                            let mut meta = std::collections::HashMap::new();
                            meta.insert("relationship_type".to_string(), relationship_type.clone());
                            meta.insert("message".to_string(), message.as_bytes().to_vec());
                            if !metadata.is_empty() {
                                meta.insert("metadata".to_string(), metadata.clone());
                            }
                            meta
                        },
                        ble_address: None,
                        status: "Active".to_string(),
                        needs_online_reconcile: false,
                        last_seen_online_counter: crate::util::deterministic_time::tick(),
                        last_seen_ble_counter: 0,
                        previous_chain_tip: None,
                    };

                    client_db::store_contact(&contact).map_err(|e| {
                        DsmError::internal(
                            format!("failed to store contact: {e}"),
                            None::<std::convert::Infallible>,
                        )
                    })?;

                    log::info!(
                        "[apply_operation] ✅ added relationship/contact tx={} type={} from={}",
                        String::from_utf8_lossy(tx_id.as_bytes()),
                        String::from_utf8_lossy(relationship_type.as_slice()),
                        sender_device_id
                    );
                } else {
                    log::info!(
                        "[apply_operation] ℹ️  relationship not addressed to us tx={} from={}",
                        String::from_utf8_lossy(tx_id.as_bytes()),
                        sender_device_id
                    );
                }
                Ok(())
            }
            dsm::types::operations::Operation::CreateRelationship {
                counterparty_id,
                commitment,
                proof,
                mode: _,
                message,
                ..
            } => {
                // Similar to AddRelationship, create a contact record
                let local_device_id_bytes = crate::sdk::app_state::AppState::get_device_id()
                    .ok_or_else(|| DsmError::state_machine("missing local device_id (AppState)"))?;
                if local_device_id_bytes.len() != 32 {
                    return Err(DsmError::state_machine(
                        "local device_id must be 32 bytes (AppState corrupt)",
                    ));
                }

                let sender_id_bytes = crate::util::text_id::decode_base32_crockford(
                    sender_device_id,
                )
                .ok_or_else(|| DsmError::invalid_operation("sender_device_id not valid base32"))?;
                if sender_id_bytes.len() != 32 {
                    return Err(DsmError::invalid_operation(
                        "apply_operation_with_replay_protection: sender_device_id must decode to 32 bytes",
                    ));
                }

                let contact = client_db::ContactRecord {
                    contact_id: format!("contact_{}", sender_device_id),
                    device_id: sender_id_bytes.clone(),
                    alias: String::from_utf8_lossy(&counterparty_id).into_owned(),
                    genesis_hash: if commitment.len() >= 32 {
                        // Genesis hash embedded in first 32 bytes of commitment
                        commitment[..32].to_vec()
                    } else {
                        // Derive deterministic genesis hash from sender device ID
                        dsm_blake3::domain_hash(
                            "DSM/genesis-counterparty",
                            &[b"genesis/", sender_id_bytes.as_slice()].concat(),
                        )
                        .as_bytes()
                        .to_vec()
                    },
                    public_key: if proof.len() >= 32 {
                        // Public key embedded in first 32 bytes of proof
                        proof[..32].to_vec()
                    } else {
                        vec![]
                    },
                    current_chain_tip: Some(
                        crate::util::text_id::decode_base32_crockford(sender_chain_tip)
                            .ok_or_else(|| {
                                DsmError::invalid_operation("sender_chain_tip not valid base32")
                            })?,
                    ),
                    added_at: crate::util::deterministic_time::tick(),
                    verified: true,
                    verification_proof: Some(proof.clone()),
                    metadata: {
                        let mut meta = std::collections::HashMap::new();
                        meta.insert("counterparty_id".to_string(), counterparty_id.clone());
                        meta.insert("message".to_string(), message.as_bytes().to_vec());
                        if !commitment.is_empty() {
                            meta.insert("commitment".to_string(), commitment.clone());
                        }
                        meta
                    },
                    ble_address: None,
                    status: "Active".to_string(),
                    needs_online_reconcile: false,
                    last_seen_online_counter: crate::util::deterministic_time::tick(),
                    last_seen_ble_counter: 0,
                    previous_chain_tip: None,
                };

                client_db::store_contact(&contact).map_err(|e| {
                    DsmError::internal(
                        format!("failed to store contact: {e}"),
                        None::<std::convert::Infallible>,
                    )
                })?;

                log::info!(
                    "[apply_operation] ✅ created relationship/contact tx={} counterparty={} from={}",
                    String::from_utf8_lossy(tx_id.as_bytes()),
                    String::from_utf8_lossy(&counterparty_id),
                    sender_device_id
                );
                Ok(())
            }
            dsm::types::operations::Operation::Generic {
                operation_type,
                data: _,
                message: _,
                ..
            } => {
                // Generic operations are allowed but may not require specific database persistence
                // The state machine validation already occurred above
                log::info!(
                    "[apply_operation] ✅ applied generic operation tx={} type={} from={}",
                    String::from_utf8_lossy(tx_id.as_bytes()),
                    String::from_utf8_lossy(&operation_type),
                    sender_device_id
                );
                Ok(())
            }
            // For operations that don't require recipient-side database persistence,
            // we still allow them through since state machine validation passed
            dsm::types::operations::Operation::Mint { .. } => {
                log::info!(
                    "[apply_operation] ✅ applied mint operation tx={} from={}",
                    String::from_utf8_lossy(tx_id.as_bytes()),
                    sender_device_id
                );
                Ok(())
            }
            dsm::types::operations::Operation::Burn { .. } => {
                log::info!(
                    "[apply_operation] ✅ applied burn operation tx={} from={}",
                    String::from_utf8_lossy(tx_id.as_bytes()),
                    sender_device_id
                );
                Ok(())
            }
            dsm::types::operations::Operation::Lock { .. } => {
                log::info!(
                    "[apply_operation] ✅ applied lock operation tx={} from={}",
                    String::from_utf8_lossy(tx_id.as_bytes()),
                    sender_device_id
                );
                Ok(())
            }
            dsm::types::operations::Operation::Unlock { .. } => {
                log::info!(
                    "[apply_operation] ✅ applied unlock operation tx={} from={}",
                    String::from_utf8_lossy(tx_id.as_bytes()),
                    sender_device_id
                );
                Ok(())
            }
            dsm::types::operations::Operation::LockToken { .. } => {
                log::info!(
                    "[apply_operation] ✅ applied lock_token operation tx={} from={}",
                    String::from_utf8_lossy(tx_id.as_bytes()),
                    sender_device_id
                );
                Ok(())
            }
            dsm::types::operations::Operation::UnlockToken { .. } => {
                log::info!(
                    "[apply_operation] ✅ applied unlock_token operation tx={} from={}",
                    String::from_utf8_lossy(tx_id.as_bytes()),
                    sender_device_id
                );
                Ok(())
            }
            dsm::types::operations::Operation::CreateToken { .. } => {
                log::info!(
                    "[apply_operation] ✅ applied create_token operation tx={} from={}",
                    String::from_utf8_lossy(tx_id.as_bytes()),
                    sender_device_id
                );
                Ok(())
            }
            dsm::types::operations::Operation::Update { .. } => {
                log::info!(
                    "[apply_operation] ✅ applied update operation tx={} from={}",
                    String::from_utf8_lossy(tx_id.as_bytes()),
                    sender_device_id
                );
                Ok(())
            }
            dsm::types::operations::Operation::RemoveRelationship { .. } => {
                log::info!(
                    "[apply_operation] ✅ applied remove_relationship operation tx={} from={}",
                    String::from_utf8_lossy(tx_id.as_bytes()),
                    sender_device_id
                );
                Ok(())
            }
            dsm::types::operations::Operation::Recovery { .. } => {
                log::info!(
                    "[apply_operation] ✅ applied recovery operation tx={} from={}",
                    String::from_utf8_lossy(tx_id.as_bytes()),
                    sender_device_id
                );
                Ok(())
            }
            dsm::types::operations::Operation::Delete { .. } => {
                log::info!(
                    "[apply_operation] ✅ applied delete operation tx={} from={}",
                    String::from_utf8_lossy(tx_id.as_bytes()),
                    sender_device_id
                );
                Ok(())
            }
            dsm::types::operations::Operation::Link { .. } => {
                log::info!(
                    "[apply_operation] ✅ applied link operation tx={} from={}",
                    String::from_utf8_lossy(tx_id.as_bytes()),
                    sender_device_id
                );
                Ok(())
            }
            dsm::types::operations::Operation::Unlink { .. } => {
                log::info!(
                    "[apply_operation] ✅ applied unlink operation tx={} from={}",
                    String::from_utf8_lossy(tx_id.as_bytes()),
                    sender_device_id
                );
                Ok(())
            }
            dsm::types::operations::Operation::Invalidate { .. } => {
                log::info!(
                    "[apply_operation] ✅ applied invalidate operation tx={} from={}",
                    String::from_utf8_lossy(tx_id.as_bytes()),
                    sender_device_id
                );
                Ok(())
            }
            dsm::types::operations::Operation::Genesis => {
                log::info!(
                    "[apply_operation] ✅ applied genesis operation tx={} from={}",
                    String::from_utf8_lossy(tx_id.as_bytes()),
                    sender_device_id
                );
                Ok(())
            }
            dsm::types::operations::Operation::Noop => {
                log::info!(
                    "[apply_operation] ✅ applied noop operation tx={} from={}",
                    String::from_utf8_lossy(tx_id.as_bytes()),
                    sender_device_id
                );
                Ok(())
            }
            dsm::types::operations::Operation::DlvCreate { .. } => {
                log::info!(
                    "[apply_operation] applied dlv_create operation tx={} from={}",
                    String::from_utf8_lossy(tx_id.as_bytes()),
                    sender_device_id
                );
                Ok(())
            }
            dsm::types::operations::Operation::DlvUnlock { .. } => {
                log::info!(
                    "[apply_operation] applied dlv_unlock operation tx={} from={}",
                    String::from_utf8_lossy(tx_id.as_bytes()),
                    sender_device_id
                );
                Ok(())
            }
            dsm::types::operations::Operation::DlvClaim { .. } => {
                log::info!(
                    "[apply_operation] applied dlv_claim operation tx={} from={}",
                    String::from_utf8_lossy(tx_id.as_bytes()),
                    sender_device_id
                );
                Ok(())
            }
            dsm::types::operations::Operation::DlvInvalidate { .. } => {
                log::info!(
                    "[apply_operation] applied dlv_invalidate operation tx={} from={}",
                    String::from_utf8_lossy(tx_id.as_bytes()),
                    sender_device_id
                );
                Ok(())
            }
        }
    }
}

/* ---------------------------------- Tests ----------------------------------- */

#[cfg(test)]
mod tests {
    use super::*;
    use dsm::types::operations::Operation as DsmOperation;
    use serial_test::serial;

    fn rt() -> tokio::runtime::Runtime {
        match tokio::runtime::Runtime::new() {
            Ok(rt) => rt,
            Err(e) => panic!("Failed to create runtime: {:?}", e),
        }
    }

    fn test_sdk() -> CoreSDK {
        let dev = DeviceInfo::from_hashed_label("test_device", vec![1u8; 32]);
        match CoreSDK::new_with_device(dev) {
            Ok(sdk) => sdk,
            Err(e) => panic!("Failed to init SDK: {:?}", e),
        }
    }

    #[test]
    fn sign_operation_matches_raw_signature_preimage_hash() {
        let sdk = test_sdk();
        let op = DsmOperation::Generic {
            operation_type: b"op_type".to_vec(),
            data: vec![0xAA, 0xBB, 0xCC],
            message: "hello".to_string(),
            signature: vec![],
        };

        let r = rt();
        // Sign via public API
        let sig = match r.block_on(sdk.sign_operation(&op)) {
            Ok(sig) => sig,
            Err(e) => panic!("Failed to sign op: {:?}", e),
        };

        // Recreate the signing preimage (private helper) and sign_raw on the same bytes
        let op_bytes = encode_dsm_operation_det(&op);
        let expected = match r.block_on(sdk.sign_raw(&op_bytes)) {
            Ok(sig) => sig,
            Err(e) => panic!("Failed to sign raw preimage: {:?}", e),
        };

        // Signatures must match exactly and be the deterministic BLAKE3 hash output length.
        assert_eq!(
            sig, expected,
            "sign_operation must equal sign_raw over preimage"
        );
        assert_eq!(sig.len(), 32, "signature length must be BLAKE3 output");

        // Hash of the operation bytes is stable across invocations (tracks the hash deterministically).
        let h1 = blake3::hash(&op_bytes);
        let h2 = blake3::hash(&encode_dsm_operation_det(&op));
        assert_eq!(
            h1.as_bytes(),
            h2.as_bytes(),
            "operation hash must be stable/symmetric"
        );
    }

    #[test]
    fn sign_operation_is_deterministic_across_calls() {
        let sdk = test_sdk();
        let op = DsmOperation::Generic {
            operation_type: b"deterministic".to_vec(),
            data: vec![1, 2, 3, 4],
            message: "m".to_string(),
            signature: vec![],
        };

        let r = rt();
        let sig1 = match r.block_on(sdk.sign_operation(&op)) {
            Ok(sig) => sig,
            Err(e) => panic!("Failed to get sig1: {:?}", e),
        };
        let sig2 = match r.block_on(sdk.sign_operation(&op)) {
            Ok(sig) => sig,
            Err(e) => panic!("Failed to get sig2: {:?}", e),
        };
        assert_eq!(
            sig1, sig2,
            "signing must be deterministic for identical input"
        );
    }

    #[test]
    #[serial]
    fn execute_operation_archives_and_restores_latest_state() {
        unsafe {
            std::env::set_var("DSM_SDK_TEST_MODE", "1");
        }
        let _ = crate::storage_utils::set_storage_base_dir(
            std::env::temp_dir().join("dsm_core_sdk_archive_state_test"),
        );
        crate::storage::client_db::reset_database_for_tests();
        crate::storage::client_db::init_database().expect("init db");

        crate::sdk::app_state::AppState::reset_memory_for_testing();
        crate::sdk::app_state::AppState::prime_memory_for_testing();
        crate::sdk::signing_authority::clear_binding_key_for_testing();
        let device_id = vec![0x43; 32];
        let genesis_hash = vec![0x53; 32];
        let binding_key = vec![0x63; 32];
        let (public_key, _secret_key) =
            crate::sdk::signing_authority::derive_signing_keys_for_testing(
                &device_id,
                &genesis_hash,
                &binding_key,
            )
            .expect("derive canonical signing keypair");
        crate::sdk::signing_authority::set_binding_key_for_testing(binding_key);
        crate::sdk::app_state::AppState::set_identity_info(
            device_id.clone(),
            public_key.clone(),
            genesis_hash,
            vec![0u8; 32],
        );
        let device = DeviceInfo::new(device_id.try_into().expect("device id"), public_key.clone());
        let sdk = CoreSDK::new_with_device(device.clone()).expect("init sdk");
        sdk.initialize_with_genesis_state()
            .expect("initialize genesis state");
        let current = sdk
            .get_current_state()
            .expect("current state after genesis");
        assert_eq!(current.device_info.public_key, device.public_key);

        let op = sdk
            .sign_operation_sphincs(DsmOperation::Generic {
                operation_type: b"archive.test".to_vec(),
                data: vec![0xAB, 0xCD],
                message: "persist state".to_string(),
                signature: vec![],
            })
            .expect("sign operation");
        let signature = op.get_signature().expect("signature present");
        let payload = op.with_cleared_signature().to_bytes();
        assert!(
            dsm::crypto::sphincs::sphincs_verify(&device.public_key, &payload, &signature)
                .expect("direct signature verify"),
            "canonical CoreSDK test signature must self-verify"
        );

        let executed = sdk.execute_dsm_operation(op).expect("execute operation");
        assert!(executed.hash[0] as u64 > 0, "state number should advance");

        let archived = crate::storage::client_db::get_bcr_states(&device.device_id, false)
            .expect("load archived states");
        assert!(
            archived
                .iter()
                .any(|state| state.hash[0] as u64 == executed.hash[0] as u64),
            "executed canonical state must be archived for sparse replay"
        );

        let restored = CoreSDK::new_with_device(device).expect("restore sdk from archive");
        let restored_state = restored.get_current_state().expect("current state");
        assert_eq!(
            restored_state.hash[0] as u64, executed.hash[0] as u64,
            "CoreSDK startup must restore the latest archived canonical state"
        );
        assert_eq!(
            restored_state.hash, executed.hash,
            "restored canonical state hash must match archived state"
        );
    }

    #[test]
    #[serial]
    fn restore_state_snapshot_rewinds_in_memory_tip() {
        unsafe {
            std::env::set_var("DSM_SDK_TEST_MODE", "1");
        }
        let _ = crate::storage_utils::set_storage_base_dir(
            std::env::temp_dir().join("dsm_core_sdk_rollback_state_test"),
        );
        crate::storage::client_db::reset_database_for_tests();
        crate::storage::client_db::init_database().expect("init db");

        crate::sdk::app_state::AppState::reset_memory_for_testing();
        crate::sdk::app_state::AppState::prime_memory_for_testing();
        crate::sdk::signing_authority::clear_binding_key_for_testing();
        let device_id = vec![0x47; 32];
        let genesis_hash = vec![0x57; 32];
        let binding_key = vec![0x67; 32];
        let (public_key, _secret_key) =
            crate::sdk::signing_authority::derive_signing_keys_for_testing(
                &device_id,
                &genesis_hash,
                &binding_key,
            )
            .expect("derive canonical signing keypair");
        crate::sdk::signing_authority::set_binding_key_for_testing(binding_key);
        crate::sdk::app_state::AppState::set_identity_info(
            device_id.clone(),
            public_key.clone(),
            genesis_hash,
            vec![0u8; 32],
        );
        let device = DeviceInfo::new(device_id.try_into().expect("device id"), public_key.clone());
        let sdk = CoreSDK::new_with_device(device.clone()).expect("init sdk");
        sdk.initialize_with_genesis_state()
            .expect("initialize genesis state");
        let current = sdk
            .get_current_state()
            .expect("current state after genesis");
        assert_eq!(current.device_info.public_key, device.public_key);
        let prior = sdk.get_current_state().expect("prior state");

        let op = sdk
            .sign_operation_sphincs(DsmOperation::Generic {
                operation_type: b"rollback.test".to_vec(),
                data: vec![0x01],
                message: "advance".to_string(),
                signature: vec![],
            })
            .expect("sign operation");
        let signature = op.get_signature().expect("signature present");
        let payload = op.with_cleared_signature().to_bytes();
        assert!(
            dsm::crypto::sphincs::sphincs_verify(&device.public_key, &payload, &signature)
                .expect("direct signature verify"),
            "canonical CoreSDK test signature must self-verify"
        );
        let advanced = sdk.execute_dsm_operation(op).expect("execute operation");
        assert!(
            advanced.hash[0] as u64 > prior.hash[0] as u64,
            "state must advance"
        );

        sdk.restore_state_snapshot(&prior)
            .expect("restore prior snapshot");
        let current = sdk.get_current_state().expect("current state");
        assert_eq!(current.hash[0] as u64, prior.hash[0] as u64);
        assert_eq!(current.hash, prior.hash);
    }
}

/* ---------------------------- Result Structures ------------------------- */

#[derive(Debug, Clone)]
pub struct GenesisInfo {
    pub genesis_hash: Vec<u8>,
    pub device_id: Vec<u8>,
    pub public_key: Vec<u8>,
    pub smt_root: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct TransferResult {
    pub tx_id: Vec<u8>,
    pub new_chain_tip: u64,
    pub new_state_hash: Vec<u8>,
    pub smt_proof: Vec<u8>,
    pub bilateral_signature: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct StateQueryInfo {
    pub current_state_hash: Vec<u8>,
    pub current_position: u64,
    pub state_entries: Vec<StateEntry>,
    pub smt_root: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct StateEntry {
    pub position: u64,
    pub state_hash: Vec<u8>,
    pub prev_hash: Vec<u8>,
    pub operation_data: Vec<u8>,
    /// Clockless build: set to 0
    pub tick: u64,
    pub smt_proof: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct ContactInfo {
    pub genesis_hash: Vec<u8>,
    pub public_key: Vec<u8>,
    pub chain_tip: Vec<u8>, // Changed from u64 to Vec<u8> (hash)
    pub challenge_response: Vec<u8>,
    pub bilateral_anchor: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct TokenPolicyInfo {
    pub policy_hash: Vec<u8>,
    pub is_valid: bool,
    pub verification_proof: Vec<u8>,
    pub total_supply: u64,
}

#[derive(Debug, Clone)]
pub struct SyncInfo {
    pub sync_needed: bool,
    pub missing_states: Vec<StateEntry>,
    pub updated_peers: Vec<Vec<u8>>,
    pub new_smt_root: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct NetworkStatus {
    pub network_type: String,
    pub connected_peers: u32,
    pub connection_status: String,
    pub is_syncing: bool,
    /// Clockless build: 0
    pub last_sync_time: u64,
}

#[derive(Debug, Clone)]
pub struct DiscoveryResult {
    pub total_discovered: u32,
    pub network_type: String,
    pub node_addresses: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct TokenBalanceInfo {
    pub balance: u64,
    pub token_id: Vec<u8>,
    pub last_updated: u64,
    pub history: Vec<BalanceEntry>,
    pub genesis_hash: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct BalanceEntry {
    pub position: u64,
    pub balance: u64,
    /// Clockless: 0 unless caller provides
    pub tick: u64,
}

#[derive(Debug, Clone)]
pub struct AppStateResult {
    pub value: Option<String>,
}

#[derive(Debug, Clone)]
pub struct BackupResult {
    pub backup_phrase: Option<String>,
    pub is_valid: bool,
}

#[derive(Debug, Clone)]
pub struct SettingResult {
    pub value: Option<String>,
}

#[derive(Debug, Clone)]
pub struct BluetoothResult {
    pub enabled: bool,
    pub available: bool,
}
