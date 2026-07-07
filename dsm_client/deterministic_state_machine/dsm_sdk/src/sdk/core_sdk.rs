// SPDX-License-Identifier: MIT OR Apache-2.0

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
use std::collections::HashMap;
use std::sync::atomic::AtomicU64;

use dsm::core::identity::genesis::create_genesis_via_blind_mpc_with_contributors;
use dsm::core::identity::genesis_session::generate_device_entropy;
use dsm::core::state_machine::StateMachine;
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
    /// Device-level Boot Fenced Fused Anchor appliance (in-process; real WOTS+SPHINCS+, mock
    /// silicon). Lazily birthed on the first offline-bearer transfer; persists across transfers so
    /// its down-counter + fused-anchor lineage advance. Its `commit_0` is bootstrapped into the
    /// DeviceState anchor-state leaf on birth; each bearer transfer drives PREPARE→COMMIT→EMIT→
    /// FINALIZE and advances the leaf in the same `DeviceState::advance`.
    anchor_appliance: Mutex<Option<Box<dyn crate::anchor::AnchorAppliance + Send>>>,
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
        if let Some(head) =
            crate::storage::client_db::load_bcr_device_head(device_id).map_err(|e| {
                DsmError::state_machine(format!(
                    "Failed to load cached device head during startup restore: {e}"
                ))
            })?
        {
            let root = head.root();
            state_machine.lock().set_device_head(head);
            log::info!(
                "[CoreSDK] restored cached device head root={} for device {}",
                crate::util::text_id::encode_base32_crockford(&root),
                crate::util::text_id::encode_base32_crockford(device_id)
            );
        }

        Ok(())
    }

    /// Phase 4.1 — fail-closed dual-write at the AdvanceOutcome chokepoint.
    ///
    /// Writes one row to `bcr_chain_states` (authoritative per-advance
    /// archive) and UPSERTs one row to `bcr_device_heads` (latest head cache)
    /// in a single SQLite transaction. Both come from the same in-memory
    /// `AdvanceOutcome` so there is no consistency window.
    ///
    /// Called BETWEEN `StateMachine::prepare_advance_relationship` and
    /// `StateMachine::commit_advance`. If this returns `Err`, the caller
    /// (`execute_on_relationship`) skips the commit step — the in-memory head
    /// is unchanged and the operation is observable as never-happened. This
    /// makes BCR persistence durable before the head is installed.
    fn dual_write_advance_outcome(
        outcome: &dsm::types::device_state::AdvanceOutcome,
        bump_capsule: bool,
    ) -> Result<(), DsmError> {
        use crate::storage::client_db::{
            get_connection, store_bcr_chain_state_with_conn, update_bcr_device_head_with_conn,
        };
        use crate::util::deterministic_time::tick;

        let devid = outcome.new_device_state.devid();
        let now = tick();

        let binding = get_connection().map_err(|e| {
            DsmError::storage(
                format!("dual-write: get_connection failed: {e}"),
                None::<std::io::Error>,
            )
        })?;
        let mut conn = binding.lock().unwrap_or_else(|poisoned| {
            log::warn!("[CoreSDK] dual-write: DB lock poisoned, recovering");
            poisoned.into_inner()
        });

        let tx = conn.transaction().map_err(|e| {
            DsmError::storage(
                format!("dual-write: begin transaction failed: {e}"),
                None::<std::io::Error>,
            )
        })?;

        store_bcr_chain_state_with_conn(&tx, &devid, &outcome.new_chain_state, false, now)
            .map_err(|e| {
                DsmError::storage(
                    format!("dual-write: store_bcr_chain_state failed: {e}"),
                    None::<std::io::Error>,
                )
            })?;
        update_bcr_device_head_with_conn(&tx, &outcome.new_device_state, now).map_err(|e| {
            DsmError::storage(
                format!("dual-write: update_bcr_device_head failed: {e}"),
                None::<std::io::Error>,
            )
        })?;
        // Capsule currency (spec §5.1): advance the accepted-state index ATOMICALLY
        // with the state commit so a frontier-changing transition can never be
        // persisted without the recovery capsule being marked dirty. Closes the
        // post-commit fail-OPEN (a missed bump on already-committed state). Uses
        // the transaction's own connection — never opens a new one (deadlock).
        if bump_capsule {
            crate::storage::client_db::recovery::bump_accepted_state_index_with_conn(&tx).map_err(
                |e| {
                    DsmError::storage(
                        format!("dual-write: bump accepted_state_index failed: {e}"),
                        None::<std::io::Error>,
                    )
                },
            )?;
        }
        tx.commit().map_err(|e| {
            DsmError::storage(
                format!("dual-write: commit failed: {e}"),
                None::<std::io::Error>,
            )
        })?;
        Ok(())
    }

    /// Explicit head-cache write for genesis.
    ///
    /// Genesis has no `AdvanceOutcome` (no relationships exist yet), but the
    /// `bcr_device_heads` cache needs a row so restore / reader paths can
    /// locate the device. The `genesis_hash` argument is the canonical
    /// `G_A` digest from the genesis state — it populates `DeviceState.genesis`
    /// (§2.2) and is also used as the legacy SMT-root anchor for the
    /// initial head so `verify_state` checks against the genesis hash work
    /// before any relationship advance has fired.
    fn write_genesis_device_head(&self, genesis_hash: [u8; 32]) -> Result<(), DsmError> {
        use crate::storage::client_db::update_bcr_device_head;
        let mut head = self.device_head().unwrap_or_else(|| {
            dsm::types::device_state::DeviceState::new(
                genesis_hash,
                self.device_info.device_id,
                self.device_info.public_key.clone(),
                1024,
            )
        });
        if head.legacy_anchor().is_none() {
            head.bootstrap_legacy_root(genesis_hash);
        }
        update_bcr_device_head(&head).map_err(|e| {
            DsmError::storage(
                format!("genesis head-cache write failed: {e}"),
                None::<std::io::Error>,
            )
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

        let state_machine = Mutex::new(StateMachine::new());

        Self::restore_latest_archived_state(&state_machine, &device_info.device_id)?;

        Ok(Self {
            state_machine,
            device_info,
            policy_system,
            audit_ctr: AtomicU64::new(0),
            anchor_appliance: Mutex::new(None),
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

    /// Current tip state (fail-closed if none).
    ///
    /// Returns a compatibility `State` view derived from the canonical
    /// `DeviceState`. Prefer `device_head()` for new code.
    pub fn get_current_state(&self) -> Result<State, DsmError> {
        // Delegate to StateMachine::current_state so callers always see the
        // single source of truth: an explicit `legacy_state` (set via
        // `set_state` / `restore_state_snapshot`) wins over the projected
        // DeviceState view. If no legacy_state is pinned, the StateMachine
        // synthesizes a compat State from the DeviceState head's SMT root +
        // balances. Pre-genesis paths return None which we surface as an
        // explicit error.
        let sm = self.state_machine.lock();
        sm.current_state()
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
        let state = match sm.current_state() {
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
        let initial_entropy = [0u8; 32];
        let mut genesis_state = State::new_genesis(initial_entropy, self.device_info.clone());
        // Precompute and embed the hash so tests and callers see a non-empty hash field
        if let Ok(h) = genesis_state.compute_hash() {
            genesis_state.hash = h;
        }
        let snapshot = {
            let mut sm = self.state_machine.lock();
            let snapshot = genesis_state.clone();
            sm.set_state(genesis_state);
            snapshot
        };
        self.write_genesis_device_head(snapshot.hash)?;
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

        // Route through relationship path with self-loop for generic ops
        let dev_id = self.get_current_state()?.device_info.device_id;
        let rel_key = dsm::core::bilateral_transaction_manager::compute_smt_key(&dev_id, &dev_id);
        let init_tip = dsm::core::bilateral_transaction_manager::initial_chain_tip_from_device_ids(
            &dev_id, &dev_id,
        );
        let (state, _) =
            self.execute_on_relationship(rel_key, dev_id, dsm_op, &[], Some(init_tip))?;
        Ok(state)
    }

    /// Register a CPTA policy for a custom token with the underlying
    /// `TokenPolicySystem`.  This is the authoritative step that makes the
    /// policy visible to `PolicyEnforcer` and binds `policy_commit =
    /// PolicyAnchor::from_policy(&policy_file)` for all subsequent balance
    /// ops on `token_id`.
    ///
    /// Must run before any balance-changing op references `token_id`.
    pub async fn register_token_policy(
        &self,
        token_id: &str,
        policy_file: dsm::types::policy_types::PolicyFile,
    ) -> Result<dsm::types::policy_types::PolicyAnchor, DsmError> {
        self.policy_system
            .register_token_policy(token_id, policy_file)
            .await
    }

    /// Register policy bytes while preserving an externally-authoritative
    /// policy anchor (for example, a storage-layer `DSM/policy` commitment).
    pub async fn register_token_policy_with_anchor(
        &self,
        token_id: &str,
        policy_file: dsm::types::policy_types::PolicyFile,
        anchor: [u8; 32],
    ) -> Result<(), DsmError> {
        self.policy_system
            .register_token_policy_with_anchor(
                token_id,
                policy_file,
                dsm::types::policy_types::PolicyAnchor::from_bytes(anchor),
            )
            .await
    }

    fn canonical_token_id_str(token_id: &[u8]) -> Option<&str> {
        std::str::from_utf8(token_id)
            .ok()
            .map(str::trim)
            .filter(|s| !s.is_empty())
    }

    fn build_token_policy_context(
        operation: &dsm::types::operations::Operation,
        state_hash: [u8; 32],
    ) -> Result<Option<(String, String, HashMap<String, Vec<u8>>)>, DsmError> {
        let mut context = HashMap::new();
        context.insert(
            "tick".to_string(),
            dsm::utils::deterministic_time::tick_index()
                .to_le_bytes()
                .to_vec(),
        );
        context.insert("state_hash".to_string(), state_hash.to_vec());

        match operation {
            DsmOperation::Transfer {
                token_id,
                amount,
                recipient,
                ..
            } => {
                let token_id = Self::canonical_token_id_str(token_id).ok_or_else(|| {
                    DsmError::invalid_operation(
                        "Policy enforcement rejected: malformed or empty token_id",
                    )
                })?;
                let amount_u64 = amount.value();
                context.insert("amount_u64".to_string(), amount_u64.to_le_bytes().to_vec());
                context.insert("amount".to_string(), amount_u64.to_string().into_bytes());
                context.insert("recipient".to_string(), recipient.clone());
                Ok(Some((
                    token_id.to_string(),
                    "transfer".to_string(),
                    context,
                )))
            }
            DsmOperation::Mint {
                token_id,
                amount,
                authorized_by,
                ..
            } => {
                let token_id = Self::canonical_token_id_str(token_id).ok_or_else(|| {
                    DsmError::invalid_operation(
                        "Policy enforcement rejected: malformed or empty token_id",
                    )
                })?;
                let amount_u64 = amount.value();
                context.insert("amount_u64".to_string(), amount_u64.to_le_bytes().to_vec());
                context.insert("amount".to_string(), amount_u64.to_string().into_bytes());
                context.insert("authorized_by".to_string(), authorized_by.clone());
                Ok(Some((token_id.to_string(), "mint".to_string(), context)))
            }
            DsmOperation::Burn {
                token_id, amount, ..
            } => {
                let token_id = Self::canonical_token_id_str(token_id).ok_or_else(|| {
                    DsmError::invalid_operation(
                        "Policy enforcement rejected: malformed or empty token_id",
                    )
                })?;
                let amount_u64 = amount.value();
                context.insert("amount_u64".to_string(), amount_u64.to_le_bytes().to_vec());
                context.insert("amount".to_string(), amount_u64.to_string().into_bytes());
                Ok(Some((token_id.to_string(), "burn".to_string(), context)))
            }
            DsmOperation::Lock {
                token_id,
                amount,
                purpose,
                owner,
                ..
            } => {
                let token_id = Self::canonical_token_id_str(token_id).ok_or_else(|| {
                    DsmError::invalid_operation(
                        "Policy enforcement rejected: malformed or empty token_id",
                    )
                })?;
                let amount_u64 = amount.value();
                context.insert("amount_u64".to_string(), amount_u64.to_le_bytes().to_vec());
                context.insert("amount".to_string(), amount_u64.to_string().into_bytes());
                context.insert("purpose".to_string(), purpose.clone());
                context.insert("owner".to_string(), owner.clone());
                Ok(Some((token_id.to_string(), "lock".to_string(), context)))
            }
            DsmOperation::Unlock {
                token_id,
                amount,
                purpose,
                owner,
                ..
            } => {
                let token_id = Self::canonical_token_id_str(token_id).ok_or_else(|| {
                    DsmError::invalid_operation(
                        "Policy enforcement rejected: malformed or empty token_id",
                    )
                })?;
                let amount_u64 = amount.value();
                context.insert("amount_u64".to_string(), amount_u64.to_le_bytes().to_vec());
                context.insert("amount".to_string(), amount_u64.to_string().into_bytes());
                context.insert("purpose".to_string(), purpose.clone());
                context.insert("owner".to_string(), owner.clone());
                Ok(Some((token_id.to_string(), "unlock".to_string(), context)))
            }
            DsmOperation::LockToken {
                token_id,
                amount,
                purpose,
                ..
            } => {
                let token_id = Self::canonical_token_id_str(token_id).ok_or_else(|| {
                    DsmError::invalid_operation(
                        "Policy enforcement rejected: malformed or empty token_id",
                    )
                })?;
                let amount_u64 = u64::try_from(*amount).map_err(|_| {
                    DsmError::invalid_operation(
                        "Policy enforcement rejected: LockToken amount must be non-negative",
                    )
                })?;
                context.insert("amount_u64".to_string(), amount_u64.to_le_bytes().to_vec());
                context.insert("amount".to_string(), amount_u64.to_string().into_bytes());
                context.insert("purpose".to_string(), purpose.clone());
                Ok(Some((token_id.to_string(), "lock".to_string(), context)))
            }
            DsmOperation::UnlockToken {
                token_id,
                amount,
                purpose,
                ..
            } => {
                let token_id = Self::canonical_token_id_str(token_id).ok_or_else(|| {
                    DsmError::invalid_operation(
                        "Policy enforcement rejected: malformed or empty token_id",
                    )
                })?;
                let amount_u64 = u64::try_from(*amount).map_err(|_| {
                    DsmError::invalid_operation(
                        "Policy enforcement rejected: UnlockToken amount must be non-negative",
                    )
                })?;
                context.insert("amount_u64".to_string(), amount_u64.to_le_bytes().to_vec());
                context.insert("amount".to_string(), amount_u64.to_string().into_bytes());
                context.insert("purpose".to_string(), purpose.clone());
                Ok(Some((token_id.to_string(), "unlock".to_string(), context)))
            }
            _ => Ok(None),
        }
    }

    fn enforce_policy_for_operation(
        &self,
        operation: &dsm::types::operations::Operation,
        state_hash: [u8; 32],
    ) -> Result<(), DsmError> {
        let Some((token_id, op_type, context)) =
            Self::build_token_policy_context(operation, state_hash)?
        else {
            return Ok(());
        };

        let result = if tokio::runtime::Handle::try_current().is_ok() {
            let policy_system = self.policy_system.clone();
            let token_id_for_thread = token_id.clone();
            let op_type_for_thread = op_type.clone();
            let context_for_thread = context.clone();
            let join_res = std::thread::spawn(move || {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|e| {
                        DsmError::internal(
                            format!("Failed to build runtime for policy enforcement: {e}"),
                            None::<std::convert::Infallible>,
                        )
                    })?;
                rt.block_on(async {
                    policy_system
                        .enforce_policy(
                            &token_id_for_thread,
                            &op_type_for_thread,
                            &context_for_thread,
                        )
                        .await
                })
            })
            .join();

            match join_res {
                Ok(res) => res?,
                Err(_) => {
                    return Err(DsmError::internal(
                        "Failed to join policy enforcement thread",
                        None::<std::convert::Infallible>,
                    ));
                }
            }
        } else {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|e| {
                    DsmError::internal(
                        format!("Failed to build runtime for policy enforcement: {e}"),
                        None::<std::convert::Infallible>,
                    )
                })?;

            rt.block_on(async {
                self.policy_system
                    .enforce_policy(&token_id, &op_type, &context)
                    .await
            })?
        };

        if !result.allowed {
            return Err(DsmError::policy_violation(
                token_id,
                result.reason,
                None::<std::convert::Infallible>,
            ));
        }

        Ok(())
    }

    /// Execute a DSM operation on a specific relationship chain (§2.2, §4.2).
    ///
    /// Returns `(State, AdvanceOutcome)` where the `State` is a compatibility
    /// view derived from the AdvanceOutcome's DeviceState + chain state. The
    /// `State` will be removed once all downstream readers migrate to
    /// `DeviceState`.
    /// Ordinary advance (no fused-anchor-state leaf). Thin wrapper over
    /// [`Self::execute_on_relationship_with_anchor_leaf`] with `anchor_leaf = None`, so the many
    /// non-bearer callers stay unchanged.
    pub fn execute_on_relationship(
        &self,
        rel_key: [u8; 32],
        counterparty_devid: [u8; 32],
        operation: dsm::types::operations::Operation,
        deltas: &[dsm::types::device_state::BalanceDelta],
        initial_chain_tip: Option<[u8; 32]>,
    ) -> Result<(State, dsm::types::device_state::AdvanceOutcome), DsmError> {
        self.execute_on_relationship_with_anchor_leaf(
            rel_key,
            counterparty_devid,
            operation,
            deltas,
            initial_chain_tip,
            None,
        )
    }

    /// Advance the relationship, optionally committing an offline-bearer fused-anchor-state leaf
    /// (`anchor_leaf`) ATOMICALLY with the relationship leaf. The bilateral confirm path passes the
    /// same `anchor_leaf` its `simulate_advance_for_confirm` used, so the committed device root
    /// matches the on-wire proofs (both-or-neither); ordinary advances pass `None`.
    pub fn execute_on_relationship_with_anchor_leaf(
        &self,
        rel_key: [u8; 32],
        counterparty_devid: [u8; 32],
        operation: dsm::types::operations::Operation,
        deltas: &[dsm::types::device_state::BalanceDelta],
        initial_chain_tip: Option<[u8; 32]>,
        anchor_leaf: Option<dsm::types::device_state::AnchorLeafUpdate>,
    ) -> Result<(State, dsm::types::device_state::AdvanceOutcome), DsmError> {
        // Phase 0 fail-closed recovery gate (spec condition R3): block
        // owner-initiated value egress while identity recovery is in progress.
        // `is_value_egress` is an exhaustive classifier (dsm core), so value
        // ingress (Receive/Mint) and identity/recovery operations still advance,
        // and any new Operation variant must be consciously classified. This is
        // the canonical state-advance chokepoint, so it covers bilateral
        // transfers, token ops, and DLV ops in one place.
        // Recovery egress gate (spec R3) + capsule currency (spec §5.1). Classify
        // before `operation` is moved into the advance.
        let is_egress = operation.is_value_egress();
        let frontier_changed = !matches!(
            operation,
            dsm::types::operations::Operation::Noop | dsm::types::operations::Operation::Genesis
        );

        // R2′ optimistic self-heal (BEFORE the lock, only when the capsule is
        // stale): re-seal so a current device is not needlessly blocked, while
        // keeping the heavy capsule rebuild off the hot path when already current.
        if is_egress && crate::storage::client_db::recovery::is_capsule_dirty() {
            crate::sdk::recovery_sdk::RecoverySDK::maybe_refresh_nfc_capsule();
        }

        let mut sm = self.state_machine.lock();

        // Authoritative fail-closed egress gate UNDER the state-machine lock, so
        // the decision is atomic with the commit + capsule-currency bump below.
        // This closes the check-before-lock TOCTOU where two concurrent egress
        // ops could both pass before either marked the capsule dirty.
        if is_egress {
            if let Some(reason) = crate::storage::client_db::recovery::value_egress_block_reason() {
                return Err(DsmError::invalid_operation(reason));
            }
            // P5 per-asset bearer gate (spec §0.4): in ADDITION to the identity-level gate
            // above, a recovered bearer asset stays LockedRecovery until its OWN verified
            // frontier reconciles — this persists AFTER recovery activation and is keyed by
            // the operation's egress asset. Fail-closed (unreadable/locked → refuse).
            if let Some(reason) =
                crate::storage::client_db::recovery::asset_egress_block_reason(&operation)
            {
                return Err(DsmError::invalid_operation(reason));
            }
        }

        // Enforce token policy constraints on the operation that will advance
        // state. This closes the previous gap where registration existed but
        // execution path skipped policy checks.
        let current_state_hash = sm.device_head().map(|ds| ds.root()).unwrap_or([0u8; 32]);
        self.enforce_policy_for_operation(&operation, current_state_hash)?;

        // Phase 4.1 fail-closed pattern (§4.3 acceptance, §6.1 single-writer):
        //   1. PREPARE — derive the AdvanceOutcome (pure; no head mutation).
        //   2. WRITE  — persist `bcr_chain_states` + `bcr_device_heads` in one
        //      SQLite transaction. If this fails, the in-memory head is
        //      unchanged and the operation is observable as never-happened.
        //   3. COMMIT — install the new head only after persistence succeeded.
        // The `sm` lock is held across all three steps, so the prepare/write/
        // commit sequence is atomic with respect to other advances.
        let outcome = sm.prepare_advance_relationship(
            rel_key,
            counterparty_devid,
            operation,
            deltas,
            initial_chain_tip,
            anchor_leaf, // Some(..) commits the fused-anchor-state leaf atomically (offline-bearer)
        )?;
        // The accepted-state index is bumped ATOMICALLY inside this transaction
        // (spec §5.1) — a frontier-changing transition can never persist without
        // the capsule being marked dirty.
        Self::dual_write_advance_outcome(&outcome, frontier_changed)?;
        sm.commit_advance(&outcome);

        // Build a compatibility State view from the outcome for callers that
        // still read State fields. This is a derived view, not the source of
        // truth — DeviceState IS the truth.
        let compat_state = {
            let cs = &outcome.new_chain_state;
            let mut s = State::default();
            s.hash = cs.compute_chain_tip();
            s.prev_state_hash = cs.embedded_parent;
            s.entropy = cs.entropy.clone();
            s.operation = cs.operation.clone();
            s.device_info = dsm::types::state_types::DeviceInfo::new(
                outcome.new_device_state.devid(),
                outcome.new_device_state.public_key().to_vec(),
            );
            // Sync balances from DeviceState → legacy HashMap<String, Balance>
            // using the canonical `{prefix}|{token_id}` key format from
            // derive_canonical_balance_key so balance.list can locate balances
            // by their {token_id} suffix (e.g. "ERA", "dBTC").
            let public_key = outcome.new_device_state.public_key();
            for (pc, val) in outcome.new_device_state.balances_snapshot() {
                let token_id =
                    dsm::core::token::builtin_token_id_for_policy_commit(pc).unwrap_or("");
                let key = if token_id.is_empty() {
                    let prefix = u128::from_le_bytes({
                        let mut a = [0u8; 16];
                        a.copy_from_slice(&pc[..16]);
                        a
                    });
                    format!("{prefix}|?")
                } else {
                    dsm::core::token::derive_canonical_balance_key(pc, public_key, token_id)
                };
                s.token_balances.insert(
                    key,
                    dsm::types::token_types::Balance::from_state(*val, s.hash),
                );
            }
            s
        };

        Ok((compat_state, outcome))
    }

    /// Get the canonical DeviceState head (§2.2 SMT root).
    pub fn device_head(&self) -> Option<dsm::types::device_state::DeviceState> {
        self.state_machine.lock().device_head().cloned()
    }

    /// Prepare-only view of the canonical [`AdvanceOutcome`] for an advance
    /// that hasn't committed yet.
    ///
    /// Used by the BLE sender in `send_bilateral_confirm` to build the
    /// stitched receipt (§4.2) with the real post-advance SMT roots + proofs
    /// *before* the sender advances canonical state — the canonical commit
    /// happens later in `mark_sender_committed_with_post_state_hash` via
    /// `execute_on_relationship_for_bilateral`, which re-runs prepare and
    /// then commits. Identical inputs → identical outcome, so the simulated
    /// receipt is byte-exact with the eventual canonical advance.
    pub fn simulate_advance_for_confirm(
        &self,
        rel_key: [u8; 32],
        counterparty_devid: [u8; 32],
        operation: dsm::types::operations::Operation,
        deltas: &[dsm::types::device_state::BalanceDelta],
        initial_chain_tip: Option<[u8; 32]>,
        anchor_leaf: Option<dsm::types::device_state::AnchorLeafUpdate>,
    ) -> Result<dsm::types::device_state::AdvanceOutcome, DsmError> {
        let sm = self.state_machine.lock();
        sm.prepare_advance_relationship(
            rel_key,
            counterparty_devid,
            operation,
            deltas,
            initial_chain_tip,
            anchor_leaf,
        )
    }

    /// Read device-level balance for a token by its 32-byte CPTA policy_commit.
    /// This reads from DeviceState directly (no string-key projection).
    pub fn get_device_balance(&self, policy_commit: &[u8; 32]) -> u64 {
        self.state_machine
            .lock()
            .device_head()
            .map(|ds| ds.balance(policy_commit))
            .unwrap_or(0)
    }

    /// Read the device's SMT root (canonical head identity per §2.2).
    pub fn device_smt_root(&self) -> Option<[u8; 32]> {
        self.state_machine.lock().device_head().map(|ds| ds.root())
    }

    /// Commit a vault state leaf into the Per-Device SMT (SoFi spec
    /// §4.1.2 / §8.4 step 2).
    ///
    /// Mirrors `execute_on_relationship`'s prepare/write/commit
    /// pattern:
    ///   1. PREPARE — clone the head, write the leaf, capture root +
    ///      siblings (pure; no head mutation).
    ///   2. WRITE   — persist the new head into `bcr_device_heads`.
    ///      If this fails, the in-memory head is unchanged.
    ///   3. COMMIT  — install the new head on the StateMachine.
    ///
    /// Returns `(new_root, siblings)` ready for the caller to embed in
    /// a `VaultStateInclusionProofV1`.  The lock is held across all
    /// three steps so the prepare/write/commit sequence is atomic
    /// with respect to other writers.
    pub fn install_vault_state_leaf(
        &self,
        vault_id: &[u8; 32],
        sequence: u64,
        reserves_digest: &[u8; 32],
    ) -> Result<([u8; 32], Vec<[u8; 32]>), DsmError> {
        use crate::storage::client_db::update_bcr_device_head;

        let mut sm = self.state_machine.lock();
        let outcome = sm.prepare_vault_state_leaf(vault_id, sequence, reserves_digest)?;
        update_bcr_device_head(&outcome.new_device_state).map_err(|e| {
            DsmError::storage(
                format!("install_vault_state_leaf: device-head write failed: {e}"),
                None::<std::io::Error>,
            )
        })?;
        sm.commit_vault_state_leaf(&outcome);
        Ok((outcome.new_root, outcome.siblings))
    }

    pub fn register_token_manager(
        &self,
        _manager: Box<dyn TokenManagerTrait>,
    ) -> Result<(), DsmError> {
        log::info!("Token manager registered");
        Ok(())
    }

    // get_state_by_number(state_number: u64) deleted: per §4.3 there is no
    // state_number, and the function compared the requested number against
    // `state.hash[0] as u64` (a value in [0,255]) — a degenerate match that
    // returned arbitrary archived states rather than the requested one. All
    // 5 prior callers migrated to either a chain-state archive scan
    // (resolve_policy_commit_strict, find_token_metadata_operation) or to
    // local_genesis_hash() (token_mpc_sdk x3).

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

    /// MPC genesis (blind MPC) — no wall-clock time.
    ///
    /// `before_install` runs once the genesis hash is known but BEFORE
    /// any local installation steps fire. It is the integration point
    /// for Phase B.6 (issue #277): the storage-node SDK publishes the
    /// initial `DeviceTreeStateV1` to a quorum of storage nodes here.
    /// If the publisher returns `Err`, the genesis aborts:
    ///
    /// * No state-machine state or BCR device-head row is written.
    /// * No partial-genesis residue is left behind.
    ///
    /// Pass `|_| async { Ok(()) }` for the noop publisher (legacy
    /// callers + offline test fixtures that don't talk to a storage
    /// node cluster).
    pub async fn create_genesis_with_passive_contributors<P, Fut>(
        &self,
        device_id: Vec<u8>,
        mpc_participants: Vec<Vec<u8>>,
        client_entropy: Option<Vec<u8>>,
        before_install: P,
    ) -> Result<GenesisInfo, DsmError>
    where
        P: FnOnce([u8; 32]) -> Fut + Send,
        Fut: std::future::Future<Output = Result<(), DsmError>> + Send,
    {
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

        let mut storage_nodes = Vec::with_capacity(mpc_participants.len());
        let mut contributor_entropies = Vec::with_capacity(mpc_participants.len());
        for (index, participant) in mpc_participants.into_iter().enumerate() {
            let contributor_entropy: [u8; 32] =
                participant.as_slice().try_into().map_err(|_| {
                    DsmError::invalid_operation("MPC participant entropy must be 32 bytes")
                })?;
            contributor_entropies.push(contributor_entropy);
            storage_nodes.push(dsm::types::identifiers::NodeId::new(format!(
                "storage-node-{}",
                index
            )));
        }

        let device_entropy = generate_device_entropy(&device_id_arr);

        // Optional high-assurance / legacy profile: n-of-n commit-reveal multipart entropy
        // (GenesisEntropyProfile::CommitRevealMpcV1). NO silicon binding and NO C-DBRW —
        // the canonical wallet path is mnemonic-rooted Genesis v2 (`create_genesis_v2`).
        let genesis_state = create_genesis_via_blind_mpc_with_contributors(
            device_id_arr,
            storage_nodes,
            device_entropy,
            contributor_entropies,
            client_entropy,
        )?;

        // Run the pre-install hook with the freshly-computed genesis
        // hash. Storage-node SDK uses this slot to publish the initial
        // `DeviceTreeStateV1` to a quorum of storage nodes (Phase B.6
        // issue #277); if quorum cannot be reached, the publisher
        // returns Err and the genesis aborts with zero local residue.
        if let Err(e) = before_install(genesis_state.hash).await {
            log::warn!(
                "Genesis aborting before local install: pre-install hook returned: {}",
                e
            );
            return Err(e);
        }

        // From here on: COMMITTED. Install local state.
        let public_key = genesis_state.signing_key.public_key.clone();
        let smt_root = genesis_state.merkle_root.unwrap_or(genesis_state.hash);

        log::info!(
            "Genesis created (hash={})",
            crate::util::text_id::encode_base32_crockford(&genesis_state.hash)
        );

        // Install the new genesis as current state and seed the canonical
        // device head cache. There is no AdvanceOutcome at genesis, so the
        // head cache write is the explicit one-shot equivalent — settlement
        // and reader paths look up the device via `bcr_device_heads`.
        let genesis_state_hash = {
            let mut sm = self.state_machine.lock();
            let mut s = State::new_genesis(genesis_state.initial_entropy, self.device_info.clone());
            s.hash = genesis_state.hash;
            let snapshot = s.clone();
            sm.set_state(s);
            snapshot.hash
        };
        self.write_genesis_device_head(genesis_state_hash)?;

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

    /// Install an already-computed canonical Genesis v2 [`GenesisState`] as the device's current
    /// state and seed the device-head cache. The caller (the `wallet.createGenesisV2` route) must
    /// construct this `CoreSDK` with the v2 `DeviceInfo` (DevID + AK public key) so the installed
    /// state + device head carry the canonical identity. Returns the installed genesis hash `G`.
    ///
    /// No MPC, no storage nodes, no silicon: the GenesisState came from
    /// `create_genesis_v2_self_attested` over the unlocked wallet seed.
    pub fn install_v2_genesis(
        &self,
        genesis_state: &dsm::core::identity::genesis::GenesisState,
    ) -> Result<[u8; 32], DsmError> {
        let genesis_state_hash = {
            let mut sm = self.state_machine.lock();
            let mut s = State::new_genesis(genesis_state.initial_entropy, self.device_info.clone());
            s.hash = genesis_state.hash;
            let snapshot = s.clone();
            sm.set_state(s);
            snapshot.hash
        };
        self.write_genesis_device_head(genesis_state_hash)?;
        Ok(genesis_state.hash)
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

        // Execute mint via relationship path (self-loop for authority mint)
        let dev_id = self.device_info.device_id;
        let rel_key = dsm::core::bilateral_transaction_manager::compute_smt_key(&dev_id, &dev_id);
        let era_pc = dsm::core::token::token_state_manager::resolve_policy_commit("ERA")?;
        let deltas = [dsm::types::device_state::BalanceDelta {
            policy_commit: era_pc,
            direction: dsm::types::device_state::BalanceDirection::Credit,
            amount: 1_000_000,
        }];
        let init_tip = dsm::core::bilateral_transaction_manager::initial_chain_tip_from_device_ids(
            &dev_id, &dev_id,
        );
        let mut sm = self.state_machine.lock();
        // Same fail-closed prepare → write → commit pattern as
        // `execute_on_relationship`. The dev-seed mint participates in BCR
        // archival so reader paths see the seeded balance.
        let outcome =
            sm.prepare_advance_relationship(rel_key, dev_id, mint, &deltas, Some(init_tip), None)?;
        // Dev-seed Mint is ingress (no capsule bump needed): bump_capsule = false.
        Self::dual_write_advance_outcome(&outcome, false)?;
        sm.commit_advance(&outcome);
        let new_hash = outcome.new_chain_state.compute_chain_tip();
        log::info!("Dev seeding applied; new chain tip {:02x?}", &new_hash[..4]);

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
        let local_id =
            dsm_blake3::domain_hash(dsm::common::domain_tags::TAG_DSM_LOCAL_ID, &id_data)
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

/// Producer-side offline-bearer artifacts from driving the device fused-anchor appliance for one
/// transfer: the wire release + the fused-anchor leaf update the DSM advance must apply + the
/// appliance root lineage the receiver pins/adopts + the pin material to admit the anchor.
pub struct OfflineBearerArtifacts {
    /// prost-encoded `dsm.anchor.OfflineRelease` (goes on `BilateralConfirmRequest.offline_release`).
    pub offline_release: Vec<u8>,
    /// The fused-anchor-state leaf update to pass to `DeviceState::advance` (`Some(...)`).
    pub anchor_leaf: dsm::types::device_state::AnchorLeafUpdate,
    /// The appliance DSM root this transfer consumes (the receiver's `accepted_prev_root`).
    pub appliance_prev_root: [u8; 32],
    /// The successor appliance DSM root the receiver adopts after acceptance.
    pub appliance_next_root: [u8; 32],
    /// The pin material (B, anchor_id, H0, partition_pk) the receiver admits for this anchor.
    pub pin: crate::anchor::AnchorPin,
}

/// A PREPARED offline-bearer transfer: the appliance has formed the cross-bound certificate but has
/// NOT moved the counter (§21.2). The physical counter therefore still sits at the FROM coordinate
/// `uᵢ`, so this is exactly the window in which the receiver takes its authenticated FROM read
/// (`H_pre = H0 − uᵢ`) before the sender commits. Returned by
/// [`CoreSDK::prepare_offline_bearer_release`]; consumed by
/// [`CoreSDK::commit_offline_bearer_release`], which moves the counter to `uᵢ+1` and emits the
/// release. Between the two, `Status::Prepared` holds the appliance (§26.4: no second transfer while
/// a prepared record exists — the serialization the Counter-Positioned Commit relies on).
#[derive(Clone, Debug)]
pub struct PreparedOfflineBearer {
    /// The appliance DSM root this transfer consumes (the receiver's `accepted_prev_root`).
    pub appliance_prev_root: [u8; 32],
    /// The successor appliance DSM root the receiver adopts after acceptance.
    pub appliance_next_root: [u8; 32],
    /// The FROM counter coordinate `uᵢ` the receiver must witness live (`H_pre = H0 − uᵢ`) BEFORE
    /// the sender commits.
    pub anchor_counter: u64,
    /// The pin material — the receiver opens its authenticated relay session to `pin.anchor_id` and
    /// checks the FROM read against `pin.enrolled_counter − anchor_counter`.
    pub pin: crate::anchor::AnchorPin,
}

impl CoreSDK {
    /// Phase 1 of the Counter-Positioned Commit producer (Boot Fenced Fused Anchor §21.2): lazily
    /// birth the appliance (bootstrapping `commit_0` into the DeviceState anchor-state leaf), then
    /// PREPARE(r_R) — form the cross-bound certificate WITHOUT moving the counter. The appliance is
    /// left `Prepared` with the physical counter still at the FROM coordinate `uᵢ`, so the receiver
    /// can take its authenticated FROM read (`H_pre = H0 − uᵢ`) before [`commit_offline_bearer_release`]
    /// moves the counter. The returned [`PreparedOfflineBearer`] carries `uᵢ` and the pin the receiver
    /// needs to read and check that FROM coordinate.
    ///
    /// The appliance certifies its OWN opaque root lineage (advances only on bearer transfers —
    /// not the per-relationship tip nor the multi-relationship device root); the receiver pins
    /// `appliance_prev_root` at admission and adopts `appliance_next_root` on acceptance. The DSM
    /// leaf proofs in the anchor `Δ` are left empty here: the receiver validates the DSM
    /// transition via the confirm's `rel_proof_parent/child` + §C1 recompute that gate acceptance.
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_offline_bearer_release(
        &self,
        relationship_id: [u8; 32],
        recipient_device_id: [u8; 32],
        object_id: [u8; 32],
        payload_hash: [u8; 32],
        authority_policy_hash: [u8; 32],
        action_type: u32,
        action_fields: Vec<u8>,
        receiver_challenge: [u8; 32],
    ) -> Result<PreparedOfflineBearer, DsmError> {
        use dsm::core::bilateral_transaction_manager::{anchor_state_commit, anchor_state_leaf_key};

        let dev = self.device_info.device_id;
        let seed = |tag: &str| blake3_cat(&[tag.as_bytes(), &dev]);

        let mut guard = self.anchor_appliance.lock();
        if guard.is_none() {
            // Sender-side appliance: the physical RP2350/TROPIC01 via the installed factory. On device
            // an absent factory FAILS CLOSED ("offline = chips"); the in-process mock is the test-only
            // producer. The factory is called once and cached (stateful appliance).
            let mut a: Box<dyn crate::anchor::AnchorAppliance + Send> =
                match crate::bridge::anchor_appliance_factory() {
                    Some(factory) => factory()?,
                    None => hardware_appliance_or_fail(&seed, dev)?,
                };
            // Reconcile the DeviceState anchor-state leaf to the appliance's CURRENT committed fused
            // state, sourced from the chip's own status()/pin() (chip identity for hardware; seeds for
            // the test mock). The CHIP is the source of truth for the counter, so this uses its live
            // `anchor_counter` (u), NOT a hardcoded 0:
            //   * fresh provisioned chip -> u == 0 (H == H0), the genesis commit;
            //   * process restart with k prior offline-bearer transfers (possibly with ONLINE transfers
            //     in between — those advance the device SMT but never touch the chip counter) -> u == k,
            //     so the leaf adopts the true post-k state instead of resetting to genesis;
            //   * device-state/chip divergence -> the hardware wins (a monotonic counter cannot lie).
            // Writing the current committed state is idempotent when the leaf already matches.
            {
                let s = a.status()?;
                let pin = a.pin();
                // Commit the COMMITTED boot head (what the next transfer's cert reports as
                // `prev_boot_head`), NOT the live `boot_head` — a boot advance moves the live head past
                // the committed one until the next finalize.
                let committed = anchor_state_commit(
                    &pin.bundle,
                    &s.anchor_head,
                    &s.committed_boot_head,
                    s.anchor_counter,
                );
                log::info!(
                    "[offline-bearer] anchor-state leaf reconciled to chip state: u(anchor_counter)={} (online-transfer-safe; chip is source of truth)",
                    s.anchor_counter
                );
                let key = anchor_state_leaf_key(&pin.bundle);
                {
                    let mut sm = self.state_machine.lock();
                    let ds = sm.device_head().ok_or_else(|| {
                        DsmError::state_machine(
                            "offline-bearer: DeviceState not initialized (genesis first)",
                        )
                    })?;
                    let bootstrapped = ds.with_anchor_state_leaf(&key, &committed)?;
                    sm.set_device_head(bootstrapped);
                }
                *guard = Some(a);
            }
        }

        let app = guard.as_mut().ok_or_else(|| {
            DsmError::state_machine("offline-bearer: anchor appliance not birthed")
        })?;
        let pin = app.pin();

        // Pre-drive state: the appliance root this transfer consumes + the current counter.
        let before = app.status()?;
        let appliance_prev_root = before.root;
        let appliance_next_root =
            blake3_cat(&[b"DSM/anchor-root-advance/v1", &before.root, &payload_hash]);

        // Build the anchor transition Δ (DSM leaf proofs left empty — see method doc).
        let owned = anchor_core::root_advance::OwnedTransition {
            relationship_id,
            object_id,
            sender_device_id: dev,
            recipient_device_id,
            prev_root: appliance_prev_root,
            next_root: appliance_next_root,
            anchor_counter: before.anchor_counter,
            next_anchor_counter: before.anchor_counter + 1,
            action_type,
            action_fields,
            payload_hash,
            old_leaf_proof: Vec::new(),
            new_leaf_proof: Vec::new(),
            authority_policy_hash,
        };

        // §21.2 PREPARE only — no counter move. The appliance is now `Prepared` with the physical
        // counter still at the FROM coordinate `uᵢ`; the receiver reads `H_pre = H0 − uᵢ` against
        // this state before [`commit_offline_bearer_release`] moves the counter.
        app.prepare(&owned.as_transition(), &receiver_challenge)?;

        Ok(PreparedOfflineBearer {
            appliance_prev_root,
            appliance_next_root,
            anchor_counter: before.anchor_counter,
            pin,
        })
    }

    /// Phase 2 of the Counter-Positioned Commit producer (§21.3–§21.6): COMMIT the prepared transfer
    /// — move the physical counter `uᵢ → uᵢ+1` — then EMIT the release and FINALIZE the active fused
    /// state. Call ONLY after the receiver has taken its authenticated FROM read against the
    /// `Prepared` appliance. Returns the wire release + the successor [`AnchorLeafUpdate`] + the
    /// appliance root lineage + the pin material.
    pub fn commit_offline_bearer_release(
        &self,
        prepared: &PreparedOfflineBearer,
    ) -> Result<OfflineBearerArtifacts, DsmError> {
        use dsm::core::bilateral_transaction_manager::{anchor_state_commit, anchor_state_leaf_key};

        let mut guard = self.anchor_appliance.lock();
        let app = guard.as_mut().ok_or_else(|| {
            DsmError::state_machine("offline-bearer: anchor appliance not prepared")
        })?;
        let bundle = prepared.pin.bundle;
        let key = anchor_state_leaf_key(&bundle);

        // §21.3 COMMIT (moves the counter uᵢ → uᵢ+1) → §21.5 EMIT → §21.6 FINALIZE.
        app.commit()?;
        let offline_release = app.emit()?;
        app.finalize()?;

        // Successor fused state (post-finalize) → the leaf update the DSM advance applies.
        let after = app.status()?;
        let successor_commit = anchor_state_commit(
            &bundle,
            &after.anchor_head,
            &after.boot_head,
            after.anchor_counter,
        );
        let anchor_leaf = dsm::types::device_state::AnchorLeafUpdate {
            key,
            new_value: successor_commit,
        };

        Ok(OfflineBearerArtifacts {
            offline_release,
            anchor_leaf,
            appliance_prev_root: prepared.appliance_prev_root,
            appliance_next_root: prepared.appliance_next_root,
            pin: prepared.pin.clone(),
        })
    }

    /// Single-shot producer: PREPARE then immediately COMMIT (the non-interactive path, used where
    /// the receiver's FROM read is not interleaved — e.g. the current single-confirm seam, which
    /// stays fail-closed on the missing FROM read). The interactive Counter-Positioned Commit flow
    /// calls [`prepare_offline_bearer_release`] and [`commit_offline_bearer_release`] separately,
    /// with the receiver's authenticated FROM read taken in between.
    #[allow(clippy::too_many_arguments)]
    pub fn build_offline_bearer_release(
        &self,
        relationship_id: [u8; 32],
        recipient_device_id: [u8; 32],
        object_id: [u8; 32],
        payload_hash: [u8; 32],
        authority_policy_hash: [u8; 32],
        action_type: u32,
        action_fields: Vec<u8>,
        receiver_challenge: [u8; 32],
    ) -> Result<OfflineBearerArtifacts, DsmError> {
        let prepared = self.prepare_offline_bearer_release(
            relationship_id,
            recipient_device_id,
            object_id,
            payload_hash,
            authority_policy_hash,
            action_type,
            action_fields,
            receiver_challenge,
        )?;
        self.commit_offline_bearer_release(&prepared)
    }
}

/* ------------------------------ Private helpers ------------------------- */

/// The sender-side appliance when NO hardware factory is installed. Test builds get the in-process
/// mock so the release-path unit tests keep exercising `build_offline_bearer_release`; real device
/// builds FAIL CLOSED — offline-bearer strictly requires the physical chip ("offline = chips").
#[cfg(test)]
fn hardware_appliance_or_fail(
    seed: &impl Fn(&str) -> [u8; 32],
    dev: [u8; 32],
) -> Result<Box<dyn crate::anchor::AnchorAppliance + Send>, DsmError> {
    use crate::anchor::{BirthConfig, InProcessAnchorAppliance};
    Ok(Box::new(InProcessAnchorAppliance::birth_and_boot(
        &BirthConfig {
            partition_trng: seed("DSM/anchor/partition-trng/v1"),
            host_nonce: seed("DSM/anchor/host-nonce/v1"),
            device_id: dev,
            policy_hash: seed("DSM/anchor/policy-hash/v1"),
            partition_device_id: seed("DSM/anchor/partition-device-id/v1"),
            anchor_id: seed("DSM/anchor/anchor-id/v1"),
            partition_key_seed: seed("DSM/anchor/partition-key-seed/v1"),
            enrolled_counter: 1_000_000,
            q_boot: 5,
            q_tx: 6,
            genesis_root: seed("DSM/anchor/genesis-root/v1"),
            firmware_measurement: seed("DSM/anchor/firmware-measurement/v1"),
            se_secret: seed("DSM/anchor/se-secret/v1"),
        },
    )?))
}

#[cfg(not(test))]
fn hardware_appliance_or_fail(
    _seed: &impl Fn(&str) -> [u8; 32],
    _dev: [u8; 32],
) -> Result<Box<dyn crate::anchor::AnchorAppliance + Send>, DsmError> {
    Err(DsmError::invalid_operation(
        "offline-bearer requires the hardware anchor; connect the Pico and install Path-B (fail closed)",
    ))
}

impl CoreSDK {
    fn validate_transfer_request(
        &self,
        token_id: &[u8],
        recipient_genesis: &[u8],
        amount: u64,
        nonce: &[u8],
        sender_signature: &[u8],
    ) -> Result<(), DsmError> {
        // Phase 0 fail-closed recovery gate (spec condition R3): no value egress
        // while identity recovery is in progress — prevents the split-acceptance
        // recovery double-spend window (spec vector V1).
        if let Some(reason) = crate::storage::client_db::recovery::value_egress_block_reason() {
            return Err(DsmError::invalid_operation(reason));
        }
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

    fn token_metadata_for_operation(
        &self,
        op: &dsm::types::operations::Operation,
        token_id: &str,
    ) -> Option<TokenMetadata> {
        match op {
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

    pub(crate) fn resolve_policy_commit_strict(
        &self,
        token_id: &[u8],
    ) -> Result<[u8; 32], DsmError> {
        let token_id = std::str::from_utf8(token_id)
            .map_err(|_| DsmError::invalid_operation("token_id must be valid UTF-8"))?;

        if let Some(commit) = crate::policy::builtin_policy_commit(token_id) {
            return Ok(commit);
        }

        // Per §4.3 there is no `state_number`. Walk the per-relationship
        // chain-state archive newest-first looking for an op that registered
        // metadata for `token_id`. Chains are keyed by chain tip and ordered
        // by insertion time — no counter, no derived sparse index.
        let device_id = self.device_info.device_id;
        let states =
            crate::storage::client_db::get_bcr_chain_states(&device_id, false).map_err(|e| {
                DsmError::state(format!(
                    "Failed to load BCR chain states for policy commit lookup: {e}"
                ))
            })?;
        for state in states.into_iter().rev() {
            if let Some(token_metadata) =
                self.token_metadata_for_operation(&state.operation, token_id)
            {
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
    ///
    /// Returns the canonical [`AdvanceOutcome`] from the underlying
    /// `execute_on_relationship` call so callers (notably the online-receiver
    /// inbox drain in `storage_routes`) can build the stitched ReceiptCommit
    /// (§4.2) directly from `smt_proofs` + `parent_r_a` + `child_r_a` — no
    /// shadow SMT replace needed.
    pub fn apply_operation_with_replay_protection(
        &self,
        op: dsm::types::operations::Operation,
        tx_id: &crate::types::identifiers::TransactionId,
        _seq: u64,
        sender_device_id: &str,
        sender_chain_tip: &str,
    ) -> Result<dsm::types::device_state::AdvanceOutcome, DsmError> {
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

        // Execute via relationship-aware path. For incoming transfers (this is a
        // recipient-side apply), the rel_key is k_{sender↔local_device}.
        let local_device_id_bytes_pre = crate::sdk::app_state::AppState::get_device_id()
            .ok_or_else(|| DsmError::state_machine("missing local device_id (AppState)"))?;
        let sender_id_bytes_pre =
            crate::util::text_id::decode_base32_crockford(sender_device_id)
                .ok_or_else(|| DsmError::invalid_operation("sender_device_id not valid base32"))?;

        let (rel_key, counterparty, deltas) = {
            let mut local_arr = [0u8; 32];
            if local_device_id_bytes_pre.len() == 32 {
                local_arr.copy_from_slice(&local_device_id_bytes_pre);
            }
            let mut sender_arr = [0u8; 32];
            if sender_id_bytes_pre.len() == 32 {
                sender_arr.copy_from_slice(&sender_id_bytes_pre);
            }
            let rk =
                dsm::core::bilateral_transaction_manager::compute_smt_key(&local_arr, &sender_arr);
            // For incoming transfers, we're the recipient → Credit
            let d: Vec<dsm::types::device_state::BalanceDelta> = match &op {
                dsm::types::operations::Operation::Transfer {
                    token_id, amount, ..
                } => {
                    let pc = self.resolve_policy_commit_strict(token_id)?;
                    vec![dsm::types::device_state::BalanceDelta {
                        policy_commit: pc,
                        direction: dsm::types::device_state::BalanceDirection::Credit,
                        amount: amount.value(),
                    }]
                }
                _ => vec![],
            };
            (rk, sender_arr, d)
        };
        let init_tip = dsm::core::bilateral_transaction_manager::initial_chain_tip_from_device_ids(
            &{
                let mut a = [0u8; 32];
                if local_device_id_bytes_pre.len() == 32 {
                    a.copy_from_slice(&local_device_id_bytes_pre);
                }
                a
            },
            &counterparty,
        );
        let (new_state, outcome) = self
            .execute_on_relationship(rel_key, counterparty, op.clone(), &deltas, Some(init_tip))
            .map_err(|e| {
                DsmError::invalid_operation(format!(
                    "apply_operation_with_replay_protection: state machine execution failed: {e}"
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
                Ok(outcome.clone())
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
                Ok(outcome.clone())
            }
            dsm::types::operations::Operation::Create { .. } => {
                log::info!(
                    "[apply_operation] ✅ applied create operation tx={} from={}",
                    String::from_utf8_lossy(tx_id.as_bytes()),
                    sender_device_id
                );
                Ok(outcome.clone())
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
                        kyber_public_key: Vec::new(),
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
                Ok(outcome.clone())
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
                    kyber_public_key: Vec::new(),
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
                Ok(outcome.clone())
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
                Ok(outcome.clone())
            }
            // For operations that don't require recipient-side database persistence,
            // we still allow them through since state machine validation passed
            dsm::types::operations::Operation::Mint { .. } => {
                log::info!(
                    "[apply_operation] ✅ applied mint operation tx={} from={}",
                    String::from_utf8_lossy(tx_id.as_bytes()),
                    sender_device_id
                );
                Ok(outcome.clone())
            }
            dsm::types::operations::Operation::Burn { .. } => {
                log::info!(
                    "[apply_operation] ✅ applied burn operation tx={} from={}",
                    String::from_utf8_lossy(tx_id.as_bytes()),
                    sender_device_id
                );
                Ok(outcome.clone())
            }
            dsm::types::operations::Operation::Lock { .. } => {
                log::info!(
                    "[apply_operation] ✅ applied lock operation tx={} from={}",
                    String::from_utf8_lossy(tx_id.as_bytes()),
                    sender_device_id
                );
                Ok(outcome.clone())
            }
            dsm::types::operations::Operation::Unlock { .. } => {
                log::info!(
                    "[apply_operation] ✅ applied unlock operation tx={} from={}",
                    String::from_utf8_lossy(tx_id.as_bytes()),
                    sender_device_id
                );
                Ok(outcome.clone())
            }
            dsm::types::operations::Operation::LockToken { .. } => {
                log::info!(
                    "[apply_operation] ✅ applied lock_token operation tx={} from={}",
                    String::from_utf8_lossy(tx_id.as_bytes()),
                    sender_device_id
                );
                Ok(outcome.clone())
            }
            dsm::types::operations::Operation::UnlockToken { .. } => {
                log::info!(
                    "[apply_operation] ✅ applied unlock_token operation tx={} from={}",
                    String::from_utf8_lossy(tx_id.as_bytes()),
                    sender_device_id
                );
                Ok(outcome.clone())
            }
            dsm::types::operations::Operation::CreateToken { .. } => {
                log::info!(
                    "[apply_operation] ✅ applied create_token operation tx={} from={}",
                    String::from_utf8_lossy(tx_id.as_bytes()),
                    sender_device_id
                );
                Ok(outcome.clone())
            }
            dsm::types::operations::Operation::Update { .. } => {
                log::info!(
                    "[apply_operation] ✅ applied update operation tx={} from={}",
                    String::from_utf8_lossy(tx_id.as_bytes()),
                    sender_device_id
                );
                Ok(outcome.clone())
            }
            dsm::types::operations::Operation::RemoveRelationship { .. } => {
                log::info!(
                    "[apply_operation] ✅ applied remove_relationship operation tx={} from={}",
                    String::from_utf8_lossy(tx_id.as_bytes()),
                    sender_device_id
                );
                Ok(outcome.clone())
            }
            dsm::types::operations::Operation::Recovery { .. } => {
                log::info!(
                    "[apply_operation] ✅ applied recovery operation tx={} from={}",
                    String::from_utf8_lossy(tx_id.as_bytes()),
                    sender_device_id
                );
                Ok(outcome.clone())
            }
            dsm::types::operations::Operation::Delete { .. } => {
                log::info!(
                    "[apply_operation] ✅ applied delete operation tx={} from={}",
                    String::from_utf8_lossy(tx_id.as_bytes()),
                    sender_device_id
                );
                Ok(outcome.clone())
            }
            dsm::types::operations::Operation::Link { .. } => {
                log::info!(
                    "[apply_operation] ✅ applied link operation tx={} from={}",
                    String::from_utf8_lossy(tx_id.as_bytes()),
                    sender_device_id
                );
                Ok(outcome.clone())
            }
            dsm::types::operations::Operation::Unlink { .. } => {
                log::info!(
                    "[apply_operation] ✅ applied unlink operation tx={} from={}",
                    String::from_utf8_lossy(tx_id.as_bytes()),
                    sender_device_id
                );
                Ok(outcome.clone())
            }
            dsm::types::operations::Operation::Invalidate { .. } => {
                log::info!(
                    "[apply_operation] ✅ applied invalidate operation tx={} from={}",
                    String::from_utf8_lossy(tx_id.as_bytes()),
                    sender_device_id
                );
                Ok(outcome.clone())
            }
            dsm::types::operations::Operation::Genesis => {
                log::info!(
                    "[apply_operation] ✅ applied genesis operation tx={} from={}",
                    String::from_utf8_lossy(tx_id.as_bytes()),
                    sender_device_id
                );
                Ok(outcome.clone())
            }
            dsm::types::operations::Operation::Noop => {
                log::info!(
                    "[apply_operation] ✅ applied noop operation tx={} from={}",
                    String::from_utf8_lossy(tx_id.as_bytes()),
                    sender_device_id
                );
                Ok(outcome.clone())
            }
            dsm::types::operations::Operation::DlvCreate { .. } => {
                log::info!(
                    "[apply_operation] applied dlv_create operation tx={} from={}",
                    String::from_utf8_lossy(tx_id.as_bytes()),
                    sender_device_id
                );
                Ok(outcome.clone())
            }
            dsm::types::operations::Operation::DlvUnlock { .. } => {
                log::info!(
                    "[apply_operation] applied dlv_unlock operation tx={} from={}",
                    String::from_utf8_lossy(tx_id.as_bytes()),
                    sender_device_id
                );
                Ok(outcome.clone())
            }
            dsm::types::operations::Operation::DlvClaim { .. } => {
                log::info!(
                    "[apply_operation] applied dlv_claim operation tx={} from={}",
                    String::from_utf8_lossy(tx_id.as_bytes()),
                    sender_device_id
                );
                Ok(outcome.clone())
            }
            dsm::types::operations::Operation::DlvInvalidate { .. } => {
                log::info!(
                    "[apply_operation] applied dlv_invalidate operation tx={} from={}",
                    String::from_utf8_lossy(tx_id.as_bytes()),
                    sender_device_id
                );
                Ok(outcome.clone())
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
    #[serial]
    fn build_offline_bearer_release_drives_appliance_binds_challenge_and_advances_lineage() {
        use prost::Message as _;
        let sdk = test_sdk();
        // Give the device a head so the fused-anchor leaf can bootstrap.
        {
            let ds = dsm::types::device_state::DeviceState::new(
                [9u8; 32],
                sdk.device_info.device_id,
                vec![0u8; 64],
                256,
            );
            sdk.state_machine.lock().set_device_head(ds);
        }

        let recipient = [4u8; 32];
        // ---- Transfer 1 ----
        let r_r_1 = [0x55u8; 32];
        let art1 = sdk
            .build_offline_bearer_release(
                [1u8; 32],
                recipient,
                [2u8; 32],
                [9u8; 32],
                [3u8; 32],
                0,
                vec![0xAB],
                r_r_1,
            )
            .expect("drive 1");
        // (2) release constructs + decodes; (3) the producer challenge r_R is bound into the cert.
        let rel = anchor_core::proto::pb::OfflineRelease::decode(&art1.offline_release[..])
            .expect("decode")
            .to_release()
            .expect("to_release");
        assert_eq!(
            rel.cert.receiver_challenge, r_r_1,
            "r_R must bind into the cert"
        );
        assert_eq!(rel.transition.recipient_device_id, recipient);
        assert_eq!(rel.cert.anchor_counter, 0);
        assert_eq!(rel.cert.next_anchor_counter, 1);

        // ---- Transfer 2: appliance lineage advances (prev == prior next), counter + leaf advance ----
        let r_r_2 = [0x66u8; 32];
        let art2 = sdk
            .build_offline_bearer_release(
                [1u8; 32],
                recipient,
                [2u8; 32],
                [9u8; 32],
                [3u8; 32],
                0,
                vec![0xCD],
                r_r_2,
            )
            .expect("drive 2");
        assert_eq!(
            art2.appliance_prev_root, art1.appliance_next_root,
            "appliance root lineage must advance (transfer 2 consumes transfer 1's successor root)"
        );
        assert_ne!(
            art2.anchor_leaf.new_value, art1.anchor_leaf.new_value,
            "the successor fused-anchor commit advances each transfer"
        );
        assert_eq!(
            art2.pin.bundle, art1.pin.bundle,
            "same device anchor bundle B"
        );
        let rel2 = anchor_core::proto::pb::OfflineRelease::decode(&art2.offline_release[..])
            .unwrap()
            .to_release()
            .unwrap();
        assert_eq!(rel2.cert.anchor_counter, 1, "counter advanced to u_i=1");
        assert_eq!(rel2.cert.receiver_challenge, r_r_2);
    }

    /// The Counter-Positioned Commit producer is two-phase: PREPARE exposes the FROM coordinate `uᵢ`
    /// WITHOUT moving the counter (so the receiver can take its authenticated FROM read `H0 − uᵢ`),
    /// then COMMIT moves the counter to `uᵢ+1`. Proves the split holds `uᵢ` pre-commit, advances by
    /// exactly one at commit, and that the emitted evidence carries BOTH coordinates (`H_pre =
    /// H_post + 1`) — the interactive handshake the receiver's FROM→TO check consumes.
    #[test]
    #[serial]
    fn two_phase_producer_exposes_from_coordinate_before_commit() {
        use dsm::types::device_state::DeviceState;

        let sdk = test_sdk();
        {
            let ds = DeviceState::new([9u8; 32], sdk.device_info.device_id, vec![0u8; 64], 256);
            sdk.state_machine.lock().set_device_head(ds);
        }
        let recipient = [4u8; 32];

        // Phase 1 — PREPARE: form the cert, DO NOT move the counter. The FROM coordinate is exposed.
        let prepared = sdk
            .prepare_offline_bearer_release(
                [1u8; 32],
                recipient,
                [2u8; 32],
                [9u8; 32],
                [3u8; 32],
                0,
                vec![0xAB],
                [0x55u8; 32],
            )
            .expect("prepare");
        assert_eq!(
            prepared.anchor_counter, 0,
            "PREPARE exposes the FROM coordinate uᵢ without moving the counter"
        );
        let h0 = prepared.pin.enrolled_counter;
        // The value the receiver must witness LIVE against the Prepared appliance, before commit.
        let h_pre = h0 - prepared.anchor_counter;

        // Phase 2 — COMMIT: move the counter uᵢ → uᵢ+1 and emit the release.
        let art = sdk
            .commit_offline_bearer_release(&prepared)
            .expect("commit");
        let rel = anchor_core::proto::pb::OfflineRelease::decode(&art.offline_release[..])
            .expect("decode")
            .to_release()
            .expect("to_release");
        assert_eq!(rel.cert.anchor_counter, 0, "FROM coordinate uᵢ");
        assert_eq!(rel.cert.next_anchor_counter, 1, "TO coordinate uᵢ+1 (advanced once)");
        let h_post = h0 - rel.cert.next_anchor_counter;
        assert_eq!(h_pre, h_post + 1, "one physical advance: H_pre = H_post + 1");

        // The producer's CounterAdvanceEvidence carries both witnessed coordinates.
        assert_eq!(
            rel.counter.pre.attested_raw_counter, h_pre,
            "pre evidence carries the FROM raw counter H0 − uᵢ"
        );
        assert_eq!(
            rel.counter.post.attested_raw_counter, h_post,
            "post evidence carries the TO raw counter H0 − (uᵢ+1)"
        );
    }

    /// End-to-end producer → receiver-predicate → adopt → replay-reject over TWO real bearer
    /// transfers. This is the activation boundary for the producer-driving cluster: the SENDER
    /// drives the real fused-anchor appliance (`build_offline_bearer_release`), commits the emitted
    /// successor leaf into a real per-device SMT advance, and the RECEIVER runs the full 22-check
    /// Boot Fenced Fused predicate (`accept_offline_release_with_counter`) against the real release +
    /// real inclusion proofs + real pin. The ONLY stub is the authenticated L3 counter session
    /// (`TrustedTestCounter`), which stands in for the not-yet-built D2 verifier; the production path
    /// keeps `DsmCounterVerifier` and stays fail-closed. Proves: (a) a real release is accepted once
    /// the counter is authenticated, (b) the receiver adopts the appliance-root + fused-state
    /// frontier, (c) replaying transfer 1 after adoption is rejected, (d) transfer 2 chains from the
    /// adopted frontier.
    #[test]
    #[serial]
    fn producer_release_accepts_adopts_and_rejects_replay_end_to_end() {
        use crate::bluetooth::anchor_accept::{
            accept_offline_release_with_counter, AnchorStateBinding, OfflineRecover, PinnedAnchor,
            TrustedTestCounter,
        };
        use dsm::core::bilateral_transaction_manager::{
            compute_smt_key, initial_chain_tip_from_device_ids,
        };
        use dsm::types::device_state::{AnchorLeafUpdate, DeviceState};

        let sdk = test_sdk();
        {
            let ds = DeviceState::new([9u8; 32], sdk.device_info.device_id, vec![0u8; 64], 256);
            sdk.state_machine.lock().set_device_head(ds);
        }
        let sender_dev = sdk.device_info.device_id;
        let recipient = [4u8; 32];
        let policy_hash = [3u8; 32];

        // Build the receiver PinnedAnchor from the producer's own enrolled pin (uncompromised).
        let pin_from = |p: &crate::anchor::AnchorPin| PinnedAnchor {
            bundle: p.bundle,
            anchor_id: p.anchor_id,
            enrolled_counter: p.enrolled_counter,
            partition_pk: p.partition_pk.clone(),
            uncompromised: true,
        };

        // One real bearer transfer: drive the appliance, then commit the emitted successor leaf into
        // a real per-device SMT advance from `dev`. Returns (artifacts, advance outcome).
        let drive = |dev: &DeviceState, cp_tag: u8, r_r: [u8; 32]| {
            let art = sdk
                .build_offline_bearer_release(
                    [1u8; 32],
                    recipient,
                    [2u8; 32],
                    [9u8; 32],
                    policy_hash,
                    0,
                    vec![0xAB],
                    r_r,
                )
                .expect("drive appliance");
            let cp = {
                let mut c = [0u8; 32];
                c[0] = cp_tag;
                c
            };
            let rk = compute_smt_key(&dev.devid(), &cp);
            let init = initial_chain_tip_from_device_ids(&dev.devid(), &cp);
            let out = dev
                .advance(
                    rk,
                    cp,
                    DsmOperation::Noop,
                    vec![cp_tag; 32],
                    None,
                    &[],
                    Some(init),
                    Some(AnchorLeafUpdate {
                        key: art.anchor_leaf.key,
                        new_value: art.anchor_leaf.new_value,
                    }),
                )
                .expect("bearer advance");
            (art, out)
        };

        // Snapshot the bootstrapped device head (holds commit_0) to start the sender's SMT chain.
        // The first `drive` call bootstraps commit_0 into the SDK head; take it after.
        let (art1, out1) = {
            // Prime commit_0 by driving once against the current head, then re-advance from the head
            // the bootstrap wrote. `build_offline_bearer_release` bootstraps on its first call.
            let art = sdk
                .build_offline_bearer_release(
                    [1u8; 32],
                    recipient,
                    [2u8; 32],
                    [9u8; 32],
                    policy_hash,
                    0,
                    vec![0xAB],
                    [0x55u8; 32],
                )
                .expect("prime bootstrap");
            let head = sdk
                .state_machine
                .lock()
                .device_head()
                .expect("bootstrapped head")
                .clone();
            let cp = [0xC0u8; 32];
            let rk = compute_smt_key(&head.devid(), &cp);
            let init = initial_chain_tip_from_device_ids(&head.devid(), &cp);
            let out = head
                .advance(
                    rk,
                    cp,
                    DsmOperation::Noop,
                    vec![0xC0u8; 32],
                    None,
                    &[],
                    Some(init),
                    Some(AnchorLeafUpdate {
                        key: art.anchor_leaf.key,
                        new_value: art.anchor_leaf.new_value,
                    }),
                )
                .expect("bearer advance 1");
            (art, out)
        };

        let ap1 = out1
            .anchor_proofs
            .clone()
            .expect("transfer 1 emits anchor proofs");
        let pin1 = pin_from(&art1.pin);
        let before1 = out1.smt_proofs.pre_root;
        let after1 = out1.child_r_a;
        let binding1 = AnchorStateBinding {
            sender_smt_root: &after1,
            sender_smt_root_before: &before1,
            prev_proof: &ap1.parent,
            next_proof: &ap1.child,
        };

        // (a) Receiver accepts the real release once the counter is authenticated. `accepted_prev_root`
        // is the appliance root this transfer consumes.
        accept_offline_release_with_counter(
            &art1.offline_release,
            Some(&pin1),
            Some(&art1.appliance_prev_root),
            &recipient,
            &[0x55u8; 32],
            &policy_hash,
            &binding1,
            &TrustedTestCounter,
        )
        .expect("transfer 1 must be accepted under an authenticated counter");
        let _ = sender_dev;

        // (a') The PRODUCTION relay-counter entry point: supplied the TWO counter values the receiver
        // would read from A's chip over the raw-SPI relay — the FROM read `H_pre = H0 - u_i`
        // (= enrolled for transfer 1, u_i=0) taken before A's commit, and the TO read
        // `H_post = H0 - (u_i+1)` (= enrolled - 1) after — each tagged with the pinned anchor_id, it
        // accepts. A missing FROM read, a missing TO read, a wrong value, or a read from a different
        // chip all fail closed — proving the FROM→TO coordinate proof flows through the real path.
        let h_pre = pin1.enrolled_counter; // H0 - u_i, u_i = 0
        let h_post = pin1.enrolled_counter - 1; // H0 - (u_i+1)
        crate::bluetooth::anchor_accept::accept_offline_release_with_relay_counter(
            &art1.offline_release,
            Some(&pin1),
            Some(&art1.appliance_prev_root),
            &recipient,
            &[0x55u8; 32],
            &policy_hash,
            &binding1,
            Some((pin1.anchor_id, h_pre)),
            Some((pin1.anchor_id, h_post)),
        )
        .expect("relay-counter accept with the exact authenticated FROM+TO reads");
        for (bad_pre, bad_post) in [
            (None, Some((pin1.anchor_id, h_post))), // no FROM read -> fail closed
            (Some((pin1.anchor_id, h_pre)), None),  // no TO read
            (Some((pin1.anchor_id, h_pre + 1)), Some((pin1.anchor_id, h_post))), // wrong FROM
            (Some((pin1.anchor_id, h_pre)), Some((pin1.anchor_id, h_post + 1))), // wrong TO
            (Some(([0xEEu8; 32], h_pre)), Some((pin1.anchor_id, h_post))), // FROM read from another chip
        ] {
            let r = crate::bluetooth::anchor_accept::accept_offline_release_with_relay_counter(
                &art1.offline_release,
                Some(&pin1),
                Some(&art1.appliance_prev_root),
                &recipient,
                &[0x55u8; 32],
                &policy_hash,
                &binding1,
                bad_pre,
                bad_post,
            );
            assert!(
                r.is_err(),
                "relay-counter must fail closed for pre={bad_pre:?} post={bad_post:?}, got {r:?}"
            );
        }

        // (b) Alice/Bob double-spend defense at the counter coordinate, through the real accept path.
        // Alice accepted above: her live FROM read was H0 (100) and TO read H0-1 (99). A SECOND (Bob)
        // attempt presenting the SAME u_i=0 release AFTER Alice's commit advanced the physical counter
        // — so Bob's live FROM read is now 99, not 100 — is rejected SPECIFICALLY on the FROM
        // coordinate. The counter has left u_i and cannot return: the same counter-positioned sender
        // state cannot be spent twice. This is the door, and the rejection is the production predicate,
        // not a test shortcut.
        let bob = crate::bluetooth::anchor_accept::accept_offline_release_with_relay_counter(
            &art1.offline_release,
            Some(&pin1),
            Some(&art1.appliance_prev_root),
            &recipient,
            &[0x55u8; 32],
            &policy_hash,
            &binding1,
            Some((pin1.anchor_id, h_post)), // Bob's live FROM read is 99 (counter already past u_i=0)
            Some((pin1.anchor_id, h_post - 1)),
        );
        assert!(
            matches!(
                bob,
                Err(crate::bluetooth::anchor_accept::OfflineRecover::Predicate(
                    anchor_core::accept::AcceptError::CounterFromCoordinateInvalid
                ))
            ),
            "Bob's stale u_i=0 attempt must be rejected on the FROM coordinate (live counter now 99), got {bob:?}"
        );

        // (c) Replay: presenting transfer 1 again AFTER the receiver adopted `appliance_next_root`
        // is rejected — the consumed appliance root is no longer the accepted root.
        let replay = accept_offline_release_with_counter(
            &art1.offline_release,
            Some(&pin1),
            Some(&art1.appliance_next_root), // receiver has adopted the successor root
            &recipient,
            &[0x55u8; 32],
            &policy_hash,
            &binding1,
            &TrustedTestCounter,
        );
        assert!(
            matches!(replay, Err(OfflineRecover::Predicate(_))),
            "replay of the consumed appliance root must be rejected, got {replay:?}"
        );

        // (d) Transfer 2 chains from the adopted frontier: appliance lineage advances and the second
        // release is accepted against the newly adopted appliance root.
        let (art2, out2) = drive(&out1.new_device_state, 0xC1, [0x66u8; 32]);
        assert_eq!(
            art2.appliance_prev_root, art1.appliance_next_root,
            "transfer 2 must consume transfer 1's successor appliance root"
        );
        let ap2 = out2
            .anchor_proofs
            .clone()
            .expect("transfer 2 emits anchor proofs");
        let pin2 = pin_from(&art2.pin);
        let before2 = out2.smt_proofs.pre_root;
        let after2 = out2.child_r_a;
        let binding2 = AnchorStateBinding {
            sender_smt_root: &after2,
            sender_smt_root_before: &before2,
            prev_proof: &ap2.parent,
            next_proof: &ap2.child,
        };
        accept_offline_release_with_counter(
            &art2.offline_release,
            Some(&pin2),
            Some(&art2.appliance_prev_root),
            &recipient,
            &[0x66u8; 32],
            &policy_hash,
            &binding2,
            &TrustedTestCounter,
        )
        .expect("transfer 2 must be accepted from the adopted frontier");
    }

    /// PHASE H0 — prove the whole phone-to-chip relay path with FAKE PIPES before any Android/BLE:
    /// receiver resolves the counter through the REAL `TropicRelayRouter` round-trip (B -> in-process
    /// "BLE" -> A.handle_inbound -> A's mock Pico -> reply -> B), feeds it through the exact confirm
    /// seam (`resolve_attested_counter`), and the canonical predicate accepts iff the counter matches.
    /// Every missing install / wrong counter fails closed to online recovery. No `tropic01`, no
    /// hardware — replace the fake pipes with Android USB/BLE in H2/H3.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn phase_h0_relay_counter_flows_end_to_end_with_mock_transports() {
        use crate::bluetooth::anchor_accept::{
            accept_offline_release_with_relay_counter, resolve_attested_counter,
            AnchorStateBinding, OfflineRecover, PinnedAnchor,
        };
        use crate::bluetooth::tropic_relay::{
            AnchorCounterReader, LocalPicoTransport, PicoFuture, TropicRelayRouter,
        };
        use dsm::crypto::anchor_enrollment::FusedAnchorPin;
        use dsm::types::device_state::{AnchorLeafUpdate, DeviceState};
        use dsm::types::error::DsmError;
        use std::sync::Arc;

        // A mock Pico A: for any MOSI, return the 4-byte LE counter `h` as MISO (stands in for a
        // real libtropic mcounter_get over the raw-SPI passthrough).
        struct MockPico {
            h: u32,
        }
        impl LocalPicoTransport for MockPico {
            fn spi_passthrough(&self, _spi: Vec<u8>) -> PicoFuture<Result<Vec<u8>, DsmError>> {
                let h = self.h;
                Box::pin(async move { Ok(h.to_le_bytes().to_vec()) })
            }
        }

        // Mock receiver-side reader standing in for the real `RelayCounterReader`: it drives the REAL
        // router round-trip through sender A's router (which owns a mock Pico), then decodes H. Fails
        // closed on an incomplete pin (mirrors the hardware reader) or any relay failure (e.g. A has
        // no local Pico). `a` is `None` to simulate "no sender router at all".
        struct RelayMockReader {
            a: Option<Arc<TropicRelayRouter>>,
        }
        impl AnchorCounterReader for RelayMockReader {
            fn read_counter(
                &self,
                _peer: [u8; 32],
                commitment: [u8; 32],
                pin: FusedAnchorPin,
            ) -> PicoFuture<Option<u32>> {
                if pin.verifier_slot.is_none()
                    || pin.chip_static_pubkey.is_none()
                    || !pin.uncompromised
                {
                    return Box::pin(async { None });
                }
                let a = self.a.clone();
                Box::pin(async move {
                    let b = Arc::new(TropicRelayRouter::new());
                    let b2 = b.clone();
                    let miso = b
                        .round_trip(commitment, vec![0u8], move |frame| {
                            let a = a.clone();
                            let b2 = b2.clone();
                            async move {
                                let a = a.ok_or_else(|| {
                                    DsmError::invalid_operation(
                                        "no sender A router (fake pipe down)",
                                    )
                                })?;
                                // A services the relayed request against its local Pico, or errors
                                // fail-closed if it has no Pico installed.
                                let reply = a.handle_inbound(&frame).await?.ok_or_else(|| {
                                    DsmError::invalid_operation("A produced no reply")
                                })?;
                                b2.handle_inbound(&reply).await?;
                                Ok(())
                            }
                        })
                        .await
                        .ok()?;
                    let arr: [u8; 4] = miso.get(..4)?.try_into().ok()?;
                    Some(u32::from_le_bytes(arr))
                })
            }
        }

        // ---- One real bearer release + a COMPLETE receiver pin (slot + stpub) ----------------------
        let sdk = test_sdk();
        {
            let ds = DeviceState::new([9u8; 32], sdk.device_info.device_id, vec![0u8; 64], 256);
            sdk.state_machine.lock().set_device_head(ds);
        }
        let sender_dev = sdk.device_info.device_id;
        let recipient = [4u8; 32];
        let policy_hash = [3u8; 32];
        let r_r = [0x55u8; 32];

        let art = sdk
            .build_offline_bearer_release(
                [1u8; 32],
                recipient,
                [2u8; 32],
                [9u8; 32],
                policy_hash,
                0,
                vec![0xAB],
                r_r,
            )
            .expect("prime bootstrap");
        let head = sdk
            .state_machine
            .lock()
            .device_head()
            .expect("bootstrapped head")
            .clone();
        let cp = [0xC0u8; 32];
        let rk = dsm::core::bilateral_transaction_manager::compute_smt_key(&head.devid(), &cp);
        let init = dsm::core::bilateral_transaction_manager::initial_chain_tip_from_device_ids(
            &head.devid(),
            &cp,
        );
        let out = head
            .advance(
                rk,
                cp,
                DsmOperation::Noop,
                vec![0xC0u8; 32],
                None,
                &[],
                Some(init),
                Some(AnchorLeafUpdate {
                    key: art.anchor_leaf.key,
                    new_value: art.anchor_leaf.new_value,
                }),
            )
            .expect("bearer advance");

        let ap = out.anchor_proofs.clone().expect("anchor proofs");
        let before = out.smt_proofs.pre_root;
        let after = out.child_r_a;
        let binding = AnchorStateBinding {
            sender_smt_root: &after,
            sender_smt_root_before: &before,
            prev_proof: &ap.parent,
            next_proof: &ap.child,
        };
        // COMPLETE pin = the producer's own enrolled material + the slot/stpub A would provision.
        let pin = FusedAnchorPin {
            bundle: art.pin.bundle,
            anchor_id: art.pin.anchor_id,
            enrolled_counter: art.pin.enrolled_counter,
            partition_pk: art.pin.partition_pk.clone(),
            uncompromised: true,
            verifier_slot: Some(1),
            chip_static_pubkey: Some([0xCC; 32]),
        };
        let pinned = PinnedAnchor::from_fused(&pin);
        let expected_h = (pin.enrolled_counter - 1) as u32; // H_post = H0 - (u_i+1), transfer 1
        let commitment = [0x42u8; 32];
        // The FROM read `H_pre = H0 - u_i` (= enrolled for transfer 1, u_i=0). This test drives the
        // TO (post-commit) read through the relay; the FROM read is supplied directly so the seam's
        // fail-closed behavior on the relay-read TO value is what is under test.
        let attested_pre = Some((pin.anchor_id, pin.enrolled_counter));

        // Helper: run the exact confirm seam (`resolve_attested_counter` -> predicate) and report the
        // acceptance result, mirroring `handle_confirm_request` byte-for-byte. `attested_post` is the
        // TO read the relay produced.
        let accept_with = |attested_post: Option<([u8; 32], u64)>| {
            accept_offline_release_with_relay_counter(
                &art.offline_release,
                Some(&pinned),
                Some(&art.appliance_prev_root),
                &recipient,
                &r_r,
                &policy_hash,
                &binding,
                attested_pre,
                attested_post,
            )
        };

        // ---- (1) HAPPY PATH: correct counter through the relay -> ACCEPT ---------------------------
        let a = Arc::new(TropicRelayRouter::new());
        a.set_local_pico(Arc::new(MockPico { h: expected_h }));
        let reader: Arc<dyn AnchorCounterReader> = Arc::new(RelayMockReader { a: Some(a) });
        let attested =
            resolve_attested_counter(Some(&pin), Some(reader.clone()), sender_dev, commitment)
                .await;
        assert_eq!(
            attested,
            Some((pin.anchor_id, expected_h as u64)),
            "the counter must flow through the relay to the seam"
        );
        accept_with(attested).expect("correct relay counter must accept");

        // ---- (2) NO READER INSTALLED -> None -> online recovery ------------------------------------
        let attested = resolve_attested_counter(Some(&pin), None, sender_dev, commitment).await;
        assert_eq!(attested, None, "no reader must yield no counter");
        assert!(
            matches!(accept_with(attested), Err(OfflineRecover::Predicate(_))),
            "no reader must recover online"
        );

        // ---- (3) NO LOCAL PICO on A (relay pipe down) -> None -> online recovery -------------------
        let a_nopico = Arc::new(TropicRelayRouter::new()); // no set_local_pico
        let reader_nopico: Arc<dyn AnchorCounterReader> =
            Arc::new(RelayMockReader { a: Some(a_nopico) });
        let attested =
            resolve_attested_counter(Some(&pin), Some(reader_nopico), sender_dev, commitment).await;
        assert_eq!(
            attested, None,
            "no local Pico must fail the relay read closed"
        );
        assert!(matches!(
            accept_with(attested),
            Err(OfflineRecover::Predicate(_))
        ));

        // ---- (4) INCOMPLETE PIN (no slot writer / no deriver provisioned it) -> None -> recovery ---
        // A first-transfer pin admitted before HW provisioning has verifier_slot = None; that is the
        // receiver-observable form of "no SeSlotWriter" and "no VerifierPairingDeriver" (the sender
        // never provisioned the slot / B never offered a pairing key), so the read is never attempted.
        let incomplete = FusedAnchorPin {
            verifier_slot: None,
            chip_static_pubkey: None,
            ..pin.clone()
        };
        let attested = resolve_attested_counter(
            Some(&incomplete),
            Some(reader.clone()),
            sender_dev,
            commitment,
        )
        .await;
        assert_eq!(
            attested, None,
            "an incomplete pin must never be counter-read"
        );
        assert!(matches!(
            accept_with(attested),
            Err(OfflineRecover::Predicate(_))
        ));

        // ---- (5) WRONG COUNTER through the relay -> predicate rejects -> recovery ------------------
        let a_wrong = Arc::new(TropicRelayRouter::new());
        a_wrong.set_local_pico(Arc::new(MockPico { h: expected_h + 1 }));
        let reader_wrong: Arc<dyn AnchorCounterReader> =
            Arc::new(RelayMockReader { a: Some(a_wrong) });
        let attested =
            resolve_attested_counter(Some(&pin), Some(reader_wrong), sender_dev, commitment).await;
        assert_eq!(
            attested,
            Some((pin.anchor_id, (expected_h + 1) as u64)),
            "the (wrong) counter still flows to the seam"
        );
        assert!(
            matches!(accept_with(attested), Err(OfflineRecover::Predicate(_))),
            "a wrong counter must be rejected by the predicate"
        );
    }

    /// SAFETY RAIL for the sender-release thread (both-or-neither): the SIMULATED post-root the
    /// sender puts on the confirm proofs MUST equal the CANONICAL committed post-root — so long as
    /// BOTH advances carry the same `anchor_leaf`. If either side omits it, the roots diverge (the
    /// sender's own §4.3 history would go Invalid). Both paths route through the deterministic
    /// `StateMachine::prepare_advance_relationship`, which already takes `anchor_leaf`, so this is
    /// provable before the higher commit layers are threaded.
    #[test]
    #[serial]
    fn sim_post_root_equals_canonical_committed_post_root_with_anchor_leaf() {
        use dsm::core::bilateral_transaction_manager::{
            anchor_state_commit, anchor_state_leaf_key, compute_smt_key,
            initial_chain_tip_from_device_ids,
        };
        use dsm::types::device_state::{AnchorLeafUpdate, DeviceState};

        let sdk = test_sdk();
        let ds = DeviceState::new([9u8; 32], sdk.device_info.device_id, vec![0u8; 64], 256);
        sdk.state_machine.lock().set_device_head(ds);

        let cp = [0x33u8; 32];
        let rel_key = compute_smt_key(&sdk.device_info.device_id, &cp);
        let init = initial_chain_tip_from_device_ids(&sdk.device_info.device_id, &cp);
        let op = DsmOperation::Noop;
        let deltas: &[dsm::types::device_state::BalanceDelta] = &[];
        let b = [0xB7u8; 32];
        let leaf = AnchorLeafUpdate {
            key: anchor_state_leaf_key(&b),
            new_value: anchor_state_commit(&b, &[0xA1u8; 32], &[0x51u8; 32], 1),
        };

        // `simulate_advance_for_confirm` is PURE (no head mutation), so we can call it twice.
        let sim_with = sdk
            .simulate_advance_for_confirm(
                rel_key,
                cp,
                op.clone(),
                deltas,
                Some(init),
                Some(leaf.clone()),
            )
            .expect("sim with anchor_leaf")
            .child_r_a;
        let sim_without = sdk
            .simulate_advance_for_confirm(rel_key, cp, op.clone(), deltas, Some(init), None)
            .expect("sim without anchor_leaf")
            .child_r_a;

        // The hazard is real: the anchor_leaf changes the device root. Omitting it on EITHER side
        // (sim carried it, a commit that dropped it) diverges -> §4.3 Invalid.
        assert_ne!(
            sim_with, sim_without,
            "anchor_leaf must change the committed device root"
        );

        // Canonical commit WITH the same anchor_leaf, via the deterministic prepare + install.
        let committed_root = {
            let mut sm = sdk.state_machine.lock();
            let outcome = sm
                .prepare_advance_relationship(
                    rel_key,
                    cp,
                    op.clone(),
                    deltas,
                    Some(init),
                    Some(leaf.clone()),
                )
                .expect("canonical prepare with anchor_leaf");
            sm.commit_advance(&outcome);
            outcome.new_device_state.root()
        };

        // Both-or-neither: sim post-root == canonical committed post-root when both carry the leaf.
        assert_eq!(
            sim_with, committed_root,
            "simulated post-root must equal the canonical committed post-root for the same anchor_leaf"
        );
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

        // Route through relationship path with self-loop for generic ops
        let dev_id = device.device_id;
        let rel_key = dsm::core::bilateral_transaction_manager::compute_smt_key(&dev_id, &dev_id);
        let init_tip = dsm::core::bilateral_transaction_manager::initial_chain_tip_from_device_ids(
            &dev_id, &dev_id,
        );
        let (executed, outcome) = sdk
            .execute_on_relationship(rel_key, dev_id, op, &[], Some(init_tip))
            .expect("execute operation");
        assert_ne!(executed.hash, [0u8; 32], "state hash should be non-zero");

        let rel_archived =
            crate::storage::client_db::get_bcr_chain_states(&device.device_id, false)
                .expect("load archived chain states");
        assert!(
            rel_archived
                .iter()
                .any(|state| state.compute_chain_tip()
                    == outcome.new_chain_state.compute_chain_tip()),
            "execute_on_relationship must archive the per-advance chain state"
        );
        let cached_head = crate::storage::client_db::load_bcr_device_head(&device.device_id)
            .expect("load cached device head")
            .expect("cached device head present");
        assert_eq!(
            cached_head.root(),
            outcome.new_device_state.root(),
            "head cache must track latest DeviceState root"
        );
        assert_eq!(
            cached_head.chain_tip(&rel_key),
            Some(outcome.new_chain_state.compute_chain_tip()),
            "head cache must carry latest relationship tip"
        );

        let restored = CoreSDK::new_with_device(device).expect("restore sdk from archive");
        let restored_head = restored.device_head().expect("restored device head");
        assert_eq!(
            restored_head.root(),
            outcome.new_device_state.root(),
            "CoreSDK startup must restore the latest cached DeviceState root"
        );
        assert_eq!(
            restored_head.chain_tip(&rel_key),
            Some(outcome.new_chain_state.compute_chain_tip()),
            "restored device head must carry the latest relationship tip"
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
        let dev_id2 = device.device_id;
        let rel_key2 =
            dsm::core::bilateral_transaction_manager::compute_smt_key(&dev_id2, &dev_id2);
        let init_tip2 = dsm::core::bilateral_transaction_manager::initial_chain_tip_from_device_ids(
            &dev_id2, &dev_id2,
        );
        let (advanced, _) = sdk
            .execute_on_relationship(rel_key2, dev_id2, op, &[], Some(init_tip2))
            .expect("execute operation");
        assert_ne!(advanced.hash, prior.hash, "state must advance");

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
