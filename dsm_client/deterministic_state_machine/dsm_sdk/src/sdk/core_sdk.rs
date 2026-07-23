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
    /// Device-level fused-anchor appliance (Software-Authority / Hardware-Identity; the
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
        Self::dual_write_advance_outcome_with_extra(outcome, bump_capsule, None)
    }

    /// `dual_write_advance_outcome` with an optional caller-supplied closure that
    /// runs INSIDE the same SQLite transaction, immediately before commit
    /// (§16.6 full-state consumption: the incoming-transfer apply path injects
    /// nonce consumption + the canonical apply record here so EVERY durable side
    /// effect of the apply commits together — all exist, or none do). The
    /// closure returning `Err` aborts the whole transaction; the in-memory head
    /// is then never installed and the operation is observable as never-happened.
    fn dual_write_advance_outcome_with_extra(
        outcome: &dsm::types::device_state::AdvanceOutcome,
        bump_capsule: bool,
        in_tx_extra: Option<
            &dyn Fn(
                &rusqlite::Transaction<'_>,
                &dsm::types::device_state::AdvanceOutcome,
            ) -> Result<(), DsmError>,
        >,
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
        // §16.6: caller-injected full-state-consumption work (nonce consumption +
        // canonical apply record for the incoming-transfer apply). Same tx — an
        // Err here rolls back the state persistence too.
        if let Some(extra) = in_tx_extra {
            extra(&tx, outcome)?;
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
        // Delegate to StateMachine::current_state. The canonical DeviceState head
        // is the single source of truth: the compat `State` is always synthesized
        // from the head's SMT root + balances, with no override that could shadow
        // it. Pre-genesis paths return None which we surface as an explicit error.
        let sm = self.state_machine.lock();
        sm.current_state()
            .ok_or_else(|| DsmError::state_machine("No current state available"))
    }

    /// Refresh the in-memory canonical tip from the latest archived sparse-replay
    /// snapshot for this device.
    pub fn restore_latest_archived_state_for_device(&self) -> Result<(), DsmError> {
        Self::restore_latest_archived_state(&self.state_machine, &self.device_info.device_id)
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
            None, // anchor_leaf — ordinary online transition
            None, // offline_spend — ordinary online transition, no allocation draw
        )
    }

    /// Advance the relationship, optionally committing an offline-bearer fused-anchor-state leaf
    /// (`anchor_leaf`) ATOMICALLY with the relationship leaf. The bilateral confirm path passes the
    /// same `anchor_leaf` its `simulate_advance_for_confirm` used, so the committed device root
    /// matches the on-wire proofs (both-or-neither); ordinary advances pass `None`.
    #[allow(clippy::too_many_arguments)]
    pub fn execute_on_relationship_with_anchor_leaf(
        &self,
        rel_key: [u8; 32],
        counterparty_devid: [u8; 32],
        operation: dsm::types::operations::Operation,
        deltas: &[dsm::types::device_state::BalanceDelta],
        initial_chain_tip: Option<[u8; 32]>,
        anchor_leaf: Option<dsm::types::device_state::AnchorLeafUpdate>,
        offline_spend: Option<dsm::types::device_state::OfflineSpend>,
    ) -> Result<(State, dsm::types::device_state::AdvanceOutcome), DsmError> {
        self.execute_on_relationship_inner(
            rel_key,
            counterparty_devid,
            operation,
            deltas,
            initial_chain_tip,
            anchor_leaf,
            offline_spend,
            None,
            None,
        )
    }

    /// Guarded relationship advance for the incoming-transfer apply (§16.6):
    /// `in_tx_extra` runs inside the single full-state apply transaction. The
    /// global `state_machine` lock is held across prepare → durable write →
    /// in-memory head install (device-root serialization across relationships).
    ///
    /// This layer performs NO comparison against the sender's signed tips. A
    /// relationship chain tip is a **per-device (side-specific) lineage value**:
    /// [`RelationshipChainState::compute_chain_tip`] hashes `counterparty_devid`
    /// (each side stores the OTHER party), `entropy` (derived from the device's
    /// own SMT root / own prior tip), and `balance_witness` (the device's own
    /// `B^T`). Two honest devices therefore NEVER produce equal chain tips for
    /// the same transfer, and they coincide at `embedded_parent` only on the
    /// first-ever advance, where both seed from the shared spec-canonical
    /// `initial_chain_tip`. Constraining this local advance by the sender's
    /// A-side values is a cross-lineage comparison: it rejects every honest
    /// transfer (child) and every transfer after the first (parent).
    /// A-side authority is validated where it belongs — see
    /// [`Self::apply_incoming_transfer_full_state`].
    /// §16.6 defect zero — STAGED advance: build artifacts between the pure
    /// prepare and the durable write, then commit them in the SAME transaction.
    ///
    /// THE ORDERING PROBLEM THIS SOLVES. An online send must not emit anything
    /// externally deliverable before the local state justifying it is durable:
    /// a storage quorum can accept a transfer, a local write can then fail, and
    /// a rollback would restore the debit while the message stays creditable.
    /// So proposal + gate + pending EK head + the exact envelope bytes have to
    /// land in one transaction with the canonical advance.
    ///
    /// But the receipt cannot be built inside that transaction: signing reads
    /// cert heads through `get_connection()`, and the advance already holds
    /// that single global mutex — re-entering it deadlocks. `prepare_advance_relationship`
    /// is pure (no writes), which is what makes the split legal:
    ///
    /// ```text
    /// prepare (pure)  →  build_artifacts (DB reads, signing)  →  ONE tx { advance + write_extra }
    /// ```
    ///
    /// `build_artifacts` sees the `AdvanceOutcome` (canonical parent/child, SMT
    /// roots) and returns whatever the caller needs to persist; `write_extra`
    /// then writes it inside the advance transaction. If `build_artifacts`
    /// fails — including a lost cert-head CAS — nothing is written and nothing
    /// was ever deliverable.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn execute_on_relationship_staged<A>(
        &self,
        rel_key: [u8; 32],
        counterparty_devid: [u8; 32],
        operation: dsm::types::operations::Operation,
        deltas: &[dsm::types::device_state::BalanceDelta],
        initial_chain_tip: Option<[u8; 32]>,
        build_artifacts: impl FnOnce(&dsm::types::device_state::AdvanceOutcome) -> Result<A, DsmError>,
        write_extra: impl Fn(
            &rusqlite::Transaction<'_>,
            &dsm::types::device_state::AdvanceOutcome,
            &A,
        ) -> Result<(), DsmError>,
    ) -> Result<(State, dsm::types::device_state::AdvanceOutcome, A), DsmError> {
        // Artifacts are built once in `pre_write` (outside the transaction, so
        // signing may read the DB) and shared with the in-tx writer through a
        // cell. The in-tx closure NEVER rebuilds them — retries and the durable
        // record must carry byte-identical bytes.
        let built: std::cell::RefCell<Option<A>> = std::cell::RefCell::new(None);
        let builder: std::cell::RefCell<Option<_>> = std::cell::RefCell::new(Some(build_artifacts));

        let pre = |outcome: &dsm::types::device_state::AdvanceOutcome| -> Result<(), DsmError> {
            let f = builder.borrow_mut().take().ok_or_else(|| {
                DsmError::internal(
                    "staged advance: artifact builder already consumed",
                    None::<std::convert::Infallible>,
                )
            })?;
            *built.borrow_mut() = Some(f(outcome)?);
            Ok(())
        };

        let write = |tx: &rusqlite::Transaction<'_>,
                     outcome: &dsm::types::device_state::AdvanceOutcome|
         -> Result<(), DsmError> {
            let guard = built.borrow();
            let artifacts = guard.as_ref().ok_or_else(|| {
                DsmError::internal(
                    "staged advance: artifacts missing at write time",
                    None::<std::convert::Infallible>,
                )
            })?;
            write_extra(tx, outcome, artifacts)
        };

        let (state, outcome) = self.execute_on_relationship_inner(
            rel_key,
            counterparty_devid,
            operation,
            deltas,
            initial_chain_tip,
            None,
            None,
            Some(&write),
            Some(&pre),
        )?;

        let artifacts = built.borrow_mut().take().ok_or_else(|| {
            DsmError::internal(
                "staged advance committed without artifacts",
                None::<std::convert::Infallible>,
            )
        })?;
        Ok((state, outcome, artifacts))
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn execute_on_relationship_guarded(
        &self,
        rel_key: [u8; 32],
        counterparty_devid: [u8; 32],
        operation: dsm::types::operations::Operation,
        deltas: &[dsm::types::device_state::BalanceDelta],
        initial_chain_tip: Option<[u8; 32]>,
        in_tx_extra: Option<
            &dyn Fn(
                &rusqlite::Transaction<'_>,
                &dsm::types::device_state::AdvanceOutcome,
            ) -> Result<(), DsmError>,
        >,
    ) -> Result<(State, dsm::types::device_state::AdvanceOutcome), DsmError> {
        self.execute_on_relationship_inner(
            rel_key,
            counterparty_devid,
            operation,
            deltas,
            initial_chain_tip,
            None,
            None,
            in_tx_extra,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn execute_on_relationship_inner(
        &self,
        rel_key: [u8; 32],
        counterparty_devid: [u8; 32],
        operation: dsm::types::operations::Operation,
        deltas: &[dsm::types::device_state::BalanceDelta],
        initial_chain_tip: Option<[u8; 32]>,
        anchor_leaf: Option<dsm::types::device_state::AnchorLeafUpdate>,
        offline_spend: Option<dsm::types::device_state::OfflineSpend>,
        in_tx_extra: Option<
            &dyn Fn(
                &rusqlite::Transaction<'_>,
                &dsm::types::device_state::AdvanceOutcome,
            ) -> Result<(), DsmError>,
        >,
        // §16.6 staged advance: runs AFTER the pure prepare and BEFORE the
        // durable write opens its transaction. This is the only window in
        // which a caller may do work that itself touches the database (e.g.
        // per-step EK signing, which reads cert heads) — inside the write
        // transaction the global connection mutex is held and re-entry
        // deadlocks. An Err here aborts before anything is persisted.
        pre_write: Option<
            &dyn Fn(&dsm::types::device_state::AdvanceOutcome) -> Result<(), DsmError>,
        >,
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
            offline_spend, // Some(..) draws the value from the offline-cash allocation instead of online balance
        )?;
        // The sender's signed A-side pair is deliberately NOT compared against
        // this device's own lineage here — see the doc comment on
        // `execute_on_relationship_guarded` for why such a comparison can never
        // hold between two honest devices. The local advance is authoritative
        // for the local lineage; A-side authority is enforced upstream in
        // `apply_incoming_transfer_full_state`.
        // The accepted-state index is bumped ATOMICALLY inside this transaction
        // (spec §5.1) — a frontier-changing transition can never persist without
        // the capsule being marked dirty. `in_tx_extra` (nonce consumption +
        // canonical apply record on the incoming-transfer path) runs in the SAME
        // transaction (§16.6 full-state consumption).
        // Staged artifact build (signing, envelope construction) — outside the
        // write transaction, so DB reads here cannot deadlock. Failing now
        // means nothing was persisted and nothing became deliverable.
        if let Some(pre) = pre_write {
            pre(&outcome)?;
        }
        Self::dual_write_advance_outcome_with_extra(&outcome, frontier_changed, in_tx_extra)?;
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

    /// **Load** `amount` of `asset` from the online balance into this device's offline-cash allocation,
    /// bound to the enrolled anchor bundle `B`. An online, conserved regime shift: online
    /// `available` drops and the device-bound allocation rises by the same amount (device root advances).
    /// Fail-closed persistence: the new device head is durably written BEFORE it is installed, so a
    /// persist failure leaves the in-memory head on the prior state (the load is never-happened).
    pub fn load_offline_cash(
        &self,
        anchor_bundle_b: [u8; 32],
        asset: [u8; 32],
        amount: u64,
    ) -> Result<dsm::types::device_state::OfflineAllocationOutcome, DsmError> {
        let mut sm = self.state_machine.lock();
        let outcome = {
            let ds = sm.device_head().ok_or_else(|| {
                DsmError::state_machine(
                    "load_offline_cash: DeviceState not initialized (genesis first)",
                )
            })?;
            ds.load_offline_cash(&anchor_bundle_b, &asset, amount)?
        };
        crate::storage::client_db::update_bcr_device_head(&outcome.new_device_state).map_err(
            |e| {
                DsmError::storage(
                    format!("load_offline_cash: persist device head failed: {e}"),
                    None::<std::io::Error>,
                )
            },
        )?;
        sm.set_device_head(outcome.new_device_state.clone());
        Ok(outcome)
    }

    /// **Unload** `amount` from this device's offline-cash allocation back to the online balance
    /// (reconcile): the allocation drops and online `available` rises by the same amount. Same
    /// fail-closed persist-before-install discipline as [`Self::load_offline_cash`].
    pub fn unload_offline_cash(
        &self,
        anchor_bundle_b: [u8; 32],
        asset: [u8; 32],
        amount: u64,
    ) -> Result<dsm::types::device_state::OfflineAllocationOutcome, DsmError> {
        let mut sm = self.state_machine.lock();
        let outcome = {
            let ds = sm.device_head().ok_or_else(|| {
                DsmError::state_machine(
                    "unload_offline_cash: DeviceState not initialized (genesis first)",
                )
            })?;
            ds.unload_offline_cash(&anchor_bundle_b, &asset, amount)?
        };
        crate::storage::client_db::update_bcr_device_head(&outcome.new_device_state).map_err(
            |e| {
                DsmError::storage(
                    format!("unload_offline_cash: persist device head failed: {e}"),
                    None::<std::io::Error>,
                )
            },
        )?;
        sm.set_device_head(outcome.new_device_state.clone());
        Ok(outcome)
    }

    /// Current offline-cash allocation balance for `asset` under the enrolled anchor bundle `B`.
    pub fn offline_cash_balance(&self, anchor_bundle_b: [u8; 32], asset: [u8; 32]) -> u64 {
        let sm = self.state_machine.lock();
        match sm.device_head() {
            Some(ds) => {
                let key = dsm::types::offline_allocation_leaf::offline_allocation_key(
                    &ds.genesis_digest(),
                    &ds.devid(),
                    &anchor_bundle_b,
                    &asset,
                );
                ds.offline_allocation(&key)
            }
            None => 0,
        }
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
    #[allow(clippy::too_many_arguments)]
    pub fn simulate_advance_for_confirm(
        &self,
        rel_key: [u8; 32],
        counterparty_devid: [u8; 32],
        operation: dsm::types::operations::Operation,
        deltas: &[dsm::types::device_state::BalanceDelta],
        initial_chain_tip: Option<[u8; 32]>,
        anchor_leaf: Option<dsm::types::device_state::AnchorLeafUpdate>,
        offline_spend: Option<dsm::types::device_state::OfflineSpend>,
    ) -> Result<dsm::types::device_state::AdvanceOutcome, DsmError> {
        let sm = self.state_machine.lock();
        sm.prepare_advance_relationship(
            rel_key,
            counterparty_devid,
            operation,
            deltas,
            initial_chain_tip,
            anchor_leaf,
            offline_spend,
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
        let outcome = sm.prepare_advance_relationship(
            rel_key,
            dev_id,
            mint,
            &deltas,
            Some(init_tip),
            None, // anchor_leaf — dev-seed mint is an ordinary ingress transition
            None, // offline_spend — online mint, no allocation draw
        )?;
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
/// transfer: the wire release + the anchor-state leaf update the DSM advance must apply + the
/// appliance frontier lineage the receiver pins/adopts + the pin material to admit the anchor.
#[derive(Clone, Debug)]
pub struct OfflineBearerArtifacts {
    /// prost-encoded `dsm.anchor.OfflineRelease` (goes on `BilateralConfirmRequest.offline_release`).
    pub offline_release: Vec<u8>,
    /// The anchor-state leaf update the DSM advance applied (`Some(...)` on the canonical commit).
    pub anchor_leaf: dsm::types::device_state::AnchorLeafUpdate,
    /// The appliance frontier `h_i` this transfer consumes (the receiver's accepted frontier).
    pub appliance_prev_root: [u8; 32],
    /// The successor frontier `h_{i+1}` the receiver adopts after acceptance.
    pub appliance_next_root: [u8; 32],
    /// The pin material (B, anchor_id, H0, pk_host, pk_chip) the receiver admits for this anchor.
    pub pin: crate::anchor::AnchorPin,
}

/// A STAGED offline-bearer transition (v2 producer phase 1): the transition `Δ` and its successor
/// anchor-state leaf are fully determined from the appliance's active state, but NOTHING has been
/// signed or committed — the appliance is untouched. The DSM layer runs its advance simulation over
/// `anchor_leaf` to materialize the real device SMT roots `R_i`/`R_{i+1}` and the inclusion proofs
/// `Π_i`/`Π_{i+1}`, then feeds those into [`CoreSDK::release_offline_bearer`] so the release is
/// born with the real roots in its signed transcript (no placeholder stamping, no re-stamp).
#[derive(Clone)]
pub struct StagedBearerTransition {
    /// The fully-formed transition `Δ` (owned; `as_transition()` for the appliance call).
    pub transition: anchor_core::root_advance::OwnedTransition,
    /// The successor anchor-state leaf `L_{i+1} = H("DSM/anchor-state/v2" ‖ B ‖ h_{i+1} ‖ u_{i+1})`
    /// at the stable per-device key — what the DSM advance commits atomically with the transfer.
    pub anchor_leaf: dsm::types::device_state::AnchorLeafUpdate,
    /// The appliance frontier `h_i` this transfer consumes.
    pub appliance_prev_root: [u8; 32],
    /// The successor frontier `h_{i+1} = H(h_i ‖ D)`.
    pub appliance_next_root: [u8; 32],
    /// The pin material the receiver admits.
    pub pin: crate::anchor::AnchorPin,
}

/// Read-only snapshot of the sender's anchor appliance for the `anchor.status` diagnostics route
/// (signal (c)). Purely observational: NO staging, NO counter move, NO device-state mutation.
/// A disconnected snapshot (no appliance attachable) reports `connected = false` with zeroed
/// identity — a diagnostics read must never fail the route.
#[derive(Clone, Debug, Default)]
pub struct AnchorStatusSnapshot {
    pub connected: bool,
    pub anchor_id: [u8; 32],
    pub pk_chip: Vec<u8>,
    pub partition_pk: Vec<u8>,
    pub anchor_counter: u64,
    pub frontier_root: [u8; 32],
    pub enrolled_counter: u64,
    pub bundle: [u8; 32],
    pub status: String,
}

impl CoreSDK {
    /// Read-only anchor appliance snapshot for the `anchor.status` diagnostics route (signal (c)).
    /// Attaches (and caches) the appliance via the installed factory if not already attached, then
    /// reads `pin()`/`status()`. Unlike [`stage_offline_bearer_transition`](Self::stage_offline_bearer_transition)
    /// this performs NO anchor-state leaf reconciliation and NO mutation. When no appliance can
    /// attach (no device / fail-closed) it returns a disconnected snapshot rather than an error, so
    /// the diagnostics panel can render "no anchor connected" instead of failing.
    #[must_use]
    pub fn anchor_appliance_status(&self) -> AnchorStatusSnapshot {
        let dev = self.device_info.device_id;
        let seed = |tag: &str| blake3_cat(&[tag.as_bytes(), &dev]);

        let mut guard = self.anchor_appliance.lock();
        if guard.is_none() {
            let attached: Result<Box<dyn crate::anchor::AnchorAppliance + Send>, DsmError> =
                match crate::bridge::anchor_appliance_factory() {
                    Some(factory) => factory(),
                    None => hardware_appliance_or_fail(&seed, dev),
                };
            match attached {
                Ok(a) => *guard = Some(a),
                Err(e) => {
                    log::info!("[anchor.status] no anchor appliance attached: {e}");
                    return AnchorStatusSnapshot {
                        status: "no anchor appliance connected".into(),
                        ..Default::default()
                    };
                }
            }
        }

        let app = match guard.as_mut() {
            Some(a) => a,
            None => {
                return AnchorStatusSnapshot {
                    status: "no anchor appliance connected".into(),
                    ..Default::default()
                }
            }
        };

        let pin = app.pin();
        match app.status() {
            Ok(s) => AnchorStatusSnapshot {
                connected: true,
                anchor_id: pin.anchor_id,
                pk_chip: pin.pk_chip,
                partition_pk: pin.partition_pk,
                anchor_counter: s.anchor_counter,
                frontier_root: s.root,
                enrolled_counter: pin.enrolled_counter,
                bundle: pin.bundle,
                status: format!("anchor connected (counter u={})", s.anchor_counter),
            },
            Err(e) => {
                log::warn!("[anchor.status] appliance attached but OP_STATUS failed: {e}");
                AnchorStatusSnapshot {
                    connected: false,
                    anchor_id: pin.anchor_id,
                    pk_chip: pin.pk_chip,
                    partition_pk: pin.partition_pk,
                    enrolled_counter: pin.enrolled_counter,
                    bundle: pin.bundle,
                    status: "anchor present but status read failed".into(),
                    ..Default::default()
                }
            }
        }
    }

    /// v2 producer phase 1 (Software-Authority / Hardware-Identity): lazily attach the appliance
    /// (reconciling the DeviceState anchor-state leaf to the chip's CURRENT active state), then
    /// deterministically stage the next transition — compute `D`, the successor frontier
    /// `h_{i+1} = H(h_i ‖ D)`, and the successor anchor-state leaf. NO appliance mutation, NO
    /// signatures, NO counter move: the caller first simulates the DSM advance over `anchor_leaf`
    /// to obtain the real device roots `R_i`/`R_{i+1}`, then calls
    /// [`release_offline_bearer`](Self::release_offline_bearer).
    #[allow(clippy::too_many_arguments)]
    pub fn stage_offline_bearer_transition(
        &self,
        relationship_id: [u8; 32],
        recipient_device_id: [u8; 32],
        object_id: [u8; 32],
        payload_hash: [u8; 32],
        authority_policy_hash: [u8; 32],
        action_type: u32,
        action_fields: Vec<u8>,
        receiver_challenge: [u8; 32],
    ) -> Result<StagedBearerTransition, DsmError> {
        use anchor_core::root_advance::{anchor_root_advance, anchor_state_leaf, transition_digest};
        use dsm::core::bilateral_transaction_manager::anchor_state_leaf_key;

        let dev = self.device_info.device_id;
        let seed = |tag: &str| blake3_cat(&[tag.as_bytes(), &dev]);

        let mut guard = self.anchor_appliance.lock();
        if guard.is_none() {
            // Sender-side appliance: the physical RP2350/TROPIC01 via the installed factory. On device
            // an absent factory FAILS CLOSED ("offline = chips"); the in-process mock is the test-only
            // producer. The factory is called once and cached (stateful appliance). Construction only —
            // the anchor-state-leaf reconcile is done PER stage call below (see the comment there), not
            // once at birth: the chip can advance between attach and a later transfer.
            let a: Box<dyn crate::anchor::AnchorAppliance + Send> =
                match crate::bridge::anchor_appliance_factory() {
                    Some(factory) => factory()?,
                    None => hardware_appliance_or_fail(&seed, dev)?,
                };
            *guard = Some(a);
        }

        let app = guard.as_mut().ok_or_else(|| {
            DsmError::state_machine("offline-bearer: anchor appliance not birthed")
        })?;
        let pin = app.pin();

        // §26 recovery gate: NEVER stage a fresh bearer over an unsettled chip. OBSERVE recover() and
        // apply the existing host policy (`recovery_action`); anything other than Ready fails closed to
        // online recovery. This does NOT cancel or erase here — an orphaned/committed record is left for
        // the dedicated `resolve_prepared_on_reattach` seam (a Committed release must be re-emitted,
        // never erased, §26). Conservative `prepared_owned_by_session = true`: never auto-cancel in stage.
        let action = crate::anchor::recovery_action(app.recover()?, true);
        if action != crate::anchor::RecoveryAction::Ready {
            return Err(DsmError::invalid_operation(format!(
                "offline-bearer stage: appliance not Ready ({action:?}) — resolve/re-emit via recovery \
                 before staging a new transfer (fail closed to online)"
            )));
        }

        // Active state: the frontier this transfer consumes + the current counter floor.
        let before = app.status()?;
        let appliance_prev_root = before.root;

        // PER-CALL reconcile (the fix for receiver `PrevStateUncommitted`): keep the device-head
        // anchor-state leaf byte-equal to the value the certificate will claim —
        // `anchor_state_leaf(B, before.root, before.anchor_counter)` at `anchor_state_leaf_key(B)`.
        // `before` is a LIVE chip status read that drives cert.prev_frontier/anchor_counter, so the
        // leaf the sim's Π_i proves must be reconciled to the SAME live state. This previously ran only
        // once at first attach (`if guard.is_none()`), so any chip move afterward that was not mirrored
        // into a persisted device head — a committed-but-failed attempt (COMMIT burns the counter +
        // FINALIZE advances the frontier), a reflash-birth, or an online-only advance that rebuilt the
        // head — left the stored leaf stale, Π_i proved a stale value, and the receiver rejected.
        // `with_anchor_state_leaf` touches only `anchor_state_leaf_key(B)`; balances / relationship tips
        // / offline_allocations are untouched (allocation conservation is unaffected).
        {
            let value = anchor_state_leaf(&pin.bundle, &before.root, before.anchor_counter);
            let key = anchor_state_leaf_key(&pin.bundle);
            let mut sm = self.state_machine.lock();
            let ds = sm.device_head().ok_or_else(|| {
                DsmError::state_machine(
                    "offline-bearer: DeviceState not initialized (genesis first)",
                )
            })?;
            let stored = ds.extra_leaves_snapshot().get(&key).copied();
            // No-op guard: an idempotent same-value write preserves the SMT root, but the explicit
            // skip makes the determinism guarantee obvious and avoids a needless head replacement.
            if stored != Some(value) {
                log::info!(
                    "[offline-bearer] anchor-state leaf reconciled to live chip: u(anchor_counter)={} (stored={}, chip is source of truth)",
                    before.anchor_counter,
                    stored.map(|v| crate::util::text_id::encode_base32_crockford(&v[..6])).unwrap_or_else(|| "absent".into()),
                );
                let bootstrapped = ds.with_anchor_state_leaf(&key, &value)?;
                sm.set_device_head(bootstrapped);
            }
        }

        // Stage Δ°: the digest excludes `next_root`, so D is computable first and the successor
        // frontier is derived, never invented.
        let mut owned = anchor_core::root_advance::OwnedTransition {
            relationship_id,
            object_id,
            sender_device_id: dev,
            recipient_device_id,
            prev_root: appliance_prev_root,
            next_root: [0u8; 32],
            anchor_counter: before.anchor_counter,
            next_anchor_counter: before.anchor_counter + 1,
            action_type,
            action_fields,
            payload_hash,
            old_leaf_proof: Vec::new(),
            new_leaf_proof: Vec::new(),
            authority_policy_hash,
        };
        let d = transition_digest(&owned.as_transition(), &receiver_challenge);
        let appliance_next_root = anchor_root_advance(&appliance_prev_root, &d);
        owned.next_root = appliance_next_root;

        // Successor anchor-state leaf: what the device SMT holds AFTER this transfer commits.
        let anchor_leaf = dsm::types::device_state::AnchorLeafUpdate {
            key: anchor_state_leaf_key(&pin.bundle),
            new_value: anchor_state_leaf(
                &pin.bundle,
                &appliance_next_root,
                before.anchor_counter + 1,
            ),
        };

        Ok(StagedBearerTransition {
            transition: owned,
            anchor_leaf,
            appliance_prev_root,
            appliance_next_root,
            pin,
        })
    }

    /// v2 producer phase 2: drive the appliance PREPARE(t, r_R, R_i, R_{i+1}) → COMMIT → EMIT →
    /// FINALIZE for a staged transition, with the REAL device SMT roots the caller's advance
    /// simulation produced. The release is emitted with those roots inside the signed transcript
    /// (σ^DSM binding is the caller's; σ^chip + σ^host are produced here) — there is no placeholder
    /// stamping and no post-hoc re-stamp. The anchor-state inclusion proofs `Π_i`/`Π_{i+1}` (from
    /// the same simulation) are attached to the release package here — they sit OUTSIDE all three
    /// signatures (the receiver verifies them independently against `R_i`/`R_{i+1}`), so attaching
    /// them mutates no signed bytes. Fails closed if the appliance's post-finalize frontier
    /// diverges from the staged successor.
    pub fn release_offline_bearer(
        &self,
        staged: &StagedBearerTransition,
        receiver_challenge: [u8; 32],
        sender_device_root_before: [u8; 32],
        sender_device_root_after: [u8; 32],
        anchor_smt_proof_before: Vec<u8>,
        anchor_smt_proof_after: Vec<u8>,
    ) -> Result<OfflineBearerArtifacts, DsmError> {
        use prost::Message;

        let mut guard = self.anchor_appliance.lock();
        let app = guard.as_mut().ok_or_else(|| {
            DsmError::state_machine("offline-bearer: anchor appliance not birthed")
        })?;

        app.prepare(
            &staged.transition.as_transition(),
            &receiver_challenge,
            &sender_device_root_before,
            &sender_device_root_after,
        )?;
        app.commit()?;
        let emitted = app.emit()?;
        let new_frontier = app.finalize()?;
        if new_frontier != staged.appliance_next_root {
            return Err(DsmError::state_machine(
                "offline-bearer: post-finalize frontier diverged from the staged successor (fail closed)",
            ));
        }

        // Attach Π_i/Π_{i+1} to the package (unsigned carrier fields; see method doc).
        let mut rel =
            anchor_core::proto::pb::OfflineRelease::decode(&emitted[..]).map_err(|e| {
                DsmError::serialization_error(
                    "OfflineRelease",
                    "protobuf",
                    Some(e.to_string()),
                    Some(e),
                )
            })?;
        rel.anchor_smt_proof_before = anchor_smt_proof_before;
        rel.anchor_smt_proof_after = anchor_smt_proof_after;

        Ok(OfflineBearerArtifacts {
            offline_release: rel.encode_to_vec(),
            anchor_leaf: staged.anchor_leaf.clone(),
            appliance_prev_root: staged.appliance_prev_root,
            appliance_next_root: staged.appliance_next_root,
            pin: staged.pin.clone(),
        })
    }

    /// Cleanup: drive an ABANDONED prepared release back to `Ready` (e.g. the confirm build failed
    /// between PREPARE and COMMIT). `cancel()` discards the uncommitted record — no counter ever
    /// moved, so nothing is lost. Idempotent and best-effort: a no-op when there is no appliance or
    /// it is not `Prepared`.
    pub fn cancel_offline_bearer_release(&self) -> Result<(), DsmError> {
        let mut guard = self.anchor_appliance.lock();
        if let Some(app) = guard.as_mut() {
            match app.cancel() {
                Ok(()) => log::info!(
                    "[offline-bearer] cancelled an abandoned prepared bearer (appliance → Ready)"
                ),
                // `cancel()` is only valid in `Prepared`; a not-Prepared appliance is already fine.
                Err(e) => {
                    log::debug!("[offline-bearer] cancel no-op (appliance not Prepared): {e}")
                }
            }
        }
        Ok(())
    }

    /// §27/§28 host recovery seam. OBSERVE the sender appliance's recovery state at a re-attach
    /// (process restart / power loss) via [`AnchorAppliance::recover`], then apply the host cancel
    /// policy ([`crate::anchor::recovery_action`]): cancel ONLY an orphaned uncommitted `Prepared` —
    /// one with no in-flight/durable session owning it and whose counter has not moved. A committed
    /// release is NEVER cancelled or erased here (it is re-emitted or resolved online); a mismatch
    /// downgrades online. `recover()` observes; this method decides and executes ONLY the
    /// orphaned-`Prepared` cancel.
    ///
    /// `prepared_owned_by_session` is supplied by the caller — the bilateral handler knows whether an
    /// in-flight session still holds the matching prepared bearer. Pass `false` at a cold re-attach
    /// where the in-memory sessions are gone. Returns the decided [`crate::anchor::RecoveryAction`].
    pub fn resolve_prepared_on_reattach(
        &self,
        prepared_owned_by_session: bool,
    ) -> Result<crate::anchor::RecoveryAction, DsmError> {
        let mut guard = self.anchor_appliance.lock();
        let Some(app) = guard.as_mut() else {
            // No appliance attached yet -> nothing is prepared -> Ready.
            return Ok(crate::anchor::RecoveryAction::Ready);
        };
        let outcome = app.recover()?;
        let action = crate::anchor::recovery_action(outcome, prepared_owned_by_session);
        if action == crate::anchor::RecoveryAction::CancelOrphanedPrepared {
            // Host policy executes the cancel — `recover()` did not. Only an orphaned uncommitted
            // Prepared reaches here (no owning session, counter not moved), so nothing is lost.
            app.cancel()?;
            log::info!(
                "[offline-bearer] re-attach cancelled an orphaned prepared bearer (appliance → Ready)"
            );
        }
        Ok(action)
    }
}

/* ------------------------------ Private helpers ------------------------- */

/// The sender-side appliance when NO hardware factory is installed. Test builds get the in-process
/// mock so the release-path unit tests keep exercising the v2 producer; real device builds FAIL
/// CLOSED — offline-bearer strictly requires the physical chip ("offline = chips").
#[cfg(test)]
fn hardware_appliance_or_fail(
    seed: &impl Fn(&str) -> [u8; 32],
    dev: [u8; 32],
) -> Result<Box<dyn crate::anchor::AnchorAppliance + Send>, DsmError> {
    use crate::anchor::{BirthConfig, InProcessAnchorAppliance};
    Ok(Box::new(InProcessAnchorAppliance::birth(&BirthConfig {
        partition_trng: seed("DSM/anchor/partition-trng/v1"),
        host_nonce: seed("DSM/anchor/host-nonce/v1"),
        device_id: dev,
        policy_hash: seed("DSM/anchor/policy-hash/v1"),
        partition_device_id: seed("DSM/anchor/partition-device-id/v1"),
        anchor_id: seed("DSM/anchor/anchor-id/v1"),
        partition_key_seed: seed("DSM/anchor/partition-key-seed/v1"),
        enrolled_counter: 1_000_000,
        genesis_root: seed("DSM/anchor/genesis-root/v1"),
        chip_birth_witness: seed("DSM/anchor/chip-birth-witness/v1"),
        chip_seed: seed("DSM/anchor/chip-seed/v1"),
        online_id_pk: Vec::new(),
    })?))
}

/// User-facing error when an offline-bearer send finds no anchor appliance connected. It rides the
/// `DsmError` up through the confirm-build failure into the `BilateralEventFailed` event's message,
/// where the frontend maps it to a "connect your anchor device" toast (Stage 4 Slice 3 signal a).
/// A const so the not(test) producer and the wording test share one source of truth.
pub(crate) const OFFLINE_BEARER_NO_APPLIANCE_MSG: &str =
    "offline-bearer requires the anchor appliance; connect the anchor device (Pico) and retry (fail closed)";

#[cfg(not(test))]
fn hardware_appliance_or_fail(
    _seed: &impl Fn(&str) -> [u8; 32],
    _dev: [u8; 32],
) -> Result<Box<dyn crate::anchor::AnchorAppliance + Send>, DsmError> {
    Err(DsmError::invalid_operation(OFFLINE_BEARER_NO_APPLIANCE_MSG))
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
    /// Apply an INCOMING online transfer with §16.6 full-state consumption.
    ///
    /// Lookup-before-execute: the canonical apply record is consulted BEFORE any
    /// mutable-state inspection or execution — an exact duplicate returns the
    /// loaded record with NO re-execution and NO re-credit; a different identity
    /// colliding on (relationship, parent) or the nonce is a `Conflict`. A fresh
    /// request executes under the global `state_machine` lock (held across
    /// canonical-parent validation → prepare → single full-state transaction →
    /// in-memory head install) with ONE atomic SQLite transaction committing the
    /// DeviceState successor (balances + relationship tip inside it), the BCR
    /// archive, the device head, the nonce consumption, the recovery index, and
    /// the `CanonicalApplyRecord` — all exist or none do. Token/UI projections
    /// stay best-effort post-commit and never invalidate the canonical commit.
    pub fn apply_incoming_transfer_full_state(
        &self,
        op: dsm::types::operations::Operation,
        tx_id: &crate::types::identifiers::TransactionId,
        sender_device_id: &str,
        canonical_operation_bytes: &[u8],
        signed_parent_tip: [u8; 32],
        signed_child_tip: [u8; 32],
    ) -> Result<crate::sdk::apply_outcome::ApplyOutcome, DsmError> {
        use crate::sdk::apply_outcome::ApplyOutcome;
        use crate::storage::client_db::{
            self as cdb, CanonicalApplyInsertOutcome, CanonicalApplyLookup, CanonicalApplyRecord,
        };
        use crate::storage::codecs::hash_blake3_bytes;

        // ---- validate the request (fail closed) ----
        let (nonce, amount_val, to_device_id, token_id) = match &op {
            dsm::types::operations::Operation::Transfer {
                nonce,
                amount,
                to_device_id,
                token_id,
                ..
            } => (
                nonce.clone(),
                amount.value(),
                to_device_id.clone(),
                token_id.clone(),
            ),
            _ => {
                return Err(DsmError::invalid_operation(
                    "apply_incoming_transfer_full_state: only Transfer operations are accepted",
                ))
            }
        };
        if nonce.is_empty() {
            return Err(DsmError::invalid_operation(
                "apply_incoming_transfer_full_state: empty transfer nonce",
            ));
        }
        if amount_val == 0 {
            return Err(DsmError::invalid_operation(
                "apply_incoming_transfer_full_state: zero transfer amount",
            ));
        }
        if canonical_operation_bytes.is_empty() {
            return Err(DsmError::invalid_operation(
                "apply_incoming_transfer_full_state: empty canonical operation bytes",
            ));
        }
        let local_device_id_bytes = crate::sdk::app_state::AppState::get_device_id()
            .ok_or_else(|| DsmError::state_machine("missing local device_id (AppState)"))?;
        if local_device_id_bytes.len() != 32 {
            return Err(DsmError::state_machine(
                "local device_id must be 32 bytes (AppState corrupt)",
            ));
        }
        if to_device_id.as_slice() != local_device_id_bytes.as_slice() {
            return Err(DsmError::invalid_operation(
                "apply_incoming_transfer_full_state: transfer not addressed to this device",
            ));
        }
        let sender_id_bytes = crate::util::text_id::decode_base32_crockford(sender_device_id)
            .ok_or_else(|| DsmError::invalid_operation("sender_device_id not valid base32"))?;
        if sender_id_bytes.len() != 32 {
            return Err(DsmError::invalid_operation(
                "apply_incoming_transfer_full_state: sender_device_id must decode to 32 bytes",
            ));
        }
        let mut local_arr = [0u8; 32];
        local_arr.copy_from_slice(&local_device_id_bytes);
        let mut sender_arr = [0u8; 32];
        sender_arr.copy_from_slice(&sender_id_bytes);

        // ---- derive the PRE-EXECUTION request identity (no roots) ----
        let rel_key =
            dsm::core::bilateral_transaction_manager::compute_smt_key(&local_arr, &sender_arr);
        // AUTHORITY SOURCING: the request pair comes from the SIGNED receipt's
        // ASYMMETRIC canonical tips — the same formula-space as the DeviceState
        // embedded relationship lineage this apply advances. The SYMMETRIC
        // (`compute_successor_tip`) lineage is a projection/routing space and is
        // NEVER derived or compared here (cross-space comparison was the
        // AWYPCNK8 false-conflict bug). C_pre is bound to the signed parent.
        let parent_tip = signed_parent_tip;
        let child_tip = signed_child_tip;
        let precommit_digest = dsm::core::bilateral_transaction_manager::compute_precommit(
            &parent_tip,
            canonical_operation_bytes,
            &nonce,
        );
        let operation_digest = {
            let mut h = dsm::crypto::blake3::dsm_domain_hasher("DSM/canonical-apply-op-digest/v1");
            h.update(canonical_operation_bytes);
            let mut out = [0u8; 32];
            out.copy_from_slice(&h.finalize().as_bytes()[..32]);
            out
        };
        let nonce_hash = hash_blake3_bytes(&nonce);
        let canonical_apply_id = cdb::compute_canonical_apply_id(
            &rel_key,
            &parent_tip,
            &child_tip,
            &precommit_digest,
            &operation_digest,
            &sender_arr,
            &local_arr,
            &nonce_hash,
        );

        // ---- lookup BEFORE inspecting any mutable state or executing ----
        match cdb::lookup_canonical_apply_status(
            &canonical_apply_id,
            &rel_key,
            &parent_tip,
            &nonce_hash,
        )
        .map_err(|e| {
            DsmError::internal(
                format!("canonical apply lookup failed: {e}"),
                None::<std::convert::Infallible>,
            )
        })? {
            CanonicalApplyLookup::Duplicate(record) => {
                log::info!(
                    "[apply_full_state] duplicate of already-applied op (tx={}); returning stored record, no re-execution",
                    String::from_utf8_lossy(tx_id.as_bytes()),
                );
                return Ok(ApplyOutcome::AlreadyAppliedSameOperation { record: *record });
            }
            CanonicalApplyLookup::Conflict => {
                return Ok(ApplyOutcome::Conflict {
                    reason: "a different operation identity already consumed this (relationship, \
                             parent) or nonce"
                        .to_string(),
                });
            }
            CanonicalApplyLookup::Fresh => {}
        }

        let init_tip = dsm::core::bilateral_transaction_manager::initial_chain_tip_from_device_ids(
            &local_arr,
            &sender_arr,
        );
        // §16.6 A-side head pin (the space-correct successor check).
        // The recipient cannot recompute the sender's child — chain tips are
        // per-device values — but it CAN pin the sender's asymmetric head and
        // require the signed parent to be exactly it. Before any transition has
        // been applied the pin is the spec-canonical genesis seed, the single
        // tip both sides derive identically. A stale, replayed, reordered, or
        // forked sender lineage fails closed HERE, before execution.
        let pinned_a_head = cdb::pinned_counterparty_a_head(&rel_key)
            .map_err(|e| {
                DsmError::internal(
                    format!("A-side head pin failed: {e}"),
                    None::<std::convert::Infallible>,
                )
            })?
            .unwrap_or(init_tip);
        if parent_tip != pinned_a_head {
            return Ok(ApplyOutcome::Conflict {
                reason: format!(
                    "signed parent ({}..) is not the pinned counterparty A-side head ({}..) — \
                     stale, replayed, or forked sender lineage",
                    crate::util::text_id::encode_base32_crockford(&parent_tip[..4]),
                    crate::util::text_id::encode_base32_crockford(&pinned_a_head[..4]),
                ),
            });
        }

        // ---- fresh: execute under the global lock with the single full-state tx ----
        let deltas = {
            let pc = self.resolve_policy_commit_strict(&token_id)?;
            vec![dsm::types::device_state::BalanceDelta {
                policy_commit: pc,
                direction: dsm::types::device_state::BalanceDirection::Credit,
                amount: amount_val,
            }]
        };
        let tx_id_str = String::from_utf8_lossy(tx_id.as_bytes()).into_owned();
        let in_tx_extra = {
            let nonce = nonce.clone();
            let tx_id_str = tx_id_str.clone();
            move |tx: &rusqlite::Transaction<'_>,
                  outcome: &dsm::types::device_state::AdvanceOutcome|
                  -> Result<(), DsmError> {
                // Nonce consumption INSIDE the full-state transaction.
                let spent = cdb::is_nonce_spent_with_conn(tx, &nonce).map_err(|e| {
                    DsmError::internal(
                        format!("in-tx nonce check failed: {e}"),
                        None::<std::convert::Infallible>,
                    )
                })?;
                if spent {
                    return Err(DsmError::invalid_operation(
                        "full-state apply race: nonce consumed concurrently (fail closed)",
                    ));
                }
                cdb::mark_nonce_spent_with_conn(tx, &nonce, &tx_id_str, &sender_arr, amount_val)
                    .map_err(|e| {
                        DsmError::internal(
                            format!("in-tx nonce consume failed: {e}"),
                            None::<std::convert::Infallible>,
                        )
                    })?;
                // Canonical apply record with the AUTHORITATIVE applied B roots
                // from the state mutation itself.
                let record = CanonicalApplyRecord {
                    relationship_key: rel_key,
                    parent_tip,
                    child_tip,
                    precommit_digest,
                    operation_digest,
                    sender_device: sender_arr,
                    recipient_device: local_arr,
                    nonce_hash,
                    applied_parent_root_b: outcome.parent_r_a,
                    applied_child_root_b: outcome.child_r_a,
                };
                match cdb::insert_canonical_apply_identity_with_conn(tx, &record).map_err(|e| {
                    DsmError::internal(
                        format!("in-tx canonical apply insert failed: {e}"),
                        None::<std::convert::Infallible>,
                    )
                })? {
                    CanonicalApplyInsertOutcome::Inserted => Ok(()),
                    CanonicalApplyInsertOutcome::DuplicateSameOperation(_)
                    | CanonicalApplyInsertOutcome::Conflict => Err(DsmError::invalid_operation(
                        "full-state apply race: canonical apply identity inserted concurrently \
                         (fail closed)",
                    )),
                }
            }
        };

        let exec = self.execute_on_relationship_guarded(
            rel_key,
            sender_arr,
            op,
            &deltas,
            Some(init_tip),
            Some(&in_tx_extra),
        );

        match exec {
            Ok((new_state, advance)) => {
                // Post-commit convergence (best-effort projection; NEVER invalidates
                // the committed canonical transition).
                let local_b32 = crate::util::text_id::encode_base32_crockford(&local_arr);
                self.sync_token_projection_best_effort(
                    &local_b32,
                    &token_id,
                    &new_state,
                    "apply_full_state",
                );
                let record = CanonicalApplyRecord {
                    relationship_key: rel_key,
                    parent_tip,
                    child_tip,
                    precommit_digest,
                    operation_digest,
                    sender_device: sender_arr,
                    recipient_device: local_arr,
                    nonce_hash,
                    applied_parent_root_b: advance.parent_r_a,
                    applied_child_root_b: advance.child_r_a,
                };
                log::info!(
                    "[apply_full_state] ✅ applied transfer tx={} amount={} from={} (single full-state tx)",
                    tx_id_str,
                    amount_val,
                    sender_device_id,
                );
                Ok(ApplyOutcome::Applied {
                    record,
                    advance: Box::new(advance),
                })
            }
            Err(e) => {
                // Losing racer / stale request classification. The DB is the
                // authority: re-lookup the exact identity first.
                match cdb::get_canonical_apply_identity_by_id(&canonical_apply_id) {
                    Ok(Some(record)) => Ok(ApplyOutcome::AlreadyAppliedSameOperation { record }),
                    _ => {
                        let msg = e.to_string();
                        if msg.contains("apply parent validation failed")
                            || msg.contains("apply child validation failed")
                            || msg.contains("full-state apply race")
                        {
                            Ok(ApplyOutcome::Conflict { reason: msg })
                        } else {
                            Err(e)
                        }
                    }
                }
            }
        }
    }

    /// TEST-ONLY honest-sender probe: the canonical (embedded_parent,
    /// computed_child) THIS device would derive for an incoming transfer —
    /// pure prepare, no persistence, no head mutation. Fixtures use it to
    /// present the signed pair an honest sender's canonical advance carries.
    /// §16.6 TEST HELPER — the A-space pair a REMOTE sender would sign.
    ///
    /// The recipient's pin is the spec-canonical genesis seed for the first
    /// transition and the previously applied signed child thereafter. The CHILD
    /// is deliberately a value this device can never compute: a real sender's
    /// chain tip hashes ITS own counterparty devid, its own hash-chained
    /// entropy, and its own balance witness. Deriving the "signed" child from
    /// the recipient's own `prepare` (as the retired probe did) makes every
    /// cross-lineage bug invisible — that is exactly how the unsatisfiable
    /// child-equality check reached production.
    #[cfg(test)]
    pub(crate) fn remote_signed_pair(
        &self,
        sender_device_id: &str,
        parent: Option<[u8; 32]>,
        remote_step: u8,
    ) -> Result<([u8; 32], [u8; 32]), DsmError> {
        let local_device_id_bytes = crate::sdk::app_state::AppState::get_device_id()
            .ok_or_else(|| DsmError::state_machine("missing local device_id (AppState)"))?;
        let mut local_arr = [0u8; 32];
        local_arr.copy_from_slice(&local_device_id_bytes);
        let sender_id_bytes = crate::util::text_id::decode_base32_crockford(sender_device_id)
            .ok_or_else(|| DsmError::invalid_operation("sender_device_id not valid base32"))?;
        let mut sender_arr = [0u8; 32];
        sender_arr.copy_from_slice(&sender_id_bytes);
        let signed_parent = parent.unwrap_or_else(|| {
            dsm::core::bilateral_transaction_manager::initial_chain_tip_from_device_ids(
                &local_arr,
                &sender_arr,
            )
        });
        // Opaque remote-lineage child; unreachable by any local computation.
        let mut signed_child = [0u8; 32];
        signed_child[0] = 0xE0;
        signed_child[1] = remote_step;
        signed_child[2..].copy_from_slice(&signed_parent[2..]);
        signed_child[31] ^= 0x5A;
        Ok((signed_parent, signed_child))
    }
}

/* ---------------------------------- Tests ----------------------------------- */

#[cfg(test)]
mod tests {
    use super::*;
    use dsm::types::operations::Operation as DsmOperation;
    use serial_test::serial;

    /// §16.6 full-state apply regression harness: fresh DB + genesis'd CoreSDK,
    /// with AppState's device id matching the SDK device (transfers addressed
    /// to us).
    fn full_state_apply_harness() -> CoreSDK {
        unsafe { std::env::set_var("DSM_SDK_TEST_MODE", "1") };
        crate::storage::client_db::reset_database_for_tests();
        crate::storage::client_db::init_database().expect("init db");
        let sdk = test_sdk();
        sdk.initialize_with_genesis_state().expect("genesis");
        let devid = sdk.device_info.device_id;
        crate::sdk::app_state::AppState::set_identity_info(
            devid.to_vec(),
            vec![0x02; 32],
            vec![0x03; 32],
            vec![0x04; 32],
        );
        sdk
    }

    fn incoming_transfer_op(to: &[u8; 32], amount: u64, nonce: Vec<u8>) -> DsmOperation {
        DsmOperation::Transfer {
            policy_commit: crate::policy::builtin_policy_commit("ERA").unwrap(),
            to_device_id: to.to_vec(),
            amount: dsm::types::token_types::Balance::from_state(amount, [0u8; 32]),
            token_id: b"ERA".to_vec(),
            mode: dsm::types::operations::TransactionMode::Bilateral,
            nonce,
            verification: dsm::types::operations::VerificationType::Standard,
            pre_commit: None,
            recipient: to.to_vec(),
            to: b"local".to_vec(),
            message: "apply-test".to_string(),
            signature: vec![0; 64],
            authority_policy: None,
        }
    }

    fn sender_ids() -> ([u8; 32], String) {
        let sender = [0x5Au8; 32];
        let b32 = crate::util::text_id::encode_base32_crockford(&sender);
        (sender, b32)
    }

    fn device_root(sdk: &CoreSDK) -> [u8; 32] {
        sdk.state_machine
            .lock()
            .device_head()
            .map(|ds| ds.root())
            .unwrap_or([0u8; 32])
    }

    /// Fresh apply commits everything in ONE transaction: balance/state advance,
    /// nonce consumption, and the CanonicalApplyRecord all exist afterwards; a
    /// duplicate returns the ORIGINAL record with NO re-execution and NO second
    /// credit (device root unchanged).
    #[test]
    #[serial]
    fn full_state_apply_fresh_then_duplicate_no_reexecution() {
        let sdk = full_state_apply_harness();
        let local: [u8; 32] = sdk.device_info.device_id;
        let (sender, sender_b32) = sender_ids();
        let nonce = vec![0x77u8; 32];
        let op = incoming_transfer_op(&local, 50, nonce.clone());
        let op_bytes = b"canonical-op-bytes-1".to_vec();
        let (parent, child) = sdk
            .remote_signed_pair(&sender_b32, None, 1)
            .expect("remote signed pair");
        let tx_id = crate::types::identifiers::TransactionId::new("tx-apply-1");

        let out = sdk
            .apply_incoming_transfer_full_state(
                op.clone(),
                &tx_id,
                &sender_b32,
                &op_bytes,
                parent,
                child,
            )
            .expect("fresh apply");
        let record = match out {
            crate::sdk::apply_outcome::ApplyOutcome::Applied { record, .. } => record,
            other => panic!("expected Applied, got {other:?}"),
        };
        // Single-tx postconditions: nonce spent + verified record present.
        assert!(crate::storage::client_db::is_nonce_spent(&nonce).unwrap());
        let rel = dsm::core::bilateral_transaction_manager::compute_smt_key(&local, &sender);
        let stored = crate::storage::client_db::get_canonical_apply_identity(&rel, &parent)
            .unwrap()
            .expect("record persisted");
        assert_eq!(stored, record);
        // Identity binds the SIGNED canonical pair + the precommit over the
        // signed parent (§16.6 authority sourcing).
        let precommit =
            dsm::core::bilateral_transaction_manager::compute_precommit(&parent, &op_bytes, &nonce);
        assert_eq!(record.parent_tip, parent);
        assert_eq!(record.child_tip, child);
        assert_eq!(record.precommit_digest, precommit);

        // DUPLICATE: exact replay → loaded original record, no re-execution.
        let root_before = device_root(&sdk);
        let dup = sdk
            .apply_incoming_transfer_full_state(op, &tx_id, &sender_b32, &op_bytes, parent, child)
            .expect("duplicate apply");
        match dup {
            crate::sdk::apply_outcome::ApplyOutcome::AlreadyAppliedSameOperation { record: r2 } => {
                assert_eq!(r2, record, "must return the ORIGINAL persisted record");
            }
            other => panic!("expected AlreadyAppliedSameOperation, got {other:?}"),
        }
        assert_eq!(
            device_root(&sdk),
            root_before,
            "duplicate must not re-execute (no second credit)"
        );
    }

    /// A DIFFERENT operation reusing a spent nonce (or consumed parent) is a
    /// Conflict with no mutation; and a stale parent (canonical tip != request
    /// parent) is a Conflict with NO state-machine execution.
    #[test]
    #[serial]
    fn full_state_apply_conflict_and_stale_parent_fail_closed() {
        let sdk = full_state_apply_harness();
        let local: [u8; 32] = sdk.device_info.device_id;
        let (_sender, sender_b32) = sender_ids();
        let nonce = vec![0x88u8; 32];
        let op = incoming_transfer_op(&local, 10, nonce.clone());
        let op_bytes = b"canonical-op-bytes-2".to_vec();
        let (parent, child) = sdk
            .remote_signed_pair(&sender_b32, None, 1)
            .expect("remote signed pair");
        let tx_id = crate::types::identifiers::TransactionId::new("tx-apply-2");
        sdk.apply_incoming_transfer_full_state(op, &tx_id, &sender_b32, &op_bytes, parent, child)
            .expect("fresh apply");

        // Different op (different canonical bytes ⇒ different identity) reusing
        // the SAME consumed parent → Conflict, nothing mutated.
        let root_before = device_root(&sdk);
        let op2 = incoming_transfer_op(&local, 11, vec![0x99u8; 32]);
        let out = sdk
            .apply_incoming_transfer_full_state(
                op2,
                &tx_id,
                &sender_b32,
                b"different-op-bytes",
                parent,
                child,
            )
            .expect("conflict classification");
        assert!(
            matches!(
                out,
                crate::sdk::apply_outcome::ApplyOutcome::Conflict { .. }
            ),
            "different identity on a consumed parent must be Conflict"
        );
        assert_eq!(device_root(&sdk), root_before, "conflict must not mutate");

        // Stale parent: the pinned A-side head has moved past this parent.
        let stale_parent = [0x31u8; 32];
        let op3 = incoming_transfer_op(&local, 12, vec![0xAAu8; 32]);
        let out3 = sdk
            .apply_incoming_transfer_full_state(
                op3,
                &tx_id,
                &sender_b32,
                b"op-bytes-stale",
                stale_parent,
                [0x32u8; 32],
            )
            .expect("stale classification");
        match out3 {
            crate::sdk::apply_outcome::ApplyOutcome::Conflict { reason } => {
                assert!(
                    reason.contains("pinned counterparty A-side head"),
                    "unexpected conflict reason: {reason}"
                );
            }
            other => panic!("expected Conflict for stale parent, got {other:?}"),
        }
        assert_eq!(device_root(&sdk), root_before, "stale must not execute");
        assert!(!crate::storage::client_db::is_nonce_spent(&[0xAAu8; 32]).unwrap());
    }

    /// AWYPCNK8 REGRESSION (§16.6 authority sourcing): a transfer whose SIGNED
    /// receipt carries the correct canonical pair must apply cleanly even when
    /// every symmetric-space value around it (contacts.chain_tip projection,
    /// wire metadata) is DIVERGENT — the two lineages are parallel formula
    /// spaces and the apply must consult only the signed pair. This is exactly
    /// the false-conflict that stranded the live AWYPCNK8 transfer.
    #[test]
    #[serial]
    fn awypcnk8_regression_divergent_projection_never_blocks_signed_receipt() {
        let sdk = full_state_apply_harness();
        let local: [u8; 32] = sdk.device_info.device_id;
        let (sender, sender_b32) = sender_ids();
        let nonce = vec![0xD1u8; 32];
        let op = incoming_transfer_op(&local, 15, nonce.clone());
        let op_bytes = b"awypcnk8-op-bytes".to_vec();
        // Honest REMOTE sender: parent is the pinned A-side head (genesis seed
        // on a fresh relationship); the child is the sender's own lineage value,
        // which this device cannot and must not recompute.
        let (signed_parent, signed_child) = sdk
            .remote_signed_pair(&sender_b32, None, 1)
            .expect("remote signed pair");

        // The projection space holds a COMPLETELY different lineage (as on the
        // live rig: 00941A79.. symmetric vs 06F28A35.. canonical).
        let divergent_projection = [0xABu8; 32];
        {
            let binding = crate::storage::client_db::get_connection().unwrap();
            let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
            conn.execute(
                "INSERT INTO contacts (contact_id, device_id, alias, genesis_hash, metadata, added_at, verified, status, needs_online_reconcile, last_seen_online_counter, last_seen_ble_counter, chain_tip)
                 VALUES ('awy', ?1, 'awy', X'00', X'00', 0, 1, 'active', 0, 0, 0, ?2)",
                rusqlite::params![sender.as_slice(), divergent_projection.as_slice()],
            )
            .unwrap();
        }

        let out = sdk
            .apply_incoming_transfer_full_state(
                op,
                &crate::types::identifiers::TransactionId::new("tx-awy"),
                &sender_b32,
                &op_bytes,
                signed_parent,
                signed_child,
            )
            .expect("apply must not consult the projection");
        assert!(
            matches!(out, crate::sdk::apply_outcome::ApplyOutcome::Applied { .. }),
            "a valid signed pair must apply regardless of projection divergence"
        );
    }

    /// §16.6 A-side head pin: a signed parent that is NOT the pinned
    /// counterparty head (stale / replayed / forked sender lineage) fails
    /// CLOSED with no side effects — prepare is pure.
    ///
    /// This replaces a retired "recomputed successor == signed child" check.
    /// That check was unsatisfiable between honest devices: a relationship chain
    /// tip hashes the holder's own counterparty devid, its own hash-chained
    /// entropy, and its own balance witness, so the recipient can never
    /// reproduce the sender's child. The pin enforces the same property —
    /// only the sender's genuine next transition is accepted — in the one
    /// formula space both parties can agree on.
    #[test]
    #[serial]
    fn apply_fails_closed_when_signed_parent_is_not_the_pinned_a_head() {
        let sdk = full_state_apply_harness();
        let local: [u8; 32] = sdk.device_info.device_id;
        let (_sender, sender_b32) = sender_ids();
        let nonce = vec![0xD2u8; 32];
        let op = incoming_transfer_op(&local, 20, nonce.clone());
        let (_pinned, signed_child) = sdk
            .remote_signed_pair(&sender_b32, None, 1)
            .expect("remote signed pair");

        let root_before = device_root(&sdk);
        let out = sdk
            .apply_incoming_transfer_full_state(
                op,
                &crate::types::identifiers::TransactionId::new("tx-badparent"),
                &sender_b32,
                b"badparent-op-bytes",
                [0x5Au8; 32], // NOT the pinned A-side head
                signed_child,
            )
            .expect("classification, not error");
        match out {
            crate::sdk::apply_outcome::ApplyOutcome::Conflict { reason } => {
                assert!(
                    reason.contains("pinned counterparty A-side head"),
                    "unexpected conflict reason: {reason}"
                );
            }
            other => panic!("expected Conflict for unpinned parent, got {other:?}"),
        }
        assert_eq!(device_root(&sdk), root_before, "no mutation on refusal");
        assert!(
            !crate::storage::client_db::is_nonce_spent(&nonce).unwrap(),
            "nonce must remain unspent"
        );
    }

    /// LIVE REGRESSION (the bug this replaces): the SECOND transfer in a
    /// relationship must apply.
    ///
    /// The retired checks compared the sender's signed tips against the
    /// recipient's own lineage. Those coincide only at the spec-canonical
    /// genesis seed, so transfer #1 passed the parent check while every later
    /// transfer failed "stale request". Here transfer #2 chains onto the signed
    /// child of transfer #1 — a value drawn from the REMOTE lineage — and must
    /// be accepted.
    #[test]
    #[serial]
    fn second_transfer_applies_when_signed_parent_continues_the_remote_lineage() {
        let sdk = full_state_apply_harness();
        let local: [u8; 32] = sdk.device_info.device_id;
        let (_sender, sender_b32) = sender_ids();

        let nonce1 = vec![0xE1u8; 32];
        let op1 = incoming_transfer_op(&local, 11, nonce1.clone());
        let (parent1, child1) = sdk
            .remote_signed_pair(&sender_b32, None, 1)
            .expect("remote pair 1");
        let out1 = sdk
            .apply_incoming_transfer_full_state(
                op1,
                &crate::types::identifiers::TransactionId::new("tx-seq-1"),
                &sender_b32,
                b"seq-op-bytes-1",
                parent1,
                child1,
            )
            .expect("apply 1");
        assert!(
            matches!(
                out1,
                crate::sdk::apply_outcome::ApplyOutcome::Applied { .. }
            ),
            "first transfer must apply, got {out1:?}"
        );

        // Transfer #2 starts exactly where the sender's signed lineage left off.
        let nonce2 = vec![0xE2u8; 32];
        let op2 = incoming_transfer_op(&local, 13, nonce2.clone());
        let (parent2, child2) = sdk
            .remote_signed_pair(&sender_b32, Some(child1), 2)
            .expect("remote pair 2");
        assert_eq!(parent2, child1, "fixture must chain onto the signed child");
        let out2 = sdk
            .apply_incoming_transfer_full_state(
                op2,
                &crate::types::identifiers::TransactionId::new("tx-seq-2"),
                &sender_b32,
                b"seq-op-bytes-2",
                parent2,
                child2,
            )
            .expect("apply 2");
        assert!(
            matches!(out2, crate::sdk::apply_outcome::ApplyOutcome::Applied { .. }),
            "SECOND transfer must apply — the retired cross-lineage check broke exactly here; got {out2:?}"
        );
    }

    /// The legacy crash state (nonce spent WITHOUT a canonical apply record —
    /// impossible under the new single tx, but seedable) must ROLL BACK the
    /// whole in-tx apply: no balance credit, no record, device root unchanged.
    /// This directly proves the all-or-nothing boundary.
    #[test]
    #[serial]
    fn full_state_apply_rolls_back_everything_when_in_tx_step_fails() {
        let sdk = full_state_apply_harness();
        let local: [u8; 32] = sdk.device_info.device_id;
        let (sender, sender_b32) = sender_ids();
        let nonce = vec![0xB7u8; 32];
        // Seed ONLY the spent nonce (no canonical record): pre-lookup sees Fresh,
        // execution proceeds, and the IN-TX nonce check must fail the whole tx.
        crate::storage::client_db::mark_nonce_spent(&nonce, "tx-seeded", &sender, 5).unwrap();

        let root_before = device_root(&sdk);
        let rel = dsm::core::bilateral_transaction_manager::compute_smt_key(&local, &sender);
        let op = incoming_transfer_op(&local, 25, nonce.clone());
        let (parent, child) = sdk
            .remote_signed_pair(&sender_b32, None, 1)
            .expect("remote signed pair");
        let tx_id = crate::types::identifiers::TransactionId::new("tx-apply-3");
        let out = sdk
            .apply_incoming_transfer_full_state(
                op,
                &tx_id,
                &sender_b32,
                b"op-bytes-3",
                parent,
                child,
            )
            .expect("race classification");
        assert!(
            matches!(
                out,
                crate::sdk::apply_outcome::ApplyOutcome::Conflict { .. }
            ),
            "in-tx nonce race must classify as Conflict"
        );
        // ALL-OR-NOTHING: no state advance, no record, no credit.
        assert_eq!(
            device_root(&sdk),
            root_before,
            "state advance must roll back"
        );
        assert!(
            crate::storage::client_db::get_canonical_apply_identity(&rel, &parent)
                .unwrap()
                .is_none()
        );
    }

    /// MANDATORY regression A (crash after apply, before convergence): the
    /// redelivery yields AlreadyAppliedSameOperation with the stored record and
    /// the fold converges — exactly ONE marker, ONE outbox entry, no second EK.
    #[test]
    #[serial]
    fn crash_after_apply_redelivery_converges_via_stored_record() {
        let sdk = full_state_apply_harness();
        let local: [u8; 32] = sdk.device_info.device_id;
        let (sender, sender_b32) = sender_ids();
        let nonce = vec![0xC7u8; 32];
        let op = incoming_transfer_op(&local, 30, nonce.clone());
        let op_bytes = b"canonical-op-bytes-A".to_vec();
        // SYMMETRIC projection pair (contacts CAS space).
        let sym_parent =
            dsm::core::bilateral_transaction_manager::initial_chain_tip_from_device_ids(
                &local, &sender,
            );
        let sym_sigma = dsm::core::bilateral_transaction_manager::compute_precommit(
            &sym_parent,
            &op_bytes,
            &nonce,
        );
        let sym_target = dsm::core::bilateral_transaction_manager::compute_successor_tip(
            &sym_parent,
            &op_bytes,
            &nonce,
            &sym_sigma,
        );
        // ASYMMETRIC authority pair (what the signed receipt carries).
        let (parent, child) = sdk
            .remote_signed_pair(&sender_b32, None, 1)
            .expect("remote signed pair");
        let rel = dsm::core::bilateral_transaction_manager::compute_smt_key(&local, &sender);
        let precommit =
            dsm::core::bilateral_transaction_manager::compute_precommit(&parent, &op_bytes, &nonce);
        let wrap = [0x42u8; 32];

        // PHASE 1 (prepare BEFORE apply, as the live path does).
        let gen_calls = std::sync::atomic::AtomicUsize::new(0);
        let prepared = crate::handlers::recipient_receipt::prepare_bside_acceptance_receipt_locked(
            rel,
            parent,
            (sym_parent, sym_target),
            || {
                gen_calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Ok(crate::handlers::recipient_receipt::GeneratedBArtifacts {
                    receipt_bytes: b"RECEIPT-A".to_vec(),
                    commitment: [0x64u8; 32],
                    child_tip: child,
                    counterparty_device_id: sender,
                    receipt_parent_root_a: [0x0Bu8; 32],
                    receipt_child_root_a: [0x0Cu8; 32],
                    precommit_digest: precommit,
                    prepared_receipt_artifact_hash:
                        crate::storage::client_db::acceptance_artifact_hash(b"RECEIPT-A"),
                    expected_local_b_head: None,
                    new_local_b_head: vec![0xBBu8; 40],
                    new_local_b_sk_enc: crate::storage::client_db::cert_chain::encrypt_chain_sk(
                        &[0xCCu8; 64],
                        &wrap,
                    )
                    .unwrap(),
                    expected_counterparty_a_head: None,
                    new_counterparty_a_head: vec![0xAAu8; 40],
                })
            },
        )
        .unwrap();
        assert_eq!(prepared, b"RECEIPT-A");

        // APPLY commits; then CRASH before convergence (we simply don't converge).
        let out = sdk
            .apply_incoming_transfer_full_state(
                op.clone(),
                &crate::types::identifiers::TransactionId::new("tx-A"),
                &sender_b32,
                &op_bytes,
                parent,
                child,
            )
            .expect("fresh apply");
        assert!(matches!(
            out,
            crate::sdk::apply_outcome::ApplyOutcome::Applied { .. }
        ));

        // REDELIVERY after "restart": prepare returns the SAME bytes without
        // re-signing; apply returns the stored record; convergence completes.
        let again = crate::handlers::recipient_receipt::prepare_bside_acceptance_receipt_locked(
            rel,
            parent,
            (sym_parent, sym_target),
            || panic!("second EK derivation is forbidden on redelivery"),
        )
        .unwrap();
        assert_eq!(again, b"RECEIPT-A");
        let redelivered = sdk
            .apply_incoming_transfer_full_state(
                op,
                &crate::types::identifiers::TransactionId::new("tx-A"),
                &sender_b32,
                &op_bytes,
                parent,
                child,
            )
            .expect("redelivery");
        let record = match redelivered {
            crate::sdk::apply_outcome::ApplyOutcome::AlreadyAppliedSameOperation { record } => {
                record
            }
            other => panic!("expected AlreadyAppliedSameOperation, got {other:?}"),
        };

        // Seed the contact row for the projection sync, then converge.
        {
            let binding = crate::storage::client_db::get_connection().unwrap();
            let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
            conn.execute(
                "INSERT INTO contacts (contact_id, device_id, alias, genesis_hash, metadata, added_at, verified, status, needs_online_reconcile, last_seen_online_counter, last_seen_ble_counter, chain_tip)
                 VALUES ('t', ?1, 't', X'00', X'00', 0, 1, 'active', 0, 0, 0, ?2)",
                rusqlite::params![sender.as_slice(), sym_parent.as_slice()],
            )
            .unwrap();
        }
        let journal = crate::storage::client_db::get_acceptance_journal(&rel, &parent)
            .unwrap()
            .unwrap();
        let bytes =
            crate::handlers::recipient_receipt::converge_accepted_locked(&journal, &record, &wrap)
                .unwrap();
        assert_eq!(bytes, b"RECEIPT-A");
        assert_eq!(
            gen_calls.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "ONE EK derivation total"
        );
        // Exactly one marker + one outbox entry; journal Complete.
        assert!(
            crate::storage::client_db::get_accepted_transition(&rel, &parent)
                .unwrap()
                .is_some()
        );
        assert!(crate::storage::client_db::outbound_reply_exists(&[0x64u8; 32]).unwrap());
        assert_eq!(
            crate::storage::client_db::get_acceptance_journal(&rel, &parent)
                .unwrap()
                .unwrap()
                .status,
            crate::storage::client_db::STATUS_COMPLETE
        );
    }

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

    /// Stage 4 Slice 3 (signal a): the offline-bearer "no appliance" error must speak v2 — name the
    /// anchor device the user connects — and never the deleted v1 "Path-B" concept. This message
    /// rides into the failed-transfer event the frontend friendly-maps.
    #[test]
    fn offline_bearer_no_appliance_message_is_v2_worded() {
        assert!(
            OFFLINE_BEARER_NO_APPLIANCE_MSG.contains("anchor device"),
            "the send-failure message must tell the user to connect the anchor device"
        );
        assert!(
            !OFFLINE_BEARER_NO_APPLIANCE_MSG.contains("Path-B"),
            "the message must not reference the deleted v1 Path-B concept"
        );
    }

    /// Stage 4 Slice 3 (signal c): the read-only `anchor.status` accessor attaches the appliance
    /// and reports a connected snapshot (identity + counters) WITHOUT mutating the device head —
    /// the data source behind the diagnostics panel. Contrast `stage_offline_bearer_transition`,
    /// which reconciles the anchor-state leaf.
    #[test]
    #[serial]
    fn anchor_status_reports_connected_snapshot_without_mutation() {
        let sdk = test_sdk();
        let had_head_before = sdk.state_machine.lock().device_head().is_some();

        let snap = sdk.anchor_appliance_status();
        assert!(
            snap.connected,
            "the in-process mock appliance must report connected"
        );
        assert_eq!(
            snap.enrolled_counter, 1_000_000,
            "enrolled counter comes from the appliance pin"
        );
        assert_ne!(
            snap.anchor_id, [0u8; 32],
            "a connected anchor exposes a non-zero identity"
        );
        assert!(
            !snap.pk_chip.is_empty(),
            "a connected anchor exposes the resident chip pubkey"
        );
        assert!(
            snap.status.contains("connected"),
            "the human-readable status names the connected state"
        );

        let had_head_after = sdk.state_machine.lock().device_head().is_some();
        assert_eq!(
            had_head_before, had_head_after,
            "anchor.status is read-only and must not create or mutate the device head"
        );
    }

    /// v2 producer phases: STAGE determines the transition + successor leaf with NO appliance
    /// mutation; RELEASE (PREPARE→COMMIT→EMIT→FINALIZE) is born with the caller-supplied real
    /// device roots in its signed transcript and the Π proofs attached — and the frontier lineage
    /// advances exactly once per release.
    #[test]
    #[serial]
    fn stage_then_release_binds_roots_challenge_and_advances_lineage() {
        use prost::Message as _;
        let sdk = test_sdk();
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
        let staged1 = sdk
            .stage_offline_bearer_transition(
                [1u8; 32],
                recipient,
                [2u8; 32],
                [9u8; 32],
                [3u8; 32],
                0,
                vec![0xAB],
                r_r_1,
            )
            .expect("stage 1");
        assert_eq!(staged1.transition.anchor_counter, 0);
        assert_eq!(staged1.transition.next_anchor_counter, 1);
        assert_eq!(staged1.transition.prev_root, staged1.appliance_prev_root);
        assert_eq!(staged1.transition.next_root, staged1.appliance_next_root);
        // Staging mutated nothing: staging again yields the identical transition.
        let staged1b = sdk
            .stage_offline_bearer_transition(
                [1u8; 32],
                recipient,
                [2u8; 32],
                [9u8; 32],
                [3u8; 32],
                0,
                vec![0xAB],
                r_r_1,
            )
            .expect("re-stage");
        assert_eq!(staged1b.appliance_prev_root, staged1.appliance_prev_root);
        assert_eq!(staged1b.appliance_next_root, staged1.appliance_next_root);

        let r_i = [0x51u8; 32];
        let r_next = [0x52u8; 32];
        let art1 = sdk
            .release_offline_bearer(&staged1, r_r_1, r_i, r_next, vec![0xAA; 40], vec![0xCC; 40])
            .expect("release 1");
        let rel = anchor_core::proto::pb::OfflineRelease::decode(&art1.offline_release[..])
            .expect("decode")
            .to_release()
            .expect("to_release");
        assert_eq!(
            rel.cert.receiver_challenge, r_r_1,
            "r_R must bind into the cert"
        );
        assert_eq!(
            rel.cert.sender_device_root_before, r_i,
            "the REAL pre-advance device root is in the signed transcript (no placeholder)"
        );
        assert_eq!(
            rel.cert.sender_device_root_after, r_next,
            "the REAL post-advance device root is in the signed transcript (no re-stamp)"
        );
        assert_eq!(rel.transition.recipient_device_id, recipient);
        assert_eq!(rel.cert.anchor_counter, 0);
        assert_eq!(rel.cert.next_anchor_counter, 1);
        assert_eq!(
            rel.anchor_smt_proof_before,
            vec![0xAA; 40],
            "Pi_i attached to the package"
        );
        assert_eq!(
            rel.anchor_smt_proof_after,
            vec![0xCC; 40],
            "Pi_i+1 attached to the package"
        );

        // ---- Transfer 2: frontier lineage advances (prev == prior next), counter + leaf advance ----
        let r_r_2 = [0x66u8; 32];
        let staged2 = sdk
            .stage_offline_bearer_transition(
                [1u8; 32],
                recipient,
                [2u8; 32],
                [9u8; 32],
                [3u8; 32],
                0,
                vec![0xCD],
                r_r_2,
            )
            .expect("stage 2");
        assert_eq!(
            staged2.appliance_prev_root, art1.appliance_next_root,
            "frontier lineage must advance (transfer 2 consumes transfer 1's successor)"
        );
        assert_ne!(
            staged2.anchor_leaf.new_value, staged1.anchor_leaf.new_value,
            "the successor anchor-state leaf advances each transfer"
        );
        assert_eq!(staged2.pin.bundle, staged1.pin.bundle);
        let art2 = sdk
            .release_offline_bearer(
                &staged2,
                r_r_2,
                r_next,
                [0x53u8; 32],
                Vec::new(),
                Vec::new(),
            )
            .expect("release 2");
        let rel2 = anchor_core::proto::pb::OfflineRelease::decode(&art2.offline_release[..])
            .unwrap()
            .to_release()
            .unwrap();
        assert_eq!(rel2.cert.anchor_counter, 1, "counter advanced to u_i=1");
        assert_eq!(rel2.cert.receiver_challenge, r_r_2);
    }

    /// Regression lock for receiver `PrevStateUncommitted`: the sender's device-head anchor-state leaf
    /// is reconciled to the LIVE chip on EVERY stage call, not once per appliance attach. When a prior
    /// transfer advances the chip (counter + frontier) without the successor leaf being committed into
    /// the device head, the next stage MUST re-reconcile the (now stale) head leaf to the live chip —
    /// otherwise the confirm-build Π_i proves a stale value while the cert claims the new frontier/
    /// counter, and the receiver rejects. The decisive assertion is that the stored device-head leaf
    /// equals EXACTLY the value the certificate claims for this transfer.
    #[test]
    #[serial]
    fn stage_reconciles_device_head_anchor_leaf_to_live_chip_every_call() {
        use anchor_core::root_advance::anchor_state_leaf;
        use dsm::core::bilateral_transaction_manager::anchor_state_leaf_key;
        use dsm::types::device_state::DeviceState;

        let sdk = test_sdk();
        {
            let ds = DeviceState::new([9u8; 32], sdk.device_info.device_id, vec![0u8; 64], 256);
            sdk.state_machine.lock().set_device_head(ds);
        }
        let recipient = [4u8; 32];

        // Transfer 1: stage (reconciles the head leaf to the live u=0 state) + release (PREPARE→COMMIT→
        // EMIT→FINALIZE advances the mock chip to u=1 / a new frontier). The unit test does NOT commit
        // the successor leaf into the device head — the real canonical commit would — so the head leaf
        // is left at the u=0 value: exactly the stale condition the bug produced.
        let staged1 = sdk
            .stage_offline_bearer_transition(
                [1u8; 32],
                recipient,
                [2u8; 32],
                [9u8; 32],
                [3u8; 32],
                0,
                vec![0xAB],
                [0x55u8; 32],
            )
            .expect("stage 1");
        let bundle = staged1.pin.bundle;
        let key = anchor_state_leaf_key(&bundle);
        let leaf_u0 = anchor_state_leaf(
            &bundle,
            &staged1.appliance_prev_root,
            staged1.transition.anchor_counter,
        );
        {
            let sm = sdk.state_machine.lock();
            let head = sm.device_head().expect("head");
            assert_eq!(
                head.extra_leaves_snapshot().get(&key),
                Some(&leaf_u0),
                "stage 1 reconciled the head leaf to the live (u=0) chip state",
            );
        }
        sdk.release_offline_bearer(
            &staged1,
            [0x55u8; 32],
            [0x51u8; 32],
            [0x52u8; 32],
            vec![0xAA; 40],
            vec![0xCC; 40],
        )
        .expect("release 1 (advances the mock chip)");

        // The head leaf is now STALE (still u=0) relative to the advanced chip (u=1). Stage 2 must
        // RE-reconcile it to the live chip — WITHOUT the per-call fix this would remain leaf_u0 and Π_i
        // would prove the wrong value.
        let staged2 = sdk
            .stage_offline_bearer_transition(
                [1u8; 32],
                recipient,
                [2u8; 32],
                [9u8; 32],
                [3u8; 32],
                0,
                vec![0xCD],
                [0x66u8; 32],
            )
            .expect("stage 2");
        assert_eq!(
            staged2.transition.anchor_counter, 1,
            "the chip advanced to u=1 after transfer 1",
        );
        let expected = anchor_state_leaf(
            &bundle,
            &staged2.appliance_prev_root,
            staged2.transition.anchor_counter,
        );
        assert_ne!(
            expected, leaf_u0,
            "the reconciled value actually advanced past the stale u=0 leaf"
        );
        let sm = sdk.state_machine.lock();
        let head = sm.device_head().expect("head");
        assert_eq!(
            head.extra_leaves_snapshot().get(&key),
            Some(&expected),
            "stage 2 RE-reconciled the stale head leaf to the live chip (u=1) — the device-head leaf now \
             equals exactly the value the cert claims, so Π_i verifies on the receiver",
        );
    }

    /// Determinism: staging twice with an unchanged live chip leaves the device-head root identical
    /// (the no-op guard skips a same-value rewrite), so the confirm-build sim and the canonical-commit
    /// re-sim see byte-identical pre-roots.
    #[test]
    #[serial]
    fn restage_with_unchanged_chip_leaves_device_root_identical() {
        use dsm::types::device_state::DeviceState;

        let sdk = test_sdk();
        {
            let ds = DeviceState::new([9u8; 32], sdk.device_info.device_id, vec![0u8; 64], 256);
            sdk.state_machine.lock().set_device_head(ds);
        }
        let recipient = [4u8; 32];
        let stage = || {
            sdk.stage_offline_bearer_transition(
                [1u8; 32],
                recipient,
                [2u8; 32],
                [9u8; 32],
                [3u8; 32],
                0,
                vec![0xAB],
                [0x55u8; 32],
            )
        };
        let s1 = stage().expect("stage 1");
        let root_after_1 = sdk.state_machine.lock().device_head().expect("head").root();
        let s2 = stage().expect("stage 2 (no chip change)");
        let root_after_2 = sdk.state_machine.lock().device_head().expect("head").root();
        assert_eq!(
            root_after_1, root_after_2,
            "an unchanged chip must not drift the device root"
        );
        assert_eq!(s1.appliance_prev_root, s2.appliance_prev_root);
        assert_eq!(s1.anchor_leaf.new_value, s2.anchor_leaf.new_value);
    }

    /// Exactly-once release: re-releasing the SAME staged transition is rejected (its `prev_root`
    /// was consumed — the appliance frontier moved), cancel after a committed release is a safe
    /// no-op, and the next stage starts from the advanced coordinate.
    #[test]
    #[serial]
    fn release_is_exactly_once_and_cancel_after_is_noop() {
        use dsm::types::device_state::DeviceState;

        let sdk = test_sdk();
        {
            let ds = DeviceState::new([9u8; 32], sdk.device_info.device_id, vec![0u8; 64], 256);
            sdk.state_machine.lock().set_device_head(ds);
        }
        let recipient = [4u8; 32];
        let r_r = [0x55u8; 32];

        let staged = sdk
            .stage_offline_bearer_transition(
                [1u8; 32],
                recipient,
                [2u8; 32],
                [9u8; 32],
                [3u8; 32],
                0,
                vec![0xAB],
                r_r,
            )
            .expect("stage");
        sdk.release_offline_bearer(&staged, r_r, [0x51u8; 32], [0x52u8; 32], vec![], vec![])
            .expect("release once");

        // A SECOND release from the SAME staged transition must be rejected — its prev_root was
        // consumed; the counter cannot move twice for one staged transfer.
        assert!(
            sdk.release_offline_bearer(&staged, r_r, [0x51u8; 32], [0x52u8; 32], vec![], vec![])
                .is_err(),
            "double-release from the same staged transition is rejected (exactly once)"
        );

        // Cleanup after a committed release is a no-op: it never re-moves the counter.
        sdk.cancel_offline_bearer_release()
            .expect("cancel after release is a safe no-op");

        // The next stage starts from the advanced coordinate u_i+1 / the advanced frontier.
        let staged2 = sdk
            .stage_offline_bearer_transition(
                [1u8; 32],
                recipient,
                [2u8; 32],
                [9u8; 32],
                [3u8; 32],
                0,
                vec![0xCD],
                [0x66u8; 32],
            )
            .expect("stage 2");
        assert_eq!(
            staged2.transition.anchor_counter, 1,
            "the next transfer starts from the advanced coordinate u_i+1"
        );
        assert_eq!(staged2.appliance_prev_root, staged.appliance_next_root);
    }

    /// §26 host recovery seam. At a re-attach the host cancels ONLY an orphaned uncommitted
    /// `Prepared` (no owning session) and moves no counter doing so; a `Prepared` an in-flight
    /// session still owns is left untouched. `recover()` observes; the host decides.
    #[test]
    #[serial]
    fn reattach_cancels_orphaned_prepared_not_owned_and_moves_no_counter() {
        use crate::anchor::RecoveryAction;
        use dsm::types::device_state::DeviceState;

        let sdk = test_sdk();
        {
            let ds = DeviceState::new([9u8; 32], sdk.device_info.device_id, vec![0u8; 64], 256);
            sdk.state_machine.lock().set_device_head(ds);
        }
        let recipient = [4u8; 32];
        let r_r = [0x55u8; 32];

        // No appliance attached yet -> nothing prepared -> Ready.
        assert_eq!(
            sdk.resolve_prepared_on_reattach(false).expect("reattach"),
            RecoveryAction::Ready
        );

        // Stage, then drive the appliance to PREPARED directly (a crash between PREPARE and COMMIT
        // — the window `release_offline_bearer` normally closes atomically).
        let staged = sdk
            .stage_offline_bearer_transition(
                [1u8; 32],
                recipient,
                [2u8; 32],
                [9u8; 32],
                [3u8; 32],
                0,
                vec![0xAB],
                r_r,
            )
            .expect("stage");
        {
            let mut guard = sdk.anchor_appliance.lock();
            let app = guard.as_mut().expect("appliance attached by stage");
            app.prepare(
                &staged.transition.as_transition(),
                &r_r,
                &[0x51u8; 32],
                &[0x52u8; 32],
            )
            .expect("prepare");
        }

        // An in-flight session OWNS this prepared record -> the host must NOT cancel it.
        assert_eq!(
            sdk.resolve_prepared_on_reattach(true).expect("owned"),
            RecoveryAction::LeavePreparedForOwner
        );

        // Orphaned (the owning session was lost on restart) -> cancel it back to Ready.
        assert_eq!(
            sdk.resolve_prepared_on_reattach(false).expect("orphan"),
            RecoveryAction::CancelOrphanedPrepared
        );

        // The appliance is Ready again and NO counter moved: a fresh stage still starts at u_i=0,
        // so a lost/abandoned prepare does not strand future sends (and burned no counter).
        let staged2 = sdk
            .stage_offline_bearer_transition(
                [1u8; 32],
                recipient,
                [2u8; 32],
                [9u8; 32],
                [3u8; 32],
                0,
                vec![0xCD],
                [0x66u8; 32],
            )
            .expect("stage after cancel");
        assert_eq!(
            staged2.transition.anchor_counter, 0,
            "cancel moved no counter — u_i unchanged, future sends not stranded"
        );
    }

    /// End-to-end producer → receiver-predicate → adopt → replay-reject over TWO real bearer
    /// transfers, v2 shape. The SENDER stages, commits the staged successor leaf into a REAL
    /// per-device SMT advance (real roots + real Π inclusion proofs), then releases with those
    /// roots; the RECEIVER runs the full v2 predicate (`accept_offline_release`: σ^chip + σ^host
    /// verified against the pin, Π verified against the device roots, frontier pin) with NO
    /// counter read on the path. Proves: (a) a real release is accepted, (b) the receiver adopts
    /// the successor frontier, (c) replaying transfer 1 after adoption is rejected, (d) transfer 2
    /// chains from the adopted frontier, (e) cert roots that differ from the verified device roots
    /// are rejected.
    #[test]
    #[serial]
    fn producer_release_accepts_adopts_and_rejects_replay_end_to_end() {
        use crate::bluetooth::anchor_accept::{accept_offline_release, OfflineRecover, PinnedAnchor};
        use dsm::core::bilateral_transaction_manager::{
            compute_smt_key, initial_chain_tip_from_device_ids,
        };
        use dsm::types::device_state::{AnchorLeafUpdate, DeviceState};

        let sdk = test_sdk();
        {
            let ds = DeviceState::new([9u8; 32], sdk.device_info.device_id, vec![0u8; 64], 256);
            sdk.state_machine.lock().set_device_head(ds);
        }
        let recipient = [4u8; 32];
        let policy_hash = [3u8; 32];

        let pin_from = |p: &crate::anchor::AnchorPin| PinnedAnchor {
            bundle: p.bundle,
            anchor_id: p.anchor_id,
            enrolled_counter: p.enrolled_counter,
            partition_pk: p.partition_pk.clone(),
            pk_chip: p.pk_chip.clone(),
            uncompromised: true,
        };

        // One real bearer transfer from `head`: stage, advance the REAL per-device SMT with the
        // staged successor leaf (producing real roots + Π), then release with those roots.
        let drive = |head: &DeviceState, cp_tag: u8, r_r: [u8; 32]| {
            let staged = sdk
                .stage_offline_bearer_transition(
                    [1u8; 32],
                    recipient,
                    [2u8; 32],
                    [9u8; 32],
                    policy_hash,
                    0,
                    vec![0xAB],
                    r_r,
                )
                .expect("stage");
            let cp = {
                let mut c = [0u8; 32];
                c[0] = cp_tag;
                c
            };
            let rk = compute_smt_key(&head.devid(), &cp);
            let init = initial_chain_tip_from_device_ids(&head.devid(), &cp);
            let out = head
                .advance(
                    rk,
                    cp,
                    DsmOperation::Noop,
                    vec![cp_tag; 32],
                    None,
                    &[],
                    Some(init),
                    Some(AnchorLeafUpdate {
                        key: staged.anchor_leaf.key,
                        new_value: staged.anchor_leaf.new_value,
                    }),
                    None,
                )
                .expect("bearer advance");
            let proofs = out
                .anchor_proofs
                .clone()
                .expect("bearer advance emits anchor proofs");
            let art = sdk
                .release_offline_bearer(
                    &staged,
                    r_r,
                    out.smt_proofs.pre_root,
                    out.child_r_a,
                    proofs.parent,
                    proofs.child,
                )
                .expect("release");
            (art, out)
        };

        // Transfer 1 runs from the head the stage-time reconcile bootstrapped (it writes the
        // current anchor-state leaf into the device head on first attach).
        let (art1, out1) = {
            // Prime the bootstrap: stage once so the reconciled head exists, then drive from it.
            sdk.stage_offline_bearer_transition(
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
            drive(&head, 0xC0, [0x55u8; 32])
        };
        let pin1 = pin_from(&art1.pin);
        let before1 = out1.smt_proofs.pre_root;
        let after1 = out1.child_r_a;

        // (a) The receiver accepts the real release: three signatures + Π against the REAL device
        // roots + frontier pin (genesis: accepted_frontier=None adopts prev_root TOFU).
        let adopted = accept_offline_release(
            &art1.offline_release,
            Some(&pin1),
            None,
            &recipient,
            &[0x55u8; 32],
            &policy_hash,
            &before1,
            &after1,
        )
        .expect("transfer 1 must be accepted by the v2 predicate");
        assert_eq!(adopted.next_root, art1.appliance_next_root);
        assert_eq!(adopted.next_anchor_counter, 1);

        // (a') Pinning the frontier explicitly also accepts.
        accept_offline_release(
            &art1.offline_release,
            Some(&pin1),
            Some(&art1.appliance_prev_root),
            &recipient,
            &[0x55u8; 32],
            &policy_hash,
            &before1,
            &after1,
        )
        .expect("accept with the pinned frontier");

        // (e) Cert roots that are NOT the verified device roots are rejected (parallel-tree cert).
        let wrong = accept_offline_release(
            &art1.offline_release,
            Some(&pin1),
            Some(&art1.appliance_prev_root),
            &recipient,
            &[0x55u8; 32],
            &policy_hash,
            &[0xEEu8; 32],
            &after1,
        );
        assert!(
            matches!(wrong, Err(OfflineRecover::Predicate(_))),
            "cert/device root mismatch must be rejected, got {wrong:?}"
        );

        // (c) Replay: presenting transfer 1 again AFTER the receiver adopted `next_root` is
        // rejected — the consumed frontier is no longer the accepted one.
        let replay = accept_offline_release(
            &art1.offline_release,
            Some(&pin1),
            Some(&adopted.next_root),
            &recipient,
            &[0x55u8; 32],
            &policy_hash,
            &before1,
            &after1,
        );
        assert!(
            matches!(replay, Err(OfflineRecover::Predicate(_))),
            "replay of the consumed frontier must be rejected, got {replay:?}"
        );

        // (d) Transfer 2 chains from the adopted frontier.
        let (art2, out2) = drive(&out1.new_device_state, 0xC1, [0x66u8; 32]);
        assert_eq!(
            art2.appliance_prev_root, art1.appliance_next_root,
            "transfer 2 must consume transfer 1's successor frontier"
        );
        let pin2 = pin_from(&art2.pin);
        accept_offline_release(
            &art2.offline_release,
            Some(&pin2),
            Some(&adopted.next_root),
            &recipient,
            &[0x66u8; 32],
            &policy_hash,
            &out2.smt_proofs.pre_root,
            &out2.child_r_a,
        )
        .expect("transfer 2 must be accepted from the adopted frontier");
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
            anchor_state_leaf_key, compute_smt_key, initial_chain_tip_from_device_ids,
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
            new_value: anchor_core::root_advance::anchor_state_leaf(&b, &[0xA1u8; 32], 1),
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
                None,
            )
            .expect("sim with anchor_leaf")
            .child_r_a;
        let sim_without = sdk
            .simulate_advance_for_confirm(rel_key, cp, op.clone(), deltas, Some(init), None, None)
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
                    None,
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

    // ---------------------------------------------------------------------
    // §16.6 defect zero — staged advance seam.
    //
    // An online send must not emit anything deliverable before the local state
    // justifying it is durable, which forces proposal + gate + pending EK head
    // + exact envelope bytes into the SAME transaction as the canonical
    // advance. But the receipt cannot be built inside that transaction:
    // signing reads cert heads through get_connection(), and the advance
    // already holds that single global mutex, so re-entry deadlocks. The
    // staged seam makes the only legal ordering explicit:
    //     prepare (pure) -> build (DB reads OK) -> ONE tx.
    // ---------------------------------------------------------------------

    /// The builder must run BEFORE the write transaction opens, and a DB read
    /// inside it must not deadlock. If this test hangs, the seam is wrong.
    #[test]
    #[serial]
    fn staged_builder_runs_before_the_write_and_may_read_the_db() {
        let sdk = full_state_apply_harness();
        let (sender, _) = sender_ids();
        let rel = dsm::verification::smt_replace_witness::compute_smt_key(
            &sdk.device_info.device_id,
            &sender,
        );

        let (_state, outcome, artifacts) = sdk
            .execute_on_relationship_staged(
                rel,
                sender,
                incoming_transfer_op(&sdk.device_info.device_id, 5, vec![0x31u8; 32]),
                &[dsm::types::device_state::BalanceDelta {
                    policy_commit: crate::policy::builtin_policy_commit("ERA").unwrap(),
                    direction: dsm::types::device_state::BalanceDirection::Credit,
                    amount: 5,
                }],
                Some([0u8; 32]),
                |o| {
                    // A real builder signs here, which touches the DB. Prove
                    // that is safe at this point in the sequence.
                    let _ = crate::storage::client_db::load_cert_chain_head_pubkey(
                        &rel,
                        crate::storage::client_db::CertChainSide::Local,
                    );
                    Ok(o.new_chain_state.compute_chain_tip())
                },
                |tx, _o, child: &[u8; 32]| {
                    tx.execute(
                        "CREATE TABLE IF NOT EXISTS staged_probe(child BLOB NOT NULL)",
                        [],
                    )
                    .map_err(|e| {
                        DsmError::storage(format!("probe: {e}"), None::<std::io::Error>)
                    })?;
                    tx.execute(
                        "INSERT INTO staged_probe(child) VALUES (?1)",
                        rusqlite::params![child.as_slice()],
                    )
                    .map_err(|e| {
                        DsmError::storage(format!("probe: {e}"), None::<std::io::Error>)
                    })?;
                    Ok(())
                },
            )
            .expect("staged advance");

        assert_eq!(
            artifacts,
            outcome.new_chain_state.compute_chain_tip(),
            "builder saw the real AdvanceOutcome and its artifacts reached the caller"
        );

        let persisted: Vec<u8> = {
            let binding = crate::storage::client_db::get_connection().expect("conn");
            let conn = binding.lock().unwrap_or_else(|e| e.into_inner());
            conn.query_row("SELECT child FROM staged_probe", [], |r| r.get(0))
                .expect("probe row committed with the advance")
        };
        assert_eq!(
            persisted,
            artifacts.to_vec(),
            "in-tx writer persisted the builder's artifacts, never a rebuild"
        );
    }

    /// A failing builder must abort BEFORE anything is persisted — this is the
    /// window where a lost cert-head CAS lands, and it must leave nothing
    /// deliverable behind.
    #[test]
    #[serial]
    fn staged_builder_failure_persists_nothing() {
        let sdk = full_state_apply_harness();
        let (sender, _) = sender_ids();
        let rel = dsm::verification::smt_replace_witness::compute_smt_key(
            &sdk.device_info.device_id,
            &sender,
        );
        let head_before = device_root(&sdk);

        let err = sdk
            .execute_on_relationship_staged(
                rel,
                sender,
                incoming_transfer_op(&sdk.device_info.device_id, 7, vec![0x32u8; 32]),
                &[dsm::types::device_state::BalanceDelta {
                    policy_commit: crate::policy::builtin_policy_commit("ERA").unwrap(),
                    direction: dsm::types::device_state::BalanceDirection::Credit,
                    amount: 7,
                }],
                Some([0u8; 32]),
                |_o| -> Result<(), DsmError> {
                    Err(DsmError::invalid_operation("cert-head CAS lost the race"))
                },
                |_tx, _o, _a| Ok(()),
            )
            .expect_err("a failed build must abort the advance");
        assert!(err.to_string().contains("CAS lost the race"));

        assert_eq!(
            device_root(&sdk),
            head_before,
            "no canonical advance may survive a failed artifact build"
        );
    }

    /// GAP 1 CRITERION 3 — a failure in ANY extra write must roll the canonical
    /// advance back with it.
    ///
    /// `write_extra` runs INSIDE the advance transaction, so the durable bundle
    /// (proposal, gate, pending EK head, outbox row) and the canonical advance
    /// share one commit. If any of those writes fails, the advance must not
    /// survive on its own — otherwise the debit lands with no lifecycle record
    /// and nothing can ever settle or reconcile it.
    #[test]
    #[serial_test::serial]
    fn extra_write_failure_rolls_back_the_canonical_advance() {
        let sdk = full_state_apply_harness();
        let (sender, _) = sender_ids();
        let rel = dsm::verification::smt_replace_witness::compute_smt_key(
            &sdk.device_info.device_id,
            &sender,
        );
        let head_before = device_root(&sdk);

        let built = std::cell::Cell::new(false);
        let err = sdk
            .execute_on_relationship_staged(
                rel,
                sender,
                incoming_transfer_op(&sdk.device_info.device_id, 9, vec![0x41u8; 32]),
                &[dsm::types::device_state::BalanceDelta {
                    policy_commit: crate::policy::builtin_policy_commit("ERA").unwrap(),
                    direction: dsm::types::device_state::BalanceDirection::Credit,
                    amount: 9,
                }],
                Some([0u8; 32]),
                |_o| -> Result<(), DsmError> {
                    built.set(true);
                    Ok(())
                },
                // The bundle write fails — e.g. the outbox UNIQUE(commitment)
                // constraint rejects a second lifecycle row for one identity.
                |_tx, _o, _a| {
                    Err(DsmError::internal(
                        "outbox insert failed",
                        None::<std::io::Error>,
                    ))
                },
            )
            .expect_err("a failed extra write must abort the whole advance");
        assert!(err.to_string().contains("outbox insert failed"));
        assert!(built.get(), "the builder must have run before the write");

        assert_eq!(
            device_root(&sdk),
            head_before,
            "the canonical advance MUST roll back with the failed bundle write — \
             a debit with no durable lifecycle record is exactly the hazard this \
             seam exists to prevent"
        );
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
