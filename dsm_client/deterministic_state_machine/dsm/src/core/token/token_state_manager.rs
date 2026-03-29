//! Token State Manager (DSM: state-integrated, atomic)
//!
//! Token truth must come from state transitions. This module applies token-related operations
//! to a `State` atomically and returns the updated balances map.
//!
//! Invariants:
//! - no wall-clock time
//! - deterministic behavior
//! - balances are part of `State` (this manager computes updates)
//!
//! Caches are optional performance helpers and must not become an alternate source of truth.

use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::RwLock;

use crate::common::helpers::secure_eq;
use crate::crypto::sphincs;
use crate::core::token::policy::TokenPolicySystem;

use crate::{
    types::{
        error::DsmError,
        operations::{Operation, Ops},
        state_types::{SparseIndex, State, StateParams, PreCommitment},
        token_types::{Balance, StateContext, Token, TokenStatus},
    },
};

/// Resolves a `token_id` string to its 32-byte CPTA `policy_commit`.
///
/// This trait enables hierarchical domain-separated hashing where
/// `policy_commit` serves as the cryptographic sub-domain for each token type.
pub trait PolicyCommitResolver: Send + Sync {
    fn resolve(&self, token_id: &str) -> Result<[u8; 32], DsmError>;
}

/// Derive the stable canonical balance key for a token position.
///
/// `balance_key` is the identity of the canonical balance entry. Freshness and
/// versioning belong to projection rows, not to the balance identity itself.
pub fn derive_canonical_balance_key(
    policy_commit: &[u8; 32],
    owner_pk: &[u8],
    token_id: &str,
) -> String {
    let digest = crate::crypto::blake3::token_domain_hash(policy_commit, "balance-key", owner_pk);
    let bytes = digest.as_bytes();
    let mut le = [0u8; 16];
    le.copy_from_slice(&bytes[..16]);
    let prefix = u128::from_le_bytes(le);
    format!("{prefix}|{token_id}")
}

/// Deterministic policy_commit lookup for builtin token types.
/// Used by state machine core to apply token operations deterministically.
pub fn builtin_policy_commit_for_token(token_id: &str) -> Option<[u8; 32]> {
    // These values must match the SDK's policy/builtins.rs for consistency.
    // Era/dBTC are the canonical builtin tokens for DSM.
    match token_id {
        "ERA" => Some([
            0xaf, 0x13, 0x49, 0xb9, 0xf5, 0xf9, 0xa1, 0xa6, 0xa0, 0x40, 0x4d, 0xea, 0x36, 0xdc,
            0xc9, 0x49, 0x9b, 0xcb, 0x25, 0xc9, 0xad, 0xc1, 0x12, 0xb7, 0xcc, 0x9a, 0x93, 0xca,
            0xe4, 0x1f, 0x32, 0x62,
        ]),
        "dBTC" => Some([
            0x03, 0xa4, 0x2b, 0x67, 0x19, 0x17, 0xaf, 0x84, 0x2f, 0x07, 0x3d, 0x87, 0xcf, 0xa4,
            0x59, 0xd8, 0x45, 0xb9, 0x68, 0xfd, 0xb1, 0xab, 0xcb, 0x03, 0x31, 0x2d, 0x91, 0x4e,
            0x35, 0x01, 0x62, 0x22,
        ]),
        _ => None,
    }
}

/// Resolve policy_commit for any token, including non-builtins.
///
/// §9.1: All TokenOps MUST include `policy_commit`. For builtins (ERA, dBTC),
/// the precomputed constants are returned. For CPTA-anchored custom tokens,
/// the policy_commit is derived deterministically from the token_id using
/// BLAKE3 domain separation. The full CPTA bytes should ideally be cached
/// locally and verified by digest, but this derivation ensures balance
/// mutations are never skipped for valid token operations.
pub fn resolve_policy_commit(token_id: &str) -> [u8; 32] {
    builtin_policy_commit_for_token(token_id).unwrap_or_else(|| {
        // §9.3: policy_commit := BLAKE3-256("DSM/cpta\0" || canonical_cpta_bytes)
        // For non-builtin tokens without cached CPTA bytes, derive a
        // deterministic placeholder from the token_id. This ensures the
        // state machine applies balance deltas for all tokens, not just
        // builtins. The real policy_commit is verified at the receipt
        // acceptance layer (§9.5 binding to policy).
        crate::crypto::blake3::domain_hash_bytes("DSM/token-policy\0", token_id.as_bytes())
    })
}

#[derive(Debug, Default)]
pub struct TokenStateManager {
    token_store: Arc<RwLock<HashMap<String, Token>>>,
    balance_cache: Arc<RwLock<HashMap<String, Balance>>>,
    policy_system: Option<Arc<TokenPolicySystem>>,
}

/// Informational transfer object.
/// DSM ordering comes from state_number / hash chain, not wall-clock markers.
#[derive(Debug, Clone)]
pub struct TokenTransfer {
    pub sender: Vec<u8>,
    pub recipient: Vec<u8>,
    pub amount: u64,
    pub token_id: String,
}

impl TokenStateManager {
    pub fn new() -> Self {
        Self {
            token_store: Arc::new(RwLock::new(HashMap::new())),
            balance_cache: Arc::new(RwLock::new(HashMap::new())),
            policy_system: None,
        }
    }

    pub fn with_policy_system(policy_system: Arc<TokenPolicySystem>) -> Self {
        Self {
            token_store: Arc::new(RwLock::new(HashMap::new())),
            balance_cache: Arc::new(RwLock::new(HashMap::new())),
            policy_system: Some(policy_system),
        }
    }

    /// Resolve a `token_id` to its 32-byte CPTA `policy_commit` for use as
    /// a hierarchical domain separator in BLAKE3 hashing.
    ///
    /// Uses an explicit token-local anchor when available, otherwise delegates
    /// to the configured `TokenPolicySystem`. Missing anchors fail closed.
    fn resolve_policy_commit(&self, token_id: &str) -> Result<[u8; 32], DsmError> {
        if let Some(token) = self.token_store.read().get(token_id) {
            if let Some(policy_anchor) = token.policy_anchor() {
                return Ok(*policy_anchor);
            }
        }

        if let Some(ps) = &self.policy_system {
            PolicyCommitResolver::resolve(ps.as_ref(), token_id)
        } else {
            Err(DsmError::invalid_operation(format!(
                "Missing policy anchor for token {token_id}"
            )))
        }
    }

    /// Create a state transition that atomically applies token balance changes.
    pub fn create_token_state_transition(
        &self,
        current_state: &State,
        operation: Operation,
        new_entropy: Vec<u8>,
        encapsulated_entropy: Option<Vec<u8>>,
    ) -> Result<State, DsmError> {
        // Validate operation basic shape if your Operation supports validation.
        // If validate() doesn't exist in your tree, remove this block.
        if let Err(e) = operation.validate() {
            return Err(DsmError::invalid_operation(format!(
                "Invalid operation for token state transition: {e}"
            )));
        }

        let updated_balances = self.apply_token_operation(current_state, &operation)?;

        let prev_state_hash = current_state.hash()?;
        let next_state_number = current_state.state_number + 1;

        // Build sparse index deterministically
        let mut indices = Vec::new();
        let mut n = next_state_number;
        while n > 0 {
            if n & 1 == 1 {
                indices.push(n);
            }
            n >>= 1;
        }
        let sparse_index = SparseIndex::new(indices);

        // Verify forward-commitment rules if present
        if let Some(pre_commit) = &current_state.forward_commitment {
            if !self.verify_precommitment_parameters(pre_commit, &operation)? {
                return Err(DsmError::policy_violation(
                    "forward commitment".to_string(),
                    "Operation violates forward commitment parameters".to_string(),
                    None::<std::io::Error>,
                ));
            }
        }

        let mut params = StateParams::new(
            next_state_number,
            new_entropy,
            operation,
            current_state.device_info.clone(),
        );

        params = params
            .with_encapsulated_entropy(encapsulated_entropy.unwrap_or_default())
            .with_prev_state_hash(prev_state_hash)
            .with_sparse_index(sparse_index);

        let mut new_state = State::new(params);

        // Atomic set of balances (state is the truth)
        new_state.token_balances = updated_balances;

        new_state.id = format!("state_{}", new_state.state_number);
        new_state.hash = new_state.compute_hash()?;

        Ok(new_state)
    }

    pub fn apply_token_operation(
        &self,
        current_state: &State,
        operation: &Operation,
    ) -> Result<HashMap<String, Balance>, DsmError> {
        // Establish canonical state context
        let ctx = StateContext::new(
            current_state.hash,
            current_state.state_number,
            current_state.device_info.device_id,
        );
        StateContext::set_current(ctx);

        struct ContextGuard;
        impl Drop for ContextGuard {
            fn drop(&mut self) {
                StateContext::clear_current();
            }
        }
        let _guard = ContextGuard;

        self.verify_token_policy(operation)?;

        let mut new_balances = current_state.token_balances.clone();

        match operation {
            Operation::Transfer {
                token_id,
                amount,
                recipient,
                ..
            } => {
                let token_id_str = String::from_utf8_lossy(token_id);
                let sender_pk = &current_state.device_info.public_key;
                let sender_key = self.make_balance_key(sender_pk, &token_id_str)?;
                let recipient_key = self.make_balance_key(recipient.as_slice(), &token_id_str)?;

                let sender_balance = new_balances.get(&sender_key).cloned().unwrap_or_else(|| {
                    Balance::from_state(0, current_state.hash, current_state.state_number)
                });

                if sender_balance.value() < amount.value() {
                    return Err(DsmError::insufficient_balance(
                        token_id_str.into_owned(),
                        sender_balance.value(),
                        amount.value(),
                    ));
                }

                let new_sender_balance = Balance::from_state(
                    sender_balance.value().saturating_sub(amount.value()),
                    current_state.hash,
                    current_state.state_number,
                );

                let recipient_balance =
                    new_balances
                        .get(&recipient_key)
                        .cloned()
                        .unwrap_or_else(|| {
                            Balance::from_state(0, current_state.hash, current_state.state_number)
                        });

                let new_recipient_value = recipient_balance
                    .value()
                    .checked_add(amount.value())
                    .ok_or_else(|| {
                        DsmError::invalid_operation("Balance overflow on transfer credit")
                    })?;
                let new_recipient_balance = Balance::from_state(
                    new_recipient_value,
                    current_state.hash,
                    current_state.state_number,
                );

                new_balances.insert(sender_key, new_sender_balance);
                new_balances.insert(recipient_key, new_recipient_balance);
            }

            Operation::Mint {
                amount,
                token_id,
                authorized_by,
                proof_of_authorization,
                ..
            } => {
                let token_id_str = String::from_utf8_lossy(token_id);
                if !self.verify_mint_authorization(
                    &token_id_str,
                    authorized_by,
                    proof_of_authorization,
                )? {
                    return Err(DsmError::unauthorized(
                        "Invalid mint authorization",
                        None::<std::io::Error>,
                    ));
                }

                let owner_pk = &current_state.device_info.public_key;
                let owner_key = self.make_balance_key(owner_pk, &token_id_str)?;

                let current_balance = new_balances.get(&owner_key).cloned().unwrap_or_else(|| {
                    Balance::from_state(0, current_state.hash, current_state.state_number)
                });

                let new_mint_value = current_balance
                    .value()
                    .checked_add(amount.value())
                    .ok_or_else(|| DsmError::invalid_operation("Balance overflow on mint"))?;
                new_balances.insert(
                    owner_key,
                    Balance::from_state(
                        new_mint_value,
                        current_state.hash,
                        current_state.state_number,
                    ),
                );
            }

            Operation::Burn {
                amount,
                token_id,
                proof_of_ownership,
                ..
            } => {
                let token_id_str = String::from_utf8_lossy(token_id);
                if !self.verify_token_ownership(&token_id_str, proof_of_ownership)? {
                    return Err(DsmError::unauthorized(
                        "Invalid burn authorization",
                        None::<std::io::Error>,
                    ));
                }

                let owner_pk = &current_state.device_info.public_key;
                let owner_key = self.make_balance_key(owner_pk, &token_id_str)?;

                let owner_balance = new_balances.get(&owner_key).cloned().unwrap_or_else(|| {
                    Balance::from_state(0, current_state.hash, current_state.state_number)
                });

                if owner_balance.value() < amount.value() {
                    return Err(DsmError::insufficient_balance(
                        token_id_str.into_owned(),
                        owner_balance.value(),
                        amount.value(),
                    ));
                }

                new_balances.insert(
                    owner_key,
                    Balance::from_state(
                        owner_balance.value().saturating_sub(amount.value()),
                        current_state.hash,
                        current_state.state_number,
                    ),
                );
            }

            // ── DLV operations ────────────────────────────────────
            //
            // DlvCreate: lock tokens from the creator's available balance.
            // DlvInvalidate: return locked tokens to the creator.
            // DlvClaim: release locked tokens to the claimant.
            // DlvUnlock: state-only transition — no balance change.
            Operation::DlvCreate {
                token_id,
                locked_amount,
                creator_public_key,
                ..
            } => {
                if let (Some(tid), Some(amount)) = (token_id, locked_amount) {
                    if amount.value() > 0 {
                        let tid_str = String::from_utf8_lossy(tid);
                        let creator_key =
                            self.make_balance_key(creator_public_key.as_slice(), &tid_str)?;

                        let creator_balance =
                            new_balances.get(&creator_key).cloned().unwrap_or_else(|| {
                                Balance::from_state(
                                    0,
                                    current_state.hash,
                                    current_state.state_number,
                                )
                            });

                        if creator_balance.value() < amount.value() {
                            return Err(DsmError::insufficient_balance(
                                tid_str.into_owned(),
                                creator_balance.value(),
                                amount.value(),
                            ));
                        }

                        // Deduct locked amount from creator's available balance
                        new_balances.insert(
                            creator_key,
                            Balance::from_state(
                                creator_balance.value().saturating_sub(amount.value()),
                                current_state.hash,
                                current_state.state_number,
                            ),
                        );
                    }
                }
            }

            Operation::DlvInvalidate {
                creator_public_key, ..
            } => {
                // Vault invalidation returns locked tokens to the creator.
                // The vault's locked_amount and token_id are not embedded in
                // DlvInvalidate directly — the caller (DLVManager in Phase 5)
                // is responsible for ensuring the DlvInvalidate operation is
                // paired with correct balance restoration via the state's
                // token_balances map before reaching this function.
                //
                // If the vault had no locked tokens, this is a no-op.
                let _ = creator_public_key;
            }

            Operation::DlvClaim {
                claimant_public_key,
                ..
            } => {
                // Claim releases locked tokens to the claimant.
                // Similar to DlvInvalidate, the vault's locked_amount and
                // token_id are resolved by DLVManager and applied to the
                // state's token_balances map before this function is called.
                let _ = claimant_public_key;
            }

            // DlvUnlock is a state-only transition (no balance change).
            Operation::DlvUnlock { .. } => {}

            _ => {}
        }

        self.update_balance_cache(&new_balances)?;
        Ok(new_balances)
    }

    /// Deterministic balance key with hierarchical domain separation.
    ///
    /// The CPTA `policy_commit` is used as the cryptographic sub-domain, ensuring
    /// that balance keys for different token types are in entirely different hash
    /// domains. This prevents cross-token confusion (e.g., dBTC credited to ERA).
    pub fn make_balance_key(&self, owner_pk: &[u8], token_id: &str) -> Result<String, DsmError> {
        let policy_commit = self.resolve_policy_commit(token_id)?;
        Ok(derive_canonical_balance_key(
            &policy_commit,
            owner_pk,
            token_id,
        ))
    }

    fn verify_mint_authorization(
        &self,
        token_id: &str,
        authorized_by: &[u8],
        proof: &[u8],
    ) -> Result<bool, DsmError> {
        if proof.is_empty() {
            return Ok(false);
        }

        // proof := u16 pk_len | pk_bytes | u16 sig_len | sig_bytes
        if proof.len() < 4 {
            return Ok(false);
        }

        let mut idx: usize = 0;
        let read_u16 = |buf: &[u8], i: &mut usize| -> Result<u16, DsmError> {
            if *i + 2 > buf.len() {
                return Err(DsmError::invalid_parameter(
                    "mint_proof: truncated length field",
                ));
            }
            let v = u16::from_le_bytes([buf[*i], buf[*i + 1]]);
            *i += 2;
            Ok(v)
        };
        let read_bytes = |buf: &[u8], i: &mut usize, n: usize| -> Result<Vec<u8>, DsmError> {
            if *i + n > buf.len() {
                return Err(DsmError::invalid_parameter("mint_proof: truncated field"));
            }
            let out = buf[*i..*i + n].to_vec();
            *i += n;
            Ok(out)
        };

        let pk_len = read_u16(proof, &mut idx)? as usize;
        let pk = read_bytes(proof, &mut idx, pk_len)?;
        let sig_len = read_u16(proof, &mut idx)? as usize;
        let sig = read_bytes(proof, &mut idx, sig_len)?;

        let policy_commit = self.resolve_policy_commit(token_id)?;
        let mut msg = b"mint|".to_vec();
        msg.extend_from_slice(authorized_by);
        let msg_hash = crate::crypto::blake3::token_domain_hash(&policy_commit, "mint", &msg);

        sphincs::sphincs_verify(&pk, msg_hash.as_bytes(), &sig)
    }

    fn verify_token_ownership(&self, token_id: &str, proof: &[u8]) -> Result<bool, DsmError> {
        if proof.is_empty() {
            return Ok(false);
        }

        if proof.len() < 4 {
            return Ok(false);
        }

        let mut idx: usize = 0;
        let read_u16 = |buf: &[u8], i: &mut usize| -> Result<u16, DsmError> {
            if *i + 2 > buf.len() {
                return Err(DsmError::invalid_parameter(
                    "ownership_proof: truncated length field",
                ));
            }
            let v = u16::from_le_bytes([buf[*i], buf[*i + 1]]);
            *i += 2;
            Ok(v)
        };
        let read_bytes = |buf: &[u8], i: &mut usize, n: usize| -> Result<Vec<u8>, DsmError> {
            if *i + n > buf.len() {
                return Err(DsmError::invalid_parameter(
                    "ownership_proof: truncated field",
                ));
            }
            let out = buf[*i..*i + n].to_vec();
            *i += n;
            Ok(out)
        };

        let pk_len = read_u16(proof, &mut idx)? as usize;
        let pk = read_bytes(proof, &mut idx, pk_len)?;
        let sig_len = read_u16(proof, &mut idx)? as usize;
        let sig = read_bytes(proof, &mut idx, sig_len)?;

        let policy_commit = self.resolve_policy_commit(token_id)?;
        let mut msg = b"burn|".to_vec();
        msg.extend_from_slice(token_id.as_bytes());
        let msg_hash = crate::crypto::blake3::token_domain_hash(&policy_commit, "burn", &msg);

        sphincs::sphincs_verify(&pk, msg_hash.as_bytes(), &sig)
    }

    fn verify_token_policy(&self, operation: &Operation) -> Result<(), DsmError> {
        let policy_system = match &self.policy_system {
            Some(system) => system,
            None => return Ok(()),
        };

        let token_id = match operation {
            Operation::Transfer { token_id, .. } => token_id,
            Operation::Mint { token_id, .. } => token_id,
            Operation::Burn { token_id, .. } => token_id,
            Operation::LockToken { token_id, .. } => token_id,
            Operation::UnlockToken { token_id, .. } => token_id,
            Operation::Lock { token_id, .. } => token_id,
            Operation::Unlock { token_id, .. } => token_id,
            _ => return Ok(()),
        };

        let mut context = std::collections::HashMap::new();
        match operation {
            Operation::Transfer {
                amount, recipient, ..
            } => {
                context.insert(
                    "amount".to_string(),
                    amount.value().to_string().into_bytes(),
                );
                context.insert("recipient".to_string(), recipient.clone());
            }
            Operation::Mint {
                amount,
                authorized_by,
                ..
            } => {
                context.insert(
                    "amount".to_string(),
                    amount.value().to_string().into_bytes(),
                );
                context.insert("authorized_by".to_string(), authorized_by.clone());
            }
            Operation::Burn { amount, .. } => {
                context.insert(
                    "amount".to_string(),
                    amount.value().to_string().into_bytes(),
                );
            }
            Operation::Lock {
                amount,
                purpose,
                owner,
                ..
            } => {
                context.insert(
                    "amount".to_string(),
                    amount.value().to_string().into_bytes(),
                );
                context.insert("purpose".to_string(), purpose.clone());
                context.insert("owner".to_string(), owner.clone());
            }
            Operation::Unlock {
                amount,
                purpose,
                owner,
                ..
            } => {
                context.insert(
                    "amount".to_string(),
                    amount.value().to_string().into_bytes(),
                );
                context.insert("purpose".to_string(), purpose.clone());
                context.insert("owner".to_string(), owner.clone());
            }
            _ => {}
        }

        if let Some(ctx) = StateContext::get_current() {
            context.insert("tick".to_string(), ctx.state_number.to_le_bytes().to_vec());
        }

        let op_type = match operation {
            Operation::Transfer { .. } => "transfer",
            Operation::Mint { .. } => "mint",
            Operation::Burn { .. } => "burn",
            Operation::Lock { .. } => "lock",
            Operation::Unlock { .. } => "unlock",
            _ => "unknown",
        };

        let token_id_str = String::from_utf8_lossy(token_id);
        let token_id_owned = token_id_str.into_owned();
        let result = if tokio::runtime::Handle::try_current().is_ok() {
            let policy_system = policy_system.clone();
            let context_clone = context.clone();
            let op_type_owned = op_type.to_string();
            let token_id_for_thread = token_id_owned.clone();
            let join_res = std::thread::spawn(move || {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|e| {
                        DsmError::internal(
                            format!("Failed to build runtime for policy verification: {e}"),
                            None::<std::convert::Infallible>,
                        )
                    })?;
                rt.block_on(async {
                    policy_system
                        .enforce_policy(&token_id_for_thread, &op_type_owned, &context_clone)
                        .await
                })
            })
            .join();

            match join_res {
                Ok(res) => res?,
                Err(_) => {
                    return Err(DsmError::internal(
                        "Failed to join policy verification thread",
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
                        format!("Failed to build runtime for policy verification: {e}"),
                        None::<std::convert::Infallible>,
                    )
                })?;

            rt.block_on(async {
                policy_system
                    .enforce_policy(&token_id_owned, op_type, &context)
                    .await
            })?
        };

        if !result.allowed {
            return Err(DsmError::policy_violation(
                token_id_owned,
                result.reason,
                None::<std::io::Error>,
            ));
        }

        Ok(())
    }

    fn verify_precommitment_parameters(
        &self,
        pre_commit: &PreCommitment,
        operation: &Operation,
    ) -> Result<bool, DsmError> {
        let matches_type = match operation {
            Operation::Transfer { .. } => pre_commit.operation_type == "transfer",
            Operation::Mint { .. } => pre_commit.operation_type == "mint",
            Operation::Burn { .. } => pre_commit.operation_type == "burn",
            Operation::LockToken { .. } => pre_commit.operation_type == "lock",
            Operation::UnlockToken { .. } => pre_commit.operation_type == "unlock",
            _ => false,
        };

        if !matches_type {
            return Ok(false);
        }

        let matches_fixed = match operation {
            Operation::Transfer {
                token_id,
                recipient,
                ..
            } => {
                let token_ok = if let Some(exp) = pre_commit.fixed_parameters.get("token_id") {
                    secure_eq(token_id.as_slice(), exp)
                } else {
                    true
                };

                let recip_ok = if let Some(exp) = pre_commit.fixed_parameters.get("recipient") {
                    secure_eq(recipient.as_slice(), exp)
                } else {
                    true
                };

                token_ok && recip_ok
            }
            Operation::Mint { token_id, .. } | Operation::Burn { token_id, .. } => {
                if let Some(exp) = pre_commit.fixed_parameters.get("token_id") {
                    secure_eq(token_id.as_slice(), exp)
                } else {
                    true
                }
            }
            _ => true,
        };

        if !matches_fixed {
            return Ok(false);
        }

        let variable_ok = match operation {
            Operation::Transfer { amount, .. }
            | Operation::Mint { amount, .. }
            | Operation::Burn { amount, .. } => {
                if pre_commit.variable_parameters.contains("amount") {
                    true
                } else if let Some(exp) = pre_commit.fixed_parameters.get("amount") {
                    if exp.len() == 8 {
                        let mut arr = [0u8; 8];
                        arr.copy_from_slice(&exp[..8]);
                        let expected = u64::from_le_bytes(arr);
                        amount.value() == expected
                    } else {
                        false
                    }
                } else {
                    false
                }
            }
            _ => true,
        };

        Ok(matches_type && matches_fixed && variable_ok)
    }

    fn update_balance_cache(
        &self,
        new_balances: &HashMap<String, Balance>,
    ) -> Result<(), DsmError> {
        {
            let mut cache = self.balance_cache.write();
            for (k, v) in new_balances {
                cache.insert(k.clone(), v.clone());
            }
        }
        self.optimize_balance_cache();
        Ok(())
    }

    fn optimize_balance_cache(&self) {
        const MAX_CACHE_SIZE: usize = 10_000;
        let mut cache = self.balance_cache.write();
        if cache.len() <= MAX_CACHE_SIZE {
            return;
        }

        // deterministic eviction: keep lexicographically largest keys
        let mut keys: Vec<String> = cache.keys().cloned().collect();
        keys.sort();

        let drop_count = keys.len().saturating_sub(MAX_CACHE_SIZE);
        for k in keys.into_iter().take(drop_count) {
            cache.remove(&k);
        }
    }

    // ---------------------------- Token store methods ----------------------------

    pub fn token_exists(&self, token_id: &str) -> Result<bool, DsmError> {
        Ok(self.token_store.read().contains_key(token_id))
    }

    pub fn get_token(&self, token_id: &str) -> Result<Token, DsmError> {
        self.token_store
            .read()
            .get(token_id)
            .cloned()
            .ok_or_else(|| DsmError::not_found("Token", Some(token_id.to_string())))
    }

    pub fn get_token_balance_from_store(
        &self,
        owner_pk: &[u8],
        token_id: &str,
    ) -> Result<Balance, DsmError> {
        let key = self.make_balance_key(owner_pk, token_id)?;

        if let Some(b) = self.balance_cache.read().get(&key) {
            return Ok(b.clone());
        }

        if let Some(ctx) = StateContext::get_current() {
            Ok(Balance::from_state(0, ctx.state_hash, ctx.state_number))
        } else {
            Ok(Balance::zero())
        }
    }

    pub fn update_token_metadata(&self, token_id: &str, metadata: Vec<u8>) -> Result<(), DsmError> {
        let mut store = self.token_store.write();
        let old = store
            .get(token_id)
            .cloned()
            .ok_or_else(|| DsmError::not_found("Token", Some(token_id.to_string())))?;

        let policy_anchor = *old.policy_anchor().ok_or_else(|| {
            DsmError::invalid_operation(format!(
                "Token {token_id} cannot be updated without a canonical policy anchor"
            ))
        })?;

        let mut updated = Token::new(
            old.owner_id(),
            old.token_hash().to_vec(),
            metadata,
            old.balance().clone(),
            policy_anchor,
        );
        updated.set_status(old.status().clone());
        store.insert(token_id.to_string(), updated);
        Ok(())
    }

    pub fn revoke_token(&self, token_id: &str) -> Result<(), DsmError> {
        let mut store = self.token_store.write();
        let tok = store
            .get_mut(token_id)
            .ok_or_else(|| DsmError::not_found("Token", Some(token_id.to_string())))?;
        tok.set_status(TokenStatus::Revoked);
        Ok(())
    }

    pub fn verify_token(&self, token_id: &str) -> Result<bool, DsmError> {
        Ok(self
            .token_store
            .read()
            .get(token_id)
            .map(|t| t.is_valid())
            .unwrap_or(false))
    }

    /// Register or update a token-local policy anchor without enabling the full
    /// policy enforcement stack. This is useful for deterministic balance-key
    /// derivation in callers that already control when policy enforcement runs.
    pub fn register_token_policy_anchor(&self, token_id: &str, policy_anchor: [u8; 32]) {
        let mut store = self.token_store.write();
        if let Some(token) = store.get_mut(token_id) {
            token.set_policy_anchor(policy_anchor);
            return;
        }

        let token = Token::new(
            "token-state-manager",
            token_id.as_bytes().to_vec(),
            Vec::new(),
            Balance::zero(),
            policy_anchor,
        );
        store.insert(token_id.to_string(), token);
    }

    pub fn list_tokens(&self) -> Result<Vec<String>, DsmError> {
        let mut out: Vec<String> = self.token_store.read().keys().cloned().collect();
        out.sort();
        Ok(out)
    }

    pub fn get_tokens_by_owner(&self, owner_id: &str) -> Result<Vec<Token>, DsmError> {
        let mut out: Vec<Token> = self
            .token_store
            .read()
            .values()
            .filter(|t| t.owner_id() == owner_id)
            .cloned()
            .collect();
        out.sort_by(|a, b| a.id().cmp(b.id()));
        Ok(out)
    }

    pub fn create_token_transfer(
        sender_state: &State,
        recipient_state: &State,
        amount: u64,
        token_id: &str,
    ) -> Result<TokenTransfer, DsmError> {
        Ok(TokenTransfer {
            sender: sender_state.device_info.public_key.clone(),
            recipient: recipient_state.device_info.public_key.clone(),
            amount,
            token_id: token_id.to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::derive_canonical_balance_key;

    #[test]
    fn canonical_balance_key_is_stable_for_same_semantic_input() {
        let policy_commit = [0x11; 32];
        let owner_pk = [0x22; 32];

        let a = derive_canonical_balance_key(&policy_commit, &owner_pk, "dBTC");
        let b = derive_canonical_balance_key(&policy_commit, &owner_pk, "dBTC");

        assert_eq!(a, b);
    }

    #[test]
    fn canonical_balance_key_changes_when_policy_commit_changes() {
        let owner_pk = [0x22; 32];

        let a = derive_canonical_balance_key(&[0x11; 32], &owner_pk, "dBTC");
        let b = derive_canonical_balance_key(&[0x33; 32], &owner_pk, "dBTC");

        assert_ne!(a, b);
    }

    #[test]
    fn canonical_balance_key_changes_when_owner_binding_changes() {
        let policy_commit = [0x11; 32];

        let a = derive_canonical_balance_key(&policy_commit, &[0x22; 32], "dBTC");
        let b = derive_canonical_balance_key(&policy_commit, &[0x44; 32], "dBTC");

        assert_ne!(a, b);
    }
}
