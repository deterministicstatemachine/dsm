// SPDX-License-Identifier: MIT OR Apache-2.0

//! DLV Manager Module
//!
//! Manages Deterministic Limbo Vaults (DLVs) in a thread-safe manner.
//! Each lifecycle method returns an unsigned `Operation` that the SDK layer
//! must sign with SPHINCS+ before submitting to the state machine.
//! NOTE: No bincode/serde. `create_vault_post` encodes with `prost`.
//!
//! # DLV Settlement Status
//!
//! The canonical σ-gated claim path lives in `limbo_vault::claim` per DSM spec
//! §7.3 (`sk_V = BLAKE3-256("DSM/dlv-unlock\0" ‖ L ‖ C ‖ σ)`). `DlvClaim` and
//! `DlvInvalidate` operations returned by this manager are unsigned signals —
//! they do NOT themselves mutate token balances. Balance movement for a DLV
//! release must be expressed through a separate canonical transfer receipt per
//! DSM spec §18.4 ("normal stitched receipt with a smart commitment clause").
//!
//! ## Coverage map against SoFi §10.3 client verifier (11-step acceptance)
//!
//! Chunks #1–#7 of the routing pipeline cover the off-chain portions of the
//! verifier directly; the SMT-side portions remain composed at higher layers.
//!
//!   * ExtCommit binding (`X = BLAKE3("DSM/ext\0", canonical(RouteCommit))`)
//!     — chunk #3 (`route_commit_sdk`).
//!   * Initiator signature verification (SPHINCS+ over the canonical
//!     RouteCommit bytes with the signature field zeroed) — chunk #5
//!     (`route_commit_sdk::verify_route_commit_unlock_eligibility`).
//!   * Anchor-visible check (atomic-visibility trigger) — chunk #4.
//!   * AMM-curve re-simulation against live reserves — chunk #7
//!     (`route_commit_sdk::verify_amm_swap_against_reserves`).
//!
//! What §10.3 still asks for but is NOT enforced inside this manager:
//!
//!   * Inclusion proofs of vault state in the owner's Per-Device SMT.
//!   * Encumbrance commit + claim availability proof (per-vault state
//!     registry to detect double-claim across stitched receipts).
//!   * Route-set membership proof.
//!   * Intent-bounds verification (price slippage envelope, expiry).
//!
//! Until those land at the receipt-building layer, token-balance effects for
//! DLV release must be composed through normal transfer operations in the
//! same stitched receipt as the `DlvClaim` / `DlvInvalidate` signal.  A prior
//! port (PR #196) wired `locked_amount` directly into
//! `apply_token_balance_delta`; that was reverted because the fork lacks the
//! upstream per-vault state registry required to cross-validate claims and
//! the self-attested credit path enabled arbitrary mint.

use super::{FulfillmentMechanism, FulfillmentProof, LimboVault, LimboVaultDraft, VaultState};
use crate::types::operations::{Operation, TransactionMode};
use crate::types::token_types::Balance;
use crate::types::error::DsmError;
use prost::Message; // for encode_to_vec()
use std::{collections::HashMap, sync::Arc};

/// Manages Limbo Vaults
pub struct DLVManager {
    /// Vaults managed by this instance, keyed by raw 32-byte vault ID.
    vaults: tokio::sync::RwLock<HashMap<[u8; 32], Arc<tokio::sync::Mutex<LimboVault>>>>,
}

impl DLVManager {
    /// Create a new DLV manager
    pub fn new() -> Self {
        Self {
            vaults: tokio::sync::RwLock::new(HashMap::new()),
        }
    }

    /// Prepare a secret-free vault draft.
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_vault(
        &self,
        creator_public_key: &[u8],
        condition: FulfillmentMechanism,
        content: &[u8],
        content_type: &str,
        intended_recipient: Option<Vec<u8>>,
        encryption_public_key: &[u8],
        reference_state_hash: &[u8; 32],
    ) -> Result<LimboVaultDraft, DsmError> {
        LimboVault::create_draft(
            creator_public_key,
            condition.clone(),
            content,
            content_type,
            intended_recipient.clone(),
            encryption_public_key,
            reference_state_hash,
        )
    }

    /// Finalize a vault draft and return the vault ID with an unsigned `Operation::DlvCreate`.
    ///
    /// `creator_signature` authenticates the vault's `parameters_hash` and is stored
    /// in the vault metadata. The caller (SDK) must still sign the returned operation
    /// before submitting it to the state machine via `apply_transition()`.
    pub async fn finalize_vault(
        &self,
        draft: LimboVaultDraft,
        creator_signature: &[u8],
        token_id: Option<&str>,
        locked_amount: Option<u64>,
    ) -> Result<([u8; 32], Operation), DsmError> {
        let vault = draft.finalize(creator_signature)?;

        let vault_id: [u8; 32] = vault.id;

        // Serialize the fulfillment condition via proto for the operation
        let fm_proto: crate::types::proto::FulfillmentMechanism =
            (&vault.fulfillment_condition).into();
        let fulfillment_bytes = fm_proto.encode_to_vec();

        // Build the unsigned DlvCreate operation
        let locked_balance =
            locked_amount.map(|amt| Balance::from_state(amt, vault.reference_state_hash));

        let operation = Operation::DlvCreate {
            vault_id: vault_id.to_vec(),
            creator_public_key: vault.creator_public_key.clone(),
            parameters_hash: vault.parameters_hash.clone(),
            fulfillment_condition: fulfillment_bytes,
            intended_recipient: vault.intended_recipient.clone(),
            token_id: token_id.map(|s| s.as_bytes().to_vec()),
            locked_amount: locked_balance,
            signature: vec![], // unsigned — caller must sign
            mode: TransactionMode::Unilateral,
        };

        // Store the vault
        let mut vaults = self.vaults.write().await;
        vaults.insert(vault_id, Arc::new(tokio::sync::Mutex::new(vault)));

        Ok((vault_id, operation))
    }

    /// Get a vault by ID
    pub async fn get_vault(
        &self,
        vault_id: &[u8; 32],
    ) -> Result<Arc<tokio::sync::Mutex<LimboVault>>, DsmError> {
        let vaults = self.vaults.read().await;
        vaults.get(vault_id).cloned().ok_or_else(|| {
            DsmError::not_found(
                "Vault",
                Some(format!(
                    "Vault with ID {} not found",
                    base32::encode(base32::Alphabet::Crockford, vault_id)
                )),
            )
        })
    }

    /// List all vault IDs
    pub async fn list_vaults(&self) -> Result<Vec<[u8; 32]>, DsmError> {
        let vaults = self.vaults.read().await;
        Ok(vaults.keys().copied().collect())
    }

    /// Get vaults by status
    pub async fn get_vaults_by_status(
        &self,
        status: VaultState,
    ) -> Result<Vec<[u8; 32]>, DsmError> {
        // Avoid holding the RwLock guard across async awaits on individual vault mutexes.
        // Copy the handles first, then release the map read guard before locking each vault.
        let vaults = self.vaults.read().await;
        let handles: Vec<([u8; 32], Arc<tokio::sync::Mutex<LimboVault>>)> =
            vaults.iter().map(|(id, v)| (*id, v.clone())).collect();
        drop(vaults);

        let mut result = Vec::new();
        for (id, vault_lock) in handles.into_iter() {
            let vault = vault_lock.lock().await;
            if vault.state == status {
                result.push(id);
            }
        }
        Ok(result)
    }

    /// Attempt to unlock a vault and return the result with an unsigned `Operation::DlvUnlock`.
    ///
    /// `requester` is the Kyber public key checked against `intended_recipient`.
    /// `signing_public_key` is the SPHINCS+ public key embedded in the operation
    /// for state-machine signature verification.
    ///
    /// The caller (SDK) must sign the returned operation before submitting it
    /// to the state machine via `apply_transition()`.
    pub async fn try_unlock_vault(
        &self,
        vault_id: &[u8; 32],
        proof: FulfillmentProof,
        requester: &[u8],
        signing_public_key: &[u8],
        reference_state_hash: &[u8; 32],
    ) -> Result<(bool, Operation), DsmError> {
        let vault_lock = self.get_vault(vault_id).await?;
        let mut vault = vault_lock.lock().await;

        let proof_bytes = proof.to_bytes();
        let unlocked = vault.unlock(proof, requester, reference_state_hash)?;

        let operation = Operation::DlvUnlock {
            vault_id: vault_id.to_vec(),
            fulfillment_proof: proof_bytes,
            requester_public_key: signing_public_key.to_vec(),
            signature: vec![], // unsigned — caller must sign
            mode: TransactionMode::Unilateral,
        };

        Ok((unlocked, operation))
    }

    /// Activate a vault after entry anchor burial (dBTC §6.4.1).
    ///
    /// Transitions `Limbo` → `Active`. The fulfillment proof is verified but NOT
    /// stored in vault state — the preimage/skV is only derivable after a Burn
    /// transition (withdrawal). No `Operation` is returned because activation is
    /// an internal state change, not a hash-chain entry.
    pub async fn activate_vault(
        &self,
        vault_id: &[u8; 32],
        proof: FulfillmentProof,
        requester: &[u8],
        reference_state_hash: &[u8; 32],
    ) -> Result<bool, DsmError> {
        let vault_lock = self.get_vault(vault_id).await?;
        let mut vault = vault_lock.lock().await;
        vault.activate(&proof, requester, reference_state_hash)
    }

    /// Claim vault content and return it with an unsigned `Operation::DlvClaim`.
    ///
    /// `claimant_kyber_sk` is the Kyber secret key for content decapsulation.
    /// `claimant_signing_pk` is the SPHINCS+ public key embedded in the operation
    /// for state-machine signature verification.
    ///
    /// The caller (SDK) must sign the returned operation before submitting it
    /// to the state machine via `apply_transition()`.
    pub async fn claim_vault_content(
        &self,
        vault_id: &[u8; 32],
        claimant_kyber_sk: &[u8],
        claimant_signing_pk: &[u8],
        reference_state_hash: &[u8; 32],
    ) -> Result<(Vec<u8>, Operation), DsmError> {
        let vault_lock = self.get_vault(vault_id).await?;
        let mut vault = vault_lock.lock().await;
        let result = vault.claim(claimant_kyber_sk, reference_state_hash)?;

        let operation = Operation::DlvClaim {
            vault_id: vault_id.to_vec(),
            claim_proof: result.claim_proof.clone(),
            claimant_public_key: claimant_signing_pk.to_vec(),
            signature: vec![], // unsigned — caller must sign
            mode: TransactionMode::Unilateral,
        };

        Ok((result.content, operation))
    }

    /// Invalidate a vault and return an unsigned `Operation::DlvInvalidate`.
    ///
    /// The caller (SDK) must sign the returned operation before submitting it
    /// to the state machine via `apply_transition()`.
    pub async fn invalidate_vault(
        &self,
        vault_id: &[u8; 32],
        reason: &str,
        creator_signature: &[u8],
        reference_state_hash: &[u8; 32],
    ) -> Result<Operation, DsmError> {
        let vault_lock = self.get_vault(vault_id).await?;
        let mut vault = vault_lock.lock().await;

        // Get the creator_public_key before invalidation mutates the vault state
        let creator_pk = vault.creator_public_key.clone();

        vault.invalidate(reason, creator_signature, reference_state_hash)?;

        let operation = Operation::DlvInvalidate {
            vault_id: vault_id.to_vec(),
            reason: reason.to_string(),
            creator_public_key: creator_pk,
            signature: vec![], // unsigned — caller must sign
            mode: TransactionMode::Unilateral,
        };

        Ok(operation)
    }

    /// Add an existing vault to the manager
    pub async fn add_vault(&self, vault: LimboVault) -> Result<[u8; 32], DsmError> {
        let vault_id = vault.id;
        let mut vaults = self.vaults.write().await;
        vaults.insert(vault_id, Arc::new(tokio::sync::Mutex::new(vault)));
        Ok(vault_id)
    }

    /// Create a vault post (protobuf-encoded bytes; no bincode)
    pub async fn create_vault_post(
        &self,
        vault_id: &[u8; 32],
        purpose: &str,
        timeout: Option<u64>,
    ) -> Result<Vec<u8>, DsmError> {
        let vault_lock = self.get_vault(vault_id).await?;
        let vault = vault_lock.lock().await;

        // Convert domain VaultPost into canonical prost VaultPostProto and encode.
        let post = vault.to_vault_post(purpose, timeout)?;
        let post_pb: crate::types::proto::VaultPostProto = (&post).into();
        Ok(post_pb.encode_to_vec())
    }
}

impl Default for DLVManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Tier 2 Foundation accessors used by the chunks #7 routed-unlock gate.
///
/// The gate authenticates a trader's `RouteCommitHopV1.vault_state_anchor_seq`
/// and `vault_state_reserves_digest` against the LOCAL vault — storage anchors
/// are advertisement-and-discovery only, never the verification source.
impl LimboVault {
    /// Returns the canonical reserves digest for this vault if it
    /// uses an AMM constant-product fulfillment.  Returns `None` for
    /// other fulfillment kinds — Tier 2 Foundation is AMM-only.
    pub fn current_reserves_digest(&self) -> Option<[u8; 32]> {
        if let crate::vault::FulfillmentMechanism::AmmConstantProduct {
            token_a,
            token_b,
            reserve_a,
            reserve_b,
            fee_bps,
        } = &self.fulfillment_condition
        {
            Some(crate::dlv::vault_state_anchor::compute_reserves_digest(
                token_a, token_b, *reserve_a, *reserve_b, *fee_bps,
            ))
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::pedersen::{PedersenCommitment, PedersenParams, SecurityLevel};
    use crate::vault::limbo_vault::{EncryptedContent, VaultState as VS};

    fn vid(n: u8) -> [u8; 32] {
        let mut v = [0u8; 32];
        v[0] = n;
        v
    }

    fn dummy_vault(id: [u8; 32], state: VS) -> LimboVault {
        let params = PedersenParams::new(SecurityLevel::Standard128).expect("pedersen params");
        let commitment =
            PedersenCommitment::commit(b"test_content", &params).expect("pedersen commit");
        LimboVault {
            id,
            created_at_state: 0,
            creator_public_key: vec![0x01; 32],
            fulfillment_condition: FulfillmentMechanism::CryptoCondition {
                condition_hash: vec![0x02; 32],
                public_params: vec![0x03; 16],
            },
            intended_recipient: None,
            state,
            content_type: "application/octet-stream".into(),
            encrypted_content: EncryptedContent {
                encapsulated_key: vec![],
                encrypted_data: vec![],
                nonce: vec![],
                aad: vec![],
            },
            content_commitment: commitment,
            parameters_hash: vec![0xAA; 32],
            creator_signature: vec![0xBB; 64],
            verification_positions: vec![],
            reference_state_hash: [0xCC; 32],
            entry_header: None,
            current_sequence: 0,
            anchor_enforcement: 0,
        }
    }

    // ── Construction ────────────────────────────────────────────────

    #[test]
    fn dlv_manager_default() {
        let mgr = DLVManager::default();
        let dbg = format!("{:?}", mgr.vaults);
        assert!(dbg.contains("RwLock"));
    }

    // ── add_vault + get_vault ───────────────────────────────────────

    #[tokio::test]
    async fn add_and_get_vault() {
        let mgr = DLVManager::new();
        let id_in = vid(1);
        let vault = dummy_vault(id_in, VS::Limbo);

        let id = mgr.add_vault(vault).await.unwrap();
        assert_eq!(id, id_in);

        let lock = mgr.get_vault(&id_in).await.unwrap();
        let v = lock.lock().await;
        assert_eq!(v.id, id_in);
        assert_eq!(v.state, VS::Limbo);
    }

    #[tokio::test]
    async fn get_vault_not_found() {
        let mgr = DLVManager::new();
        let result = mgr.get_vault(&vid(0xFF)).await;
        assert!(result.is_err());
    }

    // ── list_vaults ─────────────────────────────────────────────────

    #[tokio::test]
    async fn list_vaults_empty() {
        let mgr = DLVManager::new();
        let ids = mgr.list_vaults().await.unwrap();
        assert!(ids.is_empty());
    }

    #[tokio::test]
    async fn list_vaults_after_adds() {
        let mgr = DLVManager::new();
        let v1 = vid(1);
        let v2 = vid(2);
        mgr.add_vault(dummy_vault(v1, VS::Limbo)).await.unwrap();
        mgr.add_vault(dummy_vault(v2, VS::Limbo)).await.unwrap();

        let ids = mgr.list_vaults().await.unwrap();
        assert_eq!(ids.len(), 2);
        assert!(ids.contains(&v1));
        assert!(ids.contains(&v2));
    }

    // ── get_vaults_by_status ────────────────────────────────────────

    #[tokio::test]
    async fn get_vaults_by_status_empty() {
        let mgr = DLVManager::new();
        let result = mgr.get_vaults_by_status(VS::Limbo).await.unwrap();
        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn get_vaults_by_status_filters() {
        let mgr = DLVManager::new();
        let limbo_1 = vid(1);
        let limbo_2 = vid(2);
        let active_1 = vid(3);
        mgr.add_vault(dummy_vault(limbo_1, VS::Limbo))
            .await
            .unwrap();
        mgr.add_vault(dummy_vault(limbo_2, VS::Limbo))
            .await
            .unwrap();
        mgr.add_vault(dummy_vault(active_1, VS::Active))
            .await
            .unwrap();

        let limbo = mgr.get_vaults_by_status(VS::Limbo).await.unwrap();
        assert_eq!(limbo.len(), 2);

        let active = mgr.get_vaults_by_status(VS::Active).await.unwrap();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0], active_1);
    }

    // ── add_vault overwrites existing ───────────────────────────────

    #[tokio::test]
    async fn add_vault_overwrites_same_id() {
        let mgr = DLVManager::new();
        let dup = vid(7);
        mgr.add_vault(dummy_vault(dup, VS::Limbo)).await.unwrap();
        mgr.add_vault(dummy_vault(dup, VS::Active)).await.unwrap();

        let ids = mgr.list_vaults().await.unwrap();
        assert_eq!(ids.len(), 1);

        let lock = mgr.get_vault(&dup).await.unwrap();
        let v = lock.lock().await;
        assert_eq!(v.state, VS::Active);
    }

    // ── concurrent access safety ────────────────────────────────────

    #[tokio::test]
    async fn concurrent_add_and_list() {
        let mgr = std::sync::Arc::new(DLVManager::new());
        let mut handles = Vec::new();

        for i in 0..10u8 {
            let mgr = mgr.clone();
            handles.push(tokio::spawn(async move {
                let vault = dummy_vault(vid(i), VS::Limbo);
                mgr.add_vault(vault).await.unwrap();
            }));
        }

        for h in handles {
            h.await.unwrap();
        }

        let ids = mgr.list_vaults().await.unwrap();
        assert_eq!(ids.len(), 10);
    }

    // ── Tier 2 Foundation accessors ────────────────────────────────

    /// Build a minimal AMM-fulfilment `LimboVault` directly on the stack
    /// for accessor tests. The chunks #7 gate consumes `current_sequence`
    /// and `current_reserves_digest()` directly off the vault — no
    /// `DLVManager` traversal needed for these unit tests.
    fn amm_vault(
        token_a: &[u8],
        token_b: &[u8],
        reserve_a: u128,
        reserve_b: u128,
        fee_bps: u32,
    ) -> LimboVault {
        let params = PedersenParams::new(SecurityLevel::Standard128).expect("pedersen params");
        let commitment =
            PedersenCommitment::commit(b"amm_vault", &params).expect("pedersen commit");
        LimboVault {
            id: vid(0xAA),
            created_at_state: 0,
            creator_public_key: vec![0x01; 32],
            fulfillment_condition: FulfillmentMechanism::AmmConstantProduct {
                token_a: token_a.to_vec(),
                token_b: token_b.to_vec(),
                reserve_a,
                reserve_b,
                fee_bps,
            },
            intended_recipient: None,
            state: VS::Limbo,
            content_type: "application/octet-stream".into(),
            encrypted_content: EncryptedContent {
                encapsulated_key: vec![],
                encrypted_data: vec![],
                nonce: vec![],
                aad: vec![],
            },
            content_commitment: commitment,
            parameters_hash: vec![0xAA; 32],
            creator_signature: vec![0xBB; 64],
            verification_positions: vec![],
            reference_state_hash: [0xCC; 32],
            entry_header: None,
            current_sequence: 0,
            anchor_enforcement: 0,
        }
    }

    #[tokio::test]
    async fn vault_current_sequence_starts_at_zero() {
        // Through DLVManager: construct, insert, fetch, observe seq=0.
        let mgr = DLVManager::new();
        let v = amm_vault(b"AAA", b"BBB", 1_000, 2_000, 30);
        let id = mgr.add_vault(v).await.unwrap();
        let lock = mgr.get_vault(&id).await.unwrap();
        let v = lock.lock().await;
        assert_eq!(v.current_sequence, 0);
    }

    #[tokio::test]
    async fn vault_current_reserves_digest_matches_amm_helper() {
        use crate::dlv::vault_state_anchor::compute_reserves_digest;
        let v = amm_vault(b"AAA", b"BBB", 1_000, 2_000, 30);
        assert_eq!(
            v.current_reserves_digest(),
            Some(compute_reserves_digest(b"AAA", b"BBB", 1_000, 2_000, 30)),
        );
    }

    #[tokio::test]
    async fn vault_current_reserves_digest_returns_none_for_non_amm() {
        // Non-AMM fulfilment (CryptoCondition) — Tier 2 Foundation is AMM-only.
        let v = dummy_vault(vid(1), VS::Limbo);
        assert_eq!(v.current_reserves_digest(), None);
    }
}
