// SPDX-License-Identifier: MIT OR Apache-2.0

//! DLV Manager Module
//!
//! Manages Deterministic Limbo Vaults (DLVs) in a thread-safe manner.
//! Each lifecycle method returns an unsigned `Operation` that the SDK layer
//! must sign with SPHINCS+ before submitting to the state machine.
//! NOTE: No bincode/serde. `create_vault_post` encodes with `prost`.

use super::{FulfillmentMechanism, FulfillmentProof, LimboVault, VaultState};
use crate::types::operations::{Operation, TransactionMode};
use crate::types::token_types::Balance;
use crate::types::{error::DsmError, state_types::State};
use prost::Message; // for encode_to_vec()
use std::{collections::HashMap, sync::Arc};

/// Manages Limbo Vaults
pub struct DLVManager {
    /// Vaults managed by this instance, keyed by vault ID
    vaults: tokio::sync::RwLock<HashMap<String, Arc<tokio::sync::Mutex<LimboVault>>>>,
}

impl DLVManager {
    /// Create a new DLV manager
    pub fn new() -> Self {
        Self {
            vaults: tokio::sync::RwLock::new(HashMap::new()),
        }
    }

    /// Create a new vault and return the vault ID with an unsigned `Operation::DlvCreate`.
    ///
    /// The caller (SDK) must sign the returned operation before submitting it
    /// to the state machine via `apply_transition()`.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_vault(
        &self,
        creator_keypair: (&[u8], &[u8]),
        condition: FulfillmentMechanism,
        content: &[u8],
        content_type: &str,
        intended_recipient: Option<Vec<u8>>,
        encryption_public_key: &[u8],
        reference_state: &State,
        token_id: Option<&str>,
        locked_amount: Option<u64>,
    ) -> Result<(String, Operation), DsmError> {
        let vault = LimboVault::new(
            creator_keypair,
            condition.clone(),
            content,
            content_type,
            intended_recipient.clone(),
            encryption_public_key,
            reference_state,
        )?;

        let vault_id = vault.id.clone();

        // Serialize the fulfillment condition via proto for the operation
        let fm_proto: crate::types::proto::FulfillmentMechanism = (&condition).into();
        let fulfillment_bytes = fm_proto.encode_to_vec();

        // Build the unsigned DlvCreate operation
        let locked_balance = locked_amount.map(|amt| {
            Balance::from_state(amt, reference_state.hash, reference_state.state_number)
        });

        let operation = Operation::DlvCreate {
            vault_id: vault_id.as_bytes().to_vec(),
            creator_public_key: vault.creator_public_key.clone(),
            parameters_hash: vault.parameters_hash.clone(),
            fulfillment_condition: fulfillment_bytes,
            intended_recipient: intended_recipient.clone(),
            token_id: token_id.map(|s| s.as_bytes().to_vec()),
            locked_amount: locked_balance,
            signature: vec![], // unsigned — caller must sign
            mode: TransactionMode::Unilateral,
        };

        // Store the vault
        let mut vaults = self.vaults.write().await;
        vaults.insert(vault_id.clone(), Arc::new(tokio::sync::Mutex::new(vault)));

        Ok((vault_id, operation))
    }

    /// Get a vault by ID
    pub async fn get_vault(
        &self,
        vault_id: &str,
    ) -> Result<Arc<tokio::sync::Mutex<LimboVault>>, DsmError> {
        let vaults = self.vaults.read().await;
        vaults.get(vault_id).cloned().ok_or_else(|| {
            DsmError::not_found("Vault", Some(format!("Vault with ID {vault_id} not found")))
        })
    }

    /// List all vault IDs
    pub async fn list_vaults(&self) -> Result<Vec<String>, DsmError> {
        let vaults = self.vaults.read().await;
        Ok(vaults.keys().cloned().collect())
    }

    /// Get vaults by status
    pub async fn get_vaults_by_status(&self, status: VaultState) -> Result<Vec<String>, DsmError> {
        // Avoid holding the RwLock guard across async awaits on individual vault mutexes.
        // Clone the handles first, then release the map read guard before locking each vault.
        let vaults = self.vaults.read().await;
        let handles: Vec<(String, Arc<tokio::sync::Mutex<LimboVault>>)> = vaults
            .iter()
            .map(|(id, v)| (id.clone(), v.clone()))
            .collect();
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
        vault_id: &str,
        proof: FulfillmentProof,
        requester: &[u8],
        signing_public_key: &[u8],
        reference_state: &State,
    ) -> Result<(bool, Operation), DsmError> {
        let vault_lock = self.get_vault(vault_id).await?;
        let mut vault = vault_lock.lock().await;

        let proof_bytes = proof.to_bytes();
        let unlocked = vault.unlock(proof, requester, reference_state)?;

        let operation = Operation::DlvUnlock {
            vault_id: vault_id.as_bytes().to_vec(),
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
        vault_id: &str,
        proof: FulfillmentProof,
        requester: &[u8],
        reference_state: &State,
    ) -> Result<bool, DsmError> {
        let vault_lock = self.get_vault(vault_id).await?;
        let mut vault = vault_lock.lock().await;
        vault.activate(&proof, requester, reference_state)
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
        vault_id: &str,
        claimant_kyber_sk: &[u8],
        claimant_signing_pk: &[u8],
        reference_state: &State,
    ) -> Result<(Vec<u8>, Operation), DsmError> {
        let vault_lock = self.get_vault(vault_id).await?;
        let mut vault = vault_lock.lock().await;
        let result = vault.claim(claimant_kyber_sk, reference_state)?;

        let operation = Operation::DlvClaim {
            vault_id: vault_id.as_bytes().to_vec(),
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
        vault_id: &str,
        reason: &str,
        creator_signature: &[u8],
        reference_state: &State,
    ) -> Result<Operation, DsmError> {
        let vault_lock = self.get_vault(vault_id).await?;
        let mut vault = vault_lock.lock().await;

        // Get the creator_public_key before invalidation mutates the vault state
        let creator_pk = vault.creator_public_key.clone();

        vault.invalidate(reason, creator_signature, reference_state)?;

        let operation = Operation::DlvInvalidate {
            vault_id: vault_id.as_bytes().to_vec(),
            reason: reason.to_string(),
            creator_public_key: creator_pk,
            signature: vec![], // unsigned — caller must sign
            mode: TransactionMode::Unilateral,
        };

        Ok(operation)
    }

    /// Add an existing vault to the manager
    pub async fn add_vault(&self, vault: LimboVault) -> Result<String, DsmError> {
        let vault_id = vault.id.clone();
        let mut vaults = self.vaults.write().await;
        vaults.insert(vault_id.clone(), Arc::new(tokio::sync::Mutex::new(vault)));
        Ok(vault_id)
    }

    /// Create a vault post (protobuf-encoded bytes; no bincode)
    pub async fn create_vault_post(
        &self,
        vault_id: &str,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::pedersen::{PedersenCommitment, PedersenParams, SecurityLevel};
    use crate::vault::limbo_vault::{EncryptedContent, VaultState as VS};

    fn dummy_vault(id: &str, state: VS) -> LimboVault {
        let params = PedersenParams::new(SecurityLevel::Standard128).expect("pedersen params");
        let commitment =
            PedersenCommitment::commit(b"test_content", &params).expect("pedersen commit");
        LimboVault {
            id: id.to_string(),
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
        let vault = dummy_vault("vault_1", VS::Limbo);

        let id = mgr.add_vault(vault).await.unwrap();
        assert_eq!(id, "vault_1");

        let lock = mgr.get_vault("vault_1").await.unwrap();
        let v = lock.lock().await;
        assert_eq!(v.id, "vault_1");
        assert_eq!(v.state, VS::Limbo);
    }

    #[tokio::test]
    async fn get_vault_not_found() {
        let mgr = DLVManager::new();
        let result = mgr.get_vault("nonexistent").await;
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
        mgr.add_vault(dummy_vault("v1", VS::Limbo)).await.unwrap();
        mgr.add_vault(dummy_vault("v2", VS::Limbo)).await.unwrap();

        let mut ids = mgr.list_vaults().await.unwrap();
        ids.sort();
        assert_eq!(ids.len(), 2);
        assert!(ids.contains(&"v1".to_string()));
        assert!(ids.contains(&"v2".to_string()));
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
        mgr.add_vault(dummy_vault("limbo_1", VS::Limbo))
            .await
            .unwrap();
        mgr.add_vault(dummy_vault("limbo_2", VS::Limbo))
            .await
            .unwrap();
        mgr.add_vault(dummy_vault(
            "active_1",
            VS::Active {
                activated_state_number: 10,
            },
        ))
        .await
        .unwrap();

        let limbo = mgr.get_vaults_by_status(VS::Limbo).await.unwrap();
        assert_eq!(limbo.len(), 2);

        let active = mgr
            .get_vaults_by_status(VS::Active {
                activated_state_number: 10,
            })
            .await
            .unwrap();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0], "active_1");
    }

    // ── add_vault overwrites existing ───────────────────────────────

    #[tokio::test]
    async fn add_vault_overwrites_same_id() {
        let mgr = DLVManager::new();
        mgr.add_vault(dummy_vault("dup", VS::Limbo)).await.unwrap();
        mgr.add_vault(dummy_vault(
            "dup",
            VS::Active {
                activated_state_number: 5,
            },
        ))
        .await
        .unwrap();

        let ids = mgr.list_vaults().await.unwrap();
        assert_eq!(ids.len(), 1);

        let lock = mgr.get_vault("dup").await.unwrap();
        let v = lock.lock().await;
        assert_eq!(
            v.state,
            VS::Active {
                activated_state_number: 5
            }
        );
    }

    // ── concurrent access safety ────────────────────────────────────

    #[tokio::test]
    async fn concurrent_add_and_list() {
        let mgr = std::sync::Arc::new(DLVManager::new());
        let mut handles = Vec::new();

        for i in 0..10 {
            let mgr = mgr.clone();
            handles.push(tokio::spawn(async move {
                let vault = dummy_vault(&format!("v_{i}"), VS::Limbo);
                mgr.add_vault(vault).await.unwrap();
            }));
        }

        for h in handles {
            h.await.unwrap();
        }

        let ids = mgr.list_vaults().await.unwrap();
        assert_eq!(ids.len(), 10);
    }
}
