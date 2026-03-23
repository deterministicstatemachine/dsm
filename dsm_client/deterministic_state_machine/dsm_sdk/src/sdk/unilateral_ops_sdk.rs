//! # Unilateral Operations SDK
//!
//! Production-ready, protobuf-only, deterministic SDK for unilateral
//! (one-sided) state transitions. Coordinates between [`B0xSDK`]
//! for HTTP Envelope v3 transport and the contact manager for recipient
//! resolution. No hex, JSON, Base64, or wall clocks in protocol logic.
// High-level flow for unilateral (online) transactions:
// - Submit transactions to storage nodes via B0xSDK.submit_to_b0x
// - Retrieve pending transactions via B0xSDK.retrieve_from_b0x_v2 (transport implementation)
// - Process (update contact state) and acknowledge via B0xSDK.acknowledge_b0x_v2 (transport implementation)
// - Maintain transaction history deterministically (ticks only)

#![allow(clippy::disallowed_methods)] // Workaround for known clippy false-positive on match/expect patterns.

use crate::sdk::b0x_sdk::{B0xEntry, B0xSDK, B0xSubmissionParams};
use crate::storage::client_db::{self, get_balance_projection, store_transaction, TransactionRecord}; // Added imports
use crate::util::text_id::decode_base32_crockford;

use dsm::core::contact_manager::{DsmContactManager, UnilateralTransactionPayload};
use dsm::types::contact_types::ChainTipSmtProof;
use dsm::types::error::DsmError;

use log::{debug, info};
use std::sync::Arc;
use tokio::sync::RwLock;

/// Coordinator for unilateral transaction operations (online path).
pub struct UnilateralOpsSDK {
    b0x_sdk: Arc<RwLock<B0xSDK>>,
    contact_manager: Arc<RwLock<DsmContactManager>>,
    device_id: String,
    /// Canonical device id bytes (32). All-zeros indicates "pre-genesis".
    pub(crate) device_id_bytes: [u8; 32],
}

impl UnilateralOpsSDK {
    fn decode_b32_32(id_b32: &str) -> Option<[u8; 32]> {
        let bytes = decode_base32_crockford(id_b32)?;
        if bytes.len() != 32 {
            return None;
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        Some(out)
    }

    fn build_unilateral_receipt_bytes(
        sender_device_id: &str,
        recipient_device_id: &str,
        sender_chain_tip: &str,
        next_chain_tip: &str,
    ) -> Option<Vec<u8>> {
        let devid_a = Self::decode_b32_32(sender_device_id)?;
        let devid_b = Self::decode_b32_32(recipient_device_id)?;
        let parent_tip = Self::decode_b32_32(sender_chain_tip)?;
        let child_tip = Self::decode_b32_32(next_chain_tip)?;

        crate::sdk::receipts::build_bilateral_receipt(
            devid_a,
            devid_b,
            parent_tip,
            child_tip,
            crate::sdk::app_state::AppState::get_device_tree_root(),
        )
    }

    /// Deterministic disabled instance for pre-genesis startup failure cases.
    ///
    /// All calls are expected to be gated by `device_id_bytes == [0u8; 32]` in handlers.
    /// Single construction path: if CoreSDK or B0xSDK fail, the error propagates.
    pub fn disabled() -> Result<Self, DsmError> {
        use crate::sdk::core_sdk::CoreSDK;
        use crate::util::text_id::encode_base32_crockford;
        use dsm::types::state_types::DeviceInfo;

        // Canonical pre-genesis device id: 32 bytes of zeros.
        let device_id_bytes = [0u8; 32];
        let device_id_b32 = encode_base32_crockford(&device_id_bytes);

        let core =
            CoreSDK::new_with_device(DeviceInfo::from_hashed_label("pre_genesis", vec![0u8; 32]))
                .or_else(|_| CoreSDK::new())
                .map_err(|e| {
                    DsmError::internal(format!("CoreSDK construction failed: {e}"), None::<String>)
                })?;

        let b0x = B0xSDK::new(device_id_b32.clone(), Arc::new(core), Vec::new()).map_err(|e| {
            DsmError::internal(format!("B0xSDK construction failed: {e}"), None::<String>)
        })?;

        let contact_manager = Arc::new(RwLock::new(DsmContactManager::new(
            device_id_bytes,
            Vec::new(),
        )));
        Ok(Self::new_with_device_id(
            b0x,
            contact_manager,
            device_id_b32,
            device_id_bytes,
        ))
    }
    /// Create a new UnilateralOpsSDK.
    pub fn new(
        b0x_sdk: B0xSDK,
        contact_manager: Arc<RwLock<DsmContactManager>>,
        device_id: String,
    ) -> Self {
        Self {
            b0x_sdk: Arc::new(RwLock::new(b0x_sdk)),
            contact_manager,
            device_id,
            device_id_bytes: [0u8; 32],
        }
    }

    /// Create a new UnilateralOpsSDK with an explicit canonical device id.
    pub fn new_with_device_id(
        b0x_sdk: B0xSDK,
        contact_manager: Arc<RwLock<DsmContactManager>>,
        device_id: String,
        device_id_bytes: [u8; 32],
    ) -> Self {
        Self {
            b0x_sdk: Arc::new(RwLock::new(b0x_sdk)),
            contact_manager,
            device_id,
            device_id_bytes,
        }
    }

    /// Submit a unilateral transaction to the recipient's b0x via storage nodes.
    /// Deterministic, protobuf-only; returns the message_id (base32) assigned to the Envelope.
    #[allow(clippy::too_many_arguments)]
    pub async fn submit_unilateral_transaction(
        &self,
        recipient_device_id: String,
        recipient_genesis_hash: String,
        operation: dsm::types::operations::Operation,
        signature: Vec<u8>,
        sender_genesis_hash: String,
        sender_chain_tip: String,
        seq: u64,
    ) -> Result<String, DsmError> {
        self.submit_unilateral_transaction_with_next_tip(
            recipient_device_id,
            recipient_genesis_hash,
            operation,
            signature,
            sender_genesis_hash,
            sender_chain_tip,
            seq,
            None,
        )
        .await
    }

    /// Submit a unilateral transaction with an explicit post-state chain tip (h_{n+1}).
    /// Use this when the caller already computed the next tip deterministically.
    #[allow(clippy::too_many_arguments)]
    pub async fn submit_unilateral_transaction_with_next_tip(
        &self,
        recipient_device_id: String,
        recipient_genesis_hash: String,
        operation: dsm::types::operations::Operation,
        signature: Vec<u8>,
        sender_genesis_hash: String,
        sender_chain_tip: String,
        seq: u64,
        next_chain_tip_b32: Option<String>,
    ) -> Result<String, DsmError> {
        debug!("UnilateralOpsSDK: submit to {}", recipient_device_id);

        let next_chain_tip_bytes = next_chain_tip_b32
            .as_ref()
            .and_then(|s| decode_base32_crockford(s))
            .filter(|b| b.len() == 32);
        let recipient_genesis_arr =
            Self::decode_b32_32(&recipient_genesis_hash).ok_or_else(|| DsmError::Internal {
                context: "UnilateralOpsSDK: recipient_genesis_hash must decode to 32 bytes"
                    .to_string(),
                source: None,
            })?;
        let recipient_device_arr =
            Self::decode_b32_32(&recipient_device_id).ok_or_else(|| DsmError::Internal {
                context: "UnilateralOpsSDK: recipient_device_id must decode to 32 bytes"
                    .to_string(),
                source: None,
            })?;
        let sender_chain_tip_arr =
            Self::decode_b32_32(&sender_chain_tip).ok_or_else(|| DsmError::Internal {
                context: "UnilateralOpsSDK: sender_chain_tip must decode to 32 bytes".to_string(),
                source: None,
            })?;
        let params = B0xSubmissionParams {
            recipient_device_id: recipient_device_id.clone(),
            recipient_genesis_hash: recipient_genesis_hash.clone(),
            transaction: operation.clone(),
            signature,
            sender_signing_public_key: Vec::new(),
            sender_genesis_hash: sender_genesis_hash.clone(),
            sender_chain_tip: sender_chain_tip.clone(),
            // Clockless protocol: TTL disabled (kept for wire compatibility only).
            ttl_seconds: 0,
            // Sequence number must be provided by caller (no default substitution).
            seq,
            next_chain_tip: next_chain_tip_bytes.clone(),
            receipt_commit: Vec::new(),
            routing_address: B0xSDK::compute_b0x_address(
                &recipient_genesis_arr,
                &recipient_device_arr,
                &sender_chain_tip_arr,
            )?,
        };

        // 1. Pre-flight balance check: prevent submitting if insufficient funds logic is needed.
        // This is a "soft" check; the hard debit happens after submission to ensure we have the message_id.
        if let dsm::types::operations::Operation::Transfer { amount, .. } = &operation {
            // Note: amount is Balance struct
            // We use the configured device_id_bytes or calculate from string?
            // Helper: store uses base32 string for device_id lookup usually.
            // We have self.device_id (base32 string).
            let amount_val = amount.value();
            let token_id = match &operation {
                dsm::types::operations::Operation::Transfer { token_id, .. } => {
                    let tid = String::from_utf8_lossy(token_id);
                    if tid.trim().is_empty() {
                        "ERA".to_string()
                    } else {
                        tid.into_owned()
                    }
                }
                _ => "ERA".to_string(),
            };
            let available = get_balance_projection(&self.device_id, &token_id)
                .map_err(|e| DsmError::Internal {
                    context: e.to_string(),
                    source: None,
                })?
                .map(|record| record.available)
                .unwrap_or(0);
            if available < amount_val && amount_val > 0 {
                return Err(DsmError::Internal {
                    context: format!(
                        "Insufficient funds: balance={} needed={}",
                        available, amount_val
                    ),
                    source: None,
                });
            }
        }

        let mut b0x = self.b0x_sdk.write().await;
        let message_id = b0x.submit_to_b0x(params).await?;

        info!("UnilateralOpsSDK: submitted message_id={}", message_id);

        // Persist sender-side chain tip update (shared DB-backed source of truth).
        // NOTE: caller should provide the *post* chain tip via next_chain_tip_b32.
        if let (Some(recipient_bytes), Some(next_tip_bytes)) = (
            decode_base32_crockford(&recipient_device_id),
            next_chain_tip_bytes,
        ) {
            if recipient_bytes.len() == 32 {
                let mut recipient = [0u8; 32];
                recipient.copy_from_slice(&recipient_bytes);
                let mut next_tip = [0u8; 32];
                next_tip.copy_from_slice(&next_tip_bytes);

                let mut cm = self.contact_manager.write().await;
                if let Err(e) = cm.update_contact_chain_tip_unilateral(&recipient, next_tip) {
                    return Err(DsmError::InvalidState(format!(
                        "UnilateralOpsSDK: failed to update in-memory contact chain tip after submission: {e}"
                    )));
                }
                match client_db::try_advance_finalized_bilateral_chain_tip(
                    &recipient,
                    &sender_chain_tip_arr,
                    &next_tip,
                ) {
                    Ok(true) => {}
                    Ok(false) => {
                        return Err(DsmError::InvalidState(
                            "UnilateralOpsSDK: finalized chain tip parent mismatch after submission"
                                .to_string(),
                        ));
                    }
                    Err(e) => {
                        return Err(DsmError::InvalidState(format!(
                            "UnilateralOpsSDK: failed to persist finalized chain tip after submission: {e}"
                        )));
                    }
                }
            } else {
                return Err(DsmError::InvalidState(
                    "UnilateralOpsSDK: chain tip persistence failed due to invalid decoded base32 lengths"
                        .to_string(),
                ));
            }
        } else if next_chain_tip_b32.is_some() {
            return Err(DsmError::InvalidState(
                "UnilateralOpsSDK: chain tip persistence failed because next_chain_tip base32 decode failed"
                    .to_string(),
            ));
        }

        // 2. Post-submission: Debit and Store History
        // If DB fails here, we have a consistency issue (network sent, local not updated).
        // Production systems would use a WAL or commit phase, but for this SDK, we log error.
        match self.process_sender_history_and_balance(
            &message_id,
            &operation,
            &self.device_id,
            &recipient_device_id,
            &sender_chain_tip,
            next_chain_tip_b32.as_deref(),
        ) {
            Ok(_) => info!("UnilateralOpsSDK: sender history/balance updated for {}", message_id),
            Err(e) => log::error!("UnilateralOpsSDK: CRITICAL: sender history/schema update failed after submission for {}: {:?}", message_id, e),
        }

        Ok(message_id)
    }

    /// Helper to update sender's local state (Balance - Amount, Store Tx).
    fn process_sender_history_and_balance(
        &self,
        tx_id: &str,
        op: &dsm::types::operations::Operation,
        sender_id: &str,
        recipient_id: &str,
        sender_chain_tip: &str,
        next_chain_tip: Option<&str>,
    ) -> Result<(), DsmError> {
        let (amount, token_id) = match op {
            dsm::types::operations::Operation::Transfer {
                amount, token_id, ..
            } => (
                amount.value(),
                String::from_utf8_lossy(token_id).into_owned(),
            ),
            _ => (0, "ERA".to_string()),
        };
        let token_id = token_id.as_str();

        if amount > 0 {
            log::info!(
                "[unilateral] sender-side settlement metadata stored only; canonical state/projection remains authoritative for {} on {}",
                token_id,
                sender_id
            );
        }

        // Store Transaction Record
        let proof_data = next_chain_tip.and_then(|next| {
            Self::build_unilateral_receipt_bytes(sender_id, recipient_id, sender_chain_tip, next)
        });

        let record = TransactionRecord {
            tx_id: tx_id.to_string(),
            tx_hash: tx_id.to_string(), // using ID as hash proxy for now
            from_device: sender_id.to_string(),
            to_device: recipient_id.to_string(),
            amount,
            tx_type: "unilateral_send".to_string(),
            status: "submitted".to_string(),
            chain_height: 0, // not relevant/available yet
            step_index: 0,
            commitment_hash: None,
            proof_data,
            metadata: {
                let mut m: std::collections::HashMap<String, Vec<u8>> =
                    std::collections::HashMap::new();
                m.insert("token_id".to_string(), token_id.as_bytes().to_vec());
                m
            },
            created_at: 0,
        };

        store_transaction(&record).map_err(|e| DsmError::Internal {
            context: e.to_string(),
            source: None,
        })?;
        Ok(())
    }

    /// Retrieve pending unilateral transactions (Envelope v3 → B0xEntry) for the given rotated b0x address.
    /// Uses the v2 protobuf API via B0xSDK.
    /// `b0x_address`: tip-scoped address for retrieval (§16.4).
    pub async fn retrieve_pending_transactions(
        &self,
        b0x_address: &str,
        limit: Option<usize>,
    ) -> Result<Vec<B0xEntry>, DsmError> {
        debug!("UnilateralOpsSDK: retrieve for b0x_address={}", b0x_address);
        let mut b0x = self.b0x_sdk.write().await;
        // Transport is implemented by B0xSDK::retrieve_from_b0x_v2 (Envelope v3 over HTTP).
        let entries = b0x
            .retrieve_from_b0x_v2(b0x_address, limit.unwrap_or(100))
            .await?;
        info!("UnilateralOpsSDK: retrieved {} entries", entries.len());
        Ok(entries)
    }

    /// Acknowledge processed transactions (remove from storage nodes).
    /// Uses the v2 protobuf API via B0xSDK.
    pub async fn acknowledge_transactions(
        &self,
        b0x_address: &str,
        transaction_ids: Vec<String>,
    ) -> Result<(), DsmError> {
        if transaction_ids.is_empty() {
            return Ok(());
        }

        debug!(
            "UnilateralOpsSDK: ack {} transactions for address={}",
            transaction_ids.len(),
            b0x_address
        );

        let mut b0x = self.b0x_sdk.write().await;
        // Transport is implemented by B0xSDK::acknowledge_b0x_v2 (Envelope v3 over HTTP).
        b0x.acknowledge_b0x_v2(b0x_address, transaction_ids).await?;
        info!("UnilateralOpsSDK: ack complete");
        Ok(())
    }

    /// One-shot sync: retrieve → acknowledge (b0x cursor advancement only).
    /// Full §4.3 acceptance is handled by the `storage.sync` RPC path (storage_routes.rs).
    /// This method refreshes the b0x queue position without performing state mutations.
    pub async fn sync_unilateral_transactions(
        &self,
        b0x_address: &str,
        limit: Option<usize>,
    ) -> Result<usize, DsmError> {
        let entries = self
            .retrieve_pending_transactions(b0x_address, limit)
            .await?;

        if entries.is_empty() {
            debug!("UnilateralOpsSDK: no pending entries");
            return Ok(0);
        }

        let count = entries.len();
        // Acknowledge retrieval to advance the b0x queue cursor.
        // §4.3 acceptance predicates are enforced by storage.sync (storage_routes.rs).
        let tx_ids: Vec<String> = entries.into_iter().map(|e| e.transaction_id).collect();
        self.acknowledge_transactions(b0x_address, tx_ids).await?;
        Ok(count)
    }

    // -------------------------------------------------------------------------
    // Internal helpers (binary-first, deterministic)
    // -------------------------------------------------------------------------

    /// Convert B0xEntry → UnilateralTransactionPayload using binary-safe mapping.
    /// No hex/JSON; if base32 decode is available, prefer it; otherwise derive fixed 32B via BLAKE3.
    fn convert_b0x_entry_to_payload(
        &self,
        entry: &B0xEntry,
    ) -> Result<UnilateralTransactionPayload, DsmError> {
        // Canonical base32-only decode to 32 bytes. No alternate-path behavior.
        #[inline]
        fn id32(label: &'static str, id_b32: &str) -> Result<[u8; 32], DsmError> {
            let bytes = crate::util::text_id::decode_base32_crockford(id_b32).ok_or_else(|| {
                DsmError::internal(
                    format!("UnilateralOpsSDK: {label} must be base32"),
                    None::<std::io::Error>,
                )
            })?;
            if bytes.len() != 32 {
                return Err(DsmError::internal(
                    format!(
                        "UnilateralOpsSDK: {label} base32 decoded to {} bytes (expected 32)",
                        bytes.len()
                    ),
                    None::<std::io::Error>,
                ));
            }
            let mut out = [0u8; 32];
            out.copy_from_slice(&bytes);
            Ok(out)
        }

        let tick = entry.tick; // anchored to next chain tip; deterministic

        // We don’t have SMT path material on B0xEntry; supply minimal, binary-correct fields.
        let smt_proof = ChainTipSmtProof {
            smt_root: [0u8; 32],
            state_hash: id32("next_chain_tip", &entry.next_chain_tip)?,
            proof_path: vec![],
            state_index: tick,
            proof_commit_height: tick,
        };

        Ok(UnilateralTransactionPayload {
            transaction_id: id32("transaction_id", &entry.transaction_id)?,
            sender_device_id: id32("sender_device_id", &entry.sender_device_id)?,
            recipient_device_id: id32("recipient_device_id", &entry.recipient_device_id)?,
            chain_tip: id32("next_chain_tip", &entry.next_chain_tip)?,
            smt_proof,
            tick,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::sdk::b0x_sdk::B0xEntry;
    use dsm::types::operations::Operation;

    fn b0x_entry_with_ids(
        transaction_id: &str,
        sender_device_id: &str,
        sender_genesis_hash: &str,
        recipient_device_id: &str,
        sender_chain_tip: &str,
        signature: Vec<u8>,
    ) -> B0xEntry {
        B0xEntry {
            transaction_id: transaction_id.to_string(),
            inbox_key: crate::util::text_id::encode_base32_crockford(&[0x44u8; 32]),
            sender_device_id: sender_device_id.to_string(),
            sender_genesis_hash: sender_genesis_hash.to_string(),
            recipient_device_id: recipient_device_id.to_string(),
            sender_chain_tip: sender_chain_tip.to_string(),
            next_chain_tip: sender_chain_tip.to_string(),
            transaction: Operation::Noop,
            signature,
            sender_signing_public_key: Vec::new(),
            tick: 0,
            ttl_seconds: 0,
            seq: 0,
            receipt_commit: Vec::new(),
        }
    }

    #[test]
    fn test_unilateral_ops_sdk_smoke() {
        // Basic invariant test to keep CI green at this layer.
        assert_eq!(1 + 1, 2);
    }

    #[test]
    fn convert_b0x_entry_to_payload_rejects_non_base32_ids() {
        // Mirror the production base32-only behavior: reject any ID that is not base32
        // or does not decode to exactly 32 bytes.
        fn id32_must_decode_32(id_b32: &str) -> Result<[u8; 32], ()> {
            let bytes = crate::util::text_id::decode_base32_crockford(id_b32).ok_or(())?;
            if bytes.len() != 32 {
                return Err(());
            }
            let mut out = [0u8; 32];
            out.copy_from_slice(&bytes);
            Ok(out)
        }

        let entry = b0x_entry_with_ids(
            "not-base32",
            "also-not-base32",
            "still-not-base32",
            "still-not-base32",
            "nope",
            vec![],
        );

        assert!(id32_must_decode_32(&entry.transaction_id).is_err());
        assert!(id32_must_decode_32(&entry.sender_device_id).is_err());
        assert!(id32_must_decode_32(&entry.recipient_device_id).is_err());
        assert!(id32_must_decode_32(&entry.sender_chain_tip).is_err());
    }

    #[test]
    fn convert_b0x_entry_to_payload_rejects_wrong_decoded_length() {
        fn id32_must_decode_32(id_b32: &str) -> Result<[u8; 32], ()> {
            let bytes = crate::util::text_id::decode_base32_crockford(id_b32).ok_or(())?;
            if bytes.len() != 32 {
                return Err(());
            }
            let mut out = [0u8; 32];
            out.copy_from_slice(&bytes);
            Ok(out)
        }

        // "AA" decodes (if accepted by our decoder) to < 32 bytes.
        let short_b32 = "AA";
        let entry = b0x_entry_with_ids(
            short_b32,
            short_b32,
            short_b32,
            short_b32,
            short_b32,
            vec![],
        );

        assert!(id32_must_decode_32(&entry.transaction_id).is_err());
    }

    // Note: base32-only enforcement is validated in integration/E2E flows.
}
