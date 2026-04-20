// SPDX-License-Identifier: MIT OR Apache-2.0
//! Storage route handlers for AppRouterImpl.
//!
//! Handles `storage.status` and `storage.sync` query paths.

use dsm::types::proto as generated;
use dsm::types::identifiers::TransactionId;
use prost::Message;
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::bridge::{AppQuery, AppResult};
use super::app_router_impl::AppRouterImpl;
use super::response_helpers::{pack_envelope_ok, err};
use super::transfer_helpers::build_online_receipt_with_smt;
use super::app_router_impl::{
    collect_tagged_inbox_addresses, ensure_inbox_recipient_targets_local, InboxBatchState,
    RouteFreshness,
};
#[cfg(feature = "dev-discovery")]
use crate::sdk::network_detection::get_network_gate;

fn decode_canonical_b32_32(label: &str, value: &str) -> Result<[u8; 32], String> {
    let bytes = crate::util::text_id::decode_base32_crockford(value)
        .ok_or_else(|| format!("{label} is not valid base32"))?;
    if bytes.len() != 32 {
        return Err(format!(
            "{label} must decode to exactly 32 bytes, got {}",
            bytes.len()
        ));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

// Prefer the receiver-local archival receipt when we can build it, but never
// leave the UI empty if the incoming receipt was already cryptographically verified.
fn select_history_receipt_bytes(
    rebuilt_receipt: Option<Vec<u8>>,
    verified_receipt_commit: &[u8],
) -> Option<Vec<u8>> {
    rebuilt_receipt.or_else(|| {
        if verified_receipt_commit.is_empty() {
            None
        } else {
            Some(verified_receipt_commit.to_vec())
        }
    })
}

#[cfg(all(target_os = "android", feature = "jni"))]
fn emit_authoritative_wallet_refresh() {
    if let Err(e) = crate::jni::event_dispatch::post_event_to_webview("dsm-wallet-refresh", &[]) {
        log::debug!("[storage.sync] wallet refresh dispatch skipped: {e}");
    }
}

#[cfg(not(all(target_os = "android", feature = "jni")))]
fn emit_authoritative_wallet_refresh() {}

fn mark_contact_needs_online_reconcile_and_refresh(device_id: &[u8]) {
    match crate::storage::client_db::mark_contact_needs_online_reconcile(device_id) {
        Ok(()) => emit_authoritative_wallet_refresh(),
        Err(e) => {
            log::warn!(
                "[storage.sync] failed to mark relationship blocked for {} bytes of device id: {}",
                device_id.len(),
                e
            );
        }
    }
}

fn record_observed_remote_tip_and_refresh(device_id: &[u8], observed_tip: &[u8; 32]) {
    match crate::storage::client_db::record_observed_remote_chain_tip(
        device_id,
        observed_tip,
        crate::storage::client_db::ObservedRemoteTipSource::DeferredInbox,
    ) {
        Ok(()) => emit_authoritative_wallet_refresh(),
        Err(e) => {
            log::warn!(
                "[storage.sync] failed to record observed remote relationship tip for {} bytes of device id: {}",
                device_id.len(),
                e
            );
        }
    }
}

impl AppRouterImpl {
    pub(crate) async fn run_storage_sync_request(
        &self,
        req: generated::StorageSyncRequest,
    ) -> Result<generated::StorageSyncResponse, String> {
        let pack = generated::ArgPack {
            codec: generated::Codec::Proto as i32,
            body: req.encode_to_vec(),
            ..Default::default()
        };

        let result = self
            .handle_storage_query(AppQuery {
                path: "storage.sync".to_string(),
                params: pack.encode_to_vec(),
            })
            .await;

        if !result.success {
            return Err(result
                .error_message
                .unwrap_or_else(|| "storage.sync failed".to_string()));
        }

        let payload = result
            .data
            .strip_prefix(&[0x03])
            .ok_or_else(|| "storage.sync missing envelope v3 framing".to_string())?;
        let env = generated::Envelope::decode(payload)
            .map_err(|e| format!("storage.sync envelope decode failed: {e}"))?;
        match env.payload {
            Some(generated::envelope::Payload::StorageSyncResponse(resp)) => Ok(resp),
            Some(generated::envelope::Payload::Error(err_payload)) => Err(err_payload.message),
            _ => Err("storage.sync returned unexpected payload".to_string()),
        }
    }

    /// Dispatch handler for `storage.status` and `storage.sync` query routes.
    pub(crate) async fn handle_storage_query(&self, q: AppQuery) -> AppResult {
        match q.path.as_str() {
            "storage.status" => {
                log::info!("[DSM_SDK] storage.status called");

                // Decode request (optional, but good for validation)
                if let Ok(pack) = generated::ArgPack::decode(&*q.params) {
                    if pack.codec == generated::Codec::Proto as i32 {
                        let _ = generated::StorageStatusRequest::decode(&*pack.body);
                    }
                }

                let endpoints = self._config.storage_endpoints.clone();
                let total_nodes = endpoints.len() as u32;

                // Real connectivity check — probe /api/v2/health on each node concurrently
                let client = crate::sdk::storage_node_sdk::build_ca_aware_client();
                let mut connected_nodes = 0u32;
                let mut handles = Vec::new();
                for ep in &endpoints {
                    let c = client.clone();
                    let url = format!("{ep}/api/v2/health");
                    handles.push(tokio::spawn(async move {
                        matches!(tokio::time::timeout(
                            std::time::Duration::from_secs(5),
                            c.get(&url).send(),
                        ).await, Ok(Ok(resp)) if resp.status().is_success())
                    }));
                }
                for handle in handles {
                    if let Ok(true) = handle.await {
                        connected_nodes += 1;
                    }
                }

                // Get DB size
                let data_size = match crate::storage::client_db::get_db_size() {
                    Ok(size) => {
                        if size > 1024 * 1024 {
                            format!("{:.1} MB", size as f64 / (1024.0 * 1024.0))
                        } else {
                            format!("{:.1} KB", size as f64 / 1024.0)
                        }
                    }
                    Err(_) => "Unknown".to_string(),
                };

                // Real sync counter from transaction history
                let last_sync_iter =
                    crate::storage::client_db::get_transaction_count().unwrap_or(0);

                // Real backup status from NFC recovery SDK
                let backup_status = {
                    let rs = crate::sdk::recovery_sdk::RecoverySDK::get_recovery_status();
                    if !rs.enabled {
                        "Not configured".to_string()
                    } else if rs.pending_capsule {
                        format!("Armed (capsule #{})", rs.last_capsule_index)
                    } else if rs.capsule_count > 0 {
                        format!(
                            "Written (#{}, {} total)",
                            rs.last_capsule_index, rs.capsule_count
                        )
                    } else {
                        "Enabled (no capsule)".to_string()
                    }
                };

                let resp = generated::StorageStatusResponse {
                    total_nodes,
                    connected_nodes,
                    last_sync_iter,
                    data_size,
                    backup_status,
                };
                // NEW: Return as Envelope.storageStatusResponse (field 47)
                pack_envelope_ok(generated::envelope::Payload::StorageStatusResponse(resp))
            }

            // -------- storage.sync (QueryOp) --------
            "storage.sync" => {
                log::info!("[DSM_SDK] storage.sync called");

                // Check network connectivity before attempting sync
                #[cfg(feature = "dev-discovery")]
                let network_gate = get_network_gate();
                #[cfg(feature = "dev-discovery")]
                if network_gate.should_disable_network_features() {
                    log::warn!("[DSM_SDK] storage.sync: Network features disabled due to repeated failures");
                    return err("Network connectivity disabled due to repeated failures. Please restart the app.".into());
                }

                // Decode StorageSyncRequest
                let (pull_inbox, push_pending, limit) = match generated::ArgPack::decode(&*q.params)
                {
                    Ok(pack) if pack.codec == generated::Codec::Proto as i32 => {
                        match generated::StorageSyncRequest::decode(&*pack.body) {
                            Ok(req) => (
                                req.pull_inbox,
                                req.push_pending,
                                req.limit.clamp(1, 200) as usize,
                            ),
                            Err(_) => (true, true, 100), // default: do everything
                        }
                    }
                    _ => (true, true, 100), // default
                };

                let mut pulled = 0u32;
                let mut processed = 0u32;
                #[allow(unused_mut)]
                let mut pushed = 0u32;
                let mut errors: Vec<String> = Vec::new();

                // Get storage endpoints
                let storage_endpoints =
                    match crate::sdk::storage_node_sdk::StorageNodeConfig::from_env_config().await {
                        Ok(cfg) => cfg.node_urls,
                        Err(e) => {
                            let resp = generated::StorageSyncResponse {
                                success: false,
                                pulled: 0,
                                processed: 0,
                                pushed: 0,
                                errors: vec![format!("No storage node config available: {}", e)],
                            };
                            // NEW: Return as Envelope.storageSyncResponse (field 35)
                            return pack_envelope_ok(
                                generated::envelope::Payload::StorageSyncResponse(resp),
                            );
                        }
                    };
                if storage_endpoints.is_empty() {
                    let resp = generated::StorageSyncResponse {
                        success: false,
                        pulled: 0,
                        processed: 0,
                        pushed: 0,
                        errors: vec!["No storage endpoints configured".to_string()],
                    };
                    // NEW: Return as Envelope.storageSyncResponse (field 35)
                    return pack_envelope_ok(generated::envelope::Payload::StorageSyncResponse(
                        resp,
                    ));
                }

                let device_id_b32 =
                    crate::util::text_id::encode_base32_crockford(&self.device_id_bytes);
                // Canonical textual device id for auth/storage keys is base32(32 bytes).
                // (Older code used dotted-decimal in some paths; never use that for auth.)
                log::info!(
                    "[DSM_SDK] storage.sync device_id: prefix={}..., len={}, base32_32={}",
                    &device_id_b32[..8.min(device_id_b32.len())],
                    device_id_b32.len(),
                    crate::util::text_id::decode_base32_crockford(&device_id_b32)
                        .map(|b| b.len() == 32)
                        .unwrap_or(false)
                );

                // Pull from inbox if requested
                if pull_inbox {
                    match crate::sdk::b0x_sdk::B0xSDK::new(
                        device_id_b32.clone(),
                        self.core_sdk.clone(),
                        storage_endpoints.clone(),
                    ) {
                        Ok(mut b0x_sdk) => {
                            // Proactively register this device on all storage endpoints to ensure valid tokens
                            // before attempting any inbox retrieval. This avoids 401/InboxTokenInvalid cases
                            // when storage nodes have been reset or tokens have expired.
                            let reg_res = if let Ok(handle) = tokio::runtime::Handle::try_current()
                            {
                                tokio::task::block_in_place(|| {
                                    handle.block_on(b0x_sdk.register_device())
                                })
                            } else if let Ok(rt) = tokio::runtime::Runtime::new() {
                                rt.block_on(b0x_sdk.register_device())
                            } else {
                                Err(dsm::types::error::DsmError::internal(
                                    "runtime failed",
                                    None::<std::io::Error>,
                                ))
                            };
                            match reg_res {
                                Ok(_) => log::info!("[DSM_SDK] storage.sync: device registration succeeded on storage endpoints"),
                                Err(e) => log::warn!("[DSM_SDK] storage.sync: device registration failed (continuing): {}", e),
                            }

                            // §16.4: Compute per-contact rotated b0x addresses for inbox polling.
                            // Each contact uses a tip-scoped routing key derived from
                            // domain-separated genesis/device/tip components.
                            let my_genesis = match self.core_sdk.local_genesis_hash().await {
                                Ok(genesis) if genesis.len() == 32 => {
                                    let mut arr = [0u8; 32];
                                    arr.copy_from_slice(&genesis);
                                    arr
                                }
                                Ok(genesis) => {
                                    let resp = generated::StorageSyncResponse {
                                        success: false,
                                        pulled: 0,
                                        processed: 0,
                                        pushed: 0,
                                        errors: vec![format!(
                                            "storage.sync: local genesis must be 32 bytes, got {}",
                                            genesis.len()
                                        )],
                                    };
                                    return pack_envelope_ok(
                                        generated::envelope::Payload::StorageSyncResponse(resp),
                                    );
                                }
                                Err(e) => {
                                    let resp = generated::StorageSyncResponse {
                                        success: false,
                                        pulled: 0,
                                        processed: 0,
                                        pushed: 0,
                                        errors: vec![format!(
                                            "storage.sync: missing local genesis for rotated inbox routing: {e}"
                                        )],
                                    };
                                    return pack_envelope_ok(
                                        generated::envelope::Payload::StorageSyncResponse(resp),
                                    );
                                }
                            };

                            let contacts =
                                crate::storage::client_db::get_all_contacts().unwrap_or_default();
                            // §5.2: Use tagged addresses to distinguish current vs stale-route items.
                            let tagged_addresses = collect_tagged_inbox_addresses(
                                my_genesis,
                                self.device_id_bytes,
                                &contacts,
                            );

                            let mut all_items = Vec::new();
                            for tagged_addr in tagged_addresses {
                                if all_items.len() >= limit {
                                    break;
                                }
                                let remaining = limit - all_items.len();

                                log::info!(
                                    "[storage.sync] polling addr={}.. freshness={:?}",
                                    &tagged_addr.address[..16.min(tagged_addr.address.len())],
                                    tagged_addr.freshness,
                                );
                                let entries_res =
                                    match tokio::runtime::Handle::try_current() {
                                        Ok(handle) => tokio::task::block_in_place(|| {
                                            handle.block_on(b0x_sdk.retrieve_from_b0x_v2(
                                                &tagged_addr.address,
                                                remaining,
                                            ))
                                        }),
                                        Err(_) => {
                                            if let Ok(rt) = tokio::runtime::Runtime::new() {
                                                rt.block_on(b0x_sdk.retrieve_from_b0x_v2(
                                                    &tagged_addr.address,
                                                    remaining,
                                                ))
                                            } else {
                                                Err(dsm::types::error::DsmError::internal(
                                                    "runtime failed",
                                                    None::<std::io::Error>,
                                                ))
                                            }
                                        }
                                    };
                                match entries_res {
                                    Ok(items) => {
                                        // §5.2: Items from PreviousTip addresses that are non-adjacent
                                        // must NOT enter the mutating apply pipeline. Filter them here
                                        // so Tripwire is defense-in-depth, not the primary gate.
                                        if tagged_addr.freshness == RouteFreshness::PreviousTip {
                                            for item in items {
                                                let chain_tip_opt =
                                                    crate::util::text_id::decode_base32_crockford(
                                                        &item.sender_chain_tip,
                                                    );
                                                let from_device_opt =
                                                    crate::util::text_id::decode_base32_crockford(
                                                        &item.sender_device_id,
                                                    );
                                                let is_adjacent = match (
                                                    chain_tip_opt,
                                                    from_device_opt,
                                                ) {
                                                    (Some(ct), Some(fd))
                                                        if ct.len() == 32 && fd.len() >= 32 =>
                                                    {
                                                        let mut chain_tip_arr = [0u8; 32];
                                                        chain_tip_arr.copy_from_slice(&ct);
                                                        match crate::storage::client_db::get_contact_chain_tip_raw(
                                                            &fd[..32],
                                                        ) {
                                                            Some(stored) if stored != [0u8; 32] => stored == chain_tip_arr,
                                                            _ => true, // No stored tip or zero tip — allow
                                                        }
                                                    }
                                                    _ => true, // Decode failure — let apply pipeline handle it
                                                };
                                                if is_adjacent {
                                                    all_items.push(item);
                                                } else {
                                                    log::info!(
                                                        "[storage.sync] §5.2: stale-route item {} skipped pre-apply (non-adjacent, from previous-tip address)",
                                                        item.transaction_id,
                                                    );
                                                }
                                            }
                                        } else {
                                            all_items.extend(items);
                                        }
                                    }
                                    Err(e) => {
                                        // Record network failure for connectivity monitoring
                                        #[cfg(feature = "dev-discovery")]
                                        network_gate.record_network_failure();

                                        // Use centralized mapping for inbox errors so all code paths
                                        // produce consistent, actionable messages.
                                        let formatted = self.format_inbox_error(&e);
                                        log::warn!("[storage.sync] Error encountered: {:?} -> Formatted: {}", e, formatted);
                                        errors.push(format!("inbox pull failed: {}", formatted));
                                    }
                                }
                            }

                            if !all_items.is_empty() {
                                let items = all_items;
                                pulled = items.len() as u32;
                                let batch_state = Arc::new(Mutex::new(InboxBatchState::default()));
                                let core_sdk = self.core_sdk.clone();
                                let device_id_bytes = self.device_id_bytes;

                                for entry in items.iter().cloned() {
                                    {
                                        let state_guard = batch_state.lock().await;
                                        if state_guard.fatal_error.is_some() {
                                            break;
                                        }
                                    }

                                    if let dsm::types::operations::Operation::Transfer {
                                        amount,
                                        token_id: _token_id,
                                        nonce: _nonce,
                                        ..
                                    } = &entry.transaction
                                    {
                                        let amount_val = amount.value();
                                        if amount_val == 0 {
                                            log::warn!(
                                                "[storage.sync] Skipping zero-amount transfer"
                                            );
                                            continue;
                                        }

                                        // ============= AF-2 FIX: Canonical Transfer Signature Verification =============
                                        // Extract transfer details from the Operation
                                        let (to_device_id, amount_val, token_id, nonce, memo) =
                                            match &entry.transaction {
                                                dsm::types::operations::Operation::Transfer {
                                                    to_device_id,
                                                    amount,
                                                    token_id,
                                                    nonce,
                                                    message,
                                                    ..
                                                } => (
                                                    to_device_id.clone(),
                                                    amount.value(),
                                                    token_id.clone(),
                                                    nonce.clone(),
                                                    message.clone(),
                                                ),
                                                _ => {
                                                    log::warn!("[storage.sync] Skipping non-transfer operation");
                                                    continue;
                                                }
                                            };

                                        // Guardrail: ensure this inbox item is actually targeted to the local device.
                                        if let Err(msg) = ensure_inbox_recipient_targets_local(
                                            &entry.recipient_device_id,
                                            &to_device_id,
                                            &device_id_bytes,
                                        ) {
                                            log::warn!(
                                                "[storage.sync] Skipping tx {}: {}",
                                                entry.transaction_id,
                                                msg
                                            );
                                            let mut state_guard = batch_state.lock().await;
                                            state_guard.errors.push(format!(
                                                "inbox.pull: recipient mismatch for {}: {}",
                                                entry.transaction_id, msg
                                            ));
                                            continue;
                                        }

                                        // Get signing context from envelope (sender identity + relationship state)
                                        let from_device_id = match decode_canonical_b32_32(
                                            "sender_device_id",
                                            &entry.sender_device_id,
                                        ) {
                                            Ok(value) => value,
                                            Err(msg) => {
                                                log::warn!(
                                                    "[storage.sync] Skipping tx {}: {}",
                                                    entry.transaction_id,
                                                    msg
                                                );
                                                let mut state_guard = batch_state.lock().await;
                                                state_guard.errors.push(format!(
                                                            "inbox.pull: malformed sender identity for {}: {}",
                                                            entry.transaction_id, msg
                                                        ));
                                                continue;
                                            }
                                        };
                                        let chain_tip_arr = match decode_canonical_b32_32(
                                            "sender_chain_tip",
                                            &entry.sender_chain_tip,
                                        ) {
                                            Ok(value) => value,
                                            Err(msg) => {
                                                log::warn!(
                                                    "[storage.sync] Skipping tx {}: {}",
                                                    entry.transaction_id,
                                                    msg
                                                );
                                                let mut state_guard = batch_state.lock().await;
                                                state_guard.errors.push(format!(
                                                            "inbox.pull: malformed sender chain tip for {}: {}",
                                                            entry.transaction_id, msg
                                                        ));
                                                continue;
                                            }
                                        };
                                        let to_device_id_arr: [u8; 32] = match to_device_id
                                            .as_slice()
                                            .try_into()
                                        {
                                            Ok(value) => value,
                                            Err(_) => {
                                                let mut state_guard = batch_state.lock().await;
                                                state_guard.errors.push(format!(
                                                                "inbox.pull: tx {} has invalid operation.to_device_id length {}",
                                                                entry.transaction_id,
                                                                to_device_id.len()
                                                            ));
                                                continue;
                                            }
                                        };

                                        // =====================================================================
                                        // DIAGNOSTIC: Log all signing context fields for debugging mismatches
                                        // =====================================================================
                                        log::info!(
                                                    "[storage.sync] 📥 Verifying tx={}: from_first8={:02x}{:02x}{:02x}{:02x}... to_first8={:02x}{:02x}{:02x}{:02x}... chain_tip_first8={:02x}{:02x}{:02x}{:02x}...",
                                                    entry.transaction_id,
                                                    from_device_id[0], from_device_id[1], from_device_id[2], from_device_id[3],
                                                    to_device_id_arr[0], to_device_id_arr[1], to_device_id_arr[2], to_device_id_arr[3],
                                                    chain_tip_arr[0], chain_tip_arr[1], chain_tip_arr[2], chain_tip_arr[3],
                                                );
                                        log::info!(
                                                    "[storage.sync] 📥 tx={}: amount={} token={} nonce_len={} memo_len={} seq={}",
                                                    entry.transaction_id, amount_val, String::from_utf8_lossy(&token_id), nonce.len(), memo.len(), entry.seq
                                                );

                                        // GUARDRAIL: Check if to_device_id matches chain_tip (indicates sender bug)
                                        if to_device_id_arr == chain_tip_arr
                                            && chain_tip_arr != [0u8; 32]
                                        {
                                            log::error!(
                                                        "[storage.sync] ❌ SENDER BUG DETECTED: to_device_id == chain_tip! Sender passed chain_tip as recipient."
                                                    );
                                            let mut state_guard = batch_state.lock().await;
                                            state_guard.errors.push("inbox.pull: sender passed chain_tip as to_device_id".into());
                                            continue;
                                        }

                                        // §4.2.1: Use the sender's canonical unsigned Operation bytes
                                        // directly.  No field-by-field reconstruction — the sender
                                        // embedded the exact signing preimage in the envelope.
                                        if entry.canonical_operation_bytes.is_empty() {
                                            log::error!(
                                                "[storage.sync] ❌ REJECTING tx {}: missing canonical_operation_bytes (§4.2.1 strict-fail)",
                                                entry.transaction_id
                                            );
                                            let mut state_guard = batch_state.lock().await;
                                            state_guard.errors.push(format!(
                                                "missing canonical_operation_bytes for tx {}",
                                                entry.transaction_id
                                            ));
                                            continue;
                                        }
                                        let signing_bytes = entry.canonical_operation_bytes.clone();

                                        // Verify SPHINCS+ signature (fail-closed)
                                        // Prefer embedded sender signing key; fall back to contact book.
                                        let (pk, pk_source) = if !entry.sender_signing_public_key.is_empty() {
                                                    (entry.sender_signing_public_key.clone(), "embedded_evidence")
                                                } else if let Some(k) = crate::storage::client_db::get_contact_public_key_by_device_id(&entry.sender_device_id) {
                                                    (k, "contact_book")
                                                } else {
                                                    log::warn!("[storage.sync] ❌ No public key for sender {} (tx {}) - REJECTING", entry.sender_device_id, entry.transaction_id);
                                                    let mut state_guard = batch_state.lock().await;
                                                    state_guard.errors.push(format!("unknown sender public key for tx {}", entry.transaction_id));
                                                    continue;
                                                };

                                        // Diagnostic: hash public key for cross-device comparison
                                        let pk_hash =
                                            dsm::crypto::blake3::domain_hash("DSM/pk-hash", &pk);
                                        log::info!("[storage.sync] 🔑 signer pk hash(first8)={:?} source={} tx={}", &pk_hash.as_bytes()[..8], pk_source, entry.transaction_id);

                                        let valid = match dsm::crypto::sphincs::sphincs_verify(
                                            &pk,
                                            &signing_bytes,
                                            &entry.signature,
                                        ) {
                                            Ok(true) => true,
                                            Ok(false) => false,
                                            Err(e) => {
                                                log::warn!("[storage.sync] ❌ Signature verification error for tx {}: {} - REJECTING", entry.transaction_id, e);
                                                false
                                            }
                                        };
                                        if !valid {
                                            log::warn!(
                                                "[storage.sync] inbox.pull: signature verification failed for tx {} — skipping poisoned entry, continuing batch",
                                                entry.transaction_id
                                            );
                                            let mut state_guard = batch_state.lock().await;
                                            state_guard.errors.push(format!(
                                                "inbox.pull: signature verification failed for tx {}",
                                                entry.transaction_id
                                            ));
                                            continue;
                                        }

                                        // Rehydrate and apply the transfer operation (we already hold Operation in the entry)
                                        let op = entry.transaction.clone();
                                        let tx_id: TransactionId =
                                            TransactionId::new(entry.transaction_id.clone());
                                        // §S1: receipt_commit is mandatory — §4.3 items 2/3/4 all depend on it.
                                        if entry.receipt_commit.is_empty() {
                                            log::error!("[storage.sync] §4.3 REJECTING tx {}: receipt_commit absent (mandatory per §4.3)", entry.transaction_id);
                                            let mut state_guard = batch_state.lock().await;
                                            state_guard.errors.push(format!(
                                                "§4.3 missing receipt_commit for tx {}",
                                                entry.transaction_id
                                            ));
                                            continue;
                                        }
                                        // §S4/§6 Tripwire: bricked-contact check BEFORE state mutation.
                                        if crate::storage::client_db::is_contact_bricked(
                                            &from_device_id,
                                        ) {
                                            log::error!("[storage.sync] §6 REJECTING tx {} from BRICKED contact {} (pre-apply)", entry.transaction_id, entry.sender_device_id);
                                            let mut sg = batch_state.lock().await;
                                            sg.errors.push(format!(
                                                "§6 bricked contact for tx {}",
                                                entry.transaction_id
                                            ));
                                            continue;
                                        }
                                        // ═══════════════════════════════════════════════════════
                                        // Strict replay drain (§4.3 + §5.4): when a nonce is already
                                        // spent the balance was credited on a prior sync. We MAY only
                                        // ACK the stale entry if four invariants still hold:
                                        //   1. Sender's receipt re-verifies (same transaction body,
                                        //      not a forged nonce reuse).
                                        //   2. `receipt.child_tip == recomputed expected_h_next`.
                                        //   3. `receipt.sig_a` still verifies under the sender PK.
                                        //   4. Local `contacts.chain_tip` equals `expected_h_next`,
                                        //      or can be atomically advanced to it in this cycle.
                                        // A bare nonce-match ACK is unsafe: it lets the sender advance
                                        // while the receiver stays at h_n, producing permanent
                                        // contacts.chain_tip divergence and subsequent b0x routing
                                        // misses. Failure at any step → no ACK, storage node keeps
                                        // the entry for retry.
                                        // ═══════════════════════════════════════════════════════
                                        {
                                            let nonce_bytes: Option<&[u8]> = match &entry
                                                .transaction
                                            {
                                                dsm::types::operations::Operation::Transfer {
                                                    nonce,
                                                    ..
                                                } => {
                                                    if nonce.is_empty() {
                                                        None
                                                    } else {
                                                        Some(nonce.as_slice())
                                                    }
                                                }
                                                _ => None,
                                            };
                                            if let Some(nb) = nonce_bytes {
                                                if let Ok(true) =
                                                    crate::storage::client_db::is_nonce_spent(nb)
                                                {
                                                    let op_bytes_for_tip = signing_bytes.clone();
                                                    let receipt_sigma = dsm::core::bilateral_transaction_manager::compute_precommit(
                                                        &chain_tip_arr,
                                                        &op_bytes_for_tip,
                                                        &nonce,
                                                    );
                                                    let expected_h_next = dsm::core::bilateral_transaction_manager::compute_successor_tip(
                                                        &chain_tip_arr,
                                                        &op_bytes_for_tip,
                                                        &nonce,
                                                        &receipt_sigma,
                                                    );

                                                    let sender_device_tree_commitment = crate::storage::client_db::get_contact_device_tree_commitment(&from_device_id);
                                                    if !crate::sdk::receipts::verify_receipt_bytes(
                                                        &entry.receipt_commit,
                                                        sender_device_tree_commitment,
                                                    ) {
                                                        log::warn!("[storage.sync] Strict replay drain REJECTED (no ACK) for tx {}: receipt re-verify failed", entry.transaction_id);
                                                        let mut sg = batch_state.lock().await;
                                                        sg.errors.push(format!("replay drain receipt re-verify failed for tx {}", entry.transaction_id));
                                                        continue;
                                                    }

                                                    let receipt = match dsm::types::receipt_types::StitchedReceiptV2::from_canonical_protobuf(&entry.receipt_commit) {
                                                        Ok(r) => r,
                                                        Err(e) => {
                                                            log::warn!("[storage.sync] Strict replay drain REJECTED (no ACK) for tx {}: receipt parse failed: {}", entry.transaction_id, e);
                                                            let mut sg = batch_state.lock().await;
                                                            sg.errors.push(format!("replay drain receipt parse failed for tx {}: {}", entry.transaction_id, e));
                                                            continue;
                                                        }
                                                    };

                                                    // Receipt carries A-side asymmetric tips (what
                                                    // sender's T_A stores + what inclusion proofs prove).
                                                    // Symmetric §16.6 h_{n+1} equivalence is enforced at
                                                    // envelope-level `next_chain_tip` vs `expected_h_next`
                                                    // and via the contacts.chain_tip CAS — no per-receipt
                                                    // comparison required here.

                                                    if receipt.sig_a.is_empty() {
                                                        log::warn!("[storage.sync] Strict replay drain REJECTED (no ACK) for tx {}: sig_a absent", entry.transaction_id);
                                                        let mut sg = batch_state.lock().await;
                                                        sg.errors.push(format!(
                                                            "replay drain sig_a absent for tx {}",
                                                            entry.transaction_id
                                                        ));
                                                        continue;
                                                    }

                                                    let commitment = match receipt
                                                        .compute_commitment()
                                                    {
                                                        Ok(c) => c,
                                                        Err(e) => {
                                                            log::warn!("[storage.sync] Strict replay drain REJECTED (no ACK) for tx {}: commitment error: {}", entry.transaction_id, e);
                                                            let mut sg = batch_state.lock().await;
                                                            sg.errors.push(format!("replay drain commitment error for tx {}: {}", entry.transaction_id, e));
                                                            continue;
                                                        }
                                                    };

                                                    match dsm::crypto::sphincs::sphincs_verify(
                                                        &pk,
                                                        &commitment,
                                                        &receipt.sig_a,
                                                    ) {
                                                        Ok(true) => { /* ok */ }
                                                        Ok(false) => {
                                                            log::warn!("[storage.sync] Strict replay drain REJECTED (no ACK) for tx {}: sig_a invalid", entry.transaction_id);
                                                            let mut sg = batch_state.lock().await;
                                                            sg.errors.push(format!("replay drain sig_a invalid for tx {}", entry.transaction_id));
                                                            continue;
                                                        }
                                                        Err(e) => {
                                                            log::warn!("[storage.sync] Strict replay drain REJECTED (no ACK) for tx {}: sig_a verify error: {}", entry.transaction_id, e);
                                                            let mut sg = batch_state.lock().await;
                                                            sg.errors.push(format!("replay drain sig_a verify error for tx {}: {}", entry.transaction_id, e));
                                                            continue;
                                                        }
                                                    }

                                                    // Ensure local contacts.chain_tip is at expected_h_next.
                                                    let tip_converged = match crate::storage::client_db::get_contact_chain_tip_raw(&from_device_id) {
                                                        Some(t) if t == expected_h_next => true,
                                                        _ => {
                                                            let request = crate::storage::client_db::bilateral_tip_sync::TipSyncRequest {
                                                                counterparty_device_id: from_device_id,
                                                                expected_parent_tip: chain_tip_arr,
                                                                target_tip: expected_h_next,
                                                                observed_gate: None,
                                                                clear_gate_on_success: false,
                                                            };
                                                            matches!(
                                                                crate::storage::client_db::bilateral_tip_sync::sync_bilateral_tips_atomically(&request),
                                                                Ok(crate::storage::client_db::bilateral_tip_sync::TipSyncOutcome::Advanced { .. })
                                                                | Ok(crate::storage::client_db::bilateral_tip_sync::TipSyncOutcome::RepairedAtTarget { .. })
                                                                | Ok(crate::storage::client_db::bilateral_tip_sync::TipSyncOutcome::AlreadyAtTarget { .. })
                                                            )
                                                        }
                                                    };

                                                    if !tip_converged {
                                                        log::warn!("[storage.sync] Strict replay drain REJECTED (no ACK) for tx {}: local contacts.chain_tip could not converge to h_{{n+1}}", entry.transaction_id);
                                                        let mut sg = batch_state.lock().await;
                                                        sg.errors.push(format!("replay drain tip convergence failed for tx {}", entry.transaction_id));
                                                        continue;
                                                    }

                                                    // Canonical §2.2 SMT advance is owned by
                                                    // `apply_operation_with_replay_protection` →
                                                    // `execute_on_relationship`. Idempotency for
                                                    // already-consumed nonces is checked at the
                                                    // replay layer, not on any shadow SMT.

                                                    log::info!("[storage.sync] Strict replay drain ACK for tx {} (receipt verified, tip converged)", entry.transaction_id);
                                                    emit_authoritative_wallet_refresh();
                                                    let mut sg = batch_state.lock().await;
                                                    sg.processed_entries.push((
                                                        entry.inbox_key.clone(),
                                                        entry.transaction_id.clone(),
                                                    ));
                                                    sg.processed = sg.processed.saturating_add(1);
                                                    continue;
                                                }
                                            }
                                        }
                                        // §S4/§4.3#5: Parent-tip mismatch check BEFORE state mutation.
                                        // NOTE: For online unilateral delivery, inbox order can be non-adjacent
                                        // (stale or ahead-of-local-tip entries). A mismatch here is not by itself
                                        // cryptographic proof of equivocation, so do NOT permanently brick.
                                        // Instead, mark relationship for reconciliation and skip this entry.
                                        {
                                            let stored_tip_pre = crate::storage::client_db::get_contact_chain_tip_raw(&from_device_id);
                                            if let Some(stored) = stored_tip_pre {
                                                if stored != [0u8; 32] && stored != chain_tip_arr {
                                                    // §5.4 ACK-advancement: if we have a pending online outbox
                                                    // for this counterparty whose next_tip matches the claimed
                                                    // parent, the gap is exactly one pending-online step.
                                                    // Try ACK-based advancement before rejecting.
                                                    let mut gap_closed = false;
                                                    if let Ok(Some(pending)) = crate::storage::client_db::get_pending_online_outbox(&from_device_id) {
                                                        let pending_next: Option<[u8; 32]> = pending.next_tip.as_slice().try_into().ok();
                                                        if pending_next == Some(chain_tip_arr) {
                                                            log::info!(
                                                                "[storage.sync] Parent-tip mismatch for tx {} but pending outbox next_tip matches claimed parent; trying ACK advancement",
                                                                entry.transaction_id
                                                            );
                                                            match b0x_sdk.is_message_acknowledged(&pending.message_id).await {
                                                                Ok(true) => {
                                                                    let pending_parent: [u8; 32] = pending.parent_tip.as_slice().try_into().unwrap_or([0u8; 32]);
                                                                    let cp_arr: [u8; 32] = pending.counterparty_device_id.as_slice().try_into().unwrap_or([0u8; 32]);
                                                                    let observed_gate = crate::storage::client_db::bilateral_tip_sync::ObservedPendingGate {
                                                                        counterparty_device_id: cp_arr,
                                                                        parent_tip: pending_parent,
                                                                        next_tip: chain_tip_arr,
                                                                    };
                                                                    let request = crate::storage::client_db::bilateral_tip_sync::TipSyncRequest {
                                                                        counterparty_device_id: cp_arr,
                                                                        expected_parent_tip: pending_parent,
                                                                        target_tip: chain_tip_arr,
                                                                        observed_gate: Some(observed_gate),
                                                                        clear_gate_on_success: true,
                                                                    };
                                                                    match crate::storage::client_db::bilateral_tip_sync::sync_bilateral_tips_atomically(&request) {
                                                                        Ok(crate::storage::client_db::bilateral_tip_sync::TipSyncOutcome::Advanced { .. })
                                                                        | Ok(crate::storage::client_db::bilateral_tip_sync::TipSyncOutcome::RepairedAtTarget { .. })
                                                                        | Ok(crate::storage::client_db::bilateral_tip_sync::TipSyncOutcome::AlreadyAtTarget { .. }) => {
                                                                            log::info!(
                                                                                "[storage.sync] §5.4 ACK-advancement succeeded for tx {}; canonical tip now matches claimed parent",
                                                                                entry.transaction_id
                                                                            );
                                                                            gap_closed = true;
                                                                        }
                                                                        Ok(other) => {
                                                                            log::warn!(
                                                                                "[storage.sync] §5.4 ACK-advancement tip sync returned {:?} for tx {}; deferring",
                                                                                other, entry.transaction_id
                                                                            );
                                                                        }
                                                                        Err(e) => {
                                                                            log::warn!(
                                                                                "[storage.sync] §5.4 ACK-advancement tip sync failed for tx {}: {}; deferring",
                                                                                entry.transaction_id, e
                                                                            );
                                                                        }
                                                                    }
                                                                }
                                                                Ok(false) => {
                                                                    log::info!(
                                                                        "[storage.sync] Pending online send not yet ACKed for tx {}; deferring inbound",
                                                                        entry.transaction_id
                                                                    );
                                                                }
                                                                Err(e) => {
                                                                    log::warn!(
                                                                        "[storage.sync] ACK check failed for tx {}: {}; deferring",
                                                                        entry.transaction_id, e
                                                                    );
                                                                }
                                                            }
                                                        }
                                                    }
                                                    if !gap_closed {
                                                        log::warn!("[storage.sync] Parent-tip mismatch pre-apply for tx {}: stored={:02x?}.. claimed={:02x?}.. recording observed remote tip and marking reconcile", entry.transaction_id, &stored[..4], &chain_tip_arr[..4]);
                                                        record_observed_remote_tip_and_refresh(
                                                            &from_device_id,
                                                            &chain_tip_arr,
                                                        );
                                                        mark_contact_needs_online_reconcile_and_refresh(&from_device_id);
                                                        let mut sg = batch_state.lock().await;
                                                        sg.errors.push(format!(
                                                            "parent-tip mismatch pre-apply for tx {}",
                                                            entry.transaction_id
                                                        ));
                                                        continue;
                                                    }
                                                }
                                            }
                                        }
                                        // §5.4: Do not race an inbound online apply against a local pending online projection.
                                        {
                                            let smt_key = dsm::core::bilateral_transaction_manager::compute_smt_key(
                                                        &from_device_id,
                                                        &to_device_id_arr,
                                                    );
                                            if crate::security::modal_sync_lock::is_pending_online(
                                                &smt_key,
                                            )
                                            .await
                                            {
                                                log::warn!(
                                                            "[storage.sync] Deferring tx {} because relationship {} has a pending local online projection",
                                                            entry.transaction_id,
                                                            entry.sender_device_id
                                                        );
                                                let mut sg = batch_state.lock().await;
                                                sg.errors.push(format!(
                                                    "pending local online projection for tx {}",
                                                    entry.transaction_id
                                                ));
                                                continue;
                                            }
                                        }
                                        // ═══════════════════════════════════════════════════════
                                        // §4.3 Pre-flight verification — ALL cryptographic checks
                                        // run BEFORE any state mutation. Failure at any step →
                                        // `continue` without ACK so the storage node retains the
                                        // entry. This preserves spec-mandated acceptance order
                                        // (sigs → inclusion proofs → byte-exact SMT replace →
                                        // parent-tip) and rules out the gate-continue divergence
                                        // where balance was credited but contacts.chain_tip
                                        // stayed at h_n.
                                        // ═══════════════════════════════════════════════════════
                                        let op_bytes_for_tip = signing_bytes.clone();
                                        let receipt_sigma = dsm::core::bilateral_transaction_manager::compute_precommit(
                                            &chain_tip_arr,
                                            &op_bytes_for_tip,
                                            &nonce,
                                        );
                                        let expected_h_next = dsm::core::bilateral_transaction_manager::compute_successor_tip(
                                            &chain_tip_arr,
                                            &op_bytes_for_tip,
                                            &nonce,
                                            &receipt_sigma,
                                        );

                                        // Envelope's claimed next_chain_tip must match recomputation (§4.3#6).
                                        if let Some(claimed_tip) =
                                            crate::util::text_id::decode_base32_crockford(
                                                &entry.next_chain_tip,
                                            )
                                            .filter(|b| b.len() == 32)
                                        {
                                            let mut claimed_arr = [0u8; 32];
                                            claimed_arr.copy_from_slice(&claimed_tip);
                                            if claimed_arr != expected_h_next {
                                                log::error!("[storage.sync] §4.3#6 envelope next_chain_tip != recomputed h_{{n+1}} for tx {} — rejecting without ACK", entry.transaction_id);
                                                let mut sg = batch_state.lock().await;
                                                sg.errors.push(format!(
                                                    "§4.3#6 next_chain_tip mismatch for tx {}",
                                                    entry.transaction_id
                                                ));
                                                continue;
                                            }
                                        }

                                        // §4.3 items 2+4: full receipt verification (SMT-Replace, device proof, relation proofs).
                                        let sender_device_tree_commitment = crate::storage::client_db::get_contact_device_tree_commitment(&from_device_id);
                                        if !crate::sdk::receipts::verify_receipt_bytes(
                                            &entry.receipt_commit,
                                            sender_device_tree_commitment,
                                        ) {
                                            log::error!("[storage.sync] §4.3#2+4 ReceiptCommit verification FAILED for tx {} — rejecting without ACK", entry.transaction_id);
                                            let mut sg = batch_state.lock().await;
                                            sg.errors.push(format!("§4.3#2+4 ReceiptCommit verification failed for tx {}", entry.transaction_id));
                                            continue;
                                        }

                                        // Parse receipt, verify child_tip matches recomputed h_{n+1} (§4.3),
                                        // and verify sig_a (§4.2 mandatory sender non-repudiation).
                                        let receipt = match dsm::types::receipt_types::StitchedReceiptV2::from_canonical_protobuf(&entry.receipt_commit) {
                                            Ok(r) => r,
                                            Err(e) => {
                                                log::error!("[storage.sync] §4.3 StitchedReceiptV2 parse FAILED for tx {}: {} — rejecting without ACK", entry.transaction_id, e);
                                                let mut sg = batch_state.lock().await;
                                                sg.errors.push(format!("§4.3 receipt parse failed for tx {}: {}", entry.transaction_id, e));
                                                continue;
                                            }
                                        };

                                        // Receipt carries A-side asymmetric tips (what sender's T_A
                                        // stores + what the inclusion proofs prove). Symmetric
                                        // §16.6 h_{n+1} equivalence is enforced earlier against
                                        // `envelope.next_chain_tip` (line ~999) and later via the
                                        // contacts.chain_tip CAS — no per-receipt comparison here.

                                        if receipt.sig_a.is_empty() {
                                            log::error!("[storage.sync] §4.2 REJECTING tx {}: receipt.sig_a absent (mandatory)", entry.transaction_id);
                                            let mut sg = batch_state.lock().await;
                                            sg.errors.push(format!(
                                                "§4.2 sig_a absent for tx {}",
                                                entry.transaction_id
                                            ));
                                            continue;
                                        }

                                        let receipt_commitment = match receipt.compute_commitment()
                                        {
                                            Ok(c) => c,
                                            Err(e) => {
                                                log::error!("[storage.sync] §4.2 receipt commitment failed for tx {}: {} — rejecting without ACK", entry.transaction_id, e);
                                                let mut sg = batch_state.lock().await;
                                                sg.errors.push(format!(
                                                    "§4.2 commitment failed for tx {}: {}",
                                                    entry.transaction_id, e
                                                ));
                                                continue;
                                            }
                                        };

                                        match dsm::crypto::sphincs::sphincs_verify(
                                            &pk,
                                            &receipt_commitment,
                                            &receipt.sig_a,
                                        ) {
                                            Ok(true) => {
                                                log::info!(
                                                    "[storage.sync] §4.2 sig_a verified for tx {}",
                                                    entry.transaction_id
                                                );
                                            }
                                            Ok(false) => {
                                                log::error!("[storage.sync] §4.2 FATAL: sig_a invalid for tx {} — rejecting without ACK", entry.transaction_id);
                                                let mut sg = batch_state.lock().await;
                                                sg.errors.push(format!(
                                                    "§4.2 sig_a invalid for tx {}",
                                                    entry.transaction_id
                                                ));
                                                continue;
                                            }
                                            Err(e) => {
                                                log::error!("[storage.sync] §4.2 sig_a verify error for tx {}: {} — rejecting without ACK", entry.transaction_id, e);
                                                let mut sg = batch_state.lock().await;
                                                sg.errors.push(format!(
                                                    "§4.2 sig_a verify error for tx {}: {}",
                                                    entry.transaction_id, e
                                                ));
                                                continue;
                                            }
                                        }

                                        // Best-effort receiver counter-sign (sig_b). Failure is non-fatal:
                                        // hash chain adjacency + Tripwire fork-exclusion suffice without sig_b.
                                        let sig_b = match core_sdk
                                            .sign_bytes_sphincs(&receipt_commitment)
                                        {
                                            Ok(sb) => {
                                                log::info!("[storage.sync] §4.2 sig_b receiver counter-sign produced for tx {}", entry.transaction_id);
                                                sb
                                            }
                                            Err(e) => {
                                                log::warn!("[storage.sync] §4.2 sig_b counter-sign failed for tx {} (non-fatal): {}", entry.transaction_id, e);
                                                vec![]
                                            }
                                        };

                                        // ═══════════════════════════════════════════════════════
                                        // Phase 3: atomic commit. Pre-flight passed, now mutate.
                                        // Order: DeviceState/nonce/bcr (apply_operation) →
                                        // shared SMT → contacts.chain_tip → receipt/tx → refresh →
                                        // ACK. Any post-apply step that fails marks the contact
                                        // needs_online_reconcile and SKIPS ACK so the strict
                                        // replay drain on the next poll completes convergence.
                                        // ═══════════════════════════════════════════════════════
                                        log::debug!("[storage.sync] Pre-flight passed; calling apply_operation_with_replay_protection for tx {} amount {}", entry.transaction_id, amount_val);
                                        let apply_res = core_sdk
                                            .apply_operation_with_replay_protection(
                                                op,
                                                &tx_id,
                                                entry.seq,
                                                &entry.sender_device_id,
                                                &entry.sender_chain_tip,
                                            );
                                        let advance_outcome = match apply_res {
                                            Ok(o) => o,
                                            Err(e) => {
                                                let err_msg = format!("{}", e);
                                                if err_msg.contains("replay detected")
                                                    || err_msg.contains("nonce already spent")
                                                {
                                                    // TOCTOU: concurrent path spent nonce between strict
                                                    // drain and apply. Do NOT ACK here — the strict drain
                                                    // on the next poll will verify + converge + ACK.
                                                    log::info!("[storage.sync] apply_operation observed replay race for tx {} — deferring to next strict drain", entry.transaction_id);
                                                    let mut sg = batch_state.lock().await;
                                                    sg.errors.push(format!(
                                                        "apply_operation replay race for tx {}",
                                                        entry.transaction_id
                                                    ));
                                                } else {
                                                    log::warn!("[storage.sync] apply_operation_with_replay_protection failed for tx {}: {}", entry.transaction_id, e);
                                                    let mut sg = batch_state.lock().await;
                                                    sg.errors.push(format!(
                                                        "apply_operation failed for tx {}: {}",
                                                        entry.transaction_id, e
                                                    ));
                                                }
                                                continue;
                                            }
                                        };
                                        // Canonical advance already updated DeviceState.smt and the
                                        // balance map atomically inside `execute_on_relationship`.
                                        // The AdvanceOutcome carries receiver-side SMT proofs that
                                        // flow into the §4.2 stitched receipt below.

                                        // Atomic CAS on contacts.chain_tip.
                                        let tip_request = crate::storage::client_db::bilateral_tip_sync::TipSyncRequest {
                                            counterparty_device_id: from_device_id,
                                            expected_parent_tip: chain_tip_arr,
                                            target_tip: expected_h_next,
                                            observed_gate: None,
                                            clear_gate_on_success: false,
                                        };
                                        match crate::storage::client_db::bilateral_tip_sync::sync_bilateral_tips_atomically(&tip_request) {
                                            Ok(crate::storage::client_db::bilateral_tip_sync::TipSyncOutcome::Advanced { .. })
                                            | Ok(crate::storage::client_db::bilateral_tip_sync::TipSyncOutcome::RepairedAtTarget { .. })
                                            | Ok(crate::storage::client_db::bilateral_tip_sync::TipSyncOutcome::AlreadyAtTarget { .. }) => {
                                                log::info!("[storage.sync] §4.1 Canonical chain tip advanced for tx {}", entry.transaction_id);
                                            }
                                            Ok(other) => {
                                                log::error!("[storage.sync] §4.1 Canonical tip advance returned {:?} for tx {} — marking reconcile, no ACK", other, entry.transaction_id);
                                                mark_contact_needs_online_reconcile_and_refresh(&from_device_id);
                                                let mut sg = batch_state.lock().await;
                                                sg.errors.push(format!("tip sync unexpected outcome for tx {}: {:?}", entry.transaction_id, other));
                                                continue;
                                            }
                                            Err(e) => {
                                                log::error!("[storage.sync] §4.1 Canonical tip advance FAILED for tx {}: {} — marking reconcile, no ACK", entry.transaction_id, e);
                                                mark_contact_needs_online_reconcile_and_refresh(&from_device_id);
                                                let mut sg = batch_state.lock().await;
                                                sg.errors.push(format!("tip sync failed for tx {}: {}", entry.transaction_id, e));
                                                continue;
                                            }
                                        }

                                        // Persist receipt + transaction record. Only synthesize
                                        // a fresh §4.2 stitched receipt when the SMT actually
                                        // transitioned — AlreadyAtTarget reuses the archived
                                        // receipt body per Decision 5.
                                        let to_device_b32 =
                                            crate::util::text_id::encode_base32_crockford(
                                                &to_device_id,
                                            );
                                        let tx_hash = {
                                            let mut h = dsm::crypto::blake3::dsm_domain_hasher(
                                                "DSM/tx-record-hash",
                                            );
                                            h.update(entry.transaction_id.as_bytes());
                                            h.update(entry.sender_device_id.as_bytes());
                                            crate::util::text_id::encode_base32_crockford(
                                                &h.finalize().as_bytes()[..32],
                                            )
                                        };
                                        let mut meta = std::collections::HashMap::new();
                                        meta.insert("token_id".to_string(), token_id.clone());
                                        meta.insert("memo".to_string(), memo.as_bytes().to_vec());

                                        // Use canonical AdvanceOutcome proofs for the §4.2 stitched
                                        // receipt. Replay protection on apply_operation_with_replay_protection
                                        // already rejects double-apply at the nonce layer, so the outcome
                                        // here always reflects a real leaf replace.
                                        let recv_smt_pre = advance_outcome.parent_r_a;
                                        let recv_smt_post = advance_outcome.child_r_a;
                                        let recv_parent_bytes =
                                            advance_outcome.smt_proofs.parent_proof.to_bytes();
                                        let recv_child_bytes =
                                            advance_outcome.smt_proofs.child_proof.to_bytes();

                                        let dual = crate::storage::client_db::StitchedReceipt {
                                            tx_hash: receipt_commitment,
                                            h_n: chain_tip_arr,
                                            h_n1: expected_h_next,
                                            device_id_a: from_device_id,
                                            device_id_b: to_device_id_arr,
                                            sig_a: receipt.sig_a.clone(),
                                            sig_b: sig_b.clone(),
                                            receipt_commit: entry.receipt_commit.clone(),
                                            smt_root_pre: Some(recv_smt_pre),
                                            smt_root_post: Some(recv_smt_post),
                                        };
                                        if let Err(e) =
                                            crate::storage::client_db::store_stitched_receipt(&dual)
                                        {
                                            log::warn!("[storage.sync] §4.2 store_stitched_receipt failed for tx {}: {} (non-fatal)", entry.transaction_id, e);
                                        } else {
                                            log::info!("[storage.sync] §4.2 Dual-signed receipt persisted with SMT roots for tx {}", entry.transaction_id);
                                        }

                                        let recv_device_tree_commitment =
                                            crate::storage::client_db::get_contact_device_tree_commitment(&from_device_id);
                                        let rebuilt = build_online_receipt_with_smt(
                                            &from_device_id,
                                            &to_device_id_arr,
                                            chain_tip_arr,
                                            expected_h_next,
                                            recv_smt_pre,
                                            recv_smt_post,
                                            recv_parent_bytes,
                                            recv_child_bytes,
                                            recv_device_tree_commitment,
                                        );
                                        let history_proof_bytes: Option<Vec<u8>> =
                                            select_history_receipt_bytes(
                                                rebuilt,
                                                &entry.receipt_commit,
                                            );

                                        let rec = crate::storage::client_db::TransactionRecord {
                                            tx_id: entry.transaction_id.clone(),
                                            tx_hash,
                                            from_device: entry.sender_device_id.clone(),
                                            to_device: to_device_b32,
                                            amount: amount_val,
                                            tx_type: "online".to_string(),
                                            status: "confirmed".to_string(),
                                            chain_height: entry.seq,
                                            step_index: entry.seq,
                                            commitment_hash: None,
                                            proof_data: history_proof_bytes,
                                            metadata: meta,
                                            created_at: 0,
                                        };
                                        if let Err(e) =
                                            crate::storage::client_db::store_transaction(&rec)
                                        {
                                            log::warn!("[storage.sync] store_transaction failed for tx {}: {} (non-fatal)", entry.transaction_id, e);
                                        } else {
                                            log::info!("[storage.sync] Recorded incoming tx {} (from={}, amount={})", entry.transaction_id, entry.sender_device_id, amount_val);
                                        }

                                        // §11.1 balance already materialized by apply_operation.
                                        // Refresh in-memory caches + notify WebView.
                                        if let Some(router) = crate::bridge::app_router() {
                                            router.sync_balance_cache();
                                        }
                                        emit_authoritative_wallet_refresh();

                                        {
                                            let mut sg = batch_state.lock().await;
                                            sg.processed_entries.push((
                                                entry.inbox_key.clone(),
                                                entry.transaction_id.clone(),
                                            ));
                                            sg.processed = sg.processed.saturating_add(1);
                                        }
                                    } else {
                                        log::warn!(
                                            "[storage.sync] Unexpected transaction type: {:?}",
                                            entry.transaction
                                        );
                                    }
                                }

                                let (processed_entries, fatal_error) = {
                                    let final_state = batch_state.lock().await;
                                    processed = final_state.processed;
                                    errors.extend(final_state.errors.clone());
                                    (
                                        final_state.processed_entries.clone(),
                                        final_state.fatal_error.clone(),
                                    )
                                };

                                if let Some(fatal) = fatal_error {
                                    return err(fatal);
                                }

                                // Gate acknowledgements: only ACK entries that were validated and processed
                                if !processed_entries.is_empty() {
                                    let mut ack_groups: std::collections::BTreeMap<
                                        String,
                                        Vec<String>,
                                    > = std::collections::BTreeMap::new();
                                    for (inbox_key, tx_id) in processed_entries.clone() {
                                        ack_groups.entry(inbox_key).or_default().push(tx_id);
                                    }

                                    let mut acked_total = 0usize;
                                    for (inbox_key, tx_ids) in ack_groups {
                                        let ack_res =
                                            match tokio::runtime::Handle::try_current() {
                                                Ok(handle) => tokio::task::block_in_place(|| {
                                                    handle.block_on(b0x_sdk.acknowledge_b0x_v2(
                                                        &inbox_key,
                                                        tx_ids.clone(),
                                                    ))
                                                }),
                                                Err(_) => {
                                                    if let Ok(rt) = tokio::runtime::Runtime::new() {
                                                        rt.block_on(b0x_sdk.acknowledge_b0x_v2(
                                                            &inbox_key,
                                                            tx_ids.clone(),
                                                        ))
                                                    } else {
                                                        Err(dsm::types::error::DsmError::internal(
                                                            "runtime failed",
                                                            None::<std::io::Error>,
                                                        ))
                                                    }
                                                }
                                            };

                                        match ack_res {
                                            Ok(_) => {
                                                acked_total += tx_ids.len();
                                            }
                                            Err(e) => {
                                                #[cfg(feature = "dev-discovery")]
                                                network_gate.record_network_failure();

                                                log::warn!(
                                                    "[storage.sync] ⚠️ Ack failed for {}: {}",
                                                    inbox_key,
                                                    e
                                                );
                                                errors.push(format!(
                                                    "acknowledge failed for {}: {}",
                                                    inbox_key, e
                                                ));
                                            }
                                        }
                                    }
                                    if acked_total > 0 {
                                        log::info!(
                                            "[storage.sync] ✅ Acknowledged {} inbox entries",
                                            acked_total
                                        );
                                    }
                                }

                                // NOTE: Post-batch chain tip update loop REMOVED.
                                // The per-entry §4.3 finalize path that CAS-advances the
                                // canonical bilateral tip with independently recomputed expected_h_next
                                // is authoritative. The old loop
                                // overwrote the correct relationship tip h_{n+1} with the state-machine entity
                                // hash (entry.sender_chain_tip), breaking fork-exclusion detection.

                                // §5.4 outbox sweep runs unconditionally below the
                                // if/else — see post-else block.

                                // Auto-push any pending bilateral messages if enabled
                                if push_pending {
                                    let push_res = crate::sdk::b0x_sdk::B0xSDK::push_pending_bilateral_messages(
                                        device_id_b32.clone(),
                                        self.core_sdk.clone(),
                                        storage_endpoints.clone(),
                                    ).await;
                                    match push_res {
                                        Ok(count) => {
                                            pushed = count as u32;
                                            log::info!(
                                                "[DSM_SDK] ✅ Pushed {} pending bilateral messages",
                                                count
                                            );
                                        }
                                        Err(e) => {
                                            // Record network failure for connectivity monitoring
                                            #[cfg(feature = "dev-discovery")]
                                            network_gate.record_network_failure();

                                            log::warn!(
                                                "[DSM_SDK] ⚠️ Failed to push pending messages: {}",
                                                e
                                            );
                                            errors.push(format!(
                                                "push pending messages failed: {}",
                                                e
                                            ));
                                        }
                                    }
                                }
                            } else {
                                log::info!("[DSM_SDK] No new inbox items to process");
                            }

                            // §5.4 Outbox sweep: runs on EVERY storage.sync poll, regardless
                            // of whether new inbox items were pulled. The sender holds a pending
                            // online outbox entry until the recipient's ACK is confirmed on b0x.
                            // Without this sweep (previously gated behind `!all_items.is_empty()`),
                            // the sender's canonical tip never advanced in the common case where
                            // the sender had no further inbound traffic after its own send, which
                            // broke subsequent BLE handshakes with the recipient.
                            if let Ok(pending_entries) =
                                crate::storage::client_db::get_all_pending_online_outbox()
                            {
                                for pending in &pending_entries {
                                    let pending_next: Option<[u8; 32]> =
                                        pending.next_tip.as_slice().try_into().ok();
                                    let current_tip =
                                        crate::storage::client_db::get_contact_chain_tip_raw(
                                            &pending.counterparty_device_id,
                                        );

                                    let pending_parent: Option<[u8; 32]> =
                                        pending.parent_tip.as_slice().try_into().ok();
                                    // Per Tripwire, only consider the gate already-advanced
                                    // if current_tip exactly equals pending.next_tip.
                                    let already_advanced = match (current_tip, pending_next) {
                                        (Some(ct), Some(pn)) => ct == pn,
                                        _ => false,
                                    };

                                    let gate_parent: [u8; 32] = pending_parent.unwrap_or([0u8; 32]);
                                    let gate_next: [u8; 32] = pending_next.unwrap_or([0u8; 32]);
                                    let cp_arr: [u8; 32] = match pending
                                        .counterparty_device_id
                                        .as_slice()
                                        .try_into()
                                    {
                                        Ok(a) => a,
                                        Err(_) => {
                                            continue;
                                        }
                                    };
                                    let observed_gate = crate::storage::client_db::bilateral_tip_sync::ObservedPendingGate {
                                        counterparty_device_id: cp_arr,
                                        parent_tip: gate_parent,
                                        next_tip: gate_next,
                                    };

                                    if already_advanced {
                                        log::info!(
                                            "[storage.sync] §5.4 sweep: outbox gate stale (tip advanced); clearing for counterparty {:02x}{:02x}{:02x}{:02x}...",
                                            pending.counterparty_device_id[0], pending.counterparty_device_id[1],
                                            pending.counterparty_device_id[2], pending.counterparty_device_id[3],
                                        );
                                        if let Some(ct) = current_tip {
                                            let request = crate::storage::client_db::bilateral_tip_sync::TipSyncRequest {
                                                counterparty_device_id: cp_arr,
                                                expected_parent_tip: ct,
                                                target_tip: ct,
                                                observed_gate: Some(observed_gate),
                                                clear_gate_on_success: true,
                                            };
                                            if crate::storage::client_db::bilateral_tip_sync::sync_bilateral_tips_atomically(&request).is_ok() {
                                                emit_authoritative_wallet_refresh();
                                            }
                                        } else if crate::storage::client_db::clear_pending_online_outbox_if_matches(
                                            &pending.counterparty_device_id,
                                            &gate_parent,
                                            &gate_next,
                                        )
                                        .is_ok()
                                        {
                                            emit_authoritative_wallet_refresh();
                                        }
                                        continue;
                                    }

                                    // Network path: check ACK via storage nodes
                                    match b0x_sdk.is_message_acknowledged(&pending.message_id).await
                                    {
                                        Ok(true) => {
                                            log::info!(
                                                "[storage.sync] §5.4 sweep: message {} ACKed; finalizing tip atomically",
                                                pending.message_id,
                                            );
                                            match (
                                                pending_next,
                                                <[u8; 32]>::try_from(pending.parent_tip.as_slice()),
                                            ) {
                                                (Some(pn), Ok(parent)) => {
                                                    let request = crate::storage::client_db::bilateral_tip_sync::TipSyncRequest {
                                                        counterparty_device_id: cp_arr,
                                                        expected_parent_tip: parent,
                                                        target_tip: pn,
                                                        observed_gate: Some(observed_gate),
                                                        clear_gate_on_success: true,
                                                    };
                                                    match crate::storage::client_db::bilateral_tip_sync::sync_bilateral_tips_atomically(&request) {
                                                        Ok(outcome) => match outcome {
                                                            crate::storage::client_db::bilateral_tip_sync::TipSyncOutcome::Advanced { .. }
                                                            | crate::storage::client_db::bilateral_tip_sync::TipSyncOutcome::RepairedAtTarget { .. }
                                                            | crate::storage::client_db::bilateral_tip_sync::TipSyncOutcome::AlreadyAtTarget { .. } => {
                                                                log::info!("[storage.sync] §5.4 sweep: tip advanced and gate cleared for {}", pending.message_id);
                                                                emit_authoritative_wallet_refresh();
                                                            }
                                                            _ => {
                                                                log::warn!("[storage.sync] §5.4 sweep: ParentConsumed for message {}; gate retained", pending.message_id);
                                                                mark_contact_needs_online_reconcile_and_refresh(&pending.counterparty_device_id);
                                                            }
                                                        },
                                                        Err(e) => {
                                                            log::warn!("[storage.sync] §5.4 sweep: finalize failed for {}: {}; gate retained", pending.message_id, e);
                                                        }
                                                    }
                                                }
                                                _ => {
                                                    log::warn!(
                                                        "[storage.sync] §5.4 sweep: missing next_tip or malformed parent_tip for {}; gate retained",
                                                        pending.message_id,
                                                    );
                                                }
                                            };
                                        }
                                        Ok(false) => {
                                            log::debug!(
                                                "[storage.sync] §5.4 sweep: message {} not yet ACKed",
                                                pending.message_id,
                                            );
                                        }
                                        Err(e) => {
                                            log::debug!(
                                                "[storage.sync] §5.4 sweep: ACK check failed for {}: {}",
                                                pending.message_id, e,
                                            );
                                        }
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            // Record network failure for connectivity monitoring
                            #[cfg(feature = "dev-discovery")]
                            network_gate.record_network_failure();

                            log::warn!("[DSM_SDK] inbox.pull: B0xSDK retrieve failed: {}", e);
                            return err(format!("inbox.pull: B0xSDK retrieve failed: {}", e));
                        }
                    }
                }

                // Record network success for connectivity monitoring
                #[cfg(feature = "dev-discovery")]
                network_gate.record_network_success();

                let resp = generated::StorageSyncResponse {
                    success: true,
                    pulled,
                    processed,
                    pushed,
                    errors,
                };
                // NEW: Return as Envelope.storageSyncResponse (field 35)
                pack_envelope_ok(generated::envelope::Payload::StorageSyncResponse(resp))
            }

            // -------- storage.nodeHealth --------
            // Queries each configured storage node for health + Prometheus metrics.
            // Returns StorageNodeStatsResponse via Envelope.
            "storage.nodeHealth" => {
                log::info!("[DSM_SDK] storage.nodeHealth called");

                // Get endpoints from request or fall back to configured ones
                let endpoints = match generated::ArgPack::decode(&*q.params) {
                    Ok(pack) if pack.codec == generated::Codec::Proto as i32 => {
                        match generated::StorageNodeStatsRequest::decode(&*pack.body) {
                            Ok(req) if !req.endpoints.is_empty() => req.endpoints,
                            _ => crate::network::list_storage_endpoints().unwrap_or_default(),
                        }
                    }
                    _ => crate::network::list_storage_endpoints().unwrap_or_default(),
                };

                let client = crate::sdk::storage_node_sdk::build_ca_aware_client();
                let mut node_stats = Vec::with_capacity(endpoints.len());
                let mut healthy_count = 0u32;

                // Query each endpoint concurrently
                let mut handles = Vec::new();
                for ep in &endpoints {
                    let c = client.clone();
                    let ep_owned = ep.clone();
                    handles.push(tokio::spawn(async move {
                        check_single_node_stats(&c, &ep_owned).await
                    }));
                }

                for handle in handles {
                    match handle.await {
                        Ok(stats) => {
                            if stats.status == "healthy" {
                                healthy_count += 1;
                            }
                            node_stats.push(stats);
                        }
                        Err(e) => {
                            log::warn!("[storage.nodeHealth] task join error: {}", e);
                        }
                    }
                }

                let resp = generated::StorageNodeStatsResponse {
                    nodes: node_stats,
                    total_nodes: endpoints.len() as u32,
                    healthy_nodes: healthy_count,
                };
                pack_envelope_ok(generated::envelope::Payload::StorageNodeStatsResponse(resp))
            }

            // -------- storage.connectivity --------
            // Diagnostic route: tests TLS handshake + device registration against each
            // configured storage node. Reports CA cert status, per-node reachability,
            // and auth token validity. Use to diagnose why online transfers fail.
            "storage.connectivity" => {
                log::info!("[DSM_SDK] storage.connectivity called");

                let ca_certs = crate::sdk::storage_node_sdk::ca_certs_loaded_count();
                let endpoints = crate::network::list_storage_endpoints().unwrap_or_default();
                let client = crate::sdk::storage_node_sdk::build_ca_aware_client();
                let device_id_b32 =
                    crate::util::text_id::encode_base32_crockford(&self.device_id_bytes);

                let mut node_stats = Vec::with_capacity(endpoints.len());
                let mut healthy_count = 0u32;

                for ep in &endpoints {
                    let start = std::time::Instant::now();
                    let health_url = format!("{ep}/api/v2/health");
                    let (tls_ok, http_status, tls_error) =
                        match client.get(&health_url).send().await {
                            Ok(resp) => {
                                let code = resp.status().as_u16();
                                (true, code.to_string(), String::new())
                            }
                            Err(e) => {
                                let msg = format!("{e}");
                                let is_tls = msg.contains("certificate")
                                    || msg.contains("ssl")
                                    || msg.contains("tls")
                                    || msg.contains("InvalidCertificate")
                                    || msg.contains("UnknownIssuer");
                                let label = if is_tls {
                                    "TLS_CERT_REJECTED"
                                } else if msg.contains("connect") || msg.contains("timeout") {
                                    "NETWORK_UNREACHABLE"
                                } else {
                                    "REQUEST_FAILED"
                                };
                                (false, label.to_string(), msg)
                            }
                        };
                    let latency_ms = start.elapsed().as_millis() as u32;

                    // Try device registration if TLS passed
                    let reg_status = if tls_ok {
                        match crate::sdk::b0x_sdk::B0xSDK::new(
                            device_id_b32.clone(),
                            self.core_sdk.clone(),
                            vec![ep.clone()],
                        ) {
                            Ok(sdk) => match sdk.register_device().await {
                                Ok(_) => "AUTH_OK".to_string(),
                                Err(e) => format!("AUTH_FAIL:{e}"),
                            },
                            Err(e) => format!("SDK_INIT_FAIL:{e}"),
                        }
                    } else {
                        "SKIPPED_TLS_FAIL".to_string()
                    };

                    let status = if tls_ok
                        && http_status.parse::<u16>().map(|c| c < 500).unwrap_or(false)
                        && reg_status == "AUTH_OK"
                    {
                        healthy_count += 1;
                        "healthy".to_string()
                    } else {
                        "down".to_string()
                    };

                    // Encode diagnostic details into last_error as a structured string.
                    let diag = format!(
                        "tls={} http={} auth={} ca_certs={}{}",
                        if tls_ok { "OK" } else { "FAIL" },
                        http_status,
                        reg_status,
                        ca_certs,
                        if tls_error.is_empty() {
                            String::new()
                        } else {
                            format!(" err={}", tls_error)
                        }
                    );

                    let (name, region) = name_and_region_from_endpoint(ep);

                    node_stats.push(generated::StorageNodeStats {
                        url: ep.clone(),
                        name,
                        region,
                        status,
                        latency_ms,
                        last_error: diag,
                        ..Default::default()
                    });
                }

                log::info!(
                    "[storage.connectivity] ca_certs={} nodes={} healthy={}/{}",
                    ca_certs,
                    endpoints.len(),
                    healthy_count,
                    endpoints.len()
                );

                let resp = generated::StorageNodeStatsResponse {
                    nodes: node_stats,
                    total_nodes: endpoints.len() as u32,
                    healthy_nodes: healthy_count,
                };
                pack_envelope_ok(generated::envelope::Payload::StorageNodeStatsResponse(resp))
            }

            // -------- storage.addNode --------
            "storage.addNode" => {
                log::info!("[DSM_SDK] storage.addNode called");
                match generated::ArgPack::decode(&*q.params) {
                    Ok(pack) if pack.codec == generated::Codec::Proto as i32 => {
                        match generated::StorageNodeManageRequest::decode(&*pack.body) {
                            Ok(req) if req.auto_assign => {
                                // Protocol enforcement: node assignment is decided by keyed
                                // Fisher-Yates over the known pool (dsm_env_config.toml minus
                                // active nodes). The caller does not choose which node is added.
                                match crate::network::auto_assign_storage_node(
                                    &self.device_id_bytes,
                                ) {
                                    Ok(assigned_url) => {
                                        let current = crate::network::list_storage_endpoints()
                                            .unwrap_or_default();
                                        let resp = generated::StorageNodeManageResponse {
                                            success: true,
                                            error: String::new(),
                                            current_endpoints: current,
                                            assigned_url,
                                        };
                                        pack_envelope_ok(
                                            generated::envelope::Payload::StorageNodeManageResponse(
                                                resp,
                                            ),
                                        )
                                    }
                                    Err(e) => {
                                        let resp = generated::StorageNodeManageResponse {
                                            success: false,
                                            error: format!("{}", e),
                                            current_endpoints: vec![],
                                            assigned_url: String::new(),
                                        };
                                        pack_envelope_ok(
                                            generated::envelope::Payload::StorageNodeManageResponse(
                                                resp,
                                            ),
                                        )
                                    }
                                }
                            }
                            Ok(_) => {
                                // Reject manual URL selection — node assignment must be
                                // determined by Fisher-Yates for security and even distribution.
                                err("storage.addNode: direct node selection is not permitted; set auto_assign = true".into())
                            }
                            Err(_) => err("storage.addNode: failed to decode request".into()),
                        }
                    }
                    _ => err("storage.addNode: invalid request encoding".into()),
                }
            }

            // -------- storage.removeNode --------
            "storage.removeNode" => {
                log::info!("[DSM_SDK] storage.removeNode called");
                match generated::ArgPack::decode(&*q.params) {
                    Ok(pack) if pack.codec == generated::Codec::Proto as i32 => {
                        match generated::StorageNodeManageRequest::decode(&*pack.body) {
                            Ok(req) if !req.url.is_empty() => {
                                match crate::network::remove_storage_endpoint(&req.url) {
                                    Ok(()) => {
                                        let current = crate::network::list_storage_endpoints()
                                            .unwrap_or_default();
                                        let resp = generated::StorageNodeManageResponse {
                                            success: true,
                                            error: String::new(),
                                            current_endpoints: current,
                                            assigned_url: String::new(),
                                        };
                                        pack_envelope_ok(
                                            generated::envelope::Payload::StorageNodeManageResponse(
                                                resp,
                                            ),
                                        )
                                    }
                                    Err(e) => {
                                        let resp = generated::StorageNodeManageResponse {
                                            success: false,
                                            error: format!("{}", e),
                                            current_endpoints: vec![],
                                            assigned_url: String::new(),
                                        };
                                        pack_envelope_ok(
                                            generated::envelope::Payload::StorageNodeManageResponse(
                                                resp,
                                            ),
                                        )
                                    }
                                }
                            }
                            _ => err("storage.removeNode: missing or invalid url".into()),
                        }
                    }
                    _ => err("storage.removeNode: invalid request encoding".into()),
                }
            }

            other => err(format!("unknown storage query: {other}")),
        }
    }

    /// `diagnostics.metrics` — return a plain-text metrics snapshot.
    ///
    /// Snapshot format: newline-delimited `key=value` lines (no JSON/hex/base64).
    /// Appends `db_bytes=N` from SQLite before returning so callers have storage
    /// context without embedding DB logic in the pure `dsm` crate.
    pub(crate) async fn handle_diagnostics_query(&self, q: AppQuery) -> AppResult {
        match q.path.as_str() {
            "diagnostics.metrics" => {
                let mut snapshot = dsm::telemetry::get_global_metrics_snapshot();
                let db_bytes = crate::storage::client_db::get_db_size().unwrap_or(0);
                snapshot.extend_from_slice(format!("db_bytes={db_bytes}\n").as_bytes());

                // Encode snapshot as UTF-8 string in AppStateResponse.value so
                // the frontend can read it without a new proto field.
                let text = String::from_utf8_lossy(&snapshot).into_owned();
                let resp = generated::AppStateResponse {
                    key: "diagnostics.metrics".to_string(),
                    value: Some(text),
                };
                pack_envelope_ok(generated::envelope::Payload::AppStateResponse(resp))
            }

            other => err(format!("diagnostics: unknown route '{other}'")),
        }
    }
}

/// Check a single storage node's health and scrape its Prometheus metrics.
/// Uses `Instant::now()` for display-only latency measurement (permitted for
/// non-authoritative operational purposes per Hard Invariant §4).
async fn check_single_node_stats(
    client: &reqwest::Client,
    endpoint: &str,
) -> dsm::types::proto::StorageNodeStats {
    use dsm::types::proto::StorageNodeStats;
    use std::collections::HashMap;

    let start = std::time::Instant::now();
    let health_url = format!("{endpoint}/api/v2/health");

    // 1. Health check
    let (status, last_error) = match client.get(&health_url).send().await {
        Ok(resp) if resp.status().is_success() => ("healthy".to_string(), String::new()),
        Ok(resp) => {
            let code = resp.status();
            ("degraded".to_string(), format!("HTTP {code}"))
        }
        Err(e) => ("down".to_string(), format!("{e}")),
    };
    let latency_ms = start.elapsed().as_millis() as u32;

    // 2. Prometheus metrics (best-effort, skip if node is down)
    let prom = if status != "down" {
        let metrics_url = format!("{endpoint}/metrics");
        match client.get(&metrics_url).send().await {
            Ok(resp) if resp.status().is_success() => match resp.text().await {
                Ok(text) => parse_prometheus_text(&text),
                Err(_) => HashMap::new(),
            },
            _ => HashMap::new(),
        }
    } else {
        HashMap::new()
    };

    // 3. Derive name/region from endpoint heuristic (IP-to-region mapping)
    let (name, region) = name_and_region_from_endpoint(endpoint);

    StorageNodeStats {
        url: endpoint.to_string(),
        name,
        region,
        status,
        latency_ms,
        last_error,
        objects_put_total: prom_u64(&prom, "dsm_storage_objects_put_total"),
        objects_get_total: prom_u64(&prom, "dsm_storage_objects_get_total"),
        bytes_written_total: prom_u64(&prom, "dsm_storage_bytes_written_total"),
        bytes_read_total: prom_u64(&prom, "dsm_storage_bytes_read_total"),
        cleanup_runs_total: prom_u64(&prom, "dsm_storage_cleanup_runs_total"),
        replication_failures: prom_u64(&prom, "dsm_replication_outbox_failures_total"),
    }
}

/// Parse Prometheus exposition text format into metric_name → value map.
/// Handles simple gauge/counter lines: `metric_name value [unix_ts]`.
/// This is display-only operational data — not protocol.
fn parse_prometheus_text(text: &str) -> std::collections::HashMap<String, f64> {
    let mut metrics = std::collections::HashMap::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        // Handle optional label sets: e.g. metric_name{label="val"} 42
        let metric_part = if let Some(brace_idx) = trimmed.find('{') {
            if let Some(close_idx) = trimmed.find('}') {
                // metric_name{...} value
                let name = &trimmed[..brace_idx];
                let rest = trimmed[close_idx + 1..].trim();
                if let Some(val_str) = rest.split_whitespace().next() {
                    if let Ok(val) = val_str.parse::<f64>() {
                        metrics.insert(name.to_string(), val);
                    }
                }
                continue;
            }
            trimmed
        } else {
            trimmed
        };
        let mut parts = metric_part.split_whitespace();
        if let (Some(name), Some(val_str)) = (parts.next(), parts.next()) {
            if let Ok(val) = val_str.parse::<f64>() {
                metrics.insert(name.to_string(), val);
            }
        }
    }
    metrics
}

/// Extract a u64 from Prometheus metrics map (display-only).
fn prom_u64(prom: &std::collections::HashMap<String, f64>, key: &str) -> u64 {
    prom.get(key).copied().unwrap_or(0.0) as u64
}

/// Derive human-readable name and region from a storage node endpoint URL.
/// Uses the hardcoded production IP→region mapping.
fn name_and_region_from_endpoint(endpoint: &str) -> (String, String) {
    // GCP 6-node production cluster (must match dsm_env_config.toml)
    let ip_region_map: &[(&str, &str, &str)] = &[
        ("34.73.141.32", "us-east1-a", "us-east1"),
        ("35.243.157.151", "us-east1-b", "us-east1"),
        ("35.205.9.157", "europe-west1-a", "europe-west1"),
        ("34.53.251.120", "europe-west1-b", "europe-west1"),
        ("34.21.157.56", "asia-southeast1-a", "asia-southeast1"),
        ("34.87.93.29", "asia-southeast1-b", "asia-southeast1"),
    ];
    for &(ip, name, region) in ip_region_map {
        if endpoint.contains(ip) {
            return (name.to_string(), region.to_string());
        }
    }
    // Unknown node — derive a short name from the URL
    let short = endpoint
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .split(':')
        .next()
        .unwrap_or(endpoint);
    (
        format!("node-{}", &short[..short.len().min(12)]),
        String::new(),
    )
}

#[cfg(test)]
mod tests {
    use super::select_history_receipt_bytes;

    #[test]
    fn select_history_receipt_bytes_prefers_rebuilt_receipt() {
        let rebuilt = Some(vec![1u8, 2, 3]);
        let fallback = vec![9u8, 9, 9];

        let selected = select_history_receipt_bytes(rebuilt, &fallback);

        assert_eq!(selected, Some(vec![1u8, 2, 3]));
    }

    #[test]
    fn select_history_receipt_bytes_falls_back_to_verified_receipt_commit() {
        let selected = select_history_receipt_bytes(None, &[7u8, 8, 9]);

        assert_eq!(selected, Some(vec![7u8, 8, 9]));
    }
}
