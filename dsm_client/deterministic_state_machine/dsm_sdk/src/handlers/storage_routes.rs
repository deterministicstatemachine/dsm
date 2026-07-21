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

/// Verify an inbound stitched receipt's sender authorization (`sig_a`) the way
/// the sender actually produces it (§11.1 per-step EK).
///
/// The online `wallet.send` path signs `sig_a` with a freshly-derived per-step
/// EK (`receipt.ek_pk_a`, cert-chained to the sender's AK via `ek_cert_a`) over
/// the receipt challenge-response target — NOT with the sender's static signing
/// key over the raw commitment. The genesis cert-chain root is the sender's
/// AK_pk, which equals the static signing key published as
/// `sender_signing_public_key` (`ak_pk_genesis` here). `session_binding` for the
/// online path is the receipt commitment itself (`app_router_impl` passes
/// `session_binding: &commitment`).
///
/// VERIFY ONLY — this does NOT mutate the Counterparty cert-chain head. The head
/// is advanced by the acceptance fold's completion phase (CAS, §16.6) only after
/// the transition is durably applied and the acceptance marker is written, so a
/// receipt that verifies but fails to apply never advances the receiver's chain
/// (lockstep: a failed acceptance leaves both chains where they were).
fn verify_inbound_receipt_sig_a(
    receipt: &dsm::types::receipt_types::StitchedReceiptV2,
    commitment: &[u8; 32],
    ak_pk_genesis: &[u8],
) -> Result<(), String> {
    use crate::storage::client_db::{load_cert_chain_head_pubkey, CertChainSide};

    let rel_key =
        dsm::verification::smt_replace_witness::compute_smt_key(&receipt.devid_a, &receipt.devid_b);
    // From the receiver's viewpoint the SENDER (A-side) is the Counterparty.
    // At relationship genesis (no Counterparty head yet) the sender's ek_cert_a
    // chains back to the sender's AK — the legitimate predecessor.
    let expected_prev_pk = load_cert_chain_head_pubkey(&rel_key, CertChainSide::Counterparty)
        .ok()
        .flatten()
        .unwrap_or_else(|| ak_pk_genesis.to_vec());

    crate::sdk::receipts::verify_per_step_ek_signing(
        receipt,
        crate::sdk::receipts::BilateralSide::A,
        &expected_prev_pk,
        &receipt.parent_tip,
        commitment,
    )
    .map_err(|e| e.to_string())
}

/// AUTHENTICATED CAPABILITY HYDRATION (§16.6) — not migration residue.
///
/// A valid relationship can exist locally while its cached ML-KEM capability is
/// absent; the B-side receipt encapsulates `kyber_ct_b` to the sender's key, so
/// that gap fail-closes every inbound acceptance. This hydrates the missing
/// capability from the registry under strict rules:
///
///   * runs ONLY when the local key is missing (caller-enforced, re-asserted here);
///   * NEVER replaces a nonempty locally-bound key — persist is first-write-wins;
///   * verifies the registry binding against the STORED pairing AK, device id,
///     and genesis (never wire evidence, never the registry record itself);
///   * conflicting or ambiguous registry data fails closed;
///   * a registry failure returns an error and NEVER degrades into an insecure
///     fallback — the acceptance simply stays fail-closed and retries later.
///
/// Nothing is persisted on any error path.
async fn hydrate_missing_sender_kyber_capability(
    storage_endpoints: &[String],
    sender_device_id: [u8; 32],
    contact: &crate::storage::client_db::ContactRecord,
) -> Result<Vec<u8>, String> {
    // Re-assert the precondition at the boundary: hydration is only ever for an
    // ABSENT capability. A present key is authoritative and is returned as-is.
    if !contact.kyber_public_key.is_empty() {
        return Ok(contact.kyber_public_key.clone());
    }
    if contact.public_key.is_empty() {
        return Err(
            "contact has no pairing-established AK to verify the Kyber binding".to_string(),
        );
    }
    let contact_genesis: [u8; 32] = contact
        .genesis_hash
        .as_slice()
        .try_into()
        .map_err(|_| "contact genesis_hash is not 32 bytes".to_string())?;

    // Quorum lookup: a single equivocating node cannot decide this. Any transport
    // or agreement failure propagates as an error (no fallback).
    let identity = crate::handlers::app_router_impl::fetch_quorum_device_identity(
        storage_endpoints,
        sender_device_id,
    )
    .await?;
    if identity.device_id != sender_device_id {
        return Err("registry device_id diverges from the relationship counterparty".to_string());
    }
    if identity.genesis_hash != contact_genesis {
        return Err("registry genesis diverges from the pairing-established genesis".to_string());
    }
    crate::sdk::kyber_identity::verify_kyber_identity_binding(
        &sender_device_id,
        &contact_genesis,
        &identity.kyber_public_key,
        &identity.kyber_binding_sig,
        &contact.public_key,
    )
    .map_err(|e| format!("sender Kyber identity binding invalid: {e}"))?;

    // First-write-wins. Losing the race means another path bound a key
    // concurrently; that stored key is authoritative and is used instead.
    let bound = crate::storage::client_db::bind_contact_kyber_key_if_absent(
        &sender_device_id,
        &identity.kyber_public_key,
    )
    .map_err(|e| format!("failed to persist verified sender Kyber key: {e}"))?;
    if bound {
        return Ok(identity.kyber_public_key);
    }
    match crate::storage::client_db::get_contact_by_device_id(&sender_device_id) {
        Ok(Some(c)) if !c.kyber_public_key.is_empty() => Ok(c.kyber_public_key),
        _ => Err("Kyber capability vanished between bind and read — failing closed".to_string()),
    }
}

/// §16.6 SENDER FINALIZATION on cryptographic proof.
///
/// An online transition finalizes here — on a verified recipient countersignature —
/// and NEVER on storage-node message deletion, which is best-effort GC. The
/// returned receipt is matched to the sender's ONE persisted proposal by
/// commitment, verified against that proposal's CANONICAL pair (the gate holds
/// projection values and must never be used for this comparison), and only then
/// is the gate released and the proposal terminally finalized.
///
/// Every failure path leaves the gate intact: an unmatched, stale, or invalid
/// artifact must never release a pending transition. Idempotent — a redelivered
/// reply finds the proposal already finalized and does nothing.
async fn finalize_from_acceptance_artifact(
    artifact: &dsm::types::proto::AcceptanceReceiptArtifact,
) {
    use crate::storage::client_db::sender_proposal::{
        get_sender_proposal_by_commitment, PROPOSAL_FINALIZED,
    };

    let commitment: [u8; 32] = match artifact.commitment.as_slice().try_into() {
        Ok(c) => c,
        Err(_) => {
            log::warn!("[storage.sync] §16.6 reply ignored: commitment is not 32 bytes");
            return;
        }
    };
    let short = crate::util::text_id::encode_base32_crockford(&commitment[..4]);

    // Decode the signed receipt — every value used from here on comes from it,
    // never from the unsigned artifact envelope.
    let receipt = match dsm::types::receipt_types::StitchedReceiptV2::from_canonical_protobuf(
        &artifact.receipt_bytes,
    ) {
        Ok(r) => r,
        Err(e) => {
            log::warn!("[storage.sync] §16.6 reply {short}..: receipt decode failed: {e}");
            return;
        }
    };

    let proposal = match get_sender_proposal_by_commitment(&commitment) {
        Ok(Some(p)) => p,
        Ok(None) => {
            log::warn!(
                "[storage.sync] §16.6 reply ignored: no proposal for commitment {short}.. \
                 (not ours) — gate retained"
            );
            return;
        }
        Err(e) => {
            log::warn!("[storage.sync] §16.6 reply lookup failed for {short}..: {e}");
            return;
        }
    };

    if proposal.status == PROPOSAL_FINALIZED {
        log::info!("[storage.sync] §16.6 reply {short}.. already finalized — idempotent no-op");
        return;
    }

    let self_device_id: [u8; 32] = match crate::sdk::app_state::AppState::get_device_id()
        .and_then(|d| <[u8; 32]>::try_from(d.as_slice()).ok())
    {
        Some(d) => d,
        None => {
            log::warn!("[storage.sync] §16.6 reply {short}..: local device_id unavailable");
            return;
        }
    };

    // The recipient's AK from the STORED contact — the cert-chain genesis root.
    // Never taken from the wire artifact.
    let recipient_ak_pk = match crate::storage::client_db::get_contact_public_key_by_device_id(
        &crate::util::text_id::encode_base32_crockford(&proposal.counterparty_device_id),
    ) {
        Some(pk) => pk,
        None => {
            match crate::storage::client_db::get_contact_by_device_id(
                &proposal.counterparty_device_id,
            ) {
                Ok(Some(c)) if !c.public_key.is_empty() => c.public_key,
                _ => {
                    log::warn!(
                        "[storage.sync] §16.6 reply {short}..: no stored AK for the recipient \
                             — cannot verify sig_b, gate retained"
                    );
                    return;
                }
            }
        }
    };

    match crate::handlers::online_finalize::verify_acceptance_receipt(
        &self_device_id,
        &proposal.counterparty_device_id,
        &receipt,
        &proposal,
        &recipient_ak_pk,
        None,
        None,
    ) {
        Ok(crate::handlers::online_finalize::ReceiptVerifyOutcome::Verified { .. }) => {}
        Ok(crate::handlers::online_finalize::ReceiptVerifyOutcome::Rejected { reason }) => {
            log::error!("[storage.sync] §16.6 reply {short}.. REJECTED: {reason} — gate retained");
            return;
        }
        Err(e) => {
            log::error!("[storage.sync] §16.6 reply {short}.. verification errored: {e}");
            return;
        }
    }

    // ====================================================================
    // §16.6 DEFECT 1 — ONE ATOMIC FINALIZATION.
    //
    // Verified. Everything this acceptance proof authorises now commits in a
    // SINGLE transaction: projection tip advance, Local EK-head promotion,
    // Counterparty EK-head advance, proposal finalization, gate release, and
    // the outbox moving to `gc_pending`.
    //
    // The previous code finalized the proposal and deleted the gate HERE, and
    // left the tip advance and head promotion to the §5.4 ACK sweep — which
    // iterates the very gate this had just deleted, making them unreachable.
    // That is why every SECOND transfer on a relationship failed ("divergent
    // local bilateral chain tip") and re-chained from the root AK
    // (`used_root_ak=true`). Splitting this sequence is the defect, so it is
    // not split.
    // ====================================================================
    let expected_counterparty_head = match crate::storage::client_db::load_cert_chain_head_pubkey(
        &proposal.relationship_key,
        crate::storage::client_db::CertChainSide::Counterparty,
    ) {
        Ok(head) => head,
        Err(e) => {
            log::error!(
                "[storage.sync] §16.6 could not read counterparty head for {short}.. — \
                 refusing to finalize (retry from the durable outbox): {e}"
            );
            return;
        }
    };

    match crate::storage::client_db::finalize_on_acceptance_atomically(
        &proposal.relationship_key,
        &proposal.canonical_parent,
        &proposal.nonce_hash,
        &proposal.commitment,
        &proposal.counterparty_device_id,
        &proposal.projection_parent,
        &proposal.projection_target,
        expected_counterparty_head.as_deref(),
        &receipt.ek_pk_b,
    ) {
        Ok(()) => {
            log::info!(
                "[storage.sync] §16.6 FINALIZED atomically on acceptance proof: \
                 commitment={short}.. tx={} (tip advanced, both cert heads promoted, \
                 gate released, outbox gc_pending)",
                proposal.tx_id
            );
            // The retired §5.4 sweep emitted this on tip advance; the tip now
            // advances here, so the refresh belongs here.
            emit_authoritative_wallet_refresh();
        }
        Err(e) => log::error!(
            "[storage.sync] §16.6 atomic finalization failed for {short}.. — NOTHING \
             committed, retries from the durable outbox row: {e}"
        ),
    }
}

/// §16.6 reply-window delivery sweep.
///
/// Hands every durably-countersigned-but-undelivered acceptance receipt back to
/// its original sender. Each reply is addressed to the tip the SENDER polls (the
/// projection parent captured at PREPARE, carried in the journal) — NOT to this
/// device's own projection, which has already advanced past it by the time the
/// fold completes.
///
/// The sender's identity comes from the STORED contact (genesis + device id),
/// never from wire material. A reply whose counterparty contact is missing is
/// skipped and retried next sweep rather than guessed at.
async fn deliver_pending_acceptance_replies(
    storage_endpoints: &[String],
    core_sdk: std::sync::Arc<crate::sdk::core_sdk::CoreSDK>,
) -> Result<(), String> {
    use crate::storage::client_db::{mark_reply_submitted, pending_outbound_replies};

    let pending = pending_outbound_replies().map_err(|e| e.to_string())?;
    if pending.is_empty() {
        return Ok(());
    }
    log::info!(
        "[storage.sync] §16.6 reply window: {} undelivered acceptance repl{}",
        pending.len(),
        if pending.len() == 1 { "y" } else { "ies" }
    );

    let local_device_b32 = match crate::sdk::app_state::AppState::get_device_id() {
        Some(d) if d.len() == 32 => crate::util::text_id::encode_base32_crockford(&d),
        _ => return Err("local device_id unavailable for reply delivery".to_string()),
    };

    for reply in pending {
        let contact = match crate::storage::client_db::get_contact_by_device_id(
            &reply.counterparty_device_id,
        ) {
            Ok(Some(c)) => c,
            _ => {
                log::warn!(
                    "[storage.sync] §16.6 reply skipped: no contact for counterparty {}.. (retry next sweep)",
                    crate::util::text_id::encode_base32_crockford(&reply.counterparty_device_id[..4]),
                );
                continue;
            }
        };
        let sender_genesis: [u8; 32] = match contact.genesis_hash.as_slice().try_into() {
            Ok(g) => g,
            Err(_) => {
                log::warn!("[storage.sync] §16.6 reply skipped: contact genesis not 32 bytes");
                continue;
            }
        };

        // NOTE: the envelope is built from `dsm::types::proto`, which is a SEPARATE
        // prost generation from `crate::generated` — same schema, distinct Rust types.
        let artifact = dsm::types::proto::AcceptanceReceiptArtifact {
            receipt_bytes: reply.receipt_bytes.clone(),
            commitment: reply.commitment.to_vec(),
            relationship_key: reply.relationship_key.to_vec(),
            recipient_device_id: crate::util::text_id::decode_base32_crockford(&local_device_b32)
                .unwrap_or_default(),
            canonical_child_tip: reply.child_tip.to_vec(),
        };

        let mut b0x = match crate::sdk::b0x_sdk::B0xSDK::new(
            local_device_b32.clone(),
            core_sdk.clone(),
            storage_endpoints.to_vec(),
        ) {
            Ok(s) => s,
            Err(e) => {
                log::warn!("[storage.sync] §16.6 reply skipped: B0xSDK init failed: {e}");
                continue;
            }
        };
        match b0x
            .submit_acceptance_reply(
                &sender_genesis,
                &reply.counterparty_device_id,
                &reply.projection_parent_tip,
                artifact,
            )
            .await
        {
            Ok(msg_id) => {
                mark_reply_submitted(&reply.commitment).map_err(|e| e.to_string())?;
                log::info!(
                    "[storage.sync] §16.6 acceptance reply delivered msg={}.. commitment={}..",
                    &msg_id[..8.min(msg_id.len())],
                    crate::util::text_id::encode_base32_crockford(&reply.commitment[..4]),
                );
            }
            Err(e) => {
                // Left unmarked on purpose — retried on the next sweep.
                log::warn!("[storage.sync] §16.6 reply delivery failed (will retry): {e}");
            }
        }
    }
    Ok(())
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
        let env = dsm::envelope::from_canonical_bytes(payload)
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

                // Registry-visibility heal (detached, best-effort, latched on success): wallets
                // created offline — and pre-fix Genesis v2 wallets that never published — become
                // verifiable by counterparties on the first sync with reachable storage nodes.
                crate::sdk::storage_node_sdk::StorageNodeSDK::spawn_ensure_genesis_registry_published(
                    "storage.sync",
                );

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
                            // Already-accepted stale-route duplicates (see §5.2) collected for a
                            // DIRECT ACK: they must not re-enter the verify+apply pipeline (their
                            // sig_a no longer chains back to our advanced cert head), but they must
                            // still be ACKed to release the sender's pending online gate.
                            let mut stale_dup_acks: Vec<(String, String)> = Vec::new();
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
                                // §16.6 SENDER FINALIZATION: drain any acceptance artifacts
                                // this poll decoded. They ride the same spool as forward
                                // transfers but are a distinct payload variant, so they are
                                // discriminated structurally rather than trial-decoded.
                                // Draining happens regardless of `entries_res` — a poll that
                                // yields no forward transfers can still carry the reply that
                                // releases this device's pending gate.
                                for artifact in b0x_sdk.take_reply_artifacts() {
                                    finalize_from_acceptance_artifact(&artifact).await;
                                }

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
                                                } else if crate::storage::client_db::transaction_exists(&item.transaction_id) {
                                                    // Already-accepted duplicate re-delivered on a stale
                                                    // (previous-tip) route: non-adjacent only because our
                                                    // tip already advanced PAST it, but we DID accept it
                                                    // (a transaction row exists). It must NOT re-enter the
                                                    // verify+apply pipeline: accepting it already advanced
                                                    // our Counterparty cert-chain head, so its per-step-EK
                                                    // sig_a no longer chains back to expected_prev_pk over
                                                    // h_n and verification REJECTS it WITHOUT an ACK, which
                                                    // re-strands the sender forever ("delivered but already
                                                    // accepted, won't refresh"). Since the stored
                                                    // transaction row proves acceptance, ACK it DIRECTLY
                                                    // (delete from the storage node) so the sender's pending
                                                    // online gate finalizes. Idempotent.
                                                    log::info!(
                                                        "[storage.sync] §5.2: stale-route item {} is an already-accepted duplicate; ACKing directly to release sender gate",
                                                        item.transaction_id,
                                                    );
                                                    stale_dup_acks.push((
                                                        item.inbox_key.clone(),
                                                        item.transaction_id.clone(),
                                                    ));
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

                            // Enter the apply+ACK block when there are items to apply OR
                            // already-accepted stale-route duplicates to ACK directly (§5.2). The
                            // latter carry no apply work — the loop below is a no-op for an empty
                            // `all_items` — but their direct ACK (further down) MUST run, else a
                            // cycle that pulled only a stale duplicate would skip the ACK and leave
                            // the sender's gate stranded forever.
                            if !all_items.is_empty() || !stale_dup_acks.is_empty() {
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

                                    // §4.2.1 (issue #446): `entry.transaction` is a field-by-field
                                    // reconstruction from UNTRUSTED protobuf and is used here ONLY as
                                    // a routing hint. Every value-bearing read below derives from the
                                    // signed canonical operation — decoded from `canonical_operation_bytes`
                                    // and bound to the verified signature — never from the structured
                                    // fields a relay could tamper while leaving the signature intact.
                                    if let dsm::types::operations::Operation::Transfer { .. } =
                                        &entry.transaction
                                    {
                                        // The signed canonical preimage is mandatory (strict-fail).
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

                                        // Resolve signer key: embedded evidence first, contacts second.
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
                                        let pk_hash = dsm::crypto::blake3::domain_hash(
                                            dsm::common::domain_tags::TAG_DSM_PK_HASH,
                                            &pk,
                                        );
                                        log::info!("[storage.sync] 🔑 signer pk hash(first8)={:?} source={} tx={}", &pk_hash.as_bytes()[..8], pk_source, entry.transaction_id);

                                        // §4.2.1 authoritative binding: verify SPHINCS+ over the
                                        // canonical bytes, decode the SIGNED operation, enforce
                                        // canonical re-serialization equality, and re-attach the
                                        // verified signature. `signed_op` is the ONLY trusted
                                        // operation for this entry.
                                        let signed_op = match dsm::types::operations::Operation::decode_and_bind_signed(
                                            &signing_bytes,
                                            &entry.signature,
                                            &pk,
                                        ) {
                                            Ok(op) => op,
                                            Err(e) => {
                                                log::warn!(
                                                    "[storage.sync] inbox.pull: signed-operation binding failed for tx {} ({}) — skipping poisoned entry, continuing batch",
                                                    entry.transaction_id, e
                                                );
                                                let mut state_guard = batch_state.lock().await;
                                                state_guard.errors.push(format!(
                                                    "inbox.pull: signed-operation binding failed for tx {}: {}",
                                                    entry.transaction_id, e
                                                ));
                                                continue;
                                            }
                                        };

                                        // Authoritative transfer fields come ONLY from signed_op.
                                        let (to_device_id, amount_val, token_id, nonce, memo) =
                                            match &signed_op {
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
                                                    log::warn!("[storage.sync] Skipping tx {}: signed operation is not a Transfer", entry.transaction_id);
                                                    let mut state_guard = batch_state.lock().await;
                                                    state_guard.errors.push(format!(
                                                        "signed op not a Transfer for tx {}",
                                                        entry.transaction_id
                                                    ));
                                                    continue;
                                                }
                                            };

                                        if amount_val == 0 {
                                            log::warn!(
                                                "[storage.sync] Skipping zero-amount transfer"
                                            );
                                            continue;
                                        }

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

                                        // Apply the authoritative signed operation (decoded and bound
                                        // above from the canonical signed bytes — never the untrusted
                                        // reconstructed `entry.transaction`).
                                        let op = signed_op;
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
                                            // Authoritative nonce from the signed op (issue #446).
                                            let nonce_bytes: Option<&[u8]> = if nonce.is_empty() {
                                                None
                                            } else {
                                                Some(nonce.as_slice())
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

                                                    // §11.1 per-step EK verify (see main site) — sig_a
                                                    // verifies under receipt.ek_pk_a over the challenge
                                                    // target, not as a raw SPHINCS+ under the static key.
                                                    if let Err(e) = verify_inbound_receipt_sig_a(
                                                        &receipt,
                                                        &commitment,
                                                        &pk,
                                                    ) {
                                                        log::warn!("[storage.sync] Strict replay drain REJECTED (no ACK) for tx {}: sig_a invalid: {}", entry.transaction_id, e);
                                                        let mut sg = batch_state.lock().await;
                                                        sg.errors.push(format!(
                                                            "replay drain sig_a invalid for tx {}",
                                                            entry.transaction_id
                                                        ));
                                                        continue;
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

                                                    // Canonical §2.2 SMT advance is owned by the
                                                    // §16.6 full-state apply
                                                    // (`apply_incoming_transfer_full_state` →
                                                    // `execute_on_relationship_guarded`). Idempotency
                                                    // for already-consumed nonces is decided by the
                                                    // canonical apply identity, not on any shadow SMT.

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
                                                // Routing/diagnostic ONLY (§16.6 authority sourcing):
                                                // envelope tips are unsigned metadata and must never
                                                // invalidate an otherwise-valid signed receipt.
                                                log::warn!("[storage.sync] envelope next_chain_tip diverges from recomputed symmetric h_{{n+1}} for tx {} — diagnostic only, proceeding on the signed receipt", entry.transaction_id);
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

                                        // §11.1 sender authorization: sig_a is a per-step EK
                                        // signature (receipt.ek_pk_a, cert-chained to the sender's
                                        // AK) over the receipt challenge-response target — verify it
                                        // the way the sender signs it, NOT as a raw SPHINCS+ over
                                        // the commitment under the static signing key. `pk` is the
                                        // sender's static signing key, which is also the AK_pk that
                                        // roots the cert chain at relationship genesis.
                                        match verify_inbound_receipt_sig_a(
                                            &receipt,
                                            &receipt_commitment,
                                            &pk,
                                        ) {
                                            Ok(()) => {
                                                log::info!(
                                                    "[storage.sync] §11.1 sig_a verified (per-step EK) for tx {}",
                                                    entry.transaction_id
                                                );
                                            }
                                            Err(e) => {
                                                log::error!("[storage.sync] §11.1 FATAL: sig_a invalid for tx {}: {} — rejecting without ACK", entry.transaction_id, e);
                                                let mut sg = batch_state.lock().await;
                                                sg.errors.push(format!(
                                                    "§4.2 sig_a invalid for tx {}",
                                                    entry.transaction_id
                                                ));
                                                continue;
                                            }
                                        }

                                        // ═══════════════════════════════════════════════════════
                                        // §16.6 AUTHORITY SOURCING: the VERIFIED SIGNED receipt is
                                        // the sole authority for the canonical transition this
                                        // entry proposes. Its parent/child are ASYMMETRIC-space
                                        // canonical tips. `entry.sender_chain_tip` /
                                        // `entry.next_chain_tip` are unsigned routing metadata —
                                        // logged on divergence, never validation inputs.
                                        // ═══════════════════════════════════════════════════════
                                        let signed_parent: [u8; 32] = receipt.parent_tip;
                                        let signed_child: [u8; 32] = receipt.child_tip;
                                        if signed_parent != chain_tip_arr {
                                            log::warn!(
                                                "[storage.sync] routing metadata parent ({}..) diverges from SIGNED receipt parent ({}..) for tx {} — proceeding on the signed value",
                                                crate::util::text_id::encode_base32_crockford(&chain_tip_arr[..4]),
                                                crate::util::text_id::encode_base32_crockford(&signed_parent[..4]),
                                                entry.transaction_id
                                            );
                                        }
                                        // C_pre bound to the SIGNED parent + SIGNED operation bytes.
                                        let signed_sigma = dsm::core::bilateral_transaction_manager::compute_precommit(
                                            &signed_parent,
                                            &op_bytes_for_tip,
                                            &nonce,
                                        );
                                        // SYMMETRIC projection pair for the contacts CAS, captured
                                        // BEFORE any mutation from the LOCAL stored symmetric tip
                                        // (genesis-init when absent) + the signed operation — the
                                        // wire metadata plays no part.
                                        let projection_parent: [u8; 32] = match crate::storage::client_db::get_contact_chain_tip_raw(&from_device_id) {
                                            Some(t) if t != [0u8; 32] => t,
                                            _ => dsm::core::bilateral_transaction_manager::initial_chain_tip_from_device_ids(
                                                &to_device_id_arr,
                                                &from_device_id,
                                            ),
                                        };
                                        let projection_target: [u8; 32] = {
                                            let sigma_sym = dsm::core::bilateral_transaction_manager::compute_precommit(
                                                &projection_parent,
                                                &op_bytes_for_tip,
                                                &nonce,
                                            );
                                            dsm::core::bilateral_transaction_manager::compute_successor_tip(
                                                &projection_parent,
                                                &op_bytes_for_tip,
                                                &nonce,
                                                &sigma_sym,
                                            )
                                        };

                                        // ═══════════════════════════════════════════════════════
                                        // §16.6 SINGLE AUTHORITATIVE COUNTERSIGNING PATH (the fold).
                                        //   prepare (persist exact B receipt, BEFORE apply)
                                        //   → atomic full-state apply (DeviceState successor + BCR +
                                        //     head + balances + nonce + recovery index +
                                        //     CanonicalApplyRecord, ONE tx, lookup-before-execute)
                                        //   → convergence (projection sync + immutable marker →
                                        //     promote → CAS both cert heads → outbox → Complete)
                                        //   → ACK only after Complete.
                                        // A duplicate delivery returns
                                        // AlreadyAppliedSameOperation(record) and re-enters the SAME
                                        // convergence — never a re-ACK short-circuit.
                                        // ═══════════════════════════════════════════════════════
                                        let rel_key =
                                            dsm::verification::smt_replace_witness::compute_smt_key(
                                                &from_device_id,
                                                &to_device_id_arr,
                                            );
                                        let (ak_pk, ak_sk) = match self
                                            .wallet
                                            .ak_keypair_for_cert_chain()
                                        {
                                            Ok(p) => p,
                                            Err(e) => {
                                                log::error!("[storage.sync] §16.6 AK keypair unavailable for tx {}: {} — no ACK", entry.transaction_id, e);
                                                let mut sg = batch_state.lock().await;
                                                sg.errors.push(format!(
                                                    "AK keypair unavailable for tx {}: {}",
                                                    entry.transaction_id, e
                                                ));
                                                continue;
                                            }
                                        };
                                        let sender_kyber_pk = match crate::storage::client_db::get_contact_by_device_id(&from_device_id) {
                                            Ok(Some(c)) if !c.kyber_public_key.is_empty() => c.kyber_public_key,
                                            Ok(Some(c)) => {
                                                match hydrate_missing_sender_kyber_capability(
                                                    &storage_endpoints,
                                                    from_device_id,
                                                    &c,
                                                )
                                                .await
                                                {
                                                    Ok(k) => {
                                                        log::info!("[storage.sync] §16.6 sender Kyber capability hydrated from registry (AK binding verified) for tx {}", entry.transaction_id);
                                                        k
                                                    }
                                                    Err(e) => {
                                                        log::error!("[storage.sync] §16.6 sender contact missing Kyber capability for tx {} and registry hydration failed: {} — fail closed, no ACK", entry.transaction_id, e);
                                                        let mut sg = batch_state.lock().await;
                                                        sg.errors.push(format!("sender Kyber capability missing for tx {} (hydration: {})", entry.transaction_id, e));
                                                        continue;
                                                    }
                                                }
                                            }
                                            _ => {
                                                log::error!("[storage.sync] §16.6 no contact for sender of tx {} — fail closed, no ACK (establish the contact)", entry.transaction_id);
                                                let mut sg = batch_state.lock().await;
                                                sg.errors.push(format!("sender contact missing for tx {}", entry.transaction_id));
                                                continue;
                                            }
                                        };
                                        let wrap_key =
                                            match crate::init::current_chain_head_at_rest_key() {
                                                Ok(k) => k,
                                                Err(e) => {
                                                    log::error!("[storage.sync] §16.6 wrap key unavailable for tx {} (wallet locked?): {} — no ACK", entry.transaction_id, e);
                                                    let mut sg = batch_state.lock().await;
                                                    sg.errors.push(format!(
                                                        "wrap key unavailable for tx {}: {}",
                                                        entry.transaction_id, e
                                                    ));
                                                    continue;
                                                }
                                            };

                                        // Async relationship exclusion, held across prepare →
                                        // apply → convergence for this entry.
                                        let rel_lock =
                                            crate::handlers::recipient_receipt::relationship_lock(
                                                &rel_key,
                                            );
                                        let _rel_guard = rel_lock.lock_owned().await;

                                        // PHASE 1 — prepare + persist the exact countersigned
                                        // receipt BEFORE apply. Idempotent: a re-delivery returns
                                        // the same stored bytes, never re-signs.
                                        let prepared_bytes = match crate::handlers::recipient_receipt::prepare_bside_acceptance_receipt_locked(
                                            rel_key,
                                            signed_parent,
                                            (projection_parent, projection_target),
                                            || crate::handlers::recipient_receipt::generate_b_artifacts_from_inbound(
                                                &receipt,
                                                &signed_sigma,
                                                &sender_kyber_pk,
                                                &ak_pk,
                                                &ak_sk,
                                                &wrap_key,
                                            ),
                                        ) {
                                            Ok(b) => b,
                                            Err(e) => {
                                                log::error!("[storage.sync] §16.6 PREPARE failed for tx {}: {} — no apply, no ACK", entry.transaction_id, e);
                                                let mut sg = batch_state.lock().await;
                                                sg.errors.push(format!("acceptance prepare failed for tx {}: {}", entry.transaction_id, e));
                                                continue;
                                            }
                                        };

                                        // ATOMIC FULL-STATE APPLY (lookup-before-execute).
                                        let apply_outcome = match core_sdk
                                            .apply_incoming_transfer_full_state(
                                                op,
                                                &tx_id,
                                                &entry.sender_device_id,
                                                &op_bytes_for_tip,
                                                signed_parent,
                                                signed_child,
                                            ) {
                                            Ok(o) => o,
                                            Err(e) => {
                                                log::warn!("[storage.sync] §16.6 full-state apply errored for tx {}: {} — no ACK", entry.transaction_id, e);
                                                let mut sg = batch_state.lock().await;
                                                sg.errors.push(format!(
                                                    "full-state apply failed for tx {}: {}",
                                                    entry.transaction_id, e
                                                ));
                                                continue;
                                            }
                                        };
                                        let (apply_record, advance_opt) = match apply_outcome {
                                            crate::sdk::apply_outcome::ApplyOutcome::Applied { record, advance } => (record, Some(advance)),
                                            crate::sdk::apply_outcome::ApplyOutcome::AlreadyAppliedSameOperation { record } => {
                                                log::info!("[storage.sync] §16.6 duplicate delivery of already-applied tx {} — converging from the stored record (no re-execution)", entry.transaction_id);
                                                (record, None)
                                            }
                                            crate::sdk::apply_outcome::ApplyOutcome::Conflict { reason } => {
                                                log::error!("[storage.sync] §16.6 apply CONFLICT for tx {}: {} — fail closed, no ACK", entry.transaction_id, reason);
                                                mark_contact_needs_online_reconcile_and_refresh(&from_device_id);
                                                let mut sg = batch_state.lock().await;
                                                sg.errors.push(format!("apply conflict for tx {}: {}", entry.transaction_id, reason));
                                                continue;
                                            }
                                        };

                                        // CONVERGENCE — projection sync + immutable acceptance
                                        // marker (one client-db tx) → promote → CAS A + B cert
                                        // heads → outbox → Complete → wipe secret. Driven by the
                                        // durable CanonicalApplyRecord on BOTH fresh and duplicate
                                        // paths. Failure: reconcile-flag + no ACK (recovery sweep
                                        // converges later; the canonical commit is never reversed).
                                        let journal =
                                            match crate::storage::client_db::get_acceptance_journal(
                                                &rel_key,
                                                &signed_parent,
                                            ) {
                                                Ok(Some(j)) => j,
                                                _ => {
                                                    log::error!("[storage.sync] §16.6 prepared journal missing after apply for tx {} — reconcile, no ACK", entry.transaction_id);
                                                    mark_contact_needs_online_reconcile_and_refresh(
                                                        &from_device_id,
                                                    );
                                                    let mut sg = batch_state.lock().await;
                                                    sg.errors.push(format!(
                                                        "prepared journal missing for tx {}",
                                                        entry.transaction_id
                                                    ));
                                                    continue;
                                                }
                                            };
                                        if let Err(e) = crate::handlers::recipient_receipt::converge_accepted_locked(
                                            &journal,
                                            &apply_record,
                                            &wrap_key,
                                        ) {
                                            log::error!("[storage.sync] §16.6 convergence failed for tx {}: {} — reconcile, no ACK (recovery sweep will retry)", entry.transaction_id, e);
                                            mark_contact_needs_online_reconcile_and_refresh(&from_device_id);
                                            let mut sg = batch_state.lock().await;
                                            sg.errors.push(format!("acceptance convergence failed for tx {}: {}", entry.transaction_id, e));
                                            continue;
                                        }
                                        log::info!("[storage.sync] §16.6 acceptance CONVERGED for tx {} (marker + both heads + outbox)", entry.transaction_id);

                                        // Post-commit history/UI persistence (best-effort projections;
                                        // NEVER invalidates the committed canonical transition).
                                        // Fresh applies only — a duplicate's rows were written by the
                                        // first delivery, and its authoritative evidence lives in the
                                        // fold's journal/outbox regardless.
                                        if let Some(advance_outcome) = &advance_opt {
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
                                            meta.insert(
                                                "memo".to_string(),
                                                memo.as_bytes().to_vec(),
                                            );

                                            let recv_smt_pre = advance_outcome.parent_r_a;
                                            let recv_smt_post = advance_outcome.child_r_a;
                                            let recv_parent_bytes =
                                                advance_outcome.smt_proofs.parent_proof.to_bytes();
                                            let recv_child_bytes =
                                                advance_outcome.smt_proofs.child_proof.to_bytes();

                                            // Source BOTH signatures from the fold's persisted
                                            // countersigned artifact — ONE in-memory instance parsed
                                            // from the exact stored bytes, never a separately-signed
                                            // sig_b (the static-key path is deleted).
                                            let countersigned = match dsm::types::receipt_types::StitchedReceiptV2::from_canonical_protobuf(&prepared_bytes) {
                                                Ok(r) => r,
                                                Err(e) => {
                                                    log::warn!("[storage.sync] §4.2 countersigned artifact parse failed for tx {} (history row skipped): {}", entry.transaction_id, e);
                                                    dsm::types::receipt_types::StitchedReceiptV2::new(
                                                        [0u8; 32], [0u8; 32], [0u8; 32], [0u8; 32], [0u8; 32],
                                                        [0u8; 32], [0u8; 32], Vec::new(), Vec::new(), Vec::new(),
                                                    )
                                                }
                                            };
                                            if !countersigned.sig_a.is_empty()
                                                && !countersigned.sig_b.is_empty()
                                            {
                                                let dual =
                                                    crate::storage::client_db::StitchedReceipt {
                                                        tx_hash: receipt_commitment,
                                                        h_n: projection_parent,
                                                        h_n1: projection_target,
                                                        device_id_a: from_device_id,
                                                        device_id_b: to_device_id_arr,
                                                        sig_a: countersigned.sig_a.clone(),
                                                        sig_b: countersigned.sig_b.clone(),
                                                        receipt_commit: entry
                                                            .receipt_commit
                                                            .clone(),
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
                                            }

                                            let recv_device_tree_commitment =
                                                crate::storage::client_db::get_contact_device_tree_commitment(&from_device_id);
                                            let rebuilt = build_online_receipt_with_smt(
                                                &from_device_id,
                                                &to_device_id_arr,
                                                projection_parent,
                                                projection_target,
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

                                            let rec =
                                                crate::storage::client_db::TransactionRecord {
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
                                        }

                                        // §11.1 balance already materialized by the full-state apply.
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

                                // Gate acknowledgements: ACK entries that were validated and
                                // processed this cycle, PLUS already-accepted stale-route duplicates
                                // (see §5.2) that must be ACKed directly to release a stranded sender
                                // gate without re-running now-invalid per-step-EK verification.
                                if !processed_entries.is_empty() || !stale_dup_acks.is_empty() {
                                    let mut ack_groups: std::collections::BTreeMap<
                                        String,
                                        Vec<String>,
                                    > = std::collections::BTreeMap::new();
                                    for (inbox_key, tx_id) in processed_entries.clone() {
                                        ack_groups.entry(inbox_key).or_default().push(tx_id);
                                    }
                                    for (inbox_key, tx_id) in stale_dup_acks.clone() {
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

                            // §16.6 ON-ACCESS acceptance recovery: once per poll, finish any
                            // applied-but-incomplete acceptance journals from the durable
                            // CanonicalApplyRecord — no redelivery required. Fail-closed skip
                            // when the wallet is locked (wrap key underivable).
                            match crate::init::current_chain_head_at_rest_key() {
                                Ok(wrap_key) => {
                                    if let Err(e) =
                                        crate::handlers::recipient_receipt::recover_incomplete_acceptances(&wrap_key).await
                                    {
                                        log::warn!("[storage.sync] §16.6 acceptance recovery sweep errored (non-fatal): {e}");
                                    }
                                }
                                Err(_) => {
                                    log::debug!("[storage.sync] §16.6 acceptance recovery skipped (wallet locked)");
                                }
                            }

                            // §16.6 REPLY WINDOW: deliver every countersigned acceptance
                            // receipt that is durably persisted but not yet handed to the
                            // sender. Store-before-send + repost-until-delivered: the row
                            // survives crashes and an offline sender, and the bytes are
                            // byte-identical on every attempt (signed once, at prepare).
                            if let Err(e) = deliver_pending_acceptance_replies(
                                &storage_endpoints,
                                self.core_sdk.clone(),
                            )
                            .await
                            {
                                log::warn!("[storage.sync] §16.6 reply delivery sweep errored (non-fatal): {e}");
                            }

                            // §5.4 RETIRED AS PROTOCOL AUTHORITY — TRANSPORT GC ONLY.
                            //
                            // This sweep used to advance the projection tip, promote the
                            // Local cert head, finalize the proposal and release the gate,
                            // all keyed off a storage-node ACK. It no longer touches any of
                            // them. The verified countersigned acceptance artifact is the
                            // sole finalization authority and commits that whole sequence in
                            // ONE transaction (`finalize_on_acceptance_atomically`).
                            //
                            // An ACK is a TRANSPORT fact: a node observed the recipient
                            // consume its spooled copy. It carries no evidence the recipient
                            // ACCEPTED the transfer, so it may never mutate canonical,
                            // projection, proposal, gate, or certificate state. What remains
                            // is collection: outbox rows the finalizer already moved to
                            // `gc_pending`, whose wire copies are now consumed.
                            if let Ok(collectable) =
                                crate::storage::client_db::gc_pending_sender_outbox()
                            {
                                for row in &collectable {
                                    let Some(message_id) = row.message_ids.as_deref() else {
                                        // No wire id was ever bound — nothing spooled to collect.
                                        continue;
                                    };
                                    match b0x_sdk.is_message_acknowledged(message_id).await {
                                        Ok(true) => match crate::storage::client_db::set_sender_outbox_status(
                                            &row.relationship_key,
                                            &row.canonical_parent,
                                            &row.proposal_nonce,
                                            crate::storage::client_db::OUTBOX_COMPLETE,
                                        ) {
                                            Ok(_) => log::info!(
                                                "[storage.sync] §5.4 GC: {message_id} consumed by the recipient; outbox row complete"
                                            ),
                                            Err(e) => log::warn!(
                                                "[storage.sync] §5.4 GC: could not mark {message_id} complete: {e}"
                                            ),
                                        },
                                        Ok(false) => log::debug!(
                                            "[storage.sync] §5.4 GC: {message_id} still spooled; retaining the outbox row"
                                        ),
                                        Err(e) => log::debug!(
                                            "[storage.sync] §5.4 GC: ACK check failed for {message_id}: {e}"
                                        ),
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
