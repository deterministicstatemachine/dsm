//! BLE Frame Coordinator — Protobuf-only, production-ready
//!
//! - Strict prost/protobuf framing for BLE GATT transport (no serde, no bincode).
//! - Deterministic chunking/reassembly with per-chunk BLAKE3 checksum.
//! - No wall-clock dependence in protocol logic (no time markers stored in state).
//! - Integrates with `BilateralBleHandler` for DSM bilateral prepare/confirm flow.
//!
//! Notes:
//! - `MAX_BLE_CHUNK_SIZE` should reflect negotiated MTU minus ATT/LL + protobuf overhead.
//! - `BleFrameHeader`, `BleFrameType`, `BleChunk`, `Envelope`, `BilateralConfirmRequest`,
//!   and `Hash32` are prost-generated types in `crate::generated`.
//! - This module never serializes domain enums/structs directly — only protobuf messages.

use std::collections::HashMap;
use std::sync::Arc;
use std::convert::TryFrom;

use log::{debug, info, warn};
use prost::Message;
use tokio::sync::Mutex;

use dsm::crypto::blake3::dsm_domain_hasher;
use dsm::types::error::DsmError;

use crate::bluetooth::bilateral_ble_handler::BilateralBleHandler;
use crate::storage::client_db::types::ChunkPersistenceParams;

const MAX_BLE_CHUNK_SIZE: usize = 180;
const MAX_PENDING_REASSEMBLY: usize = 256;

/// Render a short, human-readable identifier for logs.
/// Uses Crockford Base32 via the centralized `text_id` helper.
fn short_id(bytes: &[u8]) -> String {
    crate::util::text_id::encode_base32_crockford(bytes)
}

/// Prost-generated aliases (codegen from .proto)
pub type BleFrameHeader = crate::generated::BleFrameHeader;
pub type BleFrameType = crate::generated::BleFrameType;

/// Chunk record used only within this module (reassembly queue).
#[derive(Debug, Clone)]
pub struct BleChunkMeta {
    pub header: BleFrameHeader,
    pub data: Vec<u8>,
}

/// Result of handling a BLE chunk - includes the frame type and optional response
#[derive(Debug)]
pub struct BleChunkResult {
    pub frame_type: BleFrameType,
    pub response: Option<Vec<u8>>,
}

/// Reassembly buffer for multi-chunk frames.
#[derive(Debug)]
pub struct ReassemblyBuffer {
    pub frame_commitment: [u8; 32],
    pub frame_type: BleFrameType,
    pub total_chunks: u16,
    pub received_chunks: HashMap<u16, BleChunkMeta>,
    pub expected_size: u32,
}

impl ReassemblyBuffer {
    pub fn new(header: &BleFrameHeader, commitment: &[u8; 32]) -> Self {
        Self {
            frame_commitment: *commitment,
            frame_type: BleFrameType::try_from(header.frame_type)
                .unwrap_or(BleFrameType::Unspecified),
            total_chunks: header.total_chunks as u16,
            received_chunks: HashMap::new(),
            expected_size: header.payload_len,
        }
    }

    pub fn insert_chunk(&mut self, seq: u16, meta: BleChunkMeta) {
        self.received_chunks.insert(seq, meta);
    }

    pub fn is_complete(&self) -> bool {
        self.received_chunks.len() == self.total_chunks as usize
    }

    pub fn reassemble(self) -> Result<Vec<u8>, DsmError> {
        let mut result = Vec::with_capacity(self.expected_size as usize);
        for i in 0..self.total_chunks {
            if let Some(meta) = self.received_chunks.get(&i) {
                result.extend_from_slice(&meta.data);
            } else {
                return Err(DsmError::invalid_operation(format!("missing chunk {i}")));
            }
        }
        if result.len() != self.expected_size as usize {
            return Err(DsmError::invalid_operation("reassembled size mismatch"));
        }
        Ok(result)
    }
}

/// BLE frame coordinator: handles chunking, reassembly, and bilateral flow dispatch.
pub struct BleFrameCoordinator {
    bilateral_handler: Arc<BilateralBleHandler>,
    pending_reassembly: Arc<Mutex<HashMap<[u8; 32], ReassemblyBuffer>>>,
    device_id: [u8; 32],
    /// Current sender's BLE address (set during chunk processing for event emission)
    current_sender_ble_address: Arc<Mutex<Option<String>>>,
}

impl BleFrameCoordinator {
    pub fn new(bilateral_handler: Arc<BilateralBleHandler>, device_id: [u8; 32]) -> Self {
        Self {
            bilateral_handler,
            pending_reassembly: Arc::new(Mutex::new(HashMap::new())),
            device_id,
            current_sender_ble_address: Arc::new(Mutex::new(None)),
        }
    }

    /// Compute a 32-bit checksum of the payload using BLAKE3
    fn checksum32(payload: &[u8]) -> u32 {
        let h = dsm::crypto::blake3::domain_hash("DSM/ble-frame-checksum", payload);
        let b = h.as_bytes();
        u32::from_le_bytes([b[0], b[1], b[2], b[3]])
    }

    /// Compute 32-byte content-addressed frame commitment.
    /// Domain: "DSM/ble-frame" per BLAKE3 domain separation (invariant 9).
    /// Same payload + frame_type always produces the same commitment,
    /// enabling cross-session chunk correlation for durable persistence.
    fn content_addressed_frame_commitment(frame_type: i32, payload: &[u8]) -> [u8; 32] {
        let mut hasher = dsm_domain_hasher("DSM/ble-frame");
        hasher.update(payload);
        hasher.update(&[frame_type as u8]);
        *hasher.finalize().as_bytes()
    }

    /// Extract the 32-byte frame commitment from a BleFrameHeader.
    fn extract_frame_commitment(header: &BleFrameHeader) -> [u8; 32] {
        if header.frame_commitment.len() != 32 {
            return [0u8; 32];
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&header.frame_commitment);
        key
    }

    /// Get a reference to the bilateral handler for contact management
    pub fn bilateral_handler(&self) -> &Arc<BilateralBleHandler> {
        &self.bilateral_handler
    }

    /// Public async helper to fetch current shared chain tip for a relationship.
    /// Returns None if relationship unknown or manager not initialized.
    pub async fn get_chain_tip_for(&self, remote: &[u8; 32]) -> Option<[u8; 32]> {
        let mgr_lock = self.bilateral_handler.bilateral_tx_manager().read().await;
        let mgr = &*mgr_lock;
        mgr.get_chain_tip_for(remote)
    }

    /// Given an opaque protobuf payload and a frame type, chunk it into BLE-sized
    /// `BleChunk` messages, each with a `BleFrameHeader`.
    pub fn chunk_message(
        &self,
        message_type: BleFrameType,
        payload: &[u8],
    ) -> Result<Vec<Vec<u8>>, DsmError> {
        if payload.is_empty() {
            return Err(DsmError::invalid_operation(
                "empty payload for chunk_message",
            ));
        }

        // Content-addressed frame commitment: deterministic 32-byte BLAKE3 digest
        // of (payload || frame_type). Same payload always produces same commitment,
        // enabling cross-session chunk correlation for durable persistence.
        let commitment = Self::content_addressed_frame_commitment(message_type as i32, payload);
        let total_size = payload.len() as u32;
        // Compute chunk count using usize::div_ceil for clarity (per-chunk checksum; do NOT precompute over full payload)
        let total_chunks = u16::try_from(payload.len().div_ceil(MAX_BLE_CHUNK_SIZE))
            .map_err(|_| DsmError::invalid_operation("payload too large for BLE chunking"))?;

        let mut chunks = Vec::with_capacity(total_chunks as usize);
        for i in 0..total_chunks {
            let start = (i as usize) * MAX_BLE_CHUNK_SIZE;
            let end = ((i as usize + 1) * MAX_BLE_CHUNK_SIZE).min(payload.len());
            let slice = &payload[start..end];

            // Per-chunk checksum (was previously computed over entire payload causing multi-chunk verification failures)
            let chunk_checksum = Self::checksum32(slice);

            let header = BleFrameHeader {
                frame_type: message_type as i32,
                chunk_index: i as u32,
                total_chunks: total_chunks as u32,
                payload_len: total_size,
                checksum: chunk_checksum,
                frame_commitment: commitment.to_vec(),
            };

            let chunk = crate::generated::BleChunk {
                header: Some(header),
                data: slice.to_vec(),
            };

            let mut buf = Vec::with_capacity(chunk.encoded_len());
            chunk.encode(&mut buf).map_err(|e| {
                DsmError::serialization_error("BleChunk", "protobuf", Some(e.to_string()), Some(e))
            })?;

            chunks.push(buf);
        }

        Ok(chunks)
    }

    /// Set the current sender's BLE address (called before processing chunks)
    pub async fn set_current_sender_ble_address(&self, address: Option<String>) {
        let mut guard = self.current_sender_ble_address.lock().await;
        *guard = address;
    }

    /// Get the current sender's BLE address (for use in event emission)
    pub async fn get_current_sender_ble_address(&self) -> Option<String> {
        let guard = self.current_sender_ble_address.lock().await;
        guard.clone()
    }

    /// Handle a single BLE chunk (protobuf bytes for `BleChunk`) and return an optional
    /// response payload (already chunked and framed if needed).
    pub async fn handle_ble_chunk(
        &self,
        chunk_bytes: &[u8],
    ) -> Result<Option<BleChunkResult>, DsmError> {
        self.handle_ble_chunk_with_address(chunk_bytes, None).await
    }

    /// Handle a single BLE chunk with sender's BLE address for event routing
    pub async fn handle_ble_chunk_with_address(
        &self,
        chunk_bytes: &[u8],
        sender_ble_address: Option<&str>,
    ) -> Result<Option<BleChunkResult>, DsmError> {
        // Store the sender's BLE address for the bilateral handler to use
        if let Some(addr) = sender_ble_address {
            self.set_current_sender_ble_address(Some(addr.to_string()))
                .await;
        }

        let chunk = crate::generated::BleChunk::decode(chunk_bytes).map_err(|e| {
            DsmError::serialization_error("BleChunk", "protobuf", Some(e.to_string()), Some(e))
        })?;

        let header = chunk
            .header
            .as_ref()
            .ok_or_else(|| DsmError::invalid_operation("missing BleFrameHeader"))?;

        let frame_type =
            BleFrameType::try_from(header.frame_type).unwrap_or(BleFrameType::Unspecified);

        let computed_checksum = Self::checksum32(&chunk.data);
        if computed_checksum != header.checksum {
            return Err(DsmError::invalid_operation("BLE chunk checksum mismatch"));
        }

        let frame_commitment = Self::extract_frame_commitment(header);
        let seq = header.chunk_index as u16;

        // Persist chunk to SQLite immediately after checksum validation (sovereign persistence).
        // INSERT OR IGNORE makes this idempotent — duplicate chunks are silently skipped.
        if let Err(e) = crate::storage::client_db::persist_ble_chunk(ChunkPersistenceParams {
            frame_commitment: &frame_commitment,
            chunk_index: seq,
            frame_type: header.frame_type,
            total_chunks: header.total_chunks as u16,
            payload_len: header.payload_len,
            chunk_data: &chunk.data,
            checksum: header.checksum,
            counterparty_id: None, // counterparty_id resolved at session level during cleanup
        }) {
            warn!("Chunk persistence failed (non-fatal): {}", e);
        }

        let mut buffers = self.pending_reassembly.lock().await;

        if !buffers.contains_key(&frame_commitment) {
            // Try hydrating from SQLite before creating a fresh buffer.
            // This is the auto-resume path: if we have persisted chunks from
            // a previous connection attempt, load them into memory.
            let persisted = crate::storage::client_db::load_persisted_chunks(&frame_commitment)
                .unwrap_or_default();

            if buffers.len() >= MAX_PENDING_REASSEMBLY {
                warn!("BLE reassembly buffer full; dropping oldest entry");
                if let Some(key_to_remove) = buffers.keys().next().cloned() {
                    buffers.remove(&key_to_remove);
                }
            }

            let mut buffer = ReassemblyBuffer::new(header, &frame_commitment);
            if !persisted.is_empty() {
                info!(
                    "Auto-hydrating {} persisted chunks for frame {}",
                    persisted.len(),
                    short_id(&frame_commitment[..8])
                );
                for pc in persisted {
                    // Reconstruct minimal header from persisted fields
                    let restored_header = BleFrameHeader {
                        frame_type: pc.frame_type,
                        chunk_index: pc.chunk_index as u32,
                        total_chunks: pc.total_chunks as u32,
                        payload_len: pc.payload_len,
                        checksum: pc.checksum,
                        frame_commitment: frame_commitment.to_vec(),
                    };
                    buffer.insert_chunk(
                        pc.chunk_index,
                        BleChunkMeta {
                            header: restored_header,
                            data: pc.chunk_data,
                        },
                    );
                }
            }
            buffers.insert(frame_commitment, buffer);
        }

        let buffer = buffers
            .get_mut(&frame_commitment)
            .ok_or_else(|| DsmError::invalid_operation("missing reassembly buffer"))?;

        // Deduplicate: skip if we already have this chunk (from hydration or retransmit)
        if !buffer.received_chunks.contains_key(&seq) {
            let meta = BleChunkMeta {
                header: header.clone(),
                data: chunk.data,
            };
            buffer.insert_chunk(seq, meta);
        }

        if !buffer.is_complete() {
            debug!(
                "BLE reassembly in progress: {}/{} chunks for frame {}",
                buffer.received_chunks.len(),
                buffer.total_chunks,
                short_id(&frame_commitment[..8])
            );
            return Ok(None);
        }

        let buffer = buffers
            .remove(&frame_commitment)
            .ok_or_else(|| DsmError::invalid_operation("buffer disappeared during reassembly"))?;
        let payload = buffer.reassemble()?;

        // Cleanup persisted chunks after successful reassembly
        let _ = crate::storage::client_db::delete_frame_chunks(&frame_commitment);

        let next = self
            .process_bilateral_message(&frame_type, &payload)
            .await?;

        Ok(Some(BleChunkResult {
            frame_type,
            response: next,
        }))
    }

    /// Dispatch a fully reassembled bilateral message to the handler.
    ///
    /// Returns an optional response payload (already as raw bytes; caller will
    /// chunk/frame it if needed).
    pub async fn process_bilateral_message(
        &self,
        message_type: &BleFrameType,
        payload: &[u8],
    ) -> Result<Option<Vec<u8>>, DsmError> {
        // Pass current sender BLE address to the handler before processing
        let sender_addr = self.get_current_sender_ble_address().await;
        self.bilateral_handler
            .set_current_sender_ble_address(sender_addr)
            .await;

        match message_type {
            BleFrameType::BilateralPrepare => {
                info!("Processing bilateral prepare request");
                match self.bilateral_handler.handle_prepare_request(payload).await {
                    Ok((response, _meta)) => Ok(Some(response)),
                    Err(e) if e.to_string().contains("silent_drop_duplicate_packet") => {
                        log::warn!("Silently dropping duplicate Prepare request.");
                        Ok(None)
                    }
                    Err(e) => {
                        warn!("BilateralPrepare rejected: {}. Ensure contact is added/verified and synced to BluetoothManager.", e);
                        Err(e)
                    }
                }
            }

            BleFrameType::BilateralPrepareResponse => {
                // Guard: If payload is NOT an Envelope with BilateralPrepareResponse, treat it as a pass-through
                // (e.g., a BleTransactionError wrapped in Envelope->DsmBtMessage). This prevents spurious decode
                // errors and allows error envelopes to bubble directly to the sender.
                let is_prepare_response =
                    match crate::generated::Envelope::decode(&mut std::io::Cursor::new(payload)) {
                        Ok(env) => matches!(
                            env.payload,
                            Some(crate::generated::envelope::Payload::BilateralPrepareResponse(_))
                        ),
                        Err(_) => false,
                    };
                if !is_prepare_response {
                    debug!("Pass-through BilateralPrepareResponse frame (non-prepare-response envelope detected) size={}", payload.len());
                    return Ok(Some(payload.to_vec()));
                }

                info!("Processing bilateral prepare response (validated payload)");
                match self
                    .bilateral_handler
                    .handle_prepare_response(payload)
                    .await
                {
                    Ok((commit_envelope, _meta)) => {
                        info!("Bilateral prepare response processed; emitting commit request envelope ({} bytes)", commit_envelope.len());
                        Ok(Some(commit_envelope))
                    }
                    Err(e) if e.to_string().contains("silent_drop_duplicate_packet") => {
                        log::warn!("Silently dropping duplicate Prepare Response.");
                        Ok(None)
                    }
                    Err(e) => Err(e),
                }
            }

            BleFrameType::BilateralPrepareReject => {
                // Guard rejection: ensure Envelope contains BilateralPrepareReject
                let is_prepare_reject =
                    match crate::generated::Envelope::decode(&mut std::io::Cursor::new(payload)) {
                        Ok(env) => matches!(
                            env.payload,
                            Some(crate::generated::envelope::Payload::BilateralPrepareReject(
                                _
                            ))
                        ),
                        Err(_) => false,
                    };
                if !is_prepare_reject {
                    debug!("Pass-through BilateralPrepareReject frame (non-reject envelope detected) size={}", payload.len());
                    return Ok(Some(payload.to_vec()));
                }

                info!("Processing bilateral prepare rejection (validated payload)");
                self.bilateral_handler
                    .handle_prepare_reject(payload)
                    .await?;
                info!("Bilateral prepare rejection processed; session marked rejected");
                // No response needed for rejection
                Ok(None)
            }

            BleFrameType::BilateralConfirm => {
                // 3-step protocol step 3: Sender's confirm message arrives at receiver.
                // Validate: Envelope contains UniversalTx with Invoke("bilateral.confirm")
                let is_confirm_request =
                    match crate::generated::Envelope::decode(&mut std::io::Cursor::new(payload)) {
                        Ok(env) => {
                            if let Some(crate::generated::envelope::Payload::UniversalTx(tx)) =
                                env.payload
                            {
                                if let Some(op) = tx.ops.first() {
                                    match &op.kind {
                                        Some(crate::generated::universal_op::Kind::Invoke(
                                            invoke,
                                        )) => invoke.method == "bilateral.confirm",
                                        _ => false,
                                    }
                                } else {
                                    false
                                }
                            } else {
                                false
                            }
                        }
                        Err(_) => false,
                    };
                if !is_confirm_request {
                    debug!("Pass-through BilateralConfirm frame (non-confirm UniversalTx detected) size={}", payload.len());
                    return Ok(Some(payload.to_vec()));
                }
                info!("Processing bilateral confirm request (3-step protocol step 3)");

                // Receiver processes the confirm — no response needed (protocol complete)
                match self.bilateral_handler.handle_confirm_request(payload).await {
                    Ok(_meta) => {
                        // Return None: 3-step protocol is complete, no response message needed.
                        // The TRANSFER_COMPLETE event is emitted by handle_confirm_request
                        // so the UI will update via the bilateral event bridge.
                        Ok(None)
                    }
                    Err(e) if e.to_string().contains("silent_drop_duplicate_packet") => {
                        log::warn!("Silently dropping duplicate Confirm Request.");
                        Ok(None)
                    }
                    Err(e) => Err(e),
                }
            }

            BleFrameType::Unspecified => {
                // Pure framing/reassembly path: return payload unchanged so callers can
                // validate chunking without engaging bilateral processing.
                debug!(
                    "Pass-through BLE unspecified frame type: {:?}",
                    message_type
                );
                Ok(Some(payload.to_vec()))
            }
            _ => {
                // Unknown frame type - ignore silently (no compatibility protocol support)
                debug!("Ignoring unknown BLE frame type: {:?}", message_type);
                Ok(None)
            }
        }
    }

    /// Convenience: prepare and chunk an Envelope for a bilateral prepare request.
    pub fn envelope_to_prepare_chunks(
        &self,
        envelope: &crate::generated::Envelope,
    ) -> Result<Vec<Vec<u8>>, DsmError> {
        let mut buf = Vec::with_capacity(envelope.encoded_len());
        envelope.encode(&mut buf).map_err(|e| {
            DsmError::serialization_error("Envelope", "protobuf", Some(e.to_string()), Some(e))
        })?;
        self.chunk_message(BleFrameType::BilateralPrepare, &buf)
    }

    /// Convenience: prepare and chunk an Envelope for a bilateral confirm request.
    pub fn envelope_to_confirm_chunks(
        &self,
        envelope: &crate::generated::Envelope,
    ) -> Result<Vec<Vec<u8>>, DsmError> {
        let mut buf = Vec::with_capacity(envelope.encoded_len());
        envelope.encode(&mut buf).map_err(|e| {
            DsmError::serialization_error("Envelope", "protobuf", Some(e.to_string()), Some(e))
        })?;
        self.chunk_message(BleFrameType::BilateralConfirm, &buf)
    }

    pub fn device_id(&self) -> [u8; 32] {
        self.device_id
    }

    /// Cancel the in-flight Prepared session for `counterparty_device_id`, if any.
    /// Delegates to the handler. Used when the BLE send of a prepare message
    /// fails so that subsequent attempts are not blocked by a stale session.
    pub async fn cancel_prepared_session_for_counterparty(&self, counterparty_device_id: [u8; 32]) {
        self.bilateral_handler
            .cancel_prepared_session_for_counterparty(counterparty_device_id)
            .await;
    }

    /// Create a prepare message and chunk it for BLE transmission.
    /// Wraps the bilateral handler's prepare_bilateral_transaction_with_commitment.
    /// Packs outgoing transfer metadata via transfer_hooks before passing to the handler.
    /// The handler is transport-only and token-agnostic.
    pub async fn create_prepare_message(
        &self,
        counterparty_device_id: [u8; 32],
        operation: dsm::types::operations::Operation,
        validity_iterations: u64,
    ) -> Result<Vec<Vec<u8>>, DsmError> {
        info!(
            "Creating bilateral prepare for counterparty: {}",
            short_id(&counterparty_device_id[..8])
        );

        let (envelope_bytes, _commitment_hash) = self
            .bilateral_handler
            .prepare_bilateral_transaction_with_commitment(
                counterparty_device_id,
                operation,
                validity_iterations,
            )
            .await?;

        self.chunk_message(BleFrameType::BilateralPrepare, &envelope_bytes)
    }

    /// Create a reject message for an incoming prepare and chunk it for BLE transmission.
    pub async fn create_reject_message(
        &self,
        commitment_hash: [u8; 32],
        counterparty_device_id: [u8; 32],
        reason: String,
    ) -> Result<Vec<Vec<u8>>, DsmError> {
        info!(
            "Creating bilateral prepare rejection for commitment: {}",
            short_id(&commitment_hash[..8])
        );

        let envelope_bytes = self
            .bilateral_handler
            .create_prepare_reject_envelope(commitment_hash, counterparty_device_id, reason)
            .await?;

        self.chunk_message(BleFrameType::BilateralPrepareReject, &envelope_bytes)
    }

    /// Create an accept envelope for a pending proposal and return raw bytes.
    /// This is called when the user approves an incoming bilateral proposal.
    /// The envelope should then be chunked and sent over BLE.
    pub async fn create_prepare_accept_envelope(
        &self,
        commitment_hash: [u8; 32],
    ) -> Result<Vec<u8>, DsmError> {
        info!(
            "Creating bilateral accept envelope for commitment: {}",
            short_id(&commitment_hash[..8])
        );

        self.bilateral_handler
            .create_prepare_accept_envelope(commitment_hash)
            .await
    }

    /// Create an accept envelope for a pending proposal and return both raw bytes and counterparty device ID.
    /// The counterparty_device_id is essential for proper BLE chunk addressing.
    pub async fn create_prepare_accept_envelope_with_counterparty(
        &self,
        commitment_hash: [u8; 32],
    ) -> Result<(Vec<u8>, [u8; 32]), DsmError> {
        info!(
            "Creating bilateral accept envelope with counterparty for commitment: {}",
            short_id(&commitment_hash[..8])
        );

        self.bilateral_handler
            .create_prepare_accept_envelope_with_counterparty(commitment_hash)
            .await
    }

    /// Create an accept message (chunked) for a pending proposal.
    /// This wraps create_prepare_accept_envelope and chunks the result.
    pub async fn create_accept_message(
        &self,
        commitment_hash: [u8; 32],
    ) -> Result<Vec<Vec<u8>>, DsmError> {
        let envelope_bytes = self.create_prepare_accept_envelope(commitment_hash).await?;
        self.chunk_message(BleFrameType::BilateralPrepareResponse, &envelope_bytes)
    }

    /// Create a reject envelope with cleanup for a pending proposal and return raw bytes.
    /// This properly cleans up the receiver's pre-commitment before rejection.
    pub async fn create_prepare_reject_envelope_with_cleanup(
        &self,
        commitment_hash: [u8; 32],
        reason: String,
    ) -> Result<Vec<u8>, DsmError> {
        info!(
            "Creating bilateral reject envelope with cleanup for commitment: {}",
            short_id(&commitment_hash[..8])
        );

        self.bilateral_handler
            .create_prepare_reject_envelope_with_cleanup(commitment_hash, reason)
            .await
    }

    /// Create a prepare message and also return the raw 32-byte commitment hash used.
    /// This wraps the same bilateral handler prepare path but exposes the commitment
    /// for higher-level handlers that need to surface it immediately (e.g., BiImpl BLE path).
    pub async fn create_prepare_message_with_commitment(
        &self,
        counterparty_device_id: [u8; 32],
        operation: dsm::types::operations::Operation,
        validity_iterations: u64,
    ) -> Result<(Vec<Vec<u8>>, [u8; 32]), DsmError> {
        let (envelope_bytes, commitment_hash) = self
            .bilateral_handler
            .prepare_bilateral_transaction_with_commitment(
                counterparty_device_id,
                operation,
                validity_iterations,
            )
            .await?;
        let chunks = self.chunk_message(BleFrameType::BilateralPrepare, &envelope_bytes)?;
        Ok((chunks, commitment_hash))
    }

    /// Send a bilateral message by determining its type and chunking it.
    /// Used for responses during the bilateral flow (prepare responses, commit responses).
    pub async fn send_bilateral_message(
        &self,
        counterparty_device_id: [u8; 32],
        message_type: BleFrameType,
        payload: Vec<u8>,
    ) -> Result<Vec<Vec<u8>>, DsmError> {
        debug!(
            "Sending bilateral message type {:?} to counterparty: {}",
            message_type,
            short_id(&counterparty_device_id[..8])
        );

        self.chunk_message(message_type, &payload)
    }
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)]
mod tests {
    use super::*;
    use dsm::common::deterministic_id;
    use dsm::core::bilateral_transaction_manager::BilateralTransactionManager;
    use dsm::core::contact_manager::DsmContactManager;
    use dsm::crypto::signatures::SignatureKeyPair;
    use crate::generated::{Envelope, DsmBtMessage, BtMessageType, BleFrameType};
    use prost::Message;
    use std::sync::Arc;
    use tokio::runtime::Runtime;

    // Helper: build an error envelope (DsmBtMessage -> BleTransactionError) mirroring JNI path
    fn build_error_envelope(device_id: &str, code: i32, message: &str) -> Vec<u8> {
        use crate::generated::{BleTransactionError};
        let err = BleTransactionError {
            device_id: device_id.as_bytes().to_vec(),
            error_code: code,
            message: message.to_string(),
        };
        let mut err_payload = Vec::new();
        err.encode(&mut err_payload).expect("encode error payload");
        let bt = DsmBtMessage {
            message_id: deterministic_id::generate_sequential_id("ble-msg"),
            message_type: BtMessageType::BtmsgTypeError as i32,
            sender_id: Vec::new(),
            recipient_id: Vec::new(),
            payload: err_payload,
            sequence: 0,
            requires_ack: false,
            checksum: 0,
            ack_for: String::new(),
            received_sequence: 0,
        };
        let env = Envelope {
            version: 3,
            headers: Some(crate::generated::Headers {
                device_id: Vec::new(),
                chain_tip: Vec::new(),
                genesis_hash: vec![0; 32],
                seq: 0,
            }),
            message_id: deterministic_id::generate_sequential_id("ble-msg").into_bytes(),
            payload: Some(crate::generated::envelope::Payload::DsmBtMessage(bt)),
        };
        let mut buf = Vec::new();
        env.encode(&mut buf).expect("encode envelope");
        buf
    }

    fn test_coordinator() -> BleFrameCoordinator {
        // Minimal construction: empty contact manager, fresh keypair
        let mut dev_id = [0u8; 32];
        dev_id[0] = 1; // distinguish from zero-array
        let mut genesis = [0u8; 32];
        genesis[0] = 2;
        let contact_mgr = DsmContactManager::new(dev_id, vec![]);
        let kp = SignatureKeyPair::new().expect("keypair");
        let tx_mgr = BilateralTransactionManager::new(contact_mgr, kp, dev_id, genesis);
        let handler = BilateralBleHandler::new(Arc::new(tokio::sync::RwLock::new(tx_mgr)), dev_id);
        BleFrameCoordinator::new(Arc::new(handler), dev_id)
    }

    #[test]
    fn pass_through_prepare_response_error_envelope() {
        let coord = test_coordinator();
        let payload = build_error_envelope("AA:BB:CC:DD:EE:FF", -99, "test_error");
        let rt = Runtime::new().expect("runtime");
        let result = rt
            .block_on(
                coord.process_bilateral_message(&BleFrameType::BilateralPrepareResponse, &payload),
            )
            .expect("process");
        assert!(result.is_some(), "Expected Some(pass-through payload)");
        let returned = result.unwrap();
        assert_eq!(
            returned, payload,
            "Payload should be passed through unchanged"
        );
    }

    #[test]
    fn pass_through_confirm_error_envelope() {
        let coord = test_coordinator();
        let payload = build_error_envelope("11:22:33:44:55:66", -42, "confirm_error");
        let rt = Runtime::new().expect("runtime");
        let result = rt
            .block_on(coord.process_bilateral_message(&BleFrameType::BilateralConfirm, &payload))
            .expect("process");
        assert!(result.is_some(), "Expected Some(pass-through payload)");
        let returned = result.unwrap();
        assert_eq!(
            returned, payload,
            "Payload should be passed through unchanged"
        );
    }

    #[test]
    fn prepare_reject_marks_sender_rejected() {
        use dsm::types::contact_types::DsmVerifiedContact;
        use dsm::types::operations::Operation;
        let mut counterparty = [0u8; 32];
        counterparty[0] = 9;

        // Build coordinator + access handler/manager
        let coord = test_coordinator();
        let handler = &coord.bilateral_handler;
        let rt = Runtime::new().expect("runtime");

        // Add verified contact & establish relationship
        rt.block_on(async {
            let mut mgr = handler.bilateral_tx_manager().write().await;
            if !mgr.has_verified_contact(&counterparty) {
                let contact = DsmVerifiedContact {
                    alias: "ct".to_string(),
                    device_id: counterparty,
                    genesis_hash: mgr.local_genesis_hash(),
                    public_key: vec![7u8; 32],
                    genesis_material: vec![],
                    chain_tip: None,
                    chain_tip_smt_proof: None,
                    genesis_verified_online: true,
                    verified_at_commit_height: 5,
                    added_at_commit_height: 5,
                    last_updated_commit_height: 5,
                    verifying_storage_nodes: vec![],
                    ble_address: None,
                };
                let _ = mgr.add_verified_contact(contact);
            }
            if mgr.get_relationship(&counterparty).is_none() {
                let _ = mgr.establish_relationship(&counterparty).await;
            }
        });

        // Create pre-commitment (sender prepare path)
        let pre_commitment = rt.block_on(async {
            let mut mgr = handler.bilateral_tx_manager().write().await;
            mgr.prepare_offline_transfer(&counterparty, Operation::Noop, 100)
                .await
                .expect("precommit")
        });
        let commitment_hash = pre_commitment.bilateral_commitment_hash;

        // Insert Prepared session (sender sent prepare, awaiting response)
        rt.block_on(async {
            use crate::bluetooth::bilateral_ble_handler::{BilateralBleSession, BilateralPhase};
            handler
                .test_insert_session(BilateralBleSession {
                    commitment_hash,
                    local_commitment_hash: None,
                    counterparty_device_id: counterparty,
                    counterparty_genesis_hash: None,
                    operation: Operation::Noop,
                    phase: BilateralPhase::Prepared,
                    local_signature: Some(pre_commitment.local_signature.clone()),
                    counterparty_signature: None,
                    created_at_ticks: pre_commitment.created_at,
                    expires_at_ticks: pre_commitment.expires_at,
                    sender_ble_address: None,
                    created_at_wall: std::time::Instant::now(),
                    pre_finalize_entropy: None,
                })
                .await;
        });

        // Build a BilateralPrepareReject envelope
        let reject_msg = crate::generated::BilateralPrepareReject {
            commitment_hash: Some(crate::generated::Hash32 {
                v: commitment_hash.to_vec(),
            }),
            reason: "User declined transfer".to_string(),
            rejector_device_id: counterparty.to_vec(),
        };
        let env = crate::generated::Envelope {
            version: 3,
            headers: Some(crate::generated::Headers {
                device_id: counterparty.to_vec(),
                chain_tip: vec![],
                genesis_hash: vec![0; 32],
                seq: 0,
            }),
            message_id: deterministic_id::generate_sequential_id("ble-msg").into_bytes(),
            payload: Some(crate::generated::envelope::Payload::BilateralPrepareReject(
                reject_msg,
            )),
        };
        let mut env_buf = Vec::new();
        env.encode(&mut env_buf).expect("encode reject envelope");

        // Process rejection
        let result = rt
            .block_on(
                coord.process_bilateral_message(&BleFrameType::BilateralPrepareReject, &env_buf),
            )
            .expect("process reject");
        assert!(
            result.is_none(),
            "Reject processing should return None (no response)"
        );

        // Verify sender session marked rejected
        rt.block_on(async {
            let phase = handler
                .get_session_phase(&commitment_hash)
                .await
                .expect("session phase");
            assert_eq!(
                phase as u8,
                crate::bluetooth::bilateral_ble_handler::BilateralPhase::Rejected as u8,
                "Session phase should be rejected"
            );
        });
    }

    #[test]
    fn unspecified_frame_pass_through() {
        let coord = test_coordinator();
        let rt = Runtime::new().expect("runtime");

        rt.block_on(async {
            // Create a BleFrameType::Unspecified to simulate an unknown frame
            let frame_type = BleFrameType::Unspecified;
            let mock_payload = vec![1, 2, 3, 4];

            let result = coord
                .process_bilateral_message(&frame_type, &mock_payload)
                .await;

            // For Unspecified, it should pass through unchanged
            assert!(
                result.is_ok(),
                "Processing unspecified frame should succeed"
            );
            let response = result.unwrap();
            assert!(response.is_some(), "Unspecified frame should pass through");
            assert_eq!(
                response.unwrap(),
                mock_payload,
                "Payload should be unchanged"
            );
        });
    }

    #[test]
    fn unspecified_frame_type_pass_through() {
        let coord = test_coordinator();
        let rt = Runtime::new().expect("runtime");

        rt.block_on(async {
            // Test with BleFrameType::Unspecified (which has value 0)
            let frame_type = BleFrameType::Unspecified;
            let mock_payload = vec![5, 6, 7, 8];

            let result = coord
                .process_bilateral_message(&frame_type, &mock_payload)
                .await;

            // Unspecified should pass through, not be ignored
            assert!(
                result.is_ok(),
                "Processing unspecified frame should succeed"
            );
            let response = result.unwrap();
            assert!(response.is_some(), "Unspecified frame should pass through");
            assert_eq!(
                response.unwrap(),
                mock_payload,
                "Payload should be unchanged"
            );
        });
    }

    #[test]
    fn test_handle_ble_chunk_with_modern_frame() {
        let coord = test_coordinator();
        let rt = Runtime::new().expect("runtime");

        rt.block_on(async {
            // Create a chunk with a modern frame type
            let modern_payload = vec![5, 6, 7, 8]; // Some dummy payload

            // Create BleChunk with header
            let header = crate::generated::BleFrameHeader {
                frame_type: 200, // Modern frame type
                total_chunks: 1,
                chunk_index: 0,
                payload_len: modern_payload.len() as u32,
                checksum: BleFrameCoordinator::checksum32(&modern_payload),
                frame_commitment: BleFrameCoordinator::content_addressed_frame_commitment(
                    200,
                    &modern_payload,
                )
                .to_vec(),
            };

            let chunk = crate::generated::BleChunk {
                header: Some(header),
                data: modern_payload.clone(),
            };

            let mut chunk_bytes = Vec::new();
            chunk.encode(&mut chunk_bytes).unwrap();

            // Handle the chunk - should pass through to normal processing
            let result = coord
                .handle_ble_chunk_with_address(&chunk_bytes, Some("test_device"))
                .await;

            // For modern frames that are not recognized, they get treated as Unspecified
            // and return the payload as a pass-through response
            assert!(result.is_ok());
            let chunk_result = result.unwrap();
            assert!(chunk_result.is_some());

            let chunk_result = chunk_result.unwrap();
            // Should have a response containing the original payload
            assert!(chunk_result.response.is_some());
            let response_data = chunk_result.response.unwrap();
            assert!(!response_data.is_empty());
        });
    }
}
