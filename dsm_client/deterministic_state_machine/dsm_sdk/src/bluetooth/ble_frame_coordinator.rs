//! BLE Frame Coordinator — Protobuf-only transport framing.
//!
//! - Strict prost/protobuf framing for BLE GATT transport (no serde, no bincode).
//! - Deterministic chunking/reassembly with per-chunk BLAKE3 checksum.
//! - No wall-clock dependence in protocol logic (no time markers stored in state).
//! - Emits opaque payload bytes upward; protocol semantics stay above transport.
//!
//! Notes:
//! - `MAX_BLE_CHUNK_SIZE` should reflect negotiated MTU minus ATT/LL + protobuf overhead.
//! - `BleFrameHeader`, `BleFrameType`, `BleChunk`, `Envelope`, `BilateralConfirmRequest`,
//!   and `Hash32` are prost-generated types in `crate::generated`.
//! - This module never serializes domain enums/structs directly — only protobuf messages.

use std::collections::HashMap;
use std::convert::TryFrom;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bitflags::bitflags;
use log::{debug, info, warn};
use prost::Message;
use tokio::sync::Mutex;

use dsm::crypto::blake3::dsm_domain_hasher;
use dsm::types::error::DsmError;

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
pub type BleTransportHeader = crate::generated::BleTransportHeader;
pub type BleTransportChunk = crate::generated::BleTransportChunk;
pub type BleTransportAck = crate::generated::BleTransportAck;

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct BleTransportFlags: u32 {
        const DATA = 0x01;
        const SYN = 0x02;
        const ACK = 0x04;
        const NACK = 0x08;
        const FIN = 0x10;
        const KEEPALIVE = 0x20;
    }
}

pub const BLE_TRANSPORT_VERSION: u32 = 1;
pub const DEFAULT_TRANSPORT_WINDOW_SIZE: usize = 4;
pub const DEFAULT_TRANSPORT_MAX_COMPLETED_CACHE: usize = 256;

/// Transport-only timing and retry controls.
///
/// These settings govern BLE delivery behavior only. They never alter DSM
/// protocol semantics, acceptance predicates, or commitment bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportConfig {
    pub ack_timeout: Duration,
    pub idle_timeout: Duration,
    pub reassembly_timeout: Duration,
    pub connect_timeout: Duration,
    pub max_retries: u8,
    pub window_size: usize,
    pub max_completed_cache: usize,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            ack_timeout: Duration::from_millis(500),
            idle_timeout: Duration::from_secs(15),
            reassembly_timeout: Duration::from_secs(10),
            connect_timeout: Duration::from_secs(8),
            max_retries: 5,
            window_size: DEFAULT_TRANSPORT_WINDOW_SIZE,
            max_completed_cache: DEFAULT_TRANSPORT_MAX_COMPLETED_CACHE,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TransportMessageKey {
    pub session_id: u64,
    pub message_id: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboundTransportMessage {
    pub key: TransportMessageKey,
    pub chunks: Vec<Vec<u8>>,
    pub acked: Vec<bool>,
    pub retries: u8,
    pub next_send_index: usize,
    pub last_progress_at: Instant,
}

impl OutboundTransportMessage {
    #[must_use]
    pub fn new(key: TransportMessageKey, chunks: Vec<Vec<u8>>, now: Instant) -> Self {
        let acked = vec![false; chunks.len()];
        Self {
            key,
            chunks,
            acked,
            retries: 0,
            next_send_index: 0,
            last_progress_at: now,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartialTransportMessage {
    pub key: TransportMessageKey,
    pub chunk_count: u16,
    pub chunks: Vec<Option<Vec<u8>>>,
    pub received: Vec<bool>,
    pub first_seen_at: Instant,
    pub last_updated_at: Instant,
}

impl PartialTransportMessage {
    #[must_use]
    pub fn new(key: TransportMessageKey, chunk_count: u16, now: Instant) -> Self {
        let len = usize::from(chunk_count);
        Self {
            key,
            chunk_count,
            chunks: vec![None; len],
            received: vec![false; len],
            first_seen_at: now,
            last_updated_at: now,
        }
    }

    pub fn insert_chunk(
        &mut self,
        chunk_index: u16,
        payload: Vec<u8>,
        now: Instant,
    ) -> Result<(), DsmError> {
        let idx = usize::from(chunk_index);
        if idx >= self.chunks.len() {
            return Err(DsmError::invalid_operation(
                "transport chunk index out of bounds",
            ));
        }
        self.chunks[idx] = Some(payload);
        self.received[idx] = true;
        self.last_updated_at = now;
        Ok(())
    }

    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.received.iter().all(|received| *received)
    }

    pub fn reassemble(&self) -> Result<Vec<u8>, DsmError> {
        let total_size = self
            .chunks
            .iter()
            .map(|chunk| chunk.as_ref().map_or(0usize, Vec::len))
            .sum();
        let mut payload = Vec::with_capacity(total_size);
        for chunk in &self.chunks {
            let bytes = chunk
                .as_ref()
                .ok_or_else(|| DsmError::invalid_operation("transport message missing chunk"))?;
            payload.extend_from_slice(bytes);
        }
        Ok(payload)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportError {
    PeerDisconnected,
    AckTimeout,
    RetryExceeded,
    ChecksumMismatch,
    SessionMismatch,
    ReassemblyExpired,
    MtuTooSmall,
    InvalidFrame(&'static str),
}

#[derive(Debug, Clone, PartialEq)]
pub enum BleTransportFrame {
    Chunk(BleTransportChunk),
    Ack(BleTransportAck),
}

/// Chunk record used only within this module (reassembly queue).
#[derive(Debug, Clone)]
pub struct BleChunkMeta {
    pub header: BleFrameHeader,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BleTransportMessage {
    pub frame_type: BleFrameType,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum FrameControlMessage {
    TransportAck(BleTransportAck),
}

#[derive(Debug, Clone, PartialEq)]
pub enum FrameIngressResult {
    NeedMoreChunks,
    MessageComplete { message: BleTransportMessage },
    ProtocolControl(FrameControlMessage),
}

/// Reassembly buffer for multi-chunk frames.
///
/// Transport-only timing: `created_at` is used for idle expiry and stale-session
/// recovery (rules.instructions.md §36). It never enters protocol semantics.
#[derive(Debug)]
pub struct ReassemblyBuffer {
    pub frame_commitment: [u8; 32],
    pub frame_type: BleFrameType,
    pub total_chunks: u16,
    pub received_chunks: HashMap<u16, BleChunkMeta>,
    pub expected_size: u32,
    /// Transport-only: wall-clock instant when this buffer was created.
    /// Used for reassembly timeout enforcement and LRU eviction.
    pub created_at: Instant,
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
            created_at: Instant::now(),
        }
    }

    pub fn insert_chunk(&mut self, seq: u16, meta: BleChunkMeta) {
        self.received_chunks.insert(seq, meta);
    }

    pub fn is_complete(&self) -> bool {
        self.received_chunks.len() == self.total_chunks as usize
    }

    /// Reassemble all chunks into the original payload, then verify frame-level
    /// BLAKE3 integrity against `frame_commitment`.
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

        // P0.2: Frame-level BLAKE3 integrity check.
        // Recompute content_addressed_frame_commitment over the full reassembled
        // payload and compare against the commitment carried in chunk headers.
        // Catches: SQLite corruption, mis-ordered cross-frame chunks, partial overwrites.
        let recomputed = BleFrameCoordinator::content_addressed_frame_commitment(
            self.frame_type as i32,
            &result,
        );
        if recomputed != self.frame_commitment {
            return Err(DsmError::invalid_operation(format!(
                "frame integrity check failed: expected {}, got {}",
                short_id(&self.frame_commitment[..8]),
                short_id(&recomputed[..8])
            )));
        }

        Ok(result)
    }
}

/// BLE frame coordinator: handles chunking, reassembly, and bilateral flow dispatch.
pub struct BleFrameCoordinator {
    pending_reassembly: Arc<Mutex<HashMap<[u8; 32], ReassemblyBuffer>>>,
    device_id: [u8; 32],
}

impl BleFrameCoordinator {
    fn transport_checksum(payload: &[u8]) -> u32 {
        crc32fast::hash(payload)
    }

    fn selective_ack_bitmap(received: &[bool], ack_base_chunk: u16) -> Vec<u8> {
        let start = usize::from(ack_base_chunk);
        if start >= received.len() {
            return Vec::new();
        }

        let mut bitmap = vec![0u8; (received.len() - start).div_ceil(8)];
        for (offset, chunk_received) in received.iter().enumerate().skip(start) {
            if *chunk_received {
                let rel = offset - start;
                bitmap[rel / 8] |= 1u8 << (rel % 8);
            }
        }
        bitmap
    }

    #[must_use]
    pub fn highest_contiguous_chunk(received: &[bool]) -> u16 {
        let mut highest = 0u16;
        for (idx, chunk_received) in received.iter().enumerate() {
            if !*chunk_received {
                break;
            }
            highest = u16::try_from(idx + 1).unwrap_or(u16::MAX);
        }
        highest
    }

    /// Chunk a transport payload into `BleTransportChunk` messages.
    ///
    /// The caller supplies the negotiated payload budget after MTU and GATT overhead.
    /// This preserves the protocol payload as opaque Envelope bytes above transport.
    pub fn chunk_transport_payload(
        &self,
        session_id: u64,
        message_id: u64,
        payload: &[u8],
        max_chunk_payload: usize,
    ) -> Result<Vec<Vec<u8>>, DsmError> {
        if payload.is_empty() {
            return Err(DsmError::invalid_operation(
                "empty payload for transport chunking",
            ));
        }
        if max_chunk_payload == 0 {
            return Err(DsmError::invalid_operation(
                "transport chunk size must be > 0",
            ));
        }

        let chunk_count = u32::try_from(payload.len().div_ceil(max_chunk_payload))
            .map_err(|_| DsmError::invalid_operation("payload too large for transport chunking"))?;
        let mut chunks = Vec::with_capacity(chunk_count as usize);

        for chunk_index in 0..chunk_count {
            let start = (chunk_index as usize) * max_chunk_payload;
            let end = ((chunk_index as usize + 1) * max_chunk_payload).min(payload.len());
            let chunk_payload = payload[start..end].to_vec();
            let header = BleTransportHeader {
                version: BLE_TRANSPORT_VERSION,
                flags: BleTransportFlags::DATA.bits(),
                session_id,
                message_id,
                chunk_index,
                chunk_count,
                payload_len: u32::try_from(chunk_payload.len()).map_err(|_| {
                    DsmError::invalid_operation("transport chunk payload too large")
                })?,
                checksum: Self::transport_checksum(&chunk_payload),
            };
            let chunk = BleTransportChunk {
                header: Some(header),
                payload: chunk_payload,
            };
            let mut buf = Vec::with_capacity(chunk.encoded_len());
            chunk.encode(&mut buf).map_err(|e| {
                DsmError::serialization_error(
                    "BleTransportChunk",
                    "protobuf",
                    Some(e.to_string()),
                    Some(e),
                )
            })?;
            chunks.push(buf);
        }

        Ok(chunks)
    }

    pub fn build_transport_ack(
        &self,
        session_id: u64,
        message_id: u64,
        received: &[bool],
    ) -> BleTransportAck {
        let ack_base_chunk = Self::highest_contiguous_chunk(received);
        BleTransportAck {
            session_id,
            message_id,
            ack_base_chunk: u32::from(ack_base_chunk),
            ack_bitmap: Self::selective_ack_bitmap(received, ack_base_chunk),
        }
    }

    pub fn encode_transport_ack(
        &self,
        session_id: u64,
        message_id: u64,
        received: &[bool],
    ) -> Result<Vec<u8>, DsmError> {
        let ack = self.build_transport_ack(session_id, message_id, received);
        let mut buf = Vec::with_capacity(ack.encoded_len());
        ack.encode(&mut buf).map_err(|e| {
            DsmError::serialization_error(
                "BleTransportAck",
                "protobuf",
                Some(e.to_string()),
                Some(e),
            )
        })?;
        Ok(buf)
    }

    pub fn decode_transport_frame(frame_bytes: &[u8]) -> Result<BleTransportFrame, DsmError> {
        if let Ok(chunk) = BleTransportChunk::decode(frame_bytes) {
            let header = chunk
                .header
                .as_ref()
                .ok_or_else(|| DsmError::invalid_operation("missing transport chunk header"))?;
            if header.version != BLE_TRANSPORT_VERSION {
                return Err(DsmError::invalid_operation(
                    "unsupported transport chunk version",
                ));
            }
            if header.payload_len != u32::try_from(chunk.payload.len()).unwrap_or(u32::MAX) {
                return Err(DsmError::invalid_operation(
                    "transport chunk payload length mismatch",
                ));
            }
            let checksum = Self::transport_checksum(&chunk.payload);
            if header.checksum != checksum {
                return Err(DsmError::invalid_operation(
                    "transport chunk checksum mismatch",
                ));
            }
            return Ok(BleTransportFrame::Chunk(chunk));
        }

        let ack = BleTransportAck::decode(frame_bytes).map_err(|e| {
            DsmError::serialization_error(
                "BleTransportFrame",
                "protobuf",
                Some(e.to_string()),
                Some(e),
            )
        })?;
        Ok(BleTransportFrame::Ack(ack))
    }

    pub fn new(device_id: [u8; 32]) -> Self {
        Self {
            pending_reassembly: Arc::new(Mutex::new(HashMap::new())),
            device_id,
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

    /// Given an opaque protobuf payload and a frame type, chunk it into BLE-sized
    /// `BleChunk` messages, each with a `BleFrameHeader`.
    pub fn encode_message(
        &self,
        message_type: BleFrameType,
        payload: &[u8],
    ) -> Result<Vec<Vec<u8>>, DsmError> {
        if payload.is_empty() {
            return Err(DsmError::invalid_operation(
                "empty payload for encode_message",
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

    /// Backward-compatible alias for transport-only framing.
    pub fn chunk_message(
        &self,
        message_type: BleFrameType,
        payload: &[u8],
    ) -> Result<Vec<Vec<u8>>, DsmError> {
        self.encode_message(message_type, payload)
    }

    /// Handle a single BLE chunk (protobuf bytes for `BleChunk`) and return transport ingress state.
    pub async fn ingest_chunk(&self, chunk_bytes: &[u8]) -> Result<FrameIngressResult, DsmError> {
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

        // P0.1: Sweep expired reassembly buffers before processing new chunk.
        // Transport-only timing (rules.instructions.md §36: "idle expiry, stale-session recovery").
        // Timeout scales with frame size: large bilateral confirm envelopes
        // (262 chunks / 47KB) need more time over BLE than small frames.
        let now = Instant::now();
        let expired: Vec<[u8; 32]> = buffers
            .iter()
            .filter(|(_, buf)| {
                let timeout = match buf.total_chunks {
                    0..=10 => Duration::from_secs(10),
                    11..=100 => Duration::from_secs(30),
                    _ => Duration::from_secs(60),
                };
                now.duration_since(buf.created_at) > timeout
            })
            .map(|(k, buf)| {
                warn!(
                    "BLE reassembly timeout: frame {} expired ({}/{} chunks received)",
                    short_id(&k[..8]),
                    buf.received_chunks.len(),
                    buf.total_chunks
                );
                *k
            })
            .collect();
        for key in &expired {
            // Evict in-memory buffer to free RAM, but preserve persisted
            // chunks in SQLite. When the next chunk arrives for this frame,
            // auto-hydration (line 635) will reload them and resume
            // reassembly. Persisted chunks are cleaned up after successful
            // reassembly (line 734) or by the periodic stale-frame sweep.
            buffers.remove(key);
        }

        if !buffers.contains_key(&frame_commitment) {
            // Try hydrating from SQLite before creating a fresh buffer.
            // This is the auto-resume path: if we have persisted chunks from
            // a previous connection attempt, load them into memory.
            let persisted = crate::storage::client_db::load_persisted_chunks(&frame_commitment)
                .unwrap_or_default();

            // P1.4: LRU eviction — evict the oldest buffer by created_at, not arbitrary insertion order.
            if buffers.len() >= MAX_PENDING_REASSEMBLY {
                if let Some(oldest_key) =
                    buffers
                        .iter()
                        .min_by_key(|(_, buf)| buf.created_at)
                        .map(|(k, buf)| {
                            warn!(
                                "BLE reassembly buffer full; evicting oldest frame {} ({}/{} chunks)",
                                short_id(&k[..8]),
                                buf.received_chunks.len(),
                                buf.total_chunks
                            );
                            *k
                        })
                {
                    buffers.remove(&oldest_key);
                    let _ = crate::storage::client_db::delete_frame_chunks(&oldest_key);
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
                    // P0.3: Revalidate checksum on hydration — catch SQLite corruption.
                    let recomputed = Self::checksum32(&pc.chunk_data);
                    if recomputed != pc.checksum {
                        warn!(
                            "Hydration checksum mismatch for frame {} chunk {} (expected {}, got {}) — skipping corrupt chunk",
                            short_id(&frame_commitment[..8]),
                            pc.chunk_index,
                            pc.checksum,
                            recomputed
                        );
                        // Delete corrupt chunk from SQLite so it gets retransmitted
                        let _ = crate::storage::client_db::delete_single_chunk(
                            &frame_commitment,
                            pc.chunk_index,
                        );
                        continue;
                    }

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
            return Ok(FrameIngressResult::NeedMoreChunks);
        }

        let buffer = buffers
            .remove(&frame_commitment)
            .ok_or_else(|| DsmError::invalid_operation("buffer disappeared during reassembly"))?;
        let payload = buffer.reassemble()?;

        // Cleanup persisted chunks after successful reassembly
        let _ = crate::storage::client_db::delete_frame_chunks(&frame_commitment);

        Ok(FrameIngressResult::MessageComplete {
            message: BleTransportMessage {
                frame_type,
                payload,
            },
        })
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
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)]
mod tests {
    use super::*;
    use crate::generated::BleFrameType;
    use prost::Message;
    use tokio::runtime::Runtime;

    fn test_coordinator() -> BleFrameCoordinator {
        let mut dev_id = [0u8; 32];
        dev_id[0] = 1;
        BleFrameCoordinator::new(dev_id)
    }

    #[test]
    fn test_ingest_chunk_with_modern_frame() {
        let coord = test_coordinator();
        let rt = Runtime::new().expect("runtime");

        rt.block_on(async {
            // Create a chunk with a modern frame type
            let modern_payload = vec![5, 6, 7, 8]; // Some dummy payload
            let normalized_frame_type =
                BleFrameType::try_from(200).unwrap_or(BleFrameType::Unspecified);

            // Create BleChunk with header
            let header = crate::generated::BleFrameHeader {
                frame_type: 200, // Modern frame type
                total_chunks: 1,
                chunk_index: 0,
                payload_len: modern_payload.len() as u32,
                checksum: BleFrameCoordinator::checksum32(&modern_payload),
                frame_commitment: BleFrameCoordinator::content_addressed_frame_commitment(
                    normalized_frame_type as i32,
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
                .ingest_chunk(&chunk_bytes)
                .await
                .expect("ingest modern frame");
            match result {
                FrameIngressResult::MessageComplete { message } => {
                    assert_eq!(message.frame_type, BleFrameType::Unspecified);
                    assert_eq!(message.payload, modern_payload);
                }
                other => panic!("unexpected ingress result: {other:?}"),
            }
        });
    }

    #[test]
    fn transport_chunk_round_trip_uses_session_and_message_ids() {
        let rt = Runtime::new().expect("runtime");
        rt.block_on(async {
            let coordinator = test_coordinator();

            let payload = vec![0xAB; 513];
            let chunks = coordinator
                .chunk_transport_payload(55, 99, &payload, 180)
                .expect("transport chunks");

            assert_eq!(chunks.len(), 3);

            let decoded = BleFrameCoordinator::decode_transport_frame(&chunks[0])
                .expect("decode transport chunk");
            match decoded {
                BleTransportFrame::Chunk(chunk) => {
                    let header = chunk.header.expect("header");
                    assert_eq!(header.version, BLE_TRANSPORT_VERSION);
                    assert_eq!(header.session_id, 55);
                    assert_eq!(header.message_id, 99);
                    assert_eq!(header.chunk_index, 0);
                    assert_eq!(header.chunk_count, 3);
                    assert_eq!(header.flags, BleTransportFlags::DATA.bits());
                }
                BleTransportFrame::Ack(_) => panic!("expected transport chunk"),
            }
        });
    }

    #[test]
    fn transport_ack_bitmap_tracks_sparse_progress() {
        let rt = Runtime::new().expect("runtime");
        rt.block_on(async {
            let coordinator = test_coordinator();

            let received = vec![true, true, false, true, false, true];
            let ack = coordinator.build_transport_ack(7, 11, &received);

            assert_eq!(ack.session_id, 7);
            assert_eq!(ack.message_id, 11);
            assert_eq!(ack.ack_base_chunk, 2);
            assert_eq!(ack.ack_bitmap, vec![0b0000_1010]);

            let encoded = coordinator
                .encode_transport_ack(7, 11, &received)
                .expect("encode ack");
            let decoded =
                BleFrameCoordinator::decode_transport_frame(&encoded).expect("decode ack");
            match decoded {
                BleTransportFrame::Ack(decoded_ack) => {
                    assert_eq!(decoded_ack.ack_base_chunk, 2);
                    assert_eq!(decoded_ack.ack_bitmap, vec![0b0000_1010]);
                }
                BleTransportFrame::Chunk(_) => panic!("expected ack"),
            }
        });
    }
}
