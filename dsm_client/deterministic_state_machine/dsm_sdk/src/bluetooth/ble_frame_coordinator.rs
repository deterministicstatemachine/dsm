// SPDX-License-Identifier: MIT OR Apache-2.0

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

/// BLE chunk payload budget. Each chunk is wrapped in a BleChunk protobuf
/// (BleFrameHeader + data) adding ~50-60 bytes of framing. The total
/// serialized BleChunk must fit within (MTU - 3) for GATT notifications.
/// With MTU 517 → max notification = 514 bytes → 514 - 60 framing = ~454.
/// Using 400 gives ~460 total, safely under 514 with headroom.
/// A 29KB SPHINCS+ signature fits in ~75 chunks (~30s) vs 168 at 180 bytes.
const MAX_BLE_CHUNK_SIZE: usize = 400;
/// The most frames in reassembly on this device at once. Past it, the frame
/// that has gone longest without taking a chunk makes room, never the oldest
/// one: a frame that is arriving goes only if every other frame here took a
/// chunk since its last, so a peer that rotates its radio address to open
/// frames on fresh links must out-write it that many times over (SA-113).
const MAX_PENDING_REASSEMBLY: usize = 256;
/// The most frames one link may have in reassembly at once. A peer sends one
/// step's frames at a time; past this, the link's own oldest frame goes, never
/// another link's.
const MAX_PENDING_FRAMES_PER_LINK: usize = 4;
/// The largest frame this coordinator reassembles: a client-side budget for
/// one frame's bytes, not a protocol count. The largest frame the bilateral
/// protocol sends over BLE — a bearer confirm, with its stitched receipt (at
/// most 128 KiB, `dsm::bilateral::offline::MAX_STITCHED_RECEIPT_BYTES`), its
/// SPHINCS+ signatures and its offline release — is well inside it.
pub const MAX_BLE_FRAME_BYTES: usize = 1024 * 1024;

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
            // 25s: must exceed the Android BLE supervision timeout (5-20s
            // depending on chipset and negotiated parameters) to prevent
            // Rust from tearing down a connection the OS still considers alive.
            idle_timeout: Duration::from_secs(25),
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

/// A frame in reassembly: the link its chunks arrive on and its commitment.
/// Nothing on the link says who wrote the bytes, so a frame is the link's
/// own: chunks written on one link never join, displace or poison a frame
/// arriving on another, whatever commitment they name.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct FrameKey {
    link: String,
    commitment: [u8; 32],
}

/// What a chunk's header says about its whole frame. Every chunk of a frame
/// says the same; one that says otherwise is not a chunk of that frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FrameShape {
    frame_type: i32,
    total_chunks: u16,
    payload_len: u32,
}

/// The shape of the frame a chunk belongs to and the chunk's index in it,
/// as the header claims them, checked against each other and the chunk's
/// data: the frame is non-empty and within [`MAX_BLE_FRAME_BYTES`], its chunk
/// count is the one its length makes at [`MAX_BLE_CHUNK_SIZE`] (how
/// [`BleFrameCoordinator::encode_message`] cuts it), the index is one of its
/// chunks, and the data is exactly that chunk's length.
fn chunk_shape(header: &BleFrameHeader, data_len: usize) -> Result<(FrameShape, u16), DsmError> {
    let payload_len = header.payload_len as usize;
    if payload_len == 0 || payload_len > MAX_BLE_FRAME_BYTES {
        return Err(DsmError::invalid_operation(format!(
            "BLE frame length {payload_len} is outside 1..={MAX_BLE_FRAME_BYTES} bytes"
        )));
    }
    let total = payload_len.div_ceil(MAX_BLE_CHUNK_SIZE);
    if header.total_chunks as usize != total {
        return Err(DsmError::invalid_operation(format!(
            "BLE chunk count {} is not the {total} a {payload_len}-byte frame is cut into",
            header.total_chunks
        )));
    }
    let index = header.chunk_index as usize;
    if index >= total {
        return Err(DsmError::invalid_operation(format!(
            "BLE chunk index {index} is not one of the frame's {total} chunks"
        )));
    }
    let expected_len = if index + 1 == total {
        payload_len - index * MAX_BLE_CHUNK_SIZE
    } else {
        MAX_BLE_CHUNK_SIZE
    };
    if data_len != expected_len {
        return Err(DsmError::invalid_operation(format!(
            "BLE chunk {index} holds {data_len} bytes, not the {expected_len} its frame cuts"
        )));
    }
    let as_u16 = |n: usize, what: &str| {
        u16::try_from(n)
            .map_err(|e| DsmError::invalid_operation(format!("BLE chunk {what} {n}: {e}")))
    };
    Ok((
        FrameShape {
            frame_type: header.frame_type,
            total_chunks: as_u16(total, "count")?,
            payload_len: header.payload_len,
        },
        as_u16(index, "index")?,
    ))
}

/// Reassembly buffer for multi-chunk frames.
///
/// Transport-only timing: `created_at` is used for idle expiry and stale-session
/// recovery (rules.instructions.md §36). It never enters protocol semantics.
#[derive(Debug)]
struct ReassemblyBuffer {
    frame_commitment: [u8; 32],
    frame_type: BleFrameType,
    shape: FrameShape,
    received_chunks: HashMap<u16, Vec<u8>>,
    /// Transport-only: wall-clock instant when this buffer was created.
    /// Used for reassembly timeout enforcement and a link's own eviction.
    created_at: Instant,
    /// Transport-only: when this buffer last took a chunk it did not hold.
    /// Used for eviction across links.
    last_chunk_at: Instant,
}

impl ReassemblyBuffer {
    fn new(frame_type: BleFrameType, shape: FrameShape, commitment: &[u8; 32]) -> Self {
        let now = Instant::now();
        Self {
            frame_commitment: *commitment,
            frame_type,
            shape,
            received_chunks: HashMap::new(),
            created_at: now,
            last_chunk_at: now,
        }
    }

    fn is_complete(&self) -> bool {
        self.received_chunks.len() == usize::from(self.shape.total_chunks)
    }

    /// How long a frame of this many chunks may take to arrive. Large
    /// bilateral confirm envelopes need more time over BLE than small frames.
    fn timeout(&self) -> Duration {
        match self.shape.total_chunks {
            0..=10 => Duration::from_secs(10),
            11..=100 => Duration::from_secs(30),
            _ => Duration::from_secs(60),
        }
    }

    /// Reassemble all chunks into the original payload, then verify frame-level
    /// BLAKE3 integrity against `frame_commitment`.
    fn reassemble(self) -> Result<Vec<u8>, DsmError> {
        // Every chunk's length was checked against the shape on the way in, so
        // the frame's length is the shape's, within MAX_BLE_FRAME_BYTES.
        let mut result = Vec::with_capacity(self.shape.payload_len as usize);
        for i in 0..self.shape.total_chunks {
            let data = self
                .received_chunks
                .get(&i)
                .ok_or_else(|| DsmError::invalid_operation(format!("missing chunk {i}")))?;
            result.extend_from_slice(data);
        }
        if result.len() != self.shape.payload_len as usize {
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

/// Fixed-size LRU dedup table for fully reassembled frames.
///
/// After a frame is reassembled, its link and commitment are inserted here.
/// If the same frame appears again on the same link within `TTL_SECS` (e.g.
/// peer retransmitted the entire chunk set), the duplicate is dropped before
/// it reaches the bilateral handler. The same bytes on another link are that
/// link's frame, answered on that link.
///
/// Capacity is bounded at `DEDUP_TABLE_SIZE` entries — oldest entry is evicted
/// when full, so memory usage is O(1).
struct DeduplicationTable {
    entries: Vec<(FrameKey, Instant)>,
    capacity: usize,
}

impl DeduplicationTable {
    const TTL_SECS: u64 = 60;

    fn new(capacity: usize) -> Self {
        Self {
            entries: Vec::with_capacity(capacity),
            capacity,
        }
    }

    /// Whether the frame was already seen within the TTL window. A first
    /// sighting is recorded.
    fn sight(&mut self, key: &FrameKey) -> Sighting {
        let now = Instant::now();

        // Evict expired entries
        self.entries
            .retain(|(_, ts)| now.duration_since(*ts).as_secs() < Self::TTL_SECS);

        // Check for existing entry
        if self.entries.iter().any(|(seen, _)| seen == key) {
            return Sighting::Repeat;
        }

        // Evict oldest if at capacity
        if self.entries.len() >= self.capacity {
            self.entries.remove(0);
        }

        self.entries.push((key.clone(), now));
        Sighting::First
    }
}

/// Whether a reassembled frame was seen before on its link.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Sighting {
    First,
    Repeat,
}

/// BLE frame coordinator: handles chunking, reassembly, and bilateral flow dispatch.
pub struct BleFrameCoordinator {
    pending_reassembly: Arc<Mutex<HashMap<FrameKey, ReassemblyBuffer>>>,
    dedup_table: Arc<Mutex<DeduplicationTable>>,
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
            dedup_table: Arc::new(Mutex::new(DeduplicationTable::new(32))),
            device_id,
        }
    }

    /// Compute a 32-bit checksum of the payload using BLAKE3
    fn checksum32(payload: &[u8]) -> u32 {
        let h = dsm::crypto::blake3::domain_hash(
            dsm::common::domain_tags::TAG_DSM_BLE_FRAME_CHECKSUM,
            payload,
        );
        let b = h.as_bytes();
        u32::from_le_bytes([b[0], b[1], b[2], b[3]])
    }

    /// Compute 32-byte content-addressed frame commitment.
    /// Domain: "DSM/ble-frame" per BLAKE3 domain separation (invariant 9).
    /// Same payload + frame_type always produces the same commitment,
    /// enabling cross-session chunk correlation for durable persistence.
    fn content_addressed_frame_commitment(frame_type: i32, payload: &[u8]) -> [u8; 32] {
        let mut hasher = dsm_domain_hasher(dsm::common::domain_tags::TAG_DSM_BLE_FRAME);
        hasher.update(payload);
        hasher.update(&[frame_type as u8]);
        *hasher.finalize().as_bytes()
    }

    /// The 32-byte frame commitment a BleFrameHeader names. Any other length
    /// is not a frame this coordinator reassembles.
    fn frame_commitment_of(header: &BleFrameHeader) -> Result<[u8; 32], DsmError> {
        <[u8; 32]>::try_from(header.frame_commitment.as_slice()).map_err(|e| {
            DsmError::invalid_operation(format!(
                "BLE frame commitment is {} bytes, not 32: {e}",
                header.frame_commitment.len()
            ))
        })
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

    /// Handle a single BLE chunk (protobuf bytes for `BleChunk`) written on
    /// `peer_link` — the peer's BLE address as the radio reported it — and
    /// return transport ingress state.
    ///
    /// A chunk joins only the frame its link is sending under the commitment
    /// it names, and only when its header holds against itself and that
    /// frame ([`chunk_shape`]). A frame that fails its integrity check is
    /// dropped whole, with its persisted chunks, so the peer's retransmission
    /// starts clean; so is a frame whose buffer expires or is evicted.
    pub async fn ingest_chunk(
        &self,
        peer_link: &str,
        chunk_bytes: &[u8],
    ) -> Result<FrameIngressResult, DsmError> {
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

        let key = FrameKey {
            link: peer_link.to_string(),
            commitment: Self::frame_commitment_of(header)?,
        };
        let (shape, seq) = chunk_shape(header, chunk.data.len())?;
        let storage = |what: &str, e: anyhow::Error| {
            DsmError::storage(
                format!("BLE reassembly: {what}: {e}"),
                None::<std::io::Error>,
            )
        };

        let mut buffers = self.pending_reassembly.lock().await;

        // P0.1: Sweep expired reassembly buffers before processing new chunk.
        // Transport-only timing (rules.instructions.md §36: "idle expiry, stale-session recovery").
        // An expired frame goes whole: its buffer and the chunks persisted for
        // it, so what an unanswered writer sends does not outlive its frame.
        let now = Instant::now();
        let expired: Vec<FrameKey> = buffers
            .iter()
            .filter(|(_, buf)| now.duration_since(buf.created_at) > buf.timeout())
            .map(|(k, buf)| {
                warn!(
                    "BLE reassembly timeout: frame {} on {} expired ({}/{} chunks received)",
                    short_id(&k.commitment[..8]),
                    k.link,
                    buf.received_chunks.len(),
                    buf.shape.total_chunks
                );
                k.clone()
            })
            .collect();
        for expired_key in &expired {
            Self::drop_frame(&mut buffers, expired_key).map_err(|e| storage("expiry", e))?;
        }

        if !buffers.contains_key(&key) {
            // A link has at most MAX_PENDING_FRAMES_PER_LINK frames arriving,
            // and the device MAX_PENDING_REASSEMBLY: past the first, the
            // link's own oldest frame makes room; past the second, the frame
            // of any link that has gone longest without taking a chunk.
            let link_oldest = buffers
                .iter()
                .filter(|(k, _)| k.link == key.link)
                .min_by_key(|(_, buf)| buf.created_at)
                .map(|(k, _)| k.clone());
            let link_frames = buffers.keys().filter(|k| k.link == key.link).count();
            let evict = if link_frames >= MAX_PENDING_FRAMES_PER_LINK {
                link_oldest
            } else if buffers.len() >= MAX_PENDING_REASSEMBLY {
                buffers
                    .iter()
                    .min_by_key(|(_, buf)| buf.last_chunk_at)
                    .map(|(k, _)| k.clone())
            } else {
                None
            };
            if let Some(evicted) = evict {
                warn!(
                    "BLE reassembly full; evicting frame {} on {}",
                    short_id(&evicted.commitment[..8]),
                    evicted.link
                );
                Self::drop_frame(&mut buffers, &evicted).map_err(|e| storage("eviction", e))?;
            }

            // The auto-resume path: chunks persisted for this frame on this
            // link by an earlier connection or process are hydrated, each
            // held to the checks a fresh chunk is.
            let mut buffer = ReassemblyBuffer::new(frame_type, shape, &key.commitment);
            let persisted =
                crate::storage::client_db::load_persisted_chunks(&key.link, &key.commitment)
                    .map_err(|e| storage("hydration", e))?;
            if !persisted.is_empty() {
                info!(
                    "Auto-hydrating {} persisted chunks for frame {}",
                    persisted.len(),
                    short_id(&key.commitment[..8])
                );
            }
            for pc in persisted {
                let restored_header = BleFrameHeader {
                    frame_type: pc.frame_type,
                    chunk_index: u32::from(pc.chunk_index),
                    total_chunks: u32::from(pc.total_chunks),
                    payload_len: pc.payload_len,
                    checksum: pc.checksum,
                    frame_commitment: key.commitment.to_vec(),
                };
                // P0.3: Revalidate on hydration — catch SQLite corruption.
                let refusal = match chunk_shape(&restored_header, pc.chunk_data.len()) {
                    Err(e) => Some(e.to_string()),
                    Ok(_) if Self::checksum32(&pc.chunk_data) != pc.checksum => {
                        Some("its checksum does not hold".to_string())
                    }
                    Ok((restored, index)) if restored != shape || index != pc.chunk_index => {
                        Some("it describes another frame".to_string())
                    }
                    Ok(_) => None,
                };
                match refusal {
                    None => {
                        buffer.received_chunks.insert(pc.chunk_index, pc.chunk_data);
                    }
                    Some(why) => {
                        warn!(
                            "Hydrated chunk {} of frame {} is deleted so it is retransmitted: {why}",
                            pc.chunk_index,
                            short_id(&key.commitment[..8]),
                        );
                        crate::storage::client_db::delete_single_chunk(
                            &key.link,
                            &key.commitment,
                            pc.chunk_index,
                        )
                        .map_err(|e| storage("a corrupt hydrated chunk", e))?;
                    }
                }
            }
            buffers.insert(key.clone(), buffer);
        }

        let buffer = buffers
            .get_mut(&key)
            .ok_or_else(|| DsmError::invalid_operation("missing reassembly buffer"))?;
        if buffer.shape != shape {
            return Err(DsmError::invalid_operation(format!(
                "BLE chunk {seq} describes another frame than the one arriving under its \
                 commitment on this link"
            )));
        }

        // Deduplicate: a chunk already held (from hydration or a retransmit)
        // is not taken twice. A chunk is persisted when it is taken, so the
        // rows kept for a link are only those of its frames in reassembly.
        if let std::collections::hash_map::Entry::Vacant(slot) = buffer.received_chunks.entry(seq) {
            crate::storage::client_db::persist_ble_chunk(ChunkPersistenceParams {
                peer_link: &key.link,
                frame_commitment: &key.commitment,
                chunk_index: seq,
                frame_type: header.frame_type,
                total_chunks: shape.total_chunks,
                payload_len: shape.payload_len,
                chunk_data: &chunk.data,
                checksum: header.checksum,
            })
            .map_err(|e| storage("persisting a chunk", e))?;
            slot.insert(chunk.data);
            buffer.last_chunk_at = Instant::now();
        }

        if !buffer.is_complete() {
            debug!(
                "BLE reassembly in progress: {}/{} chunks for frame {}",
                buffer.received_chunks.len(),
                buffer.shape.total_chunks,
                short_id(&key.commitment[..8])
            );
            return Ok(FrameIngressResult::NeedMoreChunks);
        }

        let buffer = buffers
            .remove(&key)
            .ok_or_else(|| DsmError::invalid_operation("buffer disappeared during reassembly"))?;
        // Whether or not the frame holds, its persisted chunks go with it: a
        // frame that fails its check is not hydrated again on the next
        // retransmission, which then starts clean.
        crate::storage::client_db::delete_frame_chunks(&key.link, &key.commitment)
            .map_err(|e| storage("the completed frame's chunks", e))?;
        let payload = buffer.reassemble()?;

        // Transport-level dedup: if the same frame was already dispatched from
        // this link (e.g. peer retransmitted the entire chunk set), drop it
        // before it reaches the bilateral handler.
        if self.dedup_table.lock().await.sight(&key) == Sighting::Repeat {
            warn!(
                "Transport dedup: dropping reassembled duplicate frame {}",
                short_id(&key.commitment[..8])
            );
            return Ok(FrameIngressResult::NeedMoreChunks);
        }

        Ok(FrameIngressResult::MessageComplete {
            message: BleTransportMessage {
                frame_type,
                payload,
            },
        })
    }

    /// Drop the frame `key` whole: its buffer and every chunk persisted for it.
    fn drop_frame(
        buffers: &mut HashMap<FrameKey, ReassemblyBuffer>,
        key: &FrameKey,
    ) -> anyhow::Result<()> {
        buffers.remove(key);
        crate::storage::client_db::delete_frame_chunks(&key.link, &key.commitment)
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

    const LINK_A: &str = "AA:AA:AA:AA:AA:01";
    const LINK_B: &str = "BB:BB:BB:BB:BB:02";

    fn init_test_db() {
        crate::economic_fixtures::use_test_storage_dir();
        crate::storage::client_db::reset_database_for_tests();
        crate::storage::client_db::init_database().expect("init db");
    }

    /// A payload of `len` bytes no other test frame shares.
    fn payload(seed: u8, len: usize) -> Vec<u8> {
        (0..len)
            .map(|i| seed.wrapping_add((i % 251) as u8))
            .collect()
    }

    /// `chunk` re-encoded with its header changed by `bend` and its data by
    /// `data`, the checksum recomputed: a chunk whose checksum holds.
    fn bent_chunk(
        chunk: &[u8],
        bend: impl Fn(&mut BleFrameHeader),
        data: impl Fn(&mut Vec<u8>),
    ) -> Vec<u8> {
        let mut decoded = crate::generated::BleChunk::decode(chunk).expect("a chunk");
        data(&mut decoded.data);
        let header = decoded.header.as_mut().expect("a header");
        bend(header);
        header.checksum = BleFrameCoordinator::checksum32(&decoded.data);
        decoded.encode_to_vec()
    }

    fn commitment_of(chunk: &[u8]) -> [u8; 32] {
        let decoded = crate::generated::BleChunk::decode(chunk).expect("a chunk");
        <[u8; 32]>::try_from(
            decoded
                .header
                .expect("a header")
                .frame_commitment
                .as_slice(),
        )
        .expect("32 bytes")
    }

    async fn feed(
        coord: &BleFrameCoordinator,
        link: &str,
        chunks: &[Vec<u8>],
    ) -> Result<FrameIngressResult, DsmError> {
        let mut last = FrameIngressResult::NeedMoreChunks;
        for chunk in chunks {
            last = coord.ingest_chunk(link, chunk).await?;
        }
        Ok(last)
    }

    /// SA-13. A peer in range writes a chunk naming an honest peer's frame
    /// commitment, first, on its own link. Frames were keyed by commitment
    /// alone and the first chunk per index won, so the honest frame failed
    /// its check on every retransmission. A frame is its link's now: the
    /// honest frame completes, and the writer's chunk stays its own link's.
    /// MUTATION CONTROL: keying reassembly by the commitment alone turns
    /// this red.
    #[test]
    #[serial_test::serial]
    fn a_chunk_written_on_another_link_cannot_poison_a_frame() {
        init_test_db();
        let coord = test_coordinator();
        let rt = Runtime::new().expect("runtime");
        rt.block_on(async {
            let honest = payload(0x10, 3 * MAX_BLE_CHUNK_SIZE - 7);
            let chunks = coord
                .encode_message(BleFrameType::BilateralPrepare, &honest)
                .expect("chunks");
            let poison = bent_chunk(
                &chunks[0],
                |_| {},
                |data| data.iter_mut().for_each(|b| *b ^= 0x5A),
            );

            assert_eq!(
                coord
                    .ingest_chunk(LINK_B, &poison)
                    .await
                    .expect("taken on B"),
                FrameIngressResult::NeedMoreChunks
            );
            match feed(&coord, LINK_A, &chunks).await.expect("A's frame") {
                FrameIngressResult::MessageComplete { message } => {
                    assert_eq!(message.payload, honest);
                }
                other => panic!("A's frame did not complete: {other:?}"),
            }
            assert_eq!(
                crate::storage::client_db::load_persisted_chunks(LINK_B, &commitment_of(&poison))
                    .expect("B's rows")
                    .len(),
                1,
                "the writer's chunk is kept for its own link only"
            );
        });
    }

    /// SA-13. A frame whose chunks do not reassemble to its commitment is
    /// dropped whole — its buffer and its persisted chunks — so the peer's
    /// retransmission starts clean. The persisted chunks used to outlive the
    /// failed check (`reassemble()?` returned first) and were hydrated into
    /// every retransmission, which failed again.
    /// MUTATION CONTROL: deleting the persisted chunks only after a frame
    /// holds turns this red.
    #[test]
    #[serial_test::serial]
    fn a_frame_that_fails_its_check_is_dropped_whole_and_its_retransmission_completes() {
        init_test_db();
        let coord = test_coordinator();
        let rt = Runtime::new().expect("runtime");
        rt.block_on(async {
            let honest = payload(0x20, 2 * MAX_BLE_CHUNK_SIZE + 11);
            let chunks = coord
                .encode_message(BleFrameType::BilateralConfirm, &honest)
                .expect("chunks");
            let mut poisoned = chunks.clone();
            poisoned[0] = bent_chunk(&chunks[0], |_| {}, |data| data[0] ^= 0x01);

            let refused = feed(&coord, LINK_A, &poisoned)
                .await
                .expect_err("a frame that does not hash to its commitment");
            assert!(
                refused.to_string().contains("frame integrity check failed"),
                "{refused}"
            );
            assert!(
                crate::storage::client_db::load_persisted_chunks(
                    LINK_A,
                    &commitment_of(&chunks[0])
                )
                .expect("rows")
                .is_empty(),
                "the failed frame's persisted chunks went with it"
            );

            match feed(&coord, LINK_A, &chunks)
                .await
                .expect("the retransmission")
            {
                FrameIngressResult::MessageComplete { message } => {
                    assert_eq!(message.payload, honest);
                }
                other => panic!("the retransmission did not complete: {other:?}"),
            }
        });
    }

    /// SA-13. A chunk's header is the writer's. An index outside its frame, a
    /// chunk count its length does not make, a frame over the budget, data of
    /// another length than its chunk, or a commitment that is not 32 bytes is
    /// refused before anything is buffered or persisted.
    /// MUTATION CONTROL: dropping the index bound turns this red.
    #[test]
    #[serial_test::serial]
    fn a_chunk_whose_header_does_not_hold_is_refused_before_it_is_kept() {
        init_test_db();
        let coord = test_coordinator();
        let rt = Runtime::new().expect("runtime");
        rt.block_on(async {
            let honest = payload(0x30, 2 * MAX_BLE_CHUNK_SIZE);
            let chunks = coord
                .encode_message(BleFrameType::BilateralPrepare, &honest)
                .expect("chunks");
            let commitment = commitment_of(&chunks[0]);
            let cases: [(&str, Vec<u8>, &str); 6] = [
                (
                    "an index past the frame",
                    bent_chunk(&chunks[1], |h| h.chunk_index = 2, |_| {}),
                    "is not one of the frame's",
                ),
                (
                    "an index past a chunk index",
                    bent_chunk(&chunks[1], |h| h.chunk_index = u32::MAX, |_| {}),
                    "is not one of the frame's",
                ),
                (
                    "a chunk count the length does not make",
                    bent_chunk(&chunks[0], |h| h.total_chunks = 9, |_| {}),
                    "is not the 2 a",
                ),
                (
                    "a frame over the budget",
                    bent_chunk(
                        &chunks[0],
                        |h| {
                            h.payload_len = u32::try_from(MAX_BLE_FRAME_BYTES + 1).expect("u32");
                            h.total_chunks = u32::try_from(
                                (MAX_BLE_FRAME_BYTES + 1).div_ceil(MAX_BLE_CHUNK_SIZE),
                            )
                            .expect("u32");
                        },
                        |_| {},
                    ),
                    "is outside",
                ),
                (
                    "data of another length",
                    bent_chunk(&chunks[0], |_| {}, |data| data.truncate(17)),
                    "not the 400 its frame cuts",
                ),
                (
                    "a short commitment",
                    bent_chunk(&chunks[0], |h| h.frame_commitment.truncate(31), |_| {}),
                    "not 32",
                ),
            ];
            for (what, chunk, why) in cases {
                let refused = coord.ingest_chunk(LINK_A, &chunk).await.expect_err(what);
                assert!(refused.to_string().contains(why), "{what}: {refused}");
            }
            assert!(
                crate::storage::client_db::load_persisted_chunks(LINK_A, &commitment)
                    .expect("rows")
                    .is_empty(),
                "a refused chunk is never persisted"
            );
            assert!(coord.pending_reassembly.lock().await.is_empty());
        });
    }

    /// SA-16. A frame whose buffer expires takes its persisted chunks with
    /// it. They used to stay (carrying no counterparty, swept only at a
    /// startup over fifty frames), so a writer that never finished a frame
    /// grew the database until the next restart.
    /// MUTATION CONTROL: expiring the buffer alone turns this red.
    #[test]
    #[serial_test::serial]
    fn an_expired_frame_takes_its_persisted_chunks_with_it() {
        init_test_db();
        let coord = test_coordinator();
        let rt = Runtime::new().expect("runtime");
        rt.block_on(async {
            let unfinished = coord
                .encode_message(
                    BleFrameType::BilateralPrepare,
                    &payload(0x40, 2 * MAX_BLE_CHUNK_SIZE),
                )
                .expect("chunks");
            let commitment = commitment_of(&unfinished[0]);
            coord
                .ingest_chunk(LINK_B, &unfinished[0])
                .await
                .expect("the first chunk");
            assert_eq!(
                crate::storage::client_db::load_persisted_chunks(LINK_B, &commitment)
                    .expect("rows")
                    .len(),
                1
            );
            // The frame's time runs out.
            for buffer in coord.pending_reassembly.lock().await.values_mut() {
                buffer.created_at = Instant::now()
                    .checked_sub(buffer.timeout() + Duration::from_secs(1))
                    .expect("an instant in the past");
            }

            let next = coord
                .encode_message(BleFrameType::BilateralPrepare, &payload(0x41, 9))
                .expect("chunks");
            coord
                .ingest_chunk(LINK_A, &next[0])
                .await
                .expect("another frame");
            assert!(
                crate::storage::client_db::load_persisted_chunks(LINK_B, &commitment)
                    .expect("rows")
                    .is_empty(),
                "the expired frame's persisted chunks are swept with it"
            );
            assert!(!coord
                .pending_reassembly
                .lock()
                .await
                .keys()
                .any(|k| k.link == LINK_B));
        });
    }

    /// SA-16. One link holds at most MAX_PENDING_FRAMES_PER_LINK frames in
    /// reassembly: past that, its own oldest frame goes, with its persisted
    /// chunks, and another link's frame stays however old it is.
    /// MUTATION CONTROL: evicting the oldest frame of any link turns this red.
    #[test]
    #[serial_test::serial]
    fn a_link_past_its_frame_bound_evicts_its_own_oldest_frame() {
        init_test_db();
        let coord = test_coordinator();
        let rt = Runtime::new().expect("runtime");
        rt.block_on(async {
            let first_chunk = |seed: u8| {
                coord
                    .encode_message(
                        BleFrameType::BilateralPrepare,
                        &payload(seed, 2 * MAX_BLE_CHUNK_SIZE),
                    )
                    .expect("chunks")
                    .remove(0)
            };
            let honest = first_chunk(0x50);
            coord
                .ingest_chunk(LINK_A, &honest)
                .await
                .expect("A's frame");
            let flood: Vec<Vec<u8>> = (0..=MAX_PENDING_FRAMES_PER_LINK)
                .map(|i| first_chunk(0x60 + u8::try_from(i).expect("small")))
                .collect();
            for chunk in &flood {
                coord.ingest_chunk(LINK_B, chunk).await.expect("B's frame");
            }

            let pending = coord.pending_reassembly.lock().await;
            assert_eq!(
                pending.keys().filter(|k| k.link == LINK_B).count(),
                MAX_PENDING_FRAMES_PER_LINK
            );
            assert!(
                pending.keys().any(|k| k.link == LINK_A),
                "another link's frame was evicted"
            );
            drop(pending);
            assert!(
                crate::storage::client_db::load_persisted_chunks(LINK_B, &commitment_of(&flood[0]))
                    .expect("rows")
                    .is_empty(),
                "the evicted frame's persisted chunks went with it"
            );
        });
    }

    /// SA-113. A peer that rotates its radio address opens frames on fresh
    /// links, each within its link's bound, until the device holds
    /// MAX_PENDING_REASSEMBLY, and then one more. The honest frame arriving on
    /// LINK_A, older than all of them but still taking chunks, is not pushed
    /// out: the frame idle longest makes room, and the honest frame completes.
    /// MUTATION CONTROL: evicting the oldest frame across links turns this red.
    #[test]
    #[serial_test::serial]
    fn an_address_rotating_peer_cannot_push_out_a_frame_that_is_arriving() {
        init_test_db();
        let coord = test_coordinator();
        let rt = Runtime::new().expect("runtime");
        rt.block_on(async {
            let honest = payload(0x70, 3 * MAX_BLE_CHUNK_SIZE);
            let chunks = coord
                .encode_message(BleFrameType::BilateralConfirm, &honest)
                .expect("chunks");
            let rotated = |i: usize| format!("RR:RR:RR:RR:{:02X}:{:02X}", i / 256, i % 256);
            let opening = |i: usize| {
                coord
                    .encode_message(
                        BleFrameType::BilateralPrepare,
                        &payload(
                            u8::try_from(i % 251).expect("small"),
                            2 * MAX_BLE_CHUNK_SIZE + i,
                        ),
                    )
                    .expect("chunks")
                    .remove(0)
            };

            coord
                .ingest_chunk(LINK_A, &chunks[0])
                .await
                .expect("the honest frame opens");
            for i in 0..MAX_PENDING_REASSEMBLY - 1 {
                coord
                    .ingest_chunk(&rotated(i), &opening(i))
                    .await
                    .expect("a rotated link's frame");
            }
            assert_eq!(
                coord.pending_reassembly.lock().await.len(),
                MAX_PENDING_REASSEMBLY,
                "the device is full"
            );
            coord
                .ingest_chunk(LINK_A, &chunks[1])
                .await
                .expect("the honest frame takes its next chunk");
            let past = MAX_PENDING_REASSEMBLY - 1;
            coord
                .ingest_chunk(&rotated(past), &opening(past))
                .await
                .expect("one more rotated link's frame");
            assert_eq!(
                coord.pending_reassembly.lock().await.len(),
                MAX_PENDING_REASSEMBLY
            );

            match coord
                .ingest_chunk(LINK_A, &chunks[2])
                .await
                .expect("the honest frame's last chunk")
            {
                FrameIngressResult::MessageComplete { message } => {
                    assert_eq!(message.payload, honest);
                }
                other => panic!("the honest frame was pushed out: {other:?}"),
            }
        });
    }

    #[test]
    #[serial_test::serial]
    fn test_ingest_chunk_with_modern_frame() {
        init_test_db();
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
                .ingest_chunk(LINK_A, &chunk_bytes)
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
