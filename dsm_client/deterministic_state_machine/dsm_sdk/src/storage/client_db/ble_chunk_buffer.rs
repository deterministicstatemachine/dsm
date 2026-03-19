// SPDX-License-Identifier: MIT OR Apache-2.0
//! BLE chunk reassembly persistence — durable chunk buffer for cross-session resume.
//!
//! Persists individual BLE chunks to SQLite as they arrive. On reconnect,
//! chunks are hydrated from the `ble_reassembly_state` table so reassembly
//! resumes from where it left off — fully automatic, no user action.
//!
//! Keys are content-addressed 32-byte BLAKE3 frame commitments, not strings.

use anyhow::{anyhow, Result};
use log::{debug, warn};
use rusqlite::params;

use super::get_connection;
use super::types::{PersistedChunk, ChunkPersistenceParams};
use crate::util::deterministic_time::tick;

/// Persist a single BLE chunk to SQLite. Idempotent — duplicates are silently ignored
/// via `INSERT OR IGNORE` on the (frame_commitment, chunk_index) primary key.
pub fn persist_ble_chunk(params: ChunkPersistenceParams) -> Result<()> {
    let binding = get_connection()?;
    let conn = binding
        .lock()
        .map_err(|_| anyhow!("Database lock poisoned"))?;
    let now = tick();

    conn.execute(
        "INSERT OR IGNORE INTO ble_reassembly_state
         (frame_commitment, chunk_index, frame_type, total_chunks,
          payload_len, chunk_data, checksum, counterparty_id, created_at_tick)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            &params.frame_commitment[..],
            params.chunk_index as i64,
            params.frame_type,
            params.total_chunks as i64,
            params.payload_len as i64,
            params.chunk_data,
            params.checksum as i64,
            params.counterparty_id.map(|id| &id[..]),
            now as i64,
        ],
    )?;

    debug!(
        "Persisted BLE chunk {}/{} for frame commitment",
        params.chunk_index, params.total_chunks
    );
    Ok(())
}

/// Load all persisted chunks for a given frame commitment, ordered by chunk_index.
pub fn load_persisted_chunks(frame_commitment: &[u8; 32]) -> Result<Vec<PersistedChunk>> {
    let binding = get_connection()?;
    let conn = binding
        .lock()
        .map_err(|_| anyhow!("Database lock poisoned"))?;

    let mut stmt = conn.prepare(
        "SELECT chunk_index, chunk_data, checksum, frame_type, total_chunks, payload_len
         FROM ble_reassembly_state
         WHERE frame_commitment = ?1
         ORDER BY chunk_index",
    )?;

    let rows = stmt.query_map(params![&frame_commitment[..]], |row| {
        Ok(PersistedChunk {
            chunk_index: row.get::<_, i64>(0)? as u16,
            chunk_data: row.get(1)?,
            checksum: row.get::<_, i64>(2)? as u32,
            frame_type: row.get(3)?,
            total_chunks: row.get::<_, i64>(4)? as u16,
            payload_len: row.get::<_, i64>(5)? as u32,
        })
    })?;

    let mut result = Vec::new();
    for row in rows {
        result.push(row?);
    }
    Ok(result)
}

/// Count persisted chunks for a given frame commitment.
pub fn count_persisted_chunks(frame_commitment: &[u8; 32]) -> Result<u16> {
    let binding = get_connection()?;
    let conn = binding
        .lock()
        .map_err(|_| anyhow!("Database lock poisoned"))?;

    let count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM ble_reassembly_state WHERE frame_commitment = ?1",
        params![&frame_commitment[..]],
        |row| row.get(0),
    )?;

    Ok(count as u16)
}

/// Delete all chunks for a given frame commitment (cleanup after successful reassembly).
pub fn delete_frame_chunks(frame_commitment: &[u8; 32]) -> Result<()> {
    let binding = get_connection()?;
    let conn = binding
        .lock()
        .map_err(|_| anyhow!("Database lock poisoned"))?;

    let deleted = conn.execute(
        "DELETE FROM ble_reassembly_state WHERE frame_commitment = ?1",
        params![&frame_commitment[..]],
    )?;

    if deleted > 0 {
        debug!("Deleted {} persisted chunks after reassembly", deleted);
    }
    Ok(())
}

/// Delete all chunks associated with a counterparty device_id.
/// Used when a bilateral session reaches a terminal state (Committed/Rejected/Failed).
pub fn delete_chunks_by_counterparty(counterparty_id: &[u8; 32]) -> Result<()> {
    let binding = get_connection()?;
    let conn = binding
        .lock()
        .map_err(|_| anyhow!("Database lock poisoned"))?;

    let deleted = conn.execute(
        "DELETE FROM ble_reassembly_state WHERE counterparty_id = ?1",
        params![&counterparty_id[..]],
    )?;

    if deleted > 0 {
        debug!(
            "Swept {} orphaned reassembly chunks for counterparty",
            deleted
        );
    }
    Ok(())
}

/// Cleanup orphaned chunk buffers. If more than 50 distinct frame_commitments
/// exist, delete the oldest ones (by created_at_tick) to prevent unbounded growth.
pub fn cleanup_orphan_chunk_buffers() -> Result<()> {
    let binding = get_connection()?;
    let conn = binding
        .lock()
        .map_err(|_| anyhow!("Database lock poisoned"))?;

    let distinct_count: i64 = conn.query_row(
        "SELECT COUNT(DISTINCT frame_commitment) FROM ble_reassembly_state",
        [],
        |row| row.get(0),
    )?;

    if distinct_count <= 50 {
        return Ok(());
    }

    // Find frame_commitments to keep (50 most recent by max created_at_tick)
    let to_delete = distinct_count - 50;
    let deleted = conn.execute(
        "DELETE FROM ble_reassembly_state
         WHERE frame_commitment IN (
             SELECT frame_commitment
             FROM ble_reassembly_state
             GROUP BY frame_commitment
             ORDER BY MAX(created_at_tick) ASC
             LIMIT ?1
         )",
        params![to_delete],
    )?;

    if deleted > 0 {
        warn!(
            "Cleaned up {} orphaned reassembly chunks ({} stale frames)",
            deleted, to_delete
        );
    }
    Ok(())
}
