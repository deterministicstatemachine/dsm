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

/// Delete a single chunk by frame_commitment + chunk_index.
/// Used to remove corrupt chunks detected during hydration revalidation.
pub fn delete_single_chunk(frame_commitment: &[u8; 32], chunk_index: u16) -> Result<()> {
    let binding = get_connection()?;
    let conn = binding
        .lock()
        .map_err(|_| anyhow!("Database lock poisoned"))?;

    conn.execute(
        "DELETE FROM ble_reassembly_state WHERE frame_commitment = ?1 AND chunk_index = ?2",
        params![&frame_commitment[..], chunk_index],
    )?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::types::ChunkPersistenceParams;
    use serial_test::serial;

    fn init_test_db() {
        unsafe { std::env::set_var("DSM_SDK_TEST_MODE", "1") };
        crate::storage::client_db::reset_database_for_tests();
        crate::storage::client_db::init_database().expect("init db");
    }

    fn make_chunk_params<'a>(
        fc: &'a [u8; 32],
        index: u16,
        data: &'a [u8],
    ) -> ChunkPersistenceParams<'a> {
        ChunkPersistenceParams {
            frame_commitment: fc,
            chunk_index: index,
            frame_type: 1,
            total_chunks: 4,
            payload_len: 1024,
            chunk_data: data,
            checksum: 0xDEAD,
            counterparty_id: None,
        }
    }

    #[test]
    #[serial]
    fn persist_and_load_chunks_roundtrip() {
        init_test_db();
        let fc = [0xAA; 32];
        let data0 = b"chunk-data-0";
        let data1 = b"chunk-data-1";

        persist_ble_chunk(make_chunk_params(&fc, 0, data0)).unwrap();
        persist_ble_chunk(make_chunk_params(&fc, 1, data1)).unwrap();

        let loaded = load_persisted_chunks(&fc).unwrap();
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded[0].chunk_index, 0);
        assert_eq!(loaded[0].chunk_data, data0);
        assert_eq!(loaded[0].checksum, 0xDEAD);
        assert_eq!(loaded[1].chunk_index, 1);
        assert_eq!(loaded[1].total_chunks, 4);
        assert_eq!(loaded[1].payload_len, 1024);
    }

    #[test]
    #[serial]
    fn persist_ble_chunk_is_idempotent() {
        init_test_db();
        let fc = [0xBB; 32];
        let data = b"dupe-data";

        persist_ble_chunk(make_chunk_params(&fc, 0, data)).unwrap();
        persist_ble_chunk(make_chunk_params(&fc, 0, data)).unwrap();

        let count = count_persisted_chunks(&fc).unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    #[serial]
    fn count_persisted_chunks_counts_correctly() {
        init_test_db();
        let fc = [0xCC; 32];
        persist_ble_chunk(make_chunk_params(&fc, 0, b"a")).unwrap();
        persist_ble_chunk(make_chunk_params(&fc, 1, b"b")).unwrap();
        persist_ble_chunk(make_chunk_params(&fc, 2, b"c")).unwrap();

        assert_eq!(count_persisted_chunks(&fc).unwrap(), 3);
    }

    #[test]
    #[serial]
    fn delete_frame_chunks_removes_all_for_commitment() {
        init_test_db();
        let fc = [0xDD; 32];
        persist_ble_chunk(make_chunk_params(&fc, 0, b"a")).unwrap();
        persist_ble_chunk(make_chunk_params(&fc, 1, b"b")).unwrap();

        delete_frame_chunks(&fc).unwrap();
        assert_eq!(count_persisted_chunks(&fc).unwrap(), 0);
    }

    #[test]
    #[serial]
    fn delete_single_chunk_removes_only_one() {
        init_test_db();
        let fc = [0xEE; 32];
        persist_ble_chunk(make_chunk_params(&fc, 0, b"a")).unwrap();
        persist_ble_chunk(make_chunk_params(&fc, 1, b"b")).unwrap();

        delete_single_chunk(&fc, 0).unwrap();
        let remaining = load_persisted_chunks(&fc).unwrap();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].chunk_index, 1);
    }

    #[test]
    #[serial]
    fn delete_chunks_by_counterparty_sweeps_related() {
        init_test_db();
        let fc = [0xFF; 32];
        let cp = [0x11; 32];
        let params = ChunkPersistenceParams {
            frame_commitment: &fc,
            chunk_index: 0,
            frame_type: 1,
            total_chunks: 2,
            payload_len: 100,
            chunk_data: b"data",
            checksum: 42,
            counterparty_id: Some(&cp),
        };
        persist_ble_chunk(params).unwrap();

        delete_chunks_by_counterparty(&cp).unwrap();
        assert_eq!(count_persisted_chunks(&fc).unwrap(), 0);
    }

    #[test]
    #[serial]
    fn different_frame_commitments_are_isolated() {
        init_test_db();
        let fc1 = [0x01; 32];
        let fc2 = [0x02; 32];

        persist_ble_chunk(make_chunk_params(&fc1, 0, b"data-fc1")).unwrap();
        persist_ble_chunk(make_chunk_params(&fc2, 0, b"data-fc2")).unwrap();
        persist_ble_chunk(make_chunk_params(&fc2, 1, b"data-fc2-b")).unwrap();

        assert_eq!(count_persisted_chunks(&fc1).unwrap(), 1);
        assert_eq!(count_persisted_chunks(&fc2).unwrap(), 2);

        delete_frame_chunks(&fc1).unwrap();
        assert_eq!(count_persisted_chunks(&fc1).unwrap(), 0);
        assert_eq!(count_persisted_chunks(&fc2).unwrap(), 2);
    }

    #[test]
    #[serial]
    fn cleanup_orphan_chunk_buffers_noop_under_threshold() {
        init_test_db();
        let fc = [0x03; 32];
        persist_ble_chunk(make_chunk_params(&fc, 0, b"data")).unwrap();

        cleanup_orphan_chunk_buffers().unwrap();
        assert_eq!(count_persisted_chunks(&fc).unwrap(), 1);
    }

    #[test]
    #[serial]
    fn load_empty_frame_returns_empty_vec() {
        init_test_db();
        let fc = [0x04; 32];
        let chunks = load_persisted_chunks(&fc).unwrap();
        assert!(chunks.is_empty());
    }

    #[test]
    #[serial]
    fn delete_single_chunk_nonexistent_is_noop() {
        init_test_db();
        let fc = [0x05; 32];
        delete_single_chunk(&fc, 99).unwrap();
    }
}
