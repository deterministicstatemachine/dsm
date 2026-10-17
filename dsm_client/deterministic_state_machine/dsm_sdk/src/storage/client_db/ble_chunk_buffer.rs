// SPDX-License-Identifier: MIT OR Apache-2.0
//! BLE chunk reassembly persistence — durable chunk buffer for cross-session resume.
//!
//! Persists individual BLE chunks to SQLite as the frame coordinator takes
//! them. When a chunk of the same frame arrives on the same link again, the
//! chunks kept for it are hydrated from the `ble_reassembly_chunks` table, so
//! reassembly resumes from where it left off — fully automatic, no user action.
//!
//! A chunk is kept under the link it arrived on and its frame's 32-byte
//! BLAKE3 commitment: chunks one peer writes never join a frame another peer
//! is sending. Rows live as long as their frame's reassembly: the coordinator
//! deletes them when the frame completes or fails its check, and when its
//! buffer expires or is evicted; [`cleanup_orphan_chunk_buffers`] bounds what
//! a previous process left behind.

use anyhow::{anyhow, Result};
use log::{debug, warn};
use rusqlite::params;

use super::get_connection;
use super::types::{ChunkPersistenceParams, PersistedChunk};

/// The most frames whose chunks a startup keeps from a previous process.
pub const MAX_PERSISTED_FRAMES: i64 = 16;

/// Persist a single BLE chunk to SQLite. Idempotent — a chunk already kept
/// for its `(peer_link, frame_commitment, chunk_index)` is left as it is.
pub fn persist_ble_chunk(params: ChunkPersistenceParams) -> Result<()> {
    let binding = get_connection()?;
    let conn = binding
        .lock()
        .map_err(|_| anyhow!("Database lock poisoned"))?;

    conn.execute(
        "INSERT OR IGNORE INTO ble_reassembly_chunks
         (peer_link, frame_commitment, chunk_index, frame_type, total_chunks,
          payload_len, chunk_data, checksum)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            params.peer_link,
            &params.frame_commitment[..],
            i64::from(params.chunk_index),
            params.frame_type,
            i64::from(params.total_chunks),
            i64::from(params.payload_len),
            params.chunk_data,
            i64::from(params.checksum),
        ],
    )?;

    debug!(
        "Persisted BLE chunk {}/{} for frame commitment",
        params.chunk_index, params.total_chunks
    );
    Ok(())
}

/// A stored integer column, as the type it was written from. A value out of
/// that type's range is a corrupt row and an error, never truncated.
fn column_int<T>(row: &rusqlite::Row<'_>, i: usize) -> rusqlite::Result<T>
where
    T: TryFrom<i64>,
    T::Error: std::fmt::Display,
{
    let v: i64 = row.get(i)?;
    T::try_from(v).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(
            i,
            rusqlite::types::Type::Integer,
            format!("column {i} holds {v}, out of range: {e}").into(),
        )
    })
}

/// Every chunk kept for the frame `frame_commitment` arriving on `peer_link`,
/// ordered by chunk_index.
pub fn load_persisted_chunks(
    peer_link: &str,
    frame_commitment: &[u8; 32],
) -> Result<Vec<PersistedChunk>> {
    let binding = get_connection()?;
    let conn = binding
        .lock()
        .map_err(|_| anyhow!("Database lock poisoned"))?;

    let mut stmt = conn.prepare(
        "SELECT chunk_index, chunk_data, checksum, frame_type, total_chunks, payload_len
         FROM ble_reassembly_chunks
         WHERE peer_link = ?1 AND frame_commitment = ?2
         ORDER BY chunk_index",
    )?;

    let rows = stmt.query_map(params![peer_link, &frame_commitment[..]], |row| {
        Ok(PersistedChunk {
            chunk_index: column_int(row, 0)?,
            chunk_data: row.get(1)?,
            checksum: column_int(row, 2)?,
            frame_type: row.get(3)?,
            total_chunks: column_int(row, 4)?,
            payload_len: column_int(row, 5)?,
        })
    })?;

    let mut result = Vec::new();
    for row in rows {
        result.push(row?);
    }
    Ok(result)
}

/// Delete every chunk kept for the frame `frame_commitment` arriving on
/// `peer_link`: its reassembly completed, failed, expired or was evicted.
pub fn delete_frame_chunks(peer_link: &str, frame_commitment: &[u8; 32]) -> Result<()> {
    let binding = get_connection()?;
    let conn = binding
        .lock()
        .map_err(|_| anyhow!("Database lock poisoned"))?;

    let deleted = conn.execute(
        "DELETE FROM ble_reassembly_chunks WHERE peer_link = ?1 AND frame_commitment = ?2",
        params![peer_link, &frame_commitment[..]],
    )?;

    if deleted > 0 {
        debug!("Deleted {} persisted chunks of a frame", deleted);
    }
    Ok(())
}

/// Delete one kept chunk: a chunk that no longer passes the checks a fresh
/// chunk passes.
pub fn delete_single_chunk(
    peer_link: &str,
    frame_commitment: &[u8; 32],
    chunk_index: u16,
) -> Result<()> {
    let binding = get_connection()?;
    let conn = binding
        .lock()
        .map_err(|_| anyhow!("Database lock poisoned"))?;

    conn.execute(
        "DELETE FROM ble_reassembly_chunks
         WHERE peer_link = ?1 AND frame_commitment = ?2 AND chunk_index = ?3",
        params![peer_link, &frame_commitment[..], i64::from(chunk_index)],
    )?;
    Ok(())
}

/// Bound what a previous process left behind. If more than
/// [`MAX_PERSISTED_FRAMES`] frames (by link and commitment) hold chunks, delete
/// the ones whose newest chunk was persisted longest ago (insertion order, the
/// rowid).
pub fn cleanup_orphan_chunk_buffers() -> Result<()> {
    let binding = get_connection()?;
    let conn = binding
        .lock()
        .map_err(|_| anyhow!("Database lock poisoned"))?;

    let frames: i64 = conn.query_row(
        "SELECT COUNT(*) FROM (
             SELECT 1 FROM ble_reassembly_chunks GROUP BY peer_link, frame_commitment
         )",
        [],
        |row| row.get(0),
    )?;

    if frames <= MAX_PERSISTED_FRAMES {
        return Ok(());
    }

    let to_delete = frames - MAX_PERSISTED_FRAMES;
    let deleted = conn.execute(
        "DELETE FROM ble_reassembly_chunks
         WHERE (peer_link, frame_commitment) IN (
             SELECT peer_link, frame_commitment
             FROM ble_reassembly_chunks
             GROUP BY peer_link, frame_commitment
             ORDER BY MAX(rowid) ASC
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
    use super::super::types::ChunkPersistenceParams;
    use super::*;
    use serial_test::serial;

    const LINK: &str = "AA:BB:CC:DD:EE:01";

    fn init_test_db() {
        crate::economic_fixtures::use_test_storage_dir();
        crate::storage::client_db::reset_database_for_tests();
        crate::storage::client_db::init_database().expect("init db");
    }

    fn make_chunk_params<'a>(
        link: &'a str,
        fc: &'a [u8; 32],
        index: u16,
        data: &'a [u8],
    ) -> ChunkPersistenceParams<'a> {
        ChunkPersistenceParams {
            peer_link: link,
            frame_commitment: fc,
            chunk_index: index,
            frame_type: 1,
            total_chunks: 4,
            payload_len: 1024,
            chunk_data: data,
            checksum: 0xDEAD,
        }
    }

    fn count(link: &str, fc: &[u8; 32]) -> usize {
        load_persisted_chunks(link, fc).unwrap().len()
    }

    #[test]
    #[serial]
    fn persist_and_load_chunks_roundtrip() {
        init_test_db();
        let fc = [0xAA; 32];
        let data0 = b"chunk-data-0";
        let data1 = b"chunk-data-1";

        persist_ble_chunk(make_chunk_params(LINK, &fc, 0, data0)).unwrap();
        persist_ble_chunk(make_chunk_params(LINK, &fc, 1, data1)).unwrap();

        let loaded = load_persisted_chunks(LINK, &fc).unwrap();
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

        persist_ble_chunk(make_chunk_params(LINK, &fc, 0, data)).unwrap();
        persist_ble_chunk(make_chunk_params(LINK, &fc, 0, data)).unwrap();

        assert_eq!(count(LINK, &fc), 1);
    }

    /// SA-13. The same frame commitment on two links is two frames: what one
    /// peer writes is never read into, or deleted with, another peer's frame.
    #[test]
    #[serial]
    fn a_frame_on_one_link_is_not_the_same_frame_on_another() {
        init_test_db();
        let fc = [0xBC; 32];
        let other = "AA:BB:CC:DD:EE:02";
        persist_ble_chunk(make_chunk_params(LINK, &fc, 0, b"honest")).unwrap();
        persist_ble_chunk(make_chunk_params(other, &fc, 0, b"poison")).unwrap();

        assert_eq!(
            load_persisted_chunks(LINK, &fc).unwrap()[0].chunk_data,
            b"honest"
        );
        assert_eq!(
            load_persisted_chunks(other, &fc).unwrap()[0].chunk_data,
            b"poison"
        );

        delete_frame_chunks(other, &fc).unwrap();
        assert_eq!(count(other, &fc), 0);
        assert_eq!(count(LINK, &fc), 1);
    }

    #[test]
    #[serial]
    fn delete_frame_chunks_removes_all_for_commitment() {
        init_test_db();
        let fc = [0xDD; 32];
        persist_ble_chunk(make_chunk_params(LINK, &fc, 0, b"a")).unwrap();
        persist_ble_chunk(make_chunk_params(LINK, &fc, 1, b"b")).unwrap();

        delete_frame_chunks(LINK, &fc).unwrap();
        assert_eq!(count(LINK, &fc), 0);
    }

    #[test]
    #[serial]
    fn delete_single_chunk_removes_only_one() {
        init_test_db();
        let fc = [0xEE; 32];
        persist_ble_chunk(make_chunk_params(LINK, &fc, 0, b"a")).unwrap();
        persist_ble_chunk(make_chunk_params(LINK, &fc, 1, b"b")).unwrap();

        delete_single_chunk(LINK, &fc, 0).unwrap();
        let remaining = load_persisted_chunks(LINK, &fc).unwrap();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].chunk_index, 1);
    }

    #[test]
    #[serial]
    fn different_frame_commitments_are_isolated() {
        init_test_db();
        let fc1 = [0x01; 32];
        let fc2 = [0x02; 32];

        persist_ble_chunk(make_chunk_params(LINK, &fc1, 0, b"data-fc1")).unwrap();
        persist_ble_chunk(make_chunk_params(LINK, &fc2, 0, b"data-fc2")).unwrap();
        persist_ble_chunk(make_chunk_params(LINK, &fc2, 1, b"data-fc2-b")).unwrap();

        assert_eq!(count(LINK, &fc1), 1);
        assert_eq!(count(LINK, &fc2), 2);

        delete_frame_chunks(LINK, &fc1).unwrap();
        assert_eq!(count(LINK, &fc1), 0);
        assert_eq!(count(LINK, &fc2), 2);
    }

    /// A stored chunk index out of a chunk index's range is a corrupt row: an
    /// error, never truncated into another chunk's index.
    #[test]
    #[serial]
    fn a_stored_index_out_of_range_is_an_error() {
        init_test_db();
        let fc = [0x06; 32];
        persist_ble_chunk(make_chunk_params(LINK, &fc, 0, b"data")).unwrap();
        {
            let binding = get_connection().unwrap();
            let conn = binding.lock().unwrap();
            conn.execute(
                "UPDATE ble_reassembly_chunks SET chunk_index = ?1",
                params![i64::from(u16::MAX) + 1],
            )
            .unwrap();
        }
        let err = load_persisted_chunks(LINK, &fc).expect_err("refused");
        assert!(err.to_string().contains("out of range"), "{err}");
    }

    #[test]
    #[serial]
    fn cleanup_orphan_chunk_buffers_noop_under_threshold() {
        init_test_db();
        let fc = [0x03; 32];
        persist_ble_chunk(make_chunk_params(LINK, &fc, 0, b"data")).unwrap();

        cleanup_orphan_chunk_buffers().unwrap();
        assert_eq!(count(LINK, &fc), 1);
    }

    /// Over the threshold, the frames whose newest chunk is oldest go; a frame
    /// that receives a chunk late counts as recent however early it started.
    #[test]
    #[serial]
    fn cleanup_orphan_chunk_buffers_evicts_the_least_recently_persisted_frames() {
        init_test_db();
        let frame = |i: u8| [i; 32];
        let frames = u8::try_from(MAX_PERSISTED_FRAMES).unwrap() + 2;
        for i in 0..frames {
            persist_ble_chunk(make_chunk_params(LINK, &frame(i), 0, b"data")).unwrap();
        }
        // Frame 0 was first, but it is the most recent to receive a chunk.
        persist_ble_chunk(make_chunk_params(LINK, &frame(0), 1, b"late")).unwrap();

        cleanup_orphan_chunk_buffers().unwrap();

        assert_eq!(count(LINK, &frame(0)), 2);
        assert_eq!(count(LINK, &frame(1)), 0);
        assert_eq!(count(LINK, &frame(2)), 0);
        for i in 3..frames {
            assert_eq!(count(LINK, &frame(i)), 1, "frame {i}");
        }
    }

    #[test]
    #[serial]
    fn load_empty_frame_returns_empty_vec() {
        init_test_db();
        let fc = [0x04; 32];
        assert!(load_persisted_chunks(LINK, &fc).unwrap().is_empty());
    }

    #[test]
    #[serial]
    fn delete_single_chunk_nonexistent_is_noop() {
        init_test_db();
        let fc = [0x05; 32];
        delete_single_chunk(LINK, &fc, 99).unwrap();
    }
}
