// SPDX-License-Identifier: MIT OR Apache-2.0

//! The route-chain writes this device made (storage spec §9): the value, the
//! cell it was written at, and the slot each route position produced.
//!
//! A write that stopped part-way continues from the position after the last
//! one it reached. The chain moves strictly in route order: a position
//! already recorded, as a link or as no response, is closed for that chain
//! and is never written again. Writing the value again from the leader would
//! put a second copy there, whose record is not the leader link. This record
//! is what lets a restarted device continue instead.

use anyhow::{anyhow, Result};
use prost::Message;
use rusqlite::{params, OptionalExtension};

use dsm::route_chain::ChainSlot;

use super::get_connection;

/// One recorded write: enough to rebuild its cell (with the members of the
/// set it names) and continue its chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordedWrite {
    pub namespace: Vec<u8>,
    pub cell_key: [u8; 32],
    pub value: Vec<u8>,
    pub seed: [u8; 32],
    pub storage_set_id: [u8; 32],
    pub slots: Vec<ChainSlot>,
}

fn digest32(bytes: Vec<u8>, what: &str) -> Result<[u8; 32]> {
    <[u8; 32]>::try_from(bytes.as_slice()).map_err(|e| anyhow!("{what}: {e}"))
}

/// Record (or update) a write and the slot every position produced.
pub fn record_write(
    namespace: &[u8],
    cell_key: &[u8; 32],
    value: &[u8],
    seed: &[u8; 32],
    storage_set_id: &[u8; 32],
    slots: &[ChainSlot],
) -> Result<()> {
    let digest = dsm::storage_cell::entry_digest(value);
    let binding = get_connection()?;
    let mut conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    let tx = conn.transaction()?;
    tx.execute(
        "INSERT OR IGNORE INTO route_chain_write
            (namespace, cell_key, value_digest, value, seed, storage_set_id)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            namespace,
            cell_key.as_slice(),
            digest.as_slice(),
            value,
            seed.as_slice(),
            storage_set_id.as_slice()
        ],
    )?;
    for (position, slot) in slots.iter().enumerate() {
        tx.execute(
            "INSERT INTO route_chain_write_slot
                (namespace, cell_key, value_digest, position, slot)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(namespace, cell_key, value_digest, position)
             DO UPDATE SET slot = excluded.slot",
            params![
                namespace,
                cell_key.as_slice(),
                digest.as_slice(),
                i64::try_from(position).map_err(|e| anyhow!("slot position: {e}"))?,
                slot.to_proto().encode_to_vec()
            ],
        )?;
    }
    tx.commit()?;
    Ok(())
}

fn slots_of(
    conn: &rusqlite::Connection,
    namespace: &[u8],
    cell_key: &[u8; 32],
    digest: &[u8; 32],
) -> Result<Vec<ChainSlot>> {
    let mut stmt = conn.prepare(
        "SELECT position, slot FROM route_chain_write_slot
          WHERE namespace = ?1 AND cell_key = ?2 AND value_digest = ?3
          ORDER BY position ASC",
    )?;
    let rows = stmt.query_map(
        params![namespace, cell_key.as_slice(), digest.as_slice()],
        |r| Ok((r.get::<_, i64>(0)?, r.get::<_, Vec<u8>>(1)?)),
    )?;
    let mut slots = Vec::new();
    for row in rows {
        let (position, bytes) = row?;
        if usize::try_from(position).map_err(|e| anyhow!("slot position: {e}"))? != slots.len() {
            return Err(anyhow!("recorded slots are not one per position"));
        }
        let proto = dsm::types::proto::ChainSlotV1::decode(bytes.as_slice())
            .map_err(|e| anyhow!("recorded slot: {e}"))?;
        slots.push(ChainSlot::from_proto(&proto).ok_or_else(|| anyhow!("malformed slot"))?);
    }
    Ok(slots)
}

/// The recorded write of `value` at `(namespace, cell_key)`, if any.
pub fn get_write(
    namespace: &[u8],
    cell_key: &[u8; 32],
    value: &[u8],
) -> Result<Option<RecordedWrite>> {
    let digest = dsm::storage_cell::entry_digest(value);
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    let row = conn
        .query_row(
            "SELECT seed, storage_set_id FROM route_chain_write
              WHERE namespace = ?1 AND cell_key = ?2 AND value_digest = ?3",
            params![namespace, cell_key.as_slice(), digest.as_slice()],
            |r| Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, Vec<u8>>(1)?)),
        )
        .optional()?;
    row.map(|(seed, set_id)| {
        Ok(RecordedWrite {
            namespace: namespace.to_vec(),
            cell_key: *cell_key,
            value: value.to_vec(),
            seed: digest32(seed, "seed")?,
            storage_set_id: digest32(set_id, "storage set id")?,
            slots: slots_of(&conn, namespace, cell_key, &digest)?,
        })
    })
    .transpose()
}

/// Up to `limit` recorded writes that have not reached the end of their
/// route: fewer slots than `route_len` positions.
pub fn open_writes(route_len: usize, limit: u32) -> Result<Vec<RecordedWrite>> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    let mut stmt = conn.prepare(
        "SELECT w.namespace, w.cell_key, w.value_digest, w.value, w.seed, w.storage_set_id
           FROM route_chain_write w
          WHERE (SELECT COUNT(*) FROM route_chain_write_slot s
                  WHERE s.namespace = w.namespace AND s.cell_key = w.cell_key
                    AND s.value_digest = w.value_digest) < ?1
          ORDER BY w.rowid ASC LIMIT ?2",
    )?;
    let route_len = i64::try_from(route_len).map_err(|e| anyhow!("route length: {e}"))?;
    let rows = stmt.query_map(params![route_len, i64::from(limit)], |r| {
        Ok((
            r.get::<_, Vec<u8>>(0)?,
            r.get::<_, Vec<u8>>(1)?,
            r.get::<_, Vec<u8>>(2)?,
            r.get::<_, Vec<u8>>(3)?,
            r.get::<_, Vec<u8>>(4)?,
            r.get::<_, Vec<u8>>(5)?,
        ))
    })?;
    let mut out = Vec::new();
    for row in rows {
        let (namespace, key, digest, value, seed, set_id) = row?;
        let cell_key = digest32(key, "cell key")?;
        let digest = digest32(digest, "value digest")?;
        let slots = slots_of(&conn, &namespace, &cell_key, &digest)?;
        out.push(RecordedWrite {
            namespace,
            cell_key,
            value,
            seed: digest32(seed, "seed")?,
            storage_set_id: digest32(set_id, "storage set id")?,
            slots,
        });
    }
    Ok(out)
}
