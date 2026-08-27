// SPDX-License-Identifier: Apache-2.0

//! Operation-neutral durable state of the economic lineage: the frozen root
//! claim per position, the admitted coordinate, the producer leaf cache, and
//! the device-local memo of peer positions THIS verifier validated.
//!
//! Split out of `economic_faucet.rs`: only the ticket table is
//! faucet-specific; everything here serves every admission kind.
//!
//! The peer memo is a cache of the verifier's OWN conclusions and is never
//! authority over a live register read — a walk that fails `Invalid` from a
//! cached start discards the rows and re-walks from the activation root.

use anyhow::{anyhow, Result};
use rusqlite::{params, OptionalExtension, Transaction};

use super::get_connection;

fn digest32(v: Vec<u8>, what: &str) -> Result<[u8; 32]> {
    <[u8; 32]>::try_from(v.as_slice()).map_err(|_| anyhow!("{what} is not 32 bytes"))
}

pub fn put_frozen_root_claim(
    economic_position: u64,
    k_root: &[u8; 32],
    envelope: &[u8],
    now: i64,
) -> Result<()> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    conn.execute(
        "INSERT OR IGNORE INTO economic_root_claim_local
           (economic_position, k_root, envelope, created_at)
         VALUES (?1, ?2, ?3, ?4)",
        params![
            i64::try_from(economic_position).map_err(|_| anyhow!("position overflow"))?,
            k_root.as_slice(),
            envelope,
            now
        ],
    )?;
    Ok(())
}

/// The frozen root-claim envelope for one position, exact bytes.
pub fn get_frozen_root_claim(economic_position: u64) -> Result<Option<([u8; 32], Vec<u8>)>> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    let row = conn
        .query_row(
            "SELECT k_root, envelope FROM economic_root_claim_local
              WHERE economic_position = ?1",
            params![i64::try_from(economic_position).map_err(|_| anyhow!("position overflow"))?],
            |r| Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, Vec<u8>>(1)?)),
        )
        .optional()?;
    row.map(|(k, e)| Ok((digest32(k, "k_root")?, e)))
        .transpose()
}

/// The admitted economic coordinate, if any.
pub fn get_admitted() -> Result<Option<(u64, [u8; 32])>> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    let row = conn
        .query_row(
            "SELECT economic_position, economic_root FROM economic_admitted WHERE id = 1",
            [],
            |r| Ok((r.get::<_, i64>(0)?, r.get::<_, Vec<u8>>(1)?)),
        )
        .optional()?;
    row.map(|(p, root)| {
        Ok((
            u64::try_from(p).map_err(|_| anyhow!("position negative"))?,
            digest32(root, "economic_root")?,
        ))
    })
    .transpose()
}

/// The admitted coordinate, read INSIDE a caller's transaction — the CAS
/// re-assert the admission commit runs before making acceptance durable.
pub fn get_admitted_with_conn(conn: &rusqlite::Connection) -> Result<Option<(u64, [u8; 32])>> {
    let row = conn
        .query_row(
            "SELECT economic_position, economic_root FROM economic_admitted WHERE id = 1",
            [],
            |r| Ok((r.get::<_, i64>(0)?, r.get::<_, Vec<u8>>(1)?)),
        )
        .optional()?;
    row.map(|(p, root)| {
        Ok((
            u64::try_from(p).map_err(|_| anyhow!("position negative"))?,
            digest32(root, "economic_root")?,
        ))
    })
    .transpose()
}

/// Record admission + install the leaf cache, INSIDE the caller's transaction
/// — the same one that clears the pending admission, so "admitted" and "no
/// longer pending" cannot disagree.
///
/// `leaves` are `(leaf_key, leaf_value, exact state CCB bytes)` for the FULL
/// post-transition tree. Full replacement, not a delta: the cache's only
/// claim to correctness is root equality on load, and a full write is what
/// keeps a crash mid-update from leaving a plausible-but-wrong mixture.
pub fn record_admitted_with_conn(
    tx: &Transaction<'_>,
    economic_position: u64,
    economic_root: &[u8; 32],
    leaves: &[([u8; 32], [u8; 32], Vec<u8>)],
    now: i64,
) -> Result<()> {
    tx.execute(
        "INSERT INTO economic_admitted (id, economic_position, economic_root, updated_at)
         VALUES (1, ?1, ?2, ?3)
         ON CONFLICT(id) DO UPDATE SET
             economic_position = excluded.economic_position,
             economic_root = excluded.economic_root,
             updated_at = excluded.updated_at",
        params![
            i64::try_from(economic_position).map_err(|_| anyhow!("position overflow"))?,
            economic_root.as_slice(),
            now
        ],
    )?;
    tx.execute("DELETE FROM economic_leaf_cache", [])?;
    for (key, value, ccb) in leaves {
        tx.execute(
            "INSERT INTO economic_leaf_cache (leaf_key, leaf_value, state_ccb, updated_at)
             VALUES (?1, ?2, ?3, ?4)",
            params![key.as_slice(), value.as_slice(), ccb, now],
        )?;
    }
    Ok(())
}

/// Load the cached leaves: `(leaf_key, leaf_value, state CCB bytes)`.
/// The CALLER must recompute the root over these and compare it with the
/// admitted root — a mismatched cache is discarded, never trusted.
pub fn load_leaf_cache() -> Result<Vec<([u8; 32], [u8; 32], Vec<u8>)>> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    let mut stmt =
        conn.prepare("SELECT leaf_key, leaf_value, state_ccb FROM economic_leaf_cache")?;
    let rows = stmt.query_map([], |r| {
        Ok((
            r.get::<_, Vec<u8>>(0)?,
            r.get::<_, Vec<u8>>(1)?,
            r.get::<_, Vec<u8>>(2)?,
        ))
    })?;
    let mut out = Vec::new();
    for row in rows {
        let (k, v, ccb) = row?;
        out.push((digest32(k, "leaf_key")?, digest32(v, "leaf_value")?, ccb));
    }
    Ok(out)
}

/// The best cached validated start strictly BELOW `target_position`.
pub fn best_peer_start(
    peer_genesis: &[u8; 32],
    peer_devid: &[u8; 32],
    target_position: u64,
) -> Result<Option<(u64, [u8; 32])>> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    let row = conn
        .query_row(
            "SELECT validated_position, validated_root FROM peer_economic_lineage
             WHERE peer_genesis = ?1 AND peer_devid = ?2 AND validated_position < ?3
             ORDER BY validated_position DESC LIMIT 1",
            params![
                peer_genesis.as_slice(),
                peer_devid.as_slice(),
                target_position as i64
            ],
            |r| Ok((r.get::<_, i64>(0)?, r.get::<_, Vec<u8>>(1)?)),
        )
        .optional()?;
    Ok(match row {
        Some((pos, root)) => Some((
            u64::try_from(pos).map_err(|_| anyhow!("negative cached position"))?,
            <[u8; 32]>::try_from(root.as_slice())
                .map_err(|_| anyhow!("cached root is not 32 bytes"))?,
        )),
        None => None,
    })
}

/// Record one validated peer coordinate (this verifier's own conclusion).
pub fn record_peer_validated(
    peer_genesis: &[u8; 32],
    peer_devid: &[u8; 32],
    validated_position: u64,
    validated_root: &[u8; 32],
) -> Result<()> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    conn.execute(
        "INSERT OR REPLACE INTO peer_economic_lineage(
             peer_genesis, peer_devid, validated_position, validated_root)
         VALUES(?1, ?2, ?3, ?4)",
        params![
            peer_genesis.as_slice(),
            peer_devid.as_slice(),
            validated_position as i64,
            validated_root.as_slice()
        ],
    )?;
    Ok(())
}

/// Discard every cached coordinate for one peer — the cached-start-was-wrong
/// path.
pub fn clear_peer_lineage(peer_genesis: &[u8; 32], peer_devid: &[u8; 32]) -> Result<()> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    conn.execute(
        "DELETE FROM peer_economic_lineage WHERE peer_genesis = ?1 AND peer_devid = ?2",
        params![peer_genesis.as_slice(), peer_devid.as_slice()],
    )?;
    Ok(())
}
