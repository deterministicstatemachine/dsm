// SPDX-License-Identifier: Apache-2.0

//! Durable storage for the ERA faucet claim flow (client-DB schema v8).
//!
//! Three kinds of state, three disciplines:
//!
//! - **Frozen envelopes** (ticket claim, root claim): exact signed bytes,
//!   written BEFORE the first external write, `INSERT OR IGNORE`d so a retry
//!   can never replace them, loaded verbatim forever after. Deterministic
//!   SPHINCS+ signing means a regenerated envelope is indistinguishable from
//!   a replayed one — so regeneration is made impossible, not discouraged.
//! - **The admitted coordinate**: one row, written in the SAME transaction
//!   that clears the pending admission.
//! - **The leaf cache**: strategy A of the producer-SMT persistence. A cache,
//!   never an authority — the loader recomputes its root and discards the
//!   whole cache on mismatch, falling back to witness replay.

use anyhow::{anyhow, Result};
use rusqlite::{params, OptionalExtension, Transaction};

use super::get_connection;

fn digest32(v: Vec<u8>, what: &str) -> Result<[u8; 32]> {
    <[u8; 32]>::try_from(v.as_slice()).map_err(|_| anyhow!("{what} is not 32 bytes"))
}

/// Freeze a ticket-claim envelope. `INSERT OR IGNORE`: the FIRST bytes win
/// forever, exactly like the register cell they will be sent to.
pub fn put_frozen_ticket_claim(
    faucet_id: &[u8; 32],
    ticket_index: u64,
    envelope: &[u8],
    now: i64,
) -> Result<()> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    conn.execute(
        "INSERT OR IGNORE INTO faucet_ticket_claim_local
           (faucet_id, ticket_index, envelope, created_at)
         VALUES (?1, ?2, ?3, ?4)",
        params![
            faucet_id.as_slice(),
            i64::try_from(ticket_index).map_err(|_| anyhow!("ticket_index overflow"))?,
            envelope,
            now
        ],
    )?;
    Ok(())
}

/// The frozen ticket-claim envelope, exact bytes.
pub fn get_frozen_ticket_claim(faucet_id: &[u8; 32], ticket_index: u64) -> Result<Option<Vec<u8>>> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    let row = conn
        .query_row(
            "SELECT envelope FROM faucet_ticket_claim_local
              WHERE faucet_id = ?1 AND ticket_index = ?2",
            params![
                faucet_id.as_slice(),
                i64::try_from(ticket_index).map_err(|_| anyhow!("ticket_index overflow"))?
            ],
            |r| r.get::<_, Vec<u8>>(0),
        )
        .optional()?;
    Ok(row)
}

/// Freeze the economic-root claim envelope for one position, BEFORE the first
/// register-member write.
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
