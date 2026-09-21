// SPDX-License-Identifier: Apache-2.0

//! Durable client state for the native ERA reserve (client-DB schema v15).
//!
//! Three kinds of state, three disciplines:
//!
//! - **Frozen releases**: the exact signed bytes this device wrote at one
//!   parent root, `INSERT OR IGNORE`d before the first member write so a
//!   retry replays them and never re-signs (deterministic SPHINCS+ makes a
//!   regenerated envelope indistinguishable from a replayed one).
//! - **The lineage memo**: every final release a walk established, with the
//!   state it succeeded. Finality is permanent, so a memoised state is a
//!   sound start for the next walk. A cache of Core's conclusions, never
//!   authority over a cell.
//! - **The carry queue**: every successor this device wrote, with the members
//!   that hold it, until all of them do (owner ruling: all-member
//!   replication, asynchronous, never a condition of finality).

use anyhow::{anyhow, Result};
use rusqlite::{params, OptionalExtension};

use dsm::economic::native_reserve::{NativeReserveState, VerifiedRelease};
use dsm::economic::provenance::ReserveReleaseWin;

use super::get_connection;

fn u64_of(v: i64, what: &str) -> Result<u64> {
    u64::try_from(v).map_err(|_| anyhow!("{what} is negative"))
}

fn i64_of(v: u64, what: &str) -> Result<i64> {
    i64::try_from(v).map_err(|_| anyhow!("{what} overflows"))
}

// ── Frozen releases ──────────────────────────────────────────────────────────

/// Freeze the release this device wrote at `parent_root`. `INSERT OR IGNORE`:
/// the FIRST bytes win forever, exactly like the cell they are sent to.
pub fn put_frozen_release(
    reserve_id: &[u8; 32],
    parent_root: &[u8; 32],
    envelope: &[u8],
    now: i64,
) -> Result<()> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    conn.execute(
        "INSERT OR IGNORE INTO native_reserve_release_local
           (reserve_id, parent_root, envelope, created_at)
         VALUES (?1, ?2, ?3, ?4)",
        params![reserve_id.as_slice(), parent_root.as_slice(), envelope, now],
    )?;
    Ok(())
}

/// The frozen release at `parent_root`, exact bytes.
pub fn get_frozen_release(
    reserve_id: &[u8; 32],
    parent_root: &[u8; 32],
) -> Result<Option<Vec<u8>>> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    Ok(conn
        .query_row(
            "SELECT envelope FROM native_reserve_release_local
              WHERE reserve_id = ?1 AND parent_root = ?2",
            params![reserve_id.as_slice(), parent_root.as_slice()],
            |r| r.get::<_, Vec<u8>>(0),
        )
        .optional()?)
}

// ── The lineage memo ─────────────────────────────────────────────────────────

/// Memoise one final release with the state it succeeded.
pub fn record_final_release(
    parent: &NativeReserveState,
    release: &VerifiedRelease,
    child: &NativeReserveState,
) -> Result<()> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    conn.execute(
        "INSERT OR IGNORE INTO native_reserve_lineage_memo
           (reserve_id, generation, parent_remaining, remaining, recipient_genesis,
            recipient_devid, recipient_position, envelope)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            parent.reserve_id.as_slice(),
            i64_of(child.generation, "generation")?,
            i64_of(parent.remaining_supply, "parent remaining")?,
            i64_of(child.remaining_supply, "remaining")?,
            release.body.recipient_genesis.as_slice(),
            release.body.recipient_devid.as_slice(),
            i64_of(
                release.body.recipient_economic_position,
                "recipient position"
            )?,
            release.envelope_bytes.as_slice(),
        ],
    )?;
    Ok(())
}

/// The latest memoised state of the reserve whose genesis is `genesis`, or
/// `genesis` itself when nothing is memoised.
pub fn latest_state(genesis: &NativeReserveState) -> Result<NativeReserveState> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    let row: Option<(i64, i64)> = conn
        .query_row(
            "SELECT generation, remaining FROM native_reserve_lineage_memo
              WHERE reserve_id = ?1 ORDER BY generation DESC LIMIT 1",
            params![genesis.reserve_id.as_slice()],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    Ok(match row {
        Some((generation, remaining)) => NativeReserveState {
            generation: u64_of(generation, "generation")?,
            remaining_supply: u64_of(remaining, "remaining")?,
            ..*genesis
        },
        None => *genesis,
    })
}

/// The memoised final release at `generation`, with the state it succeeded.
pub fn release_at(
    genesis: &NativeReserveState,
    generation: u64,
) -> Result<Option<ReserveReleaseWin>> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    let row: Option<(i64, Vec<u8>)> = conn
        .query_row(
            "SELECT parent_remaining, envelope FROM native_reserve_lineage_memo
              WHERE reserve_id = ?1 AND generation = ?2",
            params![
                genesis.reserve_id.as_slice(),
                i64_of(generation, "generation")?
            ],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    Ok(row.map(|(parent_remaining, envelope)| ReserveReleaseWin {
        envelope_bytes: envelope,
        parent: NativeReserveState {
            generation: generation - 1,
            remaining_supply: u64_of(parent_remaining, "parent remaining").unwrap_or(0),
            ..*genesis
        },
    }))
}

/// The memoised final release naming `(genesis, devid, position)` as its
/// recipient, if the walk saw one: `(generation, envelope)`. How a claim
/// that crashed after its release became final finds it again.
pub fn release_for_recipient(
    reserve_id: &[u8; 32],
    recipient_genesis: &[u8; 32],
    recipient_devid: &[u8; 32],
    recipient_position: u64,
) -> Result<Option<(u64, Vec<u8>)>> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    let row: Option<(i64, Vec<u8>)> = conn
        .query_row(
            "SELECT generation, envelope FROM native_reserve_lineage_memo
              WHERE reserve_id = ?1 AND recipient_genesis = ?2 AND recipient_devid = ?3
                AND recipient_position = ?4
              ORDER BY generation ASC LIMIT 1",
            params![
                reserve_id.as_slice(),
                recipient_genesis.as_slice(),
                recipient_devid.as_slice(),
                i64_of(recipient_position, "recipient position")?
            ],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    row.map(|(g, e)| Ok((u64_of(g, "generation")?, e)))
        .transpose()
}

// ── The carry queue ──────────────────────────────────────────────────────────

/// One queued successor and the members already holding it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingCarry {
    pub cell_key: [u8; 32],
    pub namespace: Vec<u8>,
    pub value: Vec<u8>,
    pub carried: Vec<String>,
}

/// Queue the exact bytes written at `cell_key` for the background carry.
pub fn record_carry(cell_key: &[u8; 32], namespace: &[u8], value: &[u8]) -> Result<()> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    conn.execute(
        "INSERT OR IGNORE INTO native_reserve_carry (cell_key, namespace, value)
         VALUES (?1, ?2, ?3)",
        params![cell_key.as_slice(), namespace, value],
    )?;
    Ok(())
}

/// Record that `member_id` holds the bytes queued at `cell_key`.
pub fn record_carried(cell_key: &[u8; 32], member_id: &str) -> Result<()> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    conn.execute(
        "INSERT OR IGNORE INTO native_reserve_carry_member (cell_key, member_id) VALUES (?1, ?2)",
        params![cell_key.as_slice(), member_id],
    )?;
    Ok(())
}

/// The members recorded as holding the bytes queued at `cell_key`.
pub fn carried_members(cell_key: &[u8; 32]) -> Result<Vec<String>> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    let mut stmt =
        conn.prepare("SELECT member_id FROM native_reserve_carry_member WHERE cell_key = ?1")?;
    let rows = stmt.query_map(params![cell_key.as_slice()], |r| r.get::<_, String>(0))?;
    Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
}

/// Up to `limit` queued successors, oldest first, each with its holders.
pub fn pending_carries(limit: u32) -> Result<Vec<PendingCarry>> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    let mut stmt = conn.prepare(
        "SELECT cell_key, namespace, value FROM native_reserve_carry ORDER BY rowid ASC LIMIT ?1",
    )?;
    let rows = stmt.query_map(params![limit], |r| {
        Ok((
            r.get::<_, Vec<u8>>(0)?,
            r.get::<_, Vec<u8>>(1)?,
            r.get::<_, Vec<u8>>(2)?,
        ))
    })?;
    let mut out = Vec::new();
    for row in rows {
        let (key, namespace, value) = row?;
        let cell_key = <[u8; 32]>::try_from(key.as_slice())
            .map_err(|_| anyhow!("carry cell key is not 32 bytes"))?;
        let mut holders =
            conn.prepare("SELECT member_id FROM native_reserve_carry_member WHERE cell_key = ?1")?;
        let carried = holders
            .query_map(params![cell_key.as_slice()], |r| r.get::<_, String>(0))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        out.push(PendingCarry {
            cell_key,
            namespace,
            value,
            carried,
        });
    }
    Ok(out)
}

/// Drop a successor from the queue once every member holds it.
pub fn clear_carry(cell_key: &[u8; 32]) -> Result<()> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    conn.execute(
        "DELETE FROM native_reserve_carry_member WHERE cell_key = ?1",
        params![cell_key.as_slice()],
    )?;
    conn.execute(
        "DELETE FROM native_reserve_carry WHERE cell_key = ?1",
        params![cell_key.as_slice()],
    )?;
    Ok(())
}
