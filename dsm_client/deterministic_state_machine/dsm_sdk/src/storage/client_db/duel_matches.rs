// SPDX-License-Identifier: MIT OR Apache-2.0

//! The computed escrow matches this wallet holds a stake in (SoFi Amendment
//! S22): what `computed_flow` keeps between one entry and the next.
//!
//! A row per match cell holds the verified state after the last entry the
//! wallet applied — the index, the head, each side's unopened commitment and
//! the outcome program's progress — so the next entry is applied in O(1),
//! never by replaying the match from its first entry. Every applied entry is
//! kept with its head and its side's signature, one per index: the primary
//! key `(match_cell, idx)` is what makes "this wallet never signs two
//! different entries at one index" hold across a crash, because a signature
//! leaves the wallet only after the row holding it is committed.
//!
//! Nothing here is authority. Core decides a match from what its cells hold.

use anyhow::{anyhow, Result};
use rusqlite::{params, Connection, OptionalExtension};

use super::get_connection;

type D32 = [u8; 32];

/// A side's unopened commitment: the index it was made at and what it
/// commits.
pub type OpenCommitment = (u32, D32);

/// One match, as the wallet keeps it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DuelMatchRow {
    pub match_cell: D32,
    /// 1 for side A, 2 for side B.
    pub side: u8,
    /// This wallet's own `ComputedEscrowTerms` bytes.
    pub terms: Vec<u8>,
    pub setup: Vec<u8>,
    pub vault_id: D32,
    /// This wallet's signature over `m_ready`, once it signed one.
    pub ready: Option<Vec<u8>>,
    /// The `MatchStart` bytes this wallet found final at the start cell.
    pub start_final: Option<Vec<u8>>,
    pub last_index: u32,
    /// `h_{last_index}`.
    pub head: D32,
    /// Side A's and side B's unopened commitments.
    pub open: [Option<OpenCommitment>; 2],
    /// The outcome program's progress after the last entry.
    pub progress: Vec<u8>,
    /// The `EquivocationProof` bytes, once the other side was caught signing
    /// two heads at one index.
    pub equivocation: Option<Vec<u8>>,
}

/// One applied entry: its bytes, the head after it and its side's signature
/// over that head.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DuelEntryRow {
    pub idx: u32,
    pub side: u8,
    pub entry: Vec<u8>,
    pub head: D32,
    pub signature: Vec<u8>,
}

fn d32(bytes: Vec<u8>, what: &str) -> Result<D32> {
    <D32>::try_from(bytes.as_slice()).map_err(|e| anyhow!("{what}: {e}"))
}

fn open_bytes(open: &Option<OpenCommitment>) -> Option<Vec<u8>> {
    open.as_ref().map(|(index, commitment)| {
        let mut out = index.to_be_bytes().to_vec();
        out.extend(commitment);
        out
    })
}

fn open_of(bytes: Option<Vec<u8>>) -> Result<Option<OpenCommitment>> {
    bytes
        .map(|b| {
            let (index, commitment) = b
                .split_at_checked(4)
                .ok_or_else(|| anyhow!("a kept commitment is cut short"))?;
            let index: [u8; 4] = index
                .try_into()
                .map_err(|e| anyhow!("a kept commitment's index: {e}"))?;
            Ok((
                u32::from_be_bytes(index),
                d32(commitment.to_vec(), "a kept commitment")?,
            ))
        })
        .transpose()
}

fn connection() -> Result<std::sync::Arc<std::sync::Mutex<Connection>>> {
    get_connection()
}

/// Keep a match this wallet just locked a stake in. A second insert of the
/// same match is refused: a match cell is locked once.
pub fn insert_match(row: &DuelMatchRow) -> Result<()> {
    let binding = connection()?;
    let conn = binding
        .lock()
        .map_err(|e| anyhow!("the database lock: {e}"))?;
    conn.execute(
        "INSERT INTO duel_match
            (match_cell, side, terms, setup, vault_id, ready, start_final, last_index, head,
             open_a, open_b, progress, equivocation)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
        params![
            row.match_cell.as_slice(),
            i64::from(row.side),
            row.terms,
            row.setup,
            row.vault_id.as_slice(),
            row.ready,
            row.start_final,
            i64::from(row.last_index),
            row.head.as_slice(),
            open_bytes(&row.open[0]),
            open_bytes(&row.open[1]),
            row.progress,
            row.equivocation,
        ],
    )?;
    Ok(())
}

fn match_from(conn: &Connection, match_cell: &D32) -> Result<Option<DuelMatchRow>> {
    let row = conn
        .query_row(
            "SELECT side, terms, setup, vault_id, ready, start_final, last_index, head, open_a,
                    open_b, progress, equivocation
               FROM duel_match WHERE match_cell = ?1",
            params![match_cell.as_slice()],
            |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, Vec<u8>>(1)?,
                    r.get::<_, Vec<u8>>(2)?,
                    r.get::<_, Vec<u8>>(3)?,
                    r.get::<_, Option<Vec<u8>>>(4)?,
                    r.get::<_, Option<Vec<u8>>>(5)?,
                    r.get::<_, i64>(6)?,
                    r.get::<_, Vec<u8>>(7)?,
                    r.get::<_, Option<Vec<u8>>>(8)?,
                    r.get::<_, Option<Vec<u8>>>(9)?,
                    r.get::<_, Vec<u8>>(10)?,
                    r.get::<_, Option<Vec<u8>>>(11)?,
                ))
            },
        )
        .optional()?;
    row.map(
        |(side, terms, setup, vault_id, ready, start_final, last, head, a, b, progress, eq)| {
            Ok(DuelMatchRow {
                match_cell: *match_cell,
                side: u8::try_from(side).map_err(|e| anyhow!("a kept side: {e}"))?,
                terms,
                setup,
                vault_id: d32(vault_id, "a kept vault id")?,
                ready,
                start_final,
                last_index: u32::try_from(last).map_err(|e| anyhow!("a kept index: {e}"))?,
                head: d32(head, "a kept head")?,
                open: [open_of(a)?, open_of(b)?],
                progress,
                equivocation: eq,
            })
        },
    )
    .transpose()
}

/// The match at `match_cell`, when this wallet locked a stake in it.
pub fn get_match(match_cell: &D32) -> Result<Option<DuelMatchRow>> {
    let binding = connection()?;
    let conn = binding
        .lock()
        .map_err(|e| anyhow!("the database lock: {e}"))?;
    match_from(&conn, match_cell)
}

fn set_column(match_cell: &D32, column: &str, value: &[u8]) -> Result<()> {
    let binding = connection()?;
    let conn = binding
        .lock()
        .map_err(|e| anyhow!("the database lock: {e}"))?;
    let sql = format!("UPDATE duel_match SET {column} = ?1 WHERE match_cell = ?2");
    let changed = conn.execute(&sql, params![value, match_cell.as_slice()])?;
    if changed != 1 {
        return Err(anyhow!("no kept match at that cell"));
    }
    Ok(())
}

/// Keep this wallet's ready signature for the match.
pub fn set_ready(match_cell: &D32, signature: &[u8]) -> Result<()> {
    set_column(match_cell, "ready", signature)
}

/// Keep the Start this wallet found final at the start cell.
pub fn set_start_final(match_cell: &D32, start: &[u8]) -> Result<()> {
    set_column(match_cell, "start_final", start)
}

/// Keep the proof that the other side equivocated.
pub fn set_equivocation(match_cell: &D32, proof: &[u8]) -> Result<()> {
    set_column(match_cell, "equivocation", proof)
}

/// What one application of entries moved the match to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Advance {
    pub last_index: u32,
    pub head: D32,
    pub open: [Option<OpenCommitment>; 2],
    pub progress: Vec<u8>,
}

/// Move the match from `from_index` to `to`, keeping `entries` (in index
/// order, `from_index + 1` up to `to.last_index`), in one transaction. Refused
/// when the match is no longer at `from_index` (another request applied
/// entries first), or when an index already holds an entry: nothing is kept
/// then, and no signature in `entries` may leave the wallet.
pub fn advance(
    match_cell: &D32,
    from_index: u32,
    to: &Advance,
    entries: &[DuelEntryRow],
) -> Result<()> {
    let expected: Vec<u32> = (from_index + 1..=to.last_index).collect();
    let given: Vec<u32> = entries.iter().map(|e| e.idx).collect();
    if expected != given {
        return Err(anyhow!(
            "the entries kept are not exactly those after index {from_index}"
        ));
    }
    let binding = connection()?;
    let mut conn = binding
        .lock()
        .map_err(|e| anyhow!("the database lock: {e}"))?;
    let tx = conn.transaction()?;
    let changed = tx.execute(
        "UPDATE duel_match
            SET last_index = ?1, head = ?2, open_a = ?3, open_b = ?4, progress = ?5
          WHERE match_cell = ?6 AND last_index = ?7",
        params![
            i64::from(to.last_index),
            to.head.as_slice(),
            open_bytes(&to.open[0]),
            open_bytes(&to.open[1]),
            to.progress,
            match_cell.as_slice(),
            i64::from(from_index),
        ],
    )?;
    if changed != 1 {
        return Err(anyhow!(
            "the match is no longer at index {from_index}: nothing was applied"
        ));
    }
    for e in entries {
        tx.execute(
            "INSERT INTO duel_entry (match_cell, idx, side, entry, head, signature)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                match_cell.as_slice(),
                i64::from(e.idx),
                i64::from(e.side),
                e.entry,
                e.head.as_slice(),
                e.signature,
            ],
        )?;
    }
    tx.commit()?;
    Ok(())
}

fn entry_of(r: &rusqlite::Row<'_>) -> rusqlite::Result<(i64, i64, Vec<u8>, Vec<u8>, Vec<u8>)> {
    Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
}

fn entry_row(raw: (i64, i64, Vec<u8>, Vec<u8>, Vec<u8>)) -> Result<DuelEntryRow> {
    let (idx, side, entry, head, signature) = raw;
    Ok(DuelEntryRow {
        idx: u32::try_from(idx).map_err(|e| anyhow!("a kept index: {e}"))?,
        side: u8::try_from(side).map_err(|e| anyhow!("a kept side: {e}"))?,
        entry,
        head: d32(head, "a kept head")?,
        signature,
    })
}

/// The entry kept at `idx`, if any.
pub fn entry_at(match_cell: &D32, idx: u32) -> Result<Option<DuelEntryRow>> {
    let binding = connection()?;
    let conn = binding
        .lock()
        .map_err(|e| anyhow!("the database lock: {e}"))?;
    conn.query_row(
        "SELECT idx, side, entry, head, signature FROM duel_entry
          WHERE match_cell = ?1 AND idx = ?2",
        params![match_cell.as_slice(), i64::from(idx)],
        entry_of,
    )
    .optional()?
    .map(entry_row)
    .transpose()
}

/// Every entry kept for the match, in index order.
pub fn entries(match_cell: &D32) -> Result<Vec<DuelEntryRow>> {
    let binding = connection()?;
    let conn = binding
        .lock()
        .map_err(|e| anyhow!("the database lock: {e}"))?;
    let mut stmt = conn.prepare(
        "SELECT idx, side, entry, head, signature FROM duel_entry
          WHERE match_cell = ?1 ORDER BY idx ASC",
    )?;
    let rows = stmt.query_map(params![match_cell.as_slice()], entry_of)?;
    let mut out = Vec::new();
    for row in rows {
        out.push(entry_row(row?)?);
    }
    Ok(out)
}
