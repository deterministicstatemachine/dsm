// SPDX-License-Identifier: MIT OR Apache-2.0

//! Each device's one backup slot (DSM Amendment A40; owner, 2026-11-23: "There
//! only should be one backup per phone, per device", and "It should replace
//! it. It should be a separate thing, and yes, it needs the key to do such a
//! thing").
//!
//! A slot holds one whole backup and at most one being written. A start the
//! device's cell lock signed (checked by the API with
//! `dsm::wallet_backup::admit_start` before it reaches here) names a
//! generation higher than any the slot took and every part's digest: it
//! replaces the backup being written, whose parts are deleted with it. A part
//! is taken only as the digest the start names, and the moment the slot holds
//! every part of the one being written, it is the whole backup and the parts
//! of the one before are deleted. Unlike a cell, a slot is written over: the
//! network's full history is its cells and objects, never the slot.

use anyhow::{anyhow, Result};

use super::pg::{begin_durable_write, DBPool};

type D32 = [u8; 32];

/// What a member holds at a slot: the whole backup's generation and its
/// parts' digests (0 and none before one is whole), and the highest
/// generation any start it took named.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SlotState {
    pub generation: u64,
    pub part_digests: Vec<u8>,
    pub highest_generation: u64,
}

/// How a start came out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartTaken {
    /// The backup it starts is the one being written.
    Writing,
    /// The backup it starts is already the whole one: the same start again.
    Whole,
    /// Its generation is not higher than one the slot already took.
    Stale,
}

/// How a part came out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PartTaken {
    /// Taken; the backup is still being written.
    Writing,
    /// Taken, or already held: the backup it belongs to is the whole one.
    Whole,
    /// No backup of its generation is being written or whole here.
    NotWriting,
    /// The start names no such part.
    NoSuchPart,
    /// Its digest is not the one the start names for it.
    WrongDigest,
}

fn as_i64(n: u64, what: &str) -> Result<i64> {
    i64::try_from(n).map_err(|e| anyhow!("{what} {n} past the store's range: {e}"))
}

fn as_u64(n: i64, what: &str) -> Result<u64> {
    u64::try_from(n).map_err(|e| anyhow!("stored {what} {n} is negative: {e}"))
}

/// The digest of part `part` in a list of digests, 32 bytes each.
fn digest_at(digests: &[u8], part: u32) -> Option<D32> {
    let (whole, _) = digests.as_chunks::<32>();
    whole.get(part as usize).copied()
}

fn count_of(digests: &[u8]) -> usize {
    digests.as_chunks::<32>().0.len()
}

/// The slot's row, locked for the rest of `tx`, created empty first if the
/// slot has none.
async fn locked_row(
    tx: &deadpool_postgres::Transaction<'_>,
    slot: &D32,
) -> Result<(i64, Vec<u8>, Option<i64>, Option<Vec<u8>>)> {
    tx.execute(
        "INSERT INTO backup_slots (slot_key, generation, part_digests)
         VALUES ($1, 0, ''::bytea) ON CONFLICT (slot_key) DO NOTHING",
        &[&slot.as_slice()],
    )
    .await?;
    let row = tx
        .query_one(
            "SELECT generation, part_digests, writing_generation, writing_digests
               FROM backup_slots WHERE slot_key = $1 FOR UPDATE",
            &[&slot.as_slice()],
        )
        .await?;
    Ok((row.get(0), row.get(1), row.get(2), row.get(3)))
}

fn state_of(whole: i64, digests: Vec<u8>, writing: Option<i64>) -> Result<SlotState> {
    let generation = as_u64(whole, "generation")?;
    let highest = writing.map_or(Ok(generation), |w| {
        as_u64(w, "generation").map(|w| w.max(generation))
    })?;
    Ok(SlotState {
        generation,
        part_digests: digests,
        highest_generation: highest,
    })
}

/// Take a start the device's lock signed for `generation` of `slot`, whose
/// parts have `digests` (32 bytes each), and answer how it came out and what
/// the slot holds after it.
pub async fn backup_start(
    pool: &DBPool,
    slot: &D32,
    generation: u64,
    digests: &[u8],
) -> Result<(StartTaken, SlotState)> {
    let generation = as_i64(generation, "generation")?;
    let mut client = pool.get().await?;
    let tx = begin_durable_write(&mut client).await?;
    let (whole, whole_digests, writing, writing_digests) = locked_row(&tx, slot).await?;
    let highest = writing.map_or(whole, |w| w.max(whole));
    let taken = if generation == whole && whole_digests == digests {
        StartTaken::Whole
    } else if Some(generation) == writing && writing_digests.as_deref() == Some(digests) {
        StartTaken::Writing
    } else if generation <= highest {
        StartTaken::Stale
    } else {
        // A higher generation: the backup being written, cut short, is
        // written over.
        if let Some(cut_short) = writing {
            tx.execute(
                "DELETE FROM backup_parts WHERE slot_key = $1 AND generation = $2",
                &[&slot.as_slice(), &cut_short],
            )
            .await?;
        }
        tx.execute(
            "UPDATE backup_slots SET writing_generation = $2, writing_digests = $3
              WHERE slot_key = $1",
            &[&slot.as_slice(), &generation, &digests],
        )
        .await?;
        StartTaken::Writing
    };
    let state = match taken {
        StartTaken::Writing => state_of(whole, whole_digests, Some(generation))?,
        StartTaken::Whole | StartTaken::Stale => state_of(whole, whole_digests, writing)?,
    };
    tx.commit().await?;
    Ok((taken, state))
}

/// Take `value` as part `part` of generation `generation` at `slot`, and
/// answer how it came out and what the slot holds after it.
pub async fn backup_part(
    pool: &DBPool,
    slot: &D32,
    generation: u64,
    part: u32,
    value: &[u8],
) -> Result<(PartTaken, SlotState)> {
    let generation = as_i64(generation, "generation")?;
    let digest = dsm::wallet_backup::part_digest(value);
    let mut client = pool.get().await?;
    let tx = begin_durable_write(&mut client).await?;
    let (whole, whole_digests, writing, writing_digests) = locked_row(&tx, slot).await?;
    let being_written = match (writing, writing_digests) {
        (Some(w), Some(digests)) if w == generation => Some(digests),
        _ => None,
    };
    let taken = if generation == whole {
        match digest_at(&whole_digests, part) {
            Some(named) if named == digest => PartTaken::Whole,
            Some(_) => PartTaken::WrongDigest,
            None => PartTaken::NoSuchPart,
        }
    } else if let Some(digests) = being_written {
        match digest_at(&digests, part) {
            None => PartTaken::NoSuchPart,
            Some(named) if named != digest => PartTaken::WrongDigest,
            Some(_) => {
                let part_i32 = i32::try_from(part)?;
                tx.execute(
                    "INSERT INTO backup_parts (slot_key, generation, part, value)
                     VALUES ($1, $2, $3, $4)
                     ON CONFLICT (slot_key, generation, part) DO NOTHING",
                    &[&slot.as_slice(), &generation, &part_i32, &value],
                )
                .await?;
                let held: i64 = tx
                    .query_one(
                        "SELECT COUNT(*) FROM backup_parts WHERE slot_key = $1 AND generation = $2",
                        &[&slot.as_slice(), &generation],
                    )
                    .await?
                    .get(0);
                if usize::try_from(held)? == count_of(&digests) {
                    // Every part is held: this is the whole backup now, and
                    // the one before it is written over.
                    tx.execute(
                        "DELETE FROM backup_parts WHERE slot_key = $1 AND generation = $2",
                        &[&slot.as_slice(), &whole],
                    )
                    .await?;
                    tx.execute(
                        "UPDATE backup_slots
                            SET generation = writing_generation, part_digests = writing_digests,
                                writing_generation = NULL, writing_digests = NULL
                          WHERE slot_key = $1",
                        &[&slot.as_slice()],
                    )
                    .await?;
                    PartTaken::Whole
                } else {
                    PartTaken::Writing
                }
            }
        }
    } else {
        PartTaken::NotWriting
    };
    let row = tx
        .query_one(
            "SELECT generation, part_digests, writing_generation
               FROM backup_slots WHERE slot_key = $1",
            &[&slot.as_slice()],
        )
        .await?;
    let state = state_of(row.get(0), row.get(1), row.get(2))?;
    tx.commit().await?;
    Ok((taken, state))
}

/// What the member holds at `slot`; the empty state when it holds nothing.
pub async fn backup_slot(pool: &DBPool, slot: &D32) -> Result<SlotState> {
    let client = pool.get().await?;
    let row = client
        .query_opt(
            "SELECT generation, part_digests, writing_generation
               FROM backup_slots WHERE slot_key = $1",
            &[&slot.as_slice()],
        )
        .await?;
    match row {
        Some(row) => state_of(row.get(0), row.get(1), row.get(2)),
        None => Ok(SlotState::default()),
    }
}

/// Part `part` of the whole backup at `slot`, when its generation is
/// `generation`; `None` otherwise.
pub async fn backup_whole_part(
    pool: &DBPool,
    slot: &D32,
    generation: u64,
    part: u32,
) -> Result<Option<Vec<u8>>> {
    let generation = as_i64(generation, "generation")?;
    let part = i32::try_from(part)?;
    let client = pool.get().await?;
    let row = client
        .query_opt(
            "SELECT p.value FROM backup_parts p
               JOIN backup_slots s ON s.slot_key = p.slot_key AND s.generation = p.generation
              WHERE p.slot_key = $1 AND p.generation = $2 AND p.part = $3",
            &[&slot.as_slice(), &generation, &part],
        )
        .await?;
    Ok(row.map(|r| r.get(0)))
}
