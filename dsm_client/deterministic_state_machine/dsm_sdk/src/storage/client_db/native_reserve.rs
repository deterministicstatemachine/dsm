// SPDX-License-Identifier: Apache-2.0

//! Durable client state for the native ERA reserve.
//!
//! Two kinds of state, two disciplines:
//!
//! - **Frozen releases**: the exact signed bytes this device wrote at one
//!   parent root, `INSERT OR IGNORE`d before the first member write so a
//!   retry replays them and never re-signs (deterministic SPHINCS+ makes a
//!   regenerated envelope indistinguishable from a replayed one).
//! - **The lineage memo**: every final release a walk established, with the
//!   state it succeeded. Finality is permanent, so a memoised state is a
//!   sound start for the next walk. A cache of Core's conclusions, never
//!   authority over a cell.
//!
//! The write of a release along its successor cell's route is recorded like
//! every route-chain write (`client_db::route_writes`).

use anyhow::{anyhow, Result};
use rusqlite::{params, OptionalExtension};

use dsm::economic::native_reserve::{NativeReserveState, VerifiedRelease};

use super::get_connection;

fn u64_of(v: i64, what: &str) -> Result<u64> {
    u64::try_from(v).map_err(|e| anyhow!("{what} is negative: {e}"))
}

fn i64_of(v: u64, what: &str) -> Result<i64> {
    i64::try_from(v).map_err(|e| anyhow!("{what} overflows: {e}"))
}

// ── Frozen releases ──────────────────────────────────────────────────────────

/// Freeze the release this device writes at `parent_root`, in place of one
/// frozen there for another target position. The claim reuses the frozen
/// bytes for every retry at that position; a release for an earlier
/// position, which a later admission made one this device can no longer
/// credit, is replaced rather than sent (SA-70).
pub fn freeze_release(
    reserve_id: &[u8; 32],
    parent_root: &[u8; 32],
    envelope: &[u8],
) -> Result<()> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    conn.execute(
        "INSERT INTO native_reserve_release_local
           (reserve_id, parent_root, envelope)
         VALUES (?1, ?2, ?3)
         ON CONFLICT (reserve_id, parent_root) DO UPDATE SET envelope = excluded.envelope",
        params![reserve_id.as_slice(), parent_root.as_slice(), envelope],
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

/// Memoise one final release with the state it succeeded, and `cell_reads`,
/// the reads of its cell that showed it final
/// (`dsm::route_chain::CellEvidence::encode_kept`).
pub fn record_final_release(
    parent: &NativeReserveState,
    release: &VerifiedRelease,
    child: &NativeReserveState,
    cell_reads: &[u8],
) -> Result<()> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    conn.execute(
        "INSERT OR IGNORE INTO native_reserve_lineage_memo
           (reserve_id, generation, parent_remaining, remaining, recipient_genesis,
            recipient_devid, recipient_position, envelope, cell_reads)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            parent.reserve_id().as_slice(),
            i64_of(child.generation(), "generation")?,
            i64_of(parent.remaining_supply(), "parent remaining")?,
            i64_of(child.remaining_supply(), "remaining")?,
            release.body.recipient_genesis.as_slice(),
            release.body.recipient_devid.as_slice(),
            i64_of(
                release.body.recipient_economic_position,
                "recipient position"
            )?,
            release.envelope_bytes.as_slice(),
            cell_reads,
        ],
    )?;
    Ok(())
}

/// The state at `generation` of the lineage `genesis` starts, as Core derives
/// it, when the memo's `remaining` for that generation agrees. A row that
/// disagrees is corrupt storage, never a state: the memo names generations,
/// and only Core makes reserve states.
fn memoised(
    genesis: &NativeReserveState,
    generation: u64,
    remaining: u64,
) -> Result<NativeReserveState> {
    let state = genesis
        .at_generation(generation)
        .map_err(|e| anyhow!("native_reserve_lineage_memo: generation {generation}: {e}"))?;
    if state.remaining_supply() != remaining {
        return Err(anyhow!(
            "native_reserve_lineage_memo: generation {generation} records {remaining} \
             remaining where the lineage holds {}",
            state.remaining_supply()
        ));
    }
    Ok(state)
}

/// Fold every memoised generation of the reserve whose genesis is `genesis`,
/// in generation order, into `step`: the state each final release installed,
/// the release's envelope, and the reads kept with it. What this device's
/// own walks established; Core establishes each again from those bytes.
/// One row is read at a time, so a walk holds one release, never the memo
/// (SA-75). `step` is handed the connection the fold holds, for what it
/// reads of the release elsewhere in the store: asking the store for
/// another connection while the fold holds this one never returns. `step`
/// answers whether to read on. A row whose supplies are not
/// the ones the lineage holds at its generation and the one before is
/// corrupt storage, and an error.
pub fn fold_memoised_lineage(
    genesis: &NativeReserveState,
    mut step: impl FnMut(
        &rusqlite::Connection,
        NativeReserveState,
        &[u8],
        &[u8],
    ) -> Result<std::ops::ControlFlow<()>>,
) -> Result<()> {
    let binding = get_connection()?;
    let conn = binding
        .lock()
        .map_err(|e| anyhow!("native reserve memo: the store is poisoned: {e}"))?;
    let mut stmt = conn.prepare(
        "SELECT generation, remaining, parent_remaining, envelope, cell_reads
           FROM native_reserve_lineage_memo
          WHERE reserve_id = ?1 ORDER BY generation ASC",
    )?;
    let mut rows = stmt.query(params![genesis.reserve_id().as_slice()])?;
    while let Some(row) = rows.next()? {
        let generation = u64_of(row.get::<_, i64>(0)?, "generation")?;
        let state = memoised(
            genesis,
            generation,
            u64_of(row.get::<_, i64>(1)?, "remaining")?,
        )?;
        // The row's parent supply is the lineage's one generation before;
        // generation 0 has no row, so a row has a parent.
        let parent_generation = generation
            .checked_sub(1)
            .ok_or_else(|| anyhow!("native_reserve_lineage_memo: generation 0 has no parent"))?;
        memoised(
            genesis,
            parent_generation,
            u64_of(row.get::<_, i64>(2)?, "parent remaining")?,
        )?;
        let envelope = row.get_ref(3)?.as_blob()?;
        let cell_reads = row.get_ref(4)?.as_blob()?;
        if step(&conn, state, envelope, cell_reads)?.is_break() {
            break;
        }
    }
    Ok(())
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

#[cfg(test)]
#[allow(clippy::disallowed_methods)]
mod tests {
    use super::*;
    use serial_test::serial;

    fn memo_row(
        genesis: &NativeReserveState,
        generation: i64,
        parent_remaining: i64,
        remaining: i64,
    ) {
        let binding = get_connection().expect("connection");
        let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
        conn.execute(
            "INSERT INTO native_reserve_lineage_memo
               (reserve_id, generation, parent_remaining, remaining, recipient_genesis,
                recipient_devid, recipient_position, envelope, cell_reads)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0, ?7, ?8)",
            params![
                genesis.reserve_id().as_slice(),
                generation,
                parent_remaining,
                remaining,
                [0x61u8; 32].as_slice(),
                [0x62u8; 32].as_slice(),
                [0x63u8; 8].as_slice(),
                [0x64u8; 8].as_slice(),
            ],
        )
        .expect("memo row");
    }

    /// The fold reads each memoised release with the state it installed; a
    /// row whose parent supply is negative, or is not the one the lineage
    /// holds there, is corrupt storage and an error — never a release with an
    /// invented parent supply.
    #[test]
    #[serial]
    fn a_corrupt_memo_row_is_an_error_not_a_release() {
        crate::economic_fixtures::use_test_storage_dir();
        super::super::reset_database_for_tests();
        super::super::init_database().expect("init");
        let genesis = NativeReserveState::genesis(b"memo-test", [0x5E; 32]).expect("R_0");
        let folded = |genesis: &NativeReserveState| -> Result<Vec<u64>> {
            let mut seen = Vec::new();
            fold_memoised_lineage(genesis, |_, state, _, _| {
                seen.push(state.generation());
                Ok(std::ops::ControlFlow::Continue(()))
            })?;
            Ok(seen)
        };

        let parent = genesis.at_generation(2).expect("generation 2");
        let state = genesis.at_generation(3).expect("generation 3");
        memo_row(
            &genesis,
            3,
            i64::try_from(parent.remaining_supply()).expect("fits"),
            i64::try_from(state.remaining_supply()).expect("fits"),
        );
        assert_eq!(folded(&genesis).expect("read"), vec![3]);

        memo_row(
            &genesis,
            4,
            -1,
            i64::try_from(genesis.at_generation(4).expect("4").remaining_supply()).expect("fits"),
        );
        match folded(&genesis) {
            Err(e) => assert!(
                e.to_string().contains("parent remaining is negative"),
                "refused as a negative parent supply: {e}"
            ),
            Ok(seen) => panic!("a negative parent supply is corrupt, yet the fold read {seen:?}"),
        }

        super::super::reset_database_for_tests();
        super::super::init_database().expect("init");
        memo_row(
            &genesis,
            5,
            900,
            i64::try_from(genesis.at_generation(5).expect("5").remaining_supply()).expect("fits"),
        );
        match folded(&genesis) {
            Err(e) => assert!(
                e.to_string().contains("where the lineage holds"),
                "refused as a supply the lineage does not hold there: {e}"
            ),
            Ok(..) => panic!("a parent supply the lineage does not hold there is corrupt"),
        }
    }
}
