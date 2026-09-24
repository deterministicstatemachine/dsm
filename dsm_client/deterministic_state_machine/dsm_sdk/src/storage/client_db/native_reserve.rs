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
use dsm::economic::provenance::ReserveReleaseWin;

use super::get_connection;

fn u64_of(v: i64, what: &str) -> Result<u64> {
    u64::try_from(v).map_err(|e| anyhow!("{what} is negative: {e}"))
}

fn i64_of(v: u64, what: &str) -> Result<i64> {
    i64::try_from(v).map_err(|e| anyhow!("{what} overflows: {e}"))
}

// ── Frozen releases ──────────────────────────────────────────────────────────

/// Freeze the release this device wrote at `parent_root`. `INSERT OR IGNORE`:
/// the FIRST bytes win forever, exactly like the cell they are sent to.
pub fn put_frozen_release(
    reserve_id: &[u8; 32],
    parent_root: &[u8; 32],
    envelope: &[u8],
) -> Result<()> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    conn.execute(
        "INSERT OR IGNORE INTO native_reserve_release_local
           (reserve_id, parent_root, envelope)
         VALUES (?1, ?2, ?3)",
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
    let Some((parent_remaining, envelope)) = row else {
        return Ok(None);
    };
    // A memo row that does not decode is corrupt storage, never a release: a
    // parent supply read as zero, or a parent generation below the genesis,
    // would be evidence this device invented.
    let parent_generation = generation
        .checked_sub(1)
        .ok_or_else(|| anyhow!("native_reserve_lineage_memo: generation 0 has no parent"))?;
    Ok(Some(ReserveReleaseWin {
        envelope_bytes: envelope,
        parent: NativeReserveState {
            generation: parent_generation,
            remaining_supply: u64_of(parent_remaining, "parent remaining")?,
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

#[cfg(test)]
#[allow(clippy::disallowed_methods)]
mod tests {
    use super::*;
    use serial_test::serial;

    fn memo_row(genesis: &NativeReserveState, generation: i64, parent_remaining: i64) {
        let binding = get_connection().expect("connection");
        let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
        conn.execute(
            "INSERT INTO native_reserve_lineage_memo
               (reserve_id, generation, parent_remaining, remaining, recipient_genesis,
                recipient_devid, recipient_position, envelope)
             VALUES (?1, ?2, ?3, 0, ?4, ?5, 0, ?6)",
            params![
                genesis.reserve_id.as_slice(),
                generation,
                parent_remaining,
                [0x61u8; 32].as_slice(),
                [0x62u8; 32].as_slice(),
                [0x63u8; 8].as_slice(),
            ],
        )
        .expect("memo row");
    }

    /// A memoised release reads back as the release it recorded; a row whose
    /// parent supply is negative is corrupt storage and an error — never a
    /// release with an invented parent supply.
    #[test]
    #[serial]
    fn a_corrupt_memo_row_is_an_error_not_a_release() {
        crate::economic_fixtures::use_test_storage_dir();
        super::super::reset_database_for_tests();
        super::super::init_database().expect("init");
        let genesis = NativeReserveState::genesis(b"memo-test", [0x5E; 32]);

        memo_row(&genesis, 3, 900);
        let win = release_at(&genesis, 3).expect("read").expect("recorded");
        assert_eq!(win.parent.generation, 2);
        assert_eq!(win.parent.remaining_supply, 900);

        memo_row(&genesis, 4, -1);
        assert!(
            release_at(&genesis, 4).is_err(),
            "a negative parent supply is corrupt"
        );

        assert!(release_at(&genesis, 9).expect("read").is_none());
    }
}
