// SPDX-License-Identifier: MIT OR Apache-2.0

//! Durable initiating-trader parent fence (Rev 15 Req 6.23, Req 16.5).
//!
//! The pure state machine is [`dsm::dlv::trader_fence`]; this is its durable
//! home. The fence is written BEFORE the first mutating QuorumBind op — if it
//! cannot be persisted, the transaction must not begin (Req 6.23 (1)) — and is
//! restored before a recovered trader chain may advance (Req 6.23 (5),
//! Req 16.5).
//!
//! ORCHESTRATION, NEVER AUTHORITY. This row never decides that a trade
//! happened; the canonical bilateral state does. It records only which trader
//! parent is fenced, by which unresolved DLV transaction, and — once
//! `COMMITTED` — which exact successor is the sole permitted continuation. The
//! `ballot`, `storage_set_id`, and `value_addr` are what restart recovery needs
//! to re-drive the transaction to a terminal outcome (Req 16.5); the ballot is
//! persisted so a restarted proposer never reuses one.
//!
//! No clock columns: ordering is the local monotonic insertion ordinal.

use anyhow::{anyhow, Result};
use dsm::dlv::trader_fence::{next_state, verdict, FenceEvent, FenceState, FenceVerdict};
use rusqlite::{params, Connection, OptionalExtension};

use super::get_connection;

/// One trader parent fence (in flight or terminal), with what recovery needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraderFence {
    pub trader_chain_id: [u8; 32],
    pub trader_parent_state_commitment: [u8; 32],
    pub tx_id: [u8; 32],
    /// The current QuorumBind ballot, persisted so restart never reuses one.
    pub ballot: u64,
    pub storage_set_id: [u8; 32],
    /// The immutable bundle's content address — recovery retrieves the exact
    /// bytes from storage to re-drive the transaction.
    pub value_addr: [u8; 32],
    pub state: FenceState,
    pub insertion_ordinal: i64,
}

fn state_columns(state: &FenceState) -> (&'static str, Option<Vec<u8>>) {
    match state {
        FenceState::CommittedAwaitingAcceptance {
            permitted_successor,
        } => (state.as_str(), Some(permitted_successor.to_vec())),
        other => (other.as_str(), None),
    }
}

fn state_from_row(state: &str, permitted_successor: Option<Vec<u8>>) -> Result<FenceState> {
    Ok(match state {
        "fenced" => FenceState::Fenced,
        "committed_awaiting_acceptance" => {
            let s = permitted_successor
                .ok_or_else(|| anyhow!("committed fence row missing permitted_successor"))?;
            FenceState::CommittedAwaitingAcceptance {
                permitted_successor: fixed32(&s)?,
            }
        }
        "released" => FenceState::Released,
        "released_no_advance" => FenceState::ReleasedNoAdvance,
        other => return Err(anyhow!("unknown fence state: {other}")),
    })
}

fn fixed32(v: &[u8]) -> Result<[u8; 32]> {
    <[u8; 32]>::try_from(v).map_err(|_| anyhow!("fence column is not 32 bytes"))
}

/// Place the fence before the first mutating binding op. Idempotent per
/// `(trader_chain_id, trader_parent_state_commitment, tx_id)`: a retry of the
/// same transaction reuses the first row, so its frozen ballot floor and value
/// address never change under it. The initial `state` should be
/// [`FenceState::Fenced`].
pub fn place_fence_with_conn(conn: &Connection, fence: &TraderFence) -> Result<()> {
    let (state, permitted) = state_columns(&fence.state);
    conn.execute(
        "INSERT OR IGNORE INTO trader_parent_fence
            (trader_chain_id, trader_parent_state_commitment, tx_id, ballot,
             storage_set_id, value_addr, state, permitted_successor)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            fence.trader_chain_id.as_slice(),
            fence.trader_parent_state_commitment.as_slice(),
            fence.tx_id.as_slice(),
            fence.ballot as i64,
            fence.storage_set_id.as_slice(),
            fence.value_addr.as_slice(),
            state,
            permitted,
        ],
    )?;
    Ok(())
}

/// Same, on the shared connection.
pub fn place_fence(fence: &TraderFence) -> Result<()> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    place_fence_with_conn(&conn, fence)
}

/// Apply a [`FenceEvent`] to the fence, enforcing the legal transitions of the
/// core state machine, and persist the new state (and, on `COMMITTED`, the
/// permitted successor). Optionally persist a bumped `ballot`. Returns the new
/// state, or an error if the transition is illegal — including the load-bearing
/// refusal to let a DIFFERENT successor consume a committed fence.
pub fn record_event(
    trader_chain_id: &[u8; 32],
    trader_parent_state_commitment: &[u8; 32],
    tx_id: &[u8; 32],
    event: &FenceEvent,
    new_ballot: Option<u64>,
) -> Result<FenceState> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    let current = get_fence_with_conn(
        &conn,
        trader_chain_id,
        trader_parent_state_commitment,
        tx_id,
    )?
    .ok_or_else(|| anyhow!("no fence to advance for this (parent, tx)"))?;
    let next = next_state(&current.state, event)?;
    let (state, permitted) = state_columns(&next);
    conn.execute(
        "UPDATE trader_parent_fence
            SET state = ?4, permitted_successor = ?5, ballot = ?6
          WHERE trader_chain_id = ?1
            AND trader_parent_state_commitment = ?2
            AND tx_id = ?3",
        params![
            trader_chain_id.as_slice(),
            trader_parent_state_commitment.as_slice(),
            tx_id.as_slice(),
            state,
            permitted,
            new_ballot.unwrap_or(current.ballot) as i64,
        ],
    )?;
    Ok(next)
}

const COLS: &str = "trader_chain_id, trader_parent_state_commitment, tx_id, ballot, \
                    storage_set_id, value_addr, state, permitted_successor, insertion_ordinal";

fn row_to_fence(r: &rusqlite::Row<'_>) -> Result<TraderFence> {
    Ok(TraderFence {
        trader_chain_id: fixed32(&r.get::<_, Vec<u8>>(0)?)?,
        trader_parent_state_commitment: fixed32(&r.get::<_, Vec<u8>>(1)?)?,
        tx_id: fixed32(&r.get::<_, Vec<u8>>(2)?)?,
        ballot: r.get::<_, i64>(3)? as u64,
        storage_set_id: fixed32(&r.get::<_, Vec<u8>>(4)?)?,
        value_addr: fixed32(&r.get::<_, Vec<u8>>(5)?)?,
        state: state_from_row(&r.get::<_, String>(6)?, r.get::<_, Option<Vec<u8>>>(7)?)?,
        insertion_ordinal: r.get(8)?,
    })
}

fn get_fence_with_conn(
    conn: &Connection,
    trader_chain_id: &[u8; 32],
    trader_parent_state_commitment: &[u8; 32],
    tx_id: &[u8; 32],
) -> Result<Option<TraderFence>> {
    conn.query_row(
        &format!(
            "SELECT {COLS} FROM trader_parent_fence
              WHERE trader_chain_id = ?1
                AND trader_parent_state_commitment = ?2
                AND tx_id = ?3"
        ),
        params![
            trader_chain_id.as_slice(),
            trader_parent_state_commitment.as_slice(),
            tx_id.as_slice(),
        ],
        |r| row_to_fence(r).map_err(|e| rusqlite::Error::ToSqlConversionFailure(e.into())),
    )
    .optional()
    .map_err(Into::into)
}

pub fn get_fence(
    trader_chain_id: &[u8; 32],
    trader_parent_state_commitment: &[u8; 32],
    tx_id: &[u8; 32],
) -> Result<Option<TraderFence>> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    get_fence_with_conn(
        &conn,
        trader_chain_id,
        trader_parent_state_commitment,
        tx_id,
    )
}

/// THE ADVANCEMENT GATE (Req 6.23 (2),(4)). The verdict a caller consults
/// before creating a trader successor from this parent: the verdict of the one
/// unresolved fence for the parent, or [`FenceVerdict::Clear`] if none is
/// unresolved. A fresh intent or nonce cannot change this answer — the fence is
/// keyed on the parent, not the intent.
pub fn active_verdict(
    trader_chain_id: &[u8; 32],
    trader_parent_state_commitment: &[u8; 32],
) -> Result<FenceVerdict> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    let row = conn
        .query_row(
            &format!(
                "SELECT {COLS} FROM trader_parent_fence
                  WHERE trader_chain_id = ?1
                    AND trader_parent_state_commitment = ?2
                    AND state IN ('fenced','committed_awaiting_acceptance')
                  ORDER BY insertion_ordinal DESC LIMIT 1"
            ),
            params![
                trader_chain_id.as_slice(),
                trader_parent_state_commitment.as_slice(),
            ],
            |r| row_to_fence(r).map_err(|e| rusqlite::Error::ToSqlConversionFailure(e.into())),
        )
        .optional()?;
    Ok(row.map_or(FenceVerdict::Clear, |f| verdict(&f.state)))
}

/// Every fence that has not reached a terminal state, oldest first — the work
/// list restart recovery must restore and drive to terminal before the trader
/// chain advances (Req 16.5).
pub fn list_unresolved_fences() -> Result<Vec<TraderFence>> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    let mut stmt = conn.prepare(&format!(
        "SELECT {COLS} FROM trader_parent_fence
          WHERE state IN ('fenced','committed_awaiting_acceptance')
          ORDER BY insertion_ordinal ASC"
    ))?;
    let rows = stmt
        .query_map([], |r| {
            row_to_fence(r).map_err(|e| rusqlite::Error::ToSqlConversionFailure(e.into()))
        })?
        .filter_map(|r| r.ok())
        .collect();
    Ok(rows)
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)] // test asserts; a failure here is the signal
mod tests {
    use super::*;
    use serial_test::serial;

    const CHAIN: [u8; 32] = [0x11; 32];
    const PARENT: [u8; 32] = [0x22; 32];
    const SUCC: [u8; 32] = [0xAA; 32];
    const OTHER: [u8; 32] = [0xBB; 32];

    fn fence(tx: u8) -> TraderFence {
        TraderFence {
            trader_chain_id: CHAIN,
            trader_parent_state_commitment: PARENT,
            tx_id: [tx; 32],
            ballot: 1,
            storage_set_id: [0x6B; 32],
            value_addr: [0x7C; 32],
            state: FenceState::Fenced,
            insertion_ordinal: 0,
        }
    }

    fn init() {
        crate::storage::client_db::reset_database_for_tests();
        crate::storage::client_db::init_database().expect("init");
    }

    #[test]
    #[serial]
    fn a_fenced_parent_blocks_every_successor_until_resolved() {
        init();
        place_fence(&fence(1)).unwrap();
        // The gate blocks all successors while unresolved.
        assert_eq!(
            active_verdict(&CHAIN, &PARENT).unwrap(),
            FenceVerdict::BlocksAllSuccessors
        );
        // A fresh tx_id (fresh intent) on the same parent does not lift it.
        place_fence(&fence(2)).unwrap();
        assert_eq!(
            active_verdict(&CHAIN, &PARENT).unwrap(),
            FenceVerdict::BlocksAllSuccessors
        );
    }

    #[test]
    #[serial]
    fn commit_permits_only_the_exact_successor_and_acceptance_releases() {
        init();
        place_fence(&fence(1)).unwrap();
        record_event(
            &CHAIN,
            &PARENT,
            &[1; 32],
            &FenceEvent::Committed { successor: SUCC },
            Some(3),
        )
        .unwrap();
        assert_eq!(
            active_verdict(&CHAIN, &PARENT).unwrap(),
            FenceVerdict::PermitsOnly(SUCC)
        );
        // A different successor cannot consume the fence.
        assert!(record_event(
            &CHAIN,
            &PARENT,
            &[1; 32],
            &FenceEvent::SuccessorAccepted { successor: OTHER },
            None
        )
        .is_err());
        // The exact one releases it, and the gate goes clear.
        record_event(
            &CHAIN,
            &PARENT,
            &[1; 32],
            &FenceEvent::SuccessorAccepted { successor: SUCC },
            None,
        )
        .unwrap();
        assert_eq!(
            active_verdict(&CHAIN, &PARENT).unwrap(),
            FenceVerdict::Clear
        );
    }

    #[test]
    #[serial]
    fn indeterminate_keeps_the_fence_and_restart_recovery_restores_it() {
        init();
        place_fence(&fence(1)).unwrap();
        // A lost outcome keeps it fenced and bumps the persisted ballot.
        record_event(
            &CHAIN,
            &PARENT,
            &[1; 32],
            &FenceEvent::Indeterminate,
            Some(2),
        )
        .unwrap();
        assert_eq!(
            active_verdict(&CHAIN, &PARENT).unwrap(),
            FenceVerdict::BlocksAllSuccessors
        );
        // Restart recovery finds it, with the bumped ballot and the recovery
        // inputs it needs.
        let open = list_unresolved_fences().unwrap();
        assert_eq!(open.len(), 1);
        assert_eq!(open[0].ballot, 2);
        assert_eq!(open[0].value_addr, [0x7C; 32]);
        assert_eq!(open[0].storage_set_id, [0x6B; 32]);
    }

    #[test]
    #[serial]
    fn abort_releases_without_advancing_and_leaves_no_unresolved_work() {
        init();
        place_fence(&fence(1)).unwrap();
        record_event(&CHAIN, &PARENT, &[1; 32], &FenceEvent::Aborted, None).unwrap();
        assert_eq!(
            active_verdict(&CHAIN, &PARENT).unwrap(),
            FenceVerdict::Clear
        );
        assert!(list_unresolved_fences().unwrap().is_empty());
    }

    #[test]
    #[serial]
    fn the_first_placement_freezes_the_recovery_inputs() {
        init();
        place_fence(&fence(1)).unwrap();
        let mut b = fence(1);
        b.value_addr = [0xEE; 32];
        b.storage_set_id = [0xEF; 32];
        place_fence(&b).unwrap(); // INSERT OR IGNORE: no change
        let got = get_fence(&CHAIN, &PARENT, &[1; 32]).unwrap().unwrap();
        assert_eq!(got.value_addr, [0x7C; 32], "first bytes win");
        assert_eq!(got.storage_set_id, [0x6B; 32]);
    }
}
