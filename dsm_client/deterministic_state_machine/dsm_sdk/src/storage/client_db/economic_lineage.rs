// SPDX-License-Identifier: Apache-2.0

//! Operation-neutral durable state of the economic lineage: the frozen root
//! claim per position, the admitted coordinate, the producer leaf cache, and
//! the device-local memo of peer positions THIS verifier validated.
//!
//! Nothing here is faucet-specific; everything serves every admission kind.
//! The native reserve's own state lives in `native_reserve.rs`.
//!
//! The peer memo is a cache of the verifier's OWN conclusions and is never
//! authority over a live register read — a walk that fails `Invalid` from a
//! cached start discards the rows and re-walks from the activation root.

use anyhow::{anyhow, Result};
use rusqlite::{params, OptionalExtension, Transaction};

use dsm::economic::lineage::AdmittedEconomicPosition;

use super::get_connection;

fn digest32(v: Vec<u8>, what: &str) -> Result<[u8; 32]> {
    <[u8; 32]>::try_from(v.as_slice()).map_err(|e| anyhow!("{what} is not 32 bytes: {e}"))
}

pub fn put_frozen_root_claim(
    economic_position: u64,
    k_root: &[u8; 32],
    envelope: &[u8],
) -> Result<()> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    conn.execute(
        "INSERT OR IGNORE INTO economic_root_claim_local
           (economic_position, k_root, envelope)
         VALUES (?1, ?2, ?3)",
        params![
            i64::try_from(economic_position).map_err(|e| anyhow!("position overflow: {e}"))?,
            k_root.as_slice(),
            envelope,
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
            params![
                i64::try_from(economic_position).map_err(|e| anyhow!("position overflow: {e}"))?
            ],
            |r| Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, Vec<u8>>(1)?)),
        )
        .optional()?;
    row.map(|(k, e)| Ok((digest32(k, "k_root")?, e)))
        .transpose()
}

type AdmittedRow = (
    i64,
    i64,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
);

const SELECT_ADMITTED: &str = "SELECT economic_position, claim_kind, economic_root, \
     fulfillment_id, realize_root, void_root, claim_ref FROM economic_admitted_v2 WHERE id = 1";

/// The highest ordinary (claim kind 0) position admitted below `?1`.
const SELECT_ADMITTED_SINGLE_ROOT_BELOW: &str = "SELECT economic_position, claim_kind, \
     economic_root, fulfillment_id, realize_root, void_root, claim_ref FROM \
     economic_admitted_history WHERE economic_position < ?1 AND claim_kind = 0 \
     ORDER BY economic_position DESC LIMIT 1";

const SELECT_ADMITTED_AT: &str = "SELECT economic_position, claim_kind, economic_root, \
     fulfillment_id, realize_root, void_root, claim_ref FROM economic_admitted_history \
     WHERE economic_position = ?1";

fn read_admitted_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<AdmittedRow> {
    Ok((
        r.get::<_, i64>(0)?,
        r.get::<_, i64>(1)?,
        r.get::<_, Option<Vec<u8>>>(2)?,
        r.get::<_, Option<Vec<u8>>>(3)?,
        r.get::<_, Option<Vec<u8>>>(4)?,
        r.get::<_, Option<Vec<u8>>>(5)?,
        r.get::<_, Option<Vec<u8>>>(6)?,
    ))
}

/// Reconstruct the admitted position from its row.
///
/// A row whose fields do not match its own `claim_kind` is REFUSED, never
/// patched into the nearest plausible shape: this is the coordinate a restart
/// builds its whole lineage on, and a guess here is a guess about which root
/// the lineage selected.
fn admitted_from_row(row: AdmittedRow) -> Result<AdmittedEconomicPosition> {
    let (position, kind, root, fulfillment, realize, void, claim_ref) = row;
    let economic_position =
        u64::try_from(position).map_err(|e| anyhow!("position negative: {e}"))?;
    // EXACT SHAPES, both ways. A missing field for the kind was already
    // refused; an EXTRA one was silently ignored, which is the same defect
    // wearing the other face — a row carrying both a selected root and a
    // realize/void pair is two disagreeing claims about which root this
    // position holds, and picking the one the arm happens to read is exactly
    // the guess this decoder exists to refuse. The row is the coordinate a
    // restart rebuilds the whole lineage on.
    let forbid = |field: &str, present: bool| -> Result<()> {
        if present {
            return Err(anyhow!(
                "admitted claim kind {kind} carries a {field} it has no meaning for"
            ));
        }
        Ok(())
    };
    match kind {
        0 => {
            forbid("fulfillment id", fulfillment.is_some())?;
            forbid("realize root", realize.is_some())?;
            forbid("void root", void.is_some())?;
            Ok(AdmittedEconomicPosition::SingleRoot {
                economic_position,
                economic_root: digest32(
                    root.ok_or_else(|| anyhow!("single-root admission has no root"))?,
                    "economic_root",
                )?,
                claim_ref: digest32(
                    claim_ref.ok_or_else(|| anyhow!("single-root admission has no claim"))?,
                    "claim_ref",
                )?,
            })
        }
        1 => {
            forbid("realize root", realize.is_some())?;
            forbid("void root", void.is_some())?;
            Ok(AdmittedEconomicPosition::ResolvedSofi {
                economic_position,
                selected_root: digest32(
                    root.ok_or_else(|| anyhow!("resolved SoFi admission has no selected root"))?,
                    "economic_root",
                )?,
                fulfillment_id: digest32(
                    fulfillment
                        .ok_or_else(|| anyhow!("resolved SoFi admission has no fulfillment"))?,
                    "fulfillment_id",
                )?,
                claim_ref: digest32(
                    claim_ref.ok_or_else(|| anyhow!("resolved SoFi admission has no claim"))?,
                    "claim_ref",
                )?,
            })
        }
        2 => {
            // A selected root here would say the position HAS chosen, which is
            // precisely what an unresolved position has not done.
            forbid("selected root", root.is_some())?;
            forbid("accepted claim", claim_ref.is_some())?;
            Ok(AdmittedEconomicPosition::UnresolvedSofi {
                economic_position,
                fulfillment_id: digest32(
                    fulfillment
                        .ok_or_else(|| anyhow!("conditional admission has no fulfillment"))?,
                    "fulfillment_id",
                )?,
                realize_root: digest32(
                    realize.ok_or_else(|| anyhow!("conditional admission has no realize root"))?,
                    "realize_root",
                )?,
                void_root: digest32(
                    void.ok_or_else(|| anyhow!("conditional admission has no void root"))?,
                    "void_root",
                )?,
            })
        }
        other => Err(anyhow!("unknown admitted claim kind {other}")),
    }
}

/// The admitted economic position, if any — WITH its claim kind.
pub fn get_admitted() -> Result<Option<AdmittedEconomicPosition>> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    let row = conn
        .query_row(SELECT_ADMITTED, [], read_admitted_row)
        .optional()?;
    row.map(admitted_from_row).transpose()
}

/// The position this device's lineage admitted at `economic_position`, if
/// it admitted one there — WITH its claim kind.
pub fn get_admitted_at(economic_position: u64) -> Result<Option<AdmittedEconomicPosition>> {
    let position =
        i64::try_from(economic_position).map_err(|e| anyhow!("position overflow: {e}"))?;
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    let row = conn
        .query_row(SELECT_ADMITTED_AT, params![position], read_admitted_row)
        .optional()?;
    row.map(admitted_from_row).transpose()
}

/// The admitted coordinate as a `(position, root)` pair.
///
/// TEST SUPPORT ONLY, and gated so it cannot be reached from production. The
/// pair is the shape that made a conditional position inexpressible in the
/// first place, so production reads [`get_admitted`] and matches the kind. A
/// test that wants the pair is asserting about an ordinary position, and this
/// refuses rather than inventing a root for a conditional one.
#[cfg(test)]
pub fn get_admitted_coordinate() -> Result<Option<(u64, [u8; 32])>> {
    Ok(get_admitted()?.map(|admitted| {
        let position = admitted.economic_position();
        match admitted {
            AdmittedEconomicPosition::SingleRoot { economic_root, .. } => (position, economic_root),
            AdmittedEconomicPosition::ResolvedSofi { selected_root, .. } => {
                (position, selected_root)
            }
            AdmittedEconomicPosition::UnresolvedSofi { .. } => {
                panic!("the admitted position at {position} is conditional and unresolved")
            }
        }
    }))
}

/// The admitted position, read INSIDE a caller's transaction — the CAS
/// re-assert the admission commit runs before making acceptance durable.
pub fn get_admitted_with_conn(
    conn: &rusqlite::Connection,
) -> Result<Option<AdmittedEconomicPosition>> {
    let row = conn
        .query_row(SELECT_ADMITTED, [], read_admitted_row)
        .optional()?;
    row.map(admitted_from_row).transpose()
}

/// Record admission + install the leaf cache, INSIDE the caller's transaction
/// — the same one that clears the pending admission, so "admitted" and "no
/// longer pending" cannot disagree.
///
/// The row is written in the ONE exact shape of the position's kind — the
/// shapes `admitted_from_row` refuses to read any other way. An ordinary
/// position carries its root; a resolved SoFi position carries the root the
/// route selected and the fulfillment that installed it (R13); an unresolved
/// one carries both roots it commits and no selected root.
///
/// `leaves` are `(leaf_key, leaf_value, exact state CCB bytes)` for the FULL
/// post-transition tree. Full replacement, not a delta: the cache's only
/// claim to correctness is root equality on load, and a full write is what
/// keeps a crash mid-update from leaving a plausible-but-wrong mixture.
pub fn record_admitted_with_conn(
    tx: &Transaction<'_>,
    admitted: &AdmittedEconomicPosition,
    leaves: &[([u8; 32], [u8; 32], Vec<u8>)],
) -> Result<()> {
    let position = i64::try_from(admitted.economic_position())
        .map_err(|e| anyhow!("position overflow: {e}"))?;
    let (kind, root, fulfillment, realize, void, claim_ref): (
        i64,
        Option<&[u8]>,
        Option<&[u8]>,
        Option<&[u8]>,
        Option<&[u8]>,
        Option<&[u8]>,
    ) = match admitted {
        AdmittedEconomicPosition::SingleRoot {
            economic_root,
            claim_ref,
            ..
        } => (
            0,
            Some(economic_root.as_slice()),
            None,
            None,
            None,
            Some(claim_ref.as_slice()),
        ),
        AdmittedEconomicPosition::ResolvedSofi {
            selected_root,
            fulfillment_id,
            claim_ref,
            ..
        } => (
            1,
            Some(selected_root.as_slice()),
            Some(fulfillment_id.as_slice()),
            None,
            None,
            Some(claim_ref.as_slice()),
        ),
        AdmittedEconomicPosition::UnresolvedSofi {
            fulfillment_id,
            realize_root,
            void_root,
            ..
        } => (
            2,
            None,
            Some(fulfillment_id.as_slice()),
            Some(realize_root.as_slice()),
            Some(void_root.as_slice()),
            None,
        ),
    };
    tx.execute(
        "INSERT INTO economic_admitted_v2 (id, economic_position, claim_kind, economic_root, \
             fulfillment_id, realize_root, void_root, claim_ref)
         VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7)
         ON CONFLICT(id) DO UPDATE SET
             economic_position = excluded.economic_position,
             claim_kind = excluded.claim_kind,
             economic_root = excluded.economic_root,
             fulfillment_id = excluded.fulfillment_id,
             realize_root = excluded.realize_root,
             void_root = excluded.void_root,
             claim_ref = excluded.claim_ref",
        params![position, kind, root, fulfillment, realize, void, claim_ref],
    )?;
    tx.execute(
        "INSERT INTO economic_admitted_history (economic_position, claim_kind, economic_root, \
             fulfillment_id, realize_root, void_root, claim_ref)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
         ON CONFLICT(economic_position) DO UPDATE SET
             claim_kind = excluded.claim_kind,
             economic_root = excluded.economic_root,
             fulfillment_id = excluded.fulfillment_id,
             realize_root = excluded.realize_root,
             void_root = excluded.void_root,
             claim_ref = excluded.claim_ref",
        params![position, kind, root, fulfillment, realize, void, claim_ref],
    )?;
    tx.execute("DELETE FROM economic_leaf_cache", [])?;
    for (key, value, ccb) in leaves {
        tx.execute(
            "INSERT INTO economic_leaf_cache (leaf_key, leaf_value, state_ccb)
             VALUES (?1, ?2, ?3)",
            params![key.as_slice(), value.as_slice(), ccb],
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

/// This device's own frontier strictly below `position`: the highest
/// ordinary position its own lineage admitted there, with the root and the
/// claim it admitted. A device authenticated every step of its own lineage
/// when it admitted it, so its admitted history is its frontier for itself; a
/// conditional SoFi position is never one (as [`PeerFrontier::reached_by`]
/// holds), so the search passes over those. `None` when nothing below
/// `position` was admitted as an ordinary position.
///
/// The caller passes this device's own identity; the frontier carries it.
pub fn own_frontier_below(
    own_genesis: &[u8; 32],
    own_devid: &[u8; 32],
    position: u64,
) -> Result<Option<dsm::economic::peer_lineage::PeerFrontier>> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    let row = conn
        .query_row(
            SELECT_ADMITTED_SINGLE_ROOT_BELOW,
            params![i64::try_from(position).map_err(|e| anyhow!("position overflow: {e}"))?],
            read_admitted_row,
        )
        .optional()?;
    match row.map(admitted_from_row).transpose()? {
        Some(AdmittedEconomicPosition::SingleRoot {
            economic_position,
            economic_root,
            claim_ref,
        }) => Ok(Some(
            dsm::economic::peer_lineage::PeerFrontier::rehydrate_recorded(
                *own_genesis,
                *own_devid,
                economic_position,
                economic_root,
                dsm::sofi::wire::ParentClaimRef::SingleRoot { claim_ref },
            ),
        )),
        Some(other) => Err(anyhow!(
            "the ordinary position admitted below {position} reads back as {other:?}"
        )),
        None => Ok(None),
    }
}

/// This receiver's latest frontier for a peer strictly below `position`
/// (DSM Amendment A8): a coordinate it authenticated on the way to a step it
/// accepted from the peer, with the claim it accepted there.
pub fn frontier_below(
    peer_genesis: &[u8; 32],
    peer_devid: &[u8; 32],
    position: u64,
) -> Result<Option<dsm::economic::peer_lineage::PeerFrontier>> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    let row = conn
        .query_row(
            "SELECT economic_position, economic_root, accepted_claim FROM peer_frontier
             WHERE peer_genesis = ?1 AND peer_devid = ?2 AND economic_position < ?3
             ORDER BY economic_position DESC LIMIT 1",
            params![
                peer_genesis.as_slice(),
                peer_devid.as_slice(),
                i64::try_from(position).map_err(|e| anyhow!("position overflow: {e}"))?
            ],
            |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, Vec<u8>>(1)?,
                    r.get::<_, Vec<u8>>(2)?,
                ))
            },
        )
        .optional()?;
    row.map(|(recorded, root, accepted)| {
        Ok(
            dsm::economic::peer_lineage::PeerFrontier::rehydrate_recorded(
                *peer_genesis,
                *peer_devid,
                u64::try_from(recorded)
                    .map_err(|e| anyhow!("frontier position {recorded}: {e}"))?,
                digest32(root, "frontier root")?,
                dsm::sofi::wire::ParentClaimRef::decode(&accepted)
                    .map_err(|e| anyhow!("frontier claim at {recorded}: {e:?}"))?,
            ),
        )
    })
    .transpose()
}

/// Record, inside the transaction that accepts a step from the peer, the
/// frontier that step's verification reached. The activation root is every
/// receiver's frontier and is never recorded.
pub fn record_frontier_in_tx(
    tx: &rusqlite::Transaction<'_>,
    frontier: &dsm::economic::peer_lineage::PeerFrontier,
) -> Result<()> {
    let (position, root, accepted) = frontier.recorded().ok_or_else(|| {
        anyhow!("the activation root is every receiver's frontier and is never recorded")
    })?;
    tx.execute(
        "INSERT OR IGNORE INTO peer_frontier(
             peer_genesis, peer_devid, economic_position, economic_root, accepted_claim)
         VALUES(?1, ?2, ?3, ?4, ?5)",
        params![
            frontier.genesis().as_slice(),
            frontier.device_id().as_slice(),
            i64::try_from(position).map_err(|e| anyhow!("position overflow: {e}"))?,
            root.as_slice(),
            accepted.encode()
        ],
    )?;
    Ok(())
}

// ── q-durability memos (3.5b PR4) ──────────────────────────────────────────

/// Whether ONE exact immutable object is known Stored on the canonical
/// set. Per exact address, NEVER inferred from an economic-position
/// watermark: EK ancestry advances independently of `R_econ`.
pub fn is_addr_stored(namespace: &str, addr: &[u8; 32]) -> Result<bool> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    let hit: Option<i64> = conn
        .query_row(
            "SELECT 1 FROM immutable_stored_memo WHERE namespace = ?1 AND addr = ?2",
            params![namespace, addr.as_slice()],
            |r| r.get(0),
        )
        .optional()?;
    Ok(hit.is_some())
}

/// Record one exact immutable object as read back `Stored` on the canonical
/// set (storage spec §5 rule 6).
pub fn record_addr_stored(namespace: &str, addr: &[u8; 32]) -> Result<()> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    conn.execute(
        "INSERT OR IGNORE INTO immutable_stored_memo(namespace, addr) VALUES(?1, ?2)",
        params![namespace, addr.as_slice()],
    )?;
    Ok(())
}

// ── EK step chain (3.5b PR4) ───────────────────────────────────────────────

/// The latest EK step for `(rel_key, signer)`: `(ordinal, step_addr, ek_pk)`.
/// `None` means relationship genesis — the signer's chain head is its AK.
pub fn latest_ek_step(
    rel_key: &[u8; 32],
    signer_devid: &[u8; 32],
) -> Result<Option<(u64, [u8; 32], Vec<u8>)>> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    latest_ek_step_with_conn(&conn, rel_key, signer_devid)
}

pub fn latest_ek_step_with_conn(
    conn: &rusqlite::Connection,
    rel_key: &[u8; 32],
    signer_devid: &[u8; 32],
) -> Result<Option<(u64, [u8; 32], Vec<u8>)>> {
    let row = conn
        .query_row(
            "SELECT step_ordinal, step_addr, ek_pk FROM ek_cert_step_chain
             WHERE rel_key = ?1 AND signer_devid = ?2
             ORDER BY step_ordinal DESC LIMIT 1",
            params![rel_key.as_slice(), signer_devid.as_slice()],
            |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, Vec<u8>>(1)?,
                    r.get::<_, Vec<u8>>(2)?,
                ))
            },
        )
        .optional()?;
    Ok(match row {
        Some((ord, addr, pk)) => Some((
            u64::try_from(ord).map_err(|e| anyhow!("negative step ordinal: {e}"))?,
            <[u8; 32]>::try_from(addr.as_slice())
                .map_err(|e| anyhow!("step addr is not 32 bytes: {e}"))?,
            pk,
        )),
        None => None,
    })
}

/// Append one signer-chain step inside the caller's transaction. Idempotent
/// on exact re-append of the same head (crash replay); a DIFFERENT addr at
/// the same next ordinal is refused by the primary key.
pub fn append_ek_step_with_conn(
    conn: &rusqlite::Connection,
    rel_key: &[u8; 32],
    signer_devid: &[u8; 32],
    step_addr: &[u8; 32],
    ek_pk: &[u8],
) -> Result<u64> {
    let latest = latest_ek_step_with_conn(conn, rel_key, signer_devid)?;
    if let Some((ord, addr, ..)) = &latest {
        if addr == step_addr {
            return Ok(*ord);
        }
    }
    let next = latest.map(|(ordinal, ..)| ordinal + 1).unwrap_or(0);
    conn.execute(
        "INSERT INTO ek_cert_step_chain(rel_key, signer_devid, step_ordinal, step_addr, ek_pk)
         VALUES(?1, ?2, ?3, ?4, ?5)",
        params![
            rel_key.as_slice(),
            signer_devid.as_slice(),
            i64::try_from(next).map_err(|e| anyhow!("step ordinal: {e}"))?,
            step_addr.as_slice(),
            ek_pk
        ],
    )?;
    Ok(next)
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)] // test asserts; a failure here is the signal
mod admitted_row_tests {
    use super::*;

    const ROOT: [u8; 32] = [0xC0; 32];
    const FID: [u8; 32] = [0xF1; 32];
    const REALIZE: [u8; 32] = [0xA1; 32];
    const VOID: [u8; 32] = [0xB1; 32];
    const CLAIM: [u8; 32] = [0xD1; 32];

    /// The columns of one admitted row, by name.
    #[derive(Clone, Copy, Default)]
    struct Columns {
        root: Option<[u8; 32]>,
        fid: Option<[u8; 32]>,
        realize: Option<[u8; 32]>,
        void: Option<[u8; 32]>,
        claim: Option<[u8; 32]>,
    }

    fn row(kind: i64, c: Columns) -> AdmittedRow {
        (
            7,
            kind,
            c.root.map(|r| r.to_vec()),
            c.fid.map(|r| r.to_vec()),
            c.realize.map(|r| r.to_vec()),
            c.void.map(|r| r.to_vec()),
            c.claim.map(|r| r.to_vec()),
        )
    }

    const SINGLE: Columns = Columns {
        root: Some(ROOT),
        fid: None,
        realize: None,
        void: None,
        claim: Some(CLAIM),
    };
    const RESOLVED: Columns = Columns {
        root: Some(ROOT),
        fid: Some(FID),
        realize: None,
        void: None,
        claim: Some(CLAIM),
    };
    const UNRESOLVED: Columns = Columns {
        root: None,
        fid: Some(FID),
        realize: Some(REALIZE),
        void: Some(VOID),
        claim: None,
    };

    /// Each kind has ONE exact shape, and a row is refused both for a missing
    /// field and for an extra one.
    ///
    /// A row carrying both a selected root and a realize/void pair makes two
    /// disagreeing claims about which root the position holds, and reading
    /// whichever the arm happens to name is the guess this decoder exists to
    /// refuse — on the coordinate a restart rebuilds the entire lineage from.
    /// An accepted claim belongs to a position that selected a root, and only
    /// to one.
    #[test]
    fn an_admitted_row_must_match_its_own_claim_kind_exactly() {
        // The three exact shapes are accepted.
        assert_eq!(
            admitted_from_row(row(0, SINGLE)).unwrap(),
            AdmittedEconomicPosition::SingleRoot {
                economic_position: 7,
                economic_root: ROOT,
                claim_ref: CLAIM,
            }
        );
        assert_eq!(
            admitted_from_row(row(1, RESOLVED)).unwrap(),
            AdmittedEconomicPosition::ResolvedSofi {
                economic_position: 7,
                selected_root: ROOT,
                fulfillment_id: FID,
                claim_ref: CLAIM,
            }
        );
        assert_eq!(
            admitted_from_row(row(2, UNRESOLVED)).unwrap(),
            AdmittedEconomicPosition::UnresolvedSofi {
                economic_position: 7,
                fulfillment_id: FID,
                realize_root: REALIZE,
                void_root: VOID,
            }
        );

        // EXTRA fields.
        let extras = [
            (
                "single-root with a fulfillment",
                row(
                    0,
                    Columns {
                        fid: Some(FID),
                        ..SINGLE
                    },
                ),
            ),
            (
                "single-root with a realize root",
                row(
                    0,
                    Columns {
                        realize: Some(REALIZE),
                        ..SINGLE
                    },
                ),
            ),
            (
                "single-root with a void root",
                row(
                    0,
                    Columns {
                        void: Some(VOID),
                        ..SINGLE
                    },
                ),
            ),
            (
                "resolved with a realize root",
                row(
                    1,
                    Columns {
                        realize: Some(REALIZE),
                        ..RESOLVED
                    },
                ),
            ),
            (
                "resolved with a void root",
                row(
                    1,
                    Columns {
                        void: Some(VOID),
                        ..RESOLVED
                    },
                ),
            ),
            // An unresolved position that also names a selected root claims
            // both to have chosen and not to have.
            (
                "unresolved with a selected root",
                row(
                    2,
                    Columns {
                        root: Some(ROOT),
                        ..UNRESOLVED
                    },
                ),
            ),
            // An unresolved position was registered but never accepted.
            (
                "unresolved with an accepted claim",
                row(
                    2,
                    Columns {
                        claim: Some(CLAIM),
                        ..UNRESOLVED
                    },
                ),
            ),
        ];
        for (name, r) in extras {
            assert!(
                admitted_from_row(r).is_err(),
                "{name}: an extra field must be refused, not ignored"
            );
        }

        // MISSING fields.
        let missing = [
            (
                "single-root with no root",
                row(
                    0,
                    Columns {
                        root: None,
                        ..SINGLE
                    },
                ),
            ),
            (
                "single-root with no claim",
                row(
                    0,
                    Columns {
                        claim: None,
                        ..SINGLE
                    },
                ),
            ),
            (
                "resolved with no fulfillment",
                row(
                    1,
                    Columns {
                        fid: None,
                        ..RESOLVED
                    },
                ),
            ),
            (
                "resolved with no root",
                row(
                    1,
                    Columns {
                        root: None,
                        ..RESOLVED
                    },
                ),
            ),
            (
                "resolved with no claim",
                row(
                    1,
                    Columns {
                        claim: None,
                        ..RESOLVED
                    },
                ),
            ),
            (
                "unresolved with no realize root",
                row(
                    2,
                    Columns {
                        realize: None,
                        ..UNRESOLVED
                    },
                ),
            ),
            (
                "unresolved with no void root",
                row(
                    2,
                    Columns {
                        void: None,
                        ..UNRESOLVED
                    },
                ),
            ),
            (
                "unresolved with no fulfillment",
                row(
                    2,
                    Columns {
                        fid: None,
                        ..UNRESOLVED
                    },
                ),
            ),
        ];
        for (name, r) in missing {
            assert!(admitted_from_row(r).is_err(), "{name}: must be refused");
        }

        // An unknown kind is refused rather than defaulted.
        assert!(admitted_from_row(row(3, SINGLE)).is_err());
    }
}
