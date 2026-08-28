// SPDX-License-Identifier: Apache-2.0

//! Durable storage for the economic admission in flight.
//!
//! ## Why the `_with_conn` forms exist
//!
//! The pending row must be written in the **same transaction** as the head
//! advance that created it. If the two could commit separately, a crash
//! between them leaves one of two broken states: fenced value with no record
//! of why it is fenced, or a fence with no accepted value behind it. Neither
//! is recoverable by inspection, because in both cases the device cannot tell
//! which half happened.
//!
//! So every mutator here takes an existing `&Transaction` and never opens its
//! own connection — opening one inside a transaction would also deadlock
//! against the caller's lock.
//!
//! ## At most one per device
//!
//! `PRIMARY KEY(device_id)` is the enforcement, not a convention. The economic
//! position cannot advance while an admission is pending, so a second
//! concurrent admission is not a state the protocol can be in; making it
//! unrepresentable in the schema means recovery never has to choose between
//! two candidates.

use anyhow::{anyhow, Result};
use rusqlite::{params, OptionalExtension, Transaction};

use dsm::economic::admission::{
    AcceptedAdmissionCoords, EconomicAdmissionState, PendingAdmissionKind, PendingEconomicAdmission,
};

fn kind_code(kind: &PendingAdmissionKind) -> i64 {
    match kind {
        PendingAdmissionKind::DsmBacked => 0,
        PendingAdmissionKind::OfflineLoad { .. } => 1,
        PendingAdmissionKind::OfflineUnload { .. } => 2,
    }
}

fn state_code(state: &EconomicAdmissionState) -> i64 {
    match state {
        EconomicAdmissionState::Prepared => 0,
        EconomicAdmissionState::LocalAcceptedPendingEcon => 1,
        EconomicAdmissionState::EvidencePublished => 2,
        EconomicAdmissionState::Registered => 3,
        EconomicAdmissionState::Admitted => 4,
    }
}

fn state_from_code(code: i64) -> Result<EconomicAdmissionState> {
    Ok(match code {
        0 => EconomicAdmissionState::Prepared,
        1 => EconomicAdmissionState::LocalAcceptedPendingEcon,
        2 => EconomicAdmissionState::EvidencePublished,
        3 => EconomicAdmissionState::Registered,
        4 => EconomicAdmissionState::Admitted,
        other => return Err(anyhow!("unknown admission lifecycle state {other}")),
    })
}

fn digest32(v: Vec<u8>, what: &str) -> Result<[u8; 32]> {
    <[u8; 32]>::try_from(v.as_slice()).map_err(|_| anyhow!("{what} is not 32 bytes"))
}

/// Insert or replace the pending admission, inside the caller's transaction.
pub fn put_pending_admission_with_conn(
    tx: &Transaction<'_>,
    device_id: &[u8; 32],
    pending: &PendingEconomicAdmission,
    now: i64,
) -> Result<()> {
    // `Prepared` is never durable: before acceptance nothing changed, so
    // recovery has nothing to finish — and a Prepared record has no
    // acceptance coordinates to store. Refusing here keeps the invariant
    // structural rather than conventional.
    let coords = pending
        .accepted_coords()
        .map_err(|e| anyhow!("refusing to persist a pre-acceptance admission: {e}"))?;
    let fenced: Option<Vec<u8>> = pending.kind.fenced_asset().map(|a| a.to_vec());
    tx.execute(
        "INSERT INTO economic_pending_admissions(
             device_id, kind, fenced_asset, lifecycle_state, economic_position,
             pre_economic_root, post_economic_root, operation_digest,
             accepted_substrate_addr, admission_manifest_addr, c_dsm_plus,
             embedded_parent, updated_at)
         VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)
         ON CONFLICT(device_id) DO UPDATE SET
             kind=excluded.kind,
             fenced_asset=excluded.fenced_asset,
             lifecycle_state=excluded.lifecycle_state,
             economic_position=excluded.economic_position,
             pre_economic_root=excluded.pre_economic_root,
             post_economic_root=excluded.post_economic_root,
             operation_digest=excluded.operation_digest,
             accepted_substrate_addr=excluded.accepted_substrate_addr,
             admission_manifest_addr=excluded.admission_manifest_addr,
             c_dsm_plus=excluded.c_dsm_plus,
             embedded_parent=excluded.embedded_parent,
             updated_at=excluded.updated_at",
        params![
            device_id.as_slice(),
            kind_code(&pending.kind),
            fenced,
            state_code(&pending.state),
            pending.economic_position as i64,
            pending.pre_economic_root.as_slice(),
            coords.post_economic_root.as_slice(),
            pending.operation_digest.as_slice(),
            coords.accepted_substrate_addr.as_slice(),
            coords.admission_manifest_addr.as_slice(),
            coords.c_dsm_plus.as_slice(),
            coords.embedded_parent.as_slice(),
            now,
        ],
    )?;
    Ok(())
}

/// Clear the pending admission — the ONLY legitimate reason is reaching
/// `Admitted`, and the caller is responsible for having got there.
///
/// There is deliberately no "abort" or "expire": no timeout ever abandons an
/// admission. Abandoning one would leave locally-accepted value with no
/// economic ancestry and a permanently burned register position behind it.
pub fn clear_pending_admission_with_conn(tx: &Transaction<'_>, device_id: &[u8; 32]) -> Result<()> {
    tx.execute(
        "DELETE FROM economic_pending_admissions WHERE device_id = ?1",
        params![device_id.as_slice()],
    )?;
    Ok(())
}

/// Read the pending admission using a caller-supplied connection.
///
/// Takes `&rusqlite::Connection` so the head loader can read it under the lock
/// it already holds — the head and its fence state must come from one
/// consistent read, or a concurrent writer could hand back a head whose fence
/// belongs to a different moment.
pub fn load_pending_admission_with_conn(
    conn: &rusqlite::Connection,
    device_id: &[u8; 32],
) -> Result<Option<PendingEconomicAdmission>> {
    let row = conn
        .query_row(
            "SELECT kind, fenced_asset, lifecycle_state, economic_position,
                    pre_economic_root, post_economic_root, operation_digest,
                    accepted_substrate_addr, admission_manifest_addr, c_dsm_plus,
                    embedded_parent
             FROM economic_pending_admissions WHERE device_id = ?1",
            params![device_id.as_slice()],
            |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, Option<Vec<u8>>>(1)?,
                    r.get::<_, i64>(2)?,
                    r.get::<_, i64>(3)?,
                    r.get::<_, Vec<u8>>(4)?,
                    r.get::<_, Vec<u8>>(5)?,
                    r.get::<_, Vec<u8>>(6)?,
                    r.get::<_, Vec<u8>>(7)?,
                    r.get::<_, Vec<u8>>(8)?,
                    r.get::<_, Vec<u8>>(9)?,
                    r.get::<_, Vec<u8>>(10)?,
                ))
            },
        )
        .optional()?;

    let Some((
        kind_c,
        fenced,
        state_c,
        position,
        pre,
        post,
        digest,
        substrate,
        manifest,
        c_plus,
        parent,
    )) = row
    else {
        return Ok(None);
    };

    let kind = match kind_c {
        0 => PendingAdmissionKind::DsmBacked,
        1 | 2 => {
            // A boundary admission without its asset cannot be fenced
            // correctly — the fence would have to block all bearer activity or
            // none, and both are wrong. Refuse rather than guess.
            let asset = digest32(
                fenced.ok_or_else(|| {
                    anyhow!("offline boundary admission has no fenced_asset — cannot fence")
                })?,
                "fenced_asset",
            )?;
            if kind_c == 1 {
                PendingAdmissionKind::OfflineLoad {
                    asset_policy_commit: asset,
                }
            } else {
                PendingAdmissionKind::OfflineUnload {
                    asset_policy_commit: asset,
                }
            }
        }
        other => return Err(anyhow!("unknown pending admission kind {other}")),
    };

    PendingEconomicAdmission::from_durable_parts(
        kind,
        state_from_code(state_c)?,
        u64::try_from(position).map_err(|_| anyhow!("economic_position is negative"))?,
        digest32(pre, "pre_economic_root")?,
        digest32(digest, "operation_digest")?,
        AcceptedAdmissionCoords {
            post_economic_root: digest32(post, "post_economic_root")?,
            accepted_substrate_addr: digest32(substrate, "accepted_substrate_addr")?,
            admission_manifest_addr: digest32(manifest, "admission_manifest_addr")?,
            c_dsm_plus: digest32(c_plus, "c_dsm_plus")?,
            embedded_parent: digest32(parent, "embedded_parent")?,
        },
    )
    .map(Some)
    .map_err(|e| anyhow!("stored admission is not reconstructible: {e}"))
}
