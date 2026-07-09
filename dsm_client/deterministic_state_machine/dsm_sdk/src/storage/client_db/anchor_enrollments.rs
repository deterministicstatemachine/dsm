// SPDX-License-Identifier: MIT OR Apache-2.0
//! Fused-anchor enrollment persistence (Software-Authority / Hardware-Identity receiver-admit).
//!
//! The RECEIVER's pinned admission of a counterparty's fused anchor, keyed by the counterparty
//! device id — the SQLite backing for
//! [`dsm::crypto::anchor_enrollment::AnchorEnrollmentStore`] (v2 pin shape: `pk_chip` = resident
//! chip Ed25519 key). Pins are admitted only inside the offline-bearer bilateral confirm flow
//! (first valid transfer for an already-verified contact), never implicitly from a release alone.

use anyhow::{anyhow, Result};
use rusqlite::{params, OptionalExtension};

use dsm::crypto::anchor_enrollment::{AnchorEnrollment, FusedAnchorPin};

use super::get_connection;

fn fixed32(bytes: Vec<u8>, what: &str) -> Result<[u8; 32]> {
    bytes
        .try_into()
        .map_err(|_| anyhow!("anchor_enrollments: {what} is not 32 bytes"))
}

/// The pinned enrollment for a counterparty device, if admitted.
pub fn get_anchor_enrollment_raw(device_id: &[u8; 32]) -> Result<Option<AnchorEnrollment>> {
    let binding = get_connection()?;
    let conn = binding
        .lock()
        .map_err(|_| anyhow!("anchor_enrollments: db lock poisoned"))?;
    let row = conn
        .query_row(
            "SELECT policy_hash, bundle, anchor_id, enrolled_counter, partition_pk,
                    pk_chip, uncompromised
             FROM anchor_enrollments WHERE device_id = ?1",
            params![device_id.as_slice()],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                    row.get::<_, Vec<u8>>(5)?,
                    row.get::<_, i64>(6)?,
                ))
            },
        )
        .optional()?;
    let Some((policy_hash, bundle, anchor_id, enrolled, partition_pk, pk_chip, uncompromised)) =
        row
    else {
        return Ok(None);
    };
    Ok(Some(AnchorEnrollment {
        device_id: *device_id,
        policy_hash: fixed32(policy_hash, "policy_hash")?,
        pin: FusedAnchorPin {
            bundle: fixed32(bundle, "bundle")?,
            anchor_id: fixed32(anchor_id, "anchor_id")?,
            enrolled_counter: enrolled as u64,
            partition_pk,
            pk_chip,
            uncompromised: uncompromised != 0,
        },
    }))
}

/// The appliance root the receiver adopted from the holder's last ACCEPTED
/// release (Def. 25 check 2), plus the anchor counter adopted with it.
/// `None` = relationship genesis — the next release's own `prev_root` is
/// adopted TOFU by the acceptance predicate.
pub fn load_accepted_anchor_root(device_id: &[u8; 32]) -> Result<Option<([u8; 32], u64)>> {
    let binding = get_connection()?;
    let conn = binding
        .lock()
        .map_err(|_| anyhow!("anchor_accepted_roots: db lock poisoned"))?;
    let row = conn
        .query_row(
            "SELECT accepted_root, next_anchor_counter FROM anchor_accepted_roots
             WHERE device_id = ?1",
            params![device_id.as_slice()],
            |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?)),
        )
        .optional()?;
    match row {
        Some((root, ctr)) => Ok(Some((
            fixed32(root, "accepted_root")?,
            u64::try_from(ctr).unwrap_or(0),
        ))),
        None => Ok(None),
    }
}

/// Adopt the holder's successor appliance root after an accepted release's
/// canonical commit. INSERT OR REPLACE: each accepted transfer moves the
/// lineage frontier forward.
pub fn store_accepted_anchor_root(
    device_id: &[u8; 32],
    accepted_root: &[u8; 32],
    next_anchor_counter: u64,
) -> Result<()> {
    let binding = get_connection()?;
    let conn = binding
        .lock()
        .map_err(|_| anyhow!("anchor_accepted_roots: db lock poisoned"))?;
    let now = crate::util::deterministic_time::tick() as i64;
    conn.execute(
        "INSERT OR REPLACE INTO anchor_accepted_roots
            (device_id, accepted_root, next_anchor_counter, updated_at)
         VALUES (?1, ?2, ?3, ?4)",
        params![
            device_id.as_slice(),
            accepted_root.as_slice(),
            next_anchor_counter as i64,
            now
        ],
    )?;
    Ok(())
}

/// Admit (pin) a fused anchor. INSERT OR REPLACE: re-admission overwrites, matching the
/// [`AnchorEnrollmentStore`](dsm::crypto::anchor_enrollment::AnchorEnrollmentStore) contract —
/// the CALLER owns the authority rules (first-transfer TOFU / same-anchor upgrade only; a
/// differing anchor is rejected before ever reaching this write).
pub fn admit_anchor_enrollment(e: &AnchorEnrollment) -> Result<()> {
    let binding = get_connection()?;
    let conn = binding
        .lock()
        .map_err(|_| anyhow!("anchor_enrollments: db lock poisoned"))?;
    conn.execute(
        "INSERT OR REPLACE INTO anchor_enrollments
            (device_id, policy_hash, bundle, anchor_id, enrolled_counter, partition_pk,
             pk_chip, uncompromised)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            e.device_id.as_slice(),
            e.policy_hash.as_slice(),
            e.pin.bundle.as_slice(),
            e.pin.anchor_id.as_slice(),
            e.pin.enrolled_counter as i64,
            e.pin.partition_pk.as_slice(),
            e.pin.pk_chip.as_slice(),
            e.pin.uncompromised as i64,
        ],
    )?;
    Ok(())
}
