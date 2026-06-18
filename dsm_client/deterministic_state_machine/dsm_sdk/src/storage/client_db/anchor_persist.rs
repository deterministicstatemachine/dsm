// SPDX-License-Identifier: MIT OR Apache-2.0
//! SQLite persistence for the offline-bearer anti-clone anchor: the SENDER's monotonic frontier
//! (keyed by id_anchor) and the RECEIVER's pinned enrollment (identity + firmware hash + policy +
//! frontier, keyed by counterparty device id). Both must survive an app restart — an in-memory
//! receiver frontier would let a consumed-parent replay through after a restart.

use anyhow::{anyhow, Result};

use super::get_connection;

fn vec_to_32(v: &[u8]) -> Option<[u8; 32]> {
    if v.len() != 32 {
        return None;
    }
    let mut a = [0u8; 32];
    a.copy_from_slice(v);
    Some(a)
}

// ---- Sender frontier (keyed by id_anchor) ----

pub fn get_anchor_frontier(anchor_id: &[u8; 32]) -> Option<([u8; 32], u64)> {
    let binding = get_connection().ok()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    conn.query_row(
        "SELECT frontier_root, state_number FROM anchor_frontiers WHERE anchor_id = ?1",
        rusqlite::params![anchor_id.as_slice()],
        |r| {
            let root: Vec<u8> = r.get(0)?;
            let state: i64 = r.get(1)?;
            Ok((root, state))
        },
    )
    .ok()
    .and_then(|(root, state)| vec_to_32(&root).map(|r| (r, state as u64)))
}

/// CAS-advance: apply only if the stored root equals `expected_parent_root` (or none is stored AND
/// `expected_parent_root` is genesis-zero) AND `new_state_number` strictly exceeds the stored one.
/// Returns `Ok(false)` on a stale parent / non-monotonic state (a fork). The held connection lock
/// makes the read+write atomic.
pub fn set_anchor_frontier_cas(
    anchor_id: &[u8; 32],
    expected_parent_root: [u8; 32],
    new_root: [u8; 32],
    new_state_number: u64,
) -> Result<bool> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    let current: Option<(Vec<u8>, i64)> = conn
        .query_row(
            "SELECT frontier_root, state_number FROM anchor_frontiers WHERE anchor_id = ?1",
            rusqlite::params![anchor_id.as_slice()],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .ok();
    match current {
        Some((cur_root, cur_state)) => {
            if cur_root.as_slice() != expected_parent_root.as_slice()
                || new_state_number <= cur_state as u64
            {
                return Ok(false);
            }
        }
        None => {
            if expected_parent_root != [0u8; 32] {
                return Ok(false);
            }
        }
    }
    conn.execute(
        "INSERT INTO anchor_frontiers(anchor_id, frontier_root, state_number) VALUES (?1, ?2, ?3)
         ON CONFLICT(anchor_id) DO UPDATE SET frontier_root = ?2, state_number = ?3",
        rusqlite::params![
            anchor_id.as_slice(),
            new_root.as_slice(),
            new_state_number as i64
        ],
    )?;
    Ok(true)
}

// ---- Receiver enrollment (keyed by device_id) ----

pub struct PersistedEnrollment {
    pub id_anchor: [u8; 32],
    pub commitment_c: [u8; 32],
    pub leaf_spki: Vec<u8>,
    pub firmware_id: [u8; 32],
    pub screen_template_id: u32,
    pub firmware_hash: [u8; 32],
    pub policy_hash: [u8; 32],
    pub frontier_root: [u8; 32],
    pub frontier_state: u64,
}

pub fn get_enrollment(device_id: &[u8; 32]) -> Option<PersistedEnrollment> {
    let binding = get_connection().ok()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    conn.query_row(
        "SELECT id_anchor, commitment_c, leaf_spki, firmware_id, screen_template_id, firmware_hash, \
                policy_hash, frontier_root, frontier_state \
         FROM anchor_enrollments WHERE device_id = ?1",
        rusqlite::params![device_id.as_slice()],
        |r| {
            Ok((
                r.get::<_, Vec<u8>>(0)?,
                r.get::<_, Vec<u8>>(1)?,
                r.get::<_, Vec<u8>>(2)?,
                r.get::<_, Vec<u8>>(3)?,
                r.get::<_, i64>(4)?,
                r.get::<_, Vec<u8>>(5)?,
                r.get::<_, Vec<u8>>(6)?,
                r.get::<_, Vec<u8>>(7)?,
                r.get::<_, i64>(8)?,
            ))
        },
    )
    .ok()
    .and_then(|(ida, c, spki, fwid, stid, fwh, ph, fr, fs)| {
        Some(PersistedEnrollment {
            id_anchor: vec_to_32(&ida)?,
            commitment_c: vec_to_32(&c)?,
            leaf_spki: spki,
            firmware_id: vec_to_32(&fwid)?,
            screen_template_id: stid as u32,
            firmware_hash: vec_to_32(&fwh)?,
            policy_hash: vec_to_32(&ph)?,
            frontier_root: vec_to_32(&fr)?,
            frontier_state: fs as u64,
        })
    })
}

pub fn admit_enrollment(device_id: &[u8; 32], e: &PersistedEnrollment) -> Result<()> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    conn.execute(
        "INSERT OR REPLACE INTO anchor_enrollments(device_id, id_anchor, commitment_c, leaf_spki, \
            firmware_id, screen_template_id, firmware_hash, policy_hash, frontier_root, frontier_state) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        rusqlite::params![
            device_id.as_slice(),
            e.id_anchor.as_slice(),
            e.commitment_c.as_slice(),
            e.leaf_spki.as_slice(),
            e.firmware_id.as_slice(),
            e.screen_template_id as i64,
            e.firmware_hash.as_slice(),
            e.policy_hash.as_slice(),
            e.frontier_root.as_slice(),
            e.frontier_state as i64,
        ],
    )?;
    Ok(())
}

/// CAS-advance the pinned enrollment frontier. Errors if the device is not admitted; returns
/// `Ok(false)` on a stale parent / non-monotonic state (a fork). Atomic under the connection lock.
pub fn advance_enrollment_frontier_cas(
    device_id: &[u8; 32],
    expected_parent_root: [u8; 32],
    new_root: [u8; 32],
    new_state_number: u64,
) -> Result<bool> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    let current: Option<(Vec<u8>, i64)> = conn
        .query_row(
            "SELECT frontier_root, frontier_state FROM anchor_enrollments WHERE device_id = ?1",
            rusqlite::params![device_id.as_slice()],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .ok();
    let (cur_root, cur_state) =
        current.ok_or_else(|| anyhow!("advance_enrollment_frontier_cas: device not admitted"))?;
    if cur_root.as_slice() != expected_parent_root.as_slice()
        || new_state_number <= cur_state as u64
    {
        return Ok(false);
    }
    conn.execute(
        "UPDATE anchor_enrollments SET frontier_root = ?2, frontier_state = ?3 WHERE device_id = ?1",
        rusqlite::params![
            device_id.as_slice(),
            new_root.as_slice(),
            new_state_number as i64
        ],
    )?;
    Ok(true)
}
