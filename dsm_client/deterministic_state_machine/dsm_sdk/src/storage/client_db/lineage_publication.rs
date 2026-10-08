// SPDX-License-Identifier: Apache-2.0

//! What this device owes the epoch index of a shared lineage (SoFi Amendment
//! S23): the hints and checkpoints of generations it established and found
//! unpublished. Each object is frozen as publication debt
//! (`frozen_publication_artifact`, purpose [`PURPOSE`]); its append under the
//! epoch locator is recorded here, and the sweep makes it once the object is
//! `Stored`. A debt that never reaches the set costs a later reader speed and
//! nothing else: the walk establishes every generation without it.

use anyhow::{anyhow, Result};
use rusqlite::params;

use super::frozen_publication_artifact::freeze_artifact_with_conn;
use super::get_connection;

/// The purpose a shared-lineage object is frozen under.
pub const PURPOSE: &str = "shared-lineage";

/// One append owed: the object's key, the locator it is owed under, and the
/// set it is owed to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwedAppend {
    pub object_key: String,
    pub locator: [u8; 32],
    pub storage_set_id: [u8; 32],
}

/// Owe `payload` (an object whose key is `object_key`) to `storage_set_id`,
/// and, when `locator` names one, its append there. Owing the same object
/// again is a no-op.
pub fn owe(
    storage_set_id: &[u8; 32],
    object_key: &str,
    payload: &[u8],
    bound_root: &[u8; 32],
    locator: Option<&[u8; 32]>,
) -> Result<()> {
    let binding = get_connection()?;
    let mut conn = binding
        .lock()
        .map_err(|e| anyhow!("lineage publication: the store is poisoned: {e}"))?;
    let tx = conn.transaction()?;
    freeze_artifact_with_conn(
        &tx,
        storage_set_id,
        object_key,
        payload,
        bound_root,
        PURPOSE,
    )?;
    if let Some(locator) = locator {
        tx.execute(
            "INSERT OR IGNORE INTO lineage_index_debt
                (object_key, locator, storage_set_id, state, last_error)
             VALUES (?1, ?2, ?3, 'pending', '')",
            params![object_key, locator.as_slice(), storage_set_id.as_slice()],
        )?;
    }
    tx.commit()?;
    Ok(())
}

/// The appends owed for objects already read back `Stored`, oldest object
/// first, at most `limit`.
pub fn appends_due(limit: u32) -> Result<Vec<OwedAppend>> {
    let binding = get_connection()?;
    let conn = binding
        .lock()
        .map_err(|e| anyhow!("lineage publication: the store is poisoned: {e}"))?;
    let mut stmt = conn.prepare(
        "SELECT d.object_key, d.locator, d.storage_set_id
           FROM lineage_index_debt d
           JOIN frozen_publication_artifact a ON a.object_key = d.object_key
          WHERE d.state = 'pending' AND a.state = 'stored'
          ORDER BY a.insertion_ordinal ASC
          LIMIT ?1",
    )?;
    let rows = stmt.query_map(params![i64::from(limit)], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, Vec<u8>>(1)?,
            r.get::<_, Vec<u8>>(2)?,
        ))
    })?;
    let mut due = Vec::new();
    for row in rows {
        let (object_key, locator, set) = row?;
        due.push(OwedAppend {
            object_key,
            locator: <[u8; 32]>::try_from(locator.as_slice())
                .map_err(|e| anyhow!("lineage_index_debt: locator: {e}"))?,
            storage_set_id: <[u8; 32]>::try_from(set.as_slice())
                .map_err(|e| anyhow!("lineage_index_debt: storage set: {e}"))?,
        });
    }
    Ok(due)
}

/// Record an owed append as made.
pub fn appended(owed: &OwedAppend) -> Result<()> {
    record(owed, "appended", "")
}

/// Record why an owed append was not made; it stays owed.
pub fn not_appended(owed: &OwedAppend, why: &str) -> Result<()> {
    record(owed, "pending", why)
}

fn record(owed: &OwedAppend, state: &str, why: &str) -> Result<()> {
    let binding = get_connection()?;
    let conn = binding
        .lock()
        .map_err(|e| anyhow!("lineage publication: the store is poisoned: {e}"))?;
    conn.execute(
        "UPDATE lineage_index_debt SET state = ?3, last_error = ?4
          WHERE object_key = ?1 AND locator = ?2",
        params![owed.object_key, owed.locator.as_slice(), state, why],
    )?;
    Ok(())
}
