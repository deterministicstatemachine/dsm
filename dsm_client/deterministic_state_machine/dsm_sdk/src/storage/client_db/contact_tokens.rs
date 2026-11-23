// SPDX-License-Identifier: MIT OR Apache-2.0
//! The tokens each contact has added, as this device last read them from the
//! contact's own signed lists (`sdk::contact_tokens`), and the list this
//! device last published of its own. A contact is offered, and sent, only a
//! token it has added. Adding a token is permanent, so a row is never
//! removed.

use std::collections::BTreeSet;

use anyhow::{anyhow, Result};
use rusqlite::{params, OptionalExtension};

use super::{column_32, get_connection};

/// Keep `policy_commits` as tokens the contact `device_id` has added, beside
/// those already kept for it. Answers how many of them were not kept before.
pub fn keep_added(device_id: &[u8; 32], policy_commits: &BTreeSet<[u8; 32]>) -> Result<usize> {
    let binding = get_connection()?;
    let mut conn = binding
        .lock()
        .map_err(|e| anyhow!("the client database lock: {e}"))?;
    let tx = conn.transaction()?;
    let mut newly_kept = 0usize;
    {
        let mut insert = tx.prepare_cached(
            "INSERT OR IGNORE INTO contact_added_tokens (device_id, policy_commit)
             VALUES (?1, ?2)",
        )?;
        for commit in policy_commits {
            newly_kept += insert.execute(params![&device_id[..], &commit[..]])?;
        }
    }
    tx.commit()?;
    Ok(newly_kept)
}

/// The tokens kept as added by the contact `device_id`.
pub fn added_by(device_id: &[u8; 32]) -> Result<BTreeSet<[u8; 32]>> {
    let binding = get_connection()?;
    let conn = binding
        .lock()
        .map_err(|e| anyhow!("the client database lock: {e}"))?;
    let mut stmt =
        conn.prepare_cached("SELECT policy_commit FROM contact_added_tokens WHERE device_id = ?1")?;
    let rows = stmt
        .query_map(params![&device_id[..]], |r| column_32(r, 0))?
        .collect::<rusqlite::Result<BTreeSet<[u8; 32]>>>()?;
    Ok(rows)
}

/// The encoded list this device last published of its own, if any.
pub fn own_published() -> Result<Option<Vec<u8>>> {
    let binding = get_connection()?;
    let conn = binding
        .lock()
        .map_err(|e| anyhow!("the client database lock: {e}"))?;
    Ok(conn
        .query_row("SELECT list FROM own_token_list WHERE id = 1", [], |r| {
            r.get::<_, Vec<u8>>(0)
        })
        .optional()?)
}

/// Keep `list` as the one this device last published.
pub fn store_own_published(list: &[u8]) -> Result<()> {
    let binding = get_connection()?;
    let conn = binding
        .lock()
        .map_err(|e| anyhow!("the client database lock: {e}"))?;
    conn.execute(
        "INSERT INTO own_token_list (id, list) VALUES (1, ?1)
         ON CONFLICT(id) DO UPDATE SET list = excluded.list",
        params![list],
    )?;
    Ok(())
}
