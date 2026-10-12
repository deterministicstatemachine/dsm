// SPDX-License-Identifier: MIT OR Apache-2.0
//! This device's own directory entry (`sdk::device_directory`): the last one
//! it signed, so a republish writes the same bytes and an update takes the
//! next counter. The entry is public; nothing secret is kept here.

use anyhow::Result;
use rusqlite::{params, OptionalExtension};

use super::get_connection;

/// The encoded entry this device last signed, if any.
pub fn load() -> Result<Option<Vec<u8>>> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    Ok(conn
        .query_row(
            "SELECT entry FROM own_directory_entry WHERE id = 1",
            [],
            |r| r.get::<_, Vec<u8>>(0),
        )
        .optional()?)
}

/// Keep `entry` as this device's own.
pub fn store(entry: &[u8]) -> Result<()> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    conn.execute(
        "INSERT INTO own_directory_entry (id, entry) VALUES (1, ?1)
         ON CONFLICT(id) DO UPDATE SET entry = excluded.entry",
        params![entry],
    )?;
    Ok(())
}
