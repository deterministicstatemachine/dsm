// SPDX-License-Identifier: MIT OR Apache-2.0
//! How many `storage.sync` runs completed on this device: the deterministic
//! sync counter `storage.status` reports.

use anyhow::Result;
use rusqlite::OptionalExtension;

use super::get_connection;

/// Count one more completed sync; returns the new count.
pub fn record_completed() -> Result<u64> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    let completed: i64 = conn.query_row(
        "INSERT INTO storage_sync_runs (id, completed) VALUES (1, 1)
         ON CONFLICT(id) DO UPDATE SET completed = completed + 1
         RETURNING completed",
        [],
        |r| r.get(0),
    )?;
    Ok(u64::try_from(completed)?)
}

/// The syncs completed so far; zero before the first one completes.
pub fn completed() -> Result<u64> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    let completed = conn
        .query_row(
            "SELECT completed FROM storage_sync_runs WHERE id = 1",
            [],
            |r| r.get::<_, i64>(0),
        )
        .optional()?;
    match completed {
        Some(count) => Ok(u64::try_from(count)?),
        None => Ok(0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[serial_test::serial]
    fn completed_runs_count_up_from_zero() {
        crate::economic_fixtures::use_test_storage_dir();
        crate::storage::client_db::reset_database_for_tests();
        crate::storage::client_db::init_database().expect("init db");
        assert_eq!(completed().expect("read"), 0);
        assert_eq!(record_completed().expect("first"), 1);
        assert_eq!(record_completed().expect("second"), 2);
        assert_eq!(completed().expect("read"), 2);
    }
}
