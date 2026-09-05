// SPDX-License-Identifier: MIT OR Apache-2.0

//! Storage node DB layer — unified interface.
//!
//! Default (PostgreSQL): `deadpool_postgres::Pool` via `db::pg`.
//! Local-dev (SQLite):   `rusqlite::Connection` wrapped in `Arc<Mutex<>>` via `db::sqlite`.
//!
//! Feature flag `local-dev` switches the implementation at compile time.

#[cfg(not(feature = "local-dev"))]
mod pg;

#[cfg(not(feature = "local-dev"))]
pub use pg::*;

#[cfg(feature = "local-dev")]
mod sqlite;

#[cfg(feature = "local-dev")]
pub use sqlite::*;

/// The write-once properties every one-shot register owes, stated once and
/// run against whichever backend is compiled.
#[cfg(test)]
pub(crate) mod write_once_properties;
