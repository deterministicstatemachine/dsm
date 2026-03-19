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
