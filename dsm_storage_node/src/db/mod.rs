// SPDX-License-Identifier: MIT OR Apache-2.0

//! Storage node DB layer: PostgreSQL through `deadpool_postgres::Pool`.

mod pg;

pub use pg::*;

/// The Postgres database the node's unit tests run on.
#[cfg(test)]
pub(crate) mod test_store;

/// The keyed-cell and index properties a member owes.
#[cfg(test)]
mod cell_properties;

/// The immutable-object and device-tree properties of the store.
#[cfg(test)]
mod store_properties;

/// The schema version a node starts on, and what it refuses.
#[cfg(test)]
mod schema_properties;
