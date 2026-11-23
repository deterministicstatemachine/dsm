// SPDX-License-Identifier: MIT OR Apache-2.0

//! Storage node DB layer: PostgreSQL through `deadpool_postgres::Pool`.

mod backup_slots;
mod committed;
mod pg;

pub use backup_slots::{
    backup_part, backup_slot, backup_start, backup_whole_part, PartTaken, SlotState, StartTaken,
};

pub use committed::{
    CommittedCells, TreeBuild, TreeBuildsFull, KEPT_CYCLES, KEPT_LEAVES, TREE_BUILDS_QUEUED,
};
pub use pg::*;

/// The Postgres database the node's unit tests run on.
#[cfg(test)]
pub(crate) mod test_store;

/// The keyed-cell and index properties a member owes.
#[cfg(test)]
mod cell_properties;

/// The immutable-object properties of the store.
#[cfg(test)]
mod store_properties;

/// The schema version a node starts on, and what it refuses.
#[cfg(test)]
mod schema_properties;
