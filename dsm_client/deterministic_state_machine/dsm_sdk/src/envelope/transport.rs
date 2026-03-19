//! Transport encoding helpers for SDK side (protobuf only)
//!
//! These simply re-export the core crate's envelope transport helpers to avoid duplication.

pub use dsm::envelope::{from_canonical_bytes, to_canonical_bytes};
