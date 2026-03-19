//! Canonical serialization utilities.
//!
//! This module centralizes canonical byte generation to avoid divergent encodings
//! across the repo (Canon 2).

pub mod canonical_bytes;

#[cfg(test)]
mod tests;
