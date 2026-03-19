//! # DSM SDK Prelude
//!
//! Convenience re-exports for common types used across the SDK crate.
//! Import with `use dsm_sdk::prelude::*` to bring in the core DSM types,
//! `DsmError`, `Arc`, `RwLock`, and `TokioRwLock`.

pub use dsm::*;
pub use dsm::types::error::DsmError;
pub use std::sync::{Arc, RwLock};
pub use tokio::sync::RwLock as TokioRwLock;
