//! Protocol Buffer Types
//!
//! This module includes the generated protobuf types from the build script.
//! The types are generated from the dsm_app.proto file.

// Include the generated protobuf code
include!(concat!(env!("OUT_DIR"), "/dsm.rs"));

// Re-export common items for convenience
pub use prost::Message;

// Type aliases for easier access
pub type DsmEnvelope = Envelope;
// Re-export the crate-wide error type for convenience
pub use crate::types::error::DsmError;
