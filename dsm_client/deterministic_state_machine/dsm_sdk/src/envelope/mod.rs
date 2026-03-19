//! # Envelope Construction and Encoding
//!
//! Protobuf-only on-wire encoding for Envelope v3. Provides canonical
//! serialization and transport framing helpers.

pub mod transport;

pub use transport::*;
