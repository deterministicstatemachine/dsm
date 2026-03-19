//! Generated protobuf types for DSM SDK
//!
//! This module contains the protobuf message types for the DSM envelope system.
//! These types are used by the unified protobuf bridge to maintain protocol
//! compliance with the single entry point architecture.

// Include prost-generated code behind a lint-suppressed submodule.
// Generated code can trigger clippy ICEs on certain nightly versions.
#[allow(warnings)]
#[allow(clippy::all)]
mod prost_generated {
    include!(concat!(env!("OUT_DIR"), "/dsm.rs"));
}

pub use prost_generated::*;
