//! DSM Core Prelude - Minimal, Protocol-Compliant Imports
//!
//! DSM is a non-Turing complete system focused on forward-only hash chains
//! and quantum-resistant cryptography. Only essential types are re-exported.

// Core std types for hash chains and bilateral state management
pub use std::collections::HashMap;
pub use std::sync::{Arc, RwLock, Mutex};

// DSM core types
pub use crate::types::error::DsmError;

// Core cryptographic primitives (DSM protocol required)
pub use blake3;
