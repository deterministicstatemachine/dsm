#![forbid(unsafe_code)]
// Keep critical compiler lints strict, but do not blanket-deny all warnings or clippy groups here.
// This allows the workspace-level [lints] configuration to control clippy behavior (e.g., treating
// documentation lints as warnings instead of errors).
#![deny(unused_must_use)]
#![warn(unused_imports)]
// Allow disallowed_methods in this crate because tracing macros expand to internal
// Option::expect/unwrap calls that trip the lint at call sites. We still avoid unwrap/expect
// in our own code; SDK enforces the strict lint without this allow.
#![allow(clippy::disallowed_methods)]
// Intentionally avoid `clippy::all`/`clippy::pedantic` here; managed via workspace lints.

//! # DSM Core Crate
//!
//! Pure core business logic for the Deterministic State Machine (DSM) protocol.
//! This crate contains all protocol logic, cryptographic primitives, state machine
//! transitions, and type definitions. It is deliberately I/O-free: no network calls,
//! no filesystem access, no OS time, and no global mutable state.
//!
//! ## Architecture
//!
//! The core crate sits at the bottom of the dependency stack:
//!
//! ```text
//! UI / WebView
//!   → Kotlin Bridge
//!     → JNI (dsm_sdk)
//!       → Core (this crate)
//! ```
//!
//! All I/O, platform integration, and JNI bridging live in the `dsm_sdk` crate.
//! The core crate communicates with the outside world only through trait-based
//! storage interfaces and pure function return values.
//!
//! ## Module Organization
//!
//! - [`core`] — State machine, bridge traits, bilateral management, identity, token subsystem
//! - [`crypto`] — BLAKE3 (domain-separated), SPHINCS+, ML-KEM-768, Pedersen, DBRW, ChaCha20-Poly1305
//! - [`types`] — All protocol types: [`types::state_types::State`], [`types::error::DsmError`], identifiers, tokens
//! - [`vault`] — Deterministic Limbo Vaults (DLV), asset management, fulfillment
//! - [`merkle`] — Sparse Merkle Tree (per-device SMT) and Device Trees
//! - [`emissions`] — DJTE (Deterministic Join-Triggered Emissions), JAP, winner selection
//! - [`cpta`] — Content-Addressed Token Policy Anchors
//! - [`bitcoin`] — dBTC tap primitives (HTLC, deep-anchor)
//! - [`bilateral`] — Bilateral transaction types and protocol definitions
//! - [`commitments`] — Deterministic, smart, and external commitments
//! - [`envelope`] — Envelope v3 protobuf wire format (0x03 framing)
//! - [`recovery`] — Recovery capsules, tombstones, and rollup proofs
//! - [`serialization`] — Protobuf serialization utilities
//! - [`verification`] — Chain verification and integrity checking
//!
//! ## Hard Invariants
//!
//! - **Envelope v3 only** — sole wire container, 0x03 framing byte prefix
//! - **No JSON** — protobuf-only transport; `serde_json` is banned in protocol paths
//! - **No hex in protocol** — raw bytes internally, Base32 Crockford at string boundaries
//! - **No wall-clock time** — all ordering uses logical ticks from hash chain adjacency
//! - **BLAKE3 domain separation** — all hashing uses `BLAKE3-256("DSM/<domain>\0" || data)`
//! - **Tripwire fork-exclusion** — no two valid successors from the same parent tip
//! - **Token conservation** — `B_{n+1} = B_n + Delta, B >= 0`
//!
//! ## Security Policy
//!
//! - `#![forbid(unsafe_code)]` — no unsafe Rust anywhere in this crate
//! - MPC genesis requires ≥3 storage nodes with threshold ≥3
//! - All secrets use `Zeroize` + `ZeroizeOnDrop` for memory safety
//! - Feature-gated optional modules (perf, telemetry, bluetooth)

pub mod batching;
pub mod bilateral;
pub mod commitments;
pub mod common;
// pub mod config; // Network detection moved to SDK - no HTTP in core
pub mod core;
pub mod cpta;
pub mod crypto;
pub mod crypto_verification;
pub mod emissions;
pub mod envelope;
pub mod limits;
pub mod merkle;
pub mod pbi;
pub mod spend_gate;
// #[cfg(feature = "perf")]
pub mod bitcoin;
pub mod performance;
pub mod prelude;
pub mod recovery;
pub mod serialization;
pub mod storage;
pub mod telemetry;
pub mod types;
pub mod utils;
pub mod vault;
pub mod verification;

use crate::core::identity;
use crate::types::error::DsmError;
use crate::types::state_types::State;

pub use crate::core::identity::TrustlessGenesisArtifacts;

/// Returns the version of the SDK
///
/// Retrieves the current version of the DSM SDK from cargo package metadata.
///
/// # Returns
///
/// A string containing the version number in semver format (e.g., "0.1.0")
pub fn version() -> String {
    std::env::var("CARGO_PKG_VERSION").unwrap_or_else(|_| "unknown".to_string())
}

/// Build information for debugging and support
pub fn build_info() -> BuildInfo {
    BuildInfo {
        version: std::env::var("CARGO_PKG_VERSION").unwrap_or_else(|_| "unknown".to_string()),
        rust_version: std::env::var("RUSTC_VERSION").unwrap_or_else(|_| "unknown".to_string()),
        target: std::env::var("TARGET").unwrap_or_else(|_| "unknown".to_string()),
        features: get_enabled_features(),
    }
}

/// Build information structure
#[derive(Debug, Clone)]
pub struct BuildInfo {
    /// SDK version
    pub version: String,
    /// Rust compiler version
    pub rust_version: String,
    /// Target architecture
    pub target: String,
    /// Enabled features
    pub features: Vec<String>,
}

#[allow(unused_mut)]
#[allow(clippy::vec_init_then_push)]
fn get_enabled_features() -> Vec<String> {
    let mut features = vec![];
    // JNI moved to dsm_sdk
    #[cfg(feature = "bluetooth")]
    features.push("bluetooth".to_string());
    #[cfg(feature = "storage")]
    features.push("storage".to_string());
    #[cfg(feature = "threadsafe")]
    features.push("threadsafe".to_string());
    features
}

/// Expose core trustless genesis creation to SDK consumers.
pub async fn create_trustless_genesis<
    S: crate::core::identity::genesis_mpc::GenesisStorage + Sync + Send,
>(
    device_id: String,
    storage_nodes: Vec<crate::types::identifiers::NodeId>,
    threshold: usize,
    metadata: Option<String>,
    storage: Option<&S>,
) -> Result<TrustlessGenesisArtifacts, DsmError> {
    identity::create_trustless_genesis(device_id, storage_nodes, threshold, metadata, storage)
        .await
        .map_err(DsmError::from)
}

/// Verify that a sequence of states maintains a valid hash chain from the supplied genesis.
pub fn verify_trustless_identity(
    genesis: &identity::GenesisState,
    chain: &[State],
) -> Result<(), DsmError> {
    identity::verify_trustless_identity(genesis, chain).map_err(DsmError::from)
}
