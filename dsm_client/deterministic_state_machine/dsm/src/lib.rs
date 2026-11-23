// SPDX-License-Identifier: MIT OR Apache-2.0

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
//! - [`core`] — the device head and its transition path, the app-router bridge, relationships (lifecycle and write grants), identity, tokens
//! - [`crypto`] — BLAKE3 (domain-separated), SPHINCS+, ML-KEM-768, XChaCha20-Poly1305 and AES-256-GCM, HKDF over BLAKE3, Ed25519 verification of the anchor chip
//! - [`types`] — protocol types: the device head [`types::device_state::DeviceState`], operations, receipts, errors, tokens, offline accounts
//! - [`economic`] — the online economic root `R_econ`, the root register, admission, provenance, the peer step verifier, offline boundaries
//! - [`sofi`] — SoFi v8: wire objects, predicates and resolution
//! - [`shared_lineage`] — shared lineages: discovery without authority
//! - [`vault`], [`dlv`] — Deterministic Limbo Vaults for the Bitcoin tap; vault arithmetic and the owner baseline
//! - [`merkle`] — Sparse Merkle Tree (per-device SMT) and Device Trees
//! - [`emissions`] — DJTE (Deterministic Join-Triggered Emissions), JAP, winner selection
//! - [`bitcoin`] — dBTC tap primitives (HTLC, deep-anchor)
//! - [`bilateral`] — offline steps between contacts, certificate restart
//! - [`commitments`] — the bilateral precommit and the Bitcoin tap's external commit id
//! - [`envelope`] — Envelope v3 protobuf wire format (0x03 framing)
//! - [`recovery`] — recovery cells: tombstones, succession and rollup proofs
//! - [`owned_cell`], [`app_cell`], [`offline_origin`], [`wallet_backup`], [`route_chain`], [`storage_cell`], [`spool`] — storage cells: who may write them, and what a reader recognizes there
//! - [`connect`] — DSM Connect's signed objects
//! - [`verification`] — stitched-receipt verification
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
//! - All secrets use `Zeroize` + `ZeroizeOnDrop` for memory safety
//! - One optional feature, `bitcoin-testnet-bypass`, for development rigs only

pub mod app_cell; // application cells (DSM Amendment A35)
pub mod authored_object; // authored objects (storage spec §5, §7)
pub mod bilateral;
pub mod ccb; // canonical commit bytes
pub mod commitments;
pub mod common;
// offline steps final at their origin cells (DSM Amendment A39)
pub mod offline_origin;
// a wallet's sealed backups on storage nodes (DSM Amendment A40)
pub mod wallet_backup;
// DSM Connect's signed objects (DSM Amendment A11)
pub mod connect;
// keyed-cell arrival records and running hashes (storage spec §14)
pub mod route_chain;
pub mod storage_cell;
pub mod storage_object; // immutable content addressing — addr(N, P) (storage spec §5)
                        // pub mod config; // Network detection moved to SDK - no HTTP in core
pub mod core;
pub mod crypto;
// A separate dead-code attestation module previously lived here
// (Issue #185 — all 4 findings). It exported types with zero
// production callers anywhere in `dsm/` or `dsm_sdk/` (verified by
// source inspection); the audit findings were all on a never-
// executed path. Module removed entirely.
pub mod bitcoin;
pub mod dlv;
pub mod economic; // the online economic root R_econ
pub mod emissions;
pub mod envelope;
pub mod merkle;
pub mod owned_cell; // cells a person pays for are theirs (owner ruling, 2026-11-19)
pub mod pbi;
pub mod prelude;
pub mod recovery;
pub mod shared_lineage; // shared lineages: discovery without authority (DSM A15, SoFi S23)
pub mod sofi; // SoFi v8: wire registry, derivations, predicates and resolution
pub mod spool; // the b0x spool's limits (storage spec §8)
pub mod storage;
pub mod types;
pub mod utils;
pub mod vault;
pub mod verification;

use crate::types::error::DsmError;

const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Returns the version of this crate
///
/// Retrieves the current version of the DSM core crate from cargo package metadata.
///
/// # Returns
///
/// A string containing the version number in semver format (e.g., "0.1.0")
pub fn version() -> String {
    VERSION.to_string()
}
