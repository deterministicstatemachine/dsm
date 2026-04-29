//! # Storage Node API Endpoints
//!
//! All HTTP handler modules for the storage node. Each module exposes
//! protobuf-only endpoints under `/api/v2/`. No JSON, no hex-encoded
//! paths, no wall-clock-dependent logic.
//!
//! ## Layout
//!
//! - [`infra`]      — cross-cutting plumbing (admin, hardening, rate-limit, network-config)
//! - [`identity`]   — device & genesis identity (authenticate, device_api, genesis, devtree, tips)
//! - [`objects`]    — raw byte storage (store, list, bytecommit)
//! - [`vault`]      — DLV / policy / recovery / paidk
//! - [`registry`]   — node registry, scaling, discovery, drain-proof
//! - [`transport`]  — message delivery (b0x, gossip)
//! - [`tests`]      — integration test modules

pub mod identity;
pub mod infra;
pub mod objects;
pub mod registry;
pub mod transport;
pub mod vault;

#[cfg(test)]
pub mod tests;
