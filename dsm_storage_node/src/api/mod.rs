//! # Storage Node API Endpoints
//!
//! All HTTP handler modules for the storage node. Each module exposes
//! protobuf-only endpoints under `/api/v2/`. No JSON, no hex-encoded
//! paths, no wall-clock-dependent logic.

pub mod admin;
pub mod bytecommit;
pub mod device_api;
pub mod discovery;
pub mod dlv_slot;
pub mod drain_proof;
pub mod genesis;
pub mod gossip;
pub mod hardening;
pub mod identity_devtree;
pub mod identity_tips;
pub mod network_config;
pub mod object_list;
pub mod object_store;
pub mod paidk;
pub mod policy;
pub mod rate_limit;
pub mod recovery_capsule;
pub mod registry;
pub mod registry_scaling;
pub mod unilateral_api;
pub mod validators;
