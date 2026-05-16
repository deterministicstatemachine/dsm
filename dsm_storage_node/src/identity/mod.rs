//! Per-node identity material (MPC participation key, etc.).
//!
//! Storage nodes are signature-free at the protocol layer (whitepaper
//! §7 — nodes are dumb mirrors). The keys in this module are NOT used
//! for signing protocol receipts or state transitions. They exist
//! exclusively for the genesis-MPC commit-reveal flow (spec §5),
//! where each contributing node SPHINCS+-signs its own commit and
//! reveal so the root device can verify that the contribution came
//! from the node it offered the session to.

pub mod mpc_key;

pub use mpc_key::{load_or_generate_mpc_key, MpcKeyError, StorageNodeMpcKey};
