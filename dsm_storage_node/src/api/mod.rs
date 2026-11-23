// SPDX-License-Identifier: MIT OR Apache-2.0

//! # Storage Node API Endpoints
//!
//! Every HTTP handler the node serves, protobuf-only, under `/api/v2/`.
//!
//! - [`backup`]     — each device's one backup slot, written over
//! - [`cells`]      — keyed cells and indexes: bytes in, bytes out
//! - [`objects`]    — the immutable content-addressed store and ByteCommits
//! - [`transport`]  — the b0x inbox spool

pub mod backup;
pub mod cells;
pub mod objects;
pub mod transport;
