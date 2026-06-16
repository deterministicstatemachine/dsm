// SPDX-License-Identifier: MIT OR Apache-2.0

//! # DSM Security Module
//!
//! Provides cryptographic security primitives that maintain offline capabilities.
//! All sensitive data is encrypted at rest while preserving full offline transaction
//! creation, validation, and queuing functionality.

pub mod modal_sync_lock;
