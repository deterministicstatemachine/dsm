// SPDX-License-Identifier: Apache-2.0

//! Tier 2 Foundation DLV primitives — pure-crypto helpers that the
//! `dsm_sdk` and storage layers compose into the off-device SoFi
//! flow.  This module deliberately holds no proto / I/O / runtime
//! state; each submodule is a self-contained crypto primitive.

pub mod vault_state_anchor;
