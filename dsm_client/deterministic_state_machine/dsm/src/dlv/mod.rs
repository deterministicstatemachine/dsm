// SPDX-License-Identifier: Apache-2.0

//! Tier 2 Foundation DLV primitives — pure-crypto helpers that the
//! `dsm_sdk` and storage layers compose into the off-device SoFi
//! flow.  This module deliberately holds no proto / I/O / runtime
//! state; each submodule is a self-contained crypto primitive.

pub mod beta_storage_profile; // Rev 15 Req 6.13 five-member beta profile — fixed, not a formula
pub mod controller_rotation;
pub mod pair_identity;
pub mod settlement_receipt_leaf;
pub mod settlement_slot_claim; // write-once claim envelope for the settlement-slot quorum register
pub mod vault_pending_pointer;
pub mod vault_reserve_inclusion;
pub mod vault_reserve_leaf;
pub mod vault_smt_leaf;
pub mod vault_state_anchor;
