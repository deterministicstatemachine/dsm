// SPDX-License-Identifier: Apache-2.0

//! Tier 2 Foundation DLV primitives — pure-crypto helpers that the
//! `dsm_sdk` and storage layers compose into the off-device SoFi
//! flow.  This module deliberately holds no proto / I/O / runtime
//! state; each submodule is a self-contained crypto primitive.

pub mod beta_storage_profile; // the deployed three-member beta profile — fixed, not a formula
pub mod controller_rotation;
pub mod pair_identity;
pub mod settlement_receipt_leaf;
pub mod settlement_slot_claim; // write-once claim envelope for the settlement-slot quorum register
pub mod vault_pending_pointer;
pub mod vault_reserve_inclusion;
pub mod vault_reserve_leaf;
pub mod vault_smt_leaf;
// vault_state_anchor (V1) and vault_state_anchor_v2 are DELETED by the
// state-identity cut. Their names and domains are burned, never reused; the
// only anchor form is V3 below, whose sole content is c_n.
pub mod vault_state_anchor_v3; // Def 6.4a — owner baseline over c_n; the only anchor form after the cut
