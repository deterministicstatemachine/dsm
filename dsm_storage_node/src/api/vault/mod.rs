// SPDX-License-Identifier: MIT OR Apache-2.0

//! Vault-shaped artifacts: DLV slots, token policies (CTPA),
//! recovery capsules, and the PaidK spend-gate.

pub mod paidk;
pub mod policy;
pub mod recovery;
pub mod settlement_slot; // one-shot quorum register for vault parents
pub mod slot;
