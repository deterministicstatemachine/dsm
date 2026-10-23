// SPDX-License-Identifier: MIT OR Apache-2.0

//! Transport-layer shared helpers for extracting transfer metadata.
//!
//! # Whitepaper alignment (post-§2.2 / §4.2 / §8 refactor)
//!
//! Token balance arithmetic lives in the canonical [`DeviceState`]
//! (`dsm::types::device_state::DeviceState`) at the `execute_on_relationship`
//! chokepoint. This module no longer owns any balance-mutation logic — the
//! device head is the single authoritative scalar per §8, updated atomically
//! via the pure [`DeviceState::advance`] return value and an in-memory CAS
//! swap.
//!
//! What remains here is purely metadata extraction used by both bilateral BLE
//! settlement and online Transfer paths: parsing `Operation::Transfer` bytes
//! into a display-layer [`TransferFields`]. The ticker normaliser is
//! `handlers::wallet_routes::canonicalize_token_id`.
//!
//! All legacy `apply_transfer_*` helpers and their associated balance-map
//! mutation code were removed as part of the Phase 4.1 BCR storage / device
//! state alignment; the only remaining balance-mutation path is
//! [`dsm::types::device_state::DeviceState::advance`] with
//! [`BalanceDelta`](dsm::types::device_state::BalanceDelta) inputs.

/// Transfer operation fields extracted from `Operation::Transfer`.
#[derive(Debug, Clone)]
pub struct TransferFields {
    pub amount: u64,
    pub token_id: String,
    pub to_device_id: Vec<u8>,
}
