// SPDX-License-Identifier: MIT OR Apache-2.0
//! What a bilateral step moved, reported by the offline protocol's handler.

/// The token and amount a bilateral step moved; empty for a step that moved
/// no value.
#[derive(Debug, Clone, Default)]
pub struct TransferMeta {
    pub token_id: String,
    pub amount: u64,
}
