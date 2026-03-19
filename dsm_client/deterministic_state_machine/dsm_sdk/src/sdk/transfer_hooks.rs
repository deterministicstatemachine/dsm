// SPDX-License-Identifier: MIT OR Apache-2.0
//! Bilateral transfer hooks.
//!
//! dBTC transfers move token balance only.
//!
//! Vault discovery and withdrawal route selection happen against storage-node
//! advertisements at withdrawal time. Transfer payloads must not carry vault
//! anchors, preimages, or vault-specific execution material.

/// Metadata returned by the bilateral handler after each phase.
#[derive(Debug, Clone, Default)]
pub struct TransferMeta {
    pub token_id: String,
    pub amount: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferCleanupRole {
    SenderRemove,
    ReceiverActivate,
}

/// dBTC transfers are token-only; no vault material is attached.
pub fn pack_outgoing_anchor(_token_id: &str, _amount: u64) -> Vec<u8> {
    Vec::new()
}

/// dBTC transfers are token-only; inbound transfer data does not mutate vault state.
pub fn ingest_received_anchor(_token_id: &str, _data: &[u8], _amount_sats: u64) {}

/// dBTC transfers do not remove, activate, or otherwise mutate vault mirrors.
pub fn post_transfer_cleanup(_token_id: &str, _role: TransferCleanupRole, _amount: u64) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dbtc_transfer_hooks_are_token_only() {
        assert!(pack_outgoing_anchor("dBTC", 300_000).is_empty());
        ingest_received_anchor("dBTC", b"ignored", 300_000);
        post_transfer_cleanup("dBTC", TransferCleanupRole::SenderRemove, 300_000);
        post_transfer_cleanup("dBTC", TransferCleanupRole::ReceiverActivate, 300_000);
    }
}
