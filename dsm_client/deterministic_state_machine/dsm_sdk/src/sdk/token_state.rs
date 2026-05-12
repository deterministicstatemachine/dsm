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
//! into a display-layer [`TransferFields`] plus the canonical ticker
//! normaliser [`canonicalize_token_id`].
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
    pub recipient: Vec<u8>,
    pub to_device_id: Vec<u8>,
}

/// Normalize token ticker to canonical form.
pub fn canonicalize_token_id(token_id: &str) -> String {
    let trimmed = token_id.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    match trimmed.to_ascii_uppercase().as_str() {
        "ERA" => "ERA".to_string(),
        "DBTC" => "dBTC".to_string(),
        _ => trimmed.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::canonicalize_token_id;

    #[test]
    fn canonicalize_token_id_normalizes_era_and_dbtc() {
        assert_eq!(canonicalize_token_id("ERA"), "ERA");
        assert_eq!(canonicalize_token_id("era"), "ERA");
        assert_eq!(canonicalize_token_id("DBTC"), "dBTC");
        assert_eq!(canonicalize_token_id("dbtc"), "dBTC");
        assert_eq!(canonicalize_token_id("dBTC"), "dBTC");
    }

    #[test]
    fn canonicalize_token_id_preserves_unknown_token() {
        assert_eq!(canonicalize_token_id("USDC"), "USDC");
        assert_eq!(canonicalize_token_id("  WBTC  "), "WBTC");
    }

    #[test]
    fn canonicalize_token_id_returns_empty_for_blank_input() {
        assert_eq!(canonicalize_token_id(""), "");
        assert_eq!(canonicalize_token_id("   "), "");
    }
}
