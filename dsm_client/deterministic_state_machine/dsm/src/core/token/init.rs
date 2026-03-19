//! Token Initialization - Default ERA token setup
//!
//! This module provides functionality to initialize the default ERA token
//! when the system starts up. This ensures users always have access
//! to the native token.

use crate::core::token::era_token::{EraTokenManager, NetworkType};
use crate::types::error::DsmError;

/// Default pre-mint amount for mainnet ERA token (1 billion units).
const MAINNET_PRE_MINT: u128 = 1_000_000_000;

/// Initialize the default ERA token for a given network.
///
/// Callers MUST specify the network explicitly. There is no default.
///
/// # Arguments
///
/// * `network` - The network type (Mainnet or Testnet) determining token semantics.
///
/// # Returns
///
/// Returns a configured EraTokenManager instance ready for use.
pub fn initialize_root_token(network: NetworkType) -> Result<EraTokenManager, DsmError> {
    let manager = match network {
        NetworkType::Mainnet => EraTokenManager::new_mainnet(MAINNET_PRE_MINT, "dlv"),
        NetworkType::Testnet => EraTokenManager::new_testnet("dlv"),
    };
    Ok(manager)
}

/// Initialize ERA token and mint initial supply to a device.
///
/// Convenience function that creates the ERA token for a given network
/// and mints an initial balance to a device. Only testnet allows unlimited mint.
///
/// # Arguments
///
/// * `network` - The network type (Mainnet or Testnet) determining token semantics.
/// * `device_id` - The device ID to receive the initial tokens.
/// * `initial_amount` - The amount of tokens to mint initially.
///
/// # Returns
///
/// Returns a configured EraTokenManager with the initial balance minted.
pub fn initialize_root_token_with_balance(
    network: NetworkType,
    device_id: &str,
    initial_amount: u64,
) -> Result<EraTokenManager, DsmError> {
    let mut manager = initialize_root_token(network)?;
    manager.mint(device_id, initial_amount as u128)?;
    Ok(manager)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_initialize_root_token_testnet() -> Result<(), DsmError> {
        let _ = initialize_root_token(NetworkType::Testnet)?;
        Ok(())
    }

    #[test]
    fn test_initialize_root_token_mainnet() -> Result<(), DsmError> {
        let manager = initialize_root_token(NetworkType::Mainnet)?;
        assert_eq!(manager.get_balance("dlv"), MAINNET_PRE_MINT);
        Ok(())
    }

    #[test]
    fn test_initialize_with_balance() -> Result<(), DsmError> {
        let device_id = "device1";
        let initial_amount = 10000;

        let manager =
            initialize_root_token_with_balance(NetworkType::Testnet, device_id, initial_amount)?;

        let balance = manager.get_balance(device_id);
        assert_eq!(balance, initial_amount as u128);
        Ok(())
    }

    #[test]
    fn test_multiple_device_initialization() -> Result<(), DsmError> {
        let mut manager = initialize_root_token(NetworkType::Testnet)?;

        manager.mint("device1", 1000)?;
        manager.mint("device2", 2000)?;
        manager.mint("device3", 3000)?;

        assert_eq!(manager.get_balance("device1"), 1000);
        assert_eq!(manager.get_balance("device2"), 2000);
        assert_eq!(manager.get_balance("device3"), 3000);
        Ok(())
    }
}
