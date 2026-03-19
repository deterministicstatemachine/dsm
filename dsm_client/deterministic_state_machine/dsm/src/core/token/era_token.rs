//! ERA Token Manager
//!
//! Mainnet: Pre-minted, capped, no mint after genesis.
//! Testnet: Unlimited supply, DLV can always mint, no scarcity.

use std::collections::HashMap;
use crate::types::error::DsmError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkType {
    Mainnet,
    Testnet,
}

pub struct EraTokenManager {
    balances: HashMap<String, u128>,
    total_supply: u128,
    network: NetworkType,
    dlv_account: String,
}

impl EraTokenManager {
    pub fn new_mainnet(pre_mint_amount: u128, dlv_account: &str) -> Self {
        let mut balances = HashMap::new();
        balances.insert(dlv_account.to_string(), pre_mint_amount);
        EraTokenManager {
            balances,
            total_supply: pre_mint_amount,
            network: NetworkType::Mainnet,
            dlv_account: dlv_account.to_string(),
        }
    }

    pub fn new_testnet(dlv_account: &str) -> Self {
        let mut balances = HashMap::new();
        // Start with a large amount, but mint is always allowed
        let initial = 1_000_000_000_000_000u128;
        balances.insert(dlv_account.to_string(), initial);
        EraTokenManager {
            balances,
            total_supply: initial,
            network: NetworkType::Testnet,
            dlv_account: dlv_account.to_string(),
        }
    }

    pub fn transfer(&mut self, from: &str, to: &str, amount: u128) -> Result<(), DsmError> {
        let bal = self.balances.get(from).cloned().unwrap_or(0);
        if bal < amount {
            return Err(DsmError::InsufficientBalance {
                token_id: "ERA".to_string(),
                available: bal as u64,
                requested: amount as u64,
            });
        }
        *self.balances.entry(from.to_string()).or_insert(0) -= amount;
        *self.balances.entry(to.to_string()).or_insert(0) += amount;
        Ok(())
    }

    /// Minting disabled on mainnet. Unlimited on testnet.
    pub fn mint(&mut self, to: &str, amount: u128) -> Result<(), DsmError> {
        match self.network {
            NetworkType::Mainnet => Err(DsmError::MintNotAllowed),
            NetworkType::Testnet => {
                *self.balances.entry(to.to_string()).or_insert(0) += amount;
                self.total_supply += amount;
                Ok(())
            }
        }
    }

    /// Burning disabled on mainnet. Allowed on testnet.
    pub fn burn(&mut self, from: &str, amount: u128) -> Result<(), DsmError> {
        match self.network {
            NetworkType::Mainnet => Err(DsmError::BurnNotAllowed),
            NetworkType::Testnet => {
                let bal = self.balances.get(from).cloned().unwrap_or(0);
                if bal < amount {
                    return Err(DsmError::InsufficientBalance {
                        token_id: "ERA".to_string(),
                        available: bal as u64,
                        requested: amount as u64,
                    });
                }
                *self.balances.entry(from.to_string()).or_insert(0) -= amount;
                self.total_supply -= amount;
                Ok(())
            }
        }
    }

    /// For testnet, always allow drops everywhere, abundance is guaranteed.
    pub fn drop_everywhere(&mut self, accounts: &[String], amount: u128) -> Result<(), DsmError> {
        match self.network {
            NetworkType::Mainnet => Err(DsmError::MintNotAllowed),
            NetworkType::Testnet => {
                for account in accounts {
                    self.mint(account, amount)?;
                }
                Ok(())
            }
        }
    }

    pub fn get_balance(&self, account: &str) -> u128 {
        self.balances.get(account).cloned().unwrap_or(0)
    }

    pub fn total_supply(&self) -> u128 {
        self.total_supply
    }

    pub fn network_type(&self) -> NetworkType {
        self.network
    }

    pub fn dlv_account(&self) -> &str {
        &self.dlv_account
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mainnet_no_mint() {
        let mut manager = EraTokenManager::new_mainnet(1_000_000, "dlv");
        assert!(manager.mint("user1", 100).is_err());
    }

    #[test]
    fn test_testnet_unlimited_mint() {
        let mut manager = EraTokenManager::new_testnet("dlv");
        assert!(manager.mint("user1", 1_000_000_000).is_ok());
        assert_eq!(manager.get_balance("user1"), 1_000_000_000);
    }

    #[test]
    fn test_transfer() {
        let mut manager = EraTokenManager::new_testnet("dlv");
        manager.transfer("dlv", "user1", 100).unwrap();
        assert_eq!(manager.get_balance("user1"), 100);
    }

    #[test]
    fn test_insufficient_balance() {
        let mut manager = EraTokenManager::new_testnet("dlv");
        assert!(manager.transfer("user1", "user2", 100).is_err());
    }

    #[test]
    fn test_drop_everywhere_mainnet_fails() {
        let mut manager = EraTokenManager::new_mainnet(1_000_000, "dlv");
        let accounts = vec!["user1".to_string(), "user2".to_string()];
        assert!(manager.drop_everywhere(&accounts, 50).is_err());
    }

    #[test]
    fn test_drop_everywhere_testnet_succeeds() {
        let mut manager = EraTokenManager::new_testnet("dlv");
        let accounts = vec!["user1".to_string(), "user2".to_string()];
        assert!(manager.drop_everywhere(&accounts, 50).is_ok());
        assert_eq!(manager.get_balance("user1"), 50);
        assert_eq!(manager.get_balance("user2"), 50);
    }
}
