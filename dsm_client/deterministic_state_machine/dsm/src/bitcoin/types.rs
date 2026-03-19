//! Bitcoin-specific types for the DSM tap.
//! Minimal wrappers — no wall clocks, no serde, deterministic only.

use crate::types::error::DsmError;

/// Bitcoin network identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BitcoinNetwork {
    Mainnet,
    Testnet,
    Signet,
}

impl BitcoinNetwork {
    /// Address version byte for P2SH
    pub fn p2sh_version(&self) -> u8 {
        match self {
            BitcoinNetwork::Mainnet => 0x05,
            BitcoinNetwork::Testnet | BitcoinNetwork::Signet => 0xC4,
        }
    }

    /// Bech32 human-readable part
    pub fn bech32_hrp(&self) -> &'static str {
        match self {
            BitcoinNetwork::Mainnet => "bc",
            BitcoinNetwork::Testnet => "tb",
            BitcoinNetwork::Signet => "tb",
        }
    }

    /// Convert from a u32 wire value (proto encoding)
    pub fn from_u32(n: u32) -> Self {
        match n {
            0 => BitcoinNetwork::Mainnet,
            1 => BitcoinNetwork::Testnet,
            _ => BitcoinNetwork::Signet, // legacy/unknown non-mainnet values collapse to signet
        }
    }

    /// Convert to a u32 wire value (proto encoding)
    pub fn to_u32(&self) -> u32 {
        match self {
            BitcoinNetwork::Mainnet => 0,
            BitcoinNetwork::Testnet => 1,
            BitcoinNetwork::Signet => 2,
        }
    }

    /// Convert to bitcoin crate Network
    pub fn to_bitcoin_network(&self) -> bitcoin::Network {
        match self {
            BitcoinNetwork::Mainnet => bitcoin::Network::Bitcoin,
            BitcoinNetwork::Testnet => bitcoin::Network::Testnet,
            BitcoinNetwork::Signet => bitcoin::Network::Signet,
        }
    }
}

impl TryFrom<&str> for BitcoinNetwork {
    type Error = DsmError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        match s {
            "mainnet" | "bitcoin" => Ok(BitcoinNetwork::Mainnet),
            "testnet" | "testnet3" => Ok(BitcoinNetwork::Testnet),
            "signet" => Ok(BitcoinNetwork::Signet),
            _ => Err(DsmError::invalid_operation(format!(
                "Unknown Bitcoin network: {s}"
            ))),
        }
    }
}

/// Bitcoin amount in satoshis with overflow protection
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct BtcAmount(u64);

impl BtcAmount {
    /// Maximum possible Bitcoin supply in satoshis (21M BTC)
    pub const MAX_SUPPLY: u64 = 21_000_000 * 100_000_000;

    pub fn from_sat(sats: u64) -> Result<Self, DsmError> {
        if sats > Self::MAX_SUPPLY {
            return Err(DsmError::invalid_operation(format!(
                "Bitcoin amount {sats} sats exceeds max supply"
            )));
        }
        Ok(BtcAmount(sats))
    }

    pub fn as_sat(&self) -> u64 {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn btc_amount_rejects_overflow() {
        assert!(BtcAmount::from_sat(BtcAmount::MAX_SUPPLY).is_ok());
        assert!(BtcAmount::from_sat(BtcAmount::MAX_SUPPLY + 1).is_err());
    }

    #[test]
    fn network_from_str() {
        assert_eq!(
            BitcoinNetwork::try_from("mainnet").unwrap(),
            BitcoinNetwork::Mainnet
        );
        assert_eq!(
            BitcoinNetwork::try_from("testnet").unwrap(),
            BitcoinNetwork::Testnet
        );
        assert!(BitcoinNetwork::try_from("invalid").is_err());
    }
}
