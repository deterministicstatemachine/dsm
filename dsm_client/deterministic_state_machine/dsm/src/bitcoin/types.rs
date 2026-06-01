// SPDX-License-Identifier: MIT OR Apache-2.0

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

    /// Convert from a u32 wire value (proto encoding) — fail-closed.
    ///
    /// Issue #181 Finding 1 fix: returns `Err` on unknown values. The
    /// previous `from_u32` accepted any non-0/1 value as `Signet`, which
    /// (combined with Finding 2's NON_PAPER_MODE short-circuit) silently
    /// downgraded the bridge to the `WeakenedDevelopment` trust profile on
    /// any corrupted or adversarial network selector. Use this at every
    /// trust boundary (proto decoding, external input).
    pub fn try_from_u32(n: u32) -> Result<Self, DsmError> {
        match n {
            0 => Ok(BitcoinNetwork::Mainnet),
            1 => Ok(BitcoinNetwork::Testnet),
            2 => Ok(BitcoinNetwork::Signet),
            other => Err(DsmError::Validation {
                context: format!(
                    "BitcoinNetwork: unknown wire value {other}; valid: 0=Mainnet, 1=Testnet, 2=Signet"
                ),
                source: None,
            }),
        }
    }

    /// Convert from a u32 wire value, with a SAFE fallback to `Mainnet`.
    ///
    /// Issue #181 Finding 1 fix: unknown values now fall back to `Mainnet`
    /// (the STRICTEST trust profile), not `Signet`. Callers that have a
    /// security-critical decision downstream (e.g. trust-profile selection
    /// in the SPV bridge) MUST use [`try_from_u32`] and handle the `Err`
    /// path explicitly. This wrapper exists only for UI/handler paths
    /// where the `u32` came from a previously-validated internal store.
    pub fn from_u32(n: u32) -> Self {
        Self::try_from_u32(n).unwrap_or(BitcoinNetwork::Mainnet)
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

    // Issue #181 Finding 1 regression — unknown wire values must NOT
    // silently downgrade. `try_from_u32` returns Err; `from_u32` falls
    // back to Mainnet (the STRICTEST profile), never to Signet.
    #[test]
    fn try_from_u32_accepts_only_known_values() {
        assert_eq!(
            BitcoinNetwork::try_from_u32(0).unwrap(),
            BitcoinNetwork::Mainnet
        );
        assert_eq!(
            BitcoinNetwork::try_from_u32(1).unwrap(),
            BitcoinNetwork::Testnet
        );
        assert_eq!(
            BitcoinNetwork::try_from_u32(2).unwrap(),
            BitcoinNetwork::Signet
        );
        for n in [3u32, 4, 5, 99, 1000, u32::MAX] {
            assert!(
                BitcoinNetwork::try_from_u32(n).is_err(),
                "unknown wire value {n} must reject"
            );
        }
    }

    #[test]
    fn from_u32_unknown_falls_back_to_mainnet_not_signet() {
        // Unknown values land in the STRICTEST profile so they can't
        // weaken downstream trust selection (issue #181 Finding 1).
        for n in [3u32, 4, 99, 1000, u32::MAX] {
            assert_eq!(
                BitcoinNetwork::from_u32(n),
                BitcoinNetwork::Mainnet,
                "unknown wire value {n} must fall back to Mainnet, not Signet"
            );
        }
    }
}
