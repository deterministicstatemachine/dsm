// SPDX-License-Identifier: MIT OR Apache-2.0

//! Runtime configuration lookups.

/// Runtime configuration lookups, read at the call site.
pub struct RuntimeConfig;

impl RuntimeConfig {
    /// Get the configured Bitcoin network for dBTC key derivation.
    ///
    /// Priority: `DSM_BITCOIN_NETWORK` env var > `bitcoin_network` in TOML > Signet.
    /// Valid values: "mainnet", "testnet", "signet"
    pub fn get_bitcoin_network() -> dsm::bitcoin::types::BitcoinNetwork {
        // 1. Check env var
        if let Ok(net) = std::env::var("DSM_BITCOIN_NETWORK") {
            match dsm::bitcoin::types::BitcoinNetwork::try_from(net.as_str()) {
                Ok(n) => return n,
                Err(_) => {
                    log::warn!("Unknown DSM_BITCOIN_NETWORK '{net}', defaulting to signet");
                }
            }
        }
        // 2. Check TOML config
        if let Ok(env_cfg) = crate::network::NetworkConfigLoader::load_env_config() {
            if let Some(ref net_str) = env_cfg.bitcoin_network {
                match dsm::bitcoin::types::BitcoinNetwork::try_from(net_str.as_str()) {
                    Ok(n) => return n,
                    Err(_) => {
                        log::warn!(
                            "Unknown bitcoin_network '{net_str}' in config, defaulting to signet"
                        );
                    }
                }
            }
        }
        log::warn!("No bitcoin_network configured via env or TOML, defaulting to signet");
        log::error!(
            "SECURITY: bitcoin_network not configured in a production build. \
             Set DSM_BITCOIN_NETWORK env var or bitcoin_network in config TOML. \
             Defaulting to signet is the safe fallback."
        );
        dsm::bitcoin::types::BitcoinNetwork::Signet
    }
}
