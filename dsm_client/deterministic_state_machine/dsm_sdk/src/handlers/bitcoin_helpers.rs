// SPDX-License-Identifier: MIT OR Apache-2.0
//! Shared Bitcoin helper methods for AppRouterImpl.

use dsm::types::proto as generated;

use super::app_router_impl::AppRouterImpl;

const WITHDRAWAL_BRIDGE_SYNC_LIMIT: u32 = 200;
const WITHDRAWAL_BRIDGE_SYNC_MAX_PASSES: usize = 8;

#[cfg(test)]
static WITHDRAWAL_BRIDGE_SYNC_TEST_RESULTS: once_cell::sync::Lazy<
    std::sync::Mutex<std::collections::VecDeque<Result<generated::StorageSyncResponse, String>>>,
> = once_cell::sync::Lazy::new(|| std::sync::Mutex::new(std::collections::VecDeque::new()));

fn is_acknowledgement_only_sync_error(error: &str) -> bool {
    error.starts_with("acknowledge failed for ")
}

fn bridge_sync_blocking_errors(resp: &generated::StorageSyncResponse) -> Vec<&str> {
    resp.errors
        .iter()
        .map(String::as_str)
        .filter(|error| !is_acknowledgement_only_sync_error(error))
        .collect()
}

fn evaluate_bridge_sync_pass(
    route: &str,
    sync_result: Result<generated::StorageSyncResponse, String>,
    limit: u32,
) -> Result<bool, String> {
    let resp = sync_result.map_err(|e| format!("{route}: bridge sync failed: {e}"))?;

    if !resp.success {
        let detail = if resp.errors.is_empty() {
            "no details".to_string()
        } else {
            resp.errors.join("; ")
        };
        return Err(format!("{route}: bridge sync did not succeed: {detail}"));
    }

    let blocking = bridge_sync_blocking_errors(&resp);
    if !blocking.is_empty() {
        return Err(format!(
            "{route}: bridge sync reported blocking errors: {}",
            blocking.join("; ")
        ));
    }

    for warning in resp
        .errors
        .iter()
        .filter(|error| is_acknowledgement_only_sync_error(error))
    {
        log::warn!("[bridge_sync] non-blocking ack warning: {warning}");
    }

    Ok(resp.pulled == limit)
}

#[cfg(test)]
pub(crate) fn set_withdrawal_bridge_sync_test_results(
    results: impl IntoIterator<Item = Result<generated::StorageSyncResponse, String>>,
) {
    let mut guard = WITHDRAWAL_BRIDGE_SYNC_TEST_RESULTS
        .lock()
        .expect("bridge sync test results mutex poisoned");
    guard.clear();
    guard.extend(results);
}

#[cfg(test)]
fn take_withdrawal_bridge_sync_test_result(
) -> Option<Result<generated::StorageSyncResponse, String>> {
    WITHDRAWAL_BRIDGE_SYNC_TEST_RESULTS
        .lock()
        .expect("bridge sync test results mutex poisoned")
        .pop_front()
}

impl AppRouterImpl {
    /// Lazily restore bitcoin_tap vault records + vaults from SQLite on first use.
    /// Safe to call multiple times — OnceCell ensures the work runs only once.
    pub(crate) async fn ensure_bitcoin_tap_restored(&self) {
        self.bitcoin_tap_restored
            .get_or_init(|| async {
                log::warn!("[bitcoin_tap] restore_from_persistence: starting...");
                match self.bitcoin_tap.restore_from_persistence().await {
                    Ok((ops, vaults)) => {
                        log::warn!(
                            "[bitcoin_tap] Restored {} vault records, {} vaults from SQLite",
                            ops,
                            vaults
                        );
                    }
                    Err(e) => {
                        log::error!("[bitcoin_tap] Failed to restore persistence: {e}");
                    }
                }
            })
            .await;
    }

    /// Format inbox-related errors into a concise, actionable message for the UI.
    pub(crate) fn format_inbox_error(&self, e: &crate::types::error::DsmError) -> String {
        use crate::types::error::DsmError;
        if let DsmError::InboxTokenInvalid(msg) = e {
            format!("Inbox token invalid: {msg}. This device's inbox is bound to its genesis and cannot be re-registered. Please re-bind the device or contact support.")
        } else {
            format!("inbox.pull: retrieve failed: {e}")
        }
    }

    pub(crate) async fn ensure_withdrawal_bridge_sync(&self, route: &str) -> Result<(), String> {
        for _ in 0..WITHDRAWAL_BRIDGE_SYNC_MAX_PASSES {
            #[cfg(test)]
            let sync_result = if let Some(result) = take_withdrawal_bridge_sync_test_result() {
                result
            } else {
                self.run_storage_sync_request(generated::StorageSyncRequest {
                    pull_inbox: true,
                    push_pending: true,
                    limit: WITHDRAWAL_BRIDGE_SYNC_LIMIT,
                })
                .await
            };

            #[cfg(not(test))]
            let sync_result = self
                .run_storage_sync_request(generated::StorageSyncRequest {
                    pull_inbox: true,
                    push_pending: true,
                    limit: WITHDRAWAL_BRIDGE_SYNC_LIMIT,
                })
                .await;

            let should_continue =
                evaluate_bridge_sync_pass(route, sync_result, WITHDRAWAL_BRIDGE_SYNC_LIMIT)?;

            if !should_continue {
                return Ok(());
            }
        }

        Err(format!(
            "{route}: bridge sync did not quiesce after {} passes",
            WITHDRAWAL_BRIDGE_SYNC_MAX_PASSES
        ))
    }

    pub(crate) fn bitcoin_network_from_u32(network: u32) -> dsm::bitcoin::types::BitcoinNetwork {
        dsm::bitcoin::types::BitcoinNetwork::from_u32(network)
    }

    pub(crate) fn bitcoin_account_id(import_kind: &str, secret: &str, network: u32) -> String {
        let mut data = Vec::new();
        data.extend_from_slice(import_kind.as_bytes());
        data.extend_from_slice(&network.to_le_bytes());
        data.extend_from_slice(secret.as_bytes());
        let hash = dsm::crypto::blake3::domain_hash_bytes("DSM/bitcoin-account-id", &data);
        let v = &hash[..8];
        format!(
            "btcacct-{}",
            u64::from_le_bytes(v.try_into().unwrap_or([0u8; 8]))
        )
    }

    pub(crate) fn keystore_from_import(
        import_kind: &str,
        secret: &str,
        network: dsm::bitcoin::types::BitcoinNetwork,
    ) -> Result<crate::sdk::bitcoin_key_store::BitcoinKeyStore, String> {
        match import_kind {
            "mnemonic" => {
                crate::sdk::bitcoin_key_store::BitcoinKeyStore::from_mnemonic(secret, network)
                    .map_err(|e| format!("mnemonic import failed: {e}"))
            }
            "xpriv" => {
                crate::sdk::bitcoin_key_store::BitcoinKeyStore::from_xpriv_str(secret, network)
                    .map_err(|e| format!("xpriv import failed: {e}"))
            }
            "wif" => Err(
                "wif import is not yet supported for HTLC signing path (xpriv/mnemonic supported)"
                    .to_string(),
            ),
            _ => Err(format!("unsupported import kind: {import_kind}")),
        }
    }

    pub(crate) fn first_address_for_import(
        import_kind: &str,
        secret: &str,
        network: dsm::bitcoin::types::BitcoinNetwork,
    ) -> Result<String, String> {
        if import_kind == "wif" {
            let pk =
                bitcoin::PrivateKey::from_wif(secret).map_err(|e| format!("invalid WIF: {e}"))?;
            let secp = bitcoin::secp256k1::Secp256k1::new();
            let pubkey = pk.public_key(&secp);
            let cpk = bitcoin::key::CompressedPublicKey::try_from(pubkey)
                .map_err(|e| format!("WIF key must be compressed for P2WPKH: {e}"))?;
            let addr = bitcoin::Address::p2wpkh(&cpk, network.to_bitcoin_network());
            return Ok(addr.to_string());
        }

        let ks = Self::keystore_from_import(import_kind, secret, network)?;
        let (addr, _pk) = ks
            .peek_receive_address(0)
            .map_err(|e| format!("failed to derive first address: {e}"))?;
        Ok(addr)
    }

    pub(crate) fn wif_address_and_pubkey(
        secret: &str,
        network: dsm::bitcoin::types::BitcoinNetwork,
    ) -> Result<(String, [u8; 33]), String> {
        let pk = bitcoin::PrivateKey::from_wif(secret).map_err(|e| format!("invalid WIF: {e}"))?;
        let secp = bitcoin::secp256k1::Secp256k1::new();
        let pubkey = pk.public_key(&secp);
        let cpk = bitcoin::key::CompressedPublicKey::try_from(pubkey)
            .map_err(|e| format!("WIF key must be compressed for P2WPKH: {e}"))?;
        let addr = bitcoin::Address::p2wpkh(&cpk, network.to_bitcoin_network()).to_string();
        Ok((addr, cpk.to_bytes()))
    }

    /// Broadcast a raw Bitcoin transaction through the configured mempool backend.
    /// Returns the txid in internal byte order.
    pub(crate) async fn broadcast_raw_tx(
        &self,
        raw_tx: &[u8],
        network: dsm::bitcoin::types::BitcoinNetwork,
    ) -> Result<[u8; 32], String> {
        let mempool = super::mempool_api::MempoolClient::from_config_for_network(network)
            .map_err(|e| format!("mempool client init: {e}"))?;
        let txid_hex = mempool
            .broadcast_tx_raw(raw_tx)
            .await
            .map_err(|e| format!("broadcast tx failed: {e}"))?;

        let txid_display = super::mempool_api::hex_to_bytes(&txid_hex)
            .map_err(|e| format!("invalid txid hex: {e}"))?;
        if txid_display.len() != 32 {
            return Err(format!("txid length {} != 32", txid_display.len()));
        }

        let mut txid = [0u8; 32];
        txid.copy_from_slice(&txid_display);
        txid.reverse();
        Ok(txid)
    }

    /// Query transaction confirmation state through the configured mempool backend.
    /// Returns `(confirmations, in_mempool)`.
    pub(crate) async fn query_tx_status(
        &self,
        txid_internal: &[u8; 32],
        network: dsm::bitcoin::types::BitcoinNetwork,
    ) -> Result<(u32, bool), String> {
        let mempool = super::mempool_api::MempoolClient::from_config_for_network(network)
            .map_err(|e| format!("mempool client init: {e}"))?;

        let mut display = *txid_internal;
        display.reverse();
        let txid_hex = super::mempool_api::bytes_to_hex(&display);
        let status = mempool.tx_status(&txid_hex).await?;

        if !status.confirmed {
            return Ok((0, true));
        }

        let confirmations = if let Some(block_height) = status.block_height {
            match mempool.chain_tip_height().await {
                Ok(tip) => tip.saturating_sub(block_height) + 1,
                Err(_) => 1,
            }
        } else {
            1
        };

        Ok((confirmations as u32, false))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    use serial_test::serial;

    use crate::init::SdkConfig;

    fn sync_response(
        success: bool,
        pulled: u32,
        errors: &[&str],
    ) -> generated::StorageSyncResponse {
        generated::StorageSyncResponse {
            success,
            pulled,
            processed: pulled,
            pushed: 0,
            errors: errors.iter().map(|s| s.to_string()).collect(),
        }
    }

    fn init_bridge_sync_test_router(test_name: &str) -> AppRouterImpl {
        unsafe {
            std::env::set_var("DSM_SDK_TEST_MODE", "1");
            std::env::remove_var("DSM_ENV_CONFIG_PATH");
        }
        crate::storage::client_db::reset_database_for_tests();
        let _ = crate::storage_utils::set_storage_base_dir(PathBuf::from(format!(
            "./.dsm_testdata_{test_name}"
        )));
        crate::sdk::app_state::AppState::set_identity_info(
            vec![0x21; 32],
            vec![0x31; 32],
            vec![0x41; 32],
            vec![0x51; 32],
        );
        crate::sdk::app_state::AppState::set_has_identity(true);
        crate::storage::client_db::init_database().expect("init db");
        set_withdrawal_bridge_sync_test_results(Vec::new());

        AppRouterImpl::new(SdkConfig {
            node_id: format!("bridge-sync-{test_name}"),
            storage_endpoints: vec![],
            enable_offline: true,
        })
        .expect("router init")
    }

    #[test]
    fn bridge_sync_fails_on_fatal_storage_error() {
        let err = evaluate_bridge_sync_pass(
            "bitcoin.withdraw.plan",
            Err("fatal failure".to_string()),
            WITHDRAWAL_BRIDGE_SYNC_LIMIT,
        )
        .expect_err("fatal sync failures must block");

        assert!(err.contains("bridge sync failed"));
    }

    #[test]
    fn bridge_sync_fails_when_response_is_unsuccessful() {
        let err = evaluate_bridge_sync_pass(
            "bitcoin.withdraw.plan",
            Ok(sync_response(
                false,
                0,
                &["No storage node config available"],
            )),
            WITHDRAWAL_BRIDGE_SYNC_LIMIT,
        )
        .expect_err("unsuccessful sync responses must block");

        assert!(err.contains("did not succeed"));
    }

    #[test]
    fn bridge_sync_fails_on_non_ack_errors() {
        let err = evaluate_bridge_sync_pass(
            "bitcoin.withdraw.plan",
            Ok(sync_response(
                true,
                0,
                &["inbox pull failed: contact mismatch"],
            )),
            WITHDRAWAL_BRIDGE_SYNC_LIMIT,
        )
        .expect_err("non-ack errors must block");

        assert!(err.contains("blocking errors"));
    }

    #[test]
    fn bridge_sync_allows_ack_only_warnings() {
        let should_continue = evaluate_bridge_sync_pass(
            "bitcoin.withdraw.plan",
            Ok(sync_response(
                true,
                0,
                &["acknowledge failed for inbox-1: transient network error"],
            )),
            WITHDRAWAL_BRIDGE_SYNC_LIMIT,
        )
        .expect("ack-only warnings should not block");

        assert!(!should_continue);
    }

    #[test]
    fn bridge_sync_continues_while_page_is_full() {
        let should_continue = evaluate_bridge_sync_pass(
            "bitcoin.withdraw.plan",
            Ok(sync_response(true, WITHDRAWAL_BRIDGE_SYNC_LIMIT, &[])),
            WITHDRAWAL_BRIDGE_SYNC_LIMIT,
        )
        .expect("full pages should keep syncing");

        assert!(should_continue);
    }

    #[tokio::test]
    #[serial]
    async fn ensure_withdrawal_bridge_sync_runs_until_inbox_drained() {
        let router = init_bridge_sync_test_router("bridge_sync_drains_pages");
        set_withdrawal_bridge_sync_test_results(vec![
            Ok(sync_response(true, WITHDRAWAL_BRIDGE_SYNC_LIMIT, &[])),
            Ok(sync_response(true, 17, &[])),
        ]);

        router
            .ensure_withdrawal_bridge_sync("bitcoin.withdraw.plan")
            .await
            .expect("sync should continue until pulled count falls below the limit");
    }

    #[tokio::test]
    #[serial]
    async fn ensure_withdrawal_bridge_sync_fails_when_inbox_never_quiesces() {
        let router = init_bridge_sync_test_router("bridge_sync_quiesce_cap");
        set_withdrawal_bridge_sync_test_results(
            (0..WITHDRAWAL_BRIDGE_SYNC_MAX_PASSES)
                .map(|_| Ok(sync_response(true, WITHDRAWAL_BRIDGE_SYNC_LIMIT, &[]))),
        );

        let err = router
            .ensure_withdrawal_bridge_sync("bitcoin.withdraw.plan")
            .await
            .expect_err("sync should fail after exhausting the pass cap");

        assert!(err.contains("did not quiesce"));
    }
}
