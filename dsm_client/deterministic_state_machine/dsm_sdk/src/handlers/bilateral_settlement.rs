//! Default settlement delegate for bilateral BLE transfers.
//!
//! This module lives in the **application layer** and implements the
//! [`BilateralSettlementDelegate`] trait defined in the transport-layer
//! [`bluetooth`](crate::bluetooth) module.  All token- and balance-specific
//! logic (balance debits/credits, transaction history, wallet cache sync) is
//! concentrated here so that the BLE transport layer remains coin-agnostic.

use crate::bluetooth::bilateral_ble_handler::{BilateralSettlementContext, BilateralSettlementDelegate};
use crate::sdk::transfer_hooks::TransferMeta;
use crate::util::text_id::encode_base32_crockford;
use dsm::types::operations::Operation;
use log::{warn, error};

fn canonicalize_token_id(token_id: &str) -> String {
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

/// Parse `(amount, token_id)` from raw operation bytes.
///
/// Returns `(0, None)` for non-Transfer operations or parse failures.
fn parse_transfer_fields(operation_bytes: &[u8]) -> (u64, Option<String>) {
    match Operation::from_bytes(operation_bytes) {
        Ok(Operation::Transfer {
            amount, token_id, ..
        }) => {
            let amount_u64 = amount.available();
            let token_str = canonicalize_token_id(&String::from_utf8_lossy(&token_id));
            let token_opt = if token_str.is_empty() {
                None
            } else {
                Some(token_str)
            };
            (amount_u64, token_opt)
        }
        _ => (0, None),
    }
}

/// Application-layer implementation of [`BilateralSettlementDelegate`].
///
/// Installed on [`BilateralBleHandler`](crate::bluetooth::BilateralBleHandler)
/// during SDK initialisation (see [`BluetoothManager::new`](crate::bluetooth::BluetoothManager::new)).
/// Handles balance debit/credit and transaction-history persistence once the
/// cryptographic BLE protocol has successfully completed.
pub struct DefaultBilateralSettlementDelegate;

impl BilateralSettlementDelegate for DefaultBilateralSettlementDelegate {
    /// Extract event-display metadata (amount, token_id) from serialised
    /// operation bytes without applying any wallet state changes.
    fn operation_metadata(&self, operation_bytes: &[u8]) -> (Option<u64>, Option<String>) {
        let (amount, token_opt) = parse_transfer_fields(operation_bytes);
        let amount_opt = if amount > 0 { Some(amount) } else { None };
        (amount_opt, token_opt)
    }

    /// Apply token-specific settlement: balance update + transaction history.
    ///
    /// Called by the transport layer after the 3-phase BLE protocol completes.
    /// Returns [`TransferMeta`] (token_id + amount) for upstream hooks, or an
    /// error message string if persistence fails.
    fn settle(&self, ctx: BilateralSettlementContext) -> Result<TransferMeta, String> {
        let (transfer_amount, token_id_opt) = parse_transfer_fields(&ctx.operation_bytes);
        let token_id_str = token_id_opt.clone().unwrap_or_default();

        let local_txt = encode_base32_crockford(&ctx.local_device_id);
        let counterparty_txt = encode_base32_crockford(&ctx.counterparty_device_id);
        let (from_txt, to_txt) = if ctx.is_sender {
            (local_txt.clone(), counterparty_txt.clone())
        } else {
            (counterparty_txt.clone(), local_txt.clone())
        };

        let tx_record = crate::storage::client_db::TransactionRecord {
            tx_id: encode_base32_crockford(&ctx.commitment_hash),
            tx_hash: encode_base32_crockford(&ctx.transaction_hash),
            from_device: from_txt,
            to_device: to_txt,
            amount: transfer_amount,
            tx_type: ctx.tx_type.to_string(),
            status: "completed".to_string(),
            chain_height: ctx.chain_height,
            step_index: crate::util::deterministic_time::tick(),
            commitment_hash: Some(encode_base32_crockford(&ctx.commitment_hash).into_bytes()),
            proof_data: ctx.proof_data,
            metadata: {
                let mut m = std::collections::HashMap::new();
                if !token_id_str.is_empty() {
                    m.insert("token_id".to_string(), token_id_str.as_bytes().to_vec());
                }
                m
            },
            created_at: 0,
        };

        // `token_for_atomic` is `None` for the native ERA token (identified by an
        // empty token_id string) and `Some(token_id)` for every other token.
        let token_for_atomic: Option<&str> = if token_id_str.is_empty() {
            None
        } else {
            Some(token_id_str.as_str())
        };

        if ctx.is_sender {
            if transfer_amount > 0 {
                let debit_result =
                    crate::storage::client_db::apply_sender_settlement_and_store_transaction_atomic(
                        &local_txt,
                        token_for_atomic,
                        transfer_amount,
                        &tx_record,
                    );

                if let Err(e) = &debit_result {
                    error!(
                        "[BilateralSettlement] sender settlement persistence failed: token={} amount={} error={}",
                        token_id_str,
                        transfer_amount,
                        e
                    );
                    debit_result.map_err(|e| format!("atomic sender settlement failed: {e}"))?;
                }

            } else if let Err(e) = crate::storage::client_db::store_transaction(&tx_record) {
                warn!("[BilateralSettlement] Failed to store zero-amount sender tx history: {e}");
            }
        } else {
            // Receiver: persist chain tip + transaction history atomically.
            let confirm_result =
                crate::storage::client_db::apply_receiver_confirm_and_store_transaction_atomic(
                    &ctx.counterparty_device_id,
                    &ctx.new_chain_tip,
                    &local_txt,
                    token_for_atomic,
                    transfer_amount,
                    &tx_record,
                );

            if let Err(e) = &confirm_result {
                error!(
                    "[BilateralSettlement] receiver settlement persistence failed: token={} amount={} error={}",
                    token_id_str,
                    transfer_amount,
                    e
                );
                confirm_result.map_err(|e| {
                    format!(
                        "atomic receiver confirm failed (device={}, token={:?}, amount={}): {e}",
                        local_txt, token_for_atomic, transfer_amount
                    )
                })?;
            }
        }

        Ok(TransferMeta {
            token_id: token_id_str,
            amount: transfer_amount,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{canonicalize_token_id, parse_transfer_fields};
    use dsm::types::operations::{Operation, TransactionMode, VerificationType};
    use dsm::types::token_types::Balance;

    #[test]
    fn canonicalize_token_id_normalizes_dbtc() {
        assert_eq!(canonicalize_token_id("DBTC"), "dBTC");
        assert_eq!(canonicalize_token_id("dbtc"), "dBTC");
        assert_eq!(canonicalize_token_id("ERA"), "ERA");
    }

    #[test]
    fn parse_transfer_fields_returns_canonical_dbtc() {
        let op = Operation::Transfer {
            to_device_id: vec![0x11; 32],
            amount: Balance::from_state(5, [0u8; 32], 0),
            token_id: b"DBTC".to_vec(),
            mode: TransactionMode::Bilateral,
            nonce: vec![],
            verification: VerificationType::Bilateral,
            pre_commit: None,
            recipient: vec![0x11; 32],
            to: b"recipient".to_vec(),
            message: "memo".to_string(),
            signature: vec![],
        };

        let (amount, token_id) = parse_transfer_fields(&op.to_bytes());
        assert_eq!(amount, 5);
        assert_eq!(token_id.as_deref(), Some("dBTC"));
    }
}
