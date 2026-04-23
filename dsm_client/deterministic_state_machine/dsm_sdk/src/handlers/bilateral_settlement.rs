#![allow(unused_variables)]
//! Default settlement delegate for bilateral BLE transfers.
//!
//! This module lives in the **application layer** and implements the
//! [`BilateralSettlementDelegate`] trait defined in the transport-layer
//! [`bluetooth`](crate::bluetooth) module.  All token- and balance-specific
//! logic (balance debits/credits, transaction history, wallet cache sync) is
//! concentrated here so that the BLE transport layer remains coin-agnostic.
//!
//! # Whitepaper alignment (post-§2.2 / §4.2 / §8 refactor)
//!
//! The canonical device head lives in [`dsm::types::device_state::DeviceState`].
//! The BLE bilateral path does NOT route through
//! [`execute_on_relationship`](crate::sdk::core_sdk::CoreSDK::execute_on_relationship)
//! All bilateral advances — online sender, online receiver, BLE sender,
//! BLE receiver — route through the canonical `CoreSDK::execute_on_relationship`
//! chokepoint (`AppRouter::execute_on_relationship_for_bilateral` for the
//! BLE paths). That single chokepoint applies balance deltas to the
//! canonical `DeviceState` head atomically with the SMT leaf update
//! (§8 balance binding). This delegate therefore only materialises the
//! SQLite display-layer projection + transaction-history record — it does
//! NOT mutate `DeviceState.balances` itself.

use crate::bluetooth::bilateral_ble_handler::{
    BilateralSettlementContext, BilateralSettlementDelegate, BilateralSettlementOutcome,
};
use crate::sdk::token_state::{canonicalize_token_id, TransferFields};
use crate::sdk::transfer_hooks::TransferMeta;
use crate::storage::client_db::BalanceProjectionRecord;
use crate::util::text_id::encode_base32_crockford;
use dsm::types::device_state::DeviceState;
use dsm::types::operations::Operation;
use log::{error, warn};

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

fn parse_transfer(operation_bytes: &[u8]) -> Option<TransferFields> {
    match Operation::from_bytes(operation_bytes) {
        Ok(Operation::Transfer {
            amount,
            token_id,
            recipient,
            to_device_id,
            ..
        }) => Some(TransferFields {
            amount: amount.available(),
            token_id: canonicalize_token_id(&String::from_utf8_lossy(&token_id)),
            recipient,
            to_device_id,
        }),
        _ => None,
    }
}

fn resolve_policy_commit(token_id: &str) -> Result<[u8; 32], String> {
    // Builtins (ERA, dBTC) resolve via the constant table.  Custom tokens
    // MUST be resolved through the authoritative TokenPolicySystem +
    // TokenMetadata cache via `TokenSDK::resolve_policy_commit_strict`;
    // the old `dsm.token.<id>` prefs fallback is gone (plan Part E).
    crate::policy::strict_policy_commit_for_token(token_id, None)
        .map_err(|e| format!("resolve policy commit failed for {token_id}: {e}"))
}

/// Build the post-settlement balance projection from the canonical
/// [`DeviceState`] head.
///
/// The canonical advance (`AppRouter::execute_on_relationship_for_bilateral`)
/// has already applied the sender debit / receiver credit to the device
/// head atomically with the SMT update, so this function just mirrors
/// `head.balance(policy_commit)` for both roles.
///
/// Returns `Ok(None)` for transfers that resolve to zero amount or non-transfer
/// operations — the caller still persists the transaction history record.
fn build_settlement_projection(
    ctx: &BilateralSettlementContext,
    head: &DeviceState,
) -> Result<Option<BalanceProjectionRecord>, String> {
    let transfer = match parse_transfer(&ctx.operation_bytes) {
        Some(t) if t.amount > 0 => t,
        _ => return Ok(None),
    };

    let token_for_policy = if transfer.token_id.is_empty() {
        "ERA"
    } else {
        transfer.token_id.as_str()
    };
    let policy_commit = resolve_policy_commit(token_for_policy)?;

    let effective_balance = head.balance(&policy_commit);

    let local_txt = encode_base32_crockford(&ctx.local_device_id);
    let locked = crate::storage::client_db::get_locked_balance(&local_txt, token_for_policy)
        .map_err(|e| format!("read locked balance failed: {e}"))?;

    let projection = crate::storage::client_db::build_balance_projection_from_device_head(
        &local_txt,
        token_for_policy,
        &policy_commit,
        head,
        effective_balance,
        locked,
    )
    .map_err(|e| format!("build balance projection failed: {e}"))?;

    Ok(Some(projection))
}

/// Application-layer implementation of [`BilateralSettlementDelegate`].
///
/// Installed on [`BilateralBleHandler`](crate::bluetooth::BilateralBleHandler)
/// during SDK initialisation (see [`BluetoothManager::new`](crate::bluetooth::BluetoothManager::new)).
/// Handles balance projection sync and transaction-history persistence once the
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

    /// Apply token-specific settlement: balance projection sync + transaction history.
    ///
    /// Called by the transport layer after the 3-phase BLE protocol completes.
    /// Returns [`TransferMeta`] (token_id + amount) for upstream hooks, or an
    /// error message string if persistence fails.
    fn settle(
        &self,
        ctx: BilateralSettlementContext,
    ) -> Result<BilateralSettlementOutcome, String> {
        // §8 Atomicity + Theorem 3: the same accepted transition must not
        // debit or credit twice.  The tx_id is derived from commitment_hash
        // which is identical for both parties.  In production each device has
        // its own DB so collisions are impossible; but in single-process tests
        // both roles share one DB.  Scope the guard to the local device so
        // the sender's completed record does not block the receiver.
        let local_txt = encode_base32_crockford(&ctx.local_device_id);
        let tx_id_candidate = crate::util::text_id::encode_base32_crockford(&ctx.commitment_hash);
        // Sender-only idempotency: prevent double-debit if the sender's
        // settlement is retried.  The receiver side is naturally idempotent
        // via the atomic chain-tip CAS in apply_receiver_confirm_bundle_atomic
        // (the UPDATE contacts SET chain_tip = ?1 WHERE device_id = ?3 only
        // succeeds once for the same tip value).  In production each device
        // has its own DB so a bare tx_id check suffices for senders.
        if ctx.is_sender
            && crate::storage::client_db::is_sender_settlement_completed(
                &tx_id_candidate,
                &local_txt,
            )
        {
            log::warn!(
                "[BILATERAL][settle] Idempotency guard: sender settlement already completed for {}",
                tx_id_candidate,
            );
            return Ok(BilateralSettlementOutcome::default());
        }

        let (transfer_amount, token_id_opt) = parse_transfer_fields(&ctx.operation_bytes);
        let token_id_str = token_id_opt.clone().unwrap_or_default();

        // (§2.3.1) Recovery-path settlements are allowed to have None proof_data
        // (BLE GATT failure scenario where receipt delivery failed).
        // Sender must always have proof_data (receipt from its own SMT-Replace).
        // Receiver receipt is speculative — built for archival, not a settlement
        // precondition.  Blocking receiver settlement on receipt construction
        // silently drops balance + history when AppState is not yet populated.
        let is_recovery = ctx.tx_type == "bilateral_offline_recovered";
        if transfer_amount > 0 && !is_recovery && ctx.is_sender {
            let has_proof = ctx
                .proof_data
                .as_ref()
                .is_some_and(|proof| !proof.is_empty());
            if !has_proof {
                return Err(
                    "missing proof_data for bilateral transfer settlement (strict fail-closed path)"
                        .to_string(),
                );
            }
        }

        // Canonical advance chokepoint is the sole authority for balance
        // mutation across every path (§8 balance binding):
        //  - BLE sender  : `AppRouter::execute_on_relationship_for_bilateral`
        //  - BLE receiver: `AppRouter::execute_on_relationship_for_bilateral`
        //  - Online sender / receiver: `CoreSDK::execute_on_relationship`
        //
        // The settlement delegate only materialises the SQLite display-layer
        // projection + `tx_history` record. It does NOT mutate
        // `DeviceState.balances` — doing so here would be either redundant
        // (canonical head already debited / credited) or a double-apply bug.
        let router = crate::bridge::app_router().ok_or_else(|| {
            "bilateral settle: app router unavailable (not bootstrapped)".to_string()
        })?;

        // Read the now-canonical DeviceState head from the bridge.
        let device_head = router.device_head().ok_or_else(|| {
            "bilateral settle: device head unavailable (router not bootstrapped)".to_string()
        })?;

        log::info!(
            "[BILATERAL][settle] device_head root={} balances={}",
            encode_base32_crockford(&device_head.root()),
            device_head.balances_snapshot().len(),
        );

        let projection = build_settlement_projection(&ctx, &device_head)?;

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
            chain_height: 0,
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
                let bundle_result =
                    crate::storage::client_db::apply_bilateral_settlement_bundle_atomic(
                        crate::storage::client_db::BilateralSenderSettlementBundle {
                            counterparty_device_id: &ctx.counterparty_device_id,
                            new_chain_tip: &ctx.new_chain_tip,
                            sender_device_id: &local_txt,
                            token_id: token_for_atomic,
                            amount: transfer_amount,
                            tx: &tx_record,
                            projection: projection.as_ref(),
                        },
                    );

                if let Err(e) = &bundle_result {
                    error!(
                        "[BilateralSettlement] sender settlement persistence failed: token={} amount={} error={}",
                        token_id_str, transfer_amount, e
                    );
                    bundle_result.map_err(|e| format!("atomic sender settlement failed: {e}"))?;
                }
            } else if let Err(e) = crate::storage::client_db::store_transaction(&tx_record) {
                warn!("[BilateralSettlement] Failed to store zero-amount sender tx history: {e}");
            }
        } else {
            // Receiver: persist chain tip + transaction history atomically.
            let confirm_result = crate::storage::client_db::apply_receiver_confirm_bundle_atomic(
                crate::storage::client_db::ReceiverConfirmBundle {
                    counterparty_device_id: &ctx.counterparty_device_id,
                    new_chain_tip: &ctx.new_chain_tip,
                    receiver_device_id: &local_txt,
                    token_id: token_for_atomic,
                    amount: transfer_amount,
                    tx: &tx_record,
                    projection: projection.as_ref(),
                },
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

        Ok(BilateralSettlementOutcome {
            transfer_meta: TransferMeta {
                token_id: token_id_str,
                amount: transfer_amount,
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::parse_transfer_fields;
    use crate::sdk::token_state::canonicalize_token_id;
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
            amount: Balance::from_state(5, [0u8; 32]),
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

    #[test]
    fn parse_transfer_preserves_public_key_recipient_bytes() {
        let recipient_owner = vec![0x42; 64];
        let op = Operation::Transfer {
            to_device_id: vec![0x11; 32],
            amount: Balance::from_state(7, [0u8; 32]),
            token_id: b"ERA".to_vec(),
            mode: TransactionMode::Bilateral,
            nonce: vec![],
            verification: VerificationType::Bilateral,
            pre_commit: None,
            recipient: recipient_owner.clone(),
            to: b"recipient".to_vec(),
            message: "memo".to_string(),
            signature: vec![],
        };

        let parsed = super::parse_transfer(&op.to_bytes()).expect("transfer should parse");
        assert_eq!(parsed.recipient, recipient_owner);
    }
}
