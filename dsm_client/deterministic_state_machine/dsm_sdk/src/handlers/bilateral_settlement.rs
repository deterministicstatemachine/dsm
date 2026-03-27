//! Default settlement delegate for bilateral BLE transfers.
//!
//! This module lives in the **application layer** and implements the
//! [`BilateralSettlementDelegate`] trait defined in the transport-layer
//! [`bluetooth`](crate::bluetooth) module.  All token- and balance-specific
//! logic (balance debits/credits, transaction history, wallet cache sync) is
//! concentrated here so that the BLE transport layer remains coin-agnostic.

use crate::bluetooth::bilateral_ble_handler::{
    BilateralSettlementContext, BilateralSettlementDelegate, BilateralSettlementOutcome,
};
use crate::sdk::token_state::{self, canonicalize_token_id, TransferFields};
use crate::sdk::transfer_hooks::TransferMeta;
use crate::storage::client_db::BalanceProjectionRecord;
use crate::util::text_id::encode_base32_crockford;
use dsm::types::operations::Operation;
use dsm::types::state_types::State;
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
    if let Ok(commit) = crate::policy::strict_policy_commit_for_token(token_id, None) {
        return Ok(commit);
    }

    let anchor_b32 = crate::sdk::app_state::AppState::handle_app_state_request(
        &format!("dsm.token.{token_id}"),
        "get",
        "",
    );
    if anchor_b32.is_empty() {
        return Err(format!("missing policy anchor for token {token_id}"));
    }

    crate::policy::strict_policy_commit_for_token(
        token_id,
        Some(&format!("dsm:policy:{anchor_b32}")),
    )
    .map_err(|e| format!("resolve policy commit failed for {token_id}: {e}"))
}

/// Build the canonical settled state from the caller-provided canonical state.
///
/// `ctx.canonical_state` is treated as the authoritative post-transition state
/// emitted by the state machine. Settlement must not re-apply token deltas.
fn build_canonical_settled_state(
    ctx: &BilateralSettlementContext,
) -> Result<(Option<State>, Option<BalanceProjectionRecord>), String> {
    let canonical_state = match ctx.canonical_state.as_ref() {
        Some(s) => s,
        None => {
            return Err(
                "missing canonical_state for settlement (strict fail-closed path)".to_string(),
            )
        }
    };

    let transfer = match parse_transfer(&ctx.operation_bytes) {
        Some(t) if t.amount > 0 => t,
        _ => return Ok((Some(canonical_state.clone()), None)),
    };

    let token_for_policy = if transfer.token_id.is_empty() {
        "ERA"
    } else {
        transfer.token_id.as_str()
    };
    let policy_commit = resolve_policy_commit(token_for_policy)?;

    // Bilateral settlement uses a SEPARATE state machine (BTM) for the relationship
    // chain. The device's canonical_state (from app_router) does NOT have the transfer
    // delta applied — only the BTM relationship state does. We must apply the delta here.
    let mut settled_state = canonical_state.clone();

    if ctx.is_sender {
        let token_id = if transfer.token_id.is_empty() {
            "ERA"
        } else {
            transfer.token_id.as_str()
        };
        if let Some(recipient_owner) = token_state::canonical_transfer_recipient_owner(
            transfer.recipient.as_slice(),
            transfer.to_device_id.as_slice(),
        ) {
            token_state::apply_transfer_debit_credit(
                &mut settled_state.token_balances,
                &policy_commit,
                &canonical_state.device_info.public_key,
                recipient_owner,
                token_id,
                transfer.amount,
                canonical_state.hash,
                canonical_state.state_number,
            )?;
        } else {
            token_state::apply_transfer_debit(
                &mut settled_state.token_balances,
                &policy_commit,
                &canonical_state.device_info.public_key,
                token_id,
                transfer.amount,
                canonical_state.hash,
                canonical_state.state_number,
            )?;
        }
    } else {
        let token_id = if transfer.token_id.is_empty() {
            "ERA"
        } else {
            transfer.token_id.as_str()
        };

        token_state::apply_transfer_credit(
            &mut settled_state.token_balances,
            &policy_commit,
            &canonical_state.device_info.public_key,
            token_id,
            transfer.amount,
            canonical_state.hash,
            canonical_state.state_number,
        )?;
    }

    // Advance device state_number for the settled state.
    settled_state.state_number = canonical_state.state_number + 1;

    settled_state.hash = settled_state
        .compute_hash()
        .map_err(|e| format!("settlement hash recompute failed: {e}"))?;

    // Sync balance projection so balance.list reflects the updated balance.
    let local_txt = encode_base32_crockford(&ctx.local_device_id);
    let locked = crate::storage::client_db::get_locked_balance(&local_txt, token_for_policy)
        .map_err(|e| format!("read locked balance failed: {e}"))?;
    let projection = crate::storage::client_db::build_balance_projection_from_state(
        &local_txt,
        token_for_policy,
        &policy_commit,
        &settled_state,
        locked,
    )
    .map_err(|e| format!("build balance projection failed: {e}"))?;

    Ok((Some(settled_state), Some(projection)))
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
        let tx_id_candidate =
            crate::util::text_id::encode_base32_crockford(&ctx.commitment_hash);
        // Sender-only idempotency: prevent double-debit if the sender's
        // settlement is retried.  The receiver side is naturally idempotent
        // via the atomic chain-tip CAS in apply_receiver_confirm_bundle_atomic
        // (the UPDATE contacts SET chain_tip = ?1 WHERE device_id = ?3 only
        // succeeds once for the same tip value).  In production each device
        // has its own DB so a bare tx_id check suffices for senders.
        if ctx.is_sender
            && crate::storage::client_db::is_settlement_completed(&tx_id_candidate)
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
        let (canonical_state, projection) = build_canonical_settled_state(&ctx)?;

        // Log the canonical state for debugging
        match &canonical_state {
            Some(state) => {
                let era_balance = state
                    .token_balances
                    .values()
                    .find_map(|b| if b.value() > 0 { Some(b.value()) } else { None })
                    .unwrap_or(0);
                log::info!(
                    "[BILATERAL][settle] canonical_state=Some hash={} state_number={} era_balance={}",
                    encode_base32_crockford(&state.hash),
                    state.state_number,
                    era_balance
                );
            }
            None => {
                log::warn!("[BILATERAL][settle] canonical_state=None");
            }
        }

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
            chain_height: canonical_state.as_ref().map_or(0, |s| s.state_number),
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
                    crate::storage::client_db::apply_sender_settlement_bundle_atomic(
                        &local_txt,
                        token_for_atomic,
                        transfer_amount,
                        &tx_record,
                        canonical_state.as_ref(),
                        projection.as_ref(),
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
            let confirm_result = crate::storage::client_db::apply_receiver_confirm_bundle_atomic(
                crate::storage::client_db::ReceiverConfirmBundle {
                    counterparty_device_id: &ctx.counterparty_device_id,
                    new_chain_tip: &ctx.new_chain_tip,
                    receiver_device_id: &local_txt,
                    token_id: token_for_atomic,
                    amount: transfer_amount,
                    tx: &tx_record,
                    settled_state: canonical_state.as_ref(),
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
            canonical_state,
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

    #[test]
    fn parse_transfer_preserves_public_key_recipient_bytes() {
        let recipient_owner = vec![0x42; 64];
        let op = Operation::Transfer {
            to_device_id: vec![0x11; 32],
            amount: Balance::from_state(7, [0u8; 32], 0),
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
