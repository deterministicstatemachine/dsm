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

/// Check whether a transaction with the given commitment hash has already been
/// settled (status = "completed").  Used as a replay guard for bilateral
/// balance application — the DB-level `ON CONFLICT(tx_id)` upsert handles
/// storage-layer idempotency, but we need to avoid double-applying balance
/// deltas in `build_canonical_settled_state`.
fn is_already_settled(commitment_hash: &[u8; 32]) -> bool {
    let tx_id = encode_base32_crockford(commitment_hash);
    crate::storage::client_db::get_transaction_history(None, Some(500))
        .ok()
        .map(|txs| {
            txs.iter()
                .any(|tx| tx.tx_id == tx_id && tx.status == "completed")
        })
        .unwrap_or(false)
}

fn reconcile_sender_state(
    prior_state: &State,
    _base_state: &State,
    transfer: &TransferFields,
    policy_commit: &[u8; 32],
) -> Result<State, String> {
    let token_id = if transfer.token_id.is_empty() {
        "ERA"
    } else {
        transfer.token_id.as_str()
    };
    let recipient_owner = if transfer.recipient.is_empty() {
        transfer.to_device_id.as_slice()
    } else {
        transfer.recipient.as_slice()
    };

    // Clone the device canonical state and apply the bilateral delta.
    // prior_state IS the device canonical state (correct device_id, public_key, balances).
    let mut settled_state = prior_state.clone();

    token_state::apply_transfer_debit_credit(
        &mut settled_state.token_balances,
        policy_commit,
        &prior_state.device_info.public_key,
        recipient_owner,
        token_id,
        transfer.amount,
        prior_state.hash,
        prior_state.state_number,
    )?;

    // Caller (build_canonical_settled_state) handles state_number bump and hash recompute.
    Ok(settled_state)
}

fn reconcile_receiver_state(
    prior_state: &State,
    _base_state: &State,
    transfer: &TransferFields,
    policy_commit: &[u8; 32],
) -> Result<State, String> {
    let token_id = if transfer.token_id.is_empty() {
        "ERA"
    } else {
        transfer.token_id.as_str()
    };

    // Clone the device canonical state and apply the bilateral credit.
    let mut settled_state = prior_state.clone();

    token_state::apply_transfer_credit(
        &mut settled_state.token_balances,
        policy_commit,
        &prior_state.device_info.public_key,
        token_id,
        transfer.amount,
        prior_state.hash,
        prior_state.state_number,
    )?;

    // Caller handles state_number bump and hash recompute.
    Ok(settled_state)
}

/// Build the canonical settled state by applying the bilateral transfer delta
/// to the device's canonical state.
///
/// The device's canonical state (`ctx.device_canonical_state`) is the single
/// source of truth for token balances (B_n).  This function applies Δ_{n+1}
/// from the bilateral operation, increments the device state_number, and
/// recomputes the hash.  The result is the next canonical device state.
///
/// This replaces the old `latest_archived_state()` approach which mined a BCR
/// archive mixing faucet/mint/bilateral states under one state_number space —
/// violating the spec's per-relationship chain model (§2.1, §4.3).
fn build_canonical_settled_state(
    ctx: &BilateralSettlementContext,
) -> Result<Option<State>, String> {
    // The device's canonical state is the authoritative balance source.
    let device_state = match ctx.device_canonical_state.as_ref() {
        Some(s) => s,
        None => {
            // No device state available (e.g. tests, early bootstrap).
            // Fall through to canonical_state if present.
            return Ok(ctx.canonical_state.clone());
        }
    };

    let transfer = match parse_transfer(&ctx.operation_bytes) {
        Some(t) if t.amount > 0 => t,
        _ => return Ok(Some(device_state.clone())),
    };

    // Replay guard: if this commitment_hash was already settled, return the
    // current device state without re-applying the delta.  This replaces the
    // old (broken) state_number comparison guard.
    if is_already_settled(&ctx.commitment_hash) {
        log::info!(
            "[BILATERAL][settle] duplicate settlement skipped for commitment={}",
            encode_base32_crockford(&ctx.commitment_hash),
        );
        return Ok(Some(device_state.clone()));
    }

    let token_for_policy = if transfer.token_id.is_empty() {
        "ERA"
    } else {
        transfer.token_id.as_str()
    };
    let policy_commit = resolve_policy_commit(token_for_policy)?;

    // Apply Δ_{n+1} to B_n from the device's canonical state.
    // Both prior_state and base_state are the device state:
    //   prior_state → token_balances source (B_n), public_key for key derivation
    //   base_state  → skeleton (correct device_id, state_number)
    let mut settled_state = if ctx.is_sender {
        reconcile_sender_state(device_state, device_state, &transfer, &policy_commit)?
    } else {
        reconcile_receiver_state(device_state, device_state, &transfer, &policy_commit)?
    };

    // Advance the device's state_number and recompute hash.
    settled_state.state_number = device_state.state_number + 1;
    settled_state.hash = settled_state
        .compute_hash()
        .map_err(|e| format!("settled-state hash recompute failed: {e}"))?;

    // Sync balance projection so balance.list reflects the updated balance.
    let local_txt = encode_base32_crockford(&ctx.local_device_id);
    let locked = crate::storage::client_db::get_locked_balance(&local_txt, token_for_policy)
        .map_err(|e| format!("read locked balance failed: {e}"))?;
    crate::storage::client_db::sync_token_projection_from_state(
        &local_txt,
        token_for_policy,
        &policy_commit,
        &settled_state,
        locked,
    )
    .map_err(|e| format!("sync balance projection failed: {e}"))?;

    Ok(Some(settled_state))
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
        let (transfer_amount, token_id_opt) = parse_transfer_fields(&ctx.operation_bytes);
        let token_id_str = token_id_opt.clone().unwrap_or_default();
        let canonical_state = build_canonical_settled_state(&ctx)?;

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

        // Archive the settled state to BCR so balance.list reflects the updated balances
        if let Some(ref settled_state) = canonical_state {
            crate::storage::client_db::store_bcr_state(settled_state, true)
                .map_err(|e| format!("archive settled state failed: {e}"))?;
            log::info!(
                "[BILATERAL][settle] archived settled state hash={} state_number={}",
                encode_base32_crockford(&settled_state.hash),
                settled_state.state_number
            );
        }

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
    use super::{parse_transfer_fields, reconcile_receiver_state, reconcile_sender_state};
    use crate::sdk::token_state::{canonicalize_token_id, TransferFields};
    use dsm::types::operations::{Operation, TransactionMode, VerificationType};
    use dsm::types::state_builder::StateBuilder;
    use dsm::types::state_types::{DeviceInfo, State};
    use dsm::types::token_types::Balance;
    use std::collections::HashMap;

    fn make_state(device_id: [u8; 32], public_key: Vec<u8>, state_number: u64) -> State {
        StateBuilder::new()
            .with_id(format!("state_{state_number}"))
            .with_state_number(state_number)
            .with_entropy(vec![state_number as u8; 32])
            .with_prev_state_hash([state_number.saturating_sub(1) as u8; 32])
            .with_operation(Operation::Generic {
                operation_type: b"test".to_vec(),
                data: vec![],
                message: String::new(),
                signature: vec![],
            })
            .with_device_info(DeviceInfo {
                device_id,
                public_key,
                metadata: Vec::new(),
            })
            .with_token_balances(HashMap::new())
            .build()
            .expect("state should build")
    }

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
    fn reconcile_sender_state_debits_local_and_credits_recipient() {
        let policy_commit = *crate::policy::builtins::NATIVE_POLICY_COMMIT;
        let sender_pk = vec![0x21; 32];
        let recipient = vec![0x42; 32];
        // In the new model, prior_state IS the device canonical state.
        // base_state is unused (reconcile clones from prior_state).
        let mut device_state = make_state([0x11; 32], sender_pk.clone(), 7);
        let base = make_state([0x11; 32], sender_pk.clone(), 8);

        let sender_key =
            dsm::core::token::derive_canonical_balance_key(&policy_commit, &sender_pk, "ERA");
        let recipient_key =
            dsm::core::token::derive_canonical_balance_key(&policy_commit, &recipient, "ERA");
        device_state.token_balances.insert(
            sender_key.clone(),
            Balance::from_state(10, device_state.hash, device_state.state_number),
        );

        let settled = reconcile_sender_state(
            &device_state,
            &base,
            &TransferFields {
                amount: 4,
                token_id: "ERA".to_string(),
                recipient: recipient.clone(),
                to_device_id: recipient.clone(),
            },
            &policy_commit,
        )
        .expect("sender settlement should succeed");

        // Reconcile clones from prior_state (device_state at sn=7).
        // Caller (build_canonical_settled_state) bumps to sn=8.
        assert_eq!(settled.state_number, 7);
        assert_eq!(
            settled.token_balances.get(&sender_key).map(Balance::value),
            Some(6)
        );
        assert_eq!(
            settled
                .token_balances
                .get(&recipient_key)
                .map(Balance::value),
            Some(4)
        );
    }

    #[test]
    fn reconcile_receiver_state_credits_local_owner() {
        let policy_commit = *crate::policy::builtins::NATIVE_POLICY_COMMIT;
        let receiver_pk = vec![0x33; 32];
        let device_state = make_state([0x22; 32], receiver_pk.clone(), 3);
        let base = make_state([0x22; 32], receiver_pk.clone(), 4);
        let local_key =
            dsm::core::token::derive_canonical_balance_key(&policy_commit, &receiver_pk, "ERA");

        let settled = reconcile_receiver_state(
            &device_state,
            &base,
            &TransferFields {
                amount: 7,
                token_id: "ERA".to_string(),
                recipient: vec![0x44; 32],
                to_device_id: vec![0x22; 32],
            },
            &policy_commit,
        )
        .expect("receiver settlement should succeed");

        // Reconcile clones from prior_state (device_state at sn=3).
        // Caller bumps to sn=4.
        assert_eq!(settled.state_number, 3);
        assert_eq!(
            settled.token_balances.get(&local_key).map(Balance::value),
            Some(7)
        );
    }
}
