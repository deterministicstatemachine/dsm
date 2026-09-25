// SPDX-License-Identifier: MIT OR Apache-2.0

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

use crate::bluetooth::bilateral_ble_handler::BilateralSettlementDelegate;
use crate::sdk::token_state::{canonicalize_token_id, TransferFields};
use crate::sdk::transfer_hooks::TransferMeta;
use crate::util::text_id::encode_base32_crockford;
use dsm::types::error::DsmError;
use dsm::types::operations::Operation;

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
    crate::policy::strict_policy_commit_for_token(token_id, None)
        .map_err(|e| format!("resolve policy commit failed for {token_id}: {e}"))
}

/// A transfer's settlement inputs, resolved before the step's advance.
#[derive(Debug, Clone)]
struct SettledTransfer {
    token_id: String,
    amount: u64,
    policy_commit: [u8; 32],
    /// This device's locked amount of the token; the advance does not move it.
    locked: u64,
}

/// One offline step's settlement: everything it reads is resolved before the
/// step's advance opens its transaction, and [`Self::write_in_tx`] writes the
/// step's relationship tip, projection and history inside that transaction,
/// from the head the advance produced.
#[derive(Debug, Clone)]
pub(crate) struct StepSettlement {
    local_device_id: [u8; 32],
    counterparty_device_id: [u8; 32],
    commitment_hash: [u8; 32],
    parent_tip: [u8; 32],
    operation_bytes: Vec<u8>,
    is_sender: bool,
    transfer: Option<SettledTransfer>,
}

impl StepSettlement {
    /// Resolve the step's settlement inputs. A transfer names its token — an
    /// empty token id is refused, never read as ERA — and its policy and
    /// this device's locked amount are read here, outside any transaction.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn resolve(
        local_device_id: [u8; 32],
        counterparty_device_id: [u8; 32],
        commitment_hash: [u8; 32],
        parent_tip: [u8; 32],
        operation_bytes: Vec<u8>,
        is_sender: bool,
    ) -> Result<Self, String> {
        let transfer = match parse_transfer(&operation_bytes) {
            Some(t) if t.amount > 0 => {
                if t.token_id.is_empty() {
                    return Err("bilateral settle: the transfer names no token".to_string());
                }
                let policy_commit = resolve_policy_commit(&t.token_id)?;
                let locked = crate::storage::client_db::get_locked_balance(
                    &encode_base32_crockford(&local_device_id),
                    &t.token_id,
                )
                .map_err(|e| format!("read locked balance failed: {e}"))?;
                Some(SettledTransfer {
                    token_id: t.token_id,
                    amount: t.amount,
                    policy_commit,
                    locked,
                })
            }
            _ => None,
        };
        Ok(Self {
            local_device_id,
            counterparty_device_id,
            commitment_hash,
            parent_tip,
            operation_bytes,
            is_sender,
            transfer,
        })
    }

    /// The transfer this step moved, for post-transfer hooks.
    pub(crate) fn transfer_meta(&self) -> TransferMeta {
        match &self.transfer {
            Some(t) => TransferMeta {
                token_id: t.token_id.clone(),
                amount: t.amount,
            },
            None => TransferMeta::default(),
        }
    }

    /// Write the step's relationship tip (`parent_tip` → `child_tip`, bound to
    /// the step's commitment), its balance projection from `outcome`'s head,
    /// and its history row with the step's signed `receipt`, in `tx` — the
    /// transaction the advance commits in.
    pub(crate) fn write_in_tx(
        &self,
        tx: &rusqlite::Transaction<'_>,
        outcome: &dsm::types::device_state::AdvanceOutcome,
        child_tip: [u8; 32],
        receipt: &[u8],
    ) -> Result<(), DsmError> {
        let local_txt = encode_base32_crockford(&self.local_device_id);
        let head = &outcome.new_device_state;
        let projection = match &self.transfer {
            Some(t) => {
                let balance = head.balance(&t.policy_commit);
                if t.locked > balance {
                    return Err(DsmError::invalid_operation(format!(
                        "bilateral settle: {} locked exceeds the head's balance {balance}",
                        t.locked
                    )));
                }
                Some(
                    crate::storage::client_db::build_balance_projection_from_device_head(
                        &local_txt,
                        &t.token_id,
                        &t.policy_commit,
                        head,
                        balance,
                        t.locked,
                    )
                    .map_err(|e| {
                        DsmError::storage(
                            format!("build balance projection failed: {e}"),
                            None::<std::io::Error>,
                        )
                    })?,
                )
            }
            None => None,
        };
        let counterparty_txt = encode_base32_crockford(&self.counterparty_device_id);
        let (from_device, to_device) = if self.is_sender {
            (local_txt, counterparty_txt)
        } else {
            (counterparty_txt, local_txt)
        };
        let record = crate::storage::client_db::TransactionRecord {
            tx_id: encode_base32_crockford(&self.commitment_hash),
            tx_hash: encode_base32_crockford(&child_tip),
            from_device,
            to_device,
            amount: self.transfer.as_ref().map_or(0, |t| t.amount),
            tx_type: "bilateral_offline".to_string(),
            status: "completed".to_string(),
            commitment_hash: Some(encode_base32_crockford(&self.commitment_hash).into_bytes()),
            proof_data: Some(receipt.to_vec()),
            metadata: {
                let mut m = std::collections::HashMap::new();
                if let Some(t) = &self.transfer {
                    m.insert("token_id".to_string(), t.token_id.as_bytes().to_vec());
                }
                m
            },
        };
        crate::storage::client_db::settle_step_in_tx(
            tx,
            &crate::storage::client_db::SettledStep {
                counterparty_device_id: &self.counterparty_device_id,
                parent_tip: &self.parent_tip,
                child_tip: &child_tip,
                commitment_hash: &self.commitment_hash,
                tx: &record,
                projection: projection.as_ref(),
            },
        )
        .map_err(|e| DsmError::storage(format!("bilateral settle: {e}"), None::<std::io::Error>))
    }

    /// The operation bytes the step settles.
    pub(crate) fn operation_bytes(&self) -> &[u8] {
        &self.operation_bytes
    }
}

/// Display metadata for the offline protocol's events; the application
/// layer's half of the transport's [`BilateralSettlementDelegate`].
pub struct DefaultBilateralSettlementDelegate;

impl BilateralSettlementDelegate for DefaultBilateralSettlementDelegate {
    /// Extract event-display metadata (amount, token_id) from serialised
    /// operation bytes without applying any wallet state changes.
    fn operation_metadata(&self, operation_bytes: &[u8]) -> (Option<u64>, Option<String>) {
        let (amount, token_opt) = parse_transfer_fields(operation_bytes);
        let amount_opt = if amount > 0 { Some(amount) } else { None };
        (amount_opt, token_opt)
    }
}

#[cfg(test)]
mod tests {
    use super::parse_transfer_fields;
    use crate::sdk::token_state::canonicalize_token_id;
    use dsm::types::operations::{Operation, TransactionMode};
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
            policy_commit: [0u8; 32],
            to_device_id: vec![0x11; 32],
            amount: Balance::amount(5),
            token_id: b"DBTC".to_vec(),
            mode: TransactionMode::Bilateral,
            nonce: vec![],
            recipient: vec![0x11; 32],
            to: b"recipient".to_vec(),
            message: "memo".to_string(),
            signature: vec![],
            authority_policy: None,
        };

        let (amount, token_id) = parse_transfer_fields(&op.to_bytes());
        assert_eq!(amount, 5);
        assert_eq!(token_id.as_deref(), Some("dBTC"));
    }

    #[test]
    fn parse_transfer_preserves_public_key_recipient_bytes() {
        let recipient_owner = vec![0x42; 64];
        let op = Operation::Transfer {
            policy_commit: [0u8; 32],
            to_device_id: vec![0x11; 32],
            amount: Balance::amount(7),
            token_id: b"ERA".to_vec(),
            mode: TransactionMode::Bilateral,
            nonce: vec![],
            recipient: recipient_owner.clone(),
            to: b"recipient".to_vec(),
            message: "memo".to_string(),
            signature: vec![],
            authority_policy: None,
        };

        let parsed = super::parse_transfer(&op.to_bytes()).expect("transfer should parse");
        assert_eq!(parsed.recipient, recipient_owner);
    }

    /// A step's settlement commits in its advance's transaction: when the
    /// settlement refuses — here the relationship tip is not the step's parent
    /// — the head does not advance either, and nothing of the step is kept.
    /// MUTATION CONTROL: advancing without the in-transaction settlement
    /// commits the head alone and turns this red.
    #[test]
    #[serial_test::serial]
    fn a_refused_settlement_leaves_the_head_where_it_was() {
        let (identity, core) = crate::economic_fixtures::local_device(0x31);
        let counterparty = [0x32u8; 32];
        let held = [0x70u8; 32];
        crate::storage::client_db::store_contact_for_tests(
            &dsm::types::contact_types::DsmVerifiedContact {
                alias: "peer".to_string(),
                device_id: counterparty,
                genesis_hash: [0x33u8; 32],
                public_key: vec![0x41; 64],
                chain_tip: Some(held),
                genesis_verified_online: true,
                verifying_storage_nodes: vec![],
                ble_address: None,
            },
        );
        core.establish_relationship(counterparty)
            .expect("establish the relationship");
        let before = core.device_head().expect("head").root();

        let settlement = super::StepSettlement::resolve(
            identity.device_id,
            counterparty,
            [0x34u8; 32],
            [0x71u8; 32],
            Operation::Noop.to_bytes(),
            false,
        )
        .expect("resolve");
        let err = core
            .execute_offline_step(
                dsm::core::bilateral_transaction_manager::compute_smt_key(
                    &identity.device_id,
                    &counterparty,
                ),
                counterparty,
                Operation::Noop,
                &[],
                None,
                None,
                None,
                // The settlement refuses at the tip, before a receipt is kept.
                &|tx, o| settlement.write_in_tx(tx, o, [0x72u8; 32], &[]),
            )
            .expect_err("a step whose settlement refuses does not commit");
        assert!(err.to_string().contains("conflict"), "{err}");
        assert_eq!(
            core.device_head().expect("head").root(),
            before,
            "the head advanced without its settlement"
        );
        assert_eq!(
            crate::storage::client_db::get_contact_chain_tip(&counterparty).expect("read"),
            Some(held)
        );
        assert!(!crate::storage::client_db::transaction_exists(
            &crate::util::text_id::encode_base32_crockford(&[0x34u8; 32])
        )
        .expect("read the history"));
    }
}
