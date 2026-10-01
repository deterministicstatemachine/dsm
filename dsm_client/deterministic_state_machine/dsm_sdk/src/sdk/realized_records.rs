// SPDX-License-Identifier: MIT OR Apache-2.0

//! The wallet's records of a token or SoFi event once its position realizes:
//! a history row naming every token the event moved, with its amount, and the
//! balance projection of each token it moved, rebuilt from the device head
//! (phone-rig rulings, 2026-10-01).
//!
//! Both are display caches of what the head commits. The head is final
//! before either is written, so a row or projection that fails to persist is
//! logged, the row kept in the history repair queue for the startup sweep —
//! never reported as a failed event.

use dsm::types::device_state::{BalanceDirection, DeviceState};

use crate::storage::client_db::{
    build_balance_projection_from_device_head, enqueue_history_repair, get_balance_projection,
    store_transaction, token_registry, upsert_balance_projection, TransactionRecord,
};
use crate::util::text_id::encode_base32_crockford as b32;

type D32 = [u8; 32];

/// The metadata key of a row's token movements.
pub(crate) const MOVES_KEY: &str = "moves";
/// The metadata key of the vault or token an event is about.
pub(crate) const SUBJECT_KEY: &str = "subject";

/// Bytes of one encoded movement: the policy commit, the direction, and the
/// amount, big-endian.
const MOVE_BYTES: usize = 32 + 1 + 8;
const CREDIT: u8 = 0x01;
const DEBIT: u8 = 0x02;

/// What realized.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Realized {
    /// A token created: its ERA fee paid, its genesis supply credited.
    TokenCreate,
    /// A vault created: both reserves paid in.
    VaultCreate,
    /// A setup with a vault: no token moves.
    Setup,
    /// A trade or route.
    Trade,
    /// The owner's close: both reserves credited.
    Close,
}

impl Realized {
    /// The row's stored type, which the history maps to the wire's.
    pub(crate) fn tx_type(self) -> &'static str {
        match self {
            Self::TokenCreate => "token_create",
            Self::VaultCreate => "vault_create",
            Self::Setup => "sofi_setup",
            Self::Trade => "sofi_trade",
            Self::Close => "sofi_close",
        }
    }
}

/// One token an event moved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Moved {
    pub policy_commit: D32,
    pub direction: BalanceDirection,
    pub amount: u64,
}

impl Moved {
    /// The movement from a balance before to after; `None` when it did not
    /// change.
    pub(crate) fn between(policy_commit: D32, before: u64, after: u64) -> Option<Self> {
        if after > before {
            Some(Self {
                policy_commit,
                direction: BalanceDirection::Credit,
                amount: after - before,
            })
        } else if before > after {
            Some(Self {
                policy_commit,
                direction: BalanceDirection::Debit,
                amount: before - after,
            })
        } else {
            None
        }
    }
}

/// The movements as a row stores them.
pub(crate) fn encode_moves(moved: &[Moved]) -> Vec<u8> {
    let mut out = Vec::with_capacity(moved.len() * MOVE_BYTES);
    for m in moved {
        out.extend_from_slice(&m.policy_commit);
        out.push(match m.direction {
            BalanceDirection::Credit => CREDIT,
            BalanceDirection::Debit => DEBIT,
        });
        out.extend_from_slice(&m.amount.to_be_bytes());
    }
    out
}

/// The movements a row stores. Bytes that are not whole movements, or a
/// direction that is neither, are a corrupt row.
pub(crate) fn decode_moves(bytes: &[u8]) -> Result<Vec<Moved>, String> {
    let (chunks, rest) = bytes.as_chunks::<MOVE_BYTES>();
    if !rest.is_empty() {
        return Err(format!(
            "{} bytes are not whole token movements",
            bytes.len()
        ));
    }
    let mut out = Vec::with_capacity(chunks.len());
    for chunk in chunks {
        let (commit, rest) = chunk.split_at(32);
        let (direction, amount) = rest.split_at(1);
        let direction = match direction {
            [CREDIT] => BalanceDirection::Credit,
            [DEBIT] => BalanceDirection::Debit,
            other => return Err(format!("movement direction {other:?} is not declared")),
        };
        out.push(Moved {
            policy_commit: <D32>::try_from(commit).map_err(|e| format!("policy commit: {e}"))?,
            direction,
            amount: u64::from_be_bytes(
                <[u8; 8]>::try_from(amount).map_err(|e| format!("amount: {e}"))?,
            ),
        });
    }
    Ok(out)
}

/// The ticker a token's balances are projected under: ERA and dBTC built
/// in, any other token the one this device's registry holds under the commit.
fn ticker_of(policy_commit: &D32) -> Result<String, String> {
    if let Some(builtin) =
        dsm::core::token::token_state_manager::builtin_token_id_for_policy_commit(policy_commit)
    {
        return Ok(builtin.to_string());
    }
    token_registry::get_token_by_policy_commit(policy_commit)
        .map_err(|e| format!("token registry unreadable: {e}"))?
        .map(|row| row.ticker)
        .ok_or_else(|| format!("no registry entry for token {}", b32(policy_commit)))
}

/// Rebuild the projection of `policy_commit` from `head`, keeping the lock
/// the projection holds (a dBTC withdrawal in flight).
fn project(head: &DeviceState, device_txt: &str, policy_commit: &D32) -> Result<(), String> {
    let ticker = ticker_of(policy_commit)?;
    let locked = match get_balance_projection(device_txt, &ticker)
        .map_err(|e| format!("projection unreadable: {e}"))?
    {
        Some(existing) => existing.locked,
        None => 0,
    };
    let record = build_balance_projection_from_device_head(
        device_txt,
        &ticker,
        policy_commit,
        head,
        head.balance(policy_commit),
        locked,
    )
    .map_err(|e| format!("projection: {e}"))?;
    upsert_balance_projection(&record).map_err(|e| format!("projection write: {e}"))
}

/// Record `what`, realized at `position` with `head` as the device's head:
/// its history row, identified by `event` (the vault, setup, token or
/// fulfillment it is), naming each of `subjects` and every token in `moved`, and the
/// projection of each token it moved rebuilt from `head`.
pub(crate) fn record_realized(
    head: &DeviceState,
    what: Realized,
    event: &D32,
    position: u64,
    subjects: &[D32],
    moved: &[Moved],
) {
    let device_txt = b32(&head.devid());
    for m in moved {
        if let Err(e) = project(head, &device_txt, &m.policy_commit) {
            log::error!(
                "[{}] the event stands; the projection of {} was not rebuilt: {e}",
                what.tx_type(),
                b32(&m.policy_commit)
            );
        }
    }
    let mut metadata = std::collections::HashMap::new();
    metadata.insert(MOVES_KEY.to_string(), encode_moves(moved));
    metadata.insert(
        "economic_position".to_string(),
        position.to_string().into_bytes(),
    );
    if !subjects.is_empty() {
        let named: Vec<String> = subjects.iter().map(|s| b32(s)).collect();
        metadata.insert(SUBJECT_KEY.to_string(), named.join(", ").into_bytes());
    }
    let row = TransactionRecord {
        tx_id: format!("{}_{}", what.tx_type(), b32(event)),
        tx_hash: b32(event),
        from_device: device_txt.clone(),
        to_device: device_txt,
        amount: 0,
        tx_type: what.tx_type().to_string(),
        status: "confirmed".to_string(),
        commitment_hash: None,
        proof_data: None,
        metadata,
    };
    if let Err(e) = store_transaction(&row) {
        log::error!(
            "[{}] the event stands; its history row failed to persist: {e}",
            what.tx_type()
        );
        if let Err(q) =
            enqueue_history_repair(&row, &format!("{} history row failed: {e}", what.tx_type()))
        {
            log::error!(
                "[{}] could not queue the history repair: {q}",
                what.tx_type()
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn movements_survive_the_row_and_a_corrupt_row_is_refused() {
        let moved = [
            Moved {
                policy_commit: [0x11; 32],
                direction: BalanceDirection::Debit,
                amount: 5_000,
            },
            Moved {
                policy_commit: [0x22; 32],
                direction: BalanceDirection::Credit,
                amount: 332_665,
            },
        ];
        let bytes = encode_moves(&moved);
        assert_eq!(bytes.len(), 2 * MOVE_BYTES);
        assert_eq!(decode_moves(&bytes), Ok(moved.to_vec()));
        // A setup moves no token: its row stores no movement and reads back none.
        let setup = decode_moves(&encode_moves(&[])).expect("an empty row decodes");
        assert!(setup.is_empty());
        assert_eq!(
            decode_moves(&bytes[..MOVE_BYTES - 1]),
            Err(format!(
                "{} bytes are not whole token movements",
                MOVE_BYTES - 1
            ))
        );
        let mut undeclared = bytes.clone();
        undeclared[32] = 0x07;
        assert_eq!(
            decode_moves(&undeclared),
            Err("movement direction [7] is not declared".to_string())
        );
    }

    #[test]
    fn a_movement_is_the_change_between_two_balances() {
        let token = [0x33; 32];
        assert_eq!(
            Moved::between(token, 100, 40),
            Some(Moved {
                policy_commit: token,
                direction: BalanceDirection::Debit,
                amount: 60
            })
        );
        assert_eq!(
            Moved::between(token, 0, 667_335),
            Some(Moved {
                policy_commit: token,
                direction: BalanceDirection::Credit,
                amount: 667_335
            })
        );
        assert_eq!(Moved::between(token, 9, 9), None);
    }
}
