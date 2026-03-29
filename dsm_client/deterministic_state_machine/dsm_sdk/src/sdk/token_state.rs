//! Token balance state enforcement — whitepaper Section 8.
//!
//! Balances are embedded in the state hash. `compute_hash` sorts and hashes
//! all `token_balances` entries deterministically. `create_next_state` calls
//! `apply_token_balance_delta` before hash computation. This module provides the atomic balance
//! arithmetic that every transport mode (bilateral, online) calls for the
//! Section 8 invariant: Bn+1 = Bn + Δn+1, Bn+1 ≥ 0.
//!
//! The reconciliation ORCHESTRATION (where prior_state comes from, where the
//! settled state goes, sender-vs-receiver asymmetry) stays transport-specific
//! because bilateral and online have fundamentally different liveness models
//! (whitepaper Sections 5.1, 5.3, 18.2, 18.3).

use dsm::types::token_types::Balance;
use std::collections::HashMap;

/// Transfer operation fields extracted from `Operation::Transfer`.
#[derive(Debug, Clone)]
pub struct TransferFields {
    pub amount: u64,
    pub token_id: String,
    pub recipient: Vec<u8>,
    pub to_device_id: Vec<u8>,
}

/// Canonical recipient owner bytes for transfer balance keys.
///
/// Transfer operations historically overloaded `recipient` with either the
/// recipient's balance-owner bytes (public key) or the recipient's device ID.
/// A raw device ID cannot be used to derive the canonical balance key, so those
/// legacy forms must not mint a phantom credit entry.
pub fn canonical_transfer_recipient_owner<'a>(
    recipient: &'a [u8],
    to_device_id: &[u8],
) -> Option<&'a [u8]> {
    if recipient.is_empty() || recipient == to_device_id {
        None
    } else {
        Some(recipient)
    }
}

/// Normalize token ticker to canonical form.
pub fn canonicalize_token_id(token_id: &str) -> String {
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

/// Atomic debit-sender + credit-recipient on a mutable balance map.
///
/// Section 8 invariant: `Bn+1 = Bn + Δn+1, Bn+1 ≥ 0`.
/// Callers must ensure `balances` already contains the correct prior values
/// (bilateral: explicit clone from BCR archive; online: carried by
/// `execute_transition`).
///
/// Used by: bilateral sender (`reconcile_sender_state`),
///          online sender (`execute_dsm_operation` Transfer arm).
#[allow(clippy::too_many_arguments)]
pub fn apply_transfer_debit_credit(
    balances: &mut HashMap<String, Balance>,
    policy_commit: &[u8; 32],
    sender_pk: &[u8],
    recipient_owner: &[u8],
    token_id: &str,
    amount: u64,
    anchor_hash: [u8; 32],
    anchor_state_number: u64,
) -> Result<(), String> {
    let sender_key =
        dsm::core::token::derive_canonical_balance_key(policy_commit, sender_pk, token_id);
    let recipient_key =
        dsm::core::token::derive_canonical_balance_key(policy_commit, recipient_owner, token_id);

    let sender_balance = balances
        .get(&sender_key)
        .cloned()
        .unwrap_or_else(Balance::zero);
    if sender_balance.value() < amount {
        return Err(format!(
            "insufficient {} balance: have {}, need {}",
            token_id,
            sender_balance.value(),
            amount
        ));
    }

    let recipient_balance = balances
        .get(&recipient_key)
        .cloned()
        .unwrap_or_else(Balance::zero);
    let recipient_value = recipient_balance
        .value()
        .checked_add(amount)
        .ok_or_else(|| format!("{token_id} balance overflow"))?;

    balances.insert(
        sender_key,
        Balance::from_state(
            sender_balance.value() - amount,
            anchor_hash,
            anchor_state_number,
        ),
    );
    balances.insert(
        recipient_key,
        Balance::from_state(recipient_value, anchor_hash, anchor_state_number),
    );

    Ok(())
}

/// Debit-only for sender-side transitions that do not carry a canonical
/// recipient balance owner.
pub fn apply_transfer_debit(
    balances: &mut HashMap<String, Balance>,
    policy_commit: &[u8; 32],
    sender_pk: &[u8],
    token_id: &str,
    amount: u64,
    anchor_hash: [u8; 32],
    anchor_state_number: u64,
) -> Result<(), String> {
    let sender_key =
        dsm::core::token::derive_canonical_balance_key(policy_commit, sender_pk, token_id);
    let sender_balance = balances
        .get(&sender_key)
        .cloned()
        .unwrap_or_else(Balance::zero);
    if sender_balance.value() < amount {
        return Err(format!(
            "insufficient {} balance: have {}, need {}",
            token_id,
            sender_balance.value(),
            amount
        ));
    }

    balances.insert(
        sender_key,
        Balance::from_state(
            sender_balance.value() - amount,
            anchor_hash,
            anchor_state_number,
        ),
    );

    Ok(())
}

/// Credit-only for the local party's balance.
///
/// Used by: bilateral receiver (`reconcile_receiver_state`).
/// The bilateral receiver never debits the sender locally — the sender's
/// debit is tracked on the sender's device.
pub fn apply_transfer_credit(
    balances: &mut HashMap<String, Balance>,
    policy_commit: &[u8; 32],
    local_pk: &[u8],
    token_id: &str,
    amount: u64,
    anchor_hash: [u8; 32],
    anchor_state_number: u64,
) -> Result<(), String> {
    let local_key =
        dsm::core::token::derive_canonical_balance_key(policy_commit, local_pk, token_id);
    let local_balance = balances
        .get(&local_key)
        .cloned()
        .unwrap_or_else(Balance::zero);
    let credited_value = local_balance
        .value()
        .checked_add(amount)
        .ok_or_else(|| format!("{token_id} balance overflow on credit"))?;

    balances.insert(
        local_key,
        Balance::from_state(credited_value, anchor_hash, anchor_state_number),
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{apply_transfer_debit, canonical_transfer_recipient_owner};
    use dsm::types::token_types::Balance;
    use std::collections::HashMap;

    #[test]
    fn canonical_transfer_recipient_owner_rejects_legacy_device_id() {
        let device_id = [0x11; 32];
        assert_eq!(
            canonical_transfer_recipient_owner(&device_id, &device_id),
            None
        );
    }

    #[test]
    fn canonical_transfer_recipient_owner_accepts_balance_owner_bytes() {
        let device_id = [0x11; 32];
        let owner = [0x22; 64];
        assert_eq!(
            canonical_transfer_recipient_owner(&owner, &device_id),
            Some(owner.as_slice())
        );
    }

    #[test]
    fn canonical_transfer_recipient_owner_rejects_empty_recipient() {
        let device_id = [0x11; 32];
        assert_eq!(canonical_transfer_recipient_owner(&[], &device_id), None);
    }

    #[test]
    fn apply_transfer_debit_updates_sender_balance() {
        let policy_commit = [0x33; 32];
        let sender_pk = [0x44; 64];
        let sender_key =
            dsm::core::token::derive_canonical_balance_key(&policy_commit, &sender_pk, "ERA");
        let mut balances = HashMap::new();
        balances.insert(sender_key.clone(), Balance::from_state(50, [0u8; 32], 0));

        apply_transfer_debit(
            &mut balances,
            &policy_commit,
            &sender_pk,
            "ERA",
            20,
            [0x55; 32],
            7,
        )
        .expect("debit should succeed");

        let balance = balances
            .get(&sender_key)
            .expect("sender balance should remain present");
        assert_eq!(balance.value(), 30);
    }

    #[test]
    fn apply_transfer_debit_rejects_insufficient_balance() {
        let policy_commit = [0x33; 32];
        let sender_pk = [0x44; 64];
        let sender_key =
            dsm::core::token::derive_canonical_balance_key(&policy_commit, &sender_pk, "ERA");
        let mut balances = HashMap::new();
        balances.insert(sender_key, Balance::from_state(5, [0u8; 32], 0));

        let err = apply_transfer_debit(
            &mut balances,
            &policy_commit,
            &sender_pk,
            "ERA",
            20,
            [0x55; 32],
            7,
        )
        .expect_err("insufficient balance must fail");

        assert!(err.contains("insufficient ERA balance"));
    }
}
