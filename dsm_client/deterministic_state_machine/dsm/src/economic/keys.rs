// SPDX-License-Identifier: Apache-2.0

//! The four `R_econ` key derivations.
//!
//! Each is the **only** place its key class is computed;
//! [`super::state::EconomicLeafState::leaf_key`] dispatches here rather than
//! repeating the hash, so a derivation cannot drift between the producer that
//! writes a leaf and the verifier that proves one.
//!
//! Every derivation binds `G ‖ DevID` first. That is what makes the key space
//! per-identity by construction: a trader cannot compute — let alone claim — a
//! position in another identity's economic tree, regardless of what it knows
//! about that identity's assets. All inputs are fixed-width 32-byte digests
//! (or a derived one), so the concatenation is unambiguous without length
//! prefixes.

use crate::common::domain_tags::{
    TAG_DSM_ECONOMIC_BALANCE_KEY, TAG_DSM_ECONOMIC_CONSUMED_SOURCE_KEY,
    TAG_DSM_ECONOMIC_SETTLEMENT_RECEIPT_KEY, TAG_DSM_ECONOMIC_VAULT_RESERVE_KEY,
};
use crate::crypto::blake3::dsm_domain_hasher;
use crate::crypto::domain::TaggedHashDomain;

fn derive(
    tag: TaggedHashDomain<'_>,
    genesis: &[u8; 32],
    device_id: &[u8; 32],
    rest: &[&[u8; 32]],
) -> [u8; 32] {
    let mut h = dsm_domain_hasher(tag);
    h.update(genesis);
    h.update(device_id);
    for part in rest {
        h.update(*part);
    }
    *h.finalize().as_bytes()
}

/// `H_dom(DSM/economic-balance-key/v1, G ‖ DevID ‖ policy_commit)`.
pub fn balance_key(genesis: &[u8; 32], device_id: &[u8; 32], policy_commit: &[u8; 32]) -> [u8; 32] {
    derive(
        TAG_DSM_ECONOMIC_BALANCE_KEY,
        genesis,
        device_id,
        &[policy_commit],
    )
}

/// `H_dom(DSM/economic-vault-reserve-key/v1, G ‖ DevID ‖ vault_id ‖ policy_commit)`.
pub fn vault_reserve_key(
    genesis: &[u8; 32],
    device_id: &[u8; 32],
    vault_id: &[u8; 32],
    policy_commit: &[u8; 32],
) -> [u8; 32] {
    derive(
        TAG_DSM_ECONOMIC_VAULT_RESERVE_KEY,
        genesis,
        device_id,
        &[vault_id, policy_commit],
    )
}

/// `H_dom(DSM/economic-settlement-receipt-key/v1, G ‖ DevID ‖ vault_id ‖ receipt_id)`.
pub fn settlement_receipt_key(
    genesis: &[u8; 32],
    device_id: &[u8; 32],
    vault_id: &[u8; 32],
    receipt_id: &[u8; 32],
) -> [u8; 32] {
    derive(
        TAG_DSM_ECONOMIC_SETTLEMENT_RECEIPT_KEY,
        genesis,
        device_id,
        &[vault_id, receipt_id],
    )
}

/// `H_dom(DSM/economic-consumed-source-key/v1, G ‖ DevID ‖ source_id)`.
pub fn consumed_source_key(
    genesis: &[u8; 32],
    device_id: &[u8; 32],
    source_id: &[u8; 32],
) -> [u8; 32] {
    derive(
        TAG_DSM_ECONOMIC_CONSUMED_SOURCE_KEY,
        genesis,
        device_id,
        &[source_id],
    )
}
