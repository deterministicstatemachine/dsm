// SPDX-License-Identifier: Apache-2.0

//! The five `R_econ` key derivations.
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
    TAG_DSM_ECONOMIC_BALANCE_KEY, TAG_DSM_ECONOMIC_BUNDLE_ACCEPTANCE_KEY,
    TAG_DSM_ECONOMIC_CONSUMED_SOURCE_KEY, TAG_DSM_ECONOMIC_SETTLEMENT_RECEIPT_KEY,
    TAG_DSM_ECONOMIC_VAULT_RESERVE_KEY,
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

/// `H_dom(DSM/economic-bundle-acceptance-key/v1, G ‖ DevID ‖ economic_operation_id)`.
///
/// Amendment 2c-D §5, ruling D3. The one derivation here whose identifying
/// field is not a name the operation chose but the identity of the
/// **transition** — `economic_operation_id` is itself
/// `H_dom(DSM/economic-operation-id/dsm/v2, G ‖ DevID ‖ C_dsm+)`, recomputed
/// and required to match rather than trusted.
///
/// That indirection is deliberate and is the only reason the leaf is
/// admissible at all. Its content commits `b`, which no `DlvSettle` can name —
/// `b` commits `trader_successor`, the chain tip taken over the operation's
/// own bytes — so the content-to-operation binding every other leaf gets from
/// `verify_operation_write_set` structurally cannot apply here. Keying on the
/// accepted transition is what keeps the position operation-derived when the
/// content cannot be, and it is why one operation applied to two different
/// parents yields two ids and occupies two positions rather than colliding.
///
/// **Passing the raw `C_dsm+` here would be wrong**, not merely different:
/// `economic_operation_id` is the boundary at which DSM transition context
/// enters this tree, and reaching past it would oblige every generic
/// `leaf_key` caller to hold context it has no reason to.
pub fn bundle_acceptance_key(
    genesis: &[u8; 32],
    device_id: &[u8; 32],
    economic_operation_id: &[u8; 32],
) -> [u8; 32] {
    derive(
        TAG_DSM_ECONOMIC_BUNDLE_ACCEPTANCE_KEY,
        genesis,
        device_id,
        &[economic_operation_id],
    )
}
