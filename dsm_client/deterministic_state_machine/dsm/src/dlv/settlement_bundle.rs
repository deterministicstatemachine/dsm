// SPDX-License-Identifier: Apache-2.0

//! THE CANONICAL SETTLEMENT BUNDLE'S IDENTITY (Rev 15 Def 6.14, 6.17, 6.19;
//! amendments 2c-A, 2c-B, 2c-A.1).
//!
//! `B` is [`SettlementBundle`], the CCB object `0x000E` that `crate::ccb`
//! encodes; this module is the pure identity layer over its canonical bytes:
//!
//! - [`canon`] — `Canon(B)`, the bundle's CCB bytes.
//! - [`decode_canonical`] — bytes that must be `Canon(B)` for a live-schema
//!   bundle: strict decode, then `encode(decode(B)) == B` under the frozen
//!   encoder, nested successor included (2c-A.1 ruling 8). Returns the
//!   decoded bundle WITH the exact byte span of each transition's successor
//!   — `VDS.COMMON.10.a`'s supplied operand, never a re-encoding.
//! - [`bundle_digest`] — `b = H_dom(DSM/settlement-bundle, Canon(B))`.
//! - [`bundle_addr`] — `addr(B) = H_dom(DSM/storage-object, N ‖ b)` (Def 6.19).
//! - [`resource_key`] / [`key_set`] — `k_v = H_dom(DSM/binding-keyset, c_n)`
//!   and `K(B)`, the sorted distinct resource keys, derived ONLY from the
//!   transitions' `parent_binding`.
//!
//! **Protobuf is gone.** Until 2c-A.1 this module hashed prost bytes in
//! violation of registry §2.10; no prost-era `b` is a conformant identity and
//! none is grandfathered (the cut is a reprovision, not a migration).
//!
//! **The shape is field 1.** A close and a market bundle are told apart by
//! whether `market_terms` is present — decided at construction, read from
//! the first byte after the envelope, never inferred from a transition. The
//! `close_slot_commitment` that used to play discriminator is deleted: an
//! owner close's permitted continuation is `c_{n+1}` of the exact successor
//! it carries (2c-A.1 ruling 3).
//!
//! `c_n` already commits `vault_id` (it is a field of `V_n`), so the resource
//! key does not restate the vault id — supplying both would admit a
//! disagreeing pair. No I/O, no clock.

use crate::ccb::decode::{decode_settlement_bundle_canonical, DecodeError, DecodedSettlementBundle};
pub use crate::ccb::{BundleShape, ConsumedDlvTransition, SettlementBundle};
use crate::ccb::CcbError;
use crate::common::domain_tags::{TAG_DSM_BINDING_KEYSET, TAG_DSM_SETTLEMENT_BUNDLE};
use crate::crypto::blake3::dsm_domain_hasher;
use crate::storage_object::{immutable_addr, immutable_inner};

/// Why bytes are not a canonical bundle, or a bundle has no key set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BundleError {
    /// The bytes do not decode as a live-schema bundle, or do not re-encode
    /// to themselves under the frozen encoder.
    Noncanonical(DecodeError),
    /// The object could not be encoded — only reachable if a constructor's
    /// invariant was bypassed, which the private fields prevent.
    Encode(CcbError),
    /// Two transitions committed the same `c_n`, so their resource keys
    /// collide. Unreachable under beta's cardinality; kept for the general
    /// profile.
    DuplicateResourceKey,
}

impl core::fmt::Display for BundleError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            BundleError::Noncanonical(e) => {
                write!(f, "settlement bundle bytes are not canonical: {e}")
            }
            BundleError::Encode(e) => write!(f, "settlement bundle does not encode: {e}"),
            BundleError::DuplicateResourceKey => {
                write!(f, "two vaults share a committed parent state (c_n)")
            }
        }
    }
}
impl std::error::Error for BundleError {}

/// `Canon(B)` — the bundle's canonical bytes.
pub fn canon(b: &SettlementBundle) -> Result<Vec<u8>, BundleError> {
    b.encode().map_err(BundleError::Encode)
}

/// Decode bytes that must be the canonical encoding of a live-schema bundle.
/// The whole object round-trips under the frozen encoder, so a non-canonical
/// nested successor makes the bundle non-canonical before any verifier
/// reads it.
pub fn decode_canonical(bytes: &[u8]) -> Result<DecodedSettlementBundle, BundleError> {
    decode_settlement_bundle_canonical(bytes).map_err(BundleError::Noncanonical)
}

/// The bundle's shape. Field 1, and nothing else.
pub fn shape(b: &SettlementBundle) -> BundleShape {
    b.shape()
}

/// `b = H_dom(DSM/settlement-bundle, Canon(B))` — the immutable bundle identity.
pub fn bundle_digest(canon_bytes: &[u8]) -> [u8; 32] {
    immutable_inner(TAG_DSM_SETTLEMENT_BUNDLE, canon_bytes)
}

/// `addr(B) = H_dom(DSM/storage-object, DSM/settlement-bundle ‖ b)` — the
/// content address the bundle is stored and retrieved under.
pub fn bundle_addr(canon_bytes: &[u8]) -> [u8; 32] {
    immutable_addr(TAG_DSM_SETTLEMENT_BUNDLE, canon_bytes)
}

/// `k_v = H_dom(DSM/binding-keyset, c_n)` — one settlement resource key from a
/// vault's committed parent state (Def 6.17). The vault id is not restated.
pub fn resource_key(c_n: &[u8; 32]) -> [u8; 32] {
    let mut h = dsm_domain_hasher(TAG_DSM_BINDING_KEYSET);
    h.update(c_n);
    *h.finalize().as_bytes()
}

/// `K(B)` — the sorted distinct resource keys the bundle consumes, derived
/// ONLY from the transitions' committed parent states. Strictly ascending (a
/// duplicate `c_n` is refused), so it is a valid QuorumBind key set.
pub fn key_set(b: &SettlementBundle) -> Result<Vec<[u8; 32]>, BundleError> {
    let mut keys: Vec<[u8; 32]> = b
        .transitions()
        .iter()
        .map(|t| resource_key(&t.parent_binding))
        .collect();
    keys.sort_unstable();
    if keys.windows(2).any(|w| w[0] == w[1]) {
        return Err(BundleError::DuplicateResourceKey);
    }
    Ok(keys)
}

/// The permitted continuation a binding-final bundle fixes for its ONE vault
/// transition (2c-A.1 ruling 3): the market's exact prepared trader
/// successor, or the close's `c_{n+1}` — the commitment of the exact drained
/// successor the owner authorized, derived from the carried state.
pub fn permitted_continuation(b: &SettlementBundle) -> Result<[u8; 32], CcbError> {
    match (b.market_terms(), b.transitions().first()) {
        (Some(terms), _) => Ok(terms.trader_successor),
        (None, Some(t)) => crate::ccb::vault_state_commitment(&t.successor),
        // Unreachable: a bundle always carries a transition.
        (None, None) => Err(CcbError::TransitionCount { got: 0 }),
    }
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)] // test asserts; a failure here is the signal
mod tests {
    use super::*;
    use crate::ccb::settlement::fixtures;

    #[test]
    fn identity_is_over_the_ccb_bytes_and_the_shape_is_field_one() {
        let parent = [0xC0; 32];
        let close = fixtures::owner_close_bundle(parent, fixtures::successor(parent, 0, 0));
        let bytes = canon(&close).unwrap();
        assert_eq!(bytes[4], 0x00);
        assert_eq!(shape(&close), BundleShape::OwnerClose);
        assert_eq!(
            bundle_digest(&bytes),
            immutable_inner(TAG_DSM_SETTLEMENT_BUNDLE, &bytes)
        );
        assert_eq!(
            bundle_addr(&bytes),
            immutable_addr(TAG_DSM_SETTLEMENT_BUNDLE, &bytes)
        );

        let market = fixtures::market_bundle(parent, fixtures::successor(parent, 7, 9), [0x58; 32]);
        let mbytes = canon(&market).unwrap();
        assert_eq!(mbytes[4], 0x01);
        assert_eq!(shape(&market), BundleShape::Market);
        assert_ne!(bundle_digest(&mbytes), bundle_digest(&bytes));
    }

    #[test]
    fn decode_canonical_round_trips_and_records_the_successor_span() {
        let parent = [0xC1; 32];
        let v = fixtures::successor(parent, 3, 4);
        let market = fixtures::market_bundle(parent, v.clone(), [0x58; 32]);
        let bytes = canon(&market).unwrap();
        let d = decode_canonical(&bytes).unwrap();
        assert_eq!(d.bundle, market);
        assert_eq!(
            &bytes[d.successor_spans[0].clone()],
            v.encode().unwrap().as_slice()
        );
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(matches!(
            decode_canonical(&trailing),
            Err(BundleError::Noncanonical(DecodeError::TrailingBytes {
                extra: 1
            }))
        ));
    }

    #[test]
    fn the_key_set_is_derived_from_parent_binding_alone() {
        let parent = [0xC2; 32];
        let b = fixtures::owner_close_bundle(parent, fixtures::successor(parent, 0, 0));
        assert_eq!(key_set(&b).unwrap(), vec![resource_key(&parent)]);
        // The key does not depend on the successor or on the shape.
        let m = fixtures::market_bundle(parent, fixtures::successor(parent, 1, 2), [0x59; 32]);
        assert_eq!(key_set(&m).unwrap(), key_set(&b).unwrap());
    }

    #[test]
    fn the_permitted_continuation_is_the_trader_successor_or_the_closes_c_next() {
        let parent = [0xC3; 32];
        let v = fixtures::successor(parent, 0, 0);
        let close = fixtures::owner_close_bundle(parent, v.clone());
        assert_eq!(
            permitted_continuation(&close).unwrap(),
            crate::ccb::vault_state_commitment(&v).unwrap()
        );
        let market = fixtures::market_bundle(parent, fixtures::successor(parent, 5, 5), [0x5A; 32]);
        assert_eq!(
            permitted_continuation(&market).unwrap(),
            market.market_terms().unwrap().trader_successor
        );
    }

    #[test]
    fn a_prost_era_payload_is_not_a_bundle() {
        // Whatever the old identity was, bytes that do not open with the
        // 0x000E envelope are refused with the class named.
        let stale = [0x0A, 0x20, 0x01, 0x02, 0x03];
        assert!(matches!(
            decode_canonical(&stale),
            Err(BundleError::Noncanonical(DecodeError::WrongClass { .. }))
        ));
    }
}
