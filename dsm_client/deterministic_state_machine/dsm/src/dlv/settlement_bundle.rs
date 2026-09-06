// SPDX-License-Identifier: Apache-2.0

//! THE CANONICAL SETTLEMENT BUNDLE (Rev 15 Def 6.14, 6.17, 6.19; Req 6.15).
//!
//! A [`SettlementBundleV1`] is the complete immutable object `B` a QuorumBind
//! transaction binds. It carries everything needed to verify the selected route
//! and recover the DLV decision **without a fresh constructor signature**
//! (Req 6.15): the committed storage set and `q`, the intent commitment `I` and
//! route-set commitment `X`, the selected route, the exact initiating-trader
//! parent and successor, the complete sorted per-vault transitions `{T_v}`,
//! proof material `{P_v}`, the bundle signatures, and the recovery material.
//!
//! This module is the pure canonical layer of `B`:
//!
//! - [`canon`] — the canonical bytes `Canon(B)` (the transitions must be sorted
//!   strictly ascending by `vault_id`, and the message must re-encode to
//!   itself).
//! - [`bundle_digest`] — `b = H(DSM/settlement-bundle ‖ Canon(B))` (Def 6.14).
//! - [`bundle_addr`] — `addr(B) = H(DSM/storage-object ‖ namespace ‖ b)`
//!   (Def 6.19), via the shared immutable-object construction.
//! - [`resource_key`] / [`key_set`] — `k_v = H(DSM/binding-keyset ‖ c_n)` and
//!   `K(B)`, the sorted distinct resource keys (Def 6.17), derived **only** from
//!   the canonical bundle's committed parent states.
//!
//! `c_n` already commits `vault_id` (it is a field of `V_n`), so the resource
//! key does not restate the vault id — supplying both would admit a disagreeing
//! pair. No I/O, no clock.

use crate::common::domain_tags::{
    TAG_DSM_BINDING_KEYSET, TAG_DSM_DLV_CLOSE_COMMIT, TAG_DSM_SETTLEMENT_BUNDLE,
};
use crate::crypto::blake3::dsm_domain_hasher;
use crate::storage_object::{immutable_addr, immutable_inner};
use crate::types::proto as generated;
use prost::Message;

/// The only accepted bundle version. A canonical object is frozen on deploy; a
/// new shape is a new version, never a silent field change.
pub const SETTLEMENT_BUNDLE_VERSION_V1: u32 = 1;

/// Why a bundle is not well-formed. Every variant is fail-closed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BundleError {
    /// `version` is not [`SETTLEMENT_BUNDLE_VERSION_V1`].
    Version(u32),
    /// A fixed-width field is not 32 bytes.
    Width { field: &'static str, got: usize },
    /// A bundle consumes at least one vault.
    NoTransitions,
    /// The transitions are not strictly ascending by `vault_id` (unsorted or a
    /// duplicate vault).
    TransitionsNotSorted { at: usize },
    /// Two vaults committed the same `c_n`, so their resource keys collide.
    DuplicateResourceKey,
    /// The bytes decode but do not re-encode to themselves.
    Noncanonical,
    /// A close transition rides beside another transition. A bundle is either a
    /// market bundle or a single owner-close; see [`shape`].
    MixedShape { transitions: usize },
}

impl core::fmt::Display for BundleError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            BundleError::Version(v) => write!(f, "unsupported settlement-bundle version {v}"),
            BundleError::Width { field, got } => {
                write!(f, "field {field} is {got} bytes, not 32")
            }
            BundleError::NoTransitions => write!(f, "a settlement bundle consumes no vault"),
            BundleError::TransitionsNotSorted { at } => {
                write!(f, "vault transitions are not strictly ascending at {at}")
            }
            BundleError::DuplicateResourceKey => {
                write!(f, "two vaults share a committed parent state (c_n)")
            }
            BundleError::Noncanonical => write!(f, "settlement bundle bytes are not canonical"),
            BundleError::MixedShape { transitions } => write!(
                f,
                "a close transition rides in a {transitions}-transition bundle; a close is alone"
            ),
        }
    }
}
impl std::error::Error for BundleError {}

fn need32(field: &'static str, v: &[u8]) -> Result<[u8; 32], BundleError> {
    <[u8; 32]>::try_from(v).map_err(|_| BundleError::Width {
        field,
        got: v.len(),
    })
}

/// Validate structural well-formedness: version, fixed-width fields, at least
/// one transition, and transitions strictly ascending by `vault_id`.
pub fn validate(b: &generated::SettlementBundleV1) -> Result<(), BundleError> {
    if b.version != SETTLEMENT_BUNDLE_VERSION_V1 {
        return Err(BundleError::Version(b.version));
    }
    need32("storage_set_id", &b.storage_set_id)?;
    need32("intent_commitment", &b.intent_commitment)?;
    need32("route_set_commitment", &b.route_set_commitment)?;
    need32("trader_parent", &b.trader_parent)?;
    need32("trader_successor", &b.trader_successor)?;
    if b.vault_transitions.is_empty() {
        return Err(BundleError::NoTransitions);
    }
    for (i, t) in b.vault_transitions.iter().enumerate() {
        need32("vault_id", &t.vault_id)?;
        need32("parent_state_commitment", &t.parent_state_commitment)?;
        need32("parent_reserves_digest", &t.parent_reserves_digest)?;
        need32("successor_ccb", &t.successor_ccb)?;
        if i > 0 && b.vault_transitions[i - 1].vault_id >= t.vault_id {
            return Err(BundleError::TransitionsNotSorted { at: i });
        }
    }
    shape_of(b)?;
    Ok(())
}

/// The two shapes a bundle may take. Determined entirely by CONTENT — a
/// declared `kind` field would be a second statement of what `successor_ccb`
/// already fixes, and two statements can disagree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BundleShape {
    /// One or more market transitions and no close.
    Market,
    /// Exactly one transition, and it is an owner close.
    OwnerClose,
}

/// Is this transition an owner close? `x_close` is a public derivation anyone
/// can recompute, so this is a DISCRIMINATOR and never an authorization — what
/// makes a close real is the owner signature over its exact successor
/// ([`crate::dlv::close_authorization`]).
pub fn is_close_transition(t: &generated::VaultTransitionV1) -> bool {
    let (Ok(vault), Ok(successor)) = (
        need32("vault_id", &t.vault_id),
        need32("successor_ccb", &t.successor_ccb),
    ) else {
        return false;
    };
    successor == close_slot_commitment(&vault, t.parent_generation)
}

/// Fields are already width- and order-checked by the caller.
fn shape_of(b: &generated::SettlementBundleV1) -> Result<BundleShape, BundleError> {
    let closes = b
        .vault_transitions
        .iter()
        .filter(|t| is_close_transition(t))
        .count();
    if closes == 0 {
        return Ok(BundleShape::Market);
    }
    // A CLOSE IS ALONE. `bundle_signatures[0]` authorizes ONE close successor,
    // and in a mixed bundle there is no deterministic signature-to-transition
    // mapping — so a genuine close signature for V1 would ride beside a market
    // leg on V2 that nothing authorized. Rather than invent a mapping, the
    // canonical layer removes the class: a mixed bundle cannot be encoded,
    // stored, fetched, or bound.
    if closes == b.vault_transitions.len() && closes == 1 {
        return Ok(BundleShape::OwnerClose);
    }
    Err(BundleError::MixedShape {
        transitions: b.vault_transitions.len(),
    })
}

/// The bundle's shape, after full validation.
pub fn shape(b: &generated::SettlementBundleV1) -> Result<BundleShape, BundleError> {
    validate(b)?;
    shape_of(b)
}

/// The deterministic `x` a CLOSE commits its parent generation to:
/// `H_dom(DSM/dlv-close-commit, vault_id ‖ u64_be(parent_sequence))`.
///
/// Recomputable by anyone, and that is fine: it tells a composer WHICH KIND of
/// consumer owns a generation, nothing about who authorized it. A stranger can
/// compute this value and bind a bundle carrying it; the result must be a
/// refusal to fold, never a vault that appears closed. See
/// [`crate::dlv::close_authorization`] for the proof that does the work.
pub fn close_slot_commitment(vault_id: &[u8; 32], parent_sequence: u64) -> [u8; 32] {
    let mut h = dsm_domain_hasher(TAG_DSM_DLV_CLOSE_COMMIT);
    h.update(vault_id);
    h.update(&parent_sequence.to_be_bytes());
    *h.finalize().as_bytes()
}

/// `Canon(B)` — the canonical bytes. The bundle must be well-formed and must
/// re-encode to itself (unknown fields, non-minimal encodings, and duplicates
/// all fail).
pub fn canon(b: &generated::SettlementBundleV1) -> Result<Vec<u8>, BundleError> {
    validate(b)?;
    let bytes = b.encode_to_vec();
    let re = generated::SettlementBundleV1::decode(bytes.as_slice())
        .map_err(|_| BundleError::Noncanonical)?;
    if re.encode_to_vec() != bytes {
        return Err(BundleError::Noncanonical);
    }
    Ok(bytes)
}

/// Decode bytes that must be the canonical encoding of a live-version bundle.
pub fn decode_canonical(bytes: &[u8]) -> Result<generated::SettlementBundleV1, BundleError> {
    let b = generated::SettlementBundleV1::decode(bytes).map_err(|_| BundleError::Noncanonical)?;
    // canon() re-validates and re-encodes; equality proves canonical.
    if canon(&b)? != bytes {
        return Err(BundleError::Noncanonical);
    }
    Ok(b)
}

/// `b = H(DSM/settlement-bundle ‖ Canon(B))` — the immutable bundle identity.
pub fn bundle_digest(canon_bytes: &[u8]) -> [u8; 32] {
    immutable_inner(TAG_DSM_SETTLEMENT_BUNDLE, canon_bytes)
}

/// `addr(B) = H(DSM/storage-object ‖ DSM/settlement-bundle ‖ b)` — the content
/// address the bundle is stored and retrieved under.
pub fn bundle_addr(canon_bytes: &[u8]) -> [u8; 32] {
    immutable_addr(TAG_DSM_SETTLEMENT_BUNDLE, canon_bytes)
}

/// `k_v = H(DSM/binding-keyset ‖ c_n)` — one settlement resource key from a
/// vault's committed parent state (Def 6.17). The vault id is not restated.
pub fn resource_key(c_n: &[u8; 32]) -> [u8; 32] {
    let mut h = dsm_domain_hasher(TAG_DSM_BINDING_KEYSET);
    h.update(c_n);
    *h.finalize().as_bytes()
}

/// `K(B)` — the sorted distinct resource keys the bundle consumes, derived
/// ONLY from the canonical bundle's committed parent states. Strictly ascending
/// (a duplicate `c_n` is refused), so it is a valid QuorumBind key set.
pub fn key_set(b: &generated::SettlementBundleV1) -> Result<Vec<[u8; 32]>, BundleError> {
    validate(b)?;
    let mut keys: Vec<[u8; 32]> = Vec::with_capacity(b.vault_transitions.len());
    for t in &b.vault_transitions {
        let c_n = need32("parent_state_commitment", &t.parent_state_commitment)?;
        keys.push(resource_key(&c_n));
    }
    keys.sort_unstable();
    for w in keys.windows(2) {
        if w[0] == w[1] {
            return Err(BundleError::DuplicateResourceKey);
        }
    }
    Ok(keys)
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)] // test asserts; a failure here is the signal
mod tests {
    use super::*;

    fn transition(vault: u8, c_n: u8) -> generated::VaultTransitionV1 {
        generated::VaultTransitionV1 {
            vault_id: vec![vault; 32],
            parent_generation: 3,
            parent_state_commitment: vec![c_n; 32],
            parent_reserves_digest: vec![0x0A; 32],
            successor_ccb: vec![0x5C; 32],
            reserve_deltas: b"deltas".to_vec(),
            witnesses: vec![b"w1".to_vec()],
        }
    }

    fn bundle(transitions: Vec<generated::VaultTransitionV1>) -> generated::SettlementBundleV1 {
        generated::SettlementBundleV1 {
            version: SETTLEMENT_BUNDLE_VERSION_V1,
            storage_set_id: vec![0x6B; 32],
            q: 2,
            intent_commitment: vec![0x1D; 32],
            route_set_commitment: vec![0x0C; 32],
            selected_route: b"route".to_vec(),
            trader_parent: vec![0xAA; 32],
            trader_successor: vec![0xBB; 32],
            vault_transitions: transitions,
            proof_material: vec![b"P1".to_vec()],
            bundle_signatures: vec![b"sig".to_vec()],
            recovery_material: b"recovery".to_vec(),
        }
    }

    /// A transition whose successor IS the public close derivation.
    fn close_transition(vault: u8, c_n: u8, gen: u64) -> generated::VaultTransitionV1 {
        let mut t = transition(vault, c_n);
        t.parent_generation = gen;
        t.successor_ccb = close_slot_commitment(&[vault; 32], gen).to_vec();
        t
    }

    #[test]
    fn a_bundle_with_no_close_transition_is_a_market_bundle() {
        let b = bundle(vec![transition(1, 0x11), transition(2, 0x22)]);
        assert_eq!(shape(&b), Ok(BundleShape::Market));
    }

    #[test]
    fn a_lone_close_transition_is_an_owner_close_bundle() {
        let b = bundle(vec![close_transition(1, 0x11, 3)]);
        assert_eq!(shape(&b), Ok(BundleShape::OwnerClose));
    }

    /// THE BAN. A genuine owner close of V1 must not be able to carry a market
    /// leg on V2: `bundle_signatures[0]` authorizes one successor, and in a
    /// mixed bundle there is no deterministic mapping from that signature to a
    /// transition — so V2 would fold on a signature that never named it.
    /// Refused at the CANONICAL layer, so such a bundle cannot even be encoded.
    #[test]
    fn a_close_riding_beside_a_market_leg_is_refused_by_the_canonical_layer() {
        let mixed = bundle(vec![close_transition(1, 0x11, 3), transition(2, 0x22)]);
        assert_eq!(
            shape(&mixed),
            Err(BundleError::MixedShape { transitions: 2 })
        );
        assert_eq!(
            canon(&mixed),
            Err(BundleError::MixedShape { transitions: 2 })
        );
        // And therefore it has no identity and no key set either.
        assert!(key_set(&mixed).is_err());
    }

    /// Two closes together are refused for the same reason as a close beside a
    /// market leg: one signature, two successors.
    #[test]
    fn two_closes_in_one_bundle_are_refused() {
        let two = bundle(vec![
            close_transition(1, 0x11, 3),
            close_transition(2, 0x22, 3),
        ]);
        assert_eq!(canon(&two), Err(BundleError::MixedShape { transitions: 2 }));
    }

    /// The discriminator binds the generation as well as the vault, so a close
    /// value computed for another generation does not read as a close here.
    #[test]
    fn the_close_discriminator_is_bound_to_vault_and_generation() {
        let mut t = transition(1, 0x11);
        t.parent_generation = 3;
        t.successor_ccb = close_slot_commitment(&[1; 32], 4).to_vec();
        assert!(!is_close_transition(&t));
        t.successor_ccb = close_slot_commitment(&[2; 32], 3).to_vec();
        assert!(!is_close_transition(&t));
    }

    #[test]
    fn canon_round_trips_and_the_address_is_the_storage_object_of_the_digest() {
        let b = bundle(vec![transition(1, 0x11), transition(2, 0x22)]);
        let c = canon(&b).unwrap();
        assert_eq!(decode_canonical(&c).unwrap(), b);
        // b and addr(B) match the spec construction directly.
        assert_eq!(
            bundle_digest(&c),
            immutable_inner(TAG_DSM_SETTLEMENT_BUNDLE, &c)
        );
        assert_eq!(
            bundle_addr(&c),
            immutable_addr(TAG_DSM_SETTLEMENT_BUNDLE, &c)
        );
        // Different bytes => different identity.
        let b2 = bundle(vec![transition(1, 0x11), transition(2, 0x23)]);
        assert_ne!(bundle_digest(&canon(&b2).unwrap()), bundle_digest(&c));
    }

    #[test]
    fn a_bad_version_or_width_or_empty_bundle_is_refused() {
        let mut bad = bundle(vec![transition(1, 0x11)]);
        bad.version = 2;
        assert_eq!(canon(&bad), Err(BundleError::Version(2)));
        let mut wide = bundle(vec![transition(1, 0x11)]);
        wide.trader_parent = vec![0xAA; 31];
        assert!(matches!(canon(&wide), Err(BundleError::Width { .. })));
        let empty = bundle(vec![]);
        assert_eq!(canon(&empty), Err(BundleError::NoTransitions));
    }

    #[test]
    fn transitions_must_be_strictly_ascending_by_vault_id() {
        let unsorted = bundle(vec![transition(2, 0x22), transition(1, 0x11)]);
        assert!(matches!(
            canon(&unsorted),
            Err(BundleError::TransitionsNotSorted { .. })
        ));
        let dup_vault = bundle(vec![transition(1, 0x11), transition(1, 0x22)]);
        assert!(matches!(
            canon(&dup_vault),
            Err(BundleError::TransitionsNotSorted { .. })
        ));
    }

    #[test]
    fn key_set_is_sorted_distinct_resource_keys_over_c_n() {
        let b = bundle(vec![transition(1, 0x11), transition(2, 0x22)]);
        let ks = key_set(&b).unwrap();
        assert_eq!(ks.len(), 2);
        // Strictly ascending (a valid QuorumBind key set).
        assert!(ks[0] < ks[1]);
        // Derived from c_n only — the same c_n gives the same key regardless of
        // vault_id, and two vaults sharing c_n are refused.
        assert!(ks.contains(&resource_key(&[0x11; 32])));
        let shared_cn = bundle(vec![transition(1, 0x11), transition(2, 0x11)]);
        assert_eq!(key_set(&shared_cn), Err(BundleError::DuplicateResourceKey));
    }
}
