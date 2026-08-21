// SPDX-License-Identifier: Apache-2.0

//! Canonical commit bytes (CCB) — the production encoder.
//!
//! Implements `docs/papers/ccb-object-registry.md` for the transitive encoding
//! closure of `VaultStateV2` and nothing else. The registry is the authority;
//! this module is an implementation of it, written from that text rather than
//! the other way round. If the two disagree, the registry is right.
//!
//! ## Scope
//!
//! Exactly the classes `c_n` depends on:
//!
//! | Class | Object |
//! |---|---|
//! | `0x0001` | `VaultStateV2` |
//! | `0x0002` | `StorageSet` |
//! | `0x0004` | `EncumbranceClaim` |
//! | `0x0005` | `EncumbranceSet` |
//! | `0x0007` | `MarketPolicy` |
//! | `0x0009` | `ReleasePolicy` |
//! | `0x000A` | `FeePolicy` |
//!
//! The routing and settlement classes are deliberately absent. They are still
//! blocked in the registry, and a placeholder encoder for a class whose field
//! table does not exist would be exactly the "encoder defines the protocol"
//! failure the registry ordering exists to prevent.
//!
//! ## Not a decoder
//!
//! CCB is not self-describing: structure comes from `(object_class,
//! schema_version)` plus the registry, never from the byte stream. This module
//! only encodes. Parsing is implemented independently in the conformance test,
//! which is the point — a decoder here would share this module's assumptions.

use blake3::Hasher;

use crate::common::domain_tags::{
    TAG_DSM_STORAGE_SET_V1, TAG_DSM_VAULT_STATE, TAG_DSM_VAULT_STATE_PARENT_GENESIS_V2,
};
use crate::crypto::blake3::dsm_domain_hasher;

pub mod state;

pub use state::{
    EncumbranceClaim, EncumbranceSet, FeePolicy, MarketPolicy, ReleasePolicy, StorageSetMembers,
    VaultStateV2,
};

/// Object-class discriminants, from the single namespace of registry §3.
///
/// Frozen on first ship per §2.7: never recycled, never renumbered. `0x0003`
/// is burned — it was briefly a `StorageMemberId` class before §5.2 settled
/// that member ids are bare length-prefixed bytes with no envelope.
pub mod class {
    pub const VAULT_STATE_V2: u16 = 0x0001;
    pub const STORAGE_SET: u16 = 0x0002;
    pub const ENCUMBRANCE_CLAIM: u16 = 0x0004;
    pub const ENCUMBRANCE_SET: u16 = 0x0005;
    pub const MARKET_POLICY: u16 = 0x0007;
    pub const RELEASE_POLICY: u16 = 0x0009;
    pub const FEE_POLICY: u16 = 0x000A;
}

/// The beta families. Each is the only admissible member of its class at
/// `family_version = 1`.
pub mod family {
    /// Constant-product, exact-input market predicate.
    pub const CONSTANT_PRODUCT_EXACT_INPUT: u16 = 0x0001;
    /// Owner-local full close: both legs to zero, vault retired.
    pub const OWNER_LOCAL_FULL_CLOSE: u16 = 0x0001;
    pub const BETA_VERSION: u16 = 1;
}

/// The fixed denominator of the beta fee rational, per §3.4's exact-rational
/// allowance. `fee_bps` is interpreted as `fee_bps / FEE_DENOMINATOR`.
pub const FEE_DENOMINATOR: u32 = 10_000;

/// A logical object that cannot be encoded, because encoding it would produce
/// bytes the registry does not authorize.
///
/// Every variant is a validity condition rather than a normalization
/// opportunity. The encoder refuses instead of repairing: silently sorting an
/// unordered token pair, or collapsing a duplicate set element, would map two
/// distinct logical inputs onto one byte string, which is precisely what
/// Req 3.2 forbids.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CcbError {
    /// A set contained two elements with equal encodings.
    DuplicateSetElement { class: u16 },
    /// A storage set had no members, or a member id was empty.
    EmptyStorageSetOrMember,
    /// `token_a_policy_commit` was not strictly less than `token_b`.
    TokenPairNotStrictlyOrdered,
    /// `fee_bps` was at or above the denominator.
    FeeAtOrAboveDenominator { fee_bps: u32 },
    /// A family id or version outside the beta profile.
    UnknownFamily {
        class: u16,
        family_id: u16,
        family_version: u16,
    },
    /// A length did not fit the 4-byte prefix the format allows.
    LengthOverflow,
}

impl core::fmt::Display for CcbError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            CcbError::DuplicateSetElement { class } => write!(
                f,
                "class {class:#06x}: duplicate set element — duplicates are invalid, not deduplicated"
            ),
            CcbError::EmptyStorageSetOrMember => {
                write!(f, "storage set: at least one member, and no empty member id")
            }
            CcbError::TokenPairNotStrictlyOrdered => write!(
                f,
                "market policy: token_a must be strictly less than token_b; \
                 the order is a validity condition, not a normalization"
            ),
            CcbError::FeeAtOrAboveDenominator { fee_bps } => write!(
                f,
                "fee policy: fee_bps {fee_bps} is at or above {FEE_DENOMINATOR}, \
                 which leaves the pricing rule a zero or negative effective numerator"
            ),
            CcbError::UnknownFamily { class, family_id, family_version } => write!(
                f,
                "class {class:#06x}: family {family_id:#06x} version {family_version} \
                 is not the beta profile"
            ),
            CcbError::LengthOverflow => write!(f, "length does not fit a 4-byte prefix"),
        }
    }
}

impl std::error::Error for CcbError {}

// ── Primitive writers, registry §2.2 ────────────────────────────────────────

/// The §2.1 envelope: `u16_be(class) ‖ u16_be(schema_version)`.
///
/// Every conformant object begins with this. `StorageSet` is the one class
/// that does not: see [`StorageSetMembers::encode`], which starts straight at
/// the count because its shipping preimage already begins with the domain tag
/// and a `0x00` separator.
pub(crate) fn push_envelope(out: &mut Vec<u8>, object_class: u16, schema_version: u16) {
    out.extend_from_slice(&object_class.to_be_bytes());
    out.extend_from_slice(&schema_version.to_be_bytes());
}

pub(crate) fn push_u16(out: &mut Vec<u8>, v: u16) {
    out.extend_from_slice(&v.to_be_bytes());
}

pub(crate) fn push_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_be_bytes());
}

pub(crate) fn push_u64(out: &mut Vec<u8>, v: u64) {
    out.extend_from_slice(&v.to_be_bytes());
}

/// `digest32`: exactly 32 raw bytes, no length prefix. Distinct from `bytes`
/// on purpose — a redundant prefix is a divergence a second implementation
/// might reasonably omit.
pub(crate) fn push_digest32(out: &mut Vec<u8>, v: &[u8; 32]) {
    out.extend_from_slice(v);
}

/// `bytes`: `u32_be(len) ‖ raw`.
pub(crate) fn push_bytes(out: &mut Vec<u8>, v: &[u8]) -> Result<(), CcbError> {
    let len = u32::try_from(v.len()).map_err(|_| CcbError::LengthOverflow)?;
    push_u32(out, len);
    out.extend_from_slice(v);
    Ok(())
}

/// An absent optional field: the marker alone. Never skipped — skipping would
/// shift the following field and let two logical objects share a byte string.
pub(crate) fn push_absent(out: &mut Vec<u8>) {
    out.push(0x00);
}

/// A present optional field: marker then value.
pub(crate) fn push_present(out: &mut Vec<u8>) {
    out.push(0x01);
}

/// `c_n = H(DSM/vault-state ‖ CCB(V_n))`.
pub fn vault_state_commitment(state: &VaultStateV2) -> Result<[u8; 32], CcbError> {
    let ccb = state.encode()?;
    let mut h = dsm_domain_hasher(TAG_DSM_VAULT_STATE);
    h.update(&ccb);
    Ok(*h.finalize().as_bytes())
}

/// `h_0 = H(DSM/vault-state-parent/genesis/v2 ‖ vault_id)`.
///
/// Commits the vault identity and nothing else. Birth reserves, `S` and `q`
/// are already members of `V_0`, so folding them in here would blur a field
/// whose only role is the predecessor edge.
pub fn genesis_parent_commitment(vault_id: &[u8; 32]) -> [u8; 32] {
    let mut h = dsm_domain_hasher(TAG_DSM_VAULT_STATE_PARENT_GENESIS_V2);
    h.update(vault_id);
    *h.finalize().as_bytes()
}

/// `h_n` for the successor of `parent`: `c_{n-1}`.
pub fn parent_state_commitment_for_successor_of(
    parent: &VaultStateV2,
) -> Result<[u8; 32], CcbError> {
    vault_state_commitment(parent)
}

/// `storage_set_id = H(TAG ‖ 0x00 ‖ CCB-of-the-frozen-layout)`.
///
/// The tag and its `0x00` separator come from `dsm_domain_hasher`, which is
/// why this class carries no envelope: the shipping preimage already starts
/// with them, and adding a discriminant would change every deployed vault's
/// committed set id.
pub fn storage_set_id(members: &StorageSetMembers) -> Result<[u8; 32], CcbError> {
    let body = members.encode()?;
    let mut h: Hasher = dsm_domain_hasher(TAG_DSM_STORAGE_SET_V1);
    h.update(&body);
    Ok(*h.finalize().as_bytes())
}
