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
    TAG_DSM_STORAGE_SET, TAG_DSM_VAULT_STATE, TAG_DSM_VAULT_STATE_PARENT_GENESIS_V2,
};
use crate::crypto::blake3::dsm_domain_hasher;

pub mod decode;
pub mod devtree;
pub mod genesis;
pub mod state;

pub use decode::{
    decode_delegation, decode_genesis_params, decode_transition, decode_vault_state, DecodeError,
};
pub use devtree::{
    delegation_genesis_sentinel, role, transition_genesis_sentinel, DeviceTreeRootTransition,
    RootProgressionDelegation,
};
pub use genesis::{genesis_v3_commitment, sigalg, GenesisParamsV3};
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
    /// Substrate class — the Genesis v3 parameter set (registry §5.15).
    pub const GENESIS_PARAMS_V3: u16 = 0x0018;
    /// Substrate class — GRK-signed root-progression delegation (§5.16).
    pub const ROOT_PROGRESSION_DELEGATION: u16 = 0x0019;
    /// Substrate class — delegate-signed Device Tree root transition (§5.17).
    pub const DEVICE_TREE_ROOT_TRANSITION: u16 = 0x001A;

    // ── Online economic root `R_econ` ───────────────────────────────────
    //
    // Encoders live in `crate::economic`, not in this module: `ccb` is the
    // transitive encoding closure of `c_n`, and none of these are reachable
    // from a `VaultStateV2`. The DISCRIMINANTS live here because §3 is a
    // single namespace — a class number allocated in a second place is a
    // class number allocated twice.

    /// The signed body of an economic root claim.
    pub const ECONOMIC_ROOT_CLAIM_BODY: u16 = 0x001B;
    /// The manifest an economic root claim names, and the only edge from a
    /// claim into its evidence DAG.
    pub const ECONOMIC_ADMISSION_MANIFEST: u16 = 0x001C;
    /// One leaf's pre-state, post-state and 256 siblings.
    pub const ECONOMIC_LEAF_MUTATION: u16 = 0x001E;

    // Leaf-state classes. The class is what says which key derivation
    // applies, so a mutation cannot claim a balance state at a reserve key.
    pub const ECONOMIC_BALANCE_STATE: u16 = 0x001F;
    pub const ECONOMIC_VAULT_RESERVE_STATE: u16 = 0x0020;
    pub const ECONOMIC_SETTLEMENT_RECEIPT_STATE: u16 = 0x0021;
    pub const ECONOMIC_CONSUMED_SOURCE_STATE: u16 = 0x0022;

    /// A complete pre-root → post-root economic transition, carrying its
    /// mutations and its inline credit sources.
    pub const ECONOMIC_TRANSITION_WITNESS: u16 = 0x001D;

    // Credit-provenance classes. Six arms, closed: a credit that names none
    // of them is unfunded, and there is deliberately no `Custom`.
    pub const CREDIT_SOURCE_AUTHORIZED_ISSUANCE: u16 = 0x0023;
    pub const CREDIT_SOURCE_SAME_TRANSITION_MOVE: u16 = 0x0024;
    pub const CREDIT_SOURCE_VALIDATED_PEER_DEBIT: u16 = 0x0025;
    pub const CREDIT_SOURCE_DLV_RESERVE_CONSUMPTION: u16 = 0x0026;
    pub const CREDIT_SOURCE_VALIDATED_DLV_SETTLEMENT_PAYMENT: u16 = 0x0027;
    pub const CREDIT_SOURCE_VERIFIED_OFFLINE_REENTRY: u16 = 0x0028;

    /// The recipient credit of a consumed ERA faucet ticket — the seventh
    /// provenance arm. Scoped to one network through its `faucet_id`.
    pub const CREDIT_SOURCE_VALIDATED_FAUCET_DISTRIBUTION: u16 = 0x0030;
}

/// Discriminants **allocated but not encodable** — see [`class`] for the ones
/// that are.
///
/// Allocation buys exactly one thing: the number cannot be handed out twice.
/// It confers no wire format. These classes have no field table, therefore no
/// canonical bytes, therefore nothing to hash-address, nest or sign. A
/// `0x001D` "witness" assembled by a caller today would be that caller's
/// struct layout, not the protocol's — and once something hash-addresses it,
/// the layout is burned by accident rather than by decision. That inversion is
/// what this module's header refuses, and reservation is how the refusal is
/// made structural instead of advisory.
///
/// They live in a **separate module from [`class`] on purpose**. A
/// [`CcbObject`] impl needs a `CLASS` constant, so writing an encoder for one
/// of these requires physically moving the constant into `class` — a
/// deliberate, reviewable diff that arrives with the field table that earns
/// it. Reaching into `reserved` from a `CcbObject` impl is caught by
/// `reserved_classes_have_no_encoder`.
pub mod reserved {
    /// The authorization an `AuthorizedIssuance` credit resolves against.
    ///
    /// Still reserved after the provenance wire freeze, and deliberately. A
    /// field table for this object would encode **who may issue what**, and
    /// this protocol has no authenticated issuance predicate — that absence is
    /// the finding behind the builtin ERA/dBTC mint repair, where the
    /// accepting layer now refuses builtin issuance precisely because no such
    /// predicate exists to validate against.
    ///
    /// Nothing is blocked by the reservation: `0x0023` references its
    /// authorization by **address**, so the credit source is complete on the
    /// wire while the object behind the address stays undefined until the
    /// predicate it encodes does.
    pub const ISSUANCE_AUTHORIZATION_BODY: u16 = 0x0029;

    // The offline-account boundary and portable-anchor objects, held for the
    // Step-5 offline integration cut. Pre-assigned by the frozen plan; made
    // STRUCTURAL here so a later PR cannot allocate one of these numbers
    // because "the plan said it was reserved" while the code said nothing.
    pub const OFFLINE_LOAD_BOUNDARY_BODY: u16 = 0x002A;
    pub const OFFLINE_UNLOAD_BOUNDARY_BODY: u16 = 0x002B;
    pub const OFFLINE_SPEND_STEP_EVIDENCE: u16 = 0x002C;
    pub const OFFLINE_BRANCH_EVIDENCE: u16 = 0x002D;
    pub const PORTABLE_ANCHOR_ENROLLMENT_BODY: u16 = 0x002E;
    pub const PORTABLE_HARDWARE_ENROLLMENT_BODY: u16 = 0x002F;

    /// Every reserved discriminant, so the set can be asserted against rather
    /// than restated.
    pub const ALL: &[u16] = &[
        ISSUANCE_AUTHORIZATION_BODY,
        OFFLINE_LOAD_BOUNDARY_BODY,
        OFFLINE_UNLOAD_BOUNDARY_BODY,
        OFFLINE_SPEND_STEP_EVIDENCE,
        OFFLINE_BRANCH_EVIDENCE,
        PORTABLE_ANCHOR_ENROLLMENT_BODY,
        PORTABLE_HARDWARE_ENROLLMENT_BODY,
    ];

    /// Whether a discriminant is allocated with no encoder. Never true for a
    /// live object's own `CLASS`, which [`super::CcbObject`] supplies.
    pub fn is_reserved(object_class: u16) -> bool {
        ALL.contains(&object_class)
    }
}

/// Live schema versions, and the ones the state-identity cut burned.
///
/// A burned `(class, schema)` pair is recorded so its number is never
/// re-assigned. **Nothing decodes or emits one.** There is no fallback, no
/// dual-read and no upgrade path: a clean reprovision means no old-format
/// state is valid, so there is nothing to migrate from.
pub mod schema {
    /// `(class, schema)` pairs retired by the cut, in registry order.
    ///
    /// `0x0001` retires **two**. Schema 2 defined field 13 but nested
    /// `0x0002` and `0x0005` at schema 1, and §2.7 nests by complete CCB
    /// including the nested schema version — so its bytes differ from schema
    /// 3's even though the field *list* is identical. That is exactly the
    /// silent divergence §2.8 exists to prevent, and it is why a bump
    /// propagates upward through every enclosing object.
    pub const BURNED: &[(u16, u16)] = &[
        (super::class::VAULT_STATE_V2, 1),
        (super::class::VAULT_STATE_V2, 2),
        (super::class::STORAGE_SET, 1),
        (super::class::ENCUMBRANCE_CLAIM, 1),
        (super::class::ENCUMBRANCE_SET, 1),
    ];

    /// Whether a `(class, schema)` pair is retired. Never true for a live
    /// object's own `SCHEMA`, which [`super::CcbObject`] supplies.
    pub fn is_burned(object_class: u16, schema_version: u16) -> bool {
        BURNED.contains(&(object_class, schema_version))
    }
}

/// A class whose canonical bytes this module emits.
///
/// The class and schema are **associated constants, not parameters**. That is
/// the whole point: a call site cannot pass the wrong schema, because it never
/// passes one. When a nested object's schema moves, every enclosing object's
/// envelope follows from its own constant and the change cannot be applied to
/// some call sites and missed at others.
pub trait CcbObject {
    /// Object-class discriminant from the single namespace of registry §3.
    const CLASS: u16;
    /// The one live schema version for that class.
    const SCHEMA: u16;
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
    /// A `signature_alg` value the registry does not declare.
    UnknownSignatureAlg { alg: u16 },
    /// A public key whose length is not the declared width for its algorithm.
    KeyLengthMismatch {
        alg: u16,
        expected: usize,
        got: usize,
    },
    /// A balance leaf state carried `amount = 0`. Zero balance is the ABSENCE
    /// of the leaf, so a zero-valued balance object has no canonical bytes.
    /// Reserves are the opposite and deliberately so — see
    /// `EconomicVaultReserveState`.
    ZeroBalanceLeafMustBeAbsent,
    /// A settlement-receipt leaf whose `new_sequence` is not
    /// `parent_sequence + 1`.
    ReceiptSequenceNotSuccessor { parent: u64, new: u64 },
    /// A settlement-receipt leaf with a zero amount on either leg.
    ReceiptZeroAmount,
    /// A settlement-receipt leaf whose input and output name the same asset.
    ReceiptAssetsNotDistinct,
    /// A leaf mutation with neither a pre-state nor a post-state. "Absent to
    /// absent" is not a mutation; it is a mutation that should not have been
    /// emitted, and admitting it would let a witness pad its list.
    MutationBothStatesAbsent,
    /// A leaf mutation whose pre-state and post-state are different leaf
    /// classes. The class selects the key derivation, so this would be one
    /// mutation claiming two positions.
    MutationClassMismatch { pre: u16, post: u16 },
    /// A leaf mutation whose sibling count is not exactly the tree height. A
    /// short path is a shallower tree, and a verifier that accepts one is
    /// accepting a different tree than the one it thinks it is checking.
    MutationSiblingCount { expected: usize, got: usize },
    /// An admission manifest naming both substrates, or neither. The object
    /// shape is what states the substrate; exactly one is present.
    ManifestSubstrateNotExactlyOne,
    /// A `SameTransitionMove` whose credit and debit are the same mutation.
    /// A mutation cannot fund itself.
    SameTransitionMoveIsSelfFunding { index: u32 },
    /// An offline reentry naming one boundary as its own predecessor.
    OfflineReentryBoundaryIsItsOwnParent,
    /// Credit sources out of order, or two sources for one credit.
    CreditSourcesNotStrictlyAscending { index: usize },
    /// A source naming a mutation index the witness does not have.
    CreditIndexOutOfRange { index: u32, mutations: usize },
    /// A mutation that increases a quantity with no source funding it.
    UnfundedCredit { mutation_index: usize },
    /// A source funding a mutation that is not a positive credit.
    SourceForNonCredit { mutation_index: u32 },
    /// A witness with no mutations. A transition that changes no economic
    /// leaf has no witness; it has `EconomicEffect::None`.
    WitnessHasNoMutations,
    /// The manifest's provenance index does not equal the sorted, unique set
    /// of external evidence addresses the witness's credit sources reference.
    ManifestProvenanceIndexMismatch {
        manifest_count: usize,
        derived_count: usize,
    },
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
            CcbError::UnknownSignatureAlg { alg } => write!(
                f,
                "signature_alg {alg:#06x} is not declared in the registry; \
                 enumerations range over declared values, never call-site inventions"
            ),
            CcbError::KeyLengthMismatch { alg, expected, got } => write!(
                f,
                "public key for signature_alg {alg:#06x} must be {expected} bytes, got {got}"
            ),
            CcbError::ZeroBalanceLeafMustBeAbsent => write!(
                f,
                "economic balance leaf: amount 0 is the ABSENCE of the leaf, not a leaf \
                 holding zero — a zero-valued balance state has no canonical bytes"
            ),
            CcbError::ReceiptSequenceNotSuccessor { parent, new } => write!(
                f,
                "economic settlement receipt: new_sequence {new} must be parent_sequence \
                 {parent} + 1"
            ),
            CcbError::ReceiptZeroAmount => write!(
                f,
                "economic settlement receipt: neither leg may be zero — a zero leg is a \
                 settlement that moved nothing and cannot fund a credit"
            ),
            CcbError::ReceiptAssetsNotDistinct => write!(
                f,
                "economic settlement receipt: input and output must name distinct assets"
            ),
            CcbError::MutationBothStatesAbsent => write!(
                f,
                "economic leaf mutation: absent-to-absent is not a mutation; emitting one \
                 would let a witness pad its mutation list with no-ops"
            ),
            CcbError::MutationClassMismatch { pre, post } => write!(
                f,
                "economic leaf mutation: pre-state class {pre:#06x} and post-state class \
                 {post:#06x} differ — the class selects the key derivation, so this is one \
                 mutation claiming two positions"
            ),
            CcbError::MutationSiblingCount { expected, got } => write!(
                f,
                "economic leaf mutation: expected exactly {expected} siblings, got {got} — \
                 a short path proves a shallower tree than the one being verified"
            ),
            CcbError::ManifestSubstrateNotExactlyOne => write!(
                f,
                "economic admission manifest: exactly one of dsm_successor_evidence_addr \
                 and offline_boundary_evidence_addr must be present — the object shape is \
                 what states the substrate"
            ),
            CcbError::SameTransitionMoveIsSelfFunding { index } => write!(
                f,
                "credit source: mutation {index} is named as both the credit and the debit — \
                 a mutation cannot fund itself"
            ),
            CcbError::OfflineReentryBoundaryIsItsOwnParent => write!(
                f,
                "credit source: prior_boundary_id equals unload_boundary_id — the consumed \
                 checkpoint must be the PREDECESSOR of the reentry, not the reentry itself"
            ),
            CcbError::CreditSourcesNotStrictlyAscending { index } => write!(
                f,
                "economic transition witness: credit source {index} is not strictly after its \
                 predecessor by credit_mutation_index — repeats would fund one credit twice"
            ),
            CcbError::CreditIndexOutOfRange { index, mutations } => write!(
                f,
                "economic transition witness: a credit source names mutation {index}, but the \
                 witness carries {mutations} mutations"
            ),
            CcbError::UnfundedCredit { mutation_index } => write!(
                f,
                "economic transition witness: mutation {mutation_index} increases a quantity \
                 with no credit source funding it — a closed write set proves what changed, \
                 never that a credit was funded"
            ),
            CcbError::SourceForNonCredit { mutation_index } => write!(
                f,
                "economic transition witness: a credit source funds mutation {mutation_index}, \
                 which is not a positive credit — provenance for a debit or an insertion is \
                 provenance for nothing"
            ),
            CcbError::WitnessHasNoMutations => write!(
                f,
                "economic transition witness: no mutations — a transition that changes no \
                 economic leaf has no witness, it has EconomicEffect::None"
            ),
            CcbError::ManifestProvenanceIndexMismatch { manifest_count, derived_count } => write!(
                f,
                "economic admission manifest: provenance_evidence_addrs holds {manifest_count} \
                 addresses but the witness's credit sources reference {derived_count} distinct \
                 external addresses — the field is a DERIVED publication index, not a second \
                 description of provenance"
            ),
        }
    }
}

impl std::error::Error for CcbError {}

// ── Primitive writers, registry §2.2 ────────────────────────────────────────

/// The §2.1 envelope: `u16_be(class) ‖ u16_be(schema_version)`.
///
/// **Every** conformant object begins with this, with no exceptions. The
/// state-identity cut removed the last one: `StorageSet` used to start
/// straight at its count, carrying a frozen envelope-less layout kept because
/// deployed anchors committed set ids under it. Those anchors are gone.
///
/// Takes the object as a type parameter rather than the numbers as arguments,
/// so a wrong schema is unwritable rather than merely unwritten.
pub(crate) fn push_envelope<T: CcbObject>(out: &mut Vec<u8>) {
    out.extend_from_slice(&T::CLASS.to_be_bytes());
    out.extend_from_slice(&T::SCHEMA.to_be_bytes());
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

/// `storage_set_id = H_dom(DSM/storage-set, CCB(S))`.
///
/// An ordinary CCB object under an ordinary domain. Both halves changed with
/// the cut: the frozen envelope-less layout became `0x0002` schema 2, and the
/// `DSM/storage-set/v1` tag that named it is burned in favour of the
/// normative `DSM/storage-set`. Set ids therefore differ from the deployed
/// ones, which is the reprovision rather than a regression.
pub fn storage_set_id(members: &StorageSetMembers) -> Result<[u8; 32], CcbError> {
    let body = members.encode()?;
    let mut h: Hasher = dsm_domain_hasher(TAG_DSM_STORAGE_SET);
    h.update(&body);
    Ok(*h.finalize().as_bytes())
}
