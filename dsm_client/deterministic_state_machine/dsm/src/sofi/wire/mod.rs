// SPDX-License-Identifier: Apache-2.0

//! The SoFi v8 wire registry — normative field tables, bounds and codecs.
//!
//! This module is the version-controlled normative source for the v8 object
//! bytes. The prose explainer is not; if the two disagree, these tables win.
//!
//! ## Primitive grammar (the house CCB grammar, registry §2)
//!
//! | Primitive | Bytes |
//! |---|---|
//! | envelope | `u16_be(class) ‖ u16_be(schema)` — every object starts with it |
//! | `u16` / `u32` / `u64` | big-endian, fixed width |
//! | `digest32` | exactly 32 raw bytes, no prefix |
//! | `bytes` | `u32_be(len) ‖ raw` |
//! | `seq<T>` | `u32_be(count) ‖ T …` |
//! | nested object | its complete CCB, envelope included; for a union the nested envelope IS the discriminant |
//!
//! Decoders are strict: wrong class, unknown schema, truncation and trailing
//! bytes are refused, and every decoded object is rebuilt through the same
//! validating constructor the encoder uses.
//!
//! ## Field tables (all schema 1)
//!
//! `0x0036 SofiSetupBody`:
//! 1 `genesis` digest32 · 2 `device_id` digest32 · 3 `position` u64 ·
//! 4 `vault_id` digest32 · 5 `claim_ref` digest32 (exact root-claim envelope
//! digest at `position`) · 6 `setup_root` digest32 · 7 `signature_alg` u16 ·
//! 8 `claimant_public_key` bytes (width fixed by `signature_alg`).
//!
//! `0x0037 TraderPrecommitBody`:
//! 1 `genesis` digest32 · 2 `device_id` digest32 · 3 `position` u64 (`p`, must
//! be `< u64::MAX` so `q = p + 1` exists) · 4 `parent_claim_ref` nested
//! `0x003B | 0x003C` · 5 `external_commitment` digest32 (`E`) · 6 `legs`
//! `seq<(vault_id digest32, parent_root digest32, setup_ref digest32)>`,
//! `1..=CANONICAL_MAX_LEGS`, strictly ascending by `vault_id` · 7 `realize_root`
//! digest32 · 8 `void_root` digest32 · 9 `storage_set_id` digest32 ·
//! 10 `signature_alg` u16 · 11 `claimant_public_key` bytes.
//!
//! `0x0038 DlvPolicyFulfillmentBody`:
//! 1 `precommit_id` · 2 `external_commitment` · 3 `vault_id` · 4 `parent_root` ·
//! 5 `shadow_core` (`c°_{V,j}`) — all digest32. Identity-bearing fields only:
//! policy evidence never enters it.
//!
//! `0x0039 TraderFulfillmentBody`:
//! 1 `precommit_id` digest32 · 2 `policy_fulfillment_set` `seq<digest32>`,
//! `1..=CANONICAL_MAX_LEGS`, strictly ascending · 3 `attempts`
//! `seq<(vault_id digest32, attempt u64)>`, `1..=CANONICAL_MAX_LEGS`, strictly
//! ascending by `vault_id` · 4 `position` u64 (`q`) · 5 `signature_alg` u16 ·
//! 6 `claimant_public_key` bytes. F never restates a P field.
//!
//! `0x003A SofiResolutionClaim` (`C_q`):
//! 1 `genesis` · 2 `device_id` · 3 `position` u64 · 4 `fulfillment_id` ·
//! 5 `realize_root` · 6 `void_root`. No selector, no evidence bytes.
//!
//! `0x003B ParentSingleRootClaim`: 1 `claim_ref` digest32.
//! `0x003C ParentConditionalClaim`: 1 `fulfillment_id` digest32.
//!
//! `0x003D RefContentAddr`: 1 `object_class` u16 · 2 `addr` digest32.
//! `0x003E RefSingleRootClaim`: 1 `claim_ref` digest32.
//! `0x003F RefConditionalClaim`: 1 `genesis` · 2 `device_id` · 3 `position`
//! u64 · 4 `fulfillment_id`.
//! `0x0040 RefSetup`: 1 `setup_ref` digest32.
//!
//! `0x0041 PreEClosureIndex` (`𝒞_E^pre`): 1 `refs` `seq<ValidationRef>`,
//! `0..=MAX_CLOSURE_REFS`, strictly ascending by complete encoded bytes (so a
//! duplicate is malformed). A `RefContentAddr` may not name a class that
//! depends on the current E or that has its own reference variant.
//!
//! `0x0042 PolicyFulfillmentAuxRef`: 1 `policy_fulfillment_id` digest32 ·
//! 2 `evidence_class` u16 · 3 `addr` digest32.
//!
//! Resolution records: `0x0043 RecordFulfillmentRegistered` (1
//! `fulfillment_key` · 2 `fulfillment_id`) · `0x0044 RecordSuccessorDead` (1
//! `successor_key`) · `0x0045 RecordSuccessorFinal` (1 `successor_key` · 2
//! `external_commitment`) · `0x0046 RecordOutcomeComplete` (1 `outcome_key`) ·
//! `0x0047 RecordOutcomeAbort` (1 `outcome_key`). All digest32.
//!
//! Route-outcome cell values: `0x0048 OutcomeCellComplete`, `0x0049
//! OutcomeCellAbort` — envelope only, zero fields.
//!
//! `0x004A RouteLegSet` (`Γ`): 1 `legs` `seq<(vault_id, parent_root,
//! setup_ref, shadow_core)>` all digest32, `ROUTE_MIN_LEGS..=CANONICAL_MAX_LEGS`,
//! strictly ascending by `vault_id`.
//!
//! ## The DLV tree, the cores, `B°` and vault genesis
//!
//! `0x004B VaultStateLeaf` (the value preimage of the vault's own leaf, at key
//! `H(vault-state-key/v1 ‖ v)`):
//! 1 `owner_genesis` digest32 · 2 `owner_device_id` digest32 (the ORIGIN
//! device: `vault_id` provenance, not eternal controller identity) ·
//! 3 `create_position` u64 · 4 `market_policy` digest32 (content address of a
//! `0x0007` object) · 5 `fee_policy` digest32 (`0x000A`) · 6 `release_policy`
//! digest32 (`0x0009`) · 7 `storage_set_id` digest32 · 8 `generation` u64 ·
//! 9 `reserve_a` u64 · 10 `reserve_b` u64 · 11 `status` u16, exactly
//! `VAULT_STATUS_ACTIVE` or `VAULT_STATUS_RETIRED`. A policy is named by
//! content address, so the pair's tokens and the release rule are fetched and
//! verified, never restated here.
//!
//! `0x004C VaultRelationshipLeaf` (at key `k_{T,v}`): 1 `trader_genesis` ·
//! 2 `trader_device_id` · 3 `leaf` digest32 (`hʲ`). The key material is
//! explicit, so the tree can be rebuilt by replay.
//!
//! Both leaf values are `H(vault-leaf-state/v1 ‖ CCB(leaf))`. One tag is safe
//! because the leaf's own envelope is inside the preimage.
//!
//! `0x004D TraderRelationshipLeaf` (the `R_econ` leaf state, at `k_{T,v}`):
//! 1 `vault_id` digest32 · 2 `leaf` digest32 (`hʲ`).
//!
//! Core entries, each carrying a full authentication path against the core's
//! `pre_root` (default-sibling compression is deferred):
//! `0x004E CoreEntryMutation`: 1 `key` · 2 `pre` · 3 `post` · 4 `path`
//! `seq<digest32>` of exactly `ECONOMIC_SMT_HEIGHT`, leaf-to-root.
//! `0x004F CoreEntryRead`: 1 `key` · 2 `value` · 3 `path`.
//! `0x0050 CoreEntryRelationship`: 1 `genesis` · 2 `device_id` · 3 `vault_id`
//! (together they derive the key, so it is never restated) · 4 `base` digest32
//! (`hʲ`) · 5 `path`. Its post is `H(rel-leaf/v1 ‖ base ‖ E)`, filled by
//! BindExt — which is why the entry cannot carry it.
//!
//! `0x0051 TraderCore` (`T°`): 1 `genesis` · 2 `device_id` · 3 `position` u64
//! (`q`, so E cannot be replayed at another position) · 4 `pre_root` digest32
//! · 5 `entries` `seq<0x004E | 0x004F | 0x0050>`, `1..=MAX_CORE_ENTRIES`,
//! strictly ascending by entry key.
//!
//! `0x0052 DlvCore` (`V°_j`): 1 `vault_id` · 2 `pre_root` · 3
//! `trader_genesis` · 4 `trader_device_id` · 5 `relationship_base` digest32
//! (`T°`'s pre at `k_{T,v}`; `h⁰` on a first operation) · 6 `entries`.
//!
//! `B°` is a union; the nested envelope is the branch.
//! `0x0053 SettlementSwap`: 1 `token_in` digest32 · 2 `amount_in` u64 ·
//! 3 `token_out` digest32 · 4 `exact_out` u64 (the intent) · 5 `hops`
//! `seq<(vault_id, parent_root, setup_ref, token_in, amount_in, token_out,
//! amount_out)>` in hop order, `1..=CANONICAL_MAX_LEGS`, vault ids pairwise
//! distinct · 6 `trader_core` digest32 (`c_T°`) · 7 `dlv_cores`
//! `seq<digest32>` — `c°_{V,j}` for each core, positionally against `P(E)`'s
//! own cores, which are sorted by vault id. They are digests, so they carry no
//! order of their own; `sofi::validation` binds each one to the core `P(E)`
//! carries · 8 `closure` nested `0x0041`.
//! `0x0054 SettlementClose`: 1 `vault_id` · 2 `parent_root` · 3 `setup_ref` ·
//! 4 `owner_authority` nested `0x0055 | 0x0056` · 5 `reserve_a` u64 ·
//! 6 `reserve_b` u64 · 7 `trader_core` · 8 `dlv_core` · 9 `closure`.
//!
//! `0x0055 OwnerAuthorityOrigin`: envelope only. The only branch semantic
//! validation accepts.
//! `0x0056 OwnerAuthorityDsmSuccessor`: 1 `authority_class` u16 ·
//! 2 `authority_addr` digest32 — an opaque typed reference to a future DSM
//! succession-authority object. Canonically encodable so activating it needs
//! no byte change; ALWAYS Invalid (never Unavailable) until then, and no
//! production builder emits it.
//!
//! `X_route = H(route-digest/v1 ‖ CCB(RouteDigestPreimage))`, over a union:
//! `0x0057 RouteDigestSwap`: 1 `hops`, the same entries as the Swap branch.
//! `0x0058 RouteDigestClose`: 1 `vault_id` · 2 `parent_root` · 3 `setup_ref` ·
//! 4 `reserve_a` u64 · 5 `reserve_b` u64.
//!
//! `0x0059 SettlementPreimage` (`P(E)`): 1 `settlement` nested `0x0053 |
//! 0x0054` · 2 `trader_core` nested `0x0051` · 3 `dlv_cores` `seq<0x0052>`
//! sorted by vault id, EXACTLY one per DLV parent the settlement references
//! (a swap's hop count, a close's one). The whole encoding is bounded by
//! `MAX_SETTLEMENT_PREIMAGE_BYTES` on both sides of the codec: an oversized
//! preimage has no canonical representation, so it cannot be built, encoded,
//! decoded, or folded into an `E`.
//!
//! `0x005A VaultGenesisPreimage`: 1 `owner_genesis` · 2 `owner_device_id` ·
//! 3 `create_position` u64 · 4 `state` nested `0x004B`.
//! `0x005B VaultCreation`: 1 `vault_id` · 2 `genesis_root` digest32 (`R_0`) ·
//! 3 `amount_a` u64 · 4 `amount_b` u64.

pub mod objects;

pub use objects::*;

/// The fixed storage profile: exactly five committed members.
pub const STORAGE_MEMBER_COUNT: usize = 5;
/// Storage finality: three matching write-once cells. `3 + 3 > 5`.
pub const STORAGE_FINALITY_COUNT: usize = 3;
/// Beta route cardinality: two hops across two distinct vaults.
///
/// This is an ADMISSION and BUILDER limit, never a codec one [R16-6]. The
/// canonical objects below accept any leg count the byte bound allows, so a
/// three-hop route has canonical bytes and a golden digest today; what beta
/// refuses is executing one. Keeping the cap in the codec would have made the
/// bytes of a legal route undefined, and every later relaxation a format change.
pub const ROUTE_MAX_LEGS: usize = 2;
/// The smallest leg count the route (multivault) form of E admits.
pub const ROUTE_MIN_LEGS: usize = 2;
/// The encoded size of the smallest leg entry: three digests.
const SMALLEST_LEG_BYTES: usize = 96;
/// The largest leg count any canonical object can carry — the settlement
/// preimage bound divided by the smallest leg encoding. It is an allocation
/// guard derived from the byte bound, so a hostile count is refused before it
/// is allocated; it is not a protocol cardinality.
pub const CANONICAL_MAX_LEGS: usize = MAX_SETTLEMENT_PREIMAGE_BYTES / SMALLEST_LEG_BYTES;
/// The largest entry count one core may carry, on the same footing: the
/// smallest entry is a read of 64 bytes plus a 256-deep path.
pub const MAX_CORE_ENTRIES: usize = MAX_SETTLEMENT_PREIMAGE_BYTES / (64 + 32 * 256);
/// `VaultStateLeaf.status`: both reserves above zero, and tradeable.
pub const VAULT_STATUS_ACTIVE: u16 = 0x0001;
/// `VaultStateLeaf.status`: closed, both reserves zero. Terminal.
pub const VAULT_STATUS_RETIRED: u16 = 0x0002;

// ── R8-12 normative validation bounds (frozen for beta) ─────────────────────
//
// A candidate whose own bytes, or whose successfully retrieved canonical
// objects, establish that any of these is exceeded is Invalid — never
// Unavailable. Candidate-examination and local hostile-input budgets are NOT
// here: they are per-implementation work limits, and exhausting them yields
// Unavailable/Continue, never Invalid.

/// Distinct `ValidationRef` values in one closure; duplicates are malformed.
pub const MAX_CLOSURE_REFS: usize = 64;
/// Canonical encoded bytes of one referenced object (transport excluded).
pub const MAX_CLOSURE_OBJECT_BYTES: usize = 256 * 1024;
/// Authorization envelopes one candidate may require.
pub const MAX_AUTH_ENVELOPES: usize = 16;
/// Aggregate canonical bytes over the unique fetched objects `U(E)`,
/// deduplicated by `ValidationRef`. Non-verifying candidates do not count.
pub const MAX_VALIDATION_FETCH_BYTES: usize = 4 * 1024 * 1024;
/// Direct external provenance references introduced by one transition —
/// never recursive ancestry depth.
pub const MAX_PROVENANCE_FANOUT: usize = 16;
/// The canonical settlement preimage `P(E)` itself.
pub const MAX_SETTLEMENT_PREIMAGE_BYTES: usize = 256 * 1024;

/// Why a logical v8 object has no canonical bytes, or a counter cannot advance.
///
/// Every variant is a validity condition, never a normalization opportunity:
/// an encoder that sorted or de-duplicated on the caller's behalf would map
/// two logical inputs onto one byte string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SofiWireError {
    /// `signature_alg` is not declared in the registry.
    UnknownSignatureAlg { alg: u16 },
    /// The public key width does not match `signature_alg`.
    KeyLengthMismatch { expected: usize, got: usize },
    /// A sequence has fewer or more elements than its table allows.
    Cardinality {
        field: &'static str,
        min: usize,
        max: usize,
        got: usize,
    },
    /// A sequence is not strictly ascending by its ordering key; this also
    /// covers duplicates.
    NotStrictlyAscending { field: &'static str, index: usize },
    /// A checked counter would overflow. The operation is refused, never wrapped.
    CounterOverflow { counter: &'static str },
    /// A closure `RefContentAddr` names a class that may not be content-bound
    /// in `𝒞_E^pre`.
    ForbiddenClosureClass { object_class: u16 },
    /// A length does not fit its prefix.
    LengthOverflow,
    /// `status` is not one of the two declared vault statuses.
    UnknownVaultStatus { status: u16 },
    /// An object exceeds the frozen byte bound for its class, so it has no
    /// canonical representation.
    ObjectTooLarge {
        field: &'static str,
        bytes: usize,
        max: usize,
    },
    /// An authentication path is not exactly `ECONOMIC_SMT_HEIGHT` deep.
    PathDepth { expected: usize, got: usize },
    /// `SignedSofiObject` was asked to carry a body class it does not carry.
    /// Only `P` and `F` are signed objects; `G` has no issuer signature, and a
    /// setup signs `m_setup` through its own object.
    UnsupportedSignedBodyClass { body_class: u16 },
}

impl core::fmt::Display for SofiWireError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnsupportedSignedBodyClass { body_class } => {
                write!(
                    f,
                    "class {body_class:#06x} is not a signed SoFi body: only a trader \
                     pre-commit and a trader fulfillment carry a trader signature"
                )
            }
            Self::UnknownSignatureAlg { alg } => {
                write!(
                    f,
                    "signature_alg {alg:#06x} is not declared in the registry"
                )
            }
            Self::KeyLengthMismatch { expected, got } => {
                write!(
                    f,
                    "claimant public key is {got} bytes; the algorithm fixes {expected}"
                )
            }
            Self::Cardinality {
                field,
                min,
                max,
                got,
            } => write!(f, "{field}: {got} elements, allowed {min}..={max}"),
            Self::NotStrictlyAscending { field, index } => write!(
                f,
                "{field}: element {index} is not strictly after its predecessor \
                 (duplicates are invalid, never collapsed)"
            ),
            Self::CounterOverflow { counter } => {
                write!(
                    f,
                    "{counter} is at its maximum; the successor does not exist"
                )
            }
            Self::ForbiddenClosureClass { object_class } => write!(
                f,
                "class {object_class:#06x} may not be content-bound in the pre-E closure"
            ),
            Self::LengthOverflow => write!(f, "length does not fit its prefix"),
            Self::ObjectTooLarge { field, bytes, max } => write!(
                f,
                "{field}: {bytes} bytes exceeds the {max}-byte bound, so it has \
                 no canonical encoding"
            ),
            Self::UnknownVaultStatus { status } => write!(
                f,
                "vault status {status:#06x} is neither Active nor Retired"
            ),
            Self::PathDepth { expected, got } => write!(
                f,
                "authentication path is {got} siblings deep; the tree fixes {expected}"
            ),
        }
    }
}

impl std::error::Error for SofiWireError {}

/// `q = p + 1`, checked. A position at `u64::MAX` has no successor.
pub fn next_position(p: u64) -> Result<u64, SofiWireError> {
    p.checked_add(1).ok_or(SofiWireError::CounterOverflow {
        counter: "economic position",
    })
}

/// `a + 1`, checked.
pub fn next_attempt(a: u64) -> Result<u64, SofiWireError> {
    a.checked_add(1).ok_or(SofiWireError::CounterOverflow {
        counter: "successor attempt",
    })
}

/// `generation + 1`, checked.
pub fn next_generation(g: u64) -> Result<u64, SofiWireError> {
    g.checked_add(1).ok_or(SofiWireError::CounterOverflow {
        counter: "vault generation",
    })
}
