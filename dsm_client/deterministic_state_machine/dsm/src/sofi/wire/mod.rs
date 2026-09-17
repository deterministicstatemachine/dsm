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
//! `1..=ROUTE_MAX_LEGS`, strictly ascending by `vault_id` · 7 `realize_root`
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
//! `1..=ROUTE_MAX_LEGS`, strictly ascending · 3 `attempts`
//! `seq<(vault_id digest32, attempt u64)>`, `1..=ROUTE_MAX_LEGS`, strictly
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
//! setup_ref, shadow_core)>` all digest32, `2..=ROUTE_MAX_LEGS`, strictly
//! ascending by `vault_id`.

pub mod objects;

pub use objects::*;

/// The fixed storage profile: exactly five committed members.
pub const STORAGE_MEMBER_COUNT: usize = 5;
/// Storage finality: three matching write-once cells. `3 + 3 > 5`.
pub const STORAGE_FINALITY_COUNT: usize = 3;
/// Beta route cardinality: two hops across two distinct vaults.
pub const ROUTE_MAX_LEGS: usize = 2;
/// The smallest leg count the route (multivault) form of E admits.
pub const ROUTE_MIN_LEGS: usize = 2;

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
}

impl core::fmt::Display for SofiWireError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
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
