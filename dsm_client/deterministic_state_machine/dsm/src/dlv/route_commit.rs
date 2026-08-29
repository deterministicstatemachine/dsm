// SPDX-License-Identifier: MIT OR Apache-2.0

//! Core Class-K primitives (3.6 PR3): the VALIDITY half of RouteCommit
//! verification and the AMM re-simulation, moved into core so a foreign
//! economic verifier can recompute them — the `DlvReserveConsumption`
//! (0x0026) provenance arm must prove a trade's amounts against the exact
//! authenticated vault state without any SDK machinery.
//!
//! What deliberately stays in the SDK: storage listing, the external-
//! commitment ANCHOR-VISIBILITY check (a liveness/publication property, not
//! validity — for the economic verifier the quorum settlement-slot winner is
//! the liveness anchor), and the multi-pointer composition fold (a quoting
//! concern; the verifier consumes exactly the state named by `c_n`).

use crate::common::domain_tags::TAG_DSM_EXT_COMMIT;
use crate::types::proto as generated;
use prost::Message;

/// The one supported RouteCommit schema. A stale schema forces a fresh
/// quote + sign — one route, one anchored state, one exact output, one
/// signature; there are no pre-signed fallbacks.
pub const ROUTE_COMMIT_VERSION: u32 = 2;

/// The signature-zeroed RouteCommit — the canonical form both the SPHINCS+
/// signature and the external commitment `X` are computed over, so neither
/// can cover the other.
pub fn canonicalise_for_commitment(rc: &generated::RouteCommitV1) -> generated::RouteCommitV1 {
    let mut out = rc.clone();
    out.initiator_signature.clear();
    out
}

/// `X = BLAKE3("DSM/ext\0" ‖ canonical RouteCommit bytes)` — deterministic
/// across encoders (prost emits canonical wire bytes for a given message).
pub fn compute_external_commitment(rc: &generated::RouteCommitV1) -> [u8; 32] {
    let canonical_bytes = canonicalise_for_commitment(rc).encode_to_vec();
    crate::crypto::blake3::domain_hash_bytes(TAG_DSM_EXT_COMMIT, &canonical_bytes)
}

/// Constant-product AMM output for one hop: the ONE implementation, shared
/// by the trader's quote, the owner's fold, and the economic verifier's
/// re-simulation — three callers, one arithmetic, no drift.
pub fn constant_product_output(
    input_amount: u64,
    reserve_in: u64,
    reserve_out: u64,
    fee_bps: u32,
) -> Option<u64> {
    if input_amount == 0 || reserve_in == 0 || reserve_out == 0 {
        return None;
    }
    if fee_bps >= 10_000 {
        // Fee >= 100 % is not a real AMM hop; refuse rather than divide a
        // positive numerator by zero.
        return None;
    }
    let input_amount = u128::from(input_amount);
    let reserve_in = u128::from(reserve_in);
    let reserve_out = u128::from(reserve_out);

    let fee_complement = u128::from(10_000u32 - fee_bps);
    let input_after_fee_num = input_amount.checked_mul(fee_complement)?;
    let denom_lhs = reserve_in.checked_mul(10_000)?;
    let denom = denom_lhs.checked_add(input_after_fee_num)?;
    let num = reserve_out.checked_mul(input_after_fee_num)?;
    let out = num / denom;
    if out == 0 {
        return None;
    }
    u64::try_from(out).ok()
}

/// A RouteCommit hop that passed every PURE validity check for one vault.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedRouteHop {
    /// The initiator whose SPHINCS+ signature covered the canonical bytes —
    /// the identity the settlement-slot claimant must equal.
    pub initiator_public_key: Vec<u8>,
    /// The exact assets traded, as 32-byte policy commits.
    pub token_in: [u8; 32],
    pub token_out: [u8; 32],
    /// Base-unit amounts, narrowed ONCE from the 16-byte big-endian wire
    /// form; an amount that does not fit u64 is a malformed hop.
    pub input_amount: u64,
    pub expected_output: u64,
    /// The hop's fee in basis points — must equal the vault's own fee.
    pub fee_bps: u32,
}

/// Why a RouteCommit hop failed pure verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteHopError {
    Malformed(&'static str),
    UnsupportedVersion {
        got: u32,
    },
    SignatureInvalid,
    VaultNotInRoute,
    /// The hop's `parent_binding` does not equal the expected `c_n` — it was
    /// signed against a different parent vault state.
    ParentBindingMismatch,
}

impl core::fmt::Display for RouteHopError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Malformed(w) => write!(f, "route commit malformed: {w}"),
            Self::UnsupportedVersion { got } => {
                write!(f, "route commit schema {got} is not supported")
            }
            Self::SignatureInvalid => write!(f, "route commit initiator signature invalid"),
            Self::VaultNotInRoute => write!(f, "route commit names no hop for this vault"),
            Self::ParentBindingMismatch => write!(
                f,
                "route commit hop is bound to a different parent vault state"
            ),
        }
    }
}

impl std::error::Error for RouteHopError {}

/// The PURE subset of routed-unlock eligibility — everything a foreign
/// verifier can recompute from bytes alone:
///
/// 1. strict schema-gated decode;
/// 2. SPHINCS+ `initiator_signature` over the canonical (signature-zeroed)
///    bytes under the carried `initiator_public_key`;
/// 3. a hop for exactly `vault_id` exists;
/// 4. that hop's `parent_binding` byte-equals `expected_parent_binding`
///    (the `c_n` of the exact vault state the trade consumes);
/// 5. the 16-byte big-endian amounts narrow to u64.
///
/// No storage, no anchor visibility — the caller supplies its own liveness
/// facts (the SDK's eligibility gate adds the anchor check; the economic
/// verifier adds the quorum slot winner).
pub fn verify_route_commit_hop(
    route_commit_bytes: &[u8],
    vault_id: &[u8; 32],
    expected_parent_binding: &[u8; 32],
) -> Result<VerifiedRouteHop, RouteHopError> {
    let rc = generated::RouteCommitV1::decode(route_commit_bytes)
        .map_err(|_| RouteHopError::Malformed("route commit does not decode"))?;
    if rc.version != ROUTE_COMMIT_VERSION {
        return Err(RouteHopError::UnsupportedVersion { got: rc.version });
    }
    if rc.initiator_public_key.is_empty() {
        return Err(RouteHopError::Malformed("missing initiator public key"));
    }
    if rc.initiator_signature.is_empty() {
        return Err(RouteHopError::SignatureInvalid);
    }
    let canonical_bytes = canonicalise_for_commitment(&rc).encode_to_vec();
    match crate::crypto::sphincs::sphincs_verify(
        &rc.initiator_public_key,
        &canonical_bytes,
        &rc.initiator_signature,
    ) {
        Ok(true) => {}
        Ok(false) | Err(_) => return Err(RouteHopError::SignatureInvalid),
    }
    let hop = rc
        .hops
        .iter()
        .find(|h| h.vault_id.as_slice() == vault_id.as_slice())
        .ok_or(RouteHopError::VaultNotInRoute)?;
    if hop.parent_binding.len() != 32
        || hop.parent_binding.as_slice() != expected_parent_binding.as_slice()
    {
        return Err(RouteHopError::ParentBindingMismatch);
    }
    let token_in: [u8; 32] = hop
        .token_in
        .as_slice()
        .try_into()
        .map_err(|_| RouteHopError::Malformed("token_in must be 32 bytes"))?;
    let token_out: [u8; 32] = hop
        .token_out
        .as_slice()
        .try_into()
        .map_err(|_| RouteHopError::Malformed("token_out must be 32 bytes"))?;
    let narrow = |bytes: &[u8], what: &'static str| -> Result<u64, RouteHopError> {
        let arr: [u8; 16] = bytes
            .try_into()
            .map_err(|_| RouteHopError::Malformed(what))?;
        u64::try_from(u128::from_be_bytes(arr)).map_err(|_| RouteHopError::Malformed(what))
    };
    let input_amount = narrow(&hop.input_amount_u128, "input amount")?;
    let expected_output = narrow(&hop.expected_output_amount_u128, "expected output")?;
    Ok(VerifiedRouteHop {
        initiator_public_key: rc.initiator_public_key.clone(),
        token_in,
        token_out,
        input_amount,
        expected_output,
        fee_bps: hop.fee_bps,
    })
}
