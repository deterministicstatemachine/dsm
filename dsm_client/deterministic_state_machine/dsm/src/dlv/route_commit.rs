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

/// The basis points denominator. `fee_bps` at or above this is not a hop.
pub const BPS_DENOMINATOR: u32 = 10_000;

/// Why a constant-product hop has no output.
///
/// The `Option` returned by [`constant_product_output`] collapses all of these
/// into one `None`, which makes a DUST TRADE and a MALFORMED HOP
/// indistinguishable at a verifier. Amendment 2c-C3's arithmetic discipline
/// requires each admissibility condition to refuse with its own reason, so the
/// classified form below is the one a successor-validity predicate calls.
///
/// This is a NARROWING of one arithmetic, never a second one:
/// [`constant_product_output`] is defined in terms of this function.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConstantProductRefusal {
    /// `a = 0`. Market admissibility forbids it — which is also what makes
    /// "both reserve legs zero" an unambiguous retirement marker.
    InputAmountZero,
    /// `x = 0`.
    ReserveInZero,
    /// `y = 0`.
    ReserveOutZero,
    /// `f >= D`. Fee at or above 100 % is not a real hop.
    FeeAtOrAboveDenominator,
    /// A checked product exceeded `u128`. Reachable: `reserve_out` times the
    /// fee-adjusted input is up to ~2^142.
    ArithmeticOverflow,
    /// The single floor division truncated to zero — a legitimately-shaped
    /// trade too small to move the pool. NOT a malformed hop.
    OutputZero,
}

impl ConstantProductRefusal {
    /// A stable name for logs and for crossing a boundary.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::InputAmountZero => "INPUT_AMOUNT_ZERO",
            Self::ReserveInZero => "RESERVE_IN_ZERO",
            Self::ReserveOutZero => "RESERVE_OUT_ZERO",
            Self::FeeAtOrAboveDenominator => "FEE_AT_OR_ABOVE_DENOMINATOR",
            Self::ArithmeticOverflow => "ARITHMETIC_OVERFLOW",
            Self::OutputZero => "OUTPUT_ZERO",
        }
    }
}

impl core::fmt::Display for ConstantProductRefusal {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Constant-product AMM output for one hop, with the refusal classified.
///
/// THE one arithmetic — the trader's quote, the owner's fold, the economic
/// verifier's re-simulation and the successor-validity predicate all reach it,
/// and there is exactly one floor division in it. The fee is carried as a
/// `* 10_000` numerator on BOTH sides rather than rescaling the input first,
/// so no second rounding exists to disagree about.
pub fn constant_product_output_classified(
    input_amount: u64,
    reserve_in: u64,
    reserve_out: u64,
    fee_bps: u32,
) -> Result<u64, ConstantProductRefusal> {
    if input_amount == 0 {
        return Err(ConstantProductRefusal::InputAmountZero);
    }
    if reserve_in == 0 {
        return Err(ConstantProductRefusal::ReserveInZero);
    }
    if reserve_out == 0 {
        return Err(ConstantProductRefusal::ReserveOutZero);
    }
    if fee_bps >= BPS_DENOMINATOR {
        // Fee >= 100 % is not a real AMM hop; refuse rather than divide a
        // positive numerator by zero.
        return Err(ConstantProductRefusal::FeeAtOrAboveDenominator);
    }
    let input_amount = u128::from(input_amount);
    let reserve_in = u128::from(reserve_in);
    let reserve_out = u128::from(reserve_out);

    let fee_complement = u128::from(BPS_DENOMINATOR - fee_bps);
    let overflow = || ConstantProductRefusal::ArithmeticOverflow;
    let input_after_fee_num = input_amount
        .checked_mul(fee_complement)
        .ok_or_else(overflow)?;
    let denom_lhs = reserve_in
        .checked_mul(u128::from(BPS_DENOMINATOR))
        .ok_or_else(overflow)?;
    let denom = denom_lhs
        .checked_add(input_after_fee_num)
        .ok_or_else(overflow)?;
    let num = reserve_out
        .checked_mul(input_after_fee_num)
        .ok_or_else(overflow)?;
    let out = num / denom;
    if out == 0 {
        return Err(ConstantProductRefusal::OutputZero);
    }
    u64::try_from(out).map_err(|_| overflow())
}

/// Constant-product AMM output for one hop: the ONE implementation, shared
/// by the trader's quote, the owner's fold, and the economic verifier's
/// re-simulation — three callers, one arithmetic, no drift.
///
/// Callers that must distinguish "too small to move the pool" from "malformed"
/// want [`constant_product_output_classified`]; this form deliberately erases
/// that distinction for callers whose only decision is go / no-go.
pub fn constant_product_output(
    input_amount: u64,
    reserve_in: u64,
    reserve_out: u64,
    fee_bps: u32,
) -> Option<u64> {
    constant_product_output_classified(input_amount, reserve_in, reserve_out, fee_bps).ok()
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

/// One hop of a RouteCommit whose whole chain verified, in route order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedChainHop {
    pub vault_id: [u8; 32],
    /// `c_n` of the exact vault state this hop consumes.
    pub parent_binding: [u8; 32],
    pub token_in: [u8; 32],
    pub token_out: [u8; 32],
    pub input_amount: u64,
    pub expected_output: u64,
    pub fee_bps: u32,
}

/// A RouteCommit that passed every PURE check route-wide (2c-H H11 SAT.2, H16):
/// one signature over the whole route, and hops that form one chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedRouteCommit {
    pub initiator_public_key: Vec<u8>,
    pub nonce: [u8; 32],
    pub input_token: [u8; 32],
    pub output_token: [u8; 32],
    pub input_amount: u64,
    pub expected_final_output: u64,
    pub total_fee_bps: u32,
    /// Route order, never sorted.
    pub hops: Vec<VerifiedChainHop>,
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
    /// The signed route names no hop.
    EmptyRoute,
    /// Hop `hop` and a later hop name the same vault or the same parent state
    /// (RC.5 on the signed route).
    HopRepeated {
        hop: usize,
    },
    /// Hop `hop` does not hand its output asset and exact output to hop
    /// `hop + 1` (RC.1 and RC.2 on the signed route).
    ChainBroken {
        hop: usize,
    },
    /// The route's stated input asset and amount are not its first hop's, or
    /// its stated output asset and final output are not its last hop's.
    EndsDisagree,
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
            Self::EmptyRoute => write!(f, "route commit names no hop"),
            Self::HopRepeated { hop } => write!(
                f,
                "route commit hop {hop} and a later hop name the same vault or parent state"
            ),
            Self::ChainBroken { hop } => write!(
                f,
                "route commit hop {hop} does not hand its output to hop {}",
                hop + 1
            ),
            Self::EndsDisagree => write!(
                f,
                "route commit input or final output is not its first or last hop's"
            ),
        }
    }
}

impl std::error::Error for RouteHopError {}

/// Strict decode and authentication, shared by the one-hop and route-wide
/// verifiers so they cannot disagree about what a signed RouteCommit is:
/// schema-gated decode, a carried initiator key, and the SPHINCS+ signature
/// over the canonical (signature-zeroed) bytes under that key.
fn decode_authenticated(
    route_commit_bytes: &[u8],
) -> Result<generated::RouteCommitV1, RouteHopError> {
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
        Ok(true) => Ok(rc),
        Ok(false) | Err(_) => Err(RouteHopError::SignatureInvalid),
    }
}

/// A 32-byte field, or `Malformed(what)`.
fn fixed32(bytes: &[u8], what: &'static str) -> Result<[u8; 32], RouteHopError> {
    bytes.try_into().map_err(|_| RouteHopError::Malformed(what))
}

/// A 16-byte big-endian amount narrowed ONCE to u64, or `Malformed(what)`.
fn narrow_amount(bytes: &[u8], what: &'static str) -> Result<u64, RouteHopError> {
    let arr: [u8; 16] = bytes
        .try_into()
        .map_err(|_| RouteHopError::Malformed(what))?;
    u64::try_from(u128::from_be_bytes(arr)).map_err(|_| RouteHopError::Malformed(what))
}

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
    let rc = decode_authenticated(route_commit_bytes)?;
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
    Ok(VerifiedRouteHop {
        initiator_public_key: rc.initiator_public_key.clone(),
        token_in: fixed32(&hop.token_in, "token_in must be 32 bytes")?,
        token_out: fixed32(&hop.token_out, "token_out must be 32 bytes")?,
        input_amount: narrow_amount(&hop.input_amount_u128, "input amount")?,
        expected_output: narrow_amount(&hop.expected_output_amount_u128, "expected output")?,
        fee_bps: hop.fee_bps,
    })
}

/// **2c-H H11 SAT.2 and H16, on the signed route alone.** A RouteCommit that
/// decodes, is signed ONCE over the whole route under its carried key, and
/// whose hops form one chain:
///
/// 1. at least one hop; every digest-shaped field is 32 bytes and every amount
///    narrows to u64;
/// 2. no vault and no parent state appears twice (RC.5 on the signed route);
/// 3. each hop hands its output asset and exact output to the next hop's input
///    (RC.1 and RC.2 on the signed route);
/// 4. the route's stated input asset and amount are its first hop's, and its
///    stated output asset and final output are its last hop's;
/// 5. `total_fee_bps` narrows to u32 and the nonce is 32 bytes.
///
/// Pure: no storage and no vault state. Whether each hop's output is what its
/// vault's curve yields is SAT.5-R's question, asked at that vault.
pub fn verify_route_commit_chain(
    route_commit_bytes: &[u8],
) -> Result<VerifiedRouteCommit, RouteHopError> {
    let rc = decode_authenticated(route_commit_bytes)?;
    let mut hops = Vec::with_capacity(rc.hops.len());
    for h in &rc.hops {
        hops.push(VerifiedChainHop {
            vault_id: fixed32(&h.vault_id, "hop vault_id must be 32 bytes")?,
            parent_binding: fixed32(&h.parent_binding, "hop parent_binding must be 32 bytes")?,
            token_in: fixed32(&h.token_in, "token_in must be 32 bytes")?,
            token_out: fixed32(&h.token_out, "token_out must be 32 bytes")?,
            input_amount: narrow_amount(&h.input_amount_u128, "input amount")?,
            expected_output: narrow_amount(&h.expected_output_amount_u128, "expected output")?,
            fee_bps: h.fee_bps,
        });
    }
    let (Some(first), Some(last)) = (hops.first(), hops.last()) else {
        return Err(RouteHopError::EmptyRoute);
    };
    for (i, hop) in hops.iter().enumerate() {
        if hops.iter().skip(i + 1).any(|later| {
            later.vault_id == hop.vault_id || later.parent_binding == hop.parent_binding
        }) {
            return Err(RouteHopError::HopRepeated { hop: i });
        }
        if let Some(next) = hops.get(i + 1) {
            if hop.token_out != next.token_in || hop.expected_output != next.input_amount {
                return Err(RouteHopError::ChainBroken { hop: i });
            }
        }
    }
    let input_token = fixed32(&rc.input_token, "input_token must be 32 bytes")?;
    let output_token = fixed32(&rc.output_token, "output_token must be 32 bytes")?;
    let input_amount = narrow_amount(&rc.input_amount_u128, "route input amount")?;
    let expected_final_output =
        narrow_amount(&rc.expected_final_output_amount_u128, "route final output")?;
    if first.token_in != input_token
        || first.input_amount != input_amount
        || last.token_out != output_token
        || last.expected_output != expected_final_output
    {
        return Err(RouteHopError::EndsDisagree);
    }
    let total_fee_bps = u32::try_from(rc.total_fee_bps)
        .map_err(|_| RouteHopError::Malformed("total_fee_bps must fit u32"))?;
    let nonce = fixed32(&rc.nonce, "nonce must be 32 bytes")?;
    Ok(VerifiedRouteCommit {
        initiator_public_key: rc.initiator_public_key,
        nonce,
        input_token,
        output_token,
        input_amount,
        expected_final_output,
        total_fee_bps,
        hops,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// THE FUSED-ROUNDING CONFORMANCE VECTOR (SoFi v2.0 §5.1).
    ///
    /// The spec fixes one floor division and forbids rounding the fee-adjusted
    /// input first. At `a=1, x=1, y=3, fee_bps=30` the two rules genuinely
    /// part company: the fused rule yields 1, while flooring `a·(D−f)/D` first
    /// collapses a sub-unit input to zero and takes the whole output with it.
    ///
    /// Note the spec's own example says this holds for "any fee_bps in the
    /// legal range", which overstates it: at `f=0` there is no fee to round
    /// and at `f=9999` both rules yield 0. The divergence is real for ordinary
    /// fees, which is where a low-liquidity vault actually operates, so the
    /// vector pins a fee that exhibits it rather than quoting the claim.
    #[test]
    fn the_fee_adjusted_input_is_never_rounded_before_the_curve() {
        const D: u128 = 10_000;
        let doubly_rounded = |a: u128, x: u128, y: u128, f: u128| -> u128 {
            let pre = (a * (D - f)) / D; // the forbidden first rounding
            if pre == 0 {
                return 0;
            }
            (y * pre * D) / (x * D + pre * D)
        };

        assert_eq!(
            constant_product_output(1, 1, 3, 30),
            Some(1),
            "the fused rule keeps the sub-unit input alive"
        );
        assert_eq!(
            doubly_rounded(1, 1, 3, 30),
            0,
            "…and the doubly-rounded variant loses the whole output"
        );

        // The same shape across a spread of ordinary fees, so the vector is
        // not a single lucky point.
        for f in [1u32, 5, 30, 100, 300] {
            assert_eq!(
                constant_product_output(1, 1, 3, f),
                Some(1),
                "fused rule at fee_bps={f}"
            );
            assert_eq!(
                doubly_rounded(1, 1, 3, f as u128),
                0,
                "doubly-rounded variant at fee_bps={f}"
            );
        }

        // Honest boundaries: with no fee there is nothing to round, and a
        // near-total fee zeroes both. Recording them stops a later reader
        // from "fixing" the vector by widening it to every legal fee.
        assert_eq!(constant_product_output(1, 1, 3, 0), Some(1));
        assert_eq!(doubly_rounded(1, 1, 3, 0), 1, "no fee, no divergence");
        assert_eq!(constant_product_output(1, 1, 3, 9_999), None);
    }

    // ── 2c-H H16: the signed route's own chain ──────────────────────────────

    fn chain_hop(
        vault: u8,
        parent: u8,
        token_in: u8,
        token_out: u8,
        input: u64,
        out: u64,
    ) -> generated::RouteCommitHopV1 {
        generated::RouteCommitHopV1 {
            vault_id: vec![vault; 32],
            token_in: vec![token_in; 32],
            token_out: vec![token_out; 32],
            input_amount_u128: u128::from(input).to_be_bytes().to_vec(),
            expected_output_amount_u128: u128::from(out).to_be_bytes().to_vec(),
            fee_bps: 30,
            parent_binding: vec![parent; 32],
            ..Default::default()
        }
    }

    /// A two-hop RouteCommit `0x10 → 0x30 → 0x20`, altered by `alter` BEFORE it
    /// is signed, so every refusal below is of a genuinely signed route.
    fn signed_chain(alter: impl FnOnce(&mut generated::RouteCommitV1)) -> Vec<u8> {
        let (pk, sk) = crate::crypto::sphincs::generate_sphincs_keypair().expect("keypair");
        let mut rc = generated::RouteCommitV1 {
            version: ROUTE_COMMIT_VERSION,
            nonce: vec![0x5E; 32],
            input_token: vec![0x10; 32],
            output_token: vec![0x20; 32],
            input_amount_u128: 10_000u128.to_be_bytes().to_vec(),
            expected_final_output_amount_u128: 2_000u128.to_be_bytes().to_vec(),
            total_fee_bps: 60,
            hops: vec![
                chain_hop(0x03, 0xE1, 0x10, 0x30, 10_000, 4_935),
                chain_hop(0x04, 0xE2, 0x30, 0x20, 4_935, 2_000),
            ],
            initiator_public_key: pk,
            ..Default::default()
        };
        alter(&mut rc);
        let canonical = canonicalise_for_commitment(&rc).encode_to_vec();
        rc.initiator_signature =
            crate::crypto::sphincs::sphincs_sign(&sk, &canonical).expect("sign");
        rc.encode_to_vec()
    }

    #[test]
    fn a_signed_chained_route_verifies_in_route_order() {
        let v = verify_route_commit_chain(&signed_chain(|_| {})).expect("a chained route");
        assert_eq!(v.hops.len(), 2);
        assert_eq!(
            (v.hops[0].vault_id, v.hops[1].vault_id),
            ([0x03; 32], [0x04; 32]),
            "route order, never sorted"
        );
        assert_eq!(
            (v.input_amount, v.expected_final_output, v.total_fee_bps),
            (10_000, 2_000, 60)
        );
    }

    #[test]
    fn a_route_whose_hops_do_not_chain_is_refused() {
        let amount_break = signed_chain(|rc| {
            rc.hops[1].input_amount_u128 = 4_936u128.to_be_bytes().to_vec();
        });
        assert_eq!(
            verify_route_commit_chain(&amount_break),
            Err(RouteHopError::ChainBroken { hop: 0 })
        );
        let token_break = signed_chain(|rc| rc.hops[1].token_in = vec![0x31; 32]);
        assert_eq!(
            verify_route_commit_chain(&token_break),
            Err(RouteHopError::ChainBroken { hop: 0 })
        );
    }

    #[test]
    fn a_route_naming_one_vault_or_one_parent_twice_is_refused() {
        let same_vault = signed_chain(|rc| rc.hops[1].vault_id = vec![0x03; 32]);
        assert_eq!(
            verify_route_commit_chain(&same_vault),
            Err(RouteHopError::HopRepeated { hop: 0 })
        );
        let same_parent = signed_chain(|rc| rc.hops[1].parent_binding = vec![0xE1; 32]);
        assert_eq!(
            verify_route_commit_chain(&same_parent),
            Err(RouteHopError::HopRepeated { hop: 0 })
        );
    }

    #[test]
    fn a_route_whose_ends_are_not_its_first_and_last_hops_is_refused() {
        let input = signed_chain(|rc| {
            rc.input_amount_u128 = 10_001u128.to_be_bytes().to_vec();
        });
        assert_eq!(
            verify_route_commit_chain(&input),
            Err(RouteHopError::EndsDisagree)
        );
        let output = signed_chain(|rc| rc.output_token = vec![0x30; 32]);
        assert_eq!(
            verify_route_commit_chain(&output),
            Err(RouteHopError::EndsDisagree)
        );
    }

    #[test]
    fn an_empty_or_tampered_route_is_refused() {
        assert_eq!(
            verify_route_commit_chain(&signed_chain(|rc| rc.hops.clear())),
            Err(RouteHopError::EmptyRoute)
        );
        let mut tampered =
            generated::RouteCommitV1::decode(signed_chain(|_| {}).as_slice()).expect("decodes");
        tampered.hops[1].expected_output_amount_u128 = 2_001u128.to_be_bytes().to_vec();
        assert_eq!(
            verify_route_commit_chain(&tampered.encode_to_vec()),
            Err(RouteHopError::SignatureInvalid)
        );
    }
}
