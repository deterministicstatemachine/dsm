// SPDX-License-Identifier: Apache-2.0

//! `SofiReceipt` — class `0x0034` schema 1, the Def 14.2 settlement receipt
//! (amendment 2c-F).
//!
//! A PROJECTION, NEVER A SOURCE. Every field re-derives from the canonical
//! market bundle `B` and the trader acceptance `TA_B` the walk certified:
//!
//! ```text
//! 1  bundle             b    = H_dom(DSM/settlement-bundle, CCB(B))
//! 2  route_commitment   X    = B.market_terms.route_set_commitment
//! 3  trader_acceptance  a_B  = H_dom(DSM/trader-settlement-acceptance/v2, CCB(TA_B))
//! 4  transitions        one entry c_{n+1} ‖ absent per T_v, strictly ascending
//! ```
//!
//! It carries no signature, no entropy, no clock and no node order, so every
//! party holding `(B, TA_B)` produces identical bytes. That determinism is what
//! makes publication idempotent and recovery a replay of the same bytes.
//!
//! WHAT IT IS NOT (2c-F R7). A receipt is evidence and an index object. It is
//! not certification, realization, binding finality or trader acceptance, and
//! no composition, admission, realization, fence, certification or
//! reserve-provenance rule may take one — its bytes, its address, its presence
//! or its publication state — as input. [`verify`] establishes only that bytes
//! are the projection of a given `(B, a_B)`. Whether that `B` was realized is
//! the composition walk's question, never this module's.
//!
//! `witness_hash` IS ALWAYS ABSENT in schema 1 (2c-F, the ruling on R3). It is
//! emitted as the §2.3 absent marker so Def 14.2's pair shape survives, and a
//! present marker is refused. Proof material in `B` never makes a receipt
//! unconstructible: the receipt does not commit to it and adds no
//! witness-validity rule of its own.
//!
//! The digest `ρ_B` is NOT `settlement_receipt_id`. That value is
//! `derive_receipt_id(vault_id, X)` and names the V1 / economic receipt family.

use crate::ccb::decode::{Cursor, DecodeError};
use crate::ccb::{
    class, push_absent, push_digest32, push_envelope, push_u32, vault_state_commitment, CcbError,
    CcbObject, SettlementBundle,
};
use crate::common::domain_tags::TAG_DSM_SOFI_RECEIPT_V1;
use crate::storage_object::{immutable_addr, immutable_inner};

/// One field-4 entry: the successor commitment and the absent witness marker.
const ENTRY_LEN: usize = 32 + 1;

/// The canonical length at beta cardinality (one `T_v`): 4 envelope, three
/// `digest32`, a 4-byte count and one entry.
pub const SOFI_RECEIPT_BETA_LEN: usize = 4 + 3 * 32 + 4 + ENTRY_LEN;

/// `0x0034` schema 1 (registry §5.42).
///
/// Private fields and one constructor, [`SofiReceipt::project`], so a value
/// of this type is always the projection of some market bundle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SofiReceipt {
    bundle: [u8; 32],
    route_commitment: [u8; 32],
    trader_acceptance: [u8; 32],
    /// `c_{n+1}` of each transition, strictly ascending. Every entry's
    /// `enc` is `c_{n+1} ‖ 0x00`, so byte order over the successors IS the
    /// §2.4 order over the entries.
    successors: Vec<[u8; 32]>,
}

impl CcbObject for SofiReceipt {
    const CLASS: u16 = class::SOFI_RECEIPT;
    const SCHEMA: u16 = 1;
}

/// Why a bundle has no receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProjectionRefusal {
    /// An owner close carries no trader acceptance, so Def 14.2 does not
    /// apply to it.
    NotMarket,
    /// The bundle or one of its successors could not be encoded.
    Encode(CcbError),
    /// Two transitions name the same successor. Unreachable under beta's
    /// cardinality; kept because the set rule forbids duplicates.
    DuplicateSuccessor,
}

impl core::fmt::Display for ProjectionRefusal {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NotMarket => write!(
                f,
                "an owner close has no trader acceptance to bind, so it has no Def 14.2 receipt"
            ),
            Self::Encode(e) => write!(f, "the bundle does not encode: {e}"),
            Self::DuplicateSuccessor => write!(
                f,
                "two transitions name one successor, and a receipt's transitions are a set"
            ),
        }
    }
}

impl SofiReceipt {
    /// The receipt of market bundle `bundle`, binding the trader acceptance
    /// whose identity is `trader_acceptance`.
    ///
    /// `trader_acceptance` is `a_B` — the INNER identity `ta_B`, never the
    /// acceptance's storage address.
    pub fn project(
        bundle: &SettlementBundle,
        trader_acceptance: [u8; 32],
    ) -> Result<Self, ProjectionRefusal> {
        let terms = bundle.market_terms().ok_or(ProjectionRefusal::NotMarket)?;
        let canon = bundle.encode().map_err(ProjectionRefusal::Encode)?;
        let mut successors = bundle
            .transitions()
            .iter()
            .map(|t| vault_state_commitment(&t.successor))
            .collect::<Result<Vec<_>, _>>()
            .map_err(ProjectionRefusal::Encode)?;
        successors.sort_unstable();
        if successors.windows(2).any(|w| w[0] == w[1]) {
            return Err(ProjectionRefusal::DuplicateSuccessor);
        }
        Ok(Self {
            bundle: crate::dlv::settlement_bundle::bundle_digest(&canon),
            route_commitment: terms.route_set_commitment,
            trader_acceptance,
            successors,
        })
    }

    /// Field 1, `b`.
    pub const fn bundle(&self) -> [u8; 32] {
        self.bundle
    }

    /// Field 2, `X`.
    pub const fn route_commitment(&self) -> [u8; 32] {
        self.route_commitment
    }

    /// Field 3, `a_B`.
    pub const fn trader_acceptance(&self) -> [u8; 32] {
        self.trader_acceptance
    }

    /// Field 4's successor commitments, in canonical order.
    pub fn successors(&self) -> &[[u8; 32]] {
        &self.successors
    }

    /// Canonical CCB bytes, registry §5.42.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + 3 * 32 + 4 + ENTRY_LEN * self.successors.len());
        push_envelope::<Self>(&mut out);
        push_digest32(&mut out, &self.bundle); // 1
        push_digest32(&mut out, &self.route_commitment); // 2
        push_digest32(&mut out, &self.trader_acceptance); // 3
        push_u32(&mut out, self.successors.len() as u32); // 4 — a §2.4 set
        for successor in &self.successors {
            push_digest32(&mut out, successor);
            push_absent(&mut out); // witness_hash: absent in schema 1
        }
        out
    }

    /// `ρ_B = H_dom(DSM/sofi-receipt/v1, CCB(SofiReceipt))`.
    pub fn digest(&self) -> [u8; 32] {
        immutable_inner(TAG_DSM_SOFI_RECEIPT_V1, &self.encode())
    }

    /// The content address the receipt is stored and retrieved under.
    pub fn address(&self) -> [u8; 32] {
        immutable_addr(TAG_DSM_SOFI_RECEIPT_V1, &self.encode())
    }
}

/// Why bytes are not a canonical `SofiReceipt` (registry §5.42).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SofiReceiptDecodeError {
    /// Wrong envelope, truncated, or trailing input.
    Layout(DecodeError),
    /// Field 4 carries no entry: a receipt projects at least one transition.
    NoTransitions,
    /// An entry carries a witness: schema 1 carries none.
    WitnessPresent,
    /// An entry's marker is neither the absent nor the present byte.
    BadMarker(u8),
    /// Field 4 is not strictly ascending: misordered, or a duplicate.
    NotStrictlyAscending,
}

impl core::fmt::Display for SofiReceiptDecodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Layout(e) => write!(f, "not a SofiReceipt layout: {e}"),
            Self::NoTransitions => write!(f, "a receipt that projects no transition projects nothing"),
            Self::WitnessPresent => write!(
                f,
                "schema 1 carries no witness hash; a present marker names a rule that does not exist"
            ),
            Self::BadMarker(m) => write!(f, "optional marker {m:#04x} is neither absent nor present"),
            Self::NotStrictlyAscending => write!(
                f,
                "field 4 is a set: entries must be strictly ascending, with no duplicate"
            ),
        }
    }
}

/// Decode canonical `SofiReceipt` bytes, strictly.
///
/// Every field is fixed-width and the order is pinned, so an exact-length
/// parse of this layout IS the canonical encoding;
/// `decoded_bytes_re_encode_to_themselves` pins that claim. **A decoded
/// receipt is still only a claim** about some `(B, a_B)`: [`verify`] checks
/// it against a given pair, and nothing makes it authority.
pub fn decode_sofi_receipt(bytes: &[u8]) -> Result<SofiReceipt, SofiReceiptDecodeError> {
    let layout = SofiReceiptDecodeError::Layout;
    let mut c = Cursor { b: bytes, i: 0 };
    c.envelope(SofiReceipt::CLASS, SofiReceipt::SCHEMA)
        .map_err(layout)?;
    let bundle = c.digest32().map_err(layout)?;
    let route_commitment = c.digest32().map_err(layout)?;
    let trader_acceptance = c.digest32().map_err(layout)?;
    let count = c.u32().map_err(layout)? as usize;
    if count == 0 {
        return Err(SofiReceiptDecodeError::NoTransitions);
    }
    // Bound the allocation by what the remaining bytes can actually hold.
    if count > (bytes.len() - c.i) / ENTRY_LEN {
        return Err(layout(DecodeError::Truncated));
    }
    let mut successors: Vec<[u8; 32]> = Vec::with_capacity(count);
    for _ in 0..count {
        let successor = c.digest32().map_err(layout)?;
        match c.u8().map_err(layout)? {
            0x00 => {}
            0x01 => return Err(SofiReceiptDecodeError::WitnessPresent),
            other => return Err(SofiReceiptDecodeError::BadMarker(other)),
        }
        if successors.last().is_some_and(|prev| *prev >= successor) {
            return Err(SofiReceiptDecodeError::NotStrictlyAscending);
        }
        successors.push(successor);
    }
    if c.i != bytes.len() {
        return Err(layout(DecodeError::TrailingBytes {
            extra: bytes.len() - c.i,
        }));
    }
    Ok(SofiReceipt {
        bundle,
        route_commitment,
        trader_acceptance,
        successors,
    })
}

/// A receipt field that does not re-derive from `(B, a_B)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiptField {
    Bundle,
    RouteCommitment,
    TraderAcceptance,
    Transitions,
}

/// Why receipt bytes are not the receipt of a given `(B, a_B)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SofiReceiptVerifyError {
    Decode(SofiReceiptDecodeError),
    Projection(ProjectionRefusal),
    /// The first field, in field order, whose carried value is not the one
    /// `(B, a_B)` derives.
    Mismatch(ReceiptField),
}

impl core::fmt::Display for SofiReceiptVerifyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Decode(e) => write!(f, "{e}"),
            Self::Projection(e) => write!(f, "{e}"),
            Self::Mismatch(field) => write!(
                f,
                "the receipt's {field:?} is not the one the bundle and acceptance derive — a \
                 receipt is a projection, so a field it carries is never believed over its source"
            ),
        }
    }
}

/// Check that `receipt_bytes` are exactly the receipt of `bundle` binding
/// `trader_acceptance`: decode strictly, re-derive, compare field by field.
///
/// Establishes a PROJECTION fact only. It says nothing about whether `bundle`
/// was binding-final, accepted or realized, and its result must not be read as
/// if it did (2c-F R7).
pub fn verify(
    receipt_bytes: &[u8],
    bundle: &SettlementBundle,
    trader_acceptance: [u8; 32],
) -> Result<SofiReceipt, SofiReceiptVerifyError> {
    let carried = decode_sofi_receipt(receipt_bytes).map_err(SofiReceiptVerifyError::Decode)?;
    let derived = SofiReceipt::project(bundle, trader_acceptance)
        .map_err(SofiReceiptVerifyError::Projection)?;
    let checks = [
        (ReceiptField::Bundle, carried.bundle == derived.bundle),
        (
            ReceiptField::RouteCommitment,
            carried.route_commitment == derived.route_commitment,
        ),
        (
            ReceiptField::TraderAcceptance,
            carried.trader_acceptance == derived.trader_acceptance,
        ),
        (
            ReceiptField::Transitions,
            carried.successors == derived.successors,
        ),
    ];
    if let Some((field, _)) = checks.iter().find(|(_, holds)| !holds) {
        return Err(SofiReceiptVerifyError::Mismatch(*field));
    }
    Ok(carried)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::ccb::settlement::fixtures;

    const PARENT: [u8; 32] = [0xC0; 32];
    const X: [u8; 32] = [0x58; 32];
    const A_B: [u8; 32] = [0xAB; 32];

    fn market() -> SettlementBundle {
        fixtures::market_bundle(PARENT, fixtures::successor(PARENT, 1_010_000, 495_065), X)
    }

    fn receipt_bytes() -> Vec<u8> {
        SofiReceipt::project(&market(), A_B).unwrap().encode()
    }

    /// The first entry's witness marker: after the envelope, three digests,
    /// the count and the successor.
    const MARKER_AT: usize = 4 + 3 * 32 + 4 + 32;

    #[test]
    fn a_beta_receipt_encodes_to_the_frozen_length() {
        assert_eq!(receipt_bytes().len(), SOFI_RECEIPT_BETA_LEN);
        assert_eq!(SOFI_RECEIPT_BETA_LEN, 137, "registry §5.42 pins 137 bytes");
    }

    #[test]
    fn every_field_re_derives_from_the_bundle_and_the_acceptance() {
        let bundle = market();
        let r = SofiReceipt::project(&bundle, A_B).unwrap();
        let canon = bundle.encode().unwrap();
        assert_eq!(
            r.bundle(),
            crate::dlv::settlement_bundle::bundle_digest(&canon)
        );
        assert_eq!(r.route_commitment(), X);
        assert_eq!(r.trader_acceptance(), A_B);
        assert_eq!(
            r.successors(),
            &[vault_state_commitment(&bundle.transitions()[0].successor).unwrap()]
        );
        // The same inputs, twice: identical bytes. Nothing else enters.
        assert_eq!(
            SofiReceipt::project(&market(), A_B).unwrap().encode(),
            r.encode()
        );
    }

    #[test]
    fn the_layout_is_the_registry_table() {
        let bytes = receipt_bytes();
        let r = decode_sofi_receipt(&bytes).unwrap();
        assert_eq!(&bytes[..4], &[0x00, 0x34, 0x00, 0x01], "0x0034 schema 1");
        assert_eq!(&bytes[4..36], &r.bundle());
        assert_eq!(&bytes[36..68], &X);
        assert_eq!(&bytes[68..100], &A_B);
        assert_eq!(&bytes[100..104], &[0, 0, 0, 1], "one transition");
        assert_eq!(&bytes[104..136], &r.successors()[0]);
        assert_eq!(bytes[MARKER_AT], 0x00, "witness_hash absent");
    }

    #[test]
    fn decoded_bytes_re_encode_to_themselves() {
        let bytes = receipt_bytes();
        assert_eq!(decode_sofi_receipt(&bytes).unwrap().encode(), bytes);
    }

    #[test]
    fn the_digest_and_address_are_the_domain_separated_identities() {
        let bytes = receipt_bytes();
        let r = decode_sofi_receipt(&bytes).unwrap();
        // Independent of `immutable_inner`: the frozen `BLAKE3(N ‖ 0x00 ‖ P)`.
        let mut h = blake3::Hasher::new();
        h.update(b"DSM/sofi-receipt/v1");
        h.update(&[0u8]);
        h.update(&bytes);
        assert_eq!(r.digest(), *h.finalize().as_bytes());
        let mut a = blake3::Hasher::new();
        a.update(b"DSM/storage-object");
        a.update(&[0u8]);
        a.update(b"DSM/sofi-receipt/v1");
        a.update(&r.digest());
        assert_eq!(r.address(), *a.finalize().as_bytes());
    }

    #[test]
    fn an_owner_close_has_no_receipt() {
        let close = fixtures::owner_close_bundle(PARENT, fixtures::successor(PARENT, 0, 0));
        assert_eq!(
            SofiReceipt::project(&close, A_B),
            Err(ProjectionRefusal::NotMarket)
        );
    }

    #[test]
    fn a_present_witness_is_refused() {
        let mut bytes = receipt_bytes();
        bytes[MARKER_AT] = 0x01;
        bytes.extend_from_slice(&[0x77; 32]);
        assert_eq!(
            decode_sofi_receipt(&bytes),
            Err(SofiReceiptDecodeError::WitnessPresent)
        );
    }

    #[test]
    fn a_marker_that_is_neither_absent_nor_present_is_refused() {
        let mut bytes = receipt_bytes();
        bytes[MARKER_AT] = 0x02;
        assert_eq!(
            decode_sofi_receipt(&bytes),
            Err(SofiReceiptDecodeError::BadMarker(0x02))
        );
    }

    #[test]
    fn an_empty_transition_set_is_refused() {
        let mut bytes = receipt_bytes()[..100].to_vec();
        bytes.extend_from_slice(&[0, 0, 0, 0]);
        assert_eq!(
            decode_sofi_receipt(&bytes),
            Err(SofiReceiptDecodeError::NoTransitions)
        );
    }

    fn with_entries(entries: &[[u8; 32]]) -> Vec<u8> {
        let mut bytes = receipt_bytes()[..100].to_vec();
        bytes.extend_from_slice(&(entries.len() as u32).to_be_bytes());
        for e in entries {
            bytes.extend_from_slice(e);
            bytes.push(0x00);
        }
        bytes
    }

    #[test]
    fn misordered_and_duplicated_entries_are_refused() {
        assert_eq!(
            decode_sofi_receipt(&with_entries(&[[0x02; 32], [0x01; 32]])),
            Err(SofiReceiptDecodeError::NotStrictlyAscending)
        );
        assert_eq!(
            decode_sofi_receipt(&with_entries(&[[0x01; 32], [0x01; 32]])),
            Err(SofiReceiptDecodeError::NotStrictlyAscending)
        );
        assert!(decode_sofi_receipt(&with_entries(&[[0x01; 32], [0x02; 32]])).is_ok());
    }

    #[test]
    fn the_wrong_envelope_truncation_and_trailing_bytes_are_refused() {
        let mut wrong = receipt_bytes();
        wrong[1] = 0x33;
        assert_eq!(
            decode_sofi_receipt(&wrong),
            Err(SofiReceiptDecodeError::Layout(DecodeError::WrongClass {
                got: 0x0033
            }))
        );
        let bytes = receipt_bytes();
        assert_eq!(
            decode_sofi_receipt(&bytes[..bytes.len() - 1]),
            Err(SofiReceiptDecodeError::Layout(DecodeError::Truncated))
        );
        let mut long = receipt_bytes();
        long.push(0x00);
        assert_eq!(
            decode_sofi_receipt(&long),
            Err(SofiReceiptDecodeError::Layout(DecodeError::TrailingBytes {
                extra: 1
            }))
        );
        // A count the bytes cannot hold is refused before anything is
        // allocated for it.
        let mut huge = receipt_bytes()[..100].to_vec();
        huge.extend_from_slice(&u32::MAX.to_be_bytes());
        assert_eq!(
            decode_sofi_receipt(&huge),
            Err(SofiReceiptDecodeError::Layout(DecodeError::Truncated))
        );
    }

    #[test]
    fn verification_names_the_first_field_that_does_not_re_derive() {
        let bundle = market();
        let good = receipt_bytes();
        assert!(verify(&good, &bundle, A_B).is_ok());

        assert_eq!(
            verify(&good, &bundle, [0xAC; 32]),
            Err(SofiReceiptVerifyError::Mismatch(
                ReceiptField::TraderAcceptance
            ))
        );
        let field = |at: usize, which: ReceiptField| {
            let mut bytes = good.clone();
            bytes[at] ^= 0x01;
            assert_eq!(
                verify(&bytes, &bundle, A_B),
                Err(SofiReceiptVerifyError::Mismatch(which))
            );
        };
        field(4, ReceiptField::Bundle);
        field(36, ReceiptField::RouteCommitment);
        field(104, ReceiptField::Transitions);
    }
}
