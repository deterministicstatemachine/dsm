// SPDX-License-Identifier: Apache-2.0

//! `TraderAcceptance` (`TA_B`) — class `0x0011` schema 1, amendment 2c-D §6.
//!
//! THE ARTIFACT, AND NOT THE VERDICT. This module builds `TA_B`, encodes it,
//! and computes `ta_B`. It does **not** verify one: 2c-D §7's seven ordered
//! conjuncts — authenticate `G` against `sigma_dsm`, walk to `R_T^+`, require
//! the accepted successor, bind the operation identity, fold the path, obtain
//! `b`, bind the economics — are a separate change, and until they exist
//! holding a well-formed `TA_B` establishes nothing about realization.
//!
//! **The decoder lands with its consumer.** Until the realization cutover
//! nothing fetched a foreign `TA_B`, and a decoder with no verifier behind it
//! was an invitation to read a decoded acceptance as an accepted one. The
//! composition walk now fetches one by content address and hands it straight
//! to 2c-D §7 — the only thing that can say what a decoded `TA_B` means.
//!
//! Say that precisely, because the shape invites the opposite reading: a
//! `TA_B` that decodes is a claim someone serialized. It is not evidence that
//! the bundle it names was accepted, that the path folds to any real root,
//! that the trader ever advanced, or that any settlement occurred. **Do not
//! read this type as a realization fact**, and do not add a method that would
//! let a caller mistake it for one.
//!
//! WHY FOUR FIELDS AND NOT NINE. The draft in amendment 2c §2 carried the
//! trader coordinates and `b` itself. 2c-D's rulings removed everything
//! recoverable from what the artifact already proves:
//!
//! ```text
//! recoverable from the authenticated bundle b   X, trader_parent,
//!                                               trader_successor,
//!                                               trader_devid
//! recoverable from the authenticated leaf       bundle (b)
//! ```
//!
//! `trader_genesis` survives because it is recoverable from NEITHER: it enters
//! only through `sigma_dsm`'s signing digest, so a verifier can CHECK a
//! candidate `G` against `b` but cannot RECOVER one — and the leaf key needs
//! it. It is carried as an authenticated witness, never as authority
//! (ruling D1).
//!
//! There is no `ta_B` field: the Def 14.2 public Receipt binds `ta_B`, so a
//! reciprocal field would be circular. There is no `post_economic_root`
//! either — the root is DERIVED by the walk from fields 1–2, and carrying it
//! would invite a verifier to read the carried value instead of deriving it,
//! which is the failure Req 21.17 tests for. Ruling D2 applies exactly that
//! reasoning to `b`.

use crate::ccb::{class, push_digest32, push_envelope, push_u32, push_u64, CcbError, CcbObject};
use crate::common::domain_tags::TAG_DSM_TRADER_SETTLEMENT_ACCEPTANCE;
use crate::crypto::blake3::dsm_domain_hasher;
use crate::economic::state::{EconomicBundleAcceptanceState, EconomicLeafState};
use crate::economic::tree::ECONOMIC_SMT_HEIGHT;

/// The exact canonical length: 4 envelope + 32 `G` + 8 position + 68 nested
/// leaf + 4 sequence count + 256×32 siblings.
///
/// The nested leaf is 68 bytes, not 36: amendment 2c-D ruling D3 gave `0x0032`
/// its second field, `economic_operation_id`. A nested object's size is the
/// enclosing object's size, so this constant moves whenever that one does.
pub const TRADER_ACCEPTANCE_LEN: usize = 4 + 32 + 8 + 68 + 4 + 32 * ECONOMIC_SMT_HEIGHT;

/// `0x0011` schema 1 — a trader's acceptance of one settlement bundle,
/// packaged with the proof that its own economic state committed that bundle.
///
/// Fields are private and the constructor checks the frozen rejections, so an
/// invalid `TA_B` has no canonical bytes at all and cannot be hash-addressed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraderAcceptance {
    trader_genesis: [u8; 32],
    economic_position: u64,
    acceptance_leaf: EconomicBundleAcceptanceState,
    acceptance_path: Vec<[u8; 32]>,
}

impl CcbObject for TraderAcceptance {
    const CLASS: u16 = class::TRADER_ACCEPTANCE;
    const SCHEMA: u16 = 1;
}

/// Why a `TraderAcceptance` could not be formed.
///
/// Structured, never a string: these are the frozen rejections of registry
/// §5.40, and a caller that wants to distinguish them should not have to parse
/// prose.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AcceptanceMalformed {
    /// `acceptance_path` is not exactly `ECONOMIC_SMT_HEIGHT` siblings.
    PathLength { expected: usize, got: usize },
    /// `trader_genesis` is all-zero.
    GenesisIsZero,
}

impl core::fmt::Display for AcceptanceMalformed {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::PathLength { expected, got } => write!(
                f,
                "a trader acceptance proves inclusion at tree depth, so its path is exactly \
                 {expected} siblings; this one carries {got}"
            ),
            Self::GenesisIsZero => write!(
                f,
                "the trader genesis is all-zero, so no signing digest could be reconstructed \
                 to authenticate it"
            ),
        }
    }
}

impl TraderAcceptance {
    /// Build one, refusing the frozen rejections.
    ///
    /// The leaf's own validity is its type's: an `EconomicBundleAcceptanceState`
    /// that exists has a non-zero bundle and canonical bytes, so there is
    /// nothing left for this constructor to re-check about it.
    pub fn new(
        trader_genesis: [u8; 32],
        economic_position: u64,
        acceptance_leaf: EconomicBundleAcceptanceState,
        acceptance_path: Vec<[u8; 32]>,
    ) -> Result<Self, AcceptanceMalformed> {
        if acceptance_path.len() != ECONOMIC_SMT_HEIGHT {
            return Err(AcceptanceMalformed::PathLength {
                expected: ECONOMIC_SMT_HEIGHT,
                got: acceptance_path.len(),
            });
        }
        if trader_genesis == [0u8; 32] {
            return Err(AcceptanceMalformed::GenesisIsZero);
        }
        Ok(Self {
            trader_genesis,
            economic_position,
            acceptance_leaf,
            acceptance_path,
        })
    }

    /// The trader's genesis, as CARRIED. **Not authenticated by holding this
    /// value** — 2c-D §7 step 2 authenticates it against `sigma_dsm` before the
    /// leaf key may be derived from it, and nothing here has done that.
    pub const fn trader_genesis(&self) -> [u8; 32] {
        self.trader_genesis
    }

    /// The untrusted locator: where to begin the validity walk, never
    /// authority for its result.
    pub const fn economic_position(&self) -> u64 {
        self.economic_position
    }

    /// The nested bundle-acceptance leaf. Its `bundle` is authoritative for
    /// `b` only after §7 has folded the path to the validated root — before
    /// that it is a value someone wrote down.
    pub const fn acceptance_leaf(&self) -> &EconomicBundleAcceptanceState {
        &self.acceptance_leaf
    }

    /// The 256 siblings, leaf-to-root.
    pub fn acceptance_path(&self) -> &[[u8; 32]] {
        &self.acceptance_path
    }

    /// Canonical CCB bytes, registry §5.40.
    pub fn encode(&self) -> Result<Vec<u8>, CcbError> {
        let mut out = Vec::with_capacity(TRADER_ACCEPTANCE_LEN);
        push_envelope::<Self>(&mut out);
        push_digest32(&mut out, &self.trader_genesis); // 1
        push_u64(&mut out, self.economic_position); // 2
                                                    // 3 — the complete nested CCB (§2.7), encoded THROUGH the leaf-state
                                                    // family rather than by reaching into the arm. Every leaf state's own
                                                    // `encode` is private for that reason: one dispatch point means a
                                                    // nested leaf and a leaf written to the tree cannot encode differently.
        out.extend_from_slice(
            &EconomicLeafState::BundleAcceptance(self.acceptance_leaf.clone()).encode()?,
        );
        // 4 — a §2.5 SEQUENCE, not a set: position is tree depth, so the order
        // is meaning and duplicate siblings are legal.
        push_u32(&mut out, ECONOMIC_SMT_HEIGHT as u32);
        for sibling in &self.acceptance_path {
            push_digest32(&mut out, sibling);
        }
        Ok(out)
    }

    /// `ta_B = H_dom(DSM/trader-settlement-acceptance/v2, CCB(TA_B))`.
    ///
    /// The `/v2` is the tag Rev 15 reserves for this artifact and is **not** a
    /// schema version; the CCB schema is 1.
    pub fn ta_b(&self) -> Result<[u8; 32], CcbError> {
        let ccb = self.encode()?;
        let mut h = dsm_domain_hasher(TAG_DSM_TRADER_SETTLEMENT_ACCEPTANCE);
        h.update(&ccb);
        Ok(*h.finalize().as_bytes())
    }
}

/// Why bytes are not a canonical `TA_B` (registry §5.40).
///
/// There is no "not canonical" arm: every field is fixed-width and the path
/// count is pinned, so an exact-length parse of this layout IS the canonical
/// encoding. `decoded_bytes_re_encode_to_themselves` pins that claim rather
/// than leaving it to be believed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AcceptanceDecodeError {
    /// The bytes do not follow the layout: wrong envelope, truncated, or
    /// trailing input.
    Layout(crate::ccb::decode::DecodeError),
    /// Field 3 is not a canonical `0x0032` schema 1 bundle-acceptance leaf.
    LeafNotBundleAcceptance,
    /// The layout parsed, but the object violates a frozen rejection.
    Malformed(AcceptanceMalformed),
}

impl core::fmt::Display for AcceptanceDecodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Layout(e) => write!(f, "not a TA_B layout: {e}"),
            Self::LeafNotBundleAcceptance => write!(
                f,
                "field 3 is not a canonical 0x0032 leaf, so there is no acceptance to verify"
            ),
            Self::Malformed(e) => write!(f, "{e}"),
        }
    }
}

/// The nested `0x0032` schema 1 leaf: its envelope and two `digest32`.
const NESTED_LEAF_LEN: usize = 4 + 32 + 32;

/// Decode canonical `TA_B` bytes. **A decoded acceptance is still a claim**:
/// it becomes evidence only when 2c-D §7's verifier returns a witness for it.
pub fn decode_trader_acceptance(bytes: &[u8]) -> Result<TraderAcceptance, AcceptanceDecodeError> {
    use crate::ccb::decode::{Cursor, DecodeError};
    let layout = AcceptanceDecodeError::Layout;
    let mut c = Cursor { b: bytes, i: 0 };
    c.envelope(TraderAcceptance::CLASS, TraderAcceptance::SCHEMA)
        .map_err(layout)?;
    let trader_genesis = c.digest32().map_err(layout)?;
    let economic_position = c.u64().map_err(layout)?;
    let leaf = match crate::economic::decode::decode_leaf_state(
        c.take(NESTED_LEAF_LEN).map_err(layout)?,
    ) {
        Ok(EconomicLeafState::BundleAcceptance(leaf)) => leaf,
        _ => return Err(AcceptanceDecodeError::LeafNotBundleAcceptance),
    };
    let count = c.u32().map_err(layout)? as usize;
    if count != ECONOMIC_SMT_HEIGHT {
        return Err(AcceptanceDecodeError::Malformed(
            AcceptanceMalformed::PathLength {
                expected: ECONOMIC_SMT_HEIGHT,
                got: count,
            },
        ));
    }
    let mut path = Vec::with_capacity(ECONOMIC_SMT_HEIGHT);
    for _ in 0..ECONOMIC_SMT_HEIGHT {
        path.push(c.digest32().map_err(layout)?);
    }
    if c.i != bytes.len() {
        return Err(layout(DecodeError::TrailingBytes {
            extra: bytes.len() - c.i,
        }));
    }
    TraderAcceptance::new(trader_genesis, economic_position, leaf, path)
        .map_err(AcceptanceDecodeError::Malformed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaf() -> EconomicBundleAcceptanceState {
        EconomicBundleAcceptanceState {
            bundle: [0xB0; 32],
            economic_operation_id: [0x50; 32],
        }
    }

    fn path() -> Vec<[u8; 32]> {
        vec![[0x00; 32]; ECONOMIC_SMT_HEIGHT]
    }

    #[test]
    fn a_well_formed_acceptance_encodes_to_the_frozen_length() {
        let ta = TraderAcceptance::new([0x11; 32], 3, leaf(), path()).expect("well formed");
        assert_eq!(ta.encode().expect("encodable").len(), TRADER_ACCEPTANCE_LEN);
        assert_eq!(
            TRADER_ACCEPTANCE_LEN, 8_308,
            "registry §5.40 pins 8,308 bytes"
        );
    }

    #[test]
    fn a_short_path_is_refused_rather_than_padded() {
        let mut p = path();
        p.pop();
        assert_eq!(
            TraderAcceptance::new([0x11; 32], 3, leaf(), p),
            Err(AcceptanceMalformed::PathLength {
                expected: ECONOMIC_SMT_HEIGHT,
                got: ECONOMIC_SMT_HEIGHT - 1,
            })
        );
    }

    #[test]
    fn a_long_path_is_refused_rather_than_truncated() {
        let mut p = path();
        p.push([0x01; 32]);
        assert!(matches!(
            TraderAcceptance::new([0x11; 32], 3, leaf(), p),
            Err(AcceptanceMalformed::PathLength { .. })
        ));
    }

    #[test]
    fn an_all_zero_genesis_is_refused() {
        assert_eq!(
            TraderAcceptance::new([0u8; 32], 3, leaf(), path()),
            Err(AcceptanceMalformed::GenesisIsZero)
        );
    }

    /// Every field reaches the bytes: change one, and `ta_B` moves. A field
    /// that could be altered without moving the identity would be a field the
    /// digest does not cover.
    #[test]
    fn every_field_moves_the_identity() {
        let base = TraderAcceptance::new([0x11; 32], 3, leaf(), path()).expect("base");
        let id = base.ta_b().expect("id");

        let other_g = TraderAcceptance::new([0x12; 32], 3, leaf(), path()).expect("g");
        assert_ne!(other_g.ta_b().expect("id"), id, "trader_genesis");

        let other_pos = TraderAcceptance::new([0x11; 32], 4, leaf(), path()).expect("pos");
        assert_ne!(other_pos.ta_b().expect("id"), id, "economic_position");

        let other_leaf = TraderAcceptance::new(
            [0x11; 32],
            3,
            EconomicBundleAcceptanceState {
                bundle: [0xB1; 32],
                economic_operation_id: [0x50; 32],
            },
            path(),
        )
        .expect("leaf");
        assert_ne!(other_leaf.ta_b().expect("id"), id, "acceptance_leaf");

        let mut p = path();
        p[0] = [0x01; 32];
        let other_path = TraderAcceptance::new([0x11; 32], 3, leaf(), p).expect("path");
        assert_ne!(other_path.ta_b().expect("id"), id, "acceptance_path");
    }

    fn acceptance() -> TraderAcceptance {
        TraderAcceptance::new([0x11; 32], 3, leaf(), path()).expect("well formed")
    }

    #[test]
    fn decoded_bytes_re_encode_to_themselves() {
        let bytes = acceptance().encode().expect("encodable");
        let back = decode_trader_acceptance(&bytes).expect("decodes");
        assert_eq!(back, acceptance());
        assert_eq!(
            back.encode().expect("encodable"),
            bytes,
            "decode is canonical"
        );
    }

    #[test]
    fn truncated_or_trailing_bytes_are_not_an_acceptance() {
        let bytes = acceptance().encode().expect("encodable");
        assert!(matches!(
            decode_trader_acceptance(&bytes[..bytes.len() - 1]),
            Err(AcceptanceDecodeError::Layout(_))
        ));
        let mut long = bytes;
        long.push(0);
        assert!(matches!(
            decode_trader_acceptance(&long),
            Err(AcceptanceDecodeError::Layout(
                crate::ccb::decode::DecodeError::TrailingBytes { extra: 1 }
            ))
        ));
    }

    #[test]
    fn another_class_is_not_an_acceptance() {
        let mut bytes = acceptance().encode().expect("encodable");
        bytes[1] = 0x12;
        assert!(matches!(
            decode_trader_acceptance(&bytes),
            Err(AcceptanceDecodeError::Layout(_))
        ));
    }

    /// Field 3 must be a bundle-acceptance leaf, not merely 68 bytes.
    #[test]
    fn a_nested_leaf_of_another_class_is_refused() {
        let mut bytes = acceptance().encode().expect("encodable");
        bytes[4 + 32 + 8 + 1] = 0x31; // the nested envelope's class, 0x0032 -> 0x0031
        assert_eq!(
            decode_trader_acceptance(&bytes),
            Err(AcceptanceDecodeError::LeafNotBundleAcceptance)
        );
    }

    /// The frozen rejections apply to decoded bytes exactly as to built ones.
    #[test]
    fn decoded_bytes_meet_the_frozen_rejections() {
        let mut short_count = acceptance().encode().expect("encodable");
        let at = 4 + 32 + 8 + NESTED_LEAF_LEN;
        short_count[at..at + 4].copy_from_slice(&255u32.to_be_bytes());
        assert_eq!(
            decode_trader_acceptance(&short_count),
            Err(AcceptanceDecodeError::Malformed(
                AcceptanceMalformed::PathLength {
                    expected: 256,
                    got: 255
                }
            ))
        );
        let mut zero_genesis = acceptance().encode().expect("encodable");
        zero_genesis[4..36].copy_from_slice(&[0u8; 32]);
        assert_eq!(
            decode_trader_acceptance(&zero_genesis),
            Err(AcceptanceDecodeError::Malformed(
                AcceptanceMalformed::GenesisIsZero
            ))
        );
    }
}
