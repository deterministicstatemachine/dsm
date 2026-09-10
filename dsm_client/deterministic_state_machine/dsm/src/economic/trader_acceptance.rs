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
//! **There is no decoder here, deliberately.** Nothing in this crate consumes
//! a foreign `TA_B` yet, and a decoder with no verifier behind it is an
//! invitation to read a decoded acceptance as an accepted one. It lands with
//! §7, which is the only thing that can say what a decoded `TA_B` means.
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
}
