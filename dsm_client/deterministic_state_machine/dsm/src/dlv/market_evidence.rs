// SPDX-License-Identifier: Apache-2.0

//! THE VALIDITY HALF OF MARKET SUCCESSOR EVIDENCE — 2c-B's `G1`-`G4`.
//!
//! 2c-B froze four conjuncts over `MarketTerms` field 6 and then deferred them,
//! for a reason it stated precisely: their operand did not exist. While
//! `operation_bytes` was filler no producer could satisfy them, and **nothing
//! may fabricate those operands to make a vector pass** (owner ruling,
//! 2026-09-09). 5c-2 Step 2 built the producer; this is the half that checks
//! its output, and the half a FOREIGN verifier runs.
//!
//! ```text
//! G1  operation_bytes decodes under DlvSettleOperationPreimageV1, consuming
//!     ALL bytes, with every fixed-length semantic field at its required
//!     length and the signature at the SPX256f length
//! G2  re-encode(decode(operation_bytes)) == operation_bytes
//! G3  discriminator == 26 and mode == Unilateral
//! G4  relationship_chain_tip_v2(<its six inputs>) == trader_successor
//! ```
//!
//! WHY NOT IN THE DECODER. Owner ruling: the chain-tip recomputation is
//! *successor-evidence validity, not byte decoding*, and putting it in the
//! generic CCB decoder would make every decode of any bundle recompute a hash
//! over a foreign grammar. `embedded_parent == trader_parent` is the sibling
//! that IS in-bundle structure, and it stays in
//! [`crate::ccb::settlement::MarketTerms::check_evidence_linkage`], enforced at
//! construction and decode. This module assumes it and checks the rest.
//!
//! WHY NOT IN THE C4 WALK. 2c-C4 §2.1: `G1`-`G4` gate the BUNDLE's structural
//! validity, not the economic walk, which obtains the accepted transition from
//! the trader's validated lineage and never parses these bytes. A C4 verifier
//! treats them as opaque.
//!
//! WHAT PASSING DOES NOT MEAN. That the bundle is *bound*, that the trade
//! *settled*, or that anything is *realized*. It means the carried evidence
//! does not disagree with itself. Realization stays unreachable until 2c-D.

use crate::ccb::settlement::{MarketTerms, SPX256F_SIGNATURE_LEN};
use crate::dlv::successor_validity::AUTHORITY_KEY_LEN;
use crate::types::device_state::relationship_chain_tip_v2;
use crate::types::operations::{Operation, TransactionMode};

/// The discriminator 2c-B froze for `DlvSettleOperationPreimageV1`.
pub const DLV_SETTLE_DISCRIMINATOR: u8 = 26;

/// Which conjunct refused, and what it saw. Structured, never a string: the
/// arm IS the finding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EvidenceInvalid {
    /// `G1`. The bytes do not decode under the frozen grammar at all.
    ///
    /// This is also what a TRAILING-BYTE preimage reports today: the grammar's
    /// own decoder refuses leftover input rather than returning a short read,
    /// so "consumes ALL bytes" is enforced there and surfaces here.
    Undecodable,
    /// `G1`. A decode that did not consume every byte.
    ///
    /// UNREACHABLE TODAY, and deliberately kept. `Operation::from_bytes`
    /// refuses trailing input itself, and a decode that succeeded always
    /// re-encodes to the same length — so nothing can currently reach this.
    /// It is a guard on both of those facts: if either stops being true, the
    /// failure is NAMED here instead of a longer or shorter re-encoding
    /// slipping through as canonical.
    TrailingBytes { decoded: usize, carried: usize },
    /// `G2`. Canonical re-encoding does not reproduce the carried bytes, so
    /// two encodings of one operation exist and a verifier could disagree with
    /// the signer about which was signed.
    NotCanonical,
    /// `G3`. Not discriminator 26.
    WrongDiscriminator { got: u8 },
    /// `G3`. The decoded operation is not a settle.
    NotASettle,
    /// `G3`. A settle in this profile is `Unilateral`.
    NotUnilateral,
    /// `G1`. A fixed-length semantic field is not its required length.
    ///
    /// The grammar writes these with a `bytes` length prefix, so a SHORT field
    /// re-encodes to exactly the bytes it came from: `G2` passes, and `G4`
    /// passes too whenever `trader_successor` was computed over those same
    /// short bytes. 2c-B names this hostile case explicitly and marks the
    /// width rule "owed at implementation" — this is that rule, and it is the
    /// only conjunct standing between a truncated key or signature and an
    /// otherwise self-consistent bundle.
    FieldWidth {
        field: &'static str,
        expected: usize,
        got: usize,
    },
    /// `G4`. The carried successor is not the tip of the carried inputs. This
    /// is the conjunct that makes the evidence self-consistent rather than
    /// merely well-formed.
    SuccessorIsNotTheChainTip {
        carried: [u8; 32],
        recomputed: [u8; 32],
    },
}

impl core::fmt::Display for EvidenceInvalid {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Undecodable => write!(
                f,
                "G1: operation_bytes do not decode under DlvSettleOperationPreimageV1"
            ),
            Self::TrailingBytes { decoded, carried } => write!(
                f,
                "G1: the grammar consumed {decoded} of {carried} bytes; the remainder is a second \
                 message hiding behind the first"
            ),
            Self::NotCanonical => write!(
                f,
                "G2: re-encoding does not reproduce the carried bytes, so two encodings of one \
                 operation exist"
            ),
            Self::WrongDiscriminator { got } => {
                write!(f, "G3: discriminator {got}, expected 26")
            }
            Self::NotASettle => write!(f, "G3: the decoded operation is not a DlvSettle"),
            Self::NotUnilateral => write!(f, "G3: a settle in this profile is Unilateral"),
            Self::FieldWidth {
                field,
                expected,
                got,
            } => write!(
                f,
                "G1: {field} is {got} bytes, expected {expected}; a short field re-encodes to \
                 itself, so G2 and G4 cannot catch it"
            ),
            Self::SuccessorIsNotTheChainTip { .. } => write!(
                f,
                "G4: trader_successor is not relationship_chain_tip_v2 of the carried inputs"
            ),
        }
    }
}

impl std::error::Error for EvidenceInvalid {}

/// `G1`-`G4` over a market bundle's carried successor evidence.
///
/// Every operand is read from `terms`; nothing is supplied alongside, so there
/// is no parameter through which a caller could soften the check.
pub fn check_market_evidence(terms: &MarketTerms) -> Result<(), EvidenceInvalid> {
    let ev = &terms.recovery_material;
    let bytes = &ev.operation_bytes;

    // G3's discriminator, read before decoding so a wrong tag reports as a
    // wrong tag rather than as an undecodable blob.
    match bytes.first() {
        Some(&DLV_SETTLE_DISCRIMINATOR) => {}
        Some(&got) => return Err(EvidenceInvalid::WrongDiscriminator { got }),
        None => return Err(EvidenceInvalid::Undecodable),
    }

    // G1's decode-and-consume rule. `from_bytes` refuses trailing input, so a
    // success already means the grammar consumed all of it — which is why a
    // trailing-byte preimage reports `Undecodable` rather than `TrailingBytes`.
    let op = Operation::from_bytes(bytes).map_err(|_| EvidenceInvalid::Undecodable)?;

    // G3, on the decoded operation rather than on its first byte.
    match &op {
        Operation::DlvSettle { mode, .. } => {
            if *mode != TransactionMode::Unilateral {
                return Err(EvidenceInvalid::NotUnilateral);
            }
        }
        _ => return Err(EvidenceInvalid::NotASettle),
    }

    // G1's width rule. The decoder enforces the digest-shaped fields and
    // `sigma` (`get_arr32`), but reads `vault_id`, both public keys and the
    // signature with an unbounded `get_bytes`, so those four are checked here
    // or nowhere. 2c-B's table fixes each length.
    if let Operation::DlvSettle {
        vault_id,
        owner_public_key,
        settler_public_key,
        signature,
        ..
    } = &op
    {
        for (field, expected, got) in [
            ("vault_id", 32usize, vault_id.len()),
            (
                "owner_public_key",
                AUTHORITY_KEY_LEN,
                owner_public_key.len(),
            ),
            (
                "settler_public_key",
                AUTHORITY_KEY_LEN,
                settler_public_key.len(),
            ),
            ("signature", SPX256F_SIGNATURE_LEN, signature.len()),
        ] {
            if got != expected {
                return Err(EvidenceInvalid::FieldWidth {
                    field,
                    expected,
                    got,
                });
            }
        }
    }

    // G2.
    let reencoded = op.to_bytes();
    if reencoded.len() != bytes.len() {
        return Err(EvidenceInvalid::TrailingBytes {
            decoded: reencoded.len(),
            carried: bytes.len(),
        });
    }
    if reencoded != *bytes {
        return Err(EvidenceInvalid::NotCanonical);
    }

    // G4. RECOMPUTED from the frozen inputs — the carried successor is an
    // equality target, never a value that is read.
    let recomputed = relationship_chain_tip_v2(
        &ev.rel_key,
        &ev.embedded_parent,
        &ev.counterparty_devid,
        bytes,
        &ev.entropy,
        None,
    );
    if recomputed != terms.trader_successor {
        return Err(EvidenceInvalid::SuccessorIsNotTheChainTip {
            carried: terms.trader_successor,
            recomputed,
        });
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::disallowed_methods, clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::ccb::settlement::fixtures;

    /// Genuine producer output — the only kind these conjuncts can be tested
    /// against, which is why they were deferred until it existed.
    fn produced() -> &'static MarketTerms {
        static T: std::sync::OnceLock<MarketTerms> = std::sync::OnceLock::new();
        T.get_or_init(|| fixtures::market_terms([0xC0; 32], [0x58; 32]))
    }

    #[test]
    fn genuine_producer_output_satisfies_all_four() {
        assert_eq!(check_market_evidence(produced()), Ok(()));
    }

    /// TEETH, requirement 10: altered operation bytes are rejected. The tip is
    /// a function of the bytes, so flipping one byte moves the successor away
    /// from the carried value.
    #[test]
    fn a_single_altered_operation_byte_is_rejected() {
        let mut t = produced().clone();
        // Byte 10 sits inside `vault_id` (discriminator, then a u32 length,
        // then the 32-byte id). Flipping it keeps the bytes decodable and
        // canonically re-encodable, so G1-G3 all still pass and G4 is the
        // conjunct actually under test. Flipping the LAST byte would hit
        // `mode` and be caught by G3 instead, proving something else.
        t.recovery_material.operation_bytes[10] ^= 0x01;
        match check_market_evidence(&t) {
            Err(EvidenceInvalid::SuccessorIsNotTheChainTip { .. }) => {}
            other => panic!("expected G4 refusal, got {other:?}"),
        }
    }

    /// TEETH, requirement 10: a supplied successor that is not the recomputed
    /// one is rejected. This is the case a producer cannot reach and an
    /// attacker would want.
    #[test]
    fn a_supplied_successor_that_is_not_the_recomputed_one_is_rejected() {
        let mut t = produced().clone();
        t.trader_successor = [0xAB; 32];
        match check_market_evidence(&t) {
            Err(EvidenceInvalid::SuccessorIsNotTheChainTip {
                carried,
                recomputed,
            }) => {
                assert_eq!(carried, [0xAB; 32]);
                assert_ne!(recomputed, carried);
            }
            other => panic!("expected G4 refusal, got {other:?}"),
        }
    }

    /// THE HOSTILE CASE 2c-B NAMES, and the reason the width rule exists.
    ///
    /// The signature is truncated INSIDE `operation_bytes`, and the successor
    /// is then recomputed over those same short bytes. `G1`'s decode succeeds,
    /// `G2`'s re-encode reproduces them exactly (a `bytes` field re-encodes to
    /// whatever length it had), `G3` still sees discriminator 26 and
    /// Unilateral, and `G4`'s chain tip MATCHES — because the attacker
    /// computed it over the very bytes being checked. Only the width rule
    /// refuses, which is why 2c-B lists it and marks it owed at
    /// implementation.
    #[test]
    fn a_short_signature_is_refused_even_though_the_chain_tip_agrees() {
        let mut t = produced().clone();
        let mut op = Operation::from_bytes(&t.recovery_material.operation_bytes).unwrap();
        if let Operation::DlvSettle { signature, .. } = &mut op {
            signature.truncate(8);
        }
        t.recovery_material.operation_bytes = op.to_bytes();
        // Recompute the tip so G4 CANNOT be what fires.
        t.trader_successor = relationship_chain_tip_v2(
            &t.recovery_material.rel_key,
            &t.recovery_material.embedded_parent,
            &t.recovery_material.counterparty_devid,
            &t.recovery_material.operation_bytes,
            &t.recovery_material.entropy,
            None,
        );
        assert_eq!(
            check_market_evidence(&t),
            Err(EvidenceInvalid::FieldWidth {
                field: "signature",
                expected: SPX256F_SIGNATURE_LEN,
                got: 8,
            })
        );
    }

    /// The same shape for a truncated authority key: G2 and G4 both pass.
    #[test]
    fn a_short_settler_key_is_refused_even_though_the_chain_tip_agrees() {
        let mut t = produced().clone();
        let mut op = Operation::from_bytes(&t.recovery_material.operation_bytes).unwrap();
        if let Operation::DlvSettle {
            settler_public_key, ..
        } = &mut op
        {
            settler_public_key.truncate(16);
        }
        t.recovery_material.operation_bytes = op.to_bytes();
        t.trader_successor = relationship_chain_tip_v2(
            &t.recovery_material.rel_key,
            &t.recovery_material.embedded_parent,
            &t.recovery_material.counterparty_devid,
            &t.recovery_material.operation_bytes,
            &t.recovery_material.entropy,
            None,
        );
        assert_eq!(
            check_market_evidence(&t),
            Err(EvidenceInvalid::FieldWidth {
                field: "settler_public_key",
                expected: AUTHORITY_KEY_LEN,
                got: 16,
            })
        );
    }

    #[test]
    fn trailing_bytes_are_rejected() {
        let mut t = produced().clone();
        t.recovery_material.operation_bytes.push(0xFF);
        assert_eq!(check_market_evidence(&t), Err(EvidenceInvalid::Undecodable));
    }

    #[test]
    fn a_wrong_discriminator_is_named_as_such() {
        let mut t = produced().clone();
        t.recovery_material.operation_bytes[0] = 28; // a close preimage
        assert_eq!(
            check_market_evidence(&t),
            Err(EvidenceInvalid::WrongDiscriminator { got: 28 })
        );
    }

    #[test]
    fn empty_operation_bytes_are_rejected() {
        // `DsmSuccessorEvidence::new` refuses empty bytes, so this state is
        // unreachable through construction; the arm exists so the check is
        // total rather than relying on that.
        let mut t = produced().clone();
        t.recovery_material.operation_bytes.clear();
        assert_eq!(check_market_evidence(&t), Err(EvidenceInvalid::Undecodable));
    }

    /// A bilateral settle is refused by `G3` even though it decodes and its
    /// tip would recompute correctly.
    #[test]
    fn a_bilateral_settle_is_rejected_before_the_chain_tip_is_consulted() {
        let mut t = produced().clone();
        let mut op = Operation::from_bytes(&t.recovery_material.operation_bytes).unwrap();
        if let Operation::DlvSettle { mode, .. } = &mut op {
            *mode = TransactionMode::Bilateral;
        }
        // Re-derive the tip so ONLY the mode is wrong; otherwise G4 would fire
        // first and the test would prove nothing about G3.
        t.recovery_material.operation_bytes = op.to_bytes();
        t.trader_successor = relationship_chain_tip_v2(
            &t.recovery_material.rel_key,
            &t.recovery_material.embedded_parent,
            &t.recovery_material.counterparty_devid,
            &t.recovery_material.operation_bytes,
            &t.recovery_material.entropy,
            None,
        );
        assert_eq!(
            check_market_evidence(&t),
            Err(EvidenceInvalid::NotUnilateral)
        );
    }
}
