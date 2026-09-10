// SPDX-License-Identifier: Apache-2.0

//! THE GENUINE MARKET BUNDLE PRODUCER — 5c-2 Step 2.
//!
//! Every operand of a market `MarketTerms` is DERIVED here from a real signed
//! operation. Nothing is invented, and there is no parameter through which a
//! caller could invent one:
//!
//! ```text
//! operation_bytes   = the caller's SIGNED Operation::DlvSettle, canonically
//!                     encoded. Refused unless it is a settle carrying a
//!                     signature — an unsigned operation cannot be signed
//!                     afterwards, because the signature is inside the bytes
//!                     the chain tip hashes.
//! trader_successor  = relationship_chain_tip_v2(...) over THOSE bytes.
//!                     RECOMPUTED, never accepted from a caller.
//! trader_parent     = the same embedded parent the tip was computed from, so
//!                     2c-B's second chain-tip equality holds by construction
//!                     rather than by a check that could be forgotten.
//! sigma_dsm         = SPHINCS+ over
//!                     H_dom(DSM/economic-substrate-sign,
//!                           G ‖ DevID ‖ C_dsm+ ‖ operation_digest)
//!                     — the same digest chain the economic substrate's own
//!                     producer signs, so one accepted successor has one
//!                     signature and not two disagreeing ones.
//! ```
//!
//! WHY THIS IS NOT `economic::successor_evidence`. That module signs the same
//! digest and then encodes **protobuf**. Registry §2.10 forbids protobuf
//! transport bytes from being hashed or signed as a CCB blob, and 2c-B records
//! that `DsmSuccessorEvidenceV1` "violates it twice" — a content address over
//! prost bytes, and prost determinism used AS the canonical form. The new class
//! "must not be the existing prost bytes canonized". So the signing chain is
//! shared and the encoding is not.
//!
//! WHAT THIS MODULE DOES NOT DO. It does not bind, fence, advance, admit or
//! publish anything, and it holds no I/O and no runtime state — `dlv/`'s
//! charter. It does not lift the market emission refusal: wiring the live path
//! is 5c-2 Step 3, and realization stays unreachable until 2c-D supplies the
//! bundle-acceptance witness. Producing a bundle is not settling a trade.

use crate::ccb::settlement::{DsmSuccessorEvidence, MarketTerms, Route, TradeIntent};
use crate::ccb::CcbError;
use crate::types::device_state::relationship_chain_tip_v2;
use crate::types::operations::{Operation, TransactionMode};

/// Why a market bundle could not be produced. Each arm names a fact about the
/// caller's inputs, never a repair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProducerError {
    /// The operation is not a `DlvSettle`. Discriminator 26 is what 2c-B's
    /// `G3` requires, and it is a property of the operation, not of the bytes.
    NotASettle,
    /// The settle carries no signature. The settler signs with field 18
    /// cleared and writes the signature back, so an operation committed
    /// unsigned can never be signed afterwards — the signature is inside
    /// `operation_bytes` and therefore inside `C_dsm+`.
    Unsigned,
    /// `G3` also fixes the mode. A bilateral settle is not this shape.
    NotUnilateral,
    /// Signing failed.
    Signature(String),
    /// The evidence or the terms would not encode.
    Encoding(CcbError),
    /// The producer's own output does not satisfy `G1`-`G4`. This cannot
    /// happen while the construction is what it claims; it exists so that if
    /// that ever stops being true, the producer refuses rather than emitting a
    /// bundle a foreign verifier would reject.
    SelfCheck(crate::dlv::market_evidence::EvidenceInvalid),
}

impl core::fmt::Display for ProducerError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NotASettle => write!(
                f,
                "market production needs an Operation::DlvSettle; discriminator 26 is 2c-B's G3"
            ),
            Self::Unsigned => write!(
                f,
                "the settle carries no signature, and it cannot acquire one later: the signature \
                 is inside the bytes the chain tip hashes"
            ),
            Self::NotUnilateral => write!(f, "2c-B's G3 fixes the settle's mode to Unilateral"),
            Self::Signature(e) => write!(f, "sigma_dsm could not be produced: {e}"),
            Self::Encoding(e) => write!(f, "the produced object does not encode: {e:?}"),
            Self::SelfCheck(e) => write!(
                f,
                "the producer's own output fails the verifier a foreign party runs: {e}"
            ),
        }
    }
}

impl std::error::Error for ProducerError {}

/// The trader's economic coordinates. Both are the trader's OWN; a market
/// settle advances the trader's self-loop and the vault owner never signs it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TraderIdentity {
    pub genesis: [u8; 32],
    pub device_id: [u8; 32],
}

/// A prepared successor: the evidence, and the two coordinates `MarketTerms`
/// must carry. Constructing this is the only way to obtain them, so they
/// cannot come apart.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedSuccessor {
    evidence: DsmSuccessorEvidence,
    trader_parent: [u8; 32],
    trader_successor: [u8; 32],
}

impl PreparedSuccessor {
    pub fn evidence(&self) -> &DsmSuccessorEvidence {
        &self.evidence
    }
    /// The exact `C_dsm+`, recomputed from the signed operation bytes.
    pub fn trader_successor(&self) -> [u8; 32] {
        self.trader_successor
    }
    pub fn trader_parent(&self) -> [u8; 32] {
        self.trader_parent
    }
}

/// Prepare the successor for a market settle.
///
/// `signed_settle` must already carry its signature: the settler signs the
/// canonical bytes with field 18 cleared and writes the signature back, and
/// only then are the bytes the chain tip hashes final.
#[allow(clippy::too_many_arguments)]
pub fn prepare_market_successor(
    rel_key: [u8; 32],
    embedded_parent: [u8; 32],
    counterparty_devid: [u8; 32],
    signed_settle: &Operation,
    entropy: [u8; 32],
    identity: &TraderIdentity,
    ak_secret_key: &[u8],
) -> Result<PreparedSuccessor, ProducerError> {
    match signed_settle {
        Operation::DlvSettle {
            signature, mode, ..
        } => {
            if signature.is_empty() {
                return Err(ProducerError::Unsigned);
            }
            if *mode != TransactionMode::Unilateral {
                return Err(ProducerError::NotUnilateral);
            }
        }
        _ => return Err(ProducerError::NotASettle),
    }

    let operation_bytes = signed_settle.to_bytes();

    // RECOMPUTED, never supplied. `encapsulated_entropy` is absent in this
    // profile and the 0x0031 encoder emits its absence marker.
    let trader_successor = relationship_chain_tip_v2(
        &rel_key,
        &embedded_parent,
        &counterparty_devid,
        &operation_bytes,
        &entropy,
        None,
    );

    let operation_digest = crate::economic::faucet::dsm_operation_digest(&operation_bytes);
    let digest = crate::economic::successor_evidence::substrate_signing_digest(
        &identity.genesis,
        &identity.device_id,
        &trader_successor,
        &operation_digest,
    );
    let sigma_dsm = crate::crypto::sphincs::sphincs_sign(ak_secret_key, &digest)
        .map_err(|e| ProducerError::Signature(e.to_string()))?;

    let evidence = DsmSuccessorEvidence::new(
        rel_key,
        embedded_parent,
        counterparty_devid,
        operation_bytes,
        entropy,
        sigma_dsm,
    )
    .map_err(ProducerError::Encoding)?;

    Ok(PreparedSuccessor {
        evidence,
        trader_parent: embedded_parent,
        trader_successor,
    })
}

/// Assemble `MarketTerms` around a prepared successor.
///
/// The two trader coordinates are taken from `prepared` and cannot be
/// overridden, so `MarketTerms::check_evidence_linkage` holds by construction.
pub fn market_terms(
    intent: TradeIntent,
    route_set_commitment: [u8; 32],
    selected_route: Route,
    prepared: &PreparedSuccessor,
) -> Result<MarketTerms, ProducerError> {
    let terms = MarketTerms {
        intent,
        route_set_commitment,
        selected_route,
        trader_parent: prepared.trader_parent,
        trader_successor: prepared.trader_successor,
        recovery_material: prepared.evidence.clone(),
    };
    terms
        .check_evidence_linkage()
        .map_err(ProducerError::Encoding)?;
    // THE PRODUCER VERIFIES ITS OWN OUTPUT. `G1`-`G4` hold by construction
    // here, so this can only fire if the construction above stops being what
    // it claims — which is exactly when a silent divergence would otherwise
    // start. A producer that cannot pass the verifier a foreign party runs has
    // no business emitting a bundle.
    crate::dlv::market_evidence::check_market_evidence(&terms).map_err(ProducerError::SelfCheck)?;
    Ok(terms)
}

#[cfg(test)]
#[allow(clippy::disallowed_methods, clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::ccb::settlement::fixtures;

    /// The produced bundle's operands, built once — SPX256f signing is not free.
    fn produced() -> &'static MarketTerms {
        static T: std::sync::OnceLock<MarketTerms> = std::sync::OnceLock::new();
        T.get_or_init(|| fixtures::market_terms([0xC0; 32], [0x58; 32]))
    }

    /// `G4`. The successor is the chain tip RECOMPUTED over the carried bytes,
    /// so the conjunct 2c-B deferred for want of a real prepared successor now
    /// holds on producer output. This is the one that could not be tested at
    /// all while `operation_bytes` was filler.
    #[test]
    fn g4_the_successor_is_the_recomputed_chain_tip() {
        let t = produced();
        let ev = &t.recovery_material;
        let recomputed = relationship_chain_tip_v2(
            &ev.rel_key,
            &ev.embedded_parent,
            &ev.counterparty_devid,
            &ev.operation_bytes,
            &ev.entropy,
            None,
        );
        assert_eq!(recomputed, t.trader_successor);
    }

    /// `G1` and `G2`. The carried bytes decode under the frozen grammar,
    /// consuming all of them, and re-encode to exactly the same bytes.
    #[test]
    fn g1_g2_the_operation_bytes_decode_and_round_trip_exactly() {
        let ev = &produced().recovery_material;
        let op = Operation::from_bytes(&ev.operation_bytes)
            .expect("produced operation_bytes decode under the frozen grammar");
        assert_eq!(op.to_bytes(), ev.operation_bytes, "canonical re-encode");
    }

    /// `G3`. Discriminator 26 and `Unilateral`, read off the decoded operation
    /// rather than off the first byte.
    #[test]
    fn g3_the_operation_is_a_unilateral_settle() {
        let ev = &produced().recovery_material;
        let op = Operation::from_bytes(&ev.operation_bytes).unwrap();
        assert_eq!(ev.operation_bytes[0], 26, "discriminator");
        match op {
            Operation::DlvSettle {
                mode, signature, ..
            } => {
                assert_eq!(mode, TransactionMode::Unilateral);
                assert!(!signature.is_empty(), "the settle carries its signature");
            }
            other => panic!("not a settle: {other:?}"),
        }
    }

    /// 2c-B's second chain-tip equality, which the producer makes structural:
    /// the two coordinates come from one `PreparedSuccessor` and cannot be set
    /// apart.
    #[test]
    fn the_evidence_linkage_holds_by_construction() {
        let t = produced();
        assert_eq!(t.recovery_material.embedded_parent, t.trader_parent);
        assert!(t.check_evidence_linkage().is_ok());
    }

    fn identity() -> TraderIdentity {
        TraderIdentity {
            genesis: fixtures::FIXTURE_TRADER_GENESIS,
            device_id: fixtures::FIXTURE_TRADER_DEVID,
        }
    }

    #[test]
    fn an_unsigned_settle_is_refused() {
        let mut op = Operation::from_bytes(&produced().recovery_material.operation_bytes).unwrap();
        if let Operation::DlvSettle { signature, .. } = &mut op {
            signature.clear();
        }
        let e = prepare_market_successor(
            [0x51; 32],
            [0x52; 32],
            [0x42; 32],
            &op,
            [0x55; 32],
            &identity(),
            &[0u8; 128],
        );
        assert_eq!(e, Err(ProducerError::Unsigned));
    }

    #[test]
    fn a_bilateral_settle_is_refused() {
        let mut op = Operation::from_bytes(&produced().recovery_material.operation_bytes).unwrap();
        if let Operation::DlvSettle { mode, .. } = &mut op {
            *mode = TransactionMode::Bilateral;
        }
        let e = prepare_market_successor(
            [0x51; 32],
            [0x52; 32],
            [0x42; 32],
            &op,
            [0x55; 32],
            &identity(),
            &[0u8; 128],
        );
        assert_eq!(e, Err(ProducerError::NotUnilateral));
    }

    #[test]
    fn an_operation_that_is_not_a_settle_is_refused() {
        let op = Operation::DlvUnlock {
            vault_id: vec![0x03; 32],
            fulfillment_proof: vec![1],
            requester_public_key: vec![2; 64],
            signature: vec![3; 8],
            mode: TransactionMode::Unilateral,
        };
        let e = prepare_market_successor(
            [0x51; 32],
            [0x52; 32],
            [0x42; 32],
            &op,
            [0x55; 32],
            &identity(),
            &[0u8; 128],
        );
        assert_eq!(e, Err(ProducerError::NotASettle));
    }

    /// Changing ONE byte of the operation changes the successor. The tip is a
    /// function of the bytes, which is what makes `G4` load-bearing rather
    /// than decorative.
    #[test]
    fn a_different_operation_yields_a_different_successor() {
        let a = fixtures::market_terms([0xC0; 32], [0x58; 32]);
        let b = fixtures::market_terms([0xC1; 32], [0x58; 32]);
        assert_ne!(
            a.recovery_material.operation_bytes,
            b.recovery_material.operation_bytes
        );
        assert_ne!(a.trader_successor, b.trader_successor);
    }
}
