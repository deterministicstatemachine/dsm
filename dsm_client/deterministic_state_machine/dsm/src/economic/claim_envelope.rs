// SPDX-License-Identifier: Apache-2.0

//! `EconomicRootClaimV1` — the signed carrier a trader writes into one
//! register cell, and the attribution a member checks before storing it.
//!
//! ## The body travels as CCB, not as a proto mirror
//!
//! The envelope carries the body's **exact `0x001B` CCB bytes**. Mirroring the
//! body as a nested proto message would give one object two canonical forms,
//! and the signature covers only one of them — so the two could disagree while
//! both looked well-formed. The envelope is a carrier, not a re-description.
//!
//! ## What a member checks, and what it must not
//!
//! Storage only. A member never runs P0–P6, never validates a transition,
//! never judges economics, and never checks who carries the bytes (Part II
//! §9): it keeps every value it is given at the cell, in arrival order.
//!
//! What protects a trader's cell is recognition, not a member. The cell's
//! coordinate is identity-scoped but derivable by anyone holding a trader's
//! public `(G, DevID, position)`; bytes anyone sends there are kept, but only
//! a claim that verifies under the trader's own key is an object naming the
//! cell, and Core's leader-first read counts nothing else. A claim in the
//! trader's name that the trader never signed is not a rival and not a
//! winner, however early it arrived.

use prost::Message;

use crate::ccb::decode::DecodeError;
use crate::ccb::{class, CcbError, CcbObject};
use crate::economic::claim::EconomicRootClaimBody;
use crate::types::proto as generated;

/// Matches the proto's `dsm_max_len`; prost does not enforce it, so this
/// module does.
const MAX_KEY_OR_SIG_BYTES: usize = 65_535;

/// A claim envelope that decoded strictly and whose signature verified under
/// its own `claimant_public_key`.
///
/// Verifying the signature proves the body was signed by whoever holds that
/// key. It does **not** prove that key is the trader's P0–P6-proven AK —
/// the verifying end establishes that, never a member.
/// **Fields are private, and [`decode_and_verify_economic_root_claim`] is the
/// only thing that builds one.** This type is a CAPABILITY: holding it is the
/// proof that a signature verified, and every consumer takes it on exactly
/// that meaning — `RegisteredEconomicRoot::from_verified_single_root` re-runs
/// no verification, because the argument's existence is the verification.
///
/// Public fields made that meaning unenforced. A caller could write the
/// struct literal from arbitrary bytes and hand the result straight to a
/// consumer that trusts it, which is the anti-flattening invariant defeated
/// one level up: the registered root was made opaque while the capability it
/// consumes stayed forgeable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedEconomicRootClaim {
    body: EconomicRootClaimBody,
    /// The exact bytes the member stores. Retained rather than re-derived: a
    /// byte-different re-encode reads as a different value at a write-once
    /// cell.
    envelope_bytes: Vec<u8>,
}

impl VerifiedEconomicRootClaim {
    /// The body whose signature verified.
    pub fn body(&self) -> &EconomicRootClaimBody {
        &self.body
    }

    /// The exact envelope bytes the signature covered.
    pub fn envelope_bytes(&self) -> &[u8] {
        &self.envelope_bytes
    }
}

/// Why an envelope is not a usable claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClaimEnvelopeError {
    /// The envelope did not decode, decoded non-canonically, or a bounded
    /// field was oversized or empty.
    Malformed(&'static str),
    /// The body bytes are not a well-formed `0x001B` object.
    Body(DecodeError),
    /// The signature does not verify over the body under the body's own key.
    SignatureInvalid,
    /// SPHINCS+ signing failed.
    SignFailed(String),
    /// The body could not be re-encoded to check the signing digest.
    Encode(CcbError),
}

impl core::fmt::Display for ClaimEnvelopeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Malformed(why) => write!(f, "economic root claim malformed: {why}"),
            Self::Body(e) => write!(f, "economic root claim body: {e}"),
            Self::SignatureInvalid => write!(f, "economic root claim signature invalid"),
            Self::SignFailed(e) => write!(f, "economic root claim sign failed: {e}"),
            Self::Encode(e) => write!(f, "economic root claim body not encodable: {e}"),
        }
    }
}

impl std::error::Error for ClaimEnvelopeError {}

/// Decode an `EconomicRootClaimBody` — class `0x001B`, schema 1, strict.
pub fn decode_economic_root_claim_body(bytes: &[u8]) -> Result<EconomicRootClaimBody, DecodeError> {
    use crate::ccb::decode::{invalid, Cursor};
    let mut c = Cursor { b: bytes, i: 0 };
    c.envelope(EconomicRootClaimBody::CLASS, EconomicRootClaimBody::SCHEMA)?;
    let trader_genesis = c.digest32()?;
    let trader_devid = c.digest32()?;
    let economic_position = c.u64()?;
    let post_economic_root = c.digest32()?;
    let admission_manifest_addr = c.digest32()?;
    let root_register_storage_set_id = c.digest32()?;
    let signature_alg = c.u16()?;
    let key_len = c.u32()? as usize;
    let claimant_public_key = c.take(key_len)?.to_vec();
    if c.i != bytes.len() {
        return Err(DecodeError::TrailingBytes {
            extra: bytes.len() - c.i,
        });
    }
    // Through the validating constructor, so a declared algorithm and a
    // mis-sized key are refused on the way in rather than carried.
    EconomicRootClaimBody::new(
        trader_genesis,
        trader_devid,
        economic_position,
        post_economic_root,
        admission_manifest_addr,
        root_register_storage_set_id,
        signature_alg,
        &claimant_public_key,
    )
    .map_err(invalid)
}

/// Build and sign an envelope. The caller retains the returned bytes and
/// replays them verbatim on every retry.
pub fn sign_economic_root_claim(
    body: &EconomicRootClaimBody,
    claimant_secret_key: &[u8],
) -> Result<Vec<u8>, ClaimEnvelopeError> {
    let body_ccb = body.encode().map_err(ClaimEnvelopeError::Encode)?;
    let digest = body.signing_digest().map_err(ClaimEnvelopeError::Encode)?;
    let signature = crate::crypto::sphincs::sphincs_sign(claimant_secret_key, &digest)
        .map_err(|e| ClaimEnvelopeError::SignFailed(e.to_string()))?;
    Ok(generated::EconomicRootClaimV1 {
        body_ccb,
        claimant_signature: signature,
    }
    .encode_to_vec())
}

/// Strictly decode an envelope and verify its signature under the body's own
/// `claimant_public_key`.
///
/// Refuses anything that does not re-encode to exactly the input bytes:
/// unknown fields, duplicates and non-canonical encodings all fail that
/// comparison. At a write-once cell, a byte-different encoding of "the same"
/// claim is a different value, so tolerating one would mean a member could
/// accept a claim that never wins a quorum.
pub fn decode_and_verify_economic_root_claim(
    envelope_bytes: &[u8],
) -> Result<VerifiedEconomicRootClaim, ClaimEnvelopeError> {
    if envelope_bytes.is_empty() {
        return Err(ClaimEnvelopeError::Malformed("empty envelope"));
    }
    let env = generated::EconomicRootClaimV1::decode(envelope_bytes)
        .map_err(|_| ClaimEnvelopeError::Malformed("envelope does not decode"))?;
    if env.body_ccb.is_empty() || env.body_ccb.len() > MAX_KEY_OR_SIG_BYTES {
        return Err(ClaimEnvelopeError::Malformed("body_ccb length"));
    }
    if env.claimant_signature.is_empty() || env.claimant_signature.len() > MAX_KEY_OR_SIG_BYTES {
        return Err(ClaimEnvelopeError::Malformed("signature length"));
    }
    let reencoded = generated::EconomicRootClaimV1 {
        body_ccb: env.body_ccb.clone(),
        claimant_signature: env.claimant_signature.clone(),
    }
    .encode_to_vec();
    if reencoded != envelope_bytes {
        return Err(ClaimEnvelopeError::Malformed("envelope is not canonical"));
    }

    let body = decode_economic_root_claim_body(&env.body_ccb).map_err(ClaimEnvelopeError::Body)?;
    // The body must round-trip to the exact carried bytes. Otherwise the
    // signature covers a digest over bytes nobody will recompute the same way.
    let body_reencoded = body.encode().map_err(ClaimEnvelopeError::Encode)?;
    if body_reencoded != env.body_ccb {
        return Err(ClaimEnvelopeError::Malformed("body_ccb is not canonical"));
    }

    let digest = body.signing_digest().map_err(ClaimEnvelopeError::Encode)?;
    let ok = crate::crypto::sphincs::sphincs_verify(
        &body.claimant_public_key,
        &digest,
        &env.claimant_signature,
    )
    .map_err(|_| ClaimEnvelopeError::SignatureInvalid)?;
    if !ok {
        return Err(ClaimEnvelopeError::SignatureInvalid);
    }
    Ok(VerifiedEconomicRootClaim {
        body,
        envelope_bytes: envelope_bytes.to_vec(),
    })
}

/// `H_dom(DSM/economic-root-claim-envelope/v1, exact envelope bytes)` — the
/// digest a register member stores beside the bytes and returns in a refused
/// response, so a loser can tell "someone else holds this cell" from "someone
/// holds MY exact bytes" without fetching them.
pub fn economic_root_claim_envelope_digest(envelope_bytes: &[u8]) -> [u8; 32] {
    let mut h = crate::crypto::blake3::dsm_domain_hasher(
        crate::common::domain_tags::TAG_DSM_ECONOMIC_ROOT_CLAIM_ENVELOPE,
    );
    h.update(envelope_bytes);
    *h.finalize().as_bytes()
}

/// Whether the class this module decodes is the one the registry names.
/// Kept as a compile-time-adjacent assertion so a class renumbering cannot
/// silently retarget the decoder.
const _: () = assert!(EconomicRootClaimBody::CLASS == class::ECONOMIC_ROOT_CLAIM_BODY);

// ── The register cell holds ONE claim, of ONE kind ──────────────────────────

/// What a register cell at `K_root(p)` holds, decoded by its own class.
///
/// A position is either ordinary or conditional, and the two are not
/// interchangeable:
///
/// - [`Self::SingleRoot`] registers ONE root, signed by its claimant.
/// - [`Self::ConditionalSofi`] is `C_q`: it commits TWO roots and has selected
///   **neither**. It is not "a claim whose root is not handy" — it is a claim
///   that has not chosen, and no amount of fetching changes that. Only the
///   route's resolution does.
///
/// **There is deliberately no accessor that returns "the" root.** A union with
/// an infallible `post_economic_root()` would have to pick a branch for the
/// conditional arm, and picking `realize_root` is exactly the flattening that
/// makes every downstream Merkle proof succeed against a branch the lineage
/// never took. Callers that need a concrete root must match, and the
/// conditional arm gives them a refusal naming the fulfillment it is waiting
/// on — see [`Self::single_root`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegisteredEconomicClaim {
    /// The ordinary claim: one root, one signature, one manifest.
    SingleRoot(VerifiedEconomicRootClaim),
    /// `C_q` — a conditional SoFi position. Carries no `post_economic_root`
    /// FIELD, so there is nothing for a caller to read by mistake.
    ConditionalSofi(crate::sofi::wire::SofiResolutionClaim),
}

/// Why a claim cannot supply a concrete root.
///
/// Not an error about the claim's validity: the claim is authentic, present,
/// and has not chosen. It names the fulfillment whose resolution decides.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClaimIsConditional {
    pub economic_position: u64,
    pub fulfillment_id: [u8; 32],
}

impl core::fmt::Display for ClaimIsConditional {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "the claim at position {} is conditional on fulfillment {}: it commits \
             two roots and has selected neither",
            self.economic_position,
            crate::utils::text_id::encode_base32_crockford(&self.fulfillment_id)
        )
    }
}

impl std::error::Error for ClaimIsConditional {}

impl RegisteredEconomicClaim {
    /// The trader whose position this is, from whichever arm.
    pub fn trader(&self) -> ([u8; 32], [u8; 32]) {
        match self {
            Self::SingleRoot(c) => (c.body().trader_genesis, c.body().trader_devid),
            Self::ConditionalSofi(c) => (c.genesis, c.device_id),
        }
    }

    /// The position this claim occupies. Both kinds share one counter space,
    /// which is why the position can never discriminate between them.
    pub fn economic_position(&self) -> u64 {
        match self {
            Self::SingleRoot(c) => c.body().economic_position,
            Self::ConditionalSofi(c) => c.position,
        }
    }

    /// The single-root claim, or a refusal naming what it is conditional on.
    ///
    /// THE ONLY WAY to a concrete registered root. A conditional claim cannot
    /// be coerced through here at any resolution state: resolving `C_q` is the
    /// lineage's job (`sofi::lineage::advance_resolved`), not a decoder's, and
    /// a resolved position's usable root arrives as a `ValidatedEconomicRoot`
    /// rather than as a re-reading of these bytes (P15-10: `C_q` is recomputed
    /// from `(P, F)`, never read from the register).
    pub fn single_root(&self) -> Result<&VerifiedEconomicRootClaim, ClaimIsConditional> {
        match self {
            Self::SingleRoot(c) => Ok(c),
            Self::ConditionalSofi(c) => Err(ClaimIsConditional {
                economic_position: c.position,
                fulfillment_id: c.fulfillment_id,
            }),
        }
    }
}

/// Decode a register cell into whichever claim it holds, **by class**.
///
/// The two kinds are distinguishable at the first two bytes: a conditional
/// claim is a bare CCB object and leads with its class envelope, while a
/// single-root claim is a `EconomicRootClaimV1` protobuf and never does. So
/// this peeks the class and dispatches, exactly as `ParentClaimRef::at` does
/// for the wire union — it does not try one decoder and fall back to the
/// other, because "whichever parses" is not a canonical rule.
///
/// The conditional arm has no signature to check and none to fake: `C_q` is
/// a derived object, recomputed from `(P, F)` by whoever reads it, and `F`'s
/// own signature is the attribution.
pub fn decode_registered_economic_claim(
    cell_bytes: &[u8],
) -> Result<RegisteredEconomicClaim, ClaimEnvelopeError> {
    if cell_bytes.is_empty() {
        return Err(ClaimEnvelopeError::Malformed("empty envelope"));
    }
    if cell_bytes.len() >= 2
        && u16::from_be_bytes([cell_bytes[0], cell_bytes[1]]) == class::SOFI_RESOLUTION_CLAIM
    {
        let claim = crate::sofi::wire::SofiResolutionClaim::decode(cell_bytes)
            .map_err(ClaimEnvelopeError::Body)?;
        return Ok(RegisteredEconomicClaim::ConditionalSofi(claim));
    }
    decode_and_verify_economic_root_claim(cell_bytes).map(RegisteredEconomicClaim::SingleRoot)
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)] // test asserts; a failure here is the signal
mod tests {
    use super::*;
    use crate::sofi::wire::SofiResolutionClaim;

    fn conditional() -> SofiResolutionClaim {
        SofiResolutionClaim {
            genesis: [0x11; 32],
            device_id: [0x22; 32],
            position: 7,
            fulfillment_id: [0xF1; 32],
            realize_root: [0xA1; 32],
            void_root: [0xB1; 32],
        }
    }

    /// A conditional cell decodes AS a conditional claim — by class, not by
    /// "whichever decoder happens to parse". It is not an error and it is not
    /// a single-root claim with a missing field.
    #[test]
    fn a_conditional_cell_decodes_by_class() {
        let claim = conditional();
        let decoded = decode_registered_economic_claim(&claim.encode()).unwrap();
        assert_eq!(
            decoded,
            RegisteredEconomicClaim::ConditionalSofi(claim),
            "the cell holds C_q and says so"
        );
        assert_eq!(decoded.economic_position(), 7);
        assert_eq!(decoded.trader(), ([0x11; 32], [0x22; 32]));
    }

    /// THE ROOT IS NOT AVAILABLE, AND NOT GUESSED. Asking a conditional claim
    /// for a concrete root yields a refusal naming the fulfillment it waits
    /// on — never `realize_root`, which is the flattening that would make
    /// every downstream inclusion proof succeed against an unchosen branch.
    #[test]
    fn a_conditional_claim_refuses_to_supply_a_root() {
        let claim = conditional();
        let decoded = decode_registered_economic_claim(&claim.encode()).unwrap();
        let refusal = decoded.single_root().expect_err("no root is selected");
        assert_eq!(
            refusal,
            ClaimIsConditional {
                economic_position: 7,
                fulfillment_id: [0xF1; 32],
            }
        );
        // The message names the fulfillment and NEITHER root.
        let rendered = refusal.to_string();
        assert!(rendered.contains(&crate::utils::text_id::encode_base32_crockford(&[0xF1; 32])));
        for root in [claim.realize_root, claim.void_root] {
            assert!(
                !rendered.contains(&crate::utils::text_id::encode_base32_crockford(&root)),
                "a committed root leaked into the refusal: {rendered}"
            );
        }
    }

    /// THE VERIFIED CLAIM IS A CAPABILITY, AND IT CANNOT BE FABRICATED.
    ///
    /// `RegisteredEconomicRoot::from_verified_single_root` re-runs no
    /// signature check — the argument's EXISTENCE is the verification. That
    /// only holds if the argument cannot be conjured, and with public fields
    /// it could: a caller wrote the struct literal from arbitrary bytes and
    /// handed it straight to a consumer that trusts it. Making the registered
    /// root opaque while its input stayed forgeable moved the hole up one
    /// type rather than closing it.
    ///
    /// What this test can assert at runtime is the positive half: the one
    /// construction path runs the signature check and refuses a bad one. The
    /// negative half — that no OTHER path exists — is a visibility property,
    /// and `ci/sofi_validated_root_constructors.sh` is what holds it, because
    /// no runtime test can observe a field becoming public.
    #[test]
    fn the_only_verified_claim_is_one_whose_signature_verified() {
        let (pk, sk) = crate::crypto::sphincs::generate_sphincs_keypair().unwrap();
        let body = crate::economic::claim::EconomicRootClaimBody::new(
            [0x11; 32],
            [0x22; 32],
            4,
            [0xC0; 32],
            [0xD0; 32],
            [0x77; 32],
            crate::ccb::genesis::sigalg::SPHINCS_PLUS_SPX256F,
            &pk,
        )
        .unwrap();
        let envelope = sign_economic_root_claim(&body, &sk).unwrap();

        // The capability, and it carries exactly what it verified.
        let verified = decode_and_verify_economic_root_claim(&envelope).unwrap();
        assert_eq!(*verified.body(), body);
        assert_eq!(verified.envelope_bytes(), envelope.as_slice());

        // The SAME body under a foreign signature yields no capability. This
        // is the object a fabricator would want, and the only door to it is
        // shut.
        let (_, other_sk) = crate::crypto::sphincs::generate_sphincs_keypair().unwrap();
        let forged = sign_economic_root_claim(&body, &other_sk).unwrap();
        assert_eq!(
            decode_and_verify_economic_root_claim(&forged),
            Err(ClaimEnvelopeError::SignatureInvalid)
        );

        // And a registered root is reachable only through the capability, so
        // the forged envelope produces nothing downstream either.
        let registered =
            crate::economic::register::RegisteredEconomicRoot::from_verified_single_root(
                decode_registered_economic_claim(&envelope)
                    .unwrap()
                    .single_root()
                    .unwrap(),
            );
        assert_eq!(registered.post_economic_root(), [0xC0; 32]);
    }

    /// THE OTHER ARM STILL WORKS, and the two framings cannot be confused.
    ///
    /// A single-root claim is a protobuf envelope; `C_q` is a bare CCB object
    /// leading with its class. The dispatch is unambiguous for a structural
    /// reason worth stating: the class tag's high byte is `0x00`, and no
    /// canonical protobuf can begin with `0x00` because field number 0 is
    /// illegal. So no valid single-root envelope is ever mistaken for a
    /// conditional claim, and the test asserts that rather than assuming it.
    #[test]
    fn a_single_root_envelope_still_decodes_as_a_single_root() {
        let (pk, sk) = crate::crypto::sphincs::generate_sphincs_keypair().unwrap();
        let body = crate::economic::claim::EconomicRootClaimBody::new(
            [0x11; 32],
            [0x22; 32],
            9,
            [0xC0; 32],
            [0xD0; 32],
            [0x77; 32],
            crate::ccb::genesis::sigalg::SPHINCS_PLUS_SPX256F,
            &pk,
        )
        .unwrap();
        let envelope = sign_economic_root_claim(&body, &sk).unwrap();

        // It cannot be read as the conditional arm, structurally.
        assert_ne!(
            u16::from_be_bytes([envelope[0], envelope[1]]),
            class::SOFI_RESOLUTION_CLAIM,
            "a protobuf envelope cannot lead with a CCB class tag"
        );
        assert_ne!(envelope[0], 0x00, "protobuf field number 0 is illegal");

        match decode_registered_economic_claim(&envelope).unwrap() {
            RegisteredEconomicClaim::SingleRoot(v) => {
                assert_eq!(*v.body(), body);
                assert_eq!(v.envelope_bytes(), envelope);
                // And this arm DOES supply a root — the union did not make the
                // ordinary path fallible for everyone.
                assert_eq!(
                    decode_registered_economic_claim(&envelope)
                        .unwrap()
                        .single_root()
                        .unwrap()
                        .body
                        .post_economic_root,
                    [0xC0; 32]
                );
            }
            other => panic!("a signed single-root envelope must decode as one, got {other:?}"),
        }

        // A tampered envelope is still refused by signature, through the union.
        let mut tampered = envelope.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0x01;
        assert!(decode_registered_economic_claim(&tampered).is_err());
    }

    /// Bytes that are neither a canonical `C_q` nor a canonical single-root
    /// envelope are refused, and a truncated conditional claim does not fall
    /// through to the proto decoder: class dispatch commits to one reading.
    #[test]
    fn a_malformed_cell_does_not_fall_through_to_the_other_decoder() {
        assert!(decode_registered_economic_claim(&[]).is_err());
        let mut truncated = conditional().encode();
        truncated.pop();
        match decode_registered_economic_claim(&truncated) {
            Err(ClaimEnvelopeError::Body(_)) => {}
            other => panic!("a truncated C_q must fail AS a C_q, got {other:?}"),
        }
        // Trailing bytes are not tolerated either — a write-once cell holds
        // exactly one canonical value.
        let mut trailing = conditional().encode();
        trailing.push(0x00);
        assert!(decode_registered_economic_claim(&trailing).is_err());
    }
}
