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
//! Attribution and storage only. A member never runs P0–P6, never validates a
//! transition, and never judges economics. What it does do is refuse a claim
//! that says someone other than the authenticated caller wrote it.
//!
//! That refusal is load-bearing because `K_root` does **not** gate writes.
//! The cell's coordinate is identity-scoped but derivable by anyone holding a
//! victim's public `(G, DevID, position)`, and the register is write-once — so
//! a single accepted value in that cell burns the position forever. The
//! attribution check is what makes such a write impossible, and it is only as
//! strong as the authentication behind `AuthenticatedCaller`, which the
//! verifying end establishes through P0–P6.

use prost::Message;

use crate::ccb::decode::DecodeError;
use crate::ccb::{class, CcbError, CcbObject};
use crate::economic::claim::EconomicRootClaimBody;
use crate::economic::register::{AttributionError, AuthenticatedCaller};
use crate::types::proto as generated;

/// Matches the proto's `dsm_max_len`; prost does not enforce it, so this
/// module does.
const MAX_KEY_OR_SIG_BYTES: usize = 65_535;

/// A claim envelope that decoded strictly and whose signature verified under
/// its own `claimant_public_key`.
///
/// Verifying the signature proves the body was signed by whoever holds that
/// key. It does **not** prove that key belongs to the caller — that is
/// attribution, checked separately by [`verify_claim_attribution`], and the
/// two are kept apart because a member can do the second without the first
/// being sufficient.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedEconomicRootClaim {
    pub body: EconomicRootClaimBody,
    /// The exact bytes the member stores. Retained rather than re-derived: a
    /// byte-different re-encode reads as a different value at a write-once
    /// cell.
    pub envelope_bytes: Vec<u8>,
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

/// The member-side attribution check. Storage-layer only.
///
/// Deliberately takes a decoded-and-signature-verified claim: a member that
/// checked attribution without checking the signature would accept a body
/// anyone could have written on the caller's behalf, and one that checked the
/// signature without attribution would let an authenticated caller claim as
/// somebody else.
pub fn verify_claim_attribution(
    claim: &VerifiedEconomicRootClaim,
    caller: &AuthenticatedCaller,
    configured_storage_set_id: &[u8; 32],
) -> Result<(), AttributionError> {
    if claim.body.claimant_public_key != caller.public_key {
        return Err(AttributionError::ClaimantIsNotCaller);
    }
    if claim.body.trader_devid != caller.device_id {
        return Err(AttributionError::DeviceIsNotCaller);
    }
    if claim.body.root_register_storage_set_id != *configured_storage_set_id {
        return Err(AttributionError::WrongStorageSet {
            claimed: claim.body.root_register_storage_set_id,
            configured: *configured_storage_set_id,
        });
    }
    Ok(())
}

/// Whether the class this module decodes is the one the registry names.
/// Kept as a compile-time-adjacent assertion so a class renumbering cannot
/// silently retarget the decoder.
const _: () = assert!(EconomicRootClaimBody::CLASS == class::ECONOMIC_ROOT_CLAIM_BODY);
