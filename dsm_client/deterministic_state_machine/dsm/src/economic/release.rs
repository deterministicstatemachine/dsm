// SPDX-License-Identifier: Apache-2.0

//! The recipient economic RELEASE — the transport-only post-admission
//! finalization authority (3.5b PR4).
//!
//! The PR2 acceptance bundle treats `sig_b` as the recipient acceptance
//! FACT, and the bundle is published as admission evidence BEFORE
//! `ECON_ADMITTED` (the evidence DAG must be q-durable before the root
//! registers), so `sig_b` is discoverable independently of any held reply.
//! Therefore acceptance evidence and sender-finalization authority are
//! SPLIT: bare `sig_b` is acceptance provenance and **insufficient to
//! finalize the sender**. What a sender may finalize on is THIS object —
//! signed by the recipient, naming the admitted coordinates — plus an
//! INDEPENDENT quorum read of the recipient's register cell at the named
//! position whose claim must carry exactly `post_economic_root` and
//! `admission_manifest_addr`. A hostile recipient's private "admitted" flag
//! is never trusted; the network-registered root is the fact.
//!
//! Transport evidence only — no CCB class, mirroring the settlement-slot
//! envelope discipline: strict protobuf, decode → re-encode equality on both
//! layers, signature over the exact body bytes under a dedicated domain.

use prost::Message;

use crate::common::domain_tags::TAG_DSM_RECIPIENT_ECONOMIC_RELEASE_SIGN;
use crate::crypto::blake3::dsm_domain_hasher;
use crate::types::proto as generated;

/// Why a release did not verify.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReleaseError {
    Malformed(String),
    /// `recipient_signature` does not verify under the pinned recipient AK.
    SignatureInvalid,
}

impl core::fmt::Display for ReleaseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Malformed(e) => write!(f, "recipient economic release malformed: {e}"),
            Self::SignatureInvalid => write!(
                f,
                "recipient economic release: signature does not verify under the pinned \
                 recipient AK"
            ),
        }
    }
}

impl std::error::Error for ReleaseError {}

/// What a verified release asserts (the sender still owes the independent
/// register read before finalizing on it).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReleaseFacts {
    pub receipt_commitment: [u8; 32],
    pub acceptance_evidence_addr: [u8; 32],
    pub recipient_genesis: [u8; 32],
    pub recipient_devid: [u8; 32],
    pub recipient_economic_position: u64,
    pub post_economic_root: [u8; 32],
    pub admission_manifest_addr: [u8; 32],
}

/// The immutable-store INNER digest of exact release bytes — what the
/// countersign delta's `recipient_economic_release_addr` names.
pub fn recipient_economic_release_addr(release_bytes: &[u8]) -> [u8; 32] {
    crate::storage_object::immutable_inner(
        crate::common::domain_tags::TAG_DSM_RECIPIENT_ECONOMIC_RELEASE,
        release_bytes,
    )
}

/// The signing digest: `H(tag ‖ 0x00 ‖ exact body bytes)`.
fn release_signing_digest(body_bytes: &[u8]) -> [u8; 32] {
    let mut h = dsm_domain_hasher(TAG_DSM_RECIPIENT_ECONOMIC_RELEASE_SIGN);
    h.update(body_bytes);
    *h.finalize().as_bytes()
}

/// PRODUCER: sign and encode a release for admitted coordinates. Every field
/// is an output of the recipient's built admission — nothing here is a
/// prediction.
#[allow(clippy::too_many_arguments)]
pub fn sign_recipient_economic_release(
    facts: &ReleaseFacts,
    recipient_ak_sk: &[u8],
) -> Result<Vec<u8>, ReleaseError> {
    let body = generated::RecipientEconomicReleaseBodyV1 {
        receipt_commitment: facts.receipt_commitment.to_vec(),
        acceptance_evidence_addr: facts.acceptance_evidence_addr.to_vec(),
        recipient_genesis: facts.recipient_genesis.to_vec(),
        recipient_devid: facts.recipient_devid.to_vec(),
        recipient_economic_position: facts.recipient_economic_position,
        post_economic_root: facts.post_economic_root.to_vec(),
        admission_manifest_addr: facts.admission_manifest_addr.to_vec(),
    }
    .encode_to_vec();
    let digest = release_signing_digest(&body);
    let recipient_signature = crate::crypto::sphincs::sphincs_sign(recipient_ak_sk, &digest)
        .map_err(|e| ReleaseError::Malformed(format!("sign: {e}")))?;
    Ok(generated::RecipientEconomicReleaseV1 {
        body,
        recipient_signature,
    }
    .encode_to_vec())
}

fn fixed32(what: &str, v: &[u8]) -> Result<[u8; 32], ReleaseError> {
    v.try_into()
        .map_err(|_| ReleaseError::Malformed(format!("{what} is not 32 bytes")))
}

/// VERIFIER: strict-decode both layers (decode → re-encode equality) and
/// verify the signature under `recipient_ak` — which must be the PINNED
/// contact AK (or a P0–P6-proven one), never a key found beside the release.
pub fn verify_recipient_economic_release(
    release_bytes: &[u8],
    recipient_ak: &[u8],
) -> Result<ReleaseFacts, ReleaseError> {
    let outer = generated::RecipientEconomicReleaseV1::decode(release_bytes)
        .map_err(|e| ReleaseError::Malformed(format!("decode: {e}")))?;
    if outer.encode_to_vec() != release_bytes {
        return Err(ReleaseError::Malformed(
            "non-canonical encoding (re-encode mismatch)".to_string(),
        ));
    }
    let body = generated::RecipientEconomicReleaseBodyV1::decode(outer.body.as_slice())
        .map_err(|e| ReleaseError::Malformed(format!("body decode: {e}")))?;
    if body.encode_to_vec() != outer.body {
        return Err(ReleaseError::Malformed(
            "body encoding is non-canonical".to_string(),
        ));
    }
    let digest = release_signing_digest(&outer.body);
    let ok =
        crate::crypto::sphincs::sphincs_verify(recipient_ak, &digest, &outer.recipient_signature)
            .map_err(|e| ReleaseError::Malformed(format!("verify: {e}")))?;
    if !ok {
        return Err(ReleaseError::SignatureInvalid);
    }
    Ok(ReleaseFacts {
        receipt_commitment: fixed32("receipt_commitment", &body.receipt_commitment)?,
        acceptance_evidence_addr: fixed32(
            "acceptance_evidence_addr",
            &body.acceptance_evidence_addr,
        )?,
        recipient_genesis: fixed32("recipient_genesis", &body.recipient_genesis)?,
        recipient_devid: fixed32("recipient_devid", &body.recipient_devid)?,
        recipient_economic_position: body.recipient_economic_position,
        post_economic_root: fixed32("post_economic_root", &body.post_economic_root)?,
        admission_manifest_addr: fixed32("admission_manifest_addr", &body.admission_manifest_addr)?,
    })
}
