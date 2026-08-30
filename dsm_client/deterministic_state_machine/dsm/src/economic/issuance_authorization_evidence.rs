// SPDX-License-Identifier: MIT OR Apache-2.0

//! The `0x0029` evidence bundle: strict decode of
//! `IssuanceAuthorizationEvidenceV1`.
//!
//! Transport proto, no CCB class — the frozen precedent for evidence wire.
//! Nothing here is VERIFIED beyond shape: the policy bytes are not yet hashed
//! against a commit, the body is not yet checked against the operation, and
//! no signature is checked. Every one of those is the arm's job, and doing any
//! of it here would split one conjunction across two files.

use prost::Message;

use crate::economic::issuance::IssuanceAuthorizationBody;
use crate::types::proto as generated;

/// The most signatures a bundle may carry.
///
/// A k-of-N policy needs at most N, and a bundle presenting more than this is
/// asking a verifier to do unbounded signature work for one credit — the
/// evidence is malformed, not merely wasteful. SPHINCS+ verification is
/// expensive enough that the bound is a real defence, not hygiene.
pub const MAX_ISSUANCE_SIGNATURES: usize = 16;

/// A strictly decoded issuance-authorization bundle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuanceAuthorizationEvidence {
    /// Exact `TokenPolicyV3` bytes. The arm re-hashes these to the operation's
    /// `policy_commit`; they are NOT trusted as presented.
    pub canonical_policy_bytes: Vec<u8>,
    /// The decoded body the signers signed.
    pub body: IssuanceAuthorizationBody,
    /// The exact CCB bytes the body decoded from, retained so the arm can
    /// recompute the signing digest over the same bytes rather than a
    /// re-encoding.
    pub authorization_body_ccb: Vec<u8>,
    /// `(signer_public_key, signature)` pairs, in presentation order.
    pub signatures: Vec<(Vec<u8>, Vec<u8>)>,
}

/// Strict decode: canonical re-encode equality, bounded signature count, no
/// empty fields, and a body that decodes at exactly `(0x0029, schema 1)`.
///
/// The re-encode equality is what kills unknown fields, duplicated tags and
/// non-canonical varints — the same discipline the settlement-slot envelope
/// and the two DLV evidence bundles use.
pub fn decode_issuance_authorization_evidence(
    bytes: &[u8],
) -> Result<IssuanceAuthorizationEvidence, String> {
    if bytes.is_empty() {
        return Err("empty issuance-authorization evidence".into());
    }
    let ev = generated::IssuanceAuthorizationEvidenceV1::decode(bytes)
        .map_err(|_| "issuance-authorization evidence does not decode".to_string())?;
    if ev.encode_to_vec() != bytes {
        return Err("issuance-authorization evidence is not canonical".into());
    }
    if ev.canonical_policy_bytes.is_empty() {
        return Err("issuance-authorization evidence carries no policy bytes".into());
    }
    if ev.signatures.is_empty() {
        return Err("issuance-authorization evidence carries no signatures".into());
    }
    if ev.signatures.len() > MAX_ISSUANCE_SIGNATURES {
        return Err(format!(
            "issuance-authorization evidence carries {} signatures, more than the {} a k-of-N \
             policy can need",
            ev.signatures.len(),
            MAX_ISSUANCE_SIGNATURES
        ));
    }
    let mut signatures = Vec::with_capacity(ev.signatures.len());
    for s in &ev.signatures {
        if s.signer_public_key.is_empty() || s.signature.is_empty() {
            return Err("issuance-authorization evidence carries an empty key or signature".into());
        }
        signatures.push((s.signer_public_key.clone(), s.signature.clone()));
    }
    // ONE decoder for this body, in `decode.rs` beside its peers. Re-encode
    // equality is required HERE because the signature covers bytes: two
    // encodings carrying one authorization would be two authorizations.
    let body =
        crate::economic::decode::decode_issuance_authorization_body(&ev.authorization_body_ccb)
            .map_err(|e| format!("issuance authorization body: {e}"))?;
    let reencoded = body
        .encode()
        .map_err(|e| format!("issuance authorization body re-encode: {e}"))?;
    if reencoded != ev.authorization_body_ccb {
        return Err("issuance authorization body is not canonical".into());
    }
    Ok(IssuanceAuthorizationEvidence {
        canonical_policy_bytes: ev.canonical_policy_bytes,
        body,
        authorization_body_ccb: ev.authorization_body_ccb,
        signatures,
    })
}
