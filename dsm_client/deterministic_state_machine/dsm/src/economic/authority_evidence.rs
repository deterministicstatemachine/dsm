// SPDX-License-Identifier: Apache-2.0

//! The portable P0–P6 authority evidence an economic admission publishes.
//!
//! The manifest's `authority_evidence_addr` names the exact bytes of an
//! [`AuthorityEvidenceV1`] in the immutable store. A FOREIGN lineage walker
//! verifies it with the SAME resolver every other authority check uses —
//! [`resolve_owner_authority_at_position`] — and gets back the two facts the
//! economic verifier needs and must never take from a claimant beside a
//! claim: the proven AK, and the committed `network_id` (field 2 of the
//! `GenesisParamsV3` whose recomputation IS `G`, authenticated the instant
//! P0's equality holds).
//!
//! Verification is entirely seedless: everything here is public material.
//! The object is `AnchorPresentationV3` minus its vault-anchor fields — the
//! same shape `verify_anchor_presentation` already proves foreign-verifiable.

use prost::Message;

use crate::ccb::decode::{decode_delegation, decode_genesis_params, decode_transition};
use crate::common::device_tree::DevTreeProof;
use crate::common::domain_tags::TAG_DSM_ECONOMIC_AUTHORITY_EVIDENCE;
use crate::core::identity::authority_resolver::{
    resolve_owner_authority_at_position, PresentedIdentity, ResolveFailure, SignedDelegation,
    SignedTransition,
};
use crate::types::proto as generated;

/// What verified authority evidence establishes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityFacts {
    /// The P0–P6-proven authority key.
    pub proven_ak: Vec<u8>,
    /// The committed network, recovered by recomputation — never claimed.
    pub network_id: Vec<u8>,
}

/// Why authority evidence did not verify. Mirrors the resolver's taxonomy:
/// `Incomplete` is missing material (liveness), `Invalid` is an attack or
/// corruption.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorityEvidenceError {
    Malformed(String),
    Incomplete(String),
    Invalid(String),
    /// The proven device is not the lineage owner the walker is validating.
    DeviceMismatch,
}

impl core::fmt::Display for AuthorityEvidenceError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Malformed(e) => write!(f, "authority evidence malformed: {e}"),
            Self::Incomplete(e) => write!(f, "authority evidence incomplete: {e}"),
            Self::Invalid(e) => write!(f, "authority evidence INVALID: {e}"),
            Self::DeviceMismatch => write!(
                f,
                "authority evidence proves a DIFFERENT device than the lineage owner"
            ),
        }
    }
}

impl std::error::Error for AuthorityEvidenceError {}

/// The immutable-store INNER digest of exact evidence bytes — the identity
/// the manifest carries and a fetch takes (the outer store address derives
/// from it).
pub fn authority_evidence_addr(evidence_bytes: &[u8]) -> [u8; 32] {
    crate::storage_object::immutable_inner(TAG_DSM_ECONOMIC_AUTHORITY_EVIDENCE, evidence_bytes)
}

/// Strict decode: prost + re-encode equality, the settlement-wire discipline.
/// Two byte strings must never decode to one object, or the address stops
/// being exact.
pub fn decode_authority_evidence(
    bytes: &[u8],
) -> Result<generated::AuthorityEvidenceV1, AuthorityEvidenceError> {
    let ev = generated::AuthorityEvidenceV1::decode(bytes)
        .map_err(|e| AuthorityEvidenceError::Malformed(format!("decode: {e}")))?;
    let reencoded = ev.encode_to_vec();
    if reencoded != bytes {
        return Err(AuthorityEvidenceError::Malformed(
            "non-canonical encoding (re-encode mismatch)".to_string(),
        ));
    }
    Ok(ev)
}

/// Verify authority evidence for the lineage owner `(expected_g,
/// expected_devid)` at the manifest's bound `authority_position` (a
/// transition digest `t_j`, never a tree root).
pub fn verify_authority_evidence(
    evidence_bytes: &[u8],
    expected_g: &[u8; 32],
    expected_devid: &[u8; 32],
    authority_position: &[u8; 32],
) -> Result<AuthorityFacts, AuthorityEvidenceError> {
    let ev = decode_authority_evidence(evidence_bytes)?;

    let atta: [u8; 32] = ev
        .atta
        .as_slice()
        .try_into()
        .map_err(|_| AuthorityEvidenceError::Malformed("atta is not 32 bytes".to_string()))?;
    let params = decode_genesis_params(&ev.genesis_params_ccb)
        .map_err(|e| AuthorityEvidenceError::Malformed(format!("genesis params: {e}")))?;

    let mut delegations = Vec::with_capacity(ev.delegations.len());
    for obj in &ev.delegations {
        delegations.push(SignedDelegation {
            delegation: decode_delegation(&obj.ccb)
                .map_err(|e| AuthorityEvidenceError::Malformed(format!("delegation: {e}")))?,
            grk_signature: obj.signature.clone(),
        });
    }
    let mut transitions = Vec::with_capacity(ev.transitions.len());
    for obj in &ev.transitions {
        transitions.push(SignedTransition {
            transition: decode_transition(&obj.ccb)
                .map_err(|e| AuthorityEvidenceError::Malformed(format!("transition: {e}")))?,
            delegate_signature: obj.signature.clone(),
        });
    }
    let inclusion = DevTreeProof::from_bytes(&ev.inclusion_proof).ok_or_else(|| {
        AuthorityEvidenceError::Malformed("inclusion proof does not parse".to_string())
    })?;

    let presented = PresentedIdentity {
        genesis_params: &params,
        delegations: &delegations,
        transitions: &transitions,
        inclusion: &inclusion,
        ak_pk: &ev.ak_public_key,
        atta: &atta,
    };
    let proven = resolve_owner_authority_at_position(expected_g, authority_position, &presented)
        .map_err(|e| match e {
            ResolveFailure::Absent(m) | ResolveFailure::Incomplete(m) => {
                AuthorityEvidenceError::Incomplete(m.to_string())
            }
            ResolveFailure::Invalid(m) => AuthorityEvidenceError::Invalid(m),
        })?;
    if proven.device_id != *expected_devid {
        return Err(AuthorityEvidenceError::DeviceMismatch);
    }
    Ok(AuthorityFacts {
        proven_ak: proven.ak_pk,
        network_id: proven.network_id,
    })
}
