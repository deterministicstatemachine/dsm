// SPDX-License-Identifier: Apache-2.0

//! The replayable accepted-successor evidence an economic admission publishes.
//!
//! The manifest's `dsm_successor_evidence_addr` names the exact bytes of a
//! [`DsmSuccessorEvidenceV1`]: the balance-free v2 chain-tip preimage fields,
//! the resulting `C_dsm+`, and **`sigma_dsm`** — the owner-AK signature over
//! `H(DSM/economic-substrate-sign/v1, G ‖ DevID ‖ C_dsm+ ‖ operation_digest)`.
//!
//! Before this object existed, "the device accepted this successor" was a
//! local assertion: the substrate address held bare operation bytes, and
//! recomputing a digest proves bytes are bytes. With it, a FOREIGN verifier
//! recomputes `C_dsm+` from the preimage through THE one canonical helper
//! ([`relationship_chain_tip_v2`] — never a second encoding), recomputes the
//! operation digest from the embedded operation bytes, and checks
//! `sigma_dsm` under the P0–P6-proven AK. The economic balance effect is NOT
//! here and never will be: it is bound independently and conjunctively by
//! the write-set rule (verified Operation → exact write set → `R_econ`
//! transition), and `R_econ` is the sole authenticated balance
//! representation.

use prost::Message;

use crate::common::domain_tags::{TAG_DSM_ECONOMIC_SUBSTRATE_SIGN, TAG_DSM_ECONOMIC_SUCCESSOR_EVIDENCE};
use crate::crypto::blake3::dsm_domain_hasher;
use crate::types::device_state::relationship_chain_tip_v2;
use crate::types::operations::Operation;
use crate::types::proto as generated;

/// Why successor evidence did not verify.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SuccessorEvidenceError {
    Malformed(String),
    /// The carried `C_dsm+` is not what the preimage recomputes to.
    CommitmentMismatch,
    /// `sigma_dsm` does not verify under the proven AK.
    SignatureInvalid,
}

impl core::fmt::Display for SuccessorEvidenceError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Malformed(e) => write!(f, "successor evidence malformed: {e}"),
            Self::CommitmentMismatch => write!(
                f,
                "successor evidence: carried C_dsm+ does not recompute from its own preimage"
            ),
            Self::SignatureInvalid => write!(
                f,
                "successor evidence: sigma_dsm does not verify under the proven AK"
            ),
        }
    }
}

impl std::error::Error for SuccessorEvidenceError {}

/// What verified successor evidence establishes.
#[derive(Debug, Clone)]
pub struct VerifiedDsmSuccessor {
    pub operation: Operation,
    pub operation_digest: [u8; 32],
    pub c_dsm_plus: [u8; 32],
}

/// The `sigma_dsm` signing digest.
pub fn substrate_signing_digest(
    genesis: &[u8; 32],
    device_id: &[u8; 32],
    c_dsm_plus: &[u8; 32],
    operation_digest: &[u8; 32],
) -> [u8; 32] {
    let mut h = dsm_domain_hasher(TAG_DSM_ECONOMIC_SUBSTRATE_SIGN);
    h.update(genesis);
    h.update(device_id);
    h.update(c_dsm_plus);
    h.update(operation_digest);
    *h.finalize().as_bytes()
}

/// The immutable-store inner digest of exact evidence bytes — what the
/// manifest's `dsm_successor_evidence_addr` must equal.
pub fn successor_evidence_addr(evidence_bytes: &[u8]) -> [u8; 32] {
    crate::storage_object::immutable_inner(TAG_DSM_ECONOMIC_SUCCESSOR_EVIDENCE, evidence_bytes)
}

/// PRODUCER: sign and encode successor evidence for an accepted successor.
///
/// The preimage fields must be the accepted `RelationshipChainState`'s own —
/// the recomputation below refuses anything else, so a producer cannot even
/// accidentally sign a successor it did not construct.
#[allow(clippy::too_many_arguments)]
pub fn sign_dsm_successor_evidence(
    rel_key: &[u8; 32],
    embedded_parent: &[u8; 32],
    counterparty_devid: &[u8; 32],
    operation_bytes: &[u8],
    entropy: &[u8],
    encapsulated_entropy: Option<&[u8]>,
    genesis: &[u8; 32],
    device_id: &[u8; 32],
    ak_secret_key: &[u8],
) -> Result<Vec<u8>, SuccessorEvidenceError> {
    let c_dsm_plus = relationship_chain_tip_v2(
        rel_key,
        embedded_parent,
        counterparty_devid,
        operation_bytes,
        entropy,
        encapsulated_entropy,
    );
    let operation_digest = crate::economic::faucet::dsm_operation_digest(operation_bytes);
    let digest = substrate_signing_digest(genesis, device_id, &c_dsm_plus, &operation_digest);
    let sigma_dsm = crate::crypto::sphincs::sphincs_sign(ak_secret_key, &digest)
        .map_err(|e| SuccessorEvidenceError::Malformed(format!("sign: {e}")))?;
    Ok(generated::DsmSuccessorEvidenceV1 {
        rel_key: rel_key.to_vec(),
        embedded_parent: embedded_parent.to_vec(),
        counterparty_devid: counterparty_devid.to_vec(),
        operation_bytes: operation_bytes.to_vec(),
        entropy: entropy.to_vec(),
        encapsulated_entropy: encapsulated_entropy.map(|e| e.to_vec()),
        c_dsm_plus: c_dsm_plus.to_vec(),
        sigma_dsm,
    }
    .encode_to_vec())
}

fn fixed32(what: &str, v: &[u8]) -> Result<[u8; 32], SuccessorEvidenceError> {
    v.try_into()
        .map_err(|_| SuccessorEvidenceError::Malformed(format!("{what} is not 32 bytes")))
}

/// VERIFIER: the foreign-checkable "this identity accepted this successor
/// carrying this operation".
///
/// `proven_ak` must be the P0–P6-proven authority key from verified
/// [`crate::economic::authority_evidence`] — never a key found beside the
/// evidence.
pub fn verify_dsm_successor_evidence(
    evidence_bytes: &[u8],
    genesis: &[u8; 32],
    device_id: &[u8; 32],
    proven_ak: &[u8],
) -> Result<VerifiedDsmSuccessor, SuccessorEvidenceError> {
    let ev = generated::DsmSuccessorEvidenceV1::decode(evidence_bytes)
        .map_err(|e| SuccessorEvidenceError::Malformed(format!("decode: {e}")))?;
    if ev.encode_to_vec() != evidence_bytes {
        return Err(SuccessorEvidenceError::Malformed(
            "non-canonical encoding (re-encode mismatch)".to_string(),
        ));
    }
    let rel_key = fixed32("rel_key", &ev.rel_key)?;
    let embedded_parent = fixed32("embedded_parent", &ev.embedded_parent)?;
    let counterparty_devid = fixed32("counterparty_devid", &ev.counterparty_devid)?;
    let carried = fixed32("c_dsm_plus", &ev.c_dsm_plus)?;

    // ONE preimage helper — the same function `compute_chain_tip` calls.
    let recomputed = relationship_chain_tip_v2(
        &rel_key,
        &embedded_parent,
        &counterparty_devid,
        &ev.operation_bytes,
        &ev.entropy,
        ev.encapsulated_entropy.as_deref(),
    );
    if recomputed != carried {
        return Err(SuccessorEvidenceError::CommitmentMismatch);
    }

    // The operation, strictly: decode + re-encode equality, so the digest is
    // of bytes the type system can also reason about.
    let operation = Operation::from_bytes(&ev.operation_bytes)
        .map_err(|e| SuccessorEvidenceError::Malformed(format!("operation: {e}")))?;
    if operation.to_bytes() != ev.operation_bytes {
        return Err(SuccessorEvidenceError::Malformed(
            "operation bytes are non-canonical".to_string(),
        ));
    }
    let operation_digest = crate::economic::faucet::dsm_operation_digest(&ev.operation_bytes);

    let digest = substrate_signing_digest(genesis, device_id, &carried, &operation_digest);
    let ok = crate::crypto::sphincs::sphincs_verify(proven_ak, &digest, &ev.sigma_dsm)
        .map_err(|e| SuccessorEvidenceError::Malformed(format!("verify: {e}")))?;
    if !ok {
        return Err(SuccessorEvidenceError::SignatureInvalid);
    }
    Ok(VerifiedDsmSuccessor {
        operation,
        operation_digest,
        c_dsm_plus: carried,
    })
}
