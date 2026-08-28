// SPDX-License-Identifier: Apache-2.0

//! Portable bilateral-acceptance evidence — the recipient-produced fact that
//! funds a peer-debit credit.
//!
//! `CreditSourceValidatedPeerDebit.acceptance_evidence_addr` names the exact
//! bytes of a [`PeerTransferAcceptanceEvidenceV1`]: the exact signed
//! `OnlineTransferRequest`, the exact A-side full receipt wire, and the exact
//! recipient countersignature. The A-side material alone is a PROPOSAL; the
//! `sig_b` countersignature is the acceptance.
//!
//! ## Certificate ancestry follows the signer, not the receipt role
//!
//! Per-step EK certificates chain device-locally per relationship (the AK
//! certifies only at relationship genesis), and role reversal or a BLE step
//! advances the same device chain — so each side's predecessor is referenced
//! BY SIGNER through content-addressed [`EkCertStepV1`] objects, walked
//! iteratively to the signer's P0–P6-proven AK. A non-portable ancestry step
//! fails closed as `Incomplete`, never silently assumed A→A/B→B.
//!
//! Production preimages, verbatim: `sig_a` over
//! `H_bind(commitment ‖ commitment)`; `sig_b` over
//! `H_bcanon(H_bind(commitment ‖ commitment) ‖ b_parent ‖ b_child)` — through
//! the SAME core target constructors the producers use.

use prost::Message;

use crate::common::domain_tags::{TAG_DSM_EK_CERT_STEP, TAG_DSM_PEER_TRANSFER_ACCEPTANCE};
use crate::crypto::ephemeral_key::verify_ek_cert;
use crate::crypto::sphincs::sphincs_verify;
use crate::economic::provenance::PeerLineageFailure;
use crate::types::proto as generated;
use crate::types::receipt_types::{
    compute_receipt_b_canonical_target, compute_receipt_challenge_response_target,
    decode_receipt_countersign_b_wire, StitchedReceiptV2,
};

/// The EK-step byte fetcher a caller supplies: exact bytes at one
/// `EkCertStepV1` address.
pub type EkStepFetch<'a> = dyn FnMut(&[u8; 32]) -> Result<Vec<u8>, PeerLineageFailure> + 'a;

/// Iteration budget for one EK ancestry walk. Exhausting it is `Incomplete`
/// — an adversarially deep (but acyclic) chain must never look like a
/// forgery, and must never recurse the stack.
const EK_CHAIN_BUDGET: usize = 4096;

/// The immutable-store inner digest of exact acceptance-bundle bytes.
pub fn acceptance_evidence_addr(bundle_bytes: &[u8]) -> [u8; 32] {
    crate::storage_object::immutable_inner(TAG_DSM_PEER_TRANSFER_ACCEPTANCE, bundle_bytes)
}

/// The immutable-store inner digest of exact EK-step bytes.
pub fn ek_cert_step_addr(step_bytes: &[u8]) -> [u8; 32] {
    crate::storage_object::immutable_inner(TAG_DSM_EK_CERT_STEP, step_bytes)
}

/// One side's identity anchor for the acceptance check.
pub struct AcceptanceParty<'a> {
    pub devid: [u8; 32],
    /// The P0–P6-proven authority key — never a key found beside the
    /// evidence.
    pub proven_ak: &'a [u8],
}

/// What verified acceptance evidence establishes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedAcceptance {
    pub commitment: [u8; 32],
    /// The bilateral step, in A-space: the sender successor this acceptance
    /// is FOR. Binding this to the peer's validated debit successor
    /// (`C_dsm+`) is what "same bilateral step" means.
    pub sender_parent_tip: [u8; 32],
    pub sender_child_tip: [u8; 32],
    /// The recipient's own canonical pair for the applied step.
    pub b_parent_tip: [u8; 32],
    pub b_child_tip: [u8; 32],
}

fn malformed(what: &str, e: impl core::fmt::Display) -> PeerLineageFailure {
    PeerLineageFailure::Invalid(format!("acceptance evidence: {what}: {e}"))
}

fn invalid(what: &str) -> PeerLineageFailure {
    PeerLineageFailure::Invalid(format!("acceptance evidence: {what}"))
}

/// Walk one signer's EK ancestry from `prior_step_addr` down to relationship
/// genesis, ITERATIVELY, then verify upward from the signer's AK. Returns the
/// expected certifying key for the CURRENT step.
///
/// `fetch` returns the exact bytes at an `EkCertStepV1` address (re-hash
/// verified by the fetcher). Budget exhaustion and unfetchable steps are
/// `Incomplete`; a cycle or a failed certificate is `Invalid`.
fn resolve_expected_prev_pk(
    prior_step_addr: Option<[u8; 32]>,
    signer_ak: &[u8],
    fetch: &mut EkStepFetch<'_>,
) -> Result<Vec<u8>, PeerLineageFailure> {
    // Phase 1: collect the chain down to genesis (worklist, no recursion).
    let mut chain: Vec<generated::EkCertStepV1> = Vec::new();
    let mut seen: std::collections::HashSet<[u8; 32]> = std::collections::HashSet::new();
    let mut cursor = prior_step_addr;
    while let Some(addr) = cursor {
        if chain.len() >= EK_CHAIN_BUDGET {
            return Err(PeerLineageFailure::Incomplete(
                "EK ancestry exceeds the local walk budget".to_string(),
            ));
        }
        if !seen.insert(addr) {
            return Err(invalid("EK ancestry cycle"));
        }
        let bytes = fetch(&addr)?;
        if ek_cert_step_addr(&bytes) != addr {
            return Err(invalid("EK step bytes do not hash to their address"));
        }
        let step = generated::EkCertStepV1::decode(bytes.as_slice())
            .map_err(|e| malformed("EK step decode", e))?;
        if step.encode_to_vec() != bytes {
            return Err(invalid("EK step encoding is non-canonical"));
        }
        cursor = match &step.prior_step_addr {
            Some(p) => Some(
                p.as_slice()
                    .try_into()
                    .map_err(|_| invalid("EK step prior addr is not 32 bytes"))?,
            ),
            None => None,
        };
        chain.push(step);
    }
    // Phase 2: verify upward from the AK root.
    let mut expected: Vec<u8> = signer_ak.to_vec();
    for step in chain.iter().rev() {
        let h_n: [u8; 32] = step
            .h_n
            .as_slice()
            .try_into()
            .map_err(|_| invalid("EK step h_n is not 32 bytes"))?;
        let ok = verify_ek_cert(&expected, &step.ek_pk, &h_n, &step.ek_cert)
            .map_err(|e| malformed("EK cert verify", e))?;
        if !ok {
            return Err(invalid("EK step certificate does not chain"));
        }
        expected = step.ek_pk.clone();
    }
    Ok(expected)
}

/// Verify a portable acceptance bundle.
///
/// `expected_transfer_bytes` is the exact canonical UNSIGNED
/// `Operation::Transfer` bytes of the peer's VALIDATED debit (the wire's
/// `canonical_operation_bytes` preimage — the signature is cleared before
/// hashing/signing, so the signed operation the walker verifies must be
/// cleared before comparison); `expected_sender_child_tip` is that debit
/// successor's `C_dsm+`. Binding both is what makes this acceptance be FOR
/// that debit — same sender, same recipient, same exact Transfer, same
/// bilateral step.
///
/// `expected_recipient_b_pair` is the `(embedded_parent, C_dsm+)` pair of
/// the exact RECIPIENT successor this acceptance is being consumed for —
/// derived by the caller from the verified recipient substrate, never from
/// the bundle. The countersign's self-declared `b_parent_tip`/`b_child_tip`
/// must equal it: a bundle must not self-select the pair it claims to
/// authenticate.
pub fn verify_peer_transfer_acceptance(
    bundle_bytes: &[u8],
    sender: &AcceptanceParty<'_>,
    recipient: &AcceptanceParty<'_>,
    expected_transfer_bytes: &[u8],
    expected_sender_child_tip: &[u8; 32],
    expected_recipient_b_pair: &([u8; 32], [u8; 32]),
    fetch_step: &mut EkStepFetch<'_>,
) -> Result<VerifiedAcceptance, PeerLineageFailure> {
    let bundle = generated::PeerTransferAcceptanceEvidenceV1::decode(bundle_bytes)
        .map_err(|e| malformed("bundle decode", e))?;
    if bundle.encode_to_vec() != bundle_bytes {
        return Err(invalid("bundle encoding is non-canonical"));
    }

    // ── The exact signed transfer (the sender's PROPOSAL) ──────────────────
    let request =
        generated::OnlineTransferRequest::decode(bundle.transfer_request_bytes.as_slice())
            .map_err(|e| malformed("transfer request decode", e))?;
    if request.canonical_operation_bytes != expected_transfer_bytes {
        return Err(invalid(
            "transfer request does not carry the exact validated debit operation",
        ));
    }
    let sig_ok = sphincs_verify(
        sender.proven_ak,
        &request.canonical_operation_bytes,
        &request.signature,
    )
    .map_err(|e| malformed("transfer signature verify", e))?;
    if !sig_ok {
        return Err(invalid(
            "transfer signature does not verify under the sender's proven AK",
        ));
    }

    // ── The A-side receipt evidence, bound to the request by digest ────────
    let evidence_digest = crate::crypto::blake3::domain_hash_bytes(
        crate::common::domain_tags::TAG_DSM_RECEIPT_EVIDENCE_A,
        &bundle.receipt_evidence_a_bytes,
    );
    if request.receipt_evidence_digest != evidence_digest {
        return Err(invalid(
            "receipt evidence bytes are not the ones the transfer request names",
        ));
    }
    let receipt = StitchedReceiptV2::from_canonical_protobuf(&bundle.receipt_evidence_a_bytes)
        .map_err(|e| malformed("receipt decode", e))?;
    if receipt.devid_a != sender.devid || receipt.devid_b != recipient.devid {
        return Err(invalid("receipt names different parties"));
    }
    if receipt.child_tip != *expected_sender_child_tip {
        return Err(invalid(
            "receipt is for a different bilateral step than the validated debit successor",
        ));
    }
    let commitment = receipt
        .compute_commitment()
        .map_err(|e| malformed("receipt commitment", e))?;

    // ── sig_a: the sender's per-step EK, chained to the sender AK ──────────
    let a_prior: Option<[u8; 32]> = match &bundle.a_prior_step_addr {
        Some(p) => Some(
            p.as_slice()
                .try_into()
                .map_err(|_| invalid("a_prior_step_addr is not 32 bytes"))?,
        ),
        None => None,
    };
    let expected_prev_a = resolve_expected_prev_pk(a_prior, sender.proven_ak, fetch_step)?;
    let cert_a_ok = verify_ek_cert(
        &expected_prev_a,
        &receipt.ek_pk_a,
        &receipt.parent_tip,
        &receipt.ek_cert_a,
    )
    .map_err(|e| malformed("ek_cert_a verify", e))?;
    if !cert_a_ok {
        return Err(invalid("ek_cert_a does not chain to the sender's ancestry"));
    }
    let a_target = compute_receipt_challenge_response_target(&commitment, &commitment);
    let sig_a_ok = sphincs_verify(&receipt.ek_pk_a, &a_target, &receipt.sig_a)
        .map_err(|e| malformed("sig_a verify", e))?;
    if !sig_a_ok {
        return Err(invalid("sig_a does not verify"));
    }

    // ── sig_b: THE acceptance — recipient per-step EK, chained to its AK ───
    let countersign = decode_receipt_countersign_b_wire(&bundle.receipt_countersign_b_bytes)
        .map_err(|e| malformed("countersign decode", e))?;
    let cs_commitment: [u8; 32] = countersign
        .commitment
        .as_slice()
        .try_into()
        .map_err(|_| invalid("countersign commitment is not 32 bytes"))?;
    if cs_commitment != commitment {
        return Err(invalid("countersign is for a different receipt commitment"));
    }
    let b_parent_tip: [u8; 32] = countersign
        .b_parent_tip
        .as_slice()
        .try_into()
        .map_err(|_| invalid("b_parent_tip is not 32 bytes"))?;
    let b_child_tip: [u8; 32] = countersign
        .b_child_tip
        .as_slice()
        .try_into()
        .map_err(|_| invalid("b_child_tip is not 32 bytes"))?;
    if (b_parent_tip, b_child_tip) != *expected_recipient_b_pair {
        return Err(invalid(
            "acceptance b-side pair is not the accepted recipient successor's pair",
        ));
    }
    let b_prior: Option<[u8; 32]> = match &bundle.b_prior_step_addr {
        Some(p) => Some(
            p.as_slice()
                .try_into()
                .map_err(|_| invalid("b_prior_step_addr is not 32 bytes"))?,
        ),
        None => None,
    };
    let expected_prev_b = resolve_expected_prev_pk(b_prior, recipient.proven_ak, fetch_step)?;
    let cert_b_ok = verify_ek_cert(
        &expected_prev_b,
        &countersign.ek_pk_b,
        &receipt.parent_tip,
        &countersign.ek_cert_b,
    )
    .map_err(|e| malformed("ek_cert_b verify", e))?;
    if !cert_b_ok {
        return Err(invalid(
            "ek_cert_b does not chain to the recipient's ancestry",
        ));
    }
    let b_target =
        compute_receipt_b_canonical_target(&commitment, &commitment, &b_parent_tip, &b_child_tip);
    let sig_b_ok = sphincs_verify(&countersign.ek_pk_b, &b_target, &countersign.sig_b)
        .map_err(|e| malformed("sig_b verify", e))?;
    if !sig_b_ok {
        return Err(invalid("sig_b does not verify — no acceptance"));
    }

    Ok(VerifiedAcceptance {
        commitment,
        sender_parent_tip: receipt.parent_tip,
        sender_child_tip: receipt.child_tip,
        b_parent_tip,
        b_child_tip,
    })
}
