// SPDX-License-Identifier: Apache-2.0

//! THE TRADER'S SIDE OF 0x0026.
//!
//! A trader settling against someone else's vault must hand the economic
//! verifier a `ReserveConsumptionEvidenceV1`: the exact `CCB(V_n)` the settle
//! consumes, the owner's vault-bound authority evidence, and the address of
//! the owner's `EconomicProofArtifactV1` proving that vault's reserve leaves.
//! Until now none of it could be produced — the paths lived only in the
//! owner's tree, and nothing mapped a vault to the owner's economic position.
//!
//! All three come from material the trader already authenticated:
//!
//! - `CCB(V_n)` re-encodes the composed state, whose commitment IS the
//!   `parent_binding` the settle names.
//! - the authority evidence is the six values the composition's anchor
//!   presentation already resolved, at the same position, through the same
//!   resolver — not a second format and not a second authentication.
//! - the proof address is the advertisement's locator, which this module
//!   never trusts: it is copied into the bundle, and the VERIFIER fetches it,
//!   re-hashes it and checks the artifact against the owner, position and
//!   root the verifier itself derived.
//!
//! Nothing here proves anything. This builds the bundle; the 0x0026 arm is
//! what decides whether it funds a credit.

use dsm::types::error::DsmError;
use prost::Message;

/// The bundle bytes and the inner content address they must be published and
/// referenced under — the same address form every object in the evidence DAG
/// uses, and the one the 0x0026 arm re-derives.
pub(crate) struct ReserveConsumptionBundle {
    pub bytes: Vec<u8>,
    pub addr: [u8; 32],
}

/// Build the 0x0026 bundle for a settle against `composed`, naming the
/// owner's proof artifact at `economic_proof_addr`.
///
/// `composed` must be the composition of the exact generation the settle
/// consumes: its `c_n` is what the settle's `parent_binding` names, and the
/// arm re-hashes these bytes to it. A composition of any other generation
/// produces a bundle the arm refuses, which is the intended outcome rather
/// than something this function should paper over.
pub(crate) fn build_reserve_consumption_bundle(
    composed: &crate::sdk::vault_state_composition::ComposedVaultState,
    economic_proof_addr: &[u8; 32],
) -> Result<ReserveConsumptionBundle, DsmError> {
    if composed.owner_authority_evidence.is_empty() {
        return Err(DsmError::invalid_operation(
            "0x0026 bundle: the composed vault carries no owner authority evidence",
        ));
    }
    let exact_vault_state_ccb = composed.state.encode().map_err(|e| {
        DsmError::invalid_operation(format!(
            "0x0026 bundle: the vault state does not encode: {e}"
        ))
    })?;
    // Stated, not assumed: the bytes the arm will hash to `parent_binding`
    // are the bytes of the state whose commitment the composition reached.
    let recomputed = dsm::crypto::blake3::domain_hash_bytes(
        dsm::common::domain_tags::TAG_DSM_VAULT_STATE,
        &exact_vault_state_ccb,
    );
    if recomputed != composed.c_n {
        return Err(DsmError::invalid_operation(
            "0x0026 bundle: the re-encoded vault state does not hash to the composed c_n",
        ));
    }
    let bundle = dsm::types::proto::ReserveConsumptionEvidenceV1 {
        exact_vault_state_ccb,
        owner_authority_evidence: composed.owner_authority_evidence.clone(),
        economic_proof_addr: economic_proof_addr.to_vec(),
    };
    let bytes = bundle.encode_to_vec();
    let addr = dsm::storage_object::immutable_inner(
        dsm::common::domain_tags::TAG_DSM_DLV_RESERVE_CONSUMPTION_EVIDENCE,
        &bytes,
    );
    Ok(ReserveConsumptionBundle { bytes, addr })
}

/// The frozen-artifact tuple for publishing the bundle alongside an
/// admission's own evidence, keyed the way every immutable object is.
pub(crate) fn publishable(bundle: &ReserveConsumptionBundle) -> (String, Vec<u8>, &'static str) {
    (
        crate::sdk::economic_registers::immutable_object_key(
            dsm::common::domain_tags::TAG_DSM_DLV_RESERVE_CONSUMPTION_EVIDENCE,
            &bundle.bytes,
        ),
        bundle.bytes.clone(),
        "dlv-reserve-consumption-evidence",
    )
}
