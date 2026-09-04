// SPDX-License-Identifier: Apache-2.0

//! The 0x0026 evidence bundle: strict decode of `ReserveConsumptionEvidenceV1`
//! (transport proto, no CCB class — the faucet-claim/settlement-slot
//! precedent).
//!
//! The bundle carries the material only the OWNER's side can supply, and it
//! carries no proof of its own. Two of the three fields are exact bytes the
//! arm re-hashes; the third NAMES the owner's generic
//! `EconomicProofArtifactV1`, which the arm fetches and verifies against the
//! owner, economic position and validated root it derived for itself.
//!
//! The reserve leaves and their 256-sibling paths used to live here. Carrying
//! them was a second representation of a fact the artifact already proves, and
//! two representations of one fact can disagree; the bundle now points at the
//! one proof source both directions of a settlement share.

use crate::types::proto as generated;
use prost::Message;

/// A strictly decoded bundle. Nothing here is verified beyond shape — every
/// fact is re-checked by the 0x0026 arm against authenticated inputs.
#[derive(Debug, Clone)]
pub struct ReserveConsumptionEvidence {
    /// Exact `CCB(V_n)` bytes — must hash (vault-state domain) to the
    /// settle's `parent_binding`.
    pub exact_vault_state_ccb: Vec<u8>,
    /// `AuthorityEvidenceV1` bytes for the owner at the VAULT-BOUND
    /// authority position (`V_n.owner_authority_transition_digest`).
    pub owner_authority_evidence: Vec<u8>,
    /// Inner content identity of the owner's `EconomicProofArtifactV1`, which
    /// proves the vault's reserve leaves under the owner's registered root.
    pub economic_proof_addr: [u8; 32],
}

/// Strict decode: canonical re-encode equality, a 32-byte proof address.
pub fn decode_reserve_consumption_evidence(
    bytes: &[u8],
) -> Result<ReserveConsumptionEvidence, String> {
    if bytes.is_empty() {
        return Err("empty evidence bundle".into());
    }
    let ev = generated::ReserveConsumptionEvidenceV1::decode(bytes)
        .map_err(|_| "evidence bundle does not decode".to_string())?;
    if ev.encode_to_vec() != bytes {
        return Err("evidence bundle is not canonical".into());
    }
    let economic_proof_addr: [u8; 32] =
        ev.economic_proof_addr.as_slice().try_into().map_err(|_| {
            format!(
                "the economic proof address must be 32 bytes, got {}",
                ev.economic_proof_addr.len()
            )
        })?;
    Ok(ReserveConsumptionEvidence {
        exact_vault_state_ccb: ev.exact_vault_state_ccb.clone(),
        owner_authority_evidence: ev.owner_authority_evidence.clone(),
        economic_proof_addr,
    })
}
