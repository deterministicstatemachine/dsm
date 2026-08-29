// SPDX-License-Identifier: Apache-2.0

//! The 0x0026 evidence bundle: strict decode of `ReserveConsumptionEvidenceV1`
//! (transport proto, no CCB class — the faucet-claim/settlement-slot
//! precedent). The bundle carries INCLUSION MATERIAL, not conclusions: the
//! verifier re-hashes `CCB(V_n)` against the settle's `parent_binding`,
//! replays the owner's vault-bound authority evidence, and proves both
//! reserve pre-leaves against the independently derived
//! `ValidatedEconomicRoot(owner_economic_position)`.

use crate::economic::state::{EconomicLeafState, EconomicVaultReserveState};
use crate::economic::tree::ECONOMIC_SMT_HEIGHT;
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
    pub reserve_a: EconomicVaultReserveState,
    pub reserve_a_siblings: Box<[[u8; 32]; ECONOMIC_SMT_HEIGHT]>,
    pub reserve_b: EconomicVaultReserveState,
    pub reserve_b_siblings: Box<[[u8; 32]; ECONOMIC_SMT_HEIGHT]>,
}

/// Strict decode: canonical re-encode equality, exactly 256 fixed 32-byte
/// siblings per leg, both leaf states decode as vault reserves.
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
    let siblings =
        |v: &[Vec<u8>], leg: &str| -> Result<Box<[[u8; 32]; ECONOMIC_SMT_HEIGHT]>, String> {
            if v.len() != ECONOMIC_SMT_HEIGHT {
                return Err(format!(
                "reserve {leg} witness must carry exactly {ECONOMIC_SMT_HEIGHT} siblings, got {}",
                v.len()
            ));
            }
            let mut out = Box::new([[0u8; 32]; ECONOMIC_SMT_HEIGHT]);
            for (i, s) in v.iter().enumerate() {
                out[i] = s
                    .as_slice()
                    .try_into()
                    .map_err(|_| format!("reserve {leg} sibling {i} is not 32 bytes"))?;
            }
            Ok(out)
        };
    let reserve = |bytes: &[u8], leg: &str| -> Result<EconomicVaultReserveState, String> {
        match crate::economic::decode::decode_leaf_state(bytes) {
            Ok(EconomicLeafState::VaultReserve(r)) => Ok(r),
            Ok(_) => Err(format!("reserve {leg} state is not a vault-reserve leaf")),
            Err(e) => Err(format!("reserve {leg} state: {e}")),
        }
    };
    Ok(ReserveConsumptionEvidence {
        exact_vault_state_ccb: ev.exact_vault_state_ccb.clone(),
        owner_authority_evidence: ev.owner_authority_evidence.clone(),
        reserve_a: reserve(&ev.reserve_a_state, "a")?,
        reserve_a_siblings: siblings(&ev.reserve_a_siblings, "a")?,
        reserve_b: reserve(&ev.reserve_b_state, "b")?,
        reserve_b_siblings: siblings(&ev.reserve_b_siblings, "b")?,
    })
}
