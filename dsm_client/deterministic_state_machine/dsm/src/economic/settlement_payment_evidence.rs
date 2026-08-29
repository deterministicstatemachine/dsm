// SPDX-License-Identifier: Apache-2.0

//! The 0x0027 evidence bundle: strict decode of `SettlementPaymentEvidenceV1`
//! (transport proto, no CCB class). The bundle carries the trader's
//! settlement-receipt leaf and its inclusion witness; the verifier proves the
//! leaf into the INDEPENDENTLY derived
//! `ValidatedEconomicRoot(trader_economic_position)` — the bundle asserts
//! nothing on its own.

use crate::economic::state::{EconomicLeafState, EconomicSettlementReceiptState};
use crate::economic::tree::ECONOMIC_SMT_HEIGHT;
use crate::types::proto as generated;
use prost::Message;

/// A strictly decoded bundle. Shape only — every fact is re-checked by the
/// 0x0027 arm against authenticated inputs.
#[derive(Debug, Clone)]
pub struct SettlementPaymentEvidence {
    pub receipt: EconomicSettlementReceiptState,
    pub receipt_siblings: Box<[[u8; 32]; ECONOMIC_SMT_HEIGHT]>,
}

/// Strict decode: canonical re-encode equality, exactly 256 fixed 32-byte
/// siblings, the leaf state decodes as a settlement receipt.
pub fn decode_settlement_payment_evidence(
    bytes: &[u8],
) -> Result<SettlementPaymentEvidence, String> {
    if bytes.is_empty() {
        return Err("empty evidence bundle".into());
    }
    let ev = generated::SettlementPaymentEvidenceV1::decode(bytes)
        .map_err(|_| "evidence bundle does not decode".to_string())?;
    if ev.encode_to_vec() != bytes {
        return Err("evidence bundle is not canonical".into());
    }
    if ev.receipt_siblings.len() != ECONOMIC_SMT_HEIGHT {
        return Err(format!(
            "receipt witness must carry exactly {ECONOMIC_SMT_HEIGHT} siblings, got {}",
            ev.receipt_siblings.len()
        ));
    }
    let mut siblings = Box::new([[0u8; 32]; ECONOMIC_SMT_HEIGHT]);
    for (i, s) in ev.receipt_siblings.iter().enumerate() {
        siblings[i] = s
            .as_slice()
            .try_into()
            .map_err(|_| format!("receipt sibling {i} is not 32 bytes"))?;
    }
    let receipt = match crate::economic::decode::decode_leaf_state(&ev.receipt_state) {
        Ok(EconomicLeafState::SettlementReceipt(r)) => r,
        Ok(_) => return Err("receipt state is not a settlement-receipt leaf".into()),
        Err(e) => return Err(format!("receipt state: {e}")),
    };
    Ok(SettlementPaymentEvidence {
        receipt,
        receipt_siblings: siblings,
    })
}
