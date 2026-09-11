// SPDX-License-Identifier: Apache-2.0

//! THE OWNER'S SIDE OF 0x0027 (amendment 2c-G).
//!
//! An owner applying a settlement a trader already realized must hand the
//! economic verifier a `SettlementPaymentEvidenceV1`: the trader's `0x0021`
//! settlement-receipt leaf and its 256-sibling inclusion path. The
//! `ValidatedDlvSettlementPayment` arm proves that leaf into the trader's
//! validated economic root at the descriptor's position and cross-checks it
//! field by field against the apply. Nothing produced it, so no owner apply
//! could be admitted.
//!
//! Nothing here is fetched. The composition walk already proved exactly this
//! leaf under exactly that root when it certified the fold (Req 21.16), and
//! carried both on the fold ([`CertifiedPayment`]). This module re-encodes
//! that material — which is why a catch-up consumes certified history and
//! creates none: the evidence is a projection of the certification, never a
//! second observation.
//!
//! Nothing here proves anything either. The two checks below MIRROR the arm,
//! so a defect upstream is refused before the owner signs and advances. They
//! matter more than a courtesy: the arm runs inside `finish_admission`, after
//! the advance has committed, so evidence it refuses would leave an advance
//! whose admission can never finish. The arm is still what decides.

use dsm::types::error::DsmError;
use prost::Message;

use crate::sdk::vault_state_composition::CertifiedPayment;

/// The `SettlementPaymentEvidenceV1` bytes for applying `realized`, built
/// from the payment the walk certified with it.
pub(crate) fn build_settlement_payment_evidence(
    realized: &dsm::dlv::published_receipt::VerifiedReceipt,
    payment: &CertifiedPayment,
) -> Result<Vec<u8>, DsmError> {
    let trade = realized.trade();
    let leaf = &payment.receipt;
    // The arm's step 4, stated: the leaf names exactly this settlement.
    if leaf.vault_id != realized.vault_id()
        || leaf.receipt_id != realized.receipt_id()
        || leaf.x != trade.x
        || leaf.parent_sequence != trade.parent_sequence
        || leaf.new_sequence != trade.new_sequence
        || leaf.input_policy_commit != trade.input_policy_commit
        || leaf.input_amount != trade.input_amount
        || leaf.output_policy_commit != trade.output_policy_commit
        || leaf.output_amount != trade.output_amount
    {
        return Err(DsmError::invalid_operation(
            "0x0027 evidence: the certified receipt leaf does not state this settlement",
        ));
    }
    // The arm's inclusion check, stated: at the trader's own key, the leaf
    // proves into the root certification validated for that trader.
    let state = dsm::economic::state::EconomicLeafState::SettlementReceipt(leaf.clone());
    let key = state.leaf_key(&payment.trader_genesis, &payment.trader_devid);
    let value = state.leaf_value().map_err(|e| {
        DsmError::invalid_operation(format!(
            "0x0027 evidence: the receipt leaf does not commit: {e}"
        ))
    })?;
    let folded = dsm::economic::tree::root_from_path(
        &key,
        &dsm::economic::tree::leaf_node(&key, Some(&value)),
        &payment.receipt_siblings,
    );
    if folded != realized.economic_root() {
        return Err(DsmError::invalid_operation(
            "0x0027 evidence: the receipt leaf does not prove into the root certification \
             validated",
        ));
    }
    let receipt_state = state.encode().map_err(|e| {
        DsmError::invalid_operation(format!(
            "0x0027 evidence: the receipt leaf does not encode: {e}"
        ))
    })?;
    let bytes = dsm::types::proto::SettlementPaymentEvidenceV1 {
        receipt_state,
        receipt_siblings: payment
            .receipt_siblings
            .iter()
            .map(|s| s.to_vec())
            .collect(),
    }
    .encode_to_vec();
    // And through the arm's own strict decoder, so a bundle it would refuse
    // as a shape never reaches an advance.
    dsm::economic::settlement_payment_evidence::decode_settlement_payment_evidence(&bytes)
        .map_err(|e| {
            DsmError::invalid_operation(format!("0x0027 evidence does not decode strictly: {e}"))
        })?;
    Ok(bytes)
}
