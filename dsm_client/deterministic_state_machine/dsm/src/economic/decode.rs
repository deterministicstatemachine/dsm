// SPDX-License-Identifier: Apache-2.0

//! Strict decoders for everything a `0x001D` witness transitively contains.
//!
//! CCB is not self-describing: structure comes from `(class, schema)` plus the
//! registry, never from the byte stream. These decoders accept exactly schema
//! 1 of exactly the classes named, and rebuild each object through the **same
//! validating constructors the encoder uses** — so a decoded object cannot
//! represent anything an encoder would have refused. Without that, a decoder
//! becomes a second, laxer definition of the protocol.
//!
//! **Trailing bytes are refused.** A payload that decodes and then continues
//! is not a witness with a suffix; it is not a witness.
//!
//! Scope is the witness closure: `0x001D`, `0x001E`, the leaf states
//! `0x001F`–`0x0022`, and the credit sources `0x0023`–`0x0028`. The claim and
//! manifest (`0x001B` / `0x001C`) are the register and admission layer and
//! decode with that work, not here.

use crate::ccb::decode::{invalid, Cursor, DecodeError};
use crate::ccb::{class, CcbObject};
use crate::economic::credit::{
    CreditSource, CreditSourceAuthorizedIssuance, CreditSourceDlvReserveConsumption,
    CreditSourceSameTransitionMove, CreditSourceValidatedDlvSettlementPayment,
    CreditSourceValidatedFaucetDistribution, CreditSourceValidatedPeerDebit,
    CreditSourceVerifiedOfflineReentry,
};
use crate::economic::mutation::EconomicLeafMutation;
use crate::economic::state::{
    EconomicBalanceState, EconomicConsumedSourceState, EconomicLeafState,
    EconomicSettlementReceiptState, EconomicVaultReserveState,
};
use crate::economic::tree::ECONOMIC_SMT_HEIGHT;
use crate::economic::claim::{AdmissionSubstrate, EconomicAdmissionManifest};
use crate::economic::witness::EconomicTransitionWitness;

/// Decode an `EconomicTransitionWitness` — class `0x001D`, schema 1, strict.
pub fn decode_transition_witness(bytes: &[u8]) -> Result<EconomicTransitionWitness, DecodeError> {
    let mut c = Cursor { b: bytes, i: 0 };
    let w = read_witness(&mut c)?;
    if c.i != bytes.len() {
        return Err(DecodeError::TrailingBytes {
            extra: bytes.len() - c.i,
        });
    }
    Ok(w)
}

/// Decode a standalone `EconomicLeafMutation` — class `0x001E`, schema 1.
pub fn decode_leaf_mutation(bytes: &[u8]) -> Result<EconomicLeafMutation, DecodeError> {
    let mut c = Cursor { b: bytes, i: 0 };
    let m = read_mutation(&mut c)?;
    if c.i != bytes.len() {
        return Err(DecodeError::TrailingBytes {
            extra: bytes.len() - c.i,
        });
    }
    Ok(m)
}

/// Decode a standalone `CreditSource` — one of classes `0x0023`–`0x0028`.
pub fn decode_credit_source(bytes: &[u8]) -> Result<CreditSource, DecodeError> {
    let mut c = Cursor { b: bytes, i: 0 };
    let s = read_credit_source(&mut c)?;
    if c.i != bytes.len() {
        return Err(DecodeError::TrailingBytes {
            extra: bytes.len() - c.i,
        });
    }
    Ok(s)
}

/// Decode an `EconomicAdmissionManifest` — class `0x001C`, schema 1, strict.
///
/// Canonicality is part of validity: the provenance index must arrive sorted
/// strictly ascending (the encoder's order), and exactly one substrate slot
/// must be present. Rebuilding through `new` would silently CANONICALIZE
/// unsorted bytes — a decoder must refuse them instead, or two byte strings
/// would decode to one object and the address would stop being exact.
pub fn decode_admission_manifest(bytes: &[u8]) -> Result<EconomicAdmissionManifest, DecodeError> {
    let mut c = Cursor { b: bytes, i: 0 };
    c.envelope(
        EconomicAdmissionManifest::CLASS,
        EconomicAdmissionManifest::SCHEMA,
    )?;
    let authority_position = c.digest32()?;
    let transition_witness_addr = c.digest32()?;
    let authority_evidence_addr = c.digest32()?;
    let dsm_marker = c.u8()?;
    let substrate = match dsm_marker {
        0x01 => {
            let evidence_addr = c.digest32()?;
            match c.u8()? {
                0x00 => AdmissionSubstrate::DsmSuccessor { evidence_addr },
                0x01 => {
                    return Err(DecodeError::Invalid(
                        "manifest: both substrate slots present — exactly one substrate"
                            .to_string(),
                    ))
                }
                other => {
                    return Err(DecodeError::Invalid(format!(
                        "manifest: substrate marker must be 0x00 or 0x01, got {other:#04x}"
                    )))
                }
            }
        }
        0x00 => match c.u8()? {
            0x01 => AdmissionSubstrate::OfflineBoundary {
                evidence_addr: c.digest32()?,
            },
            0x00 => {
                return Err(DecodeError::Invalid(
                    "manifest: no substrate slot present — exactly one substrate".to_string(),
                ))
            }
            other => {
                return Err(DecodeError::Invalid(format!(
                    "manifest: substrate marker must be 0x00 or 0x01, got {other:#04x}"
                )))
            }
        },
        other => {
            return Err(DecodeError::Invalid(format!(
                "manifest: substrate marker must be 0x00 or 0x01, got {other:#04x}"
            )))
        }
    };
    let count = c.u32()? as usize;
    let mut addrs: Vec<[u8; 32]> = Vec::with_capacity(count.min(1024));
    for _ in 0..count {
        let addr = c.digest32()?;
        if let Some(last) = addrs.last() {
            if *last >= addr {
                return Err(DecodeError::Invalid(
                    "manifest: provenance index must be sorted strictly ascending — \
                     non-canonical bytes are refused, never canonicalized"
                        .to_string(),
                ));
            }
        }
        addrs.push(addr);
    }
    if c.i != bytes.len() {
        return Err(DecodeError::TrailingBytes {
            extra: bytes.len() - c.i,
        });
    }
    EconomicAdmissionManifest::new(
        authority_position,
        transition_witness_addr,
        authority_evidence_addr,
        substrate,
        addrs,
    )
    .map_err(invalid)
}

/// Decode a standalone `EconomicLeafState` — one of classes `0x001F`–`0x0022`.
pub fn decode_leaf_state(bytes: &[u8]) -> Result<EconomicLeafState, DecodeError> {
    let mut c = Cursor { b: bytes, i: 0 };
    let s = read_leaf_state(&mut c)?;
    if c.i != bytes.len() {
        return Err(DecodeError::TrailingBytes {
            extra: bytes.len() - c.i,
        });
    }
    Ok(s)
}

fn read_witness(c: &mut Cursor<'_>) -> Result<EconomicTransitionWitness, DecodeError> {
    c.envelope(
        EconomicTransitionWitness::CLASS,
        EconomicTransitionWitness::SCHEMA,
    )?;
    let pre_economic_root = c.digest32()?;
    let post_economic_root = c.digest32()?;
    let economic_operation_id = c.digest32()?;
    let operation_digest = c.digest32()?;

    let mutation_count = c.u32()? as usize;
    let mut mutations = Vec::with_capacity(mutation_count.min(1024));
    for _ in 0..mutation_count {
        mutations.push(read_mutation(c)?);
    }

    let source_count = c.u32()? as usize;
    let mut credit_sources = Vec::with_capacity(source_count.min(1024));
    for _ in 0..source_count {
        credit_sources.push(read_credit_source(c)?);
    }

    // Through the validating constructor: the ordering and bijection rules
    // apply to decoded bytes exactly as they apply to constructed objects.
    EconomicTransitionWitness::new(
        pre_economic_root,
        post_economic_root,
        economic_operation_id,
        operation_digest,
        mutations,
        credit_sources,
    )
    .map_err(invalid)
}

fn read_mutation(c: &mut Cursor<'_>) -> Result<EconomicLeafMutation, DecodeError> {
    c.envelope(EconomicLeafMutation::CLASS, EconomicLeafMutation::SCHEMA)?;
    let pre_state = read_optional_leaf_state(c)?;
    let post_state = read_optional_leaf_state(c)?;
    let mut siblings = Vec::with_capacity(ECONOMIC_SMT_HEIGHT);
    for _ in 0..ECONOMIC_SMT_HEIGHT {
        siblings.push(c.digest32()?);
    }
    EconomicLeafMutation::new(pre_state, post_state, siblings).map_err(invalid)
}

fn read_optional_leaf_state(c: &mut Cursor<'_>) -> Result<Option<EconomicLeafState>, DecodeError> {
    match c.u8()? {
        0x00 => Ok(None),
        0x01 => Ok(Some(read_leaf_state(c)?)),
        other => Err(DecodeError::Invalid(format!(
            "optional marker must be 0x00 or 0x01, got {other:#04x}"
        ))),
    }
}

fn read_leaf_state(c: &mut Cursor<'_>) -> Result<EconomicLeafState, DecodeError> {
    // The envelope IS the discriminant — there is no separate tag byte, which
    // is exactly why every conformant object carries one.
    match c.peek_class()? {
        class::ECONOMIC_BALANCE_STATE => {
            c.envelope(EconomicBalanceState::CLASS, EconomicBalanceState::SCHEMA)?;
            let policy_commit = c.digest32()?;
            let amount = c.u64()?;
            // Rebuilt through `new`, so a zero-amount balance decodes to an
            // error rather than to a leaf the encoder could never emit.
            Ok(EconomicLeafState::Balance(
                EconomicBalanceState::new(policy_commit, amount).map_err(invalid)?,
            ))
        }
        class::ECONOMIC_VAULT_RESERVE_STATE => {
            c.envelope(
                EconomicVaultReserveState::CLASS,
                EconomicVaultReserveState::SCHEMA,
            )?;
            Ok(EconomicLeafState::VaultReserve(EconomicVaultReserveState {
                vault_id: c.digest32()?,
                policy_commit: c.digest32()?,
                amount: c.u64()?,
                vault_sequence: c.u64()?,
            }))
        }
        class::ECONOMIC_SETTLEMENT_RECEIPT_STATE => {
            c.envelope(
                EconomicSettlementReceiptState::CLASS,
                EconomicSettlementReceiptState::SCHEMA,
            )?;
            let vault_id = c.digest32()?;
            let carried_receipt_id = c.digest32()?;
            let x = c.digest32()?;
            let parent_sequence = c.u64()?;
            let new_sequence = c.u64()?;
            let input_policy_commit = c.digest32()?;
            let input_amount = c.u64()?;
            let output_policy_commit = c.digest32()?;
            let output_amount = c.u64()?;
            let state = EconomicSettlementReceiptState::new(
                vault_id,
                x,
                parent_sequence,
                new_sequence,
                input_policy_commit,
                input_amount,
                output_policy_commit,
                output_amount,
            )
            .map_err(invalid)?;
            // `receipt_id` is DERIVED from (vault_id, x). The constructor
            // recomputed it; if the bytes carried a different one, the object
            // was naming something its own contents do not produce.
            if state.receipt_id != carried_receipt_id {
                return Err(DecodeError::Invalid(
                    "settlement receipt: carried receipt_id does not derive from \
                     (vault_id, x) — a derived name must not be assertable"
                        .to_string(),
                ));
            }
            Ok(EconomicLeafState::SettlementReceipt(state))
        }
        class::ECONOMIC_CONSUMED_SOURCE_STATE => {
            c.envelope(
                EconomicConsumedSourceState::CLASS,
                EconomicConsumedSourceState::SCHEMA,
            )?;
            Ok(EconomicLeafState::ConsumedSource(
                EconomicConsumedSourceState {
                    source_id: c.digest32()?,
                    consumer_economic_operation_id: c.digest32()?,
                },
            ))
        }
        got => Err(DecodeError::WrongClass { got }),
    }
}

fn read_credit_source(c: &mut Cursor<'_>) -> Result<CreditSource, DecodeError> {
    match c.peek_class()? {
        class::CREDIT_SOURCE_AUTHORIZED_ISSUANCE => {
            c.envelope(
                CreditSourceAuthorizedIssuance::CLASS,
                CreditSourceAuthorizedIssuance::SCHEMA,
            )?;
            Ok(CreditSource::AuthorizedIssuance(
                CreditSourceAuthorizedIssuance {
                    credit_mutation_index: c.u32()?,
                    issuance_authorization_addr: c.digest32()?,
                },
            ))
        }
        class::CREDIT_SOURCE_SAME_TRANSITION_MOVE => {
            c.envelope(
                CreditSourceSameTransitionMove::CLASS,
                CreditSourceSameTransitionMove::SCHEMA,
            )?;
            let credit_mutation_index = c.u32()?;
            let debit_mutation_index = c.u32()?;
            if credit_mutation_index == debit_mutation_index {
                return Err(DecodeError::Invalid(format!(
                    "same-transition move: mutation {credit_mutation_index} cannot fund itself"
                )));
            }
            Ok(CreditSource::SameTransitionMove(
                CreditSourceSameTransitionMove {
                    credit_mutation_index,
                    debit_mutation_index,
                },
            ))
        }
        class::CREDIT_SOURCE_VALIDATED_PEER_DEBIT => {
            c.envelope(
                CreditSourceValidatedPeerDebit::CLASS,
                CreditSourceValidatedPeerDebit::SCHEMA,
            )?;
            Ok(CreditSource::ValidatedPeerDebit(
                CreditSourceValidatedPeerDebit {
                    credit_mutation_index: c.u32()?,
                    peer_genesis: c.digest32()?,
                    peer_devid: c.digest32()?,
                    peer_economic_position: c.u64()?,
                    peer_debit_mutation_index: c.u32()?,
                    acceptance_evidence_addr: c.digest32()?,
                },
            ))
        }
        class::CREDIT_SOURCE_DLV_RESERVE_CONSUMPTION => {
            c.envelope(
                CreditSourceDlvReserveConsumption::CLASS,
                CreditSourceDlvReserveConsumption::SCHEMA,
            )?;
            Ok(CreditSource::DlvReserveConsumption(
                CreditSourceDlvReserveConsumption {
                    credit_mutation_index: c.u32()?,
                    vault_id: c.digest32()?,
                    parent_sequence: c.u64()?,
                    x: c.digest32()?,
                    owner_economic_position: c.u64()?,
                    reserve_consumption_evidence_addr: c.digest32()?,
                },
            ))
        }
        class::CREDIT_SOURCE_VALIDATED_DLV_SETTLEMENT_PAYMENT => {
            c.envelope(
                CreditSourceValidatedDlvSettlementPayment::CLASS,
                CreditSourceValidatedDlvSettlementPayment::SCHEMA,
            )?;
            Ok(CreditSource::ValidatedDlvSettlementPayment(
                CreditSourceValidatedDlvSettlementPayment {
                    credit_mutation_index: c.u32()?,
                    vault_id: c.digest32()?,
                    settlement_receipt_id: c.digest32()?,
                    parent_sequence: c.u64()?,
                    trader_genesis: c.digest32()?,
                    trader_devid: c.digest32()?,
                    trader_economic_position: c.u64()?,
                    payment_evidence_addr: c.digest32()?,
                },
            ))
        }
        class::CREDIT_SOURCE_VALIDATED_FAUCET_DISTRIBUTION => {
            c.envelope(
                CreditSourceValidatedFaucetDistribution::CLASS,
                CreditSourceValidatedFaucetDistribution::SCHEMA,
            )?;
            Ok(CreditSource::ValidatedFaucetDistribution(
                CreditSourceValidatedFaucetDistribution {
                    credit_mutation_index: c.u32()?,
                    faucet_id: c.digest32()?,
                    ticket_index: c.u64()?,
                    faucet_claim_evidence_addr: c.digest32()?,
                },
            ))
        }
        class::CREDIT_SOURCE_VERIFIED_OFFLINE_REENTRY => {
            c.envelope(
                CreditSourceVerifiedOfflineReentry::CLASS,
                CreditSourceVerifiedOfflineReentry::SCHEMA,
            )?;
            let credit_mutation_index = c.u32()?;
            let prior_boundary_id = c.digest32()?;
            let unload_boundary_id = c.digest32()?;
            if prior_boundary_id == unload_boundary_id {
                return Err(DecodeError::Invalid(
                    "offline reentry: prior_boundary_id equals unload_boundary_id — the \
                     consumed checkpoint must be the predecessor"
                        .to_string(),
                ));
            }
            Ok(CreditSource::VerifiedOfflineReentry(
                CreditSourceVerifiedOfflineReentry {
                    credit_mutation_index,
                    prior_boundary_id,
                    unload_boundary_id,
                    branch_evidence_addr: c.digest32()?,
                },
            ))
        }
        got => Err(DecodeError::WrongClass { got }),
    }
}
