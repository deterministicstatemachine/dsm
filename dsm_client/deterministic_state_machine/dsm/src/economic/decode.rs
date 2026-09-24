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
//! `0x001F`–`0x0022`, and the credit sources `0x0023`–`0x0028`, `0x0030` and `0x0035`. The claim and
//! manifest (`0x001B` / `0x001C`) are the register and admission layer and
//! decode with that work, not here.

use crate::ccb::decode::{invalid, Cursor, DecodeError};
use crate::ccb::{class, CcbObject};
use crate::economic::credit::{
    CreditSource, CreditSourceGenesisRelease, CreditSourceNativeReserveRelease,
    CreditSourceValidatedPeerDebit,
};
use crate::economic::mutation::EconomicLeafMutation;
use crate::economic::state::{
    EconomicBalanceState, EconomicConsumedSourceState, EconomicLeafState,
    EconomicTokenCreationState,
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

/// Decode a standalone `CreditSource` — one of classes `0x0023`–`0x0028`,
/// `0x0030` and `0x0035`.
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
        // The SoFi relationship leaf (P15-6). The class is keyed here because
        // a class-keyed decoder does NOT get an exhaustiveness error when a
        // new enum arm appears — the compiler forced every `match` on the enum
        // and said nothing about this one, which is precisely how a variant
        // ends up encodable and undecodable.
        class::SOFI_TRADER_RELATIONSHIP_LEAF => Ok(EconomicLeafState::Relationship(
            crate::sofi::wire::TraderRelationshipLeaf::at(c)?,
        )),
        class::SOFI_VAULT_CREATION => Ok(EconomicLeafState::VaultCreation(
            crate::sofi::wire::VaultCreation::at(c)?,
        )),
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
        class::ECONOMIC_TOKEN_CREATION_STATE => {
            c.envelope(
                EconomicTokenCreationState::CLASS,
                EconomicTokenCreationState::SCHEMA,
            )?;
            Ok(EconomicLeafState::TokenCreation(
                EconomicTokenCreationState {
                    policy_commit: c.digest32()?,
                },
            ))
        }
        got => Err(DecodeError::WrongClass { got }),
    }
}

fn read_credit_source(c: &mut Cursor<'_>) -> Result<CreditSource, DecodeError> {
    match c.peek_class()? {
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
        class::CREDIT_SOURCE_NATIVE_RESERVE_RELEASE => {
            c.envelope(
                CreditSourceNativeReserveRelease::CLASS,
                CreditSourceNativeReserveRelease::SCHEMA,
            )?;
            Ok(CreditSource::NativeReserveRelease(
                CreditSourceNativeReserveRelease {
                    credit_mutation_index: c.u32()?,
                    reserve_id: c.digest32()?,
                    generation: c.u64()?,
                    release_evidence_addr: c.digest32()?,
                },
            ))
        }
        class::CREDIT_SOURCE_GENESIS_RELEASE => {
            c.envelope(
                CreditSourceGenesisRelease::CLASS,
                CreditSourceGenesisRelease::SCHEMA,
            )?;
            Ok(CreditSource::GenesisRelease(CreditSourceGenesisRelease {
                credit_mutation_index: c.u32()?,
            }))
        }
        got => Err(DecodeError::WrongClass { got }),
    }
}
