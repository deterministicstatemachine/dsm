// SPDX-License-Identifier: Apache-2.0

//! Credit provenance — **why** a credit may appear.
//!
//! A closed write set proves *what changed*. It says nothing about whether the
//! units were the trader's to credit, and every mutation in a self-crediting
//! write set is individually well-formed. This module is the conjunctive
//! obligation that closes that gap.
//!
//! ```text
//! DEBIT:  prove the old value exists + authorization + exact subtraction
//! CREDIT: prove exact addition + PROVE A CANONICAL SOURCE OF THOSE UNITS
//! ```
//!
//! ## Acyclicity is structural, not documented
//!
//! An external source must resolve from an **already-validated** economic
//! root, and must never depend on validating the transition it is funding.
//! That is enforced by the type system rather than by review: a resolver
//! returns [`ValidatedPeerTransition`], which *contains* a
//! [`ValidatedEconomicRoot`] — and that type has a private field with no
//! constructor except `activate` and `advance_validated`. A resolver therefore
//! **cannot fabricate** a peer root it has not actually validated.
//!
//! Pairing a genuine validated root with an unrelated witness is refused
//! separately: the witness's post-root must equal the validated root.
//!
//! [`CreditSource::SameTransitionMove`] is the deliberate exception. It is
//! intra-transition by definition, verified atomically against the witness
//! that carries it, and reaches nothing outside.
//!
//! ## Every `SourceId` is derived
//!
//! A caller never supplies one. Each is a hash over authenticated coordinates,
//! so a producer cannot name a source it has not established, and the same
//! underlying debit yields the same id however often it is presented — which
//! is what makes "no source funds two credits" checkable.
//!
//! ## Amount and asset must match the credit
//!
//! Establishing that *a* source exists is not enough. The source must fund
//! **this** credit: same asset, same amount. A source for 5 units cannot fund
//! a credit of 500, and a source for one asset cannot fund a credit of
//! another. This is where a plausible-looking provenance object stops being
//! sufficient.

use crate::common::domain_tags::{
    TAG_DSM_ECON_SOURCE_SAME_TRANSITION_MOVE, TAG_DSM_ECON_SOURCE_VALIDATED_PEER_DEBIT,
};
use crate::crypto::blake3::dsm_domain_hasher;
use crate::economic::credit::CreditSource;
use crate::economic::lineage::ValidatedEconomicRoot;
use crate::economic::mutation::EconomicLeafMutation;
use crate::economic::state::EconomicLeafState;
use crate::economic::witness::EconomicTransitionWitness;

/// What a verified source establishes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FundedCredit {
    /// Derived from authenticated facts, never supplied.
    pub source_id: [u8; 32],
    pub policy_commit: [u8; 32],
    pub amount: u64,
}

/// A peer transition this verifier has **already validated**.
///
/// Holding one is evidence: it contains a [`ValidatedEconomicRoot`], which
/// cannot be constructed except by validating. That is what makes the
/// acyclicity rule a type property rather than a convention.
#[derive(Debug, Clone)]
pub struct ValidatedPeerTransition {
    pub peer_genesis: [u8; 32],
    pub peer_devid: [u8; 32],
    pub validated_root: ValidatedEconomicRoot,
    pub witness: EconomicTransitionWitness,
}

/// Supplies the already-validated facts an external source resolves against.
///
/// Deliberately returns validated objects rather than raw bytes: a resolver
/// that could return "here is a peer root, trust me" would put the acyclicity
/// guarantee back in the hands of whoever wrote the resolver.
pub trait ProvenanceResolver {
    /// The peer's validated transition at the named position, if this verifier
    /// has one.
    fn validated_peer_transition(
        &self,
        peer_genesis: &[u8; 32],
        peer_devid: &[u8; 32],
        peer_economic_position: u64,
    ) -> Option<ValidatedPeerTransition>;
}

/// Why a credit is not funded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProvenanceError {
    /// No authenticated issuance predicate is defined for this protocol, so an
    /// `AuthorizedIssuance` source cannot be resolved by anyone.
    ///
    /// This is the same absence that makes the accepting layer refuse builtin
    /// ERA/dBTC issuance outright. Class `0x0029` stays reserved precisely
    /// because writing its field table would encode a predicate that does not
    /// exist, and a credit is not funded by an object nobody can check.
    IssuancePredicateUndefined,
    /// The verifier holds no validated transition for the named peer position.
    /// NOT a failure of the peer — a failure of *this* verifier to have
    /// established the prerequisite, and it fails closed.
    PeerTransitionNotValidated { peer_economic_position: u64 },
    /// The supplied peer transition's witness does not belong to the validated
    /// root it was handed with.
    PeerWitnessDoesNotMatchValidatedRoot,
    /// The named peer mutation is not a debit of anything.
    PeerMutationIsNotADebit { index: u32 },
    /// The source funds a different asset than the credit it claims to fund.
    AssetMismatch { source: [u8; 32], credit: [u8; 32] },
    /// The source funds a different amount than the credit it claims to fund.
    AmountMismatch { source: u64, credit: u64 },
    /// A mutation index outside the witness.
    IndexOutOfRange { index: u32 },
    /// The named mutation is not a positive credit, so nothing needs funding.
    NotACredit { index: u32 },
    /// Two sources derived the same `SourceId`. One underlying debit cannot
    /// fund two credits.
    DuplicateSourceId,
    /// A source that must be recorded as consumed has no consumed-source leaf
    /// written from ZERO in this same transition.
    SourceNotRecordedAsConsumed { source_id: [u8; 32] },
    /// The consumed-source leaf names a different consumer than this
    /// transition.
    ConsumedByAnotherOperation,
    /// The source is defined but its semantics land in a later cut.
    NotYetImplemented { class: u16 },
}

impl core::fmt::Display for ProvenanceError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::IssuancePredicateUndefined => write!(
                f,
                "credit provenance: no authenticated issuance predicate is defined, so an \
                 authorized-issuance credit cannot be funded by anyone — the same absence that \
                 makes the accepting layer refuse builtin issuance"
            ),
            Self::PeerTransitionNotValidated {
                peer_economic_position,
            } => write!(
                f,
                "credit provenance: this verifier has not validated the peer's transition at \
                 position {peer_economic_position} — fail closed; a credit is not funded by a \
                 debit nobody has checked"
            ),
            Self::PeerWitnessDoesNotMatchValidatedRoot => write!(
                f,
                "credit provenance: the peer witness does not produce the validated root it was \
                 supplied with — a genuine validated root paired with an unrelated witness"
            ),
            Self::PeerMutationIsNotADebit { index } => write!(
                f,
                "credit provenance: peer mutation {index} is not a debit, so it funds nothing"
            ),
            Self::AssetMismatch { .. } => write!(
                f,
                "credit provenance: the source funds a different asset than the credit claims"
            ),
            Self::AmountMismatch { source, credit } => write!(
                f,
                "credit provenance: the source funds {source} but the credit adds {credit}"
            ),
            Self::IndexOutOfRange { index } => {
                write!(
                    f,
                    "credit provenance: mutation {index} is outside the witness"
                )
            }
            Self::NotACredit { index } => write!(
                f,
                "credit provenance: mutation {index} is not a positive credit"
            ),
            Self::DuplicateSourceId => write!(
                f,
                "credit provenance: two sources derived the same SourceId — one underlying debit \
                 cannot fund two credits"
            ),
            Self::SourceNotRecordedAsConsumed { .. } => write!(
                f,
                "credit provenance: this source must be recorded as consumed, and no \
                 consumed-source leaf is written from ZERO in this transition — without it the \
                 same source funds a credit again in the next one"
            ),
            Self::ConsumedByAnotherOperation => write!(
                f,
                "credit provenance: the consumed-source leaf names a different consuming operation"
            ),
            Self::NotYetImplemented { class } => write!(
                f,
                "credit provenance: source class {class:#06x} has no acceptance semantics yet"
            ),
        }
    }
}

impl std::error::Error for ProvenanceError {}

/// `SourceId` for an intra-transition move.
pub fn same_transition_move_source_id(
    economic_operation_id: &[u8; 32],
    debit_mutation_index: u32,
) -> [u8; 32] {
    let mut h = dsm_domain_hasher(TAG_DSM_ECON_SOURCE_SAME_TRANSITION_MOVE);
    h.update(economic_operation_id);
    h.update(&debit_mutation_index.to_be_bytes());
    *h.finalize().as_bytes()
}

/// `SourceId` for a peer's validated debit.
pub fn validated_peer_debit_source_id(
    peer_genesis: &[u8; 32],
    peer_devid: &[u8; 32],
    peer_economic_position: u64,
    peer_debit_mutation_index: u32,
) -> [u8; 32] {
    let mut h = dsm_domain_hasher(TAG_DSM_ECON_SOURCE_VALIDATED_PEER_DEBIT);
    h.update(peer_genesis);
    h.update(peer_devid);
    h.update(&peer_economic_position.to_be_bytes());
    h.update(&peer_debit_mutation_index.to_be_bytes());
    *h.finalize().as_bytes()
}

/// The asset and quantity a mutation adds, if it adds any.
fn credit_delta(m: &EconomicLeafMutation) -> Option<([u8; 32], u64)> {
    if !m.is_positive_credit() {
        return None;
    }
    let post = m.post_state.as_ref()?;
    let asset = match post {
        EconomicLeafState::Balance(b) => b.policy_commit,
        EconomicLeafState::VaultReserve(r) => r.policy_commit,
        _ => return None,
    };
    let before = m
        .pre_state
        .as_ref()
        .and_then(EconomicLeafState::credit_amount)
        .unwrap_or(0);
    let after = post.credit_amount()?;
    Some((asset, after.saturating_sub(before)))
}

/// The asset and quantity a mutation removes, if it removes any.
fn debit_delta(m: &EconomicLeafMutation) -> Option<([u8; 32], u64)> {
    let before = m
        .pre_state
        .as_ref()
        .and_then(EconomicLeafState::credit_amount)
        .unwrap_or(0);
    let after = m
        .post_state
        .as_ref()
        .and_then(EconomicLeafState::credit_amount)
        .unwrap_or(0);
    if after >= before {
        return None;
    }
    let asset = match m.pre_state.as_ref()? {
        EconomicLeafState::Balance(b) => b.policy_commit,
        EconomicLeafState::VaultReserve(r) => r.policy_commit,
        _ => return None,
    };
    Some((asset, before - after))
}

/// Verify one credit source against the transition it appears in.
pub fn verify_credit_source(
    source: &CreditSource,
    witness: &EconomicTransitionWitness,
    resolver: &dyn ProvenanceResolver,
) -> Result<FundedCredit, ProvenanceError> {
    let credit_index = source.credit_mutation_index();
    let credit =
        witness
            .mutations
            .get(credit_index as usize)
            .ok_or(ProvenanceError::IndexOutOfRange {
                index: credit_index,
            })?;
    let (credit_asset, credit_amount) =
        credit_delta(credit).ok_or(ProvenanceError::NotACredit {
            index: credit_index,
        })?;

    let funded = match source {
        // No authenticated issuance predicate exists, so nobody can resolve
        // this. Refusing is the honest outcome; inventing one here would be
        // exactly the disguised backdoor the mint repair avoided.
        CreditSource::AuthorizedIssuance(_) => {
            return Err(ProvenanceError::IssuancePredicateUndefined)
        }

        // Intra-transition, and the ONLY arm that reaches nothing outside.
        CreditSource::SameTransitionMove(m) => {
            let debit = witness
                .mutations
                .get(m.debit_mutation_index as usize)
                .ok_or(ProvenanceError::IndexOutOfRange {
                    index: m.debit_mutation_index,
                })?;
            let (debit_asset, debit_amount) =
                debit_delta(debit).ok_or(ProvenanceError::PeerMutationIsNotADebit {
                    index: m.debit_mutation_index,
                })?;
            FundedCredit {
                source_id: same_transition_move_source_id(
                    &witness.economic_operation_id,
                    m.debit_mutation_index,
                ),
                policy_commit: debit_asset,
                amount: debit_amount,
            }
        }

        CreditSource::ValidatedPeerDebit(p) => {
            // The resolver returns a VALIDATED transition or nothing. It
            // cannot hand back an unvalidated one, because it would have to
            // construct a ValidatedEconomicRoot to do so.
            let peer = resolver
                .validated_peer_transition(&p.peer_genesis, &p.peer_devid, p.peer_economic_position)
                .ok_or(ProvenanceError::PeerTransitionNotValidated {
                    peer_economic_position: p.peer_economic_position,
                })?;
            // A genuine validated root paired with an unrelated witness is the
            // one forgery the type system cannot prevent on its own.
            if peer.witness.post_economic_root != peer.validated_root.economic_root()
                || peer.peer_genesis != p.peer_genesis
                || peer.peer_devid != p.peer_devid
            {
                return Err(ProvenanceError::PeerWitnessDoesNotMatchValidatedRoot);
            }
            let debit = peer
                .witness
                .mutations
                .get(p.peer_debit_mutation_index as usize)
                .ok_or(ProvenanceError::IndexOutOfRange {
                    index: p.peer_debit_mutation_index,
                })?;
            let (debit_asset, debit_amount) =
                debit_delta(debit).ok_or(ProvenanceError::PeerMutationIsNotADebit {
                    index: p.peer_debit_mutation_index,
                })?;
            FundedCredit {
                source_id: validated_peer_debit_source_id(
                    &p.peer_genesis,
                    &p.peer_devid,
                    p.peer_economic_position,
                    p.peer_debit_mutation_index,
                ),
                policy_commit: debit_asset,
                amount: debit_amount,
            }
        }

        CreditSource::DlvReserveConsumption(_) => {
            return Err(ProvenanceError::NotYetImplemented { class: 0x0026 })
        }
        CreditSource::ValidatedDlvSettlementPayment(_) => {
            return Err(ProvenanceError::NotYetImplemented { class: 0x0027 })
        }
        CreditSource::VerifiedOfflineReentry(_) => {
            return Err(ProvenanceError::NotYetImplemented { class: 0x0028 })
        }
    };

    // Establishing that A source exists is not enough: it must fund THIS
    // credit. Same asset, same amount.
    if funded.policy_commit != credit_asset {
        return Err(ProvenanceError::AssetMismatch {
            source: funded.policy_commit,
            credit: credit_asset,
        });
    }
    if funded.amount != credit_amount {
        return Err(ProvenanceError::AmountMismatch {
            source: funded.amount,
            credit: credit_amount,
        });
    }
    Ok(funded)
}

/// Which arms must leave a persistent consumed-source record.
///
/// `SameTransitionMove` does not: its debit is inside the same write set, so
/// it is consumed by construction and could never be presented again. The
/// external arms can, so their consumption has to be written down.
fn requires_consumed_source_record(source: &CreditSource) -> bool {
    matches!(
        source,
        CreditSource::ValidatedPeerDebit(_) | CreditSource::VerifiedOfflineReentry(_)
    )
}

/// Verify provenance for an entire transition.
///
/// Returns the funded credits in source order. Checks, beyond each source
/// individually: all derived `SourceId`s distinct, and every source that must
/// be recorded as consumed has a consumed-source leaf written **from ZERO** in
/// this same transition, naming this operation as the consumer.
pub fn verify_transition_provenance(
    witness: &EconomicTransitionWitness,
    resolver: &dyn ProvenanceResolver,
) -> Result<Vec<FundedCredit>, ProvenanceError> {
    let mut funded = Vec::with_capacity(witness.credit_sources.len());
    let mut seen: Vec<[u8; 32]> = Vec::with_capacity(witness.credit_sources.len());

    for source in &witness.credit_sources {
        let f = verify_credit_source(source, witness, resolver)?;
        if seen.contains(&f.source_id) {
            return Err(ProvenanceError::DuplicateSourceId);
        }
        seen.push(f.source_id);

        if requires_consumed_source_record(source) {
            let recorded = witness.mutations.iter().find_map(|m| match &m.post_state {
                Some(EconomicLeafState::ConsumedSource(c)) if c.source_id == f.source_id => {
                    Some((m, c))
                }
                _ => None,
            });
            let (mutation, consumed) =
                recorded.ok_or(ProvenanceError::SourceNotRecordedAsConsumed {
                    source_id: f.source_id,
                })?;
            // Written from ZERO. A consumed-source leaf that already existed
            // means this source was spent before, and the Merkle precondition
            // is what makes that unrepeatable.
            if mutation.pre_state.is_some() {
                return Err(ProvenanceError::SourceNotRecordedAsConsumed {
                    source_id: f.source_id,
                });
            }
            if consumed.consumer_economic_operation_id != witness.economic_operation_id {
                return Err(ProvenanceError::ConsumedByAnotherOperation);
            }
        }
        funded.push(f);
    }
    Ok(funded)
}
