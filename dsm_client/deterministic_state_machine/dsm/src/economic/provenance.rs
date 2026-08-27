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
    /// The peer's P0–P6-proven AK, recovered during the walk — what the
    /// acceptance evidence's sender side must chain to.
    pub proven_ak: Vec<u8>,
    /// The peer's verified successor commitment — what the acceptance
    /// evidence's receipt `child_tip` must equal ("same bilateral step").
    pub c_dsm_plus: [u8; 32],
    /// The exact operation the peer's VERIFIED successor evidence carried.
    /// The peer-debit predicate reasons about it directly (Transfer-only,
    /// online mode, addressed to the consumer) instead of trusting the
    /// descriptor's story about what the peer did.
    pub verified_operation: crate::types::operations::Operation,
}

/// The authenticated facts about the identity whose transition is being
/// validated. Every field comes from authority resolution or canonical
/// derivation — never from the objects under validation.
#[derive(Debug, Clone)]
pub struct ProvenanceContext<'a> {
    pub genesis: &'a [u8; 32],
    pub device_id: &'a [u8; 32],
    /// The economic position the registration under validation occupies.
    pub economic_position: u64,
    /// From the AUTHENTICATED Genesis v3 (field 2 of `GenesisParamsV3`,
    /// recovered by recomputation) — the claimant never chooses it.
    pub network_id: &'a [u8],
    /// The P0–P6-proven authority key. Bearer-token attribution at a storage
    /// node is NOT this binding.
    pub proven_ak: &'a [u8],
    /// The canonical register set for `network_id`, resolved FAIL-CLOSED —
    /// a claim naming any other set is foreign, whatever its bytes say.
    pub canonical_storage_set_id: [u8; 32],
}

/// The live-quorum answer for one faucet ticket cell: the exact envelope
/// bytes a quorum of the canonical set holds as the winner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FaucetTicketWin {
    pub envelope_bytes: Vec<u8>,
}

/// Why a peer's lineage could not be resolved to a validated transition.
///
/// The taxonomy is load-bearing: a retry-able outage and an authenticated
/// forgery are different EVENTS, and an `Option` would erase the difference.
/// `Incomplete` covers unavailability, missing material, and local resource
/// budgets exhausting (an adversarially deep — but acyclic — lineage must
/// exhaust a budget into `Incomplete`, never into `Invalid`); `Invalid` is
/// evidence that verified as wrong; `Quarantined` is a divergent write-once
/// register cell — never retried, never hash-ordered, never overwritten.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerLineageFailure {
    Incomplete(String),
    Invalid(String),
    Quarantined(String),
}

impl core::fmt::Display for PeerLineageFailure {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Incomplete(m) => write!(f, "peer lineage incomplete: {m}"),
            Self::Invalid(m) => write!(f, "peer lineage INVALID: {m}"),
            Self::Quarantined(m) => write!(f, "peer lineage QUARANTINED: {m}"),
        }
    }
}

/// Supplies the already-validated facts an external source resolves against.
///
/// Deliberately returns validated objects rather than raw bytes: a resolver
/// that could return "here is a peer root, trust me" would put the acyclicity
/// guarantee back in the hands of whoever wrote the resolver.
pub trait ProvenanceResolver {
    /// The peer's validated transition at the named position, or WHY it
    /// could not be resolved — the taxonomy survives to the caller so a
    /// network outage is retried and a forgery is not.
    fn validated_peer_transition(
        &self,
        peer_genesis: &[u8; 32],
        peer_devid: &[u8; 32],
        peer_economic_position: u64,
    ) -> Result<ValidatedPeerTransition, PeerLineageFailure>;

    /// The winning claim for one faucet ticket, from a LIVE quorum read
    /// against the CANONICAL set — q members returning byte-identical winner
    /// bytes. `None` when no quorum-agreed winner exists, and the verifier
    /// fails closed on it: a credit is not funded by a ticket nobody can
    /// show was won.
    fn winning_faucet_ticket(
        &self,
        faucet_id: &[u8; 32],
        ticket_index: u64,
    ) -> Option<FaucetTicketWin>;

    /// Exact immutable bytes at `addr` under `namespace` — evidence the
    /// verifier itself checks (the resolver supplies bytes, never verdicts,
    /// so the acyclicity and verification stay in the verifier's hands).
    fn immutable_evidence(
        &self,
        namespace: crate::crypto::domain::TaggedHashDomain<'static>,
        addr: &[u8; 32],
    ) -> Result<Vec<u8>, PeerLineageFailure>;
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
    PeerTransitionNotValidated {
        peer_economic_position: u64,
        failure: PeerLineageFailure,
    },
    /// The peer's verified operation is not an ONLINE `Transfer` — a Burn,
    /// a fee debit, or an offline-tier transfer cannot fund a peer credit.
    PeerDebitIsNotAnOnlineTransfer,
    /// The peer's transfer is addressed to a different identity than the one
    /// consuming the credit.
    PeerDebitNotAddressedToConsumer,
    /// The named debit mutation is not THE balance debit the peer's
    /// operation performed.
    PeerDebitIndexIsNotTheOperationDebit,
    /// The acceptance evidence failed to resolve or verify.
    AcceptanceEvidence(PeerLineageFailure),
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
    /// The descriptor names a faucet other than THE canonical one for the
    /// claimant's authenticated network. The stop-the-line check: without it,
    /// an invented faucet id is a fresh 800M-ticket universe.
    NotTheCanonicalFaucet {
        named: [u8; 32],
        canonical: [u8; 32],
    },
    /// A ticket coordinate that does not exist in the protocol.
    TicketIndexOutOfRange { index: u64 },
    /// No quorum-agreed winner for this ticket. Fails closed.
    FaucetTicketNotEstablished { ticket_index: u64 },
    /// The winning envelope is not a valid claim, or names different
    /// coordinates than the descriptor.
    FaucetWinnerInvalid(&'static str),
    /// The winner's claimant is not the identity under validation, or its
    /// key is not the P0–P6-proven AK.
    FaucetClaimantMismatch,
    /// The winner binds a different economic position or operation digest
    /// than the transition under validation. Position + digest binding IS the
    /// non-reuse mechanism.
    FaucetBindingMismatch,
    /// The winner names a storage set other than the canonical one for the
    /// claimant's network — a claim from a foreign register masquerading.
    FaucetForeignSet,
    /// The winner's bytes do not hash to the descriptor's evidence address.
    FaucetEvidenceAddrMismatch,
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
                failure,
            } => write!(
                f,
                "peer transition at position {peer_economic_position} is not resolvable as \
                 validated: {failure}"
            ),
            Self::PeerDebitIsNotAnOnlineTransfer => write!(
                f,
                "peer debit is not an online Transfer — only the online transfer debit \
                 funds a peer credit"
            ),
            Self::PeerDebitNotAddressedToConsumer => write!(
                f,
                "peer transfer is addressed to a different identity than the consumer"
            ),
            Self::PeerDebitIndexIsNotTheOperationDebit => write!(
                f,
                "named debit mutation is not THE balance debit the peer's operation performed"
            ),
            Self::AcceptanceEvidence(e) => write!(f, "acceptance evidence: {e}"),
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
            Self::NotTheCanonicalFaucet { .. } => write!(
                f,
                "credit provenance: not THE canonical ERA faucet for the claimant's \
                 authenticated network — an invented faucet id would be a fresh 800M-ticket \
                 universe, and the descriptor agreeing with the winner proves nothing"
            ),
            Self::TicketIndexOutOfRange { index } => write!(
                f,
                "credit provenance: ticket {index} is not a coordinate that exists"
            ),
            Self::FaucetTicketNotEstablished { ticket_index } => write!(
                f,
                "credit provenance: no quorum-agreed winner for ticket {ticket_index} — fail \
                 closed; a credit is not funded by a ticket nobody can show was won"
            ),
            Self::FaucetWinnerInvalid(why) => {
                write!(f, "credit provenance: faucet winner invalid: {why}")
            }
            Self::FaucetClaimantMismatch => write!(
                f,
                "credit provenance: the winning claim's claimant is not the identity under \
                 validation (or its key is not the P0–P6-proven AK — storage-node bearer \
                 attribution is not this binding)"
            ),
            Self::FaucetBindingMismatch => write!(
                f,
                "credit provenance: the winning claim binds a different economic position or \
                 operation digest than this transition — position + digest binding is the \
                 non-reuse mechanism, so a mismatch is a reuse attempt or a stale claim"
            ),
            Self::FaucetForeignSet => write!(
                f,
                "credit provenance: the winning claim names a storage set other than the \
                 canonical one for the claimant's network"
            ),
            Self::FaucetEvidenceAddrMismatch => write!(
                f,
                "credit provenance: the winner's bytes do not hash to the descriptor's \
                 evidence address"
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
    ctx: &ProvenanceContext<'_>,
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
                .map_err(|failure| ProvenanceError::PeerTransitionNotValidated {
                    peer_economic_position: p.peer_economic_position,
                    failure,
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
            // ── THE exact peer-debit predicate ─────────────────────────────
            // "Some peer had a validated debit" is not the semantics. The
            // debit must be the sender's ONLINE Transfer, addressed to THIS
            // consumer, and the named mutation must be THE debit that
            // operation performed — reasoned from the peer's VERIFIED
            // operation, never from the descriptor's story about it.
            let (op_recipient, op_amount, op_asset) = match &peer.verified_operation {
                crate::types::operations::Operation::Transfer {
                    to_device_id,
                    amount,
                    policy_commit,
                    authority_policy: Option::None,
                    ..
                } => (to_device_id.clone(), amount.value(), *policy_commit),
                _ => return Err(ProvenanceError::PeerDebitIsNotAnOnlineTransfer),
            };
            if op_recipient.as_slice() != ctx.device_id.as_slice() {
                return Err(ProvenanceError::PeerDebitNotAddressedToConsumer);
            }
            if op_asset != debit_asset || op_amount != debit_amount {
                return Err(ProvenanceError::PeerDebitIndexIsNotTheOperationDebit);
            }
            // ── The acceptance — recipient-produced, never the proposal ────
            // The bundle's bytes are fetched by content address and verified
            // HERE: sender chain to the peer's proven AK, recipient chain to
            // the consumer's proven AK, and the receipt bound to the exact
            // validated debit successor.
            let bundle_bytes = resolver
                .immutable_evidence(
                    crate::common::domain_tags::TAG_DSM_PEER_TRANSFER_ACCEPTANCE,
                    &p.acceptance_evidence_addr,
                )
                .map_err(ProvenanceError::AcceptanceEvidence)?;
            if crate::economic::peer_acceptance::acceptance_evidence_addr(&bundle_bytes)
                != p.acceptance_evidence_addr
            {
                return Err(ProvenanceError::AcceptanceEvidence(
                    PeerLineageFailure::Invalid(
                        "acceptance bytes do not hash to the descriptor's address".to_string(),
                    ),
                ));
            }
            let mut fetch_step = |addr: &[u8; 32]| {
                resolver.immutable_evidence(crate::common::domain_tags::TAG_DSM_EK_CERT_STEP, addr)
            };
            crate::economic::peer_acceptance::verify_peer_transfer_acceptance(
                &bundle_bytes,
                &crate::economic::peer_acceptance::AcceptanceParty {
                    devid: p.peer_devid,
                    proven_ak: &peer.proven_ak,
                },
                &crate::economic::peer_acceptance::AcceptanceParty {
                    devid: *ctx.device_id,
                    proven_ak: ctx.proven_ak,
                },
                &peer.verified_operation.to_bytes(),
                &peer.c_dsm_plus,
                &mut fetch_step,
            )
            .map_err(ProvenanceError::AcceptanceEvidence)?;
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

        CreditSource::ValidatedFaucetDistribution(d) => {
            use crate::economic::faucet;

            // 1. THE CANONICAL-ID RULE, first and unconditionally. The
            //    canonical id is DERIVED from the claimant's authenticated
            //    network; comparing descriptor to winner proves nothing.
            let canonical = faucet::era_faucet_id(ctx.network_id);
            if d.faucet_id != canonical {
                return Err(ProvenanceError::NotTheCanonicalFaucet {
                    named: d.faucet_id,
                    canonical,
                });
            }
            // 2. The coordinate must exist.
            if d.ticket_index >= faucet::ERA_FAUCET_TICKET_COUNT {
                return Err(ProvenanceError::TicketIndexOutOfRange {
                    index: d.ticket_index,
                });
            }
            // 3. A quorum-agreed winner, live, from the canonical set.
            let win = resolver
                .winning_faucet_ticket(&d.faucet_id, d.ticket_index)
                .ok_or(ProvenanceError::FaucetTicketNotEstablished {
                    ticket_index: d.ticket_index,
                })?;
            // 4. The winner is a strictly valid claim for THESE coordinates.
            let claim = faucet::decode_and_verify_faucet_ticket_claim(&win.envelope_bytes)
                .map_err(|_| ProvenanceError::FaucetWinnerInvalid("does not verify"))?;
            if claim.body.faucet_id != d.faucet_id || claim.body.ticket_index != d.ticket_index {
                return Err(ProvenanceError::FaucetWinnerInvalid(
                    "winner names different coordinates than the descriptor",
                ));
            }
            // 5. The winner's claimant IS the identity under validation, and
            //    its key IS the P0–P6-proven AK.
            if claim.body.claimant_genesis != *ctx.genesis
                || claim.body.claimant_devid != *ctx.device_id
                || claim.body.claimant_public_key != ctx.proven_ak
            {
                return Err(ProvenanceError::FaucetClaimantMismatch);
            }
            // 6. NON-REUSE: the envelope commits ONE target position (whose
            //    register cell is itself write-once) and ONE exact operation.
            //    Digest alone would be circular for a minimal no-nonce
            //    operation — two claims' bytes can be identical — so the
            //    position is what makes it sound; the digest pins WHICH
            //    transition.
            if claim.body.claimant_economic_position != ctx.economic_position
                || claim.body.recipient_operation_digest != witness.operation_digest
            {
                return Err(ProvenanceError::FaucetBindingMismatch);
            }
            // 7. The claim was won in the CANONICAL set for this network —
            //    accepting whatever set the winner names would let a foreign
            //    register masquerade.
            if claim.body.storage_set_id != ctx.canonical_storage_set_id {
                return Err(ProvenanceError::FaucetForeignSet);
            }
            // 8. The bytes the quorum holds are the bytes the DAG addresses.
            if faucet::faucet_claim_evidence_addr(&win.envelope_bytes)
                != d.faucet_claim_evidence_addr
            {
                return Err(ProvenanceError::FaucetEvidenceAddrMismatch);
            }
            // The derived funding: exactly the fixed payout of builtin ERA.
            // The generic asset/amount equality below then forces the credit
            // mutation to be exactly +100 ERA.
            let era = crate::core::token::token_state_manager::era_policy_commit();
            FundedCredit {
                source_id: faucet::faucet_ticket_source_id(&d.faucet_id, d.ticket_index),
                policy_commit: era,
                amount: faucet::ERA_FAUCET_PAYOUT,
            }
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
    // ValidatedFaucetDistribution deliberately does NOT require one: non-reuse
    // is the envelope's position + digest binding (the ticket commits ONE
    // target position, itself a write-once register cell, and ONE exact
    // operation), so a consumed-source leaf would be bookkeeping for an
    // impossibility.
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
    ctx: &ProvenanceContext<'_>,
) -> Result<Vec<FundedCredit>, ProvenanceError> {
    let mut funded = Vec::with_capacity(witness.credit_sources.len());
    let mut seen: Vec<[u8; 32]> = Vec::with_capacity(witness.credit_sources.len());

    for source in &witness.credit_sources {
        let f = verify_credit_source(source, witness, resolver, ctx)?;
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
