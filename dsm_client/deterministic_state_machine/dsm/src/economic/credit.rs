// SPDX-License-Identifier: Apache-2.0

//! The credit-source descriptors — CCB classes `0x0023`–`0x0028`, `0x0030` and
//! `0x0035`.
//!
//! ## Why these are inline, not addressed
//!
//! A witness must commit **directly** to which source type funds which credit.
//! If the sources were themselves content addresses, learning that mutation 3
//! is funded by mutation 1 would require fetching another object — absurd for
//! [`SameTransitionMove`], which is intra-transition by definition and refers
//! only to indices the witness already carries.
//!
//! The descriptors are therefore small and inline, and the **heavy** proof
//! material stays content-addressed behind them. That gives a verifier real
//! work it can do before retrieving a single blob: source count, source
//! classes, ordering, credit-mutation indices, duplicate mappings, and the
//! full credit/source bijection are all decidable from the witness bytes.
//!
//! ```text
//! manifest -> witness -> inline CreditSource descriptors -> heavy evidence
//! ```
//!
//! ## What a descriptor does NOT do
//!
//! It does not carry a `source_id`. Every `SourceId` is **derived** from
//! authenticated facts; a caller that could supply one could name a source it
//! had not established. The descriptor carries the facts the derivation
//! consumes, and nothing that would let a producer choose its own answer.
//!
//! It also does not carry `policy_commit` or `amount`. Those live in the
//! credit mutation this descriptor points at, and duplicating them here would
//! create a second place for the same fact to disagree with itself.
//!
//! ## No `Custom` arm
//!
//! The algebra is closed. A credit that names none of these eight is unfunded,
//! and there is deliberately no escape hatch — an open arm would be where
//! every future "just this once" credit went.
//!
//! **Wire format only.** Whether a named source *actually establishes* the
//! units it claims is acceptance semantics, and none of it is implemented
//! here.

use crate::ccb::{class, push_digest32, push_envelope, push_u32, push_u64, CcbError, CcbObject};

/// `0x0023` schema 1 — funded by an authorized issuance transition.
///
/// The authorization itself is addressed rather than inline: class `0x0029`
/// (`IssuanceAuthorizationBody`) defines the issuance predicate, and the
/// descriptor names the evidence bundle carrying it by INNER content identity.
/// Inlining the bundle here would put one fact in two encodings; the arm
/// fetches and re-verifies the addressed bytes instead.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreditSourceAuthorizedIssuance {
    pub credit_mutation_index: u32,
    pub issuance_authorization_addr: [u8; 32],
}

impl CcbObject for CreditSourceAuthorizedIssuance {
    const CLASS: u16 = class::CREDIT_SOURCE_AUTHORIZED_ISSUANCE;
    const SCHEMA: u16 = 1;
}

/// `0x0024` schema 1 — funded by a debit in the SAME transition.
///
/// The only arm with no external evidence address, and the reason the inline
/// design matters: both endpoints are indices into the witness that carries
/// this descriptor, so it is fully checkable with nothing fetched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreditSourceSameTransitionMove {
    pub credit_mutation_index: u32,
    pub debit_mutation_index: u32,
}

impl CcbObject for CreditSourceSameTransitionMove {
    const CLASS: u16 = class::CREDIT_SOURCE_SAME_TRANSITION_MOVE;
    const SCHEMA: u16 = 1;
}

/// `0x0025` schema 1 — funded by a peer's validated debit.
///
/// The peer coordinates are members because the debit must be locatable in a
/// specific position of a specific identity's lineage. "Some peer debited
/// something" is not a source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreditSourceValidatedPeerDebit {
    pub credit_mutation_index: u32,
    pub peer_genesis: [u8; 32],
    pub peer_devid: [u8; 32],
    pub peer_economic_position: u64,
    pub peer_debit_mutation_index: u32,
    pub acceptance_evidence_addr: [u8; 32],
}

impl CcbObject for CreditSourceValidatedPeerDebit {
    const CLASS: u16 = class::CREDIT_SOURCE_VALIDATED_PEER_DEBIT;
    const SCHEMA: u16 = 1;
}

/// `0x0026` schema 2 — the trader's output credit, funded by consuming an
/// owner vault reserve. Schema 1 is BURNED (3.6, owner ruling 2026-08-28):
/// it carried no locator for the owner's validated economic ancestry, and
/// zero producers ever shipped it — the strict decoder refuses its bytes.
///
/// `(vault_id, parent_sequence, x)` names *which* consumption. `receipt_id`
/// is deliberately absent: it derives from `(vault_id, x)`, and carrying a
/// derived name beside its inputs is a place for the two to disagree.
/// `owner_economic_position` is an UNTRUSTED LOCATOR, never authority — the
/// verifier uses it only to locate the claimed owner lineage position, then
/// independently derives `ValidatedEconomicRoot(position)` and proves the
/// reserve facts against that exact root (the 0x0025 discipline).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreditSourceDlvReserveConsumption {
    pub credit_mutation_index: u32,
    pub vault_id: [u8; 32],
    pub parent_sequence: u64,
    pub x: [u8; 32],
    pub owner_economic_position: u64,
    pub reserve_consumption_evidence_addr: [u8; 32],
}

impl CcbObject for CreditSourceDlvReserveConsumption {
    const CLASS: u16 = class::CREDIT_SOURCE_DLV_RESERVE_CONSUMPTION;
    const SCHEMA: u16 = 2;
}

/// `0x0027` schema 2 — the owner's input-reserve credit, funded by a trader's
/// already-admitted settlement payment. Schema 1 is BURNED (3.6, owner
/// ruling 2026-08-28): it carried no locator for the trader's validated
/// economic ancestry, and zero producers ever shipped it.
/// `trader_economic_position` is an UNTRUSTED LOCATOR, never authority —
/// exactly the 0x0025 peer-position discipline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreditSourceValidatedDlvSettlementPayment {
    pub credit_mutation_index: u32,
    pub vault_id: [u8; 32],
    pub settlement_receipt_id: [u8; 32],
    pub parent_sequence: u64,
    pub trader_genesis: [u8; 32],
    pub trader_devid: [u8; 32],
    pub trader_economic_position: u64,
    pub payment_evidence_addr: [u8; 32],
}

impl CcbObject for CreditSourceValidatedDlvSettlementPayment {
    const CLASS: u16 = class::CREDIT_SOURCE_VALIDATED_DLV_SETTLEMENT_PAYMENT;
    const SCHEMA: u16 = 2;
}

/// `0x0028` schema 1 — funded by value returning from the offline regime.
///
/// `prior_boundary_id` is the **checkpoint being consumed**, and it is the
/// anti-fork field. Deriving the source from the terminal offline state
/// instead would be an inflation bug: two forks of one branch derive two
/// distinct source ids and both reenter, so 100 exported returns as 130. Both
/// forks satisfy "complete valid branch", because the offline protocol does
/// not promise global branch uniqueness. Consuming the PRIOR checkpoint makes
/// the second sibling collide on a leaf that is no longer ZERO.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreditSourceVerifiedOfflineReentry {
    pub credit_mutation_index: u32,
    pub prior_boundary_id: [u8; 32],
    pub unload_boundary_id: [u8; 32],
    pub branch_evidence_addr: [u8; 32],
}

impl CcbObject for CreditSourceVerifiedOfflineReentry {
    const CLASS: u16 = class::CREDIT_SOURCE_VERIFIED_OFFLINE_REENTRY;
    const SCHEMA: u16 = 1;
}

/// `0x0030` schema 1 — the recipient credit of a consumed ERA faucet ticket.
///
/// Deliberately carries NO asset and NO amount: both are protocol-derived
/// (builtin ERA, the fixed payout) and already established by the credit
/// mutation and the addressed evidence — a copy here would be a second place
/// for one fact to disagree with itself. `faucet_id` is compared against the
/// CANONICAL `era_faucet_id(network_id)` by the verifier; the descriptor and
/// the winner agreeing with each other proves nothing about the cap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreditSourceValidatedFaucetDistribution {
    pub credit_mutation_index: u32,
    pub faucet_id: [u8; 32],
    pub ticket_index: u64,
    /// Content address of the EXACT signed `FaucetTicketClaimV1` bytes.
    pub faucet_claim_evidence_addr: [u8; 32],
}

impl CcbObject for CreditSourceValidatedFaucetDistribution {
    const CLASS: u16 = class::CREDIT_SOURCE_VALIDATED_FAUCET_DISTRIBUTION;
    const SCHEMA: u16 = 1;
}

/// One entry of `E_R`: one route leg's reserve-consumption locator (amendment
/// 2c-H, H9). Exactly `0x0026`'s per-vault fields; the route's `x` is stated
/// once, on the source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteLegReserveConsumption {
    pub vault_id: [u8; 32],
    pub parent_sequence: u64,
    /// UNTRUSTED locator of this leg's owner economic ancestry — the `0x0026`
    /// discipline.
    pub owner_economic_position: u64,
    pub reserve_consumption_evidence_addr: [u8; 32],
}

/// `0x0035` schema 1 — the trader's ONE output credit of a route-wide settle,
/// funded by consuming a reserve in every vault the route crosses (amendment
/// 2c-H, H9).
///
/// `legs` is `E_R`, a §2.5 sequence in ROUTE-LEG ORDER — never sorted, never
/// discovery order: entry `k` is the operation's `legs[k]`. The encoder and the
/// strict decoder refuse, from these bytes alone, an empty list, more than `h`
/// entries, and two entries naming one vault or one evidence address
/// ([`Self::entries_refusal`]). Nothing here shows that an entry corresponds to
/// its leg: that needs the operation and the dereferenced evidence, and it is
/// the credit-source verifier's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreditSourceDlvRouteReserveConsumption {
    pub credit_mutation_index: u32,
    pub x: [u8; 32],
    pub legs: Vec<RouteLegReserveConsumption>,
}

impl CcbObject for CreditSourceDlvRouteReserveConsumption {
    const CLASS: u16 = class::CREDIT_SOURCE_DLV_ROUTE_RESERVE_CONSUMPTION;
    const SCHEMA: u16 = 1;
}

impl CreditSourceDlvRouteReserveConsumption {
    /// The syntactic rules on `E_R` (2c-H H9), shared by the encoder and the
    /// strict decoder so the two cannot disagree. `None` when the entries are
    /// well formed.
    pub fn entries_refusal(&self) -> Option<CcbError> {
        let class = Self::CLASS;
        if self.legs.is_empty() {
            return Some(CcbError::EmptySequence { class });
        }
        if self.legs.len() > crate::ccb::MAX_TRANSITIONS {
            return Some(CcbError::TransitionCount {
                got: self.legs.len(),
            });
        }
        for (i, entry) in self.legs.iter().enumerate() {
            if self.legs.iter().skip(i + 1).any(|later| {
                later.vault_id == entry.vault_id
                    || later.reserve_consumption_evidence_addr
                        == entry.reserve_consumption_evidence_addr
            }) {
                return Some(CcbError::DuplicateSetElement { class });
            }
        }
        None
    }
}

/// One funding statement for one credit. Closed: eight arms, no `Custom`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CreditSource {
    AuthorizedIssuance(CreditSourceAuthorizedIssuance),
    SameTransitionMove(CreditSourceSameTransitionMove),
    ValidatedPeerDebit(CreditSourceValidatedPeerDebit),
    DlvReserveConsumption(CreditSourceDlvReserveConsumption),
    DlvRouteReserveConsumption(CreditSourceDlvRouteReserveConsumption),
    ValidatedDlvSettlementPayment(CreditSourceValidatedDlvSettlementPayment),
    VerifiedOfflineReentry(CreditSourceVerifiedOfflineReentry),
    ValidatedFaucetDistribution(CreditSourceValidatedFaucetDistribution),
}

impl CreditSource {
    /// The CCB class of this arm. Every inline element begins with its own
    /// envelope, which is how a heterogeneous sequence stays parseable
    /// without a separate discriminant field.
    pub fn class(&self) -> u16 {
        match self {
            Self::AuthorizedIssuance(_) => CreditSourceAuthorizedIssuance::CLASS,
            Self::SameTransitionMove(_) => CreditSourceSameTransitionMove::CLASS,
            Self::ValidatedPeerDebit(_) => CreditSourceValidatedPeerDebit::CLASS,
            Self::DlvReserveConsumption(_) => CreditSourceDlvReserveConsumption::CLASS,
            Self::DlvRouteReserveConsumption(_) => CreditSourceDlvRouteReserveConsumption::CLASS,
            Self::ValidatedDlvSettlementPayment(_) => {
                CreditSourceValidatedDlvSettlementPayment::CLASS
            }
            Self::VerifiedOfflineReentry(_) => CreditSourceVerifiedOfflineReentry::CLASS,
            Self::ValidatedFaucetDistribution(_) => CreditSourceValidatedFaucetDistribution::CLASS,
        }
    }

    /// The credit this source funds. Every arm names exactly one, which is
    /// what makes the bijection expressible.
    pub fn credit_mutation_index(&self) -> u32 {
        match self {
            Self::AuthorizedIssuance(s) => s.credit_mutation_index,
            Self::SameTransitionMove(s) => s.credit_mutation_index,
            Self::ValidatedPeerDebit(s) => s.credit_mutation_index,
            Self::DlvReserveConsumption(s) => s.credit_mutation_index,
            Self::DlvRouteReserveConsumption(s) => s.credit_mutation_index,
            Self::ValidatedDlvSettlementPayment(s) => s.credit_mutation_index,
            Self::VerifiedOfflineReentry(s) => s.credit_mutation_index,
            Self::ValidatedFaucetDistribution(s) => s.credit_mutation_index,
        }
    }

    /// Every direct external evidence address this source references, in field
    /// order.
    ///
    /// `SameTransitionMove` references none — it is intra-transition and has no
    /// external evidence at all — and a route reserve consumption references one
    /// per route leg (2c-H H9). The manifest's `provenance_evidence_addrs` is
    /// derived from exactly these, which is why it is a publication index rather
    /// than a second description of provenance.
    pub fn external_evidence_addrs(&self) -> Vec<[u8; 32]> {
        match self {
            Self::AuthorizedIssuance(s) => vec![s.issuance_authorization_addr],
            Self::SameTransitionMove(_) => Vec::new(),
            Self::ValidatedPeerDebit(s) => vec![s.acceptance_evidence_addr],
            Self::DlvReserveConsumption(s) => vec![s.reserve_consumption_evidence_addr],
            Self::DlvRouteReserveConsumption(s) => s
                .legs
                .iter()
                .map(|entry| entry.reserve_consumption_evidence_addr)
                .collect(),
            Self::ValidatedDlvSettlementPayment(s) => vec![s.payment_evidence_addr],
            Self::VerifiedOfflineReentry(s) => vec![s.branch_evidence_addr],
            Self::ValidatedFaucetDistribution(s) => vec![s.faucet_claim_evidence_addr],
        }
    }

    /// Fields in registry order, per arm.
    pub fn encode(&self) -> Result<Vec<u8>, CcbError> {
        let mut out = Vec::new();
        match self {
            Self::AuthorizedIssuance(s) => {
                push_envelope::<CreditSourceAuthorizedIssuance>(&mut out);
                push_u32(&mut out, s.credit_mutation_index); // 1
                push_digest32(&mut out, &s.issuance_authorization_addr); // 2
            }
            Self::SameTransitionMove(s) => {
                if s.credit_mutation_index == s.debit_mutation_index {
                    return Err(CcbError::SameTransitionMoveIsSelfFunding {
                        index: s.credit_mutation_index,
                    });
                }
                push_envelope::<CreditSourceSameTransitionMove>(&mut out);
                push_u32(&mut out, s.credit_mutation_index); // 1
                push_u32(&mut out, s.debit_mutation_index); // 2
            }
            Self::ValidatedPeerDebit(s) => {
                push_envelope::<CreditSourceValidatedPeerDebit>(&mut out);
                push_u32(&mut out, s.credit_mutation_index); // 1
                push_digest32(&mut out, &s.peer_genesis); // 2
                push_digest32(&mut out, &s.peer_devid); // 3
                push_u64(&mut out, s.peer_economic_position); // 4
                push_u32(&mut out, s.peer_debit_mutation_index); // 5
                push_digest32(&mut out, &s.acceptance_evidence_addr); // 6
            }
            Self::DlvReserveConsumption(s) => {
                push_envelope::<CreditSourceDlvReserveConsumption>(&mut out);
                push_u32(&mut out, s.credit_mutation_index); // 1
                push_digest32(&mut out, &s.vault_id); // 2
                push_u64(&mut out, s.parent_sequence); // 3
                push_digest32(&mut out, &s.x); // 4
                push_u64(&mut out, s.owner_economic_position); // 5
                push_digest32(&mut out, &s.reserve_consumption_evidence_addr); // 6
            }
            Self::DlvRouteReserveConsumption(s) => {
                if let Some(refusal) = s.entries_refusal() {
                    return Err(refusal);
                }
                push_envelope::<CreditSourceDlvRouteReserveConsumption>(&mut out);
                push_u32(&mut out, s.credit_mutation_index); // 1
                push_digest32(&mut out, &s.x); // 2
                let count = u32::try_from(s.legs.len()).map_err(|_| CcbError::LengthOverflow)?;
                push_u32(&mut out, count); // 3, E_R in route-leg order
                for entry in &s.legs {
                    push_digest32(&mut out, &entry.vault_id);
                    push_u64(&mut out, entry.parent_sequence);
                    push_u64(&mut out, entry.owner_economic_position);
                    push_digest32(&mut out, &entry.reserve_consumption_evidence_addr);
                }
            }
            Self::ValidatedDlvSettlementPayment(s) => {
                push_envelope::<CreditSourceValidatedDlvSettlementPayment>(&mut out);
                push_u32(&mut out, s.credit_mutation_index); // 1
                push_digest32(&mut out, &s.vault_id); // 2
                push_digest32(&mut out, &s.settlement_receipt_id); // 3
                push_u64(&mut out, s.parent_sequence); // 4
                push_digest32(&mut out, &s.trader_genesis); // 5
                push_digest32(&mut out, &s.trader_devid); // 6
                push_u64(&mut out, s.trader_economic_position); // 7
                push_digest32(&mut out, &s.payment_evidence_addr); // 8
            }
            Self::ValidatedFaucetDistribution(s) => {
                push_envelope::<CreditSourceValidatedFaucetDistribution>(&mut out);
                push_u32(&mut out, s.credit_mutation_index); // 1
                push_digest32(&mut out, &s.faucet_id); // 2
                push_u64(&mut out, s.ticket_index); // 3
                push_digest32(&mut out, &s.faucet_claim_evidence_addr); // 4
            }
            Self::VerifiedOfflineReentry(s) => {
                if s.prior_boundary_id == s.unload_boundary_id {
                    return Err(CcbError::OfflineReentryBoundaryIsItsOwnParent);
                }
                push_envelope::<CreditSourceVerifiedOfflineReentry>(&mut out);
                push_u32(&mut out, s.credit_mutation_index); // 1
                push_digest32(&mut out, &s.prior_boundary_id); // 2
                push_digest32(&mut out, &s.unload_boundary_id); // 3
                push_digest32(&mut out, &s.branch_evidence_addr); // 4
            }
        }
        Ok(out)
    }
}
