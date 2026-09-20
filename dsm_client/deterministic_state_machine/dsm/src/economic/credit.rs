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

/// One funding statement for one credit. Closed: four arms, no `Custom`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CreditSource {
    AuthorizedIssuance(CreditSourceAuthorizedIssuance),
    ValidatedPeerDebit(CreditSourceValidatedPeerDebit),
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
            Self::ValidatedPeerDebit(_) => CreditSourceValidatedPeerDebit::CLASS,
            Self::VerifiedOfflineReentry(_) => CreditSourceVerifiedOfflineReentry::CLASS,
            Self::ValidatedFaucetDistribution(_) => CreditSourceValidatedFaucetDistribution::CLASS,
        }
    }

    /// The credit this source funds. Every arm names exactly one, which is
    /// what makes the bijection expressible.
    pub fn credit_mutation_index(&self) -> u32 {
        match self {
            Self::AuthorizedIssuance(s) => s.credit_mutation_index,
            Self::ValidatedPeerDebit(s) => s.credit_mutation_index,
            Self::VerifiedOfflineReentry(s) => s.credit_mutation_index,
            Self::ValidatedFaucetDistribution(s) => s.credit_mutation_index,
        }
    }

    /// Every direct external evidence address this source references, in field
    /// order.
    ///
    /// The manifest's `provenance_evidence_addrs` is derived from exactly
    /// these, which is why it is a publication index rather than a second
    /// description of provenance.
    pub fn external_evidence_addrs(&self) -> Vec<[u8; 32]> {
        match self {
            Self::AuthorizedIssuance(s) => vec![s.issuance_authorization_addr],
            Self::ValidatedPeerDebit(s) => vec![s.acceptance_evidence_addr],
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
            Self::ValidatedPeerDebit(s) => {
                push_envelope::<CreditSourceValidatedPeerDebit>(&mut out);
                push_u32(&mut out, s.credit_mutation_index); // 1
                push_digest32(&mut out, &s.peer_genesis); // 2
                push_digest32(&mut out, &s.peer_devid); // 3
                push_u64(&mut out, s.peer_economic_position); // 4
                push_u32(&mut out, s.peer_debit_mutation_index); // 5
                push_digest32(&mut out, &s.acceptance_evidence_addr); // 6
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
