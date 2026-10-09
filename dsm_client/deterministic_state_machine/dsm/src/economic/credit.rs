// SPDX-License-Identifier: Apache-2.0

//! The credit-source descriptors — CCB classes `0x0025`, `0x005D` and
//! `0x005F`.
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
//! The algebra is closed. A credit that names none of these three is unfunded,
//! and there is deliberately no escape hatch — an open arm would be where
//! every future "just this once" credit went.
//!
//! **Wire format only.** Whether a named source *actually establishes* the
//! units it claims is acceptance semantics, and none of it is implemented
//! here.

use crate::ccb::{class, push_digest32, push_envelope, push_u32, push_u64, CcbError, CcbObject};

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

/// `0x005D` schema 1 — the recipient credit of one native reserve release.
///
/// Deliberately carries NO asset and NO amount: both are read from the
/// release the walk established as final at `generation` of the reserve —
/// a copy here would be a second place for one fact to disagree with itself.
/// `reserve_id` is compared against the CANONICAL `era_reserve_id(network_id)`
/// by the verifier; the descriptor and the release agreeing with each other
/// proves nothing about the supply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreditSourceNativeReserveRelease {
    pub credit_mutation_index: u32,
    pub reserve_id: [u8; 32],
    /// The generation the release installed: `R_{generation}` succeeds
    /// `R_{generation − 1}` by exactly this release.
    pub generation: u64,
    /// Content address of the EXACT signed `NativeReserveReleaseV1` bytes.
    pub release_evidence_addr: [u8; 32],
}

impl CcbObject for CreditSourceNativeReserveRelease {
    const CLASS: u16 = class::CREDIT_SOURCE_NATIVE_RESERVE_RELEASE;
    const SCHEMA: u16 = 1;
}

/// `0x005F` schema 1 — the creator's credit of a native token's whole genesis
/// supply, released in the transition that creates the token
/// (`ReleaseRule::AllAtCreation`, SoFi §51).
///
/// Deliberately carries NO asset, NO amount and NO address: the asset is the
/// accepted `CreateToken`'s own `policy_commit`, the policy bytes are fetched
/// under that commit (`H(TAG_DSM_POLICY, bytes)`), and the amount must equal
/// the genesis supply those bytes commit. A copy here would be a second place
/// for one fact to disagree with itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreditSourceGenesisRelease {
    pub credit_mutation_index: u32,
}

impl CcbObject for CreditSourceGenesisRelease {
    const CLASS: u16 = class::CREDIT_SOURCE_GENESIS_RELEASE;
    const SCHEMA: u16 = 1;
}

/// One funding statement for one credit. Closed: three arms, no `Custom`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CreditSource {
    ValidatedPeerDebit(CreditSourceValidatedPeerDebit),
    NativeReserveRelease(CreditSourceNativeReserveRelease),
    GenesisRelease(CreditSourceGenesisRelease),
}

impl CreditSource {
    /// The CCB class of this arm. Every inline element begins with its own
    /// envelope, which is how a heterogeneous sequence stays parseable
    /// without a separate discriminant field.
    pub fn class(&self) -> u16 {
        match self {
            Self::ValidatedPeerDebit(_) => CreditSourceValidatedPeerDebit::CLASS,
            Self::NativeReserveRelease(_) => CreditSourceNativeReserveRelease::CLASS,
            Self::GenesisRelease(_) => CreditSourceGenesisRelease::CLASS,
        }
    }

    /// The credit this source funds. Every arm names exactly one, which is
    /// what makes the bijection expressible.
    pub fn credit_mutation_index(&self) -> u32 {
        match self {
            Self::ValidatedPeerDebit(s) => s.credit_mutation_index,
            Self::NativeReserveRelease(s) => s.credit_mutation_index,
            Self::GenesisRelease(s) => s.credit_mutation_index,
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
            Self::ValidatedPeerDebit(s) => vec![s.acceptance_evidence_addr],
            Self::NativeReserveRelease(s) => vec![s.release_evidence_addr],
            // The policy it releases under is addressed by the operation's own
            // policy_commit, not by the descriptor: nothing external to index.
            Self::GenesisRelease(_) => vec![],
        }
    }

    /// Fields in registry order, per arm.
    pub fn encode(&self) -> Result<Vec<u8>, CcbError> {
        let mut out = Vec::new();
        match self {
            Self::ValidatedPeerDebit(s) => {
                push_envelope::<CreditSourceValidatedPeerDebit>(&mut out);
                push_u32(&mut out, s.credit_mutation_index); // 1
                push_digest32(&mut out, &s.peer_genesis); // 2
                push_digest32(&mut out, &s.peer_devid); // 3
                push_u64(&mut out, s.peer_economic_position); // 4
                push_u32(&mut out, s.peer_debit_mutation_index); // 5
                push_digest32(&mut out, &s.acceptance_evidence_addr); // 6
            }
            Self::NativeReserveRelease(s) => {
                push_envelope::<CreditSourceNativeReserveRelease>(&mut out);
                push_u32(&mut out, s.credit_mutation_index); // 1
                push_digest32(&mut out, &s.reserve_id); // 2
                push_u64(&mut out, s.generation); // 3
                push_digest32(&mut out, &s.release_evidence_addr); // 4
            }
            Self::GenesisRelease(s) => {
                push_envelope::<CreditSourceGenesisRelease>(&mut out);
                push_u32(&mut out, s.credit_mutation_index); // 1
            }
        }
        Ok(out)
    }
}
