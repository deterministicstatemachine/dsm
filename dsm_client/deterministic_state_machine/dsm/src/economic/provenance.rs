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

use crate::common::domain_tags::{TAG_DSM_ECON_SOURCE_VALIDATED_PEER_DEBIT};
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

/// A peer transition this verifier has **already validated**, carrying the
/// lineage it descends from.
///
/// Holding one is evidence: it contains a [`ValidatedEconomicRoot`], which
/// cannot be constructed except by validating. That is what makes the
/// acyclicity rule a type property rather than a convention.
///
/// There are exactly TWO arms, and the absence of a third is the point. An
/// unresolved SoFi position has selected no root, so it can never be a
/// *validated* transition at all: the walk refuses it with
/// `PeerLineageFailure::Unresolved` and produces no value of this type. An
/// `UnresolvedSofi` arm would make "a validated transition whose root was
/// never selected" representable — a contradiction, not a state. The boundary
/// divides cleanly instead:
///
/// ```text
/// unresolved SoFi -> the walk refuses; no ValidatedPeerTransition exists
/// resolved SoFi   -> a transition may exist; peer debit REFUSES it (P15-9)
/// single root     -> a transition exists; peer debit may proceed
/// ```
///
/// **The lineage is authoritative, not advisory.** Both arms wrap one opaque
/// [`PeerTransitionFacts`] rather than carrying named fields, because Rust
/// gives an enum's variant fields the visibility of the enum itself: named
/// public fields would let any caller assemble a `SingleRoot` around a genuine
/// root and a genuine witness, which is exactly the forgery the discriminant
/// exists to prevent. No accessor yields an OWNED payload either, so facts
/// cannot be lifted out of one arm and re-wrapped in the other.
#[derive(Debug, Clone)]
pub enum ValidatedPeerTransition {
    /// An ordinary single-root lineage — the only lineage eligible to be a
    /// peer-debit source.
    SingleRoot(PeerTransitionFacts),
    /// A position whose SoFi route resolved and selected a concrete root.
    ///
    /// The root is genuine and the transition is fully validated, and it is
    /// STILL refused as a debit source: P15-9 rules on lineage, not on whether
    /// resolution happened. A boolean `is_unresolved` would get this wrong.
    ///
    /// **No production path constructs this today, deliberately (E1c-3).**
    /// `validate_peer_lineage` refuses every conditional claim, resolved or
    /// not, because a resolved position's register cell still holds `C_q` —
    /// resolution is verifier-local and never rewrites the cell. The arm
    /// exists so that when E2/E3 teaches the walk to traverse a resolved SoFi
    /// position, the refusal in [`prevalidate_sender_debit`] is already there
    /// rather than owed at the moment it starts mattering.
    ResolvedSofi(PeerTransitionFacts),
}

/// The provenance a validated peer transition carries, whatever its lineage.
///
/// Its fields are private and it has no public constructor. That is what makes
/// [`ValidatedPeerTransition`]'s variants unconstructible outside this module,
/// and it is the whole reason the payload is a separate type.
#[derive(Debug, Clone)]
pub struct PeerTransitionFacts {
    peer_genesis: [u8; 32],
    peer_devid: [u8; 32],
    validated_root: ValidatedEconomicRoot,
    witness: EconomicTransitionWitness,
    /// The peer's P0–P6-proven AK, recovered during the walk — what the
    /// acceptance evidence's sender side must chain to.
    proven_ak: Vec<u8>,
    /// The peer's verified successor commitment — what the acceptance
    /// evidence's receipt `child_tip` must equal ("same bilateral step").
    c_dsm_plus: [u8; 32],
    /// The verified successor's own parent on the peer's bilateral chain —
    /// the other half of the `(embedded_parent, C_dsm+)` pair CORR.1 compares
    /// with a bundle's `(trader_parent, trader_successor)`. From the VERIFIED
    /// substrate, never from the bundle.
    embedded_parent: [u8; 32],
    /// The exact operation the peer's VERIFIED successor evidence carried.
    /// The peer-debit predicate reasons about it directly (Transfer-only,
    /// online mode, addressed to the consumer) instead of trusting the
    /// descriptor's story about what the peer did.
    verified_operation: crate::types::operations::Operation,
    /// The admission manifest the registered claim at this position names,
    /// as the walk verified it. A release that names another manifest for
    /// the same root is refused against this, not against a re-read cell.
    admission_manifest_addr: [u8; 32],
}

impl ValidatedPeerTransition {
    /// The walk's constructor for an ordinary single-root lineage.
    ///
    /// **Only `peer_lineage::validate_peer_lineage` may call this.** It is the
    /// one place that has proven every conjunct the lineage label asserts:
    /// that the register winner at each position decoded as a single-root
    /// claim, named these coordinates, and advanced validation. A second
    /// caller would be asserting a lineage rather than establishing one, and
    /// `ci/peer_debit_lineage_authoritative.sh` fails the build if one appears.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn single_root_from_walk(
        peer_genesis: [u8; 32],
        peer_devid: [u8; 32],
        validated_root: ValidatedEconomicRoot,
        witness: EconomicTransitionWitness,
        proven_ak: Vec<u8>,
        c_dsm_plus: [u8; 32],
        embedded_parent: [u8; 32],
        verified_operation: crate::types::operations::Operation,
        admission_manifest_addr: [u8; 32],
    ) -> Self {
        Self::SingleRoot(PeerTransitionFacts {
            peer_genesis,
            peer_devid,
            validated_root,
            witness,
            proven_ak,
            c_dsm_plus,
            embedded_parent,
            verified_operation,
            admission_manifest_addr,
        })
    }

    /// A single-root transition assembled directly, for FIXTURES ONLY.
    ///
    /// Gated on the `testing` feature, which both this crate and `dsm_sdk`
    /// enable only through a dev-dependency, so it cannot reach a production
    /// artifact. It exists because `tests/*.rs` are external consumers that
    /// deliberately bypass the walk.
    #[cfg(feature = "testing")]
    #[allow(clippy::too_many_arguments)]
    pub fn single_root_for_test(
        peer_genesis: [u8; 32],
        peer_devid: [u8; 32],
        validated_root: ValidatedEconomicRoot,
        witness: EconomicTransitionWitness,
        proven_ak: Vec<u8>,
        c_dsm_plus: [u8; 32],
        embedded_parent: [u8; 32],
        verified_operation: crate::types::operations::Operation,
    ) -> Self {
        Self::single_root_from_walk(
            peer_genesis,
            peer_devid,
            validated_root,
            witness,
            proven_ak,
            c_dsm_plus,
            embedded_parent,
            verified_operation,
            [0u8; 32],
        )
    }

    /// A resolved-SoFi transition, for MUTATION TESTS ONLY.
    ///
    /// This is the one way a `ResolvedSofi` value comes into existence
    /// anywhere, and it is unreachable from production by construction —
    /// `testing` is a dev-dependency-only feature. Without it the P15-9
    /// refusal could not be exercised at all today, because no production path
    /// yet produces a SoFi-lineage transition; with it, removing the refusal
    /// turns a named test red.
    ///
    /// When E2/E3 adds the authoritative production derivation, it adds a
    /// constructor beside `single_root_from_walk`. It does not change P15-9.
    #[cfg(feature = "testing")]
    #[allow(clippy::too_many_arguments)]
    pub fn resolved_sofi_for_test(
        peer_genesis: [u8; 32],
        peer_devid: [u8; 32],
        validated_root: ValidatedEconomicRoot,
        witness: EconomicTransitionWitness,
        proven_ak: Vec<u8>,
        c_dsm_plus: [u8; 32],
        embedded_parent: [u8; 32],
        verified_operation: crate::types::operations::Operation,
    ) -> Self {
        Self::ResolvedSofi(PeerTransitionFacts {
            peer_genesis,
            peer_devid,
            validated_root,
            witness,
            proven_ak,
            c_dsm_plus,
            embedded_parent,
            verified_operation,
            admission_manifest_addr: [0u8; 32],
        })
    }

    /// PRIVATE on purpose: handing out `&PeerTransitionFacts` would let a
    /// caller clone it and re-wrap it in the other arm.
    fn facts(&self) -> &PeerTransitionFacts {
        match self {
            Self::SingleRoot(f) | Self::ResolvedSofi(f) => f,
        }
    }

    pub fn peer_genesis(&self) -> &[u8; 32] {
        &self.facts().peer_genesis
    }

    pub fn peer_devid(&self) -> &[u8; 32] {
        &self.facts().peer_devid
    }

    /// The selected root. Both arms have one — that is why there is no third
    /// arm.
    pub fn validated_root(&self) -> &ValidatedEconomicRoot {
        &self.facts().validated_root
    }

    /// The admission manifest the walk verified at this position.
    pub fn admission_manifest_addr(&self) -> [u8; 32] {
        self.facts().admission_manifest_addr
    }

    pub fn witness(&self) -> &EconomicTransitionWitness {
        &self.facts().witness
    }

    pub fn proven_ak(&self) -> &[u8] {
        &self.facts().proven_ak
    }

    pub fn c_dsm_plus(&self) -> &[u8; 32] {
        &self.facts().c_dsm_plus
    }

    pub fn embedded_parent(&self) -> &[u8; 32] {
        &self.facts().embedded_parent
    }

    pub fn verified_operation(&self) -> &crate::types::operations::Operation {
        &self.facts().verified_operation
    }
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
    /// The accepted DSM successor's own `(embedded_parent, C_dsm+)` pair,
    /// from the VERIFIED substrate — `None` on an offline-boundary
    /// substrate. A `ValidatedPeerDebit` credit requires it: the acceptance
    /// bundle's countersigned B-side pair must equal the exact recipient
    /// successor being validated, never a pair the bundle self-selects.
    pub substrate_b_pair: Option<([u8; 32], [u8; 32])>,
    /// The exact operation the VERIFIED substrate carried — derived inside
    /// `advance_validated` from `AcceptedSubstrate::DsmSuccessor`, NEVER an
    /// independent caller assertion (one source: the authenticated
    /// successor). `None` on an offline-boundary substrate. The 0x0026 arm
    /// reads the settle's own fields (`c_n`, `x`, amounts, owner
    /// coordinates) from here and cross-checks the descriptor against them.
    pub verified_operation: Option<&'a crate::types::operations::Operation>,
}

/// The release that installed one generation of the native reserve: the
/// exact envelope bytes a walk of the reserve lineage established as FINAL at
/// that generation's cell (Part II §13), with the reserve state it succeeded.
/// The verifier re-runs the construction predicate over both; nothing here is
/// believed because a member returned it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReserveReleaseWin {
    pub envelope_bytes: Vec<u8>,
    /// `R_{generation − 1}`, validated by the walk from `R_0`.
    pub parent: crate::economic::native_reserve::NativeReserveState,
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
///
/// `Unresolved` is the fourth answer, and it is none of the other three. The
/// peer's claim at that position is present and authentic and has selected no
/// root: a conditional SoFi position (`C_q`) whose route has not resolved.
/// Calling that `Invalid` would report an honest counterparty as an
/// authenticated forgery — a verdict that is permanent and quarantining —
/// and calling it `Incomplete` would say a fetch might fix it, when nothing
/// this verifier can fetch will. What resolves it is the route.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerLineageFailure {
    Incomplete(String),
    Invalid(String),
    Quarantined(String),
    Unresolved(String),
}

impl core::fmt::Display for PeerLineageFailure {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Incomplete(m) => write!(f, "peer lineage incomplete: {m}"),
            Self::Invalid(m) => write!(f, "peer lineage INVALID: {m}"),
            Self::Quarantined(m) => write!(f, "peer lineage QUARANTINED: {m}"),
            Self::Unresolved(m) => write!(f, "peer lineage UNRESOLVED: {m}"),
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

    /// The release that installed `generation` of the native reserve
    /// `reserve_id`, FINAL at its cell (the leader's first recognized object,
    /// held by two other members of the committed set) on a walk from the
    /// reserve's genesis state. `None` while the lineage has not reached that
    /// generation, and the verifier fails closed on it: a credit is not
    /// funded by a release nobody can show was final.
    fn native_reserve_release(
        &self,
        reserve_id: &[u8; 32],
        generation: u64,
    ) -> Option<ReserveReleaseWin>;

    /// The network's root-register set as the local catalog resolves it.
    ///
    /// CANDIDATE entries, never authority. A set id is now a function of
    /// `(member_id, register_incarnation_id)` pairs, and an incarnation is a
    /// runtime fact a member generates once — so the pairs cannot be a
    /// constant and must come from somewhere. This is that somewhere, and it
    /// is deliberately named a candidate: the caller re-derives the id from
    /// these entries and refuses any membership that is not the network's
    /// canonical list, so a catalog that offers the wrong set is caught
    /// rather than believed.
    fn root_register_candidate_set(
        &self,
        network_id: &[u8],
    ) -> Result<crate::ccb::StorageSetMembers, PeerLineageFailure>;

    /// Exact immutable bytes at `addr` under `namespace` — evidence the
    /// verifier itself checks (the resolver supplies bytes, never verdicts,
    /// so the acyclicity and verification stay in the verifier's hands).
    fn immutable_evidence(
        &self,
        namespace: crate::crypto::domain::TaggedHashDomain<'static>,
        addr: &[u8; 32],
    ) -> Result<Vec<u8>, PeerLineageFailure>;

    /// The canonical `TokenPolicyV3` bytes rooted under `policy_commit` —
    /// the VERIFIER'S OWN anchoring in the token's public anchor, never
    /// counterparty-supplied bytes. Anchors are public identifiers (the
    /// CoinGecko model): anyone holding the commit may root to the token, and
    /// a verifier holding a `V_n`-authenticated commit IS a holder — so the
    /// resolver serves its local rooting or fetches from the authoritative
    /// content-addressed path. The verifier re-hashes whatever arrives
    /// against the commit before trusting a byte; the resolver is a locator,
    /// never authority. Unavailable bytes are `Incomplete` — an availability
    /// condition, not a permission.
    fn anchored_policy_bytes(
        &self,
        policy_commit: &[u8; 32],
    ) -> Result<Vec<u8>, PeerLineageFailure>;
}

/// Why a credit is not funded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProvenanceError {
    /// A `0x005F` genesis-release credit failed one of its conjuncts: it
    /// rides no `CreateToken`, the token's committed policy does not parse,
    /// its release rule is not all-at-creation, or its genesis supply is not
    /// a balance.
    GenesisReleaseInvalid(String),
    /// The token's committed policy could not be established for a
    /// genesis release: not fetched, or the bytes did not re-hash to the
    /// commit. The taxonomy survives, so an outage is retried.
    GenesisReleasePolicy(PeerLineageFailure),
    /// A DLV successor's leg fails the applicable token policy — the SoFi
    /// Def 4.1 / Req 4.4 / Req 4.6 conjunct on every market movement and
    /// every release. The anchored bytes did not re-hash to the committed
    /// leg, did not parse, or the parsed policy refuses the asset as a
    /// market leg.
    MarketLegPolicy(String),
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
    /// The OWNER's economic lineage could not be resolved/validated at the
    /// descriptor's locator position (taxonomy preserved: an outage retries,
    /// a forgery does not).
    OwnerLineage(PeerLineageFailure),
    /// The supplied peer transition's witness does not belong to the validated
    /// root it was handed with.
    PeerWitnessDoesNotMatchValidatedRoot,
    /// P15-9: the peer's position descends from a SoFi conditional route, so
    /// it is not an eligible debit source — regardless of whether that route
    /// resolved and selected a concrete root.
    SofiLineageNotEligible,
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
    /// The descriptor names a reserve other than THE canonical one for the
    /// claimant's authenticated network. The stop-the-line check: without it,
    /// an invented reserve id is a second genesis supply.
    NotTheCanonicalReserve {
        named: [u8; 32],
        canonical: [u8; 32],
    },
    /// A release is never the genesis generation.
    GenerationIsGenesis,
    /// The reserve lineage has not reached this generation with a final
    /// release. Fails closed.
    ReleaseNotEstablished { generation: u64 },
    /// The established envelope is not a valid release, is not the successor
    /// of the state the walk validated, or names different coordinates than
    /// the descriptor.
    ReleaseInvalid(&'static str),
    /// The release's recipient is not the identity under validation, or the
    /// claimant key is not the P0–P6-proven AK.
    ReleaseRecipientMismatch,
    /// The release binds a different economic position or operation digest
    /// than the transition under validation. Position + digest binding IS the
    /// non-reuse mechanism.
    ReleaseBindingMismatch,
    /// The release names a storage set other than the canonical one for the
    /// claimant's network — a release from a foreign register masquerading.
    ReleaseForeignSet,
    /// The release's bytes do not hash to the descriptor's evidence address.
    ReleaseEvidenceAddrMismatch,
    /// The claimant's network has no resolvable pinned register.
    RegisterNotResolvable(&'static str),
}

impl core::fmt::Display for ProvenanceError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::GenesisReleaseInvalid(m) => {
                write!(f, "genesis-release credit is invalid: {m}")
            }
            Self::GenesisReleasePolicy(e) => {
                write!(f, "genesis-release token policy: {e}")
            }
            Self::MarketLegPolicy(m) => {
                write!(f, "market leg token policy: {m}")
            }
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
            Self::SofiLineageNotEligible => write!(
                f,
                "peer position descends from a SoFi route, which is not an eligible debit \
                 source even once resolved (P15-9)"
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
            Self::NotTheCanonicalReserve { .. } => write!(
                f,
                "credit provenance: not THE canonical native ERA reserve for the claimant's \
                 authenticated network — an invented reserve id would be a second genesis \
                 supply, and the descriptor agreeing with the release proves nothing"
            ),
            Self::GenerationIsGenesis => write!(
                f,
                "credit provenance: generation 0 is the reserve's genesis state, never a release"
            ),
            Self::ReleaseNotEstablished { generation } => write!(
                f,
                "credit provenance: no final release at reserve generation {generation} — fail \
                 closed; a credit is not funded by a release nobody can show was final"
            ),
            Self::ReleaseInvalid(why) => {
                write!(f, "credit provenance: reserve release invalid: {why}")
            }
            Self::ReleaseRecipientMismatch => write!(
                f,
                "credit provenance: the release's recipient is not the identity under \
                 validation (or the claimant key is not the P0–P6-proven AK — storage \
                 attribution is not this binding)"
            ),
            Self::ReleaseBindingMismatch => write!(
                f,
                "credit provenance: the release binds a different economic position or \
                 operation digest than this transition — position + digest binding is the \
                 non-reuse mechanism, so a mismatch is a reuse attempt or a stale release"
            ),
            Self::ReleaseForeignSet => write!(
                f,
                "credit provenance: the release names a storage set other than the canonical \
                 one for the claimant's network"
            ),
            Self::OwnerLineage(e) => {
                write!(f, "credit provenance: owner lineage: {e}")
            }
            Self::ReleaseEvidenceAddrMismatch => write!(
                f,
                "credit provenance: the release's bytes do not hash to the descriptor's \
                 evidence address"
            ),
            Self::RegisterNotResolvable(why) => {
                write!(
                    f,
                    "credit provenance: the network's register is not resolvable: {why}"
                )
            }
        }
    }
}

impl std::error::Error for ProvenanceError {}

/// `SourceId` for a genesis release: one per creation.
///
/// `H(tag ‖ 0x00 ‖ creator_genesis ‖ creator_devid ‖ u64_be(creator_position) ‖
/// policy_commit)`. Every input is authenticated: the creator's coordinates
/// are the position under validation, and `policy_commit` is the accepted
/// `CreateToken`'s own. A token is created once, at one position of one
/// lineage, so its release has exactly one source id.
pub fn genesis_release_source_id(
    creator_genesis: &[u8; 32],
    creator_devid: &[u8; 32],
    creator_economic_position: u64,
    policy_commit: &[u8; 32],
) -> [u8; 32] {
    let mut h = dsm_domain_hasher(crate::common::domain_tags::TAG_DSM_ECON_SOURCE_GENESIS_RELEASE);
    h.update(creator_genesis);
    h.update(creator_devid);
    h.update(&creator_economic_position.to_be_bytes());
    h.update(policy_commit);
    *h.finalize().as_bytes()
}

/// Establish what a genesis release (`0x005F`, SoFi §51) funds.
///
/// The asset is the accepted `CreateToken`'s own `policy_commit`, and the
/// amount is the genesis supply the policy under that commit states — so the
/// generic asset/amount equality in [`verify_credit_source`] forces the credit
/// to be exactly the whole supply of exactly the new token. The credit lands
/// in the witness of the identity under validation, which is the creator.
fn verify_genesis_release(
    resolver: &dyn ProvenanceResolver,
    ctx: &ProvenanceContext<'_>,
) -> Result<FundedCredit, ProvenanceError> {
    // The operation is the verified substrate's, never the descriptor's: the
    // descriptor carries no asset and no amount to disagree with it.
    let policy_commit = match ctx.verified_operation {
        Some(crate::types::operations::Operation::CreateToken { policy_commit, .. }) => {
            *policy_commit
        }
        _ => {
            return Err(ProvenanceError::GenesisReleaseInvalid(
                "a genesis release rides only the CreateToken that creates its token".into(),
            ))
        }
    };
    let bytes = resolver
        .anchored_policy_bytes(&policy_commit)
        .map_err(ProvenanceError::GenesisReleasePolicy)?;
    // Bytes that do not re-hash to the commit are not the policy; they supply
    // nothing and prove nothing about the token.
    if crate::crypto::blake3::domain_hash_bytes(crate::common::domain_tags::TAG_DSM_POLICY, &bytes)
        != policy_commit
    {
        return Err(ProvenanceError::GenesisReleasePolicy(
            PeerLineageFailure::Incomplete(
                "policy bytes do not re-hash to the token's policy commit".into(),
            ),
        ));
    }
    let policy = crate::economic::token_policy::parse_token_policy(&bytes)
        .map_err(|e| ProvenanceError::GenesisReleaseInvalid(format!("policy: {e}")))?;
    if policy.release_rule != crate::economic::token_policy::ReleaseRule::AllAtCreation {
        return Err(ProvenanceError::GenesisReleaseInvalid(
            "the token's release rule does not release its supply at creation".into(),
        ));
    }
    let amount = u64::try_from(policy.genesis_supply).map_err(|_| {
        ProvenanceError::GenesisReleaseInvalid(
            "the genesis supply exceeds what one balance can hold".into(),
        )
    })?;
    Ok(FundedCredit {
        source_id: genesis_release_source_id(
            ctx.genesis,
            ctx.device_id,
            ctx.economic_position,
            &policy_commit,
        ),
        policy_commit,
        amount,
    })
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

/// A peer debit proven ELIGIBLE: it is the debit of an online Transfer
/// addressed to the consumer, with these exact coordinates, **and it descends
/// from an ordinary single-root lineage**.
///
/// The lineage half is why this type is opaque. Downstream code should not
/// have to remember P15-9 and re-derive it; holding one of these already means
/// the question was asked and answered. Everything in it comes from the peer's
/// VERIFIED operation and witness — never from a descriptor's story about
/// them.
///
/// Named `EligiblePeerDebit` rather than `ValidatedPeerDebit` because that name
/// is already taken by the wire-level `CreditSource::ValidatedPeerDebit` and
/// its `CreditSourceValidatedPeerDebit` body; those are a claim, this is the
/// proof, and they must not read as the same thing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EligiblePeerDebit {
    debit_asset: [u8; 32],
    debit_amount: u64,
}

impl EligiblePeerDebit {
    pub fn debit_asset(&self) -> [u8; 32] {
        self.debit_asset
    }

    pub fn debit_amount(&self) -> u64 {
        self.debit_amount
    }
}

/// The sender-side conjuncts of the `ValidatedPeerDebit` predicate — ONE
/// implementation shared by the verifier's credit arm (post-accept) and the
/// recipient's pre-accept prevalidation, so the two can never drift
/// (correction 8's split). Establishes, from the validated transition:
/// witness↔root pairing at the claimed identity; the named mutation exists
/// and IS a debit; the verified operation is an ONLINE `Transfer`
/// (`authority_policy: None`) addressed to `consumer_devid`; and the debit
/// is exactly that operation's asset and amount. What it does NOT establish
/// is the recipient-produced half — the acceptance bundle — which only
/// exists after acceptance.
pub fn prevalidate_sender_debit(
    peer: &ValidatedPeerTransition,
    expected_peer_genesis: &[u8; 32],
    expected_peer_devid: &[u8; 32],
    peer_debit_mutation_index: u32,
    consumer_devid: &[u8; 32],
) -> Result<EligiblePeerDebit, ProvenanceError> {
    // ── P15-9, BEFORE any other conjunct ──────────────────────────────────
    // Lineage, not resolution state. A `ResolvedSofi` peer has a perfectly
    // good concrete root and a fully validated transition, and it is refused
    // anyway: the rule is about where the position came from, so a boolean
    // like `is_unresolved` would let exactly the resolved case through.
    //
    // This runs first so the refusal cannot be mistaken for a failure of one
    // of the conjuncts below — and so it still holds for a SoFi transition
    // whose witness and operation are impeccable.
    //
    // The match is exhaustive on purpose. A future arm cannot be added to
    // `ValidatedPeerTransition` without the compiler forcing a ruling here.
    let peer = match peer {
        ValidatedPeerTransition::SingleRoot(_) => peer,
        ValidatedPeerTransition::ResolvedSofi(_) => {
            return Err(ProvenanceError::SofiLineageNotEligible)
        }
    };
    // A genuine validated root paired with an unrelated witness is the one
    // forgery the type system cannot prevent on its own.
    if peer.witness().post_economic_root != peer.validated_root().economic_root()
        || peer.peer_genesis() != expected_peer_genesis
        || peer.peer_devid() != expected_peer_devid
    {
        return Err(ProvenanceError::PeerWitnessDoesNotMatchValidatedRoot);
    }
    let debit = peer
        .witness()
        .mutations
        .get(peer_debit_mutation_index as usize)
        .ok_or(ProvenanceError::IndexOutOfRange {
            index: peer_debit_mutation_index,
        })?;
    let (debit_asset, debit_amount) =
        debit_delta(debit).ok_or(ProvenanceError::PeerMutationIsNotADebit {
            index: peer_debit_mutation_index,
        })?;
    // "Some peer had a validated debit" is not the semantics. The debit must
    // be the sender's ONLINE Transfer, addressed to THIS consumer, and the
    // named mutation must be THE debit that operation performed.
    let (op_recipient, op_amount, op_asset) = match peer.verified_operation() {
        crate::types::operations::Operation::Transfer {
            to_device_id,
            amount,
            policy_commit,
            authority_policy: Option::None,
            ..
        } => (to_device_id.clone(), amount.value(), *policy_commit),
        _ => return Err(ProvenanceError::PeerDebitIsNotAnOnlineTransfer),
    };
    if op_recipient.as_slice() != consumer_devid.as_slice() {
        return Err(ProvenanceError::PeerDebitNotAddressedToConsumer);
    }
    if op_asset != debit_asset || op_amount != debit_amount {
        return Err(ProvenanceError::PeerDebitIndexIsNotTheOperationDebit);
    }
    Ok(EligiblePeerDebit {
        debit_asset,
        debit_amount,
    })
}

/// The asset and quantity a mutation adds, if it adds any.
fn credit_delta(m: &EconomicLeafMutation) -> Option<([u8; 32], u64)> {
    if !m.is_positive_credit() {
        return None;
    }
    let post = m.post_state.as_ref()?;
    let asset = match post {
        EconomicLeafState::Balance(b) => b.policy_commit,
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
        // ── 0x005F: GENESIS RELEASE (SoFi §51) ───────────────────────────
        //
        // The creator's credit of a native token's whole genesis supply, in
        // the transition that creates the token. Established from the
        // accepted `CreateToken` and the policy its `policy_commit` names,
        // fetched under `TAG_DSM_POLICY` and re-hashed to that commit: the
        // credit goes to the creating device, its asset is the new token, its
        // amount is exactly the policy's genesis supply, and the policy's
        // release rule is `AllAtCreation`. No signer authorizes it.
        CreditSource::GenesisRelease(_) => verify_genesis_release(resolver, ctx)?,

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
            // The sender-side conjuncts — ONE implementation shared with the
            // recipient's pre-accept prevalidation, so the two can never
            // drift (correction 8's split).
            let prevalidated = prevalidate_sender_debit(
                &peer,
                &p.peer_genesis,
                &p.peer_devid,
                p.peer_debit_mutation_index,
                ctx.device_id,
            )?;
            let (debit_asset, debit_amount) =
                (prevalidated.debit_asset(), prevalidated.debit_amount());
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
            // The consuming transition's OWN successor pair — a peer-debit
            // credit can only ride a DSM successor, and the bundle's B-side
            // pair must be exactly that successor's, never self-selected.
            let expected_b_pair = ctx.substrate_b_pair.ok_or_else(|| {
                ProvenanceError::AcceptanceEvidence(PeerLineageFailure::Invalid(
                    "a peer-debit credit requires a DSM-successor substrate".to_string(),
                ))
            })?;
            crate::economic::peer_acceptance::verify_peer_transfer_acceptance(
                &bundle_bytes,
                &crate::economic::peer_acceptance::AcceptanceParty {
                    devid: p.peer_devid,
                    proven_ak: peer.proven_ak(),
                },
                &crate::economic::peer_acceptance::AcceptanceParty {
                    devid: *ctx.device_id,
                    proven_ak: ctx.proven_ak,
                },
                // The wire carries the UNSIGNED canonical preimage; the
                // walker verified the SIGNED operation — clear before
                // comparing or the equality can never hold.
                &peer
                    .verified_operation()
                    .with_cleared_signature()
                    .to_bytes(),
                peer.c_dsm_plus(),
                &expected_b_pair,
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

        CreditSource::NativeReserveRelease(d) => {
            use crate::economic::native_reserve::{self, ReleaseSource};

            // 1. THE CANONICAL-ID RULE, first and unconditionally. The
            //    canonical id is DERIVED from the claimant's authenticated
            //    network; comparing descriptor to release proves nothing.
            let canonical = native_reserve::era_reserve_id(ctx.network_id);
            if d.reserve_id != canonical {
                return Err(ProvenanceError::NotTheCanonicalReserve {
                    named: d.reserve_id,
                    canonical,
                });
            }
            // 2. A release is never the genesis state.
            if d.generation == 0 {
                return Err(ProvenanceError::GenerationIsGenesis);
            }
            // 3. The final release at that generation, on a walk of the ONE
            //    reserve lineage from R_0 — leader first over the committed
            //    set, nothing counted.
            let win = resolver
                .native_reserve_release(&d.reserve_id, d.generation)
                .ok_or(ProvenanceError::ReleaseNotEstablished {
                    generation: d.generation,
                })?;
            // 4. The release verifies and IS the successor of the state the
            //    walk validated: `remaining' = remaining − amount`, so the
            //    amount below cannot exceed what the reserve held.
            let release = native_reserve::decode_and_verify_release(&win.envelope_bytes)
                .map_err(|_| ProvenanceError::ReleaseInvalid("does not verify"))?;
            native_reserve::release_constructible(&win.parent, &release).map_err(|_| {
                ProvenanceError::ReleaseInvalid("is not the successor of its parent")
            })?;
            if release.body.reserve_id != d.reserve_id || release.body.generation != d.generation {
                return Err(ProvenanceError::ReleaseInvalid(
                    "release names different coordinates than the descriptor",
                ));
            }
            // 5. THE RECIPIENT IS THE CLAIMANT: the release names the identity
            //    under validation, and the claimant key that signed it IS the
            //    P0–P6-proven AK. `FaucetClaim(A, x) ⇒ recipient = A`.
            let ReleaseSource::FaucetClaimant {
                claimant_public_key,
            } = &release.body.source;
            if release.body.recipient_genesis != *ctx.genesis
                || release.body.recipient_devid != *ctx.device_id
                || claimant_public_key != ctx.proven_ak
            {
                return Err(ProvenanceError::ReleaseRecipientMismatch);
            }
            // 6. NON-REUSE: the release commits ONE target position (whose
            //    register cell is itself final once) and ONE exact operation.
            //    Digest alone would be circular for a minimal no-nonce
            //    operation — two claims' bytes can be identical — so the
            //    position is what makes it sound; the digest pins WHICH
            //    transition.
            if release.body.recipient_economic_position != ctx.economic_position
                || release.body.recipient_operation_digest != witness.operation_digest
            {
                return Err(ProvenanceError::ReleaseBindingMismatch);
            }
            // 7. The release was won in the CANONICAL set for this network —
            //    accepting whatever set it names would let a foreign register
            //    masquerade.
            if release.body.storage_set_id != ctx.canonical_storage_set_id {
                return Err(ProvenanceError::ReleaseForeignSet);
            }
            // 8. The bytes the members hold are the bytes the DAG addresses.
            if native_reserve::release_evidence_addr(&win.envelope_bytes) != d.release_evidence_addr
            {
                return Err(ProvenanceError::ReleaseEvidenceAddrMismatch);
            }
            // The derived funding: exactly what the reserve released, of the
            // reserve's own asset. The generic asset/amount equality below
            // then forces the credit mutation to be exactly that.
            FundedCredit {
                source_id: native_reserve::release_source_id(&d.reserve_id, d.generation),
                policy_commit: win.parent.policy_commit,
                amount: release.body.amount,
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
    // NativeReserveRelease deliberately does NOT require one: non-reuse is
    // the release's position + digest binding (the release commits ONE
    // target position, itself a register cell that is final once, and ONE
    // exact operation), and one generation of the reserve is final exactly
    // once — so a consumed-source leaf would be bookkeeping for an
    // impossibility.
    // EXHAUSTIVE ON PURPOSE. As a `matches!` allowlist this defaulted a new
    // arm to `false` — no consumed-source leaf, so the source stays
    // re-spendable — with no compile error anywhere. Every other function
    // over `CreditSource` in this module forces an arm; this one now does too,
    // and the permissive answer has to be written down to be chosen.
    match source {
        CreditSource::ValidatedPeerDebit(_) => true,
        CreditSource::NativeReserveRelease(_) => false,
        // The remaining arms answer `false`, exactly as the allowlist did.
        // Each is bound to a coordinate that cannot be replayed: a
        // same-transition move is internal to the witness being verified, and
        // an issuance names the position-and-root pair its evidence is
        // proven against. Listing
        // them is the point — the answer is now written down rather than
        // inherited from whichever arm a `matches!` happened to omit.
        // Bound to the one `CreateToken` that carries it: creation happens once.
        CreditSource::GenesisRelease(_) => false,
    }
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
