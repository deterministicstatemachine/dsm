// SPDX-License-Identifier: Apache-2.0

//! Foreign economic-state validation.
//!
//! A registered claim proves which bytes hold one routed cell. It does not
//! prove that the root used to route that cell was produced by a valid step.
//! This verifier starts at the activation root and advances each position
//! from the root it validated before it. Each credit source is established
//! through the same predicate. A conditional position resolves through SoFi's
//! public evidence before it can parent another position. When evidence is
//! unavailable or the validation budget is reached, nothing is accepted.

use crate::common::domain_tags::{
    TAG_DSM_ECONOMIC_ADMISSION_MANIFEST, TAG_DSM_ECONOMIC_AUTHORITY_EVIDENCE,
    TAG_DSM_ECONOMIC_OFFLINE_BOUNDARY_EVIDENCE, TAG_DSM_ECONOMIC_SUCCESSOR_EVIDENCE,
    TAG_DSM_ECONOMIC_TRANSITION_WITNESS_OBJ,
};
use crate::crypto::domain::TaggedHashDomain;
use crate::economic::authority_evidence::{
    verify_authority_evidence, AuthorityEvidenceError, AuthorityFacts,
};
use crate::economic::claim::{AdmissionSubstrate, EconomicAdmissionManifest};
use crate::economic::claim_envelope::{RegisteredEconomicClaim, VerifiedEconomicRootClaim};
use crate::economic::decode::decode_admission_manifest;
use crate::economic::lineage::{
    activate, advance_validated, AcceptedClaim, AcceptedSubstrate, EconomicActivationSnapshot,
    EconomicValidationError, ValidatedEconomicRoot,
};
use crate::economic::provenance::{
    PeerLineageFailure, PeerSubstrate, ProvenanceResolver, ReserveReleaseWin,
    ValidatedPeerTransition,
};
use crate::economic::register::{
    economic_root_register_key, read_root_cell, resolve_for_trader, resolve_root_register_profile,
    root_claim_naming, RegisteredEconomicRoot, RootCell, RootRegisterProfile,
};
use crate::economic::successor_evidence::verify_dsm_successor_evidence;
use crate::route_chain::{CellEvidence, CellReading, ChainState};
use crate::sofi::wire::{ParentClaimRef, SofiResolutionClaim};
use crate::utils::text_id::encode_base32_crockford;

/// I/O the verifier needs: raw reads of the register cells it names, and
/// immutable objects by address. The fetcher supplies bytes, never a verdict:
/// the verifier evaluates every cell's route chains itself and re-checks every
/// address.
pub trait PeerEvidenceFetcher {
    /// Every value any member of the register holds under `K_root(position)`
    /// of `(genesis, device_id)`, as the member stores it (a route entry),
    /// read at every member without a route. It is
    /// where to look, never what is final: each claim found there is checked
    /// at the cell routed from the parent it names (DSM Amendment A14).
    /// `Incomplete` when no member answered.
    fn register_key_values(
        &self,
        genesis: &[u8; 32],
        device_id: &[u8; 32],
        position: u64,
    ) -> Result<Vec<Vec<u8>>, PeerLineageFailure>;
    /// Every seat's reads of `cell` (storage spec §9): the values each seat
    /// holds, its committed state from a mirror, and each later seat's own
    /// mirror of the leader. The verifier evaluates them.
    fn register_cell(&self, cell: &RootCell) -> Result<CellEvidence, PeerLineageFailure>;
    /// The release that installed `generation` of the native reserve
    /// `reserve_id`, established final by a walk of the reserve lineage from
    /// its genesis state, with the state it succeeded. `Incomplete` while
    /// the lineage has not reached that generation.
    fn native_reserve_release(
        &self,
        reserve_id: &[u8; 32],
        generation: u64,
    ) -> Result<ReserveReleaseWin, PeerLineageFailure>;
    /// The network's root-register set as the local catalog resolves it —
    /// CANDIDATE entries the caller must re-derive and check, never authority.
    fn root_register_candidate_set(
        &self,
        network_id: &[u8],
    ) -> Result<crate::ccb::StorageSetMembers, PeerLineageFailure>;
    /// Exact immutable bytes at `addr` under `namespace`.
    fn immutable(
        &self,
        namespace: TaggedHashDomain<'static>,
        addr: &[u8; 32],
    ) -> Result<Vec<u8>, PeerLineageFailure>;
    /// The certified key of the EK step at `addr` in `signer`'s chain, when
    /// this verifier holds the step: it is a party to that relationship, or
    /// it verified the step and recorded it (SA-93).
    fn held_ek_step(
        &self,
        signer: &[u8; 32],
        addr: &[u8; 32],
    ) -> Result<Option<Vec<u8>>, PeerLineageFailure>;
    /// The canonical `TokenPolicyV3` bytes rooted under `policy_commit` —
    /// the verifier's own anchoring (local store or the authoritative
    /// content-addressed path). The verifier re-hashes against the commit;
    /// unavailable is `Incomplete`, never `Invalid`.
    fn anchored_policy_bytes(
        &self,
        policy_commit: &[u8; 32],
    ) -> Result<Vec<u8>, PeerLineageFailure>;
}

/// What a receiver validated itself of a peer's offline account: the account
/// as one of the peer's offline boundaries (a load or an unload) left it, at
/// the economic position of the step that admitted the boundary (the owner's
/// receive rule, 2026-10-22: offline acceptance only trusts what the receiver
/// recorded from the peer's online history).
///
/// The account is named by its anchor bundle `B`, which commits the anchor's
/// identity and keys and the peer's online identity. The fields are private:
/// one is built only from a boundary this module verified, in a step that
/// passed, and the only constructor from outside rehydrates what the receiver
/// recorded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerOfflineAccount {
    genesis: [u8; 32],
    device_id: [u8; 32],
    economic_position: u64,
    bundle: [u8; 32],
    account_root: [u8; 32],
    funding_chain: [u8; 32],
}

impl PeerOfflineAccount {
    /// The account `boundary` left, validated in the step at `position`;
    /// `None` for a settlement, which moves no offline account.
    fn validated(
        genesis: [u8; 32],
        device_id: [u8; 32],
        position: u64,
        boundary: &crate::economic::offline_boundary::VerifiedOfflineBoundary,
    ) -> Option<Self> {
        Some(Self {
            genesis,
            device_id,
            economic_position: position,
            bundle: boundary.bundle(),
            account_root: boundary.post_account_root()?,
            funding_chain: boundary.operation_id(),
        })
    }

    /// An offline account this device recorded, read back from its own store.
    ///
    /// **Only the receiver's store may call this**, with exactly the fields of
    /// an account this module produced and the receiver recorded. Anything
    /// read from a network or taken from a peer is not a validated account,
    /// and feeding it here is the fabrication the private fields exist to
    /// prevent.
    pub fn rehydrate_recorded(
        genesis: [u8; 32],
        device_id: [u8; 32],
        economic_position: u64,
        bundle: [u8; 32],
        account_root: [u8; 32],
        funding_chain: [u8; 32],
    ) -> Self {
        Self {
            genesis,
            device_id,
            economic_position,
            bundle,
            account_root,
            funding_chain,
        }
    }

    pub fn genesis(&self) -> &[u8; 32] {
        &self.genesis
    }

    pub fn device_id(&self) -> &[u8; 32] {
        &self.device_id
    }

    /// The economic position of the step that admitted the boundary.
    pub fn economic_position(&self) -> u64 {
        self.economic_position
    }

    /// The anchor bundle `B` that names the account.
    pub fn bundle(&self) -> &[u8; 32] {
        &self.bundle
    }

    /// The account's root after the boundary.
    pub fn account_root(&self) -> &[u8; 32] {
        &self.account_root
    }

    /// The account's funding chain after the boundary: the boundary's id.
    pub fn funding_chain(&self) -> &[u8; 32] {
        &self.funding_chain
    }
}

/// What this receiver recorded of its peers' offline accounts.
pub trait OfflineRecords {
    /// The offline account under `bundle` of `(genesis, device_id)` as the
    /// latest boundary this receiver recorded strictly below `position` left
    /// it, or `None` when it recorded none there.
    fn offline_account_below(
        &self,
        genesis: &[u8; 32],
        device_id: &[u8; 32],
        bundle: &[u8; 32],
        position: u64,
    ) -> Result<Option<PeerOfflineAccount>, PeerLineageFailure>;
}

/// An offline boundary continues the account the most recent earlier boundary
/// in its established economic ancestry left. The first boundary must open
/// the account; a later boundary cannot claim an unestablished predecessor.
pub fn continues_the_account(
    since: crate::economic::offline_boundary::BoundarySince,
    previous: Option<&PeerOfflineAccount>,
) -> Result<(), PeerLineageFailure> {
    use crate::economic::offline_boundary::BoundarySince;
    match (since, previous) {
        (BoundarySince::Opened { .. }, None) => Ok(()),
        (BoundarySince::Previous { .. }, None) => Err(invalid(
            "an offline boundary names a previous account with no established earlier boundary",
        )),
        (BoundarySince::Previous { account_root }, Some(previous))
            if account_root == previous.account_root =>
        {
            Ok(())
        }
        (BoundarySince::Opened { .. } | BoundarySince::Previous { .. }, Some(_)) => Err(invalid(
            "an offline boundary that does not continue the account its previous boundary left",
        )),
    }
}

/// A payment a peer's offline boundary exposed online: one spend of the
/// chain the boundary carried, verified hop by hop from the account the
/// previous boundary left, at the economic position of the step that admitted
/// the boundary. Built only from a step that passed whole.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerOfflineExposure {
    genesis: [u8; 32],
    device_id: [u8; 32],
    economic_position: u64,
    bundle: [u8; 32],
    payment: crate::types::offline_chain::ChainPayment,
}

impl PeerOfflineExposure {
    /// An exposure this device recorded, read back from its own store.
    ///
    /// **Only the receiver's store may call this**, with exactly the fields of
    /// an exposure this module produced and the receiver recorded.
    pub fn rehydrate_recorded(
        genesis: [u8; 32],
        device_id: [u8; 32],
        economic_position: u64,
        bundle: [u8; 32],
        payment: crate::types::offline_chain::ChainPayment,
    ) -> Self {
        Self {
            genesis,
            device_id,
            economic_position,
            bundle,
            payment,
        }
    }

    pub fn genesis(&self) -> &[u8; 32] {
        &self.genesis
    }
    pub fn device_id(&self) -> &[u8; 32] {
        &self.device_id
    }
    /// The position of the step that admitted the boundary exposing it.
    pub fn economic_position(&self) -> u64 {
        self.economic_position
    }
    pub fn bundle(&self) -> &[u8; 32] {
        &self.bundle
    }
    pub fn payment(&self) -> &crate::types::offline_chain::ChainPayment {
        &self.payment
    }
}

/// Derives the root a conditional SoFi position selected, from SoFi's public
/// objects for that position alone (SoFi Amendment S15).
pub trait ConditionalPositionResolver {
    /// `q = previous.economic_position() + 1`; `parent` is the claim accepted
    /// at `q − 1`, and `held` is the claim final at `K_root(q)`. Returns the
    /// root `q` selected and the claim accepted at `q`, or why it cannot:
    /// `Invalid` for a verified contradiction, `Incomplete` or `Unresolved`
    /// while the facts are not in hand or do not decide `q` yet.
    fn resolve(
        &self,
        previous: &ValidatedEconomicRoot,
        parent: &ParentClaimRef,
        held: &SofiResolutionClaim,
    ) -> Result<(ValidatedEconomicRoot, AcceptedClaim), PeerLineageFailure>;
}

/// The reads and transitions used to establish a peer's economic state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StepCost {
    /// Unrouted reads of a register key at every member.
    pub register_probes: u32,
    /// Routed reads of a root cell.
    pub routed_reads: u32,
    /// Credit sources whose ancestry was validated.
    pub source_steps: u32,
    /// Conditional positions resolved during ancestry validation.
    pub conditional_hops: u32,
    /// Economic transitions whose predecessor was established in this check.
    pub steps_validated: u32,
}

/// An answer about one step of a peer, with what checking it cost and what the
/// step left for this receiver to record.
#[derive(Debug)]
pub struct Checked<T> {
    answer: T,
    cost: StepCost,
    offline_accounts: Vec<PeerOfflineAccount>,
    offline_exposures: Vec<PeerOfflineExposure>,
    ek_steps: Vec<crate::economic::peer_acceptance::VerifiedEkStep>,
}

impl<T> Checked<T> {
    pub fn answer(&self) -> &T {
        &self.answer
    }

    pub fn cost(&self) -> StepCost {
        self.cost
    }

    /// Every EK step this check fetched and verified, each in a step that
    /// passed whole: the verifier records them, and a later check starts from
    /// them (SA-93).
    pub fn ek_steps(&self) -> &[crate::economic::peer_acceptance::VerifiedEkStep] {
        &self.ek_steps
    }

    /// Every offline account this check validated: what each offline boundary
    /// it passed left, each from a step that passed whole.
    pub fn offline_accounts(&self) -> &[PeerOfflineAccount] {
        &self.offline_accounts
    }

    /// Every payment an offline boundary this check validated exposed.
    pub fn offline_exposures(&self) -> &[PeerOfflineExposure] {
        &self.offline_exposures
    }

    pub fn into_answer(self) -> T {
        self.answer
    }
}

const VALIDATION_STEP_BUDGET: u32 = 512;

/// A peer's step at `target_position`, validated through every economic
/// predecessor from activation. Each credit source is established under the
/// same rule. A conditional target is unresolved until SoFi selects its root.
pub fn validate_peer_step(
    fetcher: &dyn PeerEvidenceFetcher,
    expected_network_id: &[u8],
    peer_genesis: &[u8; 32],
    peer_devid: &[u8; 32],
    target_position: u64,
    records: &dyn OfflineRecords,
    conditional: &dyn ConditionalPositionResolver,
) -> Result<Checked<ValidatedPeerTransition>, PeerLineageFailure> {
    if target_position == 0 {
        return Err(invalid(
            "position 0 is the activation root; it has no transition to validate",
        ));
    }
    let verifier = Verifier::new(fetcher, expected_network_id, records, conditional)?;
    let (_, _, answer) = verifier.validated_to(
        peer_genesis,
        peer_devid,
        target_position,
        Target::Transition(StepRole::Offered),
    )?;
    let answer = answer.ok_or_else(|| invalid("the offered position has no transition"))?;
    Ok(verifier.checked(answer))
}

/// The root a peer selected AT `position`, and the reference a later `P`
/// names that position by (SoFi Amendment S35). Its economic ancestry is
/// established from activation; a conditional claim is resolved through
/// `conditional` after its predecessor is established.
///
/// Position 0 is the activation root, where no claim was accepted for a `P`
/// to name, and is `Invalid`.
pub fn peer_root_at(
    fetcher: &dyn PeerEvidenceFetcher,
    expected_network_id: &[u8],
    peer_genesis: &[u8; 32],
    peer_devid: &[u8; 32],
    position: u64,
    records: &dyn OfflineRecords,
    conditional: &dyn ConditionalPositionResolver,
) -> Result<Checked<(ValidatedEconomicRoot, ParentClaimRef)>, PeerLineageFailure> {
    if position == 0 {
        return Err(invalid(
            "position 0 is the activation root: no claim was accepted there for a P to name as \
             its parent",
        ));
    }
    let verifier = Verifier::new(fetcher, expected_network_id, records, conditional)?;
    let (point, _, _) = verifier.validated_to(peer_genesis, peer_devid, position, Target::Root)?;
    let answer = (
        point.root,
        point
            .accepted
            .ok_or_else(|| invalid("the selected root has no accepted claim"))?,
    );
    Ok(verifier.checked(answer))
}

/// The claim a peer accepted AT `position` (SoFi Amendment S35,
/// MR-SOFI-0432): what a setup naming that position is checked against.
/// Its economic ancestry is established from activation, and a conditional
/// position is resolved from public SoFi evidence before its claim is used.
pub fn peer_claim_at(
    fetcher: &dyn PeerEvidenceFetcher,
    expected_network_id: &[u8],
    peer_genesis: &[u8; 32],
    peer_devid: &[u8; 32],
    position: u64,
    records: &dyn OfflineRecords,
    conditional: &dyn ConditionalPositionResolver,
) -> Result<Checked<AcceptedClaim>, PeerLineageFailure> {
    if position == 0 {
        return Err(invalid(
            "position 0 is the activation root: no claim was accepted there",
        ));
    }
    let verifier = Verifier::new(fetcher, expected_network_id, records, conditional)?;
    let (_, answer, _) = verifier.validated_to(peer_genesis, peer_devid, position, Target::Root)?;
    Ok(verifier.checked(answer))
}

/// The maximum positions one offline boundary scan requests. Validation
/// also establishes ancestry before the start of the requested range.
pub const OFFLINE_SCAN_POSITIONS: u64 = 512;

/// How far a scan of a peer's offline boundaries read.
#[derive(Debug)]
pub struct OfflineScan {
    reached: u64,
    stop: ScanStop,
}

/// Why a scan of a peer's offline boundaries stopped.
#[derive(Debug)]
pub enum ScanStop {
    /// No member holds a claim of the peer at the next position.
    Head,
    /// The scan read the positions it was asked to.
    Bound,
    /// A read did not decide a position yet. What the scan validated before it
    /// stands.
    Short(String),
}

impl OfflineScan {
    /// The last position the scan read past; the position before its start
    /// when it read none.
    pub fn reached(&self) -> u64 {
        self.reached
    }

    /// Why the scan stopped.
    pub fn stop(&self) -> &ScanStop {
        &self.stop
    }
}

/// Read `positions` of a peer in order and validate every predecessor from
/// activation. Record only offline boundaries from fully validated steps.
pub fn scan_offline_boundaries(
    fetcher: &dyn PeerEvidenceFetcher,
    expected_network_id: &[u8],
    peer_genesis: &[u8; 32],
    peer_devid: &[u8; 32],
    positions: std::ops::Range<u64>,
    records: &dyn OfflineRecords,
    conditional: &dyn ConditionalPositionResolver,
) -> Result<Checked<OfflineScan>, PeerLineageFailure> {
    if positions.start == 0 {
        return Err(invalid(
            "position 0 is the activation root; it holds no offline boundary",
        ));
    }
    let verifier = Verifier::new(fetcher, expected_network_id, records, conditional)?;
    let answer = verifier.offline_boundaries(peer_genesis, peer_devid, positions)?;
    Ok(verifier.checked(answer))
}

/// A failure met inside a step, kept in its own class and located at the
/// position where it was met.
fn at_position(position: u64, failure: PeerLineageFailure) -> PeerLineageFailure {
    match failure {
        PeerLineageFailure::Incomplete(m) => {
            PeerLineageFailure::Incomplete(format!("at position {position}: {m}"))
        }
        PeerLineageFailure::Invalid(m) => {
            PeerLineageFailure::Invalid(format!("at position {position}: {m}"))
        }
        PeerLineageFailure::Quarantined(m) => {
            PeerLineageFailure::Quarantined(format!("at position {position}: {m}"))
        }
        PeerLineageFailure::Unresolved(m) => {
            PeerLineageFailure::Unresolved(format!("at position {position}: {m}"))
        }
    }
}

/// The class of a step's validation failure. Evidence that verified as
/// wrong is `Invalid`; evidence that could not be established — a nested
/// peer's lineage, a reserve release, a token policy, acceptance evidence —
/// keeps the class it was established in, so an outage anywhere below a step
/// is retried and never read as a forgery (storage spec §4: a fact that is
/// not established is never read as its negation).
fn step_failure(position: u64, e: EconomicValidationError) -> PeerLineageFailure {
    use crate::economic::provenance::ProvenanceError as P;
    let invalid_at = |e: &dyn core::fmt::Display| invalid(format!("validation at {position}: {e}"));
    match e {
        EconomicValidationError::Provenance(p) => match p {
            P::GenesisReleasePolicy(failure)
            | P::PeerTransitionNotValidated { failure, .. }
            | P::AcceptanceEvidence(failure)
            | P::OwnerLineage(failure)
            | P::RegisterNotEstablished(failure)
            | P::ReleaseNotEstablished { failure, .. } => at_position(position, failure),
            P::GenesisReleaseInvalid(..)
            | P::PeerDebitIsNotAnOnlineTransfer
            | P::NotAnOfflineUnload
            | P::PeerDebitNotAddressedToConsumer
            | P::PeerDebitIndexIsNotTheOperationDebit
            | P::PeerWitnessDoesNotMatchValidatedRoot
            | P::SofiLineageNotEligible
            | P::PeerMutationIsNotADebit { .. }
            | P::AssetMismatch { .. }
            | P::AmountMismatch { .. }
            | P::IndexOutOfRange { .. }
            | P::NotACredit { .. }
            | P::DuplicateSourceId
            | P::SourceNotRecordedAsConsumed { .. }
            | P::ConsumedByAnotherOperation
            | P::NotTheCanonicalReserve { .. }
            | P::GenerationIsGenesis
            | P::ReleaseInvalid(..)
            | P::ReleaseParentNotOnTheReserve(..)
            | P::ReleaseNotTheSuccessor(..)
            | P::ReleaseIsNotTheEstablishedStep { .. }
            | P::ReleaseRecipientMismatch
            | P::ReleaseBindingMismatch
            | P::ReleaseEvidenceAddrMismatch
            | P::RegisterNotResolvable(..) => invalid_at(&p),
        },
        EconomicValidationError::PreRootIsNotThePredecessor { .. }
        | EconomicValidationError::PositionIsNotSuccessor { .. }
        | EconomicValidationError::RegisteredClaimNamesAnotherTrader
        | EconomicValidationError::SetupPositionIsNotThePredecessor { .. }
        | EconomicValidationError::SetupRootIsNotTheDerivedRoot { .. }
        | EconomicValidationError::RegisteredRootDiffersFromWitness { .. }
        | EconomicValidationError::Transition(..)
        | EconomicValidationError::OperationDigestMismatch { .. }
        | EconomicValidationError::EconomicOperationIdMismatch { .. }
        | EconomicValidationError::SubstrateKindMismatch
        | EconomicValidationError::SubstrateEvidenceMismatch { .. }
        | EconomicValidationError::OfflineBoundaryIdMismatch { .. }
        | EconomicValidationError::WriteSet(..)
        | EconomicValidationError::ManifestAddrMismatch { .. }
        | EconomicValidationError::Manifest(..) => invalid_at(&e),
    }
}

fn incomplete(m: impl Into<String>) -> PeerLineageFailure {
    PeerLineageFailure::Incomplete(m.into())
}

fn invalid(m: impl Into<String>) -> PeerLineageFailure {
    PeerLineageFailure::Invalid(m.into())
}

/// The network's root register, resolved once per verification: the pinned
/// profile, and the catalog's candidate set checked against it. Every root
/// cell of the verification is routed over this set. A catalog that offers
/// another set is this verifier's own fault, never the peer's, so it is not
/// `Invalid`.
struct Register {
    profile: RootRegisterProfile,
    set: crate::ccb::StorageSetMembers,
}

impl Register {
    fn resolve(
        fetcher: &dyn PeerEvidenceFetcher,
        expected_network_id: &[u8],
    ) -> Result<Self, PeerLineageFailure> {
        let profile = resolve_root_register_profile(expected_network_id)
            .map_err(|e| incomplete(format!("no root register for this network: {e}")))?;
        let set = fetcher.root_register_candidate_set(expected_network_id)?;
        profile.verify_candidate(&set).map_err(|e| {
            incomplete(format!(
                "the catalog's root register set is not the pinned one: {e}"
            ))
        })?;
        Ok(Self { profile, set })
    }
}

/// The parent a step is validated from: the root at the position before, and
/// the claim accepted there when it was read for a conditional claim to name
/// (`None` otherwise, and always at the activation root).
struct ChainPoint {
    root: ValidatedEconomicRoot,
    accepted: Option<ParentClaimRef>,
}

/// A single-root claim authenticated at its position.
struct Authenticated {
    manifest: EconomicAdmissionManifest,
    manifest_addr: [u8; 32],
    facts: AuthorityFacts,
}

/// Why a step is being validated, which decides where its own provenance
/// questions go.
#[derive(Clone, Copy)]
enum StepRole {
    /// The step asked about: each credit source has validated ancestry.
    Offered,
    /// A credit's source step: it must be an online transfer, a debit that
    /// names no source of its own.
    Source,
}

#[derive(Clone, Copy)]
enum Target {
    Transition(StepRole),
    Root,
}

/// A peer's position under validation: its genesis, its device and the position.
type StepCoordinate = ([u8; 32], [u8; 32], u64);

struct Verifier<'a> {
    fetcher: &'a dyn PeerEvidenceFetcher,
    expected_network_id: &'a [u8],
    register: Register,
    records: &'a dyn OfflineRecords,
    conditional: &'a dyn ConditionalPositionResolver,
    /// What this check has cost so far, counted as it reads.
    cost: std::cell::Cell<StepCost>,
    active: std::cell::RefCell<std::collections::BTreeSet<StepCoordinate>>,
    /// Every offline account a step this check validated left: each boundary
    /// in a step that passed.
    offline_accounts: std::cell::RefCell<Vec<PeerOfflineAccount>>,
    /// Every payment those boundaries exposed.
    offline_exposures: std::cell::RefCell<Vec<PeerOfflineExposure>>,
    /// Every EK step a step this check validated fetched and verified; a later
    /// step of the same check holds them.
    ek_steps: std::cell::RefCell<Vec<crate::economic::peer_acceptance::VerifiedEkStep>>,
}

/// A claim's identity at its cell: the entry digest the register recognizes
/// it by (a single-root claim by its exact bytes, a conditional one by its
/// derived body `C_q`).
fn claim_identity(claim: &RegisteredEconomicClaim) -> [u8; 32] {
    match claim {
        RegisteredEconomicClaim::SingleRoot(c) => {
            crate::storage_cell::entry_digest(c.envelope_bytes())
        }
        RegisteredEconomicClaim::ConditionalSofi(c) => {
            crate::storage_cell::entry_digest(&c.encode())
        }
    }
}

impl<'a> Verifier<'a> {
    fn new(
        fetcher: &'a dyn PeerEvidenceFetcher,
        expected_network_id: &'a [u8],
        records: &'a dyn OfflineRecords,
        conditional: &'a dyn ConditionalPositionResolver,
    ) -> Result<Self, PeerLineageFailure> {
        Ok(Self {
            fetcher,
            expected_network_id,
            register: Register::resolve(fetcher, expected_network_id)?,
            records,
            conditional,
            cost: std::cell::Cell::new(StepCost {
                register_probes: 0,
                routed_reads: 0,
                source_steps: 0,
                conditional_hops: 0,
                steps_validated: 0,
            }),
            active: std::cell::RefCell::new(std::collections::BTreeSet::new()),
            offline_accounts: std::cell::RefCell::new(Vec::new()),
            offline_exposures: std::cell::RefCell::new(Vec::new()),
            ek_steps: std::cell::RefCell::new(Vec::new()),
        })
    }
}

impl Verifier<'_> {
    /// `answer`, with what this check cost and what it left to record.
    fn checked<T>(self, answer: T) -> Checked<T> {
        Checked {
            answer,
            cost: self.cost.get(),
            offline_accounts: self.offline_accounts.into_inner(),
            offline_exposures: self.offline_exposures.into_inner(),
            ek_steps: self.ek_steps.into_inner(),
        }
    }

    /// The key of the EK step at `addr` in `signer`'s chain, when this verifier
    /// holds it: one an earlier step of this check verified, or one the
    /// fetcher holds (its own relationships', and those it recorded).
    fn held_ek_step(
        &self,
        signer: &[u8; 32],
        addr: &[u8; 32],
    ) -> Result<Option<Vec<u8>>, PeerLineageFailure> {
        let verified = self
            .ek_steps
            .borrow()
            .iter()
            .find(|step| step.signer == *signer && step.addr == *addr)
            .map(|step| step.ek_pk.clone());
        match verified {
            Some(key) => Ok(Some(key)),
            None => self.fetcher.held_ek_step(signer, addr),
        }
    }

    fn count(&self, add: impl FnOnce(&mut StepCost)) {
        let mut cost = self.cost.get();
        add(&mut cost);
        self.cost.set(cost);
    }

    fn validated_to(
        &self,
        genesis: &[u8; 32],
        device_id: &[u8; 32],
        target_position: u64,
        target: Target,
    ) -> Result<(ChainPoint, AcceptedClaim, Option<ValidatedPeerTransition>), PeerLineageFailure>
    {
        if target_position == 0 {
            return Err(invalid("the activation root has no accepted claim"));
        }
        let coordinate = (*genesis, *device_id, target_position);
        if self.active.borrow().len() >= VALIDATION_STEP_BUDGET as usize {
            return Err(incomplete(
                "economic ancestry exceeds the validation budget",
            ));
        }
        if !self.active.borrow_mut().insert(coordinate) {
            return Err(invalid(format!(
                "cyclic economic ancestry at position {target_position} of {}/{}",
                encode_base32_crockford(genesis),
                encode_base32_crockford(device_id),
            )));
        }
        let result = self.validated_to_inner(genesis, device_id, target_position, target);
        self.active.borrow_mut().remove(&coordinate);
        result
    }

    fn validated_to_inner(
        &self,
        genesis: &[u8; 32],
        device_id: &[u8; 32],
        target_position: u64,
        target: Target,
    ) -> Result<(ChainPoint, AcceptedClaim, Option<ValidatedPeerTransition>), PeerLineageFailure>
    {
        let mut point = ChainPoint {
            root: activate(EconomicActivationSnapshot::fresh())
                .map_err(|e| invalid(format!("activation shape: {e}")))?,
            accepted: None,
        };
        let mut answer = None;
        for position in 1..=target_position {
            let at = if position == target_position {
                target
            } else {
                Target::Root
            };
            let (next, accepted, transition) =
                self.validated_position(genesis, device_id, position, point, at)?;
            point = next;
            answer = Some((accepted, transition));
        }
        let (accepted, transition) =
            answer.ok_or_else(|| invalid("the target accepted no claim"))?;
        Ok((point, accepted, transition))
    }

    /// Route the next cell from the root validated at the prior position.
    /// A signed claim final only along the route its own witness names cannot
    /// make that witness-named root into an established predecessor.
    fn validated_position(
        &self,
        genesis: &[u8; 32],
        device_id: &[u8; 32],
        position: u64,
        point: ChainPoint,
        target: Target,
    ) -> Result<(ChainPoint, AcceptedClaim, Option<ValidatedPeerTransition>), PeerLineageFailure>
    {
        if self.cost.get().steps_validated >= VALIDATION_STEP_BUDGET {
            return Err(incomplete(format!(
                "validation reached its budget of {VALIDATION_STEP_BUDGET} steps before \
                 establishing position {position}"
            )));
        }
        self.count(|c| c.routed_reads += 1);
        let claim = self
            .final_claim(genesis, device_id, position, &point.root)
            .map_err(|e| at_position(position, e))?;
        let result = match claim {
            RegisteredEconomicClaim::SingleRoot(claim) => {
                let role = match target {
                    Target::Transition(role) => role,
                    Target::Root => StepRole::Offered,
                };
                let step = self.full_step(genesis, device_id, position, &point, &claim, role)?;
                let accepted = *step.accepted_claim();
                (
                    ChainPoint {
                        root: *step.validated_root(),
                        accepted: Some(ParentClaimRef::SingleRoot {
                            claim_ref: accepted.claim_ref(),
                        }),
                    },
                    accepted,
                    Some(step),
                )
            }
            RegisteredEconomicClaim::ConditionalSofi(held) => {
                match target {
                    Target::Transition(StepRole::Source) => {
                        return Err(invalid(format!(
                            "position {position}: a conditional SoFi position is not an online debit"
                        )));
                    }
                    Target::Transition(StepRole::Offered) => {
                        return Err(PeerLineageFailure::Unresolved(format!(
                            "position {position}: a conditional position has no transition until its route resolves"
                        )));
                    }
                    Target::Root => {}
                }
                if held.void_root != point.root.economic_root() {
                    return Err(invalid(format!(
                        "position {position}: the conditional claim names a different predecessor"
                    )));
                }
                let (root, accepted) =
                    self.resolve_conditional(genesis, device_id, position, &point, &held)?;
                self.count(|c| c.conditional_hops += 1);
                (
                    ChainPoint {
                        root,
                        accepted: Some(ParentClaimRef::Conditional {
                            fulfillment_id: held.fulfillment_id,
                        }),
                    },
                    accepted,
                    None,
                )
            }
        };
        self.count(|c| c.steps_validated += 1);
        Ok(result)
    }
    /// The claim final at `position`'s root cell, routed from the root
    /// authenticated at the position before. Only a claim naming
    /// `K_root(position)` is recognized there, and the key is a hash of
    /// `(G, DevID, position)`, so the claim that holds the cell is this
    /// peer's at this position; any other bytes count as nothing, however
    /// early they arrived.
    fn final_claim(
        &self,
        genesis: &[u8; 32],
        device_id: &[u8; 32],
        position: u64,
        previous: &ValidatedEconomicRoot,
    ) -> Result<RegisteredEconomicClaim, PeerLineageFailure> {
        let cell = RootCell::new(
            genesis,
            device_id,
            position,
            &previous.economic_root(),
            &self.register.set,
            &self.register.profile.storage_set_id,
        )
        .map_err(|e| incomplete(format!("root cell at {position}: {e:?}")))?;
        let evidence = self.fetcher.register_cell(&cell)?;
        match read_root_cell(&cell, &evidence) {
            Ok(CellReading::Held {
                object,
                state: ChainState::Final,
                ..
            }) => Ok(object),
            Ok(CellReading::Held {
                state: ChainState::LeaderHeld | ChainState::Preserved,
                ..
            }) => Err(incomplete(format!(
                "position {position}: the claim holding the root cell is not final yet"
            ))),
            Ok(CellReading::Open) => Err(incomplete(format!(
                "position {position}: no claim holds the root cell"
            ))),
            Err(missing) => Err(incomplete(format!(
                "position {position}: the root cell is not decided yet: {missing:?}"
            ))),
        }
    }

    /// Authenticate a single-root claim: its manifest by content address,
    /// its key the AK the manifest's authority evidence proves (P0–P6), and
    /// its register set the canonical set of the peer's committed network,
    /// which must be the network being verified.
    fn authenticate(
        &self,
        genesis: &[u8; 32],
        device_id: &[u8; 32],
        position: u64,
        claim: &VerifiedEconomicRootClaim,
    ) -> Result<Authenticated, PeerLineageFailure> {
        let body = claim.body();
        let manifest_bytes = self.fetcher.immutable(
            TAG_DSM_ECONOMIC_ADMISSION_MANIFEST,
            &body.admission_manifest_addr,
        )?;
        let manifest = decode_admission_manifest(&manifest_bytes)
            .map_err(|e| invalid(format!("manifest at {position}: {e}")))?;
        let manifest_addr = manifest
            .addr()
            .map_err(|e| invalid(format!("manifest addr: {e}")))?;
        if manifest_addr != body.admission_manifest_addr {
            return Err(invalid("manifest bytes do not address-match the claim"));
        }
        let authority_bytes = self.fetcher.immutable(
            TAG_DSM_ECONOMIC_AUTHORITY_EVIDENCE,
            &manifest.authority_evidence_addr,
        )?;
        let facts = verify_authority_evidence(
            &authority_bytes,
            genesis,
            device_id,
            &manifest.authority_position,
        )
        .map_err(|e| match e {
            AuthorityEvidenceError::Incomplete(m) => incomplete(m),
            other => invalid(other.to_string()),
        })?;
        // The committed network must be the one being verified, and the
        // register set the claim binds must be that network's canonical set —
        // never sourced from transfer metadata or contacts. The pinned id
        // covers every `(member, incarnation)` pair, so a claim written under
        // a member's old incarnation does not name it.
        let trader_profile = resolve_for_trader(&facts.network_id, self.expected_network_id)
            .map_err(|e| invalid(format!("peer network refused: {e}")))?;
        if body.root_register_storage_set_id != trader_profile.storage_set_id {
            return Err(invalid(
                "claim binds a register set that is not the canonical set of the peer's \
                 committed network",
            ));
        }
        // The claim's key IS the proven AK — storage attribution is not the
        // cryptographic binding.
        if body.claimant_public_key != facts.proven_ak {
            return Err(invalid(
                "register claim is signed by a key that is not the P0–P6-proven AK",
            ));
        }
        Ok(Authenticated {
            manifest,
            manifest_addr,
            facts,
        })
    }

    /// The root a conditional position selected and the claim accepted
    /// there, as the resolver derives them, held to this position of this
    /// peer.
    fn resolve_conditional(
        &self,
        genesis: &[u8; 32],
        device_id: &[u8; 32],
        position: u64,
        point: &ChainPoint,
        held: &SofiResolutionClaim,
    ) -> Result<(ValidatedEconomicRoot, AcceptedClaim), PeerLineageFailure> {
        let parent = point.accepted.as_ref().ok_or_else(|| {
            invalid(format!(
                "position {position}: a conditional position cannot follow the activation root, \
                 where no claim was accepted for it to name as its parent"
            ))
        })?;
        let (root, accepted) = self
            .conditional
            .resolve(&point.root, parent, held)
            .map_err(|failure| at_position(position, failure))?;
        if root.economic_position() != position
            || accepted.economic_position() != position
            || accepted.genesis() != *genesis
            || accepted.device_id() != *device_id
        {
            return Err(invalid(format!(
                "position {position}: the conditional resolution answered for another coordinate \
                 (root at {}, claim of {}/{} at {})",
                root.economic_position(),
                encode_base32_crockford(&accepted.genesis()),
                encode_base32_crockford(&accepted.device_id()),
                accepted.economic_position()
            )));
        }
        Ok((root, accepted))
    }

    /// One step validated in full from its own evidence: the transition that
    /// produced the registered root, against its authenticated parent, with
    /// the SAME conjuncts any device runs.
    fn full_step(
        &self,
        genesis: &[u8; 32],
        device_id: &[u8; 32],
        position: u64,
        point: &ChainPoint,
        claim: &VerifiedEconomicRootClaim,
        role: StepRole,
    ) -> Result<ValidatedPeerTransition, PeerLineageFailure> {
        let Authenticated {
            manifest,
            manifest_addr,
            facts,
        } = self.authenticate(genesis, device_id, position, claim)?;
        let witness_bytes = self.fetcher.immutable(
            TAG_DSM_ECONOMIC_TRANSITION_WITNESS_OBJ,
            &manifest.transition_witness_addr,
        )?;
        let witness = crate::economic::decode::decode_transition_witness(&witness_bytes)
            .map_err(|e| invalid(format!("witness at {position}: {e}")))?;
        // The payments an offline boundary at this step exposes, recorded once
        // the step passes whole.
        let mut exposed: Vec<crate::types::offline_chain::ChainPayment> = Vec::new();
        let (accepted, substrate) = match &manifest.substrate {
            AdmissionSubstrate::DsmSuccessor {
                evidence_addr: successor_addr,
            } => {
                let successor_bytes = self
                    .fetcher
                    .immutable(TAG_DSM_ECONOMIC_SUCCESSOR_EVIDENCE, successor_addr)?;
                let verified = verify_dsm_successor_evidence(
                    &successor_bytes,
                    genesis,
                    device_id,
                    &facts.proven_ak,
                )
                .map_err(|e| invalid(format!("successor evidence at {position}: {e}")))?;
                if let StepRole::Source = role {
                    // A credit's source is a peer's online transfer. Its
                    // economic predecessors have already been established;
                    // its own debit has no credit source to resolve.
                    if !matches!(
                        verified.operation(),
                        crate::types::operations::Operation::Transfer {
                            authority_policy: None,
                            ..
                        }
                    ) {
                        return Err(invalid(format!(
                            "position {position}: the credit's source is not an online transfer"
                        )));
                    }
                }
                let peer = PeerSubstrate::Dsm {
                    c_dsm_plus: verified.c_dsm_plus(),
                    embedded_parent: verified.embedded_parent(),
                    verified_operation: verified.operation().clone(),
                };
                (
                    AcceptedSubstrate::from_verified_dsm_successor(verified),
                    peer,
                )
            }
            AdmissionSubstrate::OfflineBoundary { evidence_addr } => {
                if let StepRole::Source = role {
                    return Err(invalid(format!(
                        "position {position}: the credit's source is an offline boundary, not an \
                         online transfer"
                    )));
                }
                let body_bytes = self
                    .fetcher
                    .immutable(TAG_DSM_ECONOMIC_OFFLINE_BOUNDARY_EVIDENCE, evidence_addr)?;
                use crate::economic::offline_boundary::{offline_body_kind, OfflineBodyKind};
                let verified = match offline_body_kind(&body_bytes)
                    .map_err(|e| invalid(format!("offline body at {position}: {e}")))?
                {
                    // A settlement of value received offline: funded by the
                    // payer's spend the payer's online history exposed.
                    OfflineBodyKind::Settlement => self
                        .settlement(genesis, device_id, &body_bytes)
                        .map_err(|e| at_position(position, e))?,
                    OfflineBodyKind::Boundary => {
                        let (verified, payments) =
                            crate::economic::offline_boundary::OfflineBoundaryBody::verify(
                                &body_bytes,
                                genesis,
                                device_id,
                                &facts.proven_ak,
                            )
                            .map_err(|e| invalid(format!("offline boundary at {position}: {e}")))?;
                        // The account the latest boundary strictly below this one
                        // left, as this check validated it, else as this receiver
                        // recorded it.
                        let previous = match self
                            .offline_accounts
                            .borrow()
                            .iter()
                            .filter(|a| {
                                a.genesis == *genesis
                                    && a.device_id == *device_id
                                    && a.bundle == verified.bundle()
                                    && a.economic_position < position
                            })
                            .max_by_key(|a| a.economic_position)
                            .cloned()
                        {
                            Some(earlier) => Some(earlier),
                            None => self.records.offline_account_below(
                                genesis,
                                device_id,
                                &verified.bundle(),
                                position,
                            )?,
                        };
                        let since = verified.since().ok_or_else(|| {
                            invalid(format!(
                                "offline boundary at {position}: it moves no account"
                            ))
                        })?;
                        continues_the_account(since, previous.as_ref())
                            .map_err(|e| at_position(position, e))?;
                        exposed = payments;
                        verified
                    }
                };
                (
                    AcceptedSubstrate::from_verified_offline_boundary(verified, *evidence_addr),
                    PeerSubstrate::OfflineBoundary(verified),
                )
            }
        };
        let registered = RegisteredEconomicRoot::from_verified_single_root(claim);
        let ancestry = SourceAncestry { verifier: self };
        let no_sources = DebitHasNoSources { verifier: self };
        let provenance: &dyn ProvenanceResolver = match role {
            StepRole::Offered => &ancestry,
            StepRole::Source => &no_sources,
        };
        let advanced = advance_validated(
            &point.root,
            &registered,
            &manifest,
            &witness,
            &accepted,
            provenance,
            genesis,
            device_id,
            &facts.network_id,
            &facts.proven_ak,
        )
        .map_err(|e| step_failure(position, e))?;
        // The step passed whole: the EK steps its credits' acceptances verified
        // are this verifier's from here on.
        self.ek_steps
            .borrow_mut()
            .extend(advanced.ek_steps.iter().cloned());
        // The step passed whole: the offline account its boundary left is one
        // this receiver validated.
        if let PeerSubstrate::OfflineBoundary(boundary) = &substrate {
            self.offline_accounts
                .borrow_mut()
                .extend(PeerOfflineAccount::validated(
                    *genesis, *device_id, position, boundary,
                ));
            self.offline_exposures
                .borrow_mut()
                .extend(exposed.iter().map(|payment| PeerOfflineExposure {
                    genesis: *genesis,
                    device_id: *device_id,
                    economic_position: position,
                    bundle: boundary.bundle(),
                    payment: *payment,
                }));
        }
        Ok(ValidatedPeerTransition::single_root_from_walk(
            *genesis,
            *device_id,
            advanced.root,
            witness,
            facts.proven_ak,
            substrate,
            manifest_addr,
            advanced.claim,
        ))
    }

    /// A settlement of value received offline, verified: the payer's step that
    /// exposed the spend after its ancestry was established, which records what its boundary
    /// exposed, and the settlement held to exactly that exposed payment, to this
    /// device.
    fn settlement(
        &self,
        genesis: &[u8; 32],
        device_id: &[u8; 32],
        body_bytes: &[u8],
    ) -> Result<crate::economic::offline_boundary::VerifiedOfflineBoundary, PeerLineageFailure>
    {
        use crate::economic::offline_boundary::OfflineSettlementBody;
        let body = OfflineSettlementBody::decode(body_bytes)
            .map_err(|e| invalid(format!("an offline settlement body: {e}")))?;
        if body.exposed_at == 0 {
            return Err(invalid(
                "a settlement names the payer's activation root, where nothing is exposed",
            ));
        }
        self.validated_to(
            &body.payer_genesis,
            &body.payer_device,
            body.exposed_at,
            Target::Transition(StepRole::Offered),
        )?;
        let exposure = self
            .offline_exposures
            .borrow()
            .iter()
            .find(|e| {
                e.genesis == body.payer_genesis
                    && e.device_id == body.payer_device
                    && e.economic_position == body.exposed_at
                    && e.payment.release_message == body.release_message
            })
            .copied()
            .ok_or_else(|| {
                invalid("the payer's step at the settlement's position exposes no such payment")
            })?;
        OfflineSettlementBody::verify(body_bytes, genesis, device_id, &exposure)
            .map_err(|e| invalid(format!("an offline settlement: {e}")))
    }

    /// Every claim of `(genesis, device_id)` any member holds under
    /// `K_root(position)`, each once. A member holds each value as a route
    /// entry, the copy written at one position of some route: the value
    /// inside is the candidate, whatever route it was written along.
    fn held_claims(
        &self,
        genesis: &[u8; 32],
        device_id: &[u8; 32],
        position: u64,
    ) -> Result<Vec<RegisteredEconomicClaim>, PeerLineageFailure> {
        let key = economic_root_register_key(genesis, device_id, position);
        self.count(|c| c.register_probes += 1);
        let held = self
            .fetcher
            .register_key_values(genesis, device_id, position)?;
        let namespace = crate::economic::register::economic_root_namespace();
        let mut seen = std::collections::BTreeSet::new();
        Ok(held
            .iter()
            .filter_map(|bytes| crate::route_chain::RouteEntry::decode(bytes))
            .filter(|entry| entry.namespace == namespace && entry.key == key)
            .filter_map(|entry| root_claim_naming(&entry.value, &key))
            .filter(|claim| seen.insert(claim_identity(claim)))
            .collect())
    }

    /// Scan the requested positions while establishing the peer's history
    /// from activation. Every boundary the scan records comes from a step
    /// validated against the root established at the preceding position.
    fn offline_boundaries(
        &self,
        genesis: &[u8; 32],
        device_id: &[u8; 32],
        positions: std::ops::Range<u64>,
    ) -> Result<OfflineScan, PeerLineageFailure> {
        let mut reached = positions.start.saturating_sub(1);
        let mut point = ChainPoint {
            root: activate(EconomicActivationSnapshot::fresh())
                .map_err(|e| invalid(format!("activation shape: {e}")))?,
            accepted: None,
        };
        for position in 1..positions.end {
            if position >= positions.start {
                match self.held_claims(genesis, device_id, position) {
                    Ok(candidates) if candidates.is_empty() => {
                        return Ok(OfflineScan {
                            reached,
                            stop: ScanStop::Head,
                        });
                    }
                    Ok(_) => {}
                    Err(PeerLineageFailure::Incomplete(m) | PeerLineageFailure::Unresolved(m)) => {
                        return Ok(OfflineScan {
                            reached,
                            stop: ScanStop::Short(m),
                        });
                    }
                    Err(other) => return Err(other),
                }
            }
            match self.validated_position(genesis, device_id, position, point, Target::Root) {
                Ok((next, _, _)) => {
                    point = next;
                    if position >= positions.start {
                        reached = position;
                    }
                }
                Err(PeerLineageFailure::Incomplete(m) | PeerLineageFailure::Unresolved(m)) => {
                    return Ok(OfflineScan {
                        reached,
                        stop: ScanStop::Short(m),
                    });
                }
                Err(other) => return Err(other),
            }
        }
        Ok(OfflineScan {
            reached,
            stop: ScanStop::Bound,
        })
    }

    /// A credit's source: the source's own step at `position`, validated one
    /// hop. It is an online transfer, a debit that names no source of its
    /// own, so nothing behind it is read.
    fn source_step(
        &self,
        genesis: &[u8; 32],
        device_id: &[u8; 32],
        position: u64,
    ) -> Result<ValidatedPeerTransition, PeerLineageFailure> {
        if position == 0 {
            return Err(invalid(
                "position 0 is the activation root; it holds no debit to fund a credit",
            ));
        }
        self.count(|c| c.source_steps += 1);
        let (_, _, step) = self.validated_to(
            genesis,
            device_id,
            position,
            Target::Transition(StepRole::Source),
        )?;
        step.ok_or_else(|| invalid("the credit source has no online debit transition"))
    }
}

struct SourceAncestry<'v, 'a> {
    verifier: &'v Verifier<'a>,
}

/// The provenance of a credit's source step. That step is an online transfer,
/// whose write set is a debit: it names no credit source, so a question about
/// one means the step claims a credit an online transfer does not carry.
struct DebitHasNoSources<'v, 'a> {
    verifier: &'v Verifier<'a>,
}

impl ProvenanceResolver for SourceAncestry<'_, '_> {
    fn validated_peer_transition(
        &self,
        peer_genesis: &[u8; 32],
        peer_devid: &[u8; 32],
        peer_economic_position: u64,
    ) -> Result<ValidatedPeerTransition, PeerLineageFailure> {
        self.verifier
            .source_step(peer_genesis, peer_devid, peer_economic_position)
    }

    fn native_reserve_release(
        &self,
        reserve_id: &[u8; 32],
        generation: u64,
    ) -> Result<ReserveReleaseWin, PeerLineageFailure> {
        self.verifier
            .fetcher
            .native_reserve_release(reserve_id, generation)
    }

    fn root_register_candidate_set(
        &self,
        network_id: &[u8],
    ) -> Result<crate::ccb::StorageSetMembers, PeerLineageFailure> {
        self.verifier
            .fetcher
            .root_register_candidate_set(network_id)
    }

    fn immutable_evidence(
        &self,
        namespace: TaggedHashDomain<'static>,
        addr: &[u8; 32],
    ) -> Result<Vec<u8>, PeerLineageFailure> {
        self.verifier.fetcher.immutable(namespace, addr)
    }

    fn held_ek_step(
        &self,
        signer: &[u8; 32],
        addr: &[u8; 32],
    ) -> Result<Option<Vec<u8>>, PeerLineageFailure> {
        self.verifier.held_ek_step(signer, addr)
    }

    fn anchored_policy_bytes(
        &self,
        policy_commit: &[u8; 32],
    ) -> Result<Vec<u8>, PeerLineageFailure> {
        self.verifier.fetcher.anchored_policy_bytes(policy_commit)
    }
}

impl ProvenanceResolver for DebitHasNoSources<'_, '_> {
    fn validated_peer_transition(
        &self,
        peer_genesis: &[u8; 32],
        peer_devid: &[u8; 32],
        peer_economic_position: u64,
    ) -> Result<ValidatedPeerTransition, PeerLineageFailure> {
        Err(invalid(format!(
            "an online transfer's step names a credit funded by {}/{} at position \
             {peer_economic_position}; its write set is a debit and carries no credit",
            encode_base32_crockford(peer_genesis),
            encode_base32_crockford(peer_devid),
        )))
    }

    fn native_reserve_release(
        &self,
        reserve_id: &[u8; 32],
        generation: u64,
    ) -> Result<ReserveReleaseWin, PeerLineageFailure> {
        Err(invalid(format!(
            "an online transfer's step names a credit from reserve {} at generation \
             {generation}; its write set is a debit and carries no credit",
            encode_base32_crockford(reserve_id),
        )))
    }

    fn root_register_candidate_set(
        &self,
        network_id: &[u8],
    ) -> Result<crate::ccb::StorageSetMembers, PeerLineageFailure> {
        self.verifier
            .fetcher
            .root_register_candidate_set(network_id)
    }

    fn immutable_evidence(
        &self,
        namespace: TaggedHashDomain<'static>,
        addr: &[u8; 32],
    ) -> Result<Vec<u8>, PeerLineageFailure> {
        self.verifier.fetcher.immutable(namespace, addr)
    }

    fn held_ek_step(
        &self,
        signer: &[u8; 32],
        addr: &[u8; 32],
    ) -> Result<Option<Vec<u8>>, PeerLineageFailure> {
        self.verifier.held_ek_step(signer, addr)
    }

    fn anchored_policy_bytes(
        &self,
        policy_commit: &[u8; 32],
    ) -> Result<Vec<u8>, PeerLineageFailure> {
        self.verifier.fetcher.anchored_policy_bytes(policy_commit)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::economic::claim_envelope::device_fixture::{device, signed_conditional, Device};

    const NETWORK: &[u8] = b"dsm-testnet";
    const PEER_G: [u8; 32] = [0x11; 32];

    /// The peer device: its id is derived from its key and AttA, so the
    /// claims it signs name its own cells (DSM Amendment A10).
    fn peer() -> &'static Device {
        static PEER: std::sync::OnceLock<Device> = std::sync::OnceLock::new();
        PEER.get_or_init(|| device([0xA7; 32]).expect("the peer device"))
    }

    fn peer_d() -> [u8; 32] {
        peer().devid
    }

    /// `claim` as the peer's root cell holds it: signed by the peer device
    /// (SoFi Amendment S20).
    fn peer_c_q(claim: SofiResolutionClaim) -> Vec<u8> {
        signed_conditional(claim, peer()).expect("the peer signs its own C_q")
    }

    fn conditional_claim(position: u64) -> SofiResolutionClaim {
        SofiResolutionClaim {
            genesis: PEER_G,
            device_id: peer_d(),
            position,
            fulfillment_id: [0xF1; 32],
            realize_root: [0xA1; 32],
            void_root: [0xB1; 32],
        }
    }

    /// `writes` along the route of the root cell at each listed position, in
    /// order, through the whole route. Everything else refuses, because none
    /// of it should be reached.
    struct CellsAt {
        held: Vec<(u64, Vec<Vec<u8>>)>,
        register_set: NoEvidence,
    }

    impl CellsAt {
        fn new(held: Vec<(u64, Vec<Vec<u8>>)>) -> Self {
            Self {
                held,
                register_set: NoEvidence,
            }
        }
    }

    impl PeerEvidenceFetcher for CellsAt {
        fn register_key_values(
            &self,
            genesis: &[u8; 32],
            device_id: &[u8; 32],
            position: u64,
        ) -> Result<Vec<Vec<u8>>, PeerLineageFailure> {
            self.register_set
                .register_key_values(genesis, device_id, position)
        }

        fn register_cell(&self, cell: &RootCell) -> Result<CellEvidence, PeerLineageFailure> {
            let mut seats = crate::route_chain::fixtures::Cell::at(cell.routed());
            for (_, writes) in self
                .held
                .iter()
                .filter(|(at, _)| *at == cell.economic_position())
            {
                for value in writes {
                    seats.write(value, crate::route_chain::ROUTE_LEN - 1, &[]);
                }
            }
            Ok(seats.evidence())
        }

        fn native_reserve_release(
            &self,
            reserve_id: &[u8; 32],
            generation: u64,
        ) -> Result<ReserveReleaseWin, PeerLineageFailure> {
            self.register_set
                .native_reserve_release(reserve_id, generation)
        }

        fn root_register_candidate_set(
            &self,
            network_id: &[u8],
        ) -> Result<crate::ccb::StorageSetMembers, PeerLineageFailure> {
            self.register_set.root_register_candidate_set(network_id)
        }

        fn immutable(
            &self,
            namespace: TaggedHashDomain<'static>,
            addr: &[u8; 32],
        ) -> Result<Vec<u8>, PeerLineageFailure> {
            self.register_set.immutable(namespace, addr)
        }

        fn held_ek_step(
            &self,
            signer: &[u8; 32],
            addr: &[u8; 32],
        ) -> Result<Option<Vec<u8>>, PeerLineageFailure> {
            self.register_set.held_ek_step(signer, addr)
        }

        fn anchored_policy_bytes(
            &self,
            policy_commit: &[u8; 32],
        ) -> Result<Vec<u8>, PeerLineageFailure> {
            self.register_set.anchored_policy_bytes(policy_commit)
        }
    }

    struct NoneRecorded;

    impl OfflineRecords for NoneRecorded {
        fn offline_account_below(
            &self,
            _genesis: &[u8; 32],
            _device_id: &[u8; 32],
            _bundle: &[u8; 32],
            _position: u64,
        ) -> Result<Option<PeerOfflineAccount>, PeerLineageFailure> {
            Ok(None)
        }
    }

    struct NoEvidence;

    impl PeerEvidenceFetcher for NoEvidence {
        fn register_key_values(
            &self,
            _genesis: &[u8; 32],
            _device_id: &[u8; 32],
            _position: u64,
        ) -> Result<Vec<Vec<u8>>, PeerLineageFailure> {
            Err(incomplete("no register values were supplied"))
        }

        fn register_cell(&self, _cell: &RootCell) -> Result<CellEvidence, PeerLineageFailure> {
            Err(incomplete("no root cell was supplied"))
        }

        fn native_reserve_release(
            &self,
            _reserve_id: &[u8; 32],
            _generation: u64,
        ) -> Result<ReserveReleaseWin, PeerLineageFailure> {
            Err(incomplete("no reserve release was supplied"))
        }

        fn root_register_candidate_set(
            &self,
            network_id: &[u8],
        ) -> Result<crate::ccb::StorageSetMembers, PeerLineageFailure> {
            let members = crate::economic::register::pinned_root_register_members(network_id)
                .map_err(|e| incomplete(e.to_string()))?;
            crate::ccb::StorageSetMembers::new(members).map_err(|e| incomplete(format!("{e:?}")))
        }

        fn immutable(
            &self,
            _namespace: TaggedHashDomain<'static>,
            _addr: &[u8; 32],
        ) -> Result<Vec<u8>, PeerLineageFailure> {
            Err(incomplete("no immutable object was supplied"))
        }

        fn held_ek_step(
            &self,
            _signer: &[u8; 32],
            _addr: &[u8; 32],
        ) -> Result<Option<Vec<u8>>, PeerLineageFailure> {
            Err(incomplete("no relationship step was supplied"))
        }

        fn anchored_policy_bytes(
            &self,
            _policy_commit: &[u8; 32],
        ) -> Result<Vec<u8>, PeerLineageFailure> {
            Err(incomplete("no token policy was supplied"))
        }
    }

    struct NoResolution;

    impl ConditionalPositionResolver for NoResolution {
        fn resolve(
            &self,
            _previous: &ValidatedEconomicRoot,
            _parent: &ParentClaimRef,
            _held: &SofiResolutionClaim,
        ) -> Result<(ValidatedEconomicRoot, AcceptedClaim), PeerLineageFailure> {
            Err(incomplete("no SoFi resolution was supplied"))
        }
    }

    #[test]
    fn an_offline_boundary_continues_only_an_established_account() {
        use crate::economic::offline_boundary::BoundarySince;
        let previous =
            PeerOfflineAccount::rehydrate_recorded([1; 32], [2; 32], 3, [3; 32], [4; 32], [5; 32]);
        continues_the_account(BoundarySince::Opened { frontier: [6; 32] }, None)
            .expect("the first boundary opens its account");
        continues_the_account(
            BoundarySince::Previous {
                account_root: [4; 32],
            },
            Some(&previous),
        )
        .expect("a later boundary continues the established account");
        assert!(matches!(
            continues_the_account(
                BoundarySince::Previous {
                    account_root: [4; 32]
                },
                None
            ),
            Err(PeerLineageFailure::Invalid(_))
        ));
        assert!(matches!(
            continues_the_account(
                BoundarySince::Previous {
                    account_root: [7; 32]
                },
                Some(&previous)
            ),
            Err(PeerLineageFailure::Invalid(_))
        ));
        assert!(matches!(
            continues_the_account(BoundarySince::Opened { frontier: [6; 32] }, Some(&previous)),
            Err(PeerLineageFailure::Invalid(_))
        ));
    }

    #[test]
    fn a_reached_validation_budget_never_reads_or_accepts_a_step() {
        let fetcher = NoEvidence;
        let resolver = NoResolution;
        let verifier =
            Verifier::new(&fetcher, NETWORK, &NoneRecorded, &resolver).expect("pinned register");
        let mut cost = verifier.cost.get();
        cost.steps_validated = VALIDATION_STEP_BUDGET;
        verifier.cost.set(cost);
        match verifier.validated_to(&[1; 32], &[2; 32], 1, Target::Root) {
            Err(PeerLineageFailure::Incomplete(why)) => {
                assert!(why.contains("budget"), "{why}");
            }
            Err(other) => panic!("the budget must be incomplete: {other:?}"),
            Ok(_) => panic!("a reached budget cannot establish a root"),
        }
    }

    #[test]
    fn a_cyclic_credit_dependency_never_becomes_a_valid_root() {
        let fetcher = NoEvidence;
        let resolver = NoResolution;
        let verifier =
            Verifier::new(&fetcher, NETWORK, &NoneRecorded, &resolver).expect("pinned register");
        verifier.active.borrow_mut().insert(([1; 32], [2; 32], 1));
        match verifier.validated_to(&[1; 32], &[2; 32], 1, Target::Root) {
            Err(PeerLineageFailure::Invalid(why)) => {
                assert!(why.contains("cyclic economic ancestry"), "{why}");
            }
            Err(other) => panic!("a cycle must be invalid: {other:?}"),
            Ok(_) => panic!("a cyclic dependency cannot establish a root"),
        }
    }

    /// `peer_root_at` at position 0 is the activation root, where no claim was
    /// accepted: no `P` can name it as a parent, so it is `Invalid`, and no
    /// reference is made up for it. `NoEvidence` answers `Incomplete` to every
    /// read, so `Invalid` also shows nothing was read.
    #[test]
    fn the_activation_root_names_no_parent() {
        match peer_root_at(
            &NoEvidence,
            NETWORK,
            &PEER_G,
            &peer_d(),
            0,
            &NoneRecorded,
            &NoResolution,
        ) {
            Err(PeerLineageFailure::Invalid(why)) => {
                assert!(why.contains("activation root"), "{why}")
            }
            Err(other) => panic!("position 0 is Invalid, not {other:?}"),
            Ok(_) => panic!("position 0 names no parent"),
        }
    }

    /// A CONDITIONAL PEER POSITION IS `Unresolved`, NOT `Invalid`: the peer is
    /// mid-route, not forging, and no single transition exists there yet.
    #[test]
    fn a_conditional_peer_position_is_unresolved_and_never_invalid() {
        let fetcher = CellsAt::new(vec![(1, vec![peer_c_q(conditional_claim(1))])]);
        match validate_peer_step(
            &fetcher,
            NETWORK,
            &PEER_G,
            &peer_d(),
            1,
            &NoneRecorded,
            &NoResolution,
        ) {
            Err(PeerLineageFailure::Unresolved(why)) => {
                assert!(why.contains("no transition"), "{why}")
            }
            Err(other) => panic!("a conditional position must be Unresolved, got {other:?}"),
            Ok(_) => panic!("a conditional position cannot produce a validated transition"),
        }
    }

    /// NO PATH from a conditional cell to a validated root: neither branch of
    /// an unresolved `C_q` is minted, and neither appears in the refusal.
    #[test]
    fn no_validated_root_is_minted_from_either_branch_of_an_unresolved_claim() {
        let claim = conditional_claim(1);
        let fetcher = CellsAt::new(vec![(1, vec![peer_c_q(claim)])]);
        let rendered = match validate_peer_step(
            &fetcher,
            NETWORK,
            &PEER_G,
            &peer_d(),
            1,
            &NoneRecorded,
            &NoResolution,
        ) {
            Err(refused) => refused.to_string(),
            Ok(_) => panic!("no validated transition"),
        };
        for (name, root) in [
            ("realize_root", claim.realize_root),
            ("void_root", claim.void_root),
        ] {
            let b32 = encode_base32_crockford(&root);
            assert!(
                !rendered.contains(&b32),
                "{name} leaked into the refusal: {rendered}"
            );
        }
    }

    /// A credit's source at a conditional position is not an online transfer:
    /// a validated peer debit refuses a SoFi position (MR-SOFI-0196).
    #[test]
    fn a_source_at_a_conditional_position_is_invalid() {
        let fetcher = CellsAt::new(vec![(1, vec![peer_c_q(conditional_claim(1))])]);
        let verifier = Verifier::new(&fetcher, NETWORK, &NoneRecorded, &NoResolution)
            .expect("the network's register");
        match verifier.validated_to(&PEER_G, &peer_d(), 1, Target::Transition(StepRole::Source)) {
            Err(PeerLineageFailure::Invalid(why)) => {
                assert!(why.contains("not an online debit"), "{why}")
            }
            Err(other) => panic!("a conditional source must be Invalid, got {other:?}"),
            Ok(_) => panic!("a conditional position is not a debit"),
        }
    }

    /// No claim is accepted at the activation root, so nothing can name it as
    /// a parent: a conditional position right after it is `Invalid`, and the
    /// resolver is never asked. `NoResolution` answers `Incomplete`, so
    /// `Invalid` shows it was not reached.
    #[test]
    fn a_conditional_position_right_after_the_activation_root_is_invalid() {
        let activation = activate(EconomicActivationSnapshot::fresh())
            .expect("the activation root")
            .economic_root();
        let fetcher = CellsAt::new(vec![(
            1,
            vec![peer_c_q(SofiResolutionClaim {
                void_root: activation,
                ..conditional_claim(1)
            })],
        )]);
        match peer_root_at(
            &fetcher,
            NETWORK,
            &PEER_G,
            &peer_d(),
            1,
            &NoneRecorded,
            &NoResolution,
        ) {
            Err(PeerLineageFailure::Invalid(why)) => {
                assert!(why.contains("cannot follow the activation root"), "{why}")
            }
            Err(other) => panic!("it must be Invalid, got {other:?}"),
            Ok(_) => panic!("no conditional position follows the activation root"),
        }
    }

    /// A claim naming other coordinates is never a candidate at this peer's
    /// cell: a cell holding only foreign claims holds nothing of this peer,
    /// which is a liveness outcome and never a verdict (MR-DSM-0046).
    #[test]
    fn a_claim_naming_other_coordinates_is_never_a_candidate() {
        let other = device([0x5A; 32]).expect("another device");
        let foreign = SofiResolutionClaim {
            genesis: [0x99; 32],
            device_id: other.devid,
            ..conditional_claim(1)
        };
        let ours = conditional_claim(1);
        let check = |writes: Vec<Vec<u8>>| {
            validate_peer_step(
                &CellsAt::new(vec![(1, writes)]),
                NETWORK,
                &PEER_G,
                &peer_d(),
                1,
                &NoneRecorded,
                &NoResolution,
            )
        };
        match check(vec![
            signed_conditional(foreign, &other).expect("its own C_q")
        ]) {
            Err(PeerLineageFailure::Incomplete(why)) => {
                assert!(why.contains("no claim holds the root cell"), "{why}")
            }
            Err(other) => panic!("a foreign claim holds nothing of this peer: {other:?}"),
            Ok(_) => panic!("a foreign claim is never accepted"),
        }
        assert!(
            matches!(
                check(vec![
                    signed_conditional(foreign, &other).expect("its own C_q"),
                    peer_c_q(ours),
                ]),
                Err(PeerLineageFailure::Unresolved(_))
            ),
            "the foreign claim does not hide this peer's own"
        );
    }
}
