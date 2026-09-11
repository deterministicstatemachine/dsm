// SPDX-License-Identifier: MIT OR Apache-2.0
//! Vault-state composition — quote-time derivation of a vault's canonical
//! current state from its published, verified artifacts.
//!
//! Baseline
//! --------
//! The baseline is the owner's `AnchorPresentationV3` plus the exact
//! `CCB(V_n)` bytes its anchor commits. `verify_anchor_presentation` runs the
//! full P0–P6 owner-authority predicate and re-hashes the bytes against the
//! signed `c_n`, so everything the old anchor stack restated — sequence,
//! reserves, pair, fee, storage set, owner identity — is read out of ONE
//! authenticated object with one identity:
//!
//! ```text
//! c_n = H_dom(DSM/vault-state, CCB(V_n))
//! ```
//!
//! There is no inclusion proof, no reserve proof, no birth anchor and no
//! `/latest` here — those were parallel restatements of state facts, and the
//! state-identity cut removes the duplicate sources rather than
//! cross-checking them.
//!
//! The frontier walk
//! -----------------
//! On top of the verified baseline the composer walks FORWARD one generation
//! at a time, and the edge source is the settlement-slot REGISTER CELL read
//! live at the quorum the owner committed in `V_n` (field 15), against the
//! storage set `V_n` names.
//!
//! That inversion is the point. A prefix listing's exhaustiveness is
//! unfalsifiable: a member that omits a key produces an answer no signature
//! can distinguish from a genuinely shorter chain, so a composer reading one
//! could only ever report a valid PREFIX while sounding like it reported the
//! latest state. A write-once cell cannot express omission — it either holds
//! a claim or it does not — so `q` attributed members answering "nothing
//! here" is a positive fact, and it is the only thing that ends the walk.
//!
//! Each generation therefore has four outcomes:
//!
//! ```text
//! free at quorum        -> the chain ends here; THIS is the frontier
//! bound + realized      -> fold and continue
//! bound + not realized  -> the chain ends here, and the frontier is BOUND
//! anything else         -> DLV_BINDING_EVIDENCE_UNAVAILABLE, or the edge is INVALID
//! ```
//!
//! An owner CLOSE realizes on binding finality: its successor is fully
//! determined and pre-authorized (Req 6.30). A MARKET edge realizes only when
//! CERTIFIED (amendment 2c-D §14, C2): the trader's `TA_B`, located by `b` and
//! fetched by content address, passes 2c-D §7 against the trader's own
//! validated lineage; the accepted operation corresponds to the bundle
//! (CORR.1–CORR.5, typed); the trade satisfies its signed intent (2c-E §6); and
//! the published receipt's facts are the settlement receipt the trader's
//! validated transition committed under `R_T^+` (Req 21.16, D4 as corrected).
//! The receipt is Req 21.16's EVIDENCE and never authority. Evidence not yet
//! published leaves the frontier bound-but-unrealized; evidence present and
//! failing verification is INVALID. A close consumes the same cell — close and
//! settle contend for one slot per generation.
//!
//! Nothing here is a portable proof of maximality, and nothing claims to be:
//! the statement is "during this read, no successor beyond `c_n` was
//! established". Frontier is inherently online.
//!
//! The pending-pointer records still exist as a DISCOVERY HINT for the owner's
//! own reconcile (`unapplied_settlements_for_vault`), which understates rather
//! than invents. They are not consulted here: a self-signed pointer never
//! established that an edge exists, and the cell now does.
//!
//! The composed result is a full `VaultStateV2` with a canonical identity of
//! its own: the `c_n` a new trade's hop must bind as its parent.

use dsm::ccb::VaultStateV2;
use dsm::dlv::published_receipt::{verify_published_receipt, VerifiedReceipt};
use dsm::dlv::settlement_receipt_leaf::{derive_receipt_id, SignedTraderSettlementReceipt};
use dsm::dlv::successor_validity::{
    check_correspondence, check_intent_satisfaction, check_market_correspondence,
    derive_accepted_market_successor, derive_close_successor, AcceptedTransition,
    BundleCoordinates, C3Verdict, CompleteValidity, DeriveExpected, IndependentRealization,
    IntentEvidence, IntentSatisfaction, OutcomeClass, Reason,
};
use dsm::economic::provenance::{PeerLineageFailure, ProvenanceResolver as _, ValidatedPeerTransition};
use dsm::types::operations::Operation;
use prost::Message;

use crate::sdk::bitcoin_tap_sdk::BitcoinTapSdk;
use crate::sdk::identity_presentation::verify_anchor_presentation;

/// Maximum pending-chain depth a composer will fold before treating the
/// vault as saturated and excluding it from path search.  Caps adversarial
/// pointer-flooding cost at O(MAX_PENDING_CHAIN_DEPTH) signature verifies
/// per quote.
pub(crate) const MAX_PENDING_CHAIN_DEPTH: usize = 64;

/// A parent the fold consumed on its way to the frontier — see
/// [`ComposedVaultState::folded_parents`].
#[derive(Debug, Clone)]
pub(crate) struct FoldedParent {
    pub generation: u64,
    /// `vault_state_commitment(&state)`, computed by the walk.
    pub c_n: [u8; 32],
    pub state: VaultStateV2,
    /// `b` of the binding-final bundle that owned this parent and whose
    /// successor this walk realized. Every fold now has one.
    pub bound_by: [u8; 32],
    /// Which KIND of consumer owned it. A resumed close must be able to tell
    /// its own fold from a market settle that landed at the same generation.
    pub bound_kind: dsm::dlv::settlement_bundle::BundleShape,
    /// What C3 concluded about the successor this fold produced — always
    /// [`C3Verdict::Valid`], because the walk folds nothing that fails
    /// `may_certify()` (2c-D §14). An owner close reaches it through
    /// `VDS.COMMON.10.a`; a market fold only through the independent
    /// realization fact — correspondence, the §7 bundle acceptance and intent
    /// satisfaction, together.
    pub verdict: C3Verdict,
    /// For a CERTIFIED market fold, the settlement it realized — Req 21.16's
    /// typed fact, proven under the trader's validated `R_T^+`. `None` for a
    /// close. This is what an owner's reconcile acts on (2c-D §14, C2-R1
    /// point 6): the exact certified fold, never a receipt read on the side.
    pub realized_trade: Option<VerifiedReceipt>,
    /// For a CERTIFIED market fold, the exact `TA_B` 2c-D §7 accepted for it —
    /// the acceptance the Def 14.2 receipt binds (amendment 2c-F). `None` for
    /// a close. Carried so the receipt is built from what certified, never
    /// from an acceptance fetched again afterwards.
    pub certified_acceptance: Option<dsm::economic::trader_acceptance::TraderAcceptance>,
    /// For a CERTIFIED market fold, the trader's payment exactly as Req 21.16
    /// proved it — what the owner's catch-up funds its `0x0027` apply from
    /// (amendment 2c-G). `None` for a close.
    pub certified_payment: Option<CertifiedPayment>,
}

/// The trader's settlement payment exactly as Req 21.16 proved it: the
/// `0x0021` receipt leaf and its 256-sibling path under the VALIDATED `R_T^+`
/// at the trader's own economic position (amendment 2c-G).
///
/// Carried on the certified fold for the reason `certified_acceptance` is:
/// the owner's catch-up builds its `0x0027` evidence from the material
/// certification checked, never from an inclusion proof fetched again
/// afterwards. HOLDING ONE ASSERTS NOTHING — the `0x0027` arm re-derives the
/// trader's root at `trader_economic_position` and re-proves the leaf into it.
#[derive(Debug, Clone)]
pub(crate) struct CertifiedPayment {
    /// The trader as the walk authenticated it: the acceptance's genesis and
    /// the bundle's own settler.
    pub trader_genesis: [u8; 32],
    pub trader_devid: [u8; 32],
    /// The position whose validated root the walk proved the leaf under.
    pub trader_economic_position: u64,
    /// The exact leaf the trader's inclusion proof committed, and its path.
    pub receipt: dsm::economic::state::EconomicSettlementReceiptState,
    pub receipt_siblings: Box<[[u8; 32]; dsm::economic::tree::ECONOMIC_SMT_HEIGHT]>,
}

/// What the binding register — plus this device's own fence table — says about
/// the REALIZED frontier `c_n`, at the moment of this walk.
///
/// Only these three are reachable: `Undetermined` and `Unavailable` never
/// return a composition at all, they fail closed as
/// [`CompositionError::BindingEvidenceUnavailable`]; duplicate binding
/// finality and a durable quarantine root fail closed as
/// [`CompositionError::SafetyViolation`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum FrontierBinding {
    /// `q` attributed members hold nothing at `k(c_n)`: the parent is available
    /// to a competing candidate right now.
    Free,
    /// A binding-final bundle owns `c_n` and this walk did NOT realize its
    /// successor. The state, reserves and `c_n` reported alongside this ARE the
    /// realized frontier — and quoting, pointer-publishing or binding against
    /// that `c_n` will lose at bind time.
    BoundUnrealized {
        bundle_digest: [u8; 32],
        /// The X this walk already verified out of the bound bundle, so a
        /// settle can tell ITS OWN trade's bundle from a stranger's without
        /// re-fetching bytes the walk just read.
        route_set_commitment: [u8; 32],
    },
    /// CLIENT-LOCAL, never register evidence and never published: THIS device
    /// holds an unresolved DLV transaction over this exact parent. The register
    /// may well say `Free` — the transaction's outcome simply is not known
    /// here. Nothing on this device may advance the parent (Req 6.23 (2));
    /// other devices are unaffected.
    ///
    /// Well-defined for the owner's OWN close only: `dlv_close` fences on
    /// `(vault_id, c_n)`, while a market settle fences the TRADER's chain, so
    /// the walk cannot see a foreign trader's in-flight bind through this table
    /// — that is exactly what the register's `Undetermined` answer is for.
    LocallyFenced { tx_id: [u8; 32] },
    /// Composition STOPPED at a requested state and deliberately did not read
    /// its binding — produced only by [`compose_vault_history_until`] for
    /// reserve provenance (2c-D §14). It says nothing about availability, and
    /// no route may act on it.
    NotObserved,
}

/// Where the owner's `EconomicProofArtifactV1` lives, as an unsigned
/// advertisement claims. Both halves travel together because neither is usable
/// alone: the address names the artifact, and the position names the register
/// cell whose root every inclusion path is re-derived against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct OwnerEconomicProofLocator {
    pub addr: [u8; 32],
    pub position: u64,
}

/// Result of composing pending pointers onto a presentation-verified
/// baseline.
#[derive(Debug, Clone)]
pub(crate) struct ComposedVaultState {
    /// The composed state itself — the baseline `V_n` when no pointers
    /// folded, the constructed successor otherwise. Every fact a consumer
    /// needs (generation, reserves, pair, fee, storage set, encumbrances,
    /// authority position) is a field of this one object.
    pub state: VaultStateV2,
    /// `c_n` of `state` — the canonical identity of the state this walk
    /// reached, and the exact value a new trade's hop must carry as
    /// `parent_binding`.
    ///
    /// This IS a proven frontier for the live read that produced it: the walk
    /// terminated because q attributed members of the vault's own committed
    /// storage set each answered that the settlement-slot cell at this
    /// generation holds nothing. A composition that could not establish that
    /// is not returned at all — it fails closed as
    /// [`CompositionError::BindingEvidenceUnavailable`] — so this value can
    /// never be a silently-short prefix.
    ///
    /// It is NOT a portable proof of maximality, and nothing here claims one:
    /// the statement is "during this read, no successor beyond `c_n` was
    /// established", which is only true of the moment it was read.
    pub c_n: [u8; 32],
    /// `state.generation`, broken out for callers that only order by it.
    pub sequence: u64,
    /// The parent CONSUMED by each successful fold, oldest first: its
    /// generation, its `c_n`, and the state itself. This is how a caller
    /// reconciling a settlement N generations back names the exact historical
    /// parent state that settlement consumed — and proves its trade against
    /// that state's own reserves and fee — from the chain the composition
    /// itself verified: no re-derivation and no second source.
    pub folded_parents: Vec<FoldedParent>,
    /// `state.reserve_a` / `state.reserve_b`, broken out for AMM math.
    pub reserves_a: u64,
    pub reserves_b: u64,
    /// How many successor edges this walk verified and folded to reach the
    /// frontier.
    ///
    /// There is deliberately no companion "skipped" count any more. Under the
    /// prefix-listing fold a skip was routine — anyone could publish a
    /// self-signed pointer, so unfoldable ones had to be ignored rather than
    /// allowed to suppress the vault. Under the cell walk there is no such
    /// category: an edge either does not exist (empty at quorum), or exists
    /// and validates (folded here), or exists and does not
    /// (`BindingEvidenceUnavailable`). A count of quietly-ignored edges would
    /// have nothing to hold.
    pub pending_chain_len: usize,
    /// The vault owner, proven by the presentation's P0–P6 chain at the
    /// state's own committed authority position. Constant across generations
    /// — market successors copy the authority position byte-for-byte.
    pub owner_devid: [u8; 32],
    pub owner_genesis: [u8; 32],
    pub owner_public_key: Vec<u8>,
    /// The owner's `EconomicProofArtifactV1` locator, copied verbatim from the
    /// advertisement the discovered path already fetched and decoded.
    ///
    /// `None` on paths that had no advertisement to read it from — the owner's
    /// own, which keeps its copy in `amm_vault_records`. Absence is explicit
    /// rather than an all-zero address, so a caller cannot mistake "not
    /// carried here" for "the owner published nothing".
    ///
    /// A LOCATOR, AND ONLY A LOCATOR. The advertisement is unsigned and
    /// authenticates nothing, so this is a hint about where to look, never a
    /// fact. A reader resolves the position's root from the
    /// owner's own write-once register cell and re-derives every inclusion
    /// path against it, so a wrong address or position here can only make the
    /// lookup FAIL — never succeed against a root the owner did not register.
    /// Surfaced because a settling TRADER holds no `amm_vault_record` and has
    /// no other way to reach it; the owner keeps its own copy locally.
    pub owner_economic_proof: Option<OwnerEconomicProofLocator>,
    /// `AuthorityEvidenceV1` bytes for this vault's owner, re-encoded from
    /// the SAME six values the presentation just authenticated.
    ///
    /// Not a second owner-authority format and not a second authentication:
    /// `AnchorPresentationV3` fields 4–9 ARE `AuthorityEvidenceV1` fields
    /// 1–6, and `verify_anchor_presentation` resolved them through the same
    /// resolver at the same position (`V_n.owner_authority_transition_digest`)
    /// that `verify_authority_evidence` uses. Carried from here so a consumer
    /// takes the bytes that were checked, rather than re-fetching an object
    /// that could differ from the one this composition trusted.
    pub owner_authority_evidence: Vec<u8>,
    /// `storage_set_id = H_dom(DSM/storage-set, CCB(S))` over the state's OWN
    /// storage-set member list — a derived view of a `V_n` field, never a
    /// second source. Consumers resolve it through their local catalog.
    pub storage_set_id: [u8; 32],
    /// Whether the realized frontier above is also FREE to be bound by a new
    /// candidate. A caller that stamps `c_n` as a hop's parent binding, or
    /// publishes a pointer against it, must consult this: a bound parent
    /// produces a quote that is guaranteed to lose.
    pub frontier_binding: FrontierBinding,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CompositionError {
    /// The presentation failed P0–P6, the `CCB(V_n)` bytes do not hash to the
    /// anchor's commitment, or the bytes do not strictly decode. Fail closed
    /// — without an authenticated baseline the entire composition is moot.
    InvalidBaselinePresentation(String),
    /// The baseline verified, but it describes a different market than the
    /// caller asked to compose: wrong vault id, wrong pair, or wrong fee.
    /// The signed state is authoritative; a disagreeing caller tuple means
    /// the caller's view is stale or fabricated.
    BaselineMismatch(String),
    // `StorageListFailed` and `PointerDecodeFailed` were DELETED here. Both had
    // zero construction sites workspace-wide — leftovers of the pre-cell
    // prefix-listing fold, kept alive only by their own Display arms. Amendment
    // 2c-C3 splits this taxonomy; translating dead classes forward would have
    // carried two of them into the new one.
    /// The caller names the pair by something other than 32-byte policy
    /// commits, so it cannot be matched against the signed state's market
    /// policy. FAILS CLOSED — a label is not an identity.
    PairIsNotPolicyCommits,
    /// Req 6.25 `DLV_BINDING_EVIDENCE_UNAVAILABLE`: the walk could not
    /// establish where this vault's chain ends, so no state is returned and
    /// the vault is excluded from routing.
    ///
    /// This is the ONE outcome that must never be softened into a short
    /// answer. It covers: fewer than the committed `q` members giving an
    /// attributed answer for a slot cell; members holding divergent values for
    /// one write-once cell; a quorum-established slot winner whose settlement
    /// evidence cannot be fetched or verified; and depth saturation. An
    /// adversary who wins a slot and never settles can hold a vault here
    /// indefinitely — that is a liveness cost, and it is strictly preferable
    /// to manufacturing a maximality claim the network did not support.
    BindingEvidenceUnavailable(String),
    /// A C3 conjunct decided AGAINST this successor.
    ///
    /// The distinction from `BindingEvidenceUnavailable` is the whole point of
    /// the split: a forged successor, a bundle that names another vault's
    /// parent, and an unauthorized close are all DECIDABLY FALSE, and reporting
    /// them under an `INCOMPLETE`-shaped name told a caller to retry something
    /// that can never succeed.
    SuccessorInvalid { reason: Reason, detail: String },
    /// Req 6.3 — a proven contradiction in the storage substrate.
    ///
    /// Never a failed check, and never tie-broken: two binding-final bundles at
    /// one parent means either continuation may already have been relied upon,
    /// so picking one converts a detected safety failure into a blessed fork.
    SafetyViolation { reason: Reason, detail: String },
}

impl std::fmt::Display for CompositionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CompositionError::InvalidBaselinePresentation(msg) => {
                write!(f, "baseline presentation failed verification: {msg}")
            }
            CompositionError::BaselineMismatch(msg) => {
                write!(
                    f,
                    "baseline disagrees with the caller's market tuple: {msg}"
                )
            }
            CompositionError::PairIsNotPolicyCommits => write!(
                f,
                "caller pair must be 32-byte policy commits so it can be matched to the signed \
                 state's market policy"
            ),
            CompositionError::BindingEvidenceUnavailable(msg) => {
                write!(f, "DLV_BINDING_EVIDENCE_UNAVAILABLE: {msg}")
            }
            CompositionError::SuccessorInvalid { reason, detail } => {
                write!(f, "{}: {detail}", reason.as_str())
            }
            CompositionError::SafetyViolation { reason, detail } => {
                write!(f, "STORAGE_SAFETY_VIOLATION {}: {detail}", reason.as_str())
            }
        }
    }
}

impl std::error::Error for CompositionError {}

/// Fold pending pointers onto a presentation-verified baseline.
///
/// `presentation` + `vn_bytes` are the owner's published verification bundle
/// and the exact `CCB(V_n)` bytes its anchor commits — both fetched through
/// the immutable store (which already re-hashed the bytes against the
/// requested identity) or built locally by the owner. Verification here is
/// full P0–P6; nothing is trusted as presented.
///
/// `(token_a, token_b, fee_bps)` is the market tuple the caller intends to
/// quote. It is checked AGAINST the signed state and refused on mismatch —
/// the state is authoritative, the tuple is the caller's intent.
pub(crate) async fn compose_vault_state(
    vault_id: &[u8; 32],
    presentation: &crate::generated::AnchorPresentationV3,
    vn_bytes: &[u8],
    token_a: &[u8],
    token_b: &[u8],
    fee_bps: u32,
) -> Result<ComposedVaultState, CompositionError> {
    compose_vault_state_with(
        vault_id,
        presentation,
        vn_bytes,
        token_a,
        token_b,
        fee_bps,
        None,
    )
    .await
}

/// [`compose_vault_state`], with the settling trader's own not-yet-published
/// receipt as Req 21.16's evidence for ITS settlement (2c-D §14, C2-R1 point 1).
///
/// The candidate is verified exactly as a fetched receipt is; where it came
/// from changes nothing about the verdict, and it is never authority.
pub(crate) async fn compose_vault_state_with(
    vault_id: &[u8; 32],
    presentation: &crate::generated::AnchorPresentationV3,
    vn_bytes: &[u8],
    token_a: &[u8],
    token_b: &[u8],
    fee_bps: u32,
    receipt_candidate: Option<&SignedTraderSettlementReceipt>,
) -> Result<ComposedVaultState, CompositionError> {
    compose_vault_state_inner(
        vault_id,
        presentation,
        vn_bytes,
        token_a,
        token_b,
        fee_bps,
        receipt_candidate,
        None,
    )
    .await
}

/// The walk itself. `stop_at` composes only UP TO a requested state and stops
/// there without reading its binding (reserve provenance, 2c-D §14).
#[allow(clippy::too_many_arguments)]
async fn compose_vault_state_inner(
    vault_id: &[u8; 32],
    presentation: &crate::generated::AnchorPresentationV3,
    vn_bytes: &[u8],
    token_a: &[u8],
    token_b: &[u8],
    fee_bps: u32,
    receipt_candidate: Option<&SignedTraderSettlementReceipt>,
    stop_at: Option<[u8; 32]>,
) -> Result<ComposedVaultState, CompositionError> {
    // ── The baseline: one authenticated object. ──────────────────────────
    let verified = verify_anchor_presentation(presentation, vn_bytes)
        .map_err(|e| CompositionError::InvalidBaselinePresentation(e.to_string()))?;
    // The authority half of the object just authenticated, in the shape a
    // consumer of `verify_authority_evidence` takes. Same six values, same
    // position, same resolver — see the field's doc.
    let owner_authority_evidence = {
        use prost::Message as _;
        crate::generated::AuthorityEvidenceV1 {
            genesis_params_ccb: presentation.genesis_params_ccb.clone(),
            delegations: presentation.delegations.clone(),
            transitions: presentation.transitions.clone(),
            inclusion_proof: presentation.inclusion_proof.clone(),
            ak_public_key: presentation.ak_public_key.clone(),
            atta: presentation.atta.clone(),
        }
        .encode_to_vec()
    };
    let baseline_state = verified.state;
    let baseline_c_n = verified.c_n;
    let owner = verified.owner;

    if baseline_state.vault_id != *vault_id {
        return Err(CompositionError::BaselineMismatch(
            "the presented state is for a different vault".into(),
        ));
    }

    // The caller's tuple must be the state's own market, through the ONE pair
    // parser, so the identity a vault was funded under, the identity a
    // pointer commits to, and the identity a quote is bound to are derived by
    // the same code and cannot disagree.
    let Ok(pair) = dsm::dlv::pair_identity::CanonicalPair::parse(token_a, token_b) else {
        return Err(CompositionError::PairIsNotPolicyCommits);
    };
    let (pc_a, pc_b) = (pair.a(), pair.b());
    if *baseline_state.market_policy.token_a() != pc_a
        || *baseline_state.market_policy.token_b() != pc_b
    {
        return Err(CompositionError::BaselineMismatch(
            "the caller's pair is not the signed state's market pair".into(),
        ));
    }
    if baseline_state.fee_policy.fee_bps() != fee_bps {
        return Err(CompositionError::BaselineMismatch(format!(
            "the caller's fee ({fee_bps} bps) is not the signed state's fee ({})",
            baseline_state.fee_policy.fee_bps()
        )));
    }

    let storage_set_id = dsm::ccb::storage_set_id(&baseline_state.storage_set)
        .map_err(|e| CompositionError::InvalidBaselinePresentation(format!("storage set: {e}")))?;

    // ── The vault's OWN set and quorum. ──────────────────────────────────
    // Resolved by re-deriving the id from `V_n.storage_set` (already done
    // above) and looking THAT up in the local catalog — never the catalog's
    // sole set, and never this verifier's own majority rule. `q` is field 15
    // of the owner-committed state: counting a vault's cells at a locally
    // chosen threshold would substitute the verifier's opinion for the
    // vault's rule.
    let catalog = crate::sdk::storage_set::StorageSetCatalog::from_env_config().map_err(|e| {
        CompositionError::BindingEvidenceUnavailable(format!("storage catalog: {e}"))
    })?;
    let set = catalog.resolve(&storage_set_id).cloned().ok_or_else(|| {
        CompositionError::BindingEvidenceUnavailable(
            "the vault's committed storage set is not resolvable from the local catalog".into(),
        )
    })?;
    // THE COMMITTED QUORUM IS NOT OWNER POLICY. It must BE the canonical
    // strict majority of the committed set. A weaker bound — non-zero and not
    // larger than the set — accepted a signed `1-of-3`, under which two
    // disjoint claims each reach quorum and different verifiers fold
    // different chains. Exact equality removes the discretion entirely.
    let committed_quorum = baseline_state.quorum;
    dsm::economic::cell_observation::require_canonical_quorum(set.len(), committed_quorum)
        .map_err(|e| CompositionError::BindingEvidenceUnavailable(e.to_string()))?;

    // ── THE WALK. Cursor = a full state + its commitment. ────────────────
    //
    // The edge source is BINDING OCCUPANCY at `k_v = H(DSM/binding-keyset ‖
    // c_n)`, read live at the owner-committed quorum — not a prefix listing.
    // That inversion is the whole point: a set query's exhaustiveness is
    // unfalsifiable, so a member that omits a key produces an answer
    // indistinguishable from a shorter chain, and no signature repairs it. A
    // binding key's answer is bounded, and omission is not expressible in it.
    //
    // WHAT THIS WALK NOW KEEPS SEPARATE. Occupancy and realization used to be
    // one fact, because a write-once slot could only be claimed by the party
    // that settled it. They are not one fact:
    //
    //   binding occupancy = this parent is no longer available to a rival
    //   realized frontier = this successor actually became economic state
    //
    // For an owner CLOSE they still coincide — the successor is fully
    // determined and pre-authorized, so binding finality realizes it (Req
    // 6.30). For a MARKET bundle they deliberately do not: a bound bundle
    // whose trade has not settled leaves the OLD reserves as the last realized
    // state while the parent stays blocked. So each generation has FOUR
    // outcomes, not three:
    //
    //   free at quorum      -> the chain ends here; this is the frontier
    //   bound + realized    -> fold and continue
    //   bound + not settled -> the chain ends here, and the frontier is BOUND
    //   anything else       -> DLV_BINDING_EVIDENCE_UNAVAILABLE
    let mut cursor_state = baseline_state;
    let mut cursor_c_n = baseline_c_n;
    let mut chain_len: usize = 0;
    let mut folded_parents: Vec<FoldedParent> = Vec::new();
    let frontier_binding: FrontierBinding;
    loop {
        // COMPOSITION UP TO A TARGET (2c-D §14, reserve provenance): stop AT
        // the requested state and do not read its binding at all, so the
        // history of V_n never depends on the settlement that consumes it.
        if stop_at == Some(cursor_c_n) {
            frontier_binding = FrontierBinding::NotObserved;
            break;
        }
        // Saturation is NOT a frontier. A walk that stops because it ran out
        // of budget has established nothing about maximality, and reporting
        // "frontier at 64" would be the omission defect wearing a local name.
        if chain_len >= MAX_PENDING_CHAIN_DEPTH {
            return Err(CompositionError::BindingEvidenceUnavailable(format!(
                "walk saturated at depth {MAX_PENDING_CHAIN_DEPTH} without reaching a free parent"
            )));
        }
        // 2c-C3.1 ruling B (i): the durable quarantine is consulted at EVERY
        // cursor — the baseline included — BEFORE the register is read. That
        // check lives in `observe_parent_binding`, ahead of its read, so the
        // walk and the probe cannot disagree about a root; it surfaces here as
        // `Unresolvable(LineageQuarantined)` and is routed by class below. The
        // execution routes make the same check again on their own.
        let bound = match crate::sdk::binding_occupancy::observe_parent_binding(
            &set,
            vault_id,
            cursor_state.generation,
            &cursor_c_n,
            &storage_set_id,
            committed_quorum,
        )
        .await
        {
            // THE ONLY TERMINATION THAT ESTABLISHES A FREE FRONTIER: a quorum
            // of members each EXPLICITLY hold nothing at this key. It says no
            // binding is observable now — never that this parent can never be
            // bound.
            //
            // Then, and ONLY then, overlay this device's own unresolved work.
            // That overlay is CLIENT-LOCAL and never published: the register
            // may honestly say Free while this Class K holds a transaction
            // over the same parent whose outcome it does not yet know.
            crate::sdk::binding_occupancy::ParentOccupancy::Free => {
                frontier_binding = local_fence_overlay(vault_id, &cursor_c_n)?;
                break;
            }
            // ROUTE BY CLASS. This arm used to funnel every unresolvable
            // occupancy into `BindingEvidenceUnavailable` — including forged
            // successors, bundles naming another vault's parent, and duplicate
            // binding finality, none of which is an absence of evidence.
            crate::sdk::binding_occupancy::ParentOccupancy::Unresolvable(why) => {
                let detail = format!("binding at generation {}: {why}", cursor_state.generation);
                return Err(match why.class() {
                    OutcomeClass::SafetyViolation => CompositionError::SafetyViolation {
                        reason: why.reason,
                        detail,
                    },
                    OutcomeClass::Invalid => CompositionError::SuccessorInvalid {
                        reason: why.reason,
                        detail,
                    },
                    // Genuinely nothing was learned. Req 6.25's code, kept.
                    OutcomeClass::Incomplete | OutcomeClass::Valid => {
                        CompositionError::BindingEvidenceUnavailable(detail)
                    }
                });
            }
            crate::sdk::binding_occupancy::ParentOccupancy::BoundBy(b) => b,
        };

        // A binding-final bundle OWNS this parent. From here every failure is
        // fail-closed: the network has told us this generation is not the end,
        // so we may not report it as one because a second artifact is missing.
        //
        // `observe_parent_binding` has already established that the bytes
        // re-hash to the record's identity, that the bundle names this storage
        // set and this q, and that its transition for THIS vault names this
        // generation and this exact `c_n`.
        let unavailable = |what: &str| {
            CompositionError::BindingEvidenceUnavailable(format!(
                "generation {} is bound by {} but {what}",
                cursor_state.generation,
                crate::util::text_id::encode_base32_crockford(&bound.bundle_digest)
            ))
        };
        // The same prefix, for facts that are DECIDABLY FALSE rather than
        // unobtainable. Sharing the prefix keeps the diagnostics readable; the
        // class is what a caller branches on.
        let refused = |reason: Reason, what: &str| CompositionError::SuccessorInvalid {
            reason,
            detail: format!(
                "generation {} is bound by {} but {what}",
                cursor_state.generation,
                crate::util::text_id::encode_base32_crockford(&bound.bundle_digest)
            ),
        };
        let Some(transition) = bound.transition() else {
            return Err(refused(
                Reason::BundleNotCanonical,
                "its bundle lost the transition it named",
            ));
        };

        // Discriminate on SHAPE FIRST. A close bundle's `route_set_commitment`
        // is 32 zero bytes, so reading X before this branch would silently
        // compute an all-zero commitment.
        // What this walk DERIVES for the bound transition — the frozen
        // predicate's successor, by shape. `VDS.COMMON.10.a` then compares it,
        // byte for byte, against the successor the bundle CARRIES.
        let mut market_evidence: Option<Box<EstablishedMarketEvidence>> = None;
        let expected = match bound.shape {
            // ── CLOSE: binding-final ⇒ REALIZE IMMEDIATELY (Req 6.30). ─────
            // The successor is fully determined — both reserves to zero at
            // parent+1 — so there is no amount to witness and no second
            // artifact to wait for. What must be proven is WHO authorized it:
            // the drained successor and its `c_{n+1}` are public derivations
            // anyone can recompute, so the shape is a DISCRIMINATOR and never
            // an authorization. The proof
            // is the owner's signature over the exact release successor,
            // rebuilt here from the frontier this walk is standing on.
            dsm::dlv::settlement_bundle::BundleShape::OwnerClose => {
                let successor = dsm::dlv::close_authorization::CloseSuccessor {
                    vault_id: *vault_id,
                    leg_a_policy_commit: pc_a,
                    leg_a_amount: cursor_state.reserve_a,
                    leg_b_policy_commit: pc_b,
                    leg_b_amount: cursor_state.reserve_b,
                    parent_sequence: cursor_state.generation,
                    fee_bps,
                };
                dsm::dlv::close_authorization::verify_close_authorization(
                    &bound.bundle,
                    &successor,
                    &owner.ak_pk,
                )
                .map_err(|e| {
                    refused(
                        Reason::SuccessorSignatureInvalid,
                        &format!("its close is not authorized by the vault owner: {e}"),
                    )
                })?;
                // THE PREDICATE DERIVES THE SUCCESSOR. This used to be
                // clone() plus four mutations here -- preserved fields were
                // preserved by construction of this producer, not by any
                // rule. derive_close_successor is the frozen C3 derivation:
                // both legs drained, generation+1, h_{n+1} = c_n, beta per
                // ruling F, and a RETIRED parent refused (erratum D2).
                match derive_close_successor(&cursor_state, cursor_c_n) {
                    DeriveExpected::Derived(next) => *next,
                    DeriveExpected::Refused(reason) => {
                        return Err(refused(
                            reason,
                            "its close does not derive from this parent",
                        ))
                    }
                }
            }

            // ── MARKET: realized ONLY when certified (2c-D §14, C2). ──────
            // Binding finality alone realizes nothing (Req 6.2, Req 21.15).
            // The successor is DERIVED from the trader's accepted operation
            // (CORR.5) and compared with `T_v` below (`10.a`); the verdict
            // after that needs CORR.1–CORR.5, 2c-D §7 and Tier-1 intent
            // satisfaction, and Req 21.16 has already run here.
            dsm::dlv::settlement_bundle::BundleShape::Market => {
                let Some(terms) = bound.bundle.market_terms() else {
                    return Err(refused(
                        Reason::BundleNotCanonical,
                        "its market shape carries no market terms",
                    ));
                };
                let x = terms.route_set_commitment;
                match certify_market_evidence(
                    vault_id,
                    bound.bundle_digest,
                    terms,
                    bound.bundle.transitions(),
                    &cursor_state,
                    cursor_c_n,
                    receipt_candidate,
                )
                .await
                {
                    MarketEvidence::Established(ev) => {
                        let next = ev.expected.clone();
                        market_evidence = Some(ev);
                        next
                    }
                    // Not yet published. The frontier is THIS generation and
                    // it is occupied; a later walk realizes it.
                    MarketEvidence::Absent(_) => {
                        frontier_binding = FrontierBinding::BoundUnrealized {
                            bundle_digest: bound.bundle_digest,
                            route_set_commitment: x,
                        };
                        break;
                    }
                    // Unobtainable: Req 6.25's INCOMPLETE, never a frontier.
                    MarketEvidence::Unavailable(why) => return Err(unavailable(&why)),
                    // Present and failing verification: INVALID, never absence.
                    MarketEvidence::Contradicts(reason, why) => return Err(refused(reason, &why)),
                }
            }
        };

        // ── VDS.COMMON.10.a ─────────────────────────────────────────────
        // `Canon(expected)` against the EXACT byte span of the successor the
        // bound bundle carries (2c-A.1 ruling 8: the recorded field-2 span of
        // the fetched bytes, never a re-encoding). Every preserved- and
        // mutated-field disposition of C3 ruling B is decided by this one
        // comparison. The commitment the walk installs comes from the
        // witness — derived from the SUPPLIED bytes — not from local state.
        let witness = check_correspondence(&expected, cursor_c_n, bound.successor_bytes())
            .map_err(|reason| {
                refused(
                    reason,
                    "the successor its bundle carries is not the successor this walk derives \
                     for the transition (VDS.COMMON.10.a)",
                )
            })?;
        let next_state = witness.expected().clone();
        let next_c_n = witness.c_next();
        // THE VERDICT THIS FOLD CARRIES — and every fold must CERTIFY. An owner
        // close has no conjunct left. A market fold is certified from three
        // independently established facts, each with one constructor
        // (2c-D §14, C2-R1 point 3): CORR.1–CORR.5, 2c-D §7's acceptance
        // witness, and Tier-1 intent satisfaction. Nothing uncertified is ever
        // installed as the composed state.
        let (verdict, realized_trade, certified_acceptance, certified_payment) = match bound.shape {
            dsm::dlv::settlement_bundle::BundleShape::OwnerClose => (
                C3Verdict::Valid(CompleteValidity::from_close_witness(witness)),
                None,
                None,
                None,
            ),
            dsm::dlv::settlement_bundle::BundleShape::Market => {
                let (Some(ev), Some(terms)) = (market_evidence.take(), bound.bundle.market_terms())
                else {
                    return Err(refused(
                        Reason::BundleNotCanonical,
                        "its market evidence was never established",
                    ));
                };
                let ev = *ev;
                let correspondence = check_market_correspondence(
                    &ev.accepted,
                    &ev.coords,
                    cursor_c_n,
                    witness.clone(),
                )
                .map_err(|reason| {
                    refused(
                        reason,
                        "its accepted settle does not correspond to the bundle (CORR.1-CORR.5)",
                    )
                })?;
                let acceptance = dsm::economic::acceptance_verify::verify_trader_acceptance(
                    &ev.acceptance,
                    terms,
                    bound.bundle_digest,
                    &correspondence,
                    &ev.trader.validated_root,
                    &ev.trader.proven_ak,
                )
                .map_err(|e| {
                    refused(
                        Reason::RealizationEvidenceInvalid,
                        &format!("its trader acceptance does not verify (2c-D §7): {e}"),
                    )
                })?;
                let realization =
                    IndependentRealization::from_parts(correspondence, acceptance, ev.intent);
                (
                    C3Verdict::Valid(CompleteValidity::from_market_witness(witness, realization)),
                    Some(ev.receipt),
                    Some(ev.acceptance),
                    Some(ev.payment),
                )
            }
        };
        if !verdict.may_certify() {
            return Err(refused(
                Reason::CorrespondenceMismatch,
                "its verdict does not certify",
            ));
        }
        folded_parents.push(FoldedParent {
            generation: cursor_state.generation,
            c_n: cursor_c_n,
            state: cursor_state.clone(),
            bound_by: bound.bundle_digest,
            bound_kind: bound.shape,
            verdict,
            realized_trade,
            certified_acceptance,
            certified_payment,
        });
        let _ = transition;
        cursor_state = next_state;
        cursor_c_n = next_c_n;
        chain_len += 1;
    }

    Ok(ComposedVaultState {
        sequence: cursor_state.generation,
        reserves_a: cursor_state.reserve_a,
        reserves_b: cursor_state.reserve_b,
        pending_chain_len: chain_len,
        owner_devid: owner.device_id,
        owner_genesis: cursor_state.owner_genesis_id,
        owner_public_key: owner.ak_pk,
        // Filled by the DISCOVERED path from the advertisement it decoded;
        // this constructor never saw one.
        owner_economic_proof: None,
        owner_authority_evidence,
        storage_set_id,
        c_n: cursor_c_n,
        folded_parents,
        state: cursor_state,
        frontier_binding,
    })
}

/// This device's own unresolved work over a parent the register says is FREE.
///
/// Consulted ONLY at the point the walk breaks. Earlier generations already
/// folded, so a stale fence there is moot — and a fence that blocks a
/// generation the register has already moved past would be pure noise.
///
/// Deliberately NOT a fail-closed. `dlv_reconcile` and `finish_prepared_close`
/// legitimately compose while this device's own close is in flight, and
/// refusing here would deadlock exactly the recovery paths that exist to
/// resolve it. What it does instead is REPORT, so a caller that would advance
/// the parent can decline while a caller that is recovering it can proceed.
fn local_fence_overlay(
    vault_id: &[u8; 32],
    cursor_c_n: &[u8; 32],
) -> Result<FrontierBinding, CompositionError> {
    match crate::storage::client_db::trader_parent_fence::active_fence(vault_id, cursor_c_n) {
        Ok(None) => Ok(FrontierBinding::Free),
        Ok(Some(f)) => Ok(FrontierBinding::LocallyFenced { tx_id: f.tx_id }),
        // An unreadable local fence table is not evidence that nothing is in
        // flight. Fail closed rather than report a parent free on the strength
        // of a database error.
        Err(e) => Err(CompositionError::BindingEvidenceUnavailable(format!(
            "the local trader-parent fence table is unreadable: {e}"
        ))),
    }
}

/// A bound MARKET bundle's realization evidence (2c-D §14, C2).
///
/// The split between the last three outcomes is the frozen C3 taxonomy: an
/// absence is not a failure, an unreadable input establishes nothing, and
/// evidence that is present and fails verification is INVALID — never
/// absence (`Reason::RealizationEvidenceInvalid`'s own doc).
enum MarketEvidence {
    /// Every certification input is present and verified.
    Established(Box<EstablishedMarketEvidence>),
    /// Not yet published: bound but unrealized.
    Absent(String),
    /// Could not be read: INCOMPLETE.
    Unavailable(String),
    /// Present and failing verification: INVALID.
    Contradicts(Reason, String),
}

/// What the walk needs after `10.a` to construct the certifying verdict.
struct EstablishedMarketEvidence {
    /// CORR.5's derivation from the accepted operation.
    expected: VaultStateV2,
    accepted: AcceptedTransition,
    coords: BundleCoordinates,
    acceptance: dsm::economic::trader_acceptance::TraderAcceptance,
    /// The trader's lineage at the acceptance's position: `R_T^+`, the proven
    /// AK, the verified operation and `C_dsm+`.
    trader: ValidatedPeerTransition,
    intent: IntentSatisfaction,
    receipt: VerifiedReceipt,
    /// The receipt leaf and path Req 21.16 just proved, for the fold.
    payment: CertifiedPayment,
}

/// Gather and verify everything a market certification needs, in the order
/// each step's inputs become available. Every operand is authenticated or
/// derived; nothing a locator or receipt carries is believed.
async fn certify_market_evidence(
    vault_id: &[u8; 32],
    b: [u8; 32],
    terms: &dsm::ccb::MarketTerms,
    transitions: &[dsm::ccb::ConsumedDlvTransition],
    cursor_state: &VaultStateV2,
    cursor_c_n: [u8; 32],
    receipt_candidate: Option<&SignedTraderSettlementReceipt>,
) -> MarketEvidence {
    use crate::sdk::trader_acceptance_locator::{fetch_locator, LocatorFetch};
    use MarketEvidence::{Absent, Contradicts, Unavailable};
    let invalid = |what: String| Contradicts(Reason::RealizationEvidenceInvalid, what);

    // Beta's shape, before anything is fetched (2c-A ruling 3).
    let coords = match BundleCoordinates::from_market_bundle(terms, transitions) {
        Ok(c) => c,
        Err(r) => {
            return Contradicts(
                r,
                "its route is not a beta market route (one leg, one allocation, one T_v)".into(),
            )
        }
    };

    // ── 1–2. Locate TA_B, and fetch it by CONTENT ADDRESS ─────────────────
    let (ta_b, proof_addr) = match fetch_locator(&b).await {
        LocatorFetch::Found {
            ta_b,
            economic_proof_addr,
        } => (ta_b, economic_proof_addr),
        LocatorFetch::Absent => {
            return Absent("no trader acceptance is published for its bundle".into())
        }
        LocatorFetch::Unavailable(e) => {
            return Unavailable(format!(
                "its trader-acceptance locator could not be read: {e}"
            ))
        }
        LocatorFetch::Malformed(w) => {
            return invalid(format!("its trader-acceptance locator is malformed: {w}"))
        }
    };
    let ta_bytes = match crate::sdk::storage_io::fetch_immutable_payload(
        dsm::common::domain_tags::TAG_DSM_TRADER_SETTLEMENT_ACCEPTANCE,
        &ta_b,
    )
    .await
    {
        Ok(Some(bytes)) => bytes,
        Ok(None) => return Absent("its trader acceptance is not held by any member yet".into()),
        Err(e) => return Unavailable(format!("its trader acceptance could not be read: {e}")),
    };
    let acceptance = match dsm::economic::trader_acceptance::decode_trader_acceptance(&ta_bytes) {
        Ok(a) => a,
        Err(e) => return invalid(format!("its trader acceptance is not canonical: {e}")),
    };

    // ── The trader's DevID: the bundle's own settler, never its counterparty
    // (2c-D §12). G1–G4 already held for these bytes at `observe_parent_binding`.
    let settler_devid = match Operation::from_bytes(&terms.recovery_material.operation_bytes) {
        Ok(Operation::DlvSettle { settler_devid, .. }) => settler_devid,
        _ => {
            return Contradicts(
                Reason::BundleNotCanonical,
                "its market terms carry no settle".into(),
            )
        }
    };

    // ── 3. The trader's lineage: R_T^+, the proven AK, the verified operation
    // and C_dsm+ — derived by the walk, never carried (2c-D §7 step 3). A walk
    // that cannot complete is INCOMPLETE, never invalid.
    let (network_id, root_set) = match crate::sdk::economic_admission_flow::committed_network_id()
        .and_then(|n| crate::sdk::economic_admission_flow::canonical_set(&n).map(|s| (n, s)))
    {
        Ok(v) => v,
        Err(e) => return Unavailable(format!("the root-register set is not resolvable: {e}")),
    };
    let resolver = crate::sdk::economic_registers::LiveRegisterResolver {
        set: &root_set,
        runtime: tokio::runtime::Handle::current(),
        expected_network_id: network_id,
    };
    let trader = match resolver.validated_peer_transition(
        &acceptance.trader_genesis(),
        &settler_devid,
        acceptance.economic_position(),
    ) {
        Ok(t) => t,
        Err(PeerLineageFailure::Incomplete(e)) => {
            return Unavailable(format!("the trader's lineage could not be walked: {e}"))
        }
        Err(e) => return invalid(format!("the trader's lineage does not validate: {e}")),
    };

    // ── The accepted effects, from the VERIFIED operation (C2-R2 LEFT) ─────
    let Some(accepted) = AcceptedTransition::from_verified_settle(
        trader.embedded_parent,
        trader.c_dsm_plus,
        &trader.verified_operation,
    ) else {
        return invalid(
            "the trader's validated transition at that position is not a settle".into(),
        );
    };
    let Operation::DlvSettle {
        route_commit_bytes, ..
    } = &trader.verified_operation
    else {
        return invalid(
            "the trader's validated transition at that position is not a settle".into(),
        );
    };

    // ── CORR.5's derivation: orientation, generation, fee, curve, output ───
    let expected = match derive_accepted_market_successor(cursor_state, cursor_c_n, &accepted) {
        DeriveExpected::Derived(next) => *next,
        DeriveExpected::Refused(r) => {
            return Contradicts(
                r,
                "its accepted settle does not derive a successor from this parent".into(),
            )
        }
    };

    // ── Tier 1 (2c-E §6, SAT.1–SAT.6), from the VERIFIED RouteCommit ──────
    let intent = match check_intent_satisfaction(
        &IntentEvidence {
            intent: &terms.intent,
            route: &terms.selected_route,
            route_commit_bytes: route_commit_bytes.as_slice(),
            vault_id,
            proven_ak: &trader.proven_ak,
        },
        cursor_state,
        cursor_c_n,
    ) {
        Ok(i) => i,
        Err(r) => {
            return Contradicts(
                r,
                "the trade does not satisfy its signed intent (2c-E §6)".into(),
            )
        }
    };

    // ── Req 21.16: the receipt's facts, under the VALIDATED R_T^+ ─────────
    let x = terms.route_set_commitment;
    let receipt = match receipt_candidate {
        // The local candidate is the receipt of the settlement being completed
        // and of nothing else: every other fold reads its own from storage.
        Some(r) if r.vault_id == *vault_id && r.trade.x == x => r.clone(),
        _ => match crate::sdk::settlement_receipt_codec::fetch_receipt(vault_id, &x).await {
            crate::sdk::settlement_receipt_codec::ReceiptFetch::Decoded(r) => *r,
            crate::sdk::settlement_receipt_codec::ReceiptFetch::Absent => {
                return Absent("its settlement receipt is not published yet".into())
            }
            crate::sdk::settlement_receipt_codec::ReceiptFetch::Unavailable(e) => {
                return Unavailable(format!("its settlement receipt could not be read: {e}"))
            }
            crate::sdk::settlement_receipt_codec::ReceiptFetch::Malformed(w) => {
                return invalid(format!("its settlement receipt is malformed: {w}"))
            }
        },
    };
    let proof_bytes = match crate::sdk::storage_io::fetch_immutable_payload(
        dsm::common::domain_tags::TAG_DSM_ECONOMIC_PROOF_ARTIFACT,
        &proof_addr,
    )
    .await
    {
        Ok(Some(bytes)) => bytes,
        Ok(None) => return Absent("its inclusion proof is not held by any member yet".into()),
        Err(e) => return Unavailable(format!("its inclusion proof could not be read: {e}")),
    };
    let root = trader.validated_root.economic_root();
    let artifact = match dsm::economic::proof_artifact::decode_economic_proof_artifact(&proof_bytes)
    {
        Ok(a) => a,
        Err(e) => return invalid(format!("its inclusion proof is malformed: {e}")),
    };
    if let Err(e) = artifact.verify_against(
        &acceptance.trader_genesis(),
        &settler_devid,
        acceptance.economic_position(),
        &root,
    ) {
        return invalid(format!(
            "its inclusion proof does not verify under the validated root: {e}"
        ));
    }
    let receipt_id = derive_receipt_id(vault_id, &x);
    let Some((receipt_leaf, path)) = artifact.leaves.iter().find_map(|leaf| match &leaf.state {
        dsm::economic::state::EconomicLeafState::SettlementReceipt(s)
            if s.vault_id == *vault_id && s.receipt_id == receipt_id =>
        {
            Some((s.clone(), leaf.siblings.clone()))
        }
        _ => None,
    }) else {
        return invalid("its inclusion proof names no settlement receipt for this trade".into());
    };
    let receipt = match verify_published_receipt(
        &receipt,
        &trader.validated_root,
        &path[..],
        acceptance.trader_genesis(),
        settler_devid,
        *vault_id,
        x,
    ) {
        Ok(v) => v,
        Err(e) => {
            return invalid(format!(
                "its receipt does not correspond to the committed settlement (Req 21.16): {e}"
            ))
        }
    };

    // What the owner's apply is funded by (2c-G): the leaf and path just
    // proven, at the position whose validated root they were proven under.
    let payment = CertifiedPayment {
        trader_genesis: acceptance.trader_genesis(),
        trader_devid: settler_devid,
        trader_economic_position: acceptance.economic_position(),
        receipt: receipt_leaf,
        receipt_siblings: path,
    };

    MarketEvidence::Established(Box::new(EstablishedMarketEvidence {
        expected,
        accepted,
        coords,
        acceptance,
        trader,
        intent,
        receipt,
        payment,
    }))
}

/// Compose a DISCOVERED vault from its published artifacts alone.
///
/// This is the ONE composition entry for a party holding nothing but a
/// vault id and its pair: the advertisement (located by pair + vault id)
/// carries the presentation digest — discovery, never authority — and
/// everything after that is the verified path: presentation → `c_n` →
/// exact `CCB(V_n)` bytes → full P0–P6 → receipted fold. Both the trader's
/// quote path and the pointer publisher resolve a vault THROUGH this
/// function, so no caller can substitute its own statement of any fact the
/// authenticated state carries.
pub(crate) async fn compose_discovered_vault(
    vault_id: &[u8; 32],
    token_a: &[u8],
    token_b: &[u8],
    fee_bps: u32,
) -> Result<ComposedVaultState, CompositionError> {
    compose_discovered_vault_with(vault_id, token_a, token_b, fee_bps, None).await
}

/// [`compose_discovered_vault`], with the settling trader's own receipt
/// candidate for its settlement — see [`compose_vault_state_with`].
pub(crate) async fn compose_discovered_vault_with(
    vault_id: &[u8; 32],
    token_a: &[u8],
    token_b: &[u8],
    fee_bps: u32,
    receipt_candidate: Option<&SignedTraderSettlementReceipt>,
) -> Result<ComposedVaultState, CompositionError> {
    compose_discovered_inner(vault_id, token_a, token_b, fee_bps, receipt_candidate, None).await
}

/// The vault's COMPOSED history from its owner baseline up to and including
/// the state committed as `target_c_n` — the same walk, stopped AT the target
/// so the binding there is never read (2c-D §14, reserve provenance). Baseline
/// first; every later state is a certified fold. A walk that never reaches the
/// target ends elsewhere, and the reserve rule refuses that history.
pub(crate) async fn compose_vault_history_until(
    vault_id: &[u8; 32],
    token_a: &[u8],
    token_b: &[u8],
    fee_bps: u32,
    target_c_n: [u8; 32],
    from_generation: u64,
) -> Result<dsm::dlv::composed_history::ComposedVaultHistory, CompositionError> {
    let composed = compose_discovered_inner(
        vault_id,
        token_a,
        token_b,
        fee_bps,
        None,
        Some((target_c_n, from_generation)),
    )
    .await?;
    let mut states: Vec<VaultStateV2> = composed
        .folded_parents
        .iter()
        .map(|f| f.state.clone())
        .collect();
    states.push(composed.state);
    Ok(dsm::dlv::composed_history::ComposedVaultHistory::from_walk(
        states,
    ))
}

async fn compose_discovered_inner(
    vault_id: &[u8; 32],
    token_a: &[u8],
    token_b: &[u8],
    fee_bps: u32,
    receipt_candidate: Option<&SignedTraderSettlementReceipt>,
    history: Option<([u8; 32], u64)>,
) -> Result<ComposedVaultState, CompositionError> {
    let stop_at = history.map(|(target, _)| target);
    let ad_key = crate::sdk::routing_sdk::advertisement_key(token_a, token_b, vault_id);
    let ad_bytes = BitcoinTapSdk::storage_get_bytes(&ad_key)
        .await
        .map_err(|e| {
            CompositionError::InvalidBaselinePresentation(format!(
                "advertisement not resolvable: {e}"
            ))
        })?;
    let ad = crate::generated::RoutingVaultAdvertisementV1::decode(ad_bytes.as_slice()).map_err(
        |e| CompositionError::InvalidBaselinePresentation(format!("advertisement decode: {e}")),
    )?;
    let Ok(presentation_digest) = <[u8; 32]>::try_from(ad.anchor_presentation_digest.as_slice())
    else {
        return Err(CompositionError::InvalidBaselinePresentation(
            "advertisement carries no presentation digest".into(),
        ));
    };
    let (mut presentation, mut vn_bytes) = fetch_advertised_baseline(&presentation_digest).await?;
    // THE HISTORICAL FALLBACK (amendment 2c-G, G3 blocker ruling). The current
    // anchor moves forward; a history walk that must include a generation OLDER
    // than it composes from the vault's immutable BIRTH anchor instead, so a
    // baseline that moved never makes an earlier settle unverifiable. The birth
    // field is discovery only: the anchor is authenticated by the same P0-P6
    // verification below, and one that is not this vault's birth state is
    // refused rather than composed from.
    if let Some((_, needed)) = history {
        let current = dsm::ccb::decode_vault_state(&vn_bytes).map_err(|e| {
            CompositionError::InvalidBaselinePresentation(format!("advertised baseline: {e}"))
        })?;
        if current.generation > needed {
            let Ok(birth_digest) =
                <[u8; 32]>::try_from(ad.birth_anchor_presentation_digest.as_slice())
            else {
                return Err(CompositionError::InvalidBaselinePresentation(format!(
                    "the current anchor stands at generation {}, after generation {needed} this \
                     history must include, and the advertisement names no birth anchor",
                    current.generation
                )));
            };
            let (birth_presentation, birth_bytes) =
                fetch_advertised_baseline(&birth_digest).await?;
            let birth = dsm::ccb::decode_vault_state(&birth_bytes).map_err(|e| {
                CompositionError::InvalidBaselinePresentation(format!("birth anchor: {e}"))
            })?;
            if birth.vault_id != *vault_id
                || birth.generation != 0
                || birth.parent_state_commitment != dsm::ccb::genesis_parent_commitment(vault_id)
            {
                return Err(CompositionError::InvalidBaselinePresentation(
                    "the advertised birth anchor is not this vault's birth state — refusing a \
                     substituted historical anchor"
                        .into(),
                ));
            }
            presentation = birth_presentation;
            vn_bytes = birth_bytes;
        }
    }
    let mut composed = compose_vault_state_inner(
        vault_id,
        &presentation,
        &vn_bytes,
        token_a,
        token_b,
        fee_bps,
        receipt_candidate,
        stop_at,
    )
    .await?;
    // The advertisement's economic-proof locator, carried through for readers
    // that have no `amm_vault_record` of their own — which is every settling
    // TRADER. Copied verbatim and NOT validated here: it is a hint, and the
    // reader that uses it re-derives every inclusion path against the root the
    // owner's own register cell names, so a wrong value can only fail.
    // A malformed address is treated as absent rather than as a refusal,
    // because composition is about the authenticated state and this field
    // authenticates nothing.
    composed.owner_economic_proof = <[u8; 32]>::try_from(ad.economic_proof_addr.as_slice())
        .ok()
        .map(|addr| OwnerEconomicProofLocator {
            addr,
            position: ad.economic_proof_position,
        });
    Ok(composed)
}

/// The `AnchorPresentationV3` at an advertised digest and the exact `CCB(V_n)`
/// it anchors — fetched, never trusted: the walk authenticates both.
async fn fetch_advertised_baseline(
    presentation_digest: &[u8; 32],
) -> Result<(crate::generated::AnchorPresentationV3, Vec<u8>), CompositionError> {
    let presentation =
        crate::sdk::vault_state_v3_codec::fetch_anchor_presentation(presentation_digest)
            .await
            .map_err(|e| CompositionError::InvalidBaselinePresentation(e.to_string()))?
            .ok_or_else(|| {
                CompositionError::InvalidBaselinePresentation(
                    "presentation not resolvable at its advertised digest".into(),
                )
            })?;
    let Ok(c_n) = <[u8; 32]>::try_from(presentation.state_commitment.as_slice()) else {
        return Err(CompositionError::InvalidBaselinePresentation(
            "presentation carries a malformed state commitment".into(),
        ));
    };
    let vn_bytes = crate::sdk::vault_state_v3_codec::fetch_vault_state_bytes(&c_n)
        .await
        .map_err(|e| CompositionError::InvalidBaselinePresentation(e.to_string()))?
        .ok_or_else(|| {
            CompositionError::InvalidBaselinePresentation("V_n not resolvable at its c_n".into())
        })?;
    Ok((presentation, vn_bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use dsm::dlv::successor_validity::{derive_market_successor, MarketTerms};
    use dsm::types::proto as generated;
    use dsm::ccb::{
        genesis_parent_commitment, vault_state_commitment, EncumbranceSet, FeePolicy, MarketPolicy,
        ReleasePolicy, StorageSetMembers,
    };
    use dsm::crypto::sphincs::{generate_keypair, SphincsVariant};
    use dsm::dlv::settlement_receipt_leaf::{
        derive_receipt_id, receipt_commitment, settlement_receipt_key, settlement_receipt_value,
        sign_trader_settlement_receipt, SettledTrade,
    };
    use dsm::dlv::vault_pending_pointer::sign_vault_pending_pointer;

    use crate::sdk::identity_presentation::{
        build_own_anchor_presentation, derive_own_authority_context, OwnerIdentityInputs,
    };

    /// The one wallet the fixtures own. Everything — GRK, device key, AttA,
    /// D_0/T_0 — re-derives from it, exactly as production does.
    const SEED: &[u8] = b"test-bip39-wallet-seed-64-bytes-............................xxxx";
    const NET: &[u8] = b"dsm-test";
    const INPUTS: OwnerIdentityInputs<'static> = OwnerIdentityInputs {
        network_id: NET,
        wallet_index: 0,
        device_slot: 0,
        genesis_version: 3,
    };

    /// The pair, as 32-byte policy commits (lex-ordered: TOKEN_A < TOKEN_B).
    const TOKEN_A: [u8; 32] = [0x11; 32];
    const TOKEN_B: [u8; 32] = [0x22; 32];
    const FEE_BPS: u32 = 30;

    fn vid(b: u8) -> [u8; 32] {
        let mut v = [0u8; 32];
        v[0] = 0x7A;
        v[1] = b;
        v
    }

    fn x_seed(b: u8) -> [u8; 32] {
        let mut v = [0u8; 32];
        v[0] = 0xEC;
        v[1] = b;
        v[31] = b.wrapping_mul(31).wrapping_add(11);
        v
    }

    /// Install the 3-node fleet these tests compose against and clear both
    /// the flat object store and the per-member registers.
    ///
    /// Composition now reads a REGISTER, so a test that does not stand a fleet
    /// up is not testing a weaker composition — it gets
    /// `BindingEvidenceUnavailable`, because an unresolvable set is exactly
    /// the fail-closed case.
    fn fleet() -> crate::handlers::faucet_flow_tests::FleetGuard {
        let guard = crate::handlers::faucet_flow_tests::install_canonical_fleet();
        crate::sdk::storage_io::fake_fleet::reset();
        // The binding double is a process-global too, and the board runs
        // --test-threads=1, so a leaked record makes failures order-dependent.
        crate::sdk::binding_fleet_double::reset_all();
        // Register the canonical fleet NOW, so an id-keyed injection made
        // before the first binding op resolves. The transport registers
        // lazily, which is too late for a control.
        if let Ok(catalog) = crate::sdk::storage_set::StorageSetCatalog::from_env_config() {
            if let Some(set) = catalog.sole_set() {
                crate::sdk::binding_fleet_double::register_set(set);
            }
        }
        crate::sdk::bitcoin_tap_sdk::BitcoinTapSdk::reset_dbtc_storage_test_state();
        guard
    }

    fn fleet_set() -> crate::sdk::storage_set::StorageSet {
        crate::sdk::storage_set::StorageSetCatalog::from_env_config()
            .expect("catalog")
            .sole_set()
            .expect("one set")
            .clone()
    }

    /// Bind the vault parent `parent_c_n` to the trade named by `x`, through
    /// the PRODUCTION driver.
    ///
    /// This is what makes a successor edge EXIST for the walk. Publishing a
    /// receipt and a RouteCommit no longer creates an edge on its own: a
    /// binding-final bundle has to own the parent.
    ///
    /// It drives `bind_settlement` rather than writing a record directly, so
    /// these tests exercise the real Class K decision — including the fact that
    /// a second candidate over the same parent loses.
    async fn win_slot(
        vault_id: &[u8; 32],
        parent_sequence: u64,
        x: &[u8; 32],
        parent_c_n: &[u8; 32],
        claimant_pk: &[u8],
    ) {
        win_slot_with(
            vault_id,
            x,
            parent_c_n,
            any_successor(vault_id, parent_sequence, parent_c_n),
            claimant_pk,
        )
        .await;
    }

    /// `win_slot` with the exact successor the bundle carries.
    async fn win_slot_with(
        vault_id: &[u8; 32],
        x: &[u8; 32],
        parent_c_n: &[u8; 32],
        successor: VaultStateV2,
        claimant_pk: &[u8],
    ) {
        let set = fleet_set();
        let bundle = market_bundle_for_tests(parent_c_n, successor, x);
        let out = crate::sdk::settlement_bind::bind_settlement(
            &set,
            proposer_for(claimant_pk),
            &bundle,
            *vault_id,
            *parent_c_n,
        )
        .await
        .expect("drive the bind");
        assert_eq!(
            out,
            Ok(dsm::dlv::quorum_bind::Outcome::Committed),
            "the fixture's bind must commit"
        );
    }

    /// A DETERMINISTIC per-claimant proposer id. `local_proposer_id` reads the
    /// app's genesis hash, which these tests do not set — and two claimants
    /// sharing a proposer would collide on rounds, so a contention test would
    /// pass for the wrong reason.
    fn proposer_for(claimant_pk: &[u8]) -> [u8; 32] {
        let mut h = dsm::crypto::blake3::dsm_domain_hasher(
            dsm::common::domain_tags::TAG_DSM_BINDING_KEYSET,
        );
        h.update(b"test-proposer");
        h.update(claimant_pk);
        *h.finalize().as_bytes()
    }

    /// The canonical market bundle a fixture binds: its `route_set_commitment`
    /// IS the trade's `x`, which is what the walk reads back to locate the
    /// receipt and the RouteCommit, and its one transition consumes
    /// `parent_c_n` into `successor` — which, for a fold that is meant to
    /// REALIZE, must be the exact successor the predicate derives
    /// (`VDS.COMMON.10.a` compares the bytes); for a bind whose evidence
    /// never arrives, any successor of this vault at the next generation.
    fn market_bundle_for_tests(
        parent_c_n: &[u8; 32],
        successor: VaultStateV2,
        x: &[u8; 32],
    ) -> dsm::ccb::SettlementBundle {
        dsm::ccb::settlement::fixtures::market_bundle(*parent_c_n, successor, *x)
    }

    /// A successor of `vault_id` at `parent_sequence + 1` for a bind whose
    /// realization evidence never arrives — the walk stops before `10.a`.
    fn any_successor(
        vault_id: &[u8; 32],
        parent_sequence: u64,
        parent_c_n: &[u8; 32],
    ) -> VaultStateV2 {
        dsm::ccb::settlement::fixtures::successor_of(
            *parent_c_n,
            *vault_id,
            parent_sequence.saturating_add(1),
            0,
            0,
        )
    }

    /// The exact market successor the frozen predicate derives for a swap on
    /// `parent` — what an honest bundle's field 2 carries.
    fn swapped(
        parent: &VaultStateV2,
        c_n: [u8; 32],
        input_is_a: bool,
        input_amount: u64,
    ) -> VaultStateV2 {
        let (in_pc, out_pc) = if input_is_a {
            (TOKEN_A, TOKEN_B)
        } else {
            (TOKEN_B, TOKEN_A)
        };
        match derive_market_successor(
            parent,
            c_n,
            &MarketTerms {
                input_policy_commit: in_pc,
                output_policy_commit: out_pc,
                input_amount,
                fee_bps: FEE_BPS,
            },
        ) {
            DeriveExpected::Derived(v) => *v,
            DeriveExpected::Refused(r) => panic!("the fixture swap must derive: {r}"),
        }
    }

    /// The exact drained successor the frozen predicate derives for a close of
    /// `parent` — what an honest close's field 2 carries, and what
    /// `close_bundle` requires to be linked to `c_n` and retired.
    fn drained(parent: &VaultStateV2, c_n: [u8; 32]) -> VaultStateV2 {
        use dsm::dlv::successor_validity::{derive_close_successor, DeriveExpected};
        match derive_close_successor(parent, c_n) {
            DeriveExpected::Derived(v) => *v,
            DeriveExpected::Refused(r) => panic!("the fixture parent must close: {r}"),
        }
    }

    /// Build the owner's `V_0` for a fixture vault, its `CCB(V_0)` bytes, its
    /// `c_0`, and the presentation anchoring it — all through the production
    /// builders.
    fn baseline_fixture(
        vault_id: [u8; 32],
        reserve_a: u64,
        reserve_b: u64,
    ) -> (
        crate::generated::AnchorPresentationV3,
        Vec<u8>,
        VaultStateV2,
        [u8; 32],
    ) {
        let auth = derive_own_authority_context(SEED, INPUTS).expect("authority context");
        let state = VaultStateV2 {
            owner_genesis_id: auth.g,
            owner_device_id: auth.devid,
            vault_id,
            generation: 0,
            reserve_a,
            reserve_b,
            market_policy: MarketPolicy::beta_constant_product(TOKEN_A, TOKEN_B).expect("pair"),
            release_policy: ReleasePolicy::beta_owner_local_full_close(),
            fee_policy: FeePolicy::new(FEE_BPS).expect("fee"),
            encumbrances: EncumbranceSet::empty(),
            iteration_budget: None,
            parent_state_commitment: genesis_parent_commitment(&vault_id),
            owner_authority_transition_digest: auth.position,
            // THE VAULT'S OWN SET AND QUORUM. The walk resolves this set id
            // through the local catalog and counts cells at THIS q — so the
            // fixture must commit the fleet these tests actually run against,
            // exactly as a real vault commits the fleet it was born under.
            storage_set: StorageSetMembers::new(&[
                (
                    &b"dsm-node-1"[..],
                    crate::economic_fixtures::fixture_register_incarnation_bytes("dsm-node-1"),
                ),
                (
                    &b"dsm-node-2"[..],
                    crate::economic_fixtures::fixture_register_incarnation_bytes("dsm-node-2"),
                ),
                (
                    &b"dsm-node-3"[..],
                    crate::economic_fixtures::fixture_register_incarnation_bytes("dsm-node-3"),
                ),
            ])
            .expect("set"),
            quorum: 2,
        };
        let ccb = state.encode().expect("encode");
        let c0 = vault_state_commitment(&state).expect("c_0");
        let presentation =
            build_own_anchor_presentation(SEED, INPUTS, &auth.g, &c0).expect("presentation");
        (presentation, ccb, state, c0)
    }

    /// Publish the minimal ExtCommit anchor at `sofi/extcommit/{X_b32}`.
    async fn publish_extcommit(x: &[u8; 32], publisher_pk: &[u8]) {
        let anchor = generated::ExternalCommitmentV1 {
            version: 1,
            x: x.to_vec(),
            publisher_public_key: publisher_pk.to_vec(),
            label: "test".into(),
        };
        let key = crate::sdk::route_commit_sdk::external_commitment_key(x);
        BitcoinTapSdk::storage_put_bytes(&key, &anchor.encode_to_vec())
            .await
            .expect("X publish");
    }

    /// Publish a `RouteCommitV1` with a single AMM hop touching `vault_id`,
    /// bound to `parent_binding` (the c_n of the state it consumes). Returns
    /// the swap's post-trade reserves plus the canonical commitment `X`.
    #[allow(clippy::too_many_arguments)]
    async fn publish_rc_for_swap(
        nonce_seed: &[u8; 32],
        vault_id: &[u8; 32],
        parent_reserve_a: u64,
        parent_reserve_b: u64,
        parent_binding: &[u8; 32],
        input_is_a: bool,
        input_amount: u64,
        trader_pk: &[u8],
        trader_sk: &[u8],
    ) -> (u64, u64, [u8; 32]) {
        let (reserve_in, reserve_out) = if input_is_a {
            (parent_reserve_a, parent_reserve_b)
        } else {
            (parent_reserve_b, parent_reserve_a)
        };
        let simulated = crate::sdk::routing_path_sdk::constant_product_output(
            input_amount,
            reserve_in,
            reserve_out,
            FEE_BPS,
        )
        .expect("test inputs must yield a swap");
        let (new_a, new_b) = if input_is_a {
            (
                parent_reserve_a + input_amount,
                parent_reserve_b - simulated,
            )
        } else {
            (
                parent_reserve_a - simulated,
                parent_reserve_b + input_amount,
            )
        };

        let (hop_token_in, hop_token_out) = if input_is_a {
            (TOKEN_A.to_vec(), TOKEN_B.to_vec())
        } else {
            (TOKEN_B.to_vec(), TOKEN_A.to_vec())
        };
        let hop = generated::RouteCommitHopV1 {
            vault_id: vault_id.to_vec(),
            token_in: hop_token_in,
            token_out: hop_token_out,
            input_amount_u128: u128::from(input_amount).to_be_bytes().to_vec(),
            expected_output_amount_u128: u128::from(simulated).to_be_bytes().to_vec(),
            fee_bps: FEE_BPS,
            advertisement_digest: vec![0u8; 32],
            unlock_spec_digest: vec![0u8; 32],
            owner_public_key: Vec::new(),
            parent_binding: parent_binding.to_vec(),
        };
        let rc = generated::RouteCommitV1 {
            version: crate::sdk::route_commit_sdk::ROUTE_COMMIT_VERSION,
            nonce: nonce_seed.to_vec(),
            input_token: TOKEN_A.to_vec(),
            output_token: TOKEN_B.to_vec(),
            input_amount_u128: u128::from(input_amount).to_be_bytes().to_vec(),
            expected_final_output_amount_u128: u128::from(simulated).to_be_bytes().to_vec(),
            total_fee_bps: FEE_BPS as u64,
            hops: vec![hop],
            initiator_public_key: trader_pk.to_vec(),
            initiator_signature: Vec::new(),
        };
        let canonical_bytes = rc.encode_to_vec();
        let sig = dsm::crypto::sphincs::sphincs_sign(trader_sk, &canonical_bytes)
            .expect("sign route commit");
        let mut signed_rc = rc;
        signed_rc.initiator_signature = sig;
        let x = crate::sdk::route_commit_sdk::compute_external_commitment(&signed_rc);
        let rc_key = crate::sdk::route_commit_sdk::external_commitment_rc_key(&x);
        BitcoinTapSdk::storage_put_bytes(&rc_key, &signed_rc.encode_to_vec())
            .await
            .expect("signed RC publish");
        (new_a, new_b, x)
    }

    fn settled_trade(
        x: &[u8; 32],
        parent_seq: u64,
        input_is_a: bool,
        input_amount: u64,
        output_amount: u64,
    ) -> SettledTrade {
        let (in_pc, out_pc) = if input_is_a {
            (TOKEN_A, TOKEN_B)
        } else {
            (TOKEN_B, TOKEN_A)
        };
        SettledTrade {
            x: *x,
            parent_sequence: parent_seq,
            new_sequence: parent_seq + 1,
            input_policy_commit: in_pc,
            input_amount,
            output_policy_commit: out_pc,
            output_amount,
        }
    }

    /// Publish a receipt witnessing `trade` — the artifact that makes a pointer
    /// consumable. Builds a real SMT containing the receipt leaf, so the
    /// inclusion path is genuine rather than stubbed: these tests must fail if
    /// the verifier stops checking it.
    async fn publish_receipt(
        vault_id: &[u8; 32],
        trade: &SettledTrade,
        trader_pk: &[u8],
        trader_sk: &[u8],
    ) {
        let (genesis, devid) = ([0xA0u8; 32], [0xB0u8; 32]);
        let receipt_id = derive_receipt_id(vault_id, &trade.x);
        let key = settlement_receipt_key(&genesis, &devid, vault_id, &receipt_id);
        let mut tree = dsm::merkle::sparse_merkle_tree::SparseMerkleTree::new(64);
        tree.update_leaf(&key, &settlement_receipt_value(trade))
            .expect("update_leaf");
        let root = *tree.root();
        let sibs = tree.get_inclusion_proof(&key, 256).expect("proof").siblings;
        let receipt = sign_trader_settlement_receipt(
            vault_id,
            &receipt_id,
            *trade,
            &genesis,
            &devid,
            &root,
            sibs,
            trader_pk,
            trader_sk,
        )
        .expect("sign receipt");
        crate::sdk::settlement_receipt_codec::publish_settlement_receipt(&receipt)
            .await
            .expect("publish receipt");
    }

    #[allow(clippy::too_many_arguments)]
    async fn publish_pointer(
        vault_id: &[u8; 32],
        parent_seq: u64,
        new_seq: u64,
        x: &[u8; 32],
        trade: &SettledTrade,
        publisher_pk: &[u8],
        publisher_sk: &[u8],
    ) {
        let receipt_id = derive_receipt_id(vault_id, x);
        let expected_receipt_hash = receipt_commitment(vault_id, &receipt_id, trade);
        let marker = [0x5Au8; 32];
        let signed = sign_vault_pending_pointer(
            vault_id,
            parent_seq,
            new_seq,
            x,
            &marker,
            &expected_receipt_hash,
            publisher_pk,
            publisher_sk,
        )
        .expect("sign pointer");
        let proto = generated::VaultPendingPointerV1 {
            vault_id: signed.vault_id.to_vec(),
            parent_sequence: signed.parent_sequence,
            new_sequence: signed.new_sequence,
            x: signed.x.to_vec(),
            new_reserves_digest: signed.new_reserves_digest.to_vec(),
            expected_receipt_hash: signed.expected_receipt_hash.to_vec(),
            publisher_public_key: signed.publisher_public_key,
            publisher_signature: signed.publisher_signature,
        };
        let key = crate::sdk::route_commit_sdk::vault_pending_pointer_key(vault_id, new_seq, x);
        BitcoinTapSdk::storage_put_bytes(&key, &proto.encode_to_vec())
            .await
            .expect("publish pointer");
    }

    fn trader() -> (Vec<u8>, Vec<u8>) {
        let kp = generate_keypair(SphincsVariant::SPX256f).expect("keypair");
        (kp.public_key.clone(), kp.secret_key.clone())
    }

    /// One settled trade end-to-end on `parent`: X anchor, signed RC bound to
    /// the parent's `c_n`, pointer, a matching receipt, and the canonical
    /// bundle carrying the EXACT derived successor bound through the
    /// production driver. Returns that successor — `V_{n+1}` as the walk will
    /// install it, so a caller chaining a second trade stands on the same
    /// state the walk does.
    async fn publish_settled_trade(
        vault_id: &[u8; 32],
        nonce_seed: &[u8; 32],
        parent: &VaultStateV2,
        input_is_a: bool,
        input_amount: u64,
    ) -> VaultStateV2 {
        let parent_binding = vault_state_commitment(parent).expect("c_n");
        let (pk, sk) = trader();
        let (new_a, new_b, x) = publish_rc_for_swap(
            nonce_seed,
            vault_id,
            parent.reserve_a,
            parent.reserve_b,
            &parent_binding,
            input_is_a,
            input_amount,
            &pk,
            &sk,
        )
        .await;
        publish_extcommit(&x, &pk).await;
        let output = if input_is_a {
            parent.reserve_b - new_b
        } else {
            parent.reserve_a - new_a
        };
        let trade = settled_trade(&x, parent.generation, input_is_a, input_amount, output);
        publish_receipt(vault_id, &trade, &pk, &sk).await;
        // THE EDGE. Publishing evidence no longer makes a successor exist —
        // the network must have serialized this generation to this claimant.
        let successor = swapped(parent, parent_binding, input_is_a, input_amount);
        assert_eq!(
            (successor.reserve_a, successor.reserve_b),
            (new_a, new_b),
            "the RC's simulated swap and the predicate's derivation agree"
        );
        win_slot_with(vault_id, &x, &parent_binding, successor.clone(), &pk).await;
        successor
    }

    /// 2c-D §14 (C2) — REQ 21.15's WITHHOLD HALF, and no receipt-as-authority.
    ///
    /// Everything 5-c-1 realized on — a signed RouteCommit recomputing X, its
    /// published anchor, a verifying legacy receipt, and the slot bound to that
    /// trade — is present. Without the trader's acceptance none of it realizes
    /// anything: the parent is bound, the frontier stays there, and the
    /// reserves do not move. This test used to assert the opposite.
    #[tokio::test]
    async fn a_legacy_receipt_alone_does_not_realize_a_market_bundle() {
        let _fleet = fleet();
        let vault_id = vid(0x33);
        let (presentation, ccb, state, c0) = baseline_fixture(vault_id, 1_000_000, 500_000);
        publish_settled_trade(&vault_id, &x_seed(0x33), &state, true, 10_000).await;
        let composed =
            compose_vault_state(&vault_id, &presentation, &ccb, &TOKEN_A, &TOKEN_B, FEE_BPS)
                .await
                .expect("a bound, unrealized parent composes");
        assert!(
            matches!(
                composed.frontier_binding,
                FrontierBinding::BoundUnrealized { .. }
            ),
            "bound, and not realized: {:?}",
            composed.frontier_binding
        );
        assert_eq!(
            composed.sequence, 0,
            "the frontier stays at the bound parent"
        );
        assert_eq!(composed.c_n, c0);
        assert!(composed.folded_parents.is_empty(), "nothing folded");
        assert_eq!(
            (composed.reserves_a, composed.reserves_b),
            (1_000_000, 500_000),
            "reserves move on realization, never on binding or on a receipt"
        );
    }

    /// 2c-D §14 (C2) — PRESENT-AND-FAILING EVIDENCE IS INVALID, NOT ABSENT.
    ///
    /// The property the corrupted-receipt control used to hold, re-pointed at
    /// the evidence C2 reads first. A locator that IS present and is not a
    /// locator is decidably false, not "not published yet" — and it never
    /// quarantines, because anyone able to write the key could otherwise force
    /// a denial-of-service quarantine (2c-C3.1 ruling A).
    #[tokio::test]
    async fn a_present_but_malformed_acceptance_locator_is_invalid_not_absent() {
        let _fleet = fleet();
        let vault_id = vid(0x0C);
        let (presentation, ccb, state, _c0) = baseline_fixture(vault_id, 1_000_000, 500_000);
        publish_settled_trade(&vault_id, &x_seed(0x0C), &state, true, 10_000).await;
        let bound =
            compose_vault_state(&vault_id, &presentation, &ccb, &TOKEN_A, &TOKEN_B, FEE_BPS)
                .await
                .expect("bound, unrealized");
        let FrontierBinding::BoundUnrealized { bundle_digest, .. } = bound.frontier_binding else {
            panic!("bound: {:?}", bound.frontier_binding);
        };
        BitcoinTapSdk::storage_put_bytes(
            &crate::sdk::trader_acceptance_locator::locator_key(&bundle_digest),
            &[0xFF, 0xFF, 0xFF],
        )
        .await
        .expect("put");

        let err = compose_vault_state(&vault_id, &presentation, &ccb, &TOKEN_A, &TOKEN_B, FEE_BPS)
            .await
            .expect_err("a malformed locator must not compose — as a frontier or otherwise");
        let CompositionError::SuccessorInvalid { reason, detail } = err else {
            panic!("expected REALIZATION_EVIDENCE_INVALID, got {err:?}");
        };
        assert_eq!(reason, Reason::RealizationEvidenceInvalid);
        assert_eq!(reason.class(), OutcomeClass::Invalid);
        assert!(
            crate::storage::client_db::dlv_lineage_quarantine::roots_for_vault(&vault_id)
                .expect("readable")
                .is_empty(),
            "malformed evidence never quarantines"
        );
        assert!(
            detail.contains("locator"),
            "the refusal names the locator: {detail}"
        );
    }

    /// 2c-C3.1 — THE FIVE-EFFECT CONTROL for Req 6.3, on the walk.
    ///
    /// A trade is bound at generation 0 (value A), so this verifier RECORDS A
    /// as the finality at `k(c0)` — by its own commit and again by observation.
    /// (Under C2 it is bound and NOT realized; binding finality is the subject.) Then every member of the committed set serves a
    /// DIFFERENT chosen value B at the same key: a broken write-once register,
    /// the only way duplicate finality can arise, because one read at the
    /// canonical quorum cannot show two values. Each of the five effects is
    /// asserted on its own, so a mutation that removes one turns a NAMED
    /// assertion red while the others stay green.
    ///
    /// Restart-survival is a property of the on-disk table and is not
    /// simulated here: the test database is shared in-memory and cannot be
    /// closed without being lost.
    #[tokio::test]
    async fn duplicate_binding_finality_quarantines_the_lineage_with_all_five_effects() {
        use crate::storage::client_db::dlv_lineage_quarantine as quarantine;
        let _fleet = fleet();
        let vault_id = vid(0x31);
        let (presentation, ccb, state, c0) = baseline_fixture(vault_id, 1_000_000, 500_000);
        publish_settled_trade(&vault_id, &x_seed(0x31), &state, true, 10_000).await;
        let composed =
            compose_vault_state(&vault_id, &presentation, &ccb, &TOKEN_A, &TOKEN_B, FEE_BPS)
                .await
                .expect("A composes");
        // 2c-D §14 (C2): A is BOUND at generation 0 and, without its
        // certification evidence, NOT realized — the frontier stays at c0.
        // Req 6.3 concerns BINDING finality, so none of the five effects below
        // depends on realization, and none of them changed.
        let FrontierBinding::BoundUnrealized { bundle_digest, .. } = composed.frontier_binding
        else {
            panic!("A binds c0: {:?}", composed.frontier_binding);
        };
        assert_eq!(composed.sequence, 0);
        let a = quarantine::observed_finality(&vault_id, &c0)
            .expect("readable")
            .expect("the verifier recorded A at k(c0) the moment it established it");
        assert_eq!(a.value.tx_id, bundle_digest);
        // Re-observing the SAME value is not a contradiction: composing again
        // folds A again and writes no root.
        compose_vault_state(&vault_id, &presentation, &ccb, &TOKEN_A, &TOKEN_B, FEE_BPS)
            .await
            .expect("A still composes");
        assert!(quarantine::roots_for_vault(&vault_id)
            .expect("readable")
            .is_empty());

        // A member breaks its register: every member now serves B at k(c0).
        let all = ["dsm-node-1", "dsm-node-2", "dsm-node-3"];
        let k = dsm::dlv::settlement_bundle::resource_key(&c0);
        let b_digest = [0xB1u8; 32];
        let b_addr = dsm::storage_object::immutable_addr_from_inner(
            dsm::common::domain_tags::TAG_DSM_SETTLEMENT_BUNDLE,
            &b_digest,
        );
        crate::sdk::binding_fleet_double::plant_committed(
            &all,
            &[k],
            b_digest,
            b_digest,
            b_addr,
            dsm::storage::binding_record::Round {
                counter: a.round.counter + 10,
                proposer_id: [0xB1; 32],
            },
        );

        // E1 — REPORT: SAFETY_VIOLATION, with the live reason.
        let err = compose_vault_state(&vault_id, &presentation, &ccb, &TOKEN_A, &TOKEN_B, FEE_BPS)
            .await
            .expect_err("E1: duplicate finality does not compose");
        let CompositionError::SafetyViolation { reason, detail } = err else {
            panic!("E1: expected STORAGE_SAFETY_VIOLATION, got {err:?}");
        };
        assert_eq!(reason, Reason::DuplicateBindingFinality, "E1");
        assert!(
            detail.contains("duplicate binding finality"),
            "E1: {detail}"
        );

        // E2 — PRESERVE: the root holds BOTH evidence objects. The first is
        // this device's own commit of A (source (b)); the second is the
        // observed read of B, and it reproduces B when re-tallied.
        let roots = quarantine::roots_for_vault(&vault_id).expect("readable");
        assert_eq!(roots.len(), 1, "E2: one root");
        let root = &roots[0];
        assert_eq!(
            root.root_c_n, c0,
            "E2: the root is the parent A and B both bound"
        );
        assert_eq!(root.root_generation, 0, "E2");
        let first = quarantine::Evidence::decode(&root.first_evidence).expect("E2: first decodes");
        let second =
            quarantine::Evidence::decode(&root.second_evidence).expect("E2: second decodes");
        assert_eq!(first.value(), a.value, "E2: the first evidence is A");
        assert_eq!(
            second.value().tx_id,
            b_digest,
            "E2: the second evidence is B"
        );
        match &first {
            quarantine::Evidence::OwnCommit(c) => assert_eq!(c.value, a.value, "E2"),
            quarantine::Evidence::Observed(o) => o.recompute().expect("E2: first recomputes"),
        }
        let quarantine::Evidence::Observed(o) = &second else {
            panic!("E2: B was observed, not committed by this device");
        };
        o.recompute()
            .expect("E2: the preserved read of B reproduces B");

        // E3 — REFUSE COMPOSITION, DURABLY: the durable reason from now on,
        // with NO composed state — after the register is put back to A, and
        // when the register reads Free.
        let refused = |what: &str, err: CompositionError| {
            let CompositionError::SafetyViolation { reason, .. } = err else {
                panic!("E3 ({what}): expected STORAGE_SAFETY_VIOLATION, got {err:?}");
            };
            assert_eq!(reason, Reason::LineageQuarantined, "E3 ({what})");
        };
        refused(
            "second walk",
            compose_vault_state(&vault_id, &presentation, &ccb, &TOKEN_A, &TOKEN_B, FEE_BPS)
                .await
                .expect_err("E3"),
        );
        crate::sdk::binding_fleet_double::plant_committed(
            &all,
            &[k],
            a.value.tx_id,
            a.value.value_digest,
            a.value.value_addr,
            a.round,
        );
        refused(
            "register restored to A",
            compose_vault_state(&vault_id, &presentation, &ccb, &TOKEN_A, &TOKEN_B, FEE_BPS)
                .await
                .expect_err("E3"),
        );
        crate::sdk::binding_fleet_double::reset_all();
        crate::sdk::binding_fleet_double::register_set(&fleet_set());
        refused(
            "register reads Free",
            compose_vault_state(&vault_id, &presentation, &ccb, &TOKEN_A, &TOKEN_B, FEE_BPS)
                .await
                .expect_err("E3"),
        );

        // E4 — REFUSE EXECUTION ON THIS LINEAGE ONLY (walk side; the route
        // side is `dlv_routes`): the observer refuses this parent, and a
        // sibling vault on the same set composes.
        let set = fleet_set();
        let occ = crate::sdk::binding_occupancy::observe_parent_binding(
            &set,
            &vault_id,
            0,
            &c0,
            &set.id(),
            set.quorum(),
        )
        .await;
        let crate::sdk::binding_occupancy::ParentOccupancy::Unresolvable(why) = occ else {
            panic!("E4: expected a refusal, got {occ:?}");
        };
        assert_eq!(why.reason, Reason::LineageQuarantined, "E4");
        let sibling = vid(0x32);
        let (p2, ccb2, _s2, _c2) = baseline_fixture(sibling, 1_000_000, 500_000);
        let ok = compose_vault_state(&sibling, &p2, &ccb2, &TOKEN_A, &TOKEN_B, FEE_BPS)
            .await
            .expect("E4: a sibling vault on the same set is untouched");
        assert_eq!(ok.sequence, 0, "E4");

        // E5 — NEVER TIE-BREAK: no surface resolves k(c0) to a value, even with
        // A served again. The probe reports the quarantine and names nothing.
        crate::sdk::binding_fleet_double::plant_committed(
            &all,
            &[k],
            a.value.tx_id,
            a.value.value_digest,
            a.value.value_addr,
            a.round,
        );
        let probe = crate::sdk::binding_occupancy::probe_parent_binding(
            &set,
            &vault_id,
            0,
            &c0,
            &set.id(),
            set.quorum(),
        )
        .await;
        assert_eq!(probe.verdict, "LINEAGE_QUARANTINED", "E5");
        assert!(
            probe.tx_id.is_none() && probe.value_digest.is_none() && probe.value_addr.is_none(),
            "E5: no value is resolved on a quarantined key"
        );
    }

    /// THE FRONTIER, and the only way to reach one: q attributed members of
    /// the vault's own committed set each answer that the settlement-slot cell
    /// at this generation holds nothing.
    #[tokio::test]
    async fn an_empty_slot_cell_at_quorum_is_the_frontier() {
        let _fleet = fleet();
        let vault_id = vid(0x01);
        let (presentation, ccb, state, c0) = baseline_fixture(vault_id, 1_000_000, 500_000);
        let composed =
            compose_vault_state(&vault_id, &presentation, &ccb, &TOKEN_A, &TOKEN_B, FEE_BPS)
                .await
                .expect("composes");
        assert_eq!(composed.sequence, 0);
        assert_eq!(composed.reserves_a, 1_000_000);
        assert_eq!(composed.reserves_b, 500_000);
        assert_eq!(composed.c_n, c0);
        assert_eq!(composed.state, state);
        assert_eq!(composed.pending_chain_len, 0);
        assert_eq!(
            composed.storage_set_id,
            dsm::ccb::storage_set_id(&state.storage_set).expect("set id")
        );
        assert_eq!(composed.owner_devid, state.owner_device_id);
        assert_eq!(composed.owner_genesis, state.owner_genesis_id);
    }

    /// THE OMISSION MUTATION — the control this whole cut exists for.
    ///
    /// Under the old prefix-listing fold, a member that simply did not return
    /// a key produced a SHORT CHAIN that was reported as the composed state,
    /// indistinguishable from a genuinely shorter one. Here two of three
    /// members go silent, so fewer than the committed `q = 2` give an
    /// attributed answer, and the walk refuses instead of reporting the
    /// baseline as a frontier.
    #[tokio::test]
    async fn a_short_quorum_on_the_cell_is_not_a_frontier() {
        let _fleet = fleet();
        let vault_id = vid(0x0D);
        let (presentation, ccb, _state, _c0) = baseline_fixture(vault_id, 1_000_000, 500_000);
        crate::sdk::binding_fleet_double::fail_member_id("dsm-node-2");
        crate::sdk::binding_fleet_double::fail_member_id("dsm-node-3");

        let err = compose_vault_state(&vault_id, &presentation, &ccb, &TOKEN_A, &TOKEN_B, FEE_BPS)
            .await
            .expect_err("a short quorum establishes nothing");
        let CompositionError::BindingEvidenceUnavailable(detail) = err else {
            panic!("expected DLV_BINDING_EVIDENCE_UNAVAILABLE, got {err:?}");
        };
        assert!(
            detail.contains("answered the binding key"),
            "the refusal names the counting failure: {detail}"
        );
        // 2c-C3.1 ruling A: unavailable evidence MUST NOT create a quarantine.
        assert!(
            crate::storage::client_db::dlv_lineage_quarantine::roots_for_vault(&vault_id)
                .expect("readable")
                .is_empty(),
            "a short quorum never quarantines"
        );

        // Positive control: heal the members and the SAME vault composes to a
        // frontier, so the refusal above is the quorum rule and not a broken
        // fixture.
        crate::sdk::binding_fleet_double::heal_member_id("dsm-node-2");
        crate::sdk::binding_fleet_double::heal_member_id("dsm-node-3");
        let composed =
            compose_vault_state(&vault_id, &presentation, &ccb, &TOKEN_A, &TOKEN_B, FEE_BPS)
                .await
                .expect("composes once the members answer");
        assert_eq!(composed.sequence, 0);
    }

    /// Req 15.8 counting: a member whose response echoes SOMEONE ELSE'S id is
    /// uncountable. Two members answering, one of them impersonating the
    /// other, is one attributed answer — below `q`.
    #[tokio::test]
    async fn a_member_echoing_another_id_is_uncountable() {
        let _fleet = fleet();
        let vault_id = vid(0x0E);
        let (presentation, ccb, _state, _c0) = baseline_fixture(vault_id, 1_000_000, 500_000);
        crate::sdk::binding_fleet_double::fail_member_id("dsm-node-3");
        // node-2 answers naming node-1. That defeats BOTH halves of the
        // attribution rule — the id and the register incarnation — so it is
        // uncountable, and two honest answers cannot be reached.
        let impostor = crate::sdk::binding_fleet_double::endpoint_for_member("dsm-node-2")
            .expect("node-2 is registered");
        crate::sdk::binding_fleet_double::set_echo(&impostor, b"dsm-node-1".to_vec(), [1; 32]);

        let err = compose_vault_state(&vault_id, &presentation, &ccb, &TOKEN_A, &TOKEN_B, FEE_BPS)
            .await
            .expect_err("an impersonated echo cannot be counted");
        assert!(matches!(
            err,
            CompositionError::BindingEvidenceUnavailable(_)
        ));

        // Positive control: the SAME two members, honestly attributed, reach q.
        crate::sdk::binding_fleet_double::restore_echo(
            &impostor,
            "dsm-node-2",
            crate::economic_fixtures::fixture_register_incarnation_bytes("dsm-node-2"),
        );
        compose_vault_state(&vault_id, &presentation, &ccb, &TOKEN_A, &TOKEN_B, FEE_BPS)
            .await
            .expect("composes when both answers are attributable");
    }

    /// A key with NO CHOSEN VALUE is neither a frontier nor an edge.
    ///
    /// The old test forced two claimants onto one write-once cell. That state
    /// is unreachable through the driver here, and saying otherwise would be a
    /// test pretending the driver did something it structurally cannot: with
    /// n=3 and q=2, failing two members means no quorum forms AT ALL, so no
    /// single-member accept can be left behind.
    ///
    /// The reachable — and more accurate — hostile state is UNDETERMINED: an
    /// accepted record held below this reader's quorum, with no absence quorum
    /// either. The verdict is the same fail-closed, and the premise is honest.
    /// Reading it as "free" would let a composer walk straight past a bind that
    /// is still in flight.
    #[tokio::test]
    async fn a_key_with_no_chosen_value_is_neither_a_frontier_nor_an_edge() {
        let _fleet = fleet();
        let vault_id = vid(0x0F);
        let (presentation, ccb, _state, c0) = baseline_fixture(vault_id, 1_000_000, 500_000);
        // ONE member holds an accepted record; ONE is unreachable; the third
        // holds nothing. Attributed = 2 = q, but neither a chosen value nor a
        // quorum of explicit absences exists.
        crate::sdk::binding_fleet_double::plant_committed(
            &["dsm-node-1"],
            &[dsm::dlv::settlement_bundle::resource_key(&c0)],
            [0xAB; 32],
            [0xAB; 32],
            [0xCD; 32],
            dsm::storage::binding_record::Round {
                counter: 21,
                proposer_id: [0x7B; 32],
            },
        );
        crate::sdk::binding_fleet_double::fail_member_id("dsm-node-3");

        let err = compose_vault_state(&vault_id, &presentation, &ccb, &TOKEN_A, &TOKEN_B, FEE_BPS)
            .await
            .expect_err("an undecided key is not a frontier and not an edge");
        let CompositionError::BindingEvidenceUnavailable(detail) = err else {
            panic!("expected DLV_BINDING_EVIDENCE_UNAVAILABLE, got {err:?}");
        };
        assert!(
            detail.contains("not yet decided"),
            "the refusal names the undecided binding: {detail}"
        );
    }

    /// The presentation authenticates a state; handing the composer the bytes
    /// of a DIFFERENT state must refuse — the anchor's commitment does not
    /// match the bytes.
    #[tokio::test]
    async fn bytes_of_a_different_state_are_refused() {
        let _fleet = fleet();
        let vault_id = vid(0x02);
        let (presentation, _ccb, _state, _c0) = baseline_fixture(vault_id, 1_000_000, 500_000);
        let (_p2, other_ccb, _s2, _c2) = baseline_fixture(vault_id, 999, 999);
        let err = compose_vault_state(
            &vault_id,
            &presentation,
            &other_ccb,
            &TOKEN_A,
            &TOKEN_B,
            FEE_BPS,
        )
        .await
        .expect_err("must refuse");
        assert!(matches!(
            err,
            CompositionError::InvalidBaselinePresentation(_)
        ));
    }

    /// A caller tuple that disagrees with the signed state (wrong fee) is a
    /// baseline mismatch, not something to quote around.
    #[tokio::test]
    async fn a_caller_tuple_disagreeing_with_the_signed_state_is_refused() {
        let _fleet = fleet();
        let vault_id = vid(0x03);
        let (presentation, ccb, _state, _c0) = baseline_fixture(vault_id, 1_000_000, 500_000);
        let err = compose_vault_state(
            &vault_id,
            &presentation,
            &ccb,
            &TOKEN_A,
            &TOKEN_B,
            FEE_BPS + 1,
        )
        .await
        .expect_err("must refuse");
        assert!(matches!(err, CompositionError::BaselineMismatch(_)));

        let wrong_pair = compose_vault_state(
            &vault_id,
            &presentation,
            &ccb,
            &[0x33u8; 32],
            &[0x44u8; 32],
            FEE_BPS,
        )
        .await
        .expect_err("must refuse");
        assert!(matches!(wrong_pair, CompositionError::BaselineMismatch(_)));
    }

    /// Composing under a different vault id than the state names is refused.
    #[tokio::test]
    async fn a_presentation_for_another_vault_is_refused() {
        let _fleet = fleet();
        let vault_id = vid(0x04);
        let (presentation, ccb, _state, _c0) = baseline_fixture(vault_id, 1_000_000, 500_000);
        let other = vid(0x05);
        let err = compose_vault_state(&other, &presentation, &ccb, &TOKEN_A, &TOKEN_B, FEE_BPS)
            .await
            .expect_err("must refuse");
        assert!(matches!(err, CompositionError::BaselineMismatch(_)));
    }

    /// A BOUND generation whose trade has not settled is not a failure and not
    /// a frontier that anyone may build on: it is the realized frontier, MARKED
    /// BOUND.
    ///
    /// This is the behaviour the occupancy/realization split exists to produce.
    /// Under the write-once slot the walk could not tell "claimed, not settled
    /// yet" from "claimed, evidence wrong", so both fail-closed and the vault
    /// became uncomposable — which took `dlv_reconcile`, the very path that
    /// resolves it, down with it. Now the walk reports both facts at once: the
    /// reserves are unchanged (nothing realized) AND the parent is occupied
    /// (nobody may quote against it).
    #[tokio::test]
    async fn a_bound_generation_without_its_receipt_is_the_frontier_and_is_marked_bound() {
        let _fleet = fleet();
        let vault_id = vid(0x07);
        let (presentation, ccb, _state, c0) = baseline_fixture(vault_id, 1_000_000, 500_000);
        let (pk, sk) = trader();
        let (_na, _nb, x) = publish_rc_for_swap(
            &x_seed(0x07),
            &vault_id,
            1_000_000,
            500_000,
            &c0,
            true,
            10_000,
            &pk,
            &sk,
        )
        .await;
        publish_extcommit(&x, &pk).await;
        // Bound, RC published and valid — but NO receipt was ever written.
        win_slot(&vault_id, 0, &x, &c0, &pk).await;

        let composed =
            compose_vault_state(&vault_id, &presentation, &ccb, &TOKEN_A, &TOKEN_B, FEE_BPS)
                .await
                .expect("a bound-but-unsettled parent still composes");

        // NOTHING REALIZED. The reserves and the generation are the baseline's.
        assert_eq!(composed.sequence, 0, "no successor became economic state");
        assert_eq!(composed.reserves_a, 1_000_000);
        assert_eq!(composed.reserves_b, 500_000);
        assert_eq!(composed.c_n, c0);
        assert!(
            composed.folded_parents.is_empty(),
            "an unrealized bundle folds nothing"
        );

        // AND THE PARENT IS OCCUPIED, naming the trade that owns it — so a
        // caller can tell its OWN trade's bundle from a stranger's without
        // re-fetching the bytes this walk already read.
        match composed.frontier_binding {
            FrontierBinding::BoundUnrealized {
                route_set_commitment,
                ..
            } => assert_eq!(
                route_set_commitment, x,
                "the reported X is the bound bundle's own"
            ),
            other => panic!("expected BoundUnrealized, got {other:?}"),
        }
    }

    /// A pointer creates no edge. Under the cell walk a self-signed pointer
    /// from an arbitrary keypair is not consulted at all, so the griefing case
    /// the old fold had to reason about carefully cannot even be expressed:
    /// the cell is empty, and the vault is fully quotable.
    #[tokio::test]
    async fn a_forged_pointer_creates_no_edge_and_cannot_suppress_liquidity() {
        let _fleet = fleet();
        let vault_id = vid(0x0C);
        let (presentation, ccb, state, c0) = baseline_fixture(vault_id, 1_000_000, 500_000);
        let (attacker_pk, attacker_sk) = trader();
        let x = x_seed(0x0C);
        let fake_trade = settled_trade(&x, 0, true, 1, 1);
        publish_pointer(&vault_id, 0, 1, &x, &fake_trade, &attacker_pk, &attacker_sk).await;

        let composed =
            compose_vault_state(&vault_id, &presentation, &ccb, &TOKEN_A, &TOKEN_B, FEE_BPS)
                .await
                .expect("composes");
        assert_eq!(composed.pending_chain_len, 0);
        assert_eq!(composed.sequence, 0);
        assert_eq!(
            composed.state, state,
            "one arbitrary-keypair storage write must not change what any verifier composes"
        );
        assert_eq!(composed.c_n, c0);
    }

    /// The fixture owner's authority keypair — the key the presentation's
    /// P0-P6 chain delegates to, so a close it signs is one the composer
    /// verifies as the OWNER's.
    fn owner_keys() -> (Vec<u8>, Vec<u8>) {
        let aph = dsm::core::identity::genesis_session::genesis_authority_policy_hash();
        let g = dsm::core::identity::genesis_v3::derive_genesis_v3_self_attested(
            SEED,
            INPUTS.network_id,
            INPUTS.wallet_index,
            INPUTS.device_slot,
            INPUTS.genesis_version,
            &aph,
        )
        .expect("the fixture owner's genesis derives");
        (g.ak_public.clone(), g.ak_secret.clone())
    }

    /// AN AUTHORIZED CLOSE FOLDS `Valid` — C3 owner-close completion, live.
    ///
    /// The owner's real authorization over the exact release successor, the
    /// canonical bundle carrying the exact drained successor, bound through
    /// the production driver: the walk verifies the authorization under the
    /// authority the parent committed, derives the same successor,
    /// `VDS.COMMON.10.a` holds byte for byte, and the fold's verdict is the
    /// one verdict that certifies. The installed `c_{n+1}` is the witness's —
    /// from the SUPPLIED bytes — and equals the commitment of the derived
    /// state.
    #[tokio::test]
    async fn an_authorized_close_folds_valid_and_certifies() {
        let _fleet = fleet();
        let vault_id = vid(0x1D);
        let (presentation, ccb, state, c0) = baseline_fixture(vault_id, 1_000_000, 500_000);
        let set = fleet_set();
        let (_owner_pk, owner_sk) = owner_keys();
        let release = dsm::dlv::close_authorization::CloseSuccessor {
            vault_id,
            leg_a_policy_commit: TOKEN_A,
            leg_a_amount: 1_000_000,
            leg_b_policy_commit: TOKEN_B,
            leg_b_amount: 500_000,
            parent_sequence: 0,
            fee_bps: FEE_BPS,
        };
        let sig = dsm::dlv::close_authorization::sign_close_authorization(&release, &owner_sk)
            .expect("the owner signs");
        let drained_state = drained(&state, c0);
        let bundle = crate::sdk::settlement_bind::close_bundle(c0, drained_state.clone(), sig)
            .expect("builds");
        assert_eq!(
            crate::sdk::settlement_bind::bind_settlement(&set, [0x9F; 32], &bundle, vault_id, c0)
                .await
                .expect("drive the bind"),
            Ok(dsm::dlv::quorum_bind::Outcome::Committed)
        );

        let composed =
            compose_vault_state(&vault_id, &presentation, &ccb, &TOKEN_A, &TOKEN_B, FEE_BPS)
                .await
                .expect("the owner's close folds");
        assert_eq!(
            (composed.sequence, composed.reserves_a, composed.reserves_b),
            (1, 0, 0),
            "the vault is dead"
        );
        assert_eq!(
            composed.state, drained_state,
            "the installed state IS the carried one"
        );
        assert_eq!(
            composed.c_n,
            vault_state_commitment(&drained_state).expect("commits"),
            "c_{{n+1}} of the exact successor"
        );
        assert_eq!(composed.folded_parents.len(), 1);
        let fold = &composed.folded_parents[0];
        assert_eq!(
            fold.bound_kind,
            dsm::dlv::settlement_bundle::BundleShape::OwnerClose
        );
        let C3Verdict::Valid(validity) = &fold.verdict else {
            panic!("an authorized close is C3-complete, got {:?}", fold.verdict);
        };
        assert_eq!(validity.witness().c_next(), composed.c_n);
        assert_eq!(validity.witness().parent_commitment(), c0);
        assert!(
            fold.verdict.may_certify(),
            "the close's 10.a was its last conjunct"
        );
        assert_eq!(fold.verdict.class(), OutcomeClass::Valid);
    }

    /// VDS.COMMON.10.a, CLOSE — THE MUTATION BY CONSTRUCTION. The owner's
    /// REAL authorization (it covers the release coordinates: legs, amounts,
    /// generation, fee) over a bundle whose field 2 is a drained, linked
    /// successor with ONE preserved field changed — a budget where the parent
    /// carries none. Every check but the byte comparison passes: the
    /// signature verifies, the constructor accepts a retired linked
    /// successor, the derivation succeeds. Only `10.a` sees that the state
    /// the bundle would install is not the state the owner's close derives —
    /// which is exactly why Ruling B makes the field dispositions its
    /// consequence rather than the signature's.
    #[tokio::test]
    async fn a_close_bundle_carrying_a_successor_other_than_the_derived_one_fails_10a() {
        let _fleet = fleet();
        let vault_id = vid(0x1E);
        let (presentation, ccb, state, c0) = baseline_fixture(vault_id, 1_000_000, 500_000);
        let set = fleet_set();
        let (_owner_pk, owner_sk) = owner_keys();
        let release = dsm::dlv::close_authorization::CloseSuccessor {
            vault_id,
            leg_a_policy_commit: TOKEN_A,
            leg_a_amount: 1_000_000,
            leg_b_policy_commit: TOKEN_B,
            leg_b_amount: 500_000,
            parent_sequence: 0,
            fee_bps: FEE_BPS,
        };
        let sig = dsm::dlv::close_authorization::sign_close_authorization(&release, &owner_sk)
            .expect("the owner signs");
        let mut carried = drained(&state, c0);
        carried.iteration_budget = Some(5);
        let bundle = crate::sdk::settlement_bind::close_bundle(c0, carried, sig)
            .expect("retired and linked: the constructor accepts it");
        assert_eq!(
            crate::sdk::settlement_bind::bind_settlement(&set, [0xA0; 32], &bundle, vault_id, c0)
                .await
                .expect("drive the bind"),
            Ok(dsm::dlv::quorum_bind::Outcome::Committed),
            "the register is application-blind"
        );

        let err = compose_vault_state(&vault_id, &presentation, &ccb, &TOKEN_A, &TOKEN_B, FEE_BPS)
            .await
            .expect_err("the carried successor is not the derived one");
        let CompositionError::SuccessorInvalid { reason, detail } = err else {
            panic!("expected CORRESPONDENCE_MISMATCH, got {err:?}");
        };
        assert_eq!(reason, Reason::CorrespondenceMismatch);
        assert_eq!(reason.class(), OutcomeClass::Invalid);
        assert!(
            detail.contains("VDS.COMMON.10.a"),
            "the refusal names the conjunct: {detail}"
        );
        // That the refusal is the comparison's and not the signature's is the
        // sibling test: the same key, the same release, the DERIVED successor
        // — and the fold is Valid.
    }

    /// A STRANGER CANNOT CLOSE SOMEBODY ELSE'S VAULT.
    ///
    /// The drained successor and its `c_{n+1}` are PUBLIC derivations from a
    /// public parent, and the binding register is application-blind by design
    /// (§22 #12), so anyone can build a close-shaped bundle naming a victim's
    /// vault at its current `c_n` and bind it. The register will accept it —
    /// that is not its job.
    ///
    /// What stops the composer folding that vault to zero is the owner's
    /// signature over the exact release successor. This is the mutation control
    /// for that gate: it reproduces the forbidden STATE (a bound close-shaped
    /// bundle from a non-owner) and asserts the vault does NOT die.
    #[tokio::test]
    async fn a_stranger_cannot_close_a_vault_by_binding_a_close_shaped_bundle() {
        let _fleet = fleet();
        let vault_id = vid(0x1B);
        let (presentation, ccb, state, c0) = baseline_fixture(vault_id, 1_000_000, 500_000);
        let set = fleet_set();

        // A stranger's key, and a close-shaped bundle for the victim's vault at
        // its real current parent — every input to it is public.
        let (_stranger_pk, stranger_sk) = trader();
        let successor = dsm::dlv::close_authorization::CloseSuccessor {
            vault_id,
            leg_a_policy_commit: TOKEN_A,
            leg_a_amount: 1_000_000,
            leg_b_policy_commit: TOKEN_B,
            leg_b_amount: 500_000,
            parent_sequence: 0,
            fee_bps: FEE_BPS,
        };
        let forged =
            dsm::dlv::close_authorization::sign_close_authorization(&successor, &stranger_sk)
                .expect("a stranger can always sign SOMETHING");
        let bundle = crate::sdk::settlement_bind::close_bundle(c0, drained(&state, c0), forged)
            .expect("a close-shaped bundle over a public parent always builds");
        let out =
            crate::sdk::settlement_bind::bind_settlement(&set, [0x9E; 32], &bundle, vault_id, c0)
                .await
                .expect("drive the bind");
        assert_eq!(
            out,
            Ok(dsm::dlv::quorum_bind::Outcome::Committed),
            "THE REGISTER ACCEPTS IT — it is application-blind, and that is the \
             premise of this test, not a defect"
        );

        // AND THE VAULT DOES NOT DIE. The composer refuses rather than folding
        // to the terminal zero-reserve state.
        let err = compose_vault_state(&vault_id, &presentation, &ccb, &TOKEN_A, &TOKEN_B, FEE_BPS)
            .await
            .expect_err("a close nobody authorized must not compose as a closed vault");
        // FLIPPED by amendment 2c-C3. A close no owner signed is DECIDABLY
        // FALSE (VDS.CLOSE.2), not evidence we failed to obtain. Reporting it
        // as unavailable told a caller to retry a bundle that can never verify.
        let CompositionError::SuccessorInvalid { reason, detail } = err else {
            panic!("expected SUCCESSOR_SIGNATURE_INVALID, got {err:?}");
        };
        assert_eq!(reason, Reason::SuccessorSignatureInvalid);
        assert_eq!(reason.class(), OutcomeClass::Invalid);
        assert!(
            detail.contains("not authorized by the vault owner"),
            "the refusal names the missing authorization: {detail}"
        );
    }

    /// AUTHORIZATION BEFORE OCCUPANCY — the ordering is the safety property.
    ///
    /// The signature alone is not enough; WHEN it is checked decides whether a
    /// failure is recoverable. `dlv_close` signs with the device's CURRENT
    /// authority key, while every composer verifies under the authority the
    /// vault's PARENT committed. Those can differ — a rotated or delegated
    /// owner authority — and the two orderings then diverge sharply:
    ///
    ///   authorize, then bind  -> refusal. Nothing was consumed; the parent is
    ///                            still free and a correctly-authorized close
    ///                            can still happen.
    ///   bind, then authorize  -> the bind SUCCEEDS (the register is
    ///                            application-blind), the parent is consumed,
    ///                            and no composer will ever realize it. The
    ///                            vault is permanently occupied and unclosable
    ///                            — a liveness failure reachable only AFTER
    ///                            winning contention, with no error at the
    ///                            point of failure.
    ///
    /// This pins both halves. It is the control for the preflight in
    /// `dlv.close`, which runs `verify_close_authorization` BEFORE the first
    /// mutating binding op precisely to keep the second row unreachable.
    #[tokio::test]
    async fn an_unauthorized_close_must_be_refused_before_it_reaches_occupancy() {
        let _fleet = fleet();
        let vault_id = vid(0x1C);
        let (presentation, ccb, state, c0) = baseline_fixture(vault_id, 1_000_000, 500_000);
        let set = fleet_set();

        let composed =
            compose_vault_state(&vault_id, &presentation, &ccb, &TOKEN_A, &TOKEN_B, FEE_BPS)
                .await
                .expect("the fresh vault composes");
        assert_eq!(composed.frontier_binding, FrontierBinding::Free);

        // A signer that does NOT satisfy the authority this parent committed —
        // what a rotated owner authority looks like to the composer.
        let (_other_pk, other_sk) = trader();
        let successor = dsm::dlv::close_authorization::CloseSuccessor {
            vault_id,
            leg_a_policy_commit: TOKEN_A,
            leg_a_amount: 1_000_000,
            leg_b_policy_commit: TOKEN_B,
            leg_b_amount: 500_000,
            parent_sequence: 0,
            fee_bps: FEE_BPS,
        };
        let sig = dsm::dlv::close_authorization::sign_close_authorization(&successor, &other_sk)
            .expect("sign");
        let bundle = crate::sdk::settlement_bind::close_bundle(c0, drained(&state, c0), sig)
            .expect("a close-shaped bundle over a public parent always builds");

        // ── ORDER 1: authorize first. This is what `dlv.close` does. ─────────
        assert!(
            dsm::dlv::close_authorization::verify_close_authorization(
                &bundle,
                &successor,
                &composed.owner_public_key,
            )
            .is_err(),
            "the preflight must refuse a close the parent's authority did not sign"
        );
        // Nothing was bound, because the refusal came first.
        let after =
            compose_vault_state(&vault_id, &presentation, &ccb, &TOKEN_A, &TOKEN_B, FEE_BPS)
                .await
                .expect("still composes");
        assert_eq!(
            after.frontier_binding,
            FrontierBinding::Free,
            "a refused close must consume NOTHING — the parent stays available"
        );
        assert_eq!(
            (after.sequence, after.reserves_a, after.reserves_b),
            (0, 1_000_000, 500_000)
        );

        // ── ORDER 2: bind first, and see what the preflight prevents. ────────
        // This is the mutation, performed by construction rather than by
        // editing the gate out: the register accepts the bundle because it does
        // not inspect values, so occupancy is consumed by a close that can
        // never be realized.
        assert_eq!(
            crate::sdk::settlement_bind::bind_settlement(&set, [0x9C; 32], &bundle, vault_id, c0)
                .await
                .expect("drive the bind"),
            Ok(dsm::dlv::quorum_bind::Outcome::Committed),
            "the application-blind register accepts it — that is the premise"
        );
        let err = compose_vault_state(&vault_id, &presentation, &ccb, &TOKEN_A, &TOKEN_B, FEE_BPS)
            .await
            .expect_err("and now nothing can realize it");
        // FLIPPED by amendment 2c-C3 — see the sibling test.
        let CompositionError::SuccessorInvalid { reason, detail } = err else {
            panic!("expected SUCCESSOR_SIGNATURE_INVALID, got {err:?}");
        };
        assert_eq!(reason, Reason::SuccessorSignatureInvalid);
        assert!(
            detail.contains("not authorized by the vault owner"),
            "the vault is now occupied by an unrealizable close: {detail}"
        );
        // THE PERMANENT BRICK: the parent is taken, so even a correctly
        // authorized close can no longer bind it. This is the state the
        // preflight's ordering exists to keep unreachable.
        let ordered = crate::sdk::settlement_bind::bind_settlement(
            &set,
            [0x9D; 32],
            &crate::sdk::settlement_bind::close_bundle(
                c0,
                drained(&state, c0),
                // Length-valid stand-in: the register is application-blind and
                // never verifies it, and the bind is what this asserts on.
                dsm::ccb::settlement::fixtures::signature_bytes(0x9D),
            )
            .expect("builds"),
            vault_id,
            c0,
        )
        .await
        .expect("drive the second bind");
        assert!(
            !matches!(ordered, Ok(dsm::dlv::quorum_bind::Outcome::Committed)),
            "a later, correctly authorized close cannot take a parent that is already \
             consumed — the vault is permanently unclosable, which is exactly what \
             authorizing before binding prevents"
        );
    }

    /// A bundle bound at a key it DOES NOT NAME is a divergence.
    ///
    /// `K(B)` is derived from `parent_state_commitment`, so the production
    /// driver structurally cannot put a bundle at a key its own transitions
    /// contradict — only a hand-built key set can, and the node is
    /// application-blind (§22 #12) and would accept one. So this plants the
    /// record directly: that is the honest way to reach a state the driver
    /// cannot produce, and the walk's parent check is the ONLY thing standing
    /// between it and a fold.
    #[tokio::test]
    async fn a_bundle_bound_at_a_key_it_does_not_name_fails_closed() {
        let _fleet = fleet();
        let vault_id = vid(0x10);
        let (presentation, ccb, _state, c0) = baseline_fixture(vault_id, 1_000_000, 500_000);
        let stale = [0xEEu8; 32];
        assert_ne!(stale, c0);
        let (pk, _sk) = trader();
        // A perfectly well-formed bundle — for a DIFFERENT parent.
        win_slot(&vault_id, 0, &x_seed(0x10), &stale, &pk).await;
        // Now plant its committed record at THIS parent's key, which is what
        // an application-blind register permits.
        let bundle =
            market_bundle_for_tests(&stale, any_successor(&vault_id, 0, &stale), &x_seed(0x10));
        let canon = dsm::dlv::settlement_bundle::canon(&bundle).expect("canon");
        crate::sdk::binding_fleet_double::plant_committed(
            &["dsm-node-1", "dsm-node-2"],
            &[dsm::dlv::settlement_bundle::resource_key(&c0)],
            dsm::dlv::settlement_bundle::bundle_digest(&canon),
            dsm::dlv::settlement_bundle::bundle_digest(&canon),
            dsm::dlv::settlement_bundle::bundle_addr(&canon),
            dsm::storage::binding_record::Round {
                counter: 41,
                proposer_id: [0x7C; 32],
            },
        );

        let err = compose_vault_state(&vault_id, &presentation, &ccb, &TOKEN_A, &TOKEN_B, FEE_BPS)
            .await
            .expect_err("a bundle bound elsewhere is a divergence");
        // FLIPPED by amendment 2c-C3. A bundle bound at a key it does not name
        // is a divergence, and a divergence is never an absence.
        let CompositionError::SuccessorInvalid { reason, detail } = err else {
            panic!("expected STALE_PARENT, got {err:?}");
        };
        assert_eq!(reason, Reason::StaleParent);
        assert_eq!(reason.class(), OutcomeClass::Invalid);
        assert!(
            detail.contains("different parent state"),
            "the refusal names the binding: {detail}"
        );
    }
}
