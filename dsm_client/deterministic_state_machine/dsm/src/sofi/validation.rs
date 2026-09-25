// SPDX-License-Identifier: Apache-2.0

//! `RouteValidation(P, G, E)` — static semantic validity, three-valued.
//!
//! This is the whole of what a verifier can decide about an operation from the
//! operation itself: the arithmetic, the write sets, the policies, the scope
//! and the bytes. It reads NO attempt index, no storage finality, no parent
//! canonicality and no outcome — those belong to consumption (F4), and keeping
//! them out is what makes a verdict a function of `P` alone, so every
//! fulfillment of one precommit sees the same one.
//!
//! ## Three values, and which is which
//!
//! - `Invalid` — a bound was violated, arithmetic disagreed, or a rule the
//!   verifier can evaluate was broken. Permanent.
//! - `Unavailable` — an object the check needs was not supplied. Never a
//!   verdict about the operation; more evidence may still make it Valid or
//!   Invalid (notes 9 and 10).
//! - `Valid` — every check passed.
//!
//! Missing evidence can never be read as invalidity, and a proven violation is
//! never softened into Unavailable. That asymmetry is the whole of R13-1/R13-2.
//!
//! ## What Valid does NOT create
//!
//! Credit. A valid route is a legitimate proposal, nothing more: the trader's
//! output becomes canonical only when the fulfillment resolves Realized and
//! `advance_resolved` installs `P.realize_root` (P15-9, R15-5).

use std::collections::{BTreeMap, BTreeSet};

use crate::ccb::state::{FeePolicy, MarketPolicy, ReleasePolicy};
use crate::dlv::route_commit::constant_product_output_classified;
use crate::economic::keys::balance_key;
use crate::economic::lineage::AcceptedClaim;
use crate::economic::state::{EconomicBalanceState, EconomicLeafState};

use super::conformance::Validation;
use super::derive;
use super::smt::{verify_batch, FoldEntry, FoldError};
use super::wire::{
    next_position, CoreEntry, DlvCore, OwnerAuthority, SettlementBody, SettlementPreimage, SwapHop,
    TraderCore, TraderPrecommitBody, TraderRelationshipLeaf, VaultRelationshipLeaf, VaultStateLeaf,
    MAX_SETTLEMENT_PREIMAGE_BYTES, VAULT_STATUS_ACTIVE, VAULT_STATUS_RETIRED,
};

type D32 = [u8; 32];

/// A refusal a verifier can prove from what it has. Every variant is
/// permanent: no amount of further evidence turns one into Valid.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Invalid {
    /// `P(E)` exceeds the frozen byte bound (R8-12).
    PreimageTooLarge { bytes: usize, max: usize },
    /// `E` does not recompute from the preimage, so P names another operation.
    ExternalCommitmentMismatch,
    /// `P`'s legs are not exactly the operation's DLV parents.
    LegsDoNotMatchPrecommit,
    /// A core is not the trader's, or not at the successor position (P15-1).
    CoreIdentityMismatch,
    /// `P.void_root != T°.pre_root` (P15-2).
    VoidRootIsNotThePreRoot,
    /// `P.realize_root` is not what the trader core folds to under `E` (P15-2).
    RealizeRootIsNotTheFold,
    /// A core's entries do not fold: the paths are not of one tree.
    CoreDoesNotFold { reason: &'static str },
    /// A write set holds an entry the branch does not permit, or is missing
    /// one it requires (P15-7).
    WriteSetNotExact { core: &'static str },
    /// A leaf's stated pre-value is not the value of the evidence supplied
    /// for it.
    LeafPreValueMismatch,
    /// A leaf's post-value is not what the operation's own arithmetic makes it.
    LeafPostValueMismatch,
    /// A hop's output is not the constant-product output of its inputs.
    PriceIsNotTheConstantProduct { hop: usize },
    /// A hop's input is not the previous hop's output, or the route's ends are
    /// not the intent's.
    RouteDoesNotChain { hop: usize },
    /// A token is not one of its vault's pair.
    TokenIsNotInTheVaultPair { hop: usize },
    /// The operation crosses a vault pinned to another storage set.
    NetworkScopeMismatch,
    /// A policy object the vault names does not decode under the beta profile.
    /// The family check lives in the decoder, so a release policy that is not
    /// the close family simply has no decoding — and therefore cannot
    /// authorize a close.
    PolicyDoesNotDecode { class: u16 },
    /// A close's reserves are not the vault's committed reserves, or the
    /// retired state is not both-zero at generation + 1.
    CloseDoesNotRetireExactly,
    /// The closer is not the vault's owner (P15-11).
    NotTheVaultOwner,
    /// The vault's own state does not derive the vault id it is stored under,
    /// so the state was taken from another vault.
    VaultIdIsNotTheOwnersDerivation,
    /// The operation touches a vault that is not Active. Retired is terminal.
    VaultIsNotActive,
    /// The close names the reserved DSM-succession authority, which this
    /// protocol has not activated (R18-1). A verifier KNOWS the branch is not
    /// live, so this is Invalid and never Unavailable.
    OwnerAuthorityNotActivated,
    /// A vault's generation, a reserve or a balance would overflow. Refused,
    /// never wrapped.
    CheckedArithmetic { what: &'static str },
    /// A relationship entry does not advance from the base the cores agree on.
    RelationshipBaseMismatch,
    /// A vault leaf the operation writes is not the class that key holds — an
    /// observed absence or a wrong leaf type, not a missing fetch.
    VaultLeafIsNotItsClass,
    /// `B°` names a core that is not the one `P(E)` carries. The reference is
    /// what binds the body to the cores, so a mismatch is not a detail.
    SettlementCoreReferenceMismatch { field: &'static str },
    /// A `V°` relationship entry, or the leaf it advances, belongs to another
    /// trader than the core's own marker says.
    RelationshipIdentityMismatch,
    /// A leg's setup names another trader than the precommit's.
    SetupNotThisTrader,
    /// A leg's setup names another vault than the leg's.
    SetupNotThisVault,
    /// A leg's setup is not signed by the precommit's trader key.
    SetupSignature(crate::sofi::signature::SignatureError),
    /// A leg's setup names a claim at its position other than the one the
    /// trader's lineage accepted there (SoFi §16, Amendment S9).
    SetupClaimRefIsNotTheAcceptedClaim,
    /// A token's committed policy does not parse.
    TokenPolicyDoesNotParse { token: D32 },
    /// A token's committed policy forbids transfer, so it cannot be a market
    /// leg — the vault's, or any hop's through it (SoFi §19.5, §49).
    TokenNotTransferable { token: D32 },
}

/// The conjunction, as an accumulator: any Invalid dominates, and only in its
/// absence does missing evidence stop the predicate. A validator that returned
/// on the first missing object would let evidence a verifier happens not to
/// hold mask an invalidity it could already prove. So every
/// INDEPENDENTLY decidable check runs, and only checks that genuinely need the
/// missing datum are skipped.
#[derive(Debug, Default)]
struct Verdict {
    invalid: Option<Invalid>,
    missing: Option<Missing>,
}

impl Verdict {
    /// Fold one check's outcome in. The first Invalid is kept, because it is
    /// the one that is permanent.
    fn note(&mut self, outcome: Result<(), Refusal>) {
        match outcome {
            Ok(()) => {}
            Err(Refusal::Invalid(reason)) => {
                if self.invalid.is_none() {
                    self.invalid = Some(reason);
                }
            }
            Err(Refusal::Incomplete(what)) => {
                if self.missing.is_none() {
                    self.missing = Some(what);
                }
            }
        }
    }

    /// Run a check that produces a value, folding its refusal in and handing
    /// back `None` when it could not run.
    fn get<T>(&mut self, outcome: Result<T, Refusal>) -> Option<T> {
        match outcome {
            Ok(value) => Some(value),
            Err(refusal) => {
                self.note(Err(refusal));
                None
            }
        }
    }

    fn finish(self) -> Result<(), Refusal> {
        if let Some(reason) = self.invalid {
            return Err(Refusal::Invalid(reason));
        }
        if let Some(what) = self.missing {
            return Err(Refusal::Incomplete(what));
        }
        Ok(())
    }
}

/// An object the acquisition layer has not yet got for `RouteValidation`.
/// Never a statement about the operation, and never a predicate value: the
/// predicate is not evaluated until nothing is missing (Amendment S3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Missing {
    /// A policy object named by a vault state, by content address.
    Policy { addr: D32 },
    /// The pre-state of an `R_econ` leaf a core writes.
    TraderLeaf { key: D32 },
    /// The pre-state of a vault leaf a core writes.
    VaultLeaf { vault_id: D32, key: D32 },
    /// The vault's own state leaf, which every branch needs.
    VaultState { vault_id: D32 },
    /// The signed setup envelope stored at `ρ` for one of P's legs.
    Setup { setup_ref: D32 },
    /// The claim this verifier accepted at a position of P's trader, which a
    /// setup names by `claim_ref` (SoFi Amendment S9).
    AcceptedClaim { economic_position: u64 },
    /// Bytes were supplied for an address but do not authenticate to it. They
    /// establish NOTHING — note 9: a non-verifying candidate can never prove
    /// invalidity, it only fails to supply the object.
    NonVerifyingObject { addr: D32 },
    /// The `TokenPolicyV3` bytes a market token's policy commit names.
    TokenPolicy { commit: D32 },
}

/// Why validation stopped. `Invalid` is the predicate's value. `Incomplete`
/// is not a value at all: the evidence lacks an object, so the predicate is
/// not evaluated yet, and the acquisition layer fetches what is named
/// (Amendment S3). A missing or non-verifying object never proves invalidity
/// (note 9); an invalidity provable from what is in hand stands regardless.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    Invalid(Invalid),
    Incomplete(Missing),
}

impl Refusal {
    /// The predicate's value, when the refusal is one.
    pub fn validation(&self) -> Result<Validation, Missing> {
        match self {
            Self::Invalid(_) => Ok(Validation::Invalid),
            Self::Incomplete(m) => Err(m.clone()),
        }
    }
}

/// What a trader's `R_econ` leaf held before the operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TraderLeafPre {
    Balance(EconomicBalanceState),
    Relationship(TraderRelationshipLeaf),
    /// The leaf held nothing — a first credit, or a first relationship.
    Absent,
}

/// What a vault's leaf held before the operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VaultLeafPre {
    State(VaultStateLeaf),
    Relationship(VaultRelationshipLeaf),
    Absent,
}

/// Everything `RouteValidation` consumes, complete for its preimage. The
/// acquisition layer builds it only once every item [`EvidenceNeeds`] and the
/// fetched vault states name is in hand and authenticates; until then it
/// reports [`Missing`] and retries, and the predicate is not evaluated.
///
/// Gate G2: `Default` exists only under `cfg(test)`. Production code builds
/// this ONLY from fetched bytes, through [`Evidence::acquired`] at the end of
/// an acquisition (rebuild step R5): trader leaf pre values from the
/// verifier's own validated tree, vault leaf pre values from the vault
/// lineage it fetched, policy objects from the immutable store under the
/// address the vault state commits. Nothing is defaulted or filled in.
#[derive(Debug, Clone)]
#[cfg_attr(test, derive(Default))]
pub struct Evidence {
    /// Canonical bytes by content address — the policy objects a vault names.
    pub objects: BTreeMap<D32, Vec<u8>>,
    /// Pre-states of the trader's own leaves, by `R_econ` key.
    pub trader_leaves: BTreeMap<D32, TraderLeafPre>,
    /// Pre-states of vault leaves, by `(vault_id, key)`.
    pub vault_leaves: BTreeMap<(D32, D32), VaultLeafPre>,
    /// The signed setup envelope stored at `ρ`, for every leg of P: what
    /// `SetupValid` is decided over (SoFi §16, §20.1).
    pub setups: BTreeMap<D32, Vec<u8>>,
    /// Exact `TokenPolicyV3` bytes by `policy_commit`, for both tokens of
    /// every vault the operation touches, an intermediate token included
    /// (SoFi §19.5, §49). Re-hashed to the commit under `TAG_DSM_POLICY` when
    /// consumed: bytes supplied under a commit prove nothing by themselves.
    pub token_policies: BTreeMap<D32, Vec<u8>>,
    /// The claims this verifier accepted on P's trader's lineage, by
    /// position: what each setup's `claim_ref` is checked against (SoFi
    /// Amendment S9). Only lineage validation produces an [`AcceptedClaim`].
    pub accepted_claims: BTreeMap<u64, AcceptedClaim>,
}

/// What a settlement preimage needs fetched before `validate` can reach a
/// verdict: every trader leaf a core reads or writes, and for every vault the
/// core touches, its state leaf and every leaf the core reads or writes. The
/// policy objects are named by the vault state once it is in hand
/// ([`EvidenceNeeds::policies_of`]).
///
/// Derived from the preimage alone, so an acquisition fetches exactly what
/// Core will consume — no more (nothing is trusted because it exists) and no
/// less (an item not fetched is `Unavailable`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EvidenceNeeds {
    /// `R_econ` keys of the trader's own leaves.
    pub trader_keys: BTreeSet<D32>,
    /// Per vault: the keys of its leaves, the state key included.
    pub vaults: BTreeMap<D32, BTreeSet<D32>>,
    /// The `ρ` of every leg of P: each leg's setup envelope, for `SetupValid`.
    pub setups: BTreeSet<D32>,
}

impl EvidenceNeeds {
    pub fn of(precommit: &TraderPrecommitBody, preimage: &SettlementPreimage) -> Self {
        let setups = precommit.legs().iter().map(|leg| leg.setup_ref).collect();
        let trader_keys = preimage
            .trader_core()
            .entries()
            .iter()
            .map(CoreEntry::key)
            .collect();
        let mut vaults: BTreeMap<D32, BTreeSet<D32>> = BTreeMap::new();
        for core in preimage.dlv_cores() {
            let keys = vaults.entry(*core.vault_id()).or_default();
            keys.insert(derive::vault_state_key(core.vault_id()));
            keys.extend(core.entries().iter().map(CoreEntry::key));
        }
        if let SettlementBody::Close { vault_id, .. } = preimage.settlement() {
            vaults
                .entry(*vault_id)
                .or_default()
                .insert(derive::vault_state_key(vault_id));
        }
        Self {
            trader_keys,
            vaults,
            setups,
        }
    }

    /// The three policy objects a vault state commits, by class and address.
    /// The two token policies a vault's market names: what the transferable
    /// check of SoFi §49 is decided over, for both tokens of every hop.
    pub fn token_policies_of(market: &crate::ccb::state::MarketPolicy) -> [D32; 2] {
        [*market.token_a(), *market.token_b()]
    }

    pub fn policies_of(state: &VaultStateLeaf) -> [(u16, D32); 3] {
        [
            (crate::ccb::class::MARKET_POLICY, state.market_policy),
            (crate::ccb::class::FEE_POLICY, state.fee_policy),
            (crate::ccb::class::RELEASE_POLICY, state.release_policy),
        ]
    }
}

impl Evidence {
    /// The one production constructor: what an acquisition fetched. Every
    /// item is checked again when consumed — an object against its address,
    /// a leaf against the core that names it — so supplying a map proves
    /// nothing by itself.
    pub fn acquired(
        objects: BTreeMap<D32, Vec<u8>>,
        trader_leaves: BTreeMap<D32, TraderLeafPre>,
        vault_leaves: BTreeMap<(D32, D32), VaultLeafPre>,
        setups: BTreeMap<D32, Vec<u8>>,
        token_policies: BTreeMap<D32, Vec<u8>>,
        accepted_claims: BTreeMap<u64, AcceptedClaim>,
    ) -> Self {
        Self {
            objects,
            trader_leaves,
            vault_leaves,
            setups,
            token_policies,
            accepted_claims,
        }
    }

    /// The bytes a vault's address names, AUTHENTICATED against that address
    /// under the class's own namespace.
    ///
    /// Supplying bytes under a key proves nothing — the map is the verifier's
    /// own cache, not evidence. Bytes that do not re-derive the requested
    /// address are a non-verifying candidate: they leave the object
    /// unsupplied (Unavailable) and can never make an operation Invalid, which
    /// is note 9 exactly. Only authenticated bytes may establish anything.
    fn policy_bytes(&self, addr: &D32, object_class: u16) -> Result<&[u8], Refusal> {
        let bytes = self
            .objects
            .get(addr)
            .map(Vec::as_slice)
            .ok_or(Refusal::Incomplete(Missing::Policy { addr: *addr }))?;
        let derived = crate::ccb::decode::policy_object_address(object_class, bytes).ok_or(
            Refusal::Incomplete(Missing::NonVerifyingObject { addr: *addr }),
        )?;
        if derived != *addr {
            return Err(Refusal::Incomplete(Missing::NonVerifyingObject {
                addr: *addr,
            }));
        }
        Ok(bytes)
    }

    fn trader_leaf(&self, key: &D32) -> Result<&TraderLeafPre, Refusal> {
        self.trader_leaves
            .get(key)
            .ok_or(Refusal::Incomplete(Missing::TraderLeaf { key: *key }))
    }

    fn vault_leaf(&self, vault_id: &D32, key: &D32) -> Result<&VaultLeafPre, Refusal> {
        self.vault_leaves
            .get(&(*vault_id, *key))
            .ok_or(Refusal::Incomplete(Missing::VaultLeaf {
                vault_id: *vault_id,
                key: *key,
            }))
    }

    /// The vault's own state before the operation.
    ///
    /// A state the verifier has not fetched is Unavailable. A key it HAS
    /// fetched and found empty, or holding another leaf class, is Invalid:
    /// that is an observation about the vault, not a gap in what is held.
    fn vault_state(&self, vault_id: &D32) -> Result<VaultStateLeaf, Refusal> {
        let key = derive::vault_state_key(vault_id);
        match self.vault_leaf(vault_id, &key)? {
            VaultLeafPre::State(s) => Ok(s.clone()),
            VaultLeafPre::Absent | VaultLeafPre::Relationship(_) => {
                Err(Refusal::Invalid(Invalid::VaultLeafIsNotItsClass))
            }
        }
    }
}

/// A vault's three policy objects, each decoded from the bytes its content
/// address named. A policy is never taken on the operation's word.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policies {
    pub market: MarketPolicy,
    pub fee: FeePolicy,
    pub release: ReleasePolicy,
}

impl Policies {
    /// The three policies `state` commits, from the objects `evidence` holds,
    /// each re-addressed before it is decoded.
    pub fn resolve(evidence: &Evidence, state: &VaultStateLeaf) -> Result<Self, Refusal> {
        let market = crate::ccb::decode::decode_market_policy(
            evidence.policy_bytes(&state.market_policy, crate::ccb::class::MARKET_POLICY)?,
        )
        .map_err(|_| {
            Refusal::Invalid(Invalid::PolicyDoesNotDecode {
                class: crate::ccb::class::MARKET_POLICY,
            })
        })?;
        let fee = crate::ccb::decode::decode_fee_policy(
            evidence.policy_bytes(&state.fee_policy, crate::ccb::class::FEE_POLICY)?,
        )
        .map_err(|_| {
            Refusal::Invalid(Invalid::PolicyDoesNotDecode {
                class: crate::ccb::class::FEE_POLICY,
            })
        })?;
        let release = crate::ccb::decode::decode_release_policy(
            evidence.policy_bytes(&state.release_policy, crate::ccb::class::RELEASE_POLICY)?,
        )
        .map_err(|_| {
            Refusal::Invalid(Invalid::PolicyDoesNotDecode {
                class: crate::ccb::class::RELEASE_POLICY,
            })
        })?;
        Ok(Self {
            market,
            fee,
            release,
        })
    }
}

/// `SetupValid` for one leg of P (SoFi §16, §20.1): the setup the leg names by
/// `ρ` is the canonical envelope whose body re-derives `ρ`, names P's trader
/// and the leg's vault, is signed by P's trader key, and names by
/// `claim_ref` the claim the trader's lineage accepted at the setup's
/// position (Amendment S9).
///
/// Bytes that do not authenticate to `ρ` supply nothing (note 9), and an
/// accepted claim of another trader supplies nothing either.
fn setup_valid(
    precommit: &TraderPrecommitBody,
    leg: &crate::sofi::wire::PrecommitLeg,
    evidence: &Evidence,
) -> Result<(), Refusal> {
    let bytes = evidence
        .setups
        .get(&leg.setup_ref)
        .ok_or(Refusal::Incomplete(Missing::Setup {
            setup_ref: leg.setup_ref,
        }))?;
    let non_verifying = || {
        Refusal::Incomplete(Missing::NonVerifyingObject {
            addr: leg.setup_ref,
        })
    };
    let (rho, signed) =
        crate::sofi::publication::recognize_setup(bytes).ok_or_else(non_verifying)?;
    if rho != leg.setup_ref {
        return Err(non_verifying());
    }
    let body = &signed.body;
    if body.genesis() != precommit.genesis() || body.device_id() != precommit.device_id() {
        return Err(Refusal::Invalid(Invalid::SetupNotThisTrader));
    }
    if *body.vault_id() != leg.vault_id {
        return Err(Refusal::Invalid(Invalid::SetupNotThisVault));
    }
    crate::sofi::signature::verify_setup(body, &signed.signature, precommit.claimant_public_key())
        .map_err(|e| Refusal::Invalid(Invalid::SetupSignature(e)))?;
    let missing_claim = Refusal::Incomplete(Missing::AcceptedClaim {
        economic_position: body.position(),
    });
    let accepted = evidence
        .accepted_claims
        .get(&body.position())
        .ok_or(missing_claim.clone())?;
    if accepted.genesis() != *body.genesis()
        || accepted.device_id() != *body.device_id()
        || accepted.economic_position() != body.position()
    {
        return Err(missing_claim);
    }
    if accepted.claim_ref() != *body.claim_ref() {
        return Err(Refusal::Invalid(
            Invalid::SetupClaimRefIsNotTheAcceptedClaim,
        ));
    }
    Ok(())
}

/// Both tokens of a vault the operation touches pass their policies as market
/// legs (SoFi §19.5, §49; MR-SOFI-0311), an intermediate token of a route
/// included. ERA and dBTC are pre-rooted and never consult a policy. Any
/// other token's `TokenPolicyV3` bytes are re-hashed to its commit before
/// they establish anything.
fn market_legs_permitted(
    core: &crate::sofi::wire::DlvCore,
    evidence: &Evidence,
) -> Result<(), Refusal> {
    let state = evidence.vault_state(core.vault_id())?;
    let policies = Policies::resolve(evidence, &state)?;
    for commit in EvidenceNeeds::token_policies_of(&policies.market) {
        if crate::core::token::builtin_token_id_for_policy_commit(&commit).is_some() {
            continue;
        }
        let bytes = evidence
            .token_policies
            .get(&commit)
            .ok_or(Refusal::Incomplete(Missing::TokenPolicy { commit }))?;
        let derived = crate::crypto::blake3::domain_hash_bytes(
            crate::common::domain_tags::TAG_DSM_POLICY,
            bytes,
        );
        if derived != commit {
            return Err(Refusal::Incomplete(Missing::NonVerifyingObject {
                addr: commit,
            }));
        }
        let policy = crate::economic::token_policy::parse_token_policy(bytes)
            .map_err(|_| Refusal::Invalid(Invalid::TokenPolicyDoesNotParse { token: commit }))?;
        crate::economic::issuance::check_market_leg_permitted(&policy)
            .map_err(|_| Refusal::Invalid(Invalid::TokenNotTransferable { token: commit }))?;
    }
    Ok(())
}

/// `RouteValidation(P, G, E)`: Valid or Invalid over complete evidence, or
/// the object still missing (Amendment S3).
pub fn route_validation(
    precommit: &TraderPrecommitBody,
    preimage: &SettlementPreimage,
    evidence: &Evidence,
) -> Result<Validation, Missing> {
    match validate(precommit, preimage, evidence) {
        Ok(()) => Ok(Validation::Valid),
        Err(r) => r.validation(),
    }
}

/// `RouteValidation` over the operation alone — nothing fetched and nothing
/// of the verifier's (MR-DSM-0041, MR-DSM-0042): `Some(reason)` when the
/// route is Invalid whatever storage holds, so nothing is read to know it;
/// `None` when nothing in hand refutes it. It is [`validate`] over empty
/// evidence: Invalid dominates whatever is missing, so an item that needs a
/// fetch never hides a refusal and never makes one.
pub fn route_invalid_in_hand(
    precommit: &TraderPrecommitBody,
    preimage: &SettlementPreimage,
) -> Option<Invalid> {
    let nothing = Evidence::acquired(
        BTreeMap::new(),
        BTreeMap::new(),
        BTreeMap::new(),
        BTreeMap::new(),
        BTreeMap::new(),
        BTreeMap::new(),
    );
    match validate(precommit, preimage, &nothing) {
        Err(Refusal::Invalid(why)) => Some(why),
        Ok(()) | Err(Refusal::Incomplete(..)) => None,
    }
}

/// One vault's state after the operation: the root its tree holds, and the
/// leaf preimages that root commits for the keys this operation touched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultPostState {
    pub vault_id: D32,
    /// `R_g`: the root this operation was built on, as the core states it.
    /// Carried so a recorded head is its own chain link — a store that kept
    /// only the post root would hold a set of roots and not a chain, and a
    /// parent's status is asked about a GENERATION.
    pub pre_root: D32,
    /// `g`: the generation `pre_root` belongs to, from the pre state.
    pub pre_generation: u64,
    /// `R_{g+1}`: the post root the vault core's own entries fold to against
    /// the pre-root the core states. The same value `validate` computes and
    /// discards, returned here because the vault head store needs it.
    pub root: D32,
    /// The vault state leaf at `vault_state_key(v)`, with its generation
    /// advanced and its reserves priced by the vault's own policies.
    pub state: VaultStateLeaf,
    /// The relationship leaf this operation advanced, at its own key: the
    /// trader's leaf in THIS vault's tree, which is not the trader's own
    /// relationship leaf in its own tree.
    pub relationship: Option<(D32, VaultRelationshipLeaf)>,
}

/// Every vault's state after the operation, recomputed from the pre states the
/// evidence holds and the settlement's own terms — never read back from
/// anything the producer stated.
///
/// This is the vault side of [`trader_post_states`], and it exists for the
/// same reason: a verifier that resolves a position has to be able to keep
/// the state that position selected, or the next trade against that vault has
/// no evidence to stand on. It decides no canonicality. `advance_resolved`
/// already selected the state; this only says what the state IS.
///
/// The root is the fold's, so it is authenticated by the same arithmetic the
/// verdict used: the core's entries against the pre-root the core states. A
/// caller that stored a root from anywhere else would be storing an opinion.
pub fn vault_post_states(
    precommit: &TraderPrecommitBody,
    preimage: &SettlementPreimage,
    evidence: &Evidence,
) -> Result<Vec<VaultPostState>, Refusal> {
    let e = *precommit.external_commitment();
    let mut out = Vec::with_capacity(preimage.dlv_cores().len());
    for core in preimage.dlv_cores() {
        let vault_id = *core.vault_id();
        let pre_state = evidence.vault_state(&vault_id)?;
        let post_state = match preimage.settlement() {
            SettlementBody::Swap { hops, .. } => {
                let (index, hop) = hops
                    .iter()
                    .enumerate()
                    .find(|(_, h)| h.vault_id == vault_id)
                    .ok_or(Refusal::Invalid(Invalid::LegsDoNotMatchPrecommit))?;
                let policies = Policies::resolve(evidence, &pre_state)?;
                swap_vault_post(&pre_state, &policies, hop, index)?
            }
            SettlementBody::Close { .. } => {
                let generation = pre_state.generation.checked_add(1).ok_or(Refusal::Invalid(
                    Invalid::CheckedArithmetic {
                        what: "vault generation",
                    },
                ))?;
                VaultStateLeaf {
                    generation,
                    reserve_a: 0,
                    reserve_b: 0,
                    status: VAULT_STATUS_RETIRED,
                    ..pre_state.clone()
                }
            }
        };
        // The state the core STATES must be the state the arithmetic reaches.
        // Without this the store would keep a state nothing verified.
        let state_key = derive::vault_state_key(&vault_id);
        let stated_post = core
            .entries()
            .iter()
            .find(|entry| entry.key() == state_key)
            .map(|entry| stated(entry).1)
            .ok_or(Refusal::Invalid(Invalid::WriteSetNotExact { core: "V°" }))?;
        let computed = derive::vault_state_leaf_value(&post_state)
            .map_err(|_| Refusal::Invalid(Invalid::LeafPostValueMismatch))?;
        require(
            stated_post == Some(computed),
            Invalid::LeafPostValueMismatch,
        )?;

        // The relationship leaf this operation advanced, if it advanced one.
        let relationship = core.entries().iter().find_map(|entry| match entry {
            CoreEntry::Relationship { base, .. } => Some((
                entry.key(),
                VaultRelationshipLeaf {
                    trader_genesis: *core.trader_genesis(),
                    trader_device_id: *core.trader_device_id(),
                    leaf: derive::relationship_leaf_next(base, &e),
                },
            )),
            _ => None,
        });

        let entries = dlv_fold_entries(core, &e, evidence)?;
        let root = fold_core(&entries, core.pre_root())?;
        out.push(VaultPostState {
            vault_id,
            pre_root: *core.pre_root(),
            pre_generation: pre_state.generation,
            root,
            state: post_state,
            relationship,
        });
    }
    Ok(out)
}
/// What a settlement MOVES in the trader's own balances: `(token, credit,
/// debit)` per endpoint.
///
/// ONE derivation, shared by [`trader_post_states`] and by the adoption gate
/// in `sofi::lineage::advance_resolved`. They must not compute this
/// separately: a gate that disagreed with the transition about which tokens
/// are being received would be checking a different operation from the one
/// about to be installed.
///
/// ENDPOINTS ONLY, and that is what settles the multi-hop case. A route
/// `A -> B -> C` moves the trader's `A` and `C`; the intermediate `B` exists
/// only BETWEEN hops (`RouteValidation` requires `hops[i].token_out ==
/// hops[i+1].token_in`, and the route's ends to be the intent's), and it is
/// held by the DLVs across the hop rather than by the trader. So `B` never
/// becomes a trader balance leaf, and no rule about the trader's tokens
/// reaches it. A close is different: BOTH of the vault's reserve assets are
/// credited back to the owner.
pub fn trader_movements(
    preimage: &SettlementPreimage,
    evidence: &Evidence,
) -> Result<Vec<(D32, u64, u64)>, Refusal> {
    Ok(match preimage.settlement() {
        SettlementBody::Swap {
            token_in,
            amount_in,
            token_out,
            exact_out,
            ..
        } => vec![(*token_out, *exact_out, 0), (*token_in, 0, *amount_in)],
        SettlementBody::Close {
            vault_id,
            reserve_a,
            reserve_b,
            ..
        } => {
            let state = evidence.vault_state(vault_id)?;
            let policies = Policies::resolve(evidence, &state)?;
            vec![
                (*policies.market.token_a(), *reserve_a, 0),
                (*policies.market.token_b(), *reserve_b, 0),
            ]
        }
    })
}

/// The tokens a settlement CREDITS to the trader — what actually arrives.
///
/// A debited token is not here: you cannot be handed a token by spending it,
/// and a balance you already hold was adopted before it arrived. Neither is a
/// zero credit, which writes no leaf.
pub fn trader_credits(
    preimage: &SettlementPreimage,
    evidence: &Evidence,
) -> Result<Vec<D32>, Refusal> {
    Ok(trader_movements(preimage, evidence)?
        .into_iter()
        .filter(|(_, credit, _)| *credit > 0)
        .map(|(token, _, _)| token)
        .collect())
}

/// One trader balance a settlement moves: the amount under the pre-root and
/// the amount under the realize root, for one token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TraderBalanceChange {
    pub policy_commit: D32,
    /// What the balance leaf held before the operation; zero for an absent
    /// leaf.
    pub before: u64,
    /// What it holds after; zero is a leaf absent after the operation.
    pub after: u64,
}

/// One entry of `T°` after the operation: its key, its post state, and — for
/// a balance leaf — the change the settlement made to it.
type TraderPost = (D32, Option<EconomicLeafState>, Option<TraderBalanceChange>);

/// The one derivation behind [`trader_post_states`] and
/// [`trader_balance_changes`]: each post state recomputed from the pre state
/// the evidence holds and the movement the settlement commits, then bound to
/// the value the core states.
fn trader_posts(
    precommit: &TraderPrecommitBody,
    preimage: &SettlementPreimage,
    evidence: &Evidence,
) -> Result<Vec<TraderPost>, Refusal> {
    let e = *precommit.external_commitment();
    let movements = trader_movements(preimage, evidence)?;
    let core = preimage.trader_core();
    let mut out = Vec::with_capacity(core.entries().len());
    for entry in core.entries() {
        let key = entry.key();
        let (post, change) = match entry {
            // A relationship advance states no post value of its own: the
            // next leaf is derived from the base and E, and the fold against
            // `P.R_realize` is what binds it (`trader_fold_entries`).
            CoreEntry::Relationship { vault_id, base, .. } => {
                out.push((
                    key,
                    Some(EconomicLeafState::Relationship(TraderRelationshipLeaf {
                        vault_id: *vault_id,
                        leaf: derive::relationship_leaf_next(base, &e),
                    })),
                    None,
                ));
                continue;
            }
            CoreEntry::Mutation { .. } | CoreEntry::Read { .. } => {
                let (token, credit, debit) = movements
                    .iter()
                    .find(|(t, ..)| {
                        balance_key(precommit.genesis(), precommit.device_id(), t) == key
                    })
                    .ok_or(Refusal::Invalid(Invalid::WriteSetNotExact { core: "T°" }))?;
                let before = match evidence.trader_leaf(&key)? {
                    TraderLeafPre::Balance(b) if b.policy_commit == *token => b.amount,
                    TraderLeafPre::Absent => 0,
                    TraderLeafPre::Balance(_) | TraderLeafPre::Relationship(_) => {
                        return Err(Refusal::Invalid(Invalid::LeafPreValueMismatch))
                    }
                };
                let after = before
                    .checked_add(*credit)
                    .and_then(|v| v.checked_sub(*debit))
                    .ok_or(Refusal::Invalid(Invalid::CheckedArithmetic {
                        what: "trader balance",
                    }))?;
                (
                    (after != 0).then_some(EconomicLeafState::Balance(EconomicBalanceState {
                        policy_commit: *token,
                        amount: after,
                    })),
                    TraderBalanceChange {
                        policy_commit: *token,
                        before,
                        after,
                    },
                )
            }
        };
        let value = post
            .as_ref()
            .map(|state| {
                state
                    .leaf_value()
                    .map_err(|_| Refusal::Invalid(Invalid::LeafPostValueMismatch))
            })
            .transpose()?;
        require(value == stated(entry).1, Invalid::LeafPostValueMismatch)?;
        out.push((key, post, Some(change)));
    }
    Ok(out)
}

/// The trader's leaves after the operation, for the keys `T°` touches — the
/// post STATE behind each post value the core states, so a verifier that
/// installs `P.R_realize` (stage 10 of §31, R13) also holds the leaves that
/// form it. Each state is recomputed from the pre state the evidence holds
/// and the movement the settlement commits, then bound to the value the core
/// states: a mismatch is the refusal `validate` gives for it. `None` is a leaf
/// absent after the operation (a zero balance). Keys the core does not touch
/// are unchanged and not listed.
pub fn trader_post_states(
    precommit: &TraderPrecommitBody,
    preimage: &SettlementPreimage,
    evidence: &Evidence,
) -> Result<Vec<(D32, Option<EconomicLeafState>)>, Refusal> {
    Ok(trader_posts(precommit, preimage, evidence)?
        .into_iter()
        .map(|(key, post, ..)| (key, post))
        .collect())
}

/// The trader balances the operation moves, each bound exactly as
/// [`trader_post_states`] binds its leaf: the balance before, from the pre
/// state the evidence holds, and after, recomputed from the settlement's
/// movement and equal to the value `T°` states under `P.R_realize`.
pub fn trader_balance_changes(
    precommit: &TraderPrecommitBody,
    preimage: &SettlementPreimage,
    evidence: &Evidence,
) -> Result<Vec<TraderBalanceChange>, Refusal> {
    Ok(trader_posts(precommit, preimage, evidence)?
        .into_iter()
        .filter_map(|(.., change)| change)
        .collect())
}

/// The same check, with the reason. Every refusal names what failed, so a test
/// asserts the rule rather than the verdict.
///
/// Checks compose under the three-valued conjunction rather than stopping at
/// the first refusal: an invalidity the verifier can already prove is never
/// masked by evidence it happens not to hold.
pub fn validate(
    precommit: &TraderPrecommitBody,
    preimage: &SettlementPreimage,
    evidence: &Evidence,
) -> Result<(), Refusal> {
    let mut verdict = Verdict::default();

    let bytes = preimage
        .encode()
        .map_err(|_| Refusal::Invalid(Invalid::LegsDoNotMatchPrecommit))?;
    verdict.note(require(
        bytes.len() <= MAX_SETTLEMENT_PREIMAGE_BYTES,
        Invalid::PreimageTooLarge {
            bytes: bytes.len(),
            max: MAX_SETTLEMENT_PREIMAGE_BYTES,
        },
    ));
    // E binds the whole preimage, so this is what stops P naming one operation
    // and the preimage describing another.
    verdict.note(
        derive::recompute_e(preimage)
            .map_err(|_| Refusal::Invalid(Invalid::ExternalCommitmentMismatch))
            .and_then(|recomputed| {
                require(
                    recomputed == *precommit.external_commitment(),
                    Invalid::ExternalCommitmentMismatch,
                )
            }),
    );

    let trader_core = preimage.trader_core();
    verdict.note(require(
        trader_core.genesis() == precommit.genesis()
            && trader_core.device_id() == precommit.device_id()
            && Some(trader_core.position()) == next_position(precommit.position()).ok(),
        Invalid::CoreIdentityMismatch,
    ));
    // P15-2: the void root is where the lineage returns to, so it IS the core's
    // pre-root; there is no second place for them to disagree.
    verdict.note(require(
        *trader_core.pre_root() == *precommit.void_root(),
        Invalid::VoidRootIsNotThePreRoot,
    ));
    // B° names its cores by digest. Those references are what bind the body to
    // the objects P(E) carries, so they are checked rather than assumed.
    verdict.note(check_settlement_core_references(precommit, preimage));

    // SetupValid for every required leg (SoFi §16, §20.1; MR-SOFI-0135,
    // 0205): canonical body encoding, ρ, the signature over m_setup, ClaimRef,
    // and the identity and vault relationship rules. FulfillmentConformance
    // carries only the durability half, SetupRegistered; without this,
    // setup validity would drop out of the conjunction realization depends on.
    for leg in precommit.legs() {
        verdict.note(setup_valid(precommit, leg, evidence));
    }

    // Every token passes its policy on every SoFi leg, an intermediate token
    // included (SoFi §19.5, §49; MR-SOFI-0311): both tokens of every vault
    // the operation touches must be transferable.
    for core in preimage.dlv_cores() {
        verdict.note(market_legs_permitted(core, evidence));
    }

    match preimage.settlement() {
        SettlementBody::Swap {
            token_in,
            amount_in,
            token_out,
            exact_out,
            hops,
            ..
        } => validate_swap(
            &mut verdict,
            precommit,
            preimage,
            evidence,
            SwapIntent {
                token_in: *token_in,
                amount_in: *amount_in,
                token_out: *token_out,
                exact_out: *exact_out,
            },
            hops,
        ),
        SettlementBody::Close {
            vault_id,
            owner_authority,
            reserve_a,
            reserve_b,
            ..
        } => validate_close(
            &mut verdict,
            precommit,
            preimage,
            evidence,
            vault_id,
            owner_authority,
            *reserve_a,
            *reserve_b,
        ),
    }
    verdict.finish()
}

/// `B°`'s core references must be the cores `P(E)` actually carries, and a
/// close's parent must be the leg `P` actually names.
///
/// Without this the references are decoration: the body could name one core
/// while the preimage carried another, and every later check would read the
/// carried one.
fn check_settlement_core_references(
    precommit: &TraderPrecommitBody,
    preimage: &SettlementPreimage,
) -> Result<(), Refusal> {
    let actual_trader = derive::trader_core_digest(
        &preimage
            .trader_core()
            .encode()
            .map_err(|_| Refusal::Invalid(Invalid::CoreIdentityMismatch))?,
    );
    let digest_of = |core: &DlvCore| -> Result<D32, Refusal> {
        Ok(derive::dlv_core_digest(&core.encode().map_err(|_| {
            Refusal::Invalid(Invalid::CoreIdentityMismatch)
        })?))
    };
    match preimage.settlement() {
        SettlementBody::Swap {
            hops,
            trader_core,
            dlv_cores,
            ..
        } => {
            require(
                *trader_core == actual_trader,
                Invalid::SettlementCoreReferenceMismatch {
                    field: "B°.trader_core",
                },
            )?;
            // One reference per carried core, positionally — P(E) fixes the
            // order by vault id, so there is nothing else it could mean.
            require(
                dlv_cores.len() == preimage.dlv_cores().len() && dlv_cores.len() == hops.len(),
                Invalid::SettlementCoreReferenceMismatch {
                    field: "B°.dlv_cores",
                },
            )?;
            for (reference, core) in dlv_cores.iter().zip(preimage.dlv_cores()) {
                require(
                    *reference == digest_of(core)?,
                    Invalid::SettlementCoreReferenceMismatch {
                        field: "B°.dlv_cores",
                    },
                )?;
            }
            Ok(())
        }
        SettlementBody::Close {
            vault_id,
            parent_root,
            setup_ref,
            trader_core,
            dlv_core,
            ..
        } => {
            require(
                *trader_core == actual_trader,
                Invalid::SettlementCoreReferenceMismatch {
                    field: "B°.trader_core",
                },
            )?;
            let core = preimage.dlv_cores().first().ok_or(Refusal::Invalid(
                Invalid::SettlementCoreReferenceMismatch {
                    field: "B°.dlv_core",
                },
            ))?;
            require(
                preimage.dlv_cores().len() == 1 && *dlv_core == digest_of(core)?,
                Invalid::SettlementCoreReferenceMismatch {
                    field: "B°.dlv_core",
                },
            )?;
            // A close's own parent must be the leg P names, and the core's.
            let leg = precommit
                .legs()
                .iter()
                .find(|l| l.vault_id == *vault_id)
                .ok_or(Refusal::Invalid(Invalid::LegsDoNotMatchPrecommit))?;
            require(
                *parent_root == leg.parent_root && *setup_ref == leg.setup_ref,
                Invalid::SettlementCoreReferenceMismatch {
                    field: "B°.parent_root/setup_ref",
                },
            )?;
            require(
                *core.pre_root() == *parent_root,
                Invalid::SettlementCoreReferenceMismatch {
                    field: "B°.parent_root",
                },
            )
        }
    }
}

struct SwapIntent {
    token_in: D32,
    amount_in: u64,
    token_out: D32,
    exact_out: u64,
}

/// The expected post-value of a trader balance leaf after a delta, and the
/// entry that must carry it.
fn balance_after(
    pre: &TraderLeafPre,
    policy_commit: &D32,
    credit: u64,
    debit: u64,
) -> Result<(Option<D32>, Option<D32>), Refusal> {
    let before = match pre {
        TraderLeafPre::Balance(b) => {
            if b.policy_commit != *policy_commit {
                return Err(Refusal::Invalid(Invalid::LeafPreValueMismatch));
            }
            b.amount
        }
        TraderLeafPre::Absent => 0,
        TraderLeafPre::Relationship(_) => {
            return Err(Refusal::Invalid(Invalid::LeafPreValueMismatch))
        }
    };
    let after = before
        .checked_add(credit)
        .and_then(|v| v.checked_sub(debit))
        .ok_or(Refusal::Invalid(Invalid::CheckedArithmetic {
            what: "trader balance",
        }))?;
    let pre_value = match pre {
        TraderLeafPre::Absent => None,
        TraderLeafPre::Balance(b) => Some(leaf_value_of_balance(b)?),
        TraderLeafPre::Relationship(_) => unreachable!("refused above"),
    };
    let post_value = if after == 0 {
        // A zero balance is the leaf's absence, never a leaf holding zero.
        None
    } else {
        Some(leaf_value_of_balance(&EconomicBalanceState {
            policy_commit: *policy_commit,
            amount: after,
        })?)
    };
    Ok((pre_value, post_value))
}

fn leaf_value_of_balance(state: &EconomicBalanceState) -> Result<D32, Refusal> {
    EconomicLeafState::Balance(state.clone())
        .leaf_value()
        .map_err(|_| {
            Refusal::Invalid(Invalid::CheckedArithmetic {
                what: "balance leaf encoding",
            })
        })
}

/// A core entry's stated pre and post, as the fold will read them.
fn stated(entry: &CoreEntry) -> (Option<D32>, Option<D32>) {
    match entry {
        CoreEntry::Mutation { pre, post, .. } => (absent_or(pre), absent_or(post)),
        CoreEntry::Read { value, .. } => (absent_or(value), absent_or(value)),
        CoreEntry::Relationship { .. } => (None, None),
    }
}

/// The wire carries a leaf's absence as the absent-leaf value, so the two
/// meanings never need a second encoding.
fn absent_or(value: &D32) -> Option<D32> {
    if *value == crate::economic::tree::ABSENT_LEAF {
        None
    } else {
        Some(*value)
    }
}

fn require(condition: bool, reason: Invalid) -> Result<(), Refusal> {
    if condition {
        Ok(())
    } else {
        Err(Refusal::Invalid(reason))
    }
}

/// The relationship entries of a core, by vault, with the base each states.
fn relationship_bases(entries: &[CoreEntry]) -> BTreeMap<D32, (D32, D32, D32)> {
    let mut out = BTreeMap::new();
    for e in entries {
        if let CoreEntry::Relationship {
            genesis,
            device_id,
            vault_id,
            base,
            ..
        } = e
        {
            out.insert(*vault_id, (*genesis, *device_id, *base));
        }
    }
    out
}

/// Turn a trader core's entries into fold entries, resolving each relationship
/// post through BindExt. This is the only place `E` enters a leaf value.
fn trader_fold_entries(
    core: &TraderCore,
    external_commitment: &D32,
    evidence: &Evidence,
) -> Result<Vec<FoldEntry>, Refusal> {
    let mut out = Vec::with_capacity(core.entries().len());
    for entry in core.entries() {
        let key = entry.key();
        let (pre, post) = match entry {
            CoreEntry::Mutation { .. } | CoreEntry::Read { .. } => stated(entry),
            CoreEntry::Relationship { vault_id, base, .. } => {
                let held = evidence.trader_leaf(&key)?;
                let pre = match held {
                    TraderLeafPre::Absent => None,
                    TraderLeafPre::Relationship(r) => {
                        // The base a core states must be the leaf it holds.
                        require(
                            r.leaf == *base && r.vault_id == *vault_id,
                            Invalid::RelationshipBaseMismatch,
                        )?;
                        Some(derive::trader_relationship_leaf_value(r))
                    }
                    TraderLeafPre::Balance(_) => {
                        return Err(Refusal::Invalid(Invalid::LeafPreValueMismatch))
                    }
                };
                let next = derive::relationship_leaf_next(base, external_commitment);
                let post = derive::trader_relationship_leaf_value(&TraderRelationshipLeaf {
                    vault_id: *vault_id,
                    leaf: next,
                });
                (pre, Some(post))
            }
        };
        out.push(FoldEntry {
            key,
            pre,
            post,
            path: Box::new(*entry_path(entry)?),
        });
    }
    Ok(out)
}

/// A verifier never panics on bytes it was handed. The wire constructor
/// already fixes the path depth, but this is the validation path: a malformed
/// entry that reached it is refused, not asserted away.
fn entry_path(
    entry: &CoreEntry,
) -> Result<&[D32; crate::economic::tree::ECONOMIC_SMT_HEIGHT], Refusal> {
    entry.path().try_into().map_err(|_| {
        Refusal::Invalid(Invalid::CoreDoesNotFold {
            reason: "an entry's authentication path is not one sibling per level",
        })
    })
}

/// The same for a vault core, where a relationship leaf is the vault's own
/// class and the state leaf is checked by the caller.
fn dlv_fold_entries(
    core: &DlvCore,
    external_commitment: &D32,
    evidence: &Evidence,
) -> Result<Vec<FoldEntry>, Refusal> {
    let mut out = Vec::with_capacity(core.entries().len());
    for entry in core.entries() {
        let key = entry.key();
        let (pre, post) = match entry {
            CoreEntry::Mutation { .. } | CoreEntry::Read { .. } => stated(entry),
            CoreEntry::Relationship {
                genesis,
                device_id,
                base,
                ..
            } => {
                // The entry derives its OWN key from its own identity fields,
                // so an entry naming another trader would address that
                // trader's relationship key while the core wrote this
                // trader's value into it. All three identities must agree.
                require(
                    genesis == core.trader_genesis() && device_id == core.trader_device_id(),
                    Invalid::RelationshipIdentityMismatch,
                )?;
                let held = evidence.vault_leaf(core.vault_id(), &key)?;
                let pre = match held {
                    VaultLeafPre::Absent => None,
                    VaultLeafPre::Relationship(r) => {
                        require(r.leaf == *base, Invalid::RelationshipBaseMismatch)?;
                        // And the leaf being advanced is this trader's leaf.
                        require(
                            r.trader_genesis == *core.trader_genesis()
                                && r.trader_device_id == *core.trader_device_id(),
                            Invalid::RelationshipIdentityMismatch,
                        )?;
                        Some(derive::vault_relationship_leaf_value(r))
                    }
                    VaultLeafPre::State(_) => {
                        return Err(Refusal::Invalid(Invalid::LeafPreValueMismatch))
                    }
                };
                let next = derive::relationship_leaf_next(base, external_commitment);
                let post = derive::vault_relationship_leaf_value(&VaultRelationshipLeaf {
                    trader_genesis: *core.trader_genesis(),
                    trader_device_id: *core.trader_device_id(),
                    leaf: next,
                });
                (pre, Some(post))
            }
        };
        out.push(FoldEntry {
            key,
            pre,
            post,
            path: Box::new(*entry_path(entry)?),
        });
    }
    Ok(out)
}

/// The core's entries, folded against the pre-root the core itself states.
///
/// Both refusals are `CoreDoesNotFold` and name which one happened. Reporting
/// a fold failure as `WriteSetNotExact` would name a rule the verifier never
/// checked here: a write set can be exactly the branch's own and still carry
/// paths from another tree.
fn fold_core(entries: &[FoldEntry], pre_root: &D32) -> Result<D32, Refusal> {
    verify_batch(pre_root, entries).map_err(|e| {
        Refusal::Invalid(Invalid::CoreDoesNotFold {
            reason: match e {
                FoldError::PreRootMismatch { .. } => {
                    "the entries do not fold to the core's own pre-root"
                }
                _ => "the entries' paths are not of one tree",
            },
        })
    })
}

/// `Fold(T°, E)`: the root a trader core's entries fold to under `E`, each
/// relationship advanced by `relationship_leaf_next` against the leaf the
/// trader holds — what `P.R_realize` must be. The producer computes it with
/// this function and the verifier checks it with the same one.
pub fn realize_root(
    core: &TraderCore,
    external_commitment: &D32,
    evidence: &Evidence,
) -> Result<D32, Refusal> {
    let entries = trader_fold_entries(core, external_commitment, evidence)?;
    fold_core(&entries, core.pre_root())
}

/// A vault's state after its owner's full close: the next generation, both
/// reserves released, retired.
pub fn close_vault_post(pre_state: &VaultStateLeaf) -> Result<VaultStateLeaf, Refusal> {
    let generation = pre_state.generation.checked_add(1).ok_or(Refusal::Invalid(
        Invalid::CheckedArithmetic {
            what: "vault generation",
        },
    ))?;
    Ok(VaultStateLeaf {
        generation,
        reserve_a: 0,
        reserve_b: 0,
        status: VAULT_STATUS_RETIRED,
        ..pre_state.clone()
    })
}

/// One vault's state before and after a swap hop, priced by its own policies:
/// the one computation the producer builds `V°` with and the verifier checks
/// it by.
pub fn swap_vault_post(
    state: &VaultStateLeaf,
    policies: &Policies,
    hop: &SwapHop,
    index: usize,
) -> Result<VaultStateLeaf, Refusal> {
    require(
        state.status == VAULT_STATUS_ACTIVE,
        Invalid::VaultIsNotActive,
    )?;
    let (token_a, token_b) = (*policies.market.token_a(), *policies.market.token_b());
    // Token policy: both sides of a hop are the vault's own pair, and a hop
    // cannot trade a token against itself.
    require(
        hop.token_in != hop.token_out
            && (hop.token_in == token_a || hop.token_in == token_b)
            && (hop.token_out == token_a || hop.token_out == token_b),
        Invalid::TokenIsNotInTheVaultPair { hop: index },
    )?;
    let in_is_a = hop.token_in == token_a;
    let (reserve_in, reserve_out) = if in_is_a {
        (state.reserve_a, state.reserve_b)
    } else {
        (state.reserve_b, state.reserve_a)
    };
    // THE one arithmetic (dlv::route_commit): the quote, the fold and this
    // verifier all reach the same function, so there is nothing to drift.
    let priced = constant_product_output_classified(
        hop.amount_in,
        reserve_in,
        reserve_out,
        policies.fee.fee_bps(),
    )
    .map_err(|_| Refusal::Invalid(Invalid::PriceIsNotTheConstantProduct { hop: index }))?;
    require(
        priced == hop.amount_out,
        Invalid::PriceIsNotTheConstantProduct { hop: index },
    )?;
    // The whole input stays in the pool, fee included; the output leaves it.
    let new_in = reserve_in
        .checked_add(hop.amount_in)
        .ok_or(Refusal::Invalid(Invalid::CheckedArithmetic {
            what: "reserve in",
        }))?;
    let new_out = reserve_out
        .checked_sub(hop.amount_out)
        .ok_or(Refusal::Invalid(Invalid::CheckedArithmetic {
            what: "reserve out",
        }))?;
    // A hop may not drain a pool: a zero reserve is not a tradeable vault.
    require(
        new_out > 0,
        Invalid::CheckedArithmetic {
            what: "reserve out",
        },
    )?;
    let generation =
        state
            .generation
            .checked_add(1)
            .ok_or(Refusal::Invalid(Invalid::CheckedArithmetic {
                what: "vault generation",
            }))?;
    let (reserve_a, reserve_b) = if in_is_a {
        (new_in, new_out)
    } else {
        (new_out, new_in)
    };
    Ok(VaultStateLeaf {
        generation,
        reserve_a,
        reserve_b,
        ..state.clone()
    })
}

/// The exact write set of one vault core, for either branch: its own state
/// leaf, and exactly one relationship advancement. Nothing else is permitted.
fn check_vault_write_set(
    core: &DlvCore,
    expected_state: &VaultStateLeaf,
    pre_state: &VaultStateLeaf,
) -> Result<(), Refusal> {
    let entries = core.entries();
    require(entries.len() == 2, Invalid::WriteSetNotExact { core: "V°" })?;
    let state_key = derive::vault_state_key(core.vault_id());
    let mut saw_state = false;
    let mut saw_relationship = false;
    for entry in entries {
        match entry {
            CoreEntry::Mutation { key, pre, post, .. } if *key == state_key => {
                let want_pre = derive::vault_state_leaf_value(pre_state)
                    .map_err(|_| Refusal::Invalid(Invalid::LeafPreValueMismatch))?;
                let want_post = derive::vault_state_leaf_value(expected_state)
                    .map_err(|_| Refusal::Invalid(Invalid::LeafPostValueMismatch))?;
                require(*pre == want_pre, Invalid::LeafPreValueMismatch)?;
                require(*post == want_post, Invalid::LeafPostValueMismatch)?;
                saw_state = true;
            }
            CoreEntry::Relationship {
                genesis,
                device_id,
                vault_id,
                ..
            } if vault_id == core.vault_id() => {
                require(
                    genesis == core.trader_genesis() && device_id == core.trader_device_id(),
                    Invalid::RelationshipIdentityMismatch,
                )?;
                saw_relationship = true;
            }
            _ => return Err(Refusal::Invalid(Invalid::WriteSetNotExact { core: "V°" })),
        }
    }
    require(
        saw_state && saw_relationship,
        Invalid::WriteSetNotExact { core: "V°" },
    )
}

#[allow(clippy::too_many_arguments)]
fn validate_swap(
    verdict: &mut Verdict,
    precommit: &TraderPrecommitBody,
    preimage: &SettlementPreimage,
    evidence: &Evidence,
    intent: SwapIntent,
    hops: &[SwapHop],
) {
    let e = *precommit.external_commitment();
    // The route's ends are the intent's, and each hop feeds the next exactly.
    // None of this needs evidence, so it is decided whatever the verifier holds.
    verdict.note(require(
        intent.token_in != intent.token_out,
        Invalid::RouteDoesNotChain { hop: 0 },
    ));
    let (Some(first), Some(last)) = (hops.first(), hops.last()) else {
        verdict.note(Err(Refusal::Invalid(Invalid::RouteDoesNotChain { hop: 0 })));
        return;
    };
    verdict.note(require(
        first.token_in == intent.token_in && first.amount_in == intent.amount_in,
        Invalid::RouteDoesNotChain { hop: 0 },
    ));
    verdict.note(require(
        last.token_out == intent.token_out && last.amount_out == intent.exact_out,
        Invalid::RouteDoesNotChain {
            hop: hops.len() - 1,
        },
    ));
    for (i, pair) in hops.windows(2).enumerate() {
        verdict.note(require(
            pair[0].token_out == pair[1].token_in && pair[0].amount_out == pair[1].amount_in,
            Invalid::RouteDoesNotChain { hop: i + 1 },
        ));
    }

    // P's legs are exactly the operation's DLV parents, with the same roots.
    verdict.note(require(
        precommit.legs().len() == hops.len(),
        Invalid::LegsDoNotMatchPrecommit,
    ));
    for hop in hops {
        verdict.note(
            precommit
                .legs()
                .iter()
                .find(|l| l.vault_id == hop.vault_id)
                .ok_or(Refusal::Invalid(Invalid::LegsDoNotMatchPrecommit))
                .and_then(|leg| {
                    require(
                        leg.parent_root == hop.parent_root && leg.setup_ref == hop.setup_ref,
                        Invalid::LegsDoNotMatchPrecommit,
                    )
                }),
        );
    }

    // Each vault: its own core, its own policies, its own price. A hop whose
    // evidence is missing contributes Unavailable and the REST still runs, so
    // an invalidity on any other hop is still proven.
    for (i, hop) in hops.iter().enumerate() {
        let Some(core) = verdict.get(
            preimage
                .dlv_cores()
                .iter()
                .find(|c| *c.vault_id() == hop.vault_id)
                .ok_or(Refusal::Invalid(Invalid::LegsDoNotMatchPrecommit)),
        ) else {
            continue;
        };
        verdict.note(require(
            core.trader_genesis() == precommit.genesis()
                && core.trader_device_id() == precommit.device_id(),
            Invalid::CoreIdentityMismatch,
        ));
        // The core's pre-root IS the DLV parent P named.
        verdict.note(require(
            *core.pre_root() == hop.parent_root,
            Invalid::LegsDoNotMatchPrecommit,
        ));
        // The state and the policies are separate fetches: a vault whose state
        // says Retired is invalid whether or not its policies were supplied.
        let state = verdict.get(evidence.vault_state(&hop.vault_id));
        if let Some(state) = state.as_ref() {
            verdict.note(require(
                state.status == VAULT_STATUS_ACTIVE,
                Invalid::VaultIsNotActive,
            ));
            verdict.note(require(
                state.storage_set_id == *precommit.storage_set_id(),
                Invalid::NetworkScopeMismatch,
            ));
        }
        let policies = state
            .as_ref()
            .and_then(|state| verdict.get(Policies::resolve(evidence, state)));
        if let (Some(state), Some(policies)) = (state.as_ref(), policies.as_ref()) {
            match swap_vault_post(state, policies, hop, i) {
                Ok(post_state) => verdict.note(check_vault_write_set(core, &post_state, state)),
                Err(refusal) => verdict.note(Err(refusal)),
            }
        }
        match dlv_fold_entries(core, &e, evidence) {
            Ok(entries) => verdict.note(fold_core(&entries, core.pre_root()).and(Ok(()))),
            Err(refusal) => verdict.note(Err(refusal)),
        }
    }

    // The trader side: one debit, one credit, one relationship per leg.
    let trader_core = preimage.trader_core();
    let bases = relationship_bases(trader_core.entries());
    verdict.note(require(
        bases.len() == hops.len(),
        Invalid::WriteSetNotExact { core: "T°" },
    ));
    for hop in hops {
        let Some((genesis, device_id, base)) = bases.get(&hop.vault_id) else {
            verdict.note(Err(Refusal::Invalid(Invalid::WriteSetNotExact {
                core: "T°",
            })));
            continue;
        };
        verdict.note(require(
            genesis == precommit.genesis() && device_id == precommit.device_id(),
            Invalid::CoreIdentityMismatch,
        ));
        // The two cores must agree on the relationship they are advancing.
        verdict.note(
            preimage
                .dlv_cores()
                .iter()
                .find(|c| *c.vault_id() == hop.vault_id)
                .ok_or(Refusal::Invalid(Invalid::LegsDoNotMatchPrecommit))
                .and_then(|core| {
                    require(
                        *core.relationship_base() == *base,
                        Invalid::RelationshipBaseMismatch,
                    )
                }),
        );
    }
    verdict.note(check_trader_balances(
        precommit,
        trader_core,
        evidence,
        &[
            (intent.token_out, intent.exact_out, 0),
            (intent.token_in, 0, intent.amount_in),
        ],
        hops.len(),
    ));

    verdict.note(
        realize_root(trader_core, &e, evidence).and_then(|post_root| {
            require(
                post_root == *precommit.realize_root(),
                Invalid::RealizeRootIsNotTheFold,
            )
        }),
    );
}

/// The trader core holds exactly the named balance movements and one
/// relationship advancement per leg — no extra entry, none missing.
fn check_trader_balances(
    precommit: &TraderPrecommitBody,
    core: &TraderCore,
    evidence: &Evidence,
    movements: &[(D32, u64, u64)],
    relationships: usize,
) -> Result<(), Refusal> {
    require(
        core.entries().len() == movements.len() + relationships,
        Invalid::WriteSetNotExact { core: "T°" },
    )?;
    for (token, credit, debit) in movements {
        let key = balance_key(precommit.genesis(), precommit.device_id(), token);
        let entry = core
            .entries()
            .iter()
            .find(|e| e.key() == key)
            .ok_or(Refusal::Invalid(Invalid::WriteSetNotExact { core: "T°" }))?;
        let (want_pre, want_post) =
            balance_after(evidence.trader_leaf(&key)?, token, *credit, *debit)?;
        let (got_pre, got_post) = stated(entry);
        require(got_pre == want_pre, Invalid::LeafPreValueMismatch)?;
        require(got_post == want_post, Invalid::LeafPostValueMismatch)?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn validate_close(
    verdict: &mut Verdict,
    precommit: &TraderPrecommitBody,
    preimage: &SettlementPreimage,
    evidence: &Evidence,
    vault_id: &D32,
    owner_authority: &OwnerAuthority,
    reserve_a: u64,
    reserve_b: u64,
) {
    let e = *precommit.external_commitment();
    // R18-1: the reserved branch decodes, and is refused here. A verifier KNOWS
    // it is not activated, so this is Invalid with no evidence consulted.
    verdict.note(require(
        owner_authority.is_activated(),
        Invalid::OwnerAuthorityNotActivated,
    ));
    verdict.note(require(
        precommit.legs().len() == 1 && precommit.legs()[0].vault_id == *vault_id,
        Invalid::LegsDoNotMatchPrecommit,
    ));

    let state = verdict.get(evidence.vault_state(vault_id));
    if let Some(pre_state) = state.as_ref() {
        // P15-11: the origin owner, and only it. Today's mnemonic recovery
        // re-derives the same (G, DevID), so a recovered owner closes here.
        verdict.note(require(
            *precommit.genesis() == pre_state.owner_genesis
                && *precommit.device_id() == pre_state.owner_device_id,
            Invalid::NotTheVaultOwner,
        ));
        // The vault id is the owner's own derivation; a close cannot name
        // another vault's state.
        verdict.note(require(
            derive::vault_id(
                &pre_state.owner_genesis,
                &pre_state.owner_device_id,
                pre_state.create_position,
            ) == *vault_id,
            Invalid::VaultIdIsNotTheOwnersDerivation,
        ));
        verdict.note(require(
            pre_state.storage_set_id == *precommit.storage_set_id(),
            Invalid::NetworkScopeMismatch,
        ));
        verdict.note(require(
            pre_state.status == VAULT_STATUS_ACTIVE,
            Invalid::VaultIsNotActive,
        ));
        // Exactly the committed reserves, and nothing left behind.
        verdict.note(require(
            pre_state.reserve_a == reserve_a && pre_state.reserve_b == reserve_b,
            Invalid::CloseDoesNotRetireExactly,
        ));
    }

    let core = preimage.dlv_cores().first();
    if let (Some(core), Some(pre_state)) = (core, state.as_ref()) {
        verdict.note(require(
            preimage.dlv_cores().len() == 1 && *core.vault_id() == *vault_id,
            Invalid::LegsDoNotMatchPrecommit,
        ));
        match close_vault_post(pre_state) {
            Ok(retired) => verdict.note(check_vault_write_set(core, &retired, pre_state)),
            Err(refusal) => verdict.note(Err(refusal)),
        }
    }
    if let Some(core) = core {
        match dlv_fold_entries(core, &e, evidence) {
            Ok(entries) => verdict.note(fold_core(&entries, core.pre_root()).and(Ok(()))),
            Err(refusal) => verdict.note(Err(refusal)),
        }
    }

    // The trader takes back exactly both reserves, in the pair's own tokens.
    // No debit: a close pays out, and constant-product pricing never applies.
    let trader_core = preimage.trader_core();
    let policies = state
        .as_ref()
        .and_then(|state| verdict.get(Policies::resolve(evidence, state)));
    if let Some(policies) = policies.as_ref() {
        verdict.note(check_trader_balances(
            precommit,
            trader_core,
            evidence,
            &[
                (*policies.market.token_a(), reserve_a, 0),
                (*policies.market.token_b(), reserve_b, 0),
            ],
            1,
        ));
    }
    let bases = relationship_bases(trader_core.entries());
    match bases.get(vault_id) {
        None => verdict.note(Err(Refusal::Invalid(Invalid::WriteSetNotExact {
            core: "T°",
        }))),
        Some((genesis, device_id, base)) => {
            verdict.note(require(
                genesis == precommit.genesis() && device_id == precommit.device_id(),
                Invalid::CoreIdentityMismatch,
            ));
            if let Some(core) = core {
                verdict.note(require(
                    *core.relationship_base() == *base,
                    Invalid::RelationshipBaseMismatch,
                ));
            }
        }
    }

    verdict.note(
        realize_root(trader_core, &e, evidence).and_then(|post_root| {
            require(
                post_root == *precommit.realize_root(),
                Invalid::RealizeRootIsNotTheFold,
            )
        }),
    );
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)] // fixtures; a failure here is the signal
pub(crate) mod fixtures {
    //! The swap fixture the validation tests are built on, shared with the
    //! conformance tests (R7): a real `P(E)`, its `E`, a precommit whose legs
    //! derive from it, and the acquired evidence.
    use super::*;
    use crate::sofi::smt::batch_fold;
    use crate::economic::tree::EconomicSmt;
    use crate::sofi::wire::{PreEClosureIndex, PrecommitLeg, SofiSetupBody};

    pub(crate) const G: D32 = [0x11; 32];
    pub(crate) const DEV: D32 = [0x22; 32];
    pub(crate) const P_POS: u64 = 5;
    pub(crate) const P_CREATE: u64 = 7;
    pub(crate) const FEE_BPS: u32 = 30;
    pub(crate) const RESERVE_A: u64 = 10_000;
    pub(crate) const RESERVE_B: u64 = 20_000;
    pub(crate) const AMOUNT_IN: u64 = 1_000;
    pub(crate) const SIG_ALG: u16 = 0x0001;

    pub(crate) fn token(byte: u8) -> D32 {
        [byte; 32]
    }

    /// The position the trader's setups are made at, before `P`'s.
    pub(crate) const SETUP_POS: u64 = P_POS - 1;

    /// The digest of the claim the trader's lineage accepted at
    /// [`SETUP_POS`], which the trader's setups name.
    pub(crate) const SETUP_CLAIM_REF: D32 = [0xA0; 32];

    /// The claim this verifier accepted at [`SETUP_POS`], rehydrated from the
    /// trader's own admitted store.
    pub(crate) fn accepted_setup_claim() -> AcceptedClaim {
        AcceptedClaim::rehydrate_from_admitted_store(
            G,
            DEV,
            crate::economic::lineage::AdmittedEconomicPosition::SingleRoot {
                economic_position: SETUP_POS,
                economic_root: token(0x9A),
                claim_ref: SETUP_CLAIM_REF,
            },
        )
        .expect("an ordinary admitted position")
    }

    /// The tokens a fixture route can walk: one more than its longest route.
    const FIXTURE_TOKENS: usize = 4;

    /// The trader's SPHINCS+ key pair `(pk, sk)`: `P`, `F` and every setup
    /// are signed with it. Key generation is slow, so it is made once.
    pub(crate) fn trader_keys() -> &'static (Vec<u8>, Vec<u8>) {
        static KEYS: std::sync::OnceLock<(Vec<u8>, Vec<u8>)> = std::sync::OnceLock::new();
        KEYS.get_or_init(|| crate::crypto::sphincs::generate_sphincs_keypair().expect("keypair"))
    }

    /// The `TokenPolicyV3` bytes of fixture token `i`: native, transferable,
    /// its whole supply released at creation, laid out as SoFi §47 packs it.
    fn token_policy_bytes(i: u8) -> Vec<u8> {
        token_policy_bytes_with(i, crate::economic::token_policy::POLICY_FLAG_TRANSFERABLE)
    }

    /// Fixture token `i` with the policy flags `flags`.
    pub(crate) fn token_policy_bytes_with(i: u8, flags: u8) -> Vec<u8> {
        use crate::economic::token_policy::{
            ReleaseRule, ALLOWLIST_KIND_NONE, SUPPLY_CLASS_NATIVE, TOKEN_KIND_FUNGIBLE,
            TOKEN_POLICY_VERSION,
        };
        let signer = &trader_keys().0;
        let ticker = format!("T{i:02}");
        let alias = format!("Token {i}");
        let mut blob = vec![
            TOKEN_POLICY_VERSION,
            TOKEN_KIND_FUNGIBLE,
            SUPPLY_CLASS_NATIVE,
            flags,
            ReleaseRule::AllAtCreation.code(),
        ];
        blob.extend_from_slice(&G);
        blob.extend_from_slice(&DEV);
        blob.push(1);
        blob.push(1);
        blob.extend_from_slice(&(signer.len() as u16).to_be_bytes());
        blob.extend_from_slice(signer);
        blob.push(ticker.len() as u8);
        blob.extend_from_slice(ticker.as_bytes());
        blob.extend_from_slice(&(alias.len() as u16).to_be_bytes());
        blob.extend_from_slice(alias.as_bytes());
        blob.push(6);
        blob.extend_from_slice(&1_000_000_000u128.to_be_bytes());
        blob.extend_from_slice(&0u16.to_be_bytes());
        blob.extend_from_slice(&0u16.to_be_bytes());
        blob.push(ALLOWLIST_KIND_NONE);
        blob.extend_from_slice(&0u16.to_be_bytes());
        prost::Message::encode_to_vec(&crate::types::proto::TokenPolicyV3 { policy_bytes: blob })
    }

    /// `(policy_commit, bytes)` for policy bytes.
    pub(crate) fn committed(bytes: Vec<u8>) -> (D32, Vec<u8>) {
        (
            crate::crypto::blake3::domain_hash_bytes(
                crate::common::domain_tags::TAG_DSM_POLICY,
                &bytes,
            ),
            bytes,
        )
    }

    /// The fixture tokens as `(policy_commit, TokenPolicyV3 bytes)`, in
    /// ascending commit order: vault `j` trades token `j` for token `j + 1`,
    /// the strict order its market policy requires.
    pub(crate) fn tokens() -> &'static [(D32, Vec<u8>)] {
        static TOKENS: std::sync::OnceLock<Vec<(D32, Vec<u8>)>> = std::sync::OnceLock::new();
        TOKENS.get_or_init(|| {
            let mut tokens: Vec<(D32, Vec<u8>)> = (0..FIXTURE_TOKENS as u8)
                .map(|i| committed(token_policy_bytes(i)))
                .collect();
            tokens.sort();
            tokens
        })
    }

    /// Vault `j` trades the pair `(token j, token j+1)`, strictly ordered as
    /// the market policy requires, so an N-hop route walks t0 → t1 → … → tN
    /// and never trades a token against itself.
    pub(crate) fn pair(j: usize) -> (D32, D32) {
        (tokens()[j].0, tokens()[j + 1].0)
    }

    /// The trader's setup for `vault_id`, made at [`SETUP_POS`] under the
    /// trader's key.
    pub(crate) fn setup_body_for(vault_id: D32) -> SofiSetupBody {
        SofiSetupBody::new(
            G,
            DEV,
            SETUP_POS,
            vault_id,
            SETUP_CLAIM_REF,
            token(0xB0),
            SIG_ALG,
            &trader_keys().0,
        )
        .expect("a setup body")
    }

    /// The published form of `body`: the envelope carrying the trader's
    /// signature over `m_setup`.
    pub(crate) fn setup_envelope_of(body: &SofiSetupBody) -> Vec<u8> {
        let signature = crate::crypto::sphincs::sphincs_sign(
            &trader_keys().1,
            &derive::setup_signing_digest(body),
        )
        .expect("a setup signature");
        crate::sofi::publication::Publication::Setup {
            body,
            signature: &signature,
        }
        .object_bytes()
        .expect("a setup envelope")
    }

    /// The published setup for `vault_id`.
    pub(crate) fn setup_envelope_for(vault_id: D32) -> Vec<u8> {
        setup_envelope_of(&setup_body_for(vault_id))
    }

    /// `ρ` of the trader's setup for `vault_id`.
    pub(crate) fn setup_ref_for(vault_id: D32) -> D32 {
        derive::setup_ref(&setup_body_for(vault_id))
    }

    pub(crate) fn policies(j: usize) -> (MarketPolicy, FeePolicy, ReleasePolicy) {
        policies_over(pair(j))
    }

    /// A vault's policies over the market pair `(a, b)`.
    pub(crate) fn policies_over((a, b): (D32, D32)) -> (MarketPolicy, FeePolicy, ReleasePolicy) {
        (
            MarketPolicy::beta_constant_product(a, b).unwrap(),
            FeePolicy::new(FEE_BPS).unwrap(),
            ReleasePolicy::beta_owner_local_full_close(),
        )
    }

    /// The address a vault state names a policy by: the class's own
    /// content-addressing rule, which the validator re-derives.
    pub(crate) fn policy_addr(class: u16, bytes: &[u8]) -> D32 {
        crate::ccb::decode::policy_object_address(class, bytes).expect("a policy class")
    }

    pub(crate) fn vault_id_of(j: usize) -> D32 {
        derive::vault_id(&G, &DEV, P_CREATE + j as u64)
    }

    pub(crate) fn vault_state(
        j: usize,
        reserve_a: u64,
        reserve_b: u64,
        status: u16,
    ) -> VaultStateLeaf {
        vault_state_over(j, pair(j), reserve_a, reserve_b, status)
    }

    /// Vault `j`'s state over the market pair `market_pair`.
    pub(crate) fn vault_state_over(
        j: usize,
        market_pair: (D32, D32),
        reserve_a: u64,
        reserve_b: u64,
        status: u16,
    ) -> VaultStateLeaf {
        let (market, fee, release) = policies_over(market_pair);
        VaultStateLeaf {
            owner_genesis: G,
            owner_device_id: DEV,
            create_position: P_CREATE + j as u64,
            market_policy: policy_addr(crate::ccb::class::MARKET_POLICY, &market.encode()),
            fee_policy: policy_addr(crate::ccb::class::FEE_POLICY, &fee.encode()),
            release_policy: policy_addr(crate::ccb::class::RELEASE_POLICY, &release.encode()),
            storage_set_id: token(0x77),
            generation: 3,
            reserve_a,
            reserve_b,
            status,
        }
    }

    pub(crate) fn policy_objects(hops: usize) -> BTreeMap<D32, Vec<u8>> {
        policy_objects_over(&(0..hops.max(1)).map(pair).collect::<Vec<_>>())
    }

    /// The policy objects of vaults over `pairs`.
    pub(crate) fn policy_objects_over(pairs: &[(D32, D32)]) -> BTreeMap<D32, Vec<u8>> {
        let mut objects = BTreeMap::new();
        for market_pair in pairs {
            let (market, fee, release) = policies_over(*market_pair);
            for (class, bytes) in [
                (crate::ccb::class::MARKET_POLICY, market.encode()),
                (crate::ccb::class::FEE_POLICY, fee.encode()),
                (crate::ccb::class::RELEASE_POLICY, release.encode()),
            ] {
                objects.insert(policy_addr(class, &bytes), bytes);
            }
        }
        objects
    }

    pub(crate) fn path_of(tree: &EconomicSmt, key: &D32) -> Vec<D32> {
        tree.siblings(key).to_vec()
    }

    pub(crate) fn balance(policy_commit: D32, amount: u64) -> EconomicBalanceState {
        EconomicBalanceState {
            policy_commit,
            amount,
        }
    }

    pub(crate) fn balance_leaf_value(policy_commit: D32, amount: u64) -> D32 {
        EconomicLeafState::Balance(balance(policy_commit, amount))
            .leaf_value()
            .unwrap()
    }

    pub(crate) fn base_of(j: usize) -> D32 {
        derive::relationship_leaf_genesis(&derive::setup_id(&G, &DEV, P_POS, &vault_id_of(j)))
    }

    /// A whole operation, built the way a trader builds one: the trees first,
    /// then the cores against them, then E, then the roots E fixes.
    pub(crate) struct Fixture {
        pub(crate) precommit: TraderPrecommitBody,
        pub(crate) preimage: SettlementPreimage,
        pub(crate) evidence: Evidence,
    }

    /// One vault's worth of a swap: its tree, its core, and the hop it prices.
    pub(crate) struct VaultParts {
        pub(crate) vault_id: D32,
        pub(crate) core: DlvCore,
        pub(crate) hop: SwapHop,
        pub(crate) parent_root: D32,
        pub(crate) state: VaultStateLeaf,
        pub(crate) relationship: VaultRelationshipLeaf,
        pub(crate) state_key: D32,
        pub(crate) rel_key: D32,
    }

    /// Vault `j` of a swap, trading the market pair `market_pair`.
    pub(crate) fn swap_vault_parts_over(
        j: usize,
        market_pair: (D32, D32),
        amount_in: u64,
        setup_ref: D32,
    ) -> VaultParts {
        let (token_in, token_out) = market_pair;
        let vault_id = vault_id_of(j);
        let rel_key = derive::relationship_key(&G, &DEV, &vault_id);
        let base = base_of(j);
        let state = vault_state_over(j, market_pair, RESERVE_A, RESERVE_B, VAULT_STATUS_ACTIVE);
        let amount_out =
            constant_product_output_classified(amount_in, RESERVE_A, RESERVE_B, FEE_BPS).unwrap();
        let relationship = VaultRelationshipLeaf {
            trader_genesis: G,
            trader_device_id: DEV,
            leaf: base,
        };
        let state_key = derive::vault_state_key(&vault_id);
        let mut tree = EconomicSmt::new();
        tree.insert(state_key, derive::vault_state_leaf_value(&state).unwrap());
        tree.insert(
            rel_key,
            derive::vault_relationship_leaf_value(&relationship),
        );

        let post_state = VaultStateLeaf {
            generation: state.generation + 1,
            reserve_a: RESERVE_A + amount_in,
            reserve_b: RESERVE_B - amount_out,
            ..state.clone()
        };
        let mut entries = vec![
            CoreEntry::Mutation {
                key: state_key,
                pre: derive::vault_state_leaf_value(&state).unwrap(),
                post: derive::vault_state_leaf_value(&post_state).unwrap(),
                path: path_of(&tree, &state_key),
            },
            CoreEntry::Relationship {
                genesis: G,
                device_id: DEV,
                vault_id,
                base,
                path: path_of(&tree, &rel_key),
            },
        ];
        entries.sort_by_key(|e| e.key());
        VaultParts {
            vault_id,
            core: DlvCore::new(vault_id, tree.root(), G, DEV, base, entries).unwrap(),
            hop: SwapHop {
                vault_id,
                parent_root: tree.root(),
                setup_ref,
                token_in,
                amount_in,
                token_out,
                amount_out,
            },
            parent_root: tree.root(),
            state,
            relationship,
            state_key,
            rel_key,
        }
    }

    pub(crate) fn swap_fixture_n(hops: usize) -> Fixture {
        swap_fixture_with(hops, PreEClosureIndex::new(Vec::new()).unwrap())
    }

    /// A swap over `hops` vaults whose leg `j` carries the trader's setup for
    /// that vault and whose `B°` commits `closure`.
    pub(crate) fn swap_fixture_with(hops: usize, closure: PreEClosureIndex) -> Fixture {
        swap_fixture_with_setups(hops, &|j| setup_body_for(vault_id_of(j)), closure)
    }

    /// A swap over `hops` vaults whose leg `j` carries the setup `setup(j)`,
    /// signed under the trader's key, and whose `B°` commits `closure`.
    pub(crate) fn swap_fixture_with_setups(
        hops: usize,
        setup: &dyn Fn(usize) -> SofiSetupBody,
        closure: PreEClosureIndex,
    ) -> Fixture {
        swap_fixture_over(&tokens()[..=hops], setup, closure)
    }

    /// A swap walking `route_tokens` in order — vault `j` trades token `j` for
    /// token `j + 1`, so they must ascend by commit — whose leg `j` carries
    /// `setup(j)` and whose `B°` commits `closure`. The evidence carries the
    /// policy bytes of every token that is not builtin.
    pub(crate) fn swap_fixture_over(
        route_tokens: &[(D32, Vec<u8>)],
        setup: &dyn Fn(usize) -> SofiSetupBody,
        closure: PreEClosureIndex,
    ) -> Fixture {
        let hops = route_tokens.len() - 1;
        let pairs: Vec<(D32, D32)> = route_tokens.windows(2).map(|w| (w[0].0, w[1].0)).collect();
        let mut parts: Vec<VaultParts> = Vec::new();
        let mut amount = AMOUNT_IN;
        for (j, pair) in pairs.iter().enumerate() {
            let part = swap_vault_parts_over(j, *pair, amount, derive::setup_ref(&setup(j)));
            amount = part.hop.amount_out;
            parts.push(part);
        }
        let intent_in = parts[0].hop.token_in;
        let intent_out = parts[hops - 1].hop.token_out;
        let exact_out = parts[hops - 1].hop.amount_out;

        // The trader's tree: the token spent, and one relationship per vault.
        let in_key = balance_key(&G, &DEV, &intent_in);
        let out_key = balance_key(&G, &DEV, &intent_out);
        let mut trader_tree = EconomicSmt::new();
        trader_tree.insert(in_key, balance_leaf_value(intent_in, 50_000));
        let trader_rels: Vec<TraderRelationshipLeaf> = parts
            .iter()
            .enumerate()
            .map(|(j, part)| {
                let leaf = TraderRelationshipLeaf {
                    vault_id: part.vault_id,
                    leaf: base_of(j),
                };
                trader_tree.insert(part.rel_key, derive::trader_relationship_leaf_value(&leaf));
                leaf
            })
            .collect();

        let mut trader_entries = vec![
            CoreEntry::Mutation {
                key: in_key,
                pre: balance_leaf_value(intent_in, 50_000),
                post: balance_leaf_value(intent_in, 50_000 - AMOUNT_IN),
                path: path_of(&trader_tree, &in_key),
            },
            CoreEntry::Mutation {
                key: out_key,
                pre: crate::economic::tree::ABSENT_LEAF,
                post: balance_leaf_value(intent_out, exact_out),
                path: path_of(&trader_tree, &out_key),
            },
        ];
        for (j, part) in parts.iter().enumerate() {
            trader_entries.push(CoreEntry::Relationship {
                genesis: G,
                device_id: DEV,
                vault_id: part.vault_id,
                base: base_of(j),
                path: path_of(&trader_tree, &part.rel_key),
            });
        }
        trader_entries.sort_by_key(|e| e.key());
        let trader_core =
            TraderCore::new(G, DEV, P_POS + 1, trader_tree.root(), trader_entries).unwrap();

        let mut cores: Vec<DlvCore> = parts.iter().map(|p| p.core.clone()).collect();
        cores.sort_by_key(|c| *c.vault_id());
        // B° names its cores by DIGEST, positionally against P(E)'s own
        // vault-sorted order — not by vault id.
        let core_ids: Vec<D32> = cores
            .iter()
            .map(|c| derive::dlv_core_digest(&c.encode().unwrap()))
            .collect();
        let settlement = SettlementBody::Swap {
            token_in: intent_in,
            amount_in: AMOUNT_IN,
            token_out: intent_out,
            exact_out,
            hops: parts.iter().map(|p| p.hop).collect(),
            trader_core: derive::trader_core_digest(&trader_core.encode().unwrap()),
            dlv_cores: core_ids,
            closure,
        };
        let preimage = SettlementPreimage::new(settlement, trader_core.clone(), cores).unwrap();
        let e = derive::recompute_e(&preimage).unwrap();

        let mut trader_leaves = BTreeMap::from([
            (in_key, TraderLeafPre::Balance(balance(intent_in, 50_000))),
            (out_key, TraderLeafPre::Absent),
        ]);
        let mut vault_leaves = BTreeMap::new();
        for (part, rel) in parts.iter().zip(trader_rels) {
            trader_leaves.insert(part.rel_key, TraderLeafPre::Relationship(rel));
            vault_leaves.insert(
                (part.vault_id, part.state_key),
                VaultLeafPre::State(part.state.clone()),
            );
            vault_leaves.insert(
                (part.vault_id, part.rel_key),
                VaultLeafPre::Relationship(part.relationship),
            );
        }
        let evidence = Evidence {
            objects: policy_objects_over(&pairs),
            trader_leaves,
            vault_leaves,
            setups: (0..hops)
                .map(|j| (parts[j].hop.setup_ref, setup_envelope_of(&setup(j))))
                .collect(),
            token_policies: route_tokens
                .iter()
                .filter(|(commit, _)| {
                    crate::core::token::builtin_token_id_for_policy_commit(commit).is_none()
                })
                .cloned()
                .collect(),
            accepted_claims: BTreeMap::from([(SETUP_POS, accepted_setup_claim())]),
        };
        // The realize root is what the core folds to UNDER E, so it cannot be
        // chosen: BindExt fills the relationship posts and the fold does the rest.
        let realize_root = {
            let entries = trader_fold_entries(&trader_core, &e, &evidence).unwrap();
            batch_fold(&entries).unwrap().post_root
        };
        let legs: Vec<PrecommitLeg> = {
            let mut legs: Vec<PrecommitLeg> = parts
                .iter()
                .map(|p| PrecommitLeg {
                    vault_id: p.vault_id,
                    parent_root: p.parent_root,
                    setup_ref: p.hop.setup_ref,
                })
                .collect();
            legs.sort_by_key(|l| l.vault_id);
            legs
        };
        let precommit = TraderPrecommitBody::new(
            G,
            DEV,
            P_POS,
            crate::sofi::wire::ParentClaimRef::SingleRoot {
                claim_ref: token(0x66),
            },
            e,
            legs,
            realize_root,
            trader_tree.root(),
            token(0x77),
            SIG_ALG,
            &trader_keys().0,
        )
        .unwrap();
        Fixture {
            precommit,
            preimage,
            evidence,
        }
    }

    pub(crate) fn swap_fixture() -> Fixture {
        swap_fixture_n(1)
    }
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)] // test asserts; a failure here is the signal
mod tests {
    use super::fixtures::*;
    use super::*;
    use crate::economic::tree::{EconomicSmt, ECONOMIC_SMT_HEIGHT};
    use crate::sofi::smt::batch_fold;
    use crate::sofi::wire::{PreEClosureIndex, PrecommitLeg};

    #[test]
    fn a_well_formed_swap_is_valid() {
        let f = swap_fixture();
        assert_eq!(validate(&f.precommit, &f.preimage, &f.evidence), Ok(()));
        assert_eq!(
            route_validation(&f.precommit, &f.preimage, &f.evidence),
            Ok(Validation::Valid)
        );
    }

    /// Missing evidence leaves the predicate unevaluated and names what is
    /// missing, however much of the rest is present. It never hardens into
    /// Invalid.
    #[test]
    fn missing_evidence_is_named_never_invalid() {
        let f = swap_fixture();
        let (market, _, _) = policies(0);
        let mut without_policy = Evidence {
            objects: f.evidence.objects.clone(),
            trader_leaves: f.evidence.trader_leaves.clone(),
            vault_leaves: f.evidence.vault_leaves.clone(),
            setups: f.evidence.setups.clone(),
            token_policies: f.evidence.token_policies.clone(),
            accepted_claims: f.evidence.accepted_claims.clone(),
        };
        without_policy.objects.remove(&policy_addr(
            crate::ccb::class::MARKET_POLICY,
            &market.encode(),
        ));
        assert!(matches!(
            validate(&f.precommit, &f.preimage, &without_policy),
            Err(Refusal::Incomplete(Missing::Policy { .. }))
        ));
        assert!(matches!(
            route_validation(&f.precommit, &f.preimage, &without_policy),
            Err(Missing::Policy { .. })
        ));

        let mut without_leaf = Evidence {
            objects: f.evidence.objects.clone(),
            trader_leaves: f.evidence.trader_leaves.clone(),
            vault_leaves: BTreeMap::new(),
            setups: f.evidence.setups.clone(),
            token_policies: f.evidence.token_policies.clone(),
            accepted_claims: f.evidence.accepted_claims.clone(),
        };
        without_leaf.trader_leaves.clear();
        assert!(matches!(
            route_validation(&f.precommit, &f.preimage, &without_leaf),
            Err(Missing::TraderLeaf { .. } | Missing::VaultLeaf { .. })
        ));
    }

    /// A two-hop route: the trader spends t0, receives t2, and t1 never
    /// touches its balances — it moves inside the vaults.
    #[test]
    fn a_two_hop_route_chains_through_the_intermediate_token() {
        let f = swap_fixture_n(2);
        assert_eq!(validate(&f.precommit, &f.preimage, &f.evidence), Ok(()));
        let SettlementBody::Swap { hops, .. } = f.preimage.settlement() else {
            panic!("a swap fixture")
        };
        assert_eq!(hops.len(), 2);
        assert_eq!(hops[0].token_out, hops[1].token_in);
        assert_eq!(hops[0].amount_out, hops[1].amount_in);
        // The intermediate token has no trader entry: exactly two balance
        // movements and one relationship per leg.
        assert_eq!(f.preimage.trader_core().entries().len(), 4);
    }

    /// Rebuild a fixture's settlement body with one field changed, keeping
    /// everything else — including E and the roots — as the honest trader
    /// built it. That is what makes each negative about ONE rule.
    fn with_swap<F: FnOnce(&mut Vec<SwapHop>, &mut u64, &mut u64)>(
        f: &Fixture,
        edit: F,
    ) -> SettlementPreimage {
        let SettlementBody::Swap {
            token_in,
            amount_in,
            token_out,
            exact_out,
            hops,
            trader_core,
            dlv_cores,
            closure,
        } = f.preimage.settlement().clone()
        else {
            panic!("a swap fixture")
        };
        let mut hops = hops;
        let mut amount_in = amount_in;
        let mut exact_out = exact_out;
        edit(&mut hops, &mut amount_in, &mut exact_out);
        SettlementPreimage::new(
            SettlementBody::Swap {
                token_in,
                amount_in,
                token_out,
                exact_out,
                hops,
                trader_core,
                dlv_cores,
                closure,
            },
            f.preimage.trader_core().clone(),
            f.preimage.dlv_cores().to_vec(),
        )
        .unwrap()
    }

    #[test]
    fn an_off_by_one_output_is_invalid() {
        let f = swap_fixture();
        // One unit more out than the curve gives. E moves with it, so this is
        // the price check talking, not the commitment check.
        let bent = with_swap(&f, |hops, _, exact_out| {
            hops[0].amount_out += 1;
            *exact_out += 1;
        });
        let precommit = rebind(&f, &bent);
        assert_eq!(
            validate(&precommit, &bent, &f.evidence),
            Err(Refusal::Invalid(Invalid::PriceIsNotTheConstantProduct {
                hop: 0
            }))
        );
    }

    /// Replace the trader core, keeping `B°`'s reference to it honest and
    /// re-deriving `E`. A write-set negative must test the write set — not the
    /// core reference it would otherwise break on the way.
    fn with_trader_core(
        f: &Fixture,
        entries: Vec<CoreEntry>,
    ) -> (TraderPrecommitBody, SettlementPreimage) {
        let core = TraderCore::new(
            G,
            DEV,
            P_POS + 1,
            *f.preimage.trader_core().pre_root(),
            entries,
        )
        .unwrap();
        let reference = derive::trader_core_digest(&core.encode().unwrap());
        let settlement = match f.preimage.settlement().clone() {
            SettlementBody::Swap {
                token_in,
                amount_in,
                token_out,
                exact_out,
                hops,
                dlv_cores,
                closure,
                ..
            } => SettlementBody::Swap {
                token_in,
                amount_in,
                token_out,
                exact_out,
                hops,
                trader_core: reference,
                dlv_cores,
                closure,
            },
            SettlementBody::Close {
                vault_id,
                parent_root,
                setup_ref,
                owner_authority,
                reserve_a,
                reserve_b,
                dlv_core,
                closure,
                ..
            } => SettlementBody::Close {
                vault_id,
                parent_root,
                setup_ref,
                owner_authority,
                reserve_a,
                reserve_b,
                trader_core: reference,
                dlv_core,
                closure,
            },
        };
        let preimage =
            SettlementPreimage::new(settlement, core, f.preimage.dlv_cores().to_vec()).unwrap();
        let precommit = rebind(f, &preimage);
        (precommit, preimage)
    }

    /// Re-point a precommit at an edited preimage, so the only thing under
    /// test is the rule, not `E`.
    fn rebind(f: &Fixture, preimage: &SettlementPreimage) -> TraderPrecommitBody {
        let e = derive::recompute_e(preimage).unwrap();
        TraderPrecommitBody::new(
            *f.precommit.genesis(),
            *f.precommit.device_id(),
            f.precommit.position(),
            *f.precommit.parent_claim_ref(),
            e,
            f.precommit.legs().to_vec(),
            *f.precommit.realize_root(),
            *f.precommit.void_root(),
            *f.precommit.storage_set_id(),
            f.precommit.signature_alg(),
            f.precommit.claimant_public_key(),
        )
        .unwrap()
    }

    /// A core whose paths are not all of one tree does not fold, and the
    /// refusal says so. It is not reported as a write-set violation: the write
    /// set here is exactly the branch's own.
    #[test]
    fn a_core_whose_paths_are_not_one_tree_does_not_fold() {
        let f = swap_fixture();
        let mut entries = f.preimage.trader_core().entries().to_vec();
        match &mut entries[0] {
            CoreEntry::Mutation { path, .. }
            | CoreEntry::Read { path, .. }
            | CoreEntry::Relationship { path, .. } => path[0] = token(0x7C),
        }
        let (precommit, bent) = with_trader_core(&f, entries);
        assert_eq!(
            validate(&precommit, &bent, &f.evidence),
            Err(Refusal::Invalid(Invalid::CoreDoesNotFold {
                reason: "the entries' paths are not of one tree",
            }))
        );
    }

    /// Restating the wrong root in BOTH places does not buy a trader anything.
    /// `P.void_root == T°.pre_root` then holds, and the entries still do not
    /// fold to it — so the second fold rule is what refuses this, naming the
    /// fold rather than the write set.
    #[test]
    fn a_pre_root_the_entries_do_not_produce_does_not_fold() {
        let f = swap_fixture();
        let forged = token(0x7C);
        let core = TraderCore::new(
            G,
            DEV,
            P_POS + 1,
            forged,
            f.preimage.trader_core().entries().to_vec(),
        )
        .unwrap();
        let SettlementBody::Swap {
            token_in,
            amount_in,
            token_out,
            exact_out,
            hops,
            dlv_cores,
            closure,
            ..
        } = f.preimage.settlement().clone()
        else {
            panic!("a swap")
        };
        let preimage = SettlementPreimage::new(
            SettlementBody::Swap {
                token_in,
                amount_in,
                token_out,
                exact_out,
                hops,
                trader_core: derive::trader_core_digest(&core.encode().unwrap()),
                dlv_cores,
                closure,
            },
            core,
            f.preimage.dlv_cores().to_vec(),
        )
        .unwrap();
        let precommit = TraderPrecommitBody::new(
            G,
            DEV,
            P_POS,
            *f.precommit.parent_claim_ref(),
            derive::recompute_e(&preimage).unwrap(),
            f.precommit.legs().to_vec(),
            *f.precommit.realize_root(),
            // The void root agrees with the forged pre-root, so P15-2's first
            // check passes and only the fold can catch this.
            forged,
            *f.precommit.storage_set_id(),
            f.precommit.signature_alg(),
            f.precommit.claimant_public_key(),
        )
        .unwrap();
        assert_eq!(
            validate(&precommit, &preimage, &f.evidence),
            Err(Refusal::Invalid(Invalid::CoreDoesNotFold {
                reason: "the entries do not fold to the core's own pre-root",
            }))
        );
    }

    /// MR-DSM-0041: a route refuted by its own bytes is Invalid with nothing
    /// fetched; a valid route has nothing refuted in hand, though its leaves
    /// and policies are not.
    #[test]
    fn what_the_operation_decides_alone_is_decided_before_any_read() {
        let f = swap_fixture_n(2);
        assert_eq!(route_invalid_in_hand(&f.precommit, &f.preimage), None);
        let bent = with_swap(&f, |hops, _, _| {
            hops[1].amount_in -= 1;
        });
        let precommit = rebind(&f, &bent);
        assert_eq!(
            route_invalid_in_hand(&precommit, &bent),
            Some(Invalid::RouteDoesNotChain { hop: 1 })
        );
    }

    #[test]
    fn an_unchained_hop_is_invalid() {
        let f = swap_fixture_n(2);
        let bent = with_swap(&f, |hops, _, _| {
            // The second hop takes in one unit less than the first gave out.
            hops[1].amount_in -= 1;
        });
        let precommit = rebind(&f, &bent);
        assert_eq!(
            validate(&precommit, &bent, &f.evidence),
            Err(Refusal::Invalid(Invalid::RouteDoesNotChain { hop: 1 }))
        );
    }

    #[test]
    fn a_route_whose_ends_are_not_the_intent_is_invalid() {
        let f = swap_fixture();
        let bent = with_swap(&f, |_, amount_in, _| {
            *amount_in += 1;
        });
        let precommit = rebind(&f, &bent);
        assert_eq!(
            validate(&precommit, &bent, &f.evidence),
            Err(Refusal::Invalid(Invalid::RouteDoesNotChain { hop: 0 }))
        );
    }

    #[test]
    fn a_token_outside_the_vaults_pair_is_invalid() {
        let f = swap_fixture();
        let bent = with_swap(&f, |hops, _, _| {
            hops[0].token_in = token(0x7E);
        });
        // The intent end moves with the hop, so the pair check is what speaks —
        // otherwise the route would simply fail to reach the intent's ends.
        let SettlementBody::Swap { hops, .. } = bent.settlement().clone() else {
            unreachable!()
        };
        let realigned = SettlementPreimage::new(
            SettlementBody::Swap {
                token_in: hops[0].token_in,
                amount_in: hops[0].amount_in,
                token_out: hops[0].token_out,
                exact_out: hops[0].amount_out,
                hops,
                trader_core: derive::trader_core_digest(
                    &f.preimage.trader_core().encode().unwrap(),
                ),
                dlv_cores: vec![derive::dlv_core_digest(
                    &f.preimage.dlv_cores()[0].encode().unwrap(),
                )],
                closure: PreEClosureIndex::new(Vec::new()).unwrap(),
            },
            f.preimage.trader_core().clone(),
            f.preimage.dlv_cores().to_vec(),
        )
        .unwrap();
        let precommit = rebind(&f, &realigned);
        assert_eq!(
            validate(&precommit, &realigned, &f.evidence),
            Err(Refusal::Invalid(Invalid::TokenIsNotInTheVaultPair {
                hop: 0
            }))
        );
    }

    #[test]
    fn precommit_roots_that_do_not_match_the_cores_are_invalid() {
        let f = swap_fixture();
        // P15-2: the void root IS the trader core's pre-root.
        let wrong_void = TraderPrecommitBody::new(
            *f.precommit.genesis(),
            *f.precommit.device_id(),
            f.precommit.position(),
            *f.precommit.parent_claim_ref(),
            *f.precommit.external_commitment(),
            f.precommit.legs().to_vec(),
            *f.precommit.realize_root(),
            token(0x01),
            *f.precommit.storage_set_id(),
            f.precommit.signature_alg(),
            f.precommit.claimant_public_key(),
        )
        .unwrap();
        assert_eq!(
            validate(&wrong_void, &f.preimage, &f.evidence),
            Err(Refusal::Invalid(Invalid::VoidRootIsNotThePreRoot))
        );

        // And the realize root is the fold, not a number the trader picks.
        let wrong_realize = TraderPrecommitBody::new(
            *f.precommit.genesis(),
            *f.precommit.device_id(),
            f.precommit.position(),
            *f.precommit.parent_claim_ref(),
            *f.precommit.external_commitment(),
            f.precommit.legs().to_vec(),
            token(0x02),
            *f.precommit.void_root(),
            *f.precommit.storage_set_id(),
            f.precommit.signature_alg(),
            f.precommit.claimant_public_key(),
        )
        .unwrap();
        assert_eq!(
            validate(&wrong_realize, &f.preimage, &f.evidence),
            Err(Refusal::Invalid(Invalid::RealizeRootIsNotTheFold))
        );
    }

    #[test]
    fn a_preimage_e_does_not_commit_to_is_invalid() {
        let f = swap_fixture();
        let other = swap_fixture_n(2);
        assert_eq!(
            validate(&f.precommit, &other.preimage, &other.evidence),
            Err(Refusal::Invalid(Invalid::ExternalCommitmentMismatch))
        );
    }

    /// The write sets are CLOSED: an extra trader entry is refused even though
    /// it folds and its own values are honest.
    #[test]
    fn an_extra_trader_entry_is_invalid() {
        let f = swap_fixture();
        let entries = {
            let mut entries = f.preimage.trader_core().entries().to_vec();
            entries.push(CoreEntry::Read {
                key: token(0x09),
                value: crate::economic::tree::ABSENT_LEAF,
                path: vec![[0u8; 32]; ECONOMIC_SMT_HEIGHT],
            });
            entries.sort_by_key(|e| e.key());
            entries
        };
        let (precommit, preimage) = with_trader_core(&f, entries);
        assert_eq!(
            validate(&precommit, &preimage, &f.evidence),
            Err(Refusal::Invalid(Invalid::WriteSetNotExact { core: "T°" }))
        );
    }

    /// A missing movement is the same rule from the other side.
    #[test]
    fn a_missing_trader_movement_is_invalid() {
        let f = swap_fixture();
        let entries = {
            let out_key = balance_key(&G, &DEV, &pair(0).1);
            f.preimage
                .trader_core()
                .entries()
                .iter()
                .filter(|e| e.key() != out_key)
                .cloned()
                .collect()
        };
        let (precommit, preimage) = with_trader_core(&f, entries);
        assert_eq!(
            validate(&precommit, &preimage, &f.evidence),
            Err(Refusal::Invalid(Invalid::WriteSetNotExact { core: "T°" }))
        );
    }

    /// A relationship advancing from a base the cores do not agree on.
    #[test]
    fn a_wrong_relationship_base_is_invalid() {
        let f = swap_fixture();
        let entries = f
            .preimage
            .trader_core()
            .entries()
            .iter()
            .map(|e| match e {
                CoreEntry::Relationship {
                    genesis,
                    device_id,
                    vault_id,
                    path,
                    ..
                } => CoreEntry::Relationship {
                    genesis: *genesis,
                    device_id: *device_id,
                    vault_id: *vault_id,
                    base: token(0x03),
                    path: path.clone(),
                },
                other => other.clone(),
            })
            .collect();
        let (precommit, preimage) = with_trader_core(&f, entries);
        assert_eq!(
            validate(&precommit, &preimage, &f.evidence),
            Err(Refusal::Invalid(Invalid::RelationshipBaseMismatch))
        );
    }

    /// A vault pinned to another storage set is out of this network's scope.
    #[test]
    fn a_vault_in_another_storage_set_is_invalid() {
        let f = swap_fixture();
        let vault_id = *f.preimage.dlv_cores()[0].vault_id();
        let state_key = derive::vault_state_key(&vault_id);
        let mut evidence = Evidence {
            objects: f.evidence.objects.clone(),
            trader_leaves: f.evidence.trader_leaves.clone(),
            vault_leaves: f.evidence.vault_leaves.clone(),
            setups: f.evidence.setups.clone(),
            token_policies: f.evidence.token_policies.clone(),
            accepted_claims: f.evidence.accepted_claims.clone(),
        };
        let VaultLeafPre::State(state) = evidence.vault_leaves[&(vault_id, state_key)].clone()
        else {
            panic!("the state leaf")
        };
        evidence.vault_leaves.insert(
            (vault_id, state_key),
            VaultLeafPre::State(VaultStateLeaf {
                storage_set_id: token(0x7F),
                ..state
            }),
        );
        assert_eq!(
            validate(&f.precommit, &f.preimage, &evidence),
            Err(Refusal::Invalid(Invalid::NetworkScopeMismatch))
        );
    }

    /// An overflowing reserve is refused, never wrapped.
    #[test]
    fn an_overflowing_reserve_is_invalid() {
        let f = swap_fixture();
        let vault_id = *f.preimage.dlv_cores()[0].vault_id();
        let state_key = derive::vault_state_key(&vault_id);
        let mut evidence = Evidence {
            objects: f.evidence.objects.clone(),
            trader_leaves: f.evidence.trader_leaves.clone(),
            vault_leaves: f.evidence.vault_leaves.clone(),
            setups: f.evidence.setups.clone(),
            token_policies: f.evidence.token_policies.clone(),
            accepted_claims: f.evidence.accepted_claims.clone(),
        };
        let VaultLeafPre::State(state) = evidence.vault_leaves[&(vault_id, state_key)].clone()
        else {
            panic!("the state leaf")
        };
        evidence.vault_leaves.insert(
            (vault_id, state_key),
            VaultLeafPre::State(VaultStateLeaf {
                reserve_a: u64::MAX,
                ..state
            }),
        );
        // The price is computed against the real reserves, so this refuses at
        // the curve or at the checked add — either way, never a wrap.
        assert!(matches!(
            validate(&f.precommit, &f.preimage, &evidence),
            Err(Refusal::Invalid(
                Invalid::PriceIsNotTheConstantProduct { .. } | Invalid::CheckedArithmetic { .. }
            ))
        ));
    }
    /// A close, built the same way: the vault retires and the trader takes
    /// back exactly both reserves. No debit, and no curve anywhere.
    fn close_fixture(authority: OwnerAuthority) -> Fixture {
        close_fixture_for(authority, DEV)
    }

    /// The same close, against a vault owned by `owner_device`. With `DEV` it
    /// is the trader's own vault; with anything else the operation is a close
    /// of someone else's, and every OTHER field stays self-consistent.
    fn close_fixture_for(authority: OwnerAuthority, owner_device: D32) -> Fixture {
        close_fixture_with(authority, owner_device, None)
    }

    /// `release_override` replaces the vault's release-policy bytes, so a
    /// vault released under another family is built CONSISTENTLY — its state,
    /// its leaf value and its core all agree, and the only thing wrong is the
    /// policy itself.
    fn close_fixture_with(
        authority: OwnerAuthority,
        owner_device: D32,
        release_override: Option<Vec<u8>>,
    ) -> Fixture {
        let (token_a, token_b) = pair(0);
        let vault_id = derive::vault_id(&G, &owner_device, P_CREATE);
        let rel_key = derive::relationship_key(&G, &DEV, &vault_id);
        let base = derive::relationship_leaf_genesis(&derive::setup_id(&G, &DEV, P_POS, &vault_id));
        let state = VaultStateLeaf {
            owner_device_id: owner_device,
            release_policy: match release_override.as_ref() {
                None => vault_state(0, RESERVE_A, RESERVE_B, VAULT_STATUS_ACTIVE).release_policy,
                Some(bytes) => policy_addr(crate::ccb::class::RELEASE_POLICY, bytes),
            },
            ..vault_state(0, RESERVE_A, RESERVE_B, VAULT_STATUS_ACTIVE)
        };
        let state_key = derive::vault_state_key(&vault_id);
        let relationship = VaultRelationshipLeaf {
            trader_genesis: G,
            trader_device_id: DEV,
            leaf: base,
        };
        let mut vault_tree = EconomicSmt::new();
        vault_tree.insert(state_key, derive::vault_state_leaf_value(&state).unwrap());
        vault_tree.insert(
            rel_key,
            derive::vault_relationship_leaf_value(&relationship),
        );

        let retired = VaultStateLeaf {
            generation: state.generation + 1,
            reserve_a: 0,
            reserve_b: 0,
            status: VAULT_STATUS_RETIRED,
            ..state.clone()
        };
        let mut vault_entries = vec![
            CoreEntry::Mutation {
                key: state_key,
                pre: derive::vault_state_leaf_value(&state).unwrap(),
                post: derive::vault_state_leaf_value(&retired).unwrap(),
                path: path_of(&vault_tree, &state_key),
            },
            CoreEntry::Relationship {
                genesis: G,
                device_id: DEV,
                vault_id,
                base,
                path: path_of(&vault_tree, &rel_key),
            },
        ];
        vault_entries.sort_by_key(|e| e.key());
        let dlv_core =
            DlvCore::new(vault_id, vault_tree.root(), G, DEV, base, vault_entries).unwrap();

        let a_key = balance_key(&G, &DEV, &token_a);
        let b_key = balance_key(&G, &DEV, &token_b);
        let trader_rel = TraderRelationshipLeaf {
            vault_id,
            leaf: base,
        };
        let mut trader_tree = EconomicSmt::new();
        trader_tree.insert(rel_key, derive::trader_relationship_leaf_value(&trader_rel));

        let mut trader_entries = vec![
            CoreEntry::Mutation {
                key: a_key,
                pre: crate::economic::tree::ABSENT_LEAF,
                post: balance_leaf_value(token_a, RESERVE_A),
                path: path_of(&trader_tree, &a_key),
            },
            CoreEntry::Mutation {
                key: b_key,
                pre: crate::economic::tree::ABSENT_LEAF,
                post: balance_leaf_value(token_b, RESERVE_B),
                path: path_of(&trader_tree, &b_key),
            },
            CoreEntry::Relationship {
                genesis: G,
                device_id: DEV,
                vault_id,
                base,
                path: path_of(&trader_tree, &rel_key),
            },
        ];
        trader_entries.sort_by_key(|e| e.key());
        let trader_core =
            TraderCore::new(G, DEV, P_POS + 1, trader_tree.root(), trader_entries).unwrap();

        let settlement = SettlementBody::Close {
            vault_id,
            parent_root: vault_tree.root(),
            setup_ref: setup_ref_for(vault_id),
            owner_authority: authority,
            reserve_a: RESERVE_A,
            reserve_b: RESERVE_B,
            trader_core: derive::trader_core_digest(&trader_core.encode().unwrap()),
            dlv_core: derive::dlv_core_digest(&dlv_core.encode().unwrap()),
            closure: PreEClosureIndex::new(Vec::new()).unwrap(),
        };
        let preimage =
            SettlementPreimage::new(settlement, trader_core.clone(), vec![dlv_core]).unwrap();
        let e = derive::recompute_e(&preimage).unwrap();

        let mut objects = policy_objects(1);
        if let Some(bytes) = release_override {
            objects.insert(
                policy_addr(crate::ccb::class::RELEASE_POLICY, &bytes),
                bytes,
            );
        }
        let evidence = Evidence {
            objects,
            trader_leaves: BTreeMap::from([
                (a_key, TraderLeafPre::Absent),
                (b_key, TraderLeafPre::Absent),
                (rel_key, TraderLeafPre::Relationship(trader_rel)),
            ]),
            vault_leaves: BTreeMap::from([
                ((vault_id, state_key), VaultLeafPre::State(state)),
                (
                    (vault_id, rel_key),
                    VaultLeafPre::Relationship(relationship),
                ),
            ]),
            setups: BTreeMap::from([(setup_ref_for(vault_id), setup_envelope_for(vault_id))]),
            token_policies: tokens()[..=1].iter().cloned().collect(),
            accepted_claims: BTreeMap::from([(SETUP_POS, accepted_setup_claim())]),
        };
        let realize_root = {
            let entries = trader_fold_entries(&trader_core, &e, &evidence).unwrap();
            batch_fold(&entries).unwrap().post_root
        };
        let precommit = TraderPrecommitBody::new(
            G,
            DEV,
            P_POS,
            crate::sofi::wire::ParentClaimRef::SingleRoot {
                claim_ref: token(0x66),
            },
            e,
            vec![PrecommitLeg {
                vault_id,
                parent_root: vault_tree.root(),
                setup_ref: setup_ref_for(vault_id),
            }],
            realize_root,
            trader_tree.root(),
            token(0x77),
            SIG_ALG,
            &trader_keys().0,
        )
        .unwrap();
        Fixture {
            precommit,
            preimage,
            evidence,
        }
    }

    #[test]
    fn a_well_formed_close_by_the_origin_owner_is_valid() {
        let f = close_fixture(OwnerAuthority::Origin);
        assert_eq!(validate(&f.precommit, &f.preimage, &f.evidence), Ok(()));
    }

    /// R18-1: the reserved branch has canonical bytes AND a live refusal. It is
    /// Invalid, never Unavailable — the verifier KNOWS it is not activated, so
    /// no amount of further evidence could change the answer.
    #[test]
    fn a_close_naming_the_reserved_dsm_successor_is_invalid_not_unavailable() {
        let f = close_fixture(OwnerAuthority::DsmSuccessor {
            authority_class: 0x1234,
            authority_addr: token(0x5D),
        });
        assert_eq!(
            validate(&f.precommit, &f.preimage, &f.evidence),
            Err(Refusal::Invalid(Invalid::OwnerAuthorityNotActivated))
        );
        assert_eq!(
            route_validation(&f.precommit, &f.preimage, &f.evidence),
            Ok(Validation::Invalid)
        );
        // Even with NOTHING fetched it is Invalid: the branch is refused before
        // any evidence is consulted.
        assert_eq!(
            route_validation(&f.precommit, &f.preimage, &Evidence::default()),
            Ok(Validation::Invalid)
        );
    }

    /// P15-11: `(G, DevID)` must be the vault's origin owner. Today's mnemonic
    /// recovery re-derives the same pair, which is why it still closes.
    #[test]
    fn a_close_by_another_identity_is_invalid() {
        let f = close_fixture(OwnerAuthority::Origin);
        let vault_id = *f.preimage.dlv_cores()[0].vault_id();
        let state_key = derive::vault_state_key(&vault_id);
        let mut evidence = Evidence {
            objects: f.evidence.objects.clone(),
            trader_leaves: f.evidence.trader_leaves.clone(),
            vault_leaves: f.evidence.vault_leaves.clone(),
            setups: f.evidence.setups.clone(),
            token_policies: f.evidence.token_policies.clone(),
            accepted_claims: f.evidence.accepted_claims.clone(),
        };
        let VaultLeafPre::State(state) = evidence.vault_leaves[&(vault_id, state_key)].clone()
        else {
            panic!("the state leaf")
        };
        evidence.vault_leaves.insert(
            (vault_id, state_key),
            VaultLeafPre::State(VaultStateLeaf {
                owner_device_id: token(0x2F),
                ..state
            }),
        );
        assert_eq!(
            validate(&f.precommit, &f.preimage, &evidence),
            Err(Refusal::Invalid(Invalid::NotTheVaultOwner))
        );
    }

    /// Rebuild a close with one field of the body changed.
    fn with_close<F: FnOnce(&mut u64, &mut u64)>(f: &Fixture, edit: F) -> SettlementPreimage {
        let SettlementBody::Close {
            vault_id,
            parent_root,
            setup_ref,
            owner_authority,
            mut reserve_a,
            mut reserve_b,
            trader_core,
            dlv_core,
            closure,
        } = f.preimage.settlement().clone()
        else {
            panic!("a close fixture")
        };
        edit(&mut reserve_a, &mut reserve_b);
        SettlementPreimage::new(
            SettlementBody::Close {
                vault_id,
                parent_root,
                setup_ref,
                owner_authority,
                reserve_a,
                reserve_b,
                trader_core,
                dlv_core,
                closure,
            },
            f.preimage.trader_core().clone(),
            f.preimage.dlv_cores().to_vec(),
        )
        .unwrap()
    }

    #[test]
    fn a_close_claiming_the_wrong_reserves_is_invalid() {
        let f = close_fixture(OwnerAuthority::Origin);
        let bent = with_close(&f, |a, _| *a -= 1);
        let precommit = rebind(&f, &bent);
        assert_eq!(
            validate(&precommit, &bent, &f.evidence),
            Err(Refusal::Invalid(Invalid::CloseDoesNotRetireExactly))
        );
    }

    /// A close that leaves a reserve behind, or does not retire the vault, is
    /// refused by the exact post-state check.
    #[test]
    fn a_close_that_does_not_retire_the_vault_is_invalid() {
        let f = close_fixture(OwnerAuthority::Origin);
        let vault_id = *f.preimage.dlv_cores()[0].vault_id();
        let state_key = derive::vault_state_key(&vault_id);
        let VaultLeafPre::State(pre_state) =
            f.evidence.vault_leaves[&(vault_id, state_key)].clone()
        else {
            panic!("the state leaf")
        };
        // Retired, but with a unit left in a reserve.
        let sloppy = VaultStateLeaf {
            generation: pre_state.generation + 1,
            reserve_a: 1,
            reserve_b: 0,
            status: VAULT_STATUS_RETIRED,
            ..pre_state.clone()
        };
        let core = &f.preimage.dlv_cores()[0];
        let entries: Vec<CoreEntry> = core
            .entries()
            .iter()
            .map(|e| match e {
                CoreEntry::Mutation { key, pre, path, .. } if *key == state_key => {
                    CoreEntry::Mutation {
                        key: *key,
                        pre: *pre,
                        post: derive::vault_state_leaf_value(&sloppy).unwrap(),
                        path: path.clone(),
                    }
                }
                other => other.clone(),
            })
            .collect();
        let bent_core = DlvCore::new(
            vault_id,
            *core.pre_root(),
            G,
            DEV,
            *core.relationship_base(),
            entries,
        )
        .unwrap();
        let settlement = match f.preimage.settlement().clone() {
            SettlementBody::Close {
                vault_id,
                parent_root,
                setup_ref,
                owner_authority,
                reserve_a,
                reserve_b,
                trader_core,
                closure,
                ..
            } => SettlementBody::Close {
                vault_id,
                parent_root,
                setup_ref,
                owner_authority,
                reserve_a,
                reserve_b,
                trader_core,
                // B°'s reference follows the core it names, so this negative
                // is about the retired state and nothing else.
                dlv_core: derive::dlv_core_digest(&bent_core.encode().unwrap()),
                closure,
            },
            other => other,
        };
        let preimage = SettlementPreimage::new(
            settlement,
            f.preimage.trader_core().clone(),
            vec![bent_core],
        )
        .unwrap();
        let precommit = rebind(&f, &preimage);
        assert_eq!(
            validate(&precommit, &preimage, &f.evidence),
            Err(Refusal::Invalid(Invalid::LeafPostValueMismatch))
        );
    }

    /// R14: a vault's post state is recomputed from the pre state and the
    /// settlement's own terms, and bound to what `V°` states. The root is the
    /// fold's — the same value the verdict used — so a store that keeps it
    /// keeps an authenticated root and not an opinion.
    #[test]
    fn vault_post_states_are_recomputed_and_bound_to_the_stated_values() {
        let f = fixtures::swap_fixture_n(2);
        let posts = vault_post_states(&f.precommit, &f.preimage, &f.evidence).unwrap();
        assert_eq!(posts.len(), f.preimage.dlv_cores().len());
        for post in &posts {
            let core = f
                .preimage
                .dlv_cores()
                .iter()
                .find(|c| *c.vault_id() == post.vault_id)
                .unwrap();
            let pre = f.evidence.vault_state(&post.vault_id).unwrap();
            // The generation advanced by exactly one and the vault stays live.
            assert_eq!(post.state.generation, pre.generation + 1);
            assert_eq!(post.state.status, VAULT_STATUS_ACTIVE);
            // The reserves moved by the hop, in the pool's own direction.
            assert_ne!(
                (post.state.reserve_a, post.state.reserve_b),
                (pre.reserve_a, pre.reserve_b)
            );
            // The root is the fold's, against the pre-root the core states.
            let entries =
                dlv_fold_entries(core, f.precommit.external_commitment(), &f.evidence).unwrap();
            assert_eq!(post.root, fold_core(&entries, core.pre_root()).unwrap());
            assert_ne!(post.root, *core.pre_root(), "the vault moved");
            // The record is its own chain link: where it came from, and at
            // which generation.
            assert_eq!(post.pre_root, *core.pre_root());
            assert_eq!(post.pre_generation, pre.generation);
            assert_eq!(post.state.generation, post.pre_generation + 1);
            // The relationship leaf advanced is this trader's, in the VAULT's
            // tree. It sits at the SAME key as the trader's own relationship
            // leaf — one derivation, `relationship_key(G, DevID, v)` — in a
            // DIFFERENT tree, and the two leaves carry different shapes: the
            // vault's names the trader, the trader's names the vault. A first
            // draft of this test asserted the keys differ, and the values
            // above are what corrected it.
            let (key, leaf) = post.relationship.unwrap();
            assert_eq!(leaf.trader_genesis, *core.trader_genesis());
            assert_eq!(leaf.trader_device_id, *core.trader_device_id());
            assert_eq!(
                key,
                derive::relationship_key(
                    f.precommit.genesis(),
                    f.precommit.device_id(),
                    &post.vault_id
                ),
                "one key derivation, two trees"
            );
            // The two leaves at that key are not interchangeable: the vault's
            // holds the trader's identity, the trader's holds the vault id,
            // and they hash under different tags.
            let in_vault = derive::vault_relationship_leaf_value(&leaf);
            let in_trader = derive::trader_relationship_leaf_value(&TraderRelationshipLeaf {
                vault_id: post.vault_id,
                leaf: leaf.leaf,
            });
            assert_ne!(in_vault, in_trader);
        }
        assert_ne!(posts[0].root, posts[1].root, "two vaults, two roots");
    }

    /// A `V°` that states a post state the arithmetic does not reach is
    /// refused, so nothing unverified can be stored as a vault head.
    #[test]
    fn a_vault_core_stating_another_post_state_yields_no_head() {
        let f = fixtures::swap_fixture_n(1);
        let core = &f.preimage.dlv_cores()[0];
        let state_key = derive::vault_state_key(core.vault_id());
        let mut entries = core.entries().to_vec();
        let i = entries
            .iter()
            .position(|entry| entry.key() == state_key)
            .unwrap();
        if let CoreEntry::Mutation { post, .. } = &mut entries[i] {
            *post = fixtures::token(0x7E);
        }
        let bent = DlvCore::new(
            *core.vault_id(),
            *core.pre_root(),
            *core.trader_genesis(),
            *core.trader_device_id(),
            *core.relationship_base(),
            entries,
        )
        .unwrap();
        let preimage = SettlementPreimage::new(
            f.preimage.settlement().clone(),
            f.preimage.trader_core().clone(),
            vec![bent],
        )
        .unwrap();
        assert_eq!(
            vault_post_states(&f.precommit, &preimage, &f.evidence),
            Err(Refusal::Invalid(Invalid::LeafPostValueMismatch))
        );
    }

    /// R13, stage 10: the post states behind `P.R_realize` are recomputed
    /// from the pre states and the movements the settlement commits — the
    /// debit of `amount_in`, the credit of `exact_out`, the next relationship
    /// leaf — and each is bound to the value `T°` states. A core stating
    /// another post value is refused, never believed.
    #[test]
    fn trader_post_states_are_recomputed_and_bound_to_the_stated_values() {
        let f = fixtures::swap_fixture_n(1);
        let SettlementBody::Swap {
            token_in,
            amount_in,
            token_out,
            exact_out,
            ..
        } = f.preimage.settlement().clone()
        else {
            panic!("a swap fixture")
        };
        let post = trader_post_states(&f.precommit, &f.preimage, &f.evidence).unwrap();
        assert_eq!(post.len(), f.preimage.trader_core().entries().len());
        let in_key = balance_key(f.precommit.genesis(), f.precommit.device_id(), &token_in);
        let out_key = balance_key(f.precommit.genesis(), f.precommit.device_id(), &token_out);
        let TraderLeafPre::Balance(before) = f.evidence.trader_leaf(&in_key).unwrap() else {
            panic!("the fixture holds the token spent")
        };
        let state_at = |key: &D32| post.iter().find(|(k, _)| k == key).unwrap().1.clone();
        assert_eq!(
            state_at(&in_key),
            Some(EconomicLeafState::Balance(EconomicBalanceState {
                policy_commit: token_in,
                amount: before.amount - amount_in,
            }))
        );
        assert_eq!(
            state_at(&out_key),
            Some(EconomicLeafState::Balance(EconomicBalanceState {
                policy_commit: token_out,
                amount: exact_out,
            }))
        );
        let e = *f.precommit.external_commitment();
        for entry in f.preimage.trader_core().entries() {
            if let CoreEntry::Relationship { vault_id, base, .. } = entry {
                assert_eq!(
                    state_at(&entry.key()),
                    Some(EconomicLeafState::Relationship(TraderRelationshipLeaf {
                        vault_id: *vault_id,
                        leaf: derive::relationship_leaf_next(base, &e),
                    }))
                );
            }
        }
        // Every post state's value is the one the core states, so the fold
        // of these states over the pre tree is R_realize.
        for (key, state) in &post {
            let entry = f
                .preimage
                .trader_core()
                .entries()
                .iter()
                .find(|en| en.key() == *key)
                .unwrap();
            if let CoreEntry::Mutation { post, .. } = entry {
                assert_eq!(
                    state.as_ref().map(|s| s.leaf_value().unwrap()),
                    absent_or(post)
                );
            }
        }

        // A T° stating another post value for the token spent.
        let core = f.preimage.trader_core();
        let mut entries = core.entries().to_vec();
        let i = entries.iter().position(|en| en.key() == in_key).unwrap();
        if let CoreEntry::Mutation { post, .. } = &mut entries[i] {
            *post = fixtures::token(0x77);
        }
        let bent = TraderCore::new(
            *core.genesis(),
            *core.device_id(),
            core.position(),
            *core.pre_root(),
            entries,
        )
        .unwrap();
        let settlement = match f.preimage.settlement().clone() {
            SettlementBody::Swap {
                token_in,
                amount_in,
                token_out,
                exact_out,
                hops,
                dlv_cores,
                closure,
                ..
            } => SettlementBody::Swap {
                token_in,
                amount_in,
                token_out,
                exact_out,
                hops,
                trader_core: derive::trader_core_digest(&bent.encode().unwrap()),
                dlv_cores,
                closure,
            },
            other => other,
        };
        let preimage =
            SettlementPreimage::new(settlement, bent, f.preimage.dlv_cores().to_vec()).unwrap();
        let precommit = rebind(&f, &preimage);
        assert_eq!(
            trader_post_states(&precommit, &preimage, &f.evidence),
            Err(Refusal::Invalid(Invalid::LeafPostValueMismatch))
        );
    }

    /// A vault whose release policy is not the close family does not close.
    /// The family rule lives in the decoder, so such a policy has no decoding
    /// at all — which is why the refusal names the class that failed.
    #[test]
    fn a_close_against_another_release_policy_is_invalid() {
        let bogus = {
            let mut bytes = ReleasePolicy::beta_owner_local_full_close().encode();
            let n = bytes.len();
            bytes[n - 4..n - 2].copy_from_slice(&[0x00, 0x09]);
            bytes
        };
        let f = close_fixture_with(OwnerAuthority::Origin, DEV, Some(bogus));
        assert_eq!(
            validate(&f.precommit, &f.preimage, &f.evidence),
            Err(Refusal::Invalid(Invalid::PolicyDoesNotDecode {
                class: crate::ccb::class::RELEASE_POLICY
            }))
        );
    }

    /// The close pays out; no constant-product arithmetic is ever applied to
    /// it. Proven by the amounts: the trader receives the reserves EXACTLY,
    /// which the curve would never produce.
    #[test]
    fn a_close_pays_the_reserves_exactly_and_never_prices_them() {
        let f = close_fixture(OwnerAuthority::Origin);
        assert_eq!(validate(&f.precommit, &f.preimage, &f.evidence), Ok(()));
        let (token_a, token_b) = pair(0);
        let a_key = balance_key(&G, &DEV, &token_a);
        let b_key = balance_key(&G, &DEV, &token_b);
        for (key, token, amount) in [(a_key, token_a, RESERVE_A), (b_key, token_b, RESERVE_B)] {
            let entry = f
                .preimage
                .trader_core()
                .entries()
                .iter()
                .find(|e| e.key() == key)
                .expect("a credit per reserve");
            let CoreEntry::Mutation { post, .. } = entry else {
                panic!("a credit is a mutation")
            };
            assert_eq!(*post, balance_leaf_value(token, amount));
            // The curve on the same inputs gives something else entirely.
            let priced =
                constant_product_output_classified(amount, RESERVE_A, RESERVE_B, FEE_BPS).unwrap();
            assert_ne!(priced, amount);
        }
    }

    /// A vault that has already retired is terminal: no swap touches it.
    /// Without this the operation would be caught only by the post-state
    /// comparison, which is a different rule entirely.
    #[test]
    fn a_swap_against_a_retired_vault_is_invalid() {
        let f = swap_fixture();
        let vault_id = *f.preimage.dlv_cores()[0].vault_id();
        let state_key = derive::vault_state_key(&vault_id);
        let mut evidence = Evidence {
            objects: f.evidence.objects.clone(),
            trader_leaves: f.evidence.trader_leaves.clone(),
            vault_leaves: f.evidence.vault_leaves.clone(),
            setups: f.evidence.setups.clone(),
            token_policies: f.evidence.token_policies.clone(),
            accepted_claims: f.evidence.accepted_claims.clone(),
        };
        let VaultLeafPre::State(state) = evidence.vault_leaves[&(vault_id, state_key)].clone()
        else {
            panic!("the state leaf")
        };
        evidence.vault_leaves.insert(
            (vault_id, state_key),
            VaultLeafPre::State(VaultStateLeaf {
                status: VAULT_STATUS_RETIRED,
                ..state
            }),
        );
        assert_eq!(
            validate(&f.precommit, &f.preimage, &evidence),
            Err(Refusal::Invalid(Invalid::VaultIsNotActive))
        );
    }

    /// A close of SOMEONE ELSE'S vault: the vault id IS that owner's own
    /// derivation, so the state is entirely self-consistent and the identity
    /// rule is the only thing that can refuse it.
    #[test]
    fn a_close_of_another_owners_vault_is_invalid_on_identity_alone() {
        let f = close_fixture(OwnerAuthority::Origin);
        let vault_id = *f.preimage.dlv_cores()[0].vault_id();
        let state_key = derive::vault_state_key(&vault_id);
        let mut evidence = Evidence {
            objects: f.evidence.objects.clone(),
            trader_leaves: f.evidence.trader_leaves.clone(),
            vault_leaves: f.evidence.vault_leaves.clone(),
            setups: f.evidence.setups.clone(),
            token_policies: f.evidence.token_policies.clone(),
            accepted_claims: f.evidence.accepted_claims.clone(),
        };
        let VaultLeafPre::State(state) = evidence.vault_leaves[&(vault_id, state_key)].clone()
        else {
            panic!("the state leaf")
        };
        // The owner whose derivation lands on exactly this vault id — found by
        // construction, not by search: the id is a function of the owner, so
        // re-deriving it for the other owner is what makes the state honest.
        let other_owner = token(0x2F);
        let owned_elsewhere = VaultStateLeaf {
            owner_device_id: other_owner,
            create_position: state.create_position,
            ..state
        };
        let foreign_id = derive::vault_id(
            &owned_elsewhere.owner_genesis,
            &owned_elsewhere.owner_device_id,
            owned_elsewhere.create_position,
        );
        evidence.vault_leaves.insert(
            (foreign_id, derive::vault_state_key(&foreign_id)),
            VaultLeafPre::State(owned_elsewhere.clone()),
        );
        // Point the whole operation at that vault: same shape, other owner.
        let repointed = close_fixture_for(OwnerAuthority::Origin, other_owner);
        assert_eq!(
            validate(
                &repointed.precommit,
                &repointed.preimage,
                &repointed.evidence
            ),
            Err(Refusal::Invalid(Invalid::NotTheVaultOwner))
        );
    }

    /// A state lifted from another vault: the owner matches the closer, but
    /// the id it is stored under is not that owner's derivation.
    #[test]
    fn a_vault_state_that_does_not_derive_its_own_id_is_invalid() {
        let f = close_fixture(OwnerAuthority::Origin);
        let vault_id = *f.preimage.dlv_cores()[0].vault_id();
        let state_key = derive::vault_state_key(&vault_id);
        let mut evidence = Evidence {
            objects: f.evidence.objects.clone(),
            trader_leaves: f.evidence.trader_leaves.clone(),
            vault_leaves: f.evidence.vault_leaves.clone(),
            setups: f.evidence.setups.clone(),
            token_policies: f.evidence.token_policies.clone(),
            accepted_claims: f.evidence.accepted_claims.clone(),
        };
        let VaultLeafPre::State(state) = evidence.vault_leaves[&(vault_id, state_key)].clone()
        else {
            panic!("the state leaf")
        };
        evidence.vault_leaves.insert(
            (vault_id, state_key),
            VaultLeafPre::State(VaultStateLeaf {
                create_position: state.create_position + 99,
                ..state
            }),
        );
        assert_eq!(
            validate(&f.precommit, &f.preimage, &evidence),
            Err(Refusal::Invalid(Invalid::VaultIdIsNotTheOwnersDerivation))
        );
    }

    // ── the four invariants the owner's review of #908 required ──────────

    /// A: `Invalid ∧ Unavailable = Invalid`. A Retired vault is already enough
    /// to prove invalidity, so a missing policy must NOT turn the answer into
    /// Unavailable. Evidence a verifier happens not to hold cannot mask an
    /// invalidity it can already prove.
    #[test]
    fn a_provable_invalidity_is_not_masked_by_missing_evidence() {
        let f = swap_fixture();
        let vault_id = *f.preimage.dlv_cores()[0].vault_id();
        let state_key = derive::vault_state_key(&vault_id);
        let (market, _, _) = policies(0);
        let mut evidence = Evidence {
            objects: f.evidence.objects.clone(),
            trader_leaves: f.evidence.trader_leaves.clone(),
            vault_leaves: f.evidence.vault_leaves.clone(),
            setups: f.evidence.setups.clone(),
            token_policies: f.evidence.token_policies.clone(),
            accepted_claims: f.evidence.accepted_claims.clone(),
        };
        let VaultLeafPre::State(state) = evidence.vault_leaves[&(vault_id, state_key)].clone()
        else {
            panic!("the state leaf")
        };
        evidence.vault_leaves.insert(
            (vault_id, state_key),
            VaultLeafPre::State(VaultStateLeaf {
                status: VAULT_STATUS_RETIRED,
                ..state
            }),
        );
        // ... and the market policy is not held at all.
        evidence.objects.remove(&policy_addr(
            crate::ccb::class::MARKET_POLICY,
            &market.encode(),
        ));
        assert_eq!(
            route_validation(&f.precommit, &f.preimage, &evidence),
            Ok(Validation::Invalid)
        );
        assert_eq!(
            validate(&f.precommit, &f.preimage, &evidence),
            Err(Refusal::Invalid(Invalid::VaultIsNotActive))
        );
    }

    /// A, across hops: missing evidence on hop 0 must not hide an invalidity
    /// on hop 1.
    #[test]
    fn an_invalidity_on_a_later_hop_survives_a_gap_on_an_earlier_one() {
        let f = swap_fixture_n(2);
        let SettlementBody::Swap { hops, .. } = f.preimage.settlement().clone() else {
            panic!("a swap fixture")
        };
        let (first, second) = (hops[0].vault_id, hops[1].vault_id);
        let mut evidence = Evidence {
            objects: f.evidence.objects.clone(),
            trader_leaves: f.evidence.trader_leaves.clone(),
            vault_leaves: f.evidence.vault_leaves.clone(),
            setups: f.evidence.setups.clone(),
            token_policies: f.evidence.token_policies.clone(),
            accepted_claims: f.evidence.accepted_claims.clone(),
        };
        // Hop 0's state is simply not held.
        evidence
            .vault_leaves
            .remove(&(first, derive::vault_state_key(&first)));
        // Hop 1's vault is Retired — provable, and it must win.
        let second_key = derive::vault_state_key(&second);
        let VaultLeafPre::State(state) = evidence.vault_leaves[&(second, second_key)].clone()
        else {
            panic!("the state leaf")
        };
        evidence.vault_leaves.insert(
            (second, second_key),
            VaultLeafPre::State(VaultStateLeaf {
                status: VAULT_STATUS_RETIRED,
                ..state
            }),
        );
        assert_eq!(
            route_validation(&f.precommit, &f.preimage, &evidence),
            Ok(Validation::Invalid)
        );
    }

    /// B: `B°`'s core references are binding, not decorative. Each one is
    /// checked against the core `P(E)` actually carries.
    #[test]
    fn a_settlement_body_naming_another_core_is_invalid() {
        let f = swap_fixture();
        // The vault id in place of the core digest — exactly the shape the
        // fixture used before this was checked at all.
        let bent = match f.preimage.settlement().clone() {
            SettlementBody::Swap {
                token_in,
                amount_in,
                token_out,
                exact_out,
                hops,
                trader_core,
                closure,
                ..
            } => SettlementBody::Swap {
                token_in,
                amount_in,
                token_out,
                exact_out,
                hops,
                trader_core,
                dlv_cores: vec![*f.preimage.dlv_cores()[0].vault_id()],
                closure,
            },
            other => other,
        };
        let preimage = SettlementPreimage::new(
            bent,
            f.preimage.trader_core().clone(),
            f.preimage.dlv_cores().to_vec(),
        )
        .unwrap();
        let precommit = rebind(&f, &preimage);
        assert_eq!(
            validate(&precommit, &preimage, &f.evidence),
            Err(Refusal::Invalid(Invalid::SettlementCoreReferenceMismatch {
                field: "B°.dlv_cores"
            }))
        );
    }

    /// B, the trader side and the close side.
    #[test]
    fn a_settlement_body_naming_another_trader_core_or_parent_is_invalid() {
        let f = swap_fixture();
        let bent = match f.preimage.settlement().clone() {
            SettlementBody::Swap {
                token_in,
                amount_in,
                token_out,
                exact_out,
                hops,
                dlv_cores,
                closure,
                ..
            } => SettlementBody::Swap {
                token_in,
                amount_in,
                token_out,
                exact_out,
                hops,
                trader_core: token(0x0E),
                dlv_cores,
                closure,
            },
            other => other,
        };
        let preimage = SettlementPreimage::new(
            bent,
            f.preimage.trader_core().clone(),
            f.preimage.dlv_cores().to_vec(),
        )
        .unwrap();
        let precommit = rebind(&f, &preimage);
        assert_eq!(
            validate(&precommit, &preimage, &f.evidence),
            Err(Refusal::Invalid(Invalid::SettlementCoreReferenceMismatch {
                field: "B°.trader_core"
            }))
        );

        // A close whose body names a parent the leg does not.
        let c = close_fixture(OwnerAuthority::Origin);
        let bent = match c.preimage.settlement().clone() {
            SettlementBody::Close {
                vault_id,
                setup_ref,
                owner_authority,
                reserve_a,
                reserve_b,
                trader_core,
                dlv_core,
                closure,
                ..
            } => SettlementBody::Close {
                vault_id,
                parent_root: token(0x0D),
                setup_ref,
                owner_authority,
                reserve_a,
                reserve_b,
                trader_core,
                dlv_core,
                closure,
            },
            other => other,
        };
        let preimage = SettlementPreimage::new(
            bent,
            c.preimage.trader_core().clone(),
            c.preimage.dlv_cores().to_vec(),
        )
        .unwrap();
        let precommit = rebind(&c, &preimage);
        assert_eq!(
            validate(&precommit, &preimage, &c.evidence),
            Err(Refusal::Invalid(Invalid::SettlementCoreReferenceMismatch {
                field: "B°.parent_root/setup_ref"
            }))
        );
    }

    /// C: bytes supplied under an address prove nothing until they
    /// authenticate to it. Garbage under a requested key leaves the object
    /// UNSUPPLIED — it can never make a valid operation permanently Invalid
    /// (note 9).
    #[test]
    fn bytes_that_do_not_authenticate_to_their_address_are_unavailable_not_invalid() {
        let f = swap_fixture();
        let (market, _, _) = policies(0);
        let addr = policy_addr(crate::ccb::class::MARKET_POLICY, &market.encode());
        let mut evidence = Evidence {
            objects: f.evidence.objects.clone(),
            trader_leaves: f.evidence.trader_leaves.clone(),
            vault_leaves: f.evidence.vault_leaves.clone(),
            setups: f.evidence.setups.clone(),
            token_policies: f.evidence.token_policies.clone(),
            accepted_claims: f.evidence.accepted_claims.clone(),
        };
        // Garbage, under the address of a policy that really exists.
        evidence
            .objects
            .insert(addr, b"not a policy at all".to_vec());
        assert_eq!(
            validate(&f.precommit, &f.preimage, &evidence),
            Err(Refusal::Incomplete(Missing::NonVerifyingObject { addr }))
        );
        assert_eq!(
            route_validation(&f.precommit, &f.preimage, &evidence),
            Err(Missing::NonVerifyingObject { addr })
        );

        // Well-formed bytes of the RIGHT class, under the WRONG address, are
        // the same: they are not the object that was asked for.
        let (other_market, _, _) = policies(1);
        evidence.objects.insert(addr, other_market.encode());
        assert_eq!(
            route_validation(&f.precommit, &f.preimage, &evidence),
            Err(Missing::NonVerifyingObject { addr })
        );
        // And supplying the real object validates, so the refusal really was
        // about the evidence and not about the operation.
        evidence.objects.insert(addr, market.encode());
        assert_eq!(
            route_validation(&f.precommit, &f.preimage, &evidence),
            Ok(Validation::Valid)
        );
    }

    /// D: a `V°` marked for trader A may not advance trader B's relationship.
    /// The entry derives its own key from its own identity fields, so without
    /// this the core could write an A-valued leaf under B's key.
    #[test]
    fn a_vault_core_may_not_advance_another_traders_relationship() {
        let f = swap_fixture();
        let core = &f.preimage.dlv_cores()[0];
        let other_trader = token(0x3B);
        let entries: Vec<CoreEntry> = core
            .entries()
            .iter()
            .map(|e| match e {
                CoreEntry::Relationship {
                    vault_id,
                    base,
                    path,
                    ..
                } => CoreEntry::Relationship {
                    // The core's marker still says (G, DEV); the entry says
                    // another device, and so addresses another key.
                    genesis: G,
                    device_id: other_trader,
                    vault_id: *vault_id,
                    base: *base,
                    path: path.clone(),
                },
                other => other.clone(),
            })
            .collect();
        let bent_core = DlvCore::new(
            *core.vault_id(),
            *core.pre_root(),
            G,
            DEV,
            *core.relationship_base(),
            entries,
        )
        .unwrap();
        let settlement = match f.preimage.settlement().clone() {
            SettlementBody::Swap {
                token_in,
                amount_in,
                token_out,
                exact_out,
                hops,
                trader_core,
                closure,
                ..
            } => SettlementBody::Swap {
                token_in,
                amount_in,
                token_out,
                exact_out,
                hops,
                trader_core,
                dlv_cores: vec![derive::dlv_core_digest(&bent_core.encode().unwrap())],
                closure,
            },
            other => other,
        };
        let preimage = SettlementPreimage::new(
            settlement,
            f.preimage.trader_core().clone(),
            vec![bent_core],
        )
        .unwrap();
        let precommit = rebind(&f, &preimage);
        assert_eq!(
            validate(&precommit, &preimage, &f.evidence),
            Err(Refusal::Invalid(Invalid::RelationshipIdentityMismatch))
        );
    }

    /// D, the leaf side: even with a matching entry, the leaf being advanced
    /// must be this trader's own.
    #[test]
    fn a_relationship_leaf_of_another_trader_is_invalid() {
        let f = swap_fixture();
        let core = &f.preimage.dlv_cores()[0];
        let vault_id = *core.vault_id();
        let rel_key = derive::relationship_key(&G, &DEV, &vault_id);
        let mut evidence = Evidence {
            objects: f.evidence.objects.clone(),
            trader_leaves: f.evidence.trader_leaves.clone(),
            vault_leaves: f.evidence.vault_leaves.clone(),
            setups: f.evidence.setups.clone(),
            token_policies: f.evidence.token_policies.clone(),
            accepted_claims: f.evidence.accepted_claims.clone(),
        };
        let VaultLeafPre::Relationship(leaf) = evidence.vault_leaves[&(vault_id, rel_key)].clone()
        else {
            panic!("the relationship leaf")
        };
        evidence.vault_leaves.insert(
            (vault_id, rel_key),
            VaultLeafPre::Relationship(VaultRelationshipLeaf {
                trader_device_id: token(0x3C),
                ..leaf
            }),
        );
        assert_eq!(
            validate(&f.precommit, &f.preimage, &evidence),
            Err(Refusal::Invalid(Invalid::RelationshipIdentityMismatch))
        );
    }

    // ── SetupValid (SoFi §16, §20.1, Amendment S9) ─────────────────────────

    /// A one-hop swap whose leg carries `body`, signed under the trader's key.
    fn with_setup(body: crate::sofi::wire::SofiSetupBody) -> Fixture {
        swap_fixture_with_setups(
            1,
            &|j| {
                assert_eq!(j, 0, "a one-hop swap has one leg");
                body.clone()
            },
            PreEClosureIndex::new(Vec::new()).unwrap(),
        )
    }

    fn setup_at(
        genesis: D32,
        device: D32,
        vault: D32,
        claim_ref: D32,
    ) -> crate::sofi::wire::SofiSetupBody {
        crate::sofi::wire::SofiSetupBody::new(
            genesis,
            device,
            SETUP_POS,
            vault,
            claim_ref,
            token(0xB0),
            SIG_ALG,
            &trader_keys().0,
        )
        .unwrap()
    }

    #[test]
    fn a_setup_not_held_or_not_its_reference_is_missing() {
        let f = swap_fixture();
        let rho = f.precommit.legs()[0].setup_ref;
        let mut evidence = f.evidence.clone();
        evidence.setups.remove(&rho);
        assert_eq!(
            validate(&f.precommit, &f.preimage, &evidence),
            Err(Refusal::Incomplete(Missing::Setup { setup_ref: rho }))
        );
        evidence.setups.insert(rho, b"not a setup".to_vec());
        assert_eq!(
            validate(&f.precommit, &f.preimage, &evidence),
            Err(Refusal::Incomplete(Missing::NonVerifyingObject {
                addr: rho
            }))
        );
        // Another setup's envelope under this reference.
        evidence
            .setups
            .insert(rho, setup_envelope_for(vault_id_of(1)));
        assert_eq!(
            validate(&f.precommit, &f.preimage, &evidence),
            Err(Refusal::Incomplete(Missing::NonVerifyingObject {
                addr: rho
            }))
        );
    }

    #[test]
    fn a_setup_of_another_trader_or_vault_is_invalid() {
        let f = with_setup(setup_at(token(0x33), DEV, vault_id_of(0), SETUP_CLAIM_REF));
        assert_eq!(
            validate(&f.precommit, &f.preimage, &f.evidence),
            Err(Refusal::Invalid(Invalid::SetupNotThisTrader))
        );
        let f = with_setup(setup_at(G, DEV, vault_id_of(1), SETUP_CLAIM_REF));
        assert_eq!(
            validate(&f.precommit, &f.preimage, &f.evidence),
            Err(Refusal::Invalid(Invalid::SetupNotThisVault))
        );
    }

    /// A setup is the trader's when its body commits the key `P` commits.
    /// Two different things can go wrong, and they get different answers:
    ///
    /// - The trader's setup body under a signature its committed key did not
    ///   make is not a setup at all — signing is deterministic, so one body
    ///   has exactly one valid envelope, and anyone can publish a copy with a
    ///   junk signature under the same `ρ`. It is not established, never
    ///   Invalid: a copy cannot condemn the trader's route.
    /// - A setup that verifies under its own key, and that key is not the one
    ///   `P` commits, is this `P`'s setup signed by someone else: Invalid.
    #[test]
    fn a_setup_is_the_traders_only_under_the_key_p_commits() {
        let f = swap_fixture();
        let rho = f.precommit.legs()[0].setup_ref;
        let (other_pk, other_sk) = crate::crypto::sphincs::generate_sphincs_keypair().unwrap();
        assert_ne!(other_pk, trader_keys().0);
        let body = setup_body_for(vault_id_of(0));
        let copy = crate::sofi::publication::Publication::Setup {
            body: &body,
            signature: &crate::crypto::sphincs::sphincs_sign(
                &other_sk,
                &derive::setup_signing_digest(&body),
            )
            .unwrap(),
        }
        .object_bytes()
        .unwrap();
        let mut evidence = f.evidence.clone();
        evidence.setups.insert(rho, copy);
        assert_eq!(
            validate(&f.precommit, &f.preimage, &evidence),
            Err(Refusal::Incomplete(Missing::NonVerifyingObject {
                addr: rho
            }))
        );

        let theirs = crate::sofi::wire::SofiSetupBody::new(
            G,
            DEV,
            SETUP_POS,
            vault_id_of(0),
            SETUP_CLAIM_REF,
            token(0xB0),
            SIG_ALG,
            &other_pk,
        )
        .unwrap();
        let f = with_setup(theirs.clone());
        let rho = f.precommit.legs()[0].setup_ref;
        let signed_by_them = crate::sofi::publication::Publication::Setup {
            body: &theirs,
            signature: &crate::crypto::sphincs::sphincs_sign(
                &other_sk,
                &derive::setup_signing_digest(&theirs),
            )
            .unwrap(),
        }
        .object_bytes()
        .unwrap();
        let mut evidence = f.evidence.clone();
        evidence.setups.insert(rho, signed_by_them);
        assert_eq!(
            validate(&f.precommit, &f.preimage, &evidence),
            Err(Refusal::Invalid(Invalid::SetupSignature(
                crate::sofi::signature::SignatureError::NotTheExpectedSigner { what: "SofiSetup" }
            )))
        );
    }

    /// Amendment S9: the setup names the claim the trader's lineage accepted
    /// at its position, and no other.
    #[test]
    fn a_setup_naming_another_claim_than_the_accepted_one_is_invalid() {
        let f = with_setup(setup_at(G, DEV, vault_id_of(0), token(0xA1)));
        assert_eq!(
            validate(&f.precommit, &f.preimage, &f.evidence),
            Err(Refusal::Invalid(
                Invalid::SetupClaimRefIsNotTheAcceptedClaim
            ))
        );
        assert_eq!(
            route_validation(&f.precommit, &f.preimage, &f.evidence),
            Ok(Validation::Invalid)
        );
    }

    /// Without the claim the verifier accepted at the setup's position, the
    /// setup is not decided yet; an accepted claim of another trader supplies
    /// nothing.
    #[test]
    fn a_setup_whose_accepted_claim_is_not_in_hand_is_missing() {
        let f = swap_fixture();
        let missing = Err(Refusal::Incomplete(Missing::AcceptedClaim {
            economic_position: SETUP_POS,
        }));
        let mut evidence = f.evidence.clone();
        evidence.accepted_claims.clear();
        assert_eq!(validate(&f.precommit, &f.preimage, &evidence), missing);
        let foreign = crate::economic::lineage::AcceptedClaim::rehydrate_from_admitted_store(
            token(0x33),
            DEV,
            crate::economic::lineage::AdmittedEconomicPosition::SingleRoot {
                economic_position: SETUP_POS,
                economic_root: token(0x9A),
                claim_ref: SETUP_CLAIM_REF,
            },
        )
        .unwrap();
        evidence.accepted_claims.insert(SETUP_POS, foreign);
        assert_eq!(validate(&f.precommit, &f.preimage, &evidence), missing);
    }

    // ── The transferable check on every leg (SoFi §49, MR-SOFI-0311) ────────

    #[test]
    fn a_market_tokens_policy_not_in_hand_is_missing() {
        let f = swap_fixture();
        let (token_a, _) = pair(0);
        let mut evidence = f.evidence.clone();
        evidence.token_policies.remove(&token_a);
        assert_eq!(
            validate(&f.precommit, &f.preimage, &evidence),
            Err(Refusal::Incomplete(Missing::TokenPolicy {
                commit: token_a
            }))
        );
        // Another token's policy under this commit is not this token's.
        let (other, other_bytes) = tokens()[2].clone();
        assert_ne!(other, token_a);
        evidence.token_policies.insert(token_a, other_bytes);
        assert_eq!(
            validate(&f.precommit, &f.preimage, &evidence),
            Err(Refusal::Incomplete(Missing::NonVerifyingObject {
                addr: token_a
            }))
        );
    }

    /// Both tokens of a vault must permit transfer, whichever side the
    /// trader spends.
    #[test]
    fn a_token_whose_policy_forbids_transfer_cannot_be_a_market_leg() {
        let locked = committed(token_policy_bytes_with(9, 0));
        let mut route = vec![tokens()[0].clone(), locked.clone()];
        route.sort();
        let f = swap_fixture_over(
            &route,
            &|j| setup_body_for(vault_id_of(j)),
            PreEClosureIndex::new(Vec::new()).unwrap(),
        );
        assert_eq!(
            validate(&f.precommit, &f.preimage, &f.evidence),
            Err(Refusal::Invalid(Invalid::TokenNotTransferable {
                token: locked.0
            }))
        );
    }

    /// Authenticated policy bytes that do not parse make the token no market
    /// leg: the commit is the token's identity, and its policy is not a
    /// policy.
    #[test]
    fn a_token_whose_committed_policy_does_not_parse_cannot_be_a_market_leg() {
        let broken = committed(prost::Message::encode_to_vec(
            &crate::types::proto::TokenPolicyV3 {
                policy_bytes: b"not a policy blob".to_vec(),
            },
        ));
        let mut route = vec![tokens()[0].clone(), broken.clone()];
        route.sort();
        let f = swap_fixture_over(
            &route,
            &|j| setup_body_for(vault_id_of(j)),
            PreEClosureIndex::new(Vec::new()).unwrap(),
        );
        assert_eq!(
            validate(&f.precommit, &f.preimage, &f.evidence),
            Err(Refusal::Invalid(Invalid::TokenPolicyDoesNotParse {
                token: broken.0
            }))
        );
    }

    /// The token between two hops moves inside the vaults and never touches
    /// the trader's balances, and it is checked all the same.
    #[test]
    fn an_intermediate_token_must_permit_transfer_too() {
        // A non-transferable token whose commit sorts strictly between two
        // fixture tokens, so an ascending two-hop route passes through it.
        let (lower, locked, upper) = (9u8..=u8::MAX)
            .find_map(|i| {
                let locked = committed(token_policy_bytes_with(i, 0));
                let lower = tokens().iter().rev().find(|t| t.0 < locked.0)?.clone();
                let upper = tokens().iter().find(|t| t.0 > locked.0)?.clone();
                Some((lower, locked, upper))
            })
            .expect("a locked token between two fixture tokens");
        let f = swap_fixture_over(
            &[lower, locked.clone(), upper],
            &|j| setup_body_for(vault_id_of(j)),
            PreEClosureIndex::new(Vec::new()).unwrap(),
        );
        assert_eq!(
            validate(&f.precommit, &f.preimage, &f.evidence),
            Err(Refusal::Invalid(Invalid::TokenNotTransferable {
                token: locked.0
            }))
        );
    }

    /// ERA and dBTC are pre-rooted: no policy bytes are consulted for them.
    #[test]
    fn a_builtin_token_needs_no_policy_bytes() {
        let era = crate::core::token::token_state_manager::era_policy_commit();
        let mut route = vec![(era, Vec::new()), tokens()[0].clone()];
        route.sort();
        let f = swap_fixture_over(
            &route,
            &|j| setup_body_for(vault_id_of(j)),
            PreEClosureIndex::new(Vec::new()).unwrap(),
        );
        assert!(!f.evidence.token_policies.contains_key(&era));
        assert_eq!(validate(&f.precommit, &f.preimage, &f.evidence), Ok(()));
    }
}
