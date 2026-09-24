// SPDX-License-Identifier: Apache-2.0

//! Where a resolved SoFi position joins the validated economic lineage, and
//! where a vault's genesis becomes acceptable.
//!
//! `advance_resolved` is the ONLY new constructor of a
//! [`ValidatedEconomicRoot`] at a SoFi position (P15-10). Everything it needs
//! is either recomputed here or already validated: nothing is read out of the
//! root register and believed, because the register records what a member was
//! told, not what a verifier established.
//!
//! ## Which root the position installs
//!
//! | Resolution | Root |
//! |---|---|
//! | Realized | `P.realize_root` |
//! | Void | the predecessor's root — the lineage continues where it was |
//! | Invalid | none, ever: the lineage is terminal at `p` |
//! | Pending | none yet |
//!
//! Void installing the previous root IS "SofiVoid has zero mutations": the
//! position exists, it is terminal, and it moved nothing.

use crate::economic::lineage::ValidatedEconomicRoot;
use crate::sofi::validation::{trader_balance_changes, trader_credits, Evidence, TraderBalanceChange};
use crate::sofi::wire::SettlementPreimage;
use crate::types::device_state::DeviceState;

use super::derive;
use super::resolution::Resolution;
use super::wire::{
    next_position, ParentClaimRef, SofiWireError, TraderFulfillmentBody, TraderPrecommitBody,
    VaultGenesisPreimage, VaultStateLeaf,
};

type D32 = [u8; 32];

/// Why a resolved position does not advance the lineage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdvanceError {
    /// `q` is not `p + 1`, or not the successor of the validated predecessor.
    PositionIsNotSuccessor {
        previous: u64,
        precommit: u64,
        fulfillment: u64,
    },
    /// The predecessor's root is not what `P` was built on (P15-2).
    PreRootIsNotThePredecessor { previous: D32, void_root: D32 },
    /// The claim registered at `K_root(p)` is not the one `P` names.
    ParentClaimMismatch,
    /// The fulfillment installed a different `C_q` than `(P, F)` derive.
    ResolutionClaimMismatch { registered: D32, derived: D32 },
    /// The position resolved Invalid: the lineage is terminal here, and no
    /// root follows it.
    LineageIsTerminal,
    /// A realized position was handed no receipt, so the tokens it credits
    /// could not be checked against the receiver's adoptions.
    RealizedWithoutReceipt,
    /// The credits of a realized position could not be derived from the
    /// evidence the verdict was reached on.
    CreditsNotDerivable,
    /// A realized position credits a token this device has not adopted.
    TokenNotAdopted { policy_commit: D32 },
    /// The balances a realized position moves could not be derived from the
    /// evidence the verdict was reached on.
    BalancesNotDerivable,
    /// The receipt describes a different operation from the one being
    /// installed: its settlement does not recompute this `P`'s `E`.
    ReceiptIsNotThisOperation { expected: D32, derived: D32 },
    /// A counter has no successor.
    Counter(SofiWireError),
}

impl core::fmt::Display for AdvanceError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::PositionIsNotSuccessor {
                previous,
                precommit,
                fulfillment,
            } => write!(
                f,
                "a resolved position advances p + 1 only: previous {previous}, \
                 P at {precommit}, F at {fulfillment}"
            ),
            Self::PreRootIsNotThePredecessor { .. } => {
                write!(f, "P was not built on the validated predecessor's root")
            }
            Self::ParentClaimMismatch => {
                write!(f, "the claim at K_root(p) is not the one P names")
            }
            Self::ResolutionClaimMismatch { .. } => write!(
                f,
                "the registered C_q is not the one (P, F) derive — a claim is \
                 recomputed, never believed"
            ),
            Self::LineageIsTerminal => {
                write!(f, "the position resolved Invalid: no root follows it")
            }
            Self::RealizedWithoutReceipt => write!(
                f,
                "a realized position was handed no receipt: its credits cannot be checked"
            ),
            Self::CreditsNotDerivable => write!(
                f,
                "the credits of this realized position are not derivable from its evidence"
            ),
            Self::BalancesNotDerivable => write!(
                f,
                "the balances this realized position moves are not derivable from its evidence"
            ),
            Self::TokenNotAdopted { policy_commit } => write!(
                f,
                "advance: refusing to credit token {} — this device has not adopted its \
                 policy; adoption (ADD TOKEN) must precede receipt, and a settlement that \
                 roots the token on the receiver's behalf does not satisfy it",
                crate::types::identifiers::encode_crockford(policy_commit)
            ),
            Self::ReceiptIsNotThisOperation { expected, derived } => write!(
                f,
                "the receipt is for another operation: E {} was expected, its settlement \
                 recomputes {}",
                crate::types::identifiers::encode_crockford(expected),
                crate::types::identifiers::encode_crockford(derived)
            ),
            Self::Counter(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for AdvanceError {}

/// What a verifier has established about the claim registered at `p` and `q`.
///
/// Both are EXACT registered values it read for itself. They are inputs to be
/// checked, never authorities to be trusted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegisteredClaims {
    /// The exact claim reference registered at `K_root(p)`, in the form `P`
    /// names it.
    pub parent: ParentClaimRef,
    /// The `C_q` digest the fulfillment installed at `K_root(q)`.
    pub conditional: D32,
}

/// What a REALIZED resolution must present beyond its claim: the settlement
/// whose credits are about to land, the evidence its verdict was reached on,
/// and the receiving device's own pre-state.
///
/// A `Void` needs none of it, because a void moves nothing. A `Realized`
/// cannot be advanced without one — which is the point. The credits are
/// DERIVED here from the preimage and the evidence, never supplied by the
/// caller, so no producer can present a short list and no producer can skip
/// the check by omitting the argument.
pub struct RealizedReceipt<'a> {
    pub preimage: &'a SettlementPreimage,
    pub evidence: &'a Evidence,
    /// `S_pre`: the state this advance is about to succeed. Its adoptions are
    /// the ones that count, because adoption must PRECEDE receipt.
    pub receiver: &'a DeviceState,
}

/// THE ADOPTION INVARIANT, on the resolved SoFi seam:
///
/// ```text
/// SoFiRealized(T°)  =>  for every token T credited by T°, Adopted(S_pre, T)
/// ```
///
/// This mirrors the gate `DeviceState::advance` applies to ordinary credits.
/// The resolved SoFi path does not pass through `advance` — it recomputes
/// `trader_post_states`, recomputes the economic root and admits the position
/// directly — so without this the gate was simply absent on that path, and a
/// realized route could land a token the receiver never adopted.
///
/// **Nobody adopts on the receiver's behalf.** A token's policy is anchored
/// to ITS CREATOR's chain, which is a different anchor from the DLV policy's
/// owner and usually a different party, so a vault's market policy naming a
/// token establishes nothing about the receiver having adopted it. The
/// adoption leaf lives in the receiver's own state and gets there by its own
/// `AddToken`, before any value under that policy arrives — which is what
/// keeps receipt verifiable offline.
///
/// Only CREDITS are gated. A debit is the trader spending what it already
/// holds, and the multi-hop intermediate is never credited to the trader at
/// all (see [`trader_credits`]), so a route passing through an asset does not
/// oblige the trader to adopt it — that asset is the DLVs' across the hop.
fn adoption_admits(
    precommit: &TraderPrecommitBody,
    receipt: &RealizedReceipt<'_>,
) -> Result<(), AdvanceError> {
    // The receipt must describe THIS operation. Without this, a producer
    // could present the evidence of some other, fully adopted settlement and
    // install this one's root behind it — the gate would be checking an
    // operation nobody was installing. `E` is what `P` commits its settlement
    // by, so recomputing it from the receipt's own bytes is the binding.
    let derived =
        derive::recompute_e(receipt.preimage).map_err(|_| AdvanceError::CreditsNotDerivable)?;
    let expected = *precommit.external_commitment();
    if derived != expected {
        return Err(AdvanceError::ReceiptIsNotThisOperation { expected, derived });
    }
    let credits = trader_credits(receipt.preimage, receipt.evidence)
        .map_err(|_| AdvanceError::CreditsNotDerivable)?;
    for policy_commit in credits {
        if !receipt.receiver.has_adopted(&policy_commit) {
            return Err(AdvanceError::TokenNotAdopted { policy_commit });
        }
    }
    Ok(())
}

/// The trader balances a resolved position moves, as [`advance_resolved`]
/// derived them from the settlement and the evidence its verdict was reached
/// on. A Void moves none. Only `advance_resolved` builds one, so the balances
/// a device head takes from a resolution are the ones the installed root
/// holds, never a caller's list ([`DeviceState::with_resolved_position`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedBalances(Vec<TraderBalanceChange>);

impl ResolvedBalances {
    pub fn changes(&self) -> &[TraderBalanceChange] {
        &self.0
    }
}

/// What [`advance_resolved`] establishes at `q`: the validated root, the
/// claim `C_q` accepted there, and the trader balances the root moved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedAdvance {
    pub root: ValidatedEconomicRoot,
    pub claim: crate::economic::lineage::AcceptedClaim,
    pub balances: ResolvedBalances,
}

/// Advance the validated lineage through a resolved SoFi position (P15-10).
///
/// Every conjunct is independent and each one is a separate reason to refuse:
/// the positions chain, the predecessor's root is the one `P` was built on,
/// the parent claim is the one `P` names, and the installed `C_q` is the one
/// `(P, F)` derive — recomputed here, because a register holds what a member
/// was told.
pub fn advance_resolved(
    previous: &ValidatedEconomicRoot,
    precommit: &TraderPrecommitBody,
    fulfillment: &TraderFulfillmentBody,
    claims: &RegisteredClaims,
    resolution: Resolution,
    receipt: Option<&RealizedReceipt<'_>>,
) -> Result<ResolvedAdvance, AdvanceError> {
    let q = next_position(precommit.position()).map_err(AdvanceError::Counter)?;
    if fulfillment.position() != q || previous.economic_position() != precommit.position() {
        return Err(AdvanceError::PositionIsNotSuccessor {
            previous: previous.economic_position(),
            precommit: precommit.position(),
            fulfillment: fulfillment.position(),
        });
    }
    // P15-2, at advance: the root P returns to on a void IS the predecessor's.
    if previous.economic_root() != *precommit.void_root() {
        return Err(AdvanceError::PreRootIsNotThePredecessor {
            previous: previous.economic_root(),
            void_root: *precommit.void_root(),
        });
    }
    if claims.parent != *precommit.parent_claim_ref() {
        return Err(AdvanceError::ParentClaimMismatch);
    }
    // C_q is DERIVED from (P, F). Reading it out of the register and comparing
    // it to itself would check nothing.
    let derived = derive::resolution_claim(precommit, fulfillment);
    let derived_digest = derive::claim_ref(&derived.encode());
    if claims.conditional != derived_digest {
        return Err(AdvanceError::ResolutionClaimMismatch {
            registered: claims.conditional,
            derived: derived_digest,
        });
    }
    let (root, balances) = match resolution {
        Resolution::Realized => {
            let receipt = receipt.ok_or(AdvanceError::RealizedWithoutReceipt)?;
            // The adoption invariant, inside the function that installs the
            // root, so that no caller can reach a realized advance without it.
            adoption_admits(precommit, receipt)?;
            // The balances the realize root holds for the tokens T° moves,
            // from the same bytes `adoption_admits` just bound to this `E`.
            let changes = trader_balance_changes(precommit, receipt.preimage, receipt.evidence)
                .map_err(|_| AdvanceError::BalancesNotDerivable)?;
            (*precommit.realize_root(), ResolvedBalances(changes))
        }
        // Zero mutations: the lineage continues exactly where it was.
        Resolution::Void => (previous.economic_root(), ResolvedBalances(Vec::new())),
        Resolution::Invalid => return Err(AdvanceError::LineageIsTerminal),
    };
    Ok(ResolvedAdvance {
        balances,
        root: ValidatedEconomicRoot::from_resolved_sofi_position(q, root),
        claim: crate::economic::lineage::AcceptedClaim::from_resolved_sofi_position(
            *precommit.genesis(),
            *precommit.device_id(),
            q,
            derived_digest,
        ),
    })
}

/// What the verifier knows about the claim at a predecessor position, for the
/// core-local fence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PredecessorClaim {
    /// An ordinary single-root claim. Its root is validated or it is not, and
    /// that is the whole question.
    SingleRoot,
    /// A conditional SoFi claim `C_q` that has not resolved. It commits TWO
    /// roots and has selected neither.
    ConditionalUnresolved,
    /// A conditional claim that resolved and selected a root.
    ConditionalResolved { selected_root: D32 },
}

// THERE IS NO TERMINAL ARM, AND ITS ABSENCE IS THE RULE.
//
// A SoFi resolution that ends Invalid selects NO economic root, so it is never
// admitted: it produces no `AdmittedEconomicPosition`, and therefore no
// `PredecessorClaim` describes it. A terminal arm here would model something
// this type cannot mean — "an admitted economic predecessor that has no root"
// — and `descendant_fence` would then be refusing a value nothing could ever
// hand it.
//
// The boundary is proven, not asserted: see
// `a_terminal_resolution_never_becomes_an_admitted_position`.
//
// If a terminal outcome ever needs to be persisted for recovery, diagnostics
// or resolution history, it belongs in the RESOLUTION domain, not in the
// admitted economic lineage.

/// Why a descendant may not be built on this predecessor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FenceError {
    /// The predecessor is conditional and undecided. A descendant built now
    /// would be built on a root the lineage has not chosen.
    PredecessorIsUnresolved,
    /// The descendant is built on a root the predecessor did not select.
    PreRootIsNotTheSelectedRoot { selected: D32, descendant_pre: D32 },
}

impl core::fmt::Display for FenceError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::PredecessorIsUnresolved => write!(
                f,
                "the claim at the predecessor position is conditional and has not \
                 resolved: it commits two roots and has selected neither"
            ),
            Self::PreRootIsNotTheSelectedRoot { .. } => write!(
                f,
                "the descendant is built on a root the predecessor did not select"
            ),
        }
    }
}

impl std::error::Error for FenceError {}

/// THE CORE-LOCAL FENCE (F2): nothing descends from a conditional predecessor
/// until that predecessor has chosen a root.
///
/// The STORAGE fence is a different check and a weaker one — it requires the
/// predecessor to be storage-resolved, which a member can see. This one is the
/// verifier's: a position can be storage-resolved and still undecided, because
/// whether the route realized depends on evidence a member never evaluates. A
/// descendant admitted on that basis would be built on a root the lineage had
/// not chosen, and half of the time it is the wrong one.
///
/// **Wired, and deliberately inert.** Both paths that create the next local
/// economic position cross it — the advance that stages an admission plan and
/// the transaction that makes local acceptance durable — and
/// `ci/admitted_predecessor_readers_fenced.sh` fails the build if a third
/// descendant-producing path appears without it.
///
/// It nevertheless cannot fire today, and that is a property of the WRITER,
/// not of this rule: `record_admitted_with_conn` records `claim_kind = 0`
/// unconditionally because F ingress is dark, so `predecessor_claim()` can
/// only ever answer `SingleRoot`. Deleting the calls therefore turns no test
/// red, which is why the gate is static rather than a runtime mutation.
///
/// E2/E3 owns production of conditional admitted rows and makes this live when
/// that lifecycle lands. The invariant is installed ahead of its producer on
/// purpose: a descendant path added before then would be bypassing a fence
/// nothing could yet catch, and would become a live hole the day the writer
/// arrives.
pub fn descendant_fence(
    predecessor: PredecessorClaim,
    descendant_pre_root: &D32,
) -> Result<(), FenceError> {
    match predecessor {
        PredecessorClaim::SingleRoot => Ok(()),
        PredecessorClaim::ConditionalUnresolved => Err(FenceError::PredecessorIsUnresolved),
        PredecessorClaim::ConditionalResolved { selected_root } => {
            if selected_root == *descendant_pre_root {
                Ok(())
            } else {
                Err(FenceError::PreRootIsNotTheSelectedRoot {
                    selected: selected_root,
                    descendant_pre: *descendant_pre_root,
                })
            }
        }
    }
}

/// Why a vault's market policy is not the one its genesis state commits:
/// what the creation builder refuses before the owner signs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GenesisError {
    /// The pair is not strictly ordered, so the market policy would admit two
    /// encodings of one market.
    TokenPairNotOrdered,
    /// The supplied market-policy bytes do not re-derive the address the vault
    /// state commits. They establish nothing about this vault's market:
    /// non-verifying bytes are not evidence, they are noise.
    MarketPolicyIsNotTheCommittedOne,
    /// The market-policy bytes are not a canonical `MarketPolicy`.
    MarketPolicyDoesNotDecode,
}

impl core::fmt::Display for GenesisError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::TokenPairNotOrdered => write!(f, "the token pair is not strictly ordered"),
            Self::MarketPolicyIsNotTheCommittedOne => write!(
                f,
                "the market-policy bytes do not re-derive the address the vault state \
                 commits: they are not this vault's market"
            ),
            Self::MarketPolicyDoesNotDecode => {
                write!(
                    f,
                    "the market-policy bytes are not a canonical MarketPolicy"
                )
            }
        }
    }
}

impl std::error::Error for GenesisError {}

/// A vault genesis a verifier accepted (SoFi §19.8 `GenesisAccepted`): the
/// genesis preimage that the owner's validated transition at `p_create`
/// carried, with the market it commits. Only [`genesis_accepted`] constructs
/// it, and a walk of a vault starts from nothing else (§30 step 1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptedVaultGenesis {
    vault_id: D32,
    preimage: VaultGenesisPreimage,
    genesis_root: D32,
    market: crate::ccb::state::MarketPolicy,
}

impl AcceptedVaultGenesis {
    /// `v = vault_id(G_o, DevID_o, p_create)`.
    pub fn vault_id(&self) -> &D32 {
        &self.vault_id
    }

    /// The preimage the owner's creation carried.
    pub fn preimage(&self) -> &VaultGenesisPreimage {
        &self.preimage
    }

    /// `V_0`, the vault's state at generation zero.
    pub fn state(&self) -> &VaultStateLeaf {
        &self.preimage.state
    }

    /// `R_0`.
    pub fn genesis_root(&self) -> &D32 {
        &self.genesis_root
    }

    /// The market policy `V_0` commits.
    pub fn market(&self) -> &crate::ccb::state::MarketPolicy {
        &self.market
    }
}

/// Evidence genesis acceptance consumes that is not in hand. A network
/// status: the vault is neither accepted nor refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GenesisMissing {
    /// The `TokenPolicyV3` bytes one of the vault's two tokens commits, or
    /// bytes that do not re-hash to that commit.
    TokenPolicy { commit: D32 },
}

/// Why a vault genesis is not accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GenesisInvalid {
    /// The fetched bytes are not a canonical genesis preimage.
    PreimageDoesNotDecode,
    /// The validated transition is not the owner's at `p_create`.
    NotTheOwnersCreationPosition,
    /// The owner's validated transition at `p_create` is not a vault
    /// creation, or created a vault from other preimage bytes.
    NotTheCreationTheOwnerMade,
    /// `V_0` is not at generation zero.
    NotGenerationZero { generation: u64 },
    /// `V_0` is not Active.
    NotActive { status: u16 },
    /// `V_0` names a storage set other than the network's pinned set.
    NotThePinnedSet { named: D32, pinned: D32 },
    /// No root register profile is pinned for this network.
    NoPinnedSet,
    /// `V_0` does not encode, so it has no `R_0`.
    StateDoesNotEncode,
    /// The carried market-policy bytes are not the policy `V_0` commits, or
    /// not a canonical policy with an ordered pair.
    Market(GenesisError),
    /// A token's committed policy does not parse.
    TokenPolicyDoesNotParse { token: D32 },
    /// A token's policy refuses it as a market leg (§49: `transferable`
    /// binds vault creation).
    TokenNotTransferable { token: D32 },
}

/// Why genesis acceptance has no answer yet, or its answer is no.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GenesisRefusal {
    Missing(GenesisMissing),
    Invalid(GenesisInvalid),
}

/// SoFi §19.8 `GenesisAccepted`, over the genesis preimage bytes a verifier
/// fetched under `vault_genesis_locator(v)` and the owner's transition at
/// `p_create` as the verifier's own walk of the owner's lineage validated it.
///
/// The validated transition carries the conjuncts its write set enforces:
/// `v` derived from the owner coordinates and `p_create`, reserves equal to
/// the funded amounts and the debits, the creation record's `R_0` recomputed
/// from `V_0`, and the funded pair the market policy authorizes. Acceptance
/// binds the fetched bytes to that transition — the operation the owner
/// signed carried exactly these bytes — and adds what the transition does not
/// decide: `V_0` at generation zero and Active, on the network's pinned set,
/// with both tokens transferable (§49).
///
/// `token_policies` holds `TokenPolicyV3` bytes by `policy_commit`; each is
/// re-hashed to its commit before it establishes anything.
pub fn genesis_accepted(
    network_id: &[u8],
    preimage_bytes: &[u8],
    owner: &crate::economic::provenance::ValidatedPeerTransition,
    token_policies: &std::collections::BTreeMap<D32, Vec<u8>>,
) -> Result<AcceptedVaultGenesis, GenesisRefusal> {
    creation_accepted(
        network_id,
        preimage_bytes,
        &OwnerCreation {
            genesis: owner.peer_genesis(),
            device_id: owner.peer_devid(),
            position: owner.validated_root().economic_position(),
            operation: owner.verified_operation(),
        },
        token_policies,
    )
}

/// The owner's validated transition, as far as acceptance reads it.
struct OwnerCreation<'a> {
    genesis: &'a D32,
    device_id: &'a D32,
    position: u64,
    operation: &'a crate::types::operations::Operation,
}

fn creation_accepted(
    network_id: &[u8],
    preimage_bytes: &[u8],
    owner: &OwnerCreation<'_>,
    token_policies: &std::collections::BTreeMap<D32, Vec<u8>>,
) -> Result<AcceptedVaultGenesis, GenesisRefusal> {
    let invalid = GenesisRefusal::Invalid;
    let preimage = VaultGenesisPreimage::decode(preimage_bytes)
        .map_err(|_| invalid(GenesisInvalid::PreimageDoesNotDecode))?;
    if preimage.owner_genesis != *owner.genesis
        || preimage.owner_device_id != *owner.device_id
        || preimage.create_position != owner.position
    {
        return Err(invalid(GenesisInvalid::NotTheOwnersCreationPosition));
    }
    let crate::types::operations::Operation::SofiVaultCreate {
        genesis_preimage,
        market_policy_preimage,
        ..
    } = owner.operation
    else {
        return Err(invalid(GenesisInvalid::NotTheCreationTheOwnerMade));
    };
    if genesis_preimage.as_slice() != preimage_bytes {
        return Err(invalid(GenesisInvalid::NotTheCreationTheOwnerMade));
    }
    let state = &preimage.state;
    if state.generation != 0 {
        return Err(invalid(GenesisInvalid::NotGenerationZero {
            generation: state.generation,
        }));
    }
    if state.status != super::wire::VAULT_STATUS_ACTIVE {
        return Err(invalid(GenesisInvalid::NotActive {
            status: state.status,
        }));
    }
    let pinned = crate::economic::register::resolve_root_register_profile(network_id)
        .map_err(|_| invalid(GenesisInvalid::NoPinnedSet))?
        .storage_set_id;
    if state.storage_set_id != pinned {
        return Err(invalid(GenesisInvalid::NotThePinnedSet {
            named: state.storage_set_id,
            pinned,
        }));
    }
    let vault_id = preimage.vault_id();
    let genesis_root =
        genesis_root(&vault_id, state).map_err(|_| invalid(GenesisInvalid::StateDoesNotEncode))?;
    let committed = crate::ccb::decode::policy_object_address(
        crate::ccb::class::MARKET_POLICY,
        market_policy_preimage,
    );
    if committed != Some(state.market_policy) {
        return Err(invalid(GenesisInvalid::Market(
            GenesisError::MarketPolicyIsNotTheCommittedOne,
        )));
    }
    // `token_a < token_b`: a `MarketPolicy` with an unordered pair does not
    // decode.
    let market =
        crate::ccb::decode::decode_market_policy(market_policy_preimage).map_err(|_| {
            invalid(GenesisInvalid::Market(
                GenesisError::MarketPolicyDoesNotDecode,
            ))
        })?;
    for token in [*market.token_a(), *market.token_b()] {
        token_is_a_market_leg(&token, token_policies)?;
    }
    Ok(AcceptedVaultGenesis {
        vault_id,
        preimage,
        genesis_root,
        market,
    })
}

/// §49: `transferable` binds vault creation for both tokens. ERA and dBTC are
/// pre-rooted and consult no policy.
fn token_is_a_market_leg(
    token: &D32,
    token_policies: &std::collections::BTreeMap<D32, Vec<u8>>,
) -> Result<(), GenesisRefusal> {
    if crate::core::token::builtin_token_id_for_policy_commit(token).is_some() {
        return Ok(());
    }
    let missing = GenesisRefusal::Missing(GenesisMissing::TokenPolicy { commit: *token });
    let bytes = token_policies.get(token).ok_or(missing.clone())?;
    let derived =
        crate::crypto::blake3::domain_hash_bytes(crate::common::domain_tags::TAG_DSM_POLICY, bytes);
    if derived != *token {
        return Err(missing);
    }
    let policy = crate::economic::token_policy::parse_token_policy(bytes).map_err(|_| {
        GenesisRefusal::Invalid(GenesisInvalid::TokenPolicyDoesNotParse { token: *token })
    })?;
    crate::economic::issuance::check_market_leg_permitted(&policy).map_err(|_| {
        GenesisRefusal::Invalid(GenesisInvalid::TokenNotTransferable { token: *token })
    })
}

/// The vault's leaves at `R_0`, for the keys an acquisition needs: the state
/// leaf at its key, and `Absent` at every other — nobody has traded with it
/// yet, so no relationship leaf exists (rebuild step R5).
pub fn vault_leaves_at_genesis(
    vault_id: &D32,
    state: &VaultStateLeaf,
    keys: &std::collections::BTreeSet<D32>,
) -> std::collections::BTreeMap<(D32, D32), crate::sofi::validation::VaultLeafPre> {
    use crate::sofi::validation::VaultLeafPre;
    let state_key = derive::vault_state_key(vault_id);
    keys.iter()
        .map(|key| {
            let pre = if *key == state_key {
                VaultLeafPre::State(state.clone())
            } else {
                VaultLeafPre::Absent
            };
            ((*vault_id, *key), pre)
        })
        .collect()
}

/// `R_0` — the vault's tree holding exactly its own state leaf, and no
/// relationship leaves: nobody has traded with it yet.
pub fn genesis_root(vault_id: &D32, state: &VaultStateLeaf) -> Result<D32, SofiWireError> {
    let key = derive::vault_state_key(vault_id);
    let value = derive::vault_state_leaf_value(state)?;
    let mut tree = crate::economic::tree::EconomicSmt::new();
    tree.insert(key, value);
    Ok(tree.root())
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)] // test asserts; a failure here is the signal
mod tests {
    use super::*;
    use crate::sofi::wire::{VaultCreation, VaultGenesisPreimage, VAULT_STATUS_ACTIVE};
    use crate::economic::state::EconomicLeafState;
    use crate::sofi::wire::{PrecommitLeg, TraderRelationshipLeaf};

    const G: D32 = [0x11; 32];
    const DEV: D32 = [0x22; 32];
    const P_POS: u64 = 5;
    const SIG_ALG: u16 = 0x0001;

    fn d(byte: u8) -> D32 {
        [byte; 32]
    }

    fn precommit(void_root: D32, realize_root: D32) -> TraderPrecommitBody {
        TraderPrecommitBody::new(
            G,
            DEV,
            P_POS,
            ParentClaimRef::SingleRoot { claim_ref: d(0x66) },
            d(0xEE),
            vec![PrecommitLeg {
                vault_id: d(0xC1),
                parent_root: d(0xC2),
                setup_ref: d(0x55),
            }],
            realize_root,
            void_root,
            d(0x77),
            SIG_ALG,
            &[0x01; 64],
        )
        .unwrap()
    }

    fn fulfillment(p: &TraderPrecommitBody) -> TraderFulfillmentBody {
        TraderFulfillmentBody::new(
            derive::precommit_id(p),
            vec![d(0x01)],
            vec![crate::sofi::wire::AttemptEntry {
                vault_id: d(0xC1),
                attempt: 0,
            }],
            P_POS + 1,
            SIG_ALG,
            &[0x01; 64],
        )
        .unwrap()
    }

    fn claims(p: &TraderPrecommitBody, f: &TraderFulfillmentBody) -> RegisteredClaims {
        RegisteredClaims {
            parent: *p.parent_claim_ref(),
            conditional: derive::claim_ref(&derive::resolution_claim(p, f).encode()),
        }
    }

    fn previous(root: D32) -> ValidatedEconomicRoot {
        ValidatedEconomicRoot::rehydrate_from_admitted_store(
            crate::economic::lineage::AdmittedEconomicPosition::SingleRoot {
                economic_position: P_POS,
                economic_root: root,
                claim_ref: d(0x66),
            },
        )
        .expect("an ordinary admitted position")
    }

    /// The fixture's own one-hop swap, and a receiver that HAS adopted what
    /// it credits. The receipt must describe this very operation — its
    /// settlement has to recompute `P`'s `E` — so these tests stand on the
    /// real rig rather than the synthetic precommit above, whose `E` is a
    /// literal no settlement could produce.
    fn realized_rig() -> (crate::sofi::validation::fixtures::Fixture, DeviceState) {
        let fx = crate::sofi::validation::fixtures::swap_fixture_n(1);
        let mut receiver = DeviceState::new(G, DEV, vec![0x01; 32]);
        for policy_commit in trader_credits(&fx.preimage, &fx.evidence).unwrap() {
            receiver = receiver.adopt_token(policy_commit).unwrap();
        }
        (fx, receiver)
    }

    fn receipt<'a>(
        fx: &'a crate::sofi::validation::fixtures::Fixture,
        receiver: &'a DeviceState,
    ) -> RealizedReceipt<'a> {
        RealizedReceipt {
            preimage: &fx.preimage,
            evidence: &fx.evidence,
            receiver,
        }
    }

    #[test]
    fn a_realized_position_installs_the_realize_root() {
        let (fx, receiver) = realized_rig();
        let p = fx.precommit.clone();
        let f = fulfillment(&p);
        let advanced = advance_resolved(
            &previous(*p.void_root()),
            &p,
            &f,
            &claims(&p, &f),
            Resolution::Realized,
            Some(&receipt(&fx, &receiver)),
        )
        .unwrap();
        assert_eq!(advanced.root.economic_position(), P_POS + 1);
        assert_eq!(advanced.root.economic_root(), *p.realize_root());
        // The claim accepted at q is C_q, derived from (P, F).
        assert_eq!(
            (
                advanced.claim.genesis(),
                advanced.claim.device_id(),
                advanced.claim.economic_position(),
                advanced.claim.claim_ref()
            ),
            (
                G,
                DEV,
                P_POS + 1,
                derive::claim_ref(&derive::resolution_claim(&p, &f).encode())
            )
        );
    }

    /// The swap the realized rig resolves: `AMOUNT_IN` of its first token
    /// out of the trader's 50 000, and its exact output of the last one in.
    fn swap_terms(fx: &crate::sofi::validation::fixtures::Fixture) -> (D32, D32, u64) {
        match fx.preimage.settlement() {
            crate::sofi::wire::SettlementBody::Swap {
                token_in,
                token_out,
                exact_out,
                ..
            } => (*token_in, *token_out, *exact_out),
            crate::sofi::wire::SettlementBody::Close { .. } => {
                panic!("the realized rig is a swap")
            }
        }
    }

    /// A Realized position moves the trader's balances to what its realize
    /// root holds, and a head holding what the pre-root held takes exactly
    /// those balances.
    #[test]
    fn a_realized_position_moves_exactly_the_balances_its_realize_root_holds() {
        use crate::sofi::validation::fixtures::AMOUNT_IN;
        let (fx, receiver) = realized_rig();
        let (token_in, token_out, exact_out) = swap_terms(&fx);
        let p = fx.precommit.clone();
        let f = fulfillment(&p);
        let advanced = advance_resolved(
            &previous(*p.void_root()),
            &p,
            &f,
            &claims(&p, &f),
            Resolution::Realized,
            Some(&receipt(&fx, &receiver)),
        )
        .unwrap();
        let mut changes = advanced.balances.changes().to_vec();
        changes.sort_by_key(|c| c.policy_commit);
        let mut expected = vec![
            TraderBalanceChange {
                policy_commit: token_in,
                before: 50_000,
                after: 50_000 - AMOUNT_IN,
            },
            TraderBalanceChange {
                policy_commit: token_out,
                before: 0,
                after: exact_out,
            },
        ];
        expected.sort_by_key(|c| c.policy_commit);
        assert_eq!(changes, expected);

        let holding = receiver.created_token(token_in, 50_000).unwrap();
        let resolved = holding.with_resolved_position(&advanced.balances).unwrap();
        assert_eq!(resolved.balance(&token_in), 50_000 - AMOUNT_IN);
        assert_eq!(resolved.balance(&token_out), exact_out);
        // The balances only: the resolution is not a transition, so the
        // device root is the one that registered the position.
        assert_eq!(resolved.root(), holding.root());
    }

    /// The balances a resolution moves start from the pre-root's. A head that
    /// holds anything else did not register the position, and takes nothing.
    #[test]
    fn a_head_that_does_not_hold_the_pre_balances_takes_no_resolution() {
        let (fx, receiver) = realized_rig();
        let (token_in, ..) = swap_terms(&fx);
        let p = fx.precommit.clone();
        let f = fulfillment(&p);
        let advanced = advance_resolved(
            &previous(*p.void_root()),
            &p,
            &f,
            &claims(&p, &f),
            Resolution::Realized,
            Some(&receipt(&fx, &receiver)),
        )
        .unwrap();
        assert!(receiver.with_resolved_position(&advanced.balances).is_err());
        let short = receiver.created_token(token_in, 49_999).unwrap();
        assert!(short.with_resolved_position(&advanced.balances).is_err());
    }

    /// A Void position moves nothing: the head it leaves is the head it had.
    #[test]
    fn a_void_position_moves_no_balance() {
        let pre = d(0xA0);
        let p = precommit(pre, d(0xA1));
        let f = fulfillment(&p);
        let advanced = advance_resolved(
            &previous(pre),
            &p,
            &f,
            &claims(&p, &f),
            Resolution::Void,
            None,
        )
        .unwrap();
        assert!(advanced.balances.changes().is_empty());
    }

    /// SofiVoid has zero mutations: the position exists, it is terminal, and
    /// the lineage continues exactly where it was.
    #[test]
    fn a_void_position_installs_the_previous_root() {
        let pre = d(0xA0);
        let p = precommit(pre, d(0xA1));
        let f = fulfillment(&p);
        let advanced = advance_resolved(
            &previous(pre),
            &p,
            &f,
            &claims(&p, &f),
            Resolution::Void,
            None,
        )
        .unwrap();
        assert_eq!(advanced.root.economic_position(), P_POS + 1);
        assert_eq!(advanced.root.economic_root(), pre);
    }

    #[test]
    fn an_invalid_position_installs_nothing() {
        let pre = d(0xA0);
        let p = precommit(pre, d(0xA1));
        let f = fulfillment(&p);
        assert_eq!(
            advance_resolved(
                &previous(pre),
                &p,
                &f,
                &claims(&p, &f),
                Resolution::Invalid,
                None
            ),
            Err(AdvanceError::LineageIsTerminal)
        );
    }

    /// Each conjunct is a separate reason to refuse, so removing any one of
    /// them is a hole rather than a nuance.
    #[test]
    fn advance_is_refused_on_each_missing_conjunct() {
        let pre = d(0xA0);
        let realize = d(0xA1);
        let p = precommit(pre, realize);
        let f = fulfillment(&p);
        let good = claims(&p, &f);

        // The predecessor is at another position.
        assert!(matches!(
            advance_resolved(
                &ValidatedEconomicRoot::rehydrate_from_admitted_store(
                    crate::economic::lineage::AdmittedEconomicPosition::SingleRoot {
                        economic_position: P_POS + 3,
                        economic_root: pre,
                        claim_ref: d(0x66),
                    },
                )
                .expect("an ordinary admitted position"),
                &p,
                &f,
                &good,
                Resolution::Realized,
                None,
            ),
            Err(AdvanceError::PositionIsNotSuccessor { .. })
        ));

        // F is not at q.
        let wrong_q = TraderFulfillmentBody::new(
            derive::precommit_id(&p),
            vec![d(0x01)],
            vec![crate::sofi::wire::AttemptEntry {
                vault_id: d(0xC1),
                attempt: 0,
            }],
            P_POS + 2,
            SIG_ALG,
            &[0x01; 64],
        )
        .unwrap();
        assert!(matches!(
            advance_resolved(
                &previous(pre),
                &p,
                &wrong_q,
                &good,
                Resolution::Realized,
                None
            ),
            Err(AdvanceError::PositionIsNotSuccessor { .. })
        ));

        // P was built on another root (P15-2).
        assert!(matches!(
            advance_resolved(
                &previous(d(0xBB)),
                &p,
                &f,
                &good,
                Resolution::Realized,
                None
            ),
            Err(AdvanceError::PreRootIsNotThePredecessor { .. })
        ));

        // The claim at K_root(p) is not the one P names.
        let other_parent = RegisteredClaims {
            parent: ParentClaimRef::Conditional {
                fulfillment_id: d(0x77),
            },
            ..good
        };
        assert_eq!(
            advance_resolved(
                &previous(pre),
                &p,
                &f,
                &other_parent,
                Resolution::Realized,
                None
            ),
            Err(AdvanceError::ParentClaimMismatch)
        );

        // C_q is DERIVED, so a register holding anything else is refused.
        let other_cq = RegisteredClaims {
            conditional: d(0x5A),
            ..good
        };
        assert!(matches!(
            advance_resolved(
                &previous(pre),
                &p,
                &f,
                &other_cq,
                Resolution::Realized,
                None
            ),
            Err(AdvanceError::ResolutionClaimMismatch { .. })
        ));
    }

    /// A fulfillment of ANOTHER precommit derives another `C_q`, so it cannot
    /// advance this position even at the right place in the lineage.
    #[test]
    fn a_fulfillment_of_another_precommit_cannot_advance_this_position() {
        let pre = d(0xA0);
        let p = precommit(pre, d(0xA1));
        let other = precommit(pre, d(0xA2));
        let f = fulfillment(&p);
        let other_f = fulfillment(&other);
        assert_ne!(derive::precommit_id(&p), derive::precommit_id(&other));
        assert!(matches!(
            advance_resolved(
                &previous(pre),
                &p,
                &other_f,
                &claims(&p, &f),
                Resolution::Realized,
                None,
            ),
            Err(AdvanceError::ResolutionClaimMismatch { .. })
        ));
    }

    // ── genesis ──────────────────────────────────────────────────────────

    fn genesis_state(reserve_a: u64, reserve_b: u64, generation: u64) -> VaultStateLeaf {
        VaultStateLeaf {
            owner_genesis: G,
            owner_device_id: DEV,
            create_position: P_POS,
            market_policy: market().2,
            fee_policy: d(0x32),
            release_policy: d(0x33),
            storage_set_id: d(0x77),
            generation,
            reserve_a,
            reserve_b,
            status: VAULT_STATUS_ACTIVE,
        }
    }

    fn market() -> (crate::ccb::state::MarketPolicy, Vec<u8>, D32) {
        let policy =
            crate::ccb::state::MarketPolicy::beta_constant_product(d(0x40), d(0x41)).unwrap();
        let bytes = policy.encode();
        let addr =
            crate::ccb::decode::policy_object_address(crate::ccb::class::MARKET_POLICY, &bytes)
                .unwrap();
        (policy, bytes, addr)
    }

    fn genesis_parts() -> (VaultGenesisPreimage, VaultCreation) {
        let state = genesis_state(1_000, 2_000, 0);
        let preimage = VaultGenesisPreimage {
            owner_genesis: G,
            owner_device_id: DEV,
            create_position: P_POS,
            state: state.clone(),
        };
        let vault_id = preimage.vault_id();
        let creation = VaultCreation {
            vault_id,
            genesis_root: genesis_root(&vault_id, &state).unwrap(),
            amount_a: 1_000,
            amount_b: 2_000,
        };
        (preimage, creation)
    }

    /// `R_0` holds the state leaf and nothing else.
    #[test]
    fn the_genesis_root_holds_only_the_state_leaf() {
        let (preimage, creation) = genesis_parts();
        let vault_id = preimage.vault_id();
        let mut with_a_relationship = crate::economic::tree::EconomicSmt::new();
        with_a_relationship.insert(
            derive::vault_state_key(&vault_id),
            derive::vault_state_leaf_value(&preimage.state).unwrap(),
        );
        with_a_relationship.insert(derive::relationship_key(&G, &DEV, &vault_id), d(0x5B));
        assert_ne!(creation.genesis_root, with_a_relationship.root());
    }

    /// The relationship leaf is an economic leaf with the SoFi key.
    #[test]
    fn the_relationship_leaf_is_an_economic_leaf_with_the_sofi_key() {
        let leaf = TraderRelationshipLeaf {
            vault_id: d(0xC1),
            leaf: d(0x0B),
        };
        let state = EconomicLeafState::Relationship(leaf);
        assert_eq!(
            state.class(),
            crate::ccb::class::SOFI_TRADER_RELATIONSHIP_LEAF
        );
        assert_eq!(state.encode().unwrap(), leaf.encode());
        assert_eq!(
            state.leaf_key(&G, &DEV),
            derive::relationship_key(&G, &DEV, &d(0xC1))
        );
        // It carries no amount, so it can never be read as a credit needing a
        // funding source.
        assert_eq!(state.credit_amount(), None);
    }

    /// And the creation record is one too, with ITS own key.
    #[test]
    fn the_creation_record_is_an_economic_leaf_with_its_own_key() {
        let record = VaultCreation {
            vault_id: d(0xC1),
            genesis_root: d(0x0C),
            amount_a: 1,
            amount_b: 2,
        };
        let state = EconomicLeafState::VaultCreation(record);
        assert_eq!(state.class(), crate::ccb::class::SOFI_VAULT_CREATION);
        assert_eq!(state.encode().unwrap(), record.encode());
        assert_eq!(
            state.leaf_key(&G, &DEV),
            derive::vault_creation_key(&G, &DEV, &d(0xC1))
        );
        // NOT the storage locator: an economic address and a storage
        // coordinate are different namespaces, and one derivation serving both
        // is how they collide.
        assert_ne!(
            state.leaf_key(&G, &DEV),
            derive::vault_genesis_locator(&d(0xC1))
        );
        assert_eq!(state.credit_amount(), None);
    }

    // ── the core-local fence ─────────────────────────────────────────────

    /// A conditional predecessor that has not resolved blocks EVERYTHING
    /// beneath it, whichever of its two roots a descendant guesses.
    #[test]
    fn nothing_descends_from_an_unresolved_conditional_predecessor() {
        for guess in [d(0xA0), d(0xA1), d(0x00)] {
            assert_eq!(
                descendant_fence(PredecessorClaim::ConditionalUnresolved, &guess),
                Err(FenceError::PredecessorIsUnresolved)
            );
        }
    }

    /// Once it resolves, exactly one root is admissible — the one it selected.
    #[test]
    fn a_resolved_predecessor_admits_only_the_root_it_selected() {
        let selected = d(0xA1);
        assert_eq!(
            descendant_fence(
                PredecessorClaim::ConditionalResolved {
                    selected_root: selected
                },
                &selected
            ),
            Ok(())
        );
        assert_eq!(
            descendant_fence(
                PredecessorClaim::ConditionalResolved {
                    selected_root: selected
                },
                &d(0xA0)
            ),
            Err(FenceError::PreRootIsNotTheSelectedRoot {
                selected,
                descendant_pre: d(0xA0)
            })
        );
    }

    /// TERMINAL IS NOT A PREDECESSOR STATE — the boundary that replaces the
    /// old fabricated `ConditionalTerminal` assertion.
    ///
    /// That test built a value no production path could construct and checked
    /// the fence refused it, which proved only that the arm existed. The real
    /// rule is upstream: a resolution ending Invalid selects NO root, so
    /// `advance_resolved` returns `LineageIsTerminal` and yields no
    /// `ValidatedEconomicRoot`. With no root there is nothing to record — every
    /// `AdmittedEconomicPosition` arm carries either a selected root or the two
    /// a route committed — so no `PredecessorClaim` ever describes a terminal
    /// position and the fence is never asked about one.
    #[test]
    fn a_terminal_resolution_never_becomes_an_admitted_position() {
        let pre = d(0x70);
        let p = precommit(pre, d(0xA1));
        let f = fulfillment(&p);
        // 1. Terminal yields no validated root, so the chain stops here.
        assert_eq!(
            advance_resolved(
                &previous(pre),
                &p,
                &f,
                &claims(&p, &f),
                Resolution::Invalid,
                None
            ),
            Err(AdvanceError::LineageIsTerminal)
        );

        // 2. And no admitted shape could carry one if it did. Exhaustive on
        //    purpose: a new `AdmittedEconomicPosition` arm fails to compile
        //    HERE, forcing a ruling on whether it may be a predecessor.
        use crate::economic::lineage::AdmittedEconomicPosition;
        let shapes = [
            AdmittedEconomicPosition::SingleRoot {
                economic_position: 4,
                economic_root: d(0xA0),
                claim_ref: d(0x66),
            },
            AdmittedEconomicPosition::ResolvedSofi {
                economic_position: 4,
                selected_root: d(0xA0),
                fulfillment_id: d(0xF1),
                claim_ref: d(0x66),
            },
            AdmittedEconomicPosition::UnresolvedSofi {
                economic_position: 4,
                fulfillment_id: d(0xF1),
                realize_root: d(0xA1),
                void_root: d(0xA2),
            },
        ];
        for shape in shapes {
            match shape {
                AdmittedEconomicPosition::SingleRoot { .. }
                | AdmittedEconomicPosition::ResolvedSofi { .. }
                | AdmittedEconomicPosition::UnresolvedSofi { .. } => {}
            }
            // Every shape maps to a claim the fence can decide — none is
            // terminal, and none needs a terminal arm to be decided.
            let _ = descendant_fence(shape.predecessor_claim(), &d(0xA0));
        }

        // 3. The ordinary predecessor still does not fence.
        assert_eq!(
            descendant_fence(PredecessorClaim::SingleRoot, &d(0xA0)),
            Ok(())
        );
    }

    /// THE ADOPTION INVARIANT on the resolved SoFi seam. Everything else about
    /// this operation is in order — positions chain, roots match, the claim is
    /// the one `P` names — and it is still refused, because the token it would
    /// credit was never adopted here. Nobody adopts on the receiver's behalf.
    #[test]
    fn a_realized_position_crediting_an_unadopted_token_is_refused() {
        let (fx, _) = realized_rig();
        let p = fx.precommit.clone();
        let f = fulfillment(&p);
        let credits = trader_credits(&fx.preimage, &fx.evidence).unwrap();
        assert_eq!(credits.len(), 1, "a one-hop swap credits its output only");

        // A receiver that has adopted NOTHING.
        let bare = DeviceState::new(G, DEV, vec![0x01; 32]);
        assert!(!bare.has_adopted(&credits[0]));
        assert_eq!(
            advance_resolved(
                &previous(*p.void_root()),
                &p,
                &f,
                &claims(&p, &f),
                Resolution::Realized,
                Some(&receipt(&fx, &bare)),
            ),
            Err(AdvanceError::TokenNotAdopted {
                policy_commit: credits[0]
            })
        );

        // The same bytes, once the policy was installed here first.
        let adopter = bare.adopt_token(credits[0]).unwrap();
        assert!(advance_resolved(
            &previous(*p.void_root()),
            &p,
            &f,
            &claims(&p, &f),
            Resolution::Realized,
            Some(&receipt(&fx, &adopter)),
        )
        .is_ok());
    }

    /// The gate cannot be skipped by declining to present a receipt: a
    /// realized advance without one is refused, so there is no argument a
    /// caller can omit to avoid being checked.
    #[test]
    fn a_realized_position_cannot_advance_without_a_receipt() {
        let (fx, _) = realized_rig();
        let p = fx.precommit.clone();
        let f = fulfillment(&p);
        assert_eq!(
            advance_resolved(
                &previous(*p.void_root()),
                &p,
                &f,
                &claims(&p, &f),
                Resolution::Realized,
                None,
            ),
            Err(AdvanceError::RealizedWithoutReceipt)
        );
    }

    /// Nor by presenting SOMEBODY ELSE'S receipt. A producer holding the
    /// evidence of a fully adopted settlement could otherwise install this
    /// operation's root behind it, and the gate would be checking an
    /// operation nobody was installing. `E` is the binding.
    #[test]
    fn a_receipt_for_another_operation_is_refused() {
        let (fx, receiver) = realized_rig();
        let other = crate::sofi::validation::fixtures::swap_fixture_n(2);
        let p = fx.precommit.clone();
        let f = fulfillment(&p);
        assert!(matches!(
            advance_resolved(
                &previous(*p.void_root()),
                &p,
                &f,
                &claims(&p, &f),
                Resolution::Realized,
                Some(&RealizedReceipt {
                    preimage: &other.preimage,
                    evidence: &other.evidence,
                    receiver: &receiver,
                }),
            ),
            Err(AdvanceError::ReceiptIsNotThisOperation { .. })
        ));
    }

    /// A VOID moves nothing, so it needs no receipt and no adoption: refusing
    /// it would strand a lineage over a token that never arrived.
    #[test]
    fn a_void_needs_no_adoption() {
        let (fx, _) = realized_rig();
        let p = fx.precommit.clone();
        let f = fulfillment(&p);
        let advanced = advance_resolved(
            &previous(*p.void_root()),
            &p,
            &f,
            &claims(&p, &f),
            Resolution::Void,
            None,
        )
        .unwrap();
        assert_eq!(advanced.root.economic_root(), *p.void_root());
    }

    /// THE MULTI-HOP CASE. A route `A -> B -> C` obliges the trader to have
    /// adopted `C` and nothing else. `B` is held by the DLVs across the hop
    /// and never becomes a trader balance leaf, so requiring its adoption
    /// would refuse a route over an asset the trader never receives.
    #[test]
    fn a_route_does_not_oblige_the_trader_to_adopt_what_it_passes_through() {
        let fx = crate::sofi::validation::fixtures::swap_fixture_n(2);
        let p = fx.precommit.clone();
        let f = fulfillment(&p);
        let hops = match fx.preimage.settlement() {
            crate::sofi::wire::SettlementBody::Swap { hops, .. } => hops.clone(),
            crate::sofi::wire::SettlementBody::Close { .. } => unreachable!("a swap fixture"),
        };
        assert_eq!(hops.len(), 2);
        let intermediate = hops[0].token_out;
        assert_eq!(
            intermediate, hops[1].token_in,
            "B is what the hops chain on"
        );

        let credits = trader_credits(&fx.preimage, &fx.evidence).unwrap();
        assert_eq!(credits, vec![hops[1].token_out], "the route's END, only");
        assert!(
            !credits.contains(&intermediate),
            "the trader is never credited what the route passes through"
        );

        // A receiver that adopted the OUTPUT only — not the intermediate.
        let receiver = DeviceState::new(G, DEV, vec![0x01; 32])
            .adopt_token(hops[1].token_out)
            .unwrap();
        assert!(!receiver.has_adopted(&intermediate));
        assert!(advance_resolved(
            &previous(*p.void_root()),
            &p,
            &f,
            &claims(&p, &f),
            Resolution::Realized,
            Some(&receipt(&fx, &receiver)),
        )
        .is_ok());
    }

    /// The fence and the advance agree: a position that `advance_resolved`
    /// produced is exactly one a descendant may build on, and the root it
    /// installed is the only one admissible.
    #[test]
    fn the_fence_admits_exactly_what_the_advance_installed() {
        let (fx, receiver) = realized_rig();
        let p = fx.precommit.clone();
        let (pre, realize) = (*p.void_root(), *p.realize_root());
        let f = fulfillment(&p);
        let r = receipt(&fx, &receiver);
        for (resolution, expected) in [(Resolution::Realized, realize), (Resolution::Void, pre)] {
            // A void needs no receipt; a realized one cannot advance without.
            let carried = matches!(resolution, Resolution::Realized).then_some(&r);
            let advanced =
                advance_resolved(&previous(pre), &p, &f, &claims(&p, &f), resolution, carried)
                    .unwrap();
            assert_eq!(
                descendant_fence(
                    PredecessorClaim::ConditionalResolved {
                        selected_root: advanced.root.economic_root()
                    },
                    &expected
                ),
                Ok(())
            );
            // And the branch it did NOT take is refused.
            let other = if expected == realize { pre } else { realize };
            assert!(descendant_fence(
                PredecessorClaim::ConditionalResolved {
                    selected_root: advanced.root.economic_root()
                },
                &other
            )
            .is_err());
        }
    }
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)] // test asserts; a failure here is the signal
mod genesis_acceptance {
    //! SoFi §19.8 `GenesisAccepted` over a creation signed with the owner's
    //! key and policy bytes that re-hash to their commits. Each test changes
    //! one thing the owner's validated creation or `V_0` holds and names the
    //! conjunct that refuses it.

    use std::collections::BTreeMap;

    use super::*;
    use crate::ccb::state::{FeePolicy, MarketPolicy, ReleasePolicy};
    use crate::sofi::validation::fixtures::{
        committed, token_policy_bytes_with, tokens, trader_keys, DEV, G, P_CREATE,
    };
    use crate::sofi::wire::{VaultCreation, VAULT_STATUS_ACTIVE, VAULT_STATUS_RETIRED};
    use crate::types::operations::Operation;

    const NETWORK: &[u8] = crate::economic::register::BETA_NETWORK_ID;

    fn pinned_set() -> D32 {
        crate::economic::register::resolve_root_register_profile(NETWORK)
            .expect("the beta network pins a register set")
            .storage_set_id
    }

    fn addr(class: u16, bytes: &[u8]) -> D32 {
        crate::ccb::decode::policy_object_address(class, bytes).expect("a policy class")
    }

    /// A creation as the owner signed it, with what a verifier fetched.
    struct Creation {
        preimage_bytes: Vec<u8>,
        operation: Operation,
        token_policies: BTreeMap<D32, Vec<u8>>,
    }

    /// `V_0` over `pair` at generation zero, Active, on the pinned set.
    fn genesis_state(pair: (D32, D32)) -> (VaultStateLeaf, Vec<u8>) {
        let market = MarketPolicy::beta_constant_product(pair.0, pair.1).unwrap();
        let market_bytes = market.encode();
        let fee = FeePolicy::new(30).unwrap();
        let release = ReleasePolicy::beta_owner_local_full_close();
        let state = VaultStateLeaf {
            owner_genesis: G,
            owner_device_id: DEV,
            create_position: P_CREATE,
            market_policy: addr(crate::ccb::class::MARKET_POLICY, &market_bytes),
            fee_policy: addr(crate::ccb::class::FEE_POLICY, &fee.encode()),
            release_policy: addr(crate::ccb::class::RELEASE_POLICY, &release.encode()),
            storage_set_id: pinned_set(),
            generation: 0,
            reserve_a: 1_000,
            reserve_b: 2_000,
            status: VAULT_STATUS_ACTIVE,
        };
        (state, market_bytes)
    }

    /// The creation of `state` as the owner signs it — over the operation's
    /// signing bytes, with the owner's key — and the verifier's token
    /// policies.
    fn creation_of(state: VaultStateLeaf, market_bytes: Vec<u8>, pair: (D32, D32)) -> Creation {
        let preimage = VaultGenesisPreimage {
            owner_genesis: G,
            owner_device_id: DEV,
            create_position: P_CREATE,
            state,
        };
        let vault_id = preimage.vault_id();
        let record = VaultCreation {
            vault_id,
            genesis_root: genesis_root(&vault_id, &preimage.state).unwrap(),
            amount_a: preimage.state.reserve_a,
            amount_b: preimage.state.reserve_b,
        };
        let preimage_bytes = preimage.encode().unwrap();
        let build = |signature: Vec<u8>| Operation::SofiVaultCreate {
            genesis_preimage: preimage_bytes.clone(),
            creation: record.encode(),
            market_policy_preimage: market_bytes.clone(),
            funding_a_policy_commit: pair.0,
            funding_b_policy_commit: pair.1,
            signature,
        };
        let signing = (build(Vec::new())).signing_bytes();
        let operation =
            build(crate::crypto::sphincs::sphincs_sign(&trader_keys().1, &signing).unwrap());
        Creation {
            preimage_bytes,
            operation,
            token_policies: tokens().iter().cloned().collect(),
        }
    }

    fn valid() -> Creation {
        let pair = (tokens()[0].0, tokens()[1].0);
        let (state, market_bytes) = genesis_state(pair);
        creation_of(state, market_bytes, pair)
    }

    fn accept_at(c: &Creation, position: u64) -> Result<AcceptedVaultGenesis, GenesisRefusal> {
        creation_accepted(
            NETWORK,
            &c.preimage_bytes,
            &OwnerCreation {
                genesis: &G,
                device_id: &DEV,
                position,
                operation: &c.operation,
            },
            &c.token_policies,
        )
    }

    fn accept(c: &Creation) -> Result<AcceptedVaultGenesis, GenesisRefusal> {
        accept_at(c, P_CREATE)
    }

    #[test]
    fn the_genesis_the_owners_creation_carried_is_accepted() {
        let c = valid();
        assert_eq!(
            crate::sofi::signature::verify_operation(&c.operation, &trader_keys().0),
            Ok(()),
            "the creation is signed under the owner's key"
        );
        let accepted = accept(&c).unwrap();
        let preimage = VaultGenesisPreimage::decode(&c.preimage_bytes).unwrap();
        assert_eq!(accepted.vault_id(), &preimage.vault_id());
        assert_eq!(
            accepted.genesis_root(),
            &genesis_root(&preimage.vault_id(), &preimage.state).unwrap()
        );
        assert_eq!(accepted.state(), &preimage.state);
        assert_eq!(accepted.market().token_a(), &tokens()[0].0);
    }

    /// Fetched bytes are accepted only as the bytes the owner's creation
    /// carried: another genesis for the same vault, and a transition that
    /// created no vault, bind nothing.
    #[test]
    fn a_genesis_the_owner_did_not_create_is_refused() {
        let mut c = valid();
        let mut other = VaultGenesisPreimage::decode(&c.preimage_bytes).unwrap();
        other.state.reserve_a += 1;
        c.preimage_bytes = other.encode().unwrap();
        assert_eq!(
            accept(&c),
            Err(GenesisRefusal::Invalid(
                GenesisInvalid::NotTheCreationTheOwnerMade
            ))
        );

        let mut c = valid();
        c.operation = Operation::Noop;
        assert_eq!(
            accept(&c),
            Err(GenesisRefusal::Invalid(
                GenesisInvalid::NotTheCreationTheOwnerMade
            ))
        );
    }

    /// The validated transition must be the owner's at `p_create`: the
    /// owner's transition at another position creates nothing at `v`.
    #[test]
    fn a_transition_at_another_position_is_not_the_creation() {
        assert_eq!(
            accept_at(&valid(), P_CREATE + 1),
            Err(GenesisRefusal::Invalid(
                GenesisInvalid::NotTheOwnersCreationPosition
            ))
        );
    }

    #[test]
    fn a_genesis_past_generation_zero_is_refused() {
        let pair = (tokens()[0].0, tokens()[1].0);
        let (mut state, market_bytes) = genesis_state(pair);
        state.generation = 3;
        assert_eq!(
            accept(&creation_of(state, market_bytes, pair)),
            Err(GenesisRefusal::Invalid(GenesisInvalid::NotGenerationZero {
                generation: 3
            }))
        );
    }

    #[test]
    fn a_retired_genesis_is_refused() {
        let pair = (tokens()[0].0, tokens()[1].0);
        let (mut state, market_bytes) = genesis_state(pair);
        state.status = VAULT_STATUS_RETIRED;
        assert_eq!(
            accept(&creation_of(state, market_bytes, pair)),
            Err(GenesisRefusal::Invalid(GenesisInvalid::NotActive {
                status: VAULT_STATUS_RETIRED
            }))
        );
    }

    #[test]
    fn a_genesis_on_another_storage_set_is_refused() {
        let pair = (tokens()[0].0, tokens()[1].0);
        let (mut state, market_bytes) = genesis_state(pair);
        state.storage_set_id = [0x77; 32];
        assert_eq!(
            accept(&creation_of(state, market_bytes, pair)),
            Err(GenesisRefusal::Invalid(GenesisInvalid::NotThePinnedSet {
                named: [0x77; 32],
                pinned: pinned_set(),
            }))
        );
    }

    /// The market the vault trades is the policy `V_0` commits: bytes of
    /// another market carried beside it establish nothing about this vault.
    #[test]
    fn a_carried_market_that_is_not_the_committed_one_is_refused() {
        let pair = (tokens()[0].0, tokens()[1].0);
        let (state, market_bytes) = genesis_state(pair);
        let other = MarketPolicy::beta_constant_product(tokens()[1].0, tokens()[2].0)
            .unwrap()
            .encode();
        assert_ne!(other, market_bytes);
        assert_eq!(
            accept(&creation_of(state, other, pair)),
            Err(GenesisRefusal::Invalid(GenesisInvalid::Market(
                GenesisError::MarketPolicyIsNotTheCommittedOne
            )))
        );
    }

    /// A token policy not in hand, or bytes that are another token's, leave
    /// acceptance without an answer; neither is a refusal of the vault.
    #[test]
    fn a_token_policy_not_in_hand_is_missing() {
        let mut c = valid();
        let token_b = tokens()[1].0;
        c.token_policies.remove(&token_b);
        assert_eq!(
            accept(&c),
            Err(GenesisRefusal::Missing(GenesisMissing::TokenPolicy {
                commit: token_b
            }))
        );
        c.token_policies.insert(token_b, tokens()[2].1.clone());
        assert_eq!(
            accept(&c),
            Err(GenesisRefusal::Missing(GenesisMissing::TokenPolicy {
                commit: token_b
            }))
        );
    }

    /// §49: `transferable` binds vault creation, whichever side the token is.
    #[test]
    fn a_vault_over_a_token_that_forbids_transfer_is_refused() {
        let locked = committed(token_policy_bytes_with(9, 0));
        let mut pair = [tokens()[0].0, locked.0];
        pair.sort();
        let pair = (pair[0], pair[1]);
        let (state, market_bytes) = genesis_state(pair);
        let mut c = creation_of(state, market_bytes, pair);
        c.token_policies.insert(locked.0, locked.1);
        assert_eq!(
            accept(&c),
            Err(GenesisRefusal::Invalid(
                GenesisInvalid::TokenNotTransferable { token: locked.0 }
            ))
        );
    }

    /// ERA is pre-rooted: a vault over it consults no ERA policy.
    #[test]
    fn a_pre_rooted_token_consults_no_policy() {
        let era = crate::core::token::token_state_manager::era_policy_commit();
        let mut pair = [tokens()[0].0, era];
        pair.sort();
        let pair = (pair[0], pair[1]);
        let (state, market_bytes) = genesis_state(pair);
        let mut c = creation_of(state, market_bytes, pair);
        c.token_policies
            .retain(|commit, _| *commit == tokens()[0].0);
        assert!(accept(&c).is_ok());
    }
}
