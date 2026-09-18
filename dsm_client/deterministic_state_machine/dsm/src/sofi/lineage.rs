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

use super::derive;
use crate::economic::tree::ECONOMIC_SMT_HEIGHT;
use super::resolution::Resolution;
use super::wire::{
    next_position, ParentClaimRef, SofiWireError, TraderFulfillmentBody, TraderPrecommitBody,
    VaultCreation, VaultGenesisPreimage, VaultStateLeaf, VAULT_STATUS_ACTIVE,
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
    /// The position has not resolved, so there is nothing to install.
    NotResolved,
    /// The position resolved Invalid: the lineage is terminal here, and no
    /// root follows it.
    LineageIsTerminal,
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
            Self::NotResolved => write!(f, "the position has not resolved"),
            Self::LineageIsTerminal => {
                write!(f, "the position resolved Invalid: no root follows it")
            }
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
) -> Result<ValidatedEconomicRoot, AdvanceError> {
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
    let root = match resolution {
        Resolution::Realized => *precommit.realize_root(),
        // Zero mutations: the lineage continues exactly where it was.
        Resolution::Void => previous.economic_root(),
        Resolution::Invalid => return Err(AdvanceError::LineageIsTerminal),
        Resolution::Pending => return Err(AdvanceError::NotResolved),
    };
    Ok(ValidatedEconomicRoot::from_resolved_sofi_position(q, root))
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
    /// A conditional claim that resolved Invalid: no root was selected, and
    /// none ever will be.
    ConditionalTerminal,
}

/// Why a descendant may not be built on this predecessor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FenceError {
    /// The predecessor is conditional and undecided. A descendant built now
    /// would be built on a root the lineage has not chosen.
    PredecessorIsUnresolved,
    /// The predecessor resolved Invalid: the lineage ends there.
    PredecessorIsTerminal,
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
            Self::PredecessorIsTerminal => {
                write!(
                    f,
                    "the predecessor resolved Invalid: the lineage ends there"
                )
            }
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
/// **This is the predicate, not yet the fence.** It decides a claim correctly
/// and refuses one it cannot, but no descendant admission path calls it: the
/// registered-claim kind is still `SingleRoot`-only, so there is nothing that
/// hands it a `PredecessorClaim::Conditional` in production. E1c introduces
/// `RegisteredEconomicClaim::ConditionalSofi(C_q)` and wires this into every
/// descendant admission path. Until then the rule is implemented and proven,
/// and it is not enforced.
pub fn descendant_fence(
    predecessor: PredecessorClaim,
    descendant_pre_root: &D32,
) -> Result<(), FenceError> {
    match predecessor {
        PredecessorClaim::SingleRoot => Ok(()),
        PredecessorClaim::ConditionalUnresolved => Err(FenceError::PredecessorIsUnresolved),
        PredecessorClaim::ConditionalTerminal => Err(FenceError::PredecessorIsTerminal),
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

/// The funding pair a `SofiVaultCreate` STATES, extracted from the operation
/// itself.
///
/// **Not a tuple, on purpose.** `genesis_accepted` previously took
/// `(D32, D32)`, which a caller could simply assert — and the evidence the
/// predicate holds cannot contradict it: `VaultCreation` carries
/// `vault_id`, `genesis_root`, `amount_a`, `amount_b` and NO asset commits,
/// so proving the creation leaf into the owner's root establishes the AMOUNTS
/// and never which balances were debited. A caller handing `(A, B)` for a
/// creation that actually debited `X/Y` would be believed.
///
/// The only constructor reads the pair off the signed operation, so it cannot
/// be conjured. What it deliberately does NOT establish is that this
/// operation is the accepted creation transition at `p_create` — see the
/// blocker on [`genesis_accepted`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CreationFunding {
    a: D32,
    b: D32,
}

impl CreationFunding {
    /// The pair as the signed operation states it, or `None` for anything
    /// that is not a vault creation.
    pub fn from_operation(operation: &crate::types::operations::Operation) -> Option<Self> {
        match operation {
            crate::types::operations::Operation::SofiVaultCreate {
                funding_a_policy_commit,
                funding_b_policy_commit,
                ..
            } => Some(Self {
                a: *funding_a_policy_commit,
                b: *funding_b_policy_commit,
            }),
            _ => None,
        }
    }

    pub fn pair(&self) -> (D32, D32) {
        (self.a, self.b)
    }
}

/// Why a vault's genesis is not acceptable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GenesisError {
    /// `vault_id` is not the owner's own derivation at the inserting position.
    VaultIdIsNotTheDerivation { expected: D32, named: D32 },
    /// `V_0` is not exactly `VaultState_0`: a generation, a status, or a
    /// relationship leaf that has no business in a genesis.
    GenesisStateIsNotInitial,
    /// The funded amounts are not the reserves the genesis state commits.
    FundingIsNotTheReserves,
    /// The recomputed `R_0` is not the root the creation record names.
    GenesisRootMismatch { expected: D32, named: D32 },
    /// The pair is not strictly ordered, so the market policy would admit two
    /// encodings of one market.
    TokenPairNotOrdered,
    /// The vault is pinned to a storage set that is not this network's.
    StorageSetIsNotNetworkPinned,
    /// The owner's root at the inserting position is not validated.
    OwnerRootIsNotValidated { validated: u64, create: u64 },
    /// The supplied market-policy bytes do not re-derive the address the vault
    /// state commits. They establish nothing about this vault's market:
    /// non-verifying bytes are not evidence, they are noise.
    MarketPolicyIsNotTheCommittedOne,
    /// The market-policy bytes are not a canonical `MarketPolicy`.
    MarketPolicyDoesNotDecode,
    /// The operation funds the creation from assets that are not the vault's
    /// own pair, or names them out of canonical order.
    FundingIsNotTheMarketPair,
    /// The creation record is not committed under the owner's validated root.
    /// A vault whose creation nothing proves was never created on this lineage.
    CreationIsNotCommitted,
}

impl core::fmt::Display for GenesisError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::VaultIdIsNotTheDerivation { .. } => {
                write!(
                    f,
                    "vault_id is not H(vault-id/v1 ‖ G_o ‖ DevID_o ‖ p_create)"
                )
            }
            Self::GenesisStateIsNotInitial => {
                write!(f, "V_0 is not the initial state a genesis fixes")
            }
            Self::FundingIsNotTheReserves => {
                write!(f, "the funded amounts are not the committed reserves")
            }
            Self::GenesisRootMismatch { .. } => write!(f, "R_0 is not the recomputed genesis root"),
            Self::TokenPairNotOrdered => write!(f, "the token pair is not strictly ordered"),
            Self::StorageSetIsNotNetworkPinned => {
                write!(f, "the vault's storage set is not the network's pinned set")
            }
            Self::OwnerRootIsNotValidated { .. } => {
                write!(f, "the owner's root at p_create is not validated")
            }
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
            Self::FundingIsNotTheMarketPair => write!(
                f,
                "the creation is funded from assets that are not the vault's own pair, \
                 in canonical order"
            ),
            Self::CreationIsNotCommitted => write!(
                f,
                "the creation record does not prove into the owner's validated root: \
                 nothing shows this vault was created on that lineage"
            ),
        }
    }
}

impl std::error::Error for GenesisError {}

/// `GenesisAccepted` (P15-12, F10): the conjunction that turns stored genesis
/// bytes into a vault a route may reference.
///
/// `GenesisStored` is mechanical and is a storage member's business. This is
/// the verifier's, and every conjunct is checked against something it derived
/// or already validated — the vault id from the owner's identity, `R_0` from
/// the state, the reserves from the creation record, the storage set from the
/// network, and the owner's position from its own validated lineage.
///
/// # E2 BLOCKER — a genesis is NOT yet consumable on this evidence alone
///
/// This predicate has no production caller, and it must not acquire a naive
/// one. The evidence it holds does not establish **which balances the
/// creation actually debited**:
///
/// - `VaultCreation` carries `vault_id`, `genesis_root`, `amount_a`,
///   `amount_b` — and no asset commits. Proving that leaf into the owner's
///   validated root therefore establishes the AMOUNTS, never the assets.
/// - [`CreationFunding`] reads the pair off a signed `SofiVaultCreate`, which
///   stops a caller inventing one, but does NOT establish that the operation
///   it came from is the accepted creation transition at `p_create`.
///
/// So a vault whose policy names `A/B`, created by an operation that actually
/// debited `X/Y`, could still be accepted here by handing in that operation's
/// own `A/B`-shaped sibling. That is not "the owner made a useless vault" —
/// it is an asset-provenance and conservation failure.
///
/// F10 must therefore derive the pair from the EXACT verified creation
/// transition, not from an operation presented alongside the leaf:
///
/// ```text
/// exact accepted owner transition at p_create
///     -> exact verified SofiVaultCreate
///     -> funding_{a,b}_policy_commit
///     -> verified write set produced the creation transition
///     -> exact VaultCreation insertion
///     -> owner validated lineage
/// ```
///
/// and only then compare that pair with the one the authenticated market
/// policy decodes. The intended shape is an opaque `VerifiedVaultCreation`
/// capability whose sole constructor establishes the accepted transition,
/// with this function consuming it instead of a `CreationFunding`. Missing
/// transition, policy or path evidence is `Unavailable`; authenticated
/// disagreement is `Invalid`.
///
/// No byte change is owed: `SofiVaultCreate` already signs both funding
/// commits in its canonical unsigned bytes, so the information the proof
/// needs is frozen in the right object. What is owed is the binding from that
/// signed operation to the economically accepted owner transition.
pub fn genesis_accepted(
    preimage: &VaultGenesisPreimage,
    creation: &VaultCreation,
    owner_validated: &ValidatedEconomicRoot,
    network_storage_set_id: &D32,
    // `market_policy_bytes`: the EXACT bytes of the market policy the vault
    // state commits. Not a pair and not a decoded policy — either would be the
    // caller's assertion about this vault's market, and this function would be
    // trusting the thing it exists to establish. They are re-addressed against
    // `VaultStateLeaf.market_policy` before anything is read out of them.
    //
    // `funding`: the two commits, read off the signed operation by
    // `CreationFunding::from_operation` and checked against the pair the
    // authenticated policy decodes — never used AS the pair, and no longer
    // assertable as a bare tuple.
    //
    // `creation_siblings`: the path proving the creation leaf into the owner's
    // validated root.
    market_policy_bytes: &[u8],
    funding: CreationFunding,
    creation_siblings: &[D32; ECONOMIC_SMT_HEIGHT],
) -> Result<D32, GenesisError> {
    let vault_id = preimage.vault_id();
    if creation.vault_id != vault_id {
        return Err(GenesisError::VaultIdIsNotTheDerivation {
            expected: vault_id,
            named: creation.vault_id,
        });
    }
    let state = &preimage.state;
    if state.owner_genesis != preimage.owner_genesis
        || state.owner_device_id != preimage.owner_device_id
        || state.create_position != preimage.create_position
    {
        return Err(GenesisError::GenesisStateIsNotInitial);
    }
    // Generation 0, Active, and both reserves funded: a genesis has no history
    // to carry and nothing may have happened to it yet.
    if state.generation != 0 || state.status != VAULT_STATUS_ACTIVE {
        return Err(GenesisError::GenesisStateIsNotInitial);
    }
    if state.reserve_a != creation.amount_a || state.reserve_b != creation.amount_b {
        return Err(GenesisError::FundingIsNotTheReserves);
    }
    if state.reserve_a == 0 || state.reserve_b == 0 {
        return Err(GenesisError::GenesisStateIsNotInitial);
    }
    // THE PAIR IS DERIVED, NOT ACCEPTED. Re-address the bytes under the market
    // policy's own namespace and require them to be the address the vault
    // state commits; only then read a pair out of them. Bytes that do not
    // re-derive establish nothing at all.
    let derived_addr = crate::ccb::decode::policy_object_address(
        crate::ccb::class::MARKET_POLICY,
        market_policy_bytes,
    )
    .ok_or(GenesisError::MarketPolicyDoesNotDecode)?;
    if derived_addr != state.market_policy {
        return Err(GenesisError::MarketPolicyIsNotTheCommittedOne);
    }
    let market = crate::ccb::decode::decode_market_policy(market_policy_bytes)
        .map_err(|_| GenesisError::MarketPolicyDoesNotDecode)?;
    let (token_a, token_b) = (*market.token_a(), *market.token_b());
    if token_a >= token_b {
        return Err(GenesisError::TokenPairNotOrdered);
    }
    // The signed operation funds the creation from exactly that pair, in that
    // order. The commits are execution coordinates; this is where they are
    // held to the authority.
    if funding.pair() != (token_a, token_b) {
        return Err(GenesisError::FundingIsNotTheMarketPair);
    }
    if state.storage_set_id != *network_storage_set_id {
        return Err(GenesisError::StorageSetIsNotNetworkPinned);
    }
    // THE CREATION IS PROVEN INTO THE OWNER'S VALIDATED ROOT.
    //
    // The position comparison this replaces established only that the owner's
    // lineage had reached `p_create` — it never read the root, so a genesis
    // whose creation was never committed, or was committed in a transition the
    // lineage later abandoned, passed on the counter alone.
    //
    // What proves it is the leaf itself: the creation record is insert-only at
    // `vault_creation_key(G_o, DevID_o, v)`, so its presence under a root this
    // verifier has validated IS the statement that this vault was created on
    // this lineage. The key is derived from the owner's coordinates rather
    // than supplied, and the leaf value is recomputed from the record — a
    // caller supplies only the path.
    if owner_validated.economic_position() < preimage.create_position {
        return Err(GenesisError::OwnerRootIsNotValidated {
            validated: owner_validated.economic_position(),
            create: preimage.create_position,
        });
    }
    let creation_key = derive::vault_creation_key(
        &preimage.owner_genesis,
        &preimage.owner_device_id,
        &vault_id,
    );
    let creation_value = crate::economic::state::EconomicLeafState::VaultCreation(*creation)
        .leaf_value()
        .map_err(|_| GenesisError::CreationIsNotCommitted)?;
    let proved = crate::economic::tree::root_from_path(
        &creation_key,
        &crate::economic::tree::leaf_node(&creation_key, Some(&creation_value)),
        creation_siblings,
    );
    if proved != owner_validated.economic_root() {
        return Err(GenesisError::CreationIsNotCommitted);
    }
    // `V_0` holds exactly the state leaf and nothing else, so `R_0` is a pure
    // function of the genesis state.
    let root =
        genesis_root(&vault_id, state).map_err(|_| GenesisError::GenesisStateIsNotInitial)?;
    if creation.genesis_root != root {
        return Err(GenesisError::GenesisRootMismatch {
            expected: root,
            named: creation.genesis_root,
        });
    }
    Ok(vault_id)
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
            },
        )
        .expect("an ordinary admitted position")
    }

    #[test]
    fn a_realized_position_installs_the_realize_root() {
        let pre = d(0xA0);
        let realize = d(0xA1);
        let p = precommit(pre, realize);
        let f = fulfillment(&p);
        let advanced = advance_resolved(
            &previous(pre),
            &p,
            &f,
            &claims(&p, &f),
            Resolution::Realized,
        )
        .unwrap();
        assert_eq!(advanced.economic_position(), P_POS + 1);
        assert_eq!(advanced.economic_root(), realize);
    }

    /// SofiVoid has zero mutations: the position exists, it is terminal, and
    /// the lineage continues exactly where it was.
    #[test]
    fn a_void_position_installs_the_previous_root() {
        let pre = d(0xA0);
        let p = precommit(pre, d(0xA1));
        let f = fulfillment(&p);
        let advanced =
            advance_resolved(&previous(pre), &p, &f, &claims(&p, &f), Resolution::Void).unwrap();
        assert_eq!(advanced.economic_position(), P_POS + 1);
        assert_eq!(advanced.economic_root(), pre);
    }

    #[test]
    fn an_unresolved_or_invalid_position_installs_nothing() {
        let pre = d(0xA0);
        let p = precommit(pre, d(0xA1));
        let f = fulfillment(&p);
        assert_eq!(
            advance_resolved(&previous(pre), &p, &f, &claims(&p, &f), Resolution::Pending),
            Err(AdvanceError::NotResolved)
        );
        assert_eq!(
            advance_resolved(&previous(pre), &p, &f, &claims(&p, &f), Resolution::Invalid),
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
                    },
                )
                .expect("an ordinary admitted position"),
                &p,
                &f,
                &good,
                Resolution::Realized
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
            advance_resolved(&previous(pre), &p, &wrong_q, &good, Resolution::Realized),
            Err(AdvanceError::PositionIsNotSuccessor { .. })
        ));

        // P was built on another root (P15-2).
        assert!(matches!(
            advance_resolved(&previous(d(0xBB)), &p, &f, &good, Resolution::Realized),
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
            advance_resolved(&previous(pre), &p, &f, &other_parent, Resolution::Realized),
            Err(AdvanceError::ParentClaimMismatch)
        );

        // C_q is DERIVED, so a register holding anything else is refused.
        let other_cq = RegisteredClaims {
            conditional: d(0x5A),
            ..good
        };
        assert!(matches!(
            advance_resolved(&previous(pre), &p, &f, &other_cq, Resolution::Realized),
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
                Resolution::Realized
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

    /// The market policy this vault commits, and its content address. The
    /// address is DERIVED from the bytes, so the fixture cannot hand
    /// `genesis_accepted` a pair that the policy does not actually say.
    /// The funding pair as the SIGNED OPERATION states it — the only way to
    /// obtain one, so a test cannot assert a pair production could not.
    fn funding(a: D32, b: D32) -> CreationFunding {
        CreationFunding::from_operation(&crate::types::operations::Operation::SofiVaultCreate {
            genesis_preimage: Vec::new(),
            creation: Vec::new(),
            funding_a_policy_commit: a,
            funding_b_policy_commit: b,
            signature: Vec::new(),
        })
        .expect("a creation")
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

    /// The owner's validated root WITH the creation record committed in it,
    /// plus the path that proves it. This is the shape P15-12 requires: the
    /// record is a leaf, and its inclusion is the proof the vault was created.
    fn owner_root_committing(
        preimage: &VaultGenesisPreimage,
        creation: &VaultCreation,
    ) -> (ValidatedEconomicRoot, [D32; ECONOMIC_SMT_HEIGHT]) {
        let key = derive::vault_creation_key(
            &preimage.owner_genesis,
            &preimage.owner_device_id,
            &preimage.vault_id(),
        );
        let value = crate::economic::state::EconomicLeafState::VaultCreation(*creation)
            .leaf_value()
            .unwrap();
        let mut tree = crate::economic::tree::EconomicSmt::new();
        tree.insert(key, value);
        let validated = ValidatedEconomicRoot::rehydrate_from_admitted_store(
            crate::economic::lineage::AdmittedEconomicPosition::SingleRoot {
                economic_position: P_POS,
                economic_root: tree.root(),
            },
        )
        .expect("an ordinary admitted position");
        (validated, tree.siblings(&key))
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

    /// A WELL-FORMED GENESIS IS ACCEPTED — with the market pair DERIVED from
    /// authenticated policy bytes and the creation record PROVEN into the
    /// owner's validated root.
    #[test]
    fn a_well_formed_genesis_is_accepted() {
        let (preimage, creation) = genesis_parts();
        let (_, policy_bytes, _) = market();
        let (owner, path) = owner_root_committing(&preimage, &creation);
        assert_eq!(
            genesis_accepted(
                &preimage,
                &creation,
                &owner,
                &d(0x77),
                &policy_bytes,
                funding(d(0x40), d(0x41)),
                &path,
            ),
            Ok(preimage.vault_id())
        );
    }

    /// THE PAIR IS NOT THE CALLER'S TO ASSERT. Bytes that do not re-derive the
    /// address the vault state commits establish nothing — they are not this
    /// vault's market, whatever pair they happen to contain.
    #[test]
    fn market_policy_bytes_that_are_not_the_committed_ones_establish_nothing() {
        let (preimage, creation) = genesis_parts();
        let (owner, path) = owner_root_committing(&preimage, &creation);
        // A perfectly valid policy — for a different market.
        let other = crate::ccb::state::MarketPolicy::beta_constant_product(d(0x50), d(0x51))
            .unwrap()
            .encode();
        assert_eq!(
            genesis_accepted(
                &preimage,
                &creation,
                &owner,
                &d(0x77),
                &other,
                funding(d(0x50), d(0x51)),
                &path,
            ),
            Err(GenesisError::MarketPolicyIsNotTheCommittedOne)
        );
        // Bytes that are not a policy at all.
        assert_eq!(
            genesis_accepted(
                &preimage,
                &creation,
                &owner,
                &d(0x77),
                &[0xAB; 8],
                funding(d(0x40), d(0x41)),
                &path,
            ),
            Err(GenesisError::MarketPolicyIsNotTheCommittedOne)
        );
    }

    /// The signed funding commits are held to the AUTHENTICATED pair, in
    /// canonical order. They are execution coordinates, not a second market.
    #[test]
    fn funding_must_be_the_authenticated_pair_in_order() {
        let (preimage, creation) = genesis_parts();
        let (_, policy_bytes, _) = market();
        let (owner, path) = owner_root_committing(&preimage, &creation);
        for (wa, wb) in [
            (d(0x40), d(0x42)), // one asset is not the vault's
            (d(0x41), d(0x40)), // the pair, reversed
            (d(0x50), d(0x51)), // another market entirely
        ] {
            let wrong = funding(wa, wb);
            assert_eq!(
                genesis_accepted(
                    &preimage,
                    &creation,
                    &owner,
                    &d(0x77),
                    &policy_bytes,
                    wrong,
                    &path,
                ),
                Err(GenesisError::FundingIsNotTheMarketPair)
            );
        }
    }

    /// THE FUNDING PAIR CANNOT BE CONJURED — and what that still leaves open.
    ///
    /// `CreationFunding`'s only constructor reads the pair off a signed
    /// `SofiVaultCreate`, so no caller can hand `genesis_accepted` a pair from
    /// thin air. That is the half this branch closes.
    ///
    /// The half it does NOT close, asserted here so the gap is a test rather
    /// than only prose: the creation record carries no asset commits, so
    /// proving the leaf into the owner's root says nothing about WHICH
    /// balances were debited. Two operations that debit different assets
    /// produce the SAME creation record, hence the same leaf and the same
    /// inclusion proof. Only binding the funding pair to the exact accepted
    /// creation transition closes it, and that is E2's.
    #[test]
    fn the_funding_pair_comes_from_an_operation_but_is_not_yet_bound_to_the_transition() {
        // Not conjurable: only a creation yields one.
        assert!(
            CreationFunding::from_operation(&crate::types::operations::Operation::Noop).is_none()
        );
        assert_eq!(funding(d(0x40), d(0x41)).pair(), (d(0x40), d(0x41)));

        // THE OPEN GAP. The same creation record — same leaf, same inclusion
        // proof — is produced whichever assets the operation debits.
        let (preimage, creation) = genesis_parts();
        let (_, policy_bytes, _) = market();
        let (owner, path) = owner_root_committing(&preimage, &creation);

        let honest = funding(d(0x40), d(0x41));
        let dishonest = funding(d(0x50), d(0x51));
        assert_ne!(honest.pair(), dishonest.pair());

        // The predicate distinguishes them only because the PAIR differs...
        assert_eq!(
            genesis_accepted(
                &preimage,
                &creation,
                &owner,
                &d(0x77),
                &policy_bytes,
                honest,
                &path
            ),
            Ok(preimage.vault_id())
        );
        assert_eq!(
            genesis_accepted(
                &preimage,
                &creation,
                &owner,
                &d(0x77),
                &policy_bytes,
                dishonest,
                &path
            ),
            Err(GenesisError::FundingIsNotTheMarketPair)
        );
        // ...and NOT because the leaf says anything about assets: the record
        // accepted in both calls is byte-identical.
        assert_eq!(creation.encode(), creation.encode());
        let record = crate::sofi::wire::VaultCreation::decode(&creation.encode()).unwrap();
        assert_eq!(record, creation);
        // A record naming assets would have a field for them. It has none.
        assert_eq!(
            creation.encode().len(),
            4 + 32 + 32 + 8 + 8,
            "vault_id, genesis_root, amount_a, amount_b — and no asset commits"
        );
    }

    /// Every other genesis conjunct still refuses on its own. Restored after
    /// the signature change: a rewrite is not a licence to drop coverage.
    #[test]
    fn genesis_is_refused_on_each_missing_check() {
        let (preimage, creation) = genesis_parts();
        let (_, policy_bytes, _) = market();
        let (owner, path) = owner_root_committing(&preimage, &creation);
        let pair = funding(d(0x40), d(0x41));
        let run = |pre: &VaultGenesisPreimage,
                   c: &VaultCreation,
                   own: &ValidatedEconomicRoot,
                   set: &D32,
                   sib: &[D32; ECONOMIC_SMT_HEIGHT]| {
            genesis_accepted(pre, c, own, set, &policy_bytes, pair, sib)
        };

        // A creation naming another vault.
        let other = VaultCreation {
            vault_id: d(0x09),
            ..creation
        };
        assert!(matches!(
            run(&preimage, &other, &owner, &d(0x77), &path),
            Err(GenesisError::VaultIdIsNotTheDerivation { .. })
        ));

        // A genesis with history.
        let aged = VaultGenesisPreimage {
            state: genesis_state(1_000, 2_000, 1),
            ..preimage.clone()
        };
        let aged_creation = VaultCreation {
            vault_id: aged.vault_id(),
            genesis_root: genesis_root(&aged.vault_id(), &aged.state).unwrap(),
            ..creation
        };
        let (aged_owner, aged_path) = owner_root_committing(&aged, &aged_creation);
        assert_eq!(
            run(&aged, &aged_creation, &aged_owner, &d(0x77), &aged_path),
            Err(GenesisError::GenesisStateIsNotInitial)
        );

        // Funding that is not the reserves.
        let underfunded = VaultCreation {
            amount_a: 999,
            ..creation
        };
        let (under_owner, under_path) = owner_root_committing(&preimage, &underfunded);
        assert_eq!(
            run(&preimage, &underfunded, &under_owner, &d(0x77), &under_path),
            Err(GenesisError::FundingIsNotTheReserves)
        );

        // Another network's storage set.
        assert_eq!(
            run(&preimage, &creation, &owner, &d(0x7F), &path),
            Err(GenesisError::StorageSetIsNotNetworkPinned)
        );

        // An owner whose lineage has not reached the inserting position.
        let behind = ValidatedEconomicRoot::rehydrate_from_admitted_store(
            crate::economic::lineage::AdmittedEconomicPosition::SingleRoot {
                economic_position: P_POS - 1,
                economic_root: owner.economic_root(),
            },
        )
        .expect("an ordinary admitted position");
        assert!(matches!(
            run(&preimage, &creation, &behind, &d(0x77), &path),
            Err(GenesisError::OwnerRootIsNotValidated { .. })
        ));
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

    /// THE CREATION MUST BE COMMITTED. A position counter cannot distinguish a
    /// creation that happened from one that did not: the record is insert-only
    /// at its own key, so its inclusion under a validated root IS the proof.
    #[test]
    fn a_creation_not_committed_under_the_owner_root_is_refused() {
        let (preimage, creation) = genesis_parts();
        let (_, policy_bytes, _) = market();
        let (owner, path) = owner_root_committing(&preimage, &creation);

        // The owner's lineage is at the right position and the root simply
        // does not contain the record — the exact case the old position-only
        // check accepted.
        let empty = ValidatedEconomicRoot::rehydrate_from_admitted_store(
            crate::economic::lineage::AdmittedEconomicPosition::SingleRoot {
                economic_position: P_POS,
                economic_root: crate::economic::tree::empty_economic_root(),
            },
        )
        .unwrap();
        assert_eq!(
            genesis_accepted(
                &preimage,
                &creation,
                &empty,
                &d(0x77),
                &policy_bytes,
                funding(d(0x40), d(0x41)),
                &path,
            ),
            Err(GenesisError::CreationIsNotCommitted)
        );

        // A DIFFERENT record at the same key does not prove this one: the leaf
        // value is recomputed from the record, never taken from the path.
        let other = VaultCreation {
            amount_a: creation.amount_a + 1,
            ..creation
        };
        assert_eq!(
            genesis_accepted(
                &preimage,
                &other,
                &owner,
                &d(0x77),
                &policy_bytes,
                funding(d(0x40), d(0x41)),
                &path,
            ),
            Err(GenesisError::FundingIsNotTheReserves)
        );
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

    #[test]
    fn a_terminal_predecessor_ends_the_lineage_and_an_ordinary_one_does_not_fence() {
        assert_eq!(
            descendant_fence(PredecessorClaim::ConditionalTerminal, &d(0xA0)),
            Err(FenceError::PredecessorIsTerminal)
        );
        assert_eq!(
            descendant_fence(PredecessorClaim::SingleRoot, &d(0xA0)),
            Ok(())
        );
    }

    /// The fence and the advance agree: a position that `advance_resolved`
    /// produced is exactly one a descendant may build on, and the root it
    /// installed is the only one admissible.
    #[test]
    fn the_fence_admits_exactly_what_the_advance_installed() {
        let pre = d(0xA0);
        let realize = d(0xA1);
        let p = precommit(pre, realize);
        let f = fulfillment(&p);
        for (resolution, expected) in [(Resolution::Realized, realize), (Resolution::Void, pre)] {
            let advanced =
                advance_resolved(&previous(pre), &p, &f, &claims(&p, &f), resolution).unwrap();
            assert_eq!(
                descendant_fence(
                    PredecessorClaim::ConditionalResolved {
                        selected_root: advanced.economic_root()
                    },
                    &expected
                ),
                Ok(())
            );
            // And the branch it did NOT take is refused.
            let other = if expected == realize { pre } else { realize };
            assert!(descendant_fence(
                PredecessorClaim::ConditionalResolved {
                    selected_root: advanced.economic_root()
                },
                &other
            )
            .is_err());
        }
    }
}
