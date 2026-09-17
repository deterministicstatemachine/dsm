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
pub fn genesis_accepted(
    preimage: &VaultGenesisPreimage,
    creation: &VaultCreation,
    owner_validated: &ValidatedEconomicRoot,
    network_storage_set_id: &D32,
    market_pair: (D32, D32),
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
    let (token_a, token_b) = market_pair;
    if token_a >= token_b {
        return Err(GenesisError::TokenPairNotOrdered);
    }
    if state.storage_set_id != *network_storage_set_id {
        return Err(GenesisError::StorageSetIsNotNetworkPinned);
    }
    // The owner's own lineage must already have validated the position that
    // inserts the creation; a genesis cannot bootstrap the owner.
    if owner_validated.economic_position() < preimage.create_position {
        return Err(GenesisError::OwnerRootIsNotValidated {
            validated: owner_validated.economic_position(),
            create: preimage.create_position,
        });
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
        ValidatedEconomicRoot::rehydrate_from_admitted_store(P_POS, root)
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
                &ValidatedEconomicRoot::rehydrate_from_admitted_store(P_POS + 3, pre),
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
            market_policy: d(0x31),
            fee_policy: d(0x32),
            release_policy: d(0x33),
            storage_set_id: d(0x77),
            generation,
            reserve_a,
            reserve_b,
            status: VAULT_STATUS_ACTIVE,
        }
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

    #[test]
    fn a_well_formed_genesis_is_accepted() {
        let (preimage, creation) = genesis_parts();
        let owner = ValidatedEconomicRoot::rehydrate_from_admitted_store(P_POS, d(0xA0));
        assert_eq!(
            genesis_accepted(&preimage, &creation, &owner, &d(0x77), (d(0x40), d(0x41))),
            Ok(preimage.vault_id())
        );
    }

    #[test]
    fn genesis_is_refused_on_each_missing_check() {
        let (preimage, creation) = genesis_parts();
        let owner = ValidatedEconomicRoot::rehydrate_from_admitted_store(P_POS, d(0xA0));
        let pair = (d(0x40), d(0x41));

        // A creation naming another vault.
        let other = VaultCreation {
            vault_id: d(0x09),
            ..creation
        };
        assert!(matches!(
            genesis_accepted(&preimage, &other, &owner, &d(0x77), pair),
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
        assert_eq!(
            genesis_accepted(&aged, &aged_creation, &owner, &d(0x77), pair),
            Err(GenesisError::GenesisStateIsNotInitial)
        );

        // Funding that is not the reserves.
        let underfunded = VaultCreation {
            amount_a: 999,
            ..creation
        };
        assert_eq!(
            genesis_accepted(&preimage, &underfunded, &owner, &d(0x77), pair),
            Err(GenesisError::FundingIsNotTheReserves)
        );

        // An unordered pair.
        assert_eq!(
            genesis_accepted(&preimage, &creation, &owner, &d(0x77), (d(0x41), d(0x40))),
            Err(GenesisError::TokenPairNotOrdered)
        );

        // Another network's storage set.
        assert_eq!(
            genesis_accepted(&preimage, &creation, &owner, &d(0x7F), pair),
            Err(GenesisError::StorageSetIsNotNetworkPinned)
        );

        // An owner whose lineage has not reached the inserting position.
        let behind = ValidatedEconomicRoot::rehydrate_from_admitted_store(P_POS - 1, d(0xA0));
        assert!(matches!(
            genesis_accepted(&preimage, &creation, &behind, &d(0x77), pair),
            Err(GenesisError::OwnerRootIsNotValidated { .. })
        ));

        // A root that is not the recomputed one.
        let bent = VaultCreation {
            genesis_root: d(0x5E),
            ..creation
        };
        assert!(matches!(
            genesis_accepted(&preimage, &bent, &owner, &d(0x77), pair),
            Err(GenesisError::GenesisRootMismatch { .. })
        ));
    }

    /// `R_0` holds the state leaf and NOTHING else: no relationship has been
    /// established with a vault nobody has traded with.
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

    /// P15-6: the trader's relationship leaf is an `R_econ` leaf like any
    /// other — one encoding, the SoFi key, and no amount to credit.
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
}
