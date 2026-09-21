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
    VaultStateLeaf,
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

/// Why a vault's market policy is not the one its genesis state commits.
///
/// WHAT THIS NO LONGER IS. It was the refusal set of `genesis_accepted`, a
/// twelve-conjunct predicate that established a vault genesis from a
/// PRESENTED creation operation. That predicate could never acquire a
/// production caller — `VaultCreation` carries no asset commitments, so
/// proving the creation leaf establishes the AMOUNTS and never which balances
/// were debited — and a CI gate existed to keep it callerless. Owner ruling
/// Section 44.4 settled it: the standalone production predicate was the stale
/// piece, not the gate. Genesis validity is established by the vault genesis
/// constructor and recognizer with the accepted genesis root, the predicate
/// survives as the formal definition (`lean4/DSMSofiAtomicity.lean`,
/// `GenesisAccepted`; `tla/DSM_SofiFulfillment.tla`,
/// `GenesisCanonicalOnlyIfCreationValid`), and what remains here is the
/// market-policy half that `build_vault_create` actually uses.
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
            advance_resolved(&previous(pre), &p, &f, &claims(&p, &f), Resolution::Invalid),
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
            },
            AdmittedEconomicPosition::ResolvedSofi {
                economic_position: 4,
                selected_root: d(0xA0),
                fulfillment_id: d(0xF1),
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
