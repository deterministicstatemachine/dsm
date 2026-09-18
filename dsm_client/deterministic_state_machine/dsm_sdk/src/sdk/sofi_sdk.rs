// SPDX-License-Identifier: MIT OR Apache-2.0

//! SoFi v8 producers: setup, vault creation, trade, route and close.
//!
//! No key material enters this module. Each producer hands back exactly what
//! must be signed and nothing else signs anything here, because a builder that
//! signed would be a second place where a signing rule is decided.
//!
//! ## Two signatures, two stages
//!
//! An exercise is signed TWICE, by design: `m_P` over the precommit, and `m_F`
//! over the fulfillment. They cannot be produced in one step — the canonical
//! policy-fulfillment set and the attempt vector are fixed against a P that is
//! already published and signed, which is the whole point of P being a
//! standalone content-addressed object. So the API is staged:
//!
//! ```text
//! draft_trade / draft_route / draft_close  ->  PrecommitDraft (gives m_P)
//!                    caller signs m_P
//! build_fulfillment(draft, p_signature, attempts)  ->  Produced (gives m_F)
//! ```
//!
//! The operation's own signature is a third thing and a frozen one: SPHINCS+
//! over `operation_signing_bytes`, the canonical encoding with the signature
//! cleared. Producers surface those bytes rather than inventing a digest.
//!
//! ## What a producer refuses
//!
//! Everything `sofi::admission` refuses — routes beyond the beta hop cap, and
//! the reserved DSM-succession authority (R16-6, R18-1) — AND everything a
//! verifier would call Invalid without needing any evidence. A producer that
//! emits an operation the validator will deterministically reject has produced
//! a way to strand a trader, not a trade.
//!
//! Dark: nothing calls these yet.

use dsm::core::state_machine::transition::operation_signing_bytes;
use dsm::sofi::admission::{admissible, NotAdmissible};
use dsm::sofi::conformance::{
    check_fulfillment_against_precommit, derive_policy_fulfillments, FulfillmentConformanceError,
};
use dsm::sofi::derive;
use dsm::sofi::validation::{validate, Evidence, Invalid, Refusal};
use dsm::sofi::wire::{
    AttemptEntry, DlvCore, OwnerAuthority, ParentClaimRef, PreEClosureIndex, PrecommitLeg,
    SettlementBody, SettlementPreimage, SofiSetupBody, SofiWireError, SwapHop, TraderCore,
    TraderFulfillmentBody, TraderPrecommitBody, VaultCreation, VaultGenesisPreimage,
};
use dsm::types::operations::Operation;

type D32 = [u8; 32];

/// Why an operation could not be produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BuildError {
    /// The objects do not have canonical bytes in this shape.
    Wire(SofiWireError),
    /// Beta will not execute this, so nothing here will build it.
    NotAdmissible(NotAdmissible),
    /// The fulfillment is not a mechanical fulfillment of its precommit.
    Conformance(FulfillmentConformanceError),
    /// A verifier would call this Invalid with no evidence at all, for this
    /// named reason. Producing it would hand the trader an operation that is
    /// already refused.
    StaticallyInvalid(Invalid),
    /// `P` must be signed before `F` can reference it: the fulfillment names a
    /// precommit that storage will refuse without its signature.
    PrecommitNotSigned,
}

impl core::fmt::Display for BuildError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Wire(e) => write!(f, "{e}"),
            Self::NotAdmissible(e) => write!(f, "{e}"),
            Self::Conformance(e) => write!(f, "{e:?}"),
            Self::StaticallyInvalid(reason) => write!(
                f,
                "a verifier refuses this operation with no evidence at all \
                 ({reason:?}); it is not a trade, it is a way to strand one"
            ),
            Self::PrecommitNotSigned => write!(
                f,
                "the precommit carries no signature: P is published and signed \
                 before F may reference it"
            ),
        }
    }
}

impl std::error::Error for BuildError {}

impl From<SofiWireError> for BuildError {
    fn from(e: SofiWireError) -> Self {
        Self::Wire(e)
    }
}

impl From<FulfillmentConformanceError> for BuildError {
    fn from(e: FulfillmentConformanceError) -> Self {
        Self::Conformance(e)
    }
}

/// A content-addressed object to publish, with the signature its ingress
/// checks. An unsigned `P` is refused by storage, so the two travel together.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishedObject {
    pub bytes: Vec<u8>,
    pub signature: Vec<u8>,
}

/// A produced operation: the transition, what must be published for anyone to
/// verify it, and the exact bytes the operation's signature covers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Produced {
    /// The operation, with an EMPTY signature.
    pub operation: Operation,
    /// The canonical unsigned operation bytes — what SPHINCS+ signs. This is
    /// the frozen rule the verifier implements, not a digest invented here.
    pub operation_signing_bytes: Vec<u8>,
    /// Objects a verifier needs and cannot derive.
    pub publish: Vec<PublishedObject>,
    /// `m_F` — the protocol digest the fulfillment envelope's signature
    /// covers. `None` for operations that carry no fulfillment.
    pub fulfillment_signing_digest: Option<D32>,
}

/// A precommit and its settlement preimage, built and checked, waiting for the
/// trader to sign `m_P`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrecommitDraft {
    precommit: TraderPrecommitBody,
    preimage: SettlementPreimage,
}

impl PrecommitDraft {
    /// `m_P` — what the trader signs to make this precommit publishable.
    pub fn precommit_signing_digest(&self) -> D32 {
        derive::precommit_signing_digest(&self.precommit)
    }

    /// `PrecommitId`, which `F` references and storage keys `P` by.
    pub fn precommit_id(&self) -> D32 {
        derive::precommit_id(&self.precommit)
    }

    pub fn precommit(&self) -> &TraderPrecommitBody {
        &self.precommit
    }

    pub fn preimage(&self) -> &SettlementPreimage {
        &self.preimage
    }

    /// `E`, as the preimage derives it.
    pub fn external_commitment(&self) -> D32 {
        *self.precommit.external_commitment()
    }
}

/// The relationship setup (F1). Non-economic: it establishes the right to
/// trade with one vault, and moves nothing.
pub fn build_setup(body: &SofiSetupBody) -> Result<Produced, BuildError> {
    let operation = Operation::SofiSetup {
        setup_body: body.encode(),
        signature: Vec::new(),
    };
    Ok(Produced {
        operation_signing_bytes: operation_signing_bytes(&operation),
        operation,
        publish: Vec::new(),
        fulfillment_signing_digest: None,
    })
}

/// The owner's vault creation at `p_create` (P15-12).
///
/// `vault_id` and `R_0` are recomputed from the preimage rather than accepted
/// from the caller, so a creation cannot name a vault its own identity does not
/// derive or a root its own state does not produce.
pub fn build_vault_create(
    preimage: &VaultGenesisPreimage,
    amount_a: u64,
    amount_b: u64,
) -> Result<Produced, BuildError> {
    let vault_id = preimage.vault_id();
    let creation = VaultCreation {
        vault_id,
        genesis_root: dsm::sofi::lineage::genesis_root(&vault_id, &preimage.state)?,
        amount_a,
        amount_b,
    };
    let operation = Operation::SofiVaultCreate {
        genesis_preimage: preimage.encode()?,
        creation: creation.encode(),
        signature: Vec::new(),
    };
    Ok(Produced {
        // The operation's OWN frozen rule. There is no separate vault-create
        // signing derivation in the registry, and inventing one here would be
        // a rule no verifier implements.
        operation_signing_bytes: operation_signing_bytes(&operation),
        operation,
        publish: Vec::new(),
        fulfillment_signing_digest: None,
    })
}

/// Everything a draft needs that is not the settlement itself.
#[derive(Debug, Clone)]
pub struct TraderContext<'a> {
    pub genesis: D32,
    pub device_id: D32,
    /// The trader's position `p`; the fulfillment lands at `p + 1`.
    pub position: u64,
    pub parent_claim: ParentClaimRef,
    pub storage_set_id: D32,
    pub signature_alg: u16,
    pub claimant_public_key: &'a [u8],
    /// `T°`, already built against the trader's own pre-root.
    pub trader_core: TraderCore,
}

/// Assemble `P(E)` and `P`, refusing anything beta will not run and anything a
/// verifier already calls Invalid.
fn draft(
    settlement: SettlementBody,
    ctx: &TraderContext<'_>,
    cores: Vec<DlvCore>,
    legs: Vec<PrecommitLeg>,
    realize_root: D32,
    void_root: D32,
) -> Result<PrecommitDraft, BuildError> {
    admissible(&settlement).map_err(BuildError::NotAdmissible)?;

    let preimage = SettlementPreimage::new(settlement, ctx.trader_core.clone(), cores)?;
    let e = derive::recompute_e(&preimage)?;
    let precommit = TraderPrecommitBody::new(
        ctx.genesis,
        ctx.device_id,
        ctx.position,
        ctx.parent_claim,
        e,
        legs,
        realize_root,
        void_root,
        ctx.storage_set_id,
        ctx.signature_alg,
        ctx.claimant_public_key,
    )?;

    // THE EVIDENCE-INDEPENDENT REFUSAL. With no evidence at all, a verifier
    // answers Unavailable for everything that needs a fetched object and
    // Invalid for everything it can already decide — route chaining, the ends
    // against the intent, the legs against the cores, E against the preimage.
    // Invalid here means the trader would be building something already
    // refused, so it is refused now instead.
    if let Err(Refusal::Invalid(reason)) = validate(&precommit, &preimage, &Evidence::default()) {
        return Err(BuildError::StaticallyInvalid(reason));
    }

    Ok(PrecommitDraft {
        precommit,
        preimage,
    })
}

/// A single-vault trade.
pub fn draft_trade(
    hop: SwapHop,
    core: DlvCore,
    ctx: &TraderContext<'_>,
    realize_root: D32,
    void_root: D32,
) -> Result<PrecommitDraft, BuildError> {
    draft_route(vec![hop], vec![core], ctx, realize_root, void_root)
}

/// A route over one or more vaults. Beta executes at most two hops, and this
/// refuses to build a third rather than leaving the trader holding an
/// operation nothing will run.
pub fn draft_route(
    hops: Vec<SwapHop>,
    cores: Vec<DlvCore>,
    ctx: &TraderContext<'_>,
    realize_root: D32,
    void_root: D32,
) -> Result<PrecommitDraft, BuildError> {
    let (first, last) = match (hops.first(), hops.last()) {
        (Some(f), Some(l)) => (*f, *l),
        _ => {
            return Err(BuildError::Wire(SofiWireError::Cardinality {
                field: "swap hops",
                min: 1,
                max: usize::MAX,
                got: 0,
            }))
        }
    };
    let mut sorted_cores = cores;
    sorted_cores.sort_by_key(|c| *c.vault_id());
    let core_digests: Vec<D32> = sorted_cores
        .iter()
        .map(|c| c.encode().map(|b| derive::dlv_core_digest(&b)))
        .collect::<Result<_, _>>()?;
    let mut legs: Vec<PrecommitLeg> = hops
        .iter()
        .map(|h| PrecommitLeg {
            vault_id: h.vault_id,
            parent_root: h.parent_root,
            setup_ref: h.setup_ref,
        })
        .collect();
    legs.sort_by_key(|l| l.vault_id);
    let settlement = SettlementBody::Swap {
        token_in: first.token_in,
        amount_in: first.amount_in,
        token_out: last.token_out,
        exact_out: last.amount_out,
        hops,
        trader_core: derive::trader_core_digest(&ctx.trader_core.encode()?),
        dlv_cores: core_digests,
        closure: PreEClosureIndex::new(Vec::new())?,
    };
    draft(settlement, ctx, sorted_cores, legs, realize_root, void_root)
}

/// A full close of one vault by its origin owner.
///
/// The authority is not a parameter: `OriginOwner` is the only branch this
/// protocol activates, and a producer that took the reserved branch as an
/// argument would be a way to build what nothing executes (R18-1).
#[allow(clippy::too_many_arguments)]
pub fn draft_close(
    vault_id: D32,
    parent_root: D32,
    setup_ref: D32,
    reserve_a: u64,
    reserve_b: u64,
    core: DlvCore,
    ctx: &TraderContext<'_>,
    realize_root: D32,
    void_root: D32,
) -> Result<PrecommitDraft, BuildError> {
    let settlement = SettlementBody::Close {
        vault_id,
        parent_root,
        setup_ref,
        owner_authority: OwnerAuthority::Origin,
        reserve_a,
        reserve_b,
        trader_core: derive::trader_core_digest(&ctx.trader_core.encode()?),
        dlv_core: derive::dlv_core_digest(&core.encode()?),
        closure: PreEClosureIndex::new(Vec::new())?,
    };
    draft(
        settlement,
        ctx,
        vec![core],
        vec![PrecommitLeg {
            vault_id,
            parent_root,
            setup_ref,
        }],
        realize_root,
        void_root,
    )
}

/// Stage two: the exercise, against a `P` the trader has already signed.
///
/// `attempts` is chosen HERE, at exercise time, against then-live keys — that
/// is why it is not part of the draft. The canonical policy-fulfillment set is
/// derived rather than supplied, and the whole thing is checked against `P`
/// before it is returned: a producer that emits a non-conforming `F` has built
/// something storage refuses at ingress.
pub fn build_fulfillment(
    draft: &PrecommitDraft,
    precommit_signature: Vec<u8>,
    attempts: &[(D32, u64)],
) -> Result<Produced, BuildError> {
    if precommit_signature.is_empty() {
        return Err(BuildError::PrecommitNotSigned);
    }
    let precommit = &draft.precommit;
    let shadow_cores: Vec<D32> = draft
        .preimage
        .dlv_cores()
        .iter()
        .map(|core| core.encode().map(|b| derive::dlv_core_digest(&b)))
        .collect::<Result<_, _>>()?;
    let mut policy_set: Vec<D32> = derive_policy_fulfillments(precommit, &shadow_cores)?
        .iter()
        .map(derive::policy_fulfillment_id)
        .collect();
    policy_set.sort();

    let mut attempt_entries: Vec<AttemptEntry> = attempts
        .iter()
        .map(|(vault_id, attempt)| AttemptEntry {
            vault_id: *vault_id,
            attempt: *attempt,
        })
        .collect();
    attempt_entries.sort_by_key(|a| a.vault_id);
    let fulfillment = TraderFulfillmentBody::new(
        derive::precommit_id(precommit),
        policy_set,
        attempt_entries,
        dsm::sofi::wire::next_position(precommit.position())?,
        precommit.signature_alg(),
        precommit.claimant_public_key(),
    )?;
    // The mechanical half of F ingress, run before the operation exists: a
    // complete canonical policy set, one attempt per leg, the successor
    // position, P's key.
    check_fulfillment_against_precommit(precommit, &fulfillment, &shadow_cores)?;

    let operation = Operation::SofiFulfill {
        fulfillment_body: fulfillment.encode(),
        precommit_id: derive::precommit_id(precommit).to_vec(),
        signature: Vec::new(),
    };
    Ok(Produced {
        operation_signing_bytes: operation_signing_bytes(&operation),
        operation,
        // P travels WITH its signature: storage refuses an unsigned one, and a
        // verifier checks it against the key the parent claim commits.
        publish: vec![
            PublishedObject {
                bytes: precommit.encode(),
                signature: precommit_signature,
            },
            PublishedObject {
                bytes: draft.preimage.encode()?,
                signature: Vec::new(),
            },
        ],
        fulfillment_signing_digest: Some(derive::fulfillment_signing_digest(&fulfillment)),
    })
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)] // test asserts; a failure here is the signal
mod tests {
    use super::*;
    use dsm::economic::keys::balance_key;
    use dsm::economic::tree::{EconomicSmt, ECONOMIC_SMT_HEIGHT};
    use dsm::sofi::wire::{CoreEntry, VaultStateLeaf, VAULT_STATUS_ACTIVE};

    const G: D32 = [0x11; 32];
    const DEV: D32 = [0x22; 32];
    const P_POS: u64 = 5;
    const ALG: u16 = 0x0001;
    const P_SIG: [u8; 8] = [0xAB; 8];
    const PRE_ROOT: D32 = [0x61; 32];
    const REL_BASE: D32 = [0x63; 32];

    fn d(byte: u8) -> D32 {
        [byte; 32]
    }

    fn path() -> Vec<D32> {
        vec![[0u8; 32]; ECONOMIC_SMT_HEIGHT]
    }

    fn balance(token: D32) -> CoreEntry {
        CoreEntry::Mutation {
            key: balance_key(&G, &DEV, &token),
            pre: d(0x41),
            post: d(0x42),
            path: path(),
        }
    }

    fn relationship(vault: D32) -> CoreEntry {
        CoreEntry::Relationship {
            genesis: G,
            device_id: DEV,
            vault_id: vault,
            base: REL_BASE,
            path: path(),
        }
    }

    /// `T°`, in the EXACT shape the branch permits: the intent's two endpoint
    /// movements and one relationship advancement per leg. A fixture with a
    /// different shape is refused by the write-set rule before anything else
    /// is examined, which is the point.
    fn trader_core(token_in: D32, token_out: D32, vaults: &[D32]) -> TraderCore {
        let mut entries = vec![balance(token_out), balance(token_in)];
        entries.extend(vaults.iter().map(|v| relationship(*v)));
        entries.sort_by_key(CoreEntry::key);
        TraderCore::new(G, DEV, P_POS + 1, PRE_ROOT, entries).unwrap()
    }

    /// `V°`: its own state leaf and the matching relationship advancement.
    fn dlv_core(vault: u8) -> DlvCore {
        let vault_id = d(vault);
        DlvCore::new(vault_id, d(0x62), G, DEV, REL_BASE, {
            let mut entries = vec![
                CoreEntry::Mutation {
                    key: dsm::sofi::derive::vault_state_key(&vault_id),
                    pre: d(0x51),
                    post: d(0x52),
                    path: path(),
                },
                relationship(vault_id),
            ];
            entries.sort_by_key(CoreEntry::key);
            entries
        })
        .unwrap()
    }

    /// A hop that actually chains: it gives out what the next hop takes in, at
    /// the amount the next hop consumes.
    fn hop(vault: u8, token_in: u8, amount_in: u64, token_out: u8, amount_out: u64) -> SwapHop {
        SwapHop {
            vault_id: d(vault),
            parent_root: d(0x62),
            setup_ref: d(0x55),
            token_in: d(token_in),
            amount_in,
            token_out: d(token_out),
            amount_out,
        }
    }

    fn ctx(core: TraderCore) -> TraderContext<'static> {
        TraderContext {
            genesis: G,
            device_id: DEV,
            position: P_POS,
            parent_claim: ParentClaimRef::SingleRoot { claim_ref: d(0x66) },
            storage_set_id: d(0x77),
            signature_alg: ALG,
            claimant_public_key: &[0x01; 64],
            trader_core: core,
        }
    }

    fn one_hop_ctx() -> TraderContext<'static> {
        ctx(trader_core(d(0x40), d(0x41), &[d(0xC1)]))
    }

    fn draft_one_hop() -> PrecommitDraft {
        draft_trade(
            hop(0xC1, 0x40, 100, 0x41, 90),
            dlv_core(0xC1),
            &one_hop_ctx(),
            d(0xA1),
            PRE_ROOT,
        )
        .unwrap()
    }

    /// An exercise is signed TWICE, and the draft is the first stage: it hands
    /// back `m_P` and nothing else. (The producer this replaces returned one
    /// object and dropped P's signature on the floor.)
    #[test]
    fn an_exercise_is_signed_twice_and_p_travels_with_its_signature() {
        let draft = draft_one_hop();
        assert_eq!(
            draft.precommit_signing_digest(),
            derive::precommit_signing_digest(draft.precommit()),
            "m_P is the precommit's own frozen digest"
        );

        // F cannot be built against an unsigned P: storage refuses one.
        assert_eq!(
            build_fulfillment(&draft, Vec::new(), &[(d(0xC1), 0)]),
            Err(BuildError::PrecommitNotSigned)
        );

        let produced = build_fulfillment(&draft, P_SIG.to_vec(), &[(d(0xC1), 0)]).unwrap();
        assert!(produced.fulfillment_signing_digest.is_some(), "m_F");
        assert_eq!(produced.publish[0].bytes, draft.precommit().encode());
        assert_eq!(
            produced.publish[0].signature,
            P_SIG.to_vec(),
            "P is published WITH the signature its ingress checks"
        );
        assert!(produced.operation.get_signature().is_none());
        assert_eq!(
            produced.operation_signing_bytes,
            dsm::core::state_machine::transition::operation_signing_bytes(&produced.operation),
            "the operation's signing bytes are the verifier's own rule"
        );
    }

    /// THE ROUTE MUST CHAIN, and a producer refuses one that does not — with
    /// no evidence fetched at all, because a verifier needs none to know.
    /// This test previously built exactly this pair and PASSED, which is what
    /// made it a demonstration of the bug rather than a test of the gate.
    #[test]
    fn a_producer_refuses_a_route_that_does_not_chain() {
        // hop0 gives 0x41/90; hop1 takes 0x40/100. Neither end matches.
        let broken = vec![
            hop(0xC1, 0x40, 100, 0x41, 90),
            hop(0xC2, 0x40, 100, 0x41, 90),
        ];
        assert_eq!(
            draft_route(
                broken,
                vec![dlv_core(0xC1), dlv_core(0xC2)],
                &ctx(trader_core(d(0x40), d(0x41), &[d(0xC1), d(0xC2)])),
                d(0xA1),
                PRE_ROOT,
            ),
            Err(BuildError::StaticallyInvalid(Invalid::RouteDoesNotChain {
                hop: 1
            }))
        );
    }

    /// A route that chains builds, at the beta cap.
    #[test]
    fn a_two_hop_route_that_chains_builds() {
        let draft = draft_route(
            vec![
                hop(0xC1, 0x40, 100, 0x41, 90),
                hop(0xC2, 0x41, 90, 0x42, 80),
            ],
            vec![dlv_core(0xC1), dlv_core(0xC2)],
            &ctx(trader_core(d(0x40), d(0x42), &[d(0xC1), d(0xC2)])),
            d(0xA1),
            PRE_ROOT,
        )
        .unwrap();
        let produced =
            build_fulfillment(&draft, P_SIG.to_vec(), &[(d(0xC1), 0), (d(0xC2), 1)]).unwrap();
        assert!(matches!(produced.operation, Operation::SofiFulfill { .. }));
    }

    /// `P.void_root` IS `T°.pre_root` (P15-2) — evidence-independent, so the
    /// producer refuses a draft that guesses it.
    #[test]
    fn a_producer_refuses_a_void_root_that_is_not_the_pre_root() {
        assert_eq!(
            draft_trade(
                hop(0xC1, 0x40, 100, 0x41, 90),
                dlv_core(0xC1),
                &one_hop_ctx(),
                d(0xA1),
                d(0x6F),
            ),
            Err(BuildError::StaticallyInvalid(
                Invalid::VoidRootIsNotThePreRoot
            ))
        );
    }

    /// The attempt vector is chosen at exercise time, and one that does not
    /// cover P's legs is refused here rather than at a member's ingress.
    #[test]
    fn a_producer_refuses_attempts_that_do_not_cover_the_legs() {
        let draft = draft_one_hop();
        // An attempt for a vault this P never names.
        assert_eq!(
            build_fulfillment(&draft, P_SIG.to_vec(), &[(d(0xCF), 0)]),
            Err(BuildError::Conformance(
                FulfillmentConformanceError::AttemptsDoNotCoverLegs
            ))
        );
        // An empty attempt vector is not even canonical bytes.
        assert!(matches!(
            build_fulfillment(&draft, P_SIG.to_vec(), &[]),
            Err(BuildError::Wire(SofiWireError::Cardinality {
                field: "attempts",
                ..
            }))
        ));
    }

    /// Beta's hop cap is refused before anything is assembled (R16-6).
    #[test]
    fn a_producer_refuses_a_route_beta_will_not_execute() {
        let hops = vec![
            hop(0xC1, 0x40, 100, 0x41, 90),
            hop(0xC2, 0x41, 90, 0x42, 80),
            hop(0xC3, 0x42, 80, 0x43, 70),
        ];
        let vaults = [d(0xC1), d(0xC2), d(0xC3)];
        assert_eq!(
            draft_route(
                hops,
                vaults.iter().map(|v| dlv_core(v[0])).collect(),
                &ctx(trader_core(d(0x40), d(0x43), &vaults)),
                d(0xA1),
                PRE_ROOT,
            ),
            Err(BuildError::NotAdmissible(NotAdmissible::TooManyLegs {
                legs: 3,
                max: 2
            }))
        );
    }

    /// A close is the same operation variant as a trade — the branch lives in
    /// `B°` — and no producer can name the reserved authority (R18-1).
    #[test]
    fn a_close_is_the_same_variant_and_only_the_origin_owner() {
        let draft = draft_close(
            d(0xC1),
            d(0x62),
            d(0x55),
            1_000,
            2_000,
            dlv_core(0xC1),
            &ctx(trader_core(d(0x40), d(0x41), &[d(0xC1)])),
            d(0xA1),
            PRE_ROOT,
        )
        .unwrap();
        let produced = build_fulfillment(&draft, P_SIG.to_vec(), &[(d(0xC1), 0)]).unwrap();
        assert!(matches!(produced.operation, Operation::SofiFulfill { .. }));
        match draft.preimage().settlement() {
            SettlementBody::Close {
                owner_authority, ..
            } => assert_eq!(*owner_authority, OwnerAuthority::Origin),
            _ => panic!("a close"),
        }
    }

    /// The vault-create signature is the OPERATION's frozen rule — the
    /// canonical unsigned bytes — not a digest this module invents. (It used
    /// to be `blake3(genesis_preimage ‖ creation)`, which no verifier checks.)
    #[test]
    fn a_vault_creation_signs_the_operations_own_bytes() {
        let state = VaultStateLeaf {
            owner_genesis: G,
            owner_device_id: DEV,
            create_position: P_POS,
            market_policy: d(0x31),
            fee_policy: d(0x32),
            release_policy: d(0x33),
            storage_set_id: d(0x77),
            generation: 0,
            reserve_a: 1_000,
            reserve_b: 2_000,
            status: VAULT_STATUS_ACTIVE,
        };
        let preimage = VaultGenesisPreimage {
            owner_genesis: G,
            owner_device_id: DEV,
            create_position: P_POS,
            state: state.clone(),
        };
        let created = build_vault_create(&preimage, 1_000, 2_000).unwrap();
        assert_eq!(
            created.operation_signing_bytes,
            dsm::core::state_machine::transition::operation_signing_bytes(&created.operation),
            "one signing rule, and it is the verifier's"
        );
        let Operation::SofiVaultCreate {
            genesis_preimage,
            creation,
            ..
        } = &created.operation
        else {
            panic!("a creation")
        };
        assert_ne!(
            created.operation_signing_bytes,
            [genesis_preimage.clone(), creation.clone()].concat(),
            "not a bare concatenation of the objects it carries"
        );

        // `vault_id` and `R_0` are the preimage's own derivations.
        let decoded = VaultCreation::decode(creation).unwrap();
        assert_eq!(decoded.vault_id, preimage.vault_id());
        let mut tree = EconomicSmt::new();
        tree.insert(
            derive::vault_state_key(&preimage.vault_id()),
            derive::vault_state_leaf_value(&state).unwrap(),
        );
        assert_eq!(decoded.genesis_root, tree.root());
    }

    /// A setup moves nothing and signs by the same one rule.
    #[test]
    fn a_setup_produces_its_own_operation() {
        let setup =
            SofiSetupBody::new(G, DEV, P_POS, d(0xC1), d(0x66), d(0x67), ALG, &[0x01; 64]).unwrap();
        let produced = build_setup(&setup).unwrap();
        assert!(matches!(produced.operation, Operation::SofiSetup { .. }));
        assert_eq!(
            produced.operation_signing_bytes,
            dsm::core::state_machine::transition::operation_signing_bytes(&produced.operation)
        );
        assert!(produced.fulfillment_signing_digest.is_none());
    }
}
