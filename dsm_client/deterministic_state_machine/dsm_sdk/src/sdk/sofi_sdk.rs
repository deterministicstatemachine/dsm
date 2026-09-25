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
//! ## What each operation's signature covers
//!
//! Three rules, and no generic fourth one. A setup signs `m_setup` and a
//! fulfillment signs `m_F` — their own objects' digests, which is what a
//! storage member checks when the same object arrives with no operation
//! around it. Only a vault creation, which has no protocol object digest of
//! its own, signs the operation's canonical unsigned bytes. Each producer
//! returns that payload as [`SigningPayload`]; none of them invents a digest,
//! and none of them asks for a second signature over the same facts.
//!
//! ## What a producer refuses
//!
//! Everything `sofi::admission` refuses — routes beyond the beta hop cap, and
//! the reserved DSM-succession authority (R16-6, R18-1) — AND everything a
//! verifier would call Invalid without needing any evidence. A producer that
//! emits an operation the validator will deterministically reject has produced
//! a way to strand a trader, not a trade.
//!
//! `sdk::sofi_flow` runs them for the SoFi routes.

use dsm::sofi::admission::{preimage_admissible, NotAdmissible};
use dsm::sofi::conformance::{
    check_fulfillment_against_precommit, derive_policy_fulfillments, FulfillmentConformanceError,
};
use dsm::sofi::derive;
use dsm::economic::lineage::ValidatedEconomicRoot;
use dsm::economic::tree::EconomicSmt;
use dsm::sofi::lineage::GenesisError;
use dsm::sofi::publication::Signed;
use dsm::sofi::signature::{verify_precommit, SignatureError, SigningPayload};
use dsm::sofi::validation::{realize_root, validate, Evidence, Invalid, Missing, Refusal};
use dsm::sofi::wire::{
    AttemptEntry, DlvCore, DlvPolicyFulfillmentBody, OwnerAuthority, ParentClaimRef,
    PreEClosureIndex, PrecommitLeg, SettlementBody, SettlementPreimage, SofiSetupBody,
    SofiWireError, SwapHop, TraderCore, TraderFulfillmentBody, TraderPrecommitBody, VaultCreation,
    VaultGenesisPreimage,
};
use dsm::types::operations::Operation;

use crate::sdk::sofi_evidence::LocalLeaves;

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
    /// A verifier calls this Invalid, for this named reason. Producing it
    /// would hand the trader an operation that is already refused.
    StaticallyInvalid(Invalid),
    /// Rule T5: evidence the verifier needs is not in hand, so the producer
    /// stops — it never publishes, exercises or advances without a verdict.
    /// Nothing about the operation is wrong; what is missing is named.
    Incomplete(Missing),
    /// `P` is not validly signed, so the fulfillment would name a precommit
    /// storage refuses.
    PrecommitSignature(SignatureError),
    /// A vault genesis a verifier would refuse — the market policy does not
    /// authenticate, or its pair is not canonical.
    Genesis(GenesisError),
    /// The trader's own leaves cannot supply the pre values its core names.
    LocalLeaves(String),
    /// This identity already holds a relationship with that vault. `h⁰` is a
    /// function of the setup id, so a second setup would reset a chain that
    /// has already advanced.
    SetupAlreadyExists,
    /// The producer's tree is not the predecessor's root, so `R_T^setup`
    /// computed from it would describe a mutation of some other state.
    PreTreeIsNotThePredecessor,
}

impl core::fmt::Display for BuildError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Wire(e) => write!(f, "{e}"),
            Self::NotAdmissible(e) => write!(f, "{e}"),
            Self::Conformance(e) => write!(f, "{e:?}"),
            Self::StaticallyInvalid(reason) => write!(
                f,
                "a verifier refuses this operation ({reason:?}); it is not a trade, it is a \
                 way to strand one"
            ),
            Self::Incomplete(missing) => write!(
                f,
                "the producer stops: evidence a verifier needs is not in hand ({missing:?}); \
                 nothing is published, exercised or advanced without a verdict"
            ),
            Self::Genesis(e) => write!(f, "{e}"),
            Self::LocalLeaves(e) => write!(f, "the trader's own leaves: {e}"),
            Self::PreTreeIsNotThePredecessor => write!(
                f,
                "the producer's economic tree is not the validated predecessor's root: \
                 R_T^setup derived from it would describe a mutation of another state"
            ),
            Self::SetupAlreadyExists => write!(
                f,
                "this identity already holds a relationship with that vault; h⁰ is the \
                 setup id's derivation and a second setup would reset the chain"
            ),
            Self::PrecommitSignature(e) => write!(
                f,
                "the precommit is not validly signed ({e}): P is published and \
                 signed before F may reference it"
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

/// What a producer hands back to publish (Part II §10, rebuild step R8):
/// the objects a verifier needs and cannot derive, each of a kind Core knows
/// how to store, index and recognize (`sofi::publication`).
///
/// The setup and the fulfillment sign through the operation — `m_setup` and
/// `m_F` are `Produced::signs` — so they are handed back bare and completed
/// with that signature by `sofi_publish::publish_produced` once the caller
/// has made it. `P` travels WITH the signature the trader already made, and
/// a verifier checks it against the key the parent claim commits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ToPublish {
    Setup(SofiSetupBody),
    Precommit(Signed<TraderPrecommitBody>),
    Preimage(SettlementPreimage),
    PolicyFulfillment(DlvPolicyFulfillmentBody),
    Fulfillment(TraderFulfillmentBody),
}

/// A produced operation: the transition, what must be published for anyone to
/// verify it, and the exact bytes to sign.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Produced {
    /// The operation, with an EMPTY signature.
    pub operation: Operation,
    /// What the operation's `signature` field must cover, and which of the
    /// three rules fixed it. A setup signs `m_setup`, a fulfillment signs
    /// `m_F`, and a vault creation signs the operation's own unsigned bytes.
    /// There is no additional generic operation signature for the first two:
    /// the object a storage member receives has no operation around it, and
    /// `m_setup` / `m_F` are what it checks there.
    pub signs: SigningPayload,
    /// Objects a verifier needs and cannot derive, in the order they are
    /// published.
    pub publish: Vec<ToPublish>,
}

/// A precommit and its settlement preimage, assembled and not yet checked.
/// The evidence a verifier consumes is acquired over exactly these
/// (`EvidenceNeeds::of`), so it cannot be acquired before them; only
/// [`check_draft`] turns this into a [`PrecommitDraft`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UncheckedDraft {
    precommit: TraderPrecommitBody,
    preimage: SettlementPreimage,
}

impl UncheckedDraft {
    pub fn precommit(&self) -> &TraderPrecommitBody {
        &self.precommit
    }

    pub fn preimage(&self) -> &SettlementPreimage {
        &self.preimage
    }
}

/// The verifier's own verdict over a draft, over evidence acquired for it
/// (`sofi_evidence::acquire_evidence`, rebuild step R5). Any result but Valid
/// stops the producer (rebuild step R6): Invalid means the trader would be
/// building something a verifier already refuses; evidence not in hand
/// means there is no verdict, and rule T5 says a producer never publishes,
/// exercises or advances without one.
pub fn check_draft(
    draft: UncheckedDraft,
    evidence: &Evidence,
) -> Result<PrecommitDraft, BuildError> {
    match validate(&draft.precommit, &draft.preimage, evidence) {
        Ok(()) => Ok(PrecommitDraft {
            precommit: draft.precommit,
            preimage: draft.preimage,
        }),
        Err(Refusal::Invalid(reason)) => Err(BuildError::StaticallyInvalid(reason)),
        Err(Refusal::Incomplete(missing)) => Err(BuildError::Incomplete(missing)),
    }
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
/// `R_T^setup` IS DERIVED HERE, exactly as the verifier derives it.
///
/// The body is built rather than accepted, because two of its fields are not
/// the caller's to choose: `p` is the position the parent claim names, and
/// `setup_root` is the trader economic root AFTER the P15-6 absent→`h⁰`
/// insertion is applied to the root at that position. A producer that took a
/// body would let a caller put arbitrary bytes in `R_T^setup`, sign them, and
/// discover at admission that the transition is refused — or, worse, have a
/// first setup pin an index entry committing bytes nothing ever checked.
///
/// `pre_tree` is the producer's own `R_econ` at `p`; the insertion is computed
/// against it so the root is the one the mutation sequence will actually
/// yield.
#[allow(clippy::too_many_arguments)]
pub fn build_setup(
    previous: &ValidatedEconomicRoot,
    pre_tree: &EconomicSmt,
    genesis: D32,
    device_id: D32,
    vault_id: D32,
    claim_ref: D32,
    signature_alg: u16,
    claimant_public_key: &[u8],
) -> Result<Produced, BuildError> {
    // `p`, `R_p` AND `R_T^setup` COME FROM ONE PREDECESSOR CONTEXT. A naked
    // `position` argument let a caller pass p = 12 against the real tree at
    // p = 7 and get a perfectly self-consistent σ(12) → h⁰(12) →
    // R_T^setup(12, real tree) — an operation the verifier then deterministically
    // refuses. Fail-closed, but the producer should not be able to build
    // something known-impossible at construction time.
    let position = previous.economic_position();
    if pre_tree.root() != previous.economic_root() {
        return Err(BuildError::PreTreeIsNotThePredecessor);
    }
    let sigma = derive::setup_id(&genesis, &device_id, position, &vault_id);
    let leaf = dsm::sofi::wire::TraderRelationshipLeaf {
        vault_id,
        leaf: derive::relationship_leaf_genesis(&sigma),
    };
    let state = dsm::economic::state::EconomicLeafState::Relationship(leaf);
    let key = state.leaf_key(&genesis, &device_id);
    // INSERT-FROM-ZERO, the same rule the write set enforces: a producer that
    // overwrote an existing relationship would compute a root the verifier
    // refuses to reach.
    if pre_tree.get(&key).is_some() {
        return Err(BuildError::SetupAlreadyExists);
    }
    let mut post = pre_tree.clone();
    post.insert(
        key,
        state
            .leaf_value()
            .map_err(|e| BuildError::LocalLeaves(format!("relationship leaf value: {e}")))?,
    );
    let body = SofiSetupBody::new(
        genesis,
        device_id,
        position,
        vault_id,
        claim_ref,
        post.root(),
        signature_alg,
        claimant_public_key,
    )?;
    Ok(Produced {
        signs: SigningPayload::SetupDigest(derive::setup_signing_digest(&body)),
        operation: Operation::SofiSetup {
            setup_body: body.encode(),
            signature: Vec::new(),
        },
        // The setup body is put as an object and indexed under ρ (and the
        // relationship index key); SetupRegistered holds once it is Stored.
        publish: vec![ToPublish::Setup(body)],
    })
}

/// The owner's vault creation at `p_create` (P15-12).
///
/// `vault_id` and `R_0` are recomputed from the preimage rather than accepted
/// from the caller, so a creation cannot name a vault its own identity does not
/// derive or a root its own state does not produce.
pub fn build_vault_create(
    preimage: &VaultGenesisPreimage,
    market_policy_bytes: &[u8],
) -> Result<Produced, BuildError> {
    let vault_id = preimage.vault_id();
    // THE FUNDING ASSETS ARE DERIVED, NOT TAKEN. A caller that could pass the
    // two commits could pass the wrong ones, and `genesis_accepted` would
    // refuse the result — after the owner had signed it. So the producer
    // resolves them from the SAME authority the verifier uses: the policy the
    // vault state commits, authenticated by re-addressing its bytes.
    let derived = dsm::ccb::decode::policy_object_address(
        dsm::ccb::class::MARKET_POLICY,
        market_policy_bytes,
    )
    .ok_or(BuildError::Genesis(GenesisError::MarketPolicyDoesNotDecode))?;
    if derived != preimage.state.market_policy {
        return Err(BuildError::Genesis(
            GenesisError::MarketPolicyIsNotTheCommittedOne,
        ));
    }
    let market = dsm::ccb::decode::decode_market_policy(market_policy_bytes)
        .map_err(|_| BuildError::Genesis(GenesisError::MarketPolicyDoesNotDecode))?;
    let (token_a, token_b) = (*market.token_a(), *market.token_b());
    if token_a >= token_b {
        return Err(BuildError::Genesis(GenesisError::TokenPairNotOrdered));
    }
    // The amounts are the genesis reserves, not a second pair of arguments
    // that could disagree with them (P15-12).
    let creation = VaultCreation {
        vault_id,
        genesis_root: dsm::sofi::lineage::genesis_root(&vault_id, &preimage.state)?,
        amount_a: preimage.state.reserve_a,
        amount_b: preimage.state.reserve_b,
    };
    let operation = Operation::SofiVaultCreate {
        genesis_preimage: preimage.encode()?,
        creation: creation.encode(),
        // The EXACT bytes whose address the state commits — carried, not
        // referenced, so Core re-addresses and decodes them itself instead of
        // taking this producer's word for the pair.
        market_policy_preimage: market_policy_bytes.to_vec(),
        funding_a_policy_commit: token_a,
        funding_b_policy_commit: token_b,
        signature: Vec::new(),
    };
    Ok(Produced {
        // A creation has no protocol object digest of its own: `vault_id` and
        // `R_0` are derivations of the preimage it carries. So it signs the
        // operation, by the one frozen rule — inventing a vault-create digest
        // here would be a rule no verifier implements.
        signs: SigningPayload::OperationBytes(operation.signing_bytes()),
        operation,
        publish: Vec::new(),
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

/// `𝒞_E^pre` of a draft: the typed reference of the parent `P` names (P
/// conformance rule 2), so `E` commits to the exact claim the operation
/// extends. Beta references no other pre-E object.
fn pre_e_closure(ctx: &TraderContext<'_>) -> Result<PreEClosureIndex, BuildError> {
    Ok(PreEClosureIndex::new(vec![ctx
        .parent_claim
        .validation_ref(
            &ctx.genesis,
            &ctx.device_id,
            ctx.position,
        )])?)
}

/// Assemble `P(E)` and `P`, refusing anything beta will not run.
///
/// Neither root is the caller's: `R_void` is `T°.pre_root` (P15-2), and
/// `R_realize` is `Fold(T°, E)` over the trader's own leaves, computed by the
/// Core function the verifier checks it with — so it can only be computed
/// once `E` exists, which is here.
fn draft(
    settlement: SettlementBody,
    ctx: &TraderContext<'_>,
    cores: Vec<DlvCore>,
    legs: Vec<PrecommitLeg>,
    local: &LocalLeaves,
) -> Result<UncheckedDraft, BuildError> {
    let preimage = SettlementPreimage::new(settlement, ctx.trader_core.clone(), cores)?;
    // Beta will not execute this, so nothing here will build it.
    preimage_admissible(&preimage).map_err(BuildError::NotAdmissible)?;
    let e = derive::recompute_e(&preimage)?;
    let trader_evidence = local
        .trader_evidence(&ctx.trader_core)
        .map_err(|why| BuildError::LocalLeaves(why.to_string()))?;
    let realize = match realize_root(&ctx.trader_core, &e, &trader_evidence) {
        Ok(root) => root,
        Err(Refusal::Invalid(reason)) => return Err(BuildError::StaticallyInvalid(reason)),
        Err(Refusal::Incomplete(missing)) => return Err(BuildError::Incomplete(missing)),
    };
    let void_root = *ctx.trader_core.pre_root();
    let precommit = TraderPrecommitBody::new(
        ctx.genesis,
        ctx.device_id,
        ctx.position,
        ctx.parent_claim,
        e,
        legs,
        realize,
        void_root,
        ctx.storage_set_id,
        ctx.signature_alg,
        ctx.claimant_public_key,
    )?;

    Ok(UncheckedDraft {
        precommit,
        preimage,
    })
}

/// A single-vault trade.
pub fn draft_trade(
    hop: SwapHop,
    core: DlvCore,
    ctx: &TraderContext<'_>,
    local: &LocalLeaves,
) -> Result<UncheckedDraft, BuildError> {
    draft_route(vec![hop], vec![core], ctx, local)
}

/// A route over one or more vaults. Beta executes at most two hops, and this
/// refuses to build a third rather than leaving the trader holding an
/// operation nothing will run.
pub fn draft_route(
    hops: Vec<SwapHop>,
    cores: Vec<DlvCore>,
    ctx: &TraderContext<'_>,
    local: &LocalLeaves,
) -> Result<UncheckedDraft, BuildError> {
    let (first, last) = match (hops.first(), hops.last()) {
        (Some(f), Some(l)) => (*f, *l),
        (None, ..) | (.., None) => {
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
        closure: pre_e_closure(ctx)?,
    };
    draft(settlement, ctx, sorted_cores, legs, local)
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
    local: &LocalLeaves,
) -> Result<UncheckedDraft, BuildError> {
    let settlement = SettlementBody::Close {
        vault_id,
        parent_root,
        setup_ref,
        owner_authority: OwnerAuthority::Origin,
        reserve_a,
        reserve_b,
        trader_core: derive::trader_core_digest(&ctx.trader_core.encode()?),
        dlv_core: derive::dlv_core_digest(&core.encode()?),
        closure: pre_e_closure(ctx)?,
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
        local,
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
    let precommit = &draft.precommit;
    // THE P SIGNATURE IS VERIFIED, NOT COUNTED. `F` names a `P` that storage
    // will refuse unless `m_P` verifies under the key `P` commits, so a
    // producer that only checked for non-empty bytes would hand the trader an
    // exercise of a precommit nobody will accept — after the trader has
    // already signed `m_F`, which is the irreversible half.
    verify_precommit(precommit, &precommit_signature).map_err(BuildError::PrecommitSignature)?;
    let shadow_cores: Vec<D32> = draft
        .preimage
        .dlv_cores()
        .iter()
        .map(|core| core.encode().map(|b| derive::dlv_core_digest(&b)))
        .collect::<Result<_, _>>()?;
    let witnesses = derive_policy_fulfillments(precommit, &shadow_cores)?;
    let mut policy_set: Vec<D32> = witnesses
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
    // Stages 4 and 5 (§31): P under PrecommitId, P(E) under L(E), every G_j
    // under its PolicyFulfillmentId; then F itself, once m_F is signed.
    let mut publish = vec![
        ToPublish::Precommit(Signed {
            body: precommit.clone(),
            signature: precommit_signature,
        }),
        ToPublish::Preimage(draft.preimage.clone()),
    ];
    publish.extend(witnesses.into_iter().map(ToPublish::PolicyFulfillment));
    publish.push(ToPublish::Fulfillment(fulfillment.clone()));
    Ok(Produced {
        signs: SigningPayload::FulfillmentDigest(derive::fulfillment_signing_digest(&fulfillment)),
        operation,
        publish,
    })
}
