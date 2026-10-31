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
//! build_fulfillment(draft, p_signature, attempts, att_a)  ->  Produced (gives m_F)
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

use std::collections::BTreeMap;

use dsm::sofi::admission::{preimage_admissible, NotAdmissible};
use dsm::sofi::conformance::{
    check_fulfillment_against_precommit, derive_policy_fulfillments, FulfillmentConformanceError,
};
use dsm::sofi::derive;
use dsm::economic::lineage::ValidatedEconomicRoot;
use dsm::economic::tree::EconomicSmt;
use dsm::sofi::lineage::{setup_body, GenesisError, SetupBodyError, SetupNames};
use dsm::sofi::publication::Signed;
use dsm::sofi::signature::{verify_precommit, SignatureError, SigningPayload};
use dsm::sofi::validation::{realize_root, validate, Evidence, Invalid, Missing, Refusal};
use dsm::sofi::wire::{
    AttemptEntry, DlvCore, DlvPolicyFulfillmentBody, OwnerAuthority, ParentClaimRef,
    PreEClosureIndex, PrecommitLeg, SettlementBody, SettlementPreimage, SofiSetupBody,
    SofiWireError, SwapHop, TraderCore, TraderFulfillmentBody, TraderPreBalance,
    TraderPrecommitBody, ValidationRef, VaultCreation, VaultGenesisPreimage,
};
use dsm::types::operations::Operation;

use dsm::sofi::resolve::LocalLeaves;

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
    /// Core builds no setup body on this predecessor, for the reason named.
    Setup(SetupBodyError),
    /// `P`'s key, with the `AttA` given, does not derive the device `P` names,
    /// so `F` would occupy no cell of it (DSM Amendment A10, SoFi Amendment
    /// S20).
    KeyIsNotTheDevices,
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
            Self::Setup(e) => write!(f, "{e}"),
            Self::KeyIsNotTheDevices => write!(
                f,
                "the precommit's key, with this device's AttA, does not derive the device it \
                 names; the fulfillment would occupy no cell of it"
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
    /// A trader's balance before the trade (SoFi Amendment S12), found by
    /// the address `𝒞_E^pre` names.
    PreBalance(TraderPreBalance),
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
    pre_balances: Vec<TraderPreBalance>,
}

impl UncheckedDraft {
    pub fn precommit(&self) -> &TraderPrecommitBody {
        &self.precommit
    }

    pub fn preimage(&self) -> &SettlementPreimage {
        &self.preimage
    }

    /// The closure objects only this trader holds before they are published:
    /// each `TraderPreBalance` under the reference `𝒞_E^pre` names it by.
    pub fn carried(&self) -> BTreeMap<ValidationRef, Vec<u8>> {
        carried(&self.pre_balances)
    }
}

/// Each `TraderPreBalance` under the closure reference that names it.
fn carried(pre_balances: &[TraderPreBalance]) -> BTreeMap<ValidationRef, Vec<u8>> {
    pre_balances
        .iter()
        .map(|balance| (pre_balance_ref(balance), balance.encode()))
        .collect()
}

/// The `ContentAddr` `𝒞_E^pre` names a `TraderPreBalance` by.
fn pre_balance_ref(balance: &TraderPreBalance) -> ValidationRef {
    ValidationRef::ContentAddr {
        object_class: dsm::ccb::class::SOFI_TRADER_PRE_BALANCE,
        addr: derive::trader_pre_balance_addr(balance),
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
            pre_balances: draft.pre_balances,
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
    pre_balances: Vec<TraderPreBalance>,
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

    /// The closure objects only this trader holds: each `TraderPreBalance`
    /// under the reference `𝒞_E^pre` names it by.
    pub fn carried(&self) -> BTreeMap<ValidationRef, Vec<u8>> {
        carried(&self.pre_balances)
    }

    /// `E`, as the preimage derives it.
    pub fn external_commitment(&self) -> D32 {
        *self.precommit.external_commitment()
    }
}

/// The relationship setup (F1). Non-economic: it establishes the right to
/// trade with one vault, and moves nothing.
///
/// The body is Core's (`sofi::lineage::setup_body`): Core derives `p` and
/// `R_T^setup` from the validated predecessor and the tree at its root, and
/// this producer only states what the trader signs and what is published
/// (SoFi §2.1). `pre_tree` is the producer's own `R_econ` at `p`.
pub fn build_setup(
    previous: &ValidatedEconomicRoot,
    pre_tree: &EconomicSmt,
    names: &SetupNames<'_>,
) -> Result<Produced, BuildError> {
    let body = setup_body(previous, pre_tree, names).map_err(BuildError::Setup)?;
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
    funding_policies: Vec<Vec<u8>>,
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
        // The funded tokens' committed policies, which Core re-hashes and
        // checks before it debits anything (MR-SOFI-0311).
        funding_policies,
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

/// An escrow vault's creation (SoFi Amendment S21): the stake of the terms'
/// token, the creation record, and the exact terms bytes all three of the
/// genesis state's slots name, carried so Core re-addresses and decodes them
/// itself. Terms the slots do not name are refused before the owner signs.
pub fn build_escrow_vault_create(
    preimage: &VaultGenesisPreimage,
    terms: &dsm::sofi::wire::EscrowTerms,
    funding_policies: Vec<Vec<u8>>,
) -> Result<Produced, BuildError> {
    escrow_vault_create(preimage, &terms.encode(), funding_policies)
}

/// `EscrowVaultCreate` of a computed escrow vault (SoFi Amendment S22): the
/// operation carries the exact `ComputedEscrowTerms` bytes in place of
/// `EscrowTerms`; the debit, the record and the write set are §19.9's.
pub fn build_computed_vault_create(
    preimage: &VaultGenesisPreimage,
    terms: &dsm::sofi::wire::ComputedEscrowTerms,
    funding_policies: Vec<Vec<u8>>,
) -> Result<Produced, BuildError> {
    escrow_vault_create(preimage, &terms.encode(), funding_policies)
}

/// The creation of an escrow vault of either kind whose three slots name
/// `terms_bytes` (the class of the bytes is the kind).
fn escrow_vault_create(
    preimage: &VaultGenesisPreimage,
    terms_bytes: &[u8],
    funding_policies: Vec<Vec<u8>>,
) -> Result<Produced, BuildError> {
    let addr = dsm::sofi::escrow::terms_address_of(terms_bytes);
    let state = &preimage.state;
    if state.market_policy != addr || state.fee_policy != addr || state.release_policy != addr {
        return Err(BuildError::Wire(SofiWireError::EscrowTermsNotCommitted));
    }
    let vault_id = preimage.vault_id();
    // The stake is the genesis reserve, not a second argument that could
    // disagree with it.
    let creation = VaultCreation {
        vault_id,
        genesis_root: dsm::sofi::lineage::genesis_root(&vault_id, state)?,
        amount_a: state.reserve_a,
        amount_b: state.reserve_b,
    };
    let operation = Operation::EscrowVaultCreate {
        genesis_preimage: preimage.encode()?,
        creation: creation.encode(),
        terms: terms_bytes.to_vec(),
        funding_policies,
        signature: Vec::new(),
    };
    Ok(Produced {
        // Like a market's creation, it has no object digest of its own and
        // signs the operation.
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
/// extends; and one `TraderPreBalance` for each balance `T°` states as
/// present before the trade (SoFi Amendment S12), so a verifier that is not
/// this trader can judge it. The references are in canonical order.
fn pre_e_closure(
    ctx: &TraderContext<'_>,
    pre_balances: &[TraderPreBalance],
) -> Result<PreEClosureIndex, BuildError> {
    let mut refs =
        vec![ctx
            .parent_claim
            .validation_ref(&ctx.genesis, &ctx.device_id, ctx.position)];
    refs.extend(pre_balances.iter().map(pre_balance_ref));
    refs.sort_by_key(ValidationRef::encode);
    Ok(PreEClosureIndex::new(refs)?)
}

/// Assemble `P(E)` and `P`, refusing anything beta will not run.
///
/// Neither root is the caller's: `R_void` is `T°.pre_root` (P15-2), and
/// `R_realize` is `Fold(T°, E)`, computed by the Core function the verifier
/// checks it with — so it can only be computed once `E` exists, which is
/// here.
fn draft(
    settlement: SettlementBody,
    ctx: &TraderContext<'_>,
    cores: Vec<DlvCore>,
    legs: Vec<PrecommitLeg>,
    pre_balances: Vec<TraderPreBalance>,
) -> Result<UncheckedDraft, BuildError> {
    let preimage = SettlementPreimage::new(settlement, ctx.trader_core.clone(), cores)?;
    // Beta will not execute this, so nothing here will build it.
    preimage_admissible(&preimage).map_err(BuildError::NotAdmissible)?;
    let e = derive::recompute_e(&preimage)?;
    let realize = match realize_root(&ctx.trader_core, &e) {
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
        pre_balances,
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
    if hops.is_empty() {
        return Err(BuildError::Wire(SofiWireError::Cardinality {
            field: "swap hops",
            min: 1,
            max: usize::MAX,
            got: 0,
        }));
    }
    // A chain's ends, or a split's pair and sums (Amendment S19).
    let (token_in, amount_in, token_out, exact_out) =
        dsm::sofi::validation::swap_endpoints(&hops).map_err(BuildError::StaticallyInvalid)?;
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
    let pre_balances = local
        .pre_balances(&ctx.trader_core)
        .map_err(|why| BuildError::LocalLeaves(why.to_string()))?;
    let settlement = SettlementBody::Swap {
        token_in,
        amount_in,
        token_out,
        exact_out,
        hops,
        trader_core: derive::trader_core_digest(&ctx.trader_core.encode()?),
        dlv_cores: core_digests,
        closure: pre_e_closure(ctx, &pre_balances)?,
    };
    draft(settlement, ctx, sorted_cores, legs, pre_balances)
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
    let pre_balances = local
        .pre_balances(&ctx.trader_core)
        .map_err(|why| BuildError::LocalLeaves(why.to_string()))?;
    let settlement = SettlementBody::Close {
        vault_id,
        parent_root,
        setup_ref,
        owner_authority: OwnerAuthority::Origin,
        reserve_a,
        reserve_b,
        trader_core: derive::trader_core_digest(&ctx.trader_core.encode()?),
        dlv_core: derive::dlv_core_digest(&core.encode()?),
        closure: pre_e_closure(ctx, &pre_balances)?,
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
        pre_balances,
    )
}

/// What a release names (SoFi Amendment S21): the escrow vault at its head,
/// this device's setup with it, the verdict cell its terms derive, the
/// outcome the cell's verdict names, and the whole stake.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseNames {
    pub vault_id: D32,
    pub parent_root: D32,
    pub setup_ref: D32,
    pub verdict_cell: D32,
    pub outcome: Vec<u8>,
    pub amount: u64,
}

/// A release of an escrow vault's whole stake to the branch's recipient, this
/// device (SoFi Amendment S21): a one-hop route whose `V°` retires the vault.
pub fn draft_release(
    names: ReleaseNames,
    core: DlvCore,
    ctx: &TraderContext<'_>,
    local: &LocalLeaves,
) -> Result<UncheckedDraft, BuildError> {
    let pre_balances = local
        .pre_balances(&ctx.trader_core)
        .map_err(|why| BuildError::LocalLeaves(why.to_string()))?;
    let leg = PrecommitLeg {
        vault_id: names.vault_id,
        parent_root: names.parent_root,
        setup_ref: names.setup_ref,
    };
    let settlement = SettlementBody::Release {
        vault_id: names.vault_id,
        parent_root: names.parent_root,
        setup_ref: names.setup_ref,
        verdict_cell: names.verdict_cell,
        outcome: names.outcome,
        amount: names.amount,
        trader_core: derive::trader_core_digest(&ctx.trader_core.encode()?),
        dlv_core: derive::dlv_core_digest(&core.encode()?),
        closure: pre_e_closure(ctx, &pre_balances)?,
    };
    draft(settlement, ctx, vec![core], vec![leg], pre_balances)
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
    claimant_att_a: D32,
) -> Result<Produced, BuildError> {
    let precommit = &draft.precommit;
    // F occupies K_ful(q) only under a key that, with its AttA, derives the
    // device P names (DSM Amendment A10, SoFi Amendment S20). A producer that
    // built one otherwise would hand the trader an F that names no cell.
    if dsm::core::identity::genesis_v2::derive_devid(
        precommit.claimant_public_key(),
        &claimant_att_a,
    ) != *precommit.device_id()
    {
        return Err(BuildError::KeyIsNotTheDevices);
    }
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
        claimant_att_a,
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
    publish.extend(
        draft
            .pre_balances
            .iter()
            .cloned()
            .map(ToPublish::PreBalance),
    );
    publish.extend(witnesses.into_iter().map(ToPublish::PolicyFulfillment));
    publish.push(ToPublish::Fulfillment(fulfillment.clone()));
    Ok(Produced {
        signs: SigningPayload::FulfillmentDigest(derive::fulfillment_signing_digest(&fulfillment)),
        operation,
        publish,
    })
}
