// SPDX-License-Identifier: MIT OR Apache-2.0

//! SoFi orchestration: one entry per route of SoFi §27, running the stages of
//! §28–§33 in order over the producers in `sofi_sdk`, the publication and
//! evidence acquisition in `sofi_publish` / `sofi_evidence`, and the
//! fulfillment, completion and resolution steps in `sofi_advance`.
//!
//! Producers assemble and publish; Core decides (§26). Nothing here interprets
//! a storage read, skips a Core check, or advances state other than through
//! the Core transition with Core's result unchanged. Every number a core
//! states — a hop's price, a vault's post state, `R_realize` — comes from the
//! Core function the verifier checks it with.

use std::collections::{BTreeMap, BTreeSet};

use dsm::ccb::state::{FeePolicy, MarketPolicy, ReleasePolicy};
use dsm::dlv::route_commit::{constant_product_output_classified, ConstantProductRefusal};
use dsm::economic::keys::balance_key;
use dsm::economic::lineage::{AdmittedEconomicPosition, ValidatedEconomicRoot};
use dsm::economic::state::{EconomicBalanceState, EconomicLeafState};
use dsm::economic::tree::{EconomicSmt, ABSENT_LEAF};
use dsm::economic::write_set::CreditSourceFacts;
use dsm::sofi::derive;
use dsm::sofi::frontier::VaultWitness;
use dsm::sofi::publication::{Publication, VaultPolicyClass};
use dsm::sofi::registration::{PairStanding, Registration};
use dsm::sofi::resolution::{VaultChain, WalkOutcome};
use dsm::sofi::resolve::{AcceptedGeneses, Acquired, LocalLeaves, VaultGenesis, Verifier, WALK_BUDGET};
use dsm::sofi::storage::Discovered;
use dsm::sofi::validation::{
    movement_shape, retire_vault_post, route_endpoints, swap_vault_post, Evidence, EvidenceNeeds,
    HopMovement, Policies, RouteShape, VaultTerms,
};
use dsm::sofi::wire::{
    next_attempt, next_position, CoreEntry, DlvCore, SwapHop, TraderCore, VaultGenesisPreimage,
    VaultStateLeaf, VAULT_STATUS_ACTIVE,
};
use dsm::types::device_state::{BalanceDelta, BalanceDirection};
use dsm::types::error::DsmError;

use crate::sdk::core_sdk::CoreSDK;
use crate::sdk::realized_records::{record_realized, Moved, Realized};
use crate::sdk::economic_admission_flow::{
    admitted_self_loop_operation, committed_network_id, producer_tree_and_pre_state,
    validated_root_or_activate, BuiltOn,
};
use crate::sdk::economic_registers::{resolve_peer, LiveRegisterResolver};
use crate::sdk::sofi_advance::{
    complete_pending_fulfillment, fulfill, own_closure_objects, own_parent_claim,
    resolve_pending_position, Advanced, Completion, FulfillRequest,
};
use crate::sdk::sofi_reads::{
    local_leaves_of_validated, verifier_error, KeptReadings, LiveSofiReads, VerifierContext,
};
use crate::sdk::sofi_publish::{fetch_setup_for, publish, publish_produced, Published};
use crate::sdk::sofi_relay::relay_fulfillment;
use crate::sdk::sofi_sdk::{
    build_fulfillment, build_setup, build_vault_create, check_draft, draft_close, draft_route,
    ToPublish, TraderContext, UncheckedDraft,
};
use crate::sdk::storage_set::StorageSet;
use crate::storage::client_db::{economic_lineage, sofi_vault_head};

type D32 = [u8; 32];

/// The signature algorithm of every SoFi object this device signs: its AK.
pub(crate) const SIGNATURE_ALG: u16 = dsm::ccb::genesis::sigalg::SPHINCS_PLUS_SPX256F;

/// How many times one route reads its position's resolution before it
/// reports `RetriesExhausted`: the network status, not a verdict.
pub const RESOLVE_ROUNDS: usize = 3;

/// How many attempt keys past the walk's first unresolved one a leg may
/// advance while earlier keys are held by exercises still in flight.
pub const ATTEMPT_ADVANCE: usize = 8;

/// `sofi.createVault` (§28). The beta market family (constant product, exact
/// input) and release family (the owner's full close) are fixed, so the
/// owner's choices are the pair, the reserves and the fee. The storage set is
/// the network's pinned set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateVaultIntent {
    /// `token_a < token_b`, bytewise: the market policy refuses any other
    /// order rather than swapping it.
    pub token_a_policy_commit: D32,
    pub token_b_policy_commit: D32,
    pub reserve_a: u64,
    pub reserve_b: u64,
    pub fee_bps: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultCreated {
    pub vault_id: D32,
    /// The owner's economic position whose transition carries the creation.
    pub position: u64,
}

/// A setup with one vault (§29), admitted ahead of the first operation
/// through it (Amendment S16).
#[derive(Debug, Clone, PartialEq, Eq)]
struct SetupIntent {
    vault_id: D32,
}

/// `sofi.findRoute` (§30): path search over walked heads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindRouteIntent {
    pub token_in_policy_commit: D32,
    pub token_out_policy_commit: D32,
    pub amount_in: u64,
}

/// What `sofi.findRoute` searched (Amendment S16): every vault the two token
/// indexes name, or not every one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Search {
    /// Every candidate vault, and the head of each, was established.
    Complete,
    /// A candidate vault, or its head, was not established: a better route
    /// may run through it.
    Partial,
}

/// The best route over the vaults the search established, and how complete
/// the search was. An empty `hops` is no route among them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteFound {
    pub hops: Vec<Hop>,
    pub search: Search,
    /// What the route takes and gives as one operation; `None` for no route.
    pub ends: Option<RouteEnds>,
}

/// What a route takes and gives as one operation, by Core's one rule for a
/// chain's or a split's endpoints (Amendment S19): a chain gives its last
/// hop's output, a split the sum of its legs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RouteEnds {
    pub shape: RouteShape,
    pub amount_in: u64,
    pub amount_out: u64,
}

/// One hop of a proposed route, priced at the vault's walked head. Carries no
/// authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hop {
    pub vault_id: D32,
    pub parent_root: D32,
    pub token_in_policy_commit: D32,
    pub token_out_policy_commit: D32,
    pub amount_in: u64,
    pub amount_out: u64,
}

/// `sofi.trade` and `sofi.route` (§31): one hop, or several through distinct
/// vaults in hop order, all or none.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TradeIntent {
    pub vault_ids: Vec<D32>,
    pub token_in_policy_commit: D32,
    /// The token the trader asks for: the route must give it.
    pub token_out_policy_commit: D32,
    pub amount_in: u64,
    pub min_amount_out: u64,
}

/// `sofi.close` (§32).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloseIntent {
    pub vault_id: D32,
}

/// `sofi.relay` (§33).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayIntent {
    pub trader_genesis: D32,
    pub trader_device_id: D32,
    pub position: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Relayed {
    /// Cells whose write reached their route's leader: the position pair's
    /// two, and each leg key the exercise was carried to.
    pub cells_written: u32,
}

/// Where a trade, route, close or resolve left the device's position.
/// Predicates are Valid or Invalid only; `RetriesExhausted` is the separate
/// network status: the predicates held, and the network retries ran out
/// before the position resolved (owner, 2026-09-23). Nothing is recorded for
/// it, and the device may try again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PositionState {
    Realized,
    /// Nothing executed and no balance moved.
    Void,
    /// The predicates failed.
    Invalid,
    /// The predicates held; the network retries were exhausted.
    RetriesExhausted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PositionOutcome {
    pub position: u64,
    pub state: PositionState,
}

pub(crate) fn refuse(what: impl std::fmt::Display) -> DsmError {
    DsmError::invalid_operation(format!("sofi: {what}"))
}

pub(crate) fn storage(what: &str, e: impl std::fmt::Display) -> DsmError {
    DsmError::storage(format!("sofi: {what}: {e}"), None::<std::io::Error>)
}

/// Sign `message` with this device's AK.
pub(crate) fn sign(message: &[u8]) -> Result<Vec<u8>, DsmError> {
    let secret_key = crate::sdk::signing_authority::current_secret_key()?;
    dsm::crypto::sphincs::sphincs_sign(&secret_key, message)
}

/// The published object must be `Stored`, read back from the members, before
/// anything is built on it.
/// The address `object` is stored at: its bytes under its namespace.
pub(crate) fn publication_addr(object: &Publication<'_>) -> Result<D32, DsmError> {
    let bytes = object.object_bytes().map_err(refuse)?;
    Ok(dsm::storage_object::immutable_addr(
        object.namespace(),
        &bytes,
    ))
}

pub(crate) fn require_stored(what: &str, published: &Published) -> Result<(), DsmError> {
    if published.stored {
        Ok(())
    } else {
        Err(storage(
            what,
            "not Stored yet: fewer than three members return the exact bytes; nothing advanced",
        ))
    }
}

/// This device's identity.
pub(crate) fn identity(core: &CoreSDK) -> Result<(D32, D32), DsmError> {
    let head = core
        .device_head()
        .ok_or_else(|| storage("device head", "none"))?;
    Ok((head.genesis_digest(), head.devid()))
}

// ── §28 Creating a vault ───────────────────────────────────────────────────

/// §28: the owner's creation. The three policy objects and the genesis
/// preimage are published and read back `Stored` first: a genesis nobody's
/// creation carried is refused by `genesis_accepted`, so publishing first
/// asserts nothing, and it means the vault is findable — by its id and by
/// each of its two tokens (Amendment S16) — the moment it exists.
/// Then the creation runs through the Core transition, debiting both
/// reserves as one write set.
pub async fn create_vault(
    core: &CoreSDK,
    set: &StorageSet,
    intent: &CreateVaultIntent,
) -> Result<VaultCreated, DsmError> {
    let (genesis, device_id) = identity(core)?;
    let validated = validated_root_or_activate(core)?;
    let create_position = next_position(validated.economic_position()).map_err(refuse)?;

    let pair = MarketPolicy::beta_constant_product(
        intent.token_a_policy_commit,
        intent.token_b_policy_commit,
    )
    .map_err(refuse)?;
    let market = pair.encode();
    let fee = FeePolicy::new(intent.fee_bps).map_err(refuse)?.encode();
    let release = ReleasePolicy::beta_owner_local_full_close().encode();
    let policies = [
        (VaultPolicyClass::Market, &market),
        (VaultPolicyClass::Fee, &fee),
        (VaultPolicyClass::Release, &release),
    ];
    // The genesis names each policy by its address, which its bytes fix: the
    // addresses are derived here, and the policies and the genesis that
    // names them are published together below, every one read back Stored
    // before the admission.
    let mut addresses = BTreeMap::new();
    for (class, bytes) in &policies {
        let publication = Publication::VaultPolicy {
            class: *class,
            bytes,
        };
        addresses.insert(class.class(), publication_addr(&publication)?);
    }
    let address = |class: u16| {
        addresses
            .get(&class)
            .copied()
            .ok_or_else(|| refuse("a vault policy was not published"))
    };
    let state = VaultStateLeaf {
        owner_genesis: genesis,
        owner_device_id: device_id,
        create_position,
        market_policy: address(dsm::ccb::class::MARKET_POLICY)?,
        fee_policy: address(dsm::ccb::class::FEE_POLICY)?,
        release_policy: address(dsm::ccb::class::RELEASE_POLICY)?,
        storage_set_id: set.id(),
        generation: 0,
        reserve_a: intent.reserve_a,
        reserve_b: intent.reserve_b,
        status: VAULT_STATUS_ACTIVE,
    };
    let preimage = VaultGenesisPreimage {
        owner_genesis: genesis,
        owner_device_id: device_id,
        create_position,
        state,
    };
    let produced = build_vault_create(&preimage, &market).map_err(refuse)?;
    // The genesis is indexed under its genesis locator and under each token
    // of its pair, so any trader finds it by the tokens it trades (Amendment
    // S16). None of the four objects waits on another's answer.
    let mut publications: Vec<Publication<'_>> = policies
        .iter()
        .map(|(class, bytes)| Publication::VaultPolicy {
            class: *class,
            bytes,
        })
        .collect();
    publications.push(Publication::VaultGenesis {
        preimage: &preimage,
        market: &pair,
    });
    let published =
        futures::future::try_join_all(publications.iter().map(|object| publish(set, object)))
            .await?;
    for (object, published) in publications.iter().zip(&published) {
        require_stored("vault object", published)?;
        if published.addr != publication_addr(object)? {
            return Err(refuse("a vault object was stored at another address"));
        }
    }

    let operation = produced
        .operation
        .clone()
        .with_signature(sign(produced.signs.bytes())?);
    let deltas = [
        BalanceDelta {
            policy_commit: intent.token_a_policy_commit,
            direction: BalanceDirection::Debit,
            amount: intent.reserve_a,
        },
        BalanceDelta {
            policy_commit: intent.token_b_policy_commit,
            direction: BalanceDirection::Debit,
            amount: intent.reserve_b,
        },
    ];
    // The genesis names `create_position`, the successor of the predecessor
    // it was built on: the admission is refused before the advance unless
    // that is still the predecessor this device stands on.
    let (outcome, admitted) = admitted_self_loop_operation(
        core,
        operation,
        &deltas,
        CreditSourceFacts::None,
        Vec::new(),
        None,
        Some(BuiltOn::of(&validated)),
    )
    .await?;
    let vault_id = preimage.vault_id();
    let moved: Vec<Moved> = deltas
        .iter()
        .map(|d| Moved {
            policy_commit: d.policy_commit,
            direction: d.direction,
            amount: d.amount,
        })
        .collect();
    record_realized(
        &outcome.new_device_state,
        Realized::VaultCreate,
        &vault_id,
        admitted.economic_position,
        &[vault_id],
        &moved,
    );
    Ok(VaultCreated {
        vault_id,
        position: admitted.economic_position,
    })
}

// ── §29 Setting up with a vault ────────────────────────────────────────────

/// The digest of the claim this device registered at its admitted position:
/// what a setup names as `claim_ref` (Amendment S9).
fn own_claim_ref(admitted: &AdmittedEconomicPosition) -> Result<D32, DsmError> {
    match admitted {
        AdmittedEconomicPosition::SingleRoot {
            economic_position, ..
        } => {
            let (.., bytes) = economic_lineage::get_frozen_root_claim(*economic_position)
                .map_err(|e| storage("frozen root claim", e))?
                .ok_or_else(|| {
                    refuse(format!(
                        "no claim of this device's own at position {economic_position}"
                    ))
                })?;
            Ok(derive::claim_ref(&bytes))
        }
        AdmittedEconomicPosition::ResolvedSofi { claim_ref, .. } => Ok(*claim_ref),
        AdmittedEconomicPosition::UnresolvedSofi {
            economic_position, ..
        } => Err(refuse(format!(
            "the admitted position {economic_position} is conditional and unresolved"
        ))),
    }
}

/// §29: the setup body is built against this device's validated predecessor,
/// published and read back `Stored`, then carried by the trader's transition,
/// which inserts `h⁰`. Run by [`set_up_with`] ahead of the first operation
/// through the vault (Amendment S16).
async fn setup(
    core: &CoreSDK,
    set: &StorageSet,
    intent: &SetupIntent,
    accepted: &AcceptedGeneses,
) -> Result<(), DsmError> {
    let (genesis, device_id) = identity(core)?;
    let admitted = economic_lineage::get_admitted()
        .map_err(|e| storage("load admitted", e))?
        .ok_or_else(|| {
            refuse("no admitted position: a setup names the claim registered at its position")
        })?;
    let validated = validated_root_or_activate(core)?;
    let ctx = VerifierContext::sharing(set, Some((genesis, device_id)), Some(&admitted), accepted)?;
    match ctx
        .verifier()
        .vault_genesis(&intent.vault_id)
        .map_err(verifier_error)?
    {
        VaultGenesis::Accepted(..) => {}
        VaultGenesis::NotPublished => {
            return Err(refuse(
                "no genesis the owner's creation carried is published",
            ))
        }
        VaultGenesis::OwnerUnresolved(why) => {
            return Err(refuse(format!(
                "the vault owner's lineage is unresolved: {why}"
            )))
        }
        VaultGenesis::Refused(why) => return Err(refuse(format!("vault genesis refused: {why}"))),
    }
    let (pre_tree, ..) = producer_tree_and_pre_state(&validated)?;
    let claim_ref = own_claim_ref(&admitted)?;
    let public_key = crate::sdk::signing_authority::current_public_key()?;
    let produced = build_setup(
        &validated,
        &pre_tree,
        genesis,
        device_id,
        intent.vault_id,
        claim_ref,
        SIGNATURE_ALG,
        &public_key,
    )
    .map_err(refuse)?;
    let signature = sign(produced.signs.bytes())?;
    let setup_ref = match produced.publish.as_slice() {
        [ToPublish::Setup(body)] => derive::setup_ref(body),
        other => {
            return Err(refuse(format!(
                "a setup publishes its body alone, not {} objects",
                other.len()
            )))
        }
    };
    for published in publish_produced(set, &produced, &signature).await? {
        require_stored("setup", &published)?;
    }
    let operation = produced.operation.clone().with_signature(signature);
    // The setup is built against `validated`: the admission is refused
    // before the advance unless that is still the predecessor this device
    // stands on.
    let (outcome, admitted) = admitted_self_loop_operation(
        core,
        operation,
        &[],
        CreditSourceFacts::None,
        Vec::new(),
        None,
        Some(BuiltOn::of(&validated)),
    )
    .await?;
    record_realized(
        &outcome.new_device_state,
        Realized::Setup,
        &setup_ref,
        admitted.economic_position,
        &[intent.vault_id],
        &[],
    );
    Ok(())
}

// ── §30 Finding the head of a vault ────────────────────────────────────────

/// A vault at its walked head: the root the next hop is built on, its state,
/// this device's witness there — the state leaf and this device's
/// relationship leaf with their paths (SoFi Amendment S24) — and its terms: a
/// market's policies, or an escrow vault's terms (SoFi Amendment S21).
pub(crate) struct VaultAtHead {
    pub(crate) vault_id: D32,
    pub(crate) root: D32,
    pub(crate) state: VaultStateLeaf,
    pub(crate) witness: VaultWitness,
    pub(crate) terms: VaultTerms,
}

impl VaultAtHead {
    /// The market's policies; an escrow vault has no market to price by.
    fn market(&self) -> Result<&Policies, DsmError> {
        match &self.terms {
            VaultTerms::Market(policies) => Ok(policies),
            VaultTerms::Escrow(..) | VaultTerms::Computed(..) => {
                Err(refuse("an escrow vault has no market"))
            }
        }
    }
}

/// What this device stands on: its identity, its validated predecessor and
/// the leaves that form it, and the conditional positions it resolved.
pub(crate) struct Standing {
    pub(crate) genesis: D32,
    pub(crate) device_id: D32,
    pub(crate) validated: ValidatedEconomicRoot,
    pub(crate) admitted: AdmittedEconomicPosition,
    pub(crate) local: LocalLeaves,
    pub(crate) tree: EconomicSmt,
    pub(crate) balances: BTreeMap<D32, u64>,
}

/// Stage 0 of §31: no pending position, and a resolved predecessor.
pub(crate) fn standing(core: &CoreSDK) -> Result<Standing, DsmError> {
    let head = core
        .device_head()
        .ok_or_else(|| storage("device head", "none"))?;
    if let Some(pending) = head.pending_economic_admission() {
        return Err(refuse(format!(
            "position {} is pending; resolve it before building the next one",
            pending.economic_position
        )));
    }
    let (genesis, device_id) = (head.genesis_digest(), head.devid());
    let validated = validated_root_or_activate(core)?;
    let admitted = economic_lineage::get_admitted()
        .map_err(|e| storage("load admitted", e))?
        .ok_or_else(|| refuse("no admitted position to build on"))?;
    let (tree, pre_state) = producer_tree_and_pre_state(&validated)?;
    let local = local_leaves_of_validated(&genesis, &device_id, &validated)?;
    Ok(Standing {
        genesis,
        device_id,
        validated,
        admitted,
        local,
        tree,
        balances: pre_state.balances,
    })
}

/// The terms `state` commits — a market's three policies, or an escrow
/// vault's terms — fetched by the addresses it names and decoded by Core,
/// which re-addresses each first.
///
/// The objects are content-addressed and none names another: they are read
/// at once, and an object once read `Stored` is kept by the process.
async fn vault_terms(set: &StorageSet, state: &VaultStateLeaf) -> Result<VaultTerms, DsmError> {
    let read = futures::future::try_join_all(EvidenceNeeds::policies_of(state).into_iter().map(
        |(class, addr)| async move {
            let bytes = crate::sdk::storage_io::read_stored_bytes_kept(set, &addr)
                .await?
                .ok_or_else(|| {
                    storage(
                        "vault policy",
                        format!("the class {class:#06x} object the vault commits is not Stored"),
                    )
                })?;
            Ok::<_, DsmError>((addr, bytes))
        },
    ))
    .await?;
    let objects: BTreeMap<_, _> = read.into_iter().collect();
    let evidence = Evidence::acquired(
        objects,
        BTreeMap::new(),
        BTreeMap::new(),
        BTreeMap::new(),
        BTreeMap::new(),
    );
    VaultTerms::resolve(&evidence, state).map_err(|refusal| refuse(format!("{refusal:?}")))
}

/// §30: walk `vault_id` to its head — from the genesis, or from the owner
/// baseline this device started its record at — and witness it there.
pub(crate) async fn vault_at_head(
    set: &StorageSet,
    verifier: &Verifier<'_, LiveSofiReads<'_>>,
    vault_id: &D32,
) -> Result<(VaultAtHead, VaultChain), DsmError> {
    // The history others published is read ahead of the walk (SoFi
    // Amendment S23); the walk establishes the chain exactly as before.
    let history = crate::sdk::vault_history::discover(set, vault_id).await?;
    let chain =
        tokio::task::block_in_place(|| crate::sdk::vault_history::walk(set, verifier, &history))?;
    head_of(set, verifier, vault_id, chain).await
}

/// Start the record of each vault `offered` that this device holds nothing
/// of at the owner baseline offered for it (SoFi Amendment S24): what a
/// quote and a swap do before they walk the vaults' heads.
pub(crate) async fn adopt_offered(
    core: &CoreSDK,
    set: &StorageSet,
    offered: &[dsm::types::proto::ConnectVaultWitnessV1],
) -> Result<(), DsmError> {
    let accepted = &AcceptedGeneses::default();
    let standing = standing(core)?;
    let ctx = standing.context(set, accepted)?;
    let verifier = ctx.verifier();
    crate::sdk::vault_baseline::adopt(
        set,
        &verifier,
        offered,
        (standing.genesis, standing.device_id),
    )
    .await
}

/// Each of `vault_ids`' chains, walked at once, in the order given. A vault's
/// walk reads its owner's lineage and its own cells, and needs nothing
/// another vault's walk finds first, so each runs on a thread of its own over
/// the one verifier: the reads it keeps are shared, and each read blocks only
/// its own walk.
async fn chains_at_once(
    set: &StorageSet,
    verifier: &Verifier<'_, LiveSofiReads<'_>>,
    vault_ids: &[D32],
) -> Vec<Result<VaultChain, DsmError>> {
    // Each vault's history is read from the epoch index first, at once
    // (SoFi Amendment S23), and read ahead of its walk.
    let histories = crate::sdk::vault_history::discover_all(set, vault_ids).await;
    tokio::task::block_in_place(|| {
        std::thread::scope(|scope| {
            let walks: Vec<_> = histories
                .iter()
                .map(|history| {
                    scope.spawn(move || match history {
                        Ok(history) => crate::sdk::vault_history::walk(set, verifier, history),
                        Err(e) => Err(DsmError::storage(
                            format!("vault history: {e}"),
                            None::<std::io::Error>,
                        )),
                    })
                })
                .collect();
            // A walk that panicked panics here, as it would have in line.
            walks
                .into_iter()
                .map(|walk| match walk.join() {
                    Ok(chain) => chain,
                    Err(panic) => std::panic::resume_unwind(panic),
                })
                .collect()
        })
    })
}

/// Each of `vault_ids` at its walked head, in the order given: the chains
/// walked at once ([`chains_at_once`]), then each head's leaves and terms
/// taken at once. A vault's walk and head need nothing another vault's find
/// first, and nothing here writes to storage.
async fn heads_at_once(
    set: &StorageSet,
    verifier: &Verifier<'_, LiveSofiReads<'_>>,
    vault_ids: &[D32],
) -> Vec<Result<(VaultAtHead, VaultChain), DsmError>> {
    let chains = chains_at_once(set, verifier, vault_ids).await;
    futures::future::join_all(
        vault_ids
            .iter()
            .zip(chains)
            .map(|(vault_id, chain)| async move { head_of(set, verifier, vault_id, chain?).await }),
    )
    .await
}

/// `vault_id` at the head of its walked `chain`, witnessed for this device.
pub(crate) async fn head_of(
    set: &StorageSet,
    verifier: &Verifier<'_, LiveSofiReads<'_>>,
    vault_id: &D32,
    chain: VaultChain,
) -> Result<(VaultAtHead, VaultChain), DsmError> {
    if let Some(why) =
        sofi_vault_head::quarantined(vault_id).map_err(|e| storage("vault quarantine", e))?
    {
        return Err(refuse(format!("the vault is quarantined: {why}")));
    }
    let (.., root) = chain
        .head()
        .ok_or_else(|| refuse("no head of this vault is established"))?;
    let own = verifier.reads.own().ok_or_else(|| {
        refuse("a vault's head is witnessed for a trader, and this context is none")
    })?;
    let witness = head_witness(verifier, vault_id, &chain, own)?;
    let state = witness.state().clone();
    let terms = vault_terms(set, &state).await?;
    Ok((
        VaultAtHead {
            vault_id: *vault_id,
            root,
            state,
            witness,
            terms,
        },
        chain,
    ))
}

/// This device's witness of `vault_id` at the head of `chain`: the one it
/// recorded and advanced to that head; at the genesis, the genesis's; or,
/// where this device holds the whole tree at the head (it walked every
/// generation), one stated from that tree. Each is checked by Core against
/// the chain's head before it is stood on, and kept, so the generations
/// recorded next advance it.
fn head_witness(
    verifier: &Verifier<'_, LiveSofiReads<'_>>,
    vault_id: &D32,
    chain: &VaultChain,
    own: (D32, D32),
) -> Result<VaultWitness, DsmError> {
    let (generation, root) = chain
        .head()
        .ok_or_else(|| refuse("no head of this vault is established"))?;
    let recorded = sofi_vault_head::witness(vault_id).map_err(|e| storage("vault witness", e))?;
    let witness = match recorded {
        Some(held)
            if held.generation == generation
                && held.root == root
                && (held.trader_genesis, held.trader_device_id) == own =>
        {
            match VaultWitness::recorded(chain, vault_id, &held.witness, own.0, own.1) {
                Ok(witness) => witness,
                Err(refused) => {
                    // This device's witness at the head it recorded does not
                    // fold to that head: two of its own conclusions disagree.
                    let why =
                        format!("the recorded witness at the head does not fold to it: {refused}");
                    sofi_vault_head::quarantine(vault_id, &why)
                        .map_err(|e| storage("vault quarantine", e))?;
                    return Err(refuse(why));
                }
            }
        }
        _ if generation == 0 => {
            let accepted = match verifier.vault_genesis(vault_id).map_err(verifier_error)? {
                VaultGenesis::Accepted(accepted) => accepted,
                VaultGenesis::NotPublished => {
                    return Err(refuse(
                        "no genesis the owner's creation carried is published",
                    ))
                }
                VaultGenesis::OwnerUnresolved(why) => {
                    return Err(refuse(format!(
                        "the vault owner's lineage is unresolved: {why}"
                    )))
                }
                VaultGenesis::Refused(why) => {
                    return Err(refuse(format!("vault genesis refused: {why}")))
                }
            };
            VaultWitness::at_genesis(&accepted, own.0, own.1).map_err(refuse)?
        }
        _ => {
            let (tree, state, relationships) = crate::sdk::vault_baseline::tree_at(
                vault_id, generation, &root,
            )?
            .ok_or_else(|| {
                refuse("this device holds no witness of the vault's head, and not its whole tree")
            })?;
            let rel_key = derive::relationship_key(&own.0, &own.1, vault_id);
            let wire = dsm::sofi::frontier::witness_from_tree(
                &tree,
                vault_id,
                &state,
                relationships.get(&rel_key).copied(),
                &own.0,
                &own.1,
            );
            VaultWitness::recorded(chain, vault_id, &wire, own.0, own.1).map_err(refuse)?
        }
    };
    sofi_vault_head::put_witness(&witness).map_err(|e| storage("vault witness", e))?;
    Ok(witness)
}

impl Standing {
    /// This device as the verifier: its identity and the position it
    /// resolved itself, over the pinned set.
    pub(crate) fn context<'a>(
        &'a self,
        set: &'a StorageSet,
        accepted: &AcceptedGeneses,
    ) -> Result<VerifierContext<'a>, DsmError> {
        self.context_kept(set, accepted, &KeptReadings::default())
    }

    /// [`Self::context`], keeping what it reads in `kept`, which the other
    /// contexts of the same operation share.
    pub(crate) fn context_kept<'a>(
        &'a self,
        set: &'a StorageSet,
        accepted: &AcceptedGeneses,
        kept: &KeptReadings,
    ) -> Result<VerifierContext<'a>, DsmError> {
        VerifierContext::sharing_kept(
            set,
            Some((self.genesis, self.device_id)),
            Some(&self.admitted),
            accepted,
            kept,
        )
    }
}

/// The other token of a vault's pair, and whether `token_in` is its `a`. An
/// escrow vault has no pair, and trades nothing.
fn other_token(terms: &VaultTerms, token_in: &D32) -> Option<(D32, bool)> {
    let VaultTerms::Market(policies) = terms else {
        return None;
    };
    let (a, b) = (*policies.market.token_a(), *policies.market.token_b());
    if *token_in == a {
        Some((b, true))
    } else if *token_in == b {
        Some((a, false))
    } else {
        None
    }
}

/// What a vault's head gives for `amount_in` of `token_in`: the other token
/// of its pair, and the amount the one constant-product arithmetic prices.
fn quote(
    vault: &VaultAtHead,
    token_in: &D32,
    amount_in: u64,
    index: usize,
) -> Result<(D32, u64), DsmError> {
    // A vault without a market prices nothing, whatever token is offered.
    let fee_bps = vault.market()?.fee.fee_bps();
    let (token_out, in_is_a) = other_token(&vault.terms, token_in)
        .ok_or_else(|| refuse(format!("hop {index}: the vault does not trade that token")))?;
    let (reserve_in, reserve_out) = if in_is_a {
        (vault.state.reserve_a, vault.state.reserve_b)
    } else {
        (vault.state.reserve_b, vault.state.reserve_a)
    };
    let amount_out =
        constant_product_output_classified(amount_in, reserve_in, reserve_out, fee_bps)
            .map_err(|e| refuse(format!("hop {index}: {e:?}")))?;
    Ok((token_out, amount_out))
}

/// One hop priced at a vault's head, naming this device's setup with it, and
/// the post state Core computes from it.
fn price_hop(
    vault: &VaultAtHead,
    token_in: D32,
    amount_in: u64,
    setup_ref: D32,
    index: usize,
) -> Result<(SwapHop, VaultStateLeaf), DsmError> {
    let (token_out, amount_out) = quote(vault, &token_in, amount_in, index)?;
    let hop = SwapHop {
        vault_id: vault.vault_id,
        parent_root: vault.root,
        setup_ref,
        token_in,
        amount_in,
        token_out,
        amount_out,
    };
    let post = swap_vault_post(&vault.state, vault.market()?, &hop, index)
        .map_err(|refusal| refuse(format!("hop {index}: {refusal:?}")))?;
    Ok((hop, post))
}

/// One hop as planned at its vault's head: what goes in and what comes out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Planned {
    token_in: D32,
    amount_in: u64,
    token_out: D32,
    amount_out: u64,
}

impl Planned {
    fn movement(&self) -> HopMovement {
        (
            self.token_in,
            self.amount_in,
            self.token_out,
            self.amount_out,
        )
    }
}

/// What `vault` gives for `amount_in` of `token_in` at its head: `None` for
/// an amount too small to move it. Any other refusal is an error.
fn leg_out(vault: &VaultAtHead, token_in: &D32, amount_in: u64) -> Result<Option<u64>, DsmError> {
    let fee_bps = vault.market()?.fee.fee_bps();
    let (_, in_is_a) = other_token(&vault.terms, token_in)
        .ok_or_else(|| refuse("the vault does not trade that token"))?;
    let (reserve_in, reserve_out) = if in_is_a {
        (vault.state.reserve_a, vault.state.reserve_b)
    } else {
        (vault.state.reserve_b, vault.state.reserve_a)
    };
    match constant_product_output_classified(amount_in, reserve_in, reserve_out, fee_bps) {
        Ok(out) => Ok(Some(out)),
        Err(ConstantProductRefusal::OutputZero) => Ok(None),
        Err(other) => Err(refuse(other.as_str())),
    }
}

/// The least input in `1..=max` that `vault` prices, by bisection: a larger
/// input never gives less.
fn least_priced(vault: &VaultAtHead, token_in: &D32, max: u64) -> Result<Option<u64>, DsmError> {
    if leg_out(vault, token_in, max)?.is_none() {
        return Ok(None);
    }
    let (mut lo, mut hi) = (1u64, max);
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        match leg_out(vault, token_in, mid)? {
            Some(..) => hi = mid,
            None => lo = mid + 1,
        }
    }
    Ok(Some(lo))
}

/// The split of `amount_in` of `token_in` across `one` and `two`, which both
/// trade it for `token_out`, that gives the most (Amendment S19): each leg
/// priced at its own vault's head, the share searched over the inputs both
/// legs price. `None` when no split prices both legs.
fn plan_split(
    one: &VaultAtHead,
    two: &VaultAtHead,
    token_in: D32,
    token_out: D32,
    amount_in: u64,
) -> Result<Option<[Planned; 2]>, DsmError> {
    if amount_in < 2 {
        return Ok(None);
    }
    let (Some(least_one), Some(least_two)) = (
        least_priced(one, &token_in, amount_in - 1)?,
        least_priced(two, &token_in, amount_in - 1)?,
    ) else {
        return Ok(None);
    };
    let (mut lo, mut hi) = (least_one, amount_in - least_two);
    if lo > hi {
        return Ok(None);
    }
    let legs = |x: u64| -> Result<(u64, u64), DsmError> {
        let first = leg_out(one, &token_in, x)?
            .ok_or_else(|| refuse("a split leg below the first vault's least price"))?;
        let second = leg_out(two, &token_in, amount_in - x)?
            .ok_or_else(|| refuse("a split leg below the second vault's least price"))?;
        Ok((first, second))
    };
    let total = |x: u64| -> Result<u64, DsmError> {
        let (first, second) = legs(x)?;
        first
            .checked_add(second)
            .ok_or_else(|| refuse("a split's output overflows"))
    };
    // The total is concave in the share, up to the price's floor: narrow
    // by thirds, then take the best of what is left.
    while hi - lo > 2 {
        let m1 = lo + (hi - lo) / 3;
        let m2 = hi - (hi - lo) / 3;
        if total(m1)? < total(m2)? {
            lo = m1 + 1;
        } else {
            hi = m2;
        }
    }
    let mut best = (lo, total(lo)?);
    for x in lo + 1..=hi {
        let t = total(x)?;
        if t > best.1 {
            best = (x, t);
        }
    }
    let (first, second) = legs(best.0)?;
    Ok(Some([
        Planned {
            token_in,
            amount_in: best.0,
            token_out,
            amount_out: first,
        },
        Planned {
            token_in,
            amount_in: amount_in - best.0,
            token_out,
            amount_out: second,
        },
    ]))
}

/// The hops through `vaults` in order, each feeding the next.
fn plan_chain(
    vaults: &[&VaultAtHead],
    token_in: D32,
    amount_in: u64,
) -> Result<Vec<Planned>, DsmError> {
    let mut token = token_in;
    let mut amount = amount_in;
    let mut out = Vec::with_capacity(vaults.len());
    for (index, vault) in vaults.iter().enumerate() {
        let (token_out, amount_out) = quote(vault, &token, amount, index)?;
        out.push(Planned {
            token_in: token,
            amount_in: amount,
            token_out,
            amount_out,
        });
        token = token_out;
        amount = amount_out;
    }
    Ok(out)
}

/// A route through `vaults` at their heads (Amendment S19): split across
/// them when there are two and both trade `token_in` for the same token,
/// chained otherwise.
fn plan(vaults: &[&VaultAtHead], token_in: D32, amount_in: u64) -> Result<Vec<Planned>, DsmError> {
    if let [one, two] = vaults {
        if let (Some((a, ..)), Some((b, ..))) = (
            other_token(&one.terms, &token_in),
            other_token(&two.terms, &token_in),
        ) {
            if a == b {
                return plan_split(one, two, token_in, a, amount_in)?
                    .map(Vec::from)
                    .ok_or_else(|| refuse("the amount does not split across the two vaults"));
            }
        }
    }
    plan_chain(vaults, token_in, amount_in)
}

/// What a planned route gives the trader: its output token and amount, by
/// Core's one rule for a chain's or a split's endpoints.
fn planned_out(planned: &[Planned]) -> Result<(D32, u64), DsmError> {
    let movements: Vec<HopMovement> = planned.iter().map(Planned::movement).collect();
    let (.., token_out, exact_out) =
        route_endpoints(&movements).map_err(|why| refuse(format!("{why:?}")))?;
    Ok((token_out, exact_out))
}

/// [`RouteEnds`] of a proposed route; `None` for no hops.
fn route_ends(hops: &[Hop]) -> Result<Option<RouteEnds>, DsmError> {
    let movements: Vec<HopMovement> = hops
        .iter()
        .map(|h| {
            (
                h.token_in_policy_commit,
                h.amount_in,
                h.token_out_policy_commit,
                h.amount_out,
            )
        })
        .collect();
    let Some(shape) = movement_shape(&movements) else {
        return Ok(None);
    };
    let (_, amount_in, _, amount_out) =
        route_endpoints(&movements).map_err(|why| refuse(format!("{why:?}")))?;
    Ok(Some(RouteEnds {
        shape,
        amount_in,
        amount_out,
    }))
}

/// Geneses accepted at once.
const GENESES_AT_ONCE: usize = 16;

/// What accepting the vaults of a route's tokens ahead came to: a report
/// only. What a vault of a token is, is decided by `vaults_of_token`.
struct AcceptedAhead {
    candidates: usize,
    accepted: usize,
    not_accepted: Vec<String>,
}

impl core::fmt::Display for AcceptedAhead {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "{} candidate vaults, {} geneses accepted at once, {} not",
            self.candidates,
            self.accepted,
            self.not_accepted.len()
        )?;
        if let Some(first) = self.not_accepted.first() {
            write!(f, " (first: {first})")?;
        }
        Ok(())
    }
}

/// Accept the genesis of every vault published under `tokens`' indexes at
/// once, through the verifier's own `vault_genesis`, which keeps each one it
/// accepts for the rest of the operation. Each acceptance reads its owner's
/// creation; one at a time, a token with many vaults cost a round trip per
/// vault before a quote. Call from a thread that may block.
fn accept_ahead(verifier: &Verifier<'_, LiveSofiReads<'_>>, tokens: &[D32]) -> AcceptedAhead {
    use dsm::sofi::resolve::SofiReads as _;
    let mut report = AcceptedAhead {
        candidates: 0,
        accepted: 0,
        not_accepted: Vec::new(),
    };
    let mut vault_ids: Vec<D32> = Vec::new();
    for token in tokens {
        match verifier.reads.vault_token_candidates(token) {
            Ok(Discovered::Complete(found) | Discovered::Partial(found)) => {
                for vault_id in found {
                    if !vault_ids.contains(&vault_id) {
                        vault_ids.push(vault_id);
                    }
                }
            }
            Err(failure) => report
                .not_accepted
                .push(format!("the token index: {failure}")),
        }
    }
    report.candidates = vault_ids.len();
    for chunk in vault_ids.chunks(GENESES_AT_ONCE) {
        let outcomes: Vec<Result<VaultGenesis, String>> = std::thread::scope(|scope| {
            let handles: Vec<_> = chunk
                .iter()
                .map(|vault_id| {
                    scope.spawn(move || {
                        verifier
                            .vault_genesis(vault_id)
                            .map_err(|failure| failure.to_string())
                    })
                })
                .collect();
            handles
                .into_iter()
                .map(|handle| match handle.join() {
                    Ok(outcome) => outcome,
                    Err(panic) => std::panic::resume_unwind(panic),
                })
                .collect()
        });
        for outcome in outcomes {
            match outcome {
                Ok(VaultGenesis::Accepted(..)) => report.accepted += 1,
                Ok(VaultGenesis::NotPublished) => report.not_accepted.push("not published".into()),
                Ok(VaultGenesis::OwnerUnresolved(why) | VaultGenesis::Refused(why)) => {
                    report.not_accepted.push(why)
                }
                Err(why) => report.not_accepted.push(why),
            }
        }
    }
    report
}

/// How far below the best quote, in basis points, a route still counts as
/// near-equal to it. CLIENT POLICY, never validity: a route is valid or not
/// whatever this says. Wider spreads trades across more of a pair's vaults
/// (fewer races for one vault's key) at the cost of up to this much output;
/// tune it from the measured collision rate against the output given up.
pub(crate) const ROUTE_TOLERANCE_BPS: u64 = 300;

/// Which of a search's priced routes `(output, vault ids in hop order)` the
/// trader takes (client policy): among those within
/// [`ROUTE_TOLERANCE_BPS`] of the best output, the fewest legs, then the
/// order the trader's own identity gives the routes' vaults —
/// `H(DSM/sofi/route-lane/v1; G ‖ DevID ‖ sorted vault ids)` — then the
/// lowest vault ids. Deterministic: the same candidates give one trader the
/// same route, and different traders different vaults of a pair, so small
/// trades spread across the pair's vaults instead of piling into the first;
/// a split wins only when it beats every single vault by more than the
/// tolerance. `None` for no route.
fn choose_route(routes: &[(u64, Vec<D32>)], trader: (&D32, &D32)) -> Option<usize> {
    let best = routes.iter().map(|(out, ..)| *out).max()?;
    let floor = u128::from(best) * u128::from(10_000 - ROUTE_TOLERANCE_BPS);
    routes
        .iter()
        .enumerate()
        .filter(|(_, (out, ..))| u128::from(*out) * 10_000 >= floor)
        .min_by_key(|(_, (_, vaults))| {
            let mut sorted = vaults.clone();
            sorted.sort();
            let mut h = dsm::crypto::blake3::dsm_domain_hasher(
                dsm::common::domain_tags::TAG_DSM_SOFI_ROUTE_LANE,
            );
            h.update(trader.0);
            h.update(trader.1);
            for vault in &sorted {
                h.update(vault);
            }
            (vaults.len(), *h.finalize().as_bytes(), sorted)
        })
        .map(|(index, ..)| index)
}

/// The vaults whose market pairs `token`, from its token index (Amendment
/// S16): accepted by Core, never taken from the index. A discovery that is
/// not complete marks the search partial.
fn vaults_of(
    verifier: &Verifier<'_, LiveSofiReads<'_>>,
    token: &D32,
    search: &mut Search,
) -> Result<Vec<Paired>, DsmError> {
    let vaults = match verifier.vaults_of_token(token).map_err(verifier_error)? {
        Discovered::Complete(vaults) => vaults,
        Discovered::Partial(vaults) => {
            *search = Search::Partial;
            vaults
        }
    };
    Ok(vaults
        .iter()
        .filter_map(|accepted| {
            accepted.market().map(|market| Paired {
                vault_id: *accepted.vault_id(),
                tokens: (*market.token_a(), *market.token_b()),
            })
        })
        .collect())
}

/// The vaults a route search walks to their heads: only those that can be in
/// a candidate route of `find_route`, in the order found. One pairs the two
/// tokens; or it is a leg of a chain whose middle token both legs pair. Every
/// other vault of either token takes no part in any route, so walking its
/// chain would decide nothing (and on a shared network, every vault of the
/// native token is a vault of either token).
fn route_legs(firsts: &[Paired], seconds: &[Paired], token_in: &D32, token_out: &D32) -> Vec<D32> {
    let middles: BTreeSet<D32> = firsts
        .iter()
        .filter_map(|v| v.other(token_in))
        .filter(|middle| middle != token_out)
        .collect();
    let second_legs: Vec<&Paired> = seconds
        .iter()
        .filter(|v| v.other(token_out).is_some_and(|m| middles.contains(&m)))
        .collect();
    let reached: BTreeSet<D32> = second_legs
        .iter()
        .filter_map(|v| v.other(token_out))
        .collect();
    let mut walked: Vec<D32> = firsts
        .iter()
        .filter(|v| {
            v.other(token_in)
                .is_some_and(|o| &o == token_out || reached.contains(&o))
        })
        .map(|v| v.vault_id)
        .collect();
    for v in second_legs {
        if !walked.contains(&v.vault_id) {
            walked.push(v.vault_id);
        }
    }
    walked
}

/// A vault of a token, with the two tokens its accepted genesis commits its
/// market to: known before its chain is walked.
struct Paired {
    vault_id: D32,
    tokens: (D32, D32),
}

impl Paired {
    /// The token this vault's market pairs with `token`, if it pairs `token`.
    fn other(&self, token: &D32) -> Option<D32> {
        if &self.tokens.0 == token {
            Some(self.tokens.1)
        } else if &self.tokens.1 == token {
            Some(self.tokens.0)
        } else {
            None
        }
    }
}

/// §30 and the path search of `sofi.findRoute` (Amendment S16): the best
/// route of one or two hops (the beta `ROUTE_MAX_LEGS`) from `token_in` to
/// `token_out`. The vaults come from the two tokens' indexes — those that
/// pair the tokens directly, and a vault of each that share their other
/// token — and are not limited to the vaults this device is set up with; a
/// quote needs no setup. Each hop is priced at its vault's walked head. A
/// vault, or a head, that is not established is left out and makes the
/// search `Partial`; over what was established, no route is an empty list.
pub async fn find_route(
    core: &CoreSDK,
    set: &StorageSet,
    intent: &FindRouteIntent,
) -> Result<RouteFound, DsmError> {
    let accepted = &AcceptedGeneses::default();
    let standing = standing(core)?;
    let ctx = standing.context(set, accepted)?;
    let verifier = ctx.verifier();
    let mut search = Search::Complete;
    // Every vault of either token is accepted at once, so the discovery
    // below finds each one already accepted for this operation.
    let ahead = tokio::task::block_in_place(|| {
        accept_ahead(
            &verifier,
            &[
                intent.token_in_policy_commit,
                intent.token_out_policy_commit,
            ],
        )
    });
    log::info!("[sofi] route search: {ahead}");
    let firsts = vaults_of(&verifier, &intent.token_in_policy_commit, &mut search)?;
    let seconds = vaults_of(&verifier, &intent.token_out_policy_commit, &mut search)?;
    let (token_in, token_out) = (
        intent.token_in_policy_commit,
        intent.token_out_policy_commit,
    );
    let walked = route_legs(&firsts, &seconds, &token_in, &token_out);
    let firsts: Vec<D32> = firsts.iter().map(|v| v.vault_id).collect();
    let seconds: Vec<D32> = seconds.iter().map(|v| v.vault_id).collect();
    let mut heads: BTreeMap<D32, VaultAtHead> = BTreeMap::new();
    let mut unique: Vec<D32> = Vec::with_capacity(walked.len());
    for vault_id in &walked {
        if !unique.contains(vault_id) {
            unique.push(*vault_id);
        }
    }
    let at_heads = heads_at_once(set, &verifier, &unique).await;
    for (vault_id, at_head) in unique.iter().zip(at_heads) {
        match at_head {
            Ok((head, ..)) => {
                if head.state.status == VAULT_STATUS_ACTIVE {
                    heads.insert(*vault_id, head);
                }
            }
            // A head the reads did not establish may be the best route.
            Err(DsmError::Storage { .. }) => search = Search::Partial,
            // A head refused is no vault to trade through.
            Err(..) => {}
        }
    }
    // Every candidate route over the established heads: each vault of the
    // input token alone, each chain through a vault of each token, and each
    // split across two vaults of the pair (Amendment S19).
    let mut candidates: Vec<Vec<&VaultAtHead>> = Vec::new();
    let direct: Vec<&VaultAtHead> = firsts
        .iter()
        .filter_map(|id| heads.get(id))
        .filter(
            |vault| matches!(other_token(&vault.terms, &token_in), Some((t, ..)) if t == token_out),
        )
        .collect();
    for (i, one) in direct.iter().enumerate() {
        candidates.push(vec![one]);
        for two in &direct[i + 1..] {
            candidates.push(vec![one, two]);
        }
    }
    for first in firsts.iter().filter_map(|id| heads.get(id)) {
        let Some((middle, ..)) = other_token(&first.terms, &token_in) else {
            continue;
        };
        if middle == token_out {
            continue;
        }
        for second in seconds.iter().filter_map(|id| heads.get(id)) {
            if second.vault_id != first.vault_id
                && matches!(other_token(&second.terms, &middle), Some((t, ..)) if t == token_out)
            {
                candidates.push(vec![first, second]);
            }
        }
    }
    // Every candidate that carries the amount, priced; a candidate that
    // cannot is not a route, and no route leaves the list empty.
    let mut priced: Vec<(u64, Vec<Hop>)> = Vec::new();
    for vaults in candidates {
        let Ok(planned) = plan(&vaults, token_in, intent.amount_in) else {
            continue;
        };
        let (gives, out) = planned_out(&planned)?;
        if gives != token_out {
            continue;
        }
        let hops = vaults
            .iter()
            .zip(&planned)
            .map(|(vault, p)| Hop {
                vault_id: vault.vault_id,
                parent_root: vault.root,
                token_in_policy_commit: p.token_in,
                token_out_policy_commit: p.token_out,
                amount_in: p.amount_in,
                amount_out: p.amount_out,
            })
            .collect();
        priced.push((out, hops));
    }
    let routes: Vec<(u64, Vec<D32>)> = priced
        .iter()
        .map(|(out, hops)| (*out, hops.iter().map(|hop| hop.vault_id).collect()))
        .collect();
    let hops = match choose_route(&routes, (&standing.genesis, &standing.device_id)) {
        Some(chosen) => priced.swap_remove(chosen).1,
        None => Vec::new(),
    };
    let ends = route_ends(&hops)?;
    Ok(RouteFound { hops, search, ends })
}

/// `sofi.vaults`: one vault this device created, at its walked head.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnedVault {
    pub vault_id: D32,
    pub token_a_policy_commit: D32,
    pub token_b_policy_commit: D32,
    pub reserve_a: u64,
    pub reserve_b: u64,
    pub fee_bps: u32,
    pub generation: u64,
    pub status: u16,
}

/// `sofi.vaults`: every vault this device created — the creation records its
/// validated root commits — each walked to its head (§30), so the owner sees
/// the live reserves, fee, generation and status without closing. A vault
/// whose head is not established is an error: the list would not be the
/// owner's vaults as they stand.
pub async fn owned_vaults(core: &CoreSDK, set: &StorageSet) -> Result<Vec<OwnedVault>, DsmError> {
    let accepted = &AcceptedGeneses::default();
    let standing = standing(core)?;
    let ctx = standing.context(set, accepted)?;
    let verifier = ctx.verifier();
    let mut out = Vec::new();
    for creation in standing.local.vault_creations() {
        let (vault, ..) = vault_at_head(set, &verifier, &creation.vault_id).await?;
        // An escrow vault is listed by `escrow.vaults` (SoFi Amendment S21).
        let VaultTerms::Market(policies) = &vault.terms else {
            continue;
        };
        out.push(OwnedVault {
            vault_id: vault.vault_id,
            token_a_policy_commit: *policies.market.token_a(),
            token_b_policy_commit: *policies.market.token_b(),
            reserve_a: vault.state.reserve_a,
            reserve_b: vault.state.reserve_b,
            fee_bps: policies.fee.fee_bps(),
            generation: vault.state.generation,
            status: vault.state.status,
        });
    }
    Ok(out)
}

// ── §31 A trade and a multihop route ───────────────────────────────────────

/// The setup this device admitted with `vault_id`, by its reference: of the
/// setups published under the relationship index, the one whose `R_T^setup`
/// is the root this device admitted right after the setup's position.
pub(crate) async fn own_setup_ref(
    set: &StorageSet,
    genesis: &D32,
    device_id: &D32,
    vault_id: &D32,
) -> Result<D32, DsmError> {
    let (setups, complete) = match fetch_setup_for(set, genesis, device_id, vault_id).await? {
        Discovered::Complete(setups) => (setups, true),
        Discovered::Partial(setups) => (setups, false),
    };
    for signed in setups {
        let admitted_at = next_position(signed.body.position()).map_err(refuse)?;
        if let Some(AdmittedEconomicPosition::SingleRoot { economic_root, .. }) =
            economic_lineage::get_admitted_at(admitted_at)
                .map_err(|e| storage("admitted history", e))?
        {
            if economic_root == *signed.body.setup_root() {
                return Ok(derive::setup_ref(&signed.body));
            }
        }
    }
    // A setup the scan could not establish may be the one this device
    // admitted: only a complete scan says it is not published.
    if complete {
        Err(refuse(
            "no published setup with this vault is one this device admitted",
        ))
    } else {
        Err(storage(
            "setup",
            "the relationship index scan did not establish every candidate",
        ))
    }
}

/// How many times a trade is planned again when the vault moves under its
/// draft before anything is published.
const TRADE_REPLANS: usize = 3;

/// What the walk at a parent found for a new attempt.
enum Walked {
    /// The live attempt: the walk's first unresolved key, advanced past keys
    /// an exercise still in flight holds.
    Live(u64),
    /// A key the walk would have passed was held by an exercise whose pair
    /// its trader withheld, and that pair is now registered from the
    /// exercise. The walk is run again.
    Registered,
    /// The vault moved under the draft: its parent was consumed, or every
    /// nearby key is held by an exercise still in flight. Nothing is
    /// published; the trade re-plans at the vault's new head.
    Moved(String),
}

/// The walk at `parent_root` of `vault_id` (§31 stage 6): its first
/// unresolved key, advanced past keys an exercise still in flight holds.
///
/// Before it goes past a key held by an exercise whose position pair is not
/// registered, it registers that pair from the trader's signed `C_q` the
/// exercise carries (owner ruling, 2026-10-01, pre-audit 12e: "If a vault key
/// is held by an exercise whose pair is not yet registered, the relayer MUST
/// use the signed C_q carried by that exercise to register the trader's
/// missing pair before advancing past that held key"). The relayer authors
/// nothing: it carries the trader's bytes exactly. A pair already
/// registered, lost, or not decided by the reads is not written.
async fn walk_for_attempt(
    set: &StorageSet,
    verifier: &Verifier<'_, LiveSofiReads<'_>>,
    chains: &BTreeMap<D32, VaultChain>,
    vault_id: &D32,
    parent_root: &D32,
) -> Result<Walked, DsmError> {
    let mut walked = verifier
        .walk_parent(chains, vault_id, parent_root, 0, WALK_BUDGET)
        .map_err(verifier_error)?;
    let first = loop {
        match walked.outcome {
            WalkOutcome::Unresolved { attempt } => break attempt,
            WalkOutcome::Continue { .. } => {
                walked = verifier
                    .continue_walk(chains, walked, WALK_BUDGET)
                    .map_err(verifier_error)?
            }
            WalkOutcome::Consumed { attempt } => {
                return Ok(Walked::Moved(format!(
                    "the vault's parent was consumed at attempt {attempt}: its head moved"
                )))
            }
            WalkOutcome::CounterExhausted { attempt } => {
                return Err(refuse(format!(
                    "the attempt counter is exhausted at {attempt}"
                )))
            }
        }
    };
    let mut attempt = first;
    // The walk read the key it stopped on: that reading is what holds the key
    // as this attempt knows it, and the key is not read again to learn it.
    let mut in_hand = walked.unresolved_reading().cloned();
    let mut advanced = 0;
    while advanced <= ATTEMPT_ADVANCE {
        let held = match in_hand.take() {
            Some(read) => Ok(read),
            None => verifier
                .read_attempt_cell(vault_id, parent_root, attempt)
                .map_err(verifier_error)?,
        };
        let read = match held {
            Ok(read) => read,
            Err(missing) => {
                return Err(storage(
                    "attempt cell",
                    format!("the reads do not decide attempt {attempt}: {missing:?}"),
                ))
            }
        };
        let Some(exercise) = read.exercise() else {
            return Ok(Walked::Live(attempt));
        };
        if pair_withheld(verifier, exercise, attempt)? {
            let relayed =
                crate::sdk::sofi_relay::relay_exercise(set, vault_id, parent_root, attempt).await?;
            if !relayed.pair.iter().all(|report| report.reached_leader()) {
                return Err(storage(
                    "withheld pair",
                    format!(
                        "the leader of the pair the exercise at attempt {attempt} carries did not \
                         take it"
                    ),
                ));
            }
            log::info!(
                "[sofi] registered the withheld pair of the exercise at attempt {attempt} from \
                 its own signed C_q"
            );
            return Ok(Walked::Registered);
        }
        attempt = next_attempt(attempt).map_err(refuse)?;
        advanced += 1;
    }
    Ok(Walked::Moved(
        "every nearby attempt key is held by an exercise in flight".to_string(),
    ))
}

/// Whether the position pair of the exercise holding `attempt` is still to
/// be registered: neither registered nor lost, as its cells read now. Reads
/// that do not decide the pair establish nothing, so the pair is not
/// written on them.
fn pair_withheld(
    verifier: &Verifier<'_, LiveSofiReads<'_>>,
    exercise: &dsm::sofi::exercise::RecognizedExercise,
    attempt: u64,
) -> Result<bool, DsmError> {
    let (precommit, fulfillment) = (&exercise.precommit().body, &exercise.fulfillment().body);
    let standing = match verifier
        .read_registration(
            precommit.genesis(),
            precommit.device_id(),
            fulfillment.position(),
            precommit.void_root(),
        )
        .map_err(verifier_error)?
    {
        Ok(read) => Some(read.standing_of(precommit, fulfillment)),
        Err(missing) => {
            log::info!(
                "[sofi] the pair of the exercise at attempt {attempt} is not decided yet: \
                 {missing:?}"
            );
            None
        }
    };
    Ok(standing == Some(PairStanding::Pending))
}

/// The live attempt of a leg at `parent_root` (§31 stage 6), every withheld
/// pair the walk meets registered first, or why the vault moved under the
/// draft (`Err`). A registration can consume the parent: the walk run again
/// then says the head moved.
async fn live_attempt(
    set: &StorageSet,
    verifier: &Verifier<'_, LiveSofiReads<'_>>,
    chains: &mut BTreeMap<D32, VaultChain>,
    vault_id: &D32,
    parent_root: &D32,
) -> Result<Result<u64, String>, DsmError> {
    // Each round registers a pair the walk met at one of the keys it
    // examines, at most ATTEMPT_ADVANCE + 1 of them.
    for _ in 0..=ATTEMPT_ADVANCE {
        match walk_for_attempt(set, verifier, chains, vault_id, parent_root).await? {
            Walked::Live(attempt) => return Ok(Ok(attempt)),
            Walked::Moved(why) => return Ok(Err(why)),
            Walked::Registered => {
                chains.insert(*vault_id, verifier.chain(vault_id).map_err(verifier_error)?);
            }
        }
    }
    Err(refuse(
        "every nearby attempt key is held by an exercise whose withheld pair was registered",
    ))
}

/// `vault_id`'s chain, walked again past every withheld pair the walk at its
/// head meets: each is registered from its exercise and the chain is walked
/// again, so a trade or a close is drafted at the head those registrations
/// leave (owner ruling, 2026-10-01: "After successful pair registration, the
/// relayer retries progression").
pub(crate) async fn chain_past_withheld_pairs(
    set: &StorageSet,
    verifier: &Verifier<'_, LiveSofiReads<'_>>,
    vault_id: &D32,
    chain: VaultChain,
) -> Result<VaultChain, DsmError> {
    let mut chains = BTreeMap::from([(*vault_id, chain)]);
    for _ in 0..=ATTEMPT_ADVANCE {
        let (.., head) = chains
            .get(vault_id)
            .and_then(VaultChain::head)
            .ok_or_else(|| refuse("no head of this vault is established"))?;
        match walk_for_attempt(set, verifier, &chains, vault_id, &head).await? {
            Walked::Live(..) => {
                return chains
                    .remove(vault_id)
                    .ok_or_else(|| refuse("the vault's chain is not in hand"))
            }
            // The head the chain named was consumed while it was walked:
            // the chain is walked again, from where it stands.
            Walked::Moved(..) | Walked::Registered => {
                chains.insert(*vault_id, verifier.chain(vault_id).map_err(verifier_error)?);
            }
        }
    }
    Err(refuse(
        "every nearby attempt key is held by an exercise whose withheld pair was registered",
    ))
}

/// `V°` of one vault: its state mutation to `post_state`, and this trader's
/// relationship advancement from `base`, by the paths of this device's
/// witness at the vault's head.
pub(crate) fn vault_core(
    standing: &Standing,
    vault: &VaultAtHead,
    post_state: &VaultStateLeaf,
    base: D32,
) -> Result<DlvCore, DsmError> {
    // The paths are this device's witness at the head: the vault's state
    // leaf's, and this device's own relationship leaf's.
    if vault.witness.trader() != (&standing.genesis, &standing.device_id) {
        return Err(refuse("the vault's witness is another trader's"));
    }
    let state_key = derive::vault_state_key(&vault.vault_id);
    let mut entries = vec![
        CoreEntry::Mutation {
            key: state_key,
            pre: derive::vault_state_leaf_value(&vault.state).map_err(refuse)?,
            post: derive::vault_state_leaf_value(post_state).map_err(refuse)?,
            path: vault.witness.state_path().to_vec(),
        },
        CoreEntry::Relationship {
            genesis: standing.genesis,
            device_id: standing.device_id,
            vault_id: vault.vault_id,
            base,
            path: vault.witness.relationship_path().to_vec(),
        },
    ];
    entries.sort_by_key(CoreEntry::key);
    DlvCore::new(
        vault.vault_id,
        vault.root,
        standing.genesis,
        standing.device_id,
        base,
        entries,
    )
    .map_err(refuse)
}

/// A balance leaf's value holding `amount`; a zero balance is the leaf's
/// absence.
fn balance_value(policy_commit: &D32, amount: u64) -> Result<D32, DsmError> {
    if amount == 0 {
        return Ok(ABSENT_LEAF);
    }
    EconomicLeafState::Balance(EconomicBalanceState {
        policy_commit: *policy_commit,
        amount,
    })
    .leaf_value()
    .map_err(refuse)
}

/// `T°`: each named balance movement `(token, credit, debit)` and one
/// relationship advancement per vault, against this device's own tree.
pub(crate) fn trader_core(
    standing: &Standing,
    movements: &[(D32, u64, u64)],
    vaults: &[(D32, D32)],
) -> Result<TraderCore, DsmError> {
    let mut entries = Vec::new();
    for (token, credit, debit) in movements {
        // An absent balance leaf is a zero balance.
        let held = match standing.balances.get(token) {
            Some(held) => *held,
            None => 0,
        };
        let after = held
            .checked_add(*credit)
            .and_then(|value| value.checked_sub(*debit))
            .ok_or_else(|| refuse("the balance does not cover the movement"))?;
        let key = balance_key(&standing.genesis, &standing.device_id, token);
        entries.push(CoreEntry::Mutation {
            key,
            pre: balance_value(token, held)?,
            post: balance_value(token, after)?,
            path: standing.tree.siblings(&key).to_vec(),
        });
    }
    for (vault_id, base) in vaults {
        let key = derive::relationship_key(&standing.genesis, &standing.device_id, vault_id);
        entries.push(CoreEntry::Relationship {
            genesis: standing.genesis,
            device_id: standing.device_id,
            vault_id: *vault_id,
            base: *base,
            path: standing.tree.siblings(&key).to_vec(),
        });
    }
    entries.sort_by_key(CoreEntry::key);
    TraderCore::new(
        standing.genesis,
        standing.device_id,
        next_position(standing.validated.economic_position()).map_err(refuse)?,
        standing.validated.economic_root(),
        entries,
    )
    .map_err(refuse)
}

/// The relationship leaf this device holds with `vault_id`: the base its
/// advancement starts from.
pub(crate) fn relationship_base(standing: &Standing, vault_id: &D32) -> Result<D32, DsmError> {
    standing
        .local
        .relationship(vault_id)
        .map(|leaf| leaf.leaf)
        .ok_or_else(|| refuse("no relationship with this vault: its setup is not admitted"))
}

/// The context a draft takes.
pub(crate) fn context<'a>(
    standing: &Standing,
    set: &StorageSet,
    public_key: &'a [u8],
    trader_core: TraderCore,
) -> Result<TraderContext<'a>, DsmError> {
    Ok(TraderContext {
        genesis: standing.genesis,
        device_id: standing.device_id,
        position: standing.validated.economic_position(),
        parent_claim: own_parent_claim(&standing.admitted)?,
        storage_set_id: set.id(),
        signature_alg: SIGNATURE_ALG,
        claimant_public_key: public_key,
        trader_core,
    })
}

/// A position read after the route's cells are written, as the route reports
/// it. A position that does not resolve within the rounds is
/// `RetriesExhausted`: the network status, recording nothing.
async fn settle(
    core: &CoreSDK,
    set: &StorageSet,
    accepted: &AcceptedGeneses,
) -> Result<PositionOutcome, DsmError> {
    let mut last = None;
    for round in 1..=RESOLVE_ROUNDS {
        match resolve_pending_position(core, set, accepted).await? {
            Advanced::Installed {
                resolution,
                validated,
                ..
            } => {
                return Ok(PositionOutcome {
                    position: validated.economic_position(),
                    state: match resolution {
                        dsm::sofi::resolution::Resolution::Realized => PositionState::Realized,
                        dsm::sofi::resolution::Resolution::Void => PositionState::Void,
                        dsm::sofi::resolution::Resolution::Invalid => PositionState::Invalid,
                    },
                })
            }
            Advanced::Invalid { position } => {
                return Ok(PositionOutcome {
                    position,
                    state: PositionState::Invalid,
                })
            }
            Advanced::NotYet { position, why } => {
                log::info!(
                    "[sofi] position {position} not resolved (round {round}/{RESOLVE_ROUNDS}): \
                     {why:?}"
                );
                last = Some(position);
            }
        }
    }
    let position = last.ok_or_else(|| refuse("the resolution rounds read no position"))?;
    Ok(PositionOutcome {
        position,
        state: PositionState::RetriesExhausted,
    })
}

/// Stages 3 to 10 of §31 for a draft: validate over acquired evidence, sign
/// and publish, fulfill through the Core transition, complete, resolve.
///
/// `ctx` is the context the caller drafted over, built from the same
/// standing: what it read and kept is not read again here.
pub(crate) async fn exercise_draft(
    core: &CoreSDK,
    set: &StorageSet,
    ctx: &VerifierContext<'_>,
    draft: UncheckedDraft,
    accepted: &AcceptedGeneses,
) -> Result<PositionOutcome, DsmError> {
    match exercise_draft_at_head(core, set, ctx, draft, accepted).await? {
        Drafted::Position(outcome) => Ok(outcome),
        Drafted::HeadMoved(why) => Err(refuse(why)),
    }
}

/// What a draft came to: a position, or a vault that moved under it before
/// anything was published.
pub(crate) enum Drafted {
    Position(PositionOutcome),
    HeadMoved(String),
}

/// [`exercise_draft`], with a vault that moved under the draft before
/// anything was published returned as such, for a trade to re-plan.
pub(crate) async fn exercise_draft_at_head(
    core: &CoreSDK,
    set: &StorageSet,
    ctx: &VerifierContext<'_>,
    draft: UncheckedDraft,
    accepted: &AcceptedGeneses,
) -> Result<Drafted, DsmError> {
    // Stage 3.
    let verifier = ctx.verifier();
    let evidence = match verifier
        .acquire_evidence(draft.precommit(), draft.preimage(), &draft.carried())
        .map_err(verifier_error)?
    {
        Acquired::Complete(evidence) => evidence,
        Acquired::Exhausted(missing) => {
            return Err(storage(
                "evidence",
                format!("not in hand after the acquisition rounds: {missing:?}; nothing published"),
            ))
        }
    };
    let checked = check_draft(draft, &evidence).map_err(refuse)?;
    let precommit_signature = sign(&checked.precommit_signing_digest())?;

    // Stage 6: each leg's live attempt, from the walk at its parent.
    let mut chains = BTreeMap::new();
    for leg in checked.precommit().legs() {
        chains.insert(
            leg.vault_id,
            verifier.chain(&leg.vault_id).map_err(verifier_error)?,
        );
    }
    let mut attempts = Vec::new();
    for leg in checked.precommit().legs() {
        match live_attempt(set, &verifier, &mut chains, &leg.vault_id, &leg.parent_root).await? {
            Ok(attempt) => attempts.push((leg.vault_id, attempt)),
            Err(why) => return Ok(Drafted::HeadMoved(why)),
        }
    }
    let att_a = crate::sdk::signing_authority::current_att_a()?;
    let produced = build_fulfillment(&checked, precommit_signature.clone(), &attempts, att_a)
        .map_err(refuse)?;
    let fulfillment_signature = sign(produced.signs.bytes())?;

    // Stages 4 and 5.
    for published in publish_produced(set, &produced, &fulfillment_signature).await? {
        require_stored("route object", &published)?;
    }
    let fulfillment = produced
        .publish
        .iter()
        .find_map(|item| match item {
            ToPublish::Fulfillment(body) => Some(body.clone()),
            ToPublish::Setup(..)
            | ToPublish::Precommit(..)
            | ToPublish::Preimage(..)
            | ToPublish::PolicyFulfillment(..)
            | ToPublish::PreBalance(..) => None,
        })
        .ok_or_else(|| refuse("the fulfillment was not produced"))?;

    // Stage 6: the transition. The closure objects only this trader holds
    // exactly — the parent claim P names — come from its own durable state.
    // The position is durable and fenced from here.
    let own_objects = own_closure_objects(set, checked.precommit(), checked.preimage()).await?;
    fulfill(
        core,
        set,
        &FulfillRequest {
            precommit: checked.precommit(),
            precommit_signature: &precommit_signature,
            preimage: checked.preimage(),
            fulfillment: &fulfillment,
            fulfillment_signature: &fulfillment_signature,
            own_objects: &own_objects,
        },
    )
    .await?;
    let settled = complete_and_settle(core, set, accepted).await;
    settled.map(Drafted::Position)
}

/// Stages 7 to 10 for the pending position: the install and the exercise
/// from what storage holds, then the resolution rounds. A stage the network
/// did not take this pass is the network's status, logged; the rounds still
/// read the position as storage holds it — another party may have carried
/// the pair or the exercise (§33) — and report `RetriesExhausted` if it does
/// not resolve. A refusal is an error, and reported as one.
async fn complete_and_settle(
    core: &CoreSDK,
    set: &StorageSet,
    accepted: &AcceptedGeneses,
) -> Result<PositionOutcome, DsmError> {
    log::info!("[sofi] position: completing its fulfillment");
    if let Completion::NotTaken { position, why } =
        complete_pending_fulfillment(core, set, accepted).await?
    {
        log::info!("[sofi] position {position}: stages 7 and 8 not taken by the network this pass: {why:?}");
    }
    log::info!("[sofi] position: settling");
    settle(core, set, accepted).await
}

/// Amendment S16: the setup with each of `vault_ids` this device has none
/// with, admitted in order before the operation that needs it — one
/// transaction per vault, a position of its own that every later leg through
/// that vault names by `ρ` (§16, §29). A vault this device is already set up
/// with is passed over, so later trades reuse their setup.
pub(crate) async fn set_up_with(
    core: &CoreSDK,
    set: &StorageSet,
    vault_ids: &[D32],
    accepted: &AcceptedGeneses,
) -> Result<(), DsmError> {
    for vault_id in vault_ids {
        match standing(core)?.local.relationship(vault_id) {
            Some(..) => {}
            None => {
                setup(
                    core,
                    set,
                    &SetupIntent {
                        vault_id: *vault_id,
                    },
                    accepted,
                )
                .await?;
            }
        }
    }
    Ok(())
}

/// The route through `intent.vault_ids` at each vault's walked head, and
/// that this device can receive what it gives: checked before a setup is
/// admitted for it, so a route that cannot be built admits nothing.
async fn check_route(
    core: &CoreSDK,
    set: &StorageSet,
    standing: &Standing,
    intent: &TradeIntent,
    accepted: &AcceptedGeneses,
    kept: &KeptReadings,
) -> Result<(), DsmError> {
    let ctx = standing.context_kept(set, accepted, kept)?;
    let verifier = ctx.verifier();
    let mut vaults = Vec::with_capacity(intent.vault_ids.len());
    for at_head in heads_at_once(set, &verifier, &intent.vault_ids).await {
        vaults.push(at_head?.0);
    }
    let refs: Vec<&VaultAtHead> = vaults.iter().collect();
    let (token, amount) = planned_out(&plan(
        &refs,
        intent.token_in_policy_commit,
        intent.amount_in,
    )?)?;
    received(core, intent, &token, amount)
}

/// A route's output is the token the trader asked for, at least its minimum,
/// in a token this device adopted.
fn received(
    core: &CoreSDK,
    intent: &TradeIntent,
    token: &D32,
    amount: u64,
) -> Result<(), DsmError> {
    if *token != intent.token_out_policy_commit {
        return Err(refuse("the route does not give the token asked for"));
    }
    if amount < intent.min_amount_out {
        return Err(refuse(format!(
            "the route gives {amount}, below the minimum {}",
            intent.min_amount_out
        )));
    }
    let head = core
        .device_head()
        .ok_or_else(|| storage("device head", "none"))?;
    if !head.has_adopted(token) {
        return Err(refuse(
            "the output token is not adopted: adopt it before receiving it",
        ));
    }
    Ok(())
}

/// `sofi.trade` and `sofi.route` (§31): a route through `intent.vault_ids`
/// in hop order, priced at each vault's walked head. A vault this device has
/// no setup with is set up with first (Amendment S16).
pub async fn trade(
    core: &CoreSDK,
    set: &StorageSet,
    intent: &TradeIntent,
) -> Result<PositionOutcome, DsmError> {
    // One memo for the whole operation: the check, the setups, the plan at
    // the heads and the settle each read a vault's genesis from it.
    let accepted = &AcceptedGeneses::default();
    // And one store of what its contexts read and keep: the check's, the
    // walk at the heads' and the draft's.
    let kept = &KeptReadings::default();
    {
        let standing = standing(core)?;
        let unset = intent
            .vault_ids
            .iter()
            .any(|vault_id| standing.local.relationship(vault_id).is_none());
        if unset {
            check_route(core, set, &standing, intent, accepted, kept).await?;
        }
    }
    set_up_with(core, set, &intent.vault_ids, accepted).await?;
    // Each stage logs where it ends; the log's own timestamps time it.
    log::info!(
        "[sofi] trade: set up with each of {} vaults",
        intent.vault_ids.len()
    );
    // The vault can move under the draft — another trade consumes the head
    // the plan was priced at — before anything is published: the trade is
    // re-planned at the new head, up to TRADE_REPLANS times.
    let mut moved = String::new();
    for round in 1..=TRADE_REPLANS {
        let standing = standing(core)?;
        let verifying = standing.context_kept(set, accepted, kept)?;
        let verifier = verifying.verifier();
        // Each vault walked past its withheld pairs in turn: two vaults' walks
        // can meet one exercise of a split route and would each register its
        // pair. Each head's leaves and terms are then taken at once.
        let mut chains = Vec::with_capacity(intent.vault_ids.len());
        for (vault_id, chain) in intent
            .vault_ids
            .iter()
            .zip(chains_at_once(set, &verifier, &intent.vault_ids).await)
        {
            chains.push(chain_past_withheld_pairs(set, &verifier, vault_id, chain?).await?);
        }
        let verifier_ref = &verifier;
        let mut heads = Vec::with_capacity(intent.vault_ids.len());
        for at_head in futures::future::join_all(intent.vault_ids.iter().zip(chains).map(
            |(vault_id, chain)| async move { head_of(set, verifier_ref, vault_id, chain).await },
        ))
        .await
        {
            heads.push(at_head?.0);
        }
        log::info!("[sofi] trade: walked {} vault heads", heads.len());
        // A chain, or a split across two vaults of the pair (Amendment S19),
        // planned again at the heads walked now.
        let refs: Vec<&VaultAtHead> = heads.iter().collect();
        let planned = plan(&refs, intent.token_in_policy_commit, intent.amount_in)?;
        let (token, amount) = planned_out(&planned)?;
        received(core, intent, &token, amount)?;
        // Each vault's setup is found by its own index scan: all at once, in
        // hop order.
        let setup_refs = futures::future::try_join_all(heads.iter().map(|vault| {
            own_setup_ref(set, &standing.genesis, &standing.device_id, &vault.vault_id)
        }))
        .await?;
        let mut hops = Vec::new();
        let mut cores = Vec::new();
        let mut vaults = Vec::new();
        for (index, ((vault, p), setup_ref)) in
            heads.iter().zip(&planned).zip(setup_refs).enumerate()
        {
            let base = relationship_base(&standing, &vault.vault_id)?;
            let (hop, post) = price_hop(vault, p.token_in, p.amount_in, setup_ref, index)?;
            cores.push(vault_core(&standing, vault, &post, base)?);
            vaults.push((vault.vault_id, base));
            hops.push(hop);
        }
        let movements = [
            (token, amount, 0),
            (intent.token_in_policy_commit, 0, intent.amount_in),
        ];
        let trader = trader_core(&standing, &movements, &vaults)?;
        let public_key = crate::sdk::signing_authority::current_public_key()?;
        let ctx = context(&standing, set, &public_key, trader)?;
        let draft = draft_route(hops, cores, &ctx, &standing.local).map_err(refuse)?;
        log::info!("[sofi] trade: drafted {} hops", planned.len());
        match exercise_draft_at_head(core, set, &verifying, draft, accepted).await? {
            Drafted::Position(outcome) => return Ok(outcome),
            Drafted::HeadMoved(why) => {
                log::info!("[sofi] trade: re-planning ({round}/{TRADE_REPLANS}): {why}");
                moved = why;
            }
        }
    }
    Err(refuse(format!(
        "the vault moved under the trade {TRADE_REPLANS} times: {moved}"
    )))
}

// ── §32 Closing a vault ────────────────────────────────────────────────────

/// Only the vault's origin owner closes it (§19.7).
fn only_the_owner(standing: &Standing, vault: &VaultAtHead) -> Result<(), DsmError> {
    if vault.state.owner_genesis != standing.genesis
        || vault.state.owner_device_id != standing.device_id
    {
        return Err(refuse("only the vault's origin owner closes it"));
    }
    Ok(())
}

/// `sofi.close` (§32): the owner's full close of its own vault, a one-hop
/// route under its release policy that credits both reserves. The owner's
/// first Close sets up with its vault first (Amendment S16).
pub async fn close(
    core: &CoreSDK,
    set: &StorageSet,
    intent: &CloseIntent,
) -> Result<PositionOutcome, DsmError> {
    let accepted = &AcceptedGeneses::default();
    {
        let standing = standing(core)?;
        if standing.local.relationship(&intent.vault_id).is_none() {
            let ctx = standing.context(set, accepted)?;
            let verifier = ctx.verifier();
            let (vault, ..) = vault_at_head(set, &verifier, &intent.vault_id).await?;
            only_the_owner(&standing, &vault)?;
        }
    }
    set_up_with(core, set, &[intent.vault_id], accepted).await?;
    let standing = standing(core)?;
    let verifying = standing.context(set, accepted)?;
    let verifier = verifying.verifier();
    let chain = chain_past_withheld_pairs(
        set,
        &verifier,
        &intent.vault_id,
        verifier.chain(&intent.vault_id).map_err(verifier_error)?,
    )
    .await?;
    let (vault, ..) = head_of(set, &verifier, &intent.vault_id, chain).await?;
    only_the_owner(&standing, &vault)?;
    let setup_ref = own_setup_ref(
        set,
        &standing.genesis,
        &standing.device_id,
        &intent.vault_id,
    )
    .await?;
    let base = relationship_base(&standing, &intent.vault_id)?;
    let retired =
        retire_vault_post(&vault.state).map_err(|refusal| refuse(format!("{refusal:?}")))?;
    let dlv = vault_core(&standing, &vault, &retired, base)?;
    let policies = vault.market()?;
    let (token_a, token_b) = (*policies.market.token_a(), *policies.market.token_b());
    let head = core
        .device_head()
        .ok_or_else(|| storage("device head", "none"))?;
    if !head.has_adopted(&token_a) || !head.has_adopted(&token_b) {
        return Err(refuse(
            "both reserve tokens must be adopted before they are released",
        ));
    }
    let movements = [
        (token_a, vault.state.reserve_a, 0),
        (token_b, vault.state.reserve_b, 0),
    ];
    let trader = trader_core(&standing, &movements, &[(intent.vault_id, base)])?;
    let public_key = crate::sdk::signing_authority::current_public_key()?;
    let ctx = context(&standing, set, &public_key, trader)?;
    let draft = draft_close(
        intent.vault_id,
        vault.root,
        setup_ref,
        vault.state.reserve_a,
        vault.state.reserve_b,
        dlv,
        &ctx,
        &standing.local,
    )
    .map_err(refuse)?;
    exercise_draft(core, set, &verifying, draft, accepted).await
}

// ── §33 Relaying ───────────────────────────────────────────────────────────

/// `sofi.relay` (§33): the trader's lineage is walked to `p = q − 1`, whose
/// root routes the position pair; `F` is read at `K_ful(q)` and its
/// exercise and copies carried. It needs nothing from the trader.
pub async fn relay(set: &StorageSet, intent: &RelayIntent) -> Result<Relayed, DsmError> {
    let parent_position = intent
        .position
        .checked_sub(1)
        .ok_or_else(|| refuse("position 0 has no fulfillment"))?;
    let network = committed_network_id()?;
    let resolver = LiveRegisterResolver {
        set,
        runtime: tokio::runtime::Handle::current(),
        expected_network_id: network.clone(),
    };
    let ctx = VerifierContext::new(set, None, None)?;
    let parent = resolve_peer(
        &resolver,
        &network,
        &intent.trader_genesis,
        &intent.trader_device_id,
        parent_position,
        &ctx.peer_position_resolver(),
    )
    .map_err(|failure| {
        refuse(format!(
            "the trader's lineage at {parent_position}: {failure:?}"
        ))
    })?;
    let parent_root = parent.validated_root().economic_root();
    let registration = ctx
        .verifier()
        .read_registration(
            &intent.trader_genesis,
            &intent.trader_device_id,
            intent.position,
            &parent_root,
        )
        .map_err(verifier_error)?
        .map_err(|missing| storage("position pair", format!("not decided yet: {missing:?}")))?;
    let fulfillment = match registration.into_registration() {
        Registration::Registered(signed) => signed,
        Registration::NeverRegistered { .. } => {
            return Err(refuse("the position holds no fulfillment"))
        }
        Registration::Held(..) | Registration::RootTaken { .. } | Registration::Unresolved => {
            return Err(refuse("no fulfillment is registered at the position yet"))
        }
    };
    let relayed = relay_fulfillment(set, &derive::fulfillment_id(&fulfillment.body)).await?;
    let mut cells_written = 0u32;
    for report in &relayed.pair {
        if report.reached_leader() {
            cells_written += 1;
        }
    }
    for leg in &relayed.legs {
        if leg.reached_leader {
            cells_written += 1;
        }
    }
    Ok(Relayed { cells_written })
}

// ── Resolving the device's own position ────────────────────────────────────

/// `sofi.resolve`: finish this device's pending fulfillment from what storage
/// holds — install and exercise, idempotently — and resolve it.
pub async fn resolve(core: &CoreSDK, set: &StorageSet) -> Result<PositionOutcome, DsmError> {
    complete_and_settle(core, set, &AcceptedGeneses::default()).await
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)]
mod tests {
    use super::*;
    use crate::sdk::storage_node_sdk::SetClient;
    use dsm::common::domain_tags::TAG_DSM_SOFI_REL_INDEX;
    use dsm::crypto::domain::TaggedHashDomain;

    /// A route search walks only the vaults that can be in a route: the one
    /// pairing ERA and WILD, and the two legs of the chain WILD→TKN→ERA.
    fn lane(i: u8) -> [u8; 32] {
        [0x30 + i; 32]
    }

    fn trader(i: u16) -> ([u8; 32], [u8; 32]) {
        let mut g = [0x51; 32];
        g[..2].copy_from_slice(&i.to_be_bytes());
        (g, [0x52; 32])
    }

    /// Five equal vaults of a pair, each alone or split in two: a small
    /// trade's split is within the tolerance of a single vault, so each
    /// trader takes one vault alone — the same one every time — and traders
    /// spread over all five instead of piling into the first.
    #[test]
    fn near_equal_routes_spread_traders_over_a_pairs_vaults() {
        let mut routes: Vec<(u64, Vec<[u8; 32]>)> =
            (0..5).map(|i| (1_000, vec![lane(i)])).collect();
        for i in 0..5 {
            for j in i + 1..5 {
                routes.push((1_020, vec![lane(i), lane(j)]));
            }
        }
        let mut chosen = std::collections::BTreeSet::new();
        for t in 0..60 {
            let (g, d) = trader(t);
            let pick = choose_route(&routes, (&g, &d)).expect("a route");
            assert_eq!(
                routes[pick].1.len(),
                1,
                "a single vault within the tolerance"
            );
            assert_eq!(
                choose_route(&routes, (&g, &d)),
                Some(pick),
                "one trader, one route"
            );
            chosen.insert(routes[pick].1[0]);
        }
        assert_eq!(chosen.len(), 5, "the traders spread over every vault");
    }

    /// Both sides of the tolerance band, to the base unit: a single vault
    /// exactly `ROUTE_TOLERANCE_BPS` below a split is inside the band
    /// (inclusive) and wins on fewer legs; one base unit lower is outside it,
    /// and the economically better split wins.
    #[test]
    fn the_tolerance_band_is_inclusive_to_the_base_unit() {
        let (g, d) = trader(3);
        let best = 10_000u64;
        let at_band = best * (10_000 - ROUTE_TOLERANCE_BPS) / 10_000;
        let inside = vec![(at_band, vec![lane(0)]), (best, vec![lane(0), lane(1)])];
        assert_eq!(
            choose_route(&inside, (&g, &d)),
            Some(0),
            "inside: fewer legs win"
        );
        let outside = vec![(at_band - 1, vec![lane(0)]), (best, vec![lane(0), lane(1)])];
        assert_eq!(
            choose_route(&outside, (&g, &d)),
            Some(1),
            "outside: the split wins"
        );
    }

    /// A split that beats every single vault by more than the tolerance is
    /// taken; a single vault far below the best is never; no routes, none.
    #[test]
    fn a_materially_better_route_wins_and_a_poor_one_never_does() {
        let (g, d) = trader(7);
        let big = vec![
            (1_000, vec![lane(0)]),
            (1_000, vec![lane(1)]),
            (1_100, vec![lane(0), lane(1)]),
        ];
        assert_eq!(choose_route(&big, (&g, &d)), Some(2));
        let poor = vec![(900, vec![lane(0)]), (1_000, vec![lane(1)])];
        assert_eq!(choose_route(&poor, (&g, &d)), Some(1));
        assert_eq!(choose_route(&[], (&g, &d)), None);
    }

    /// An ERA vault of an unrelated pair, and a chain whose second leg is
    /// missing, take no part in any route and are never walked.
    #[test]
    fn a_route_search_walks_only_the_vaults_a_route_can_use() {
        let (wild, era, tkn, other, lone) = ([1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32], [5u8; 32]);
        let vault = |id: u8, a: D32, b: D32| Paired {
            vault_id: [id; 32],
            tokens: (a, b),
        };
        let firsts = [
            vault(10, wild, era),
            vault(11, tkn, wild),
            vault(12, wild, lone),
        ];
        let seconds = [
            vault(10, wild, era),
            vault(20, era, tkn),
            vault(21, other, era),
        ];
        assert_eq!(
            route_legs(&firsts, &seconds, &wild, &era),
            vec![[10; 32], [11; 32], [20; 32]],
            "the direct vault and the WILD→TKN→ERA legs; not ERA/OTHER, not WILD/LONE"
        );
        assert!(route_legs(&[vault(12, wild, lone)], &seconds, &wild, &era).is_empty());
    }

    /// MR-STOR-0021 (storage §4): a setup candidate whose bytes no member
    /// holds may be this device's setup, so a relationship-index scan that
    /// met one is a network failure; only a scan whose every candidate was
    /// established says no admitted setup is published. On the storage node's
    /// own code, on Postgres.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[serial_test::serial]
    async fn a_setup_scan_that_met_an_unestablished_candidate_is_not_a_refusal() {
        let _fleet = crate::test_support::one_device::Fleet::start();
        let set = crate::sdk::storage_set::canonical_set(crate::economic_fixtures::NETWORK)
            .expect("the pinned set");
        let client = SetClient::new(&set).expect("a client of the set");
        let index = TAG_DSM_SOFI_REL_INDEX.source_bytes();
        let (genesis, device_id) = ([0x61; 32], [0x62; 32]);

        // Held bytes that are not a setup: every candidate established.
        let held_vault = [0x63; 32];
        let domain = TaggedHashDomain::try_new(b"DSM/test/not-a-setup").expect("domain");
        let garbage = b"these bytes decode as no setup";
        assert_eq!(client.put_immutable(domain, garbage).await, 5);
        let held = dsm::storage_object::immutable_addr(domain, garbage);
        let locator = derive::relationship_index_key(&genesis, &device_id, &held_vault);
        assert_eq!(client.append_index(index, &locator, &held).await, 5);
        assert!(matches!(
            own_setup_ref(&set, &genesis, &device_id, &held_vault).await,
            Err(DsmError::InvalidOperation(_))
        ));

        // An address whose bytes no member holds: not established.
        let unknown_vault = [0x64; 32];
        let locator = derive::relationship_index_key(&genesis, &device_id, &unknown_vault);
        assert_eq!(client.append_index(index, &locator, &[0x98; 32]).await, 5);
        assert!(matches!(
            own_setup_ref(&set, &genesis, &device_id, &unknown_vault).await,
            Err(DsmError::Storage { .. })
        ));
    }
}
