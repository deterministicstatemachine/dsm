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

use std::collections::BTreeMap;

use dsm::ccb::state::{FeePolicy, MarketPolicy, ReleasePolicy};
use dsm::dlv::route_commit::constant_product_output_classified;
use dsm::economic::keys::balance_key;
use dsm::economic::lineage::{AdmittedEconomicPosition, ValidatedEconomicRoot};
use dsm::economic::state::{EconomicBalanceState, EconomicLeafState};
use dsm::economic::tree::{EconomicSmt, ABSENT_LEAF};
use dsm::economic::write_set::CreditSourceFacts;
use dsm::sofi::derive;
use dsm::sofi::publication::{Publication, VaultPolicyClass};
use dsm::sofi::registration::Registration;
use dsm::sofi::resolution::{ParentPosition, VaultChain, WalkOutcome};
use dsm::sofi::storage::Resolved;
use dsm::sofi::validation::{close_vault_post, swap_vault_post, Evidence, EvidenceNeeds, Policies};
use dsm::sofi::wire::{
    next_attempt, next_position, CoreEntry, DlvCore, SwapHop, TraderCore, VaultGenesisPreimage,
    VaultStateLeaf, VAULT_STATUS_ACTIVE,
};
use dsm::types::device_state::{BalanceDelta, BalanceDirection};
use dsm::types::error::DsmError;

use crate::sdk::core_sdk::CoreSDK;
use crate::sdk::economic_admission_flow::{
    admitted_self_loop_operation, committed_network_id, producer_tree_and_pre_state,
    validated_root_or_activate,
};
use crate::sdk::economic_registers::{resolve_peer_with_cache, LiveRegisterResolver};
use crate::sdk::sofi_advance::{
    complete_pending_fulfillment, fulfill, own_parent_claim, resolve_pending_position, Advanced,
    FulfillRequest,
};
use crate::sdk::sofi_chain::ChainWalker;
use crate::sdk::sofi_evidence::{
    acquire_evidence, fetch_vault_genesis, Acquired, LocalLeaves, VaultGenesis,
};
use crate::sdk::sofi_exercise::read_attempt_cell;
use crate::sdk::sofi_publish::{fetch_setup_for, publish, publish_produced, Published};
use crate::sdk::sofi_register::read_registration;
use crate::sdk::sofi_relay::relay_fulfillment;
use crate::sdk::sofi_resolve::{Resolver, WALK_BUDGET};
use crate::sdk::sofi_sdk::{
    build_fulfillment, build_setup, build_vault_create, check_draft, draft_close, draft_route,
    ToPublish, TraderContext, UncheckedDraft,
};
use crate::sdk::storage_set::StorageSet;
use crate::storage::client_db::{economic_lineage, sofi_vault_head};

type D32 = [u8; 32];

/// The signature algorithm of every SoFi object this device signs: its AK.
const SIGNATURE_ALG: u16 = dsm::ccb::genesis::sigalg::SPHINCS_PLUS_SPX256F;

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

/// `sofi.setup` (§29).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetupIntent {
    pub vault_id: D32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetUp {
    /// ρ.
    pub setup_ref: D32,
    pub position: u64,
}

/// `sofi.findRoute` (§30): path search over walked heads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindRouteIntent {
    pub token_in_policy_commit: D32,
    pub token_out_policy_commit: D32,
    pub amount_in: u64,
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

fn refuse(what: impl std::fmt::Display) -> DsmError {
    DsmError::invalid_operation(format!("sofi: {what}"))
}

fn storage(what: &str, e: impl std::fmt::Display) -> DsmError {
    DsmError::storage(format!("sofi: {what}: {e}"), None::<std::io::Error>)
}

/// Sign `message` with this device's AK.
fn sign(message: &[u8]) -> Result<Vec<u8>, DsmError> {
    let secret_key = crate::sdk::signing_authority::current_secret_key()?;
    dsm::crypto::sphincs::sphincs_sign(&secret_key, message)
}

/// The published object must be `Stored`, read back from the members, before
/// anything is built on it.
fn require_stored(what: &str, published: &Published) -> Result<(), DsmError> {
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
fn identity(core: &CoreSDK) -> Result<(D32, D32), DsmError> {
    let head = core
        .device_head()
        .ok_or_else(|| storage("device head", "none"))?;
    Ok((head.genesis_digest(), head.devid()))
}

// ── §28 Creating a vault ───────────────────────────────────────────────────

/// §28: the owner's creation. The three policy objects and the genesis
/// preimage are published and read back `Stored` first: a genesis nobody's
/// creation carried is refused by `genesis_accepted`, so publishing first
/// asserts nothing, and it means the vault is findable the moment it exists.
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

    let market = MarketPolicy::beta_constant_product(
        intent.token_a_policy_commit,
        intent.token_b_policy_commit,
    )
    .map_err(refuse)?
    .encode();
    let fee = FeePolicy::new(intent.fee_bps).map_err(refuse)?.encode();
    let release = ReleasePolicy::beta_owner_local_full_close().encode();
    let policies = [
        (VaultPolicyClass::Market, &market),
        (VaultPolicyClass::Fee, &fee),
        (VaultPolicyClass::Release, &release),
    ];
    let mut addresses = BTreeMap::new();
    for (class, bytes) in policies {
        let publication = Publication::VaultPolicy { class, bytes };
        let published = publish(set, &publication).await?;
        require_stored("vault policy", &published)?;
        addresses.insert(class.class(), published.addr);
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
    let published = publish(set, &Publication::VaultGenesis(&preimage)).await?;
    require_stored("vault genesis", &published)?;

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
    let (.., admitted) = admitted_self_loop_operation(
        core,
        operation,
        &deltas,
        CreditSourceFacts::None,
        Vec::new(),
        None,
    )
    .await?;
    if admitted.economic_position != create_position {
        return Err(refuse(format!(
            "the creation was admitted at position {}, not the position {create_position} its \
             genesis names",
            admitted.economic_position
        )));
    }
    Ok(VaultCreated {
        vault_id: preimage.vault_id(),
        position: create_position,
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
/// which inserts `h⁰`.
pub async fn setup(
    core: &CoreSDK,
    set: &StorageSet,
    intent: &SetupIntent,
) -> Result<SetUp, DsmError> {
    let (genesis, device_id) = identity(core)?;
    match fetch_vault_genesis(set, &intent.vault_id).await? {
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
    let admitted = economic_lineage::get_admitted()
        .map_err(|e| storage("load admitted", e))?
        .ok_or_else(|| {
            refuse("no admitted position: a setup names the claim registered at its position")
        })?;
    let validated = validated_root_or_activate(core)?;
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
    let (.., admitted) = admitted_self_loop_operation(
        core,
        operation,
        &[],
        CreditSourceFacts::None,
        Vec::new(),
        None,
    )
    .await?;
    Ok(SetUp {
        setup_ref,
        position: admitted.economic_position,
    })
}

// ── §30 Finding the head of a vault ────────────────────────────────────────

/// A vault at its walked head: the root the next hop is built on, the whole
/// tree there, its state, and its policies.
struct VaultAtHead {
    vault_id: D32,
    root: D32,
    state: VaultStateLeaf,
    tree: EconomicSmt,
    policies: Policies,
}

/// What this device stands on: its identity, its validated predecessor and
/// the leaves that form it, and the conditional positions it resolved.
struct Standing {
    genesis: D32,
    device_id: D32,
    validated: ValidatedEconomicRoot,
    admitted: AdmittedEconomicPosition,
    local: LocalLeaves,
    tree: EconomicSmt,
    balances: BTreeMap<D32, u64>,
    parents: BTreeMap<D32, ParentPosition>,
}

/// Stage 0 of §31: no pending position, and a resolved predecessor.
fn standing(core: &CoreSDK) -> Result<Standing, DsmError> {
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
    let local = LocalLeaves::of_validated(&genesis, &device_id, &validated)?;
    let mut parents = BTreeMap::new();
    if let AdmittedEconomicPosition::ResolvedSofi {
        fulfillment_id,
        selected_root,
        ..
    } = admitted
    {
        parents.insert(
            fulfillment_id,
            ParentPosition::ConditionalSelected { selected_root },
        );
    }
    Ok(Standing {
        genesis,
        device_id,
        validated,
        admitted,
        local,
        tree,
        balances: pre_state.balances,
        parents,
    })
}

/// The policies `state` commits, fetched by the addresses it names and
/// decoded by Core, which re-addresses each first.
async fn vault_policies(set: &StorageSet, state: &VaultStateLeaf) -> Result<Policies, DsmError> {
    let mut objects = BTreeMap::new();
    for (class, addr) in EvidenceNeeds::policies_of(state) {
        let bytes = crate::sdk::storage_io::read_stored_bytes(set, &addr)
            .await?
            .ok_or_else(|| {
                storage(
                    "vault policy",
                    format!("the class {class:#06x} policy the vault commits is not Stored"),
                )
            })?;
        objects.insert(addr, bytes);
    }
    let evidence = Evidence::acquired(
        objects,
        BTreeMap::new(),
        BTreeMap::new(),
        BTreeMap::new(),
        BTreeMap::new(),
        BTreeMap::new(),
    );
    Policies::resolve(&evidence, state).map_err(|refusal| refuse(format!("{refusal:?}")))
}

/// §30: walk `vault_id` from its accepted genesis to its head. At generation
/// zero the tree is the genesis state leaf alone; past it, the head store the
/// walk wrote must reproduce the head's root.
async fn vault_at_head(
    set: &StorageSet,
    walker: &ChainWalker<'_>,
    vault_id: &D32,
) -> Result<(VaultAtHead, VaultChain), DsmError> {
    let chain = walker.chain(vault_id).await?;
    let (generation, root) = chain
        .head()
        .ok_or_else(|| refuse("no head of this vault is established"))?;
    let (state, tree) = if generation == 0 {
        let accepted = match fetch_vault_genesis(set, vault_id).await? {
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
        let state = accepted.state().clone();
        let mut tree = EconomicSmt::new();
        tree.insert(
            derive::vault_state_key(vault_id),
            derive::vault_state_leaf_value(&state).map_err(refuse)?,
        );
        (state, tree)
    } else {
        let (head, tree, state) = sofi_vault_head::tree_at_head(vault_id)
            .map_err(|e| storage("vault head", e))?
            .ok_or_else(|| refuse("this device's record of the vault cannot reproduce its head"))?;
        if head.generation != generation {
            return Err(refuse(format!(
                "the recorded head is generation {}, the walk reached {generation}",
                head.generation
            )));
        }
        (state, tree)
    };
    if tree.root() != root {
        return Err(refuse(
            "the vault's leaves do not recompute its walked head",
        ));
    }
    let policies = vault_policies(set, &state).await?;
    Ok((
        VaultAtHead {
            vault_id: *vault_id,
            root,
            state,
            tree,
            policies,
        },
        chain,
    ))
}

impl Standing {
    fn walker<'a>(&'a self, set: &'a StorageSet) -> ChainWalker<'a> {
        ChainWalker {
            set,
            local: &self.local,
            parents: &self.parents,
        }
    }
}

/// The other token of a vault's pair, and whether `token_in` is its `a`.
fn other_token(policies: &Policies, token_in: &D32) -> Option<(D32, bool)> {
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
    let (token_out, in_is_a) = other_token(&vault.policies, token_in)
        .ok_or_else(|| refuse(format!("hop {index}: the vault does not trade that token")))?;
    let (reserve_in, reserve_out) = if in_is_a {
        (vault.state.reserve_a, vault.state.reserve_b)
    } else {
        (vault.state.reserve_b, vault.state.reserve_a)
    };
    let amount_out = constant_product_output_classified(
        amount_in,
        reserve_in,
        reserve_out,
        vault.policies.fee.fee_bps(),
    )
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
    let post = swap_vault_post(&vault.state, &vault.policies, &hop, index)
        .map_err(|refusal| refuse(format!("hop {index}: {refusal:?}")))?;
    Ok((hop, post))
}

/// §30 and the path search of `sofi.findRoute`: the best route of one or two
/// hops (the beta `ROUTE_MAX_LEGS`) from `token_in` to `token_out` through
/// vaults this device is set up with — every leg names this device's setup
/// with its vault — each hop quoted at its vault's walked head. A vault whose
/// head cannot be established here is left out; no route is an empty list.
pub async fn find_route(
    core: &CoreSDK,
    set: &StorageSet,
    intent: &FindRouteIntent,
) -> Result<Vec<Hop>, DsmError> {
    let standing = standing(core)?;
    let walker = standing.walker(set);
    let mut heads = Vec::new();
    for leaf in standing.local.relationships() {
        match vault_at_head(set, &walker, &leaf.vault_id).await {
            Ok((head, ..)) if head.state.status == VAULT_STATUS_ACTIVE => heads.push(head),
            Ok(..) => {}
            Err(e) => log::info!(
                "[sofi findRoute] vault {} left out: {e}",
                crate::util::text_id::encode_base32_crockford(&leaf.vault_id)
            ),
        }
    }
    let hop = |vault: &VaultAtHead, token_in: D32, amount_in: u64, index: usize| {
        quote(vault, &token_in, amount_in, index).map(|(token_out, amount_out)| Hop {
            vault_id: vault.vault_id,
            parent_root: vault.root,
            token_in_policy_commit: token_in,
            token_out_policy_commit: token_out,
            amount_in,
            amount_out,
        })
    };
    let mut routes: Vec<Vec<Hop>> = Vec::new();
    for (index, first) in heads.iter().enumerate() {
        // A vault that does not trade the token, or cannot price it, is not a
        // first hop.
        let Ok(one) = hop(first, intent.token_in_policy_commit, intent.amount_in, 0) else {
            continue;
        };
        if one.token_out_policy_commit == intent.token_out_policy_commit {
            routes.push(vec![one]);
            continue;
        }
        for (other, second) in heads.iter().enumerate() {
            if other == index {
                continue;
            }
            if let Ok(two) = hop(second, one.token_out_policy_commit, one.amount_out, 1) {
                if two.token_out_policy_commit == intent.token_out_policy_commit {
                    routes.push(vec![one.clone(), two]);
                }
            }
        }
    }
    // The route that gives the most; no route leaves the list empty.
    let mut best: Vec<Hop> = Vec::new();
    for route in routes {
        if route.last().map(|hop| hop.amount_out) > best.last().map(|hop| hop.amount_out) {
            best = route;
        }
    }
    Ok(best)
}

// ── §31 A trade and a multihop route ───────────────────────────────────────

/// The setup this device admitted with `vault_id`, by its reference: of the
/// setups published under the relationship index, the one whose `R_T^setup`
/// is the root this device admitted right after the setup's position.
async fn own_setup_ref(
    set: &StorageSet,
    standing: &Standing,
    vault_id: &D32,
) -> Result<D32, DsmError> {
    let setups =
        match fetch_setup_for(set, &standing.genesis, &standing.device_id, vault_id).await? {
            Resolved::Kept(setups) => setups,
            Resolved::None => {
                return Err(refuse(
                    "no setup of this device with the vault is published",
                ))
            }
            Resolved::Unavailable => {
                return Err(storage(
                    "setup",
                    "the relationship index scan did not complete",
                ))
            }
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
    Err(refuse(
        "no published setup with this vault is one this device admitted",
    ))
}

/// The live attempt of a leg at `parent_root`: the walk's first unresolved
/// key, advanced past keys an exercise still in flight holds (§31 stage 6).
async fn live_attempt(
    set: &StorageSet,
    resolver: &Resolver<'_>,
    vault_id: &D32,
    parent_root: &D32,
) -> Result<u64, DsmError> {
    let mut cursor = 0;
    let first = loop {
        let walked = resolver
            .walk_parent(vault_id, parent_root, cursor, WALK_BUDGET)
            .await?;
        match walked.outcome {
            WalkOutcome::Unresolved { attempt } => break attempt,
            WalkOutcome::Continue { cursor: next } => cursor = next,
            WalkOutcome::Consumed { attempt } => {
                return Err(refuse(format!(
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
    let mut advanced = 0;
    while advanced <= ATTEMPT_ADVANCE {
        match read_attempt_cell(set, vault_id, parent_root, attempt).await? {
            Ok(read) if read.exercise.is_none() => return Ok(attempt),
            Ok(..) => {
                attempt = next_attempt(attempt).map_err(refuse)?;
                advanced += 1;
            }
            Err(missing) => {
                return Err(storage(
                    "attempt cell",
                    format!("the reads do not decide attempt {attempt}: {missing:?}"),
                ))
            }
        }
    }
    Err(refuse(
        "every nearby attempt key is held by an exercise in flight",
    ))
}

/// `V°` of one vault: its state mutation to `post_state`, and this trader's
/// relationship advancement from `base`, against the vault's tree at its head.
fn vault_core(
    standing: &Standing,
    vault: &VaultAtHead,
    post_state: &VaultStateLeaf,
    base: D32,
) -> Result<DlvCore, DsmError> {
    let state_key = derive::vault_state_key(&vault.vault_id);
    let rel_key = derive::relationship_key(&standing.genesis, &standing.device_id, &vault.vault_id);
    let mut entries = vec![
        CoreEntry::Mutation {
            key: state_key,
            pre: derive::vault_state_leaf_value(&vault.state).map_err(refuse)?,
            post: derive::vault_state_leaf_value(post_state).map_err(refuse)?,
            path: vault.tree.siblings(&state_key).to_vec(),
        },
        CoreEntry::Relationship {
            genesis: standing.genesis,
            device_id: standing.device_id,
            vault_id: vault.vault_id,
            base,
            path: vault.tree.siblings(&rel_key).to_vec(),
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
fn trader_core(
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
fn relationship_base(standing: &Standing, vault_id: &D32) -> Result<D32, DsmError> {
    standing
        .local
        .relationship(vault_id)
        .map(|leaf| leaf.leaf)
        .ok_or_else(|| refuse("no relationship with this vault: set up with it first"))
}

/// The context a draft takes.
fn context<'a>(
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
async fn settle(core: &CoreSDK, set: &StorageSet) -> Result<PositionOutcome, DsmError> {
    let mut last = None;
    for round in 1..=RESOLVE_ROUNDS {
        match resolve_pending_position(core, set).await? {
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
async fn exercise_draft(
    core: &CoreSDK,
    set: &StorageSet,
    standing: &Standing,
    draft: UncheckedDraft,
) -> Result<PositionOutcome, DsmError> {
    // Stage 3.
    let evidence = match acquire_evidence(set, draft.precommit(), draft.preimage(), &standing.local)
        .await?
    {
        Acquired::Complete(evidence) => evidence,
        Acquired::Exhausted(missing) | Acquired::NoSource(missing) => {
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
    let walker = standing.walker(set);
    for leg in checked.precommit().legs() {
        chains.insert(leg.vault_id, walker.chain(&leg.vault_id).await?);
    }
    let resolver = Resolver {
        set,
        local: &standing.local,
        parents: &standing.parents,
        chains: &chains,
    };
    let mut attempts = Vec::new();
    for leg in checked.precommit().legs() {
        attempts.push((
            leg.vault_id,
            live_attempt(set, &resolver, &leg.vault_id, &leg.parent_root).await?,
        ));
    }
    let produced =
        build_fulfillment(&checked, precommit_signature.clone(), &attempts).map_err(refuse)?;
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
            | ToPublish::PolicyFulfillment(..) => None,
        })
        .ok_or_else(|| refuse("the fulfillment was not produced"))?;

    // Stages 6 and 7: the transition, then the install.
    let own_objects = BTreeMap::new();
    let fulfilled = fulfill(
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
    // Stage 8, then stages 9 and 10. The position is durable and fenced from
    // here: a completion the network does not take is retried by
    // `sofi.resolve`, and reported as the network status meanwhile.
    if let Err(e) = complete_pending_fulfillment(core, set).await {
        log::warn!(
            "[sofi] position {} completion not written this pass: {e}",
            fulfilled.position
        );
        return Ok(PositionOutcome {
            position: fulfilled.position,
            state: PositionState::RetriesExhausted,
        });
    }
    settle(core, set).await
}

/// `sofi.trade` and `sofi.route` (§31): a route through `intent.vault_ids`
/// in hop order, priced at each vault's walked head.
pub async fn trade(
    core: &CoreSDK,
    set: &StorageSet,
    intent: &TradeIntent,
) -> Result<PositionOutcome, DsmError> {
    let standing = standing(core)?;
    let walker = standing.walker(set);
    let mut token = intent.token_in_policy_commit;
    let mut amount = intent.amount_in;
    let mut hops = Vec::new();
    let mut cores = Vec::new();
    let mut vaults = Vec::new();
    for (index, vault_id) in intent.vault_ids.iter().enumerate() {
        let (vault, ..) = vault_at_head(set, &walker, vault_id).await?;
        let setup_ref = own_setup_ref(set, &standing, vault_id).await?;
        let base = relationship_base(&standing, vault_id)?;
        let (hop, post) = price_hop(&vault, token, amount, setup_ref, index)?;
        cores.push(vault_core(&standing, &vault, &post, base)?);
        vaults.push((*vault_id, base));
        token = hop.token_out;
        amount = hop.amount_out;
        hops.push(hop);
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
    if !head.has_adopted(&token) {
        return Err(refuse(
            "the output token is not adopted: adopt it before receiving it",
        ));
    }
    let movements = [
        (token, amount, 0),
        (intent.token_in_policy_commit, 0, intent.amount_in),
    ];
    let trader = trader_core(&standing, &movements, &vaults)?;
    let public_key = crate::sdk::signing_authority::current_public_key()?;
    let ctx = context(&standing, set, &public_key, trader)?;
    let draft = draft_route(hops, cores, &ctx, &standing.local).map_err(refuse)?;
    exercise_draft(core, set, &standing, draft).await
}

// ── §32 Closing a vault ────────────────────────────────────────────────────

/// `sofi.close` (§32): the owner's full close of its own vault, a one-hop
/// route under its release policy that credits both reserves.
pub async fn close(
    core: &CoreSDK,
    set: &StorageSet,
    intent: &CloseIntent,
) -> Result<PositionOutcome, DsmError> {
    let standing = standing(core)?;
    let walker = standing.walker(set);
    let (vault, ..) = vault_at_head(set, &walker, &intent.vault_id).await?;
    if vault.state.owner_genesis != standing.genesis
        || vault.state.owner_device_id != standing.device_id
    {
        return Err(refuse("only the vault's origin owner closes it"));
    }
    let setup_ref = own_setup_ref(set, &standing, &intent.vault_id).await?;
    let base = relationship_base(&standing, &intent.vault_id)?;
    let retired =
        close_vault_post(&vault.state).map_err(|refusal| refuse(format!("{refusal:?}")))?;
    let dlv = vault_core(&standing, &vault, &retired, base)?;
    let (token_a, token_b) = (
        *vault.policies.market.token_a(),
        *vault.policies.market.token_b(),
    );
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
    exercise_draft(core, set, &standing, draft).await
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
    let parent = resolve_peer_with_cache(
        &resolver,
        &network,
        &intent.trader_genesis,
        &intent.trader_device_id,
        parent_position,
    )
    .map_err(|failure| {
        refuse(format!(
            "the trader's lineage at {parent_position}: {failure:?}"
        ))
    })?;
    let parent_root = parent.validated_root().economic_root();
    let registration = read_registration(
        set,
        &intent.trader_genesis,
        &intent.trader_device_id,
        intent.position,
        &parent_root,
    )
    .await?
    .map_err(|missing| storage("position pair", format!("not decided yet: {missing:?}")))?;
    let fulfillment = match registration {
        Registration::Registered(signed) => signed,
        Registration::NeverRegistered { .. } => {
            return Err(refuse("the position holds no fulfillment"))
        }
        Registration::Unresolved => {
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
    complete_pending_fulfillment(core, set).await?;
    settle(core, set).await
}
