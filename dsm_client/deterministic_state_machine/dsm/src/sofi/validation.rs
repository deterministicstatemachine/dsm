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

use std::collections::BTreeMap;

use crate::ccb::state::{FeePolicy, MarketPolicy, ReleasePolicy};
use crate::dlv::route_commit::constant_product_output_classified;
use crate::economic::keys::balance_key;
use crate::economic::state::{EconomicBalanceState, EconomicLeafState};

use super::conformance::Validation;
use super::derive;
use super::smt::{batch_fold, FoldEntry};
use super::wire::{
    CoreEntry, DlvCore, OwnerAuthority, SettlementBody, SettlementPreimage, SwapHop, TraderCore,
    TraderPrecommitBody, TraderRelationshipLeaf, VaultRelationshipLeaf, VaultStateLeaf,
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
}

/// An object a check needed and did not get. Never a statement about the
/// operation — only about what the verifier holds.
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
}

/// The outcome of a static validation, with its reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    Invalid(Invalid),
    Unavailable(Missing),
}

impl Refusal {
    pub fn validation(&self) -> Validation {
        match self {
            Self::Invalid(_) => Validation::Invalid,
            Self::Unavailable(_) => Validation::Unavailable,
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

/// Everything the verifier fetched. Anything absent from here is Unavailable,
/// never Invalid.
#[derive(Debug, Default)]
pub struct Evidence {
    /// Canonical bytes by content address — the policy objects a vault names.
    pub objects: BTreeMap<D32, Vec<u8>>,
    /// Pre-states of the trader's own leaves, by `R_econ` key.
    pub trader_leaves: BTreeMap<D32, TraderLeafPre>,
    /// Pre-states of vault leaves, by `(vault_id, key)`.
    pub vault_leaves: BTreeMap<(D32, D32), VaultLeafPre>,
}

impl Evidence {
    fn policy_bytes(&self, addr: &D32) -> Result<&[u8], Refusal> {
        self.objects
            .get(addr)
            .map(Vec::as_slice)
            .ok_or(Refusal::Unavailable(Missing::Policy { addr: *addr }))
    }

    fn trader_leaf(&self, key: &D32) -> Result<&TraderLeafPre, Refusal> {
        self.trader_leaves
            .get(key)
            .ok_or(Refusal::Unavailable(Missing::TraderLeaf { key: *key }))
    }

    fn vault_leaf(&self, vault_id: &D32, key: &D32) -> Result<&VaultLeafPre, Refusal> {
        self.vault_leaves
            .get(&(*vault_id, *key))
            .ok_or(Refusal::Unavailable(Missing::VaultLeaf {
                vault_id: *vault_id,
                key: *key,
            }))
    }

    /// The vault's own state before the operation, and the policies it names.
    fn vault_state(&self, vault_id: &D32) -> Result<(VaultStateLeaf, Policies), Refusal> {
        let key = derive::vault_state_key(vault_id);
        let state = match self.vault_leaf(vault_id, &key)? {
            VaultLeafPre::State(s) => s.clone(),
            _ => {
                return Err(Refusal::Unavailable(Missing::VaultState {
                    vault_id: *vault_id,
                }))
            }
        };
        let policies = Policies::resolve(self, &state)?;
        Ok((state, policies))
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
    fn resolve(evidence: &Evidence, state: &VaultStateLeaf) -> Result<Self, Refusal> {
        let market =
            crate::ccb::decode::decode_market_policy(evidence.policy_bytes(&state.market_policy)?)
                .map_err(|_| {
                    Refusal::Invalid(Invalid::PolicyDoesNotDecode {
                        class: crate::ccb::class::MARKET_POLICY,
                    })
                })?;
        let fee = crate::ccb::decode::decode_fee_policy(evidence.policy_bytes(&state.fee_policy)?)
            .map_err(|_| {
                Refusal::Invalid(Invalid::PolicyDoesNotDecode {
                    class: crate::ccb::class::FEE_POLICY,
                })
            })?;
        let release = crate::ccb::decode::decode_release_policy(
            evidence.policy_bytes(&state.release_policy)?,
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

/// `RouteValidation(P, G, E)`, as the ladder reads it.
pub fn route_validation(
    precommit: &TraderPrecommitBody,
    preimage: &SettlementPreimage,
    evidence: &Evidence,
) -> Validation {
    match validate(precommit, preimage, evidence) {
        Ok(()) => Validation::Valid,
        Err(r) => r.validation(),
    }
}

/// The same check, with the reason. Every refusal names what failed, so a test
/// asserts the rule rather than the verdict.
pub fn validate(
    precommit: &TraderPrecommitBody,
    preimage: &SettlementPreimage,
    evidence: &Evidence,
) -> Result<(), Refusal> {
    let bytes = preimage
        .encode()
        .map_err(|_| Refusal::Invalid(Invalid::LegsDoNotMatchPrecommit))?;
    if bytes.len() > MAX_SETTLEMENT_PREIMAGE_BYTES {
        return Err(Refusal::Invalid(Invalid::PreimageTooLarge {
            bytes: bytes.len(),
            max: MAX_SETTLEMENT_PREIMAGE_BYTES,
        }));
    }
    // E binds the whole preimage, so this is what stops P naming one operation
    // and the preimage describing another.
    let recomputed = derive::recompute_e(preimage)
        .map_err(|_| Refusal::Invalid(Invalid::ExternalCommitmentMismatch))?;
    if recomputed != *precommit.external_commitment() {
        return Err(Refusal::Invalid(Invalid::ExternalCommitmentMismatch));
    }

    let trader_core = preimage.trader_core();
    if trader_core.genesis() != precommit.genesis()
        || trader_core.device_id() != precommit.device_id()
        || trader_core.position() != precommit.position().saturating_add(1)
    {
        return Err(Refusal::Invalid(Invalid::CoreIdentityMismatch));
    }
    // P15-2: the void root is where the lineage returns to, so it IS the core's
    // pre-root; there is no second place for them to disagree.
    if *trader_core.pre_root() != *precommit.void_root() {
        return Err(Refusal::Invalid(Invalid::VoidRootIsNotThePreRoot));
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
            precommit,
            preimage,
            evidence,
            vault_id,
            owner_authority,
            *reserve_a,
            *reserve_b,
        ),
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
            CoreEntry::Relationship { base, .. } => {
                let held = evidence.vault_leaf(core.vault_id(), &key)?;
                let pre = match held {
                    VaultLeafPre::Absent => None,
                    VaultLeafPre::Relationship(r) => {
                        require(r.leaf == *base, Invalid::RelationshipBaseMismatch)?;
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

fn fold_core(entries: &[FoldEntry], pre_root: &D32, core: &'static str) -> Result<D32, Refusal> {
    let folded = batch_fold(entries).map_err(|_| {
        Refusal::Invalid(Invalid::CoreDoesNotFold {
            reason: "the entries' paths are not of one tree",
        })
    })?;
    require(
        folded.pre_root == *pre_root,
        Invalid::CoreDoesNotFold {
            reason: "the entries do not fold to the core's own pre-root",
        },
    )
    .map_err(|_| Refusal::Invalid(Invalid::WriteSetNotExact { core }))?;
    Ok(folded.post_root)
}

/// One vault's state before and after a swap hop, priced by its own policies.
fn swap_vault_post(
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
            CoreEntry::Relationship { vault_id, .. } if vault_id == core.vault_id() => {
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

fn validate_swap(
    precommit: &TraderPrecommitBody,
    preimage: &SettlementPreimage,
    evidence: &Evidence,
    intent: SwapIntent,
    hops: &[SwapHop],
) -> Result<(), Refusal> {
    let e = *precommit.external_commitment();
    // The route's ends are the intent's, and each hop feeds the next exactly.
    require(
        intent.token_in != intent.token_out,
        Invalid::RouteDoesNotChain { hop: 0 },
    )?;
    let first = hops
        .first()
        .ok_or(Refusal::Invalid(Invalid::RouteDoesNotChain { hop: 0 }))?;
    let last = hops
        .last()
        .ok_or(Refusal::Invalid(Invalid::RouteDoesNotChain { hop: 0 }))?;
    require(
        first.token_in == intent.token_in && first.amount_in == intent.amount_in,
        Invalid::RouteDoesNotChain { hop: 0 },
    )?;
    require(
        last.token_out == intent.token_out && last.amount_out == intent.exact_out,
        Invalid::RouteDoesNotChain {
            hop: hops.len() - 1,
        },
    )?;
    for (i, pair) in hops.windows(2).enumerate() {
        require(
            pair[0].token_out == pair[1].token_in && pair[0].amount_out == pair[1].amount_in,
            Invalid::RouteDoesNotChain { hop: i + 1 },
        )?;
    }

    // P's legs are exactly the operation's DLV parents, with the same roots.
    require(
        precommit.legs().len() == hops.len(),
        Invalid::LegsDoNotMatchPrecommit,
    )?;
    for hop in hops {
        let leg = precommit
            .legs()
            .iter()
            .find(|l| l.vault_id == hop.vault_id)
            .ok_or(Refusal::Invalid(Invalid::LegsDoNotMatchPrecommit))?;
        require(
            leg.parent_root == hop.parent_root && leg.setup_ref == hop.setup_ref,
            Invalid::LegsDoNotMatchPrecommit,
        )?;
    }

    // Each vault: its own core, its own policies, its own price.
    for (i, hop) in hops.iter().enumerate() {
        let core = preimage
            .dlv_cores()
            .iter()
            .find(|c| *c.vault_id() == hop.vault_id)
            .ok_or(Refusal::Invalid(Invalid::LegsDoNotMatchPrecommit))?;
        require(
            core.trader_genesis() == precommit.genesis()
                && core.trader_device_id() == precommit.device_id(),
            Invalid::CoreIdentityMismatch,
        )?;
        // The core's pre-root IS the DLV parent P named.
        require(
            *core.pre_root() == hop.parent_root,
            Invalid::LegsDoNotMatchPrecommit,
        )?;
        let (pre_state, policies) = evidence.vault_state(&hop.vault_id)?;
        require(
            pre_state.storage_set_id == *precommit.storage_set_id(),
            Invalid::NetworkScopeMismatch,
        )?;
        let post_state = swap_vault_post(&pre_state, &policies, hop, i)?;
        check_vault_write_set(core, &post_state, &pre_state)?;
        let entries = dlv_fold_entries(core, &e, evidence)?;
        fold_core(&entries, core.pre_root(), "V°")?;
    }

    // The trader side: one debit, one credit, one relationship per leg.
    let trader_core = preimage.trader_core();
    let bases = relationship_bases(trader_core.entries());
    require(
        bases.len() == hops.len(),
        Invalid::WriteSetNotExact { core: "T°" },
    )?;
    for hop in hops {
        let (genesis, device_id, base) = bases
            .get(&hop.vault_id)
            .ok_or(Refusal::Invalid(Invalid::WriteSetNotExact { core: "T°" }))?;
        require(
            genesis == precommit.genesis() && device_id == precommit.device_id(),
            Invalid::CoreIdentityMismatch,
        )?;
        // The two cores must agree on the relationship they are advancing.
        let core = preimage
            .dlv_cores()
            .iter()
            .find(|c| *c.vault_id() == hop.vault_id)
            .ok_or(Refusal::Invalid(Invalid::LegsDoNotMatchPrecommit))?;
        require(
            *core.relationship_base() == *base,
            Invalid::RelationshipBaseMismatch,
        )?;
    }
    check_trader_balances(
        precommit,
        trader_core,
        evidence,
        &[
            (intent.token_out, intent.exact_out, 0),
            (intent.token_in, 0, intent.amount_in),
        ],
        hops.len(),
    )?;

    let entries = trader_fold_entries(trader_core, &e, evidence)?;
    let post_root = fold_core(&entries, trader_core.pre_root(), "T°")?;
    require(
        post_root == *precommit.realize_root(),
        Invalid::RealizeRootIsNotTheFold,
    )
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
    precommit: &TraderPrecommitBody,
    preimage: &SettlementPreimage,
    evidence: &Evidence,
    vault_id: &D32,
    owner_authority: &OwnerAuthority,
    reserve_a: u64,
    reserve_b: u64,
) -> Result<(), Refusal> {
    let e = *precommit.external_commitment();
    // R18-1: the reserved branch decodes, and is refused here. A verifier KNOWS
    // it is not activated, so this is Invalid and never Unavailable.
    require(
        owner_authority.is_activated(),
        Invalid::OwnerAuthorityNotActivated,
    )?;
    require(
        precommit.legs().len() == 1 && precommit.legs()[0].vault_id == *vault_id,
        Invalid::LegsDoNotMatchPrecommit,
    )?;
    let (pre_state, policies) = evidence.vault_state(vault_id)?;

    // P15-11: the origin owner, and only it. Today's mnemonic recovery
    // re-derives the same (G, DevID), so a recovered owner closes here.
    require(
        *precommit.genesis() == pre_state.owner_genesis
            && *precommit.device_id() == pre_state.owner_device_id,
        Invalid::NotTheVaultOwner,
    )?;
    // The vault id is the owner's own derivation; a close cannot name another.
    require(
        derive::vault_id(
            &pre_state.owner_genesis,
            &pre_state.owner_device_id,
            pre_state.create_position,
        ) == *vault_id,
        Invalid::VaultIdIsNotTheOwnersDerivation,
    )?;
    // The release family is enforced where it is parsed: `decode_release_policy`
    // admits ONLY `OWNER_LOCAL_FULL_CLOSE`, so a vault released under any other
    // family has no policy to resolve and never reaches here. An equality check
    // on top of that would be decoration — a mutation proved it could not fail.
    require(
        pre_state.storage_set_id == *precommit.storage_set_id(),
        Invalid::NetworkScopeMismatch,
    )?;
    // Exactly the committed reserves, and nothing left behind.
    require(
        pre_state.status == VAULT_STATUS_ACTIVE,
        Invalid::VaultIsNotActive,
    )?;
    require(
        pre_state.reserve_a == reserve_a && pre_state.reserve_b == reserve_b,
        Invalid::CloseDoesNotRetireExactly,
    )?;
    let generation = pre_state.generation.checked_add(1).ok_or(Refusal::Invalid(
        Invalid::CheckedArithmetic {
            what: "vault generation",
        },
    ))?;
    let retired = VaultStateLeaf {
        generation,
        reserve_a: 0,
        reserve_b: 0,
        status: VAULT_STATUS_RETIRED,
        ..pre_state.clone()
    };

    let core = preimage
        .dlv_cores()
        .first()
        .ok_or(Refusal::Invalid(Invalid::LegsDoNotMatchPrecommit))?;
    require(
        preimage.dlv_cores().len() == 1 && *core.vault_id() == *vault_id,
        Invalid::LegsDoNotMatchPrecommit,
    )?;
    require(
        *core.pre_root() == precommit.legs()[0].parent_root,
        Invalid::LegsDoNotMatchPrecommit,
    )?;
    check_vault_write_set(core, &retired, &pre_state)?;
    let entries = dlv_fold_entries(core, &e, evidence)?;
    fold_core(&entries, core.pre_root(), "V°")?;

    // The trader takes back exactly both reserves, in the pair's own tokens.
    // No debit: a close pays out, and constant-product pricing never applies.
    let trader_core = preimage.trader_core();
    check_trader_balances(
        precommit,
        trader_core,
        evidence,
        &[
            (*policies.market.token_a(), reserve_a, 0),
            (*policies.market.token_b(), reserve_b, 0),
        ],
        1,
    )?;
    let bases = relationship_bases(trader_core.entries());
    let (genesis, device_id, base) = bases
        .get(vault_id)
        .ok_or(Refusal::Invalid(Invalid::WriteSetNotExact { core: "T°" }))?;
    require(
        genesis == precommit.genesis() && device_id == precommit.device_id(),
        Invalid::CoreIdentityMismatch,
    )?;
    require(
        *core.relationship_base() == *base,
        Invalid::RelationshipBaseMismatch,
    )?;

    let entries = trader_fold_entries(trader_core, &e, evidence)?;
    let post_root = fold_core(&entries, trader_core.pre_root(), "T°")?;
    require(
        post_root == *precommit.realize_root(),
        Invalid::RealizeRootIsNotTheFold,
    )
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)] // test asserts; a failure here is the signal
mod tests {
    use super::*;
    use crate::economic::tree::{EconomicSmt, ECONOMIC_SMT_HEIGHT};
    use crate::sofi::wire::{PreEClosureIndex, PrecommitLeg};

    const G: D32 = [0x11; 32];
    const DEV: D32 = [0x22; 32];
    const P_POS: u64 = 5;
    const P_CREATE: u64 = 7;
    const FEE_BPS: u32 = 30;
    const RESERVE_A: u64 = 10_000;
    const RESERVE_B: u64 = 20_000;
    const AMOUNT_IN: u64 = 1_000;
    const SIG_ALG: u16 = 0x0001;

    fn token(byte: u8) -> D32 {
        [byte; 32]
    }

    /// Vault `j` trades the pair `(token(j), token(j+1))`, strictly ordered as
    /// the market policy requires, so an N-hop route walks t0 → t1 → … → tN
    /// and never trades a token against itself.
    fn pair(j: usize) -> (D32, D32) {
        (token(0x40 + j as u8), token(0x41 + j as u8))
    }

    fn policies(j: usize) -> (MarketPolicy, FeePolicy, ReleasePolicy) {
        let (a, b) = pair(j);
        (
            MarketPolicy::beta_constant_product(a, b).unwrap(),
            FeePolicy::new(FEE_BPS).unwrap(),
            ReleasePolicy::beta_owner_local_full_close(),
        )
    }

    fn content_addr(bytes: &[u8]) -> D32 {
        *blake3::hash(bytes).as_bytes()
    }

    fn vault_id_of(j: usize) -> D32 {
        derive::vault_id(&G, &DEV, P_CREATE + j as u64)
    }

    fn vault_state(j: usize, reserve_a: u64, reserve_b: u64, status: u16) -> VaultStateLeaf {
        let (market, fee, release) = policies(j);
        VaultStateLeaf {
            owner_genesis: G,
            owner_device_id: DEV,
            create_position: P_CREATE + j as u64,
            market_policy: content_addr(&market.encode()),
            fee_policy: content_addr(&fee.encode()),
            release_policy: content_addr(&release.encode()),
            storage_set_id: token(0x77),
            generation: 3,
            reserve_a,
            reserve_b,
            status,
        }
    }

    fn policy_objects(hops: usize) -> BTreeMap<D32, Vec<u8>> {
        let mut objects = BTreeMap::new();
        for j in 0..hops.max(1) {
            let (market, fee, release) = policies(j);
            for bytes in [market.encode(), fee.encode(), release.encode()] {
                objects.insert(content_addr(&bytes), bytes);
            }
        }
        objects
    }

    fn path_of(tree: &EconomicSmt, key: &D32) -> Vec<D32> {
        tree.siblings(key).to_vec()
    }

    fn balance(policy_commit: D32, amount: u64) -> EconomicBalanceState {
        EconomicBalanceState {
            policy_commit,
            amount,
        }
    }

    fn balance_leaf_value(policy_commit: D32, amount: u64) -> D32 {
        EconomicLeafState::Balance(balance(policy_commit, amount))
            .leaf_value()
            .unwrap()
    }

    fn base_of(j: usize) -> D32 {
        derive::relationship_leaf_genesis(&derive::setup_id(&G, &DEV, P_POS, &vault_id_of(j)))
    }

    /// A whole operation, built the way a trader builds one: the trees first,
    /// then the cores against them, then E, then the roots E fixes.
    struct Fixture {
        precommit: TraderPrecommitBody,
        preimage: SettlementPreimage,
        evidence: Evidence,
    }

    /// One vault's worth of a swap: its tree, its core, and the hop it prices.
    struct VaultParts {
        vault_id: D32,
        core: DlvCore,
        hop: SwapHop,
        parent_root: D32,
        state: VaultStateLeaf,
        relationship: VaultRelationshipLeaf,
        state_key: D32,
        rel_key: D32,
    }

    fn swap_vault_parts(j: usize, amount_in: u64) -> VaultParts {
        let (token_in, token_out) = pair(j);
        let vault_id = vault_id_of(j);
        let rel_key = derive::relationship_key(&G, &DEV, &vault_id);
        let base = base_of(j);
        let state = vault_state(j, RESERVE_A, RESERVE_B, VAULT_STATUS_ACTIVE);
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
                setup_ref: token(0x55 + j as u8),
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

    fn swap_fixture_n(hops: usize) -> Fixture {
        let mut parts: Vec<VaultParts> = Vec::new();
        let mut amount = AMOUNT_IN;
        for j in 0..hops {
            let part = swap_vault_parts(j, amount);
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
        let mut core_ids: Vec<D32> = cores.iter().map(|c| *c.vault_id()).collect();
        core_ids.sort_unstable();
        let settlement = SettlementBody::Swap {
            token_in: intent_in,
            amount_in: AMOUNT_IN,
            token_out: intent_out,
            exact_out,
            hops: parts.iter().map(|p| p.hop).collect(),
            trader_core: derive::trader_core_digest(&trader_core.encode().unwrap()),
            dlv_cores: core_ids,
            closure: PreEClosureIndex::new(Vec::new()).unwrap(),
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
            objects: policy_objects(hops),
            trader_leaves,
            vault_leaves,
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
            &[0x01; 64],
        )
        .unwrap();
        Fixture {
            precommit,
            preimage,
            evidence,
        }
    }

    fn swap_fixture() -> Fixture {
        swap_fixture_n(1)
    }

    #[test]
    fn a_well_formed_swap_is_valid() {
        let f = swap_fixture();
        assert_eq!(validate(&f.precommit, &f.preimage, &f.evidence), Ok(()));
        assert_eq!(
            route_validation(&f.precommit, &f.preimage, &f.evidence),
            Validation::Valid
        );
    }

    /// Missing evidence is Unavailable, and stays Unavailable however much of
    /// the rest is present. It never hardens into Invalid.
    #[test]
    fn missing_evidence_is_unavailable_never_invalid() {
        let f = swap_fixture();
        let (market, _, _) = policies(0);
        let mut without_policy = Evidence {
            objects: f.evidence.objects.clone(),
            trader_leaves: f.evidence.trader_leaves.clone(),
            vault_leaves: f.evidence.vault_leaves.clone(),
        };
        without_policy
            .objects
            .remove(&content_addr(&market.encode()));
        assert!(matches!(
            validate(&f.precommit, &f.preimage, &without_policy),
            Err(Refusal::Unavailable(Missing::Policy { .. }))
        ));
        assert_eq!(
            route_validation(&f.precommit, &f.preimage, &without_policy),
            Validation::Unavailable
        );

        let mut without_leaf = Evidence {
            objects: f.evidence.objects.clone(),
            trader_leaves: f.evidence.trader_leaves.clone(),
            vault_leaves: BTreeMap::new(),
        };
        without_leaf.trader_leaves.clear();
        assert_eq!(
            route_validation(&f.precommit, &f.preimage, &without_leaf),
            Validation::Unavailable
        );
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
                dlv_cores: vec![*f.preimage.dlv_cores()[0].vault_id()],
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
        let mut entries = f.preimage.trader_core().entries().to_vec();
        let stray_key = token(0x09);
        entries.push(CoreEntry::Read {
            key: stray_key,
            value: crate::economic::tree::ABSENT_LEAF,
            path: vec![[0u8; 32]; ECONOMIC_SMT_HEIGHT],
        });
        entries.sort_by_key(|e| e.key());
        let core = TraderCore::new(
            G,
            DEV,
            P_POS + 1,
            *f.preimage.trader_core().pre_root(),
            entries,
        )
        .unwrap();
        let preimage = SettlementPreimage::new(
            f.preimage.settlement().clone(),
            core,
            f.preimage.dlv_cores().to_vec(),
        )
        .unwrap();
        let precommit = rebind(&f, &preimage);
        assert_eq!(
            validate(&precommit, &preimage, &f.evidence),
            Err(Refusal::Invalid(Invalid::WriteSetNotExact { core: "T°" }))
        );
    }

    /// A missing movement is the same rule from the other side.
    #[test]
    fn a_missing_trader_movement_is_invalid() {
        let f = swap_fixture();
        let out_key = balance_key(&G, &DEV, &pair(0).1);
        let entries: Vec<CoreEntry> = f
            .preimage
            .trader_core()
            .entries()
            .iter()
            .filter(|e| e.key() != out_key)
            .cloned()
            .collect();
        let core = TraderCore::new(
            G,
            DEV,
            P_POS + 1,
            *f.preimage.trader_core().pre_root(),
            entries,
        )
        .unwrap();
        let preimage = SettlementPreimage::new(
            f.preimage.settlement().clone(),
            core,
            f.preimage.dlv_cores().to_vec(),
        )
        .unwrap();
        let precommit = rebind(&f, &preimage);
        assert_eq!(
            validate(&precommit, &preimage, &f.evidence),
            Err(Refusal::Invalid(Invalid::WriteSetNotExact { core: "T°" }))
        );
    }

    /// A relationship advancing from a base the cores do not agree on.
    #[test]
    fn a_wrong_relationship_base_is_invalid() {
        let f = swap_fixture();
        let vault_id = *f.preimage.dlv_cores()[0].vault_id();
        let entries: Vec<CoreEntry> = f
            .preimage
            .trader_core()
            .entries()
            .iter()
            .map(|e| match e {
                CoreEntry::Relationship {
                    genesis,
                    device_id,
                    vault_id: v,
                    path,
                    ..
                } => CoreEntry::Relationship {
                    genesis: *genesis,
                    device_id: *device_id,
                    vault_id: *v,
                    base: token(0x03),
                    path: path.clone(),
                },
                other => other.clone(),
            })
            .collect();
        let core = TraderCore::new(
            G,
            DEV,
            P_POS + 1,
            *f.preimage.trader_core().pre_root(),
            entries,
        )
        .unwrap();
        let preimage = SettlementPreimage::new(
            f.preimage.settlement().clone(),
            core,
            f.preimage.dlv_cores().to_vec(),
        )
        .unwrap();
        let precommit = rebind(&f, &preimage);
        let _ = vault_id;
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
        let (token_a, token_b) = pair(0);
        let vault_id = derive::vault_id(&G, &owner_device, P_CREATE);
        let rel_key = derive::relationship_key(&G, &DEV, &vault_id);
        let base = derive::relationship_leaf_genesis(&derive::setup_id(&G, &DEV, P_POS, &vault_id));
        let state = VaultStateLeaf {
            owner_device_id: owner_device,
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
            setup_ref: token(0x55),
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

        let evidence = Evidence {
            objects: policy_objects(1),
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
                setup_ref: token(0x55),
            }],
            realize_root,
            trader_tree.root(),
            token(0x77),
            SIG_ALG,
            &[0x01; 64],
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
            Validation::Invalid
        );
        // Even with NOTHING fetched it is Invalid: the branch is refused before
        // any evidence is consulted.
        assert_eq!(
            route_validation(&f.precommit, &f.preimage, &Evidence::default()),
            Validation::Invalid
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
        let preimage = SettlementPreimage::new(
            f.preimage.settlement().clone(),
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

    /// A vault whose release policy is not the close family does not close.
    #[test]
    fn a_close_against_another_release_policy_is_invalid() {
        let f = close_fixture(OwnerAuthority::Origin);
        let vault_id = *f.preimage.dlv_cores()[0].vault_id();
        let state_key = derive::vault_state_key(&vault_id);
        let mut evidence = Evidence {
            objects: f.evidence.objects.clone(),
            trader_leaves: f.evidence.trader_leaves.clone(),
            vault_leaves: f.evidence.vault_leaves.clone(),
        };
        let VaultLeafPre::State(state) = evidence.vault_leaves[&(vault_id, state_key)].clone()
        else {
            panic!("the state leaf")
        };
        // A release policy object whose family is not OWNER_LOCAL_FULL_CLOSE
        // does not decode, so the verifier refuses rather than guessing.
        let bogus = {
            let mut bytes = ReleasePolicy::beta_owner_local_full_close().encode();
            let n = bytes.len();
            bytes[n - 4..n - 2].copy_from_slice(&[0x00, 0x09]);
            bytes
        };
        let addr = content_addr(&bogus);
        evidence.objects.insert(addr, bogus);
        evidence.vault_leaves.insert(
            (vault_id, state_key),
            VaultLeafPre::State(VaultStateLeaf {
                release_policy: addr,
                ..state
            }),
        );
        assert_eq!(
            validate(&f.precommit, &f.preimage, &evidence),
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
}
