// SPDX-License-Identifier: Apache-2.0

//! The closed write set of an operation — BOTH sides of one deterministic rule.
//!
//! [`crate::economic::classifier::classify`] names the category
//! (`ClosedWriteSet`) and deliberately does not compute the set. This module
//! is that computation, twice, from the same table:
//!
//! - [`build_write_set`] — the PRODUCER: from a verified operation, the
//!   authenticated local identity, and the pre-state, derive the exact
//!   mutations (key-ordered, progressively-proved) and credit sources.
//! - [`verify_operation_write_set`] — the VERIFIER: given a verified
//!   operation and a witness, require the witness's mutations to be EXACTLY
//!   the semantic effect of that operation — no missing mutation, no extra
//!   mutation, exact asset, exact amount, exact role, exact source kind.
//!
//! The verifier side is the security rule. `advance_validated` already proved
//! the mutation sequence internally consistent and the credits funded; without
//! this check an adversarial producer could pair a valid accepted operation
//! with a DIFFERENT internally consistent write set. The producer side is the
//! honest-wallet convenience that can never disagree with the verifier,
//! because both are generated from the one match below.
//!
//! ## Role is derived, never supplied
//!
//! An online `Transfer` is ONE role-dependent economic event: the role follows
//! from `operation.to_device_id == the authenticated local DevID`. A
//! caller-supplied role enum would be a second place for that fact to live.
//!
//! ## Ordering and proofs
//!
//! Mutations are ordered by derived leaf key ascending, and each mutation's
//! siblings are captured from the tree AFTER every earlier mutation applied —
//! exactly the sequential-root semantics `verify_mutation_sequence` checks.
//! `credit_mutation_index` is therefore assigned only after the key sort.

use std::collections::BTreeMap;

use crate::economic::credit::{
    CreditSource, CreditSourceSameTransitionMove, CreditSourceValidatedFaucetDistribution,
    CreditSourceValidatedPeerDebit,
};
use crate::economic::mutation::EconomicLeafMutation;
use crate::economic::provenance::validated_peer_debit_source_id;
use crate::economic::state::{
    EconomicBalanceState, EconomicConsumedSourceState, EconomicLeafState, EconomicVaultReserveState,
};
use crate::economic::tree::EconomicSmt;
use crate::economic::witness::EconomicTransitionWitness;
use crate::types::operations::Operation;

/// Why an operation has no buildable/verifiable write set, or why a witness
/// is not the exact effect of its operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WriteSetError {
    /// The consumed-source leaf for this funding source already exists in the
    /// pre-state tree — the source has ALREADY funded a credit. The verifier
    /// refuses this independently (a `pre: None` mutation cannot prove
    /// against a tree whose leaf is non-zero); refusing at build gives an
    /// honest producer a named error instead of an unverifiable witness.
    SourceAlreadyConsumed,
    /// `CreateToken` with `initial_supply > 0`: the new asset's supply credit
    /// has no fundable source until the issuance predicate (`0x0029`) exists.
    /// Funding it from the ERA fee debit would turn a fee payment into
    /// arbitrary issuance (`SameTransitionMove` is same-asset conservation).
    CreateTokenInitialSupplyRequiresIssuancePredicate,
    /// `Mint`: no authenticated issuance predicate exists.
    IssuancePredicateUndefined,
    /// Classified `ClosedWriteSet` but its write set is deferred
    /// (`DlvSettle`/`DlvClose` — 3.6).
    OperationWriteSetNotYetSpecified,
    /// The operation touches online value with no defined foreign-verifiable
    /// source predicate.
    UnsupportedValueTransition,
    /// The operation writes no economic leaf; there is nothing to witness,
    /// and a witness claiming otherwise is refused.
    NoEconomicWriteSet,
    /// A `Transfer` whose `to_device_id` is not 32 bytes.
    MalformedRecipient,
    /// The producer's pre-state cannot fund the debit.
    InsufficientBalance {
        policy_commit: [u8; 32],
        have: u64,
        need: u64,
    },
    /// A credit would overflow the balance.
    BalanceOverflow,
    /// The facts supplied to the producer do not match what the operation's
    /// write set requires (missing peer coordinates, unexpected faucet
    /// evidence, ...).
    FactsDoNotMatchOperation,
    /// A witness mutation touches a leaf class this operation's write set
    /// does not contain.
    UnexpectedLeafClass,
    /// The witness's mutations are not the exact semantic effect of the
    /// operation.
    WrongWriteSet { detail: &'static str },
    /// A DLV operation whose own fields are malformed for a write set:
    /// non-canonical or duplicate legs, a zero leg, a vault id that is not
    /// 32 bytes, or a generation step that is not exactly one.
    MalformedVaultOperation { detail: &'static str },
    /// A mutation or state constructor refused (zero-amount leaf, sibling
    /// arity, ...) — carried through from the CCB layer.
    Ccb(String),
}

impl core::fmt::Display for WriteSetError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::SourceAlreadyConsumed => write!(
                f,
                "this funding source has already been consumed — a source funds exactly one \
                 credit, and V1 defines no splits"
            ),
            Self::CreateTokenInitialSupplyRequiresIssuancePredicate => write!(
                f,
                "CreateToken with initial_supply > 0 cannot enter a validated lineage: the new \
                 asset's supply credit has no authenticated issuance/source predicate yet, and \
                 the ERA fee debit must not fund a different asset"
            ),
            Self::IssuancePredicateUndefined => write!(
                f,
                "Mint has no authenticated issuance predicate; nothing can fund its credit"
            ),
            Self::OperationWriteSetNotYetSpecified => write!(
                f,
                "this operation's economic write set is not yet specified (deferred to the DLV \
                 economic integration)"
            ),
            Self::UnsupportedValueTransition => write!(
                f,
                "operation touches online economic value with no defined foreign-verifiable \
                 source predicate"
            ),
            Self::NoEconomicWriteSet => {
                write!(f, "operation writes no economic leaf; nothing to witness")
            }
            Self::MalformedRecipient => write!(f, "transfer recipient is not a 32-byte device id"),
            Self::InsufficientBalance { have, need, .. } => write!(
                f,
                "insufficient balance for exact debit: have {have}, need {need}"
            ),
            Self::BalanceOverflow => write!(f, "credit would overflow the balance"),
            Self::FactsDoNotMatchOperation => write!(
                f,
                "the supplied credit-source facts do not match what this operation's write set \
                 requires"
            ),
            Self::UnexpectedLeafClass => write!(
                f,
                "witness mutation touches a leaf class outside this operation's write set"
            ),
            Self::WrongWriteSet { detail } => write!(
                f,
                "witness is not the exact economic effect of the operation: {detail}"
            ),
            Self::MalformedVaultOperation { detail } => {
                write!(f, "the DLV operation cannot state a write set: {detail}")
            }
            Self::Ccb(e) => write!(f, "write set: {e}"),
        }
    }
}

impl std::error::Error for WriteSetError {}

/// The external facts a credit source needs — everything the operation bytes
/// alone cannot know. Pure debits need none.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CreditSourceFacts {
    /// Debit-only write set.
    None,
    /// A faucet claim's evidence address (the exact winning envelope bytes).
    FaucetTicket {
        faucet_claim_evidence_addr: [u8; 32],
    },
    /// A recipient credit funded by the sender's validated debit.
    PeerDebit {
        peer_genesis: [u8; 32],
        peer_devid: [u8; 32],
        peer_economic_position: u64,
        peer_debit_mutation_index: u32,
        acceptance_evidence_addr: [u8; 32],
    },
}

/// The producer's authenticated pre-state, decoded. `balances` is keyed by
/// policy commit; `vault_reserves` by `(vault_id, policy_commit)` — absence
/// means the leaf is absent. The tree remains the authority: a pre-state that
/// disagrees with it produces a witness that fails Merkle verification.
pub struct EconomicPreState<'a> {
    pub balances: &'a BTreeMap<[u8; 32], u64>,
    pub vault_reserves: &'a BTreeMap<([u8; 32], [u8; 32]), EconomicVaultReserveState>,
}

static EMPTY_RESERVES: BTreeMap<([u8; 32], [u8; 32]), EconomicVaultReserveState> = BTreeMap::new();

impl<'a> EconomicPreState<'a> {
    /// A pre-state with no vault reserves — every non-DLV producer.
    pub fn balances_only(balances: &'a BTreeMap<[u8; 32], u64>) -> Self {
        Self {
            balances,
            vault_reserves: &EMPTY_RESERVES,
        }
    }
}

/// The producer's output: key-ordered mutations with progressive proofs, the
/// matching credit sources, and the resulting root.
#[derive(Debug, Clone)]
pub struct BuiltWriteSet {
    pub mutations: Vec<EconomicLeafMutation>,
    pub credit_sources: Vec<CreditSource>,
    pub post_root: [u8; 32],
}

/// One planned leaf change, before ordering and proof capture.
struct PlannedLeaf {
    key: [u8; 32],
    pre: Option<EconomicLeafState>,
    post: Option<EconomicLeafState>,
    /// `Some` when this leaf is the positive credit a source funds.
    source: Option<PlannedSource>,
}

/// How a planned credit is funded. `SameMove` names the DEBIT leaf by key;
/// the index is resolved only after the key sort, so descriptor indices are
/// derived facts, never plan-time guesses.
enum PlannedSource {
    External(CreditSourceFacts),
    SameMove { debit_key: [u8; 32] },
}

/// The semantic write set of an operation, before proofs: what changes and
/// what funds it. One derivation, used by both the producer and (in delta
/// form) the verifier.
enum SemanticWriteSet {
    /// One balance debit, no credit source.
    DebitOnly {
        policy_commit: [u8; 32],
        amount: u64,
    },
    /// One balance credit plus its source; for a peer debit, also the
    /// consumed-source insertion.
    Credit {
        policy_commit: [u8; 32],
        amount: u64,
        facts_required: FactsKind,
    },
    /// `DlvCreateFundedV2`: two balance debits + two vault-reserve credits at
    /// generation 0, each reserve credit funded by the matching balance debit
    /// (`SameTransitionMove`). Legs are canonical (`a < b`), both non-zero.
    DlvFund {
        vault_id: [u8; 32],
        leg_a: ([u8; 32], u64),
        leg_b: ([u8; 32], u64),
    },
    /// `DlvClose`: both reserves `{amount, parent} -> {0, parent+1}` plus the
    /// matching balance credits, each funded by the reserve it drains
    /// (`SameTransitionMove`). The zero-amount terminal reserve stays PRESENT.
    DlvWithdraw {
        vault_id: [u8; 32],
        leg_a: ([u8; 32], u64),
        leg_b: ([u8; 32], u64),
        parent_sequence: u64,
        new_sequence: u64,
    },
}

/// One asset leg of a DLV pair operation: `(policy_commit, amount)`.
type DlvLeg = ([u8; 32], u64);

/// Validate and project the two signed legs of a DLV pair operation.
fn dlv_pair_legs(
    vault_id: &[u8],
    leg_a: DlvLeg,
    leg_b: DlvLeg,
) -> Result<([u8; 32], DlvLeg, DlvLeg), WriteSetError> {
    let vault: [u8; 32] =
        vault_id
            .try_into()
            .map_err(|_| WriteSetError::MalformedVaultOperation {
                detail: "vault id is not 32 bytes",
            })?;
    if leg_a.0 >= leg_b.0 {
        return Err(WriteSetError::MalformedVaultOperation {
            detail: "legs are not distinct assets in canonical order (a < b)",
        });
    }
    if leg_a.1 == 0 || leg_b.1 == 0 {
        return Err(WriteSetError::MalformedVaultOperation {
            detail: "both legs must be non-zero",
        });
    }
    Ok((vault, leg_a, leg_b))
}

#[derive(PartialEq, Eq, Debug, Clone, Copy)]
enum FactsKind {
    FaucetTicket,
    PeerDebit,
}

/// The one table: what an operation does to `R_econ`, or why it cannot be
/// witnessed. Role for `Transfer` derives from the authenticated local DevID.
fn semantic_write_set(
    operation: &Operation,
    local_devid: &[u8; 32],
) -> Result<SemanticWriteSet, WriteSetError> {
    match operation {
        Operation::Transfer {
            to_device_id,
            amount,
            policy_commit,
            authority_policy,
            ..
        } => {
            if authority_policy.is_some() {
                // Offline-bearer tier: moves allocation, not balance.
                return Err(WriteSetError::NoEconomicWriteSet);
            }
            let recipient: [u8; 32] = to_device_id
                .as_slice()
                .try_into()
                .map_err(|_| WriteSetError::MalformedRecipient)?;
            if recipient == *local_devid {
                Ok(SemanticWriteSet::Credit {
                    policy_commit: *policy_commit,
                    amount: amount.value(),
                    facts_required: FactsKind::PeerDebit,
                })
            } else {
                Ok(SemanticWriteSet::DebitOnly {
                    policy_commit: *policy_commit,
                    amount: amount.value(),
                })
            }
        }
        Operation::Burn {
            amount,
            policy_commit,
            ..
        } => Ok(SemanticWriteSet::DebitOnly {
            policy_commit: *policy_commit,
            amount: amount.value(),
        }),
        Operation::CreateToken {
            initial_supply,
            fee_amount,
            ..
        } => {
            if initial_supply.value() > 0 {
                return Err(WriteSetError::CreateTokenInitialSupplyRequiresIssuancePredicate);
            }
            if *fee_amount == 0 {
                return Err(WriteSetError::NoEconomicWriteSet);
            }
            Ok(SemanticWriteSet::DebitOnly {
                policy_commit: crate::core::token::token_state_manager::era_policy_commit(),
                amount: *fee_amount,
            })
        }
        Operation::FaucetClaim { .. } => Ok(SemanticWriteSet::Credit {
            policy_commit: crate::core::token::token_state_manager::era_policy_commit(),
            amount: crate::economic::faucet::ERA_FAUCET_PAYOUT,
            facts_required: FactsKind::FaucetTicket,
        }),
        Operation::Mint { .. } => Err(WriteSetError::IssuancePredicateUndefined),
        Operation::DlvCreateFundedV2 {
            vault_id,
            leg_a_policy_commit,
            leg_a_amount,
            leg_b_policy_commit,
            leg_b_amount,
            ..
        } => {
            let (vault_id, leg_a, leg_b) = dlv_pair_legs(
                vault_id,
                (*leg_a_policy_commit, *leg_a_amount),
                (*leg_b_policy_commit, *leg_b_amount),
            )?;
            Ok(SemanticWriteSet::DlvFund {
                vault_id,
                leg_a,
                leg_b,
            })
        }
        Operation::DlvClose {
            vault_id,
            leg_a_policy_commit,
            leg_a_amount,
            leg_b_policy_commit,
            leg_b_amount,
            parent_sequence,
            new_sequence,
            ..
        } => {
            let (vault_id, leg_a, leg_b) = dlv_pair_legs(
                vault_id,
                (*leg_a_policy_commit, *leg_a_amount),
                (*leg_b_policy_commit, *leg_b_amount),
            )?;
            if parent_sequence
                .checked_add(1)
                .is_none_or(|n| n != *new_sequence)
            {
                return Err(WriteSetError::MalformedVaultOperation {
                    detail: "a close advances the vault by exactly one generation",
                });
            }
            Ok(SemanticWriteSet::DlvWithdraw {
                vault_id,
                leg_a,
                leg_b,
                parent_sequence: *parent_sequence,
                new_sequence: *new_sequence,
            })
        }
        // The settle and v2 owner-apply write sets need the 0x0026/0x0027
        // provenance arms (PR3/PR4 of the 3.6 cut) — refused honestly until
        // then.
        Operation::DlvSettle { .. } | Operation::DlvOwnerApplyV2 { .. } => {
            Err(WriteSetError::OperationWriteSetNotYetSpecified)
        }
        other => match crate::economic::classifier::classify(other) {
            crate::economic::classifier::EconomicEffect::UnsupportedValueTransition => {
                Err(WriteSetError::UnsupportedValueTransition)
            }
            _ => Err(WriteSetError::NoEconomicWriteSet),
        },
    }
}

fn balance_state(
    policy_commit: [u8; 32],
    amount: u64,
) -> Result<Option<EconomicLeafState>, WriteSetError> {
    if amount == 0 {
        return Ok(None);
    }
    Ok(Some(EconomicLeafState::Balance(
        EconomicBalanceState::new(policy_commit, amount)
            .map_err(|e| WriteSetError::Ccb(e.to_string()))?,
    )))
}

/// Build the exact write set against the producer's own pre-state.
///
/// `tree` must recompute the validated pre-root; on success it holds the
/// post-state and `post_root` is its root. `economic_operation_id` is the v2
/// id of the PREPARED successor (`H(G ‖ DevID ‖ C_dsm+)`) — the successor is
/// prepared before the write set is built, which is why this function can
/// require it rather than a placeholder.
pub fn build_write_set(
    operation: &Operation,
    genesis: &[u8; 32],
    device_id: &[u8; 32],
    economic_operation_id: &[u8; 32],
    pre_state: &EconomicPreState<'_>,
    tree: &mut EconomicSmt,
    facts: &CreditSourceFacts,
) -> Result<BuiltWriteSet, WriteSetError> {
    let pre_balances = pre_state.balances;
    let semantic = semantic_write_set(operation, device_id)?;
    let mut planned: Vec<PlannedLeaf> = Vec::new();

    /// Plan one balance debit against the pre-state.
    fn plan_balance_debit(
        genesis: &[u8; 32],
        device_id: &[u8; 32],
        pre_balances: &BTreeMap<[u8; 32], u64>,
        policy_commit: [u8; 32],
        amount: u64,
    ) -> Result<PlannedLeaf, WriteSetError> {
        let have = pre_balances.get(&policy_commit).copied().unwrap_or(0);
        if have < amount {
            return Err(WriteSetError::InsufficientBalance {
                policy_commit,
                have,
                need: amount,
            });
        }
        let pre = balance_state(policy_commit, have)?;
        let post = balance_state(policy_commit, have - amount)?;
        let key = pre.as_ref().map(|s| s.leaf_key(genesis, device_id)).ok_or(
            WriteSetError::WrongWriteSet {
                detail: "debit from an absent balance",
            },
        )?;
        Ok(PlannedLeaf {
            key,
            pre,
            post,
            source: None,
        })
    }

    match semantic {
        SemanticWriteSet::DebitOnly {
            policy_commit,
            amount,
        } => {
            if *facts != CreditSourceFacts::None {
                return Err(WriteSetError::FactsDoNotMatchOperation);
            }
            planned.push(plan_balance_debit(
                genesis,
                device_id,
                pre_balances,
                policy_commit,
                amount,
            )?);
        }
        SemanticWriteSet::Credit {
            policy_commit,
            amount,
            facts_required,
        } => {
            let matches = matches!(
                (facts, facts_required),
                (
                    CreditSourceFacts::FaucetTicket { .. },
                    FactsKind::FaucetTicket
                ) | (CreditSourceFacts::PeerDebit { .. }, FactsKind::PeerDebit)
            );
            if !matches {
                return Err(WriteSetError::FactsDoNotMatchOperation);
            }
            let have = pre_balances.get(&policy_commit).copied().unwrap_or(0);
            let next = have
                .checked_add(amount)
                .ok_or(WriteSetError::BalanceOverflow)?;
            let pre = balance_state(policy_commit, have)?;
            let post = balance_state(policy_commit, next)?;
            let key = post
                .as_ref()
                .map(|s| s.leaf_key(genesis, device_id))
                .ok_or(WriteSetError::WrongWriteSet {
                    detail: "credit produced no post state",
                })?;
            planned.push(PlannedLeaf {
                key,
                pre,
                post,
                source: Some(PlannedSource::External(facts.clone())),
            });
            // A peer-funded credit also consumes the source, from ZERO, in
            // the SAME witness — the non-reuse leaf.
            if let CreditSourceFacts::PeerDebit {
                peer_genesis,
                peer_devid,
                peer_economic_position,
                peer_debit_mutation_index,
                ..
            } = facts
            {
                let source_id = validated_peer_debit_source_id(
                    peer_genesis,
                    peer_devid,
                    *peer_economic_position,
                    *peer_debit_mutation_index,
                );
                let consumed = EconomicLeafState::ConsumedSource(EconomicConsumedSourceState {
                    source_id,
                    consumer_economic_operation_id: *economic_operation_id,
                });
                let key = consumed.leaf_key(genesis, device_id);
                if tree.get(&key).is_some() {
                    return Err(WriteSetError::SourceAlreadyConsumed);
                }
                planned.push(PlannedLeaf {
                    key,
                    pre: None,
                    post: Some(consumed),
                    source: None,
                });
            }
        }
        SemanticWriteSet::DlvFund {
            vault_id,
            leg_a,
            leg_b,
        } => {
            if *facts != CreditSourceFacts::None {
                return Err(WriteSetError::FactsDoNotMatchOperation);
            }
            for (policy_commit, amount) in [leg_a, leg_b] {
                let debit =
                    plan_balance_debit(genesis, device_id, pre_balances, policy_commit, amount)?;
                let debit_key = debit.key;
                planned.push(debit);
                let reserve = EconomicLeafState::VaultReserve(EconomicVaultReserveState {
                    vault_id,
                    policy_commit,
                    amount,
                    vault_sequence: 0,
                });
                let key = reserve.leaf_key(genesis, device_id);
                // Birth is generation 0 from ABSENT: an existing leaf (any
                // amount, any generation — a closed vault's terminal zero
                // included) means this vault id was already used.
                if tree.get(&key).is_some() {
                    return Err(WriteSetError::WrongWriteSet {
                        detail: "a reserve leaf for this vault and asset already exists",
                    });
                }
                planned.push(PlannedLeaf {
                    key,
                    pre: None,
                    post: Some(reserve),
                    source: Some(PlannedSource::SameMove { debit_key }),
                });
            }
        }
        SemanticWriteSet::DlvWithdraw {
            vault_id,
            leg_a,
            leg_b,
            parent_sequence,
            new_sequence,
        } => {
            if *facts != CreditSourceFacts::None {
                return Err(WriteSetError::FactsDoNotMatchOperation);
            }
            for (policy_commit, amount) in [leg_a, leg_b] {
                let pre_reserve = pre_state
                    .vault_reserves
                    .get(&(vault_id, policy_commit))
                    .ok_or(WriteSetError::WrongWriteSet {
                        detail: "close names a reserve leg the pre-state does not hold",
                    })?;
                if pre_reserve.vault_id != vault_id
                    || pre_reserve.policy_commit != policy_commit
                    || pre_reserve.amount != amount
                    || pre_reserve.vault_sequence != parent_sequence
                {
                    return Err(WriteSetError::WrongWriteSet {
                        detail: "close must drain the exact reserve amount at the exact \
                                 parent generation",
                    });
                }
                let pre = EconomicLeafState::VaultReserve(pre_reserve.clone());
                let reserve_key = pre.leaf_key(genesis, device_id);
                // Terminal generation: zero amount, PRESENT — never deleted,
                // which is what makes a closed vault id single-use.
                let post = EconomicLeafState::VaultReserve(EconomicVaultReserveState {
                    vault_id,
                    policy_commit,
                    amount: 0,
                    vault_sequence: new_sequence,
                });
                planned.push(PlannedLeaf {
                    key: reserve_key,
                    pre: Some(pre),
                    post: Some(post),
                    source: None,
                });
                // The matching balance credit, funded by the reserve it
                // drains.
                let have = pre_balances.get(&policy_commit).copied().unwrap_or(0);
                let next = have
                    .checked_add(amount)
                    .ok_or(WriteSetError::BalanceOverflow)?;
                let pre = balance_state(policy_commit, have)?;
                let post = balance_state(policy_commit, next)?;
                let key = post
                    .as_ref()
                    .map(|s| s.leaf_key(genesis, device_id))
                    .ok_or(WriteSetError::WrongWriteSet {
                        detail: "close credit produced no post state",
                    })?;
                planned.push(PlannedLeaf {
                    key,
                    pre,
                    post,
                    source: Some(PlannedSource::SameMove {
                        debit_key: reserve_key,
                    }),
                });
            }
        }
    }

    // Key order, then progressive proof capture: mutation i's siblings come
    // from the tree with mutations 0..i already applied. Indices — including
    // a SameMove's debit index — exist only after this sort.
    planned.sort_by_key(|l| l.key);
    let index_of_key: BTreeMap<[u8; 32], u32> = planned
        .iter()
        .enumerate()
        .map(|(i, l)| {
            u32::try_from(i)
                .map(|i| (l.key, i))
                .map_err(|_| WriteSetError::Ccb("index overflow".into()))
        })
        .collect::<Result<_, _>>()?;
    let mut mutations = Vec::with_capacity(planned.len());
    let mut credit_sources = Vec::new();
    for (index, leaf) in planned.into_iter().enumerate() {
        let siblings = tree.siblings(&leaf.key).to_vec();
        let mutation = EconomicLeafMutation::new(leaf.pre, leaf.post.clone(), siblings)
            .map_err(|e| WriteSetError::Ccb(e.to_string()))?;
        match &leaf.post {
            Some(state) => {
                let value = state
                    .leaf_value()
                    .map_err(|e| WriteSetError::Ccb(e.to_string()))?;
                tree.insert(leaf.key, value);
            }
            None => tree.remove(&leaf.key),
        }
        if let Some(planned_source) = leaf.source {
            let credit_mutation_index =
                u32::try_from(index).map_err(|_| WriteSetError::Ccb("index overflow".into()))?;
            let facts = match planned_source {
                PlannedSource::SameMove { debit_key } => {
                    let debit_mutation_index = *index_of_key
                        .get(&debit_key)
                        .ok_or(WriteSetError::Ccb("same-move debit key not planned".into()))?;
                    credit_sources.push(CreditSource::SameTransitionMove(
                        CreditSourceSameTransitionMove {
                            credit_mutation_index,
                            debit_mutation_index,
                        },
                    ));
                    mutations.push(mutation);
                    continue;
                }
                PlannedSource::External(facts) => facts,
            };
            let source = match (facts, operation) {
                (
                    CreditSourceFacts::FaucetTicket {
                        faucet_claim_evidence_addr,
                    },
                    Operation::FaucetClaim {
                        faucet_id,
                        ticket_index,
                    },
                ) => CreditSource::ValidatedFaucetDistribution(
                    CreditSourceValidatedFaucetDistribution {
                        credit_mutation_index,
                        faucet_id: *faucet_id,
                        ticket_index: *ticket_index,
                        faucet_claim_evidence_addr,
                    },
                ),
                (
                    CreditSourceFacts::PeerDebit {
                        peer_genesis,
                        peer_devid,
                        peer_economic_position,
                        peer_debit_mutation_index,
                        acceptance_evidence_addr,
                    },
                    _,
                ) => CreditSource::ValidatedPeerDebit(CreditSourceValidatedPeerDebit {
                    credit_mutation_index,
                    peer_genesis,
                    peer_devid,
                    peer_economic_position,
                    peer_debit_mutation_index,
                    acceptance_evidence_addr,
                }),
                _ => return Err(WriteSetError::FactsDoNotMatchOperation),
            };
            credit_sources.push(source);
        }
        mutations.push(mutation);
    }

    Ok(BuiltWriteSet {
        mutations,
        credit_sources,
        post_root: tree.root(),
    })
}

/// One observed balance change in a witness.
struct ObservedBalance {
    policy_commit: [u8; 32],
    pre_amount: u64,
    post_amount: u64,
    mutation_index: u32,
}

/// One observed vault-reserve change in a witness.
struct ObservedReserve {
    pre: Option<EconomicVaultReserveState>,
    post: EconomicVaultReserveState,
    mutation_index: u32,
}

/// The VERIFIER half: the witness's mutations must be exactly the semantic
/// effect of the verified operation.
///
/// Structure only — funding is `verify_transition_provenance`'s job, and the
/// internal Merkle consistency is `verify_mutation_sequence`'s. What THIS
/// check owns is the operation↔write-set binding: without it, "internally
/// consistent and funded" could describe a different operation than the one
/// the substrate accepted.
pub fn verify_operation_write_set(
    operation: &Operation,
    genesis: &[u8; 32],
    device_id: &[u8; 32],
    witness: &EconomicTransitionWitness,
) -> Result<(), WriteSetError> {
    let _ = genesis;
    let semantic = semantic_write_set(operation, device_id)?;

    // Classify every mutation. The legal leaf classes are VARIANT-DRIVEN:
    // vault-reserve leaves exist only in the DLV write sets, and settlement
    // receipts only in the settle write set (PR3) — everything else refuses
    // them outright, exactly as before 3.6.
    let reserves_legal = matches!(
        semantic,
        SemanticWriteSet::DlvFund { .. } | SemanticWriteSet::DlvWithdraw { .. }
    );
    let mut balances: Vec<ObservedBalance> = Vec::new();
    let mut consumed: Vec<(u32, EconomicConsumedSourceState)> = Vec::new();
    let mut reserves: Vec<ObservedReserve> = Vec::new();
    for (i, m) in witness.mutations.iter().enumerate() {
        let index = u32::try_from(i).map_err(|_| WriteSetError::Ccb("index overflow".into()))?;
        let classify = |s: &Option<EconomicLeafState>| -> Result<(), WriteSetError> {
            match s {
                None
                | Some(EconomicLeafState::Balance(_))
                | Some(EconomicLeafState::ConsumedSource(_)) => Ok(()),
                Some(EconomicLeafState::VaultReserve(_)) if reserves_legal => Ok(()),
                Some(_) => Err(WriteSetError::UnexpectedLeafClass),
            }
        };
        classify(&m.pre_state)?;
        classify(&m.post_state)?;
        match (&m.pre_state, &m.post_state) {
            (pre, Some(EconomicLeafState::VaultReserve(post))) => {
                let pre = match pre {
                    Some(EconomicLeafState::VaultReserve(p)) => Some(p.clone()),
                    None => None,
                    _ => {
                        return Err(WriteSetError::WrongWriteSet {
                            detail: "a reserve mutation cannot change leaf class",
                        })
                    }
                };
                reserves.push(ObservedReserve {
                    pre,
                    post: post.clone(),
                    mutation_index: index,
                });
            }
            (Some(EconomicLeafState::VaultReserve(_)), _) => {
                return Err(WriteSetError::WrongWriteSet {
                    detail: "a reserve leaf is never removed — a closed vault's terminal \
                             zero stays present",
                })
            }
            (pre, Some(EconomicLeafState::Balance(post))) => {
                let pre_amount = match pre {
                    Some(EconomicLeafState::Balance(b)) => b.amount,
                    None => 0,
                    _ => return Err(WriteSetError::UnexpectedLeafClass),
                };
                balances.push(ObservedBalance {
                    policy_commit: post.policy_commit,
                    pre_amount,
                    post_amount: post.amount,
                    mutation_index: index,
                });
            }
            (Some(EconomicLeafState::Balance(pre)), None) => balances.push(ObservedBalance {
                policy_commit: pre.policy_commit,
                pre_amount: pre.amount,
                post_amount: 0,
                mutation_index: index,
            }),
            (None, Some(EconomicLeafState::ConsumedSource(c))) => {
                consumed.push((index, c.clone()));
            }
            (Some(EconomicLeafState::ConsumedSource(_)), _) => {
                return Err(WriteSetError::WrongWriteSet {
                    detail: "a consumed-source leaf is write-once; it has no pre-state here",
                })
            }
            _ => {
                return Err(WriteSetError::WrongWriteSet {
                    detail: "mutation shape outside this operation's write set",
                })
            }
        }
    }

    match semantic {
        SemanticWriteSet::DebitOnly {
            policy_commit,
            amount,
        } => {
            if !consumed.is_empty() {
                return Err(WriteSetError::WrongWriteSet {
                    detail: "a pure debit consumes no source",
                });
            }
            if balances.len() != 1 || witness.mutations.len() != 1 {
                return Err(WriteSetError::WrongWriteSet {
                    detail: "a pure debit is exactly one balance mutation",
                });
            }
            let b = &balances[0];
            if b.policy_commit != policy_commit {
                return Err(WriteSetError::WrongWriteSet {
                    detail: "debit touches a different asset than the operation names",
                });
            }
            if b.pre_amount.checked_sub(b.post_amount) != Some(amount) || amount == 0 {
                return Err(WriteSetError::WrongWriteSet {
                    detail: "debit delta is not exactly the operation amount",
                });
            }
            if !witness.credit_sources.is_empty() {
                return Err(WriteSetError::WrongWriteSet {
                    detail: "a pure debit has no credit to fund",
                });
            }
            Ok(())
        }
        SemanticWriteSet::Credit {
            policy_commit,
            amount,
            facts_required,
        } => {
            if balances.len() != 1 {
                return Err(WriteSetError::WrongWriteSet {
                    detail: "exactly one balance credit",
                });
            }
            let b = &balances[0];
            if b.policy_commit != policy_commit {
                return Err(WriteSetError::WrongWriteSet {
                    detail: "credit lands on a different asset than the operation derives",
                });
            }
            if b.post_amount.checked_sub(b.pre_amount) != Some(amount) {
                return Err(WriteSetError::WrongWriteSet {
                    detail: "credit delta is not exactly the derived amount",
                });
            }
            if witness.credit_sources.len() != 1 {
                return Err(WriteSetError::WrongWriteSet {
                    detail: "exactly one credit source",
                });
            }
            let source = &witness.credit_sources[0];
            match (facts_required, source, operation) {
                (
                    FactsKind::FaucetTicket,
                    CreditSource::ValidatedFaucetDistribution(d),
                    Operation::FaucetClaim {
                        faucet_id,
                        ticket_index,
                    },
                ) => {
                    if !consumed.is_empty() || witness.mutations.len() != 1 {
                        return Err(WriteSetError::WrongWriteSet {
                            detail: "a faucet claim is exactly one balance credit — its \
                                     non-reuse is the envelope's position+digest binding, not a \
                                     consumed-source leaf",
                        });
                    }
                    if d.credit_mutation_index != b.mutation_index {
                        return Err(WriteSetError::WrongWriteSet {
                            detail: "faucet source does not fund the balance credit",
                        });
                    }
                    if d.faucet_id != *faucet_id || d.ticket_index != *ticket_index {
                        return Err(WriteSetError::WrongWriteSet {
                            detail: "faucet source names a different ticket than the operation",
                        });
                    }
                    Ok(())
                }
                (FactsKind::PeerDebit, CreditSource::ValidatedPeerDebit(d), _) => {
                    if consumed.len() != 1 || witness.mutations.len() != 2 {
                        return Err(WriteSetError::WrongWriteSet {
                            detail: "a peer-funded credit is exactly one balance credit plus \
                                     one consumed-source insertion",
                        });
                    }
                    if d.credit_mutation_index != b.mutation_index {
                        return Err(WriteSetError::WrongWriteSet {
                            detail: "peer-debit source does not fund the balance credit",
                        });
                    }
                    let (_, c) = &consumed[0];
                    let expected_source_id = validated_peer_debit_source_id(
                        &d.peer_genesis,
                        &d.peer_devid,
                        d.peer_economic_position,
                        d.peer_debit_mutation_index,
                    );
                    if c.source_id != expected_source_id {
                        return Err(WriteSetError::WrongWriteSet {
                            detail: "consumed-source leaf does not name the peer debit the \
                                     descriptor funds from",
                        });
                    }
                    if c.consumer_economic_operation_id != witness.economic_operation_id {
                        return Err(WriteSetError::WrongWriteSet {
                            detail: "consumed-source leaf names a different consuming operation",
                        });
                    }
                    Ok(())
                }
                _ => Err(WriteSetError::WrongWriteSet {
                    detail: "credit source kind does not match the operation",
                }),
            }
        }
        SemanticWriteSet::DlvFund {
            vault_id,
            leg_a,
            leg_b,
        } => {
            if !consumed.is_empty() {
                return Err(WriteSetError::WrongWriteSet {
                    detail: "a funded create consumes no external source",
                });
            }
            if witness.mutations.len() != 4 || balances.len() != 2 || reserves.len() != 2 {
                return Err(WriteSetError::WrongWriteSet {
                    detail: "a funded create is exactly two balance debits plus two reserve \
                             births",
                });
            }
            if witness.credit_sources.len() != 2 {
                return Err(WriteSetError::WrongWriteSet {
                    detail: "a funded create has exactly two same-transition-move sources",
                });
            }
            for (policy_commit, amount) in [leg_a, leg_b] {
                let debit = expect_one_balance(&balances, policy_commit)?;
                if debit.pre_amount.checked_sub(debit.post_amount) != Some(amount) {
                    return Err(WriteSetError::WrongWriteSet {
                        detail: "funding debit is not exactly the signed leg amount",
                    });
                }
                let reserve = expect_one_reserve(&reserves, policy_commit)?;
                if reserve.pre.is_some() {
                    return Err(WriteSetError::WrongWriteSet {
                        detail: "a vault is born from ABSENT reserve leaves",
                    });
                }
                if reserve.post.vault_id != vault_id
                    || reserve.post.amount != amount
                    || reserve.post.vault_sequence != 0
                {
                    return Err(WriteSetError::WrongWriteSet {
                        detail: "reserve birth does not equal the signed leg at generation 0",
                    });
                }
                expect_same_move(
                    &witness.credit_sources,
                    reserve.mutation_index,
                    debit.mutation_index,
                )?;
            }
            Ok(())
        }
        SemanticWriteSet::DlvWithdraw {
            vault_id,
            leg_a,
            leg_b,
            parent_sequence,
            new_sequence,
        } => {
            if !consumed.is_empty() {
                return Err(WriteSetError::WrongWriteSet {
                    detail: "a close consumes no external source",
                });
            }
            if witness.mutations.len() != 4 || balances.len() != 2 || reserves.len() != 2 {
                return Err(WriteSetError::WrongWriteSet {
                    detail: "a close is exactly two reserve drains plus two balance credits",
                });
            }
            if witness.credit_sources.len() != 2 {
                return Err(WriteSetError::WrongWriteSet {
                    detail: "a close has exactly two same-transition-move sources",
                });
            }
            for (policy_commit, amount) in [leg_a, leg_b] {
                let reserve = expect_one_reserve(&reserves, policy_commit)?;
                let pre = reserve.pre.as_ref().ok_or(WriteSetError::WrongWriteSet {
                    detail: "a close drains an EXISTING reserve leaf",
                })?;
                if pre.vault_id != vault_id
                    || pre.amount != amount
                    || pre.vault_sequence != parent_sequence
                {
                    return Err(WriteSetError::WrongWriteSet {
                        detail: "close must drain the exact reserve amount at the exact \
                                 parent generation",
                    });
                }
                if reserve.post.vault_id != vault_id
                    || reserve.post.amount != 0
                    || reserve.post.vault_sequence != new_sequence
                {
                    return Err(WriteSetError::WrongWriteSet {
                        detail: "close must leave the terminal zero reserve at parent + 1",
                    });
                }
                let credit = expect_one_balance(&balances, policy_commit)?;
                if credit.post_amount.checked_sub(credit.pre_amount) != Some(amount) {
                    return Err(WriteSetError::WrongWriteSet {
                        detail: "close credit is not exactly the drained reserve amount",
                    });
                }
                expect_same_move(
                    &witness.credit_sources,
                    credit.mutation_index,
                    reserve.mutation_index,
                )?;
            }
            Ok(())
        }
    }
}

/// Exactly one observed balance mutation for this asset.
fn expect_one_balance(
    balances: &[ObservedBalance],
    policy_commit: [u8; 32],
) -> Result<&ObservedBalance, WriteSetError> {
    let mut found = None;
    for b in balances {
        if b.policy_commit == policy_commit {
            if found.is_some() {
                return Err(WriteSetError::WrongWriteSet {
                    detail: "duplicate balance mutation for one asset",
                });
            }
            found = Some(b);
        }
    }
    found.ok_or(WriteSetError::WrongWriteSet {
        detail: "missing the balance mutation for a signed leg",
    })
}

/// Exactly one observed reserve mutation for this asset.
fn expect_one_reserve(
    reserves: &[ObservedReserve],
    policy_commit: [u8; 32],
) -> Result<&ObservedReserve, WriteSetError> {
    let mut found = None;
    for r in reserves {
        if r.post.policy_commit == policy_commit {
            if found.is_some() {
                return Err(WriteSetError::WrongWriteSet {
                    detail: "duplicate reserve mutation for one asset",
                });
            }
            found = Some(r);
        }
    }
    found.ok_or(WriteSetError::WrongWriteSet {
        detail: "missing the reserve mutation for a signed leg",
    })
}

/// Exactly one `SameTransitionMove` source pairing this credit with this
/// debit — the descriptor indices are checked, and the asset/amount equality
/// between the two legs is proved independently by the provenance arm.
fn expect_same_move(
    sources: &[CreditSource],
    credit_mutation_index: u32,
    debit_mutation_index: u32,
) -> Result<(), WriteSetError> {
    let mut found = false;
    for s in sources {
        if let CreditSource::SameTransitionMove(m) = s {
            if m.credit_mutation_index == credit_mutation_index {
                if found || m.debit_mutation_index != debit_mutation_index {
                    return Err(WriteSetError::WrongWriteSet {
                        detail: "same-transition-move source does not pair the credit with \
                                 its own leg's debit",
                    });
                }
                found = true;
            }
        } else {
            return Err(WriteSetError::WrongWriteSet {
                detail: "a DLV pair operation is funded only by same-transition moves",
            });
        }
    }
    if !found {
        return Err(WriteSetError::WrongWriteSet {
            detail: "no source funds this credit",
        });
    }
    Ok(())
}
