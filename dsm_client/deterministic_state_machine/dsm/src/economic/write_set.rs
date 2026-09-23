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
    CreditSource, CreditSourceGenesisRelease, CreditSourceNativeReserveRelease,
    CreditSourceValidatedPeerDebit,
};
use crate::economic::mutation::EconomicLeafMutation;
use crate::economic::provenance::validated_peer_debit_source_id;
use crate::economic::state::{EconomicBalanceState, EconomicConsumedSourceState, EconomicLeafState};
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
    /// The operation touches online value with no defined foreign-verifiable
    /// source predicate.
    UnsupportedValueTransition,
    /// The operation writes no economic leaf; there is nothing to witness,
    /// and a witness claiming otherwise is refused.
    NoEconomicWriteSet,
    /// A SoFi v8 operation. Its write set is real and closed, and it is
    /// deliberately not derived here: the position is earned through
    /// `sofi::lineage::advance_resolved` against the route's resolution, not
    /// through `advance_validated`. Refused BY NAME rather than by falling
    /// into the catch-all, so the reason is the rule and not an accident of
    /// which arms happen to exist.
    ///
    /// THE FULFILLMENT ONLY. A setup and a vault creation have no route and
    /// nothing to resolve: each has its own write set, right here.
    SofiWriteSetBelongsToTheResolvedPath,
    /// The operation's classification is contradicted by its own witness: it
    /// claims to write no economic leaf and the witness writes one.
    ///
    /// Distinct from every other arm here, which compare a witness against a
    /// write set. This one catches the case where the write set consulted was
    /// the wrong one — or where there is none to consult.
    Tripwire(crate::economic::classifier::EconomicTripwire),
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
            Self::UnsupportedValueTransition => write!(
                f,
                "operation touches online economic value with no defined foreign-verifiable \
                 source predicate"
            ),
            Self::NoEconomicWriteSet => {
                write!(f, "operation writes no economic leaf; nothing to witness")
            }
            Self::SofiWriteSetBelongsToTheResolvedPath => write!(
                f,
                "a SoFi fulfillment's write set is fixed by its own preimage and its \
                 position is earned by the route's resolution: it is advanced through \
                 sofi::lineage::advance_resolved, never through advance_validated"
            ),
            Self::Tripwire(t) => write!(f, "{t}"),
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
    /// A faucet claim's evidence address: the exact bytes of the reserve
    /// release that won its generation. The reserve and generation are read
    /// from the operation, never supplied twice.
    NativeReserveRelease { release_evidence_addr: [u8; 32] },
    /// A recipient credit funded by the sender's validated debit.
    PeerDebit {
        peer_genesis: [u8; 32],
        peer_devid: [u8; 32],
        peer_economic_position: u64,
        peer_debit_mutation_index: u32,
        acceptance_evidence_addr: [u8; 32],
    },
    /// The genesis release of a token's whole supply at its creation
    /// (`0x005F`). Nothing is supplied: the asset and the amount are the
    /// accepted `CreateToken`'s own, and the policy is fetched by its commit.
    GenesisRelease,
}

/// The producer's authenticated pre-state, decoded. `balances` is keyed by
/// policy commit — absence means the leaf is absent. The tree remains the
/// authority: a pre-state that disagrees with it produces a witness that fails
/// Merkle verification.
pub struct EconomicPreState<'a> {
    pub balances: &'a BTreeMap<[u8; 32], u64>,
    /// The position the operation being built LANDS AT — the successor of the
    /// admitted predecessor this pre-state came from. It travels with the
    /// pre-state because it is the same fact: a pre-state at `p` can only be
    /// the pre-state of the transition at `p + 1`.
    pub economic_position: u64,
}

impl<'a> EconomicPreState<'a> {
    pub fn new(balances: &'a BTreeMap<[u8; 32], u64>, economic_position: u64) -> Self {
        Self {
            balances,
            economic_position,
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

/// How a planned credit is funded.
enum PlannedSource {
    External(CreditSourceFacts),
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
    /// `SofiSetup` (P15-6): exactly ONE relationship leaf, inserted FROM
    /// ZERO, and no value movement at all.
    ///
    /// Insert-only is the rule, not a detail. `h⁰` is derived from the setup
    /// id, so a setup that OVERWROTE an existing relationship would reset a
    /// chain that has already advanced — every `hʲ` after it would be
    /// unreachable, and the leaf's whole job is to be that chain.
    SofiSetup { vault_id: [u8; 32], leaf: [u8; 32] },
    /// `SofiVaultCreate` (P15-12): two balance debits and the creation record
    /// inserted FROM ZERO, as ONE write set.
    ///
    /// Not "two debits and separately a record": the funding leaving the
    /// owner's balances and the record of what it funded are the same
    /// economic act, and splitting them would allow either half alone.
    /// Canonical pair (`a < b`), both amounts non-zero.
    SofiVaultCreate {
        vault_id: [u8; 32],
        leg_a: ([u8; 32], u64),
        leg_b: ([u8; 32], u64),
        creation: crate::sofi::wire::VaultCreation,
    },
    /// `CreateToken` (SoFi §51): the ERA fee debit and the creator's credit of
    /// the new token's whole genesis supply, as ONE write set. The credit's
    /// source is the genesis release (`0x005F`), whose arm checks the amount
    /// against the genesis supply the token's policy commits. Fee and supply
    /// are different assets: neither funds the other.
    CreateTokenRelease {
        /// `(ERA policy_commit, fee_amount)`.
        fee: ([u8; 32], u64),
        /// `(the new token's policy_commit, its whole genesis supply)`.
        release: ([u8; 32], u64),
    },
}

/// One asset leg of a vault pair: `(policy_commit, amount)`.
type AssetLeg = ([u8; 32], u64);

/// Validate and project the two signed legs of a vault pair.
fn pair_legs(
    vault_id: &[u8],
    leg_a: AssetLeg,
    leg_b: AssetLeg,
) -> Result<([u8; 32], AssetLeg, AssetLeg), WriteSetError> {
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
    NativeReserveRelease,
    PeerDebit,
    GenesisRelease,
}

/// The one table: what an operation does to `R_econ`, or why it cannot be
/// witnessed. Role for `Transfer` derives from the authenticated local DevID.
fn semantic_write_set(
    operation: &Operation,
    local_genesis: &[u8; 32],
    local_devid: &[u8; 32],
    economic_position: u64,
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
        // Creation releases the token's whole genesis supply to its creator
        // (`ReleaseRule::AllAtCreation`, SoFi §51) in the same write set as
        // the ERA fee. A token with no supply is not a token (§50).
        Operation::CreateToken {
            initial_supply,
            fee_amount,
            policy_commit,
            ..
        } => {
            if initial_supply.value() == 0 {
                return Err(WriteSetError::NoEconomicWriteSet);
            }
            Ok(SemanticWriteSet::CreateTokenRelease {
                fee: (
                    crate::core::token::token_state_manager::era_policy_commit(),
                    *fee_amount,
                ),
                release: (*policy_commit, initial_supply.value()),
            })
        }
        // The beta faucet: one balance credit of exactly the beta payout of
        // builtin ERA, funded by one release of the network's native reserve.
        // The operation carries no amount; the claim policy fixes it, and the
        // provenance arm requires the release to carry exactly that.
        Operation::FaucetClaim { .. } => Ok(SemanticWriteSet::Credit {
            policy_commit: crate::core::token::token_state_manager::era_policy_commit(),
            amount: crate::economic::native_reserve::ERA_FAUCET_PAYOUT,
            facts_required: FactsKind::NativeReserveRelease,
        }),
        // ISSUANCE: one balance credit of exactly the operation's amount,
        // funded by the 0x0023 arm resolving a 0x0029 authorization. The
        // amount and asset come from the operation; the write set states the
        // effect, and the arm states who was entitled to cause it.
        // SOFI v8 IS REFUSED HERE BY NAME — and the three do not share a
        // reason, which is why they no longer share an arm.
        //
        // A FULFILLMENT belongs to the resolved path: its write set is fixed
        // by its own preimage and its position is earned by the route's
        // resolution, so `advance_validated` is the wrong constructor.
        Operation::SofiFulfill { .. } => Err(WriteSetError::SofiWriteSetBelongsToTheResolvedPath),
        // A SETUP inserts exactly one relationship leaf and moves no value
        // (P15-6). `h⁰` is derived here from the setup id rather than read
        // off the operation, so a setup cannot name a starting leaf.
        Operation::SofiSetup { setup_body, .. } => {
            let body = crate::sofi::wire::SofiSetupBody::decode(setup_body).map_err(|_| {
                WriteSetError::MalformedVaultOperation {
                    detail: "a setup body that is not canonical has no write set",
                }
            })?;
            // BOTH coordinates, not just the device. The leaf's KEY is
            // derived from the authenticated `(G, DevID)` while `h⁰` is
            // derived from the BODY's — so a body naming a foreign genesis
            // would place a leaf computed from that foreign identity at this
            // device's key, and the two would disagree about whose
            // relationship it is. Binding both is what makes them one claim.
            if body.genesis() != local_genesis || body.device_id() != local_devid {
                return Err(WriteSetError::MalformedVaultOperation {
                    detail: "a setup writes into its own identity's tree",
                });
            }
            let setup_id = crate::sofi::derive::setup_id(
                body.genesis(),
                body.device_id(),
                body.position(),
                body.vault_id(),
            );
            Ok(SemanticWriteSet::SofiSetup {
                vault_id: *body.vault_id(),
                leaf: crate::sofi::derive::relationship_leaf_genesis(&setup_id),
            })
        }
        // A CREATION debits the funding and inserts the record, as one write
        // set (P15-12). The funding assets are the operation's signed
        // execution coordinates; `genesis_accepted` is what holds them to the
        // authenticated market policy.
        Operation::SofiVaultCreate {
            genesis_preimage,
            creation,
            market_policy_preimage,
            funding_a_policy_commit,
            funding_b_policy_commit,
            ..
        } => {
            let preimage = crate::sofi::wire::VaultGenesisPreimage::decode(genesis_preimage)
                .map_err(|_| WriteSetError::MalformedVaultOperation {
                    detail: "a genesis preimage that is not canonical has no write set",
                })?;
            let record = crate::sofi::wire::VaultCreation::decode(creation).map_err(|_| {
                WriteSetError::MalformedVaultOperation {
                    detail: "a creation record that is not canonical has no write set",
                }
            })?;
            // Same binding for the creation: `vault_id` derives from the
            // preimage's owner coordinates, and the debits land at keys
            // derived from the authenticated ones.
            if preimage.owner_genesis != *local_genesis || preimage.owner_device_id != *local_devid
            {
                return Err(WriteSetError::MalformedVaultOperation {
                    detail: "a creation debits its own owner's balances",
                });
            }
            // `v` is the owner's derivation, and the record names the same
            // vault. Neither is taken on the operation's word.
            let vault_id = preimage.vault_id();
            if record.vault_id != vault_id {
                return Err(WriteSetError::MalformedVaultOperation {
                    detail: "the creation record names another vault than the preimage derives",
                });
            }
            // The funding IS the genesis reserves: a creation that debited
            // less than it funded would mint reserves out of nothing.
            if record.amount_a != preimage.state.reserve_a
                || record.amount_b != preimage.state.reserve_b
            {
                return Err(WriteSetError::MalformedVaultOperation {
                    detail: "the funded amounts are not the genesis reserves",
                });
            }
            // THE PREIMAGE AGREES WITH ITSELF. `vault_id` derives from the
            // OUTER owner coordinates, and the close path re-derives it from
            // the INNER ones (`sofi::validation`). Two spellings of the same
            // fact that nothing required to agree is a fork in who owns the
            // vault, so they are held equal here rather than at one of the
            // two readers.
            if preimage.state.owner_genesis != preimage.owner_genesis
                || preimage.state.owner_device_id != preimage.owner_device_id
                || preimage.state.create_position != preimage.create_position
            {
                return Err(WriteSetError::MalformedVaultOperation {
                    detail: "the genesis state names different owner coordinates than the \
                             preimage it sits in",
                });
            }
            // `p_create` IS THE POSITION THIS OPERATION LANDS AT. It is not a
            // coordinate the caller may choose: `vault_id` derives from it, so
            // a creation free to name any position could mint a second vault
            // id from one transition, and the close path would then derive an
            // owner for a vault the lineage never created at that position.
            if preimage.create_position != economic_position {
                return Err(WriteSetError::MalformedVaultOperation {
                    detail: "the creation names a position other than the one it lands at",
                });
            }
            // `R_0` IS DERIVED, NEVER ACCEPTED. The creation record states a
            // genesis root; recomputing it from the canonical state is the
            // only thing that makes it a fact rather than the caller's
            // assertion, and every input is already in hand.
            let derived_root = crate::sofi::lineage::genesis_root(&vault_id, &preimage.state)
                .map_err(|_| WriteSetError::MalformedVaultOperation {
                    detail: "a genesis state that does not encode has no root",
                })?;
            if record.genesis_root != derived_root {
                return Err(WriteSetError::MalformedVaultOperation {
                    detail: "the creation record states a genesis root the state does not derive",
                });
            }
            // THE POLICY BYTES ARE THE ONES THE STATE NAMED. Re-address them
            // under the market-policy namespace and require the address the
            // vault state commits. This is checked BEFORE anything is read out
            // of them: bytes that do not authenticate to what was asked for
            // establish nothing, so they are never decoded on their own word.
            let derived_addr = crate::ccb::decode::policy_object_address(
                crate::ccb::class::MARKET_POLICY,
                market_policy_preimage,
            )
            .ok_or(WriteSetError::MalformedVaultOperation {
                detail: "the market policy class has no addressing rule",
            })?;
            if derived_addr != preimage.state.market_policy {
                return Err(WriteSetError::MalformedVaultOperation {
                    detail: "the carried market policy is not the one the genesis state commits",
                });
            }
            // Strict decode. 72 fixed-width bytes, a pinned envelope, a pinned
            // beta family and version, a strictly ordered pair and no trailing
            // byte — so an accepted policy has exactly one encoding and the
            // address above identifies it uniquely.
            let market =
                crate::ccb::decode::decode_market_policy(market_policy_preimage).map_err(|_| {
                    WriteSetError::MalformedVaultOperation {
                        detail: "a market policy that is not canonical authorizes no pair",
                    }
                })?;
            // THE FUNDING IS THE AUTHORIZED PAIR. A SEPARATE binding from the
            // address: that one proves these are the named policy's bytes,
            // this one proves the assets actually debited are the two that
            // policy authorizes. Without it a creation may debit X and Y while
            // declaring a market in A and B — and a later close credits the
            // owner A and B, which it never funded.
            if *funding_a_policy_commit != *market.token_a()
                || *funding_b_policy_commit != *market.token_b()
            {
                return Err(WriteSetError::MalformedVaultOperation {
                    detail: "the funded assets are not the pair the market policy authorizes",
                });
            }
            let (vault_id, leg_a, leg_b) = pair_legs(
                &vault_id,
                (*funding_a_policy_commit, record.amount_a),
                (*funding_b_policy_commit, record.amount_b),
            )?;
            Ok(SemanticWriteSet::SofiVaultCreate {
                vault_id,
                leg_a,
                leg_b,
                creation: record,
            })
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
    let economic_position = pre_state.economic_position;
    let semantic = semantic_write_set(operation, genesis, device_id, economic_position)?;

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
                    CreditSourceFacts::NativeReserveRelease { .. },
                    FactsKind::NativeReserveRelease
                ) | (CreditSourceFacts::PeerDebit { .. }, FactsKind::PeerDebit)
                    | (CreditSourceFacts::GenesisRelease, FactsKind::GenesisRelease)
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
        // P15-6: one relationship insert, from zero, and nothing else.
        SemanticWriteSet::SofiSetup { vault_id, leaf } => {
            if *facts != CreditSourceFacts::None {
                return Err(WriteSetError::FactsDoNotMatchOperation);
            }
            let state =
                EconomicLeafState::Relationship(crate::sofi::wire::TraderRelationshipLeaf {
                    vault_id,
                    leaf,
                });
            let key = state.leaf_key(genesis, device_id);
            // FROM ZERO. `h⁰` is a function of the setup id, so overwriting an
            // existing relationship would reset a chain that has already
            // advanced and orphan every `hʲ` after it. A second setup for the
            // same vault is refused, not applied.
            if tree.get(&key).is_some() {
                return Err(WriteSetError::WrongWriteSet {
                    detail: "a relationship leaf for this vault already exists",
                });
            }
            planned.push(PlannedLeaf {
                key,
                pre: None,
                post: Some(state),
                source: None,
            });
        }
        // P15-12: two debits and the record, as one write set.
        SemanticWriteSet::SofiVaultCreate {
            vault_id,
            leg_a,
            leg_b,
            creation,
        } => {
            if *facts != CreditSourceFacts::None {
                return Err(WriteSetError::FactsDoNotMatchOperation);
            }
            for (policy_commit, amount) in [leg_a, leg_b] {
                planned.push(plan_balance_debit(
                    genesis,
                    device_id,
                    pre_balances,
                    policy_commit,
                    amount,
                )?);
            }
            let state = EconomicLeafState::VaultCreation(creation);
            let key = state.leaf_key(genesis, device_id);
            // Insert-only, and that is what makes the record's presence under
            // a validated root a proof the vault was created on this lineage
            // (P15-12). A vault id is created once.
            if tree.get(&key).is_some() {
                return Err(WriteSetError::WrongWriteSet {
                    detail: "a creation record for this vault already exists",
                });
            }
            let _ = vault_id;
            planned.push(PlannedLeaf {
                key,
                pre: None,
                post: Some(state),
                source: None,
            });
        }
    }

    // Key order, then progressive proof capture: mutation i's siblings come
    // from the tree with mutations 0..i already applied.
    planned.sort_by_key(|l| l.key);
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
            let PlannedSource::External(facts) = planned_source;
            let source = match (facts, operation) {
                // The descriptor carries the credit index and nothing else: the
                // asset and the amount are the operation's own, so there is no
                // second place for one fact to disagree with itself.
                (CreditSourceFacts::GenesisRelease, Operation::CreateToken { .. }) => {
                    CreditSource::GenesisRelease(CreditSourceGenesisRelease {
                        credit_mutation_index,
                    })
                }
                (
                    CreditSourceFacts::NativeReserveRelease {
                        release_evidence_addr,
                    },
                    Operation::FaucetClaim {
                        reserve_id,
                        generation,
                    },
                ) => CreditSource::NativeReserveRelease(CreditSourceNativeReserveRelease {
                    credit_mutation_index,
                    reserve_id: *reserve_id,
                    generation: *generation,
                    release_evidence_addr,
                }),
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
    economic_position: u64,
) -> Result<(), WriteSetError> {
    // THE TRIPWIRE, ON THE REAL PATH AND BEFORE ANYTHING ELSE.
    //
    // It asks a different question from every check below: not "does this
    // witness match the operation's write set", but "does an operation that
    // claims to write NOTHING carry a witness that writes leaves". That is the
    // one failure a write-set comparison cannot catch, because a
    // misclassified operation may have no write set to compare against — it
    // would be refused as "writes no economic leaf" while its witness sits
    // there full of them, and the diagnosis would point at the wrong thing.
    //
    // It runs first so the contradiction is the reported reason, and it reads
    // the witness rather than the classification it is checking.
    crate::economic::classifier::check_tripwire(
        crate::economic::classifier::classify(operation),
        crate::economic::classifier::observed_from_witness(witness),
    )
    .map_err(WriteSetError::Tripwire)?;

    let semantic = semantic_write_set(operation, genesis, device_id, economic_position)?;

    // Classify every mutation. The legal leaf classes are VARIANT-DRIVEN, and
    // EACH SOFI LEAF IS LEGAL FOR EXACTLY ONE OPERATION. The closure below
    // ends in a catch-all, so a new class is refused outright until an arm
    // authorizes it for the one write set that produces it. A setup carrying
    // a creation record, or a creation carrying a relationship leaf, is
    // refused here by class.
    let relationships_legal = matches!(semantic, SemanticWriteSet::SofiSetup { .. });
    let creations_legal = matches!(semantic, SemanticWriteSet::SofiVaultCreate { .. });
    let mut balances: Vec<ObservedBalance> = Vec::new();
    let mut consumed: Vec<(u32, EconomicConsumedSourceState)> = Vec::new();
    let mut relationships: Vec<(u32, crate::sofi::wire::TraderRelationshipLeaf)> = Vec::new();
    let mut creations: Vec<(u32, crate::sofi::wire::VaultCreation)> = Vec::new();
    for (i, m) in witness.mutations.iter().enumerate() {
        let index = u32::try_from(i).map_err(|_| WriteSetError::Ccb("index overflow".into()))?;
        let classify = |s: &Option<EconomicLeafState>| -> Result<(), WriteSetError> {
            match s {
                None
                | Some(EconomicLeafState::Balance(_))
                | Some(EconomicLeafState::ConsumedSource(_)) => Ok(()),
                Some(EconomicLeafState::Relationship(_)) if relationships_legal => Ok(()),
                Some(EconomicLeafState::VaultCreation(_)) if creations_legal => Ok(()),
                Some(_) => Err(WriteSetError::UnexpectedLeafClass),
            }
        };
        classify(&m.pre_state)?;
        classify(&m.post_state)?;
        match (&m.pre_state, &m.post_state) {
            // Both SoFi leaves are INSERT-ONLY, so a pre-state is not a
            // different shape of the same write — it is a different write.
            (None, Some(EconomicLeafState::Relationship(r))) => {
                relationships.push((index, *r));
            }
            (Some(EconomicLeafState::Relationship(_)), _) => {
                return Err(WriteSetError::WrongWriteSet {
                    detail: "a setup inserts a relationship leaf from zero; it never replaces one",
                })
            }
            (None, Some(EconomicLeafState::VaultCreation(c))) => {
                creations.push((index, *c));
            }
            (Some(EconomicLeafState::VaultCreation(_)), _) => {
                return Err(WriteSetError::WrongWriteSet {
                    detail: "a creation record is insert-only; a vault is created once",
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
                    FactsKind::NativeReserveRelease,
                    CreditSource::NativeReserveRelease(d),
                    Operation::FaucetClaim {
                        reserve_id,
                        generation,
                    },
                ) => {
                    if !consumed.is_empty() || witness.mutations.len() != 1 {
                        return Err(WriteSetError::WrongWriteSet {
                            detail: "a faucet claim is exactly one balance credit — its \
                                     non-reuse is the release's position+digest binding, not a \
                                     consumed-source leaf",
                        });
                    }
                    if d.credit_mutation_index != b.mutation_index {
                        return Err(WriteSetError::WrongWriteSet {
                            detail: "reserve release does not fund the balance credit",
                        });
                    }
                    if d.reserve_id != *reserve_id || d.generation != *generation {
                        return Err(WriteSetError::WrongWriteSet {
                            detail: "reserve release names a different generation than the \
                                     operation",
                        });
                    }
                    Ok(())
                }
                (
                    FactsKind::GenesisRelease,
                    CreditSource::GenesisRelease(d),
                    Operation::CreateToken { .. },
                ) => {
                    // THE SHAPE HALF of the issuance rule. Exactly one balance
                    // credit and nothing else: non-reuse is the signed body's
                    // position + operation-digest binding, proven by the
                    // 0x0023 provenance arm — never a consumed-source leaf.
                    // Everything semantic (the policy bytes, the k-of-N
                    // signatures, amount, position, digest) is that arm's job;
                    // this layer pins that the witness claims exactly the
                    // effect the operation derives and that the descriptor
                    // funds exactly the one credit.
                    if !consumed.is_empty() || witness.mutations.len() != 1 {
                        return Err(WriteSetError::WrongWriteSet {
                            detail: "an authorized issuance is exactly one balance credit — \
                                     its non-reuse is the authorization's position+digest \
                                     binding, not a consumed-source leaf",
                        });
                    }
                    if d.credit_mutation_index != b.mutation_index {
                        return Err(WriteSetError::WrongWriteSet {
                            detail: "issuance source does not fund the balance credit",
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
        // P15-6: exactly one relationship insert, and NO value movement.
        SemanticWriteSet::SofiSetup { vault_id, leaf } => {
            if !consumed.is_empty() || !balances.is_empty() {
                return Err(WriteSetError::WrongWriteSet {
                    detail: "a setup is non-economic: it moves no balance and consumes no source",
                });
            }
            if relationships.len() != 1 || witness.mutations.len() != 1 {
                return Err(WriteSetError::WrongWriteSet {
                    detail: "a setup is exactly one relationship insertion",
                });
            }
            let (_, r) = &relationships[0];
            if r.vault_id != vault_id || r.leaf != leaf {
                return Err(WriteSetError::WrongWriteSet {
                    detail: "the relationship leaf is not this setup's vault at h⁰",
                });
            }
            Ok(())
        }
        // P15-12: two debits and the record, and nothing else.
        SemanticWriteSet::SofiVaultCreate {
            vault_id,
            leg_a,
            leg_b,
            creation,
        } => {
            if !consumed.is_empty() {
                return Err(WriteSetError::WrongWriteSet {
                    detail: "a creation consumes no external source: it is funded from the \
                             owner's own balances",
                });
            }
            if balances.len() != 2 || creations.len() != 1 || witness.mutations.len() != 3 {
                return Err(WriteSetError::WrongWriteSet {
                    detail: "a creation is exactly two balance debits and one creation record",
                });
            }
            // BY ASSET, not by position: a witness's mutations are ordered by
            // derived key, which has nothing to do with which leg is which.
            for leg in [leg_a, leg_b] {
                let observed = expect_one_balance(&balances, leg.0)?;
                let expected =
                    observed
                        .pre_amount
                        .checked_sub(leg.1)
                        .ok_or(WriteSetError::WrongWriteSet {
                            detail: "a creation debit underflows the owner's balance",
                        })?;
                if observed.post_amount != expected {
                    return Err(WriteSetError::WrongWriteSet {
                        detail: "a creation debit is not the funded amount",
                    });
                }
            }
            let (_, c) = &creations[0];
            if *c != creation || c.vault_id != vault_id {
                return Err(WriteSetError::WrongWriteSet {
                    detail: "the creation record is not the one the operation carries",
                });
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

#[cfg(test)]
#[allow(clippy::disallowed_methods)] // test asserts; a failure here is the signal
mod sofi_refusal_tests {
    use super::*;
    use crate::economic::classifier::{classify, EconomicEffect};

    fn sofi_operations() -> Vec<Operation> {
        vec![
            Operation::SofiSetup {
                setup_body: vec![0x36, 0x00],
                signature: vec![0xA1; 8],
            },
            Operation::SofiVaultCreate {
                genesis_preimage: vec![0x5A, 0x00],
                creation: vec![0x5B, 0x00],
                market_policy_preimage: vec![0x00, 0x07],
                funding_a_policy_commit: [0x5C; 32],
                funding_b_policy_commit: [0x5D; 32],
                signature: vec![0xA1; 8],
            },
            Operation::SofiFulfill {
                fulfillment_body: vec![0x39, 0x00],
                precommit_id: vec![0x11; 32],
                signature: vec![0xA1; 8],
            },
        ]
    }

    /// ONLY THE FULFILLMENT IS REFUSED NOW. The setup and the vault creation
    /// are ORDINARY transitions (P15-6, P15-12) and this is their home: each
    /// produces a write set here.
    ///
    /// The history is the point. All three once fell into a catch-all that
    /// said "writes no economic leaf" — false of all three, since `classify`
    /// calls them `ClosedWriteSet`. Then all three claimed to "belong to the
    /// resolved path" — true only of the fulfillment. Both refusals were
    /// correct in outcome and wrong in reason, and each wrong reason described
    /// a rule that did not exist. Now two of them have the rule.
    #[test]
    fn a_fulfillment_is_resolved_elsewhere_and_the_other_two_are_written_here() {
        for op in sofi_operations() {
            let name = op.get_operation_type();
            assert_eq!(
                classify(&op),
                EconomicEffect::ClosedWriteSet,
                "{name}: it does move value under a closed write set"
            );
            match (&op, semantic_write_set(&op, &[0x11; 32], &[0x22; 32], 0)) {
                (Operation::SofiFulfill { .. }, Err(e)) => assert_eq!(
                    e,
                    WriteSetError::SofiWriteSetBelongsToTheResolvedPath,
                    "a fulfillment's position is earned by the route's resolution"
                ),
                (Operation::SofiFulfill { .. }, Ok(_)) => {
                    panic!("a fulfillment has no advance_validated write set")
                }
                // The fixtures carry placeholder bodies, so these refuse as
                // MALFORMED — which is itself the point: they are refused for
                // what their bytes are, not for being SoFi.
                (_, Err(e)) => assert!(
                    matches!(e, WriteSetError::MalformedVaultOperation { .. }),
                    "{name}: an ordinary transition is judged by its own bytes, got {e:?}"
                ),
                (_, Ok(_)) => {}
            }
        }
    }

    /// The resolved-path refusal names the fulfillment, so nobody reads it as
    /// a statement about all three.
    #[test]
    fn the_resolved_path_refusal_is_about_the_fulfillment() {
        let resolved = WriteSetError::SofiWriteSetBelongsToTheResolvedPath.to_string();
        assert!(resolved.contains("advance_resolved"));
        assert!(
            resolved.contains("fulfillment"),
            "it must say WHICH operation belongs to that path: {resolved}"
        );
    }
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)] // test asserts; a failure here is the signal
mod vault_create_binding_tests {
    //! THE FIRST BEHAVIOURAL COVERAGE OF `SofiVaultCreate`.
    //!
    //! Before this module the arm had none. The only `SofiVaultCreate` any test
    //! built carried bytes that do not decode, so it exercised classification
    //! and never reached a single binding — which is how several of them came to
    //! be enforced in the SDK producer alone, or not at all.
    //!
    //! Each test removes exactly one thing from a valid creation and names the
    //! rule that refuses it.
    use super::*;
    use crate::ccb::state::{FeePolicy, MarketPolicy, ReleasePolicy};
    use crate::sofi::wire::{VaultCreation, VaultGenesisPreimage, VaultStateLeaf};
    use crate::sofi::wire::VAULT_STATUS_ACTIVE;

    const G: [u8; 32] = [0x11; 32];
    const DEV: [u8; 32] = [0x22; 32];
    const POS: u64 = 7;
    const X: u64 = 1_000;
    const Y: u64 = 2_000;

    fn tok(b: u8) -> [u8; 32] {
        [b; 32]
    }

    fn addr(class: u16, bytes: &[u8]) -> [u8; 32] {
        crate::ccb::decode::policy_object_address(class, bytes).expect("a policy class")
    }

    /// A creation whose every binding holds, plus the pieces a test needs to
    /// break exactly one of them.
    struct Valid {
        state: VaultStateLeaf,
        policy_bytes: Vec<u8>,
        pair: ([u8; 32], [u8; 32]),
    }

    fn valid() -> Valid {
        let (a, b) = (tok(0x40), tok(0x41));
        let market = MarketPolicy::beta_constant_product(a, b).unwrap();
        let policy_bytes = market.encode();
        let fee = FeePolicy::new(30).unwrap();
        let release = ReleasePolicy::beta_owner_local_full_close();
        let state = VaultStateLeaf {
            owner_genesis: G,
            owner_device_id: DEV,
            create_position: POS,
            market_policy: addr(crate::ccb::class::MARKET_POLICY, &policy_bytes),
            fee_policy: addr(crate::ccb::class::FEE_POLICY, &fee.encode()),
            release_policy: addr(crate::ccb::class::RELEASE_POLICY, &release.encode()),
            storage_set_id: tok(0x77),
            generation: 0,
            reserve_a: X,
            reserve_b: Y,
            status: VAULT_STATUS_ACTIVE,
        };
        Valid {
            state,
            policy_bytes,
            pair: (a, b),
        }
    }

    /// Assemble the operation from parts, so a test can perturb any one of them.
    fn op_from(
        v: &Valid,
        state: &VaultStateLeaf,
        policy_bytes: &[u8],
        pair: ([u8; 32], [u8; 32]),
        amounts: (u64, u64),
        root: Option<[u8; 32]>,
        vault_id: Option<[u8; 32]>,
    ) -> Operation {
        let _ = v;
        let preimage = VaultGenesisPreimage {
            owner_genesis: G,
            owner_device_id: DEV,
            create_position: POS,
            state: state.clone(),
        };
        let derived = preimage.vault_id();
        let creation = VaultCreation {
            vault_id: vault_id.unwrap_or(derived),
            genesis_root: root
                .unwrap_or_else(|| crate::sofi::lineage::genesis_root(&derived, state).unwrap()),
            amount_a: amounts.0,
            amount_b: amounts.1,
        };
        Operation::SofiVaultCreate {
            genesis_preimage: preimage.encode().unwrap(),
            creation: creation.encode(),
            market_policy_preimage: policy_bytes.to_vec(),
            funding_a_policy_commit: pair.0,
            funding_b_policy_commit: pair.1,
            signature: vec![0xA1; 8],
        }
    }

    fn good(v: &Valid) -> Operation {
        op_from(v, &v.state, &v.policy_bytes, v.pair, (X, Y), None, None)
    }

    fn refusal(op: &Operation) -> &'static str {
        match semantic_write_set(op, &G, &DEV, POS) {
            Err(WriteSetError::MalformedVaultOperation { detail }) => detail,
            Err(e) => panic!("expected a malformed-creation refusal, got {e:?}"),
            Ok(_) => panic!("expected a refusal, got a write set"),
        }
    }

    #[test]
    fn a_creation_whose_every_binding_holds_produces_the_write_set() {
        let v = valid();
        match semantic_write_set(&good(&v), &G, &DEV, POS) {
            Ok(SemanticWriteSet::SofiVaultCreate {
                leg_a,
                leg_b,
                creation,
                ..
            }) => {
                assert_eq!(leg_a, (v.pair.0, X), "leg a is the market's token a");
                assert_eq!(leg_b, (v.pair.1, Y));
                assert_eq!(creation.amount_a, X);
            }
            Ok(_) => panic!("expected a creation write set, got another variant"),
            Err(e) => panic!("expected a creation write set, got {e:?}"),
        }
    }

    /// M1's subject. The assets debited must be the two the market policy
    /// authorizes — otherwise a creation funds with X and Y while declaring a
    /// market in A and B, and a later close credits the owner A and B.
    #[test]
    fn funding_assets_that_are_not_the_markets_pair_are_refused() {
        let v = valid();
        let impostor = (tok(0x60), tok(0x61));
        assert_ne!(impostor, v.pair);
        let op = op_from(&v, &v.state, &v.policy_bytes, impostor, (X, Y), None, None);
        assert_eq!(
            refusal(&op),
            "the funded assets are not the pair the market policy authorizes"
        );
    }

    /// MA's subject, and a SEPARATE binding from the pair equality. These are
    /// canonical, decodable, correctly ordered policy bytes that authorize
    /// exactly the pair being funded — and they are still refused, because
    /// they are not the policy object this vault's state names.
    #[test]
    fn policy_bytes_that_are_not_the_ones_the_state_names_are_refused() {
        let v = valid();
        let (c, d) = (tok(0x50), tok(0x51));
        let other = MarketPolicy::beta_constant_product(c, d).unwrap().encode();
        assert_ne!(other, v.policy_bytes);
        // Fund the pair THOSE bytes authorize, so only the address binding can
        // refuse this: pair equality holds against the carried policy.
        let op = op_from(&v, &v.state, &other, (c, d), (X, Y), None, None);
        assert_eq!(
            refusal(&op),
            "the carried market policy is not the one the genesis state commits"
        );
    }

    #[test]
    fn a_market_policy_preimage_that_is_not_canonical_is_refused() {
        let v = valid();
        // Each of these re-addresses to something other than what the state
        // commits, so the address binding catches them first; the point is
        // that no malformed policy ever reaches a decode on its own word.
        for bad in [
            Vec::new(),
            v.policy_bytes[..v.policy_bytes.len() - 1].to_vec(),
            [v.policy_bytes.clone(), vec![0x00]].concat(),
        ] {
            let op = op_from(&v, &v.state, &bad, v.pair, (X, Y), None, None);
            assert_eq!(
                refusal(&op),
                "the carried market policy is not the one the genesis state commits",
                "a non-canonical policy preimage must never authorize a pair"
            );
        }
    }

    #[test]
    fn a_state_naming_other_owner_coordinates_than_its_preimage_is_refused() {
        let v = valid();
        for mutate in [0u8, 1, 2] {
            let mut state = v.state.clone();
            match mutate {
                0 => state.owner_genesis = tok(0x99),
                1 => state.owner_device_id = tok(0x99),
                _ => state.create_position = POS + 1,
            }
            let op = op_from(&v, &state, &v.policy_bytes, v.pair, (X, Y), None, None);
            assert_eq!(
                refusal(&op),
                "the genesis state names different owner coordinates than the preimage it sits in"
            );
        }
    }

    #[test]
    fn a_creation_by_another_owner_is_refused() {
        let v = valid();
        let op = good(&v);
        for (g, d) in [(tok(0x99), DEV), (G, tok(0x99))] {
            match semantic_write_set(&op, &g, &d, POS) {
                Err(WriteSetError::MalformedVaultOperation { detail }) => {
                    assert_eq!(detail, "a creation debits its own owner's balances")
                }
                Err(e) => panic!("expected an owner refusal, got {e:?}"),
                Ok(_) => panic!("expected an owner refusal, got a write set"),
            }
        }
    }

    #[test]
    fn a_creation_naming_a_position_it_does_not_land_at_is_refused() {
        let v = valid();
        let op = good(&v);
        match semantic_write_set(&op, &G, &DEV, POS + 1) {
            Err(WriteSetError::MalformedVaultOperation { detail }) => assert_eq!(
                detail,
                "the creation names a position other than the one it lands at"
            ),
            Err(e) => panic!("expected a position refusal, got {e:?}"),
            Ok(_) => panic!("expected a position refusal, got a write set"),
        }
    }

    #[test]
    fn a_creation_stating_a_genesis_root_the_state_does_not_derive_is_refused() {
        let v = valid();
        let op = op_from(
            &v,
            &v.state,
            &v.policy_bytes,
            v.pair,
            (X, Y),
            Some(tok(0xBE)),
            None,
        );
        assert_eq!(
            refusal(&op),
            "the creation record states a genesis root the state does not derive"
        );
    }

    #[test]
    fn a_creation_naming_another_vault_than_the_preimage_derives_is_refused() {
        let v = valid();
        let op = op_from(
            &v,
            &v.state,
            &v.policy_bytes,
            v.pair,
            (X, Y),
            None,
            Some(tok(0xAD)),
        );
        assert_eq!(
            refusal(&op),
            "the creation record names another vault than the preimage derives"
        );
    }

    #[test]
    fn funded_amounts_that_are_not_the_genesis_reserves_are_refused() {
        let v = valid();
        for amounts in [(X + 1, Y), (X, Y + 1)] {
            let op = op_from(&v, &v.state, &v.policy_bytes, v.pair, amounts, None, None);
            assert_eq!(
                refusal(&op),
                "the funded amounts are not the genesis reserves"
            );
        }
    }

    #[test]
    fn a_funding_pair_out_of_canonical_order_is_refused() {
        let v = valid();
        // Swap the market's own pair: pair equality then fails before the
        // ordering check, which is the correct precedence — the authority is
        // the policy, and order is a property of what it authorizes.
        let op = op_from(
            &v,
            &v.state,
            &v.policy_bytes,
            (v.pair.1, v.pair.0),
            (X, Y),
            None,
            None,
        );
        assert_eq!(
            refusal(&op),
            "the funded assets are not the pair the market policy authorizes"
        );
    }
}
