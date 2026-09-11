// SPDX-License-Identifier: Apache-2.0

//! THE COMPOSED DLV HISTORY AS RESERVE PROVENANCE — the SoFi composed-state
//! rule, applied to the reserves a market settlement consumes (2c-D §14,
//! conformance repair).
//!
//! ```text
//! current composed DLV state = latest authenticated owner baseline
//!                            + every later realized market successor, in order
//! ```
//!
//! The owner baseline is economically backed: the owner's admitted
//! vault-reserve leaves at ONE generation `g`. A parent `V_n` at `n == g` must
//! state exactly those reserves. Past the baseline, `V_n` must be exactly the
//! last state of the history the composition walk produced from that baseline,
//! and that history must pass through `g` with the owner's reserves and advance
//! one linked generation at a time. The walk folds a market successor only once
//! the full C2 certification boundary holds, so an uncertified, merely bound or
//! merely published successor never appears in a history.
//!
//! WHAT THIS REMOVES. Reserve provenance accepted ONLY owner leaves at exactly
//! `n`, which only an owner action could produce, so a delegated market could
//! not advance past generation 0 while its LP was away — the property the SoFi
//! model requires. Owner catch-up is later synchronization, never authorization
//! for the next generation.
//!
//! WHAT THIS DOES NOT ESTABLISH. That `V_n` is the CURRENT frontier. That is
//! the binding register's fact: exclusivity at `k(c_n)` decides which
//! continuation of a parent wins, and a trade quoting a consumed parent loses
//! there. This rule answers only whether `V_n`'s reserves are the ones the
//! owner's backing and the certified history say it holds.
//!
//! Pure. The `DlvReserveConsumption` provenance arm and the settle route's
//! pre-bind preflight call this ONE function, so the two cannot disagree.

use crate::ccb::VaultStateV2;
use crate::economic::state::EconomicVaultReserveState;

/// One vault's composed history, baseline first, ending at the state a
/// verifier asked about. Produced by the composition walk, which folds a
/// successor only once it certifies; it carries states, never verdicts, and
/// every commitment is recomputed from them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComposedVaultHistory {
    states: Vec<VaultStateV2>,
}

impl ComposedVaultHistory {
    /// The walk's states, baseline first.
    pub fn from_walk(states: Vec<VaultStateV2>) -> Self {
        Self { states }
    }

    /// Baseline first, target last.
    pub fn states(&self) -> &[VaultStateV2] {
        &self.states
    }
}

/// Why a DLV parent's reserves are not provenanced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ComposedReserveRefusal {
    /// The owner's proof does not carry exactly this vault's two reserve legs
    /// at one generation.
    BaselineLegs { count: usize },
    /// The owner's legs are not the parent's market pair.
    BaselinePair,
    /// The owner's baseline is at a LATER generation than the parent.
    BaselineNewerThanParent { baseline: u64, parent: u64 },
    /// The owner's leaves and the state at the baseline disagree.
    BaselineReservesDisagree { generation: u64 },
    /// A parent past the baseline, with no composed history to carry it.
    HistoryRequired { baseline: u64, parent: u64 },
    /// The composed history does not end at exactly the parent.
    NotTheComposedState,
    /// The composed history does not pass through the owner's baseline.
    HistoryMissesBaseline { baseline: u64 },
    /// Two consecutive composed states are not consecutive generations.
    GenerationGap { after: u64 },
    /// A composed state does not name its predecessor as its parent.
    BrokenLink { at: u64 },
    /// A state has no canonical encoding.
    NotEncodable,
}

impl core::fmt::Display for ComposedReserveRefusal {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BaselineLegs { count } => write!(
                f,
                "the owner's proof carries {count} reserve legs for this vault, not its two at \
                 one generation"
            ),
            Self::BaselinePair => write!(f, "the owner's reserve legs are not the vault's pair"),
            Self::BaselineNewerThanParent { baseline, parent } => write!(
                f,
                "the owner's baseline is at generation {baseline}, past the parent at {parent}"
            ),
            Self::BaselineReservesDisagree { generation } => write!(
                f,
                "the owner's reserve leaves disagree with the vault's state at generation \
                 {generation}"
            ),
            Self::HistoryRequired { baseline, parent } => write!(
                f,
                "the parent at generation {parent} is past the owner's baseline at {baseline}, and \
                 no composed history carries it"
            ),
            Self::NotTheComposedState => write!(
                f,
                "the parent is not the state the certified composition reaches at its commitment"
            ),
            Self::HistoryMissesBaseline { baseline } => write!(
                f,
                "the composed history does not pass through the owner's baseline at generation \
                 {baseline}"
            ),
            Self::GenerationGap { after } => {
                write!(f, "the composed history skips a generation after {after}")
            }
            Self::BrokenLink { at } => write!(
                f,
                "the composed state at generation {at} does not name its predecessor as parent"
            ),
            Self::NotEncodable => write!(f, "a composed state has no canonical encoding"),
        }
    }
}

/// **The reserve-provenance rule for a DLV parent** — the SoFi composed-state
/// model (module docs). `owner_leaves` are the vault-reserve leaves the owner's
/// VALIDATED proof carries; `history` is the composition walk's, required only
/// when the parent is past the owner's baseline.
pub fn check_composed_reserve_provenance(
    owner_leaves: &[EconomicVaultReserveState],
    parent: &VaultStateV2,
    history: Option<&ComposedVaultHistory>,
) -> Result<(), ComposedReserveRefusal> {
    use ComposedReserveRefusal as R;

    // THE OWNER BASELINE: exactly this vault's two legs, at one generation.
    let mut legs: Vec<&EconomicVaultReserveState> = owner_leaves
        .iter()
        .filter(|l| l.vault_id == parent.vault_id)
        .collect();
    if legs.len() != 2 || legs[0].vault_sequence != legs[1].vault_sequence {
        return Err(R::BaselineLegs { count: legs.len() });
    }
    legs.sort_by_key(|l| l.policy_commit);
    if legs[0].policy_commit != *parent.market_policy.token_a()
        || legs[1].policy_commit != *parent.market_policy.token_b()
    {
        return Err(R::BaselinePair);
    }
    let baseline = legs[0].vault_sequence;
    let owner_reserves = (legs[0].amount, legs[1].amount);

    // AT THE BASELINE, the parent states the owner's reserves exactly.
    if baseline > parent.generation {
        return Err(R::BaselineNewerThanParent {
            baseline,
            parent: parent.generation,
        });
    }
    if baseline == parent.generation {
        if (parent.reserve_a, parent.reserve_b) != owner_reserves {
            return Err(R::BaselineReservesDisagree {
                generation: baseline,
            });
        }
        return Ok(());
    }

    // PAST IT, the parent is the composition of that baseline and every
    // certified successor since — nothing else.
    let Some(history) = history else {
        return Err(R::HistoryRequired {
            baseline,
            parent: parent.generation,
        });
    };
    let states = history.states();
    let encoded = |s: &VaultStateV2| s.encode().map_err(|_| R::NotEncodable);
    match states.last() {
        Some(last) if encoded(last)? == encoded(parent)? => {}
        _ => return Err(R::NotTheComposedState),
    }
    let start = states
        .iter()
        .position(|s| s.generation == baseline)
        .ok_or(R::HistoryMissesBaseline { baseline })?;
    if (states[start].reserve_a, states[start].reserve_b) != owner_reserves {
        return Err(R::BaselineReservesDisagree {
            generation: baseline,
        });
    }
    for pair in states[start..].windows(2) {
        let (prev, next) = (&pair[0], &pair[1]);
        if Some(next.generation) != prev.generation.checked_add(1) {
            return Err(R::GenerationGap {
                after: prev.generation,
            });
        }
        let prev_c = crate::ccb::vault_state_commitment(prev).map_err(|_| R::NotEncodable)?;
        if next.parent_state_commitment != prev_c {
            return Err(R::BrokenLink {
                at: next.generation,
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ccb::{EncumbranceSet, FeePolicy, MarketPolicy, ReleasePolicy, StorageSetMembers};
    use crate::dlv::successor_validity::{derive_market_successor, DeriveExpected, MarketTerms};

    const VAULT: [u8; 32] = [0x03; 32];
    const PC_A: [u8; 32] = [0x10; 32];
    const PC_B: [u8; 32] = [0x20; 32];

    fn v0() -> VaultStateV2 {
        VaultStateV2 {
            owner_genesis_id: [1; 32],
            owner_device_id: [2; 32],
            vault_id: VAULT,
            generation: 0,
            reserve_a: 10_000,
            reserve_b: 5_000,
            market_policy: MarketPolicy::beta_constant_product(PC_A, PC_B).expect("ordered pair"),
            release_policy: ReleasePolicy::beta_owner_local_full_close(),
            fee_policy: FeePolicy::new(30).expect("fee below denominator"),
            encumbrances: EncumbranceSet::empty(),
            iteration_budget: None,
            parent_state_commitment: [4; 32],
            owner_authority_transition_digest: [5; 32],
            storage_set: StorageSetMembers::new(&[(b"dsm-node-1".as_slice(), [9; 32])])
                .expect("one member"),
            quorum: 1,
        }
    }

    /// The certified successor the walk would fold: the frozen derivation.
    fn next(v: &VaultStateV2) -> VaultStateV2 {
        let c = crate::ccb::vault_state_commitment(v).expect("commits");
        match derive_market_successor(
            v,
            c,
            &MarketTerms {
                input_policy_commit: PC_A,
                output_policy_commit: PC_B,
                input_amount: 1_000,
                fee_bps: 30,
            },
        ) {
            DeriveExpected::Derived(s) => *s,
            DeriveExpected::Refused(r) => panic!("the fixture trade derives: {r}"),
        }
    }

    fn owner(generation: u64, a: u64, b: u64) -> Vec<EconomicVaultReserveState> {
        vec![
            EconomicVaultReserveState {
                vault_id: VAULT,
                policy_commit: PC_A,
                amount: a,
                vault_sequence: generation,
            },
            EconomicVaultReserveState {
                vault_id: VAULT,
                policy_commit: PC_B,
                amount: b,
                vault_sequence: generation,
            },
        ]
    }

    fn history(states: &[&VaultStateV2]) -> ComposedVaultHistory {
        ComposedVaultHistory::from_walk(states.iter().map(|s| (*s).clone()).collect())
    }

    #[test]
    fn the_baseline_generation_is_provenanced_by_the_owners_leaves_alone() {
        let v = v0();
        assert_eq!(
            check_composed_reserve_provenance(&owner(0, 10_000, 5_000), &v, None),
            Ok(())
        );
        assert_eq!(
            check_composed_reserve_provenance(&owner(0, 10_000, 4_999), &v, None),
            Err(ComposedReserveRefusal::BaselineReservesDisagree { generation: 0 })
        );
    }

    /// (b)+(c): generations 1 and 2, with the owner's backing still at 0 —
    /// the LP absent throughout — are provenanced by the composed history.
    #[test]
    fn later_generations_are_provenanced_by_the_composed_history_with_the_lp_absent() {
        let (a, b) = (v0(), next(&v0()));
        let c = next(&b);
        let leaves = owner(0, 10_000, 5_000);
        assert_eq!(
            check_composed_reserve_provenance(&leaves, &b, Some(&history(&[&a, &b]))),
            Ok(())
        );
        assert_eq!(
            check_composed_reserve_provenance(&leaves, &c, Some(&history(&[&a, &b, &c]))),
            Ok(())
        );
        assert_eq!(
            check_composed_reserve_provenance(&leaves, &c, None),
            Err(ComposedReserveRefusal::HistoryRequired {
                baseline: 0,
                parent: 2
            })
        );
    }

    /// (d): a successor the walk did not certify is absent from the history,
    /// so the next generation cannot be provenanced from it.
    #[test]
    fn a_successor_missing_from_the_certified_history_authorizes_nothing() {
        let (a, b) = (v0(), next(&v0()));
        let c = next(&b);
        assert_eq!(
            check_composed_reserve_provenance(
                &owner(0, 10_000, 5_000),
                &c,
                Some(&history(&[&a, &b]))
            ),
            Err(ComposedReserveRefusal::NotTheComposedState)
        );
    }

    /// (e): a parent at a generation the history does not reach, and an owner
    /// baseline past the parent.
    #[test]
    fn a_wrong_generation_is_refused() {
        let (a, b) = (v0(), next(&v0()));
        let mut later = b.clone();
        later.generation = 5;
        assert_eq!(
            check_composed_reserve_provenance(
                &owner(0, 10_000, 5_000),
                &later,
                Some(&history(&[&a, &b]))
            ),
            Err(ComposedReserveRefusal::NotTheComposedState)
        );
        assert_eq!(
            check_composed_reserve_provenance(&owner(3, 10_000, 5_000), &b, None),
            Err(ComposedReserveRefusal::BaselineNewerThanParent {
                baseline: 3,
                parent: 1
            })
        );
    }

    /// (f): a history that jumps a generation. The first case LINKS
    /// correctly — it names its predecessor as parent — so only the
    /// generation check refuses it; the second skips a state entirely.
    #[test]
    fn a_skipped_generation_is_refused() {
        let (a, b) = (v0(), next(&v0()));
        let mut leaped = b.clone();
        leaped.generation = 2;
        assert_eq!(
            check_composed_reserve_provenance(
                &owner(0, 10_000, 5_000),
                &leaped,
                Some(&history(&[&a, &leaped]))
            ),
            Err(ComposedReserveRefusal::GenerationGap { after: 0 })
        );
        let c = next(&b);
        assert_eq!(
            check_composed_reserve_provenance(
                &owner(0, 10_000, 5_000),
                &c,
                Some(&history(&[&a, &c]))
            ),
            Err(ComposedReserveRefusal::GenerationGap { after: 0 })
        );
    }

    /// (g): a history whose states do not link by `parent_state_commitment`.
    #[test]
    fn a_wrong_parent_state_commitment_is_refused() {
        let (a, b) = (v0(), next(&v0()));
        let mut unlinked = b.clone();
        unlinked.parent_state_commitment = [0xEE; 32];
        assert_eq!(
            check_composed_reserve_provenance(
                &owner(0, 10_000, 5_000),
                &unlinked,
                Some(&history(&[&a, &unlinked]))
            ),
            Err(ComposedReserveRefusal::BrokenLink { at: 1 })
        );
    }

    /// (h): reserves that are not the composed state's, and an owner backing
    /// that is not the baseline's.
    #[test]
    fn altered_reserves_are_refused() {
        let (a, b) = (v0(), next(&v0()));
        let mut richer = b.clone();
        richer.reserve_b += 1;
        assert_eq!(
            check_composed_reserve_provenance(
                &owner(0, 10_000, 5_000),
                &richer,
                Some(&history(&[&a, &b]))
            ),
            Err(ComposedReserveRefusal::NotTheComposedState)
        );
        assert_eq!(
            check_composed_reserve_provenance(
                &owner(0, 10_000, 5_001),
                &b,
                Some(&history(&[&a, &b]))
            ),
            Err(ComposedReserveRefusal::BaselineReservesDisagree { generation: 0 })
        );
    }

    #[test]
    fn a_history_that_does_not_reach_back_to_the_baseline_is_refused() {
        let (a, b) = (v0(), next(&v0()));
        let c = next(&b);
        let _ = a;
        assert_eq!(
            check_composed_reserve_provenance(
                &owner(0, 10_000, 5_000),
                &c,
                Some(&history(&[&b, &c]))
            ),
            Err(ComposedReserveRefusal::HistoryMissesBaseline { baseline: 0 })
        );
    }

    #[test]
    fn the_owner_backing_must_be_exactly_the_vaults_two_legs() {
        let v = v0();
        let mut one = owner(0, 10_000, 5_000);
        one.pop();
        assert_eq!(
            check_composed_reserve_provenance(&one, &v, None),
            Err(ComposedReserveRefusal::BaselineLegs { count: 1 })
        );
        let mut split = owner(0, 10_000, 5_000);
        split[1].vault_sequence = 1;
        assert_eq!(
            check_composed_reserve_provenance(&split, &v, None),
            Err(ComposedReserveRefusal::BaselineLegs { count: 2 })
        );
        let mut other_pair = owner(0, 10_000, 5_000);
        other_pair[1].policy_commit = [0x30; 32];
        assert_eq!(
            check_composed_reserve_provenance(&other_pair, &v, None),
            Err(ComposedReserveRefusal::BaselinePair)
        );
    }
}
