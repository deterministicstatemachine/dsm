// SPDX-License-Identifier: Apache-2.0

//! THE `TA_B` PRODUCER — amendment 2c-D §6, producer adoption.
//!
//! [`crate::economic::acceptance_verify`] is the other half: it checks a
//! `TA_B` against a bundle under §7's seven conjuncts. This module is what
//! makes one exist at all. Before it, `TraderAcceptance::new` had no caller
//! outside its own tests — §7 was constructible in the verifier and
//! unreachable in the live settle path.
//!
//! ## Everything is read from the transition that already happened
//!
//! A `TA_B` names four things, and not one of them is chosen here:
//!
//! ```text
//! trader_genesis      the authenticated local identity, passed in
//! economic_position   the position the register just committed
//! acceptance_leaf     THE emitted 0x0032, lifted out of the witness
//! acceptance_path     that leaf's siblings, taken from the post-state tree
//! ```
//!
//! `b` and `economic_operation_id` therefore arrive inside the leaf the write
//! set emitted, never as parameters a caller could pick — the owner ruling's
//! *"no reconstructed or caller-selected identities"*. There is deliberately
//! no argument through which either could be supplied.
//!
//! ## What "under `R_T^+`" costs
//!
//! §7 step 5 folds the path and requires the result to equal the root the
//! validity walk derived. The path must therefore be the one that holds in the
//! FINAL post-state, and a mutation's own siblings are not that: they are
//! captured with mutations `0..i` applied, so any later mutation in key order
//! invalidates them. The acceptance leaf is not last by construction — its key
//! is a hash — so this module takes the path from the finished tree, and
//! refuses when that tree is not the one whose root was validated.
//!
//! ## What producing a `TA_B` does NOT do
//!
//! Nothing. It publishes an artifact. It does not realize the settlement,
//! release the trader fence, advance the realized frontier, or promote any
//! market fold out of `PartialPendingRealization` — those remain the dedicated
//! cutover, and 2c-D §11's boundary note is why they are one change and not
//! several. A `TA_B` existing is a precondition of realization, never its
//! trigger.

use crate::economic::state::{EconomicBundleAcceptanceState, EconomicLeafState};
use crate::economic::trader_acceptance::{AcceptanceMalformed, TraderAcceptance};
use crate::economic::tree::{leaf_node, root_from_path, EconomicSmt};
use crate::economic::witness::EconomicTransitionWitness;

/// Why a transition that wrote an acceptance leaf still cannot yield a `TA_B`.
///
/// Every arm is a disagreement between two facts that must be the same
/// transition. None of them is recoverable by retry: a producer holding a
/// tree, a witness and a validated root that do not describe one another has
/// a bug, not a transient.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AcceptanceNotProducible {
    /// The tree the path would come from is not the post-state whose root was
    /// validated. A path taken from any other tree folds to any other root.
    TreeIsNotTheValidatedPostState { tree: [u8; 32], validated: [u8; 32] },
    /// The witness the leaf would come from does not describe the transition
    /// that produced the validated root — so its acceptance leaf, whatever it
    /// says, belongs to some other transition.
    WitnessIsNotTheValidatedPostState {
        witness: [u8; 32],
        validated: [u8; 32],
    },
    /// More than one `0x0032` in one witness. The write-set boundary already
    /// refuses this; reaching it here means a witness arrived from somewhere
    /// else, and picking one of them would be a silent choice about which
    /// bundle this transition accepted.
    MoreThanOneAcceptanceLeaf { count: usize },
    /// The emitted leaf and the witness name different economic operations.
    /// This is §7 step 5's middle term, checked at production so an artifact
    /// that could never satisfy it is never published.
    OperationIdentityDisagrees { leaf: [u8; 32], witness: [u8; 32] },
    /// The path this module just took does not fold the leaf back to the
    /// validated root.
    PathDoesNotFoldToTheValidatedRoot {
        folded: [u8; 32],
        validated: [u8; 32],
    },
    /// `TraderAcceptance`'s own frozen rejections (§6).
    Malformed(AcceptanceMalformed),
    /// The leaf has no canonical bytes, so it has no leaf value to fold.
    LeafNotEncodable,
}

impl core::fmt::Display for AcceptanceNotProducible {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::TreeIsNotTheValidatedPostState { tree, validated } => write!(
                f,
                "the producer tree is at {tree:02x?}, not at the validated economic root \
                 {validated:02x?}, so any path taken from it proves inclusion in a different tree"
            ),
            Self::WitnessIsNotTheValidatedPostState { witness, validated } => write!(
                f,
                "the witness ends at {witness:02x?}, not at the validated economic root \
                 {validated:02x?}, so its acceptance leaf is not this transition's"
            ),
            Self::MoreThanOneAcceptanceLeaf { count } => write!(
                f,
                "{count} bundle-acceptance leaves in one economic operation; exactly one is the \
                 rule, and choosing among them would decide which bundle was accepted"
            ),
            Self::OperationIdentityDisagrees { leaf, witness } => write!(
                f,
                "the acceptance leaf names operation {leaf:02x?} while its own witness names \
                 {witness:02x?}"
            ),
            Self::PathDoesNotFoldToTheValidatedRoot { folded, validated } => write!(
                f,
                "the acceptance path folds to {folded:02x?}, not to the validated economic root \
                 {validated:02x?}"
            ),
            Self::Malformed(e) => write!(f, "{e}"),
            Self::LeafNotEncodable => {
                write!(f, "the acceptance leaf has no canonical encoding")
            }
        }
    }
}

/// Build the canonical `TA_B` for a transition that accepted a settlement
/// bundle, or `None` for one that accepted none.
///
/// `None` is the ordinary answer: every non-settlement writes no `0x0032`, and
/// that is an absence rather than a failure. A market settle always writes
/// exactly one (2c-D §8's producer-adoption cardinality), so `None` from a
/// settle would mean the write set did not emit its mandatory leaf — which
/// `build_write_set` refuses before this point.
///
/// `validated_root` and `economic_position` come from the register commitment,
/// never from the tree: the point of passing them is that they can DISAGREE
/// with the tree, and the disagreement is the thing worth refusing.
pub fn produce_trader_acceptance(
    tree: &EconomicSmt,
    witness: &EconomicTransitionWitness,
    genesis: &[u8; 32],
    device_id: &[u8; 32],
    validated_root: [u8; 32],
    economic_position: u64,
) -> Result<Option<TraderAcceptance>, AcceptanceNotProducible> {
    // Both origins pinned to the validated root BEFORE anything is read out of
    // either. The tree supplies the path, the witness supplies the leaf; if
    // they are not the same finished transition, the artifact would pair one
    // transition's leaf with another's proof.
    let tree_root = tree.root();
    if tree_root != validated_root {
        return Err(AcceptanceNotProducible::TreeIsNotTheValidatedPostState {
            tree: tree_root,
            validated: validated_root,
        });
    }
    if witness.post_economic_root != validated_root {
        return Err(AcceptanceNotProducible::WitnessIsNotTheValidatedPostState {
            witness: witness.post_economic_root,
            validated: validated_root,
        });
    }

    let mut accepted: Vec<&EconomicBundleAcceptanceState> = Vec::new();
    for m in &witness.mutations {
        if let Some(EconomicLeafState::BundleAcceptance(a)) = &m.post_state {
            accepted.push(a);
        }
    }
    let leaf = match accepted.as_slice() {
        [] => return Ok(None),
        [one] => *one,
        many => {
            return Err(AcceptanceNotProducible::MoreThanOneAcceptanceLeaf { count: many.len() })
        }
    };
    if leaf.economic_operation_id != witness.economic_operation_id {
        return Err(AcceptanceNotProducible::OperationIdentityDisagrees {
            leaf: leaf.economic_operation_id,
            witness: witness.economic_operation_id,
        });
    }

    // The key is derived through the leaf-state family, the one dispatch point
    // a leaf written to the tree and a leaf nested in `TA_B` share.
    let state = EconomicLeafState::BundleAcceptance(leaf.clone());
    let key = state.leaf_key(genesis, device_id);
    let value = state
        .leaf_value()
        .map_err(|_| AcceptanceNotProducible::LeafNotEncodable)?;
    let path = tree.siblings(&key);

    // §7 step 5's fold, run here against the tree the path came from. It
    // cannot disagree while `siblings` and `root_from_path` agree — which is
    // exactly why running it is worth its 256 hashes: an artifact that would
    // fail step 5 is refused at birth rather than published and rejected by
    // every verifier that ever reads it.
    let folded = root_from_path(&key, &leaf_node(&key, Some(&value)), &path);
    if folded != validated_root {
        return Err(AcceptanceNotProducible::PathDoesNotFoldToTheValidatedRoot {
            folded,
            validated: validated_root,
        });
    }

    TraderAcceptance::new(*genesis, economic_position, leaf.clone(), path.to_vec())
        .map(Some)
        .map_err(AcceptanceNotProducible::Malformed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::economic::keys::bundle_acceptance_key;
    use crate::economic::mutation::EconomicLeafMutation;
    use crate::economic::state::EconomicBalanceState;
    use crate::economic::trader_acceptance::TRADER_ACCEPTANCE_LEN;

    const G: [u8; 32] = [0x11; 32];
    const DEV: [u8; 32] = [0x22; 32];
    const B: [u8; 32] = [0xB0; 32];
    const EOID: [u8; 32] = [0x50; 32];
    const OTHER_EOID: [u8; 32] = [0x51; 32];
    const OPD: [u8; 32] = [0x0D; 32];
    const POSITION: u64 = 3;

    fn pc() -> [u8; 32] {
        [0x10; 32]
    }

    fn acceptance(bundle: [u8; 32], eoid: [u8; 32]) -> EconomicLeafState {
        EconomicLeafState::BundleAcceptance(EconomicBundleAcceptanceState {
            bundle,
            economic_operation_id: eoid,
        })
    }

    fn balance(amount: u64) -> EconomicLeafState {
        EconomicLeafState::Balance(EconomicBalanceState::new(pc(), amount).expect("balance"))
    }

    /// A transition that debits a funded balance and writes `extra`, built the
    /// way the write set builds one: key order, siblings captured with every
    /// earlier mutation applied. Returns the witness and the FINISHED tree.
    ///
    /// The debit leg is not decoration — it is what makes the acceptance leaf
    /// stop being the only mutation, so the difference between a mutation's own
    /// captured siblings and the path under the final root is real here.
    fn transition(extra: &[EconomicLeafState]) -> (EconomicTransitionWitness, EconomicSmt) {
        transition_id(EOID, extra)
    }

    /// As above, with the witness's own operation id chosen by the caller —
    /// needed wherever the acceptance leaf's KEY, which is a function of that
    /// id, has to land in a particular place in the mutation order.
    fn transition_id(
        eoid: [u8; 32],
        extra: &[EconomicLeafState],
    ) -> (EconomicTransitionWitness, EconomicSmt) {
        let mut tree = EconomicSmt::new();
        let funded = balance(5_000);
        tree.insert(
            funded.leaf_key(&G, &DEV),
            funded.leaf_value().expect("value"),
        );
        let pre_root = tree.root();

        let mut planned: Vec<(Option<EconomicLeafState>, EconomicLeafState)> =
            vec![(Some(funded), balance(4_000))];
        planned.extend(extra.iter().map(|s| (None, s.clone())));
        planned.sort_by_key(|(_, post)| post.leaf_key(&G, &DEV));

        let mut mutations = Vec::new();
        for (pre, post) in planned {
            let key = post.leaf_key(&G, &DEV);
            let siblings = tree.siblings(&key).to_vec();
            tree.insert(key, post.leaf_value().expect("value"));
            mutations.push(EconomicLeafMutation::new(pre, Some(post), siblings).expect("mutation"));
        }
        let witness =
            EconomicTransitionWitness::new(pre_root, tree.root(), eoid, OPD, mutations, Vec::new())
                .expect("witness");
        (witness, tree)
    }

    fn produce(
        witness: &EconomicTransitionWitness,
        tree: &EconomicSmt,
    ) -> Result<Option<TraderAcceptance>, AcceptanceNotProducible> {
        produce_trader_acceptance(tree, witness, &G, &DEV, tree.root(), POSITION)
    }

    /// The ordinary answer for everything that is not a settle: no acceptance
    /// leaf, so no `TA_B`, and that is an absence rather than a failure.
    #[test]
    fn a_transition_that_accepted_no_bundle_produces_nothing() {
        let (witness, tree) = transition(&[]);
        assert_eq!(produce(&witness, &tree), Ok(None));
    }

    /// THE PRODUCER'S WHOLE CLAIM: the path it emits folds the emitted leaf
    /// back to `R_T^+`, and the identities it carries are the leaf's own.
    ///
    /// The fold is recomputed here from the artifact's OWN fields — never from
    /// the tree — because that is what a verifier will have.
    #[test]
    fn the_emitted_path_folds_the_emitted_leaf_back_to_the_validated_root() {
        let (witness, tree) = transition(&[acceptance(B, EOID)]);
        let root = tree.root();
        let ta = produce(&witness, &tree)
            .expect("producible")
            .expect("a settle produces one");

        assert_eq!(ta.trader_genesis(), G);
        assert_eq!(ta.economic_position(), POSITION);
        assert_eq!(ta.acceptance_leaf().bundle, B, "the emitted b, verbatim");
        assert_eq!(
            ta.acceptance_leaf().economic_operation_id,
            EOID,
            "the emitted operation id, verbatim"
        );
        assert_eq!(ta.encode().expect("encodable").len(), TRADER_ACCEPTANCE_LEN);

        let key = bundle_acceptance_key(&G, &DEV, &EOID);
        let value = EconomicLeafState::BundleAcceptance(ta.acceptance_leaf().clone())
            .leaf_value()
            .expect("value");
        let siblings: &[[u8; 32]; crate::economic::tree::ECONOMIC_SMT_HEIGHT] =
            ta.acceptance_path().try_into().expect("exactly 256");
        assert_eq!(
            root_from_path(&key, &leaf_node(&key, Some(&value)), siblings),
            root,
            "the artifact's own fields must reconstruct R_T^+"
        );
    }

    /// A mutation's captured siblings are NOT the path under `R_T^+` unless it
    /// happens to sort last. This is the reason the producer reads the finished
    /// tree, stated as a test rather than as a comment: if it ever became true
    /// that the two agreed, taking the cheaper one would look safe.
    ///
    /// The operation id is CHOSEN so the acceptance leaf sorts before the
    /// debit. Left to the fixture's own id it sorts last, the two paths agree,
    /// and the test would pass while proving nothing — which is how this one
    /// was written the first time.
    #[test]
    fn the_leafs_own_captured_siblings_are_not_the_path_under_the_final_root() {
        let debit_key = balance(4_000).leaf_key(&G, &DEV);
        let eoid = (0u8..=255)
            .map(|i| [i; 32])
            .find(|e| acceptance(B, *e).leaf_key(&G, &DEV) < debit_key)
            .expect("some operation id keys the acceptance before the debit");
        let (witness, tree) = transition_id(eoid, &[acceptance(B, eoid)]);
        let key = bundle_acceptance_key(&G, &DEV, &eoid);
        let captured = witness
            .mutations
            .iter()
            .find(|m| m.leaf_key(&G, &DEV).expect("keyed") == key)
            .expect("the acceptance mutation")
            .siblings
            .clone();
        let root = tree.root();
        let ta = produce_trader_acceptance(&tree, &witness, &G, &DEV, root, POSITION)
            .expect("producible")
            .expect("one");
        assert_ne!(
            captured.as_slice(),
            ta.acceptance_path(),
            "a later mutation must invalidate the siblings captured at the acceptance"
        );
        // AND THE CAPTURED ONE WOULD BE WRONG, not merely different.
        let value = EconomicLeafState::BundleAcceptance(ta.acceptance_leaf().clone())
            .leaf_value()
            .expect("value");
        let stale: &[[u8; 32]; crate::economic::tree::ECONOMIC_SMT_HEIGHT] =
            captured.as_slice().try_into().expect("exactly 256");
        assert_ne!(
            root_from_path(&key, &leaf_node(&key, Some(&value)), stale),
            root,
            "the mutation's own siblings must NOT fold to R_T^+"
        );
    }

    /// A path taken from any other tree proves inclusion in that other tree.
    #[test]
    fn a_tree_that_is_not_the_validated_post_state_is_refused() {
        let (witness, tree) = transition(&[acceptance(B, EOID)]);
        let elsewhere = [0x77; 32];
        assert_eq!(
            produce_trader_acceptance(&tree, &witness, &G, &DEV, elsewhere, POSITION),
            Err(AcceptanceNotProducible::TreeIsNotTheValidatedPostState {
                tree: tree.root(),
                validated: elsewhere,
            })
        );
    }

    /// The leaf and the path must come from ONE transition. A witness ending
    /// somewhere else describes another.
    #[test]
    fn a_witness_that_is_not_the_validated_post_state_is_refused() {
        let (_, tree) = transition(&[acceptance(B, EOID)]);
        let (other, _) = transition(&[acceptance(B, OTHER_EOID)]);
        let root = tree.root();
        assert_eq!(
            produce_trader_acceptance(&tree, &other, &G, &DEV, root, POSITION),
            Err(AcceptanceNotProducible::WitnessIsNotTheValidatedPostState {
                witness: other.post_economic_root,
                validated: root,
            })
        );
    }

    /// Two acceptances, two bundles, one transition: which one did this
    /// transition accept? The producer declines to answer rather than taking
    /// the first. The write-set boundary refuses this upstream; a witness that
    /// arrived from anywhere else has not been through it.
    #[test]
    fn two_acceptance_leaves_refuse_rather_than_choose_a_bundle() {
        let (witness, tree) =
            transition(&[acceptance(B, EOID), acceptance([0xB1; 32], OTHER_EOID)]);
        assert_eq!(
            produce(&witness, &tree),
            Err(AcceptanceNotProducible::MoreThanOneAcceptanceLeaf { count: 2 })
        );
    }

    /// §7 step 5's middle term, refused at production: a leaf whose operation
    /// id is not its own witness's could never fold under an id the verifier
    /// recomputes.
    #[test]
    fn a_leaf_naming_another_operation_than_its_witness_is_refused() {
        let (witness, tree) = transition(&[acceptance(B, OTHER_EOID)]);
        assert_eq!(
            produce(&witness, &tree),
            Err(AcceptanceNotProducible::OperationIdentityDisagrees {
                leaf: OTHER_EOID,
                witness: EOID,
            })
        );
    }

    /// `TraderAcceptance`'s own frozen rejection reaches the producer rather
    /// than being re-implemented by it.
    #[test]
    fn a_zero_genesis_produces_no_acceptance_at_all() {
        let zero = [0u8; 32];
        let mut tree = EconomicSmt::new();
        let state = acceptance(B, EOID);
        let key = state.leaf_key(&zero, &DEV);
        let pre_root = tree.root();
        let siblings = tree.siblings(&key).to_vec();
        tree.insert(key, state.leaf_value().expect("value"));
        let witness = EconomicTransitionWitness::new(
            pre_root,
            tree.root(),
            EOID,
            OPD,
            vec![EconomicLeafMutation::new(None, Some(state), siblings).expect("mutation")],
            Vec::new(),
        )
        .expect("witness");
        let root = tree.root();
        assert_eq!(
            produce_trader_acceptance(&tree, &witness, &zero, &DEV, root, POSITION),
            Err(AcceptanceNotProducible::Malformed(
                AcceptanceMalformed::GenesisIsZero
            ))
        );
    }
}
