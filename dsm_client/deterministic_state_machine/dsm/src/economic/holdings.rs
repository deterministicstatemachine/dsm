// SPDX-License-Identifier: Apache-2.0

//! Holdings proofs as a verifier checks them (DSM Amendment A11): never a
//! statement, always a proof.
//!
//! The holder presents a position `p` and, for each asked token, the amount
//! and the Sparse Merkle path from the token's balance key to the economic
//! root. The verifier validates the holder's root at `p` itself (Amendment
//! A8) and recomputes that root from every path here: each leaf is the one
//! its stated amount puts at the holder's balance key, and a path that does
//! not fold to the validated root proves no balance at all. Whether the proof
//! is still current, the holder's next root cell, is read beside it.

use std::collections::BTreeMap;

use crate::economic::keys::balance_key;
use crate::economic::lineage::ValidatedEconomicRoot;
use crate::economic::state::{EconomicBalanceState, EconomicLeafState};
use crate::economic::tree::{leaf_node, root_from_path};
use crate::merkle::smt_path::{self, PathError};
use crate::sofi::smt::fold::EconomicHashes;
use crate::types::proto::HoldingsProofV1;

type D32 = [u8; 32];

/// Why a holdings proof proves nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HoldingsError {
    /// A field that names a 32-byte value is another length.
    NotThirtyTwoBytes {
        field: &'static str,
        got: usize,
        why: String,
    },
    /// The proof is another identity's than the holder asked about.
    AnotherIdentity,
    /// Position 0 is the activation root: nothing is proven there.
    ActivationPosition,
    /// The proof names another position than the root it is checked at.
    AnotherPosition { proof: u64, validated: u64 },
    /// The proof does not answer exactly the asked tokens.
    AnswersOtherThanAsked { answered: usize, asked: usize },
    /// The proof answers a token that was not asked, or one twice.
    TokenNotAskedOrTwice { policy_commit: D32 },
    /// A holding's path is not a path in its one wire form.
    PathDoesNotDecode { policy_commit: D32, why: PathError },
    /// A holding's amount has no balance leaf.
    AmountHasNoLeaf {
        policy_commit: D32,
        why: crate::ccb::CcbError,
    },
    /// A holding's path, under the leaf its amount puts at its key, does not
    /// recompute the validated root.
    PathDoesNotRecomputeTheRoot { policy_commit: D32 },
}

impl core::fmt::Display for HoldingsError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let id = crate::utils::text_id::encode_base32_crockford;
        match self {
            Self::NotThirtyTwoBytes { field, got, why } => {
                write!(f, "{field} is {got} bytes, not 32: {why}")
            }
            Self::AnotherIdentity => write!(
                f,
                "the proof is another identity's than the holder asked about"
            ),
            Self::ActivationPosition => write!(
                f,
                "position 0 is the activation root; nothing is proven there"
            ),
            Self::AnotherPosition { proof, validated } => write!(
                f,
                "the proof names position {proof}; the root it is checked at is position \
                 {validated}'s"
            ),
            Self::AnswersOtherThanAsked { answered, asked } => {
                write!(f, "the proof answers {answered} tokens; {asked} were asked")
            }
            Self::TokenNotAskedOrTwice { policy_commit } => write!(
                f,
                "the proof answers token {} that was not asked, or answers it twice",
                id(policy_commit)
            ),
            Self::PathDoesNotDecode { policy_commit, why } => write!(
                f,
                "the path of token {} is not a path: {why}",
                id(policy_commit)
            ),
            Self::AmountHasNoLeaf { policy_commit, why } => write!(
                f,
                "the amount of token {} has no balance leaf: {why:?}",
                id(policy_commit)
            ),
            Self::PathDoesNotRecomputeTheRoot { policy_commit } => write!(
                f,
                "a holding's path does not recompute the validated root (token {})",
                id(policy_commit)
            ),
        }
    }
}

impl std::error::Error for HoldingsError {}

fn d32(bytes: &[u8], field: &'static str) -> Result<D32, HoldingsError> {
    <D32>::try_from(bytes).map_err(|e| HoldingsError::NotThirtyTwoBytes {
        field,
        got: bytes.len(),
        why: e.to_string(),
    })
}

/// The position whose root a verifier validates for `proof`, once the proof
/// is shown to be the holder's: `(genesis, device_id)` is the identity the
/// verifier asked, and position 0, the activation root, proves nothing.
pub fn proven_position(
    proof: &HoldingsProofV1,
    genesis: &D32,
    device_id: &D32,
) -> Result<u64, HoldingsError> {
    if d32(&proof.genesis, "the proof's genesis")? != *genesis
        || d32(&proof.device_id, "the proof's device")? != *device_id
    {
        return Err(HoldingsError::AnotherIdentity);
    }
    if proof.position == 0 {
        return Err(HoldingsError::ActivationPosition);
    }
    Ok(proof.position)
}

/// Each asked token's balance, from `proof` checked against `validated`, the
/// holder's root at the proven position as this verifier validated it.
///
/// THE ROOT IS THE VERIFIER'S, AND THE AMOUNTS ARE THE PROOF'S ONLY THROUGH
/// IT. The proof must be the holder's at that position and answer exactly the
/// asked tokens, each once. Each holding's leaf is the one its amount puts at
/// the holder's balance key (absent for zero), and its path must fold that
/// leaf to the validated root. A proof that does not verify is not a smaller
/// balance; it is no balance at all.
pub fn proven_balances(
    proof: &HoldingsProofV1,
    genesis: &D32,
    device_id: &D32,
    asked: &[D32],
    validated: &ValidatedEconomicRoot,
) -> Result<BTreeMap<D32, u64>, HoldingsError> {
    let position = proven_position(proof, genesis, device_id)?;
    if position != validated.economic_position() {
        return Err(HoldingsError::AnotherPosition {
            proof: position,
            validated: validated.economic_position(),
        });
    }
    if proof.holdings.len() != asked.len() {
        return Err(HoldingsError::AnswersOtherThanAsked {
            answered: proof.holdings.len(),
            asked: asked.len(),
        });
    }
    let root = validated.economic_root();
    let mut balances = BTreeMap::new();
    for holding in &proof.holdings {
        let policy_commit = d32(&holding.policy_commit, "a holding's token")?;
        if !asked.contains(&policy_commit) || balances.contains_key(&policy_commit) {
            return Err(HoldingsError::TokenNotAskedOrTwice { policy_commit });
        }
        let path = smt_path::decode::<EconomicHashes>(&holding.explicit_heights, &holding.siblings)
            .map_err(|why| HoldingsError::PathDoesNotDecode { policy_commit, why })?;
        let key = balance_key(genesis, device_id, &policy_commit);
        let leaf = balance_leaf(&key, policy_commit, holding.amount)
            .map_err(|why| HoldingsError::AmountHasNoLeaf { policy_commit, why })?;
        if root_from_path(&key, &leaf, &path) != root {
            return Err(HoldingsError::PathDoesNotRecomputeTheRoot { policy_commit });
        }
        balances.insert(policy_commit, holding.amount);
    }
    Ok(balances)
}

/// The leaf node a balance of `amount` puts at `key`: absent for zero, which
/// is never encoded.
fn balance_leaf(key: &D32, policy_commit: D32, amount: u64) -> Result<D32, crate::ccb::CcbError> {
    if amount == 0 {
        return Ok(leaf_node(key, None));
    }
    let value = EconomicLeafState::Balance(EconomicBalanceState::new(policy_commit, amount)?)
        .leaf_value()?;
    Ok(leaf_node(key, Some(&value)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::economic::lineage::AdmittedEconomicPosition;
    use crate::economic::tree::EconomicSmt;
    use crate::types::proto::HoldingV1;

    const G: D32 = [3; 32];
    const D: D32 = [4; 32];
    const WILD: D32 = [5; 32];
    const MOSS: D32 = [6; 32];
    const ERA: D32 = [7; 32];
    const POSITION: u64 = 3;

    /// The holder's position 3, validated at `root`.
    fn validated_at(root: D32) -> ValidatedEconomicRoot {
        ValidatedEconomicRoot::rehydrate_from_admitted_store(AdmittedEconomicPosition::SingleRoot {
            economic_position: POSITION,
            economic_root: root,
            claim_ref: [0xC7; 32],
        })
        .expect("an ordinary admitted position")
    }

    fn balance_value(token: D32, amount: u64) -> D32 {
        EconomicLeafState::Balance(EconomicBalanceState::new(token, amount).expect("a balance"))
            .leaf_value()
            .expect("a value")
    }

    /// A tree holding 40 WILD and 1 MOSS (no ERA) for (G, D), with a proof
    /// of exactly those three tokens built the way a holder builds one.
    fn tree_and_proof() -> (EconomicSmt, HoldingsProofV1) {
        let mut tree = EconomicSmt::new();
        let mut balances = BTreeMap::new();
        for (token, amount) in [(WILD, 40u64), (MOSS, 1)] {
            tree.insert(balance_key(&G, &D, &token), balance_value(token, amount));
            balances.insert(token, amount);
        }
        let holdings = [WILD, MOSS, ERA]
            .iter()
            .map(|token| {
                let path =
                    smt_path::encode::<EconomicHashes>(&tree.siblings(&balance_key(&G, &D, token)));
                HoldingV1 {
                    policy_commit: token.to_vec(),
                    amount: match balances.get(token) {
                        Some(amount) => *amount,
                        None => 0,
                    },
                    explicit_heights: path.explicit_heights.to_vec(),
                    siblings: path.siblings,
                }
            })
            .collect();
        let proof = HoldingsProofV1 {
            genesis: G.to_vec(),
            device_id: D.to_vec(),
            position: POSITION,
            holdings,
        };
        (tree, proof)
    }

    fn check(
        proof: &HoldingsProofV1,
        device_id: &D32,
        asked: &[D32],
        root: D32,
    ) -> Result<BTreeMap<D32, u64>, HoldingsError> {
        proven_balances(proof, &G, device_id, asked, &validated_at(root))
    }

    #[test]
    fn honest_paths_recompute_the_root_and_give_each_balance() {
        let (tree, proof) = tree_and_proof();
        let balances = check(&proof, &D, &[WILD, MOSS, ERA], tree.root()).expect("honest");
        assert_eq!(
            balances,
            BTreeMap::from([(WILD, 40), (MOSS, 1), (ERA, 0)]),
            "an absent leaf proves a zero balance"
        );
    }

    /// MUTATION CONTROL: the root comparison removed turns this red.
    #[test]
    fn a_forged_amount_proves_nothing() {
        let (tree, mut proof) = tree_and_proof();
        proof.holdings[0].amount = 41;
        assert_eq!(
            check(&proof, &D, &[WILD, MOSS, ERA], tree.root()),
            Err(HoldingsError::PathDoesNotRecomputeTheRoot {
                policy_commit: WILD
            })
        );
        let (tree, mut proof) = tree_and_proof();
        proof.holdings[2].amount = 5;
        assert_eq!(
            check(&proof, &D, &[WILD, MOSS, ERA], tree.root()),
            Err(HoldingsError::PathDoesNotRecomputeTheRoot { policy_commit: ERA }),
            "a balance claimed where the tree has none"
        );
    }

    #[test]
    fn another_tokens_path_proves_nothing() {
        let (tree, mut proof) = tree_and_proof();
        let moss = proof.holdings[1].clone();
        proof.holdings[0].explicit_heights = moss.explicit_heights;
        proof.holdings[0].siblings = moss.siblings;
        assert_eq!(
            check(&proof, &D, &[WILD, MOSS, ERA], tree.root()),
            Err(HoldingsError::PathDoesNotRecomputeTheRoot {
                policy_commit: WILD
            })
        );
    }

    #[test]
    fn another_devices_key_proves_nothing() {
        let (tree, proof) = tree_and_proof();
        assert_eq!(
            check(&proof, &[9; 32], &[WILD, MOSS, ERA], tree.root()),
            Err(HoldingsError::AnotherIdentity)
        );
    }

    #[test]
    fn a_proof_at_another_root_proves_nothing() {
        let (mut tree, proof) = tree_and_proof();
        let stale = tree.root();
        tree.insert(balance_key(&G, &D, &WILD), balance_value(WILD, 10));
        assert_eq!(
            check(&proof, &D, &[WILD, MOSS, ERA], stale).map(|b| b.len()),
            Ok(3)
        );
        assert_eq!(
            check(&proof, &D, &[WILD, MOSS, ERA], tree.root()),
            Err(HoldingsError::PathDoesNotRecomputeTheRoot {
                policy_commit: WILD
            }),
            "the holder spent since: the old proof does not recompute the new root"
        );
    }

    #[test]
    fn a_proof_must_answer_exactly_what_was_asked() {
        let (tree, proof) = tree_and_proof();
        assert_eq!(
            check(&proof, &D, &[WILD, MOSS], tree.root()),
            Err(HoldingsError::AnswersOtherThanAsked {
                answered: 3,
                asked: 2
            })
        );
        let (tree, mut proof) = tree_and_proof();
        proof.holdings[2] = proof.holdings[0].clone();
        assert_eq!(
            check(&proof, &D, &[WILD, MOSS, ERA], tree.root()),
            Err(HoldingsError::TokenNotAskedOrTwice {
                policy_commit: WILD
            })
        );
    }

    /// The proof is checked at the root of the position it names, and never
    /// at position 0.
    #[test]
    fn a_proof_is_checked_only_at_the_position_it_names() {
        let (tree, mut proof) = tree_and_proof();
        proof.position = POSITION + 1;
        assert_eq!(
            check(&proof, &D, &[WILD, MOSS, ERA], tree.root()),
            Err(HoldingsError::AnotherPosition {
                proof: POSITION + 1,
                validated: POSITION
            })
        );
        proof.position = 0;
        assert_eq!(
            proven_position(&proof, &G, &D),
            Err(HoldingsError::ActivationPosition)
        );
    }
}
