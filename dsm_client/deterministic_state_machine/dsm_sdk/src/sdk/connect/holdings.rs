// SPDX-License-Identifier: MIT OR Apache-2.0

//! Holdings proofs (DSM Amendment A11): never a statement, always a proof.
//!
//! The holder presents its latest admitted economic position `p` and, for
//! each asked token, the amount and the Sparse Merkle path from the token's
//! balance key to the economic root. The application validates the holder's
//! root at `p` from its own frontier (Amendment A8), recomputes the root from
//! each path, and reads the register cell of `p + 1` at its leader: the proof
//! is current only while that cell is empty. A proof that does not verify is
//! no balance at all.

use std::collections::BTreeMap;

use dsm::economic::keys::balance_key;
use dsm::economic::lineage::ValidatedEconomicRoot;
use dsm::economic::provenance::PeerLineageFailure;
use dsm::economic::state::{EconomicBalanceState, EconomicLeafState};
use dsm::economic::tree::{leaf_node, root_from_path};
use dsm::merkle::smt_path;
use dsm::sofi::smt::fold::EconomicHashes;
use dsm::types::proto as generated;

use super::d32;
use crate::sdk::core_sdk::CoreSDK;

/// The leaf node a balance of `amount` puts at `key`: absent for zero, which
/// is never encoded.
fn balance_leaf(key: &[u8; 32], policy_commit: [u8; 32], amount: u64) -> Result<[u8; 32], String> {
    if amount == 0 {
        return Ok(leaf_node(key, None));
    }
    let state = EconomicBalanceState::new(policy_commit, amount)
        .map_err(|e| format!("a balance leaf: {e:?}"))?;
    let value = EconomicLeafState::Balance(state)
        .leaf_value()
        .map_err(|e| format!("a balance leaf value: {e:?}"))?;
    Ok(leaf_node(key, Some(&value)))
}

/// The position this device is still admitting, if one is: a proof waits
/// for it rather than prove an earlier position.
pub(crate) fn admission_pending(core: &CoreSDK) -> Result<Option<u64>, String> {
    let head = core
        .device_head()
        .ok_or_else(|| "this device has no head".to_string())?;
    Ok(head
        .pending_economic_admission()
        .map(|pending| pending.economic_position))
}

/// This device's balances of `policy_commits` at its latest admitted
/// position, each with its path to the root admitted there.
pub(crate) fn prove(
    core: &CoreSDK,
    policy_commits: &[[u8; 32]],
) -> Result<generated::HoldingsProofV1, String> {
    let head = core
        .device_head()
        .ok_or_else(|| "this device has no head".to_string())?;
    if let Some(pending) = head.pending_economic_admission() {
        return Err(format!(
            "position {} is still being admitted; ask again once it settles",
            pending.economic_position
        ));
    }
    let (genesis, device_id) = (head.genesis_digest(), head.devid());
    let (validated, tree, pre) = crate::sdk::economic_admission_flow::admitted_root_and_tree()
        .map_err(|e| format!("the admitted economic root: {e}"))?
        .ok_or_else(|| "this device has admitted no economic position yet".to_string())?;
    let mut holdings = Vec::with_capacity(policy_commits.len());
    for policy_commit in policy_commits {
        let key = balance_key(&genesis, &device_id, policy_commit);
        let amount = match pre.balances.get(policy_commit) {
            Some(amount) => *amount,
            None => 0,
        };
        let path = smt_path::encode::<EconomicHashes>(&tree.siblings(&key));
        holdings.push(generated::HoldingV1 {
            policy_commit: policy_commit.to_vec(),
            amount,
            explicit_heights: path.explicit_heights.to_vec(),
            siblings: path.siblings,
        });
    }
    Ok(generated::HoldingsProofV1 {
        genesis: genesis.to_vec(),
        device_id: device_id.to_vec(),
        position: validated.economic_position(),
        holdings,
    })
}

/// Balances a holdings proof established.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedHoldings {
    pub position: u64,
    pub balances: BTreeMap<[u8; 32], u64>,
}

/// Why a proof established nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// The proof is wrong: it is not the session's holder, it does not
    /// answer what was asked, or a path does not recompute the validated
    /// root. No balance.
    Invalid(String),
    /// The holder has moved past the proven position. Ask again.
    NotCurrent(String),
    /// The network did not decide it yet (a walk or a cell read). Ask again.
    Incomplete(String),
}

/// Each asked token's balance, if every path in `proof` recomputes `root`
/// for the holder `(genesis, device_id)`. Exactly the asked tokens, each once.
pub fn check_paths(
    proof: &generated::HoldingsProofV1,
    genesis: &[u8; 32],
    device_id: &[u8; 32],
    asked: &[[u8; 32]],
    root: &[u8; 32],
) -> Result<BTreeMap<[u8; 32], u64>, String> {
    if proof.holdings.len() != asked.len() {
        return Err(format!(
            "the proof answers {} tokens; {} were asked",
            proof.holdings.len(),
            asked.len()
        ));
    }
    let mut balances = BTreeMap::new();
    for holding in &proof.holdings {
        let policy_commit = d32(&holding.policy_commit, "a holding's token")?;
        if !asked.contains(&policy_commit) || balances.contains_key(&policy_commit) {
            return Err("the proof answers a token that was not asked, or one twice".into());
        }
        let path = smt_path::decode::<EconomicHashes>(&holding.explicit_heights, &holding.siblings)
            .map_err(|e| format!("a holding's path: {e}"))?;
        let key = balance_key(genesis, device_id, &policy_commit);
        let leaf = balance_leaf(&key, policy_commit, holding.amount)?;
        if &root_from_path(&key, &leaf, &path) != root {
            return Err("a holding's path does not recompute the validated root".into());
        }
        balances.insert(policy_commit, holding.amount);
    }
    Ok(balances)
}

fn walk_failure(failure: PeerLineageFailure) -> Refusal {
    match failure {
        PeerLineageFailure::Invalid(why) => {
            Refusal::Invalid(format!("the holder's lineage is invalid: {why}"))
        }
        other => Refusal::Incomplete(format!("the holder's root is not decided yet: {other:?}")),
    }
}

/// Verify `proof` as the holdings of `(genesis, device_id)`, the session's
/// wallet, for exactly `asked`. Runs on a multi-thread runtime: the lineage
/// walk blocks in place.
pub(crate) async fn verify(
    proof: &generated::HoldingsProofV1,
    genesis: &[u8; 32],
    device_id: &[u8; 32],
    asked: &[[u8; 32]],
) -> Result<VerifiedHoldings, Refusal> {
    let invalid = |why: String| Refusal::Invalid(why);
    if d32(&proof.genesis, "the proof's genesis").map_err(invalid)? != *genesis
        || d32(&proof.device_id, "the proof's device").map_err(invalid)? != *device_id
    {
        return Err(Refusal::Invalid(
            "the proof is another identity's than the session's wallet".into(),
        ));
    }
    if proof.position == 0 {
        return Err(Refusal::Invalid(
            "position 0 is the activation root; nothing is proven there".into(),
        ));
    }
    let network = crate::sdk::economic_admission_flow::committed_network_id()
        .map_err(|e| Refusal::Incomplete(format!("this account's network: {e}")))?;
    let set = crate::sdk::storage_set::canonical_set(&network)
        .map_err(|e| Refusal::Incomplete(format!("the pinned storage set: {e}")))?;
    let position = proof.position;
    let validated: ValidatedEconomicRoot = tokio::task::block_in_place(|| {
        let reads = crate::sdk::sofi_reads::LiveSofiReads::new(&set, None)
            .map_err(|e| Refusal::Incomplete(format!("the verifier's reads: {e}")))?;
        dsm::sofi::resolve::SofiReads::trader_root_at(&reads, genesis, device_id, position)
            .map(|(root, _)| root)
            .map_err(walk_failure)
    })?;
    let root = validated.economic_root();
    let balances =
        check_paths(proof, genesis, device_id, asked, &root).map_err(Refusal::Invalid)?;
    match crate::sdk::economic_registers::next_root_cell(
        &set, &network, genesis, device_id, position, &root,
    )
    .await
    .map_err(|e| Refusal::Incomplete(format!("the next root cell: {e}")))?
    {
        crate::sdk::economic_registers::NextRootCell::Open => {
            Ok(VerifiedHoldings { position, balances })
        }
        crate::sdk::economic_registers::NextRootCell::Held => Err(Refusal::NotCurrent(format!(
            "the holder has moved past position {position}"
        ))),
        crate::sdk::economic_registers::NextRootCell::Undecided(why) => {
            Err(Refusal::Incomplete(format!("the next root cell: {why}")))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dsm::economic::tree::EconomicSmt;

    const G: [u8; 32] = [3; 32];
    const D: [u8; 32] = [4; 32];
    const WILD: [u8; 32] = [5; 32];
    const MOSS: [u8; 32] = [6; 32];
    const ERA: [u8; 32] = [7; 32];

    /// A tree holding 40 WILD and 1 MOSS (no ERA) for (G, D), with a proof
    /// of exactly those three tokens built the way `prove` builds one.
    fn tree_and_proof() -> Result<(EconomicSmt, generated::HoldingsProofV1), String> {
        let mut tree = EconomicSmt::new();
        let mut balances = BTreeMap::new();
        for (token, amount) in [(WILD, 40u64), (MOSS, 1)] {
            let key = balance_key(&G, &D, &token);
            let value = EconomicLeafState::Balance(
                EconomicBalanceState::new(token, amount).map_err(|e| format!("{e:?}"))?,
            )
            .leaf_value()
            .map_err(|e| format!("{e:?}"))?;
            tree.insert(key, value);
            balances.insert(token, amount);
        }
        let holdings = [WILD, MOSS, ERA]
            .iter()
            .map(|token| {
                let path =
                    smt_path::encode::<EconomicHashes>(&tree.siblings(&balance_key(&G, &D, token)));
                generated::HoldingV1 {
                    policy_commit: token.to_vec(),
                    amount: match balances.get(token) {
                        Some(a) => *a,
                        None => 0,
                    },
                    explicit_heights: path.explicit_heights.to_vec(),
                    siblings: path.siblings,
                }
            })
            .collect();
        let proof = generated::HoldingsProofV1 {
            genesis: G.to_vec(),
            device_id: D.to_vec(),
            position: 3,
            holdings,
        };
        Ok((tree, proof))
    }

    #[test]
    fn honest_paths_recompute_the_root_and_give_each_balance() -> Result<(), String> {
        let (tree, proof) = tree_and_proof()?;
        let balances = check_paths(&proof, &G, &D, &[WILD, MOSS, ERA], &tree.root())?;
        assert_eq!(balances.get(&WILD), Some(&40));
        assert_eq!(balances.get(&MOSS), Some(&1));
        assert_eq!(
            balances.get(&ERA),
            Some(&0),
            "an absent leaf proves a zero balance"
        );
        Ok(())
    }

    #[test]
    fn a_forged_amount_proves_nothing() -> Result<(), String> {
        let (tree, mut proof) = tree_and_proof()?;
        proof.holdings[0].amount = 41;
        check_paths(&proof, &G, &D, &[WILD, MOSS, ERA], &tree.root()).expect_err("must be refused");
        let (tree, mut proof) = tree_and_proof()?;
        proof.holdings[2].amount = 5;
        check_paths(&proof, &G, &D, &[WILD, MOSS, ERA], &tree.root())
            .expect_err("a balance claimed where the tree has none");
        Ok(())
    }

    #[test]
    fn another_tokens_path_proves_nothing() -> Result<(), String> {
        let (tree, mut proof) = tree_and_proof()?;
        let moss = proof.holdings[1].clone();
        proof.holdings[0].explicit_heights = moss.explicit_heights;
        proof.holdings[0].siblings = moss.siblings;
        check_paths(&proof, &G, &D, &[WILD, MOSS, ERA], &tree.root()).expect_err("must be refused");
        Ok(())
    }

    #[test]
    fn another_devices_key_proves_nothing() -> Result<(), String> {
        let (tree, proof) = tree_and_proof()?;
        check_paths(&proof, &G, &[9; 32], &[WILD, MOSS, ERA], &tree.root())
            .expect_err("must be refused");
        Ok(())
    }

    #[test]
    fn a_proof_at_another_root_proves_nothing() -> Result<(), String> {
        let (mut tree, proof) = tree_and_proof()?;
        let stale = tree.root();
        let key = balance_key(&G, &D, &WILD);
        let spent = EconomicLeafState::Balance(
            EconomicBalanceState::new(WILD, 10).map_err(|e| format!("{e:?}"))?,
        )
        .leaf_value()
        .map_err(|e| format!("{e:?}"))?;
        tree.insert(key, spent);
        check_paths(&proof, &G, &D, &[WILD, MOSS, ERA], &stale)?;
        check_paths(&proof, &G, &D, &[WILD, MOSS, ERA], &tree.root())
            .expect_err("the holder spent since: the old proof does not recompute the new root");
        Ok(())
    }

    #[test]
    fn a_proof_must_answer_exactly_what_was_asked() -> Result<(), String> {
        let (tree, proof) = tree_and_proof()?;
        check_paths(&proof, &G, &D, &[WILD, MOSS], &tree.root()).expect_err("must be refused");
        let (tree, mut proof) = tree_and_proof()?;
        proof.holdings[2] = proof.holdings[0].clone();
        check_paths(&proof, &G, &D, &[WILD, MOSS, ERA], &tree.root()).expect_err("must be refused");
        Ok(())
    }
}
