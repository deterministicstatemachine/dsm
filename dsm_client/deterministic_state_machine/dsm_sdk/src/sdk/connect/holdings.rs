// SPDX-License-Identifier: MIT OR Apache-2.0

//! Holdings proofs (DSM Amendment A11): never a statement, always a proof.
//!
//! The holder presents its latest admitted economic position `p` and, for
//! each asked token, the amount and the Sparse Merkle path from the token's
//! balance key to the economic root. The application validates the holder's
//! root at `p` from its own frontier (Amendment A8), Core recomputes that root
//! from each path (`economic::holdings::proven_balances`), and the register
//! cell of `p + 1` is read at its leader: the proof is current only while that
//! cell is empty. A proof that does not verify is no balance at all. This
//! module carries the proof and the reads; it computes no root.

use std::collections::BTreeMap;

use dsm::economic::keys::balance_key;
use dsm::economic::lineage::ValidatedEconomicRoot;
use dsm::economic::provenance::PeerLineageFailure;
use dsm::merkle::smt_path;
use dsm::sofi::smt::fold::EconomicHashes;
use dsm::types::proto as generated;

use crate::sdk::core_sdk::CoreSDK;

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
    let invalid = |why: dsm::economic::holdings::HoldingsError| Refusal::Invalid(why.to_string());
    let position =
        dsm::economic::holdings::proven_position(proof, genesis, device_id).map_err(invalid)?;
    let network = crate::sdk::economic_admission_flow::committed_network_id()
        .map_err(|e| Refusal::Incomplete(format!("this account's network: {e}")))?;
    let set = crate::sdk::storage_set::canonical_set(&network)
        .map_err(|e| Refusal::Incomplete(format!("the pinned storage set: {e}")))?;
    // The holder's root at `position` is read from this account's frontier
    // for the holder (`economic_registers::resolve_peer_root`, DSM Amendment
    // A19): a frontier at or past `position` answers it, and a read records
    // nothing, so what lies past the frontier is walked again on each poll.
    // Whether the proof is still current is read below
    // on every call, never kept: the next root cell is open until the holder
    // moves on.
    let validated: ValidatedEconomicRoot = tokio::task::block_in_place(|| {
        let reads = crate::sdk::sofi_reads::LiveSofiReads::new(&set, None)
            .map_err(|e| Refusal::Incomplete(format!("the verifier's reads: {e}")))?;
        dsm::sofi::resolve::SofiReads::trader_root_at(&reads, genesis, device_id, position)
            .map(|(root, _)| root)
            .map_err(walk_failure)
    })?;
    let root = validated.economic_root();
    let balances =
        dsm::economic::holdings::proven_balances(proof, genesis, device_id, asked, &validated)
            .map_err(invalid)?;
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
