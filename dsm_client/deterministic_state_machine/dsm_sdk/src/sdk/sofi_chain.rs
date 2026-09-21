// SPDX-License-Identifier: Apache-2.0
//! The forward walk over successor cells (Section 30, rebuild step R14): the
//! producer of [`ParentStatus::Orphaned`].
//!
//! Every other fact a leg needs had a producer before this module. Its parent
//! did not: the resolver mapped the `(vault, root)` pairs it happened to walk
//! to onto `Canonical`, and everything else onto `Unavailable`, so a route
//! built on a refuted parent waited forever instead of being defeated. The
//! fact that decides it is `R*_g` — the canonical root of that vault at that
//! GENERATION — and that is what this module establishes.
//!
//! # The chain, and why it is walked forward
//!
//! A vault's lineage is a chain, not a set. It starts at the accepted genesis
//! and advances exactly one step per realized consumption:
//!
//! ```text
//! R*_0  --consumed by X_0-->  R*_1  --consumed by X_1-->  R*_2  ...
//! ```
//!
//! So the chain is walked by finding, at each root, the exercise that consumed
//! it, and recomputing what that exercise did to the vault. Both halves are
//! borrowed rather than reinvented: `Resolver::walk_parent` classifies the
//! attempt keys with Core's own ladder, and `vault_post_states` recomputes the
//! post state from the pre state and the settlement's terms rather than
//! reading back what the producer stated.
//!
//! # Absence never refutes
//!
//! The rule this module does NOT implement is worth naming, because it is the
//! obvious one and it is wrong: *a root the chain does not name is orphaned.*
//! A head is open precisely so the NEXT root can still arrive, so a root the
//! chain does not name may be one an in-flight operation is about to realize.
//! Refuting it answers `Orphaned`, a `RouteImpossible` arm, hence a permanent
//! `Void` on a route whose only defect is that this verifier looked early.
//!
//! Only a DIFFERENT root at the SAME generation refutes, which is
//! [`VaultChain::status_of`] over `dsm::sofi::resolution::parent_status`. That
//! refutation is permanent without any argument of this module's own: a
//! successor cell admits at most one realized consumption per attempt key
//! (`OneConsumerPerParent`, model-checked across crash and recover), so `R*_g`
//! is unique and never changes once established.
//!
//! # It records what it establishes
//!
//! Each generation is written to the vault head store through `record_walked`
//! — the same writer the resolved path uses, because the walk establishes a
//! generation by the same predicate, and because the NEXT walk must not
//! re-derive what this one proved. That is also what lets `acquire_evidence`
//! serve a vault this device never traded with: the walk reconstructs the leaf
//! set generation by generation, and the leaves are what a later acquisition
//! consumes.
use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;

use dsm::sofi::exercise::RecognizedExercise;
use dsm::sofi::lineage::genesis_root;
use dsm::sofi::resolution::{ParentPosition, VaultChain, WalkOutcome};
use dsm::sofi::validation::{vault_post_states, VaultPostState};
use dsm::types::error::DsmError;

use crate::sdk::sofi_evidence::{acquire_evidence, fetch_vault_genesis, LocalLeaves};
use crate::sdk::sofi_exercise::read_attempt_cell;
use crate::sdk::sofi_resolve::{Resolver, WALK_BUDGET};
use crate::sdk::storage_set::StorageSet;
use crate::storage::client_db::sofi_vault_head;

type D32 = [u8; 32];

/// How many generations one call extends a vault's chain by. A budget only,
/// never a verdict: a chain that stops here is short, not complete, and a
/// generation it did not reach is `Unavailable`.
pub const GENERATION_BUDGET: usize = 16;

/// How far the walk recurses into OTHER vaults' chains. A multi-leg route can
/// only have consumed this vault's root if every leg's parent was canonical,
/// so establishing this chain can require establishing a sibling's. Beta
/// routes are two hops, so two levels cover them; past this depth a sibling is
/// unestablished, which stops this chain rather than guessing at it.
pub const SIBLING_DEPTH: usize = 2;

type Fut<'s, T> = Pin<Box<dyn Future<Output = Result<T, DsmError>> + 's>>;

/// What the walk brings: the committed set, this verifier's own leaves, and
/// the conditional positions it resolved itself — the same three the resolver
/// stands on, because the walk classifies keys with the resolver.
pub struct ChainWalker<'a> {
    pub set: &'a StorageSet,
    pub local: &'a LocalLeaves,
    pub parents: &'a BTreeMap<D32, ParentPosition>,
    /// Timestamp for the rows this walk records. Passed in, never read from a
    /// clock here: nothing in the walk's ANSWER depends on it.
    pub now: i64,
}

impl ChainWalker<'_> {
    /// The canonical chain of `vault_id`, extended as far as the committed set
    /// and the budget allow, recording each generation it establishes.
    pub async fn chain(&self, vault_id: &D32) -> Result<VaultChain, DsmError> {
        self.chain_to_depth(*vault_id, SIBLING_DEPTH).await
    }

    fn chain_to_depth(&self, vault_id: D32, depth: usize) -> Fut<'_, VaultChain> {
        Box::pin(async move {
            let mut roots = stored_prefix(&vault_id)?;
            if roots.is_empty() {
                // Nothing recorded: the chain starts where every chain starts.
                let Some(genesis) = fetch_vault_genesis(self.set, &vault_id).await? else {
                    // Not even the genesis is established. The chain is empty,
                    // and an empty chain refutes nothing.
                    return Ok(VaultChain { roots: Vec::new() });
                };
                let root = genesis_root(&vault_id, &genesis.state).map_err(|e| {
                    DsmError::verification(format!("chain: vault genesis root: {e}"))
                })?;
                roots.push(root);
            }
            // What the resolver is told while this chain is being extended:
            // this vault's chain SO FAR, plus any sibling chain a multi-leg
            // consumption forced us to establish. The chain so far is not an
            // assumption — it is the induction, from a genesis nobody
            // resolved through one realized consumption per step.
            let mut chains: BTreeMap<D32, VaultChain> = BTreeMap::new();
            chains.insert(
                vault_id,
                VaultChain {
                    roots: roots.clone(),
                },
            );
            for _ in 0..GENERATION_BUDGET {
                // The chain is non-empty here, but say so in the type rather
                // than in a panic: an empty chain means nothing was
                // established, which is a stop, never a crash.
                let Some(&current) = roots.last() else {
                    break;
                };
                let Some(post) = self
                    .next_generation(&vault_id, &current, &mut chains, depth)
                    .await?
                else {
                    break;
                };
                sofi_vault_head::record_walked(&post, self.now).map_err(|e| {
                    DsmError::storage(
                        format!("chain: record generation: {e}"),
                        None::<std::io::Error>,
                    )
                })?;
                roots.push(post.root);
                chains.insert(
                    vault_id,
                    VaultChain {
                        roots: roots.clone(),
                    },
                );
            }
            Ok(VaultChain { roots })
        })
    }

    /// The post state of the exercise that consumed `current`, or `None` when
    /// nothing has consumed it yet, nothing could be read, or the consumption
    /// cannot be recomputed. Every `None` stops the chain WITHOUT refuting
    /// anything.
    fn next_generation<'s>(
        &'s self,
        vault_id: &'s D32,
        current: &'s D32,
        chains: &'s mut BTreeMap<D32, VaultChain>,
        depth: usize,
    ) -> Fut<'s, Option<VaultPostState>> {
        Box::pin(async move {
            // Two passes at most. The first can stall because a SIBLING leg's
            // parent is not established yet, which is not a fact about this
            // vault; the second runs once those chains have been walked.
            for pass in 0..2 {
                let walked = {
                    let resolver = Resolver {
                        set: self.set,
                        local: self.local,
                        parents: self.parents,
                        chains: &*chains,
                    };
                    resolver
                        .walk_parent(vault_id, current, 0, WALK_BUDGET)
                        .await?
                };
                match walked.outcome {
                    WalkOutcome::Consumed { .. } => {
                        let Some(exercise) = walked.consumed else {
                            return Ok(None);
                        };
                        return self.post_state_of(vault_id, current, &exercise).await;
                    }
                    WalkOutcome::Unresolved { attempt } if pass == 0 && depth > 0 => {
                        if !self
                            .establish_siblings(vault_id, current, attempt, chains, depth)
                            .await?
                        {
                            return Ok(None);
                        }
                    }
                    _ => return Ok(None),
                }
            }
            Ok(None)
        })
    }

    /// Recompute what `exercise` did to this vault. The post root is the
    /// fold's, over the pre state the evidence holds — never the value the
    /// producer wrote into `V°`, which is what `vault_post_states` checks.
    async fn post_state_of(
        &self,
        vault_id: &D32,
        current: &D32,
        exercise: &RecognizedExercise,
    ) -> Result<Option<VaultPostState>, DsmError> {
        let evidence = acquire_evidence(self.set, &exercise.preimage, self.local).await?;
        let Ok(posts) = vault_post_states(&exercise.precommit.body, &exercise.preimage, &evidence)
        else {
            // The evidence this verifier holds does not let it recompute the
            // consumption. The chain stops; nothing is refuted.
            return Ok(None);
        };
        Ok(posts
            .into_iter()
            .find(|p| p.vault_id == *vault_id && p.pre_root == *current))
    }

    /// Establish the parents of the OTHER legs of whatever sits at this key,
    /// so a multi-leg consumption can be classified. Returns whether anything
    /// new was established — if nothing was, retrying the walk would read the
    /// same cells and reach the same answer.
    async fn establish_siblings(
        &self,
        vault_id: &D32,
        current: &D32,
        attempt: u64,
        chains: &mut BTreeMap<D32, VaultChain>,
        depth: usize,
    ) -> Result<bool, DsmError> {
        let (_, exercise) = read_attempt_cell(self.set, vault_id, current, attempt).await?;
        let Some(exercise) = exercise else {
            return Ok(false);
        };
        let mut learned = false;
        for leg in exercise.precommit.body.legs() {
            if leg.vault_id == *vault_id || chains.contains_key(&leg.vault_id) {
                continue;
            }
            // POSITIVE evidence only for the RETRY decision: a sibling chain
            // that names the parent is new information and the walk is worth
            // repeating; one that does not name it changes no answer, so
            // repeating would read the same cells and stall the same way.
            // The chain is handed over either way — the resolver, not this
            // loop, decides what it means.
            let sibling = self.chain_to_depth(leg.vault_id, depth - 1).await?;
            learned |= sibling.names(&leg.parent_root);
            chains.insert(leg.vault_id, sibling);
        }
        Ok(learned)
    }
}

/// The recorded roots of a vault, from generation zero, stopping at the first
/// gap. A CONTIGUOUS prefix, because `roots[g]` is read positionally and a gap
/// would silently shift every generation after it.
fn stored_prefix(vault_id: &D32) -> Result<Vec<D32>, DsmError> {
    let mut roots = Vec::new();
    loop {
        let generation = roots.len() as u64;
        let found = sofi_vault_head::root_at(vault_id, generation).map_err(|e| {
            DsmError::storage(format!("chain: stored root: {e}"), None::<std::io::Error>)
        })?;
        match found {
            Some(root) => roots.push(root),
            None => return Ok(roots),
        }
    }
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)] // test asserts; a failure here is the signal
mod tests {
    use dsm::sofi::resolution::ParentStatus;
    use serial_test::serial;

    use super::*;
    use crate::sdk::sofi_test_fixtures::{block_on, signed_route};

    /// Forget what this process already recorded about a vault.
    ///
    /// The client_db is shared by every test in this binary and the fixture
    /// derives a DETERMINISTIC vault id, so a settlement an earlier test
    /// resolved leaves generations recorded against the same vault. A chain
    /// of two would then be the correct answer to a different question. These
    /// tests are about what the WALK derives from the committed set, so they
    /// start from a record that says nothing — which is also the state of any
    /// verifier that never traded with the vault.
    fn forget(vault_id: &D32) {
        let binding = crate::storage::client_db::get_connection().unwrap();
        let conn = binding.lock().unwrap();
        for table in ["sofi_vault_root", "sofi_vault_leaf"] {
            conn.execute(
                &format!("DELETE FROM {table} WHERE vault_id = ?1"),
                rusqlite::params![vault_id.as_slice()],
            )
            .unwrap();
        }
    }

    fn walker<'a>(
        r: &'a crate::sdk::sofi_test_fixtures::SignedRoute,
        parents: &'a BTreeMap<D32, ParentPosition>,
    ) -> ChainWalker<'a> {
        ChainWalker {
            set: &r.set,
            local: &r.local,
            parents,
            now: 0,
        }
    }

    /// CASE 1. The chain reaches the generation asked about and names exactly
    /// the root the leg names: canonical.
    #[test]
    #[serial]
    fn a_chain_that_names_the_claimed_root_at_that_generation_is_canonical() {
        let r = signed_route(true);
        let parents = BTreeMap::new();
        let leg = &r.precommit.legs()[0];
        forget(&leg.vault_id);
        let chain = block_on(walker(&r, &parents).chain(&leg.vault_id)).unwrap();

        assert_eq!(
            chain.roots,
            vec![leg.parent_root],
            "an untraded vault's chain is its genesis alone"
        );
        assert_eq!(chain.head(), Some((0, leg.parent_root)));
        assert_eq!(chain.generation_of(&leg.parent_root), Some(0));
        assert_eq!(
            chain.status_of(0, &leg.parent_root),
            ParentStatus::Canonical
        );
    }

    /// CASE 2. The chain reaches that generation and names a DIFFERENT root.
    /// The claimed parent is refuted, permanently — `R*_g` is unique, so no
    /// later evidence restores it.
    #[test]
    #[serial]
    fn a_different_root_at_a_generation_the_chain_reached_is_orphaned() {
        let r = signed_route(true);
        let parents = BTreeMap::new();
        let leg = &r.precommit.legs()[0];
        forget(&leg.vault_id);
        let chain = block_on(walker(&r, &parents).chain(&leg.vault_id)).unwrap();

        let impostor = [0x5A; 32];
        assert_ne!(impostor, leg.parent_root);
        assert_eq!(chain.status_of(0, &impostor), ParentStatus::Orphaned);
    }

    /// CASE 3. The chain does NOT reach that generation. It waits, and it is
    /// never orphaned — a chain may simply be short, and a head is open
    /// precisely so that the next root can still arrive. Orphaning here would
    /// be a permanent Void on a route whose only defect is that this verifier
    /// looked early.
    #[test]
    #[serial]
    fn a_generation_the_chain_did_not_reach_waits_and_is_never_orphaned() {
        let r = signed_route(true);
        let parents = BTreeMap::new();
        let leg = &r.precommit.legs()[0];
        forget(&leg.vault_id);
        let chain = block_on(walker(&r, &parents).chain(&leg.vault_id)).unwrap();

        // The chain established generation 0 and stopped at an open head.
        // Generation 1 is not refuted by that; it has not happened yet.
        for claimed in [leg.parent_root, [0x5A; 32]] {
            assert_eq!(
                chain.status_of(1, &claimed),
                ParentStatus::Unavailable,
                "a generation the chain never reached decides nothing"
            );
            assert_ne!(chain.status_of(1, &claimed), ParentStatus::Orphaned);
        }
    }

    /// The same, one step earlier: a vault whose genesis this verifier cannot
    /// even fetch has an EMPTY chain, and an empty chain refutes nothing. The
    /// failure this guards is a walker that reads "no roots" as "no other
    /// root", which would orphan every parent of every vault it cannot see.
    #[test]
    #[serial]
    fn a_vault_with_no_established_genesis_refutes_nothing() {
        let r = signed_route(true);
        let parents = BTreeMap::new();
        let stranger = [0xEE; 32];

        let chain = block_on(walker(&r, &parents).chain(&stranger)).unwrap();
        assert!(chain.roots.is_empty());
        assert_eq!(chain.head(), None);
        assert_eq!(
            chain.status_of(0, &[0x11; 32]),
            ParentStatus::Unavailable,
            "nothing established is not something refuted"
        );
    }
}
