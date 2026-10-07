// SPDX-License-Identifier: Apache-2.0

//! A vault's chain, walked with its history read ahead (SoFi Amendment S23,
//! a vault as a shared lineage of kind 1).
//!
//! Before the walk, the epoch index names the roots others say the vault's
//! generations have. The consumption cell of each named root is read at once
//! through the verifier's own `read_attempt_cell` — Core keeps a cell only
//! when it reads it final there — and each final exercise's trader position
//! is checked at once through the same one-hop checks the walk runs, which
//! keep what they establish. Then `Verifier::chain` walks exactly as before,
//! from the vault's accepted genesis, one consumption at a time. A named root
//! decides only what is read early; the walk decides what the state is.
//! Afterwards, the hints nobody published for what the walk established are
//! owed, and the storage sweep publishes them.

use std::collections::{BTreeMap, BTreeSet};

use dsm::route_chain::{CellFact, ChainState};
use dsm::shared_lineage::{vault_step_digest, GenerationChain, LineageKind, SharedGenesisV1};
use dsm::sofi::resolution::VaultChain;
use dsm::sofi::resolve::{SofiReads, VaultGenesis, Verifier};
use dsm::sofi::storage::Resolved;
use dsm::types::error::DsmError;

use crate::sdk::lineage_discovery::{self, Candidates};
use crate::sdk::sofi_reads::{verifier_error, LiveSofiReads};
use crate::sdk::storage_set::StorageSet;
use crate::storage::client_db::sofi_vault_head;

type D32 = [u8; 32];

/// Roots whose cells are read at once.
const ROOTS_AT_ONCE: usize = 32;

/// What the epoch index named for one vault, from the generation this device
/// stands at. Discovery only.
pub(crate) struct VaultHistory {
    vault_id: D32,
    from: u64,
    candidates: Candidates,
}

/// The epoch index of `vault_id` from the generation this device established
/// last (zero when it established none).
pub(crate) async fn discover(set: &StorageSet, vault_id: &D32) -> Result<VaultHistory, DsmError> {
    let from = sofi_vault_head::head(vault_id)
        .map_err(|e| DsmError::storage(format!("vault head: {e}"), None::<std::io::Error>))?
        .map_or(0, |head| head.generation);
    let candidates = lineage_discovery::discover(set, LineageKind::Vault, vault_id, from).await;
    Ok(VaultHistory {
        vault_id: *vault_id,
        from,
        candidates,
    })
}

/// Each of `vault_ids`' histories, discovered at once.
pub(crate) async fn discover_all(
    set: &StorageSet,
    vault_ids: &[D32],
) -> Vec<Result<VaultHistory, DsmError>> {
    futures::future::join_all(vault_ids.iter().map(|vault_id| discover(set, vault_id))).await
}

/// What reading ahead came to: reports only, nothing a walk stands on.
#[derive(Debug, Default)]
struct ReadAhead {
    cells: usize,
    final_cells: usize,
    positions: usize,
    not_read: Vec<String>,
}

impl core::fmt::Display for ReadAhead {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "{} cells read ahead, {} final, {} trader positions checked, {} not read",
            self.cells,
            self.final_cells,
            self.positions,
            self.not_read.len()
        )?;
        if let Some(first) = self.not_read.first() {
            write!(f, " (first: {first})")?;
        }
        Ok(())
    }
}

/// One named root's cell, and what reading it ahead established.
enum RootRead {
    Final {
        positions: usize,
        not_read: Vec<String>,
    },
    NotFinal,
    NotRead(String),
}

/// Read the consumption cell at `root` (attempt 0) through the verifier, and
/// when an exercise holds it final, check the exercise's trader positions.
fn read_root(verifier: &Verifier<'_, LiveSofiReads<'_>>, vault_id: &D32, root: &D32) -> RootRead {
    let read = match verifier.read_attempt_cell(vault_id, root, 0) {
        Ok(Ok(read)) => read,
        Ok(Err(missing)) => return RootRead::NotRead(format!("{missing:?}")),
        Err(failure) => return RootRead::NotRead(failure.to_string()),
    };
    if !matches!(
        read.fact(),
        CellFact::Held {
            state: ChainState::Final,
            ..
        }
    ) {
        return RootRead::NotFinal;
    }
    let Some(exercise) = read.exercise() else {
        return RootRead::NotFinal;
    };
    let precommit = &exercise.precommit().body;
    let (genesis, device_id) = (precommit.genesis(), precommit.device_id());
    // The position's registration (R10), the trader at the parent its `P`
    // names, and the claims its setups name: each one hop, at once.
    let checks: Vec<Vec<Result<(), String>>> = std::thread::scope(|scope| {
        let registration = scope.spawn(|| {
            vec![match verifier.read_registration(
                genesis,
                device_id,
                exercise.fulfillment().body.position(),
                precommit.void_root(),
            ) {
                Ok(Ok(..)) => Ok(()),
                Ok(Err(missing)) => Err(format!("{missing:?}")),
                Err(failure) => Err(failure.to_string()),
            }]
        });
        let parent = scope.spawn(|| {
            vec![verifier
                .reads
                .trader_root_at(genesis, device_id, precommit.position())
                .map(drop)
                .map_err(|failure| failure.to_string())]
        });
        let setups = scope.spawn(|| {
            precommit
                .legs()
                .iter()
                .filter(|leg| leg.vault_id == *vault_id)
                .map(|leg| match verifier.reads.setup_bytes(&leg.setup_ref) {
                    Ok(Resolved::Kept(bytes)) => {
                        match dsm::sofi::publication::recognize_setup(&bytes) {
                            Some((.., setup)) => verifier
                                .reads
                                .accepted_claim_at(genesis, device_id, setup.body.position())
                                .map(drop)
                                .map_err(|failure| failure.to_string()),
                            None => Err("the setup bytes are no setup".to_string()),
                        }
                    }
                    Ok(..) => Err("the setup is not established yet".to_string()),
                    Err(failure) => Err(failure.to_string()),
                })
                .collect::<Vec<_>>()
        });
        [registration, parent, setups]
            .into_iter()
            .map(|check| match check.join() {
                Ok(outcomes) => outcomes,
                Err(panic) => std::panic::resume_unwind(panic),
            })
            .collect()
    });
    let mut positions = 0usize;
    let mut not_read = Vec::new();
    for outcome in checks.into_iter().flatten() {
        match outcome {
            Ok(()) => positions += 1,
            Err(why) => not_read.push(why),
        }
    }
    RootRead::Final {
        positions,
        not_read,
    }
}

/// Read ahead the roots `history` names from the generation this device
/// stands at — `start_root` first — whose successors it names too, up to
/// [`ROOTS_AT_ONCE`] at once.
fn read_ahead(
    verifier: &Verifier<'_, LiveSofiReads<'_>>,
    history: &VaultHistory,
    start_root: &D32,
) -> ReadAhead {
    // A root's cell is read ahead only when the index names the generation
    // after it: that cell was consumed. The newest named root's cell is the
    // likely open head, which the walk reads itself, and an open cell read
    // twice is read twice for nothing.
    let named = |generation: u64| history.candidates.roots_at(generation).next().is_some();
    let mut roots: BTreeSet<D32> = BTreeSet::new();
    if named(history.from + 1) {
        roots.insert(*start_root);
    }
    for generation in history
        .candidates
        .generations()
        .filter(|g| *g > history.from && named(g + 1))
    {
        roots.extend(history.candidates.roots_at(generation).copied());
    }
    let roots: Vec<D32> = roots.into_iter().collect();
    let mut report = ReadAhead::default();
    for chunk in roots.chunks(ROOTS_AT_ONCE) {
        let reads: Vec<RootRead> = std::thread::scope(|scope| {
            let handles: Vec<_> = chunk
                .iter()
                .map(|root| scope.spawn(move || read_root(verifier, &history.vault_id, root)))
                .collect();
            handles
                .into_iter()
                .map(|handle| match handle.join() {
                    Ok(read) => read,
                    Err(panic) => std::panic::resume_unwind(panic),
                })
                .collect()
        });
        for read in reads {
            report.cells += 1;
            match read {
                RootRead::Final {
                    positions,
                    not_read,
                } => {
                    report.final_cells += 1;
                    report.positions += positions;
                    report.not_read.extend(not_read);
                }
                RootRead::NotFinal => {}
                RootRead::NotRead(why) => report.not_read.push(why),
            }
        }
    }
    report
}

/// `history`'s vault walked from its accepted genesis by `Verifier::chain`,
/// with what the epoch index named read ahead. Call from a thread that may
/// block (inside `block_in_place`, or a thread of its own).
pub(crate) fn walk(
    set: &StorageSet,
    verifier: &Verifier<'_, LiveSofiReads<'_>>,
    history: &VaultHistory,
) -> Result<VaultChain, DsmError> {
    let genesis = match verifier
        .vault_genesis(&history.vault_id)
        .map_err(verifier_error)?
    {
        VaultGenesis::Accepted(accepted) => accepted,
        // Not established: the walk itself says what that means.
        _ => return verifier.chain(&history.vault_id).map_err(verifier_error),
    };
    let start_root = match sofi_vault_head::head(&history.vault_id)
        .map_err(|e| DsmError::storage(format!("vault head: {e}"), None::<std::io::Error>))?
    {
        Some(head) => head.root,
        None => *genesis.genesis_root(),
    };
    let report = read_ahead(verifier, history, &start_root);
    log::info!(
        "[vault history] {}: {report}",
        crate::util::text_id::encode_base32_crockford(&history.vault_id[..5])
    );
    let chain = verifier.chain(&history.vault_id).map_err(verifier_error)?;
    owe_hints(set, verifier, history, &genesis)?;
    Ok(chain)
}

/// Owe the epoch index a hint for every generation this device established
/// that the index named no hint for, and start the sweep that publishes
/// them.
fn owe_hints(
    set: &StorageSet,
    verifier: &Verifier<'_, LiveSofiReads<'_>>,
    history: &VaultHistory,
    genesis: &dsm::sofi::lineage::AcceptedVaultGenesis,
) -> Result<usize, DsmError> {
    let preimage = genesis
        .preimage()
        .encode()
        .map_err(|e| DsmError::storage(format!("vault genesis: {e}"), None::<std::io::Error>))?;
    let shared = SharedGenesisV1::new(
        LineageKind::Vault,
        history.vault_id,
        *genesis.genesis_root(),
        dsm::storage_object::immutable_addr(
            dsm::common::domain_tags::TAG_DSM_SOFI_VAULT_GENESIS_OBJECT,
            &preimage,
        ),
    );
    let mut chain = GenerationChain::from_genesis(&shared);
    let mut steps = BTreeMap::new();
    let rows = verifier
        .reads
        .recorded_generations(&history.vault_id)
        .map_err(|e| {
            DsmError::storage(
                format!("recorded generations: {e:?}"),
                None::<std::io::Error>,
            )
        })?;
    for row in rows.iter().filter(|row| row.generation > 0) {
        if row.generation != chain.head().generation() + 1 {
            break;
        }
        let Some(consumed_by) = row.consumed_by else {
            break;
        };
        let step = vault_step_digest(&consumed_by);
        chain.push(row.root, step).map_err(|e| {
            DsmError::storage(
                format!("vault generation chain: {e}"),
                None::<std::io::Error>,
            )
        })?;
        steps.insert(row.generation, step);
    }
    let owed = lineage_discovery::owe_missing_hints(
        &set.id(),
        &chain,
        &steps,
        &history.candidates,
        history.from,
    )?;
    if owed > 0 {
        crate::handlers::artifact_republish::spawn_frozen_artifact_republish("vault history");
    }
    Ok(owed)
}
