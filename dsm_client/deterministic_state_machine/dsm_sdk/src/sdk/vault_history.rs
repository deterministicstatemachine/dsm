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
//! owed, with the checkpoint and bundle of each complete segment nobody
//! published one for, and the storage sweep publishes them. The trader whose
//! position resolves Realized owes its own generation's the same way, once
//! the position is committed ([`owe_realized`]).

use std::collections::{BTreeMap, BTreeSet};

use dsm::route_chain::{CellFact, ChainState};
use dsm::shared_lineage::{GenerationChain, LineageKind, TransitionBundleV1, EPOCH_GENERATIONS};
use dsm::sofi::resolution::VaultChain;
use dsm::sofi::resolve::{SofiReads, VaultGenesis, Verifier};
use dsm::sofi::storage::Resolved;
use dsm::sofi::validation::VaultPostState;
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

/// The epoch index of `vault_id` from the generation a walk of it starts at:
/// the owner baseline this device adopted, or the genesis. This device's
/// record says which, and says only where to look.
pub(crate) async fn discover(set: &StorageSet, vault_id: &D32) -> Result<VaultHistory, DsmError> {
    let from = sofi_vault_head::recorded_generations(vault_id)
        .map_err(|e| DsmError::storage(format!("vault record: {e}"), None::<std::io::Error>))?
        .first()
        .map_or(0, |row| row.generation);
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

/// Read ahead the roots `history` names from the generation a walk starts
/// at, whose successors it names too, and the roots this device recorded
/// whose successors it recorded, up to [`ROOTS_AT_ONCE`] at once. A recorded
/// root, like a named one, decides only what is read early.
fn read_ahead(
    verifier: &Verifier<'_, LiveSofiReads<'_>>,
    history: &VaultHistory,
    recorded: &[sofi_vault_head::RecordedGenerationRow],
) -> ReadAhead {
    // A root's cell is read ahead only when the index names the generation
    // after it: that cell was consumed. The newest named root's cell is the
    // likely open head, which the walk reads itself, and an open cell read
    // twice is read twice for nothing.
    let named = |generation: u64| history.candidates.roots_at(generation).next().is_some();
    let mut roots: BTreeSet<D32> = BTreeSet::new();
    // At most as many as one walk reads ahead (SA-69), of each.
    for (_, root) in history
        .candidates
        .named_from(history.from)
        .into_iter()
        .filter(|(generation, _)| named(generation + 1))
    {
        roots.insert(root);
    }
    for pair in recorded
        .windows(2)
        .take(lineage_discovery::NAMED_READS_PER_WALK)
    {
        roots.insert(pair[0].root);
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
    history: &mut VaultHistory,
) -> Result<VaultChain, DsmError> {
    let genesis = match verifier
        .vault_genesis(&history.vault_id)
        .map_err(verifier_error)?
    {
        VaultGenesis::Accepted(accepted) => accepted,
        // Not established: the walk itself says what that means.
        _ => return verifier.chain(&history.vault_id).map_err(verifier_error),
    };
    // A checkpoint names cells to read only for the segment that starts at
    // a head Core established (SA-69). Before the walk, Core has established
    // the genesis: nothing this device recorded is a head (MR-DSM-0331).
    let lineage_genesis = dsm::sofi::resolution::vault_lineage_genesis(&history.vault_id, &genesis)
        .map_err(|e| DsmError::storage(format!("vault genesis: {e}"), None::<std::io::Error>))?;
    history
        .candidates
        .admit_checkpoints(&GenerationChain::from_genesis(&lineage_genesis).head());
    let recorded = sofi_vault_head::recorded_generations(&history.vault_id)
        .map_err(|e| DsmError::storage(format!("vault record: {e}"), None::<std::io::Error>))?;
    let report = read_ahead(verifier, history, &recorded);
    log::info!(
        "[vault history] {}: {report}",
        crate::util::text_id::encode_base32_crockford(&history.vault_id[..5])
    );
    let chain = verifier.chain(&history.vault_id).map_err(verifier_error)?;
    // The walk's outcome names every generation of this device's record it
    // replaced with what Core established (MR-DSM-0331): never silent, and
    // never a verdict on the vault.
    match verifier
        .replaced_records()
        .map_err(verifier_error)?
        .as_slice()
    {
        [] => {}
        replaced => log::warn!(
            "[vault history] {}: the walk replaced {} contradicted generation(s) of this \
             device's record: {}",
            crate::util::text_id::encode_base32_crockford(&history.vault_id[..5]),
            replaced.len(),
            replaced
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("; ")
        ),
    }
    // What the walk established from the genesis: a chain from an adopted
    // baseline holds no generation digest from the genesis, and owes none.
    let Some((walked, steps)) = chain
        .generation_chain(&history.vault_id, &genesis)
        .map_err(|e| {
            DsmError::storage(
                format!("vault generation chain: {e:?}"),
                None::<std::io::Error>,
            )
        })?
    else {
        return Ok(chain);
    };
    // A checkpoint whose end the walk did not reproduce is discarded (SoFi
    // Amendment S23, step 4).
    let settled = history.candidates.settle_checkpoints(&walked);
    log::info!(
        "[vault history] checkpoints after the walk: {} borne out, {} discarded",
        settled.borne_out,
        settled.discarded
    );
    owe_lineage(set, history, &chain, &walked, &steps)?;
    Ok(chain)
}

/// Owe the epoch index a hint for every generation this device established
/// that the index named no hint for, and the checkpoint and bundle of every
/// complete segment it named no checkpoint for; then start the sweep that
/// publishes them.
fn owe_lineage(
    set: &StorageSet,
    history: &VaultHistory,
    walked: &VaultChain,
    chain: &GenerationChain,
    steps: &BTreeMap<u64, D32>,
) -> Result<usize, DsmError> {
    let set_id = set.id();
    let mut owed = lineage_discovery::owe_missing_hints(
        &set_id,
        chain,
        steps,
        &history.candidates,
        history.from,
    )?;
    let head = chain.head().generation();
    let mut start = history.from - history.from % EPOCH_GENERATIONS;
    while start + EPOCH_GENERATIONS <= head {
        if let Some(bundle) = segment_bundle(walked, chain, start)? {
            owed += lineage_discovery::owe_checkpoint(
                &set_id,
                chain,
                &bundle,
                start,
                &history.candidates,
            )?;
        }
        start += EPOCH_GENERATIONS;
    }
    if owed > 0 {
        crate::handlers::artifact_republish::spawn_frozen_artifact_republish("vault history");
    }
    Ok(owed)
}

/// What the trader whose position resolved Realized owes for each vault
/// generation `g` it made (SoFi Amendment S23, "who writes"): the hint for
/// `g` and, when `g` is a positive multiple of 32, the checkpoint and bundle
/// of the segment that ends at `g`. Called once the position is committed,
/// never on its path; anything it does not owe, a later walk owes. The
/// digests come from Core's walk of the vault up to the generation's root; a
/// vault this device walks from an owner baseline holds no digest at `g`
/// from its genesis, and nothing is owed for it.
pub(crate) fn owe_realized(
    set: &StorageSet,
    verifier: &Verifier<'_, LiveSofiReads<'_>>,
    heads: &[VaultPostState],
) -> Result<usize, DsmError> {
    let set_id = set.id();
    let mut owed = 0usize;
    for post in heads {
        let vault_id = post.vault_id();
        let generation = post.generation();
        let VaultGenesis::Accepted(genesis) =
            verifier.vault_genesis(vault_id).map_err(verifier_error)?
        else {
            return Err(DsmError::storage(
                "a vault this position realized through has no accepted genesis",
                None::<std::io::Error>,
            ));
        };
        let walked = verifier
            .chain_until(vault_id, post.root())
            .map_err(verifier_error)?;
        let Some((chain, steps)) = walked.generation_chain(vault_id, &genesis).map_err(|e| {
            DsmError::storage(
                format!("vault generation chain: {e:?}"),
                None::<std::io::Error>,
            )
        })?
        else {
            continue;
        };
        if chain.head().generation() < generation {
            log::info!(
                "[vault history] {}: the walk stands at {}, below {generation}; nothing owed \
                 for it",
                crate::util::text_id::encode_base32_crockford(&vault_id[..5]),
                chain.head().generation()
            );
            continue;
        }
        let none_found = Candidates::default();
        let own: BTreeMap<u64, D32> = steps
            .get(&generation)
            .map(|step| (generation, *step))
            .into_iter()
            .collect();
        owed +=
            lineage_discovery::owe_missing_hints(&set_id, &chain, &own, &none_found, generation)?;
        if generation % EPOCH_GENERATIONS == 0 {
            let start = generation - EPOCH_GENERATIONS;
            if let Some(bundle) = segment_bundle(&walked, &chain, start)? {
                owed += lineage_discovery::owe_checkpoint(
                    &set_id,
                    &chain,
                    &bundle,
                    start,
                    &none_found,
                )?;
            }
        }
    }
    if owed > 0 {
        crate::handlers::artifact_republish::spawn_frozen_artifact_republish("realized vaults");
    }
    Ok(owed)
}

/// The bundle of the segment of the vault starting at `start`: each
/// generation's step as Core derived it from the exercise that built it,
/// taken from the chain Core's walk established (`walked`) and from nothing
/// this device recorded. `None` when the walk did not reach the segment's
/// end.
fn segment_bundle(
    walked: &VaultChain,
    chain: &GenerationChain,
    start: u64,
) -> Result<Option<TransitionBundleV1>, DsmError> {
    let Some(steps) = walked.bundle_steps(start, EPOCH_GENERATIONS) else {
        return Ok(None);
    };
    TransitionBundleV1::new(
        LineageKind::Vault,
        *chain.head().lineage_id(),
        start,
        steps.to_vec(),
    )
    .map(Some)
    .map_err(|e| {
        DsmError::storage(
            format!("vault segment: bundle: {e}"),
            None::<std::io::Error>,
        )
    })
}
