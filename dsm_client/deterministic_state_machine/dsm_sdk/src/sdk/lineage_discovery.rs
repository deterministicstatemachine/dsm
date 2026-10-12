// SPDX-License-Identifier: Apache-2.0

//! Finding a shared lineage's history (DSM Amendment A15, SoFi Amendment
//! S23): reading the epoch index for the hints and checkpoints others
//! published, and publishing the ones this device can.
//!
//! Everything read here is discovery. A discovered root tells this device
//! where to look; it never tells it what the state is. The roots found here
//! only decide which cells and objects are read ahead of the Core walk, and
//! the walk establishes every generation exactly as it would without them.
//! Nothing in this module constructs or records an established lineage
//! (`ci/sofi_validated_root_constructors.sh` [6]).

use std::collections::{BTreeMap, BTreeSet};

use dsm::common::domain_tags::TAG_DSM_SHARED_LINEAGE_EPOCH_LOCATOR;
use dsm::shared_lineage::{
    epoch_locator, epoch_of, CheckpointV1, GenerationChain, GenerationHintV1, LineageKind,
    LineageObject, TransitionBundleV1, EPOCH_GENERATIONS,
};
use dsm::sofi::storage::Discovered;
use dsm::types::error::DsmError;

use crate::sdk::storage_io::resolve_locator_all;
use crate::sdk::storage_set::StorageSet;

type D32 = [u8; 32];

/// Hints and checkpoints read per epoch. An epoch holds 32 generations, so an
/// honest epoch holds 32 hints and a checkpoint or two; past this bound the
/// epoch's discovery is unavailable, which costs speed and nothing else.
pub(crate) const CANDIDATES_PER_EPOCH: usize = 96;

/// Epochs read past the one this device stands in. Hints anyone may append
/// can name any generation: a hint naming generation 1,000,000 is a place to
/// look, and this bound is how far looking goes in one discovery.
pub(crate) const EPOCHS_PER_DISCOVERY: u64 = 64;

/// What the epoch index held for a lineage, from the generation this device
/// stands at onward. Discovery only.
#[derive(Debug, Default)]
pub(crate) struct Candidates {
    /// The roots someone claims each generation has, by generation.
    roots: BTreeMap<u64, BTreeSet<D32>>,
    /// The checkpoints found.
    checkpoints: Vec<CheckpointV1>,
    /// The generations some hint was found for.
    hinted: BTreeSet<u64>,
    /// The epochs whose index could not be read in full.
    unavailable: BTreeSet<u64>,
}

impl Candidates {
    /// The roots someone claims generation `g` has.
    pub(crate) fn roots_at(&self, generation: u64) -> impl Iterator<Item = &D32> {
        self.roots.get(&generation).into_iter().flatten()
    }

    /// Every generation some candidate root was found for, in order.
    pub(crate) fn generations(&self) -> impl Iterator<Item = u64> + '_ {
        self.roots.keys().copied()
    }

    pub(crate) fn checkpoints(&self) -> &[CheckpointV1] {
        &self.checkpoints
    }

    /// Whether some hint names generation `g`.
    pub(crate) fn hinted(&self, generation: u64) -> bool {
        self.hinted.contains(&generation)
    }

    fn add(&mut self, object: LineageObject) {
        match object {
            LineageObject::Hint(hint) => {
                self.hinted.insert(hint.generation());
                self.roots
                    .entry(hint.generation())
                    .or_default()
                    .insert(*hint.claimed_root());
            }
            LineageObject::Checkpoint(checkpoint) => {
                for (offset, root) in checkpoint.claimed_roots().iter().enumerate() {
                    self.roots
                        .entry(checkpoint.start_generation() + offset as u64)
                        .or_default()
                        .insert(*root);
                }
                self.checkpoints.push(checkpoint);
            }
        }
    }
}

/// Whether an epoch's index was read in full.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Completeness {
    Complete,
    Partial,
}

/// One epoch's index, read: the hints and checkpoints of this lineage it
/// holds, and whether that is all of them.
struct EpochRead {
    objects: Vec<LineageObject>,
    completeness: Completeness,
}

fn belongs(object: &LineageObject, kind: LineageKind, lineage_id: &D32, epoch: u64) -> bool {
    match object {
        LineageObject::Hint(hint) => {
            hint.kind() == kind
                && hint.lineage_id() == lineage_id
                && epoch_of(hint.generation()) == epoch
        }
        LineageObject::Checkpoint(checkpoint) => {
            checkpoint.kind() == kind
                && checkpoint.lineage_id() == lineage_id
                && epoch_of(checkpoint.start_generation()) == epoch
        }
    }
}

async fn read_epoch(
    set: &StorageSet,
    kind: LineageKind,
    lineage_id: &D32,
    epoch: u64,
) -> EpochRead {
    let locator = epoch_locator(kind, lineage_id, epoch);
    let read = resolve_locator_all(
        set,
        TAG_DSM_SHARED_LINEAGE_EPOCH_LOCATOR.source_bytes(),
        &locator,
        CANDIDATES_PER_EPOCH,
        |bytes| match LineageObject::recognize(bytes) {
            Ok(object) => belongs(&object, kind, lineage_id, epoch).then_some((locator, object)),
            Err(refused) => {
                log::debug!("[lineage discovery] not a hint or checkpoint: {refused}");
                None
            }
        },
    )
    .await;
    match read {
        Ok(Discovered::Complete(objects)) => EpochRead {
            objects,
            completeness: Completeness::Complete,
        },
        Ok(Discovered::Partial(objects)) => EpochRead {
            objects,
            completeness: Completeness::Partial,
        },
        Err(e) => {
            log::info!("[lineage discovery] epoch {epoch} unreadable: {e}");
            EpochRead {
                objects: Vec::new(),
                completeness: Completeness::Partial,
            }
        }
    }
}

/// The hints and checkpoints of `(kind, lineage_id)` from `from_generation`'s
/// epoch onward.
///
/// The epochs are probed at `e, e + 1, e + 2, e + 4, …` until one holds
/// nothing of this lineage, the highest populated one is found by bisection,
/// and every epoch up to it is read at once: the reads waited on in sequence
/// grow with the logarithm of the history, not with its length. At most
/// [`EPOCHS_PER_DISCOVERY`] epochs past the first are read; beyond them
/// discovery is unavailable, never "no later generation".
pub(crate) async fn discover(
    set: &StorageSet,
    kind: LineageKind,
    lineage_id: &D32,
    from_generation: u64,
) -> Candidates {
    let first = epoch_of(from_generation);
    let last_allowed = first.saturating_add(EPOCHS_PER_DISCOVERY);
    let mut read: BTreeMap<u64, EpochRead> = BTreeMap::new();
    let populated = |r: &EpochRead| !r.objects.is_empty();

    let first_read = read_epoch(set, kind, lineage_id, first).await;
    let mut low = first;
    let first_populated = populated(&first_read);
    read.insert(first, first_read);
    if first_populated {
        // Probe forward, doubling, to an epoch holding nothing of it.
        let mut step = 1u64;
        let mut high = None;
        while high.is_none() {
            let e = first.saturating_add(step).min(last_allowed);
            let r = read_epoch(set, kind, lineage_id, e).await;
            let found = populated(&r);
            read.insert(e, r);
            if !found {
                high = Some(e);
            } else if e >= last_allowed {
                low = e;
                break;
            } else {
                low = e;
                step = step.saturating_mul(2);
            }
        }
        // Bisect between the highest populated epoch and the first empty one.
        if let Some(mut high) = high {
            while high - low > 1 {
                let mid = low + (high - low) / 2;
                let r = read_epoch(set, kind, lineage_id, mid).await;
                let found = populated(&r);
                read.insert(mid, r);
                if found {
                    low = mid;
                } else {
                    high = mid;
                }
            }
        }
        // Every epoch up to the highest populated one, at once.
        let missing: Vec<u64> = (first..=low).filter(|e| !read.contains_key(e)).collect();
        let reads = futures::future::join_all(
            missing
                .iter()
                .map(|e| read_epoch(set, kind, lineage_id, *e)),
        )
        .await;
        for (e, r) in missing.into_iter().zip(reads) {
            read.insert(e, r);
        }
    }

    let mut candidates = Candidates::default();
    for (epoch, r) in read {
        if r.completeness == Completeness::Partial {
            candidates.unavailable.insert(epoch);
        }
        for object in r.objects {
            candidates.add(object);
        }
    }
    log::info!(
        "[lineage discovery] {kind:?} {}: {} generations named from {from_generation}, {} \
         checkpoints, {} epochs unavailable",
        crate::util::text_id::encode_base32_crockford(&lineage_id[..5]),
        candidates.roots.len(),
        candidates.checkpoints.len(),
        candidates.unavailable.len()
    );
    candidates
}

/// Owe the epoch index a hint for every generation of `chain` in the epochs
/// discovery read from `from` on that no hint was found for;
/// `step_digests[g]` is generation `g`'s step digest. The sweep publishes
/// what is owed (`artifact_republish::publish_lineage_debt`). Returns how
/// many hints are newly owed.
pub(crate) fn owe_missing_hints(
    set_id: &D32,
    chain: &GenerationChain,
    step_digests: &BTreeMap<u64, D32>,
    found: &Candidates,
    from: u64,
) -> Result<usize, DsmError> {
    let head = chain.head();
    let first_read = epoch_of(from) * EPOCH_GENERATIONS;
    let mut owed = 0usize;
    for (generation, step) in step_digests {
        if *generation == 0
            || *generation < first_read
            || *generation > head.generation()
            || found.hinted(*generation)
        {
            continue;
        }
        let hint = GenerationHintV1::of_established(chain, *generation, *step)
            .map_err(|e| lineage_err("hint", e))?;
        owe(
            set_id,
            &hint.encode(),
            hint.claimed_root(),
            Some(&epoch_locator(
                head.kind(),
                head.lineage_id(),
                epoch_of(*generation),
            )),
        )?;
        owed += 1;
    }
    Ok(owed)
}

/// Owe the checkpoint, and its bundle, of the segment of `chain` that starts
/// at `start`, when no checkpoint was found for it.
pub(crate) fn owe_checkpoint(
    set_id: &D32,
    chain: &GenerationChain,
    bundle: &TransitionBundleV1,
    start: u64,
    found: &Candidates,
) -> Result<usize, DsmError> {
    if found
        .checkpoints()
        .iter()
        .any(|c| c.start_generation() == start)
    {
        return Ok(0);
    }
    let head = chain.head();
    let missing = |g: u64| lineage_err("checkpoint", format!("generation {g} is not established"));
    let end = start + EPOCH_GENERATIONS;
    let mut roots = Vec::with_capacity(EPOCH_GENERATIONS as usize + 1);
    for g in start..=end {
        roots.push(chain.at(g).ok_or_else(|| missing(g))?.0);
    }
    let checkpoint = CheckpointV1::new(
        head.kind(),
        *head.lineage_id(),
        start,
        chain.at(start).ok_or_else(|| missing(start))?.1,
        chain.at(end).ok_or_else(|| missing(end))?.1,
        roots,
        bundle.address(),
    )
    .map_err(|e| lineage_err("checkpoint", e))?;
    let end_root = chain.at(end).ok_or_else(|| missing(end))?.0;
    owe(set_id, &bundle.encode(), &end_root, None)?;
    owe(
        set_id,
        &checkpoint.encode(),
        &end_root,
        Some(&epoch_locator(
            head.kind(),
            head.lineage_id(),
            epoch_of(start),
        )),
    )?;
    Ok(1)
}

fn owe(
    set_id: &D32,
    bytes: &[u8],
    bound_root: &D32,
    locator: Option<&D32>,
) -> Result<(), DsmError> {
    let key = crate::sdk::economic_registers::immutable_object_key(
        dsm::common::domain_tags::TAG_DSM_SHARED_LINEAGE_OBJECT,
        bytes,
    );
    crate::storage::client_db::lineage_publication::owe(set_id, &key, bytes, bound_root, locator)
        .map_err(|e| lineage_err("owe", e))
}

fn lineage_err(what: &str, e: impl core::fmt::Display) -> DsmError {
    DsmError::storage(
        format!("shared lineage {what}: {e}"),
        None::<std::io::Error>,
    )
}

#[cfg(test)]
mod tests {
    /// Discovery carries no authority (DSM Amendment A15): the code that
    /// reads hints and checkpoints names nothing that constructs or records
    /// established state, and the vault walk with its history read ahead
    /// builds, extends and records no chain itself — `Verifier::chain` does.
    #[test]
    fn discovery_code_names_no_constructor_of_established_state() {
        let discovery = include_str!("lineage_discovery.rs");
        let tests_start = discovery
            .find("#[cfg(test)]")
            .expect("this module has tests");
        let discovery = &discovery[..tests_start];
        for forbidden in [
            "VaultChain",
            "from_recorded",
            "record_generation",
            "record_walked",
            "record_final_release",
            "NativeReserveState",
            "ValidatedEconomicRoot",
        ] {
            assert!(
                !discovery.contains(forbidden),
                "lineage_discovery names {forbidden}"
            );
        }
        let vault_history = include_str!("vault_history.rs");
        for forbidden in [
            "from_recorded",
            "VaultChain::",
            ".extend(&",
            "record_generation",
            "record_walked",
            "record_resolved",
        ] {
            assert!(
                !vault_history.contains(forbidden),
                "vault_history names {forbidden}"
            );
        }
    }
}
