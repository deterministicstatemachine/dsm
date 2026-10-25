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
    epoch_locator, epoch_of, CheckpointV1, EstablishedSharedHead, GenerationChain,
    GenerationHintV1, LineageKind, LineageObject, TransitionBundleV1, EPOCH_GENERATIONS,
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

/// Named roots one walk reads ahead: one for each generation a discovery
/// reads, the most an honest index names. Past it the walk reads each cell
/// when it reaches it, which costs speed and nothing else (SA-69).
pub(crate) const NAMED_READS_PER_WALK: usize =
    ((EPOCHS_PER_DISCOVERY + 1) * EPOCH_GENERATIONS) as usize;

/// What the epoch index held for a lineage, from the generation this device
/// stands at onward. Discovery only.
#[derive(Debug, Default)]
pub(crate) struct Candidates {
    /// The roots someone claims each generation has, by generation: what the
    /// hints name, and what each checkpoint admitted at a head this device
    /// established names.
    roots: BTreeMap<u64, BTreeSet<D32>>,
    /// The checkpoints found, admitted or not. Anyone may append one naming
    /// any 33 roots, so a checkpoint's roots are read only once it is
    /// eligible at a head this device established (SoFi Amendment S23,
    /// "a fresh reader", step 2; SA-69).
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

    pub(crate) fn checkpoints(&self) -> &[CheckpointV1] {
        &self.checkpoints
    }

    /// Whether some hint names generation `g`.
    pub(crate) fn hinted(&self, generation: u64) -> bool {
        self.hinted.contains(&generation)
    }

    /// The roots a walk reads ahead from generation `from` on, generation by
    /// generation, at most [`NAMED_READS_PER_WALK`] of them.
    pub(crate) fn named_from(&self, from: u64) -> Vec<(u64, D32)> {
        self.roots
            .range(from..)
            .flat_map(|(generation, roots)| roots.iter().map(move |root| (*generation, *root)))
            .take(NAMED_READS_PER_WALK)
            .collect()
    }

    /// Name the roots of every checkpoint found for the segment that starts
    /// at `head`, a head this device's own walk established: its lineage,
    /// start generation, start digest and start root are the head's
    /// (`CheckpointV1::eligible_at`). Any other checkpoint names nothing.
    /// Returns how many were admitted.
    pub(crate) fn admit_checkpoints(&mut self, head: &EstablishedSharedHead) -> usize {
        let mut admitted = 0usize;
        for checkpoint in &self.checkpoints {
            if let Err(why) = checkpoint.eligible_at(head) {
                log::debug!("[lineage discovery] a checkpoint not taken: {why:?}");
                continue;
            }
            for (offset, root) in checkpoint.claimed_roots().iter().enumerate() {
                self.roots
                    .entry(checkpoint.start_generation() + offset as u64)
                    .or_default()
                    .insert(*root);
            }
            admitted += 1;
        }
        admitted
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
            LineageObject::Checkpoint(checkpoint) => self.checkpoints.push(checkpoint),
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
/// at `start`, unless that very checkpoint was found. Another checkpoint for
/// the same start, which anyone may append, is not the segment's own.
pub(crate) fn owe_checkpoint(
    set_id: &D32,
    chain: &GenerationChain,
    bundle: &TransitionBundleV1,
    start: u64,
    found: &Candidates,
) -> Result<usize, DsmError> {
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
    if found.checkpoints().contains(&checkpoint) {
        return Ok(0);
    }
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
    use super::*;
    use dsm::shared_lineage::{BundleStep, SharedGenesisV1};

    const LINEAGE: D32 = [0x31; 32];

    /// A reserve lineage `generations` long, as a walk would establish it.
    fn chain_of(generations: u64) -> GenerationChain {
        let genesis = SharedGenesisV1::new(LineageKind::Reserve, LINEAGE, [0x30; 32], [0x2F; 32]);
        let mut chain = GenerationChain::from_genesis(&genesis);
        for g in 1..=generations {
            chain
                .push([g as u8; 32], [0x80 | g as u8; 32])
                .expect("the next generation");
        }
        chain
    }

    /// A checkpoint whose first root is `first` and whose other 32 roots are
    /// made up from `fill`.
    fn checkpoint(
        kind: LineageKind,
        lineage_id: D32,
        start: u64,
        start_digest: D32,
        first: D32,
        fill: u8,
    ) -> CheckpointV1 {
        let mut roots = vec![first];
        for i in 1..=EPOCH_GENERATIONS {
            let mut root = [fill; 32];
            root[0] = i as u8;
            roots.push(root);
        }
        CheckpointV1::new(
            kind,
            lineage_id,
            start,
            start_digest,
            [0x7A; 32],
            roots,
            [0x7B; 32],
        )
        .expect("a checkpoint")
    }

    /// SA-69. Anyone may append a checkpoint naming any 33 roots, and every
    /// root a walk is handed is a cell it reads. A checkpoint names roots
    /// only for the segment that starts at a head this device established —
    /// its lineage, start, start digest and start root (S23, a fresh reader,
    /// step 2). One for another lineage, another kind, another start, or with
    /// the wrong digest or root names nothing, and none names anything
    /// before it is admitted.
    /// MUTATION CONTROL: admitting without `eligible_at` turns this red.
    #[test]
    fn a_checkpoint_names_roots_only_once_eligible_at_an_established_head() {
        let chain = chain_of(EPOCH_GENERATIONS);
        let head = chain.head();
        let (r_s, d_s) = (*head.state_root(), *head.generation_digest());
        let (r_0, d_0) = chain.at(0).expect("the genesis");
        let s = EPOCH_GENERATIONS;
        let eligible = checkpoint(LineageKind::Reserve, LINEAGE, s, d_s, r_s, 0xE1);
        let mut found = Candidates::default();
        for object in [
            eligible.clone(),
            checkpoint(LineageKind::Reserve, [0x32; 32], s, d_s, r_s, 0xE2),
            checkpoint(LineageKind::Vault, LINEAGE, s, d_s, r_s, 0xE3),
            checkpoint(LineageKind::Reserve, LINEAGE, 0, d_0, r_0, 0xE4),
            checkpoint(LineageKind::Reserve, LINEAGE, s, [0x77; 32], r_s, 0xE5),
            checkpoint(LineageKind::Reserve, LINEAGE, s, d_s, [0x78; 32], 0xE6),
        ] {
            found.add(LineageObject::Checkpoint(object));
        }
        assert_eq!(
            found.named_from(0),
            Vec::new(),
            "a checkpoint found names nothing before it is admitted"
        );
        assert_eq!(found.admit_checkpoints(&head), 1);
        let expected: Vec<(u64, D32)> = eligible
            .claimed_roots()
            .iter()
            .enumerate()
            .map(|(i, root)| (s + i as u64, *root))
            .collect();
        assert_eq!(
            found.named_from(0),
            expected,
            "only the checkpoint eligible at the head names roots"
        );
    }

    /// SA-69. Hints are anyone's too, up to `CANDIDATES_PER_EPOCH` an epoch:
    /// a walk reads ahead at most `NAMED_READS_PER_WALK` named roots,
    /// generation by generation, however many the index names.
    /// MUTATION CONTROL: dropping the bound turns this red.
    #[test]
    fn a_walk_reads_ahead_no_more_named_roots_than_its_bound() {
        let mut found = Candidates::default();
        let past = NAMED_READS_PER_WALK as u64 + 40;
        for g in 1..=past {
            let mut root = [0x5A; 32];
            root[..8].copy_from_slice(&g.to_be_bytes());
            let hint = GenerationHintV1::new(
                LineageKind::Reserve,
                LINEAGE,
                g,
                root,
                [0x5B; 32],
                [0x5C; 32],
            )
            .expect("a hint");
            found.add(LineageObject::Hint(hint));
        }
        let named = found.named_from(0);
        assert_eq!(named.len(), NAMED_READS_PER_WALK);
        let generations: Vec<u64> = named.iter().map(|(g, _)| *g).collect();
        let first: Vec<u64> = (1..=NAMED_READS_PER_WALK as u64).collect();
        assert_eq!(generations, first, "the earliest generations, in order");
    }

    /// A checkpoint anyone appended for a segment's start is not the
    /// segment's own: the device that established the segment still owes its
    /// checkpoint, and owes nothing once that very checkpoint is found.
    /// MUTATION CONTROL: taking any checkpoint at the start as the segment's
    /// turns this red.
    #[test]
    #[serial_test::serial]
    fn only_the_segments_own_checkpoint_stands_for_its_debt() {
        crate::economic_fixtures::use_test_storage_dir();
        crate::storage::client_db::reset_database_for_tests();
        crate::storage::client_db::init_database().expect("init db");
        let chain = chain_of(EPOCH_GENERATIONS);
        let steps: Vec<BundleStep> = (1..=EPOCH_GENERATIONS)
            .map(|g| BundleStep::Reserve {
                release_evidence_addr: [0x90 | g as u8; 32],
            })
            .collect();
        let bundle = TransitionBundleV1::new(LineageKind::Reserve, LINEAGE, 0, steps)
            .expect("the segment's bundle");
        let roots: Vec<D32> = (0..=EPOCH_GENERATIONS)
            .map(|g| chain.at(g).expect("established").0)
            .collect();
        let digest = |g: u64| chain.at(g).expect("established").1;
        let own = CheckpointV1::new(
            LineageKind::Reserve,
            LINEAGE,
            0,
            digest(0),
            digest(EPOCH_GENERATIONS),
            roots.clone(),
            bundle.address(),
        )
        .expect("the segment's checkpoint");
        let mut lying_roots = roots;
        lying_roots[5] = [0x79; 32];
        let lie = CheckpointV1::new(
            LineageKind::Reserve,
            LINEAGE,
            0,
            digest(0),
            digest(EPOCH_GENERATIONS),
            lying_roots,
            bundle.address(),
        )
        .expect("a checkpoint anyone may write");

        let set_id = [0x3C; 32];
        let mut with_own = Candidates::default();
        with_own.add(LineageObject::Checkpoint(own));
        assert_eq!(
            owe_checkpoint(&set_id, &chain, &bundle, 0, &with_own).expect("owed"),
            0
        );
        let mut with_lie = Candidates::default();
        with_lie.add(LineageObject::Checkpoint(lie));
        assert_eq!(
            owe_checkpoint(&set_id, &chain, &bundle, 0, &with_lie).expect("owed"),
            1,
            "a lying checkpoint at the start leaves the segment's own owed"
        );
    }

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
