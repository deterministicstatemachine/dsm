// SPDX-License-Identifier: Apache-2.0

//! Shared lineages (DSM Amendment A15, SoFi Amendment S23).
//!
//! A shared lineage is a resource with no single writer — a SoFi vault, the
//! native reserve — that advances one generation at a time, each generation
//! consuming its parent through the key derived from that parent. Its
//! generations are established only by induction from the accepted genesis,
//! by the lineage's own Core rules (`sofi::resolve`, `economic::native_reserve`).
//!
//! This module holds what helps a reader FIND a lineage's history, and
//! nothing that establishes it: the generation digests, the hint, checkpoint
//! and bundle objects, the epoch locator, and the eligibility rule for a
//! checkpoint. A discovered root tells a reader where to look; it never tells
//! the reader what the state is. Nothing here constructs an established vault
//! chain, reserve state or record of one, and nothing here may.

use crate::ccb::decode::{Cursor, DecodeError};
use crate::ccb::{class, push_digest32, push_u16, push_u32, push_u64};
use crate::common::domain_tags::{
    TAG_DSM_SHARED_LINEAGE_CHECKPOINT, TAG_DSM_SHARED_LINEAGE_EPOCH_LOCATOR,
    TAG_DSM_SHARED_LINEAGE_GENERATION, TAG_DSM_SHARED_LINEAGE_GENESIS,
    TAG_DSM_SHARED_LINEAGE_OBJECT, TAG_DSM_SHARED_LINEAGE_VAULT_STEP,
};
use crate::crypto::blake3::{domain_hash_bytes, dsm_domain_hasher};

type D32 = [u8; 32];

/// Every shared-lineage object ships at schema 1.
pub const SCHEMA_V1: u16 = 1;

/// Generations in one epoch, and in one checkpoint's segment.
pub const EPOCH_GENERATIONS: u64 = 32;

/// The most sibling legs a vault step names: a route's other vaults.
pub const MAX_SIBLING_LEGS: usize = 8;

/// What kind of lineage an object belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum LineageKind {
    /// A SoFi vault; its lineage id is the vault id.
    Vault,
    /// The native reserve (SoFi §51); its lineage id is the reserve id.
    Reserve,
}

impl LineageKind {
    pub fn byte(self) -> u8 {
        match self {
            Self::Vault => 1,
            Self::Reserve => 2,
        }
    }

    fn at(c: &mut Cursor<'_>) -> Result<Self, DecodeError> {
        match c.u8()? {
            1 => Ok(Self::Vault),
            2 => Ok(Self::Reserve),
            other => Err(DecodeError::Invalid(format!(
                "lineage kind {other} is not declared"
            ))),
        }
    }
}

/// Why a shared-lineage object cannot be built.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LineageObjectError {
    /// Generation 0 is the genesis; a generation, hint or step names one
    /// after it.
    GenerationIsGenesis,
    /// A checkpoint's segment does not start on an epoch boundary.
    StartNotOnEpoch { start: u64 },
    /// A checkpoint's segment is not exactly one epoch long.
    WrongSegmentLength { start: u64, end: u64 },
    /// A checkpoint lists other than one root per generation of its segment.
    WrongRootCount { got: usize },
    /// A bundle's steps are other than one per generation of a segment.
    WrongStepCount { got: usize },
    /// A step of another kind than its bundle.
    StepKindMismatch,
    /// More sibling legs than a route has.
    TooManySiblings { got: usize },
    /// The generation counter would overflow.
    GenerationOverflow,
    /// A hint for a generation the chain has not established.
    NotEstablished { generation: u64 },
}

impl core::fmt::Display for LineageObjectError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{self:?}")
    }
}

fn invalid(e: LineageObjectError) -> DecodeError {
    DecodeError::Invalid(e.to_string())
}

fn push_env(out: &mut Vec<u8>, object_class: u16) {
    push_u16(out, object_class);
    push_u16(out, SCHEMA_V1);
}

fn finish<T>(c: &Cursor<'_>, value: T) -> Result<T, DecodeError> {
    if c.i != c.b.len() {
        return Err(DecodeError::TrailingBytes {
            extra: c.b.len() - c.i,
        });
    }
    Ok(value)
}

fn after_genesis(generation: u64) -> Result<u64, LineageObjectError> {
    match generation {
        0 => Err(LineageObjectError::GenerationIsGenesis),
        g => Ok(g),
    }
}

// ── digests ────────────────────────────────────────────────────────────────

/// A vault generation's step digest: `H(vault-step/v1; E)`, where `E` is the
/// external commitment of the exercise that consumed the parent. `E` commits
/// the exercise's legs, so it names the parent root it consumed.
pub fn vault_step_digest(external_commitment: &D32) -> D32 {
    domain_hash_bytes(TAG_DSM_SHARED_LINEAGE_VAULT_STEP, external_commitment)
}

/// `lineage_epoch_locator(k, id, e) = H(epoch-locator/v1; u8 k ‖ id ‖ u64be(e))`:
/// the index that lists epoch `e`'s hints and checkpoints. Anyone may append
/// to it, so it may hold anything.
pub fn epoch_locator(kind: LineageKind, lineage_id: &D32, epoch: u64) -> D32 {
    let mut h = dsm_domain_hasher(TAG_DSM_SHARED_LINEAGE_EPOCH_LOCATOR);
    h.update(&[kind.byte()]);
    h.update(lineage_id);
    h.update(&epoch.to_be_bytes());
    *h.finalize().as_bytes()
}

/// The epoch a generation falls in.
pub fn epoch_of(generation: u64) -> u64 {
    generation / EPOCH_GENERATIONS
}

/// The immutable-store address of a hint, checkpoint or bundle's bytes.
pub fn object_address(bytes: &[u8]) -> D32 {
    crate::storage_object::immutable_addr(TAG_DSM_SHARED_LINEAGE_OBJECT, bytes)
}

// ── SharedGenesisV1 (0x006C) ───────────────────────────────────────────────

/// A shared lineage's genesis: `d_0 = H(genesis/v1; CCB(·))`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SharedGenesisV1 {
    kind: LineageKind,
    lineage_id: D32,
    state_root: D32,
    genesis_preimage_digest: D32,
}

impl SharedGenesisV1 {
    /// `genesis_preimage_digest` is, for a vault, the address of its genesis
    /// preimage; for the reserve, the policy commit its genesis supply is
    /// fixed in.
    pub fn new(
        kind: LineageKind,
        lineage_id: D32,
        state_root: D32,
        genesis_preimage_digest: D32,
    ) -> Self {
        Self {
            kind,
            lineage_id,
            state_root,
            genesis_preimage_digest,
        }
    }

    pub fn kind(&self) -> LineageKind {
        self.kind
    }

    pub fn lineage_id(&self) -> &D32 {
        &self.lineage_id
    }

    pub fn state_root(&self) -> &D32 {
        &self.state_root
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_env(&mut out, class::SHARED_LINEAGE_GENESIS);
        out.push(self.kind.byte());
        push_digest32(&mut out, &self.lineage_id);
        push_digest32(&mut out, &self.state_root);
        push_digest32(&mut out, &self.genesis_preimage_digest);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut c = Cursor { b: bytes, i: 0 };
        c.envelope(class::SHARED_LINEAGE_GENESIS, SCHEMA_V1)?;
        let v = Self {
            kind: LineageKind::at(&mut c)?,
            lineage_id: c.digest32()?,
            state_root: c.digest32()?,
            genesis_preimage_digest: c.digest32()?,
        };
        finish(&c, v)
    }

    /// `d_0`.
    pub fn digest(&self) -> D32 {
        domain_hash_bytes(TAG_DSM_SHARED_LINEAGE_GENESIS, &self.encode())
    }
}

// ── SharedGenerationV1 (0x006D) ────────────────────────────────────────────

/// One generation after the genesis: `d_g = H(generation/v1; CCB(·))`, where
/// `parent_generation_digest` is `d_{g−1}`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SharedGenerationV1 {
    kind: LineageKind,
    lineage_id: D32,
    generation: u64,
    parent_generation_digest: D32,
    state_root: D32,
    step_digest: D32,
}

impl SharedGenerationV1 {
    pub fn new(
        kind: LineageKind,
        lineage_id: D32,
        generation: u64,
        parent_generation_digest: D32,
        state_root: D32,
        step_digest: D32,
    ) -> Result<Self, LineageObjectError> {
        Ok(Self {
            kind,
            lineage_id,
            generation: after_genesis(generation)?,
            parent_generation_digest,
            state_root,
            step_digest,
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_env(&mut out, class::SHARED_LINEAGE_GENERATION);
        out.push(self.kind.byte());
        push_digest32(&mut out, &self.lineage_id);
        push_u64(&mut out, self.generation);
        push_digest32(&mut out, &self.parent_generation_digest);
        push_digest32(&mut out, &self.state_root);
        push_digest32(&mut out, &self.step_digest);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut c = Cursor { b: bytes, i: 0 };
        c.envelope(class::SHARED_LINEAGE_GENERATION, SCHEMA_V1)?;
        let kind = LineageKind::at(&mut c)?;
        let lineage_id = c.digest32()?;
        let generation = c.u64()?;
        let parent_generation_digest = c.digest32()?;
        let state_root = c.digest32()?;
        let step_digest = c.digest32()?;
        let v = Self::new(
            kind,
            lineage_id,
            generation,
            parent_generation_digest,
            state_root,
            step_digest,
        )
        .map_err(invalid)?;
        finish(&c, v)
    }

    /// `d_g`.
    pub fn digest(&self) -> D32 {
        domain_hash_bytes(TAG_DSM_SHARED_LINEAGE_GENERATION, &self.encode())
    }
}

// ── the generation chain a reader computes ─────────────────────────────────

/// A lineage's head as a reader established it: the result every backend
/// produces (DSM Amendment A15). Built only by [`GenerationChain`], from the
/// genesis and the generations the reader's own Core walk established.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EstablishedSharedHead {
    kind: LineageKind,
    lineage_id: D32,
    generation: u64,
    generation_digest: D32,
    state_root: D32,
}

impl EstablishedSharedHead {
    pub fn kind(&self) -> LineageKind {
        self.kind
    }
    pub fn lineage_id(&self) -> &D32 {
        &self.lineage_id
    }
    pub fn generation(&self) -> u64 {
        self.generation
    }
    pub fn generation_digest(&self) -> &D32 {
        &self.generation_digest
    }
    pub fn state_root(&self) -> &D32 {
        &self.state_root
    }
}

/// The digests `d_0 … d_n` of the generations a reader established, in
/// order. The digests are a commitment a reader computes for itself; feeding
/// it anything but generations the reader's own Core walk established makes
/// its digests describe something nobody established, and nothing here can
/// tell. Hints and checkpoints are compared against these, never the other
/// way round.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenerationChain {
    kind: LineageKind,
    lineage_id: D32,
    /// `(state_root, d_g)` for g = 0 … n.
    generations: Vec<(D32, D32)>,
}

impl GenerationChain {
    pub fn from_genesis(genesis: &SharedGenesisV1) -> Self {
        Self {
            kind: genesis.kind,
            lineage_id: genesis.lineage_id,
            generations: vec![(genesis.state_root, genesis.digest())],
        }
    }

    /// Append the next established generation, its root and step digest.
    pub fn push(&mut self, state_root: D32, step_digest: D32) -> Result<(), LineageObjectError> {
        let parent = self.head();
        let generation = parent
            .generation
            .checked_add(1)
            .ok_or(LineageObjectError::GenerationOverflow)?;
        let next = SharedGenerationV1::new(
            self.kind,
            self.lineage_id,
            generation,
            parent.generation_digest,
            state_root,
            step_digest,
        )?;
        self.generations.push((state_root, next.digest()));
        Ok(())
    }

    /// The head: the last generation pushed, or the genesis.
    pub fn head(&self) -> EstablishedSharedHead {
        let last = self.generations.len() - 1;
        let (state_root, generation_digest) = self.generations[last];
        EstablishedSharedHead {
            kind: self.kind,
            lineage_id: self.lineage_id,
            generation: last as u64,
            generation_digest,
            state_root,
        }
    }

    /// The digest and root of generation `g`, when it has been pushed.
    pub fn at(&self, generation: u64) -> Option<(D32, D32)> {
        if generation >= self.generations.len() as u64 {
            return None;
        }
        self.generations
            .get(generation as usize)
            .map(|(root, d)| (*root, *d))
    }
}

/// The interface a phase-C backend implements (DSM Amendment A15): a
/// validity proof of a lineage's history, checked against live facts,
/// yielding the same established head the Core walk yields. No backend
/// exists yet; nothing implements this until a proof does.
pub trait SharedLineageValidity {
    type LiveFacts;
    type Error;
    fn verify(
        &self,
        genesis: &SharedGenesisV1,
        claimed_generation: u64,
        claimed_state_root: &D32,
        proof: &[u8],
        live_facts: &Self::LiveFacts,
    ) -> Result<EstablishedSharedHead, Self::Error>;
}

// ── GenerationHintV1 (0x006E) ──────────────────────────────────────────────

/// One realized generation, as someone claims it: discovery only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenerationHintV1 {
    kind: LineageKind,
    lineage_id: D32,
    generation: u64,
    state_root: D32,
    generation_digest: D32,
    step_digest: D32,
}

impl GenerationHintV1 {
    pub fn new(
        kind: LineageKind,
        lineage_id: D32,
        generation: u64,
        state_root: D32,
        generation_digest: D32,
        step_digest: D32,
    ) -> Result<Self, LineageObjectError> {
        Ok(Self {
            kind,
            lineage_id,
            generation: after_genesis(generation)?,
            state_root,
            generation_digest,
            step_digest,
        })
    }

    /// The hint for an established generation of `chain`.
    pub fn of_established(
        chain: &GenerationChain,
        generation: u64,
        step_digest: D32,
    ) -> Result<Self, LineageObjectError> {
        let (state_root, generation_digest) = chain
            .at(generation)
            .ok_or(LineageObjectError::NotEstablished { generation })?;
        Self::new(
            chain.kind,
            chain.lineage_id,
            generation,
            state_root,
            generation_digest,
            step_digest,
        )
    }

    pub fn kind(&self) -> LineageKind {
        self.kind
    }
    pub fn lineage_id(&self) -> &D32 {
        &self.lineage_id
    }
    pub fn generation(&self) -> u64 {
        self.generation
    }
    /// The root someone claims generation `generation` has: where to look
    /// for its successor, never what the state is.
    pub fn claimed_root(&self) -> &D32 {
        &self.state_root
    }
    pub fn generation_digest(&self) -> &D32 {
        &self.generation_digest
    }
    pub fn step_digest(&self) -> &D32 {
        &self.step_digest
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_env(&mut out, class::SHARED_LINEAGE_GENERATION_HINT);
        out.push(self.kind.byte());
        push_digest32(&mut out, &self.lineage_id);
        push_u64(&mut out, self.generation);
        push_digest32(&mut out, &self.state_root);
        push_digest32(&mut out, &self.generation_digest);
        push_digest32(&mut out, &self.step_digest);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut c = Cursor { b: bytes, i: 0 };
        c.envelope(class::SHARED_LINEAGE_GENERATION_HINT, SCHEMA_V1)?;
        let kind = LineageKind::at(&mut c)?;
        let lineage_id = c.digest32()?;
        let generation = c.u64()?;
        let state_root = c.digest32()?;
        let generation_digest = c.digest32()?;
        let step_digest = c.digest32()?;
        let v = Self::new(
            kind,
            lineage_id,
            generation,
            state_root,
            generation_digest,
            step_digest,
        )
        .map_err(invalid)?;
        finish(&c, v)
    }
}

// ── CheckpointV1 (0x006F) ──────────────────────────────────────────────────

/// One epoch's segment, as someone claims it: discovery only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckpointV1 {
    kind: LineageKind,
    lineage_id: D32,
    start_generation: u64,
    end_generation: u64,
    start_generation_digest: D32,
    end_generation_digest: D32,
    roots: Vec<D32>,
    transition_bundle_digest: D32,
    checkpoint_digest: D32,
}

/// Every checkpoint field but its digest, in encoding order: what
/// `checkpoint_digest` commits.
struct CheckpointBody<'a> {
    kind: LineageKind,
    lineage_id: &'a D32,
    start_generation: u64,
    end_generation: u64,
    start_generation_digest: &'a D32,
    end_generation_digest: &'a D32,
    roots: &'a [D32],
    transition_bundle_digest: &'a D32,
}

impl CheckpointBody<'_> {
    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(self.kind.byte());
        push_digest32(&mut out, self.lineage_id);
        push_u64(&mut out, self.start_generation);
        push_u64(&mut out, self.end_generation);
        push_digest32(&mut out, self.start_generation_digest);
        push_digest32(&mut out, self.end_generation_digest);
        push_u32(&mut out, self.roots.len() as u32);
        for root in self.roots {
            push_digest32(&mut out, root);
        }
        push_digest32(&mut out, self.transition_bundle_digest);
        out
    }
}

/// Why a checkpoint is not taken for the segment a reader stands at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckpointIneligible {
    OtherLineage,
    OtherStart { start: u64, established: u64 },
    StartDigestMismatch,
    StartRootMismatch,
}

impl CheckpointV1 {
    pub fn new(
        kind: LineageKind,
        lineage_id: D32,
        start_generation: u64,
        start_generation_digest: D32,
        end_generation_digest: D32,
        roots: Vec<D32>,
        transition_bundle_digest: D32,
    ) -> Result<Self, LineageObjectError> {
        if start_generation % EPOCH_GENERATIONS != 0 {
            return Err(LineageObjectError::StartNotOnEpoch {
                start: start_generation,
            });
        }
        let end_generation = start_generation
            .checked_add(EPOCH_GENERATIONS)
            .ok_or(LineageObjectError::GenerationOverflow)?;
        if roots.len() as u64 != EPOCH_GENERATIONS + 1 {
            return Err(LineageObjectError::WrongRootCount { got: roots.len() });
        }
        let body = CheckpointBody {
            kind,
            lineage_id: &lineage_id,
            start_generation,
            end_generation,
            start_generation_digest: &start_generation_digest,
            end_generation_digest: &end_generation_digest,
            roots: &roots,
            transition_bundle_digest: &transition_bundle_digest,
        }
        .encode();
        let checkpoint_digest = domain_hash_bytes(TAG_DSM_SHARED_LINEAGE_CHECKPOINT, &body);
        Ok(Self {
            kind,
            lineage_id,
            start_generation,
            end_generation,
            start_generation_digest,
            end_generation_digest,
            roots,
            transition_bundle_digest,
            checkpoint_digest,
        })
    }

    fn body(&self) -> Vec<u8> {
        CheckpointBody {
            kind: self.kind,
            lineage_id: &self.lineage_id,
            start_generation: self.start_generation,
            end_generation: self.end_generation,
            start_generation_digest: &self.start_generation_digest,
            end_generation_digest: &self.end_generation_digest,
            roots: &self.roots,
            transition_bundle_digest: &self.transition_bundle_digest,
        }
        .encode()
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_env(&mut out, class::SHARED_LINEAGE_CHECKPOINT);
        out.extend_from_slice(&self.body());
        push_digest32(&mut out, &self.checkpoint_digest);
        out
    }

    /// Strict: the end is exactly one epoch after the start, there is one
    /// root per generation of the segment, and `checkpoint_digest`
    /// recomputes.
    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut c = Cursor { b: bytes, i: 0 };
        c.envelope(class::SHARED_LINEAGE_CHECKPOINT, SCHEMA_V1)?;
        let kind = LineageKind::at(&mut c)?;
        let lineage_id = c.digest32()?;
        let start_generation = c.u64()?;
        let end_generation = c.u64()?;
        let start_generation_digest = c.digest32()?;
        let end_generation_digest = c.digest32()?;
        let count = c.u32()? as u64;
        if count != EPOCH_GENERATIONS + 1 {
            return Err(invalid(LineageObjectError::WrongRootCount {
                got: count as usize,
            }));
        }
        let mut roots = Vec::with_capacity(count as usize);
        for _ in 0..count {
            roots.push(c.digest32()?);
        }
        let transition_bundle_digest = c.digest32()?;
        let carried = c.digest32()?;
        let v = Self::new(
            kind,
            lineage_id,
            start_generation,
            start_generation_digest,
            end_generation_digest,
            roots,
            transition_bundle_digest,
        )
        .map_err(invalid)?;
        if v.end_generation != end_generation {
            return Err(invalid(LineageObjectError::WrongSegmentLength {
                start: start_generation,
                end: end_generation,
            }));
        }
        if v.checkpoint_digest != carried {
            return Err(DecodeError::Invalid(
                "checkpoint_digest does not recompute".to_string(),
            ));
        }
        finish(&c, v)
    }

    pub fn kind(&self) -> LineageKind {
        self.kind
    }
    pub fn lineage_id(&self) -> &D32 {
        &self.lineage_id
    }
    pub fn start_generation(&self) -> u64 {
        self.start_generation
    }
    pub fn end_generation(&self) -> u64 {
        self.end_generation
    }
    pub fn end_generation_digest(&self) -> &D32 {
        &self.end_generation_digest
    }
    /// The roots someone claims generations `start … end` have: where to
    /// look, never what the state is.
    pub fn claimed_roots(&self) -> &[D32] {
        &self.roots
    }
    pub fn transition_bundle_digest(&self) -> &D32 {
        &self.transition_bundle_digest
    }

    /// Whether this checkpoint is for the segment that starts at the head a
    /// reader established: the same lineage, starting at the head's
    /// generation, with the head's digest and root. Eligibility makes a
    /// checkpoint worth reading from, and nothing more.
    pub fn eligible_at(&self, head: &EstablishedSharedHead) -> Result<(), CheckpointIneligible> {
        if self.kind != head.kind || self.lineage_id != head.lineage_id {
            return Err(CheckpointIneligible::OtherLineage);
        }
        if self.start_generation != head.generation {
            return Err(CheckpointIneligible::OtherStart {
                start: self.start_generation,
                established: head.generation,
            });
        }
        if self.start_generation_digest != head.generation_digest {
            return Err(CheckpointIneligible::StartDigestMismatch);
        }
        if self.roots[0] != head.state_root {
            return Err(CheckpointIneligible::StartRootMismatch);
        }
        Ok(())
    }

    /// Whether the walk, having established the segment, reached what this
    /// checkpoint claims its end is. A mismatch discards the checkpoint and
    /// nothing else.
    pub fn end_matches(&self, end: &EstablishedSharedHead) -> bool {
        end.generation == self.end_generation
            && end.generation_digest == self.end_generation_digest
            && Some(&end.state_root) == self.roots.last()
    }
}

// ── TransitionBundleV1 (0x0070) ────────────────────────────────────────────

/// What a reader needs to read one generation of a segment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BundleStep {
    /// A vault generation: the attempt that consumed its parent, the
    /// exercise's `E`, the trader's position, and the route's other legs
    /// `(vault_id, parent_root)`.
    Vault {
        attempt: u64,
        external_commitment: D32,
        trader_genesis: D32,
        trader_device_id: D32,
        trader_position: u64,
        siblings: Vec<(D32, D32)>,
    },
    /// A reserve generation: its release envelope's evidence address.
    Reserve { release_evidence_addr: D32 },
}

impl BundleStep {
    fn kind(&self) -> LineageKind {
        match self {
            Self::Vault { .. } => LineageKind::Vault,
            Self::Reserve { .. } => LineageKind::Reserve,
        }
    }
}

/// A segment's read plan: discovery only. Its address is the checkpoint's
/// `transition_bundle_digest` (retrieval integrity, never a transition's
/// identity).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransitionBundleV1 {
    kind: LineageKind,
    lineage_id: D32,
    start_generation: u64,
    steps: Vec<BundleStep>,
}

impl TransitionBundleV1 {
    pub fn new(
        kind: LineageKind,
        lineage_id: D32,
        start_generation: u64,
        steps: Vec<BundleStep>,
    ) -> Result<Self, LineageObjectError> {
        if start_generation % EPOCH_GENERATIONS != 0 {
            return Err(LineageObjectError::StartNotOnEpoch {
                start: start_generation,
            });
        }
        if steps.len() as u64 != EPOCH_GENERATIONS {
            return Err(LineageObjectError::WrongStepCount { got: steps.len() });
        }
        for step in &steps {
            if step.kind() != kind {
                return Err(LineageObjectError::StepKindMismatch);
            }
            if let BundleStep::Vault { siblings, .. } = step {
                if siblings.len() > MAX_SIBLING_LEGS {
                    return Err(LineageObjectError::TooManySiblings {
                        got: siblings.len(),
                    });
                }
            }
        }
        Ok(Self {
            kind,
            lineage_id,
            start_generation,
            steps,
        })
    }

    pub fn steps(&self) -> &[BundleStep] {
        &self.steps
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_env(&mut out, class::SHARED_LINEAGE_TRANSITION_BUNDLE);
        out.push(self.kind.byte());
        push_digest32(&mut out, &self.lineage_id);
        push_u64(&mut out, self.start_generation);
        push_u32(&mut out, self.steps.len() as u32);
        for step in &self.steps {
            match step {
                BundleStep::Vault {
                    attempt,
                    external_commitment,
                    trader_genesis,
                    trader_device_id,
                    trader_position,
                    siblings,
                } => {
                    push_u64(&mut out, *attempt);
                    push_digest32(&mut out, external_commitment);
                    push_digest32(&mut out, trader_genesis);
                    push_digest32(&mut out, trader_device_id);
                    push_u64(&mut out, *trader_position);
                    push_u32(&mut out, siblings.len() as u32);
                    for (vault_id, parent_root) in siblings {
                        push_digest32(&mut out, vault_id);
                        push_digest32(&mut out, parent_root);
                    }
                }
                BundleStep::Reserve {
                    release_evidence_addr,
                } => push_digest32(&mut out, release_evidence_addr),
            }
        }
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut c = Cursor { b: bytes, i: 0 };
        c.envelope(class::SHARED_LINEAGE_TRANSITION_BUNDLE, SCHEMA_V1)?;
        let kind = LineageKind::at(&mut c)?;
        let lineage_id = c.digest32()?;
        let start_generation = c.u64()?;
        let count = c.u32()? as u64;
        if count != EPOCH_GENERATIONS {
            return Err(invalid(LineageObjectError::WrongStepCount {
                got: count as usize,
            }));
        }
        let mut steps = Vec::with_capacity(count as usize);
        for _ in 0..count {
            steps.push(match kind {
                LineageKind::Vault => {
                    let attempt = c.u64()?;
                    let external_commitment = c.digest32()?;
                    let trader_genesis = c.digest32()?;
                    let trader_device_id = c.digest32()?;
                    let trader_position = c.u64()?;
                    let n = c.u32()? as usize;
                    if n > MAX_SIBLING_LEGS {
                        return Err(invalid(LineageObjectError::TooManySiblings { got: n }));
                    }
                    let mut siblings = Vec::with_capacity(n);
                    for _ in 0..n {
                        siblings.push((c.digest32()?, c.digest32()?));
                    }
                    BundleStep::Vault {
                        attempt,
                        external_commitment,
                        trader_genesis,
                        trader_device_id,
                        trader_position,
                        siblings,
                    }
                }
                LineageKind::Reserve => BundleStep::Reserve {
                    release_evidence_addr: c.digest32()?,
                },
            });
        }
        let v = Self::new(kind, lineage_id, start_generation, steps).map_err(invalid)?;
        finish(&c, v)
    }

    /// The bundle's address: what a checkpoint's `transition_bundle_digest`
    /// names.
    pub fn address(&self) -> D32 {
        object_address(&self.encode())
    }
}

/// A discovered object, recognized from its bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LineageObject {
    Hint(GenerationHintV1),
    Checkpoint(CheckpointV1),
}

impl LineageObject {
    /// The hint or checkpoint these bytes are. Anything else is refused —
    /// an index anyone may append to holds whatever was appended.
    pub fn recognize(bytes: &[u8]) -> Result<Self, DecodeError> {
        let c = Cursor { b: bytes, i: 0 };
        match c.peek_class()? {
            class::SHARED_LINEAGE_GENERATION_HINT => {
                Ok(Self::Hint(GenerationHintV1::decode(bytes)?))
            }
            class::SHARED_LINEAGE_CHECKPOINT => Ok(Self::Checkpoint(CheckpointV1::decode(bytes)?)),
            got => Err(DecodeError::WrongClass { got }),
        }
    }
}

#[cfg(test)]
mod tests;
