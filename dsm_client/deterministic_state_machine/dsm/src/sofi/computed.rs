// SPDX-License-Identifier: Apache-2.0

//! Computed escrow vaults (SoFi §19.10, Amendment S22; DSM Amendment A13):
//! the derivations, the canonical transcript, the outcome program, what
//! occupies the match and start cells, and how a reader stands on them.
//!
//! A computed escrow vault is an S21 escrow vault whose outcome is not signed
//! by anyone. Its terms pin a program `P` by hash, the digest of the setup
//! `P` runs on, and one session key per side. The two players' wallets build
//! a transcript of canonical entries under a head chain, each side covering
//! its own entries with its session key. When the match ends, the whole
//! transcript is written to the match cell and proves its outcome from its
//! own bytes: every entry round-trips, the chain recomputes, the signatures
//! verify, and the registered `P` computes a branch label. Two heads one key
//! signed at one index prove that side cheated, and give the other side the
//! win. A Start or a Withdraw races at a separate start cell, and the match
//! cell counts only once Start holds.
//!
//! Nothing here knows what a match is. `P` is the only thing that reads a
//! move, and Core runs it only when the verifier itself registered it. An
//! unregistered `P` establishes nothing: it is never guessed and never
//! refused as invalid.

use std::collections::BTreeMap;
use std::sync::Arc;

use crate::common::domain_tags::{
    TAG_DSM_ESCROW_COMPUTED_MATCH, TAG_DSM_ESCROW_COMPUTED_MATCH_SEED,
    TAG_DSM_ESCROW_COMPUTED_OCCUPANT, TAG_DSM_ESCROW_COMPUTED_READY, TAG_DSM_ESCROW_COMPUTED_SETUP,
    TAG_DSM_ESCROW_COMPUTED_START, TAG_DSM_ESCROW_COMPUTED_START_SEED,
    TAG_DSM_ESCROW_COMPUTED_START_STATEMENT, TAG_DSM_ESCROW_COMPUTED_TABLE,
    TAG_DSM_ESCROW_MOVE_COMMIT, TAG_DSM_ESCROW_TRANSCRIPT, TAG_DSM_ESCROW_TRANSCRIPT_HEAD,
    TAG_DSM_ESCROW_TRANSCRIPT_STEP,
};
use crate::crypto::blake3::dsm_domain_hasher;
use crate::crypto::domain::TaggedHashDomain;
use crate::route_chain::{
    completion_proof, evaluate, CellError, CellEvidence, CellFact, CellReading, ChainState,
    CompletionProof, Missing, RoutedCell,
};

use super::escrow::VerdictStanding;
use super::signature::{verify_bytes, SignatureError};
use super::wire::{
    ComputedEscrowTerms, ComputedTable, EntryKind, EquivocationProof, MatchSide, MatchStart,
    StartBody, StartKind, TranscriptEntry, TranscriptOutcome, COMPUTED_LABELS, COMPUTED_LABEL_VOID,
};

type D32 = [u8; 32];

fn h(tag: TaggedHashDomain<'static>, parts: &[&[u8]]) -> D32 {
    let mut hasher = dsm_domain_hasher(tag);
    for p in parts {
        hasher.update(p);
    }
    *hasher.finalize().as_bytes()
}

/// `u32be(|bytes|)`. Every length hashed here is bounded far below `u32::MAX`
/// by the wire's own bounds.
fn len32(bytes: &[u8]) -> [u8; 4] {
    (bytes.len() as u32).to_be_bytes()
}

// ── derivations ────────────────────────────────────────────────────────────

/// `H(DSM/escrow/computed-setup/v1 ‖ setup)`: what a computed table commits
/// for the program's input. DSM never interprets `setup`.
pub fn setup_digest(setup: &[u8]) -> D32 {
    h(TAG_DSM_ESCROW_COMPUTED_SETUP, &[setup])
}

/// `τ_c = H(DSM/escrow/computed-table/v1 ‖ table bytes)`.
pub fn table_digest(table: &ComputedTable) -> D32 {
    h(TAG_DSM_ESCROW_COMPUTED_TABLE, &[&table.canonical()])
}

/// `K_match = H(DSM/escrow/computed-match/v1 ‖ Y ‖ τ_c)`.
pub fn match_cell_key(external_commitment: &D32, table_digest: &D32) -> D32 {
    h(
        TAG_DSM_ESCROW_COMPUTED_MATCH,
        &[external_commitment, table_digest],
    )
}

/// The match cell `Y` and a table bind to.
pub fn match_cell_of_table(external_commitment: &D32, table: &ComputedTable) -> D32 {
    match_cell_key(external_commitment, &table_digest(table))
}

/// The match cell a computed escrow vault's terms bind it to: every vault
/// naming the same `Y` and a byte-identical table shares it.
pub fn match_cell_of(terms: &ComputedEscrowTerms) -> D32 {
    match_cell_of_table(terms.external_commitment(), terms.table())
}

/// `s_match = H(DSM/escrow/computed-match-seed/v1 ‖ K_match)`.
pub fn match_seed(match_cell: &D32) -> D32 {
    h(TAG_DSM_ESCROW_COMPUTED_MATCH_SEED, &[match_cell])
}

/// `K_start = H(DSM/escrow/computed-start/v1 ‖ K_match)`.
pub fn start_cell_key(match_cell: &D32) -> D32 {
    h(TAG_DSM_ESCROW_COMPUTED_START, &[match_cell])
}

/// `s_start = H(DSM/escrow/computed-start-seed/v1 ‖ K_start)`.
pub fn start_seed(start_cell: &D32) -> D32 {
    h(TAG_DSM_ESCROW_COMPUTED_START_SEED, &[start_cell])
}

/// `m_ready = H(DSM/escrow/computed-ready/v1 ‖ K_match)`: what each side's
/// session key signs once its wallet has checked both vaults. A Start holds
/// both sides' signatures over it.
pub fn ready_statement(match_cell: &D32) -> D32 {
    h(TAG_DSM_ESCROW_COMPUTED_READY, &[match_cell])
}

/// `m_withdraw = H(DSM/escrow/computed-start-statement/v1 ‖ K_start ‖
/// u8(2))`: what either side signs to Withdraw before a Start.
pub fn withdraw_statement(start_cell: &D32) -> D32 {
    h(
        TAG_DSM_ESCROW_COMPUTED_START_STATEMENT,
        &[start_cell, &[StartKind::Withdraw.byte()]],
    )
}

/// `H(DSM/escrow/computed-occupant/v1 ‖ K ‖ u32be(|o|) ‖ o)`: a reader's
/// name for the occupant of a match or start cell, by its label.
pub fn occupant_id(cell: &D32, label: &[u8]) -> D32 {
    h(
        TAG_DSM_ESCROW_COMPUTED_OCCUPANT,
        &[cell, &len32(label), label],
    )
}

/// `H(DSM/escrow/move-commit/v1 ‖ salt ‖ u32be(|move|) ‖ move)`: a Commit's
/// commitment.
pub fn move_commitment(salt: &D32, played: &[u8]) -> D32 {
    h(TAG_DSM_ESCROW_MOVE_COMMIT, &[salt, &len32(played), played])
}

/// `h_0 = H(DSM/escrow/transcript/v1 ‖ K_match ‖ setup_digest)`.
pub fn genesis_head(match_cell: &D32, setup_digest: &D32) -> D32 {
    h(TAG_DSM_ESCROW_TRANSCRIPT, &[match_cell, setup_digest])
}

/// `h_i = H(DSM/escrow/transcript-step/v1 ‖ h_{i−1} ‖ CCB(entry_i))`.
pub fn next_head(previous: &D32, entry_bytes: &[u8]) -> D32 {
    h(TAG_DSM_ESCROW_TRANSCRIPT_STEP, &[previous, entry_bytes])
}

/// `m_head(i, h_i) = H(DSM/escrow/transcript-head/v1 ‖ K_match ‖ u32be(i) ‖
/// h_i)`: what a side signs over the head of its own entry `i`. It names the
/// match and the index, so a signature counts for nothing in another match,
/// and two of them at one index are comparable.
pub fn head_statement(match_cell: &D32, index: u32, head: &D32) -> D32 {
    h(
        TAG_DSM_ESCROW_TRANSCRIPT_HEAD,
        &[match_cell, &index.to_be_bytes(), head],
    )
}

// ── the outcome program ────────────────────────────────────────────────────

/// What an opened entry did: a revealed move, with the index of the Commit
/// it opened, or a resignation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpenedKind {
    Move { committed_at: u32, played: Vec<u8> },
    Resign,
}

/// One opened entry of a transcript, as the program sees it. Core builds
/// these only from entries that round-tripped canonically, chained and are
/// covered by their side's session key; an unopened commitment is never
/// shown.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Opened {
    /// The entry's own index: a Reveal's, or a Resign's.
    pub index: u32,
    pub side: MatchSide,
    pub kind: OpenedKind,
}

/// What a program computes from a transcript.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProgramOutcome {
    /// The match ended with this label.
    Done(Vec<u8>),
    /// The match has not ended.
    Incomplete,
}

/// A transcript the program refuses: a move its rules do not allow, or an
/// entry after the match ended. The transcript proves nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProgramFault(pub String);

/// A deterministic outcome program `P` (SoFi §19.10; Explainer Amendment
/// A13). It is a total function of the committed setup and the opened
/// entries: it keeps no state between calls, calls nothing, reads no clock
/// and fetches nothing. It never sets an amount or a recipient; it names a
/// label, and Core counts the label only when it is a branch of the terms.
///
/// `outcome` must be final: once it returns `Done` for a transcript, any
/// opened entry after it is a fault. Core holds a transcript to the entry
/// that ended the match by requiring `Incomplete` without its last entry.
pub trait OutcomeProgram: Send + Sync {
    /// `P`: the hash a computed table pins this program by.
    fn id(&self) -> [u8; 32];

    /// What the match `setup` describes has come to after `opened`.
    fn outcome(&self, setup: &[u8], opened: &[Opened]) -> Result<ProgramOutcome, ProgramFault>;
}

/// Why a program was not registered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegistryError {
    /// Another program is registered under the same hash.
    AlreadyRegistered { program: D32 },
}

/// The outcome programs one verifier runs, by the hash each is pinned by.
/// Registration is the verifier's own act, as pinning a storage set is:
/// nothing a party sends registers a program.
#[derive(Clone, Default)]
pub struct ProgramRegistry {
    programs: BTreeMap<D32, Arc<dyn OutcomeProgram>>,
}

impl core::fmt::Debug for ProgramRegistry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_list()
            .entries(
                self.programs
                    .keys()
                    .map(|id| crate::utils::text_id::encode_base32_crockford(id)),
            )
            .finish()
    }
}

impl ProgramRegistry {
    /// A registry with no program.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register `program` under its own hash. A second program under one
    /// hash is refused: which of the two runs would be a guess.
    pub fn register(&mut self, program: Arc<dyn OutcomeProgram>) -> Result<(), RegistryError> {
        let id = program.id();
        if self.programs.contains_key(&id) {
            return Err(RegistryError::AlreadyRegistered { program: id });
        }
        self.programs.insert(id, program);
        Ok(())
    }

    /// The program pinned by `program`, when this verifier registered it.
    pub fn get(&self, program: &D32) -> Option<&Arc<dyn OutcomeProgram>> {
        self.programs.get(program)
    }
}

// ── the canonical transcript ───────────────────────────────────────────────

/// Why entries are not a canonical transcript (SoFi §19.10, "The canonical
/// transcript"). Every variant is decided from the bytes in hand.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TranscriptRefusal {
    /// The setup does not hash to the table's setup digest.
    NotTheCommittedSetup,
    /// The entry at `position` does not decode.
    EntryDoesNotDecode {
        position: u32,
        why: crate::ccb::decode::DecodeError,
    },
    /// The entry at `position` decodes, but re-encodes to other bytes.
    EntryNotCanonical { position: u32 },
    /// The entry at `position` names another index.
    IndexOutOfOrder { position: u32, index: u32 },
    /// A Commit by a side that has a commitment not yet opened.
    CommitWhileOneIsOpen { index: u32 },
    /// A Reveal by a side with no commitment to open.
    NothingToReveal { index: u32 },
    /// A Reveal that does not hash to its side's commitment.
    RevealDoesNotOpenTheCommitment { index: u32 },
    /// An entry after a Resign.
    EntryAfterResign { index: u32 },
    /// More entries than a transcript holds.
    TooManyEntries,
}

/// A canonical transcript: its entries, the head after each, and what the
/// program sees. Built by [`verify_transcript`] and by nothing else.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedTranscript {
    entries: Vec<TranscriptEntry>,
    heads: Vec<D32>,
    opened: Vec<Opened>,
}

impl VerifiedTranscript {
    /// The entries, in order.
    pub fn entries(&self) -> &[TranscriptEntry] {
        &self.entries
    }

    /// `h_i`, for `i` from 1 to the number of entries.
    pub fn head(&self, index: u32) -> Option<&D32> {
        // A u32 index always fits a usize on the targets DSM builds for.
        self.heads.get(index as usize)
    }

    /// The head after the last entry.
    pub fn last_head(&self) -> &D32 {
        &self.heads[self.heads.len() - 1]
    }

    /// The opened entries, in order: what the program sees.
    pub fn opened(&self) -> &[Opened] {
        &self.opened
    }

    /// The index of the last entry `side` made, when it made any.
    pub fn last_of(&self, side: MatchSide) -> Option<u32> {
        self.entries
            .iter()
            .rev()
            .find(|e| e.side() == side)
            .map(TranscriptEntry::index)
    }
}

/// Whether `entry_bytes` are a canonical transcript for the match cell, the
/// table and the setup. The order of the checks is fixed (§19.10): each
/// entry is decoded, re-encoded and compared byte for byte before anything
/// is read out of it, and the chain is recomputed over the exact bytes.
/// Signatures are the occupant's to verify, over the heads this returns.
pub fn verify_transcript(
    match_cell: &D32,
    table: &ComputedTable,
    setup: &[u8],
    entry_bytes: &[Vec<u8>],
) -> Result<VerifiedTranscript, TranscriptRefusal> {
    if setup_digest(setup) != *table.setup_digest() {
        return Err(TranscriptRefusal::NotTheCommittedSetup);
    }
    if entry_bytes.len() > super::wire::TRANSCRIPT_MAX_ENTRIES {
        return Err(TranscriptRefusal::TooManyEntries);
    }
    let mut heads = Vec::with_capacity(entry_bytes.len() + 1);
    heads.push(genesis_head(match_cell, table.setup_digest()));
    let mut entries: Vec<TranscriptEntry> = Vec::with_capacity(entry_bytes.len());
    let mut opened = Vec::new();
    // Each side's unopened commitment, with the index it was made at.
    let mut open: BTreeMap<MatchSide, (u32, D32)> = BTreeMap::new();
    for (at, bytes) in entry_bytes.iter().enumerate() {
        // At most TRANSCRIPT_MAX_ENTRIES positions, so it fits.
        let position = (at + 1) as u32;
        let entry = TranscriptEntry::decode(bytes)
            .map_err(|why| TranscriptRefusal::EntryDoesNotDecode { position, why })?;
        if entry.encode() != *bytes {
            return Err(TranscriptRefusal::EntryNotCanonical { position });
        }
        if entry.index() != position {
            return Err(TranscriptRefusal::IndexOutOfOrder {
                position,
                index: entry.index(),
            });
        }
        if let Some(previous) = entries.last() {
            if matches!(previous.kind(), EntryKind::Resign) {
                return Err(TranscriptRefusal::EntryAfterResign { index: position });
            }
        }
        match entry.kind() {
            EntryKind::Commit { commitment } => {
                if open.contains_key(&entry.side()) {
                    return Err(TranscriptRefusal::CommitWhileOneIsOpen { index: position });
                }
                open.insert(entry.side(), (position, *commitment));
            }
            EntryKind::Reveal { salt, played } => {
                let (committed_at, commitment) = open
                    .remove(&entry.side())
                    .ok_or(TranscriptRefusal::NothingToReveal { index: position })?;
                if move_commitment(salt, played) != commitment {
                    return Err(TranscriptRefusal::RevealDoesNotOpenTheCommitment {
                        index: position,
                    });
                }
                opened.push(Opened {
                    index: position,
                    side: entry.side(),
                    kind: OpenedKind::Move {
                        committed_at,
                        played: played.clone(),
                    },
                });
            }
            EntryKind::Resign => opened.push(Opened {
                index: position,
                side: entry.side(),
                kind: OpenedKind::Resign,
            }),
        }
        let head = next_head(&heads[heads.len() - 1], bytes);
        heads.push(head);
        entries.push(entry);
    }
    Ok(VerifiedTranscript {
        entries,
        heads,
        opened,
    })
}

// ── signing: the producer halves ───────────────────────────────────────────

/// A side's signature over the head of its own entry `index`. Refuses a key
/// that does not sign as the session key it names.
pub fn sign_head(
    session: &super::wire::EscrowSigner,
    secret_key: &[u8],
    match_cell: &D32,
    index: u32,
    head: &D32,
) -> Result<Vec<u8>, crate::types::error::DsmError> {
    let digest = head_statement(match_cell, index, head);
    let signature = crate::crypto::sphincs::sphincs_sign(secret_key, &digest)?;
    verify_bytes(
        "TranscriptHead",
        session.signature_alg(),
        session.public_key(),
        &digest,
        &signature,
    )?;
    Ok(signature)
}

/// `side`'s ready signature for the match `Y` and `table` bind to: its
/// session key over `m_ready`. A wallet signs it only after it has checked
/// both vaults (SoFi §19.10, the ready handshake). Refuses a key that does
/// not sign as that side's session key.
pub fn sign_ready(
    external_commitment: &D32,
    table: &ComputedTable,
    side: MatchSide,
    secret_key: &[u8],
) -> Result<Vec<u8>, crate::types::error::DsmError> {
    let digest = ready_statement(&match_cell_of_table(external_commitment, table));
    let session = table.session(side);
    let signature = crate::crypto::sphincs::sphincs_sign(secret_key, &digest)?;
    verify_bytes(
        "Ready",
        session.signature_alg(),
        session.public_key(),
        &digest,
        &signature,
    )?;
    Ok(signature)
}

/// The Start the side that readies second writes: both ready signatures,
/// once each verifies under its side's session key.
pub fn assemble_start(
    external_commitment: &D32,
    table: &ComputedTable,
    ready_a: &[u8],
    ready_b: &[u8],
) -> Result<MatchStart, ComputedRefusal> {
    let start = MatchStart::new(
        *external_commitment,
        table.clone(),
        StartBody::Start {
            ready_a: ready_a.to_vec(),
            ready_b: ready_b.to_vec(),
        },
    )
    .map_err(ComputedRefusal::NoEncoding)?;
    let start_cell = start_cell_key(&match_cell_of_table(external_commitment, table));
    start_authority(&start, &start_cell)?;
    Ok(start)
}

/// `side`'s Withdraw for the match `Y` and `table` bind to. Refuses a key
/// that does not sign as that side's session key.
pub fn sign_withdraw(
    external_commitment: &D32,
    table: &ComputedTable,
    side: MatchSide,
    secret_key: &[u8],
) -> Result<MatchStart, crate::types::error::DsmError> {
    let start_cell = start_cell_key(&match_cell_of_table(external_commitment, table));
    let digest = withdraw_statement(&start_cell);
    let session = table.session(side);
    let signature = crate::crypto::sphincs::sphincs_sign(secret_key, &digest)?;
    verify_bytes(
        "Withdraw",
        session.signature_alg(),
        session.public_key(),
        &digest,
        &signature,
    )?;
    MatchStart::new(
        *external_commitment,
        table.clone(),
        StartBody::Withdraw { side, signature },
    )
    .map_err(|e| crate::types::error::DsmError::invalid_operation(e.to_string()))
}

// ── recognition ────────────────────────────────────────────────────────────

/// Why bytes do not occupy a match or start cell. Every variant is decided
/// from the bytes and the cell's key, with the verifier's own registry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ComputedRefusal {
    /// The bytes are not a canonical object of a class the cell holds.
    DoesNotDecode(crate::ccb::decode::DecodeError),
    /// An object of a class this cell never holds.
    NotAnOccupantClass { class: u16 },
    /// Its `Y` and table derive another cell.
    NotThisCell,
    /// Its entries are not a canonical transcript.
    Transcript(TranscriptRefusal),
    /// Its signatures are not exactly one for each side that made an entry.
    NotTheSidesThatPlayed,
    /// A signature does not verify under its side's session key.
    Signature(SignatureError),
    /// Its last entry opens nothing: the transcript runs past the entry that
    /// ended the match, or stops before one.
    LastEntryDoesNotOpen,
    /// The program the table pins is not registered with this verifier.
    ProgramNotRegistered { program: D32 },
    /// The program refuses the transcript.
    Program(ProgramFault),
    /// The program says the match has not ended.
    MatchNotEnded,
    /// The program says the match had already ended before the last entry.
    EndedBeforeTheLastEntry,
    /// The program named a label that is not a branch of the terms.
    LabelNotABranch { label: Vec<u8> },
    /// The signatures in hand form no `MatchStart` with canonical bytes.
    NoEncoding(super::wire::SofiWireError),
}

/// The outcome a recognized match-cell occupant gives, and which kind of
/// occupant it is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MatchOccupant {
    /// A transcript the registered program computed this label from.
    Transcript { label: Vec<u8> },
    /// Two heads `cheater`'s key signed at one index: the other side wins.
    Equivocation { cheater: MatchSide },
}

impl MatchOccupant {
    /// The branch label this occupant gives.
    pub fn label(&self) -> &[u8] {
        match self {
            Self::Transcript { label } => label,
            Self::Equivocation { cheater } => cheater.other().win_label(),
        }
    }
}

/// Whether `outcome` proves its own outcome at the match cell `match_cell`
/// (SoFi §19.10, "What occupies the match cell"):
/// 1. its `Y` and table derive the cell;
/// 2. its entries are a canonical transcript for the table and the setup;
/// 3. it holds exactly one signature per side that made an entry, each
///    verifying under that side's session key over the head of the last
///    entry that side made;
/// 4. its last entry opens (a Reveal or a Resign);
/// 5. the registered program gives `Done(o)` with `o` a branch label, and
///    `Incomplete` without the last opened entry.
///
/// No vault, member or reader's position enters it. The program sees nothing
/// until 1 to 4 hold.
pub fn transcript_authority(
    outcome: &TranscriptOutcome,
    match_cell: &D32,
    programs: &ProgramRegistry,
) -> Result<Vec<u8>, ComputedRefusal> {
    let table = outcome.table();
    if match_cell_of_table(outcome.external_commitment(), table) != *match_cell {
        return Err(ComputedRefusal::NotThisCell);
    }
    let transcript = verify_transcript(match_cell, table, outcome.setup(), outcome.entries())
        .map_err(ComputedRefusal::Transcript)?;
    let played: Vec<MatchSide> = [MatchSide::A, MatchSide::B]
        .into_iter()
        .filter(|side| transcript.last_of(*side).is_some())
        .collect();
    let signed: Vec<MatchSide> = outcome.signatures().iter().map(|s| s.side()).collect();
    if played != signed {
        return Err(ComputedRefusal::NotTheSidesThatPlayed);
    }
    for s in outcome.signatures() {
        let index = transcript
            .last_of(s.side())
            .ok_or(ComputedRefusal::NotTheSidesThatPlayed)?;
        let head = transcript
            .head(index)
            .ok_or(ComputedRefusal::NotTheSidesThatPlayed)?;
        let session = table.session(s.side());
        verify_bytes(
            "TranscriptOutcome",
            session.signature_alg(),
            session.public_key(),
            &head_statement(match_cell, index, head),
            s.signature(),
        )
        .map_err(ComputedRefusal::Signature)?;
    }
    let last_opens = transcript.entries().last().is_some_and(|last| {
        transcript
            .opened()
            .last()
            .is_some_and(|opened| opened.index == last.index())
    });
    if !last_opens {
        return Err(ComputedRefusal::LastEntryDoesNotOpen);
    }
    let program = programs
        .get(table.program())
        .ok_or(ComputedRefusal::ProgramNotRegistered {
            program: *table.program(),
        })?;
    let opened = transcript.opened();
    let label = match program
        .outcome(outcome.setup(), opened)
        .map_err(ComputedRefusal::Program)?
    {
        ProgramOutcome::Done(label) => label,
        ProgramOutcome::Incomplete => return Err(ComputedRefusal::MatchNotEnded),
    };
    if !COMPUTED_LABELS.contains(&label.as_slice()) {
        return Err(ComputedRefusal::LabelNotABranch { label });
    }
    match program
        .outcome(outcome.setup(), &opened[..opened.len() - 1])
        .map_err(ComputedRefusal::Program)?
    {
        ProgramOutcome::Incomplete => Ok(label),
        ProgramOutcome::Done(..) => Err(ComputedRefusal::EndedBeforeTheLastEntry),
    }
}

/// Whether `proof` proves, at the match cell `match_cell`, that its side's
/// session key signed two different heads at one index: its `Y` and table
/// derive the cell, and both signatures verify under that side's key over
/// the head statement of their own heads. The heads differ by encoding.
pub fn equivocation_authority(
    proof: &EquivocationProof,
    match_cell: &D32,
) -> Result<MatchSide, ComputedRefusal> {
    if match_cell_of_table(proof.external_commitment(), proof.table()) != *match_cell {
        return Err(ComputedRefusal::NotThisCell);
    }
    let session = proof.table().session(proof.side());
    for signed in proof.heads() {
        verify_bytes(
            "EquivocationProof",
            session.signature_alg(),
            session.public_key(),
            &head_statement(match_cell, proof.index(), signed.head()),
            signed.signature(),
        )
        .map_err(ComputedRefusal::Signature)?;
    }
    Ok(proof.side())
}

/// What `bytes` are at the match cell `match_cell`, when they prove their
/// own outcome there, or why they do not: anything that does not counts as
/// nothing at the cell.
pub fn match_occupant(
    bytes: &[u8],
    match_cell: &D32,
    programs: &ProgramRegistry,
) -> Result<MatchOccupant, ComputedRefusal> {
    let class = class_of(bytes)?;
    match class {
        crate::ccb::class::ESCROW_TRANSCRIPT_OUTCOME => {
            let outcome =
                TranscriptOutcome::decode(bytes).map_err(ComputedRefusal::DoesNotDecode)?;
            let label = transcript_authority(&outcome, match_cell, programs)?;
            Ok(MatchOccupant::Transcript { label })
        }
        crate::ccb::class::ESCROW_EQUIVOCATION_PROOF => {
            let proof = EquivocationProof::decode(bytes).map_err(ComputedRefusal::DoesNotDecode)?;
            let cheater = equivocation_authority(&proof, match_cell)?;
            Ok(MatchOccupant::Equivocation { cheater })
        }
        class => Err(ComputedRefusal::NotAnOccupantClass { class }),
    }
}

/// What `bytes` are at the start cell `start_cell`, when they prove their
/// own authority there ([`start_authority`]): a Start or a Withdraw.
pub fn start_occupant(bytes: &[u8], start_cell: &D32) -> Result<StartKind, ComputedRefusal> {
    let class = class_of(bytes)?;
    if class != crate::ccb::class::ESCROW_MATCH_START {
        return Err(ComputedRefusal::NotAnOccupantClass { class });
    }
    let start = MatchStart::decode(bytes).map_err(ComputedRefusal::DoesNotDecode)?;
    start_authority(&start, start_cell)?;
    Ok(start.kind())
}

/// Whether `start` proves its own authority at the start cell `start_cell`
/// (SoFi §19.10, the ready handshake): its `Y` and table derive the cell,
/// and
/// - a Start holds side A's signature over `m_ready` under `session_a` and
///   side B's under `session_b`, for the match cell its `Y` and table
///   derive; one side's ready alone is no Start;
/// - a Withdraw holds the signature of the side it names, under that side's
///   session key, over `m_withdraw`.
pub fn start_authority(start: &MatchStart, start_cell: &D32) -> Result<(), ComputedRefusal> {
    let match_cell = match_cell_of_table(start.external_commitment(), start.table());
    if start_cell_key(&match_cell) != *start_cell {
        return Err(ComputedRefusal::NotThisCell);
    }
    let by = |side: MatchSide, statement: &D32, signature: &[u8]| {
        let session = start.table().session(side);
        verify_bytes(
            "MatchStart",
            session.signature_alg(),
            session.public_key(),
            statement,
            signature,
        )
        .map_err(ComputedRefusal::Signature)
    };
    match start.body() {
        StartBody::Start { ready_a, ready_b } => {
            let ready = ready_statement(&match_cell);
            by(MatchSide::A, &ready, ready_a)?;
            by(MatchSide::B, &ready, ready_b)
        }
        StartBody::Withdraw { side, signature } => {
            by(*side, &withdraw_statement(start_cell), signature)
        }
    }
}

fn class_of(bytes: &[u8]) -> Result<u16, ComputedRefusal> {
    match bytes {
        [hi, lo, ..] => Ok(u16::from_be_bytes([*hi, *lo])),
        _ => Err(ComputedRefusal::DoesNotDecode(
            crate::ccb::decode::DecodeError::Truncated,
        )),
    }
}

// ── the cells ──────────────────────────────────────────────────────────────

/// The match and start cells of a computed escrow vault as Core derives
/// them: each key, and each route over the network's pinned set. Built only
/// by [`ComputedCells::new`], which refuses members that are not the
/// committed set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComputedCells {
    match_key: D32,
    start_key: D32,
    program: D32,
    match_cell: RoutedCell,
    start_cell: RoutedCell,
}

impl ComputedCells {
    /// The cells `terms` bind a vault to. `members` must re-derive
    /// `committed_set_id`, the network's pinned set.
    pub fn new(
        terms: &ComputedEscrowTerms,
        members: &crate::ccb::StorageSetMembers,
        committed_set_id: &D32,
    ) -> Result<Self, CellError> {
        let match_key = match_cell_of(terms);
        let start_key = start_cell_key(&match_key);
        let match_cell = RoutedCell::new(
            TAG_DSM_ESCROW_COMPUTED_MATCH.source_bytes(),
            match_key,
            &match_seed(&match_key),
            members,
            committed_set_id,
        )?;
        let start_cell = RoutedCell::new(
            TAG_DSM_ESCROW_COMPUTED_START.source_bytes(),
            start_key,
            &start_seed(&start_key),
            members,
            committed_set_id,
        )?;
        Ok(Self {
            match_key,
            start_key,
            program: *terms.table().program(),
            match_cell,
            start_cell,
        })
    }

    /// `K_match`.
    pub fn match_key(&self) -> &D32 {
        &self.match_key
    }

    /// `K_start`.
    pub fn start_key(&self) -> &D32 {
        &self.start_key
    }

    /// `P`, the program the terms pin.
    pub fn program(&self) -> &D32 {
        &self.program
    }

    pub fn match_routed(&self) -> &RoutedCell {
        &self.match_cell
    }

    pub fn start_routed(&self) -> &RoutedCell {
        &self.start_cell
    }
}

/// What a reader found at a start cell: open, or the Start or Withdraw
/// holding it with its exact bytes. Built by [`start_resolution`] only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartCellRead {
    key: D32,
    match_key: D32,
    fact: CellFact,
    held: Option<(StartKind, Vec<u8>)>,
    passed_over: Vec<ComputedRefusal>,
}

impl StartCellRead {
    pub fn key(&self) -> &D32 {
        &self.key
    }

    pub fn fact(&self) -> CellFact {
        self.fact
    }

    /// The Start or Withdraw holding the cell, if any.
    pub fn held(&self) -> Option<StartKind> {
        self.held.as_ref().map(|(kind, _)| *kind)
    }

    /// The exact bytes holding the cell: what a relay carries.
    pub fn value(&self) -> Option<&[u8]> {
        self.held.as_ref().map(|(_, value)| value.as_slice())
    }

    /// Why each value ahead of the one holding the cell counts as nothing.
    pub fn passed_over(&self) -> &[ComputedRefusal] {
        &self.passed_over
    }

    /// The chain state of a held Start: what the match cell's facts stand
    /// on. `None` while the cell is open or a Withdraw holds it.
    fn started(&self) -> Option<ChainState> {
        match (&self.held, self.fact) {
            (Some((StartKind::Start, _)), CellFact::Held { state, .. }) => Some(state),
            (Some(..), _) | (None, _) => None,
        }
    }
}

/// What a reader found at a match cell: open, or the label of the occupant
/// holding it with its exact bytes. Built by [`match_resolution`] only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatchCellRead {
    key: D32,
    fact: CellFact,
    held: Option<(MatchOccupant, Vec<u8>)>,
    passed_over: Vec<ComputedRefusal>,
}

impl MatchCellRead {
    pub fn key(&self) -> &D32 {
        &self.key
    }

    pub fn fact(&self) -> CellFact {
        self.fact
    }

    /// The occupant holding the cell, if any.
    pub fn occupant(&self) -> Option<&MatchOccupant> {
        self.held.as_ref().map(|(occupant, _)| occupant)
    }

    /// The exact bytes holding the cell: what a relay carries.
    pub fn value(&self) -> Option<&[u8]> {
        self.held.as_ref().map(|(_, value)| value.as_slice())
    }

    /// Why each value ahead of the one holding the cell counts as nothing.
    pub fn passed_over(&self) -> &[ComputedRefusal] {
        &self.passed_over
    }
}

/// What a Release reads at a computed vault's cells (SoFi §19.10, "The
/// facts"): the start cell, and the match cell only once a Start holds the
/// start cell. Built by [`ComputedCellRead::of`] only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComputedCellRead {
    start: StartCellRead,
    matched: Option<MatchCellRead>,
}

/// Why a computed cell read was not assembled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ComputedReadError {
    /// A match cell read without a Start holding the start cell: the match
    /// cell counts for nothing until one does.
    MatchReadBeforeStart,
    /// A match cell read whose key is not the one the start cell derives
    /// from.
    NotThisMatch,
    /// A Start holds the start cell and the match cell was not read.
    MatchCellUnread,
}

impl ComputedCellRead {
    /// The read of a computed vault's cells: the start cell's, and the match
    /// cell's exactly when a Start holds the start cell.
    pub fn of(
        start: StartCellRead,
        matched: Option<MatchCellRead>,
    ) -> Result<Self, ComputedReadError> {
        match (start.started(), &matched) {
            (Some(..), Some(m)) if start_cell_key(m.key()) != *start.key() => {
                Err(ComputedReadError::NotThisMatch)
            }
            (Some(..), Some(..)) | (None, None) => Ok(Self { start, matched }),
            (Some(..), None) => Err(ComputedReadError::MatchCellUnread),
            (None, Some(..)) => Err(ComputedReadError::MatchReadBeforeStart),
        }
    }

    /// `K_match`: the cell a Release against the vault names.
    pub fn key(&self) -> D32 {
        match &self.matched {
            Some(m) => m.key,
            None => self.start.match_key,
        }
    }

    pub fn start(&self) -> &StartCellRead {
        &self.start
    }

    /// The match cell, read once a Start held the start cell.
    pub fn matched(&self) -> Option<&MatchCellRead> {
        self.matched.as_ref()
    }

    /// Where a release naming `outcome` stands (SoFi §19.10, "The facts"):
    ///
    /// - a Withdraw holding the start cell is `void`, final when it is final
    ///   there, and every other outcome is lost;
    /// - a Start holding it lets the match cell decide: its occupant's label
    ///   is lost for every other outcome in any state, and final only when
    ///   both the Start and the occupant are final;
    /// - anything else settles nothing.
    pub fn standing_for(&self, outcome: &[u8]) -> VerdictStanding {
        let start_state = match (&self.start.held, self.start.fact) {
            (Some((StartKind::Withdraw, _)), CellFact::Held { state, .. }) => {
                return if outcome != COMPUTED_LABEL_VOID {
                    VerdictStanding::Lost
                } else if state == ChainState::Final {
                    VerdictStanding::Final
                } else {
                    VerdictStanding::Unsettled
                };
            }
            (Some((StartKind::Start, _)), CellFact::Held { state, .. }) => state,
            (Some(..), CellFact::Open) | (None, _) => return VerdictStanding::Unsettled,
        };
        let Some(matched) = &self.matched else {
            return VerdictStanding::Unsettled;
        };
        match (&matched.held, matched.fact) {
            (Some((occupant, _)), CellFact::Held { state, .. }) => {
                if occupant.label() != outcome {
                    VerdictStanding::Lost
                } else if state == ChainState::Final && start_state == ChainState::Final {
                    VerdictStanding::Final
                } else {
                    VerdictStanding::Unsettled
                }
            }
            (None, _) | (Some(..), CellFact::Open) => VerdictStanding::Unsettled,
        }
    }
}

/// The route-chain reading of a computed vault's start cell (storage spec
/// §9): open, or the first Start or Withdraw at its leader that proves its
/// own authority there, and how far its chain has gone. Evidence that does
/// not decide the cell yet is [`Missing`].
pub fn start_resolution(
    cells: &ComputedCells,
    evidence: &CellEvidence,
) -> Result<StartCellRead, Missing> {
    let refused = std::cell::RefCell::new(Vec::new());
    let reading = evaluate(&cells.start_cell, evidence, start_at(cells, &refused))?;
    let fact = reading.fact();
    let held = match reading {
        CellReading::Held { object, value, .. } => Some((object, value)),
        CellReading::Open => None,
    };
    Ok(StartCellRead {
        key: cells.start_key,
        match_key: cells.match_key,
        fact,
        held,
        passed_over: refused.into_inner(),
    })
}

fn start_at<'c>(
    cells: &'c ComputedCells,
    refused: &'c std::cell::RefCell<Vec<ComputedRefusal>>,
) -> impl Fn(&[u8]) -> Option<(D32, StartKind)> + 'c {
    move |bytes| match start_occupant(bytes, &cells.start_key) {
        Ok(kind) => Some((occupant_id(&cells.start_key, start_label(kind)), kind)),
        Err(refusal) => {
            refused.borrow_mut().push(refusal);
            None
        }
    }
}

fn start_label(kind: StartKind) -> &'static [u8] {
    match kind {
        StartKind::Start => b"start",
        StartKind::Withdraw => b"withdraw",
    }
}

/// Why a match cell has no reading.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MatchUnread {
    /// The program the terms pin is not registered with this verifier:
    /// nothing at the cell can be recognized or refuted, so nothing is
    /// established.
    ProgramNotRegistered { program: D32 },
    /// The cell's evidence does not decide it yet: a network status.
    Missing(Missing),
}

/// The route-chain reading of a computed vault's match cell: open, or the
/// first occupant at its leader that proves its own outcome there, and how
/// far its chain has gone. Read only with the program the terms pin
/// registered: without it the reading is not established, never open.
pub fn match_resolution(
    cells: &ComputedCells,
    evidence: &CellEvidence,
    programs: &ProgramRegistry,
) -> Result<MatchCellRead, MatchUnread> {
    if programs.get(&cells.program).is_none() {
        return Err(MatchUnread::ProgramNotRegistered {
            program: cells.program,
        });
    }
    let refused = std::cell::RefCell::new(Vec::new());
    let reading = evaluate(
        &cells.match_cell,
        evidence,
        match_at(cells, programs, &refused),
    )
    .map_err(MatchUnread::Missing)?;
    let fact = reading.fact();
    let held = match reading {
        CellReading::Held { object, value, .. } => Some((object, value)),
        CellReading::Open => None,
    };
    Ok(MatchCellRead {
        key: cells.match_key,
        fact,
        held,
        passed_over: refused.into_inner(),
    })
}

fn match_at<'c>(
    cells: &'c ComputedCells,
    programs: &'c ProgramRegistry,
    refused: &'c std::cell::RefCell<Vec<ComputedRefusal>>,
) -> impl Fn(&[u8]) -> Option<(D32, MatchOccupant)> + 'c {
    move |bytes| match match_occupant(bytes, &cells.match_key, programs) {
        Ok(occupant) => Some((occupant_id(&cells.match_key, occupant.label()), occupant)),
        Err(refusal) => {
            refused.borrow_mut().push(refusal);
            None
        }
    }
}

/// The completion proof of the Start or Withdraw `read` found final at the
/// start cell (SoFi Amendment S10); `None` while no chain of it has three
/// links, or when the cell is open.
pub fn start_completion(
    cells: &ComputedCells,
    read: &StartCellRead,
    evidence: &CellEvidence,
) -> Result<Option<CompletionProof>, Missing> {
    let held = |bytes: &[u8]| match &read.held {
        Some((kind, value)) if value.as_slice() == bytes => {
            Some((occupant_id(&cells.start_key, start_label(*kind)), *kind))
        }
        Some(..) | None => None,
    };
    Ok(completion_proof(&cells.start_cell, evidence, held)?.map(|(_, proof)| proof))
}

/// The completion proof of the occupant `read` found final at the match
/// cell; `None` while no chain of it has three links, or when the cell is
/// open.
pub fn match_completion(
    cells: &ComputedCells,
    read: &MatchCellRead,
    evidence: &CellEvidence,
) -> Result<Option<CompletionProof>, Missing> {
    let held = |bytes: &[u8]| match &read.held {
        Some((occupant, value)) if value.as_slice() == bytes => Some((
            occupant_id(&cells.match_key, occupant.label()),
            occupant.clone(),
        )),
        Some(..) | None => None,
    };
    Ok(completion_proof(&cells.match_cell, evidence, held)?.map(|(_, proof)| proof))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ccb::sigalg::SPHINCS_PLUS_SPX256F as ALG;
    use crate::crypto::sphincs::{generate_keypair_from_seed, SphincsVariant};
    use crate::route_chain::fixtures::{committed_set, committed_set_id, Cell};
    use crate::sofi::escrow::external_commitment;
    use crate::sofi::wire::{
        ComputedBranch, EscrowSigner, SideSignature, SignedHead, SofiWireError,
        COMPUTED_LABEL_A_WINS, COMPUTED_LABEL_B_WINS, COMPUTED_MAX_SETUP_BYTES,
        TRANSCRIPT_MAX_ENTRIES, TRANSCRIPT_MAX_MOVE_BYTES,
    };

    // ── a test program ─────────────────────────────────────────────────

    /// The test program's hash.
    const SUM_PROGRAM: D32 = [0x9A; 32];

    /// A match of `setup[0]` rounds. In each round both sides commit a move
    /// of one byte and then both reveal; once every round is revealed, the
    /// side whose moves sum higher wins, and an equal sum is `void`. A
    /// resignation gives the other side the win. Both commitments of a round
    /// precede both reveals of it, and nothing follows the end: anything
    /// else is a fault.
    struct HighestSum;

    impl OutcomeProgram for HighestSum {
        fn id(&self) -> [u8; 32] {
            SUM_PROGRAM
        }

        fn outcome(&self, setup: &[u8], opened: &[Opened]) -> Result<ProgramOutcome, ProgramFault> {
            let rounds = usize::from(*setup.first().ok_or(ProgramFault("no setup".into()))?);
            let mut moves: BTreeMap<MatchSide, Vec<(u32, u32, u8)>> = BTreeMap::new();
            for (at, entry) in opened.iter().enumerate() {
                let ended = at > 0 && ended_by(rounds, &opened[..at]).is_some();
                if ended {
                    return Err(ProgramFault("an entry after the end".into()));
                }
                match &entry.kind {
                    OpenedKind::Resign => {}
                    OpenedKind::Move {
                        committed_at,
                        played,
                    } => {
                        let byte = match played.as_slice() {
                            [b] => *b,
                            _ => return Err(ProgramFault("a move is one byte".into())),
                        };
                        moves.entry(entry.side).or_default().push((
                            *committed_at,
                            entry.index,
                            byte,
                        ));
                    }
                }
            }
            // Within a round, both commitments precede both reveals.
            let made = |side: MatchSide| -> &[(u32, u32, u8)] {
                match moves.get(&side) {
                    Some(made) => made,
                    None => &[],
                }
            };
            for ((ca, ra, _), (cb, rb, _)) in made(MatchSide::A).iter().zip(made(MatchSide::B)) {
                if ca.max(cb) > ra.min(rb) {
                    return Err(ProgramFault("a move revealed before both committed".into()));
                }
            }
            Ok(match ended_by(rounds, opened) {
                Some(label) => ProgramOutcome::Done(label),
                None => ProgramOutcome::Incomplete,
            })
        }
    }

    /// The label the match has ended with after `opened`, or `None`.
    fn ended_by(rounds: usize, opened: &[Opened]) -> Option<Vec<u8>> {
        if let Some(resigned) = opened.iter().find(|o| o.kind == OpenedKind::Resign) {
            return Some(resigned.side.other().win_label().to_vec());
        }
        let sum = |side: MatchSide| -> (usize, u32) {
            opened
                .iter()
                .filter(|o| o.side == side)
                .fold((0, 0), |(n, total), o| match &o.kind {
                    OpenedKind::Move { played, .. } => (n + 1, total + u32::from(played[0])),
                    OpenedKind::Resign => (n, total),
                })
        };
        let (na, sa) = sum(MatchSide::A);
        let (nb, sb) = sum(MatchSide::B);
        if na < rounds || nb < rounds {
            return None;
        }
        Some(match sa.cmp(&sb) {
            core::cmp::Ordering::Greater => COMPUTED_LABEL_A_WINS.to_vec(),
            core::cmp::Ordering::Less => COMPUTED_LABEL_B_WINS.to_vec(),
            core::cmp::Ordering::Equal => COMPUTED_LABEL_VOID.to_vec(),
        })
    }

    /// A program that is not final: it reports the end and keeps reporting
    /// it whatever follows. Core still holds a transcript to the entry that
    /// ended the match.
    struct NeverFaults;

    impl OutcomeProgram for NeverFaults {
        fn id(&self) -> [u8; 32] {
            SUM_PROGRAM
        }

        fn outcome(&self, setup: &[u8], opened: &[Opened]) -> Result<ProgramOutcome, ProgramFault> {
            let rounds = usize::from(setup[0]);
            Ok(match ended_by(rounds, opened) {
                Some(label) => ProgramOutcome::Done(label),
                None => ProgramOutcome::Incomplete,
            })
        }
    }

    /// A program that names a label no computed vault has.
    struct SaysDraw;

    impl OutcomeProgram for SaysDraw {
        fn id(&self) -> [u8; 32] {
            SUM_PROGRAM
        }

        fn outcome(&self, _: &[u8], opened: &[Opened]) -> Result<ProgramOutcome, ProgramFault> {
            Ok(match opened.len() {
                0..=3 => ProgramOutcome::Incomplete,
                _ => ProgramOutcome::Done(b"draw".to_vec()),
            })
        }
    }

    fn registry(program: impl OutcomeProgram + 'static) -> ProgramRegistry {
        let mut r = ProgramRegistry::new();
        r.register(Arc::new(program)).expect("registers");
        r
    }

    // ── the match ──────────────────────────────────────────────────────

    struct Player {
        session: EscrowSigner,
        secret: Vec<u8>,
    }

    fn player(seed: u8) -> Player {
        let kp = generate_keypair_from_seed(SphincsVariant::SPX256f, &[seed; 32]).expect("keypair");
        Player {
            session: EscrowSigner::new(ALG, &kp.public_key).expect("a declared key"),
            secret: kp.secret_key.clone(),
        }
    }

    struct Match {
        a: Player,
        b: Player,
        y: D32,
        setup: Vec<u8>,
        table: ComputedTable,
    }

    impl Match {
        fn key(&self) -> D32 {
            match_cell_of_table(&self.y, &self.table)
        }

        fn player(&self, side: MatchSide) -> &Player {
            match side {
                MatchSide::A => &self.a,
                MatchSide::B => &self.b,
            }
        }

        /// One side's terms: every branch pays as a match's do, `void` to
        /// `owner`.
        fn terms(&self, owner: (D32, D32)) -> ComputedEscrowTerms {
            ComputedEscrowTerms::new(
                [0xE7; 32],
                self.y,
                self.table.clone(),
                vec![
                    ComputedBranch::new(COMPUTED_LABEL_A_WINS, [0xA1; 32], [0xA2; 32]),
                    ComputedBranch::new(COMPUTED_LABEL_B_WINS, [0xB1; 32], [0xB2; 32]),
                    ComputedBranch::new(COMPUTED_LABEL_VOID, owner.0, owner.1),
                ],
            )
            .expect("terms")
        }

        /// The heads of `entries`, `h_0` first.
        fn heads(&self, entries: &[Vec<u8>]) -> Vec<D32> {
            let mut heads = vec![genesis_head(&self.key(), &setup_digest(&self.setup))];
            for e in entries {
                let next = next_head(&heads[heads.len() - 1], e);
                heads.push(next);
            }
            heads
        }

        /// `side`'s signature over the head of entry `index` of `entries`.
        fn sign(&self, side: MatchSide, entries: &[Vec<u8>], index: u32) -> Vec<u8> {
            let heads = self.heads(entries);
            sign_head(
                &self.player(side).session,
                &self.player(side).secret,
                &self.key(),
                index,
                &heads[index as usize],
            )
            .expect("signs")
        }

        /// The transcript of `entries`, each side signing the head of its
        /// last entry.
        fn outcome(&self, entries: Vec<Vec<u8>>) -> TranscriptOutcome {
            let mut signatures = Vec::new();
            for side in [MatchSide::A, MatchSide::B] {
                let last = entries
                    .iter()
                    .rev()
                    .map(|e| TranscriptEntry::decode(e).expect("an entry"))
                    .find(|e| e.side() == side);
                if let Some(last) = last {
                    signatures.push(
                        SideSignature::new(side, &self.sign(side, &entries, last.index()))
                            .expect("signature"),
                    );
                }
            }
            self.outcome_signed(entries, signatures)
        }

        fn outcome_signed(
            &self,
            entries: Vec<Vec<u8>>,
            signatures: Vec<SideSignature>,
        ) -> TranscriptOutcome {
            TranscriptOutcome::new(self.y, self.table.clone(), &self.setup, entries, signatures)
                .expect("outcome")
        }
    }

    /// Both sides ready: the Start the second to ready writes.
    fn start_of(m: &Match) -> MatchStart {
        let ready_a = sign_ready(&m.y, &m.table, MatchSide::A, &m.a.secret).expect("A ready");
        let ready_b = sign_ready(&m.y, &m.table, MatchSide::B, &m.b.secret).expect("B ready");
        assemble_start(&m.y, &m.table, &ready_a, &ready_b).expect("a Start")
    }

    fn withdraw_by(m: &Match, side: MatchSide) -> MatchStart {
        sign_withdraw(&m.y, &m.table, side, &m.player(side).secret).expect("a Withdraw")
    }

    fn the_match() -> Match {
        let a = player(0x61);
        let b = player(0x62);
        let setup = vec![2, 0xC0, 0xDE];
        let table = ComputedTable::new(
            SUM_PROGRAM,
            setup_digest(&setup),
            a.session.clone(),
            b.session.clone(),
        )
        .expect("table");
        Match {
            a,
            b,
            y: external_commitment(b"computed match 1"),
            setup,
            table,
        }
    }

    fn salt(side: MatchSide, round: u8) -> D32 {
        [0x50 + side.byte() * 0x10 + round; 32]
    }

    fn commit(index: u32, side: MatchSide, round: u8, played: u8) -> Vec<u8> {
        TranscriptEntry::new(
            index,
            side,
            EntryKind::Commit {
                commitment: move_commitment(&salt(side, round), &[played]),
            },
        )
        .expect("entry")
        .encode()
    }

    fn reveal(index: u32, side: MatchSide, round: u8, played: u8) -> Vec<u8> {
        TranscriptEntry::new(
            index,
            side,
            EntryKind::Reveal {
                salt: salt(side, round),
                played: vec![played],
            },
        )
        .expect("entry")
        .encode()
    }

    fn resign(index: u32, side: MatchSide) -> Vec<u8> {
        TranscriptEntry::new(index, side, EntryKind::Resign)
            .expect("entry")
            .encode()
    }

    /// Rounds of `(a's move, b's move)`, each committed by A then B and
    /// revealed by A then B, indexed from `from`.
    fn rounds(moves: &[(u8, u8)], from: u32) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        let mut i = from;
        for (round, (ma, mb)) in moves.iter().enumerate() {
            let r = round as u8;
            out.push(commit(i, MatchSide::A, r, *ma));
            out.push(commit(i + 1, MatchSide::B, r, *mb));
            out.push(reveal(i + 2, MatchSide::A, r, *ma));
            out.push(reveal(i + 3, MatchSide::B, r, *mb));
            i += 4;
        }
        out
    }

    /// Two rounds A wins on the sum.
    fn a_wins() -> Vec<Vec<u8>> {
        rounds(&[(5, 3), (4, 4)], 1)
    }

    fn occupant(m: &Match, outcome: &TranscriptOutcome) -> Result<MatchOccupant, ComputedRefusal> {
        match_occupant(&outcome.encode(), &m.key(), &registry(HighestSum))
    }

    /// `BLAKE3(tag ‖ 0x00 ‖ parts)` with the tag typed from the specification,
    /// not read from the constants.
    fn independent(tag: &str, parts: &[&[u8]]) -> D32 {
        let mut hasher = ::blake3::Hasher::new();
        hasher.update(tag.as_bytes());
        hasher.update(&[0x00]);
        for p in parts {
            hasher.update(p);
        }
        *hasher.finalize().as_bytes()
    }

    // ── the wire ───────────────────────────────────────────────────────

    #[test]
    fn the_computed_objects_round_trip_and_refuse_what_has_no_encoding() {
        let m = the_match();
        let terms = m.terms(([0x01; 32], [0x02; 32]));
        let bytes = terms.encode();
        assert_eq!(&bytes[..4], &[0x00, 0x67, 0x00, 0x01]);
        assert_eq!(ComputedEscrowTerms::decode(&bytes), Ok(terms.clone()));
        assert_eq!(
            super::super::wire::EscrowKind::decode(&bytes),
            Ok(super::super::wire::EscrowKind::Computed(terms.clone()))
        );

        for entry in [
            commit(1, MatchSide::A, 0, 7),
            reveal(2, MatchSide::B, 0, 9),
            resign(3, MatchSide::A),
        ] {
            let decoded = TranscriptEntry::decode(&entry).expect("decodes");
            assert_eq!(decoded.encode(), entry);
            let mut trailing = entry.clone();
            trailing.push(0);
            assert!(matches!(
                TranscriptEntry::decode(&trailing),
                Err(crate::ccb::decode::DecodeError::TrailingBytes { extra: 1 })
            ));
        }
        // An entry's bytes, by hand from the field table: a Reveal.
        let mut want = vec![0x00, 0x68, 0x00, 0x01];
        want.extend_from_slice(&2u32.to_be_bytes());
        want.extend_from_slice(&[2, 2]);
        want.extend_from_slice(&salt(MatchSide::B, 0));
        want.extend_from_slice(&1u32.to_be_bytes());
        want.push(9);
        assert_eq!(reveal(2, MatchSide::B, 0, 9), want);

        let outcome = m.outcome(a_wins());
        assert_eq!(TranscriptOutcome::decode(&outcome.encode()), Ok(outcome));
        let start = start_of(&m);
        assert_eq!(MatchStart::decode(&start.encode()), Ok(start));
        let withdraw = withdraw_by(&m, MatchSide::B);
        assert_eq!(MatchStart::decode(&withdraw.encode()), Ok(withdraw.clone()));
        // A Withdraw's bytes, by hand from the field table.
        let StartBody::Withdraw { signature, .. } = withdraw.body() else {
            panic!("a Withdraw")
        };
        let mut want = vec![0x00, 0x6B, 0x00, 0x01];
        want.extend_from_slice(&m.y);
        want.extend_from_slice(&m.table.canonical());
        want.extend_from_slice(&[2, 2]);
        want.extend_from_slice(&(signature.len() as u32).to_be_bytes());
        want.extend_from_slice(signature);
        assert_eq!(withdraw.encode(), want);
        let proof = EquivocationProof::new(
            m.y,
            m.table.clone(),
            MatchSide::A,
            1,
            SignedHead::new([0x01; 32], &[0x0A; 3]).expect("head"),
            SignedHead::new([0x02; 32], &[0x0B; 3]).expect("head"),
        )
        .expect("proof");
        assert_eq!(EquivocationProof::decode(&proof.encode()), Ok(proof));

        // What has no encoding.
        let mut wrong_labels: Vec<ComputedBranch> = terms.branches().to_vec();
        wrong_labels.swap(0, 1);
        assert_eq!(
            ComputedEscrowTerms::new([0xE7; 32], m.y, m.table.clone(), wrong_labels),
            Err(SofiWireError::ComputedBranchesNotTheThreeLabels)
        );
        assert_eq!(
            ComputedEscrowTerms::new(
                [0xE7; 32],
                m.y,
                m.table.clone(),
                terms.branches()[..2].to_vec()
            ),
            Err(SofiWireError::ComputedBranchesNotTheThreeLabels)
        );
        assert_eq!(
            ComputedTable::new(
                SUM_PROGRAM,
                setup_digest(&m.setup),
                m.a.session.clone(),
                m.a.session.clone()
            ),
            Err(SofiWireError::SessionKeysNotDistinct)
        );
        assert!(matches!(
            TranscriptEntry::new(0, MatchSide::A, EntryKind::Resign),
            Err(SofiWireError::UndeclaredValue { value: 0, .. })
        ));
        assert!(matches!(
            TranscriptEntry::new(
                1,
                MatchSide::A,
                EntryKind::Reveal {
                    salt: [0x01; 32],
                    played: vec![0x01; TRANSCRIPT_MAX_MOVE_BYTES + 1]
                }
            ),
            Err(SofiWireError::Cardinality { .. })
        ));
        let mut side_three = commit(1, MatchSide::A, 0, 7);
        side_three[8] = 3;
        assert!(matches!(
            TranscriptEntry::decode(&side_three),
            Err(crate::ccb::decode::DecodeError::Invalid(..))
        ));
        assert!(matches!(
            EquivocationProof::new(
                m.y,
                m.table.clone(),
                MatchSide::A,
                1,
                SignedHead::new([0x02; 32], &[0x0A; 3]).expect("head"),
                SignedHead::new([0x02; 32], &[0x0B; 3]).expect("head"),
            ),
            Err(SofiWireError::NotStrictlyAscending { .. })
        ));
    }

    /// The largest transcript and the largest proof fit a cell's value bound,
    /// with two SPHINCS+ signatures (SoFi §19.10, "Bounds").
    #[test]
    fn the_largest_occupants_fit_a_cell_value() {
        let m = the_match();
        let longest_entry = TranscriptEntry::new(
            u32::MAX,
            MatchSide::B,
            EntryKind::Reveal {
                salt: [0x01; 32],
                played: vec![0x01; TRANSCRIPT_MAX_MOVE_BYTES],
            },
        )
        .expect("entry")
        .encode();
        assert_eq!(
            longest_entry.len(),
            crate::sofi::wire::TRANSCRIPT_MAX_ENTRY_BYTES
        );
        let signature = vec![0x01; 49_856];
        let largest = TranscriptOutcome::new(
            m.y,
            m.table.clone(),
            &vec![0x01; COMPUTED_MAX_SETUP_BYTES],
            vec![longest_entry; TRANSCRIPT_MAX_ENTRIES],
            vec![
                SideSignature::new(MatchSide::A, &signature).expect("signature"),
                SideSignature::new(MatchSide::B, &signature).expect("signature"),
            ],
        )
        .expect("the largest outcome");
        assert!(largest.encode().len() <= crate::route_chain::MAX_VALUE_LEN);
        let proof = EquivocationProof::new(
            m.y,
            m.table.clone(),
            MatchSide::A,
            1,
            SignedHead::new([0x01; 32], &signature).expect("head"),
            SignedHead::new([0x02; 32], &signature).expect("head"),
        )
        .expect("proof");
        assert!(proof.encode().len() <= crate::route_chain::MAX_VALUE_LEN);
    }

    // ── the derivations ────────────────────────────────────────────────

    #[test]
    fn the_derivations_are_the_specified_hashes() {
        let m = the_match();
        let tau = table_digest(&m.table);
        assert_eq!(
            tau,
            independent("DSM/escrow/computed-table/v1", &[&m.table.canonical()])
        );
        let k = m.key();
        assert_eq!(
            k,
            independent("DSM/escrow/computed-match/v1", &[&m.y, &tau])
        );
        assert_eq!(
            match_seed(&k),
            independent("DSM/escrow/computed-match-seed/v1", &[&k])
        );
        let ks = start_cell_key(&k);
        assert_eq!(ks, independent("DSM/escrow/computed-start/v1", &[&k]));
        assert_eq!(
            start_seed(&ks),
            independent("DSM/escrow/computed-start-seed/v1", &[&ks])
        );
        assert_eq!(
            withdraw_statement(&ks),
            independent("DSM/escrow/computed-start-statement/v1", &[&ks, &[2]])
        );
        assert_eq!(
            ready_statement(&k),
            independent("DSM/escrow/computed-ready/v1", &[&k])
        );
        assert_eq!(
            setup_digest(&m.setup),
            independent("DSM/escrow/computed-setup/v1", &[&m.setup])
        );
        assert_eq!(
            occupant_id(&k, b"void"),
            independent(
                "DSM/escrow/computed-occupant/v1",
                &[&k, &4u32.to_be_bytes(), b"void"]
            )
        );
        assert_eq!(
            move_commitment(&[0x07; 32], &[9]),
            independent(
                "DSM/escrow/move-commit/v1",
                &[&[0x07; 32], &1u32.to_be_bytes(), &[9]]
            )
        );
        let h0 = genesis_head(&k, m.table.setup_digest());
        assert_eq!(
            h0,
            independent("DSM/escrow/transcript/v1", &[&k, m.table.setup_digest()])
        );
        let e1 = commit(1, MatchSide::A, 0, 5);
        let h1 = next_head(&h0, &e1);
        assert_eq!(
            h1,
            independent("DSM/escrow/transcript-step/v1", &[&h0, &e1])
        );
        assert_eq!(
            head_statement(&k, 1, &h1),
            independent(
                "DSM/escrow/transcript-head/v1",
                &[&k, &1u32.to_be_bytes(), &h1]
            )
        );
        // The table's bytes, by hand.
        let mut want = SUM_PROGRAM.to_vec();
        want.extend_from_slice(&setup_digest(&m.setup));
        for s in [&m.a.session, &m.b.session] {
            want.extend_from_slice(&s.signature_alg().to_be_bytes());
            want.extend_from_slice(&(s.public_key().len() as u32).to_be_bytes());
            want.extend_from_slice(s.public_key());
        }
        assert_eq!(m.table.canonical(), want);
    }

    /// `K_match` changes with every byte of `Y` and of the table, and with
    /// nothing else: the two players' terms differ only in recipients and
    /// share one cell.
    #[test]
    fn the_match_cell_changes_with_every_byte_of_y_and_the_table() {
        let m = the_match();
        let a_terms = m.terms(([0xA1; 32], [0xA2; 32]));
        let b_terms = m.terms(([0xB1; 32], [0xB2; 32]));
        assert_ne!(a_terms, b_terms);
        assert_eq!(match_cell_of(&a_terms), match_cell_of(&b_terms));

        let bytes = a_terms.encode();
        let k = match_cell_of(&a_terms);
        // Y and the table run from after the envelope and the token to the
        // branch count.
        let from = 4 + 32;
        let to = from + 32 + m.table.canonical().len();
        let mut decoded = 0;
        for i in from..to {
            let mut mutated = bytes.clone();
            mutated[i] ^= 0x01;
            if let Ok(terms) = ComputedEscrowTerms::decode(&mutated) {
                decoded += 1;
                assert_ne!(match_cell_of(&terms), k, "byte {i}");
                assert_ne!(
                    start_cell_key(&match_cell_of(&terms)),
                    start_cell_key(&k),
                    "byte {i}"
                );
            }
        }
        // Every byte but the eight algorithm and length bytes of the two
        // keys decodes to other terms.
        assert_eq!(decoded, to - from - 12);
    }

    // ── what occupies the match cell ───────────────────────────────────

    #[test]
    fn a_finished_transcript_proves_its_outcome() {
        let m = the_match();
        assert_eq!(
            occupant(&m, &m.outcome(a_wins())),
            Ok(MatchOccupant::Transcript {
                label: COMPUTED_LABEL_A_WINS.to_vec()
            })
        );
        // B wins on the sum, and an equal sum is void.
        assert_eq!(
            occupant(&m, &m.outcome(rounds(&[(1, 3), (4, 4)], 1))).map(|o| o.label().to_vec()),
            Ok(COMPUTED_LABEL_B_WINS.to_vec())
        );
        assert_eq!(
            occupant(&m, &m.outcome(rounds(&[(3, 3), (4, 4)], 1))).map(|o| o.label().to_vec()),
            Ok(COMPUTED_LABEL_VOID.to_vec())
        );
        // A resignation, by one side alone: only that side signs.
        let mut resigned = rounds(&[(5, 3)], 1);
        resigned.push(resign(5, MatchSide::A));
        assert_eq!(
            occupant(&m, &m.outcome(resigned)).map(|o| o.label().to_vec()),
            Ok(COMPUTED_LABEL_B_WINS.to_vec())
        );
        let first_move = vec![resign(1, MatchSide::B)];
        let outcome = m.outcome(first_move);
        assert_eq!(outcome.signatures().len(), 1);
        assert_eq!(
            occupant(&m, &outcome).map(|o| o.label().to_vec()),
            Ok(COMPUTED_LABEL_A_WINS.to_vec())
        );
    }

    /// The transcript proves its outcome at its own match cell only: the
    /// same bytes at another match's cell count as nothing.
    #[test]
    fn a_transcript_counts_only_at_its_own_match_cell() {
        let m = the_match();
        let other = Match {
            y: external_commitment(b"computed match 2"),
            ..the_match()
        };
        assert_eq!(
            match_occupant(
                &m.outcome(a_wins()).encode(),
                &other.key(),
                &registry(HighestSum)
            ),
            Err(ComputedRefusal::NotThisCell)
        );
    }

    /// An entry that does not round-trip is no entry, even with the chain
    /// and the signatures made over its exact bytes.
    #[test]
    fn a_non_canonical_entry_is_refused() {
        let m = the_match();
        let mut entries = a_wins();
        // The same Commit with one byte after it: an equivalent entry in
        // bytes a strict decoder does not take, chained and signed as sent.
        entries[0].push(0x00);
        let outcome = m.outcome(entries);
        assert!(matches!(
            occupant(&m, &outcome),
            Err(ComputedRefusal::Transcript(
                TranscriptRefusal::EntryDoesNotDecode { position: 1, .. }
                    | TranscriptRefusal::EntryNotCanonical { position: 1 }
            ))
        ));
    }

    /// The head chain fixes each entry's content, place and membership:
    /// entries reordered, dropped or inserted under the signatures made over
    /// the honest chain do not verify.
    #[test]
    fn the_head_chain_fixes_order_and_membership() {
        let m = the_match();
        let honest = a_wins();
        let signed = m.outcome(honest.clone());
        let resent =
            |entries: Vec<Vec<u8>>| m.outcome_signed(entries, signed.signatures().to_vec());

        // A's two moves swapped, each re-indexed to its new place.
        let mut swapped = honest.clone();
        swapped[2] = reveal(3, MatchSide::A, 0, 4);
        swapped[6] = reveal(7, MatchSide::A, 1, 5);
        swapped[0] = commit(1, MatchSide::A, 0, 4);
        swapped[4] = commit(5, MatchSide::A, 1, 5);
        assert!(matches!(
            occupant(&m, &resent(swapped)),
            Err(ComputedRefusal::Signature(
                SignatureError::DoesNotVerify { .. }
            ))
        ));

        // The first round dropped, the second re-indexed.
        let dropped = rounds(&[(4, 4)], 1);
        assert!(matches!(
            occupant(&m, &resent(dropped)),
            Err(ComputedRefusal::Signature(
                SignatureError::DoesNotVerify { .. }
            ))
        ));

        // A round inserted ahead, the rest re-indexed.
        let inserted = rounds(&[(9, 0), (5, 3), (4, 4)], 1);
        let mut longer = signed.signatures().to_vec();
        longer.truncate(2);
        assert!(matches!(
            occupant(&m, &m.outcome_signed(inserted, longer)),
            Err(ComputedRefusal::Signature(
                SignatureError::DoesNotVerify { .. }
            ))
        ));
    }

    /// B cannot make moves for A. Here B takes A's genuine signature over
    /// the head of A's reveal at index 3, appends a forged A commit and a
    /// forged A reveal whose index field says 3 again, and signs the result
    /// itself: A's key covers none of the forged entries, and an entry that
    /// names another index than its place is no entry.
    #[test]
    fn a_side_cannot_be_given_entries_its_key_never_covered() {
        let m = the_match();
        let honest = rounds(&[(1, 9)], 1);
        let a_signed = m.sign(MatchSide::A, &honest, 3);
        let mut forged = honest.clone();
        forged.push(commit(5, MatchSide::A, 1, 0));
        forged.push(commit(6, MatchSide::B, 1, 9));
        forged.push(reveal(3, MatchSide::A, 1, 0));
        forged.push(reveal(8, MatchSide::B, 1, 9));
        let b_signed = m.sign(MatchSide::B, &forged, 8);
        let outcome = m.outcome_signed(
            forged,
            vec![
                SideSignature::new(MatchSide::A, &a_signed).expect("signature"),
                SideSignature::new(MatchSide::B, &b_signed).expect("signature"),
            ],
        );
        assert_eq!(
            occupant(&m, &outcome),
            Err(ComputedRefusal::Transcript(
                TranscriptRefusal::IndexOutOfOrder {
                    position: 7,
                    index: 3
                }
            ))
        );
    }

    #[test]
    fn a_signature_must_be_its_sides_key_over_its_own_last_head() {
        let m = the_match();
        let entries = a_wins();
        // B signs A's slot.
        let by_b = m.sign(MatchSide::B, &entries, 7);
        let honest_b = m.sign(MatchSide::B, &entries, 8);
        let swapped_key = m.outcome_signed(
            entries.clone(),
            vec![
                SideSignature::new(MatchSide::A, &by_b).expect("signature"),
                SideSignature::new(MatchSide::B, &honest_b).expect("signature"),
            ],
        );
        assert!(matches!(
            occupant(&m, &swapped_key),
            Err(ComputedRefusal::Signature(
                SignatureError::DoesNotVerify { .. }
            ))
        ));
        // A signs the head of its earlier entry, not its last.
        let early = m.sign(MatchSide::A, &entries, 3);
        let wrong_head = m.outcome_signed(
            entries.clone(),
            vec![
                SideSignature::new(MatchSide::A, &early).expect("signature"),
                SideSignature::new(MatchSide::B, &honest_b).expect("signature"),
            ],
        );
        assert!(matches!(
            occupant(&m, &wrong_head),
            Err(ComputedRefusal::Signature(
                SignatureError::DoesNotVerify { .. }
            ))
        ));
        // A side that played and did not sign.
        let one_side = m.outcome_signed(
            entries,
            vec![SideSignature::new(MatchSide::B, &honest_b).expect("signature")],
        );
        assert_eq!(
            occupant(&m, &one_side),
            Err(ComputedRefusal::NotTheSidesThatPlayed)
        );
    }

    #[test]
    fn a_reveal_must_open_its_sides_commitment() {
        let m = the_match();
        // A reveals another move than it committed.
        let mut changed = a_wins();
        changed[2] = reveal(3, MatchSide::A, 0, 9);
        assert_eq!(
            occupant(&m, &m.outcome(changed)),
            Err(ComputedRefusal::Transcript(
                TranscriptRefusal::RevealDoesNotOpenTheCommitment { index: 3 }
            ))
        );
        // A reveal with nothing committed.
        let unopened = vec![reveal(1, MatchSide::A, 0, 5)];
        assert_eq!(
            occupant(&m, &m.outcome(unopened)),
            Err(ComputedRefusal::Transcript(
                TranscriptRefusal::NothingToReveal { index: 1 }
            ))
        );
        // A second commitment while one is open.
        let twice = vec![commit(1, MatchSide::A, 0, 5), commit(2, MatchSide::A, 1, 5)];
        assert_eq!(
            occupant(&m, &m.outcome(twice)),
            Err(ComputedRefusal::Transcript(
                TranscriptRefusal::CommitWhileOneIsOpen { index: 2 }
            ))
        );
        // Anything after a resignation.
        let after = vec![resign(1, MatchSide::A), resign(2, MatchSide::B)];
        assert_eq!(
            occupant(&m, &m.outcome(after)),
            Err(ComputedRefusal::Transcript(
                TranscriptRefusal::EntryAfterResign { index: 2 }
            ))
        );
        // A setup other than the one the table commits.
        let mut other_setup = m.outcome(a_wins());
        other_setup = TranscriptOutcome::new(
            m.y,
            m.table.clone(),
            &[2, 0xC0, 0xDF],
            other_setup.entries().to_vec(),
            other_setup.signatures().to_vec(),
        )
        .expect("outcome");
        assert_eq!(
            occupant(&m, &other_setup),
            Err(ComputedRefusal::Transcript(
                TranscriptRefusal::NotTheCommittedSetup
            ))
        );
    }

    /// A transcript cut short computes no outcome, and one that runs past
    /// the entry that ended the match is not the match's transcript, even
    /// under a program that does not fault on it.
    #[test]
    fn a_truncated_or_overlong_transcript_is_never_recognized() {
        let m = the_match();
        let full = a_wins();
        // Cut before B's last reveal.
        assert_eq!(
            occupant(&m, &m.outcome(full[..7].to_vec())),
            Err(ComputedRefusal::MatchNotEnded)
        );
        // Cut after a commitment: the last entry opens nothing.
        assert_eq!(
            occupant(&m, &m.outcome(full[..5].to_vec())),
            Err(ComputedRefusal::LastEntryDoesNotOpen)
        );
        // A round after the end, under a program that keeps saying "ended".
        let mut overlong = full.clone();
        overlong.extend(rounds(&[(0, 9)], 9));
        assert_eq!(
            match_occupant(
                &m.outcome(overlong).encode(),
                &m.key(),
                &registry(NeverFaults)
            ),
            Err(ComputedRefusal::EndedBeforeTheLastEntry)
        );
    }

    #[test]
    fn an_equivocation_proves_itself_only_with_one_key_one_index_two_heads() {
        let m = the_match();
        // A signs two different first entries at index 1.
        let one = vec![commit(1, MatchSide::A, 0, 5)];
        let two = vec![commit(1, MatchSide::A, 0, 6)];
        let head_of = |entries: &Vec<Vec<u8>>| m.heads(entries)[1];
        let mut signed = vec![
            SignedHead::new(head_of(&one), &m.sign(MatchSide::A, &one, 1)).expect("head"),
            SignedHead::new(head_of(&two), &m.sign(MatchSide::A, &two, 1)).expect("head"),
        ];
        signed.sort_by_key(|s| *s.head());
        let proof = |side: MatchSide, index: u32, heads: &[SignedHead]| {
            EquivocationProof::new(
                m.y,
                m.table.clone(),
                side,
                index,
                heads[0].clone(),
                heads[1].clone(),
            )
            .expect("proof")
        };
        let cheated = proof(MatchSide::A, 1, &signed);
        assert_eq!(
            match_occupant(&cheated.encode(), &m.key(), &ProgramRegistry::new()),
            Ok(MatchOccupant::Equivocation {
                cheater: MatchSide::A
            }),
            "recognized from its own bytes, with no program"
        );
        assert_eq!(
            MatchOccupant::Equivocation {
                cheater: MatchSide::A
            }
            .label(),
            COMPUTED_LABEL_B_WINS
        );

        // Charged to the other side: B's key signed neither head.
        assert!(matches!(
            match_occupant(
                &proof(MatchSide::B, 1, &signed).encode(),
                &m.key(),
                &ProgramRegistry::new()
            ),
            Err(ComputedRefusal::Signature(
                SignatureError::DoesNotVerify { .. }
            ))
        ));
        // Two heads at different indices, restated at one.
        let three = a_wins();
        let mut apart = vec![
            signed[0].clone(),
            SignedHead::new(m.heads(&three)[3], &m.sign(MatchSide::A, &three, 3)).expect("head"),
        ];
        apart.sort_by_key(|s| *s.head());
        for index in [1, 3] {
            assert!(matches!(
                match_occupant(
                    &proof(MatchSide::A, index, &apart).encode(),
                    &m.key(),
                    &ProgramRegistry::new()
                ),
                Err(ComputedRefusal::Signature(
                    SignatureError::DoesNotVerify { .. }
                ))
            ));
        }
        // One head signed by A and one by B, at one index.
        let b_one = vec![commit(1, MatchSide::B, 0, 5)];
        let mut mixed = vec![
            signed[0].clone(),
            SignedHead::new(head_of(&b_one), &m.sign(MatchSide::B, &b_one, 1)).expect("head"),
        ];
        mixed.sort_by_key(|s| *s.head());
        for side in [MatchSide::A, MatchSide::B] {
            assert!(matches!(
                match_occupant(
                    &proof(side, 1, &mixed).encode(),
                    &m.key(),
                    &ProgramRegistry::new()
                ),
                Err(ComputedRefusal::Signature(
                    SignatureError::DoesNotVerify { .. }
                ))
            ));
        }
        // At another match's cell.
        let other = Match {
            y: external_commitment(b"computed match 2"),
            ..the_match()
        };
        assert_eq!(
            match_occupant(&cheated.encode(), &other.key(), &ProgramRegistry::new()),
            Err(ComputedRefusal::NotThisCell)
        );
    }

    #[test]
    fn a_label_outside_the_branches_counts_for_nothing() {
        let m = the_match();
        assert_eq!(
            match_occupant(&m.outcome(a_wins()).encode(), &m.key(), &registry(SaysDraw)),
            Err(ComputedRefusal::LabelNotABranch {
                label: b"draw".to_vec()
            })
        );
    }

    /// An unregistered program establishes nothing: not at recognition, and
    /// not at the cell, where the reading is not established rather than
    /// open. Another registered program is never run in its place.
    #[test]
    fn an_unregistered_program_establishes_nothing() {
        let m = the_match();
        let outcome = m.outcome(a_wins());

        /// The same rules, registered under another hash.
        struct Elsewhere;
        impl OutcomeProgram for Elsewhere {
            fn id(&self) -> [u8; 32] {
                [0x9B; 32]
            }
            fn outcome(
                &self,
                setup: &[u8],
                opened: &[Opened],
            ) -> Result<ProgramOutcome, ProgramFault> {
                HighestSum.outcome(setup, opened)
            }
        }
        let others = registry(Elsewhere);
        assert_eq!(
            match_occupant(&outcome.encode(), &m.key(), &others),
            Err(ComputedRefusal::ProgramNotRegistered {
                program: SUM_PROGRAM
            })
        );

        let terms = m.terms(([0x01; 32], [0x02; 32]));
        let cells =
            ComputedCells::new(&terms, &committed_set(), &committed_set_id()).expect("cells");
        let mut at = Cell::at(cells.match_routed());
        at.write(&outcome.encode(), 2, &[]);
        assert_eq!(
            match_resolution(&cells, &at.evidence(), &others),
            Err(MatchUnread::ProgramNotRegistered {
                program: SUM_PROGRAM
            })
        );
        // Registered, the same cell reads final on A's win.
        let read = match_resolution(&cells, &at.evidence(), &registry(HighestSum)).expect("read");
        assert_eq!(
            read.occupant().map(|o| o.label().to_vec()),
            Some(COMPUTED_LABEL_A_WINS.to_vec())
        );
        assert!(matches!(
            read.fact(),
            CellFact::Held {
                state: ChainState::Final,
                ..
            }
        ));

        // One hash, one program.
        let mut twice = registry(HighestSum);
        assert_eq!(
            twice.register(Arc::new(NeverFaults)),
            Err(RegistryError::AlreadyRegistered {
                program: SUM_PROGRAM
            })
        );
    }

    // ── the start cell ─────────────────────────────────────────────────

    /// A Start is both sides' readies, each under its own session key over
    /// this match's `m_ready`; a Withdraw is either side's, under the key of
    /// the side it names.
    #[test]
    fn a_start_holds_both_readies_and_a_withdraw_either_sides_key() {
        let m = the_match();
        let ks = start_cell_key(&m.key());
        assert_eq!(
            start_occupant(&start_of(&m).encode(), &ks),
            Ok(StartKind::Start)
        );
        for side in [MatchSide::A, MatchSide::B] {
            assert_eq!(
                start_occupant(&withdraw_by(&m, side).encode(), &ks),
                Ok(StartKind::Withdraw)
            );
        }

        let ready_a = sign_ready(&m.y, &m.table, MatchSide::A, &m.a.secret).expect("A ready");
        let ready_b = sign_ready(&m.y, &m.table, MatchSide::B, &m.b.secret).expect("B ready");
        let start = |a: &[u8], b: &[u8]| {
            MatchStart::new(
                m.y,
                m.table.clone(),
                StartBody::Start {
                    ready_a: a.to_vec(),
                    ready_b: b.to_vec(),
                },
            )
            .expect("encodes")
        };
        let refused = |bytes: Vec<u8>| {
            matches!(
                start_occupant(&bytes, &ks),
                Err(ComputedRefusal::Signature(
                    SignatureError::DoesNotVerify { .. }
                ))
            )
        };
        // One side's ready alone, in both slots: no Start.
        assert!(refused(start(&ready_a, &ready_a).encode()));
        assert!(refused(start(&ready_b, &ready_b).encode()));
        // Each ready in the other side's slot: the wrong key for the slot.
        assert!(refused(start(&ready_b, &ready_a).encode()));
        // Readies for another match: another K_match, so another statement.
        let other = Match {
            y: external_commitment(b"computed match 2"),
            ..the_match()
        };
        let other_a = sign_ready(&other.y, &other.table, MatchSide::A, &m.a.secret).expect("ready");
        let other_b = sign_ready(&other.y, &other.table, MatchSide::B, &m.b.secret).expect("ready");
        assert!(refused(start(&other_a, &other_b).encode()));
        assert!(refused(start(&ready_a, &other_b).encode()));
        // This match's Start at another match's start cell.
        assert_eq!(
            start_occupant(&start_of(&m).encode(), &start_cell_key(&other.key())),
            Err(ComputedRefusal::NotThisCell)
        );
        // A side cannot ready under the other side's key, and a Start is
        // assembled only from two readies that verify.
        assert!(matches!(
            sign_ready(&m.y, &m.table, MatchSide::B, &m.a.secret),
            Err(..)
        ));
        assert!(matches!(
            assemble_start(&m.y, &m.table, &ready_a, &ready_a),
            Err(ComputedRefusal::Signature(..))
        ));

        // A Withdraw naming one side with the other side's signature, or a
        // signature over the ready statement instead of the withdraw one.
        let StartBody::Withdraw { signature, .. } = withdraw_by(&m, MatchSide::B).body().clone()
        else {
            panic!("a Withdraw")
        };
        for (side, signature) in [(MatchSide::A, signature), (MatchSide::A, ready_a.clone())] {
            let wrong = MatchStart::new(
                m.y,
                m.table.clone(),
                StartBody::Withdraw { side, signature },
            )
            .expect("encodes");
            assert!(refused(wrong.encode()));
        }
        assert_eq!(
            match_occupant(&start_of(&m).encode(), &m.key(), &registry(HighestSum)),
            Err(ComputedRefusal::NotAnOccupantClass {
                class: crate::ccb::class::ESCROW_MATCH_START
            })
        );
    }

    /// The cells as a reader evaluates them from route-chain evidence.
    struct Seats {
        cells: ComputedCells,
        start: Cell,
        matched: Cell,
    }

    impl Seats {
        fn new(m: &Match) -> Self {
            let terms = m.terms(([0x01; 32], [0x02; 32]));
            let cells =
                ComputedCells::new(&terms, &committed_set(), &committed_set_id()).expect("cells");
            Self {
                start: Cell::at(cells.start_routed()),
                matched: Cell::at(cells.match_routed()),
                cells,
            }
        }

        fn read(&self) -> ComputedCellRead {
            let start = start_resolution(&self.cells, &self.start.evidence()).expect("start read");
            let matched = match start.held() {
                Some(StartKind::Start) => Some(
                    match_resolution(&self.cells, &self.matched.evidence(), &registry(HighestSum))
                        .expect("match read"),
                ),
                Some(StartKind::Withdraw) | None => None,
            };
            ComputedCellRead::of(start, matched).expect("assembled")
        }
    }

    /// A Withdraw first at the start cell, by either side, voids the match:
    /// `void` is final once the Withdraw is, every other outcome is lost, and
    /// a full Start after it and a transcript at the match cell count for
    /// nothing.
    #[test]
    fn a_withdraw_by_either_side_holding_the_start_cell_voids_the_match() {
        let m = the_match();
        let ready_a = sign_ready(&m.y, &m.table, MatchSide::A, &m.a.secret).expect("A ready");
        for side in [MatchSide::A, MatchSide::B] {
            let mut seats = Seats::new(&m);
            // Junk first at the leader: a Start holding A's ready twice.
            let junk = MatchStart::new(
                m.y,
                m.table.clone(),
                StartBody::Start {
                    ready_a: ready_a.clone(),
                    ready_b: ready_a.clone(),
                },
            )
            .expect("encodes");
            seats.start.write(&junk.encode(), 0, &[]);
            let withdraw = withdraw_by(&m, side);
            seats.start.write(&withdraw.encode(), 0, &[]);
            seats.start.write(&start_of(&m).encode(), 2, &[]);
            seats.matched.write(&m.outcome(a_wins()).encode(), 2, &[]);

            let read = seats.read();
            assert_eq!(read.start().held(), Some(StartKind::Withdraw));
            assert_eq!(read.start().passed_over().len(), 1, "the junk Start");
            assert_eq!(read.matched(), None, "the match cell is not read");
            assert_eq!(read.key(), m.key());
            // Only the leader link so far: void is held, not final.
            assert_eq!(
                read.standing_for(COMPUTED_LABEL_VOID),
                VerdictStanding::Unsettled
            );
            assert_eq!(
                read.standing_for(COMPUTED_LABEL_A_WINS),
                VerdictStanding::Lost
            );
            assert_eq!(
                read.standing_for(COMPUTED_LABEL_B_WINS),
                VerdictStanding::Lost
            );

            // The Withdraw's chain carried to final.
            seats.start.continue_chain(&withdraw.encode(), 2, 2);
            let read = seats.read();
            assert_eq!(
                read.standing_for(COMPUTED_LABEL_VOID),
                VerdictStanding::Final
            );
            assert_eq!(
                read.standing_for(COMPUTED_LABEL_A_WINS),
                VerdictStanding::Lost
            );
            let proof = start_completion(&seats.cells, read.start(), &seats.start.evidence())
                .expect("decided");
            assert!(proof.is_some(), "a final Withdraw has a completion proof");
        }
    }

    /// The match cell counts only once a Start holds the start cell, and an
    /// outcome is final only when both the Start and the occupant are.
    #[test]
    fn the_match_cell_counts_only_once_start_holds() {
        let m = the_match();
        let mut seats = Seats::new(&m);
        let outcome = m.outcome(a_wins());
        seats.matched.write(&outcome.encode(), 2, &[]);

        // No Start: the transcript, final at its cell, settles nothing.
        let read = seats.read();
        assert_eq!(read.matched(), None);
        for label in COMPUTED_LABELS {
            assert_eq!(read.standing_for(label), VerdictStanding::Unsettled);
        }
        // A match read without a Start is not a read of the vault's cells.
        let start = start_resolution(&seats.cells, &seats.start.evidence()).expect("start");
        let matched = match_resolution(
            &seats.cells,
            &seats.matched.evidence(),
            &registry(HighestSum),
        )
        .expect("match");
        assert_eq!(
            ComputedCellRead::of(start, Some(matched)),
            Err(ComputedReadError::MatchReadBeforeStart)
        );

        // A Start held, not final: the other outcomes are lost already, and
        // A's win is not final yet.
        let start = start_of(&m);
        seats.start.write(&start.encode(), 0, &[]);
        let read = seats.read();
        assert_eq!(
            read.standing_for(COMPUTED_LABEL_A_WINS),
            VerdictStanding::Unsettled
        );
        assert_eq!(
            read.standing_for(COMPUTED_LABEL_B_WINS),
            VerdictStanding::Lost
        );
        assert_eq!(
            read.standing_for(COMPUTED_LABEL_VOID),
            VerdictStanding::Lost
        );

        // Both final.
        seats.start.continue_chain(&start.encode(), 1, 2);
        let read = seats.read();
        assert_eq!(
            read.standing_for(COMPUTED_LABEL_A_WINS),
            VerdictStanding::Final
        );
        assert_eq!(
            read.standing_for(COMPUTED_LABEL_B_WINS),
            VerdictStanding::Lost
        );
        let matched = read.matched().expect("read once Start holds");
        assert!(
            match_completion(&seats.cells, matched, &seats.matched.evidence())
                .expect("decided")
                .is_some(),
            "a final occupant has a completion proof"
        );
        // A Withdraw after the Start, by either side, counts for nothing.
        for side in [MatchSide::A, MatchSide::B] {
            seats.start.write(&withdraw_by(&m, side).encode(), 2, &[]);
            let read = seats.read();
            assert_eq!(read.start().held(), Some(StartKind::Start));
            assert_eq!(
                read.standing_for(COMPUTED_LABEL_A_WINS),
                VerdictStanding::Final
            );
            assert_eq!(
                read.standing_for(COMPUTED_LABEL_VOID),
                VerdictStanding::Lost
            );
        }
    }

    /// The first recognized occupant holds the match cell for good: an
    /// equivocation proof arriving after a transcript changes nothing, and
    /// one arriving first wins.
    #[test]
    fn the_first_recognized_occupant_holds_the_match_cell() {
        let m = the_match();
        let mut seats = Seats::new(&m);
        let start = start_of(&m);
        seats.start.write(&start.encode(), 2, &[]);
        let one = vec![commit(1, MatchSide::A, 0, 5)];
        let two = vec![commit(1, MatchSide::A, 0, 6)];
        let mut heads = [
            SignedHead::new(m.heads(&one)[1], &m.sign(MatchSide::A, &one, 1)).expect("head"),
            SignedHead::new(m.heads(&two)[1], &m.sign(MatchSide::A, &two, 1)).expect("head"),
        ];
        heads.sort_by_key(|s| *s.head());
        let proof = EquivocationProof::new(
            m.y,
            m.table.clone(),
            MatchSide::A,
            1,
            heads[0].clone(),
            heads[1].clone(),
        )
        .expect("proof");
        // A truncated transcript first counts as nothing.
        seats
            .matched
            .write(&m.outcome(a_wins()[..7].to_vec()).encode(), 0, &[]);
        seats.matched.write(&proof.encode(), 2, &[]);
        seats.matched.write(&m.outcome(a_wins()).encode(), 2, &[]);
        let read = seats.read();
        assert_eq!(
            read.standing_for(COMPUTED_LABEL_B_WINS),
            VerdictStanding::Final
        );
        assert_eq!(
            read.standing_for(COMPUTED_LABEL_A_WINS),
            VerdictStanding::Lost
        );
        assert_eq!(
            read.matched().map(|r| r.passed_over().to_vec()),
            Some(vec![ComputedRefusal::MatchNotEnded])
        );
    }
}
