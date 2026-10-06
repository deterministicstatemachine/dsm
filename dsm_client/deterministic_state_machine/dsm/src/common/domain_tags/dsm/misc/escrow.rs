// SPDX-License-Identifier: MIT OR Apache-2.0

//! DSM namespace tags: escrow vaults (SoFi Amendments S21 and S22).
//!
//! An escrow vault is a SoFi vault whose terms are a set of precommitted
//! branches, released by the canonical verdict on an external commitment
//! `Y = H(DSM/external/v1 ‖ X)` (Explainer §60). The derivations live in
//! `crate::sofi::escrow`; this file only allocates the domains.

use crate::crypto::domain::TaggedHashDomain;

/// `Y = H(DSM/external/v1 ‖ X)` — an external commitment (Explainer §60).
/// DSM never reads `X`; it verifies only predicates bound to `Y`.
pub const TAG_DSM_EXTERNAL: TaggedHashDomain<'static> = crate::tagged_domain!(b"DSM/external/v1");
/// `A_T = immutable_addr(tag, CCB(EscrowTerms))` — the address an escrow
/// vault's three policy slots name.
pub const TAG_DSM_ESCROW_TERMS_OBJECT: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/escrow/terms-object/v1");
/// `τ = H(tag ‖ u8(|O|) ‖ entries)` — the outcome table: each outcome with the
/// exact signer set that decides it.
pub const TAG_DSM_ESCROW_OUTCOME_TABLE: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/escrow/outcome-table/v1");
/// `K_verdict = H(tag ‖ Y ‖ τ)` — the one cell every vault bound to `Y` under
/// table `τ` settles against.
pub const TAG_DSM_ESCROW_VERDICT_CELL: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/escrow/verdict-cell/v1");
/// `s_verdict = H(tag ‖ K_verdict)` — the seed of the verdict cell's route.
pub const TAG_DSM_ESCROW_VERDICT_SEED: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/escrow/verdict-seed/v1");
/// `m(o) = H(tag ‖ K_verdict ‖ u32be(|o|) ‖ o)` — what a signer signs to
/// decide outcome `o` at the cell.
pub const TAG_DSM_ESCROW_STATEMENT: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/escrow/statement/v1");
/// `immutable_addr(tag, CCB(EscrowVerdict))` — a gathered verdict, put as an
/// object while its signers' signatures are collected.
pub const TAG_DSM_ESCROW_VERDICT_OBJECT: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/escrow/verdict-object/v1");
/// `H(tag ‖ K_verdict)` — where the genesis of every escrow vault bound to a
/// verdict cell is indexed.
pub const TAG_DSM_ESCROW_CELL_LOCATOR: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/escrow/cell-locator/v1");
/// `H(tag ‖ K_verdict ‖ u32be(|o|) ‖ o)` — where gathered signatures deciding
/// outcome `o` at a cell are indexed.
pub const TAG_DSM_ESCROW_STATEMENT_LOCATOR: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/escrow/statement-locator/v1");

// ── computed escrow vaults (SoFi Amendment S22) ─────────────────────────────

/// `τ_c = H(tag ‖ table bytes)` — a computed escrow vault's table: the
/// program hash, the setup digest and the two session keys.
pub const TAG_DSM_ESCROW_COMPUTED_TABLE: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/escrow/computed-table/v1");
/// `K_match = H(tag ‖ Y ‖ τ_c)` — the cell a match's outcome occupies.
pub const TAG_DSM_ESCROW_COMPUTED_MATCH: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/escrow/computed-match/v1");
/// `s_match = H(tag ‖ K_match)` — the seed of the match cell's route.
pub const TAG_DSM_ESCROW_COMPUTED_MATCH_SEED: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/escrow/computed-match-seed/v1");
/// `K_start = H(tag ‖ K_match)` — the cell a Start or a Withdraw races for.
pub const TAG_DSM_ESCROW_COMPUTED_START: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/escrow/computed-start/v1");
/// `s_start = H(tag ‖ K_start)` — the seed of the start cell's route.
pub const TAG_DSM_ESCROW_COMPUTED_START_SEED: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/escrow/computed-start-seed/v1");
/// `m_withdraw = H(tag ‖ K_start ‖ u8(2))` — what a side signs to Withdraw a
/// match before it starts.
pub const TAG_DSM_ESCROW_COMPUTED_START_STATEMENT: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/escrow/computed-start-statement/v1");
/// `m_ready = H(tag ‖ K_match)` — what each side's session key signs once
/// its wallet has checked both vaults; a Start holds both (the ready
/// handshake, owner ruling 2026-10-06).
pub const TAG_DSM_ESCROW_COMPUTED_READY: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/escrow/computed-ready/v1");
/// `H(tag ‖ setup)` — the digest of the program's input fixed at lock.
pub const TAG_DSM_ESCROW_COMPUTED_SETUP: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/escrow/computed-setup/v1");
/// `H(tag ‖ K ‖ u32be(|o|) ‖ o)` — a reader's name for the occupant of a
/// match or start cell.
pub const TAG_DSM_ESCROW_COMPUTED_OCCUPANT: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/escrow/computed-occupant/v1");
/// `h_0 = H(tag ‖ K_match ‖ setup_digest)` — the head of an empty transcript.
pub const TAG_DSM_ESCROW_TRANSCRIPT: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/escrow/transcript/v1");
/// `h_i = H(tag ‖ h_{i−1} ‖ CCB(entry_i))` — one step of the head chain.
pub const TAG_DSM_ESCROW_TRANSCRIPT_STEP: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/escrow/transcript-step/v1");
/// `m_head = H(tag ‖ K_match ‖ u32be(i) ‖ h_i)` — what a side signs over the
/// head of its own entry `i`.
pub const TAG_DSM_ESCROW_TRANSCRIPT_HEAD: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/escrow/transcript-head/v1");
/// `H(tag ‖ salt ‖ u32be(|move|) ‖ move)` — a Commit's commitment.
pub const TAG_DSM_ESCROW_MOVE_COMMIT: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/escrow/move-commit/v1");

#[cfg(test)]
pub(crate) const ESCROW_TAGS: &[TaggedHashDomain<'static>] = &[
    TAG_DSM_EXTERNAL,
    TAG_DSM_ESCROW_TERMS_OBJECT,
    TAG_DSM_ESCROW_OUTCOME_TABLE,
    TAG_DSM_ESCROW_VERDICT_CELL,
    TAG_DSM_ESCROW_VERDICT_SEED,
    TAG_DSM_ESCROW_STATEMENT,
    TAG_DSM_ESCROW_VERDICT_OBJECT,
    TAG_DSM_ESCROW_CELL_LOCATOR,
    TAG_DSM_ESCROW_STATEMENT_LOCATOR,
    TAG_DSM_ESCROW_COMPUTED_TABLE,
    TAG_DSM_ESCROW_COMPUTED_MATCH,
    TAG_DSM_ESCROW_COMPUTED_MATCH_SEED,
    TAG_DSM_ESCROW_COMPUTED_START,
    TAG_DSM_ESCROW_COMPUTED_START_SEED,
    TAG_DSM_ESCROW_COMPUTED_START_STATEMENT,
    TAG_DSM_ESCROW_COMPUTED_READY,
    TAG_DSM_ESCROW_COMPUTED_SETUP,
    TAG_DSM_ESCROW_COMPUTED_OCCUPANT,
    TAG_DSM_ESCROW_TRANSCRIPT,
    TAG_DSM_ESCROW_TRANSCRIPT_STEP,
    TAG_DSM_ESCROW_TRANSCRIPT_HEAD,
    TAG_DSM_ESCROW_MOVE_COMMIT,
];
