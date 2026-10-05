// SPDX-License-Identifier: MIT OR Apache-2.0

//! DSM namespace tags: escrow vaults (SoFi Amendment S21).
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
];
