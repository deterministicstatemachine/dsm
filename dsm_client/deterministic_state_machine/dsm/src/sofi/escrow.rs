// SPDX-License-Identifier: Apache-2.0

//! Escrow vaults (SoFi §19.9, Amendment S21): the derivations, the verdict
//! cell, and what occupies it.
//!
//! An escrow vault is a SoFi vault whose three policy slots name one
//! [`EscrowTerms`] object. It releases its whole amount once, by a Release
//! position of the branch's recipient, when the canonical verdict on its
//! external commitment `Y` names that branch's outcome. Every vault whose
//! terms name `Y` and the same outcome table `τ` is bound to one cell,
//! `K_verdict = H(DSM/escrow/verdict-cell/v1 ‖ Y ‖ τ)`, and the first verdict
//! at that cell's leader that proves its own authority from its own bytes is
//! the only one any of them settles against. A second verdict, even one
//! validly signed by the same signers for another outcome, never becomes the
//! cell's value.
//!
//! Nothing here knows what an application's commitment means: `X` is never
//! read, only `Y`.

use crate::common::domain_tags::{
    TAG_DSM_ESCROW_CELL_LOCATOR, TAG_DSM_ESCROW_OUTCOME_TABLE, TAG_DSM_ESCROW_STATEMENT,
    TAG_DSM_ESCROW_STATEMENT_LOCATOR, TAG_DSM_ESCROW_TERMS_OBJECT, TAG_DSM_ESCROW_VERDICT_CELL,
    TAG_DSM_ESCROW_VERDICT_SEED, TAG_DSM_EXTERNAL,
};
use crate::crypto::blake3::dsm_domain_hasher;
use crate::crypto::domain::TaggedHashDomain;
use crate::route_chain::{
    completion_proof, evaluate, CellError, CellEvidence, CellFact, CellReading, ChainState,
    CompletionProof, Missing, RoutedCell,
};
use crate::storage_object::immutable_addr;

use super::signature::{verify_bytes, SignatureError};
use super::wire::{EscrowSigner, EscrowTerms, EscrowVerdict, OutcomeTable, VerdictSignature};

type D32 = [u8; 32];

fn h(tag: TaggedHashDomain<'static>, parts: &[&[u8]]) -> D32 {
    let mut hasher = dsm_domain_hasher(tag);
    for p in parts {
        hasher.update(p);
    }
    *hasher.finalize().as_bytes()
}

// ── derivations ────────────────────────────────────────────────────────────

/// `Y = H(DSM/external/v1 ‖ X)` (Explainer §60). DSM never reads `X`.
pub fn external_commitment(x: &[u8]) -> D32 {
    h(TAG_DSM_EXTERNAL, &[x])
}

/// `A_T = immutable_addr(DSM/escrow/terms-object/v1, CCB(EscrowTerms))`: what
/// an escrow vault's three policy slots name.
pub fn terms_address(terms: &EscrowTerms) -> D32 {
    terms_address_of(&terms.encode())
}

/// The address `bytes` take as escrow terms. Bytes that do not re-derive the
/// address a vault names are not its terms.
pub fn terms_address_of(bytes: &[u8]) -> D32 {
    immutable_addr(TAG_DSM_ESCROW_TERMS_OBJECT, bytes)
}

/// `τ = H(DSM/escrow/outcome-table/v1 ‖ u8(|O|) ‖ entries)`.
pub fn table_digest(table: &OutcomeTable) -> D32 {
    h(TAG_DSM_ESCROW_OUTCOME_TABLE, &[&table.digest_preimage()])
}

/// `K_verdict = H(DSM/escrow/verdict-cell/v1 ‖ Y ‖ τ)`.
pub fn verdict_cell_key(external_commitment: &D32, table_digest: &D32) -> D32 {
    h(
        TAG_DSM_ESCROW_VERDICT_CELL,
        &[external_commitment, table_digest],
    )
}

/// The verdict cell an escrow vault's terms bind it to.
pub fn verdict_cell_of(terms: &EscrowTerms) -> D32 {
    verdict_cell_key(
        terms.external_commitment(),
        &table_digest(&terms.outcome_table()),
    )
}

/// `s_verdict = H(DSM/escrow/verdict-seed/v1 ‖ K_verdict)`: the seed of the
/// verdict cell's route, so a reader that knows only the key finds its
/// leader.
pub fn verdict_seed(verdict_cell: &D32) -> D32 {
    h(TAG_DSM_ESCROW_VERDICT_SEED, &[verdict_cell])
}

/// `m(o) = H(DSM/escrow/statement/v1 ‖ K_verdict ‖ u32be(|o|) ‖ o)`: what a
/// signer signs to decide outcome `o` at the cell. It names the cell and no
/// vault, so a signature decides nothing anywhere else, and one signature
/// serves every vault bound to the cell.
pub fn statement(verdict_cell: &D32, outcome: &[u8]) -> D32 {
    // An outcome is at most ESCROW_MAX_OUTCOME_BYTES long.
    let len = (outcome.len() as u32).to_be_bytes();
    h(TAG_DSM_ESCROW_STATEMENT, &[verdict_cell, &len, outcome])
}

/// `H(DSM/escrow/cell-locator/v1 ‖ K_verdict)`: where the genesis of every
/// escrow vault bound to the cell is indexed. Discovery by cell, so a vault
/// bound to another cell is never found among the linked ones.
pub fn cell_locator(verdict_cell: &D32) -> D32 {
    h(TAG_DSM_ESCROW_CELL_LOCATOR, &[verdict_cell])
}

/// `H(DSM/escrow/statement-locator/v1 ‖ K_verdict ‖ u32be(|o|) ‖ o)`: where
/// gathered signatures deciding outcome `o` at the cell are indexed.
pub fn statement_locator(verdict_cell: &D32, outcome: &[u8]) -> D32 {
    let len = (outcome.len() as u32).to_be_bytes();
    h(
        TAG_DSM_ESCROW_STATEMENT_LOCATOR,
        &[verdict_cell, &len, outcome],
    )
}

// ── signing and recognition ────────────────────────────────────────────────

/// One signer's signature over `m(outcome)` for the cell. The producer half
/// of [`verdict_authority`]: what a signer contributes to a verdict.
pub fn sign_statement(
    signer: &EscrowSigner,
    secret_key: &[u8],
    verdict_cell: &D32,
    outcome: &[u8],
) -> Result<VerdictSignature, crate::types::error::DsmError> {
    let digest = statement(verdict_cell, outcome);
    let signature = crate::crypto::sphincs::sphincs_sign(secret_key, &digest)?;
    // Refuse a key that does not sign as the signer it names: a contribution
    // that would never verify is not one.
    verify_bytes(
        "EscrowStatement",
        signer.signature_alg(),
        signer.public_key(),
        &digest,
        &signature,
    )?;
    VerdictSignature::new(signer.clone(), &signature)
        .map_err(|e| crate::types::error::DsmError::invalid_operation(e.to_string()))
}

/// Why a verdict does not occupy a cell. Every variant is decided from the
/// verdict's own bytes and the cell's key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerdictRefusal {
    /// The bytes are not a canonical `EscrowVerdict`.
    DoesNotDecode(crate::ccb::decode::DecodeError),
    /// Its `Y` and table derive another cell.
    NotThisCell,
    /// Its outcome is not a label of its table.
    OutcomeNotInTable,
    /// Its signers are not exactly the signers its table assigns to the
    /// outcome: one is missing, or one is not among them.
    NotTheOutcomesSigners,
    /// A signature does not verify over the statement for this cell.
    Signature(SignatureError),
    /// A gathered verdict for another outcome than the one being gathered.
    AnotherOutcome,
    /// The signatures in hand form no verdict with canonical bytes: none, or
    /// more than an outcome's signers.
    NoEncoding(super::wire::SofiWireError),
}

/// Whether `verdict` proves its own authority for the cell at `verdict_cell`
/// (SoFi §19.9, "What occupies the cell"):
/// 1. its `Y` and table derive the cell;
/// 2. its outcome is a label of the table;
/// 3. its signers are exactly the signers the table assigns to the outcome;
/// 4. every signature verifies over `m(outcome)` under its key.
///
/// No vault, member or reader's position enters it, so every reader reaches
/// the same answer. At most `ESCROW_MAX_SIGNERS` signatures are verified,
/// and none before the cheap conjuncts hold.
pub fn verdict_authority(
    verdict: &EscrowVerdict,
    verdict_cell: &D32,
) -> Result<(), VerdictRefusal> {
    if verdict_cell_key(
        verdict.external_commitment(),
        &table_digest(verdict.table()),
    ) != *verdict_cell
    {
        return Err(VerdictRefusal::NotThisCell);
    }
    let decided_by = verdict
        .table()
        .signers_of(verdict.outcome())
        .ok_or(VerdictRefusal::OutcomeNotInTable)?;
    // Both sides are strictly ascending by the signer's canonical bytes, so
    // the sets are equal exactly when the sequences are.
    let signed_by: Vec<&EscrowSigner> = verdict.signatures().iter().map(|s| s.signer()).collect();
    if signed_by.len() != decided_by.len() || signed_by.iter().zip(decided_by).any(|(a, b)| *a != b)
    {
        return Err(VerdictRefusal::NotTheOutcomesSigners);
    }
    let digest = statement(verdict_cell, verdict.outcome());
    for s in verdict.signatures() {
        verify_bytes(
            "EscrowVerdict",
            s.signer().signature_alg(),
            s.signer().public_key(),
            &digest,
            s.signature(),
        )
        .map_err(VerdictRefusal::Signature)?;
    }
    Ok(())
}

/// The verdict `bytes` are, when they prove their own authority for the cell
/// at `verdict_cell`, or why they do not: anything that does not counts as
/// nothing at the cell.
pub fn verdict_occupying(
    bytes: &[u8],
    verdict_cell: &D32,
) -> Result<EscrowVerdict, VerdictRefusal> {
    let verdict = EscrowVerdict::decode(bytes).map_err(VerdictRefusal::DoesNotDecode)?;
    verdict_authority(&verdict, verdict_cell)?;
    Ok(verdict)
}

/// The signatures a gathered verdict holds for `outcome` at the cell at
/// `verdict_cell`, each from a signer the table assigns to that outcome and
/// verifying over `m(outcome)`; or why the bytes are no gathered verdict for
/// that cell and outcome. Gathering carries no authority: only a verdict
/// recognized at the cell decides anything ([`verdict_authority`]).
pub fn gathered_signatures(
    bytes: &[u8],
    verdict_cell: &D32,
    outcome: &[u8],
) -> Result<Vec<VerdictSignature>, VerdictRefusal> {
    let verdict = EscrowVerdict::decode(bytes).map_err(VerdictRefusal::DoesNotDecode)?;
    if verdict_cell_key(
        verdict.external_commitment(),
        &table_digest(verdict.table()),
    ) != *verdict_cell
    {
        return Err(VerdictRefusal::NotThisCell);
    }
    if verdict.outcome() != outcome {
        return Err(VerdictRefusal::AnotherOutcome);
    }
    let decided_by = verdict
        .table()
        .signers_of(outcome)
        .ok_or(VerdictRefusal::OutcomeNotInTable)?;
    let digest = statement(verdict_cell, outcome);
    let mut kept = Vec::with_capacity(verdict.signatures().len());
    for s in verdict.signatures() {
        if !decided_by.contains(s.signer()) {
            return Err(VerdictRefusal::NotTheOutcomesSigners);
        }
        verify_bytes(
            "EscrowVerdict",
            s.signer().signature_alg(),
            s.signer().public_key(),
            &digest,
            s.signature(),
        )
        .map_err(VerdictRefusal::Signature)?;
        kept.push(s.clone());
    }
    Ok(kept)
}

/// A verdict on `outcome` from `signatures`, one per signer in canonical
/// order, once they are exactly the signers `table` assigns to `outcome` and
/// the verdict proves its own authority for its cell: what a producer writes
/// to the cell. Fewer signatures than the outcome needs is
/// `NotTheOutcomesSigners`: the gathering is not done.
pub fn assemble_verdict(
    external_commitment: D32,
    table: OutcomeTable,
    outcome: &[u8],
    signatures: Vec<VerdictSignature>,
) -> Result<EscrowVerdict, VerdictRefusal> {
    let mut by_signer: std::collections::BTreeMap<Vec<u8>, VerdictSignature> =
        std::collections::BTreeMap::new();
    for s in signatures {
        by_signer.entry(s.signer().canonical()).or_insert(s);
    }
    let cell = verdict_cell_key(&external_commitment, &table_digest(&table));
    let verdict = EscrowVerdict::new(
        external_commitment,
        table,
        outcome,
        by_signer.into_values().collect(),
    )
    .map_err(VerdictRefusal::NoEncoding)?;
    verdict_authority(&verdict, &cell)?;
    Ok(verdict)
}

// ── the verdict cell ───────────────────────────────────────────────────────

/// The verdict cell at `K_verdict` as Core derives it: the key, and the route
/// seeded by `s_verdict` over the network's pinned set. Built only by
/// [`VerdictCell::new`], which refuses members that are not the committed
/// set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerdictCell {
    key: D32,
    cell: RoutedCell,
}

impl VerdictCell {
    /// `members` must re-derive `committed_set_id`, the storage set the
    /// vaults bound to the cell commit (the network's pinned set).
    pub fn new(
        verdict_cell: &D32,
        members: &crate::ccb::StorageSetMembers,
        committed_set_id: &D32,
    ) -> Result<Self, CellError> {
        let cell = RoutedCell::new(
            TAG_DSM_ESCROW_VERDICT_CELL.source_bytes(),
            *verdict_cell,
            &verdict_seed(verdict_cell),
            members,
            committed_set_id,
        )?;
        Ok(Self {
            key: *verdict_cell,
            cell,
        })
    }

    pub fn key(&self) -> &D32 {
        &self.key
    }

    pub fn routed(&self) -> &RoutedCell {
        &self.cell
    }
}

/// Where a Release stands at its verdict cell (SoFi §19.9, "The facts").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerdictStanding {
    /// The cell holds no recognized verdict, or holds one on this outcome
    /// whose chain is not final yet: nothing is settled.
    Unsettled,
    /// `VerdictFinal(K, o)`: the cell's verdict is final on this outcome.
    Final,
    /// `VerdictHeld(K, o′)` for another outcome, in any state: this outcome
    /// can never be the cell's, because the leader holds one value for good.
    Lost,
}

/// What the ladder reads at a verdict cell, bound to the key it was read at:
/// the storage fact, and the verdict holding the cell with its exact bytes.
/// Built by [`verdict_resolution`] over the seats' reads and by nothing
/// else.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerdictCellRead {
    key: D32,
    fact: CellFact,
    held: Option<(EscrowVerdict, Vec<u8>)>,
    passed_over: Vec<VerdictRefusal>,
}

impl VerdictCellRead {
    pub fn key(&self) -> &D32 {
        &self.key
    }

    pub fn fact(&self) -> CellFact {
        self.fact
    }

    /// The verdict holding the cell, if any.
    pub fn verdict(&self) -> Option<&EscrowVerdict> {
        self.held.as_ref().map(|(verdict, _)| verdict)
    }

    /// The exact bytes of the verdict holding the cell: what a relay carries.
    pub fn value(&self) -> Option<&[u8]> {
        self.held.as_ref().map(|(_, value)| value.as_slice())
    }

    /// Why each value the leader holds ahead of the one deciding the cell
    /// counts as nothing there, in the leader's arrival order: a verdict for
    /// another cell, under signers its table does not assign, or with a
    /// signature that does not verify. What a reader reports when a cell it
    /// expects decided is still open.
    pub fn passed_over(&self) -> &[VerdictRefusal] {
        &self.passed_over
    }

    /// Where a release naming `outcome` stands at this cell.
    pub fn standing_for(&self, outcome: &[u8]) -> VerdictStanding {
        match (&self.held, self.fact) {
            (Some((verdict, _)), CellFact::Held { state, .. }) => {
                if verdict.outcome() != outcome {
                    VerdictStanding::Lost
                } else if state == ChainState::Final {
                    VerdictStanding::Final
                } else {
                    VerdictStanding::Unsettled
                }
            }
            (None, _) | (Some(..), CellFact::Open) => VerdictStanding::Unsettled,
        }
    }
}

/// The recognizer of a verdict cell: verdicts that prove their own authority
/// for its key, identified by their statement `m(o)`. Every value it passes
/// over is recorded in `refused` with the reason.
fn verdict_at<'c>(
    cell: &'c VerdictCell,
    refused: &'c std::cell::RefCell<Vec<VerdictRefusal>>,
) -> impl Fn(&[u8]) -> Option<(D32, EscrowVerdict)> + 'c {
    move |bytes| match verdict_occupying(bytes, &cell.key) {
        Ok(verdict) => Some((statement(&cell.key, verdict.outcome()), verdict)),
        Err(refusal) => {
            refused.borrow_mut().push(refusal);
            None
        }
    }
}

/// The recognizer of the one verdict a read found holding the cell: its exact
/// bytes. The first copy of those bytes in the leader's log is the first
/// value the read recognized there, so a completion proof built or checked
/// with it is about the same leader link.
fn held_verdict(read: &VerdictCellRead) -> impl Fn(&[u8]) -> Option<(D32, EscrowVerdict)> + '_ {
    move |bytes| match &read.held {
        Some((verdict, value)) if value.as_slice() == bytes => {
            Some((statement(&read.key, verdict.outcome()), verdict.clone()))
        }
        Some(..) | None => None,
    }
}

/// The route-chain reading of a verdict cell (storage spec §9): open, or the
/// first recognized verdict at its leader and how far its chain has gone,
/// with why every value ahead of it counts as nothing. Evidence that does not
/// decide the cell yet is [`Missing`], a network status and never an answer.
pub fn verdict_resolution(
    cell: &VerdictCell,
    evidence: &CellEvidence,
) -> Result<VerdictCellRead, Missing> {
    let refused = std::cell::RefCell::new(Vec::new());
    let reading = evaluate(&cell.cell, evidence, verdict_at(cell, &refused))?;
    let fact = reading.fact();
    let held = match reading {
        CellReading::Held { object, value, .. } => Some((object, value)),
        CellReading::Open => None,
    };
    Ok(VerdictCellRead {
        key: cell.key,
        fact,
        held,
        passed_over: refused.into_inner(),
    })
}

/// The completion proof of the verdict `read` found final at the cell (SoFi
/// Amendment S10), with the verdict; `None` while no chain of it has three
/// links, or when the read found the cell open.
pub fn verdict_completion(
    cell: &VerdictCell,
    read: &VerdictCellRead,
    evidence: &CellEvidence,
) -> Result<Option<(EscrowVerdict, CompletionProof)>, Missing> {
    completion_proof(&cell.cell, evidence, held_verdict(read))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ccb::sigalg::SPHINCS_PLUS_SPX256F as ALG;
    use crate::crypto::sphincs::{generate_keypair_from_seed, SphincsVariant};
    use crate::sofi::wire::{
        EscrowBranch, EscrowOutcome, SofiWireError, ESCROW_MAX_BRANCHES, ESCROW_MAX_SIGNERS,
    };

    /// A signer and its secret key, from a fixed seed.
    fn party(seed: u8) -> (EscrowSigner, Vec<u8>) {
        let kp = generate_keypair_from_seed(SphincsVariant::SPX256f, &[seed; 32]).expect("keypair");
        (
            EscrowSigner::new(ALG, &kp.public_key).expect("a declared key"),
            kp.secret_key.clone(),
        )
    }

    /// `signers` in their canonical order.
    fn set(mut signers: Vec<EscrowSigner>) -> Vec<EscrowSigner> {
        signers.sort_by_key(EscrowSigner::canonical);
        signers
    }

    struct Match {
        referee: (EscrowSigner, Vec<u8>),
        a: (EscrowSigner, Vec<u8>),
        b: (EscrowSigner, Vec<u8>),
        y: D32,
    }

    fn the_match() -> Match {
        Match {
            referee: party(0x51),
            a: party(0x52),
            b: party(0x53),
            y: external_commitment(b"match 7: A v B, 25 each, referee R"),
        }
    }

    /// The terms of one player's stake: A wins → A, B wins → B, cancel (both
    /// players) → `owner`, void (referee) → `owner`.
    fn terms(m: &Match, owner: (D32, D32)) -> EscrowTerms {
        let referee = vec![m.referee.0.clone()];
        let both = set(vec![m.a.0.clone(), m.b.0.clone()]);
        let branch = |outcome: &[u8], signers: Vec<EscrowSigner>, to: (D32, D32)| {
            EscrowBranch::new(
                EscrowOutcome::new(outcome, signers).expect("outcome"),
                to.0,
                to.1,
            )
        };
        EscrowTerms::new(
            [0xE7; 32],
            m.y,
            vec![
                branch(b"a-wins", referee.clone(), ([0xA1; 32], [0xA2; 32])),
                branch(b"b-wins", referee.clone(), ([0xB1; 32], [0xB2; 32])),
                branch(b"cancel", both, owner),
                branch(b"void", referee, owner),
            ],
        )
        .expect("terms")
    }

    fn verdict(
        m: &Match,
        terms: &EscrowTerms,
        outcome: &[u8],
        by: &[&(EscrowSigner, Vec<u8>)],
    ) -> EscrowVerdict {
        let cell = verdict_cell_of(terms);
        let mut signatures: Vec<VerdictSignature> = by
            .iter()
            .map(|(signer, sk)| sign_statement(signer, sk, &cell, outcome).expect("signs"))
            .collect();
        signatures.sort_by_key(|s| s.signer().canonical());
        EscrowVerdict::new(m.y, terms.outcome_table(), outcome, signatures).expect("verdict")
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

    #[test]
    fn the_derivations_are_the_specified_hashes() {
        let m = the_match();
        let t = terms(&m, ([0x01; 32], [0x02; 32]));
        assert_eq!(
            external_commitment(b"x"),
            independent("DSM/external/v1", &[b"x"])
        );
        let tau = table_digest(&t.outcome_table());
        assert_eq!(
            tau,
            independent(
                "DSM/escrow/outcome-table/v1",
                &[&t.outcome_table().digest_preimage()]
            )
        );
        let k = verdict_cell_of(&t);
        assert_eq!(k, independent("DSM/escrow/verdict-cell/v1", &[&m.y, &tau]));
        assert_eq!(
            verdict_seed(&k),
            independent("DSM/escrow/verdict-seed/v1", &[&k])
        );
        assert_eq!(
            statement(&k, b"void"),
            independent(
                "DSM/escrow/statement/v1",
                &[&k, &4u32.to_be_bytes(), b"void"]
            )
        );
        assert_eq!(
            cell_locator(&k),
            independent("DSM/escrow/cell-locator/v1", &[&k])
        );
        assert_eq!(
            statement_locator(&k, b"void"),
            independent(
                "DSM/escrow/statement-locator/v1",
                &[&k, &4u32.to_be_bytes(), b"void"]
            )
        );
    }

    /// The table τ hashes is exactly `u8(|O|) ‖ ⨁ (u32be(|o|) ‖ o ‖
    /// u8(|signers|) ‖ ⨁ (u16be(alg) ‖ u32be(|key|) ‖ key))`, built here by
    /// hand from the branches.
    #[test]
    fn the_outcome_table_has_the_specified_bytes() {
        let m = the_match();
        let t = terms(&m, ([0x01; 32], [0x02; 32]));
        let mut want = vec![t.branches().len() as u8];
        for b in t.branches() {
            want.extend_from_slice(&(b.outcome().len() as u32).to_be_bytes());
            want.extend_from_slice(b.outcome());
            want.push(b.signers().len() as u8);
            for s in b.signers() {
                want.extend_from_slice(&s.signature_alg().to_be_bytes());
                want.extend_from_slice(&(s.public_key().len() as u32).to_be_bytes());
                want.extend_from_slice(s.public_key());
            }
        }
        assert_eq!(t.outcome_table().digest_preimage(), want);
    }

    /// Linked vaults: the same Y and the same table derive one cell whatever
    /// the recipients; a table that differs in one signer, or another Y,
    /// derives another (SoFi §19.9, "Linked vaults").
    #[test]
    fn vaults_share_a_cell_exactly_when_they_share_y_and_the_table() {
        let m = the_match();
        let a_stake = terms(&m, ([0xA1; 32], [0xA2; 32]));
        let b_stake = terms(&m, ([0xB1; 32], [0xB2; 32]));
        assert_ne!(a_stake, b_stake, "the two stakes pay their own owners");
        assert_eq!(verdict_cell_of(&a_stake), verdict_cell_of(&b_stake));
        assert_ne!(terms_address(&a_stake), terms_address(&b_stake));

        let other_y = Match {
            y: external_commitment(b"match 8"),
            ..the_match()
        };
        assert_ne!(
            verdict_cell_of(&terms(&other_y, ([0xA1; 32], [0xA2; 32]))),
            verdict_cell_of(&a_stake)
        );

        // The same outcomes with one signer changed: another authority, so
        // another cell.
        let mut branches: Vec<EscrowBranch> = a_stake.branches().to_vec();
        branches[3] = EscrowBranch::new(
            EscrowOutcome::new(b"void", vec![party(0x54).0]).expect("outcome"),
            [0xA1; 32],
            [0xA2; 32],
        );
        let other_table = EscrowTerms::new(*a_stake.token(), m.y, branches).expect("terms");
        assert_ne!(verdict_cell_of(&other_table), verdict_cell_of(&a_stake));
    }

    #[test]
    fn terms_round_trip_and_what_has_no_canonical_order_has_no_encoding() {
        let m = the_match();
        let t = terms(&m, ([0x01; 32], [0x02; 32]));
        let bytes = t.encode();
        assert_eq!(EscrowTerms::decode(&bytes).expect("decodes"), t);
        assert_eq!(terms_address_of(&bytes), terms_address(&t));

        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(matches!(
            EscrowTerms::decode(&trailing),
            Err(crate::ccb::decode::DecodeError::TrailingBytes { .. })
        ));

        // Signers out of order, or one signer twice, is no outcome.
        let both = set(vec![m.a.0.clone(), m.b.0.clone()]);
        let reversed = vec![both[1].clone(), both[0].clone()];
        assert!(matches!(
            EscrowOutcome::new(b"cancel", reversed),
            Err(SofiWireError::NotStrictlyAscending { .. })
        ));
        assert!(matches!(
            EscrowOutcome::new(b"cancel", vec![both[0].clone(), both[0].clone()]),
            Err(SofiWireError::NotStrictlyAscending { .. })
        ));
        assert!(matches!(
            EscrowOutcome::new(b"cancel", Vec::new()),
            Err(SofiWireError::Cardinality { got: 0, .. })
        ));
        let five: Vec<EscrowSigner> = set((0..=ESCROW_MAX_SIGNERS as u8)
            .map(|i| party(0x60 + i).0)
            .collect());
        assert!(matches!(
            EscrowOutcome::new(b"cancel", five),
            Err(SofiWireError::Cardinality { got: 5, .. })
        ));
        assert!(matches!(
            EscrowOutcome::new(b"", vec![m.referee.0.clone()]),
            Err(SofiWireError::Cardinality { got: 0, .. })
        ));
        assert!(matches!(
            EscrowOutcome::new(&[0x61; 65], vec![m.referee.0.clone()]),
            Err(SofiWireError::Cardinality { got: 65, .. })
        ));

        // Branches out of order, or two with one outcome, are no terms.
        let mut swapped: Vec<EscrowBranch> = t.branches().to_vec();
        swapped.swap(0, 1);
        assert!(matches!(
            EscrowTerms::new(*t.token(), m.y, swapped),
            Err(SofiWireError::NotStrictlyAscending { .. })
        ));
        let mut twice: Vec<EscrowBranch> = t.branches().to_vec();
        twice[1] = twice[0].clone();
        assert!(matches!(
            EscrowTerms::new(*t.token(), m.y, twice),
            Err(SofiWireError::NotStrictlyAscending { .. })
        ));
        assert!(matches!(
            EscrowTerms::new(*t.token(), m.y, Vec::new()),
            Err(SofiWireError::Cardinality { got: 0, .. })
        ));
        let seventeen: Vec<EscrowBranch> = (0..=ESCROW_MAX_BRANCHES as u8)
            .map(|i| {
                EscrowBranch::new(
                    EscrowOutcome::new(&[0x40 + i], vec![m.referee.0.clone()]).expect("outcome"),
                    [0x01; 32],
                    [0x02; 32],
                )
            })
            .collect();
        assert!(matches!(
            EscrowTerms::new(*t.token(), m.y, seventeen),
            Err(SofiWireError::Cardinality { got: 17, .. })
        ));
    }

    #[test]
    fn a_verdict_proves_its_own_authority_for_its_cell() {
        let m = the_match();
        let t = terms(&m, ([0x01; 32], [0x02; 32]));
        let k = verdict_cell_of(&t);

        let won = verdict(&m, &t, b"a-wins", &[&m.referee]);
        assert_eq!(
            won.encode(),
            EscrowVerdict::decode(&won.encode())
                .expect("decodes")
                .encode()
        );
        assert_eq!(verdict_occupying(&won.encode(), &k), Ok(won.clone()));

        // A joint cancel needs both players' signatures, and only theirs.
        let cancel = verdict(&m, &t, b"cancel", &[&m.a, &m.b]);
        assert_eq!(verdict_occupying(&cancel.encode(), &k), Ok(cancel));
        let half = verdict(&m, &t, b"cancel", &[&m.a]);
        assert_eq!(
            verdict_occupying(&half.encode(), &k),
            Err(VerdictRefusal::NotTheOutcomesSigners)
        );
        let with_referee = verdict(&m, &t, b"cancel", &[&m.a, &m.b, &m.referee]);
        assert_eq!(
            verdict_occupying(&with_referee.encode(), &k),
            Err(VerdictRefusal::NotTheOutcomesSigners)
        );

        // The referee cannot decide the players' cancel, nor a player the
        // referee's outcome.
        let by_referee = verdict(&m, &t, b"cancel", &[&m.referee]);
        assert_eq!(
            verdict_occupying(&by_referee.encode(), &k),
            Err(VerdictRefusal::NotTheOutcomesSigners)
        );
        let by_a = verdict(&m, &t, b"a-wins", &[&m.a]);
        assert_eq!(
            verdict_occupying(&by_a.encode(), &k),
            Err(VerdictRefusal::NotTheOutcomesSigners)
        );

        // An outcome the table does not have decides nothing.
        let off_table = verdict(&m, &t, b"draw", &[&m.referee]);
        assert_eq!(
            verdict_occupying(&off_table.encode(), &k),
            Err(VerdictRefusal::OutcomeNotInTable)
        );
    }

    /// The statement names the cell: the referee's signature for one cell is
    /// no verdict at another, even for the same outcome and the same signers.
    #[test]
    fn a_signature_decides_only_the_cell_it_was_made_for() {
        let m = the_match();
        let t = terms(&m, ([0x01; 32], [0x02; 32]));
        let other = Match {
            y: external_commitment(b"match 8"),
            ..the_match()
        };
        let t8 = terms(&other, ([0x01; 32], [0x02; 32]));
        let k8 = verdict_cell_of(&t8);

        let for_7 = verdict(&m, &t, b"a-wins", &[&m.referee]);
        // Presented at match 8's cell as it is: its own Y and table derive
        // match 7's cell.
        assert_eq!(
            verdict_occupying(&for_7.encode(), &k8),
            Err(VerdictRefusal::NotThisCell)
        );
        // Restated for match 8 with match 7's signature: the signature is over
        // match 7's statement, so it does not verify.
        let moved = EscrowVerdict::new(
            other.y,
            t8.outcome_table(),
            b"a-wins",
            for_7.signatures().to_vec(),
        )
        .expect("verdict");
        assert!(matches!(
            verdict_occupying(&moved.encode(), &k8),
            Err(VerdictRefusal::Signature(
                SignatureError::DoesNotVerify { .. }
            ))
        ));
        // And a signature over another outcome is not this outcome's.
        let b_won = verdict(&m, &t, b"b-wins", &[&m.referee]);
        let relabeled = EscrowVerdict::new(
            m.y,
            t.outcome_table(),
            b"a-wins",
            b_won.signatures().to_vec(),
        )
        .expect("verdict");
        assert!(matches!(
            verdict_occupying(&relabeled.encode(), &verdict_cell_of(&t)),
            Err(VerdictRefusal::Signature(
                SignatureError::DoesNotVerify { .. }
            ))
        ));
    }

    /// A joint cancel gathered one signature at a time: each signer's gathered
    /// verdict yields only that outcome's verifying signatures, and the
    /// verdict is assembled only once they are exactly the outcome's signers.
    #[test]
    fn a_verdict_is_assembled_only_from_the_outcomes_signatures() {
        let m = the_match();
        let t = terms(&m, ([0x01; 32], [0x02; 32]));
        let k = verdict_cell_of(&t);
        let from_a = verdict(&m, &t, b"cancel", &[&m.a]).encode();
        let from_b = verdict(&m, &t, b"cancel", &[&m.b]).encode();

        let mut gathered = gathered_signatures(&from_a, &k, b"cancel").expect("a's signature");
        assert_eq!(gathered.len(), 1);
        assert_eq!(
            assemble_verdict(m.y, t.outcome_table(), b"cancel", gathered.clone()),
            Err(VerdictRefusal::NotTheOutcomesSigners),
            "one player's signature is not a cancel"
        );
        gathered.extend(gathered_signatures(&from_b, &k, b"cancel").expect("b's signature"));
        // The same signature gathered twice is one signature.
        gathered.extend(gathered_signatures(&from_a, &k, b"cancel").expect("a's again"));
        let cancel =
            assemble_verdict(m.y, t.outcome_table(), b"cancel", gathered).expect("both players");
        assert_eq!(verdict_occupying(&cancel.encode(), &k), Ok(cancel.clone()));
        assert_eq!(cancel, verdict(&m, &t, b"cancel", &[&m.a, &m.b]));

        // Gathering for another outcome, at another cell, or from a signer
        // the outcome does not name, yields nothing.
        assert_eq!(
            gathered_signatures(&from_a, &k, b"void"),
            Err(VerdictRefusal::AnotherOutcome)
        );
        let other = Match {
            y: external_commitment(b"match 8"),
            ..the_match()
        };
        assert_eq!(
            gathered_signatures(
                &from_a,
                &verdict_cell_of(&terms(&other, ([0x01; 32], [0x02; 32]))),
                b"cancel"
            ),
            Err(VerdictRefusal::NotThisCell)
        );
        let by_referee = verdict(&m, &t, b"cancel", &[&m.referee]).encode();
        assert_eq!(
            gathered_signatures(&by_referee, &k, b"cancel"),
            Err(VerdictRefusal::NotTheOutcomesSigners)
        );
        // A gathered signature over another statement does not verify.
        let b_won = verdict(&m, &t, b"b-wins", &[&m.referee]);
        let relabeled = EscrowVerdict::new(
            m.y,
            t.outcome_table(),
            b"a-wins",
            b_won.signatures().to_vec(),
        )
        .expect("verdict")
        .encode();
        assert!(matches!(
            gathered_signatures(&relabeled, &k, b"a-wins"),
            Err(VerdictRefusal::Signature(
                SignatureError::DoesNotVerify { .. }
            ))
        ));
        // No signatures at all have no encoding.
        assert!(matches!(
            assemble_verdict(m.y, t.outcome_table(), b"void", Vec::new()),
            Err(VerdictRefusal::NoEncoding(SofiWireError::Cardinality {
                got: 0,
                ..
            }))
        ));
    }

    /// Where a release stands, from what the cell holds: open or not final
    /// on its outcome is unsettled, final on its outcome is final, and the
    /// other outcome held in any state is lost.
    #[test]
    fn a_release_stands_on_the_verdict_the_cell_holds() {
        let m = the_match();
        let t = terms(&m, ([0x01; 32], [0x02; 32]));
        let k = verdict_cell_of(&t);
        let a_won = verdict(&m, &t, b"a-wins", &[&m.referee]);
        let read = |state: Option<ChainState>| VerdictCellRead {
            key: k,
            fact: match state {
                Some(state) => CellFact::Held {
                    id: statement(&k, b"a-wins"),
                    state,
                },
                None => CellFact::Open,
            },
            held: state.map(|_| (a_won.clone(), a_won.encode())),
            passed_over: Vec::new(),
        };
        assert_eq!(
            read(None).standing_for(b"a-wins"),
            VerdictStanding::Unsettled
        );
        assert_eq!(
            read(None).standing_for(b"b-wins"),
            VerdictStanding::Unsettled
        );
        for state in [ChainState::LeaderHeld, ChainState::Preserved] {
            assert_eq!(
                read(Some(state)).standing_for(b"a-wins"),
                VerdictStanding::Unsettled
            );
            assert_eq!(
                read(Some(state)).standing_for(b"b-wins"),
                VerdictStanding::Lost
            );
        }
        assert_eq!(
            read(Some(ChainState::Final)).standing_for(b"a-wins"),
            VerdictStanding::Final
        );
        assert_eq!(
            read(Some(ChainState::Final)).standing_for(b"b-wins"),
            VerdictStanding::Lost
        );
    }

    /// The fixed terms the golden digests are frozen over: synthetic keys
    /// of the declared width (encoding verifies no key), two branches.
    fn golden_terms() -> EscrowTerms {
        let r = EscrowSigner::new(ALG, &[0x5A; 64]).expect("a declared key");
        let p1 = EscrowSigner::new(ALG, &[0x31; 64]).expect("a declared key");
        let p2 = EscrowSigner::new(ALG, &[0x32; 64]).expect("a declared key");
        EscrowTerms::new(
            [0x7E; 32],
            [0x59; 32],
            vec![
                EscrowBranch::new(
                    EscrowOutcome::new(b"cancel", vec![p1, p2]).expect("outcome"),
                    [0xC1; 32],
                    [0xC2; 32],
                ),
                EscrowBranch::new(
                    EscrowOutcome::new(b"void", vec![r]).expect("outcome"),
                    [0xD1; 32],
                    [0xD2; 32],
                ),
            ],
        )
        .expect("terms")
    }

    /// `u16be(alg) ‖ u32be(|key|) ‖ key`, built by hand.
    fn key_bytes(alg: u16, key: &[u8]) -> Vec<u8> {
        [
            alg.to_be_bytes().to_vec(),
            (key.len() as u32).to_be_bytes().to_vec(),
            key.to_vec(),
        ]
        .concat()
    }

    /// The CCB bytes of both objects, built here from the field tables in
    /// `sofi::wire`'s module docs and not by the encoders, and the digests
    /// over them frozen: a change to either is a change to the wire.
    #[test]
    fn the_wire_bytes_follow_the_field_tables_and_the_digests_are_frozen() {
        let t = golden_terms();
        let part = |b: &[u8]| [(b.len() as u32).to_be_bytes().to_vec(), b.to_vec()].concat();
        let mut want = vec![0x00, 0x63, 0x00, 0x01];
        want.extend_from_slice(&[0x7E; 32]);
        want.extend_from_slice(&[0x59; 32]);
        want.extend_from_slice(&2u32.to_be_bytes());
        want.extend_from_slice(&part(b"cancel"));
        want.extend_from_slice(&2u32.to_be_bytes());
        want.extend_from_slice(&key_bytes(ALG, &[0x31; 64]));
        want.extend_from_slice(&key_bytes(ALG, &[0x32; 64]));
        want.extend_from_slice(&[0xC1; 32]);
        want.extend_from_slice(&[0xC2; 32]);
        want.extend_from_slice(&part(b"void"));
        want.extend_from_slice(&1u32.to_be_bytes());
        want.extend_from_slice(&key_bytes(ALG, &[0x5A; 64]));
        want.extend_from_slice(&[0xD1; 32]);
        want.extend_from_slice(&[0xD2; 32]);
        assert_eq!(t.encode(), want);

        let k = verdict_cell_of(&t);
        let signer = EscrowSigner::new(ALG, &[0x5A; 64]).expect("a declared key");
        let v = EscrowVerdict::new(
            *t.external_commitment(),
            t.outcome_table(),
            b"void",
            vec![VerdictSignature::new(signer, &[0x99; 3]).expect("signature")],
        )
        .expect("verdict");
        let mut want = vec![0x00, 0x64, 0x00, 0x01];
        want.extend_from_slice(&[0x59; 32]);
        want.extend_from_slice(&2u32.to_be_bytes());
        want.extend_from_slice(&part(b"cancel"));
        want.extend_from_slice(&2u32.to_be_bytes());
        want.extend_from_slice(&key_bytes(ALG, &[0x31; 64]));
        want.extend_from_slice(&key_bytes(ALG, &[0x32; 64]));
        want.extend_from_slice(&part(b"void"));
        want.extend_from_slice(&1u32.to_be_bytes());
        want.extend_from_slice(&key_bytes(ALG, &[0x5A; 64]));
        want.extend_from_slice(&part(b"void"));
        want.extend_from_slice(&1u32.to_be_bytes());
        want.extend_from_slice(&key_bytes(ALG, &[0x5A; 64]));
        want.extend_from_slice(&part(&[0x99; 3]));
        assert_eq!(v.encode(), want);
        assert_eq!(EscrowVerdict::decode(&want).expect("decodes"), v);

        let b32 = crate::utils::text_id::encode_base32_crockford;
        assert_eq!(
            b32(&terms_address(&t)),
            "RE1WCSK9TWW7CRDGVR8B680KV579N0C7TXQE9J199K9DQ1DMMVJ0"
        );
        assert_eq!(
            b32(&table_digest(&t.outcome_table())),
            "4V1EDH3RSS5KXEBDHXC6J9S2NPFQ5115H42JGZV62EPSC632QEHG"
        );
        assert_eq!(
            b32(&k),
            "WNJGZV7JPY4GDMP17W0JPKMAR21YG6Z06M9YR6EHR18YSA257VC0"
        );
        assert_eq!(
            b32(&statement(&k, b"void")),
            "K0P13J70J0N3KXNAM1HJEHSFG8PDEKWXQ460MVDDB0TPCJG8ADSG"
        );
        assert_eq!(
            b32(&cell_locator(&k)),
            "6H86QMFR7WZQ32S59TY4BJ4A919SB86Y2M6SRH82N3XB3G7HAGTG"
        );
    }
}
