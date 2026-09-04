// SPDX-License-Identifier: MIT OR Apache-2.0
//! Vault-state composition — quote-time derivation of a vault's canonical
//! current state from its published, verified artifacts.
//!
//! Baseline
//! --------
//! The baseline is the owner's `AnchorPresentationV3` plus the exact
//! `CCB(V_n)` bytes its anchor commits. `verify_anchor_presentation` runs the
//! full P0–P6 owner-authority predicate and re-hashes the bytes against the
//! signed `c_n`, so everything the old anchor stack restated — sequence,
//! reserves, pair, fee, storage set, owner identity — is read out of ONE
//! authenticated object with one identity:
//!
//! ```text
//! c_n = H_dom(DSM/vault-state, CCB(V_n))
//! ```
//!
//! There is no inclusion proof, no reserve proof, no birth anchor and no
//! `/latest` here — those were parallel restatements of state facts, and the
//! state-identity cut removes the duplicate sources rather than
//! cross-checking them.
//!
//! The frontier walk
//! -----------------
//! On top of the verified baseline the composer walks FORWARD one generation
//! at a time, and the edge source is the settlement-slot REGISTER CELL read
//! live at the quorum the owner committed in `V_n` (field 15), against the
//! storage set `V_n` names.
//!
//! That inversion is the point. A prefix listing's exhaustiveness is
//! unfalsifiable: a member that omits a key produces an answer no signature
//! can distinguish from a genuinely shorter chain, so a composer reading one
//! could only ever report a valid PREFIX while sounding like it reported the
//! latest state. A write-once cell cannot express omission — it either holds
//! a claim or it does not — so `q` attributed members answering "nothing
//! here" is a positive fact, and it is the only thing that ends the walk.
//!
//! Each generation therefore has exactly three outcomes:
//!
//! ```text
//! empty at quorum   -> the chain ends here; THIS is the frontier
//! winner at quorum  -> validate the edge and fold, or fail closed
//! anything else     -> DLV_BINDING_EVIDENCE_UNAVAILABLE
//! ```
//!
//! Validating an edge means: the winner's claim verifies and binds this exact
//! parent `c_n`; a settlement receipt witnesses this generation step; the
//! signed `RouteCommit` recomputes the claimed `X`; the hop binds the cursor's
//! `c_n`; and the AMM re-simulates to exactly the claimed output. A close
//! consumes the same cell — close and settle contend for one slot per
//! generation — and is recognised by its deterministic `x` claimed under the
//! owner's proven authority key, folding to the terminal zero-reserve state.
//!
//! Nothing here is a portable proof of maximality, and nothing claims to be:
//! the statement is "during this read, no successor beyond `c_n` was
//! established". Frontier is inherently online.
//!
//! The pending-pointer records still exist as a DISCOVERY HINT for the owner's
//! own reconcile (`unapplied_settlements_for_vault`), which understates rather
//! than invents. They are not consulted here: a self-signed pointer never
//! established that an edge exists, and the cell now does.
//!
//! The composed result is a full `VaultStateV2` with a canonical identity of
//! its own: the `c_n` a new trade's hop must bind as its parent.

use dsm::ccb::{vault_state_commitment, VaultStateV2};
use dsm::types::proto as generated;
use prost::Message;

use crate::sdk::bitcoin_tap_sdk::BitcoinTapSdk;
use crate::sdk::identity_presentation::verify_anchor_presentation;
use crate::sdk::route_commit_sdk::{
    compute_external_commitment, external_commitment_rc_key, verify_route_commit_unlock_eligibility,
};
use crate::sdk::routing_path_sdk::constant_product_output;

/// Maximum pending-chain depth a composer will fold before treating the
/// vault as saturated and excluding it from path search.  Caps adversarial
/// pointer-flooding cost at O(MAX_PENDING_CHAIN_DEPTH) signature verifies
/// per quote.
pub(crate) const MAX_PENDING_CHAIN_DEPTH: usize = 64;

/// A parent the fold consumed on its way to the frontier — see
/// [`ComposedVaultState::folded_parents`].
#[derive(Debug, Clone)]
pub(crate) struct FoldedParent {
    pub generation: u64,
    /// `vault_state_commitment(&state)`, computed by the walk.
    pub c_n: [u8; 32],
    pub state: VaultStateV2,
}

/// Result of composing pending pointers onto a presentation-verified
/// baseline.
#[derive(Debug, Clone)]
pub(crate) struct ComposedVaultState {
    /// The composed state itself — the baseline `V_n` when no pointers
    /// folded, the constructed successor otherwise. Every fact a consumer
    /// needs (generation, reserves, pair, fee, storage set, encumbrances,
    /// authority position) is a field of this one object.
    pub state: VaultStateV2,
    /// `c_n` of `state` — the canonical identity of the state this walk
    /// reached, and the exact value a new trade's hop must carry as
    /// `parent_binding`.
    ///
    /// This IS a proven frontier for the live read that produced it: the walk
    /// terminated because q attributed members of the vault's own committed
    /// storage set each answered that the settlement-slot cell at this
    /// generation holds nothing. A composition that could not establish that
    /// is not returned at all — it fails closed as
    /// [`CompositionError::BindingEvidenceUnavailable`] — so this value can
    /// never be a silently-short prefix.
    ///
    /// It is NOT a portable proof of maximality, and nothing here claims one:
    /// the statement is "during this read, no successor beyond `c_n` was
    /// established", which is only true of the moment it was read.
    pub c_n: [u8; 32],
    /// `state.generation`, broken out for callers that only order by it.
    pub sequence: u64,
    /// The parent CONSUMED by each successful fold, oldest first: its
    /// generation, its `c_n`, and the state itself. This is how a caller
    /// reconciling a settlement N generations back names the exact historical
    /// parent state that settlement consumed — and proves its trade against
    /// that state's own reserves and fee — from the chain the composition
    /// itself verified: no re-derivation and no second source.
    pub folded_parents: Vec<FoldedParent>,
    /// `state.reserve_a` / `state.reserve_b`, broken out for AMM math.
    pub reserves_a: u64,
    pub reserves_b: u64,
    /// How many successor edges this walk verified and folded to reach the
    /// frontier.
    ///
    /// There is deliberately no companion "skipped" count any more. Under the
    /// prefix-listing fold a skip was routine — anyone could publish a
    /// self-signed pointer, so unfoldable ones had to be ignored rather than
    /// allowed to suppress the vault. Under the cell walk there is no such
    /// category: an edge either does not exist (empty at quorum), or exists
    /// and validates (folded here), or exists and does not
    /// (`BindingEvidenceUnavailable`). A count of quietly-ignored edges would
    /// have nothing to hold.
    pub pending_chain_len: usize,
    /// The vault owner, proven by the presentation's P0–P6 chain at the
    /// state's own committed authority position. Constant across generations
    /// — market successors copy the authority position byte-for-byte.
    pub owner_devid: [u8; 32],
    pub owner_genesis: [u8; 32],
    pub owner_public_key: Vec<u8>,
    /// `AuthorityEvidenceV1` bytes for this vault's owner, re-encoded from
    /// the SAME six values the presentation just authenticated.
    ///
    /// Not a second owner-authority format and not a second authentication:
    /// `AnchorPresentationV3` fields 4–9 ARE `AuthorityEvidenceV1` fields
    /// 1–6, and `verify_anchor_presentation` resolved them through the same
    /// resolver at the same position (`V_n.owner_authority_transition_digest`)
    /// that `verify_authority_evidence` uses. Carried from here so a consumer
    /// takes the bytes that were checked, rather than re-fetching an object
    /// that could differ from the one this composition trusted.
    pub owner_authority_evidence: Vec<u8>,
    /// `storage_set_id = H_dom(DSM/storage-set, CCB(S))` over the state's OWN
    /// storage-set member list — a derived view of a `V_n` field, never a
    /// second source. Consumers resolve it through their local catalog.
    pub storage_set_id: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CompositionError {
    /// The presentation failed P0–P6, the `CCB(V_n)` bytes do not hash to the
    /// anchor's commitment, or the bytes do not strictly decode. Fail closed
    /// — without an authenticated baseline the entire composition is moot.
    InvalidBaselinePresentation(String),
    /// The baseline verified, but it describes a different market than the
    /// caller asked to compose: wrong vault id, wrong pair, or wrong fee.
    /// The signed state is authoritative; a disagreeing caller tuple means
    /// the caller's view is stale or fabricated.
    BaselineMismatch(String),
    /// Storage listing the pending prefix failed.
    StorageListFailed(String),
    /// Decoding a pointer proto failed in a non-recoverable way.  The
    /// individual pointer is skipped; this variant fires only if the
    /// whole list page failed.
    PointerDecodeFailed(String),
    /// The caller names the pair by something other than 32-byte policy
    /// commits, so it cannot be matched against the signed state's market
    /// policy. FAILS CLOSED — a label is not an identity.
    PairIsNotPolicyCommits,
    /// Req 6.25 `DLV_BINDING_EVIDENCE_UNAVAILABLE`: the walk could not
    /// establish where this vault's chain ends, so no state is returned and
    /// the vault is excluded from routing.
    ///
    /// This is the ONE outcome that must never be softened into a short
    /// answer. It covers: fewer than the committed `q` members giving an
    /// attributed answer for a slot cell; members holding divergent values for
    /// one write-once cell; a quorum-established slot winner whose settlement
    /// evidence cannot be fetched or verified; and depth saturation. An
    /// adversary who wins a slot and never settles can hold a vault here
    /// indefinitely — that is a liveness cost, and it is strictly preferable
    /// to manufacturing a maximality claim the network did not support.
    BindingEvidenceUnavailable(String),
}

impl std::fmt::Display for CompositionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CompositionError::InvalidBaselinePresentation(msg) => {
                write!(f, "baseline presentation failed verification: {msg}")
            }
            CompositionError::BaselineMismatch(msg) => {
                write!(
                    f,
                    "baseline disagrees with the caller's market tuple: {msg}"
                )
            }
            CompositionError::StorageListFailed(msg) => {
                write!(f, "storage list failed: {msg}")
            }
            CompositionError::PointerDecodeFailed(msg) => {
                write!(f, "pointer decode failed: {msg}")
            }
            CompositionError::PairIsNotPolicyCommits => write!(
                f,
                "caller pair must be 32-byte policy commits so it can be matched to the signed \
                 state's market policy"
            ),
            CompositionError::BindingEvidenceUnavailable(msg) => {
                write!(f, "DLV_BINDING_EVIDENCE_UNAVAILABLE: {msg}")
            }
        }
    }
}

impl std::error::Error for CompositionError {}

/// Fold pending pointers onto a presentation-verified baseline.
///
/// `presentation` + `vn_bytes` are the owner's published verification bundle
/// and the exact `CCB(V_n)` bytes its anchor commits — both fetched through
/// the immutable store (which already re-hashed the bytes against the
/// requested identity) or built locally by the owner. Verification here is
/// full P0–P6; nothing is trusted as presented.
///
/// `(token_a, token_b, fee_bps)` is the market tuple the caller intends to
/// quote. It is checked AGAINST the signed state and refused on mismatch —
/// the state is authoritative, the tuple is the caller's intent.
pub(crate) async fn compose_vault_state(
    vault_id: &[u8; 32],
    presentation: &crate::generated::AnchorPresentationV3,
    vn_bytes: &[u8],
    token_a: &[u8],
    token_b: &[u8],
    fee_bps: u32,
) -> Result<ComposedVaultState, CompositionError> {
    // ── The baseline: one authenticated object. ──────────────────────────
    let verified = verify_anchor_presentation(presentation, vn_bytes)
        .map_err(|e| CompositionError::InvalidBaselinePresentation(e.to_string()))?;
    // The authority half of the object just authenticated, in the shape a
    // consumer of `verify_authority_evidence` takes. Same six values, same
    // position, same resolver — see the field's doc.
    let owner_authority_evidence = {
        use prost::Message as _;
        crate::generated::AuthorityEvidenceV1 {
            genesis_params_ccb: presentation.genesis_params_ccb.clone(),
            delegations: presentation.delegations.clone(),
            transitions: presentation.transitions.clone(),
            inclusion_proof: presentation.inclusion_proof.clone(),
            ak_public_key: presentation.ak_public_key.clone(),
            atta: presentation.atta.clone(),
        }
        .encode_to_vec()
    };
    let baseline_state = verified.state;
    let baseline_c_n = verified.c_n;
    let owner = verified.owner;

    if baseline_state.vault_id != *vault_id {
        return Err(CompositionError::BaselineMismatch(
            "the presented state is for a different vault".into(),
        ));
    }

    // The caller's tuple must be the state's own market, through the ONE pair
    // parser, so the identity a vault was funded under, the identity a
    // pointer commits to, and the identity a quote is bound to are derived by
    // the same code and cannot disagree.
    let Ok(pair) = dsm::dlv::pair_identity::CanonicalPair::parse(token_a, token_b) else {
        return Err(CompositionError::PairIsNotPolicyCommits);
    };
    let (pc_a, pc_b) = (pair.a(), pair.b());
    if *baseline_state.market_policy.token_a() != pc_a
        || *baseline_state.market_policy.token_b() != pc_b
    {
        return Err(CompositionError::BaselineMismatch(
            "the caller's pair is not the signed state's market pair".into(),
        ));
    }
    if baseline_state.fee_policy.fee_bps() != fee_bps {
        return Err(CompositionError::BaselineMismatch(format!(
            "the caller's fee ({fee_bps} bps) is not the signed state's fee ({})",
            baseline_state.fee_policy.fee_bps()
        )));
    }

    let storage_set_id = dsm::ccb::storage_set_id(&baseline_state.storage_set)
        .map_err(|e| CompositionError::InvalidBaselinePresentation(format!("storage set: {e}")))?;

    // ── The vault's OWN set and quorum. ──────────────────────────────────
    // Resolved by re-deriving the id from `V_n.storage_set` (already done
    // above) and looking THAT up in the local catalog — never the catalog's
    // sole set, and never this verifier's own majority rule. `q` is field 15
    // of the owner-committed state: counting a vault's cells at a locally
    // chosen threshold would substitute the verifier's opinion for the
    // vault's rule.
    let catalog = crate::sdk::storage_set::StorageSetCatalog::from_env_config().map_err(|e| {
        CompositionError::BindingEvidenceUnavailable(format!("storage catalog: {e}"))
    })?;
    let set = catalog.resolve(&storage_set_id).cloned().ok_or_else(|| {
        CompositionError::BindingEvidenceUnavailable(
            "the vault's committed storage set is not resolvable from the local catalog".into(),
        )
    })?;
    let committed_quorum = baseline_state.quorum;
    if committed_quorum == 0 || committed_quorum as usize > set.len() {
        return Err(CompositionError::BindingEvidenceUnavailable(format!(
            "the state commits q={committed_quorum} over a {}-member set",
            set.len()
        )));
    }

    // ── THE WALK. Cursor = a full state + its commitment. ────────────────
    //
    // The edge source is the settlement-slot REGISTER CELL, read live at the
    // owner-committed quorum — not a prefix listing. That inversion is the
    // whole point: a set query's exhaustiveness is unfalsifiable, so a member
    // that omits a key produces an answer indistinguishable from a shorter
    // chain, and no signature repairs it. A write-once cell's answer is
    // bounded, and omission is not expressible in it: the cell either holds a
    // claim or it does not, and q attributed members saying "nothing here" is
    // a positive fact.
    //
    // So each generation asks exactly one question — "is there a claimed
    // successor to THIS state?" — and only three answers exist:
    //
    //   empty at quorum   -> the chain ends here; this is the frontier
    //   winner at quorum  -> verify its settlement and fold, or fail closed
    //   anything else     -> DLV_BINDING_EVIDENCE_UNAVAILABLE
    let mut cursor_state = baseline_state;
    let mut cursor_c_n = baseline_c_n;
    let mut chain_len: usize = 0;
    let mut folded_parents: Vec<FoldedParent> = Vec::new();
    loop {
        // Saturation is NOT a frontier. A walk that stops because it ran out
        // of budget has established nothing about maximality, and reporting
        // "frontier at 64" would be the omission defect wearing a local name.
        if chain_len >= MAX_PENDING_CHAIN_DEPTH {
            return Err(CompositionError::BindingEvidenceUnavailable(format!(
                "walk saturated at depth {MAX_PENDING_CHAIN_DEPTH} without reaching an empty slot                  cell"
            )));
        }
        let observation = crate::sdk::economic_registers::observe_settlement_slot_cell(
            &set,
            vault_id,
            cursor_state.generation,
            committed_quorum,
        )
        .await
        .map_err(|e| {
            // A divergent write-once cell is a network fault, never something
            // to pick a side of.
            CompositionError::BindingEvidenceUnavailable(format!(
                "settlement-slot cell at generation {}: {e}",
                cursor_state.generation
            ))
        })?;
        let winner_bytes = match observation {
            // THE ONLY TERMINATION THAT ESTABLISHES A FRONTIER.
            crate::sdk::economic_registers::CellObservation::EmptyAtQuorum => break,
            crate::sdk::economic_registers::CellObservation::NoQuorum {
                attributed,
                required,
            } => {
                return Err(CompositionError::BindingEvidenceUnavailable(format!(
                    "only {attributed} attributed member(s) answered the slot cell at generation {} ({required} required)",
                    cursor_state.generation
                )))
            }
            crate::sdk::economic_registers::CellObservation::Winner(b) => b,
        };

        // A claimed successor EXISTS. From here every failure is fail-closed:
        // the network has told us this generation is not the end, so we may
        // not report it as one because a second artifact is missing.
        let unavailable = |what: &str| {
            CompositionError::BindingEvidenceUnavailable(format!(
                "generation {} has a quorum-established successor but {what}",
                cursor_state.generation
            ))
        };
        let claim =
            dsm::dlv::settlement_slot_claim::decode_and_verify_settlement_slot_claim(&winner_bytes)
                .map_err(|e| unavailable(&format!("its slot claim does not verify: {e}")))?;
        if claim.body.vault_id != *vault_id || claim.body.parent_sequence != cursor_state.generation
        {
            return Err(unavailable("its slot claim names a different cell"));
        }
        // The claim binds the exact parent STATE, not just the generation
        // number — the v2 body's whole purpose. A winner bound to a different
        // c_n means our baseline and the network disagree about what this
        // generation IS, which is a divergence to report, never to fold past.
        if claim.body.parent_binding_c_n != cursor_c_n {
            return Err(unavailable("its slot claim binds a different parent state"));
        }
        let x = claim.body.x;

        // A CLOSE CONSUMES THIS CELL TOO. Close and settle contend for one
        // slot per generation by design, so "a winner exists" does not mean
        // "a trade happened" — the owner may have retired the vault here.
        //
        // A close needs no receipt and no RouteCommit: its successor is fully
        // determined (both reserves to zero at parent+1), so there is no
        // amount to witness. What it does need is proof the OWNER did it. The
        // close's `x` is a public derivation anyone can recompute, so the `x`
        // alone proves nothing; the claim on it signed by the owner's
        // P0–P6-proven authority key is what a stranger cannot forge. A
        // stranger who claims this cell with the close `x` therefore does not
        // produce a vault that looks closed — they produce a generation
        // consumed by something unverifiable, which fails closed below.
        if x == dsm::dlv::settlement_slot_claim::close_slot_commitment(
            vault_id,
            cursor_state.generation,
        ) {
            if claim.body.claimant_public_key != owner.ak_pk {
                return Err(unavailable(
                    "its close slot was claimed by someone other than the vault owner",
                ));
            }
            let mut next_state = cursor_state.clone();
            next_state.generation = cursor_state.generation.saturating_add(1);
            next_state.reserve_a = 0;
            next_state.reserve_b = 0;
            next_state.parent_state_commitment = cursor_c_n;
            let next_c_n = vault_state_commitment(&next_state)
                .map_err(|e| unavailable(&format!("its terminal state does not encode: {e}")))?;
            folded_parents.push(FoldedParent {
                generation: cursor_state.generation,
                c_n: cursor_c_n,
                state: cursor_state.clone(),
            });
            cursor_state = next_state;
            cursor_c_n = next_c_n;
            chain_len += 1;
            continue;
        }

        // THE RECEIPT GATE. Everything below this line moves someone's
        // liquidity, so nothing below it runs until the settlement is
        // witnessed. The receipt is the only artifact here that cannot be
        // produced without settling: it carries an inclusion path for a leaf
        // the trader's own settling advance wrote into its own device root.
        //
        // Under the cell walk a missing receipt is no longer "inert". It was,
        // when a self-signed pointer was the only evidence an edge existed —
        // anyone could publish one, so concluding anything from its presence
        // handed out free liquidity suppression. A quorum-established slot
        // winner is a different fact: the network serialized this generation
        // to this claimant. We cannot validate the edge without the receipt
        // and we may not pretend the edge is absent, so the vault leaves
        // routing until the evidence appears. A claimant who wins a slot and
        // never settles can hold a vault here; that liveness cost is the
        // honest price of not manufacturing maximality.
        let receipt = match crate::sdk::settlement_receipt_codec::fetch_verified_receipt(
            vault_id, &x,
        )
        .await
        {
            Some(r) => r,
            None => return Err(unavailable("its settlement receipt is not available")),
        };
        // The receipt must describe the step this cell claims. It is fetched
        // by (vault, x) and x came from the authenticated winner, so it is
        // already bound to this trade; this pins the generations it moves
        // between.
        if receipt.trade.parent_sequence != cursor_state.generation
            || receipt.trade.new_sequence != cursor_state.generation.saturating_add(1)
        {
            return Err(unavailable(
                "its receipt witnesses a different generation step",
            ));
        }
        let new_sequence = receipt.trade.new_sequence;
        // Fetch the full signed RouteCommit paired with X.
        let rc_key = external_commitment_rc_key(&x);
        let rc_bytes = BitcoinTapSdk::storage_get_bytes(&rc_key)
            .await
            .map_err(|_| unavailable("its RouteCommit is not published"))?;
        let rc = generated::RouteCommitV1::decode(rc_bytes.as_slice())
            .map_err(|_| unavailable("its RouteCommit does not decode"))?;
        // Storage keys are untrusted labels, so X is RECOMPUTED from the
        // RouteCommit bytes and required to equal the one the winner named.
        if compute_external_commitment(&rc) != x {
            return Err(unavailable(
                "its RouteCommit does not recompute the claimed X",
            ));
        }
        // Enforce routed-unlock eligibility gate:
        //   1) initiator SPHINCS+ signature valid over canonical RC bytes
        //   2) this vault is present in the route
        //   3) external commitment anchor for X is visible
        let hop = verify_route_commit_unlock_eligibility(&rc_bytes, vault_id)
            .await
            .map_err(|_| unavailable("its RouteCommit fails routed-unlock eligibility"))?;
        // THE PARENT BINDING. The hop must name the c_n of the exact cursor
        // state it consumes — one byte-equality that pins the generation, the
        // reserves, the pair, the fee and the authority position all at once,
        // because they are members of the identified V_n. A hop bound to any
        // other state (stale, future, fabricated) was signed against a
        // different parent and folding it would diverge from the canonical
        // chain. Mandatory: an unbound hop is skipped, never tolerated.
        if hop.parent_binding.len() != 32 || hop.parent_binding.as_slice() != cursor_c_n.as_slice()
        {
            return Err(unavailable("its hop is bound to a different parent state"));
        }
        // Decode the hop's input/output amounts.
        if hop.input_amount_u128.len() != 16 || hop.expected_output_amount_u128.len() != 16 {
            return Err(unavailable("its hop amounts are malformed"));
        }
        let mut in_buf = [0u8; 16];
        in_buf.copy_from_slice(&hop.input_amount_u128);
        let mut out_buf = [0u8; 16];
        out_buf.copy_from_slice(&hop.expected_output_amount_u128);
        // The wire carries 16-byte big-endian amounts; base units are u64. The
        // narrowing happens HERE, once, checked — an amount that does not fit
        // is a malformed hop, not a value to truncate.
        let (Ok(input_amount), Ok(expected_output)) = (
            u64::try_from(u128::from_be_bytes(in_buf)),
            u64::try_from(u128::from_be_bytes(out_buf)),
        ) else {
            return Err(unavailable("its hop amounts do not fit u64"));
        };
        // Determine trade direction against the state's own canonical pair.
        let input_is_a = hop.token_in.as_slice() == pc_a && hop.token_out.as_slice() == pc_b;
        let input_is_b = hop.token_in.as_slice() == pc_b && hop.token_out.as_slice() == pc_a;
        if !input_is_a && !input_is_b {
            return Err(unavailable("its hop trades a different pair"));
        }
        let (cursor_in, cursor_out) = if input_is_a {
            (cursor_state.reserve_a, cursor_state.reserve_b)
        } else {
            (cursor_state.reserve_b, cursor_state.reserve_a)
        };
        // Re-simulate against the cursor.  The composer demands the
        // simulated output equals the trader's claimed expected_output
        // — anything else means the trade settled against a different
        // baseline and folding it is unsafe.
        let simulated = constant_product_output(input_amount, cursor_in, cursor_out, fee_bps)
            .ok_or_else(|| unavailable("its trade does not re-simulate against this state"))?;
        if simulated != expected_output {
            return Err(unavailable(
                "its claimed output is not what this state's curve yields",
            ));
        }
        // Construct the successor state: generation advanced, reserves moved,
        // predecessor edge set to the consumed state's identity, and EVERY
        // other field — pair, fee, release policy, encumbrances, authority
        // position, storage set, quorum — copied byte-for-byte. Saturating-sub
        // on the output side defends against malformed RCs; the re-sim above
        // should already exclude these, but defense-in-depth is cheap.
        let (new_a, new_b) = if input_is_a {
            (
                cursor_state.reserve_a.saturating_add(input_amount),
                cursor_state.reserve_b.saturating_sub(expected_output),
            )
        } else {
            (
                cursor_state.reserve_a.saturating_sub(expected_output),
                cursor_state.reserve_b.saturating_add(input_amount),
            )
        };
        let mut next_state = cursor_state.clone();
        next_state.generation = new_sequence;
        next_state.reserve_a = new_a;
        next_state.reserve_b = new_b;
        next_state.parent_state_commitment = cursor_c_n;
        let next_c_n = match vault_state_commitment(&next_state) {
            Ok(c) => c,
            Err(e) => {
                // A successor of a decoded-valid state re-encodes unless the
                // walk produced something the constructors refuse. Never a
                // partial advance, and never a frontier.
                return Err(unavailable(&format!("its successor does not encode: {e}")));
            }
        };
        folded_parents.push(FoldedParent {
            generation: cursor_state.generation,
            c_n: cursor_c_n,
            state: cursor_state.clone(),
        });
        cursor_state = next_state;
        cursor_c_n = next_c_n;
        chain_len += 1;
    }

    Ok(ComposedVaultState {
        sequence: cursor_state.generation,
        reserves_a: cursor_state.reserve_a,
        reserves_b: cursor_state.reserve_b,
        pending_chain_len: chain_len,
        owner_devid: owner.device_id,
        owner_genesis: cursor_state.owner_genesis_id,
        owner_public_key: owner.ak_pk,
        owner_authority_evidence,
        storage_set_id,
        c_n: cursor_c_n,
        folded_parents,
        state: cursor_state,
    })
}

/// Compose a DISCOVERED vault from its published artifacts alone.
///
/// This is the ONE composition entry for a party holding nothing but a
/// vault id and its pair: the advertisement (located by pair + vault id)
/// carries the presentation digest — discovery, never authority — and
/// everything after that is the verified path: presentation → `c_n` →
/// exact `CCB(V_n)` bytes → full P0–P6 → receipted fold. Both the trader's
/// quote path and the pointer publisher resolve a vault THROUGH this
/// function, so no caller can substitute its own statement of any fact the
/// authenticated state carries.
pub(crate) async fn compose_discovered_vault(
    vault_id: &[u8; 32],
    token_a: &[u8],
    token_b: &[u8],
    fee_bps: u32,
) -> Result<ComposedVaultState, CompositionError> {
    let ad_key = crate::sdk::routing_sdk::advertisement_key(token_a, token_b, vault_id);
    let ad_bytes = BitcoinTapSdk::storage_get_bytes(&ad_key)
        .await
        .map_err(|e| {
            CompositionError::InvalidBaselinePresentation(format!(
                "advertisement not resolvable: {e}"
            ))
        })?;
    let ad = crate::generated::RoutingVaultAdvertisementV1::decode(ad_bytes.as_slice()).map_err(
        |e| CompositionError::InvalidBaselinePresentation(format!("advertisement decode: {e}")),
    )?;
    let Ok(presentation_digest) = <[u8; 32]>::try_from(ad.anchor_presentation_digest.as_slice())
    else {
        return Err(CompositionError::InvalidBaselinePresentation(
            "advertisement carries no presentation digest".into(),
        ));
    };
    let presentation =
        crate::sdk::vault_state_v3_codec::fetch_anchor_presentation(&presentation_digest)
            .await
            .map_err(|e| CompositionError::InvalidBaselinePresentation(e.to_string()))?
            .ok_or_else(|| {
                CompositionError::InvalidBaselinePresentation(
                    "presentation not resolvable at its advertised digest".into(),
                )
            })?;
    let Ok(c_n) = <[u8; 32]>::try_from(presentation.state_commitment.as_slice()) else {
        return Err(CompositionError::InvalidBaselinePresentation(
            "presentation carries a malformed state commitment".into(),
        ));
    };
    let vn_bytes = crate::sdk::vault_state_v3_codec::fetch_vault_state_bytes(&c_n)
        .await
        .map_err(|e| CompositionError::InvalidBaselinePresentation(e.to_string()))?
        .ok_or_else(|| {
            CompositionError::InvalidBaselinePresentation("V_n not resolvable at its c_n".into())
        })?;
    compose_vault_state(
        vault_id,
        &presentation,
        &vn_bytes,
        token_a,
        token_b,
        fee_bps,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use dsm::ccb::{
        genesis_parent_commitment, EncumbranceSet, FeePolicy, MarketPolicy, ReleasePolicy,
        StorageSetMembers,
    };
    use dsm::crypto::sphincs::{generate_keypair, SphincsVariant};
    use dsm::dlv::settlement_receipt_leaf::{
        derive_receipt_id, receipt_commitment, settlement_receipt_key, settlement_receipt_value,
        sign_trader_settlement_receipt, SettledTrade,
    };
    use dsm::dlv::vault_pending_pointer::sign_vault_pending_pointer;

    use crate::sdk::identity_presentation::{
        build_own_anchor_presentation, derive_own_authority_context, OwnerIdentityInputs,
    };

    /// The one wallet the fixtures own. Everything — GRK, device key, AttA,
    /// D_0/T_0 — re-derives from it, exactly as production does.
    const SEED: &[u8] = b"test-bip39-wallet-seed-64-bytes-............................xxxx";
    const NET: &[u8] = b"dsm-test";
    const INPUTS: OwnerIdentityInputs<'static> = OwnerIdentityInputs {
        network_id: NET,
        wallet_index: 0,
        device_slot: 0,
        genesis_version: 3,
    };

    /// The pair, as 32-byte policy commits (lex-ordered: TOKEN_A < TOKEN_B).
    const TOKEN_A: [u8; 32] = [0x11; 32];
    const TOKEN_B: [u8; 32] = [0x22; 32];
    const FEE_BPS: u32 = 30;

    fn vid(b: u8) -> [u8; 32] {
        let mut v = [0u8; 32];
        v[0] = 0x7A;
        v[1] = b;
        v
    }

    fn x_seed(b: u8) -> [u8; 32] {
        let mut v = [0u8; 32];
        v[0] = 0xEC;
        v[1] = b;
        v[31] = b.wrapping_mul(31).wrapping_add(11);
        v
    }

    /// Install the 3-node fleet these tests compose against and clear both
    /// the flat object store and the per-member registers.
    ///
    /// Composition now reads a REGISTER, so a test that does not stand a fleet
    /// up is not testing a weaker composition — it gets
    /// `BindingEvidenceUnavailable`, because an unresolvable set is exactly
    /// the fail-closed case.
    fn fleet() -> crate::handlers::faucet_flow_tests::FleetGuard {
        let guard = crate::handlers::faucet_flow_tests::install_canonical_fleet();
        crate::sdk::storage_io::fake_fleet::reset();
        crate::sdk::bitcoin_tap_sdk::BitcoinTapSdk::reset_dbtc_storage_test_state();
        guard
    }

    fn fleet_set() -> crate::sdk::storage_set::StorageSet {
        crate::sdk::storage_set::StorageSetCatalog::from_env_config()
            .expect("catalog")
            .sole_set()
            .expect("one set")
            .clone()
    }

    /// Win the settlement slot at `(vault_id, parent_sequence)` for the trade
    /// named by `x`, binding the exact parent state `parent_c_n`.
    ///
    /// This is what makes a successor edge EXIST for the walk. Publishing a
    /// receipt and a RouteCommit no longer creates an edge on its own: the
    /// network has to have serialized the generation to this claimant.
    async fn win_slot(
        vault_id: &[u8; 32],
        parent_sequence: u64,
        x: &[u8; 32],
        parent_c_n: &[u8; 32],
        claimant_pk: &[u8],
        claimant_sk: &[u8],
    ) {
        let set = fleet_set();
        let body = dsm::dlv::settlement_slot_claim::SettlementSlotClaimBody {
            vault_id: *vault_id,
            parent_sequence,
            x: *x,
            claimant_public_key: claimant_pk.to_vec(),
            storage_set_id: set.id(),
            parent_binding_c_n: *parent_c_n,
        };
        let envelope =
            dsm::dlv::settlement_slot_claim::sign_settlement_slot_claim(&body, claimant_sk)
                .expect("sign slot claim");
        crate::sdk::storage_io::fake_fleet::claim(&set, &envelope);
    }

    /// Build the owner's `V_0` for a fixture vault, its `CCB(V_0)` bytes, its
    /// `c_0`, and the presentation anchoring it — all through the production
    /// builders.
    fn baseline_fixture(
        vault_id: [u8; 32],
        reserve_a: u64,
        reserve_b: u64,
    ) -> (
        crate::generated::AnchorPresentationV3,
        Vec<u8>,
        VaultStateV2,
        [u8; 32],
    ) {
        let auth = derive_own_authority_context(SEED, INPUTS).expect("authority context");
        let state = VaultStateV2 {
            owner_genesis_id: auth.g,
            owner_device_id: auth.devid,
            vault_id,
            generation: 0,
            reserve_a,
            reserve_b,
            market_policy: MarketPolicy::beta_constant_product(TOKEN_A, TOKEN_B).expect("pair"),
            release_policy: ReleasePolicy::beta_owner_local_full_close(),
            fee_policy: FeePolicy::new(FEE_BPS).expect("fee"),
            encumbrances: EncumbranceSet::empty(),
            iteration_budget: None,
            parent_state_commitment: genesis_parent_commitment(&vault_id),
            owner_authority_transition_digest: auth.position,
            // THE VAULT'S OWN SET AND QUORUM. The walk resolves this set id
            // through the local catalog and counts cells at THIS q — so the
            // fixture must commit the fleet these tests actually run against,
            // exactly as a real vault commits the fleet it was born under.
            storage_set: StorageSetMembers::new(&[b"dsm-node-1", b"dsm-node-2", b"dsm-node-3"])
                .expect("set"),
            quorum: 2,
        };
        let ccb = state.encode().expect("encode");
        let c0 = vault_state_commitment(&state).expect("c_0");
        let presentation =
            build_own_anchor_presentation(SEED, INPUTS, &auth.g, &c0).expect("presentation");
        (presentation, ccb, state, c0)
    }

    /// Publish the minimal ExtCommit anchor at `sofi/extcommit/{X_b32}`.
    async fn publish_extcommit(x: &[u8; 32], publisher_pk: &[u8]) {
        let anchor = generated::ExternalCommitmentV1 {
            version: 1,
            x: x.to_vec(),
            publisher_public_key: publisher_pk.to_vec(),
            label: "test".into(),
        };
        let key = crate::sdk::route_commit_sdk::external_commitment_key(x);
        BitcoinTapSdk::storage_put_bytes(&key, &anchor.encode_to_vec())
            .await
            .expect("X publish");
    }

    /// Publish a `RouteCommitV1` with a single AMM hop touching `vault_id`,
    /// bound to `parent_binding` (the c_n of the state it consumes). Returns
    /// the swap's post-trade reserves plus the canonical commitment `X`.
    #[allow(clippy::too_many_arguments)]
    async fn publish_rc_for_swap(
        nonce_seed: &[u8; 32],
        vault_id: &[u8; 32],
        parent_reserve_a: u64,
        parent_reserve_b: u64,
        parent_binding: &[u8; 32],
        input_is_a: bool,
        input_amount: u64,
        trader_pk: &[u8],
        trader_sk: &[u8],
    ) -> (u64, u64, [u8; 32]) {
        let (reserve_in, reserve_out) = if input_is_a {
            (parent_reserve_a, parent_reserve_b)
        } else {
            (parent_reserve_b, parent_reserve_a)
        };
        let simulated = crate::sdk::routing_path_sdk::constant_product_output(
            input_amount,
            reserve_in,
            reserve_out,
            FEE_BPS,
        )
        .expect("test inputs must yield a swap");
        let (new_a, new_b) = if input_is_a {
            (
                parent_reserve_a + input_amount,
                parent_reserve_b - simulated,
            )
        } else {
            (
                parent_reserve_a - simulated,
                parent_reserve_b + input_amount,
            )
        };

        let (hop_token_in, hop_token_out) = if input_is_a {
            (TOKEN_A.to_vec(), TOKEN_B.to_vec())
        } else {
            (TOKEN_B.to_vec(), TOKEN_A.to_vec())
        };
        let hop = generated::RouteCommitHopV1 {
            vault_id: vault_id.to_vec(),
            token_in: hop_token_in,
            token_out: hop_token_out,
            input_amount_u128: u128::from(input_amount).to_be_bytes().to_vec(),
            expected_output_amount_u128: u128::from(simulated).to_be_bytes().to_vec(),
            fee_bps: FEE_BPS,
            advertisement_digest: vec![0u8; 32],
            unlock_spec_digest: vec![0u8; 32],
            owner_public_key: Vec::new(),
            parent_binding: parent_binding.to_vec(),
        };
        let rc = generated::RouteCommitV1 {
            version: crate::sdk::route_commit_sdk::ROUTE_COMMIT_VERSION,
            nonce: nonce_seed.to_vec(),
            input_token: TOKEN_A.to_vec(),
            output_token: TOKEN_B.to_vec(),
            input_amount_u128: u128::from(input_amount).to_be_bytes().to_vec(),
            expected_final_output_amount_u128: u128::from(simulated).to_be_bytes().to_vec(),
            total_fee_bps: FEE_BPS as u64,
            hops: vec![hop],
            initiator_public_key: trader_pk.to_vec(),
            initiator_signature: Vec::new(),
        };
        let canonical_bytes = rc.encode_to_vec();
        let sig = dsm::crypto::sphincs::sphincs_sign(trader_sk, &canonical_bytes)
            .expect("sign route commit");
        let mut signed_rc = rc;
        signed_rc.initiator_signature = sig;
        let x = crate::sdk::route_commit_sdk::compute_external_commitment(&signed_rc);
        let rc_key = crate::sdk::route_commit_sdk::external_commitment_rc_key(&x);
        BitcoinTapSdk::storage_put_bytes(&rc_key, &signed_rc.encode_to_vec())
            .await
            .expect("signed RC publish");
        (new_a, new_b, x)
    }

    fn settled_trade(
        x: &[u8; 32],
        parent_seq: u64,
        input_is_a: bool,
        input_amount: u64,
        output_amount: u64,
    ) -> SettledTrade {
        let (in_pc, out_pc) = if input_is_a {
            (TOKEN_A, TOKEN_B)
        } else {
            (TOKEN_B, TOKEN_A)
        };
        SettledTrade {
            x: *x,
            parent_sequence: parent_seq,
            new_sequence: parent_seq + 1,
            input_policy_commit: in_pc,
            input_amount,
            output_policy_commit: out_pc,
            output_amount,
        }
    }

    /// Publish a receipt witnessing `trade` — the artifact that makes a pointer
    /// consumable. Builds a real SMT containing the receipt leaf, so the
    /// inclusion path is genuine rather than stubbed: these tests must fail if
    /// the verifier stops checking it.
    async fn publish_receipt(
        vault_id: &[u8; 32],
        trade: &SettledTrade,
        trader_pk: &[u8],
        trader_sk: &[u8],
    ) {
        let (genesis, devid) = ([0xA0u8; 32], [0xB0u8; 32]);
        let receipt_id = derive_receipt_id(vault_id, &trade.x);
        let key = settlement_receipt_key(&genesis, &devid, vault_id, &receipt_id);
        let mut tree = dsm::merkle::sparse_merkle_tree::SparseMerkleTree::new(64);
        tree.update_leaf(&key, &settlement_receipt_value(trade))
            .expect("update_leaf");
        let root = *tree.root();
        let sibs = tree.get_inclusion_proof(&key, 256).expect("proof").siblings;
        let receipt = sign_trader_settlement_receipt(
            vault_id,
            &receipt_id,
            *trade,
            &genesis,
            &devid,
            &root,
            sibs,
            trader_pk,
            trader_sk,
        )
        .expect("sign receipt");
        crate::sdk::settlement_receipt_codec::publish_settlement_receipt(&receipt)
            .await
            .expect("publish receipt");
    }

    #[allow(clippy::too_many_arguments)]
    async fn publish_pointer(
        vault_id: &[u8; 32],
        parent_seq: u64,
        new_seq: u64,
        x: &[u8; 32],
        trade: &SettledTrade,
        publisher_pk: &[u8],
        publisher_sk: &[u8],
    ) {
        let receipt_id = derive_receipt_id(vault_id, x);
        let expected_receipt_hash = receipt_commitment(vault_id, &receipt_id, trade);
        let marker = [0x5Au8; 32];
        let signed = sign_vault_pending_pointer(
            vault_id,
            parent_seq,
            new_seq,
            x,
            &marker,
            &expected_receipt_hash,
            publisher_pk,
            publisher_sk,
        )
        .expect("sign pointer");
        let proto = generated::VaultPendingPointerV1 {
            vault_id: signed.vault_id.to_vec(),
            parent_sequence: signed.parent_sequence,
            new_sequence: signed.new_sequence,
            x: signed.x.to_vec(),
            new_reserves_digest: signed.new_reserves_digest.to_vec(),
            expected_receipt_hash: signed.expected_receipt_hash.to_vec(),
            publisher_public_key: signed.publisher_public_key,
            publisher_signature: signed.publisher_signature,
        };
        let key = crate::sdk::route_commit_sdk::vault_pending_pointer_key(vault_id, new_seq, x);
        BitcoinTapSdk::storage_put_bytes(&key, &proto.encode_to_vec())
            .await
            .expect("publish pointer");
    }

    fn trader() -> (Vec<u8>, Vec<u8>) {
        let kp = generate_keypair(SphincsVariant::SPX256f).expect("keypair");
        (kp.public_key.clone(), kp.secret_key.clone())
    }

    /// One settled trade end-to-end: X anchor, signed RC bound to
    /// `parent_binding`, pointer, and a matching receipt. Returns the
    /// post-trade reserves.
    #[allow(clippy::too_many_arguments)]
    async fn publish_settled_trade(
        vault_id: &[u8; 32],
        nonce_seed: &[u8; 32],
        parent_reserve_a: u64,
        parent_reserve_b: u64,
        parent_sequence: u64,
        parent_binding: &[u8; 32],
        input_is_a: bool,
        input_amount: u64,
    ) -> (u64, u64) {
        let (pk, sk) = trader();
        let (new_a, new_b, x) = publish_rc_for_swap(
            nonce_seed,
            vault_id,
            parent_reserve_a,
            parent_reserve_b,
            parent_binding,
            input_is_a,
            input_amount,
            &pk,
            &sk,
        )
        .await;
        publish_extcommit(&x, &pk).await;
        let output = if input_is_a {
            parent_reserve_b - new_b
        } else {
            parent_reserve_a - new_a
        };
        let trade = settled_trade(&x, parent_sequence, input_is_a, input_amount, output);
        publish_receipt(vault_id, &trade, &pk, &sk).await;
        // THE EDGE. Publishing evidence no longer makes a successor exist —
        // the network must have serialized this generation to this claimant.
        win_slot(vault_id, parent_sequence, &x, parent_binding, &pk, &sk).await;
        (new_a, new_b)
    }

    /// THE FRONTIER, and the only way to reach one: q attributed members of
    /// the vault's own committed set each answer that the settlement-slot cell
    /// at this generation holds nothing.
    #[tokio::test]
    async fn an_empty_slot_cell_at_quorum_is_the_frontier() {
        let _fleet = fleet();
        let vault_id = vid(0x01);
        let (presentation, ccb, state, c0) = baseline_fixture(vault_id, 1_000_000, 500_000);
        let composed =
            compose_vault_state(&vault_id, &presentation, &ccb, &TOKEN_A, &TOKEN_B, FEE_BPS)
                .await
                .expect("composes");
        assert_eq!(composed.sequence, 0);
        assert_eq!(composed.reserves_a, 1_000_000);
        assert_eq!(composed.reserves_b, 500_000);
        assert_eq!(composed.c_n, c0);
        assert_eq!(composed.state, state);
        assert_eq!(composed.pending_chain_len, 0);
        assert_eq!(
            composed.storage_set_id,
            dsm::ccb::storage_set_id(&state.storage_set).expect("set id")
        );
        assert_eq!(composed.owner_devid, state.owner_device_id);
        assert_eq!(composed.owner_genesis, state.owner_genesis_id);
    }

    /// THE OMISSION MUTATION — the control this whole cut exists for.
    ///
    /// Under the old prefix-listing fold, a member that simply did not return
    /// a key produced a SHORT CHAIN that was reported as the composed state,
    /// indistinguishable from a genuinely shorter one. Here two of three
    /// members go silent, so fewer than the committed `q = 2` give an
    /// attributed answer, and the walk refuses instead of reporting the
    /// baseline as a frontier.
    #[tokio::test]
    async fn a_short_quorum_on_the_cell_is_not_a_frontier() {
        let _fleet = fleet();
        let vault_id = vid(0x0D);
        let (presentation, ccb, _state, _c0) = baseline_fixture(vault_id, 1_000_000, 500_000);
        crate::sdk::storage_io::fake_fleet::fail_member("dsm-node-2");
        crate::sdk::storage_io::fake_fleet::fail_member("dsm-node-3");

        let err = compose_vault_state(&vault_id, &presentation, &ccb, &TOKEN_A, &TOKEN_B, FEE_BPS)
            .await
            .expect_err("a short quorum establishes nothing");
        let CompositionError::BindingEvidenceUnavailable(detail) = err else {
            panic!("expected DLV_BINDING_EVIDENCE_UNAVAILABLE, got {err:?}");
        };
        assert!(
            detail.contains("attributed member"),
            "the refusal names the counting failure: {detail}"
        );

        // Positive control: heal the members and the SAME vault composes to a
        // frontier, so the refusal above is the quorum rule and not a broken
        // fixture.
        crate::sdk::storage_io::fake_fleet::heal_member("dsm-node-2");
        crate::sdk::storage_io::fake_fleet::heal_member("dsm-node-3");
        let composed =
            compose_vault_state(&vault_id, &presentation, &ccb, &TOKEN_A, &TOKEN_B, FEE_BPS)
                .await
                .expect("composes once the members answer");
        assert_eq!(composed.sequence, 0);
    }

    /// Req 15.8 counting: a member whose response echoes SOMEONE ELSE'S id is
    /// uncountable. Two members answering, one of them impersonating the
    /// other, is one attributed answer — below `q`.
    #[tokio::test]
    async fn a_member_echoing_another_id_is_uncountable() {
        let _fleet = fleet();
        let vault_id = vid(0x0E);
        let (presentation, ccb, _state, _c0) = baseline_fixture(vault_id, 1_000_000, 500_000);
        crate::sdk::storage_io::fake_fleet::fail_member("dsm-node-3");
        crate::sdk::storage_io::fake_fleet::set_echo("dsm-node-2", Some("dsm-node-1"));

        let err = compose_vault_state(&vault_id, &presentation, &ccb, &TOKEN_A, &TOKEN_B, FEE_BPS)
            .await
            .expect_err("an impersonated echo cannot be counted");
        assert!(matches!(
            err,
            CompositionError::BindingEvidenceUnavailable(_)
        ));

        // Positive control: the SAME two members, honestly attributed, reach q.
        crate::sdk::storage_io::fake_fleet::set_echo("dsm-node-2", Some("dsm-node-2"));
        compose_vault_state(&vault_id, &presentation, &ccb, &TOKEN_A, &TOKEN_B, FEE_BPS)
            .await
            .expect("composes when both answers are attributable");
    }

    /// Members holding DIFFERENT values for one write-once cell is a network
    /// fault, never something to pick a side of.
    #[tokio::test]
    async fn a_divergent_write_once_cell_fails_closed() {
        let _fleet = fleet();
        let vault_id = vid(0x0F);
        let (presentation, ccb, _state, c0) = baseline_fixture(vault_id, 1_000_000, 500_000);
        let (pk1, sk1) = trader();
        let (pk2, sk2) = trader();
        // One claimant lands on node-1 only; a different one on node-2 only.
        crate::sdk::storage_io::fake_fleet::fail_member("dsm-node-2");
        crate::sdk::storage_io::fake_fleet::fail_member("dsm-node-3");
        win_slot(&vault_id, 0, &x_seed(0x1A), &c0, &pk1, &sk1).await;
        crate::sdk::storage_io::fake_fleet::heal_member("dsm-node-2");
        crate::sdk::storage_io::fake_fleet::fail_member("dsm-node-1");
        win_slot(&vault_id, 0, &x_seed(0x1B), &c0, &pk2, &sk2).await;
        crate::sdk::storage_io::fake_fleet::heal_member("dsm-node-1");
        crate::sdk::storage_io::fake_fleet::heal_member("dsm-node-3");

        let err = compose_vault_state(&vault_id, &presentation, &ccb, &TOKEN_A, &TOKEN_B, FEE_BPS)
            .await
            .expect_err("a divergent cell is not a frontier and not an edge");
        assert!(matches!(
            err,
            CompositionError::BindingEvidenceUnavailable(_)
        ));
    }

    /// The presentation authenticates a state; handing the composer the bytes
    /// of a DIFFERENT state must refuse — the anchor's commitment does not
    /// match the bytes.
    #[tokio::test]
    async fn bytes_of_a_different_state_are_refused() {
        let _fleet = fleet();
        let vault_id = vid(0x02);
        let (presentation, _ccb, _state, _c0) = baseline_fixture(vault_id, 1_000_000, 500_000);
        let (_p2, other_ccb, _s2, _c2) = baseline_fixture(vault_id, 999, 999);
        let err = compose_vault_state(
            &vault_id,
            &presentation,
            &other_ccb,
            &TOKEN_A,
            &TOKEN_B,
            FEE_BPS,
        )
        .await
        .expect_err("must refuse");
        assert!(matches!(
            err,
            CompositionError::InvalidBaselinePresentation(_)
        ));
    }

    /// A caller tuple that disagrees with the signed state (wrong fee) is a
    /// baseline mismatch, not something to quote around.
    #[tokio::test]
    async fn a_caller_tuple_disagreeing_with_the_signed_state_is_refused() {
        let _fleet = fleet();
        let vault_id = vid(0x03);
        let (presentation, ccb, _state, _c0) = baseline_fixture(vault_id, 1_000_000, 500_000);
        let err = compose_vault_state(
            &vault_id,
            &presentation,
            &ccb,
            &TOKEN_A,
            &TOKEN_B,
            FEE_BPS + 1,
        )
        .await
        .expect_err("must refuse");
        assert!(matches!(err, CompositionError::BaselineMismatch(_)));

        let wrong_pair = compose_vault_state(
            &vault_id,
            &presentation,
            &ccb,
            &[0x33u8; 32],
            &[0x44u8; 32],
            FEE_BPS,
        )
        .await
        .expect_err("must refuse");
        assert!(matches!(wrong_pair, CompositionError::BaselineMismatch(_)));
    }

    /// Composing under a different vault id than the state names is refused.
    #[tokio::test]
    async fn a_presentation_for_another_vault_is_refused() {
        let _fleet = fleet();
        let vault_id = vid(0x04);
        let (presentation, ccb, _state, _c0) = baseline_fixture(vault_id, 1_000_000, 500_000);
        let other = vid(0x05);
        let err = compose_vault_state(&other, &presentation, &ccb, &TOKEN_A, &TOKEN_B, FEE_BPS)
            .await
            .expect_err("must refuse");
        assert!(matches!(err, CompositionError::BaselineMismatch(_)));
    }

    /// A claimed AND settled generation folds: the generation advances by one,
    /// the reserves move by exactly the simulated swap, and the successor's
    /// predecessor edge is the baseline's identity — the c_n chain is real.
    #[tokio::test]
    async fn a_claimed_and_settled_generation_folds_and_advances_the_chain() {
        let _fleet = fleet();
        let vault_id = vid(0x06);
        let (presentation, ccb, state, c0) = baseline_fixture(vault_id, 1_000_000, 500_000);
        let (new_a, new_b) = publish_settled_trade(
            &vault_id,
            &x_seed(0x06),
            1_000_000,
            500_000,
            0,
            &c0,
            true,
            10_000,
        )
        .await;

        let composed =
            compose_vault_state(&vault_id, &presentation, &ccb, &TOKEN_A, &TOKEN_B, FEE_BPS)
                .await
                .expect("composes");
        assert_eq!(composed.pending_chain_len, 1);
        assert_eq!(composed.sequence, 1);
        assert_eq!(composed.reserves_a, new_a);
        assert_eq!(composed.reserves_b, new_b);
        // The successor is a real V_n: parent edge = c_0, identity recomputes.
        assert_eq!(composed.state.parent_state_commitment, c0);
        assert_eq!(
            composed.c_n,
            vault_state_commitment(&composed.state).expect("c_1")
        );
        assert_ne!(composed.c_n, c0);
        // Everything not moved by the trade is copied byte-for-byte.
        assert_eq!(
            composed.state.owner_authority_transition_digest,
            state.owner_authority_transition_digest
        );
        assert_eq!(composed.state.storage_set, state.storage_set);
        assert_eq!(composed.state.quorum, state.quorum);
    }

    /// THE OWNER'S RULING (2026-08-29), pinned.
    ///
    /// A quorum-established slot winner whose settlement receipt is missing is
    /// NOT a frontier. The network has already said this generation has a
    /// claimed successor; reporting it as the end of the chain because a
    /// second artifact is absent would make the cell walk decorative. It
    /// fails closed, and an adversary who wins a slot and never settles holds
    /// the vault here — an accepted liveness cost, never permission to
    /// manufacture maximality.
    #[tokio::test]
    async fn a_claimed_generation_without_its_receipt_fails_closed() {
        let _fleet = fleet();
        let vault_id = vid(0x07);
        let (presentation, ccb, _state, c0) = baseline_fixture(vault_id, 1_000_000, 500_000);
        let (pk, sk) = trader();
        let (_na, _nb, x) = publish_rc_for_swap(
            &x_seed(0x07),
            &vault_id,
            1_000_000,
            500_000,
            &c0,
            true,
            10_000,
            &pk,
            &sk,
        )
        .await;
        publish_extcommit(&x, &pk).await;
        // Slot won, RC published and valid — but NO receipt was ever written.
        win_slot(&vault_id, 0, &x, &c0, &pk, &sk).await;

        let err = compose_vault_state(&vault_id, &presentation, &ccb, &TOKEN_A, &TOKEN_B, FEE_BPS)
            .await
            .expect_err("a claimed successor without evidence is not a frontier");
        let CompositionError::BindingEvidenceUnavailable(detail) = err else {
            panic!("expected DLV_BINDING_EVIDENCE_UNAVAILABLE, got {err:?}");
        };
        assert!(
            detail.contains("receipt"),
            "the refusal names the missing evidence: {detail}"
        );
    }

    /// A pointer creates no edge. Under the cell walk a self-signed pointer
    /// from an arbitrary keypair is not consulted at all, so the griefing case
    /// the old fold had to reason about carefully cannot even be expressed:
    /// the cell is empty, and the vault is fully quotable.
    #[tokio::test]
    async fn a_forged_pointer_creates_no_edge_and_cannot_suppress_liquidity() {
        let _fleet = fleet();
        let vault_id = vid(0x0C);
        let (presentation, ccb, state, c0) = baseline_fixture(vault_id, 1_000_000, 500_000);
        let (attacker_pk, attacker_sk) = trader();
        let x = x_seed(0x0C);
        let fake_trade = settled_trade(&x, 0, true, 1, 1);
        publish_pointer(&vault_id, 0, 1, &x, &fake_trade, &attacker_pk, &attacker_sk).await;

        let composed =
            compose_vault_state(&vault_id, &presentation, &ccb, &TOKEN_A, &TOKEN_B, FEE_BPS)
                .await
                .expect("composes");
        assert_eq!(composed.pending_chain_len, 0);
        assert_eq!(composed.sequence, 0);
        assert_eq!(
            composed.state, state,
            "one arbitrary-keypair storage write must not change what any verifier composes"
        );
        assert_eq!(composed.c_n, c0);
    }

    /// A slot winner that binds a parent state OTHER than the cursor's `c_n`
    /// means the network and this verifier disagree about what the generation
    /// IS. Fail closed — never fold past it, never call it a frontier.
    #[tokio::test]
    async fn a_winner_binding_a_different_parent_state_fails_closed() {
        let _fleet = fleet();
        let vault_id = vid(0x10);
        let (presentation, ccb, _state, c0) = baseline_fixture(vault_id, 1_000_000, 500_000);
        let stale = [0xEEu8; 32];
        assert_ne!(stale, c0);
        let (pk, sk) = trader();
        win_slot(&vault_id, 0, &x_seed(0x10), &stale, &pk, &sk).await;

        let err = compose_vault_state(&vault_id, &presentation, &ccb, &TOKEN_A, &TOKEN_B, FEE_BPS)
            .await
            .expect_err("a winner bound elsewhere is a divergence");
        let CompositionError::BindingEvidenceUnavailable(detail) = err else {
            panic!("expected DLV_BINDING_EVIDENCE_UNAVAILABLE, got {err:?}");
        };
        assert!(
            detail.contains("different parent state"),
            "the refusal names the binding: {detail}"
        );
    }

    /// A hop bound to a parent that is NOT the cursor's `c_n` was signed
    /// against a different state. The slot binds correctly, so the walk
    /// reaches the RouteCommit — and refuses there rather than folding.
    #[tokio::test]
    async fn a_hop_bound_to_a_stale_parent_fails_closed() {
        let _fleet = fleet();
        let vault_id = vid(0x08);
        let (presentation, ccb, _state, c0) = baseline_fixture(vault_id, 1_000_000, 500_000);
        let stale_binding = [0xEEu8; 32];
        assert_ne!(stale_binding, c0);
        let (pk, sk) = trader();
        let (_na, _nb, x) = publish_rc_for_swap(
            &x_seed(0x08),
            &vault_id,
            1_000_000,
            500_000,
            &stale_binding,
            true,
            10_000,
            &pk,
            &sk,
        )
        .await;
        publish_extcommit(&x, &pk).await;
        let out = crate::sdk::routing_path_sdk::constant_product_output(
            10_000, 1_000_000, 500_000, FEE_BPS,
        )
        .expect("sim");
        let trade = settled_trade(&x, 0, true, 10_000, out);
        publish_receipt(&vault_id, &trade, &pk, &sk).await;
        // The SLOT binds the true parent; only the hop is stale.
        win_slot(&vault_id, 0, &x, &c0, &pk, &sk).await;

        let err = compose_vault_state(&vault_id, &presentation, &ccb, &TOKEN_A, &TOKEN_B, FEE_BPS)
            .await
            .expect_err("a stale hop binding cannot fold");
        let CompositionError::BindingEvidenceUnavailable(detail) = err else {
            panic!("expected DLV_BINDING_EVIDENCE_UNAVAILABLE, got {err:?}");
        };
        assert!(
            detail.contains("bound to a different parent state"),
            "the refusal names the hop binding: {detail}"
        );
    }

    /// A receipt that witnesses a DIFFERENT trade than the claimed one cannot
    /// activate the edge.
    #[tokio::test]
    async fn a_receipt_for_a_different_generation_fails_closed() {
        let _fleet = fleet();
        let vault_id = vid(0x09);
        let (presentation, ccb, _state, c0) = baseline_fixture(vault_id, 1_000_000, 500_000);
        let (pk, sk) = trader();
        let (_na, _nb, x) = publish_rc_for_swap(
            &x_seed(0x09),
            &vault_id,
            1_000_000,
            500_000,
            &c0,
            true,
            10_000,
            &pk,
            &sk,
        )
        .await;
        publish_extcommit(&x, &pk).await;
        // The receipt witnesses a step from generation 5, not from 0.
        let witnessed = settled_trade(&x, 5, true, 10, 3);
        publish_receipt(&vault_id, &witnessed, &pk, &sk).await;
        win_slot(&vault_id, 0, &x, &c0, &pk, &sk).await;

        let err = compose_vault_state(&vault_id, &presentation, &ccb, &TOKEN_A, &TOKEN_B, FEE_BPS)
            .await
            .expect_err("a receipt for another step cannot activate this edge");
        let CompositionError::BindingEvidenceUnavailable(detail) = err else {
            panic!("expected DLV_BINDING_EVIDENCE_UNAVAILABLE, got {err:?}");
        };
        assert!(
            detail.contains("different generation step"),
            "the refusal names the step: {detail}"
        );
    }

    /// Two settled generations chain: c_0 → c_1 → c_2, each successor binding
    /// the previous identity, the second slot claimed at generation 1 and its
    /// hop bound to c_1 (not c_0), and the walk terminating on the empty cell
    /// at generation 2.
    #[tokio::test]
    async fn two_settled_generations_chain_by_commitment() {
        let _fleet = fleet();
        let vault_id = vid(0x0A);
        let (presentation, ccb, state0, c0) = baseline_fixture(vault_id, 1_000_000, 500_000);
        let (a1, b1) = publish_settled_trade(
            &vault_id,
            &x_seed(0x0A),
            1_000_000,
            500_000,
            0,
            &c0,
            true,
            10_000,
        )
        .await;
        // Recompute c_1 exactly as the walk will.
        let mut s1 = state0.clone();
        s1.generation = 1;
        s1.reserve_a = a1;
        s1.reserve_b = b1;
        s1.parent_state_commitment = c0;
        let c1 = vault_state_commitment(&s1).expect("c_1");
        let (a2, b2) =
            publish_settled_trade(&vault_id, &x_seed(0x0B), a1, b1, 1, &c1, false, 7_000).await;

        let composed =
            compose_vault_state(&vault_id, &presentation, &ccb, &TOKEN_A, &TOKEN_B, FEE_BPS)
                .await
                .expect("composes");
        assert_eq!(composed.pending_chain_len, 2);
        assert_eq!(composed.sequence, 2);
        assert_eq!(composed.reserves_a, a2);
        assert_eq!(composed.reserves_b, b2);
        assert_eq!(composed.state.parent_state_commitment, c1);
        assert_eq!(
            composed.c_n,
            vault_state_commitment(&composed.state).expect("c_2")
        );
    }
}
