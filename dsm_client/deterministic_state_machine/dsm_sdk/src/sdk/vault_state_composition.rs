// SPDX-License-Identifier: MIT OR Apache-2.0
//! Phase 6: vault-state composition for SoFi quote-time correctness.
//!
//! Background
//! ----------
//! SoFi spec §2.3 + §4.1 specify that once a valid σ (stitched proof of
//! completion) exists on storage, the unlock is computable by anyone and
//! "settlement executes deterministically".  In particular this implies
//! that the **next trader** quoting against a vault should derive the
//! vault's canonical current state from:
//!
//!   1. The latest owner-signed `VaultStateAnchorV1` (the baseline)
//!   2. PLUS any pending `VaultPendingPointerV1` records published since
//!      the baseline that chain forward by one sequence step
//!
//! Without this composition, traders see only the latest owner-published
//! anchor.  If the owner is offline between trades, concurrent traders
//! all build against the stale anchor and Tripwire prunes all but one of
//! them — the owner becomes a continuous-throughput bottleneck.
//!
//! What this module does
//! ---------------------
//! `compose_vault_state` takes a vault id + owner-signed baseline anchor
//! + the canonical (token_a, token_b, fee_bps) tuple. It:
//!
//! - Lists `sofi/vault-pending/{vault_id_b32}/` (lex-ordered by `new_sequence`)
//! - For each pointer: verifies the SPHINCS+ signature; fetches
//!   `sofi/extcommit/{x_b32}` to confirm the X anchor is published;
//!   fetches `sofi/extcommit-rc/{x_b32}` to obtain the signed RouteCommit;
//!   locates the hop touching this vault, verifies the hop's bound
//!   reserves digest matches the cursor, and re-simulates the AMM swap
//!   to advance both the sequence AND the reserves
//! - Stops at first pointer that fails any check, or at
//!   `MAX_PENDING_CHAIN_DEPTH`, or when a sequence gap is detected
//! - Returns the composed state (sequence + composed reserves)
//!
//! Reserve folding
//! ---------------
//! The composer walks each pointer in sequence order and applies the
//! AMM swap embedded in the corresponding signed RouteCommit (fetched
//! from `sofi/extcommit-rc/{X_b32}`).  Concretely, for each pointer:
//!
//! - Look up the hop in the RouteCommit whose `vault_id` matches.
//! - Verify the hop's `vault_state_reserves_digest` equals the cursor's
//!   current reserves digest (this is the cryptographic link between
//!   pointer and cursor state).
//! - Re-simulate `constant_product_output(input, reserve_in, reserve_out,
//!   fee_bps)` against the cursor.  The simulated output must equal the
//!   hop's claimed `expected_output_amount`; if it doesn't the pointer
//!   was signed against a different baseline and folding it is unsafe.
//! - Advance the cursor's reserves (`+input` on the input side, `-output`
//!   on the output side) and bump the sequence.
//!
//! The result is a derived state where both `sequence` AND `reserves`
//! reflect everything published so far, not just the owner-signed
//! baseline.  Path search consumes this composed view, so concurrent
//! traders quoting against the same vault while the owner is offline
//! see each other's pending trades and serialize on top of them
//! instead of all colliding against the stale anchor.

use dsm::dlv::vault_pending_pointer::{verify_vault_pending_pointer, SignedVaultPendingPointer};
use dsm::dlv::vault_state_anchor::{
    compute_reserves_digest, verify_vault_state_anchor, SignedVaultStateAnchor,
};
use dsm::types::proto as generated;
use prost::Message;

use crate::sdk::bitcoin_tap_sdk::BitcoinTapSdk;
use crate::sdk::route_commit_sdk::{
    compute_external_commitment, external_commitment_rc_key,
    verify_route_commit_unlock_eligibility, vault_pending_prefix,
};
use crate::sdk::routing_path_sdk::constant_product_output;

/// Maximum pending-chain depth a composer will fold before treating the
/// vault as saturated and excluding it from path search.  Caps adversarial
/// pointer-flooding cost at O(MAX_PENDING_CHAIN_DEPTH) signature verifies
/// per quote.
pub(crate) const MAX_PENDING_CHAIN_DEPTH: usize = 64;

/// Result of composing pending pointers onto an owner-signed baseline.
#[derive(Debug, Clone)]
pub(crate) struct ComposedVaultState {
    /// Latest sequence number the composer was able to verify.  This is
    /// the baseline's sequence when no valid pointers were folded; the
    /// last successfully-folded pointer's `new_sequence` otherwise.
    pub sequence: u64,
    /// Composed reserves after applying every successfully-folded
    /// pending pointer's AMM swap.  Path search consumes these for
    /// quote-time AMM math; the chunks-#7 gate verifies against the
    /// vault's local DLVManager at unlock time so the chain is
    /// authoritative for the actual settlement.
    pub reserves_a: u64,
    pub reserves_b: u64,
    /// Number of pending pointers successfully verified + chained.
    pub pending_chain_len: usize,
    /// Number of pending pointers skipped (signature invalid, X missing,
    /// out-of-sequence, beyond MAX_PENDING_CHAIN_DEPTH).  Useful for
    /// telemetry / regression tests.
    pub pending_chain_skipped: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CompositionError {
    /// Baseline anchor's SPHINCS+ signature failed verification.  Fail
    /// closed — without a valid baseline the entire composition is moot.
    InvalidBaselineAnchor,
    /// SoFi spec §4.1.2 / §8.4 step 2: a vault state inclusion proof
    /// was published for this vault BUT the proof's signature, SMT
    /// inclusion path, OR (vault_id, sequence, reserves_digest) tuple
    /// disagrees with the baseline anchor.  Fail closed — either the
    /// owner equivocated or someone tampered with one of the two
    /// records; both possibilities make the vault unsafe to quote.
    InvalidInclusionProof,
    /// SoFi spec §4.1.2 strict mode: NO inclusion proof was published
    /// for this vault.  The vault may pre-date the Phase-7 SMT flow
    /// (legacy advertisement) OR the owner has not yet republished
    /// after the upgrade.  Either way, strict-mode composition refuses
    /// to fold it — the trader cannot prove the vault state is in the
    /// owner's PD-SMT, which is what the spec demands.
    MissingInclusionProof,
    /// Storage listing the pending prefix failed.
    StorageListFailed(String),
    /// Decoding a pointer proto failed in a non-recoverable way.  The
    /// individual pointer is skipped; this variant fires only if the
    /// whole list page failed.
    PointerDecodeFailed(String),
    /// No verified `VaultReserveInclusionProofV1` exists for the baseline
    /// sequence. The vault's liquidity is therefore unproven, and a quote
    /// against unproven liquidity is a quote against a number.
    ///
    /// The owner's signed reserves digest is NOT a substitute: it is one-way, so
    /// checking it can only confirm that numbers someone already supplied hash
    /// to what the owner signed. The owner signing a digest of its own claim
    /// establishes authorship, not solvency.
    MissingReserveProof,
    /// A reserve proof exists but does not agree with the vault-state inclusion
    /// proof on `(vault_id, sequence, smt_root)`, or its own verification fails.
    /// Either the owner equivocated or a record was tampered with; a vault that
    /// can show reserves at one state and vault-state at another could show
    /// funded reserves beside a drained state.
    InvalidReserveProof,
    /// The vault names its pair by label rather than by 32-byte policy commits,
    /// so a proven reserve leg cannot be matched to a side of the pair.
    ///
    /// FAILS CLOSED. Guessing the mapping would defeat the proof: the whole
    /// point is that the magnitudes come out of authenticated leaves keyed by
    /// asset identity, and a label is not an identity — this session had two
    /// distinct tokens sharing the ticker RIGB.
    PairIsNotPolicyCommits,
}

impl std::fmt::Display for CompositionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CompositionError::InvalidBaselineAnchor => {
                write!(f, "baseline anchor signature invalid")
            }
            CompositionError::InvalidInclusionProof => {
                write!(f, "vault state inclusion proof failed verification")
            }
            CompositionError::MissingInclusionProof => {
                write!(
                    f,
                    "vault has no published VaultStateInclusionProofV1 — strict mode requires one (SoFi §4.1.2)"
                )
            }
            CompositionError::StorageListFailed(msg) => {
                write!(f, "storage list failed: {msg}")
            }
            CompositionError::PointerDecodeFailed(msg) => {
                write!(f, "pointer decode failed: {msg}")
            }
            CompositionError::MissingReserveProof => write!(
                f,
                "vault has no verified VaultReserveInclusionProofV1 at its baseline sequence — its liquidity is unproven"
            ),
            CompositionError::InvalidReserveProof => write!(
                f,
                "reserve proof disagrees with the vault-state inclusion proof, or failed verification"
            ),
            CompositionError::PairIsNotPolicyCommits => write!(
                f,
                "vault pair must be 32-byte policy commits so proven reserve legs can be matched to a side"
            ),
        }
    }
}

impl std::error::Error for CompositionError {}

/// Fold pending pointers onto an owner-signed baseline.
///
/// `baseline` is the latest `VaultStateAnchorV1` the owner has published
/// (typically fetched via `dlv.getVaultStateAnchor` or via the routing
/// advertisement's `state_number`).  Its signature is re-verified here
/// — fail-closed if the baseline itself is broken.
///
/// `baseline_reserves` are the (reserve_a, reserve_b) values committed
/// in the baseline's `reserves_digest`.  Caller supplies them because
/// the digest is one-way (verification re-derives + compares, but the
/// composer needs the magnitudes to compute the running cursor).
///
/// Returns the composed `(sequence, reserves_a, reserves_b)` plus
/// telemetry (`pending_chain_len` / `pending_chain_skipped`) so the
/// path search handler can log progress and drop saturated vaults
/// from the candidate set.
pub(crate) async fn compose_vault_state(
    vault_id: &[u8; 32],
    baseline: &SignedVaultStateAnchor,
    token_a: &[u8],
    token_b: &[u8],
    fee_bps: u32,
) -> Result<ComposedVaultState, CompositionError> {
    // Verify the baseline anchor's signature.  No further composition
    // is meaningful without this.
    verify_vault_state_anchor(baseline).map_err(|_| CompositionError::InvalidBaselineAnchor)?;

    // SoFi spec §4.1.2 / §8.4 step 2 — STRICT MODE.  Verify the
    // owner's PD-SMT inclusion proof for the baseline vault state.
    // The anchor signature above is *necessary* but not *sufficient*:
    // an attacker who recovered the signing key could forge a signed anchor.
    // The inclusion proof additionally commits the SMT root + a
    // 256-sibling Merkle path that
    // dsm::dlv::vault_smt_leaf::verify_vault_smt_inclusion recomputes
    // against the device's actual SMT — forgery requires also
    // fabricating SMT consistency, which a stateless attacker cannot.
    //
    // Strict mode: a vault with no published inclusion proof is
    // dropped from the candidate set.  This is the documented Phase-7
    // migration behaviour — legacy ads pre-dating this code do not
    // pass.
    let inclusion = crate::sdk::vault_smt_inclusion_codec::fetch_latest_inclusion_proof(vault_id)
        .await
        .map_err(|e| CompositionError::StorageListFailed(format!("inclusion fetch: {e}")))?;
    let inclusion = match inclusion {
        Some(p) => p,
        None => return Err(CompositionError::MissingInclusionProof),
    };
    // Cross-bind the inclusion proof to the baseline: same
    // (vault_id, sequence, reserves_digest) tuple.  If they disagree,
    // the owner equivocated and the vault is unsafe.
    if inclusion.vault_id != baseline.vault_id
        || inclusion.sequence != baseline.sequence
        || inclusion.reserves_digest != baseline.reserves_digest
    {
        return Err(CompositionError::InvalidInclusionProof);
    }
    // Verify the inclusion proof end-to-end (signature + SMT path).
    dsm::dlv::vault_smt_leaf::verify_vault_state_inclusion_proof(&inclusion)
        .map_err(|_| CompositionError::InvalidInclusionProof)?;

    // GATE 1 — the reserves are PROVEN, not supplied.
    //
    // This function used to take the baseline reserves as arguments and check
    // them against the owner's signed digest. A digest is one-way, so that check
    // could only confirm that numbers the caller already held hash to the value
    // the owner signed: whoever chose the numbers chose what the vault appeared
    // to hold, and in production they came straight out of a published
    // advertisement. The magnitudes now come OUT of an authenticated proof.
    let reserve_proof = crate::sdk::vault_reserve_proof_codec::fetch_verified_reserve_proof(
        vault_id,
        baseline.sequence,
    )
    .await
    .ok_or(CompositionError::MissingReserveProof)?;

    // Bind it to the state proof. Reserve leaves carry the VAULT's own sequence
    // rather than a per-leaf counter precisely so both proofs meet at one root;
    // an owner able to present reserves at one state and vault-state at another
    // could show funded reserves beside a later, drained state.
    if reserve_proof.smt_root != inclusion.smt_root
        || reserve_proof.sequence != inclusion.sequence
        || reserve_proof.vault_id != inclusion.vault_id
    {
        return Err(CompositionError::InvalidReserveProof);
    }

    // Match proven legs to the sides of the pair. A leg is keyed by 32-byte
    // policy commit, so a vault naming its pair by label cannot be matched and
    // fails closed rather than being guessed at.
    // Through the ONE pair parser, so the identity a vault was funded under, the
    // identity a pointer commits to, and the identity a quote is bound to are
    // derived by the same code and cannot disagree.
    let Ok(pair) = dsm::dlv::pair_identity::CanonicalPair::parse(token_a, token_b) else {
        return Err(CompositionError::PairIsNotPolicyCommits);
    };
    let (pc_a, pc_b) = (pair.a(), pair.b());
    let (Some(proven_a), Some(proven_b)) = (
        dsm::dlv::vault_reserve_inclusion::proven_amount(&reserve_proof, &pc_a),
        dsm::dlv::vault_reserve_inclusion::proven_amount(&reserve_proof, &pc_b),
    ) else {
        // A proof that omits a side has not shown that side holds nothing — it
        // has shown nothing about it. Treating an absent leg as zero would let a
        // half-funded vault quote as if it were empty on one side.
        return Err(CompositionError::InvalidReserveProof);
    };
    let baseline_reserves = (proven_a, proven_b);

    // The owner's signed digest must agree with what its own leaves prove. Both
    // are the owner's, so disagreement means the two records were produced from
    // different states — the vault is not safe to quote either way.
    let expected_digest = compute_reserves_digest(
        token_a,
        token_b,
        baseline_reserves.0,
        baseline_reserves.1,
        fee_bps,
    );
    if expected_digest != baseline.reserves_digest {
        return Err(CompositionError::InvalidReserveProof);
    }

    let prefix = vault_pending_prefix(vault_id);
    let mut cursor: Option<String> = None;
    const LIST_LIMIT: u32 = 256;

    let mut pointers: Vec<SignedVaultPendingPointer> = Vec::new();
    loop {
        let resp = BitcoinTapSdk::storage_list_objects(&prefix, cursor.as_deref(), LIST_LIMIT)
            .await
            .map_err(|e| CompositionError::StorageListFailed(format!("{e}")))?;
        for item in &resp.items {
            let bytes = match BitcoinTapSdk::storage_get_bytes(&item.key).await {
                Ok(b) => b,
                Err(e) => {
                    log::debug!(
                        "[compose_vault_state] skipping {}: fetch failed: {e}",
                        item.key,
                    );
                    continue;
                }
            };
            let proto = match generated::VaultPendingPointerV1::decode(bytes.as_slice()) {
                Ok(p) => p,
                Err(e) => {
                    log::debug!(
                        "[compose_vault_state] skipping {}: decode failed: {e}",
                        item.key,
                    );
                    continue;
                }
            };
            // Convert proto → typed struct for verification.
            if proto.vault_id.len() != 32
                || proto.x.len() != 32
                || proto.new_reserves_digest.len() != 32
                || proto.expected_receipt_hash.len() != 32
            {
                // A pointer with no well-formed receipt commitment names no
                // receipt, so nothing could ever activate it. Drop it here
                // rather than carrying a zero-filled commitment forward, which
                // would be a commitment some receipt might accidentally match.
                continue;
            }
            let mut vid_arr = [0u8; 32];
            vid_arr.copy_from_slice(&proto.vault_id);
            let mut x_arr = [0u8; 32];
            x_arr.copy_from_slice(&proto.x);
            let mut digest_arr = [0u8; 32];
            digest_arr.copy_from_slice(&proto.new_reserves_digest);
            let mut receipt_commit_arr = [0u8; 32];
            receipt_commit_arr.copy_from_slice(&proto.expected_receipt_hash);
            // Confirm the pointer references the vault we're composing.
            // (Storage prefix should already filter this, but defensive
            // re-check costs nothing.)
            if vid_arr != *vault_id {
                continue;
            }
            pointers.push(SignedVaultPendingPointer {
                vault_id: vid_arr,
                parent_sequence: proto.parent_sequence,
                new_sequence: proto.new_sequence,
                x: x_arr,
                new_reserves_digest: digest_arr,
                expected_receipt_hash: receipt_commit_arr,
                publisher_public_key: proto.publisher_public_key,
                publisher_signature: proto.publisher_signature,
            });
        }
        if (resp.items.len() as u32) < LIST_LIMIT {
            break;
        }
        cursor = resp.next_cursor;
        if cursor.is_none() {
            break;
        }
    }

    // Sort by new_sequence ascending so chain folding is deterministic.
    pointers.sort_by(|a, b| a.new_sequence.cmp(&b.new_sequence).then(a.x.cmp(&b.x)));

    // Fold pointers onto the baseline.  Full Phase-6 fold-rule:
    //   - Pointer's parent_sequence must equal the running cursor.
    //   - Pointer's signature must verify.
    //   - The X it references must actually exist on storage (so we
    //     never advance the cursor against a pointer for a non-published
    //     trade).
    //   - The signed RouteCommit at defi/extcommit-rc/{x_b32} must be
    //     present + decode + carry a hop touching this vault.
    //   - The hop's vault_state_reserves_digest (the digest the trader
    //     signed against) must match the running cursor's reserves +
    //     fee_bps — this ties the pointer to the cursor's actual state.
    //   - The AMM swap math against the cursor's reserves must succeed.
    //   - Up to MAX_PENDING_CHAIN_DEPTH folds total.
    //
    // Both sequence AND reserves advance.  This is the load-bearing
    // step that makes "math speaks for itself" observable: the
    // composer derives the canonical current state from published
    // proofs, not from the owner's (possibly stale) signed anchor.
    let mut cursor_seq = baseline.sequence;
    let mut cursor_reserve_a = baseline_reserves.0;
    let mut cursor_reserve_b = baseline_reserves.1;
    let mut chain_len: usize = 0;
    let mut chain_skipped: usize = 0;
    for ptr in pointers.into_iter() {
        if chain_len >= MAX_PENDING_CHAIN_DEPTH {
            chain_skipped += 1;
            continue;
        }
        if ptr.parent_sequence != cursor_seq {
            chain_skipped += 1;
            continue;
        }
        if verify_vault_pending_pointer(&ptr).is_err() {
            chain_skipped += 1;
            continue;
        }
        // THE RECEIPT GATE. Everything below this line moves someone's
        // liquidity, so nothing below it runs until the settlement is witnessed.
        //
        // Every other check in this fold describes an INTENT: the pointer is
        // signed, X is published, the RouteCommit is valid, the AMM math is
        // exact. A trader who publishes all of that and then simply never
        // advances has paid nothing and taken nothing — yet under the old rule
        // the vault's quotable liquidity dropped for every other trader,
        // indefinitely, for the price of one storage write. Free griefing.
        //
        // The receipt is the only artifact here that cannot be produced without
        // settling: it carries an inclusion path for a leaf that the trader's
        // own settling advance wrote into its own device root.
        //
        // Both halves are required. `fetch_verified_receipt` establishes that
        // SOME settlement really committed; the commitment comparison
        // establishes it is THIS pointer's settlement, so a pointer for a large
        // trade cannot be activated by a receipt for a tiny one.
        let receipt =
            match crate::sdk::settlement_receipt_codec::fetch_verified_receipt(vault_id, &ptr.x)
                .await
            {
                Some(r) => r,
                None => {
                    // INERT, not invalid. The pointer may be perfectly well-formed
                    // and its settlement may land a moment from now. Skipping leaves
                    // effective reserves exactly as if it had never been published,
                    // which is the whole point.
                    chain_skipped += 1;
                    continue;
                }
            };
        if dsm::dlv::settlement_receipt_leaf::receipt_commitment_of(&receipt)
            != ptr.expected_receipt_hash
        {
            chain_skipped += 1;
            continue;
        }
        // The receipt must also describe the step this pointer claims. The
        // commitment already covers the sequence pair, so this cannot disagree
        // silently — but checking it here means the fold reads as one rule
        // rather than relying on a hash to have covered it.
        if receipt.trade.parent_sequence != ptr.parent_sequence
            || receipt.trade.new_sequence != ptr.new_sequence
        {
            chain_skipped += 1;
            continue;
        }
        // Fetch the full signed RouteCommit paired with X.
        let rc_key = external_commitment_rc_key(&ptr.x);
        let rc_bytes = match BitcoinTapSdk::storage_get_bytes(&rc_key).await {
            Ok(b) => b,
            Err(_) => {
                // RC not yet published (publisher crashed between X and
                // RC writes, or publisher used the legacy bare-anchor
                // path).  Cannot fold reserves without the RC; skip.
                chain_skipped += 1;
                continue;
            }
        };
        let rc = match generated::RouteCommitV1::decode(rc_bytes.as_slice()) {
            Ok(r) => r,
            Err(_) => {
                chain_skipped += 1;
                continue;
            }
        };
        // Bind pointer.x to the canonical RouteCommit commitment.
        // Storage keys are untrusted labels, so we MUST recompute X
        // from RouteCommit bytes and require exact equality.
        let computed_x = compute_external_commitment(&rc);
        if computed_x != ptr.x {
            chain_skipped += 1;
            continue;
        }
        // Enforce routed-unlock eligibility gate:
        //   1) initiator SPHINCS+ signature valid over canonical RC bytes
        //   2) this vault is present in the route
        //   3) external commitment anchor for X is visible
        let hop = match verify_route_commit_unlock_eligibility(&rc_bytes, vault_id).await {
            Ok(h) => h,
            Err(_) => {
                chain_skipped += 1;
                continue;
            }
        };
        // Verify the hop's bound reserves_digest matches the cursor's
        // current reserves.  If it doesn't, this pointer's RC was
        // signed against a different parent state and folding it would
        // diverge from the canonical chain — skip.  Note: this is the
        // cryptographic link between pointer and cursor.
        let cursor_digest = compute_reserves_digest(
            token_a,
            token_b,
            cursor_reserve_a,
            cursor_reserve_b,
            fee_bps,
        );
        if !hop.vault_state_reserves_digest.is_empty()
            && hop.vault_state_reserves_digest.as_slice() != cursor_digest.as_slice()
        {
            chain_skipped += 1;
            continue;
        }
        // Decode the hop's input/output amounts.
        if hop.input_amount_u128.len() != 16 || hop.expected_output_amount_u128.len() != 16 {
            chain_skipped += 1;
            continue;
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
            chain_skipped += 1;
            continue;
        };
        // Determine trade direction against the lex-canonical vault pair.
        let input_is_a = hop.token_in.as_slice() == token_a && hop.token_out.as_slice() == token_b;
        let input_is_b = hop.token_in.as_slice() == token_b && hop.token_out.as_slice() == token_a;
        if !input_is_a && !input_is_b {
            chain_skipped += 1;
            continue;
        }
        let (cursor_in, cursor_out) = if input_is_a {
            (cursor_reserve_a, cursor_reserve_b)
        } else {
            (cursor_reserve_b, cursor_reserve_a)
        };
        // Re-simulate against the cursor.  The composer demands the
        // simulated output equals the trader's claimed expected_output
        // — anything else means the trade settled against a different
        // baseline and folding it is unsafe.
        let simulated = match constant_product_output(input_amount, cursor_in, cursor_out, fee_bps)
        {
            Some(v) => v,
            None => {
                chain_skipped += 1;
                continue;
            }
        };
        if simulated != expected_output {
            chain_skipped += 1;
            continue;
        }
        // Apply the swap to the cursor.  Saturating-sub on the output
        // side defends against malformed RCs that claim more than the
        // allocation can pay; the re-sim above should already exclude these,
        // but defense-in-depth is cheap.
        let (new_a, new_b) = if input_is_a {
            (
                cursor_reserve_a.saturating_add(input_amount),
                cursor_reserve_b.saturating_sub(expected_output),
            )
        } else {
            (
                cursor_reserve_a.saturating_sub(expected_output),
                cursor_reserve_b.saturating_add(input_amount),
            )
        };
        cursor_reserve_a = new_a;
        cursor_reserve_b = new_b;
        cursor_seq = ptr.new_sequence;
        chain_len += 1;
    }

    Ok(ComposedVaultState {
        sequence: cursor_seq,
        reserves_a: cursor_reserve_a,
        reserves_b: cursor_reserve_b,
        pending_chain_len: chain_len,
        pending_chain_skipped: chain_skipped,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use dsm::crypto::sphincs::{generate_keypair, SphincsVariant};

    /// The pair, as 32-byte policy commits. Labels are no longer admissible:
    /// a proven reserve leg is keyed by asset identity, and a ticker is not one
    /// — this repo has had two distinct tokens sharing the ticker RIGB.
    /// TOKEN_A is lex-lower, matching the canonical pair order.
    const TOKEN_A: [u8; 32] = [0x11; 32];
    const TOKEN_B: [u8; 32] = [0x22; 32];
    /// Owner identity the reserve leaves are keyed under.
    const OWNER_GENESIS: [u8; 32] = [0xA0; 32];
    const OWNER_DEVID: [u8; 32] = [0xB0; 32];
    use dsm::dlv::settlement_receipt_leaf::{
        derive_receipt_id, receipt_commitment, settlement_receipt_key, settlement_receipt_value,
        sign_trader_settlement_receipt, SettledTrade,
    };
    use dsm::dlv::vault_pending_pointer::sign_vault_pending_pointer;
    use dsm::dlv::vault_state_anchor::sign_vault_state_anchor;

    /// Sign-only baseline anchor.  Used by negative tests that want
    /// to deliberately skip the inclusion-proof publish (so strict
    /// mode rejects the vault).
    #[allow(clippy::too_many_arguments)]
    fn make_baseline_anchor_only(
        vault_id: &[u8; 32],
        seq: u64,
        token_a: &[u8],
        token_b: &[u8],
        reserve_a: u64,
        reserve_b: u64,
        fee_bps: u32,
        owner_pk: &[u8],
        owner_sk: &[u8],
    ) -> SignedVaultStateAnchor {
        let digest = compute_reserves_digest(token_a, token_b, reserve_a, reserve_b, fee_bps);
        sign_vault_state_anchor(vault_id, seq, &digest, owner_pk, owner_sk).expect("sign anchor")
    }

    /// Phase-7 strict-mode-compatible baseline: sign the anchor AND
    /// publish a matching `VaultStateInclusionProofV1` so
    /// `compose_vault_state` sees a verifiable PD-SMT witness.  Most
    /// composition tests use this — it's the production-equivalent
    /// path.
    #[allow(clippy::too_many_arguments)]
    async fn make_baseline(
        vault_id: &[u8; 32],
        seq: u64,
        token_a: &[u8],
        token_b: &[u8],
        reserve_a: u64,
        reserve_b: u64,
        fee_bps: u32,
        owner_pk: &[u8],
        owner_sk: &[u8],
    ) -> SignedVaultStateAnchor {
        let anchor = make_baseline_anchor_only(
            vault_id, seq, token_a, token_b, reserve_a, reserve_b, fee_bps, owner_pk, owner_sk,
        );
        publish_baseline_inclusion_proof(
            vault_id, seq, token_a, token_b, reserve_a, reserve_b, fee_bps, owner_pk, owner_sk,
        )
        .await;
        anchor
    }

    /// Phase 7 test helper: publish a real
    /// `VaultStateInclusionProofV1` for the baseline `(vault_id,
    /// sequence, reserves_digest)` so strict-mode composition accepts
    /// it.  Mirrors what `publish_vault_state_inclusion_proof` does on
    /// the live `dlv.create` path, but driven from test code by
    /// building a fresh SMT and signing with the supplied owner key.
    #[allow(clippy::too_many_arguments)]
    async fn publish_baseline_inclusion_proof(
        vault_id: &[u8; 32],
        sequence: u64,
        token_a: &[u8],
        token_b: &[u8],
        reserve_a: u64,
        reserve_b: u64,
        fee_bps: u32,
        owner_pk: &[u8],
        owner_sk: &[u8],
    ) {
        use dsm::dlv::vault_reserve_inclusion::{sign_vault_reserve_inclusion_proof, ReserveLegProof};
        use dsm::dlv::vault_reserve_leaf::{vault_reserve_key, vault_reserve_value};
        use dsm::dlv::vault_smt_leaf::{
            compute_vault_smt_key, compute_vault_smt_value, sign_vault_state_inclusion_proof,
        };
        use dsm::merkle::sparse_merkle_tree::SparseMerkleTree;

        let reserves_digest =
            compute_reserves_digest(token_a, token_b, reserve_a, reserve_b, fee_bps);

        // ONE tree carrying the vault-state leaf AND both reserve leaves, which
        // is what a real owner's device SMT looks like. Two separate trees would
        // produce two roots, and the composer requires the state proof and the
        // reserve proof to meet at one — a fixture that could not satisfy that
        // would be testing a shape production never produces.
        let mut tree = SparseMerkleTree::new(64);
        let leaf_key = compute_vault_smt_key(vault_id);
        let leaf_value = compute_vault_smt_value(sequence, &reserves_digest);
        tree.update_leaf(&leaf_key, &leaf_value)
            .expect("update_leaf");

        let pair: [(&[u8], u64); 2] = [(token_a, reserve_a), (token_b, reserve_b)];
        for (token, amount) in pair {
            let pc = <[u8; 32]>::try_from(token).expect("pair must be policy commits");
            tree.update_leaf(
                &vault_reserve_key(&OWNER_GENESIS, &OWNER_DEVID, vault_id, &pc),
                &vault_reserve_value(amount, sequence),
            )
            .expect("reserve leaf");
        }

        let smt_root = *tree.root();
        let proof = tree.get_inclusion_proof(&leaf_key, 256).expect("proof");

        let signed = sign_vault_state_inclusion_proof(
            vault_id,
            sequence,
            &reserves_digest,
            &smt_root,
            proof.siblings,
            owner_pk,
            owner_sk,
        )
        .expect("sign inclusion proof");

        let proto_bytes =
            crate::sdk::vault_smt_inclusion_codec::encode_inclusion_proof_to_proto(&signed);
        crate::sdk::vault_smt_inclusion_codec::publish_inclusion_proof(
            vault_id,
            sequence,
            &proto_bytes,
        )
        .await
        .expect("publish inclusion proof");

        // The reserve proof, against the SAME root and sequence.
        let mut legs: Vec<ReserveLegProof> = pair
            .iter()
            .map(|(token, amount)| {
                let pc = <[u8; 32]>::try_from(*token).expect("pair must be policy commits");
                ReserveLegProof {
                    policy_commit: pc,
                    amount: *amount,
                    smt_siblings: tree
                        .get_inclusion_proof(
                            &vault_reserve_key(&OWNER_GENESIS, &OWNER_DEVID, vault_id, &pc),
                            256,
                        )
                        .expect("reserve proof")
                        .siblings,
                }
            })
            .collect();
        legs.sort_by(|a, b| a.policy_commit.cmp(&b.policy_commit));
        let reserve_proof = sign_vault_reserve_inclusion_proof(
            vault_id,
            sequence,
            &smt_root,
            &OWNER_GENESIS,
            &OWNER_DEVID,
            legs,
            owner_pk,
            owner_sk,
        )
        .expect("sign reserve proof");
        crate::sdk::vault_reserve_proof_codec::publish_reserve_proof(&reserve_proof)
            .await
            .expect("publish reserve proof");
    }

    fn marker_digest(x: &[u8; 32], hop_index: u32) -> [u8; 32] {
        use blake3::Hasher;
        let mut h = Hasher::new();
        h.update(b"DSM/pending-marker\0");
        h.update(x);
        h.update(&hop_index.to_le_bytes());
        *h.finalize().as_bytes()
    }

    fn vid_seed(b: u8) -> [u8; 32] {
        let mut v = [0u8; 32];
        v[0] = b;
        v[31] = b.wrapping_mul(13).wrapping_add(7);
        v
    }

    fn x_seed(b: u8) -> [u8; 32] {
        let mut v = [0u8; 32];
        v[0] = 0xEC;
        v[1] = b;
        v[31] = b.wrapping_mul(31).wrapping_add(11);
        v
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

    /// Publish a `RouteCommitV1` with a single AMM hop touching
    /// `vault_id` at `sofi/extcommit-rc/{X_b32}`.  Returns the swap's
    /// post-trade reserves plus the canonical commitment `X` so callers
    /// can publish matching anchors/pointers.  The hop's
    /// `vault_state_reserves_digest` is bound
    /// to the supplied parent reserves so the composer's
    /// cursor-vs-hop digest check passes.
    #[allow(clippy::too_many_arguments)]
    async fn publish_rc_for_swap(
        nonce_seed: &[u8; 32],
        vault_id: &[u8; 32],
        token_a: &[u8],
        token_b: &[u8],
        parent_reserve_a: u64,
        parent_reserve_b: u64,
        fee_bps: u32,
        parent_sequence: u64,
        input_is_a: bool,
        input_amount: u64,
        trader_pk: &[u8],
        trader_sk: &[u8],
    ) -> (u64, u64, [u8; 32]) {
        // Reserves cursor logic mirrors compose_vault_state.
        let (reserve_in, reserve_out) = if input_is_a {
            (parent_reserve_a, parent_reserve_b)
        } else {
            (parent_reserve_b, parent_reserve_a)
        };
        let simulated = crate::sdk::routing_path_sdk::constant_product_output(
            input_amount,
            reserve_in,
            reserve_out,
            fee_bps,
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

        // Digest the parent reserves so the composer's cursor digest
        // matches this hop's bound digest.
        let parent_digest = compute_reserves_digest(
            token_a,
            token_b,
            parent_reserve_a,
            parent_reserve_b,
            fee_bps,
        );

        let (hop_token_in, hop_token_out) = if input_is_a {
            (token_a.to_vec(), token_b.to_vec())
        } else {
            (token_b.to_vec(), token_a.to_vec())
        };
        let hop = generated::RouteCommitHopV1 {
            vault_id: vault_id.to_vec(),
            token_in: hop_token_in,
            token_out: hop_token_out,
            input_amount_u128: u128::from(input_amount).to_be_bytes().to_vec(),
            expected_output_amount_u128: u128::from(simulated).to_be_bytes().to_vec(),
            fee_bps,
            advertisement_digest: vec![0u8; 32],
            state_number: parent_sequence,
            unlock_spec_digest: vec![0u8; 32],
            owner_public_key: Vec::new(),
            vault_state_anchor_seq: parent_sequence,
            vault_state_reserves_digest: parent_digest.to_vec(),
            vault_state_anchor_digest: vec![0u8; 32],
        };
        let rc = generated::RouteCommitV1 {
            version: crate::sdk::route_commit_sdk::ROUTE_COMMIT_VERSION,
            nonce: nonce_seed.to_vec(),
            input_token: token_a.to_vec(),
            output_token: token_b.to_vec(),
            input_amount_u128: u128::from(input_amount).to_be_bytes().to_vec(),
            expected_final_output_amount_u128: u128::from(simulated).to_be_bytes().to_vec(),
            total_fee_bps: fee_bps as u64,
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

    /// Deterministic 32-byte stand-in for a token's policy commit. These
    /// fixtures name their pair by label (`&TOKEN_A`); a settled trade is stated
    /// in policy commits, so the two are bridged here rather than in production
    /// code.
    fn pc_of(label: &[u8]) -> [u8; 32] {
        *blake3::hash(label).as_bytes()
    }

    fn settled_trade(
        x: &[u8; 32],
        parent_seq: u64,
        input_policy_commit: &[u8; 32],
        input_amount: u64,
        output_policy_commit: &[u8; 32],
        output_amount: u64,
    ) -> SettledTrade {
        SettledTrade {
            x: *x,
            parent_sequence: parent_seq,
            new_sequence: parent_seq + 1,
            input_policy_commit: *input_policy_commit,
            input_amount,
            output_policy_commit: *output_policy_commit,
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
    /// Publish a standalone reserve proof at `sequence` proving `(a, b)`, under
    /// a root of its own. Used to state a reserve proof that disagrees with what
    /// the owner signed.
    /// Publish only the vault-state inclusion proof, withholding the reserve
    /// proof — the "state known, holdings unproven" case.
    async fn publish_state_inclusion_proof_only(
        vault_id: &[u8; 32],
        sequence: u64,
        reserve_a: u64,
        reserve_b: u64,
        owner_pk: &[u8],
        owner_sk: &[u8],
    ) {
        use dsm::dlv::vault_smt_leaf::{
            compute_vault_smt_key, compute_vault_smt_value, sign_vault_state_inclusion_proof,
        };
        use dsm::merkle::sparse_merkle_tree::SparseMerkleTree;

        let digest = compute_reserves_digest(&TOKEN_A, &TOKEN_B, reserve_a, reserve_b, 30);
        let mut tree = SparseMerkleTree::new(64);
        let key = compute_vault_smt_key(vault_id);
        tree.update_leaf(&key, &compute_vault_smt_value(sequence, &digest))
            .expect("state leaf");
        let root = *tree.root();
        let proof = tree.get_inclusion_proof(&key, 256).expect("proof");
        let signed = sign_vault_state_inclusion_proof(
            vault_id,
            sequence,
            &digest,
            &root,
            proof.siblings,
            owner_pk,
            owner_sk,
        )
        .expect("sign");
        let bytes = crate::sdk::vault_smt_inclusion_codec::encode_inclusion_proof_to_proto(&signed);
        crate::sdk::vault_smt_inclusion_codec::publish_inclusion_proof(vault_id, sequence, &bytes)
            .await
            .expect("publish");
    }

    /// A reserve proof that verifies against its OWN root but not the root the
    /// vault-state proof committed to.
    async fn publish_reserve_proof_with_foreign_root(
        vault_id: &[u8; 32],
        sequence: u64,
        reserve_a: u64,
        reserve_b: u64,
        owner_pk: &[u8],
        owner_sk: &[u8],
    ) {
        use dsm::dlv::vault_reserve_inclusion::{sign_vault_reserve_inclusion_proof, ReserveLegProof};
        use dsm::dlv::vault_reserve_leaf::{vault_reserve_key, vault_reserve_value};
        use dsm::merkle::sparse_merkle_tree::SparseMerkleTree;

        // No vault-state leaf in this tree, so its root differs from the one the
        // state proof binds while every leg still verifies internally.
        let mut tree = SparseMerkleTree::new(64);
        for (pc, amount) in [(TOKEN_A, reserve_a), (TOKEN_B, reserve_b)] {
            tree.update_leaf(
                &vault_reserve_key(&OWNER_GENESIS, &OWNER_DEVID, vault_id, &pc),
                &vault_reserve_value(amount, sequence),
            )
            .expect("reserve leaf");
        }
        let root = *tree.root();
        let mut legs: Vec<ReserveLegProof> = [(TOKEN_A, reserve_a), (TOKEN_B, reserve_b)]
            .iter()
            .map(|(pc, amount)| ReserveLegProof {
                policy_commit: *pc,
                amount: *amount,
                smt_siblings: tree
                    .get_inclusion_proof(
                        &vault_reserve_key(&OWNER_GENESIS, &OWNER_DEVID, vault_id, pc),
                        256,
                    )
                    .expect("proof")
                    .siblings,
            })
            .collect();
        legs.sort_by(|a, b| a.policy_commit.cmp(&b.policy_commit));
        let proof = sign_vault_reserve_inclusion_proof(
            vault_id,
            sequence,
            &root,
            &OWNER_GENESIS,
            &OWNER_DEVID,
            legs,
            owner_pk,
            owner_sk,
        )
        .expect("sign");
        crate::sdk::vault_reserve_proof_codec::publish_reserve_proof(&proof)
            .await
            .expect("publish");
    }

    async fn publish_reserve_proof_for(
        vault_id: &[u8; 32],
        sequence: u64,
        reserve_a: u64,
        reserve_b: u64,
        owner_pk: &[u8],
        owner_sk: &[u8],
    ) {
        use dsm::dlv::vault_reserve_inclusion::{sign_vault_reserve_inclusion_proof, ReserveLegProof};
        use dsm::dlv::vault_reserve_leaf::{vault_reserve_key, vault_reserve_value};
        use dsm::dlv::vault_smt_leaf::{compute_vault_smt_key, compute_vault_smt_value};
        use dsm::merkle::sparse_merkle_tree::SparseMerkleTree;

        // Include the vault-state leaf at the SAME digest the baseline was
        // signed over, so the root still matches the published state proof and
        // the ONLY disagreement under test is the reserve magnitudes.
        let digest = compute_reserves_digest(&TOKEN_A, &TOKEN_B, 1_000_000, 500_000, 30);
        let mut tree = SparseMerkleTree::new(64);
        tree.update_leaf(
            &compute_vault_smt_key(vault_id),
            &compute_vault_smt_value(sequence, &digest),
        )
        .expect("state leaf");
        for (pc, amount) in [(TOKEN_A, reserve_a), (TOKEN_B, reserve_b)] {
            tree.update_leaf(
                &vault_reserve_key(&OWNER_GENESIS, &OWNER_DEVID, vault_id, &pc),
                &vault_reserve_value(amount, sequence),
            )
            .expect("reserve leaf");
        }
        let root = *tree.root();
        let mut legs: Vec<ReserveLegProof> = [(TOKEN_A, reserve_a), (TOKEN_B, reserve_b)]
            .iter()
            .map(|(pc, amount)| ReserveLegProof {
                policy_commit: *pc,
                amount: *amount,
                smt_siblings: tree
                    .get_inclusion_proof(
                        &vault_reserve_key(&OWNER_GENESIS, &OWNER_DEVID, vault_id, pc),
                        256,
                    )
                    .expect("proof")
                    .siblings,
            })
            .collect();
        legs.sort_by(|a, b| a.policy_commit.cmp(&b.policy_commit));
        let proof = sign_vault_reserve_inclusion_proof(
            vault_id,
            sequence,
            &root,
            &OWNER_GENESIS,
            &OWNER_DEVID,
            legs,
            owner_pk,
            owner_sk,
        )
        .expect("sign");
        crate::sdk::vault_reserve_proof_codec::publish_reserve_proof(&proof)
            .await
            .expect("publish");
    }

    async fn publish_pointer(
        vault_id: &[u8; 32],
        parent_seq: u64,
        new_seq: u64,
        x: &[u8; 32],
        digest: &[u8; 32],
        trade: &SettledTrade,
        publisher_pk: &[u8],
        publisher_sk: &[u8],
    ) {
        let receipt_id = derive_receipt_id(vault_id, x);
        let expected_receipt_hash = receipt_commitment(vault_id, &receipt_id, trade);
        let signed = sign_vault_pending_pointer(
            vault_id,
            parent_seq,
            new_seq,
            x,
            digest,
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

    /// Combined helper that publishes the three storage records needed
    /// for one fold-able pending trade: X anchor, full RC, and the
    /// vault-keyed pointer.  Returns the swap's post-trade reserves.
    #[allow(clippy::too_many_arguments)]
    async fn publish_trade(
        vault_id: &[u8; 32],
        nonce_seed: &[u8; 32],
        token_a: &[u8],
        token_b: &[u8],
        parent_reserve_a: u64,
        parent_reserve_b: u64,
        fee_bps: u32,
        parent_sequence: u64,
        input_is_a: bool,
        input_amount: u64,
        trader_pk: &[u8],
        trader_sk: &[u8],
        with_receipt: bool,
    ) -> (u64, u64) {
        let (new_a, new_b, x) = publish_rc_for_swap(
            nonce_seed,
            vault_id,
            token_a,
            token_b,
            parent_reserve_a,
            parent_reserve_b,
            fee_bps,
            parent_sequence,
            input_is_a,
            input_amount,
            trader_pk,
            trader_sk,
        )
        .await;
        publish_extcommit(&x, trader_pk).await;
        let (input_pc, output_pc, output_amount) = if input_is_a {
            (&TOKEN_A, &TOKEN_B, parent_reserve_b - new_b)
        } else {
            (&TOKEN_B, &TOKEN_A, parent_reserve_a - new_a)
        };
        let trade = settled_trade(
            &x,
            parent_sequence,
            input_pc,
            input_amount,
            output_pc,
            output_amount,
        );
        publish_pointer(
            vault_id,
            parent_sequence,
            parent_sequence + 1,
            &x,
            &marker_digest(&x, 0),
            &trade,
            trader_pk,
            trader_sk,
        )
        .await;
        // A pointer alone is inert. Publishing the receipt is what makes this
        // trade fold — which is exactly what `publish_trade_without_receipt`
        // withholds.
        if with_receipt {
            publish_receipt(vault_id, &trade, trader_pk, trader_sk).await;
        }
        (new_a, new_b)
    }

    #[tokio::test]
    async fn composes_empty_chain_returns_baseline() {
        let vault_id = vid_seed(0x10);
        let owner = generate_keypair(SphincsVariant::SPX256f).expect("owner kp");
        let baseline = make_baseline(
            &vault_id,
            5,
            &TOKEN_A,
            &TOKEN_B,
            1_000_000,
            500_000,
            30,
            &owner.public_key,
            &owner.secret_key,
        )
        .await;
        let composed = compose_vault_state(&vault_id, &baseline, &TOKEN_A, &TOKEN_B, 30)
            .await
            .expect("compose succeeds");
        assert_eq!(composed.sequence, 5);
        assert_eq!(composed.reserves_a, 1_000_000);
        assert_eq!(composed.reserves_b, 500_000);
        assert_eq!(composed.pending_chain_len, 0);
        assert_eq!(composed.pending_chain_skipped, 0);
    }

    // ── the reserve-proof gate ─────────────────────────────────────────────
    //
    // The reserves a trader quotes against must come out of an authenticated
    // proof, not out of an argument or an advertisement.

    /// A vault whose owner published no reserve proof cannot be quoted, even
    /// with a perfectly good signed anchor and state inclusion proof.
    ///
    /// Those two establish WHICH state the vault is in; neither establishes what
    /// it HOLDS. Composing without the third would be quoting against a number.
    #[tokio::test]
    async fn a_vault_with_no_reserve_proof_cannot_be_quoted() {
        let vault_id = vid_seed(0x50);
        let owner = generate_keypair(SphincsVariant::SPX256f).expect("owner kp");
        // Anchor + state inclusion proof, deliberately without the reserve proof.
        let anchor = make_baseline_anchor_only(
            &vault_id,
            0,
            &TOKEN_A,
            &TOKEN_B,
            1_000_000,
            500_000,
            30,
            &owner.public_key,
            &owner.secret_key,
        );
        publish_state_inclusion_proof_only(
            &vault_id,
            0,
            1_000_000,
            500_000,
            &owner.public_key,
            &owner.secret_key,
        )
        .await;

        let err = compose_vault_state(&vault_id, &anchor, &TOKEN_A, &TOKEN_B, 30)
            .await
            .expect_err("unproven liquidity must not be quotable");
        assert!(matches!(err, CompositionError::MissingReserveProof));
    }

    /// A reserve proof for a DIFFERENT state must not be accepted for this one.
    ///
    /// Reserve leaves carry the vault's own sequence so both proofs meet at one
    /// root. Without that binding an owner could present funded reserves beside
    /// a later, drained vault state.
    #[tokio::test]
    async fn a_reserve_proof_from_another_state_is_refused() {
        let vault_id = vid_seed(0x51);
        let owner = generate_keypair(SphincsVariant::SPX256f).expect("owner kp");
        let baseline = make_baseline(
            &vault_id,
            0,
            &TOKEN_A,
            &TOKEN_B,
            1_000_000,
            500_000,
            30,
            &owner.public_key,
            &owner.secret_key,
        )
        .await;

        // Overwrite the sequence-0 proof with one whose root is its own, so the
        // amounts still verify internally but the root no longer matches the
        // state proof.
        publish_reserve_proof_for(
            &vault_id,
            0,
            1_000_000,
            500_000,
            &owner.public_key,
            &owner.secret_key,
        )
        .await;
        // That helper reproduces the same digest, so it must still compose —
        // this establishes the negative case below is about the ROOT, not the
        // amounts.
        compose_vault_state(&vault_id, &baseline, &TOKEN_A, &TOKEN_B, 30)
            .await
            .expect("a consistent re-publish still composes");

        // Now a proof carrying a foreign root.
        publish_reserve_proof_with_foreign_root(
            &vault_id,
            0,
            1_000_000,
            500_000,
            &owner.public_key,
            &owner.secret_key,
        )
        .await;
        let err = compose_vault_state(&vault_id, &baseline, &TOKEN_A, &TOKEN_B, 30)
            .await
            .expect_err("a reserve proof must meet the state proof at one root");
        assert!(matches!(err, CompositionError::InvalidReserveProof));
    }

    /// A vault naming its pair by label fails CLOSED. A proven leg is keyed by
    /// asset identity, and a ticker is not one — guessing the mapping would
    /// defeat the proof it is being matched against.
    #[tokio::test]
    async fn a_label_pair_cannot_be_matched_to_proven_legs() {
        let vault_id = vid_seed(0x52);
        let owner = generate_keypair(SphincsVariant::SPX256f).expect("owner kp");
        let baseline = make_baseline(
            &vault_id,
            0,
            &TOKEN_A,
            &TOKEN_B,
            1_000_000,
            500_000,
            30,
            &owner.public_key,
            &owner.secret_key,
        )
        .await;
        let err = compose_vault_state(&vault_id, &baseline, b"AAA", b"BBB", 30)
            .await
            .expect_err("a label pair must fail closed");
        assert!(matches!(err, CompositionError::PairIsNotPolicyCommits));
    }

    // ── the receipt gate ───────────────────────────────────────────────────
    //
    // A pending pointer is INERT until a verified settlement receipt binds it.
    // These are the tests that rule exists for.

    /// THE GRIEFING CASE, end to end.
    ///
    /// A trader publishes everything the old fold rule asked for — X, the signed
    /// RouteCommit, a valid pointer with exact AMM math — and then simply never
    /// advances its own chain. It has paid nothing and taken nothing. Under the
    /// old rule the vault's quotable liquidity dropped anyway, for every other
    /// trader, indefinitely, for the price of one storage write.
    ///
    /// Effective reserves must be byte-identical to a vault nobody ever pointed
    /// at. Not "close", not "eventually corrected" — identical.
    #[tokio::test]
    async fn an_abandoned_pointer_consumes_no_liquidity() {
        let vault_id = vid_seed(0x40);
        let owner = generate_keypair(SphincsVariant::SPX256f).expect("owner kp");
        let griefer = generate_keypair(SphincsVariant::SPX256f).expect("griefer kp");
        let baseline = make_baseline(
            &vault_id,
            0,
            &TOKEN_A,
            &TOKEN_B,
            1_000_000,
            500_000,
            30,
            &owner.public_key,
            &owner.secret_key,
        )
        .await;

        // Everything except the one artifact that requires actually settling.
        publish_trade(
            &vault_id,
            &x_seed(0x41),
            &TOKEN_A,
            &TOKEN_B,
            1_000_000,
            500_000,
            30,
            0,
            true,
            250_000, // a large bite, so a partial fold would be obvious
            &griefer.public_key,
            &griefer.secret_key,
            false, // no receipt: the advance never happened
        )
        .await;

        let composed = compose_vault_state(&vault_id, &baseline, &TOKEN_A, &TOKEN_B, 30)
            .await
            .expect("compose succeeds");

        assert_eq!(
            (composed.reserves_a, composed.reserves_b),
            (1_000_000, 500_000),
            "an unreceipted pointer must not move effective reserves"
        );
        assert_eq!(
            composed.sequence, 0,
            "nor advance the sequence past the owner's baseline"
        );
        assert_eq!(composed.pending_chain_len, 0, "nothing was folded");
        assert_eq!(
            composed.pending_chain_skipped, 1,
            "and the pointer was seen and deliberately skipped, not missed"
        );
    }

    /// The same trade, with and without its receipt. Everything else about the
    /// two runs is identical, so the receipt is provably the only thing that
    /// moves reserves — the assertion above cannot be passing because the fold
    /// broke for some unrelated reason.
    #[tokio::test]
    async fn the_receipt_is_the_only_difference_between_inert_and_folded() {
        async fn run(vault_seed: u8, x: u8, with_receipt: bool) -> ComposedVaultState {
            let vault_id = vid_seed(vault_seed);
            let owner = generate_keypair(SphincsVariant::SPX256f).expect("owner kp");
            let trader = generate_keypair(SphincsVariant::SPX256f).expect("trader kp");
            let baseline = make_baseline(
                &vault_id,
                0,
                &TOKEN_A,
                &TOKEN_B,
                1_000_000,
                500_000,
                30,
                &owner.public_key,
                &owner.secret_key,
            )
            .await;
            publish_trade(
                &vault_id,
                &x_seed(x),
                &TOKEN_A,
                &TOKEN_B,
                1_000_000,
                500_000,
                30,
                0,
                true,
                1_000,
                &trader.public_key,
                &trader.secret_key,
                with_receipt,
            )
            .await;
            compose_vault_state(&vault_id, &baseline, &TOKEN_A, &TOKEN_B, 30)
                .await
                .expect("compose succeeds")
        }

        let inert = run(0x42, 0x43, false).await;
        let folded = run(0x44, 0x45, true).await;

        assert_eq!((inert.reserves_a, inert.reserves_b), (1_000_000, 500_000));
        assert_eq!(inert.sequence, 0);
        assert!(
            folded.reserves_a > 1_000_000 && folded.reserves_b < 500_000,
            "the receipted run must actually move reserves, or this test proves nothing"
        );
        assert_eq!(folded.sequence, 1);
    }

    /// A receipt for a DIFFERENT trade must not activate this pointer.
    ///
    /// Without the commitment check a trader could publish a pointer taking
    /// 250,000 out of the vault and then satisfy it with a receipt for a
    /// one-unit settlement it was willing to actually pay for.
    #[tokio::test]
    async fn a_receipt_for_a_different_trade_leaves_the_pointer_inert() {
        let vault_id = vid_seed(0x46);
        let owner = generate_keypair(SphincsVariant::SPX256f).expect("owner kp");
        let trader = generate_keypair(SphincsVariant::SPX256f).expect("trader kp");
        let baseline = make_baseline(
            &vault_id,
            0,
            &TOKEN_A,
            &TOKEN_B,
            1_000_000,
            500_000,
            30,
            &owner.public_key,
            &owner.secret_key,
        )
        .await;
        let x = x_seed(0x47);
        publish_trade(
            &vault_id,
            &x,
            &TOKEN_A,
            &TOKEN_B,
            1_000_000,
            500_000,
            30,
            0,
            true,
            250_000,
            &trader.public_key,
            &trader.secret_key,
            false,
        )
        .await;

        // A perfectly valid receipt — signed, with a genuine inclusion path —
        // for a settlement that is not the one this pointer claims.
        let (_, _, canonical_x) = publish_rc_for_swap(
            &x,
            &vault_id,
            &TOKEN_A,
            &TOKEN_B,
            1_000_000,
            500_000,
            30,
            0,
            true,
            250_000,
            &trader.public_key,
            &trader.secret_key,
        )
        .await;
        let cheap = settled_trade(&canonical_x, 0, &TOKEN_A, 1, &TOKEN_B, 1);
        publish_receipt(&vault_id, &cheap, &trader.public_key, &trader.secret_key).await;

        let composed = compose_vault_state(&vault_id, &baseline, &TOKEN_A, &TOKEN_B, 30)
            .await
            .expect("compose succeeds");
        assert_eq!(
            (composed.reserves_a, composed.reserves_b),
            (1_000_000, 500_000),
            "a receipt for a cheaper trade must not satisfy this pointer"
        );
        assert_eq!(composed.pending_chain_len, 0);
    }

    /// Composing twice over the same receipted pointer yields the same state.
    ///
    /// The fold is what every quote runs, so a receipt that folded twice would
    /// let the vault drift further from the owner's actual reserves on every
    /// quote — with no attacker involved at all.
    #[tokio::test]
    async fn replaying_a_receipted_pointer_is_a_no_op() {
        let vault_id = vid_seed(0x48);
        let owner = generate_keypair(SphincsVariant::SPX256f).expect("owner kp");
        let trader = generate_keypair(SphincsVariant::SPX256f).expect("trader kp");
        let baseline = make_baseline(
            &vault_id,
            0,
            &TOKEN_A,
            &TOKEN_B,
            1_000_000,
            500_000,
            30,
            &owner.public_key,
            &owner.secret_key,
        )
        .await;
        publish_trade(
            &vault_id,
            &x_seed(0x49),
            &TOKEN_A,
            &TOKEN_B,
            1_000_000,
            500_000,
            30,
            0,
            true,
            1_000,
            &trader.public_key,
            &trader.secret_key,
            true,
        )
        .await;

        let first = compose_vault_state(&vault_id, &baseline, &TOKEN_A, &TOKEN_B, 30)
            .await
            .expect("compose succeeds");
        let second = compose_vault_state(&vault_id, &baseline, &TOKEN_A, &TOKEN_B, 30)
            .await
            .expect("compose succeeds");

        assert_eq!(first.sequence, second.sequence);
        assert_eq!(first.reserves_a, second.reserves_a);
        assert_eq!(first.reserves_b, second.reserves_b);
        assert_eq!(first.pending_chain_len, second.pending_chain_len);
        assert_eq!(
            first.sequence, 1,
            "and it folded exactly once, not zero times"
        );
    }

    /// A receipt that fails verification is worth exactly as much as no receipt.
    ///
    /// Publishing well-formed bytes under the right key is free; producing a
    /// valid inclusion path is not. This pins that the fold depends on the
    /// second, not the first.
    #[tokio::test]
    async fn a_receipt_with_a_broken_inclusion_path_leaves_the_pointer_inert() {
        let vault_id = vid_seed(0x4A);
        let owner = generate_keypair(SphincsVariant::SPX256f).expect("owner kp");
        let trader = generate_keypair(SphincsVariant::SPX256f).expect("trader kp");
        let baseline = make_baseline(
            &vault_id,
            0,
            &TOKEN_A,
            &TOKEN_B,
            1_000_000,
            500_000,
            30,
            &owner.public_key,
            &owner.secret_key,
        )
        .await;
        publish_trade(
            &vault_id,
            &x_seed(0x4B),
            &TOKEN_A,
            &TOKEN_B,
            1_000_000,
            500_000,
            30,
            0,
            true,
            1_000,
            &trader.public_key,
            &trader.secret_key,
            true,
        )
        .await;

        // Overwrite the good receipt with one whose path has been corrupted.
        let pointers_prefix = vault_pending_prefix(&vault_id);
        let listing = BitcoinTapSdk::storage_list_objects(&pointers_prefix, None, 16)
            .await
            .expect("list pointers");
        let ptr_bytes = BitcoinTapSdk::storage_get_bytes(&listing.items[0].key)
            .await
            .expect("fetch pointer");
        let ptr = generated::VaultPendingPointerV1::decode(ptr_bytes.as_slice()).expect("decode");
        let mut x = [0u8; 32];
        x.copy_from_slice(&ptr.x);

        let key = crate::sdk::settlement_receipt_codec::vault_receipt_key(&vault_id, &x);
        let good = BitcoinTapSdk::storage_get_bytes(&key)
            .await
            .expect("fetch receipt");
        let mut r = generated::TraderSettlementReceiptV1::decode(good.as_slice()).expect("decode");
        r.smt_siblings[0][0] ^= 0xff;
        BitcoinTapSdk::storage_put_bytes(&key, &r.encode_to_vec())
            .await
            .expect("overwrite receipt");

        let composed = compose_vault_state(&vault_id, &baseline, &TOKEN_A, &TOKEN_B, 30)
            .await
            .expect("compose succeeds");
        assert_eq!(
            (composed.reserves_a, composed.reserves_b),
            (1_000_000, 500_000),
            "a receipt whose inclusion path does not check must not consume liquidity"
        );
        assert_eq!(composed.pending_chain_len, 0);
    }

    #[tokio::test]
    async fn folds_single_valid_pointer_advances_sequence_and_reserves() {
        let vault_id = vid_seed(0x11);
        let owner = generate_keypair(SphincsVariant::SPX256f).expect("owner kp");
        let trader = generate_keypair(SphincsVariant::SPX256f).expect("trader kp");
        let baseline = make_baseline(
            &vault_id,
            0,
            &TOKEN_A,
            &TOKEN_B,
            1_000_000,
            500_000,
            30,
            &owner.public_key,
            &owner.secret_key,
        )
        .await;
        let x = x_seed(0x21);
        let (expected_a, expected_b) = publish_trade(
            &vault_id,
            &x,
            &TOKEN_A,
            &TOKEN_B,
            1_000_000,
            500_000,
            30,
            0,
            true, // input is A (1000 AAA → some BBB out)
            1_000,
            &trader.public_key,
            &trader.secret_key,
            true,
        )
        .await;

        let composed = compose_vault_state(&vault_id, &baseline, &TOKEN_A, &TOKEN_B, 30)
            .await
            .expect("compose succeeds");
        assert_eq!(composed.sequence, 1);
        assert_eq!(
            composed.reserves_a, expected_a,
            "reserve_a should grow by the trader's input"
        );
        assert_eq!(
            composed.reserves_b, expected_b,
            "reserve_b should shrink by the simulated output"
        );
        assert!(composed.reserves_a > 1_000_000);
        assert!(composed.reserves_b < 500_000);
        assert_eq!(composed.pending_chain_len, 1);
        assert_eq!(composed.pending_chain_skipped, 0);
    }

    #[tokio::test]
    async fn folds_chained_pointers_reserves_track_each_swap() {
        let vault_id = vid_seed(0x12);
        let owner = generate_keypair(SphincsVariant::SPX256f).expect("owner kp");
        let trader = generate_keypair(SphincsVariant::SPX256f).expect("trader kp");
        let baseline = make_baseline(
            &vault_id,
            0,
            &TOKEN_A,
            &TOKEN_B,
            1_000_000,
            500_000,
            30,
            &owner.public_key,
            &owner.secret_key,
        )
        .await;
        // Three sequential trades.  Each picks up where the previous
        // left off so the composer sees a coherent chain.
        let mut cur_a: u64 = 1_000_000;
        let mut cur_b: u64 = 500_000;
        let mut expected_final_a = cur_a;
        let mut expected_final_b = cur_b;
        for (parent_seq, seed_byte, input_is_a, input_amount) in [
            (0u64, 0x31u8, true, 1_000u64),
            (1, 0x32, false, 500),
            (2, 0x33, true, 2_000),
        ]
        .iter()
        {
            let x = x_seed(*seed_byte);
            let (new_a, new_b) = publish_trade(
                &vault_id,
                &x,
                &TOKEN_A,
                &TOKEN_B,
                cur_a,
                cur_b,
                30,
                *parent_seq,
                *input_is_a,
                *input_amount,
                &trader.public_key,
                &trader.secret_key,
                true,
            )
            .await;
            cur_a = new_a;
            cur_b = new_b;
            expected_final_a = new_a;
            expected_final_b = new_b;
        }
        let composed = compose_vault_state(&vault_id, &baseline, &TOKEN_A, &TOKEN_B, 30)
            .await
            .expect("compose succeeds");
        assert_eq!(composed.sequence, 3);
        assert_eq!(composed.reserves_a, expected_final_a);
        assert_eq!(composed.reserves_b, expected_final_b);
        assert_eq!(composed.pending_chain_len, 3);
        assert_eq!(composed.pending_chain_skipped, 0);
    }

    #[tokio::test]
    async fn skips_pointer_with_missing_x_anchor() {
        let vault_id = vid_seed(0x13);
        let owner = generate_keypair(SphincsVariant::SPX256f).expect("owner kp");
        let trader = generate_keypair(SphincsVariant::SPX256f).expect("trader kp");
        let baseline = make_baseline(
            &vault_id,
            0,
            &TOKEN_A,
            &TOKEN_B,
            1_000_000,
            500_000,
            30,
            &owner.public_key,
            &owner.secret_key,
        )
        .await;
        let x = x_seed(0x41);
        // Intentionally do NOT publish the X anchor (or the RC).
        publish_pointer(
            &vault_id,
            0,
            1,
            &x,
            &marker_digest(&x, 0),
            &settled_trade(&x, 0, &TOKEN_A, 1, &TOKEN_B, 1),
            &trader.public_key,
            &trader.secret_key,
        )
        .await;
        let composed = compose_vault_state(&vault_id, &baseline, &TOKEN_A, &TOKEN_B, 30)
            .await
            .expect("compose succeeds");
        assert_eq!(composed.sequence, 0, "cursor stays at baseline");
        assert_eq!(composed.reserves_a, 1_000_000);
        assert_eq!(composed.reserves_b, 500_000);
        assert_eq!(composed.pending_chain_len, 0);
        assert_eq!(composed.pending_chain_skipped, 1);
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn skips_pointer_when_rc_missing_even_if_x_present() {
        // Cross-version safety: a legacy publisher might write the X
        // anchor without the paired RC bytes.  The composer must skip
        // that pointer (it can't verify the swap math without the RC)
        // and report it as skipped, not silently advance the cursor.
        let vault_id = vid_seed(0x16);
        let owner = generate_keypair(SphincsVariant::SPX256f).expect("owner kp");
        let trader = generate_keypair(SphincsVariant::SPX256f).expect("trader kp");
        let baseline = make_baseline(
            &vault_id,
            0,
            &TOKEN_A,
            &TOKEN_B,
            1_000_000,
            500_000,
            30,
            &owner.public_key,
            &owner.secret_key,
        )
        .await;
        let x = x_seed(0x61);
        publish_extcommit(&x, &trader.public_key).await;
        // Skip the RC publish.
        publish_pointer(
            &vault_id,
            0,
            1,
            &x,
            &marker_digest(&x, 0),
            &settled_trade(&x, 0, &TOKEN_A, 1, &TOKEN_B, 1),
            &trader.public_key,
            &trader.secret_key,
        )
        .await;
        let composed = compose_vault_state(&vault_id, &baseline, &TOKEN_A, &TOKEN_B, 30)
            .await
            .expect("compose succeeds");
        assert_eq!(composed.sequence, 0);
        assert_eq!(composed.reserves_a, 1_000_000);
        assert_eq!(composed.reserves_b, 500_000);
        assert_eq!(composed.pending_chain_len, 0);
        assert_eq!(composed.pending_chain_skipped, 1);
    }

    #[tokio::test]
    async fn stops_at_sequence_gap_and_preserves_partial_reserve_advance() {
        let vault_id = vid_seed(0x14);
        let owner = generate_keypair(SphincsVariant::SPX256f).expect("owner kp");
        let trader = generate_keypair(SphincsVariant::SPX256f).expect("trader kp");
        let baseline = make_baseline(
            &vault_id,
            0,
            &TOKEN_A,
            &TOKEN_B,
            1_000_000,
            500_000,
            30,
            &owner.public_key,
            &owner.secret_key,
        )
        .await;
        // Publish seq=1 (chainable) and seq=3 (gap; parent=2 missing).
        // After folding, the cursor advances to seq=1 with reserves
        // reflecting that one trade and stops.
        let (after_first_a, after_first_b) = publish_trade(
            &vault_id,
            &x_seed(0x51),
            &TOKEN_A,
            &TOKEN_B,
            1_000_000,
            500_000,
            30,
            0,
            true,
            1_000,
            &trader.public_key,
            &trader.secret_key,
            true,
        )
        .await;
        // Orphan pointer at seq=3 (skips seq=2).
        let orphan_x = x_seed(0x53);
        publish_trade(
            &vault_id,
            &orphan_x,
            &TOKEN_A,
            &TOKEN_B,
            after_first_a,
            after_first_b,
            30,
            2, // parent=2, no preceding seq=2 trade
            true,
            500,
            &trader.public_key,
            &trader.secret_key,
            true,
        )
        .await;
        let composed = compose_vault_state(&vault_id, &baseline, &TOKEN_A, &TOKEN_B, 30)
            .await
            .expect("compose succeeds");
        assert_eq!(composed.sequence, 1, "advances through seq=1 then stops");
        assert_eq!(composed.reserves_a, after_first_a);
        assert_eq!(composed.reserves_b, after_first_b);
        assert_eq!(composed.pending_chain_len, 1);
        assert_eq!(composed.pending_chain_skipped, 1);
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn rejects_pointer_whose_rc_hop_baseline_disagrees_with_cursor() {
        // A trader publishes a RouteCommit whose hop's
        // vault_state_reserves_digest doesn't match the composer's
        // cursor (i.e., the trader signed against the wrong baseline).
        // The composer must reject — folding would diverge from the
        // canonical chain.
        let vault_id = vid_seed(0x17);
        let owner = generate_keypair(SphincsVariant::SPX256f).expect("owner kp");
        let trader = generate_keypair(SphincsVariant::SPX256f).expect("trader kp");
        let baseline = make_baseline(
            &vault_id,
            0,
            &TOKEN_A,
            &TOKEN_B,
            1_000_000,
            500_000,
            30,
            &owner.public_key,
            &owner.secret_key,
        )
        .await;
        let nonce_seed = x_seed(0x71);
        // Build the RC with WRONG parent reserves (777, 888 instead of
        // the real 1_000_000, 500_000).
        let (_, _, x) = publish_rc_for_swap(
            &nonce_seed,
            &vault_id,
            &TOKEN_A,
            &TOKEN_B,
            777, // wrong parent_reserve_a
            888, // wrong parent_reserve_b
            30,
            0,
            true,
            10,
            &trader.public_key,
            &trader.secret_key,
        )
        .await;
        publish_extcommit(&x, &trader.public_key).await;
        publish_pointer(
            &vault_id,
            0,
            1,
            &x,
            &marker_digest(&x, 0),
            &settled_trade(&x, 0, &TOKEN_A, 1, &TOKEN_B, 1),
            &trader.public_key,
            &trader.secret_key,
        )
        .await;
        let composed = compose_vault_state(&vault_id, &baseline, &TOKEN_A, &TOKEN_B, 30)
            .await
            .expect("compose succeeds");
        assert_eq!(composed.sequence, 0);
        assert_eq!(composed.reserves_a, 1_000_000);
        assert_eq!(composed.reserves_b, 500_000);
        assert_eq!(composed.pending_chain_len, 0);
        assert_eq!(composed.pending_chain_skipped, 1);
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn rejects_pointer_when_route_commit_x_mismatches_pointer_x() {
        let vault_id = vid_seed(0x18);
        let owner = generate_keypair(SphincsVariant::SPX256f).expect("owner kp");
        let trader = generate_keypair(SphincsVariant::SPX256f).expect("trader kp");
        let baseline = make_baseline(
            &vault_id,
            0,
            &TOKEN_A,
            &TOKEN_B,
            1_000_000,
            500_000,
            30,
            &owner.public_key,
            &owner.secret_key,
        )
        .await;

        // Publish a valid signed RouteCommit and obtain its canonical X.
        let nonce_seed = x_seed(0x81);
        let (_, _, canonical_x) = publish_rc_for_swap(
            &nonce_seed,
            &vault_id,
            &TOKEN_A,
            &TOKEN_B,
            1_000_000,
            500_000,
            30,
            0,
            true,
            1_000,
            &trader.public_key,
            &trader.secret_key,
        )
        .await;

        // Copy the same RC bytes under a different storage key to simulate
        // storage-key spoofing (keys are untrusted labels).
        let spoofed_x = x_seed(0x82);
        let canonical_key = external_commitment_rc_key(&canonical_x);
        let spoofed_key = external_commitment_rc_key(&spoofed_x);
        let rc_bytes = BitcoinTapSdk::storage_get_bytes(&canonical_key)
            .await
            .expect("fetch canonical rc");
        BitcoinTapSdk::storage_put_bytes(&spoofed_key, &rc_bytes)
            .await
            .expect("publish spoofed rc");

        // Make both anchors visible; eligibility-by-signature alone would pass,
        // so only pointer.x ↔ canonical X binding should reject folding.
        publish_extcommit(&canonical_x, &trader.public_key).await;
        publish_extcommit(&spoofed_x, &trader.public_key).await;
        publish_pointer(
            &vault_id,
            0,
            1,
            &spoofed_x,
            &marker_digest(&spoofed_x, 0),
            &settled_trade(&spoofed_x, 0, &TOKEN_A, 1, &TOKEN_B, 1),
            &trader.public_key,
            &trader.secret_key,
        )
        .await;

        let composed = compose_vault_state(&vault_id, &baseline, &TOKEN_A, &TOKEN_B, 30)
            .await
            .expect("compose succeeds");
        assert_eq!(composed.sequence, 0);
        assert_eq!(composed.reserves_a, 1_000_000);
        assert_eq!(composed.reserves_b, 500_000);
        assert_eq!(composed.pending_chain_len, 0);
        assert_eq!(composed.pending_chain_skipped, 1);
    }

    /// The headline scenario the Phase-6 plan targets: Alice (vault
    /// owner) is offline; Bob's trade has settled cryptographically
    /// (X published + RC published + pointer published); Carol comes
    /// along and computes a composed state — she should see sequence=1
    /// AND reserves shifted by Bob's exact trade.  This is the property
    /// that lets concurrent traders serialize against a vault without
    /// the owner online between trades.
    #[tokio::test]
    async fn multi_trader_serialization_without_owner_refresh() {
        let vault_id = vid_seed(0x99);
        let alice = generate_keypair(SphincsVariant::SPX256f).expect("alice kp");
        let bob = generate_keypair(SphincsVariant::SPX256f).expect("bob kp");
        let _carol = generate_keypair(SphincsVariant::SPX256f).expect("carol kp");

        // Alice publishes the baseline anchor at seq=0.  Alice's chain
        // is the authority; everyone else sees this anchor on storage.
        let baseline = make_baseline(
            &vault_id,
            0,
            &TOKEN_A,
            &TOKEN_B,
            10_000,
            10_000,
            30,
            &alice.public_key,
            &alice.secret_key,
        )
        .await;

        // Bob trades.  His RouteCommit settles; X + RC + pointer are
        // published.  CRUCIALLY: Alice is offline — she does NOT publish
        // a refreshed anchor at seq=1.
        let bob_x = x_seed(0xBB);
        let (after_bob_a, after_bob_b) = publish_trade(
            &vault_id,
            &bob_x,
            &TOKEN_A,
            &TOKEN_B,
            10_000,
            10_000,
            30,
            0,
            true, // Bob sends AAA in
            500,
            &bob.public_key,
            &bob.secret_key,
            true,
        )
        .await;

        // Carol composes.  She sees Alice's seq=0 baseline + Bob's
        // pending pointer + Bob's RC = composed cursor at seq=1 with
        // reserves reflecting Bob's exact trade.  Concurrent
        // serialization without Alice's involvement.
        let composed = compose_vault_state(&vault_id, &baseline, &TOKEN_A, &TOKEN_B, 30)
            .await
            .expect("compose succeeds for Carol");
        assert_eq!(
            composed.sequence, 1,
            "Carol should see Bob's pending advance even though Alice is offline",
        );
        assert_eq!(
            composed.reserves_a, after_bob_a,
            "reserve_a reflects Bob's input"
        );
        assert_eq!(
            composed.reserves_b, after_bob_b,
            "reserve_b reflects Bob's simulated output"
        );
        assert!(composed.reserves_a > 10_000);
        assert!(composed.reserves_b < 10_000);
        assert_eq!(composed.pending_chain_len, 1);
        assert_eq!(composed.pending_chain_skipped, 0);
    }

    #[tokio::test]
    async fn rejects_reserve_proof_disagreeing_with_the_signed_digest() {
        let vault_id = vid_seed(0x15);
        let owner = generate_keypair(SphincsVariant::SPX256f).expect("owner kp");
        let baseline = make_baseline(
            &vault_id,
            0,
            &TOKEN_A,
            &TOKEN_B,
            1_000_000,
            500_000,
            30,
            &owner.public_key,
            &owner.secret_key,
        )
        .await;
        // The proven reserves and the owner's signed digest are BOTH the
        // owner's. Disagreement means the two records came from different
        // states, so the vault is unsafe to quote either way. Overwrite the
        // published reserve proof with one proving different amounts under a
        // consistent root of its own.
        publish_reserve_proof_for(
            &vault_id,
            0,
            777_777,
            888_888,
            &owner.public_key,
            &owner.secret_key,
        )
        .await;
        let err = compose_vault_state(&vault_id, &baseline, &TOKEN_A, &TOKEN_B, 30)
            .await
            .expect_err("proven reserves disagreeing with the signed digest must reject");
        assert!(matches!(err, CompositionError::InvalidReserveProof));
    }

    // ───────────────────────────────────────────────────────────
    // Phase 7 — SoFi spec §4.1.2 / §8.4 step 2 strict-mode tests
    // ───────────────────────────────────────────────────────────

    /// Strict mode refuses to fold a vault whose owner never published
    /// a `VaultStateInclusionProofV1` — the legacy anchor alone is
    /// insufficient.  This is the signing-key-forgery hole closure: an
    /// attacker with the owner's key can forge a signed anchor but
    /// cannot fabricate SMT consistency.
    #[tokio::test]
    async fn strict_mode_rejects_vault_without_inclusion_proof() {
        let vault_id = vid_seed(0x80);
        let owner = generate_keypair(SphincsVariant::SPX256f).expect("owner kp");
        // Only sign the anchor — DO NOT publish an inclusion proof.
        // make_baseline_anchor_only is the escape hatch for exactly
        // this negative-test scenario.
        let baseline = make_baseline_anchor_only(
            &vault_id,
            0,
            &TOKEN_A,
            &TOKEN_B,
            1_000_000,
            500_000,
            30,
            &owner.public_key,
            &owner.secret_key,
        );
        let err = compose_vault_state(&vault_id, &baseline, &TOKEN_A, &TOKEN_B, 30)
            .await
            .expect_err("strict mode must refuse vault without inclusion proof");
        assert!(matches!(err, CompositionError::MissingInclusionProof));
    }

    /// Strict mode catches owner equivocation: the inclusion proof
    /// references a different (sequence, reserves_digest) than the
    /// baseline anchor.  This would happen if a compromised owner
    /// signed two records with the same key but disagreeing payloads.
    #[tokio::test]
    async fn strict_mode_rejects_inclusion_proof_disagreeing_with_baseline() {
        use dsm::dlv::vault_smt_leaf::{
            compute_vault_smt_key, compute_vault_smt_value, sign_vault_state_inclusion_proof,
        };
        use dsm::merkle::sparse_merkle_tree::SparseMerkleTree;

        let vault_id = vid_seed(0x81);
        let owner = generate_keypair(SphincsVariant::SPX256f).expect("owner kp");
        // Anchor is at sequence=0 with the canonical reserves.
        let baseline = make_baseline_anchor_only(
            &vault_id,
            0,
            &TOKEN_A,
            &TOKEN_B,
            1_000_000,
            500_000,
            30,
            &owner.public_key,
            &owner.secret_key,
        );

        // Publish an inclusion proof at sequence=5 — disagreeing with
        // the baseline's sequence=0.
        let bogus_reserves_digest =
            compute_reserves_digest(&TOKEN_A, &TOKEN_B, 1_000_000, 500_000, 30);
        let mut tree = SparseMerkleTree::new(64);
        let leaf_key = compute_vault_smt_key(&vault_id);
        let leaf_value = compute_vault_smt_value(5, &bogus_reserves_digest);
        tree.update_leaf(&leaf_key, &leaf_value)
            .expect("update_leaf");
        let smt_root = *tree.root();
        let proof = tree.get_inclusion_proof(&leaf_key, 256).expect("proof");
        let signed = sign_vault_state_inclusion_proof(
            &vault_id,
            5, // <-- disagrees with baseline's seq=0
            &bogus_reserves_digest,
            &smt_root,
            proof.siblings,
            &owner.public_key,
            &owner.secret_key,
        )
        .expect("sign inclusion proof");
        let proto_bytes =
            crate::sdk::vault_smt_inclusion_codec::encode_inclusion_proof_to_proto(&signed);
        crate::sdk::vault_smt_inclusion_codec::publish_inclusion_proof(&vault_id, 5, &proto_bytes)
            .await
            .expect("publish");

        let err = compose_vault_state(&vault_id, &baseline, &TOKEN_A, &TOKEN_B, 30)
            .await
            .expect_err("strict mode must reject disagreeing inclusion proof");
        assert!(matches!(err, CompositionError::InvalidInclusionProof));
    }

    /// Strict mode catches a tampered SMT path: the inclusion proof's
    /// (vault_id, sequence, reserves_digest) match the baseline, the
    /// signature is valid (because it doesn't sign over the siblings —
    /// only over the root), but the supplied siblings DON'T hash up to
    /// the claimed root.  Verifier rejects via the SMT inclusion
    /// check.
    #[tokio::test]
    async fn strict_mode_rejects_inclusion_proof_with_tampered_siblings() {
        use dsm::dlv::vault_smt_leaf::{
            compute_vault_smt_key, compute_vault_smt_value, sign_vault_state_inclusion_proof,
        };
        use dsm::merkle::sparse_merkle_tree::SparseMerkleTree;

        let vault_id = vid_seed(0x82);
        let owner = generate_keypair(SphincsVariant::SPX256f).expect("owner kp");
        let baseline = make_baseline_anchor_only(
            &vault_id,
            0,
            &TOKEN_A,
            &TOKEN_B,
            1_000_000,
            500_000,
            30,
            &owner.public_key,
            &owner.secret_key,
        );

        // Build a real SMT, then corrupt one sibling before signing —
        // the signed payload (which excludes siblings, by design)
        // still verifies, but the inclusion check rejects.
        let reserves_digest = compute_reserves_digest(&TOKEN_A, &TOKEN_B, 1_000_000, 500_000, 30);
        let mut tree = SparseMerkleTree::new(64);
        let leaf_key = compute_vault_smt_key(&vault_id);
        let leaf_value = compute_vault_smt_value(0, &reserves_digest);
        tree.update_leaf(&leaf_key, &leaf_value)
            .expect("update_leaf");
        let smt_root = *tree.root();
        let mut proof = tree.get_inclusion_proof(&leaf_key, 256).expect("proof");
        // Corrupt one sibling.
        proof.siblings[0][0] ^= 0xff;

        let signed = sign_vault_state_inclusion_proof(
            &vault_id,
            0,
            &reserves_digest,
            &smt_root,
            proof.siblings,
            &owner.public_key,
            &owner.secret_key,
        )
        .expect("sign inclusion proof");
        let proto_bytes =
            crate::sdk::vault_smt_inclusion_codec::encode_inclusion_proof_to_proto(&signed);
        crate::sdk::vault_smt_inclusion_codec::publish_inclusion_proof(&vault_id, 0, &proto_bytes)
            .await
            .expect("publish");

        let err = compose_vault_state(&vault_id, &baseline, &TOKEN_A, &TOKEN_B, 30)
            .await
            .expect_err("strict mode must reject tampered SMT path");
        assert!(matches!(err, CompositionError::InvalidInclusionProof));
    }
}
