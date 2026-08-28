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
//! Pending fold
//! ------------
//! On top of the verified baseline the composer folds any published
//! `VaultPendingPointerV1` records that chain forward by one sequence step,
//! so concurrent traders quoting against the same vault while the owner is
//! offline see each other's settled trades and serialize on top of them.
//! Each fold step:
//!
//! - verifies the pointer's SPHINCS+ signature;
//! - demands a verified settlement receipt matching the pointer's committed
//!   receipt hash (the receipt gate — the only artifact that cannot exist
//!   without a real settlement);
//! - fetches the signed `RouteCommit` bound to the pointer's `X` and
//!   re-derives `X` from its bytes;
//! - requires the hop's `parent_binding` to equal the `c_n` of the CURRENT
//!   cursor state — the one byte-equality that replaces the old
//!   (sequence, reserves digest, anchor digest) triple;
//! - re-simulates the AMM swap against the cursor's reserves and demands the
//!   exact claimed output;
//! - constructs the successor `V_{n+1}` — generation advanced, reserves
//!   moved, `parent_state_commitment` set to the consumed state's `c_n`,
//!   every other field copied byte-for-byte — and advances the cursor to its
//!   commitment.
//!
//! The composed result is therefore a full `VaultStateV2` with a canonical
//! identity of its own: the `c_n` a new trade's hop must bind as its parent.

use dsm::ccb::{vault_state_commitment, VaultStateV2};
use dsm::dlv::vault_pending_pointer::{verify_vault_pending_pointer, SignedVaultPendingPointer};
use dsm::types::proto as generated;
use prost::Message;

use crate::sdk::bitcoin_tap_sdk::BitcoinTapSdk;
use crate::sdk::identity_presentation::verify_anchor_presentation;
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

/// Result of composing pending pointers onto a presentation-verified
/// baseline.
#[derive(Debug, Clone)]
pub(crate) struct ComposedVaultState {
    /// The composed state itself — the baseline `V_n` when no pointers
    /// folded, the constructed successor otherwise. Every fact a consumer
    /// needs (generation, reserves, pair, fee, storage set, encumbrances,
    /// authority position) is a field of this one object.
    pub state: VaultStateV2,
    /// `c_n` of `state` — the canonical identity of the state this fold reached,
    /// and the exact value a new trade's hop must carry as `parent_binding`.
    ///
    /// This is a valid PREFIX, not a proven frontier: the fold stops when the
    /// pointer listing it read is exhausted, and that listing came from a single
    /// member, so absence and omission are the same observation. Do not read this
    /// as "the latest state" — establishing that needs a live quorum read the
    /// composer does not perform.
    pub c_n: [u8; 32],
    /// `state.generation`, broken out for callers that only order by it.
    pub sequence: u64,
    /// The parent identity CONSUMED by each successful fold, oldest first:
    /// `(parent_generation, parent c_n)`. This is how a caller reconciling a
    /// settlement N generations back names the exact historical parent state
    /// that settlement consumed — the fold computed every cursor identity on
    /// the way here, so no re-derivation and no second source.
    pub folded_parent_bindings: Vec<(u64, [u8; 32])>,
    /// `state.reserve_a` / `state.reserve_b`, broken out for AMM math.
    pub reserves_a: u64,
    pub reserves_b: u64,
    /// Number of pending pointers successfully verified + chained.
    pub pending_chain_len: usize,
    /// Number of pending pointers skipped (signature invalid, X missing,
    /// out-of-sequence, beyond MAX_PENDING_CHAIN_DEPTH).  Useful for
    /// telemetry / regression tests.
    ///
    /// DIAGNOSTIC AGGREGATION, never a safety predicate. It sums causes that
    /// mean entirely different things, so a caller that refused on
    /// `pending_chain_skipped > 0` would let anyone un-quotable a vault forever
    /// by publishing one malformed pointer — the free-griefing property the
    /// receipt gate exists to remove. There is deliberately NO narrower
    /// "parent in flight" signal either: a pointer is self-signed, so its bare
    /// presence proves nothing a quote decision may consume, and the
    /// first-writer settlement-slot claim is where competing quotes serialize.
    pub pending_chain_skipped: usize,
    /// The vault owner, proven by the presentation's P0–P6 chain at the
    /// state's own committed authority position. Constant across generations
    /// — market successors copy the authority position byte-for-byte.
    pub owner_devid: [u8; 32],
    pub owner_genesis: [u8; 32],
    pub owner_public_key: Vec<u8>,
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

    // ── Collect pending pointers. ────────────────────────────────────────
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

    // ── The fold. Cursor = a full state + its commitment. ────────────────
    let mut cursor_state = baseline_state;
    let mut cursor_c_n = baseline_c_n;
    let mut chain_len: usize = 0;
    let mut chain_skipped: usize = 0;
    let mut folded_parent_bindings: Vec<(u64, [u8; 32])> = Vec::new();
    for ptr in pointers.into_iter() {
        if chain_len >= MAX_PENDING_CHAIN_DEPTH {
            chain_skipped += 1;
            continue;
        }
        if ptr.parent_sequence != cursor_state.generation {
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
                    // INERT — for reserves AND for quote availability. The
                    // pointer may be a perfectly well-formed trade whose
                    // settlement lands a moment from now, or it may be one
                    // storage write from an arbitrary keypair: the primitive
                    // cannot tell them apart, because a pointer is
                    // SELF-signed and establishes no vault authority and no
                    // settlement. Anything a composer concluded from its bare
                    // presence — "this parent is in flight", most temptingly —
                    // would hand liquidity suppression to anyone for the
                    // price of one write. Skipping leaves the composed state
                    // exactly as if the pointer had never been published;
                    // serialization safety lives where it always did, at the
                    // first-writer settlement-slot claim, where a losing
                    // quote costs its owner nothing.
                    chain_skipped += 1;
                    continue;
                }
            };
        if dsm::dlv::settlement_receipt_leaf::receipt_commitment_of(&receipt)
            != ptr.expected_receipt_hash
        {
            // A receipt exists but does not witness THIS trade, so this pointer
            // is as unwitnessed as one with no receipt at all — and exactly as
            // inert.
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
                // RC not yet published (publisher crashed between X and RC
                // writes). Cannot fold reserves without the RC; skip.
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
        // THE PARENT BINDING. The hop must name the c_n of the exact cursor
        // state it consumes — one byte-equality that pins the generation, the
        // reserves, the pair, the fee and the authority position all at once,
        // because they are members of the identified V_n. A hop bound to any
        // other state (stale, future, fabricated) was signed against a
        // different parent and folding it would diverge from the canonical
        // chain. Mandatory: an unbound hop is skipped, never tolerated.
        if hop.parent_binding.len() != 32 || hop.parent_binding.as_slice() != cursor_c_n.as_slice()
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
        // Determine trade direction against the state's own canonical pair.
        let input_is_a = hop.token_in.as_slice() == pc_a && hop.token_out.as_slice() == pc_b;
        let input_is_b = hop.token_in.as_slice() == pc_b && hop.token_out.as_slice() == pc_a;
        if !input_is_a && !input_is_b {
            chain_skipped += 1;
            continue;
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
        next_state.generation = ptr.new_sequence;
        next_state.reserve_a = new_a;
        next_state.reserve_b = new_b;
        next_state.parent_state_commitment = cursor_c_n;
        let next_c_n = match vault_state_commitment(&next_state) {
            Ok(c) => c,
            Err(e) => {
                // A successor of a decoded-valid state re-encodes unless the
                // fold produced something the constructors refuse; treat as a
                // skip, never a partial advance.
                log::warn!("[compose_vault_state] successor encode refused: {e}");
                chain_skipped += 1;
                continue;
            }
        };
        folded_parent_bindings.push((cursor_state.generation, cursor_c_n));
        cursor_state = next_state;
        cursor_c_n = next_c_n;
        chain_len += 1;
    }

    Ok(ComposedVaultState {
        sequence: cursor_state.generation,
        reserves_a: cursor_state.reserve_a,
        reserves_b: cursor_state.reserve_b,
        pending_chain_len: chain_len,
        pending_chain_skipped: chain_skipped,
        owner_devid: owner.device_id,
        owner_genesis: cursor_state.owner_genesis_id,
        owner_public_key: owner.ak_pk,
        storage_set_id,
        c_n: cursor_c_n,
        folded_parent_bindings,
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
            storage_set: StorageSetMembers::new(&[b"n1", b"n2", b"n3", b"n4", b"n5"]).expect("set"),
            quorum: 4,
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
        publish_pointer(
            vault_id,
            parent_sequence,
            parent_sequence + 1,
            &x,
            &trade,
            &pk,
            &sk,
        )
        .await;
        (new_a, new_b)
    }

    /// No pointers: the composed state IS the verified baseline, identity
    /// included.
    #[tokio::test]
    async fn composes_the_verified_baseline_when_no_pointers_exist() {
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

    /// The presentation authenticates a state; handing the composer the bytes
    /// of a DIFFERENT state must refuse — the anchor's commitment does not
    /// match the bytes.
    #[tokio::test]
    async fn bytes_of_a_different_state_are_refused() {
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
        let vault_id = vid(0x04);
        let (presentation, ccb, _state, _c0) = baseline_fixture(vault_id, 1_000_000, 500_000);
        let other = vid(0x05);
        let err = compose_vault_state(&other, &presentation, &ccb, &TOKEN_A, &TOKEN_B, FEE_BPS)
            .await
            .expect_err("must refuse");
        assert!(matches!(err, CompositionError::BaselineMismatch(_)));
    }

    /// One receipted trade folds: the generation advances by one, the
    /// reserves move by exactly the simulated swap, and the successor's
    /// predecessor edge is the baseline's identity — the c_n chain is real.
    #[tokio::test]
    async fn a_receipted_pointer_folds_and_advances_the_commitment_chain() {
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

    /// An unreceipted pointer is INERT — for reserves and for quote
    /// availability alike. Even a fully valid RouteCommit with a visible X is
    /// producible without settling or claiming the slot, so nothing short of
    /// the receipt may change what a composer reports: the composed state
    /// must be byte-identical to the no-pointer case.
    #[tokio::test]
    async fn an_unreceipted_pointer_is_inert_even_with_a_valid_route_and_visible_x() {
        let vault_id = vid(0x07);
        let (presentation, ccb, state, c0) = baseline_fixture(vault_id, 1_000_000, 500_000);
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
        let out = 1_000_000u64; // any number; no receipt will exist
        let trade = settled_trade(&x, 0, true, 10_000, out);
        publish_pointer(&vault_id, 0, 1, &x, &trade, &pk, &sk).await;

        let composed =
            compose_vault_state(&vault_id, &presentation, &ccb, &TOKEN_A, &TOKEN_B, FEE_BPS)
                .await
                .expect("composes");
        assert_eq!(composed.pending_chain_len, 0);
        assert_eq!(composed.sequence, 0);
        assert_eq!(composed.c_n, c0);
        assert_eq!(
            composed.state, state,
            "an unwitnessed intent changes NOTHING a composer reports"
        );
    }

    /// The griefing case, pinned as refused: a pointer forged by an arbitrary
    /// keypair — no RouteCommit, no X, arbitrary receipt commitment — at
    /// exactly the current parent must leave the vault fully quotable. A
    /// pointer is self-signed; its bare presence establishes no vault
    /// authority and no settlement, so it may not suppress liquidity.
    #[tokio::test]
    async fn a_forged_pointer_from_an_arbitrary_key_cannot_suppress_liquidity() {
        let vault_id = vid(0x0C);
        let (presentation, ccb, state, c0) = baseline_fixture(vault_id, 1_000_000, 500_000);
        let (attacker_pk, attacker_sk) = trader();
        // No X anchor, no RouteCommit, no receipt — one storage write.
        let x = x_seed(0x0C);
        let fake_trade = settled_trade(&x, 0, true, 1, 1);
        publish_pointer(&vault_id, 0, 1, &x, &fake_trade, &attacker_pk, &attacker_sk).await;

        let composed =
            compose_vault_state(&vault_id, &presentation, &ccb, &TOKEN_A, &TOKEN_B, FEE_BPS)
                .await
                .expect("composes");
        assert_eq!(composed.pending_chain_len, 0);
        assert_eq!(composed.sequence, 0);
        assert_eq!(composed.c_n, c0);
        assert_eq!(
            composed.state, state,
            "one arbitrary-keypair storage write must not change what any verifier composes"
        );
    }

    /// A hop bound to a parent that is NOT the cursor's c_n is skipped: the
    /// trade was signed against a different state and cannot be folded here.
    #[tokio::test]
    async fn a_hop_bound_to_a_stale_parent_is_skipped() {
        let vault_id = vid(0x08);
        let (presentation, ccb, _state, c0) = baseline_fixture(vault_id, 1_000_000, 500_000);
        let stale_binding = [0xEEu8; 32];
        assert_ne!(stale_binding, c0);
        let (_new_a, _new_b) = publish_settled_trade(
            &vault_id,
            &x_seed(0x08),
            1_000_000,
            500_000,
            0,
            &stale_binding,
            true,
            10_000,
        )
        .await;

        let composed =
            compose_vault_state(&vault_id, &presentation, &ccb, &TOKEN_A, &TOKEN_B, FEE_BPS)
                .await
                .expect("composes");
        assert_eq!(composed.pending_chain_len, 0, "stale binding must not fold");
        assert_eq!(composed.sequence, 0);
        assert_eq!(composed.c_n, c0);
        assert!(composed.pending_chain_skipped >= 1);
    }

    /// A receipt that witnesses a DIFFERENT trade than the pointer committed
    /// to does not activate the pointer.
    #[tokio::test]
    async fn a_receipt_for_a_different_trade_does_not_activate_the_pointer() {
        let vault_id = vid(0x09);
        let (presentation, ccb, _state, c0) = baseline_fixture(vault_id, 1_000_000, 500_000);
        let (pk, sk) = trader();
        let (new_a, _new_b, x) = publish_rc_for_swap(
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
        let _ = new_a;
        // The pointer commits to the REAL trade …
        let real_out = crate::sdk::routing_path_sdk::constant_product_output(
            10_000, 1_000_000, 500_000, FEE_BPS,
        )
        .expect("sim");
        let committed = settled_trade(&x, 0, true, 10_000, real_out);
        publish_pointer(&vault_id, 0, 1, &x, &committed, &pk, &sk).await;
        // … but the receipt witnesses a much smaller one.
        let witnessed = settled_trade(&x, 0, true, 10, 3);
        publish_receipt(&vault_id, &witnessed, &pk, &sk).await;

        let composed =
            compose_vault_state(&vault_id, &presentation, &ccb, &TOKEN_A, &TOKEN_B, FEE_BPS)
                .await
                .expect("composes");
        assert_eq!(composed.pending_chain_len, 0);
        assert_eq!(composed.sequence, 0);
        assert_eq!(
            composed.c_n, c0,
            "an unmatched receipt leaves the pointer unwitnessed — and inert"
        );
    }

    /// Two settled trades chain: c_0 → c_1 → c_2, each successor binding the
    /// previous identity, with the second hop bound to c_1 (not c_0).
    #[tokio::test]
    async fn two_settled_trades_chain_by_commitment() {
        let vault_id = vid(0x0A);
        let (presentation, ccb, _state, c0) = baseline_fixture(vault_id, 1_000_000, 500_000);
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
        // Recompute c_1 exactly as the composer will.
        let (_p, _ccb2, state0, _c0b) = baseline_fixture(vault_id, 1_000_000, 500_000);
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
