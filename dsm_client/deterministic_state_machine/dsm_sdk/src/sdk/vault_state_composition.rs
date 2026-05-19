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
//! - Lists `defi/vault-pending/{vault_id_b32}/` (lex-ordered by `new_sequence`)
//! - For each pointer: verifies the SPHINCS+ signature; fetches
//!   `defi/extcommit/{x_b32}` to confirm the X anchor is published
//!   (pointers without backing X are skipped); intends to re-simulate
//!   the AMM swap against the running cursor's reserves (gated on the
//!   RC-on-storage extension, see "Open question" below)
//! - Stops at first pointer that fails any check, or at
//!   `MAX_PENDING_CHAIN_DEPTH`, or when a sequence gap is detected
//! - Returns the composed state
//!
//! Open question
//! -------------
//! The current `ExternalCommitmentV1` proto carries only `(x, publisher_pk,
//! label)`.  The full signed RouteCommit is NOT on storage — only the
//! pointer's signature binds (vault_id, parent_seq, new_seq, x, marker).
//!
//! Composition therefore can only verify:
//!   - The pointer's own signature is valid
//!   - The X it references is published
//!   - The chain links forward by parent→new sequence
//!
//! It CANNOT re-simulate the AMM swap from storage data alone because the
//! input/output amounts live in the RouteCommit, not the ExtCommit.  The
//! pointer chain proves "someone with key K_pub attested to a state
//! advance from N to N+1 for vault V backed by X" but not the magnitudes
//! of the reserve shift.
//!
//! Two options:
//!   (A) Extend `ExternalCommitmentV1` to embed the signed RouteCommit
//!       bytes.  Inflates per-X storage by ~RC size (~1 KB) but makes
//!       composition fully self-contained.
//!   (B) Publish the full RouteCommit at a separate key (e.g.
//!       `defi/extcommit-rc/{x_b32}`) that composition fetches.
//!
//! This module ships with (B) as a follow-up.  For now composition stops
//! at "pointer chain validated, but actual reserves require a fetch of
//! the canonical RC".  Path search uses the BASELINE reserves with a
//! warning logged for each pending pointer it had to skip.  This is
//! strictly safer than the pre-Phase-6 behaviour: traders are now AWARE
//! of pending state advances even if they can't fold them yet.
//!
//! When the RC-on-storage path lands, this module's `try_fold_hop_from_rc`
//! becomes the load-bearing step.

use dsm::dlv::vault_pending_pointer::{verify_vault_pending_pointer, SignedVaultPendingPointer};
use dsm::dlv::vault_state_anchor::{
    compute_reserves_digest, verify_vault_state_anchor, SignedVaultStateAnchor,
};
use dsm::types::proto as generated;
use prost::Message;

use crate::sdk::bitcoin_tap_sdk::BitcoinTapSdk;
use crate::sdk::route_commit_sdk::{external_commitment_key, vault_pending_prefix};

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
    /// Reserves used by path search for AMM edges.  In Phase 6.0 these
    /// remain the baseline reserves; when the RC-on-storage extension
    /// lands these become the composed-forward reserves.
    pub reserves_a: u128,
    pub reserves_b: u128,
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
    /// Storage listing the pending prefix failed.
    StorageListFailed(String),
    /// Decoding a pointer proto failed in a non-recoverable way.  The
    /// individual pointer is skipped; this variant fires only if the
    /// whole list page failed.
    PointerDecodeFailed(String),
}

impl std::fmt::Display for CompositionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CompositionError::InvalidBaselineAnchor => {
                write!(f, "baseline anchor signature invalid")
            }
            CompositionError::StorageListFailed(msg) => {
                write!(f, "storage list failed: {msg}")
            }
            CompositionError::PointerDecodeFailed(msg) => {
                write!(f, "pointer decode failed: {msg}")
            }
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
/// Returns the composed state.  Even when no pointers can be folded
/// (e.g., RC-on-storage extension not yet shipped), the returned struct
/// carries telemetry (`pending_chain_skipped`) so path search can log
/// or downweight vaults with high pending counts.
pub(crate) async fn compose_vault_state(
    vault_id: &[u8; 32],
    baseline: &SignedVaultStateAnchor,
    baseline_reserves: (u128, u128),
    token_a: &[u8],
    token_b: &[u8],
    fee_bps: u32,
) -> Result<ComposedVaultState, CompositionError> {
    // Verify the baseline anchor's signature.  No further composition
    // is meaningful without this.
    verify_vault_state_anchor(baseline).map_err(|_| CompositionError::InvalidBaselineAnchor)?;
    // And cross-check the supplied reserves match the baseline digest.
    let expected_digest = compute_reserves_digest(
        token_a,
        token_b,
        baseline_reserves.0,
        baseline_reserves.1,
        fee_bps,
    );
    if expected_digest != baseline.reserves_digest {
        // Caller bug — they supplied reserves that don't match the
        // signed baseline.  Surface as InvalidBaselineAnchor: the
        // baseline cannot be trusted for composition.
        return Err(CompositionError::InvalidBaselineAnchor);
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
                        &item.key,
                    );
                    continue;
                }
            };
            let proto = match generated::VaultPendingPointerV1::decode(bytes.as_slice()) {
                Ok(p) => p,
                Err(e) => {
                    log::debug!(
                        "[compose_vault_state] skipping {}: decode failed: {e}",
                        &item.key,
                    );
                    continue;
                }
            };
            // Convert proto → typed struct for verification.
            if proto.vault_id.len() != 32
                || proto.x.len() != 32
                || proto.new_reserves_digest.len() != 32
            {
                continue;
            }
            let mut vid_arr = [0u8; 32];
            vid_arr.copy_from_slice(&proto.vault_id);
            let mut x_arr = [0u8; 32];
            x_arr.copy_from_slice(&proto.x);
            let mut digest_arr = [0u8; 32];
            digest_arr.copy_from_slice(&proto.new_reserves_digest);
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

    // Fold pointers onto the baseline.  Phase 6.0 fold-rule:
    //   - Pointer's parent_sequence must equal the running cursor.
    //   - Pointer's signature must verify.
    //   - The X it references must actually exist on storage (so we
    //     never advance the cursor against a pointer for a non-published
    //     trade).
    //   - Up to MAX_PENDING_CHAIN_DEPTH folds total.
    //
    // Phase 6.0 does NOT mutate reserves (see module-level "Open
    // question").  When RC-on-storage lands, this is where we'd
    // re-simulate the AMM swap against the running cursor's reserves.
    let mut cursor_seq = baseline.sequence;
    let mut chain_len: usize = 0;
    let mut chain_skipped: usize = 0;
    for ptr in pointers.into_iter() {
        if chain_len >= MAX_PENDING_CHAIN_DEPTH {
            chain_skipped += 1;
            continue;
        }
        if ptr.parent_sequence != cursor_seq {
            // Sequence gap — chain broken.  Stop folding; remaining
            // pointers are reported as skipped.
            chain_skipped += 1;
            continue;
        }
        if verify_vault_pending_pointer(&ptr).is_err() {
            chain_skipped += 1;
            continue;
        }
        // Confirm the X anchor exists on storage.  Without it, the
        // pointer references a not-yet-published trade and we can't
        // advance the cursor (the trade hasn't actually committed).
        let x_key = external_commitment_key(&ptr.x);
        let x_present = BitcoinTapSdk::storage_get_bytes(&x_key).await.is_ok();
        if !x_present {
            chain_skipped += 1;
            continue;
        }
        // All checks passed.  Advance the cursor.
        cursor_seq = ptr.new_sequence;
        chain_len += 1;
    }

    Ok(ComposedVaultState {
        sequence: cursor_seq,
        reserves_a: baseline_reserves.0,
        reserves_b: baseline_reserves.1,
        pending_chain_len: chain_len,
        pending_chain_skipped: chain_skipped,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use dsm::crypto::sphincs::{generate_keypair, SphincsVariant};
    use dsm::dlv::vault_pending_pointer::sign_vault_pending_pointer;
    use dsm::dlv::vault_state_anchor::sign_vault_state_anchor;

    fn make_baseline(
        vault_id: &[u8; 32],
        seq: u64,
        token_a: &[u8],
        token_b: &[u8],
        reserve_a: u128,
        reserve_b: u128,
        fee_bps: u32,
        owner_pk: &[u8],
        owner_sk: &[u8],
    ) -> SignedVaultStateAnchor {
        let digest = compute_reserves_digest(token_a, token_b, reserve_a, reserve_b, fee_bps);
        sign_vault_state_anchor(vault_id, seq, &digest, owner_pk, owner_sk).expect("sign anchor")
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

    /// Publish a synthetic ExtCommit anchor at `defi/extcommit/{X_b32}`
    /// (just enough bytes so the composer's "is X present?" check
    /// succeeds).  Tests run against the in-process mock storage backend.
    async fn publish_synthetic_extcommit(x: &[u8; 32], publisher_pk: &[u8]) {
        let anchor = generated::ExternalCommitmentV1 {
            version: 1,
            x: x.to_vec(),
            publisher_public_key: publisher_pk.to_vec(),
            label: "test".into(),
        };
        let key = external_commitment_key(x);
        BitcoinTapSdk::storage_put_bytes(&key, &anchor.encode_to_vec())
            .await
            .expect("synthetic X publish");
    }

    async fn publish_pointer(
        vault_id: &[u8; 32],
        parent_seq: u64,
        new_seq: u64,
        x: &[u8; 32],
        digest: &[u8; 32],
        publisher_pk: &[u8],
        publisher_sk: &[u8],
    ) {
        let signed = sign_vault_pending_pointer(
            vault_id,
            parent_seq,
            new_seq,
            x,
            digest,
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
            publisher_public_key: signed.publisher_public_key,
            publisher_signature: signed.publisher_signature,
        };
        let key = crate::sdk::route_commit_sdk::vault_pending_pointer_key(vault_id, new_seq, x);
        BitcoinTapSdk::storage_put_bytes(&key, &proto.encode_to_vec())
            .await
            .expect("publish pointer");
    }

    #[tokio::test]
    async fn composes_empty_chain_returns_baseline() {
        let vault_id = vid_seed(0x10);
        let owner = generate_keypair(SphincsVariant::SPX256f).expect("owner kp");
        let baseline = make_baseline(
            &vault_id,
            5,
            b"AAA",
            b"BBB",
            1_000_000,
            500_000,
            30,
            &owner.public_key,
            &owner.secret_key,
        );
        let composed = compose_vault_state(
            &vault_id,
            &baseline,
            (1_000_000, 500_000),
            b"AAA",
            b"BBB",
            30,
        )
        .await
        .expect("compose succeeds");
        assert_eq!(composed.sequence, 5);
        assert_eq!(composed.reserves_a, 1_000_000);
        assert_eq!(composed.reserves_b, 500_000);
        assert_eq!(composed.pending_chain_len, 0);
        assert_eq!(composed.pending_chain_skipped, 0);
    }

    #[tokio::test]
    async fn folds_single_valid_pointer() {
        let vault_id = vid_seed(0x11);
        let owner = generate_keypair(SphincsVariant::SPX256f).expect("owner kp");
        let trader = generate_keypair(SphincsVariant::SPX256f).expect("trader kp");
        let baseline = make_baseline(
            &vault_id,
            0,
            b"AAA",
            b"BBB",
            1_000_000,
            500_000,
            30,
            &owner.public_key,
            &owner.secret_key,
        );
        let x = x_seed(0x21);
        publish_synthetic_extcommit(&x, &trader.public_key).await;
        publish_pointer(
            &vault_id,
            0,
            1,
            &x,
            &marker_digest(&x, 0),
            &trader.public_key,
            &trader.secret_key,
        )
        .await;
        let composed = compose_vault_state(
            &vault_id,
            &baseline,
            (1_000_000, 500_000),
            b"AAA",
            b"BBB",
            30,
        )
        .await
        .expect("compose succeeds");
        assert_eq!(composed.sequence, 1);
        assert_eq!(composed.pending_chain_len, 1);
        assert_eq!(composed.pending_chain_skipped, 0);
    }

    #[tokio::test]
    async fn folds_chained_pointers_in_order() {
        let vault_id = vid_seed(0x12);
        let owner = generate_keypair(SphincsVariant::SPX256f).expect("owner kp");
        let trader = generate_keypair(SphincsVariant::SPX256f).expect("trader kp");
        let baseline = make_baseline(
            &vault_id,
            0,
            b"AAA",
            b"BBB",
            1_000_000,
            500_000,
            30,
            &owner.public_key,
            &owner.secret_key,
        );
        for (parent, new, seed_byte) in [(0u64, 1u64, 0x31u8), (1, 2, 0x32), (2, 3, 0x33)].iter() {
            let x = x_seed(*seed_byte);
            publish_synthetic_extcommit(&x, &trader.public_key).await;
            publish_pointer(
                &vault_id,
                *parent,
                *new,
                &x,
                &marker_digest(&x, 0),
                &trader.public_key,
                &trader.secret_key,
            )
            .await;
        }
        let composed = compose_vault_state(
            &vault_id,
            &baseline,
            (1_000_000, 500_000),
            b"AAA",
            b"BBB",
            30,
        )
        .await
        .expect("compose succeeds");
        assert_eq!(composed.sequence, 3);
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
            b"AAA",
            b"BBB",
            1_000_000,
            500_000,
            30,
            &owner.public_key,
            &owner.secret_key,
        );
        let x = x_seed(0x41);
        // Intentionally do NOT publish the X anchor.
        publish_pointer(
            &vault_id,
            0,
            1,
            &x,
            &marker_digest(&x, 0),
            &trader.public_key,
            &trader.secret_key,
        )
        .await;
        let composed = compose_vault_state(
            &vault_id,
            &baseline,
            (1_000_000, 500_000),
            b"AAA",
            b"BBB",
            30,
        )
        .await
        .expect("compose succeeds");
        assert_eq!(composed.sequence, 0, "cursor stays at baseline");
        assert_eq!(composed.pending_chain_len, 0);
        assert_eq!(composed.pending_chain_skipped, 1);
    }

    #[tokio::test]
    async fn stops_at_sequence_gap() {
        let vault_id = vid_seed(0x14);
        let owner = generate_keypair(SphincsVariant::SPX256f).expect("owner kp");
        let trader = generate_keypair(SphincsVariant::SPX256f).expect("trader kp");
        let baseline = make_baseline(
            &vault_id,
            0,
            b"AAA",
            b"BBB",
            1_000_000,
            500_000,
            30,
            &owner.public_key,
            &owner.secret_key,
        );
        // Publish seq=1 and seq=3 but not seq=2 → chain breaks at the gap.
        for (parent, new, seed_byte) in [(0u64, 1u64, 0x51u8), (2, 3, 0x53)].iter() {
            let x = x_seed(*seed_byte);
            publish_synthetic_extcommit(&x, &trader.public_key).await;
            publish_pointer(
                &vault_id,
                *parent,
                *new,
                &x,
                &marker_digest(&x, 0),
                &trader.public_key,
                &trader.secret_key,
            )
            .await;
        }
        let composed = compose_vault_state(
            &vault_id,
            &baseline,
            (1_000_000, 500_000),
            b"AAA",
            b"BBB",
            30,
        )
        .await
        .expect("compose succeeds");
        assert_eq!(composed.sequence, 1, "advances through seq=1 then stops");
        assert_eq!(composed.pending_chain_len, 1);
        assert_eq!(composed.pending_chain_skipped, 1);
    }

    /// The headline scenario the Phase-6 plan targets: Alice (vault
    /// owner) is offline; Bob's trade has settled cryptographically
    /// (X published + pointer published); Carol comes along and
    /// computes a composed state — she should see sequence=1, not 0.
    /// This is the property that lets concurrent traders serialize
    /// against a vault without the owner online between trades.
    #[tokio::test]
    async fn multi_trader_serialization_without_owner_refresh() {
        let vault_id = vid_seed(0x99);
        // Alice owns the vault.
        let alice = generate_keypair(SphincsVariant::SPX256f).expect("alice kp");
        // Bob is trader 1, Carol is trader 2 (different keypairs to
        // emulate cross-device).
        let bob = generate_keypair(SphincsVariant::SPX256f).expect("bob kp");
        let _carol = generate_keypair(SphincsVariant::SPX256f).expect("carol kp");

        // Alice publishes the baseline anchor at seq=0.  Alice's chain
        // is the authority; everyone else sees this anchor on storage.
        let baseline = make_baseline(
            &vault_id,
            0,
            b"AAA",
            b"BBB",
            10_000,
            10_000,
            30,
            &alice.public_key,
            &alice.secret_key,
        );

        // Bob trades.  His RouteCommit settles; his X anchor and pending
        // pointer are published.  CRUCIALLY: Alice is offline — she does
        // NOT publish a refreshed anchor at seq=1.
        let bob_x = x_seed(0xBB);
        publish_synthetic_extcommit(&bob_x, &bob.public_key).await;
        publish_pointer(
            &vault_id,
            0,
            1,
            &bob_x,
            &marker_digest(&bob_x, 0),
            &bob.public_key,
            &bob.secret_key,
        )
        .await;

        // Carol composes.  She sees Alice's seq=0 baseline + Bob's
        // pending pointer = composed cursor at seq=1.  Concurrent
        // serialization without Alice's involvement.
        let composed =
            compose_vault_state(&vault_id, &baseline, (10_000, 10_000), b"AAA", b"BBB", 30)
                .await
                .expect("compose succeeds for Carol");
        assert_eq!(
            composed.sequence, 1,
            "Carol should see Bob's pending advance even though Alice is offline",
        );
        assert_eq!(composed.pending_chain_len, 1);
        assert_eq!(composed.pending_chain_skipped, 0);
    }

    #[tokio::test]
    async fn rejects_baseline_with_tampered_reserves_supplied() {
        let vault_id = vid_seed(0x15);
        let owner = generate_keypair(SphincsVariant::SPX256f).expect("owner kp");
        let baseline = make_baseline(
            &vault_id,
            0,
            b"AAA",
            b"BBB",
            1_000_000,
            500_000,
            30,
            &owner.public_key,
            &owner.secret_key,
        );
        // Supply DIFFERENT reserves than the baseline was signed over.
        let err = compose_vault_state(&vault_id, &baseline, (777_777, 888_888), b"AAA", b"BBB", 30)
            .await
            .err()
            .expect("composition rejects mismatched baseline_reserves");
        assert!(matches!(err, CompositionError::InvalidBaselineAnchor));
    }
}
