// SPDX-License-Identifier: MIT OR Apache-2.0

//! First-writer protection over a vault's settlement slot.
//!
//! WHAT MUST BE IMPOSSIBLE. Two settlements receipted against the same parent
//! sequence. Each would be individually valid — correct conservation, correct
//! authorization, a genuine receipt — and together they spend the same reserves
//! twice. Nothing downstream can undo that: a receipted settlement is final by
//! construction, which is the property that makes owner-offline finality work.
//!
//! So it is prevented, not resolved. A trader claims the slot BEFORE it
//! advances, and an unclaimable slot fails closed while the trade is still just
//! bytes. Detecting the collision afterwards and picking a winner would mean one
//! of the two已 moved value.
//!
//! THE SLOT IS THE CANONICAL TUPLE `(vault_id, parent_sequence, X)`. Vault and
//! parent sequence name exactly the state being consumed; `X` names the trade
//! consuming it. The pending-pointer key already encodes all three
//! (`sofi/vault-pending/{vault}/{new_sequence}/{x}`), so the claim is a listing
//! of one slot prefix rather than a new record — the pointer a trader must
//! publish anyway IS the claim.
//!
//! CONTENTION FAILS EVERYONE, DELIBERATELY. When the slot holds any X but this
//! trader's, this trader stops. There is no "lowest X wins" rule, because any
//! such rule is grindable: a trader that can choose its X can choose to win.
//! Refusing on contention costs liveness — a contested slot means both traders
//! re-quote at the next sequence — and buys the safety property outright. That
//! is the correct direction for this trade to fail in.
//!
//! A STORAGE ERROR IS A REFUSAL, NOT AN ABSENCE. If the slot cannot be listed,
//! the trader does not know whether it is contested. Treating "I could not ask"
//! as "nobody else is there" is exactly how a partition becomes a double-spend,
//! and it is the more dangerous failure because it looks like the happy path.

use crate::sdk::bitcoin_tap_sdk::BitcoinTapSdk;
use crate::util::text_id::encode_base32_crockford;

/// Storage prefix for one settlement slot: every pointer published against the
/// same `(vault, parent_sequence)`.
///
/// `new_sequence` is `parent_sequence + 1` — the sequence a pointer names — so
/// the prefix is derived from the parent the trader is actually consuming
/// rather than from a number it supplies separately.
pub(crate) fn settlement_slot_prefix(vault_id: &[u8; 32], parent_sequence: u64) -> Option<String> {
    let new_sequence = parent_sequence.checked_add(1)?;
    Some(format!(
        "{}{}/{:016}/",
        crate::sdk::route_commit_sdk::VAULT_PENDING_ROOT,
        encode_base32_crockford(vault_id),
        new_sequence,
    ))
}

/// Evidence that this trader holds a settlement slot exclusively.
///
/// Returned only by [`claim_settlement_slot`] and constructible nowhere else,
/// so a settle path that takes one cannot be reached without having claimed.
/// "Receipt production only for the winner" becomes an obligation the compiler
/// carries rather than a comment asking the next caller to remember: the
/// receipt leaf is written solely by the `DlvSettle` advance, so if the advance
/// requires this, no unclaimed settlement can produce a receipt.
///
/// Deliberately carries the tuple it attests to, so a claim for one slot cannot
/// be presented for another.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SettlementSlotClaim {
    vault_id: [u8; 32],
    parent_sequence: u64,
    x: [u8; 32],
}

impl SettlementSlotClaim {
    pub(crate) fn vault_id(&self) -> [u8; 32] {
        self.vault_id
    }
    pub(crate) fn parent_sequence(&self) -> u64 {
        self.parent_sequence
    }
    pub(crate) fn x(&self) -> [u8; 32] {
        self.x
    }
    /// `true` when this claim is for exactly the settlement described.
    pub(crate) fn matches(&self, vault_id: &[u8; 32], parent_sequence: u64, x: &[u8; 32]) -> bool {
        self.vault_id == *vault_id && self.parent_sequence == parent_sequence && self.x == *x
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum SlotClaimError {
    /// The slot could not be listed. The trader does not know whether it is
    /// contested, so it must not proceed — "I could not ask" is not "nobody is
    /// there".
    StorageUnavailable(String),
    /// This trader's own pointer is not visible in the slot yet. Publishing the
    /// pointer is what claims the slot, so advancing before it is readable
    /// would be advancing on an unclaimed slot.
    NotClaimed,
    /// Another trade already occupies this slot. This trader loses and stops,
    /// with nothing moved and nothing to undo.
    Contested { others: usize },
    /// `parent_sequence` cannot be advanced.
    SequenceOverflow,
}

impl std::fmt::Display for SlotClaimError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SlotClaimError::StorageUnavailable(msg) => write!(
                f,
                "settlement slot could not be read, so contention is unknown and settlement must not proceed: {msg}"
            ),
            SlotClaimError::NotClaimed => write!(
                f,
                "this trader's pending pointer is not visible in the slot; publish it before settling"
            ),
            SlotClaimError::Contested { others } => write!(
                f,
                "settlement slot is already held by {others} other trade(s); re-quote at the next sequence"
            ),
            SlotClaimError::SequenceOverflow => {
                write!(f, "parent sequence cannot be advanced")
            }
        }
    }
}

impl std::error::Error for SlotClaimError {}

/// Confirm this trader holds the settlement slot for `(vault_id,
/// parent_sequence, x)`, exclusively.
///
/// Call IMMEDIATELY BEFORE the settling advance. Everything after it moves
/// value; everything before it is reversible by simply stopping.
///
/// Succeeds only when the slot listing contains exactly this trader's `X` and
/// nothing else. Every other outcome — unreadable, empty, or holding another
/// trade — is a refusal.
///
/// What this does NOT claim: that the slot cannot become contested a moment
/// later. It cannot, because storage is not a consensus system and this is a
/// read. What it gives is that two traders cannot BOTH observe an exclusive
/// slot and proceed — the second to publish sees the first, and the first sees
/// the second unless it had already advanced. The window where both see a clean
/// slot requires both listings to precede both publishes, which the
/// publish-then-claim ordering excludes.
pub(crate) async fn claim_settlement_slot(
    vault_id: &[u8; 32],
    parent_sequence: u64,
    x: &[u8; 32],
) -> Result<SettlementSlotClaim, SlotClaimError> {
    let prefix = settlement_slot_prefix(vault_id, parent_sequence)
        .ok_or(SlotClaimError::SequenceOverflow)?;
    let mine = encode_base32_crockford(x);

    // Page the whole slot. Stopping at the first page would let a contender
    // sitting past the page boundary go unseen, which is the same as not
    // checking at all for a slot that is busy enough to matter.
    let mut cursor: Option<String> = None;
    let mut mine_seen = false;
    let mut others = 0usize;
    loop {
        let resp = BitcoinTapSdk::storage_list_objects(&prefix, cursor.as_deref(), 256)
            .await
            .map_err(|e| SlotClaimError::StorageUnavailable(format!("{e}")))?;
        for item in &resp.items {
            // The key's last segment is the trade's X. Compare against the whole
            // segment, never a prefix: a truncated compare would let a crafted
            // key impersonate a claim.
            match item.key.rsplit('/').next() {
                Some(seg) if seg == mine => mine_seen = true,
                Some(seg) if !seg.is_empty() => others += 1,
                _ => {}
            }
        }
        if (resp.items.len() as u32) < 256 {
            break;
        }
        match resp.next_cursor {
            Some(c) => cursor = Some(c),
            None => break,
        }
    }

    if others > 0 {
        // Reported even when our own pointer is also present: another trade
        // holding the slot is decisive regardless of what else is there.
        return Err(SlotClaimError::Contested { others });
    }
    if !mine_seen {
        return Err(SlotClaimError::NotClaimed);
    }
    Ok(SettlementSlotClaim {
        vault_id: *vault_id,
        parent_sequence,
        x: *x,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sdk::route_commit_sdk::vault_pending_pointer_key;

    fn vid(b: u8) -> [u8; 32] {
        [b; 32]
    }
    fn x_of(b: u8) -> [u8; 32] {
        [b; 32]
    }

    async fn put_pointer(vault_id: &[u8; 32], parent_sequence: u64, x: &[u8; 32]) {
        let key = vault_pending_pointer_key(vault_id, parent_sequence + 1, x);
        BitcoinTapSdk::storage_put_bytes(&key, b"pointer-bytes")
            .await
            .expect("publish pointer");
    }

    /// The slot prefix is derived from the PARENT the trader consumes, so it
    /// cannot be aimed at a different state by supplying a separate number.
    #[test]
    fn the_slot_is_the_canonical_tuple() {
        let v = vid(0x11);
        assert_eq!(
            settlement_slot_prefix(&v, 7),
            settlement_slot_prefix(&v, 7),
            "deterministic"
        );
        assert_ne!(settlement_slot_prefix(&v, 7), settlement_slot_prefix(&v, 8));
        assert_ne!(
            settlement_slot_prefix(&v, 7),
            settlement_slot_prefix(&vid(0x22), 7)
        );
        assert_eq!(
            settlement_slot_prefix(&v, u64::MAX),
            None,
            "a parent that cannot advance has no slot"
        );
        // A pointer published for parent 7 lands under parent 7's slot.
        let prefix = settlement_slot_prefix(&v, 7).expect("prefix");
        assert!(vault_pending_pointer_key(&v, 8, &x_of(0xAA)).starts_with(&prefix));
        assert!(!vault_pending_pointer_key(&v, 9, &x_of(0xAA)).starts_with(&prefix));
    }

    #[tokio::test]
    async fn an_exclusive_slot_is_claimable() {
        let (v, x) = (vid(0x30), x_of(0xA1));
        put_pointer(&v, 5, &x).await;
        claim_settlement_slot(&v, 5, &x)
            .await
            .expect("a trader alone in its slot may settle");
    }

    /// THE DOUBLE-SETTLE CASE. Two traders, one parent. The second must be
    /// refused before it advances — not reconciled afterwards, because a
    /// receipted settlement is final and there is nothing to reconcile.
    #[tokio::test]
    async fn a_contested_slot_refuses_both_rather_than_picking_a_winner() {
        let v = vid(0x31);
        let (alice, bob) = (x_of(0xA1), x_of(0xB2));
        put_pointer(&v, 5, &alice).await;
        put_pointer(&v, 5, &bob).await;

        // Neither may proceed. A "lowest X wins" rule would be grindable: a
        // trader that chooses its X can choose to win.
        for (who, x) in [("alice", alice), ("bob", bob)] {
            let err = claim_settlement_slot(&v, 5, &x)
                .await
                .expect_err("{who} must not settle a contested slot");
            assert!(
                matches!(err, SlotClaimError::Contested { others: 1 }),
                "{who} must see the contention explicitly, got {err:?}"
            );
        }
    }

    /// A trader that has not published its pointer has not claimed anything.
    /// Advancing here would be advancing on an unclaimed slot.
    #[tokio::test]
    async fn an_unpublished_pointer_claims_nothing() {
        let v = vid(0x32);
        let err = claim_settlement_slot(&v, 5, &x_of(0xA1))
            .await
            .expect_err("an empty slot is not a claim");
        assert_eq!(err, SlotClaimError::NotClaimed);
    }

    /// The claim names the slot it attests to, so one cannot be presented for
    /// another settlement.
    #[tokio::test]
    #[serial_test::serial]
    async fn a_claim_attests_to_its_own_slot_only() {
        let (v, x) = (vid(0x37), x_of(0xA1));
        put_pointer(&v, 5, &x).await;
        let claim = claim_settlement_slot(&v, 5, &x).await.expect("claim");
        assert!(claim.matches(&v, 5, &x));
        assert!(!claim.matches(&v, 6, &x), "not a claim on another sequence");
        assert!(
            !claim.matches(&vid(0x38), 5, &x),
            "not a claim on another vault"
        );
        assert!(
            !claim.matches(&v, 5, &x_of(0xB2)),
            "not a claim on another trade"
        );
        assert_eq!(
            (claim.vault_id(), claim.parent_sequence(), claim.x()),
            (v, 5, x)
        );
    }

    /// DRIVEN CONCURRENTLY, not asserted in prose.
    ///
    /// Two traders publish and claim against one parent with their operations
    /// interleaved by the runtime. Whatever the interleaving, the run must never
    /// end with both holding the slot — that is the state from which two
    /// receipted settlements would follow, and a receipted settlement cannot be
    /// undone.
    ///
    /// At most one winner, possibly none: if both publish before either claims,
    /// both correctly refuse and re-quote. Zero winners is a liveness cost;
    /// two winners is a double-spend.
    #[tokio::test]
    #[serial_test::serial]
    async fn two_traders_racing_one_parent_never_both_win() {
        for round in 0u8..24 {
            let v = vid(0x40u8.wrapping_add(round));
            let (alice, bob) = (x_of(0xA1), x_of(0xB2));

            // Interleave differently each round so the race is actually varied
            // rather than the same ordering repeated.
            let (first, second) = if round % 2 == 0 {
                (alice, bob)
            } else {
                (bob, alice)
            };

            let a = async {
                put_pointer(&v, 5, &first).await;
                claim_settlement_slot(&v, 5, &first).await
            };
            let b = async {
                put_pointer(&v, 5, &second).await;
                claim_settlement_slot(&v, 5, &second).await
            };
            let (ra, rb) = tokio::join!(a, b);

            let winners = [&ra, &rb].iter().filter(|r| r.is_ok()).count();
            assert!(
                winners <= 1,
                "round {round}: {winners} traders claimed one slot — that is the double-settle state"
            );
            for r in [&ra, &rb] {
                if let Err(e) = r {
                    assert!(
                        matches!(
                            e,
                            SlotClaimError::Contested { .. } | SlotClaimError::NotClaimed
                        ),
                        "round {round}: a loser must fail on the slot itself, got {e:?}"
                    );
                }
            }
        }
    }

    /// The loser stops while the trade is still bytes. Nothing it published is
    /// consuming: an unreceipted pointer is inert, so a refused claim leaves the
    /// vault exactly as it was and the loser has nothing to undo.
    #[tokio::test]
    #[serial_test::serial]
    async fn a_refused_claim_leaves_nothing_to_undo() {
        let v = vid(0x60);
        let (winner, loser) = (x_of(0xA1), x_of(0xB2));
        put_pointer(&v, 5, &winner).await;
        put_pointer(&v, 5, &loser).await;

        // Both refuse, so neither reaches the settling advance — and the
        // advance is the only thing that writes a receipt leaf. No claim, no
        // advance, no receipt: the winner-only property holds structurally
        // rather than by a separate check.
        assert!(claim_settlement_slot(&v, 5, &winner).await.is_err());
        assert!(claim_settlement_slot(&v, 5, &loser).await.is_err());

        // The slot is still exactly what was published; refusing wrote nothing.
        let prefix = settlement_slot_prefix(&v, 5).expect("prefix");
        let listed = BitcoinTapSdk::storage_list_objects(&prefix, None, 256)
            .await
            .expect("list");
        assert_eq!(
            listed.items.len(),
            2,
            "a refusal must not add, remove or rewrite anything in the slot"
        );
    }

    /// A STORAGE ERROR IS A REFUSAL. The trader could not ask whether the slot
    /// is contested, so it does not know — and "I could not ask" read as
    /// "nobody is there" is how a partition becomes a double-spend. This is the
    /// more dangerous failure precisely because it otherwise looks like the
    /// happy path.
    #[tokio::test]
    #[serial_test::serial]
    async fn an_unreadable_slot_refuses_rather_than_assuming_it_is_free() {
        let (v, x) = (vid(0x36), x_of(0xA1));
        // The pointer IS published — so if the listing failure were treated as
        // an empty result, this call would wrongly succeed on a real claim.
        put_pointer(&v, 5, &x).await;
        claim_settlement_slot(&v, 5, &x)
            .await
            .expect("readable slot is claimable");

        BitcoinTapSdk::set_dbtc_storage_list_results([Err("node unreachable".to_string())]);
        let err = claim_settlement_slot(&v, 5, &x)
            .await
            .expect_err("an unreadable slot must refuse");
        assert!(
            matches!(err, SlotClaimError::StorageUnavailable(_)),
            "must refuse as unreadable, not as free or as contested: {err:?}"
        );
        assert!(
            format!("{err}").contains("must not proceed"),
            "the message must say settlement is refused, not merely that a read failed"
        );

        // The queue is drained; the slot reads normally again.
        claim_settlement_slot(&v, 5, &x)
            .await
            .expect("recovered storage claims normally");
    }

    /// Slots do not bleed across sequences: a claim at parent 5 says nothing
    /// about parent 6, and vice versa.
    #[tokio::test]
    async fn a_claim_is_scoped_to_its_parent_sequence() {
        let (v, x) = (vid(0x33), x_of(0xA1));
        put_pointer(&v, 5, &x).await;
        claim_settlement_slot(&v, 5, &x)
            .await
            .expect("parent 5 held");
        assert_eq!(
            claim_settlement_slot(&v, 6, &x).await,
            Err(SlotClaimError::NotClaimed),
            "holding parent 5 must not imply holding parent 6"
        );
    }

    /// Another vault's traffic is not this vault's contention.
    #[tokio::test]
    async fn another_vaults_slot_does_not_contend() {
        let (mine, theirs) = (vid(0x34), vid(0x35));
        let x = x_of(0xA1);
        put_pointer(&mine, 5, &x).await;
        put_pointer(&theirs, 5, &x_of(0xB2)).await;
        claim_settlement_slot(&mine, 5, &x)
            .await
            .expect("a different vault's pointer is not contention");
    }
}
