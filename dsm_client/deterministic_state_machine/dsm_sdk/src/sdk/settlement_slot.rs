// SPDX-License-Identifier: MIT OR Apache-2.0

//! First-writer protection over a vault's settlement slot — the SDK side of a
//! distributed, crash-fault-tolerant, ONE-SHOT quorum register.
//!
//! WHAT MUST BE IMPOSSIBLE. Two settlements — or a settlement and the owner's
//! close — receipted against the same parent sequence. Each would be
//! individually valid, and together they spend the same reserves twice. Nothing
//! downstream can undo that: a receipted settlement is final by construction,
//! which is the property that makes owner-offline finality work.
//!
//! So it is prevented, not resolved. A contestant CLAIMS the slot before it
//! advances, and an unclaimable slot fails closed while the trade is still just
//! bytes. The old shape of this module was a storage LISTING: "is my pointer
//! the only one under this prefix?" — a read against a system that is not
//! consensus. Under partition a trader and the close could each observe an
//! exclusive slot at K, and a trader's settlement final on its own chain plus an
//! owner release of the same reserves is value duplication — the exact boundary
//! this work exists to prevent. That implementation is deleted, not kept beside.
//!
//! THE REGISTER. Every member of the vault's canonical storage set (its
//! BIRTH set, read from the vault's signed anchor and resolved through the local
//! catalog — never from local config) performs write-once conditional acceptance
//! for `(vault_id, parent_sequence)`: the first claim bytes win, identical bytes
//! re-ack, different bytes are refused. A claimant WINS only when a quorum of
//! the set (`StorageSet::quorum()`, the one definition) accepted the SAME
//! envelope bytes. Quorums over one canonical set intersect and a member holds
//! one value per slot, so two conflicting claimants cannot both win. Failure to
//! reach quorum is NOT claimed, for everyone — liveness cost, safety kept:
//! contention fails everyone, deliberately, and there is no "lowest X wins"
//! (any such rule is grindable).
//!
//! WHAT IT IS NOT. Storage provides concurrency serialization for
//! mutually-unknown actors — never validity. Members verify claimant
//! attribution (the body key is the authenticated caller's) and nothing about
//! the settlement. Under the beta client model (protocol-conforming clients)
//! this yields exclusivity; a modified client that skips the claim is a
//! Byzantine-client case the beta model excludes (see the storage node docs).
//! Griefing — claim and vanish — wedges the parent: accepted for the controlled
//! beta, a launch blocker for a public market.
//!
//! BYTE DISCIPLINE. The claim envelope is signed once over the canonical body,
//! canonically encoded once, and RETAINED durably (`settlement_slot_claim_local`);
//! every retry and recovery replays those exact bytes. A member echoes its own
//! node id on every response; an acceptance counts only when that id is the
//! catalog member being contacted — "distinct members" is executable.
//!
//! A STORAGE ERROR IS A REFUSAL, NOT AN ABSENCE. If quorum cannot be reached,
//! the contestant does not know whether it holds the parent. Treating "I could
//! not ask" as "I hold it" is exactly how a partition becomes a double-spend.

use dsm::dlv::settlement_slot_claim::{
    claim_envelope_digest, decode_and_verify_settlement_slot_claim, sign_settlement_slot_claim,
    SettlementSlotClaimBody, VerifiedSettlementSlotClaim,
};

use crate::sdk::storage_set::StorageSet;

/// Evidence that this contestant holds a settlement slot: a quorum of the
/// vault's canonical set accepted exactly its claim bytes.
///
/// Returned only by [`claim_settlement_slot`] and constructible nowhere else,
/// so a settle/close path that takes one cannot be reached without having won
/// the register. Carries the tuple it attests to, so a claim for one slot
/// cannot be presented for another.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SettlementSlotClaim {
    vault_id: [u8; 32],
    parent_sequence: u64,
    x: [u8; 32],
    /// Members that accepted these exact bytes, out of the set's size.
    accepted: u32,
    total: u32,
}

impl SettlementSlotClaim {
    pub(crate) fn accepted(&self) -> u32 {
        self.accepted
    }
    pub(crate) fn total(&self) -> u32 {
        self.total
    }
    /// `true` when this claim is for exactly the settlement described.
    pub(crate) fn matches(&self, vault_id: &[u8; 32], parent_sequence: u64, x: &[u8; 32]) -> bool {
        self.vault_id == *vault_id && self.parent_sequence == parent_sequence && self.x == *x
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum SlotClaimError {
    /// Quorum could not be reached and no member reported a different holder:
    /// transport, auth, or too few members reachable. The contestant does not
    /// know whether it holds the parent, so it must not proceed.
    StorageUnavailable {
        accepted: u32,
        total: u32,
        detail: String,
    },
    /// At least one member holds DIFFERENT bytes for this slot and we did not
    /// reach quorum: another contestant is (or may be) ahead. This contestant
    /// loses and stops, with nothing moved and nothing to undo.
    Contested {
        refused_by: u32,
        accepted: u32,
        total: u32,
    },
    /// The frozen envelope does not describe the requested slot (internal
    /// contradiction — refuse before contacting anyone).
    EnvelopeMismatch,
}

impl std::fmt::Display for SlotClaimError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SlotClaimError::StorageUnavailable {
                accepted,
                total,
                detail,
            } => write!(
                f,
                "settlement-slot register did not reach quorum ({accepted}/{total} accepted) and \
                 no other holder was reported — contention is unknown, settlement must not \
                 proceed: {detail}"
            ),
            SlotClaimError::Contested {
                refused_by,
                accepted,
                total,
            } => write!(
                f,
                "settlement slot is held by another claim on {refused_by} member(s) \
                 ({accepted}/{total} accepted ours); re-quote at the next sequence"
            ),
            SlotClaimError::EnvelopeMismatch => write!(
                f,
                "frozen claim envelope does not describe the requested slot"
            ),
        }
    }
}

impl std::error::Error for SlotClaimError {}

/// A settlement-slot claim envelope that came OUT OF DURABLE STORAGE.
///
/// This type is the recovery boundary, and it exists because no observation
/// downstream can enforce the rule it enforces. SPHINCS+ signing here is
/// deterministic (`R = H(sk_prf || m)`), so a rebuilt claim is byte-identical
/// to a replayed one: nothing on the wire, in a digest, or in a test can tell
/// which happened. The guarantee therefore has to be that the machinery is
/// ABSENT rather than merely unused.
///
/// So there is exactly one constructor — [`FrozenClaimEnvelope::load`], which
/// reads bytes that are already retained — and [`claim_settlement_slot`]
/// accepts nothing else. A caller holding one of these cannot have built it,
/// and a caller with a signing key but no retained bytes cannot obtain one at
/// all. Making recovery re-sign a claim would mean changing this type, not
/// quietly editing a call site while every test stays green.
pub(crate) struct FrozenClaimEnvelope {
    bytes: Vec<u8>,
    verified: VerifiedSettlementSlotClaim,
}

impl FrozenClaimEnvelope {
    /// The ONLY constructor: the envelope retained for this slot, if any.
    ///
    /// Verified on the way out, so a caller cannot act on retained bytes that
    /// no longer decode or no longer describe the slot they were asked for.
    pub(crate) fn load(
        vault_id: &[u8; 32],
        parent_sequence: u64,
        x: &[u8; 32],
    ) -> Result<Option<Self>, dsm::types::error::DsmError> {
        use crate::storage::client_db::settlement_slot_claim_local as local;
        let Some(bytes) = local::get_frozen_claim(vault_id, parent_sequence, x).map_err(|e| {
            dsm::types::error::DsmError::storage(
                format!("frozen slot claim lookup: {e}"),
                None::<std::io::Error>,
            )
        })?
        else {
            return Ok(None);
        };
        let verified = decode_and_verify_settlement_slot_claim(&bytes).map_err(|e| {
            dsm::types::error::DsmError::invalid_operation(format!(
                "retained slot claim is not a valid envelope: {e}"
            ))
        })?;
        if verified.body.vault_id != *vault_id
            || verified.body.parent_sequence != parent_sequence
            || verified.body.x != *x
        {
            return Err(dsm::types::error::DsmError::invalid_operation(
                "retained slot claim describes a different slot — refusing",
            ));
        }
        Ok(Some(Self { bytes, verified }))
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The set this claim was frozen against — the client half of the
    /// three-way storage-set equality a resumed close re-establishes.
    pub(crate) fn storage_set_id(&self) -> [u8; 32] {
        self.verified.body.storage_set_id
    }
}

/// The claim envelope for `(vault_id, parent_sequence, x)` under `storage_set_id`,
/// signed by this device's canonical signing authority — RETAINED durably the
/// first time it is built, and returned byte-identically thereafter. Retries
/// and recovery must never re-sign: members compare exact bytes.
pub(crate) fn frozen_claim_envelope(
    vault_id: &[u8; 32],
    parent_sequence: u64,
    x: &[u8; 32],
    storage_set_id: &[u8; 32],
) -> Result<FrozenClaimEnvelope, dsm::types::error::DsmError> {
    use crate::storage::client_db::settlement_slot_claim_local as local;
    if let Some(retained) = FrozenClaimEnvelope::load(vault_id, parent_sequence, x)? {
        if retained.storage_set_id() != *storage_set_id {
            return Err(dsm::types::error::DsmError::invalid_operation(
                "retained slot claim describes a different set — refusing",
            ));
        }
        return Ok(retained);
    }
    let pk = crate::sdk::signing_authority::current_public_key()?;
    let sk = crate::sdk::signing_authority::current_secret_key()?;
    if pk.is_empty() || sk.is_empty() {
        return Err(dsm::types::error::DsmError::invalid_operation(
            "signing authority unavailable (wallet locked) — cannot sign a slot claim",
        ));
    }
    let body = SettlementSlotClaimBody {
        vault_id: *vault_id,
        parent_sequence,
        x: *x,
        claimant_public_key: pk,
        storage_set_id: *storage_set_id,
    };
    let bytes = sign_settlement_slot_claim(&body, &sk).map_err(|e| {
        dsm::types::error::DsmError::crypto(format!("sign slot claim: {e}"), None::<std::io::Error>)
    })?;
    local::put_frozen_claim(vault_id, parent_sequence, x, &bytes).map_err(|e| {
        dsm::types::error::DsmError::storage(
            format!("retain frozen slot claim: {e}"),
            None::<std::io::Error>,
        )
    })?;
    // Read it back rather than wrapping the bytes we just signed, so that what
    // is submitted is ALWAYS what storage holds — on the first attempt exactly
    // as on every later one. A retention that silently failed to persist
    // surfaces here, before the claim goes out, instead of at recovery.
    FrozenClaimEnvelope::load(vault_id, parent_sequence, x)?.ok_or_else(|| {
        dsm::types::error::DsmError::storage(
            "frozen slot claim did not persist — refusing to claim from memory",
            None::<std::io::Error>,
        )
    })
}

/// Submit the exact `frozen_envelope` to every member of `set` and decide:
/// `Ok` iff a quorum of the set accepted (or already held) exactly these bytes;
/// `Contested` if any member holds different bytes and quorum was not reached;
/// `StorageUnavailable` otherwise. Idempotent: replaying the same bytes re-acks
/// at members that hold them, so a crash-and-retry converges.
///
/// Call IMMEDIATELY BEFORE the value-moving advance. Everything after moves
/// value; everything before is reversible by stopping.
pub(crate) async fn claim_settlement_slot(
    set: &StorageSet,
    frozen_envelope: &FrozenClaimEnvelope,
    vault_id: &[u8; 32],
    parent_sequence: u64,
    x: &[u8; 32],
) -> Result<SettlementSlotClaim, SlotClaimError> {
    // Only a [`FrozenClaimEnvelope`] can be submitted, and the only way to hold
    // one is to have loaded it from storage — so no caller, on any path, can
    // hand this function a claim it just built.
    let frozen_envelope = frozen_envelope.as_bytes();
    // The envelope must describe the slot we are claiming and this set.
    let v = decode_and_verify_settlement_slot_claim(frozen_envelope)
        .map_err(|_| SlotClaimError::EnvelopeMismatch)?;
    if v.body.vault_id != *vault_id
        || v.body.parent_sequence != parent_sequence
        || v.body.x != *x
        || v.body.storage_set_id != set.id()
    {
        return Err(SlotClaimError::EnvelopeMismatch);
    }
    let our_digest = claim_envelope_digest(frozen_envelope);

    let fanout = crate::sdk::storage_io::submit_settlement_slot_claim(set, frozen_envelope)
        .await
        .map_err(|e| SlotClaimError::StorageUnavailable {
            accepted: 0,
            total: set.len() as u32,
            detail: format!("fan-out failed: {e}"),
        })?;

    let mut accepted = 0u32;
    let mut refused_by = 0u32;
    let mut details: Vec<String> = Vec::new();
    for o in &fanout.outcomes {
        // ATTRIBUTION IS A PRECONDITION OF COUNTING, on every path that counts.
        // Quorum means a majority of DISTINCT members hold these exact bytes,
        // and an outcome only says anything about a member if that member
        // named ITSELF in the reply. One node answering under another's id
        // would otherwise contribute twice to a majority that does not exist.
        let attributed = o.echoed_node_id.as_deref() == Some(o.member_id.as_str());
        match &o.result {
            crate::sdk::storage_node_sdk::MemberClaimResult::Accepted
            | crate::sdk::storage_node_sdk::MemberClaimResult::HeldIdentical => {
                if attributed {
                    accepted += 1;
                } else {
                    details.push(format!(
                        "{}: accepted but echoed {:?} — not counted",
                        o.member_id, o.echoed_node_id
                    ));
                }
            }
            crate::sdk::storage_node_sdk::MemberClaimResult::Refused { held_digest } => {
                if held_digest.as_deref() == Some(&our_digest[..]) {
                    // A member reporting OUR digest as "held" is holding our
                    // bytes — a re-ack expressed oddly. It is an ACCEPTANCE, so
                    // it carries the same attribution requirement as one; the
                    // current node never phrases a re-ack this way, and this
                    // arm exists so that a node which did could not slip an
                    // unattributed count past the check its siblings apply.
                    if attributed {
                        accepted += 1;
                    } else {
                        details.push(format!(
                            "{}: holds our claim but echoed {:?} — not counted",
                            o.member_id, o.echoed_node_id
                        ));
                    }
                } else {
                    // A refusal is NOT attributed on purpose: counting it makes
                    // this claim fail closed as Contested, so an unattributed
                    // one can only make us more conservative, never less.
                    refused_by += 1;
                }
            }
            crate::sdk::storage_node_sdk::MemberClaimResult::Unavailable(e) => {
                details.push(format!("{}: {e}", o.member_id));
            }
        }
    }
    let total = set.len() as u32;
    if accepted >= set.quorum() {
        return Ok(SettlementSlotClaim {
            vault_id: *vault_id,
            parent_sequence,
            x: *x,
            accepted,
            total,
        });
    }
    if refused_by > 0 {
        return Err(SlotClaimError::Contested {
            refused_by,
            accepted,
            total,
        });
    }
    Err(SlotClaimError::StorageUnavailable {
        accepted,
        total,
        detail: details.join("; "),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sdk::storage_io::fake_fleet;
    use crate::sdk::storage_set::StorageMember;
    use dsm::dlv::settlement_slot_claim::sign_settlement_slot_claim;
    use serial_test::serial;

    /// The THREE-member set these tests reason about, built explicitly.
    ///
    /// Deliberately not `StorageSetCatalog::from_env_config()`: quorum
    /// arithmetic over "however many members happen to be configured" is not a
    /// test of quorum arithmetic. Ambient config is also not stable inside one
    /// test binary — a fleet installed by any earlier test persists — so a set
    /// taken from it silently became a one-member set here, and every
    /// assertion about 2-of-3 splits passed or failed for reasons having
    /// nothing to do with the code under test. The functions under test take
    /// the set as a parameter, so naming it here is both hermetic and exact.
    fn init() -> StorageSet {
        unsafe {
            std::env::set_var("DSM_SDK_TEST_MODE", "1");
            std::env::remove_var("DSM_ENV_CONFIG_PATH");
        };
        crate::storage::client_db::reset_database_for_tests();
        crate::storage::client_db::init_database().expect("init db");
        fake_fleet::reset();
        StorageSet::new(
            (1..=3)
                .map(|i| StorageMember {
                    member_id: format!("test-{i}"),
                    endpoint: format!("http://127.0.0.1:808{i}"),
                })
                .collect(),
        )
        .expect("a three-member set")
    }

    /// Sign a claim, RETAIN it, and hand back the loaded envelope.
    ///
    /// The tests go through storage exactly as production does, because
    /// `claim_settlement_slot` accepts only a [`FrozenClaimEnvelope`] and the
    /// only way to hold one is to load it. A test-only constructor taking raw
    /// bytes would hand these tests the very capability the type exists to
    /// withhold, and the boundary would then be enforced everywhere except
    /// where it is exercised.
    fn envelope(sk: &[u8], pk: &[u8], set: &StorageSet, seq: u64, x: u8) -> FrozenClaimEnvelope {
        let bytes = sign_settlement_slot_claim(
            &SettlementSlotClaimBody {
                vault_id: [0x11; 32],
                parent_sequence: seq,
                x: [x; 32],
                claimant_public_key: pk.to_vec(),
                storage_set_id: set.id(),
            },
            sk,
        )
        .expect("sign");
        crate::storage::client_db::settlement_slot_claim_local::put_frozen_claim(
            &[0x11; 32],
            seq,
            &[x; 32],
            &bytes,
        )
        .expect("retain");
        FrozenClaimEnvelope::load(&[0x11; 32], seq, &[x; 32])
            .expect("load")
            .expect("retained")
    }

    /// Two contestants, three members: at most one reaches quorum, and the
    /// loser is told the slot is contested — nothing "unknown" about it.
    #[tokio::test]
    #[serial]
    async fn two_contestants_at_most_one_wins() {
        let set = init();
        let (pk_a, sk_a) = dsm::crypto::sphincs::generate_sphincs_keypair().unwrap();
        let (pk_b, sk_b) = dsm::crypto::sphincs::generate_sphincs_keypair().unwrap();
        let a = envelope(&sk_a, &pk_a, &set, 5, 0xA1);
        let b = envelope(&sk_b, &pk_b, &set, 5, 0xB2);
        let won = claim_settlement_slot(&set, &a, &[0x11; 32], 5, &[0xA1; 32])
            .await
            .expect("A claims first");
        assert_eq!((won.accepted(), won.total()), (3, 3));
        let lost = claim_settlement_slot(&set, &b, &[0x11; 32], 5, &[0xB2; 32])
            .await
            .expect_err("B is contested");
        assert!(
            matches!(lost, SlotClaimError::Contested { refused_by: 3, .. }),
            "{lost}"
        );
        // A's retry with the SAME bytes re-acks (idempotent).
        let again = claim_settlement_slot(&set, &a, &[0x11; 32], 5, &[0xA1; 32])
            .await
            .expect("A re-acks");
        assert_eq!(again.accepted(), 3);
    }

    /// Partition split: m1 accepts A, m2 accepts B, m3 accepts A ⇒ A wins 2/3,
    /// B is refused (2 members hold A) — never both.
    #[tokio::test]
    #[serial]
    async fn partition_split_yields_one_winner() {
        let set = init();
        let (pk_a, sk_a) = dsm::crypto::sphincs::generate_sphincs_keypair().unwrap();
        let (pk_b, sk_b) = dsm::crypto::sphincs::generate_sphincs_keypair().unwrap();
        let a = envelope(&sk_a, &pk_a, &set, 9, 0xA1);
        let b = envelope(&sk_b, &pk_b, &set, 9, 0xB2);
        // B reaches only test-2 first (test-1/test-3 down for B's attempt).
        fake_fleet::fail_member("test-1");
        fake_fleet::fail_member("test-3");
        let b_first = claim_settlement_slot(&set, &b, &[0x11; 32], 9, &[0xB2; 32])
            .await
            .expect_err("1/3 is not quorum");
        assert!(
            matches!(
                b_first,
                SlotClaimError::StorageUnavailable { accepted: 1, .. }
            ),
            "{b_first}"
        );
        // Now everyone is up; A claims: test-1 + test-3 accept, test-2 holds B.
        fake_fleet::heal_member("test-1");
        fake_fleet::heal_member("test-3");
        let a_res = claim_settlement_slot(&set, &a, &[0x11; 32], 9, &[0xA1; 32])
            .await
            .expect("A wins 2/3");
        assert_eq!(a_res.accepted(), 2);
        // B retries with everyone up: only test-2 holds B ⇒ contested, never a win.
        let b_retry = claim_settlement_slot(&set, &b, &[0x11; 32], 9, &[0xB2; 32])
            .await
            .expect_err("B cannot win");
        assert!(
            matches!(
                b_retry,
                SlotClaimError::Contested {
                    refused_by: 2,
                    accepted: 1,
                    ..
                }
            ),
            "{b_retry}"
        );
        // The minority conflicting row on test-2 is legal and permanent: it
        // still holds B's bytes.
        assert!(fake_fleet::slot_held_digest("test-2", &[0x11; 32], 9).is_some());
    }

    /// A node echoing another member's id does not count toward quorum.
    #[tokio::test]
    #[serial]
    async fn echo_mismatch_is_not_counted() {
        let set = init();
        let (pk, sk) = dsm::crypto::sphincs::generate_sphincs_keypair().unwrap();
        let a = envelope(&sk, &pk, &set, 2, 0xA1);
        fake_fleet::set_echo("test-1", Some("test-2"));
        fake_fleet::fail_member("test-3");
        let r = claim_settlement_slot(&set, &a, &[0x11; 32], 2, &[0xA1; 32])
            .await
            .expect_err("only test-2's own acceptance counts");
        assert!(
            matches!(r, SlotClaimError::StorageUnavailable { accepted: 1, .. }),
            "{r}"
        );
    }

    /// A RE-ACK PHRASED AS A REFUSAL IS STILL AN ACCEPTANCE, so it carries the
    /// same attribution requirement as one.
    ///
    /// A member answering `Refused` while naming OUR digest as the value it
    /// holds is holding our bytes. Counting it is correct — and counting it
    /// without checking who answered is not. Quorum means a majority of
    /// DISTINCT members hold these exact bytes; one node replying under
    /// another's id would otherwise contribute twice to a majority that does
    /// not exist, on the one acceptance path that never checked.
    ///
    /// The current node never phrases a re-ack this way. That is the reason to
    /// test it: the arm exists for a node that would, and such a node is
    /// precisely the one whose attribution cannot be taken on trust.
    #[tokio::test]
    #[serial]
    async fn a_refusal_holding_our_own_digest_still_needs_attribution() {
        let set = init();
        let (pk, sk) = dsm::crypto::sphincs::generate_sphincs_keypair().unwrap();
        let a = envelope(&sk, &pk, &set, 7, 0xA1);

        // First pass: every member takes our bytes, so every later answer is a
        // re-ack over the identical envelope.
        claim_settlement_slot(&set, &a, &[0x11; 32], 7, &[0xA1; 32])
            .await
            .expect("the first claim reaches quorum");

        // The retry: test-1 re-acks in the refusal phrasing AND names test-2 as
        // itself; test-3 is unreachable. Only test-2's own re-ack may count.
        fake_fleet::set_refuse_phrasing("test-1");
        fake_fleet::set_echo("test-1", Some("test-2"));
        fake_fleet::fail_member("test-3");
        let r = claim_settlement_slot(&set, &a, &[0x11; 32], 7, &[0xA1; 32])
            .await
            .expect_err("an unattributed re-ack must not complete a quorum");
        assert!(
            matches!(r, SlotClaimError::StorageUnavailable { accepted: 1, .. }),
            "{r}"
        );
    }

    /// An envelope for another slot or another set is refused before any
    /// member is contacted.
    #[tokio::test]
    #[serial]
    async fn envelope_must_describe_the_requested_slot_and_set() {
        let set = init();
        let (pk, sk) = dsm::crypto::sphincs::generate_sphincs_keypair().unwrap();
        let a = envelope(&sk, &pk, &set, 4, 0xA1);
        assert_eq!(
            claim_settlement_slot(&set, &a, &[0x11; 32], 5, &[0xA1; 32]).await,
            Err(SlotClaimError::EnvelopeMismatch)
        );
        assert!(fake_fleet::put_log().is_empty(), "no member was contacted");
    }
}
