// SPDX-License-Identifier: MIT OR Apache-2.0

//! Rebuild a vault's operational state after a restart.
//!
//! The runtime vault object is NOT serialized. It is reconstructed from two
//! authoritative sources that already survive a restart:
//!
//! - the canonical record ([`AmmVaultRecord`]) — identity, pair, fee, anchor
//!   policy, the CPTA digest;
//! - the owner's reserve leaves — the amounts AND the sequence, since every
//!   reserve write stamps the vault's sequence into the leaf value and the
//!   device-head codec persists it.
//!
//! Serializing the whole struct would have made a second copy of facts the
//! device root already authenticates, and a second copy is a second answer: when
//! the blob and the leaves disagreed, nothing would say which was right. Here
//! the leaves win by construction, because they are the only place those numbers
//! are written.
//!
//! NOTHING IS REPAIRED. Every gap makes the vault UNAVAILABLE:
//!
//! - no record → not a vault, whatever leaves exist;
//! - malformed record → not a vault;
//! - a leg with no reserve entry → not a funded vault;
//! - legs disagreeing on sequence → an incoherent vault;
//! - an anchor-enforcement value this build does not know → not a vault.
//!
//! The defaults that would "fix" these are exactly the dangerous ones. Sequence
//! defaulting to 0 makes a traded vault look untraded, so every `Required`
//! anchor gate mismatches and — since reserve proofs are fetched at an exact
//! sequence — the vault's own liquidity becomes unprovable. Enforcement
//! defaulting to permissive drops the gate a user asked for. Both turn missing
//! reconstruction data into a vault trading under rules nobody chose.

use dsm::types::device_state::DeviceState;

use crate::storage::client_db::amm_vault_records::AmmVaultRecord;

/// A vault's operational state, rebuilt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RehydratedVault {
    pub vault_id: [u8; 32],
    /// Canonical pair, lex-sorted over the policy commits.
    pub pair: dsm::dlv::pair_identity::CanonicalPair,
    /// From the record, but only after the vault-state leaf has been recomputed
    /// from it and matched — a fee this device never committed cannot reach a
    /// quote. Foreign verification of the fee is the signed baseline's job.
    pub fee_bps: u32,
    /// DERIVED, DISPLAY-ONLY. Always the canonical `Required`: anchor binding
    /// is unconditional in the code that enforces it, so there is no per-vault
    /// posture to restore. The persisted column is NOT read to produce this —
    /// that is the whole point of the retirement. Kept so the vault summary the
    /// UI already renders does not change shape.
    pub anchor_enforcement: i32,
    pub policy_digest: [u8; 32],
    /// Read from the leaves, not from the record.
    pub current_sequence: u64,
    pub reserve_a: u64,
    pub reserve_b: u64,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum RehydrationError {
    /// The record's pair is not a canonical pair of policy commits.
    RecordNotCanonical,
    /// The record names an owner that is not this device. Its reserve leaves
    /// live under a different key space and could not be located, so accepting
    /// it would produce a vault with no reserves rather than a wrong one — but
    /// naming the mismatch is more useful than reporting empty legs.
    OwnerMismatch,
    /// A leg of the pair has no reserve entry. A vault missing a side is not a
    /// funded vault, and treating the absence as zero would let it advertise
    /// and quote as if it were merely empty.
    LegNotFunded { policy_commit: [u8; 32] },
    /// The two legs were last written at different sequences. They are written
    /// together in one batch, so this cannot happen to a coherent vault and
    /// must not be resolved by picking one.
    LegSequencesDisagree { a: u64, b: u64 },
    /// The head holds reserve legs for this vault but the device root commits
    /// no vault-state leaf for it. `advance` writes that leaf on every funding
    /// and every settlement, so its absence means these legs were not produced
    /// by a vault transition — there is nothing to check the record against.
    VaultStateLeafMissing,
    /// The record disagrees with the vault-state leaf this device wrote. The
    /// leaf folds the pair, the fee and both reserves at this generation into
    /// one value; recomputing it from the record and the legs must reproduce it
    /// exactly. The fee is the field this catches on its own: nothing else in
    /// the reconstruction would notice a row claiming a fee the device never
    /// committed, and a vault quoting at it would charge a rate its own state
    /// does not carry.
    RecordDisagreesWithRoot,
}

impl std::fmt::Display for RehydrationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RehydrationError::RecordNotCanonical => {
                write!(f, "vault record pair is not a canonical policy-commit pair")
            }
            RehydrationError::OwnerMismatch => write!(
                f,
                "vault record names a different owner than this device; its reserve leaves are not here"
            ),
            RehydrationError::LegNotFunded { .. } => write!(
                f,
                "a leg of this vault has no reserve entry; an unfunded side is not a zero balance"
            ),
            RehydrationError::LegSequencesDisagree { a, b } => write!(
                f,
                "vault legs were last written at different sequences ({a} vs {b}); the vault is incoherent"
            ),
            RehydrationError::VaultStateLeafMissing => write!(
                f,
                "the device root commits no vault-state leaf for this vault; its reserve legs were not written by a vault transition"
            ),
            RehydrationError::RecordDisagreesWithRoot => write!(
                f,
                "the vault record disagrees with the device root (pair, fee or reserves at this generation); the root is the authority, not the row"
            ),
        }
    }
}

impl std::error::Error for RehydrationError {}

/// Rebuild one vault from its record and the device head.
///
/// The head supplies reserves and sequence; the record supplies everything the
/// leaves cannot express. Fails closed on every gap — see [`RehydrationError`].
pub(crate) fn rehydrate_amm_vault(
    record: &AmmVaultRecord,
    head: &DeviceState,
) -> Result<RehydratedVault, RehydrationError> {
    let pair = dsm::dlv::pair_identity::CanonicalPair::parse(
        &record.policy_commit_a,
        &record.policy_commit_b,
    )
    .map_err(|_| RehydrationError::RecordNotCanonical)?;
    // The record stores the pair already sorted; a row claiming otherwise is a
    // row written by something that did not canonicalise, so it is not trusted
    // to have canonicalised anything else either.
    if pair.a() != record.policy_commit_a || pair.b() != record.policy_commit_b {
        return Err(RehydrationError::RecordNotCanonical);
    }
    if record.owner_genesis != head.genesis() || record.owner_devid != head.devid() {
        return Err(RehydrationError::OwnerMismatch);
    }
    // `record.anchor_enforcement` is deliberately NOT read. It is deprecation
    // residue; the posture below is a constant.

    // Absence is distinguished from zero. `vault_reserve` would answer 0 for
    // both, which is exactly the conflation that lets an unfunded vault look
    // like an empty one.
    let leg_a = head
        .vault_reserve_entry(&record.vault_id, &pair.a())
        .ok_or(RehydrationError::LegNotFunded {
            policy_commit: pair.a(),
        })?;
    let leg_b = head
        .vault_reserve_entry(&record.vault_id, &pair.b())
        .ok_or(RehydrationError::LegNotFunded {
            policy_commit: pair.b(),
        })?;
    if leg_a.sequence != leg_b.sequence {
        return Err(RehydrationError::LegSequencesDisagree {
            a: leg_a.sequence,
            b: leg_b.sequence,
        });
    }

    // THE ROW MUST AGREE WITH THE LEAF THE TRANSITION WROTE.
    //
    // Everything above reads the record for the pair and the fee, and the
    // leaves for the reserves, and never compares the two. `advance` folds
    // (generation, pair, fee, both reserves) into a vault-state leaf on every
    // funding and every settlement, so recompute that leaf from the record's
    // own fields and the legs this head holds — with the SAME derivation the
    // transition used, `VaultStatePair::reserves_digest` — and require it to
    // match.
    //
    // The fee is why this matters. The reserves and the generation come from
    // the leaves and cannot drift, and a wrong pair leg already failed above as
    // unfunded; nothing else in the reconstruction would notice a row claiming
    // a fee the device never committed, and the vault would quote, advertise
    // and settle at it.
    //
    // WHAT THIS IS NOT. It is a coherence check between two local stores — the
    // record row and this device's own leaf map — not an authority proof. The
    // head is persisted in the same local database as the row, and its load
    // check is self-consistency (`bcr`: encoded root vs recomputed), so an
    // adversary able to rewrite both can make them agree. Nor is it an
    // inclusion proof: `extra_leaves` is a superset of the SMT's live leaves,
    // which evict FIFO past the tree's bound (the direction that cannot cause a
    // false refusal). The fee's foreign-verifiable authority is the SIGNED
    // baseline CCB, checked in `vault_state_composition` against
    // `baseline_state.fee_policy`. What this gate buys is that a stale,
    // desynced or partially-edited row cannot reach a quote.
    let committed = head
        .extra_leaves_snapshot()
        .get(&dsm::dlv::vault_smt_leaf::compute_vault_smt_key(
            &record.vault_id,
        ))
        .copied()
        .ok_or(RehydrationError::VaultStateLeafMissing)?;
    // `from_pair` is documented as the only production source and cannot fail:
    // the pair was parsed canonical above, which is exactly its precondition.
    let state_pair = dsm::types::device_state::VaultStatePair::from_pair(&pair, record.fee_bps);
    if committed
        != dsm::dlv::vault_smt_leaf::compute_vault_smt_value(
            leg_a.sequence,
            &state_pair.reserves_digest(leg_a.amount, leg_b.amount),
        )
    {
        return Err(RehydrationError::RecordDisagreesWithRoot);
    }

    Ok(RehydratedVault {
        vault_id: record.vault_id,
        pair,
        fee_bps: record.fee_bps,
        // DERIVED, never restored: binding is unconditional, so this is the
        // only posture in force regardless of what the row holds.
        anchor_enforcement: dsm::types::proto::AnchorEnforcement::Required as i32,
        policy_digest: record.policy_digest,
        // From the leaves. Both legs agree, checked above.
        current_sequence: leg_a.sequence,
        reserve_a: leg_a.amount,
        reserve_b: leg_b.amount,
    })
}

/// Rebuild every persisted vault. A vault that cannot be rebuilt is omitted and
/// logged — it becomes unavailable rather than degraded, which is the whole
/// point of refusing to repair.
pub(crate) fn rehydrate_all_amm_vaults(head: &DeviceState) -> Vec<RehydratedVault> {
    let records = match crate::storage::client_db::amm_vault_records::list_amm_vault_records() {
        Ok(r) => r,
        Err(e) => {
            log::warn!("[vault-rehydrate] record listing failed, no vaults restored: {e}");
            return Vec::new();
        }
    };
    let mut out = Vec::with_capacity(records.len());
    for rec in records {
        match rehydrate_amm_vault(&rec, head) {
            Ok(v) => out.push(v),
            Err(e) => log::warn!(
                "[vault-rehydrate] vault {} unavailable: {e}",
                crate::util::text_id::encode_base32_crockford(&rec.vault_id),
            ),
        }
    }
    out
}

/// The external commitments of settlements published against `vault_id` that
/// this owner has not folded yet.
///
/// "Unapplied" is read from the LEAVES, the same way `dlv.reconcile` decides
/// idempotence: a settlement counts while the reserve leaf still sits below the
/// sequence its receipt would advance to. There is no bookkeeping table to
/// drift out of step with the state.
///
/// A pointer with no valid receipt is skipped, not counted. Publishing a
/// pointer must never, by itself, make an owner believe value is owed — that is
/// the whole reason pointers are inert until a receipt witnesses them.
///
/// A storage failure yields an empty list and a warning: the owner is told
/// nothing is outstanding only when nothing could be READ, which understates
/// rather than invents. Reconciliation is not time-critical, and inventing a
/// settlement is worse than showing one late.
pub(crate) async fn unapplied_settlements_for_vault(
    vault_id: &[u8; 32],
    head: &DeviceState,
) -> Vec<[u8; 32]> {
    use crate::sdk::bitcoin_tap_sdk::BitcoinTapSdk;
    let prefix = crate::sdk::route_commit_sdk::vault_pending_prefix(vault_id);
    let mut cursor: Option<String> = None;
    // (new_sequence, x): ORDERED by generation before returning. A fold consumes
    // exactly the current parent (the reserve leaf's `parent_sequence` claim),
    // so the owner must fold generation N before N+1; the storage key layout
    // happens to sort that way, but the order is a protocol requirement, not a
    // property of a path string, so it is made explicit here.
    let mut out: Vec<(u64, [u8; 32])> = Vec::new();
    loop {
        let resp = match BitcoinTapSdk::storage_list_objects(&prefix, cursor.as_deref(), 256).await
        {
            Ok(r) => r,
            Err(e) => {
                log::warn!("[vault-pending] listing {prefix} failed, reporting none: {e}");
                return Vec::new();
            }
        };
        for item in &resp.items {
            // The trade is the last path segment.
            let Some(seg) = item.key.rsplit('/').next() else {
                continue;
            };
            let Some(x_bytes) = crate::util::text_id::decode_base32_crockford(seg) else {
                continue;
            };
            let Ok(x) = <[u8; 32]>::try_from(x_bytes.as_slice()) else {
                continue;
            };
            // Inert without a verified receipt.
            let Some(receipt) =
                crate::sdk::settlement_receipt_codec::fetch_verified_receipt(vault_id, &x).await
            else {
                continue;
            };
            let applied = head
                .vault_reserve_entry(vault_id, &receipt.trade.input_policy_commit)
                .map(|e| e.sequence >= receipt.trade.new_sequence)
                .unwrap_or(false);
            if !applied && !out.iter().any(|(_, seen)| *seen == x) {
                out.push((receipt.trade.new_sequence, x));
            }
        }
        match resp.next_cursor {
            Some(c) if !c.is_empty() => cursor = Some(c),
            _ => break,
        }
    }
    out.sort_by_key(|(seq, _)| *seq);
    out.into_iter().map(|(_, x)| x).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::client_db::amm_vault_records::{get_amm_vault_record, put_amm_vault_record};
    use serial_test::serial;

    fn init_test_db() {
        unsafe { std::env::set_var("DSM_SDK_TEST_MODE", "1") };
        crate::storage::client_db::reset_database_for_tests();
        crate::storage::client_db::init_database().expect("init db");
    }

    const REQUIRED: i32 = dsm::types::proto::AnchorEnforcement::Required as i32;

    const GENESIS: [u8; 32] = [0u8; 32];
    const DEVID: [u8; 32] = [0xB0u8; 32];

    /// The fixture device's REAL signing keypair, generated once (SPHINCS+
    /// keygen is slow).
    ///
    /// A head's `public_key` is what `advance` verifies a funded create and an
    /// owner-apply against, so a placeholder key cannot authorize its own
    /// transitions: the head must carry the mate of the key that signs.
    fn identity() -> &'static (Vec<u8>, Vec<u8>) {
        static KP: std::sync::OnceLock<(Vec<u8>, Vec<u8>)> = std::sync::OnceLock::new();
        KP.get_or_init(|| {
            dsm::crypto::sphincs::generate_sphincs_keypair().expect("fixture keypair")
        })
    }

    /// A real device head holding NOTHING — genesis, before any value.
    fn empty_head() -> DeviceState {
        DeviceState::new(GENESIS, DEVID, identity().0.clone(), 1024)
    }

    /// A head holding `legs`, where every unit entered through an ADMITTED
    /// origin: one `admitted_mint` per asset, each an admitted, fenced
    /// `advance` on the device's own self-loop. Nothing here invents a
    /// balance — the head is returned as an admitted head stands after
    /// `finish_admission`, carrying no pending admission.
    fn admitted_holding(legs: &[([u8; 32], u64)]) -> DeviceState {
        let mut head = empty_head();
        for (i, (pc, amount)) in legs.iter().enumerate() {
            head = head
                .admitted_mint(*pc, *amount, 0xA0 + i as u8)
                .expect("admitted issuance");
        }
        head.with_pending_economic_admission(None)
    }

    /// A funded vault, advanced past sequence zero, under `Required`
    /// enforcement — the state a restart has to reproduce.
    ///
    /// Every step is a production transition through `advance`: admitted
    /// issuance of both legs, a SIGNED `DlvCreateFundedV2` carrying the `Fund`
    /// mutation, then a SIGNED `DlvOwnerApplyV2` carrying the settlement fold
    /// that moves the vault to generation 1 — the same operation
    /// `dlv.reconcile` builds.
    fn funded_and_advanced() -> (AmmVaultRecord, DeviceState) {
        use dsm::types::device_state::{VaultReserveMutation, VaultStatePair};
        use dsm::types::operations::{Operation, TransactionMode};

        let (pc_a, pc_b) = ([0x11u8; 32], [0x22u8; 32]);
        let vault_id = [0x77u8; 32];
        let (_, sk) = identity();
        let head = admitted_holding(&[(pc_a, 50_000), (pc_b, 20_000)])
            .admitted_funded_create(vault_id, [(pc_a, 10_000), (pc_b, 5_000)], 30, sk, 0xA2)
            .expect("admitted funded create");

        // Advance past zero the way a settlement does: one owner-apply through
        // `advance`, which verifies the signature against this head's own key,
        // checks the fold against the vault's pair, and moves the legs and the
        // vault-state leaf together.
        let (rel_key, tip) = (
            dsm::core::bilateral_transaction_manager::compute_smt_key(&DEVID, &DEVID),
            dsm::core::bilateral_transaction_manager::initial_chain_tip_from_device_ids(
                &DEVID, &DEVID,
            ),
        );
        let pair = VaultStatePair::new(pc_a, pc_b, 30).expect("canonical pair");
        let unsigned = Operation::DlvOwnerApplyV2 {
            vault_id: vault_id.to_vec(),
            settlement_receipt_id: [0x77; 32],
            pending_pointer_x: [0x55; 32],
            parent_sequence: 0,
            new_sequence: 1,
            input_policy_commit: pc_a,
            output_policy_commit: pc_b,
            input_amount: 1_000,
            output_amount: 970,
            parent_binding: [0x23; 32],
            fee_bps: 30,
            signature: Vec::new(),
            mode: TransactionMode::Bilateral,
        };
        let signature =
            dsm::crypto::sphincs::sphincs_sign(sk, &unsigned.with_cleared_signature().to_bytes())
                .expect("sign the owner apply");
        let head = head
            .advance(
                rel_key,
                DEVID,
                unsigned.with_signature(signature),
                vec![0xA3; 32],
                None,
                &[],
                Some(tip),
                None,
                None,
                Some(VaultReserveMutation::ApplySettlement {
                    vault_id,
                    input_policy_commit: pc_a,
                    input_amount: 1_000,
                    output_policy_commit: pc_b,
                    output_amount: 970,
                    parent_sequence: 0,
                    new_sequence: 1,
                    pair,
                }),
            )
            .expect("owner apply")
            .new_device_state
            // The admission that authorized the create is settled by the time a
            // head is persisted; a restart reloads it with none in flight.
            .with_pending_economic_admission(None);

        let record = AmmVaultRecord {
            vault_id,
            owner_genesis: head.genesis(),
            owner_devid: head.devid(),
            policy_commit_a: pc_a,
            policy_commit_b: pc_b,
            fee_bps: 30,
            anchor_enforcement: REQUIRED,
            policy_digest: [0x5A; 32],
            storage_set_id: [0x6B; 32],
            baseline_state_ccb: Vec::new(),
            baseline_presentation: Vec::new(),
            vault_post_proto: Vec::new(),
        };
        (record, head)
    }

    /// Simulate a restart: the head goes through the real persistence codec and
    /// comes back, and the record goes through SQLite.
    fn restart(record: &AmmVaultRecord, head: &DeviceState) -> (AmmVaultRecord, DeviceState) {
        put_amm_vault_record(record).expect("persist record");
        let bytes = crate::storage::client_db::bcr::encode_device_state(head);
        let (reloaded, _) =
            crate::storage::client_db::bcr::decode_device_state(&bytes, None).expect("decode head");
        let rec = get_amm_vault_record(&record.vault_id)
            .expect("read")
            .expect("record survived");
        (rec, reloaded)
    }

    /// THE GATE-4 PROOF. Create, fund, advance past zero, use `Required`,
    /// restart, rehydrate — and every operational value is identical.
    #[test]
    #[serial]
    fn a_restart_reproduces_sequence_enforcement_reserves_and_root() {
        init_test_db();
        let (record, head) = funded_and_advanced();
        let before = rehydrate_amm_vault(&record, &head).expect("rehydrate before restart");

        let root_before = head.root();
        let (rec2, head2) = restart(&record, &head);
        let after = rehydrate_amm_vault(&rec2, &head2).expect("rehydrate after restart");

        assert_eq!(
            head2.root(),
            root_before,
            "the device root must survive the codec, or nothing below it means anything"
        );
        assert_eq!(after, before, "the whole operational state is identical");
        assert_eq!(after.current_sequence, 1, "NOT reset to zero");
        assert_eq!(
            after.anchor_enforcement, REQUIRED,
            "NOT downgraded to permissive"
        );
        assert_eq!((after.reserve_a, after.reserve_b), (11_000, 4_030));
        assert_eq!(after.pair.a(), [0x11u8; 32]);
        assert_eq!(after.pair.b(), [0x22u8; 32]);
        assert_eq!(after.fee_bps, 30);
        assert_eq!(after.policy_digest, [0x5A; 32]);
    }

    /// The quote inputs a trader would derive are the same before and after, so
    /// the restart is invisible where it matters.
    #[test]
    #[serial]
    fn the_quote_inputs_are_unchanged_by_a_restart() {
        init_test_db();
        let (record, head) = funded_and_advanced();
        let before = rehydrate_amm_vault(&record, &head).expect("before");
        let (rec2, head2) = restart(&record, &head);
        let after = rehydrate_amm_vault(&rec2, &head2).expect("after");

        let quote = |v: &RehydratedVault| {
            crate::sdk::routing_path_sdk::constant_product_output(
                1_000,
                v.reserve_a,
                v.reserve_b,
                v.fee_bps,
            )
        };
        assert_eq!(quote(&before), quote(&after));
        assert!(quote(&after).is_some(), "and the vault actually quotes");

        // The reserves digest a trader binds is identical too — that is what
        // makes a pre-restart quote still verifiable after one.
        let digest = |v: &RehydratedVault| {
            dsm::dlv::vault_smt_leaf::compute_reserves_digest(
                &v.pair.a(),
                &v.pair.b(),
                v.reserve_a,
                v.reserve_b,
                v.fee_bps,
            )
        };
        assert_eq!(digest(&before), digest(&after));
    }

    /// Rehydration is a read. Running it twice cannot advance anything, so a
    /// settlement already folded into the leaves is not folded again.
    #[test]
    #[serial]
    fn rehydrating_twice_does_not_advance_the_vault() {
        init_test_db();
        let (record, head) = funded_and_advanced();
        let (rec2, head2) = restart(&record, &head);
        let first = rehydrate_amm_vault(&rec2, &head2).expect("first");
        let second = rehydrate_amm_vault(&rec2, &head2).expect("second");
        assert_eq!(first, second);
        assert_eq!(
            second.current_sequence, 1,
            "the settlement in the leaves is read, never re-applied"
        );
        assert_eq!((second.reserve_a, second.reserve_b), (11_000, 4_030));
    }

    /// Reserve leaves with NO record do not become a tradable vault. The record
    /// is the only thing that says a vault exists.
    #[test]
    #[serial]
    fn leaves_without_a_record_are_not_a_vault() {
        init_test_db();
        let (_, head) = funded_and_advanced();
        // Head has the funded leaves; the record table is empty.
        assert!(
            rehydrate_all_amm_vaults(&head).is_empty(),
            "encumbered leaves alone must not materialise a tradable vault"
        );
    }

    /// A record with no leaves is not a funded vault. Absence is not zero.
    #[test]
    #[serial]
    fn a_record_without_leaves_fails_closed() {
        init_test_db();
        let (record, _) = funded_and_advanced();
        let err = rehydrate_amm_vault(&record, &empty_head()).expect_err("must refuse");
        assert!(matches!(err, RehydrationError::LegNotFunded { .. }));
    }

    /// One funded leg is not a vault either — the case that would otherwise
    /// advertise a market it cannot make.
    ///
    /// THE INVALID WITNESS is the half-funded HEAD, as it was before: a funded
    /// create takes exactly two legs, so no production transition can leave a
    /// vault with one. The leaf writer stamps the single leg; the VALUE it
    /// encumbers is admitted issuance, never invented.
    #[test]
    #[serial]
    fn a_half_funded_vault_fails_closed() {
        init_test_db();
        let (record, _) = funded_and_advanced();
        let head = admitted_holding(&[(record.policy_commit_a, 50_000)])
            .fund_vault_reserves(&record.vault_id, &[(record.policy_commit_a, 10_000)], 0)
            .expect("fund one leg")
            .new_device_state;
        let err = rehydrate_amm_vault(&record, &head).expect_err("must refuse");
        assert_eq!(
            err,
            RehydrationError::LegNotFunded {
                policy_commit: record.policy_commit_b
            }
        );
    }

    /// THE COLUMN CANNOT WEAKEN THE POSTURE ANY MORE. `anchor_enforcement` is
    /// deprecation residue: whatever a row holds — a permissive `Optional`, an
    /// `Unspecified` 0, or a value no build knows — rehydration DERIVES the
    /// canonical `Required` and never reads the column.
    ///
    /// The refusal this replaces was the honest answer while the value was
    /// still consulted. Now that nothing consults it, refusing would only make
    /// an edited row a denial-of-service on a real vault.
    ///
    /// POSITIVE CONTROL first, so the assertions below are attributable to the
    /// mutation and not to a broken fixture.
    #[test]
    #[serial]
    fn a_mutated_enforcement_column_cannot_weaken_the_derived_posture() {
        init_test_db();
        let (record, head) = funded_and_advanced();
        let control = rehydrate_amm_vault(&record, &head).expect("the untouched row rehydrates");
        assert_eq!(control.anchor_enforcement, REQUIRED);

        for stored in [
            dsm::types::proto::AnchorEnforcement::Unspecified as i32,
            dsm::types::proto::AnchorEnforcement::Optional as i32,
            99,
            -7,
        ] {
            let mut mutated = record.clone();
            mutated.anchor_enforcement = stored;
            let out = rehydrate_amm_vault(&mutated, &head)
                .expect("the column is residue; it must not decide anything");
            assert_eq!(
                out.anchor_enforcement, REQUIRED,
                "a row holding {stored} must not weaken the derived posture"
            );
            assert_eq!(out, control, "and nothing else may move with it either");
        }
    }

    /// A record whose pair is not canonical is not trusted.
    #[test]
    #[serial]
    fn a_non_canonical_record_fails_closed() {
        init_test_db();
        let (record, head) = funded_and_advanced();

        // Sides stored backwards.
        let mut swapped = record.clone();
        swapped.policy_commit_a = record.policy_commit_b;
        swapped.policy_commit_b = record.policy_commit_a;
        assert_eq!(
            rehydrate_amm_vault(&swapped, &head),
            Err(RehydrationError::RecordNotCanonical)
        );

        // One asset named twice.
        let mut doubled = record.clone();
        doubled.policy_commit_b = record.policy_commit_a;
        assert_eq!(
            rehydrate_amm_vault(&doubled, &head),
            Err(RehydrationError::RecordNotCanonical)
        );
    }

    /// THE ROOT-VERSUS-ROW GATE. The record supplies the fee; the device root
    /// COMMITS it, in the vault-state leaf every funding and every settlement
    /// writes. A row claiming a fee the root never committed must not produce a
    /// quoting vault.
    ///
    /// The fee is the field that needs this. Reserves and generation are read
    /// from the leaves and so cannot drift; the pair is caught as an unfunded
    /// leg. A wrong fee is invisible to every other check, and it is the one
    /// the constant-product quote is computed with.
    #[test]
    #[serial]
    fn a_record_whose_fee_disagrees_with_the_root_fails_closed() {
        init_test_db();
        let (record, head) = funded_and_advanced();
        // Positive control: untouched, this record rebuilds. Whatever the
        // mutated one refuses for, it is the mutation.
        assert!(
            rehydrate_amm_vault(&record, &head).is_ok(),
            "the record as written must rebuild"
        );

        let mut tampered = record.clone();
        tampered.fee_bps = record.fee_bps + 1;
        assert_eq!(
            rehydrate_amm_vault(&tampered, &head),
            Err(RehydrationError::RecordDisagreesWithRoot),
            "a fee the root does not commit cannot reach a quote"
        );
    }

    /// Reserve legs that no vault transition wrote are not a vault. `advance`
    /// derives the vault-state leaf from the mutation it just applied, so legs
    /// that appear without one were not produced by a funding or a settlement,
    /// and there is nothing for the record to be checked against.
    #[test]
    #[serial]
    fn reserve_legs_with_no_root_committed_vault_state_leaf_fail_closed() {
        init_test_db();
        let (record, _) = funded_and_advanced();
        // Both legs, one generation — everything the earlier checks ask for.
        // What is missing is the leaf the root commits.
        let head = admitted_holding(&[
            (record.policy_commit_a, 50_000),
            (record.policy_commit_b, 20_000),
        ])
        .fund_vault_reserves(
            &record.vault_id,
            &[
                (record.policy_commit_a, 10_000),
                (record.policy_commit_b, 5_000),
            ],
            0,
        )
        .expect("both legs at one generation")
        .new_device_state;
        assert_eq!(
            rehydrate_amm_vault(&record, &head),
            Err(RehydrationError::VaultStateLeafMissing)
        );
    }

    /// A record belonging to another device does not rehydrate here. Its leaves
    /// live under a different key space entirely.
    #[test]
    #[serial]
    fn another_devices_record_fails_closed() {
        init_test_db();
        let (mut record, head) = funded_and_advanced();
        record.owner_devid = [0xEE; 32];
        assert_eq!(
            rehydrate_amm_vault(&record, &head),
            Err(RehydrationError::OwnerMismatch)
        );
    }

    /// Legs written at different sequences are incoherent — they are written
    /// together in one batch, so this cannot happen to a healthy vault and must
    /// not be resolved by picking one.
    ///
    /// THE INVALID WITNESS. No production transition can produce it: a funded
    /// create stamps both legs at sequence 0 and an owner-apply moves both to
    /// the same `new_sequence`, so the shape is reached with the leaf writer
    /// (`fund_vault_reserves`) alone. The VALUE it writes is not invented —
    /// every unit comes from an admitted issuance and is debited out of
    /// `balances` by the writer, exactly as funding does. Only the SEQUENCE
    /// stamping is deliberately impossible, which is the property under test.
    #[test]
    #[serial]
    fn legs_at_different_sequences_fail_closed() {
        init_test_db();
        let (pc_a, pc_b) = ([0x11u8; 32], [0x22u8; 32]);
        let vault_id = [0x77u8; 32];
        let head = admitted_holding(&[(pc_a, 50_000), (pc_b, 20_000)])
            .fund_vault_reserves(&vault_id, &[(pc_a, 10_000)], 0)
            .expect("leg a at seq 0")
            .new_device_state;
        let head = head
            .fund_vault_reserves(&vault_id, &[(pc_b, 5_000)], 4)
            .expect("leg b at seq 4")
            .new_device_state;

        let record = AmmVaultRecord {
            vault_id,
            owner_genesis: head.genesis(),
            owner_devid: head.devid(),
            policy_commit_a: pc_a,
            policy_commit_b: pc_b,
            fee_bps: 30,
            anchor_enforcement: REQUIRED,
            policy_digest: [0x5A; 32],
            storage_set_id: [0x6B; 32],
            baseline_state_ccb: Vec::new(),
            baseline_presentation: Vec::new(),
            vault_post_proto: Vec::new(),
        };
        assert_eq!(
            rehydrate_amm_vault(&record, &head),
            Err(RehydrationError::LegSequencesDisagree { a: 0, b: 4 })
        );
    }

    /// A vault that cannot be rebuilt is OMITTED from the restored set rather
    /// than restored in a degraded form.
    #[test]
    #[serial]
    fn an_unrebuildable_vault_is_omitted_not_degraded() {
        init_test_db();
        let (good, head) = funded_and_advanced();
        put_amm_vault_record(&good).expect("put good");

        let mut broken = good.clone();
        broken.vault_id = [0x99; 32]; // no leaves for this one
        put_amm_vault_record(&broken).expect("put broken");

        let restored = rehydrate_all_amm_vaults(&head);
        assert_eq!(restored.len(), 1, "only the rebuildable vault comes back");
        assert_eq!(restored[0].vault_id, good.vault_id);
        assert_eq!(restored[0].current_sequence, 1);
    }
}
