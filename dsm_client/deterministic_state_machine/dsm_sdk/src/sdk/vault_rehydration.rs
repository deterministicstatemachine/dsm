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
    pub fee_bps: u32,
    /// The enforcement mode the vault was created with — never a default.
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
    /// This build does not recognise the stored enforcement mode. Refusing is
    /// the whole point: falling back to a permissive default would drop a gate
    /// the owner asked for.
    UnknownAnchorEnforcement { stored: i32 },
    /// A leg of the pair has no reserve entry. A vault missing a side is not a
    /// funded vault, and treating the absence as zero would let it advertise
    /// and quote as if it were merely empty.
    LegNotFunded { policy_commit: [u8; 32] },
    /// The two legs were last written at different sequences. They are written
    /// together in one batch, so this cannot happen to a coherent vault and
    /// must not be resolved by picking one.
    LegSequencesDisagree { a: u64, b: u64 },
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
            RehydrationError::UnknownAnchorEnforcement { stored } => write!(
                f,
                "unknown anchor_enforcement {stored}; refusing rather than falling back to a permissive default"
            ),
            RehydrationError::LegNotFunded { .. } => write!(
                f,
                "a leg of this vault has no reserve entry; an unfunded side is not a zero balance"
            ),
            RehydrationError::LegSequencesDisagree { a, b } => write!(
                f,
                "vault legs were last written at different sequences ({a} vs {b}); the vault is incoherent"
            ),
        }
    }
}

impl std::error::Error for RehydrationError {}

/// Known `AnchorEnforcement` values. Listed rather than range-checked so a value
/// added to the proto but not handled here fails closed instead of silently
/// becoming whatever the numeric neighbours mean.
fn known_enforcement(v: i32) -> bool {
    matches!(
        v,
        x if x == dsm::types::proto::AnchorEnforcement::Unspecified as i32
            || x == dsm::types::proto::AnchorEnforcement::Optional as i32
            || x == dsm::types::proto::AnchorEnforcement::Required as i32
    )
}

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
    if !known_enforcement(record.anchor_enforcement) {
        return Err(RehydrationError::UnknownAnchorEnforcement {
            stored: record.anchor_enforcement,
        });
    }

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

    Ok(RehydratedVault {
        vault_id: record.vault_id,
        pair,
        fee_bps: record.fee_bps,
        anchor_enforcement: record.anchor_enforcement,
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

    /// A device head holding `balances`. Built through `restore`, the same
    /// constructor the persistence layer uses, so the fixture cannot diverge
    /// from what a reloaded device actually looks like.
    fn holding(balances: &[([u8; 32], u64)]) -> DeviceState {
        DeviceState::restore(
            [0u8; 32],
            [0xB0u8; 32],
            vec![0xAA; 64],
            None,
            balances.iter().copied().collect(),
            Vec::new(),
            std::collections::BTreeMap::new(),
            std::collections::BTreeMap::new(),
            std::collections::BTreeMap::new(),
            1024,
        )
        .expect("device head")
    }

    /// A funded vault, advanced past sequence zero, under `Required`
    /// enforcement — the state a restart has to reproduce.
    fn funded_and_advanced() -> (AmmVaultRecord, DeviceState) {
        let (pc_a, pc_b) = ([0x11u8; 32], [0x22u8; 32]);
        let vault_id = [0x77u8; 32];
        let head = holding(&[(pc_a, 50_000), (pc_b, 20_000)])
            .fund_vault_reserves(&vault_id, &[(pc_a, 10_000), (pc_b, 5_000)], 0)
            .expect("fund")
            .new_device_state;
        // Advance past zero, as a settlement does.
        let head = head
            .apply_settlement_to_reserves(&vault_id, &pc_a, 1_000, &pc_b, 970, 1)
            .expect("settle")
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
        };
        (record, head)
    }

    /// Simulate a restart: the head goes through the real persistence codec and
    /// comes back, and the record goes through SQLite.
    fn restart(record: &AmmVaultRecord, head: &DeviceState) -> (AmmVaultRecord, DeviceState) {
        put_amm_vault_record(record).expect("persist record");
        let bytes = crate::storage::client_db::bcr::encode_device_state(head);
        let (reloaded, _) =
            crate::storage::client_db::bcr::decode_device_state(&bytes).expect("decode head");
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
            dsm::dlv::vault_state_anchor::compute_reserves_digest(
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
        let empty = holding(&[]);
        let err = rehydrate_amm_vault(&record, &empty).expect_err("must refuse");
        assert!(matches!(err, RehydrationError::LegNotFunded { .. }));
    }

    /// One funded leg is not a vault either — the case that would otherwise
    /// advertise a market it cannot make.
    #[test]
    #[serial]
    fn a_half_funded_vault_fails_closed() {
        init_test_db();
        let (record, _) = funded_and_advanced();
        let head = holding(&[(record.policy_commit_a, 50_000)])
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

    /// An unrecognised enforcement mode refuses rather than defaulting. This is
    /// the specific repair that must never happen: a permissive fallback drops a
    /// gate the owner asked for.
    #[test]
    #[serial]
    fn an_unknown_enforcement_mode_refuses_rather_than_defaulting() {
        init_test_db();
        let (mut record, head) = funded_and_advanced();
        record.anchor_enforcement = 99;
        let err = rehydrate_amm_vault(&record, &head).expect_err("must refuse");
        assert_eq!(
            err,
            RehydrationError::UnknownAnchorEnforcement { stored: 99 }
        );
        assert!(
            format!("{err}").contains("permissive default"),
            "the message must name the repair being refused"
        );
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
    #[test]
    #[serial]
    fn legs_at_different_sequences_fail_closed() {
        init_test_db();
        let (pc_a, pc_b) = ([0x11u8; 32], [0x22u8; 32]);
        let vault_id = [0x77u8; 32];
        let head = holding(&[(pc_a, 50_000), (pc_b, 20_000)])
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
