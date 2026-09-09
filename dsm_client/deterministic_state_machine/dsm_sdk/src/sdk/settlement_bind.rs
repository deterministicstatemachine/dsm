// SPDX-License-Identifier: Apache-2.0

//! THE SETTLE-SIDE QUORUMBIND DRIVER (5c-1).
//!
//! `bind_settlement` is what the live settle paths call in place of the old
//! settlement-slot claim: it stores the canonical [`SettlementBundle`], derives
//! `K(B)` and the transaction identity from the bytes, and drives the fenced
//! QuorumBind runner to a terminal outcome. It records the DLV outcome only —
//! a `COMMITTED` is binding-final, NOT realized. Owner-close folds one-phase on
//! that (Req 6.30); market realization (the `TA_B` acceptance gate) is 5c-2. The
//! old register is still present until 5d; this is the wiring step.
//!
//! `PutImmutable(B)` happens before the first mutating binding op (Req 6.15/16.1
//! ordering), so a recovering Class K can always fetch `B`. The transport is
//! cfg-split: the live path speaks HTTP; tests drive the deterministic
//! [`binding_fleet_double`].
//!
//! [`SettlementBundle`]: dsm::dlv::settlement_bundle

use dsm::ccb::{ConsumedDlvTransition, SettlementBundle, VaultStateV2};
use dsm::dlv::quorum_bind::{BindingTransaction, CommittedMember, Outcome, QuorumBind};
use dsm::dlv::settlement_bundle;

use crate::sdk::quorum_bind_runner::{binding_transport, run_fenced, Backoff, FenceKey, RunError};
use crate::sdk::storage_set::StorageSet;

/// Bounded recovery ballots for one settle attempt. Exhausting it is not
/// ABORT: the parent stays fenced (INDETERMINATE) and restart recovery resumes.
const MAX_BALLOTS: u32 = 8;

/// Why a settle could not even be driven (before any terminal outcome).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BindError {
    /// The bundle is not canonical / well-formed.
    Bundle,
    /// The immutable bundle could not be stored at all (no usable member SDK).
    PutImmutable,
    /// The bundle reached fewer than `q` ATTRIBUTABLE members of the committed
    /// set, so it is not durably published and the transaction must not begin.
    PublicationNotDurable {
        accepted: u32,
        required: u32,
        total: u32,
    },
    /// The transaction profile is invalid (q not the strict majority).
    Profile,
    /// The fence could not be persisted, so the transaction did not begin.
    FenceNotPersisted,
}

/// This Class K instance's proposer id — the low tiebreak of every round and
/// the `proposer_id` a member records. The device's genesis hash is a stable,
/// per-device 32-byte value; two distinct devices have distinct genesis, so
/// their rounds never collide.
pub fn local_proposer_id() -> Option<[u8; 32]> {
    let g = crate::sdk::app_state::AppState::get_genesis_hash()?;
    <[u8; 32]>::try_from(g.as_slice()).ok()
}

fn committed_members(set: &StorageSet) -> Vec<CommittedMember> {
    set.members()
        .iter()
        .map(|m| CommittedMember {
            member_id: m.member_id.as_bytes().to_vec(),
            register_incarnation: m.register_incarnation_id,
        })
        .collect()
}

/// Publish `B` to the committed set, and REQUIRE a quorum of attributable
/// acceptances before the caller is allowed to mutate anything.
///
/// Req 6.15 puts the bundle in the store before the first mutating binding op
/// so recovery can always fetch it. The ordering alone is not the requirement:
/// a fan-out where every member refused still *returns*, and the two facts
///
/// ```text
/// the SDK invocation succeeded
/// enough committed members actually accepted B
/// ```
///
/// are different. Collapsing them — which `.map(|_| ())` used to do — lets a
/// 413, a 401 or an unreachable fleet read as success, after which the fence is
/// placed and the register driven against a `value_addr` NO member holds. The
/// bundle is then unfetchable, `settlement_resume` can never complete, and the
/// DLV parent stays fenced forever. That is a far worse state than refusing.
///
/// `accepted` is already the ATTRIBUTABLE count on both paths: the production
/// fan-out counts a 2xx only when the member echoes its own configured id
/// (Req 15.8), and the fleet double applies the same echo rule. So the
/// threshold is the vault's committed `q` — never a hardcoded majority, and
/// never the locally configured fleet size.
async fn put_bundle(set: &StorageSet, canon: &[u8], addr: [u8; 32]) -> Result<(), BindError> {
    let ns =
        String::from_utf8_lossy(dsm::common::domain_tags::TAG_DSM_SETTLEMENT_BUNDLE.source_bytes())
            .to_string();
    let addr_b32 = crate::util::text_id::encode_base32_crockford(&addr);
    let fanout = crate::sdk::storage_io::put_immutable_to_all_members(set, &ns, canon, &addr_b32)
        .await
        .map_err(|_| BindError::PutImmutable)?;
    let required = set.quorum();
    if fanout.accepted < required {
        log::warn!(
            "[settle] bundle publication not durable: {}/{} attributable acceptances, {} required; \
             refusing BEFORE any fence or binding round",
            fanout.accepted,
            fanout.total,
            required
        );
        return Err(BindError::PublicationNotDurable {
            accepted: fanout.accepted,
            required,
            total: fanout.total,
        });
    }
    Ok(())
}

/// Build the canonical owner-close `SettlementBundle` (2c-A.1): no market
/// terms, one transition carrying the exact drained successor the frozen
/// predicate derived (`derive_close_successor`) and the owner's authorization
/// over it. The permitted continuation the fence fixes on `COMMITTED` is
/// `c_{n+1}` of that successor (ruling 3); the close folds one-phase on it
/// (Req 6.30). A successor that is not linked to `parent_c_n`, not retired,
/// or an authorization of any length but 49,856 cannot be built.
pub fn close_bundle(
    parent_c_n: [u8; 32],
    successor: VaultStateV2,
    owner_authorization: Vec<u8>,
) -> Result<SettlementBundle, BindError> {
    let transition = ConsumedDlvTransition::owner_close(parent_c_n, successor, owner_authorization)
        .map_err(|_| BindError::Bundle)?;
    SettlementBundle::owner_close(transition).map_err(|_| BindError::Bundle)
}

/// Store `B` and drive its QuorumBind transaction to a terminal outcome under
/// the trader-parent fence. `trader_chain_id` / `trader_parent_state_commitment`
/// name the fenced parent; the bundle's `trader_successor` is the exact
/// permitted continuation the fence fixes on `COMMITTED`.
///
/// Returns the terminal [`Outcome`] (`Committed` = binding-final, not realized),
/// or a [`RunError`] if the transaction is left unresolved (the parent stays
/// fenced and restart recovery resumes it).
pub async fn bind_settlement(
    set: &StorageSet,
    proposer_id: [u8; 32],
    bundle: &SettlementBundle,
    trader_chain_id: [u8; 32],
    trader_parent_state_commitment: [u8; 32],
) -> Result<Result<Outcome, RunError>, BindError> {
    let canon = settlement_bundle::canon(bundle).map_err(|_| BindError::Bundle)?;
    let b = settlement_bundle::bundle_digest(&canon);
    let addr = settlement_bundle::bundle_addr(&canon);
    let keys = settlement_bundle::key_set(bundle).map_err(|_| BindError::Bundle)?;
    // The continuation the fence fixes on COMMITTED: the market's exact
    // prepared trader successor, or the close's c_{n+1} (2c-A.1 ruling 3).
    let trader_successor =
        settlement_bundle::permitted_continuation(bundle).map_err(|_| BindError::Bundle)?;

    // Store B before any mutating binding op, so recovery can always fetch it.
    put_bundle(set, &canon, addr).await?;

    let members = committed_members(set);
    // RESUME ABOVE THE PERSISTED BALLOT, NEVER FROM ZERO. `place_fence` is
    // INSERT OR IGNORE, so an interrupted attempt's ballot survives — and the
    // close-resume path re-derives the same deterministic bundle and calls back
    // in here, so this is a resume far more often than it looks. Restarting at
    // zero would reuse ballots this transaction already spent, which is exactly
    // the recovery property the fence exists to provide (`reconstruct` seeds
    // from `fence.ballot` for the same reason).
    let base_ballot = crate::storage::client_db::trader_parent_fence::get_fence(
        &trader_chain_id,
        &trader_parent_state_commitment,
        &b,
    )
    .ok()
    .flatten()
    .map(|f| f.ballot)
    .unwrap_or(0);
    let tx = BindingTransaction {
        proposer_id,
        members: members.clone(),
        quorum: set.quorum(),
        keys: keys.clone(),
        // One bundle is one transaction: tx_id = value_digest = b.
        tx_id: b,
        value_addr: addr,
        value_digest: b,
        base_ballot,
    };
    let mut engine = QuorumBind::begin(tx).map_err(|_| BindError::Profile)?;
    let fence_key = FenceKey {
        trader_chain_id,
        trader_parent_state_commitment,
        tx_id: b,
    };
    let t = binding_transport(set);
    let out = run_fenced(
        &mut engine,
        &members,
        &keys,
        t.as_ref(),
        Backoff::default(),
        MAX_BALLOTS,
        fence_key,
        trader_successor,
        set.id(),
        addr,
    )
    .await;
    if out == Err(RunError::FenceNotPersisted) {
        return Err(BindError::FenceNotPersisted);
    }
    // 2c-C3.1 ruling A, source (b): this device's OWN committed bind is a
    // qualifying finality at every key the bundle bound. It is recorded like
    // an observed one and compared on value against what was recorded earlier,
    // so a commit that lands where this verifier already saw a DIFFERENT value
    // chosen is the same contradiction, caught here.
    if out == Ok(Outcome::Committed) {
        record_own_commit(
            set,
            bundle,
            b,
            addr,
            engine.ballot(),
            proposer_id,
            trader_successor,
        );
    }
    Ok(out)
}

/// Record a committed bind as this device's own finality at each vault parent
/// the bundle consumed (2c-C3.1 ruling A, source (b)). Never changes the
/// outcome: the bind DID commit. A contradiction writes the quarantine root
/// and is logged at error level; composition refuses from then on.
pub(crate) fn record_own_commit(
    set: &StorageSet,
    bundle: &SettlementBundle,
    b: [u8; 32],
    addr: [u8; 32],
    ballot: u64,
    proposer_id: [u8; 32],
    trader_successor: [u8; 32],
) {
    use crate::storage::client_db::dlv_lineage_quarantine as quarantine;
    let b32 = crate::util::text_id::encode_base32_crockford;
    let value = quarantine::FinalityValue {
        tx_id: b,
        value_digest: b,
        value_addr: addr,
    };
    let evidence = quarantine::Evidence::OwnCommit(quarantine::OwnCommitEvidence {
        quorum: set.quorum(),
        value,
        ballot,
        storage_set_id: set.id(),
        trader_successor,
    })
    .encode();
    for t in bundle.transitions() {
        // The vault and the consumed generation come from the carried
        // successor (registry §5.19: no vault id beside c_n) — its vault_id,
        // and its generation less one.
        let vault_id = t.successor.vault_id;
        let c_n = t.parent_binding;
        let finality = quarantine::ObservedFinality {
            vault_id,
            c_n,
            generation: t.successor.generation.saturating_sub(1),
            value,
            // The round column carries the driver's final ballot for a commit;
            // rounds are never compared.
            round: dsm::storage::binding_record::Round {
                counter: ballot,
                proposer_id,
            },
            holders: set.quorum(),
            storage_set_id: set.id(),
            quorum: set.quorum(),
            evidence: evidence.clone(),
        };
        match quarantine::record_finality(&finality) {
            Ok(quarantine::RecordOutcome::Recorded)
            | Ok(quarantine::RecordOutcome::AlreadyRecordedSameValue) => {}
            Ok(quarantine::RecordOutcome::Contradiction { recorded }) => {
                let written = quarantine::quarantine_root(&quarantine::QuarantineRoot {
                    vault_id,
                    root_c_n: c_n,
                    root_generation: t.successor.generation.saturating_sub(1),
                    storage_set_id: set.id(),
                    quorum: set.quorum(),
                    first_evidence: recorded.evidence,
                    second_evidence: evidence.clone(),
                    insertion_ordinal: 0,
                });
                log::error!(
                    "STORAGE_SAFETY_VIOLATION DUPLICATE_BINDING_FINALITY: this device committed {} \
                     at a parent where it had recorded {} chosen (vault {}, generation {}); the \
                     lineage is quarantined{}",
                    b32(&b),
                    b32(&recorded.value.tx_id),
                    b32(&vault_id),
                    t.successor.generation.saturating_sub(1),
                    match written {
                        Ok(()) => String::new(),
                        Err(e) => format!(" — and the root could NOT be durably written: {e}"),
                    }
                );
            }
            Err(e) => log::error!(
                "could not durably record this device's own binding finality at vault {} \
                 generation {}: {e}",
                b32(&vault_id),
                t.successor.generation.saturating_sub(1)
            ),
        }
    }
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)] // test asserts; a failure here is the signal
mod tests {
    use super::*;
    use crate::sdk::binding_fleet_double;
    use crate::sdk::storage_set::{StorageMember, StorageSet};
    use dsm::dlv::trader_fence::FenceVerdict;
    use serial_test::serial;

    fn test_set(n: u8) -> StorageSet {
        let members = (0..n)
            .map(|i| StorageMember {
                member_id: format!("n{i}"),
                register_incarnation_id: [i + 1; 32],
                endpoint: format!("http://n{i}.test"),
            })
            .collect();
        StorageSet::new(members).unwrap()
    }

    fn fleet_tuples(set: &StorageSet) -> Vec<(String, Vec<u8>, [u8; 32])> {
        set.members()
            .iter()
            .map(|m| {
                (
                    m.endpoint.clone(),
                    m.member_id.as_bytes().to_vec(),
                    m.register_incarnation_id,
                )
            })
            .collect()
    }

    /// A canonical market bundle over vault `[value; 32]`, consuming parent
    /// `[value ^ 0x40; 32]`.
    fn a_bundle(_set: &StorageSet, value: u8) -> SettlementBundle {
        let parent = [value ^ 0x40; 32];
        dsm::ccb::settlement::fixtures::market_bundle(
            parent,
            dsm::ccb::settlement::fixtures::successor_of(parent, [value; 32], 4, 1, 1),
            [0x0C; 32],
        )
    }

    fn init_db() {
        crate::storage::client_db::reset_database_for_tests();
        crate::storage::client_db::init_database().expect("init");
    }

    /// Reset BOTH doubles. `binding_fleet_double::reset_with` clears only the
    /// register; the immutable puts go through `storage_io::fake_fleet`, whose
    /// injected failures and echo overrides are process-global and would
    /// otherwise leak into the next test under `--test-threads=1`.
    fn reset_fleets(set: &StorageSet) {
        binding_fleet_double::reset_with(&fleet_tuples(set));
        crate::sdk::storage_io::fake_fleet::reset();
    }

    /// No fence row for this parent, and no binding record anywhere: the
    /// transaction must be refused BEFORE either mutation.
    fn assert_nothing_mutated(chain: &[u8; 32], parent: &[u8; 32]) {
        assert_eq!(
            crate::storage::client_db::trader_parent_fence::active_verdict(chain, parent).unwrap(),
            FenceVerdict::Clear,
            "a fence row was written despite a non-durable publication"
        );
        assert!(
            binding_fleet_double::cas_log().is_empty(),
            "a binding round was driven despite a non-durable publication"
        );
    }

    /// n=3, q=2. Drive `bind_settlement` with `accepted` members attributable
    /// and return the result.
    async fn bind_with_accepted(
        set: &StorageSet,
        bundle: &SettlementBundle,
        make_unattributable: &[&str],
        fail: &[&str],
    ) -> Result<Result<Outcome, RunError>, BindError> {
        for id in fail {
            crate::sdk::storage_io::fake_fleet::fail_member(id);
        }
        for id in make_unattributable {
            // The HTTP call SUCCEEDS and the member stores the bytes; it just
            // does not echo its own id, so the acceptance is not attributable.
            crate::sdk::storage_io::fake_fleet::set_echo(id, Some("someone-else"));
        }
        bind_settlement(set, [7; 32], bundle, [0x11; 32], [0xA1; 32]).await
    }

    #[tokio::test]
    #[serial]
    async fn zero_of_three_accepted_refuses_before_any_fence_or_bind() {
        init_db();
        let set = test_set(3);
        reset_fleets(&set);
        let bundle = a_bundle(&set, 0xAA);
        let res = bind_with_accepted(&set, &bundle, &[], &["n0", "n1", "n2"]).await;
        // THE FORBIDDEN STATE FIRST: whatever the return value, nothing may have
        // been mutated. A mutation that removes the gate must fail HERE.
        assert_nothing_mutated(&[0x11; 32], &[0xA1; 32]);
        assert_eq!(
            res.unwrap_err(),
            BindError::PublicationNotDurable {
                accepted: 0,
                required: 2,
                total: 3
            }
        );
    }

    #[tokio::test]
    #[serial]
    async fn one_of_three_accepted_refuses_before_any_fence_or_bind() {
        init_db();
        let set = test_set(3);
        reset_fleets(&set);
        let bundle = a_bundle(&set, 0xAA);
        let res = bind_with_accepted(&set, &bundle, &[], &["n1", "n2"]).await;
        // THE FORBIDDEN STATE FIRST: whatever the return value, nothing may have
        // been mutated. A mutation that removes the gate must fail HERE.
        assert_nothing_mutated(&[0x11; 32], &[0xA1; 32]);
        assert_eq!(
            res.unwrap_err(),
            BindError::PublicationNotDurable {
                accepted: 1,
                required: 2,
                total: 3
            }
        );
    }

    /// THE CASE `.map(|_| ())` HID: every HTTP call returns normally and every
    /// member stores the bytes, but none is attributable, so the publication is
    /// worth nothing. It must read exactly like 0/3.
    #[tokio::test]
    #[serial]
    async fn transport_succeeds_but_no_member_is_attributable_refuses() {
        init_db();
        let set = test_set(3);
        reset_fleets(&set);
        let bundle = a_bundle(&set, 0xAA);
        let res = bind_with_accepted(&set, &bundle, &["n0", "n1", "n2"], &[]).await;
        // THE FORBIDDEN STATE FIRST: whatever the return value, nothing may have
        // been mutated. A mutation that removes the gate must fail HERE.
        assert_nothing_mutated(&[0x11; 32], &[0xA1; 32]);
        assert_eq!(
            res.unwrap_err(),
            BindError::PublicationNotDurable {
                accepted: 0,
                required: 2,
                total: 3
            }
        );
    }

    #[tokio::test]
    #[serial]
    async fn two_of_three_accepted_is_a_quorum_and_proceeds() {
        init_db();
        let set = test_set(3);
        reset_fleets(&set);
        let bundle = a_bundle(&set, 0xAA);
        let out = bind_with_accepted(&set, &bundle, &[], &["n2"])
            .await
            .unwrap();
        assert_eq!(out, Ok(Outcome::Committed));
    }

    #[tokio::test]
    #[serial]
    async fn three_of_three_accepted_proceeds() {
        init_db();
        let set = test_set(3);
        reset_fleets(&set);
        let bundle = a_bundle(&set, 0xAA);
        let out = bind_with_accepted(&set, &bundle, &[], &[]).await.unwrap();
        assert_eq!(out, Ok(Outcome::Committed));
    }

    #[tokio::test]
    #[serial]
    async fn bind_settlement_commits_and_fences_the_parent_on_the_successor() {
        init_db();
        let set = test_set(3);
        reset_fleets(&set);
        let bundle = a_bundle(&set, 0xAA);
        let out = bind_settlement(&set, [7; 32], &bundle, [0x11; 32], [0xA1; 32])
            .await
            .unwrap();
        assert_eq!(out, Ok(Outcome::Committed));
        // The fence now permits ONLY the bundle's continuation — for a market
        // bundle, its exact prepared trader successor.
        let verdict = crate::storage::client_db::trader_parent_fence::active_verdict(
            &[0x11; 32],
            &[0xA1; 32],
        )
        .unwrap();
        assert_eq!(
            verdict,
            FenceVerdict::PermitsOnly(settlement_bundle::permitted_continuation(&bundle).unwrap())
        );
    }

    #[tokio::test]
    #[serial]
    async fn a_second_bundle_over_the_same_vault_parent_conflicts() {
        init_db();
        let set = test_set(3);
        reset_fleets(&set);
        // First bundle over vault/c_n 0xAA commits.
        let first = a_bundle(&set, 0xAA);
        assert_eq!(
            bind_settlement(&set, [1; 32], &first, [0x11; 32], [0xA1; 32])
                .await
                .unwrap(),
            Ok(Outcome::Committed)
        );
        // A different bundle sharing the SAME vault parent (same c_n) cannot
        // also become binding-final.
        let same_parent = first.transitions()[0].parent_binding;
        let second = dsm::ccb::settlement::fixtures::market_bundle(
            same_parent,
            dsm::ccb::settlement::fixtures::successor_of(same_parent, [0xBB; 32], 4, 1, 1),
            [0x0D; 32],
        );
        let out = bind_settlement(&set, [2; 32], &second, [0x22; 32], [0xB2; 32])
            .await
            .unwrap();
        assert!(
            matches!(out, Ok(Outcome::ConflictFinal { .. })),
            "a second bundle over the same parent must conflict, got {out:?}"
        );
    }
}
