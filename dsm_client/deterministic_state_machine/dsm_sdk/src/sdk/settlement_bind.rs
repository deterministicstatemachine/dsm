// SPDX-License-Identifier: Apache-2.0

//! THE SETTLE-SIDE QUORUMBIND DRIVER (5c-1).
//!
//! `bind_settlement` is what the live settle paths call in place of the old
//! settlement-slot claim: it stores the canonical [`SettlementBundle`], derives
//! `K(B)` and the transaction identity from the bytes, and drives the fenced
//! QuorumBind runner to a terminal outcome. It records the DLV outcome only —
//! a `COMMITTED` is binding-final, NOT realized. Owner-close folds one-phase on
//! that (Req 6.30); market realization (the `A_B` acceptance gate) is 5c-2. The
//! old register is still present until 5d; this is the wiring step.
//!
//! `PutImmutable(B)` happens before the first mutating binding op (Req 6.15/16.1
//! ordering), so a recovering Class K can always fetch `B`. The transport is
//! cfg-split: the live path speaks HTTP; tests drive the deterministic
//! [`binding_fleet_double`].
//!
//! [`SettlementBundle`]: dsm::dlv::settlement_bundle

use dsm::dlv::quorum_bind::{BindingTransaction, CommittedMember, Outcome, QuorumBind};
use dsm::dlv::settlement_bundle;
use dsm::types::proto as pb;

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
    /// A fixed-width bundle field is not 32 bytes.
    BadField,
    /// The immutable bundle could not be stored.
    PutImmutable,
    /// The transaction profile is invalid (q not the strict majority).
    Profile,
    /// The fence could not be persisted, so the transaction did not begin.
    FenceNotPersisted,
}

fn as32(v: &[u8]) -> Result<[u8; 32], BindError> {
    <[u8; 32]>::try_from(v).map_err(|_| BindError::BadField)
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

async fn put_bundle(set: &StorageSet, canon: &[u8], addr: [u8; 32]) -> Result<(), BindError> {
    let ns =
        String::from_utf8_lossy(dsm::common::domain_tags::TAG_DSM_SETTLEMENT_BUNDLE.source_bytes())
            .to_string();
    let addr_b32 = crate::util::text_id::encode_base32_crockford(&addr);
    crate::sdk::storage_io::put_immutable_to_all_members(set, &ns, canon, &addr_b32)
        .await
        .map(|_| ())
        .map_err(|_| BindError::PutImmutable)
}

/// Build the minimal owner-close `SettlementBundle` (5c-1). A close consumes one
/// vault parent and is owner-local, so the market fields (`I`, `X`, route) are
/// empty and there is one vault transition. `trader_parent` is the vault's
/// committed parent state `c_n` (the resource the quorum consumes); the close's
/// unique commitment `x_close` is the permitted successor the fence fixes on
/// `COMMITTED`, and the close folds one-phase (Req 6.30) on that.
#[allow(clippy::too_many_arguments)]
pub fn close_bundle(
    storage_set_id: [u8; 32],
    quorum: u32,
    vault_id: [u8; 32],
    parent_sequence: u64,
    c_n: [u8; 32],
    parent_reserves_digest: [u8; 32],
    x_close: [u8; 32],
) -> pb::SettlementBundleV1 {
    pb::SettlementBundleV1 {
        version: settlement_bundle::SETTLEMENT_BUNDLE_VERSION_V1,
        storage_set_id: storage_set_id.to_vec(),
        q: quorum,
        intent_commitment: vec![0u8; 32],
        route_set_commitment: vec![0u8; 32],
        selected_route: Vec::new(),
        trader_parent: c_n.to_vec(),
        trader_successor: x_close.to_vec(),
        vault_transitions: vec![pb::VaultTransitionV1 {
            vault_id: vault_id.to_vec(),
            parent_generation: parent_sequence,
            parent_state_commitment: c_n.to_vec(),
            parent_reserves_digest: parent_reserves_digest.to_vec(),
            successor_ccb: x_close.to_vec(),
            reserve_deltas: Vec::new(),
            witnesses: Vec::new(),
        }],
        proof_material: Vec::new(),
        bundle_signatures: Vec::new(),
        recovery_material: Vec::new(),
    }
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
    bundle: &pb::SettlementBundleV1,
    trader_chain_id: [u8; 32],
    trader_parent_state_commitment: [u8; 32],
) -> Result<Result<Outcome, RunError>, BindError> {
    let canon = settlement_bundle::canon(bundle).map_err(|_| BindError::Bundle)?;
    let b = settlement_bundle::bundle_digest(&canon);
    let addr = settlement_bundle::bundle_addr(&canon);
    let keys = settlement_bundle::key_set(bundle).map_err(|_| BindError::Bundle)?;
    let trader_successor = as32(&bundle.trader_successor)?;

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
    Ok(out)
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

    fn a_bundle(set: &StorageSet, value: u8) -> pb::SettlementBundleV1 {
        pb::SettlementBundleV1 {
            version: settlement_bundle::SETTLEMENT_BUNDLE_VERSION_V1,
            storage_set_id: set.id().to_vec(),
            q: set.quorum(),
            intent_commitment: vec![0x1D; 32],
            route_set_commitment: vec![0x0C; 32],
            selected_route: b"route".to_vec(),
            trader_parent: vec![0xA1; 32],
            trader_successor: vec![value; 32],
            vault_transitions: vec![pb::VaultTransitionV1 {
                vault_id: vec![value; 32],
                parent_generation: 3,
                parent_state_commitment: vec![value ^ 0x40; 32],
                parent_reserves_digest: vec![0x0A; 32],
                successor_ccb: vec![0x5C; 32],
                reserve_deltas: b"d".to_vec(),
                witnesses: vec![],
            }],
            proof_material: vec![],
            bundle_signatures: vec![],
            recovery_material: b"r".to_vec(),
        }
    }

    fn init_db() {
        crate::storage::client_db::reset_database_for_tests();
        crate::storage::client_db::init_database().expect("init");
    }

    #[tokio::test]
    #[serial]
    async fn bind_settlement_commits_and_fences_the_parent_on_the_successor() {
        init_db();
        let set = test_set(3);
        binding_fleet_double::reset_with(&fleet_tuples(&set));
        let bundle = a_bundle(&set, 0xAA);
        let out = bind_settlement(&set, [7; 32], &bundle, [0x11; 32], [0xA1; 32])
            .await
            .unwrap();
        assert_eq!(out, Ok(Outcome::Committed));
        // The fence now permits ONLY the bundle's trader successor.
        let verdict = crate::storage::client_db::trader_parent_fence::active_verdict(
            &[0x11; 32],
            &[0xA1; 32],
        )
        .unwrap();
        assert_eq!(verdict, FenceVerdict::PermitsOnly([0xAA; 32]));
    }

    #[tokio::test]
    #[serial]
    async fn a_second_bundle_over_the_same_vault_parent_conflicts() {
        init_db();
        let set = test_set(3);
        binding_fleet_double::reset_with(&fleet_tuples(&set));
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
        let mut second = a_bundle(&set, 0xBB);
        second.vault_transitions[0].parent_state_commitment =
            first.vault_transitions[0].parent_state_commitment.clone();
        let out = bind_settlement(&set, [2; 32], &second, [0x22; 32], [0xB2; 32])
            .await
            .unwrap();
        assert!(
            matches!(out, Ok(Outcome::ConflictFinal { .. })),
            "a second bundle over the same parent must conflict, got {out:?}"
        );
    }
}
