// SPDX-License-Identifier: Apache-2.0

//! RESTART RECONSTRUCTION FOR A FENCED SETTLEMENT (Rev 15 Req 16.5, Req 15.3,
//! Req 6.15).
//!
//! [`crate::sdk::quorum_bind_runner::recover_unresolved_fences`] hands each
//! unresolved trader-parent fence to a `resume_one` that must rebuild the
//! transaction and drive it to a terminal outcome **without the original
//! constructor's private state** (Req 6.15). This module is that reconstruction:
//!
//! 1. resolve the committed storage set from the catalog (`storage_set_id`);
//! 2. fetch the immutable bundle `B` by its content identity;
//! 3. re-hash the fetched bytes and refuse anything that does not hash to the
//!    fence's committed identity (Req 15.3), and whose own commitments do not
//!    match the fence;
//! 4. rebuild `K(B)` and the trader successor from `B` alone;
//! 5. resume the transaction through the fenced runner, above the persisted
//!    ballot so no ballot is reused.
//!
//! The fence stores the bundle digest `b` as its `tx_id` (one bundle is one
//! transaction, Req 16.2), so `tx_id` is both the fetch key and the identity the
//! re-hash must reproduce.
//!
//! [`reconstruct`] is the pure core (no I/O); [`resume_one`] / [`recover_all`]
//! are the thin async wrapper over the catalog, `GetImmutable`, the HTTP
//! transport, and the runner.

use dsm::dlv::quorum_bind::{BindingTransaction, CommittedMember};
use dsm::dlv::settlement_bundle;

use crate::storage::client_db::trader_parent_fence::TraderFence;

/// Why a fenced settlement could not be reconstructed. Every variant leaves the
/// fence in place (the parent stays fenced) for a later pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResumeError {
    /// The fetched bytes are not a canonical settlement bundle.
    BundleDecode,
    /// The bytes do not hash to the fence's committed digest (`tx_id` = `b`).
    DigestMismatch,
    /// The bytes' content address is not the fence's `value_addr`.
    AddrMismatch,
    /// The bundle's own `storage_set_id` disagrees with the fence.
    SetMismatch,
    /// The bundle's `trader_parent` disagrees with the fenced parent.
    ParentMismatch,
    /// `K(B)` could not be derived (a malformed bundle).
    KeySet,
    /// A fixed-width bundle field is not 32 bytes.
    Width,
}

/// The rebuilt inputs for a resumed transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reconstructed {
    pub transaction: BindingTransaction,
    pub trader_successor: [u8; 32],
    pub keys: Vec<[u8; 32]>,
}

fn as32(v: &[u8]) -> Result<[u8; 32], ResumeError> {
    <[u8; 32]>::try_from(v).map_err(|_| ResumeError::Width)
}

/// Rebuild the transaction from the fetched immutable bundle bytes and the
/// fence, PURELY. The caller supplies the committed members, `q`, and this
/// device's proposer id; everything else comes from `B` and the fence.
///
/// The bytes are re-hashed and every identity is checked against the fence
/// (Req 15.3): a wrong, stale, or tampered bundle is refused rather than driven.
/// The resumed `base_ballot` is the persisted fence ballot, so the engine opens
/// the next ballot above it and never reuses one.
pub fn reconstruct(
    fence: &TraderFence,
    bundle_bytes: &[u8],
    members: Vec<CommittedMember>,
    quorum: u32,
    proposer_id: [u8; 32],
) -> Result<Reconstructed, ResumeError> {
    let b =
        settlement_bundle::decode_canonical(bundle_bytes).map_err(|_| ResumeError::BundleDecode)?;
    let canon = settlement_bundle::canon(&b).map_err(|_| ResumeError::BundleDecode)?;

    // Req 15.3: the bytes must hash to the fence's committed identity.
    let digest = settlement_bundle::bundle_digest(&canon);
    if digest != fence.tx_id {
        return Err(ResumeError::DigestMismatch);
    }
    if settlement_bundle::bundle_addr(&canon) != fence.value_addr {
        return Err(ResumeError::AddrMismatch);
    }
    // The bundle's OWN commitments must match the fence.
    if as32(&b.storage_set_id)? != fence.storage_set_id {
        return Err(ResumeError::SetMismatch);
    }
    if as32(&b.trader_parent)? != fence.trader_parent_state_commitment {
        return Err(ResumeError::ParentMismatch);
    }

    let keys = settlement_bundle::key_set(&b).map_err(|_| ResumeError::KeySet)?;
    let trader_successor = as32(&b.trader_successor)?;
    let transaction = BindingTransaction {
        proposer_id,
        members,
        quorum,
        keys: keys.clone(),
        tx_id: fence.tx_id,
        value_addr: fence.value_addr,
        // value_digest = b; one bundle is one transaction, so it equals tx_id.
        value_digest: digest,
        base_ballot: fence.ballot,
    };
    Ok(Reconstructed {
        transaction,
        trader_successor,
        keys,
    })
}

// ───────────────────────── async wrapper ─────────────────────────

#[cfg(not(any(test, feature = "test-utils")))]
mod live {
    use super::*;
    use dsm::dlv::quorum_bind::QuorumBind;
    use crate::sdk::binding_http_transport::{HttpBindingTransport, MemberEndpoint};
    use crate::sdk::quorum_bind_runner::{run_fenced, Backoff, FenceKey};
    use crate::sdk::storage_set::StorageSetCatalog;
    use dsm::common::domain_tags::TAG_DSM_SETTLEMENT_BUNDLE;

    /// Bounded recovery ballots per resume pass. Exhausting it is not ABORT: the
    /// fence stays and a later pass retries.
    const MAX_BALLOTS: u32 = 8;

    fn proposer_id() -> Option<[u8; 32]> {
        let id = crate::sdk::app_state::AppState::get_device_id()?;
        <[u8; 32]>::try_from(id.as_slice()).ok()
    }

    /// Resolve, fetch, reconstruct, and drive one fenced settlement to a
    /// terminal outcome. Returns `true` iff it reached one; any failure leaves
    /// the fence in place.
    pub async fn resume_one(fence: TraderFence) -> bool {
        let Ok(catalog) = StorageSetCatalog::from_env_config() else {
            return false;
        };
        let Some(set) = catalog.resolve(&fence.storage_set_id).cloned() else {
            return false;
        };
        let Some(proposer_id) = proposer_id() else {
            return false;
        };
        let members: Vec<CommittedMember> = set
            .members()
            .iter()
            .map(|m| CommittedMember {
                member_id: m.member_id.as_bytes().to_vec(),
                register_incarnation: m.register_incarnation_id,
            })
            .collect();

        // Fetch B by its inner digest (tx_id = b); fetch_immutable_payload
        // re-verifies the bytes hash to the requested identity.
        let Ok(Some(bytes)) = crate::sdk::storage_io::fetch_immutable_payload(
            TAG_DSM_SETTLEMENT_BUNDLE,
            &fence.tx_id,
        )
        .await
        else {
            return false;
        };
        let Ok(r) = reconstruct(&fence, &bytes, members.clone(), set.quorum(), proposer_id) else {
            return false;
        };

        let endpoints: Vec<MemberEndpoint> = set
            .members()
            .iter()
            .map(|m| MemberEndpoint {
                endpoint: m.endpoint.clone(),
                auth: crate::sdk::storage_io::resolve_storage_auth(&m.endpoint),
            })
            .collect();
        let transport = HttpBindingTransport::new(endpoints);
        let Ok(mut engine) = QuorumBind::begin(r.transaction) else {
            return false;
        };
        let fence_key = FenceKey {
            trader_chain_id: fence.trader_chain_id,
            trader_parent_state_commitment: fence.trader_parent_state_commitment,
            tx_id: fence.tx_id,
        };
        run_fenced(
            &mut engine,
            &members,
            &r.keys,
            &transport,
            Backoff::default(),
            MAX_BALLOTS,
            fence_key,
            r.trader_successor,
            fence.storage_set_id,
            fence.value_addr,
        )
        .await
        .is_ok()
    }

    /// Restore every unresolved trader-parent fence on restart (Req 16.5).
    pub async fn recover_all() -> anyhow::Result<usize> {
        let recoveries =
            crate::sdk::quorum_bind_runner::recover_unresolved_fences(resume_one).await?;
        Ok(recoveries.iter().filter(|r| !r.resolved).count())
    }
}

#[cfg(not(any(test, feature = "test-utils")))]
pub use live::{recover_all, resume_one};

#[cfg(test)]
#[allow(clippy::disallowed_methods)] // test asserts; a failure here is the signal
mod tests {
    use super::*;
    use dsm::dlv::trader_fence::FenceState;
    use dsm::types::proto as pb;

    fn members(n: u8) -> Vec<CommittedMember> {
        (0..n)
            .map(|i| CommittedMember {
                member_id: vec![i],
                register_incarnation: [i; 32],
            })
            .collect()
    }

    fn transition(vault: u8, c_n: u8) -> pb::VaultTransitionV1 {
        pb::VaultTransitionV1 {
            vault_id: vec![vault; 32],
            parent_generation: 3,
            parent_state_commitment: vec![c_n; 32],
            parent_reserves_digest: vec![0x0A; 32],
            successor_ccb: vec![0x5C; 32],
            reserve_deltas: b"d".to_vec(),
            witnesses: vec![],
        }
    }

    fn a_bundle() -> pb::SettlementBundleV1 {
        pb::SettlementBundleV1 {
            version: settlement_bundle::SETTLEMENT_BUNDLE_VERSION_V1,
            storage_set_id: vec![0x6B; 32],
            q: 2,
            intent_commitment: vec![0x1D; 32],
            route_set_commitment: vec![0x0C; 32],
            selected_route: b"route".to_vec(),
            trader_parent: vec![0xA1; 32],
            trader_successor: vec![0xAA; 32],
            vault_transitions: vec![transition(1, 0x11), transition(2, 0x22)],
            proof_material: vec![b"P".to_vec()],
            bundle_signatures: vec![b"s".to_vec()],
            recovery_material: b"r".to_vec(),
        }
    }

    /// A fence whose identity fields match `a_bundle()`.
    fn matching_fence(canon: &[u8]) -> TraderFence {
        TraderFence {
            trader_chain_id: [0x11; 32],
            trader_parent_state_commitment: [0xA1; 32], // == bundle.trader_parent
            tx_id: settlement_bundle::bundle_digest(canon),
            ballot: 5,
            storage_set_id: [0x6B; 32], // == bundle.storage_set_id
            value_addr: settlement_bundle::bundle_addr(canon),
            state: FenceState::Fenced,
            insertion_ordinal: 0,
        }
    }

    #[test]
    fn reconstruct_rebuilds_the_transaction_and_keys_from_the_bundle_and_fence() {
        let b = a_bundle();
        let canon = settlement_bundle::canon(&b).unwrap();
        let fence = matching_fence(&canon);
        let r = reconstruct(&fence, &canon, members(3), 2, [7; 32]).unwrap();
        assert_eq!(r.keys, settlement_bundle::key_set(&b).unwrap());
        assert_eq!(r.trader_successor, [0xAA; 32]);
        assert_eq!(
            r.transaction.base_ballot, 5,
            "resumes above the persisted ballot"
        );
        assert_eq!(r.transaction.tx_id, fence.tx_id);
        assert_eq!(r.transaction.value_addr, fence.value_addr);
        assert_eq!(
            r.transaction.value_digest, fence.tx_id,
            "value_digest = b = tx_id"
        );
        assert_eq!(r.transaction.quorum, 2);
    }

    #[test]
    fn a_bundle_that_does_not_hash_to_the_fence_identity_is_refused() {
        let b = a_bundle();
        let canon = settlement_bundle::canon(&b).unwrap();
        let good = matching_fence(&canon);

        // Wrong digest (tx_id).
        let mut wrong_digest = good.clone();
        wrong_digest.tx_id = [0xFF; 32];
        assert_eq!(
            reconstruct(&wrong_digest, &canon, members(3), 2, [7; 32]),
            Err(ResumeError::DigestMismatch)
        );
        // Wrong address.
        let mut wrong_addr = good.clone();
        wrong_addr.value_addr = [0xEE; 32];
        assert_eq!(
            reconstruct(&wrong_addr, &canon, members(3), 2, [7; 32]),
            Err(ResumeError::AddrMismatch)
        );
        // The fence's parent disagrees with the bundle's trader_parent.
        let mut wrong_parent = good.clone();
        wrong_parent.trader_parent_state_commitment = [0xC3; 32];
        assert_eq!(
            reconstruct(&wrong_parent, &canon, members(3), 2, [7; 32]),
            Err(ResumeError::ParentMismatch)
        );
        // The fence's set disagrees with the bundle.
        let mut wrong_set = good.clone();
        wrong_set.storage_set_id = [0xD4; 32];
        wrong_set.tx_id = good.tx_id;
        wrong_set.value_addr = good.value_addr;
        assert_eq!(
            reconstruct(&wrong_set, &canon, members(3), 2, [7; 32]),
            Err(ResumeError::SetMismatch)
        );
        // Non-bundle bytes.
        assert_eq!(
            reconstruct(&good, b"not a bundle", members(3), 2, [7; 32]),
            Err(ResumeError::BundleDecode)
        );
    }
}
