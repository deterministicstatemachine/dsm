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
    /// The bundle's `trader_parent` disagrees with the fenced parent.
    ParentMismatch,
    /// `K(B)` could not be derived (a malformed bundle).
    KeySet,
}

/// The rebuilt inputs for a resumed transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reconstructed {
    pub transaction: BindingTransaction,
    pub trader_successor: [u8; 32],
    pub keys: Vec<[u8; 32]>,
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
    // Strict decode and the whole-bundle round trip under the frozen encoder;
    // the identity is over exactly the bytes that were fetched.
    let decoded =
        settlement_bundle::decode_canonical(bundle_bytes).map_err(|_| ResumeError::BundleDecode)?;
    let b = decoded.bundle;

    // Req 15.3: the bytes must hash to the fence's committed identity.
    let digest = settlement_bundle::bundle_digest(bundle_bytes);
    if digest != fence.tx_id {
        return Err(ResumeError::DigestMismatch);
    }
    if settlement_bundle::bundle_addr(bundle_bytes) != fence.value_addr {
        return Err(ResumeError::AddrMismatch);
    }
    // The bundle's OWN parent must match the fence: the trader's ordinary-DSM
    // parent for a market bundle, the consumed vault parent for an owner
    // close (the close fence is keyed by the vault and its c_n). The bundle
    // carries no storage set (registry §5.19); the fence's is the resolver's.
    let bundle_parent = match (b.market_terms(), b.transitions().first()) {
        (Some(terms), _) => terms.trader_parent,
        (None, Some(t)) => t.parent_binding,
        (None, None) => return Err(ResumeError::BundleDecode),
    };
    if bundle_parent != fence.trader_parent_state_commitment {
        return Err(ResumeError::ParentMismatch);
    }

    let keys = settlement_bundle::key_set(&b).map_err(|_| ResumeError::KeySet)?;
    let trader_successor =
        settlement_bundle::permitted_continuation(&b).map_err(|_| ResumeError::BundleDecode)?;
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

// NOT cfg'd out of test builds. It reaches the fleet through the shared
// `binding_transport` factory, which is itself cfg-split — so restart recovery
// is exercisable under the deterministic double instead of being pinned to
// HTTP and therefore untestable.
mod live {
    use super::*;
    use crate::sdk::quorum_bind_runner::{binding_transport, run_fenced, Backoff, FenceKey};
    use dsm::dlv::quorum_bind::QuorumBind;
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

        let transport = binding_transport(&set);
        let Ok(mut engine) = QuorumBind::begin(r.transaction) else {
            return false;
        };
        let fence_key = FenceKey {
            trader_chain_id: fence.trader_chain_id,
            trader_parent_state_commitment: fence.trader_parent_state_commitment,
            tx_id: fence.tx_id,
        };
        let out = run_fenced(
            &mut engine,
            &members,
            &r.keys,
            transport.as_ref(),
            Backoff::default(),
            MAX_BALLOTS,
            fence_key,
            r.trader_successor,
            fence.storage_set_id,
            fence.value_addr,
        )
        .await;
        // 2c-C3.1 ruling A, source (b): a resumed transaction that commits is
        // this device's own finality too.
        if out == Ok(dsm::dlv::quorum_bind::Outcome::Committed) {
            if let Ok(decoded) = dsm::dlv::settlement_bundle::decode_canonical(&bytes) {
                crate::sdk::settlement_bind::record_own_commit(
                    &set,
                    &decoded.bundle,
                    fence.tx_id,
                    fence.value_addr,
                    engine.ballot(),
                    proposer_id,
                    r.trader_successor,
                );
            }
        }
        out.is_ok()
    }

    /// Restore every unresolved trader-parent fence on restart (Req 16.5).
    pub async fn recover_all() -> anyhow::Result<usize> {
        let recoveries =
            crate::sdk::quorum_bind_runner::recover_unresolved_fences(resume_one).await?;
        Ok(recoveries.iter().filter(|r| !r.resolved).count())
    }
}

pub use live::{recover_all, resume_one};

#[cfg(test)]
#[allow(clippy::disallowed_methods)] // test asserts; a failure here is the signal
mod tests {
    use super::*;
    use dsm::dlv::trader_fence::FenceState;

    fn members(n: u8) -> Vec<CommittedMember> {
        (0..n)
            .map(|i| CommittedMember {
                member_id: vec![i],
                register_incarnation: [i; 32],
            })
            .collect()
    }

    /// A canonical market bundle: one transition over parent `[0x11; 32]`,
    /// trader parent `[0x52; 32]` (the fixture's).
    fn a_bundle() -> dsm::ccb::SettlementBundle {
        dsm::ccb::settlement::fixtures::market_bundle(
            [0x11; 32],
            dsm::ccb::settlement::fixtures::successor_of([0x11; 32], [1; 32], 4, 1, 1),
            [0x0C; 32],
        )
    }

    /// A fence whose identity fields match `a_bundle()`.
    fn matching_fence(canon: &[u8]) -> TraderFence {
        TraderFence {
            trader_chain_id: [0x11; 32],
            trader_parent_state_commitment: [0x52; 32], // == bundle.market_terms.trader_parent
            tx_id: settlement_bundle::bundle_digest(canon),
            ballot: 5,
            storage_set_id: [0x6B; 32], // the resolver's set; the bundle carries none
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
        assert_eq!(
            r.trader_successor,
            settlement_bundle::permitted_continuation(&b).unwrap()
        );
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
        // Non-bundle bytes.
        assert_eq!(
            reconstruct(&good, b"not a bundle", members(3), 2, [7; 32]),
            Err(ResumeError::BundleDecode)
        );
    }
}
