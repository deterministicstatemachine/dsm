// SPDX-License-Identifier: MIT OR Apache-2.0
//! Receiver-side anchor enrollment — the pinned admission record + monotonic frontier store
//! for a counterparty's offline-bearer anchor (the identity/frontier the sender gate admits
//! and advances). Offline-bearer RECEIVER ACCEPTANCE now lives in the Boot Fenced Fused Anchor
//! predicate (`anchor_core::accept::accept_offline`, wired in `dsm_sdk::bluetooth::anchor_accept`).
//!
//! # Why this exists
//!
//! The device-side gate (Track 2/3) only constrains what the holder's OWN device will
//! sign. It does NOT bind the RECEIVER's release-of-goods decision. As built, the
//! offline-bearer anchor check runs SENDER-side ([`crate::core::bilateral_transaction_manager::run_offline_bearer_gate`])
//! against the device's SELF-REPORTED identity — circular for an attacker who controls
//! their own device. So a reflashed firmware with a FRESH self-provisioned identity, or
//! an erase-then-reprovision re-genesis, would be accepted by a receiver that never
//! pins the enrolled identity.
//!
//! This module is the receiver-side invariant: pin `{anchor_pubkey, firmware_hash,
//! policy_hash, frontier}` at admission, then reject any offline-bearer receipt whose
//! anchor signature does not verify against the PINNED identity + firmware, or whose
//! frontier does not advance the pinned one monotonically. See the project memory
//! `finding_receiver_must_pin_anchor`.
//!
//! # Status
//!
//! The legacy Safe 7 IslandAttestation receiver verification (`verify_admitted_offline_bearer`)
//! was removed when the offline-bearer model became the Boot Fenced Fused Anchor: the receiver
//! now applies `anchor_core::accept::accept_offline` (the 22-check predicate). This module retains
//! the pinned enrollment + monotonic frontier store, which the sender gate uses to admit and
//! advance a counterparty anchor identity. See the project memory `finding_receiver_must_pin_anchor`.

use std::collections::HashMap;
use std::sync::Mutex;

use crate::crypto::anchor_transport::AnchorIdentityRecord;
use crate::types::error::DsmError;

/// The pinned admission record for one counterparty's anchor.
///
/// Filed under the counterparty's 32-byte DSM `device_id`. Populated ONLY through the
/// normal authority/admission path — never implicitly from a received receipt (that is
/// the anti-reprovision rule: a fresh self-provisioned identity has no enrollment and is
/// rejected).
#[derive(Clone, Debug)]
pub struct AnchorEnrollment {
    /// 32-byte DSM device id of the anchor holder (the key this enrollment is filed under).
    pub device_id: [u8; 32],
    /// The PINNED anchor identity: `leaf_spki` (pubkey), `firmware_id`, `screen_template_id`,
    /// and the enrolled `firmware_hash`. The signature is verified against THIS, not the
    /// device-self-reported record.
    pub record: AnchorIdentityRecord,
    /// The PINNED offline-bearer policy hash this anchor is admitted under.
    pub policy_hash: [u8; 32],
    /// The anchor's monotonic frontier the next advance must consume `(root, state_number)`.
    pub frontier_root: [u8; 32],
    /// The frontier state the next advance must be `state + 1` of.
    pub frontier_state: u64,
}

/// Receiver-side store of pinned anchor enrollments + their frontiers.
///
/// SDKs provide a persistent backing store; the in-memory impl below is the reference and
/// is used by tests + host wiring without a DB. Keyed by counterparty `device_id`.
pub trait AnchorEnrollmentStore: Send + Sync {
    /// The pinned enrollment for a counterparty device, if admitted.
    fn get(&self, device_id: &[u8; 32]) -> Option<AnchorEnrollment>;

    /// Admit (pin) an anchor through the authority path. Overwrites any prior enrollment for the
    /// device (re-admission is an explicit authority action, never implicit from a receipt).
    fn admit(&self, enrollment: AnchorEnrollment) -> Result<(), DsmError>;

    /// CAS-advance the pinned frontier: apply only if the stored root still equals
    /// `expected_parent_root` AND `new_state_number` strictly exceeds the stored one. Returns
    /// `Ok(false)` on a stale parent or non-monotonic state — a fork (a second advance from an
    /// already-consumed root reaching this receiver). Returns `Err` if the device is not admitted.
    fn advance_frontier(
        &self,
        device_id: &[u8; 32],
        expected_parent_root: [u8; 32],
        new_root: [u8; 32],
        new_state_number: u64,
    ) -> Result<bool, DsmError>;
}

impl std::fmt::Debug for dyn AnchorEnrollmentStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "AnchorEnrollmentStore(..)")
    }
}

/// Reference in-memory [`AnchorEnrollmentStore`] (host wiring + tests; SDKs back it with storage).
#[derive(Default)]
pub struct InMemoryAnchorEnrollmentStore {
    enrollments: Mutex<HashMap<[u8; 32], AnchorEnrollment>>,
}

impl InMemoryAnchorEnrollmentStore {
    pub fn new() -> Self {
        Self {
            enrollments: Mutex::new(HashMap::new()),
        }
    }
}

impl std::fmt::Debug for InMemoryAnchorEnrollmentStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "InMemoryAnchorEnrollmentStore(..)")
    }
}

impl AnchorEnrollmentStore for InMemoryAnchorEnrollmentStore {
    fn get(&self, device_id: &[u8; 32]) -> Option<AnchorEnrollment> {
        self.enrollments.lock().ok()?.get(device_id).cloned()
    }

    fn admit(&self, enrollment: AnchorEnrollment) -> Result<(), DsmError> {
        self.enrollments
            .lock()
            .map_err(|_| DsmError::lock_error())?
            .insert(enrollment.device_id, enrollment);
        Ok(())
    }

    fn advance_frontier(
        &self,
        device_id: &[u8; 32],
        expected_parent_root: [u8; 32],
        new_root: [u8; 32],
        new_state_number: u64,
    ) -> Result<bool, DsmError> {
        let mut map = self
            .enrollments
            .lock()
            .map_err(|_| DsmError::lock_error())?;
        let enr = map.get_mut(device_id).ok_or_else(|| {
            DsmError::verification("offline-bearer receiver: device not admitted (fail-closed)")
        })?;
        if enr.frontier_root != expected_parent_root || new_state_number <= enr.frontier_state {
            return Ok(false);
        }
        enr.frontier_root = new_root;
        enr.frontier_state = new_state_number;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attestation::{compute_anchor_set_id, dsm_ui_transcript, id_island_from_spki};
    use crate::crypto::anchor_transport::{AnchorSignRequest, AnchorTransport, MockAnchorTransport};
    use crate::types::device_state::IslandAttestation;

    const POLICY_HASH: [u8; 32] = [0x9Au8; 32];

    // Build a genuine (record, attestation, owned-request-fields) for one frontier advance from
    // `(frontier_root, frontier_state)` -> state `frontier_state + 1`, signed by `mock`.
    struct Triple {
        att: IslandAttestation,
        // Owned fields the AnchorSignRequest borrows.
        h_n: [u8; 32],
        payload: [u8; 32],
        rel: [u8; 32],
        dev: [u8; 32],
        cp: [u8; 32],
        policy_id: [u8; 32],
        policy_hash: [u8; 32],
        parent_root: [u8; 32],
        successor_root: [u8; 32],
        nonce: Vec<u8>,
        state_number: u64,
    }

    impl Triple {
        fn req(&self) -> AnchorSignRequest<'_> {
            AnchorSignRequest {
                h_n: &self.h_n,
                payload_hash: &self.payload,
                relationship_id: &self.rel,
                device_id: &self.dev,
                value_capability: 1,
                offline_bearer_mode: 1,
                nonce: &self.nonce,
                expiry_tick: 42,
                amount: 10,
                asset: b"ERA",
                counterparty_id: &self.cp,
                policy_id: &self.policy_id,
                policy_hash: &self.policy_hash,
                parent_root: &self.parent_root,
                successor_root: &self.successor_root,
                state_number: self.state_number,
            }
        }
    }

    async fn genuine(
        mock: &MockAnchorTransport,
        frontier_root: [u8; 32],
        frontier_state: u64,
    ) -> Triple {
        let record = mock.get_identity().await.expect("id");
        let payload = [0xB2u8; 32];
        let state_number = frontier_state + 1;
        let successor_root = crate::attestation::dsm_anchor_frontier_successor(
            &frontier_root,
            &payload,
            state_number,
        );
        let mut t = Triple {
            att: IslandAttestation {
                id_island: [0u8; 32],
                id_anchor_set: [0u8; 32],
                ui_transcript_hash: [0u8; 32],
                signature: Vec::new(),
                policy_id: [0x6u8; 32],
                anchor_pubkey_hash: [0u8; 32],
                firmware_hash: record.firmware_hash,
                policy_hash: POLICY_HASH,
                parent_root: frontier_root,
                successor_root,
                operation_hash: payload,
                state_number,
            },
            h_n: [0xA1u8; 32],
            payload,
            rel: [0x3u8; 32],
            dev: [0x4u8; 32],
            cp: [0x5u8; 32],
            policy_id: [0x6u8; 32],
            policy_hash: POLICY_HASH,
            parent_root: frontier_root,
            successor_root,
            nonce: b"n0".to_vec(),
            state_number,
        };
        let sig = mock.sign(&t.req()).await.expect("sign");
        t.att.signature = sig;
        t.att.id_island = id_island_from_spki(&record.leaf_spki);
        t.att.id_anchor_set = compute_anchor_set_id(&[record.id_anchor]);
        t.att.anchor_pubkey_hash = crate::attestation::dsm_anchor_pubkey_hash(&record.leaf_spki);
        t.att.ui_transcript_hash = dsm_ui_transcript(
            10,
            b"ERA",
            &t.cp,
            &t.h_n,
            &t.payload,
            &t.policy_id,
            &record.firmware_id,
            record.screen_template_id,
        );
        t
    }

    fn enroll(record: &AnchorIdentityRecord) -> AnchorEnrollment {
        AnchorEnrollment {
            device_id: [0x4u8; 32],
            record: record.clone(),
            policy_hash: POLICY_HASH,
            frontier_root: [0u8; 32],
            frontier_state: 0,
        }
    }

    #[tokio::test]
    async fn store_frontier_cas_serializes_and_rejects_replay() {
        let store = InMemoryAnchorEnrollmentStore::new();
        let mock = MockAnchorTransport::from_seed([7u8; 32]);
        let rec = mock.get_identity().await.expect("id");
        store.admit(enroll(&rec)).expect("admit");
        let dev = [0x4u8; 32];

        // First advance from genesis (state 0 -> 1) advances the pinned frontier.
        let t1 = genuine(&mock, [0u8; 32], 0).await;
        assert!(store
            .advance_frontier(
                &dev,
                t1.att.parent_root,
                t1.att.successor_root,
                t1.att.state_number
            )
            .expect("cas"));

        // Second advance consuming the NEW frontier root (state 1 -> 2) advances.
        let t2 = genuine(&mock, t1.att.successor_root, 1).await;
        assert!(store
            .advance_frontier(
                &dev,
                t2.att.parent_root,
                t2.att.successor_root,
                t2.att.state_number
            )
            .expect("cas"));

        // Replay of the FIRST advance (already-consumed genesis parent) is rejected by the CAS —
        // the cross-receiver fork detector.
        assert!(!store
            .advance_frontier(
                &dev,
                t1.att.parent_root,
                t1.att.successor_root,
                t1.att.state_number
            )
            .expect("cas"));
    }

    #[tokio::test]
    async fn advance_frontier_on_unadmitted_device_errors() {
        let store = InMemoryAnchorEnrollmentStore::new();
        assert!(store
            .advance_frontier(&[0xABu8; 32], [0u8; 32], [1u8; 32], 1)
            .is_err());
    }
}
