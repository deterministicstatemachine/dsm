// SPDX-License-Identifier: MIT OR Apache-2.0
//! SQLite-backed receiver-side anchor enrollment store (offline-bearer anti-clone).
//!
//! Persists the pinned counterparty anchor identity + enrolled firmware hash + policy + monotonic
//! frontier (table `anchor_enrollments`), so the receiver's admission and frontier survive an app
//! restart. Without persistence a restart would reset the frontier and let a consumed-parent replay
//! through. The CAS advance is atomic under the DB connection lock.

use dsm::crypto::anchor_enrollment::{AnchorEnrollment, AnchorEnrollmentStore};
use dsm::crypto::anchor_transport::AnchorIdentityRecord;
use dsm::types::error::DsmError;

use crate::storage::client_db::anchor_persist as ap;

/// SQLite-backed [`AnchorEnrollmentStore`] for SDK usage.
#[derive(Default, Clone)]
pub struct SqliteAnchorEnrollmentStore;

impl SqliteAnchorEnrollmentStore {
    pub fn new() -> Self {
        Self
    }
}

impl AnchorEnrollmentStore for SqliteAnchorEnrollmentStore {
    fn get(&self, device_id: &[u8; 32]) -> Option<AnchorEnrollment> {
        ap::get_enrollment(device_id).map(|p| AnchorEnrollment {
            device_id: *device_id,
            record: AnchorIdentityRecord {
                id_anchor: p.id_anchor,
                commitment_c: p.commitment_c,
                leaf_spki: p.leaf_spki,
                firmware_id: p.firmware_id,
                screen_template_id: p.screen_template_id,
                firmware_hash: p.firmware_hash,
            },
            policy_hash: p.policy_hash,
            frontier_root: p.frontier_root,
            frontier_state: p.frontier_state,
        })
    }

    fn admit(&self, enrollment: AnchorEnrollment) -> Result<(), DsmError> {
        let p = ap::PersistedEnrollment {
            id_anchor: enrollment.record.id_anchor,
            commitment_c: enrollment.record.commitment_c,
            leaf_spki: enrollment.record.leaf_spki,
            firmware_id: enrollment.record.firmware_id,
            screen_template_id: enrollment.record.screen_template_id,
            firmware_hash: enrollment.record.firmware_hash,
            policy_hash: enrollment.policy_hash,
            frontier_root: enrollment.frontier_root,
            frontier_state: enrollment.frontier_state,
        };
        ap::admit_enrollment(&enrollment.device_id, &p)
            .map_err(|e| DsmError::InvalidState(format!("admit_enrollment persist failed: {e}")))
    }

    fn advance_frontier(
        &self,
        device_id: &[u8; 32],
        expected_parent_root: [u8; 32],
        new_root: [u8; 32],
        new_state_number: u64,
    ) -> Result<bool, DsmError> {
        ap::advance_enrollment_frontier_cas(
            device_id,
            expected_parent_root,
            new_root,
            new_state_number,
        )
        .map_err(|e| DsmError::verification(format!("advance_enrollment_frontier failed: {e}")))
    }
}
