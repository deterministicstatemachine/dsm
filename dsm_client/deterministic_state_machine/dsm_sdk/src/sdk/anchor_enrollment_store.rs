// SPDX-License-Identifier: MIT OR Apache-2.0

//! # SQLite Anchor Enrollment Store
//!
//! Implements [`AnchorEnrollmentStore`] from `dsm::crypto::anchor_enrollment` over the SDK's
//! SQLite client database, so the receiver's pinned fused-anchor admissions survive an app
//! restart (a restart must never re-open the first-transfer TOFU window). Mirrors
//! [`SqliteChainTipStore`](crate::sdk::chain_tip_store::SqliteChainTipStore): a stateless wrapper
//! delegating to `client_db` helpers.
//!
//! Installing this store does NOT by itself admit anyone — pins are admitted only through the
//! offline-bearer bilateral confirm flow (first-transfer TOFU / same-anchor upgrade).

use dsm::crypto::anchor_enrollment::{AnchorEnrollment, AnchorEnrollmentStore};
use dsm::types::error::DsmError;

use crate::storage::client_db;

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
        match client_db::anchor_enrollments::get_anchor_enrollment_raw(device_id) {
            Ok(e) => e,
            Err(err) => {
                // Fail-closed: an unreadable pin behaves as "not admitted" (online recovery),
                // never as a permissive default.
                log::warn!("[anchor_enrollment] get failed (treating as not admitted): {err}");
                None
            }
        }
    }

    fn admit(&self, enrollment: AnchorEnrollment) -> Result<(), DsmError> {
        client_db::anchor_enrollments::admit_anchor_enrollment(&enrollment)
            .map_err(|e| DsmError::invalid_operation(format!("admit anchor enrollment: {e}")))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::disallowed_methods)]

    use super::*;
    use dsm::crypto::anchor_enrollment::FusedAnchorPin;
    use serial_test::serial;

    fn enrollment(dev: [u8; 32], pk_chip: Vec<u8>) -> AnchorEnrollment {
        AnchorEnrollment {
            device_id: dev,
            policy_hash: [0x9A; 32],
            pin: FusedAnchorPin {
                bundle: [0xB1; 32],
                anchor_id: [0xA1; 32],
                enrolled_counter: 1_000_000,
                partition_pk: vec![0x07; 64],
                pk_chip,
                uncompromised: true,
            },
        }
    }

    #[test]
    #[serial]
    fn admit_then_get_round_trips_through_sqlite() {
        unsafe {
            std::env::set_var("DSM_SDK_TEST_MODE", "1");
        }
        crate::storage::client_db::reset_database_for_tests();
        crate::storage::client_db::init_database().expect("init db");

        let store = SqliteAnchorEnrollmentStore::new();

        // Not admitted -> None.
        assert!(store.get(&[0x11; 32]).is_none());

        let dev_a = [0x11; 32];
        store
            .admit(enrollment(dev_a, vec![0xCC; 32]))
            .expect("admit");
        let got = store.get(&dev_a).expect("admitted");
        assert_eq!(got.pin.bundle, [0xB1; 32]);
        assert_eq!(got.pin.anchor_id, [0xA1; 32]);
        assert_eq!(got.pin.enrolled_counter, 1_000_000);
        assert!(got.pin.uncompromised);
        assert_eq!(got.pin.pk_chip, vec![0xCC; 32]);

        // Overwrite semantics (the CALLER owns the authority rules): re-admit upgrades in place.
        store
            .admit(enrollment(dev_a, vec![0xDD; 32]))
            .expect("re-admit");
        let got = store.get(&dev_a).expect("admitted");
        assert_eq!(got.pin.pk_chip, vec![0xDD; 32]);
    }
}
