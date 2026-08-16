// SPDX-License-Identifier: MIT OR Apache-2.0
//! Two-device, one-process test harness for the bilateral protocol.
//!
//! The bilateral finality tests need two devices (A and B) whose durable state
//! persists across many round-trips: A's counterparty-canonical-head pin for B
//! must survive while B applies two inbound transfers and advances its own local
//! relationship lineage, then A must recognise B's head when B finally sends.
//! One process has ONE `DB_CONNECTION`, and `cert_chain_heads` is keyed by the
//! SYMMETRIC relationship key, so A's Local head and B's Local head collide in a
//! single database. This harness gives each device its own named in-memory
//! database ("slot") and swaps the active one with
//! [`crate::storage::client_db::switch_test_database_slot`].
//!
//! STRICTLY SERIALIZED. Exactly one device is active while production code runs;
//! A-side and B-side calls must never overlap in-process, because `AppState`,
//! the cached wallet seed, and other identity context are process-global. This
//! harness proves protocol SEQUENCING, not concurrency. Use [`TestDevice::enter`]
//! to make a device current before driving any production code against it.

use crate::sdk::app_state::AppState;
use crate::storage::client_db::{self, ContactRecord};

/// One test device: its DB slot, identity, and authentication material. Only
/// durable/identity state lives here; per-device `CoreSDK`/`AppRouterImpl`
/// instances are constructed by the caller while the device is [`enter`](Self::enter)ed.
#[derive(Clone)]
pub struct TestDevice {
    /// Distinct DB slot suffix; also the AppState device label seed.
    pub slot: &'static str,
    pub device_id: [u8; 32],
    pub genesis: [u8; 32],
    pub wallet_seed: Vec<u8>,
    pub ak_pk: Vec<u8>,
    pub ak_sk: Vec<u8>,
    pub kyber_pk: Vec<u8>,
    pub kyber_sk: Vec<u8>,
}

impl TestDevice {
    /// Build a device with deterministic-but-distinct identity material and
    /// initialize its (empty) database slot. Does not leave the device active —
    /// call [`enter`](Self::enter) before driving production code.
    pub fn create(slot: &'static str, tag: u8) -> Self {
        // Real AK/Kyber keypairs, seeded deterministically per device so a test
        // is reproducible while A and B remain cryptographically distinct.
        let (ak_pk, ak_sk) = dsm::crypto::sphincs::generate_keypair_from_seed(
            dsm::crypto::sphincs::SphincsVariant::SPX256f,
            &[tag; 32],
        )
        .map(|kp| (kp.public_key.clone(), kp.secret_key.clone()))
        .expect("ak");
        let (kyber_pk, kyber_sk) = dsm::crypto::kyber::generate_kyber_keypair_from_entropy(
            &[tag ^ 0x5A; 32],
            "two-device-test",
        )
        .expect("kyber");
        let dev = Self {
            slot,
            device_id: [tag; 32],
            genesis: [tag ^ 0xF0; 32],
            wallet_seed: vec![tag ^ 0x9C; 64],
            ak_pk,
            ak_sk,
            kyber_pk,
            kyber_sk,
        };
        dev.enter();
        dev
    }

    /// Make this device the active one: switch its DB slot, install its identity
    /// and wallet seed. Every process-global consulted by production code
    /// (`DB_CONNECTION`, `AppState`, the cached wallet seed) now reflects THIS
    /// device until the next `enter` on another device.
    pub fn enter(&self) {
        unsafe {
            std::env::set_var("DSM_SDK_TEST_MODE", "1");
        }
        // AppState reads/writes go through the storage base dir even in test
        // mode; set it once (idempotent OnceLock) so set_identity_info does not
        // panic. All slots share it — identity is swapped in memory per device.
        let _ = crate::storage_utils::set_storage_base_dir(std::path::PathBuf::from(
            "./.dsm_testdata_two_device",
        ));
        client_db::switch_test_database_slot(self.slot);
        client_db::init_database().expect("init slot db");
        AppState::reset_for_testing();
        AppState::set_identity_info(
            self.device_id.to_vec(),
            self.ak_pk.clone(),
            self.genesis.to_vec(),
            vec![0u8; 32],
        );
        AppState::set_has_identity(true);
        crate::sdk::recovery_sdk::RecoverySDK::set_cached_wallet_seed_for_testing(
            self.wallet_seed.clone(),
        );
    }

    /// Record `peer` in THIS device's contact book (call while entered), pinning
    /// the peer's authenticated AK and Kyber key — exactly what an online
    /// transfer needs before it can verify and encapsulate to the peer.
    pub fn add_contact(&self, peer: &TestDevice) {
        client_db::store_contact(&ContactRecord {
            contact_id: format!("c_{}", peer.slot),
            device_id: peer.device_id.to_vec(),
            alias: peer.slot.to_string(),
            genesis_hash: peer.genesis.to_vec(),
            public_key: peer.ak_pk.clone(),
            kyber_public_key: peer.kyber_pk.clone(),
            current_chain_tip: None,
            added_at: 0,
            verified: true,
            verification_proof: None,
            metadata: std::collections::HashMap::new(),
            ble_address: None,
            status: "Created".to_string(),
            needs_online_reconcile: false,
            last_seen_online_counter: 0,
            last_seen_ble_counter: 0,
            previous_chain_tip: None,
        })
        .expect("store contact");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The whole reason the harness exists: two devices' durable state must be
    // isolated. Write a contact into A's database, switch to B and prove it is
    // absent, switch back to A and prove it survived the excursion. If slots
    // leaked into one shared DB (the pre-harness reality), B would see A's
    // contact and every symmetric-keyed CAS would collide.
    #[test]
    #[serial_test::serial]
    fn two_device_slots_keep_durable_state_isolated() {
        client_db::reset_database_for_tests();
        let a = TestDevice::create("A", 0x0A);
        let b = TestDevice::create("B", 0x0B);

        a.enter();
        a.add_contact(&b);
        assert!(
            client_db::get_contact_by_device_id(&b.device_id)
                .expect("query")
                .is_some(),
            "A sees the contact it stored"
        );

        b.enter();
        assert!(
            client_db::get_contact_by_device_id(&a.device_id)
                .expect("query")
                .is_none(),
            "B's database is a different slot — it must NOT see A's contact"
        );
        b.add_contact(&a);
        assert!(
            client_db::get_contact_by_device_id(&a.device_id)
                .expect("query")
                .is_some(),
            "B sees the contact it stored"
        );

        a.enter();
        assert!(
            client_db::get_contact_by_device_id(&b.device_id)
                .expect("query")
                .is_some(),
            "A's contact survived the excursion into B's slot"
        );
        assert!(
            client_db::get_contact_by_device_id(&a.device_id)
                .expect("query")
                .is_none(),
            "A never stored ITSELF as a contact; B's write did not bleed across"
        );

        client_db::reset_database_for_tests();
    }
}
