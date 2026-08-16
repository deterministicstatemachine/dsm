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
//! Every helper drives PRODUCTION code, never a re-implementation of it: a send
//! is the real `wallet.send` handler (`process_online_transfer_logic`) against
//! a [`FakeB0xNode`]; a receive, a reply and a finalize are the real
//! `storage.sync` on the entered device. The node is a dumb mirror, so a
//! failure can only come from the code under test.
//!
//! STRICTLY SERIALIZED. Exactly one device is active while production code runs;
//! A-side and B-side calls must never overlap in-process, because `AppState`,
//! the cached wallet seed, the bridge's Kyber slot and other identity context
//! are process-global. This harness proves protocol SEQUENCING, not
//! concurrency. Every helper calls [`TestDevice::enter`] first.

use crate::handlers::app_router_impl::AppRouterImpl;
use crate::sdk::app_state::AppState;
use crate::storage::client_db::{self, ContactRecord};
use crate::test_support::fake_node::FakeB0xNode;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// The device every fixture funds itself from: a fictitious third party whose
/// signed lineage is opaque (see `CoreSDK::remote_signed_pair`). Funding is a
/// real inbound canonical apply on the DEVICE's own relationship with this
/// id, so it also serves as "a different relationship" in scope tests.
pub const FAUCET_DEVICE_ID: [u8; 32] = [0xFAu8; 32];

/// One test device: its DB slot, identity, authentication material and — once
/// [`boot`](Self::boot)ed — its own `AppRouterImpl` (per-device `CoreSDK`
/// state machine and wallet).
#[derive(Clone)]
pub struct TestDevice {
    /// Distinct DB slot suffix; also the AppState device label seed.
    pub slot: &'static str,
    pub device_id: [u8; 32],
    pub genesis: [u8; 32],
    pub wallet_seed: Vec<u8>,
    /// Genesis v2 AK — the SAME derivation production signs with
    /// (`init::derive_device_signing_keypair(wallet_seed, genesis)`), so a peer
    /// that pins this key verifies what `wallet.send` actually signs.
    pub ak_pk: Vec<u8>,
    pub ak_sk: Vec<u8>,
    /// Deterministic device Kyber key — the SAME Smaster derivation
    /// `WalletSDK::initialize_device_keys` installs, so a peer's contact copy
    /// equals what this device registers on the node.
    pub kyber_pk: Vec<u8>,
    router: Option<Arc<AppRouterImpl>>,
    seq: Arc<AtomicU64>,
}

impl TestDevice {
    /// Build a device with deterministic-but-distinct identity material and
    /// initialize its (empty) database slot. Does not leave the device active —
    /// call [`enter`](Self::enter) before driving production code.
    pub fn create(slot: &'static str, tag: u8) -> Self {
        use dsm::core::identity::genesis_session::genesis_authority_policy_hash;
        use dsm::core::identity::genesis_v2::{derive_s0, derive_smaster};

        let device_id = [tag; 32];
        let genesis = [tag ^ 0xF0; 32];
        let wallet_seed = vec![tag ^ 0x9C; 64];
        let ak = crate::init::derive_device_signing_keypair(&wallet_seed, &genesis).expect("ak");
        let aph = genesis_authority_policy_hash();
        let s0 = derive_s0(&wallet_seed, &genesis, 0, &aph);
        let smaster = derive_smaster(&s0, &genesis, &device_id, &aph);
        let (kyber_pk, _kyber_sk) =
            dsm::crypto::kyber::generate_kyber_keypair_from_entropy(&smaster, "DSM/kyber\0")
                .expect("kyber");
        let dev = Self {
            slot,
            device_id,
            genesis,
            wallet_seed,
            ak_pk: ak.public_key().to_vec(),
            ak_sk: ak.secret_key().to_vec(),
            kyber_pk,
            router: None,
            seq: Arc::new(AtomicU64::new(1)),
        };
        dev.enter();
        dev
    }

    /// Make this device the active one: switch its DB slot, install its identity,
    /// wallet seed and Kyber key. Every process-global consulted by production
    /// code (`DB_CONNECTION`, `AppState`, the cached wallet seed, the bridge's
    /// local Kyber slot) now reflects THIS device until the next `enter`.
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
        crate::bridge::install_local_kyber_pubkey(self.kyber_pk.clone());
    }

    /// Bring the device up against `node`: seed its genesis record (what
    /// `local_genesis_hash` and inbox routing read) and build its
    /// `AppRouterImpl` — per-device `CoreSDK` (genesis'd) and wallet.
    pub fn boot(&mut self, nodes: &[FakeB0xNode]) {
        self.enter();
        let endpoints: Vec<String> = nodes.iter().map(|n| n.endpoint.clone()).collect();
        let genesis_b32 = crate::util::text_id::encode_base32_crockford(&self.genesis);
        client_db::store_genesis_record_with_verification(&client_db::GenesisRecord {
            genesis_id: genesis_b32,
            device_id: crate::util::text_id::encode_base32_crockford(&self.device_id),
            mpc_proof: "test".to_string(),
            device_birth_binding: String::new(),
            merkle_root: String::new(),
            participant_count: 1,
            progress_marker: String::new(),
            publication_hash: String::new(),
            storage_nodes: endpoints.clone(),
            entropy_hash: String::new(),
            protocol_version: "v1".to_string(),
            hash_chain_proof: None,
            smt_proof: None,
            verification_step: None,
            genesis_nonce: String::new(),
            genesis_profile: "MnemonicV2".to_string(),
        })
        .expect("seed genesis record");
        let router = AppRouterImpl::new(crate::init::SdkConfig {
            node_id: self.slot.to_string(),
            storage_endpoints: endpoints,
            enable_offline: false,
        })
        .expect("router");
        self.router = Some(Arc::new(router));
    }

    /// The device's router. Only meaningful while [`enter`](Self::enter)ed.
    pub fn router(&self) -> &AppRouterImpl {
        self.router.as_deref().expect("device not booted")
    }

    /// Record `peer` in THIS device's contact book (call while entered), pinning
    /// the peer's authenticated AK and Kyber key — exactly what an online
    /// transfer needs before it can verify and encapsulate to the peer.
    pub fn add_contact(&self, peer: &TestDevice) {
        // The pairing flow stores the symmetric initial relationship tip on
        // the contact; the send preflight tripwire compares against it.
        let initial_tip = crate::handlers::app_router_impl::relationship_tip_for_contact_restore(
            self.device_id,
            self.genesis,
            &ContactRecord {
                contact_id: String::new(),
                device_id: peer.device_id.to_vec(),
                alias: String::new(),
                genesis_hash: peer.genesis.to_vec(),
                public_key: Vec::new(),
                kyber_public_key: Vec::new(),
                current_chain_tip: None,
                added_at: 0,
                verified: false,
                verification_proof: None,
                metadata: std::collections::HashMap::new(),
                ble_address: None,
                status: String::new(),
                needs_online_reconcile: false,
                last_seen_online_counter: 0,
                last_seen_ble_counter: 0,
                previous_chain_tip: None,
            },
        )
        .expect("initial relationship tip");
        client_db::store_contact(&ContactRecord {
            contact_id: format!("c_{}", peer.slot),
            device_id: peer.device_id.to_vec(),
            alias: peer.slot.to_string(),
            genesis_hash: peer.genesis.to_vec(),
            public_key: peer.ak_pk.clone(),
            kyber_public_key: peer.kyber_pk.clone(),
            current_chain_tip: Some(initial_tip.to_vec()),
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

    /// Symmetric relationship key with `peer` (the same value from either side).
    pub fn rel_key_with(&self, peer: &TestDevice) -> [u8; 32] {
        dsm::core::bilateral_transaction_manager::compute_smt_key(&self.device_id, &peer.device_id)
    }

    /// Credit `amount` ERA to this device through the ONE production canonical
    /// apply, as an inbound transfer from [`FAUCET_DEVICE_ID`]. Chains on the
    /// faucet relationship's pinned head so it can be called repeatedly.
    pub fn fund(&self, amount: u64) {
        self.enter();
        let core = self.router().core_sdk.clone();
        let faucet_b32 = crate::util::text_id::encode_base32_crockford(&FAUCET_DEVICE_ID);
        let rel = dsm::core::bilateral_transaction_manager::compute_smt_key(
            &self.device_id,
            &FAUCET_DEVICE_ID,
        );
        let parent = client_db::pinned_counterparty_a_head(&rel).expect("pin");
        let step = self.seq.fetch_add(1, Ordering::SeqCst) as u8;
        let (parent, child) = core
            .remote_signed_pair(&faucet_b32, parent, step)
            .expect("faucet pair");
        let nonce = {
            let mut n = vec![0xF0u8; 32];
            n[0] = step;
            n
        };
        let op = dsm::types::operations::Operation::Transfer {
            policy_commit: crate::policy::builtin_policy_commit("ERA").expect("ERA policy"),
            to_device_id: self.device_id.to_vec(),
            amount: dsm::types::token_types::Balance::from_state(amount, [0u8; 32]),
            token_id: b"ERA".to_vec(),
            mode: dsm::types::operations::TransactionMode::Bilateral,
            nonce,
            verification: dsm::types::operations::VerificationType::Standard,
            pre_commit: None,
            recipient: self.device_id.to_vec(),
            to: self.slot.as_bytes().to_vec(),
            message: "faucet".to_string(),
            signature: vec![0; 64],
            authority_policy: None,
        };
        let tx_id =
            crate::types::identifiers::TransactionId::new(format!("faucet-{}-{step}", self.slot));
        let out = core
            .apply_incoming_transfer_full_state(
                op,
                &tx_id,
                &faucet_b32,
                format!("faucet-op-{}-{step}", self.slot).as_bytes(),
                parent,
                child,
            )
            .expect("faucet apply");
        assert!(
            matches!(out, crate::sdk::apply_outcome::ApplyOutcome::Applied { .. }),
            "faucet credit must apply: {out:?}"
        );
    }

    /// The device's spendable ERA as the canonical state machine holds it.
    pub fn era_balance(&self) -> u64 {
        self.enter();
        let pc = crate::policy::builtin_policy_commit("ERA").expect("ERA policy");
        self.router()
            .core_sdk
            .device_head()
            .map(|ds| ds.balance(&pc))
            .unwrap_or(0)
    }

    /// The REAL `wallet.send`: builds, signs, advances, freezes and delivers an
    /// online transfer of `amount` ERA to `to` through the production handler.
    pub async fn send(&self, to: &TestDevice, amount: u64) -> crate::bridge::AppResult {
        self.enter();
        let seq = self.seq.fetch_add(1, Ordering::SeqCst);
        self.router()
            .process_online_transfer_logic(dsm::types::proto::OnlineTransferRequest {
                token_id: "ERA".to_string(),
                to_device_id: to.device_id.to_vec(),
                amount,
                memo: format!("{}->{} #{seq}", self.slot, to.slot),
                signature: Vec::new(),
                nonce: Vec::new(),
                from_device_id: self.device_id.to_vec(),
                chain_tip: Vec::new(),
                seq,
                canonical_operation_bytes: Vec::new(),
                receipt_evidence_digest: Vec::new(),
            })
            .await
    }

    /// The REAL `storage.sync` (pull + push): on a recipient this stages the
    /// polled halves, verifies and applies the pair, converges, ACKs and posts
    /// the countersign delta; on a sender it consumes deltas (finalize),
    /// re-drives unsettled outbox rows and runs GC.
    pub async fn sync(&self) -> dsm::types::proto::StorageSyncResponse {
        self.enter();
        self.router()
            .run_storage_sync_request(dsm::types::proto::StorageSyncRequest {
                pull_inbox: true,
                push_pending: true,
                limit: 50,
            })
            .await
            .expect("storage.sync")
    }
}

/// A booted A/B pair sharing a three-node fleet (identity quorum and delivery
/// quorum are both K=3, as in production), mutually added as contacts and
/// funded. The starting point of every protocol test.
pub struct Pair {
    pub nodes: Vec<FakeB0xNode>,
    pub a: TestDevice,
    pub b: TestDevice,
}

impl Pair {
    /// Every `POST /api/v2/b0x/submit` any node received, in arrival order per
    /// node (node 0's first, then node 1's, ...).
    pub fn submits(&self) -> Vec<crate::test_support::fake_node::RecordedPost> {
        self.nodes.iter().flat_map(|n| n.submits()).collect()
    }

    /// Make every node answer `status` to submits under `message_id`.
    pub fn override_submit(&self, message_id: &str, status: u16) {
        for n in &self.nodes {
            n.override_submit(message_id, status);
        }
    }

    pub fn clear_submit_override(&self, message_id: &str) {
        for n in &self.nodes {
            n.clear_submit_override(message_id);
        }
    }

    /// Take the whole fleet down for writes (`Some(503)`) or back up (`None`).
    pub fn override_all_submits(&self, status: Option<u16>) {
        for n in &self.nodes {
            n.override_all_submits(status);
        }
    }

    /// Number of nodes on which `message_id` is spooled AND acked.
    pub fn acked_count(&self, message_id: &str) -> usize {
        self.nodes
            .iter()
            .filter(|n| n.is_acked(message_id) == Some(true))
            .count()
    }
}

impl Pair {
    /// Boot both devices, register each on the node (its first `storage.sync`
    /// does that, exactly as production does), pin each other as contacts and
    /// fund them.
    pub async fn boot(a_funding: u64, b_funding: u64) -> Self {
        client_db::reset_database_for_tests();
        let nodes: Vec<FakeB0xNode> = (0..3).map(|_| FakeB0xNode::spawn()).collect();
        let endpoints: Vec<String> = nodes.iter().map(|n| n.endpoint.clone()).collect();
        crate::test_support::fake_node::point_env_config_at(&endpoints);
        let mut a = TestDevice::create("A", 0x0A);
        let mut b = TestDevice::create("B", 0x0B);
        a.boot(&nodes);
        b.boot(&nodes);
        a.enter();
        a.add_contact(&b);
        b.enter();
        b.add_contact(&a);
        // First sync = per-endpoint registration (token issue) on every node,
        // driven by polling the peer's route — exactly how a real device
        // becomes resolvable to its counterparty's identity quorum.
        a.sync().await;
        b.sync().await;
        if a_funding > 0 {
            a.fund(a_funding);
        }
        if b_funding > 0 {
            b.fund(b_funding);
        }
        Self { nodes, a, b }
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

    // The identity material the harness hands a peer must be what production
    // actually uses: the AK `wallet.send` signs with (signing authority) and
    // the Kyber key the wallet installs. A mismatch here would make every
    // "peer refuses" assertion downstream a fixture artefact.
    #[test]
    #[serial_test::serial]
    fn device_material_matches_production_derivations() {
        client_db::reset_database_for_tests();
        let node = FakeB0xNode::spawn();
        let mut a = TestDevice::create("A", 0x0A);
        a.boot(std::slice::from_ref(&node));
        assert_eq!(
            crate::sdk::signing_authority::current_public_key().expect("ak"),
            a.ak_pk,
            "signing authority AK == harness AK"
        );
        assert_eq!(
            a.router().wallet.get_kyber_public_key().expect("kyber"),
            a.kyber_pk,
            "wallet Kyber key == harness Kyber key"
        );
        client_db::reset_database_for_tests();
    }
}
