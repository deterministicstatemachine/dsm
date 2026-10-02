// SPDX-License-Identifier: MIT OR Apache-2.0
//! Two-device, one-process test harness for the bilateral protocol.
//!
//! The bilateral tests need two devices (A and B) whose durable state persists
//! across many round-trips. One process has ONE `DB_CONNECTION`, and
//! `cert_chain_heads` is keyed by the SYMMETRIC relationship key, so A's Local
//! head and B's Local head collide in a single database. This harness gives
//! each device its own database file ("slot") and swaps the active one with
//! [`crate::storage::client_db::switch_test_database_slot`].
//!
//! Every step is the device's own path, never a re-implementation of it: an
//! identity is created as wallet creation creates it
//! ([`economic_fixtures::create_identity`]) and published on the fleet; a
//! contact is added through `contacts.addManual`, which resolves the peer's
//! directory entry on the fleet; a send is `wallet.sendSmart` with the request
//! the frontend builds (`dsm/transactions.ts`); a receive, a reply and a
//! finalize are the `storage.sync` query the inbox poller makes, through the
//! router. The fleet is the network's pinned set of storage nodes on Postgres
//! ([`NodeSet`]).
//!
//! STRICTLY SERIALIZED. Exactly one device is active while production code runs;
//! A-side and B-side calls must never overlap in-process, because `AppState`,
//! the cached wallet seed, the SDK context and the bridge's Kyber slot are
//! process-global — one process stands in for two devices' processes, and
//! [`TestDevice::enter`] brings up the entered device's process state. The
//! process's background inbox poller is held off while a [`Pair`] lives: it
//! would sync whichever device is entered at times of its own. This harness
//! proves protocol SEQUENCING, not concurrency.

use crate::bridge::{AppInvoke, AppQuery, AppRouter};
use crate::economic_fixtures::{self, FleetGuard};
use crate::handlers::app_router_impl::AppRouterImpl;
use crate::sdk::app_state::AppState;
use crate::storage::client_db;
use crate::test_support::nodes::NodeSet;
use dsm::types::proto as generated;
use prost::Message;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// One test device: its DB slot, identity and — once [`boot`](Self::boot)ed —
/// its own `AppRouterImpl` (per-device `CoreSDK` state machine and wallet).
#[derive(Clone)]
pub struct TestDevice {
    /// Distinct DB slot suffix.
    pub slot: &'static str,
    /// The seed of the device's mnemonic ([`economic_fixtures::test_mnemonic`]).
    pub seed: u8,
    pub device_id: [u8; 32],
    pub genesis: [u8; 32],
    pub smt_root: [u8; 32],
    /// The device's AK, as its genesis installed it.
    pub ak_pk: Vec<u8>,
    /// The device's Kyber key, as its wallet holds it. Known once booted.
    pub kyber_pk: Vec<u8>,
    router: Option<Arc<AppRouterImpl>>,
    seq: Arc<AtomicU64>,
}

/// How many times one funding claim's held admission is resumed before the
/// harness gives up on it.
const FUNDING_RESUMES: usize = 4;

impl TestDevice {
    /// Create the device's identity the way wallet creation does, in its own
    /// (empty) database slot. Leaves the device entered.
    pub fn create(slot: &'static str, seed: u8) -> Self {
        economic_fixtures::use_test_storage_dir();
        client_db::switch_test_database_slot(slot);
        client_db::init_database().expect("init slot db");
        let identity = economic_fixtures::create_identity(seed);
        Self {
            slot,
            seed,
            device_id: identity.device_id,
            genesis: identity.genesis,
            smt_root: identity.smt_root,
            ak_pk: identity.ak_public_key,
            kyber_pk: Vec::new(),
            router: None,
            seq: Arc::new(AtomicU64::new(1)),
        }
    }

    /// Make this device the active one, as its own process would be: its
    /// database slot, its identity in `AppState`, its wallet unlocked from its
    /// mnemonic, its SDK context and its Kyber key in the bridge. Every
    /// process-global consulted by production code now reflects THIS device
    /// until the next `enter`.
    pub fn enter(&self) {
        client_db::switch_test_database_slot(self.slot);
        client_db::init_database().expect("init slot db");
        AppState::set_identity_info(
            self.device_id.to_vec(),
            self.ak_pk.clone(),
            self.genesis.to_vec(),
            self.smt_root.to_vec(),
        )
        .expect("AppState identity");
        AppState::set_has_identity(true).expect("AppState has_identity");
        crate::reset_sdk_context_for_testing();
        crate::sdk::recovery_sdk::RecoverySDK::derive_and_cache_key(
            &economic_fixtures::test_mnemonic(self.seed),
        )
        .expect("unlock the wallet");
        let wallet_seed = crate::sdk::recovery_sdk::RecoverySDK::get_cached_wallet_seed()
            .expect("the unlocked wallet seed");
        crate::initialize_sdk_context(
            self.device_id.to_vec(),
            self.genesis.to_vec(),
            crate::derive_production_entropy(&self.device_id, &self.genesis, &wallet_seed),
        )
        .expect("SDK context");
        if !self.kyber_pk.is_empty() {
            crate::bridge::install_local_kyber_pubkey(self.kyber_pk.clone());
        }
        // One process has one router: the entered device's.
        if let Some(router) = &self.router {
            crate::bridge::install_app_router(router.clone()).expect("install the router");
        }
    }

    /// Bring the device up on `fleet`: build its `AppRouterImpl` (which loads
    /// its head, and installs its wallet's Kyber key), install the durable
    /// policy resolver and the pinned-anchor store production bring-up
    /// installs beside it, and publish its directory entry. The store reads the
    /// entered device's database, as each device's process reads its own.
    pub async fn boot(&mut self, fleet: &FleetGuard) {
        self.enter();
        let router = AppRouterImpl::new(crate::init::SdkConfig {
            node_id: self.slot.to_string(),
            storage_endpoints: fleet.endpoints(),
            enable_offline: false,
        })
        .expect("router");
        router.install_policy_resolver();
        crate::bridge::install_anchor_enrollment_store(Arc::new(
            crate::sdk::anchor_enrollment_store::SqliteAnchorEnrollmentStore::new(),
        ));
        self.kyber_pk = router
            .wallet
            .get_kyber_public_key()
            .expect("wallet Kyber key");
        self.router = Some(Arc::new(router));
        economic_fixtures::publish_identity(&self.device_id, &self.genesis).await;
    }

    /// The device's router. Only meaningful while [`enter`](Self::enter)ed.
    pub fn router(&self) -> &AppRouterImpl {
        self.router.as_deref().expect("device not booted")
    }

    /// Invoke `method` on this device's router with `body` in a PROTO
    /// `ArgPack`, as the frontend does.
    pub async fn invoke<M: Message>(&self, method: &str, body: &M) -> crate::bridge::AppResult {
        self.enter();
        let args = generated::ArgPack {
            codec: generated::Codec::Proto as i32,
            body: body.encode_to_vec(),
            ..Default::default()
        }
        .encode_to_vec();
        self.router()
            .invoke(AppInvoke {
                method: method.to_string(),
                args,
            })
            .await
    }

    /// Add `peer` to THIS device's contacts through `contacts.addManual`: the
    /// peer's directory entry is resolved on the fleet and its AK must match
    /// the one presented.
    pub async fn add_contact(&self, peer: &TestDevice) {
        let added = self
            .invoke(
                "contacts.addManual",
                &generated::ContactManualAddRequest {
                    alias: peer.slot.to_string(),
                    device_id: peer.device_id.to_vec(),
                    genesis_hash: peer.genesis.to_vec(),
                    signing_public_key: peer.ak_pk.clone(),
                },
            )
            .await;
        assert!(
            added.success,
            "{} adds {}: {:?}",
            self.slot, peer.slot, added.error_message
        );
    }

    /// Symmetric relationship key with `peer` (the same value from either side).
    pub fn rel_key_with(&self, peer: &TestDevice) -> [u8; 32] {
        dsm::core::bilateral_transaction_manager::compute_smt_key(&self.device_id, &peer.device_id)
    }

    /// Fund with economic ancestry: `whole_era` ERA, in faucet claims of the
    /// fixed payout (100.00 ERA each). Amounts must be multiples of the
    /// payout — a fixture asking for anything else is asking for value the
    /// protocol cannot issue. Balances read back in base units.
    pub async fn fund_admitted(&self, whole_era: u64) {
        let scale = 10u64.pow(
            dsm::core::token::era_policy::era_policy()
                .expect("ERA's policy")
                .decimals,
        );
        let payout = dsm::economic::native_reserve::ERA_FAUCET_PAYOUT / scale;
        assert!(
            whole_era.is_multiple_of(payout),
            "fund_admitted: amounts are multiples of the {payout}-ERA faucet payout"
        );
        self.enter();
        let core = self.router().core_sdk.clone();
        for claim in 0..(whole_era / payout) {
            // A claim whose admission is held (its evidence not yet final at
            // every member a verifier reads) is finished by resuming that
            // admission, exactly as the device resumes it before anything
            // else. A failure with nothing held is a refusal.
            let mut outcome =
                crate::sdk::faucet_claim_flow::claim_era_faucet(&core, economic_fixtures::NETWORK)
                    .await
                    .map(drop);
            let mut resumed = 0;
            while let Err(e) = outcome {
                let held = core
                    .device_head()
                    .and_then(|head| head.pending_economic_admission().cloned());
                resumed += 1;
                let Some(pending) = held.filter(|_| resumed <= FUNDING_RESUMES) else {
                    panic!("funding claim {claim}: {e}");
                };
                // The members a verifier reads catch up between attempts.
                tokio::time::sleep(std::time::Duration::from_millis(250 * resumed as u64)).await;
                outcome = crate::sdk::economic_admission_flow::resume_pending_admission(
                    &core,
                    economic_fixtures::NETWORK,
                    pending,
                )
                .await
                .map(drop);
            }
        }
    }

    /// The device's spendable ERA as the canonical state machine holds it.
    pub fn era_balance(&self) -> u64 {
        self.enter();
        let pc = crate::policy::builtin_policy_commit("ERA").expect("ERA policy");
        self.router()
            .core_sdk
            .device_head()
            .expect("a booted device has a head")
            .balance(&pc)
    }

    /// `wallet.sendSmart` of `amount` ERA to `to`: builds, signs, advances,
    /// freezes and delivers an online transfer through the production route.
    pub async fn send(&self, to: &TestDevice, amount: u64) -> crate::bridge::AppResult {
        self.send_token(to, "ERA", amount).await
    }

    /// As [`send`](Self::send), for any asset this device holds, by ticker —
    /// a created token moves through exactly the route ERA does. The request is
    /// the one the frontend builds (`dsm/transactions.ts`): the recipient by
    /// its device id, the amount as the display string in the token's own
    /// decimals.
    /// The SDK owns every protocol field.
    pub async fn send_token(
        &self,
        to: &TestDevice,
        token_id: &str,
        amount: u64,
    ) -> crate::bridge::AppResult {
        self.enter();
        let decimals = crate::handlers::wallet_routes::token_decimals(token_id)
            .expect("the harness sends tokens this device can name");
        let seq = self.seq.fetch_add(1, Ordering::SeqCst);
        self.invoke(
            "wallet.sendSmart",
            &generated::OnlineTransferSmartRequest {
                recipient_device_id: to.device_id.to_vec(),
                amount: crate::handlers::wallet_routes::format_base_units_for_display(
                    amount, decimals,
                ),
                token_id: token_id.to_string(),
                memo: format!("{}->{} #{seq}", self.slot, to.slot),
            },
        )
        .await
    }

    /// `storage.sync` (pull + push), the query the inbox poller makes, through
    /// the router: on a recipient this ingests the polled halves, applies the
    /// bound pair, converges and posts the countersign delta; on a sender it
    /// consumes deltas (finalize), re-drives unsettled outbox rows and runs GC.
    pub async fn sync(&self) -> generated::StorageSyncResponse {
        self.enter();
        let params = generated::ArgPack {
            codec: generated::Codec::Proto as i32,
            body: crate::sdk::inbox_poller::poll_sync_request().encode_to_vec(),
            schema_hash: None,
        }
        .encode_to_vec();
        let answered = self
            .router()
            .query(AppQuery {
                path: "storage.sync".to_string(),
                params,
            })
            .await;
        assert!(
            answered.success,
            "storage.sync: {:?}",
            answered.error_message
        );
        let env = crate::handlers::response_helpers::decode_local_envelope(&answered.data)
            .expect("storage.sync answers an envelope");
        match env.payload {
            Some(generated::envelope::Payload::StorageSyncResponse(resp)) => resp,
            other => panic!("storage.sync answered {other:?}"),
        }
    }
}

/// A sync run while too few members serve to meet every delivery: it ran —
/// what it read was processed and what it owed was pushed — and it is not a
/// complete sync, because a delivery held only by members that did not
/// answer is still there (storage spec §4; owner ruling 2026-09-25).
pub fn assert_incomplete(sync: &generated::StorageSyncResponse) {
    assert!(
        !sync.success,
        "a sync that did not read every delivery reported success: {:?}",
        sync.errors
    );
    assert!(
        sync.errors
            .iter()
            .any(|e| e.contains("inbox read incomplete")),
        "{:?}",
        sync.errors
    );
}

/// A booted A/B pair on the network's pinned set of storage nodes, each device
/// published, mutually added as contacts and funded. The starting point of
/// every protocol test.
pub struct Pair {
    pub nodes: NodeSet,
    pub fleet: FleetGuard,
    pub a: TestDevice,
    pub b: TestDevice,
    /// The background poller is held off while the pair lives; released on
    /// drop, or by [`Pair::release_background_poller`].
    _poller_hold: Option<crate::sdk::inbox_poller::PollerHold>,
}

impl Pair {
    /// Start the nodes, create and boot both devices, add each as the other's
    /// contact and fund them.
    pub async fn boot(a_funding: u64, b_funding: u64) -> Self {
        // No background poller syncs a device behind the harness's back.
        let poller_hold = crate::sdk::inbox_poller::hold_off_for_two_device_harness().await;
        economic_fixtures::use_test_storage_dir();
        client_db::reset_database_for_tests();
        // Fresh nodes per pair: each test gets empty registers, so no earlier
        // test's claims sit where this one will write.
        let nodes = NodeSet::start().await;
        let fleet = economic_fixtures::point_sdk_at(&nodes.members(), nodes.ca_pem());
        let mut a = TestDevice::create("A", 0x0A);
        let mut b = TestDevice::create("B", 0x0B);
        a.boot(&fleet).await;
        b.boot(&fleet).await;
        a.add_contact(&b).await;
        b.add_contact(&a).await;
        if a_funding > 0 {
            a.fund_admitted(a_funding).await;
        }
        if b_funding > 0 {
            b.fund_admitted(b_funding).await;
        }
        Self {
            nodes,
            fleet,
            a,
            b,
            _poller_hold: Some(poller_hold),
        }
    }

    /// Release the pair's hold on the background poller before the pair ends:
    /// a start it deferred runs now.
    pub fn release_background_poller(&mut self) {
        self._poller_hold = None;
    }

    /// The message ids of every envelope node `node` holds in its spool, in
    /// arrival order, as a reader decodes them. Every entry in these suites
    /// is an envelope a device sent.
    pub async fn spooled_message_ids(&self, node: usize) -> Vec<String> {
        self.nodes.nodes[node]
            .spool()
            .await
            .into_iter()
            .map(|spooled| spooled.message_id.expect("a spooled entry is an envelope"))
            .collect()
    }

    /// How many nodes hold `message_id` in their spool.
    pub async fn holders_of(&self, message_id: &str) -> usize {
        let mut holders = 0;
        for node in &self.nodes.nodes {
            if node
                .spool()
                .await
                .iter()
                .any(|spooled| spooled.message_id.as_deref() == Some(message_id))
            {
                holders += 1;
            }
        }
        holders
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The whole reason the harness exists: two devices' durable state must
    /// be isolated. Each device holds the other as a contact and never itself;
    /// if the slots shared one database, each would see both rows.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[serial_test::serial]
    async fn two_device_slots_keep_durable_state_isolated() {
        let p = Pair::boot(0, 0).await;

        p.a.enter();
        assert!(
            client_db::get_contact_by_device_id(&p.b.device_id)
                .expect("query")
                .is_some(),
            "A holds B"
        );
        assert!(
            client_db::get_contact_by_device_id(&p.a.device_id)
                .expect("query")
                .is_none(),
            "A never stored itself; B's write did not bleed into A's slot"
        );

        p.b.enter();
        assert!(
            client_db::get_contact_by_device_id(&p.a.device_id)
                .expect("query")
                .is_some(),
            "B holds A"
        );
        assert!(
            client_db::get_contact_by_device_id(&p.b.device_id)
                .expect("query")
                .is_none(),
            "B never stored itself; A's write did not bleed into B's slot"
        );
    }

    /// The identity material a peer holds must be what the device uses: the
    /// AK its signing authority signs with, and the Kyber key its wallet holds
    /// — carried to the peer by the device's directory entry alone.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[serial_test::serial]
    async fn a_peer_holds_the_keys_the_device_uses() {
        let p = Pair::boot(0, 0).await;

        p.a.enter();
        assert_eq!(
            crate::sdk::signing_authority::current_public_key().expect("ak"),
            p.a.ak_pk,
            "A's signing authority signs with the AK its genesis installed"
        );
        let a_kyber = p.a.router().wallet.get_kyber_public_key().expect("kyber");

        p.b.enter();
        let a_at_b = client_db::get_contact_by_device_id(&p.a.device_id)
            .expect("query")
            .expect("B holds A");
        assert_eq!(a_at_b.public_key, p.a.ak_pk, "B holds A's AK");
        assert_eq!(
            a_at_b.kyber_public_key, a_kyber,
            "B holds the Kyber key A's wallet holds"
        );
    }
}
