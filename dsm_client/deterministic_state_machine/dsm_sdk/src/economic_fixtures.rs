// SPDX-License-Identifier: Apache-2.0

//! The funding path for economic tests, reachable from integration tests.
//!
//! Every balance an economic test holds must have been produced by the protocol
//! that produces it on a device. This module is the only sanctioned way for a
//! test to obtain one:
//!
//! ```text
//! identity     the steps system.createGenesisV2 installs a wallet with
//! ERA          the faucet admission
//! user asset   token.create: the genesis supply released to its creator
//! ```
//!
//! There is deliberately no way here to set a balance, a reserve, a head or an
//! admission directly. A balance with no economic lineage is one no admission
//! can debit, so a test holding one proves nothing about the real path.
//!
//! Storage is the storage node's own code on Postgres (`test_support/nodes.rs`,
//! which the SDK's unit and integration tests both run); [`point_sdk_at`]
//! writes the device's environment config for a node set, as a deployed
//! device's config names its fleet.
//!
//! Gated `any(test, feature = "test-utils")`. `test-utils` is non-default and
//! reaches the build only through dev-dependencies, which `cargo build` does not
//! resolve, so none of this ships.

// A fixture's only failure mode IS a panic: a faucet that does not admit or a
// token that does not register is a broken precondition, not a recoverable
// condition for the test to reason about. The production-safety clippy pass runs
// with `--all-features`, which compiles this test-only module under lints
// written for shipped code; the module never reaches an artifact.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use crate::handlers::app_router_impl::AppRouterImpl;
use crate::init::SdkConfig;
use crate::storage::client_db;

/// Set this process's storage base directory — where the device database and
/// `AppState` live — to a directory of its own under the system temp dir, as a
/// device's startup sets it. The first call in the process empties it, so no
/// earlier run's files are read; later calls find it set. Every test that
/// touches device storage calls this first.
pub fn use_test_storage_dir() {
    static EMPTIED: std::sync::Once = std::sync::Once::new();
    let dir = std::env::temp_dir().join(format!("dsm_sdk_test_{}", std::process::id()));
    EMPTIED.call_once(|| {
        if dir.exists() {
            std::fs::remove_dir_all(&dir).expect("empty the test storage dir");
        }
    });
    crate::storage_utils::set_storage_base_dir(dir.clone()).expect("create the test storage dir");
    assert_eq!(
        crate::storage_utils::get_storage_base_dir().as_ref(),
        Some(&dir),
        "the storage base dir was set to another directory first"
    );
}

/// The beta network — the only one whose root-register profile resolves.
/// An unknown network fails closed by design, so a fixture pinned to anything
/// else can never produce an admitted position.
pub const NETWORK: &[u8] = b"dsm-testnet";

/// The device's environment config, pointed at one node set. Dropping it
/// removes the config, so a later test that forgets to point the SDK at its
/// own nodes fails to load a config rather than reaching this set's.
pub struct FleetGuard {
    config_path: std::path::PathBuf,
}

impl FleetGuard {
    /// The endpoints the config names, in pin order.
    pub fn endpoints(&self) -> Vec<String> {
        crate::network::NetworkConfigLoader::load_env_config()
            .expect("the fleet config loads")
            .nodes
            .into_iter()
            .map(|n| n.endpoint)
            .collect()
    }
}

impl Drop for FleetGuard {
    fn drop(&mut self) {
        if let Err(e) = std::fs::remove_file(&self.config_path) {
            eprintln!(
                "fleet config {} was not removed: {e}",
                self.config_path.display()
            );
        }
    }
}

/// Write the device's environment config for a node set: each member as
/// `(member id, endpoint, register incarnation)`, in pin order — what
/// `NodeSet::members` reports. The config lives at one path for the process;
/// the loader reads it on every load, so each test's nodes replace the last.
pub fn point_sdk_at(members: &[(String, String, [u8; 32])]) -> FleetGuard {
    let config_path =
        std::env::temp_dir().join(format!("dsm_sdk_fleet_{}.toml", std::process::id()));
    let mut cfg = String::from(
        "protocol = \"http\"\nlan_ip = \"127.0.0.1\"\nallow_localhost = true\n\
         bitcoin_network = \"signet\"\n",
    );
    for (member_id, endpoint, incarnation) in members {
        cfg.push_str(&format!(
            "\n[[nodes]]\nname = \"{member_id}\"\nendpoint = \"{endpoint}\"\n\
             register_incarnation = \"{}\"\n",
            crate::util::text_id::encode_base32_crockford(incarnation)
        ));
    }
    std::fs::write(&config_path, cfg).expect("write env config");
    let path_text = config_path.to_string_lossy().into_owned();
    crate::network::set_env_config_path(path_text.clone());
    assert_eq!(
        crate::network::get_env_config_path(),
        Some(path_text.as_str()),
        "the env config path was set to another file first"
    );
    FleetGuard { config_path }
}

/// The network's PINNED root-register member ids, in pin order.
pub fn canonical_member_ids() -> Vec<String> {
    dsm::economic::register::pinned_root_register_members(NETWORK)
        .expect("the beta network is pinned")
        .iter()
        .map(|(id, _)| String::from_utf8(id.to_vec()).expect("pinned member ids are UTF-8"))
        .collect()
}

/// The delivery quorum over the pinned register members: the strict
/// majority `publication::quorum_for` — artifact delivery, not authority.
pub fn canonical_quorum() -> usize {
    crate::storage::client_db::publication::quorum_for(canonical_member_ids().len()) as usize
}

/// How many nodes one b0x submit lands on: the submit loop stops at `q`
/// successes, so a fleet of `n > q` holds a message on `q` nodes, not all `n`.
pub fn delivery_quorum() -> usize {
    canonical_quorum().min(canonical_member_ids().len())
}

/// The fewest pinned members whose loss leaves the fleet below quorum: the
/// LAST `n − q + 1` in pin order, so exactly `q − 1` stay reachable and the
/// members earlier in pin order are the ones still answering.
pub fn members_to_break_quorum() -> Vec<String> {
    let ids = canonical_member_ids();
    ids[canonical_quorum() - 1..].to_vec()
}

/// The BIP39 mnemonic a test device `seed` is created from: 24 words over the
/// entropy `[seed; 32]`, so a device is the same device in every run.
pub fn test_mnemonic(seed: u8) -> String {
    bip39::Mnemonic::from_entropy(&[seed; 32])
        .expect("32 bytes of entropy make a mnemonic")
        .to_string()
}

/// A device identity created by [`create_identity`].
pub struct TestIdentity {
    pub device_id: [u8; 32],
    pub genesis: [u8; 32],
    pub ak_public_key: Vec<u8>,
    pub smt_root: [u8; 32],
    /// The BIP39 wallet seed the mnemonic unlocks.
    pub wallet_seed: Vec<u8>,
}

impl TestIdentity {
    /// The device's signing keypair, derived as production derives it.
    pub fn signing_keypair(&self) -> dsm::crypto::signatures::SignatureKeyPair {
        crate::init::derive_device_signing_keypair(&self.wallet_seed, &self.genesis)
            .expect("device signing keypair")
    }
}

/// Create a device identity on the beta network the way wallet creation does:
/// unlock the mnemonic (the wallet seed cached for the session), derive the
/// canonical Genesis v3 under `system.createGenesisV2`'s inputs, and install
/// it — genesis state and head, public genesis record, wallet state, AppState
/// and the SDK context ([`crate::handlers::system_routes::install_wallet_genesis`]).
/// Any identity this process held before is replaced: this is a new device.
pub fn create_identity(seed: u8) -> TestIdentity {
    crate::reset_sdk_context_for_testing();
    let mnemonic = test_mnemonic(seed);
    crate::sdk::recovery_sdk::RecoverySDK::derive_and_cache_key(&mnemonic)
        .expect("unlock the mnemonic");
    let wallet_seed = crate::sdk::recovery_sdk::RecoverySDK::get_cached_wallet_seed()
        .expect("the unlocked wallet seed");
    let inputs = crate::sdk::identity_presentation::OwnerIdentityInputs::beta(NETWORK);
    let outcome = dsm::core::identity::genesis::create_genesis_v3_self_attested(
        &wallet_seed,
        inputs.network_id,
        inputs.wallet_index,
        inputs.device_slot,
        inputs.genesis_version,
        &dsm::core::identity::genesis_v2::genesis_authority_policy_hash(),
    )
    .expect("v3 genesis");
    let network = String::from_utf8(NETWORK.to_vec()).expect("network id is UTF-8");
    let installed =
        crate::handlers::system_routes::install_wallet_genesis(&outcome, &wallet_seed, &network)
            .unwrap_or_else(|e| panic!("install the genesis: {e}"));
    TestIdentity {
        device_id: installed.device_id,
        genesis: installed.genesis,
        ak_public_key: installed.ak_public_key,
        smt_root: installed.smt_root,
        wallet_seed,
    }
}

/// A `CoreSDK` for `identity`, built as the router builds its own: over the
/// device id and AK the genesis installed, restoring the head genesis wrote.
pub fn core_sdk_for(identity: &TestIdentity) -> crate::sdk::core_sdk::CoreSDK {
    crate::sdk::core_sdk::CoreSDK::new_with_device(dsm::types::state_types::DeviceInfo::new(
        identity.device_id,
        identity.ak_public_key.clone(),
    ))
    .expect("CoreSDK")
}

/// A device with a fresh database and a new identity, and its `CoreSDK`: for
/// tests of code that needs a device but no network.
pub fn local_device(seed: u8) -> (TestIdentity, crate::sdk::core_sdk::CoreSDK) {
    use_test_storage_dir();
    client_db::reset_database_for_tests();
    client_db::init_database().expect("init db");
    let identity = create_identity(seed);
    let core = core_sdk_for(&identity);
    (identity, core)
}

/// Publish this device's directory entry on the fleet and require it held by
/// enough members to count as published — what a device's genesis session
/// (and its startup retry) does before anyone can resolve it.
pub async fn publish_identity(device_id: &[u8; 32], genesis: &[u8; 32]) {
    let device_b32 = crate::util::text_id::encode_base32_crockford(device_id);
    let genesis_b32 = crate::util::text_id::encode_base32_crockford(genesis);
    let report = crate::sdk::identity_publication::publish_identity_now(&device_b32, &genesis_b32)
        .await
        .expect("publish the directory entry");
    assert!(
        report.is_published(),
        "{}/{} members hold the directory entry; {} needed",
        report.holders,
        report.members,
        report.required
    );
}

/// The router a device builds once its identity exists, with the durable
/// policy resolver production bring-up installs beside it.
fn device_router(fleet: &FleetGuard, node_id: &str, enable_offline: bool) -> AppRouterImpl {
    let router = AppRouterImpl::new(SdkConfig {
        node_id: node_id.to_string(),
        storage_endpoints: fleet.endpoints(),
        enable_offline,
    })
    .expect("router");
    router.install_policy_resolver();
    router
}

/// A router on a new device identity, holding NOTHING, its directory entry
/// published on the fleet.
pub async fn empty_router(fleet: &FleetGuard, seed: u8) -> AppRouterImpl {
    empty_router_with(fleet, seed, false).await.0
}

/// As [`empty_router`], with the router's offline (bilateral-storage) mode
/// chosen by the caller, and the identity handed back — for a test that drives
/// a protocol handler directly and must sign as the SAME device.
pub async fn empty_router_with(
    fleet: &FleetGuard,
    seed: u8,
    enable_offline: bool,
) -> (AppRouterImpl, TestIdentity) {
    use_test_storage_dir();
    client_db::reset_database_for_tests();
    client_db::init_database().expect("init db");
    let identity = create_identity(seed);
    let router = device_router(fleet, "econ-fixture", enable_offline);
    publish_identity(&identity.device_id, &identity.genesis).await;
    (router, identity)
}

/// Claim ERA through the faucet admission. Returns the admitted economic
/// position.
pub async fn claim_era(router: &AppRouterImpl) -> u64 {
    crate::sdk::faucet_claim_flow::claim_era_faucet(&router.core_sdk, NETWORK)
        .await
        .expect("faucet claim must admit")
        .economic_position
}

/// A router funded with ERA through one faucet admission.
pub async fn funded_router(fleet: &FleetGuard, seed: u8) -> AppRouterImpl {
    let router = empty_router(fleet, seed).await;
    let position = claim_era(&router).await;
    assert_eq!(position, 1, "the faucet claim must be economic position 1");
    router
}

/// A SECOND router over the same identity and the same database — a restart.
///
/// Deliberately does not reset storage, recreate the identity, or fund
/// anything: the point of a cold-start test is that durable state survives, so
/// re-seeding it would destroy the property under test. The head is whatever
/// was persisted.
pub fn restart_router(fleet: &FleetGuard) -> AppRouterImpl {
    // A new PROCESS: the startup-admission record belongs to the process that
    // is being modeled as gone.
    crate::sdk::core_sdk::CoreSDK::forget_process_startup_admissions_for_testing();
    device_router(fleet, "econ-fixture-restart", false)
}

/// Create a user asset through `token.create`: its whole genesis supply
/// released to this device in the creating transition (SoFi §51). Returns the
/// token's policy commit, which does not exist until the token does.
///
/// The router must already hold ERA for the creation fee — call
/// `funded_router` or `claim_era` first.
pub async fn create_asset(
    router: &AppRouterImpl,
    ticker: &str,
    decimals: u32,
    genesis_supply: u128,
) -> [u8; 32] {
    create_asset_with_icon(router, ticker, decimals, genesis_supply, "").await
}

/// [`create_asset`] with the policy's icon field set, for tests of what a
/// token's policy carries to the wallet (its coin artwork).
pub async fn create_asset_with_icon(
    router: &AppRouterImpl,
    ticker: &str,
    decimals: u32,
    genesis_supply: u128,
    icon_url: &str,
) -> [u8; 32] {
    use crate::bridge::{AppInvoke, AppRouter};
    use dsm::types::proto as generated;
    use prost::Message as ProstMessage;

    let args = generated::ArgPack {
        codec: generated::Codec::Proto as i32,
        body: generated::TokenCreateRequest {
            ticker: ticker.into(),
            alias: format!("{ticker} Fixture Asset"),
            decimals,
            genesis_supply_u128: genesis_supply.to_be_bytes().to_vec(),
            burn_enabled: true,
            transferable: true,
            threshold: 1,
            description: String::new(),
            icon_url: icon_url.into(),
            allowlist_device_ids: Vec::new(),
        }
        .encode_to_vec(),
        ..Default::default()
    }
    .encode_to_vec();

    let created = router
        .invoke(AppInvoke {
            method: "token.create".into(),
            args,
        })
        .await;
    assert!(
        created.success,
        "fixture: token.create {ticker}: {:?}",
        created.error_message
    );

    client_db::token_registry::get_token_by_ticker(ticker)
        .expect("registry read")
        .unwrap_or_else(|| panic!("fixture: {ticker} not registered"))
        .policy_commit
}

/// Resume a pending economic admission — the recovery path.
///
/// Returns the admitted economic position. This is what a later admitted
/// operation would trigger on its own (`stage_admission` resumes first); the
/// fixture exposes it so a recovery property can be asserted directly instead
/// of being inferred from a side effect.
pub async fn resume_pending(router: &AppRouterImpl) -> u64 {
    let pending = router
        .core_sdk
        .device_head()
        .and_then(|h| h.pending_economic_admission().cloned())
        .expect("resume_pending: no pending admission on the head");
    crate::sdk::economic_admission_flow::resume_pending_admission(
        &router.core_sdk,
        NETWORK,
        pending,
    )
    .await
    .expect("the pending admission must resume once the register is reachable")
    .economic_position
}

/// The device's ADMITTED economic position, or `None` before activation.
pub fn admitted_position() -> Option<u64> {
    client_db::economic_lineage::get_admitted()
        .expect("read admitted lineage")
        .map(|admitted| admitted.economic_position())
}

/// Does the head carry a pending admission, and in what state?
pub fn pending_state(
    router: &AppRouterImpl,
) -> Option<dsm::economic::admission::EconomicAdmissionState> {
    router
        .core_sdk
        .device_head()
        .and_then(|h| h.pending_economic_admission().cloned())
        .map(|p| p.state)
}
