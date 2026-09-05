// SPDX-License-Identifier: Apache-2.0

//! THE legitimate funding path for economic tests, reachable from integration
//! tests.
//!
//! Every balance an economic test holds must have been produced by the protocol
//! that produces it in the real system. This module is the only sanctioned way
//! for a test to obtain one:
//!
//! ```text
//! ERA          real faucet admission                    0x0030
//! user asset   token.create + token.mint                0x0029 -> 0x0023
//! ```
//!
//! There is deliberately no way here to set a balance, a reserve or an
//! admission directly. A balance with no economic lineage is one no admission
//! can debit, so a test holding one proves nothing about the real path.
//!
//! Why fabrication is not harmless here: debits are deliberately NOT fenced in
//! core (a raw local debit is self-harm), so a fabricated balance does not sit
//! below the acceptance boundary — it CROSSES it the moment it is spent,
//! producing a real chain tip, a real SMT root and a real receipt.
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

/// The beta network — the only one whose root-register profile resolves.
/// An unknown network fails closed by design, so a fixture pinned to anything
/// else can never produce an admitted position.
pub const NETWORK: &[u8] = b"dsm-testnet";

/// Restores the hermetic default fleet on drop, so a test that chose a fleet
/// does not hand it to every test that runs after it.
pub struct FleetGuard;

impl Drop for FleetGuard {
    fn drop(&mut self) {
        std::env::remove_var("DSM_ENV_CONFIG_PATH");
    }
}

/// Point the loader at a fleet whose member NAMES are the canonical register
/// members (`dsm-node-1..3`).
///
/// The profile resolves its set by RE-HASHING member ids, so the default
/// `test-1..3` fleet can never satisfy it. The endpoints are irrelevant: all
/// register I/O is faked under `cfg(test)`.
pub fn install_canonical_fleet() -> FleetGuard {
    let cfg_path = std::env::temp_dir().join(format!(
        "dsm_sdk_econ_fixture_env_{}.toml",
        std::process::id()
    ));
    let mut cfg = String::from(
        "protocol = \"http\"\nlan_ip = \"127.0.0.1\"\nallow_localhost = true\nports = [8080]\n",
    );
    for i in 1..=3 {
        let inc = fixture_register_incarnation(&format!("dsm-node-{i}"));
        cfg.push_str(&format!(
            "\n[[nodes]]\nname = \"dsm-node-{i}\"\nendpoint = \"http://127.0.0.1:808{i}\"\n\
             register_incarnation = \"{inc}\"\n"
        ));
    }
    std::fs::write(&cfg_path, cfg).expect("write env config");
    crate::network::set_env_config_path(cfg_path.to_string_lossy().into_owned());
    std::env::set_var("DSM_ENV_CONFIG_PATH", &cfg_path);
    FleetGuard
}

/// A real seed-rooted v3 identity on the beta network, with its genesis record
/// persisted so the admission flow can read the committed network back.
///
/// Returns `(public_key, devid, genesis)`.
pub fn install_testnet_identity(seed: u8) -> (Vec<u8>, [u8; 32], [u8; 32]) {
    let (keypair, devid, genesis) = install_testnet_identity_with_keypair(seed);
    (keypair.public_key().to_vec(), devid, genesis)
}

/// As [`install_testnet_identity`], also handing back the device's signing
/// keypair — for a test that drives a protocol handler directly (the BLE
/// bilateral handler, say) and must sign as the SAME device whose head the
/// router funded. Returns `(keypair, devid, genesis)`.
pub fn install_testnet_identity_with_keypair(
    seed: u8,
) -> (
    dsm::crypto::signatures::SignatureKeyPair,
    [u8; 32],
    [u8; 32],
) {
    let wallet_seed = vec![seed; 64];
    let aph = dsm::core::identity::genesis_session::genesis_authority_policy_hash();
    let genesis = dsm::core::identity::genesis_v3::derive_genesis_v3_self_attested(
        &wallet_seed,
        NETWORK,
        0,
        0,
        3,
        &aph,
    )
    .expect("v3 genesis");
    let device_id = genesis.devid.to_vec();
    let genesis_hash = genesis.g.to_vec();
    crate::sdk::signing_authority::clear_binding_key_for_testing();
    let keypair = crate::sdk::signing_authority::derive_signing_keypair_for_testing(
        &device_id,
        &genesis_hash,
        &wallet_seed,
    )
    .expect("derive signing keypair");
    let public_key = keypair.public_key().to_vec();
    crate::sdk::signing_authority::set_binding_key_for_testing(wallet_seed);
    client_db::store_genesis_record_with_verification(&client_db::GenesisRecord {
        genesis_id: crate::util::text_id::encode_base32_crockford(&genesis.g),
        device_id: crate::util::text_id::encode_base32_crockford(&genesis.devid),
        mpc_proof: String::new(),
        device_birth_binding: String::new(),
        merkle_root: crate::util::text_id::encode_base32_crockford(&[0u8; 32]),
        participant_count: 0,
        progress_marker: "genesis".to_string(),
        publication_hash: crate::util::text_id::encode_base32_crockford(&genesis.g),
        storage_nodes: Vec::new(),
        entropy_hash: crate::util::text_id::encode_base32_crockford(&genesis.genesis_nonce),
        protocol_version: "genesis-v3".to_string(),
        hash_chain_proof: None,
        smt_proof: None,
        verification_step: None,
        genesis_nonce: crate::util::text_id::encode_base32_crockford(&genesis.genesis_nonce),
        genesis_profile: "MnemonicV3".to_string(),
        network_id: "dsm-testnet".to_string(),
    })
    .expect("store genesis record");
    crate::sdk::app_state::AppState::set_identity_info(
        device_id,
        public_key,
        genesis_hash,
        vec![0u8; 32],
    );
    crate::sdk::app_state::AppState::set_has_identity(true);
    (keypair, genesis.devid, genesis.g)
}

/// A router on a real testnet identity, holding NOTHING.
///
/// Position 0 with the real `(G, DevID)` is the only state that can become
/// position 1: admissions re-derive and re-verify everything from the identity,
/// so a lazily-bootstrapped zero-genesis head cannot admit; and `activate`
/// refuses to self-root a head that already holds value it never admitted.
pub fn empty_router(seed: u8) -> (AppRouterImpl, FleetGuard) {
    let (router, keypair, guard) = empty_router_with(seed, false);
    drop(keypair);
    (router, guard)
}

/// As [`empty_router`], with the router's offline (bilateral-storage) mode
/// chosen by the caller, and the identity's signing keypair handed back — for
/// a test that drives a protocol handler directly and must sign as the SAME
/// device whose head the router will fund.
///
/// Returns `(router, keypair, guard)`.
pub fn empty_router_with(
    seed: u8,
    enable_offline: bool,
) -> (
    AppRouterImpl,
    dsm::crypto::signatures::SignatureKeyPair,
    FleetGuard,
) {
    std::env::set_var("DSM_SDK_TEST_MODE", "1");
    let guard = install_canonical_fleet();
    client_db::reset_database_for_tests();
    client_db::init_database().expect("init db");
    crate::sdk::storage_io::fake_registers::reset();
    crate::sdk::storage_io::fake_fleet::reset();
    let (keypair, devid, genesis) = install_testnet_identity_with_keypair(seed);
    let router = AppRouterImpl::new(SdkConfig {
        node_id: "econ-fixture".to_string(),
        storage_endpoints: Vec::new(),
        enable_offline,
    })
    .expect("router");
    router
        .core_sdk
        .set_device_head_for_testing(dsm::types::device_state::DeviceState::new(
            genesis,
            devid,
            keypair.public_key().to_vec(),
            1024,
        ));
    (router, keypair, guard)
}

/// Claim ERA through the REAL faucet admission (0x0030). Returns the admitted
/// economic position.
pub fn claim_era(router: &AppRouterImpl) -> u64 {
    crate::runtime::get_runtime()
        .block_on(crate::sdk::faucet_claim_flow::claim_era_faucet(
            &router.core_sdk,
            NETWORK,
        ))
        .expect("faucet claim must admit")
        .economic_position
}

/// A router funded with ERA through a real faucet admission.
///
/// The ERA amount is the faucet's own payout, so balance assertions written
/// against a hard-coded 100 hold unchanged.
pub fn funded_router(seed: u8) -> (AppRouterImpl, FleetGuard) {
    let (router, guard) = empty_router(seed);
    let position = claim_era(&router);
    assert_eq!(position, 1, "the faucet claim must be economic position 1");
    (router, guard)
}

/// A SECOND router over the same identity and the same database — a restart.
///
/// Deliberately does not reset storage, reinstall the identity, or fund
/// anything: the point of a cold-start test is that durable state survives, so
/// re-seeding it would destroy the property under test. The head is whatever
/// was persisted.
pub fn restart_router() -> AppRouterImpl {
    AppRouterImpl::new(SdkConfig {
        node_id: "econ-fixture-restart".to_string(),
        storage_endpoints: Vec::new(),
        enable_offline: false,
    })
    .expect("router")
}

/// Create a user asset and mint `amount` of it, both ADMITTED — the legitimate
/// second-asset origin (0x0029 authorized issuance, consumed by the 0x0023 arm).
///
/// Returns the token's policy commit, which does not exist until the token does:
/// `token.create` binds the creator's own key as the policy signer, so a commit
/// computed any other way names a policy no device can issue under.
///
/// The router must already hold ERA for the creation fee — call `funded_router`
/// or `claim_era` first.
pub fn mint_asset(router: &AppRouterImpl, ticker: &str, decimals: u32, amount: u64) -> [u8; 32] {
    use crate::bridge::{AppInvoke, AppRouter};
    use dsm::types::proto as generated;
    use prost::Message as _;

    let pack = |body: Vec<u8>| {
        generated::ArgPack {
            schema_hash: Some(generated::Hash32 { v: vec![0u8; 32] }),
            codec: generated::Codec::Proto as i32,
            body,
        }
        .encode_to_vec()
    };

    crate::runtime::get_runtime().block_on(async {
        let created = router
            .invoke(AppInvoke {
                method: "token.create".into(),
                args: pack(
                    generated::TokenCreateRequest {
                        ticker: ticker.into(),
                        alias: format!("{ticker} Fixture Asset"),
                        decimals,
                        max_supply_u128: 0u128.to_be_bytes().to_vec(),
                        initial_alloc_u128: 0u128.to_be_bytes().to_vec(),
                        mint_burn_enabled: true,
                        transferable: true,
                        unlimited_supply: true,
                        mint_burn_threshold: 1,
                        description: String::new(),
                        icon_url: String::new(),
                        allowlist_device_ids: Vec::new(),
                    }
                    .encode_to_vec(),
                ),
            })
            .await;
        assert!(
            created.success,
            "fixture: token.create {ticker}: {:?}",
            created.error_message
        );
        if amount > 0 {
            let minted = router
                .invoke(AppInvoke {
                    method: "token.mint".into(),
                    args: pack(
                        generated::TokenMintRequest {
                            token_id: ticker.into(),
                            amount,
                            message: String::new(),
                        }
                        .encode_to_vec(),
                    ),
                })
                .await;
            assert!(
                minted.success,
                "fixture: token.mint {ticker} {amount}: {:?}",
                minted.error_message
            );
        }
    });

    client_db::token_registry::get_token_by_ticker(ticker)
        .expect("registry read")
        .unwrap_or_else(|| panic!("fixture: {ticker} not registered"))
        .policy_commit
}

/// Take the register fleet down, so no admission can reach quorum.
///
/// This simulates an OUTAGE — a transport condition — and fabricates nothing:
/// the device's balance is still whatever the protocol legitimately gave it,
/// and the operation under test still builds its real write set and witness.
/// It exists so a fail-closed property ("an operation that cannot be admitted
/// must burn nothing and advance nothing") stays reachable without reaching for
/// an unfunded or fabricated head.
pub fn take_register_offline() {
    for i in 1..=3 {
        crate::sdk::storage_io::fake_registers::fail_member(&format!("dsm-node-{i}"), true);
    }
}

/// Bring the register fleet back up.
pub fn bring_register_online() {
    for i in 1..=3 {
        crate::sdk::storage_io::fake_registers::fail_member(&format!("dsm-node-{i}"), false);
    }
}

/// Resume a pending economic admission — the real recovery path.
///
/// Returns the admitted economic position. This is what a later admitted
/// operation would trigger on its own (`stage_admission` resumes first); the
/// fixture exposes it so a recovery property can be asserted directly instead
/// of being inferred from a side effect.
pub fn resume_pending(router: &AppRouterImpl) -> u64 {
    let pending = router
        .core_sdk
        .device_head()
        .and_then(|h| h.pending_economic_admission().cloned())
        .expect("resume_pending: no pending admission on the head");
    crate::runtime::get_runtime()
        .block_on(
            crate::sdk::economic_admission_flow::resume_pending_admission(
                &router.core_sdk,
                NETWORK,
                pending,
            ),
        )
        .expect("the pending admission must resume once the register is reachable")
        .economic_position
}

/// The device's ADMITTED economic position, or `None` before activation.
pub fn admitted_position(_router: &AppRouterImpl) -> Option<u64> {
    client_db::economic_lineage::get_admitted()
        .expect("read admitted lineage")
        .map(|(position, _root)| position)
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

/// A test fleet member's register incarnation, derived from its name so every
/// fixture and every assertion agree without threading the value.
///
/// Production derives nothing: a node's incarnation is random at its first
/// init and lives only in its own database. This stands in for "the value
/// that node reported to whoever wrote the catalog".
pub fn fixture_register_incarnation(member_id: &str) -> String {
    crate::util::text_id::encode_base32_crockford(&fixture_register_incarnation_bytes(member_id))
}

/// The same value as bytes, for fixtures that build the COMMITTED set.
///
/// One derivation for both sides on purpose: a committed set whose
/// incarnations differ from the catalog's resolves to a different set id, and
/// the vault's own storage set stops being resolvable — which is correct
/// behaviour and a useless test failure.
pub fn fixture_register_incarnation_bytes(member_id: &str) -> [u8; 32] {
    // A PINNED member gets its pinned incarnation: a fixture fleet must
    // resolve to the network's real committed register, or every economic
    // path in the fixture fails closed for the right reason and the test
    // proves nothing. Non-members (extra fake nodes) get a derived value —
    // they cannot be in the pinned set by construction.
    dsm::economic::register::pinned_root_register_members(b"dsm-testnet")
        .ok()
        .and_then(|pinned| {
            pinned
                .iter()
                .find(|(id, _)| *id == member_id.as_bytes())
                .map(|(_, inc)| *inc)
        })
        .unwrap_or_else(|| {
            *blake3::hash(format!("dsm-test-incarnation/{member_id}").as_bytes()).as_bytes()
        })
}
