// SPDX-License-Identifier: Apache-2.0

//! End-to-end tests for the ERA faucet claim flow, over the fake registers —
//! the full lifecycle: ticket won, fence-coupled advance, evidence frozen +
//! published, root registered, verifier-validated, admitted.
//!
//! `flavor = "multi_thread"` is required: the live resolver bridges the sync
//! verifier to async quorum reads via `block_in_place`.

use serial_test::serial;

use dsm::types::device_state::DeviceState;
use dsm::types::state_types::DeviceInfo;

use crate::sdk::core_sdk::CoreSDK;
use crate::sdk::faucet_claim_flow::claim_era_faucet;
use crate::sdk::storage_set::{StorageSet, StorageSetCatalog};
use crate::storage::client_db;

pub(crate) const NETWORK: &[u8] = b"dsm-testnet";

/// Full v3 identity on the beta network (the only one the register profile
/// resolves — fail-closed by design), with the genesis record persisted so
/// the flow can read the committed network back. Mirrors
/// `funded_vault_fixture::install_v3_identity`, which is pinned to
/// `dsm-test` and therefore cannot be reused here.
fn install_testnet_identity(seed: u8) -> (Vec<u8>, [u8; 32], [u8; 32]) {
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
    let (public_key, _sk) = crate::sdk::signing_authority::derive_signing_keys_for_testing(
        &device_id,
        &genesis_hash,
        &wallet_seed,
    )
    .expect("derive signing keypair");
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
        public_key.clone(),
        genesis_hash,
        vec![0u8; 32],
    );
    crate::sdk::app_state::AppState::set_has_identity(true);
    (public_key, genesis.devid, genesis.g)
}

/// Removes the fleet override on drop so tests outside this module keep the
/// hermetic default fleet.
pub(crate) struct FleetGuard;
impl Drop for FleetGuard {
    fn drop(&mut self) {
        std::env::remove_var("DSM_ENV_CONFIG_PATH");
    }
}

/// Point the loader at a fleet whose member NAMES are the canonical register
/// members (`dsm-node-1..3`) — the profile resolves its set by re-hashing
/// member ids, so the default `test-1..3` fleet can never satisfy it. The
/// endpoints are irrelevant: all register I/O is faked in `cfg(test)`.
pub(crate) fn install_canonical_fleet() -> FleetGuard {
    let cfg_path = std::env::temp_dir().join(format!(
        "dsm_sdk_faucet_flow_env_{}.toml",
        std::process::id()
    ));
    let mut cfg = String::from(
        "protocol = \"http\"\nlan_ip = \"127.0.0.1\"\nallow_localhost = true\nports = [8080]\n",
    );
    for i in 1..=3 {
        let inc = crate::economic_fixtures::fixture_register_incarnation(&format!("dsm-node-{i}"));
        cfg.push_str(&format!(
            "\n[[nodes]]\nname = \"dsm-node-{i}\"\nendpoint = \"http://127.0.0.1:808{i}\"\n\
             register_incarnation = \"{inc}\"\n"
        ));
    }
    std::fs::write(&cfg_path, cfg).expect("write env config");
    std::env::set_var("DSM_ENV_CONFIG_PATH", cfg_path.as_os_str());
    FleetGuard
}

pub(crate) fn setup(seed: u8) -> (CoreSDK, FleetGuard) {
    std::env::set_var("DSM_SDK_TEST_MODE", "1");
    let guard = install_canonical_fleet();
    client_db::reset_database_for_tests();
    client_db::init_database().expect("init db");
    crate::sdk::storage_io::fake_registers::reset();
    let (public_key, devid, genesis) = install_testnet_identity(seed);
    let core =
        CoreSDK::new_with_device(DeviceInfo::new(devid, public_key.clone())).expect("core sdk");
    core.set_device_head_for_testing(DeviceState::new(genesis, devid, public_key, 1024));
    (core, guard)
}

fn era() -> [u8; 32] {
    dsm::core::token::token_state_manager::era_policy_commit()
}

fn canonical_set() -> StorageSet {
    let profile = dsm::economic::register::resolve_root_register_profile(NETWORK).expect("profile");
    StorageSetCatalog::from_env_config()
        .expect("catalog")
        .sets()
        .iter()
        .find(|s| {
            crate::sdk::storage_set::as_ccb_members(s)
                .ok()
                .and_then(|m| profile.verify_candidate(&m).ok())
                .is_some()
        })
        .cloned()
        .expect("canonical set resolvable in test mode")
}

/// The process authenticated as ANOTHER device for the duration of one
/// register request, restored on drop. A register member attributes a
/// claim to the device that authenticated the request; a test that has a
/// second party claim must make that party the caller, exactly as a second
/// handset would be — never present its envelope from the first party's
/// session and rely on a lenient double.
struct AsDevice {
    saved: Option<(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>)>,
}

impl AsDevice {
    fn enter(device_id: [u8; 32], public_key: Vec<u8>) -> Self {
        use crate::sdk::app_state::AppState;
        let saved = match (
            AppState::get_device_id(),
            AppState::get_public_key(),
            AppState::get_genesis_hash(),
            AppState::get_device_tree_root(),
        ) {
            (Some(d), Some(p), Some(g), Some(r)) => Some((d, p, g, r.to_vec())),
            _ => None,
        };
        let genesis = AppState::get_genesis_hash().unwrap_or_else(|| vec![0u8; 32]);
        let root = AppState::get_device_tree_root()
            .map(|r| r.to_vec())
            .unwrap_or_else(|| vec![0u8; 32]);
        AppState::set_identity_info(device_id.to_vec(), public_key, genesis, root);
        Self { saved }
    }
}

impl Drop for AsDevice {
    fn drop(&mut self) {
        if let Some((d, p, g, r)) = self.saved.take() {
            crate::sdk::app_state::AppState::set_identity_info(d, p, g, r);
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn a_full_claim_credits_100_era_and_admits_position_1() {
    let (core, _fleet) = setup(0xA1);
    let outcome = claim_era_faucet(&core, NETWORK)
        .await
        .expect("claim succeeds");
    assert_eq!(outcome.tokens_received, 100);
    assert_eq!(outcome.economic_position, 1);

    let head = core.device_head().expect("head");
    assert_eq!(head.balance(&era()), 100, "exactly +100, conservation");
    assert!(
        head.pending_economic_admission().is_none(),
        "admitted ⇒ unfenced"
    );
    let (position, _root) = client_db::economic_lineage::get_admitted()
        .expect("read admitted")
        .expect("admitted recorded");
    assert_eq!(position, 1);
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn a_repeat_claimant_succeeds_on_a_different_ticket() {
    let (core, _fleet) = setup(0xA2);
    let one = claim_era_faucet(&core, NETWORK).await.expect("first claim");
    assert_eq!(one.economic_position, 1);
    let two = claim_era_faucet(&core, NETWORK)
        .await
        .expect("second claim");
    assert_eq!(two.economic_position, 2, "each claim advances the position");
    let head = core.device_head().expect("head");
    assert_eq!(head.balance(&era()), 200, "two claims, exactly 200");
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn poisoned_ticket_does_not_brick_the_faucet_end_to_end() {
    // THE availability regression control, through the WHOLE flow: an
    // attacker consumes the victim's attempt-0 ticket first; the victim's
    // claim still succeeds via the next attempt. If this fails, shared state
    // crept back between tickets. It proves ticket INDEPENDENCE, not
    // guaranteed claimant liveness under targeted pre-consumption — selection
    // is publicly predictable and that residual is documented in the plan.
    let (core, _fleet) = setup(0xA3);
    let head = core.device_head().expect("head");
    let (genesis, devid) = (head.genesis_digest(), head.devid());
    let target = crate::sdk::economic_registers::select_ticket(&genesis, &devid, 1, 0)
        .expect("victim's attempt-0 ticket");

    // Attacker (its own identity/key) wins that exact ticket first — as
    // ITSELF: a register attributes a claim to the authenticated device, so
    // the attacker's envelope must arrive from the attacker's session.
    let (atk_pk, atk_sk) = dsm::crypto::sphincs::generate_sphincs_keypair().unwrap();
    let attacker_devid = [0x67u8; 32];
    let set = canonical_set();
    let poison = dsm::economic::faucet::sign_faucet_ticket_claim(
        &dsm::economic::faucet::FaucetTicketClaimBody {
            faucet_id: dsm::economic::faucet::era_faucet_id(NETWORK),
            ticket_index: target,
            claimant_genesis: [0x66; 32],
            claimant_devid: attacker_devid,
            claimant_economic_position: 1,
            recipient_operation_digest: [0x68; 32],
            claimant_public_key: atk_pk.clone(),
            storage_set_id: set.id(),
        },
        &atk_sk,
    )
    .unwrap();
    {
        let _as_attacker = AsDevice::enter(attacker_devid, atk_pk);
        crate::sdk::economic_registers::claim_faucet_ticket(&set, NETWORK, &poison)
            .await
            .expect("attacker consumes the ticket — allowed, costs exactly that ticket");
    }

    let outcome = claim_era_faucet(&core, NETWORK)
        .await
        .expect("victim claims on the NEXT attempt's ticket");
    assert_eq!(outcome.tokens_received, 100);
    assert_eq!(core.device_head().unwrap().balance(&era()), 100);
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn crash_after_ticket_win_before_acceptance_resumes_byte_identically() {
    // Boundary 1: ticket won at quorum, envelope frozen, then crash before
    // the local advance. The retry re-derives the same ticket, loads the
    // FROZEN envelope (sign-once), gets held-identical from the register,
    // and completes.
    let (core, _fleet) = setup(0xA4);
    let head = core.device_head().expect("head");
    let (genesis, devid) = (head.genesis_digest(), head.devid());
    let faucet_id = dsm::economic::faucet::era_faucet_id(NETWORK);
    let ticket = crate::sdk::economic_registers::select_ticket(&genesis, &devid, 1, 0).unwrap();
    let set = canonical_set();

    // The pre-crash half, exactly as the flow performs it: build the op,
    // sign the envelope, freeze it, win the quorum cell — then "crash".
    let op = dsm::types::operations::Operation::FaucetClaim {
        faucet_id,
        ticket_index: ticket,
    };
    let op_digest = dsm::economic::faucet::dsm_operation_digest(&op.to_bytes());
    let (pk, sk) = crate::sdk::signing_authority::current_keypair().unwrap();
    let envelope = dsm::economic::faucet::sign_faucet_ticket_claim(
        &dsm::economic::faucet::FaucetTicketClaimBody {
            faucet_id,
            ticket_index: ticket,
            claimant_genesis: genesis,
            claimant_devid: devid,
            claimant_economic_position: 1,
            recipient_operation_digest: op_digest,
            claimant_public_key: pk,
            storage_set_id: set.id(),
        },
        &sk,
    )
    .unwrap();
    client_db::economic_faucet::put_frozen_ticket_claim(&faucet_id, ticket, &envelope, 1).unwrap();
    crate::sdk::economic_registers::claim_faucet_ticket(&set, NETWORK, &envelope)
        .await
        .expect("pre-crash quorum win");

    // Restart: the full flow completes on the SAME ticket, same bytes.
    let outcome = claim_era_faucet(&core, NETWORK)
        .await
        .expect("resumed claim");
    assert_eq!(outcome.tokens_received, 100);
    assert_eq!(outcome.economic_position, 1);
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn admissions_are_never_double_finished_and_positions_stay_monotonic() {
    // The admitted store, the register, and the head must agree after every
    // completed admission: re-entering the flow when nothing is pending
    // starts the NEXT admission, never re-finishes or forks the last one.
    let (core, _fleet) = setup(0xA5);
    claim_era_faucet(&core, NETWORK).await.expect("claim 1");
    let second = claim_era_faucet(&core, NETWORK).await.expect("claim 2");
    assert_eq!(second.economic_position, 2);
    let third = claim_era_faucet(&core, NETWORK).await.expect("claim 3");
    assert_eq!(third.economic_position, 3);
    assert_eq!(core.device_head().unwrap().balance(&era()), 300);
    let (position, _root) = client_db::economic_lineage::get_admitted()
        .unwrap()
        .expect("admitted");
    assert_eq!(position, 3);
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn a_faucet_lineage_is_walkable_by_a_foreign_verifier() {
    // THE point of the evidence migration: after a live claim, the SAME
    // resolver a FOREIGN device would use must be able to walk this lineage
    // from the registers and immutable store alone — register winner,
    // manifest, P0–P6 authority evidence (recovering AK + network),
    // sigma_dsm successor evidence, and the full advance_validated conjuncts.
    let (core, _fleet) = setup(0xB7);
    let outcome = claim_era_faucet(&core, NETWORK).await.expect("claim");
    assert_eq!(outcome.economic_position, 1);
    let head = core.device_head().expect("head");
    let (genesis, devid) = (head.genesis_digest(), head.devid());
    let (_, admitted_root) = client_db::economic_lineage::get_admitted()
        .unwrap()
        .expect("admitted");

    // A "foreign" walk: nothing below reads local admission state — the
    // resolver's cache is cleared first so the walk is from position 0.
    client_db::economic_lineage::clear_peer_lineage(&genesis, &devid).unwrap();
    let handle = tokio::runtime::Handle::current();
    let peer = tokio::task::spawn_blocking(move || {
        // block_in_place needs a worker thread; the resolver methods bridge
        // to async internally. The set is built inside the closure so the
        // resolver borrows nothing across the spawn.
        let set = canonical_set();
        let resolver = crate::sdk::economic_registers::LiveRegisterResolver {
            set: &set,
            runtime: handle,
            expected_network_id: NETWORK.to_vec(),
        };
        resolver_walk(&resolver, &genesis, &devid)
    })
    .await
    .expect("join");
    let peer = peer.expect("a faucet lineage MUST be foreign-walkable");
    assert_eq!(peer.validated_root.economic_position(), 1);
    assert_eq!(
        peer.validated_root.economic_root(),
        admitted_root,
        "the foreign walk and the local admission agree byte-for-byte"
    );
    assert!(matches!(
        peer.verified_operation,
        dsm::types::operations::Operation::FaucetClaim { .. }
    ));
}

fn resolver_walk(
    resolver: &crate::sdk::economic_registers::LiveRegisterResolver<'_>,
    genesis: &[u8; 32],
    devid: &[u8; 32],
) -> Result<
    dsm::economic::provenance::ValidatedPeerTransition,
    dsm::economic::provenance::PeerLineageFailure,
> {
    use dsm::economic::provenance::ProvenanceResolver;
    resolver.validated_peer_transition(genesis, devid, 1)
}
