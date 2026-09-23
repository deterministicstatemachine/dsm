// SPDX-License-Identifier: Apache-2.0

//! End-to-end tests for the ERA faucet claim flow, over the fake fleet —
//! the full lifecycle: a generation of the native reserve won leader first,
//! fence-coupled advance, evidence frozen + published, root registered,
//! verifier-validated, admitted.
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
/// members (derived from the pin) — the profile resolves its set by re-hashing
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
    for (i, id) in crate::economic_fixtures::canonical_member_ids()
        .iter()
        .enumerate()
    {
        let inc = crate::economic_fixtures::fixture_register_incarnation(id);
        let port = 8081 + i;
        cfg.push_str(&format!(
            "\n[[nodes]]\nname = \"{id}\"\nendpoint = \"http://127.0.0.1:{port}\"\n\
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
    core.set_device_head_for_testing(DeviceState::new(genesis, devid, public_key));
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
    let (position, _root) = client_db::economic_lineage::get_admitted_coordinate()
        .expect("read admitted")
        .expect("admitted recorded");
    assert_eq!(position, 1);
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn a_repeat_claimant_succeeds_on_the_next_generation() {
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
async fn a_concurrent_claimant_at_the_head_does_not_brick_the_faucet_end_to_end() {
    // THE availability control, through the WHOLE flow: another claimant's
    // release wins the reserve's next generation first (it reached the
    // leader first, and is final). The victim's claim loses that race,
    // re-walks to the moved head, and wins the generation after. Nothing is
    // bricked: a lost generation costs nothing but a retry, and the reserve
    // moved by exactly the other claimant's release.
    let (core, _fleet) = setup(0xA3);
    let set = canonical_set();
    let r0 = crate::sdk::native_reserve::genesis_state(&set, NETWORK);

    // The other claimant (its own identity/key) releases generation 1 to
    // itself — as ITSELF: the release names its own recipient and is signed
    // by its own key.
    let (atk_pk, atk_sk) = dsm::crypto::sphincs::generate_sphincs_keypair().unwrap();
    let rival = dsm::economic::native_reserve::sign_release(
        &dsm::economic::native_reserve::NativeReserveReleaseBody {
            reserve_id: r0.reserve_id,
            parent_root: r0.root(),
            generation: 1,
            amount: dsm::economic::native_reserve::ERA_FAUCET_PAYOUT,
            recipient_genesis: [0x66; 32],
            recipient_devid: [0x67; 32],
            recipient_economic_position: 1,
            recipient_operation_digest: [0x68; 32],
            storage_set_id: set.id(),
            source: dsm::economic::native_reserve::ReleaseSource::FaucetClaimant {
                claimant_public_key: atk_pk,
            },
        },
        &atk_sk,
    )
    .unwrap();
    let write = crate::sdk::native_reserve::write_release(&set, &r0, &rival)
        .await
        .expect("the rival's release reaches the members");
    assert!(write.leader_reached);

    let outcome = claim_era_faucet(&core, NETWORK)
        .await
        .expect("the victim claims the NEXT generation");
    assert_eq!(outcome.tokens_received, 100);
    assert_eq!(core.device_head().unwrap().balance(&era()), 100);
    // The reserve moved by both releases, in order: the rival's at 1, ours at 2.
    let handle = tokio::runtime::Handle::current();
    let head = tokio::task::spawn_blocking({
        let set = set.clone();
        move || crate::sdk::native_reserve::walk_reserve(&set, NETWORK, &handle)
    })
    .await
    .unwrap()
    .expect("walk");
    match head {
        dsm::economic::native_reserve::WalkStop::Head(state) => {
            assert_eq!(state.generation, 2);
            assert_eq!(
                state.remaining_supply,
                dsm::economic::native_reserve::ERA_RESERVE_GENESIS_SUPPLY - 200
            );
        }
        other => panic!("{other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn crash_after_the_release_is_final_before_acceptance_resumes_byte_identically() {
    // Boundary 1: the release is final at the members, frozen locally, then
    // crash before the local advance. The retry walks the reserve, finds the
    // FINAL release naming this device's target position (sign-once: the
    // frozen bytes), and completes on that generation — never releasing a
    // second time for the same position.
    let (core, _fleet) = setup(0xA4);
    let head = core.device_head().expect("head");
    let (genesis, devid) = (head.genesis_digest(), head.devid());
    let set = canonical_set();
    let r0 = crate::sdk::native_reserve::genesis_state(&set, NETWORK);

    // The pre-crash half, exactly as the flow performs it: build the op,
    // sign the release, freeze it, write it leader first — then "crash".
    let op = dsm::types::operations::Operation::FaucetClaim {
        reserve_id: r0.reserve_id,
        generation: 1,
    };
    let op_digest = dsm::economic::admission::dsm_operation_digest(&op.to_bytes());
    let (pk, sk) = crate::sdk::signing_authority::current_keypair().unwrap();
    let envelope = dsm::economic::native_reserve::sign_release(
        &dsm::economic::native_reserve::NativeReserveReleaseBody {
            reserve_id: r0.reserve_id,
            parent_root: r0.root(),
            generation: 1,
            amount: dsm::economic::native_reserve::ERA_FAUCET_PAYOUT,
            recipient_genesis: genesis,
            recipient_devid: devid,
            recipient_economic_position: 1,
            recipient_operation_digest: op_digest,
            storage_set_id: set.id(),
            source: dsm::economic::native_reserve::ReleaseSource::FaucetClaimant {
                claimant_public_key: pk,
            },
        },
        &sk,
    )
    .unwrap();
    client_db::native_reserve::put_frozen_release(&r0.reserve_id, &r0.root(), &envelope, 1)
        .unwrap();
    crate::sdk::native_reserve::write_release(&set, &r0, &envelope)
        .await
        .expect("pre-crash final release");

    // Restart: the full flow completes on the SAME generation, same bytes.
    let outcome = claim_era_faucet(&core, NETWORK)
        .await
        .expect("resumed claim");
    assert_eq!(outcome.tokens_received, 100);
    assert_eq!(outcome.economic_position, 1);
    let handle = tokio::runtime::Handle::current();
    let win = tokio::task::spawn_blocking({
        let set = set.clone();
        move || crate::sdk::native_reserve::release_at(&set, NETWORK, &handle, &r0.reserve_id, 1)
    })
    .await
    .unwrap()
    .expect("memo")
    .expect("generation 1 is final");
    assert_eq!(
        win.envelope_bytes, envelope,
        "the resumed claim used the frozen release"
    );
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
    let (position, _root) = client_db::economic_lineage::get_admitted_coordinate()
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
    let (_, admitted_root) = client_db::economic_lineage::get_admitted_coordinate()
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
    assert_eq!(peer.validated_root().economic_position(), 1);
    assert_eq!(
        peer.validated_root().economic_root(),
        admitted_root,
        "the foreign walk and the local admission agree byte-for-byte"
    );
    assert!(matches!(
        peer.verified_operation(),
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
