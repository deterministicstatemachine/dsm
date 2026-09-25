// SPDX-License-Identifier: MIT OR Apache-2.0
//! System, state, and sys route handlers.

use dsm::types::proto as generated;
use prost::Message;

use crate::bridge::{AppQuery, AppResult};
use super::app_router_impl::AppRouterImpl;
use super::response_helpers::{pack_envelope_ok, pack_bytes_ok, err};

/// system.generateMnemonic — return a fresh BIP39 mnemonic for display/backup at wallet creation.
/// Stateless: the wallet seed is derived + cached at `system.createGenesisV2` time.
pub(crate) fn handle_generate_mnemonic_query() -> AppResult {
    match crate::sdk::recovery_sdk::RecoverySDK::generate_mnemonic() {
        Ok(m) => pack_bytes_ok(m.into_bytes()),
        Err(e) => err(format!("system.generateMnemonic: {e}")),
    }
}

/// system.createGenesisV2 — canonical mnemonic-rooted wallet creation (whitepaper §2.5,
/// GenesisEntropyProfile::MnemonicV3). The BIP39 mnemonic is the sole root: derive `wallet_seed`,
/// cache it in the unlocked session, then run `create_genesis_v3_self_attested` and install the
/// resulting GenesisState. Nothing is persisted but public values (no s0, no Smaster). Fails
/// closed if the wallet seed cannot be derived/cached.
pub(crate) fn handle_create_genesis_v2_query(q: AppQuery) -> AppResult {
    let pack = match generated::ArgPack::decode(&*q.params) {
        Ok(p) => p,
        Err(e) => return err(format!("decode ArgPack failed: {e}")),
    };
    if pack.codec != generated::Codec::Proto as i32 {
        return err("system.createGenesisV2: ArgPack.codec must be PROTO".into());
    }
    let req = match generated::WalletCreateGenesisV2Request::decode(&*pack.body) {
        Ok(r) => r,
        Err(e) => return err(format!("decode WalletCreateGenesisV2Request failed: {e}")),
    };
    if req.mnemonic.trim().is_empty() {
        return err("system.createGenesisV2: mnemonic is required".into());
    }
    let network_id = if req.network_id.is_empty() {
        String::from_utf8_lossy(dsm::economic::register::BETA_NETWORK_ID).into_owned()
    } else {
        req.network_id.clone()
    };

    // FAIL CLOSED on re-genesis: one wallet identity per process/app-data. The full router,
    // ContactManager, and SDK context all snapshot the identity when they are built — a second
    // successful genesis in the same process would rewrite AppState/persisted genesis to a NEW
    // identity while those keep serving the OLD one (silent split-brain, and the user's newly
    // backed-up mnemonic would not recover the chain actually being advanced). This guard sits
    // BEFORE derive_and_cache_key so a rejected retry can't clobber the cached wallet seed either.
    // (A retry after a genuine mid-genesis failure is still possible: the error paths below roll
    // has_identity back.)
    if crate::sdk::app_state::AppState::get_has_identity() {
        return err(
            "system.createGenesisV2: an identity already exists on this device; wipe app data or \
             restore instead of re-running genesis (fail closed)"
                .into(),
        );
    }

    // Genesis v2 lifecycle rail: drive the frontend securing screen through the SAME native
    // events as the legacy bootstrap path (EventBridge maps these to `genesis.securing-device*`
    // topics the useGenesisFlow hook already renders). The frontend is pure rendering — progress
    // truth lives here. Emission is best-effort: a failed WebView dispatch must never fail the
    // wallet creation itself.
    use crate::generated::genesis_lifecycle_event::Kind as LifecycleKind;
    let emit = |kind: LifecycleKind, progress: u32| {
        if let Err(e) = crate::ingress::push_genesis_lifecycle_event(kind as i32, progress) {
            log::warn!(
                "system.createGenesisV2: lifecycle event dispatch failed (non-fatal): {:?}",
                e
            );
        }
    };
    // Hold phase=securing_device for any concurrent session-state read until this function
    // exits (success OR error), mirroring the finalize_bootstrap_core scope-guard discipline —
    // otherwise a mid-genesis snapshot would report needs_genesis and flash the start screen.
    crate::sdk::session_manager::BOOTSTRAP_SECURING
        .store(true, std::sync::atomic::Ordering::SeqCst);
    struct ClearSecuringOnDrop;
    impl Drop for ClearSecuringOnDrop {
        fn drop(&mut self) {
            crate::sdk::session_manager::BOOTSTRAP_SECURING
                .store(false, std::sync::atomic::Ordering::SeqCst);
        }
    }
    let _clear_securing = ClearSecuringOnDrop;
    emit(LifecycleKind::GenesisKindStarted, 0);
    emit(LifecycleKind::GenesisKindSecuringDevice, 0);

    // 1. Derive + cache the wallet seed from the mnemonic (the unlocked-session secret).
    if let Err(e) = crate::sdk::recovery_sdk::RecoverySDK::derive_and_cache_key(&req.mnemonic) {
        return err(format!(
            "system.createGenesisV2: wallet seed derivation failed: {e}"
        ));
    }
    let wallet_seed = match crate::sdk::recovery_sdk::RecoverySDK::get_cached_wallet_seed() {
        Some(s) => s,
        None => {
            return err(
                "system.createGenesisV2: wallet seed unavailable after unlock (fail closed)".into(),
            )
        }
    };
    emit(LifecycleKind::GenesisKindSecuringProgress, 30);

    // 2. Canonical mnemonic-rooted Genesis v3 (self-attested AttA; G commits the GRK).
    let aph = dsm::core::identity::genesis_v2::genesis_authority_policy_hash();
    let inputs =
        crate::sdk::identity_presentation::OwnerIdentityInputs::beta(network_id.as_bytes());
    let outcome = match dsm::core::identity::genesis::create_genesis_v3_self_attested(
        &wallet_seed,
        inputs.network_id,
        inputs.wallet_index,
        inputs.device_slot,
        inputs.genesis_version,
        &aph,
    ) {
        Ok(o) => o,
        Err(e) => {
            return err(format!(
                "system.createGenesisV2: genesis derivation failed: {e}"
            ))
        }
    };
    emit(LifecycleKind::GenesisKindSecuringProgress, 60);

    // 3–5. Install the genesis state, persist the public record and install the identity.
    let installed = match install_wallet_genesis(&outcome, &wallet_seed, &network_id) {
        Ok(installed) => installed,
        Err(e) => return err(format!("system.createGenesisV2: {e}")),
    };
    let devid = installed.device_id;
    let g = installed.genesis;
    let ak_pk = installed.ak_public_key;
    let smt_root = installed.smt_root;
    let device_id_b32 = crate::util::text_id::encode_base32_crockford(&devid);
    // Any failure from here on must roll the identity mark back before returning the error
    // envelope: Kotlin publishes a session snapshot after EVERY createGenesisV2 response, and
    // with has_identity left true a failed genesis would compute phase=wallet_ready — landing the
    // user on a wallet screen whose router never came up (fail-open). Rolled back, the snapshot
    // honestly reports needs_genesis and the user can retry.
    let fail_rolled_back =
        |msg: String| match crate::sdk::app_state::AppState::set_has_identity(false) {
            Ok(()) => err(msg),
            Err(rollback) => err(format!(
                "{msg}; the identity mark was not rolled back: {rollback}"
            )),
        };
    emit(LifecycleKind::GenesisKindSecuringProgress, 85);

    // 5b. Hot-swap the MinimalBootstrapRouter for the full AppRouter now that the canonical identity
    //     exists (device_id set + wallet seed cached above). Without this the bootstrap router stays
    //     installed for the rest of the session and every post-genesis route (identity.pairingQR,
    //     wallet.*, contacts.*) fails with "requires genesis". The core adapter reads the router slot
    //     live, so the swap takes effect on the very next query.
    match crate::init::install_full_app_router_self_config() {
        Ok(true) => {}
        Ok(false) => {
            return fail_rolled_back(
                "system.createGenesisV2: canonical identity not ready after genesis (fail closed)"
                    .into(),
            )
        }
        Err(e) => {
            return fail_rolled_back(format!(
                "system.createGenesisV2: full AppRouter install failed: {e}"
            ))
        }
    }

    // 5c. IDENTITY PUBLICATION, driven in THIS session: this device's own
    //     directory entry, read back from the network's pinned set
    //     (`identity_publication`). The row FIRST, so a crash between here and
    //     the publish still leaves something for the startup retry to find;
    //     then the publish itself, SPAWNED — genesis never blocks on the
    //     network. Failure is non-fatal: local genesis stays durable, the row
    //     stays unpublished, and the startup retry resumes it.
    {
        let dev_b32 = device_id_b32.clone();
        let g_b32 = crate::util::text_id::encode_base32_crockford(&g);
        if let Err(e) = crate::storage::client_db::publication::upsert_publication_state(
            &dev_b32,
            &g_b32,
            crate::storage::client_db::publication::PublicationState::LocalGenesisCommitted,
            0,
            "",
        ) {
            log::warn!(
                "system.createGenesisV2: failed to record local-genesis publication state: {e}"
            );
        }
        crate::runtime::get_runtime().spawn(async move {
            let short = &dev_b32[..8.min(dev_b32.len())];
            match crate::sdk::identity_publication::publish_identity_now(&dev_b32, &g_b32).await {
                Ok(report) if report.is_published() => log::info!(
                    "system.createGenesisV2: identity PUBLISHED for device={short} ({}/{} \
                     members hold the entry)",
                    report.holders,
                    report.members
                ),
                Ok(report) => log::warn!(
                    "system.createGenesisV2: identity NOT published for device={short} ({}/{} \
                     members hold the entry, {} needed) — local genesis is durable and startup \
                     will retry",
                    report.holders,
                    report.members,
                    report.required
                ),
                Err(e) => log::warn!(
                    "system.createGenesisV2: identity publication failed for device={short}: {e} \
                     — local genesis is durable and startup will retry"
                ),
            }
        });
    }

    // Success rail (mirrors finalize_bootstrap_core): complete → ok. The wallet_ready screen
    // transition itself rides the fresh session snapshot Kotlin publishes after this response.
    emit(LifecycleKind::GenesisKindSecuringComplete, 0);
    emit(LifecycleKind::GenesisKindOk, 0);

    // 6. Return the genesis envelope.
    let resp = generated::GenesisCreated {
        device_id: devid.to_vec(),
        genesis_hash: Some(generated::Hash32 { v: g.to_vec() }),
        public_key: ak_pk,
        smt_root: Some(generated::Hash32 {
            v: smt_root.to_vec(),
        }),
        genesis_nonce: outcome.genesis_nonce.to_vec(),
        network_id,
        locale: req.locale.clone(),
    };
    pack_envelope_ok(generated::envelope::Payload::GenesisCreatedResponse(resp))
}

/// A wallet identity installed on this device by [`install_wallet_genesis`].
pub(crate) struct InstalledGenesis {
    pub(crate) device_id: [u8; 32],
    pub(crate) genesis: [u8; 32],
    pub(crate) ak_public_key: Vec<u8>,
    pub(crate) smt_root: [u8; 32],
}

/// `[device_id 32][genesis_hash 32]` from the genesis route's local answer:
/// its `GenesisCreatedResponse`, nothing else.
#[cfg(test)]
fn genesis_identity_from_answer(framed: &[u8]) -> Result<Vec<u8>, String> {
    let envelope = super::response_helpers::decode_local_envelope(framed)?;
    let Some(generated::envelope::Payload::GenesisCreatedResponse(created)) = envelope.payload
    else {
        return Err(format!(
            "the answer is not a GenesisCreatedResponse: {:?}",
            envelope.payload
        ));
    };
    let genesis = created
        .genesis_hash
        .ok_or_else(|| "the genesis answer carries no genesis hash".to_string())?
        .v;
    if created.device_id.len() != 32 || genesis.len() != 32 {
        return Err(format!(
            "device id {} bytes, genesis hash {} bytes; both must be 32",
            created.device_id.len(),
            genesis.len()
        ));
    }
    let mut identity = created.device_id;
    identity.extend_from_slice(&genesis);
    Ok(identity)
}

/// Wallet creation's local install (`system.createGenesisV2` steps 3–5): the
/// genesis state and device head under the canonical identity, the public
/// genesis record and wallet state, and the identity in `AppState` and the SDK
/// context (entropy rooted in `wallet_seed`). A failure after the identity is
/// marked present rolls the mark back.
pub(crate) fn install_wallet_genesis(
    outcome: &dsm::core::identity::genesis::GenesisCreationOutcome,
    wallet_seed: &[u8],
    network_id: &str,
) -> Result<InstalledGenesis, String> {
    let genesis_state = &outcome.state;
    let devid = genesis_state.device_id;
    let g = genesis_state.hash;
    let ak_pk = genesis_state.signing_key.public_key.clone();

    // 3. Install the genesis state + device head under the canonical v2 identity.
    let device_info = dsm::types::state_types::DeviceInfo::new(devid, ak_pk.clone());
    let core = crate::sdk::core_sdk::CoreSDK::new_with_device(device_info)
        .map_err(|e| format!("CoreSDK init failed: {e}"))?;
    core.install_v2_genesis(genesis_state)
        .map_err(|e| format!("genesis install failed: {e}"))?;
    // The device's SMT root at genesis is the root of the head just installed.
    let smt_root = core
        .device_head()
        .ok_or_else(|| "genesis install left no device head".to_string())?
        .root();

    // 4. Persist the public Genesis v2 record (genesis_nonce + profile + version).
    let device_id_b32 = crate::util::text_id::encode_base32_crockford(&devid);
    let genesis_id_b32 = crate::util::text_id::encode_base32_crockford(&g);
    let nonce_b32 = crate::util::text_id::encode_base32_crockford(&outcome.genesis_nonce);
    let record = crate::storage::client_db::GenesisRecord {
        genesis_id: genesis_id_b32.clone(),
        device_id: device_id_b32.clone(),
        device_birth_binding: String::new(),
        merkle_root: crate::util::text_id::encode_base32_crockford(&smt_root),
        progress_marker: "genesis".to_string(),
        publication_hash: genesis_id_b32,
        entropy_hash: nonce_b32.clone(),
        protocol_version: "genesis-v3".to_string(),
        hash_chain_proof: None,
        smt_proof: None,
        verification_step: None,
        genesis_nonce: nonce_b32,
        genesis_profile: "MnemonicV3".to_string(),
        network_id: network_id.to_string(),
    };
    crate::storage::client_db::store_genesis_record_with_verification(&record)
        .map_err(|e| format!("store genesis record failed: {e}"))?;

    // 5. Install identity into AppState + SDK context (entropy rooted in the wallet seed).
    crate::sdk::app_state::AppState::set_identity_info(
        devid.to_vec(),
        ak_pk.clone(),
        g.to_vec(),
        smt_root.to_vec(),
    )
    .map_err(|e| format!("persist the identity: {e}"))?;
    crate::sdk::app_state::AppState::set_has_identity(true)
        .map_err(|e| format!("persist the identity mark: {e}"))?;
    let entropy = crate::derive_production_entropy(&devid, &g, wallet_seed);
    if let Err(e) = crate::initialize_sdk_context(devid.to_vec(), g.to_vec(), entropy) {
        return Err(
            match crate::sdk::app_state::AppState::set_has_identity(false) {
                Ok(()) => format!("SDK context init failed: {e}"),
                Err(rollback) => format!(
                "SDK context init failed: {e}; the identity mark was not rolled back: {rollback}"
            ),
            },
        );
    }

    Ok(InstalledGenesis {
        device_id: devid,
        genesis: g,
        ak_public_key: ak_pk,
        smt_root,
    })
}

impl AppRouterImpl {
    /// Dispatch handler for `system.*` query routes.
    pub(crate) async fn handle_system_query(&self, q: AppQuery) -> AppResult {
        match q.path.as_str() {
            // -------- canonical mnemonic-rooted Genesis v2 (QueryOp) --------
            "system.generateMnemonic" => handle_generate_mnemonic_query(),
            "system.createGenesisV2" => handle_create_genesis_v2_query(q),
            _ => err(format!("unknown system query: {}", q.path)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sdk::app_state::AppState;

    /// Wallet creation through `system.createGenesisV2`, on a device with no
    /// identity: the answer names exactly the identity the wallet installed.
    #[test]
    #[serial_test::serial]
    fn the_genesis_answer_names_the_identity_the_wallet_installed() {
        crate::economic_fixtures::use_test_storage_dir();
        crate::storage::client_db::reset_database_for_tests();
        crate::storage::client_db::init_database().expect("init db");
        crate::reset_sdk_context_for_testing();
        AppState::reset_for_testing();

        let answer = handle_create_genesis_v2_query(AppQuery {
            path: "system.createGenesisV2".to_string(),
            params: generated::ArgPack {
                codec: generated::Codec::Proto as i32,
                body: generated::WalletCreateGenesisV2Request {
                    mnemonic: crate::economic_fixtures::test_mnemonic(0x5B),
                    locale: String::new(),
                    network_id: String::from_utf8(crate::economic_fixtures::NETWORK.to_vec())
                        .expect("the network id is UTF-8"),
                }
                .encode_to_vec(),
                ..Default::default()
            }
            .encode_to_vec(),
        });
        assert!(answer.success, "{:?}", answer.error_message);

        let identity = genesis_identity_from_answer(&answer.data).expect("the genesis answer");
        assert_eq!(
            Some(identity[..32].to_vec()),
            AppState::get_device_id(),
            "the device id the wallet installed"
        );
        assert_eq!(
            Some(identity[32..].to_vec()),
            AppState::get_genesis_hash(),
            "the genesis the wallet installed"
        );
    }
}
