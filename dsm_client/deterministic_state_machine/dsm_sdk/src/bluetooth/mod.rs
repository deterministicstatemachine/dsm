//! # Bluetooth Bilateral Transaction Module
//!
//! Production BLE transport for offline bilateral transfers. Coordinates
//! GATT server/client roles, MTU-aware frame chunking, and the 3-phase
//! bilateral commit protocol over Bluetooth Low Energy.

pub mod android_ble_bridge;
pub mod bilateral_ble_handler;
pub mod bilateral_envelope;
pub mod bilateral_session;
pub mod ble_frame_coordinator;
pub mod pairing_orchestrator;

// Re-export bilateral transaction components
pub use bilateral_ble_handler::{
    BilateralBleHandler, BilateralBleSession, BilateralPhase, BilateralSettlementContext,
    BilateralSettlementDelegate,
};
pub use ble_frame_coordinator::{
    BLE_TRANSPORT_VERSION, BleFrameCoordinator, BleFrameHeader, BleFrameType,
    BleTransportAck, BleTransportChunk, BleTransportFlags, BleTransportFrame,
    BleTransportHeader, OutboundTransportMessage, PartialTransportMessage, TransportConfig,
    TransportError, TransportMessageKey,
};
pub use pairing_orchestrator::{PairingOrchestrator, PairingSession, PairingState};

#[cfg(all(target_os = "android", feature = "bluetooth"))]
use dsm::types::error::DsmError;

use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::RwLock;

/// Global pairing orchestrator
static PAIRING_ORCHESTRATOR: RwLock<Option<Arc<pairing_orchestrator::PairingOrchestrator>>> =
    RwLock::new(None);

/// Get or initialize the global pairing orchestrator
pub fn get_pairing_orchestrator() -> Arc<pairing_orchestrator::PairingOrchestrator> {
    {
        let guard = PAIRING_ORCHESTRATOR
            .read()
            .unwrap_or_else(|e| e.into_inner());
        if let Some(ref orch) = *guard {
            return orch.clone();
        }
    }
    let mut guard = PAIRING_ORCHESTRATOR
        .write()
        .unwrap_or_else(|e| e.into_inner());
    if let Some(ref orch) = *guard {
        return orch.clone();
    }
    let orch = Arc::new(pairing_orchestrator::PairingOrchestrator::new());
    *guard = Some(orch.clone());
    orch
}

/// Test-only: reset the global pairing orchestrator to a fresh, empty state.
/// Safe replacement — acquires a write lock and clears the singleton.
/// Use `#[serial_test]` to ensure tests run sequentially.
#[cfg(test)]
pub fn reset_pairing_orchestrator_for_tests() {
    if let Ok(mut guard) = PAIRING_ORCHESTRATOR.write() {
        *guard = None;
    }
}

/// Manual-accept mode (global flag for bilateral prepare responses)
static MANUAL_ACCEPT: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

pub fn manual_accept_enabled() -> bool {
    MANUAL_ACCEPT.load(std::sync::atomic::Ordering::Relaxed)
}

pub fn set_manual_accept_enabled(v: bool) {
    MANUAL_ACCEPT.store(v, std::sync::atomic::Ordering::Relaxed);
}

/// Bluetooth manager orchestrates bilateral BLE transactions.
pub struct BluetoothManager {
    /// BLE frame coordinator for chunking
    frame_coordinator: Arc<BleFrameCoordinator>,
    /// Android BLE bridge
    android_bridge: Arc<android_ble_bridge::AndroidBleBridge>,
    /// Local device information
    local_device_id: String,
    device_id_bytes: [u8; 32],
}

impl BluetoothManager {
    /// Create a new bluetooth manager with local device info
    pub fn new(
        device_id_bytes: [u8; 32],
        bilateral_tx_manager: Arc<
            tokio::sync::RwLock<
                dsm::core::bilateral_transaction_manager::BilateralTransactionManager,
            >,
        >,
    ) -> Self {
        let device_id = crate::util::text_id::encode_base32_crockford(&device_id_bytes);

        #[allow(unused_mut)]
        let mut bilateral_handler = BilateralBleHandler::new(bilateral_tx_manager, device_id_bytes);

        // Install the application-layer settlement delegate so the BLE transport
        // layer stays coin-agnostic.  All token/balance logic lives in the delegate.
        bilateral_handler.set_settlement_delegate(Arc::new(
            crate::handlers::bilateral_settlement::DefaultBilateralSettlementDelegate,
        ));

        #[cfg(all(target_os = "android", feature = "bluetooth"))]
        {
            use std::sync::Arc;
            let callback_arc: Arc<dyn Fn(&[u8]) + Send + Sync> =
                Arc::new(|event_bytes: &[u8]| {
                    let data = event_bytes.to_vec();
                    crate::runtime::get_runtime().spawn(async move {
                        use prost::Message;
                        use crate::generated;
                        if let Ok(event) = generated::BilateralEventNotification::decode(&data[..])
                        {
                            log::info!(
                                "Bilateral event: type={:?}, counterparty_len={}, status={}",
                                event.event_type,
                                event.counterparty_device_id.len(),
                                event.status
                            );
                        }
                        if let Err(e) = post_bilateral_event_to_webview_jni(data) {
                            log::debug!("(stub) WebView post skipped: {}", e);
                        }
                    });
                });
            bilateral_handler.set_event_callback(callback_arc);
        }

        let bilateral_handler = Arc::new(bilateral_handler);

        // Restore sessions from persistent storage on startup
        // Use std::thread::spawn with its own runtime to avoid requiring an active Tokio runtime
        // This allows BluetoothManager::new() to be called from sync JNI contexts
        let bilateral_handler_clone = Arc::clone(&bilateral_handler);
        std::thread::spawn(move || {
            let rt = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(r) => r,
                Err(e) => {
                    log::warn!("Failed to create runtime for session restoration: {}", e);
                    return;
                }
            };
            rt.block_on(async move {
                if let Err(e) = bilateral_handler_clone
                    .restore_sessions_from_storage()
                    .await
                {
                    log::warn!("Failed to restore bilateral sessions from storage: {}", e);
                }
            });
        });

        let frame_coordinator = Arc::new(BleFrameCoordinator::new(
            Arc::clone(&bilateral_handler),
            device_id_bytes,
        ));
        let android_bridge = Arc::new(android_ble_bridge::AndroidBleBridge::new(
            Arc::clone(&frame_coordinator),
            Arc::clone(&bilateral_handler),
            device_id_bytes,
        ));

        android_ble_bridge::register_global_android_bridge(android_bridge.clone());

        log::info!(
            "BluetoothManager initialized for device(b32): {}",
            crate::util::text_id::encode_base32_crockford(&device_id_bytes)
        );

        BluetoothManager {
            frame_coordinator,
            android_bridge,
            local_device_id: device_id,
            device_id_bytes,
        }
    }
}

impl BluetoothManager {
    /// Process BLE event from Android (bilateral transactions).
    /// Despite the parameter name, input is protobuf-encoded BleEvent bytes
    /// passed as a &str slice from the JNI layer.
    pub async fn handle_android_ble_event(
        &self,
        event_proto: &str,
    ) -> Result<Option<Vec<u8>>, dsm::types::error::DsmError> {
        self.android_bridge
            .handle_ble_event_bytes(event_proto.as_bytes())
            .await
    }

    /// Get frame coordinator for direct access if needed
    pub fn frame_coordinator(&self) -> &Arc<BleFrameCoordinator> {
        &self.frame_coordinator
    }

    /// Get android bridge for direct access if needed
    pub fn android_bridge(&self) -> &Arc<android_ble_bridge::AndroidBleBridge> {
        &self.android_bridge
    }

    /// Add a verified contact to the BLE bilateral handler so it can accept prepares from this peer.
    /// This must be called whenever a new contact is added via the protobuf bridge.
    pub async fn add_verified_contact(
        &self,
        contact: dsm::types::contact_types::DsmVerifiedContact,
    ) -> Result<(), dsm::types::error::DsmError> {
        self.frame_coordinator
            .bilateral_handler()
            .add_verified_contact(contact)
            .await
    }

    /// Check if a contact exists in the BLE bilateral handler
    pub async fn has_verified_contact(&self, device_id: &[u8; 32]) -> bool {
        self.frame_coordinator
            .bilateral_handler()
            .has_verified_contact(device_id)
            .await
    }
}

/// Global Bluetooth Manager registry
static GLOBAL_BT_MANAGER: OnceLock<Arc<BluetoothManager>> = OnceLock::new();

pub fn register_global_bluetooth_manager(manager: Arc<BluetoothManager>) {
    if GLOBAL_BT_MANAGER.set(manager).is_err() {
        log::warn!("BluetoothManager already registered globally");
    }
}

pub fn get_global_bluetooth_manager() -> Option<Arc<BluetoothManager>> {
    GLOBAL_BT_MANAGER.get().cloned()
}

/// Ensure BluetoothManager is initialized and sync a verified contact to it.
/// This handles the late-init case where QR contact is added before BLE init.
/// Returns Ok(true) if contact was synced, Ok(false) if BLE not available, Err on failure.
#[cfg(all(target_os = "android", feature = "bluetooth"))]
pub async fn ensure_bluetooth_manager_and_sync_contact(
    contact: dsm::types::contact_types::DsmVerifiedContact,
) -> Result<bool, String> {
    // First check if manager already exists
    if let Some(bt_mgr) = get_global_bluetooth_manager() {
        log::info!("[BLE] ensure_bluetooth_manager_and_sync_contact: manager exists, syncing contact device_id={:02x?}", 
            &contact.device_id[..8]);
        bt_mgr
            .add_verified_contact(contact)
            .await
            .map_err(|e| format!("add_verified_contact failed: {e}"))?;
        return Ok(true);
    }

    // Manager doesn't exist - try to late-init it
    log::warn!("[BLE] ensure_bluetooth_manager_and_sync_contact: manager not available, attempting late init");

    // Get identity from AppState
    let dev = crate::sdk::app_state::AppState::get_device_id();
    let gen = crate::sdk::app_state::AppState::get_genesis_hash();

    let (dev_fixed, gen_fixed) = match (dev, gen) {
        (Some(d), Some(g)) if d.len() == 32 && g.len() == 32 => {
            let mut df = [0u8; 32];
            let mut gf = [0u8; 32];
            df.copy_from_slice(&d);
            gf.copy_from_slice(&g);
            (df, gf)
        }
        _ => {
            log::error!(
                "[BLE] ensure_bluetooth_manager_and_sync_contact: no valid identity in AppState"
            );
            return Ok(false);
        }
    };

    // Skip if device_id is all zeros
    if dev_fixed == [0u8; 32] {
        log::warn!("[BLE] ensure_bluetooth_manager_and_sync_contact: device_id is zero, skipping");
        return Ok(false);
    }

    // Create the BluetoothManager
    use dsm::core::contact_manager::DsmContactManager;
    use dsm::core::bilateral_transaction_manager::BilateralTransactionManager;
    // Note: Health state tracking removed - always proceed
    use dsm::crypto::signatures::SignatureKeyPair;
    use tokio::sync::RwLock as TokioRwLock;

    let storage_nodes: Vec<dsm::types::identifiers::NodeId> =
        vec![dsm::types::identifiers::NodeId::new("n")];
    let contact_manager = DsmContactManager::new(dev_fixed, storage_nodes);
    let keypair = SignatureKeyPair::new().map_err(|e| format!("keypair generation failed: {e}"))?;
    let chain_tip_store = Arc::new(crate::sdk::chain_tip_store::SqliteChainTipStore::new());
    let btx = Arc::new(TokioRwLock::new(
        BilateralTransactionManager::new_with_chain_tip_store(
            contact_manager,
            keypair,
            dev_fixed,
            gen_fixed,
            chain_tip_store,
        ),
    ));
    let mgr = BluetoothManager::new(dev_fixed, btx);
    let mgr_arc = Arc::new(mgr);

    // Register globally (if another thread beat us, that's fine)
    register_global_bluetooth_manager(mgr_arc.clone());
    log::info!("[BLE] ensure_bluetooth_manager_and_sync_contact: late BluetoothManager registered");

    // CRITICAL: Also inject the coordinator into BiImpl so that processBleChunk,
    // acceptBilateralByCommitment, and bilateralOfflineSend all use the SAME
    // BilateralBleHandler instance. Without this, sessions created by one path
    // are invisible to the other, causing "NO SESSION FOUND" failures.
    let coordinator = mgr_arc.frame_coordinator().clone();
    match crate::bridge::inject_ble_coordinator(coordinator).await {
        Ok(_) => log::info!(
            "[BLE] ensure_bluetooth_manager_and_sync_contact: coordinator injected into BiImpl"
        ),
        Err(e) => log::warn!(
            "[BLE] ensure_bluetooth_manager_and_sync_contact: coordinator injection failed: {e}"
        ),
    }

    // Now sync the contact
    mgr_arc
        .add_verified_contact(contact)
        .await
        .map_err(|e| format!("add_verified_contact (late init) failed: {e}"))?;

    log::info!("[BLE] ensure_bluetooth_manager_and_sync_contact: contact synced successfully");
    Ok(true)
}

/// Non-Android stub for ensure_bluetooth_manager_and_sync_contact
#[cfg(not(all(target_os = "android", feature = "bluetooth")))]
pub async fn ensure_bluetooth_manager_and_sync_contact(
    _contact: dsm::types::contact_types::DsmVerifiedContact,
) -> Result<bool, String> {
    log::debug!("[BLE] ensure_bluetooth_manager_and_sync_contact: not on Android, skipping");
    Ok(false)
}

/// Resync ALL contacts from SQLite to BluetoothManager.
/// This is called when forceBleCoordinatorInit detects an existing BluetoothManager
/// to ensure contacts are loaded even if the initial sync was missed.
/// Returns Ok(count) with number of contacts synced, or Err on failure.
#[cfg(all(target_os = "android", feature = "bluetooth"))]
pub async fn resync_all_contacts_to_bluetooth_manager() -> Result<usize, String> {
    let bt_mgr = get_global_bluetooth_manager()
        .ok_or_else(|| "BluetoothManager not registered".to_string())?;

    let contacts = crate::storage::client_db::get_all_contacts()
        .map_err(|e| format!("Failed to load contacts from SQLite: {e}"))?;

    log::warn!(
        "[BLE] resync_all_contacts_to_bluetooth_manager: 🔄 Syncing {} contacts to BluetoothManager",
        contacts.len()
    );

    let mut synced_count = 0;
    for c in contacts {
        let Some(verified_contact) = c.to_verified_contact() else {
            log::warn!("[BLE] resync_all_contacts: ⚠️ Skipping contact with invalid lengths");
            continue;
        };
        log::warn!(
            "[BLE] resync_all_contacts: contact alias={} public_key_len={}",
            c.alias,
            c.public_key.len()
        );

        match bt_mgr.add_verified_contact(verified_contact).await {
            Ok(_) => {
                log::warn!("[BLE] resync_all_contacts: ✅ Synced contact {}", c.alias);
                synced_count += 1;
            }
            Err(e) => {
                log::warn!(
                    "[BLE] resync_all_contacts: ❌ Failed to sync contact {}: {}",
                    c.alias,
                    e
                );
            }
        }
    }

    log::warn!(
        "[BLE] resync_all_contacts_to_bluetooth_manager: 🔄 Complete. Synced {} contacts",
        synced_count
    );
    Ok(synced_count)
}

/// Non-Android stub for resync_all_contacts_to_bluetooth_manager
#[cfg(not(all(target_os = "android", feature = "bluetooth")))]
pub async fn resync_all_contacts_to_bluetooth_manager() -> Result<usize, String> {
    log::debug!("[BLE] resync_all_contacts_to_bluetooth_manager: not on Android, skipping");
    Ok(0)
}

// Android WebView event dispatch: delegates to the generic event_dispatch module.
// Bytes-only MessagePort: invokes SinglePathWebViewBridge.postBinary("bilateral.event", payloadBytes).
#[cfg(all(target_os = "android", feature = "bluetooth", feature = "jni"))]
pub fn post_bilateral_event_to_webview_jni(event_bytes: Vec<u8>) -> Result<(), DsmError> {
    crate::jni::event_dispatch::post_event_to_webview("bilateral.event", &event_bytes)
}

// Compatibility stub when JNI feature not enabled (desktop builds / non-JNI Android)
#[cfg(all(target_os = "android", feature = "bluetooth", not(feature = "jni")))]
pub fn post_bilateral_event_to_webview_jni(event_bytes: Vec<u8>) -> Result<(), DsmError> {
    log::debug!(
        "(stub-no-jni) post_bilateral_event_to_webview_jni len={} (JNI feature disabled)",
        event_bytes.len()
    );
    Ok(())
}

// Non-Android stub
#[cfg(not(all(target_os = "android", feature = "bluetooth")))]
pub fn post_bilateral_event_to_webview_jni(
    _event_bytes: Vec<u8>,
) -> Result<(), dsm::types::error::DsmError> {
    Ok(())
}

// Mark device as successfully paired - persists GATT connection in Android layer
#[cfg(all(target_os = "android", feature = "bluetooth", feature = "jni"))]
pub fn mark_device_as_paired(ble_address: &str) -> Result<(), DsmError> {
    use crate::jni::jni_common::get_java_vm_borrowed;
    use jni::objects::JValue;

    log::info!("[Bluetooth] Marking device as paired: {}", ble_address);

    let vm = get_java_vm_borrowed()
        .ok_or_else(|| DsmError::invalid_operation("JavaVM not initialized".to_string()))?;

    let mut env = vm
        .attach_current_thread()
        .map_err(|e| DsmError::invalid_operation(format!("Failed to attach JNI thread: {e}")))?;

    let res = (|| -> Result<(), String> {
        // Get the service class
        let service_cls = env
            .find_class("com/dsm/wallet/bridge/DsmBluetoothService")
            .map_err(|e| format!("find_class(DsmBluetoothService) failed: {e}"))?;

        let j_address = env
            .new_string(ble_address)
            .map_err(|e| format!("new_string(address) failed: {e}"))?;

        // Call static helper: markDeviceAsPairedStatic(String address)
        env.call_static_method(
            service_cls,
            "markDeviceAsPairedStatic",
            "(Ljava/lang/String;)V",
            &[JValue::Object(&j_address)],
        )
        .map_err(|e| format!("call_static_method(markDeviceAsPairedStatic) failed: {e}"))?;

        Ok(())
    })();

    match res {
        Ok(_) => {
            log::info!("✅ Device marked as paired in Android: {}", ble_address);
            Ok(())
        }
        Err(err) => {
            log::warn!("⚠️ Failed to mark device as paired: {}", err);
            Err(DsmError::invalid_operation(format!(
                "mark_device_as_paired: {err}"
            )))
        }
    }
}

// Compatibility stub when JNI feature not enabled
#[cfg(all(target_os = "android", feature = "bluetooth", not(feature = "jni")))]
pub fn mark_device_as_paired(_ble_address: &str) -> Result<(), DsmError> {
    log::debug!("(stub-no-jni) mark_device_as_paired (JNI feature disabled)");
    Ok(())
}

// Non-Android platforms stub
#[cfg(not(all(target_os = "android", feature = "bluetooth")))]
pub fn mark_device_as_paired(_ble_address: &str) -> Result<(), dsm::types::error::DsmError> {
    log::debug!("(stub-non-android) mark_device_as_paired");
    Ok(())
}
