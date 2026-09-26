// SPDX-License-Identifier: MIT OR Apache-2.0

//! # Bluetooth Bilateral Transaction Module
//!
//! Production BLE transport for offline bilateral transfers. Coordinates
//! GATT server/client roles, MTU-aware frame chunking, and the 3-phase
//! bilateral commit protocol over Bluetooth Low Energy.

pub mod anchor_accept;
pub mod android_ble_bridge;
pub mod bilateral_ble_handler;
pub mod bilateral_envelope;
pub mod bilateral_session;
pub mod bilateral_transport_adapter;
pub mod ble_frame_coordinator;
pub mod frame_classify;
#[cfg(test)]
mod offline_step_tests;
pub mod pairing_orchestrator;

// Re-export bilateral transaction components
pub use bilateral_ble_handler::{
    BilateralBleHandler, BilateralBleSession, BilateralPhase, BilateralSettlementDelegate,
};
pub use bilateral_transport_adapter::{
    BilateralTransportAdapter, BleTransportDelegate, TransportInboundMessage, TransportOutbound,
};
pub use ble_frame_coordinator::{
    BLE_TRANSPORT_VERSION, BleFrameCoordinator, BleFrameHeader, BleFrameType, BleTransportAck,
    BleTransportChunk, BleTransportFlags, BleTransportFrame, BleTransportHeader,
    BleTransportMessage, FrameControlMessage, FrameIngressResult, OutboundTransportMessage,
    PartialTransportMessage, TransportConfig, TransportError, TransportMessageKey,
};
pub use pairing_orchestrator::{PairingOrchestrator, PairingSession, PairingState};

#[cfg(all(target_os = "android", feature = "bluetooth"))]
use dsm::types::error::DsmError;

use std::sync::Arc;
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

/// Bluetooth manager orchestrates bilateral BLE transactions.
pub struct BluetoothManager {
    /// BLE frame coordinator for chunking
    frame_coordinator: Arc<BleFrameCoordinator>,
    /// Protocol adapter that sits above transport
    transport_adapter: Arc<BilateralTransportAdapter>,
    /// Android BLE bridge
    android_bridge: Arc<android_ble_bridge::AndroidBleBridge>,
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

        let transport_adapter = Arc::new(BilateralTransportAdapter::new(Arc::clone(
            &bilateral_handler,
        )));
        let frame_coordinator = Arc::new(BleFrameCoordinator::new(device_id_bytes));
        let android_bridge = Arc::new(android_ble_bridge::AndroidBleBridge::new(
            Arc::clone(&frame_coordinator),
            transport_adapter.clone(),
            device_id_bytes,
        ));

        log::info!(
            "BluetoothManager initialized for device(b32): {}",
            crate::util::text_id::encode_base32_crockford(&device_id_bytes)
        );

        BluetoothManager {
            frame_coordinator,
            transport_adapter,
            android_bridge,
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

    /// Get transport adapter for bilateral authoring/dispatch above transport.
    pub fn transport_adapter(&self) -> &Arc<BilateralTransportAdapter> {
        &self.transport_adapter
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
        self.transport_adapter
            .bilateral_handler()
            .add_verified_contact(contact)
            .await
    }

    /// Check if a contact exists in the BLE bilateral handler
    pub async fn has_verified_contact(&self, device_id: &[u8; 32]) -> bool {
        self.transport_adapter
            .bilateral_handler()
            .has_verified_contact(device_id)
            .await
    }
}

/// The process's one BLE stack, and the identity it was built for: the
/// manager whose handler takes every offline frame, every link event and
/// every user decision.
static BLUETOOTH_STACK: RwLock<Option<([u8; 32], Arc<BluetoothManager>)>> = RwLock::new(None);

/// The BLE stack for `device_id`: the live one, when it was built for this
/// identity; otherwise the one `build` makes, which becomes the live one.
/// `init_dsm_sdk` can run more than once in a process, and it reuses the
/// stack, so the handler that holds a step's session and precommitment is the
/// one every later frame and every user decision on that step reaches.
pub fn bluetooth_manager_for(
    device_id: [u8; 32],
    build: impl FnOnce() -> Result<BluetoothManager, String>,
) -> Result<Arc<BluetoothManager>, String> {
    let mut stack = BLUETOOTH_STACK.write().unwrap_or_else(|e| e.into_inner());
    if let Some((built_for, manager)) = stack.as_ref() {
        if *built_for == device_id {
            return Ok(manager.clone());
        }
    }
    let manager = Arc::new(build()?);
    *stack = Some((device_id, manager.clone()));
    Ok(manager)
}

/// The live BLE stack, if `init_dsm_sdk` has built one.
pub fn get_global_bluetooth_manager() -> Option<Arc<BluetoothManager>> {
    BLUETOOTH_STACK
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .as_ref()
        .map(|(_, manager)| manager.clone())
}

/// Test-only: no live BLE stack.
#[cfg(test)]
pub(crate) fn reset_bluetooth_stack_for_tests() {
    *BLUETOOTH_STACK.write().unwrap_or_else(|e| e.into_inner()) = None;
}

/// Hand a contact to the live BLE stack's handler. With no stack yet there is
/// nothing to hand it to, and nothing is lost: `init_dsm_sdk` loads every
/// stored contact into the stack it builds. Returns whether a stack took it.
#[cfg(all(target_os = "android", feature = "bluetooth"))]
pub async fn sync_contact_to_bluetooth_manager(
    contact: dsm::types::contact_types::DsmVerifiedContact,
) -> Result<bool, String> {
    let Some(bt_mgr) = get_global_bluetooth_manager() else {
        return Ok(false);
    };
    bt_mgr
        .add_verified_contact(contact)
        .await
        .map_err(|e| format!("add_verified_contact failed: {e}"))?;
    Ok(true)
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

#[cfg(test)]
mod stack_tests {
    use super::*;
    use dsm::core::bilateral_transaction_manager::BilateralTransactionManager;
    use dsm::core::contact_manager::DsmContactManager;
    use serial_test::serial;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn stack(identity: &crate::economic_fixtures::TestIdentity) -> BluetoothManager {
        let manager = BilateralTransactionManager::new(
            DsmContactManager::new(identity.device_id),
            identity.signing_keypair(),
            identity.device_id,
            identity.genesis,
            Arc::new(crate::sdk::chain_tip_store::SqliteChainTipStore::new()),
        );
        BluetoothManager::new(
            identity.device_id,
            Arc::new(tokio::sync::RwLock::new(manager)),
        )
    }

    /// The process holds one BLE stack per identity. Init run again for the
    /// same identity reuses the live stack — its handler, sessions and
    /// precommitments — and builds nothing; the bridge JNI hands BLE events to
    /// is the live stack's. A new identity's stack replaces it.
    /// MUTATION CONTROL: building a stack on every call leaves two handlers
    /// live and turns this red.
    #[test]
    #[serial]
    fn the_process_holds_one_ble_stack_per_identity() {
        reset_bluetooth_stack_for_tests();
        let (identity, _core) = crate::economic_fixtures::local_device(0x31);
        let built = AtomicUsize::new(0);
        let first = bluetooth_manager_for(identity.device_id, || {
            built.fetch_add(1, Ordering::SeqCst);
            Ok(stack(&identity))
        })
        .expect("the first init builds the stack");
        let again = bluetooth_manager_for(identity.device_id, || {
            built.fetch_add(1, Ordering::SeqCst);
            Ok(stack(&identity))
        })
        .expect("init again reuses it");
        assert!(
            Arc::ptr_eq(&first, &again),
            "init built a second BLE stack for the same identity"
        );
        assert_eq!(built.load(Ordering::SeqCst), 1);
        assert!(Arc::ptr_eq(
            &get_global_bluetooth_manager().expect("a live stack"),
            &first
        ));
        assert!(
            Arc::ptr_eq(
                &android_ble_bridge::get_global_android_bridge().expect("its bridge"),
                first.android_bridge()
            ),
            "BLE events would reach another stack's bridge"
        );

        let (other, _core) = crate::economic_fixtures::local_device(0x32);
        let replaced = bluetooth_manager_for(other.device_id, || Ok(stack(&other)))
            .expect("a new identity's stack");
        assert!(!Arc::ptr_eq(&first, &replaced));
        assert!(Arc::ptr_eq(
            &get_global_bluetooth_manager().expect("a live stack"),
            &replaced
        ));
        reset_bluetooth_stack_for_tests();
    }
}
