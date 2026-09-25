// SPDX-License-Identifier: MIT OR Apache-2.0

//! # The BLE runtime
//!
//! The slots the offline session engine's BLE carrier is injected into: the
//! frame coordinator and the transport adapter. It handles no protocol step.
//! Offline bilateral steps run in `BilateralBleHandler`; the envelope bridge
//! routes none of them.

#[cfg(all(target_os = "android", feature = "bluetooth"))]
use std::sync::Arc;

#[cfg(all(target_os = "android", feature = "bluetooth"))]
use crate::bluetooth::bilateral_transport_adapter::BilateralTransportAdapter;

#[cfg(all(target_os = "android", feature = "bluetooth"))]
use crate::bluetooth::ble_frame_coordinator::BleFrameCoordinator;

/// The BLE runtime slots (Android + bluetooth builds fill them).
#[derive(Default)]
pub struct BiImpl {
    #[cfg(all(target_os = "android", feature = "bluetooth"))]
    ble_coordinator: Arc<tokio::sync::RwLock<Option<Arc<BleFrameCoordinator>>>>,
    #[cfg(all(target_os = "android", feature = "bluetooth"))]
    ble_transport_adapter: Arc<tokio::sync::RwLock<Option<Arc<BilateralTransportAdapter>>>>,
}

impl BiImpl {
    pub fn new() -> Self {
        Self {
            #[cfg(all(target_os = "android", feature = "bluetooth"))]
            ble_coordinator: Arc::new(tokio::sync::RwLock::new(None)),
            #[cfg(all(target_os = "android", feature = "bluetooth"))]
            ble_transport_adapter: Arc::new(tokio::sync::RwLock::new(None)),
        }
    }

    /// Inject BleFrameCoordinator after BLE handler initialization.
    #[cfg(all(target_os = "android", feature = "bluetooth"))]
    pub async fn set_ble_coordinator(&self, coordinator: Arc<BleFrameCoordinator>) {
        let mut guard = self.ble_coordinator.write().await;
        *guard = Some(coordinator);
        log::info!("[BiImpl] BLE coordinator injected successfully");
    }

    /// Get a reference to the BleFrameCoordinator if available.
    #[cfg(all(target_os = "android", feature = "bluetooth"))]
    pub async fn get_ble_coordinator(&self) -> Option<Arc<BleFrameCoordinator>> {
        let guard = self.ble_coordinator.read().await;
        guard.clone()
    }

    #[cfg(all(target_os = "android", feature = "bluetooth"))]
    pub async fn set_ble_transport_adapter(&self, adapter: Arc<BilateralTransportAdapter>) {
        let mut guard = self.ble_transport_adapter.write().await;
        *guard = Some(adapter);
        log::info!("[BiImpl] BLE transport adapter injected successfully");
    }

    #[cfg(all(target_os = "android", feature = "bluetooth"))]
    pub async fn get_ble_transport_adapter(&self) -> Option<Arc<BilateralTransportAdapter>> {
        let guard = self.ble_transport_adapter.read().await;
        guard.clone()
    }
}
