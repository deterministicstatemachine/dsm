// SPDX-License-Identifier: MIT OR Apache-2.0
//! # Mandatory Secure BLE Transport
//!
//! Enhanced BLE transport that enforces end-to-end encryption for all communications,
//! preventing MITM attacks and ensuring channel binding.

use crate::sdk::bluetooth_transport::{BleLink, BluetoothDevice, BluetoothTransport, BluetoothMode};
use dsm::types::error::DsmError;
use std::sync::Arc;

/// Mandatory Secure BLE Transport
///
/// Wraps the standard BluetoothTransport to enforce mandatory encryption
/// for all communications, preventing MITM attacks.
#[derive(Clone)]
pub struct SecureBluetoothTransport<L: BleLink> {
    inner: BluetoothTransport<L>,
    local_device_id: String,
}
impl<L: BleLink> SecureBluetoothTransport<L> {
    /// Create a new secure BLE transport
    pub fn new(mode: BluetoothMode, link: Arc<L>, local_device: BluetoothDevice) -> Self {
        let local_device_id = local_device.device_id.clone();
        let inner = BluetoothTransport::new(mode, link, local_device);
        Self {
            inner,
            local_device_id,
        }
    }

    /// Establish a mandatory secure connection
    pub fn establish_secure_connection(&self, device_id: &str) -> Result<(), DsmError> {
        self.inner
            .establish_secure_connection(device_id, &self.local_device_id)
    }

    /// Check if connection is secure
    pub fn is_secure_connection(&self, device_id: &str) -> bool {
        self.inner.is_secure_connection(device_id)
    }

    /// Send data with mandatory encryption
    pub async fn send_secure(&self, device_id: &str, data: &[u8]) -> Result<(), DsmError> {
        if !self.is_secure_connection(device_id) {
            return Err(DsmError::crypto(
                "Secure connection not established",
                None::<String>,
            ));
        }
        self.inner.send_secure(device_id, data).await
    }
}
