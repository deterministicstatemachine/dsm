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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sdk::bluetooth_transport::{BleLink, BluetoothDevice, BluetoothMode};
    use async_trait::async_trait;
    use core::pin::Pin;
    use futures::Stream;
    use std::sync::Arc;

    #[derive(Clone)]
    struct MockBleLink;

    #[async_trait]
    impl BleLink for MockBleLink {
        async fn start_scan(&self) -> Result<(), DsmError> {
            Ok(())
        }
        async fn stop_scan(&self) -> Result<(), DsmError> {
            Ok(())
        }
        async fn start_advertise(&self) -> Result<(), DsmError> {
            Ok(())
        }
        async fn stop_advertise(&self) -> Result<(), DsmError> {
            Ok(())
        }
        async fn connect(&self, _device_id: &str) -> Result<(), DsmError> {
            Ok(())
        }
        async fn disconnect(&self, _device_id: &str) -> Result<(), DsmError> {
            Ok(())
        }
        async fn send(&self, _device_id: &str, _bytes: &[u8]) -> Result<(), DsmError> {
            Ok(())
        }
        async fn recv_stream(
            &self,
            _device_id: &str,
        ) -> Result<Pin<Box<dyn Stream<Item = Result<Vec<u8>, DsmError>> + Send>>, DsmError>
        {
            Ok(Box::pin(futures::stream::empty()))
        }
        async fn discovered(&self) -> Result<Vec<BluetoothDevice>, DsmError> {
            Ok(Vec::new())
        }
    }

    fn make_secure_transport() -> SecureBluetoothTransport<MockBleLink> {
        let link = Arc::new(MockBleLink);
        let device = BluetoothDevice::new("local-dev-001", "Local Device");
        SecureBluetoothTransport::new(BluetoothMode::Central, link, device)
    }

    #[test]
    fn new_stores_local_device_id() {
        let transport = make_secure_transport();
        assert_eq!(transport.local_device_id, "local-dev-001");
    }

    #[test]
    fn is_secure_connection_false_initially() {
        let transport = make_secure_transport();
        assert!(!transport.is_secure_connection("remote-device"));
    }

    #[test]
    fn establish_secure_connection_no_connected_device_errors() {
        let transport = make_secure_transport();
        let result = transport.establish_secure_connection("nonexistent-device");
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn send_secure_rejects_without_secure_connection() {
        let transport = make_secure_transport();
        let err = transport
            .send_secure("remote-device", b"hello")
            .await
            .unwrap_err();
        assert!(format!("{err:?}").contains("Secure connection not established"));
    }

    #[test]
    fn clone_transport() {
        let transport = make_secure_transport();
        let cloned = transport.clone();
        assert_eq!(cloned.local_device_id, "local-dev-001");
    }

    #[test]
    fn is_secure_connection_false_for_multiple_devices() {
        let transport = make_secure_transport();
        assert!(!transport.is_secure_connection("device-a"));
        assert!(!transport.is_secure_connection("device-b"));
        assert!(!transport.is_secure_connection("device-c"));
    }

    #[test]
    fn new_with_peripheral_mode() {
        let link = Arc::new(MockBleLink);
        let device = BluetoothDevice::new("periph-001", "Peripheral Device");
        let transport = SecureBluetoothTransport::new(BluetoothMode::Peripheral, link, device);
        assert_eq!(transport.local_device_id, "periph-001");
    }

    #[tokio::test]
    async fn send_secure_different_device_ids_all_fail_without_connection() {
        let transport = make_secure_transport();
        for id in &["dev-a", "dev-b", "dev-c"] {
            let err = transport.send_secure(id, b"data").await.unwrap_err();
            assert!(format!("{err:?}").contains("Secure connection not established"));
        }
    }

    #[test]
    fn establish_secure_connection_different_devices_all_fail() {
        let transport = make_secure_transport();
        assert!(transport.establish_secure_connection("a").is_err());
        assert!(transport.establish_secure_connection("b").is_err());
    }
}
