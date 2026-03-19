// dsm_sdk/src/sdk/nfc_transport_sdk.rs
//! SDK wrapper for DSM Core NFC Transport API.

use dsm::types::error::DsmError;
use thiserror::Error;

/// Errors specific to NFC transport
#[derive(Error, Debug)]
pub enum NfcError {
    #[error("NFC device not found")]
    DeviceNotFound,

    #[error("NFC connection failed: {0}")]
    ConnectionFailed(String),

    #[error("NFC transport error: {0}")]
    TransportError(String),

    #[error("NFC operation timeout")]
    Timeout,

    #[error("NFC data serialization error: {0}")]
    SerializationError(String),
}

impl From<NfcError> for DsmError {
    fn from(_err: NfcError) -> Self {
        DsmError::network("NFC transport not implemented", None::<std::io::Error>)
    }
}

/// NFC Transport implementation for short-range communication
#[derive(Clone, Debug)]
pub struct NfcTransport {
    device_id: String,
    is_active: bool,
}

impl NfcTransport {
    /// Create a new NFC transport instance
    pub fn new() -> Result<Self, NfcError> {
        // In a real implementation, this would scan for NFC devices and select one.
        // Here, we simulate device detection.
        let device_found = true; // Simulate device detection
        if !device_found {
            return Err(NfcError::DeviceNotFound);
        }
        Ok(Self {
            device_id: "nfc_device_001".to_string(),
            is_active: false,
        })
    }

    /// Send bytes over NFC
    pub fn send(&self, data: &[u8]) -> Result<(), NfcError> {
        if !self.is_active {
            return Err(NfcError::ConnectionFailed("NFC not active".to_string()));
        }
        if data.is_empty() {
            return Err(NfcError::SerializationError("No data to send".to_string()));
        }
        // Simulate NFC transmission
        println!("NFC: Sending {} bytes: {:?}", data.len(), data);
        // In a real implementation, send data to NFC device here.
        Ok(())
    }

    /// Receive bytes over NFC
    pub fn receive(&self) -> Result<Vec<u8>, NfcError> {
        if !self.is_active {
            return Err(NfcError::ConnectionFailed("NFC not active".to_string()));
        }
        // Simulate receiving data
        // In a real implementation, receive data from NFC device here.
        let received_data = vec![0x42, 0x43, 0x44]; // Test data
        println!(
            "NFC: Received {} bytes: {:?}",
            received_data.len(),
            received_data
        );
        Ok(received_data)
    }

    /// Activate NFC for communication
    pub fn activate(&mut self) -> Result<(), NfcError> {
        // In a real implementation, open the NFC device and prepare for communication.
        if self.is_active {
            return Ok(());
        }
        // Simulate activation
        self.is_active = true;
        println!("NFC: Device {} activated", self.device_id);
        Ok(())
    }

    /// Deactivate NFC
    pub fn deactivate(&mut self) -> Result<(), NfcError> {
        // In a real implementation, close the NFC device and release resources.
        if !self.is_active {
            return Ok(());
        }
        // Simulate deactivation
        self.is_active = false;
        println!("NFC: Device {} deactivated", self.device_id);
        Ok(())
    }
}

/// Exposes DSM NFC peer-to-peer transport.
#[derive(Clone, Debug)]
pub struct NfcTransportSDK {
    inner: NfcTransport,
}

impl NfcTransportSDK {
    /// Create a new NFC transport instance.
    pub fn new() -> Result<Self, DsmError> {
        NfcTransport::new()
            .map(|t| NfcTransportSDK { inner: t })
            .map_err(|e: NfcError| {
                DsmError::network(format!("NFC error: {e}"), None::<std::io::Error>)
            })
    }

    /// Send bytes over NFC.
    pub fn send(&self, data: &[u8]) -> Result<(), DsmError> {
        self.inner
            .send(data)
            .map_err(|e: NfcError| DsmError::network("NFC send error", Some(e)))
    }

    /// Receive bytes over NFC.
    pub fn receive(&self) -> Result<Vec<u8>, DsmError> {
        self.inner
            .receive()
            .map_err(|e: NfcError| DsmError::network("NFC receive error", Some(e)))
    }

    /// Activate NFC for communication.
    pub fn activate(&mut self) -> Result<(), DsmError> {
        self.inner
            .activate()
            .map_err(|e: NfcError| DsmError::network("NFC handshake error", Some(e)))
    }

    /// Deactivate NFC.
    pub fn deactivate(&mut self) -> Result<(), DsmError> {
        self.inner
            .deactivate()
            .map_err(|e: NfcError| DsmError::network("NFC exchange error", Some(e)))
    }

    /// Returns whether the NFC transport is currently active.
    pub fn is_active(&self) -> bool {
        self.inner.is_active
    }

    /// Returns the device ID of the NFC transport.
    pub fn device_id(&self) -> &str {
        &self.inner.device_id
    }
}
