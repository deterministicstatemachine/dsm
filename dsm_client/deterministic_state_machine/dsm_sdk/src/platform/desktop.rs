//! # Desktop Platform Implementation
//!
//! Provides `DesktopPlatform` with file-system-based storage and DBRW
//! stubs for non-Android (desktop/test) builds.

use dsm::types::error::DsmError;

#[derive(Debug)]
pub struct DesktopPlatform;

impl Default for DesktopPlatform {
    fn default() -> Self {
        Self::new()
    }
}

impl DesktopPlatform {
    pub fn new() -> Self {
        Self
    }

    pub fn get_device_info(&self) -> Result<String, DsmError> {
        Ok("desktop-device".to_string())
    }
}
