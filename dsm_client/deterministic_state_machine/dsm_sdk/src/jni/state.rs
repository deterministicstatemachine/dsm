//! # JNI Global State
//!
//! Process-global atomic flags and state slots shared across all JNI entry
//! points. BLE address resolution map, bilateral poll flag, and hex parsing.
//!
//! `SDK_READY` has moved to `sdk::session_manager` (always compiled, not cfg-gated).

// SPDX-License-Identifier: MIT OR Apache-2.0
use std::sync::Mutex;
use std::collections::HashMap;
#[cfg(all(target_os = "android", feature = "bluetooth"))]
use std::sync::atomic::AtomicBool;
use once_cell::sync::Lazy;

#[cfg(all(target_os = "android", feature = "bluetooth"))]
pub static BILATERAL_INIT_POLL_STARTED: AtomicBool = AtomicBool::new(false);

pub static DEVICE_ID_TO_ADDR: Lazy<Mutex<HashMap<[u8; 32], String>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

/// Parse a 64-char lowercase hex string into `[u8; 32]`. Returns `None` on bad input.
pub fn parse_hex_32(hex: &str) -> Option<[u8; 32]> {
    if hex.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        let hi = (*hex.as_bytes().get(i * 2)? as char).to_digit(16)? as u8;
        let lo = (*hex.as_bytes().get(i * 2 + 1)? as char).to_digit(16)? as u8;
        out[i] = (hi << 4) | lo;
    }
    Some(out)
}

/// Register a BLE address mapping for a device_id in the in-memory resolution map.
/// Called from BLE pairing flow (ble_events.rs) to ensure resolveBleAddressForDeviceId works.
pub fn register_ble_address_mapping(device_id: &[u8; 32], address: &str) {
    if address.is_empty() {
        return;
    }
    if let Ok(mut map) = DEVICE_ID_TO_ADDR.try_lock() {
        map.insert(*device_id, address.to_string());
        log::info!(
            "register_ble_address_mapping: {:02x}{:02x}... -> {}",
            device_id[0],
            device_id[1],
            address
        );
    } else {
        log::warn!("DEVICE_ID_TO_ADDR lock contention, skipping");
    }
}
