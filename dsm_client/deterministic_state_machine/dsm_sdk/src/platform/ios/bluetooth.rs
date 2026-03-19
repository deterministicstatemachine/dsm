//! iOS Bluetooth Implementation
//!
//! This module provides iOS-specific Bluetooth functionality using Swift/Objective-C
//! bridging to interact with iOS CoreBluetooth framework.

use std::sync::Once;

static INIT: Once = Once::new();

/// Initialize the Bluetooth module
fn init_bluetooth() {
    INIT.call_once(|| {
        // Initialization code runs only once
        log::info!("Initializing iOS Bluetooth module");
    });
}

/// Connect to a Bluetooth device
pub fn connect(device_addr: &str) -> Result<(), String> {
    init_bluetooth();
    log::debug!("Connecting to Bluetooth device: {}", device_addr);

    // Call into Swift/Objective-C via FFI to connect to the device
    match unsafe { ios_bluetooth_connect(device_addr) } {
        0 => {
            log::info!("Successfully connected to device: {}", device_addr);
            Ok(())
        }
        -1 => Err(format!(
            "Invalid device address (encoding error): {}",
            device_addr
        )),
        1 => Err(format!("Device not found: {}", device_addr)),
        2 => Err(format!("Connection refused by device: {}", device_addr)),
        code => Err(format!(
            "Unknown error connecting to device {}: error code {}",
            device_addr, code
        )),
    }
}

/// Disconnect from a Bluetooth device
pub fn disconnect(device_addr: &str) -> Result<(), String> {
    init_bluetooth();
    log::debug!("Disconnecting from Bluetooth device: {}", device_addr);

    // Call into Swift/Objective-C via FFI to disconnect from the device
    match unsafe { ios_bluetooth_disconnect(device_addr) } {
        0 => {
            log::info!("Successfully disconnected from device: {}", device_addr);
            Ok(())
        }
        code => Err(format!(
            "Error disconnecting from device {}: error code {}",
            device_addr, code
        )),
    }
}

/// Send data to a Bluetooth device
pub fn send_data(device_addr: &str, data: &[u8]) -> Result<(), String> {
    init_bluetooth();
    log::debug!("Sending {} bytes to device: {}", data.len(), device_addr);

    // Call into Swift/Objective-C via FFI to send data to the device
    match unsafe { ios_bluetooth_send_data(device_addr, data.as_ptr(), data.len() as u32) } {
        0 => {
            log::debug!(
                "Successfully sent {} bytes to device: {}",
                data.len(),
                device_addr
            );
            Ok(())
        }
        1 => Err(format!("Device not connected: {}", device_addr)),
        2 => Err(format!("Send error to device: {}", device_addr)),
        code => Err(format!(
            "Unknown error sending to device {}: error code {}",
            device_addr, code
        )),
    }
}

/// Receive data from a Bluetooth device with timeout
pub fn receive_data(device_addr: &str, timeout_ms: u32) -> Result<Vec<u8>, String> {
    init_bluetooth();
    log::debug!(
        "Receiving data from device: {} (timeout: {}ms)",
        device_addr,
        timeout_ms
    );

    // Allocate buffer for result size
    let mut size: u32 = 0;

    // Call into Swift/Objective-C via FFI to check data size first
    let status =
        unsafe { ios_bluetooth_receive_data_size(device_addr, timeout_ms, &mut size as *mut u32) };

    match status {
        0 => {
            // Size returned successfully, now allocate buffer and get data
            let mut buffer = vec![0u8; size as usize];

            let recv_status =
                unsafe { ios_bluetooth_receive_data(device_addr, buffer.as_mut_ptr(), size) };

            match recv_status {
                0 => {
                    log::debug!(
                        "Successfully received {} bytes from device: {}",
                        size,
                        device_addr
                    );
                    Ok(buffer)
                }
                code => Err(format!(
                    "Error reading data from device {}: error code {}",
                    device_addr, code
                )),
            }
        }
        1 => Err(format!("Device not connected: {}", device_addr)),
        2 => Err(format!(
            "Timeout waiting for data from device: {}",
            device_addr
        )),
        code => Err(format!(
            "Unknown error receiving from device {}: error code {}",
            device_addr, code
        )),
    }
}

// FFI declarations for Swift/Objective-C functions
extern "C" {
    fn ios_bluetooth_connect(device_addr: *const libc::c_char) -> libc::c_int;
    fn ios_bluetooth_disconnect(device_addr: *const libc::c_char) -> libc::c_int;
    fn ios_bluetooth_send_data(
        device_addr: *const libc::c_char,
        data: *const u8,
        data_len: u32,
    ) -> libc::c_int;
    fn ios_bluetooth_receive_data_size(
        device_addr: *const libc::c_char,
        timeout_ms: u32,
        size_out: *mut u32,
    ) -> libc::c_int;
    fn ios_bluetooth_receive_data(
        device_addr: *const libc::c_char,
        data_out: *mut u8,
        data_len: u32,
    ) -> libc::c_int;
}

// Helper function to convert Rust string to C string.
// Returns null on interior NUL bytes instead of panicking (FFI safety).
fn to_c_string(s: &str) -> *const libc::c_char {
    use std::ffi::CString;
    match CString::new(s) {
        Ok(c) => c.into_raw() as *const libc::c_char,
        Err(_) => {
            log::error!("iOS BLE: string contains interior NUL byte");
            std::ptr::null()
        }
    }
}

// Actual implementations with proper FFI.
// Each wrapper checks for null after to_c_string (interior NUL defense).
unsafe fn ios_bluetooth_connect(device_addr: &str) -> libc::c_int {
    let c_addr = to_c_string(device_addr);
    if c_addr.is_null() {
        return -1;
    }
    let result = ios_bluetooth_connect(c_addr);
    let _ = std::ffi::CString::from_raw(c_addr as *mut libc::c_char);
    result
}

unsafe fn ios_bluetooth_disconnect(device_addr: &str) -> libc::c_int {
    let c_addr = to_c_string(device_addr);
    if c_addr.is_null() {
        return -1;
    }
    let result = ios_bluetooth_disconnect(c_addr);
    let _ = std::ffi::CString::from_raw(c_addr as *mut libc::c_char);
    result
}

unsafe fn ios_bluetooth_send_data(device_addr: &str, data: &[u8]) -> libc::c_int {
    let c_addr = to_c_string(device_addr);
    if c_addr.is_null() {
        return -1;
    }
    let result = ios_bluetooth_send_data(c_addr, data.as_ptr(), data.len() as u32);
    let _ = std::ffi::CString::from_raw(c_addr as *mut libc::c_char);
    result
}

unsafe fn ios_bluetooth_receive_data_size(
    device_addr: &str,
    timeout_ms: u32,
) -> (libc::c_int, u32) {
    let c_addr = to_c_string(device_addr);
    if c_addr.is_null() {
        return (-1, 0);
    }
    let mut size: u32 = 0;
    let result = ios_bluetooth_receive_data_size(c_addr, timeout_ms, &mut size);
    let _ = std::ffi::CString::from_raw(c_addr as *mut libc::c_char);
    (result, size)
}

unsafe fn ios_bluetooth_receive_data(device_addr: &str, buffer: &mut [u8]) -> libc::c_int {
    let c_addr = to_c_string(device_addr);
    if c_addr.is_null() {
        return -1;
    }
    let result = ios_bluetooth_receive_data(c_addr, buffer.as_mut_ptr(), buffer.len() as u32);
    let _ = std::ffi::CString::from_raw(c_addr as *mut libc::c_char);
    result
}
