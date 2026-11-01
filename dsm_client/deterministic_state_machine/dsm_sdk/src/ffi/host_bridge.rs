// SPDX-License-Identifier: MIT OR Apache-2.0

//! iOS as the SDK's host: Swift registers C callbacks once at start, and
//! every [`HostBridge`] call is one of them. A callback answers `0` when it
//! did what was asked and another code when it did not; the code is what
//! Rust reports.

use std::os::raw::c_char;

use crate::bluetooth::link_session::Link;
use crate::ffi::DsmBytes;
use crate::host::{Delivery, HostBridge};

/// `write_on_link` answered that every record was written.
pub const WRITE_SENT: i32 = 1;
/// `write_on_link` answered that the link is gone or refused a write.
pub const WRITE_NOT_NOW: i32 = 0;

/// What the host does for Rust, as C function pointers. Every pointer is
/// called from Rust's own threads; the host hops to its queues itself.
#[repr(C)]
pub struct DsmHostCallbacks {
    /// Hand the page `payload` under the NUL-terminated `topic`.
    pub post_event: extern "C" fn(topic: *const c_char, payload: *const u8, len: usize) -> i32,
    /// The count on the app icon; zero takes it down.
    pub show_money_received: extern "C" fn(count: i32) -> i32,
    /// Write the records on exactly the link at `address` where this device
    /// is `role` (1 client, 2 server). `records` is each record behind its
    /// big-endian u32 length, back to back. Answers [`WRITE_SENT`],
    /// [`WRITE_NOT_NOW`], or a negative code for a failure to try.
    pub write_on_link:
        extern "C" fn(address: *const c_char, role: i32, records: *const u8, len: usize) -> i32,
    /// Connect for the contact `device_id` (32 bytes), reaching for `hint`
    /// first when it is not empty.
    pub request_connect: extern "C" fn(device_id: *const u8, hint: *const c_char) -> i32,
    pub start_advertising: extern "C" fn() -> i32,
    pub start_scan: extern "C" fn() -> i32,
    pub stop_scan: extern "C" fn() -> i32,
    /// Seal `input` under the device's sealing key into `out`, a buffer the
    /// host takes from `dsm_bytes_alloc`; Rust owns `out` afterwards.
    pub seal_seed: extern "C" fn(input: *const u8, len: usize, out: *mut DsmBytes) -> i32,
    /// Open a blob `seal_seed` made on this device, into `out` as above.
    pub open_seed: extern "C" fn(input: *const u8, len: usize, out: *mut DsmBytes) -> i32,
    /// One line of Rust's log: `level` 1 error, 2 warn, 3 info, 4 debug,
    /// 5 trace; `target` the module that wrote it. The host keeps it where its
    /// own log goes, so a diagnostics report reads both back together.
    pub log_line: extern "C" fn(level: i32, target: *const c_char, message: *const c_char),
}

// Function pointers are plain addresses the host owns for the process's life.
unsafe impl Send for DsmHostCallbacks {}
unsafe impl Sync for DsmHostCallbacks {}

/// The Swift side of the host.
pub struct IosHost {
    callbacks: DsmHostCallbacks,
}

/// `answered` as the host's answer to `what`.
fn answered(what: &str, code: i32) -> Result<(), String> {
    if code == 0 {
        Ok(())
    } else {
        Err(format!("the host's {what} answered {code}"))
    }
}

/// A NUL-terminated copy of `text` for a callback.
fn c_string(text: &str, what: &str) -> Result<std::ffi::CString, String> {
    std::ffi::CString::new(text).map_err(|e| format!("{what} holds a NUL byte: {e}"))
}

/// `records`, each behind its big-endian u32 length.
pub fn frame_records(records: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::with_capacity(records.iter().map(|r| 4 + r.len()).sum());
    for record in records {
        out.extend_from_slice(&(record.len() as u32).to_be_bytes());
        out.extend_from_slice(record);
    }
    out
}

/// Run a seal/open callback and take the bytes it filled in.
fn transform(
    what: &str,
    callback: extern "C" fn(*const u8, usize, *mut DsmBytes) -> i32,
    input: &[u8],
) -> Result<Vec<u8>, String> {
    let mut out = DsmBytes::none();
    let code = callback(input.as_ptr(), input.len(), &mut out);
    // Whatever the code, the buffer is Rust's now.
    let bytes = if out.ptr.is_null() {
        Vec::new()
    } else {
        unsafe { Vec::from_raw_parts(out.ptr, out.len, out.cap) }
    };
    answered(what, code)?;
    if bytes.is_empty() {
        return Err(format!("the host's {what} answered no bytes"));
    }
    Ok(bytes)
}

impl HostBridge for IosHost {
    fn post_event(&self, topic: &str, payload: &[u8]) -> Result<(), String> {
        let topic_c = c_string(topic, "an event topic")?;
        answered(
            "post_event",
            (self.callbacks.post_event)(topic_c.as_ptr(), payload.as_ptr(), payload.len()),
        )
    }

    fn show_money_received(&self, count: i32) -> Result<(), String> {
        answered(
            "show_money_received",
            (self.callbacks.show_money_received)(count),
        )
    }

    fn write_on_link(&self, link: &Link, sealed: &[Vec<u8>]) -> Result<Delivery, String> {
        let address = c_string(&link.address, "a link address")?;
        let framed = frame_records(sealed);
        let code = (self.callbacks.write_on_link)(
            address.as_ptr(),
            link.role.to_wire(),
            framed.as_ptr(),
            framed.len(),
        );
        match code {
            WRITE_SENT => Ok(Delivery::Sent),
            WRITE_NOT_NOW => Ok(Delivery::NotNow),
            other => Err(format!("the host's write_on_link answered {other}")),
        }
    }

    fn request_connect(
        &self,
        device_id: &[u8; 32],
        address_hint: Option<&str>,
    ) -> Result<(), String> {
        // The callback reads an empty hint as "no address to try first": that
        // is its spelling of the absent hint, as Kotlin's requestGattConnect.
        let hint_text = match address_hint {
            Some(address) => address,
            None => "",
        };
        let hint = c_string(hint_text, "an address hint")?;
        answered(
            "request_connect",
            (self.callbacks.request_connect)(device_id.as_ptr(), hint.as_ptr()),
        )
    }

    fn start_advertising(&self) -> Result<(), String> {
        answered("start_advertising", (self.callbacks.start_advertising)())
    }

    fn start_scan(&self) -> Result<(), String> {
        answered("start_scan", (self.callbacks.start_scan)())
    }

    fn stop_scan(&self) -> Result<(), String> {
        answered("stop_scan", (self.callbacks.stop_scan)())
    }

    fn seal_seed(&self, plaintext: &[u8]) -> Result<Vec<u8>, String> {
        transform("seal_seed", self.callbacks.seal_seed, plaintext)
    }

    fn open_seed(&self, blob: &[u8]) -> Result<Vec<u8>, String> {
        transform("open_seed", self.callbacks.open_seed, blob)
    }

    fn as_ios(&self) -> Option<&IosHost> {
        Some(self)
    }
}

impl IosHost {
    /// Hand one log record to the host.
    fn log_line(&self, record: &log::Record<'_>) {
        let level = match record.level() {
            log::Level::Error => 1,
            log::Level::Warn => 2,
            log::Level::Info => 3,
            log::Level::Debug => 4,
            log::Level::Trace => 5,
        };
        let text = record.args().to_string();
        match (c_string(record.target(), "a log target"), c_string(&text, "a log line")) {
            (Ok(target), Ok(message)) => {
                (self.callbacks.log_line)(level, target.as_ptr(), message.as_ptr())
            }
            (Err(why), _) | (_, Err(why)) => {
                // A line that cannot cross is replaced by why it could not; the
                // level is kept so the loss is as loud as the line was.
                if let Ok(replacement) = c_string(&why, "the replacement line") {
                    let target = c"dsm_sdk::ffi";
                    (self.callbacks.log_line)(level, target.as_ptr(), replacement.as_ptr())
                }
            }
        }
    }
}

/// Rust's `log` backend on iOS: every record goes to the host's `log_line`.
/// Installed by [`dsm_ffi_install_host`], after the host, so no record is
/// written before there is a host to take it.
pub struct HostLogger;

impl log::Log for HostLogger {
    fn enabled(&self, metadata: &log::Metadata<'_>) -> bool {
        metadata.level() <= log::max_level()
    }

    fn log(&self, record: &log::Record<'_>) {
        if !self.enabled(record.metadata()) {
            return;
        }
        if let Ok(host) = crate::host::host() {
            // The installed host is the iOS one: `dsm_ffi_install_host` is the
            // only installer in an `ffi` build.
            if let Some(ios) = host.as_ios() {
                ios.log_line(record);
            }
        }
    }

    fn flush(&self) {}
}

/// Install Swift as this process's host, then route Rust's log to it.
/// Answers nothing, or why it was not installed (a host already is).
#[no_mangle]
pub extern "C" fn dsm_ffi_install_host(callbacks: DsmHostCallbacks) -> DsmBytes {
    let installed = crate::host::install(Box::new(IosHost { callbacks }));
    crate::logging::init_android_device_logging();
    crate::logging::init_panic_handler();
    DsmBytes::outcome(installed)
}

/// The records framed by `frame_records`, split again; for the host's tests
/// of its own splitter and for Rust's of the framing.
pub fn split_records(framed: &[u8]) -> Result<Vec<Vec<u8>>, String> {
    let mut records = Vec::new();
    let mut rest = framed;
    while !rest.is_empty() {
        let (len, after) = rest
            .split_first_chunk::<4>()
            .ok_or_else(|| format!("{} trailing bytes are no record length", rest.len()))?;
        let len = u32::from_be_bytes(*len) as usize;
        if after.len() < len {
            return Err(format!(
                "a record length of {len} with {} bytes behind it",
                after.len()
            ));
        }
        let (record, after) = after.split_at(len);
        records.push(record.to_vec());
        rest = after;
    }
    Ok(records)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ffi::bytes_from;

    #[test]
    fn records_frame_and_split_back() {
        let records = vec![vec![6u8; 501], Vec::new(), vec![7u8; 3]];
        let framed = frame_records(&records);
        assert_eq!(framed.len(), 12 + 501 + 3);
        assert_eq!(split_records(&framed).expect("splits"), records);
        let (ok, short) = unsafe { (bytes_from(framed.as_ptr(), 4), bytes_from(framed.as_ptr(), 3)) };
        assert!(split_records(ok).is_err_and(|e| e.contains("bytes behind it")));
        assert!(split_records(short).is_err_and(|e| e.contains("no record length")));
    }

    #[test]
    fn a_nonzero_code_is_the_hosts_refusal() {
        let refused = answered("start_scan", 7).err().expect("refused");
        assert_eq!(refused, "the host's start_scan answered 7");
        assert_eq!(answered("start_scan", 0), Ok(()));
    }
}
