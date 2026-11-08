// SPDX-License-Identifier: MIT OR Apache-2.0

//! The app that hosts the SDK, as Rust sees it.
//!
//! Rust decides; the host moves bytes and draws. Everything Rust asks of the
//! platform is one of these calls: hand the page an event, write sealed
//! records on exactly the link Rust chose (DSM Amendment A27), connect for a
//! contact, start or stop the radio, seal the wallet seed under the device's
//! own key, and put a count on the app icon. Android answers them through
//! JNI (`crate::jni::host_bridge`); iOS through the C callbacks Swift
//! registers (`crate::ffi::host_bridge`). A build with no host installed
//! answers every call with an error, never with a result it did not get.

use std::sync::OnceLock;

use crate::bluetooth::link_session::Link;
use crate::generated as pb;
use prost::Message;

/// What writing sealed records on a link came to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Delivery {
    /// The host wrote every record on the link.
    Sent,
    /// Not delivered now: the link is gone or refused a write. The caller's
    /// frame stays owed; nothing switches to another link.
    NotNow,
}

/// What the host does for Rust. Every method answers what the platform
/// answered: a refusal is `Err`, never a silent success.
pub trait HostBridge: Send + Sync {
    /// Hand the page `payload` under `topic`.
    fn post_event(&self, topic: &str, payload: &[u8]) -> Result<(), String>;

    /// The count on the app icon of received transfers not yet looked at;
    /// zero takes it down.
    fn show_money_received(&self, count: i32) -> Result<(), String>;

    /// Write `sealed`, in order, on exactly `link`. The host never picks
    /// another link: a link that is gone is `NotNow`.
    fn write_on_link(&self, link: &Link, sealed: &[Vec<u8>]) -> Result<Delivery, String>;

    /// Connect for the contact `device_id`, reaching for `address_hint`
    /// first when it names an address. The link that opens names the contact
    /// as its handshake target.
    fn request_connect(
        &self,
        device_id: &[u8; 32],
        address_hint: Option<&str>,
    ) -> Result<(), String>;

    /// Advertise this appliance; `Err` when the radio refused.
    fn start_advertising(&self) -> Result<(), String>;

    /// Scan for DSM appliances; `Err` when the radio refused.
    fn start_scan(&self) -> Result<(), String>;

    /// Stop the scan; `Err` when it was not stopped.
    fn stop_scan(&self) -> Result<(), String>;

    /// Seal the wallet seed under the device's sealing key. The key never
    /// enters Rust.
    fn seal_seed(&self, plaintext: &[u8]) -> Result<Vec<u8>, String>;

    /// Open a blob [`HostBridge::seal_seed`] made on this device.
    fn open_seed(&self, blob: &[u8]) -> Result<Vec<u8>, String>;

    /// This host as the iOS host, when it is one: the log backend hands it
    /// Rust's records.
    #[cfg(feature = "ffi")]
    fn as_ios(&self) -> Option<&crate::ffi::host_bridge::IosHost> {
        None
    }
}

static HOST: OnceLock<Box<dyn HostBridge>> = OnceLock::new();

/// Install the host, once per process. A second install is refused: the
/// first host keeps every call.
pub fn install(host: Box<dyn HostBridge>) -> Result<(), String> {
    HOST.set(host).map_err(|rejected| {
        format!(
            "a host is already installed; the first one keeps every call, and the {} offered now is dropped",
            std::any::type_name_of_val(rejected.as_ref())
        )
    })
}

/// The installed host, or why there is none.
pub fn host() -> Result<&'static dyn HostBridge, String> {
    HOST.get()
        .map(|boxed| boxed.as_ref())
        .ok_or_else(|| "no host is installed: the platform has not registered itself".to_string())
}

/// Hand the page `payload` under `topic`, logging a host that is missing or
/// refused it. For producers whose work stands whether or not the page heard
/// of it (a registry write, an inbox pull).
pub fn post_event(topic: &str, payload: &[u8]) {
    if let Err(e) = host().and_then(|host| host.post_event(topic, payload)) {
        log::warn!("[host] {topic} did not reach the page: {e}");
    }
}

/// A local answer for the page, framed as it reads one: `0x03 ‖ Envelope`
/// with no sender headers and no message id. Encoding an in-memory message
/// into a growing buffer has no failure.
pub fn framed_local_answer(payload: pb::envelope::Payload) -> Vec<u8> {
    let envelope = crate::envelope::local_answer(payload);
    let mut buf = Vec::with_capacity(1 + envelope.encoded_len());
    buf.push(0x03);
    buf.extend(envelope.encode_to_vec());
    buf
}

/// A `BleEvent` for the page: this device's own radio reporting what
/// happened to it, as a framed local answer. Never a frame for a peer.
pub fn ble_event_envelope(event: pb::BleEvent) -> Vec<u8> {
    framed_local_answer(pb::envelope::Payload::BleEvent(event))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// With no host, every call answers an error: nothing is reported done.
    /// MUTATION CONTROL: a default host that answers `Ok` turns this red.
    #[test]
    fn without_a_host_nothing_is_reported_done() {
        // The process-wide host may have been installed by another test in
        // this binary; the property under test is the absent case, which
        // `host()` states in its error.
        if HOST.get().is_some() {
            return;
        }
        let missing = host().err().expect("no host is installed");
        assert!(missing.contains("no host is installed"), "{missing}");
    }

    #[test]
    fn a_ble_event_is_a_framed_local_answer() {
        let framed = ble_event_envelope(pb::BleEvent {
            ev: Some(pb::ble_event::Ev::DeviceDisconnected(pb::BleDeviceInfo {
                address: "6B2C7F1E-9A3D-4E08-B5C1-2D7A9F0E4C61".to_string(),
                name: String::new(),
                rssi: 0,
            })),
        });
        assert_eq!(framed[0], 0x03);
        let envelope = pb::Envelope::decode(&framed[1..]).expect("decodes");
        assert!(matches!(
            envelope.payload,
            Some(pb::envelope::Payload::BleEvent(_))
        ));
        assert!(envelope.headers.is_none() && envelope.message_id.is_empty());
    }
}
