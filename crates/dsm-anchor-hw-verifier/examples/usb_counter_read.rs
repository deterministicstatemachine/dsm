// SPDX-License-Identifier: MIT OR Apache-2.0
//! Hardware bring-up proof for the D2 Path-B remote-SPI verifier path.
//!
//! Runs the receiver's FULL libtropic-rs stack over [`RemoteSpiDevice`], tunnelling every SPI
//! transaction to a real TROPIC01 as an `OP_SPI_PASSTHROUGH` frame over USB-CDC (the Pico is a dumb
//! raw-SPI bridge). Proves, on real silicon, that the host — acting as Receiver B — can:
//!   1. clock raw SPI transactions through the relay (RemoteSpiDevice round-trips),
//!   2. read the chip id + Noise static key (`stpub`) itself,
//!   3. open its own authenticated L3 session to the chip (`session_start`, PROD0 slot 0),
//!   4. read the physical monotonic counter `H` (`mcounter_get`).
//!
//! This stands in for the phone-to-phone BLE relay: same architecture, USB-CDC as the transport.
//! Run with the board attached: `cargo run -p dsm-anchor-hw-verifier --example usb_counter_read`

// Bring-up example, not a production path: fail loudly at the console.
#![allow(clippy::disallowed_methods)]

#[path = "shared/usb.rs"]
mod usb;

use dsm_anchor_verifier::RemoteSpiDevice;
use tropic01::keys::{SH0PRIV_PROD0, SH0PUB_PROD0};
use tropic01::{MCounterIndex, Tropic01, X25519Dalek};
use x25519_dalek::{PublicKey, StaticSecret};

fn main() {
    let dev = std::env::args().nth(1).unwrap_or_else(usb::find_port);
    eprintln!("[usb_counter_read] port = {dev}");
    let port = usb::open_and_drain(&dev);
    eprintln!("\n[usb_counter_read] serve loop quiet; starting libtropic over RemoteSpiDevice");

    let channel = usb::UsbPassthrough { port };
    let mut chip = Tropic01::new(RemoteSpiDevice::new(channel));

    let chip_id = chip
        .get_info_chip_id()
        .expect("get_info_chip_id over relay");
    println!("[1] chip id (via RemoteSpiDevice passthrough): {chip_id:02x?}");

    let stpub: [u8; 32] = *chip
        .get_info_cert_store()
        .expect("get_info_cert_store")
        .public_key()
        .expect("cert public_key");
    println!("[2] chip Noise static key (pin this as chip_static_pubkey): {stpub:02x?}");

    // Ephemeral handshake secret (fixed here for a deterministic bring-up run).
    let ehpriv = StaticSecret::from([0x42u8; 32]);
    let ehpub = PublicKey::from(&ehpriv);
    let mut session = chip
        .session_start(
            &X25519Dalek,
            PublicKey::from(SH0PUB_PROD0),
            StaticSecret::from(SH0PRIV_PROD0),
            ehpub,
            ehpriv,
            0,
        )
        .map_err(|(_, e)| e)
        .expect("session_start (PROD0 slot 0) over relay");
    println!("[3] authenticated L3 session established to TROPIC01 A over the relay");

    let h = session
        .mcounter_get(MCounterIndex::Index0)
        .expect("mcounter_get over relay");
    println!("[4] LIVE COUNTER H_attested = {h}  (u = H0 - H)");
    println!(
        "[usb_counter_read] PASS — receiver read A's physical counter through the raw-SPI relay"
    );
}
