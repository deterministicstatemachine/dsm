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
//! Run with the board attached:  `cargo run -p dsm-anchor-verifier --example usb_counter_read`

use std::io::{Read, Write};
use std::time::{Duration, Instant};

use anchor_core::proto::{decode_response, encode_request, pb};
use dsm_anchor_verifier::{RelayError, RemoteSpiDevice, SpiRelayChannel};
use tropic01::keys::{SH0PRIV_PROD0, SH0PUB_PROD0};
use tropic01::{MCounterIndex, Tropic01, X25519Dalek};
use x25519_dalek::{PublicKey, StaticSecret};

/// A [`SpiRelayChannel`] over the Pico's USB-CDC `OP_SPI_PASSTHROUGH` command. Each transceive frames
/// one raw SPI transaction as `LE32 len + ApplianceRequest{op:SPI_PASSTHROUGH, spi_payload:mosi}` and
/// reads back `LE32 len + ApplianceResponse{spi_response:miso}`.
struct UsbPassthrough {
    port: Box<dyn serialport::SerialPort>,
}

impl UsbPassthrough {
    fn read_exact_timeout(&mut self, buf: &mut [u8]) -> Result<(), RelayError> {
        let mut got = 0;
        let dl = Instant::now() + Duration::from_secs(8);
        while got < buf.len() {
            if Instant::now() > dl {
                return Err(RelayError::Transport("read timeout".into()));
            }
            match self.port.read(&mut buf[got..]) {
                Ok(0) => {}
                Ok(n) => got += n,
                Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {}
                Err(e) => return Err(RelayError::Transport(e.to_string())),
            }
        }
        Ok(())
    }
}

impl SpiRelayChannel for UsbPassthrough {
    fn transceive(&mut self, mosi: &[u8]) -> Result<Vec<u8>, RelayError> {
        let req = pb::ApplianceRequest {
            op: pb::Op::SpiPassthrough as i32,
            spi_payload: mosi.to_vec(),
            ..Default::default()
        };
        let body = encode_request(&req);
        let mut frame = (body.len() as u32).to_le_bytes().to_vec();
        frame.extend_from_slice(&body);
        self.port
            .write_all(&frame)
            .map_err(|e| RelayError::Transport(e.to_string()))?;

        let mut lenb = [0u8; 4];
        self.read_exact_timeout(&mut lenb)?;
        let n = u32::from_le_bytes(lenb) as usize;
        let mut respb = vec![0u8; n];
        self.read_exact_timeout(&mut respb)?;
        let resp =
            decode_response(&respb).map_err(|e| RelayError::Transport(format!("decode: {e:?}")))?;
        if !resp.ok {
            return Err(RelayError::Transport(format!(
                "passthrough error code {}",
                resp.error
            )));
        }
        Ok(resp.spi_response)
    }
}

fn find_port() -> String {
    for p in serialport::available_ports().unwrap_or_default() {
        if p.port_name.contains("usbmodem") && p.port_name.contains("dsm_anchor") {
            return p.port_name;
        }
    }
    // Fallback: first usbmodem.
    for p in serialport::available_ports().unwrap_or_default() {
        if p.port_name.contains("usbmodem") {
            return p.port_name;
        }
    }
    panic!("no dsm_anchor usbmodem serial port found");
}

fn main() {
    let dev = std::env::args().nth(1).unwrap_or_else(find_port);
    eprintln!("[usb_counter_read] port = {dev}");
    let mut port = serialport::new(&dev, 115_200)
        .timeout(Duration::from_millis(500))
        .open()
        .expect("open serial port");

    // Drain the boot log + self-test (T1..T6; T5 runs full SPHINCS signing, which is slow on the
    // RP2350) until the serve loop goes quiet. Be patient — up to 45s, breaking after 2.5s of
    // silence once output has been seen.
    let mut scratch = [0u8; 1024];
    let dl = Instant::now() + Duration::from_secs(45);
    let mut last = Instant::now();
    let mut saw_any = false;
    while Instant::now() < dl {
        match port.read(&mut scratch) {
            Ok(n) if n > 0 => {
                std::io::stderr().write_all(&scratch[..n]).ok();
                last = Instant::now();
                saw_any = true;
            }
            _ => {
                if saw_any && last.elapsed() > Duration::from_millis(2500) {
                    break;
                }
            }
        }
    }
    eprintln!("\n[usb_counter_read] serve loop quiet; starting libtropic over RemoteSpiDevice");

    let channel = UsbPassthrough { port };
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
