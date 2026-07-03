// SPDX-License-Identifier: MIT OR Apache-2.0
//! H2 bench-vector capture: record the exact `OP_SPI_PASSTHROUGH` request frame + the real chip's
//! response body for ONE L1 `GET_RESPONSE` transaction, so the Android `PicoSelfTestActivity` can
//! replay the SAME single round-trip against the SAME Pico after it moves to the phone over USB-OTG.
//!
//! L1 `GET_RESPONSE` (libtropic `lt_1.rs`) is a single CS-framed SPI transfer of the L2 buffer:
//! MOSI = `[0xAA, L2_CMD_REQ_LEN(128), 0x00 * 255]` (257 bytes); MISO[0] is the chip STATUS byte and
//! MISO[1] the response status (0xff = NO_RESP on an idle chip). It needs no session — so the phone
//! can prove the USB path reached a real TROPIC01 with one opaque frame. Run TWICE here to confirm
//! the response is deterministic before hard-coding it.
//!
//!   cargo run -p dsm-anchor-hw-verifier --example usb_capture_selftest_vector -- /dev/cu.usbmodemdsm_anchor1

// Bring-up tool, not a production path: fail loudly at the console.
#![allow(clippy::disallowed_methods)]

#[path = "shared/usb.rs"]
mod usb;

use std::io::{Read, Write};
use std::time::{Duration, Instant};

use anchor_core::proto::{decode_response, encode_request, pb};

/// TROPIC01 L1 GET_RESPONSE opcode + request length (libtropic `lt_1.rs` / `lib.rs`).
const L2_CMD_ID_GET_RESPONSE: u8 = 0xaa;
const L2_CMD_REQ_LEN: u8 = 128;
/// L2_MAX_FRAME_SIZE + 1 = the size of libtropic's `l2_buf`, i.e. the full MOSI clocked for an L1 read.
const L2_BUF_LEN: usize = 257;

fn read_exact_timeout(port: &mut Box<dyn serialport::SerialPort>, buf: &mut [u8]) {
    let mut got = 0;
    let dl = Instant::now() + Duration::from_secs(8);
    while got < buf.len() {
        assert!(Instant::now() <= dl, "read timeout");
        match port.read(&mut buf[got..]) {
            Ok(0) => {}
            Ok(n) => got += n,
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {}
            Err(e) => panic!("serial read: {e}"),
        }
    }
}

/// Send ONE `OP_SPI_PASSTHROUGH` framing the given MOSI; return `(request_frame, response_body)`
/// exactly as `LocalPicoUsb.transceive` sees them (request frame = LE32 len + ApplianceRequest;
/// response body = the ApplianceResponse bytes with its own LE32 prefix already stripped).
fn one_passthrough(port: &mut Box<dyn serialport::SerialPort>, mosi: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let req = pb::ApplianceRequest {
        op: pb::Op::SpiPassthrough as i32,
        spi_payload: mosi.to_vec(),
        ..Default::default()
    };
    let body = encode_request(&req);
    let mut frame = (body.len() as u32).to_le_bytes().to_vec();
    frame.extend_from_slice(&body);
    port.write_all(&frame).expect("serial write");

    let mut lenb = [0u8; 4];
    read_exact_timeout(port, &mut lenb);
    let n = u32::from_le_bytes(lenb) as usize;
    let mut respb = vec![0u8; n];
    read_exact_timeout(port, &mut respb);
    (frame, respb)
}

fn hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push_str(&format!("{x:02x}"));
    }
    s
}

fn main() {
    let dev = std::env::args().nth(1).unwrap_or_else(usb::find_port);
    eprintln!("[capture] port = {dev}");
    let mut port = usb::open_and_drain(&dev);
    eprintln!("[capture] serve loop quiet; sending L1 GET_RESPONSE passthrough\n");

    // MOSI = the exact L1 GET_RESPONSE buffer libtropic clocks: [0xAA, 128, 0x00 * 255].
    let mut mosi = vec![0u8; L2_BUF_LEN];
    mosi[0] = L2_CMD_ID_GET_RESPONSE;
    mosi[1] = L2_CMD_REQ_LEN;

    let (frame1, body1) = one_passthrough(&mut port, &mosi);
    let (frame2, body2) = one_passthrough(&mut port, &mosi);

    let resp1 = decode_response(&body1).expect("decode ApplianceResponse #1");
    assert_eq!(
        frame1, frame2,
        "request frame must be identical (it is host-built)"
    );
    let deterministic = body1 == body2;

    println!("req_frame_len   = {}", frame1.len());
    println!("req_frame_hex   = {}", hex(&frame1));
    println!("resp_body_len   = {}", body1.len());
    println!("resp_body_hex   = {}", hex(&body1));
    println!("resp.ok         = {}", resp1.ok);
    println!("resp.spi_len    = {}", resp1.spi_response.len());
    if let Some(status) = resp1.spi_response.first() {
        println!(
            "chip_status_b0  = 0x{status:02x}  (ready bit0={})",
            status & 0x01
        );
    }
    println!("deterministic   = {deterministic}  (body #1 == body #2)");
    if !deterministic {
        println!("resp_body_hex#2 = {}", hex(&body2));
        eprintln!("[warn] response NOT byte-identical across calls; compare a stable prefix, not the full body");
    }
}
