// SPDX-License-Identifier: MIT OR Apache-2.0
//! Shared USB-CDC transport for the hardware bring-up examples: a [`SpiRelayChannel`] over the
//! Pico anchor firmware's `OP_SPI_PASSTHROUGH` (each transceive frames one raw SPI transaction as
//! `LE32 len + ApplianceRequest` and reads back `LE32 len + ApplianceResponse`), plus port
//! discovery and the boot-log drain. Not an example target itself (lives under `examples/shared/`).

use std::io::{Read, Write};
use std::time::{Duration, Instant};

use anchor_core::proto::{decode_response, encode_request, pb};
use dsm_anchor_verifier::{RelayError, SpiRelayChannel};

pub struct UsbPassthrough {
    pub port: Box<dyn serialport::SerialPort>,
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

pub fn find_port() -> String {
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

/// Open the port and drain the firmware boot log + self-test output until the serve loop goes
/// quiet (up to 45s; breaks after 2.5s of silence once output has been seen).
pub fn open_and_drain(dev: &str) -> Box<dyn serialport::SerialPort> {
    let mut port = serialport::new(dev, 115_200)
        .timeout(Duration::from_millis(500))
        .open()
        .expect("open serial port");
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
    port
}
