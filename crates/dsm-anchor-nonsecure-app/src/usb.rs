// SPDX-License-Identifier: MIT OR Apache-2.0
//! The USB-CDC host link. A host opening the port raises DTR, which starts a new conversation: an
//! app that died partway through a frame leaves nothing for the next one to be read against. A host
//! that drops DTR has gone, and what it asked for is abandoned. A host that is there but silent, or
//! not reading, is waited for: the keepalive task feeds the watchdog meanwhile.

use embassy_futures::yield_now;
use rp235x_hal as hal;
use usb_device::prelude::*;
use usb_device::UsbError;
use usbd_serial::SerialPort;

use crate::frames::{HostGone, Link};

pub type Serial = SerialPort<'static, hal::usb::UsbBus>;
pub type Device = UsbDevice<'static, hal::usb::UsbBus>;

pub struct UsbLink {
    serial: Serial,
    device: Device,
    /// Whether a host held the port at the last look (DTR).
    host_there: bool,
}

impl UsbLink {
    pub fn new(serial: Serial, device: Device) -> Self {
        let host_there = serial.dtr();
        Self {
            serial,
            device,
            host_there,
        }
    }
}

impl Link for UsbLink {
    async fn read(&mut self, into: &mut [u8]) -> Result<usize, HostGone> {
        loop {
            self.device.poll(&mut [&mut self.serial]);
            let dtr = self.serial.dtr();
            let opened = dtr && !self.host_there;
            self.host_there = dtr;
            if opened {
                return Err(HostGone);
            }
            match self.serial.read(into) {
                Ok(n) if n > 0 => return Ok(n),
                Ok(_none) => {}
                Err(UsbError::WouldBlock) => {}
                Err(_usb_fault) => {}
            }
            yield_now().await;
        }
    }

    async fn write_all(&mut self, bytes: &[u8]) -> Result<(), HostGone> {
        let host_was_there = self.serial.dtr();
        let mut sent = 0;
        while sent < bytes.len() {
            self.device.poll(&mut [&mut self.serial]);
            if host_was_there && !self.serial.dtr() {
                return Err(HostGone);
            }
            match self.serial.write(&bytes[sent..]) {
                Ok(n) => sent += n,
                Err(UsbError::WouldBlock) => yield_now().await,
                Err(_usb_fault) => return Err(HostGone),
            }
        }
        Ok(())
    }
}
