// SPDX-License-Identifier: MIT OR Apache-2.0
//! DSM anchor RP2350 **Non-secure application** (TrustZone-M Non-secure world).
//!
//! Owns the two host transports, USB-CDC and Bluetooth Low Energy over the Pico 2 W radio, and
//! carries LE32-length-prefixed request and response frames between a host and the Secure monitor.
//! It reaches the monitor ONLY through the single NSC Secure Gateway `dsm_secure_dispatch(slot,
//! seq)`; a fixed Non-secure SRAM mailbox slot carries the frames in parts. It has NO access to OTP,
//! the host key, TROPIC01, the counter, DMA or Secure state — any attempt faults (SAU) or stalls.
//!
//! It runs in place from its own flash region, which the monitor measures whole before every
//! authority operation; only its writable memory is in Non-secure SRAM. Its tasks share one core
//! cooperatively: the USB link, the radio's bus runner, the Bluetooth host with the anchor's
//! service, and a keepalive that crosses the gateway every few hundred milliseconds so the Secure
//! watchdog knows the side is alive while no host is talking.

#![no_std]
#![no_main]

extern crate panic_halt;

#[cfg(feature = "radio")]
mod ble;
mod clock;
mod frames;
mod gateway;
#[cfg(feature = "radio")]
mod radio;
mod usb;

use embassy_executor::{Executor, Spawner};
use embassy_time::Timer;
use rp235x_hal as hal;
use static_cell::StaticCell;
use usb_device::class_prelude::UsbBusAllocator;
use usb_device::prelude::*;
use usbd_serial::SerialPort;

use crate::frames::FrameServer;
use crate::usb::UsbLink;

/// RP2350 crystal on the anchor board (mirrors the pico anchor).
const XTAL_HZ: u32 = 12_000_000;

/// How often the idle side tells the Secure watchdog it is alive. The watchdog's period is about
/// two seconds; a crossing every 700 ms leaves it fed through the longest Bluetooth event.
const KEEPALIVE_MS: u64 = 700;

static EXECUTOR: StaticCell<Executor> = StaticCell::new();
static USB_BUS: StaticCell<UsbBusAllocator<hal::usb::UsbBus>> = StaticCell::new();

#[hal::entry]
fn main() -> ! {
    let mut pac = hal::pac::Peripherals::take().unwrap();
    let mut watchdog = hal::watchdog::Watchdog::new(pac.WATCHDOG);
    // This inits the PLL/clock tree from the Non-secure world, through grants the monitor holds open
    // only until this app's first crossing (below). TIMER1 and PIO0 are released from reset in the
    // same window; the monitor keeps them, USBCTRL, the radio's four pins and this image's flash
    // granted while the app serves.
    let clocks = hal::clocks::init_clocks_and_plls(
        XTAL_HZ,
        pac.XOSC,
        pac.CLOCKS,
        pac.PLL_SYS,
        pac.PLL_USB,
        &mut pac.RESETS,
        &mut watchdog,
    )
    .ok()
    .unwrap();

    clock::init(&mut pac.RESETS);

    let usb_bus = USB_BUS.init(UsbBusAllocator::new(hal::usb::UsbBus::new(
        pac.USB,
        pac.USB_DPRAM,
        clocks.usb_clock,
        true,
        &mut pac.RESETS,
    )));
    let serial = SerialPort::new(usb_bus);
    let usb_dev = UsbDeviceBuilder::new(usb_bus, UsbVidPid(0x1209, 0xd5a1))
        .strings(&[StringDescriptors::default()
            .manufacturer("DSM")
            .product("DSM Anchor")
            .serial_number("dsm-anchor")])
        .unwrap()
        .max_packet_size_0(64)
        .unwrap()
        .device_class(usbd_serial::USB_CLASS_CDC)
        .build();

    #[cfg(feature = "radio")]
    let (spi, pwr) = radio::setup(pac.PIO0, &mut pac.RESETS);

    // The first crossing, before a byte from any host is read: the Secure side takes back the
    // peripherals this app needed only to bring up its clocks, USB, timer and PIO.
    gateway::keepalive();

    let executor = EXECUTOR.init(Executor::new());
    executor.run(|spawner| {
        spawner.spawn(keepalive().expect("the keepalive task spawns once"));
        spawner.spawn(serve_usb(UsbLink::new(serial, usb_dev)).expect("the USB task spawns once"));
        #[cfg(feature = "radio")]
        spawner.spawn(serve_radio(spi, pwr, spawner).expect("the radio task spawns once"));
    })
}

/// A crossing that moves no frame, on a steady beat: the Secure handler feeds the watchdog on it,
/// so an anchor waiting on its hosts is not a hung one.
#[embassy_executor::task]
async fn keepalive() {
    loop {
        Timer::after_millis(KEEPALIVE_MS).await;
        gateway::keepalive();
    }
}

/// Serve the anchor over USB-CDC forever, host after host.
#[embassy_executor::task]
async fn serve_usb(mut link: UsbLink) {
    static FRAMES: StaticCell<FrameServer> = StaticCell::new();
    let frames = FRAMES.init(FrameServer::new());
    loop {
        frames.serve(&mut link).await;
    }
}

/// Bring the radio up, run its bus, and serve the anchor over Bluetooth with an address the Secure
/// side's entropy gave this boot. A boot the Secure side gives no entropy keeps the radio dark:
/// the anchor still serves over USB, and nothing on the air is made up.
#[cfg(feature = "radio")]
#[embassy_executor::task]
async fn serve_radio(spi: radio::PioGspi, pwr: radio::OverridePin, spawner: Spawner) {
    let (bt, mut control, runner) = radio::bring_up(spi, pwr).await;
    spawner.spawn(run_radio_bus(runner).expect("the radio bus task spawns once"));
    control.init(radio::clm()).await;
    radio::at(radio::stage::CONTROL_READY);
    let Some(entropy) = gateway::entropy() else {
        radio::at(radio::stage::ENTROPY_REFUSED);
        return;
    };
    radio::at(radio::stage::ENTROPY_TAKEN);
    let mut address = [0u8; 6];
    address.copy_from_slice(&entropy[..6]);
    // A static random address: its two top bits set, the rest random.
    address[5] |= 0xC0;
    ble::run(bt, address).await;
}

/// The radio's bus: every word to and from the CYW43439, for the Bluetooth controller.
#[cfg(feature = "radio")]
#[embassy_executor::task]
async fn run_radio_bus(
    runner: cyw43::Runner<'static, cyw43::SpiBus<radio::OverridePin, radio::PioGspi>>,
) -> ! {
    runner.run().await
}
